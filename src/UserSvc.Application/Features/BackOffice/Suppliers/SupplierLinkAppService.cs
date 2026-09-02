using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Accounts;
using UserSvc.Application.Features.BackOffice.Rbac;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Suppliers;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Application.Security;
using UserSvc.Domain.BackOffice;
using UserSvc.Domain.Suppliers;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Application.Features.BackOffice.Suppliers;

/// <summary>
/// The platform-side plane for managing which approved suppliers hang off which company: a batch
/// read that merges each supplier's ACTIVE mounting with its administrators and active member
/// count, and a mount/unmount write that validates the codes against the product master data
/// before it touches the link table.
/// <para>
/// <b>The mounting is data scope, so unmounting is a revocation.</b> The scope envelope hands every
/// member of a company the suppliers mounted onto it, and every member of a supplier the company it
/// hangs under; both are baked into issued access tokens and trusted downstream. A revocation that
/// waits out the token lifetime is not a revocation, which is why a relink and an unmount retire the
/// affected sessions' tokens. A <i>first</i> mount takes nothing away - purely additive grants
/// converge on the next natural refresh, and re-signing every session for one is churn.
/// </para>
/// </summary>
public sealed class SupplierLinkAppService(
    AdminScopeService adminScopes,
    ISupplierCompanyLinkRepository links,
    ITenantMemberRepository members,
    IBackendUserRepository backendUsers,
    IBackendIdentityRepository backendIdentities,
    ITenantMasterDataDirectory masterData,
    IAuthzConvergence convergence,
    IdentifierProtector protector,
    IamAuditWriter audit,
    IUnitOfWork unitOfWork,
    IClock clock,
    ILogger<SupplierLinkAppService> logger)
{
    /// <summary>
    /// 422, not 400. The request is well formed and the code names a real supplier; what fails is a
    /// rule about that supplier's state, and nothing the caller can retype fixes it - somebody has
    /// to approve it in the master data first. The architecture's status grouping is by "what should
    /// the client do next", and that is the difference between this and the two not-found codes.
    /// </summary>
    private const int UnprocessableEntity = 422;

    /// <summary>
    /// One item per requested supplier code: its ACTIVE company mounting, its administrators and
    /// its active member count.
    /// <para>
    /// When <paramref name="supplierCodes"/> is empty and <paramref name="companyCode"/> is set, it
    /// lists the suppliers mounted onto that company instead. When both are empty it returns no
    /// items - an unfiltered dump of every mounting is not on offer. A company code alongside an
    /// explicit supplier set narrows that set to the ones mounted onto that company.
    /// </para>
    /// </summary>
    public async Task<SupplierLinkListResponse> ListAsync(
        IBackOfficeCaller caller,
        IReadOnlyList<string>? supplierCodes,
        string? companyCode,
        CancellationToken cancellationToken)
    {
        AssertPlatformPlane(caller, "read the supplier mountings");
        await adminScopes.AssertHoldsAnyAsync(caller, [SupplierLinkPermissions.Read], cancellationToken);

        var company = (companyCode ?? string.Empty).Trim();
        var codes = SupplierCodes.Normalize(supplierCodes);

        // Supplier code -> the company code of its ACTIVE mounting. A code that is absent from this
        // map is independent, which is a normal state rather than a missing row.
        var mountedOn = new Dictionary<string, string>(StringComparer.Ordinal);

        if (codes.Count > 0)
        {
            foreach (var link in await links.ListActiveBySuppliersAsync(codes, cancellationToken))
            {
                mountedOn[link.SupplierCode] = link.CompanyCode;
            }

            if (company.Length > 0)
            {
                // A company filter narrows an explicit supplier set to those mounted onto that
                // company. An unmounted code compares against the empty string and drops out; the
                // surviving codes keep the caller's order.
                codes = [.. codes.Where(code => mountedOn.GetValueOrDefault(code, string.Empty) == company)];
            }
        }
        else if (company.Length > 0)
        {
            var mounted = await links.ListActiveByCompanyAsync(company, cancellationToken);
            foreach (var link in mounted)
            {
                mountedOn[link.SupplierCode] = link.CompanyCode;
            }

            // Sorted rather than left in row order: the caller supplied no order of its own here,
            // and a listing whose row order comes from the database is one that changes under the
            // reader for no reason they can see.
            codes = [.. SupplierCodes.Normalize(mounted.Select(link => link.SupplierCode)).Order(StringComparer.Ordinal)];
        }
        else
        {
            return new SupplierLinkListResponse();
        }

        if (codes.Count == 0)
        {
            return new SupplierLinkListResponse();
        }

        // Ordered by membership id, because the port deliberately does not order and this response
        // depends on the order twice over: Admins is rendered in it, and Admin - the legacy
        // single-value field - IS its first element. Without a sort, "the first administrator" of a
        // supplier that has two is whichever row the database happened to hand back, so the field
        // can change between two page loads with nothing having changed underneath.
        //
        // Sorted here rather than pushed into the port for two reasons: the key is an integer, so
        // this has none of the collation dependence that keeps the code sorts in SQL, and the port
        // is shared with callers whose own tests pin its natural order.
        var admins = (await members.FindAdminsByTenantsAsync(
                TenantTypes.Supplier, codes, cancellationToken))
            .OrderBy(member => member.Id)
            .ToList();

        // Several rows per tenant are normal now that the one-administrator unique index is gone,
        // so group rather than overwrite: keying a single member by tenant code would silently keep
        // only the last administrator.
        var adminsByTenant = new Dictionary<string, List<TenantMember>>(StringComparer.Ordinal);
        foreach (var member in admins)
        {
            if (!adminsByTenant.TryGetValue(member.TenantCode, out var bucket))
            {
                bucket = [];
                adminsByTenant[member.TenantCode] = bucket;
            }

            bucket.Add(member);
        }

        var counts = await members.CountActiveByTenantsAsync(
            TenantTypes.Supplier, codes, cancellationToken);

        var (nicknames, emails) = await ResolveAdminProfilesAsync(
            CallerFacts.DedupeSort(admins.Select(member => member.UserId)), cancellationToken);

        var items = new List<SupplierLinkResponse>(codes.Count);
        foreach (var code in codes)
        {
            var tenantAdmins = adminsByTenant.TryGetValue(code, out var bucket)
                ? bucket.Select(member => new SupplierLinkAdminResponse
                {
                    UserId = member.UserId,
                    Nickname = nicknames.GetValueOrDefault(member.UserId, string.Empty),
                    Email = emails.GetValueOrDefault(member.UserId, string.Empty),
                }).ToList()
                : [];

            items.Add(new SupplierLinkResponse
            {
                SupplierCode = code,
                CompanyCode = mountedOn.TryGetValue(code, out var mounted) ? mounted : null,
                Admins = tenantAdmins,
                Admin = tenantAdmins.Count > 0 ? tenantAdmins[0] : null,
                MemberCount = counts.GetValueOrDefault(code, 0),
            });
        }

        return new SupplierLinkListResponse { Items = items };
    }

    /// <summary>
    /// Mount, move or unmount one supplier.
    /// <para>
    /// A non-empty company code mounts - or relinks - the supplier onto that company after a live
    /// master-data validation: the supplier must exist and be approved, the company must exist and
    /// be active. An empty or absent one unmounts.
    /// </para>
    /// </summary>
    public async Task UpdateLinkAsync(
        IBackOfficeCaller caller,
        string supplierCode,
        UpdateSupplierLinkRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        AssertPlatformPlane(caller, "change a supplier mounting");
        await adminScopes.AssertHoldsAnyAsync(caller, [SupplierLinkPermissions.Manage], cancellationToken);

        var supplier = (supplierCode ?? string.Empty).Trim();
        if (supplier.Length == 0)
        {
            // SUPPLIER_NOT_FOUND rather than BAD_REQUEST, matching the Go contract. In practice
            // unreachable - the code is a path segment, so routing has already refused a blank one.
            throw new BadRequestException(ErrorCodes.SupplierNotFound, "A supplier code is required.");
        }

        var company = (request.CompanyCode ?? string.Empty).Trim();

        if (company.Length == 0)
        {
            await UnlinkAsync(caller, supplier, cancellationToken);
            return;
        }

        await LinkAsync(caller, supplier, company, cancellationToken);
    }

    /// <summary>
    /// Mounts the supplier onto a company after the master data has vouched for both codes.
    /// Relinking - the supplier is already mounted elsewhere - is one transaction: the old row goes
    /// UNLINKED and the new one is inserted ACTIVE. Re-mounting onto the same company is refused.
    /// </summary>
    private async Task LinkAsync(
        IBackOfficeCaller caller,
        string supplierCode,
        string companyCode,
        CancellationToken cancellationToken)
    {
        await AssertMountableAsync(supplierCode, companyCode, cancellationToken);

        var existing = await links.FindActiveBySupplierAsync(supplierCode, cancellationToken);
        if (existing is not null && existing.CompanyCode == companyCode)
        {
            throw new ConflictException(
                ErrorCodes.SupplierAlreadyLinked,
                $"Supplier {supplierCode} is already mounted onto company {companyCode}.");
        }

        var previousCompany = existing?.CompanyCode ?? string.Empty;
        var hadMounting = existing is not null;
        var now = clock.UtcNow;
        var actor = Actor(caller);

        // Steps here are deliberately NOT serialized against a competing writer:
        // uk_supplier_links_active is the invariant, and a racing double mount surfaces as a unique
        // violation - which the unit of work maps to 409 - rather than as a lock every read pays
        // for.
        //
        // Everything the body needs is computed inside it, and the retirement is a set-based
        // statement rather than a tracked mutation. Both are because ExecuteInTransactionAsync runs
        // under PostgreSQL's transient-failure retry strategy, which re-executes this delegate from
        // a clean transaction: a statement re-applies on the second pass, while a change-tracker
        // entry whose changes were already accepted by a first SaveChanges would not - and the
        // retried transaction would then insert an ACTIVE row without retiring the old one.
        await unitOfWork.ExecuteInTransactionAsync(
            async transactionToken =>
            {
                if (hadMounting)
                {
                    // The retirement lands before the insert because it is an immediate statement
                    // and the insert is staged. That order is load-bearing: two ACTIVE rows for one
                    // supplier, even momentarily inside the transaction, is exactly what the
                    // partial unique index refuses.
                    await links.UnlinkActiveBySupplierAsync(
                        supplierCode, now, actor, transactionToken);
                }

                links.Add(new SupplierCompanyLink
                {
                    SupplierCode = supplierCode,
                    CompanyCode = companyCode,
                    Status = SupplierCompanyLinkStatuses.Active,
                    CreatedAt = now,
                    UpdatedAt = now,
                    CreatedBy = actor,
                    UpdatedBy = actor,
                });

                await unitOfWork.SaveChangesAsync(transactionToken);
            },
            cancellationToken);

        await audit.WriteAsync(
            caller,
            SupplierLinkAuditVocabulary.LinkAction,
            SupplierLinkAuditVocabulary.TargetType,
            supplierCode,
            hadMounting
                ? new SupplierLinkAuditSnapshot(
                    supplierCode, previousCompany, SupplierCompanyLinkStatuses.Unlinked)
                : null,
            new SupplierLinkAuditSnapshot(
                supplierCode, companyCode, SupplierCompanyLinkStatuses.Active),
            cancellationToken);

        if (hadMounting)
        {
            // A relink is also a revocation: the previous company's members lose this supplier from
            // their envelope, and the supplier's own members lose that company from theirs.
            await ReissueScopeHoldersAsync(supplierCode, previousCompany, cancellationToken);
        }
    }

    /// <summary>
    /// Retires the supplier's ACTIVE mounting. Idempotent: a supplier with nothing mounted is a
    /// no-op, with no audit row and no token churn.
    /// </summary>
    private async Task UnlinkAsync(
        IBackOfficeCaller caller,
        string supplierCode,
        CancellationToken cancellationToken)
    {
        // Read before the row is retired: the company it names is who loses this supplier from
        // their scope envelope, and once the row is UNLINKED nothing else remembers which company
        // that was. No transaction is needed to hold that fact - the retirement below is a single
        // statement, and the code was captured before it ran.
        var existing = await links.FindActiveBySupplierAsync(supplierCode, cancellationToken);
        if (existing is null)
        {
            return;
        }

        var companyCode = existing.CompanyCode;

        // One statement, and its affected count is the decision. Two operators unmounting at once
        // both read an ACTIVE row above; only the one whose UPDATE actually touched it goes on to
        // write the audit row and retire the tokens. Nothing happened for the other, so it records
        // nothing - the same outcome as unmounting a supplier that hangs nowhere.
        var retired = await links.UnlinkActiveBySupplierAsync(
            supplierCode, clock.UtcNow, Actor(caller), cancellationToken);

        if (retired == 0)
        {
            return;
        }

        await audit.WriteAsync(
            caller,
            SupplierLinkAuditVocabulary.UnlinkAction,
            SupplierLinkAuditVocabulary.TargetType,
            supplierCode,
            new SupplierLinkAuditSnapshot(supplierCode, companyCode, SupplierCompanyLinkStatuses.Active),
            new SupplierLinkAuditSnapshot(supplierCode, companyCode, SupplierCompanyLinkStatuses.Unlinked),
            cancellationToken);

        await ReissueScopeHoldersAsync(supplierCode, companyCode, cancellationToken);
    }

    /// <summary>
    /// Refuses a mounting the product master data does not vouch for.
    /// <para>
    /// The write path is the one place these codes are checked at all - there is no foreign key
    /// behind either column, because the rows they name live in another service - so an unreachable
    /// master data fails the write rather than being waved through. That is the opposite direction
    /// from the tenancy reads, which treat "not reached" as "no opinion" and carry on, and the
    /// asymmetry is the point: a read that falls open shows somebody a stale tenant name, while a
    /// write that falls open grants data scope over a company nobody has confirmed exists.
    /// </para>
    /// <para>
    /// It breaks only itself. Master data being unavailable fails this endpoint and nothing else -
    /// the listing above makes no master-data call at all.
    /// </para>
    /// </summary>
    private async Task AssertMountableAsync(
        string supplierCode,
        string companyCode,
        CancellationToken cancellationToken)
    {
        var entries = await masterData.ValidateAsync(
            [companyCode], [supplierCode], cancellationToken);

        if (entries is null)
        {
            throw new UpstreamException(
                ErrorCodes.UpstreamUnavailable,
                "The product master data could not be reached, so the supplier and company codes "
                + "could not be verified. No mounting was changed.");
        }

        var supplier = entries.FirstOrDefault(entry =>
            entry.TenantType == TenantTypes.Supplier && entry.TenantCode == supplierCode);

        if (supplier is null)
        {
            throw new BadRequestException(
                ErrorCodes.SupplierNotFound,
                $"The product master data knows no supplier {supplierCode}.");
        }

        if (!supplier.Usable)
        {
            // The port collapses "exists" and "is approved" into one verdict, so this is the only
            // place the two Go codes cannot both be reproduced. NOT_APPROVED is the one reported,
            // because the operator picks the code off a list of suppliers that do exist and the
            // failure they actually hit is an unapproved one. Distinguishing them needs a wider
            // master-data port, which belongs to the slice that owns it.
            throw new AppException(
                ErrorCodes.SupplierNotApproved,
                $"Supplier {supplierCode} is not approved, so it cannot be mounted.",
                UnprocessableEntity);
        }

        var company = entries.FirstOrDefault(entry =>
            entry.TenantType == TenantTypes.Company && entry.TenantCode == companyCode);

        // An inactive company reports COMPANY_NOT_FOUND as well: a company that has been switched
        // off is not somewhere a supplier may be mounted, and the contract exposes one outcome for
        // "this company cannot take a mounting".
        if (company is null || !company.Usable)
        {
            throw new BadRequestException(
                ErrorCodes.CompanyNotFound,
                $"Company {companyCode} does not exist in the product master data, or is not active.");
        }
    }

    /// <summary>
    /// Batch-loads the display name and primary email address of the given administrator ids.
    /// <para>
    /// Batched rather than resolved per administrator, because this read answers the same question
    /// for every supplier on the page and the per-account path is one query each.
    /// </para>
    /// </summary>
    private async Task<(Dictionary<int, string> Nicknames, Dictionary<int, string> Emails)>
        ResolveAdminProfilesAsync(IReadOnlyList<int> userIds, CancellationToken cancellationToken)
    {
        var nicknames = new Dictionary<int, string>();
        var emails = new Dictionary<int, string>();

        if (userIds.Count == 0)
        {
            return (nicknames, emails);
        }

        foreach (var user in await backendUsers.ListByIdsAsync(userIds, cancellationToken))
        {
            nicknames[user.Id] = BackOfficeNames.DisplayName(user.FirstName, user.LastName, user.Nickname);
        }

        // Ordered by id, so "the first email identity" is the same one on every page load.
        foreach (var identity in await backendIdentities.ListActiveByUserIdsAsync(userIds, cancellationToken))
        {
            if (identity.IdentityType != BackendIdentityTypes.Email || emails.ContainsKey(identity.UserId))
            {
                continue;
            }

            emails[identity.UserId] = ReadIdentifier(identity);
        }

        return (nicknames, emails);
    }

    /// <summary>
    /// The administrator's address, or its stored mask when the ciphertext will not decrypt.
    /// <para>
    /// The Go original reported an empty string for an unreadable row. The mask is preferred here
    /// for the same reason the back-office roster prefers it: a column that degrades to blank looks
    /// like data loss to the operator reading it, whereas the mask is already what several other
    /// back-office screens show and leaks nothing new.
    /// </para>
    /// </summary>
    private string ReadIdentifier(BackendIdentity identity)
    {
        if (string.IsNullOrEmpty(identity.IdentifierCiphertext))
        {
            return identity.IdentifierMasked;
        }

        try
        {
            return protector.Decrypt(identity.IdentifierCiphertext);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            logger.LogDebug(
                ex,
                "The address of back-office account {BackendUserId} could not be decrypted "
                + "(identity {IdentityId}, key version {KeyVersion}); reporting its masked form.",
                identity.UserId,
                identity.Id,
                identity.KeyVersion);

            return identity.IdentifierMasked;
        }
    }

    /// <summary>
    /// Re-signs the sessions whose data-scope envelope just lost this mounting.
    /// <para>
    /// The mounting <b>is</b> scope: the envelope hands every member of the company the suppliers
    /// mounted onto it, and every member of the supplier the company it hangs under - both baked
    /// into the access token and trusted downstream. Unmounting is therefore a revocation, and a
    /// revocation that waits out the token lifetime is not one: without this, every member of the
    /// company, and every company-dimension whole-dimension operator, keeps read and write access
    /// on the unmounted supplier until their token expires.
    /// </para>
    /// <para>
    /// Post-commit and best effort, like the audit row. The database is already authoritative for
    /// the next token, so a failed bump leaves the old expiry window in place rather than undoing
    /// an unmount that has happened. <paramref name="companyCode"/> is empty when the supplier had
    /// no mounting to lose.
    /// </para>
    /// </summary>
    private async Task ReissueScopeHoldersAsync(
        string supplierCode,
        string companyCode,
        CancellationToken cancellationToken)
    {
        var affected = new HashSet<int>();

        await CollectAsync(TenantTypes.Supplier, supplierCode);

        if (companyCode.Length > 0)
        {
            await CollectAsync(TenantTypes.Company, companyCode);
        }

        if (affected.Count == 0)
        {
            return;
        }

        try
        {
            await convergence.BumpTokenVersionAsync(
                CallerFacts.DedupeSort(affected), cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(
                ex,
                "The token version of {Count} account(s) could not be bumped after supplier "
                + "{SupplierCode} was unmounted; their existing tokens keep the old scope until "
                + "they expire.",
                affected.Count,
                supplierCode);
        }

        async Task CollectAsync(string tenantType, string tenantCode)
        {
            try
            {
                foreach (var userId in await members.FindUserIdsByTenantCodeAsync(
                             tenantType, tenantCode, cancellationToken))
                {
                    affected.Add(userId);
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Warn and carry on with whoever was collected. Bumping the members we did find is
                // strictly better than bumping nobody, and this whole method is best effort.
                logger.LogWarning(
                    ex,
                    "The members of {TenantType} {TenantCode} could not be listed for a token "
                    + "reissue after a supplier mounting changed.",
                    tenantType,
                    tenantCode);
            }
        }
    }

    /// <summary>
    /// Refuses a caller who is acting as one company or one supplier, whatever permission codes
    /// they hold.
    /// <para>
    /// <b>The permission code alone is not enough here, and the Go original's gate is.</b> Both
    /// points are seeded against the platform-audience "approved suppliers" menu, so the intended
    /// holder is a platform role - but the audience rule that would keep a platform menu off a
    /// company-owned role is switched off service-wide (see the note in
    /// <c>RoleGrantsAppService.ValidateGrantsAsync</c>). A company administrator who holds the role
    /// page can therefore grant that menu, and these two points, to a role in their own company.
    /// Without this guard, what that buys them is every supplier's administrators - user ids,
    /// display names and <i>email addresses</i> - for any code they care to guess, and, with the
    /// manage point, the ability to mount another company's supplier onto their own, which hands
    /// their own members data scope over that supplier downstream. This endpoint has no per-tenant
    /// narrowing to fall back on: it answers for exactly the codes it is asked about.
    /// </para>
    /// <para>
    /// PLATFORM and GLOBAL pass, which is the whole intended audience: a whole-dimension operator
    /// legitimately administers mountings across their dimension, and the platform super
    /// administrator always acts as PLATFORM. Only a single-tenant session is refused, and for a
    /// single-tenant session there is no correct answer to give - the question spans tenants.
    /// </para>
    /// </summary>
    private static void AssertPlatformPlane(IBackOfficeCaller caller, string what)
    {
        var (tenantType, tenantCode, isTenant) = CallerFacts.Tenant(caller);
        if (!isTenant)
        {
            return;
        }

        throw new ForbiddenException(
            ErrorCodes.Forbidden,
            $"A session acting as {tenantType} {tenantCode} may not {what}: the supplier mountings "
            + "are a platform-wide plane, not one tenant's data.");
    }

    /// <summary>What goes into <c>created_by</c> / <c>updated_by</c>: the caller's display name, or
    /// <c>system</c> when the request carries none.</summary>
    private static string Actor(IBackOfficeCaller caller) =>
        string.IsNullOrWhiteSpace(caller.Nickname) ? "system" : caller.Nickname;
}

/// <summary>
/// A mounting as it looked at one point in the audit trail. Property names become the keys of the
/// stored JSON, which the writer spells in snake case.
/// <para>
/// The Go original wrote both payloads null. They are filled here because a relink otherwise loses
/// the only record of which company the supplier hung under: the previous row is retired in the
/// same transaction, and the code it named is exactly what somebody asking "who lost access, and
/// when" needs.
/// </para>
/// </summary>
internal sealed record SupplierLinkAuditSnapshot(string SupplierCode, string CompanyCode, string Status);
