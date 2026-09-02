using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Tenants;
using UserSvc.Application.Features.Registration;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Application.Security;
using UserSvc.Domain.BackOffice;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Application.Features.BackOffice.SignIn;

/// <summary>
/// Back-office sign-in: the two doors an operator comes through, and the decision tree that says
/// what they get once they are through one.
/// <para>
/// <b>It issues no tokens.</b> Credentials come out of the OpenIddict token endpoint and nowhere
/// else (decision 10); what this service produces is a signed
/// <see cref="BackOfficeSignInTicket"/> plus the tenant list the context chooser is drawn from.
/// Splitting it that way is what lets a sign-in keep the ProblemDetails error contract - a refused
/// domain, a locked-out mailbox, an unreachable staff directory are all distinguishable here,
/// where at a token endpoint they would collapse into one <c>invalid_grant</c>.
/// </para>
/// <para>
/// <b>The staff directory is injected as a factory, not as an instance.</b> The real adapter reads
/// validated options when it is built, so injecting it directly would make the password door
/// depend on the corporate one-time-password credentials: a deployment with no staff directory
/// configured would answer 500 to every password sign-in, naming a secret that door does not use
/// (docs/architecture.md, "a missing capability may only break itself").
/// </para>
/// </summary>
public sealed class BackOfficeSignInAppService(
    IBackendUserRepository users,
    IBackendIdentityRepository identities,
    BackOfficeStaffOnboarding onboarding,
    Func<IStaffDirectory> staffDirectory,
    TenantContextAppService contexts,
    BackOfficeContextAppService switcher,
    IAdminStandingService standing,
    IIamAuditLogRepository auditLog,
    IRateLimiter rateLimiter,
    ISingleUseMarkerStore markers,
    IdentifierProtector protector,
    PasswordHasher passwordHasher,
    BackOfficeSignInTicketService tickets,
    IUnitOfWork unitOfWork,
    IClock clock,
    IOptions<Accounts.BackOfficeAccountOptions> accountOptions,
    IOptions<BackOfficeSignInOptions> signInOptions,
    ILogger<BackOfficeSignInAppService> logger)
{
    /// <summary>Rate-limit dimensions. Three, so a password lockout, a per-address lockout's
    /// per-source counterpart and a one-time-password lockout are independent budgets - and all
    /// three are separate from every consumer counter, so one mailbox used on both planes cannot be
    /// locked out of one by hammering the other.</summary>
    private const string PasswordDimension = "backoffice-sign-in";

    /// <summary>
    /// The per-source budget on the password door. A dimension of its own rather than the
    /// <c>login-ip</c> the port's documentation names as an example: that slug would eventually be
    /// shared with consumer sign-in, and one address failing on the consumer plane would then eat
    /// the back office's budget for the whole office behind it.
    /// </summary>
    private const string PasswordIpDimension = "backoffice-sign-in-ip";

    private const string OtpDimension = "backoffice-sign-in-otp";

    /// <summary>What the consume-once marker for a sign-in ticket is filed under.</summary>
    private const string SignInTicketPurpose = "back-office-sign-in-ticket";

    /// <summary>
    /// How much longer than the ticket the consume-once marker lives.
    /// <para>
    /// The marker has to outlast the ticket or a replay lands in the gap, and the gap is exactly
    /// where somebody holding a captured ticket is waiting. The two are measured by different
    /// clocks - the ticket's expiry by whichever pod minted it, the marker's TTL by Redis - so
    /// equal lifetimes are not enough: a minute of skew is generous for machines that are meant to
    /// be NTP-synchronised, and the cost of being generous is one key per sign-in living a minute
    /// longer in a key space that expires itself.
    /// </para>
    /// </summary>
    private static readonly TimeSpan MarkerSkew = TimeSpan.FromMinutes(1);

    /// <summary>Stamped on the rows this flow writes.</summary>
    private const string SystemActor = "system";

    /// <summary>
    /// Sign in with a corporate mailbox and a password.
    /// <para>
    /// The order of the gates is the contract. The lockout check first, because everything after it
    /// costs either a database read or 50 ms of Argon2. Then identity, then the password, then the
    /// account's status, and the corporate domain gate <b>last</b> - after the identity is known,
    /// so an unknown mailbox is answered with "invalid credentials" and never with "your domain is
    /// not allowed", which would confirm the address exists.
    /// </para>
    /// <para>
    /// <b>Every refusal before a real password verify pays for one anyway.</b> The bodies were
    /// already identical; the clock was not. Measured live, an unknown mailbox came back in a
    /// median of 3.6 ms, a wrong password in 52.3 ms and an account with no local password in
    /// 6.0 ms - three states of an account, readable by anybody with a stopwatch and no credential
    /// at all. See <see cref="BackOfficePasswordTiming"/>.
    /// </para>
    /// </summary>
    /// <exception cref="RateLimitedException">Too many failures on this mailbox, or from this
    /// source address.</exception>
    /// <exception cref="UnauthorizedException">Unknown mailbox, wrong password, or an account that
    /// may not sign in.</exception>
    /// <exception cref="ForbiddenException">An internal account presenting a non-corporate mailbox.</exception>
    public async Task<BackOfficeSignInResponse> SignInWithPasswordAsync(
        BackOfficePasswordSignInRequest request,
        BackOfficeSignInContext requestContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(requestContext);

        var normalizedEmail = Accounts.BackOfficeIdentifiers.Normalize(
            BackendIdentityTypes.Email, request.Email);

        var budgets = PasswordBudgets(normalizedEmail, requestContext.IpAddress);

        await RefuseWhenLockedOutAsync(budgets, cancellationToken);

        var identity = await identities.FindActiveAsync(
            BackendIdentityTypes.Email, protector.Hash(normalizedEmail), cancellationToken);

        if (identity is null)
        {
            // Nothing is audited: there is no account row to anchor an entry to, and writing one
            // keyed on the address would persist attacker-chosen text into the audit table.
            logger.LogInformation(
                "A back-office password sign-in named an address with no active identity.");

            throw await RefuseCredentialAsync(budgets, request.Password, cancellationToken);
        }

        var account = await users.FindByIdAsync(identity.UserId, cancellationToken);
        if (account is null)
        {
            logger.LogError(
                "Back-office identity {IdentityId} points at account {BackendUserId}, which does "
                + "not exist. The foreign key makes this impossible unless the row was written "
                + "around it.",
                identity.Id,
                identity.UserId);

            throw await RefuseCredentialAsync(budgets, request.Password, cancellationToken);
        }

        await VerifyPasswordAsync(account, request.Password, budgets, requestContext, cancellationToken);
        await RequireSignInAllowedAsync(account, requestContext, password: true, cancellationToken);
        await EnforceCorporateDomainAsync(account, request.Email, requestContext, cancellationToken);

        var response = await FinishAsync(account, requestContext, canSave: true, cancellationToken);

        // Specification 3.2 step 7. Only the per-address budget: the per-source one counts failures
        // from an address across every mailbox it tries, and clearing it on a success would hand
        // anybody holding one valid account an unlimited spray - four failures, one own sign-in,
        // repeat. See PasswordBudgets.
        await ClearFailuresAsync(
            PasswordDimension, normalizedEmail, budgets.Mailbox, cancellationToken);

        return response;
    }

    /// <summary>
    /// Sign in with the corporate one-time password.
    /// <para>
    /// <b>No domain gate applies here, and that is deliberate rather than an oversight.</b> A code
    /// the corporate directory has just verified <i>is</i> the authorization, and the mailbox it
    /// resolves to comes from the HR record rather than from the caller - there is no
    /// client-supplied address for a domain rule to be about.
    /// </para>
    /// <para>
    /// <b>A disabled account is refused with 403 here and with 401 on the password door.</b> That
    /// asymmetry is inherited from the service being replaced and kept on purpose: on this path
    /// the credential was accepted and it is the account that is closed, which is "stop asking",
    /// while on the password path the two are indistinguishable to the caller and 401 is what tells
    /// a client to re-authenticate rather than to give up.
    /// </para>
    /// </summary>
    /// <exception cref="AppException">The staff directory is not available on this deployment
    /// (501), or answered nothing usable (502). Neither is a failed sign-in and neither is phrased
    /// as one.</exception>
    public async Task<BackOfficeSignInResponse> SignInWithStaffOtpAsync(
        BackOfficeStaffOtpSignInRequest request,
        BackOfficeSignInContext requestContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(requestContext);

        var settings = signInOptions.Value;
        var staffId = request.StaffId.Trim();

        if (staffId.Length == 0)
        {
            throw new BadRequestException(ErrorCodes.ValidationFailed, "An employee number is required.");
        }

        RateLimitPolicy[] otpBudget =
        [
            RateLimitPolicy.PerMinute(settings.OtpAttemptsPerMinute),
            RateLimitPolicy.PerHour(settings.OtpAttemptsPerHour),
        ];

        await ThrottleAsync(
            OtpDimension,
            staffId,
            otpBudget,
            "Too many one-time-password sign-in attempts for this employee number. Try again shortly.",
            cancellationToken);

        // Constructed here rather than injected: see the note on the class. An unconfigured
        // directory throws NOT_CONFIGURED from this line, which is the one place it should.
        var directory = staffDirectory();

        var verification = await directory.VerifyOtpAsync(
            staffId, request.OneTimePassword, cancellationToken);

        if (!verification.IsVerified)
        {
            // The upstream's own codes go to the log so support can tell "expired" from "wrong"
            // from "locked out". Its message is deliberately not returned: it is text another
            // system wrote about a failed credential check, and forwarding it would let that
            // system decide what our sign-in endpoint tells an attacker.
            logger.LogInformation(
                "The staff directory refused a one-time password: result {ResultCode}, info "
                + "{InfoCode}, message {ResultMessage}.",
                verification.ResultCode,
                verification.InfoCode,
                verification.ResultMessage);

            throw new UnauthorizedException(
                ErrorCodes.OtpVerificationFailed, "That one-time password is not valid.");
        }

        var profile = await directory.GetStaffProfileAsync(staffId, cancellationToken);
        var email = profile.Email.Trim();

        if (email.Length == 0)
        {
            // 502 and not a 4xx: the code was correct and the caller did nothing wrong. An HR
            // record with no mailbox cannot become an account, because the mailbox is the account's
            // only login identity on the password door and its only route for credential mail.
            logger.LogError(
                "The staff directory verified a one-time password but its HR record carries no "
                + "mailbox, so no account can be provisioned or matched.");

            throw new UpstreamException(
                ErrorCodes.UpstreamUnavailable,
                "The staff directory returned an incomplete record for this employee.");
        }

        var resolution = await onboarding.ResolveAsync(staffId, email, profile, cancellationToken);
        var account = resolution.Account;

        await RequireSignInAllowedAsync(account, requestContext, password: false, cancellationToken);

        if (resolution.CanSave)
        {
            if (resolution.NeedsOtpIdentity)
            {
                await onboarding.EnsureOtpIdentityAsync(account, staffId, cancellationToken);
            }

            // Refreshed before the branching, so the token and the response carry what HR holds
            // today. The context funnel does not read staff fields, so writing them first cannot
            // change any authority decision below.
            if (onboarding.SyncStaffProfile(account, staffId, profile))
            {
                logger.LogInformation(
                    "Refreshed the HR fields of back-office account {BackendUserId} from the staff "
                    + "directory.",
                    account.Id);
            }
        }

        var response = await FinishAsync(account, requestContext, resolution.CanSave, cancellationToken);

        // Specification 3.3 step 9. This door counts attempts rather than failures - each one costs
        // an upstream call - so without the clear an operator who signs in twice in a minute is
        // three attempts from being locked out of a door they are using correctly. Only consecutive
        // failures should accumulate.
        await ClearFailuresAsync(OtpDimension, staffId, otpBudget, cancellationToken);

        return response;
    }

    /// <summary>
    /// Redeems a sign-in ticket into what the token endpoint should mint. <b>Once.</b>
    /// <para>
    /// <b>The ticket is claimed before anything else happens.</b> Verifying the signature first and
    /// claiming second is the only sound order: claiming on an unauthenticated id would let anybody
    /// write a marker per request into Redis, and doing the account read first would let two
    /// concurrent redemptions of one ticket both get as far as minting. Claiming immediately after
    /// the signature check means a refusal further down still burns the ticket - which is correct.
    /// A disabled account's ticket should not be redeemable a second time either.
    /// </para>
    /// <para>
    /// <b>The account's status is re-read here rather than trusted from the ticket.</b> The window
    /// is small - a ticket lives two minutes - but it is exactly the window in which an
    /// administrator who has just disabled somebody expects them to stop being able to sign in, and
    /// the ticket was signed before that happened.
    /// </para>
    /// </summary>
    /// <exception cref="UnauthorizedException">The ticket is unusable, has already been redeemed,
    /// or the account has since been disabled.</exception>
    /// <exception cref="UpstreamException">It could not be established whether the ticket had
    /// already been redeemed. Fail-closed: see <see cref="ISingleUseMarkerStore"/>.</exception>
    public async Task<BackOfficeTokenGrant> RedeemAsync(string ticket, CancellationToken cancellationToken)
    {
        var opened = tickets.Open(ticket);

        await ConsumeAsync(opened, cancellationToken);

        var account = await users.ReadByIdAsync(opened.UserId, cancellationToken);
        if (account is null)
        {
            logger.LogWarning(
                "A back-office sign-in ticket named account {BackendUserId}, which no longer exists.",
                opened.UserId);

            throw TicketNotUsable();
        }

        if (account.Status == BackendUserStatuses.Disabled)
        {
            throw new UnauthorizedException(ErrorCodes.AccountDisabled, "This account is disabled.");
        }

        return new BackOfficeTokenGrant(
            opened.UserId,
            opened.ActorName,
            account.TokenVersion,
            opened.ToActClaim(),
            opened.ContextRequired);
    }

    /// <summary>
    /// Turns an already-authenticated back-office session's choice of context into what the token
    /// endpoint should mint.
    /// <para>
    /// The decision, every guard behind it and its audit row belong to
    /// <see cref="BackOfficeContextAppService.SelectContextAsync"/> - the same code path the REST
    /// context endpoint runs, so a rule added there cannot apply on one route and be missing on the
    /// other. What is left here is reading the resulting act back out and pairing it with the
    /// account's current token version.
    /// </para>
    /// </summary>
    public async Task<BackOfficeTokenGrant> SelectContextAsync(
        BackOfficeCaller caller,
        SelectTenantContextRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(caller);

        var userId = caller.RequireUserId();
        var selected = await switcher.SelectContextAsync(caller, request, cancellationToken);

        var account = await users.ReadByIdAsync(userId, cancellationToken)
                      ?? throw new NotFoundException(
                          ErrorCodes.UserNotFound, "The back-office account was not found.");

        var act = ActFrom(selected)
                  ?? throw new AppException(
                      ErrorCodes.InternalError,
                      "The chosen context resolved to no acting context at all.",
                      500);

        return new BackOfficeTokenGrant(
            userId,
            Accounts.BackOfficeNames.DisplayName(account.FirstName, account.LastName, account.Nickname),
            account.TokenVersion,
            act,
            IsPreTenant: false);
    }

    // ------------------------------------------------------------------ the decision tree

    /// <summary>
    /// What a signed-in operator gets, and the one place that decides it.
    /// <para>
    /// Four outcomes, and three of them are branches that look wrong until you have watched them
    /// go wrong the other way.
    /// </para>
    /// <list type="number">
    /// <item><description>
    /// <b>An account that is not ACTIVE signs in and is handed nothing.</b> Not a refusal: a
    /// PENDING account is somebody midway through onboarding, and a 401 makes a brand-new account
    /// look broken to the person who has just been told to log in and finish setting it up. They
    /// get a session with an empty authority surface, which closes every gate in the product while
    /// still letting the shell render and say why.
    /// </description></item>
    /// <item><description>
    /// <b>The platform super administrator is offered no choice at all.</b> The flag is re-read
    /// from the database rather than believed from anything the caller sent, and it resolves
    /// straight to the platform context with an <i>empty</i> tenant list - the switcher draws a
    /// badge rather than a menu with one item in it.
    /// </description></item>
    /// <item><description>
    /// <b>An account with no context signs in too.</b> Zero options is the same outcome as
    /// PENDING: a session with nothing granted. Refusing it - which is what the service being
    /// replaced used to do - made every freshly created account look defective in the minutes
    /// before an administrator added it to a tenant.
    /// </description></item>
    /// <item><description>
    /// <b>Exactly one option is entered automatically, and a whole dimension counts as one.</b> So
    /// somebody whose only access is "every company" lands in that dimension without being asked,
    /// and somebody who holds both a dimension and a single company is asked - because that is two
    /// places to be, not one.
    /// </description></item>
    /// </list>
    /// <para>
    /// The options are counted <b>after</b> the master data has had its say, which is what stops a
    /// one-company operator being dropped into a company that has been switched off. That filter
    /// fails open, so during a master-data outage every tenant counts - deliberately: locking the
    /// whole back office out of every tenant because one upstream is unreachable is the worse
    /// failure, and the member row plus the permission codes are the real boundary.
    /// </para>
    /// </summary>
    private async Task<BackOfficeSignInResponse> FinishAsync(
        BackendUser account,
        BackOfficeSignInContext requestContext,
        bool canSave,
        CancellationToken cancellationToken)
    {
        var actorName = Accounts.BackOfficeNames.DisplayName(
            account.FirstName, account.LastName, account.Nickname);

        var response = await ResolveOutcomeAsync(account, actorName, cancellationToken);

        // Audited only when the sign-in actually finished. A pre-tenant outcome is half a sign-in:
        // its later choice of context is recorded as TENANT_SWITCH by the endpoint that makes it,
        // and auditing both would count one arrival twice.
        if (!response.ContextRequired)
        {
            await WriteSignInAsync(account, actorName, response.ActiveTenant, requestContext, cancellationToken);
        }

        await TouchLastSeenAsync(account, canSave, cancellationToken);

        return response;
    }

    private async Task<BackOfficeSignInResponse> ResolveOutcomeAsync(
        BackendUser account, string actorName, CancellationToken cancellationToken)
    {
        if (account.Status != BackendUserStatuses.Active)
        {
            logger.LogInformation(
                "Back-office account {BackendUserId} signed in with status {Status}; it holds a "
                + "session and no authority.",
                account.Id,
                account.Status);

            return NoAccess(account, actorName, isGlobal: false, tenants: []);
        }

        if (await standing.IsPlatformSuperAdminAsync(account.Id, cancellationToken))
        {
            var platform = await contexts.ComputeAsync(
                account.Id, new ActClaim(ActTypes.Platform), cancellationToken);

            return WithContext(account, actorName, platform, isGlobal: true, tenants: []);
        }

        var caller = new BackOfficeCaller(account.Id, actorName, null, account.TokenVersion);
        var listing = await switcher.ListTenantsAsync(caller, cancellationToken);
        var options = listing.Tenants;

        if (options.Count == 0)
        {
            logger.LogInformation(
                "Back-office account {BackendUserId} signed in with no context to enter; it holds a "
                + "session and no authority.",
                account.Id);

            return NoAccess(account, actorName, listing.IsGlobal, tenants: []);
        }

        if (options.Count == 1)
        {
            var only = options[0];
            var act = only.ScopeAll
                ? new ActClaim(ActTypes.Global, Dimension: only.TenantType)
                : new ActClaim(ActTypes.ForTenantType(only.TenantType), only.TenantCode);

            var resolved = await contexts.ComputeAsync(account.Id, act, cancellationToken);

            return WithContext(account, actorName, resolved, listing.IsGlobal, options);
        }

        return PreTenant(account, actorName, listing.IsGlobal, options);
    }

    // ------------------------------------------------------------------ the three response shapes

    /// <summary>
    /// A session that carries no authority. Every collection is stated as empty rather than left
    /// out: the front end reads a missing menu list as "this backend does not gate menus" and opens
    /// everything, while an empty one says "nothing is granted" and closes the gates.
    /// </summary>
    private BackOfficeSignInResponse NoAccess(
        BackendUser account,
        string actorName,
        bool isGlobal,
        IReadOnlyList<TenantSummaryResponse> tenants) =>
        Build(
            account,
            BackOfficeSignInTicket.ForContext(account.Id, actorName, account.TokenVersion, act: null),
            contextRequired: false,
            isGlobal,
            tenants,
            TenantContextResult.NoAccess());

    private BackOfficeSignInResponse WithContext(
        BackendUser account,
        string actorName,
        TenantContextResult result,
        bool isGlobal,
        IReadOnlyList<TenantSummaryResponse> tenants) =>
        Build(
            account,
            BackOfficeSignInTicket.ForContext(account.Id, actorName, account.TokenVersion, result.Act),
            contextRequired: false,
            isGlobal,
            tenants,
            result);

    /// <summary>
    /// A sign-in that has authenticated but not chosen where to act. It carries the option list and
    /// nothing else - no roles, no permissions, no menus, no scopes - because none of those exist
    /// until a context does, and inventing a widest-guess surface here is how a chooser screen ends
    /// up rendering an administrator's menu tree.
    /// </summary>
    private BackOfficeSignInResponse PreTenant(
        BackendUser account,
        string actorName,
        bool isGlobal,
        IReadOnlyList<TenantSummaryResponse> tenants) =>
        Build(
            account,
            BackOfficeSignInTicket.PreTenant(account.Id, actorName, account.TokenVersion),
            contextRequired: true,
            isGlobal,
            tenants,
            TenantContextResult.NoAccess());

    private BackOfficeSignInResponse Build(
        BackendUser account,
        BackOfficeSignInTicket ticket,
        bool contextRequired,
        bool isGlobal,
        IReadOnlyList<TenantSummaryResponse> tenants,
        TenantContextResult result) =>
        new()
        {
            UserId = account.Id,
            ContextRequired = contextRequired,
            SignInTicket = tickets.Issue(ticket),
            TicketExpiresIn = (int)signInOptions.Value.SignInTicketLifetime.TotalSeconds,
            GrantedScope = contextRequired
                ? BackOfficeSignInScopes.PreTenant
                : BackOfficeSignInScopes.BackOffice,
            Origin = account.Origin,
            IsGlobal = isGlobal,
            Tenants = tenants,
            User = new BackOfficeUserResponse
            {
                Id = account.Id,
                FirstName = account.FirstName ?? string.Empty,
                LastName = account.LastName ?? string.Empty,
                Nickname = Accounts.BackOfficeNames.DisplayName(
                    account.FirstName, account.LastName, account.Nickname),
                StaffCode = account.StaffCode ?? string.Empty,
                Status = account.Status,
                LastLoginAt = account.LastLoginAt,
            },
            ActiveTenant = ActiveTenantFrom(result.Act, result.Scopes),
            IsTenantAdmin = result.Act?.IsAdmin ?? false,
            Roles = result.Roles,
            Permissions = result.Permissions,
            Menus = result.Menus,
            Scopes = result.Scopes,
        };

    // ------------------------------------------------------------------ gates

    /// <summary>
    /// Checks the password, and says so out loud when the stored value is not one this service can
    /// read.
    /// <para>
    /// <see cref="PasswordHasher.Verify"/> answers false for a malformed stored hash exactly as it
    /// does for a wrong password, which is the right answer to give a caller and the wrong one to
    /// leave in a log: "nobody can sign in to this account" would otherwise be a fact only its
    /// owner ever discovers. The hasher holds no logger because it is pure computation, so this is
    /// the place that has to notice.
    /// </para>
    /// </summary>
    private async Task VerifyPasswordAsync(
        BackendUser account,
        string password,
        PasswordBudget budgets,
        BackOfficeSignInContext requestContext,
        CancellationToken cancellationToken)
    {
        if (!account.HasPassword())
        {
            // Not a distinct error code. An account provisioned through the staff directory has no
            // local password, and saying so would tell an anonymous caller which door to use for
            // any address they can guess.
            logger.LogInformation(
                "Back-office account {BackendUserId} has no local password; the password door is "
                + "closed for it until it registers one.",
                account.Id);

            await WriteFailureAsync(
                account, BackOfficeSignInFailureReasons.InvalidPassword, requestContext, cancellationToken);

            // The third timing class, and the one the wave-6 report did not name: this path used to
            // return in 6.0 ms against 52.3 ms for a wrong password, so "this address exists and
            // signs in through the corporate one-time password" was readable off the clock. The
            // response has always been identical; now the cost is too.
            throw await RefuseCredentialAsync(budgets, password, cancellationToken);
        }

        var stored = account.PasswordHash!;

        if (!passwordHasher.Verify(password, stored))
        {
            if (!stored.StartsWith("$argon2id$", StringComparison.Ordinal))
            {
                logger.LogError(
                    "The stored password of back-office account {BackendUserId} is not an Argon2id "
                    + "PHC string, so no password can ever verify against it. This row needs "
                    + "rehashing; until then its owner is locked out and every attempt reads as a "
                    + "wrong password.",
                    account.Id);
            }

            await WriteFailureAsync(
                account, BackOfficeSignInFailureReasons.InvalidPassword, requestContext, cancellationToken);

            // No equalising verify here: this path has just paid for a real one. Adding it would
            // make a wrong password cost twice what a right one does, which is a new oracle in the
            // other direction - and two concurrent 19 MiB derivations per attempt rather than one.
            await CountFailureAsync(budgets, cancellationToken);

            throw InvalidCredentials();
        }
    }

    /// <summary>
    /// Whether this account may hold a session at all, on either door.
    /// <para>
    /// <b>Both doors run the same gate, and both audit the refusal.</b> The service being replaced
    /// checked only DISABLED on the one-time-password path and wrote no row for it - but a blocked
    /// staff member still presenting a valid corporate code is exactly the event an operator wants
    /// to find, and it cannot be used to flood the table: the code was verified upstream before
    /// this runs, so an attacker cannot produce a row without a working credential. The status
    /// codes stay different per door, which is the asymmetry the specification does state.
    /// </para>
    /// <para>
    /// PENDING passes here on both doors on purpose. What refuses a PENDING account is not this
    /// gate but the decision tree, which hands it a session with no authority so onboarding can
    /// finish - locking it out of the door it was told to use would be the older, worse behaviour.
    /// </para>
    /// </summary>
    private async Task RequireSignInAllowedAsync(
        BackendUser account,
        BackOfficeSignInContext requestContext,
        bool password,
        CancellationToken cancellationToken)
    {
        if (account.Status == BackendUserStatuses.Disabled)
        {
            await WriteFailureAsync(
                account, BackOfficeSignInFailureReasons.AccountDisabled, requestContext, cancellationToken);

            // 401 on the password door - see the note on the one-time-password method for why that
            // one answers 403 instead.
            throw password
                ? new UnauthorizedException(ErrorCodes.AccountDisabled, "This account is disabled.")
                : new ForbiddenException(ErrorCodes.AccountDisabled, "This account is disabled.");
        }

        // ACTIVE and PENDING may both sign in; anything else may not. The database CHECK
        // constraint allows no fourth value, which is precisely why this branch exists: if one
        // ever appears - a hand-written UPDATE, a future status added to the constraint and not to
        // this file - the safe reading is "not allowed to sign in", not "treated as PENDING".
        if (account.Status != BackendUserStatuses.Active
            && account.Status != BackendUserStatuses.Pending)
        {
            logger.LogError(
                "Back-office account {BackendUserId} carries status {Status}, which this build does "
                + "not recognise. Refusing the sign-in.",
                account.Id,
                account.Status);

            await WriteFailureAsync(
                account, BackOfficeSignInFailureReasons.AccountInactive, requestContext, cancellationToken);

            throw new UnauthorizedException(ErrorCodes.AccountInactive, "This account is not active.");
        }
    }

    /// <summary>
    /// The corporate domain allow-list, applied to internal accounts only.
    /// <para>
    /// An external partner - a supplier, an agency - authenticates with whatever mailbox they have,
    /// so the gate reads the account's own origin rather than the address. It runs after the
    /// identity lookup on purpose: an unknown address must never reach it, or the difference
    /// between "no such account" and "wrong domain" becomes an oracle for which addresses exist.
    /// </para>
    /// </summary>
    private async Task EnforceCorporateDomainAsync(
        BackendUser account,
        string email,
        BackOfficeSignInContext requestContext,
        CancellationToken cancellationToken)
    {
        if (account.Origin == BackendUserOrigins.External)
        {
            return;
        }

        var allowed = Accounts.BackOfficeNames.InternalDomains(accountOptions.Value.InternalDomains);
        if (Accounts.BackOfficeNames.EmailInDomains(email, allowed))
        {
            return;
        }

        await WriteFailureAsync(
            account, BackOfficeSignInFailureReasons.InvalidDomain, requestContext, cancellationToken);

        // The allow-list is named in the message: it is configuration a client renders, not a
        // secret, and it says nothing about any account. By this point the caller has already
        // proved they hold this account's password.
        throw new ForbiddenException(
            ErrorCodes.InvalidDomain,
            "This account may only sign in with a corporate email address "
            + $"({string.Join(", ", allowed)}).");
    }

    // ------------------------------------------------------------------ side effects

    /// <summary>
    /// Counts the attempt against a per-subject budget and refuses when it is spent. The
    /// one-time-password door's throttle, and the only one that still counts <i>attempts</i>.
    /// <para>
    /// <b>That is deliberate here and wrong on the password door.</b> Specification 3.3 step 1
    /// counts every one-time-password attempt, and the reason is in what an attempt costs: each one
    /// is an HTTP call to the corporate directory and a code somebody was sent, so arriving at all
    /// is the thing worth bounding. A password attempt costs us a hash and nothing else, so there
    /// the budget is a lockout - see <see cref="RefuseWhenLockedOutAsync"/>. Both doors clear the
    /// budget on a successful sign-in (steps 7 and 9), which is what stops an operator who signs in
    /// repeatedly from being throttled for it.
    /// </para>
    /// <para>
    /// The minute window is evaluated first and a refusal stops there. Each call spends a unit of
    /// its own budget, so carrying on to the hour window after the minute window has already said
    /// no charges the hour for a request that was never served - and a client retrying into a
    /// one-minute block would burn its whole hour that way, turning a short throttle into a long
    /// one.
    /// </para>
    /// </summary>
    private async Task ThrottleAsync(
        string dimension,
        string key,
        IReadOnlyList<RateLimitPolicy> policies,
        string message,
        CancellationToken cancellationToken)
    {
        foreach (var policy in policies)
        {
            var decision = await rateLimiter.TryAcquireAsync(dimension, key, policy, cancellationToken);
            if (!decision.Allowed)
            {
                throw new RateLimitedException(ErrorCodes.RateLimitExceeded, message, decision.RetryAfter);
            }
        }
    }

    // ------------------------------------------------------------- the password door's two budgets

    /// <summary>
    /// The two independent budgets a password attempt is measured against, and the subjects they
    /// are measured on.
    /// <para>
    /// <b>Both count failures rather than attempts, and only one of them is cleared by a
    /// success.</b> The per-address budget is a lockout for one mailbox and is cleared when its
    /// owner finally types the right password (specification 3.2 step 7). The per-source budget is
    /// not: clearing it would mean anybody holding one working back-office account could spray as
    /// much as they liked - fail four times, sign into their own account, repeat - and the whole
    /// point of the per-source dimension is that it survives the attacker having a valid credential
    /// of their own.
    /// </para>
    /// </summary>
    /// <param name="Mailbox">Windows for the normalized address.</param>
    /// <param name="Source">Windows for the client address, empty when there is none to attribute to.</param>
    /// <param name="Email">The normalized address, as the counter's subject.</param>
    /// <param name="Ip">The client address, as the counter's subject.</param>
    private sealed record PasswordBudget(
        IReadOnlyList<RateLimitPolicy> Mailbox,
        IReadOnlyList<RateLimitPolicy> Source,
        string Email,
        string Ip);

    /// <summary>
    /// Reads the configured budgets for this attempt.
    /// <para>
    /// <b>The client address comes from <see cref="BackOfficeSignInContext.IpAddress"/></b>, which
    /// the API layer fills from the same place the rest of the service resolves a peer address -
    /// the socket, since nothing in this host registers the forwarded-headers middleware (see
    /// <c>RequestContext.ClientIp</c>). A second, private <c>X-Forwarded-For</c> parse here would
    /// be a second trust model: this one would believe a header the audit trail does not, so a
    /// spray could pick a fresh budget per request by inventing one while the audit rows kept
    /// recording the gateway. When the host does start trusting a proxy, both move together.
    /// </para>
    /// <para>
    /// <b>An empty address disables the per-source budget rather than sharing one bucket.</b> Every
    /// request that arrives without an attributable peer - a unit test, a Unix socket, some future
    /// transport - would otherwise count into the same counter, and the first few would lock out
    /// all the others. A budget that cannot name its subject is not a budget.
    /// </para>
    /// </summary>
    private PasswordBudget PasswordBudgets(string normalizedEmail, string clientIp)
    {
        var settings = signInOptions.Value;

        RateLimitPolicy[] mailbox =
        [
            RateLimitPolicy.PerMinute(settings.PasswordFailuresPerMinute),
            RateLimitPolicy.PerHour(settings.PasswordFailuresPerHour),
        ];

        RateLimitPolicy[] source = string.IsNullOrWhiteSpace(clientIp)
            ? []
            :
            [
                RateLimitPolicy.PerMinute(settings.PasswordFailuresPerSourcePerMinute),
                RateLimitPolicy.PerHour(settings.PasswordFailuresPerSourcePerHour),
            ];

        return new PasswordBudget(mailbox, source, normalizedEmail, clientIp);
    }

    /// <summary>
    /// Refuses an attempt whose subject has already spent its failure budget, without spending any
    /// of it to find out.
    /// <para>
    /// <b>A read, not a count</b> - which is the whole difference between a lockout and an attempt
    /// budget. Counting here is what made a correct password spend budget, so the configured 10 a
    /// minute described a human who mistypes rather than the five-strikes lockout the numbers were
    /// chosen for.
    /// </para>
    /// <para>
    /// <b>The address is checked before the source, and the first refusal stops everything.</b>
    /// Order matters twice over: <see cref="IRateLimiter"/> requires a caller enforcing several
    /// policies to stop at the first refusal, and the messages differ - somebody who has locked
    /// their own mailbox needs to be told about their mailbox, not about the office they share an
    /// address with.
    /// </para>
    /// </summary>
    private async Task RefuseWhenLockedOutAsync(
        PasswordBudget budgets, CancellationToken cancellationToken)
    {
        await RefuseWhenSpentAsync(
            PasswordDimension,
            budgets.Email,
            budgets.Mailbox,
            "Too many failed sign-in attempts for this address. Try again shortly.",
            cancellationToken);

        await RefuseWhenSpentAsync(
            PasswordIpDimension,
            budgets.Ip,
            budgets.Source,
            "Too many failed sign-in attempts from this network. Try again shortly.",
            cancellationToken);
    }

    private async Task RefuseWhenSpentAsync(
        string dimension,
        string key,
        IReadOnlyList<RateLimitPolicy> policies,
        string message,
        CancellationToken cancellationToken)
    {
        foreach (var policy in policies)
        {
            var decision = await rateLimiter.PeekAsync(dimension, key, policy, cancellationToken);
            if (!decision.Allowed)
            {
                throw new RateLimitedException(ErrorCodes.RateLimitExceeded, message, decision.RetryAfter);
            }
        }
    }

    /// <summary>
    /// Records one credential failure against every window of both budgets.
    /// <para>
    /// <b>Every window is counted, and the decisions are discarded</b>, which is the one case
    /// <see cref="IRateLimiter"/> exempts from its stop-at-the-first-refusal rule: this is a tally
    /// of something that has already happened, not a gate. Stopping at the minute window would
    /// leave the hour window empty for a subject failing steadily at just under the minute rate -
    /// which is exactly the shape of a patient attack, and the reason the hour window exists.
    /// </para>
    /// </summary>
    private async Task CountFailureAsync(PasswordBudget budgets, CancellationToken cancellationToken)
    {
        foreach (var policy in budgets.Mailbox)
        {
            _ = await rateLimiter.TryAcquireAsync(
                PasswordDimension, budgets.Email, policy, cancellationToken);
        }

        foreach (var policy in budgets.Source)
        {
            _ = await rateLimiter.TryAcquireAsync(
                PasswordIpDimension, budgets.Ip, policy, cancellationToken);
        }
    }

    /// <summary>
    /// The one exit every refusal before a real password verify goes through: count the failure,
    /// spend the missing Argon2id cost, and hand back the exception for the caller to throw.
    /// <para>
    /// It returns the exception rather than throwing it so that the compiler can see the calling
    /// branch ends - <c>throw await RefuseCredentialAsync(...)</c> reads as the exit it is, and a
    /// method that merely always threw would leave every call site needing an unreachable
    /// <c>return</c> after it.
    /// </para>
    /// <para>
    /// <b>The order inside is deliberate.</b> The verify goes last, so the failure is recorded
    /// even if the request is abandoned during the 50 ms it takes - otherwise a client that hangs
    /// up on every attempt would never fill the budget it is exhausting.
    /// </para>
    /// </summary>
    private async Task<UnauthorizedException> RefuseCredentialAsync(
        PasswordBudget budgets, string password, CancellationToken cancellationToken)
    {
        await CountFailureAsync(budgets, cancellationToken);

        BackOfficePasswordTiming.SpendVerifyCost(passwordHasher, password);

        return InvalidCredentials();
    }

    /// <summary>
    /// Clears a subject's failure budget after it has authenticated correctly.
    /// <para>
    /// Best effort by contract: <see cref="IRateLimiter.ResetAsync"/> swallows a store failure and
    /// logs it, because by this point the sign-in has already been decided and a bookkeeping write
    /// must not fail a request that succeeded. What is lost when it fails is bounded and errs the
    /// safe way - the counter stands, so this subject may still be refused for the rest of the
    /// window despite having just proved its password.
    /// </para>
    /// </summary>
    private Task ClearFailuresAsync(
        string dimension,
        string key,
        IReadOnlyList<RateLimitPolicy> policies,
        CancellationToken cancellationToken) =>
        rateLimiter.ResetAsync(dimension, key, policies, cancellationToken);

    /// <summary>
    /// Records the arrival. The tenant columns come from the context the sign-in resolved, so a
    /// row says which company or supplier the operator walked into; a platform, whole-dimension or
    /// no-authority sign-in belongs to no tenant and leaves them empty rather than inventing one.
    /// </summary>
    private Task WriteSignInAsync(
        BackendUser account,
        string actorName,
        ActiveTenantResponse? activeTenant,
        BackOfficeSignInContext requestContext,
        CancellationToken cancellationToken)
    {
        var (tenantType, tenantCode) = activeTenant switch
        {
            { Type: "company" } tenant => (TenantTypes.Company, tenant.CompanyCode),
            { Type: "supplier" } tenant => (TenantTypes.Supplier, tenant.SupplierCode),
            _ => (string.Empty, string.Empty),
        };

        return AppendAsync(
            new Domain.Iam.IamAuditLog
            {
                ActorUserId = account.Id,
                ActorName = actorName,
                TenantType = tenantType,
                TenantCode = tenantCode,
                Action = BackOfficeSignInAuditActions.SignIn,
                TargetType = Domain.Iam.IamAuditTargetTypes.User,
                TargetId = account.Id.ToString(CultureInfo.InvariantCulture),
                Ip = requestContext.IpAddress,
                RequestId = requestContext.RequestId,
                CreatedAt = clock.UtcNow,
            },
            cancellationToken);
    }

    /// <summary>
    /// Records a refusal, with the reason and nothing else - see
    /// <see cref="BackOfficeSignInFailureReasons"/> for why the credential itself never appears.
    /// <para>
    /// <b>The tenant columns are left empty rather than stamped "platform".</b> A refused sign-in
    /// happened before any context existed, so it belongs to no tenant at all - which is the same
    /// answer <see cref="WriteSignInAsync"/> writes for a platform, whole-dimension or
    /// no-authority arrival. Stamping the literal would put failed sign-ins into the result of
    /// every "what happened at platform level" query, beside the administrative actions that are
    /// genuinely scoped there.
    /// </para>
    /// </summary>
    private Task WriteFailureAsync(
        BackendUser account,
        string reason,
        BackOfficeSignInContext requestContext,
        CancellationToken cancellationToken) =>
        AppendAsync(
            new Domain.Iam.IamAuditLog
            {
                ActorUserId = account.Id,
                ActorName = Accounts.BackOfficeNames.DisplayName(
                    account.FirstName, account.LastName, account.Nickname),
                TenantType = string.Empty,
                TenantCode = string.Empty,
                Action = BackOfficeSignInAuditActions.SignInFailed,
                TargetType = Domain.Iam.IamAuditTargetTypes.User,
                TargetId = account.Id.ToString(CultureInfo.InvariantCulture),
                AfterData = JsonSerializer.Serialize(
                    new Dictionary<string, string>(StringComparer.Ordinal) { ["reason"] = reason }),
                Ip = requestContext.IpAddress,
                RequestId = requestContext.RequestId,
                CreatedAt = clock.UtcNow,
            },
            cancellationToken);

    /// <summary>
    /// Appends an audit row, best effort.
    /// <para>
    /// Swallowed because the thing it describes has already happened: a refusal is about to be
    /// returned whatever this does, and an arrival is about to be answered with a ticket. Logged at
    /// Error rather than Warning because a missing sign-in row is a real gap in the one trail that
    /// answers "who got in, and from where".
    /// </para>
    /// </summary>
    private async Task AppendAsync(Domain.Iam.IamAuditLog entry, CancellationToken cancellationToken)
    {
        try
        {
            await auditLog.AppendAsync(entry, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(
                ex,
                "The {Action} audit row for back-office account {BackendUserId} could not be "
                + "written. The trail is missing this event.",
                entry.Action,
                entry.ActorUserId);
        }
    }

    /// <summary>
    /// Records that the account was used, and tolerates not being able to.
    /// <para>
    /// A failure here is logged and dropped: the operator is signed in either way, and refusing a
    /// completed sign-in because a timestamp would not write is the wrong trade. It is skipped
    /// entirely when the unit of work is no longer writable - see
    /// <see cref="StaffAccountResolution.CanSave"/>.
    /// </para>
    /// </summary>
    private async Task TouchLastSeenAsync(
        BackendUser account, bool canSave, CancellationToken cancellationToken)
    {
        if (!canSave)
        {
            logger.LogWarning(
                "Skipped the last-login write for back-office account {BackendUserId}: this unit of "
                + "work already failed a write and cannot be flushed. It lands at the next sign-in.",
                account.Id);

            return;
        }

        account.LastLoginAt = clock.UtcNow;
        account.UpdatedAt = clock.UtcNow;
        account.UpdatedBy = SystemActor;

        try
        {
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(
                ex,
                "Could not record the sign-in of back-office account {BackendUserId}. The sign-in "
                + "itself stands.",
                account.Id);
        }
    }

    /// <summary>
    /// Where a session is acting, for the sign-in response. A supplier context also reports the
    /// company its supplier hangs off, which is only knowable from the data-scope envelope and not
    /// from the act claim.
    /// </summary>
    private static ActiveTenantResponse? ActiveTenantFrom(
        ActClaim? act, IReadOnlyDictionary<string, ScopeClaim>? scopes)
    {
        if (act is null)
        {
            return null;
        }

        var response = new ActiveTenantResponse
        {
            Type = act.Type.ToLowerInvariant(),
            Dimension = act.Dimension,
        };

        return act.Type switch
        {
            ActTypes.Company => response with { CompanyCode = act.Code },
            ActTypes.Supplier => response with
            {
                SupplierCode = act.Code,
                CompanyCode = scopes?.GetValueOrDefault(TenantTypes.Company, ScopeClaim.None)
                    .Values.FirstOrDefault() ?? string.Empty,
            },
            _ => response,
        };
    }

    /// <summary>
    /// Reads the act back out of a context response. The response states where the session is
    /// acting rather than the claim itself, so this is the inverse of
    /// <see cref="ActiveTenantFrom"/> - and it is deliberately narrow: only a real tenant or
    /// dimension context can be exchanged for a token here.
    /// </summary>
    private static ActClaim? ActFrom(TenantContextResponse selected) =>
        selected.ActiveTenant switch
        {
            null => null,
            { Type: "company" } tenant => new ActClaim(
                ActTypes.Company, tenant.CompanyCode, tenant.Dimension, selected.IsTenantAdmin),
            { Type: "supplier" } tenant => new ActClaim(
                ActTypes.Supplier, tenant.SupplierCode, tenant.Dimension, selected.IsTenantAdmin),
            { Type: "global" } tenant => new ActClaim(
                ActTypes.Global, string.Empty, tenant.Dimension, selected.IsTenantAdmin),
            { Type: "platform" } => new ActClaim(ActTypes.Platform),
            _ => null,
        };

    /// <summary>
    /// Spends the ticket, or refuses.
    /// <para>
    /// <b>A replay is answered in exactly the words an expired or forged ticket is answered in.</b>
    /// Saying "this ticket has already been used" would confirm to whoever intercepted it that they
    /// had intercepted a real one, and that the legitimate holder had got there first. The log line
    /// says which it was, at Warning: a second redemption inside a two-minute window is not a
    /// client retrying, it is either a bug in a client or somebody holding a credential they should
    /// not have.
    /// </para>
    /// </summary>
    private async Task ConsumeAsync(
        BackOfficeSignInTicket opened, CancellationToken cancellationToken)
    {
        var claimed = await markers.TryClaimAsync(
            SignInTicketPurpose,
            opened.TicketId,
            signInOptions.Value.SignInTicketLifetime + MarkerSkew,
            cancellationToken);

        if (claimed)
        {
            return;
        }

        logger.LogWarning(
            "A back-office sign-in ticket for account {BackendUserId} was presented a second time "
            + "and refused. A ticket is redeemable once; a repeat means a client is retrying a "
            + "token request it already completed, or somebody else is holding the ticket.",
            opened.UserId);

        throw TicketNotUsable();
    }

    private static UnauthorizedException InvalidCredentials() =>
        new(ErrorCodes.InvalidCredentials, "That email address and password do not match.");

    /// <summary>One sentence for every unusable ticket - malformed, forged, expired, already
    /// redeemed, or naming an account that has gone. The redeeming grant turns all of them into one
    /// OAuth <c>invalid_grant</c>, and none of them tells a caller something they did not know.</summary>
    private static UnauthorizedException TicketNotUsable() =>
        new(ErrorCodes.InvalidToken, "The sign-in ticket has expired or is not valid. Sign in again.");
}

/// <summary>
/// The two OAuth scopes a back-office sign-in can produce, stated in the sign-in response so a
/// client asks the token endpoint for the one it is actually going to get.
/// <para>
/// <b>These strings are the same two the API layer's authorization policies are built on</b>, and
/// they are duplicated here rather than shared because the constants live in the API project,
/// which the application layer must not reference. If they ever drift, a sign-in advertises a scope
/// the token endpoint refuses - which is why the unit tests assert the literals.
/// </para>
/// </summary>
public static class BackOfficeSignInScopes
{
    public const string BackOffice = "backoffice";

    public const string PreTenant = "backoffice_pre_tenant";
}
