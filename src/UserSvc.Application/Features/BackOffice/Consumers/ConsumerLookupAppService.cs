using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Rbac;
using UserSvc.Application.Features.Registration;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Users;
using UserSvc.Application.Security;

namespace UserSvc.Application.Features.BackOffice.Consumers;

/// <summary>
/// Resolves one exact phone number or email address to a consumer account summary, so an operator
/// holding a contact detail can find the id the test whitelist asks for.
/// <para>
/// <b>Exact match is a storage constraint, not a product decision.</b> Consumer identifiers are
/// stored encrypted, and the only queryable index over them is a deterministic HMAC - it answers
/// equality and nothing else. A partial contact detail simply does not hash to the stored value, so
/// it surfaces as "no such account" rather than as a near miss, and there is no prefix or substring
/// search to offer. That is also the property worth keeping: a search that decrypted rows to find a
/// match would read every consumer's address to answer one operator's question, and it would make
/// enumeration possible where hashing makes it arithmetic-hard.
/// </para>
/// <para>
/// <b>The guard is the platform super-administrator flag, read from the database per request</b>
/// rather than a permission code. That is deliberate and is the same decision the test whitelist
/// makes: the audience is one boolean on one account row, a permission point granted to exactly
/// that boolean would be an indirection with no payoff, and reading the flag live means revoking it
/// takes effect on the next request instead of at the holder's next token refresh.
/// </para>
/// </summary>
public sealed class ConsumerLookupAppService(
    AdminScopeService adminScopes,
    IUserIdentityRepository identities,
    IdentifierProtector protector,
    ConsumerSummaryService summaries)
{
    /// <summary>The longest contact detail this endpoint will consider, matching the Go query
    /// DTO's <c>max=100</c> binding. The longest value that can actually be stored is far
    /// shorter.</summary>
    public const int MaxIdentifierLength = 100;

    /// <summary>
    /// The account behind one contact detail.
    /// </summary>
    /// <param name="caller">The back-office caller, whose super-administrator standing is re-read
    /// from the database.</param>
    /// <param name="identityType"><c>phone</c> or <c>email</c>, case-insensitive.</param>
    /// <param name="identifier">The complete contact detail. Normalized exactly as registration
    /// normalizes it, because the blind index is a hash of that spelling and no other.</param>
    /// <param name="cancellationToken">Cancels the reads.</param>
    public async Task<ConsumerSummaryResponse> LookupAsync(
        IBackOfficeCaller caller,
        string? identityType,
        string? identifier,
        CancellationToken cancellationToken)
    {
        await adminScopes.AssertPlatformSuperAdminAsync(caller, cancellationToken);

        var type = identityType ?? string.Empty;
        if (!IdentifierNormalizer.IsSupportedIdentityType(type))
        {
            throw new BadRequestException(
                ErrorCodes.BadRequest, "The identity type must be 'phone' or 'email'.");
        }

        var value = identifier ?? string.Empty;
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new BadRequestException(ErrorCodes.BadRequest, "A contact detail is required.");
        }

        if (value.Length > MaxIdentifierLength)
        {
            // The Go contract binds max=100 on this parameter and it is worth keeping - not because
            // a value that long could match (none is stored), but because this endpoint is
            // reachable with an arbitrary query string and everything that gets past here is
            // normalized and HMAC'd. Refusing at the edge bounds that work by the contract rather
            // than by whatever the caller sent.
            throw new BadRequestException(
                ErrorCodes.BadRequest,
                $"A contact detail may not exceed {MaxIdentifierLength} characters.");
        }

        var resolvedType = IdentifierNormalizer.ResolveIdentityType(type);
        var normalized = IdentifierNormalizer.Normalize(resolvedType, value);

        // One indexed equality read on the blind index. Nothing is decrypted to get here, and a
        // wrong or partial value is indistinguishable from an address nobody registered - which is
        // the correct answer to give an operator either way.
        var identity = await identities.FindActiveAsync(
            resolvedType, protector.Hash(normalized), cancellationToken);

        if (identity is null)
        {
            throw new NotFoundException(
                ErrorCodes.NotFound, "No consumer account holds this contact detail.");
        }

        var summarized = await summaries.SummarizeAsync([identity.UserId], cancellationToken);

        // The summarizer always yields one entry per id, so an identity row pointing at a consumer
        // row that is gone arrives here as AccountExists=false rather than as an empty list. Report
        // it as not found: this endpoint exists so an operator can VERIFY an account before
        // whitelisting it, and a bare id verifies nothing. The listing deliberately goes the other
        // way - there, an orphaned entry has to stay visible to be removable.
        if (summarized.Count == 0 || !summarized[0].AccountExists)
        {
            throw new NotFoundException(
                ErrorCodes.NotFound, "No consumer account holds this contact detail.");
        }

        return summarized[0];
    }
}
