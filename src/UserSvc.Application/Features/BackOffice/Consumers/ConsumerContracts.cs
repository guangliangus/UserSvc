namespace UserSvc.Application.Features.BackOffice.Consumers;

/// <summary>
/// A consumer account, identified well enough for an operator to confirm "yes, that is the tester"
/// - and no further than that.
/// <para>
/// <b>Contact details are masked, always.</b> This is an operator reading somebody else's contact
/// details, where recognition is the entire requirement; the plaintext path is
/// <c>/user/profile</c>, where a person reads their own. The consumer identity table stores no
/// masked copy, so the mask is derived from the ciphertext for the rows on the page being rendered
/// and the plaintext is discarded - it is never returned, never logged and never used as a lookup
/// key.
/// </para>
/// <para>
/// Where an account holds several ACTIVE identities of one type, the first by id whose stored value
/// can be read back is reported, so two page loads describe the account the same way.
/// </para>
/// </summary>
public sealed record ConsumerSummaryResponse
{
    public required int UserId { get; init; }

    /// <summary>The nickname when the account has one, otherwise the joined legal name. Empty for a
    /// quick-registered account that has neither - an empty label beats an invented one.</summary>
    public string Nickname { get; init; } = string.Empty;

    /// <summary>Masked address, or empty when the account has no ACTIVE email identity.</summary>
    public string EmailMasked { get; init; } = string.Empty;

    /// <summary>Masked number, or empty when the account has no ACTIVE phone identity.</summary>
    public string PhoneMasked { get; init; } = string.Empty;

    /// <summary>
    /// False for an orphaned whitelist entry - an id whose consumer row is gone - so the front end
    /// can mark the row instead of rendering a nameless one. Such an entry is still listed rather
    /// than filtered out: otherwise it would be invisible and therefore impossible to remove.
    /// </summary>
    public required bool AccountExists { get; init; }
}
