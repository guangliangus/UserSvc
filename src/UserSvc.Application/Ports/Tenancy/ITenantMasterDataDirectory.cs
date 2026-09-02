namespace UserSvc.Application.Ports.Tenancy;

/// <summary>
/// What the product master data says about one tenant.
/// <para>
/// <c>Verdict</c> is <b>three</b>-valued, because two of its answers are not the same failure. The
/// read paths only ever ask "may anyone enter", so a boolean served them - but the mounting write
/// has to tell a code the master data has never heard of from a real tenant in a state that forbids
/// mounting, and answer a different error code for each. A boolean cannot carry that, and the
/// endpoint spent its life reporting "not approved" for both.
/// </para>
/// <para>
/// <c>Name</c> carries localized display names by locale tag, and is empty when unknown - the front
/// end then renders the code, which beats inventing a name.
/// </para>
/// </summary>
public sealed record TenantMasterDataEntry(
    string TenantType,
    string TenantCode,
    TenantMasterDataEntry.Verdicts Verdict,
    IReadOnlyDictionary<string, string> Name)
{
    /// <summary>
    /// Nested deliberately, exactly as <c>SendCodeRiskDecision.RiskAction</c> is: <c>Ports/</c> is
    /// guarded to interfaces and contract records only, and an enum is neither. Nesting keeps the
    /// vocabulary next to the thing it describes instead of exiling it to a layer that has no
    /// reason to own it.
    /// </summary>
    public enum Verdicts
    {
        /// <summary>
        /// The master data holds no such tenant. First on purpose, so that it is the default: an
        /// entry nobody filled in says "never heard of it" rather than waving a code through. It
        /// covers both shapes the upstream can say it in - the code missing from the answer
        /// entirely, and the code echoed back as not existing - because no caller has a use for
        /// the difference.
        /// </summary>
        Unknown,

        /// <summary>
        /// The tenant exists, and nobody may enter it or mount anything onto it. For a supplier
        /// that means it is not approved (PIM's cooperation status is not "approved"); for a
        /// company it means its status is not ACTIVE.
        /// </summary>
        NotUsable,

        /// <summary>The tenant exists and is in a state that admits people: an ACTIVE company, or
        /// an approved supplier.</summary>
        Usable,
    }

    /// <summary>
    /// Whether this is still a place anyone may enter - the question the read paths ask, kept as
    /// one property so they do not each spell out the comparison, and so that a fourth verdict,
    /// should the master data ever grow one, is unusable by default rather than usable by omission.
    /// </summary>
    public bool Usable => Verdict == Verdicts.Usable;
}

/// <summary>
/// The product master data, as tenancy consults it.
/// <para>
/// <b>Null is "not reached", and what that means is the caller's choice.</b> The tenancy reads fall
/// open on it: this gate exists to keep people out of a tenant that has been switched off, it is
/// not the authorization boundary - that is the member row plus the permission codes - and a
/// master-data outage must not lock the whole platform out of every tenant at once. The mounting
/// write falls closed on it instead, because there is no foreign key behind either code it writes,
/// so falling open there would grant data scope over a company nobody has confirmed exists.
/// </para>
/// </summary>
public interface ITenantMasterDataDirectory
{
    /// <returns>
    /// One entry per requested code - a code the master data does not know still gets an entry,
    /// with <see cref="TenantMasterDataEntry.Verdicts.Unknown"/> - or null if the master data could
    /// not be reached at all. An implementation may also just omit the codes it knows nothing
    /// about: every caller reads an absent entry and an
    /// <see cref="TenantMasterDataEntry.Verdicts.Unknown"/> one identically.
    /// </returns>
    Task<IReadOnlyList<TenantMasterDataEntry>?> ValidateAsync(
        IReadOnlyCollection<string> companyCodes,
        IReadOnlyCollection<string> supplierCodes,
        CancellationToken cancellationToken);
}
