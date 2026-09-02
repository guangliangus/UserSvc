namespace UserSvc.Domain.Verification;

/// <summary>
/// Which column the send-code history is aggregated on when risk control falls back to counting
/// rows in <c>verification_codes</c>.
/// <para>
/// It is a closed enum for one reason: the column name is then never derived from caller input, so
/// the fallback count carries no SQL-injection surface. Adding a member means adding a mapping in
/// the repository, which is exactly the review that a string parameter would have skipped.
/// </para>
/// </summary>
public enum VerificationCountDimension
{
    /// <summary>Aggregate on <c>target_hash</c>: how often this phone or email was sent a code.</summary>
    Target = 0,

    /// <summary>Aggregate on <c>device_id_hash</c>: how often this device asked for a code, whatever
    /// target it named.</summary>
    Device = 1,
}
