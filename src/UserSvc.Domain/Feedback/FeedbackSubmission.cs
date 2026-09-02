namespace UserSvc.Domain.Feedback;

/// <summary>
/// One feedback submission from the personal-centre form: a category, some free text, the contact
/// details the person typed, and up to five images.
/// <para>
/// <b>Deliberately flat</b> (decision 04). Nothing here is an invariant worth protecting in the
/// domain: a submission is written once and never edited by the person who wrote it, and the only
/// rules that exist - the length of the text, the number and type of the images - are input
/// validation, which belongs to the application layer where the request arrives.
/// </para>
/// <para>
/// The type is named <c>FeedbackSubmission</c> rather than <c>Feedback</c> because the namespace is
/// already <c>Feedback</c>, and a type whose simple name equals its own namespace makes every later
/// reference ambiguous to read and, in some positions, to compile.
/// </para>
/// </summary>
public sealed class FeedbackSubmission
{
    public int Id { get; set; }

    /// <summary>The consumer account that submitted it. A real foreign key to
    /// <c>identity.users</c>; rows are never deleted, and deregistration only disables the
    /// account, so this reference cannot dangle.</summary>
    public int UserId { get; set; }

    /// <summary>Foreign key to <see cref="FeedbackType.Code"/>. Matched exactly - case-sensitive,
    /// untrimmed beyond the trim the application does once on the way in.</summary>
    public string TypeCode { get; set; } = string.Empty;

    /// <summary>The free text, trimmed, at most 500 Unicode code points.</summary>
    public string Content { get; set; } = string.Empty;

    /// <summary>The contact name exactly as typed. It is deliberately <b>not</b> taken from the
    /// profile: these are the contact details for this one submission and overwriting them from
    /// the account would send the reply to the wrong place.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>The contact email exactly as typed. See <see cref="Name"/>.</summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// <b>jsonb</b>: a JSON array of the uploaded image URLs, in submission order. Held as raw JSON
    /// text for the same reason <c>iam.menus.name</c> is - no dynamic-JSON opt-in is needed from the
    /// driver, and the shape is read in exactly one place. Empty submissions store <c>[]</c>, never
    /// <c>null</c>.
    /// </summary>
    public string ImageUrls { get; set; } = EmptyImageUrlsJson;

    /// <summary>Triage state; see <see cref="FeedbackStatuses"/>. This service only ever writes
    /// <see cref="FeedbackStatuses.Pending"/> - the other two belong to a back-office triage screen
    /// that does not exist yet.</summary>
    public string Status { get; set; } = FeedbackStatuses.Pending;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    /// <summary>Nullable because the live column is. See <see cref="FeedbackType.CreatedBy"/>.</summary>
    public string? CreatedBy { get; set; }

    public string? UpdatedBy { get; set; }

    /// <summary>The database default, spelled the way the live column default is.</summary>
    public const string EmptyImageUrlsJson = "[]";
}

/// <summary>
/// The closed set behind <c>chk_feedback_status</c>. There is no deleted or archived state on
/// purpose: a submission is a record of something a person told us, and it is never withdrawn.
/// </summary>
public static class FeedbackStatuses
{
    /// <summary>The initial triage status of a new submission, and the only value this service writes.</summary>
    public const string Pending = "PENDING";

    /// <summary>Reserved for back-office triage.</summary>
    public const string Reviewed = "REVIEWED";

    /// <summary>Reserved for back-office triage.</summary>
    public const string Resolved = "RESOLVED";
}
