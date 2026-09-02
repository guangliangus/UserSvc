namespace UserSvc.Application.Features.Feedback;

/// <summary>
/// One selectable category, already localized for the caller. There is no envelope (decision 09),
/// so the list endpoint answers with an array of these.
/// </summary>
public sealed record FeedbackTypeResponse
{
    /// <summary>The machine code, passed back verbatim on submit.</summary>
    public required string Code { get; init; }

    /// <summary>The label in the caller's language, English when there is no label for it, and the
    /// empty string when the row has no labels at all. A category with no label is still listed:
    /// dropping it would make the drop-down silently shorter than the codes the server accepts.</summary>
    public required string Label { get; init; }
}

/// <summary>
/// The multipart body of a feedback submission. Image parts arrive separately, on the repeated
/// <c>images</c> field, and are not part of this type.
/// <para>
/// The properties are settable rather than init-only because MVC's form binder assigns them after
/// construction, and the four names are pinned explicitly: form field names are a wire contract and
/// must not follow a rename of the C# property.
/// </para>
/// <para>
/// <b>The 500-character limit on <see cref="Content"/> is checked after trimming</b>, both here and
/// again in the application service - a bind-time limit would reject text that is within the limit
/// once its trailing newlines are gone.
/// </para>
/// </summary>
public sealed class SubmitFeedbackRequest
{
    /// <summary>The category code, from the list endpoint.</summary>
    public string Type { get; set; } = string.Empty;

    /// <summary>The feedback itself.</summary>
    public string Content { get; set; } = string.Empty;

    /// <summary>Contact name, stored exactly as typed.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Contact email, stored exactly as typed.</summary>
    public string Email { get; set; } = string.Empty;
}

/// <summary>What the caller gets back: enough to quote the submission in a support conversation,
/// and nothing else. There is no endpoint that reads a submission back.</summary>
public sealed record SubmitFeedbackResponse
{
    /// <summary>Serialized as a JSON number (decision 09).</summary>
    public required int Id { get; init; }

    /// <summary>Always <c>PENDING</c> today; it is returned rather than assumed so that a client
    /// showing triage state keeps working when the back office starts moving submissions on.</summary>
    public required string Status { get; init; }
}
