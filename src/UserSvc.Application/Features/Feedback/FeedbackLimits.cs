namespace UserSvc.Application.Features.Feedback;

/// <summary>
/// The bounds of one feedback submission. They are constants rather than configuration on purpose:
/// every one of them is a number the mobile clients were built against and show in their own
/// error copy, so changing one is a contract change that wants a code review, not a config edit.
/// </summary>
public static class FeedbackLimits
{
    /// <summary>Images per submission. A sixth is refused before any file is looked at.</summary>
    public const int MaxImages = 5;

    /// <summary>Bytes per image, inclusive - exactly 5 MiB is accepted.</summary>
    public const long MaxImageBytes = 5 * 1024 * 1024;

    /// <summary>Unicode code points of feedback text after trimming, inclusive.</summary>
    public const int MaxContentRunes = 500;

    /// <summary>Unicode code points of the contact name.</summary>
    public const int MaxNameRunes = 100;

    /// <summary>Unicode code points of the contact email. 254 is the longest address SMTP can carry.</summary>
    public const int MaxEmailRunes = 254;

    /// <summary>
    /// The whole multipart body: five 5 MiB images plus room for the text fields and the multipart
    /// boundaries. This is the real upload bound - a form-length limit only decides when the server
    /// spills to a temp file, not how much it is willing to accept.
    /// </summary>
    public const long MaxRequestBytes = 26L * 1024 * 1024;

    /// <summary>The multipart field the images arrive on. Repeated once per file.</summary>
    public const string ImagesFieldName = "images";

    /// <summary>
    /// Length in Unicode code points, which is what the limits above are stated in and what the
    /// service being replaced counted.
    /// <para>
    /// <b>Not <see cref="string.Length"/>.</b> That counts UTF-16 code units, so every emoji counts
    /// twice and a caller pasting 300 emoji into a 500-character box would be refused for exceeding
    /// a limit they are nowhere near. The difference is invisible in ASCII testing, which is
    /// exactly why it survives to production.
    /// </para>
    /// </summary>
    public static int RuneCount(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return 0;
        }

        var count = 0;
        foreach (var _ in value.EnumerateRunes())
        {
            count++;
        }

        return count;
    }
}
