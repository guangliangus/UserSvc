using System.Text;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Feedback;

namespace UserSvc.Application.Features.Feedback;

/// <summary>
/// The count, size and type checks every attached image passes before a single byte is uploaded.
/// <para>
/// <b>The media type is read from the file's own leading bytes, never from the part's declared
/// <c>Content-Type</c>.</b> That header is written by the client and costs nothing to forge, so
/// trusting it would mean the allow-list below decides nothing at all: a caller uploads a script,
/// labels it <c>image/png</c>, and the storage account serves it back from a URL our own users are
/// told to open.
/// </para>
/// <para>
/// <b>The checks are ordered cheapest first and they stop at the first failure.</b> The count check
/// runs before any file is touched, the declared size before any file is opened, and the sniff -
/// the only step that reads - last. A caller who attaches fifty files therefore pays for one
/// comparison, not fifty stream opens.
/// </para>
/// </summary>
public static class FeedbackImageRules
{
    /// <summary>
    /// How many leading bytes are enough to identify every format on the allow-list. It is the size
    /// the standard library sniffers use; the longest signature here needs twelve.
    /// </summary>
    private const int SniffLength = 512;

    /// <summary>
    /// 413, not 400. The caller cannot fix this by editing a field - it has to send a smaller
    /// image - and 413 is the status every HTTP client and proxy already reads that way. It is also
    /// the status the avatar endpoint answers with for the same <see cref="ErrorCodes.FileTooLarge"/>
    /// code: one code that means two statuses on two routes is a code that tells a client nothing.
    /// </summary>
    private const int PayloadTooLarge = 413;

    /// <summary>415, for the same reason: the payload's <i>type</i> is what is wrong, and a client
    /// branching on the status can separate "too big" from "not an image" without parsing a
    /// sentence.</summary>
    private const int UnsupportedMediaType = 415;

    private const string Jpeg = "image/jpeg";
    private const string Png = "image/png";
    private const string Webp = "image/webp";
    private const string Heic = "image/heic";
    private const string Heif = "image/heif";

    /// <summary>The eight bytes every PNG starts with. The trailing CR LF pair is part of the
    /// signature on purpose - it is how the format detects a file mangled by a text-mode transfer.</summary>
    private static ReadOnlySpan<byte> PngSignature => [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    /// <summary>
    /// What each accepted type is stored as. The extension is cosmetic - the object's content type
    /// is what a browser honours - but a URL ending in <c>.jpg</c> is what makes a blob listing
    /// readable to a human triaging feedback.
    /// </summary>
    private static readonly Dictionary<string, string> ExtensionsByType = new(StringComparer.Ordinal)
    {
        [Jpeg] = ".jpg",
        [Png] = ".png",
        [Webp] = ".webp",
        [Heic] = ".heic",
        [Heif] = ".heif",
    };

    /// <summary>
    /// The sentence a caller gets when the bytes are not one of the accepted formats. It names the
    /// formats rather than saying "unsupported", because the caller's next move is to convert the
    /// file.
    /// <para>
    /// Sorted, not left in declaration order: this string is shown to a person, and a dictionary's
    /// enumeration order is an implementation detail that no one should be able to reorder a
    /// user-visible sentence by editing.
    /// </para>
    /// </summary>
    public static readonly string UnsupportedTypeMessage =
        "Each image must be one of "
        + string.Join(", ", ExtensionsByType.Keys.Order(StringComparer.Ordinal))
        + ".";

    /// <summary>The file extension stored objects of this type get.</summary>
    public static string ExtensionFor(string contentType) =>
        ExtensionsByType.TryGetValue(contentType, out var extension) ? extension : string.Empty;

    /// <summary>Whether the sniffed type is one this service accepts.</summary>
    public static bool IsAccepted(string contentType) => ExtensionsByType.ContainsKey(contentType);

    /// <summary>
    /// Checks the whole attachment set and returns it ready to upload, each file paired with the
    /// type its own bytes claim.
    /// <para>
    /// Nothing is uploaded and no database row is touched by anything in here, which is what makes
    /// "a rejected submission leaves nothing behind" true rather than hopeful.
    /// </para>
    /// </summary>
    public static IReadOnlyList<PendingImage> Validate(IReadOnlyList<IUploadedFile>? files)
    {
        if (files is null || files.Count == 0)
        {
            return [];
        }

        if (files.Count > FeedbackLimits.MaxImages)
        {
            throw new BadRequestException(
                ErrorCodes.TooManyFiles,
                $"At most {FeedbackLimits.MaxImages} images may be attached to one submission.");
        }

        var pending = new List<PendingImage>(files.Count);

        foreach (var file in files)
        {
            if (file.Size > FeedbackLimits.MaxImageBytes)
            {
                throw new AppException(
                    ErrorCodes.FileTooLarge,
                    $"Each image must be at most {FeedbackLimits.MaxImageBytes / (1024 * 1024)} MB.",
                    PayloadTooLarge);
            }

            var contentType = Sniff(file);

            if (!IsAccepted(contentType))
            {
                throw new AppException(
                    ErrorCodes.InvalidFileType, UnsupportedTypeMessage, UnsupportedMediaType);
            }

            pending.Add(new PendingImage(file, contentType));
        }

        return pending;
    }

    /// <summary>
    /// The media type the leading bytes declare, or the empty string when they match nothing known.
    /// <para>
    /// A file shorter than the sniff window is not an error: whatever it has is what gets examined.
    /// A genuine read failure is, and it surfaces as a 500 rather than as "not an image", because
    /// telling the caller their JPEG is not a JPEG when the truth is that our own disk hiccuped
    /// sends them off to convert a file that was fine.
    /// </para>
    /// </summary>
    private static string Sniff(IUploadedFile file)
    {
        var head = new byte[SniffLength];
        int read;

        try
        {
            using var stream = file.Open();

            // ReadAtLeast, not Read: a single Read on a network or buffered stream is allowed to
            // return one byte, and a one-byte sniff recognises nothing. Short files are expected,
            // so the end of the stream is not an error.
            read = stream.ReadAtLeast(head, SniffLength, throwOnEndOfStream: false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or NotSupportedException)
        {
            throw new AppException(
                ErrorCodes.InternalError, "The attached image could not be read.", 500, ex);
        }

        return Detect(head.AsSpan(0, read));
    }

    /// <summary>
    /// Magic-number detection for the five accepted formats, and nothing else - anything
    /// unrecognised is the empty string and is refused by the caller. Deliberately a closed
    /// allow-list rather than a general sniffer: a general one recognises HTML and SVG, and both
    /// are executable when served back from a URL.
    /// </summary>
    public static string Detect(ReadOnlySpan<byte> head)
    {
        if (head.Length >= 3 && head[0] == 0xFF && head[1] == 0xD8 && head[2] == 0xFF)
        {
            return Jpeg;
        }

        if (head.Length >= 8 && head[..8].SequenceEqual(PngSignature))
        {
            return Png;
        }

        // RIFF container, four bytes of length, then the form type. Both markers are checked: a
        // RIFF alone is just as likely to be a WAV file.
        if (head.Length >= 12 && Ascii(head[..4]) == "RIFF" && Ascii(head[8..12]) == "WEBP")
        {
            return Webp;
        }

        // ISO base media file format: a four-byte box length, the literal "ftyp", then the brand.
        // HEIC and HEIF differ only in that brand, and no standard sniffer recognises either, which
        // is why this is written out by hand - a phone shooting in HEIC is the common case here.
        if (head.Length >= 12 && Ascii(head[4..8]) == "ftyp")
        {
            return Ascii(head[8..12]) switch
            {
                "heic" or "heix" or "hevc" or "hevx" => Heic,
                "mif1" or "msf1" or "heif" => Heif,
                _ => string.Empty,
            };
        }

        return string.Empty;
    }

    private static string Ascii(ReadOnlySpan<byte> bytes) => Encoding.ASCII.GetString(bytes);
}

/// <summary>
/// A file that has passed every check and is waiting to be uploaded.
/// <para><see cref="ContentType"/> is the <b>sniffed</b> type, which is the one that gets stored:
/// the declared one never leaves the validation step.</para>
/// </summary>
public readonly record struct PendingImage(IUploadedFile File, string ContentType);
