namespace UserSvc.Application.Features.Profile;

/// <summary>
/// One avatar image on its way in. Not an OpenAPI schema - the request is
/// <c>multipart/form-data</c>, so nothing here is serialized - which is why it is named for what it
/// is rather than carrying the <c>Request</c> suffix the JSON contracts use. It exists so the
/// application layer can take an upload without knowing what an <c>IFormFile</c> is.
/// </summary>
/// <param name="Content">The image bytes. Read once, forward-only; the caller owns and disposes it.</param>
/// <param name="ContentType">The media type the client declared for the file part. <b>A claim, not a
/// fact</b> - it is used only to refuse obvious nonsense before the body is read. What the object is
/// actually stored as comes from <see cref="AvatarImageRules.Sniff"/>.</param>
/// <param name="DeclaredLength">Length the transport reported, when it reported one. Also a claim:
/// the real cap is enforced while reading.</param>
public sealed record AvatarUpload(Stream Content, string? ContentType, long? DeclaredLength);

/// <summary>
/// What counts as an avatar: how big, which formats, and - the part that matters - how the answer
/// is decided.
/// <para>
/// <b>The declared content type and the file extension are both attacker-controlled, so neither
/// decides anything.</b> A part labelled <c>image/png</c> named <c>me.png</c> whose bytes are an
/// HTML document is a file we would happily store and then serve <c>inline</c>, as
/// <c>text/html</c>-sniffing browsers or a permissive CDN might render it, from a domain our users
/// are already signed in to. That is a stored cross-site-scripting hole with our own name on it.
/// The leading bytes are the only part of an upload the uploader cannot lie about while still
/// producing a working image, so <see cref="Sniff"/> is what the service believes.
/// </para>
/// <para>
/// The accepted set is JPEG and PNG. The original service advertised six formats at its HTTP
/// handler (adding HEIC, HEIF and WebP) and then refused everything but JPEG and PNG one layer
/// deeper, when it went to pick a file extension - so a HEIC upload was accepted, read in full and
/// rejected with a message naming only JPEG and PNG. The set of images that actually worked is
/// reproduced exactly; the two-stage refusal is not, because a caller cannot tell the difference
/// and the honest answer is cheaper.
/// </para>
/// </summary>
public static class AvatarImageRules
{
    /// <summary>Hard cap on the stored image, matching the original's 200 KB. Enforced while
    /// reading rather than from any declared length.</summary>
    public const int MaxBytes = 200 * 1024;

    /// <summary>Cache directive written onto every stored avatar. Safe at a year because the object
    /// name carries an upload timestamp, so a given URL's bytes never change.</summary>
    public const string CacheControl = "public, max-age=31536000";

    /// <summary>Avatars are meant to be rendered, not downloaded. Only safe because
    /// <see cref="Sniff"/> has confirmed the bytes are a real image first.</summary>
    public const string ContentDisposition = "inline";

    /// <summary>The canonical JPEG media type. Stored objects always use this spelling.</summary>
    public const string Jpeg = "image/jpeg";

    /// <summary>The canonical PNG media type.</summary>
    public const string Png = "image/png";

    /// <summary><c>image/jpg</c> is not a registered media type, but enough iOS and Android clients
    /// send it that refusing it would be a bug report rather than a defence. Normalized to
    /// <see cref="Jpeg"/>.</summary>
    private const string JpegAlias = "image/jpg";

    /// <summary>
    /// Fold a declared content-type header into <see cref="Jpeg"/> or <see cref="Png"/>, or return
    /// <see langword="null"/> when it is neither.
    /// <para>
    /// Parameters are dropped (<c>image/png; charset=binary</c> is a legal thing for a multipart
    /// part to say) and matching is case-insensitive, because media types are.
    /// </para>
    /// </summary>
    public static string? NormalizeContentType(string? declared)
    {
        if (string.IsNullOrWhiteSpace(declared))
        {
            return null;
        }

        var separator = declared.IndexOf(';', StringComparison.Ordinal);
        var mediaType = (separator < 0 ? declared : declared[..separator]).Trim();

        if (mediaType.Equals(Png, StringComparison.OrdinalIgnoreCase))
        {
            return Png;
        }

        return mediaType.Equals(Jpeg, StringComparison.OrdinalIgnoreCase)
               || mediaType.Equals(JpegAlias, StringComparison.OrdinalIgnoreCase)
            ? Jpeg
            : null;
    }

    /// <summary>The file extension an object of this media type is stored under. Only ever called
    /// with a value <see cref="Sniff"/> returned.</summary>
    public static string ExtensionFor(string mediaType) => mediaType == Png ? ".png" : ".jpg";

    /// <summary>
    /// Identify an image from its leading bytes, ignoring every claim made about it.
    /// <para>
    /// Formats we do not accept are still recognised by name, so the refusal log can say what
    /// someone actually sent - "an upload claiming PNG that is really WebP" is a client bug worth
    /// seeing, and "really HTML" is worth paging about. Anything unrecognised comes back
    /// <see langword="null"/>: this is an allow-list, and an image format nobody here has heard of
    /// is not an avatar.
    /// </para>
    /// </summary>
    /// <param name="content">The start of the file. Sixteen bytes is enough for every signature
    /// below; a shorter buffer simply matches fewer of them.</param>
    /// <returns>A media type, or <see langword="null"/> when the bytes match no known image format.</returns>
    public static string? Sniff(ReadOnlySpan<byte> content)
    {
        // PNG: the 8-byte signature, whose CR/LF/EOF bytes exist precisely so that a file mangled
        // by a text-mode transfer stops looking like a PNG.
        ReadOnlySpan<byte> pngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

        if (content.StartsWith(pngSignature))
        {
            return Png;
        }

        // JPEG: SOI followed by the first marker. Covers JFIF, Exif and raw JPEG alike.
        ReadOnlySpan<byte> jpegSignature = [0xFF, 0xD8, 0xFF];

        if (content.StartsWith(jpegSignature))
        {
            return Jpeg;
        }

        if (content.StartsWith("GIF87a"u8) || content.StartsWith("GIF89a"u8))
        {
            return "image/gif";
        }

        // BMP is only two bytes of signature, so it is checked late - after the formats whose
        // signatures are long enough to be conclusive.
        if (content.StartsWith("BM"u8))
        {
            return "image/bmp";
        }

        // RIFF container: bytes 0-3 name the container, 4-7 are its length, 8-11 the form type.
        if (content.Length >= 12 && content[..4].SequenceEqual("RIFF"u8) && content[8..12].SequenceEqual("WEBP"u8))
        {
            return "image/webp";
        }

        // ISO base media file format: a 4-byte box length, the literal "ftyp", then the brand.
        // HEIC and HEIF differ only by brand, and neither is accepted - but both are common enough
        // from iPhones that recognising them turns a mystery rejection into a readable one.
        if (content.Length >= 12 && content[4..8].SequenceEqual("ftyp"u8))
        {
            var brand = content[8..12];

            if (brand.SequenceEqual("heic"u8) || brand.SequenceEqual("heix"u8)
                || brand.SequenceEqual("hevc"u8) || brand.SequenceEqual("hevx"u8))
            {
                return "image/heic";
            }

            if (brand.SequenceEqual("mif1"u8) || brand.SequenceEqual("msf1"u8) || brand.SequenceEqual("heif"u8))
            {
                return "image/heif";
            }
        }

        return null;
    }
}
