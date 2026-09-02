using System.Text;
using UserSvc.Application.Ports.Feedback;

namespace UserSvc.UnitTests.Feedback;

/// <summary>The leading bytes of each format the sniffer is meant to recognise, plus one that is
/// plainly not an image.</summary>
internal static class ImageMagic
{
    /// <summary>The shortest prefix a JPEG sniffer accepts, followed by a JFIF header so the bytes
    /// are a plausible file rather than three magic bytes and nothing.</summary>
    internal static readonly byte[] Jpeg =
        [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00];

    internal static readonly byte[] Png =
        [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D];

    /// <summary>RIFF, four length bytes, then the WEBP form type and the start of a VP8 chunk.</summary>
    internal static readonly byte[] Webp =
        [.. "RIFF"u8, 0x00, 0x00, 0x00, 0x00, .. "WEBPVP8 "u8];

    /// <summary>An ISO base media box declaring the heic brand. No standard sniffer recognises it,
    /// which is exactly why the detector spells it out.</summary>
    internal static readonly byte[] Heic = [0x00, 0x00, 0x00, 0x18, .. "ftypheic"u8, .. "mif1heic"u8];

    internal static readonly byte[] Heif = [0x00, 0x00, 0x00, 0x18, .. "ftypmif1"u8, .. "mif1heic"u8];

    /// <summary>Text. Used for the file that declares image/png and is not one.</summary>
    internal static readonly byte[] PlainText =
        Encoding.UTF8.GetBytes("this is plainly not an image, just some text content");
}

/// <summary>An attachment backed by real bytes; <see cref="Open"/> hands out a fresh stream each
/// time, exactly as <c>IFormFile.OpenReadStream</c> does.</summary>
internal sealed class InMemoryUploadedFile(byte[] bytes) : IUploadedFile
{
    /// <summary>How many times the bytes were actually opened - the sniff and the upload should be
    /// two, and the checks that run before either should leave it at zero.</summary>
    public int OpenCount { get; private set; }

    public long Size => bytes.Length;

    public Stream Open()
    {
        OpenCount++;
        return new MemoryStream(bytes, writable: false);
    }
}

/// <summary>
/// An attachment that knows its declared size and <b>throws if anything tries to read it</b>.
/// <para>
/// It is the whole point of the count and size tests: asserting "no repository call happened" only
/// shows the lookup was skipped, while a file that explodes on open proves the cheap checks really
/// did run before anything touched the body.
/// </para>
/// </summary>
internal sealed class UnreadableUploadedFile(long size) : IUploadedFile
{
    public long Size => size;

    public Stream Open() =>
        throw new InvalidOperationException("This file must not be opened: the check before it should have refused the request.");
}
