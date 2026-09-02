using System.Globalization;
using Microsoft.Extensions.Logging;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;

namespace UserSvc.Application.Features.Profile;

/// <summary>
/// Replacing the picture on a profile: validate the bytes, put them in object storage, point
/// <c>identity.users.avatar</c> at the URL that comes back.
/// <para>
/// <b>The validation is the interesting half.</b> Three separate claims arrive with every upload -
/// the declared content type, the declared length, and the file name - and all three are written by
/// whoever is calling. The size cap is therefore enforced while reading rather than from the
/// declared length, and the media type is decided by
/// <see cref="AvatarImageRules.Sniff"/> reading the leading bytes, not by the header. The header is
/// still checked, but only as a cheap refusal before the body is pulled over the network; it never
/// decides what gets stored. See <see cref="AvatarImageRules"/> for why an HTML document served
/// back as <c>me.png</c> from our own domain is the failure being designed against.
/// </para>
/// <para>
/// <b>There is no transaction around the two writes, and there cannot be one.</b> The object store
/// commits when the upload returns; the database commits afterwards. If the row write fails, the
/// object is already there and orphaned. The alternative - write the row first - loses the other
/// way: a profile pointing at a URL that 404s, which is visible to the user, whereas an orphan is
/// visible only to a storage bill. The original made the same choice.
/// </para>
/// <para>
/// <b>The previous avatar is deliberately left in place.</b> Object names carry the upload instant,
/// so every upload is a new object and the old one is never overwritten or deleted. That is the
/// original's behaviour and it is kept on purpose: the old URL may still be sitting in a client's
/// image cache, in a push payload or in a back-office screenshot, and deleting on replace breaks
/// all of those to reclaim a few kilobytes. It does mean storage grows without bound - a lifecycle
/// rule on the container is the answer, not a delete here.
/// </para>
/// </summary>
public sealed class AvatarAppService(
    IUserRepository users,
    IObjectStorage storage,
    ProfileAppService profiles,
    IUnitOfWork unitOfWork,
    IClock clock,
    ILogger<AvatarAppService> logger)
{
    /// <summary>413, not 400. The client cannot fix this by editing a field - it has to send a
    /// smaller image - and 413 is the status every HTTP client and proxy already understands that
    /// to mean.</summary>
    private const int PayloadTooLarge = 413;

    /// <summary>415, not 400, for the same reason: the payload's <i>type</i> is the problem, and a
    /// client that branches on status can tell "too big" from "wrong format" without parsing a
    /// string.</summary>
    private const int UnsupportedMediaType = 415;

    /// <summary>Read in chunks rather than in one go so a lying Content-Length cannot make us
    /// allocate more than the cap allows.</summary>
    private const int ReadChunkBytes = 16 * 1024;

    /// <summary>Enough for every signature <see cref="AvatarImageRules.Sniff"/> knows.</summary>
    private const int SniffBytes = 16;

    private const string TooLargeMessage = "The avatar image must be 200 KB or smaller.";

    private const string UnsupportedTypeMessage = "The avatar must be a JPEG or PNG image.";

    /// <summary>
    /// Store a new avatar for <paramref name="userId"/> and return the profile as it now reads.
    /// <para>
    /// The order of the steps is deliberate: everything that can be judged from the request alone
    /// runs before the first database round trip, so a malformed upload costs one connection and no
    /// query. The account is then resolved before the object is written, so a request for an
    /// account that does not exist - or one that has been disabled - never leaves bytes behind in
    /// storage.
    /// </para>
    /// </summary>
    public async Task<ProfileResponse> UploadAsync(
        int userId,
        AvatarUpload upload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(upload);

        // 1. The declared length. First because the original checked size first, and the order is
        //    observable: a 300 KB text file answers FILE_TOO_LARGE, not INVALID_FILE_TYPE. Cheap to
        //    check and trusted for nothing - step 3 enforces the cap against the bytes that arrive.
        if (upload.DeclaredLength > AvatarImageRules.MaxBytes)
        {
            throw TooLarge();
        }

        // 2. The declared type, purely as a fast refusal. It is a claim; the bytes decide in step 4.
        if (AvatarImageRules.NormalizeContentType(upload.ContentType) is null)
        {
            throw Unsupported();
        }

        // 3. The bytes themselves, capped as they are read.
        var content = await ReadCappedAsync(upload.Content, cancellationToken).ConfigureAwait(false);

        if (content.Length == 0)
        {
            throw new BadRequestException(ErrorCodes.BadRequest, "The avatar file is empty.");
        }

        // 4. What the file actually is. This is the answer everything downstream uses.
        var mediaType = AvatarImageRules.Sniff(content.AsSpan(0, Math.Min(SniffBytes, content.Length)));

        if (mediaType is not (AvatarImageRules.Jpeg or AvatarImageRules.Png))
        {
            // Warning, not information: an upload whose bytes disagree with its own header is
            // either a broken client or someone probing for a place to park an HTML file on a
            // domain our users trust. Neither is routine. The sniffed type is our own vocabulary,
            // never the caller's string, so nothing attacker-written reaches the log.
            logger.LogWarning(
                "Avatar upload for user {UserId} was refused: the file's leading bytes are "
                + "{DetectedType}, which is not a JPEG or a PNG.",
                userId,
                mediaType ?? "an unrecognised format");

            throw Unsupported();
        }

        // 5. Only now is the database touched.
        var user = await users.FindByIdAsync(userId, cancellationToken).ConfigureAwait(false)
                   ?? throw new NotFoundException(ErrorCodes.UserNotFound, "User was not found.");

        // The sibling profile write refuses a disabled account, and an avatar is profile content.
        // The original did not check - it had no such check anywhere on this path - but letting a
        // disabled account keep publishing images to a public URL while every other profile write
        // is closed to it is a hole rather than a feature.
        if (!user.IsActive())
        {
            throw new ForbiddenException(ErrorCodes.AccountDisabled, "This account is not active.");
        }

        var url = await StoreAsync(userId, content, mediaType, cancellationToken).ConfigureAwait(false);

        user.Avatar = url.ToString();
        user.UpdatedAt = clock.UtcNow;

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        // Re-read through the profile service rather than mapping here. It is the same request's
        // tracked entity, so it costs nothing worth measuring, and it means the shape of a profile
        // is defined in exactly one place - a second copy of that mapping would drift the first
        // time a field is added.
        return await profiles.GetAsync(userId, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Hand the bytes to whichever object store is configured.
    /// <para>
    /// The name is <c>{userId}/{unixMillis}{extension}</c>, exactly as the original built it. The
    /// user id prefix makes one account's images greppable in a bucket listing and gives the
    /// container a natural prefix to write lifecycle rules against; the millisecond timestamp makes
    /// the name unique per upload, which is what allows the year-long cache directive and what
    /// leaves the previous image untouched.
    /// </para>
    /// </summary>
    private async Task<Uri> StoreAsync(
        int userId,
        byte[] content,
        string mediaType,
        CancellationToken cancellationToken)
    {
        var objectName = string.Create(
            CultureInfo.InvariantCulture,
            $"{userId}/{clock.UtcNow.ToUnixTimeMilliseconds()}{AvatarImageRules.ExtensionFor(mediaType)}");

        using var stream = new MemoryStream(content, writable: false);

        var url = await storage.PutAsync(
            objectName,
            stream,
            new ObjectHttpHeaders(mediaType, AvatarImageRules.CacheControl, AvatarImageRules.ContentDisposition),
            cancellationToken).ConfigureAwait(false);

        logger.LogInformation(
            "Stored a new avatar for user {UserId} as {ObjectName} ({MediaType}, {ByteCount} bytes).",
            userId,
            objectName,
            mediaType,
            content.Length);

        return url;
    }

    /// <summary>
    /// Read the whole upload into memory, refusing the moment it passes the cap.
    /// <para>
    /// Buffering is not laziness. The bytes have to be read twice - once to identify the format and
    /// once to store it - and the source stream is forward-only, so something has to hold them. At
    /// a 200 KB ceiling that is a rounding error per request, and it is the ceiling itself that
    /// makes it safe: the loop stops at <see cref="AvatarImageRules.MaxBytes"/> whatever the
    /// transport claimed the length was, so a request that lies about its size is refused after
    /// reading 200 KB rather than after allocating whatever it asked for.
    /// </para>
    /// </summary>
    private static async Task<byte[]> ReadCappedAsync(Stream source, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[ReadChunkBytes];

        while (true)
        {
            var read = await source.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);

            if (read == 0)
            {
                return buffer.ToArray();
            }

            if (buffer.Length + read > AvatarImageRules.MaxBytes)
            {
                throw TooLarge();
            }

            buffer.Write(chunk, 0, read);
        }
    }

    private static AppException TooLarge() =>
        new(ErrorCodes.FileTooLarge, TooLargeMessage, PayloadTooLarge);

    private static AppException Unsupported() =>
        new(ErrorCodes.InvalidFileType, UnsupportedTypeMessage, UnsupportedMediaType);
}
