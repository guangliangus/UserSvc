namespace UserSvc.Application.Ports.External;

/// <summary>
/// Put these bytes somewhere durable and public, and tell me the URL they can be fetched from.
/// <para>
/// <b>No vendor appears in this file, and that is the whole point of it.</b> Avatars land in Azure
/// Blob on AKS and would land in S3 on EKS; both are the same three-line operation - write a named
/// object, attach the response headers it should be served with, hand back an address - and the
/// difference between them is a connection string, not a use case. Naming the vendor here would
/// push that choice into <c>AvatarAppService</c>, and the next deployment target would mean editing
/// a use case to change a hosting decision.
/// </para>
/// <para>
/// The port is deliberately narrower than any storage SDK: no list, no metadata read, no container
/// management. Two operations, because two are what the callers need - a write, and the delete that
/// unwinds a write when the rest of a submission fails.
/// </para>
/// <para>
/// <b>Delete is here for the unwind, not for housekeeping.</b> The avatar flow never calls it: it
/// keeps every object it writes (see <c>AvatarAppService</c> for why), and reclaiming those is a
/// lifecycle rule on the container, not a request-time delete. The feedback flow does call it, to
/// remove the images it had already uploaded when a later one fails, so that a rejected submission
/// leaves nothing behind.
/// </para>
/// </summary>
public interface IObjectStorage
{
    /// <summary>
    /// Write <paramref name="content"/> under <paramref name="objectName"/> and return the URL it
    /// is publicly readable from. An object already stored under that name is replaced.
    /// <para>
    /// The stream is read from its current position to the end and is <b>not</b> disposed - the
    /// caller owns it. Implementations must not assume it is seekable.
    /// </para>
    /// <para>
    /// Failure is reported as an <see cref="Errors.AppException"/> so the error contract stays
    /// identical whichever adapter is registered: 502 when the storage account is unreachable or
    /// answered a 5xx, 500 when it refused a request that we built wrong, and 501 when this
    /// deployment has no storage configured at all.
    /// </para>
    /// </summary>
    /// <param name="objectName">Path-like name within the configured container or bucket, without a
    /// leading slash - for example <c>42/1750000000000.png</c>.</param>
    /// <param name="content">The bytes to store.</param>
    /// <param name="headers">How the object should be served back. See <see cref="ObjectHttpHeaders"/>.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    Task<Uri> PutAsync(
        string objectName,
        Stream content,
        ObjectHttpHeaders headers,
        CancellationToken cancellationToken);

    /// <summary>
    /// Remove the object stored under <paramref name="objectName"/>.
    /// <para>
    /// <b>Idempotent, and deliberately forgiving about what does not exist.</b> A name that was
    /// never written, a name already deleted, a blank name, and a deployment with no storage
    /// configured all complete successfully - because every caller of this method is already on a
    /// failure path, cleaning up after something else that went wrong, and none of them can tell
    /// whether a failed write left bytes behind. Turning "there is nothing there" into an error
    /// would replace the real reason a request failed with a complaint about the cleanup.
    /// </para>
    /// <para>
    /// What it does <b>not</b> forgive is the store itself failing: an unreachable or refusing
    /// account throws, exactly as <see cref="PutAsync"/> does, so a caller that wants a best-effort
    /// cleanup has to say so by catching. Adapters log the failure themselves, at warning level,
    /// since a delete that could not happen costs storage rather than correctness.
    /// </para>
    /// </summary>
    /// <param name="objectName">The name the object was written under. Blank is a no-op.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    Task DeleteAsync(string objectName, CancellationToken cancellationToken);
}

/// <summary>
/// The response headers the stored object should carry when it is fetched again.
/// <para>
/// These are HTTP header values rather than a vendor's option object because HTTP is the one thing
/// every object store agrees on: Azure Blob calls them <c>BlobHttpHeaders</c>, S3 calls them
/// <c>PutObjectRequest.ContentType</c> and friends, and both put the same bytes on the wire.
/// </para>
/// <para>
/// <b><see cref="ContentDisposition"/> is a security decision, not a formatting one.</b> Serving a
/// user-supplied file <c>inline</c> from a domain the user's browser already trusts is the classic
/// stored-XSS delivery route, and it is only safe here because nothing reaches this port until its
/// leading bytes have been read and confirmed to be a real JPEG or PNG. A caller that skips that
/// check must send <c>attachment</c>.
/// </para>
/// </summary>
/// <param name="ContentType">The media type to serve the object as. Must describe the bytes actually
/// being stored, not what the uploading client claimed.</param>
/// <param name="CacheControl">Cache directive, for example <c>public, max-age=31536000</c>. Object
/// names are unique per upload, so the content behind one URL never changes and may be cached
/// forever.</param>
/// <param name="ContentDisposition">Usually <c>inline</c>. See the remarks above before changing it.</param>
public sealed record ObjectHttpHeaders(string ContentType, string CacheControl, string ContentDisposition);
