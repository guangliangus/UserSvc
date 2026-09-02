namespace UserSvc.Application.Ports.Feedback;

/// <summary>
/// One file the caller attached to a request, reduced to the two things the feedback flow actually
/// needs: how big it says it is, and a stream over its bytes.
/// <para>
/// It is a port because the alternative is an <c>IFormFile</c> in the application layer, which
/// would drag ASP.NET Core across the dependency rule, and because the unit tests have to be able
/// to hand the service a file that refuses to open - that is the only way to prove the cheap checks
/// really do run before anything is read.
/// </para>
/// </summary>
public interface IUploadedFile
{
    /// <summary>
    /// The declared length in bytes, available without reading the body. It is what the size limit
    /// is checked against, which is the point: a file over the limit is rejected without a single
    /// byte being read.
    /// </summary>
    long Size { get; }

    /// <summary>
    /// Opens a <b>new</b> readable stream positioned at the start. It is called twice for the same
    /// file - once to sniff the leading bytes, once to upload - so an implementation that hands out
    /// the same already-consumed stream twice would upload an empty object with no error anywhere.
    /// </summary>
    Stream Open();
}
