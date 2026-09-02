using UserSvc.Domain.Iam;

namespace UserSvc.Application.Ports.Iam;

/// <summary>
/// The IAM audit trail (spec 2.7). <b>Append is the only operation there is</b> - no read, no
/// update, no delete. That is structural rather than a convention: a port that cannot express a
/// rewrite cannot be talked into one, and the reviewer does not have to trust that nobody added an
/// update path later.
/// <para>
/// Reads live behind a separate reporting concern with its own permission point
/// (<c>uam.audit.read</c>); handing this interface a query method would put them on the same key.
/// </para>
/// </summary>
public interface IIamAuditLogRepository
{
    /// <summary>Insert one entry. Callers treat failure as a warning: the action being recorded has
    /// already committed, and failing the request afterwards would report a false negative to the
    /// operator while leaving the change in place.</summary>
    Task AppendAsync(IamAuditLog entry, CancellationToken cancellationToken);
}
