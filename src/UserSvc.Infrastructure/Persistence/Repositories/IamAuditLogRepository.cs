using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>
/// EF Core adapter for the IAM audit trail.
/// <para>
/// It writes immediately rather than waiting for the caller's unit of work: an audit entry describes
/// something that already happened, so tying it to a transaction that may still roll back would make
/// the trail disagree with the outcome. It also means an audit failure cannot take a committed change
/// down with it.
/// </para>
/// <para>
/// It saves through the context, so every call site writes its own change first - which all of them
/// do, since an audit entry is only ever written after the thing it records has committed.
/// </para>
/// </summary>
public sealed class IamAuditLogRepository(UserSvcDbContext db) : IIamAuditLogRepository
{
    public async Task AppendAsync(IamAuditLog entry, CancellationToken cancellationToken)
    {
        db.IamAuditLogs.Add(entry);
        await db.SaveChangesAsync(cancellationToken);
    }
}
