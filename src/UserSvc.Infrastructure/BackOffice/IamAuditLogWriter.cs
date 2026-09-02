using Microsoft.Extensions.Logging;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Iam;

namespace UserSvc.Infrastructure.BackOffice;

/// <summary>
/// The tenant slice's append-only audit trail, over the IAM audit table's own repository.
/// <para>
/// <b>Every failure is swallowed here rather than at the call sites.</b> The port promises that a
/// failed audit insert never fails the request, and the call sites are all past the point of no
/// return - the membership change has committed. Letting the exception out would tell the
/// administrator that nothing happened while the change is already live, which is a worse lie than
/// a missing audit row.
/// </para>
/// <para>
/// <c>ip</c> and <c>request_id</c> are left null. The entry record carries neither, and this adapter
/// has no request to read them from; inventing them from an ambient caller would risk stamping one
/// person's address onto another person's row. The RBAC slice's own writer fills them because it is
/// handed the caller explicitly.
/// </para>
/// </summary>
public sealed class IamAuditLogWriter(
    IIamAuditLogRepository log,
    IClock clock,
    ILogger<IamAuditLogWriter> logger) : IIamAuditLog
{
    public async Task WriteAsync(IamAuditEntry entry, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);

        try
        {
            await log.AppendAsync(
                new IamAuditLog
                {
                    ActorUserId = entry.ActorUserId,
                    ActorName = entry.ActorName,
                    TenantType = entry.TenantType,
                    TenantCode = entry.TenantCode,
                    Action = entry.Action,
                    TargetType = entry.TargetType,
                    TargetId = entry.TargetId,
                    BeforeData = entry.BeforeData,
                    AfterData = entry.AfterData,
                    CreatedAt = clock.UtcNow,
                },
                cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // The caller gave up on the request; that is not an audit fault and must keep
            // propagating as cancellation rather than being recorded as a swallowed failure.
            throw;
        }
        catch (Exception ex)
        {
            // Warning, not error: the write it describes succeeded, and paging somebody at 3 a.m.
            // for a missing explanation of a correct change is not proportionate. The action and
            // target are enough to reconstruct the row by hand from the affected table.
            logger.LogWarning(
                ex,
                "The IAM audit row for {Action} on {TargetType} {TargetId} could not be written. "
                + "The change it describes is already committed.",
                entry.Action,
                entry.TargetType,
                entry.TargetId);
        }
    }
}
