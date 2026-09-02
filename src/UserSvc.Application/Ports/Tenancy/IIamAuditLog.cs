namespace UserSvc.Application.Ports.Tenancy;

/// <summary>
/// One row of the IAM audit trail.
/// <para>
/// <c>BeforeData</c> and <c>AfterData</c> are JSON snapshots of the state that changed, or null
/// when there is nothing worth recording. A password reset writes null on both sides on purpose:
/// the only thing that changed is a hash, and a hash has no business anywhere near an audit
/// payload.
/// </para>
/// </summary>
public sealed record IamAuditEntry(
    int ActorUserId,
    string ActorName,
    string TenantType,
    string TenantCode,
    string Action,
    string TargetType,
    string TargetId,
    string? BeforeData = null,
    string? AfterData = null);

/// <summary>
/// Append-only IAM audit trail.
/// <para>
/// Every write is best effort: a failure is logged and swallowed, never surfaced. An audit insert
/// that fails a membership change would leave the caller believing nothing happened while the
/// change is already committed - the audit exists to explain writes, not to veto them.
/// </para>
/// </summary>
public interface IIamAuditLog
{
    Task WriteAsync(IamAuditEntry entry, CancellationToken cancellationToken);
}
