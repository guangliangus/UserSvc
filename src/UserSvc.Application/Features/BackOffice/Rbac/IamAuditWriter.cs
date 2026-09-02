using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Iam;

namespace UserSvc.Application.Features.BackOffice.Rbac;

/// <summary>
/// Writes the IAM audit trail. <b>Always best effort.</b>
/// <para>
/// Every call site runs after its change has committed, so failing the request here would report a
/// false negative to the operator while the change stands. The one place in this module where a
/// post-commit side effect <i>is</i> allowed to fail the request is the token-version bump behind an
/// account status change, and that is deliberate: silently skipping it leaves an account alive behind
/// a 200 that said otherwise.
/// </para>
/// </summary>
public sealed class IamAuditWriter(
    IIamAuditLogRepository log,
    IClock clock,
    ILogger<IamAuditWriter> logger)
{
    private static readonly JsonSerializerOptions SnapshotOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Record one action against a role, menu or account.</summary>
    public async Task WriteAsync(
        IBackOfficeCaller caller,
        string action,
        string targetType,
        string targetId,
        object? before,
        object? after,
        CancellationToken cancellationToken)
    {
        var tenantType = IamAuditTenantTypes.Platform;
        var tenantCode = string.Empty;

        var (callerTenantType, callerTenantCode, isTenant) = CallerFacts.Tenant(caller);
        if (isTenant)
        {
            tenantType = callerTenantType;
            tenantCode = callerTenantCode;
        }

        var entry = new IamAuditLog
        {
            ActorUserId = caller.UserId,
            ActorName = caller.Nickname,
            TenantType = tenantType,
            TenantCode = tenantCode,
            Action = action,
            TargetType = targetType,
            TargetId = targetId,
            BeforeData = ToJson(before),
            AfterData = ToJson(after),
            Ip = caller.IpAddress,
            RequestId = caller.RequestId,
            CreatedAt = clock.UtcNow,
        };

        try
        {
            await log.AppendAsync(entry, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(
                ex,
                "Failed to write the {Action} audit entry for {TargetType} {TargetId}. The change itself is committed.",
                action,
                targetType,
                targetId);
        }
    }

    /// <summary>Serialise a snapshot for a jsonb column. Null in, null out; an unserialisable value
    /// is null too, because an audit row with one empty column beats no audit row.</summary>
    private static string? ToJson(object? value)
    {
        if (value is null)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Serialize(value, value.GetType(), SnapshotOptions);
        }
        catch (NotSupportedException)
        {
            return null;
        }
    }
}

/// <summary>A role as it looked at one point in an audit trail. Null members are omitted from the
/// stored JSON.</summary>
public sealed record RoleAuditSnapshot
{
    public string? Code { get; init; }

    public string? Name { get; init; }

    public string? OwnerType { get; init; }

    /// <summary>Flattened to an empty string for a platform role - the audit trail is read by people,
    /// and a missing key reads worse than a blank one.</summary>
    public string? OwnerCode { get; init; }

    public IReadOnlyList<string>? MenuCodes { get; init; }

    public IReadOnlyList<string>? PermissionCodes { get; init; }
}

/// <summary>A menu, and the permission points that went offline with it.</summary>
public sealed record MenuAuditSnapshot
{
    public string Code { get; init; } = string.Empty;

    public string? Path { get; init; }

    public string? Status { get; init; }

    public IReadOnlyList<string>? PermissionCodes { get; init; }
}
