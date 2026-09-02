using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Shouldly;
using UserSvc.Application.Features.BackOffice.Rbac;
using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;
using Xunit;

namespace UserSvc.UnitTests.Iam;

/// <summary>
/// <c>iam_audit_logs.before_data</c> and <c>after_data</c> are one column written by two slices.
/// The tenancy slice names every key by hand in snake case; this writer relies on a serializer
/// policy to reach the same spelling, and a policy is exactly the kind of thing an edit removes
/// without anyone noticing - the rows keep being written, they just stop being readable the same
/// way. These tests pin the spelling rather than the mechanism.
/// </summary>
public sealed class IamAuditWriterTests
{
    [Fact]
    public async Task ASnapshotIsStoredWithSnakeCaseKeys()
    {
        var log = new CapturingAuditLog();
        var writer = new IamAuditWriter(
            log, new TestClock(DateTimeOffset.UnixEpoch), NullLogger<IamAuditWriter>.Instance);

        await writer.WriteAsync(
            new FakeCaller { UserId = 1 },
            "ROLE_GRANTS_UPDATE",
            "role",
            "99",
            new RoleAuditSnapshot { Code = "probe", MenuCodes = ["message"] },
            new RoleAuditSnapshot { Code = "probe", PermissionCodes = ["message.read"] },
            CancellationToken.None);

        var before = Keys(log.Entry!.BeforeData!);
        before.ShouldContain("menu_codes");
        before.ShouldNotContain("MenuCodes");

        Keys(log.Entry.AfterData!).ShouldContain("permission_codes");
    }

    /// <summary>
    /// The super-administrator payload is the one the spec spells out key by key
    /// (08 §3.11: <c>cleared_memberships</c>, <c>tenant_code</c>, <c>scope_all</c>,
    /// <c>role_codes</c>), and it is nested - so it also proves the policy reaches inside a record
    /// rather than only naming the outer property.
    /// </summary>
    [Fact]
    public async Task TheClearedMembershipPayloadMatchesTheSpelledOutContract()
    {
        var log = new CapturingAuditLog();
        var writer = new IamAuditWriter(
            log, new TestClock(DateTimeOffset.UnixEpoch), NullLogger<IamAuditWriter>.Instance);

        await writer.WriteAsync(
            new FakeCaller { UserId = 1 },
            "SUPER_ADMIN_GRANT",
            "user",
            "4",
            new
            {
                ClearedMemberships = new[]
                {
                    new ClearedMembership("company", "C001", false, true, ["ota_tc_admin"]),
                },
            },
            after: null,
            CancellationToken.None);

        var json = log.Entry!.BeforeData!;

        json.ShouldContain("\"cleared_memberships\"");
        json.ShouldContain("\"tenant_code\":\"C001\"");
        json.ShouldContain("\"scope_all\":false");
        json.ShouldContain("\"is_admin\":true");
        json.ShouldContain("\"role_codes\":[\"ota_tc_admin\"]");
    }

    private static IReadOnlyList<string> Keys(string json) =>
        [.. JsonDocument.Parse(json).RootElement.EnumerateObject().Select(property => property.Name)];

    private sealed class CapturingAuditLog : IIamAuditLogRepository
    {
        public IamAuditLog? Entry { get; private set; }

        public Task AppendAsync(IamAuditLog entry, CancellationToken cancellationToken)
        {
            Entry = entry;
            return Task.CompletedTask;
        }
    }
}
