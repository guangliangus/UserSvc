using Shouldly;
using UserSvc.Domain.Abstractions;
using UserSvc.Domain.Verification;
using Xunit;

namespace UserSvc.UnitTests.Domain;

/// <summary>
/// The two guards that run before a verification code row is ever written. Ported from the Go
/// repository's own validation tests, which covered them without a database for the same reason
/// these do: neither guard needs one, and a test that needs a container is a test that gets skipped.
/// </summary>
public sealed class VerificationCodeTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ACodeThatHasAlreadyExpiredIsRefused()
    {
        var ex = Should.Throw<DomainRuleException>(() => Issue(
            expiresAt: Now - TimeSpan.FromMinutes(1),
            createdAt: Now));

        ex.ErrorCode.ShouldBe(VerificationCode.ExpiredErrorCode);
        ex.Message.ShouldContain("expired");
    }

    [Fact]
    public void ACodeExpiringExactlyNowIsRefusedToo()
    {
        // The boundary matters: a row whose deadline is this instant can never satisfy the
        // verify query's strict "expires_at > now", so accepting it would write a code that is
        // dead the moment it lands.
        Should.Throw<DomainRuleException>(() => Issue(expiresAt: Now, createdAt: Now));
    }

    [Fact]
    public void AnUnsetCreationTimeIsFilledInWithTheCurrentTime()
    {
        var code = Issue(expiresAt: Now + TimeSpan.FromMinutes(5), createdAt: default);

        code.CreatedAt.ShouldBe(Now, "the epoch would drop the row out of every risk-control window count");
    }

    [Fact]
    public void AGivenCreationTimeIsKept()
    {
        var issuedAt = Now - TimeSpan.FromSeconds(3);

        Issue(expiresAt: Now + TimeSpan.FromMinutes(5), createdAt: issuedAt).CreatedAt.ShouldBe(issuedAt);
    }

    [Fact]
    public void TheAuditStampNamesTheActorOnBothColumns()
    {
        var code = Issue(expiresAt: Now + TimeSpan.FromMinutes(5), createdAt: Now);

        code.CreatedBy.ShouldBe(VerificationActors.System);
        code.UpdatedBy.ShouldBe(VerificationActors.System);
    }

    private static VerificationCode Issue(DateTimeOffset expiresAt, DateTimeOffset createdAt) =>
        VerificationCode.Issue(
            targetHash: "target-hash",
            deviceIdHash: "device-hash",
            purpose: VerificationPurposes.Auth,
            codeHash: "code-hash",
            expiresAt: expiresAt,
            createdAt: createdAt,
            now: Now,
            actor: VerificationActors.System);
}
