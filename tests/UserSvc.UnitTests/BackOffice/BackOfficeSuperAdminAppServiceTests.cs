using System.Globalization;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Accounts;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.BackOffice;
using UserSvc.Domain.Iam;
using Xunit;

namespace UserSvc.UnitTests.BackOffice;

/// <summary>
/// The platform super-administrator lever. Every test here is about one of three properties: only
/// an owner may appoint an owner, the platform is never left without an active one, and asking for
/// the state something is already in changes nothing.
/// </summary>
public sealed class BackOfficeSuperAdminAppServiceTests
{
    private const int CallerId = 1;
    private const int TargetId = 2;

    private readonly IBackendUserRepository _users = Substitute.For<IBackendUserRepository>();
    private readonly ICurrentUser _currentUser = Substitute.For<ICurrentUser>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();
    private readonly IIamAuditLogRepository _auditLog = Substitute.For<IIamAuditLogRepository>();
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 9, 2, 9, 0, 0, TimeSpan.Zero));

    public BackOfficeSuperAdminAppServiceTests()
    {
        _currentUser.UserId.Returns(CallerId);
        GivenAccount(CallerId, isSuperAdmin: true);

        _unitOfWork
            .ExecuteInTransactionAsync(Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>())
            .Returns(call => call.Arg<Func<CancellationToken, Task>>().Invoke(CancellationToken.None));

        _users.GrantSuperAdminAsync(Arg.Any<int>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true);
    }

    private BackOfficeSuperAdminAppService Sut => new(
        _users,
        _currentUser,
        _auditLog,
        _clock,
        _unitOfWork,
        NullLogger<BackOfficeSuperAdminAppService>.Instance);

    /// <summary>
    /// Refused before the target is read: answering "no such account" to someone who may not ask
    /// still tells them which ids exist.
    /// </summary>
    [Fact]
    public async Task RefusesACallerWhoIsNotASuperAdministrator()
    {
        GivenAccount(CallerId, isSuperAdmin: false);

        var ex = await Should.ThrowAsync<ForbiddenException>(
            () => Sut.SetSuperAdminAsync(TargetId, Enabled(true), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.SuperAdminRequired);
        ex.StatusCode.ShouldBe(403);
        await _users.DidNotReceive().ReadByIdAsync(TargetId, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RefusesAnAnonymousCaller()
    {
        _currentUser.UserId.Returns((int?)null);

        await Should.ThrowAsync<ForbiddenException>(
            () => Sut.SetSuperAdminAsync(TargetId, Enabled(true), CancellationToken.None));
    }

    [Fact]
    public async Task ReportsAMissingTargetAsNotFound()
    {
        _users.ReadByIdAsync(TargetId, Arg.Any<CancellationToken>()).Returns((BackendUser?)null);

        var ex = await Should.ThrowAsync<NotFoundException>(
            () => Sut.SetSuperAdminAsync(TargetId, Enabled(true), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.NotFound);
    }

    /// <summary>
    /// A retry, or two operators pressing the same switch, must not sign the account out twice for
    /// nothing - so the state it is already in is a success that writes nothing at all.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task AskingForTheCurrentStateWritesNothing(bool enabled)
    {
        GivenAccount(TargetId, isSuperAdmin: enabled);

        await Sut.SetSuperAdminAsync(TargetId, Enabled(enabled), CancellationToken.None);

        await _users.DidNotReceive().GrantSuperAdminAsync(
            Arg.Any<int>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _users.DidNotReceive().RevokeSuperAdminIfAnotherActiveExistsAsync(
            Arg.Any<int>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _users.DidNotReceive().IncrementTokenVersionAsync(
            Arg.Any<IReadOnlyList<int>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task GrantingSetsTheFlagAndInvalidatesTheAccountsTokens()
    {
        GivenAccount(TargetId, isSuperAdmin: false);

        await Sut.SetSuperAdminAsync(TargetId, Enabled(true), CancellationToken.None);

        await _users.Received(1).GrantSuperAdminAsync(TargetId, "1", Arg.Any<CancellationToken>());
        await _users.Received(1).IncrementTokenVersionAsync(
            Arg.Is<IReadOnlyList<int>>(ids => ids.Single() == TargetId), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// A disabled or pending account cannot sign in, so granting it the platform identity creates a
    /// dormant owner nobody can use - and one the last-active guard will refuse to count.
    /// </summary>
    [Theory]
    [InlineData(BackendUserStatuses.Disabled)]
    [InlineData(BackendUserStatuses.Pending)]
    public async Task RefusesToGrantToAnAccountThatIsNotActive(string status)
    {
        GivenAccount(TargetId, isSuperAdmin: false, status: status);

        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.SetSuperAdminAsync(TargetId, Enabled(true), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.BadRequest);
        await _users.DidNotReceive().GrantSuperAdminAsync(
            Arg.Any<int>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RevokingClearsTheFlagAndInvalidatesTheAccountsTokens()
    {
        GivenAccount(TargetId, isSuperAdmin: true);
        _users.RevokeSuperAdminIfAnotherActiveExistsAsync(
                TargetId, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true);

        await Sut.SetSuperAdminAsync(TargetId, Enabled(false), CancellationToken.None);

        await _users.Received(1).IncrementTokenVersionAsync(
            Arg.Is<IReadOnlyList<int>>(ids => ids.Single() == TargetId), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The guard writes nothing, the re-read still shows the flag: this account is the last active
    /// owner, and removing it would leave a platform nobody can administer - a state no endpoint
    /// here can recover from, because appointing an owner requires being one.
    /// </summary>
    [Fact]
    public async Task RefusesToRevokeTheLastActiveSuperAdministrator()
    {
        GivenAccount(TargetId, isSuperAdmin: true);
        _users.RevokeSuperAdminIfAnotherActiveExistsAsync(
                TargetId, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        var ex = await Should.ThrowAsync<ConflictException>(
            () => Sut.SetSuperAdminAsync(TargetId, Enabled(false), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.SuperAdminRequired);
        ex.StatusCode.ShouldBe(409);
        await _users.DidNotReceive().IncrementTokenVersionAsync(
            Arg.Any<IReadOnlyList<int>>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The same "wrote nothing" answer means the opposite when the flag is already gone: somebody
    /// else revoked it first, and the caller asked for the state the account is now in. A lost race
    /// on an idempotent operation is a success, not a refusal the operator cannot explain.
    /// </summary>
    [Fact]
    public async Task TreatsALostRevocationRaceAsSuccess()
    {
        GivenAccount(TargetId, isSuperAdmin: true);
        _users.RevokeSuperAdminIfAnotherActiveExistsAsync(
                TargetId, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        // The re-read is what tells the two apart, and it has to see the row as it is NOW - which
        // is why the port reads it untracked.
        _users.ReadByIdAsync(TargetId, Arg.Any<CancellationToken>())
            .Returns(
                Account(TargetId, isSuperAdmin: true, BackendUserStatuses.Active),
                Account(TargetId, isSuperAdmin: false, BackendUserStatuses.Active));

        await Sut.SetSuperAdminAsync(TargetId, Enabled(false), CancellationToken.None);

        await _users.DidNotReceive().IncrementTokenVersionAsync(
            Arg.Any<IReadOnlyList<int>>(), Arg.Any<CancellationToken>());
    }

    /// <summary>The exclusivity guard other modules run before binding anything to an account.</summary>
    [Fact]
    public async Task RefusesTenantBindingsForAPlatformSuperAdministrator()
    {
        GivenAccount(TargetId, isSuperAdmin: true);

        var ex = await Should.ThrowAsync<ConflictException>(
            () => Sut.AssertNotSuperAdminTargetAsync(TargetId, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.SuperAdminExclusive);
    }

    [Fact]
    public async Task ReportsAnUnknownAccountToTheTenantGuardAsAMissingMember()
    {
        _users.ReadByIdAsync(TargetId, Arg.Any<CancellationToken>()).Returns((BackendUser?)null);

        var ex = await Should.ThrowAsync<NotFoundException>(
            () => Sut.AssertNotSuperAdminTargetAsync(TargetId, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.MemberNotFound);
    }

    /// <summary>"I cannot tell" is answered no, because every caller is asking an authorization
    /// question.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task AnImpossibleIdIsNotASuperAdministrator(int userId)
    {
        (await Sut.IsPlatformSuperAdminAsync(userId, CancellationToken.None)).ShouldBeFalse();

        await _users.DidNotReceive().ReadByIdAsync(userId, Arg.Any<CancellationToken>());
    }

    // ------------------------------------------------------------------- audit trail

    /// <summary>
    /// Who owns the platform changing hands is the one action in this trail nobody can afford to be
    /// missing, and the service logging it to a file is not the same thing as recording it.
    /// </summary>
    [Theory]
    [InlineData(true, IamAuditActions.SuperAdminGrant)]
    [InlineData(false, IamAuditActions.SuperAdminRevoke)]
    public async Task EveryChangeOfPlatformOwnershipIsAudited(bool enabled, string action)
    {
        GivenAccount(TargetId, isSuperAdmin: !enabled);
        _users.RevokeSuperAdminIfAnotherActiveExistsAsync(
                TargetId, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true);

        await Sut.SetSuperAdminAsync(TargetId, Enabled(enabled), CancellationToken.None);

        await _auditLog.Received(1).AppendAsync(
            Arg.Is<IamAuditLog>(entry =>
                entry.Action == action
                && entry.ActorUserId == CallerId
                && entry.TargetType == IamAuditTargetTypes.User
                && entry.TargetId == TargetId.ToString(CultureInfo.InvariantCulture)
                && entry.TenantType == IamAuditTenantTypes.Platform),
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// An idempotent no-op writes no audit row. The trail records changes; an entry for a request
    /// that changed nothing would make "who took this away" unanswerable by reading it.
    /// </summary>
    [Fact]
    public async Task AskingForTheStateAnAccountIsAlreadyInIsNotAudited()
    {
        GivenAccount(TargetId, isSuperAdmin: true);

        await Sut.SetSuperAdminAsync(TargetId, Enabled(true), CancellationToken.None);

        await _auditLog.DidNotReceive().AppendAsync(Arg.Any<IamAuditLog>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// A lost race is reported as success and writes nothing, so it must not be audited either -
    /// the revocation this request did not perform already has an entry under whoever did.
    /// </summary>
    [Fact]
    public async Task ALostRaceIsNotAudited()
    {
        GivenAccount(TargetId, isSuperAdmin: true);
        _users.RevokeSuperAdminIfAnotherActiveExistsAsync(
                TargetId, Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        // The re-read, untracked, sees the flag already gone.
        _users.ReadByIdAsync(TargetId, Arg.Any<CancellationToken>())
            .Returns(
                Account(TargetId, isSuperAdmin: true, BackendUserStatuses.Active),
                Account(TargetId, isSuperAdmin: false, BackendUserStatuses.Active));

        await Sut.SetSuperAdminAsync(TargetId, Enabled(false), CancellationToken.None);

        await _auditLog.DidNotReceive().AppendAsync(Arg.Any<IamAuditLog>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The audit write happens after the change has committed, so a failure there cannot be allowed
    /// to fail the request - the operator would be told the promotion failed while the account
    /// holds the platform.
    /// </summary>
    [Fact]
    public async Task AnAuditFailureDoesNotUndoACommittedGrant()
    {
        GivenAccount(TargetId, isSuperAdmin: false);
        _auditLog.AppendAsync(Arg.Any<IamAuditLog>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromException(new InvalidOperationException("the audit table is gone")));

        await Sut.SetSuperAdminAsync(TargetId, Enabled(true), CancellationToken.None);

        await _users.Received(1).GrantSuperAdminAsync(
            TargetId, Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    private static SetSuperAdminRequest Enabled(bool value) => new() { Enabled = value };

    private static BackendUser Account(int id, bool isSuperAdmin, string status) => new()
    {
        Id = id,
        IsSuperAdmin = isSuperAdmin,
        Status = status,
    };

    private void GivenAccount(int id, bool isSuperAdmin, string status = BackendUserStatuses.Active) =>
        _users.ReadByIdAsync(id, Arg.Any<CancellationToken>()).Returns(Account(id, isSuperAdmin, status));
}
