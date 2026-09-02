using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Tenants;
using UserSvc.Application.Features.Registration;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Tenancy;
using Xunit;
using static UserSvc.UnitTests.Tenancy.TenantTestData;

namespace UserSvc.UnitTests.Tenancy;

/// <summary>
/// The member surface with every port substituted.
/// <para>
/// These are ports of the Go service's own cases. That matters more here than anywhere else in
/// this codebase: the rules being asserted - who may edit an administrator, what an overwrite is
/// allowed to drop, when the last administrator may go - were each added in response to something
/// that went wrong, and the tests are the only place that history is written down.
/// </para>
/// </summary>
public sealed class TenantMemberAppServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 2, 9, 0, 0, TimeSpan.Zero);

    private readonly ITenantMemberRepository _members = Substitute.For<ITenantMemberRepository>();
    private readonly IUserTenantRoleRepository _bindings = Substitute.For<IUserTenantRoleRepository>();
    private readonly IRoleDirectory _roles = Substitute.For<IRoleDirectory>();
    private readonly IRoleDelegationService _delegation = Substitute.For<IRoleDelegationService>();
    private readonly IAdminStandingService _standing = Substitute.For<IAdminStandingService>();
    private readonly IBackOfficeAccountDirectory _accounts = Substitute.For<IBackOfficeAccountDirectory>();
    private readonly IBackOfficeUserProvisioner _provisioner = Substitute.For<IBackOfficeUserProvisioner>();
    private readonly ICredentialEmailSender _emails = Substitute.For<ICredentialEmailSender>();
    private readonly IIamAuditLog _audit = Substitute.For<IIamAuditLog>();
    private readonly ITokenVersionCache _tokenVersions = Substitute.For<ITokenVersionCache>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();
    private readonly TestClock _clock = new(Now);
    private readonly List<IamAuditEntry> _auditTrail = [];

    public TenantMemberAppServiceTests()
    {
        // The transaction runs inline: these tests are about the decisions inside it.
        _unitOfWork
            .ExecuteInTransactionAsync(Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>())
            .Returns(call => call.Arg<Func<CancellationToken, Task>>()(CancellationToken.None));

        _standing.CanManageMembersAsync(
                Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true);

        _accounts.FindAsync(Arg.Any<int>(), Arg.Any<CancellationToken>()).Returns(Account());
        _accounts.ListByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);
        _accounts.ListPrimaryEmailsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns(new Dictionary<int, string>());

        _audit.WriteAsync(Arg.Do<IamAuditEntry>(_auditTrail.Add), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);

        Catalogue();
        Ceiling();
    }

    private TenantMemberAppService Sut => new(
        _members,
        _bindings,
        _roles,
        _delegation,
        _standing,
        _accounts,
        _provisioner,
        _emails,
        _audit,
        _tokenVersions,
        new PasswordHasher(),
        _unitOfWork,
        _clock,
        NullLogger<TenantMemberAppService>.Instance);

    // --------------------------------------------------------------------- tenant reference

    [Fact]
    public async Task TheWholeDimensionSentinelIsNotAnAddressableTenant()
    {
        // Not input hygiene: '*' is the tenant code of a whole-dimension row, and reaching one
        // through this path would rewrite the role set that governs every company for that person.
        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.RemoveMemberAsync(
            GlobalCaller(), TenantTypes.Company, TenantScopes.ScopeAllSentinelCode, 57, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.BadRequest);
        await _members.DidNotReceive().FindByUserAndTenantAsync(
            Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnUnknownTenantTypeIsRefused()
    {
        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.RemoveMemberAsync(
            GlobalCaller(), "platform", "C1", 57, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.BadRequest);
    }

    // -------------------------------------------------------------------------- create

    [Fact]
    public async Task AddingAnExistingUserBindsTheirRolesAndBumpsTheirTokenVersion()
    {
        Ceiling(12);
        Catalogue(Role(12, "sales"));
        Provision(new ProvisionedTarget(57, ReusedAccount: true, InitialPassword: string.Empty));
        NoExistingMembership();
        AssignIdOnInsert(900);

        var result = await Sut.CreateMemberAsync(
            CompanyCaller(),
            TenantTypes.Company,
            "C1",
            new CreateMemberRequest { UserId = 57, RoleIds = [12] },
            CancellationToken.None);

        result.MemberId.ShouldBe(900);
        result.UserId.ShouldBe(57);
        result.ReusedAccount.ShouldBeTrue();
        result.EmailSent.ShouldBeFalse("no account was created, so no credential mail is due");

        await _bindings.Received(1).ReplaceForMemberAsync(
            900, Arg.Is<IReadOnlyList<int>>(ids => ids.SequenceEqual(new[] { 12 })),
            Arg.Any<string>(), Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>());
        await _accounts.Received(1).IncrementTokenVersionAsync(57, Arg.Any<CancellationToken>());
        await _tokenVersions.Received(1).InvalidateAsync(57, Arg.Any<CancellationToken>());

        var audit = _auditTrail.ShouldHaveSingleItem();
        audit.Action.ShouldBe(IamAuditActions.MemberAdd);
        audit.TargetId.ShouldBe("57");
        audit.BeforeData.ShouldBeNull("a first-time join has no prior state");
    }

    [Fact]
    public async Task AddingSomebodyWhoIsAlreadyAnActiveMemberConflicts()
    {
        Provision(new ProvisionedTarget(57, true, string.Empty));
        ExistingMembership(Member(id: 900));

        var ex = await Should.ThrowAsync<ConflictException>(() => Sut.CreateMemberAsync(
            CompanyCaller(),
            TenantTypes.Company,
            "C1",
            new CreateMemberRequest { UserId = 57 },
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.MemberAlreadyExists);
        ex.StatusCode.ShouldBe(409);
    }

    [Fact]
    public async Task AddingSomebodyWhoWasRemovedRevivesTheirRowAndKeepsItsDepartment()
    {
        Provision(new ProvisionedTarget(57, true, string.Empty));
        var removed = Member(id: 901, status: TenantMemberStatuses.Removed, deptName: "Finance");
        ExistingMembership(removed);

        var result = await Sut.CreateMemberAsync(
            CompanyCaller(),
            TenantTypes.Company,
            "C1",
            new CreateMemberRequest { UserId = 57, DeptName = "Sales" },
            CancellationToken.None);

        result.MemberId.ShouldBe(901, "the unique key means the same row comes back, not a new one");
        removed.Status.ShouldBe(TenantMemberStatuses.Active);
        removed.DeptName.ShouldBe(
            "Finance", "a revival keeps the row's own department; only a new row takes the request's");

        _auditTrail.ShouldHaveSingleItem().BeforeData!.ShouldContain(TenantMemberStatuses.Removed);
    }

    [Fact]
    public async Task RolesOutsideTheCallersCeilingAreRefusedBeforeAnythingIsWritten()
    {
        Ceiling(12);
        Catalogue(Role(12, "sales"), Role(99, "company_admin", isAdmin: true));

        var ex = await Should.ThrowAsync<ForbiddenException>(() => Sut.CreateMemberAsync(
            CompanyCaller(),
            TenantTypes.Company,
            "C1",
            new CreateMemberRequest { UserId = 57, RoleIds = [99] },
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RoleNotDelegable);
        ex.Message.ShouldContain("company_admin", Case.Sensitive);

        // The gate is deliberately in front of the transaction: it needs no lock, and refusing
        // after provisioning would roll back an invitation for a knowable reason.
        await _unitOfWork.DidNotReceive().ExecuteInTransactionAsync(
            Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AWholeDimensionAdministratorGrantsFromItsOwnCeiling()
    {
        // The fix for a real hole: asking only for the target tenant resolves an empty ceiling for
        // an operator who holds no row there, so they could add members but never give them a role.
        _delegation.DelegableRoleIdsAsync(11, TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns(new HashSet<int>());
        _delegation.DelegableRoleIdsAsync(
                11, TenantTypes.Company, TenantScopes.ScopeAllSentinelCode, Arg.Any<CancellationToken>())
            .Returns(new HashSet<int> { 12 });

        Catalogue(Role(12, "sales"));
        Provision(new ProvisionedTarget(57, true, string.Empty));
        NoExistingMembership();
        AssignIdOnInsert(910);

        var result = await Sut.CreateMemberAsync(
            GlobalCaller(userId: 11, dimension: TenantTypes.Company),
            TenantTypes.Company,
            "C1",
            new CreateMemberRequest { UserId = 57, RoleIds = [12] },
            CancellationToken.None);

        result.MemberId.ShouldBe(910);
    }

    [Fact]
    public async Task ATenantContextCannotReachAnotherTenant()
    {
        var ex = await Should.ThrowAsync<ForbiddenException>(() => Sut.CreateMemberAsync(
            CompanyCaller(tenantCode: "C1"),
            TenantTypes.Company,
            "C2",
            new CreateMemberRequest { UserId = 57 },
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.TenantNotAuthorized);
        await _standing.DidNotReceive().CanManageMembersAsync(
            Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ACompanyContextCannotReachASupplierEvenWithStandingThere()
    {
        // Standing stopped mattering when company contexts were locked back to their own dimension:
        // a supplier's members are managed from that supplier's context, or from a global one.
        _standing.CanManageMembersAsync(
                10, TenantTypes.Supplier, "S1", Arg.Any<CancellationToken>())
            .Returns(true);

        var ex = await Should.ThrowAsync<ForbiddenException>(() => Sut.CreateMemberAsync(
            CompanyCaller(),
            TenantTypes.Supplier,
            "S1",
            new CreateMemberRequest { UserId = 57 },
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(
            ErrorCodes.TenantNotAuthorized,
            "the context guard rejects first, so this is never reported as a missing admin role");
    }

    [Fact]
    public async Task ThePlatformSuperAdministratorCannotBeGivenTenantAccess()
    {
        Provision(new ProvisionedTarget(57, true, string.Empty));
        _accounts.FindAsync(57, Arg.Any<CancellationToken>()).Returns(Account(isSuperAdmin: true));

        var ex = await Should.ThrowAsync<ConflictException>(() => Sut.CreateMemberAsync(
            CompanyCaller(),
            TenantTypes.Company,
            "C1",
            new CreateMemberRequest { UserId = 57 },
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.SuperAdminExclusive);
    }

    [Fact]
    public async Task ExactlyOneOfUserIdAndNewUserIsRequired()
    {
        var both = await Should.ThrowAsync<BadRequestException>(() => Sut.CreateMemberAsync(
            CompanyCaller(),
            TenantTypes.Company,
            "C1",
            new CreateMemberRequest
            {
                UserId = 57,
                NewUser = new NewMemberAccountRequest { Email = "a@b.c" },
            },
            CancellationToken.None));

        both.ErrorCode.ShouldBe(ErrorCodes.BadRequest);

        var neither = await Should.ThrowAsync<BadRequestException>(() => Sut.CreateMemberAsync(
            CompanyCaller(), TenantTypes.Company, "C1", new CreateMemberRequest(), CancellationToken.None));

        neither.ErrorCode.ShouldBe(ErrorCodes.BadRequest);
    }

    [Fact]
    public async Task ANewAccountsPasswordIsMailedAfterTheCommitAndNeverReturned()
    {
        Provision(new ProvisionedTarget(61, ReusedAccount: false, InitialPassword: "Qk7mzT4nRa"));
        NoExistingMembership();
        AssignIdOnInsert(950);
        _emails.SendInitialPasswordAsync(
                61, "new@ext.com", Arg.Any<string>(), "Qk7mzT4nRa", Arg.Any<CancellationToken>())
            .Returns(true);

        var result = await Sut.CreateMemberAsync(
            CompanyCaller(),
            TenantTypes.Company,
            "C1",
            new CreateMemberRequest
            {
                NewUser = new NewMemberAccountRequest
                {
                    Email = "new@ext.com",
                    Nickname = "newbie",
                    FirstName = "New",
                    LastName = "Bie",
                },
            },
            CancellationToken.None);

        result.ReusedAccount.ShouldBeFalse();
        result.EmailSent.ShouldBeTrue();
        await _emails.Received(1).SendInitialPasswordAsync(
            61, "new@ext.com", "newbie", "Qk7mzT4nRa", Arg.Any<CancellationToken>());

        // A reused account is never checked for the super-administrator flag here, because it was
        // just created and cannot be one.
        await _accounts.DidNotReceive().FindAsync(61, Arg.Any<CancellationToken>());
    }

    // ------------------------------------------------------------------------- roles

    [Fact]
    public async Task ReplacingRolesWritesTheSubmittedSetWhenItIsAllInsideTheCeiling()
    {
        Ceiling(3, 4);
        Catalogue(Role(3, "finance"), Role(4, "sales"));
        ExistingMembership(Member());
        Bound(900, 3);

        await Sut.UpdateMemberRolesAsync(
            CompanyCaller(), TenantTypes.Company, "C1", 57, [3, 4], CancellationToken.None);

        await _bindings.Received(1).ReplaceForMemberAsync(
            900,
            Arg.Is<IReadOnlyList<int>>(ids => ids.SequenceEqual(new[] { 3, 4 })),
            Arg.Any<string>(),
            Arg.Any<DateTimeOffset>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ReplacingRolesKeepsBindingsTheCallerCouldNotHaveGranted()
    {
        // Role 7 was granted by somebody more senior. It is not in the submitted set - the UI does
        // not even offer it - and it must survive an unrelated edit by a junior administrator.
        Ceiling(3);
        Catalogue(Role(3, "finance"), Role(7, "company_admin", isAdmin: true));
        ExistingMembership(Member(isAdmin: true));
        Bound(900, 3, 7);

        // A global caller: inside a tenant context, editing an administrator at all is refused by
        // the peer guard, which the next test covers.
        await Sut.UpdateMemberRolesAsync(
            GlobalCaller(userId: 11), TenantTypes.Company, "C1", 57, [3], CancellationToken.None);

        await _bindings.Received(1).ReplaceForMemberAsync(
            900,
            Arg.Is<IReadOnlyList<int>>(ids => ids.SequenceEqual(new[] { 3, 7 })),
            Arg.Any<string>(),
            Arg.Any<DateTimeOffset>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task DroppingADelegableAdminRoleAlsoDropsTheAdminFlag()
    {
        Ceiling(3, 7);
        Catalogue(Role(3, "finance"), Role(7, "company_admin", isAdmin: true));
        var member = Member(isAdmin: true);
        ExistingMembership(member);
        Bound(900, 3, 7);
        _members.CountActiveAdminsAsync(TenantTypes.Company, "C1", Arg.Any<CancellationToken>()).Returns(2);

        await Sut.UpdateMemberRolesAsync(
            GlobalCaller(), TenantTypes.Company, "C1", 57, [3], CancellationToken.None);

        member.IsAdmin.ShouldBeFalse("the flag is derived from the bindings, never set on its own");
    }

    [Fact]
    public async Task TheLastAdministratorCannotBeDeAdminedThroughARoleEdit()
    {
        Ceiling(3, 7);
        Catalogue(Role(3, "finance"), Role(7, "company_admin", isAdmin: true));
        ExistingMembership(Member(isAdmin: true));
        Bound(900, 3, 7);
        _members.CountActiveAdminsAsync(TenantTypes.Company, "C1", Arg.Any<CancellationToken>()).Returns(1);

        var ex = await Should.ThrowAsync<ConflictException>(() => Sut.UpdateMemberRolesAsync(
            GlobalCaller(), TenantTypes.Company, "C1", 57, [3], CancellationToken.None));

        ex.ErrorCode.ShouldBe(
            ErrorCodes.AdminTransferRequired,
            "editing roles must not become a back door around the transfer flow");
    }

    [Fact]
    public async Task ARoleFiledUnderTheWrongCategoryIsRefusedForThatReasonNotTheCeiling()
    {
        Catalogue(Role(9, "supplier_pm", category: RoleCategories.Supplier));

        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.UpdateMemberRolesAsync(
            CompanyCaller(), TenantTypes.Company, "C1", 57, [9], CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RoleCategoryMismatch);
        ex.Message.ShouldContain("supplier_pm", Case.Sensitive);

        // Category before ceiling: a super administrator has no range to be outside of, and no
        // amount of authority makes a supplier role fit a company.
        await _delegation.DidNotReceive().DelegableRoleIdsAsync(
            Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnUncategorisedRoleIsBindableNowhere()
    {
        Catalogue(Role(9, "legacy_role", category: RoleCategories.None));

        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.UpdateMemberRolesAsync(
            CompanyCaller(), TenantTypes.Company, "C1", 57, [9], CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RoleCategoryMismatch);
    }

    [Fact]
    public async Task ARoleEditRecordsWhatChangedOnBothSides()
    {
        Ceiling(3, 4);
        Catalogue(Role(3, "company_admin", isAdmin: true), Role(4, "sales"));
        ExistingMembership(Member(isAdmin: true));
        Bound(900, 3);

        await Sut.UpdateMemberRolesAsync(
            GlobalCaller(), TenantTypes.Company, "C1", 57, [3, 4], CancellationToken.None);

        var audit = _auditTrail.ShouldHaveSingleItem();
        audit.Action.ShouldBe(IamAuditActions.MemberRolesUpdate);

        JsonSerializer.Deserialize<JsonElement>(audit.BeforeData!)
            .GetProperty("role_codes").EnumerateArray().Select(e => e.GetString())
            .ShouldBe(["company_admin"]);
        JsonSerializer.Deserialize<JsonElement>(audit.AfterData!)
            .GetProperty("role_codes").EnumerateArray().Select(e => e.GetString())
            .ShouldBe(["company_admin", "sales"]);
        JsonSerializer.Deserialize<JsonElement>(audit.AfterData!)
            .GetProperty("is_admin").GetBoolean().ShouldBeTrue();
    }

    // ------------------------------------------------------------------------ status

    [Fact]
    public async Task DisablingTheLastAdministratorIsRefused()
    {
        ExistingMembership(Member(isAdmin: true));
        _members.CountActiveAdminsAsync(TenantTypes.Company, "C1", Arg.Any<CancellationToken>()).Returns(1);

        var ex = await Should.ThrowAsync<ConflictException>(() => Sut.UpdateMemberStatusAsync(
            GlobalCaller(),
            TenantTypes.Company,
            "C1",
            57,
            TenantMemberStatuses.Disabled,
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.AdminTransferRequired);
    }

    [Fact]
    public async Task DisablingAnAdministratorWithPeersIsAllowed()
    {
        var member = Member(isAdmin: true);
        ExistingMembership(member);
        _members.CountActiveAdminsAsync(TenantTypes.Company, "C1", Arg.Any<CancellationToken>()).Returns(2);

        await Sut.UpdateMemberStatusAsync(
            GlobalCaller(),
            TenantTypes.Company,
            "C1",
            57,
            TenantMemberStatuses.Disabled,
            CancellationToken.None);

        member.Status.ShouldBe(TenantMemberStatuses.Disabled);
        member.UpdatedAt.ShouldBe(Now);
        await _accounts.Received(1).IncrementTokenVersionAsync(57, Arg.Any<CancellationToken>());

        var audit = _auditTrail.ShouldHaveSingleItem();
        audit.Action.ShouldBe(IamAuditActions.MemberStatusUpdate);
        audit.BeforeData.ShouldBe("""{"status":"ACTIVE"}""");
        audit.AfterData.ShouldBe(
            """{"status":"DISABLED"}""",
            "the payload carries only what the action touched");
    }

    [Fact]
    public async Task ThePlatformSuperAdministratorIsNotBoundByTheLastAdministratorGuard()
    {
        // The guard exists so a tenant cannot lock itself out. A super administrator can manage the
        // tenant with no member row at all, so for them it would only obstruct a clean-up.
        _standing.IsPlatformSuperAdminAsync(11, Arg.Any<CancellationToken>()).Returns(true);
        var member = Member(isAdmin: true);
        ExistingMembership(member);

        await Sut.UpdateMemberStatusAsync(
            GlobalCaller(userId: 11),
            TenantTypes.Company,
            "C1",
            57,
            TenantMemberStatuses.Disabled,
            CancellationToken.None);

        member.Status.ShouldBe(TenantMemberStatuses.Disabled);
        await _members.DidNotReceive().CountActiveAdminsAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(TenantMemberStatuses.Active)]
    [InlineData(TenantMemberStatuses.Disabled)]
    public async Task OneAdministratorMayNotChangeAnothersMembershipFromInsideTheTenant(string target)
    {
        // Refused in both directions: reinstating an administrator somebody more senior suspended
        // is the same end run around the transfer flow as suspending one.
        ExistingMembership(Member(isAdmin: true));

        var ex = await Should.ThrowAsync<ConflictException>(() => Sut.UpdateMemberStatusAsync(
            CompanyCaller(), TenantTypes.Company, "C1", 57, target, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.AdminTransferRequired);
        await _members.DidNotReceive().CountActiveAdminsAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RemovalIsNotAStatusUpdate()
    {
        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.UpdateMemberStatusAsync(
            GlobalCaller(),
            TenantTypes.Company,
            "C1",
            57,
            TenantMemberStatuses.Removed,
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.BadRequest);
    }

    // ------------------------------------------------------------------------ removal

    [Fact]
    public async Task RemovingAMemberSoftDeletesTheRowAndRecordsWhatItTookAway()
    {
        var member = Member();
        ExistingMembership(member);
        Bound(900, 3);
        Catalogue(Role(3, "finance"));

        await Sut.RemoveMemberAsync(
            GlobalCaller(), TenantTypes.Company, "C1", 57, CancellationToken.None);

        member.Status.ShouldBe(TenantMemberStatuses.Removed);
        await _bindings.DidNotReceive().ReplaceForMemberAsync(
            Arg.Any<int>(),
            Arg.Any<IReadOnlyList<int>>(),
            Arg.Any<string>(),
            Arg.Any<DateTimeOffset>(),
            Arg.Any<CancellationToken>());

        var audit = _auditTrail.ShouldHaveSingleItem();
        audit.Action.ShouldBe(IamAuditActions.MemberRemove);
        audit.BeforeData!.ShouldContain("finance", Case.Sensitive);
    }

    [Fact]
    public async Task RemovingSomebodyWhoIsNotAMemberIsANotFound()
    {
        NoExistingMembership();

        var ex = await Should.ThrowAsync<NotFoundException>(() => Sut.RemoveMemberAsync(
            GlobalCaller(), TenantTypes.Company, "C1", 57, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.MemberNotFound);
    }

    [Fact]
    public async Task AnAlreadyRemovedMembershipReadsAsNotFound()
    {
        ExistingMembership(Member(status: TenantMemberStatuses.Removed));

        await Should.ThrowAsync<NotFoundException>(() => Sut.RemoveMemberAsync(
            GlobalCaller(), TenantTypes.Company, "C1", 57, CancellationToken.None));
    }

    [Fact]
    public async Task ACallerWithoutAdministratorStandingIsRefused()
    {
        _standing.CanManageMembersAsync(
                Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        var ex = await Should.ThrowAsync<ForbiddenException>(() => Sut.RemoveMemberAsync(
            CompanyCaller(userId: 11), TenantTypes.Company, "C1", 57, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.CallerNotAdmin);
    }

    // ------------------------------------------------------------------------- roster

    [Fact]
    public async Task TheRosterJoinsAccountsRolesAndEmails()
    {
        _members.ListByTenantAsync(Arg.Any<TenantMemberQuery>(), Arg.Any<CancellationToken>())
            .Returns(new TenantMemberPage([Member(isAdmin: true)], 1));
        BoundAcrossMembers((900, [12]));
        Catalogue(Role(12, "sales"));
        _accounts.ListByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([Account()]);
        _accounts.ListPrimaryEmailsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns(new Dictionary<int, string> { [57] = "wang@example.com" });

        var page = await Sut.ListMembersAsync(
            CompanyCaller(), TenantTypes.Company, "C1", null, null, 0, 0, CancellationToken.None);

        page.Total.ShouldBe(1);
        page.Page.ShouldBe(1, "a page below one is normalised rather than refused");
        page.PageSize.ShouldBe(20);

        var row = page.Items.ShouldHaveSingleItem();
        row.UserId.ShouldBe(57);
        row.IsAdmin.ShouldBeTrue();
        row.Email.ShouldBe("wang@example.com");
        row.StaffCode.ShouldBe("S001");
        row.Nickname.ShouldBe("Xiaoming Wang", "both name parts are present, so the nickname yields");
        row.Roles.ShouldHaveSingleItem().Code.ShouldBe("sales");
    }

    [Fact]
    public async Task ReadingYourOwnTenantsRosterNeedsNoAdministratorStanding()
    {
        // The read permission is meant to be grantable to an ordinary member; requiring admin
        // standing here would also break the user-detail reads that follow from this screen.
        _standing.CanManageMembersAsync(
                Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);
        _members.ListByTenantAsync(Arg.Any<TenantMemberQuery>(), Arg.Any<CancellationToken>())
            .Returns(new TenantMemberPage([], 0));

        var page = await Sut.ListMembersAsync(
            CompanyCaller(userId: 11), TenantTypes.Company, "C1", null, null, 1, 20, CancellationToken.None);

        page.Items.ShouldBeEmpty();
    }

    [Fact]
    public async Task ReadingSomebodyElsesRosterDoesNeedIt()
    {
        // Names, decrypted addresses and role bindings are not something a read permission on one
        // dimension should hand over for a tenant the caller has no standing in.
        _standing.CanManageMembersAsync(
                Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        var ex = await Should.ThrowAsync<ForbiddenException>(() => Sut.ListMembersAsync(
            GlobalCaller(userId: 11), TenantTypes.Supplier, "S1", null, null, 1, 20, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.CallerNotAdmin);
        await _members.DidNotReceive().ListByTenantAsync(
            Arg.Any<TenantMemberQuery>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AKeywordThatMatchesNobodyFiltersToNothingRatherThanToEverything()
    {
        _accounts.SearchUserIdsAsync("nobody", Arg.Any<CancellationToken>()).Returns([]);
        _members.ListByTenantAsync(Arg.Any<TenantMemberQuery>(), Arg.Any<CancellationToken>())
            .Returns(new TenantMemberPage([], 0));

        await Sut.ListMembersAsync(
            CompanyCaller(), TenantTypes.Company, "C1", null, "nobody", 1, 20, CancellationToken.None);

        await _members.Received(1).ListByTenantAsync(
            Arg.Is<TenantMemberQuery>(query => query.UserIds != null && query.UserIds.Count == 0),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task PageSizeIsCappedSoOneRequestCannotAskForTheWholeTable()
    {
        _members.ListByTenantAsync(Arg.Any<TenantMemberQuery>(), Arg.Any<CancellationToken>())
            .Returns(new TenantMemberPage([], 0));

        var page = await Sut.ListMembersAsync(
            CompanyCaller(), TenantTypes.Company, "C1", null, null, 1, 5000, CancellationToken.None);

        page.PageSize.ShouldBe(100);
    }

    // ---------------------------------------------------------------- password reset

    [Fact]
    public async Task ResettingAnExternalMembersPasswordMailsItAndKillsTheirSessions()
    {
        ExistingMembership(Member());
        string? captured = null;
        await _accounts.SetPasswordHashAsync(
            57,
            Arg.Do<string>(hash => captured = hash),
            PasswordHasher.AlgorithmName,
            Arg.Any<CancellationToken>());
        _accounts.ListPrimaryEmailsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns(new Dictionary<int, string> { [57] = "wang@example.com" });
        _emails.SendPasswordResetAsync(
                57, "wang@example.com", Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true);

        var result = await Sut.ResetMemberPasswordAsync(
            GlobalCaller(), TenantTypes.Company, "C1", 57, CancellationToken.None);

        result.UserId.ShouldBe(57);
        result.EmailSent.ShouldBeTrue();
        captured.ShouldNotBeNull();
        captured.ShouldStartWith("$argon2id$", Case.Sensitive);
        await _accounts.Received(1).IncrementTokenVersionAsync(57, Arg.Any<CancellationToken>());

        var audit = _auditTrail.ShouldHaveSingleItem();
        audit.Action.ShouldBe(IamAuditActions.MemberPasswordReset);
        audit.BeforeData.ShouldBeNull();
        audit.AfterData.ShouldBeNull("the only thing that changed is a hash, and it stays out of here");
    }

    [Fact]
    public async Task AnInternalAccountHasNoPasswordToReset()
    {
        ExistingMembership(Member());
        _accounts.FindAsync(57, Arg.Any<CancellationToken>())
            .Returns(Account(origin: BackOfficeAccountStates.InternalOrigin));

        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.ResetMemberPasswordAsync(
            GlobalCaller(), TenantTypes.Company, "C1", 57, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.BadRequest);
        await _accounts.DidNotReceive().SetPasswordHashAsync(
            Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task OnlyASuperAdministratorMayResetASuperAdministratorsPassword()
    {
        // Minting a password is a complete takeover of an account. That identity must not be
        // reachable by an administrator of a tenant it happens to belong to.
        ExistingMembership(Member());
        _accounts.FindAsync(57, Arg.Any<CancellationToken>()).Returns(Account(isSuperAdmin: true));

        var ex = await Should.ThrowAsync<ForbiddenException>(() => Sut.ResetMemberPasswordAsync(
            GlobalCaller(userId: 11), TenantTypes.Company, "C1", 57, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.SuperAdminRequired);
    }

    [Fact]
    public async Task ResettingThePasswordOfSomebodyWhoIsNotAMemberIsANotFound()
    {
        NoExistingMembership();

        await Should.ThrowAsync<NotFoundException>(() => Sut.ResetMemberPasswordAsync(
            GlobalCaller(), TenantTypes.Company, "C1", 57, CancellationToken.None));

        await _accounts.DidNotReceive().SetPasswordHashAsync(
            Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    // ------------------------------------------------------------------------ helpers

    private void Catalogue(params RoleSummary[] catalogue) =>
        _roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns(call => (IReadOnlyList<RoleSummary>)
                [.. catalogue.Where(role => call.Arg<IReadOnlyCollection<int>>().Contains(role.Id))]);

    private void Ceiling(params int[] roleIds) =>
        _delegation.DelegableRoleIdsAsync(
                Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new HashSet<int>(roleIds));

    private void Provision(ProvisionedTarget target) =>
        _provisioner.ResolveOrProvisionAsync(
                Arg.Any<int>(), Arg.Any<NewAccountRequest?>(), Arg.Any<CancellationToken>())
            .Returns(target);

    private void ExistingMembership(TenantMember member) =>
        _members.FindByUserAndTenantAsync(
                member.UserId, member.TenantType, member.TenantCode, Arg.Any<CancellationToken>())
            .Returns(member);

    private void NoExistingMembership() =>
        _members.FindByUserAndTenantAsync(
                Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((TenantMember?)null);

    private void Bound(int memberId, params int[] roleIds) =>
        _bindings.ListByMemberAsync(memberId, Arg.Any<CancellationToken>())
            .Returns([.. roleIds.Select(id => new UserTenantRole { MemberId = memberId, RoleId = id })]);

    private void BoundAcrossMembers(params (int MemberId, int[] RoleIds)[] bindings) =>
        _bindings.ListRoleIdsByMembersAsync(
                Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns(bindings.ToDictionary(
                binding => binding.MemberId,
                binding => (IReadOnlyList<int>)binding.RoleIds));

    /// <summary>Stands in for the database assigning the key on insert.</summary>
    private void AssignIdOnInsert(int id) =>
        _members.When(repository => repository.Add(Arg.Any<TenantMember>()))
            .Do(call => call.Arg<TenantMember>().Id = id);
}
