using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Rbac;
using UserSvc.Application.Features.BackOffice.Suppliers;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Suppliers;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Application.Security;
using UserSvc.Domain.Suppliers;
using UserSvc.Domain.Tenancy;
using static UserSvc.Application.Ports.Tenancy.TenantMasterDataEntry;
using Xunit;

namespace UserSvc.UnitTests.Suppliers;

/// <summary>
/// The mounting plane. Two things dominate these tests: the mounting is data scope, so every write
/// that <b>takes one away</b> has to retire the affected tokens and record why; and the write is
/// the only place the supplier and company codes are checked at all, so it must not proceed when
/// the master data cannot be reached.
/// </summary>
public sealed class SupplierLinkAppServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 2, 8, 0, 0, TimeSpan.Zero);

    private readonly IBackOfficeUserDirectory _directory = Substitute.For<IBackOfficeUserDirectory>();
    private readonly ISupplierCompanyLinkRepository _links = Substitute.For<ISupplierCompanyLinkRepository>();
    private readonly ITenantMemberRepository _members = Substitute.For<ITenantMemberRepository>();
    private readonly IBackendUserRepository _backendUsers = Substitute.For<IBackendUserRepository>();
    private readonly IBackendIdentityRepository _backendIdentities = Substitute.For<IBackendIdentityRepository>();
    private readonly ITenantMasterDataDirectory _masterData = Substitute.For<ITenantMasterDataDirectory>();
    private readonly IAuthzConvergence _convergence = Substitute.For<IAuthzConvergence>();
    private readonly IIamAuditLogRepository _auditLog = Substitute.For<IIamAuditLogRepository>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();

    private readonly List<SupplierCompanyLink> _added = [];

    /// <summary>The real thing with a throwaway key: given a key it is pure computation, so there
    /// is nothing here worth substituting.</summary>
    private readonly IdentifierProtector _protector = new(Options.Create(new IdentifierProtectionOptions
    {
        Pepper = "00112233445566778899aabbccddeeff",
        DataKey = Convert.ToBase64String(new byte[32]),
        KeyVersion = "v3",
    }));

    public SupplierLinkAppServiceTests()
    {
        _links.ListActiveBySuppliersAsync(Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>())
            .Returns([]);
        _links.ListActiveByCompanyAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([]);
        _links.FindActiveBySupplierAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((SupplierCompanyLink?)null);
        _links.UnlinkActiveBySupplierAsync(
                Arg.Any<string>(), Arg.Any<DateTimeOffset>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(1);

        _members.FindAdminsByTenantsAsync(
                Arg.Any<string>(), Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([]);
        _members.CountActiveByTenantsAsync(
                Arg.Any<string>(), Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns(new Dictionary<string, int>());
        _members.FindUserIdsByTenantCodeAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns([]);

        _backendUsers.ListByIdsAsync(Arg.Any<IReadOnlyList<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);
        _backendIdentities.ListActiveByUserIdsAsync(Arg.Any<IReadOnlyList<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);

        // The substitute has to run the body, or a relink's assertions would pass against a
        // transaction that never opened.
        _unitOfWork
            .ExecuteInTransactionAsync(Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>())
            .Returns(call => call.Arg<Func<CancellationToken, Task>>().Invoke(CancellationToken.None));

        _links.When(repository => repository.Add(Arg.Any<SupplierCompanyLink>()))
            .Do(call => _added.Add(call.Arg<SupplierCompanyLink>()));
    }

    private SupplierLinkAppService Sut => new(
        new AdminScopeService(
            _directory,
            Substitute.For<ITenantMemberDirectory>(),
            Substitute.For<IUserTenantRoleRepository>(),
            Substitute.For<IRoleRepository>(),
            Substitute.For<IRoleMenuRepository>(),
            Substitute.For<IMenuRepository>(),
            Substitute.For<IRolePermissionRepository>()),
        _links,
        _members,
        _backendUsers,
        _backendIdentities,
        _masterData,
        _convergence,
        _protector,
        new IamAuditWriter(_auditLog, new TestClock(Now), NullLogger<IamAuditWriter>.Instance),
        _unitOfWork,
        new TestClock(Now),
        NullLogger<SupplierLinkAppService>.Instance);

    // ---------------------------------------------------------------- the read

    [Fact]
    public async Task ListRefusesACallerWithoutTheReadPermission()
    {
        var caller = SliceCaller.HoldingNothing();
        _directory.FindFlagsAsync(caller.UserId, Arg.Any<CancellationToken>())
            .Returns((BackOfficeUserFlags?)null);

        var error = await Should.ThrowAsync<ForbiddenException>(() =>
            Sut.ListAsync(caller, ["S1"], null, CancellationToken.None));

        error.ErrorCode.ShouldBe(ErrorCodes.Forbidden);
        await _links.DidNotReceive().ListActiveBySuppliersAsync(
            Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ListRefusesASingleTenantSessionEvenWhenItHoldsTheReadPermission()
    {
        // The permission points sit on a platform-audience menu, but the audience rule that would
        // keep that menu off a company-owned role is off service-wide - so a company administrator
        // can grant themselves this code. The answer here spans tenants and has no per-tenant
        // narrowing to fall back on, so the acting context has to be part of the gate.
        var caller = SliceCaller.InCompanyContext("C9", SupplierLinkPermissions.Read);

        await Should.ThrowAsync<ForbiddenException>(
            Sut.ListAsync(caller, ["S1"], null, CancellationToken.None));

        await _links.DidNotReceive().ListActiveBySuppliersAsync(
            Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task UpdateRefusesASingleTenantSessionEvenWhenItHoldsTheManagePermission()
    {
        // Worse than the read: with the manage point a company session could mount another
        // company's supplier onto its own, which hands its own members data scope over that
        // supplier downstream.
        var caller = SliceCaller.InCompanyContext("C9", SupplierLinkPermissions.Manage);
        MasterData();

        await Should.ThrowAsync<ForbiddenException>(
            Sut.UpdateLinkAsync(
                caller, "S1", new UpdateSupplierLinkRequest { CompanyCode = "C9" }, CancellationToken.None));

        _added.ShouldBeEmpty();
        await _masterData.DidNotReceive().ValidateAsync(
            Arg.Any<IReadOnlyCollection<string>>(),
            Arg.Any<IReadOnlyCollection<string>>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ListWithNeitherFilterAnswersEmptyRatherThanEveryMountingOnThePlatform()
    {
        var response = await Sut.ListAsync(Caller(), [], "  ", CancellationToken.None);

        response.Items.ShouldBeEmpty();
        await _links.DidNotReceive().ListActiveByCompanyAsync(
            Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _members.DidNotReceive().FindAdminsByTenantsAsync(
            Arg.Any<string>(), Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ListKeepsTheRequestedOrderAndReportsAnUnmountedSupplierAsNull()
    {
        _links.ListActiveBySuppliersAsync(Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>())
            .Returns([Link("S2", "C9")]);
        _members.CountActiveByTenantsAsync(
                TenantTypes.Supplier, Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns(new Dictionary<string, int> { ["S2"] = 3 });

        var response = await Sut.ListAsync(Caller(), ["S2", "S1"], null, CancellationToken.None);

        response.Items.Select(item => item.SupplierCode).ShouldBe(["S2", "S1"]);
        response.Items[0].CompanyCode.ShouldBe("C9");
        response.Items[0].MemberCount.ShouldBe(3);

        // Null, not "": the front end has to be able to tell "independent" from "mounted onto a
        // company whose code we failed to read".
        response.Items[1].CompanyCode.ShouldBeNull();
        response.Items[1].MemberCount.ShouldBe(0);
        response.Items[1].Admins.ShouldBeEmpty();
        response.Items[1].Admin.ShouldBeNull();
    }

    [Fact]
    public async Task ListReportsEveryAdministratorAndKeepsTheFirstAsTheLegacyField()
    {
        _members.FindAdminsByTenantsAsync(
                TenantTypes.Supplier, Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([Admin(11, "S1"), Admin(12, "S1")]);

        var response = await Sut.ListAsync(Caller(), ["S1"], null, CancellationToken.None);

        // Grouped rather than overwritten: keying one member per tenant code would silently keep
        // only the last administrator.
        response.Items[0].Admins.Select(admin => admin.UserId).ShouldBe([11, 12]);
        response.Items[0].Admin!.UserId.ShouldBe(11);
    }

    [Fact]
    public async Task TheLegacyFirstAdministratorDoesNotDependOnWhatOrderTheDatabaseReturned()
    {
        // The port does not order, so a row order is not something this response may inherit: the
        // Admin field is Admins[0], and it must name the same person on the next page load.
        _members.FindAdminsByTenantsAsync(
                TenantTypes.Supplier, Arg.Any<IReadOnlyCollection<string>>(), Arg.Any<CancellationToken>())
            .Returns([Admin(12, "S1"), Admin(11, "S1")]);

        var response = await Sut.ListAsync(Caller(), ["S1"], null, CancellationToken.None);

        response.Items[0].Admins.Select(admin => admin.UserId).ShouldBe([11, 12]);
        response.Items[0].Admin!.UserId.ShouldBe(11);
    }

    [Fact]
    public async Task ACompanyFilterNarrowsAnExplicitSupplierSet()
    {
        _links.ListActiveBySuppliersAsync(Arg.Any<IReadOnlyList<string>>(), Arg.Any<CancellationToken>())
            .Returns([Link("S1", "C1"), Link("S2", "C2")]);

        var response = await Sut.ListAsync(Caller(), ["S1", "S2", "S3"], "C1", CancellationToken.None);

        // S2 hangs elsewhere and S3 hangs nowhere; both drop out rather than coming back with a
        // company code the caller did not ask about.
        response.Items.Select(item => item.SupplierCode).ShouldBe(["S1"]);
    }

    [Fact]
    public async Task ListingByCompanyAloneSortsTheCodesItDiscovered()
    {
        _links.ListActiveByCompanyAsync("C1", Arg.Any<CancellationToken>())
            .Returns([Link("S3", "C1"), Link("S1", "C1"), Link("S3", "C1")]);

        var response = await Sut.ListAsync(Caller(), [], "C1", CancellationToken.None);

        response.Items.Select(item => item.SupplierCode).ShouldBe(["S1", "S3"]);
    }

    // ---------------------------------------------------------------- the write

    [Fact]
    public async Task UpdateRefusesACallerWithoutTheManagePermission()
    {
        var caller = SliceCaller.Holding(SupplierLinkPermissions.Read);
        _directory.FindFlagsAsync(caller.UserId, Arg.Any<CancellationToken>())
            .Returns((BackOfficeUserFlags?)null);

        await Should.ThrowAsync<ForbiddenException>(() => Sut.UpdateLinkAsync(
            caller, "S1", new UpdateSupplierLinkRequest { CompanyCode = "C1" }, CancellationToken.None));

        await _masterData.DidNotReceive().ValidateAsync(
            Arg.Any<IReadOnlyCollection<string>>(),
            Arg.Any<IReadOnlyCollection<string>>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ABlankSupplierCodeReportsSupplierNotFound()
    {
        var error = await Should.ThrowAsync<BadRequestException>(() => Sut.UpdateLinkAsync(
            ManagingCaller(), "   ", new UpdateSupplierLinkRequest(), CancellationToken.None));

        // Not BAD_REQUEST. The Go contract answers SUPPLIER_NOT_FOUND here and the code is a client
        // contract, not ours to improve on.
        error.ErrorCode.ShouldBe(ErrorCodes.SupplierNotFound);
    }

    [Fact]
    public async Task UnreachableMasterDataFailsTheWriteInsteadOfMountingUncheckedCodes()
    {
        _masterData.ValidateAsync(
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<CancellationToken>())
            .Returns((IReadOnlyList<TenantMasterDataEntry>?)null);

        var error = await Should.ThrowAsync<UpstreamException>(() => Sut.UpdateLinkAsync(
            ManagingCaller(), "S1", new UpdateSupplierLinkRequest { CompanyCode = "C1" },
            CancellationToken.None));

        error.ErrorCode.ShouldBe(ErrorCodes.UpstreamUnavailable);
        error.StatusCode.ShouldBe(502);

        // Nothing was written, so nothing is audited. This is the whole point of failing the write:
        // the mounting grants data scope over a company nobody confirmed exists.
        _added.ShouldBeEmpty();
        await _auditLog.DidNotReceive().AppendAsync(
            Arg.Any<UserSvc.Domain.Iam.IamAuditLog>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// A supplier that exists and is not approved. <b>Not</b> the same answer as a supplier the
    /// master data has never heard of - the two were one code until the port could tell them
    /// apart, and the operator's next move differs: one of them means "get it approved", the other
    /// means "you typed the wrong code".
    /// </summary>
    [Fact]
    public async Task AnUnapprovedSupplierIsRefusedWith422()
    {
        MasterData(supplier: Verdicts.NotUsable);

        var error = await Should.ThrowAsync<AppException>(() => Sut.UpdateLinkAsync(
            ManagingCaller(), "S1", new UpdateSupplierLinkRequest { CompanyCode = "C1" },
            CancellationToken.None));

        error.ErrorCode.ShouldBe(ErrorCodes.SupplierNotApproved);
        error.StatusCode.ShouldBe(422);
        _added.ShouldBeEmpty();
    }

    /// <summary>
    /// A supplier the master data reports as not existing is SUPPLIER_NOT_FOUND, not
    /// SUPPLIER_NOT_APPROVED. This is the case a boolean port could not express: the entry is
    /// present and unusable either way, so the endpoint used to tell an operator to go and get a
    /// supplier approved that the master data has never heard of.
    /// </summary>
    [Fact]
    public async Task ASupplierTheMasterDataDoesNotKnowIsNotFoundRatherThanNotApproved()
    {
        MasterData(supplier: Verdicts.Unknown);

        var error = await Should.ThrowAsync<BadRequestException>(() => Sut.UpdateLinkAsync(
            ManagingCaller(), "S1", new UpdateSupplierLinkRequest { CompanyCode = "C1" },
            CancellationToken.None));

        error.ErrorCode.ShouldBe(ErrorCodes.SupplierNotFound);
        error.StatusCode.ShouldBe(400);
        error.Message.ShouldContain("knows no supplier");
        _added.ShouldBeEmpty();
    }

    /// <summary>
    /// The other shape of "never heard of it": the master data answered and mentioned neither code.
    /// The port says the two shapes must read identically, so an omitted entry is the unknown
    /// verdict and not a usable one.
    /// </summary>
    [Fact]
    public async Task AMasterDataAnswerThatMentionsNoCodesIsSupplierNotFound()
    {
        MasterDataMentioningNothing();

        var error = await Should.ThrowAsync<BadRequestException>(() => Sut.UpdateLinkAsync(
            ManagingCaller(), "S1", new UpdateSupplierLinkRequest { CompanyCode = "C1" },
            CancellationToken.None));

        error.ErrorCode.ShouldBe(ErrorCodes.SupplierNotFound);
        _added.ShouldBeEmpty();
    }

    /// <summary>
    /// A company the master data has never heard of, and one that has been switched off, answer the
    /// <b>same</b> error code - the Go contract publishes one for both and neither is somewhere a
    /// supplier may hang - and different details, which is all the port's extra precision is spent
    /// on here.
    /// </summary>
    [Fact]
    public async Task AnUnknownCompanyAndAnInactiveOneShareTheirCodeAndNotTheirDetail()
    {
        MasterData(company: Verdicts.Unknown);

        var unknown = await Should.ThrowAsync<BadRequestException>(() => Sut.UpdateLinkAsync(
            ManagingCaller(), "S1", new UpdateSupplierLinkRequest { CompanyCode = "C1" },
            CancellationToken.None));

        MasterData(company: Verdicts.NotUsable);

        var inactive = await Should.ThrowAsync<BadRequestException>(() => Sut.UpdateLinkAsync(
            ManagingCaller(), "S1", new UpdateSupplierLinkRequest { CompanyCode = "C1" },
            CancellationToken.None));

        unknown.ErrorCode.ShouldBe(ErrorCodes.CompanyNotFound);
        inactive.ErrorCode.ShouldBe(ErrorCodes.CompanyNotFound);
        unknown.Message.ShouldContain("knows no company");
        inactive.Message.ShouldContain("not active");
        _added.ShouldBeEmpty();
    }

    /// <summary>
    /// The supplier is judged before the company, so an operator who got both codes wrong is told
    /// about the one in the path first. Pinned because both are refusals and the order is the only
    /// thing that decides which code the client sees.
    /// </summary>
    [Fact]
    public async Task TheSupplierVerdictIsReportedAheadOfTheCompanyOne()
    {
        MasterData(
            supplier: Verdicts.NotUsable,
            company: Verdicts.Unknown);

        var error = await Should.ThrowAsync<AppException>(() => Sut.UpdateLinkAsync(
            ManagingCaller(), "S1", new UpdateSupplierLinkRequest { CompanyCode = "C1" },
            CancellationToken.None));

        error.ErrorCode.ShouldBe(ErrorCodes.SupplierNotApproved);
    }

    [Fact]
    public async Task RemountingOntoTheSameCompanyIsAConflict()
    {
        MasterData();
        _links.FindActiveBySupplierAsync("S1", Arg.Any<CancellationToken>()).Returns(Link("S1", "C1"));

        var error = await Should.ThrowAsync<ConflictException>(() => Sut.UpdateLinkAsync(
            ManagingCaller(), "S1", new UpdateSupplierLinkRequest { CompanyCode = "C1" },
            CancellationToken.None));

        error.ErrorCode.ShouldBe(ErrorCodes.SupplierAlreadyLinked);
        _added.ShouldBeEmpty();
    }

    [Fact]
    public async Task AFirstMountWritesTheRowAndAnAuditEntryButRetiresNobodysToken()
    {
        MasterData();

        await Sut.UpdateLinkAsync(
            ManagingCaller(), " S1 ", new UpdateSupplierLinkRequest { CompanyCode = " C1 " },
            CancellationToken.None);

        var inserted = _added.ShouldHaveSingleItem();
        inserted.SupplierCode.ShouldBe("S1");
        inserted.CompanyCode.ShouldBe("C1");
        inserted.Status.ShouldBe(SupplierCompanyLinkStatuses.Active);
        inserted.CreatedBy.ShouldBe("operator");

        var entry = await CapturedAuditAsync();
        entry.Action.ShouldBe(SupplierLinkAuditVocabulary.LinkAction);
        entry.TargetType.ShouldBe(SupplierLinkAuditVocabulary.TargetType);
        entry.TargetId.ShouldBe("S1");
        entry.BeforeData.ShouldBeNull();
        entry.AfterData.ShouldNotBeNull().ShouldContain("\"company_code\":\"C1\"");
        entry.Ip.ShouldBe("203.0.113.9");
        entry.RequestId.ShouldBe("req-supplier-1");

        // A first mount takes nothing away: purely additive grants converge on the next natural
        // refresh, and re-signing every session for one is churn.
        await _convergence.DidNotReceive().BumpTokenVersionAsync(
            Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ARelinkRetiresTheOldRowInTheSameTransactionAndRevokesBothSidesTokens()
    {
        MasterData(companyCode: "C2");
        var existing = Link("S1", "C1");
        _links.FindActiveBySupplierAsync("S1", Arg.Any<CancellationToken>()).Returns(existing);
        _members.FindUserIdsByTenantCodeAsync(TenantTypes.Supplier, "S1", Arg.Any<CancellationToken>())
            .Returns([5, 4]);
        _members.FindUserIdsByTenantCodeAsync(TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns([4, 9]);

        await Sut.UpdateLinkAsync(
            ManagingCaller(), "S1", new UpdateSupplierLinkRequest { CompanyCode = "C2" },
            CancellationToken.None);

        _added.ShouldHaveSingleItem().CompanyCode.ShouldBe("C2");

        await _unitOfWork.Received(1).ExecuteInTransactionAsync(
            Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>());

        // The old row is retired by one statement carrying the actor and the timestamp, inside that
        // transaction and before the insert is saved: two ACTIVE rows for one supplier is exactly
        // what the partial unique index refuses, even momentarily.
        await _links.Received(1).UnlinkActiveBySupplierAsync(
            "S1", Now, "operator", Arg.Any<CancellationToken>());

        // One save, not two. The retirement is a statement rather than staged entity state, which
        // is also what makes the transaction body safe for the retry strategy to replay.
        await _unitOfWork.Received(1).SaveChangesAsync(Arg.Any<CancellationToken>());

        // A relink is a revocation for the company that lost the supplier, and for the supplier's
        // own members who lose that company. Deduplicated and sorted.
        await _convergence.Received(1).BumpTokenVersionAsync(
            Arg.Is<IReadOnlyCollection<int>>(ids => ids.SequenceEqual(new[] { 4, 5, 9 })),
            Arg.Any<CancellationToken>());

        var entry = await CapturedAuditAsync();
        entry.BeforeData.ShouldNotBeNull().ShouldContain("\"company_code\":\"C1\"");
        entry.AfterData.ShouldNotBeNull().ShouldContain("\"company_code\":\"C2\"");
    }

    [Fact]
    public async Task UnmountingASupplierThatHangsNowhereDoesNothingAtAll()
    {
        await Sut.UpdateLinkAsync(
            ManagingCaller(), "S1", new UpdateSupplierLinkRequest { CompanyCode = null },
            CancellationToken.None);

        await _unitOfWork.DidNotReceive().SaveChangesAsync(Arg.Any<CancellationToken>());
        await _links.DidNotReceive().UnlinkActiveBySupplierAsync(
            Arg.Any<string>(), Arg.Any<DateTimeOffset>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _auditLog.DidNotReceive().AppendAsync(
            Arg.Any<UserSvc.Domain.Iam.IamAuditLog>(), Arg.Any<CancellationToken>());
        await _convergence.DidNotReceive().BumpTokenVersionAsync(
            Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>());
        await _masterData.DidNotReceive().ValidateAsync(
            Arg.Any<IReadOnlyCollection<string>>(),
            Arg.Any<IReadOnlyCollection<string>>(),
            Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task AnAbsentOrBlankCompanyCodeMeansUnmount(string? companyCode)
    {
        _links.FindActiveBySupplierAsync("S1", Arg.Any<CancellationToken>()).Returns(Link("S1", "C1"));
        _members.FindUserIdsByTenantCodeAsync(TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns([9]);

        await Sut.UpdateLinkAsync(
            ManagingCaller(), "S1", new UpdateSupplierLinkRequest { CompanyCode = companyCode },
            CancellationToken.None);

        await _links.Received(1).UnlinkActiveBySupplierAsync(
            "S1", Now, "operator", Arg.Any<CancellationToken>());

        // No SaveChanges and no transaction: one statement is already atomic, and the company code
        // the reissue needs was captured by the read above.
        await _unitOfWork.DidNotReceive().SaveChangesAsync(Arg.Any<CancellationToken>());
        await _unitOfWork.DidNotReceive().ExecuteInTransactionAsync(
            Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>());

        var entry = await CapturedAuditAsync();
        entry.Action.ShouldBe(SupplierLinkAuditVocabulary.UnlinkAction);

        // The company that just lost the supplier from its envelope is exactly who has to be
        // re-signed, which is why the row is read before it is retired.
        await _convergence.Received(1).BumpTokenVersionAsync(
            Arg.Is<IReadOnlyCollection<int>>(ids => ids.SequenceEqual(new[] { 9 })),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnUnmountThatTouchedNoRowRecordsNothing()
    {
        // Two operators unmounting the same supplier at once: both read an ACTIVE row, and the
        // statement of the one that arrives second touches nothing. Nothing happened for it, so it
        // must not write an audit row saying it did, and must not retire anybody's token.
        _links.FindActiveBySupplierAsync("S1", Arg.Any<CancellationToken>()).Returns(Link("S1", "C1"));
        _links.UnlinkActiveBySupplierAsync(
                "S1", Arg.Any<DateTimeOffset>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(0);
        _members.FindUserIdsByTenantCodeAsync(TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns([9]);

        await Sut.UpdateLinkAsync(
            ManagingCaller(), "S1", new UpdateSupplierLinkRequest(), CancellationToken.None);

        await _auditLog.DidNotReceive().AppendAsync(
            Arg.Any<UserSvc.Domain.Iam.IamAuditLog>(), Arg.Any<CancellationToken>());
        await _convergence.DidNotReceive().BumpTokenVersionAsync(
            Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AFailedTokenRetirementDoesNotUndoAnUnmountThatHasHappened()
    {
        _links.FindActiveBySupplierAsync("S1", Arg.Any<CancellationToken>()).Returns(Link("S1", "C1"));
        _members.FindUserIdsByTenantCodeAsync(TenantTypes.Supplier, "S1", Arg.Any<CancellationToken>())
            .Throws(new InvalidOperationException("membership read is down"));
        _members.FindUserIdsByTenantCodeAsync(TenantTypes.Company, "C1", Arg.Any<CancellationToken>())
            .Returns([9]);
        _convergence.BumpTokenVersionAsync(
                Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Throws(new InvalidOperationException("cache is down"));

        // Both halves of the reissue fail and the call still succeeds: the database is already
        // authoritative for the next token, so the fallback is the old expiry window rather than an
        // unmount that silently did not happen.
        await Sut.UpdateLinkAsync(
            ManagingCaller(), "S1", new UpdateSupplierLinkRequest(), CancellationToken.None);

        await _links.Received(1).UnlinkActiveBySupplierAsync(
            "S1", Now, "operator", Arg.Any<CancellationToken>());
        (await CapturedAuditAsync()).Action.ShouldBe(SupplierLinkAuditVocabulary.UnlinkAction);
    }

    [Fact]
    public async Task AFailedAuditWriteDoesNotFailTheWriteItDescribes()
    {
        _links.FindActiveBySupplierAsync("S1", Arg.Any<CancellationToken>()).Returns(Link("S1", "C1"));
        _auditLog.AppendAsync(Arg.Any<UserSvc.Domain.Iam.IamAuditLog>(), Arg.Any<CancellationToken>())
            .Throws(new InvalidOperationException("audit table is unreachable"));

        await Sut.UpdateLinkAsync(
            ManagingCaller(), "S1", new UpdateSupplierLinkRequest(), CancellationToken.None);

        await _links.Received(1).UnlinkActiveBySupplierAsync(
            "S1", Now, "operator", Arg.Any<CancellationToken>());
    }

    // ---------------------------------------------------------------- helpers

    private static SliceCaller Caller() => SliceCaller.Holding(SupplierLinkPermissions.Read);

    private static SliceCaller ManagingCaller() => SliceCaller.Holding(SupplierLinkPermissions.Manage);

    private static SupplierCompanyLink Link(string supplierCode, string companyCode) => new()
    {
        Id = 1,
        SupplierCode = supplierCode,
        CompanyCode = companyCode,
        Status = SupplierCompanyLinkStatuses.Active,
        CreatedAt = Now,
        UpdatedAt = Now,
    };

    private static TenantMember Admin(int userId, string tenantCode) => new()
    {
        Id = userId,
        UserId = userId,
        TenantType = TenantTypes.Supplier,
        TenantCode = tenantCode,
        IsAdmin = true,
        Status = TenantMemberStatuses.Active,
    };

    /// <summary>
    /// What the master data says about the two codes a mounting names. The default is the happy
    /// answer; each verdict is passed explicitly by the test that cares about it.
    /// </summary>
    private void MasterData(
        Verdicts supplier = Verdicts.Usable,
        Verdicts company = Verdicts.Usable,
        string supplierCode = "S1",
        string companyCode = "C1") =>
        _masterData.ValidateAsync(
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<CancellationToken>())
            .Returns(new List<TenantMasterDataEntry>
            {
                new(TenantTypes.Supplier, supplierCode, supplier, new Dictionary<string, string>()),
                new(TenantTypes.Company, companyCode, company, new Dictionary<string, string>()),
            });

    /// <summary>
    /// A master data that answered, but mentioned neither code - the other shape of "never heard of
    /// it", and the one a real adapter produces when the upstream simply omits an unknown code.
    /// </summary>
    private void MasterDataMentioningNothing() =>
        _masterData.ValidateAsync(
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<CancellationToken>())
            .Returns(new List<TenantMasterDataEntry>());

    private async Task<UserSvc.Domain.Iam.IamAuditLog> CapturedAuditAsync()
    {
        var calls = _auditLog.ReceivedCalls().ToList();
        calls.ShouldNotBeEmpty("the write must record why it happened");

        await Task.CompletedTask;

        return (UserSvc.Domain.Iam.IamAuditLog)calls[^1].GetArguments()[0]!;
    }
}
