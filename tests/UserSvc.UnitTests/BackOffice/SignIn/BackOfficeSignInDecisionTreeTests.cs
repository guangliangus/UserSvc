using NSubstitute;
using Shouldly;
using UserSvc.Application.Features.BackOffice.SignIn;
using UserSvc.Domain.BackOffice;
using UserSvc.Domain.Tenancy;
using Xunit;

namespace UserSvc.UnitTests.BackOffice.SignIn;

/// <summary>
/// The sign-in decision tree: what an operator gets once their credential has been accepted.
/// <para>
/// Several of these outcomes look wrong at first reading and are deliberate. An account that is
/// not activated signs in; an account nobody has added to a tenant signs in; a whole dimension is
/// a context you can be dropped into without being asked; and a company the master data has
/// switched off stops counting as somewhere you can go. Each case below says which failure the
/// obvious alternative produced.
/// </para>
/// </summary>
public sealed class BackOfficeSignInDecisionTreeTests
{
    private readonly SignInTestHarness _harness = new();

    private BackOfficePasswordSignInRequest Request => new()
    {
        Email = SignInTestHarness.CorporateEmail,
        Password = SignInTestHarness.Password,
    };

    /// <summary>
    /// A PENDING account authenticates and is handed nothing. Refusing it - the obvious reading of
    /// "not activated" - makes a brand-new account look broken to the person who has just been
    /// told to log in and finish setting it up.
    /// </summary>
    [Fact]
    public async Task AnAccountThatIsNotActivatedSignsInAndHoldsNoAuthority()
    {
        _harness.WithPasswordAccount(status: BackendUserStatuses.Pending);

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        response.ContextRequired.ShouldBeFalse();
        response.GrantedScope.ShouldBe("backoffice");
        response.ActiveTenant.ShouldBeNull();
        response.IsTenantAdmin.ShouldBeFalse();

        // Stated as empty, never omitted: a missing menu list reads to the front end as "this
        // backend does not gate menus" and opens everything.
        response.Roles.ShouldBeEmpty();
        response.Permissions.ShouldBeEmpty();
        response.Menus.ShouldBeEmpty();
        response.Tenants.ShouldBeEmpty();
        response.Scopes.Keys.ShouldBe([TenantTypes.Company, TenantTypes.Supplier], ignoreOrder: true);
        response.Scopes.Values.ShouldAllBe(scope => !scope.IsGlobal && scope.Values.Count == 0);

        _harness.Tickets.Open(response.SignInTicket).ToActClaim().ShouldBeNull();
    }

    /// <summary>
    /// An account with no context signs in too. The older behaviour - refusing with
    /// NO_TENANT_BOUND - made every account look defective in the window between being created and
    /// being added to a tenant.
    /// </summary>
    [Fact]
    public async Task AnAccountWithNoContextSignsInAndHoldsNoAuthority()
    {
        _harness.WithPasswordAccount();

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        response.ContextRequired.ShouldBeFalse();
        response.ActiveTenant.ShouldBeNull();
        response.Tenants.ShouldBeEmpty();
        response.Menus.ShouldBeEmpty();
    }

    /// <summary>
    /// The platform super administrator is asked nothing and offered nothing to choose from. The
    /// flag is read from the database, never from anything the caller sent.
    /// </summary>
    [Fact]
    public async Task ThePlatformSuperAdministratorLandsInThePlatformContextWithNoOptions()
    {
        _harness.WithPasswordAccount();
        _harness.Standing.IsPlatformSuperAdminAsync(57, Arg.Any<CancellationToken>()).Returns(true);

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        response.ContextRequired.ShouldBeFalse();
        response.ActiveTenant.ShouldNotBeNull().Type.ShouldBe("platform");
        response.IsGlobal.ShouldBeTrue();

        // Empty on purpose: the platform context is their only one, so the switcher renders a badge
        // rather than a menu with a single item in it.
        response.Tenants.ShouldBeEmpty();

        _harness.Tickets.Open(response.SignInTicket).ActType.ShouldBe(ActTypes.Platform);
    }

    /// <summary>One tenant and nothing else is entered without asking.</summary>
    [Fact]
    public async Task ASingleTenantIsEnteredAutomatically()
    {
        _harness.WithPasswordAccount();
        _harness.AddMembership(tenantCode: "C1", isAdmin: true);

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        response.ContextRequired.ShouldBeFalse();
        response.GrantedScope.ShouldBe("backoffice");

        var active = response.ActiveTenant.ShouldNotBeNull();
        active.Type.ShouldBe("company");
        active.CompanyCode.ShouldBe("C1");

        // The administrator flag rides in the act claim, because it is what the shell renders
        // administrator affordances from and recomputing it downstream would need the member row
        // again.
        response.IsTenantAdmin.ShouldBeTrue();

        var ticket = _harness.Tickets.Open(response.SignInTicket);
        ticket.ActType.ShouldBe(ActTypes.Company);
        ticket.ActCode.ShouldBe("C1");
        ticket.ActIsAdmin.ShouldBeTrue();
    }

    /// <summary>
    /// A whole dimension counts as a context, so somebody whose only access is "every company" is
    /// dropped into that dimension rather than being shown a chooser with one card on it.
    /// </summary>
    [Fact]
    public async Task ASingleWholeDimensionIsEnteredAutomatically()
    {
        _harness.WithPasswordAccount();
        _harness.AddMembership(tenantType: TenantTypes.Company, scopeAll: true);

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        response.ContextRequired.ShouldBeFalse();
        response.ActiveTenant.ShouldNotBeNull().Type.ShouldBe("global");
        response.ActiveTenant.Dimension.ShouldBe(TenantTypes.Company);
        response.IsGlobal.ShouldBeTrue();

        var ticket = _harness.Tickets.Open(response.SignInTicket);
        ticket.ActType.ShouldBe(ActTypes.Global);
        ticket.ActDimension.ShouldBe(TenantTypes.Company);
    }

    /// <summary>
    /// A dimension and a tenant are two places to be, not one, so this sign-in has to choose - and
    /// what it gets until it does is a pre-tenant ticket and the option list, with every authority
    /// field empty.
    /// </summary>
    [Fact]
    public async Task TwoContextsProduceAPreTenantSignIn()
    {
        _harness.WithPasswordAccount();
        _harness.AddMembership(tenantType: TenantTypes.Company, scopeAll: true);
        _harness.AddMembership(tenantType: TenantTypes.Supplier, tenantCode: "S1");

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        response.ContextRequired.ShouldBeTrue();
        response.GrantedScope.ShouldBe("backoffice_pre_tenant");
        response.ActiveTenant.ShouldBeNull();
        response.Tenants.Count.ShouldBe(2);

        // Widest first: the dimension card sits above the single supplier.
        response.Tenants[0].ScopeAll.ShouldBeTrue();
        response.Tenants[0].TenantCode.ShouldBe(TenantScopes.ScopeAllSentinelCode);
        response.Tenants[1].TenantCode.ShouldBe("S1");

        response.Roles.ShouldBeEmpty();
        response.Permissions.ShouldBeEmpty();
        response.Menus.ShouldBeEmpty();

        _harness.Tickets.Open(response.SignInTicket).ContextRequired.ShouldBeTrue();
    }

    /// <summary>
    /// The options are counted after the master data has had its say. Without that, a one-company
    /// operator whose company was switched off yesterday is still dropped straight into it.
    /// </summary>
    [Fact]
    public async Task ADeactivatedTenantStopsCountingAsAContext()
    {
        _harness.WithPasswordAccount();
        _harness.AddMembership(tenantCode: "C1");
        _harness.WithUnusableTenant(TenantTypes.Company, "C1");

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        response.ContextRequired.ShouldBeFalse();
        response.ActiveTenant.ShouldBeNull();
        response.Tenants.ShouldBeEmpty();
    }

    /// <summary>
    /// Two tenants, one of them switched off, resolve to the survivor - the count drops to one and
    /// the auto-select happens, rather than a chooser being drawn with a dead entry on it.
    /// </summary>
    [Fact]
    public async Task ADeactivatedTenantDoesNotForceAChoice()
    {
        _harness.WithPasswordAccount();
        _harness.AddMembership(tenantCode: "C1");
        _harness.AddMembership(tenantCode: "C2");
        _harness.WithUnusableTenant(TenantTypes.Company, "C2");

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        response.ContextRequired.ShouldBeFalse();
        response.ActiveTenant.ShouldNotBeNull().CompanyCode.ShouldBe("C1");
    }

    /// <summary>
    /// <b>Master data unreachable keeps every tenant.</b> Fail-open is deliberate and it has a
    /// cost: during an outage a switched-off tenant can be entered. The alternative locks the whole
    /// back office out of every tenant because one upstream is down, and this gate was never the
    /// authorization boundary - the member row and the permission codes are.
    /// </summary>
    [Fact]
    public async Task UnreachableMasterDataKeepsEveryTenant()
    {
        _harness.WithPasswordAccount();
        _harness.AddMembership(tenantCode: "C1");
        _harness.AddMembership(tenantCode: "C2");

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        response.ContextRequired.ShouldBeTrue();
        response.Tenants.Count.ShouldBe(2);
    }

    /// <summary>
    /// A finished sign-in is audited; a sign-in still at the chooser is not. Its later choice is
    /// recorded as a tenant switch by the endpoint that makes it, and auditing both would count one
    /// arrival twice.
    /// </summary>
    [Fact]
    public async Task OnlyAFinishedSignInIsAudited()
    {
        _harness.WithPasswordAccount();
        _harness.AddMembership(tenantCode: "C1");

        await _harness.Sut.SignInWithPasswordAsync(
            Request, new BackOfficeSignInContext("203.0.113.7", "curl", "req-1"), CancellationToken.None);

        await _harness.AuditLog.Received(1).AppendAsync(
            Arg.Is<UserSvc.Domain.Iam.IamAuditLog>(entry =>
                entry.Action == BackOfficeSignInAuditActions.SignIn
                && entry.ActorUserId == 57
                && entry.TenantType == TenantTypes.Company
                && entry.TenantCode == "C1"
                && entry.Ip == "203.0.113.7"
                && entry.RequestId == "req-1"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task APreTenantSignInIsNotAuditedAsAnArrival()
    {
        _harness.WithPasswordAccount();
        _harness.AddMembership(tenantCode: "C1");
        _harness.AddMembership(tenantCode: "C2");

        await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        await _harness.AuditLog.DidNotReceive().AppendAsync(
            Arg.Is<UserSvc.Domain.Iam.IamAuditLog>(entry => entry.Action == BackOfficeSignInAuditActions.SignIn),
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// A failed audit write never fails the sign-in. The operator is through the door either way,
    /// and refusing them afterwards would report a false negative for a session that exists.
    /// </summary>
    [Fact]
    public async Task AFailedAuditWriteDoesNotFailTheSignIn()
    {
        _harness.WithPasswordAccount();
        _harness.AddMembership(tenantCode: "C1");
        _harness.AuditLog
            .AppendAsync(Arg.Any<UserSvc.Domain.Iam.IamAuditLog>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromException(new InvalidOperationException("audit table is full")));

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        response.ActiveTenant.ShouldNotBeNull().CompanyCode.ShouldBe("C1");
    }

    /// <summary>The arrival is recorded on the account row, and a failure to record it does not
    /// fail the sign-in either.</summary>
    [Fact]
    public async Task TheSignInIsRecordedOnTheAccount()
    {
        var account = _harness.WithPasswordAccount();

        await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        account.LastLoginAt.ShouldBe(_harness.Clock.UtcNow);
        await _harness.UnitOfWork.Received(1).SaveChangesAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AFailedLastLoginWriteDoesNotFailTheSignIn()
    {
        _harness.WithPasswordAccount();
        _harness.UnitOfWork.SaveChangesAsync(Arg.Any<CancellationToken>())
            .Returns(Task.FromException<int>(new InvalidOperationException("connection reset")));

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        response.UserId.ShouldBe(57);
    }

    /// <summary>The ticket carries the token version the sign-in saw, because it is the authority
    /// snapshot's cache key.</summary>
    [Fact]
    public async Task TheTicketCarriesTheAccountsTokenVersion()
    {
        _harness.WithPasswordAccount(tokenVersion: 11);

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        _harness.Tickets.Open(response.SignInTicket).TokenVersion.ShouldBe(11);
    }
}
