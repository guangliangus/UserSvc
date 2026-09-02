using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.SignIn;
using UserSvc.Application.Features.BackOffice.Tenants;
using UserSvc.Domain.BackOffice;
using UserSvc.Domain.Tenancy;
using Xunit;

namespace UserSvc.UnitTests.BackOffice.SignIn;

/// <summary>
/// Redeeming a ticket, and exchanging a chosen context - the two things the token endpoint asks the
/// application layer before it mints anything.
/// </summary>
public sealed class BackOfficeTokenGrantTests
{
    private readonly SignInTestHarness _harness = new();

    private static BackOfficePasswordSignInRequest Request => new()
    {
        Email = SignInTestHarness.CorporateEmail,
        Password = SignInTestHarness.Password,
    };

    /// <summary>
    /// A pre-tenant sign-in redeems into a grant with no context, which is what makes the minted
    /// token a pre-tenant one. The client does not get to choose.
    /// </summary>
    [Fact]
    public async Task APreTenantTicketRedeemsIntoAPreTenantGrant()
    {
        _harness.WithPasswordAccount();
        _harness.AddMembership(tenantCode: "C1");
        _harness.AddMembership(tenantCode: "C2");

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        var grant = await _harness.Sut.RedeemAsync(response.SignInTicket, CancellationToken.None);

        grant.IsPreTenant.ShouldBeTrue();
        grant.Act.ShouldBeNull();
        grant.UserId.ShouldBe(57);
    }

    [Fact]
    public async Task AResolvedTicketRedeemsIntoAFullGrantCarryingTheContext()
    {
        _harness.WithPasswordAccount();
        _harness.AddMembership(tenantCode: "C1", isAdmin: true);

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        var grant = await _harness.Sut.RedeemAsync(response.SignInTicket, CancellationToken.None);

        grant.IsPreTenant.ShouldBeFalse();
        grant.Act.ShouldNotBeNull().Type.ShouldBe(ActTypes.Company);
        grant.Act.Code.ShouldBe("C1");
        grant.Act.IsAdmin.ShouldBeTrue();
        grant.ActorName.ShouldBe("Xiaoming Wang");
    }

    /// <summary>
    /// The status is re-read at redemption rather than trusted from the ticket. The window is two
    /// minutes, and it is exactly the window in which an administrator who has just disabled
    /// somebody expects them to stop being able to sign in.
    /// </summary>
    [Fact]
    public async Task AnAccountDisabledAfterSigningInCannotRedeemItsTicket()
    {
        var account = _harness.WithPasswordAccount();

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        account.Status = BackendUserStatuses.Disabled;

        var refusal = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.RedeemAsync(response.SignInTicket, CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.AccountDisabled);
    }

    /// <summary>A ticket naming an account that no longer exists reads as an unusable ticket, not
    /// as a missing account - the caller must not learn the difference.</summary>
    [Fact]
    public async Task ATicketNamingAVanishedAccountIsUnusable()
    {
        var account = _harness.WithPasswordAccount();

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        _harness.AccountRows.Remove(account);

        var refusal = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.RedeemAsync(response.SignInTicket, CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.InvalidToken);
    }

    /// <summary>The redeemed grant carries the account's <i>current</i> token version, not the one
    /// the ticket was signed with: it is the authority snapshot's cache key.</summary>
    [Fact]
    public async Task TheGrantCarriesTheAccountsCurrentTokenVersion()
    {
        var account = _harness.WithPasswordAccount(tokenVersion: 4);

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        account.TokenVersion = 5;

        var grant = await _harness.Sut.RedeemAsync(response.SignInTicket, CancellationToken.None);

        grant.TokenVersion.ShouldBe(5);
    }

    // ------------------------------------------------------------------ the context exchange

    /// <summary>
    /// Choosing a context produces a full grant carrying it. Every guard behind that choice, and
    /// its audit row, belong to the context service - this exchange contributes none of its own, so
    /// that the REST route and the token route cannot diverge.
    /// </summary>
    [Fact]
    public async Task ChoosingATenantProducesAFullGrantCarryingIt()
    {
        _harness.WithPasswordAccount();
        _harness.AddMembership(tenantCode: "C1", isAdmin: true);
        _harness.AddMembership(tenantCode: "C2");

        var caller = new BackOfficeCaller(57, "Xiaoming Wang", null, 3);

        var grant = await _harness.Sut.SelectContextAsync(
            caller,
            new SelectTenantContextRequest { TenantType = TenantTypes.Company, TenantCode = "C1" },
            CancellationToken.None);

        grant.IsPreTenant.ShouldBeFalse();
        grant.Act.ShouldNotBeNull().Type.ShouldBe(ActTypes.Company);
        grant.Act.Code.ShouldBe("C1");
        grant.Act.IsAdmin.ShouldBeTrue();
    }

    /// <summary>A whole dimension is a context of its own, authorized by standing rather than by a
    /// member row - so it is exchanged the same way.</summary>
    [Fact]
    public async Task ChoosingAWholeDimensionProducesAGlobalGrant()
    {
        _harness.WithPasswordAccount();
        _harness.AddMembership(tenantType: TenantTypes.Company, scopeAll: true);
        _harness.AddMembership(tenantType: TenantTypes.Supplier, tenantCode: "S1");

        var grant = await _harness.Sut.SelectContextAsync(
            new BackOfficeCaller(57, "Xiaoming Wang", null, 3),
            new SelectTenantContextRequest
            {
                TenantType = TenantTypes.Company,
                TenantCode = TenantScopes.ScopeAllSentinelCode,
            },
            CancellationToken.None);

        grant.Act.ShouldNotBeNull().Type.ShouldBe(ActTypes.Global);
        grant.Act.Dimension.ShouldBe(TenantTypes.Company);

        // A dimension has no administrator seat; that standing travels as permissions instead.
        grant.Act.IsAdmin.ShouldBeFalse();
    }

    /// <summary>A context this account does not hold is refused by the context service, and the
    /// exchange does not soften it.</summary>
    [Fact]
    public async Task AContextTheAccountDoesNotHoldIsRefused()
    {
        _harness.WithPasswordAccount();
        _harness.AddMembership(tenantCode: "C1");

        var refusal = await Should.ThrowAsync<ForbiddenException>(() =>
            _harness.Sut.SelectContextAsync(
                new BackOfficeCaller(57, "Xiaoming Wang", null, 3),
                new SelectTenantContextRequest { TenantType = TenantTypes.Company, TenantCode = "C9" },
                CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.TenantNotAuthorized);
    }

    /// <summary>
    /// A disabled account cannot exchange a context either. Without that check, somebody whose
    /// account was switched off but whose membership was left alone could keep re-entering contexts
    /// and walking away with brand-new tokens.
    /// </summary>
    [Fact]
    public async Task ADisabledAccountCannotExchangeAContext()
    {
        _harness.WithPasswordAccount(status: BackendUserStatuses.Disabled);
        _harness.AddMembership(tenantCode: "C1");

        var refusal = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SelectContextAsync(
                new BackOfficeCaller(57, "Xiaoming Wang", null, 3),
                new SelectTenantContextRequest { TenantType = TenantTypes.Company, TenantCode = "C1" },
                CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.AccountDisabled);
    }

    /// <summary>An unidentified caller is refused before anything is read: "no caller" is a real
    /// answer here, and treating it as one is what keeps it from being read as "the platform".</summary>
    [Fact]
    public async Task AnUnidentifiedCallerCannotExchangeAContext()
    {
        var refusal = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SelectContextAsync(
                new BackOfficeCaller(0, string.Empty, null),
                new SelectTenantContextRequest { TenantType = TenantTypes.Company, TenantCode = "C1" },
                CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.Unauthorized);
    }

    /// <summary>The exchange records the switch, so the audit trail says which tenant the operator
    /// entered rather than only that they signed in somewhere.</summary>
    [Fact]
    public async Task TheExchangeIsAuditedAsATenantSwitch()
    {
        _harness.WithPasswordAccount();
        _harness.AddMembership(tenantCode: "C1");

        await _harness.Sut.SelectContextAsync(
            new BackOfficeCaller(57, "Xiaoming Wang", null, 3),
            new SelectTenantContextRequest { TenantType = TenantTypes.Company, TenantCode = "C1" },
            CancellationToken.None);

        await _harness.TenantAudit.Received(1).WriteAsync(
            Arg.Is<UserSvc.Application.Ports.Tenancy.IamAuditEntry>(entry =>
                entry.Action == IamAuditActions.TenantSwitch
                && entry.TenantType == TenantTypes.Company
                && entry.TenantCode == "C1"),
            Arg.Any<CancellationToken>());
    }
}
