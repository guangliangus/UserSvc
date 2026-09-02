using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Domain.Auth;
using UserSvc.Domain.BackOffice;
using UserSvc.Domain.Tenancy;
using UserSvc.Domain.Users;
using UserSvc.IntegrationTests.Infrastructure;
using Xunit;

namespace UserSvc.IntegrationTests;

/// <summary>
/// The back-office credential path, end to end over HTTP: the password door, the ticket it
/// produces, the two grants that redeem it, and the gated endpoints the resulting token does and
/// does not reach.
/// <para>
/// <b>Why this file exists at all.</b> In wave 6 an auditor found that
/// <c>BackOfficeSignInOptions</c> was bound to no configuration section: <c>Program.cs</c>
/// registered the ticket service, the sign-in service and the token issuer, but never called
/// <c>AddOptions&lt;BackOfficeSignInOptions&gt;().Bind(...)</c>. <c>IOptions</c> therefore handed out
/// a default-constructed instance with an empty <c>SignInTicketKey</c>, so both back-office sign-in
/// endpoints and both back-office grants answered 500 <c>NOT_CONFIGURED</c> in <i>every</i>
/// deployment, and no environment variable could fix it because nothing read the section. Twenty-odd
/// endpoints were unreachable. The service had 1,281 passing tests and not one of them touched
/// <c>POST /api/v1/auth/back-office/login</c> or either back-office grant - which is the only
/// reason it survived to be found by a human reading configuration code.
/// </para>
/// <para>
/// <b>So the shape of these tests is deliberate: every one of them walks as far as a working
/// credential.</b> A test that asserted 200 on the login call would not have caught it - the
/// defect's whole signature is that the sign-in <i>and</i> the redemption both fail, and a
/// half-walk that stopped at the ticket would have failed for the same reason without proving the
/// ticket was usable. The happy path therefore goes login -> ticket -> <c>/connect/token</c> ->
/// bearer token -> <c>GET /back-office/me</c>, and asserts a fact from each hop.
/// </para>
/// </summary>
public sealed class BackOfficeSignInFlowTests(ServiceFixture fixture) : IntegrationTest(fixture)
{
    /// <summary>
    /// Codes are per test rather than shared constants because <c>iam.tenant_members</c> carries a
    /// unique index on (user_id, tenant_type, tenant_code) and the audit assertions count rows by
    /// tenant code - two tests sharing a code would make "no audit row names this tenant" a claim
    /// about the whole assembly's history.
    /// </summary>
    private static string Company(string discriminator) => "C-" + discriminator;

    // ------------------------------------------------------------------ 1 · the whole walk

    /// <summary>
    /// The full path a real client takes, with a fact asserted at every hop. This is the test the
    /// wave-6 defect would have failed on the day it was written, and it fails on the ticket key
    /// being unreadable at three separate points - so removing the binding again cannot slip past
    /// it.
    /// </summary>
    [RequiresDockerFact]
    public async Task ABackOfficeSignInWalksAllTheWayToATokenThatResolvesTheAccountAndItsContext()
    {
        var company = Company("walk");
        var account = await BackOfficeSeed.OperatorAsync(Fixture, "walker");
        await BackOfficeSeed.MembershipAsync(Fixture, account.UserId, company);

        using var anonymous = Fixture.CreateClient();

        // --- hop 1: the password door -------------------------------------------------------
        var (signIn, response) = await BackOfficeEndpoints.SignInAsync(
            anonymous, account.Email, account.Password);

        using (response)
        {
            signIn.Status.ShouldBe(
                HttpStatusCode.OK,
                $"The password door refused a correct credential: {await response.Content.ReadAsStringAsync()}");
        }

        signIn.UserId.ShouldBe(account.UserId);
        signIn.SignInTicket.ShouldNotBeNullOrEmpty(
            "Without a ticket there is no way to reach the token endpoint at all, which is exactly "
            + "the state an unbound BackOfficeSignInOptions leaves this endpoint in.");
        signIn.TicketExpiresIn.ShouldBeGreaterThan(0);
        signIn.ContextRequired.ShouldBeFalse(
            "One usable context is entered automatically; asking the operator to choose from a "
            + "list of one is the behaviour the decision tree exists to avoid.");
        signIn.GrantedScope.ShouldBe(
            "backoffice",
            "The sign-in advertises the scope its ticket will produce, so a client asks for what it "
            + "is going to get rather than being quietly downgraded.");
        signIn.Tenants.ShouldHaveSingleItem().TenantCode.ShouldBe(company);

        // --- hop 2: redeeming the ticket ----------------------------------------------------
        var tokens = await TokenEndpoint.RedeemBackOfficeTicketAsync(
            anonymous, signIn.SignInTicket, deviceId: "operator-laptop");

        tokens.Status.ShouldBe(
            HttpStatusCode.OK,
            $"The back-office grant refused the ticket the sign-in just minted: "
            + $"{tokens.Error} {tokens.ErrorDescription}");
        tokens.AccessToken.ShouldNotBeNullOrEmpty();
        tokens.RefreshToken.ShouldNotBeNullOrEmpty(
            "A completed back-office sign-in is granted offline_access; without it an operator is "
            + "signed out when the access token expires and has nothing to renew with.");

        tokens.GrantedScopes.ShouldContain(
            "backoffice",
            "The scope is the mechanism: every gated back-office route is a policy over this "
            + "claim, so a token without it reaches nothing.");
        tokens.GrantedScopes.ShouldNotContain(
            "backoffice_pre_tenant",
            "A sign-in that resolved a context must not also carry the unfinished-sign-in scope, "
            + "or the context chooser and the product are open to the same credential at once.");

        JwtClaims.Subject(tokens.AccessToken).ShouldBe(
            account.UserId.ToString(CultureInfo.InvariantCulture),
            "sub is a iam.backend_users id here, never a consumer one.");

        tokens.ActClaim.ShouldNotBeNullOrEmpty(
            "act is what every back-office guard is a function of; a token that lost it resolves "
            + "to 'holds nothing' for somebody who holds everything.");
        using (var act = JsonDocument.Parse(tokens.ActClaim))
        {
            act.RootElement.GetProperty("type").GetString().ShouldBe(ActTypes.Company);
            act.RootElement.GetProperty("code").GetString().ShouldBe(company);
            act.RootElement.GetProperty("is_admin").GetBoolean().ShouldBeTrue();
        }

        // The session behind the credential, in the plane it belongs to. BACKOFFICE is what stops
        // consumer N's device list from answering for operator N.
        var sessionId = tokens.SessionId;
        sessionId.ShouldNotBeNullOrEmpty();

        var session = await Fixture.QueryStringsAsync(
            "SELECT realm || '|' || status || '|' || user_id FROM identity.user_sessions WHERE session_id = @p0",
            sessionId);

        session.ShouldHaveSingleItem().ShouldBe(
            $"{SessionRealms.BackOffice}|{SessionStatuses.Active}|{account.UserId}",
            "The grant must open a real device session in the back-office realm, or 'sign this "
            + "device out' and the revocation set do not work for an operator.");

        // --- hop 3: using the token on a gated endpoint --------------------------------------
        using var operatorClient = BackOfficeEndpoints.Bearer(Fixture, tokens.AccessToken);
        var me = await BackOfficeEndpoints.MeAsync(operatorClient);

        me.Status.ShouldBe(
            HttpStatusCode.OK,
            "A token the token endpoint just issued has to be accepted by the shell endpoint, or "
            + "the operator gets a working credential and a blank screen.");
        me.UserId.ShouldBe(account.UserId);
        me.ActiveTenantType.ShouldBe(TenantTypes.Company);
        me.ActiveCompanyCode.ShouldBe(company);
        me.IsTenantAdmin.ShouldBeTrue();

        me.Roles.ShouldNotBeNull(
            "Null means 'the snapshot was not delivered'. The shell then keeps whatever it had, so "
            + "a null here would hide a broken authority derivation rather than report it.");
        me.Roles.ShouldContain(BackOfficeSeed.CompanyAdminRoleCode);
        me.Permissions.ShouldNotBeNull();
        me.Permissions.ShouldContain(
            "uam.member.manage",
            "The permission comes from the bound role through the authority snapshot, which is the "
            + "part that makes the token an identity ticket rather than a permission bundle.");
        me.Menus.ShouldNotBeNull();
        me.Menus.ShouldNotBeEmpty();
    }

    // ------------------------------------------------------------------ 2 · the pre-tenant grant

    /// <summary>
    /// Two contexts to choose between: the ticket mints a pre-tenant token, which is short lived,
    /// carries no refresh token and no <c>act</c>, reaches the chooser and is refused everywhere
    /// else. Then the second grant turns a choice into a full credential.
    /// </summary>
    [RequiresDockerFact]
    public async Task APreTenantSignInMintsAContextlessTokenThatReachesOnlyTheChooser()
    {
        var first = Company("pre-a");
        var second = Company("pre-b");
        var account = await BackOfficeSeed.OperatorAsync(Fixture, "chooser");
        await BackOfficeSeed.MembershipAsync(Fixture, account.UserId, first);
        await BackOfficeSeed.MembershipAsync(Fixture, account.UserId, second);

        using var anonymous = Fixture.CreateClient();
        var (signIn, response) = await BackOfficeEndpoints.SignInAsync(
            anonymous, account.Email, account.Password);
        response.Dispose();

        signIn.Status.ShouldBe(HttpStatusCode.OK);
        signIn.ContextRequired.ShouldBeTrue(
            "Two places to be is a choice, and the sign-in must say so rather than picking one.");
        signIn.GrantedScope.ShouldBe("backoffice_pre_tenant");
        signIn.Tenants.Select(tenant => tenant.TenantCode).ShouldBe([first, second], ignoreOrder: true);

        // No device_id: a pre-tenant redemption opens no session, so it needs none.
        var pre = await TokenEndpoint.RedeemBackOfficeTicketAsync(anonymous, signIn.SignInTicket);

        pre.Status.ShouldBe(
            HttpStatusCode.OK, $"The pre-tenant grant was refused: {pre.Error} {pre.ErrorDescription}");
        pre.GrantedScopes.ShouldBe(["backoffice_pre_tenant"]);

        // Short-lived, and measurably shorter than the service-wide access-token lifetime the
        // fixture pins at ten minutes. An unfinished sign-in has no business holding a credential
        // as long as a working session's, and it has no refresh token to renew one with either.
        pre.ExpiresIn.ShouldBeInRange(
            1,
            (int)UserSvcApplicationFactory.AccessTokenLifetime.TotalSeconds - 1,
            "BackOfficeSignIn:PreTenantTokenLifetime has to override the service-wide lifetime for "
            + $"this token. It reported {pre.ExpiresIn}s against a service-wide "
            + $"{UserSvcApplicationFactory.AccessTokenLifetime.TotalSeconds}s.");
        pre.RefreshToken.ShouldBeEmpty(
            "An unfinished sign-in must not leave a renewable credential behind; if it could be "
            + "refreshed, abandoning the chooser would leave a session nobody chose a context for.");
        pre.ActClaim.ShouldBeEmpty(
            "A pre-tenant token carries no context. The absence has to be real - the scope is what "
            + "authorizes it, precisely because absence of act is also what a broken token looks like.");
        pre.SessionId.ShouldBeEmpty(
            "No session row either: a device on the 'signed-in devices' screen for a sign-in that "
            + "never completed is a device its owner cannot explain.");

        (await Fixture.CountAsync("SELECT count(*) FROM identity.user_sessions"))
            .ShouldBe(0, "The pre-tenant grant opened a session it had no business opening.");

        using var preClient = BackOfficeEndpoints.Bearer(Fixture, pre.AccessToken);

        // Accepted at the chooser...
        using (var tenants = await preClient.GetAsync(BackOfficeEndpoints.TenantsPath))
        {
            tenants.StatusCode.ShouldBe(
                HttpStatusCode.OK,
                "The chooser is the one screen a pre-tenant token exists to draw; refusing it here "
                + "would strand every operator who holds more than one context.");
        }

        // ...and refused everywhere else.
        var me = await BackOfficeEndpoints.MeAsync(preClient);
        me.Status.ShouldBe(
            HttpStatusCode.Forbidden,
            "The shell endpoint is gated on the full scope. A pre-tenant token reaching it would "
            + "make 'has not chosen a context' indistinguishable from 'is in a context'.");

        // The second half of the walk: a choice becomes a credential.
        var full = await TokenEndpoint.ExchangeBackOfficeContextAsync(
            preClient, TenantTypes.Company, second, deviceId: "chooser-laptop");

        full.Status.ShouldBe(
            HttpStatusCode.OK, $"The context grant refused a held tenant: {full.Error} {full.ErrorDescription}");
        full.GrantedScopes.ShouldContain("backoffice");
        full.RefreshToken.ShouldNotBeNullOrEmpty();

        full.ExpiresIn.ShouldBeGreaterThan(
            pre.ExpiresIn,
            "The finished sign-in gets the ordinary access-token lifetime back. If the pre-tenant "
            + "override leaked into this one, every operator would be re-authenticating on the "
            + "chooser's clock.");

        using var fullClient = BackOfficeEndpoints.Bearer(Fixture, full.AccessToken);
        var meAfter = await BackOfficeEndpoints.MeAsync(fullClient);

        meAfter.Status.ShouldBe(HttpStatusCode.OK);
        meAfter.ActiveCompanyCode.ShouldBe(
            second, "The context the operator picked is the context the credential has to carry.");
    }

    // ------------------------------------------------------------------ 2b · no authority at all

    /// <summary>
    /// A sign-in that resolved to <b>no</b> authority - a brand-new account nobody has added to a
    /// tenant, or one still PENDING - is a <i>finished</i> sign-in, and has to end in a usable
    /// credential.
    /// <para>
    /// It is the third outcome of the decision tree and the easiest one to get wrong, because "no
    /// context" and "has not chosen a context yet" look identical from the act claim alone. When
    /// they were conflated, the REST response reported the sign-in complete
    /// (<c>contextRequired: false</c>, <c>grantedScope: backoffice</c>) and audited an arrival while
    /// the token endpoint minted a pre-tenant credential: a client that believed the response and
    /// asked for <c>backoffice</c> was refused <c>invalid_scope</c>, and one that asked for nothing
    /// got a five-minute token answering 403 on the only screen that would have explained why. So
    /// this test walks to the token and then onto <c>/back-office/me</c>, which is the only place
    /// the difference shows.
    /// </para>
    /// <para>
    /// The authority collections must be <b>empty and present</b>. Empty says "you hold nothing"
    /// and closes every gate; null says "not delivered" and tells the shell to keep whatever it had,
    /// which for a new account is a blank slate rendered as an unrestricted one.
    /// </para>
    /// </summary>
    [RequiresDockerTheory]
    [InlineData(BackendUserStatuses.Active, false)]
    [InlineData(BackendUserStatuses.Pending, true)]
    public async Task AnOperatorWithNoAuthorityStillEndsUpHoldingAUsableCredential(
        string status, bool hasMembership)
    {
        var account = await BackOfficeSeed.OperatorAsync(
            Fixture, "newcomer-" + status.ToLowerInvariant(), status: status);

        if (hasMembership)
        {
            // A PENDING account is refused authority by its status, before its memberships are
            // even looked at - so the row must make no difference to the outcome.
            await BackOfficeSeed.MembershipAsync(Fixture, account.UserId, Company("newcomer"));
        }

        using var anonymous = Fixture.CreateClient();
        var (signIn, tokens) = await BackOfficeEndpoints.SignInAndRedeemAsync(
            anonymous, account, "newcomer-laptop");

        signIn.Status.ShouldBe(HttpStatusCode.OK);
        signIn.ContextRequired.ShouldBeFalse(
            "There is nothing to choose, so there is nothing to ask about. Reporting a choice with "
            + "an empty option list is how a chooser screen ends up rendering a dead end.");
        signIn.GrantedScope.ShouldBe("backoffice");

        tokens.Status.ShouldBe(
            HttpStatusCode.OK,
            "A sign-in the REST response called complete has to be redeemable for the scope it "
            + $"advertised: {tokens.Error} {tokens.ErrorDescription}");
        tokens.GrantedScopes.ShouldContain(
            "backoffice",
            "A pre-tenant token here is the bug: the sign-in already said it was finished, and a "
            + "client obeying that response asks for this scope and is refused invalid_scope.");
        tokens.ActClaim.ShouldBeEmpty("There is no context, so there is no act to carry.");

        using var newcomer = BackOfficeEndpoints.Bearer(Fixture, tokens.AccessToken);
        var me = await BackOfficeEndpoints.MeAsync(newcomer);

        me.Status.ShouldBe(
            HttpStatusCode.OK,
            "This is the one screen that can tell a new operator their administrator has not "
            + "finished setting them up. A 403 here is a dead end with nothing to read.");
        me.ActiveTenantType.ShouldBeEmpty();
        me.IsTenantAdmin.ShouldBeFalse();

        me.Roles.ShouldNotBeNull("Empty means 'you hold nothing'; null means 'not delivered'.");
        me.Roles.ShouldBeEmpty();
        me.Permissions.ShouldNotBeNull();
        me.Permissions.ShouldBeEmpty();
        me.Menus.ShouldNotBeNull();
        me.Menus.ShouldBeEmpty();
    }

    // ------------------------------------------------------------------ 3 · cross-tenant isolation

    /// <summary>
    /// A full back-office token acting for tenant A, pointed at tenant B's membership routes.
    /// <para>
    /// The 403 is the weakest half of this assertion and on its own it would be nearly worthless:
    /// the permission gate in front of the route would produce one too, for a completely different
    /// reason, and so would an unrelated failure. What proves the isolation held is that tenant B's
    /// row is byte-for-byte what it was - status, stamp, and the victim's token version, which the
    /// successful path bumps in the same transaction as the status.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task ATokenActingForOneTenantCannotWriteAnotherTenantsMembership()
    {
        var mine = Company("iso-mine");
        var theirs = Company("iso-theirs");

        var attacker = await BackOfficeSeed.OperatorAsync(Fixture, "insider");
        await BackOfficeSeed.MembershipAsync(Fixture, attacker.UserId, mine);

        var victim = await BackOfficeSeed.OperatorAsync(Fixture, "bystander");
        await BackOfficeSeed.MembershipAsync(
            Fixture, victim.UserId, theirs, isAdmin: false, roleId: null);

        using var anonymous = Fixture.CreateClient();
        var (signIn, tokens) = await BackOfficeEndpoints.SignInAndRedeemAsync(
            anonymous, attacker, "insider-laptop");

        signIn.Status.ShouldBe(HttpStatusCode.OK);
        tokens.Status.ShouldBe(HttpStatusCode.OK, $"{tokens.Error} {tokens.ErrorDescription}");

        using var insider = BackOfficeEndpoints.Bearer(Fixture, tokens.AccessToken);

        // It holds uam.member.manage - in its own tenant. That is what makes this the interesting
        // case rather than a plain permission refusal.
        var me = await BackOfficeEndpoints.MeAsync(insider);
        me.Permissions.ShouldNotBeNull();
        me.Permissions.ShouldContain("uam.member.manage");

        var target = new Uri(
            $"/api/v1/back-office/tenants/{TenantTypes.Company}/{theirs}/members/{victim.UserId}/status",
            UriKind.Relative);

        using var refused = await insider.PutAsJsonAsync(
            target, new { status = TenantMemberStatuses.Disabled });

        refused.StatusCode.ShouldBe(
            HttpStatusCode.Forbidden,
            $"A token acting for {mine} reached {theirs}'s membership route: "
            + await refused.Content.ReadAsStringAsync());

        var problem = await ProblemDetailsBody.ReadAsync(refused);
        problem.ErrorCode.ShouldBe(
            ErrorCodes.TenantNotAuthorized,
            "TENANT_NOT_AUTHORIZED, not FORBIDDEN: the caller holds the permission and is in the "
            + "wrong tenant, and the front end branches on which of those it was.");

        // The part that actually proves nothing happened.
        var row = await Fixture.QueryStringsAsync(
            """
            SELECT status || '|' || coalesce(updated_by, '') || '|' || (updated_at = created_at)::text
            FROM iam.tenant_members
            WHERE user_id = @p0 AND tenant_type = @p1 AND tenant_code = @p2
            """,
            victim.UserId,
            TenantTypes.Company,
            theirs);

        row.ShouldHaveSingleItem().ShouldBe(
            $"{TenantMemberStatuses.Active}|integration-test|true",
            "The refusal has to happen before the write, not alongside it. A 403 returned after the "
            + "row had been suspended would look identical to a client and be a complete breach.");

        (await Fixture.QueryStringsAsync(
                "SELECT token_version FROM iam.backend_users WHERE id = @p0", victim.UserId))
            .ShouldHaveSingleItem()
            .ShouldBe(
                "0",
                "Suspending a membership bumps the target's token version in the same transaction, "
                + "which kills every session they hold. A bumped version beside an unchanged status "
                + "would mean the transaction ran and was only half undone.");

        (await Fixture.CountAsync(
                "SELECT count(*) FROM iam.iam_audit_logs WHERE tenant_code = @p0", theirs))
            .ShouldBe(
                0,
                "Nor may the attempt leave an audit row attributing an action to the victim's "
                + "tenant - an audit trail that records refused writes as writes is worse than none.");
    }

    // ------------------------------------------------------------------ 3b · the plane boundary

    /// <summary>
    /// The credential this whole file mints, pointed at the <i>consumer</i> endpoints. It must be
    /// refused, and the consumer whose integer it shares must be untouched.
    /// <para>
    /// One OpenIddict instance serves both planes and <c>identity.users</c> and
    /// <c>iam.backend_users</c> number their accounts independently, so an operator's access token
    /// is a perfectly valid bearer token on a consumer route and its <c>sub</c> is a different
    /// person's id. Measured against a running host in wave 7, before the realm signal existed: a
    /// back-office token with <c>sub=1</c> read consumer 1's profile at 200, and
    /// <c>DELETE /api/v1/account</c> with the same token closed that consumer's account and signed
    /// every one of their devices out. Nothing in either request was malformed.
    /// </para>
    /// <para>
    /// <b>The test depends on the two ids actually colliding</b>, so it asserts that first rather
    /// than assuming it: both tables restart their sequence at every reset, so the first account
    /// seeded on each plane is number one. Without the collision the test would pass for the wrong
    /// reason - a lookup that simply found nobody.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task ABackOfficeTokenCannotActOnTheConsumerWhoSharesItsInteger()
    {
        var consumerId = await Fixture.SeedUserAsync();
        var account = await BackOfficeSeed.OperatorAsync(Fixture, "namesake");
        await BackOfficeSeed.MembershipAsync(Fixture, account.UserId, Company("namesake"));

        account.UserId.ShouldBe(
            consumerId,
            "This test is about one integer naming two people. If the two sequences have drifted "
            + "apart the refusals below prove nothing, so the collision is arranged, not hoped for.");

        using var anonymous = Fixture.CreateClient();

        // The consumer, with a real device session of their own.
        var consumerTokens = await TokenEndpoint.SignInDeviceAsync(anonymous, consumerId, "phone");
        consumerTokens.Status.ShouldBe(HttpStatusCode.OK);
        var consumerSessionId = consumerTokens.SessionId;

        // The operator who happens to share the integer.
        var (_, operatorTokens) = await BackOfficeEndpoints.SignInAndRedeemAsync(
            anonymous, account, "operator-laptop");
        operatorTokens.Status.ShouldBe(
            HttpStatusCode.OK, $"{operatorTokens.Error} {operatorTokens.ErrorDescription}");

        using var impostor = BackOfficeEndpoints.Bearer(Fixture, operatorTokens.AccessToken);

        using (var profile = await impostor.GetAsync(new Uri("/api/v1/user/profile", UriKind.Relative)))
        {
            profile.StatusCode.ShouldBe(
                HttpStatusCode.Forbidden,
                "A back-office credential read a consumer's profile. This is the exact request that "
                + $"answered 200 before the realm signal existed: {await profile.Content.ReadAsStringAsync()}");

            (await ProblemDetailsBody.ReadAsync(profile)).ErrorCode.ShouldBe(ErrorCodes.Forbidden);
        }

        using (var deregister = await impostor.DeleteAsync(new Uri("/api/v1/account", UriKind.Relative)))
        {
            deregister.StatusCode.ShouldBe(
                HttpStatusCode.Forbidden,
                "This is the destructive one: it closes the account and sweeps every session.");
        }

        // The status assertion above is not the proof - this is. Deregistration sweeps sessions
        // before it touches the account, so a refusal that arrived late would leave the consumer
        // signed out of every device with their row still ACTIVE and nothing to explain it.
        (await Fixture.QueryStringsAsync(
                "SELECT status FROM identity.users WHERE id = @p0", consumerId))
            .ShouldHaveSingleItem()
            .ShouldBe(UserStatuses.Active, "The consumer's account was closed by somebody else's token.");

        (await Fixture.QueryStringsAsync(
                "SELECT status FROM identity.user_sessions WHERE session_id = @p0", consumerSessionId))
            .ShouldHaveSingleItem()
            .ShouldBe(
                SessionStatuses.Active,
                "The consumer's device was signed out by a credential belonging to another plane.");

        // The device list is realm-scoped rather than refused - an operator has devices too - so
        // what has to be true is that it answers about the back office and not about the consumer.
        using (var devices = await impostor.GetAsync(new Uri("/api/v1/user/sessions", UriKind.Relative)))
        {
            devices.StatusCode.ShouldBe(HttpStatusCode.OK);

            var listed = await devices.Content.ReadAsStringAsync();
            listed.Contains(consumerSessionId, StringComparison.Ordinal).ShouldBeFalse(
                "The operator's device list named the consumer's session, which is also the row the "
                + $"DELETE beside it would have accepted: {listed}");
        }
    }

    // ------------------------------------------------------------------ 4 · the sign-in refusals

    /// <summary>
    /// An unknown mailbox and a wrong password answer identically - status, error code and every
    /// byte of the body except the trace id.
    /// <para>
    /// Compared as whole bodies rather than field by field on purpose. The interesting way for this
    /// to break is somebody adding a helpful field to one branch, and a field-by-field assertion
    /// would not notice a field it was not told to look at.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task AnUnknownMailboxAndAWrongPasswordAreAnsweredIdentically()
    {
        var account = await BackOfficeSeed.OperatorAsync(Fixture, "known");
        await BackOfficeSeed.MembershipAsync(Fixture, account.UserId, Company("refusals"));

        using var anonymous = Fixture.CreateClient();

        var (_, unknownResponse) = await BackOfficeEndpoints.SignInAsync(
            anonymous, "nobody-at-all" + BackOfficeSeed.CorporateDomain, BackOfficeSeed.Password);
        var (_, wrongResponse) = await BackOfficeEndpoints.SignInAsync(
            anonymous, account.Email, "not-the-password");

        ProblemDetailsBody unknown;
        ProblemDetailsBody wrong;

        using (unknownResponse)
        using (wrongResponse)
        {
            unknown = await ProblemDetailsBody.ReadAsync(unknownResponse);
            wrong = await ProblemDetailsBody.ReadAsync(wrongResponse);
        }

        unknown.Status.ShouldBe(HttpStatusCode.Unauthorized);
        wrong.Status.ShouldBe(HttpStatusCode.Unauthorized);

        unknown.ErrorCode.ShouldBe(ErrorCodes.InvalidCredentials);
        wrong.ErrorCode.ShouldBe(
            ErrorCodes.InvalidCredentials,
            "One code for both, or the code itself is a directory of which addresses have "
            + "back-office accounts.");

        WithoutTraceId(unknown).ShouldBe(
            WithoutTraceId(wrong),
            "The two refusals differ somewhere in the body. Anything that separates them - a "
            + "different detail, an extra member - tells an anonymous caller whether an address "
            + "exists, which is the whole reason the domain gate runs last.");

        // The bodies match; the side effects have to differ in exactly one direction. A failure
        // against a real account is audited, and an unknown address writes nothing at all - there
        // is no row to anchor an entry to, and one keyed on the address would persist
        // attacker-chosen text into the audit table. So every row here belongs to the account that
        // exists, and the total is the proof that the unknown attempt added none.
        var auditRows = await Fixture.CountAsync("SELECT count(*) FROM iam.iam_audit_logs");
        var accountRows = await Fixture.CountAsync(
            "SELECT count(*) FROM iam.iam_audit_logs WHERE actor_user_id = @p0", account.UserId);

        accountRows.ShouldBeGreaterThan(0, "The failure against a real account must be recorded.");
        auditRows.ShouldBe(
            accountRows,
            "An audit row was written for an address with no account behind it, which puts "
            + "attacker-supplied text in the audit table and makes the table itself an "
            + "enumeration oracle for anybody who can read it.");
    }

    /// <summary>
    /// The third state of an account, and the one the wave-6 report did not name: an account
    /// provisioned through the corporate one-time-password door has no local password at all.
    /// Saying so would tell an anonymous caller which door to use for any address they can guess.
    /// </summary>
    [RequiresDockerFact]
    public async Task AnAccountWithNoLocalPasswordIsRefusedInTheSameWordsAsAWrongOne()
    {
        var withPassword = await BackOfficeSeed.OperatorAsync(Fixture, "has-password");
        var withoutPassword = await BackOfficeSeed.OperatorAsync(
            Fixture, "staff-only", password: null);

        using var anonymous = Fixture.CreateClient();

        var (_, wrongResponse) = await BackOfficeEndpoints.SignInAsync(
            anonymous, withPassword.Email, "not-the-password");
        var (_, noneResponse) = await BackOfficeEndpoints.SignInAsync(
            anonymous, withoutPassword.Email, BackOfficeSeed.Password);

        ProblemDetailsBody wrong;
        ProblemDetailsBody none;

        using (wrongResponse)
        using (noneResponse)
        {
            wrong = await ProblemDetailsBody.ReadAsync(wrongResponse);
            none = await ProblemDetailsBody.ReadAsync(noneResponse);
        }

        none.Status.ShouldBe(HttpStatusCode.Unauthorized);
        none.ErrorCode.ShouldBe(ErrorCodes.InvalidCredentials);
        WithoutTraceId(none).ShouldBe(WithoutTraceId(wrong));
    }

    /// <summary>
    /// A disabled account is refused too, and the refusal is audited against the account it names -
    /// unlike an unknown address, which deliberately writes nothing because there is no row to
    /// anchor an entry to and the identifier is attacker-chosen text.
    /// </summary>
    [RequiresDockerFact]
    public async Task ADisabledAccountIsRefusedAndTheRefusalIsAudited()
    {
        var account = await BackOfficeSeed.OperatorAsync(
            Fixture, "switched-off", status: BackendUserStatuses.Disabled);

        using var anonymous = Fixture.CreateClient();
        var (_, response) = await BackOfficeEndpoints.SignInAsync(
            anonymous, account.Email, account.Password);

        ProblemDetailsBody problem;
        using (response)
        {
            problem = await ProblemDetailsBody.ReadAsync(response);
        }

        problem.Status.ShouldBe(
            HttpStatusCode.Unauthorized,
            "401 on the password door, where the credential and the account are indistinguishable "
            + "to the caller; the staff one-time-password door answers 403 for the same state, "
            + "which is an asymmetry inherited from the service being replaced.");
        problem.ErrorCode.ShouldBe(ErrorCodes.AccountDisabled);

        (await Fixture.CountAsync(
                "SELECT count(*) FROM iam.iam_audit_logs WHERE actor_user_id = @p0", account.UserId))
            .ShouldBeGreaterThan(
                0,
                "A blocked account still trying its password is exactly the event an operator wants "
                + "to find, and the row can be anchored because the account exists.");
    }

    // ------------------------------------------------------------------ 5 · malformed redemptions

    /// <summary>
    /// A ticket that was never issued. It has to be refused with one OAuth <c>invalid_grant</c> and
    /// nothing else: at a token endpoint the difference between forged, expired and already
    /// redeemed is an oracle.
    /// </summary>
    [RequiresDockerTheory]
    [InlineData("not-a-ticket")]
    [InlineData("eyJzdWIiOjF9.c2lnbmF0dXJl")]
    [InlineData(".")]
    public async Task AForgedSignInTicketIsRefusedWithOneIndistinguishableInvalidGrant(string ticket)
    {
        using var anonymous = Fixture.CreateClient();

        var refused = await TokenEndpoint.RedeemBackOfficeTicketAsync(
            anonymous, ticket, deviceId: "attacker-laptop");

        refused.Status.ShouldBe(HttpStatusCode.BadRequest);
        refused.Error.ShouldBe(
            OpenIddictErrors.InvalidGrant,
            "A forged ticket must not be told what was wrong with it, and must not answer "
            + "server_error either - that would say the deployment is broken when it is not.");
        refused.AccessToken.ShouldBeEmpty();
        refused.ErrorDescription.Contains("BackOfficeSignIn", StringComparison.Ordinal).ShouldBeFalse(
            "The description reaches an anonymous caller, so it may never name a configuration "
            + $"key. It said: {refused.ErrorDescription}");

        (await Fixture.CountAsync("SELECT count(*) FROM openiddict.openiddict_authorizations"))
            .ShouldBe(0, "Nothing was authenticated, so nothing may be authorized.");
    }

    /// <summary>
    /// A well-formed ticket redeemed without <c>device_id</c>. It must be a 4xx, and it must leave
    /// no authorization row behind.
    /// <para>
    /// That second half is the one worth pinning. The natural place to check <c>device_id</c> is
    /// beside the session insert, which is <i>after</i> the authorization row has been created -
    /// and refusing there leaves one orphaned ad-hoc authorization per malformed request, a table
    /// anybody holding one ticket can grow, cleared only by a pruning job. Wave 6 moved the check
    /// in front of the first write; this is what stops it drifting back.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task ARedemptionWithNoDeviceIdIsRefusedAndWritesNoOrphanedAuthorization()
    {
        var account = await BackOfficeSeed.OperatorAsync(Fixture, "forgetful");
        await BackOfficeSeed.MembershipAsync(Fixture, account.UserId, Company("no-device"));

        using var anonymous = Fixture.CreateClient();
        var (signIn, response) = await BackOfficeEndpoints.SignInAsync(
            anonymous, account.Email, account.Password);
        response.Dispose();

        signIn.Status.ShouldBe(HttpStatusCode.OK);
        signIn.ContextRequired.ShouldBeFalse(
            "This case only exists for a full token: a pre-tenant redemption needs no device.");

        var refused = await TokenEndpoint.RedeemBackOfficeTicketAsync(
            anonymous, signIn.SignInTicket, deviceId: null);

        ((int)refused.Status).ShouldBeInRange(
            400, 499, $"Expected a client error, got {(int)refused.Status}: {refused.Error}");
        refused.Error.ShouldBe(OpenIddictErrors.InvalidRequest);
        refused.AccessToken.ShouldBeEmpty();

        (await Fixture.CountAsync("SELECT count(*) FROM openiddict.openiddict_authorizations"))
            .ShouldBe(
                0,
                "The refusal left an orphaned ad-hoc authorization. One per malformed request is a "
                + "table any holder of a single sign-in ticket can grow without limit.");

        (await Fixture.CountAsync("SELECT count(*) FROM identity.user_sessions"))
            .ShouldBe(0, "And no session, for the same reason.");
    }

    /// <summary>
    /// The ticket is single use, which landed in wave 7. A second redemption inside its two-minute
    /// window is refused with the same words as a forged one, and mints nothing.
    /// </summary>
    [RequiresDockerFact]
    public async Task ASignInTicketIsRedeemableExactlyOnce()
    {
        var account = await BackOfficeSeed.OperatorAsync(Fixture, "replayer");
        await BackOfficeSeed.MembershipAsync(Fixture, account.UserId, Company("replay"));

        using var anonymous = Fixture.CreateClient();
        var (signIn, response) = await BackOfficeEndpoints.SignInAsync(
            anonymous, account.Email, account.Password);
        response.Dispose();

        var first = await TokenEndpoint.RedeemBackOfficeTicketAsync(
            anonymous, signIn.SignInTicket, deviceId: "device-one");
        first.Status.ShouldBe(HttpStatusCode.OK, $"{first.Error} {first.ErrorDescription}");

        var replay = await TokenEndpoint.RedeemBackOfficeTicketAsync(
            anonymous, signIn.SignInTicket, deviceId: "device-two");

        replay.Status.ShouldBe(HttpStatusCode.BadRequest);
        replay.Error.ShouldBe(
            OpenIddictErrors.InvalidGrant,
            "A replay is refused in the same words as an expired or forged ticket: a caller who did "
            + "not mint it learns nothing about why.");
        replay.AccessToken.ShouldBeEmpty();

        (await Fixture.CountAsync("SELECT count(*) FROM identity.user_sessions"))
            .ShouldBe(1, "The replay minted a second session, so the ticket was spendable twice.");
    }

    // ------------------------------------------------------------------ 6 · failure isolation

    /// <summary>
    /// The other half of the wave-6 story: a deployment that has genuinely not been given a ticket
    /// key must <b>boot</b>, must say which key is missing, and must keep serving everything that
    /// does not need it.
    /// <para>
    /// All three clauses were paid for. Refusing to boot over a secret only the back office needs
    /// is the failure docs/architecture.md records having been made twice (a <c>ValidateOnStart</c>
    /// on an unconfigured section, and a construction-time <c>IOptions.Value</c> read); answering
    /// <c>INTERNAL_ERROR</c> instead of <c>NOT_CONFIGURED</c> sends an operator to read code rather
    /// than to look at their secrets; and a section name in the message is exactly what turns a
    /// 500 into a five-minute fix, which is why the detail is asserted to name it.
    /// </para>
    /// <para>
    /// The token endpoint is the deliberate exception and is asserted the other way round: its
    /// caller is anonymous, so the same message would hand a stranger a map of the deployment's
    /// secret names. It answers a generic <c>server_error</c> and the key name goes to the log.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task ADeploymentWithNoTicketKeyStillBootsAndBreaksOnlyTheBackOfficeDoor()
    {
        var account = await BackOfficeSeed.OperatorAsync(Fixture, "unconfigured");
        await BackOfficeSeed.MembershipAsync(Fixture, account.UserId, Company("no-key"));
        var consumerId = await Fixture.SeedUserAsync();

        // Empty rather than absent: the section still exists in appsettings.Development.json, and
        // an empty highest-precedence value is what an unset secret looks like to Bind.
        await using var host = Fixture.CreateHost(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["BackOfficeSignIn:SignInTicketKey"] = string.Empty,
            });

        // Constructing the client is what builds and starts the host, so reaching the next line at
        // all is the "it still boots" assertion.
        using var client = host.CreateClient();

        var (signIn, response) = await BackOfficeEndpoints.SignInAsync(
            client, account.Email, account.Password);

        ProblemDetailsBody problem;
        using (response)
        {
            problem = await ProblemDetailsBody.ReadAsync(response);
        }

        signIn.Status.ShouldBe(HttpStatusCode.InternalServerError);
        problem.ErrorCode.ShouldBe(
            ErrorCodes.NotConfigured,
            "NOT_CONFIGURED, not INTERNAL_ERROR: the two send an operator to different places, and "
            + "only one of them is the right place.");
        problem.Detail.Contains(
            "BackOfficeSignIn:SignInTicketKey", StringComparison.Ordinal).ShouldBeTrue(
            $"The detail has to name the missing key. It said: {problem.Detail}");

        // The token endpoint, where the caller is anonymous and the same sentence would be a leak.
        var refused = await TokenEndpoint.RedeemBackOfficeTicketAsync(
            client, "anything", deviceId: "operator-laptop");

        refused.Error.ShouldBe(
            "server_error",
            "It is the deployment that cannot serve the grant, not the credential that is bad. "
            + "invalid_grant here would send an operator hunting for a client bug.");
        refused.ErrorDescription.Contains("BackOfficeSignIn", StringComparison.Ordinal).ShouldBeFalse(
            $"An anonymous caller may not be told a configuration key's name. It said: "
            + refused.ErrorDescription);

        // And the isolation itself: consumer sign-in on the same deployment is untouched.
        var consumer = await TokenEndpoint.SignInDeviceAsync(client, consumerId, "consumer-phone");

        consumer.Status.ShouldBe(
            HttpStatusCode.OK,
            "A missing back-office secret took consumer sign-in down with it. A missing capability "
            + $"may only break itself: {consumer.Error} {consumer.ErrorDescription}");
        consumer.AccessToken.ShouldNotBeNullOrEmpty();
    }

    // ------------------------------------------------------------------ 7 · the per-address budget

    /// <summary>
    /// One password sprayed from one address across many mailboxes, which is the attack the
    /// per-mailbox budget cannot see - every mailbox is on its first failure, so ten a minute each
    /// never fires. This is the dimension that notices, and this is its only end-to-end coverage.
    /// <para>
    /// <b>It needs a host of its own, and the reason is worth writing down.</b> <c>TestServer</c>
    /// serves requests over no socket, so <c>HttpContext.Connection.RemoteIpAddress</c> is null and
    /// <c>BackOfficeSignInContext.IpAddress</c> arrives empty - and an empty address deliberately
    /// disables the per-source budget rather than sharing one bucket, because a budget that cannot
    /// name its subject is not a budget. Measured: fourteen failed sign-ins across fourteen
    /// mailboxes through the shared host wrote fourteen pairs of <c>backoffice-sign-in</c> counters
    /// and not one <c>backoffice-sign-in-ip</c> key. That is good news for the suite - a CI run
    /// cannot throttle itself on this dimension - and it also means the control ships with no
    /// integration coverage at all unless a test asks for an address.
    /// </para>
    /// <para>
    /// The budget is turned down to three rather than run at its shipped thirty: the mechanism is
    /// what this test is about, three failures cost three Argon2 derivations instead of thirty, and
    /// the shipped number is a judgement about office sizes that belongs in the option's own
    /// documentation rather than in an assertion here. The per-mailbox budget is turned up out of
    /// the way, so a refusal can only have come from the address dimension.
    /// </para>
    /// </summary>
    [RequiresDockerFact]
    public async Task OneAddressSprayingManyMailboxesIsLockedOutAndASuccessDoesNotClearThat()
    {
        var account = await BackOfficeSeed.OperatorAsync(Fixture, "sprayed-at");
        await BackOfficeSeed.MembershipAsync(Fixture, account.UserId, Company("spray"));

        await using var host = Fixture.CreateHost(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["BackOfficeSignIn:PasswordFailuresPerSourcePerMinute"] = "3",
                ["BackOfficeSignIn:PasswordFailuresPerSourcePerHour"] = "1000",

                // High enough to be out of the way: any 429 below can then only be the address.
                ["BackOfficeSignIn:PasswordFailuresPerMinute"] = "1000",
                ["BackOfficeSignIn:PasswordFailuresPerHour"] = "1000",
            },
            peerAddress: "203.0.113.7");

        using var attacker = host.CreateClient();

        // Two mailboxes that do not exist. The per-mailbox budget sees one failure each.
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var (_, spray) = await BackOfficeEndpoints.SignInAsync(
                attacker, $"victim-{attempt}{BackOfficeSeed.CorporateDomain}", "one-guess");

            using (spray)
            {
                spray.StatusCode.ShouldBe(
                    HttpStatusCode.Unauthorized,
                    $"Attempt {attempt} was refused for the wrong reason; the budget is 3.");
            }
        }

        // A correct sign-in in the middle. It clears the mailbox budget, and must NOT clear the
        // address budget - otherwise anybody holding one working account could spray without limit:
        // fail twice, sign into their own, repeat.
        var (_, success) = await BackOfficeEndpoints.SignInAsync(
            attacker, account.Email, account.Password);

        using (success)
        {
            success.StatusCode.ShouldBe(
                HttpStatusCode.OK, await success.Content.ReadAsStringAsync());
        }

        var (_, third) = await BackOfficeEndpoints.SignInAsync(
            attacker, "victim-2" + BackOfficeSeed.CorporateDomain, "one-guess");
        using (third)
        {
            third.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        }

        // The fourth attempt from this address, and the budget was three.
        var (_, refused) = await BackOfficeEndpoints.SignInAsync(
            attacker, account.Email, account.Password);

        ProblemDetailsBody problem;
        string? retryAfter;

        using (refused)
        {
            problem = await ProblemDetailsBody.ReadAsync(refused);
            retryAfter = refused.Headers.RetryAfter?.Delta?.TotalSeconds.ToString(
                CultureInfo.InvariantCulture);
        }

        problem.Status.ShouldBe(
            HttpStatusCode.TooManyRequests,
            "Three failures from this address were not counted, or a success cleared them. Either "
            + "way one address gets as many guesses as it likes across as many mailboxes as it "
            + $"likes. The body was: {problem.Raw}");
        problem.ErrorCode.ShouldBe(ErrorCodes.RateLimitExceeded);
        retryAfter.ShouldNotBeNull(
            "Without Retry-After a client has to guess when to come back, and guesses by retrying.");

        problem.Detail.Contains("network", StringComparison.OrdinalIgnoreCase).ShouldBeTrue(
            "The two budgets say different things on purpose - somebody who has locked their own "
            + "mailbox needs to be told about their mailbox, not about the office they share an "
            + $"address with. This refusal has to be the address one. It said: {problem.Detail}");
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>
    /// A ProblemDetails body with the one member that legitimately differs between two requests
    /// removed, so two refusals can be compared whole.
    /// </summary>
    private static string WithoutTraceId(ProblemDetailsBody problem)
    {
        problem.TraceId.ShouldNotBeNullOrEmpty(
            "Every failure carries a traceId; without one there is nothing to remove and the "
            + "comparison below would be comparing the wrong thing.");

        return problem.Raw.Replace(problem.TraceId, "<traceId>", StringComparison.Ordinal);
    }

    /// <summary>
    /// The two RFC 6749 error codes these tests assert on, spelled out rather than taken from
    /// OpenIddict's constants: they are the wire contract, and a test that read them from the
    /// library would keep passing if the library changed them under us.
    /// </summary>
    private static class OpenIddictErrors
    {
        public const string InvalidGrant = "invalid_grant";

        public const string InvalidRequest = "invalid_request";
    }
}
