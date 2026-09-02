using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Shouldly;
using StackExchange.Redis;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.SignIn;
using Xunit;

namespace UserSvc.UnitTests.BackOffice.SignIn;

/// <summary>
/// The sign-in ticket is redeemable once.
/// <para>
/// Wave 6 shipped it as a bearer credential with a two-minute window and nothing remembering
/// whether it had been spent, so an intercepted ticket was worth as many tokens as the holder
/// cared to ask for inside that window. These are the cases that say it is not any more - and, just
/// as importantly, the case that says a Redis failure refuses the redemption rather than waving it
/// through.
/// </para>
/// </summary>
public sealed class BackOfficeSignInTicketReplayTests
{
    private const string Purpose = "back-office-sign-in-ticket";

    private readonly SignInTestHarness _harness = new();

    private static BackOfficePasswordSignInRequest Request => new()
    {
        Email = SignInTestHarness.CorporateEmail,
        Password = SignInTestHarness.Password,
    };

    private async Task<string> SignInAsync()
    {
        _harness.WithPasswordAccount();

        var response = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        return response.SignInTicket;
    }

    /// <summary>
    /// The claim is made against this ticket's own id, under the sign-in purpose, with a marker
    /// that outlives the ticket. A TTL shorter than the ticket would leave a gap between the marker
    /// expiring and the ticket expiring, and that gap is exactly where somebody holding a captured
    /// ticket is waiting.
    /// </summary>
    [Fact]
    public async Task RedemptionClaimsTheTicketsOwnIdWithAMarkerThatOutlivesIt()
    {
        var ticket = await SignInAsync();
        var lifetime = _harness.SignInOptions.SignInTicketLifetime;

        await _harness.Sut.RedeemAsync(ticket, CancellationToken.None);

        await _harness.Markers.Received(1).TryClaimAsync(
            Purpose,
            Arg.Is<string>(id => id.Length > 0),
            Arg.Is<TimeSpan>(ttl => ttl > lifetime),
            Arg.Any<CancellationToken>());
    }

    /// <summary>Two sign-ins are two tickets, so redeeming one must not spend the other. The id is
    /// per issue, not per account.</summary>
    [Fact]
    public async Task TwoSignInsClaimTwoDifferentIds()
    {
        _harness.WithPasswordAccount();

        var first = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);
        var second = await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        var claimed = new List<string>();
        _harness.Markers.TryClaimAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                claimed.Add(call.ArgAt<string>(1));
                return true;
            });

        await _harness.Sut.RedeemAsync(first.SignInTicket, CancellationToken.None);
        await _harness.Sut.RedeemAsync(second.SignInTicket, CancellationToken.None);

        claimed.Count.ShouldBe(2);
        claimed[0].ShouldNotBe(claimed[1]);
    }

    /// <summary>
    /// A ticket whose marker is already claimed is refused - in exactly the words an expired or
    /// forged one is refused in. Saying "already used" would confirm to whoever intercepted it that
    /// they had a real ticket and that the rightful holder had beaten them to it.
    /// </summary>
    [Fact]
    public async Task ASecondRedemptionIsRefusedAndIsIndistinguishableFromAnExpiredTicket()
    {
        var ticket = await SignInAsync();

        _harness.Markers.TryClaimAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
            .Returns(false);

        var replay = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.RedeemAsync(ticket, CancellationToken.None));

        _harness.Clock.Advance(TimeSpan.FromMinutes(5));

        var expired = await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.RedeemAsync(ticket, CancellationToken.None));

        replay.ErrorCode.ShouldBe(ErrorCodes.InvalidToken);
        replay.StatusCode.ShouldBe(401);
        replay.Message.ShouldBe(expired.Message);
        replay.ErrorCode.ShouldBe(expired.ErrorCode);
    }

    /// <summary>
    /// The claim happens before the account is read, which is what makes it a claim rather than a
    /// race. Two redemptions arriving together must not both get as far as minting; the first thing
    /// after the signature check has to be the atomic step.
    /// </summary>
    [Fact]
    public async Task NothingIsReadBeforeTheTicketIsClaimed()
    {
        var ticket = await SignInAsync();
        _harness.Users.ClearReceivedCalls();

        _harness.Markers.TryClaimAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
            .Returns(false);

        await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.RedeemAsync(ticket, CancellationToken.None));

        await _harness.Users.DidNotReceive().ReadByIdAsync(Arg.Any<int>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// A forged ticket never reaches the marker store. Claiming on an unauthenticated id would let
    /// anybody who can POST a form write a Redis key per request, and it would burn ids that had
    /// not been issued.
    /// </summary>
    [Fact]
    public async Task AForgedTicketIsRefusedWithoutTouchingTheMarkerStore()
    {
        _harness.WithPasswordAccount();

        await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.RedeemAsync("bm90LWEtdGlja2V0.bm90LWEtc2lnbmF0dXJl", CancellationToken.None));

        await _harness.Markers.DidNotReceive().TryClaimAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// <b>The fail-closed case, which is the whole reason the marker is not in the revocation
    /// store.</b> That store's read path fails open by contract, so a replay would sail through a
    /// Redis blip and nothing would report that the single-use guarantee had lapsed. Here an
    /// unreachable store refuses the redemption, and refuses it as a 502 rather than as an invalid
    /// credential - the caller did nothing wrong and an operator must not go hunting for a stolen
    /// ticket during what is actually a Redis outage.
    /// </summary>
    [Fact]
    public async Task AnUnreachableMarkerStoreRefusesTheRedemptionRatherThanAllowingIt()
    {
        var ticket = await SignInAsync();

        _harness.Markers.TryClaimAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new UpstreamException(
                ErrorCodes.UpstreamUnavailable,
                "This credential could not be verified as unused. Sign in again.",
                new RedisTimeoutException(CommandFlags.None, "timed out", CommandStatus.Unknown)));

        var refusal = await Should.ThrowAsync<UpstreamException>(() =>
            _harness.Sut.RedeemAsync(ticket, CancellationToken.None));

        refusal.StatusCode.ShouldBe(502);
        refusal.ErrorCode.ShouldBe(ErrorCodes.UpstreamUnavailable);
    }

    /// <summary>
    /// The context exchange is not the ticket path and claims nothing. It authenticates with a
    /// bearer token that OpenIddict has already validated and which the session machinery can
    /// revoke; there is no self-contained one-shot credential in it to consume.
    /// </summary>
    [Fact]
    public async Task TheContextExchangeClaimsNoMarker()
    {
        _harness.WithPasswordAccount();
        _harness.AddMembership(tenantCode: "C1");
        _harness.AddMembership(tenantCode: "C2");

        await _harness.Sut.SignInWithPasswordAsync(
            Request, BackOfficeSignInContext.None, CancellationToken.None);

        _harness.Markers.ClearReceivedCalls();

        await _harness.Sut.SelectContextAsync(
            new Application.Features.BackOffice.Tenants.BackOfficeCaller(57, "Xiaoming Wang", null, 3),
            new Application.Features.BackOffice.Tenants.SelectTenantContextRequest
            {
                TenantType = "company",
                TenantCode = "C1",
            },
            CancellationToken.None);

        await _harness.Markers.DidNotReceive().TryClaimAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<TimeSpan>(), Arg.Any<CancellationToken>());
    }
}
