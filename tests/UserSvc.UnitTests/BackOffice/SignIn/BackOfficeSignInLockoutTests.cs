using System.Diagnostics;
using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.SignIn;
using UserSvc.Application.Features.Registration;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.BackOffice;
using Xunit;

namespace UserSvc.UnitTests.BackOffice.SignIn;

/// <summary>
/// What the sign-in doors' budgets actually count, and when they are cleared.
/// <para>
/// The distinction under test is the whole of it: a budget spent by <i>arriving</i> throttles the
/// person who mistypes once, and a budget spent by <i>failing</i> and cleared on success is the
/// five-strikes lockout the specification describes. Nothing in a response distinguishes the two,
/// so the only place it can be pinned is here.
/// </para>
/// </summary>
public sealed class BackOfficeSignInLockoutTests
{
    private const string PasswordDimension = "backoffice-sign-in";
    private const string SourceDimension = "backoffice-sign-in-ip";
    private const string OtpDimension = "backoffice-sign-in-otp";

    private readonly SignInTestHarness _harness = new();

    private static BackOfficePasswordSignInRequest Request(
        string email = SignInTestHarness.CorporateEmail,
        string password = SignInTestHarness.Password) =>
        new() { Email = email, Password = password };

    private static BackOfficeSignInContext From(string ip) => new(ip, "curl", "req-1");

    // ------------------------------------------------------------------ failures, not attempts

    /// <summary>
    /// A correct password spends nothing. Before this, the same 10-a-minute budget was charged for
    /// arriving, so an operator signing in ten times in a minute - a tab reopened, a context
    /// switched, a page reloaded - was locked out of a door they were using correctly.
    /// </summary>
    [Fact]
    public async Task ASuccessfulSignInCountsNothing()
    {
        _harness.WithPasswordAccount();

        await _harness.Sut.SignInWithPasswordAsync(
            Request(), From("203.0.113.7"), CancellationToken.None);

        await _harness.Limiter.DidNotReceive().TryAcquireAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<RateLimitPolicy>(), Arg.Any<CancellationToken>());
    }

    /// <summary>Specification 3.2 step 7: the address's budget is cleared, both windows at once.
    /// Clearing the minute and leaving the hour would be a lockout that outlives a correct
    /// password.</summary>
    [Fact]
    public async Task ASuccessfulSignInClearsBothWindowsOfTheAddressBudget()
    {
        _harness.WithPasswordAccount();

        await _harness.Sut.SignInWithPasswordAsync(
            Request(), From("203.0.113.7"), CancellationToken.None);

        await _harness.Limiter.Received(1).ResetAsync(
            PasswordDimension,
            SignInTestHarness.CorporateEmail,
            Arg.Is<IReadOnlyList<RateLimitPolicy>>(policies =>
                policies.Count == 2
                && policies.Any(policy => policy.Window == TimeSpan.FromMinutes(1) && policy.Limit == 10)
                && policies.Any(policy => policy.Window == TimeSpan.FromHours(1) && policy.Limit == 60)),
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The per-source budget survives a success, and that asymmetry is the point of it. Clearing it
    /// too would let anybody holding one working back-office account spray without limit: fail
    /// four times, sign into their own account, repeat forever.
    /// </summary>
    [Fact]
    public async Task ASuccessfulSignInDoesNotClearThePerSourceBudget()
    {
        _harness.WithPasswordAccount();

        await _harness.Sut.SignInWithPasswordAsync(
            Request(), From("203.0.113.7"), CancellationToken.None);

        await _harness.Limiter.DidNotReceive().ResetAsync(
            SourceDimension,
            Arg.Any<string>(),
            Arg.Any<IReadOnlyList<RateLimitPolicy>>(),
            Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData("not-the-password")]
    [InlineData(SignInTestHarness.Password)]
    public async Task AWrongCredentialCountsAgainstBothWindowsOfBothBudgets(string password)
    {
        // Two shapes of the same failure: a wrong password against a real account, and a correct
        // password against an address that does not exist. Both are credential failures and both
        // have to fill the budgets, or an attacker enumerating addresses is never counted at all.
        var email = password == SignInTestHarness.Password
            ? "nobody@liontravel.com"
            : SignInTestHarness.CorporateEmail;

        _harness.WithPasswordAccount();

        await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(email, password), From("203.0.113.7"), CancellationToken.None));

        await _harness.Limiter.Received(1).TryAcquireAsync(
            PasswordDimension, email, Policy(TimeSpan.FromMinutes(1)), Arg.Any<CancellationToken>());
        await _harness.Limiter.Received(1).TryAcquireAsync(
            PasswordDimension, email, Policy(TimeSpan.FromHours(1)), Arg.Any<CancellationToken>());
        await _harness.Limiter.Received(1).TryAcquireAsync(
            SourceDimension, "203.0.113.7", Policy(TimeSpan.FromMinutes(1)), Arg.Any<CancellationToken>());
        await _harness.Limiter.Received(1).TryAcquireAsync(
            SourceDimension, "203.0.113.7", Policy(TimeSpan.FromHours(1)), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// A refusal that happens <b>after</b> the password verified spends no budget. The specification
    /// increments only on the credential failures, and the reason is that by then the caller has
    /// already proved they hold this account's password - there is no brute force to bound, and
    /// counting it would let a disabled account's own owner lock the mailbox out by retrying.
    /// </summary>
    [Fact]
    public async Task ARefusalAfterTheCredentialVerifiedSpendsNoBudget()
    {
        _harness.WithPasswordAccount(status: BackendUserStatuses.Disabled);

        await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(), From("203.0.113.7"), CancellationToken.None));

        await _harness.Limiter.DidNotReceive().TryAcquireAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<RateLimitPolicy>(), Arg.Any<CancellationToken>());
    }

    // ------------------------------------------------------------------ the per-source dimension

    /// <summary>
    /// The counters this door reads are the ones it writes. A gate that peeked one dimension and
    /// counted another would refuse nobody and nothing would say so.
    /// </summary>
    [Fact]
    public async Task BothDimensionsAreCheckedBeforeAnythingIsRead()
    {
        _harness.WithPasswordAccount();

        await _harness.Sut.SignInWithPasswordAsync(
            Request(), From("203.0.113.7"), CancellationToken.None);

        await _harness.Limiter.Received().PeekAsync(
            PasswordDimension,
            SignInTestHarness.CorporateEmail,
            Arg.Any<RateLimitPolicy>(),
            Arg.Any<CancellationToken>());

        await _harness.Limiter.Received().PeekAsync(
            SourceDimension, "203.0.113.7", Arg.Any<RateLimitPolicy>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// One password sprayed across many mailboxes never fills any mailbox's budget - every address
    /// is on its first failure - so the source budget is the only thing that stops it. Its refusal
    /// says "this network", not "this address": the caller has locked out nothing of their own.
    /// </summary>
    [Fact]
    public async Task AnExhaustedSourceBudgetRefusesAFreshMailbox()
    {
        _harness.WithPasswordAccount();
        _harness.WithRateLimitRefusalOn(SourceDimension, TimeSpan.FromSeconds(30));

        var refusal = await Should.ThrowAsync<RateLimitedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(email: "never.seen.before@liontravel.com"),
                From("203.0.113.7"),
                CancellationToken.None));

        refusal.ErrorCode.ShouldBe(ErrorCodes.RateLimitExceeded);
        refusal.RetryAfter.ShouldBe(TimeSpan.FromSeconds(30));
        refusal.Message.ShouldContain("network");
    }

    /// <summary>
    /// The address's own lockout is reported first and in its own words. Somebody who has locked
    /// their own mailbox needs to be told about their mailbox rather than about the office they
    /// happen to share an egress address with.
    /// </summary>
    [Fact]
    public async Task AnExhaustedAddressBudgetIsReportedBeforeTheSourceOne()
    {
        _harness.WithPasswordAccount();
        _harness.WithRateLimitRefusalOn(PasswordDimension, TimeSpan.FromSeconds(11));
        _harness.WithRateLimitRefusalOn(SourceDimension, TimeSpan.FromSeconds(30));

        var refusal = await Should.ThrowAsync<RateLimitedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(), From("203.0.113.7"), CancellationToken.None));

        refusal.RetryAfter.ShouldBe(TimeSpan.FromSeconds(11));
        refusal.Message.ShouldContain("this address");

        await _harness.Limiter.DidNotReceive().PeekAsync(
            SourceDimension, Arg.Any<string>(), Arg.Any<RateLimitPolicy>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// With no attributable peer address the per-source budget is skipped rather than counted under
    /// an empty subject. Every such request would otherwise share one counter, and the first
    /// handful would lock out all the rest - a budget that cannot name its subject is not a budget.
    /// </summary>
    [Fact]
    public async Task NoClientAddressMeansNoPerSourceBudgetRatherThanASharedOne()
    {
        _harness.WithPasswordAccount();

        await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(
                Request(password: "wrong"), BackOfficeSignInContext.None, CancellationToken.None));

        await _harness.Limiter.DidNotReceive().PeekAsync(
            SourceDimension, Arg.Any<string>(), Arg.Any<RateLimitPolicy>(), Arg.Any<CancellationToken>());
        await _harness.Limiter.DidNotReceive().TryAcquireAsync(
            SourceDimension, Arg.Any<string>(), Arg.Any<RateLimitPolicy>(), Arg.Any<CancellationToken>());
    }

    /// <summary>The three dimensions never share a counter, so hammering one door cannot lock
    /// anybody out of another.</summary>
    [Fact]
    public void TheThreeDimensionsAreDistinct()
    {
        var dimensions = new[] { PasswordDimension, SourceDimension, OtpDimension };

        dimensions.Distinct(StringComparer.Ordinal).Count().ShouldBe(3);
    }

    // ------------------------------------------------------------------ the one-time-password door

    /// <summary>
    /// This door still counts attempts, and that is not an oversight: every attempt is an HTTP call
    /// to the corporate directory about a code somebody was sent, so arriving at all is what is
    /// worth bounding. Specification 3.3 step 1.
    /// </summary>
    [Fact]
    public async Task TheOneTimePasswordDoorStillCountsEveryAttempt()
    {
        await _harness.Sut.SignInWithStaffOtpAsync(
            new BackOfficeStaffOtpSignInRequest
            {
                StaffId = SignInTestHarness.StaffId,
                OneTimePassword = SignInTestHarness.OneTimePassword,
            },
            BackOfficeSignInContext.None,
            CancellationToken.None);

        await _harness.Limiter.Received(1).TryAcquireAsync(
            OtpDimension,
            SignInTestHarness.StaffId,
            Policy(TimeSpan.FromMinutes(1)),
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// Specification 3.3 step 9: and because it counts attempts, it has to clear them on success or
    /// five correct sign-ins in a minute lock the employee number out. Only consecutive attempts
    /// should accumulate.
    /// </summary>
    [Fact]
    public async Task TheOneTimePasswordDoorClearsItsBudgetOnSuccess()
    {
        await _harness.Sut.SignInWithStaffOtpAsync(
            new BackOfficeStaffOtpSignInRequest
            {
                StaffId = SignInTestHarness.StaffId,
                OneTimePassword = SignInTestHarness.OneTimePassword,
            },
            BackOfficeSignInContext.None,
            CancellationToken.None);

        await _harness.Limiter.Received(1).ResetAsync(
            OtpDimension,
            SignInTestHarness.StaffId,
            Arg.Is<IReadOnlyList<RateLimitPolicy>>(policies =>
                policies.Count == 2
                && policies.Any(policy => policy.Window == TimeSpan.FromMinutes(1) && policy.Limit == 5)
                && policies.Any(policy => policy.Window == TimeSpan.FromHours(1) && policy.Limit == 20)),
            Arg.Any<CancellationToken>());
    }

    /// <summary>A refused one-time-password attempt clears nothing - the whole point of the budget
    /// is that consecutive failures accumulate.</summary>
    [Fact]
    public async Task ARefusedOneTimePasswordClearsNothing()
    {
        _harness.StaffDirectory.VerifyOtpAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new StaffOtpVerification(false, "9999", "expired", "no"));

        await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithStaffOtpAsync(
                new BackOfficeStaffOtpSignInRequest
                {
                    StaffId = SignInTestHarness.StaffId,
                    OneTimePassword = SignInTestHarness.OneTimePassword,
                },
                BackOfficeSignInContext.None,
                CancellationToken.None));

        await _harness.Limiter.DidNotReceive().ResetAsync(
            Arg.Any<string>(),
            Arg.Any<string>(),
            Arg.Any<IReadOnlyList<RateLimitPolicy>>(),
            Arg.Any<CancellationToken>());
    }

    // ------------------------------------------------------------------ the timing equaliser

    /// <summary>
    /// The dummy hash carries the parameters this service writes today, compared against a real
    /// hash rather than against a copy of the literal. Raise the Argon2id constants and this fails,
    /// which is the point: a dummy with cheaper parameters costs less than a real verify, and the
    /// enumeration oracle simply comes back quieter.
    /// </summary>
    [Fact]
    public void TheDummyHashCarriesTheProductionParameters()
    {
        var real = new PasswordHasher().Hash("any-password-at-all").Split('$');
        var dummy = BackOfficePasswordTiming.DummyHash.Split('$');

        dummy.Length.ShouldBe(real.Length);
        dummy[1].ShouldBe(real[1], "the algorithm");
        dummy[2].ShouldBe(real[2], "the version");
        dummy[3].ShouldBe(real[3], "memory, iterations and lanes - what the cost actually is");
        Decoded(dummy[4]).ShouldBe(Decoded(real[4]), "the salt length");
        Decoded(dummy[5]).ShouldBe(Decoded(real[5]), "the tag length, which is the output length");
    }

    /// <summary>
    /// Nothing verifies against it. The tag is 32 random bytes rather than the digest of a chosen
    /// password, so there is no preimage for anybody to sign in as a non-existent address with.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("password")]
    [InlineData(SignInTestHarness.Password)]
    public void NoPasswordVerifiesAgainstTheDummyHash(string password) =>
        new PasswordHasher().Verify(password, BackOfficePasswordTiming.DummyHash).ShouldBeFalse();

    /// <summary>
    /// The property the whole exercise is about, measured where it is cheap to measure: the three
    /// refusal paths of the password door cost the same.
    /// <para>
    /// <b>Why a clock and not a call count.</b> <see cref="PasswordHasher"/> is sealed and holds no
    /// seam - correctly, it is pure computation - so there is nothing to count calls on, and
    /// counting them would prove the call happened rather than that it cost anything. Argon2id at
    /// <c>m=19456,t=2</c> is tens of milliseconds while everything else on these paths is a
    /// substituted repository answering from a list, so in-process the signal is two orders of
    /// magnitude above the noise. The assertions are shaped to survive a slow machine: a floor
    /// low enough that only a <i>missing</i> derivation trips it, and a ratio - all three grow
    /// together under load, so their ratio does not.
    /// </para>
    /// <para>
    /// The floor is what catches the oracle coming back. The ratio is what catches the opposite
    /// mistake: an equalising verify added to the path that already ran a real one, which would
    /// make a wrong password cost double and 19 MiB of Argon2id working set is charged to the
    /// container's memory limit, not only to the latency.
    /// </para>
    /// </summary>
    [Fact]
    public async Task TheThreeRefusalPathsOfThePasswordDoorCostTheSame()
    {
        var known = _harness.WithPasswordAccount();
        _harness.AddIdentity(58, BackendIdentityTypes.Email, "no.local.password@liontravel.com");
        _harness.AccountRows.Add(new BackendUser
        {
            Id = 58,
            PasswordHash = null,
            Nickname = "otp.only",
            Status = BackendUserStatuses.Active,
            Origin = BackendUserOrigins.Internal,
        });

        known.PasswordHash.ShouldNotBeNull();

        var unknownAddress = await ElapsedAsync(Request(email: "nobody@liontravel.com"));
        var noLocalPassword = await ElapsedAsync(Request(email: "no.local.password@liontravel.com"));
        var wrongPassword = await ElapsedAsync(Request(password: "not-the-password"));

        double[] samples = [unknownAddress, noLocalPassword, wrongPassword];

        foreach (var sample in samples)
        {
            sample.ShouldBeGreaterThan(
                15,
                $"every refusal must pay for one Argon2id verification; these were "
                + $"{unknownAddress:F1} / {noLocalPassword:F1} / {wrongPassword:F1} ms");
        }

        (samples.Max() / samples.Min()).ShouldBeLessThan(
            1.8,
            $"no path may pay for two verifications, or none; these were "
            + $"{unknownAddress:F1} / {noLocalPassword:F1} / {wrongPassword:F1} ms");
    }

    private async Task<double> ElapsedAsync(BackOfficePasswordSignInRequest request)
    {
        var started = Stopwatch.GetTimestamp();

        await Should.ThrowAsync<UnauthorizedException>(() =>
            _harness.Sut.SignInWithPasswordAsync(request, From("203.0.113.7"), CancellationToken.None));

        return Stopwatch.GetElapsedTime(started).TotalMilliseconds;
    }

    private static RateLimitPolicy Policy(TimeSpan window) =>
        Arg.Is<RateLimitPolicy>(policy => policy.Window == window);

    private static int Decoded(string phcBase64) =>
        Convert.FromBase64String(
            phcBase64.PadRight(phcBase64.Length + ((4 - (phcBase64.Length % 4)) % 4), '=')).Length;
}
