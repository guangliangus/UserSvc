using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.RiskControl;
using UserSvc.Application.Ports.External;
using UserSvc.Infrastructure.External;
using UserSvc.Infrastructure.Platform;
using Xunit;

namespace UserSvc.UnitTests.RiskControl;

/// <summary>
/// The send-code state machine and the CAPTCHA token's lifecycle.
/// <para>
/// Every test here pins a decision that is invisible in the type signature and expensive to get
/// wrong: which comparison the threshold uses, whether a cooldown is checked before or after
/// counting, what a Redis outage answers on each of the three methods, and - the one that matters
/// most - that a bypass credential is spendable exactly once.
/// </para>
/// </summary>
public sealed class RiskControlServiceTests
{
    private const string KeyPrefix = "test:";

    private const string Target = "user@example.com";

    private const string DeviceId = "device-1";

    private static readonly DateTimeOffset Now = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeRedis _redis = new();

    private readonly FakeCaptchaVerifier _captcha = new();

    private readonly TestClock _clock = new(Now);

    private readonly RiskControlOptions _options = new();

    private FakeRateLimiter _limiter = null!;

    private static SendCodeRiskContext Subject(string target = Target, string deviceId = DeviceId) =>
        new(target, "email", deviceId);

    private static CaptchaVerificationContext Challenge(string target = Target, string deviceId = DeviceId) =>
        new("provider-token", target, "email", deviceId, CaptchaRegions.Overseas, CaptchaPlatforms.Web, "203.0.113.7", "curl/8.4.0");

    private RiskControlService Build()
    {
        _limiter = new FakeRateLimiter(_redis, KeyPrefix);

        return new RiskControlService(
            _limiter,
            _captcha,
            _redis.Connection,
            Options.Create(new RedisOptions { Configuration = "localhost:6379", KeyPrefix = KeyPrefix }),
            Options.Create(_options),
            _clock,
            NullLogger<RiskControlService>.Instance);
    }

    // ------------------------------------------------------------------ Throttling

    /// <summary>
    /// The threshold includes the request being decided, so a threshold of 5 serves four and
    /// challenges the fifth. This is deliberately one less than the rate limiter's convention, and
    /// getting it backwards is a silent off-by-one in a security control - which is why it is the
    /// first test in the file.
    /// </summary>
    [Fact]
    public async Task ThresholdServesOneFewerRequestThanItsNumber()
    {
        var service = Build();

        for (var attempt = 1; attempt < _options.SendCodeThreshold; attempt++)
        {
            var allowed = await service.EvaluateSendCodeAsync(Subject(), CancellationToken.None);
            allowed.Action.ShouldBe(SendCodeRiskDecision.RiskAction.Allow, $"attempt {attempt} is under the threshold");
        }

        var decision = await service.EvaluateSendCodeAsync(Subject(), CancellationToken.None);

        decision.Action.ShouldBe(SendCodeRiskDecision.RiskAction.CaptchaRequired);
        decision.ResetAt.ShouldBeNull();
        decision.RetryAfter.ShouldBe(TimeSpan.Zero);
    }

    /// <summary>
    /// A subject that has already solved a CAPTCHA and comes straight back over the threshold is
    /// cooled down instead of challenged again: a second CAPTCHA from someone who just passed one
    /// is not evidence of anything.
    /// </summary>
    [Fact]
    public async Task SecondTriggerCoolsDownInsteadOfChallengingAgain()
    {
        var service = Build();
        _redis.Set(PassedKey(Target), "1");

        SendCodeRiskDecision decision = SendCodeRiskDecision.Allow();

        for (var attempt = 0; attempt < _options.SendCodeThreshold; attempt++)
        {
            decision = await service.EvaluateSendCodeAsync(Subject(), CancellationToken.None);
        }

        decision.Action.ShouldBe(SendCodeRiskDecision.RiskAction.Cooldown);
        decision.RetryAfter.ShouldBe(_options.CooldownDuration);
        decision.ResetAt.ShouldBe(Now + _options.CooldownDuration);

        // Both dimensions carry the cooldown, so switching device or address does not shake it off.
        _redis.Peek(CooldownKey("target", Target))
            .ShouldBe((Now + _options.CooldownDuration).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
        _redis.Peek(CooldownKey("device", DeviceId)).ShouldNotBeNull();
        _redis.TimeToLive(CooldownKey("target", Target)).ShouldBe(_options.CooldownDuration);
    }

    /// <summary>
    /// A cooldown already in flight is reported <b>before</b> anything is counted. Counting first
    /// would let a client extend its own lockout by retrying into it - a punishment that grows the
    /// more politely the client behaves, which is the shape of a bug rather than of a policy.
    /// </summary>
    [Fact]
    public async Task AnActiveCooldownIsReportedWithoutCountingTheRequest()
    {
        var service = Build();
        var until = Now.AddMinutes(3);
        _redis.Set(CooldownKey("target", Target), until.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));

        var decision = await service.EvaluateSendCodeAsync(Subject(), CancellationToken.None);

        decision.Action.ShouldBe(SendCodeRiskDecision.RiskAction.Cooldown);
        decision.ResetAt.ShouldBe(until);
        decision.RetryAfter.ShouldBe(TimeSpan.FromMinutes(3));
        _limiter.Calls.ShouldBeEmpty("a cooled-down subject must not be able to inflate its own counter");
    }

    /// <summary>
    /// The device dimension is its own subject. An attacker cycling fresh addresses from one device
    /// never trips any single address, which is exactly the case this counter exists for.
    /// </summary>
    [Fact]
    public async Task TheDeviceDimensionTripsOnItsOwn()
    {
        var service = Build();
        SendCodeRiskDecision decision = SendCodeRiskDecision.Allow();

        for (var attempt = 0; attempt < _options.SendCodeThreshold; attempt++)
        {
            decision = await service.EvaluateSendCodeAsync(
                Subject($"user{attempt}@example.com", "shared-device"),
                CancellationToken.None);
        }

        decision.Action.ShouldBe(SendCodeRiskDecision.RiskAction.CaptchaRequired);
    }

    /// <summary>
    /// A counting outage degrades to Allow, which the port promises: the counters slow abuse of a
    /// code-sending endpoint, and losing them must not stop people signing in. The per-IP budget in
    /// front of the endpoint is what remains.
    /// </summary>
    [Fact]
    public async Task ACountingOutageAllows()
    {
        var service = Build();
        _limiter.FailOpen = true;
        _redis.FaultReads = true;

        for (var attempt = 0; attempt < _options.SendCodeThreshold + 3; attempt++)
        {
            var decision = await service.EvaluateSendCodeAsync(Subject(), CancellationToken.None);
            decision.Action.ShouldBe(SendCodeRiskDecision.RiskAction.Allow);
        }
    }

    /// <summary>
    /// <b>Nothing on the send path throws, whatever Redis is doing.</b>
    /// <para>
    /// This is the promise the port writes down and the one that matters most in the wiring: the
    /// send-code path is crossed by login, registration and every code request, so a risk engine
    /// that raised during a Redis incident would convert a degraded cache into an outage of
    /// sign-in. Every read, every write and the script are faulted at once here, which is more than
    /// any single outage does.
    /// </para>
    /// </summary>
    [Fact]
    public async Task NothingOnTheSendPathThrowsDuringATotalRedisOutage()
    {
        var service = Build();
        _redis.FaultReads = true;
        _redis.FaultWrites = true;
        _redis.FaultScripts = true;
        _limiter.FailOpen = true;

        var decision = await service.EvaluateSendCodeAsync(Subject(), CancellationToken.None);
        decision.Action.ShouldBe(SendCodeRiskDecision.RiskAction.Allow);

        // And the gate still refuses rather than degrading: a token nothing could check is not a
        // bypass. This is the one place in the class where an outage says no.
        (await service.TryConsumeCaptchaTokenAsync("cpt_anything", Subject(), CancellationToken.None))
            .ShouldBeFalse();
    }

    /// <summary>
    /// The counters trip but the cooldown cannot be written. The decision has already been made, so
    /// it is returned - a bookkeeping write must not turn a throttle into a 502 for a caller who
    /// was going to be refused anyway. The cost is one extra challenge later, which is why the
    /// write is best-effort.
    /// </summary>
    [Fact]
    public async Task ACooldownThatCannotBeWrittenIsStillReported()
    {
        var service = Build();
        _redis.Set(PassedKey(Target), "1");
        _redis.FaultWrites = true;

        SendCodeRiskDecision decision = null!;

        for (var attempt = 0; attempt < _options.SendCodeThreshold; attempt++)
        {
            decision = await service.EvaluateSendCodeAsync(Subject(), CancellationToken.None);
        }

        decision.Action.ShouldBe(SendCodeRiskDecision.RiskAction.Cooldown);
        decision.RetryAfter.ShouldBe(_options.CooldownDuration);
    }

    /// <summary>
    /// With no CAPTCHA provider configured, the escalation is a cooldown and never a challenge.
    /// <para>
    /// Answering CaptchaRequired here would send every over-threshold user to solve something that
    /// can never mint a redeemable token: the endpoint would be dead rather than throttled, and the
    /// 403 would promise a remedy that does not exist. A cooldown is a 429 with a Retry-After the
    /// client can act on, and it lifts by itself.
    /// </para>
    /// </summary>
    [Fact]
    public async Task WithNoProviderConfiguredTheThresholdCoolsDownRatherThanChallenging()
    {
        var service = Build();
        _captcha.IsConfigured = false;

        SendCodeRiskDecision decision = SendCodeRiskDecision.Allow();

        for (var attempt = 0; attempt < _options.SendCodeThreshold; attempt++)
        {
            decision = await service.EvaluateSendCodeAsync(Subject(), CancellationToken.None);
        }

        decision.Action.ShouldBe(SendCodeRiskDecision.RiskAction.Cooldown);
        decision.RetryAfter.ShouldBe(_options.CooldownDuration);
    }

    // ------------------------------------------------------------------ Token redemption

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task ABlankTokenIsNeverRedeemed(string token) =>
        (await Build().TryConsumeCaptchaTokenAsync(token, Subject(), CancellationToken.None)).ShouldBeFalse();

    /// <summary>
    /// A token is bound to the target and the device it was issued for. Without the binding one
    /// solved CAPTCHA would be a reusable bypass for every address in the system.
    /// </summary>
    [Fact]
    public async Task ATokenIssuedForAnotherSubjectIsRefused()
    {
        var service = Build();
        var token = (await service.VerifyCaptchaAsync(Challenge(), CancellationToken.None)).CaptchaToken;

        (await service.TryConsumeCaptchaTokenAsync(token, Subject("someone.else@example.com"), CancellationToken.None))
            .ShouldBeFalse();

        (await service.TryConsumeCaptchaTokenAsync(token, Subject(deviceId: "another-device"), CancellationToken.None))
            .ShouldBeFalse();

        // Refusing a mismatch must not destroy the token - otherwise anyone who can guess a key
        // deletes somebody else's valid credential.
        (await service.TryConsumeCaptchaTokenAsync(token, Subject(), CancellationToken.None)).ShouldBeTrue();
    }

    /// <summary>
    /// A redemption clears the send counters - by deleting the very keys the limiter wrote - and
    /// records that this target has passed, which is what makes the next trip escalate to a
    /// cooldown instead of another challenge.
    /// </summary>
    [Fact]
    public async Task RedeemingATokenClearsTheCountersAndMarksTheSubjectAsPassed()
    {
        var service = Build();

        for (var attempt = 0; attempt < _options.SendCodeThreshold; attempt++)
        {
            await service.EvaluateSendCodeAsync(Subject(), CancellationToken.None);
        }

        var token = (await service.VerifyCaptchaAsync(Challenge(), CancellationToken.None)).CaptchaToken;

        (await service.TryConsumeCaptchaTokenAsync(token, Subject(), CancellationToken.None)).ShouldBeTrue();

        _redis.Peek(PassedKey(Target)).ShouldBe("1");
        _redis.TimeToLive(PassedKey(Target)).ShouldBe(_options.CaptchaPassedTtl);

        // The window that was full a moment ago now serves again.
        (await service.EvaluateSendCodeAsync(Subject(), CancellationToken.None)).Action
            .ShouldBe(SendCodeRiskDecision.RiskAction.Allow);
    }

    /// <summary>
    /// The single most load-bearing property in the file. With a GET followed by a DEL, ten
    /// concurrent callers all read the same live token and all get their bypass; the delete
    /// afterwards only decides which of them tidied up.
    /// </summary>
    [Fact]
    public async Task ATokenIsRedeemableExactlyOnceUnderConcurrency()
    {
        var service = Build();
        var token = (await service.VerifyCaptchaAsync(Challenge(), CancellationToken.None)).CaptchaToken;

        var attempts = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => Task.Run(
            () => service.TryConsumeCaptchaTokenAsync(token, Subject(), CancellationToken.None))));

        attempts.Count(consumed => consumed).ShouldBe(1, "a captcha token must be consumable exactly once");
    }

    /// <summary>
    /// The one place a Redis outage refuses rather than degrades. Returning true for a token
    /// nothing could check would honour a bypass credential on nobody's authority - and unlike the
    /// counters, there is no backstop underneath this one.
    /// </summary>
    [Fact]
    public async Task AnOutageRefusesTheBypassRatherThanHonouringIt()
    {
        var service = Build();
        var token = (await service.VerifyCaptchaAsync(Challenge(), CancellationToken.None)).CaptchaToken;
        _redis.FaultScripts = true;

        (await service.TryConsumeCaptchaTokenAsync(token, Subject(), CancellationToken.None)).ShouldBeFalse();
    }

    // ------------------------------------------------------------------ Verification

    /// <summary>
    /// A successful assessment mints a prefixed, high-entropy credential and stores only its digest,
    /// bound to this target and device.
    /// </summary>
    [Fact]
    public async Task ASolvedChallengeMintsABoundSingleUseToken()
    {
        var service = Build();

        var result = await service.VerifyCaptchaAsync(Challenge(), CancellationToken.None);

        result.CaptchaToken.ShouldStartWith("cpt_");
        result.CaptchaToken.Length.ShouldBeGreaterThan(40);
        result.ExpiresIn.ShouldBe(_options.CaptchaTokenTtl);

        var key = $"{KeyPrefix}riskctl:captcha-token:{HashSecret(result.CaptchaToken)}";
        _redis.Peek(key).ShouldBe($"{Hash(Target)}|{Hash(DeviceId)}");
        _redis.TimeToLive(key).ShouldBe(_options.CaptchaTokenTtl);

        // The plaintext exists only in the response; Redis holds a digest of it and nothing else.
        _redis.Keys().ShouldNotContain(k => k.Contains(result.CaptchaToken, StringComparison.Ordinal));
    }

    /// <summary>
    /// A failed assessment is a 400 the client can retry, and the reason the provider gave stays in
    /// the log: "score 0.1" would hand an attacker a dial to tune their automation against.
    /// </summary>
    [Fact]
    public async Task AFailedAssessmentIsARetryableRefusal()
    {
        var service = Build();
        _captcha.Assessment = CaptchaAssessment.Fail("score below threshold", 0.1);

        var ex = await Should.ThrowAsync<BadRequestException>(
            () => service.VerifyCaptchaAsync(Challenge(), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.CaptchaInvalid);
        ex.StatusCode.ShouldBe(400);
        ex.Message.ShouldNotContain("score");
    }

    /// <summary>
    /// Consecutive failures from one device end in a cooldown rather than looping forever.
    /// reCAPTCHA v3 is score-only, so a human the model dislikes has no puzzle to solve their way
    /// out of; telling them to come back later is at least true.
    /// </summary>
    [Fact]
    public async Task RepeatedFailuresCoolTheCallingDeviceDownInsteadOfLooping()
    {
        var service = Build();
        _captcha.Assessment = CaptchaAssessment.Fail("score below threshold", 0.1);

        for (var attempt = 1; attempt < _options.CaptchaFailThreshold; attempt++)
        {
            await Should.ThrowAsync<BadRequestException>(
                () => service.VerifyCaptchaAsync(Challenge(), CancellationToken.None));
        }

        var cooled = await Should.ThrowAsync<RateLimitedException>(
            () => service.VerifyCaptchaAsync(Challenge(), CancellationToken.None));

        cooled.ErrorCode.ShouldBe(ErrorCodes.RiskControlCooldown);
        cooled.RetryAfter.ShouldBe(_options.CooldownDuration);

        // The cooldown is shared with the send path, so the two endpoints agree about the device
        // rather than each keeping its own opinion.
        (await service.EvaluateSendCodeAsync(Subject(), CancellationToken.None)).Action
            .ShouldBe(SendCodeRiskDecision.RiskAction.Cooldown);

        // And it landed on the device, not on the address that was typed. See the next two tests
        // for why that distinction is the whole point.
        _redis.Peek(CooldownKey("device", DeviceId)).ShouldNotBeNull();
        _redis.Peek(CooldownKey("target", Target)).ShouldBeNull();
    }

    /// <summary>
    /// <b>A failed CAPTCHA must not be able to refuse an address the caller does not control.</b>
    /// <para>
    /// This is the one place this implementation deliberately departs from the Go original, and it
    /// is a security fix rather than a preference. The Go service counted failed assessments on the
    /// target dimension and wrote the shared cooldown there, which means five requests carrying
    /// deliberate garbage tokens put any known phone number or email address into a five-minute
    /// cooldown - repeatable indefinitely, from anywhere, with no account and no prior state. That
    /// is a free way to stop a victim from ever receiving a password-reset code.
    /// </para>
    /// <para>
    /// A send genuinely spends the target's budget, so the send counter is rightly per target. A
    /// failed assessment spends nothing of the target's, so it cools down the caller's own device
    /// and nothing else.
    /// </para>
    /// </summary>
    [Fact]
    public async Task FailedAssessmentsCannotCoolDownAnAddressTheCallerDoesNotControl()
    {
        var service = Build();
        _captcha.Assessment = CaptchaAssessment.Fail("score below threshold", 0.1);

        // An attacker, on their own device, burning the victim's address through the threshold and
        // well past it.
        for (var attempt = 0; attempt < _options.CaptchaFailThreshold * 3; attempt++)
        {
            await Should.ThrowAsync<AppException>(
                () => service.VerifyCaptchaAsync(
                    Challenge(deviceId: "attacker-device"),
                    CancellationToken.None));
        }

        _redis.Peek(CooldownKey("target", Target)).ShouldBeNull(
            "a failed assessment consumes nothing belonging to the address that was typed");

        // The victim, on their own device, is unaffected and still gets a code.
        (await service.EvaluateSendCodeAsync(Subject(deviceId: "victim-device"), CancellationToken.None)).Action
            .ShouldBe(SendCodeRiskDecision.RiskAction.Allow);
    }

    /// <summary>
    /// With no device id there is nothing the failure can be charged to, so it stays a retryable
    /// 400 forever rather than escalating.
    /// <para>
    /// That is the accepted cost of the fix above: a caller who sends no <c>X-Device-ID</c> loops
    /// on <c>CAPTCHA_INVALID</c> instead of being told to come back later. It is the same answer
    /// they got before the threshold, it is retryable, and it is a great deal better than a
    /// lockout anyone can aim at anyone.
    /// </para>
    /// </summary>
    [Fact]
    public async Task WithNoDeviceIdAFailedAssessmentStaysRetryable()
    {
        var service = Build();
        _captcha.Assessment = CaptchaAssessment.Fail("score below threshold", 0.1);

        for (var attempt = 0; attempt < _options.CaptchaFailThreshold * 2; attempt++)
        {
            var ex = await Should.ThrowAsync<BadRequestException>(
                () => service.VerifyCaptchaAsync(Challenge(deviceId: ""), CancellationToken.None));

            ex.ErrorCode.ShouldBe(ErrorCodes.CaptchaInvalid);
        }

        _redis.Keys().ShouldNotContain(CooldownKey("target", Target));
    }

    /// <summary>
    /// A cooled-down subject is refused here too, before the provider is called at all.
    /// <para>
    /// Cooldown is defined as "a CAPTCHA will not help". If one could be solved and redeemed during
    /// a cooldown - and the send path redeems a token without consulting the throttle - then the
    /// second-trigger escalation would be a suggestion rather than a decision.
    /// </para>
    /// </summary>
    [Fact]
    public async Task AChallengeIsNotEvenAssessedWhileTheSubjectIsCoolingDown()
    {
        var service = Build();
        var until = Now.AddMinutes(4);
        _redis.Set(CooldownKey("target", Target), until.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));

        var ex = await Should.ThrowAsync<RateLimitedException>(
            () => service.VerifyCaptchaAsync(Challenge(), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RiskControlCooldown);
        ex.RetryAfter.ShouldBe(TimeSpan.FromMinutes(4));
        _captcha.CallCount.ShouldBe(0, "there is no point paying for an assessment we would refuse anyway");
    }

    /// <summary>
    /// A token that was minted but not stored is a credential the caller cannot spend. Handing it
    /// back would show a success that fails at the next step with nothing anywhere to explain it,
    /// so the write is the one in this class that throws.
    /// </summary>
    [Fact]
    public async Task ATokenThatCouldNotBeStoredIsNotReturned()
    {
        var service = Build();
        _redis.FaultWrites = true;

        var ex = await Should.ThrowAsync<UpstreamException>(
            () => service.VerifyCaptchaAsync(Challenge(), CancellationToken.None));

        ex.StatusCode.ShouldBe(502);
        ex.ErrorCode.ShouldBe(ErrorCodes.UpstreamUnavailable);
    }

    /// <summary>The provider's own failures travel out unchanged: an unconfigured deployment is a
    /// 500 and an unreachable provider is a 502, and neither can be mistaken for a pass.</summary>
    [Fact]
    public async Task ProviderFailuresAreNotTurnedIntoAPass()
    {
        var service = Build();
        _captcha.Throws = new UpstreamException(ErrorCodes.UpstreamUnavailable, "unreachable");

        await Should.ThrowAsync<UpstreamException>(
            () => service.VerifyCaptchaAsync(Challenge(), CancellationToken.None));
    }

    private static string CooldownKey(string dimension, string subject) =>
        $"{KeyPrefix}riskctl:cooldown:{dimension}:{Hash(subject)}";

    private static string PassedKey(string subject) => $"{KeyPrefix}riskctl:captcha-passed:{Hash(subject)}";

    private static string Hash(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value.Trim().ToLowerInvariant())));

    private static string HashSecret(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
