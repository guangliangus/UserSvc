using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.RiskControl;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Platform;
using UserSvc.Infrastructure.Platform;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// The real adaptive throttle for the send-code path, and the CAPTCHA escalation that lets a
/// legitimate user who tripped it carry on.
/// <para>
/// <b>The counting is not done here.</b> Both counters - sends per subject, failed assessments per
/// subject - are <see cref="IRateLimiter"/> policies, so there is exactly one fixed-window
/// implementation in this service, one key layout, one Lua script and one fail-open decision to
/// reason about. What this class owns is the state a limiter has no concept of: the cooldown, the
/// "already solved one" marker, and the one-time bypass token.
/// </para>
/// <para>
/// <b>The two conventions differ by one and the difference is deliberate.</b> A rate limit of 5
/// serves five requests; a risk threshold of 5 serves four and challenges the fifth, because a
/// threshold is where suspicion starts while a limit is an allowance that must be spendable in
/// full. The translation lives in one place - <see cref="SendCodePolicy"/> - and is
/// <c>limit = threshold - 1</c>, so the limiter's <c>count &gt; limit</c> is exactly the port's
/// <c>count &gt;= threshold</c>. Writing it anywhere else would be a silent off-by-one in a
/// security control.
/// </para>
/// <para>
/// <b>Failure directions, each taken from the table in docs/architecture.md rather than invented
/// here.</b>
/// </para>
/// <list type="bullet">
/// <item>
/// <b>Counting and cooldown reads fail open.</b> They are protective counters in front of an
/// endpoint that is separately rate-limited per IP; a Redis blip must not stop people signing in.
/// This is the limiter's own line in that table, and the reads are the same kind of thing.
/// </item>
/// <item>
/// <b>Redeeming a token fails closed.</b> It is not a counter, it is the gate: returning true for a
/// token nothing could check would honour a bypass credential on nobody's authority. The port
/// mandates false, and false is also what a Redis outage produces here.
/// </item>
/// <item>
/// <b>Storing a freshly minted token fails loud.</b> Same reasoning as the revocation set's write
/// path: the caller is about to be handed a credential, and if the binding did not land the
/// credential is worthless - silently returning it would show the user a success they cannot spend.
/// </item>
/// <item>
/// <b>Cooldown writes are best-effort.</b> The decision has already been made and is being returned;
/// throwing would turn a throttle into a 502 for a caller who was going to be refused anyway.
/// </item>
/// </list>
/// <para>
/// <b>One dimension rule, and it is the reason this differs from the Go original.</b> A cooldown
/// may only be written on a dimension the failing action actually consumed. A send spends the
/// target's budget - a code was delivered to that address - so the send counter is rightly per
/// target and its cooldown rightly refuses that target. A failed CAPTCHA assessment spends nothing
/// of the target's; it says something about the caller and nothing about the address they typed.
/// The Go service counted it per target anyway, and five requests carrying deliberate garbage
/// tokens would then put any known phone number or email into a cooldown, repeatably, from
/// anywhere, with no account and no prior state - a free way to keep a victim from receiving a
/// password-reset code. So <see cref="CaptchaFailDeviceDimension"/> is device-only.
/// </para>
/// <para>
/// <b>What remains, and is not this class's to fix:</b> a third party who knows an address can
/// still spend that address's <i>send</i> budget and push it into <c>CAPTCHA_REQUIRED</c> and then
/// a cooldown - but each of those requests delivers a real code to the victim, which is the abuse
/// the throttle exists to bound rather than a side effect of it, and it is what the spec mandates.
/// Dropping the target dimension there would remove the only defence against an attacker who
/// rotates devices and IPs.
/// </para>
/// </summary>
public sealed class RiskControlService(
    IRateLimiter rateLimiter,
    ICaptchaVerifier captcha,
    IConnectionMultiplexer connection,
    IOptions<RedisOptions> redisOptions,
    IOptions<RiskControlOptions> options,
    IClock clock,
    ILogger<RiskControlService> logger) : IRiskControlService
{
    /// <summary>The send counter's dimensions. Two dimensions never share a counter, so an
    /// attacker cycling fresh addresses from one device still trips the device one.</summary>
    private const string SendCodeTargetDimension = "riskctl-sendcode-target";

    private const string SendCodeDeviceDimension = "riskctl-sendcode-device";

    /// <summary>
    /// The failed-assessment counter, a separate budget from the send counters above and
    /// <b>deliberately device-only</b>.
    /// <para>
    /// The send counters have a target dimension because a send genuinely spends the target's
    /// budget - a code was delivered to that address. A failed CAPTCHA spends nothing of the
    /// target's: it says something about the caller and nothing about the address they typed. The
    /// Go service counted it per target anyway, and the consequence is cheap and specific - five
    /// requests carrying deliberate garbage tokens put any known phone number or email address
    /// into a five-minute cooldown, repeatable indefinitely, which is a free way to keep a victim
    /// from ever receiving a password-reset code.
    /// </para>
    /// <para>
    /// So the rule here is: <b>a cooldown may only be written on a dimension the failing action
    /// actually consumed.</b> The device id is caller-supplied, so cooling it down is self-
    /// inflicted; the target is not, so it is never cooled down by a failed assessment. A caller
    /// with no device id at all is simply told <c>CAPTCHA_INVALID</c> every time and can retry -
    /// which is the same answer they got before the threshold, and strictly better than a lockout
    /// anyone could aim at anyone.
    /// </para>
    /// </summary>
    private const string CaptchaFailDeviceDimension = "riskctl-captchafail-device";

    /// <summary>Cooldown dimensions. <c>target</c> rather than the Go service's <c>phone</c>: the
    /// same counter holds email addresses, and a key that lies about what it holds costs an
    /// operator an hour during an incident.</summary>
    private const string TargetDimension = "target";

    private const string DeviceDimension = "device";

    /// <summary>Prefix of every bypass token, so a value found in a log or a bug report is
    /// recognisable for what it is.</summary>
    private const string TokenPrefix = "cpt_";

    /// <summary>The value of the "already solved one" marker. Only the key's existence and its TTL
    /// carry meaning.</summary>
    private const string PassedMarker = "1";

    /// <summary>
    /// Compare-and-delete in one Redis execution.
    /// <para>
    /// <b>It must not be a GET followed by a DEL</b>, and this is the single most load-bearing
    /// detail in the file: with two round trips, N concurrent requests all read the same live token
    /// and all get their bypass, and the delete afterwards only decides which of them tidied up. A
    /// script runs to completion without interleaving, so exactly one caller can observe the value
    /// and remove it.
    /// </para>
    /// <para>
    /// It is also not <c>GETDEL</c>. That would delete the key even when the binding does not
    /// match, handing anyone who can guess a token key a way to destroy somebody else's valid one.
    /// The delete has to be conditional on the comparison.
    /// </para>
    /// </summary>
    private const string ConsumeTokenScript =
        """
        local value = redis.call('GET', KEYS[1])
        if value == false then return 0 end
        if value == ARGV[1] then
          redis.call('DEL', KEYS[1])
          return 1
        end
        return 0
        """;

    private readonly RiskControlOptions _options = options.Value;

    private readonly string _keyPrefix = redisOptions.Value.KeyPrefix;

    /// <summary>The send threshold as a limiter policy: see the class remarks for the minus one.</summary>
    private RateLimitPolicy SendCodePolicy => new(_options.SendCodeWindow, _options.SendCodeThreshold - 1);

    /// <summary>The failed-assessment threshold, same translation, rolling over one cooldown.</summary>
    private RateLimitPolicy CaptchaFailPolicy => new(_options.CooldownDuration, _options.CaptchaFailThreshold - 1);

    private IDatabase Database => connection.GetDatabase();

    /// <inheritdoc />
    public async Task<SendCodeRiskDecision> EvaluateSendCodeAsync(
        SendCodeRiskContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        // A blank target cannot be counted against anything - the limiter refuses a blank subject,
        // and hashing one would aggregate every such caller into a single shared bucket. The
        // send-code path validates the target before it gets here, so this is only reachable from a
        // future caller that does not; allowing is the port's promised degradation.
        if (string.IsNullOrWhiteSpace(context.Target))
        {
            return SendCodeRiskDecision.Allow();
        }

        var targetHash = HashSubject(context.Target);
        var deviceHash = string.IsNullOrWhiteSpace(context.DeviceId) ? string.Empty : HashSubject(context.DeviceId);
        var now = clock.UtcNow;

        // Cooldowns are read BEFORE anything is counted. Counting first would let a subject already
        // serving a cooldown inflate the counter that decides its next one, so hammering during a
        // cooldown would extend it - a lockout that grows the more the client retries, which is the
        // shape of a bug rather than of a policy.
        if (await ReadCooldownAsync(TargetDimension, targetHash).ConfigureAwait(false) is { } targetUntil
            && targetUntil > now)
        {
            return SendCodeRiskDecision.Cooldown(targetUntil, targetUntil - now);
        }

        if (deviceHash.Length > 0
            && await ReadCooldownAsync(DeviceDimension, deviceHash).ConfigureAwait(false) is { } deviceUntil
            && deviceUntil > now)
        {
            return SendCodeRiskDecision.Cooldown(deviceUntil, deviceUntil - now);
        }

        var policy = SendCodePolicy;

        // Both dimensions are counted, not short-circuited on the first trip: unlike a caller
        // holding several rate-limit policies, these are two independent subjects rather than two
        // budgets belonging to one. Skipping the device increment because the target tripped would
        // let an attacker keep a device invisible by always using a fresh, already-hot address.
        var targetTripped = !(await rateLimiter
            .TryAcquireAsync(SendCodeTargetDimension, context.Target, policy, cancellationToken)
            .ConfigureAwait(false)).Allowed;

        var deviceTripped = deviceHash.Length > 0
                            && !(await rateLimiter
                                .TryAcquireAsync(SendCodeDeviceDimension, context.DeviceId, policy, cancellationToken)
                                .ConfigureAwait(false)).Allowed;

        if (!targetTripped && !deviceTripped)
        {
            return SendCodeRiskDecision.Allow();
        }

        return await EscalateAsync(targetHash, deviceHash, now).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<bool> TryConsumeCaptchaTokenAsync(
        string captchaToken,
        SendCodeRiskContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        // Both halves of the binding must be real for a redemption to mean anything. A blank
        // target hashes to one shared subject, so honouring it would let a token minted for that
        // shared subject unblock any caller who also sent nothing. The port forbids throwing here,
        // and false is the refusing answer.
        if (string.IsNullOrWhiteSpace(captchaToken) || string.IsNullOrWhiteSpace(context.Target))
        {
            return false;
        }

        var targetHash = HashSubject(context.Target);
        var deviceHash = string.IsNullOrWhiteSpace(context.DeviceId) ? string.Empty : HashSubject(context.DeviceId);
        var binding = Bind(targetHash, deviceHash);

        // The stored key hashes the token exactly as presented, with no trimming, because that is
        // how the issuing side wrote it. Trimming one side and not the other would break every
        // redemption in a way that looks like a Redis fault.
        RedisResult reply;

        try
        {
            reply = await Database.ScriptEvaluateAsync(
                ConsumeTokenScript,
                [TokenKey(captchaToken)],
                [binding]).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsRedisFailure(ex))
        {
            // Fail-closed, and the only place in this class where a Redis outage refuses rather
            // than degrades. The alternative is honouring a bypass credential nothing validated.
            logger.LogWarning(
                ex,
                "The CAPTCHA token could not be checked against Redis, so the bypass is refused. "
                + "Callers holding a valid token will be asked to solve another challenge.");

            return false;
        }

        if (!TryReadLong(reply, out var consumed) || consumed != 1)
        {
            return false;
        }

        // Everything past this point is best-effort: the token is already spent and the caller is
        // already through. Losing any of it costs one extra challenge, whereas redeeming twice
        // would cost the gate itself - which is why it happens after the atomic step, not inside it.
        await ClearSendCodeCountersAsync(context).ConfigureAwait(false);
        await MarkCaptchaPassedAsync(targetHash).ConfigureAwait(false);

        return true;
    }

    /// <inheritdoc />
    public async Task<CaptchaVerificationResult> VerifyCaptchaAsync(
        CaptchaVerificationContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        // Not a client-facing check - the API layer answers 400 for a blank target long before
        // this - but the token minted below is *bound* to the target, and a blank one binds every
        // such caller's credential to a single shared subject. If a future caller ever reaches
        // here without validating, the honest outcome is a 500 that names the argument, not a
        // bypass token that half the world can redeem.
        ArgumentException.ThrowIfNullOrWhiteSpace(context.Target, $"{nameof(context)}.{nameof(context.Target)}");

        var targetHash = HashSubject(context.Target);
        var deviceHash = string.IsNullOrWhiteSpace(context.DeviceId) ? string.Empty : HashSubject(context.DeviceId);
        var now = clock.UtcNow;

        // A subject in cooldown is refused here too, before the provider is called at all.
        //
        // The Go original did not do this, and the omission makes its own state machine incoherent:
        // Cooldown is defined as "a CAPTCHA will not help", yet a cooled-down caller could solve one
        // and redeem the resulting token straight past the cooldown - the send path consumes a token
        // without ever consulting the throttle. Either the cooldown means something or it does not.
        // The cost of the difference is one 429 instead of one 400 for a caller who was refused
        // either way; the benefit is that the second-trigger escalation is not a suggestion.
        if (await ReadCooldownAsync(TargetDimension, targetHash).ConfigureAwait(false) is { } targetUntil
            && targetUntil > now)
        {
            throw Cooled(targetUntil - now);
        }

        if (deviceHash.Length > 0
            && await ReadCooldownAsync(DeviceDimension, deviceHash).ConfigureAwait(false) is { } deviceUntil
            && deviceUntil > now)
        {
            throw Cooled(deviceUntil - now);
        }

        var assessment = await captcha.AssessAsync(
            new CaptchaAssessmentRequest(
                context.ProviderToken,
                context.Platform,
                context.ClientIpAddress,
                context.UserAgent),
            cancellationToken).ConfigureAwait(false);

        if (!assessment.Passed)
        {
            // The reason stays in the adapter's log. Telling the caller "score 0.1" would hand an
            // attacker a dial to tune their automation against.
            throw await RefuseAsync(context, deviceHash, now, cancellationToken).ConfigureAwait(false);
        }

        await ClearCaptchaFailureCountersAsync(context).ConfigureAwait(false);

        // 256 bits from a cryptographic source. This is a bypass credential for a throttle on a
        // public endpoint, so it is sized like the verification ticket rather than like a nonce.
        var token = TokenPrefix + Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

        await StoreTokenAsync(token, Bind(targetHash, deviceHash)).ConfigureAwait(false);

        logger.LogInformation(
            "A CAPTCHA was solved for region {Region} on platform {Platform}; a one-time token was "
            + "issued for {Ttl}.",
            context.Region,
            context.Platform,
            _options.CaptchaTokenTtl);

        return new CaptchaVerificationResult(token, _options.CaptchaTokenTtl);
    }

    /// <summary>
    /// What happens once a send counter trips: ask for a CAPTCHA the first time, cool the subject
    /// down the second.
    /// <para>
    /// <b>With no CAPTCHA provider configured there is no first time.</b> Answering
    /// <c>CaptchaRequired</c> when nothing can mint a redeemable token sends every over-threshold
    /// user to solve a challenge that cannot unblock them: the endpoint would be dead rather than
    /// throttled, and the 403 would promise a remedy that does not exist. A cooldown is the honest
    /// answer - it is a 429 with a <c>Retry-After</c> the client can actually act on, it lifts by
    /// itself, and the per-IP budget in front of the endpoint is unaffected. It is deliberately not
    /// <c>Allow</c>: the counters work perfectly well without Google, and an unconfigured provider
    /// is not a reason to stop throttling a public code-sending endpoint.
    /// </para>
    /// </summary>
    private async Task<SendCodeRiskDecision> EscalateAsync(string targetHash, string deviceHash, DateTimeOffset now)
    {
        if (!captcha.IsConfigured)
        {
            logger.LogWarning(
                "A send-code threshold was reached, but no CAPTCHA provider is configured, so the "
                + "subject is cooled down instead of being challenged. Configure {Section} to give "
                + "these callers a way through.",
                RecaptchaOptions.SectionName);

            return await CoolDownAsync(targetHash, deviceHash, now).ConfigureAwait(false);
        }

        if (await HasPassedCaptchaAsync(targetHash).ConfigureAwait(false))
        {
            return await CoolDownAsync(targetHash, deviceHash, now).ConfigureAwait(false);
        }

        return SendCodeRiskDecision.CaptchaRequired();
    }

    /// <summary>
    /// Writes the cooldown on every dimension that has a subject and returns the decision.
    /// <para>
    /// The retry the caller is told is the <b>whole</b> duration, not a remainder: the cooldown
    /// starts now. The remainder form is for a cooldown that was already running when the request
    /// arrived.
    /// </para>
    /// </summary>
    private async Task<SendCodeRiskDecision> CoolDownAsync(string targetHash, string deviceHash, DateTimeOffset now)
    {
        var until = now + _options.CooldownDuration;

        await WriteCooldownAsync(TargetDimension, targetHash, until).ConfigureAwait(false);

        if (deviceHash.Length > 0)
        {
            await WriteCooldownAsync(DeviceDimension, deviceHash, until).ConfigureAwait(false);
        }

        return SendCodeRiskDecision.Cooldown(until, _options.CooldownDuration);
    }

    /// <summary>
    /// Counts one failed assessment and decides whether the caller is told to try again or told to
    /// come back later.
    /// <para>
    /// The escalation exists because reCAPTCHA v3 is score-only: a human the model dislikes has no
    /// puzzle to solve their way out of, so without it they loop on <c>CAPTCHA_INVALID</c> forever.
    /// The cooldown it writes is read by the send path too, so the two endpoints agree about the
    /// subject instead of each keeping its own opinion.
    /// </para>
    /// <para>
    /// <b>It is written on the device dimension and never on the target.</b> See
    /// <see cref="CaptchaFailDeviceDimension"/> - a failed assessment consumes nothing belonging to
    /// the address the caller typed, so letting it refuse that address hands any passer-by a
    /// five-request lockout of anyone whose phone number they know. A caller with no device id is
    /// therefore never cooled down here; it answers <c>CAPTCHA_INVALID</c>, which is a retryable
    /// 400 rather than a refusal.
    /// </para>
    /// <para>
    /// Fail-open on the counter: the limiter allows when it cannot count, and an uncounted failure
    /// is simply <c>CAPTCHA_INVALID</c>. Refusing to answer because Redis is down would take the
    /// endpoint out over a protective counter.
    /// </para>
    /// </summary>
    private async Task<AppException> RefuseAsync(
        CaptchaVerificationContext context,
        string deviceHash,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (_options.CaptchaFailThreshold == 0 || deviceHash.Length == 0)
        {
            return Invalid();
        }

        var tripped = !(await rateLimiter
            .TryAcquireAsync(CaptchaFailDeviceDimension, context.DeviceId, CaptchaFailPolicy, cancellationToken)
            .ConfigureAwait(false)).Allowed;

        if (!tripped)
        {
            return Invalid();
        }

        logger.LogWarning(
            "{Threshold} consecutive CAPTCHA assessments failed on platform {Platform}; the calling "
            + "device is cooled down for {Cooldown} rather than being asked to solve another.",
            _options.CaptchaFailThreshold,
            context.Platform,
            _options.CooldownDuration);

        await WriteCooldownAsync(DeviceDimension, deviceHash, now + _options.CooldownDuration).ConfigureAwait(false);

        // The failure counter is cleared with the cooldown so that the cooldown is served once
        // rather than re-armed by the first attempt after it lifts.
        await ClearCaptchaFailureCountersAsync(context).ConfigureAwait(false);

        return Cooled(_options.CooldownDuration);
    }

    /// <summary>
    /// 400, and the same sentence whatever the provider objected to. The caller's only move is to
    /// solve another challenge, and which of the three checks failed is information only an
    /// attacker benefits from.
    /// </summary>
    private static BadRequestException Invalid() => new(
        ErrorCodes.CaptchaInvalid,
        "The verification challenge could not be confirmed. Complete it again.");

    /// <summary>429 with <c>Retry-After</c>: here waiting genuinely is the remedy, and the header
    /// says how long. It carries what the Go contract returned as a <c>cooldown_seconds</c> detail
    /// member.</summary>
    private static RateLimitedException Cooled(TimeSpan retryAfter) => new(
        ErrorCodes.RiskControlCooldown,
        "Too many attempts. Try again shortly.",
        retryAfter);

    // ---------------------------------------------------------------- Redis state

    private async Task<DateTimeOffset?> ReadCooldownAsync(string dimension, string hash)
    {
        try
        {
            var value = await Database.StringGetAsync(CooldownKey(dimension, hash)).ConfigureAwait(false);

            if (value.IsNullOrEmpty)
            {
                return null;
            }

            // Unparseable means a key this build did not write. Treating it as "no cooldown" is the
            // fail-open direction and costs at most one extra send; treating it as an active
            // cooldown of unknown length would refuse a caller for a reason nobody can see.
            if (!long.TryParse(
                    value.ToString(),
                    NumberStyles.Integer,
                    CultureInfo.InvariantCulture,
                    out var unixSeconds)
                || unixSeconds < 0
                || unixSeconds > 253_402_300_799)
            {
                return null;
            }

            return DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
        }
        catch (Exception ex) when (IsRedisFailure(ex))
        {
            // Warning per affected request, on purpose: the rate of these lines is what tells an
            // operator how much traffic is currently skipping the cooldown check.
            logger.LogWarning(
                ex,
                "The risk-control cooldown for dimension {Dimension} could not be read; failing open "
                + "and treating the subject as not cooled down.",
                dimension);

            return null;
        }
    }

    private async Task WriteCooldownAsync(string dimension, string hash, DateTimeOffset until)
    {
        // A plain overwrite rather than SET NX. A second trigger during an existing cooldown cannot
        // happen - the cooldown is checked before anything is counted - so the only writer is the
        // one that just decided, and it should win.
        var value = until.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);

        await BestEffortAsync(
            () => Database.StringSetAsync(
                CooldownKey(dimension, hash),
                value,
                expiry: _options.CooldownDuration,
                keepTtl: false,
                when: When.Always,
                flags: CommandFlags.None),
            $"write the risk-control cooldown for dimension {dimension}").ConfigureAwait(false);
    }

    private async Task<bool> HasPassedCaptchaAsync(string targetHash)
    {
        try
        {
            return await Database.KeyExistsAsync(PassedKey(targetHash)).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsRedisFailure(ex))
        {
            // Fail-open towards the *milder* answer: "has not passed" produces CaptchaRequired,
            // which a real user can clear, rather than a five-minute cooldown they cannot.
            logger.LogWarning(
                ex,
                "The risk-control captcha-passed marker could not be read; treating the subject as "
                + "not having passed, which asks for a challenge rather than cooling it down.");

            return false;
        }
    }

    private Task MarkCaptchaPassedAsync(string targetHash) => BestEffortAsync(
        () => Database.StringSetAsync(
            PassedKey(targetHash),
            PassedMarker,
            expiry: _options.CaptchaPassedTtl,
            keepTtl: false,
            when: When.Always,
            flags: CommandFlags.None),
        "mark the subject as having passed a captcha");

    /// <summary>
    /// The one write in this class that throws.
    /// <para>
    /// A token that was minted but not stored is a credential the caller cannot spend: they would
    /// see a success, replay it at the send endpoint, and be told their CAPTCHA was invalid - with
    /// nothing anywhere to explain why. 502 rather than 500 because the failure is Redis, the same
    /// call the revocation set's write path makes for the same reason.
    /// </para>
    /// </summary>
    private async Task StoreTokenAsync(string token, string binding)
    {
        try
        {
            var stored = await Database.StringSetAsync(
                TokenKey(token),
                binding,
                expiry: _options.CaptchaTokenTtl,
                keepTtl: false,
                when: When.Always,
                flags: CommandFlags.None).ConfigureAwait(false);

            if (stored)
            {
                return;
            }
        }
        catch (Exception ex) when (IsRedisFailure(ex))
        {
            throw TokenNotStored(ex);
        }

        throw TokenNotStored(null);
    }

    private UpstreamException TokenNotStored(Exception? cause)
    {
        logger.LogError(
            cause,
            "A CAPTCHA was solved but its one-time token could not be stored, so no usable token "
            + "can be returned.");

        return new UpstreamException(
            ErrorCodes.UpstreamUnavailable,
            "The verification challenge was solved, but the result could not be saved. Try again.",
            cause);
    }

    /// <summary>
    /// Clears the send counters after a redemption, so the caller who just proved they are human is
    /// not challenged again by the same window they had already filled.
    /// <para>
    /// <b>It deletes the limiter's own keys, by asking the limiter's adapter how they are spelled.</b>
    /// <see cref="IRateLimiter"/> has no reset - it is a counter, not a budget anyone can refund -
    /// and adding one to the port for this single caller would put a "clear the evidence" method on
    /// every rate limit in the service. Reaching for <see cref="RedisRateLimiter.BuildKey"/> keeps
    /// the layout defined in exactly one place; if the limiter is ever backed by something other
    /// than Redis, this stops working and the cost is one extra challenge, which is why it is
    /// best-effort rather than load-bearing.
    /// </para>
    /// </summary>
    private async Task ClearSendCodeCountersAsync(SendCodeRiskContext context)
    {
        var window = _options.SendCodeWindow;

        await DeleteCounterAsync(SendCodeTargetDimension, context.Target, window).ConfigureAwait(false);

        if (!string.IsNullOrWhiteSpace(context.DeviceId))
        {
            await DeleteCounterAsync(SendCodeDeviceDimension, context.DeviceId, window).ConfigureAwait(false);
        }
    }

    /// <summary>Clears the failed-assessment counter. A success ends the streak; only consecutive
    /// failures should accumulate towards a cooldown. Device-only, like the counter itself.</summary>
    private async Task ClearCaptchaFailureCountersAsync(CaptchaVerificationContext context)
    {
        if (_options.CaptchaFailThreshold == 0 || string.IsNullOrWhiteSpace(context.DeviceId))
        {
            return;
        }

        await DeleteCounterAsync(CaptchaFailDeviceDimension, context.DeviceId, _options.CooldownDuration)
            .ConfigureAwait(false);
    }

    private Task DeleteCounterAsync(string dimension, string subject, TimeSpan window) => BestEffortAsync(
        () => Database.KeyDeleteAsync(RedisRateLimiter.BuildKey(_keyPrefix, dimension, subject, window)),
        $"clear the risk-control counter for dimension {dimension}");

    /// <summary>
    /// Runs a write whose loss costs at most one extra challenge. It swallows Redis failures on
    /// purpose - every caller of this is on a path where the decision has already been made and
    /// returned, and turning a bookkeeping write into a 502 there would fail a request that
    /// succeeded.
    /// </summary>
    private async Task BestEffortAsync<T>(Func<Task<T>> operation, string description)
    {
        try
        {
            await operation().ConfigureAwait(false);
        }
        catch (Exception ex) when (IsRedisFailure(ex))
        {
            logger.LogWarning(ex, "Risk control could not {Description}; continuing without it.", description);
        }
    }

    // ---------------------------------------------------------------- Keys and hashing

    private string CooldownKey(string dimension, string hash) => $"{_keyPrefix}riskctl:cooldown:{dimension}:{hash}";

    private string PassedKey(string targetHash) => $"{_keyPrefix}riskctl:captcha-passed:{targetHash}";

    /// <summary>
    /// The token's key is the digest of the token, so what Redis holds is a hash and not the
    /// credential itself: a key-space dump, a slowlog entry or a replica snapshot then contains
    /// nothing that can be replayed. The plaintext exists once, in the response.
    /// </summary>
    private string TokenKey(string token) => $"{_keyPrefix}riskctl:captcha-token:{HashSecret(token)}";

    /// <summary>
    /// What the token is bound to. The separator makes the two halves unambiguous, and both halves
    /// are fixed-length digests, so no target can be spelled to look like a different target plus a
    /// device.
    /// <para>
    /// An absent device binds to the empty half rather than to a wildcard: a token issued with no
    /// device id is redeemable only by a request that also has none.
    /// </para>
    /// </summary>
    private static string Bind(string targetHash, string deviceHash) => $"{targetHash}|{deviceHash}";

    /// <summary>
    /// Normalizes before hashing - trim and lowercase - so <c>" User@Example.com "</c> and
    /// <c>"user@example.com"</c> are one subject. It is the same normalization
    /// <see cref="RedisRateLimiter"/> applies to a limiter subject, which is what keeps a token's
    /// binding and the counters it clears talking about the same person.
    /// </summary>
    private static string HashSubject(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value.Trim().ToLowerInvariant())));

    /// <summary>
    /// Hashes a machine-generated secret with <b>no</b> trimming and no case folding: it is compared
    /// for exact equality, and normalizing it would widen the set of strings that redeem a bypass.
    /// </summary>
    private static string HashSecret(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    /// <summary>
    /// The StackExchange.Redis hierarchy is not what it looks like: <c>RedisTimeoutException</c>
    /// derives from <see cref="TimeoutException"/> and <c>RedisCommandException</c> derives straight
    /// from <see cref="Exception"/>, so catching <c>RedisException</c> alone misses every timeout -
    /// which is precisely the failure these guards exist for.
    /// </summary>
    private static bool IsRedisFailure(Exception exception) =>
        exception is RedisException or RedisTimeoutException or RedisCommandException;

    /// <summary>
    /// Reads the script's integer reply. The conversion throws rather than returning null on an
    /// unexpected shape, and an unreadable reply must not become a 500 from the endpoint the gate is
    /// protecting - it becomes "not redeemed", which is the refusing answer.
    /// <para>
    /// It logs at <b>Error</b>, unlike every other guard in this class. The others catch outages,
    /// which fix themselves and are already visible as a rate of warnings; this one can only fire
    /// if <see cref="ConsumeTokenScript"/> stopped returning an integer, which is a defect in this
    /// file. Swallowing it silently would turn every redemption into a refusal - a CAPTCHA gate
    /// nobody can get through - with nothing anywhere to say why.
    /// </para>
    /// </summary>
    private bool TryReadLong(RedisResult reply, out long value)
    {
        try
        {
            value = (long)reply;
            return true;
        }
        catch (InvalidCastException ex)
        {
            logger.LogError(
                ex,
                "The CAPTCHA token script returned a reply that is not an integer, so no token can "
                + "be redeemed. This is a defect in the script, not a Redis outage.");

            value = 0;
            return false;
        }
    }
}
