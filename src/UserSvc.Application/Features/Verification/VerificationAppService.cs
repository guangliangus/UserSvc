using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Accounts;
using UserSvc.Application.Features.Registration;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;
using UserSvc.Application.Ports.Verification;
using UserSvc.Application.Security;
using UserSvc.Domain.Verification;

namespace UserSvc.Application.Features.Verification;

/// <summary>
/// Sending a verification code and exchanging it for a ticket - the front door of every flow that
/// has to prove someone controls a phone number or a mailbox.
/// <para>
/// <b>The order of the checks in <see cref="SendVerificationCodeAsync"/> is the design.</b> The
/// per-IP budget is spent first, before anything is parsed, so a flood costs the attacker a request
/// and costs us nothing. Payload validation comes next, so risk control is never asked to reason
/// about a target that is not even a phone number. Risk control comes before the purpose
/// precondition, so an attacker enumerating addresses is throttled before the lookup that would
/// tell them whether an address exists. Only then does anything touch the database.
/// </para>
/// <para>
/// <b>Two of the purpose preconditions are an enumeration oracle and are known to be one.</b>
/// <c>reset_password</c> answers <c>UNREGISTERED</c> for an address nobody has registered and
/// <c>bind</c> answers <c>IDENTITY_ALREADY_BOUND</c> for one that is taken, so a patient caller can
/// map the user base one address at a time. They are kept because they are the contract the mobile
/// clients branch on today, and because removing them without also removing the same signal from
/// the register and bind endpoints would buy nothing. What stands between that oracle and a scraped
/// user base is the throttling above, which is why it runs first. Closing it properly means one
/// uniform "if that address is registered, a code is on its way" answer across every flow that
/// takes an address - a contract change for every client, tracked separately.
/// </para>
/// <para>
/// <b><c>backoffice_reset_password</c> is deliberately not the third one.</b> It is the newest of
/// the purposes, it has no client branching on it yet, and the plane it asks about is the operator
/// directory rather than the customer base - so it answers the uniform sentence instead: a target
/// with no back-office account, or one whose account is disabled, gets the same 200 and the same
/// <see cref="SentMessage"/> as an eligible one, and no code is issued or mailed. The reasoning,
/// and the two channels that still separate the cases (elapsed time, and a notification outage
/// turning an eligible target into a 502), are in
/// <see cref="BackOfficeResetTargetGate"/> and in docs/architecture.md.
/// </para>
/// </summary>
public sealed class VerificationAppService(
    IVerificationCodeRepository codes,
    IUserIdentityRepository identities,
    INotificationClient notifications,
    IRateLimiter rateLimiter,
    IRiskControlService riskControl,
    BackOfficeResetTargetGate backOfficeResetTargets,
    IdentifierProtector protector,
    IUnitOfWork unitOfWork,
    IClock clock,
    IOptions<VerificationOptions> options,
    ILogger<VerificationAppService> logger)
{
    /// <summary>
    /// The one place the per-IP send budget is charged. It is a name, not a key: the adapter owns
    /// the key layout, and nothing outside it depends on the spelling.
    /// </summary>
    private const string SendRateLimitDimension = "verification-send-ip";

    /// <summary>
    /// The bucket a request whose client address could not be determined is charged to. It is a
    /// literal rather than the empty string because the limiter rejects a blank subject, and
    /// because a named bucket is greppable in the key space when someone asks why one counter is
    /// hot.
    /// </summary>
    private const string UnknownClient = "unknown-client";

    /// <summary>Prefix of every verification ticket, so a value found in a log or a bug report is
    /// recognisable for what it is.</summary>
    private const string TicketPrefix = "vft_";

    /// <summary>The fixed code issued when <see cref="VerificationOptions.UseMockCode"/> is on.</summary>
    private const string MockCode = "123456";

    /// <summary>
    /// Deliberately the same sentence whatever happened: it must not differ between an address that
    /// exists and one that does not, or between a delivered message and one the provider dropped.
    /// </summary>
    private const string SentMessage = "Verification code sent successfully";

    /// <summary>
    /// Read at the point of use, never in a field initializer (docs/architecture.md: "a missing
    /// capability may only break itself"). A field initializer runs during construction, and
    /// <see cref="IOptions{TOptions}.Value"/> is where DataAnnotations validation runs - so
    /// binding it into a field makes merely constructing this service throw, and both verification
    /// routes plus every flow that consumes a ticket sit on it.
    /// <see cref="IOptions{TOptions}.Value"/> caches, so the property costs nothing per call.
    /// </summary>
    private VerificationOptions _options => options.Value;

    /// <summary>
    /// Issue a code for the target and deliver it. See the class remarks for why the checks run in
    /// this order.
    /// </summary>
    public async Task<SendVerificationCodeResponse> SendVerificationCodeAsync(
        SendVerificationCodeRequest request,
        VerificationRequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(context);

        await ChargeSendBudgetAsync(context, cancellationToken);
        VerificationRequestRules.Validate(request);
        await ApplyRiskControlAsync(request, context, cancellationToken);

        if (await EnsureTargetSuitsPurposeAsync(request, cancellationToken) == SendVerdict.AnswerAsIfIssued)
        {
            // The uniform answer: byte-identical to a real one, including a deadline the client can
            // count down, because a response that differed in any field would be the oracle this
            // branch exists to close. Nothing is written and nothing is mailed - the budget and the
            // risk-control counters above have already been charged, so probing still costs the
            // caller what a real send costs.
            return new SendVerificationCodeResponse
            {
                Message = SentMessage,
                ExpiresAt = clock.UtcNow + _options.CodeExpires,
            };
        }

        var code = GenerateCode();

        // The transaction spans one repository call because that call is two statements: retiring
        // the previous live code and inserting this one. Committing only the first would leave the
        // target with no usable code and no way to tell.
        //
        // The issue instant is read INSIDE the body, not before it, because the unit of work
        // replays the body when PostgreSQL reports a transient failure. Measured once outside, a
        // retry landing seconds later would store a deadline taken from the first attempt - and
        // with CodeExpires at its 30-second floor the retry could hand the repository a code that
        // is already dead, failing the send with an expiry error about a code nobody has seen. The
        // deadline the caller is told is therefore the one the surviving attempt actually wrote.
        var codeId = 0;
        var expiresAt = default(DateTimeOffset);

        await unitOfWork.ExecuteInTransactionAsync(
            async token =>
            {
                var issuedAt = clock.UtcNow;
                expiresAt = issuedAt + _options.CodeExpires;

                codeId = await codes.CreateAsync(
                    new NewVerificationCode(
                        request.Target,
                        context.DeviceId,
                        request.Purpose,
                        code,
                        expiresAt,
                        issuedAt),
                    token);
            },
            cancellationToken);

        await DeliverAsync(request, code, codeId, cancellationToken);

        return new SendVerificationCodeResponse { Message = SentMessage, ExpiresAt = expiresAt };
    }

    /// <summary>
    /// Exchange a correct code for a verification ticket.
    /// <para>
    /// <b>There is no throttle on this path, and that is a faithful port rather than an oversight.</b>
    /// The spec (02-verification-codes, section 4.2) states plainly that <c>/verify</c> carries no
    /// per-IP rate limit and no risk control - only <c>/send</c> and <c>/captcha/verify</c> do - so
    /// what bounds a brute force here is the code itself, not a counter. The bounds, exactly:
    /// <list type="bullet">
    /// <item><b>Entropy:</b> six decimal digits, one of 1,000,000 values, about 19.9 bits.</item>
    /// <item><b>One live code:</b> <see cref="SendVerificationCodeAsync"/> retires every prior live
    /// code for the target and purpose, so an attacker faces exactly one valid code at a time - a
    /// fresh send does not add a second, it replaces the first.</item>
    /// <item><b>A hard time ceiling:</b> the candidate lookup requires <c>expires_at &gt; now</c>, so
    /// the code is unguessable after <c>CodeExpires</c> (default five minutes); the window does not
    /// reopen without a new send delivering a new code to the victim.</item>
    /// <item><b>No attempt counter:</b> a wrong guess does not retire the row - the conditional
    /// UPDATE fires only on a match - and nothing counts misses, so guesses are limited only by the
    /// caller's request throughput.</item>
    /// </list>
    /// So an attacker who can trigger one send to a victim gets, within that five-minute window,
    /// guesses ≈ throughput × 300 s out of 1,000,000, and success probability ≈ that many over a
    /// million: about 500,000 distinct guesses (~1,700 req/s sustained) for a coin flip, ~167 req/s
    /// for a 5% chance. That is a real online-guessing oracle for a well-resourced attacker, not a
    /// trivial one - the five-minute ceiling and the single live code are the whole defence.
    /// </para>
    /// <para>
    /// Closing it means a per-target attempt budget on this endpoint, keyed on the target rather
    /// than the caller's address (an attacker rotates addresses; the victim's mailbox does not
    /// move). It is deliberately not added here: it introduces a 429 on a path the clients and the
    /// two auth slices were written against, and a naive per-target counter hands an attacker a
    /// cheap way to block a victim's own reset. That trade needs the client-contract owner's
    /// decision (tracked alongside the enumeration oracles in docs/architecture.md), not a
    /// unilateral edit during a port.
    /// </para>
    /// </summary>
    public async Task<VerifyCodeResponse> VerifyCodeAsync(
        VerifyCodeRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        VerificationRequestRules.Validate(request);

        var ticket = GenerateTicket();
        var ticketExpiresAt = clock.UtcNow + _options.TicketTtl;

        // A transaction because the repository reads the candidate row and then updates it under a
        // condition; without one, the read and the guard could straddle another verify's commit.
        await unitOfWork.ExecuteInTransactionAsync(
            token => codes.VerifyCodeAndIssueTicketAsync(
                request.Target, request.Purpose, request.Code, ticket, ticketExpiresAt, token),
            cancellationToken);

        return new VerifyCodeResponse { Verified = true, VerificationTicket = ticket };
    }

    /// <summary>
    /// Spend one token from the per-minute budget and, only if that call allowed the request, one
    /// from the per-hour budget.
    /// <para>
    /// <b>Stopping at the first refusal is what <see cref="IRateLimiter"/> requires of a caller
    /// holding several policies, and the reason is not tidiness.</b> Every call counts whether or
    /// not the request is served, so charging the hour window after the minute window has already
    /// refused bills the caller for requests it never received an answer to. A client retrying
    /// into a one-minute block would spend its entire hourly allowance on refusals and turn a
    /// one-minute throttle into an hour-long one - and the client that suffers most is the polite
    /// one retrying on a timer.
    /// </para>
    /// </summary>
    private async Task ChargeSendBudgetAsync(VerificationRequestContext context, CancellationToken cancellationToken)
    {
        // The adapter refuses a blank subject outright, so a request whose peer address the server
        // could not determine would leave as a 500 raised by the one component whose entire design
        // is to fail open. One named bucket instead: those callers share a budget, which is the
        // safe direction and the one VerificationRequestContext.ClientIp promises.
        var client = string.IsNullOrWhiteSpace(context.ClientIp) ? UnknownClient : context.ClientIp;

        var perMinute = await rateLimiter.TryAcquireAsync(
            SendRateLimitDimension,
            client,
            RateLimitPolicy.PerMinute(_options.SendPerIpPerMinute),
            cancellationToken);

        if (!perMinute.Allowed)
        {
            throw Refuse(client, perMinute.RetryAfter);
        }

        var perHour = await rateLimiter.TryAcquireAsync(
            SendRateLimitDimension,
            client,
            RateLimitPolicy.PerHour(_options.SendPerIpPerHour),
            cancellationToken);

        if (!perHour.Allowed)
        {
            throw Refuse(client, perHour.RetryAfter);
        }
    }

    /// <summary>The same refusal whichever window ran out, because the client can do only one thing
    /// about either: wait for as long as <c>Retry-After</c> says.</summary>
    private RateLimitedException Refuse(string client, TimeSpan retryAfter)
    {
        logger.LogWarning(
            "Verification send refused for client {ClientIp}: the per-IP budget is spent, retry in {RetryAfter}.",
            client,
            retryAfter);

        return new RateLimitedException(
            ErrorCodes.RateLimitExceeded,
            "Too many verification codes have been requested from this address. Try again later.",
            retryAfter);
    }

    /// <summary>
    /// Account- and device-level throttling, which is a different question from the per-IP budget
    /// above: that one bounds a host, this one bounds how often one phone number or one device can
    /// be targeted from anywhere.
    /// <para>
    /// A captcha token short-circuits the check, but only after the risk-control service confirms
    /// it was issued for this same target and device - otherwise one solved captcha would be a
    /// reusable bypass for every address.
    /// </para>
    /// </summary>
    private async Task ApplyRiskControlAsync(
        SendVerificationCodeRequest request,
        VerificationRequestContext context,
        CancellationToken cancellationToken)
    {
        var subject = new SendCodeRiskContext(request.Target, request.TargetType, context.DeviceId);

        if (!string.IsNullOrWhiteSpace(request.CaptchaToken))
        {
            if (await riskControl.TryConsumeCaptchaTokenAsync(request.CaptchaToken, subject, cancellationToken))
            {
                return;
            }

            throw new BadRequestException(
                ErrorCodes.CaptchaInvalid,
                "The verification challenge could not be confirmed. Complete it again.");
        }

        var decision = await riskControl.EvaluateSendCodeAsync(subject, cancellationToken);

        switch (decision.Action)
        {
            case SendCodeRiskDecision.RiskAction.Allow:
                return;

            // 403 rather than 429: repeating this exact request will never succeed, however long
            // the caller waits. What unblocks it is a different request - one carrying a captcha
            // token - and 429 would promise the opposite.
            case SendCodeRiskDecision.RiskAction.CaptchaRequired:
                throw new ForbiddenException(
                    ErrorCodes.CaptchaRequired,
                    "Too many attempts. Complete the verification challenge to continue.");

            // 429 with Retry-After: here waiting genuinely is the remedy, and the header says how
            // long. It carries what the original returned as a cooldown_seconds detail member.
            case SendCodeRiskDecision.RiskAction.Cooldown:
                throw new RateLimitedException(
                    ErrorCodes.RiskControlCooldown,
                    "Too many attempts. Try again shortly.",
                    decision.RetryAfter);

            default:
                throw new AppException(
                    ErrorCodes.InternalError,
                    "The request could not be completed.",
                    500);
        }
    }

    /// <summary>
    /// What the purpose precondition decided. A third state beside "proceed" and "throw", because
    /// one purpose refuses a target <b>without saying so</b>: the caller is told the same thing a
    /// successful send tells them, and this is how the send path learns to skip the work while
    /// still answering that way.
    /// </summary>
    private enum SendVerdict
    {
        /// <summary>Issue a code and deliver it.</summary>
        Issue = 0,

        /// <summary>Issue nothing, deliver nothing, and answer exactly as if both had happened.</summary>
        AnswerAsIfIssued = 1,
    }

    /// <summary>
    /// Each purpose owns its precondition, and the two identity planes are physically separate
    /// tables that must never gate each other.
    /// <para>
    /// The auth purposes check nothing at all: registration and code login share them, so at send
    /// time we cannot know whether the target is supposed to exist - and refusing an unknown target
    /// would break registration.
    /// </para>
    /// <para>
    /// Two of them refuse out loud and one refuses silently; which is which, and why, is the class
    /// remarks' second and third paragraphs.
    /// </para>
    /// </summary>
    private async Task<SendVerdict> EnsureTargetSuitsPurposeAsync(
        SendVerificationCodeRequest request,
        CancellationToken cancellationToken)
    {
        switch (request.Purpose)
        {
            case VerificationPurposes.Auth:
            case VerificationPurposes.BackOfficeAuth:
                return SendVerdict.Issue;

            case VerificationPurposes.ResetPassword:
                if (await FindIdentityAsync(request, cancellationToken) is null)
                {
                    throw new BadRequestException(
                        ErrorCodes.Unregistered,
                        "That email address or phone number is not registered.");
                }

                return SendVerdict.Issue;

            case VerificationPurposes.Bind:
                if (await FindIdentityAsync(request, cancellationToken) is not null)
                {
                    throw new ConflictException(
                        ErrorCodes.IdentityAlreadyBound,
                        "That email address or phone number is already linked to an account.");
                }

                return SendVerdict.Issue;

            case VerificationPurposes.BackOfficeResetPassword:
                return await DecideBackOfficeResetAsync(request, cancellationToken);

            default:
                throw new BadRequestException(
                    ErrorCodes.BadRequest,
                    "The verification purpose is not one this service issues codes for.");
        }
    }

    /// <summary>
    /// The back-office plane's precondition: the same gate the reset submission runs, asked in the
    /// form that does not answer the caller.
    /// <para>
    /// A target that could not complete a reset gets <see cref="SendVerdict.AnswerAsIfIssued"/>
    /// rather than <c>UNREGISTERED</c> or <c>ACCOUNT_DISABLED</c> - see
    /// <see cref="BackOfficeResetTargetGate"/> for why this plane in particular must not answer
    /// that question to a stranger. A target that is not an address at all is still refused
    /// outright by the gate, because that verdict comes from the string rather than from the
    /// directory.
    /// </para>
    /// <para>
    /// <b>The log line is the only trace, and it is the point.</b> Silence towards the caller means
    /// support has nothing to go on when an operator reports that no mail arrived, so the masked
    /// address and the reason are recorded here - at Information, because a mistyped address is a
    /// normal event and a stream of warnings would train people to ignore it.
    /// </para>
    /// </summary>
    private async Task<SendVerdict> DecideBackOfficeResetAsync(
        SendVerificationCodeRequest request,
        CancellationToken cancellationToken)
    {
        var verdict = await backOfficeResetTargets.EvaluateAsync(request.Target, cancellationToken);

        if (verdict.Eligibility == BackOfficeResetEligibility.Eligible)
        {
            return SendVerdict.Issue;
        }

        logger.LogInformation(
            "A back-office password reset was requested for {MaskedTarget}, which is {Eligibility}. "
            + "No code was sent and the caller was told the same thing an eligible address is told.",
            verdict.MaskedTarget,
            verdict.Eligibility);

        return SendVerdict.AnswerAsIfIssued;
    }

    /// <summary>
    /// Look the target up as an active login identity.
    /// <para>
    /// <b>It normalizes through <see cref="IdentifierNormalizer"/>, not through
    /// <see cref="VerificationHashing.HashTarget"/></b>, and the difference is deliberate: this
    /// query has to find the row registration wrote, so it must spell the identifier exactly the
    /// way registration spelled it. The code row's own hash uses the looser trim-and-lowercase
    /// rule, which is self-consistent across send, verify and consume and is never compared with
    /// an identity row. Blurring the two would make a bind check silently miss an account that
    /// exists.
    /// </para>
    /// </summary>
    private Task<Domain.Users.UserIdentity?> FindIdentityAsync(
        SendVerificationCodeRequest request,
        CancellationToken cancellationToken)
    {
        var identityType = IdentifierNormalizer.ResolveIdentityType(request.TargetType);
        var identifier = IdentifierNormalizer.Normalize(identityType, request.Target);

        return identities.FindActiveAsync(identityType, protector.Hash(identifier), cancellationToken);
    }

    /// <summary>
    /// Six digits from a cryptographic source, drawn without modulo bias - the original folded a
    /// 24-bit sample into a million buckets, which made a handful of codes marginally likelier than
    /// the rest. Nothing observable depends on that, so it is not reproduced.
    /// </summary>
    private string GenerateCode() => _options.UseMockCode
        ? MockCode
        : RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6", CultureInfo.InvariantCulture);

    /// <summary>256 bits of entropy, base64url without padding. The ticket is a bearer credential
    /// for the flow it unlocks, so it is sized like one.</summary>
    private static string GenerateTicket() =>
        TicketPrefix + Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

    /// <summary>
    /// Hand the code to the notification service, or - for a phone - record that we did not.
    /// <para>
    /// SMS is the notification service's job now and this service no longer talks to an SMS vendor.
    /// Until the SMS notification types exist upstream, the row is still written, so mock-code and
    /// test flows keep working, but nothing is actually sent. The caller is told the send succeeded,
    /// which is the one thing here that is a lie and the reason for the warning log.
    /// </para>
    /// </summary>
    private async Task DeliverAsync(
        SendVerificationCodeRequest request,
        string code,
        int codeId,
        CancellationToken cancellationToken)
    {
        if (request.TargetType != VerificationTargetTypes.Email)
        {
            logger.LogWarning(
                "SMS verification code delivery is not implemented; no message was sent to {MaskedTarget}.",
                Mask(request.Target));
            return;
        }

        var notification = new SendDirectRequest(
            NotificationTypeFor(request.Purpose),
            [request.Target],
            new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["code"] = code,
                ["minute"] = MinuteVariable(),
            },
            $"email-vc:{request.Purpose}:{codeId}");

        try
        {
            await notifications.SendDirectAsync(notification, cancellationToken);
        }
        catch (AppException ex)
        {
            // The status is kept exactly as the adapter decided it - 502 when the notification
            // service is down, 500 when it rejected a payload that is our bug - because that split
            // is what points the alert at the right team. Only the error code is swapped, so
            // clients see one code for "the code did not go out" whichever side was at fault.
            throw new AppException(
                ErrorCodes.SendFailed,
                "The verification code could not be sent. Try again in a moment.",
                ex.StatusCode,
                ex);
        }
    }

    /// <summary>
    /// The code's lifetime as a whole number of minutes for the email template, floored at 1.
    /// A sub-minute lifetime is legal configuration and would otherwise render as "0 minutes",
    /// which reads as broken; saying 1 overstates it by less than a minute.
    /// </summary>
    private string MinuteVariable()
    {
        var minutes = (int)_options.CodeExpires.TotalMinutes;
        if (minutes >= 1)
        {
            return minutes.ToString(CultureInfo.InvariantCulture);
        }

        logger.LogWarning(
            "The verification code TTL {CodeExpires} is under a minute; the email will still say one minute.",
            _options.CodeExpires);

        return "1";
    }

    /// <summary>
    /// Which email template the code goes out on. The back-office purposes get their own templates
    /// whose copy names the back-office account: someone holding both a consumer and a back-office
    /// account has to be able to tell which one a code is for, so the two planes never share one.
    /// </summary>
    private static string NotificationTypeFor(string purpose) => purpose switch
    {
        VerificationPurposes.Auth => "vc_login_email",
        VerificationPurposes.BackOfficeAuth => "backend_vc_auth_email",
        VerificationPurposes.ResetPassword => "vc_reset_pwd_email",
        VerificationPurposes.BackOfficeResetPassword => "backend_vc_reset_pwd_email",
        VerificationPurposes.Bind => "vc_bind_email",

        // Unreachable while validation and this map agree; it exists so that adding a purpose to
        // one and forgetting the other fails loudly instead of sending a blank template name.
        _ => throw new AppException(
            ErrorCodes.InternalError,
            "The verification code could not be sent.",
            500),
    };

    /// <summary>
    /// Enough of a phone number to recognise in a log line, not enough to be one. Personal data does
    /// not belong in logs, and a support engineer only ever needs to confirm which number a user is
    /// asking about.
    /// </summary>
    private static string Mask(string phone)
    {
        if (phone.Length < 4)
        {
            return phone;
        }

        var last4 = phone[^4..];
        if (phone.Length <= 7)
        {
            return "****" + last4;
        }

        var prefixLength = phone.StartsWith('+') ? 4 : 3;
        return phone[..prefixLength] + "****" + last4;
    }
}
