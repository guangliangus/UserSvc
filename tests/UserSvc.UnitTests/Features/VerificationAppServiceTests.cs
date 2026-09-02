using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Verification;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;
using UserSvc.Application.Ports.Verification;
using UserSvc.Domain.Users;
using UserSvc.Domain.Verification;
using Xunit;

namespace UserSvc.UnitTests.Features;

/// <summary>
/// The send and verify use cases with every port substituted - no database, no Redis, no HTTP.
/// <para>
/// The bulk of these cases are ports of the Go service's own tests, because those assertions are
/// the specification of the behaviour the mobile clients were written against. The rest cover the
/// decisions this port made that the original could not have: real HTTP status codes instead of an
/// envelope, and the per-IP budget moved into the use case where it can be tested at all.
/// </para>
/// </summary>
public sealed class VerificationAppServiceTests
{
    private const string Email = "user@example.com";

    private static readonly DateTimeOffset Now = new(2026, 9, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly VerificationRequestContext Context = new("203.0.113.7", "dev-1");

    private readonly IVerificationCodeRepository _codes = Substitute.For<IVerificationCodeRepository>();
    private readonly IUserIdentityRepository _identities = Substitute.For<IUserIdentityRepository>();
    private readonly INotificationClient _notifications = Substitute.For<INotificationClient>();
    private readonly IRateLimiter _rateLimiter = Substitute.For<IRateLimiter>();
    private readonly IRiskControlService _riskControl = Substitute.For<IRiskControlService>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();
    private readonly TestClock _clock = new(Now);

    private VerificationOptions _options = new();
    private SendDirectRequest? _sent;

    public VerificationAppServiceTests()
    {
        _rateLimiter
            .TryAcquireAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<RateLimitPolicy>(), Arg.Any<CancellationToken>())
            .Returns(new RateLimitDecision(true, 99, TimeSpan.Zero));

        _riskControl
            .EvaluateSendCodeAsync(Arg.Any<SendCodeRiskContext>(), Arg.Any<CancellationToken>())
            .Returns(SendCodeRiskDecision.Allow());

        // The real unit of work runs the delegate inside a transaction; here it just runs it, so
        // that a repository failure still surfaces the way the caller would see it.
        _unitOfWork
            .ExecuteInTransactionAsync(Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>())
            .Returns(call => ((Func<CancellationToken, Task>)call[0]).Invoke(CancellationToken.None));

        _notifications
            .SendDirectAsync(Arg.Do<SendDirectRequest>(request => _sent = request), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);
    }

    private VerificationAppService Sut => new(
        _codes,
        _identities,
        _notifications,
        _rateLimiter,
        _riskControl,
        TestProtector.Create(),
        _unitOfWork,
        _clock,
        Options.Create(_options),
        NullLogger<VerificationAppService>.Instance);

    // ------------------------------------------------------------------ sending

    [Fact]
    public async Task AnAuthCodeIsSentWithoutEverLookingTheTargetUp()
    {
        var response = await Sut.SendVerificationCodeAsync(SendRequest(), Context, CancellationToken.None);

        response.Message.ShouldBe("Verification code sent successfully");
        response.ExpiresAt.ShouldBe(Now + _options.CodeExpires);
        response.ExpiresAt.ShouldBeGreaterThan(Now);

        // Registration and code login share the auth purpose, so at send time we cannot know
        // whether the target is meant to exist - and refusing an unknown one would break signup.
        await _identities.DidNotReceive()
            .FindActiveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task APhoneCodeIsPersistedButNoMessageGoesOut()
    {
        var response = await Sut.SendVerificationCodeAsync(
            SendRequest(target: "+1234567890", targetType: VerificationTargetTypes.Phone),
            Context,
            CancellationToken.None);

        response.ExpiresAt.ShouldBe(Now + _options.CodeExpires);
        await _codes.Received(1).CreateAsync(Arg.Any<NewVerificationCode>(), Arg.Any<CancellationToken>());

        // SMS belongs to the notification service and its templates do not exist yet. The row is
        // still written so mock-code flows keep working.
        await _notifications.DidNotReceive().SendDirectAsync(Arg.Any<SendDirectRequest>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task TheRawTargetAndDeviceIdReachTheRepositoryUnhashed()
    {
        NewVerificationCode? created = null;
        _codes.CreateAsync(Arg.Do<NewVerificationCode>(code => created = code), Arg.Any<CancellationToken>())
            .Returns(1);

        await Sut.SendVerificationCodeAsync(SendRequest(), Context, CancellationToken.None);

        // Hashing lives in exactly one place, the adapter. If the use case hashed anything itself
        // the two sides could drift and the code would simply never be findable again.
        created.ShouldNotBeNull();
        created.Target.ShouldBe(Email);
        created.DeviceId.ShouldBe("dev-1");
        created.Purpose.ShouldBe(VerificationPurposes.Auth);
        created.Code.Length.ShouldBe(6);
        created.ExpiresAt.ShouldBe(Now + _options.CodeExpires);
        created.CreatedAt.ShouldBe(Now);
    }

    /// <summary>
    /// The real unit of work replays its body when PostgreSQL reports a transient failure. The
    /// deadline must therefore be measured on the attempt that survives, not on the first one -
    /// otherwise a retry stores a code whose life was already spent waiting for the retry, and with
    /// CodeExpires at its floor the row would be refused as born expired.
    /// </summary>
    [Fact]
    public async Task ARetriedTransactionMeasuresTheCodesLifeFromTheAttemptThatSurvives()
    {
        var written = new List<NewVerificationCode>();
        _codes.CreateAsync(Arg.Do<NewVerificationCode>(written.Add), Arg.Any<CancellationToken>()).Returns(1);

        _unitOfWork
            .ExecuteInTransactionAsync(Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>())
            .Returns(async call =>
            {
                var body = (Func<CancellationToken, Task>)call[0];
                await body(CancellationToken.None);
                _clock.Advance(TimeSpan.FromSeconds(45));
                await body(CancellationToken.None);
            });

        var response = await Sut.SendVerificationCodeAsync(SendRequest(), Context, CancellationToken.None);

        written.Count.ShouldBe(2);
        written[1].CreatedAt.ShouldBe(Now + TimeSpan.FromSeconds(45));
        written[1].ExpiresAt.ShouldBe(Now + TimeSpan.FromSeconds(45) + _options.CodeExpires);

        // And the caller is told the deadline that was actually stored.
        response.ExpiresAt.ShouldBe(written[1].ExpiresAt);
    }

    [Fact]
    public async Task AFailureToStoreTheCodeStopsTheSend()
    {
        _codes.CreateAsync(Arg.Any<NewVerificationCode>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new InvalidOperationException("db error"));

        await Should.ThrowAsync<InvalidOperationException>(
            () => Sut.SendVerificationCodeAsync(SendRequest(), Context, CancellationToken.None));

        // Nothing is sent for a code nobody could ever verify.
        await _notifications.DidNotReceive().SendDirectAsync(Arg.Any<SendDirectRequest>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task APasswordResetForAnUnregisteredTargetIsRefused()
    {
        _identities.FindActiveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((UserIdentity?)null);

        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.SendVerificationCodeAsync(
            SendRequest(purpose: VerificationPurposes.ResetPassword),
            Context,
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.Unregistered);
        ex.StatusCode.ShouldBe(400);
        await _codes.DidNotReceive().CreateAsync(Arg.Any<NewVerificationCode>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task BindingATargetThatIsAlreadyLinkedIsAConflict()
    {
        _identities.FindActiveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new UserIdentity { Id = 4, UserId = 7, Status = UserStatuses.Active });

        var ex = await Should.ThrowAsync<ConflictException>(() => Sut.SendVerificationCodeAsync(
            SendRequest(target: "taken@example.com", purpose: VerificationPurposes.Bind),
            Context,
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.IdentityAlreadyBound);
        ex.StatusCode.ShouldBe(409);
    }

    [Fact]
    public async Task AnUpstreamNotificationOutageIsReportedAsSendFailedWithoutBlamingTheCaller()
    {
        _notifications.SendDirectAsync(Arg.Any<SendDirectRequest>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new UpstreamException(ErrorCodes.UpstreamUnavailable, "notification center down"));

        var ex = await Should.ThrowAsync<AppException>(
            () => Sut.SendVerificationCodeAsync(SendRequest(), Context, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.SendFailed);
        ex.StatusCode.ShouldBe(502, "the notification service was down; that is not the caller's mistake");
        ex.InnerException.ShouldBeOfType<UpstreamException>();
    }

    [Fact]
    public async Task ARejectedNotificationPayloadStaysA500BecauseItIsOurBug()
    {
        _notifications.SendDirectAsync(Arg.Any<SendDirectRequest>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new AppException(ErrorCodes.InternalError, "unknown template", 500));

        var ex = await Should.ThrowAsync<AppException>(
            () => Sut.SendVerificationCodeAsync(SendRequest(), Context, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.SendFailed);
        ex.StatusCode.ShouldBe(500, "reporting our own malformed payload as 502 would page the wrong team");
    }

    [Fact]
    public async Task BackOfficePasswordResetSaysSoRatherThanClaimingTheAccountIsUnknown()
    {
        var ex = await Should.ThrowAsync<AppException>(() => Sut.SendVerificationCodeAsync(
            SendRequest(purpose: VerificationPurposes.BackOfficeResetPassword),
            Context,
            CancellationToken.None));

        ex.StatusCode.ShouldBe(501);
        ex.ErrorCode.ShouldBe(ErrorCodes.NotImplemented);
    }

    // ------------------------------------------------------- notification routing

    [Theory]
    [InlineData(VerificationPurposes.Auth, "vc_login_email", 42)]
    [InlineData(VerificationPurposes.BackOfficeAuth, "backend_vc_auth_email", 55)]
    [InlineData(VerificationPurposes.Bind, "vc_bind_email", 7)]
    public async Task EachPurposeRoutesToItsOwnEmailTemplate(string purpose, string template, int codeId)
    {
        // A back-office code must say "back-office account": someone holding both a consumer and a
        // back-office account has to be able to tell which one a code is for.
        _codes.CreateAsync(Arg.Any<NewVerificationCode>(), Arg.Any<CancellationToken>()).Returns(codeId);
        _identities.FindActiveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((UserIdentity?)null);

        await Sut.SendVerificationCodeAsync(
            SendRequest(purpose: purpose), Context, CancellationToken.None);

        _sent.ShouldNotBeNull();
        _sent.Type.ShouldBe(template);
        _sent.Recipients.ShouldBe([Email]);
        _sent.IdempotencyKey.ShouldBe($"email-vc:{purpose}:{codeId}");
    }

    [Fact]
    public async Task APasswordResetForARegisteredTargetRoutesToTheResetTemplate()
    {
        _identities.FindActiveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new UserIdentity { Id = 9, UserId = 3, Status = UserStatuses.Active });
        _codes.CreateAsync(Arg.Any<NewVerificationCode>(), Arg.Any<CancellationToken>()).Returns(99);

        await Sut.SendVerificationCodeAsync(
            SendRequest(purpose: VerificationPurposes.ResetPassword),
            Context,
            CancellationToken.None);

        _sent.ShouldNotBeNull();
        _sent.Type.ShouldBe("vc_reset_pwd_email");
        _sent.IdempotencyKey.ShouldBe("email-vc:reset_password:99");
    }

    [Fact]
    public async Task TheTemplateGetsTheCodeAndItsLifetimeInWholeMinutes()
    {
        await Sut.SendVerificationCodeAsync(SendRequest(), Context, CancellationToken.None);

        _sent.ShouldNotBeNull();
        _sent.Variables["minute"].ShouldBe("5");
        _sent.Variables["code"].ShouldBeOfType<string>().Length.ShouldBe(6);
    }

    [Theory]
    [InlineData(30)]
    [InlineData(90)]
    public async Task ASubMinuteOrRaggedLifetimeStillReadsAsOneMinute(int seconds)
    {
        // Truncation would render 90 seconds as "1" and 30 seconds as "0 minutes", which reads as
        // broken. Saying one minute overstates the shorter case by less than a minute.
        _options = new VerificationOptions { CodeExpires = TimeSpan.FromSeconds(seconds) };

        await Sut.SendVerificationCodeAsync(SendRequest(), Context, CancellationToken.None);

        _sent.ShouldNotBeNull();
        _sent.Variables["minute"].ShouldBe("1");
    }

    [Fact]
    public async Task TheMockCodeIsIssuedVerbatimWhenItIsTurnedOn()
    {
        _options = new VerificationOptions { UseMockCode = true };

        await Sut.SendVerificationCodeAsync(SendRequest(), Context, CancellationToken.None);

        _sent.ShouldNotBeNull();
        _sent.Variables["code"].ShouldBe("123456");
    }

    // ------------------------------------------------------------ abuse controls

    [Fact]
    public async Task ASpentPerIpBudgetRefusesBeforeAnythingIsParsedOrLookedUp()
    {
        _rateLimiter
            .TryAcquireAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<RateLimitPolicy>(), Arg.Any<CancellationToken>())
            .Returns(new RateLimitDecision(false, 0, TimeSpan.FromSeconds(30)));

        var ex = await Should.ThrowAsync<RateLimitedException>(() => Sut.SendVerificationCodeAsync(
            SendRequest(target: "not-an-email"), Context, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RateLimitExceeded);
        ex.StatusCode.ShouldBe(429);
        ex.RetryAfter.ShouldBe(TimeSpan.FromSeconds(30));

        // A flood costs the attacker a request and costs us nothing: no validation, no lookup.
        await _riskControl.DidNotReceive()
            .EvaluateSendCodeAsync(Arg.Any<SendCodeRiskContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnAllowedSendIsChargedToBothPerIpWindows()
    {
        await Sut.SendVerificationCodeAsync(SendRequest(), Context, CancellationToken.None);

        await _rateLimiter.Received(1).TryAcquireAsync(
            Arg.Any<string>(),
            Context.ClientIp,
            Arg.Is<RateLimitPolicy>(p => p.Window == TimeSpan.FromMinutes(1) && p.Limit == 100),
            Arg.Any<CancellationToken>());

        await _rateLimiter.Received(1).TryAcquireAsync(
            Arg.Any<string>(),
            Context.ClientIp,
            Arg.Is<RateLimitPolicy>(p => p.Window == TimeSpan.FromHours(1) && p.Limit == 500),
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The hour window must not be charged for a request the minute window already refused.
    /// Otherwise a client retrying into a one-minute block spends its whole hourly allowance on
    /// answers it never got, and a one-minute throttle silently becomes an hour-long one.
    /// </summary>
    [Fact]
    public async Task AMinuteWindowRefusalDoesNotAlsoSpendTheHourlyBudget()
    {
        _rateLimiter
            .TryAcquireAsync(
                Arg.Any<string>(),
                Arg.Any<string>(),
                Arg.Is<RateLimitPolicy>(p => p.Window == TimeSpan.FromMinutes(1)),
                Arg.Any<CancellationToken>())
            .Returns(new RateLimitDecision(false, 0, TimeSpan.FromSeconds(42)));

        var ex = await Should.ThrowAsync<RateLimitedException>(() => Sut.SendVerificationCodeAsync(
            SendRequest(), Context, CancellationToken.None));

        ex.RetryAfter.ShouldBe(TimeSpan.FromSeconds(42));

        await _rateLimiter.DidNotReceive().TryAcquireAsync(
            Arg.Any<string>(),
            Arg.Any<string>(),
            Arg.Is<RateLimitPolicy>(p => p.Window == TimeSpan.FromHours(1)),
            Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The limiter refuses a blank subject with an <c>ArgumentException</c>, so a request whose
    /// peer address the server could not read must not be handed one - that would surface as a 500
    /// from the component whose whole design is to fail open.
    /// </summary>
    [Fact]
    public async Task ARequestWithNoKnownClientAddressIsThrottledInASharedBucketRatherThanFailing()
    {
        var anonymous = new VerificationRequestContext(string.Empty, "dev-1");

        await Sut.SendVerificationCodeAsync(SendRequest(), anonymous, CancellationToken.None);

        await _rateLimiter.Received(2).TryAcquireAsync(
            Arg.Any<string>(),
            Arg.Is<string>(key => !string.IsNullOrWhiteSpace(key)),
            Arg.Any<RateLimitPolicy>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ACaptchaDemandIsA403BecauseRepeatingTheSameRequestWillNeverWork()
    {
        _riskControl.EvaluateSendCodeAsync(Arg.Any<SendCodeRiskContext>(), Arg.Any<CancellationToken>())
            .Returns(SendCodeRiskDecision.CaptchaRequired());

        var ex = await Should.ThrowAsync<ForbiddenException>(
            () => Sut.SendVerificationCodeAsync(SendRequest(), Context, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.CaptchaRequired);
        ex.StatusCode.ShouldBe(403);
    }

    [Fact]
    public async Task ACooldownIsA429AndSaysHowLongToWait()
    {
        _riskControl.EvaluateSendCodeAsync(Arg.Any<SendCodeRiskContext>(), Arg.Any<CancellationToken>())
            .Returns(SendCodeRiskDecision.Cooldown(Now.AddMinutes(5), TimeSpan.FromSeconds(300)));

        var ex = await Should.ThrowAsync<RateLimitedException>(
            () => Sut.SendVerificationCodeAsync(SendRequest(), Context, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.RiskControlCooldown);
        ex.RetryAfter.ShouldBe(TimeSpan.FromSeconds(300));
    }

    [Fact]
    public async Task AValidCaptchaTokenBypassesThrottlingEntirely()
    {
        _riskControl.TryConsumeCaptchaTokenAsync("cpt_good", Arg.Any<SendCodeRiskContext>(), Arg.Any<CancellationToken>())
            .Returns(true);

        await Sut.SendVerificationCodeAsync(
            SendRequest(captchaToken: "cpt_good"), Context, CancellationToken.None);

        await _riskControl.DidNotReceive()
            .EvaluateSendCodeAsync(Arg.Any<SendCodeRiskContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ACaptchaTokenThatDoesNotBelongToThisTargetIsRefused()
    {
        _riskControl.TryConsumeCaptchaTokenAsync("cpt_bad", Arg.Any<SendCodeRiskContext>(), Arg.Any<CancellationToken>())
            .Returns(false);

        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.SendVerificationCodeAsync(
            SendRequest(captchaToken: "cpt_bad"), Context, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.CaptchaInvalid);

        // One solved captcha must not become a reusable bypass, so the throttling check is not
        // consulted as a fallback either.
        await _riskControl.DidNotReceive()
            .EvaluateSendCodeAsync(Arg.Any<SendCodeRiskContext>(), Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData("", VerificationTargetTypes.Email, ErrorCodes.BadRequest)]
    [InlineData("user@example.com", "fax", ErrorCodes.BadRequest)]
    [InlineData("not-an-email", VerificationTargetTypes.Email, ErrorCodes.InvalidEmailFormat)]
    [InlineData("0123456789", VerificationTargetTypes.Phone, ErrorCodes.InvalidPhoneFormat)]
    public async Task AMalformedRequestIsRefusedWithACodeTheClientCanBranchOn(
        string target,
        string targetType,
        string expected)
    {
        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.SendVerificationCodeAsync(
            SendRequest(target: target, targetType: targetType), Context, CancellationToken.None));

        ex.ErrorCode.ShouldBe(expected);
    }

    [Fact]
    public async Task AShortNumberIsStillAcceptedAsAPhone()
    {
        // Carried over deliberately: the original pattern accepts any 2-to-15-digit number that
        // does not start with zero, so a short code such as this one passes. Tightening it would
        // reject numbering plans we have no list of, and delivery is the real check.
        await Sut.SendVerificationCodeAsync(
            SendRequest(target: "12345", targetType: VerificationTargetTypes.Phone),
            Context,
            CancellationToken.None);

        await _codes.Received(1).CreateAsync(Arg.Any<NewVerificationCode>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnUnknownPurposeIsRefused()
    {
        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.SendVerificationCodeAsync(
            SendRequest(purpose: "take_over_account"), Context, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.BadRequest);
    }

    // ----------------------------------------------------------------- verifying

    [Fact]
    public async Task ACorrectCodeIsExchangedForATicket()
    {
        var response = await Sut.VerifyCodeAsync(
            new VerifyCodeRequest { Target = Email, Code = "123456", Purpose = VerificationPurposes.Auth },
            CancellationToken.None);

        response.Verified.ShouldBeTrue();
        response.VerificationTicket.ShouldStartWith("vft_");
        response.VerificationTicket.Length.ShouldBeGreaterThan(20);

        await _codes.Received(1).VerifyCodeAndIssueTicketAsync(
            Email,
            VerificationPurposes.Auth,
            "123456",
            response.VerificationTicket,
            Now + _options.TicketTtl,
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task EveryVerifyMintsAFreshTicket()
    {
        var request = new VerifyCodeRequest { Target = Email, Code = "123456", Purpose = VerificationPurposes.Auth };

        var first = await Sut.VerifyCodeAsync(request, CancellationToken.None);
        var second = await Sut.VerifyCodeAsync(request, CancellationToken.None);

        first.VerificationTicket.ShouldNotBe(second.VerificationTicket);
    }

    [Fact]
    public async Task AnIncorrectCodeIsReportedExactlyAsTheRepositoryClassifiedIt()
    {
        _codes.VerifyCodeAndIssueTicketAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(),
                Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new BadRequestException(ErrorCodes.VerificationCodeIncorrect, "not correct"));

        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.VerifyCodeAsync(
            new VerifyCodeRequest { Target = Email, Code = "000000", Purpose = VerificationPurposes.Auth },
            CancellationToken.None));

        // Deliberately not re-wrapped into one vague "invalid or expired" message the way the Go
        // service did: the caller has to know whether to retype or ask for a new code.
        ex.ErrorCode.ShouldBe(ErrorCodes.VerificationCodeIncorrect);
    }

    [Fact]
    public async Task AnExpiredCodeKeepsItsOwnErrorCodeSoTheClientCanOfferANewOne()
    {
        _codes.VerifyCodeAndIssueTicketAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(),
                Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new BadRequestException(ErrorCodes.VerificationCodeExpired, "expired"));

        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.VerifyCodeAsync(
            new VerifyCodeRequest { Target = Email, Code = "123456", Purpose = VerificationPurposes.Auth },
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.VerificationCodeExpired);
    }

    [Fact]
    public async Task AVerifyMissingItsCodeNeverReachesTheDatabase()
    {
        var ex = await Should.ThrowAsync<BadRequestException>(() => Sut.VerifyCodeAsync(
            new VerifyCodeRequest { Target = Email, Code = "", Purpose = VerificationPurposes.Auth },
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.BadRequest);
        await _codes.DidNotReceive().VerifyCodeAndIssueTicketAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(),
            Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>());
    }

    private static SendVerificationCodeRequest SendRequest(
        string target = Email,
        string targetType = VerificationTargetTypes.Email,
        string purpose = VerificationPurposes.Auth,
        string captchaToken = "") => new()
    {
        Target = target,
        TargetType = targetType,
        Purpose = purpose,
        CaptchaToken = captchaToken,
    };
}
