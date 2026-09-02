using UserSvc.Infrastructure.External;

namespace UserSvc.UnitTests.RiskControl;

/// <summary>Stands in for the provider so the risk engine's own decisions can be tested without a
/// Google account or a socket.</summary>
internal sealed class FakeCaptchaVerifier : ICaptchaVerifier
{
    public bool IsConfigured { get; set; } = true;

    /// <summary>What the provider says. Default: a comfortable pass.</summary>
    public CaptchaAssessment Assessment { get; set; } = CaptchaAssessment.Pass(0.9);

    /// <summary>Thrown instead of answering, for the "nobody could reach a verdict" paths.</summary>
    public Exception? Throws { get; set; }

    public int CallCount { get; private set; }

    public Task<CaptchaAssessment> AssessAsync(
        CaptchaAssessmentRequest request,
        CancellationToken cancellationToken)
    {
        CallCount++;

        return Throws is null ? Task.FromResult(Assessment) : Task.FromException<CaptchaAssessment>(Throws);
    }
}
