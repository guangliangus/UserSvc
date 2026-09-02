using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;

namespace UserSvc.UnitTests.Suppliers;

/// <summary>
/// A back-office caller under test control.
/// <para>
/// Deliberately its own type rather than the IAM tests' equivalent: these two slices are written by
/// different hands at the same time, and a shared fake is the one file a change to either would
/// break for both.
/// </para>
/// </summary>
internal sealed class SliceCaller : IBackOfficeCaller
{
    public int UserId { get; init; } = 7;

    public string Nickname { get; init; } = "operator";

    public string ActType { get; init; } = ActTypes.Platform;

    public string ActCode { get; init; } = string.Empty;

    public string ActDim { get; init; } = string.Empty;

    public string? IpAddress => "203.0.113.9";

    public string? RequestId => "req-supplier-1";

    public EffectiveAuthz Authz { get; init; } = EffectiveAuthz.Empty;

    /// <summary>A caller whose resolved face carries exactly these permission codes.</summary>
    public static SliceCaller Holding(params string[] permissions) => new()
    {
        Authz = new EffectiveAuthz([], permissions, [], new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)),
    };

    /// <summary>A caller whose face carries nothing at all - the fail-closed default.</summary>
    public static SliceCaller HoldingNothing() => new();

    /// <summary>A caller acting as one company, holding these permission codes - the shape a
    /// company administrator can grant themselves while the menu audience rule is off.</summary>
    public static SliceCaller InCompanyContext(string companyCode, params string[] permissions) => new()
    {
        ActType = ActTypes.Company,
        ActCode = companyCode,
        ActDim = TenantTypes.Company,
        Authz = new EffectiveAuthz([], permissions, [], new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)),
    };
}
