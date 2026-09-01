namespace UserSvc.Domain.Abstractions;

/// <summary>
/// A domain invariant was violated. Deliberately carries <b>no</b> HTTP status code — the domain
/// does not know HTTP exists (decision 03). The API layer maps it to 422 (decision 09: the
/// request was well formed but broke a business rule).
/// </summary>
public sealed class DomainRuleException(string errorCode, string message) : Exception(message)
{
    public string ErrorCode { get; } = errorCode;
}
