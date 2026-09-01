namespace UserSvc.Application.Features.Profile;

/// <summary>
/// The profile a caller reads back. The envelope is gone (decision 09), so a successful response
/// is this object itself.
/// <para>
/// Named for its role in the HTTP exchange rather than for the pattern it implements: this type
/// name becomes the schema name in the OpenAPI document and therefore the class name in every
/// generated client. "Dto" would describe the mechanism, not the thing.
/// </para>
/// </summary>
public sealed record ProfileResponse
{
    /// <summary>Serialized as a JSON number. Should identifiers ever outgrow <see cref="int"/>,
    /// that is a versioned contract change, not something to pre-empt by shipping every id as a
    /// string today.</summary>
    public required int Id { get; init; }
    public string FirstName { get; init; } = string.Empty;
    public string LastName { get; init; } = string.Empty;
    public string Nickname { get; init; } = string.Empty;
    public string Avatar { get; init; } = string.Empty;
    public string ResidenceCountryCode { get; init; } = string.Empty;
    public string Status { get; init; } = string.Empty;
    public DateTimeOffset CreatedAt { get; init; }
}

/// <summary>Profile update request. Omitted fields are left unchanged.</summary>
public sealed record UpdateProfileRequest
{
    public string? FirstName { get; init; }
    public string? LastName { get; init; }
    public string? Nickname { get; init; }
    public string? ResidenceCountryCode { get; init; }
}
