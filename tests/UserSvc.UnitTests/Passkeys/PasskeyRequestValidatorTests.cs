using System.Text.Json;
using Shouldly;
using UserSvc.Application.Features.Passkeys;
using UserSvc.Domain.Auth;
using Xunit;

namespace UserSvc.UnitTests.Passkeys;

/// <summary>
/// The two request shapes where the validator has to be careful about <i>blank</i> rather than
/// absent, because the anonymous login endpoint is reachable by clients this service does not own.
/// </summary>
public sealed class PasskeyRequestValidatorTests
{
    private readonly PasskeyLoginBeginRequestValidator _loginBegin = new();

    [Theory]
    [InlineData(null, null)]
    [InlineData("", "")]
    [InlineData("   ", "   ")]
    [InlineData("0912345678", "phone")]
    [InlineData("a@b.com", "email")]
    [InlineData("a@b.com", "EMAIL")]
    public void ALoginBeginRequestThatAsksForADiscoverableOrScopedCeremonyIsAccepted(
        string? identifier,
        string? identityType)
    {
        // A blank identity type is how an unfilled client form serializes, and it means
        // "discoverable" - not "bad request". A recognised type in any casing is accepted, because
        // the lookup that follows this validator is case-insensitive and the two must agree.
        _loginBegin
            .Validate(new PasskeyLoginBeginRequest { Identifier = identifier, IdentityType = identityType })
            .IsValid
            .ShouldBeTrue();
    }

    [Fact]
    public void ALoginBeginRequestNamingAnUnsupportedIdentityTypeIsRefused()
    {
        var result = _loginBegin.Validate(new PasskeyLoginBeginRequest
        {
            Identifier = "wxid_1",
            IdentityType = "wechat",
        });

        result.IsValid.ShouldBeFalse();
    }

    [Fact]
    public void AnOverLongIdentifierIsRefused() =>
        _loginBegin
            .Validate(new PasskeyLoginBeginRequest { Identifier = new string('a', 101), IdentityType = "email" })
            .IsValid
            .ShouldBeFalse();

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void ARenameToABlankLabelIsRefusedRatherThanStored(string name) =>
        new RenamePasskeyRequestValidator()
            .Validate(new RenamePasskeyRequest { Name = name })
            .IsValid
            .ShouldBeFalse();

    [Fact]
    public void ARenameBeyondTheColumnLengthIsRefused() =>
        new RenamePasskeyRequestValidator()
            .Validate(new RenamePasskeyRequest { Name = new string('a', UserPasskey.MaxNameLength + 1) })
            .IsValid
            .ShouldBeFalse();

    [Fact]
    public void AFinishRequestWithNoCredentialAtAllIsRefusedBeforeItReachesTheVerifier() =>
        new PasskeyLoginFinishRequestValidator()
            .Validate(new PasskeyLoginFinishRequest { FlowId = "pklogin_1" })
            .IsValid
            .ShouldBeFalse("a default JsonElement is Undefined, not an object");

    [Fact]
    public void AFinishRequestCarryingAnObjectIsAccepted() =>
        new PasskeyLoginFinishRequestValidator()
            .Validate(new PasskeyLoginFinishRequest
            {
                FlowId = "pklogin_1",
                Credential = JsonDocument.Parse("""{"id":"AQID"}""").RootElement,
            })
            .IsValid
            .ShouldBeTrue();
}
