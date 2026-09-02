using Shouldly;
using UserSvc.Application.Features.SocialIdentity;
using Xunit;

namespace UserSvc.UnitTests.SocialIdentity;

/// <summary>
/// The <c>provider_details</c> jsonb column. It is decoration, never a lookup key, and the tests
/// are mostly about it staying harmless.
/// </summary>
public sealed class ProviderDetailsTests
{
    [Fact]
    public void NothingWorthRecordingStoresAnEmptyObjectRatherThanNull()
    {
        ProviderDetails.Empty.ToJson().ShouldBe("{}");
    }

    /// <summary>
    /// Empty members are omitted, so a WeChat identity stores one key rather than three, two of
    /// them blank. The difference matters when a human is reading a row to work out what a provider
    /// actually returned.
    /// </summary>
    [Fact]
    public void OnlyThePopulatedMembersAreWritten()
    {
        var json = new ProviderDetails(UnionId: "wx-union-1").ToJson();

        json.ShouldContain("wx-union-1");
        json.ShouldNotContain("email_masked");
        json.ShouldNotContain("\"name\"");
    }

    [Fact]
    public void AFullSetSurvivesTheRoundTrip()
    {
        var details = new ProviderDetails("wx-union-1", "car***@gmail.com", "Carol");

        var restored = ProviderDetails.FromJson(details.ToJson());

        restored.ShouldBe(details);
    }

    /// <summary>
    /// <b>Malformed json answers empty instead of throwing</b>, which is a deliberate call about
    /// blast radius: this value is decoration on a login identity, and a row whose json was mangled
    /// by some past migration must not be able to stop its owner signing in. Everything that
    /// decides anything is a real column.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("{ not json")]
    [InlineData("[]")]
    public void UnreadableJsonDegradesToEmpty(string? json)
    {
        ProviderDetails.FromJson(json).ShouldBe(ProviderDetails.Empty);
    }

    [Fact]
    public void UnknownMembersAreIgnoredRatherThanRefused()
    {
        var restored = ProviderDetails.FromJson("""{"union_id":"u","something_new":42}""");

        restored.UnionId.ShouldBe("u");
    }
}
