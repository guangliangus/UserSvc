using Shouldly;
using UserSvc.Domain.Feedback;
using Xunit;

namespace UserSvc.UnitTests.Feedback;

/// <summary>
/// Label resolution never throws, because a category with a broken label still belongs in the
/// drop-down and a drop-down that fails to load leaves the form with nothing to choose from.
/// </summary>
public sealed class FeedbackTypeTests
{
    private static FeedbackType With(string labels) => new() { Code = "bug", Labels = labels };

    [Fact]
    public void TheExactLocaleWins() =>
        With("""{"ja":"A","en":"Bug report"}""").ResolveLabel("ja").ShouldBe("A");

    [Fact]
    public void AMissingLocaleFallsBackToEnglish() =>
        With("""{"en":"Bug report"}""").ResolveLabel("ko").ShouldBe("Bug report");

    [Fact]
    public void LookupIsCaseSensitiveBecauseTheKeysAre() =>
        // The seeded key is spelled zh-CN. A caller that reaches this with zh-cn gets English,
        // which is exactly why callers normalize before asking.
        With("""{"zh-CN":"A","en":"Bug report"}""").ResolveLabel("zh-cn").ShouldBe("Bug report");

    [Fact]
    public void AnEmptyLabelIsTreatedAsAbsent() =>
        With("""{"ja":"","en":"Bug report"}""").ResolveLabel("ja").ShouldBe("Bug report");

    [Theory]
    [InlineData("{}")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not json at all")]
    [InlineData("""["an","array"]""")]
    [InlineData("""{"en":{"nested":"object"}}""")]
    [InlineData("""{"en":42}""")]
    public void AnythingUnusableResolvesToTheEmptyStringRatherThanThrowing(string labels) =>
        With(labels).ResolveLabel("en").ShouldBe(string.Empty);

}
