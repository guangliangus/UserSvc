using Shouldly;
using UserSvc.Infrastructure.Persistence.Repositories;
using Xunit;

namespace UserSvc.UnitTests.BackOffice;

/// <summary>
/// The directory search fragment. Two things are asserted without a database because both are
/// decisions rather than queries: what a term is escaped into, and which of the two search paths a
/// term takes.
/// </summary>
public sealed class BackendUserSearchTests
{
    [Fact]
    public void WrapsATermIntoAContainsPattern() =>
        BackendUserSearch.ContainsPattern("  chen  ").ShouldBe("%chen%");

    /// <summary>
    /// An unescaped wildcard turns the search box into "show me everything", which reads as a
    /// permission bug rather than as a typo; the underscore is worse, because it silently widens
    /// the result by one character without looking wrong at all.
    /// </summary>
    [Theory]
    [InlineData("100%", "%100\\%%")]
    [InlineData("a_b", "%a\\_b%")]
    [InlineData("back\\slash", "%back\\\\slash%")]
    public void EscapesWildcardsTypedIntoTheSearchBox(string term, string expected) =>
        BackendUserSearch.ContainsPattern(term).ShouldBe(expected);

    /// <summary>
    /// Addresses are stored hashed, so only a complete one can be matched. The branch is what keeps
    /// a name search from ever surfacing an address, and an address search from returning everyone
    /// whose name shares a few letters.
    /// </summary>
    [Theory]
    [InlineData("alice.chen@liontravel.com", true)]
    [InlineData("alice", false)]
    [InlineData("260022", false)]
    [InlineData("alice@liontravel", false)]
    public void SendsOnlyCompleteAddressesDownTheIdentityPath(string term, bool expected) =>
        BackendUserSearch.LooksLikeAddress(term).ShouldBe(expected);

    /// <summary>The escape character is passed on every call rather than left to the server's
    /// configuration, so it is pinned here too.</summary>
    [Fact]
    public void UsesBackslashAsTheEscapeCharacter() => BackendUserSearch.EscapeCharacter.ShouldBe("\\");
}
