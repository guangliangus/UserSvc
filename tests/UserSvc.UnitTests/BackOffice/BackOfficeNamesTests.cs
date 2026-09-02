using Shouldly;
using UserSvc.Application.Features.BackOffice.Accounts;
using Xunit;

namespace UserSvc.UnitTests.BackOffice;

/// <summary>
/// The name helpers, ported from the Go service's <c>name_util</c> and <c>email_util</c> tests.
/// They look like string trivia and are not: the composed display name is what every back-office
/// screen shows and what every operator searches for, and the domain check is a gate on who may
/// register an account at all.
/// </summary>
public sealed class BackOfficeNamesTests
{
    [Theory]
    [InlineData("Alice Chen", "Alice", "Chen")]
    [InlineData("Maria del Carmen Ruiz", "Maria", "del Carmen Ruiz")]
    [InlineData("Alice", "Alice", "")]
    [InlineData("  Alice   Chen  ", "Alice", "Chen")]
    [InlineData("", "", "")]
    public void SplitsLatinNamesOnWhitespace(string input, string first, string last)
    {
        var (actualFirst, actualLast) = BackOfficeNames.SplitFullName(input);

        actualFirst.ShouldBe(first);
        actualLast.ShouldBe(last);
    }

    /// <summary>
    /// A CJK name has no separator, so the family name is taken as the first character.
    /// <para>
    /// The names in this file are written as escape sequences because C# source in this repository
    /// must stay English-only, and a literal here would fail that guard. This one is the family name
    /// Wang followed by the given name Xiaoming.
    /// </para>
    /// </summary>
    [Fact]
    public void SplitsCjkNamesAfterTheFirstCharacter()
    {
        var (first, last) = BackOfficeNames.SplitFullName("\u738B\u5C0F\u660E");

        last.ShouldBe("\u738B");
        first.ShouldBe("\u5C0F\u660E");
    }

    /// <summary>
    /// The documented limitation, pinned rather than hidden: a two-character compound surname is
    /// split after its first character. If someone ever adds a surname table, this test is what
    /// tells them which behaviour they are changing.
    /// </summary>
    [Fact]
    public void MisSplitsCompoundCjkSurnamesAndThatIsKnown()
    {
        // The two-character surname Ouyang, followed by a one-character given name.
        var (first, last) = BackOfficeNames.SplitFullName("\u6B50\u967D\u5A1C");

        last.ShouldBe("\u6B50");
        first.ShouldBe("\u967D\u5A1C");
    }

    [Theory]
    [InlineData("Alice", "Chen", "Alice Chen")]
    [InlineData("Alice", "", "Alice")]
    [InlineData("", "Chen", "Chen")]
    public void JoinsLatinNamesWithASpace(string first, string last, string expected) =>
        BackOfficeNames.JoinFullName(first, last).ShouldBe(expected);

    /// <summary>Family name first and no separator - a space would make one name read as two.</summary>
    [Fact]
    public void JoinsCjkNamesWithoutASeparator() =>
        BackOfficeNames.JoinFullName("\u5C0F\u660E", "\u738B").ShouldBe("\u738B\u5C0F\u660E");

    [Fact]
    public void DisplayNamePrefersTheComposedName() =>
        BackOfficeNames.DisplayName("\u5C0F\u660E", "\u738B", "wang.xm").ShouldBe("\u738B\u5C0F\u660E");

    /// <summary>
    /// Half a name is not a name. An account seeded from a mailbox has a handle and nothing else,
    /// and composing from one half would display a bare surname.
    /// </summary>
    [Theory]
    [InlineData("Alice", "", "alice.c")]
    [InlineData("", "Chen", "alice.c")]
    [InlineData(null, null, "alice.c")]
    public void DisplayNameFallsBackToTheHandle(string? first, string? last, string expected) =>
        BackOfficeNames.DisplayName(first, last, "alice.c").ShouldBe(expected);

    [Theory]
    [InlineData("Alice.Chen@Liontravel.com", "alice.chen")]
    [InlineData("no-at-sign", "no-at-sign")]
    [InlineData("@leading", "@leading")]
    public void TakesTheLocalPartOfAnAddress(string input, string expected) =>
        BackOfficeNames.EmailLocalPart(input).ShouldBe(expected);

    [Theory]
    [InlineData("ops@liontravel.com", true)]
    [InlineData("  ops@liontravel.com  ", true)]
    [InlineData("ops@liontravel", false)]
    [InlineData("not an address", false)]
    [InlineData("prefix ops@liontravel.com suffix", false)]
    [InlineData("", false)]
    public void RecognizesAddressesOnlyWhenTheWholeStringIsOne(string input, bool expected) =>
        BackOfficeNames.IsEmail(input).ShouldBe(expected);

    [Fact]
    public void ParsesTheDomainAllowListAndSuppliesTheMissingSign() =>
        BackOfficeNames.InternalDomains(" liontravel.com , @xinflight.com ,, ")
            .ShouldBe(["@liontravel.com", "@xinflight.com"]);

    [Theory]
    [InlineData("ops@liontravel.com", true)]
    [InlineData("OPS@LIONTRAVEL.COM", true)]
    [InlineData("ops@example.com", false)]
    [InlineData("ops@", false)]
    [InlineData("liontravel.com", false)]
    public void MatchesTheDomainOfAnAddress(string email, bool expected) =>
        BackOfficeNames.EmailInDomains(email, ["@liontravel.com", "@xinflight.com"]).ShouldBe(expected);

    /// <summary>
    /// The attack this closes: an address whose <i>local part</i> contains a corporate domain is not
    /// a corporate address, because mail is delivered on what follows the last sign. Reading the
    /// first one would let anyone with a mailbox anywhere register a back-office account.
    /// </summary>
    [Fact]
    public void MatchesTheLastAtSignRatherThanTheFirst() =>
        BackOfficeNames.EmailInDomains("attacker@liontravel.com@evil.example", ["@liontravel.com"])
            .ShouldBeFalse();
}
