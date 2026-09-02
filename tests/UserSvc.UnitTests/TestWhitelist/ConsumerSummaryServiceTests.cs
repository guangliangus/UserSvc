using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Shouldly;
using UserSvc.Application.Features.BackOffice.Consumers;
using UserSvc.Application.Ports.TestWhitelist;
using UserSvc.Application.Security;
using UserSvc.Domain.Users;
using Xunit;

namespace UserSvc.UnitTests.TestWhitelist;

/// <summary>
/// How much of a consumer an operator is shown. Every assertion here is a privacy boundary: the
/// plaintext of somebody's contact detail must never reach the response, and an account that no
/// longer exists must still be visible enough to be removed from the whitelist.
/// </summary>
public sealed class ConsumerSummaryServiceTests
{
    private readonly IConsumerAccountDirectory _consumers = Substitute.For<IConsumerAccountDirectory>();

    private readonly IdentifierProtector _protector = new(Options.Create(new IdentifierProtectionOptions
    {
        Pepper = "00112233445566778899aabbccddeeff",
        DataKey = Convert.ToBase64String(new byte[32]),
        KeyVersion = "v3",
    }));

    public ConsumerSummaryServiceTests()
    {
        _consumers.ListAccountsAsync(Arg.Any<IReadOnlyList<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);
        _consumers.ListActiveContactsAsync(Arg.Any<IReadOnlyList<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);
    }

    private ConsumerSummaryService Sut =>
        new(_consumers, _protector, NullLogger<ConsumerSummaryService>.Instance);

    [Fact]
    public async Task NoIdsMeansNoQueries()
    {
        (await Sut.SummarizeAsync([], CancellationToken.None)).ShouldBeEmpty();

        await _consumers.DidNotReceive().ListAccountsAsync(
            Arg.Any<IReadOnlyList<int>>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ContactDetailsComeBackMaskedAndNeverInTheClear()
    {
        Account(4, nickname: "Tester");
        Contacts(
            Contact(4, IdentityTypes.Email, "tester@example.com"),
            Contact(4, IdentityTypes.Phone, "0912345678"));

        var summary = (await Sut.SummarizeAsync([4], CancellationToken.None)).ShouldHaveSingleItem();

        summary.AccountExists.ShouldBeTrue();
        summary.Nickname.ShouldBe("Tester");
        summary.EmailMasked.ShouldBe("t***@example.com");
        summary.PhoneMasked.ShouldBe("******5678");
        summary.EmailMasked.ShouldNotContain("tester@");
        summary.PhoneMasked.ShouldNotContain("0912");
    }

    [Fact]
    public async Task TheFirstIdentityOfEachTypeWins()
    {
        Account(4);
        Contacts(
            Contact(4, IdentityTypes.Email, "first@example.com"),
            Contact(4, IdentityTypes.Email, "second@example.com"));

        var summary = (await Sut.SummarizeAsync([4], CancellationToken.None)).ShouldHaveSingleItem();

        // The port orders by id, so "first seen" is the whole rule - and it is what keeps two page
        // loads from describing the same account differently.
        summary.EmailMasked.ShouldBe("f***@example.com");
    }

    [Fact]
    public async Task AnUndecryptableIdentifierBlanksThatColumnRatherThanFailingTheListing()
    {
        Account(4);
        Contacts(new ConsumerContactRow(4, IdentityTypes.Email, "not-a-ciphertext"));

        var summary = (await Sut.SummarizeAsync([4], CancellationToken.None)).ShouldHaveSingleItem();

        summary.AccountExists.ShouldBeTrue();
        summary.EmailMasked.ShouldBeEmpty();
    }

    [Fact]
    public async Task AnUndecryptableRowLeavesItsSlotToTheNextIdentityOfThatType()
    {
        Account(4);
        Contacts(
            new ConsumerContactRow(4, IdentityTypes.Email, "not-a-ciphertext"),
            Contact(4, IdentityTypes.Email, "second@example.com"));

        var summary = (await Sut.SummarizeAsync([4], CancellationToken.None)).ShouldHaveSingleItem();

        // "First by id" holds among the rows that can be read back. An unreadable row does not
        // claim the column and hide a readable address behind it - the operator gets an address the
        // account really holds, and the choice is still deterministic because the order is the
        // database's.
        summary.EmailMasked.ShouldBe("s***@example.com");
    }

    [Fact]
    public async Task AThirdPartyIdentityIsNeitherAnEmailNorAPhone()
    {
        Account(4);
        Contacts(Contact(4, IdentityTypes.Line, "U1234567890"));

        var summary = (await Sut.SummarizeAsync([4], CancellationToken.None)).ShouldHaveSingleItem();

        summary.EmailMasked.ShouldBeEmpty();
        summary.PhoneMasked.ShouldBeEmpty();
    }

    [Fact]
    public async Task AnOrphanedIdStillYieldsARowSoItCanBeRemoved()
    {
        var summaries = await Sut.SummarizeAsync([4], CancellationToken.None);

        var summary = summaries.ShouldHaveSingleItem();
        summary.UserId.ShouldBe(4);
        summary.AccountExists.ShouldBeFalse();
        summary.Nickname.ShouldBeEmpty();
    }

    [Fact]
    public async Task OrderFollowsTheIdsThatWereAskedFor()
    {
        _consumers.ListAccountsAsync(Arg.Any<IReadOnlyList<int>>(), Arg.Any<CancellationToken>())
            .Returns([
                new ConsumerAccountRow(2, string.Empty, string.Empty, "two"),
                new ConsumerAccountRow(1, string.Empty, string.Empty, "one"),
            ]);

        var summaries = await Sut.SummarizeAsync([1, 2], CancellationToken.None);

        summaries.Select(summary => summary.UserId).ShouldBe([1, 2]);
    }

    [Fact]
    public async Task AnAccountWithNoNicknameFallsBackToItsJoinedName()
    {
        Account(4, nickname: string.Empty, firstName: "Ada", lastName: "Lovelace");

        var summary = (await Sut.SummarizeAsync([4], CancellationToken.None)).ShouldHaveSingleItem();

        summary.Nickname.ShouldBe("Ada Lovelace");
    }

    private void Account(
        int userId,
        string nickname = "nick",
        string firstName = "",
        string lastName = "") =>
        _consumers.ListAccountsAsync(Arg.Any<IReadOnlyList<int>>(), Arg.Any<CancellationToken>())
            .Returns([new ConsumerAccountRow(userId, firstName, lastName, nickname)]);

    private void Contacts(params ConsumerContactRow[] rows) =>
        _consumers.ListActiveContactsAsync(Arg.Any<IReadOnlyList<int>>(), Arg.Any<CancellationToken>())
            .Returns(rows);

    private ConsumerContactRow Contact(int userId, string identityType, string plaintext) =>
        new(userId, identityType, _protector.Encrypt(plaintext));
}
