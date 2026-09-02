using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Registration;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;
using UserSvc.Application.Ports.Verification;
using UserSvc.Application.Security;
using UserSvc.Domain.Users;
using UserSvc.Domain.Users.Events;
using UserSvc.Domain.Verification;
using Xunit;

namespace UserSvc.UnitTests.Features;

/// <summary>
/// The Go service's <c>auth_service_test.go</c> Register cases, ported: happy path, nickname
/// derivation, a bad ticket, and an identifier that is already taken. The rest are cases the Go
/// original had no equivalent of because it had neither a blind index, nor an outbox, nor real
/// HTTP status codes to leak information through.
/// <para>
/// Every port is substituted; <see cref="IdentifierProtector"/> and <see cref="PasswordHasher"/>
/// are the real things, because they are pure computation and a fake would only assert that the
/// test's own arithmetic matches itself.
/// </para>
/// </summary>
public sealed class RegistrationAppServiceTests
{
    private const string Ticket = "ticket-abc";

    private readonly IUserRepository _users = Substitute.For<IUserRepository>();
    private readonly IUserIdentityRepository _identities = Substitute.For<IUserIdentityRepository>();
    private readonly IVerificationTicketConsumer _tickets = Substitute.For<IVerificationTicketConsumer>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 9, 1, 12, 0, 0, TimeSpan.Zero));
    private readonly IdentifierProtector _protector = new(Options.Create(new IdentifierProtectionOptions
    {
        Pepper = "00112233445566778899aabbccddeeff",
        DataKey = Convert.ToBase64String(new byte[32]),
        KeyVersion = "v3",
    }));

    private readonly PasswordHasher _passwordHasher = new();

    /// <summary>The user handed to <see cref="IUserRepository.Add"/>, captured as the database
    /// would see it: with the key the insert generated, and with its identity attached.</summary>
    private User? _inserted;

    public RegistrationAppServiceTests()
    {
        _identities.FindActiveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((UserIdentity?)null);

        _tickets.TryConsumeAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(true);

        // The substitute has to run the body, or every assertion below would pass against a
        // transaction that never opened.
        _unitOfWork
            .ExecuteInTransactionAsync(Arg.Any<Func<CancellationToken, Task>>(), Arg.Any<CancellationToken>())
            .Returns(call => call.Arg<Func<CancellationToken, Task>>().Invoke(CancellationToken.None));

        // Stands in for the insert: PostgreSQL assigns the key, EF writes it back onto the entity.
        _users.When(repository => repository.Add(Arg.Any<User>()))
            .Do(call =>
            {
                _inserted = call.Arg<User>();
                _inserted.Id = 4711;
            });
    }

    private RegistrationAppService Sut => new(
        _users,
        _identities,
        _tickets,
        _protector,
        _passwordHasher,
        _unitOfWork,
        _clock,
        NullLogger<RegistrationAppService>.Instance);

    private static RegisterRequest Request(
        string identityType = IdentityTypes.Email,
        string identifier = "alice@example.com",
        string? nickname = "alice-nick") => new()
    {
        IdentityType = identityType,
        Identifier = identifier,
        Password = "sup3rsecret",
        VerificationTicket = Ticket,
        FirstName = "Alice",
        LastName = "Liddell",
        Nickname = nickname,
    };

    [Fact]
    public async Task RegisteringCreatesAnActiveAccountWithItsFirstLoginIdentity()
    {
        var response = await Sut.RegisterAsync(Request(), CancellationToken.None);

        response.Id.ShouldBe(4711);
        response.Status.ShouldBe(UserStatuses.Active);
        response.Nickname.ShouldBe("alice-nick");
        response.CreatedAt.ShouldBe(_clock.UtcNow);

        var user = _inserted.ShouldNotBeNull();
        user.FirstName.ShouldBe("Alice");
        user.LastName.ShouldBe("Liddell");
        user.Status.ShouldBe(UserStatuses.Active);
        user.CreatedAt.ShouldBe(_clock.UtcNow);
        user.UpdatedAt.ShouldBe(_clock.UtcNow);

        var identity = user.Identities.ShouldHaveSingleItem();
        identity.IdentityType.ShouldBe(IdentityTypes.Email);
        identity.Status.ShouldBe(UserStatuses.Active);
        identity.IdentifierKeyVersion.ShouldBe("v3");

        await _unitOfWork.Received(1).SaveChangesAsync(Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The ticket is spent inside the transaction, so it cannot outlive a failed insert - and the
    /// purpose it is spent under is what stops a "reset password" ticket from creating an account.
    /// <para>
    /// The target is the identifier <b>as the caller typed it</b>. The ticket's <c>target_hash</c>
    /// was built by <c>VerificationHashing.HashTarget</c>, which trims and lowercases and nothing
    /// else; handing the consumer this slice's normalized value instead would miss every ticket
    /// ever minted for a phone number, because normalization drops the plus.
    /// </para>
    /// </summary>
    [Fact]
    public async Task TheTicketIsConsumedForTheAuthPurposeAgainstTheIdentifierAsTheCallerTypedIt()
    {
        await Sut.RegisterAsync(Request(identifier: "  Alice@Example.COM "), CancellationToken.None);

        await _tickets.Received(1).TryConsumeAsync(
            "  Alice@Example.COM ", VerificationPurposes.Auth, Ticket, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ThePhoneNumberHandedToTheTicketConsumerKeepsThePlusTheCallerVerifiedWith()
    {
        await Sut.RegisterAsync(
            Request(IdentityTypes.Phone, "+886912345678", nickname: null), CancellationToken.None);

        await _tickets.Received(1).TryConsumeAsync(
            "+886912345678", VerificationPurposes.Auth, Ticket, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnOmittedNicknameIsDerivedFromTheEmailLocalPart()
    {
        await Sut.RegisterAsync(
            Request(identifier: "random@example.com", nickname: null), CancellationToken.None);

        _inserted.ShouldNotBeNull().Nickname.ShouldBe("random");
    }

    /// <summary>A phone number is not a display name, so there is nothing to derive from.</summary>
    [Fact]
    public async Task APhoneSignUpWithNoNicknameGetsTheDefaultMemberName()
    {
        await Sut.RegisterAsync(
            Request(IdentityTypes.Phone, "+886912345678", nickname: null), CancellationToken.None);

        _inserted.ShouldNotBeNull().Nickname.ShouldBe("Lion Travel Member");
    }

    /// <summary>
    /// Nothing is written, and - the part worth asserting - the identifier is never even looked up.
    /// Everything past the ticket either costs the server real work or tells the caller something,
    /// so a caller who cannot spend a ticket reaches none of it.
    /// </summary>
    [Fact]
    public async Task AnInvalidTicketIsRefusedBeforeAnythingIsLookedUpOrHashed()
    {
        _tickets.TryConsumeAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.RegisterAsync(Request(), CancellationToken.None));

        ex.StatusCode.ShouldBe(400);
        ex.ErrorCode.ShouldBe(ErrorCodes.VerificationFailed);

        await _identities.DidNotReceive().FindActiveAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        _users.DidNotReceive().Add(Arg.Any<User>());
        await _unitOfWork.DidNotReceive().SaveChangesAsync(Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// <b>The account-enumeration test.</b> The Go original checked for an existing identifier
    /// before it consumed the ticket (spec 03 3.4.1 step 2), which under real status codes would
    /// let anyone post an address with a junk ticket and read the answer off the status: 409 means
    /// "this mailbox has an account", 400 means it does not. Both cases must be indistinguishable
    /// to a caller who cannot spend a ticket.
    /// </summary>
    [Fact]
    public async Task ABadTicketAnswersTheSameWhetherOrNotTheIdentifierIsAlreadyRegistered()
    {
        _identities.FindActiveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new UserIdentity { Id = 1, UserId = 9, IdentityType = IdentityTypes.Email });
        _tickets.TryConsumeAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(false);

        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.RegisterAsync(Request(), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.VerificationFailed);
    }

    /// <summary>The Go original answered 400 here; a real status code says 409, because the request
    /// was well formed and it is the state of the world that refuses it. It is only reachable by a
    /// caller who has just proved control of the identifier.</summary>
    [Fact]
    public async Task AnAlreadyBoundIdentifierIsRefusedOnceTheTicketProvesTheCallerOwnsIt()
    {
        _identities.FindActiveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new UserIdentity { Id = 1, UserId = 9, IdentityType = IdentityTypes.Email });

        var ex = await Should.ThrowAsync<ConflictException>(
            () => Sut.RegisterAsync(Request(), CancellationToken.None));

        ex.StatusCode.ShouldBe(409);
        ex.ErrorCode.ShouldBe(ErrorCodes.AlreadyRegistered);

        // The consumption is rolled back with the transaction it ran in, so the ticket the caller
        // still holds stays spendable until its own TTL expires.
        await _tickets.Received(1).TryConsumeAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
        _users.DidNotReceive().Add(Arg.Any<User>());
        await _unitOfWork.DidNotReceive().SaveChangesAsync(Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The check above is advisory. What actually enforces one active binding per identifier is the
    /// partial unique index, and losing that race must read to the client exactly like losing the
    /// check - not like the generic constraint violation the unit of work reports.
    /// </summary>
    [Fact]
    public async Task LosingTheRaceOnTheUniqueIndexIsReportedAsAlreadyRegistered()
    {
        var violation = new ConflictException(
            ErrorCodes.Conflict,
            "The value violates the uniqueness constraint 'ix_user_identities_identity_type_identifier_hash'.");

        _unitOfWork.SaveChangesAsync(Arg.Any<CancellationToken>()).ThrowsAsync(violation);

        var ex = await Should.ThrowAsync<ConflictException>(
            () => Sut.RegisterAsync(Request(), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.AlreadyRegistered);
        ex.InnerException.ShouldBe(violation, "the SQLSTATE that explains the incident belongs in the log");
    }

    /// <summary>Decision 13: the plaintext never reaches a column, and the blind index is the only
    /// thing a later lookup can match on - so it has to be the hash of the normalized value.</summary>
    [Fact]
    public async Task TheIdentifierIsStoredAsABlindIndexAndCiphertextAndNeverAsPlaintext()
    {
        await Sut.RegisterAsync(Request(identifier: "Alice@Example.com"), CancellationToken.None);

        var identity = _inserted.ShouldNotBeNull().Identities.ShouldHaveSingleItem();

        identity.IdentifierHash.ShouldBe(_protector.Hash("alice@example.com"));
        _protector.Decrypt(identity.IdentifierCiphertext).ShouldBe("alice@example.com");

        identity.IdentifierHash.ShouldNotContain("alice", Case.Insensitive);
        identity.IdentifierCiphertext.ShouldNotContain("alice", Case.Insensitive);
    }

    /// <summary>
    /// The blind index is what the partial unique index is built on, so if the plus survived
    /// normalization the same telephone typed two ways would be two accounts - and the second of
    /// them would be undiscoverable by the first one's owner.
    /// </summary>
    [Fact]
    public async Task APhoneNumberIsIndexedWithoutItsPlusSoBothSpellingsAreOneAccount()
    {
        await Sut.RegisterAsync(
            Request(IdentityTypes.Phone, "+886912345678", nickname: null), CancellationToken.None);

        var identity = _inserted.ShouldNotBeNull().Identities.ShouldHaveSingleItem();

        identity.IdentifierHash.ShouldBe(_protector.Hash("886912345678"));
        identity.IdentifierHash.ShouldBe(
            _protector.Hash(IdentifierNormalizer.Normalize(IdentityTypes.Phone, "886912345678")));
    }

    [Fact]
    public async Task ThePasswordIsStoredAsAnArgon2idHashAlongsideTheAlgorithmThatMadeIt()
    {
        await Sut.RegisterAsync(Request(), CancellationToken.None);

        var user = _inserted.ShouldNotBeNull();
        user.PasswordAlgo.ShouldBe(PasswordHasher.AlgorithmName);
        user.PasswordHash.ShouldStartWith("$argon2id$");
        user.PasswordHash.ShouldNotContain("sup3rsecret");
        _passwordHasher.Verify("sup3rsecret", user.PasswordHash).ShouldBeTrue();
    }

    /// <summary>
    /// The outbox row is serialized by the SaveChanges interceptor, before PostgreSQL has assigned
    /// the key - so the event must identify the account by something that already exists. This test
    /// reads the event off the entity at the moment it reaches the repository, which is exactly the
    /// moment the interceptor would.
    /// </summary>
    [Fact]
    public async Task TheRegistrationEventCarriesBusinessKeysBecauseThereIsNoIdYet()
    {
        IReadOnlyList<UserRegistered> raisedBeforeInsert = [];
        _users.When(repository => repository.Add(Arg.Any<User>()))
            .Do(call =>
            {
                var user = call.Arg<User>();
                raisedBeforeInsert = [.. user.DomainEvents.OfType<UserRegistered>()];
                user.Id = 4711;
            });

        await Sut.RegisterAsync(Request(), CancellationToken.None);

        var registered = raisedBeforeInsert.ShouldHaveSingleItem();
        registered.IdentityType.ShouldBe(IdentityTypes.Email);
        registered.IdentifierHash.ShouldBe(_protector.Hash("alice@example.com"));
        registered.OccurredAt.ShouldBe(_clock.UtcNow);
    }

    /// <summary>
    /// The validation filter rejects this first in production. The service must not depend on that:
    /// on its own it has to answer 400 rather than let an <see cref="ArgumentOutOfRangeException"/>
    /// out, which the handler could only render as a 500.
    /// </summary>
    [Fact]
    public async Task AnUnsupportedIdentityTypeIsABadRequestRatherThanAnUnhandledException()
    {
        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.RegisterAsync(Request(identityType: "wechat"), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.ValidationFailed);
        await _tickets.DidNotReceive().TryConsumeAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// A phone number of pure punctuation normalizes to the empty string. Hashing that would give
    /// every such request one blind index - so the first would claim the account and the rest would
    /// collide with it - which is why it is refused instead.
    /// </summary>
    [Fact]
    public async Task AnIdentifierThatNormalizesToNothingIsRefusedRatherThanHashedEmpty()
    {
        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.RegisterAsync(Request(IdentityTypes.Phone, "+"), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.ValidationFailed);
        await _tickets.DidNotReceive().TryConsumeAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }
}
