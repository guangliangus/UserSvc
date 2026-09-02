using Microsoft.Extensions.Options;
using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Accounts;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Security;
using UserSvc.Domain.BackOffice;
using Xunit;

namespace UserSvc.UnitTests.BackOffice;

/// <summary>
/// The gate both ends of the back-office self-service reset run.
/// <para>
/// What these cases are really pinning is that there is <b>one</b> rule with two phrasings. The
/// send-code end reads a verdict and answers every target the same way; the submit end turns the
/// same verdict into a status code. The failure mode worth a test file is the two drifting apart -
/// a target the send step is willing to mail a code to and the submit step then refuses, or worse
/// the reverse - so every case below asserts both entry points against one arrangement of the
/// tables.
/// </para>
/// </summary>
public sealed class BackOfficeResetTargetGateTests
{
    private const string CorporateEmail = "alice.chen@liontravel.com";

    private readonly IBackendUserRepository _users = Substitute.For<IBackendUserRepository>();
    private readonly IBackendIdentityRepository _identities = Substitute.For<IBackendIdentityRepository>();

    private readonly IdentifierProtector _protector = new(Options.Create(new IdentifierProtectionOptions
    {
        Pepper = "00112233445566778899aabbccddeeff",
        DataKey = Convert.ToBase64String(new byte[32]),
        KeyVersion = "v3",
    }));

    private BackOfficeResetTargetGate Sut => new(_users, _identities, _protector);

    [Theory]
    [InlineData(BackendUserStatuses.Active)]
    [InlineData(BackendUserStatuses.Pending)]
    public async Task AnAccountThatMaySetAPasswordIsEligibleAtBothEnds(string status)
    {
        var account = GivenAccount(status);

        var verdict = await Sut.EvaluateAsync(CorporateEmail, CancellationToken.None);
        verdict.Eligibility.ShouldBe(BackOfficeResetEligibility.Eligible);
        verdict.Account.ShouldBe(account);

        (await Sut.ResolveAsync(CorporateEmail, CancellationToken.None)).ShouldBe(account);
    }

    /// <summary>
    /// The two ends part company here, and this is the whole point of the split: the send step is
    /// told what happened and says nothing, the submit step says <c>ACCOUNT_DISABLED</c> to a
    /// caller who has already proved they own the mailbox.
    /// </summary>
    [Fact]
    public async Task ADisabledAccountIsRefusedLoudlyOnlyAtTheSubmitEnd()
    {
        var account = GivenAccount(BackendUserStatuses.Disabled);

        var verdict = await Sut.EvaluateAsync(CorporateEmail, CancellationToken.None);
        verdict.Eligibility.ShouldBe(BackOfficeResetEligibility.Disabled);

        // The account travels with the verdict even though it may not reset: a caller that has to
        // log or audit the refusal should not have to read the row again to find out who it was.
        verdict.Account.ShouldBe(account);

        var ex = await Should.ThrowAsync<ForbiddenException>(
            () => Sut.ResolveAsync(CorporateEmail, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.AccountDisabled);
        ex.StatusCode.ShouldBe(403);
    }

    [Fact]
    public async Task AnAddressWithNoIdentityHasNoAccountAtBothEnds()
    {
        _identities.FindActiveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((BackendIdentity?)null);

        var verdict = await Sut.EvaluateAsync(CorporateEmail, CancellationToken.None);
        verdict.Eligibility.ShouldBe(BackOfficeResetEligibility.NoAccount);
        verdict.Account.ShouldBeNull();

        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.ResolveAsync(CorporateEmail, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.Unregistered);
    }

    /// <summary>
    /// An identity pointing at an account that is gone reads as no account rather than as a fault:
    /// from either caller's side there is nothing to reset, and a 500 would say the service is
    /// broken when the answer is simply no.
    /// </summary>
    [Fact]
    public async Task AnIdentityWhoseAccountIsGoneHasNoAccount()
    {
        GivenIdentity(userId: 77);
        _users.FindByIdAsync(77, Arg.Any<CancellationToken>()).Returns((BackendUser?)null);

        var verdict = await Sut.EvaluateAsync(CorporateEmail, CancellationToken.None);

        verdict.Eligibility.ShouldBe(BackOfficeResetEligibility.NoAccount);
    }

    /// <summary>
    /// Both ends refuse a non-address out loud, and both do it without touching the directory. That
    /// is what makes this refusal safe to state where <c>UNREGISTERED</c> is not: the verdict comes
    /// from the string the caller sent, so it tells them nothing they did not already know.
    /// </summary>
    [Fact]
    public async Task APhoneTargetIsRefusedByBothEndsWithoutALookup()
    {
        var evaluated = await Should.ThrowAsync<BadRequestException>(
            () => Sut.EvaluateAsync("+886912345678", CancellationToken.None));
        evaluated.ErrorCode.ShouldBe(ErrorCodes.BadRequest);

        var resolved = await Should.ThrowAsync<BadRequestException>(
            () => Sut.ResolveAsync("+886912345678", CancellationToken.None));
        resolved.ErrorCode.ShouldBe(ErrorCodes.BadRequest);

        await _identities.DidNotReceive().FindActiveAsync(
            Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    /// <summary>
    /// The address is looked up in its normalized spelling, so the casing and padding a person
    /// types cannot decide whether their own account is found. Two spellings of one mailbox
    /// resolving differently is the bug the normalizer exists to prevent, and it would present here
    /// as a reset that works for some people and silently does nothing for others.
    /// </summary>
    [Fact]
    public async Task TheTargetIsNormalizedBeforeItIsHashed()
    {
        var account = GivenAccount(BackendUserStatuses.Active);

        var verdict = await Sut.EvaluateAsync("  Alice.Chen@LionTravel.com ", CancellationToken.None);

        verdict.Eligibility.ShouldBe(BackOfficeResetEligibility.Eligible);
        verdict.Account.ShouldBe(account);
    }

    /// <summary>
    /// The masked address is what a caller may put in a log line. It exists on the verdict so that
    /// a caller which has just decided to say nothing to the client still has something safe to
    /// record - and so that no caller writes a masking rule of its own.
    /// </summary>
    [Fact]
    public async Task TheVerdictCarriesAMaskedAddressAndNotThePlainOne()
    {
        _identities.FindActiveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns((BackendIdentity?)null);

        var verdict = await Sut.EvaluateAsync(CorporateEmail, CancellationToken.None);

        verdict.MaskedTarget.ShouldBe("a***@liontravel.com");
        verdict.MaskedTarget.ShouldNotContain("alice.chen");
    }

    private BackendUser GivenAccount(string status)
    {
        GivenIdentity(userId: 12);

        var account = new BackendUser
        {
            Id = 12,
            Status = status,
            Origin = BackendUserOrigins.External,
        };

        _users.FindByIdAsync(12, Arg.Any<CancellationToken>()).Returns(account);

        return account;
    }

    private void GivenIdentity(int userId)
    {
        var hash = _protector.Hash(CorporateEmail);

        _identities.FindActiveAsync(BackendIdentityTypes.Email, hash, Arg.Any<CancellationToken>())
            .Returns(new BackendIdentity
            {
                Id = 99,
                UserId = userId,
                IdentityType = BackendIdentityTypes.Email,
                IdentifierHash = hash,
                Status = BackendIdentityStatuses.Active,
            });
    }
}
