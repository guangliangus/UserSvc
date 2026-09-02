using Shouldly;
using UserSvc.Domain.Auth;
using Xunit;

namespace UserSvc.UnitTests.Passkeys;

/// <summary>
/// The clone rule, on its own, as a table.
/// <para>
/// It is tested separately from the verifier because it is the copy of the rule that survives
/// changing FIDO2 libraries. The four rows below are the whole of it, and each one is a real
/// authenticator population: counting authenticators that advance, counting authenticators that
/// have been copied, and the very large group that reports a constant zero because a monotonic
/// counter is a cross-site correlation handle.
/// </para>
/// </summary>
public sealed class UserPasskeyTests
{
    [Theory]
    // A counting authenticator, used again: normal.
    [InlineData(5L, 6L, false)]
    // Same counter twice. A counting authenticator increments before it signs, so this is two
    // devices holding one key - not one device signing twice.
    [InlineData(5L, 5L, true)]
    // Backwards: a clone restored from an older backup of the key material.
    [InlineData(5L, 3L, true)]
    // An authenticator that does not count, on its first use and on every use after.
    [InlineData(0L, 0L, false)]
    // A counting authenticator's first use against a stored zero.
    [InlineData(0L, 1L, false)]
    // A previously counting authenticator that now reports zero. Not treated as a clone: zero is
    // the documented "I do not count" answer, and refusing it would lock out a user whose
    // authenticator was replaced or whose credential was migrated to one that does not count.
    [InlineData(5L, 0L, false)]
    public void TheCloneRuleFiresOnlyWhenBothCountersAreCounting(long stored, long presented, bool isClone) =>
        UserPasskey.IndicatesClone(stored, presented).ShouldBe(isClone);

    [Fact]
    public void RecordingAnAssertionAdvancesTheCounterAndStampsTheUse()
    {
        var now = new DateTimeOffset(2026, 9, 1, 12, 0, 0, TimeSpan.Zero);
        var passkey = new UserPasskey { SignCount = 5, BackupState = false };

        passkey.RecordAssertion(9, backupState: true, now).ShouldBeTrue();

        passkey.SignCount.ShouldBe(9);
        passkey.BackupState.ShouldBeTrue("the BS flag changes over a credential's life and is rewritten every login");
        passkey.LastUsedAt.ShouldBe(now);
        passkey.UpdatedAt.ShouldBe(now);
    }

    [Fact]
    public void RecordingACloneChangesNothingAtAll()
    {
        var now = new DateTimeOffset(2026, 9, 1, 12, 0, 0, TimeSpan.Zero);
        var passkey = new UserPasskey { SignCount = 5, BackupState = false, LastUsedAt = null };

        passkey.RecordAssertion(4, backupState: true, now).ShouldBeFalse();

        // Not even the last-used stamp: the login did not happen. Leaving the counter alone also
        // matters - lowering it towards the clone's value would let the clone win next time.
        passkey.SignCount.ShouldBe(5);
        passkey.BackupState.ShouldBeFalse();
        passkey.LastUsedAt.ShouldBeNull();
    }

    [Fact]
    public void AZeroCounterNeverWindsAnAdvancedCounterBack()
    {
        var passkey = new UserPasskey { SignCount = 7 };

        passkey.RecordAssertion(0, backupState: false, DateTimeOffset.UnixEpoch).ShouldBeTrue();

        // The assertion is accepted - zero is legitimate - but the stored high-water mark stands,
        // so a real clone cannot get a clean slate by claiming not to count.
        passkey.SignCount.ShouldBe(7);
    }

    [Fact]
    public void AnEmptyLabelFallsBackToTheDefaultRatherThanBlankingTheRow()
    {
        var passkey = new UserPasskey { Name = "iPhone" };

        passkey.Rename("   ", DateTimeOffset.UnixEpoch);

        passkey.Name.ShouldBe(UserPasskey.DefaultName);
    }
}
