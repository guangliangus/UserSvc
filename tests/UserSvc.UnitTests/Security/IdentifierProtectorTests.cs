using Microsoft.Extensions.Options;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Security;
using Xunit;

namespace UserSvc.UnitTests.Security;

/// <summary>
/// The key material, and above all <b>when</b> it is read.
/// <para>
/// This class used to decode and length-check its key in its constructor, and it is a singleton
/// that the back-office authorization snapshot provider depends on - which a middleware resolves on
/// every request. So a three-byte <c>IdentifierProtection:DataKey</c> made the constructor throw
/// while the pipeline was resolving that middleware's dependencies, and the host answered
/// <c>500 INTERNAL_ERROR</c> to <c>/health/live</c>, <c>/health/ready</c>, <c>/health/startup</c>
/// and every endpoint, authenticated or not, with a body that said only "The request could not be
/// completed."
/// </para>
/// <para>
/// What is pinned here is therefore two things at once: that constructing one is total, and that
/// the refusal, when it comes, is a 500 <see cref="ErrorCodes.NotConfigured"/> naming the setting -
/// so that an operator reading a response knows to go and look at the secret.
/// </para>
/// </summary>
public sealed class IdentifierProtectorTests
{
    /// <summary>32 bytes of base64, so the happy path is a real AES-256 key.</summary>
    private const string GoodDataKey = "ZGV2LW9ubHkta2V5LTMyLWJ5dGVzLS0tLS0tLS0tLS0=";

    private const string GoodPepper = "6465762d6f6e6c792d7065707065722d6e6f742d612d736563726574";

    /// <summary>Base64 for "ABC". Three bytes, which is the value the outage was measured with.</summary>
    private const string ThreeByteDataKey = "QUJD";

    [Fact]
    public void AProtectorWithAnUnusableKeyStillConstructs()
    {
        // The whole availability guarantee. Anything in this service's dependency graph may be
        // resolved on a path that has nothing to do with identifiers - a middleware's method
        // injection, a health check, the container's own validation - and a constructor that throws
        // turns a missing secret into an outage on all of them.
        var construct = () => new IdentifierProtector(Options.Create(new IdentifierProtectionOptions
        {
            Pepper = GoodPepper,
            DataKey = ThreeByteDataKey,
            KeyVersion = "v1",
        }));

        construct.ShouldNotThrow();
    }

    [Fact]
    public void TheSectionIsNotEvenReadUntilSomethingNeedsIt()
    {
        var options = new CountingOptions(new IdentifierProtectionOptions
        {
            Pepper = GoodPepper,
            DataKey = GoodDataKey,
            KeyVersion = "v1",
        });

        var protector = new IdentifierProtector(options);

        options.Reads.ShouldBe(0, "IOptions<T>.Value is where validation runs, so reading it during "
            + "construction is what makes construction able to fail");

        protector.Hash("0912345678");

        options.Reads.ShouldBe(1);
    }

    [Fact]
    public void TheKeyMaterialIsDecodedOnceHoweverManyCallsFollow()
    {
        var options = new CountingOptions(new IdentifierProtectionOptions
        {
            Pepper = GoodPepper,
            DataKey = GoodDataKey,
            KeyVersion = "v1",
        });

        var protector = new IdentifierProtector(options);

        protector.Hash("a");
        protector.Encrypt("b");
        _ = protector.KeyVersion;
        protector.EnsureUsable();

        options.Reads.ShouldBe(1, "deferring the read must not turn it into a per-call read - this "
            + "type is on the hottest paths in the service");
    }

    [Fact]
    public void AKeyThatIsNotThirtyTwoBytesRefusesTheCallAndNamesTheSetting()
    {
        var protector = Protector(GoodPepper, ThreeByteDataKey);

        var ex = Should.Throw<AppException>(() => protector.Hash("0912345678"));

        ex.StatusCode.ShouldBe(500, "it is our misconfiguration, and no caller can correct it");
        ex.ErrorCode.ShouldBe(
            ErrorCodes.NotConfigured,
            "not INTERNAL_ERROR: one sends an operator to the key store, the other to the source");

        ex.Message.ShouldContain("IdentifierProtection:DataKey");
        ex.Message.ShouldContain("32 bytes");

        // The length it actually decoded to. It is the fact that turns "the secret is wrong" into
        // "somebody put the wrong secret in this field", and it is safe: a usable key is always 32
        // bytes, so this number only ever describes one already known to be broken.
        ex.Message.ShouldContain("decodes to 3");

        // The name of the setting is the diagnosis; the value is a secret even when it is a broken
        // one, and this message reaches a response body.
        ex.Message.ShouldNotContain(ThreeByteDataKey);
    }

    [Fact]
    public void ADataKeyThatIsNotBase64AtAllIsTheSameKindOfRefusal()
    {
        var protector = Protector(GoodPepper, "this is not base64!!");

        var ex = Should.Throw<AppException>(() => protector.Encrypt("0912345678"));

        ex.StatusCode.ShouldBe(500);
        ex.ErrorCode.ShouldBe(ErrorCodes.NotConfigured);
        ex.Message.ShouldContain("IdentifierProtection:DataKey");
        ex.Message.ShouldNotContain("this is not base64");
    }

    [Fact]
    public void APepperThatIsNotHexIsRefusedAgainstItsOwnSettingName()
    {
        // Two settings, two names. Reporting the wrong one sends whoever is holding the secrets to
        // rotate a key that was never the problem.
        var protector = Protector("zzzz", GoodDataKey);

        var ex = Should.Throw<AppException>(() => protector.Hash("0912345678"));

        ex.ErrorCode.ShouldBe(ErrorCodes.NotConfigured);
        ex.Message.ShouldContain("IdentifierProtection:Pepper");
        ex.Message.ShouldNotContain("DataKey");
    }

    [Fact]
    public void EnsureUsableThrowsExactlyWhatARealCallWouldThrow()
    {
        // This is what the readiness probe calls, so it has to report the same fault as the request
        // path. A probe that passes while every request fails is worse than no probe.
        var protector = Protector(GoodPepper, ThreeByteDataKey);

        var probed = Should.Throw<AppException>(protector.EnsureUsable);
        var used = Should.Throw<AppException>(() => protector.Hash("0912345678"));

        probed.ErrorCode.ShouldBe(used.ErrorCode);
        probed.StatusCode.ShouldBe(used.StatusCode);
        probed.Message.ShouldBe(used.Message);
    }

    [Fact]
    public void EnsureUsableIsSilentWhenTheKeyIsFine() =>
        Should.NotThrow(Protector(GoodPepper, GoodDataKey).EnsureUsable);

    [Fact]
    public void AnEmptySectionFailsAsAnOptionsValidationExceptionWhichIsAlsoNotConfigured()
    {
        // Not this type's own refusal: an absent or empty section is caught by
        // ValidateDataAnnotations, and AppExceptionHandler already maps OptionsValidationException
        // to 500 NOT_CONFIGURED naming the members. It is asserted here so the deferral is known to
        // move that failure to the point of use as well, rather than only the length check.
        var options = new ValidatingOptions();
        var protector = new IdentifierProtector(options);

        Should.Throw<OptionsValidationException>(() => protector.Hash("0912345678"));
    }

    /// <summary>
    /// The reason the two columns exist, still working after the key material moved behind a
    /// <see cref="Lazy{T}"/>: the blind index is deterministic so a unique index and an exact
    /// lookup both work, and the ciphertext is not, so two rows holding the same identifier do not
    /// look alike.
    /// </summary>
    [Fact]
    public void AWorkingKeyHashesDeterministicallyAndRoundTripsTheCiphertext()
    {
        var protector = Protector(GoodPepper, GoodDataKey);

        protector.KeyVersion.ShouldBe("v1");
        protector.Hash("0912345678").ShouldBe(protector.Hash("0912345678"));
        protector.Hash("0912345678").ShouldNotBe(protector.Hash("0912345679"));

        var first = protector.Encrypt("0912345678");
        var second = protector.Encrypt("0912345678");

        first.ShouldNotBe(second, "a fresh nonce per call is what stops the column being a blind index");
        protector.Decrypt(first).ShouldBe("0912345678");
        protector.Decrypt(second).ShouldBe("0912345678");
    }

    private static IdentifierProtector Protector(string pepper, string dataKey) =>
        new(Options.Create(new IdentifierProtectionOptions
        {
            Pepper = pepper,
            DataKey = dataKey,
            KeyVersion = "v1",
        }));

    /// <summary>Counts how often <see cref="IOptions{TOptions}.Value"/> is read.</summary>
    private sealed class CountingOptions(IdentifierProtectionOptions value)
        : IOptions<IdentifierProtectionOptions>
    {
        public int Reads { get; private set; }

        public IdentifierProtectionOptions Value
        {
            get
            {
                Reads++;
                return value;
            }
        }
    }

    /// <summary>
    /// Fails the way <c>ValidateDataAnnotations</c> does, which is the only way an absent section
    /// can be reproduced without a host: <see cref="Options.Create{TOptions}"/> never validates.
    /// </summary>
    private sealed class ValidatingOptions : IOptions<IdentifierProtectionOptions>
    {
        public IdentifierProtectionOptions Value => throw new OptionsValidationException(
            IdentifierProtectionOptions.SectionName,
            typeof(IdentifierProtectionOptions),
            ["The DataKey field is required."]);
    }
}
