using System.Buffers.Text;
using System.Text;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.External;
using UserSvc.Infrastructure.External;
using Xunit;

namespace UserSvc.UnitTests.SocialIdentity;

/// <summary>
/// The parts of Firebase token handling that are arithmetic on strings. All of it runs without a
/// Firebase project, a credential or a network, which is why it is tested exhaustively.
/// </summary>
public sealed class FirebaseTokenClaimsTests
{
    private static string Segment(string json) => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(json));

    private static string Token(string payloadJson) => $"{Segment("{}")}.{Segment(payloadJson)}.{Segment("sig")}";

    // ------------------------------------------------------------------ shape

    [Fact]
    public void AWellFormedTokenYieldsItsPayload()
    {
        FirebaseTokenClaims.RequireWellFormed(Token("""{"email":"a@b.com"}"""))
            .ShouldBe("""{"email":"a@b.com"}""");
    }

    /// <summary>
    /// A truncated token would otherwise reach the SDK and come back as a generic parse failure
    /// indistinguishable from a bad signature - which sends whoever is debugging a broken client
    /// looking for a key-rotation problem that does not exist.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("abc.def")]
    [InlineData("a.b.c.d")]
    [InlineData("a..c")]
    [InlineData("aaaa.!!!!.cccc")]
    public void AMalformedTokenIsRefusedBeforeItReachesTheSdk(string? token)
    {
        Should.Throw<UnauthorizedException>(() => FirebaseTokenClaims.RequireWellFormed(token))
            .ErrorCode.ShouldBe(ErrorCodes.FirebaseIdTokenInvalid);
    }

    // ------------------------------------------------------------------ claims

    [Fact]
    public void TheProviderAndItsSubjectAreReadFromTheFirebaseClaim()
    {
        var identity = FirebaseTokenClaims.Read(
            """
            {
              "email": "carol@gmail.com",
              "email_verified": true,
              "name": "Carol",
              "picture": "https://pic",
              "firebase": {
                "sign_in_provider": "google.com",
                "identities": { "google.com": ["google-sub-1"], "email": ["carol@gmail.com"] }
              }
            }
            """,
            "uid-1");

        identity.Uid.ShouldBe("uid-1");
        identity.Provider.ShouldBe("google.com");
        identity.ProviderUid.ShouldBe("google-sub-1");
        identity.Email.ShouldBe("carol@gmail.com");
        identity.EmailVerified.ShouldBeTrue();
        identity.Name.ShouldBe("Carol");
        identity.Picture.ShouldBe("https://pic");
    }

    /// <summary>
    /// Every field is optional. An absent provider subject costs the stale-uid fallback; refusing
    /// the sign-in over it would be a far larger loss.
    /// </summary>
    [Theory]
    [InlineData("{}")]
    [InlineData("""{"firebase":"not-an-object"}""")]
    [InlineData("""{"firebase":{}}""")]
    public void AMissingFirebaseClaimYieldsEmptyStringsRatherThanAnError(string payload)
    {
        var identity = FirebaseTokenClaims.Read(payload, "uid-1");

        identity.Provider.ShouldBeEmpty();
        identity.ProviderUid.ShouldBeEmpty();
    }

    [Fact]
    public void AProviderWithNoIdentitiesEntryStillYieldsTheProvider()
    {
        var identity = FirebaseTokenClaims.Read(
            """{"firebase":{"sign_in_provider":"google.com"}}""", "uid-1");

        identity.Provider.ShouldBe("google.com");
        identity.ProviderUid.ShouldBeEmpty();
    }

    [Fact]
    public void TheSubjectIsTakenFromTheSignInProvidersOwnEntry()
    {
        var identity = FirebaseTokenClaims.Read(
            """
            {"firebase":{"sign_in_provider":"apple.com",
             "identities":{"google.com":["google-sub"],"apple.com":["apple-sub"]}}}
            """,
            "uid-1");

        identity.ProviderUid.ShouldBe("apple-sub");
    }

    [Fact]
    public void ANonStringSubjectIsSkipped()
    {
        var identity = FirebaseTokenClaims.Read(
            """{"firebase":{"sign_in_provider":"google.com","identities":{"google.com":[null,7,"real-sub"]}}}""",
            "uid-1");

        identity.ProviderUid.ShouldBe("real-sub");
    }

    /// <summary>
    /// Firebase writes <c>email_verified</c> as a real boolean. A string <c>"true"</c> is not it,
    /// and treating one as verified would be a silent downgrade.
    /// </summary>
    [Theory]
    [InlineData("""{"email_verified":false}""")]
    [InlineData("""{"email_verified":"true"}""")]
    [InlineData("{}")]
    public void EmailVerifiedIsFalseUnlessTheClaimIsTheBooleanTrue(string payload)
    {
        FirebaseTokenClaims.Read(payload, "uid-1").EmailVerified.ShouldBeFalse();
    }

    [Fact]
    public void AnUnparseablePayloadIsRefused()
    {
        Should.Throw<UnauthorizedException>(() => FirebaseTokenClaims.Read("not json", "uid-1"));
    }

    // ------------------------------------------------------------------ user record

    private static FirebaseIdentity Identity(
        string email = "",
        bool emailVerified = false,
        string name = "",
        string picture = "",
        string provider = "google.com") =>
        new("uid-1", provider, "sub-1", email, emailVerified, name, picture);

    [Fact]
    public void TheUserRecordOverridesWhatTheTokenSaidWhenItHasAValue()
    {
        var applied = FirebaseTokenClaims.ApplyUserRecord(
            Identity(email: "claim@example.com", name: "Claim Name"),
            new FirebaseUserProfile("verified@example.com", "Verified Name", "https://record", []));

        applied.Email.ShouldBe("verified@example.com");
        applied.Name.ShouldBe("Verified Name");
        applied.Picture.ShouldBe("https://record");
    }

    /// <summary>The record lags behind the token more often than the reverse, so a blank record
    /// field must never blank out a claim.</summary>
    [Fact]
    public void ABlankUserRecordFieldLeavesTheTokenValueAlone()
    {
        var applied = FirebaseTokenClaims.ApplyUserRecord(
            Identity(email: "claim@example.com", name: "Claim Name", picture: "https://claim"),
            new FirebaseUserProfile("   ", string.Empty, string.Empty, []));

        applied.Email.ShouldBe("claim@example.com");
        applied.Name.ShouldBe("Claim Name");
        applied.Picture.ShouldBe("https://claim");
    }

    /// <summary>
    /// Firebase writes the top-level profile at user-creation time and only refreshes the
    /// per-provider entries afterwards, so a pre-created or cross-provider-linked uid can have an
    /// empty top level while the provider that just signed in knows everything.
    /// </summary>
    [Fact]
    public void AnEmptyTopLevelFallsBackToTheProviderEntry()
    {
        var applied = FirebaseTokenClaims.ApplyUserRecord(
            Identity(),
            new FirebaseUserProfile(
                string.Empty,
                string.Empty,
                string.Empty,
                [new FirebaseProviderProfile("google.com", "g@example.com", "G Name", "https://g")]));

        applied.Email.ShouldBe("g@example.com");
        applied.Name.ShouldBe("G Name");
        applied.Picture.ShouldBe("https://g");
    }

    /// <summary>
    /// An account linked to both Apple and Google lists both, in an order nothing guarantees.
    /// Taking the first would attach the wrong address about half the time.
    /// </summary>
    [Fact]
    public void TheFallbackMatchesTheSignInProviderRatherThanTakingTheFirstEntry()
    {
        var applied = FirebaseTokenClaims.ApplyUserRecord(
            Identity(provider: "google.com"),
            new FirebaseUserProfile(
                string.Empty,
                string.Empty,
                string.Empty,
                [
                    new FirebaseProviderProfile("apple.com", "a@example.com", "A Name", "https://a"),
                    new FirebaseProviderProfile("google.com", "g@example.com", "G Name", "https://g"),
                ]));

        applied.Email.ShouldBe("g@example.com");
        applied.Name.ShouldBe("G Name");
    }

    /// <summary>
    /// <c>EmailVerified</c> describes what the credential in hand attested to; the record describes
    /// the account's state now. Letting the record raise it would mean a token that said
    /// "unverified" could sign in as verified.
    /// </summary>
    [Fact]
    public void TheUserRecordNeverChangesEmailVerified()
    {
        var applied = FirebaseTokenClaims.ApplyUserRecord(
            Identity(emailVerified: false),
            new FirebaseUserProfile("record@example.com", "R", "https://r", []));

        applied.EmailVerified.ShouldBeFalse();
    }
}
