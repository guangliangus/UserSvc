using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using UserSvc.Application.Features.SocialIdentity;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Security;

namespace UserSvc.UnitTests.SocialIdentity;

/// <summary>
/// The subject under test with its ports in place.
/// <para>
/// <b>The three provider clients are substituted and everything else is real.</b> That split is
/// the whole point of the suite: the clients are the part that needs an AppID and a secret, and
/// the account resolution behind them is the part where the bugs live. With the clients mocked,
/// every branch of every resolution - including the concurrency ones - is reachable without a
/// single credential.
/// </para>
/// <para>
/// <see cref="IdentifierProtector"/>, <see cref="OAuthStateService"/> and
/// <see cref="SocialBindingTokenService"/> are the genuine implementations, because a fake for a
/// pure function only asserts that the test's arithmetic matches itself.
/// </para>
/// </summary>
internal sealed class SocialIdentityFixture
{
    public SocialIdentityFixture()
    {
        Options = Microsoft.Extensions.Options.Options.Create(new SocialIdentityOptions
        {
            SigningKey = new string('a', 64),
            StateLifetime = TimeSpan.FromMinutes(5),
            BindingTokenLifetime = TimeSpan.FromMinutes(5),
            AllowedFirebaseProviders = ["google.com", "apple.com"],
        });

        States = new OAuthStateService(Options, Clock);
        BindingTokens = new SocialBindingTokenService(Options, Clock);
    }

    public SocialTestStore Store { get; } = new();

    public TestClock Clock { get; } = new(new DateTimeOffset(2026, 9, 2, 10, 0, 0, TimeSpan.Zero));

    public IWechatClient Wechat { get; } = Substitute.For<IWechatClient>();

    public IWechatMiniClient WechatMini { get; } = Substitute.For<IWechatMiniClient>();

    public ILineClient Line { get; } = Substitute.For<ILineClient>();

    public IFirebaseTokenVerifier Firebase { get; } = Substitute.For<IFirebaseTokenVerifier>();

    public IOptions<SocialIdentityOptions> Options { get; }

    public OAuthStateService States { get; }

    public SocialBindingTokenService BindingTokens { get; }

    /// <summary>
    /// Real, and with a fixed key: the blind index has to be reproducible inside a test so a seeded
    /// row can be found the way production finds it.
    /// </summary>
    public IdentifierProtector Protector { get; } = new(Microsoft.Extensions.Options.Options.Create(
        new IdentifierProtectionOptions
        {
            Pepper = "00112233445566778899aabbccddeeff",
            DataKey = Convert.ToBase64String(new byte[32]),
            KeyVersion = "test",
        }));

    public SocialIdentityAppService Sut => new(
        Store,
        Store,
        () => Wechat,
        () => WechatMini,
        () => Line,
        () => Firebase,
        States,
        BindingTokens,
        Protector,
        Store,
        Clock,
        Options,
        Microsoft.Extensions.Options.Options.Create(new WechatOptions
        {
            AppId = "wx-app-id",
            AppSecret = "wx-secret",
            Scope = "snsapi_userinfo",
        }),
        Microsoft.Extensions.Options.Options.Create(new LineOptions
        {
            ChannelId = "line-channel-1",
            Scope = "openid profile email",
        }),
        NullLogger<SocialIdentityAppService>.Instance);

    /// <summary>A state this fixture's own service will accept, so tests do not hand-roll one.</summary>
    public string ValidState(string deviceId = "device-1") => States.Issue(deviceId);

    /// <summary>The blind index of a provider subject, spelled the way the service spells it.</summary>
    public string HashOfSubject(string subject) => Protector.Hash(subject.Trim());

    /// <summary>The blind index of a phone number, through the shared normalizer.</summary>
    public string HashOfPhone(string phone) => Protector.Hash(
        UserSvc.Application.Features.Registration.IdentifierNormalizer.Normalize(
            UserSvc.Domain.Users.IdentityTypes.Phone, phone));

    public string HashOfEmail(string email) => Protector.Hash(
        UserSvc.Application.Features.Registration.IdentifierNormalizer.Normalize(
            UserSvc.Domain.Users.IdentityTypes.Email, email));
}
