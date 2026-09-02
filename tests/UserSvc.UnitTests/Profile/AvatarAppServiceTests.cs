using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Profile;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;
using UserSvc.Domain.Users;
using Xunit;

namespace UserSvc.UnitTests.Profile;

/// <summary>
/// The upload path, with the object store substituted. Most of what is asserted here is refusal:
/// the endpoint's job is to be hard to abuse, and every one of these cases is a real upload someone
/// will eventually send - a HEIC straight off an iPhone, a photo that is too big, and an HTML
/// document wearing a <c>.png</c> name.
/// </summary>
public sealed class AvatarAppServiceTests
{
    /// <summary>1970-01-01 plus 1_750_000_000_000 ms, so the object names below are readable.</summary>
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeMilliseconds(1_750_000_000_000);

    private static readonly Uri StoredUrl = new("https://acct.blob.core.windows.net/users/7/1750000000000.png");

    private readonly IUserRepository _users = Substitute.For<IUserRepository>();
    private readonly IObjectStorage _storage = Substitute.For<IObjectStorage>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();
    private readonly TestClock _clock = new(Now);

    public AvatarAppServiceTests() =>
        _storage
            .PutAsync(Arg.Any<string>(), Arg.Any<Stream>(), Arg.Any<ObjectHttpHeaders>(), Arg.Any<CancellationToken>())
            .Returns(StoredUrl);

    private AvatarAppService Sut => new(
        _users,
        _storage,
        new ProfileAppService(_users, _unitOfWork, _clock),
        _unitOfWork,
        _clock,
        NullLogger<AvatarAppService>.Instance);

    // --- the happy path ------------------------------------------------------------------------

    [Fact]
    public async Task APngIsStoredAndItsUrlLandsOnTheProfile()
    {
        var user = ActiveUser();

        var result = await Sut.UploadAsync(7, Upload(Png(), "image/png"), CancellationToken.None);

        user.Avatar.ShouldBe(StoredUrl.ToString());
        result.Avatar.ShouldBe(StoredUrl.ToString());
        user.UpdatedAt.ShouldBe(Now);
        await _unitOfWork.Received(1).SaveChangesAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task TheObjectNameIsTheUserIdThenTheUploadInstantThenTheExtension()
    {
        ActiveUser();

        await Sut.UploadAsync(7, Upload(Png(), "image/png"), CancellationToken.None);

        await _storage.Received(1).PutAsync(
            "7/1750000000000.png",
            Arg.Any<Stream>(),
            Arg.Any<ObjectHttpHeaders>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task TheStoredObjectCarriesTheServingHeadersTheContractPromises()
    {
        ActiveUser();
        ObjectHttpHeaders? captured = null;
        _storage
            .PutAsync(Arg.Any<string>(), Arg.Any<Stream>(), Arg.Do<ObjectHttpHeaders>(h => captured = h), Arg.Any<CancellationToken>())
            .Returns(StoredUrl);

        await Sut.UploadAsync(7, Upload(Png(), "image/png"), CancellationToken.None);

        captured.ShouldNotBeNull();
        captured.ContentType.ShouldBe("image/png");
        captured.CacheControl.ShouldBe("public, max-age=31536000");
        captured.ContentDisposition.ShouldBe("inline");
    }

    [Fact]
    public async Task TheWholeImageReachesTheStoreUnchanged()
    {
        ActiveUser();
        var sent = Png(padTo: 4096);
        byte[]? received = null;
        _storage
            .PutAsync(Arg.Any<string>(), Arg.Do<Stream>(s => received = Drain(s)), Arg.Any<ObjectHttpHeaders>(), Arg.Any<CancellationToken>())
            .Returns(StoredUrl);

        await Sut.UploadAsync(7, Upload(sent, "image/png"), CancellationToken.None);

        received.ShouldBe(sent);
    }

    // --- the bytes decide, not the header ------------------------------------------------------

    [Fact]
    public async Task TheBytesOverrideAMislabelledContentType()
    {
        ActiveUser();

        // A client that says PNG and sends JPEG is sloppy, not hostile - both are formats we
        // accept, so the upload succeeds and is stored as what it actually is.
        await Sut.UploadAsync(7, Upload(Jpeg(), "image/png"), CancellationToken.None);

        await _storage.Received(1).PutAsync(
            "7/1750000000000.jpg",
            Arg.Any<Stream>(),
            Arg.Is<ObjectHttpHeaders>(h => h.ContentType == "image/jpeg"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnHtmlDocumentNamedAsAPngIsRefusedAndNeverStored()
    {
        ActiveUser();
        var html = "<html><script>alert(document.cookie)</script></html>"u8.ToArray();

        var ex = await Should.ThrowAsync<AppException>(
            () => Sut.UploadAsync(7, Upload(html, "image/png"), CancellationToken.None));

        ex.StatusCode.ShouldBe(415);
        ex.ErrorCode.ShouldBe(ErrorCodes.InvalidFileType);
        await NothingWasStoredOrSaved();

        // The documented promise that a malformed upload costs no database round trip. Without
        // this the ordering of the sniff and the lookup is free to drift.
        await _users.DidNotReceiveWithAnyArgs().FindByIdAsync(default, default);
    }

    [Theory]
    // The formats the original's HTTP handler advertised and its storage layer then refused. They
    // are refused here too - once, at the door, with a message that names what is accepted.
    [InlineData("heic")]
    [InlineData("heif")]
    [InlineData("webp")]
    [InlineData("gif")]
    [InlineData("bmp")]
    [InlineData("empty-ish")]
    public async Task FormatsOutsideTheAllowListAreRefusedWith415(string format)
    {
        ActiveUser();

        var ex = await Should.ThrowAsync<AppException>(
            () => Sut.UploadAsync(7, Upload(Sample(format), "image/png"), CancellationToken.None));

        ex.StatusCode.ShouldBe(415);
        ex.ErrorCode.ShouldBe(ErrorCodes.InvalidFileType);
        await NothingWasStoredOrSaved();
    }

    [Fact]
    public async Task ADeclaredContentTypeOutsideTheAllowListIsRefusedBeforeTheBodyIsRead()
    {
        ActiveUser();
        var body = new ThrowingStream();

        var ex = await Should.ThrowAsync<AppException>(
            () => Sut.UploadAsync(7, new AvatarUpload(body, "image/gif", 100), CancellationToken.None));

        ex.StatusCode.ShouldBe(415);
        body.WasRead.ShouldBeFalse("a type we will never accept must cost us no body read at all");
    }

    [Theory]
    [InlineData("image/jpeg")]
    [InlineData("image/jpg")]
    [InlineData("IMAGE/JPEG")]
    [InlineData("image/png; charset=binary")]
    public async Task TheDeclaredTypeIsMatchedLenientlyBecauseClientsSpellItSeveralWays(string declared)
    {
        ActiveUser();

        await Sut.UploadAsync(7, Upload(Jpeg(), declared), CancellationToken.None);

        await _storage.Received(1).PutAsync(
            Arg.Any<string>(), Arg.Any<Stream>(), Arg.Any<ObjectHttpHeaders>(), Arg.Any<CancellationToken>());
    }

    // --- size ------------------------------------------------------------------------------------

    [Fact]
    public async Task AnOversizeDeclaredLengthIsRefusedWith413BeforeTheBodyIsRead()
    {
        ActiveUser();
        var body = new ThrowingStream();

        var ex = await Should.ThrowAsync<AppException>(
            () => Sut.UploadAsync(7, new AvatarUpload(body, "image/png", (200 * 1024) + 1), CancellationToken.None));

        ex.StatusCode.ShouldBe(413);
        ex.ErrorCode.ShouldBe(ErrorCodes.FileTooLarge);
        body.WasRead.ShouldBeFalse();
    }

    [Fact]
    public async Task SizeIsJudgedBeforeTypeWhenBothAreWrong()
    {
        ActiveUser();
        var body = new ThrowingStream();

        // The original's handler checked size first and type second, and the order is observable:
        // a 300 KB text file has to answer FILE_TOO_LARGE. Pinned because swapping these two reads
        // as a harmless reordering of two cheap guards and is not one.
        var ex = await Should.ThrowAsync<AppException>(
            () => Sut.UploadAsync(7, new AvatarUpload(body, "text/plain", (200 * 1024) + 1), CancellationToken.None));

        ex.StatusCode.ShouldBe(413);
        ex.ErrorCode.ShouldBe(ErrorCodes.FileTooLarge);
        body.WasRead.ShouldBeFalse();
    }

    [Fact]
    public async Task ABodyThatOutgrowsTheCapIsRefusedEvenWhenTheDeclaredLengthLied()
    {
        ActiveUser();
        var oversize = Png(padTo: (200 * 1024) + 1);

        // Declared length says 10 bytes; the stream delivers 200 KB and one. The cap is enforced
        // against what actually arrives, which is the only number an attacker does not choose.
        var ex = await Should.ThrowAsync<AppException>(
            () => Sut.UploadAsync(7, new AvatarUpload(new MemoryStream(oversize), "image/png", 10), CancellationToken.None));

        ex.StatusCode.ShouldBe(413);
        await NothingWasStoredOrSaved();
    }

    [Fact]
    public async Task AnImageExactlyAtTheCapIsAccepted()
    {
        ActiveUser();

        await Sut.UploadAsync(7, Upload(Png(padTo: 200 * 1024), "image/png"), CancellationToken.None);

        await _storage.Received(1).PutAsync(
            Arg.Any<string>(), Arg.Any<Stream>(), Arg.Any<ObjectHttpHeaders>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnEmptyFileIsA400RatherThanAnUnsupportedType()
    {
        ActiveUser();

        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.UploadAsync(7, Upload([], "image/png"), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.BadRequest);
        await NothingWasStoredOrSaved();
    }

    // --- the account ------------------------------------------------------------------------------

    [Fact]
    public async Task AnUnknownUserIs404AndLeavesNothingInStorage()
    {
        _users.FindByIdAsync(7, Arg.Any<CancellationToken>()).Returns((User?)null);

        var ex = await Should.ThrowAsync<NotFoundException>(
            () => Sut.UploadAsync(7, Upload(Png(), "image/png"), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.UserNotFound);
        await NothingWasStoredOrSaved();
    }

    [Fact]
    public async Task ADisabledAccountIsRefusedWith403AndLeavesNothingInStorage()
    {
        _users.FindByIdAsync(7, Arg.Any<CancellationToken>())
            .Returns(new User { Id = 7, Status = UserStatuses.Disabled });

        var ex = await Should.ThrowAsync<ForbiddenException>(
            () => Sut.UploadAsync(7, Upload(Png(), "image/png"), CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.AccountDisabled);
        await NothingWasStoredOrSaved();
    }

    [Fact]
    public async Task AStorageFailureLeavesTheProfileUntouched()
    {
        var user = ActiveUser();
        user.Avatar = "https://acct.blob.core.windows.net/users/7/old.png";
        _storage
            .PutAsync(Arg.Any<string>(), Arg.Any<Stream>(), Arg.Any<ObjectHttpHeaders>(), Arg.Any<CancellationToken>())
            .ThrowsAsyncForAnyArgs(new UpstreamException(ErrorCodes.UpstreamUnavailable, "down"));

        await Should.ThrowAsync<UpstreamException>(
            () => Sut.UploadAsync(7, Upload(Png(), "image/png"), CancellationToken.None));

        user.Avatar.ShouldBe("https://acct.blob.core.windows.net/users/7/old.png");
        await _unitOfWork.DidNotReceive().SaveChangesAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ThePreviousAvatarIsNotDeletedWhenANewOneReplacesIt()
    {
        // Documented behaviour, carried over deliberately: the port has no delete and the service
        // calls nothing but PutAsync, so the old object survives. If this ever changes, the change
        // is a decision, not a refactor.
        var user = ActiveUser();
        user.Avatar = "https://acct.blob.core.windows.net/users/7/1749999999999.png";

        await Sut.UploadAsync(7, Upload(Png(), "image/png"), CancellationToken.None);

        _storage.ReceivedCalls().Count().ShouldBe(1);
    }

    // --- the sniffer itself -------------------------------------------------------------------

    [Theory]
    [InlineData("png", "image/png")]
    [InlineData("jpeg", "image/jpeg")]
    [InlineData("gif", "image/gif")]
    [InlineData("bmp", "image/bmp")]
    [InlineData("webp", "image/webp")]
    [InlineData("heic", "image/heic")]
    [InlineData("heif", "image/heif")]
    [InlineData("html", null)]
    [InlineData("empty-ish", null)]
    public void TheSnifferNamesTheFormatFromTheLeadingBytesAlone(string format, string? expected) =>
        AvatarImageRules.Sniff(Sample(format)).ShouldBe(expected);

    [Fact]
    public void TheSnifferSurvivesABufferShorterThanEverySignature() =>
        AvatarImageRules.Sniff([0x89, 0x50]).ShouldBeNull();

    [Fact]
    public void TheSnifferSurvivesAnEmptyBuffer() =>
        AvatarImageRules.Sniff([]).ShouldBeNull();

    [Theory]
    [InlineData("image/png", "image/png")]
    [InlineData("image/jpeg", "image/jpeg")]
    [InlineData("image/jpg", "image/jpeg")]
    [InlineData("Image/PNG", "image/png")]
    [InlineData("image/gif", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void TheDeclaredTypeFoldsOntoTheTwoCanonicalSpellings(string? declared, string? expected) =>
        AvatarImageRules.NormalizeContentType(declared).ShouldBe(expected);

    // --- fixtures ---------------------------------------------------------------------------------

    private User ActiveUser()
    {
        var user = new User { Id = 7, Status = UserStatuses.Active, Nickname = "alan" };
        _users.FindByIdAsync(7, Arg.Any<CancellationToken>()).Returns(user);
        return user;
    }

    private async Task NothingWasStoredOrSaved()
    {
        await _storage.DidNotReceiveWithAnyArgs()
            .PutAsync(default!, default!, default!, default);
        await _unitOfWork.DidNotReceive().SaveChangesAsync(Arg.Any<CancellationToken>());
    }

    private static AvatarUpload Upload(byte[] content, string? contentType) =>
        new(new MemoryStream(content), contentType, content.Length);

    private static byte[] Png(int padTo = 0) =>
        Pad([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], padTo);

    private static byte[] Jpeg(int padTo = 0) => Pad([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10], padTo);

    /// <summary>Leading bytes of each format, long enough for the signatures that need 12 bytes.</summary>
    private static byte[] Sample(string format) => format switch
    {
        "png" => Png(),
        "jpeg" => Jpeg(),
        "gif" => "GIF89a\0\0\0\0\0\0"u8.ToArray(),
        "bmp" => "BM\0\0\0\0\0\0\0\0\0\0"u8.ToArray(),
        "webp" => [.. "RIFF"u8, 0, 0, 0, 0, .. "WEBPVP8 "u8],
        "heic" => [0x00, 0x00, 0x00, 0x18, .. "ftypheic"u8],
        "heif" => [0x00, 0x00, 0x00, 0x18, .. "ftypmif1"u8],
        "html" => "<!DOCTYPE html><body>hi</body>"u8.ToArray(),
        "empty-ish" => [0x00, 0x00],
        _ => throw new ArgumentOutOfRangeException(nameof(format)),
    };

    private static byte[] Pad(byte[] head, int padTo)
    {
        if (padTo <= head.Length)
        {
            return head;
        }

        var padded = new byte[padTo];
        head.CopyTo(padded, 0);
        return padded;
    }

    private static byte[] Drain(Stream stream)
    {
        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }

    /// <summary>Proves a refusal happened before anything touched the request body.</summary>
    private sealed class ThrowingStream : Stream
    {
        public bool WasRead { get; private set; }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            WasRead = true;
            throw new InvalidOperationException("The body must not be read after an early refusal.");
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
        {
            WasRead = true;
            throw new InvalidOperationException("The body must not be read after an early refusal.");
        }

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
