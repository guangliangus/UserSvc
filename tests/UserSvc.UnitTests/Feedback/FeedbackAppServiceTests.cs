using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Feedback;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Feedback;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Feedback;
using Xunit;

namespace UserSvc.UnitTests.Feedback;

/// <summary>
/// Every port is substituted, so there is no database and no storage account here. What these
/// tests are really pinning down is <b>order</b>: which checks run before which side effects, and
/// what is cleaned up when a later step fails.
/// </summary>
public sealed class FeedbackAppServiceTests
{
    private const int UserId = 7;

    private readonly IFeedbackRepository _feedback = Substitute.For<IFeedbackRepository>();
    private readonly IObjectStorage _storage = Substitute.For<IObjectStorage>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 9, 2, 8, 0, 0, TimeSpan.Zero));

    private FeedbackSubmission? _added;

    public FeedbackAppServiceTests()
    {
        _feedback.FindActiveTypeAsync("bug", Arg.Any<CancellationToken>())
            .Returns(new FeedbackType { Code = "bug", IsActive = true });

        // Stands in for the insert: PostgreSQL assigns the key, EF writes it back onto the entity.
        _feedback.When(repository => repository.Add(Arg.Any<FeedbackSubmission>()))
            .Do(call =>
            {
                _added = call.Arg<FeedbackSubmission>();
                _added.Id = 42;
            });

        _storage.PutAsync(
                Arg.Any<string>(),
                Arg.Any<Stream>(),
                Arg.Any<ObjectHttpHeaders>(),
                Arg.Any<CancellationToken>())
            .Returns(call => new Uri("https://blob.example/" + call.ArgAt<string>(0)));
    }

    private FeedbackAppService Sut =>
        new(_feedback, _storage, _unitOfWork, _clock, NullLogger<FeedbackAppService>.Instance);

    private static SubmitFeedbackRequest ValidRequest(string content = "something broke") => new()
    {
        Type = "bug",
        Content = content,
        Name = "Alice",
        Email = "alice@example.com",
    };

    // ----------------------------------------------------------------- ListTypes

    [Fact]
    public async Task LabelsResolveToTheRequestedLocaleAndFallBackToEnglish()
    {
        _feedback.ListActiveTypesAsync(Arg.Any<CancellationToken>()).Returns(
        [
            new FeedbackType { Code = "bug", Labels = """{"zh-CN":"A","en":"Bug report"}""" },
            new FeedbackType { Code = "other", Labels = """{"en":"Other"}""" },
        ]);

        var simplified = await Sut.ListTypesAsync("zh-CN", CancellationToken.None);

        simplified.Select(type => type.Label).ShouldBe(["A", "Other"],
            "the localized label wins where there is one, and English covers the row that has none");

        var japanese = await Sut.ListTypesAsync("ja", CancellationToken.None);

        japanese.Select(type => type.Label).ShouldBe(["Bug report", "Other"],
            "a locale with no label of its own falls back to English rather than disappearing");
    }

    [Fact]
    public async Task TheRepositoryOrderIsPreservedVerbatim()
    {
        _feedback.ListActiveTypesAsync(Arg.Any<CancellationToken>()).Returns(
        [
            new FeedbackType { Code = "suggestion", SortOrder = 1 },
            new FeedbackType { Code = "bug", SortOrder = 2 },
        ]);

        var types = await Sut.ListTypesAsync("en", CancellationToken.None);

        types.Select(type => type.Code).ShouldBe(["suggestion", "bug"],
            "the drop-down renders in the order the database returned, not in any order applied here");
    }

    [Fact]
    public async Task AnEmptyCatalogueIsAnEmptyListRatherThanNull()
    {
        _feedback.ListActiveTypesAsync(Arg.Any<CancellationToken>()).Returns([]);

        var types = await Sut.ListTypesAsync("en", CancellationToken.None);

        types.ShouldBeEmpty();
    }

    [Fact]
    public async Task ACategoryWhoseLabelsAreUnusableIsStillListedWithAnEmptyLabel()
    {
        // A category the submit endpoint accepts has to appear in the list it publishes, whatever
        // state its labels are in - dropping it would make the drop-down shorter than the set of
        // codes the server takes, and the person could never file that kind of feedback again.
        _feedback.ListActiveTypesAsync(Arg.Any<CancellationToken>()).Returns(
        [
            new FeedbackType { Code = "bug", Labels = "not json at all" },
            new FeedbackType { Code = "other", Labels = """{"ja":"Sonota"}""" },
        ]);

        var types = await Sut.ListTypesAsync("en", CancellationToken.None);

        types.Select(type => type.Code).ShouldBe(["bug", "other"]);
        types.ShouldAllBe(type => type.Label == string.Empty);
    }

    [Fact]
    public async Task ARepositoryFailureIsNotDressedUpAsAnEmptyCatalogue()
    {
        _feedback.ListActiveTypesAsync(Arg.Any<CancellationToken>())
            .ThrowsAsync(new InvalidOperationException("db down"));

        await Should.ThrowAsync<InvalidOperationException>(
            () => Sut.ListTypesAsync("en", CancellationToken.None));
    }

    // ----------------------------------------------------------------- Submit, happy paths

    [Fact]
    public async Task ASubmissionWithNoImagesStoresTrimmedTextAndAnEmptyJsonArray()
    {
        var response = await Sut.SubmitAsync(
            UserId, ValidRequest("  something broke  "), null, CancellationToken.None);

        response.Id.ShouldBe(42);
        response.Status.ShouldBe(FeedbackStatuses.Pending);

        _added.ShouldNotBeNull();
        _added.UserId.ShouldBe(UserId);
        _added.TypeCode.ShouldBe("bug");
        _added.Content.ShouldBe("something broke", "the stored text is trimmed, not the raw box contents");
        _added.ImageUrls.ShouldBe("[]", "no images must serialize to an empty array, never to null");
        _added.CreatedAt.ShouldBe(_clock.UtcNow);

        // The person is already named by user_id; the audit columns record that no operator typed
        // this row. Left NULL they would read as "nobody has triaged this yet", which is a
        // different fact and one the back office would act on.
        _added.CreatedBy.ShouldBe("system");
        _added.UpdatedBy.ShouldBe("system");
    }

    [Fact]
    public async Task ContactDetailsAreStoredAsTypedRatherThanTakenFromTheProfile()
    {
        var request = ValidRequest();
        request.Name = "  Someone Else  ";
        request.Email = "  someone.else@example.com  ";

        await Sut.SubmitAsync(UserId, request, null, CancellationToken.None);

        _added.ShouldNotBeNull();
        _added.Name.ShouldBe("Someone Else");
        _added.Email.ShouldBe("someone.else@example.com");
    }

    [Fact]
    public async Task TheStoredUrlsAreInTheOrderTheImagesWereAttached()
    {
        var files = new IUploadedFile[]
        {
            new InMemoryUploadedFile(ImageMagic.Jpeg),
            new InMemoryUploadedFile(ImageMagic.Png),
        };

        await Sut.SubmitAsync(UserId, ValidRequest(), files, CancellationToken.None);

        _added.ShouldNotBeNull();
        var urls = JsonSerializer.Deserialize<List<string>>(_added.ImageUrls);

        urls.ShouldNotBeNull();
        urls.Count.ShouldBe(2);
        // Photo 2 in a triage screen has to be the second photo the person attached.
        urls[0].ShouldEndWith(".jpg");
        urls[1].ShouldEndWith(".png");
    }

    [Theory]
    [InlineData("image/jpeg")]
    [InlineData("image/png")]
    [InlineData("image/webp")]
    [InlineData("image/heic")]
    [InlineData("image/heif")]
    public async Task TheContentTypeHandedToStorageIsTheSniffedOne(string expected)
    {
        var bytes = expected switch
        {
            "image/jpeg" => ImageMagic.Jpeg,
            "image/png" => ImageMagic.Png,
            "image/webp" => ImageMagic.Webp,
            "image/heic" => ImageMagic.Heic,
            _ => ImageMagic.Heif,
        };

        await Sut.SubmitAsync(
            UserId, ValidRequest(), [new InMemoryUploadedFile(bytes)], CancellationToken.None);

        await _storage.Received(1).PutAsync(
            Arg.Any<string>(),
            Arg.Any<Stream>(),
            Arg.Is<ObjectHttpHeaders>(headers => headers.ContentType == expected),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task TheObjectKeyIsScopedToTheSubmittingAccount()
    {
        await Sut.SubmitAsync(
            UserId, ValidRequest(), [new InMemoryUploadedFile(ImageMagic.Jpeg)], CancellationToken.None);

        await _storage.Received(1).PutAsync(
            Arg.Is<string>(name => name.StartsWith($"feedback/{UserId}/", StringComparison.Ordinal)),
            Arg.Any<Stream>(),
            Arg.Any<ObjectHttpHeaders>(),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ImagesAreStoredWithHeadersThatMakeThemSafeToOpenInABrowser()
    {
        await Sut.SubmitAsync(
            UserId, ValidRequest(), [new InMemoryUploadedFile(ImageMagic.Jpeg)], CancellationToken.None);

        // Content-Type is the sniffed type, so a browser has no reason to sniff for itself; inline
        // is only safe because of that check, and this assertion is what ties the two together.
        await _storage.Received(1).PutAsync(
            Arg.Any<string>(),
            Arg.Any<Stream>(),
            Arg.Is<ObjectHttpHeaders>(headers =>
                headers.ContentType == "image/jpeg" && headers.ContentDisposition == "inline"),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AnImageIsOpenedTwiceOnceToSniffAndOnceToUpload()
    {
        var file = new InMemoryUploadedFile(ImageMagic.Jpeg);

        await Sut.SubmitAsync(UserId, ValidRequest(), [file], CancellationToken.None);

        file.OpenCount.ShouldBe(2,
            "re-using the sniffing stream would upload nothing but the bytes it had already read");
    }

    // ----------------------------------------------------------------- Submit, text rules

    [Fact]
    public async Task ContentThatIsOnlyWhitespaceIsRefusedWithoutTouchingAnything()
    {
        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.SubmitAsync(UserId, ValidRequest("    "), null, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.ValidationFailed);
        await _feedback.DidNotReceive().FindActiveTypeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
        _feedback.DidNotReceive().Add(Arg.Any<FeedbackSubmission>());
    }

    [Fact]
    public async Task ContentIsCountedInCodePointsNotUtf16Units()
    {
        // 250 astral characters are 500 UTF-16 units and 250 code points. Counting the wrong one
        // refuses a caller who is at half the limit.
        var emoji = string.Concat(Enumerable.Repeat("\U0001F642", 250));

        await Sut.SubmitAsync(UserId, ValidRequest(emoji), null, CancellationToken.None);

        _added.ShouldNotBeNull();
        FeedbackLimits.RuneCount(_added.Content).ShouldBe(250);
    }

    [Theory]
    [InlineData(500, false)]
    [InlineData(501, true)]
    public async Task TheContentLimitIsInclusive(int runes, bool refused)
    {
        var text = string.Concat(Enumerable.Repeat("\U0001F642", runes));
        var submit = () => Sut.SubmitAsync(UserId, ValidRequest(text), null, CancellationToken.None);

        if (refused)
        {
            var ex = await Should.ThrowAsync<BadRequestException>(submit);
            ex.ErrorCode.ShouldBe(ErrorCodes.ValidationFailed);
        }
        else
        {
            await submit();
            _added.ShouldNotBeNull();
        }
    }

    [Fact]
    public async Task AnUnknownOrRetiredTypeIsABadRequestRatherThanANotFound()
    {
        _feedback.FindActiveTypeAsync("bug", Arg.Any<CancellationToken>()).Returns((FeedbackType?)null);

        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.SubmitAsync(UserId, ValidRequest(), null, CancellationToken.None));

        ex.StatusCode.ShouldBe(400, "the type is a field of the request, not the resource being addressed");
        ex.ErrorCode.ShouldBe(ErrorCodes.BadRequest);
        _feedback.DidNotReceive().Add(Arg.Any<FeedbackSubmission>());
    }

    // ----------------------------------------------------------------- Submit, image rules

    [Fact]
    public async Task ASixthImageIsRefusedBeforeAnyFileIsEvenOpened()
    {
        var files = Enumerable.Range(0, 6)
            .Select(_ => (IUploadedFile)new UnreadableUploadedFile(1024))
            .ToList();

        var ex = await Should.ThrowAsync<BadRequestException>(
            () => Sut.SubmitAsync(UserId, ValidRequest(), files, CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.TooManyFiles);

        // The image checks run before the category lookup on purpose: a malformed request costs no
        // query. Losing that ordering is invisible without this assertion.
        await _feedback.DidNotReceive().FindActiveTypeAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
        await _storage.DidNotReceiveWithAnyArgs().PutAsync(default!, default!, default!, default);
    }

    [Fact]
    public async Task AnOversizedImageIsRefusedOnItsDeclaredSizeWithoutReadingIt()
    {
        var ex = await Should.ThrowAsync<AppException>(() => Sut.SubmitAsync(
            UserId,
            ValidRequest(),
            [new UnreadableUploadedFile(FeedbackLimits.MaxImageBytes + 1)],
            CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.FileTooLarge);
        ex.StatusCode.ShouldBe(413, "the caller has to send a smaller file, not edit a field");
        await _storage.DidNotReceiveWithAnyArgs().PutAsync(default!, default!, default!, default);
    }

    [Fact]
    public async Task AnImageOfExactlyTheLimitIsAccepted()
    {
        var bytes = new byte[FeedbackLimits.MaxImageBytes];
        ImageMagic.Jpeg.CopyTo(bytes, 0);

        await Sut.SubmitAsync(
            UserId, ValidRequest(), [new InMemoryUploadedFile(bytes)], CancellationToken.None);

        _added.ShouldNotBeNull();
    }

    [Fact]
    public async Task AFileIsJudgedOnItsBytesNotOnItsDeclaredType()
    {
        // The part would have declared image/png. Nothing in this service ever looks at that.
        var ex = await Should.ThrowAsync<AppException>(() => Sut.SubmitAsync(
            UserId, ValidRequest(), [new InMemoryUploadedFile(ImageMagic.PlainText)], CancellationToken.None));

        ex.ErrorCode.ShouldBe(ErrorCodes.InvalidFileType);
        ex.StatusCode.ShouldBe(415, "the payload's type is what is wrong, and the avatar route agrees");
        await _storage.DidNotReceiveWithAnyArgs().PutAsync(default!, default!, default!, default);
    }

    // ----------------------------------------------------------------- Submit, unwinding

    [Fact]
    public async Task AFailedUploadDeletesTheOnesThatAlreadySucceededAndWritesNoRow()
    {
        _storage.PutAsync(
                Arg.Any<string>(),
                Arg.Any<Stream>(),
                Arg.Is<ObjectHttpHeaders>(headers => headers.ContentType == "image/png"),
                Arg.Any<CancellationToken>())
            .ThrowsAsync(new InvalidOperationException("upload boom"));

        var files = new IUploadedFile[]
        {
            new InMemoryUploadedFile(ImageMagic.Jpeg),
            new InMemoryUploadedFile(ImageMagic.Png),
        };

        await Should.ThrowAsync<InvalidOperationException>(
            () => Sut.SubmitAsync(UserId, ValidRequest(), files, CancellationToken.None));

        await _storage.Received(1).DeleteAsync(
            Arg.Is<string>(name => name.EndsWith(".jpg", StringComparison.Ordinal)), Arg.Any<CancellationToken>());

        // Deleted by object name, not by URL. The port hands back only a URL, so the name the
        // service composed is the one thing that can address the object again - passing the URL
        // here would delete nothing and report success.
        await _storage.DidNotReceive().DeleteAsync(
            Arg.Is<string>(name => name.StartsWith("https://", StringComparison.Ordinal)), Arg.Any<CancellationToken>());

        _feedback.DidNotReceive().Add(Arg.Any<FeedbackSubmission>());
    }

    [Fact]
    public async Task AFailedInsertDeletesEveryImageThisRequestUploaded()
    {
        _unitOfWork.SaveChangesAsync(Arg.Any<CancellationToken>())
            .ThrowsAsync(new InvalidOperationException("constraint violated"));

        var files = new IUploadedFile[]
        {
            new InMemoryUploadedFile(ImageMagic.Jpeg),
            new InMemoryUploadedFile(ImageMagic.Png),
        };

        await Should.ThrowAsync<InvalidOperationException>(
            () => Sut.SubmitAsync(UserId, ValidRequest(), files, CancellationToken.None));

        await _storage.Received(2).DeleteAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task AFailedCleanupDoesNotReplaceTheErrorTheCallerNeedsToSee()
    {
        _unitOfWork.SaveChangesAsync(Arg.Any<CancellationToken>())
            .ThrowsAsync(new InvalidOperationException("constraint violated"));
        _storage.DeleteAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .ThrowsAsync(new TimeoutException("storage is down too"));

        var ex = await Should.ThrowAsync<InvalidOperationException>(() => Sut.SubmitAsync(
            UserId, ValidRequest(), [new InMemoryUploadedFile(ImageMagic.Jpeg)], CancellationToken.None));

        ex.Message.ShouldBe("constraint violated",
            "a leaked object costs storage; a lost error costs an afternoon");
    }
}
