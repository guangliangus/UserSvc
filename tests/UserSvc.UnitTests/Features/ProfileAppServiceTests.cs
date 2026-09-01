using NSubstitute;
using Shouldly;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.Profile;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;
using UserSvc.Domain.Users;
using Xunit;

namespace UserSvc.UnitTests.Features;

/// <summary>
/// Every port is substituted, so no database and no containers are involved. This is what "there
/// is a database on the other side, so it gets a port" buys: <see cref="IUserRepository"/> exists
/// not because the feature is important but because it fronts I/O.
/// </summary>
public sealed class ProfileAppServiceTests
{
    private readonly IUserRepository _users = Substitute.For<IUserRepository>();
    private readonly IUnitOfWork _unitOfWork = Substitute.For<IUnitOfWork>();
    private readonly TestClock _clock = new(new DateTimeOffset(2026, 9, 1, 12, 0, 0, TimeSpan.Zero));

    private ProfileAppService Sut => new(_users, _unitOfWork, _clock);

    [Fact]
    public async Task MissingUserProduces404()
    {
        _users.FindByIdAsync(7, Arg.Any<CancellationToken>()).Returns((User?)null);

        var ex = await Should.ThrowAsync<NotFoundException>(() => Sut.GetAsync(7, CancellationToken.None));

        ex.StatusCode.ShouldBe(404);
        ex.ErrorCode.ShouldBe(ErrorCodes.UserNotFound);
    }

    [Fact]
    public async Task UpdatingAnInactiveAccountIsRefusedWith403()
    {
        _users.FindByIdAsync(7, Arg.Any<CancellationToken>())
            .Returns(new User { Id = 7, Status = UserStatuses.Disabled });

        var ex = await Should.ThrowAsync<ForbiddenException>(
            () => Sut.UpdateAsync(7, new UpdateProfileRequest { Nickname = "x" }, CancellationToken.None));

        ex.StatusCode.ShouldBe(403);
        await _unitOfWork.DidNotReceive().SaveChangesAsync(Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task OmittedFieldsKeepTheirCurrentValue()
    {
        var user = new User
        {
            Id = 7,
            Status = UserStatuses.Active,
            FirstName = "Alan",
            Nickname = "old-nick",
        };
        _users.FindByIdAsync(7, Arg.Any<CancellationToken>()).Returns(user);

        var result = await Sut.UpdateAsync(
            7, new UpdateProfileRequest { Nickname = "new-nick" }, CancellationToken.None);

        result.Nickname.ShouldBe("new-nick");
        result.FirstName.ShouldBe("Alan", "the request omitted FirstName, so it must not be cleared");
        user.UpdatedAt.ShouldBe(_clock.UtcNow);
        await _unitOfWork.Received(1).SaveChangesAsync(Arg.Any<CancellationToken>());
    }
}
