using UserSvc.Application.Errors;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Users;

namespace UserSvc.Application.Features.Profile;

/// <summary>
/// Profile use cases. <b>No MediatR</b> (decision 05) — controllers inject this class directly,
/// and cross-cutting concerns (validation, transactions, logging) are carried by filters and
/// <see cref="IUnitOfWork"/>.
/// </summary>
public sealed class ProfileAppService(
    IUserRepository users,
    IUnitOfWork unitOfWork,
    IClock clock)
{
    public async Task<ProfileResponse> GetAsync(int userId, CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId, cancellationToken)
                   ?? throw new NotFoundException(ErrorCodes.UserNotFound, "User was not found.");

        return Map(user);
    }

    public async Task<ProfileResponse> UpdateAsync(
        int userId,
        UpdateProfileRequest request,
        CancellationToken cancellationToken)
    {
        var user = await users.FindByIdAsync(userId, cancellationToken)
                   ?? throw new NotFoundException(ErrorCodes.UserNotFound, "User was not found.");

        if (!user.IsActive())
        {
            throw new ForbiddenException(ErrorCodes.AccountDisabled, "This account is not active.");
        }

        user.FirstName = request.FirstName ?? user.FirstName;
        user.LastName = request.LastName ?? user.LastName;
        user.Nickname = request.Nickname ?? user.Nickname;
        user.ResidenceCountryCode = request.ResidenceCountryCode ?? user.ResidenceCountryCode;
        user.UpdatedAt = clock.UtcNow;

        await unitOfWork.SaveChangesAsync(cancellationToken);
        return Map(user);
    }

    private static ProfileResponse Map(Domain.Users.User user) => new()
    {
        Id = user.Id,
        FirstName = user.FirstName,
        LastName = user.LastName,
        Nickname = user.Nickname,
        Avatar = user.Avatar,
        ResidenceCountryCode = user.ResidenceCountryCode,
        Status = user.Status,
        CreatedAt = user.CreatedAt,
    };
}
