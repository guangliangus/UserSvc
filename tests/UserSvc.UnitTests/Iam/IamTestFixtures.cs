using System.Text.Json;
using UserSvc.Application.Ports.Iam;
using UserSvc.Domain.Iam;

namespace UserSvc.UnitTests.Iam;

/// <summary>Builders shared by the IAM tests. Every port is substituted, so none of this touches a
/// database.</summary>
internal static class Fixtures
{
    public static Role Role(
        int id,
        string code,
        bool isAdmin = false,
        string ownerType = RoleOwnerTypes.System,
        string? ownerCode = null,
        int? parentRoleId = null,
        string category = RoleCategories.Company) => new()
    {
        Id = id,
        Code = code,
        Name = code,
        Category = category,
        OwnerType = ownerType,
        OwnerCode = ownerCode,
        IsAdmin = isAdmin,
        ParentRoleId = parentRoleId,
    };

    public static Menu Menu(
        int id,
        string code,
        int? parentId = null,
        int sortOrder = 0,
        string status = MenuStatuses.Active) => new()
    {
        Id = id,
        Code = code,
        ParentId = parentId,
        Name = JsonSerializer.Serialize(new Dictionary<string, string> { ["en"] = code }),
        SortOrder = sortOrder,
        Status = status,
    };

    public static Permission Permission(
        int id,
        string code,
        int? menuId = null,
        string status = PermissionStatuses.Active) => new()
    {
        Id = id,
        Code = code,
        Name = code,
        Module = "uam",
        Status = status,
        MenuId = menuId,
    };

    public static TenantMembershipRow Membership(
        int id,
        int userId,
        string tenantType = TenantTypes.Company,
        string tenantCode = "C1",
        bool isAdmin = false,
        bool scopeAll = false,
        string status = TenantMembershipStatuses.Active) =>
        new(id, userId, tenantType, tenantCode, isAdmin, scopeAll, null, status);
}

/// <summary>A back-office caller under test control.</summary>
internal sealed class FakeCaller : IBackOfficeCaller
{
    public int UserId { get; init; }

    public string Nickname { get; init; } = "tester";

    public string ActType { get; init; } = ActTypes.Platform;

    public string ActCode { get; init; } = string.Empty;

    public string ActDim { get; init; } = string.Empty;

    public string? IpAddress => "127.0.0.1";

    public string? RequestId => "req-1";

    public EffectiveAuthz Authz { get; init; } = EffectiveAuthz.Empty;

    public static FakeCaller Tenant(int userId, string tenantType, string tenantCode) => new()
    {
        UserId = userId,
        ActType = tenantType == TenantTypes.Supplier ? ActTypes.Supplier : ActTypes.Company,
        ActCode = tenantCode,
    };

    public static FakeCaller Global(int userId, string dimension) => new()
    {
        UserId = userId,
        ActType = ActTypes.Global,
        ActCode = IamConstants.ScopeAllSentinelCode,
        ActDim = dimension,
    };

    public FakeCaller Holding(
        IReadOnlyList<string>? menus = null,
        IReadOnlyList<string>? permissions = null,
        IReadOnlyDictionary<string, ScopeClaim>? scopes = null) =>
        new()
        {
            UserId = UserId,
            Nickname = Nickname,
            ActType = ActType,
            ActCode = ActCode,
            ActDim = ActDim,
            Authz = new EffectiveAuthz(
                [],
                permissions ?? [],
                menus ?? [],
                scopes ?? new Dictionary<string, ScopeClaim>(StringComparer.Ordinal)),
        };
}
