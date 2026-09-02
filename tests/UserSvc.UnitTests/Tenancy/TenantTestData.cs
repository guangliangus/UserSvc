using UserSvc.Application.Features.BackOffice.Tenants;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Tenancy;

namespace UserSvc.UnitTests.Tenancy;

/// <summary>Shorthand for the rows these tests keep needing. Nothing here has behaviour.</summary>
internal static class TenantTestData
{
    public static BackOfficeCaller CompanyCaller(int userId = 10, string tenantCode = "C1") =>
        new(userId, "caller", new ActClaim(ActTypes.Company, tenantCode));

    public static BackOfficeCaller SupplierCaller(int userId = 10, string tenantCode = "S1") =>
        new(userId, "caller", new ActClaim(ActTypes.Supplier, tenantCode));

    public static BackOfficeCaller GlobalCaller(int userId = 10, string dimension = "") =>
        new(userId, "operator", new ActClaim(ActTypes.Global, Dimension: dimension));

    public static RoleSummary Role(
        int id,
        string code,
        bool isAdmin = false,
        string category = RoleCategories.Company,
        string ownerType = RoleOwnerTypes.System) =>
        new(id, code, code, category, isAdmin, ownerType);

    public static TenantMember Member(
        int id = 900,
        int userId = 57,
        string tenantType = TenantTypes.Company,
        string tenantCode = "C1",
        bool isAdmin = false,
        bool scopeAll = false,
        string status = TenantMemberStatuses.Active,
        string? deptName = "Sales") =>
        new()
        {
            Id = id,
            UserId = userId,
            TenantType = tenantType,
            TenantCode = tenantCode,
            IsAdmin = isAdmin,
            ScopeAll = scopeAll,
            Status = status,
            DeptName = deptName,
        };

    public static BackOfficeAccount Account(
        int id = 57,
        string status = BackOfficeAccountStates.Active,
        string origin = BackOfficeAccountStates.ExternalOrigin,
        bool isSuperAdmin = false,
        int tokenVersion = 3) =>
        new(id, "Xiaoming", "Wang", "wang.xm", "S001", status, origin, isSuperAdmin, tokenVersion, null);

    public static MenuRecord Menu(
        int id, string code, int? parentId = null, params string[] audience) =>
        new(id, code, parentId, audience.Length == 0 ? [TenantTypes.Company] : audience);

    public static PermissionRecord Permission(
        int id, string code, int? menuId = null, string status = IamCatalogStatuses.Active) =>
        new(id, code, status, menuId);
}
