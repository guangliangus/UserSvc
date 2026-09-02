namespace UserSvc.Application.Ports.Tenancy;

/// <summary>
/// What tenancy needs to know about a role. A projection rather than the IAM aggregate, so that
/// this slice does not pin the shape of a table another slice owns.
/// <para>
/// <c>Category</c> is empty, <c>platform</c>, <c>company</c> or <c>supplier</c>; an empty category
/// is a leftover from the migration that introduced categories and is bindable <b>nowhere</b> (see
/// <c>TenantRoleRules</c>). <c>IsAdmin</c> is what makes a member an administrator of the tenant
/// the role is bound in. <c>OwnerType</c> is SYSTEM | COMPANY | SUPPLIER, and only SYSTEM roles may
/// carry service-level permissions - the ones with no menu behind them.
/// </para>
/// </summary>
public sealed record RoleSummary(
    int Id,
    string Code,
    string Name,
    string Category,
    bool IsAdmin,
    string OwnerType);

/// <summary>Read side of the role catalogue.</summary>
public interface IRoleDirectory
{
    /// <summary>Roles by id. Ids with no row are simply absent from the result - a dangling
    /// binding is not an error, it is a role that was deleted out from under it.</summary>
    Task<IReadOnlyList<RoleSummary>> FindByIdsAsync(
        IReadOnlyCollection<int> roleIds, CancellationToken cancellationToken);
}
