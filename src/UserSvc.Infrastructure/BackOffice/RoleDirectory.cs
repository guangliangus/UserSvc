using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Tenancy;

namespace UserSvc.Infrastructure.BackOffice;

/// <summary>
/// The tenant slice's read-only window onto the role catalogue, over the catalogue's own
/// repository.
/// <para>
/// It is a projection and nothing else: the two shapes carry the same six facts under different
/// names, so this adapter renames and drops the audit columns the tenant slice never reads. The
/// alternative - letting tenancy take <c>IRoleRepository</c> directly - would hand it twelve
/// methods including <c>Add</c> and <c>Remove</c>, which is exactly the coupling the narrow port
/// exists to prevent.
/// </para>
/// </summary>
public sealed class RoleDirectory(IRoleRepository roles) : IRoleDirectory
{
    /// <summary>
    /// Ids with no row are absent from the result rather than reported: the underlying repository
    /// already answers that way, and a dangling binding is a role deleted out from under it, not an
    /// error for the caller to handle.
    /// </summary>
    public async Task<IReadOnlyList<RoleSummary>> FindByIdsAsync(
        IReadOnlyCollection<int> roleIds, CancellationToken cancellationToken) =>
        [.. (await roles.FindByIdsAsync(roleIds, cancellationToken))
            .Select(role => new RoleSummary(
                role.Id, role.Code, role.Name, role.Category, role.IsAdmin, role.OwnerType))];
}
