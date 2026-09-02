using System.Globalization;
using UserSvc.Application.Errors;
using UserSvc.Application.Features.BackOffice.Rbac.Contracts;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Domain.Iam;

namespace UserSvc.Application.Features.BackOffice.Rbac;

/// <summary>The role catalogue: who may write which roles, and which roles anyone may see.</summary>
public sealed class RoleAppService(
    IRoleRepository roles,
    IRoleMenuRepository roleMenus,
    IRolePermissionRepository rolePermissions,
    IUserTenantRoleRepository bindings,
    AdminScopeService adminScopes,
    RoleVisibilityService roleVisibility,
    RoleDelegationService delegation,
    RoleGrantsAppService grants,
    IamAuditWriter audit,
    IUnitOfWork unitOfWork,
    IClock clock)
{
    /// <summary>Create a role, optionally with its initial grants.</summary>
    public async Task<RoleResponse> CreateRoleAsync(
        IBackOfficeCaller caller,
        CreateRoleRequest request,
        CancellationToken cancellationToken)
    {
        var scope = await adminScopes.AssertCanManageRolesAsync(caller, cancellationToken);
        var owner = ResolveRoleOwner(scope, request.OwnerType, request.OwnerCode);

        if (request.IsAdmin && !scope.IsSuperAdmin)
        {
            throw new BadRequestException(
                ErrorCodes.SuperAdminRequired,
                "Only the platform super administrator may create an administrator role.");
        }

        if (request.IsAdmin && owner.OwnerType != RoleOwnerTypes.System)
        {
            // Mirrors chk_roles_admin_system. Refused here with a sentence a human can act on,
            // rather than surfacing as an opaque write failure from the database.
            throw new BadRequestException(
                ErrorCodes.BadRequest,
                "An administrator role must be owned by the platform (SYSTEM).");
        }

        if (owner.OwnerType != RoleOwnerTypes.System && request.Code == IamConstants.RoleCodeAdmin)
        {
            throw new BadRequestException(
                ErrorCodes.RoleCodeReserved,
                $"Role code \"{IamConstants.RoleCodeAdmin}\" is reserved for the platform.");
        }

        // Refuse a taken code up front so the form gets a field-level answer. The loser of a create
        // race is caught by the unique index and mapped to the same soft error.
        if (await roles.ExistsByCodeAsync(request.Code, cancellationToken))
        {
            throw new ConflictException(ErrorCodes.RoleCodeExists, "Role code already exists.");
        }

        var category = ResolveRoleCategory(owner.OwnerType, request.Category);
        var parentRoleId = ResolveParentRoleId(scope, owner, request.ParentRoleId);
        await ValidateParentRoleAsync(0, parentRoleId, cancellationToken);

        var now = clock.UtcNow;
        var role = new Role
        {
            Code = request.Code,
            Name = request.Name,
            Category = category,
            Description = request.Description,
            OwnerType = owner.OwnerType,
            OwnerCode = owner.OwnerCode,
            IsAdmin = request.IsAdmin && scope.IsSuperAdmin,
            ParentRoleId = parentRoleId,
            CreatedAt = now,
            UpdatedAt = now,
            CreatedBy = AuditStamp(caller),
            UpdatedBy = AuditStamp(caller),
        };

        var hasGrants = request.MenuCodes.Count > 0 || request.PermissionCodes.Count > 0;
        if (!hasGrants)
        {
            roles.Add(role);
            await SaveTranslatingCodeConflictAsync(cancellationToken);
        }
        else
        {
            var (menuIds, _, permissionCodes) = await grants.ValidateGrantsAsync(
                caller, role, request.MenuCodes, request.PermissionCodes, cancellationToken);

            await unitOfWork.ExecuteInTransactionAsync(async ct =>
            {
                roles.Add(role);
                await SaveTranslatingCodeConflictAsync(ct);
                await roleMenus.ReplaceForRoleAsync(role.Id, menuIds, AuditStamp(caller), ct);
                await rolePermissions.ReplaceForRoleAsync(role.Id, permissionCodes, AuditStamp(caller), ct);
                await unitOfWork.SaveChangesAsync(ct);
            }, cancellationToken);
        }

        await audit.WriteAsync(
            caller,
            IamAuditActions.RoleCreate,
            IamAuditTargetTypes.Role,
            role.Id.ToString(CultureInfo.InvariantCulture),
            before: null,
            after: SnapshotOf(role, request.MenuCodes, request.PermissionCodes),
            cancellationToken);

        return ToResponse(role);
    }

    /// <summary>Edit a role's name, description and - for the platform owner only - its group.</summary>
    public async Task<RoleResponse> UpdateRoleAsync(
        IBackOfficeCaller caller,
        int roleId,
        UpdateRoleRequest request,
        CancellationToken cancellationToken)
    {
        var role = await FindRoleAsync(roleId, cancellationToken);

        // Cheap claims-only tenant guard first; the expensive scope resolution follows.
        await roleVisibility.AssertRoleVisibleAsync(caller, role, mutate: true, cancellationToken);
        var scope = await adminScopes.AssertCanManageRolesAsync(caller, cancellationToken);
        AssertOwnerWritable(scope, role, "edit a platform role");

        var before = SnapshotOf(role, menuCodes: null, permissionCodes: null);

        role.Name = request.Name;
        role.Description = request.Description;
        // Category is deliberately untouched: it is immutable, and UpdateRoleRequest has no field
        // for it.

        if (scope.IsSuperAdmin)
        {
            // Only the platform owner re-parents. A tenant role keeps the group it was filed under.
            await ValidateParentRoleAsync(role.Id, request.ParentRoleId, cancellationToken);
            await grants.AssertGrantsWithinNewParentAsync(role, request.ParentRoleId, cancellationToken);
            role.ParentRoleId = request.ParentRoleId;
        }

        role.UpdatedAt = clock.UtcNow;
        role.UpdatedBy = AuditStamp(caller);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        await audit.WriteAsync(
            caller,
            IamAuditActions.RoleUpdate,
            IamAuditTargetTypes.Role,
            role.Id.ToString(CultureInfo.InvariantCulture),
            before,
            SnapshotOf(role, menuCodes: null, permissionCodes: null),
            cancellationToken);

        return ToResponse(role);
    }

    /// <summary>Delete a role. Refused while it still leads a group or is bound to anyone.</summary>
    public async Task DeleteRoleAsync(
        IBackOfficeCaller caller,
        int roleId,
        CancellationToken cancellationToken)
    {
        var role = await FindRoleAsync(roleId, cancellationToken);
        await roleVisibility.AssertRoleVisibleAsync(caller, role, mutate: true, cancellationToken);
        var scope = await adminScopes.AssertCanManageRolesAsync(caller, cancellationToken);
        AssertOwnerWritable(scope, role, "delete a platform role");

        if (await roles.CountChildrenAsync(roleId, cancellationToken) > 0)
        {
            throw new ConflictException(ErrorCodes.RoleHasChildren, "Role still has child roles.");
        }

        if (await bindings.CountActiveByRoleIdAsync(roleId, cancellationToken) > 0)
        {
            throw new ConflictException(ErrorCodes.RoleInUse, "Role still has member bindings.");
        }

        var before = SnapshotOf(role, menuCodes: null, permissionCodes: null);
        roles.Remove(role);
        await unitOfWork.SaveChangesAsync(cancellationToken);

        await audit.WriteAsync(
            caller,
            IamAuditActions.RoleDelete,
            IamAuditTargetTypes.Role,
            roleId.ToString(CultureInfo.InvariantCulture),
            before,
            after: null,
            cancellationToken);
    }

    /// <summary>
    /// The create/edit form's duplicate-name probe.
    /// <para>
    /// Behind the <b>write</b> gate, not the list gate, because it answers across every tenant's
    /// roles - and it deliberately does not narrow to what the caller can see. A tenant administrator
    /// cannot see another tenant's roles, and telling a platform owner "available" for a name they
    /// will then find duplicated in their own full list is exactly what this check exists to prevent.
    /// What leaks is one bit, to a caller who already passed the create-role gate. It stays advisory:
    /// there is no unique index on the name.
    /// </para>
    /// </summary>
    public async Task<RoleNameExistsResponse> RoleNameExistsAsync(
        IBackOfficeCaller caller,
        string name,
        int excludeRoleId,
        CancellationToken cancellationToken)
    {
        await adminScopes.AssertCanManageRolesAsync(caller, cancellationToken);

        var trimmed = (name ?? string.Empty).Trim();
        if (trimmed.Length == 0)
        {
            // An empty name is the form's own required-field problem, not a duplicate.
            return new RoleNameExistsResponse { Exists = false };
        }

        return new RoleNameExistsResponse
        {
            Exists = await roles.ExistsByNameAsync(trimmed, excludeRoleId, cancellationToken),
        };
    }

    /// <summary>
    /// What the caller may do with roles. Open to every authenticated back-office user - failing the
    /// gate is an answer, not an error.
    /// </summary>
    public async Task<MyRoleScopeResponse> GetMyRoleScopeAsync(
        IBackOfficeCaller caller,
        CancellationToken cancellationToken)
    {
        var (scope, canManage) = await adminScopes.ResolveRoleManageScopeAsync(caller, cancellationToken);

        return new MyRoleScopeResponse
        {
            IsSuperAdmin = scope.IsSuperAdmin,
            CanManageRoles = canManage,
            Owners =
            [
                .. scope.Owners.Select(owner => new RoleScopeOwnerResponse
                {
                    OwnerType = owner.OwnerType,
                    OwnerCode = owner.OwnerCode,
                    AdminRoleIds = [.. scope.AdminRolesForOwner(owner).Select(role => role.Id)],
                }),
            ],
            AdminRoles =
            [
                .. scope.AdminRoles.Select(role => new RoleScopeAdminRoleResponse
                {
                    Id = role.Id,
                    Code = role.Code,
                    Name = role.Name,
                    OwnerType = role.OwnerType,
                    OwnerCode = role.OwnerCode,
                }),
            ],
        };
    }

    /// <summary>
    /// The role list. It carries no route permission of its own - every narrowing happens here.
    /// </summary>
    public async Task<IReadOnlyList<RoleResponse>> GetRolesAsync(
        IBackOfficeCaller caller,
        CancellationToken cancellationToken)
    {
        var catalogue = await roles.ListAllAsync(cancellationToken);

        // Built from the FULL catalogue: a child's leader may be hidden from this caller, and without
        // its code the page would render an ungrouped orphan. The code is display only.
        var codeById = catalogue.ToDictionary(role => role.Id, role => role.Code);

        var visible = await roleVisibility.ResolveVisibleRoleIdsAsync(caller, catalogue, cancellationToken);
        var rows = visible is null
            ? catalogue
            : [.. catalogue.Where(role => visible.Contains(role.Id))];

        var bindable = await ResolveBindableRoleIdsAsync(caller, cancellationToken);

        // The same narrowed scope the write path uses, so the UI offers exactly the edits the server
        // will accept.
        var (writeScope, _) = await adminScopes.ResolveRoleManageScopeAsync(caller, cancellationToken);

        var result = new List<RoleResponse>(rows.Count);
        foreach (var role in rows)
        {
            // Category gates each dimension on top of the delegation ceiling, in the same order the
            // write path applies them: a supplier role never binds to a company member however wide
            // the caller's authority, and an uncategorised legacy role binds nowhere until re-filed.
            var bindableCompany =
                (bindable.All || bindable.Company.Contains(role.Id))
                && RoleCategories.BindableTo(role.Category, TenantTypes.Company);

            var bindableSupplier =
                (bindable.All || bindable.Supplier.Contains(role.Id))
                && RoleCategories.BindableTo(role.Category, TenantTypes.Supplier);

            result.Add(ToResponse(role) with
            {
                ParentRoleCode = role.ParentRoleId is not null
                                 && codeById.TryGetValue(role.ParentRoleId.Value, out var parentCode)
                    ? parentCode
                    : null,
                Readonly = !RoleVisibilityService.RoleWritableByScope(writeScope, role),
                BindableCompany = bindableCompany,
                BindableSupplier = bindableSupplier,
                Bindable = bindableCompany || bindableSupplier,
            });
        }

        return result;
    }

    /// <summary>
    /// Which roles the caller may assign, kept <b>per dimension</b>.
    /// <para>
    /// Somebody who administers both "all companies" and "all suppliers" holds two separate subtrees,
    /// and a supplier member's candidate list must not offer the company group's child roles. Flatten
    /// them into one union and you have reproduced the gap the write path then refuses.
    /// </para>
    /// </summary>
    private async Task<(bool All, HashSet<int> Company, HashSet<int> Supplier)> ResolveBindableRoleIdsAsync(
        IBackOfficeCaller caller,
        CancellationToken cancellationToken)
    {
        var company = new HashSet<int>();
        var supplier = new HashSet<int>();

        var (tenantType, tenantCode, isTenant) = CallerFacts.Tenant(caller);
        if (isTenant)
        {
            var ids = await delegation.DelegableRoleIdsAsync(
                caller.UserId, tenantType, tenantCode, cancellationToken);

            // Only this dimension is filled. The other stays empty: member management in a tenant
            // context has been dimension-locked, so offering the other side would be a lie.
            var target = tenantType == TenantTypes.Supplier ? supplier : company;
            foreach (var id in ids)
            {
                target.Add(id);
            }

            return (false, company, supplier);
        }

        var scope = await adminScopes.ResolveAdminScopeAsync(caller, cancellationToken);
        if (scope.IsSuperAdmin)
        {
            return (true, company, supplier);
        }

        foreach (var dimension in new[] { TenantTypes.Company, TenantTypes.Supplier })
        {
            var prefix = RoleOwnerTypes.ForTenantType(dimension) + "|";
            var rootIds = CallerFacts.DedupeSort(scope.AdminRoleByOwner
                .Where(pair => pair.Key.StartsWith(prefix, StringComparison.Ordinal))
                .SelectMany(pair => pair.Value)
                .Select(role => role.Id));

            if (rootIds.Count == 0)
            {
                continue;
            }

            var descendants = await roles.ListDescendantsAsync(rootIds, cancellationToken);
            var target = dimension == TenantTypes.Supplier ? supplier : company;
            foreach (var descendant in descendants)
            {
                target.Add(descendant.Id);
            }
        }

        return (false, company, supplier);
    }

    /// <summary>Which owner a new role belongs to.</summary>
    private static RoleOwner ResolveRoleOwner(AdminScope scope, string? requestedType, string? requestedCode)
    {
        if (scope.IsSuperAdmin)
        {
            return requestedType switch
            {
                null or "" or RoleOwnerTypes.System => new RoleOwner(RoleOwnerTypes.System, null),
                RoleOwnerTypes.Company or RoleOwnerTypes.Supplier =>
                    string.IsNullOrEmpty(requestedCode) || requestedCode == IamConstants.ScopeAllSentinelCode
                        // The sentinel is not a tenant: a role owned by it would match no tenant's
                        // delegable set while looking as though it should.
                        ? throw new BadRequestException(
                            ErrorCodes.RoleOwnerRequired,
                            "Select the company or supplier this role belongs to.")
                        : new RoleOwner(requestedType, requestedCode),
                _ => throw new BadRequestException(
                    ErrorCodes.RoleOwnerNotAllowed,
                    "Owner type must be SYSTEM, COMPANY or SUPPLIER."),
            };
        }

        if (!string.IsNullOrEmpty(requestedType))
        {
            var wanted = new RoleOwner(
                requestedType,
                string.IsNullOrEmpty(requestedCode) ? null : requestedCode);

            return scope.HasOwner(wanted)
                ? wanted
                : throw new BadRequestException(
                    ErrorCodes.RoleOwnerNotAllowed,
                    "You may not create or edit roles for this company or supplier.");
        }

        return scope.Owners.Count == 1
            ? scope.Owners[0]
            : throw new BadRequestException(
                ErrorCodes.RoleOwnerRequired,
                "Select the company or supplier this role belongs to.");
    }

    /// <summary>
    /// Which category a new role gets.
    /// <para>
    /// A company may only write company roles and a supplier only supplier roles - the tenant
    /// <i>is</i> the dimension, and accepting another would create a role its own owner could never
    /// bind. The value still has to be sent and still has to agree; a mismatch is a caller bug, not
    /// something to paper over. SYSTEM roles pick freely: that is how the platform writes a template
    /// <i>for</i> suppliers.
    /// </para>
    /// </summary>
    private static string ResolveRoleCategory(string ownerType, string requested)
    {
        if (!RoleCategories.IsValid(requested))
        {
            throw new BadRequestException(
                ErrorCodes.RoleCategoryInvalid,
                "Role category must be one of platform, supplier or company.");
        }

        var pinned = RoleCategories.PinnedFor(ownerType);
        if (pinned.Length > 0 && pinned != requested)
        {
            throw new BadRequestException(
                ErrorCodes.RoleCategoryInvalid,
                $"A role owned by a {ownerType} must be categorised as {pinned}.");
        }

        return requested;
    }

    /// <summary>Which group a new role is filed under.</summary>
    private static int? ResolveParentRoleId(AdminScope scope, RoleOwner owner, int? requested)
    {
        if (scope.IsSuperAdmin)
        {
            return requested;
        }

        var candidates = scope.AdminRolesForOwner(owner);

        if (requested is not null)
        {
            return candidates.Any(role => role.Id == requested.Value)
                ? requested
                : throw new BadRequestException(
                    ErrorCodes.RoleParentInvalid,
                    "The parent role must be an administrator role you hold.");
        }

        return candidates.Count == 1
            ? candidates[0].Id
            : throw new BadRequestException(
                ErrorCodes.RoleParentInvalid,
                "Select the administrator role this role belongs to.");
    }

    /// <summary>
    /// Validate a parent link. A <c>roleId</c> of zero means create - a role that does not exist yet
    /// cannot appear in anyone's ancestor chain, so the walk is skipped.
    /// </summary>
    private async Task ValidateParentRoleAsync(int roleId, int? parentId, CancellationToken cancellationToken)
    {
        if (parentId is null)
        {
            return;
        }

        if (roleId != 0 && parentId.Value == roleId)
        {
            throw new BadRequestException(ErrorCodes.RoleParentInvalid, "A role cannot be its own parent.");
        }

        var parent = await roles.FindByIdAsync(parentId.Value, cancellationToken)
                     ?? throw new BadRequestException(ErrorCodes.RoleParentInvalid, "Parent role not found.");

        if (!parent.IsAdmin)
        {
            throw new BadRequestException(
                ErrorCodes.RoleParentInvalid, "The parent role must be an administrator role.");
        }

        if (roleId == 0)
        {
            return;
        }

        var current = parent.ParentRoleId;
        for (var depth = 0; depth < IamConstants.MaxRoleAncestorDepth && current is not null; depth++)
        {
            if (current.Value == roleId)
            {
                throw new BadRequestException(
                    ErrorCodes.RoleParentInvalid, "The parent role would form a cycle.");
            }

            var ancestor = await roles.FindByIdAsync(current.Value, cancellationToken);
            if (ancestor is null)
            {
                // A broken chain is treated as acyclic: it cannot loop back to this role.
                return;
            }

            current = ancestor.ParentRoleId;
        }
    }

    private async Task<Role> FindRoleAsync(int roleId, CancellationToken cancellationToken) =>
        await roles.FindByIdAsync(roleId, cancellationToken)
        ?? throw new NotFoundException(ErrorCodes.NotFound, "Role was not found.");

    private static void AssertOwnerWritable(AdminScope scope, Role role, string what)
    {
        if (role.OwnerType == RoleOwnerTypes.System)
        {
            if (!scope.IsSuperAdmin)
            {
                throw new BadRequestException(
                    ErrorCodes.SuperAdminRequired,
                    $"Only the platform super administrator may {what}.");
            }

            return;
        }

        AdminScopeService.AssertOwnerAllowed(scope, role);
    }

    private async Task SaveTranslatingCodeConflictAsync(CancellationToken cancellationToken)
    {
        try
        {
            await unitOfWork.SaveChangesAsync(cancellationToken);
        }
        catch (ConflictException ex) when (ex.ErrorCode == ErrorCodes.Conflict)
        {
            // The loser of a create race. The unique index is the real guarantee behind
            // ExistsByCode, and both paths must answer the client the same way.
            throw new ConflictException(ErrorCodes.RoleCodeExists, "Role code already exists.", ex);
        }
    }

    private static RoleAuditSnapshot SnapshotOf(
        Role role,
        IReadOnlyList<string>? menuCodes,
        IReadOnlyList<string>? permissionCodes) =>
        new()
        {
            Code = role.Code,
            Name = role.Name,
            OwnerType = role.OwnerType,
            OwnerCode = role.OwnerCode ?? string.Empty,
            MenuCodes = menuCodes is { Count: > 0 } ? menuCodes : null,
            PermissionCodes = permissionCodes is { Count: > 0 } ? permissionCodes : null,
        };

    private static string? AuditStamp(IBackOfficeCaller caller) =>
        caller.UserId <= 0 ? null : $"{caller.UserId}:{caller.Nickname}";

    /// <summary>Flat mapping. The list-only flags are filled by the caller.</summary>
    public static RoleResponse ToResponse(Role role) => new()
    {
        Id = role.Id,
        Code = role.Code,
        Name = role.Name,
        Category = role.Category,
        Description = role.Description ?? string.Empty,
        OwnerType = role.OwnerType,
        OwnerCode = role.OwnerCode,
        IsAdmin = role.IsAdmin,
        ParentRoleId = role.ParentRoleId,
        CreatedAt = role.CreatedAt,
        UpdatedAt = role.UpdatedAt,
    };
}
