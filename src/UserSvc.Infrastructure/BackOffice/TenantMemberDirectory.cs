using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Tenancy;
using UserSvc.Infrastructure.Persistence;

namespace UserSvc.Infrastructure.BackOffice;

/// <summary>
/// Role management's window onto tenant membership, over the membership table's own repository.
/// <para>
/// Four of the five methods are a projection of an existing repository call. The fifth,
/// <see cref="SetAdminAsync"/>, has no counterpart there and goes to the context directly: the
/// tenancy slice keeps that flag in step by mutating a tracked <see cref="TenantMember"/> it is
/// already holding, and role management never has one - it works from
/// <see cref="TenantMembershipRow"/> and knows only the id. Widening
/// <c>ITenantMemberRepository</c> for one caller's write would have put a second way to set a
/// derived flag on the slice that owns it.
/// </para>
/// </summary>
public sealed class TenantMemberDirectory(
    ITenantMemberRepository members,
    UserSvcDbContext db,
    IClock clock) : ITenantMemberDirectory
{
    public async Task<IReadOnlyList<TenantMembershipRow>> ListActiveByUserAsync(
        int userId, CancellationToken cancellationToken) =>
        [.. (await members.ListActiveByUserAsync(userId, cancellationToken)).Select(Project)];

    public async Task<IReadOnlyList<TenantMembershipRow>> ListNonRemovedByUserAsync(
        int userId, CancellationToken cancellationToken) =>
        [.. (await members.ListNonRemovedByUserIdsAsync([userId], cancellationToken)).Select(Project)];

    public async Task<TenantMembershipRow?> FindAsync(
        int userId, string tenantType, string tenantCode, CancellationToken cancellationToken)
    {
        var member = await members.FindByUserAndTenantAsync(
            userId, tenantType, tenantCode, cancellationToken);

        return member is null ? null : Project(member);
    }

    public Task<int> CountActiveAdminsAsync(
        string tenantType, string tenantCode, CancellationToken cancellationToken) =>
        members.CountActiveAdminsAsync(tenantType, tenantCode, cancellationToken);

    /// <summary>
    /// One statement rather than a load-mutate-save, so the write costs a single round trip and
    /// cannot be undone by a stale copy of the row loaded earlier in the same request. It runs on
    /// the caller's connection and therefore inside the caller's transaction, which is what the
    /// grant paths need: the flag and the bindings it is derived from commit together or not at
    /// all. <c>updated_by</c> is deliberately not written - this port carries no actor, and the
    /// change is a derivation rather than an authored edit; who caused it is in the audit row.
    /// </summary>
    public Task SetAdminAsync(int memberId, bool isAdmin, CancellationToken cancellationToken) =>
        db.TenantMembers
            .Where(member => member.Id == memberId)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(member => member.IsAdmin, isAdmin)
                    .SetProperty(member => member.UpdatedAt, clock.UtcNow),
                cancellationToken);

    private static TenantMembershipRow Project(TenantMember member) => new(
        member.Id,
        member.UserId,
        member.TenantType,
        member.TenantCode,
        member.IsAdmin,
        member.ScopeAll,
        member.DeptName,
        member.Status);
}
