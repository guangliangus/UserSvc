using UserSvc.Api.Controllers.BackOffice;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Domain.Tenancy;

namespace UserSvc.Api.Auth;

/// <summary>
/// Resolves what the caller effectively holds, once per request, and leaves it where
/// <see cref="HttpContextBackOfficeCaller"/> can read it.
/// <para>
/// This is the piece that makes "the access token is an identity ticket" true rather than
/// aspirational. Authority is recomputed from the database on every request - memoised for five
/// minutes and keyed on the token version - so a permission taken away is gone on the next call
/// instead of at the next sign-in, and a context an account has since lost resolves to nothing.
/// </para>
/// <para>
/// <b>It never fails a request.</b> A caller with no context, an unknown act type or a snapshot that
/// cannot be computed all leave the face absent, which every consumer reads as "holds nothing". The
/// permission gates then refuse and the ungated endpoints - the shell, the context chooser - keep
/// working, which is exactly the split the back office needs during a cache or database wobble.
/// Turning a snapshot failure into a 500 would take down the two screens a user needs to recover.
/// </para>
/// <para>
/// It runs after authentication (there is no <c>act</c> claim before that) and before authorization,
/// beside <see cref="RevokedSessionMiddleware"/> and for the same reason.
/// </para>
/// </summary>
public sealed class BackOfficeAuthzMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(
        HttpContext context,
        IAuthzSnapshotProvider snapshots,
        ILogger<BackOfficeAuthzMiddleware> logger)
    {
        ArgumentNullException.ThrowIfNull(context);

        var caller = BackOfficeCallerReader.Read(context.User);

        if (caller.UserId > 0 && caller.Act is { } act && ActTypes.IsKnown(act.Type))
        {
            context.Items[HttpContextBackOfficeCaller.AuthzItemKey] =
                await ResolveAsync(snapshots, caller.UserId, act, caller.TokenVersion, context, logger);
        }

        await next(context);
    }

    private static async Task<EffectiveAuthz> ResolveAsync(
        IAuthzSnapshotProvider snapshots,
        int userId,
        ActClaim act,
        int tokenVersion,
        HttpContext context,
        ILogger logger)
    {
        try
        {
            var snapshot = await snapshots.GetOrComputeAsync(
                userId, act, tokenVersion, context.RequestAborted);

            return new EffectiveAuthz(
                snapshot.Roles,
                snapshot.Permissions,
                snapshot.Menus,
                snapshot.Scopes.ToDictionary(
                    entry => entry.Key,
                    entry => new Domain.Iam.ScopeClaim(entry.Value.Values, entry.Value.IsGlobal),
                    StringComparer.Ordinal));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Warning, not error, and no rethrow: failing closed is the correct handling, and this
            // line is what tells an operator that gated routes are refusing for an infrastructure
            // reason rather than a permissions one.
            logger.LogWarning(
                ex,
                "The authorization face of account {UserId} could not be resolved for {Path}; "
                + "failing closed and treating the caller as holding nothing.",
                userId,
                context.Request.Path);

            return EffectiveAuthz.Empty;
        }
    }
}
