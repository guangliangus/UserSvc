using BuildingBlocks.Core.Abstractions;
using Microsoft.AspNetCore.Http;

namespace BuildingBlocks.Web.Auth;

/// <summary>
/// Audit actor for HTTP hosts: user token → sub, client-credentials token → client_id/azp,
/// unauthenticated → "anonymous", no HTTP context (startup work) → "system".
/// </summary>
public sealed class HttpContextCurrentActor(IHttpContextAccessor httpContextAccessor) : ICurrentActor
{
    public string Actor
    {
        get
        {
            var user = httpContextAccessor.HttpContext?.User;
            if (user is null)
            {
                return SystemActor.Name;
            }

            return user.FindFirst("sub")?.Value
                ?? user.FindFirst("client_id")?.Value
                ?? user.FindFirst("azp")?.Value
                ?? (user.Identity?.IsAuthenticated == true ? user.Identity.Name ?? "authenticated" : "anonymous");
        }
    }
}
