using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Shouldly;
using UserSvc.Api.Controllers.BackOffice;
using UserSvc.Api.OpenApi;
using Xunit;

namespace UserSvc.ArchitectureTests;

/// <summary>
/// The two identity planes are told apart by the route prefix, guarded by a policy, and never share
/// a request or response type.
/// <para>
/// <b>Why all three are guards rather than review items.</b> The planes number their accounts
/// independently, so the only thing standing between a consumer token and a back-office endpoint is
/// the scope policy — and it was missing. <c>RbacController</c> and <c>MenuController</c> shipped
/// with a bare <c>[Authorize]</c>, which any valid token satisfies. Measured on a running host: a
/// device-grant token for consumer 1 read all 11 roles, all 39 permissions and the whole menu tree
/// at 200, and created a role at 201 — because <c>iam.backend_users</c> id 1 happens to be the
/// platform super administrator and <c>AdminScopeService</c> resolves authority from the database
/// by the caller's id. Nothing in the requests was malformed.
/// </para>
/// <para>
/// <see cref="ConsumerPlaneCallerIdTests"/> is the same rule from the other side: it keeps a
/// back-office token out of consumer endpoints. This one keeps a consumer token out of the back
/// office, and adds the prefix rule that makes "which plane is this" answerable from the URL
/// instead of from the controller's folder.
/// </para>
/// </summary>
public sealed class PlaneSeparationTests
{
    private const string BackOfficeNamespace = "UserSvc.Api.Controllers.BackOffice";
    private const string ControllerNamespaceRoot = "UserSvc.Api.Controllers";

    /// <summary>
    /// The prefix every back-office route carries. The version placeholder is spelled the way the
    /// attributes spell it, so a controller that routed itself with a literal version would fail
    /// here rather than quietly land outside the prefix rule.
    /// </summary>
    private const string BackOfficeRoutePrefix = "api/v{version:apiVersion}/" + ApiPlanes.BackOfficeSegment;

    /// <summary>
    /// The token endpoint serves both planes and is version-neutral, so it has neither prefix and
    /// belongs to neither namespace rule. It is the only route in the service like that.
    /// </summary>
    private static readonly string[] PlaneNeutralControllers = ["TokenController"];

    [Fact]
    public void EveryBackOfficeControllerRoutesUnderTheBackOfficePrefix()
    {
        foreach (var controller in Controllers().Where(IsBackOffice))
        {
            Route(controller).ShouldStartWith(
                BackOfficeRoutePrefix,
                Case.Sensitive,
                $"{controller.Name} serves the back office, so its route must say so. The prefix is "
                + "what lets a policy, a reader and the OpenAPI document splitter all agree on which "
                + "plane a route is on without opening the file. Five endpoints were moved out of "
                + "/api/v{n}/auth/ for exactly this reason.");
        }
    }

    [Fact]
    public void NoConsumerControllerRoutesUnderTheBackOfficePrefix()
    {
        foreach (var controller in Controllers().Where(c => !IsBackOffice(c) && !IsPlaneNeutral(c)))
        {
            Route(controller).StartsWith(BackOfficeRoutePrefix, StringComparison.Ordinal).ShouldBeFalse(
                $"{controller.Name} is not in the {BackOfficeNamespace} namespace but claims a "
                + "back-office route. The prefix rule only means something while the two agree: a "
                + "consumer controller sitting on that prefix would be published in the back-office "
                + "OpenAPI document and read as back office by anyone auditing the routes.");
        }
    }

    [Fact]
    public void EveryBackOfficeControllerAssertsThePlaneOrIsExplicitlyAnonymous()
    {
        foreach (var controller in Controllers().Where(IsBackOffice))
        {
            // Either the class settles it for every action, or every action settles it for itself.
            // TenantContextController is the second shape and legitimately so: the context chooser
            // takes TenantSelection, and the profile beside it takes BackOffice, so no single
            // class-level policy is correct for all three.
            var unguarded = Guards(controller)
                ? []
                : Actions(controller).Where(action => !Guards(action)).Select(a => a.Name).ToArray();

            unguarded.ShouldBeEmpty(
                $"{controller.Name} leaves {string.Join(", ", unguarded)} without a plane check. "
                + "A bare [Authorize] is not one: both planes are served by one OpenIddict instance, "
                + "so a consumer access token satisfies it, and its sub is then resolved against "
                + "iam.backend_users, which numbers its rows independently. Use "
                + $"{nameof(BackOfficePolicies)}.{nameof(BackOfficePolicies.BackOffice)}, or "
                + $"{nameof(BackOfficePolicies.TenantSelection)} for the context chooser, or "
                + "[AllowAnonymous] for a sign-in door that has no caller yet.");
        }
    }

    /// <summary>Whether this class or method states which plane it serves.</summary>
    private static bool Guards(MemberInfo member)
    {
        if (member.GetCustomAttribute<AllowAnonymousAttribute>() is not null)
        {
            return true;
        }

        var policy = member.GetCustomAttribute<AuthorizeAttribute>()?.Policy;

        return policy == BackOfficePolicies.BackOffice || policy == BackOfficePolicies.TenantSelection;
    }

    /// <summary>The controller's routed actions - methods carrying an HTTP verb attribute, which is
    /// what makes one reachable at all.</summary>
    private static IEnumerable<MethodInfo> Actions(Type controller) =>
        controller.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m => m.GetCustomAttributes<HttpMethodAttribute>().Any());

    [Fact]
    public void TheTwoPlanesShareNoRequestOrResponseType()
    {
        var consumer = ContractTypes(c => !IsBackOffice(c) && !IsPlaneNeutral(c));
        var backOffice = ContractTypes(IsBackOffice);

        var shared = consumer.Intersect(backOffice).Select(t => t.FullName).Order(StringComparer.Ordinal).ToArray();

        shared.ShouldBeEmpty(
            "A type on both planes' wires is one definition two audiences depend on, and they do not "
            + "evolve together: a field the back office needs becomes a field the mobile app must be "
            + "told to ignore, and a field the app stops sending becomes a break in an admin screen. "
            + "Give each plane its own record, even when the two are identical today. Shared: "
            + string.Join(", ", shared));
    }

    /// <summary>
    /// Types that cross the wire: what an action returns and what it binds from the body. Only
    /// types from this solution count — <c>string</c>, <c>int</c> and the framework's own result
    /// types are shared by every endpoint everywhere and say nothing about the planes.
    /// </summary>
    private static HashSet<Type> ContractTypes(Func<Type, bool> plane)
    {
        var types = new HashSet<Type>();

        foreach (var controller in Controllers().Where(plane))
        {
            foreach (var method in controller.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                Collect(method.ReturnType, types);

                foreach (var parameter in method.GetParameters())
                {
                    Collect(parameter.ParameterType, types);
                }
            }
        }

        return types;
    }

    private static void Collect(Type type, HashSet<Type> into)
    {
        if (type.IsGenericType)
        {
            foreach (var argument in type.GetGenericArguments())
            {
                Collect(argument, into);
            }

            return;
        }

        if (type.Assembly == Assemblies.Application || type.Assembly == Assemblies.Domain)
        {
            into.Add(type);
        }
    }

    private static IEnumerable<Type> Controllers() =>
        Assemblies.Api.GetTypes()
            .Where(t => t is { IsAbstract: false, IsClass: true })
            .Where(t => t.Namespace?.StartsWith(ControllerNamespaceRoot, StringComparison.Ordinal) == true)
            .Where(t => t.Name.EndsWith("Controller", StringComparison.Ordinal));

    private static bool IsBackOffice(Type controller) =>
        controller.Namespace == BackOfficeNamespace;

    private static bool IsPlaneNeutral(Type controller) =>
        PlaneNeutralControllers.Contains(controller.Name, StringComparer.Ordinal);

    private static string Route(Type controller) =>
        controller.GetCustomAttribute<RouteAttribute>()?.Template ?? string.Empty;
}
