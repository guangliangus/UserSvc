using Microsoft.Extensions.DependencyInjection;
using UserSvc.Application.Features.BackOffice.Accounts;
using UserSvc.Application.Features.Registration;
using UserSvc.Application.Security;
using UserSvc.Domain.BackOffice;
using UserSvc.Domain.Tenancy;

namespace UserSvc.IntegrationTests.Infrastructure;

/// <summary>
/// A back-office account as a test holds it: the row's id plus the two secrets a sign-in needs.
/// </summary>
/// <param name="UserId">The <c>iam.backend_users</c> id. Never a consumer id - the two planes
/// number their accounts independently, which is exactly what several of these tests are about.</param>
/// <param name="Email">The address the e-mail identity was seeded from.</param>
/// <param name="Password">The plaintext whose Argon2id hash is in the row.</param>
public sealed record SeededOperator(int UserId, string Email, string Password);

/// <summary>
/// Seeds the <c>iam</c> rows a back-office sign-in reads, straight into the tables.
/// <para>
/// <b>Written with SQL rather than through the service's own endpoints, on purpose.</b> The only
/// way to create a back-office account through HTTP is to be an administrator of a tenant already,
/// so a test that bootstrapped itself that way would need the very credential path it is trying to
/// prove. SQL states the starting position and leaves the whole sign-in flow under test.
/// </para>
/// <para>
/// <b>The two derived columns are computed by the running host's own services</b> -
/// <see cref="PasswordHasher"/> for the Argon2id PHC string and <see cref="IdentifierProtector"/>
/// for the blind index and the ciphertext - resolved out of <see cref="ServiceFixture.Services"/>.
/// A literal hash pasted in here would be a hash made with somebody else's pepper: the blind index
/// is an HMAC keyed on <c>IdentifierProtection:Pepper</c>, so a fixed value would simply never be
/// found by the lookup, and the test would fail as "unknown mailbox" for a reason that has nothing
/// to do with the code under test.
/// </para>
/// </summary>
internal static class BackOfficeSeed
{
    /// <summary>
    /// A password that satisfies every rule this service applies at sign-in - which is only a
    /// length ceiling. It is shared by every seeded account so that "the wrong password" can be a
    /// literal in a test rather than a second constant to keep in step.
    /// </summary>
    public const string Password = "Corp!Passw0rd-2026";

    /// <summary>
    /// <c>ota_tc_admin</c>, from <c>db/0007_iam_seed.sql</c>: a company-category admin role holding
    /// <c>uam.member.read</c> and <c>uam.member.manage</c>.
    /// <para>
    /// A seeded id, not a role these tests create. The catalogue is contract data applied once at
    /// fixture start and deliberately outside the between-tests truncation, so this id is stable
    /// for the whole assembly - and a test asserting on <c>uam.member.manage</c> is asserting
    /// against the grant the back office actually ships with.
    /// </para>
    /// </summary>
    public const int CompanyAdminRoleId = 88;

    /// <summary>The role code <see cref="CompanyAdminRoleId"/> carries, as the authority snapshot
    /// reports it.</summary>
    public const string CompanyAdminRoleCode = "ota_tc_admin";

    /// <summary>
    /// A corporate domain on the default <c>BackOffice:InternalDomains</c> allow-list.
    /// <para>
    /// It matters: an INTERNAL account presenting an address outside the list is refused with 403
    /// <c>INVALID_DOMAIN</c> <i>after</i> its password has verified, so a seed using
    /// <c>example.com</c> would make every happy-path test fail at the last gate.
    /// </para>
    /// </summary>
    public const string CorporateDomain = "@liontravel.com";

    /// <summary>
    /// Seeds one back-office account with an e-mail identity and, unless
    /// <paramref name="password"/> is null, a local Argon2id password.
    /// </summary>
    /// <param name="fixture">The running fixture.</param>
    /// <param name="localPart">Local part of the address; the corporate domain is appended.</param>
    /// <param name="password">Plaintext to hash into the row, or null for an account that has
    /// never registered a local password - the state the corporate one-time-password door leaves an
    /// account in, and one the password door has to refuse indistinguishably.</param>
    /// <param name="status">PENDING | ACTIVE | DISABLED.</param>
    /// <param name="origin">INTERNAL (domain gate applies) | EXTERNAL (exempt).</param>
    public static async Task<SeededOperator> OperatorAsync(
        ServiceFixture fixture,
        string localPart,
        string? password = Password,
        string status = BackendUserStatuses.Active,
        string origin = BackendUserOrigins.Internal)
    {
        ArgumentNullException.ThrowIfNull(fixture);

        var email = localPart + CorporateDomain;
        var normalized = BackOfficeIdentifiers.Normalize(BackendIdentityTypes.Email, email);

        var hasher = fixture.Services.GetRequiredService<PasswordHasher>();
        var protector = fixture.Services.GetRequiredService<IdentifierProtector>();

        var userId = await fixture.InsertReturningIdAsync(
            """
            INSERT INTO iam.backend_users
                (password_hash, first_name, last_name, nickname, staff_code, status, origin,
                 token_version, is_super_admin, created_by, updated_by)
            VALUES (@p0, 'Ada', 'Lovelace', @p1, 'E1234', @p2, @p3, 0, false, 'integration-test', 'integration-test')
            RETURNING id
            """,
            password is null ? DBNull.Value : hasher.Hash(password),
            localPart,
            status,
            origin);

        await fixture.ExecuteAsync(
            """
            INSERT INTO iam.backend_identities
                (user_id, identity_type, provider, identifier_hash, identifier_ciphertext,
                 identifier_masked, key_version, status, created_by, updated_by)
            VALUES (@p0, @p1, '', @p2, @p3, @p4, @p5, 'ACTIVE', 'integration-test', 'integration-test')
            """,
            userId,
            BackendIdentityTypes.Email,
            protector.Hash(normalized),
            protector.Encrypt(normalized),
            BackOfficeIdentifiers.Mask(BackendIdentityTypes.Email, normalized),
            protector.KeyVersion);

        return new SeededOperator(userId, email, password ?? string.Empty);
    }

    /// <summary>
    /// Makes an account a member of one tenant and, unless <paramref name="roleId"/> is null, binds
    /// a role to that membership.
    /// <para>
    /// The role binding is what produces permissions: <c>is_admin</c> on the member row buys
    /// administrator standing, and the permission gate on every managing route reads a code that
    /// only a bound role can supply. A membership with no role passes the tenant guards and is
    /// refused by the permission gate, which is a state worth being able to seed.
    /// </para>
    /// </summary>
    /// <returns>The <c>iam.tenant_members</c> id.</returns>
    public static async Task<int> MembershipAsync(
        ServiceFixture fixture,
        int userId,
        string tenantCode,
        string tenantType = TenantTypes.Company,
        bool isAdmin = true,
        int? roleId = CompanyAdminRoleId,
        string status = TenantMemberStatuses.Active)
    {
        ArgumentNullException.ThrowIfNull(fixture);

        var memberId = await fixture.InsertReturningIdAsync(
            """
            INSERT INTO iam.tenant_members
                (user_id, tenant_type, tenant_code, is_admin, scope_all, dept_name, status,
                 created_by, updated_by)
            VALUES (@p0, @p1, @p2, @p3, false, 'Operations', @p4, 'integration-test', 'integration-test')
            RETURNING id
            """,
            userId,
            tenantType,
            tenantCode,
            isAdmin,
            status);

        if (roleId is { } role)
        {
            await fixture.ExecuteAsync(
                """
                INSERT INTO iam.user_tenant_roles (member_id, role_id, created_by)
                VALUES (@p0, @p1, 'integration-test')
                """,
                memberId,
                role);
        }

        return memberId;
    }
}
