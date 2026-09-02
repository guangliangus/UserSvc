using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using UserSvc.Application.Features.BackOffice.Accounts;
using UserSvc.Application.Features.BackOffice.SignIn;
using UserSvc.Application.Features.BackOffice.Tenants;
using UserSvc.Application.Features.Registration;
using UserSvc.Application.Ports.BackOffice;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Iam;
using UserSvc.Application.Ports.Platform;
using UserSvc.Application.Ports.Tenancy;
using UserSvc.Application.Security;
using UserSvc.Domain.BackOffice;
using UserSvc.Domain.Tenancy;

namespace UserSvc.UnitTests.BackOffice.SignIn;

/// <summary>
/// The sign-in slice wired up with substituted ports.
/// <para>
/// <b>The two context services are the real ones, not fakes.</b> They are sealed, so a substitute
/// is not on offer - but that is a happy accident: the decision tree's whole job is to count what
/// the context switcher offers, and a faked switcher would let the tree agree with a list this test
/// invented rather than with the one the product computes. What is substituted is everything with a
/// database or a network behind it, plus the clock.
/// </para>
/// <para>
/// <see cref="IdentifierProtector"/>, <see cref="PasswordHasher"/> and the ticket service are also
/// the real things: the first two are pure computation, and a faked ticket would leave the
/// signature and the expiry - the parts that matter - untested.
/// </para>
/// </summary>
internal sealed class SignInTestHarness
{
    public const string CorporateEmail = "alice.chen@liontravel.com";
    public const string Password = "correct-horse-9";
    public const string StaffId = "260022";
    public const string OneTimePassword = "2449673";

    /// <summary>64 hex characters. Anything shorter is refused by the ticket service, which is one
    /// of the cases under test.</summary>
    public const string TicketKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    public SignInTestHarness()
    {
        Accounts.FindAsync(Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns(call => AccountFacade(call.ArgAt<int>(0)));

        Members.ListActiveByUserAsync(Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns(call => Memberships
                .Where(member => member.UserId == call.ArgAt<int>(0))
                .ToList());

        Members.FindByUserAndTenantAsync(
                Arg.Any<int>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(call => Memberships.FirstOrDefault(member =>
                member.UserId == call.ArgAt<int>(0)
                && member.TenantType == call.ArgAt<string>(1)
                && !member.ScopeAll
                && member.TenantCode == call.ArgAt<string>(2)));

        Catalog.ListActiveMenusAsync(Arg.Any<CancellationToken>()).Returns([]);
        Catalog.ListMenuIdsByRolesAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);
        Catalog.ListPermissionsByRolesAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>())
            .Returns([]);
        Roles.FindByIdsAsync(Arg.Any<IReadOnlyCollection<int>>(), Arg.Any<CancellationToken>()).Returns([]);
        Bindings.ListByMemberIdAsync(Arg.Any<int>(), Arg.Any<CancellationToken>()).Returns([]);
        Links.ListSupplierCodesByCompanyAsync(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns([]);

        // Null is "the master data could not be reached", which every caller reads as "no opinion".
        // It is the default here so a test that does not care about tenant deactivation does not
        // have to say so.
        MasterData.ValidateAsync(
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<CancellationToken>())
            .Returns((IReadOnlyList<TenantMasterDataEntry>?)null);

        Identities.FindActiveAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(call => IdentityRows.FirstOrDefault(row =>
                row.IdentityType == call.ArgAt<string>(0)
                && row.IdentifierHash == call.ArgAt<string>(1)
                && row.Status == BackendIdentityStatuses.Active));

        Users.FindByIdAsync(Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns(call => AccountRows.FirstOrDefault(row => row.Id == call.ArgAt<int>(0)));

        Users.ReadByIdAsync(Arg.Any<int>(), Arg.Any<CancellationToken>())
            .Returns(call => AccountRows.FirstOrDefault(row => row.Id == call.ArgAt<int>(0)));

        Users.When(repository => repository.Add(Arg.Any<BackendUser>()))
            .Do(call =>
            {
                var account = call.Arg<BackendUser>();
                account.Id = NextAccountId++;
                Inserted = account;
                AccountRows.Add(account);

                foreach (var identity in account.Identities)
                {
                    identity.UserId = account.Id;
                    IdentityRows.Add(identity);
                }
            });

        Identities.When(repository => repository.Add(Arg.Any<BackendIdentity>()))
            .Do(call => IdentityRows.Add(call.Arg<BackendIdentity>()));

        // Allowed by default. A test that wants a refusal says so, because a limiter that refused
        // everything would make every other assertion in this file pass for the wrong reason.
        Limiter.TryAcquireAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<RateLimitPolicy>(), Arg.Any<CancellationToken>())
            .Returns(call => new RateLimitDecision(true, 9, TimeSpan.Zero));

        StaffDirectory.VerifyOtpAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new StaffOtpVerification(true, "0000", string.Empty, "ok"));

        StaffDirectory.GetStaffProfileAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(new StaffProfile(StaffId, "Wang Xiaoming", "wang.xm", CorporateEmail, "A", "D01", "Sales"));
    }

    public IBackendUserRepository Users { get; } = Substitute.For<IBackendUserRepository>();

    public IBackendIdentityRepository Identities { get; } = Substitute.For<IBackendIdentityRepository>();

    public ITenantMemberRepository Members { get; } = Substitute.For<ITenantMemberRepository>();

    public IUserTenantRoleRepository Bindings { get; } = Substitute.For<IUserTenantRoleRepository>();

    public IRoleDirectory Roles { get; } = Substitute.For<IRoleDirectory>();

    public IRbacCatalog Catalog { get; } = Substitute.For<IRbacCatalog>();

    public IAdminStandingService Standing { get; } = Substitute.For<IAdminStandingService>();

    public IBackOfficeAccountDirectory Accounts { get; } = Substitute.For<IBackOfficeAccountDirectory>();

    public ISupplierCompanyLinkDirectory Links { get; } = Substitute.For<ISupplierCompanyLinkDirectory>();

    public ITenantMasterDataDirectory MasterData { get; } = Substitute.For<ITenantMasterDataDirectory>();

    public IIamAuditLog TenantAudit { get; } = Substitute.For<IIamAuditLog>();

    public IIamAuditLogRepository AuditLog { get; } = Substitute.For<IIamAuditLogRepository>();

    public IRateLimiter Limiter { get; } = Substitute.For<IRateLimiter>();

    public IStaffDirectory StaffDirectory { get; } = Substitute.For<IStaffDirectory>();

    public IUnitOfWork UnitOfWork { get; } = Substitute.For<IUnitOfWork>();

    public TestClock Clock { get; } = new(new DateTimeOffset(2026, 9, 2, 9, 0, 0, TimeSpan.Zero));

    public IdentifierProtector Protector { get; } = new(Options.Create(new IdentifierProtectionOptions
    {
        Pepper = "00112233445566778899aabbccddeeff",
        DataKey = Convert.ToBase64String(new byte[32]),
        KeyVersion = "v3",
    }));

    public PasswordHasher PasswordHasher { get; } = new();

    public BackOfficeSignInOptions SignInOptions { get; set; } = new() { SignInTicketKey = TicketKey };

    public BackOfficeAccountOptions AccountOptions { get; set; } = new();

    /// <summary>Rows the substituted repositories answer from.</summary>
    public List<BackendUser> AccountRows { get; } = [];

    public List<BackendIdentity> IdentityRows { get; } = [];

    public List<TenantMember> Memberships { get; } = [];

    /// <summary>The account handed to <c>Add</c>, as the database would see it: with the key the
    /// insert generated and its identities attached.</summary>
    public BackendUser? Inserted { get; private set; }

    private int NextAccountId { get; set; } = 500;

    public BackOfficeSignInTicketService Tickets =>
        new(Options.Create(SignInOptions), Clock);

    public TenantContextAppService Contexts =>
        new(Members, Bindings, Roles, Catalog, Standing, Accounts, Links);

    public BackOfficeContextAppService Switcher =>
        new(
            Contexts,
            Members,
            Accounts,
            MasterData,
            TenantAudit,
            Clock,
            NullLogger<BackOfficeContextAppService>.Instance);

    public BackOfficeStaffOnboarding Onboarding =>
        new(
            Users,
            Identities,
            Protector,
            UnitOfWork,
            Clock,
            NullLogger<BackOfficeStaffOnboarding>.Instance);

    public BackOfficeSignInAppService Sut =>
        new(
            Users,
            Identities,
            Onboarding,
            () => StaffDirectory,
            Contexts,
            Switcher,
            Standing,
            AuditLog,
            Limiter,
            Protector,
            PasswordHasher,
            Tickets,
            UnitOfWork,
            Clock,
            Options.Create(AccountOptions),
            Options.Create(SignInOptions),
            NullLogger<BackOfficeSignInAppService>.Instance);

    /// <summary>Adds an account with a password and an e-mail identity, the way the password door
    /// finds one.</summary>
    public BackendUser WithPasswordAccount(
        int id = 57,
        string email = CorporateEmail,
        string password = Password,
        string status = BackendUserStatuses.Active,
        string origin = BackendUserOrigins.Internal,
        int tokenVersion = 3)
    {
        var account = new BackendUser
        {
            Id = id,
            PasswordHash = PasswordHasher.Hash(password),
            FirstName = "Xiaoming",
            LastName = "Wang",
            Nickname = "wang.xm",
            StaffCode = "S001",
            Status = status,
            Origin = origin,
            TokenVersion = tokenVersion,
        };

        AccountRows.Add(account);
        AddIdentity(id, BackendIdentityTypes.Email, email);

        return account;
    }

    public BackendIdentity AddIdentity(int userId, string identityType, string identifier)
    {
        var normalized = BackOfficeIdentifiers.Normalize(identityType, identifier);
        var row = new BackendIdentity
        {
            Id = IdentityRows.Count + 1,
            UserId = userId,
            IdentityType = identityType,
            IdentifierHash = Protector.Hash(normalized),
            IdentifierCiphertext = Protector.Encrypt(normalized),
            IdentifierMasked = BackOfficeIdentifiers.Mask(identityType, normalized),
            KeyVersion = Protector.KeyVersion,
            Status = BackendIdentityStatuses.Active,
        };

        IdentityRows.Add(row);

        return row;
    }

    public TenantMember AddMembership(
        int userId = 57,
        string tenantType = TenantTypes.Company,
        string tenantCode = "C1",
        bool scopeAll = false,
        bool isAdmin = false,
        string status = TenantMemberStatuses.Active)
    {
        var member = new TenantMember
        {
            Id = Memberships.Count + 900,
            UserId = userId,
            TenantType = tenantType,
            TenantCode = scopeAll ? TenantScopes.ScopeAllSentinelCode : tenantCode,
            ScopeAll = scopeAll,
            IsAdmin = isAdmin,
            Status = status,
            DeptName = "Sales",
        };

        Memberships.Add(member);

        return member;
    }

    /// <summary>Master data that calls one tenant unusable, which is how a deactivated company is
    /// dropped from the option count.</summary>
    public void WithUnusableTenant(string tenantType, string tenantCode) =>
        MasterData.ValidateAsync(
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<IReadOnlyCollection<string>>(),
                Arg.Any<CancellationToken>())
            .Returns(new List<TenantMasterDataEntry>
            {
                new(tenantType, tenantCode, Usable: false, new Dictionary<string, string>()),
            });

    public void WithRateLimitRefusal(TimeSpan retryAfter) =>
        Limiter.TryAcquireAsync(
                Arg.Any<string>(), Arg.Any<string>(), Arg.Any<RateLimitPolicy>(), Arg.Any<CancellationToken>())
            .Returns(new RateLimitDecision(false, 0, retryAfter));

    /// <summary>The tenancy slice's view of an account row, which the context funnel reads.</summary>
    private BackOfficeAccount? AccountFacade(int userId)
    {
        var row = AccountRows.FirstOrDefault(account => account.Id == userId);

        return row is null
            ? null
            : new BackOfficeAccount(
                row.Id,
                row.FirstName ?? string.Empty,
                row.LastName ?? string.Empty,
                row.Nickname ?? string.Empty,
                row.StaffCode ?? string.Empty,
                row.Status,
                row.Origin,
                row.IsSuperAdmin,
                row.TokenVersion,
                row.LastLoginAt);
    }
}
