using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Shouldly;
using UserSvc.Domain.BackOffice;
using UserSvc.Infrastructure.Persistence;
using Xunit;

namespace UserSvc.UnitTests.BackOffice;

/// <summary>
/// Pins the EF model for the two <c>iam</c> account tables against the live database's own shape,
/// column by column.
/// <para>
/// <b>This file exists because a model can drift from a database without anything failing.</b> The
/// six partial unique indexes on <c>backend_identities</c> were configured with the property-list
/// overload of <c>HasIndex</c>, which identifies an index by the columns it covers - so three calls
/// over the same two columns configured one index three times and the last one silently won. The
/// model carried two of the six, every behavioural test still passed, and a database created from
/// it would have let two accounts claim the same mailbox. Only a test that counts them catches
/// that.
/// </para>
/// <para>
/// The expectations below are transcribed from a read of the live database, not from the porting
/// specs, which are the stale side on schema. Nothing here touches a server: the model is built
/// offline from a connection string that is never opened.
/// </para>
/// </summary>
public sealed class BackOfficeSchemaParityTests
{
    private static UserSvcDbContext BuildContext()
    {
        var options = new DbContextOptionsBuilder<UserSvcDbContext>()
            // Never opened - EF builds the model from the configurations alone, and the provider is
            // needed only so that column types and index filters resolve the way they will in
            // production.
            .UseNpgsql("Host=schema-parity;Database=none")
            .UseSnakeCaseNamingConvention()
            .Options;

        return new UserSvcDbContext(options);
    }

    /// <summary>
    /// The <b>design-time</b> model, not <c>context.Model</c>. The runtime model is trimmed of
    /// everything queries do not need - check constraints among it - and asking it for a constraint
    /// throws rather than answering "none", which would have read here as a passing test.
    /// </summary>
    private static IEntityType EntityType<TEntity>()
    {
        using var context = BuildContext();

        return context.GetService<IDesignTimeModel>().Model.FindEntityType(typeof(TEntity))
               ?? throw new InvalidOperationException($"{typeof(TEntity).Name} is not in the model.");
    }

    /// <summary>Column name, store type and nullability for every column of the live table, in the
    /// live table's own order.</summary>
    public static TheoryData<string, string, bool> BackendUserColumns => new()
    {
        { "id", "integer", false },
        { "password_hash", "text", true },
        { "first_name", "text", true },
        { "last_name", "text", true },
        { "nickname", "text", true },
        { "avatar", "text", true },
        { "staff_code", "text", true },
        { "dept_no", "text", true },
        { "dept_name", "text", true },
        { "status", "text", false },
        { "last_login_at", "timestamp with time zone", true },
        { "created_at", "timestamp with time zone", false },
        { "updated_at", "timestamp with time zone", false },
        { "created_by", "text", true },
        { "updated_by", "text", true },
        { "is_super_admin", "boolean", false },
        { "origin", "text", false },
        { "token_version", "integer", false },
    };

    [Theory]
    [MemberData(nameof(BackendUserColumns))]
    public void BackendUserColumnsMatchTheLiveTable(string column, string storeType, bool nullable)
    {
        var property = EntityType<BackendUser>().GetProperties()
            .SingleOrDefault(candidate => candidate.GetColumnName() == column);

        property.ShouldNotBeNull($"iam.backend_users.{column} is missing from the model.");
        property.GetColumnType().ShouldBe(storeType);
        property.IsNullable.ShouldBe(nullable);
    }

    /// <summary>Same for the identity table. <c>provider_details</c> is jsonb and must stay jsonb -
    /// flattening a provider's payload into text columns would make every upstream change a
    /// migration.</summary>
    public static TheoryData<string, string, bool> BackendIdentityColumns => new()
    {
        { "id", "integer", false },
        { "user_id", "integer", false },
        { "identity_type", "text", false },
        { "provider", "text", false },
        { "provider_uid", "text", true },
        { "identifier_hash", "text", false },
        { "identifier_ciphertext", "text", false },
        { "identifier_masked", "text", false },
        { "key_version", "text", false },
        { "provider_details", "jsonb", true },
        { "status", "text", false },
        { "created_at", "timestamp with time zone", false },
        { "updated_at", "timestamp with time zone", false },
        { "created_by", "text", true },
        { "updated_by", "text", true },
    };

    [Theory]
    [MemberData(nameof(BackendIdentityColumns))]
    public void BackendIdentityColumnsMatchTheLiveTable(string column, string storeType, bool nullable)
    {
        var property = EntityType<BackendIdentity>().GetProperties()
            .SingleOrDefault(candidate => candidate.GetColumnName() == column);

        property.ShouldNotBeNull($"iam.backend_identities.{column} is missing from the model.");
        property.GetColumnType().ShouldBe(storeType);
        property.IsNullable.ShouldBe(nullable);
    }

    [Fact]
    public void NeitherTableCarriesAColumnTheLiveDatabaseDoesNot()
    {
        // xmin is EF's concurrency token, not a column of ours; it is filtered out the same way a
        // schema diff would ignore a system column.
        EntityType<BackendUser>().GetProperties()
            .Select(property => property.GetColumnName())
            .Where(column => column != "xmin")
            .OrderBy(column => column, StringComparer.Ordinal)
            .ShouldBe(
                BackendUserColumns.Select(row => (string)row[0]!)
                    .OrderBy(column => column, StringComparer.Ordinal));

        EntityType<BackendIdentity>().GetProperties()
            .Select(property => property.GetColumnName())
            .Where(column => column != "xmin")
            .OrderBy(column => column, StringComparer.Ordinal)
            .ShouldBe(
                BackendIdentityColumns.Select(row => (string)row[0]!)
                    .OrderBy(column => column, StringComparer.Ordinal));
    }

    [Fact]
    public void BothTablesLandInTheIamSchemaAndNotBesideTheConsumerTables()
    {
        EntityType<BackendUser>().GetSchema().ShouldBe("iam");
        EntityType<BackendIdentity>().GetSchema().ShouldBe("iam");
        EntityType<BackendUser>().GetTableName().ShouldBe("backend_users");
        EntityType<BackendIdentity>().GetTableName().ShouldBe("backend_identities");
    }

    /// <summary>
    /// <b>The regression this file was written for.</b> Six partial unique indexes, in two families
    /// of three, each under the name the live database gives it. The property-list overload of
    /// <c>HasIndex</c> collapses a family into one index without a word of warning, so the count and
    /// the names are both asserted - a count alone would pass on six indexes with EF's generated
    /// names, which is a different database from the live one.
    /// </summary>
    [Fact]
    public void TheIdentityTableCarriesAllSevenLiveIndexes()
    {
        var indexes = EntityType<BackendIdentity>().GetIndexes()
            .ToDictionary(index => index.GetDatabaseName() ?? string.Empty, StringComparer.Ordinal);

        indexes.Keys.Order(StringComparer.Ordinal).ShouldBe(
        [
            "idx_backend_identity_unique_email_active",
            "idx_backend_identity_unique_otp_active",
            "idx_backend_identity_unique_phone_active",
            "idx_backend_identity_user",
            "idx_backend_identity_user_email_active",
            "idx_backend_identity_user_otp_active",
            "idx_backend_identity_user_phone_active",
        ]);

        indexes["idx_backend_identity_user"].IsUnique.ShouldBeFalse();

        foreach (var name in indexes.Keys.Where(key => key.EndsWith("_active", StringComparison.Ordinal)))
        {
            indexes[name].IsUnique.ShouldBeTrue($"{name} is what makes the address exclusive.");
            indexes[name].GetFilter().ShouldNotBeNullOrEmpty(
                $"{name} must stay filtered on ACTIVE, or a revoked identity would keep its address.");
        }

        // One family keys on the address, the other on the account. Neither implies the other, and
        // a refactor that kept only one would look correct in every behavioural test.
        indexes["idx_backend_identity_unique_email_active"]!.Properties
            .Select(property => property.GetColumnName())
            .ShouldBe(["identity_type", "identifier_hash"]);

        indexes["idx_backend_identity_user_email_active"].Properties
            .Select(property => property.GetColumnName())
            .ShouldBe(["user_id", "identity_type"]);
    }

    [Fact]
    public void TheAccountTableCarriesTheLiveStatusIndexAndNoOther()
    {
        var indexes = EntityType<BackendUser>().GetIndexes().ToList();

        indexes.Select(index => index.GetDatabaseName() ?? string.Empty)
            .ShouldBe(["idx_backend_users_status"]);
        indexes[0].IsUnique.ShouldBeFalse();
    }

    /// <summary>
    /// Defaults matter as much as types here. <c>is_super_admin</c> and <c>token_version</c> are
    /// store defaults so that an INSERT which does not mention them still lands on false and zero -
    /// the mechanical form of "no creation path can mint a platform owner". <c>provider_details</c>
    /// defaults to an empty object, as the live column does.
    /// </summary>
    [Fact]
    public void TheDefaultsMatchTheLiveColumns()
    {
        var users = EntityType<BackendUser>();
        users.GetProperty(nameof(BackendUser.Status)).GetDefaultValue().ShouldBe("PENDING");
        users.GetProperty(nameof(BackendUser.Origin)).GetDefaultValue().ShouldBe("INTERNAL");
        users.GetProperty(nameof(BackendUser.IsSuperAdmin)).GetDefaultValue().ShouldBe(false);
        users.GetProperty(nameof(BackendUser.TokenVersion)).GetDefaultValue().ShouldBe(0);
        users.GetProperty(nameof(BackendUser.CreatedAt)).GetDefaultValueSql().ShouldBe("now()");

        var identities = EntityType<BackendIdentity>();
        identities.GetProperty(nameof(BackendIdentity.Provider)).GetDefaultValue().ShouldBe(string.Empty);
        identities.GetProperty(nameof(BackendIdentity.Status)).GetDefaultValue().ShouldBe("ACTIVE");
        // No default, in either direction. This used to assert '{}'::jsonb "with the live
        // column's own default"; the live column has none, so the model was declaring a default the
        // database would never supply. NULL is the honest value for an identity with no upstream
        // payload, which is every password- and OTP-provisioned row.
        identities.GetProperty(nameof(BackendIdentity.ProviderDetails))
            .GetDefaultValueSql().ShouldBeNull();
    }

    /// <summary>
    /// The two CHECK constraints are closed value sets the back office renders directly. A status
    /// the console cannot draw is worse than a refused write, which is why they are reproduced from
    /// the live schema rather than left to the application.
    /// </summary>
    [Fact]
    public void TheLiveCheckConstraintsAreReproduced()
    {
        var userChecks = EntityType<BackendUser>().GetCheckConstraints()
            .ToDictionary(check => check.Name ?? string.Empty, check => check.Sql, StringComparer.Ordinal);

        userChecks["chk_backend_users_status"].ShouldBe("status IN ('PENDING', 'ACTIVE', 'DISABLED')");
        userChecks["chk_backend_users_origin"].ShouldBe("origin IN ('INTERNAL', 'EXTERNAL')");

        var identityChecks = EntityType<BackendIdentity>().GetCheckConstraints()
            .ToDictionary(check => check.Name ?? string.Empty, check => check.Sql, StringComparer.Ordinal);

        identityChecks["chk_backend_identity_type"]
            .ShouldBe("identity_type IN ('email', 'phone', 'OTP')");
    }

    /// <summary>
    /// One foreign key, cascading, and it must not cross into the consumer schema. The two planes
    /// are separate bounded contexts with separate id spaces; a key between them would let a
    /// consumer row's lifetime decide an operator account's.
    /// </summary>
    [Fact]
    public void TheOnlyForeignKeyCascadesWithinTheIamSchema()
    {
        var foreignKeys = EntityType<BackendIdentity>().GetForeignKeys().ToList();

        foreignKeys.Count.ShouldBe(1);
        foreignKeys[0].PrincipalEntityType.GetSchema().ShouldBe("iam");
        foreignKeys[0].PrincipalEntityType.GetTableName().ShouldBe("backend_users");
        foreignKeys[0].DeleteBehavior.ShouldBe(DeleteBehavior.Cascade);
        foreignKeys[0].Properties.Select(property => property.GetColumnName()).ShouldBe(["user_id"]);
    }

    [Fact]
    public void NothingInThisSliceReferencesTheConsumerSchema()
    {
        foreach (var entity in new[] { EntityType<BackendUser>(), EntityType<BackendIdentity>() })
        {
            foreach (var foreignKey in entity.GetForeignKeys())
            {
                foreignKey.PrincipalEntityType.GetSchema().ShouldNotBe(UserSvcDbContext.Schema);
            }
        }
    }
}
