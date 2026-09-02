using Shouldly;
using UserSvc.Infrastructure.Persistence.Repositories;
using Xunit;

namespace UserSvc.UnitTests.BackOffice;

/// <summary>
/// The two guarded statements, asserted as text.
/// <para>
/// This is an unusual thing to test and it is the most valuable test in the slice. The property
/// these statements have - that the "is there another active owner" check happens <b>inside</b> the
/// UPDATE - is invisible at every other level: a refactor that reads the count first and then
/// updates passes every behavioural test, because a single-threaded test never loses the race. What
/// it breaks only shows up as two concurrent revocations leaving the platform with no
/// administrator, which is unrecoverable and untestable after the fact.
/// </para>
/// </summary>
public sealed class BackendUserSqlTests
{
    [Fact]
    public void RevokingCarriesItsGuardInsideTheStatement()
    {
        var sql = BackendUserSql.RevokeSuperAdminIfAnotherActiveExists;

        sql.ShouldContain("UPDATE iam.backend_users");
        sql.ShouldContain("SET is_super_admin = false");

        // The whole guard: another row, still holding the flag, and still able to sign in.
        sql.ShouldContain("EXISTS");
        sql.ShouldContain("o.id <> {1}");
        sql.ShouldContain("o.is_super_admin");
        sql.ShouldContain("o.status = 'ACTIVE'");

        // AND is_super_admin keeps "wrote nothing" honest: it also means "there was nothing to
        // clear", which is how a lost race is told apart from a refusal.
        sql.ShouldContain("WHERE id = {1} AND is_super_admin");
    }

    [Fact]
    public void MovingTheStatusOfAnOwnerCarriesTheSameGuard()
    {
        var sql = BackendUserSql.SetStatusIfAnotherActiveSuperAdminExists;

        sql.ShouldContain("SET status = {0}");
        sql.ShouldContain("o.id <> {2}");
        sql.ShouldContain("o.is_super_admin");
        sql.ShouldContain("o.status = 'ACTIVE'");
    }

    /// <summary>
    /// A whole-dimension membership is an ordinary row, so without <c>NOT scope_all</c> the
    /// administrator of one company would see every account that holds platform-wide company
    /// access - through their own tenant, and with no way to tell that is what happened.
    /// </summary>
    [Fact]
    public void TheVisibilitySubqueryExcludesWholeDimensionRowsFromTheTenantBranch()
    {
        var sql = BackendUserSql.VisibleUserIds;

        sql.ShouldContain("NOT m.scope_all");
        sql.ShouldContain("m.status = 'ACTIVE'");
        sql.ShouldContain("m.tenant_type = ANY({0}::text[])");

        // EF's scalar query API reads the column by this name.
        sql.ShouldContain("AS \"Value\"");
    }
}
