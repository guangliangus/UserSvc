using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Features.BackOffice.Accounts;
using UserSvc.Domain.BackOffice;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>
/// The one definition of "this account matches what the operator typed", shared by the directory
/// and the people picker.
/// <para>
/// <b>The two composed forms are the reason this is not a single-column LIKE.</b> What every screen
/// displays is the composed name - family name and given name, joined the way that name's script
/// joins them - so an operator searching for the person they can see on screen types a string that
/// exists in no single column. A search that looked only at <c>first_name</c> and <c>last_name</c>
/// separately would find nothing, and the operator would conclude the account does not exist.
/// </para>
/// <para>
/// It lives beside the repository rather than in the application layer because it is a query
/// fragment: an expression tree the provider translates into SQL, not a decision.
/// </para>
/// </summary>
public static class BackendUserSearch
{
    /// <summary>
    /// The character that escapes a wildcard inside a pattern. Backslash is PostgreSQL's default
    /// for LIKE, and it is passed explicitly on every call so the behaviour does not depend on a
    /// server setting.
    /// </summary>
    public const string EscapeCharacter = "\\";

    /// <summary>
    /// Wraps a search term into a contains-pattern, escaping the wildcards first.
    /// <para>
    /// Escaping matters more than it looks: an unescaped <c>%</c> typed into the box turns the
    /// query into "match everything", and a search that quietly returns the whole directory reads
    /// as a permission bug rather than as a typo. <c>_</c> is subtler and worse - it matches one
    /// character, so a term containing it silently matches accounts the operator never asked about.
    /// </para>
    /// </summary>
    public static string ContainsPattern(string term)
    {
        ArgumentNullException.ThrowIfNull(term);

        var escaped = term
            .Trim()
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("%", "\\%", StringComparison.Ordinal)
            .Replace("_", "\\_", StringComparison.Ordinal);

        return $"%{escaped}%";
    }

    /// <summary>
    /// Matches a term against every spelling of an account's name: the handle, the employee number,
    /// each name part on its own, and the two composed forms - family name then given name with no
    /// separator for CJK names, given name then family name with a space for Latin ones.
    /// <para>
    /// Case-insensitive throughout, because nobody types their colleagues' names with the casing
    /// the HR system used.
    /// </para>
    /// </summary>
    public static Expression<Func<BackendUser, bool>> NameMatches(string term)
    {
        var pattern = ContainsPattern(term);

        return user =>
            EF.Functions.ILike(user.Nickname ?? string.Empty, pattern, EscapeCharacter)
            || EF.Functions.ILike(user.StaffCode ?? string.Empty, pattern, EscapeCharacter)
            || EF.Functions.ILike(user.FirstName ?? string.Empty, pattern, EscapeCharacter)
            || EF.Functions.ILike(user.LastName ?? string.Empty, pattern, EscapeCharacter)
            || EF.Functions.ILike(
                (user.LastName ?? string.Empty) + (user.FirstName ?? string.Empty), pattern, EscapeCharacter)
            || EF.Functions.ILike(
                (user.FirstName ?? string.Empty) + " " + (user.LastName ?? string.Empty), pattern, EscapeCharacter);
    }

    /// <summary>
    /// Whether a search term should be resolved against the encrypted identity table instead of the
    /// name columns.
    /// <para>
    /// An address is stored as a deterministic hash and a ciphertext, never as searchable text, so
    /// there is nothing for a prefix to match: a full address either hashes to a row or it does
    /// not. That is a deliberate trade - it means an operator cannot search for "everyone at this
    /// domain", and it also means a name search can never accidentally surface an address.
    /// </para>
    /// </summary>
    public static bool LooksLikeAddress(string term) => BackOfficeNames.IsEmail(term);
}
