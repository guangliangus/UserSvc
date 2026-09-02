using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Shouldly;
using Xunit;

namespace UserSvc.ArchitectureTests;

/// <summary>
/// The project's PostgreSQL DDL conventions, enforced against the hand-written scripts in
/// <c>db/</c> that are the schema's source of truth (decision 14: the application never changes
/// the database).
/// <para>
/// <b>Why a test and not a pipeline step.</b> The conventions are non-negotiable but they were
/// still broken - seven columns shipped as <c>varchar(n)</c> where the rule is "always text" - and
/// nothing noticed for seven waves. The question a guard has to answer is <i>when does the author
/// find out</i>. Living here, it runs in every <c>dotnet test</c> and every build of the solution,
/// so the answer is "seconds after saving the script, on their own machine, with no database and no
/// Docker". A pipeline step would answer "after pushing", by which time the script has usually
/// already been applied to a real database by hand. The scan is pure text over ~140 KB, which costs
/// a few milliseconds, and this project already keeps its other self-checks here
/// (<see cref="SourceLanguageTests"/>, <see cref="OptionsReadSiteTests"/>) for the same reason.
/// </para>
/// <para>
/// <b>The escape hatch.</b> A deliberate deviation is declared in the script itself, on the
/// offending line or the line directly above it:
/// <code>
/// -- ddl-allow: string-text  the live Go database has this column as varchar(20) and rows exist
/// </code>
/// The reason travels with the line it excuses, which is the one place it cannot drift away from.
/// A pragma naming an unknown rule, carrying no reason, or sitting where nothing is wrong fails the
/// build too - a stale exception makes the guard look tighter than it is.
/// </para>
/// <para>
/// <b>Known blind spots</b>, listed so nobody mistakes a green run for a full audit. Comments and
/// single-quoted literals are blanked before scanning, so DDL hidden inside a <c>DO '...'</c> body
/// written as a plain string is invisible (dollar-quoted bodies <i>are</i> scanned). Rules that
/// need to know a column's meaning are not checked: money as <c>numeric(10,2)</c> cannot be
/// separated from a legitimate <c>price_cents integer</c> by name, and "foreign keys are NOT NULL"
/// has more legitimate exceptions here than instances - a self-referencing parent_id, OpenIddict's
/// optional application_id - so the guard would train people to write pragmas. Those stay with
/// review; everything below is mechanical.
/// </para>
/// </summary>
public sealed class DdlConventionTests
{
    private const string PragmaMarker = "ddl-allow:";

    /// <summary>The shortest reason accepted on a pragma. "wip" is not a reason.</summary>
    private const int MinimumReasonLength = 15;

    /// <summary>PostgreSQL truncates identifiers past this length silently.</summary>
    private const int MaximumIdentifierLength = 63;

    private static readonly TimeSpan RegexBudget = TimeSpan.FromSeconds(2);

    private static readonly RegexOptions Options =
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture;

    /// <summary>
    /// Reserved PostgreSQL keywords, plus the three the house rules call out by name
    /// (<c>order</c>, <c>before</c>, <c>after</c>). A column called "order" forces every statement
    /// touching it to be quoted forever, and the first one that forgets is a syntax error in
    /// production.
    /// </summary>
    private static readonly HashSet<string> ReservedWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "after", "all", "analyse", "analyze", "and", "any", "array", "as", "asc", "asymmetric",
        "authorization", "before", "between", "binary", "both", "case", "cast", "check", "collate",
        "collation", "column", "concurrently", "constraint", "create", "cross", "current_catalog",
        "current_date", "current_role", "current_schema", "current_time", "current_timestamp",
        "current_user", "default", "deferrable", "desc", "distinct", "do", "else", "end", "except",
        "false", "fetch", "for", "foreign", "freeze", "from", "full", "grant", "group", "having",
        "ilike", "in", "initially", "inner", "intersect", "into", "is", "isnull", "join", "lateral",
        "leading", "left", "like", "limit", "localtime", "localtimestamp", "natural", "not",
        "notnull", "null", "offset", "on", "only", "or", "order", "outer", "overlaps", "placing",
        "primary", "references", "returning", "right", "select", "session_user", "similar", "some",
        "symmetric", "table", "tablesample", "then", "to", "trailing", "true", "union", "unique",
        "user", "using", "variadic", "verbose", "when", "where", "window", "with",
    };

    /// <summary>
    /// Words that are already plural or uncountable, so a table name ending in one satisfies the
    /// "last word complete and plural" rule without an "s". This is a dictionary, not an exception
    /// list: <c>identity.feedback</c> is correctly named because "feedbacks" is not English.
    /// </summary>
    private static readonly HashSet<string> AlreadyPlural = new(StringComparer.OrdinalIgnoreCase)
    {
        "feedback", "data", "metadata", "media", "people", "children", "staff", "news", "audio",
    };

    /// <summary>
    /// The rules, each a pattern over the script with comments and string literals blanked out.
    /// The id is what a pragma has to name; the advice is what the author reads when it fires.
    /// </summary>
    private static readonly Rule[] PatternRules =
    [
        new(
            "string-text",
            new Regex(@"\b(?:varchar|character\s+varying)\b|\b(?:char|character)\s*\(", Options, RegexBudget),
            "every string column is 'text'; length is validated in code, and widening a varchar(n) "
            + "later is a table rewrite on a live table"),
        new(
            "no-enum-type",
            new Regex(@"\bcreate\s+type\b|\bas\s+enum\b", Options, RegexBudget),
            "no PostgreSQL enum types: use text plus at most a simple CHECK, because adding a value "
            + "to an enum is DDL and removing one is impossible"),
        new(
            "timestamptz",
            new Regex(@"\btimestamp\b(?!\s*(?:\(\s*\d+\s*\))?\s*with\s+time\s+zone)", Options, RegexBudget),
            "datetimes are TIMESTAMPTZ (UTC); a bare timestamp silently reinterprets every value "
            + "when the server's time zone differs from the writer's"),
        new(
            "serial-primary-key",
            new Regex(@"\b(?:bigserial|serial8)\b", Options, RegexBudget),
            "surrogate keys are SERIAL, not BIGSERIAL"),
        new(
            "no-physical-delete",
            new Regex(@"\bdrop\s+table\b|\btruncate\b|\bdelete\s+from\b", Options, RegexBudget),
            "nothing is physically deleted: use a status column or archive. A destructive statement "
            + "in a re-runnable script also destroys data on the second run"),
        new(
            "snake-case",
            new Regex(@"""[^""\r\n]*[A-Z][^""\r\n]*""", RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture, RegexBudget),
            "identifiers are lowercase snake_case; a quoted mixed-case name has to be quoted in "
            + "every statement that ever touches it"),
        new(
            "idempotent-ddl",
            new Regex(
                // The "if not exists" lookahead swallows the whitespace itself. Written as
                // \s+(?!if...) it would match anyway on "CREATE INDEX        IF NOT EXISTS":
                // \s+ backtracks to leave the lookahead standing on a space, which is not "if".
                @"\bcreate\s+(?:unique\s+)?index\b(?:\s+concurrently\b)?(?!\s+if\s+not\s+exists\b)"
                + @"|\bcreate\s+table\b(?!\s+if\s+not\s+exists\b)"
                + @"|\bcreate\s+schema\b(?!\s+if\s+not\s+exists\b)"
                + @"|\badd\s+column\b(?!\s+if\s+not\s+exists\b)",
                Options,
                RegexBudget),
            "scripts are applied by hand and re-run: CREATE ... IF NOT EXISTS / ADD COLUMN IF NOT "
            + "EXISTS, or CI gate 03 (double application) fails"),
    ];

    /// <summary>
    /// One offending pattern and the advice printed when it matches.
    /// </summary>
    /// <param name="Id">The rule id, as written in a <c>-- ddl-allow:</c> pragma.</param>
    /// <param name="Pattern">What the rule looks for in the blanked script text.</param>
    /// <param name="Advice">Why the convention exists, phrased as what to do instead.</param>
    private sealed record Rule(string Id, Regex Pattern, string Advice);

    /// <summary>A single violation, located precisely enough to jump straight to it.</summary>
    /// <param name="File">Repository-relative script path.</param>
    /// <param name="Line">One-based line number.</param>
    /// <param name="RuleId">The rule that fired.</param>
    /// <param name="Found">The offending text, quoted back.</param>
    /// <param name="Advice">What to do instead.</param>
    private sealed record Violation(string File, int Line, string RuleId, string Found, string Advice)
    {
        public string Describe() => string.Create(
            CultureInfo.InvariantCulture,
            $"{File}:{Line} [{RuleId}] {Found} - {Advice}");
    }

    /// <summary>A declared exception: a <c>-- ddl-allow:</c> pragma found in a script.</summary>
    /// <param name="File">Repository-relative script path.</param>
    /// <param name="Line">One-based line the pragma sits on.</param>
    /// <param name="RuleId">The rule it excuses.</param>
    /// <param name="Reason">The written justification.</param>
    private sealed record Pragma(string File, int Line, string RuleId, string Reason);

    [Fact]
    public void DatabaseScriptsFollowTheDdlConventions()
    {
        var (violations, pragmas) = Scan();

        var unexcused = violations
            .Where(v => !pragmas.Any(p => Excuses(p, v)))
            .Select(v => v.Describe())
            .ToList();

        unexcused.ShouldBeEmpty(
            string.Create(CultureInfo.InvariantCulture, $"{unexcused.Count} DDL convention violation(s) ")
            + "in db/*.sql. The conventions are "
            + "project-wide and non-negotiable (docs/architecture.md, db/README.md); fix the script "
            + "rather than the guard. If a deviation is deliberate, declare it on the offending "
            + "line or the line above it as \"-- ddl-allow: <rule-id>  <reason>\" so the reason "
            + "lives next to the line it excuses."
            + Environment.NewLine
            + string.Join(Environment.NewLine, unexcused));
    }

    /// <summary>
    /// Pragmas are exceptions, so they are held to the same standard as the rules: a pragma has to
    /// name a real rule, carry a real reason, and still be excusing something. A stale one makes the
    /// next reader believe a violation was considered when it no longer exists.
    /// </summary>
    [Fact]
    public void EveryDeclaredExceptionIsWellFormedAndStillNeeded()
    {
        var (violations, pragmas) = Scan();
        var knownRuleIds = KnownRuleIds();

        var problems = new List<string>();

        foreach (var pragma in pragmas)
        {
            var where = string.Create(CultureInfo.InvariantCulture, $"{pragma.File}:{pragma.Line}");

            if (!knownRuleIds.Contains(pragma.RuleId))
            {
                problems.Add($"{where} names rule '{pragma.RuleId}', which does not exist. "
                             + $"Known rules: {string.Join(", ", knownRuleIds.Order(StringComparer.Ordinal))}.");
                continue;
            }

            if (pragma.Reason.Length < MinimumReasonLength)
            {
                problems.Add($"{where} excuses '{pragma.RuleId}' without a reason. Write why the "
                             + "convention cannot be followed here, not that it is not followed.");
                continue;
            }

            if (!violations.Any(v => Excuses(pragma, v)))
            {
                problems.Add($"{where} excuses '{pragma.RuleId}' but nothing on that line or the "
                             + "line below breaks that rule any more. Delete the pragma.");
            }
        }

        problems.ShouldBeEmpty(
            "Malformed or stale \"-- ddl-allow:\" pragmas in db/*.sql:"
            + Environment.NewLine
            + string.Join(Environment.NewLine, problems));
    }

    /// <summary>
    /// A guard that scans nothing passes, which is worse than having no guard: the pipeline reports
    /// green. This asserts the scan actually found the scripts and saw content in them, so moving
    /// or renaming <c>db/</c> fails loudly instead of quietly disabling every rule above.
    /// </summary>
    [Fact]
    public void TheScanSeesEveryScript()
    {
        var scripts = ScriptPaths();

        scripts.Length.ShouldBeGreaterThanOrEqualTo(
            13,
            "db/*.sql is the schema's source of truth and its scripts are never deleted (changes "
            + "are additive, numbered scripts). Finding fewer than the 13 that existed when this "
            + "guard was written means the scan is looking in the wrong place, and every rule in "
            + "this file silently passes.");

        foreach (var script in scripts)
        {
            var text = File.ReadAllText(script);
            text.Trim().ShouldNotBeEmpty($"{Relative(script)} is empty.");
            Scrub(text).Length.ShouldBe(text.Length, $"The scrubber changed the length of {Relative(script)}, "
                                                     + "so reported line numbers would be wrong.");
        }
    }

    private static bool Excuses(Pragma pragma, Violation violation) =>
        pragma.RuleId.Equals(violation.RuleId, StringComparison.Ordinal)
        && pragma.File.Equals(violation.File, StringComparison.Ordinal)
        && (pragma.Line == violation.Line || pragma.Line == violation.Line - 1);

    private static HashSet<string> KnownRuleIds()
    {
        var ids = PatternRules.Select(r => r.Id).ToHashSet(StringComparer.Ordinal);
        ids.Add("no-reserved-word");
        ids.Add("plural-table-name");
        ids.Add("identifier-length");
        return ids;
    }

    private static (List<Violation> Violations, List<Pragma> Pragmas) Scan()
    {
        var violations = new List<Violation>();
        var pragmas = new List<Pragma>();

        foreach (var path in ScriptPaths())
        {
            var file = Relative(path);
            var raw = File.ReadAllText(path);
            var scrubbed = Scrub(raw);
            var starts = LineStarts(raw);

            pragmas.AddRange(ReadPragmas(file, raw, starts));

            foreach (var rule in PatternRules)
            {
                foreach (var match in rule.Pattern.Matches(scrubbed).Cast<Match>())
                {
                    violations.Add(new Violation(
                        file,
                        LineOf(starts, match.Index),
                        rule.Id,
                        Quote(match.Value),
                        rule.Advice));
                }
            }

            violations.AddRange(IdentifierViolations(file, scrubbed, starts));
        }

        return (violations, pragmas);
    }

    /// <summary>
    /// Rules that need an identifier rather than a pattern: table and column names taken from the
    /// <c>CREATE TABLE</c> bodies, index and constraint names from their own statements.
    /// </summary>
    private static IEnumerable<Violation> IdentifierViolations(string file, string scrubbed, int[] starts)
    {
        foreach (var (name, index) in NamedObjects(scrubbed))
        {
            if (name.Length > MaximumIdentifierLength)
            {
                yield return new Violation(
                    file,
                    LineOf(starts, index),
                    "identifier-length",
                    Quote(name),
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"is {name.Length} characters, over the PostgreSQL limit of {MaximumIdentifierLength}")
                    + ", which truncates silently: the object ends up with a name no script "
                    + "mentions and the EF model cannot match");
            }

            if (ReservedWords.Contains(name))
            {
                yield return new Violation(
                    file,
                    LineOf(starts, index),
                    "no-reserved-word",
                    Quote(name),
                    "is a reserved word, so every statement touching it needs quoting forever; "
                    + "rename it (order -> sort_order, user -> account, check -> checked_at)");
            }
        }

        foreach (var (table, index) in TableNames(scrubbed))
        {
            var lastWord = table.Split('_')[^1];

            if (!lastWord.EndsWith('s') && !AlreadyPlural.Contains(lastWord))
            {
                yield return new Violation(
                    file,
                    LineOf(starts, index),
                    "plural-table-name",
                    Quote(table),
                    "a table holds many rows, so its last word is plural and complete "
                    + "(channel_configs, not channel_config)");
            }
        }
    }

    /// <summary>
    /// Every identifier this guard can name with confidence: table names, the column names inside
    /// each <c>CREATE TABLE</c> body, <c>ADD COLUMN</c> names, index names and constraint names.
    /// </summary>
    private static IEnumerable<(string Name, int Index)> NamedObjects(string scrubbed)
    {
        foreach (var (table, index) in TableNames(scrubbed))
        {
            yield return (table, index);
        }

        foreach (var column in ColumnDeclarations.Matches(scrubbed).Cast<Match>())
        {
            yield return (column.Groups["name"].Value, column.Groups["name"].Index);
        }

        foreach (var index in IndexNames.Matches(scrubbed).Cast<Match>())
        {
            yield return (index.Groups["name"].Value, index.Groups["name"].Index);
        }

        foreach (var constraint in ConstraintNames.Matches(scrubbed).Cast<Match>())
        {
            yield return (constraint.Groups["name"].Value, constraint.Groups["name"].Index);
        }

        foreach (var table in CreateTableHeads.Matches(scrubbed).Cast<Match>())
        {
            foreach (var column in ColumnsOf(scrubbed, table.Index + table.Length))
            {
                yield return column;
            }
        }
    }

    /// <summary>
    /// The head of a <c>CREATE TABLE</c>, with the schema prefix optional and the table name
    /// either bare or double-quoted - a quoted name is exactly how a reserved word gets into a
    /// schema in the first place.
    /// </summary>
    private static readonly Regex CreateTableHeads = new(
        @"\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?:""?[a-z_][\w$]*""?\s*\.\s*)?"
        + @"(?:""(?<table>[^""\r\n]+)""|(?<table>[a-z_][\w$]*))",
        Options,
        RegexBudget);

    private static readonly Regex ColumnDeclarations = new(
        @"\badd\s+column\s+(?:if\s+not\s+exists\s+)?(?<name>[a-z_][\w$]*)",
        Options,
        RegexBudget);

    private static readonly Regex IndexNames = new(
        @"\bcreate\s+(?:unique\s+)?index\s+(?:concurrently\s+)?(?:if\s+not\s+exists\s+)?(?<name>[a-z_][\w$]*)",
        Options,
        RegexBudget);

    private static readonly Regex ConstraintNames = new(
        @"\bconstraint\s+(?<name>[a-z_][\w$]*)",
        Options,
        RegexBudget);

    private static readonly Regex ColumnLine = new(
        @"^\s*(?:""(?<name>[^""\r\n]+)""|(?<name>[a-z_][\w$]*))\s",
        RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture,
        RegexBudget);

    /// <summary>Words that open a table constraint rather than a column declaration.</summary>
    private static readonly HashSet<string> NotColumnNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "constraint", "primary", "unique", "foreign", "check", "exclude", "like", "inherits",
    };

    private static IEnumerable<(string Name, int Index)> TableNames(string scrubbed) =>
        CreateTableHeads.Matches(scrubbed)
            .Cast<Match>()
            .Select(m => (m.Groups["table"].Value, m.Groups["table"].Index));

    /// <summary>
    /// Splits the parenthesised body that follows a <c>CREATE TABLE</c> head into its top-level
    /// items and returns the first token of each one that declares a column.
    /// </summary>
    private static IEnumerable<(string Name, int Index)> ColumnsOf(string scrubbed, int afterHead)
    {
        var open = afterHead;
        while (open < scrubbed.Length && char.IsWhiteSpace(scrubbed[open]))
        {
            open++;
        }

        if (open >= scrubbed.Length || scrubbed[open] != '(')
        {
            yield break;
        }

        var depth = 0;
        var itemStart = open + 1;

        for (var i = open; i < scrubbed.Length; i++)
        {
            var c = scrubbed[i];

            if (c == '(')
            {
                depth++;
                continue;
            }

            if (c == ')')
            {
                depth--;
                if (depth > 0)
                {
                    continue;
                }

                foreach (var column in ColumnOf(scrubbed, itemStart, i))
                {
                    yield return column;
                }

                yield break;
            }

            if (c == ',' && depth == 1)
            {
                foreach (var column in ColumnOf(scrubbed, itemStart, i))
                {
                    yield return column;
                }

                itemStart = i + 1;
            }
        }
    }

    private static IEnumerable<(string Name, int Index)> ColumnOf(string scrubbed, int start, int end)
    {
        var item = scrubbed[start..end];
        var match = ColumnLine.Match(item);

        if (match.Success && !NotColumnNames.Contains(match.Groups["name"].Value))
        {
            yield return (match.Groups["name"].Value, start + match.Groups["name"].Index);
        }
    }

    private static IEnumerable<Pragma> ReadPragmas(string file, string raw, int[] starts)
    {
        var index = 0;

        while ((index = raw.IndexOf(PragmaMarker, index, StringComparison.Ordinal)) >= 0)
        {
            var lineEnd = raw.IndexOf('\n', index);
            var rest = lineEnd < 0 ? raw[(index + PragmaMarker.Length)..] : raw[(index + PragmaMarker.Length)..lineEnd];
            var parts = rest.Trim().Split(' ', 2, StringSplitOptions.TrimEntries);

            yield return new Pragma(
                file,
                LineOf(starts, index),
                parts[0],
                parts.Length > 1 ? parts[1] : string.Empty);

            index += PragmaMarker.Length;
        }
    }

    /// <summary>
    /// Replaces comments and single-quoted literals with spaces, character for character, so that
    /// rule matches keep their original offsets and a match index still maps to the right line.
    /// Dollar-quoted bodies keep their contents - they hold PL/pgSQL, which is code the rules
    /// should see - but their <c>$tag$</c> delimiters are blanked.
    /// </summary>
    private static string Scrub(string sql)
    {
        var result = new StringBuilder(sql.Length);
        var i = 0;

        while (i < sql.Length)
        {
            var c = sql[i];

            if (c == '-' && Peek(sql, i + 1) == '-')
            {
                i = BlankUntilNewline(sql, i, result);
                continue;
            }

            if (c == '/' && Peek(sql, i + 1) == '*')
            {
                i = BlankBlockComment(sql, i, result);
                continue;
            }

            if (c == '\'')
            {
                i = BlankStringLiteral(sql, i, result);
                continue;
            }

            if (c == '$' && DollarTagLength(sql, i) is { } tagLength)
            {
                Blank(sql, i, i + tagLength, result);
                i += tagLength;
                continue;
            }

            result.Append(c);
            i++;
        }

        return result.ToString();
    }

    private static char Peek(string sql, int index) => index < sql.Length ? sql[index] : '\0';

    private static int BlankUntilNewline(string sql, int from, StringBuilder result)
    {
        var i = from;
        while (i < sql.Length && sql[i] != '\n')
        {
            result.Append(' ');
            i++;
        }

        return i;
    }

    private static int BlankBlockComment(string sql, int from, StringBuilder result)
    {
        var depth = 0;
        var i = from;

        while (i < sql.Length)
        {
            if (sql[i] == '/' && Peek(sql, i + 1) == '*')
            {
                depth++;
                result.Append("  ");
                i += 2;
                continue;
            }

            if (sql[i] == '*' && Peek(sql, i + 1) == '/')
            {
                depth--;
                result.Append("  ");
                i += 2;

                if (depth == 0)
                {
                    return i;
                }

                continue;
            }

            result.Append(sql[i] == '\n' ? '\n' : ' ');
            i++;
        }

        return i;
    }

    private static int BlankStringLiteral(string sql, int from, StringBuilder result)
    {
        result.Append(' ');
        var i = from + 1;

        while (i < sql.Length)
        {
            if (sql[i] == '\'' && Peek(sql, i + 1) == '\'')
            {
                result.Append("  ");
                i += 2;
                continue;
            }

            if (sql[i] == '\'')
            {
                result.Append(' ');
                return i + 1;
            }

            result.Append(sql[i] == '\n' ? '\n' : ' ');
            i++;
        }

        return i;
    }

    /// <summary>
    /// The length of the <c>$tag$</c> delimiter starting at <paramref name="from"/>, or null when
    /// the dollar sign is not one (a positional parameter, or money in a comment).
    /// </summary>
    private static int? DollarTagLength(string sql, int from)
    {
        var i = from + 1;

        while (i < sql.Length && (char.IsLetterOrDigit(sql[i]) || sql[i] == '_'))
        {
            i++;
        }

        return i < sql.Length && sql[i] == '$' ? i - from + 1 : null;
    }

    private static void Blank(string sql, int from, int to, StringBuilder result)
    {
        for (var i = from; i < to; i++)
        {
            result.Append(sql[i] == '\n' ? '\n' : ' ');
        }
    }

    private static string Quote(string found)
    {
        var single = found.ReplaceLineEndings(" ").Trim();
        return single.Length <= 60 ? $"\"{single}\"" : $"\"{single[..57]}...\"";
    }

    private static int[] LineStarts(string text)
    {
        var starts = new List<int> { 0 };

        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] == '\n')
            {
                starts.Add(i + 1);
            }
        }

        return [.. starts];
    }

    private static int LineOf(int[] starts, int index)
    {
        var found = Array.BinarySearch(starts, index);
        return found >= 0 ? found + 1 : ~found;
    }

    private static string[] ScriptPaths() =>
        [.. Directory.EnumerateFiles(Path.Combine(PackageReferenceTests.RepositoryRoot(), "db"), "*.sql")
            .OrderBy(path => path, StringComparer.Ordinal)];

    private static string Relative(string path) =>
        Path.GetRelativePath(PackageReferenceTests.RepositoryRoot(), path)
            .Replace(Path.DirectorySeparatorChar, '/');
}
