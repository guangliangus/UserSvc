using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Shouldly;
using Xunit;

namespace UserSvc.ArchitectureTests;

/// <summary>
/// Enforces the rule docs/architecture.md calls "a missing capability may only break itself", in
/// the one form that has broken this service over and over:
/// <b><c>IOptions&lt;T&gt;.Value</c> is read at the point of use, never while a type is being
/// constructed.</b>
/// <para>
/// <c>.Value</c> is where <c>ValidateDataAnnotations</c> actually runs, so a type that binds it
/// during construction throws when its section is unconfigured - and it throws for every endpoint
/// whose object graph contains that type, not only the one that wanted the setting. Eight
/// instances are on record and every single one was found by running the host: an app service
/// holding four social providers answered 500 for all four when any one lacked credentials; a
/// pure-database unbind endpoint answered 500 about a signing key; the passkey list, rename and
/// delete endpoints - three database operations that never touch a relying-party identity -
/// answered 500 naming <c>RpId</c>, and a back-office token on those routes got that 500 instead
/// of the 403 every other consumer endpoint gives it, because the throw beat the realm guard; and
/// a 31-byte data-encryption key answered 500 to <c>/health/live</c>.
/// </para>
/// <para>
/// <b>This is no longer a ratchet.</b> Its predecessor carried an allow-list of nine existing
/// offenders so it could pass on a tree that still held them, which meant it only ever failed on
/// the <i>next</i> type - and the list, being the thing that made the guard green, was also the
/// thing nobody rechecked. Every entry has been converted; <see cref="Allowed"/> is empty and the
/// second test below keeps it honest by failing on any entry that no longer describes a real read.
/// </para>
/// <para>
/// <b>The fix, every time, is two lines:</b> replace the field with an expression-bodied property
/// of the same name (<c>private FooOptions _options =&gt; options.Value;</c>) so that not one call
/// site changes. Where the constructor built something immutable out of the section - the one case
/// with a real reason to read early - put that construction behind a
/// <c>Lazy&lt;T&gt;(..., LazyThreadSafetyMode.ExecutionAndPublication)</c>: still built once per
/// process, but built on the first call that needs it. <c>Lazy&lt;T&gt;</c> rethrows the factory's
/// own exception rather than wrapping it, so the 500 <c>NOT_CONFIGURED</c> naming the section
/// survives the move.
/// </para>
/// </summary>
public sealed class OptionsReadSiteTests
{
    /// <summary>
    /// Individually justified exceptions, as <c>path:line</c> plus the reason it is allowed.
    /// <para>
    /// <b>Empty, and the bar for adding an entry is a reason that survives the question "what does
    /// a deployment without this section get?".</b> "The section is <c>[Required]</c> and
    /// <c>ValidateOnStart</c>, so the host refuses to boot before this line can run" is not such a
    /// reason: it is containment that lives in a different file, which somebody removes for good
    /// reasons of their own - which is exactly how instances four, five and six happened.
    /// </para>
    /// </summary>
    private static readonly (string Site, string Why)[] Allowed = [];

    [Fact]
    public void OptionsAreNeverReadWhileATypeIsBeingConstructed()
    {
        var root = PackageReferenceTests.RepositoryRoot();

        var offenders = ConstructionTimeReads(root)
            .Where(read => !Allowed.Any(entry => string.Equals(entry.Site, read.Site, StringComparison.Ordinal)))
            .ToList();

        offenders.ShouldBeEmpty(
            "These types read IOptions<T>.Value while being constructed, so merely constructing "
            + "one throws when its section is unconfigured - and it takes every endpoint that "
            + "shares the object graph down with it, reporting somebody else's missing setting "
            + "(docs/architecture.md, \"a missing capability may only break itself\"). Read it at "
            + "the point of use instead: replace the field with an expression-bodied property of "
            + "the same name, or move an immutable instance built from the section behind a "
            + "Lazy<T>. Offenders: "
            + string.Join(", ", offenders.Select(read => $"{read.Site} ({read.Kind}) -> {read.Text}")));
    }

    /// <summary>
    /// An exception that no longer describes a real read makes the guard look tighter than it is,
    /// and hides the next offender behind an entry nobody rechecks.
    /// </summary>
    [Fact]
    public void EveryAllowedExceptionStillDescribesARealRead()
    {
        var root = PackageReferenceTests.RepositoryRoot();
        var actual = ConstructionTimeReads(root).Select(read => read.Site).ToHashSet(StringComparer.Ordinal);

        var stale = Allowed.Where(entry => !actual.Contains(entry.Site)).Select(entry => entry.Site).ToList();

        stale.ShouldBeEmpty(
            "These allowed sites no longer read their options while being constructed, or have "
            + "moved to another line, so delete the entry: " + string.Join(", ", stale));
    }

    /// <summary>
    /// A guard whose detector silently stops matching is how the next instance gets in, so the
    /// detector is tested against source of its own holding every shape it must catch and every
    /// shape it must not. Without this, a well-meaning tidy-up of the scanner turns both tests
    /// above permanently and invisibly green.
    /// </summary>
    [Fact]
    public void TheDetectorFindsEveryConstructionTimeShapeAndNothingElse()
    {
        const string Source = """
            using Microsoft.Extensions.Options;

            namespace Sample;

            public sealed class Caught(IOptions<FooOptions> options, IOptions<BarOptions> bar)
            {
                // CAUGHT, line 8: a field initializer.
                private readonly FooOptions _eager = options.Value;

                // CAUGHT, line 11: a property initializer.
                public string Prefix { get; } = bar.Value.Prefix;

                // CAUGHT, line 14: an object initializer inside a field initializer.
                private readonly Wrapper _wrapped = new() { Name = options.Value.Name };

                // CAUGHT, line 17: an interpolation hole in a field initializer.
                private readonly string _key = $"{options.Value.Name}:suffix";

                // IGNORED, line 20: the point of use, which is the whole point.
                private FooOptions Settings => options.Value;

                // IGNORED, line 23: an expression-bodied member.
                public string Use() => Settings.Name + _eager.Name + bar.Value.Prefix + _key;
            }

            public sealed class CaughtInConstructor
            {
                private readonly string _name;
                private readonly System.Lazy<string> _deferred;

                public CaughtInConstructor(IOptions<FooOptions> options, IOptions<BarOptions> other)
                {
                    // CAUGHT, line 34: a constructor body.
                    var settings = options.Value;
                    _name = settings.Name;

                    if (_name.Length == 0)
                    {
                        // CAUGHT, line 40: a nested block of a constructor still runs during it.
                        _name = options.Value.Name;
                    }

                    // CAUGHT, line 44: an object initializer inside a constructor, likewise.
                    var wrapped = new Wrapper { Name = other.Value.Prefix };
                    _name += wrapped.Name;

                    // IGNORED, line 48: deferred behind a lambda, which runs on first use.
                    _deferred = new System.Lazy<string>(() => options.Value.Name);
                }

                public string Read(IOptions<FooOptions> late)
                {
                    // IGNORED, line 54: a method body.
                    var settings = late.Value;
                    return settings.Name + _deferred.Value + _name;
                }
            }
            """;

        var found = OptionsReadScan.Find(Source);

        found.Select(read => read.Line).ShouldBe([8, 11, 14, 17, 34, 40, 44]);
        found.Where(read => read.Kind == MemberInitializer).Select(read => read.Line).ShouldBe([8, 11, 14, 17]);
        found.Where(read => read.Kind == ConstructorBody).Select(read => read.Line).ShouldBe([34, 40, 44]);
    }

    private const string MemberInitializer = "member initializer";
    private const string ConstructorBody = "constructor body";

    private static IReadOnlyList<(string Site, string Kind, string Text)> ConstructionTimeReads(string root)
    {
        var results = new List<(string Site, string Kind, string Text)>();

        var files = Directory
            .EnumerateFiles(Path.Combine(root, "src"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .OrderBy(path => path, StringComparer.Ordinal);

        foreach (var file in files)
        {
            var relative = Path.GetRelativePath(root, file).Replace(Path.DirectorySeparatorChar, '/');

            foreach (var read in OptionsReadScan.Find(File.ReadAllText(file)))
            {
                results.Add((
                    string.Create(CultureInfo.InvariantCulture, $"{relative}:{read.Line}"),
                    read.Kind,
                    read.Text));
            }
        }

        return results;
    }
}

/// <summary>
/// Finds reads of <c>IOptions&lt;T&gt;.Value</c> that happen while a type is being constructed.
/// <para>
/// It is a source scan rather than a Roslyn pass because the architecture-test project holds no
/// compiler reference and adding one is itself a guarded decision. Precision comes from three
/// other things. <b>Comments and string literals are blanked first</b> - interpolation holes
/// excepted, so <c>$"{options.Value.Name}"</c> is still seen - which matters here because this
/// codebase's comments discuss <c>options.Value</c> constantly. <b>Only identifiers actually
/// declared as <c>IOptions&lt;&gt;</c>, <c>IOptionsMonitor&lt;&gt;</c> or
/// <c>IOptionsSnapshot&lt;&gt;</c> in the same file are tracked</b>, so
/// <c>Nullable&lt;T&gt;.Value</c>, <c>PathString.Value</c>, <c>KeyValuePair.Value</c>,
/// <c>Lazy&lt;T&gt;.Value</c> and <c>TryGetValue</c> cannot trip it. And <b>a brace walk decides
/// where each read sits</b> - member initializer, constructor body, a nested block or object
/// initializer inside either, or a method body - rather than a per-line pattern.
/// </para>
/// <para>
/// <b>What it deliberately does not report.</b> A read inside a lambda, because a
/// <c>Lazy&lt;T&gt;</c> factory or a callback runs on first use and not during construction - which
/// leaves a lambda that its own constructor <i>invokes</i> as a blind spot, accepted because the
/// alternative is failing the two idioms that are the actual fix. A read inside a raw string
/// literal, which is blanked whole. And instance seven, which was a missing
/// <c>Func&lt;T&gt;</c> registration in <c>Program.cs</c> - a container-shape mistake with no read
/// site at all, guarded by the integration tests that build the host instead.
/// </para>
/// </summary>
internal static class OptionsReadScan
{
    private static readonly Regex AccessorDeclaration = new(
        @"\bIOptions(?:Monitor|Snapshot)?\s*<[^;{}()]*?>\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)",
        RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture,
        TimeSpan.FromSeconds(5));

    private static readonly Regex TypeDeclaration = new(
        @"\G(?:public|internal|private|protected|file)\s+(?:[a-z]+\s+)*"
        + @"(?:class|interface|enum|record(?:\s+(?:struct|class))?|struct)\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)",
        RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture,
        TimeSpan.FromSeconds(5));

    private const string MemberInitializer = "member initializer";
    private const string ConstructorBody = "constructor body";

    /// <summary>One open brace: what it opened, and what closing it has to put back.</summary>
    private readonly record struct Frame(Scope Kind, bool OwnsTypeName, bool Initializer);

    private enum Scope
    {
        /// <summary>A type body: a <c>{</c> here opens a member, an <c>=</c> here starts an initializer.</summary>
        Type,

        /// <summary>A constructor body or a nested block of one. Everything here runs during construction.</summary>
        Constructor,

        /// <summary>A lambda body. Runs on first use, not during construction.</summary>
        Lambda,

        /// <summary>A method, property or accessor body, or a nested block of one.</summary>
        Block,
    }

    /// <summary>Reads that happen while a type is being constructed, in source order.</summary>
    internal static IReadOnlyList<(int Line, string Kind, string Text)> Find(string source)
    {
        ArgumentNullException.ThrowIfNull(source);

        var code = Blank(source);
        var accessors = AccessorDeclaration.Matches(code)
            .Select(match => match.Groups["name"].Value)
            .ToHashSet(StringComparer.Ordinal);

        if (accessors.Count == 0)
        {
            return [];
        }

        var lines = source.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        var found = new List<(int Line, string Kind, string Text)>();
        var scopes = new Stack<Frame>();
        var typeNames = new Stack<string>();

        // What the next '{' opens, decided by whatever declaration was seen since the last ';'.
        var pending = (Scope?)null;
        var pendingType = string.Empty;

        // All three reset at every ';', '{' and '}': one logical statement's worth of context.
        var sawAssignment = false;
        var behindArrow = false;
        var inConstructorExpressionBody = false;

        var line = 1;

        for (var i = 0; i < code.Length; i++)
        {
            var c = code[i];

            if (c == '\n')
            {
                line++;
                continue;
            }

            if (c == '=' && i + 1 < code.Length && code[i + 1] == '>')
            {
                // An arrow on a constructor's own signature is an expression-bodied constructor, so
                // what follows it still runs during construction. Anywhere else it opens a lambda
                // or an expression-bodied member, and the read is deferred to first use.
                if (pending == Scope.Constructor)
                {
                    inConstructorExpressionBody = true;
                    pending = null;
                }
                else
                {
                    pending = Scope.Lambda;
                    behindArrow = true;
                }

                i++;
                continue;
            }

            if (c == '{')
            {
                var enclosing = scopes.Count > 0 ? scopes.Peek().Kind : Scope.Type;

                // With no declaration since the last ';', this brace opens a block rather than a
                // member body - an object initializer, an interpolation hole, an if, a using. Such
                // a brace inherits its enclosing scope, because a block inside a constructor still
                // runs during construction, and it stays inside the current statement rather than
                // starting a new one. In a type body the two cases are told apart by whether
                // anything has been assigned yet: nothing means a member body, something means an
                // initializer belonging to the field being declared.
                var initializer = pending is null && sawAssignment;

                scopes.Push(new Frame(
                    pending switch
                    {
                        Scope.Constructor => Scope.Constructor,
                        Scope.Lambda => Scope.Lambda,
                        Scope.Type => Scope.Type,
                        _ => enclosing == Scope.Type && !initializer ? Scope.Block : enclosing,
                    },
                    OwnsTypeName: pending == Scope.Type,
                    Initializer: initializer));

                if (pending == Scope.Type)
                {
                    typeNames.Push(pendingType);
                }

                pending = null;
                sawAssignment = initializer;
                behindArrow = false;
                continue;
            }

            if (c == '}')
            {
                var closed = scopes.Count > 0 ? scopes.Pop() : new Frame(Scope.Type, false, false);

                if (closed.OwnsTypeName && typeNames.Count > 0)
                {
                    typeNames.Pop();
                }

                pending = null;

                // Closing an object initializer returns to the statement that opened it, so what
                // follows on that statement is still an initializer.
                sawAssignment = closed.Initializer;
                behindArrow = false;
                inConstructorExpressionBody = false;
                continue;
            }

            if (c == ';')
            {
                pending = null;
                sawAssignment = false;
                behindArrow = false;
                inConstructorExpressionBody = false;
                continue;
            }

            if (c == '=' && !IsComparison(code, i))
            {
                sawAssignment = true;
                continue;
            }

            if (!char.IsLetter(c) && c != '_')
            {
                continue;
            }

            var end = i;

            while (end < code.Length && (char.IsLetterOrDigit(code[end]) || code[end] == '_'))
            {
                end++;
            }

            var word = code[i..end];

            if (accessors.Contains(word) && ReadsValueAt(code, end))
            {
                var kind = Classify(
                    scopes.Count > 0 ? scopes.Peek().Kind : Scope.Type,
                    sawAssignment,
                    behindArrow,
                    inConstructorExpressionBody);

                if (kind is not null)
                {
                    found.Add((line, kind, lines[line - 1].Trim()));
                }
            }
            else if (typeNames.Count > 0
                     && string.Equals(word, typeNames.Peek(), StringComparison.Ordinal)
                     && OpensParameterList(code, end)
                     && HasAccessModifierBefore(code, i))
            {
                pending = Scope.Constructor;
            }
            else
            {
                var declaration = TypeDeclaration.Match(code, i);

                if (declaration.Success)
                {
                    pending = Scope.Type;
                    pendingType = declaration.Groups["name"].Value;
                    i = declaration.Index + declaration.Length - 1;
                    continue;
                }
            }

            i = end - 1;
        }

        return found;
    }

    private static string? Classify(
        Scope scope,
        bool sawAssignment,
        bool behindArrow,
        bool inConstructorExpressionBody)
    {
        if (inConstructorExpressionBody)
        {
            return ConstructorBody;
        }

        if (behindArrow)
        {
            return null;
        }

        return scope switch
        {
            Scope.Constructor => ConstructorBody,
            Scope.Type when sawAssignment => MemberInitializer,
            _ => null,
        };
    }

    private static bool ReadsValueAt(string code, int after)
    {
        var i = SkipSpace(code, after);

        if (i >= code.Length || code[i] != '.')
        {
            return false;
        }

        i = SkipSpace(code, i + 1);

        return i + 5 <= code.Length
               && string.CompareOrdinal(code, i, "Value", 0, 5) == 0
               && (i + 5 == code.Length || (!char.IsLetterOrDigit(code[i + 5]) && code[i + 5] != '_'));
    }

    private static bool OpensParameterList(string code, int after)
    {
        var i = SkipSpace(code, after);

        return i < code.Length && code[i] == '(';
    }

    /// <summary>
    /// Walks back over <c>public sealed</c>, <c>private static</c> and the like. A constructor is
    /// the only member whose name equals its type's, and requiring a modifier in front keeps
    /// <c>new Thing(...)</c> written inside <c>Thing</c> from being read as one.
    /// </summary>
    private static bool HasAccessModifierBefore(string code, int start)
    {
        var i = start - 1;

        while (i >= 0 && char.IsWhiteSpace(code[i]))
        {
            i--;
        }

        var end = i + 1;

        while (i >= 0 && (char.IsLetter(code[i]) || code[i] == '_'))
        {
            i--;
        }

        var word = code[(i + 1)..end];

        return word is "public" or "private" or "protected" or "internal"
               || (word is "static" or "unsafe" or "sealed" && i >= 0 && HasAccessModifierBefore(code, i + 1));
    }

    private static bool IsComparison(string code, int i) =>
        (i > 0 && code[i - 1] is '=' or '!' or '<' or '>' or '+' or '-' or '*' or '/' or '%' or '&' or '|' or '^')
        || (i + 1 < code.Length && code[i + 1] == '=');

    private static int SkipSpace(string code, int i)
    {
        while (i < code.Length && code[i] is ' ' or '\t' or '\r' or '\n')
        {
            i++;
        }

        return i;
    }

    /// <summary>
    /// Replaces comments and string literals with spaces, keeping every newline so that line
    /// numbers still line up. Interpolation holes are left alone: a read inside <c>$"{...}"</c> is
    /// a read like any other, and blanking the hole would hide it.
    /// </summary>
    private static string Blank(string source)
    {
        var output = new StringBuilder(source);
        var i = 0;

        void Erase(int from, int count)
        {
            for (var k = from; k < from + count && k < source.Length; k++)
            {
                if (source[k] != '\n')
                {
                    output[k] = ' ';
                }
            }
        }

        while (i < source.Length)
        {
            if (Is(source, i, "//"))
            {
                var stop = source.IndexOf('\n', i);
                stop = stop < 0 ? source.Length : stop;
                Erase(i, stop - i);
                i = stop;
                continue;
            }

            if (Is(source, i, "/*"))
            {
                var stop = source.IndexOf("*/", i, StringComparison.Ordinal);
                stop = stop < 0 ? source.Length : stop + 2;
                Erase(i, stop - i);
                i = stop;
                continue;
            }

            if (StartsRawString(source, i, out var rawStart))
            {
                // A raw string's interpolation holes are blanked with the rest of it, unlike a
                // single-quoted one's: the delimiter rules make matching them by hand a poor
                // trade, and no read in this codebase hides in one.
                Erase(i, rawStart - i);
                i = BlankRawString(source, rawStart, Erase);
                continue;
            }

            if (source[i] == '\'')
            {
                var stop = i + 1;

                while (stop < source.Length && source[stop] != '\'')
                {
                    stop += source[stop] == '\\' ? 2 : 1;
                }

                stop = Math.Min(stop + 1, source.Length);
                Erase(i, stop - i);
                i = stop;
                continue;
            }

            if (source[i] == '"' || StartsStringLiteral(source, i))
            {
                i = BlankStringLiteral(source, i, Erase);
                continue;
            }

            i++;
        }

        return output.ToString();
    }

    /// <summary>Matches <c>"""</c>, and the <c>$</c> or <c>@</c> prefixed spellings of it.</summary>
    private static bool StartsRawString(string source, int i, out int quoteStart)
    {
        var j = i;

        while (j < source.Length && source[j] is '@' or '$')
        {
            j++;
        }

        quoteStart = j;

        return Is(source, j, "\"\"\"");
    }

    private static bool StartsStringLiteral(string source, int i)
    {
        var j = i;

        while (j < source.Length && source[j] is '@' or '$')
        {
            j++;
        }

        return j > i && j < source.Length && source[j] == '"';
    }

    private static int BlankRawString(string source, int i, Action<int, int> erase)
    {
        var quotes = 0;

        while (i + quotes < source.Length && source[i + quotes] == '"')
        {
            quotes++;
        }

        var stop = i + quotes;

        while (stop < source.Length)
        {
            if (source[stop] != '"')
            {
                stop++;
                continue;
            }

            var run = 0;

            while (stop + run < source.Length && source[stop + run] == '"')
            {
                run++;
            }

            stop += run;

            if (run >= quotes)
            {
                break;
            }
        }

        erase(i, stop - i);

        return stop;
    }

    private static int BlankStringLiteral(string source, int i, Action<int, int> erase)
    {
        var interpolated = false;
        var verbatim = false;

        while (source[i] is '@' or '$')
        {
            interpolated |= source[i] == '$';
            verbatim |= source[i] == '@';
            erase(i, 1);
            i++;
        }

        erase(i, 1);
        i++;

        while (i < source.Length)
        {
            if (!verbatim && source[i] == '\\')
            {
                erase(i, 2);
                i += 2;
                continue;
            }

            if (verbatim && Is(source, i, "\"\""))
            {
                erase(i, 2);
                i += 2;
                continue;
            }

            if (source[i] == '"')
            {
                erase(i, 1);

                return i + 1;
            }

            if (interpolated && Is(source, i, "{{"))
            {
                erase(i, 2);
                i += 2;
                continue;
            }

            if (interpolated && source[i] == '{')
            {
                // Leave the hole's code alone, braces included: the brace walk needs a matched
                // pair, and a read inside a hole is a read.
                var depth = 0;

                do
                {
                    depth += source[i] switch { '{' => 1, '}' => -1, _ => 0 };
                    i++;
                }
                while (i < source.Length && depth > 0);

                continue;
            }

            if (source[i] != '\n')
            {
                erase(i, 1);
            }

            i++;
        }

        return i;
    }

    private static bool Is(string source, int i, string token) =>
        i + token.Length <= source.Length
        && string.CompareOrdinal(source, i, token, 0, token.Length) == 0;
}
