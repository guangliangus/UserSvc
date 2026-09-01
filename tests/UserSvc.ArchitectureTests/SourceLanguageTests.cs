using System.Globalization;
using Shouldly;
using Xunit;

namespace UserSvc.ArchitectureTests;

/// <summary>
/// C# source is written in English — identifiers, comments and messages alike.
/// <para>
/// The reason is not aesthetic. Compiler and analyzer diagnostics, stack traces, log messages and
/// public API documentation all quote source text verbatim, and a mixed-language codebase makes
/// those unsearchable for half the people reading them. Prose documentation under docs/ is exempt;
/// this rule covers code only.
/// </para>
/// <para>
/// Scoped to .cs deliberately: SQL seed data may legitimately need non-Latin content one day
/// (localized menu names, for instance), and this guard should not stand in the way of that.
/// </para>
/// </summary>
public sealed class SourceLanguageTests
{
    [Fact]
    public void SourceFilesContainNoCjkCharacters()
    {
        var root = PackageReferenceTests.RepositoryRoot();
        var offenders = new List<string>();

        foreach (var directory in new[] { "src", "tests" })
        {
            var files = Directory.EnumerateFiles(Path.Combine(root, directory), "*.cs", SearchOption.AllDirectories)
                .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
                .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal));

            foreach (var file in files)
            {
                var lines = File.ReadAllLines(file);
                for (var i = 0; i < lines.Length; i++)
                {
                    if (lines[i].Any(IsCjk))
                    {
                        offenders.Add(string.Create(
                            CultureInfo.InvariantCulture,
                            $"{Path.GetRelativePath(root, file)}:{i + 1}"));
                    }
                }
            }
        }

        offenders.ShouldBeEmpty("C# source must be written in English. Offending lines: " +
                                string.Join(", ", offenders.Take(20)));
    }

    /// <summary>CJK Unified Ideographs plus kana and fullwidth forms. Written as code points
    /// rather than literals so this file stays inside the rule it enforces.</summary>
    private static bool IsCjk(char c) =>
        c is >= (char)0x4E00 and <= (char)0x9FFF       // CJK Unified Ideographs
            or >= (char)0x3040 and <= (char)0x30FF     // Hiragana and Katakana
            or >= (char)0xFF00 and <= (char)0xFFEF;    // Halfwidth and fullwidth forms
}
