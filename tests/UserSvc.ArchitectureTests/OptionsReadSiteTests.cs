using System.Globalization;
using System.Text.RegularExpressions;
using Shouldly;
using Xunit;

namespace UserSvc.ArchitectureTests;

/// <summary>
/// A ratchet on the rule docs/architecture.md calls "a missing capability may only break itself":
/// <b><c>IOptions&lt;T&gt;.Value</c> is read at the point of use, never while a type is being
/// constructed.</b>
/// <para>
/// <c>.Value</c> is where <c>ValidateDataAnnotations</c> actually runs, so a field initializer that
/// binds it makes <i>merely constructing</i> the type throw when its section is unconfigured. That
/// has taken this service down three separate times, each time somewhere unrelated to the missing
/// section: an app service holding four social providers answered 500 for all four when any one
/// lacked credentials, and a pure-database unbind endpoint answered 500 about a signing key. Both
/// were found by running the host, not by reading the code - which is why the rule needs a guard
/// rather than a reviewer.
/// </para>
/// <para>
/// <b>This is a ratchet, not a clean bill of health.</b> The files below still hold the shape and
/// are listed so the guard can fail on the <i>next</i> one. Every one of them currently sits on a
/// section registered with <c>ValidateOnStart()</c> (or, for <c>BackOfficeAccountOptions</c>, one
/// with no DataAnnotations at all), so an invalid section already refuses the boot and <c>.Value</c>
/// cannot throw afterwards - they are the shape without the outage. The shape is what turned into
/// an outage each of the three times <c>ValidateOnStart</c> was deliberately dropped from a section,
/// which is a change somebody makes for good reasons in a different file. Fixing one is a two-line
/// change (an expression-bodied property with the same name), so shorten this list rather than
/// lengthen it.
/// </para>
/// <para>
/// <b>What it deliberately does not catch.</b> Reads inside a constructor <i>body</i> and reads
/// spread over more than one line: matching those textually costs precision, and a guard that
/// misfires on somebody else's file gets deleted. Two constructor-body reads exist and are known -
/// <c>IdentifierProtector</c> and <c>Fido2WebAuthnCeremony</c>, the latter being the one place that
/// reads a section without <c>ValidateOnStart</c> during construction, bounded to the passkey slice
/// because <c>IWebAuthnCeremony</c> reaches exactly one controller. A read deferred behind a
/// <c>Lazy&lt;T&gt;</c> or a lambda is not a construction-time read at all and is correctly ignored.
/// </para>
/// </summary>
public sealed class OptionsReadSiteTests
{
    /// <summary>
    /// A field declaration whose initializer reads <c>.Value</c> directly. Lines containing
    /// <c>=&gt;</c> are excluded because the read is then inside a lambda - the
    /// <c>Lazy&lt;byte[]&gt;</c> idiom two of these were converted to - and runs on first use.
    /// </summary>
    private static readonly Regex ConstructionTimeRead = new(
        @"^\s*(?:private|protected|internal|public)[^;=]*\breadonly\b[^;=]*=[^;]*\.Value\b",
        RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture,
        TimeSpan.FromSeconds(2));

    /// <summary>
    /// The instances that exist today, by path. Keyed on the file rather than the line so that
    /// editing an unrelated part of one of these files does not fail the build.
    /// </summary>
    private static readonly string[] Known =
    [
        "src/UserSvc.Api/Controllers/TokenController.cs",
        "src/UserSvc.Application/Features/BackOffice/Accounts/BackOfficeAccountAppService.cs",
        "src/UserSvc.Application/Features/RiskControl/CaptchaAppService.cs",
        "src/UserSvc.Application/Features/Verification/VerificationAppService.cs",
        "src/UserSvc.Infrastructure/Auth/Fido2WebAuthnCeremony.cs",
        "src/UserSvc.Infrastructure/Auth/OpenIddictPruningService.cs",
        "src/UserSvc.Infrastructure/Platform/RedisAuthzSnapshotCache.cs",
        "src/UserSvc.Infrastructure/Platform/RedisRateLimiter.cs",
        "src/UserSvc.Infrastructure/Platform/RedisSessionRevocationStore.cs",
    ];

    [Fact]
    public void NoNewTypeReadsItsOptionsWhileBeingConstructed()
    {
        var root = PackageReferenceTests.RepositoryRoot();
        var found = new List<string>();

        var files = Directory
            .EnumerateFiles(Path.Combine(root, "src"), "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal));

        foreach (var file in files)
        {
            var lines = File.ReadAllLines(file);

            for (var i = 0; i < lines.Length; i++)
            {
                if (!lines[i].Contains("=>", StringComparison.Ordinal)
                    && ConstructionTimeRead.IsMatch(lines[i]))
                {
                    found.Add(string.Create(
                        CultureInfo.InvariantCulture,
                        $"{Relative(root, file)}:{i + 1}"));
                }
            }
        }

        var unexpected = found
            .Where(hit => !Known.Contains(hit[..hit.LastIndexOf(':')], StringComparer.Ordinal))
            .ToList();

        unexpected.ShouldBeEmpty(
            "A new type reads IOptions<T>.Value in a field initializer, so merely constructing it "
            + "throws when its section is unconfigured - and it takes every endpoint that shares "
            + "the constructor down with it (docs/architecture.md, \"a missing capability may only "
            + "break itself\"). Read it at the point of use instead: replace the field with an "
            + "expression-bodied property of the same name. Offenders: "
            + string.Join(", ", unexpected));
    }

    /// <summary>
    /// The list has to shrink to stay honest. A file that has been fixed but is still listed makes
    /// the ratchet look tighter than it is, and hides the next one behind an entry nobody rechecks.
    /// </summary>
    [Fact]
    public void TheKnownListNamesOnlyFilesThatStillHoldTheShape()
    {
        var root = PackageReferenceTests.RepositoryRoot();

        var stale = Known
            .Where(known => !File.Exists(Path.Combine(root, known))
                            || !File.ReadAllLines(Path.Combine(root, known)).Any(
                                line => !line.Contains("=>", StringComparison.Ordinal)
                                        && ConstructionTimeRead.IsMatch(line)))
            .ToList();

        stale.ShouldBeEmpty(
            "These files no longer read their options while being constructed, so remove them from "
            + "the known list: " + string.Join(", ", stale));
    }

    private static string Relative(string root, string file) =>
        Path.GetRelativePath(root, file).Replace(Path.DirectorySeparatorChar, '/');
}
