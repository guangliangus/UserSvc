using System.Globalization;
using System.Text.RegularExpressions;
using Shouldly;
using Xunit;

namespace UserSvc.ArchitectureTests;

/// <summary>
/// A consumer-plane controller obtains the caller's id <b>only</b> through
/// <c>ICurrentUser.RequireConsumerId()</c> or <c>ICurrentUser.RequireSubject()</c> - never through
/// <c>RequireUserId()</c> and never off a caller's bare <c>UserId</c>.
/// <para>
/// <b>Why this needs a guard rather than a reviewer.</b> Both identity planes are served by one
/// OpenIddict instance, so a back-office operator's access token is a perfectly valid bearer token
/// on a consumer route and satisfies a bare <c>[Authorize]</c>. Its <c>sub</c> is an
/// <c>iam.backend_users</c> id, and <c>identity.users</c> numbers its rows independently, so the
/// two planes hand out the same integers to different people. Measured against a running host
/// during the wave-7 audit, before <c>RequireConsumerId()</c> existed: a back-office token with
/// <c>sub=1</c> read consumer 1's full profile at 200, and <c>DELETE /api/v1/account</c> with the
/// same token reached <c>DeregisterAsync</c> - it would have closed a stranger's account and signed
/// every one of their devices out. Nothing in either request was malformed.
/// </para>
/// <para>
/// The fix was per-endpoint, and <b>that is what makes it fragile</b>: nothing about writing a new
/// consumer controller pushes anybody towards the safe call. <c>RequireUserId()</c> is the shorter
/// name, it is the one on the interface, it compiles, and it returns exactly the integer the app
/// service below wants. The hole reopens silently, one new endpoint at a time - which is the same
/// argument <see cref="OptionsReadSiteTests"/> makes about a rule that survived on discipline for
/// four instances and then failed three more times in one wave.
/// </para>
/// <para>
/// <b>The rule is scoped to controllers because that is where the two planes are actually told
/// apart.</b> A consumer app service below takes a plain <c>int userId</c> and cannot know which
/// table it came from; the back-office slice takes <c>IBackOfficeCaller</c>, a separate abstraction
/// with its own <c>RequireUserId()</c> that is correct on its own routes. The controller is the one
/// layer holding both the token and the knowledge of which plane the route serves, so it is the
/// only layer where the question can be asked at all.
/// </para>
/// <para>
/// <b>What it deliberately does not do.</b> It does not read IL and it does not resolve types, so
/// it cannot tell <c>ICurrentUser.RequireUserId()</c> from some future unrelated
/// <c>RequireUserId()</c>. A textual ban on the name across a directory of twenty files is the
/// trade this project has already made twice (see <see cref="SourceLanguageTests"/> and
/// <see cref="OptionsReadSiteTests"/>): it costs precision and buys a failure that names a file and
/// a line, which is what a guard has to do to be acted on rather than deleted. Commented-out lines
/// are skipped - commented code is not code, and an XML doc that mentions the banned name while
/// explaining the rule must not fail the build.
/// </para>
/// <para>
/// <b>The deeper fix this guard is standing in for, and why it was not taken.</b> A positive
/// <c>consumer</c> scope, minted at the device-login grant and required by an authorization policy,
/// would turn all of this from a discipline into a policy - one declaration per controller, checked
/// by the framework, impossible to forget in a method body. Its cost is that it is not backwards
/// compatible: every access and refresh token already issued lacks the scope, so the day the policy
/// goes live every signed-in consumer device is refused until it re-authenticates, and there is no
/// migration window in which both are accepted without the policy meaning nothing during it. The
/// tempting cheap version - a policy built on the <i>absence</i> of a back-office scope - is worse
/// than the discipline it replaces, and <c>BackOfficeAuthorization</c>'s own documentation records
/// why: absence is also what a downgraded token, a malformed token and a token from another
/// authority look like, so a check built on it fails open. If the scope is ever minted, it has to
/// be minted first and required later, and this guard is what holds the line until then.
/// </para>
/// </summary>
public sealed class ConsumerPlaneCallerIdTests
{
    /// <summary>Every controller in the service lives under here.</summary>
    private const string ControllersRoot = "src/UserSvc.Api/Controllers";

    /// <summary>
    /// The one exempt area, and it is exempt because its routes serve the other plane: a
    /// back-office endpoint's <c>sub</c> <i>is</i> an <c>iam.backend_users</c> id, so
    /// <c>RequireUserId()</c> there is the correct call and <c>RequireConsumerId()</c> would refuse
    /// every legitimate caller. Today the exemption is used exactly once, by
    /// <c>BackOffice/TenantContextController.cs</c>.
    /// </summary>
    private const string BackOfficeArea = "BackOffice";

    private const string ControllerNamespaceRoot = "UserSvc.Api.Controllers";

    /// <summary>
    /// Where a name in this file becomes a caller: a declaration whose type is one of the three
    /// abstractions that can hand out a realm-ambiguous integer, or a <c>var</c> assigned from the
    /// static reader that builds one.
    /// <para>
    /// The read check below only looks at identifiers <i>this very file</i> declared to be a
    /// caller, and that is what keeps it from firing on an unrelated <c>UserId</c>:
    /// <c>TokenController</c>'s <c>DeviceLoginParameters.UserId</c> is a form-field name and
    /// <c>request.UserId</c> is an argument, neither of which any file binds to a caller type.
    /// </para>
    /// </summary>
    private static readonly Regex CallerBinding = new(
        @"\b(?:(?:ICurrentUser|IBackOfficeCaller|BackOfficeCaller)\??\s+"
        + @"|var\s+(?=[_a-z][A-Za-z0-9_]*\s*=\s*BackOfficeCallerReader\.Read\())"
        + @"(?<name>[_a-z][A-Za-z0-9_]*)\b",
        RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture,
        TimeSpan.FromSeconds(2));

    /// <summary>IDE0161 makes every file in this repository file-scoped, so one line is enough.</summary>
    private static readonly Regex FileScopedNamespace = new(
        @"^\s*namespace\s+(?<name>[A-Za-z0-9_.]+)\s*;",
        RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture,
        TimeSpan.FromSeconds(2));

    [Fact]
    public void NoConsumerPlaneControllerTakesARealmAmbiguousCallerId()
    {
        var root = PackageReferenceTests.RepositoryRoot();
        var offences = new List<string>();

        foreach (var file in ControllerFiles(root))
        {
            var relative = Relative(root, file);

            if (IsBackOfficeArea(relative))
            {
                continue;
            }

            offences.AddRange(Offences(relative, File.ReadAllLines(file)));
        }

        offences.ShouldBeEmpty(
            "A consumer-plane controller is taking a caller id that does not say which plane it "
            + "came from. Both planes are issued tokens by one OpenIddict instance, so a "
            + "back-office operator's token is a valid bearer token on this route and its sub is an "
            + "iam.backend_users id - measured live in wave 7, sub=1 read consumer 1's whole "
            + "profile at 200. Ask for the id as a consumer id instead: "
            + "ICurrentUser.RequireConsumerId() for an endpoint that acts on the consumer's own "
            + "rows (a back-office token then gets 403 FORBIDDEN), or ICurrentUser.RequireSubject() "
            + "where the id is paired with its realm and the endpoint legitimately serves both "
            + "planes, as /user/sessions does. Read the XML doc on ICurrentUser.RequireConsumerId "
            + "before choosing. Offences: " + string.Join("; ", offences));
    }

    /// <summary>
    /// The exemption above is a directory, so the directory has to mean something. A consumer
    /// controller dropped into <c>Controllers/BackOffice/</c> would be silently exempt from the rule
    /// while still serving a consumer route, and the namespace is the one other place the same fact
    /// is written down - so the two are required to agree.
    /// </summary>
    [Fact]
    public void TheBackOfficeExemptionIsTheDirectoryAndTheNamespaceTogether()
    {
        var root = PackageReferenceTests.RepositoryRoot();
        var mismatches = new List<string>();

        foreach (var file in ControllerFiles(root))
        {
            var relative = Relative(root, file);
            var segments = relative.Split('/')[3..^1];
            var expected = string.Join('.', [ControllerNamespaceRoot, .. segments]);

            var declared = File.ReadAllLines(file)
                .Select(line => FileScopedNamespace.Match(line))
                .FirstOrDefault(match => match.Success)
                ?.Groups["name"].Value;

            if (!string.Equals(declared, expected, StringComparison.Ordinal))
            {
                mismatches.Add(string.Create(
                    CultureInfo.InvariantCulture,
                    $"{relative} declares '{declared}' but its directory says '{expected}'"));
            }
        }

        mismatches.ShouldBeEmpty(
            "A controller's namespace and its directory disagree. The back-office area is exempt "
            + "from the consumer-plane caller-id rule by directory, so a file whose namespace and "
            + "directory say different things is either exempt without looking exempt or the "
            + "reverse. Move the file or fix the namespace: " + string.Join("; ", mismatches));
    }

    /// <summary>
    /// The guard has to be watched failing, and this is the part of it that can be watched without
    /// editing a controller. It feeds <see cref="Offences"/> every shape it is meant to catch - the
    /// exact one wave 7 removed from five controllers, the nullable property behind it, its
    /// null-conditional spelling, and both ways the static back-office reader yields an id - beside
    /// the ones it must leave alone, including the real line its first run wrongly flagged. A regex
    /// that quietly stopped matching would leave every test above green and the rule unguarded,
    /// which is the failure mode a scanning guard actually has.
    /// </summary>
    [Fact]
    public void TheDetectorFiresOnTheShapesWaveSevenRemoved()
    {
        string[] caught =
        [
            "        profiles.GetAsync(currentUser.RequireUserId(), cancellationToken);",
            "        var id = currentUser.UserId ?? 0;",
            "        var id = currentUser?.UserId ?? 0;",
            "        var id = BackOfficeCallerReader.Read(User).UserId;",
            "        var caller = BackOfficeCallerReader.Read(User); var id = caller.UserId;",
        ];

        string[] allowed =
        [
            "        profiles.GetAsync(currentUser.RequireConsumerId(), cancellationToken);",
            "        sessions.ListAsync(currentUser.RequireSubject(), cancellationToken);",
            "        var subject = (string?)request.GetParameter(DeviceLoginParameters.UserId);",
            "        await whitelist.AddAsync(caller, request.UserId, cancellationToken);",
            "        // var id = currentUser.RequireUserId();",
            "        /// Scoped by ICurrentUser.RequireUserId rather than sub alone.",

            // The line the first run of this guard wrongly flagged. AuthValidationController
            // describes a token to a relying service and legitimately serves both planes; it reads
            // the act claim and never an id, so the type is not what is banned here.
            "            IsTenantAdmin = BackOfficeCallerReader.Read(principal).Act?.IsAdmin ?? false,",
        ];

        foreach (var line in caught)
        {
            Offences("src/UserSvc.Api/Controllers/SampleController.cs", [Binding, line])
                .ShouldNotBeEmpty($"The detector no longer catches: {line.Trim()}");
        }

        Offences("src/UserSvc.Api/Controllers/SampleController.cs", [Binding, .. allowed])
            .ShouldBeEmpty("The detector fired on a line it must leave alone.");
    }

    /// <summary>The primary-constructor line the sample sources above are read against, so the
    /// detector is exercised with the binding it derives its identifiers from.</summary>
    private const string Binding =
        "public sealed class SampleController(ProfileAppService profiles, ICurrentUser currentUser) : ControllerBase";

    /// <summary>
    /// The rule itself, over one file's text. Static and taking its lines as an argument so that
    /// <see cref="TheDetectorFiresOnTheShapesWaveSevenRemoved"/> can prove it still fires without
    /// anybody having to break a controller first.
    /// </summary>
    private static IEnumerable<string> Offences(string relativePath, string[] lines)
    {
        var callerRead = CallerReadIn(lines);
        var offences = new List<string>();

        for (var i = 0; i < lines.Length; i++)
        {
            if (IsComment(lines[i]))
            {
                continue;
            }

            var reason = Reason(lines[i], callerRead);

            if (reason is not null)
            {
                offences.Add(string.Create(
                    CultureInfo.InvariantCulture, $"{relativePath}:{i + 1} {reason}"));
            }
        }

        return offences;
    }

    /// <summary>
    /// A matcher for "one of <i>this file's own</i> caller identifiers, dot UserId", or null when
    /// the file binds no caller at all.
    /// <para>
    /// Built per file rather than spelled as a fixed pattern, and anchored on both sides, because
    /// the alternative - a substring search for <c>"{name}.UserId"</c> - matches wherever the name
    /// happens to end another identifier: a caller called <c>user</c> would fire on
    /// <c>context.UserId</c>. A guard that misfires on somebody else's file gets deleted.
    /// </para>
    /// </summary>
    private static Regex CallerReadIn(string[] lines)
    {
        var receivers = new SortedSet<string>(StringComparer.Ordinal)
        {
            // The static reader, reached inline. Its other members are claim-type constants that
            // both planes legitimately use - TokenController names two of them, and
            // AuthValidationController reads Read(principal).Act to describe a token to a relying
            // service - so it is the .UserId that is banned here, never the type.
            @"BackOfficeCallerReader\.Read\([^)]*\)",
        };

        foreach (var line in lines.Where(line => !IsComment(line)))
        {
            foreach (Match binding in CallerBinding.Matches(line))
            {
                receivers.Add(Regex.Escape(binding.Groups["name"].Value));
            }
        }

        return new Regex(
            @"(?<![A-Za-z0-9_])(?:" + string.Join('|', receivers) + @")\??\.UserId\b",
            RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture,
            TimeSpan.FromSeconds(2));
    }

    private static string? Reason(string line, Regex callerRead)
    {
        if (line.Contains("RequireUserId(", StringComparison.Ordinal))
        {
            return "reads the caller id as RequireUserId(), which answers a back-office token's "
                   + "iam.backend_users id on a consumer route - call RequireConsumerId() instead";
        }

        // The nullable property behind RequireUserId(). Spelled "?? 0" or "is { } id", it is the
        // same integer with the same ambiguity and nothing refusing in front of it.
        return callerRead.IsMatch(line)
            ? "reads a caller's bare UserId, which does not say which of the two independently "
              + "numbered account tables it points into - call RequireConsumerId(), or "
              + "RequireSubject() to carry the realm with it"
            : null;
    }

    private static bool IsComment(string line)
    {
        var trimmed = line.TrimStart();

        return trimmed.StartsWith("//", StringComparison.Ordinal)
               || trimmed.StartsWith('*');
    }

    private static bool IsBackOfficeArea(string relativePath) =>
        relativePath.Split('/').Contains(BackOfficeArea, StringComparer.Ordinal);

    private static IEnumerable<string> ControllerFiles(string root) =>
        Directory
            .EnumerateFiles(Path.Combine(root, ControllersRoot), "*.cs", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .OrderBy(path => path, StringComparer.Ordinal);

    private static string Relative(string root, string file) =>
        Path.GetRelativePath(root, file).Replace(Path.DirectorySeparatorChar, '/');
}
