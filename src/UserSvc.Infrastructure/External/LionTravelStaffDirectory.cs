using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Polly;
using StackExchange.Redis;
using UserSvc.Application.Errors;
using UserSvc.Application.Ports.External;
using UserSvc.Application.Ports.Platform;
using UserSvc.Infrastructure.Platform;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// The real client for the corporate staff directory: the upstream that verifies an employee's
/// one-time password and holds the HR record behind an employee number.
/// <para>
/// <b>Three base addresses, one client.</b> The upstream is three services - an authentication host
/// that mints the application token, the host that checks one-time passwords, and the HR host - so
/// every request is built as an absolute URI and no <c>BaseAddress</c> is set. Setting one would
/// silently pin two thirds of the calls to the wrong host, and <see cref="Uri"/> resolution drops
/// a base path's last segment without complaining.
/// </para>
/// <para>
/// <b>What this class does and does not own.</b> Retries, timeouts and the circuit breaker live in
/// the standard resilience handler configured in <c>DependencyInjection</c>; the one thing here is
/// turning an upstream outcome into this service's error contract, and holding the application
/// token that every call needs.
/// </para>
/// <para>
/// <b>The credential check and the outage are deliberately different outcomes</b>, because
/// <see cref="IStaffDirectory"/> promises they are: a code the upstream examined and rejected comes
/// back as <see cref="StaffOtpVerification.IsVerified"/> false, while an upstream that could not be
/// asked is an <see cref="UpstreamException"/>. Collapsing them would tell a user their code was
/// wrong during an outage and tell no dashboard anything at all.
/// </para>
/// <para>
/// <b>Every detail of the wire shape below is an assumption.</b> The upstream's own contract was
/// not available while this was written; the paths, the request bodies, the response envelopes, the
/// field names, the checksum recipe and the token's <c>"basic "</c> scheme prefix are all taken
/// from a written description of it. They are asserted by the unit tests so that a mismatch shows
/// up as a failing test naming the field rather than as "sign-in does not work" - but the first
/// real call against the live upstream is what confirms them. See the notes on
/// <see cref="LionTravelOptions"/> for what a deployment must supply.
/// </para>
/// </summary>
public sealed class LionTravelStaffDirectory(
    HttpClient httpClient,
    LionTravelAccessTokenCache accessTokens,
    IOptions<LionTravelOptions> options,
    IClock clock,
    ILogger<LionTravelStaffDirectory> logger) : IStaffDirectory
{
    /// <summary>Assumed upstream paths, relative to their own hosts.</summary>
    private const string TokenPath = "v2/token/generator";

    private const string VerifyOtpPath = "api/V2/OTPLogin";

    private const string StaffProfilePath = "api/V2/Staff/StaffProfile";

    /// <summary>
    /// The upstream's timestamp layout: local-looking, with no zone. Because the checksum encodes
    /// only <c>HHmmss</c> in UTC, a host whose clock has drifted more than a few seconds will have
    /// every request rejected - NTP is a deployment requirement of this adapter, not a nicety.
    /// </summary>
    private const string UpstreamTimeLayout = "yyyy-MM-ddTHH:mm:ss";

    /// <summary>How much of an error body is worth keeping. An upstream error page is not a log
    /// entry.</summary>
    private const int MaxLoggedBodyLength = 2048;

    /// <summary>
    /// Case-insensitive on purpose. The envelope is PascalCase, the verification result is
    /// lowerCamel and the status fields are <c>rCode</c>/<c>rDesc</c>; an upstream that tidies its
    /// own casing one day should not take staff sign-in down.
    /// </summary>
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
    };

    public async Task<StaffOtpVerification> VerifyOtpAsync(
        string staffId,
        string oneTimePassword,
        CancellationToken cancellationToken)
    {
        var settings = ReadSettings();

        var response = await SendWithTokenAsync(
            settings,
            token =>
            {
                var request = new HttpRequestMessage(
                    HttpMethod.Post, Absolute(settings.OtpBaseAddress, VerifyOtpPath))
                {
                    // Re-readable content, because the resilience handler re-sends this very
                    // message on a retry and a stream would be spent after the first attempt.
                    Content = JsonContent.Create(
                        new LionOtpRequest { Stfn = staffId, Pswd = oneTimePassword }),
                };

                // Verbatim, with no scheme of ours prepended: the upstream's token is documented to
                // arrive already carrying its own "basic " prefix, and adding a second one produces
                // a 401 that looks like an expired token and provokes a pointless refresh.
                request.Headers.TryAddWithoutValidation("Authorization", token);

                return request;
            },
            "OTPLogin",
            cancellationToken);

        using (response)
        {
            await RequireSuccessAsync(response, "OTPLogin", cancellationToken);

            var body = await ReadAsync<LionOtpResponse>(response, "OTPLogin", cancellationToken);

            if (body?.Data is null)
            {
                // A 2xx with no result is the upstream saying "not verified" in its own way. It
                // becomes a refusal rather than an outage: something did answer, and this method
                // must never originate a true.
                logger.LogInformation(
                    "The staff directory answered the one-time-password check with no result "
                    + "(code {ResultCode}); treating it as not verified.",
                    body?.ResultCode);

                return new StaffOtpVerification(false, body?.ResultCode ?? string.Empty, string.Empty, string.Empty);
            }

            var result = body.Data;

            return new StaffOtpVerification(
                result.IsVerified,
                result.AuthResultCode ?? string.Empty,
                result.InfoCode ?? string.Empty,
                result.AuthResultMessage ?? string.Empty);
        }
    }

    public async Task<StaffProfile> GetStaffProfileAsync(string staffId, CancellationToken cancellationToken)
    {
        var settings = ReadSettings();
        var query = $"?CultureID={Uri.EscapeDataString(settings.CultureId)}"
                    + $"&StaffID={Uri.EscapeDataString(staffId)}"
                    + $"&UserID={Uri.EscapeDataString(staffId)}";

        var response = await SendWithTokenAsync(
            settings,
            token =>
            {
                var request = new HttpRequestMessage(
                    HttpMethod.Get, Absolute(settings.HrBaseAddress, StaffProfilePath + query));

                request.Headers.TryAddWithoutValidation("Authorization", token);

                return request;
            },
            "StaffProfile",
            cancellationToken);

        using (response)
        {
            await RequireSuccessAsync(response, "StaffProfile", cancellationToken);

            var body = await ReadAsync<LionStaffProfileResponse>(response, "StaffProfile", cancellationToken);

            if (body?.Data is null)
            {
                // 404, not 502: the upstream answered and has no such employee. That is a real
                // answer, and the port's contract says callers may rely on the difference.
                logger.LogInformation(
                    "The staff directory has no HR record for the employee number requested "
                    + "(code {ResultCode}).",
                    body?.ResultCode);

                throw new NotFoundException(
                    ErrorCodes.NotFound, "The staff directory has no record for that employee number.");
            }

            var profile = body.Data;

            return new StaffProfile(
                profile.StaffCode ?? staffId,
                profile.Name ?? string.Empty,
                profile.Alias ?? string.Empty,
                profile.Email ?? string.Empty,
                profile.Status ?? string.Empty,
                profile.DepartmentNo ?? string.Empty,
                profile.DepartmentName ?? string.Empty);
        }
    }

    /// <summary>
    /// Sends a request with the cached application token, and retries once with a fresh one if the
    /// upstream rejects it.
    /// <para>
    /// The retry is <b>one</b> attempt and only on 401. A cached token can be stale for reasons
    /// nothing here can see - the upstream restarted, an operator revoked it - and re-minting is
    /// the correct response; looping would turn one expired token into an unbounded mint storm
    /// against the host whose rate limit the cache exists to respect.
    /// </para>
    /// </summary>
    private async Task<HttpResponseMessage> SendWithTokenAsync(
        LionTravelOptions settings,
        Func<string, HttpRequestMessage> build,
        string operation,
        CancellationToken cancellationToken)
    {
        var token = await GetTokenAsync(settings, forceRefresh: false, cancellationToken);
        var response = await SendAsync(build(token), operation, cancellationToken);

        if (response.StatusCode != HttpStatusCode.Unauthorized)
        {
            return response;
        }

        response.Dispose();

        logger.LogWarning(
            "The staff directory rejected our application token on {Operation}; minting a fresh one "
            + "and retrying once.",
            operation);

        await accessTokens.InvalidateAsync();
        var refreshed = await GetTokenAsync(settings, forceRefresh: true, cancellationToken);

        return await SendAsync(build(refreshed), operation, cancellationToken);
    }

    /// <summary>
    /// The application token, from the shared cache, minting one when there is none.
    /// <para>
    /// Caching is a correctness requirement rather than an optimisation: the token is per
    /// application and the mint endpoint is rate limited, so a per-request mint stops working
    /// entirely under real traffic.
    /// </para>
    /// </summary>
    private Task<string> GetTokenAsync(
        LionTravelOptions settings, bool forceRefresh, CancellationToken cancellationToken) =>
        accessTokens.GetAsync(
            forceRefresh,
            ct => MintTokenAsync(settings, ct),
            clock.UtcNow,
            cancellationToken);

    private async Task<(string Token, TimeSpan Ttl)> MintTokenAsync(
        LionTravelOptions settings, CancellationToken cancellationToken)
    {
        // Not disposed here: SendAsync owns the request it is handed, on every path.
        var request = new HttpRequestMessage(
            HttpMethod.Post, Absolute(settings.TokenBaseAddress, TokenPath))
        {
            Content = JsonContent.Create(new LionTokenRequest
            {
                ApiKey = settings.ApiKey,
                ApiSecret = settings.ApiSecret,
                Checksum = BuildChecksum(settings.ApiKey, settings.ApiSecret, clock.UtcNow),
            }),
        };

        using var response = await SendAsync(request, "token", cancellationToken);

        await RequireSuccessAsync(response, "token", cancellationToken);

        var body = await ReadAsync<LionTokenResponse>(response, "token", cancellationToken);

        if (body?.Data is null || string.IsNullOrWhiteSpace(body.Data.AccessToken))
        {
            logger.LogError(
                "The staff directory answered the token mint with no access token (code "
                + "{ResultCode}). Nothing can be asked of it until this is fixed.",
                body?.ResultCode);

            throw Unavailable();
        }

        return (body.Data.AccessToken, TokenLifetime(body.Data));
    }

    /// <summary>
    /// How long a minted token may be cached.
    /// <para>
    /// A minute is shaved off the upstream's own window so a token is never presented in the
    /// second it expires - a race that surfaces as one intermittent 401 per token lifetime, which
    /// is the most expensive kind of bug to chase. An unparseable or non-positive window falls back
    /// to five minutes: caching briefly is safe, and caching a token forever because a timestamp
    /// could not be read is not.
    /// </para>
    /// </summary>
    private TimeSpan TokenLifetime(LionTokenData data)
    {
        const int skewSeconds = 60;
        var fallback = TimeSpan.FromMinutes(5);

        if (!DateTime.TryParseExact(
                data.CreateDateTime,
                UpstreamTimeLayout,
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out var created)
            || !DateTime.TryParseExact(
                data.ExpireDateTime,
                UpstreamTimeLayout,
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out var expires))
        {
            logger.LogWarning(
                "Could not read the staff directory token's validity window ({Created} to "
                + "{Expires}); caching it for {Fallback} instead.",
                data.CreateDateTime,
                data.ExpireDateTime,
                fallback);

            return fallback;
        }

        var life = expires - created;
        if (life <= TimeSpan.Zero)
        {
            return fallback;
        }

        var shaved = life - TimeSpan.FromSeconds(skewSeconds);

        return shaved > TimeSpan.Zero ? shaved : life;
    }

    /// <summary>
    /// The upstream's request signature, ported from the recipe it publishes.
    /// <para>
    /// <b>MD5 is the upstream's choice, not ours, and this is not a security primitive of this
    /// service.</b> It authenticates nothing on our side: the value is computed from two secrets we
    /// already hold and sent alongside them, so a collision or a preimage buys an attacker nothing
    /// they did not need the secrets for anyway. It is here because the upstream refuses requests
    /// without it.
    /// </para>
    /// <para>
    /// It encodes only <c>HHmmss</c> in UTC, which is why the clock note on
    /// <see cref="UpstreamTimeLayout"/> matters: a host more than a few seconds out of sync has
    /// every request refused, and nothing in the refusal says so.
    /// </para>
    /// </summary>
    public static string BuildChecksum(string apiKey, string apiSecret, DateTimeOffset now)
    {
        var nonce = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        var timestamp = now.UtcDateTime.ToString("HHmmss", CultureInfo.InvariantCulture);

#pragma warning disable CA5351 // The upstream's published recipe. See the remarks above.
        var digest = MD5.HashData(Encoding.UTF8.GetBytes(nonce + apiKey + apiSecret + timestamp));
#pragma warning restore CA5351

        return Convert.ToHexStringLower(digest) + nonce;
    }

    /// <summary>
    /// Reads the options and refuses when the deployment has not supplied them.
    /// <para>
    /// <b>Read here rather than in the constructor, and answered with <c>NOT_CONFIGURED</c> rather
    /// than <c>INTERNAL_ERROR</c>.</b> Constructing this adapter must not throw: it is built on
    /// the sign-in service's dependency graph, and a constructor that read options would make a
    /// deployment with no corporate directory fail on the password door too - the failure mode
    /// docs/architecture.md records. The code names the section so an operator goes and looks at
    /// the secrets instead of at this file.
    /// </para>
    /// </summary>
    private LionTravelOptions ReadSettings()
    {
        var settings = options.Value;

        var missing = new List<string>();
        AddIfBlank(missing, nameof(LionTravelOptions.TokenBaseAddress), settings.TokenBaseAddress);
        AddIfBlank(missing, nameof(LionTravelOptions.OtpBaseAddress), settings.OtpBaseAddress);
        AddIfBlank(missing, nameof(LionTravelOptions.HrBaseAddress), settings.HrBaseAddress);
        AddIfBlank(missing, nameof(LionTravelOptions.ApiKey), settings.ApiKey);
        AddIfBlank(missing, nameof(LionTravelOptions.ApiSecret), settings.ApiSecret);

        if (missing.Count > 0)
        {
            throw new AppException(
                ErrorCodes.NotConfigured,
                "The corporate staff directory is not configured on this deployment: "
                + string.Join(", ", missing.Select(key => $"{LionTravelOptions.SectionName}:{key}"))
                + " must be supplied.",
                500);
        }

        return settings;

        static void AddIfBlank(List<string> into, string name, string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                into.Add(name);
            }
        }
    }

    private static Uri Absolute(string baseAddress, string path) =>
        new(baseAddress.TrimEnd('/') + "/" + path, UriKind.Absolute);

    private async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, string operation, CancellationToken cancellationToken)
    {
        try
        {
            return await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw Unreachable(operation, ex);
        }
        catch (ExecutionRejectedException ex)
        {
            // The resilience pipeline's own verdict: the budget elapsed, the breaker is open, or
            // the call was shed. None of these derives from OperationCanceledException, so the
            // filter below would not see them.
            throw Unreachable(operation, ex);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw Unreachable(operation, ex);
        }
        finally
        {
            request.Dispose();
        }
    }

    private async Task RequireSuccessAsync(
        HttpResponseMessage response, string operation, CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        var body = await ReadBodyForLogAsync(response, cancellationToken);

        // Every non-2xx is an upstream fault here, including the 4xx range - unlike the
        // notification client, which splits them. The difference is who wrote the request: there we
        // compose a payload and a 400 means we got it wrong, while here the only variable inputs
        // are an employee number and a code the caller typed, and the upstream signals a bad one
        // through its own result fields in a 200. A 4xx therefore means our application
        // credentials or our contract are wrong, which nobody on this request can fix.
        logger.LogError(
            "The staff directory answered {StatusCode} on {Operation}. Upstream body: {ResponseBody}",
            (int)response.StatusCode,
            operation,
            body);

        throw Unavailable();
    }

    private async Task<T?> ReadAsync<T>(
        HttpResponseMessage response, string operation, CancellationToken cancellationToken)
    {
        try
        {
            return await response.Content.ReadFromJsonAsync<T>(Json, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException)
        {
            // 502 rather than a parse error surfacing as a 500: the body is the upstream's, and a
            // shape we cannot read is its fault and not this request's.
            logger.LogError(
                ex,
                "The staff directory's {Operation} response could not be read as {Shape}.",
                operation,
                typeof(T).Name);

            throw Unavailable();
        }
    }

    private static async Task<string> ReadBodyForLogAsync(
        HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            return body.Length <= MaxLoggedBodyLength ? body : body[..MaxLoggedBodyLength];
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or InvalidOperationException)
        {
            return "<unreadable: " + ex.GetType().Name + ">";
        }
    }

    private UpstreamException Unreachable(string operation, Exception cause)
    {
        // Neither the employee number nor the code appears here: the first is attacker-controlled
        // input and the second is a credential.
        logger.LogError(cause, "The staff directory is unreachable for {Operation}.", operation);

        return Unavailable(cause);
    }

    private static UpstreamException Unavailable(Exception? cause = null) => new(
        ErrorCodes.UpstreamUnavailable,
        "The corporate staff directory is unavailable. Nothing about the code you entered was checked.",
        cause);
}

/// <summary>
/// The corporate staff directory's application token, cached across the fleet and across requests.
/// <para>
/// <b>Two layers, and Redis is the soft one.</b> Redis is read first so every replica shares one
/// token, but a Redis outage degrades to one token per process rather than failing - the worst case
/// is one mint per replica instead of one per fleet. Failing closed here would take staff sign-in
/// down for a cache.
/// </para>
/// <para>
/// <b>Concurrent mints are collapsed into one.</b> A cold start with fifty simultaneous sign-ins
/// must produce one call to the upstream, not fifty; the gate plus the re-check inside it is what
/// makes the forty-nine that queued take the winner's answer instead of racing it.
/// </para>
/// <para>
/// Registered as a singleton, because the in-process half of the cache and the gate <i>are</i> the
/// state. It is a separate type from the client for exactly that reason: the client is a typed
/// <c>HttpClient</c> and therefore transient, and a singleton holding one would pin a single
/// handler for the life of the process.
/// </para>
/// <para>
/// It deliberately mirrors <see cref="WechatMiniAccessTokenCache"/> rather than sharing code with
/// it: the two cache different upstreams' tokens under different keys, and the day one of them
/// needs a different failure direction, a shared base class is what makes that change dangerous.
/// </para>
/// </summary>
public sealed class LionTravelAccessTokenCache(
    IConnectionMultiplexer connection,
    IOptions<RedisOptions> redisOptions,
    ILogger<LionTravelAccessTokenCache> logger)
{
    private const string CacheKeySuffix = "liontravel:access_token";

    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private readonly string _key = redisOptions.Value.KeyPrefix + CacheKeySuffix;

    private string _token = string.Empty;
    private DateTimeOffset _expiresAt = DateTimeOffset.MinValue;

    /// <param name="forceRefresh">Skip both layers. Set only after the upstream has rejected a
    /// token this cache handed out, never speculatively - the rate limit the cache exists for comes
    /// straight back.</param>
    /// <param name="mint">Mints a fresh token and reports how long it may be cached.</param>
    /// <param name="now">Current time, so the in-process expiry is not read from an ambient clock.</param>
    /// <param name="cancellationToken">Cancels the wait for the gate and the mint.</param>
    public async Task<string> GetAsync(
        bool forceRefresh,
        Func<CancellationToken, Task<(string Token, TimeSpan Ttl)>> mint,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(mint);

        if (!forceRefresh && TryRead(now) is { Length: > 0 } cached)
        {
            return cached;
        }

        if (!forceRefresh && await TryReadRedisAsync().ConfigureAwait(false) is { Length: > 0 } shared)
        {
            return shared;
        }

        await _refreshGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!forceRefresh && TryRead(now) is { Length: > 0 } refreshed)
            {
                return refreshed;
            }

            var (token, ttl) = await mint(cancellationToken).ConfigureAwait(false);

            _token = token;
            _expiresAt = now + ttl;

            await TryWriteRedisAsync(token, ttl).ConfigureAwait(false);

            return token;
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    /// <summary>Drops both layers after the upstream rejected the cached token. Best effort on the
    /// Redis half: the local copy is already gone, and a stale shared copy costs one more retry
    /// rather than a failure.</summary>
    public async Task InvalidateAsync()
    {
        _token = string.Empty;
        _expiresAt = DateTimeOffset.MinValue;

        try
        {
            await connection.GetDatabase().KeyDeleteAsync(_key).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsRedisFailure(ex))
        {
            logger.LogWarning(ex, "Could not drop the cached staff-directory token from Redis.");
        }
    }

    private string TryRead(DateTimeOffset now) =>
        _token.Length > 0 && now < _expiresAt ? _token : string.Empty;

    private async Task<string> TryReadRedisAsync()
    {
        try
        {
            var value = await connection.GetDatabase().StringGetAsync(_key).ConfigureAwait(false);

            return value.IsNullOrEmpty ? string.Empty : value.ToString();
        }
        catch (Exception ex) when (IsRedisFailure(ex))
        {
            logger.LogWarning(
                ex, "Could not read the shared staff-directory token; falling back to a local one.");

            return string.Empty;
        }
    }

    private async Task TryWriteRedisAsync(string token, TimeSpan ttl)
    {
        try
        {
            await connection.GetDatabase()
                .StringSetAsync(_key, token, expiry: ttl, keepTtl: false, when: When.Always, flags: CommandFlags.None)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (IsRedisFailure(ex))
        {
            logger.LogWarning(ex, "Could not share the staff-directory token through Redis.");
        }
    }

    /// <summary>
    /// The StackExchange.Redis hierarchy is not what it looks like: <c>RedisTimeoutException</c>
    /// derives from <see cref="TimeoutException"/> and <c>RedisCommandException</c> straight from
    /// <see cref="Exception"/>, so catching <c>RedisException</c> alone misses every timeout.
    /// </summary>
    private static bool IsRedisFailure(Exception ex) =>
        ex is RedisException or RedisTimeoutException or RedisCommandException;
}

/// <summary>
/// Where the corporate staff directory lives and which application credentials to present.
/// <para>
/// <b>Nothing here is <see cref="RequiredAttribute"/>, and this section is deliberately not
/// validated at startup.</b> One capability out of the whole service needs it - sign-in with a
/// corporate one-time password - while the password door, consumer sign-in, registration, sessions
/// and every integration test work without it. A <c>[Required]</c> plus <c>ValidateOnStart</c>
/// here would stop the host booting on a deployment that has no corporate directory, which is
/// every deployment today; and a <c>[Required]</c> without it would answer
/// <c>INTERNAL_ERROR</c> from the options validator rather than naming the missing keys. The
/// adapter checks them at the point of use and answers 500 <c>NOT_CONFIGURED</c> listing exactly
/// what is absent.
/// </para>
/// <para>
/// The three hosts are separate because the upstream is three services. Trailing slashes are
/// optional - the adapter builds absolute URIs and trims.
/// </para>
/// </summary>
public sealed class LionTravelOptions
{
    public const string SectionName = "StaffDirectory";

    /// <summary>Host that mints the application token, for example
    /// <c>https://auth.api.example.com</c>.</summary>
    public string TokenBaseAddress { get; init; } = string.Empty;

    /// <summary>Host that verifies one-time passwords.</summary>
    public string OtpBaseAddress { get; init; } = string.Empty;

    /// <summary>Host that serves HR staff profiles.</summary>
    public string HrBaseAddress { get; init; } = string.Empty;

    /// <summary>Application key. A secret: a Kubernetes secret or a local override file, never
    /// <c>appsettings.json</c>.</summary>
    public string ApiKey { get; init; } = string.Empty;

    /// <summary>Application secret. Same handling as <see cref="ApiKey"/>.</summary>
    public string ApiSecret { get; init; } = string.Empty;

    /// <summary>Culture the HR host is asked to localize names and departments into.</summary>
    public string CultureId { get; init; } = "zh_TW";

    /// <summary>Budget for one attempt against any of the three hosts.</summary>
    [Range(typeof(TimeSpan), "00:00:01", "00:00:30")]
    public TimeSpan AttemptTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Budget for the whole call, retries and backoff included. Somebody is waiting on a
    /// sign-in, so this is the number that decides how long they stare at a spinner.</summary>
    [Range(typeof(TimeSpan), "00:00:02", "00:01:00")]
    public TimeSpan TotalRequestTimeout { get; init; } = TimeSpan.FromSeconds(15);
}

// ---------------------------------------------------------------------------------------------
// The upstream's wire shapes. Names are its own, not ours, and every one of them is an assumption
// taken from a written description rather than from the upstream's contract - which is why they
// are pinned by unit tests. Kept in this file because nothing else may ever depend on them: they
// are one vendor's spelling of an idea the port states properly.
// ---------------------------------------------------------------------------------------------

/// <summary>Assumed body of the token mint.</summary>
internal sealed record LionTokenRequest
{
    [JsonPropertyName("ApiKey")]
    public string ApiKey { get; init; } = string.Empty;

    [JsonPropertyName("ApiSecret")]
    public string ApiSecret { get; init; } = string.Empty;

    [JsonPropertyName("Checksum")]
    public string Checksum { get; init; } = string.Empty;
}

/// <summary>Assumed envelope of the token mint's answer.</summary>
internal sealed record LionTokenResponse
{
    [JsonPropertyName("Data")]
    public LionTokenData? Data { get; init; }

    [JsonPropertyName("rCode")]
    public string? ResultCode { get; init; }

    [JsonPropertyName("rDesc")]
    public string? ResultDescription { get; init; }
}

/// <summary>Assumed token payload. <see cref="AccessToken"/> is documented to arrive already
/// carrying its authorization scheme prefix and is used verbatim as a header value.</summary>
internal sealed record LionTokenData
{
    [JsonPropertyName("AccessToken")]
    public string? AccessToken { get; init; }

    [JsonPropertyName("CreateDateTime")]
    public string? CreateDateTime { get; init; }

    [JsonPropertyName("ExpireDateTime")]
    public string? ExpireDateTime { get; init; }
}

/// <summary>Assumed body of the one-time-password check. <c>Stfn</c> is the employee number and
/// <c>Pswd</c> the code.</summary>
internal sealed record LionOtpRequest
{
    [JsonPropertyName("Stfn")]
    public string Stfn { get; init; } = string.Empty;

    [JsonPropertyName("Pswd")]
    public string Pswd { get; init; } = string.Empty;
}

/// <summary>Assumed envelope of the one-time-password check's answer.</summary>
internal sealed record LionOtpResponse
{
    [JsonPropertyName("Data")]
    public LionOtpResult? Data { get; init; }

    [JsonPropertyName("rCode")]
    public string? ResultCode { get; init; }

    [JsonPropertyName("rDesc")]
    public string? ResultDescription { get; init; }
}

/// <summary>
/// Assumed verdict on one code. <see cref="IsVerified"/> is the entire authentication decision on
/// the staff sign-in path, which is why the adapter never defaults it to true and never infers it
/// from a status code.
/// </summary>
internal sealed record LionOtpResult
{
    [JsonPropertyName("isVerified")]
    public bool IsVerified { get; init; }

    [JsonPropertyName("authResultCode")]
    public string? AuthResultCode { get; init; }

    [JsonPropertyName("infoCode")]
    public string? InfoCode { get; init; }

    [JsonPropertyName("authResultMsg")]
    public string? AuthResultMessage { get; init; }
}

/// <summary>Assumed envelope of the HR profile read.</summary>
internal sealed record LionStaffProfileResponse
{
    [JsonPropertyName("Data")]
    public LionStaffProfile? Data { get; init; }

    [JsonPropertyName("rCode")]
    public string? ResultCode { get; init; }

    [JsonPropertyName("rDesc")]
    public string? ResultDescription { get; init; }
}

/// <summary>Assumed HR record. <c>StfnSts</c> is carried through the port for a future
/// employment-status gate; nothing reads it yet.</summary>
internal sealed record LionStaffProfile
{
    [JsonPropertyName("StfnCode")]
    public string? StaffCode { get; init; }

    [JsonPropertyName("StfnName")]
    public string? Name { get; init; }

    [JsonPropertyName("StfnAlias")]
    public string? Alias { get; init; }

    [JsonPropertyName("StfnEmail")]
    public string? Email { get; init; }

    [JsonPropertyName("StfnSts")]
    public string? Status { get; init; }

    [JsonPropertyName("StfnDeptNo")]
    public string? DepartmentNo { get; init; }

    [JsonPropertyName("StfnDeptName")]
    public string? DepartmentName { get; init; }
}
