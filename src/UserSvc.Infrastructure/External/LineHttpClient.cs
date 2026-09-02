using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Polly;
using UserSvc.Application.Features.SocialIdentity;
using UserSvc.Application.Ports.External;

namespace UserSvc.Infrastructure.External;

/// <summary>
/// LINE OpenID verification over HTTP.
/// <para>
/// The id_token is handed to LINE's own <c>/oauth2/v2.1/verify</c> endpoint together with the
/// channel id and the nonce, so LINE checks the signature, the expiry, the audience and the nonce
/// in one round trip. This service therefore holds no LINE public keys and cannot fall behind
/// LINE's rotation schedule - which is the failure a local verifier would eventually have, quietly,
/// at three in the morning.
/// </para>
/// <para>
/// <b>The three defensive re-checks after LINE has already answered are not redundancy for its own
/// sake.</b> The issuer, the audience and the presence of a subject are the three things that make
/// the answer mean "this token belongs to our channel"; a response that verified fine but names
/// somebody else's channel is exactly what a token borrowed from another LINE app looks like.
/// </para>
/// <para>
/// <b>Every failure - including transport and parse failures - is a refusal, not a 502.</b> That is
/// the opposite of the WeChat adapter and it is deliberate: verification happens <i>at</i> LINE, so
/// "LINE said no" and "we could not ask LINE" both leave this service holding a token nobody has
/// vouched for. Reporting the second as an upstream fault would mean answering 502 to a forged
/// token during an outage, which is the one moment a forgery would most like to be treated as
/// infrastructure noise.
/// </para>
/// </summary>
public sealed class LineHttpClient(
    HttpClient httpClient,
    IOptions<LineOptions> options,
    ILogger<LineHttpClient> logger) : ILineClient
{
    /// <summary>The only issuer a LINE id_token may name.</summary>
    private const string LineIssuer = "https://access.line.me";

    private const string VerifyPath = "oauth2/v2.1/verify";

    /// <summary>
    /// How much of LINE's <c>error_description</c> reaches the log. Short on purpose: the field is
    /// free-form and has been observed quoting the id_token back, and a whole id_token is a bearer
    /// credential that does not belong in a log line. This is enough to tell LINE's refusal reasons
    /// apart and not enough to hold one.
    /// </summary>
    private const int MaxLoggedDescriptionLength = 200;

        // Read at the point of use, NOT in the constructor. IOptions<T>.Value is what runs
        // DataAnnotations validation, so reading it eagerly throws OptionsValidationException
        // while this type is merely being CONSTRUCTED - and SocialIdentityAppService takes all
        // four providers in its constructor, so one missing credential made every provider's
        // endpoint answer 500. Deferring the read means an unconfigured provider fails only on
        // its own endpoints. Value is cached after the first successful read, so this costs nothing.
    private LineOptions _options => options.Value;

    public async Task<LineIdentity> VerifyIdTokenAsync(
        string idToken,
        string nonce,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(idToken))
        {
            throw new LineRejectedException("A LINE identity token is required.");
        }

        var form = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["id_token"] = idToken,
            ["client_id"] = _options.ChannelId,
        };

        if (!string.IsNullOrEmpty(nonce))
        {
            form["nonce"] = nonce;
        }

        var verified = await SendAsync(form, cancellationToken);

        if (!string.IsNullOrEmpty(verified.Error))
        {
            // error_description is written for developers and can quote the id_token, so it is
            // truncated on the way into the log: an id_token is a bearer credential and a log line
            // is the wrong place for a whole one, and an unbounded upstream string is a log-flood
            // primitive besides. The client learns only that LINE refused, which is all it can
            // act on.
            logger.LogWarning(
                "LINE refused an identity token: {Error} {ErrorDescription}.",
                verified.Error,
                ForLog(verified.ErrorDescription));

            throw new LineRejectedException("LINE could not verify the sign-in.");
        }

        if (!string.Equals(verified.Issuer, LineIssuer, StringComparison.Ordinal))
        {
            logger.LogWarning("A LINE verify response named an unexpected issuer {Issuer}.", verified.Issuer);

            throw new LineRejectedException("LINE could not verify the sign-in.");
        }

        if (_options.ChannelId.Length > 0
            && !string.Equals(verified.Audience, _options.ChannelId, StringComparison.Ordinal))
        {
            // A token minted for a different LINE channel. It verifies perfectly and belongs to
            // somebody else's application; without this check it would sign its holder in here.
            logger.LogWarning(
                "A LINE identity token was issued for channel {Audience}, not this one.", verified.Audience);

            throw new LineRejectedException("LINE could not verify the sign-in.");
        }

        if (string.IsNullOrWhiteSpace(verified.Subject))
        {
            throw new LineRejectedException("LINE returned no account identifier.");
        }

        return new LineIdentity(
            verified.Subject,
            verified.Email ?? string.Empty,
            verified.Name ?? string.Empty,
            verified.Picture ?? string.Empty);
    }

    private async Task<LineVerifyResponse> SendAsync(
        Dictionary<string, string> form,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, VerifyPath)
        {
            // Re-readable content, which the resilience handler's retries require: each attempt
            // re-sends this same message and a stream would be exhausted after the first.
            Content = new FormUrlEncodedContent(form),
        };

        HttpResponseMessage response;

        try
        {
            response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or ExecutionRejectedException)
        {
            throw Unverifiable(ex);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw Unverifiable(ex);
        }

        using (response)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                var parsed = JsonSerializer.Deserialize(body, LineApiJson.Default.LineVerifyResponse);
                if (parsed is null)
                {
                    throw new LineRejectedException("LINE could not verify the sign-in.");
                }

                if (!response.IsSuccessStatusCode && string.IsNullOrEmpty(parsed.Error))
                {
                    // A failure status whose body carried no error object. Manufacture one so the
                    // caller's single check below still sees a refusal.
                    return parsed with
                    {
                        Error = "invalid_request",
                        ErrorDescription = string.Create(
                            CultureInfo.InvariantCulture,
                            $"LINE answered {(int)response.StatusCode}."),
                    };
                }

                return parsed;
            }
            catch (JsonException ex)
            {
                throw Unverifiable(ex);
            }
        }
    }

    private static string ForLog(string? description)
    {
        var value = description ?? string.Empty;

        return value.Length <= MaxLoggedDescriptionLength ? value : value[..MaxLoggedDescriptionLength] + "...";
    }

    private LineRejectedException Unverifiable(Exception cause)
    {
        logger.LogWarning(cause, "LINE could not be asked to verify an identity token.");

        return new LineRejectedException("LINE could not verify the sign-in.", cause);
    }
}
