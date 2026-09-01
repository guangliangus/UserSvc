using System.Net.Sockets;
using DotNet.Testcontainers.Configurations;

namespace UserSvc.IntegrationTests.Infrastructure;

/// <summary>
/// One cheap, cached answer to "can this machine start containers at all?".
/// <para>
/// Both the skip attribute and the collection fixture consult <b>this</b> probe, and that is the
/// load-bearing part. xunit constructs a collection fixture and awaits its
/// <c>InitializeAsync</c> even when every test in the collection is skipped, so a fixture that
/// only knew how to start containers would make a machine without Docker pay the full Docker
/// connect timeout in order to run nothing.
/// </para>
/// <para>
/// Testcontainers 4.14.0 depends on the Docker.DotNet.Enhanced fork, which does not expose
/// <c>DockerClientConfiguration</c>, so the endpoint Testcontainers resolved is read out of its
/// settings and connected to directly instead.
/// </para>
/// </summary>
internal static class DockerAvailability
{
    private const int ProbeTimeoutMilliseconds = 2_000;

    private static readonly Lazy<string?> Probe = new(Detect, LazyThreadSafetyMode.ExecutionAndPublication);

    /// <summary>True when a Docker daemon answered on the endpoint Testcontainers would use.</summary>
    public static bool IsAvailable => Probe.Value is null;

    /// <summary>Why the containers cannot start, phrased for a skip message; null when they can.</summary>
    public static string? SkipReason => Probe.Value;

    private static string? Detect()
    {
        Uri? endpoint;

        try
        {
            endpoint = TestcontainersSettings.OS.DockerEndpointAuthConfig?.Endpoint;
        }
        catch (Exception ex)
        {
            return $"Testcontainers could not resolve a Docker endpoint: {ex.Message}";
        }

        if (endpoint is null)
        {
            return "Testcontainers resolved no Docker endpoint on this machine.";
        }

        return endpoint.Scheme switch
        {
            "unix" => ProbeUnixSocket(endpoint.AbsolutePath),
            "npipe" => ProbeNamedPipe(endpoint),
            "tcp" or "http" or "https" => ProbeTcp(endpoint),
            _ => $"The Docker endpoint '{endpoint}' uses an unsupported scheme.",
        };
    }

    private static string? ProbeUnixSocket(string path)
    {
        if (!File.Exists(path))
        {
            return $"The Docker socket '{path}' does not exist.";
        }

        try
        {
            using var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            socket.Connect(new UnixDomainSocketEndPoint(path));
            return null;
        }
        catch (SocketException ex)
        {
            return $"The Docker socket '{path}' refused a connection: {ex.SocketErrorCode}.";
        }
        catch (IOException ex)
        {
            return $"The Docker socket '{path}' could not be reached: {ex.Message}";
        }
    }

    private static string? ProbeNamedPipe(Uri endpoint)
    {
        var pipe = $@"\\.\pipe\{endpoint.Segments[^1].Trim('/')}";
        return File.Exists(pipe) ? null : $"The Docker named pipe '{pipe}' does not exist.";
    }

    private static string? ProbeTcp(Uri endpoint)
    {
        try
        {
            using var client = new TcpClient();
            return client.ConnectAsync(endpoint.Host, endpoint.Port).Wait(ProbeTimeoutMilliseconds)
                ? null
                : $"The Docker endpoint '{endpoint}' did not answer within {ProbeTimeoutMilliseconds} ms.";
        }
        catch (AggregateException ex)
        {
            return $"The Docker endpoint '{endpoint}' refused a connection: {ex.InnerException?.Message}";
        }
        catch (SocketException ex)
        {
            return $"The Docker endpoint '{endpoint}' refused a connection: {ex.SocketErrorCode}.";
        }
    }
}
