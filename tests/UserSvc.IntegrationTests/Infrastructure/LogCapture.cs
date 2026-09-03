using System.Collections.Concurrent;
using System.Globalization;
using Microsoft.Extensions.Logging;

namespace UserSvc.IntegrationTests.Infrastructure;

/// <summary>One captured log line, flattened to the parts an assertion can read.</summary>
/// <param name="Level">Severity.</param>
/// <param name="Category">Logger category - the type that wrote it.</param>
/// <param name="Message">The formatted message.</param>
/// <param name="Exception">The exception's type and message, or null.</param>
internal sealed record LogEntry(LogLevel Level, string Category, string Message, string? Exception);

/// <summary>
/// An in-memory <see cref="ILoggerProvider"/> for the hosts these tests build themselves.
/// <para>
/// It exists because two of the task queue's promises are <b>only</b> observable in the log. "This
/// pod is not working the queue" has no endpoint and writes no row - by design, since the whole
/// point of the kill switch is that nothing happens - and "the handler threw and the row was left
/// for the reclaim" is a decision the runner records rather than a state it stores. Asserting the
/// absence of work proves the first only weakly; the log line is the positive statement, and it is
/// the line an operator will actually read during an incident, so it is worth pinning.
/// </para>
/// <para>
/// It also doubles as the diagnostic for every timeout in this file: a test that waited for a
/// delivery that never came prints the runner's own log with the failure, which is the difference
/// between "expected 3, got 0" and "the claim failed with SQLSTATE 42P01".
/// </para>
/// </summary>
internal sealed class LogCapture : ILoggerProvider
{
    private readonly ConcurrentQueue<LogEntry> _entries = new();

    /// <summary>Everything logged so far, oldest first.</summary>
    public IReadOnlyList<LogEntry> Entries => [.. _entries];

    public ILogger CreateLogger(string categoryName) => new CaptureLogger(this, categoryName);

    /// <summary>Nothing to release: the entries are held for the test to read after the host is
    /// stopped, so disposal must not clear them.</summary>
    public void Dispose()
    {
    }

    /// <summary>Whether any line at <paramref name="level"/> or above contains
    /// <paramref name="fragment"/>.</summary>
    public bool Contains(string fragment, LogLevel level = LogLevel.Trace) => _entries.Any(
        entry => entry.Level >= level
                 && entry.Message.Contains(fragment, StringComparison.Ordinal));

    /// <summary>Every line, formatted for a failure message.</summary>
    public string Dump()
    {
        var lines = _entries.Select(entry => string.Create(
            CultureInfo.InvariantCulture,
            $"  [{entry.Level}] {entry.Category}: {entry.Message}{(entry.Exception is null ? string.Empty : " <- " + entry.Exception)}"));

        return "Host log:" + Environment.NewLine + string.Join(Environment.NewLine, lines);
    }

    private void Add(LogEntry entry) => _entries.Enqueue(entry);

    private sealed class CaptureLogger(LogCapture sink, string category) : ILogger
    {
        public IDisposable BeginScope<TState>(TState state)
            where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            ArgumentNullException.ThrowIfNull(formatter);

            sink.Add(new LogEntry(
                logLevel,
                category,
                formatter(state, exception),
                exception is null ? null : exception.GetType().Name + ": " + exception.Message));
        }
    }

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();

        public void Dispose()
        {
        }
    }
}
