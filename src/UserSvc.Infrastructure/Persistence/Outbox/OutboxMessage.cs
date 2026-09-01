namespace UserSvc.Infrastructure.Persistence.Outbox;

/// <summary>
/// An integration event waiting to be published (decision 16). It is <b>written in the same
/// transaction as the business row</b> — the one point in the whole chain that guarantees
/// "the database changed ⟺ the event will be published". Miss it and there is no second chance.
/// The background dispatcher that pushes these to the broker provides delivery guarantees, not
/// atomicity.
/// </summary>
public sealed class OutboxMessage
{
    public int Id { get; set; }
    public string MessageId { get; set; } = string.Empty;
    public string EventName { get; set; } = string.Empty;
    public string Payload { get; set; } = string.Empty;
    public string TraceParent { get; set; } = string.Empty;
    public DateTimeOffset OccurredAt { get; set; }
    public DateTimeOffset? DispatchedAt { get; set; }
    public int Attempts { get; set; }
    public string LastError { get; set; } = string.Empty;
}
