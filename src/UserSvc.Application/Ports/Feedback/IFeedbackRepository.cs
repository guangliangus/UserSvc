using UserSvc.Domain.Feedback;

namespace UserSvc.Application.Ports.Feedback;

/// <summary>Persistence outlet for feedback. There is a database on the other side, so it is a port.</summary>
public interface IFeedbackRepository
{
    /// <summary>
    /// Every active category, in the order the drop-down renders them.
    /// <para>
    /// <b>The ordering is part of the contract</b> - <c>sort_order</c> then <c>code</c> - and it is
    /// PostgreSQL that must produce it. Re-sorting in memory would use .NET's culture-aware string
    /// comparison, which orders differently from the database collation, so two callers reading the
    /// same rows through different paths would see different drop-downs.
    /// </para>
    /// <para>An empty catalogue is an empty list, never null: the form still has to render.</para>
    /// </summary>
    Task<IReadOnlyList<FeedbackType>> ListActiveTypesAsync(CancellationToken cancellationToken);

    /// <summary>
    /// One active category by its exact code, or <c>null</c> when there is no such active row.
    /// <para>
    /// Both halves matter: an inactive category is indistinguishable from one that never existed,
    /// which is what makes <c>is_active = false</c> a working retirement switch. The foreign key on
    /// <c>feedback.type_code</c> cannot do this - it does not look at <c>is_active</c>.
    /// </para>
    /// <para>
    /// The match is exact and case-sensitive, as PostgreSQL compares text. <c>Bug</c> does not find
    /// <c>bug</c>; that is the behaviour the clients were written against.
    /// </para>
    /// </summary>
    Task<FeedbackType?> FindActiveTypeAsync(string code, CancellationToken cancellationToken);

    /// <summary>Stages one submission for insert. The id is assigned by the database and readable
    /// on the entity once the unit of work has saved.</summary>
    void Add(FeedbackSubmission submission);
}
