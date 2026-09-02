using Microsoft.EntityFrameworkCore;
using UserSvc.Application.Ports.Feedback;
using UserSvc.Domain.Feedback;

namespace UserSvc.Infrastructure.Persistence.Repositories;

/// <summary>
/// <see cref="IFeedbackRepository"/> over the shared persistence context, so a submission and the
/// outbox row of anything raised alongside it commit together.
/// </summary>
public sealed class FeedbackRepository(UserSvcDbContext db) : IFeedbackRepository
{
    /// <summary>
    /// The active catalogue in drop-down order.
    /// <para>
    /// <b>The ORDER BY belongs to PostgreSQL and must stay there.</b> The secondary key is a text
    /// column, and sorting it in .NET would apply the host's culture rules, which order differently
    /// from the database collation - so the list would silently depend on where it was sorted.
    /// </para>
    /// <para>
    /// Untracked: the caller reads labels off these rows and never writes to them.
    /// </para>
    /// </summary>
    public async Task<IReadOnlyList<FeedbackType>> ListActiveTypesAsync(CancellationToken cancellationToken) =>
        await db.FeedbackTypes
            .AsNoTracking()
            .Where(type => type.IsActive)
            .OrderBy(type => type.SortOrder)
            .ThenBy(type => type.Code)
            .ToListAsync(cancellationToken);

    /// <summary>
    /// One active category by exact code.
    /// <para>
    /// Both predicates are on the database side deliberately. Fetching by code and testing
    /// <c>IsActive</c> in memory would work, but it also reads a row this service has no other use
    /// for, and it puts the retirement rule somewhere a later edit can drop it without failing a
    /// test.
    /// </para>
    /// </summary>
    public Task<FeedbackType?> FindActiveTypeAsync(string code, CancellationToken cancellationToken) =>
        db.FeedbackTypes
            .AsNoTracking()
            .FirstOrDefaultAsync(type => type.Code == code && type.IsActive, cancellationToken);

    public void Add(FeedbackSubmission submission) => db.Feedback.Add(submission);
}
