using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using UserSvc.Application.Features.BackOffice.Accounts;
using UserSvc.Application.Ports.TestWhitelist;
using UserSvc.Application.Security;
using UserSvc.Domain.Users;

namespace UserSvc.Application.Features.BackOffice.Consumers;

/// <summary>
/// Turns consumer account ids into the summaries an operator is allowed to see.
/// <para>
/// One place, two callers - the test-whitelist listing and the single-account lookup - because the
/// question "how much of a consumer may a back-office operator see" must have exactly one answer.
/// Two implementations of it would drift, and the direction they drift in is always towards showing
/// more.
/// </para>
/// <para>
/// <b>Decryption is bounded and one-way.</b> The consumer identity table stores a blind index and a
/// ciphertext and no masked copy, so a mask can only be derived by decrypting. That happens for the
/// ids handed in - one page of a listing, or one looked-up account - never for the table, and the
/// plaintext leaves this method only as a mask. Anything that wanted to <i>search</i> by contact
/// detail goes through the blind index instead: an implementation that decrypted rows looking for a
/// match would read every consumer's address to answer one question, which is a different
/// capability wearing the same name.
/// </para>
/// </summary>
public sealed class ConsumerSummaryService(
    IConsumerAccountDirectory consumers,
    IdentifierProtector protector,
    ILogger<ConsumerSummaryService> logger)
{
    /// <summary>
    /// One summary per id, in the order the ids were given. An id with no consumer row still yields
    /// an entry, with <see cref="ConsumerSummaryResponse.AccountExists"/> false: filtering it out
    /// would make an orphaned whitelist entry invisible, and an invisible entry cannot be removed.
    /// </summary>
    public async Task<IReadOnlyList<ConsumerSummaryResponse>> SummarizeAsync(
        IReadOnlyList<int> userIds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(userIds);

        if (userIds.Count == 0)
        {
            return [];
        }

        var accounts = (await consumers.ListAccountsAsync(userIds, cancellationToken))
            .ToDictionary(account => account.UserId);

        var contacts = await consumers.ListActiveContactsAsync(userIds, cancellationToken);

        var emailById = new Dictionary<int, string>();
        var phoneById = new Dictionary<int, string>();

        // The first ACTIVE identity per type that yields a mask wins. The port filters to ACTIVE
        // phone and email rows and orders them by id, so "first seen" is almost the whole rule -
        // the exception is a row whose ciphertext will not decrypt, which leaves the slot open for
        // the next identity of that type rather than claiming it with a blank. That is still
        // deterministic (the order is the database's), and it shows the operator an address the
        // account really holds instead of an empty column beside a readable one.
        foreach (var contact in contacts)
        {
            var target = contact.IdentityType switch
            {
                IdentityTypes.Email => emailById,
                IdentityTypes.Phone => phoneById,
                _ => null,
            };

            if (target is null || target.ContainsKey(contact.UserId))
            {
                continue;
            }

            var masked = MaskOrEmpty(contact);
            if (masked.Length > 0)
            {
                target[contact.UserId] = masked;
            }
        }

        return
        [
            .. userIds.Select(userId =>
            {
                var exists = accounts.TryGetValue(userId, out var account);

                return new ConsumerSummaryResponse
                {
                    UserId = userId,
                    AccountExists = exists,
                    Nickname = exists ? DisplayName(account!) : string.Empty,
                    EmailMasked = emailById.GetValueOrDefault(userId, string.Empty),
                    PhoneMasked = phoneById.GetValueOrDefault(userId, string.Empty),
                };
            })
        ];
    }

    /// <summary>
    /// The most recognisable label for a consumer: the nickname when it is set, otherwise the
    /// joined legal name. A quick-registered account has neither, and an empty label is still
    /// better than inventing one.
    /// <para>
    /// The join is the back-office one on purpose - it puts a CJK family name first and unseparated
    /// and a Latin given name first with a space - because a name rendered by two different rules
    /// in two screens reads as two different people.
    /// </para>
    /// </summary>
    private static string DisplayName(ConsumerAccountRow account) =>
        account.Nickname.Length > 0
            ? account.Nickname
            : BackOfficeNames.JoinFullName(account.FirstName, account.LastName);

    /// <summary>
    /// The masked identifier, or empty when this row cannot produce one.
    /// <para>
    /// A row whose ciphertext will not decrypt - a rotated or unavailable data key, a hand-edited
    /// value - yields empty rather than failing the request. The endpoint's job is to help an
    /// operator recognise an account, and one unreadable column must not take the listing down.
    /// It logs at Debug: this is a property of that row rather than news about this request, and an
    /// operator who needs to know can see the blank column.
    /// </para>
    /// </summary>
    private string MaskOrEmpty(ConsumerContactRow contact)
    {
        if (contact.IdentifierCiphertext.Length == 0)
        {
            return string.Empty;
        }

        try
        {
            return ConsumerContactMask.Mask(contact.IdentityType, protector.Decrypt(contact.IdentifierCiphertext));
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            logger.LogDebug(
                ex,
                "The {IdentityType} identifier of consumer account {UserId} could not be decrypted, "
                + "so its masked form is reported as empty. The row needs re-encrypting.",
                contact.IdentityType,
                contact.UserId);

            return string.Empty;
        }
    }
}
