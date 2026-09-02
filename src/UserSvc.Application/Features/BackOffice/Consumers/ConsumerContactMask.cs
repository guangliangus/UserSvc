using UserSvc.Application.Features.BackOffice.Accounts;
using UserSvc.Domain.BackOffice;
using UserSvc.Domain.Users;

namespace UserSvc.Application.Features.BackOffice.Consumers;

/// <summary>
/// How much of a consumer's contact detail an operator is shown.
/// <para>
/// It delegates to the back-office masking rule rather than defining a second one. The rule itself
/// - first character plus the readable domain for an address, last four digits for a number - is
/// not the interesting part; having <b>one</b> of it is, because the same human can appear on the
/// back-office roster and in this listing, and two rules would show two different maskings of the
/// same mailbox and make an operator doubt they are looking at the same person.
/// </para>
/// <para>
/// The two planes spell their identity types differently (<c>EMAIL</c> here, <c>email</c> there),
/// which is exactly why the mapping is explicit: passing this plane's constant straight through
/// would silently fall to the opaque default and mask an address as if it were an employee number.
/// </para>
/// <para>
/// Pure computation, so it is not a port and the tests use the real thing.
/// </para>
/// </summary>
public static class ConsumerContactMask
{
    /// <summary>
    /// Masks a decrypted identifier for display. An identity type that is not a contact detail -
    /// a social provider, a passkey - masks to nothing rather than to stars: those rows are not
    /// contact details, and showing a masked provider subject would suggest they are.
    /// </summary>
    public static string Mask(string identityType, string plaintext) => identityType switch
    {
        IdentityTypes.Email => BackOfficeIdentifiers.Mask(BackendIdentityTypes.Email, plaintext),
        IdentityTypes.Phone => BackOfficeIdentifiers.Mask(BackendIdentityTypes.Phone, plaintext),
        _ => string.Empty,
    };
}
