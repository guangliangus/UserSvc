namespace UserSvc.Domain.Abstractions;

/// <summary>
/// The name an integration event travels under on the broker. <b>Must be declared explicitly and
/// carry a version</b> — renaming a class should never change a published contract. Evolve by
/// adding fields only; to change one, publish a <c>.v2</c> and dual-write for a while
/// (decision 16).
/// </summary>
[AttributeUsage(AttributeTargets.Class, Inherited = false)]
public sealed class EventNameAttribute(string name) : Attribute
{
    public string Name { get; } = name;
}
