using FulcrumLabs.Conductor.Modules.Common;

namespace FulcrumLabs.Conductor.Modules.Posix.Firewalld;

/// <summary>
///     Attributes for this module
/// </summary>
public class FirewalldModuleAttributes : IModuleAttributes
{
    /// <inheritdoc />
    public string[] RespondsTo { get; } =
    [
        "ansible.posix.firewalld",
        "conductor.posix.firewalld",
        "firewalld"
    ];

    /// <inheritdoc />
    public string Author => "Greg Bair";

    /// <inheritdoc />
    public Uri Url { get; } = new("https://github.com/gregbair/conductor-modules-posix/");

    /// <inheritdoc />
    public string Description => "A module that allows management of firewalld rules";
}