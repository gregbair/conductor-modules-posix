namespace FulcrumLabs.Conductor.Modules.Posix.Firewalld;

internal class FirewallArgs
{
    public string? Port { get; set; }
    public string? Service { get; set; }
    public string? RichRule { get; set; }
    public bool? Permanent { get; set; }
    public FirewallState State { get; set; }
    public bool? Immediate { get; set; }
    public string? Zone { get; set; }
}