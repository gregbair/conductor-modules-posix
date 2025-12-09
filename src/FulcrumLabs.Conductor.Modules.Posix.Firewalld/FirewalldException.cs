namespace FulcrumLabs.Conductor.Modules.Posix.Firewalld;

public class FirewalldException(string? message = null, Exception? innerException = null)
    : Exception(message, innerException);