using System.Threading;

using FulcrumLabs.Conductor.Core.Util;
using FulcrumLabs.Conductor.Modules.Posix.Firewalld;

CancellationTokenSource cts = CancellationTokenSourceUtils.CreateProcessShutdownTokenSource();

return await new FirewalldModule().RunAsync(cts.Token);