using System.Diagnostics;
using System.Globalization;
using System.Text;
using FulcrumLabs.Conductor.Core.Modules;
using FulcrumLabs.Conductor.Modules.Common;

namespace FulcrumLabs.Conductor.Modules.Posix.Firewalld;

public class FirewalldModule : ModuleBase
{
    protected override async Task<ModuleResult> ExecuteAsync(Dictionary<string, object?> vars)
    {
        var args = new FirewallArgs();

        if (TryGetRequiredParameter(vars, "state", out var state)) args.State = StringToFirewallState(state);

        args.Port = GetOptionalParameter(vars, "port");
        args.Service = GetOptionalParameter(vars, "service");
        args.RichRule = GetOptionalParameter(vars, "rich_rule");

        var nonNullCount = new[] { args.Port, args.Service, args.RichRule }.Count(s => s is not null);
        if (nonNullCount > 1) return Failure("Only one of `port`, `service`, or `rich_rule` may be provided.");

        args.Zone = GetOptionalParameter(vars, "zone");

        if (args.Port is null && args.Service is null && args.RichRule is null)
            return Failure("One of 'port', 'service', or 'richrule' is required");

        if (bool.TryParse(GetOptionalParameter(vars, "permanent", "false"), out var permanent))
            args.Permanent = permanent;

        if (bool.TryParse(GetOptionalParameter(vars, "immediate", "false"), out var immediate))
            args.Immediate = immediate;

        var cancellationToken = CancellationToken.None; // TODO: Replace with real one once module lib updated

        switch (args.State)
        {
            case FirewallState.Disabled:
                return await Disable(args, cancellationToken);
        }

        throw new NotImplementedException();
    }

    private static async Task<ModuleResult> Disable(FirewallArgs args, CancellationToken token)
    {
        if (args.Port is not null) return await DisablePort(args, token);

        if (args.Service is not null) return await DisableService(args, token);

        if (args.RichRule is not null) return await DisableRichRule(args, token);

        throw new InvalidOperationException("One of 'port', 'service', or 'rich_rule' is required.");
    }

    private static async Task<ModuleResult> DisablePort(FirewallArgs args, CancellationToken token)
    {
        if (args.Port is null) return Failure("Port is required");

        if (!await PortExists(args.Port, args.Zone, token))
            return Success("Port not enabled", false, new Dictionary<string, object?> { ["port"] = args.Port });

        StringBuilder cmdArgs = new($"--remove-port={args.Port}");

        if (args.Permanent.HasValue && args.Permanent.Value) cmdArgs.Append(" --permanent");

        if (args.Immediate.HasValue && args.Immediate.Value) cmdArgs.Append(" --immediate");

        if (args.Zone is not null) cmdArgs.Append($" --zone={args.Zone}");

        var pResult = await RunFirewallCommand(cmdArgs.ToString(), token);

        Dictionary<string, object?> facts = new()
        {
            ["port"] = args.Port,
            ["stderr"] = pResult.StdErr,
            ["stdout"] = pResult.StdOut,
            ["exit_code"] = pResult.ExitCode
        };

        if (pResult.ExitCode != 0)
            return Failure($"Could not disable port: {args.Port}",
                facts);

        var changed = await PortExists(args.Port, args.Zone, token);
        return Success("Port changed", changed, facts);
    }

    private static async Task<ModuleResult> DisableService(FirewallArgs args, CancellationToken token)
    {
        if (args.Service is null) return Failure("Service is required");
        if (!await ServiceExists(args.Service, args.Zone, token))
            return Success("Service not found", false, new Dictionary<string, object?> { ["service"] = args.Service });

        StringBuilder cmdArgs = new($"--remove-service={args.Service}");

        if (args.Permanent.HasValue && args.Permanent.Value) cmdArgs.Append(" --permanent");

        if (args.Immediate.HasValue && args.Immediate.Value) cmdArgs.Append(" --immediate");

        if (args.Zone is not null) cmdArgs.Append($" --zone={args.Zone}");

        var pResult = await RunFirewallCommand(cmdArgs.ToString(), token);

        Dictionary<string, object?> facts = new()
        {
            ["service"] = args.Service,
            ["stderr"] = pResult.StdErr,
            ["stdout"] = pResult.StdOut,
            ["exit_code"] = pResult.ExitCode
        };

        if (pResult.ExitCode != 0)
            return Failure($"Could not disable service: {args.Service}",
                facts);

        var changed = await ServiceExists(args.Service, args.Zone, token);
        return Success("Port changed", changed, facts);
    }

    private static async Task<ModuleResult> DisableRichRule(FirewallArgs args, CancellationToken token)
    {
        if (args.RichRule is null) return Failure("Rich rule is required");
        if (!await RichRuleExists(args.RichRule, args.Zone, token))
            return Success("Rich rule not found", false,
                new Dictionary<string, object?> { ["rich_rule"] = args.RichRule });

        StringBuilder cmdArgs = new($"--remove-rich-rule='{args.RichRule}'");

        if (args.Permanent.HasValue && args.Permanent.Value) cmdArgs.Append(" --permanent");

        if (args.Immediate.HasValue && args.Immediate.Value) cmdArgs.Append(" --immediate");

        if (args.Zone is not null) cmdArgs.Append($" --zone={args.Zone}");

        var pResult = await RunFirewallCommand(cmdArgs.ToString(), token);

        Dictionary<string, object?> facts = new()
        {
            ["rich_rule"] = args.RichRule,
            ["stderr"] = pResult.StdErr,
            ["stdout"] = pResult.StdOut,
            ["exit_code"] = pResult.ExitCode
        };

        if (pResult.ExitCode != 0)
            return Failure($"Could not disable service: {args.Service}",
                facts);

        var changed = await RichRuleExists(args.RichRule, args.Zone, token);
        return Success("Port changed", changed, facts);
    }

    private static async Task<bool> ServiceExists(string service, string? zone, CancellationToken token)
    {
        StringBuilder cmdArgs = new("--list-services");
        if (zone is not null) cmdArgs.Append($" --zone={zone}");

        var pResult = await RunFirewallCommand(cmdArgs.ToString(), token);

        var serviceExists = pResult.StdOut.Split(" ").Any(x => x == service);

        return pResult.ExitCode == 0 && string.IsNullOrWhiteSpace(pResult.StdErr) && serviceExists;
    }

    private static async Task<bool> PortExists(string port, string? zone, CancellationToken token)
    {
        StringBuilder cmdArgs = new("--list-ports");
        if (zone is not null) cmdArgs.Append($" --zone={zone}");

        var pResult = await RunFirewallCommand(cmdArgs.ToString(), token);

        var portExists = pResult.StdOut.Split(" ").Any(x => x == port);

        return pResult.ExitCode == 0 && string.IsNullOrWhiteSpace(pResult.StdErr) && portExists;
    }

    private static async Task<bool> RichRuleExists(string rule, string? zone, CancellationToken token)
    {
        StringBuilder cmdArgs = new("--list-rich-rules");
        if (zone is not null) cmdArgs.Append($" --zone={zone}");

        var pResult = await RunFirewallCommand(cmdArgs.ToString(), token);

        var ruleExists = pResult.StdOut.Split(Environment.NewLine).Any(x => x == rule);
        return pResult.ExitCode == 0 && string.IsNullOrWhiteSpace(pResult.StdErr) && ruleExists;
    }

    private static async Task<ProcessResult> RunFirewallCommand(string args, CancellationToken token)
    {
        ProcessStartInfo start = new()
        {
            FileName = "firewall-cmd",
            Arguments = args
        };

        using var process = Process.Start(start);
        if (process is null)
            throw new InvalidOperationException("Could not run firewall-cmd");

        var stdoutTask = process.StandardOutput.ReadToEndAsync(token);
        var stderrTask = process.StandardError.ReadToEndAsync(token);

        await process.WaitForExitAsync(token);

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        var exitCode = process.ExitCode;

        return new ProcessResult(exitCode, stdout, stderr);
    }

    private static FirewallState StringToFirewallState(string state)
    {
        return state.ToLower(CultureInfo.InvariantCulture) switch
        {
            "enabled" => FirewallState.Enabled,
            "disabled" => FirewallState.Disabled,
            "present" => FirewallState.Present,
            _ => FirewallState.Absent
        };
    }

    private record ProcessResult(int ExitCode, string StdOut, string StdErr);
}