using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using FulcrumLabs.Conductor.Core.Modules;
using FulcrumLabs.Conductor.Modules.Common;

namespace FulcrumLabs.Conductor.Modules.Posix.Firewalld;

/// <summary>
///     Module that manages firewalld rules
/// </summary>
public class FirewalldModule : ModuleBase
{
    /// <inheritdoc/>
    protected override async Task<ModuleResult> ExecuteAsync(Dictionary<string, object?> vars)
    {
        FirewallArgs args = new();

        if (TryGetRequiredParameter(vars, "state", out var state))
        {
            args.State = StringToFirewallState(state);
        }

        args.Port = GetOptionalParameter(vars, "port");
        args.Service = GetOptionalParameter(vars, "service");
        args.RichRule = GetOptionalParameter(vars, "rich_rule");

        int nonNullCount = new[] { args.Port, args.Service, args.RichRule }.Count(s => s is not null);
        if (nonNullCount > 1)
        {
            return Failure("Only one of `port`, `service`, or `rich_rule` may be provided.");
        }

        args.Zone = GetOptionalParameter(vars, "zone");

        if (args.Port is null && args.Service is null && args.RichRule is null)
        {
            return Failure("One of 'port', 'service', or 'richrule' is required");
        }

        if (bool.TryParse(GetOptionalParameter(vars, "permanent", "false"), out bool permanent))
        {
            args.Permanent = permanent;
        }

        if (bool.TryParse(GetOptionalParameter(vars, "immediate", "false"), out bool immediate))
        {
            args.Immediate = immediate;
        }

        CancellationToken
            cancellationToken = CancellationToken.None; // TODO: Replace with real one once module lib updated

        return args.State switch
        {
            FirewallState.Disabled or FirewallState.Absent => await Disable(args, cancellationToken),
            FirewallState.Enabled or FirewallState.Present => await Enable(args, cancellationToken),
            _ => throw new InvalidOperationException($"Unknown state {args.State}")
        };
    }

    private static async Task<ModuleResult> Enable(FirewallArgs args, CancellationToken token)
    {
        if (args.Port is not null)
        {
            return await EnablePort(args, token);
        }

        if (args.Service is not null)
        {
            return await EnableService(args, token);
        }

        if (args.RichRule is not null)
        {
            return await EnableRichRule(args, token);
        }

        throw new InvalidOperationException("One of 'port', 'service', or 'rich_rule' is required.");
    }

    private static async Task<ModuleResult> EnablePort(FirewallArgs args, CancellationToken token)
    {
        if (args.Port is null)
        {
            throw new InvalidOperationException("Port is required");
        }

        if (await PortExists(args.Port, args.Zone, token))
        {
            return Success("Port Exists", false, new Dictionary<string, object?> { ["port"] = args.Port });
        }

        ProcessResult pResult = await RunFirewallCommand($"--add-port={args.Port}", token);

        Dictionary<string, object?> facts = new()
        {
            ["port"] = args.Port,
            ["stderr"] = pResult.StdErr,
            ["stdout"] = pResult.StdOut,
            ["exit_code"] = pResult.ExitCode
        };

        return pResult.ExitCode != 0
            ? Failure($"Could not add port: {args.Port}, error: {pResult.StdErr}", facts)
            : Success("Port added", true, facts);
    }

    private static async Task<ModuleResult> EnableRichRule(FirewallArgs args, CancellationToken token)
    {
        if (args.RichRule is null)
        {
            throw new InvalidOperationException("RichRule is required");
        }

        if (await RichRuleExists(args.RichRule, args.Zone, token))
        {
            return Success("Rule exists", false, new Dictionary<string, object?> { ["rich_rule"] = args.RichRule });
        }

        ProcessResult pResult = await RunFirewallCommand($"--add-rich-rule='{args.RichRule}'", token);

        Dictionary<string, object?> facts = new()
        {
            ["rich_rule"] = args.RichRule,
            ["stderr"] = pResult.StdErr,
            ["stdout"] = pResult.StdOut,
            ["exit_code"] = pResult.ExitCode
        };

        return pResult.ExitCode != 0
            ? Failure($"Could not add rich rule: {args.RichRule}, error: {pResult.StdErr}", facts)
            : Success("Rich Rule added", true, facts);
    }

    private static async Task<ModuleResult> EnableService(FirewallArgs args, CancellationToken token)
    {
        if (args.Service is null)
        {
            throw new InvalidOperationException("Service is required");
        }

        if (await ServiceExists(args.Service, args.Zone, token))
        {
            return Success("Service exists", false, new Dictionary<string, object?> { ["service"] = args.Service });
        }

        ProcessResult pResult = await RunFirewallCommand($"--add-service={args.Service}", args, token);

        Dictionary<string, object?> facts = new()
        {
            ["service"] = args.Service,
            ["stderr"] = pResult.StdErr,
            ["stdout"] = pResult.StdOut,
            ["exit_code"] = pResult.ExitCode
        };

        return pResult.ExitCode != 0
            ? Failure($"Could not add service: {args.Service}, error: {pResult.StdErr}", facts)
            : Success("Service added", true, facts);
    }

    private static async Task<ModuleResult> Disable(FirewallArgs args, CancellationToken token)
    {
        if (args.Port is not null)
        {
            return await DisablePort(args, token);
        }

        if (args.Service is not null)
        {
            return await DisableService(args, token);
        }

        if (args.RichRule is not null)
        {
            return await DisableRichRule(args, token);
        }

        throw new InvalidOperationException("One of 'port', 'service', or 'rich_rule' is required.");
    }

    private static async Task<ModuleResult> DisablePort(FirewallArgs args, CancellationToken token)
    {
        if (args.Port is null)
        {
            throw new InvalidOperationException("Port is required");
        }

        if (!await PortExists(args.Port, args.Zone, token))
        {
            return Success("Port not enabled", false, new Dictionary<string, object?> { ["port"] = args.Port });
        }

        ProcessResult pResult = await RunFirewallCommand($"--remove-port={args.Port}", args, token);

        Dictionary<string, object?> facts = new()
        {
            ["port"] = args.Port,
            ["stderr"] = pResult.StdErr,
            ["stdout"] = pResult.StdOut,
            ["exit_code"] = pResult.ExitCode
        };

        return pResult.ExitCode != 0
            ? Failure($"Could not remove port: {args.Port}", facts)
            : Success("Port removed", true, facts);
    }

    private static async Task<ModuleResult> DisableService(FirewallArgs args, CancellationToken token)
    {
        if (args.Service is null)
        {
            throw new InvalidOperationException("Service is required");
        }

        if (!await ServiceExists(args.Service, args.Zone, token))
        {
            return Success("Service not found", false, new Dictionary<string, object?> { ["service"] = args.Service });
        }

        ProcessResult pResult = await RunFirewallCommand($"--remove-service={args.Service}", args, token);

        Dictionary<string, object?> facts = new()
        {
            ["service"] = args.Service,
            ["stderr"] = pResult.StdErr,
            ["stdout"] = pResult.StdOut,
            ["exit_code"] = pResult.ExitCode
        };

        return pResult.ExitCode != 0
            ? Failure($"Could not remove service: {args.Service}, error: {pResult.StdErr}", facts)
            : Success("Service removed", true, facts);
    }

    private static async Task<ModuleResult> DisableRichRule(FirewallArgs args, CancellationToken token)
    {
        if (args.RichRule is null)
        {
            throw new InvalidOperationException("Rich Rule is required");
        }

        if (!await RichRuleExists(args.RichRule, args.Zone, token))
        {
            return Success("Rich rule not found", false,
                new Dictionary<string, object?> { ["rich_rule"] = args.RichRule });
        }

        ProcessResult pResult = await RunFirewallCommand($"--remove-rich-rule='{args.RichRule}'", args, token);

        Dictionary<string, object?> facts = new()
        {
            ["rich_rule"] = args.RichRule,
            ["stderr"] = pResult.StdErr,
            ["stdout"] = pResult.StdOut,
            ["exit_code"] = pResult.ExitCode
        };

        if (pResult.ExitCode != 0)
        {
            return Failure($"Could not disable service: {args.Service}",
                facts);
        }

        return Success("Rich Rule removed", true, facts);
    }

    private static async Task<bool> ServiceExists(string service, string? zone, CancellationToken token)
    {
        StringBuilder cmdArgs = new("--list-services");
        if (zone is not null)
        {
            cmdArgs.Append($" --zone={zone}");
        }

        ProcessResult pResult = await RunFirewallCommand(cmdArgs.ToString(), token);

        bool serviceExists = pResult.StdOut.Split(" ").Any(x => x == service);

        return pResult.ExitCode == 0 && string.IsNullOrWhiteSpace(pResult.StdErr) && serviceExists;
    }

    private static async Task<bool> PortExists(string port, string? zone, CancellationToken token)
    {
        StringBuilder cmdArgs = new("--list-ports");
        if (zone is not null)
        {
            cmdArgs.Append($" --zone={zone}");
        }

        ProcessResult pResult = await RunFirewallCommand(cmdArgs.ToString(), token);

        bool portExists = pResult.StdOut.Split(" ").Any(x => x == port);

        return pResult.ExitCode == 0 && string.IsNullOrWhiteSpace(pResult.StdErr) && portExists;
    }

    private static async Task<bool> RichRuleExists(string rule, string? zone, CancellationToken token)
    {
        StringBuilder cmdArgs = new("--list-rich-rules");
        if (zone is not null)
        {
            cmdArgs.Append($" --zone={zone}");
        }

        ProcessResult pResult = await RunFirewallCommand(cmdArgs.ToString(), token);

        bool ruleExists = pResult.StdOut.Split(Environment.NewLine).Any(x => x == rule);
        return pResult.ExitCode == 0 && string.IsNullOrWhiteSpace(pResult.StdErr) && ruleExists;
    }

    private static async Task<ProcessResult> RunFirewallCommand(string command, FirewallArgs args,
        CancellationToken token)
    {
        StringBuilder cmdArgs = new(command);

        if (args.Permanent.HasValue && args.Permanent.Value)
        {
            cmdArgs.Append(" --permanent");
        }

        if (args.Immediate.HasValue && args.Immediate.Value)
        {
            cmdArgs.Append(" --immediate");
        }

        if (args.Zone is not null)
        {
            cmdArgs.Append($" --zone={args.Zone}");
        }

        ProcessStartInfo start = new() { FileName = "firewall-cmd", Arguments = args.ToString() };

        using Process? process = Process.Start(start);
        if (process is null)
        {
            throw new InvalidOperationException("Could not run firewall-cmd");
        }

        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync(token);
        Task<string> stderrTask = process.StandardError.ReadToEndAsync(token);

        await process.WaitForExitAsync(token);

        string stdout = await stdoutTask;
        string stderr = await stderrTask;
        int exitCode = process.ExitCode;

        return new ProcessResult(exitCode, stdout, stderr);
    }

    private static async Task<ProcessResult> RunFirewallCommand(string args, CancellationToken token)
    {
        ProcessStartInfo start = new() { FileName = "firewall-cmd", Arguments = args };

        using Process? process = Process.Start(start);
        if (process is null)
        {
            throw new InvalidOperationException("Could not run firewall-cmd");
        }

        Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync(token);
        Task<string> stderrTask = process.StandardError.ReadToEndAsync(token);

        await process.WaitForExitAsync(token);

        string stdout = await stdoutTask;
        string stderr = await stderrTask;
        int exitCode = process.ExitCode;

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