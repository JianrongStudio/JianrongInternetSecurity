using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace JianRongSecurity.Engine;

/// <summary>
/// 防火墙引擎：基于 Windows 高级防火墙（netsh advfirewall / PowerShell）。
/// 支持查看状态、启用/禁用、阻止程序联网、列出规则。
/// </summary>
public class FirewallEngine
{
    public record FirewallStatus(bool Enabled, string Profile, string? Error);
    public record FirewallRule(string Name, string Action, string Direction, string Program, string LocalPort, string RemotePort);

    public static FirewallStatus GetStatus()
    {
        try
        {
            var output = RunNetsh("advfirewall show allprofiles state");
            bool enabled = output.Contains("ON") || output.Contains("启用");
            return new FirewallStatus(enabled, "域/专用/公用", null);
        }
        catch (Exception ex)
        {
            return new FirewallStatus(false, "未知", ex.Message);
        }
    }

    public static bool Enable()
    {
        try { RunNetsh("advfirewall set allprofiles state on"); return true; }
        catch { return false; }
    }

    public static bool Disable()
    {
        try { RunNetsh("advfirewall set allprofiles state off"); return true; }
        catch { return false; }
    }

    public static bool BlockProgram(string programPath, string ruleName)
    {
        try
        {
            try { RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}\""); } catch { }
            RunNetsh($"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=block program=\"{programPath}\" enable=yes");
            return true;
        }
        catch { return false; }
    }

    public static bool AllowProgram(string programPath, string ruleName)
    {
        try
        {
            try { RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}\""); } catch { }
            RunNetsh($"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=allow program=\"{programPath}\" enable=yes");
            return true;
        }
        catch { return false; }
    }

    public static bool RemoveRule(string ruleName)
    {
        try { RunNetsh($"advfirewall firewall delete rule name=\"{ruleName}\""); return true; }
        catch { return false; }
    }

    public static List<FirewallRule> ListRules(int max = 50)
    {
        var rules = new List<FirewallRule>();
        try
        {
            var output = RunNetsh("advfirewall firewall show rule name=all");
            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            string? name = null, action = null, direction = null, program = null, localPort = null, remotePort = null;
            foreach (var line in lines)
            {
                var t = line.Trim();
                if (t.StartsWith("规则名称:") || t.StartsWith("Rule Name:")) { name = t.Split(':')[1].Trim(); }
                else if (t.StartsWith("操作:") || t.StartsWith("Action:")) { action = t.Split(':')[1].Trim(); }
                else if (t.StartsWith("方向:") || t.StartsWith("Direction:")) { direction = t.Split(':')[1].Trim(); }
                else if (t.StartsWith("程序:") || t.StartsWith("Program:")) { program = t.Split(':')[1].Trim(); }
                else if (t.StartsWith("本地端口:") || t.StartsWith("LocalPort:")) { localPort = t.Split(':')[1].Trim(); }
                else if (t.StartsWith("远程端口:") || t.StartsWith("RemotePort:")) { remotePort = t.Split(':')[1].Trim(); }
                else if (string.IsNullOrWhiteSpace(t) && name != null)
                {
                    rules.Add(new FirewallRule(name, action ?? "-", direction ?? "-", program ?? "-", localPort ?? "-", remotePort ?? "-"));
                    name = action = direction = program = localPort = remotePort = null;
                    if (rules.Count >= max) break;
                }
            }
        }
        catch { }
        return rules;
    }

    private static string RunNetsh(string args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "netsh.exe",
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.GetEncoding(936)
        };
        using var p = Process.Start(psi);
        var output = p!.StandardOutput.ReadToEnd();
        p.WaitForExit();
        return output;
    }
}
