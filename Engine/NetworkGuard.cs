using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace JianRongSecurity.Engine;

/// <summary>
/// 网络防护引擎：监控活动 TCP 连接，检测可疑外联。
/// 可疑特征：连接高危端口、已知恶意 IP、非浏览器进程的 80/443 外联。
/// </summary>
public class NetworkGuard
{
    public record NetConnection(int Pid, string ProcessName, string LocalAddress, int LocalPort,
                                string RemoteAddress, int RemotePort, string State, bool Suspicious, string Reason);

    private static readonly int[] HighRiskPorts = { 4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 4899, 5900, 3389, 135, 139, 445 };
    private static readonly string[] BadIpPrefixes = { "185.220.", "192.42.", "104.244.", "45.155." };
    private static readonly string[] BrowserProcs = { "chrome", "msedge", "firefox", "360se", "360chrome", "iexplore", "opera", "brave", "vivaldi", "sogouexplorer" };

    public static List<NetConnection> GetConnections()
    {
        var result = new List<NetConnection>();
        try
        {
            var props = IPGlobalProperties.GetIPGlobalProperties();
            var conns = props.GetActiveTcpConnections();

            foreach (var c in conns)
            {
                if (c.RemoteEndPoint.Address.Equals(IPAddress.Any) || c.RemoteEndPoint.Address.Equals(IPAddress.IPv6Any))
                    continue;

                string pname = "未知";
                int pid = 0;
                try { pid = FindPidForEndpoint(c.LocalEndPoint); pname = pid > 0 ? Process.GetProcessById(pid).ProcessName : "未知"; }
                catch { }

                bool suspicious = false;
                var reasons = new List<string>();

                if (HighRiskPorts.Contains(c.RemoteEndPoint.Port))
                {
                    suspicious = true;
                    reasons.Add($"连接高危端口 {c.RemoteEndPoint.Port}");
                }

                var ip = c.RemoteEndPoint.Address.ToString();
                if (BadIpPrefixes.Any(p => ip.StartsWith(p)))
                {
                    suspicious = true;
                    reasons.Add($"连接可疑 IP 段 {ip}");
                }

                if ((c.RemoteEndPoint.Port == 80 || c.RemoteEndPoint.Port == 443) &&
                    !BrowserProcs.Any(b => pname.Contains(b, StringComparison.OrdinalIgnoreCase)))
                {
                    if (!new[] { "svchost", "system", "lsass", "csrss", "wininit" }.Contains(pname.ToLower()))
                    {
                        suspicious = true;
                        reasons.Add($"非浏览器进程 {pname} 发起 HTTP/HTTPS 外联");
                    }
                }

                result.Add(new NetConnection(
                    pid, pname,
                    c.LocalEndPoint.Address.ToString(), c.LocalEndPoint.Port,
                    ip, c.RemoteEndPoint.Port,
                    c.State.ToString(), suspicious, string.Join("；", reasons)));
            }
        }
        catch { }
        return result.OrderByDescending(x => x.Suspicious).ToList();
    }

    public static bool KillProcess(int pid)
    {
        try { Process.GetProcessById(pid).Kill(); return true; }
        catch { return false; }
    }

    private static int FindPidForEndpoint(IPEndPoint local)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netstat.exe",
                Arguments = "-ano -p tcp",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            var output = p!.StandardOutput.ReadToEnd();
            p.WaitForExit();
            var target = $"{local.Address}:{local.Port}";
            foreach (var line in output.Split('\n'))
            {
                if (line.Contains(target) && line.Contains("LISTENING"))
                {
                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 5 && int.TryParse(parts[^1], out int pid))
                        return pid;
                }
            }
        }
        catch { }
        return 0;
    }
}
