using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace JianRongSecurity.Engine;

/// <summary>
/// 金荣自研静态分析引擎 v1：
/// 不依赖第三方引擎，直接提取文件中的可读字符串，与内置 JSON 危险模式库对比。
/// 命中高危 API / 危险 URL / 持久化路径时给出高分。
/// </summary>
public static class JinRongStaticEngine
{
    private static readonly List<(string Pattern, string Threat, int Score)> Rules = new()
    {
        ("DeleteFileA", "文件删除API", 70),
        ("DeleteFileW", "文件删除API", 70),
        ("RemoveDirectory", "目录删除API", 65),
        ("SHFileOperation", "Shell文件操作(批量删除)", 60),
        ("FormatDrive", "格式化磁盘", 95),
        ("CreateRemoteThread", "远程线程注入", 80),
        ("WriteProcessMemory", "进程内存写入", 75),
        ("VirtualAllocEx", "远程内存分配", 65),
        ("SetWindowsHookEx", "全局钩子注入", 60),
        ("URLDownloadToFile", "自动下载文件", 75),
        ("InternetOpenUrl", "自动联网下载", 60),
        ("WinHttpOpen", "WinHTTP联网", 50),
        ("WSAStartup", "Socket联网", 45),
        ("CurrentVersion\\Run", "注册表自启动", 65),
        ("CurrentVersion\\RunOnce", "RunOnce自启动", 60),
        ("Startup", "启动文件夹", 45),
        ("schtasks", "计划任务持久化", 65),
        ("bcdedit", "启动项修改", 60),
        ("xmrig", "门罗币挖矿", 90),
        ("cpuminer", "挖矿程序", 85),
        ("minerd", "门罗币挖矿", 85),
    };

    /// <summary>扫描文件，返回威胁名和分数（0-100），null 表示无威胁。</summary>
    public static (string? ThreatName, int Score, string Detail)? Analyze(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            var fi = new FileInfo(path);
            if (fi.Length > 64 * 1024 * 1024) return null;

            using var fs = File.OpenRead(path);
            int len = (int)Math.Min(fs.Length, 4 * 1024 * 1024);
            byte[] buf = new byte[len];
            int read = fs.Read(buf, 0, len);
            if (read <= 0) return null;

            var strings = ExtractAsciiStrings(buf, read);
            strings.UnionWith(ExtractUnicodeStrings(buf, read));

            int totalScore = 0;
            var hits = new List<string>();
            string bestThreat = "";
            int bestScore = 0;

            foreach (var rule in Rules)
            {
                bool hit = false;
                foreach (var s in strings)
                {
                    if (s.IndexOf(rule.Pattern, StringComparison.OrdinalIgnoreCase) >= 0)
                    { hit = true; break; }
                }
                if (hit)
                {
                    totalScore += rule.Score;
                    hits.Add(rule.Threat);
                    if (rule.Score > bestScore) { bestScore = rule.Score; bestThreat = rule.Threat; }
                }
            }

            foreach (var s in strings)
            {
                if (s.Length > 8 && s.Length < 256 &&
                    (s.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                     s.StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
                {
                    string lower = s.ToLowerInvariant();
                    if (!lower.Contains("microsoft.com") && !lower.Contains("windows.com") &&
                        !lower.Contains("apple.com") && !lower.Contains("google.com") &&
                        !lower.Contains("github.com") && !lower.Contains("baidu.com"))
                    {
                        totalScore += 25;
                        hits.Add("可疑联网URL: " + s.Substring(0, Math.Min(80, s.Length)));
                        if (25 > bestScore) { bestScore = 25; bestThreat = "可疑后台连接"; }
                        break;
                    }
                }
            }

            if (totalScore >= 60)
            {
                string detail = string.Join("; ", hits.Take(5));
                string name = "金荣自研引擎: " + bestThreat;
                int score = Math.Min(100, totalScore);
                return (name, score, detail);
            }
            return null;
        }
        catch { return null; }
    }

    private static HashSet<string> ExtractAsciiStrings(byte[] data, int length)
    {
        var result = new HashSet<string>();
        var sb = new StringBuilder();
        for (int i = 0; i < length; i++)
        {
            byte b = data[i];
            if (b >= 32 && b < 127) { sb.Append((char)b); }
            else
            {
                if (sb.Length >= 5) result.Add(sb.ToString());
                sb.Clear();
            }
        }
        if (sb.Length >= 5) result.Add(sb.ToString());
        return result;
    }

    private static HashSet<string> ExtractUnicodeStrings(byte[] data, int length)
    {
        var result = new HashSet<string>();
        var sb = new StringBuilder();
        for (int i = 0; i < length - 1; i += 2)
        {
            char c = (char)(data[i] | (data[i + 1] << 8));
            if (c >= 32 && c < 127) { sb.Append(c); }
            else
            {
                if (sb.Length >= 5) result.Add(sb.ToString());
                sb.Clear();
            }
        }
        if (sb.Length >= 5) result.Add(sb.ToString());
        return result;
    }
}
