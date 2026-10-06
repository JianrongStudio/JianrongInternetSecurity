using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace JianRongSecurity.Engine;

/// <summary>
/// 系统进程硬保护：任何"终止进程"动作必须先过这一关。
/// 双重防护：内置白名单 + 动态 IsProcessCritical（Win10+）。
/// 受保护进程一律拒绝终止，仅记录日志（防蓝屏）。
/// </summary>
public static class SystemGuard
{
    private static readonly HashSet<string> Protected = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "system idle process", "registry", "smss.exe", "csrss.exe",
        "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsm.exe",
        "svchost.exe", "dwm.exe", "fontdrvhost.exe", "runtimebroker.exe",
        "explorer.exe", "searchhost.exe", "searchapp.exe",
        "startmenuexperiencehost.exe", "textinputhost.exe", "shellexperiencehost.exe",
        "securityhealthservice.exe", "securityhealthsystray.exe",
        "winrshost.exe", "conhost.exe", "taskhostw.exe", "taskhostex.exe",
        "spoolsv.exe", "audiodg.exe", "sihost.exe", "ctfmon.exe",
        "jianrongsecurity.exe"
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(IntPtr h, uint flags,
        [MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder name, ref uint size);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetModuleHandleW([MarshalAs(UnmanagedType.LPWStr)] string name);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetProcAddress(IntPtr h, [MarshalAs(UnmanagedType.LPStr)] string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr h, uint code);

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint PROCESS_TERMINATE = 0x0001;

    private static string? ProcessName(uint pid)
    {
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new System.Text.StringBuilder(1024);
            uint sz = 1024;
            if (QueryFullProcessImageNameW(h, 0, sb, ref sz))
            {
                var full = sb.ToString();
                var i = full.LastIndexOf('\\');
                return i >= 0 ? full.Substring(i + 1) : full;
            }
            return null;
        }
        finally { CloseHandle(h); }
    }

    private static bool IsCriticalDynamic(IntPtr h)
    {
        var k = GetModuleHandleW("kernel32.dll");
        if (k == IntPtr.Zero) return false;
        var addr = GetProcAddress(k, "IsProcessCritical");
        if (addr == IntPtr.Zero) return false;
        var fn = Marshal.GetDelegateForFunctionPointer<IsCriticalFn>(addr);
        int crit = 0;
        return fn(h, ref crit) != 0 && crit != 0;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate int IsCriticalFn(IntPtr h, ref int critical);

    public static bool IsSystemProcess(uint pid, out string reason)
    {
        reason = "";
        var name = ProcessName(pid);
        if (name != null && Protected.Contains(name))
        {
            reason = $"系统关键进程白名单: {name}";
            return true;
        }
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h != IntPtr.Zero)
        {
            try
            {
                if (IsCriticalDynamic(h))
                {
                    reason = $"IsProcessCritical 标记为系统关键进程: {name ?? "(unknown)"}";
                    return true;
                }
            }
            finally { CloseHandle(h); }
        }
        return false;
    }

    public static bool CanTerminate(uint pid, out string reason) => !IsSystemProcess(pid, out reason);

    public static string[] ProtectedNames() => Protected.ToArray();

    public static bool TerminateProcessSafely(uint pid, out string reason)
    {
        if (IsSystemProcess(pid, out reason))
        {
            Debug.WriteLine($"[SystemGuard] 拒绝终止受保护进程 pid={pid} {reason}");
            return false;
        }
        var h = OpenProcess(PROCESS_TERMINATE, false, pid);
        if (h == IntPtr.Zero)
        {
            reason = $"无法打开进程 pid={pid}";
            return false;
        }
        try
        {
            if (!TerminateProcess(h, 1))
            {
                reason = $"TerminateProcess 失败 pid={pid} err={Marshal.GetLastWin32Error()}";
                return false;
            }
            reason = $"已终止 pid={pid}";
            return true;
        }
        finally { CloseHandle(h); }
    }
}
