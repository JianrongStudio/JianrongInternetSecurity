using Microsoft.Win32;
using System;

namespace JianRongSecurity.Engine;

/// <summary>
/// 文件资源管理器右键菜单：程序运行时注册（菜单显示），退出时注销（菜单隐藏）。
/// 注册在当前用户 HKCU（无需管理员），影响文件与文件夹的右键菜单。
/// </summary>
public static class ShellContextMenu
{
    private const string KeyFiles = @"Software\Classes\*\shell\JianRongSecurityScan";
    private const string KeyDirs = @"Software\Classes\Directory\shell\JianRongSecurityScan";

    private static string ExePath
    {
        get
        {
            var p = Environment.ProcessPath;
            if (!string.IsNullOrEmpty(p)) return p;
            // 回退：AppContext.BaseDirectory + 程序集名
            var fallback = System.IO.Path.Combine(AppContext.BaseDirectory, "JianRongSecurity.exe");
            return System.IO.File.Exists(fallback) ? fallback : "";
        }
    }

    /// <summary>注册右键菜单（启动时调用 → 资源管理器右键显示）。</summary>
    public static void Register()
    {
        if (string.IsNullOrEmpty(ExePath)) return; // 路径不可用时不注册，避免写入损坏命令
        try { RegisterFor(KeyFiles, "使用金荣安全中心扫描"); } catch { }
        try { RegisterFor(KeyDirs, "使用金荣安全中心扫描"); } catch { }
    }

    private static void RegisterFor(string keyPath, string menuText)
    {
        using var key = Registry.CurrentUser.CreateSubKey(keyPath);
        if (key == null) return;
        key.SetValue(null, menuText);
        key.SetValue("Icon", $"\"{ExePath}\"");
        using var cmd = key.CreateSubKey("command");
        cmd?.SetValue(null, $"\"{ExePath}\" --scan-file \"%1\"");
    }

    /// <summary>注销右键菜单（退出时调用 → 资源管理器右键隐藏）。</summary>
    public static void Unregister()
    {
        try { Registry.CurrentUser.DeleteSubKeyTree(KeyFiles, false); } catch { }
        try { Registry.CurrentUser.DeleteSubKeyTree(KeyDirs, false); } catch { }
    }
}
