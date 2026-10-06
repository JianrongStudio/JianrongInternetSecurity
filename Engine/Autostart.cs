using Microsoft.Win32;
using System;
using System.IO;

namespace JianRongSecurity.Engine;

/// <summary>开机自启管理：写 HKCU\Software\Microsoft\Windows\CurrentVersion\Run。</summary>
public static class Autostart
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string AppName = "JianRongSecurity";

    public static bool IsEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey);
            return key?.GetValue(AppName) != null;
        }
        catch { return false; }
    }

    public static void Enable()
    {
        try
        {
            var exePath = Environment.ProcessPath ?? System.Reflection.Assembly.GetExecutingAssembly().Location;
            using var key = Registry.CurrentUser.CreateSubKey(RunKey);
            key.SetValue(AppName, $"\"{exePath}\" --minimized");
        }
        catch { }
    }

    public static void Disable()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKey, writable: true);
            key?.DeleteValue(AppName, throwOnMissingValue: false);
        }
        catch { }
    }
}
