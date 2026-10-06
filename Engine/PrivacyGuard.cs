using Microsoft.Win32;
using System;

namespace JianRongSecurity.Engine;

/// <summary>
/// 隐私防护引擎：控制摄像头、麦克风、指纹（Windows Hello）的访问权限。
/// 通过 Windows 10/11 的 CapabilityAccessManager 注册表实现。
/// </summary>
public class PrivacyGuard
{
    public enum PrivacyDevice { Webcam, Microphone, Fingerprint, Location, Notifications }

    public record PrivacyStatus(PrivacyDevice Device, string Name, bool Enabled, string? CurrentApp, string? Error);

    private const string ConsentStoreRoot = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    public static PrivacyStatus[] GetAllStatus()
    {
        return new[]
        {
            GetStatus(PrivacyDevice.Webcam),
            GetStatus(PrivacyDevice.Microphone),
            GetStatus(PrivacyDevice.Fingerprint),
            GetStatus(PrivacyDevice.Location),
        };
    }

    public static PrivacyStatus GetStatus(PrivacyDevice device)
    {
        string subKey = device switch
        {
            PrivacyDevice.Webcam => "webcam",
            PrivacyDevice.Microphone => "microphone",
            PrivacyDevice.Fingerprint => "biometric",
            PrivacyDevice.Location => "location",
            _ => "webcam"
        };
        string name = device switch
        {
            PrivacyDevice.Webcam => "摄像头",
            PrivacyDevice.Microphone => "麦克风",
            PrivacyDevice.Fingerprint => "指纹/生物识别",
            PrivacyDevice.Location => "位置",
            _ => "未知"
        };

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey($@"{ConsentStoreRoot}\{subKey}", writable: false);
            var value = key?.GetValue("Value") as string;
            bool enabled = value != "Deny";

            string? lastApp = null;
            using var appKey = Registry.CurrentUser.OpenSubKey($@"{ConsentStoreRoot}\{subKey}\NonPackaged");
            if (appKey != null)
            {
                foreach (var app in appKey.GetSubKeyNames())
                {
                    lastApp = app;
                    break;
                }
            }

            return new PrivacyStatus(device, name, enabled, lastApp, null);
        }
        catch (Exception ex)
        {
            return new PrivacyStatus(device, name, false, null, ex.Message);
        }
    }

    public static bool SetEnabled(PrivacyDevice device, bool enabled)
    {
        string subKey = device switch
        {
            PrivacyDevice.Webcam => "webcam",
            PrivacyDevice.Microphone => "microphone",
            PrivacyDevice.Fingerprint => "biometric",
            PrivacyDevice.Location => "location",
            _ => "webcam"
        };

        try
        {
            using var key = Registry.CurrentUser.CreateSubKey($@"{ConsentStoreRoot}\{subKey}", writable: true);
            key.SetValue("Value", enabled ? "Allow" : "Deny", RegistryValueKind.String);
            return true;
        }
        catch
        {
            try
            {
                using var key = Registry.LocalMachine.CreateSubKey($@"{ConsentStoreRoot}\{subKey}", writable: true);
                key.SetValue("Value", enabled ? "Allow" : "Deny", RegistryValueKind.String);
                return true;
            }
            catch { return false; }
        }
    }

    public static bool IsWebcamInUse()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey($@"{ConsentStoreRoot}\webcam\NonPackaged");
            if (key == null) return false;
            foreach (var app in key.GetSubKeyNames())
            {
                using var appKey = key.OpenSubKey(app);
                var lastUsed = appKey?.GetValue("LastUsedTimeStop") as long?;
                if (lastUsed.HasValue && lastUsed.Value == 0)
                    return true;
            }
        }
        catch { }
        return false;
    }

    public static bool IsMicrophoneInUse()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey($@"{ConsentStoreRoot}\microphone\NonPackaged");
            if (key == null) return false;
            foreach (var app in key.GetSubKeyNames())
            {
                using var appKey = key.OpenSubKey(app);
                var lastUsed = appKey?.GetValue("LastUsedTimeStop") as long?;
                if (lastUsed.HasValue && lastUsed.Value == 0)
                    return true;
            }
        }
        catch { }
        return false;
    }
}
