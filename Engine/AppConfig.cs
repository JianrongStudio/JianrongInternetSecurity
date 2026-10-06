using System;
using System.IO;
using System.Text.Json;

namespace JianRongSecurity.Engine;

/// <summary>
/// 便携式 JSON 配置持久化：配置文件位于 exe 同目录 config.json，
/// 不依赖注册表，随程序目录拷贝即可携带全部设置。
/// </summary>
public sealed class AppConfig
{
    public static AppConfig Instance { get; } = new AppConfig();

    private static readonly string ConfigPath = Path.Combine(AppContext.BaseDirectory, "config.json");
    private static readonly object SaveLock = new();

    static AppConfig() { Instance.Load(); }

    private AppConfig() { }

    public bool CloudScanEnabled { get; set; } = false;
    public bool RealtimeProtectionEnabled { get; set; } = true;
    public bool GuideDone { get; set; } = false;
    public List<string> Whitepaths { get; set; } = new();
    public bool CloudApiEnabled { get; set; } = false;
    public string CloudApiUrl { get; set; } = "";
    public string CloudApiKey { get; set; } = "";
    public string CloudApiSecret { get; set; } = "";
    public string JinRongApiKey { get; set; } = "";
    public bool SystemIntegrityEnabled { get; set; } = true;
    public bool RegistryGuardEnabled { get; set; } = true;
    public bool ExplorerGuardEnabled { get; set; } = true;
    public bool WindowsFileGuardEnabled { get; set; } = true;
    public bool SignatureGuardEnabled { get; set; } = true;
    public bool BootGuardEnabled { get; set; } = true;

    public void Load()
    {
        try
        {
            if (!File.Exists(ConfigPath)) return;
            string json = File.ReadAllText(ConfigPath);
            var data = JsonSerializer.Deserialize<AppConfigData>(json);
            if (data == null) return;
            CloudScanEnabled = data.CloudScanEnabled;
            RealtimeProtectionEnabled = data.RealtimeProtectionEnabled;
            GuideDone = data.GuideDone;
            Whitepaths = data.Whitepaths ?? new List<string>();
            CloudApiEnabled = data.CloudApiEnabled;
            CloudApiUrl = data.CloudApiUrl ?? "";
            CloudApiKey = data.CloudApiKey ?? "";
            CloudApiSecret = data.CloudApiSecret ?? "";
            JinRongApiKey = data.JinRongApiKey ?? "";
            SystemIntegrityEnabled = data.SystemIntegrityEnabled;
            RegistryGuardEnabled = data.RegistryGuardEnabled;
            ExplorerGuardEnabled = data.ExplorerGuardEnabled;
            WindowsFileGuardEnabled = data.WindowsFileGuardEnabled;
            SignatureGuardEnabled = data.SignatureGuardEnabled;
            BootGuardEnabled = data.BootGuardEnabled;
        }
        catch { }
    }

    public void Save()
    {
        lock (SaveLock)
        {
            try
            {
                var data = new AppConfigData
                {
                    CloudScanEnabled = CloudScanEnabled,
                    RealtimeProtectionEnabled = RealtimeProtectionEnabled,
                    GuideDone = GuideDone,
                    Whitepaths = Whitepaths,
                    CloudApiEnabled = CloudApiEnabled,
                    CloudApiUrl = CloudApiUrl,
                    CloudApiKey = CloudApiKey,
                    CloudApiSecret = CloudApiSecret,
                    JinRongApiKey = JinRongApiKey,
                    SystemIntegrityEnabled = SystemIntegrityEnabled,
                    RegistryGuardEnabled = RegistryGuardEnabled,
                    ExplorerGuardEnabled = ExplorerGuardEnabled,
                    WindowsFileGuardEnabled = WindowsFileGuardEnabled,
                    SignatureGuardEnabled = SignatureGuardEnabled,
                    BootGuardEnabled = BootGuardEnabled,
                };
                string json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(ConfigPath, json);
            }
            catch { }
        }
    }

    private sealed class AppConfigData
    {
        public bool CloudScanEnabled { get; set; } = false;
        public bool RealtimeProtectionEnabled { get; set; } = true;
        public bool GuideDone { get; set; } = false;
        public List<string> Whitepaths { get; set; } = new();
        public bool CloudApiEnabled { get; set; } = false;
        public string CloudApiUrl { get; set; } = "";
        public string CloudApiKey { get; set; } = "";
        public string CloudApiSecret { get; set; } = "";
        public string JinRongApiKey { get; set; } = "";
        public bool SystemIntegrityEnabled { get; set; } = true;
        public bool RegistryGuardEnabled { get; set; } = true;
        public bool ExplorerGuardEnabled { get; set; } = true;
        public bool WindowsFileGuardEnabled { get; set; } = true;
        public bool SignatureGuardEnabled { get; set; } = true;
        public bool BootGuardEnabled { get; set; } = true;
    }
}
