using System;
using System.Diagnostics;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace JianRongSecurity.Engine;

/// <summary>
/// 更新检测引擎：读取 GitHub 仓库上的 version.json，判断当前版本是否过期。
/// 只做检测并提示，不自动下载/不自动替换；一旦过期用默认浏览器打开 version.json 指定的下载页。
/// </summary>
public class UpdateEngine
{
    // version.json 地址（JianrongStudio/JianrongInternetSecurity 仓库 main 分支）
    public string UpdateJsonUrl { get; set; } = "https://raw.githubusercontent.com/JianrongStudio/JianrongInternetSecurity/refs/heads/main/version.json";

    // 软件当前内部版本号
    public string CurrentVersion { get; set; } = "1.0.3";

    public record UpdateInfo(string Version, string Url, string Notes);

    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(15) };

    /// <summary>检查更新，返回新版本信息或 null（已是最新 / 网络失败 / JSON 异常）。</summary>
    public async Task<UpdateInfo?> CheckAsync()
    {
        try
        {
            var json = await _http.GetStringAsync(UpdateJsonUrl);
            var root = JsonDocument.Parse(json).RootElement;
            var version = ReadString(root, "version");
            var url = ReadString(root, "url");
            var notes = root.TryGetProperty("notes", out var n) ? ReadString(root, "notes") : "";
            if (CompareVersion(version, CurrentVersion) > 0)
                return new UpdateInfo(version, url, notes);
            return null;
        }
        catch { return null; }
    }

    /// <summary>检测更新；若版本过期则用默认浏览器打开 version.json 中的 url。返回 true 表示发现过期并已打开。</summary>
    public async Task<bool> CheckAndOpenIfOutdatedAsync()
    {
        var info = await CheckAsync();
        if (info == null) return false;
        if (!string.IsNullOrEmpty(info.Url))
        {
            try { Process.Start(new ProcessStartInfo(info.Url) { UseShellExecute = true }); }
            catch { }
        }
        return true;
    }

    /// <summary>兼容 version/url 字段是字符串（"1.0.3"）或数值（1.0.3）的情况。</summary>
    private static string ReadString(JsonElement root, string prop)
    {
        if (!root.TryGetProperty(prop, out var el)) return "";
        if (el.ValueKind == JsonValueKind.String) return el.GetString() ?? "";
        if (el.ValueKind == JsonValueKind.Number) return el.GetRawText();
        return "";
    }

    private static int CompareVersion(string a, string b)
    {
        try
        {
            var pa = a.Split('.');
            var pb = b.Split('.');
            for (int i = 0; i < Math.Max(pa.Length, pb.Length); i++)
            {
                int na = i < pa.Length && int.TryParse(pa[i], out var x) ? x : 0;
                int nb = i < pb.Length && int.TryParse(pb[i], out var y) ? y : 0;
                if (na != nb) return na.CompareTo(nb);
            }
            return 0;
        }
        catch { return 0; }
    }
}
