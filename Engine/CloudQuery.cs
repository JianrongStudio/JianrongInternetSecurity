using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace JianRongSecurity.Engine;

/// <summary>金荣安全云 TLSH 查询结果。</summary>
public sealed class CloudQueryResult
{
    public bool Hit { get; set; }
    public int Distance { get; set; } = -1;
    public string MatchedTlsh { get; set; } = "";
    public string Remark { get; set; } = "";
}

/// <summary>
/// 金荣安全云 TLSH 云查杀：对文件 TLSH 模糊哈希查询云端恶意库 /api/query_hash。
/// 只上传模糊哈希、绝不上传文件本体。同步查询、单次超时硬上限、失败静默。
/// </summary>
public static class CloudQuery
{
    private const string BaseUrl = "https://jianrongstudio.pythonanywhere.com";
    private static string ApiKey => AppConfig.Instance.JinRongApiKey;
    private const int TimeoutSeconds = 8;

    private static readonly HttpClient Http = new HttpClient { Timeout = TimeSpan.FromSeconds(TimeoutSeconds) };

    public static CloudQueryResult QueryTlsh(string tlsh)
    {
        var out_ = new CloudQueryResult();
        if (string.IsNullOrWhiteSpace(tlsh) || tlsh.Length < 8) return out_;
        var payload = new { api_key = ApiKey, tlsh = tlsh.Trim() };
        string json;
        try { json = JsonSerializer.Serialize(payload); }
        catch { return out_; }
        try
        {
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var resp = Http.PostAsync(BaseUrl + "/api/query_hash", content).GetAwaiter().GetResult();
            if (!resp.IsSuccessStatusCode) return out_;
            string body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (root.TryGetProperty("match", out var m) && m.ValueKind == JsonValueKind.Object)
            {
                out_.Hit = true;
                if (m.TryGetProperty("tlsh", out var mt) && mt.ValueKind == JsonValueKind.String)
                    out_.MatchedTlsh = mt.GetString() ?? "";
                if (m.TryGetProperty("remark", out var mr) && mr.ValueKind == JsonValueKind.String)
                    out_.Remark = mr.GetString() ?? "";
            }
            if (root.TryGetProperty("distance", out var d) && d.ValueKind == JsonValueKind.Number)
                out_.Distance = d.GetInt32();
            else if (root.TryGetProperty("min_distance", out var md) && md.ValueKind == JsonValueKind.Number)
                out_.Distance = md.GetInt32();
        }
        catch { }
        return out_;
    }
}
