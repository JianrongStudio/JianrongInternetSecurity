using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace JianRongSecurity.Engine;

/// <summary>金荣安全云 TLSH 查询结果。</summary>
public sealed class CloudQueryResult
{
    /// <summary>是否命中云端恶意库。</summary>
    public bool Hit { get; set; }

    /// <summary>命中时的相似度距离（越小越相似，0=完全一致）。</summary>
    public int Distance { get; set; } = -1;

    /// <summary>命中的库内 TLSH（用于确认/日志）。</summary>
    public string MatchedTlsh { get; set; } = "";

    /// <summary>云端备注。</summary>
    public string Remark { get; set; } = "";
}

/// <summary>
/// 金荣安全云 TLSH 云查杀：对文件 TLSH 模糊哈希查询云端恶意库 /api/query_hash。
/// 与 CloudTlshReporter 的上传通道配套，构成"上传攒库 → 查询命中"闭环。
/// 只上传模糊哈希、绝不上传文件本体。同步查询、单次超时硬上限、失败静默。
/// </summary>
public static class CloudQuery
{
    private const string BaseUrl = "https://jianrongstudio.pythonanywhere.com";
    private static string ApiKey => AppConfig.Instance.JinRongApiKey; // 由 config.json 注入，源码不硬编码
    private const int TimeoutSeconds = 8; // 免费接口排队，超时硬上限

    private static readonly HttpClient Http = new HttpClient { Timeout = TimeSpan.FromSeconds(TimeoutSeconds) };

    /// <summary>查询单个 TLSH 是否命中云端恶意库。失败/超时返回未命中，绝不抛异常。</summary>
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

            // 命中：响应含 match 对象且非 null（未命中返回 status:"clean"）
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
        catch { /* 网络/超时/解析失败静默，返回未命中 */ }

        return out_;
    }
}
