using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace JianRongSecurity.Engine;

/// <summary>
/// 云端 TLSH 哈希上报：扫描检出恶意文件后，本地计算该文件的 TLSH 并上传到云端
/// 接口 /api/submit_tlsh（与 main.py 的 client_hash_upload.py 逻辑一致）。
///
/// 只上传哈希，绝不上传文件本体，供云端付费人员后续做相似哈希比对。
/// 全部异步、失败静默、限并发，绝不阻塞或拖垮扫描主流程。
/// </summary>
public static class CloudTlshReporter
{
    private const string BaseUrl = "https://jianrongstudio.pythonanywhere.com";
    private static string ApiKey => AppConfig.Instance.JinRongApiKey; // 由 config.json 注入，源码不硬编码
    private const int TimeoutSeconds = 20;
    private const long MaxFileBytes = 100 * 1024 * 1024; // 超过 100MB 的文件不参与 TLSH 上传（避免读全文件开销）

    private static readonly HttpClient Http = new HttpClient { Timeout = TimeSpan.FromSeconds(TimeoutSeconds) };
    private static readonly SemaphoreSlim ConcurrencyGate = new SemaphoreSlim(3); // 最多同时 3 个上传

    /// <summary>检出威胁后触发异步上报（fire-and-forget，不阻塞调用线程）。</summary>
    public static void ReportThreatAsync(string filePath, string threatName)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return;
        _ = Task.Run(() => UploadCoreAsync(filePath, threatName));
    }

    private static async Task UploadCoreAsync(string filePath, string threatName)
    {
        if (!await ConcurrencyGate.WaitAsync(0)) return; // 并发已满，静默丢弃本次，避免堆积
        try
        {
            FileInfo fi;
            try { fi = new FileInfo(filePath); }
            catch { return; }
            if (!fi.Exists || fi.Length < 50 || fi.Length > MaxFileBytes) return;

            byte[] data;
            try { data = await File.ReadAllBytesAsync(filePath); }
            catch { return; }

            var tlsh = Tlsh.Compute(data);
            if (tlsh == null) return; // TNULL（数据过短或复杂度不足），与 main.py 一致

            var payload = new { api_key = ApiKey, tlsh = tlsh, remark = string.IsNullOrWhiteSpace(threatName) ? "未知恶意样本" : threatName.Trim() };
            string json;
            try { json = JsonSerializer.Serialize(payload); }
            catch { return; }

            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            try
            {
                using var resp = await Http.PostAsync(BaseUrl + "/api/submit_tlsh", content);
                // 结果不影响本地；无论成功与否都静默
            }
            catch { /* 网络/超时等异常静默，绝不抛给调用方 */ }
        }
        catch { /* 任何异常静默 */ }
        finally
        {
            ConcurrencyGate.Release();
        }
    }
}
