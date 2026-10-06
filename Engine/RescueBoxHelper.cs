using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace JianRongSecurity.Engine;

/// <summary>
/// 360系统急救箱下载与启动助手。
/// 检测到银狐等顽固木马（WDAC策略/BYOVD驱动/hosts劫持）时，
/// 自动从官网拉取急救箱压缩包，解压后启动 superkiller.exe。
/// </summary>
public static class RescueBoxHelper
{
    /// <summary>360系统急救箱64位版官方直链（从 weishi.360.cn/jijiuxiang 页面获取）</summary>
    public const string DefaultDownloadUrl = "https://dl.360safe.com/360c0mpkill_5.1.64.1289-0701.zip";

    private static readonly string TempDir = Path.Combine(Path.GetTempPath(), "JianRongRescueBox");

    /// <summary>
    /// 下载并解压360系统急救箱，返回解压后的 superkiller.exe 路径；失败返回 null。
    /// </summary>
    public static async Task<string?> DownloadAndExtractAsync(IProgress<string>? progress = null, string? url = null)
    {
        try
        {
            Directory.CreateDirectory(TempDir);
            string zipPath = Path.Combine(TempDir, "360compkill.zip");
            string extractDir = Path.Combine(TempDir, "extracted");

            progress?.Report("正在从360官网下载系统急救箱...");

            using var http = new HttpClient
            {
                Timeout = TimeSpan.FromMinutes(5),
            };
            http.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");

            var data = await http.GetByteArrayAsync(url ?? DefaultDownloadUrl);
            if (data == null || data.Length < 1024)
            {
                progress?.Report("下载失败：文件过小或为空");
                return null;
            }
            await File.WriteAllBytesAsync(zipPath, data);
            progress?.Report($"下载完成（{data.Length / 1024 / 1024} MB），正在解压...");

            if (Directory.Exists(extractDir))
            {
                try { Directory.Delete(extractDir, true); } catch { }
            }
            ZipFile.ExtractToDirectory(zipPath, extractDir);

            string? exe = Directory.GetFiles(extractDir, "superkiller.exe", SearchOption.AllDirectories).FirstOrDefault();
            if (exe == null)
            {
                exe = Directory.GetFiles(extractDir, "*.exe", SearchOption.AllDirectories)
                    .OrderByDescending(f => new FileInfo(f).Length)
                    .FirstOrDefault();
            }

            if (exe != null)
            {
                progress?.Report($"急救箱已就绪：{Path.GetFileName(exe)}");
            }
            else
            {
                progress?.Report("解压完成但未找到可执行程序");
            }
            return exe;
        }
        catch (Exception ex)
        {
            progress?.Report($"下载/解压失败：{ex.Message}");
            return null;
        }
    }

    public static bool Launch(string exePath)
    {
        try
        {
            if (!File.Exists(exePath)) return false;
            Process.Start(new ProcessStartInfo(exePath) { UseShellExecute = true });
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static async Task<bool> DownloadAndLaunchAsync(IProgress<string>? progress = null, string? url = null)
    {
        var exe = await DownloadAndExtractAsync(progress, url);
        if (exe == null) return false;
        progress?.Report("正在启动360系统急救箱...");
        return Launch(exe);
    }
}
