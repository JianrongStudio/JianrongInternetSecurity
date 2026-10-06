using System;
using System.IO;
using System.Linq;

namespace JianRongSecurity.Engine;

/// <summary>
/// ML 威胁分析器：基于多维度特征评分，区分真威胁与误报。
/// 评分维度：文件位置、威胁类型置信度、数字签名、文件熵、多规则命中、文件名可信度。
/// </summary>
public class MlAnalyzer
{
    public record MlVerdict(int Score, string Level, string Reason, bool LikelyFalsePositive);

    private static readonly string[] TrustedDirs =
    {
        @"\windows\system32", @"\windows\syswow64", @"\program files\",
        @"\program files (x86)\", @"\programdata\microsoft\",
    };

    private static readonly string[] SuspiciousDirs =
    {
        @"\appdata\local\temp", @"\appdata\roaming\", @"\downloads\",
        @"\desktop\", @"\programdata\",
    };

    private static readonly string[] HighPriorityThreats =
    {
        "银狐", "yinhu", "silverfox", "wdac", "sipolicy", "远控", "rat",
        "backdoor", "trojan", "木马", "cobaltstrike", "asyncrat", "redline",
    };

    public MlVerdict Analyze(ThreatInfo threat, byte[]? fileData = null)
    {
        int score = 0;
        var reasons = new System.Collections.Generic.List<string>();
        var path = (threat.Path ?? "").ToLowerInvariant();
        var name = Path.GetFileName(path);

        if (TrustedDirs.Any(d => path.Contains(d)))
        {
            score -= 30;
            reasons.Add("位于系统受信任目录 (-30)");
        }
        if (SuspiciousDirs.Any(d => path.Contains(d)))
        {
            score += 15;
            reasons.Add("位于可疑目录 (+15)");
        }

        var tname = threat.ThreatName ?? "";
        if (tname.StartsWith("YARA:"))
        {
            var rule = tname.Substring(5);
            if (rule is "EICAR_Test" or "Ransom_Generic" or "Credential_Theft" or "RAT_CobaltStrike" or "Stealer_RedLine" or "Miner_XMRig")
            {
                score += 25;
                reasons.Add($"YARA 规则 {rule} 命中（高置信特征）(+25)");
            }
            else if (rule is "Injector_Heuristic" or "Worm_Spreading" or "Backdoor_WebShell" or "RAT_AsyncRAT")
            {
                score += 10;
                reasons.Add($"YARA 规则 {rule} 命中（启发式，需确认）(+10)");
            }
        }
        else if (tname.Contains("Heuristic") || tname.Contains("PUP.Packed"))
        {
            score += 5;
            reasons.Add("启发式检测（低置信，常见于正常软件）(+5)");
        }
        else
        {
            score += 25;
            reasons.Add($"特征码命中 {tname}（高置信）(+25)");
        }

        var threatLower = tname.ToLowerInvariant();
        bool isHighPriority = HighPriorityThreats.Any(h => threatLower.Contains(h));
        if (isHighPriority)
        {
            score += 80;
            reasons.Add($"高优先威胁 {tname}（银狐/远控类，强制高分）(+80)");
        }

        if (fileData != null && fileData.Length > 1024)
        {
            var entropy = CalculateEntropy(fileData);
            if (entropy > 7.5)
            {
                score += 10;
                reasons.Add($"文件熵 {entropy:F2}（疑似加壳/加密）(+10)");
            }
            else if (entropy < 5.0)
            {
                score -= 5;
                reasons.Add($"文件熵 {entropy:F2}（正常文本/资源）(-5)");
            }
        }

        try
        {
            if (File.Exists(threat.Path))
            {
                var size = new FileInfo(threat.Path).Length;
                if (size < 50 * 1024 && (path.EndsWith(".exe") || path.EndsWith(".dll")))
                {
                    score += 10;
                    reasons.Add($"可执行文件仅 {size / 1024}KB（疑似小型木马/加载器）(+10)");
                }
                if (size > 50 * 1024 * 1024)
                {
                    score -= 10;
                    reasons.Add("大文件（通常非恶意）(-10)");
                }
            }
        }
        catch { }

        bool hasSig = HasValidSignature(threat.Path);
        if (hasSig)
        {
            score -= 50;
            reasons.Add("文件有有效数字签名 (-50)");
        }

        if (hasSig && (path.Contains(@"\program files\") || path.Contains(@"\program files (x86)\")))
        {
            score -= 20;
            reasons.Add("Program Files 目录下的已签名程序 (-20)");
        }

        if (isHighPriority && score < 45)
        {
            score = 45;
            reasons.Add("高优先威胁最低分兜底 (≥45)");
        }

        string level;
        bool fp;
        if (score <= 5) { level = "大概率安全（误报）"; fp = true; }
        else if (score < 25) { level = "低风险，建议人工确认"; fp = false; }
        else if (score < 45) { level = "中风险，可疑"; fp = false; }
        else { level = "高风险，建议隔离"; fp = false; }

        return new MlVerdict(score, level, string.Join("；", reasons), fp);
    }

    private static double CalculateEntropy(byte[] data)
    {
        var freq = new long[256];
        foreach (var b in data) freq[b]++;
        double entropy = 0;
        double len = data.Length;
        foreach (var c in freq)
        {
            if (c > 0)
            {
                double p = c / len;
                entropy -= p * Math.Log(p, 2);
            }
        }
        return entropy;
    }

    private static bool HasValidSignature(string path)
    {
        try
        {
            if (!File.Exists(path) || path.EndsWith(".ps1") || path.EndsWith(".bat")) return false;
            using var fs = File.OpenRead(path);
            if (fs.Length < 512) return false;
            var buf = new byte[512];
            fs.Read(buf, 0, 512);
            if (buf[0] != 0x4D || buf[1] != 0x5A) return false;
            int peOffset = BitConverter.ToInt32(buf, 0x3C);
            if (peOffset <= 0 || peOffset + 256 > fs.Length) return false;
            fs.Seek(peOffset, SeekOrigin.Begin);
            var pe = new byte[256];
            fs.Read(pe, 0, 256);
            int optOffset = peOffset + 4 + 20;
            if (optOffset + 160 > fs.Length) return false;
            fs.Seek(optOffset + 152, SeekOrigin.Begin);
            var secDir = new byte[8];
            fs.Read(secDir, 0, 8);
            var rva = BitConverter.ToUInt32(secDir, 0);
            return rva != 0;
        }
        catch { return false; }
    }
}
