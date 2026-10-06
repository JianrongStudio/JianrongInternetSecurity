using System;
using System.Collections.Generic;
using System.IO;

namespace JianRongSecurity.Engine;

/// <summary>
/// CSafe 特征库加载器（静态类）。
/// 对应 B 站开源杀毒 CSafe 的四套内存表：
///   - BITProtect 黑名单（black.txt）
///   - BITProtect 系统白名单（white_system.txt）
///   - BITProtect 普通白名单（white_normal.txt）
///   - LSProtect 导入表黑名单（import_black.txt）
/// 数据文件为 UTF-8(无BOM) 文本，每行一行：key<TAB>value。
/// 路径 = AppContext.BaseDirectory\csafe_db\*.txt。
/// 加载失败绝不抛异常，而是置 IsReady=false 并返回空字典。
/// </summary>
public static class CsafeSignatureDb
{
    private static Dictionary<string, short> _black = new(StringComparer.Ordinal);
    private static Dictionary<string, short> _whiteSystem = new(StringComparer.Ordinal);
    private static Dictionary<string, short> _whiteNormal = new(StringComparer.Ordinal);
    private static Dictionary<string, short> _importBlack = new(StringComparer.Ordinal);
    private static bool _ready;

    private static readonly Lazy<object> _init = new(() =>
    {
        try { LoadAll(); }
        catch (Exception ex)
        {
            Log("CSafe特征库加载发生未预期异常：" + ex.Message);
            _ready = false;
        }
        return new object();
    });

    public static bool IsReady { get { _ = _init.Value; return _ready; } }
    public static IReadOnlyDictionary<string, short> Black { get { _ = _init.Value; return _black; } }
    public static IReadOnlyDictionary<string, short> WhiteSystem { get { _ = _init.Value; return _whiteSystem; } }
    public static IReadOnlyDictionary<string, short> WhiteNormal { get { _ = _init.Value; return _whiteNormal; } }
    public static IReadOnlyDictionary<string, short> ImportBlack { get { _ = _init.Value; return _importBlack; } }

    private static string DbDir => Path.Combine(AppContext.BaseDirectory, "csafe_db");

    private static void LoadAll()
    {
        bool ok = true;
        ok &= TryLoad("black.txt", ref _black);
        ok &= TryLoad("white_system.txt", ref _whiteSystem);
        ok &= TryLoad("white_normal.txt", ref _whiteNormal);
        ok &= TryLoad("import_black.txt", ref _importBlack);
        _ready = ok;

        if (ok)
            Log(string.Format("CSafe特征库加载完成：黑词={0} 系统白词={1} 普通白词={2} 导入黑名单={3}",
                _black.Count, _whiteSystem.Count, _whiteNormal.Count, _importBlack.Count));
        else
            Log("CSafe特征库未就绪，CSafe启发式/导入表引擎将被跳过。");
    }

    private static bool TryLoad(string fileName, ref Dictionary<string, short> dict)
    {
        string path = Path.Combine(DbDir, fileName);
        if (!File.Exists(path))
        {
            Log("CSafe特征文件不存在：" + path);
            return false;
        }
        try
        {
            var fresh = new Dictionary<string, short>(StringComparer.Ordinal);
            foreach (var raw in File.ReadAllLines(path))
            {
                if (string.IsNullOrEmpty(raw)) continue;
                int tab = raw.IndexOf('\t');
                if (tab <= 0) continue;
                string key = raw.Substring(0, tab);
                string valText = raw.Substring(tab + 1).Trim();
                if (short.TryParse(valText, out short w))
                {
                    if (!fresh.ContainsKey(key)) fresh[key] = w;
                }
            }
            dict = fresh;
            return true;
        }
        catch (Exception ex)
        {
            Log("CSafe特征文件解析失败：" + path + " ，原因：" + ex.Message);
            return false;
        }
    }

    private static void Log(string message)
    {
        try
        {
            System.Diagnostics.Trace.WriteLine("[CSafe] " + message);
            Console.WriteLine("[CSafe] " + message);
        }
        catch { }
    }
}
