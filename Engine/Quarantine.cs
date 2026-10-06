using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace JianRongSecurity.Engine;

public record QuarantineItem(string Id, string OriginalPath, string ThreatName, string Category, string Sha256, DateTime QuarantinedAt);

public class Quarantine
{
    public string Dir { get; }
    public Quarantine()
    {
        Dir = Path.Combine(AppContext.BaseDirectory, "quarantine");
        Directory.CreateDirectory(Dir);
    }

    public QuarantineItem? QuarantineFile(string path, string threatName, string category, string sha256)
    {
        try
        {
            if (!File.Exists(path)) return null;
            // 用户态隔离：直接移动到隔离目录（驱动防护已移除）
            var id = Guid.NewGuid().ToString("N");
            var dest = Path.Combine(Dir, id + ".quarantine");
            File.Move(path, dest);
            var item = new QuarantineItem(id, path, threatName, category, sha256, DateTime.Now);
            File.WriteAllText(Path.Combine(Dir, id + ".meta"), JsonSerializer.Serialize(item));
            return item;
        }
        catch { return null; }
    }

    public List<QuarantineItem> List()
    {
        var result = new List<QuarantineItem>();
        foreach (var meta in Directory.GetFiles(Dir, "*.meta"))
        {
            try
            {
                var item = JsonSerializer.Deserialize<QuarantineItem>(File.ReadAllText(meta));
                if (item != null) result.Add(item);
            }
            catch { }
        }
        return result.OrderByDescending(x => x.QuarantinedAt).ToList();
    }

    public bool Restore(string id)
    {
        try
        {
            var meta = Path.Combine(Dir, id + ".meta");
            var data = Path.Combine(Dir, id + ".quarantine");
            if (!File.Exists(meta) || !File.Exists(data)) return false;
            var item = JsonSerializer.Deserialize<QuarantineItem>(File.ReadAllText(meta));
            if (item == null) return false;
            Directory.CreateDirectory(Path.GetDirectoryName(item.OriginalPath)!);
            File.Move(data, item.OriginalPath, overwrite: true);
            File.Delete(meta);
            return true;
        }
        catch { return false; }
    }
}
