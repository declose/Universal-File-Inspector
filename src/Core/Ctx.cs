namespace Ufi.Core;

public enum Level { Info, Warn, Bad, Good }

public readonly record struct Finding(Level Level, string Area, string Text, long Jump);

/// <summary>Shared analysis context: findings plus facts that different analyzers hand to each other.</summary>
public sealed class Ctx
{
    readonly List<Finding> _f = new();
    readonly object _g = new();

    public void Add(Level l, string area, string text, long jump = -1) { lock (_g) _f.Add(new Finding(l, area, text, jump)); }
    public void Bad(string area, string text, long jump = -1) => Add(Level.Bad, area, text, jump);
    public void Warn(string area, string text, long jump = -1) => Add(Level.Warn, area, text, jump);
    public void Info(string area, string text, long jump = -1) => Add(Level.Info, area, text, jump);
    public void Good(string area, string text, long jump = -1) => Add(Level.Good, area, text, jump);

    public List<Finding> Findings { get { lock (_g) return _f.ToList(); } }

    /// <summary>Type after structure parsing refined it (e.g. ZIP → DOCX).</summary>
    public volatile FileType Refined;

    // PE facts
    public string ImpHash;
    public long CertOffset = -1, CertSize;
    public bool IsPE, IsDotNet;
    public List<(string Name, long Off, long Size)> Regions = new();
    public List<string> ExtraStrings = new();   // e.g. decompressed metadata, fed to the indicator scan
}
