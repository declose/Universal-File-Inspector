using System.Text;
using Ufi.Core;
using Ufi.Parsers;

namespace Ufi.Analysis;

public enum Sec { Overview, FileSystem, Hashes, Structure, Hex, Strings, Entropy, Indicators, Text, Signature }

/// <summary>One inspected file. Runs all analyzers on background threads; each section is swapped in when ready.</summary>
public sealed class Session : IDisposable
{
    public static readonly string[] Names = { "Overview", "File System", "Hashes", "Structure", "Hex View", "Strings", "Entropy", "Indicators", "Text", "Signature" };

    public readonly string FilePath;
    public readonly ByteSource Src;
    public readonly FsInfo.Snapshot Snap;
    public readonly Ctx Ctx = new();
    public readonly Doc[] Docs = new Doc[10];
    public readonly CancellationTokenSource Cts = new();
    public FileType Type;
    public StreamStats Stats;
    public Scanner.Result Scan;
    public volatile int PHash, PScan;
    public volatile bool DoneMeta, DoneHash, DoneScan;
    public readonly DateTime Started = DateTime.Now;
    public TimeSpan Elapsed;
    public double TMeta, THash, TScan, TIoc;
    public event Action Changed;
    readonly object _ov = new();

    public Session(string path)
    {
        FilePath = Path.GetFullPath(path);
        Snap = FsInfo.Capture(FilePath);     // timestamps first, before our own open touches anything
        Src = new ByteSource(FilePath);
        for (int i = 0; i < Docs.Length; i++) Docs[i] = null;
    }

    public FileType EffectiveType => Ctx.Refined ?? Type;

    public void Start()
    {
        var ct = Cts.Token;
        Task.Run(() =>
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            Guard(() => Meta(ct), "structure");
            TMeta = sw.Elapsed.TotalSeconds;
            DoneMeta = true;
            if (ct.IsCancellationRequested) return;
            Guard(() => ScanStrings(ct), "strings");
            DoneScan = true;
            Guard(RebuildOverview, "overview");
        });
        Task.Run(() => { var sw = System.Diagnostics.Stopwatch.StartNew(); Guard(() => Hash(ct), "hashes"); THash = sw.Elapsed.TotalSeconds; DoneHash = true; Guard(RebuildOverview, "overview"); });
    }

    void Guard(Action a, string what)
    {
        try { a(); }
        catch (OperationCanceledException) { }
        catch (ObjectDisposedException) { }
        catch (Exception ex) { Ctx.Warn("Analyzer", $"{what} analysis failed: {ex.GetType().Name}: {ex.Message}"); }
        finally { Notify(); }
    }

    void Notify() { if (!Cts.IsCancellationRequested) Changed?.Invoke(); }

    void Meta(CancellationToken ct)
    {
        Type = Detect.Run(Src, Path.GetExtension(FilePath));
        Ctx.Refined = Type.Clone();
        RebuildOverview();
        try { Docs[(int)Sec.FileSystem] = FsInfo.Build(FilePath, Snap, Ctx); }
        catch (Exception ex) { Docs[(int)Sec.FileSystem] = Doc.Message("File system", "Unavailable: " + ex.Message, R.Warn); }
        Notify();
        ct.ThrowIfCancellationRequested();

        Docs[(int)Sec.Structure] = BuildStructure();
        RebuildOverview(); Notify();
        ct.ThrowIfCancellationRequested();

        Docs[(int)Sec.Text] = BuildTextView();
        Notify();
        try { Docs[(int)Sec.Signature] = SignatureInfo.Build(Src, FilePath, Ctx); }
        catch (Exception ex) { Docs[(int)Sec.Signature] = Doc.Message("Signature", "Unavailable: " + ex.Message, R.Warn); }
        RebuildOverview(); Notify();
    }

    void Hash(CancellationToken ct)
    {
        Stats = StatsRunner.Run(Src, ct, p => { PHash = p; });
        Docs[(int)Sec.Hashes] = BuildHashes();
        Docs[(int)Sec.Entropy] = BuildEntropy();
        if (Stats.Total > 4096)
        {
            if (Stats.Entropy > 7.9 && EffectiveType.Category is not ("Archive" or "Media" or "Image" or "Encrypted"))
                Ctx.Warn("Entropy", $"Overall entropy {Stats.Entropy:0.000} bits/byte – data looks encrypted or packed");
            int hi = Stats.Blocks.Count(b => b > 7.9);
            if (hi > 0 && hi < Stats.Blocks.Count && EffectiveType.Kind == "pe" && hi * 5 > Stats.Blocks.Count)
                Ctx.Info("Entropy", $"{hi} of {Stats.Blocks.Count} blocks have near-random entropy (embedded compressed/encrypted data)");
        }
    }

    void ScanStrings(CancellationToken ct)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Scan = Scanner.Run(Src, EffectiveType.Kind, ct, p => { PScan = p; });
        TScan = sw.Elapsed.TotalSeconds; sw.Restart();
        Docs[(int)Sec.Strings] = BuildStrings();
        Notify();
        Docs[(int)Sec.Indicators] = BuildIndicators(ct);
        TIoc = sw.Elapsed.TotalSeconds;
        Elapsed = DateTime.Now - Started;
    }

    // ------------------------------------------------------------------ builders

    Doc BuildStructure()
    {
        var d = new Doc();
        var t = Type;
        d.H("Format identification");
        d.KV("Detected format", t.Name, R.Accent);
        d.KV("Parser", t.Kind, R.Value);
        d.KV("MIME type", t.Mime, R.Value);
        d.KV("Magic bytes", Fmt.Bytes(Src.Bytes(0, 16), 16) + "   " + Fmt.AsciiPreview(Src.Bytes(0, 16)), R.Hex, 0);
        try
        {
            switch (t.Kind)
            {
                case "pe": PeParser.Parse(Src, d, Ctx); break;
                case "mz": d.H("MS-DOS executable"); d.KV("Pages / last page bytes", $"{Src.U16(4)} / {Src.U16(2)}", R.Num, 2); d.KV("Header paragraphs", Src.U16(8), R.Num, 8); d.KV("Initial CS:IP", $"{Src.U16(0x16):X4}:{Src.U16(0x14):X4}", R.Value, 0x14); d.KV("Initial SS:SP", $"{Src.U16(0x0E):X4}:{Src.U16(0x10):X4}", R.Value, 0x0E); break;
                case "elf": ElfParser.Parse(Src, d, Ctx); break;
                case "macho": MachOParser.Parse(Src, d, Ctx); break;
                case "class": JavaClassParser.Parse(Src, d, Ctx); break;
                case "wasm": WasmParser.Parse(Src, d, Ctx); break;
                case "zip": ZipParser.Parse(Src, d, Ctx); break;
                case "gzip": GzipParser.Parse(Src, d, Ctx); break;
                case "tar": TarParser.Parse(Src, d, Ctx); break;
                case "7z": SevenZipParser.Parse(Src, d, Ctx); break;
                case "rar": RarParser.Parse(Src, d, Ctx); break;
                case "cab": CabParser.Parse(Src, d, Ctx); break;
                case "png": PngParser.Parse(Src, d, Ctx); break;
                case "jpeg": JpegParser.Parse(Src, d, Ctx); break;
                case "gif": GifParser.Parse(Src, d, Ctx); break;
                case "bmp": BmpParser.Parse(Src, d, Ctx); break;
                case "ico": IcoParser.Parse(Src, d, Ctx); break;
                case "tiff": TiffParser.Parse(Src, d, Ctx); break;
                case "riff": RiffParser.Parse(Src, d, Ctx); break;
                case "isobmff": IsoBmffParser.Parse(Src, d, Ctx); break;
                case "mp3": Mp3Parser.Parse(Src, d, Ctx); break;
                case "flac": FlacParser.Parse(Src, d, Ctx); break;
                case "pdf": PdfParser.Parse(Src, d, Ctx); break;
                case "cfb": CfbParser.Parse(Src, d, Ctx); break;
                case "lnk": LnkParser.Parse(Src, d, Ctx); break;
                case "sqlite": SqliteParser.Parse(Src, d, Ctx); break;
                case "regf": RegfParser.Parse(Src, d, Ctx); break;
                case "iso": IsoParser.Parse(Src, d, Ctx); break;
                case "der": CertParser.Parse(Src, d, Ctx, false); break;
                case "pem": CertParser.Parse(Src, d, Ctx, true); break;
                case "empty": d.Info("The file is empty – there is nothing inside to inspect."); break;
                default:
                    if (!t.IsText) { d.H("No dedicated parser"); d.T("  This format was identified by its signature, but has no structural parser yet.", R.Dim); d.T("  Use HEX VIEW, STRINGS, ENTROPY and INDICATORS to inspect it byte by byte.", R.Dim); }
                    break;
            }
        }
        catch (EndOfDataException ex) { d.Warn("Structure is truncated / malformed: " + ex.Message); Ctx.Warn("Structure", "File structure is truncated or malformed"); }
        catch (Exception ex) { d.Warn($"Parser stopped: {ex.GetType().Name}: {ex.Message}"); }
        if (t.IsText) { try { TextParser.Parse(Src, d, Ctx, t); } catch (Exception ex) { d.Warn("Text analysis failed: " + ex.Message); } }

        if (Ctx.Regions.Count > 0) { }
        var rt = EffectiveType;
        if (rt.Name != t.Name) { d.Lines.Insert(2, new Line(-1, new[] { new Seg("  " + "Refined type".PadRight(Doc.KeyWidth) + " ", R.Key), new Seg(Fmt.Clean(rt.Name), R.Good) })); }
        return d;
    }

    Doc BuildTextView()
    {
        var d = new Doc();
        var t = Type;
        long cap = Math.Min(Src.Length, 4L << 20);
        var bytes = Src.Bytes(0, cap);
        string text;
        if (t.IsText) text = TextParser.Decode(bytes, t);
        else
        {
            d.H("Binary file – printable rendering");
            d.T("  Not a text file. Non-printable bytes are shown as '·' (first 4 MiB).", R.Dim);
            var sb = new StringBuilder(bytes.Length);
            foreach (byte b in bytes) sb.Append(b == 10 ? '\n' : b == 9 ? '\t' : b >= 0x20 && b < 0x7F ? (char)b : '·');
            text = sb.ToString();
        }
        var lines = text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        int w = Math.Max(4, lines.Length.ToString().Length);
        int n = 0;
        foreach (var l in lines)
        {
            if (++n > 200_000) { d.T($"  … truncated after 200,000 lines", R.Dim); break; }
            string line = l.Length > 3000 ? l[..3000] + " …(line continues)" : l;
            d.Add(new Seg(n.ToString().PadLeft(w) + " │ ", R.Dim), new Seg(Fmt.Clean(line.Replace("\t", "    "), 4000), t.IsText ? R.Normal : R.Str));
        }
        if (Src.Length > cap) d.T($"  … showing first {Fmt.Human(cap)} of {Fmt.Human(Src.Length)}", R.Dim);
        return d;
    }

    Doc BuildHashes()
    {
        var d = new Doc();
        d.H("Cryptographic & checksum hashes (whole file)");
        foreach (var (name, hex) in Stats.Hashes) d.KV(name, hex, name.StartsWith("SHA") || name == "MD5" ? R.Hex : R.Num);
        if (Ctx.ImpHash != null) { d.H("PE fingerprints"); d.KV("Import hash (imphash)", Ctx.ImpHash, R.Hex); }
        string sha = Stats.Hashes.FirstOrDefault(h => h.Name == "SHA-256").Hex;
        d.H("Look-up references (not contacted – copy & paste)");
        d.KV("VirusTotal", "https://www.virustotal.com/gui/file/" + sha, R.Str);
        d.KV("MalwareBazaar", "https://bazaar.abuse.ch/sample/" + sha + "/", R.Str);
        d.KV("Hybrid Analysis", "https://www.hybrid-analysis.com/search?query=" + sha, R.Str);
        d.T("  The inspector never uploads or looks up anything – these links are for you to use manually.", R.Dim);
        d.H("Partial hashes");
        using (var md5 = System.Security.Cryptography.SHA256.Create())
        {
            var first = Src.Bytes(0, 4096); var last = Src.Bytes(Math.Max(0, Src.Length - 4096), 4096);
            d.KV("SHA-256 of first 4 KiB", Convert.ToHexString(md5.ComputeHash(first)).ToLowerInvariant(), R.Hex, 0);
            d.KV("SHA-256 of last 4 KiB", Convert.ToHexString(md5.ComputeHash(last)).ToLowerInvariant(), R.Hex, Math.Max(0, Src.Length - 4096));
        }
        return d;
    }

    Doc BuildEntropy()
    {
        var st = Stats;
        var d = new Doc();
        d.H("Randomness statistics (ent-style)");
        d.KV("Shannon entropy", $"{st.Entropy:0.000000} bits/byte  " + Fmt.Bar(st.Entropy / 8, 24) + "  " + StreamStats.Verdict(st.Entropy), st.Entropy > 7.5 ? R.Warn : R.Value);
        d.KV("Optimum compression", $"would shrink by ~{(100 - st.Entropy / 8 * 100):0.#}%", R.Value);
        double exp = st.Total / 256.0;
        d.KV("Chi-square (255 dof)", $"{st.Chi:0.00}   (random data ≈ 255 ± 23{(st.Total < 10000 ? ", sample small" : "")})", R.Value);
        d.KV("Arithmetic mean", $"{st.Mean:0.0000}   (random = 127.5)", R.Value);
        d.KV("Monte Carlo π", double.IsNaN(st.Pi) ? "n/a" : $"{st.Pi:0.000000}   (error {Math.Abs(st.Pi - Math.PI) / Math.PI * 100:0.00}%)", R.Value);
        d.KV("Serial correlation", double.IsNaN(st.Serial) ? "n/a" : $"{st.Serial:0.000000}   (random ≈ 0.0)", R.Value);
        d.KV("Distinct byte values", $"{st.Unique} / 256", R.Num);
        d.KV("Longest run", $"{st.RunLen:N0} × {Fmt.Hx(st.RunByte, 2)} at {Fmt.Hx(st.RunOff)}", R.Num, st.RunOff);
        long printable = 0, ws = 0, ctrl = 0, high = 0;
        for (int i = 0; i < 256; i++)
        {
            if (i is 9 or 10 or 13 or 32) ws += st.Hist[i];
            else if (i >= 33 && i < 127) printable += st.Hist[i];
            else if (i < 32 || i == 127) ctrl += st.Hist[i];
            else high += st.Hist[i];
        }
        d.H("Byte classes");
        void Cls(string n, long c) => d.KV(n, $"{c,14:N0}  {Fmt.Pct(c, st.Total),8}  {Fmt.Bar((double)c / Math.Max(1, st.Total), 30)}", R.Value);
        Cls("NUL (0x00)", st.Hist[0]);
        Cls("Printable ASCII", printable);
        Cls("Whitespace (TAB LF CR SP)", ws);
        Cls("Other control bytes", ctrl - st.Hist[0]);
        Cls("High bytes (0x80-0xFF)", high);
        d.KV("Line endings", $"CRLF {st.CrLf:N0}   LF {st.Lf:N0}   CR {st.Cr:N0}", R.Num);

        d.H($"Entropy map ({st.Blocks.Count} blocks × {Fmt.Human(st.BlockSize)})  –  Enter jumps to a block");
        d.T("  offset        entropy  0 ─────────────── 4 ─────────────── 8", R.Dim);
        for (int i = 0; i < st.Blocks.Count; i++)
        {
            double e = st.Blocks[i];
            long off = (long)i * st.BlockSize;
            R role = e > 7.5 ? R.Bad : e > 6.5 ? R.Warn : e > 4 ? R.Accent : e > 1 ? R.Good : R.Dim;
            d.Add(off, new Seg($"  {Fmt.Hx(off, 10)}  {e:0.000}   ", R.Offset), new Seg(Fmt.Bar(e / 8, 36, '▇', '·'), role));
        }

        d.H("Byte histogram");
        long max = st.Hist.Max();
        var top = Enumerable.Range(0, 256).OrderByDescending(i => st.Hist[i]).Take(16).ToList();
        d.Sub("Most frequent bytes");
        foreach (int b in top)
            d.T($"      {Fmt.Hx(b, 2)} {(b >= 0x20 && b < 0x7F ? "'" + (char)b + "'" : "   ")}  {st.Hist[b],14:N0}  {Fmt.Pct(st.Hist[b], st.Total),8}", R.Value);
        d.Sub("All 256 values");
        for (int b = 0; b < 256; b++)
        {
            long c = st.Hist[b];
            d.Add(new Seg($"      {b:X2} {(b >= 0x20 && b < 0x7F ? (char)b : '·')} ", R.Hex), new Seg($"{c,13:N0} ", R.Num),
                new Seg(Fmt.Bar(max > 0 ? (double)c / max : 0, 40, '▇', ' '), c == 0 ? R.Dim : R.Accent));
        }
        _ = exp;
        return d;
    }

    Doc BuildStrings()
    {
        var d = new Doc();
        var sc = Scan;
        int a = sc.Strings.Count(x => x.Kind == 'A'), u = sc.Strings.Count - a;
        d.H($"Strings: {sc.Strings.Count:N0}  (ASCII {a:N0}, UTF-16LE {u:N0}, min length {Scanner.MinLen})");
        if (sc.Scanned < Src.Length) d.Info($"Scanned the first {Fmt.Human(sc.Scanned)} of {Fmt.Human(Src.Length)}.");
        if (sc.StringsCapped) d.Info($"Capped at {Scanner.MaxStrings:N0} strings.");
        d.T("  Press / to filter, Enter to jump to a string in the hex view.  A = ASCII, U = UTF-16LE", R.Dim);
        d.Th(new C("Offset", 12), new C("T", 1), new C("String", 100));
        foreach (var s in sc.Strings)
            d.Add(s.Off, new Seg("  " + Fmt.Hx(s.Off, 10) + " ", R.Offset), new Seg(s.Kind + " ", s.Kind == 'U' ? R.Accent : R.Dim), new Seg(Fmt.Clean(s.Text, 400), R.Str));
        return d;
    }

    Doc BuildIndicators(CancellationToken ct)
    {
        var d = new Doc();
        var ioc = Scanner.Indicators(Scan.Strings, Ctx.ExtraStrings.ToList(), ct);
        d.H("Indicators extracted from strings & metadata");
        d.T("  Heuristic pattern matches – context matters (a URL inside a signed installer is normal).", R.Dim);
        if (ioc.Groups.Count == 0) d.T("  (none found)", R.Dim);
        var order = new[] { "URLs", "IPv4 addresses", "Domain names", "E-mail addresses", "Crypto wallets / onion", "Registry keys", "File system paths", "Base64 blobs" };
        foreach (var g in ioc.Groups.OrderBy(g => Array.IndexOf(order, g.Key) is var i && i >= 0 ? i : 100).ThenBy(g => g.Key))
        {
            bool risky = g.Key.StartsWith("Suspicious API") || g.Key.StartsWith("Keyword");
            d.Sub($"{g.Key}  ({g.Value.Count})");
            foreach (var (v, off, cnt) in g.Value.Take(1000))
                d.Add(off, new Seg("      " + (off >= 0 ? Fmt.Hx(off, 10) : "  metadata  ") + "  ", R.Offset), new Seg(Fmt.Clean(v, 300), risky ? R.Warn : R.Str), new Seg(cnt > 1 ? $"  ×{cnt}" : "", R.Dim));
            if (g.Key.StartsWith("Suspicious API: Process injection") && g.Value.Count >= 3) Ctx.Warn("Indicators", $"References {g.Value.Count} process-injection APIs ({string.Join(", ", g.Value.Take(4).Select(x => x.Value))}…)");
            if (g.Key == "Keyword: PowerShell") Ctx.Warn("Indicators", "Contains PowerShell command fragments");
            if (g.Key == "Keyword: Crypto / ransom" && g.Value.Any(x => x.Value.Contains("encrypted", StringComparison.OrdinalIgnoreCase))) Ctx.Warn("Indicators", "Ransom-note-like text found");
            if (g.Key == "Crypto wallets / onion") Ctx.Warn("Indicators", "Cryptocurrency wallet or .onion address present");
        }
        int urls = ioc.Groups.GetValueOrDefault("URLs")?.Count ?? 0;
        if (urls > 0) Ctx.Info("Indicators", $"{urls} distinct URL(s) found – see INDICATORS");

        d.H($"Embedded file signatures ({Scan.Carved.Count})");
        d.T("  Known magic numbers found at non-zero offsets (possible embedded / appended files). Enter jumps there.", R.Dim);
        foreach (var (off, what) in Scan.Carved.Take(5000))
        {
            string where = Ctx.Regions.FirstOrDefault(r => off >= r.Off && off < r.Off + r.Size).Name;
            d.Add(off, new Seg("      " + Fmt.Hx(off, 10) + "  ", R.Offset), new Seg(what, R.Accent), new Seg(where != null ? "   in " + where : "", R.Dim));
        }
        int pes = Scan.Carved.Count(c => c.What.StartsWith("PE"));
        if (pes > 0) Ctx.Warn("Carving", $"{pes} embedded PE executable header(s) found inside the file", Scan.Carved.First(c => c.What.StartsWith("PE")).Off);
        return d;
    }

    public void RebuildOverview()
    {
        lock (_ov)
        {
            var d = new Doc();
            var t = EffectiveType ?? new FileType { Name = "detecting…" };
            string name = Path.GetFileName(FilePath);
            d.H("Identity");
            d.KV("File name", name, R.Accent);
            d.KV("Location", Path.GetDirectoryName(FilePath), R.Str);
            d.KV("Size", Fmt.Size(Src.Length), R.Num);
            d.KV("Detected type", t.Name, R.Good);
            d.KV("Category / MIME", $"{t.Category}  ·  {t.Mime}", R.Value);
            string ext = Path.GetExtension(FilePath).TrimStart('.').ToLowerInvariant();
            bool match = t.Exts.Length == 0 || t.Exts.Contains(ext) || t.Kind == "unknown";
            d.KV("Extension", ext.Length == 0 ? "(none)" : "." + ext + (match ? "  (consistent with content)" : "  ≠ content!  expected: ." + string.Join(" .", t.Exts.Where(x => x.Length > 0).Take(6))), match ? R.Value : R.Bad);
            if (t.IsText) d.KV("Text encoding", t.TextEncoding, R.Value);
            d.KV("First 16 bytes", Fmt.Bytes(Src.Bytes(0, 16), 16) + "   " + Fmt.AsciiPreview(Src.Bytes(0, 16)), R.Hex, 0);

            d.H("Quick facts");
            d.KV("Modified", Fmt.Time(Snap.Modified), R.Value);
            d.KV("Created", Fmt.Time(Snap.Created), R.Value);
            if (Stats != null)
            {
                d.KV("Entropy", $"{Stats.Entropy:0.000} bits/byte  {Fmt.Bar(Stats.Entropy / 8, 20)}  {StreamStats.Verdict(Stats.Entropy)}", Stats.Entropy > 7.5 ? R.Warn : R.Value);
                foreach (var h in Stats.Hashes.Where(h => h.Name is "MD5" or "SHA-1" or "SHA-256")) d.KV(h.Name, h.Hex, R.Hex);
            }
            else d.KV("Hashes", $"computing… {PHash}%", R.Dim);
            if (Ctx.ImpHash != null) d.KV("imphash", Ctx.ImpHash, R.Hex);
            if (Scan != null) d.KV("Strings", $"{Scan.Strings.Count:N0}   embedded signatures: {Scan.Carved.Count:N0}", R.Num);

            var f = Ctx.Findings;
            if (!match && ext.Length > 0 && t.Kind != "unknown" && !t.IsText)
                f.Insert(0, new Finding(t.Category == "Executable" ? Level.Bad : Level.Warn, "Type", $"Extension .{ext} does not match the content ({t.Name})", 0));
            int bad = f.Count(x => x.Level == Level.Bad), warn = f.Count(x => x.Level == Level.Warn);
            d.H($"Findings ({bad} high, {warn} medium, {f.Count - bad - warn} info)");
            if (f.Count == 0) d.T("  (none yet)", R.Dim);
            foreach (var x in f.OrderBy(x => x.Level switch { Level.Bad => 0, Level.Warn => 1, Level.Good => 2, _ => 3 }))
            {
                string tag = x.Level switch { Level.Bad => "[!!] ", Level.Warn => "[!]  ", Level.Good => "[ok] ", _ => "[i]  " };
                R role = x.Level switch { Level.Bad => R.Bad, Level.Warn => R.Warn, Level.Good => R.Good, _ => R.Normal };
                d.Add(x.Jump, new Seg("  " + tag, role), new Seg(("[" + x.Area + "]").PadRight(15), R.Dim), new Seg(Fmt.Clean(x.Text, 600), role));
            }

            d.H("Analysis status");
            d.KV("Structure / metadata", DoneMeta ? $"done in {TMeta:0.00} s" : "running…", DoneMeta ? R.Good : R.Warn);
            d.KV("Hashes & statistics", DoneHash ? $"done in {THash:0.00} s" : $"{PHash}%", DoneHash ? R.Good : R.Warn);
            d.KV("Strings & indicators", DoneScan ? $"done in {TScan:0.00} s + {TIoc:0.00} s" : Scan == null && !DoneMeta ? "waiting" : $"{PScan}%", DoneScan ? R.Good : R.Warn);
            if (DoneScan && DoneHash) d.KV("Total time", $"{(DateTime.Now - Started).TotalSeconds:0.00} s", R.Value);
            d.T("  The file is only ever read as data. It is never executed, opened by its associated program, or uploaded.", R.Dim);
            Docs[(int)Sec.Overview] = d;
        }
        Notify();
    }

    public string BuildReport()
    {
        var sb = new StringBuilder();
        sb.AppendLine("UNIVERSAL FILE INSPECTOR – REPORT");
        sb.AppendLine($"File:      {FilePath}");
        sb.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine(new string('=', 100));
        for (int i = 0; i < Docs.Length; i++)
        {
            if (i == (int)Sec.Hex)
            {
                sb.AppendLine().AppendLine($"#### {Names[i].ToUpperInvariant()} (first 1 KiB) ####");
                var b = Src.Bytes(0, 1024);
                for (int r = 0; r < b.Length; r += 16)
                {
                    var row = b.AsSpan(r, Math.Min(16, b.Length - r));
                    sb.AppendLine($"{r:X8}  {Fmt.Bytes(row, 16).PadRight(47)}  |{Fmt.AsciiPreview(row, 16)}|");
                }
                continue;
            }
            var d = Docs[i];
            if (d == null) continue;
            sb.AppendLine().AppendLine($"#### {Names[i].ToUpperInvariant()} ####");
            sb.Append(d.ToPlainText());
        }
        return sb.ToString();
    }

    public void Dispose()
    {
        Cts.Cancel();
        // let running readers notice the cancellation before the handle goes away
        Task.Delay(1500).ContinueWith(_ => Src.Dispose());
    }
}
