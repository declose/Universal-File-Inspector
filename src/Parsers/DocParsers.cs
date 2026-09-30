using System.Text;
using System.Text.RegularExpressions;
using Ufi.Core;

namespace Ufi.Parsers;

public static class PdfParser
{
    static readonly string[] Keys =
    {
        "obj", "endobj", "stream", "endstream", "xref", "trailer", "startxref", "/Page", "/Encrypt", "/ObjStm", "/JS", "/JavaScript", "/AA", "/OpenAction",
        "/AcroForm", "/JBIG2Decode", "/RichMedia", "/Launch", "/EmbeddedFile", "/XFA", "/URI", "/SubmitForm", "/GoToR", "/GoToE", "/ImportData", "/Colors", "/Names", "/Linearized", "/Sig",
    };

    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        long cap = Math.Min(s.Length, 128L << 20);
        var counts = Keys.ToDictionary(k => k, _ => 0);
        var firstAt = new Dictionary<string, long>();
        var eofs = new List<long>();
        var text = new StringBuilder();
        const int Chunk = 8 << 20, Ov = 64;
        var buf = new byte[Chunk + Ov];
        for (long off = 0; off < cap; off += Chunk)
        {
            int n = s.ReadAt(off, buf.AsSpan(0, (int)Math.Min(Chunk + Ov, cap - off)));
            int body = Math.Min(n, Chunk);
            var sp = buf.AsSpan(0, n);
            foreach (var k in Keys)
            {
                var kb = Encoding.ASCII.GetBytes(k);
                int from = 0;
                while (from < body)
                {
                    int i = sp[from..].IndexOf(kb);
                    if (i < 0) break;
                    int at = from + i; from = at + 1;
                    if (at >= body) break;
                    int after = at + kb.Length;
                    bool word = k[0] == '/' ? after >= n || !char.IsLetterOrDigit((char)sp[after]) : (at == 0 || !char.IsLetter((char)sp[at - 1])) && (after >= n || !char.IsLetter((char)sp[after]));
                    if (!word) continue;
                    counts[k]++;
                    firstAt.TryAdd(k, off + at);
                }
            }
            int e = 0;
            while (e < body) { int i = sp[e..].IndexOf("%%EOF"u8); if (i < 0) break; eofs.Add(off + e + i); e += i + 1; }
            if (text.Length < 32 << 20) text.Append(Encoding.Latin1.GetString(buf, 0, body));
        }
        string t = text.ToString();

        d.H("PDF header");
        long hp = t.IndexOf("%PDF-", StringComparison.Ordinal);
        d.KV("Version", hp >= 0 ? t.Substring((int)hp + 5, Math.Min(3, t.Length - (int)hp - 5)) : "?", R.Value, hp);
        if (hp > 0) { d.KV("Header offset", Fmt.Hx(hp) + "  (data before %PDF – polyglot?)", R.Warn, 0); ctx.Warn("PDF", $"{hp} bytes precede the %PDF header (polyglot / evasion trick)"); }
        d.KV("Incremental updates", Math.Max(0, eofs.Count - 1) + $"  ({eofs.Count} %%EOF markers)", eofs.Count > 1 ? R.Warn : R.Value);
        if (eofs.Count > 1) ctx.Info("PDF", $"Document was saved {eofs.Count - 1} more time(s) incrementally (earlier revisions are still inside the file)");
        if (counts["/Linearized"] > 0) d.KV("Linearized", "yes (fast web view)", R.Value);

        d.H("Keyword counts (pdfid-style)");
        foreach (var k in Keys)
        {
            int c = counts[k];
            bool danger = k is "/JS" or "/JavaScript" or "/Launch" or "/OpenAction" or "/AA" or "/EmbeddedFile" or "/XFA" or "/RichMedia" or "/SubmitForm" or "/ImportData" or "/GoToR" or "/GoToE" or "/JBIG2Decode";
            d.Add(firstAt.TryGetValue(k, out var fa) ? fa : -1, new Seg("  " + k.PadRight(18), R.Key), new Seg(c.ToString().PadLeft(8), c > 0 && danger ? R.Bad : c > 0 ? R.Num : R.Dim));
        }
        if (counts["/JS"] + counts["/JavaScript"] > 0) ctx.Bad("PDF", "PDF contains JavaScript", firstAt.GetValueOrDefault("/JavaScript", firstAt.GetValueOrDefault("/JS", -1)));
        if (counts["/OpenAction"] + counts["/AA"] > 0) ctx.Warn("PDF", "PDF has automatic actions (/OpenAction or /AA) that run when opened", firstAt.GetValueOrDefault("/OpenAction", firstAt.GetValueOrDefault("/AA", -1)));
        if (counts["/Launch"] > 0) ctx.Bad("PDF", "PDF contains /Launch actions (can start programs)", firstAt["/Launch"]);
        if (counts["/EmbeddedFile"] > 0) ctx.Warn("PDF", "PDF contains embedded files", firstAt["/EmbeddedFile"]);
        if (counts["/XFA"] > 0) ctx.Warn("PDF", "PDF contains an XFA form", firstAt["/XFA"]);
        if (counts["/RichMedia"] > 0) ctx.Warn("PDF", "PDF contains rich media (Flash / video)", firstAt["/RichMedia"]);
        if (counts["/Encrypt"] > 0) ctx.Info("PDF", "PDF is encrypted (content streams are not readable without the key)");
        if (counts["/ObjStm"] > 0) ctx.Info("PDF", $"{counts["/ObjStm"]} compressed object stream(s) – keywords inside them are not counted above");
        if (counts["/JBIG2Decode"] > 0) ctx.Warn("PDF", "JBIG2 image streams (historically exploited decoder)");

        // Info dictionary
        d.H("Document information");
        foreach (var key in new[] { "Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate", "Company", "SourceModified" })
        {
            var m = Regex.Match(t, "/" + key + @"\s*(\((?:\\.|[^\\)]){0,2000}\)|<[0-9A-Fa-f\s]{0,4000}>)");
            if (!m.Success) continue;
            string v = PdfString(m.Groups[1].Value);
            if (key.EndsWith("Date")) v = PdfDate(v);
            d.KV(key, v, R.Str, m.Index);
            ctx.ExtraStrings.Add(v);
        }
        var xmpTool = Regex.Match(t, @"<xmp:CreatorTool>([^<]{1,300})</");
        if (xmpTool.Success) d.KV("XMP CreatorTool", xmpTool.Groups[1].Value, R.Str, xmpTool.Index);
        var xmpProd = Regex.Match(t, @"<pdf:Producer>([^<]{1,300})</");
        if (xmpProd.Success) d.KV("XMP Producer", xmpProd.Groups[1].Value, R.Str, xmpProd.Index);
        var docId = Regex.Match(t, @"/ID\s*\[\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>");
        if (docId.Success) d.KV("Document ID", docId.Groups[1].Value + (docId.Groups[1].Value != docId.Groups[2].Value ? " (modified: " + docId.Groups[2].Value + ")" : ""), R.Hex, docId.Index);

        // URIs / launch targets / embedded names
        var uris = Regex.Matches(t, @"/URI\s*\(((?:\\.|[^\\)]){1,2000})\)").Select(m => (PdfString("(" + m.Groups[1].Value + ")"), (long)m.Index)).DistinctBy(x => x.Item1).Take(500).ToList();
        if (uris.Count > 0)
        {
            d.H($"Link targets (/URI) – {uris.Count}");
            foreach (var (u, o) in uris) { d.T("    " + u, R.Str, o); ctx.ExtraStrings.Add(u); }
        }
        foreach (Match m in Regex.Matches(t, @"/Launch.{0,300}?/F\s*\(((?:\\.|[^\\)]){1,500})\)", RegexOptions.Singleline).Take(50))
            ctx.Bad("PDF", "Launch target: " + PdfString("(" + m.Groups[1].Value + ")"), m.Index);
        var files = Regex.Matches(t, @"/Type\s*/Filespec.{0,300}?/(?:UF|F)\s*\(((?:\\.|[^\\)]){1,500})\)", RegexOptions.Singleline).Take(100).ToList();
        if (files.Count > 0)
        {
            d.H("Embedded / referenced files");
            foreach (Match m in files) d.T("    " + PdfString("(" + m.Groups[1].Value + ")"), R.Warn, m.Index);
        }
        var js = Regex.Matches(t, @"/JS\s*\(((?:\\.|[^\\)]){1,4000})\)").Take(20).ToList();
        if (js.Count > 0)
        {
            d.H("Inline JavaScript");
            foreach (Match m in js) { d.T($"  at {Fmt.Hx(m.Index)}:", R.Dim, m.Index); d.Text(PdfString("(" + m.Groups[1].Value + ")"), R.Bad, "      ", 40); }
        }

        // objects & streams summary
        var filters = Regex.Matches(t, @"/Filter\s*(/\w+|\[[^\]]{0,200}\])").GroupBy(m => Regex.Replace(m.Groups[1].Value, @"\s+", " ")).OrderByDescending(g => g.Count()).Take(12);
        d.H("Stream filters used");
        foreach (var g in filters) d.KV(g.Key, g.Count(), R.Num);
        var types = Regex.Matches(t, @"/Type\s*/(\w+)").GroupBy(m => m.Groups[1].Value).OrderByDescending(g => g.Count()).Take(20);
        d.H("Object types");
        foreach (var g in types) d.KV(g.Key, g.Count(), R.Num);
        int pages = Regex.Matches(t, @"/Type\s*/Page\b").Count;
        var rt = ctx.Refined ?? new FileType(); rt.Name = $"PDF document{(pages > 0 ? $", ~{pages} page(s)" : "")}"; ctx.Refined = rt;

        if (eofs.Count > 0)
        {
            long last = eofs[^1] + 5;
            var tail = s.Bytes(last, 4096);
            int nonWs = tail.Count(b => b is not (0x0A or 0x0D or 0x20 or 0x00 or 0x09));
            if (last < s.Length && nonWs > 8)
            {
                string q = Detect.Quick(tail);
                d.H("Data after final %%EOF");
                d.KV("Offset / size", $"{Fmt.Hx(last)} / {Fmt.Size(s.Length - last)}", R.Warn, last);
                ctx.Warn("PDF", $"{Fmt.Human(s.Length - last)} of data after the last %%EOF{(q != null ? " (" + q + ")" : "")}", last);
            }
        }
        if (s.Length > cap) d.Info($"Only the first {Fmt.Human(cap)} were scanned for keywords.");
    }

    static string PdfString(string raw)
    {
        if (raw.StartsWith("<"))
        {
            string hex = Regex.Replace(raw.Trim('<', '>'), @"\s", "");
            if (hex.Length % 2 == 1) hex += "0";
            try
            {
                var b = Convert.FromHexString(hex);
                return b.Length >= 2 && b[0] == 0xFE && b[1] == 0xFF ? Encoding.BigEndianUnicode.GetString(b, 2, b.Length - 2) : Encoding.Latin1.GetString(b);
            }
            catch { return raw; }
        }
        string inner = raw.Length >= 2 ? raw[1..^1] : raw;
        var sb = new StringBuilder();
        for (int i = 0; i < inner.Length; i++)
        {
            char c = inner[i];
            if (c != '\\' || i + 1 >= inner.Length) { sb.Append(c); continue; }
            char n = inner[++i];
            switch (n)
            {
                case 'n': sb.Append('\n'); break; case 'r': sb.Append('\r'); break; case 't': sb.Append('\t'); break;
                case 'b': sb.Append('\b'); break; case 'f': sb.Append('\f'); break;
                case >= '0' and <= '7':
                    int v = n - '0', k = 0;
                    while (k < 2 && i + 1 < inner.Length && inner[i + 1] is >= '0' and <= '7') { v = v * 8 + (inner[++i] - '0'); k++; }
                    sb.Append((char)(v & 0xFF)); break;
                default: sb.Append(n); break;
            }
        }
        string r = sb.ToString();
        if (r.Length >= 2 && r[0] == 'þ' && r[1] == 'ÿ')
        {
            var bytes = Encoding.Latin1.GetBytes(r);
            return Encoding.BigEndianUnicode.GetString(bytes, 2, bytes.Length - 2);
        }
        return r;
    }

    static string PdfDate(string v)
    {
        var m = Regex.Match(v, @"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([Z+\-])?(\d{2})?'?(\d{2})?");
        if (!m.Success) return v;
        string g(int i, string def) => m.Groups[i].Success && m.Groups[i].Value != "" ? m.Groups[i].Value : def;
        string tz = m.Groups[7].Success ? (g(7, "") == "Z" ? " UTC" : $" {g(7, "")}{g(8, "00")}:{g(9, "00")}") : "";
        return $"{g(1, "0000")}-{g(2, "01")}-{g(3, "01")} {g(4, "00")}:{g(5, "00")}:{g(6, "00")}{tz}   [{v}]";
    }
}

public static class CfbParser
{
    const uint EndChain = 0xFFFFFFFE, Free = 0xFFFFFFFF;

    sealed class Ent
    {
        public int Id; public string Name; public byte Type; public uint Left, Right, Child, Start; public ulong Size; public string Clsid; public long Ctime, Mtime; public string Path;
    }

    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        ushort major = s.U16(26), shift = s.U16(30), mshift = s.U16(32);
        int ss = 1 << shift, mss = 1 << mshift;
        uint nFat = s.U32(44), firstDir = s.U32(48), cutoff = s.U32(56), firstMini = s.U32(60), nMini = s.U32(64), firstDifat = s.U32(68), nDifat = s.U32(72);
        d.H("Compound File Binary header");
        d.KV("Version", $"{major}.{s.U16(24)}  (sector size {ss}, mini sector {mss})", R.Value, 24);
        d.KV("FAT sectors", nFat, R.Num, 44);
        d.KV("First directory sector", Fmt.Hx(firstDir), R.Num, 48);
        d.KV("Mini stream cutoff", cutoff, R.Num, 56);
        d.KV("Mini FAT sectors / first", $"{nMini} / {Fmt.Hx(firstMini)}", R.Num, 60);
        d.KV("DIFAT sectors / first", $"{nDifat} / {Fmt.Hx(firstDifat)}", R.Num, 68);
        if (shift is not (9 or 12)) { d.Warn("Invalid sector shift"); return; }

        long SecOff(uint n) => (long)(n + 1) << shift;
        // FAT
        var fatSecs = new List<uint>();
        for (int i = 0; i < 109; i++) { uint v = s.U32(76 + i * 4); if (v < 0xFFFFFFFA) fatSecs.Add(v); }
        uint dif = firstDifat; int guard = 0;
        while (dif < 0xFFFFFFFA && guard++ < 10000)
        {
            long o = SecOff(dif);
            for (int i = 0; i < ss / 4 - 1; i++) { uint v = s.U32(o + i * 4); if (v < 0xFFFFFFFA) fatSecs.Add(v); }
            dif = s.U32(o + ss - 4);
        }
        var fat = new List<uint>();
        foreach (var fs in fatSecs.Take(1 << 20)) { long o = SecOff(fs); if (!s.Has(o, ss)) break; var b = s.Bytes(o, ss); for (int i = 0; i < ss; i += 4) fat.Add(BitConverter.ToUInt32(b, i)); }
        List<uint> Chain(uint start, List<uint> table, int max = 1 << 22)
        {
            var r = new List<uint>(); var seen = new HashSet<uint>();
            while (start < 0xFFFFFFFA && start < table.Count && seen.Add(start) && r.Count < max) { r.Add(start); start = table[(int)start]; }
            return r;
        }
        byte[] ReadChain(uint start, long size)
        {
            var ms = new MemoryStream();
            foreach (var sc in Chain(start, fat)) { ms.Write(s.Bytes(SecOff(sc), ss)); if (ms.Length >= size) break; }
            var a = ms.ToArray(); if (a.Length > size) Array.Resize(ref a, (int)size);
            return a;
        }
        // directory
        var dirBytes = new MemoryStream();
        foreach (var sc in Chain(firstDir, fat, 100000)) dirBytes.Write(s.Bytes(SecOff(sc), ss));
        var db = dirBytes.ToArray();
        var ents = new List<Ent>();
        for (int i = 0; i + 128 <= db.Length && ents.Count < 100000; i += 128)
        {
            int nl = BitConverter.ToUInt16(db, i + 64);
            var e = new Ent
            {
                Id = i / 128, Name = nl >= 2 ? Encoding.Unicode.GetString(db, i, Math.Min(nl, 64) - 2) : "", Type = db[i + 66],
                Left = BitConverter.ToUInt32(db, i + 68), Right = BitConverter.ToUInt32(db, i + 72), Child = BitConverter.ToUInt32(db, i + 76),
                Clsid = Fmt.Guid(db.AsSpan(i + 80, 16)), Ctime = BitConverter.ToInt64(db, i + 100), Mtime = BitConverter.ToInt64(db, i + 108),
                Start = BitConverter.ToUInt32(db, i + 116), Size = major == 3 ? BitConverter.ToUInt32(db, i + 120) : BitConverter.ToUInt64(db, i + 120)
            };
            ents.Add(e);
        }
        if (ents.Count == 0) { d.Warn("No directory entries"); return; }
        var root = ents[0];
        // mini stream
        var miniFat = new List<uint>();
        if (nMini > 0) { var mf = ReadChain(firstMini, (long)nMini * ss); for (int i = 0; i + 4 <= mf.Length; i += 4) miniFat.Add(BitConverter.ToUInt32(mf, i)); }
        byte[] miniStream = null;
        byte[] Read(Ent e, long max = 16 << 20)
        {
            long size = (long)Math.Min(e.Size, (ulong)max);
            if (e.Size < cutoff && e.Type == 2)
            {
                miniStream ??= ReadChain(root.Start, (long)Math.Min(root.Size, 256UL << 20));
                var ms = new MemoryStream();
                foreach (var m in Chain(e.Start, miniFat)) { long o = (long)m * mss; if (o + mss > miniStream.Length) break; ms.Write(miniStream, (int)o, mss); if (ms.Length >= size) break; }
                var a = ms.ToArray(); if (a.Length > size) Array.Resize(ref a, (int)size); return a;
            }
            return ReadChain(e.Start, size);
        }
        // tree → paths
        var visited = new HashSet<uint>();
        void Tree(uint id, string parent)
        {
            if (id >= ents.Count || !visited.Add(id)) return;
            var e = ents[(int)id];
            e.Path = parent + "/" + e.Name;
            Tree(e.Left, parent); Tree(e.Right, parent);
            if (e.Type is 1 or 5) Tree(e.Child, e.Path);
        }
        root.Path = "";
        if (root.Child < ents.Count) Tree(root.Child, "");

        d.H($"Storage / stream tree ({ents.Count(e => e.Path != null)} entries)");
        d.Th(new C("Type", 8), new C("Size", 12, R.Dim, true), new C("Modified", 19), new C("Path", 60));
        foreach (var e in ents.Where(e => e.Path != null && e.Type != 0).OrderBy(e => e.Path, StringComparer.OrdinalIgnoreCase))
        {
            string tn = e.Type switch { 1 => "storage", 2 => "stream", 5 => "root", _ => "?" };
            long jump = e.Type == 2 && e.Size >= cutoff ? SecOff(e.Start) : -1;
            string mt = Fmt.FileTimeOrNull(e.Mtime)?.ToString("yyyy-MM-dd HH:mm:ss") ?? "";
            d.Tr(jump, new C(tn, 8, R.Key), new C(e.Type == 2 ? e.Size.ToString("N0") : "", 12, R.Num, true), new C(mt, 19, R.Value),
                new C(Visible(e.Path), 60, e.Type == 1 ? R.Accent : R.Str));
        }
        d.KV("Root CLSID", root.Clsid, R.Value);
        if (Fmt.FileTimeOrNull(root.Mtime) is DateTime rm) d.KV("Root modified", Fmt.Time(rm), R.Value);

        // subtype
        var names = ents.Where(e => e.Path != null).Select(e => e.Name).ToList();
        bool Has(string n) => names.Any(x => x.Equals(n, StringComparison.OrdinalIgnoreCase));
        string sub = null; string[] exts = null;
        if (Has("WordDocument")) (sub, exts) = ("Microsoft Word 97-2003 document", new[] { "doc", "dot", "wiz" });
        else if (Has("Workbook") || Has("Book")) (sub, exts) = ("Microsoft Excel 97-2003 workbook", new[] { "xls", "xlt", "xla" });
        else if (Has("PowerPoint Document")) (sub, exts) = ("Microsoft PowerPoint 97-2003 presentation", new[] { "ppt", "pps", "pot" });
        else if (root.Clsid == "{000C1084-0000-0000-C000-000000000046}") (sub, exts) = ("Windows Installer package (MSI)", new[] { "msi" });
        else if (root.Clsid == "{000C1086-0000-0000-C000-000000000046}") (sub, exts) = ("Windows Installer patch (MSP)", new[] { "msp" });
        else if (names.Any(n => n.StartsWith("__substg1.0_"))) (sub, exts) = ("Outlook message (MSG)", new[] { "msg", "oft" });
        else if (Has("VisioDocument")) (sub, exts) = ("Microsoft Visio drawing", new[] { "vsd", "vss", "vst" });
        else if (Has("Contents") && Has("Quill")) (sub, exts) = ("Microsoft Publisher document", new[] { "pub" });
        else if (Has("EncryptedPackage")) (sub, exts) = ("Password-protected Office (OOXML) document", new[] { "docx", "xlsx", "pptx", "doc", "xls" });
        else if (names.Any(n => n.EndsWith("Thumbs.db", StringComparison.OrdinalIgnoreCase)) || Has("Catalog")) (sub, exts) = ("Windows thumbnail cache (Thumbs.db)", new[] { "db" });
        if (sub != null)
        {
            var rt = ctx.Refined ?? new FileType(); rt.Name = sub; rt.Exts = exts; ctx.Refined = rt;
            d.KV("Container type", sub, R.Accent);
        }
        if (Has("EncryptedPackage")) ctx.Warn("Office", "Document is encrypted (password-protected) – contents hidden from scanners");
        if (names.Any(n => n is "VBA" or "_VBA_PROJECT" or "_VBA_PROJECT_CUR" or "Macros" or "PROJECT")) ctx.Bad("Office", "Document contains VBA macro storage");
        if (names.Any(n => n.Contains("Ole10Native"))) ctx.Warn("Office", "Embedded OLE package (\\x01Ole10Native) – may carry a file/executable");
        if (Has("ObjectPool")) ctx.Info("Office", "Document contains embedded objects (ObjectPool)");

        // property sets
        foreach (var e in ents.Where(e => e.Path != null && e.Type == 2 && (e.Name == "\u0005SummaryInformation" || e.Name == "\u0005DocumentSummaryInformation")))
        {
            bool docsum = e.Name.Contains("Document");
            d.H(docsum ? "Document summary information" : "Summary information");
            PropSet(Read(e, 1 << 20), d, ctx, docsum, sub?.Contains("MSI") == true);
        }
        // Outlook MSG properties
        if (sub?.StartsWith("Outlook") == true)
        {
            d.H("Outlook message properties");
            var props = new (string id, string name)[] { ("0037", "Subject"), ("0C1A", "Sender name"), ("0C1F", "Sender e-mail"), ("5D01", "Sender SMTP"), ("0E04", "Display To"), ("0E03", "Display CC"), ("0E02", "Display BCC"), ("0039", "Client submit time"), ("1035", "Message-ID"), ("007D", "Transport headers"), ("1000", "Body") };
            foreach (var (pid, pn) in props)
            {
                var e = ents.FirstOrDefault(x => x.Path != null && x.Path.Count(c => c == '/') == 1 && x.Name.StartsWith("__substg1.0_" + pid));
                if (e == null) continue;
                var b = Read(e, 256 << 10);
                string v = e.Name.EndsWith("001F") ? Encoding.Unicode.GetString(b) : Encoding.Latin1.GetString(b);
                v = v.TrimEnd('\0');
                if (pn is "Body" or "Transport headers") { d.KV(pn, "", R.Str); d.Text(v, R.Str, "      ", pn == "Body" ? 60 : 80); }
                else d.KV(pn, v, R.Str);
                ctx.ExtraStrings.Add(v);
            }
            int att = ents.Count(x => x.Path != null && x.Name.StartsWith("__attach_version1.0_"));
            if (att > 0)
            {
                d.KV("Attachments", att, R.Warn);
                foreach (var a in ents.Where(x => x.Path != null && x.Path.Contains("__attach_version1.0_") && x.Name.StartsWith("__substg1.0_3707")))
                    d.KV("  Attachment name", Encoding.Unicode.GetString(Read(a, 4096)).TrimEnd('\0'), R.Warn);
            }
        }
        // VBA project source module names
        var dirStream = ents.FirstOrDefault(e => e.Path != null && e.Type == 2 && e.Name == "dir" && e.Path.Contains("/VBA/", StringComparison.OrdinalIgnoreCase));
        if (dirStream != null)
        {
            d.H("VBA project");
            var mods = ents.Where(e => e.Path != null && e.Type == 2 && e.Path.Contains("/VBA/", StringComparison.OrdinalIgnoreCase) && e.Name is not ("dir" or "_VBA_PROJECT") && !e.Name.StartsWith("__SRP_")).ToList();
            foreach (var m in mods) d.KV("Module stream", $"{m.Name}  ({m.Size:N0} bytes)", R.Bad);
            var src = VbaDecompress(Read(dirStream));
            if (src != null)
            {
                // walk modules: decompress each module's source using MODULEOFFSET from the dir stream
                foreach (var m in mods)
                {
                    var raw = Read(m);
                    string code = null;
                    for (int start = 0; start < raw.Length && start < 1 << 20; start++)
                    {
                        if (raw[start] != 1 || start + 3 > raw.Length) continue;
                        var dec = VbaDecompress(raw.AsSpan(start).ToArray());
                        if (dec == null || dec.Length < 10) continue;
                        string txt = Encoding.Latin1.GetString(dec);
                        if (txt.Contains("Attribute VB_")) { code = txt; break; }
                    }
                    if (code == null) continue;
                    d.Sub("Source of module " + m.Name);
                    d.Text(code, R.Str, "      ", 800);
                    ctx.ExtraStrings.AddRange(code.Split('\n'));
                }
            }
        }
    }

    static string Visible(string s) => new string(s.Select(c => c < 0x20 ? '¤' : c).ToArray());

    static void PropSet(byte[] b, Doc d, Ctx ctx, bool docsum, bool msi)
    {
        if (b.Length < 48) return;
        int secOff = BitConverter.ToInt32(b, 44);
        if (secOff <= 0 || secOff + 8 > b.Length) return;
        int n = BitConverter.ToInt32(b, secOff + 4);
        var names = docsum
            ? new Dictionary<int, string> { [2] = "Category", [3] = "Presentation target", [4] = "Bytes", [5] = "Lines", [6] = "Paragraphs", [7] = "Slides", [8] = "Notes", [9] = "Hidden slides", [10] = "MM clips", [11] = "Scale crop", [14] = "Manager", [15] = "Company", [16] = "Links dirty", [17] = "Characters (w/ spaces)", [19] = "Shared doc", [22] = "Hyperlinks changed", [23] = "App version" }
            : new Dictionary<int, string> { [1] = "Code page", [2] = "Title", [3] = "Subject", [4] = "Author", [5] = "Keywords", [6] = "Comments", [7] = msi ? "Template (platform;language)" : "Template", [8] = "Last saved by", [9] = msi ? "Package code (revision)" : "Revision number", [10] = "Total editing time", [11] = "Last printed", [12] = "Created", [13] = "Last saved", [14] = msi ? "Schema (page count)" : "Page count", [15] = msi ? "Source flags (word count)" : "Word count", [16] = "Character count", [18] = "Application name", [19] = "Security" };
        int cp = 1252;
        for (int i = 0; i < Math.Min(n, 200); i++)
        {
            int po = secOff + 8 + i * 8;
            if (po + 8 > b.Length) break;
            int pid = BitConverter.ToInt32(b, po), off = secOff + BitConverter.ToInt32(b, po + 4);
            if (off + 4 > b.Length) continue;
            int vt = BitConverter.ToUInt16(b, off);
            string val = null;
            try
            {
                switch (vt)
                {
                    case 2: val = BitConverter.ToInt16(b, off + 4).ToString(); if (pid == 1) cp = (ushort)BitConverter.ToInt16(b, off + 4); break;
                    case 3: val = BitConverter.ToInt32(b, off + 4).ToString(); break;
                    case 11: val = BitConverter.ToInt16(b, off + 4) != 0 ? "true" : "false"; break;
                    case 0x1E:
                        int len = BitConverter.ToInt32(b, off + 4);
                        Encoding enc; try { enc = cp == 1200 ? Encoding.Unicode : Encoding.GetEncoding(cp); } catch { enc = Encoding.Latin1; }
                        val = enc.GetString(b, off + 8, Math.Clamp(len, 0, b.Length - off - 8)).TrimEnd('\0'); break;
                    case 0x1F: int wl = BitConverter.ToInt32(b, off + 4); val = Encoding.Unicode.GetString(b, off + 8, Math.Clamp(wl * 2, 0, b.Length - off - 8)).TrimEnd('\0'); break;
                    case 0x40:
                        long ft = BitConverter.ToInt64(b, off + 4);
                        val = pid == 10 && !docsum ? TimeSpan.FromTicks(ft).ToString() : Fmt.FileTime(ft); break;
                }
            }
            catch { }
            if (val == null) continue;
            d.KV(names.TryGetValue(pid, out var nm) ? nm : $"Property {pid}", val, R.Str);
            if (vt is 0x1E or 0x1F) ctx.ExtraStrings.Add(val);
            if (!docsum && pid is 4 or 8 && val.Length > 0) ctx.Info("Metadata", (pid == 4 ? "Author: " : "Last saved by: ") + val);
        }
    }

    /// <summary>MS-OVBA RLE decompression.</summary>
    public static byte[] VbaDecompress(byte[] c)
    {
        try
        {
            if (c.Length < 3 || c[0] != 1) return null;
            var o = new List<byte>(c.Length * 3);
            int p = 1;
            while (p + 2 <= c.Length)
            {
                int hdr = c[p] | c[p + 1] << 8;
                int size = (hdr & 0xFFF) + 3;
                bool comp = (hdr & 0x8000) != 0;
                if ((hdr >> 12 & 7) != 3) return o.Count > 0 ? o.ToArray() : null;
                int end = Math.Min(c.Length, p + size);
                p += 2;
                int dstart = o.Count;
                if (!comp) { for (int i = 0; i < 4096 && p < end; i++) o.Add(c[p++]); continue; }
                while (p < end)
                {
                    byte flags = c[p++];
                    for (int bit = 0; bit < 8 && p < end; bit++)
                    {
                        if ((flags & (1 << bit)) == 0) { o.Add(c[p++]); continue; }
                        if (p + 1 >= end) { p = end; break; }
                        int tok = c[p] | c[p + 1] << 8; p += 2;
                        int dlen = o.Count - dstart;
                        int bits = Math.Max(4, (int)Math.Ceiling(Math.Log2(Math.Max(dlen, 1))));
                        int lenMask = 0xFFFF >> bits;
                        int len = (tok & lenMask) + 3, off = (tok >> (16 - bits)) + 1;
                        if (off > o.Count) return o.ToArray();
                        int from = o.Count - off;
                        for (int k = 0; k < len; k++) o.Add(o[from + k]);
                    }
                }
                if (o.Count > 32 << 20) break;
            }
            return o.ToArray();
        }
        catch { return null; }
    }
}

public static class LnkParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        uint flags = s.U32(20);
        d.H("Shell link header");
        d.KV("Link flags", Fmt.Hx(flags, 8) + "  " + Fmt.Flags(flags, new (ulong, string)[] { (1, "HasTargetIDList"), (2, "HasLinkInfo"), (4, "HasName"), (8, "HasRelativePath"), (0x10, "HasWorkingDir"), (0x20, "HasArguments"), (0x40, "HasIconLocation"), (0x80, "IsUnicode"), (0x100, "ForceNoLinkInfo"), (0x200, "HasExpString"), (0x400, "RunInSeparateProcess"), (0x1000, "HasDarwinID"), (0x2000, "RunAsUser"), (0x4000, "HasExpIcon"), (0x8000, "NoPidlAlias"), (0x20000, "RunWithShimLayer"), (0x40000, "ForceNoLinkTrack"), (0x80000, "EnableTargetMetadata") }), R.Value, 20);
        d.KV("Target attributes", Fmt.Hx(s.U32(24), 8) + "  " + (FileAttributes)s.U32(24), R.Value, 24);
        d.KV("Target created", Fmt.FileTime(s.I64(28)), R.Value, 28);
        d.KV("Target accessed", Fmt.FileTime(s.I64(36)), R.Value, 36);
        d.KV("Target modified", Fmt.FileTime(s.I64(44)), R.Value, 44);
        d.KV("Target size", Fmt.Size(s.U32(52)), R.Num, 52);
        d.KV("Icon index", s.I32(56), R.Num, 56);
        uint show = s.U32(60);
        d.KV("Show command", show switch { 1 => "SW_SHOWNORMAL", 3 => "SW_SHOWMAXIMIZED", 7 => "SW_SHOWMINNOACTIVE (hidden-ish window)", _ => show.ToString() }, show == 7 ? R.Warn : R.Value, 60);
        ushort hk = s.U16(64);
        if (hk != 0) d.KV("Hot key", Fmt.Hx(hk, 4), R.Value, 64);
        if (s.U32(24) is var att && (att & 0x10) != 0) { }
        bool uni = (flags & 0x80) != 0;
        long p = 76;
        if ((flags & 1) != 0)
        {
            ushort idl = s.U16(p);
            d.H($"Target ID list ({idl} bytes)");
            long q = p + 2, end = p + 2 + idl;
            while (q + 2 <= end)
            {
                ushort sz = s.U16(q);
                if (sz == 0) break;
                byte type = s.U8(q + 2);
                string desc = (type & 0x70) switch
                {
                    0x10 => "root: " + RootGuid(Fmt.Guid(s.Bytes(q + 4, 16))),
                    0x20 => "volume: " + s.Ascii(q + 3, 32),
                    0x30 => "file entry: " + s.Ascii(q + 14, Math.Max(0, sz - 14)) + LongName(s, q, sz),
                    0x40 => "network: " + s.Ascii(q + 5, Math.Max(0, sz - 5)),
                    _ => $"item type {Fmt.Hx(type, 2)}"
                };
                d.T($"    {Fmt.Hx(q, 6)}  {desc}", R.Str, q);
                q += sz;
            }
            p = end;
        }
        if ((flags & 2) != 0 && s.Has(p, 28))
        {
            uint size = s.U32(p), hsize = s.U32(p + 4), lf = s.U32(p + 8);
            d.H("Link info");
            if ((lf & 1) != 0)
            {
                long vid = p + s.U32(p + 12);
                uint dt = s.U32(vid + 4);
                d.KV("Drive type", dt switch { 2 => "removable", 3 => "fixed", 4 => "network", 5 => "CD-ROM", 6 => "RAM disk", _ => dt.ToString() }, R.Value, vid);
                d.KV("Volume serial", s.U32(vid + 8).ToString("X8"), R.Hex, vid + 8);
                uint lo = s.U32(vid + 12);
                d.KV("Volume label", lo == 0x14 ? s.Utf16Z(vid + s.U32(vid + 16), 64) : s.Ascii(vid + lo, 64), R.Str);
                string lbp = s.Ascii(p + s.U32(p + 16), 1024);
                if (hsize >= 0x24 && s.U32(p + 28) != 0) lbp = s.Utf16Z(p + s.U32(p + 28), 1024);
                d.KV("Local base path", lbp, R.Accent, p + s.U32(p + 16));
                ctx.Info("LNK", "Target: " + lbp);
                ctx.ExtraStrings.Add(lbp);
            }
            if ((lf & 2) != 0)
            {
                long cn = p + s.U32(p + 20);
                d.KV("Network share", s.Ascii(cn + s.U32(cn + 8), 512), R.Accent, cn);
                if (s.U32(cn + 12) != 0) d.KV("Device", s.Ascii(cn + s.U32(cn + 12), 64), R.Str);
            }
            string suffix = s.Ascii(p + s.U32(p + 24), 512);
            if (suffix.Length > 0) d.KV("Path suffix", suffix, R.Str);
            p += size;
        }
        d.H("String data");
        string[] labels = { "Name / description", "Relative path", "Working directory", "Command-line arguments", "Icon location" };
        uint[] bits = { 4, 8, 0x10, 0x20, 0x40 };
        for (int i = 0; i < 5; i++)
        {
            if ((flags & bits[i]) == 0) continue;
            int cnt = s.U16(p);
            string v = uni ? s.Utf16(p + 2, cnt) : s.Fixed(p + 2, cnt);
            bool args = i == 3;
            d.KV(labels[i], v, args ? R.Warn : R.Str, p + 2);
            ctx.ExtraStrings.Add(v);
            if (args)
            {
                string lv = v.ToLowerInvariant();
                if (Regex.IsMatch(lv, @"powershell|cmd(\.exe)?\s*/c|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|http[s]?://|frombase64|-enc|iex|curl|msiexec"))
                    ctx.Bad("LNK", "Shortcut arguments launch a script/LOLBin: " + Fmt.Trunc(v.Trim(), 200), p + 2);
                else if (v.Length > 0) ctx.Info("LNK", "Arguments: " + Fmt.Trunc(v.Trim(), 200), p + 2);
                if (v.Length > 250 && v.TrimStart().Length < v.Length - 100) ctx.Warn("LNK", "Arguments are padded with whitespace to hide them in the Properties dialog");
            }
            if (i == 4 && Regex.IsMatch(v, @"\.(pdf|docx?|xlsx?|txt|jpg)$", RegexOptions.IgnoreCase) && (flags & 0x20) != 0)
                ctx.Warn("LNK", "Icon borrowed from a document type while the shortcut runs a command (disguise)");
            p += 2 + (uni ? cnt * 2 : cnt);
        }
        d.H("Extra data blocks");
        for (int i = 0; i < 64 && s.Has(p, 8); i++)
        {
            uint size = s.U32(p);
            if (size < 8) break;
            uint sig = s.U32(p + 4);
            switch (sig)
            {
                case 0xA0000001:
                    d.KV("Environment target", s.Ascii(p + 8, 260) is { Length: > 0 } a ? a : s.Utf16Z(p + 268, 260), R.Accent, p); break;
                case 0xA0000003:
                    d.KV("Tracker: machine ID", s.Ascii(p + 16, 16), R.Warn, p + 16);
                    var droid = s.Bytes(p + 48, 16);
                    d.KV("Tracker: file droid", Fmt.Guid(droid), R.Value);
                    if ((droid[7] >> 4) == 1) d.KV("Tracker: MAC address", string.Join(":", droid.Skip(10).Take(6).Select(x => x.ToString("x2"))), R.Warn);
                    ctx.Info("LNK", "Created on machine: " + s.Ascii(p + 16, 16));
                    break;
                case 0xA0000002: d.KV("Console properties", $"{size} bytes", R.Value, p); break;
                case 0xA0000004: d.KV("Console code page", s.U32(p + 8), R.Value, p); break;
                case 0xA0000005: d.KV("Special folder", $"ID {s.U32(p + 8)}", R.Value, p); break;
                case 0xA0000006: d.KV("Darwin (MSI) ID", s.Utf16Z(p + 268, 260), R.Str, p); break;
                case 0xA0000007: d.KV("Icon environment", s.Ascii(p + 8, 260), R.Str, p); break;
                case 0xA0000008: d.KV("Shim layer", s.Utf16Z(p + 8, 260), R.Warn, p); break;
                case 0xA0000009: d.KV("Property store", $"{size} bytes", R.Value, p); break;
                case 0xA000000B: d.KV("Known folder", Fmt.Guid(s.Bytes(p + 8, 16)), R.Value, p); break;
                case 0xA000000C: d.KV("Vista+ ID list", $"{size} bytes", R.Value, p); break;
                default: d.KV("Block " + Fmt.Hx(sig, 8), $"{size} bytes", R.Dim, p); break;
            }
            p += size;
        }
        if (p + 4 < s.Length && s.Length - p > 16) ctx.Warn("LNK", $"{Fmt.Human(s.Length - p)} of data appended after the shortcut structure", p);
    }

    static string LongName(ByteSource s, long q, int sz)
    {
        var b = s.Bytes(q, sz);
        int i = b.AsSpan().IndexOf(new byte[] { 0x04, 0x00, 0xEF, 0xBE });
        if (i < 4) return "";
        int ver = BitConverter.ToUInt16(b, i - 2);
        int nameOff = i - 4 + (ver >= 7 ? 46 : ver >= 3 ? 20 : 18);
        if (nameOff >= b.Length) return "";
        int e = nameOff;
        while (e + 1 < b.Length && (b[e] | b[e + 1]) != 0) e += 2;
        string ln = Encoding.Unicode.GetString(b, nameOff, e - nameOff);
        return ln.Length > 0 ? "  (long name: " + ln + ")" : "";
    }

    static string RootGuid(string g) => g switch
    {
        "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" => "My Computer " + g,
        "{59031A47-3F72-44A7-89C5-5595FE6B30EE}" => "User profile " + g,
        "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" => "Network " + g,
        "{21EC2020-3AEA-1069-A2DD-08002B30309D}" => "Control Panel " + g,
        _ => g
    };
}

public static class SqliteParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        int ps = s.U16(16, true); if (ps == 1) ps = 65536;
        d.H("SQLite database header");
        d.KV("Page size", ps, R.Num, 16);
        d.KV("Write / read version", $"{s.U8(18)} / {s.U8(19)}  ({(s.U8(18) == 2 ? "WAL" : "rollback journal")})", R.Value, 18);
        d.KV("Reserved bytes per page", s.U8(20), R.Num, 20);
        d.KV("File change counter", s.U32(24, true), R.Num, 24);
        uint pages = s.U32(28, true);
        d.KV("Database size (pages)", $"{pages:N0}  ({Fmt.Human((double)pages * ps)})", R.Num, 28);
        d.KV("Freelist pages", s.U32(36, true), R.Num, 36);
        d.KV("Schema cookie / format", $"{s.U32(40, true)} / {s.U32(44, true)}", R.Num, 40);
        d.KV("Text encoding", s.U32(56, true) switch { 1 => "UTF-8", 2 => "UTF-16le", 3 => "UTF-16be", var x => x.ToString() }, R.Value, 56);
        d.KV("User version", s.U32(60, true), R.Num, 60);
        d.KV("Application ID", Fmt.Hx(s.U32(68, true), 8), R.Num, 68);
        uint lib = s.U32(96, true);
        d.KV("Written by SQLite", $"{lib / 1000000}.{lib / 1000 % 1000}.{lib % 1000}", R.Value, 96);
        if (s.U32(36, true) > 0) ctx.Info("SQLite", $"{s.U32(36, true)} free page(s) – deleted records may be recoverable");

        int usable = ps - s.U8(20);
        var rows = new List<string[]>();
        int visited = 0;
        void Page(uint no, int depth, Action<byte[]> onRecord)
        {
            if (no == 0 || depth > 20 || ++visited > 20000) return;
            long po = (long)(no - 1) * ps;
            long h = po + (no == 1 ? 100 : 0);
            if (!s.Has(h, 8)) return;
            byte type = s.U8(h);
            int cells = s.U16(h + 3, true);
            bool interior = type == 5;
            long ptrs = h + (interior ? 12 : 8);
            for (int i = 0; i < Math.Min(cells, 5000); i++)
            {
                long c = po + s.U16(ptrs + i * 2, true);
                if (interior) { Page(s.U32(c, true), depth + 1, onRecord); continue; }
                if (type != 0x0D) continue;
                long q = c;
                long plen = Varint(s, ref q); Varint(s, ref q);
                int x = usable - 35;
                long local = plen;
                if (plen > x)
                {
                    int m = (usable - 12) * 32 / 255 - 23;
                    long k = m + (plen - m) % (usable - 4);
                    local = k <= x ? k : m;
                }
                var ms = new MemoryStream();
                ms.Write(s.Bytes(q, local));
                if (local < plen)
                {
                    uint ov = s.U32(q + local, true); int g = 0;
                    while (ov != 0 && ms.Length < plen && g++ < 1000) { long oo = (long)(ov - 1) * ps; ms.Write(s.Bytes(oo + 4, Math.Min(usable - 4, plen - ms.Length))); ov = s.U32(oo, true); }
                }
                onRecord(ms.ToArray());
            }
            if (interior) Page(s.U32(h + 8, true), depth + 1, onRecord);
        }
        var enc = s.U32(56, true) switch { 2 => Encoding.Unicode, 3 => Encoding.BigEndianUnicode, _ => Encoding.UTF8 };
        Page(1, 0, rec => rows.Add(Record(rec, enc)));
        d.H($"Schema (sqlite_master) – {rows.Count} objects");
        foreach (var r in rows.Where(r => r.Length >= 5))
        {
            long count = -1;
            if (r[0] == "table" && uint.TryParse(r[3], out uint root) && root > 0)
            {
                long n = 0; visited = 0;
                Page(root, 0, _ => n++);
                count = n;
            }
            d.Sub($"{r[0]} {r[1]}" + (count >= 0 ? $"   ({count:N0} rows{(visited > 20000 ? "+" : "")})" : ""), (long)((uint.TryParse(r[3], out uint rp) && rp > 0 ? rp - 1 : 0) * (long)ps));
            if (!string.IsNullOrEmpty(r[4])) d.Text(r[4], R.Str, "      ", 30);
        }
    }

    static long Varint(ByteSource s, ref long p)
    {
        long v = 0;
        for (int i = 0; i < 9; i++)
        {
            byte b = s.U8(p++);
            if (i == 8) return v << 8 | b;
            v = v << 7 | (long)(b & 0x7F);
            if ((b & 0x80) == 0) break;
        }
        return v;
    }

    static string[] Record(byte[] b, Encoding enc)
    {
        try
        {
            int p = 0;
            long V() { long v = 0; for (int i = 0; i < 9; i++) { byte x = b[p++]; if (i == 8) return v << 8 | x; v = v << 7 | (long)(x & 0x7F); if ((x & 0x80) == 0) break; } return v; }
            long hl = V();
            var types = new List<long>();
            while (p < hl) types.Add(V());
            p = (int)hl;
            var r = new string[types.Count];
            for (int i = 0; i < types.Count; i++)
            {
                long t = types[i];
                int n = t switch { 0 or 8 or 9 => 0, 1 => 1, 2 => 2, 3 => 3, 4 => 4, 5 => 6, 6 or 7 => 8, _ => t >= 12 ? (int)((t - (t % 2 == 0 ? 12 : 13)) / 2) : 0 };
                if (p + n > b.Length) n = Math.Max(0, b.Length - p);
                if (t >= 13 && t % 2 == 1) r[i] = enc.GetString(b, p, n);
                else if (t is >= 1 and <= 6) { long v = 0; for (int k = 0; k < n; k++) v = v << 8 | b[p + k]; r[i] = v.ToString(); }
                else if (t == 8) r[i] = "0"; else if (t == 9) r[i] = "1";
                else r[i] = "";
                p += n;
            }
            return r;
        }
        catch { return Array.Empty<string>(); }
    }
}
