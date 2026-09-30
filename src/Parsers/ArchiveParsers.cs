using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using Ufi.Core;

namespace Ufi.Parsers;

public static class ZipParser
{
    sealed class Entry
    {
        public string Name; public ushort Method, Flags, Time, Date, VerMade; public uint Crc; public long CSize, USize, LocalOff; public uint ExtAttr; public string Comment; public long CdOff;
    }

    static readonly Dictionary<ushort, string> Methods = new()
    {
        [0] = "Stored", [1] = "Shrunk", [6] = "Imploded", [8] = "Deflate", [9] = "Deflate64", [12] = "BZIP2", [14] = "LZMA", [19] = "LZ77", [93] = "Zstd", [95] = "XZ", [96] = "JPEG", [97] = "WavPack", [98] = "PPMd", [99] = "AES-encrypted",
    };

    static readonly string[] RiskyExt = { ".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".msi", ".jar", ".iso", ".img", ".vhd", ".cpl", ".reg", ".url", ".chm", ".xll", ".one", ".application", ".appref-ms", ".library-ms", ".sys", ".msc" };

    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        // locate EOCD
        long scanStart = Math.Max(0, s.Length - 65557);
        var tail = s.Bytes(scanStart, s.Length - scanStart);
        int eo = tail.AsSpan().LastIndexOf("PK\x05\x06"u8);
        var entries = new List<Entry>();
        d.H("ZIP end of central directory");
        if (eo < 0)
        {
            d.Warn("End-of-central-directory record not found (truncated, or not a standard ZIP). Walking local headers instead.");
            WalkLocal(s, entries);
        }
        else
        {
            long e = scanStart + eo;
            long cdOff = s.U32(e + 16), cdSize = s.U32(e + 12);
            long total = s.U16(e + 10);
            ushort clen = s.U16(e + 20);
            d.KV("EOCD offset", Fmt.Hx(e), R.Offset, e);
            d.KV("Disk number / CD disk", $"{s.U16(e + 4)} / {s.U16(e + 6)}", R.Num);
            d.KV("Entries (total)", total, R.Num);
            d.KV("Central directory", $"offset {Fmt.Hx(cdOff)} size {Fmt.Size(cdSize)}", R.Num, cdOff);
            if (e >= 20 && s.Match(e - 20, "PK\x06\x07"))
            {
                long z64 = (long)s.U64(e - 20 + 8);
                if (s.Match(z64, "PK\x06\x06"))
                {
                    total = (long)s.U64(z64 + 32); cdSize = (long)s.U64(z64 + 40); cdOff = (long)s.U64(z64 + 48);
                    d.KV("ZIP64", $"yes – entries {total:N0}, CD at {Fmt.Hx(cdOff)}", R.Accent, z64);
                }
            }
            if (clen > 0) d.KV("Archive comment", s.Fixed(e + 22, clen), R.Str, e + 22);
            long prefix = e - cdSize - cdOff;
            if (prefix > 0) { d.KV("Prepended data", Fmt.Size(prefix) + " before the archive (SFX stub / polyglot?)", R.Warn); ctx.Warn("ZIP", $"{Fmt.Human(prefix)} of data precede the ZIP archive (self-extractor or polyglot file)"); }
            else prefix = 0;
            long trailing = s.Length - (e + 22 + clen);
            if (trailing > 0) { d.KV("Trailing data", Fmt.Size(trailing) + " after the archive", R.Warn); ctx.Warn("ZIP", $"{Fmt.Human(trailing)} of data appended after the ZIP end record", e + 22 + clen); }

            long p = cdOff + prefix;
            for (long i = 0; i < Math.Min(total, 200000) && s.Has(p, 46) && s.Match(p, "PK\x01\x02"); i++)
            {
                var en = new Entry
                {
                    CdOff = p, VerMade = s.U16(p + 4), Flags = s.U16(p + 8), Method = s.U16(p + 10), Time = s.U16(p + 12), Date = s.U16(p + 14), Crc = s.U32(p + 16),
                    CSize = s.U32(p + 20), USize = s.U32(p + 24), ExtAttr = s.U32(p + 38), LocalOff = s.U32(p + 42) + prefix
                };
                int nl = s.U16(p + 28), xl = s.U16(p + 30), cl = s.U16(p + 32);
                var nb = s.Bytes(p + 46, nl);
                en.Name = (en.Flags & 0x800) != 0 ? Encoding.UTF8.GetString(nb) : Encoding.GetEncoding(437).GetString(nb);
                // zip64 extra
                long x = p + 46 + nl, xe = x + xl;
                while (x + 4 <= xe)
                {
                    ushort id = s.U16(x), sz = s.U16(x + 2);
                    if (id == 1)
                    {
                        long q = x + 4;
                        if (en.USize == 0xFFFFFFFF && q + 8 <= x + 4 + sz) { en.USize = (long)s.U64(q); q += 8; }
                        if (en.CSize == 0xFFFFFFFF && q + 8 <= x + 4 + sz) { en.CSize = (long)s.U64(q); q += 8; }
                        if (s.U32(p + 42) == 0xFFFFFFFF && q + 8 <= x + 4 + sz) { en.LocalOff = (long)s.U64(q) + prefix; }
                    }
                    if (id == 0x9901) en.Method = 99;
                    x += 4 + sz;
                }
                if (cl > 0) en.Comment = s.Fixed(p + 46 + nl + xl, cl);
                entries.Add(en);
                p += 46 + nl + xl + cl;
            }
        }

        // ---- sub-type detection
        var names = entries.Select(e => e.Name).ToList();
        bool Has(string n) => names.Any(x => x.Equals(n, StringComparison.OrdinalIgnoreCase));
        bool Starts(string n) => names.Any(x => x.StartsWith(n, StringComparison.OrdinalIgnoreCase));
        string sub = null; string[] exts = null;
        if (Has("[Content_Types].xml"))
        {
            if (Starts("word/")) (sub, exts) = ("Microsoft Word document (OOXML)", new[] { "docx", "docm", "dotx", "dotm" });
            else if (Starts("xl/")) (sub, exts) = ("Microsoft Excel workbook (OOXML)", new[] { "xlsx", "xlsm", "xltx", "xltm", "xlsb", "xlam" });
            else if (Starts("ppt/")) (sub, exts) = ("Microsoft PowerPoint presentation (OOXML)", new[] { "pptx", "pptm", "potx", "ppsx", "ppsm" });
            else if (Starts("visio/")) (sub, exts) = ("Microsoft Visio drawing (OOXML)", new[] { "vsdx", "vsdm" });
            else if (Has("AppxManifest.xml") || Has("AppxMetadata/AppxBundleManifest.xml")) (sub, exts) = ("Windows app package (APPX/MSIX)", new[] { "appx", "msix", "appxbundle", "msixbundle" });
            else if (names.Any(n => n.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase))) (sub, exts) = ("NuGet package", new[] { "nupkg", "snupkg" });
            else if (Has("extension.vsixmanifest")) (sub, exts) = ("Visual Studio extension (VSIX)", new[] { "vsix" });
            else (sub, exts) = ("Open Packaging Convention package", new[] { "zip" });
        }
        else if (Has("AndroidManifest.xml") && Has("classes.dex")) (sub, exts) = ("Android application package (APK)", new[] { "apk", "apks", "xapk" });
        else if (Has("AndroidManifest.xml")) (sub, exts) = ("Android library / bundle", new[] { "aar", "aab", "apk" });
        else if (Starts("Payload/") && names.Any(n => n.Contains(".app/"))) (sub, exts) = ("iOS application (IPA)", new[] { "ipa" });
        else if (Has("META-INF/MANIFEST.MF") || names.Any(n => n.EndsWith(".class"))) (sub, exts) = ("Java archive (JAR)", new[] { "jar", "war", "ear", "jmod" });
        else if (Has("manifest.json") && names.Any(n => n.EndsWith(".js"))) (sub, exts) = ("Browser extension (ZIP)", new[] { "xpi", "crx", "zip" });
        else if (Has("doc.kml")) (sub, exts) = ("Google Earth KMZ", new[] { "kmz" });
        else if (Has("3D/3dmodel.model")) (sub, exts) = ("3D Manufacturing Format (3MF)", new[] { "3mf" });
        else if (names.Any(n => n.EndsWith(".dist-info/WHEEL"))) (sub, exts) = ("Python wheel", new[] { "whl" });
        var mt = entries.FirstOrDefault(e => e.Name == "mimetype");
        if (mt != null && mt.Method == 0 && mt.USize < 200)
        {
            string mime = Encoding.ASCII.GetString(s.Bytes(DataOffset(s, mt), mt.USize));
            sub = mime switch
            {
                "application/epub+zip" => "EPUB e-book",
                "application/vnd.oasis.opendocument.text" => "OpenDocument text (ODT)",
                "application/vnd.oasis.opendocument.spreadsheet" => "OpenDocument spreadsheet (ODS)",
                "application/vnd.oasis.opendocument.presentation" => "OpenDocument presentation (ODP)",
                "application/vnd.oasis.opendocument.graphics" => "OpenDocument drawing (ODG)",
                _ => "ZIP container, mimetype " + mime
            };
            exts = mime switch { "application/epub+zip" => new[] { "epub" }, _ when mime.Contains("opendocument") => new[] { "odt", "ods", "odp", "odg", "ott", "ots" }, _ => exts };
        }
        if (sub != null)
        {
            var rt = ctx.Refined ?? new FileType();
            rt.Name = sub; if (exts != null) rt.Exts = exts; rt.Category = sub.Contains("document") || sub.Contains("workbook") || sub.Contains("presentation") || sub.Contains("book") ? "Document" : rt.Category;
            ctx.Refined = rt;
            d.KV("Container type", sub, R.Accent);
        }

        // ---- risk checks
        long totalU = entries.Sum(e => e.USize), totalC = entries.Sum(e => e.CSize);
        if (names.Any(n => n.Contains("vbaProject.bin", StringComparison.OrdinalIgnoreCase))) ctx.Bad("Office", "Document contains VBA macros (vbaProject.bin)");
        if (Starts("xl/macrosheets/")) ctx.Bad("Office", "Workbook contains Excel 4.0 (XLM) macro sheets");
        if (names.Any(n => n.Contains("/embeddings/", StringComparison.OrdinalIgnoreCase))) ctx.Warn("Office", "Document contains embedded OLE objects / files");
        if (names.Any(n => n.Contains("activeX", StringComparison.OrdinalIgnoreCase))) ctx.Warn("Office", "Document contains ActiveX controls");
        if (entries.Any(e => (e.Flags & 1) != 0)) ctx.Warn("ZIP", $"{entries.Count(e => (e.Flags & 1) != 0)} encrypted entr(y/ies) – content cannot be inspected without the password");
        foreach (var e in entries)
        {
            string n = e.Name.Replace('\\', '/');
            if (n.StartsWith("/") || n.Contains("../") || (n.Length > 1 && n[1] == ':')) ctx.Bad("ZIP", $"Path traversal / absolute path in entry name: {e.Name}", e.CdOff);
            string ln = n.ToLowerInvariant();
            var ext = RiskyExt.FirstOrDefault(x => ln.EndsWith(x));
            if (ext != null && sub?.Contains("Java") != true && sub?.Contains("Android") != true) ctx.Warn("ZIP", $"Archive contains potentially executable file: {e.Name}", e.LocalOff);
            if (Regex.IsMatch(ln, @"\.(pdf|docx?|xlsx?|jpg|png|txt)\s*\.(exe|scr|js|vbs|bat|cmd|lnk|hta)$")) ctx.Bad("ZIP", $"Double extension in entry name: {e.Name}", e.LocalOff);
            if (e.CSize > 0 && e.USize / Math.Max(1, e.CSize) > 200 && e.USize > 50 << 20) ctx.Warn("ZIP", $"Extreme compression ratio {e.USize / Math.Max(1, e.CSize)}:1 for {e.Name} (zip bomb?)");
        }
        if (totalU > 8L << 30 && totalC < totalU / 100) ctx.Bad("ZIP", $"Declared uncompressed size {Fmt.Human(totalU)} from {Fmt.Human(totalC)} – likely a zip bomb");

        // ---- entry table
        d.H($"Entries ({entries.Count:N0})");
        d.KV("Total compressed", Fmt.Size(totalC), R.Num);
        d.KV("Total uncompressed", Fmt.Size(totalU), R.Num);
        d.Th(new C("Method", 9), new C("Packed", 11, R.Dim, true), new C("Size", 11, R.Dim, true), new C("Ratio", 6, R.Dim, true), new C("Modified", 19), new C("CRC32", 8), new C("Fl", 3), new C("Name", 60));
        foreach (var e in entries.Take(50000))
        {
            string ratio = e.USize > 0 ? (100.0 - e.CSize * 100.0 / e.USize).ToString("0") + "%" : "";
            string fl = ((e.Flags & 1) != 0 ? "E" : "") + ((e.Flags & 8) != 0 ? "D" : "") + ((e.Flags & 0x800) != 0 ? "U" : "");
            bool dir = e.Name.EndsWith("/");
            d.Tr(e.LocalOff, new C(Fmt.Lookup(Methods, e.Method, e.Method.ToString()), 9, R.Key), new C(e.CSize.ToString("N0"), 11, R.Num, true),
                new C(e.USize.ToString("N0"), 11, R.Num, true), new C(ratio, 6, R.Dim, true), new C(Fmt.DosDateTime(e.Date, e.Time), 19, R.Value),
                new C(e.Crc.ToString("x8"), 8, R.Hex), new C(fl, 3, (e.Flags & 1) != 0 ? R.Warn : R.Dim), new C(e.Name, 60, dir ? R.Accent : R.Str));
            if (!string.IsNullOrEmpty(e.Comment)) d.T("        comment: " + e.Comment, R.Dim);
        }
        if (entries.Count > 50000) d.T($"  … {entries.Count - 50000:N0} more entries", R.Dim);
        d.T("  Flags: E = encrypted, D = data descriptor, U = UTF-8 name.  Enter on a row jumps to its local header.", R.Dim);

        // ---- metadata of OOXML / ODF / JAR
        string Read(string name, int max = 4 << 20)
        {
            var en = entries.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (en == null) return null;
            var b = Extract(s, en, max);
            return b == null ? null : Encoding.UTF8.GetString(b);
        }
        foreach (var metaName in new[] { "docProps/core.xml", "docProps/app.xml", "meta.xml" })
        {
            string xml = Read(metaName);
            if (xml == null) continue;
            d.H("Document metadata: " + metaName);
            foreach (Match m in Regex.Matches(xml, @"<(?:[\w]+:)?(\w+)(?:\s[^>]*)?>([^<]{1,500})</"))
            {
                d.KV(m.Groups[1].Value, System.Net.WebUtility.HtmlDecode(m.Groups[2].Value), R.Str);
                ctx.ExtraStrings.Add(m.Groups[2].Value);
            }
        }
        foreach (var rel in entries.Where(e => e.Name.EndsWith(".rels", StringComparison.OrdinalIgnoreCase) && e.USize < 4 << 20).Take(200))
        {
            string xml = Read(rel.Name);
            if (xml == null) continue;
            foreach (Match m in Regex.Matches(xml, @"<Relationship\b[^>]*>"))
            {
                string tag = m.Value;
                if (!tag.Contains("TargetMode=\"External\"")) continue;
                var tgt = Regex.Match(tag, "Target=\"([^\"]*)\"").Groups[1].Value;
                var type = Regex.Match(tag, "Type=\"[^\"]*/([^\"/]*)\"").Groups[1].Value;
                tgt = System.Net.WebUtility.HtmlDecode(tgt);
                ctx.ExtraStrings.Add(tgt);
                if (type is "attachedTemplate" or "oleObject" or "frame" or "subDocument")
                    ctx.Bad("Office", $"External {type} relationship → {tgt} (remote template / object injection)", rel.LocalOff);
                else ctx.Info("Office", $"External link ({type}) → {tgt}", rel.LocalOff);
            }
        }
        string mf = Read("META-INF/MANIFEST.MF", 256 << 10);
        if (mf != null) { d.H("JAR manifest (META-INF/MANIFEST.MF)"); d.Text(mf, R.Str, "    ", 200); }
        string sheet = Read("xl/workbook.xml");
        if (sheet != null)
        {
            var hidden = Regex.Matches(sheet, "<sheet [^>]*state=\"(hidden|veryHidden)\"[^>]*name=\"([^\"]*)\"|<sheet [^>]*name=\"([^\"]*)\"[^>]*state=\"(hidden|veryHidden)\"");
            foreach (Match h in hidden) ctx.Warn("Office", $"Workbook has a {h.Groups[1].Value + h.Groups[4].Value} sheet: {h.Groups[2].Value + h.Groups[3].Value}");
        }
    }

    static long DataOffset(ByteSource s, Entry e)
    {
        if (!s.Match(e.LocalOff, "PK\x03\x04")) return -1;
        return e.LocalOff + 30 + s.U16(e.LocalOff + 26) + s.U16(e.LocalOff + 28);
    }

    static byte[] Extract(ByteSource s, Entry e, int max)
    {
        try
        {
            if ((e.Flags & 1) != 0 || e.CSize > 16 << 20) return null;
            long o = DataOffset(s, e);
            if (o < 0) return null;
            if (e.Method == 0) return s.Bytes(o, Math.Min(e.CSize, max));
            if (e.Method != 8) return null;
            using var ds = new DeflateStream(s.OpenStream(o, e.CSize), CompressionMode.Decompress);
            var ms = new MemoryStream();
            var buf = new byte[81920];
            int n;
            while ((n = ds.Read(buf)) > 0 && ms.Length < max) ms.Write(buf, 0, n);
            return ms.ToArray();
        }
        catch { return null; }
    }

    static void WalkLocal(ByteSource s, List<Entry> list)
    {
        long p = 0;
        while (s.Has(p, 30) && s.Match(p, "PK\x03\x04") && list.Count < 100000)
        {
            var e = new Entry { LocalOff = p, CdOff = p, Flags = s.U16(p + 6), Method = s.U16(p + 8), Time = s.U16(p + 10), Date = s.U16(p + 12), Crc = s.U32(p + 14), CSize = s.U32(p + 18), USize = s.U32(p + 22) };
            int nl = s.U16(p + 26), xl = s.U16(p + 28);
            e.Name = Encoding.UTF8.GetString(s.Bytes(p + 30, nl));
            list.Add(e);
            if ((e.Flags & 8) != 0 && e.CSize == 0) break;
            p += 30 + nl + xl + e.CSize;
        }
    }
}

public static class TarParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        using var st = s.OpenStream();
        d.H("TAR archive");
        ParseStream(st, d, ctx, 0);
    }

    /// <summary>Parses TAR headers from a sequential stream (plain file or decompressed gzip).</summary>
    public static void ParseStream(Stream st, Doc d, Ctx ctx, long baseForJump)
    {
        var hdr = new byte[512];
        long pos = 0; int n = 0; string longName = null;
        d.Th(new C("Type", 5), new C("Mode", 10), new C("Owner", 16), new C("Size", 14, R.Dim, true), new C("Modified", 19), new C("Name", 60));
        while (n < 20000)
        {
            if (ReadFull(st, hdr) < 512) break;
            long hdrPos = pos; pos += 512;
            if (hdr.All(b => b == 0)) break;
            string name = Str(hdr, 0, 100);
            long size = Oct(hdr, 124, 12);
            long mtime = Oct(hdr, 136, 12);
            char type = (char)hdr[156];
            string link = Str(hdr, 157, 100);
            bool ustar = Encoding.ASCII.GetString(hdr, 257, 5) == "ustar";
            string prefix = ustar ? Str(hdr, 345, 155) : "";
            if (prefix.Length > 0) name = prefix + "/" + name;
            if (longName != null) { name = longName; longName = null; }
            string owner = ustar ? $"{Str(hdr, 265, 32)}/{Str(hdr, 297, 32)}" : $"{Oct(hdr, 108, 8)}/{Oct(hdr, 116, 8)}";
            long data = pos;
            long padded = (size + 511) & ~511L;
            if (type == 'L')
            {
                var nb = new byte[Math.Min(size, 65536)];
                ReadFull(st, nb); Skip(st, padded - nb.Length); pos += padded;
                longName = Encoding.UTF8.GetString(nb).TrimEnd('\0');
                continue;
            }
            if (type is 'x' or 'g')
            {
                var pb = new byte[Math.Min(size, 65536)];
                ReadFull(st, pb); Skip(st, padded - pb.Length); pos += padded;
                var m = Regex.Match(Encoding.UTF8.GetString(pb), @"\d+ path=([^\n]*)\n");
                if (m.Success && type == 'x') longName = m.Groups[1].Value;
                continue;
            }
            string tn = type switch { '0' or '\0' or '7' => "file", '1' => "hard", '2' => "sym", '3' => "chr", '4' => "blk", '5' => "dir", '6' => "fifo", _ => type.ToString() };
            long mode = Oct(hdr, 100, 8);
            d.Tr(baseForJump >= 0 ? baseForJump + hdrPos : -1, new C(tn, 5, R.Key), new C(Perm(mode, type == '5'), 10, R.Value), new C(owner, 16, R.Dim),
                new C(size.ToString("N0"), 14, R.Num, true), new C(mtime > 0 ? DateTimeOffset.FromUnixTimeSeconds(Math.Min(mtime, 253402300799)).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") : "", 19, R.Value),
                new C(name + (type is '1' or '2' ? " → " + link : ""), 60, tn == "dir" ? R.Accent : R.Str));
            if (name.Contains("../") || name.StartsWith("/")) ctx.Bad("TAR", "Path traversal / absolute path in entry: " + name);
            if (type == '2' && (link.StartsWith("/") || link.Contains(".."))) ctx.Warn("TAR", $"Symlink points outside the archive: {name} → {link}");
            if ((mode & 0x800) != 0 && type != '5') ctx.Warn("TAR", "setuid file: " + name);
            n++;
            Skip(st, padded); pos += padded;
        }
        d.KV("Entries listed", n, R.Num);
    }

    static string Perm(long m, bool dir)
    {
        var c = new char[10];
        c[0] = dir ? 'd' : '-';
        string r = "rwxrwxrwx";
        for (int i = 0; i < 9; i++) c[i + 1] = (m & (1 << (8 - i))) != 0 ? r[i] : '-';
        if ((m & 0x800) != 0) c[3] = 's';
        return new string(c);
    }

    static int ReadFull(Stream st, byte[] b)
    {
        int t = 0;
        while (t < b.Length) { int n = st.Read(b, t, b.Length - t); if (n <= 0) break; t += n; }
        return t;
    }

    static void Skip(Stream st, long n)
    {
        if (n <= 0) return;
        if (st.CanSeek) { st.Seek(n, SeekOrigin.Current); return; }
        var buf = new byte[81920];
        while (n > 0) { int r = st.Read(buf, 0, (int)Math.Min(buf.Length, n)); if (r <= 0) break; n -= r; }
    }

    static string Str(byte[] b, int o, int n)
    {
        int z = Array.IndexOf(b, (byte)0, o, n);
        return Encoding.UTF8.GetString(b, o, (z < 0 ? o + n : z) - o);
    }

    static long Oct(byte[] b, int o, int n)
    {
        if ((b[o] & 0x80) != 0) { long v = b[o] & 0x7F; for (int i = 1; i < n; i++) v = v << 8 | b[o + i]; return v; }
        long r = 0;
        for (int i = o; i < o + n; i++)
        {
            byte c = b[i];
            if (c == 0 || c == ' ') { if (r > 0) break; continue; }
            if (c < '0' || c > '7') break;
            r = r * 8 + (c - '0');
        }
        return r;
    }
}

public static class GzipParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        d.H("GZIP member header");
        byte cm = s.U8(2), flg = s.U8(3);
        d.KV("Compression method", cm == 8 ? "8 (deflate)" : cm.ToString(), R.Value, 2);
        d.KV("Flags", Fmt.Flags(flg, new (ulong, string)[] { (1, "FTEXT"), (2, "FHCRC"), (4, "FEXTRA"), (8, "FNAME"), (16, "FCOMMENT") }), R.Value, 3);
        d.KV("MTIME", Fmt.Unix(s.U32(4)), R.Value, 4);
        byte xfl = s.U8(8), os = s.U8(9);
        d.KV("Extra flags", xfl == 2 ? "2 (max compression)" : xfl == 4 ? "4 (fastest)" : xfl.ToString(), R.Value, 8);
        string[] oss = { "FAT (MS-DOS/Windows)", "Amiga", "VMS", "Unix", "VM/CMS", "Atari TOS", "HPFS", "Macintosh", "Z-System", "CP/M", "TOPS-20", "NTFS", "QDOS", "Acorn RISCOS" };
        d.KV("Operating system", os < oss.Length ? $"{os} ({oss[os]})" : os == 255 ? "255 (unknown)" : os.ToString(), R.Value, 9);
        long p = 10;
        if ((flg & 4) != 0) { ushort xl = s.U16(p); d.KV("Extra field", $"{xl} bytes", R.Num, p); p += 2 + xl; }
        if ((flg & 8) != 0) { string nm = s.Ascii(p, 1024); d.KV("Original file name", nm, R.Str, p); p += Encoding.Latin1.GetByteCount(nm) + 1; }
        if ((flg & 16) != 0) { string cmt = s.Ascii(p, 4096); d.KV("Comment", cmt, R.Str, p); p += Encoding.Latin1.GetByteCount(cmt) + 1; }
        if ((flg & 2) != 0) { d.KV("Header CRC16", Fmt.Hx(s.U16(p), 4), R.Num, p); p += 2; }
        d.KV("Compressed data starts", Fmt.Hx(p), R.Offset, p);
        if (s.Length >= 18)
        {
            d.KV("Trailer CRC-32", s.U32(s.Length - 8).ToString("x8"), R.Hex, s.Length - 8);
            uint isize = s.U32(s.Length - 4);
            d.KV("Trailer ISIZE (mod 2^32)", Fmt.Size(isize), R.Num, s.Length - 4);
            if (isize > 0) d.KV("Compression ratio", $"{(double)isize / s.Length:0.00}:1", R.Value);
        }
        // peek inside
        try
        {
            using var gz = new GZipStream(s.OpenStream(), CompressionMode.Decompress);
            var head = new byte[1024];
            int got = 0;
            while (got < head.Length) { int n = gz.Read(head, got, head.Length - got); if (n <= 0) break; got += n; }
            var q = Detect.Quick(head.AsSpan(0, got));
            bool tar = got >= 262 && Encoding.ASCII.GetString(head, 257, 5) == "ustar";
            d.H("Decompressed content (streamed, never written to disk)");
            d.KV("Inner type", tar ? "TAR archive" : q ?? (Detect.SniffText(head.AsSpan(0, got)).isText ? "text" : "unknown binary"), R.Accent);
            d.KV("First bytes", Fmt.Bytes(head.AsSpan(0, Math.Min(got, 32)), 32), R.Hex);
            if (tar)
            {
                var rt = ctx.Refined ?? new FileType(); rt.Name = "GZIP-compressed TAR archive (.tar.gz)"; rt.Exts = new[] { "tgz", "gz", "tar.gz" }; ctx.Refined = rt;
                using var gz2 = new GZipStream(s.OpenStream(), CompressionMode.Decompress);
                d.H("TAR entries (inside gzip)");
                TarParser.ParseStream(gz2, d, ctx, -1);
            }
            else if (Detect.SniffText(head.AsSpan(0, got)).isText)
            {
                d.T("  Preview:", R.Dim);
                d.Text(Encoding.UTF8.GetString(head, 0, got), R.Str, "    ", 20);
            }
        }
        catch (Exception ex) { d.Warn("Could not decompress: " + ex.Message); }
    }
}

public static class SevenZipParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        d.H("7-Zip signature header");
        d.KV("Format version", $"{s.U8(6)}.{s.U8(7)}", R.Value, 6);
        d.KV("Start header CRC", s.U32(8).ToString("x8"), R.Hex, 8);
        ulong nOff = s.U64(12), nSize = s.U64(20);
        d.KV("Next header offset", Fmt.Hx(nOff) + $" (absolute {Fmt.Hx(32 + (long)nOff)})", R.Offset, 32 + (long)nOff);
        d.KV("Next header size", Fmt.Size((long)nSize), R.Num);
        d.KV("Next header CRC", s.U32(28).ToString("x8"), R.Hex, 28);
        long nh = 32 + (long)nOff;
        if (s.Has(nh, 1))
        {
            byte id = s.U8(nh);
            d.KV("Next header type", id == 1 ? "0x01 kHeader (plain file list)" : id == 0x17 ? "0x17 kEncodedHeader (compressed or ENCRYPTED file list)" : Fmt.Hx(id), R.Value, nh);
            if (id == 0x17) d.Info("File names are inside an encoded header; if the archive uses header encryption they cannot be listed without the password.");
            if (id == 1) ListNames(s, d, nh, (long)nSize);
        }
        if (32 + (long)nOff + (long)nSize < s.Length) ctx.Warn("7z", "Data appended after the 7z archive");
    }

    static void ListNames(ByteSource s, Doc d, long p, long size)
    {
        // Heuristic: find the kName (0x11) property and read UTF-16 names.
        var buf = s.Bytes(p, Math.Min(size, 4 << 20));
        for (int i = 0; i + 3 < buf.Length; i++)
        {
            if (buf[i] != 0x11) continue;
            int q = i + 1; ulong len = 0; int shift = 0;
            // 7z NUMBER encoding (first byte mask)
            byte first = buf[q++];
            int extra = 0; for (int m = 0x80; m != 0 && (first & m) != 0; m >>= 1) extra++;
            if (extra == 0) len = first;
            else { for (int k = 0; k < extra && q < buf.Length; k++) { len |= (ulong)buf[q++] << shift; shift += 8; } if (extra < 8) len |= (ulong)(first & (0xFF >> (extra + 1))) << shift; }
            if (q >= buf.Length || buf[q] != 0 || len < 4 || (long)len > buf.Length - q) continue;
            q++;
            var names = Encoding.Unicode.GetString(buf, q, (int)len - 1).Split('\0', StringSplitOptions.RemoveEmptyEntries);
            if (names.Length == 0) continue;
            d.H($"File names ({names.Length})");
            foreach (var n in names.Take(20000)) d.T("    " + n, R.Str);
            return;
        }
    }
}

public static class RarParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        bool v5 = s.Match(0, "Rar!\x1A\x07\x01\x00");
        d.H(v5 ? "RAR 5.x archive" : "RAR 1.5–4.x archive");
        if (v5) ParseV5(s, d, ctx); else ParseV4(s, d, ctx);
    }

    static void ParseV4(ByteSource s, Doc d, Ctx ctx)
    {
        long p = 7; int n = 0;
        d.Th(new C("Packed", 12, R.Dim, true), new C("Size", 12, R.Dim, true), new C("Modified", 19), new C("CRC32", 8), new C("OS", 6), new C("Name", 60));
        while (s.Has(p, 7) && n < 20000)
        {
            ushort flags = s.U16(p + 3), hsize = s.U16(p + 5);
            byte type = s.U8(p + 2);
            if (hsize < 7) break;
            long add = 0;
            if (type == 0x73 && (flags & 0x80) != 0) { d.Warn("Archive headers are encrypted – file names cannot be listed without the password"); ctx.Warn("RAR", "RAR archive with encrypted headers"); return; }
            if (type == 0x74)
            {
                uint pack = s.U32(p + 7), unp = s.U32(p + 11);
                byte os = s.U8(p + 15); uint crc = s.U32(p + 16), ftime = s.U32(p + 20);
                ushort nsz = s.U16(p + 26);
                long hp = p + 32;
                long highPack = 0, highUnp = 0;
                if ((flags & 0x100) != 0) { highPack = s.U32(hp); highUnp = s.U32(hp + 4); hp += 8; }
                string name = s.Fixed(hp, nsz);
                int z = name.IndexOf('\0'); if (z >= 0) name = name[..z];
                long packed = pack | highPack << 32;
                d.Tr(p, new C(packed.ToString("N0"), 12, R.Num, true), new C((unp | highUnp << 32).ToString("N0"), 12, R.Num, true),
                    new C(Fmt.DosDateTime((ushort)(ftime >> 16), (ushort)ftime), 19, R.Value), new C(crc.ToString("x8"), 8, R.Hex),
                    new C(os switch { 0 => "DOS", 2 => "Win", 3 => "Unix", 5 => "BeOS", _ => os.ToString() }, 6), new C(name + ((flags & 4) != 0 ? "  [encrypted]" : ""), 60, (flags & 4) != 0 ? R.Warn : R.Str));
                add = packed;
                n++;
            }
            else if ((flags & 0x8000) != 0) add = s.U32(p + 7);
            if (type == 0x7B) break;
            p += hsize + add;
        }
    }

    static ulong V(ByteSource s, ref long p)
    {
        ulong r = 0; int sh = 0;
        for (int i = 0; i < 10; i++) { byte b = s.U8(p++); r |= (ulong)(b & 0x7F) << sh; if ((b & 0x80) == 0) break; sh += 7; }
        return r;
    }

    static void ParseV5(ByteSource s, Doc d, Ctx ctx)
    {
        long p = 8; int n = 0;
        d.Th(new C("Packed", 12, R.Dim, true), new C("Size", 12, R.Dim, true), new C("Modified", 19), new C("CRC32", 8), new C("Name", 60));
        while (s.Has(p, 7) && n < 20000)
        {
            long start = p;
            p += 4; // crc
            ulong hsize = V(s, ref p);
            long hstart = p;
            ulong type = V(s, ref p), hflags = V(s, ref p);
            ulong extra = 0, dataSize = 0;
            if ((hflags & 1) != 0) extra = V(s, ref p);
            if ((hflags & 2) != 0) dataSize = V(s, ref p);
            if (type == 4) { d.Warn("Archive encryption header – file names are encrypted"); ctx.Warn("RAR", "RAR5 archive with encrypted headers"); return; }
            if (type == 2)
            {
                ulong fflags = V(s, ref p), unp = V(s, ref p); V(s, ref p);
                uint mtime = 0, crc = 0;
                if ((fflags & 2) != 0) { mtime = s.U32(p); p += 4; }
                if ((fflags & 4) != 0) { crc = s.U32(p); p += 4; }
                V(s, ref p); V(s, ref p);
                ulong nl = V(s, ref p);
                string name = Encoding.UTF8.GetString(s.Bytes(p, (long)Math.Min(nl, 4096UL)));
                bool enc = false;
                long xe = hstart + (long)hsize, xs = xe - (long)extra;
                long q = xs;
                while (q < xe && extra > 0)
                {
                    ulong sz = V(s, ref q); long rs = q; ulong xt = V(s, ref q);
                    if (xt == 1) enc = true;
                    q = rs + (long)sz;
                }
                d.Tr(start, new C(dataSize.ToString("N0"), 12, R.Num, true), new C(unp.ToString("N0"), 12, R.Num, true),
                    new C(mtime != 0 ? DateTimeOffset.FromUnixTimeSeconds(mtime).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") : "", 19, R.Value),
                    new C(crc.ToString("x8"), 8, R.Hex), new C(name + ((fflags & 1) != 0 ? "/" : "") + (enc ? "  [encrypted]" : ""), 60, enc ? R.Warn : R.Str));
                n++;
            }
            if (type == 5) break;
            p = hstart + (long)hsize + (long)dataSize;
        }
    }
}

public static class CabParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        d.H("Cabinet header (CFHEADER)");
        uint cb = s.U32(8), coffFiles = s.U32(16);
        ushort folders = s.U16(26), files = s.U16(28), flags = s.U16(30);
        d.KV("Cabinet size", Fmt.Size(cb), R.Num, 8);
        d.KV("Version", $"{s.U8(25)}.{s.U8(24)}", R.Value, 24);
        d.KV("Folders / files", $"{folders} / {files}", R.Num, 26);
        d.KV("Flags", Fmt.Flags(flags, new (ulong, string)[] { (1, "PREV_CABINET"), (2, "NEXT_CABINET"), (4, "RESERVE_PRESENT") }), R.Value, 30);
        d.KV("Set ID / index", $"{s.U16(32)} / {s.U16(34)}", R.Num);
        long p = 36; int cbFolderRes = 0;
        if ((flags & 4) != 0) { ushort hr = s.U16(p); cbFolderRes = s.U8(p + 2); p += 4 + hr; if (hr > 0) d.Info("Reserved area present (often holds an Authenticode signature)"); }
        if ((flags & 1) != 0) { p += s.Ascii(p, 256).Length + 1; p += s.Ascii(p, 256).Length + 1; }
        if ((flags & 2) != 0) { p += s.Ascii(p, 256).Length + 1; p += s.Ascii(p, 256).Length + 1; }
        d.H("Folders (compression streams)");
        for (int i = 0; i < Math.Min((int)folders, 1000); i++)
        {
            uint start = s.U32(p); ushort blocks = s.U16(p + 4), comp = s.U16(p + 6);
            string cn = (comp & 0xF) switch { 0 => "none", 1 => "MSZIP", 2 => "Quantum", 3 => $"LZX (window 2^{(comp >> 8) & 0x1F})", _ => comp.ToString() };
            d.KV($"Folder {i}", $"data at {Fmt.Hx(start)}, {blocks} blocks, compression {cn}", R.Value, start);
            p += 8 + cbFolderRes;
        }
        d.H($"Files ({files})");
        d.Th(new C("Size", 12, R.Dim, true), new C("Folder", 6, R.Dim, true), new C("Modified", 19), new C("Attr", 6), new C("Name", 60));
        p = coffFiles;
        for (int i = 0; i < Math.Min((int)files, 65535) && s.Has(p, 16); i++)
        {
            uint size = s.U32(p); ushort fold = s.U16(p + 8), date = s.U16(p + 10), time = s.U16(p + 12), attr = s.U16(p + 14);
            string name = (attr & 0x80) != 0 ? s.Utf8Z(p + 16, 512) : s.Ascii(p + 16, 512);
            d.Tr(p, new C(size.ToString("N0"), 12, R.Num, true), new C(fold.ToString(), 6, R.Num, true), new C(Fmt.DosDateTime(date, time), 19, R.Value),
                new C(Fmt.Hx(attr, 2), 6, R.Dim), new C(name, 60, R.Str));
            p += 16 + Encoding.UTF8.GetByteCount(name) + 1;
        }
    }
}
