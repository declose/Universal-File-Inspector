using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using Ufi.Core;

namespace Ufi.Parsers;

public static class JavaClassParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        var c = new Cur(s, 4, true);
        ushort minor = c.U16(), major = c.U16();
        d.H("Java class file");
        string jv = major >= 49 ? (major - 44).ToString() : major switch { 45 => "1.1", 46 => "1.2", 47 => "1.3", 48 => "1.4", _ => "?" };
        d.KV("Class file version", $"{major}.{minor}  (Java {jv}{(minor == 0xFFFF ? ", preview features" : "")})", R.Value, 4);
        int n = c.U16();
        var utf = new Dictionary<int, string>(); var cls = new Dictionary<int, int>(); var nat = new Dictionary<int, (int, int)>();
        var classRefs = new List<int>(); var strings = new List<int>();
        for (int i = 1; i < n; i++)
        {
            byte tag = c.U8();
            switch (tag)
            {
                case 1: int l = c.U16(); utf[i] = Encoding.UTF8.GetString(c.Bytes(l)); break;
                case 3 or 4: c.Skip(4); break;
                case 5 or 6: c.Skip(8); i++; break;
                case 7: cls[i] = c.U16(); classRefs.Add(i); break;
                case 8: strings.Add(c.U16()); break;
                case 9 or 10 or 11 or 17 or 18: c.Skip(4); break;
                case 12: nat[i] = (c.U16(), c.U16()); break;
                case 15: c.Skip(3); break;
                case 16 or 19 or 20: c.Skip(2); break;
                default: d.Warn($"Unknown constant-pool tag {tag} at {Fmt.Hx(c.P - 1)}"); return;
            }
        }
        string Cls(int idx) => cls.TryGetValue(idx, out var u) && utf.TryGetValue(u, out var nm) ? nm.Replace('/', '.') : "?";
        ushort acc = c.U16(); int self = c.U16(), super = c.U16();
        d.KV("Constant pool entries", n - 1, R.Num);
        d.KV("Access flags", Fmt.Flags(acc, new (ulong, string)[] { (1, "public"), (0x10, "final"), (0x20, "super"), (0x200, "interface"), (0x400, "abstract"), (0x1000, "synthetic"), (0x2000, "annotation"), (0x4000, "enum"), (0x8000, "module") }), R.Value);
        d.KV("This class", Cls(self), R.Accent);
        d.KV("Super class", super == 0 ? "(none)" : Cls(super), R.Str);
        int ni = c.U16();
        for (int i = 0; i < ni; i++) d.KV("Implements", Cls(c.U16()), R.Str);
        var rt = ctx.Refined ?? new FileType(); rt.Name = $"Java class {Cls(self)} (Java {jv})"; ctx.Refined = rt;
        void Members(string what)
        {
            int cnt = c.U16();
            d.H($"{what} ({cnt})");
            for (int i = 0; i < cnt; i++)
            {
                ushort fa = c.U16(); int nm = c.U16(), ds = c.U16(), ac = c.U16();
                string mods = string.Join(" ", new[] { (1, "public"), (2, "private"), (4, "protected"), (8, "static"), (0x10, "final"), (0x20, "synchronized"), (0x100, "native"), (0x400, "abstract") }.Where(x => (fa & x.Item1) != 0).Select(x => x.Item2));
                d.T($"    {mods} {utf.GetValueOrDefault(nm, "?")} {utf.GetValueOrDefault(ds, "")}".Replace("  ", " "), R.Str);
                for (int k = 0; k < ac; k++) { c.U16(); uint al = c.U32(); c.Skip(al); }
            }
        }
        Members("Fields");
        Members("Methods");
        int ca = c.U16();
        for (int i = 0; i < ca; i++)
        {
            string an = utf.GetValueOrDefault(c.U16(), "?"); uint al = c.U32(); long at = c.P;
            if (an == "SourceFile") d.KV("Source file", utf.GetValueOrDefault(s.U16(at, true), "?"), R.Str, at);
            c.Skip(al);
        }
        d.H($"Referenced classes ({classRefs.Count})");
        foreach (var r in classRefs.Take(2000)) d.T("    " + Cls(r), R.Str);
        foreach (var si in strings) if (utf.TryGetValue(si, out var sv)) ctx.ExtraStrings.Add(sv);
        if (classRefs.Any(r => Cls(r) is "java.lang.Runtime" or "java.lang.ProcessBuilder")) ctx.Warn("Java", "Class can execute OS commands (Runtime / ProcessBuilder)");
        if (classRefs.Any(r => Cls(r).StartsWith("java.lang.reflect") || Cls(r) == "java.lang.ClassLoader")) ctx.Info("Java", "Class uses reflection / custom class loading");
    }
}

public static class WasmParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        d.H("WebAssembly module");
        d.KV("Version", s.U32(4), R.Num, 4);
        var c = new Cur(s, 8);
        string[] names = { "custom", "type", "import", "function", "table", "memory", "global", "export", "start", "element", "code", "data", "datacount", "tag" };
        string Name() { int l = (int)c.Leb(); return Encoding.UTF8.GetString(c.Bytes(l)); }
        d.Th(new C("ID", 3, R.Dim, true), new C("Section", 12), new C("Offset", 10), new C("Size", 10, R.Dim, true), new C("Info", 50));
        var imports = new List<string>(); var exports = new List<string>();
        while (c.P < s.Length)
        {
            long at = c.P;
            byte id = c.U8(); ulong size = c.Leb(); long body = c.P;
            string info = "";
            try
            {
                if (id == 0) info = "name: " + Name();
                if (id == 2)
                {
                    ulong n = c.Leb(); info = $"{n} imports";
                    for (ulong i = 0; i < Math.Min(n, 5000UL); i++)
                    {
                        string mod = Name(), fld = Name(); byte k = c.U8();
                        switch (k) { case 0: c.Leb(); break; case 1: c.U8(); if ((c.U8() & 1) != 0) { c.Leb(); c.Leb(); } else c.Leb(); break; case 2: if ((c.U8() & 1) != 0) { c.Leb(); c.Leb(); } else c.Leb(); break; case 3: c.U8(); c.U8(); break; case 4: c.U8(); c.Leb(); break; }
                        imports.Add($"{mod}.{fld}  ({(k switch { 0 => "func", 1 => "table", 2 => "memory", 3 => "global", 4 => "tag", _ => "?" })})");
                    }
                }
                if (id == 7)
                {
                    ulong n = c.Leb(); info = $"{n} exports";
                    for (ulong i = 0; i < Math.Min(n, 5000UL); i++) { string nm = Name(); byte k = c.U8(); c.Leb(); exports.Add($"{nm}  ({(k switch { 0 => "func", 1 => "table", 2 => "memory", 3 => "global", 4 => "tag", _ => "?" })})"); }
                }
                if (id is 3 or 1 or 10 or 11) info = $"{c.Leb()} entries";
            }
            catch { }
            d.Tr(at, new C(id.ToString(), 3, R.Num, true), new C(id < names.Length ? names[id] : "?", 12, R.Key), new C(Fmt.Hx(at), 10, R.Offset), new C(size.ToString("N0"), 10, R.Num, true), new C(info, 50, R.Str));
            c.P = body + (long)size;
            if (size > (ulong)s.Length) break;
        }
        if (imports.Count > 0) { d.H("Imports"); foreach (var i in imports) d.T("    " + i, R.Str); }
        if (exports.Count > 0) { d.H("Exports"); foreach (var e in exports) d.T("    " + e, R.Str); }
    }
}

public static class RegfParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        d.H("Registry hive base block");
        uint s1 = s.U32(4), s2 = s.U32(8);
        d.KV("Sequence numbers", $"{s1} / {s2}" + (s1 != s2 ? "  (DIRTY – transaction log not applied)" : ""), s1 != s2 ? R.Warn : R.Value, 4);
        d.KV("Last written", Fmt.FileTime(s.I64(12)), R.Value, 12);
        d.KV("Format version", $"{s.U32(20)}.{s.U32(24)}", R.Value, 20);
        d.KV("Root cell offset", Fmt.Hx(s.U32(36)), R.Num, 36);
        d.KV("Hive bins size", Fmt.Size(s.U32(40)), R.Num, 40);
        d.KV("Embedded file name", s.Utf16Z(48, 32), R.Str, 48);
        long nk = 4096 + s.U32(36) + 4;
        if (s.Match(nk, "nk"))
        {
            d.KV("Root key name", s.Fixed(nk + 76, s.U16(nk + 72)), R.Accent, nk);
            d.KV("Root key last write", Fmt.FileTime(s.I64(nk + 4)), R.Value);
            d.KV("Root subkeys / values", $"{s.U32(nk + 20)} / {s.U32(nk + 36)}", R.Num);
        }
    }
}

public static class IsoParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        d.H("ISO 9660 volume descriptors");
        long jolietRoot = -1, pvdRoot = -1; uint rootSize = 0, jolietSize = 0;
        for (long sec = 16; sec < 64; sec++)
        {
            long p = sec * 2048;
            if (!s.Match(p + 1, "CD001")) break;
            byte t = s.U8(p);
            string tn = t switch { 0 => "Boot record", 1 => "Primary volume descriptor", 2 => "Supplementary (Joliet?)", 3 => "Partition", 255 => "Terminator", _ => t.ToString() };
            d.Sub($"{tn} at {Fmt.Hx(p)}", p);
            if (t == 0) { d.KV("    Boot system", s.Fixed(p + 7, 32), R.Warn); ctx.Info("ISO", "Disc image is bootable (El Torito)"); }
            if (t is 1 or 2)
            {
                bool joliet = t == 2 && s.U8(p + 88) == 0x25 && s.U8(p + 89) == 0x2F;
                string F(int o, int n) => joliet ? Encoding.BigEndianUnicode.GetString(s.Bytes(p + o, n)).TrimEnd(' ', '\0') : s.Fixed(p + o, n);
                d.KV("    System ID", F(8, 32), R.Str);
                d.KV("    Volume ID", F(40, 32), R.Accent);
                d.KV("    Volume size", Fmt.Size((long)s.U32(p + 80) * s.U16(p + 128)), R.Num);
                d.KV("    Publisher", F(318, 128), R.Str);
                d.KV("    Data preparer", F(446, 128), R.Str);
                d.KV("    Application", F(574, 128), R.Str);
                d.KV("    Created", IsoDate(s.Fixed(p + 813, 16)), R.Value);
                d.KV("    Modified", IsoDate(s.Fixed(p + 830, 16)), R.Value);
                long root = (long)s.U32(p + 156 + 2) * 2048; uint rs = s.U32(p + 156 + 10);
                if (joliet) { jolietRoot = root; jolietSize = rs; } else if (t == 1) { pvdRoot = root; rootSize = rs; }
            }
            if (t == 255) break;
        }
        bool j = jolietRoot >= 0;
        long r0 = j ? jolietRoot : pvdRoot; uint rsz = j ? jolietSize : rootSize;
        if (r0 < 0) return;
        d.H("Directory tree" + (j ? " (Joliet names)" : ""));
        int count = 0;
        void Dir(long off, uint size, string path, int depth)
        {
            if (depth > 8 || count > 5000) return;
            long p = off, end = off + size;
            while (p < end && count < 5000)
            {
                int len = s.U8(p);
                if (len == 0) { p = (p / 2048 + 1) * 2048; continue; }
                long ext = (long)s.U32(p + 2) * 2048; uint dsize = s.U32(p + 10); byte fl = s.U8(p + 25); int nl = s.U8(p + 32);
                string name = j ? Encoding.BigEndianUnicode.GetString(s.Bytes(p + 33, nl)) : s.Fixed(p + 33, nl);
                if (!(nl == 1 && (s.U8(p + 33) == 0 || s.U8(p + 33) == 1)))
                {
                    name = Regex.Replace(name, ";1$", "");
                    bool dir = (fl & 2) != 0;
                    count++;
                    string full = path + "/" + name;
                    string dt = $"{1900 + s.U8(p + 18)}-{s.U8(p + 19):00}-{s.U8(p + 20):00} {s.U8(p + 21):00}:{s.U8(p + 22):00}";
                    d.Add(ext, new Seg("  " + (dir ? "[DIR] " : "      "), R.Dim), new Seg((dir ? "" : dsize.ToString("N0")).PadLeft(14) + "  ", R.Num), new Seg(dt + "  ", R.Value), new Seg(Fmt.Clean(full, 300), dir ? R.Accent : R.Str));
                    if ((fl & 1) != 0) ctx.Warn("ISO", "Hidden entry in disc image: " + full);
                    if (!dir && Regex.IsMatch(name, @"\.(exe|scr|lnk|js|vbs|bat|cmd|hta|dll|msi|ps1)$", RegexOptions.IgnoreCase) && depth == 0) ctx.Warn("ISO", "Executable/script at the root of the disc image: " + name, ext);
                    if (dir) Dir(ext, dsize, full, depth + 1);
                }
                p += len;
            }
        }
        Dir(r0, rsz, "", 0);
    }

    static string IsoDate(string v) => v.Length >= 14 && v.Any(c => c != '0') ? $"{v[..4]}-{v[4..6]}-{v[6..8]} {v[8..10]}:{v[10..12]}:{v[12..14]}" : "(not set)";
}

public static class CertParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx, bool pem)
    {
        var blobs = new List<(string label, byte[] der)>();
        if (pem)
        {
            string t = Encoding.ASCII.GetString(s.Bytes(0, Math.Min(s.Length, 8 << 20)));
            foreach (Match m in Regex.Matches(t, @"-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----"))
            {
                string label = m.Groups[1].Value;
                try { blobs.Add((label, Convert.FromBase64String(Regex.Replace(m.Groups[2].Value, @"[^A-Za-z0-9+/=]", "")))); } catch { blobs.Add((label, null)); }
                if (label.Contains("PRIVATE KEY")) ctx.Bad("Crypto", $"File contains a {label} – secret key material");
            }
        }
        else blobs.Add(("DER", s.Bytes(0, Math.Min(s.Length, 16 << 20))));
        foreach (var (label, der) in blobs)
        {
            d.H(label);
            if (der == null) { d.Warn("Invalid base64"); continue; }
            d.KV("Encoded size", Fmt.Size(der.Length), R.Num);
            if (!label.Contains("CERTIFICATE") && label != "DER") continue;
            try
            {
                var cert = X509CertificateLoader.LoadCertificate(der);
                Describe(cert, d);
                if (cert.NotAfter < DateTime.Now) ctx.Warn("Crypto", $"Certificate expired {cert.NotAfter:yyyy-MM-dd}: {cert.Subject}");
            }
            catch (Exception ex)
            {
                try
                {
                    var col = X509CertificateLoader.LoadPkcs12Collection(der, null);
                    foreach (var c2 in col) Describe(c2, d);
                }
                catch { d.Warn("Not a parsable X.509 certificate: " + ex.Message); }
            }
        }
    }

    public static void Describe(X509Certificate2 c, Doc d, string indent = "")
    {
        d.KV(indent + "Subject", c.Subject, R.Accent);
        d.KV(indent + "Issuer", c.Issuer, R.Str);
        d.KV(indent + "Serial number", c.SerialNumber, R.Hex);
        d.KV(indent + "Valid from", Fmt.Time(c.NotBefore.ToUniversalTime()), R.Value);
        d.KV(indent + "Valid to", Fmt.Time(c.NotAfter.ToUniversalTime()) + (c.NotAfter < DateTime.Now ? "  (EXPIRED)" : ""), c.NotAfter < DateTime.Now ? R.Warn : R.Value);
        d.KV(indent + "Thumbprint (SHA-1)", c.Thumbprint, R.Hex);
        d.KV(indent + "Thumbprint (SHA-256)", c.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256), R.Hex);
        d.KV(indent + "Signature algorithm", c.SignatureAlgorithm.FriendlyName ?? c.SignatureAlgorithm.Value, R.Value);
        string keyAlg = c.PublicKey.Oid.FriendlyName ?? c.PublicKey.Oid.Value;
        int bits = 0;
        try { bits = c.GetRSAPublicKey()?.KeySize ?? c.GetECDsaPublicKey()?.KeySize ?? 0; } catch { }
        d.KV(indent + "Public key", keyAlg + (bits > 0 ? $" {bits} bits" : ""), R.Value);
        d.KV(indent + "Self-signed", c.Subject == c.Issuer ? "yes" : "no", R.Value);
        foreach (var ext in c.Extensions)
        {
            string v;
            try { v = ext.Format(false); } catch { v = "(unreadable)"; }
            d.KV(indent + "ext: " + (ext.Oid?.FriendlyName ?? ext.Oid?.Value), v + (ext.Critical ? "  [critical]" : ""), R.Dim);
        }
    }
}

public static class TextParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx, FileType ft)
    {
        long cap = Math.Min(s.Length, 32L << 20);
        var bytes = s.Bytes(0, cap);
        string text = Decode(bytes, ft);
        d.H("Text analysis");
        d.KV("Encoding", ft.TextEncoding ?? "?", R.Value);
        d.KV("Byte-order mark", ft.BomLength > 0 ? Fmt.Bytes(bytes.AsSpan(0, ft.BomLength), 4) : "none", R.Value, 0);
        int lines = 1, crlf = 0, lf = 0, cr = 0, longest = 0, cur = 0, tabs = 0, ctrl = 0, nonAscii = 0, trailing = 0, words = 0;
        bool inWord = false;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '\r') { if (i + 1 < text.Length && text[i + 1] == '\n') { crlf++; i++; } else cr++; lines++; longest = Math.Max(longest, cur); cur = 0; inWord = false; continue; }
            if (c == '\n') { lf++; lines++; longest = Math.Max(longest, cur); cur = 0; inWord = false; if (i > 0 && text[i - 1] is ' ' or '\t') trailing++; continue; }
            cur++;
            if (c == '\t') tabs++;
            else if (c < 0x20) ctrl++;
            if (c > 0x7F) nonAscii++;
            bool ws = char.IsWhiteSpace(c);
            if (!ws && !inWord) words++;
            inWord = !ws;
        }
        longest = Math.Max(longest, cur);
        d.KV("Characters", text.Length.ToString("N0") + (s.Length > cap ? $" (first {Fmt.Human(cap)} analysed)" : ""), R.Num);
        d.KV("Lines", lines.ToString("N0"), R.Num);
        d.KV("Words (approx.)", words.ToString("N0"), R.Num);
        d.KV("Line endings", $"CRLF {crlf:N0}  LF {lf:N0}  CR {cr:N0}  → {(crlf > 0 && lf == 0 && cr == 0 ? "Windows" : lf > 0 && crlf == 0 && cr == 0 ? "Unix" : cr > 0 && crlf == 0 && lf == 0 ? "classic Mac" : crlf + lf + cr == 0 ? "single line" : "MIXED")}", crlf > 0 && lf > 0 ? R.Warn : R.Value);
        d.KV("Longest line", longest.ToString("N0") + " chars", longest > 2000 ? R.Warn : R.Num);
        d.KV("Tabs / control chars", $"{tabs:N0} / {ctrl:N0}", R.Num);
        d.KV("Non-ASCII characters", nonAscii.ToString("N0"), R.Num);
        d.KV("Lines with trailing space", trailing.ToString("N0"), R.Num);
        if (text.IndexOfAny(new[] { '‮', '‭', '⁦', '⁧', '⁨' }) >= 0) ctx.Bad("Text", "Bidirectional override characters present (Trojan Source / spoofing)");
        if (text.IndexOfAny(new[] { '​', '‌', '‍', '⁠' }) >= 0) ctx.Warn("Text", "Zero-width characters present (hidden text / watermarking)");
        if (text.StartsWith("#!")) d.KV("Shebang (interpreter)", text.Split('\n')[0].TrimEnd(), R.Accent);
        if (longest > 5000 && lines < 20) ctx.Info("Text", "Very long lines – minified or obfuscated content");

        string lt = text.Length > 4 << 20 ? text[..(4 << 20)] : text;
        if (ft.Name.StartsWith("JSON")) Json(lt, d, ctx);
        else if (ft.Kind == "xml" || ft.Name.Contains("XML") || ft.Name.StartsWith("SVG")) Xml(lt, d, ctx);
        else if (ft.Kind == "html") Html(lt, d, ctx);
        ScriptChecks(lt, d, ctx);
    }

    public static string Decode(byte[] b, FileType ft)
    {
        string enc = ft?.TextEncoding ?? "";
        int bom = ft?.BomLength ?? 0;
        if (enc.StartsWith("UTF-16 LE")) return Encoding.Unicode.GetString(b, bom, (b.Length - bom) & ~1);
        if (enc.StartsWith("UTF-16 BE")) return Encoding.BigEndianUnicode.GetString(b, bom, (b.Length - bom) & ~1);
        if (enc.StartsWith("UTF-32 LE")) return new UTF32Encoding(false, false).GetString(b, bom, (b.Length - bom) & ~3);
        if (enc.StartsWith("UTF-32 BE")) return new UTF32Encoding(true, false).GetString(b, bom, (b.Length - bom) & ~3);
        if (enc.StartsWith("Windows-1252")) { try { return Encoding.GetEncoding(1252).GetString(b); } catch { return Encoding.Latin1.GetString(b); } }
        return Encoding.UTF8.GetString(b, bom, b.Length - bom);
    }

    static void Json(string t, Doc d, Ctx ctx)
    {
        d.H("JSON structure");
        try
        {
            using var doc = JsonDocument.Parse(t, new JsonDocumentOptions { MaxDepth = 512, AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
            int maxDepth = 0; long nodes = 0;
            void Walk(JsonElement e, int depth) { nodes++; maxDepth = Math.Max(maxDepth, depth); if (e.ValueKind == JsonValueKind.Object) foreach (var p in e.EnumerateObject()) Walk(p.Value, depth + 1); else if (e.ValueKind == JsonValueKind.Array) foreach (var x in e.EnumerateArray()) Walk(x, depth + 1); }
            Walk(doc.RootElement, 0);
            d.Good("Valid JSON");
            d.KV("Root type", doc.RootElement.ValueKind, R.Value);
            d.KV("Nodes / max depth", $"{nodes:N0} / {maxDepth}", R.Num);
            if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                d.Sub("Top-level keys");
                foreach (var p in doc.RootElement.EnumerateObject().Take(200))
                    d.KV("    " + p.Name, p.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array ? p.Value.ValueKind.ToString() + (p.Value.ValueKind == JsonValueKind.Array ? $" [{p.Value.GetArrayLength()}]" : "") : Fmt.Trunc(p.Value.ToString(), 120), R.Str);
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.Array) d.KV("Array length", doc.RootElement.GetArrayLength(), R.Num);
        }
        catch (JsonException ex) { d.Warn("Not valid JSON: " + ex.Message); }
    }

    static void Xml(string t, Doc d, Ctx ctx)
    {
        d.H("XML structure");
        try
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null, MaxCharactersFromEntities = 1024 };
            using var r = XmlReader.Create(new StringReader(t), settings);
            var counts = new Dictionary<string, int>(); string root = null; int maxDepth = 0;
            while (r.Read())
            {
                if (r.NodeType == XmlNodeType.Element)
                {
                    root ??= r.Name; maxDepth = Math.Max(maxDepth, r.Depth);
                    counts[r.Name] = counts.GetValueOrDefault(r.Name) + 1;
                }
                if (r.NodeType == XmlNodeType.DocumentType) { d.KV("DOCTYPE", r.Name, R.Value); if (t.Contains("<!ENTITY")) ctx.Warn("XML", "Document declares entities (XXE / billion-laughs risk for parsers)"); }
            }
            d.Good("Well-formed XML");
            d.KV("Root element", root, R.Accent);
            d.KV("Elements / max depth", $"{counts.Values.Sum():N0} / {maxDepth}", R.Num);
            d.Sub("Most frequent elements");
            foreach (var kv in counts.OrderByDescending(x => x.Value).Take(25)) d.KV("    " + kv.Key, kv.Value, R.Num);
            if (Regex.IsMatch(t, @"<script", RegexOptions.IgnoreCase)) ctx.Warn("XML", "Contains <script> elements (active content, e.g. SVG with JavaScript)");
        }
        catch (XmlException ex) { d.Warn($"Not well-formed: {ex.Message}"); }
    }

    static void Html(string t, Doc d, Ctx ctx)
    {
        d.H("HTML overview");
        var title = Regex.Match(t, @"<title[^>]*>([^<]{0,300})</title>", RegexOptions.IgnoreCase);
        if (title.Success) d.KV("Title", System.Net.WebUtility.HtmlDecode(title.Groups[1].Value.Trim()), R.Accent);
        int scripts = Regex.Matches(t, @"<script", RegexOptions.IgnoreCase).Count, iframes = Regex.Matches(t, @"<iframe", RegexOptions.IgnoreCase).Count, forms = Regex.Matches(t, @"<form", RegexOptions.IgnoreCase).Count;
        d.KV("<script> / <iframe> / <form>", $"{scripts} / {iframes} / {forms}", R.Num);
        foreach (Match m in Regex.Matches(t, @"<script[^>]+src\s*=\s*[""']?([^""'\s>]+)", RegexOptions.IgnoreCase).Take(100)) d.KV("  external script", m.Groups[1].Value, R.Str);
        foreach (Match m in Regex.Matches(t, @"<form[^>]+action\s*=\s*[""']?([^""'\s>]+)", RegexOptions.IgnoreCase).Take(50)) { d.KV("  form action", m.Groups[1].Value, R.Warn); }
        if (Regex.IsMatch(t, @"type\s*=\s*[""']?password", RegexOptions.IgnoreCase)) ctx.Warn("HTML", "Page contains a password field (phishing pages often arrive as local HTML attachments)");
        if (Regex.IsMatch(t, @"(atob|unescape|String\.fromCharCode|eval)\s*\(", RegexOptions.IgnoreCase)) ctx.Warn("HTML", "Page uses script de-obfuscation functions (atob/unescape/eval/fromCharCode)");
        if (Regex.IsMatch(t, @"<meta[^>]+http-equiv\s*=\s*[""']?refresh", RegexOptions.IgnoreCase)) ctx.Info("HTML", "Page has a meta-refresh redirect");
        if (Regex.IsMatch(t, @"msSaveOrOpenBlob|download\s*=|new\s+Blob\s*\(", RegexOptions.IgnoreCase)) ctx.Warn("HTML", "Page can generate a file download from script (HTML smuggling technique)");
        if (Regex.IsMatch(t, @"ActiveXObject|<hta:application", RegexOptions.IgnoreCase)) ctx.Bad("HTML", "HTA / ActiveX content (runs with full user privileges when opened by mshta)");
    }

    static void ScriptChecks(string t, Doc d, Ctx ctx)
    {
        var m = Regex.Match(t, @"(?i)-e(?:nc(?:odedcommand)?|c)?\s+([A-Za-z0-9+/]{40,}={0,2})");
        if (m.Success)
        {
            try
            {
                string dec = Encoding.Unicode.GetString(Convert.FromBase64String(m.Groups[1].Value));
                d.H("Decoded PowerShell -EncodedCommand");
                d.Text(dec, R.Bad, "    ", 60);
                ctx.Bad("Script", "Encoded PowerShell command found and decoded (see STRUCTURE)");
                ctx.ExtraStrings.Add(dec);
            }
            catch { }
        }
        if (Regex.IsMatch(t, @"(?i)\b(iex|invoke-expression)\b") && Regex.IsMatch(t, @"(?i)(downloadstring|invoke-webrequest|net\.webclient|iwr\s)"))
            ctx.Bad("Script", "PowerShell download-and-execute pattern (IEX + web download)");
        if (Regex.IsMatch(t, @"(?i)frombase64string")) ctx.Warn("Script", "Script decodes Base64 data at runtime");
        if (Regex.IsMatch(t, @"(?i)wscript\.shell|shell\.application")) ctx.Warn("Script", "Script instantiates WScript.Shell / Shell.Application (can run commands)");
        if (Regex.IsMatch(t, @"(?i)set-mppreference|add-mppreference.*exclusion|disablerealtimemonitoring")) ctx.Bad("Script", "Script tampers with Microsoft Defender settings");
        if (Regex.IsMatch(t, @"(?i)(chr\(\d+\)\s*[&+]\s*){8,}")) ctx.Warn("Script", "Heavy Chr() concatenation – obfuscated script");
        if (Regex.IsMatch(t, @"(?i)vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit.*recoveryenabled\s+no")) ctx.Bad("Script", "Backup / shadow-copy deletion commands (ransomware behaviour)");
    }
}
