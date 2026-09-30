using System.Text;
using Ufi.Core;

namespace Ufi.Parsers;

public static class RiffParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        uint size = s.U32(4);
        string form = s.Fixed(8, 4);
        d.H($"RIFF container – form '{form}'");
        d.KV("Declared size", Fmt.Size(size + 8L) + (size + 8L != s.Length ? $"  (file is {Fmt.Size(s.Length)})" : ""), size + 8L == s.Length ? R.Value : R.Warn, 4);
        d.H("Chunk tree");
        int count = 0;
        uint byteRate = 0;
        void Walk(long p, long end, int depth)
        {
            while (p + 8 <= end && count < 20000 && depth < 8)
            {
                string id = s.Fixed(p, 4);
                uint len = s.U32(p + 4);
                long data = p + 8;
                string ind = new string(' ', 2 + depth * 2);
                count++;
                if (id is "LIST" or "RIFF")
                {
                    string lt = s.Fixed(data, 4);
                    d.Add(p, new Seg(ind + id, R.Key), new Seg($" '{lt}'", R.Accent), new Seg($"  {Fmt.Hx(p)}  {len:N0} bytes", R.Dim));
                    if (lt == "INFO")
                    {
                        long q = data + 4;
                        while (q + 8 <= data + len)
                        {
                            string k = s.Fixed(q, 4); uint l = s.U32(q + 4);
                            string v = s.Fixed(q + 8, (int)Math.Min(l, 4096u));
                            d.KV(ind + "  " + InfoName(k), v, R.Str, q);
                            ctx.ExtraStrings.Add(v);
                            q += 8 + l + (l & 1);
                        }
                    }
                    else Walk(data + 4, Math.Min(data + len, end), depth + 1);
                }
                else
                {
                    string det = "";
                    switch (id)
                    {
                        case "fmt ":
                            ushort tag = s.U16(data), ch = s.U16(data + 2); uint sr = s.U32(data + 4); byteRate = s.U32(data + 8); ushort bits = s.U16(data + 14);
                            det = $"{(tag switch { 1 => "PCM", 3 => "IEEE float", 6 => "A-law", 7 => "µ-law", 0x11 => "IMA ADPCM", 0x55 => "MP3", 0xFFFE => "extensible", _ => Fmt.Hx(tag, 4) })}, {ch} ch, {sr} Hz, {bits}-bit";
                            var rt = ctx.Refined ?? new FileType(); rt.Name = $"WAVE audio, {det}"; ctx.Refined = rt;
                            break;
                        case "data": if (byteRate > 0) det = $"duration {TimeSpan.FromSeconds((double)len / byteRate):hh\\:mm\\:ss\\.fff}"; break;
                        case "avih": det = $"{s.U32(data + 32)}×{s.U32(data + 36)}, {s.U32(data + 16)} frames, {(s.U32(data) > 0 ? 1e6 / s.U32(data) : 0):0.##} fps, {s.U32(data + 24)} streams"; break;
                        case "strh": det = $"stream type {s.Fixed(data, 4)}, handler '{s.Fixed(data + 4, 4)}'"; break;
                        case "VP8X":
                            uint fl = s.U8(data); det = $"canvas {s.U24(data + 4) + 1}×{s.U24(data + 7) + 1}" + ((fl & 2) != 0 ? ", animated" : "") + ((fl & 0x10) != 0 ? ", alpha" : "") + ((fl & 8) != 0 ? ", EXIF" : "") + ((fl & 4) != 0 ? ", XMP" : "") + ((fl & 0x20) != 0 ? ", ICC" : "");
                            break;
                        case "VP8L": uint b = s.U32(data + 1); det = $"lossless {(b & 0x3FFF) + 1}×{((b >> 14) & 0x3FFF) + 1}"; break;
                        case "VP8 ": det = $"lossy {s.U16(data + 6) & 0x3FFF}×{s.U16(data + 8) & 0x3FFF}"; break;
                        case "EXIF": det = "EXIF metadata"; break;
                        case "XMP ": det = "XMP metadata"; break;
                        case "anih": det = $"{s.U32(data + 4)} frames, {s.U32(data + 8)} steps"; break;
                    }
                    d.Add(p, new Seg(ind + id, R.Key), new Seg($"  {Fmt.Hx(p)}  {len:N0} bytes  ", R.Dim), new Seg(Fmt.Clean(det), R.Str));
                    if (id == "EXIF") TiffParser.ParseTiff(s, d, ctx, s.Match(data, "Exif\0\0") ? data + 6 : data, "EXIF metadata (WebP)");
                }
                if (len > s.Length) { d.Warn("Chunk length exceeds file size"); return; }
                p = data + len + (len & 1);
            }
        }
        Walk(12, Math.Min(s.Length, size + 8L), 0);
        if (size + 8L < s.Length - 1) ctx.Warn("RIFF", $"{Fmt.Human(s.Length - size - 8)} of data after the RIFF container", size + 8L);
    }

    static string InfoName(string k) => k switch
    {
        "INAM" => "Title (INAM)", "IART" => "Artist (IART)", "ICMT" => "Comment (ICMT)", "ICRD" => "Date (ICRD)", "ISFT" => "Software (ISFT)", "IGNR" => "Genre (IGNR)",
        "ICOP" => "Copyright (ICOP)", "IPRD" => "Product (IPRD)", "IENG" => "Engineer (IENG)", "ITRK" => "Track (ITRK)", "ISRC" => "Source (ISRC)", _ => k
    };
}

public static class IsoBmffParser
{
    static readonly HashSet<string> Containers = new() { "moov", "trak", "mdia", "minf", "stbl", "dinf", "edts", "udta", "mvex", "moof", "traf", "mfra", "ilst", "sinf", "schi", "iprp", "ipco", "tref", "gmhd", "stsd_", "wave", "tapt" };

    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        d.H("ISO base media box tree");
        int count = 0;
        void Walk(long p, long end, int depth, string parent)
        {
            while (p + 8 <= end && count < 5000 && depth < 14)
            {
                long size = s.U32(p, true);
                string type = Encoding.Latin1.GetString(s.Bytes(p + 4, 4));
                long hdr = 8;
                if (size == 1) { size = (long)s.U64(p + 8, true); hdr = 16; }
                else if (size == 0) size = end - p;
                if (size < hdr || p + size > end + 8) { d.Warn($"Invalid box size at {Fmt.Hx(p)}"); return; }
                count++;
                long c = p + hdr;
                string ind = new string(' ', 2 + depth * 2);
                string det = Detail(s, ctx, type, c, size - hdr, parent);
                d.Add(p, new Seg(ind + Fmt.Clean(type), R.Key), new Seg($"  {size:N0} bytes  ", R.Dim), new Seg(Fmt.Clean(det, 300), R.Str));
                if (Containers.Contains(type) || (parent == "ilst")) Walk(c, p + size, depth + 1, type);
                else if (type == "meta") Walk(c + (s.Match(c + 4, "hdlr") ? 0 : 4), p + size, depth + 1, type);
                else if (type == "stsd") WalkStsd(c, p + size, depth + 1);
                p += size;
            }
        }
        void WalkStsd(long c, long end, int depth)
        {
            uint n = s.U32(c + 4, true);
            long q = c + 8;
            for (int i = 0; i < Math.Min(n, 16u) && q + 8 <= end; i++)
            {
                long sz = s.U32(q, true);
                string fmt = s.Fixed(q + 4, 4);
                string det = fmt is "avc1" or "hvc1" or "hev1" or "mp4v" or "av01" or "vp09" or "jpeg" or "mjpa" or "apcn" or "apch"
                    ? $"video codec, {s.U16(q + 32, true)}×{s.U16(q + 34, true)}"
                    : fmt is "mp4a" or "alac" or "Opus" or "ac-3" or "ec-3" or "fLaC" or "sowt" or "twos" or "lpcm" ? $"audio codec, {s.U16(q + 24, true)} ch, {s.U16(q + 26, true)}-bit, {s.U32(q + 32, true) >> 16} Hz" : "sample entry";
                d.Add(q, new Seg(new string(' ', 2 + depth * 2) + fmt, R.Accent), new Seg($"  {sz:N0} bytes  ", R.Dim), new Seg(det, R.Str));
                if (sz < 8) break;
                q += sz;
            }
        }
        Walk(0, s.Length, 0, "");
        if (count >= 5000) d.T("  … box listing truncated", R.Dim);
    }

    static string Detail(ByteSource s, Ctx ctx, string type, long c, long len, string parent)
    {
        try
        {
            switch (type)
            {
                case "ftyp":
                    var brands = new List<string>();
                    for (long i = 8; i + 4 <= len && brands.Count < 20; i += 4) brands.Add(s.Fixed(c + i, 4));
                    return $"major '{s.Fixed(c, 4)}' v{s.U32(c + 4, true)}, compatible: {string.Join(" ", brands)}";
                case "mvhd":
                    {
                        byte v = s.U8(c);
                        ulong ct = v == 1 ? s.U64(c + 4, true) : s.U32(c + 4, true), mt = v == 1 ? s.U64(c + 12, true) : s.U32(c + 8, true);
                        uint ts = v == 1 ? s.U32(c + 20, true) : s.U32(c + 12, true); ulong du = v == 1 ? s.U64(c + 24, true) : s.U32(c + 16, true);
                        string dur = ts > 0 ? TimeSpan.FromSeconds((double)du / ts).ToString(@"hh\:mm\:ss\.fff") : "?";
                        ctx.Info("Media", $"Movie created {Fmt.Mac1904(ct)}");
                        return $"duration {dur}, created {Fmt.Mac1904(ct)}, modified {Fmt.Mac1904(mt)}";
                    }
                case "tkhd":
                    {
                        byte v = s.U8(c);
                        long wo = c + (v == 1 ? 88 : 76);
                        uint id = s.U32(c + (v == 1 ? 20 : 12), true);
                        return $"track {id}, {s.U32(wo, true) >> 16}×{s.U32(wo + 4, true) >> 16}";
                    }
                case "mdhd":
                    {
                        byte v = s.U8(c);
                        uint ts = v == 1 ? s.U32(c + 20, true) : s.U32(c + 12, true); ulong du = v == 1 ? s.U64(c + 24, true) : s.U32(c + 16, true);
                        ushort lang = s.U16(c + (v == 1 ? 32 : 20), true);
                        string l = new string(new[] { (char)(((lang >> 10) & 31) + 0x60), (char)(((lang >> 5) & 31) + 0x60), (char)((lang & 31) + 0x60) });
                        return $"timescale {ts}, duration {(ts > 0 ? (double)du / ts : 0):0.###} s, language '{l}'";
                    }
                case "hdlr": return $"handler '{s.Fixed(c + 8, 4)}' {s.Ascii(c + 24, (int)Math.Min(len - 24, 128))}";
                case "mdat": return "media data";
                case "free" or "skip": return "padding";
                case "©xyz":
                    {
                        string loc = s.Fixed(c + 4, (int)Math.Min(len - 4, 64));
                        ctx.Bad("Privacy", "Video contains a GPS location: " + loc);
                        return "GPS location " + loc;
                    }
                case "data" when parent != "":
                    {
                        uint dt = s.U32(c, true);
                        if (dt == 1) { string v = Encoding.UTF8.GetString(s.Bytes(c + 8, Math.Min(len - 8, 2048))); ctx.ExtraStrings.Add(v); return "= " + v; }
                        if (dt is 13 or 14) return $"embedded image ({Fmt.Size(len - 8)})";
                        if (dt is 21 or 22 or 0) return "= " + Fmt.Bytes(s.Bytes(c + 8, Math.Min(len - 8, 16)), 16);
                        return $"type {dt}";
                    }
                case "uuid": return "uuid " + Fmt.Guid(s.Bytes(c, 16));
                case "ispe": return $"image {s.U32(c + 4, true)}×{s.U32(c + 8, true)}";
                case "elst": return $"{s.U32(c + 4, true)} edit(s)";
                case "stts" or "stss" or "stsz" or "stco" or "co64" or "stsc" or "ctts": return $"{s.U32(c + 4 + (type == "stsz" ? 4 : 0), true):N0} entries";
            }
            if (parent == "ilst") return IlstName(type);
        }
        catch (EndOfDataException) { return "(truncated)"; }
        return "";
    }

    static string IlstName(string t) => t switch
    {
        "©nam" => "title", "©ART" => "artist", "©alb" => "album", "©day" => "date", "©too" => "encoder", "©cmt" => "comment", "©gen" => "genre",
        "©wrt" => "composer", "aART" => "album artist", "covr" => "cover art", "trkn" => "track number", "cprt" => "copyright", "desc" => "description", "©swr" => "software", _ => ""
    };
}

public static class Mp3Parser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        long audio = 0;
        if (s.Match(0, "ID3"))
        {
            byte major = s.U8(3), flags = s.U8(5);
            long size = Syncsafe(s, 6);
            audio = 10 + size + ((flags & 0x10) != 0 ? 10 : 0);
            d.H($"ID3v2.{major}.{s.U8(4)} tag");
            d.KV("Tag size", Fmt.Size(size), R.Num, 6);
            d.KV("Flags", Fmt.Flags(flags, new (ulong, string)[] { (0x80, "UNSYNCHRONISATION"), (0x40, "EXTENDED_HEADER"), (0x20, "EXPERIMENTAL"), (0x10, "FOOTER") }), R.Value, 5);
            long p = 10;
            if ((flags & 0x40) != 0) p += major == 4 ? Syncsafe(s, p) : s.U32(p, true) + 4;
            long end = 10 + size;
            int n = 0;
            while (p + (major == 2 ? 6 : 10) <= end && n < 2000)
            {
                string id; long fs; int hl;
                if (major == 2) { id = s.Fixed(p, 3); fs = s.U24(p + 3, true); hl = 6; }
                else { id = s.Fixed(p, 4); fs = major == 4 ? Syncsafe(s, p + 4) : s.U32(p + 4, true); hl = 10; }
                if (id.Length == 0 || id[0] == '\0' || fs <= 0 || p + hl + fs > end) break;
                long data = p + hl;
                string v = Frame(s, id, data, fs);
                d.KV($"{id} {FrameName(id)}", v, id.StartsWith("W") || id == "PRIV" || id == "GEOB" ? R.Warn : R.Str, data);
                ctx.ExtraStrings.Add(v);
                p = data + fs; n++;
            }
        }
        // first MPEG frame
        var buf = s.Bytes(audio, 128 * 1024);
        for (int i = 0; i + 4 < buf.Length; i++)
        {
            if (buf[i] != 0xFF || (buf[i + 1] & 0xE0) != 0xE0) continue;
            int ver = (buf[i + 1] >> 3) & 3, layer = (buf[i + 1] >> 1) & 3, bri = buf[i + 2] >> 4, sri = (buf[i + 2] >> 2) & 3, mode = buf[i + 3] >> 6;
            if (ver == 1 || layer == 0 || bri == 0 || bri == 15 || sri == 3) continue;
            int[] br1 = { 0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320 }, br2 = { 0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160 };
            int[][] srs = { new[] { 11025, 12000, 8000 }, null, new[] { 22050, 24000, 16000 }, new[] { 44100, 48000, 32000 } };
            int br = (ver == 3 && layer == 1) ? br1[bri] : br2[bri];
            if (ver != 3 && layer != 1) br = br2[bri];
            if (ver == 3 && layer != 1) br = layer == 2 ? new[] { 0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384 }[bri] : new[] { 0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448 }[bri];
            int sr = srs[ver][sri];
            long at = audio + i;
            d.H("First MPEG audio frame");
            d.KV("Offset", Fmt.Hx(at), R.Offset, at);
            d.KV("Version / layer", $"MPEG-{(ver == 3 ? "1" : ver == 2 ? "2" : "2.5")} Layer {(4 - layer) switch { 1 => "I", 2 => "II", _ => "III" }}", R.Value);
            d.KV("Bitrate / sample rate", $"{br} kbit/s / {sr} Hz", R.Value);
            d.KV("Channel mode", mode switch { 0 => "stereo", 1 => "joint stereo", 2 => "dual channel", _ => "mono" }, R.Value);
            var fr = Encoding.ASCII.GetString(buf, i, Math.Min(200, buf.Length - i));
            bool vbr = fr.Contains("Xing") || fr.Contains("Info") || fr.Contains("VBRI");
            d.KV("VBR header", vbr ? "yes (Xing/Info/VBRI)" : "no (CBR assumed)", R.Value);
            long audioLen = s.Length - at - (s.Length > 128 && s.Match(s.Length - 128, "TAG") ? 128 : 0);
            if (br > 0) d.KV("Estimated duration", TimeSpan.FromSeconds(audioLen * 8.0 / (br * 1000)).ToString(@"hh\:mm\:ss") + (vbr ? " (rough, VBR)" : ""), R.Value);
            var rt = ctx.Refined ?? new FileType(); rt.Name = $"MP3 audio, {br} kbit/s, {sr} Hz"; ctx.Refined = rt;
            break;
        }
        if (s.Length > 128 && s.Match(s.Length - 128, "TAG"))
        {
            long t = s.Length - 128;
            d.H("ID3v1 tag");
            d.KV("Title", s.Fixed(t + 3, 30), R.Str, t + 3);
            d.KV("Artist", s.Fixed(t + 33, 30), R.Str);
            d.KV("Album", s.Fixed(t + 63, 30), R.Str);
            d.KV("Year", s.Fixed(t + 93, 4), R.Str);
            d.KV("Comment", s.Fixed(t + 97, 30), R.Str);
            d.KV("Genre", s.U8(t + 127), R.Num);
        }
    }

    static long Syncsafe(ByteSource s, long p) => (s.U8(p) & 0x7F) << 21 | (s.U8(p + 1) & 0x7F) << 14 | (s.U8(p + 2) & 0x7F) << 7 | (s.U8(p + 3) & 0x7F);

    static string Frame(ByteSource s, string id, long p, long len)
    {
        var b = s.Bytes(p, Math.Min(len, 16384));
        if (b.Length == 0) return "";
        Encoding Enc(byte e) => e switch { 1 => Encoding.Unicode, 2 => Encoding.BigEndianUnicode, 3 => Encoding.UTF8, _ => Encoding.Latin1 };
        string Dec(byte e, byte[] x, int o) { if (o >= x.Length) return ""; string r = Enc(e).GetString(x, o, x.Length - o); return r.TrimStart('﻿').Replace("\0", " / ").Trim(' ', '/'); }
        if (id is "APIC" or "PIC")
        {
            int z = Array.IndexOf(b, (byte)0, 1);
            string mime = z > 0 ? Encoding.Latin1.GetString(b, 1, z - 1) : "?";
            return $"embedded picture ({mime}, {Fmt.Size(len)})";
        }
        if (id == "PRIV") { int z = Array.IndexOf(b, (byte)0); return $"private data owner '{(z > 0 ? Encoding.Latin1.GetString(b, 0, z) : "")}' ({len} bytes)"; }
        if (id == "GEOB") return $"encapsulated object ({Fmt.Size(len)})";
        if (id[0] == 'T' || id is "COMM" or "USLT" or "TXXX" or "COM" or "ULT")
        {
            byte e = b[0];
            if (id is "COMM" or "USLT" or "COM" or "ULT") return Dec(e, b, 4);
            return Dec(e, b, 1);
        }
        if (id[0] == 'W') return id == "WXXX" ? Dec(b[0], b, 1) : Encoding.Latin1.GetString(b).TrimEnd('\0');
        return $"({len} bytes) " + Fmt.Bytes(b, 16);
    }

    static string FrameName(string id) => id switch
    {
        "TIT2" or "TT2" => "(title)", "TPE1" or "TP1" => "(artist)", "TALB" or "TAL" => "(album)", "TYER" or "TDRC" or "TYE" => "(year)", "TCON" or "TCO" => "(genre)",
        "COMM" or "COM" => "(comment)", "TRCK" or "TRK" => "(track)", "TENC" or "TEN" => "(encoded by)", "TSSE" or "TSS" => "(encoder settings)", "APIC" or "PIC" => "(picture)",
        "TCOP" => "(copyright)", "TPE2" => "(album artist)", "TCOM" => "(composer)", "USLT" => "(lyrics)", "TXXX" => "(user text)", "WXXX" => "(user URL)", "PRIV" => "(private)", _ => ""
    };
}

public static class FlacParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        d.H("FLAC metadata blocks");
        long p = 4;
        for (int i = 0; i < 1000 && s.Has(p, 4); i++)
        {
            byte h = s.U8(p); bool last = (h & 0x80) != 0; int type = h & 0x7F;
            uint len = s.U24(p + 1, true);
            long c = p + 4;
            string tn = type switch { 0 => "STREAMINFO", 1 => "PADDING", 2 => "APPLICATION", 3 => "SEEKTABLE", 4 => "VORBIS_COMMENT", 5 => "CUESHEET", 6 => "PICTURE", _ => "type " + type };
            d.Sub($"{tn}  ({len:N0} bytes)", p);
            if (type == 0)
            {
                var b = s.Bytes(c + 10, 8);
                long v = 0; foreach (var x in b) v = v << 8 | x;
                int sr = (int)(v >> 44), ch = (int)((v >> 41) & 7) + 1, bps = (int)((v >> 36) & 31) + 1; long total = v & 0xFFFFFFFFFL;
                d.KV("    Sample rate / channels / bits", $"{sr} Hz / {ch} / {bps}", R.Value, c + 10);
                if (sr > 0) d.KV("    Duration", TimeSpan.FromSeconds((double)total / sr).ToString(@"hh\:mm\:ss\.fff"), R.Value);
                d.KV("    Audio MD5", Fmt.HexStr(s.Bytes(c + 18, 16)), R.Hex);
                var rt = ctx.Refined ?? new FileType(); rt.Name = $"FLAC audio, {sr} Hz, {ch} ch, {bps}-bit"; ctx.Refined = rt;
            }
            else if (type == 4)
            {
                uint vl = s.U32(c); d.KV("    Vendor", s.Fixed(c + 4, (int)Math.Min(vl, 512u)), R.Str);
                long q = c + 4 + vl; uint n = s.U32(q); q += 4;
                for (int k = 0; k < Math.Min(n, 500u); k++)
                {
                    uint l = s.U32(q); string kv = Encoding.UTF8.GetString(s.Bytes(q + 4, Math.Min(l, 4096u)));
                    int eq = kv.IndexOf('=');
                    d.KV("    " + (eq > 0 ? kv[..eq] : "?"), eq > 0 ? kv[(eq + 1)..] : kv, R.Str, q);
                    ctx.ExtraStrings.Add(kv);
                    q += 4 + l;
                }
            }
            else if (type == 6)
            {
                uint ml = s.U32(c + 4, true); string mime = s.Fixed(c + 8, (int)Math.Min(ml, 128u));
                d.KV("    Picture", mime, R.Str, c);
            }
            p = c + len;
            if (last) break;
        }
        d.KV("Audio frames start", Fmt.Hx(p), R.Offset, p);
    }
}
