using System.IO.Compression;
using System.Text;
using Ufi.Core;

namespace Ufi.Parsers;

public static class PngParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        d.H("PNG chunks");
        d.Th(new C("Offset", 10), new C("Type", 5), new C("Length", 10, R.Dim, true), new C("CRC", 9), new C("Details", 60));
        long p = 8; int n = 0; long iend = -1; int idat = 0; long idatBytes = 0;
        var texts = new List<(string k, string v, long o)>();
        while (s.Has(p, 12) && n < 100000)
        {
            uint len = s.U32(p, true);
            string type = s.Fixed(p + 4, 4);
            if (len > s.Length) { d.Warn($"Chunk at {Fmt.Hx(p)} declares impossible length {len}"); break; }
            long data = p + 8;
            uint stored = s.Has(data + len, 4) ? s.U32(data + len, true) : 0;
            string crcOk = "";
            if (len < 16 << 20)
            {
                uint calc = StatsRunner.Crc(s.Bytes(p + 4, len + 4));
                crcOk = calc == stored ? "ok" : "BAD";
                if (calc != stored) ctx.Warn("PNG", $"CRC mismatch in {type} chunk (corrupted or modified)", p);
            }
            string det = "";
            switch (type)
            {
                case "IHDR":
                    uint w = s.U32(data, true), h = s.U32(data + 4, true);
                    byte bd = s.U8(data + 8), ct = s.U8(data + 9), il = s.U8(data + 12);
                    string cts = ct switch { 0 => "grayscale", 2 => "RGB", 3 => "palette", 4 => "grayscale+alpha", 6 => "RGBA", _ => ct.ToString() };
                    det = $"{w} × {h}, {bd}-bit {cts}, {(il == 1 ? "Adam7 interlaced" : "non-interlaced")}";
                    var rt = ctx.Refined ?? new FileType(); rt.Name = $"PNG image, {w} × {h}, {cts}"; ctx.Refined = rt;
                    break;
                case "IDAT": idat++; idatBytes += len; break;
                case "tEXt":
                    {
                        var b = s.Bytes(data, Math.Min(len, 1 << 20)); int z = Array.IndexOf(b, (byte)0);
                        if (z > 0) { string k = Encoding.Latin1.GetString(b, 0, z), v = Encoding.Latin1.GetString(b, z + 1, b.Length - z - 1); texts.Add((k, v, data)); det = k + " = " + Fmt.Trunc(v, 60); }
                        break;
                    }
                case "zTXt":
                    {
                        var b = s.Bytes(data, Math.Min(len, 4 << 20)); int z = Array.IndexOf(b, (byte)0);
                        if (z > 0)
                        {
                            string k = Encoding.Latin1.GetString(b, 0, z);
                            string v = Inflate(b.AsSpan(z + 2).ToArray()) is { } dz ? Encoding.Latin1.GetString(dz) : "(decompression failed)";
                            texts.Add((k, v, data)); det = k + " = " + Fmt.Trunc(v, 60);
                        }
                        break;
                    }
                case "iTXt":
                    {
                        var b = s.Bytes(data, Math.Min(len, 4 << 20)); int z = Array.IndexOf(b, (byte)0);
                        if (z > 0 && z + 3 < b.Length)
                        {
                            string k = Encoding.Latin1.GetString(b, 0, z);
                            bool comp = b[z + 1] == 1;
                            int z2 = Array.IndexOf(b, (byte)0, z + 3); int z3 = z2 < 0 ? -1 : Array.IndexOf(b, (byte)0, z2 + 1);
                            if (z3 > 0)
                            {
                                var raw = b.AsSpan(z3 + 1).ToArray();
                                string v = comp ? (Inflate(raw) is { } dz ? Encoding.UTF8.GetString(dz) : "(decompression failed)") : Encoding.UTF8.GetString(raw);
                                texts.Add((k, v, data)); det = k + " = " + Fmt.Trunc(v, 60);
                            }
                        }
                        break;
                    }
                case "pHYs":
                    uint px = s.U32(data, true), py = s.U32(data + 4, true); byte unit = s.U8(data + 8);
                    det = unit == 1 ? $"{px * 0.0254:0} × {py * 0.0254:0} DPI" : $"{px}:{py} aspect"; break;
                case "tIME": det = $"{s.U16(data, true):0000}-{s.U8(data + 2):00}-{s.U8(data + 3):00} {s.U8(data + 4):00}:{s.U8(data + 5):00}:{s.U8(data + 6):00} (last modified)"; break;
                case "gAMA": det = "gamma " + (s.U32(data, true) / 100000.0).ToString("0.#####"); break;
                case "sRGB": det = "rendering intent " + s.U8(data); break;
                case "iCCP": det = "ICC profile: " + s.Ascii(data, 80); break;
                case "acTL": det = $"APNG animation: {s.U32(data, true)} frames, {(s.U32(data + 4, true) == 0 ? "infinite" : s.U32(data + 4, true).ToString())} plays"; break;
                case "eXIf": det = "EXIF metadata (parsed below)"; break;
                case "PLTE": det = $"{len / 3} palette entries"; break;
                case "bKGD" or "cHRM" or "sBIT" or "tRNS" or "hIST" or "sPLT" or "fcTL" or "fdAT": break;
                case "IEND": iend = p; break;
                default: det = char.IsLower(type[0]) ? "ancillary (private/unknown)" : "CRITICAL unknown chunk"; break;
            }
            if (type != "IDAT" || idat <= 3)
                d.Tr(p, new C(Fmt.Hx(p, 8), 10, R.Offset), new C(type, 5, R.Key), new C(len.ToString("N0"), 10, R.Num, true), new C(crcOk, 9, crcOk == "BAD" ? R.Bad : R.Good), new C(det, 60, R.Str));
            else if (idat == 4) d.T("             … further IDAT chunks omitted", R.Dim);
            if (type == "eXIf") { d.Lines.Add(new Line(-1, new[] { new Seg("", R.Normal) })); }
            n++;
            p = data + len + 4;
            if (type == "IEND") break;
        }
        d.KV("IDAT chunks / bytes", $"{idat} / {Fmt.Size(idatBytes)}", R.Num);
        if (texts.Count > 0)
        {
            d.H("Text metadata");
            foreach (var (k, v, o) in texts)
            {
                if (v.Length > 120 || v.Contains('\n')) { d.KV(k, "", R.Str, o); d.Text(v, R.Str, "      ", 200); }
                else d.KV(k, v, R.Str, o);
                ctx.ExtraStrings.Add(v);
            }
        }
        // eXIf chunk
        p = 8;
        while (s.Has(p, 12))
        {
            uint len = s.U32(p, true); string type = s.Fixed(p + 4, 4);
            if (type == "eXIf") { TiffParser.ParseTiff(s, d, ctx, p + 8, "EXIF (eXIf chunk)"); break; }
            if (type == "IEND" || len > s.Length) break;
            p += 12 + len;
        }
        if (iend >= 0 && iend + 12 < s.Length)
        {
            long t = iend + 12;
            var head = s.Bytes(t, 512);
            string q = Detect.Quick(head);
            d.H("Data after IEND");
            d.KV("Offset / size", $"{Fmt.Hx(t)} / {Fmt.Size(s.Length - t)}", R.Warn, t);
            d.KV("Looks like", q ?? "(unrecognised)", R.Accent);
            ctx.Warn("PNG", $"{Fmt.Human(s.Length - t)} of data hidden after the PNG end marker{(q != null ? " (" + q + ")" : "")}", t);
        }
    }

    public static byte[] Inflate(byte[] zlib)
    {
        try
        {
            using var z = new ZLibStream(new MemoryStream(zlib), CompressionMode.Decompress);
            var ms = new MemoryStream();
            var buf = new byte[16384]; int n;
            while ((n = z.Read(buf)) > 0 && ms.Length < 8 << 20) ms.Write(buf, 0, n);
            return ms.ToArray();
        }
        catch { return null; }
    }
}

public static class TiffParser
{
    static readonly Dictionary<ushort, string> Tags = new()
    {
        [0x00FE] = "NewSubfileType", [0x0100] = "ImageWidth", [0x0101] = "ImageLength", [0x0102] = "BitsPerSample", [0x0103] = "Compression",
        [0x0106] = "PhotometricInterpretation", [0x010D] = "DocumentName", [0x010E] = "ImageDescription", [0x010F] = "Make", [0x0110] = "Model",
        [0x0111] = "StripOffsets", [0x0112] = "Orientation", [0x0115] = "SamplesPerPixel", [0x0116] = "RowsPerStrip", [0x0117] = "StripByteCounts",
        [0x011A] = "XResolution", [0x011B] = "YResolution", [0x011C] = "PlanarConfiguration", [0x0128] = "ResolutionUnit", [0x0131] = "Software",
        [0x0132] = "DateTime", [0x013B] = "Artist", [0x013C] = "HostComputer", [0x013E] = "WhitePoint", [0x013F] = "PrimaryChromaticities",
        [0x0201] = "JPEGInterchangeFormat (thumbnail)", [0x0202] = "JPEGInterchangeFormatLength", [0x0211] = "YCbCrCoefficients", [0x0213] = "YCbCrPositioning",
        [0x0214] = "ReferenceBlackWhite", [0x02BC] = "XMP", [0x8298] = "Copyright", [0x829A] = "ExposureTime", [0x829D] = "FNumber", [0x83BB] = "IPTC-NAA",
        [0x8769] = "ExifIFD", [0x8773] = "ICC profile", [0x8822] = "ExposureProgram", [0x8825] = "GPSInfoIFD", [0x8827] = "ISOSpeedRatings",
        [0x8830] = "SensitivityType", [0x9000] = "ExifVersion", [0x9003] = "DateTimeOriginal", [0x9004] = "DateTimeDigitized", [0x9010] = "OffsetTime",
        [0x9011] = "OffsetTimeOriginal", [0x9012] = "OffsetTimeDigitized", [0x9101] = "ComponentsConfiguration", [0x9102] = "CompressedBitsPerPixel",
        [0x9201] = "ShutterSpeedValue", [0x9202] = "ApertureValue", [0x9203] = "BrightnessValue", [0x9204] = "ExposureBiasValue", [0x9205] = "MaxApertureValue",
        [0x9206] = "SubjectDistance", [0x9207] = "MeteringMode", [0x9208] = "LightSource", [0x9209] = "Flash", [0x920A] = "FocalLength", [0x9214] = "SubjectArea",
        [0x927C] = "MakerNote", [0x9286] = "UserComment", [0x9290] = "SubSecTime", [0x9291] = "SubSecTimeOriginal", [0x9292] = "SubSecTimeDigitized",
        [0x9C9B] = "XPTitle", [0x9C9C] = "XPComment", [0x9C9D] = "XPAuthor", [0x9C9E] = "XPKeywords", [0x9C9F] = "XPSubject",
        [0xA000] = "FlashpixVersion", [0xA001] = "ColorSpace", [0xA002] = "PixelXDimension", [0xA003] = "PixelYDimension", [0xA004] = "RelatedSoundFile",
        [0xA005] = "InteropIFD", [0xA20E] = "FocalPlaneXResolution", [0xA20F] = "FocalPlaneYResolution", [0xA210] = "FocalPlaneResolutionUnit",
        [0xA215] = "ExposureIndex", [0xA217] = "SensingMethod", [0xA300] = "FileSource", [0xA301] = "SceneType", [0xA302] = "CFAPattern",
        [0xA401] = "CustomRendered", [0xA402] = "ExposureMode", [0xA403] = "WhiteBalance", [0xA404] = "DigitalZoomRatio", [0xA405] = "FocalLengthIn35mmFilm",
        [0xA406] = "SceneCaptureType", [0xA407] = "GainControl", [0xA408] = "Contrast", [0xA409] = "Saturation", [0xA40A] = "Sharpness",
        [0xA40C] = "SubjectDistanceRange", [0xA420] = "ImageUniqueID", [0xA430] = "CameraOwnerName", [0xA431] = "BodySerialNumber",
        [0xA432] = "LensSpecification", [0xA433] = "LensMake", [0xA434] = "LensModel", [0xA435] = "LensSerialNumber", [0xC4A5] = "PrintIM",
        [0xC612] = "DNGVersion", [0xC614] = "UniqueCameraModel", [0x0001] = "InteropIndex", [0x0002] = "InteropVersion",
    };
    static readonly Dictionary<ushort, string> GpsTags = new()
    {
        [0] = "GPSVersionID", [1] = "GPSLatitudeRef", [2] = "GPSLatitude", [3] = "GPSLongitudeRef", [4] = "GPSLongitude", [5] = "GPSAltitudeRef",
        [6] = "GPSAltitude", [7] = "GPSTimeStamp", [8] = "GPSSatellites", [9] = "GPSStatus", [10] = "GPSMeasureMode", [11] = "GPSDOP", [12] = "GPSSpeedRef",
        [13] = "GPSSpeed", [14] = "GPSTrackRef", [15] = "GPSTrack", [16] = "GPSImgDirectionRef", [17] = "GPSImgDirection", [18] = "GPSMapDatum",
        [23] = "GPSDestBearingRef", [24] = "GPSDestBearing", [27] = "GPSProcessingMethod", [29] = "GPSDateStamp", [30] = "GPSDifferential", [31] = "GPSHPositioningError",
    };
    static readonly int[] TypeSize = { 0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8, 4 };

    public static void Parse(ByteSource s, Doc d, Ctx ctx) => ParseTiff(s, d, ctx, 0, "TIFF image file directories");

    public static void ParseTiff(ByteSource s, Doc d, Ctx ctx, long b, string title)
    {
        bool be = s.Match(b, "MM");
        if (!be && !s.Match(b, "II")) { d.Warn("Not a TIFF header at " + Fmt.Hx(b)); return; }
        ushort magic = s.U16(b + 2, be);
        d.H(title);
        d.KV("Byte order", be ? "MM (Motorola, big-endian)" : "II (Intel, little-endian)", R.Value, b);
        if (magic == 43) { d.Info("BigTIFF (64-bit offsets) – IFD listing not supported"); return; }
        uint first = s.U32(b + 4, be);
        var seen = new HashSet<long>();
        double? lat = null, lon = null; string latRef = "N", lonRef = "E";
        int ifdNo = 0;
        void Ifd(long off, string name, bool gps, int depth)
        {
            if (off <= 0 || depth > 6 || !seen.Add(off) || !s.Has(b + off, 2)) return;
            long p = b + off;
            int count = s.U16(p, be);
            d.Sub($"{name}  ({count} entries at {Fmt.Hx(p)})", p);
            var subs = new List<(long, string, bool)>();
            for (int i = 0; i < Math.Min(count, 1000); i++)
            {
                long e = p + 2 + i * 12L;
                if (!s.Has(e, 12)) break;
                ushort tag = s.U16(e, be), type = s.U16(e + 2, be);
                uint cnt = s.U32(e + 4, be);
                int ts = type < TypeSize.Length ? TypeSize[type] : 1;
                long total = (long)ts * cnt;
                long vo = total <= 4 ? e + 8 : b + s.U32(e + 8, be);
                string tn = gps ? Fmt.Lookup(GpsTags, tag, $"GPS tag {Fmt.Hx(tag, 4)}") : Fmt.Lookup(Tags, tag, $"Tag {Fmt.Hx(tag, 4)}");
                string val = Value(s, vo, type, cnt, be, tag);
                if (tag == 0x8769) subs.Add((s.U32(e + 8, be), "Exif IFD", false));
                else if (tag == 0x8825) subs.Add((s.U32(e + 8, be), "GPS IFD", true));
                else if (tag == 0xA005) subs.Add((s.U32(e + 8, be), "Interoperability IFD", false));
                R role = R.Str;
                if (gps)
                {
                    role = R.Warn;
                    if (tag == 1) latRef = val.Trim(); if (tag == 3) lonRef = val.Trim();
                    if ((tag == 2 || tag == 4) && type == 5 && cnt >= 3)
                    {
                        double Rat(long o) { uint n = s.U32(o, be), dd = s.U32(o + 4, be); return dd == 0 ? 0 : (double)n / dd; }
                        double v = Rat(vo) + Rat(vo + 8) / 60 + Rat(vo + 16) / 3600;
                        if (tag == 2) lat = v; else lon = v;
                    }
                }
                if (tag is 0xA431 or 0xA435 or 0xA430 or 0x013B or 0x9C9D or 0x013C) role = R.Warn;
                d.KV("    " + tn, val, role, vo);
                if (tag is 0x010F or 0x0110 or 0x0131 or 0x013B or 0x9003 or 0xA431 or 0xA430 or 0x8298 or 0xA434) ctx.ExtraStrings.Add(val);
            }
            long next = s.Has(p + 2 + count * 12L, 4) ? s.U32(p + 2 + count * 12L, be) : 0;
            foreach (var (o, n, g) in subs) Ifd(o, n, g, depth + 1);
            if (next != 0 && depth == 0) { ifdNo++; Ifd(next, $"IFD{ifdNo}" + (ifdNo == 1 ? " (thumbnail)" : ""), false, 0); }
        }
        Ifd(first, "IFD0 (main image)", false, 0);
        if (lat != null && lon != null)
        {
            double la = latRef.StartsWith("S") ? -lat.Value : lat.Value, lo = lonRef.StartsWith("W") ? -lon.Value : lon.Value;
            string pos = $"{la:0.000000}, {lo:0.000000}";
            d.KV("  ► GPS position (decimal)", pos, R.Bad);
            ctx.Bad("Privacy", $"Photo contains GPS coordinates: {pos}  (maps: https://www.openstreetmap.org/?mlat={la:0.######}&mlon={lo:0.######})");
        }
        var names = new[] { "Make", "Model" };
        if (d.Lines.Any(l => l.Plain.Contains("BodySerialNumber"))) ctx.Warn("Privacy", "Photo contains the camera body serial number");
        _ = names;
    }

    static string Value(ByteSource s, long o, ushort type, uint cnt, bool be, ushort tag)
    {
        try
        {
            if (cnt == 0) return "";
            if (tag == 0x927C) return $"({cnt:N0} bytes, vendor-specific maker note)";
            if (tag is 0x9C9B or 0x9C9C or 0x9C9D or 0x9C9E or 0x9C9F) return Encoding.Unicode.GetString(s.Bytes(o, Math.Min(cnt, 4096u))).TrimEnd('\0');
            if (tag == 0x02BC) return Fmt.Trunc(Encoding.UTF8.GetString(s.Bytes(o, Math.Min(cnt, 4096u))).Replace('\n', ' '), 200);
            switch (type)
            {
                case 2: return s.Fixed(o, (int)Math.Min(cnt, 4096u));
                case 1 or 6: return cnt <= 16 ? string.Join(" ", s.Bytes(o, cnt).Select(x => x.ToString())) : $"({cnt} bytes) " + Fmt.Bytes(s.Bytes(o, 16), 16);
                case 7:
                    var raw = s.Bytes(o, Math.Min(cnt, 256u));
                    if (tag == 0x9286 && raw.Length > 8) return Encoding.ASCII.GetString(raw, 0, 8).TrimEnd('\0') + ": " + Encoding.Latin1.GetString(raw, 8, raw.Length - 8).TrimEnd('\0', ' ');
                    if (raw.All(x => x >= 0x20 && x < 0x7F || x == 0) && raw.Length > 0) return Encoding.ASCII.GetString(raw).TrimEnd('\0');
                    return (cnt > 256 ? $"({cnt:N0} bytes) " : "") + Fmt.Bytes(raw, 24);
                case 3 or 8:
                    return string.Join(", ", Enumerable.Range(0, (int)Math.Min(cnt, 16u)).Select(i => type == 3 ? s.U16(o + i * 2, be).ToString() : ((short)s.U16(o + i * 2, be)).ToString())) + (cnt > 16 ? ", …" : "") + Enum16(tag, cnt == 1 ? s.U16(o, be) : -1);
                case 4 or 9 or 13:
                    return string.Join(", ", Enumerable.Range(0, (int)Math.Min(cnt, 16u)).Select(i => type == 9 ? s.I32(o + i * 4, be).ToString() : s.U32(o + i * 4, be).ToString())) + (cnt > 16 ? ", …" : "");
                case 5 or 10:
                    return string.Join(", ", Enumerable.Range(0, (int)Math.Min(cnt, 8u)).Select(i =>
                    {
                        long n = type == 5 ? s.U32(o + i * 8, be) : s.I32(o + i * 8, be);
                        long dd = type == 5 ? s.U32(o + i * 8 + 4, be) : s.I32(o + i * 8 + 4, be);
                        if (dd == 0) return $"{n}/0";
                        double v = (double)n / dd;
                        if (tag == 0x829A && n < dd && n > 0) return $"1/{(double)dd / n:0.#} s";
                        return dd == 1 ? n.ToString() : $"{v:0.####}";
                    })) + (cnt > 8 ? ", …" : "");
                case 11: return BitConverter.Int32BitsToSingle(s.I32(o, be)).ToString();
                case 12: return BitConverter.Int64BitsToDouble(s.I64(o, be)).ToString();
                default: return Fmt.Bytes(s.Bytes(o, Math.Min(cnt, 16u)), 16);
            }
        }
        catch (EndOfDataException) { return "(value outside file)"; }
    }

    static string Enum16(ushort tag, int v)
    {
        if (v < 0) return "";
        string r = tag switch
        {
            0x0112 => v switch { 1 => "normal", 3 => "rotated 180°", 6 => "rotated 90° CW", 8 => "rotated 90° CCW", 2 => "mirrored", _ => "" },
            0x0103 => v switch { 1 => "uncompressed", 5 => "LZW", 6 => "JPEG (old)", 7 => "JPEG", 8 => "Deflate", 32773 => "PackBits", _ => "" },
            0x0128 or 0xA210 => v switch { 2 => "inch", 3 => "cm", _ => "" },
            0x9207 => v switch { 1 => "average", 2 => "center-weighted", 3 => "spot", 5 => "pattern", _ => "" },
            0xA001 => v switch { 1 => "sRGB", 0xFFFF => "uncalibrated", _ => "" },
            0x8822 => v switch { 1 => "manual", 2 => "program", 3 => "aperture priority", 4 => "shutter priority", _ => "" },
            0x9209 => (v & 1) != 0 ? "flash fired" : "no flash",
            _ => ""
        };
        return r.Length > 0 ? $"  ({r})" : "";
    }
}

public static class JpegParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        d.H("JPEG segments");
        d.Th(new C("Offset", 10), new C("Marker", 7), new C("Name", 8), new C("Length", 8, R.Dim, true), new C("Details", 60));
        long p = 2; long eoi = -1; int n = 0;
        var exif = new List<long>(); var xmp = new List<(long, int)>();
        while (s.Has(p, 2) && n < 10000)
        {
            if (s.U8(p) != 0xFF) { d.Warn($"Expected marker at {Fmt.Hx(p)}, found {Fmt.Hx(s.U8(p), 2)} – stream corrupt"); break; }
            byte m = s.U8(p + 1);
            if (m == 0xFF) { p++; continue; }
            string name = Marker(m);
            if (m == 0xD9) { eoi = p; d.Tr(p, new C(Fmt.Hx(p, 8), 10, R.Offset), new C("FFD9", 7, R.Hex), new C("EOI", 8, R.Key), new C("", 8), new C("end of image", 60, R.Dim)); break; }
            if (m is >= 0xD0 and <= 0xD7 || m == 0x01) { p += 2; continue; }
            ushort len = s.U16(p + 2, true);
            long seg = p + 4;
            string det = "";
            if (m is >= 0xC0 and <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC)
            {
                int h = s.U16(seg + 1, true), w = s.U16(seg + 3, true), comps = s.U8(seg + 5);
                det = $"{w} × {h}, {comps} component(s), {s.U8(seg)}-bit, " + (m switch { 0xC0 => "baseline", 0xC1 => "extended sequential", 0xC2 => "progressive", 0xC3 => "lossless", _ => "SOF" + (m - 0xC0) });
                var rt = ctx.Refined ?? new FileType(); if (!rt.Name.Contains("×")) { rt.Name = $"JPEG image, {w} × {h}"; ctx.Refined = rt; }
            }
            else if (m == 0xE0 && s.Match(seg, "JFIF\0")) det = $"JFIF {s.U8(seg + 5)}.{s.U8(seg + 6):00}, density {s.U16(seg + 8, true)}×{s.U16(seg + 10, true)} {(s.U8(seg + 7) switch { 1 => "dpi", 2 => "dpcm", _ => "(aspect)" })}";
            else if (m == 0xE1 && s.Match(seg, "Exif\0\0")) { det = "EXIF metadata (TIFF structure)"; exif.Add(seg + 6); }
            else if (m == 0xE1 && s.Match(seg, "http://ns.adobe.com/xap/1.0/\0")) { det = "XMP metadata (XML)"; xmp.Add((seg + 29, len - 31)); }
            else if (m == 0xE2 && s.Match(seg, "ICC_PROFILE\0")) det = $"ICC colour profile chunk {s.U8(seg + 12)}/{s.U8(seg + 13)}, {s.Fixed(seg + 14 + 16, 4)} class {s.Fixed(seg + 14 + 12, 4)}";
            else if (m == 0xED) det = s.Ascii(seg, 14) + " (IPTC / Photoshop resources)";
            else if (m == 0xEE) det = s.Ascii(seg, 5) + " (Adobe)";
            else if (m == 0xFE) { string c = s.Fixed(seg, Math.Min(len - 2, 2000)); det = "comment: " + c; ctx.ExtraStrings.Add(c); ctx.Info("JPEG", "Comment: " + Fmt.Trunc(c, 100), seg); }
            else if (m == 0xDB) det = $"{(len - 2) / 65} quantisation table(s)";
            else if (m == 0xC4) det = "Huffman table(s)";
            else if (m == 0xDD) det = "restart interval " + s.U16(seg, true);
            else if (m is >= 0xE0 and <= 0xEF) det = s.Ascii(seg, 32);
            d.Tr(p, new C(Fmt.Hx(p, 8), 10, R.Offset), new C("FF" + m.ToString("X2"), 7, R.Hex), new C(name, 8, R.Key), new C(len.ToString(), 8, R.Num, true), new C(det, 60, R.Str));
            n++;
            p = seg + len - 2;
            if (m == 0xDA)
            {
                // skip entropy-coded data
                long q = p;
                var buf = new byte[65536];
                bool found = false;
                while (q < s.Length && !found)
                {
                    int got = s.Copy(q, buf);
                    if (got < 2) { q += got; break; }
                    for (int i = 0; i < got - 1; i++)
                    {
                        if (buf[i] == 0xFF && buf[i + 1] != 0 && !(buf[i + 1] >= 0xD0 && buf[i + 1] <= 0xD7) && buf[i + 1] != 0xFF) { q += i; found = true; break; }
                    }
                    if (!found) q += got - 1;
                }
                d.T($"             … entropy-coded scan data {Fmt.Size(q - p)}", R.Dim, p);
                p = q;
            }
        }
        foreach (var e in exif) TiffParser.ParseTiff(s, d, ctx, e, "EXIF metadata");
        foreach (var (o, l) in xmp)
        {
            string x = Encoding.UTF8.GetString(s.Bytes(o, Math.Max(0, Math.Min(l, 262144))));
            d.H("XMP metadata");
            foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(x, @"<(\w+:\w+)>([^<]{1,300})</|(\w+:\w+)=""([^""]{1,300})"""))
            {
                string k = m.Groups[1].Success && m.Groups[1].Value != "" ? m.Groups[1].Value : m.Groups[3].Value;
                string v = m.Groups[2].Success && m.Groups[2].Value != "" ? m.Groups[2].Value : m.Groups[4].Value;
                if (k.StartsWith("xmlns") || k.StartsWith("x:") || k.StartsWith("rdf:")) continue;
                d.KV(k, v, R.Str, o);
                ctx.ExtraStrings.Add(v);
            }
        }
        if (eoi >= 0 && eoi + 2 < s.Length)
        {
            long t = eoi + 2;
            long size = s.Length - t;
            var head = s.Bytes(t, 512);
            string q = Detect.Quick(head);
            d.H("Data after end-of-image marker");
            d.KV("Offset / size", $"{Fmt.Hx(t)} / {Fmt.Size(size)}", R.Warn, t);
            d.KV("Looks like", q ?? (head.All(b => b == 0) ? "zero padding" : "(unrecognised)"), R.Accent);
            if (!head.All(b => b == 0) && size > 16) ctx.Warn("JPEG", $"{Fmt.Human(size)} of data appended after the JPEG end marker{(q != null ? " (" + q + ")" : "")} – possible hidden payload / polyglot", t);
        }
    }

    static string Marker(byte m) => m switch
    {
        0xD8 => "SOI", 0xC4 => "DHT", 0xCC => "DAC", 0xDA => "SOS", 0xDB => "DQT", 0xDD => "DRI", 0xFE => "COM", 0xD9 => "EOI", 0xDC => "DNL",
        >= 0xC0 and <= 0xCF => "SOF" + (m - 0xC0), >= 0xE0 and <= 0xEF => "APP" + (m - 0xE0), _ => Fmt.Hx(m, 2)
    };
}

public static class GifParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        d.H("GIF logical screen");
        ushort w = s.U16(6), h = s.U16(8); byte pk = s.U8(10);
        d.KV("Version", s.Fixed(0, 6), R.Value, 0);
        d.KV("Canvas", $"{w} × {h}", R.Value, 6);
        bool gct = (pk & 0x80) != 0; int gsz = gct ? 3 << ((pk & 7) + 1) : 0;
        d.KV("Global colour table", gct ? $"{gsz / 3} colours" : "none", R.Value, 10);
        d.KV("Background index / aspect", $"{s.U8(11)} / {s.U8(12)}", R.Num);
        long p = 13 + gsz; int frames = 0; long delay = 0; int loops = -1;
        d.H("Blocks");
        while (s.Has(p, 1))
        {
            byte b = s.U8(p);
            if (b == 0x3B) { d.T($"  {Fmt.Hx(p, 8)}  trailer", R.Dim, p); p++; break; }
            if (b == 0x2C)
            {
                frames++;
                ushort fw = s.U16(p + 5), fh = s.U16(p + 7); byte fp = s.U8(p + 9);
                if (frames <= 50) d.T($"  {Fmt.Hx(p, 8)}  image #{frames}: {fw}×{fh} at ({s.U16(p + 1)},{s.U16(p + 3)}){((fp & 0x40) != 0 ? " interlaced" : "")}{((fp & 0x80) != 0 ? " local palette" : "")}", R.Str, p);
                p += 10;
                if ((fp & 0x80) != 0) p += 3 << ((fp & 7) + 1);
                p++; // LZW min code size
                p = SkipSub(s, p);
            }
            else if (b == 0x21)
            {
                byte label = s.U8(p + 1);
                long q = p + 2;
                if (label == 0xF9) { delay += s.U16(q + 2) * 10L; }
                else if (label == 0xFE)
                {
                    var sb = new StringBuilder(); long r = q;
                    while (s.Has(r, 1) && s.U8(r) != 0 && sb.Length < 4000) { int n = s.U8(r); sb.Append(Encoding.Latin1.GetString(s.Bytes(r + 1, n))); r += 1 + n; }
                    d.KV("  Comment", sb.ToString(), R.Str, p); ctx.ExtraStrings.Add(sb.ToString());
                }
                else if (label == 0xFF)
                {
                    string app = s.Fixed(q + 1, 11);
                    if (app == "NETSCAPE2.0") loops = s.U16(q + 14);
                    d.T($"  {Fmt.Hx(p, 8)}  application extension: {app}", R.Dim, p);
                }
                p = SkipSub(s, q);
            }
            else { d.Warn($"Unknown block {Fmt.Hx(b, 2)} at {Fmt.Hx(p)}"); break; }
        }
        d.KV("Frames", frames, R.Num);
        if (frames > 1) d.KV("Animation length", $"{delay / 1000.0:0.00} s, loops: {(loops == 0 ? "infinite" : loops < 0 ? "once" : loops.ToString())}", R.Value);
        var rt = ctx.Refined ?? new FileType(); rt.Name = $"GIF image, {w} × {h}{(frames > 1 ? $", {frames} frames (animated)" : "")}"; ctx.Refined = rt;
        if (p < s.Length) { ctx.Warn("GIF", $"{Fmt.Human(s.Length - p)} of data after the GIF trailer", p); d.KV("Trailing data", Fmt.Size(s.Length - p), R.Warn, p); }
    }

    static long SkipSub(ByteSource s, long p)
    {
        while (s.Has(p, 1)) { int n = s.U8(p); p++; if (n == 0) break; p += n; }
        return p;
    }
}

public static class BmpParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        d.H("BITMAPFILEHEADER");
        d.KV("Declared file size", Fmt.Size(s.U32(2)), s.U32(2) == s.Length ? R.Value : R.Warn, 2);
        d.KV("Pixel data offset", Fmt.Hx(s.U32(10)), R.Offset, s.U32(10));
        uint hs = s.U32(14);
        d.H("DIB header (" + (hs switch { 12 => "BITMAPCOREHEADER", 40 => "BITMAPINFOHEADER", 108 => "BITMAPV4HEADER", 124 => "BITMAPV5HEADER", _ => hs + " bytes" }) + ")");
        if (hs == 12) { d.KV("Size", $"{s.U16(18)} × {s.U16(20)}", R.Value); d.KV("Bits per pixel", s.U16(24), R.Num); return; }
        int w = s.I32(18), h = s.I32(22);
        d.KV("Width × height", $"{w} × {Math.Abs(h)} ({(h < 0 ? "top-down" : "bottom-up")})", R.Value, 18);
        d.KV("Planes / bpp", $"{s.U16(26)} / {s.U16(28)}", R.Num, 26);
        uint comp = s.U32(30);
        d.KV("Compression", comp switch { 0 => "BI_RGB (none)", 1 => "BI_RLE8", 2 => "BI_RLE4", 3 => "BI_BITFIELDS", 4 => "BI_JPEG", 5 => "BI_PNG", 6 => "BI_ALPHABITFIELDS", _ => comp.ToString() }, R.Value, 30);
        d.KV("Image size", Fmt.Size(s.U32(34)), R.Num);
        d.KV("Resolution (px/m)", $"{s.I32(38)} × {s.I32(42)}  (≈ {s.I32(38) * 0.0254:0} dpi)", R.Value);
        d.KV("Colours used / important", $"{s.U32(46)} / {s.U32(50)}", R.Num);
        var rt = ctx.Refined ?? new FileType(); rt.Name = $"BMP image, {w} × {Math.Abs(h)}, {s.U16(28)} bpp"; ctx.Refined = rt;
        if (s.U32(2) < s.Length && s.U32(2) > 54) ctx.Warn("BMP", $"{Fmt.Human(s.Length - s.U32(2))} of data after the declared bitmap size", s.U32(2));
    }
}

public static class IcoParser
{
    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        bool cur = s.U16(2) == 2;
        int n = s.U16(4);
        d.H((cur ? "Cursor" : "Icon") + $" directory ({n} images)");
        d.Th(new C("#", 3, R.Dim, true), new C("Size", 10), new C("BPP", 5), new C(cur ? "Hotspot" : "Planes", 9), new C("Bytes", 10, R.Dim, true), new C("Offset", 10), new C("Format", 10));
        for (int i = 0; i < Math.Min(n, 256); i++)
        {
            long e = 6 + i * 16;
            int w = s.U8(e) == 0 ? 256 : s.U8(e), h = s.U8(e + 1) == 0 ? 256 : s.U8(e + 1);
            uint size = s.U32(e + 8), off = s.U32(e + 12);
            string fmt = s.Match(off, "\x89PNG") ? "PNG" : s.Has(off, 4) && s.U32(off) == 40 ? "DIB" : "?";
            d.Tr(off, new C(i.ToString(), 3, R.Dim, true), new C($"{w}×{h}", 10, R.Value), new C(cur ? "" : s.U16(e + 6).ToString(), 5, R.Num),
                new C(cur ? $"{s.U16(e + 4)},{s.U16(e + 6)}" : s.U16(e + 4).ToString(), 9, R.Num), new C(size.ToString("N0"), 10, R.Num, true), new C(Fmt.Hx(off), 10, R.Offset), new C(fmt, 10, R.Key));
        }
    }
}
