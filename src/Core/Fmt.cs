using System.Globalization;
using System.Text;

namespace Ufi.Core;

public static class Fmt
{
    static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    public static string Hx(long v) => "0x" + v.ToString("X", Inv);
    public static string Hx(ulong v) => "0x" + v.ToString("X", Inv);
    public static string Hx(long v, int digits) => "0x" + v.ToString("X" + digits, Inv);
    public static string HxD(long v) => $"0x{v:X} ({v:N0})";

    public static string Human(double n)
    {
        string[] u = { "bytes", "KiB", "MiB", "GiB", "TiB", "PiB" };
        int i = 0;
        while (n >= 1024 && i < u.Length - 1) { n /= 1024; i++; }
        return i == 0 ? $"{n:0} bytes" : $"{n:0.##} {u[i]}";
    }

    public static string Size(long n) => n >= 1024 ? $"{n:N0} bytes ({Human(n)})" : $"{n:N0} bytes";

    public static string Pct(double part, double total) => total <= 0 ? "0%" : (part * 100.0 / total).ToString("0.##", Inv) + "%";

    public static string Bytes(ReadOnlySpan<byte> b, int max = 32, string sep = " ")
    {
        var sb = new StringBuilder();
        int n = Math.Min(max, b.Length);
        for (int i = 0; i < n; i++) { if (i > 0) sb.Append(sep); sb.Append(b[i].ToString("X2")); }
        if (b.Length > max) sb.Append(sep + "…");
        return sb.ToString();
    }

    public static string HexStr(ReadOnlySpan<byte> b) => Convert.ToHexString(b).ToLowerInvariant();

    public static string AsciiPreview(ReadOnlySpan<byte> b, int max = 64)
    {
        var sb = new StringBuilder();
        int n = Math.Min(max, b.Length);
        for (int i = 0; i < n; i++) sb.Append(b[i] >= 0x20 && b[i] < 0x7F ? (char)b[i] : '.');
        return sb.ToString();
    }

    /// <summary>True for characters the monospace grid can render at exactly one cell.</summary>
    public static bool Renderable(char c) =>
        (c >= 0x20 && c < 0x7F) ||
        (c >= 0xA1 && c <= 0x24F && c != 0xAD) ||
        (c >= 0x370 && c <= 0x4FF) ||
        (c >= 0x2010 && c <= 0x2027) || (c >= 0x2030 && c <= 0x205E) ||
        (c >= 0x2190 && c <= 0x21FF) || (c >= 0x2200 && c <= 0x22FF) ||
        (c >= 0x2500 && c <= 0x25FF) || c == 0x20AC || c == 0x2122;

    /// <summary>Makes arbitrary (untrusted) text safe for display: control, bidi and wide chars are replaced.</summary>
    public static string Clean(string s, int max = 1000)
    {
        if (string.IsNullOrEmpty(s)) return s ?? "";
        bool ok = s.Length <= max;
        if (ok) foreach (char c in s) if (!Renderable(c)) { ok = false; break; }
        if (ok) return s;
        var sb = new StringBuilder(Math.Min(s.Length, max) + 1);
        foreach (char c in s)
        {
            if (sb.Length >= max) { sb.Append('…'); break; }
            if (Renderable(c)) sb.Append(c);
            else if (c == '\t') sb.Append("    ");
            else if (c == 0x202E || c == 0x202D || c == 0x202A || c == 0x202B || c == 0x202C || c == 0x2066 || c == 0x2067 || c == 0x2068 || c == 0x2069) sb.Append("‹BIDI›");
            else if (c == 0x200B || c == 0x200C || c == 0x200D || c == 0xFEFF) sb.Append("‹ZW›");
            else if (c < 0x20 || c == 0x7F) sb.Append('·');
            else sb.Append('?');
        }
        return sb.ToString();
    }

    /// <summary>Shows every non-ASCII / invisible character in a string as an escape.</summary>
    public static string Escape(string s)
    {
        var sb = new StringBuilder();
        foreach (char c in s)
        {
            if (c >= 0x20 && c < 0x7F) sb.Append(c);
            else sb.Append($"\\u{(int)c:X4}");
        }
        return sb.ToString();
    }

    public static string Time(DateTime utc)
    {
        if (utc.Kind == DateTimeKind.Unspecified) utc = DateTime.SpecifyKind(utc, DateTimeKind.Utc);
        utc = utc.ToUniversalTime();
        return $"{utc:yyyy-MM-dd HH:mm:ss} UTC  (local {utc.ToLocalTime():yyyy-MM-dd HH:mm:ss})";
    }

    public static string Unix(long secs)
    {
        if (secs == 0) return "0 (not set)";
        try { return Time(DateTimeOffset.FromUnixTimeSeconds(secs).UtcDateTime) + $"  [{secs}]"; }
        catch { return $"{secs} (out of range)"; }
    }

    public static string FileTime(long ft)
    {
        if (ft == 0) return "0 (not set)";
        try { return Time(DateTime.FromFileTimeUtc(ft)); }
        catch { return $"{Hx(ft)} (invalid FILETIME)"; }
    }

    public static DateTime? FileTimeOrNull(long ft)
    {
        if (ft <= 0) return null;
        try { return DateTime.FromFileTimeUtc(ft); } catch { return null; }
    }

    public static string DosDateTime(ushort date, ushort time)
    {
        int y = 1980 + (date >> 9), mo = (date >> 5) & 15, d = date & 31;
        int h = time >> 11, mi = (time >> 5) & 63, s = (time & 31) * 2;
        return $"{y:0000}-{mo:00}-{d:00} {h:00}:{mi:00}:{s:00}";
    }

    public static string Mac1904(ulong secs)
    {
        if (secs == 0) return "0 (not set)";
        try { return Time(new DateTime(1904, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(secs)); }
        catch { return secs.ToString(); }
    }

    public static string Flags(ulong value, IEnumerable<(ulong bit, string name)> names)
    {
        var parts = new List<string>();
        ulong known = 0;
        foreach (var (bit, name) in names)
        {
            known |= bit;
            if ((value & bit) != 0) parts.Add(name);
        }
        ulong rest = value & ~known;
        if (rest != 0) parts.Add(Hx(rest));
        return parts.Count == 0 ? "(none)" : string.Join(" | ", parts);
    }

    public static string Lookup<T>(IReadOnlyDictionary<T, string> map, T key, string fallback = "unknown") =>
        map.TryGetValue(key, out var v) ? v : fallback;

    public static string Bar(double frac, int width, char full = '▇', char empty = '░')
    {
        frac = Math.Clamp(frac, 0, 1);
        int n = (int)Math.Round(frac * width);
        return new string(full, n) + new string(empty, width - n);
    }

    public static string Guid(ReadOnlySpan<byte> b) => b.Length >= 16 ? new Guid(b[..16]).ToString("B").ToUpperInvariant() : "";

    public static string Latin1(ReadOnlySpan<byte> b) => Encoding.Latin1.GetString(b);

    public static string Trunc(string s, int n) => s == null ? "" : s.Length <= n ? s : s[..(n - 1)] + "…";
}
