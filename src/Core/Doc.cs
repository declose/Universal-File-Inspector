using System.Text;

namespace Ufi.Core;

/// <summary>Semantic color roles. The UI theme maps each role to a color.</summary>
public enum R : byte
{
    Normal, Dim, Key, Value, Title, Accent, Warn, Bad, Good, Offset,
    Hex, HexZero, HexHigh, Ascii, Num, Str,
    Border, BarFg, BarBg, SelBg, Bg, CursorFg, CursorBg, Track, Thumb, MatchBg, PanelBg
}

/// <summary>A colored text segment.</summary>
public readonly record struct Seg(string Text, R Role);

/// <summary>A table cell: fixed width, optional right alignment.</summary>
public readonly record struct C(string Text, int Width, R Role = R.Normal, bool Right = false);

public sealed class Line
{
    public readonly Seg[] Segs;
    /// <summary>File offset this line refers to (Enter jumps to it in the hex view), or -1.</summary>
    public readonly long Jump;
    string _plain;

    public Line(long jump, Seg[] segs) { Jump = jump; Segs = segs; }

    public string Plain => _plain ??= string.Concat(Segs.Select(s => s.Text));
}

/// <summary>A scrollable, colorable text document produced by the analyzers.</summary>
public sealed class Doc
{
    public const int KeyWidth = 30;
    public readonly List<Line> Lines = new();
    public int Count => Lines.Count;

    public Doc Add(long jump, params Seg[] segs) { Lines.Add(new Line(jump, segs)); return this; }
    public Doc Add(params Seg[] segs) => Add(-1, segs);
    public Doc Blank() => Add(new Seg("", R.Normal));

    public Doc H(string title)
    {
        if (Lines.Count > 0 && Lines[^1].Plain.Length != 0) Blank();
        string t = " " + title.ToUpperInvariant() + " ";
        Add(new Seg("══", R.Border), new Seg(t, R.Title), new Seg(new string('═', Math.Max(4, 76 - t.Length)), R.Border));
        return this;
    }

    public Doc Sub(string title, long jump = -1)
    {
        if (Lines.Count > 0 && Lines[^1].Plain.Length != 0) Blank();
        return Add(jump, new Seg("  ► ", R.Accent), new Seg(Fmt.Clean(title, 300), R.Accent));
    }

    public Doc KV(string key, object val, R role = R.Value, long jump = -1)
    {
        string k = key.Length >= KeyWidth ? key[..(KeyWidth - 1)] + "…" : key.PadRight(KeyWidth);
        return Add(jump, new Seg("  " + k + " ", R.Key), new Seg(Fmt.Clean(val?.ToString() ?? "", 4000), role));
    }

    public Doc T(string text, R role = R.Normal, long jump = -1) => Add(jump, new Seg(Fmt.Clean(text, 4000), role));

    public Doc Text(string multiline, R role = R.Normal, string indent = "    ", int maxLines = 400)
    {
        int n = 0;
        foreach (var l in multiline.Replace("\r\n", "\n").Split('\n'))
        {
            if (++n > maxLines) { T(indent + "… (truncated)", R.Dim); break; }
            T(indent + l.TrimEnd(), role);
        }
        return this;
    }

    public Doc Bad(string t, long jump = -1) => Add(jump, new Seg("  [!!] ", R.Bad), new Seg(Fmt.Clean(t, 2000), R.Bad));
    public Doc Warn(string t, long jump = -1) => Add(jump, new Seg("  [!]  ", R.Warn), new Seg(Fmt.Clean(t, 2000), R.Warn));
    public Doc Info(string t, long jump = -1) => Add(jump, new Seg("  [i]  ", R.Accent), new Seg(Fmt.Clean(t, 2000), R.Normal));
    public Doc Good(string t, long jump = -1) => Add(jump, new Seg("  [ok] ", R.Good), new Seg(Fmt.Clean(t, 2000), R.Good));

    public Doc Th(params C[] cols)
    {
        Tr(-1, cols.Select(c => c with { Role = R.Dim }).ToArray());
        int w = cols.Sum(c => c.Width + 1);
        return Add(new Seg("  " + new string('─', Math.Max(0, w - 1)), R.Border));
    }

    public Doc Tr(long jump, params C[] cols)
    {
        var segs = new Seg[cols.Length + 1];
        segs[0] = new Seg("  ", R.Normal);
        for (int i = 0; i < cols.Length; i++)
        {
            var c = cols[i];
            string t = Fmt.Clean(c.Text ?? "", 2000);
            bool last = i == cols.Length - 1;
            if (!last)
            {
                if (t.Length > c.Width) t = c.Width > 1 ? t[..(c.Width - 1)] + "…" : t[..c.Width];
                t = c.Right ? t.PadLeft(c.Width) : t.PadRight(c.Width);
                t += " ";
            }
            else if (c.Right) t = t.PadLeft(c.Width);
            segs[i + 1] = new Seg(t, c.Role);
        }
        return Add(jump, segs);
    }

    public string ToPlainText()
    {
        var sb = new StringBuilder();
        foreach (var l in Lines) sb.AppendLine(l.Plain.TrimEnd());
        return sb.ToString();
    }

    public static Doc Message(string title, string text, R role = R.Dim)
    {
        var d = new Doc();
        d.H(title);
        d.T("  " + text, role);
        return d;
    }
}
