using Ufi.Core;

namespace Ufi.UI;

public sealed class Theme
{
    public string Name;
    public readonly Color[] C = new Color[Enum.GetValues<R>().Length];
    public Color this[R r] => C[(int)r];

    static Color H(string hex) => ColorTranslator.FromHtml(hex);

    static Theme Make(string name, params (R role, string hex)[] map)
    {
        var t = new Theme { Name = name };
        foreach (var (r, h) in map) t.C[(int)r] = H(h);
        return t;
    }

    public static readonly Theme[] All =
    {
        Make("Midnight",
            (R.Bg, "#0B0E14"), (R.PanelBg, "#0B0E14"), (R.Normal, "#C5CDD9"), (R.Dim, "#5C6773"), (R.Key, "#7FB4F0"), (R.Value, "#E6E1CF"),
            (R.Title, "#FFB454"), (R.Accent, "#D2A6FF"), (R.Warn, "#FFB454"), (R.Bad, "#F07178"), (R.Good, "#AAD94C"), (R.Offset, "#6C7A8C"),
            (R.Hex, "#95E6CB"), (R.HexZero, "#3D4751"), (R.HexHigh, "#F29668"), (R.Ascii, "#E6E1CF"), (R.Num, "#E6B673"), (R.Str, "#C2D94C"),
            (R.Border, "#3A4552"), (R.BarFg, "#0B0E14"), (R.BarBg, "#59C2FF"), (R.SelBg, "#1F2A38"), (R.CursorFg, "#0B0E14"), (R.CursorBg, "#FFB454"),
            (R.Track, "#1A212B"), (R.Thumb, "#4D5B6B"), (R.MatchBg, "#5A3E00")),
        Make("Phosphor",
            (R.Bg, "#040A05"), (R.PanelBg, "#040A05"), (R.Normal, "#33FF66"), (R.Dim, "#1C7A38"), (R.Key, "#66FF99"), (R.Value, "#B3FFC6"),
            (R.Title, "#D4FFE0"), (R.Accent, "#00FFB0"), (R.Warn, "#E6FF66"), (R.Bad, "#FF6B6B"), (R.Good, "#66FF66"), (R.Offset, "#22AA44"),
            (R.Hex, "#33FF66"), (R.HexZero, "#145228"), (R.HexHigh, "#99FFBB"), (R.Ascii, "#B3FFC6"), (R.Num, "#88FFAA"), (R.Str, "#D0FFE0"),
            (R.Border, "#1F6B35"), (R.BarFg, "#031A08"), (R.BarBg, "#33FF66"), (R.SelBg, "#0F3319"), (R.CursorFg, "#031A08"), (R.CursorBg, "#D4FFE0"),
            (R.Track, "#0A1F0F"), (R.Thumb, "#2E8B4A"), (R.MatchBg, "#3D5C00")),
        Make("Amber",
            (R.Bg, "#0D0800"), (R.PanelBg, "#0D0800"), (R.Normal, "#FFB000"), (R.Dim, "#7A5200"), (R.Key, "#FFCC4D"), (R.Value, "#FFE0A3"),
            (R.Title, "#FFF0CC"), (R.Accent, "#FFD27F"), (R.Warn, "#FFF3B0"), (R.Bad, "#FF5C33"), (R.Good, "#E6C200"), (R.Offset, "#A66F00"),
            (R.Hex, "#FFB000"), (R.HexZero, "#4D3300"), (R.HexHigh, "#FFD580"), (R.Ascii, "#FFE0A3"), (R.Num, "#FFC266"), (R.Str, "#FFE9C2"),
            (R.Border, "#6B4700"), (R.BarFg, "#1A1000"), (R.BarBg, "#FFB000"), (R.SelBg, "#2E1F00"), (R.CursorFg, "#1A1000"), (R.CursorBg, "#FFF0CC"),
            (R.Track, "#1F1400"), (R.Thumb, "#8C5E00"), (R.MatchBg, "#5C3D00")),
        Make("Solar Light",
            (R.Bg, "#FDF6E3"), (R.PanelBg, "#FDF6E3"), (R.Normal, "#586E75"), (R.Dim, "#93A1A1"), (R.Key, "#268BD2"), (R.Value, "#073642"),
            (R.Title, "#CB4B16"), (R.Accent, "#6C71C4"), (R.Warn, "#B58900"), (R.Bad, "#DC322F"), (R.Good, "#859900"), (R.Offset, "#93A1A1"),
            (R.Hex, "#2AA198"), (R.HexZero, "#D3CBB5"), (R.HexHigh, "#D33682"), (R.Ascii, "#073642"), (R.Num, "#B58900"), (R.Str, "#859900"),
            (R.Border, "#C9C1A8"), (R.BarFg, "#FDF6E3"), (R.BarBg, "#268BD2"), (R.SelBg, "#EEE8D5"), (R.CursorFg, "#FDF6E3"), (R.CursorBg, "#CB4B16"),
            (R.Track, "#EEE8D5"), (R.Thumb, "#B8B09A"), (R.MatchBg, "#F5E0A0")),
    };
}
