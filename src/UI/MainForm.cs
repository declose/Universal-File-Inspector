using System.Buffers.Binary;
using System.Drawing.Text;
using System.Globalization;
using System.Text;
using Ufi.Analysis;
using Ufi.Core;

namespace Ufi.UI;

/// <summary>
/// The whole UI is one custom-painted character grid (like a terminal emulator): title bar, sidebar,
/// content pane, command line and status bar are all drawn as cells.
/// </summary>
public sealed class MainForm : Form
{
    const int SideW = 26, HEX = (int)Sec.Hex, NSec = 10;

    sealed class ViewState { public int Top, Cur, HScroll; public string Filter; public List<int> Map; public Doc MapDoc; }

    // grid
    Font _font; string _fontName; float _pt = 10.5f;
    int _cw = 8, _ch = 16, _cols = 120, _rows = 40;
    char[] _c = Array.Empty<char>(); R[] _f = Array.Empty<R>(), _b = Array.Empty<R>();
    Theme _th = Theme.All[0];
    readonly Dictionary<Color, SolidBrush> _brushes = new();

    // state
    Session _s;
    int _sec;
    readonly ViewState[] _vs = Enumerable.Range(0, NSec).Select(_ => new ViewState()).ToArray();
    long _hexCur, _hexTop, _hlStart = -1, _hlLen;
    bool _cmd; string _cmdText = ""; readonly List<string> _hist = new(); int _histIdx;
    string _msg = "Drop a file anywhere, or press Ctrl+O."; R _msgRole = R.Dim;
    bool _help, _dragging, _blink = true;
    byte[] _lastFind; string _lastFindLabel; CancellationTokenSource _findCts; volatile int _findPct = -1;
    int _spin;
    readonly System.Windows.Forms.Timer _timer = new() { Interval = 120 };
    int _blinkTick;
    volatile bool _dirty;

    // layout (cells), filled while composing
    int _x0, _y0, _w, _h, _sbX;
    int _hexX, _ascX, _od, _hexRows, _hexY0;
    bool _sbDrag;

    public MainForm(string initialPath)
    {
        Text = "Universal File Inspector";
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw | ControlStyles.Selectable, true);
        KeyPreview = true;
        AllowDrop = true;
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(820, 520);
        try
        {
            using var st = typeof(MainForm).Assembly.GetManifestResourceStream("app.ico");
            if (st != null) Icon = new Icon(st);
        }
        catch { }
        LoadSettings();
        _fontName = PickFont();
        MakeFont();
        var wa = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1600, 900);
        Size = new Size(Math.Min(1480, wa.Width - 60), Math.Min(900, wa.Height - 60));
        BackColor = _th[R.Bg];

        _timer.Tick += (_, _) =>
        {
            _spin++;
            if (++_blinkTick % 4 == 0) { _blink = !_blink; if (_cmd || _s == null) _dirty = true; }
            bool busy = _s != null && (!_s.DoneHash || !_s.DoneScan || !_s.DoneMeta) || _findPct >= 0;
            if (busy || _dirty) { _dirty = false; Invalidate(); }
        };
        _timer.Start();
        if (!string.IsNullOrEmpty(initialPath)) Shown += (_, _) => Open(initialPath);
    }

    // ================================================================== settings / font

    static string SettingsPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "UniversalFileInspector", "settings.ini");

    void LoadSettings()
    {
        try
        {
            if (!File.Exists(SettingsPath)) return;
            foreach (var l in File.ReadAllLines(SettingsPath))
            {
                var kv = l.Split('=', 2);
                if (kv.Length != 2) continue;
                if (kv[0] == "theme") _th = Theme.All.FirstOrDefault(t => t.Name == kv[1]) ?? _th;
                if (kv[0] == "font" && float.TryParse(kv[1], NumberStyles.Float, CultureInfo.InvariantCulture, out var f)) _pt = Math.Clamp(f, 7, 28);
            }
        }
        catch { }
    }

    void SaveSettings()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath));
            File.WriteAllText(SettingsPath, $"theme={_th.Name}\nfont={_pt.ToString(CultureInfo.InvariantCulture)}\n");
        }
        catch { }
    }

    static string PickFont()
    {
        using var fc = new InstalledFontCollection();
        var names = fc.Families.Select(f => f.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var n in new[] { "Cascadia Mono", "Cascadia Code", "Consolas", "Lucida Console", "Courier New" }) if (names.Contains(n)) return n;
        return FontFamily.GenericMonospace.Name;
    }

    void MakeFont()
    {
        _font?.Dispose();
        _font = new Font(_fontName, _pt * DeviceDpi / 72f, FontStyle.Regular, GraphicsUnit.Pixel);
        var sz = TextRenderer.MeasureText("MMMMMMMMMMMMMMMMMMMM", _font, new Size(int.MaxValue, int.MaxValue), TextFormatFlags.NoPadding | TextFormatFlags.SingleLine);
        _cw = Math.Max(4, (int)Math.Round(sz.Width / 20.0));
        _ch = Math.Max(8, sz.Height);
        Invalidate();
    }

    protected override void OnDpiChanged(DpiChangedEventArgs e) { base.OnDpiChanged(e); MakeFont(); }

    // ================================================================== open / session

    void Open(string path)
    {
        try
        {
            path = path.Trim().Trim('"');
            if (Directory.Exists(path)) { Msg("That is a folder – drop a file instead.", R.Warn); return; }
            if (!File.Exists(path)) { Msg("File not found: " + path, R.Bad); return; }
            var s = new Session(path);
            _findCts?.Cancel(); _findPct = -1;
            var old = _s;
            _s = s;
            old?.Dispose();
            foreach (var v in _vs) { v.Top = v.Cur = v.HScroll = 0; v.Filter = null; v.Map = null; v.MapDoc = null; }
            _hexCur = _hexTop = 0; _hlStart = -1; _sec = 0;
            s.Changed += () => { if (ReferenceEquals(_s, s)) _dirty = true; };
            s.Start();
            Text = "Universal File Inspector — " + Path.GetFileName(path);
            Msg("Inspecting " + Path.GetFileName(path) + " (read-only)…", R.Dim);
        }
        catch (Exception ex) { Msg("Cannot open: " + ex.Message, R.Bad); }
        Invalidate();
    }

    void Msg(string m, R role = R.Normal) { _msg = m; _msgRole = role; Invalidate(); }

    // ================================================================== drag & drop

    protected override void OnDragEnter(DragEventArgs e)
    {
        if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) { e.Effect = DragDropEffects.Copy; _dragging = true; Invalidate(); }
        else e.Effect = DragDropEffects.None;
    }
    protected override void OnDragLeave(EventArgs e) { _dragging = false; Invalidate(); }
    protected override void OnDragDrop(DragEventArgs e)
    {
        _dragging = false;
        if (e.Data?.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0)
        {
            Activate();
            Open(files[0]);
            if (files.Length > 1) Msg($"Inspecting {Path.GetFileName(files[0])} ({files.Length - 1} other dropped file(s) ignored – one file at a time)", R.Warn);
        }
        Invalidate();
    }

    // ================================================================== grid primitives

    void Put(int x, int y, string s, R fg, R? bg = null, int maxX = int.MaxValue)
    {
        if (y < 0 || y >= _rows || s == null) return;
        int lim = Math.Min(_cols, maxX);
        for (int i = 0; i < s.Length; i++)
        {
            int xx = x + i;
            if (xx < 0) continue;
            if (xx >= lim) break;
            int k = y * _cols + xx;
            _c[k] = s[i]; _f[k] = fg;
            if (bg.HasValue) _b[k] = bg.Value;
        }
    }

    void Fill(int x, int y, int w, int h, char ch, R fg, R bg)
    {
        for (int yy = Math.Max(0, y); yy < Math.Min(_rows, y + h); yy++)
            for (int xx = Math.Max(0, x); xx < Math.Min(_cols, x + w); xx++)
            { int k = yy * _cols + xx; _c[k] = ch; _f[k] = fg; _b[k] = bg; }
    }

    void Bg(int x, int y, int w, R bg)
    {
        if (y < 0 || y >= _rows) return;
        for (int xx = Math.Max(0, x); xx < Math.Min(_cols, x + w); xx++) _b[y * _cols + xx] = bg;
    }

    void Box(int x, int y, int w, int h, R border, string title = null, string right = null)
    {
        if (w < 2 || h < 2) return;
        Put(x, y, "┌" + new string('─', w - 2) + "┐", border);
        for (int i = 1; i < h - 1; i++) { Put(x, y + i, "│", border); Put(x + w - 1, y + i, "│", border); }
        Put(x, y + h - 1, "└" + new string('─', w - 2) + "┘", border);
        if (title != null) Put(x + 2, y, " " + title + " ", R.Title, null, x + w - 2);
        if (right != null && right.Length + 4 < w - (title?.Length ?? 0) - 4) Put(x + w - right.Length - 4, y, " " + right + " ", R.Dim);
    }

    // ================================================================== compose

    void Compose()
    {
        _cols = Math.Max(40, ClientSize.Width / _cw);
        _rows = Math.Max(12, ClientSize.Height / _ch);
        int n = _cols * _rows;
        if (_c.Length != n) { _c = new char[n]; _f = new R[n]; _b = new R[n]; }
        Array.Fill(_c, ' '); Array.Fill(_f, R.Normal); Array.Fill(_b, R.Bg);

        TitleBar();
        if (_s == null) Splash(); else { Sidebar(); MainPane(); }
        CommandLine();
        StatusBar();
        if (_help) HelpOverlay();
        if (_dragging) DropOverlay();
    }

    void TitleBar()
    {
        Fill(0, 0, _cols, 1, ' ', R.BarFg, R.BarBg);
        string left = " ▓▒░ UNIVERSAL FILE INSPECTOR ░▒▓ ";
        Put(0, 0, left, R.BarFg, R.BarBg);
        if (_s != null)
        {
            string info = $" {Path.GetFileName(_s.FilePath)}  ·  {Fmt.Human(_s.Src.Length)}  ·  {_s.EffectiveType?.Name ?? "…"} ";
            Put(left.Length + 1, 0, Fmt.Clean(info, _cols), R.BarFg, R.BarBg, _cols - 16);
        }
        string ro = " READ-ONLY ● ";
        Put(_cols - ro.Length, 0, ro, R.BarFg, R.BarBg);
    }

    static readonly string[] Logo =
    {
        "██╗   ██╗███████╗██╗",
        "██║   ██║██╔════╝██║",
        "██║   ██║█████╗  ██║",
        "██║   ██║██╔══╝  ██║",
        "╚██████╔╝██║     ██║",
        " ╚═════╝ ╚═╝     ╚═╝",
    };

    void Splash()
    {
        int top = Math.Max(2, (_rows - 22) / 2);
        foreach (var (l, i) in Logo.Select((l, i) => (l, i))) Put((_cols - l.Length) / 2, top + i, l, i < 4 ? R.Accent : R.Key);
        string t1 = "U N I V E R S A L   F I L E   I N S P E C T O R";
        Put((_cols - t1.Length) / 2, top + 7, t1, R.Title);
        string t2 = "every byte · every bit · every structure — without ever executing the file";
        Put((_cols - t2.Length) / 2, top + 8, t2, R.Dim);
        int bw = Math.Min(60, _cols - 4), bx = (_cols - bw) / 2, by = top + 10;
        for (int x = 0; x < bw; x++) { Put(bx + x, by, x % 2 == 0 ? "─" : " ", R.Border); Put(bx + x, by + 6, x % 2 == 0 ? "─" : " ", R.Border); }
        for (int y = 1; y < 6; y++) { Put(bx, by + y, y % 2 == 1 ? "│" : " ", R.Border); Put(bx + bw - 1, by + y, y % 2 == 1 ? "│" : " ", R.Border); }
        string d1 = "▼  DRAG & DROP ANY FILE HERE  ▼";
        Put(bx + (bw - d1.Length) / 2, by + 2, d1, R.Warn);
        string d2 = "or press Ctrl+O to browse" + (_blink ? "_" : " ");
        Put(bx + (bw - d2.Length) / 2, by + 4, d2, R.Normal);
        string[] tips =
        {
            "PE/ELF/Mach-O · ZIP/Office/7z/RAR/CAB/TAR/GZ · PDF · OLE/MSG/MSI · LNK · JPEG/PNG/GIF/TIFF/EXIF",
            "MP4/MOV/HEIC · WAV/AVI/WebP · MP3/FLAC · SQLite · Registry hives · ISO · certificates · text & scripts",
            "hashes · entropy map · strings · IOCs · embedded files · NTFS streams & Mark-of-the-Web · Authenticode",
        };
        for (int i = 0; i < tips.Length; i++) Put((_cols - tips[i].Length) / 2, by + 9 + i, tips[i], R.Dim);
    }

    void Sidebar()
    {
        int h = _rows - 3;
        Box(0, 1, SideW, h, R.Border, "SECTIONS");
        for (int i = 0; i < NSec; i++)
        {
            int y = 2 + i;
            bool sel = i == _sec;
            string key = ((i + 1) % 10).ToString();
            bool ready = i == HEX || _s.Docs[i] != null;
            if (sel) Bg(1, y, SideW - 2, R.SelBg);
            Put(2, y, sel ? "►" : " ", R.Warn);
            Put(3, y, key, R.Key);
            Put(5, y, Session.Names[i], sel ? R.Title : ready ? R.Normal : R.Dim);
            string badge = Badge(i);
            if (badge != null) Put(SideW - 2 - badge.Length, y, badge, badge.StartsWith("!") ? R.Bad : R.Dim);
        }
        int yy = 3 + NSec;
        Put(0, yy, "├" + new string('─', SideW - 2) + "┤", R.Border);
        Put(2, yy, " ANALYSIS ", R.Title);
        yy++;
        void Prog(string label, bool done, int pct, bool waiting = false)
        {
            Put(2, yy, label.PadRight(8), R.Key);
            if (done) Put(10, yy, "▇▇▇▇▇▇▇▇▇▇▇▇ ok", R.Good);
            else if (waiting) Put(10, yy, "░░░░░░░░░░░░ …", R.Dim);
            else { Put(10, yy, Fmt.Bar(pct / 100.0, 12), R.Warn); Put(23, yy, "|/-\\"[_spin % 4].ToString(), R.Warn); }
            yy++;
        }
        Prog("Parse", _s.DoneMeta, 50);
        Prog("Hashes", _s.DoneHash, _s.PHash);
        Prog("Strings", _s.DoneScan, _s.PScan, _s.Scan == null && !_s.DoneMeta);
        if (_findPct >= 0) Prog("Find", false, _findPct);

        yy++;
        if (yy + 1 < h)
        {
            Put(0, yy, "├" + new string('─', SideW - 2) + "┤", R.Border);
            Put(2, yy, " FILE ", R.Title);
            yy++;
            var t = _s.EffectiveType;
            var lines = new List<(string, R)>();
            foreach (var w in Wrap(t?.Name ?? "detecting…", SideW - 4)) lines.Add((w, R.Good));
            lines.Add((Fmt.Human(_s.Src.Length), R.Num));
            if (_s.Stats != null) lines.Add(($"entropy {_s.Stats.Entropy:0.00}", _s.Stats.Entropy > 7.5 ? R.Warn : R.Value));
            var f = _s.Ctx.Findings;
            int bad = f.Count(x => x.Level == Level.Bad), warn = f.Count(x => x.Level == Level.Warn);
            lines.Add(($"{bad} high · {warn} medium", bad > 0 ? R.Bad : warn > 0 ? R.Warn : R.Good));
            foreach (var (l, r) in lines) { if (yy >= _rows - 3) break; Put(2, yy++, l, r, null, SideW - 1); }
        }
    }

    string Badge(int i)
    {
        if (i == 0)
        {
            int n = _s.Ctx.Findings.Count(x => x.Level == Level.Bad);
            return n > 0 ? "!" + n : null;
        }
        if (i == HEX || _s.Docs[i] != null) return null;
        return "…";
    }

    static IEnumerable<string> Wrap(string s, int w)
    {
        s = Fmt.Clean(s, 300);
        while (s.Length > w)
        {
            int cut = s.LastIndexOf(' ', w);
            if (cut <= 0) cut = w;
            yield return s[..cut];
            s = s[cut..].TrimStart();
        }
        if (s.Length > 0) yield return s;
    }

    // ------------------------------------------------------------------ main pane

    void MainPane()
    {
        int x = SideW, y = 1, w = _cols - SideW, h = _rows - 3;
        _x0 = x + 1; _y0 = y + 1; _w = w - 2; _h = h - 2; _sbX = x + w - 1;
        string title = $"{(_sec + 1) % 10} · {Session.Names[_sec].ToUpperInvariant()}";
        if (_sec == HEX) { Box(x, y, w, h, R.Border, title, HexStatus()); HexPane(); return; }
        var doc = _s.Docs[_sec];
        var vs = _vs[_sec];
        if (doc == null)
        {
            Box(x, y, w, h, R.Border, title);
            string sp = "|/-\\"[_spin % 4].ToString();
            string m = _sec == (int)Sec.Hashes || _sec == (int)Sec.Entropy ? $"hashing & measuring every byte… {_s.PHash}%"
                     : _sec == (int)Sec.Strings || _sec == (int)Sec.Indicators ? (_s.Scan == null && !_s.DoneMeta ? "waiting for the structure parser…" : $"scanning strings & signatures… {_s.PScan}%")
                     : "analyzing…";
            Put(_x0 + 2, _y0 + 1, sp + " " + m, R.Warn);
            return;
        }
        int count = Count(vs, doc);
        vs.Cur = Math.Clamp(vs.Cur, 0, Math.Max(0, count - 1));
        vs.Top = Math.Clamp(vs.Top, 0, Math.Max(0, count - _h));
        if (vs.Cur < vs.Top) vs.Top = vs.Cur;
        if (vs.Cur >= vs.Top + _h) vs.Top = vs.Cur - _h + 1;
        string right = (vs.Filter != null ? $"filter \"{vs.Filter}\": {count:N0} of {doc.Count:N0}  " : "") + $"{(count == 0 ? 0 : vs.Cur + 1):N0}/{count:N0}" + (vs.HScroll > 0 ? $"  col +{vs.HScroll}" : "");
        Box(x, y, w, h, R.Border, title, right);
        for (int r = 0; r < _h; r++)
        {
            int idx = vs.Top + r;
            if (idx >= count) break;
            var line = GetLine(vs, doc, idx);
            int yy = _y0 + r;
            bool sel = idx == vs.Cur;
            if (sel) Bg(_x0, yy, _w, R.SelBg);
            int cx = _x0, skip = vs.HScroll, lim = _x0 + _w;
            foreach (var seg in line.Segs)
            {
                string t = seg.Text;
                if (skip >= t.Length) { skip -= t.Length; continue; }
                if (skip > 0) { t = t[skip..]; skip = 0; }
                Put(cx, yy, t, seg.Role, null, lim);
                cx += t.Length;
                if (cx >= lim) break;
            }
            if (sel && line.Jump >= 0) Put(lim - 2, yy, "»", R.Warn, R.SelBg);
        }
        if (count == 0 && vs.Filter != null) Put(_x0 + 2, _y0 + 1, $"No lines match \"{vs.Filter}\" – press Esc to clear the filter.", R.Dim);
        ScrollBar(vs.Top, count, _h);
    }

    void ScrollBar(long top, long count, int visible)
    {
        if (count <= visible || _h < 3) return;
        int h = _h;
        int th = Math.Max(1, (int)(h * (double)visible / count));
        int ty = (int)((h - th) * (double)top / Math.Max(1, count - visible));
        for (int i = 0; i < h; i++) Put(_sbX, _y0 + i, i >= ty && i < ty + th ? "█" : "│", i >= ty && i < ty + th ? R.Thumb : R.Border);
    }

    int Count(ViewState vs, Doc doc)
    {
        if (vs.Filter == null) return doc.Count;
        if (vs.MapDoc != doc || vs.Map == null)
        {
            vs.MapDoc = doc;
            vs.Map = new List<int>();
            for (int i = 0; i < doc.Count; i++)
                if (doc.Lines[i].Plain.Contains(vs.Filter, StringComparison.OrdinalIgnoreCase)) vs.Map.Add(i);
        }
        return vs.Map.Count;
    }

    static Line GetLine(ViewState vs, Doc doc, int idx) => vs.Filter == null ? doc.Lines[idx] : doc.Lines[vs.Map[idx]];

    Line CurLine()
    {
        if (_s == null || _sec == HEX) return null;
        var doc = _s.Docs[_sec]; var vs = _vs[_sec];
        if (doc == null) return null;
        int n = Count(vs, doc);
        return vs.Cur >= 0 && vs.Cur < n ? GetLine(vs, doc, vs.Cur) : null;
    }

    // ------------------------------------------------------------------ hex pane

    string HexStatus()
    {
        string region = _s.Ctx.Regions.FirstOrDefault(r => _hexCur >= r.Off && _hexCur < r.Off + r.Size).Name;
        return $"{Fmt.Hx(_hexCur)} / {Fmt.Hx(Math.Max(0, _s.Src.Length - 1))}  ({(_s.Src.Length == 0 ? 0 : _hexCur * 100.0 / _s.Src.Length):0.0}%)" + (region != null ? "  in " + region : "");
    }

    void HexPane()
    {
        long len = _s.Src.Length;
        _od = len > 0xFFFFFFFFL ? 12 : 8;
        int rowW = _od + 2 + 67;
        bool right = _w >= rowW + 3 + 36;
        bool bottom = !right && _h >= 26;
        int inspH = bottom ? 13 : 0;
        _hexY0 = _y0 + 1;
        _hexRows = Math.Max(1, _h - 1 - inspH);
        _hexX = _x0 + _od + 2;
        _ascX = _hexX + 50;
        long totalRows = Math.Max(1, (len + 15) / 16);
        long curRow = _hexCur / 16;
        if (curRow < _hexTop) _hexTop = curRow;
        if (curRow >= _hexTop + _hexRows) _hexTop = curRow - _hexRows + 1;
        _hexTop = Math.Clamp(_hexTop, 0, Math.Max(0, totalRows - _hexRows));

        // header
        var hdr = new StringBuilder();
        for (int i = 0; i < 16; i++) { hdr.Append(i.ToString("X2")).Append(' '); if (i == 7) hdr.Append(' '); }
        Put(_x0, _y0, "Offset(h)".PadRight(_od + 2)[..(_od + 2)], R.Dim);
        Put(_hexX, _y0, hdr.ToString(), R.Dim);
        Put(_ascX, _y0, "ASCII", R.Dim);

        if (len == 0) { Put(_x0 + 2, _hexY0 + 1, "(empty file)", R.Dim); return; }
        var buf = new byte[_hexRows * 16];
        int got = _s.Src.Copy(_hexTop * 16, buf);
        for (int r = 0; r < _hexRows; r++)
        {
            long rowOff = (_hexTop + r) * 16;
            if (rowOff >= len) break;
            int y = _hexY0 + r;
            Put(_x0, y, rowOff.ToString(_od == 8 ? "X8" : "X12"), rowOff / 16 == curRow ? R.Warn : R.Offset);
            Put(_ascX - 1, y, "│", R.Border);
            for (int i = 0; i < 16; i++)
            {
                long o = rowOff + i;
                int bi = r * 16 + i;
                if (o >= len || bi >= got) break;
                byte b = buf[bi];
                R fg = b == 0 ? R.HexZero : b >= 0x20 && b < 0x7F ? R.Hex : b == 0xFF ? R.HexHigh : b >= 0x80 ? R.HexHigh : R.Offset;
                R? bgc = null;
                if (_hlStart >= 0 && o >= _hlStart && o < _hlStart + _hlLen) bgc = R.MatchBg;
                if (o == _hexCur) { fg = R.CursorFg; bgc = R.CursorBg; }
                int hx = _hexX + i * 3 + (i >= 8 ? 1 : 0);
                Put(hx, y, b.ToString("X2"), fg, bgc);
                char ch = b >= 0x20 && b < 0x7F ? (char)b : '·';
                Put(_ascX + i, y, ch.ToString(), o == _hexCur ? R.CursorFg : b >= 0x20 && b < 0x7F ? R.Ascii : R.HexZero, bgc);
            }
            Put(_ascX + 16, y, "│", R.Border);
        }
        ScrollBar(_hexTop, totalRows, _hexRows);

        // inspector
        var items = Inspect(_hexCur);
        if (right)
        {
            int px = _x0 + rowW + 2, pw = _x0 + _w - px;
            for (int i = 0; i < _h; i++) Put(px - 2, _y0 + i, "│", R.Border);
            Put(px, _y0, "DATA INSPECTOR", R.Title);
            int yy = _y0 + 1;
            foreach (var (k, v) in items)
            {
                if (yy >= _y0 + _h) break;
                if (k == null) { yy++; continue; }
                Put(px, yy, k.PadRight(11), R.Key, null, px + pw);
                Put(px + 12, yy, v, R.Value, null, px + pw);
                yy++;
            }
        }
        else if (bottom)
        {
            int py = _y0 + _h - inspH;
            Put(_x0, py, new string('─', _w), R.Border);
            Put(_x0 + 2, py, " DATA INSPECTOR ", R.Title);
            var list = items.Where(i => i.k != null).ToList();
            int colW = _w / 2, per = inspH - 1;
            for (int i = 0; i < list.Count && i < per * 2; i++)
            {
                int cx = _x0 + (i / per) * colW, cy = py + 1 + i % per;
                Put(cx, cy, list[i].k.PadRight(11), R.Key, null, cx + colW);
                Put(cx + 12, cy, list[i].v, R.Value, null, cx + colW - 1);
            }
        }
    }

    List<(string k, string v)> Inspect(long off)
    {
        var r = new List<(string, string)>();
        var b = new byte[16];
        int n = _s.Src.Copy(off, b);
        var sp = b.AsSpan(0, n);
        string F(Func<string> f) { try { return f(); } catch { return "—"; } }
        r.Add(("offset", $"{Fmt.Hx(off)} = {off:N0}"));
        if (n == 0) return r;
        r.Add(("bits", Convert.ToString(b[0], 2).PadLeft(8, '0').Insert(4, " ") + $"  ({b[0]:X2})"));
        r.Add(("int8", $"{(sbyte)b[0]}   uint8 {b[0]}"));
        r.Add(("char", b[0] >= 0x20 && b[0] < 0x7F ? $"'{(char)b[0]}'" : b[0] < 0x20 ? $"^{(char)(b[0] + 64)} (control)" : $"Latin-1 '{Fmt.Clean(((char)b[0]).ToString())}'"));
        if (n >= 2)
        {
            r.Add(("int16 LE", $"{BinaryPrimitives.ReadInt16LittleEndian(sp)}   u {BinaryPrimitives.ReadUInt16LittleEndian(sp)}"));
            r.Add(("int16 BE", $"{BinaryPrimitives.ReadInt16BigEndian(sp)}   u {BinaryPrimitives.ReadUInt16BigEndian(sp)}"));
            r.Add(("UTF-16LE", F(() => Fmt.Clean(Encoding.Unicode.GetString(b, 0, 2)))));
        }
        if (n >= 3) r.Add(("int24 LE", (b[0] | b[1] << 8 | b[2] << 16).ToString()));
        if (n >= 4)
        {
            r.Add(("int32 LE", $"{BinaryPrimitives.ReadInt32LittleEndian(sp)}"));
            r.Add(("uint32 LE", $"{BinaryPrimitives.ReadUInt32LittleEndian(sp)}  {Fmt.Hx(BinaryPrimitives.ReadUInt32LittleEndian(sp), 8)}"));
            r.Add(("int32 BE", $"{BinaryPrimitives.ReadInt32BigEndian(sp)}"));
            r.Add(("uint32 BE", $"{BinaryPrimitives.ReadUInt32BigEndian(sp)}"));
            r.Add(("float32 LE", F(() => BinaryPrimitives.ReadSingleLittleEndian(b).ToString("G9", CultureInfo.InvariantCulture))));
            uint u = BinaryPrimitives.ReadUInt32LittleEndian(sp);
            r.Add(("unix time", F(() => u == 0 ? "—" : DateTimeOffset.FromUnixTimeSeconds(u).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss") + " UTC")));
            ushort dt = BinaryPrimitives.ReadUInt16LittleEndian(sp[2..]), tm = BinaryPrimitives.ReadUInt16LittleEndian(sp);
            r.Add(("DOS time", dt == 0 ? "—" : Fmt.DosDateTime(dt, tm)));
            r.Add(("UTF-8", F(() => { var s = new UTF8Encoding(false, true).GetString(b, 0, Utf8Len(b[0])); return "'" + Fmt.Clean(s) + $"' U+{char.ConvertToUtf32(s, 0):X4}"; })));
            r.Add(("IPv4", $"{b[0]}.{b[1]}.{b[2]}.{b[3]}"));
        }
        if (n >= 8)
        {
            r.Add(("int64 LE", $"{BinaryPrimitives.ReadInt64LittleEndian(sp)}"));
            r.Add(("uint64 LE", Fmt.Hx(BinaryPrimitives.ReadUInt64LittleEndian(sp))));
            r.Add(("int64 BE", $"{BinaryPrimitives.ReadInt64BigEndian(sp)}"));
            r.Add(("float64 LE", F(() => BinaryPrimitives.ReadDoubleLittleEndian(b).ToString("G17", CultureInfo.InvariantCulture))));
            long ft = BinaryPrimitives.ReadInt64LittleEndian(sp);
            r.Add(("FILETIME", F(() => ft <= 0 ? "—" : DateTime.FromFileTimeUtc(ft).ToString("yyyy-MM-dd HH:mm:ss") + " UTC")));
            long ms = BinaryPrimitives.ReadInt64LittleEndian(sp);
            r.Add(("unix ms", F(() => ms <= 0 || ms > 253402300799999 ? "—" : DateTimeOffset.FromUnixTimeMilliseconds(ms).UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.fff"))));
        }
        if (n >= 16) r.Add(("GUID", new Guid(sp[..16]).ToString("B").ToUpperInvariant()));
        r.Add(("bytes", Fmt.Bytes(sp[..Math.Min(8, n)], 8)));
        return r;
    }

    static int Utf8Len(byte b) => b < 0x80 ? 1 : (b & 0xE0) == 0xC0 ? 2 : (b & 0xF0) == 0xE0 ? 3 : 4;

    // ------------------------------------------------------------------ bottom lines

    void CommandLine()
    {
        int y = _rows - 2;
        if (_cmd)
        {
            Put(0, y, " :", R.Warn);
            string t = _cmdText;
            int room = _cols - 4;
            if (t.Length > room) t = t[^room..];
            Put(2, y, t, R.Value);
            if (_blink) Put(2 + t.Length, y, " ", R.CursorFg, R.CursorBg);
            return;
        }
        string hint = CurLine() is { Jump: >= 0 } l ? $"   Enter → hex at {Fmt.Hx(l.Jump)}" : "";
        Put(1, y, Fmt.Clean(_msg ?? "", _cols), _msgRole, null, _cols - hint.Length - 1);
        if (hint.Length > 0) Put(_cols - hint.Length - 1, y, hint, R.Dim);
    }

    void StatusBar()
    {
        int y = _rows - 1;
        Fill(0, y, _cols, 1, ' ', R.BarFg, R.BarBg);
        var keys = new (string k, string v)[] { ("F1", "Help"), ("^O", "Open"), ("Tab", "Section"), (":", "Cmd"), ("/", "Filter"), ("^F", "Find"), ("^G", "Goto"), ("^E", "Export"), ("^C", "Copy"), ("F9", "Theme"), ("^±", "Zoom") };
        int x = 1;
        foreach (var (k, v) in keys)
        {
            if (x + k.Length + v.Length + 3 > _cols - 18) break;
            Put(x, y, k, R.CursorFg, R.CursorBg);
            Put(x + k.Length, y, " " + v + " ", R.BarFg, R.BarBg);
            x += k.Length + v.Length + 3;
        }
        string th = $" {_th.Name} ";
        Put(_cols - th.Length - 1, y, th, R.BarFg, R.BarBg);
    }

    void HelpOverlay()
    {
        string[] lines =
        {
            "NAVIGATION",
            "  1-9, 0          jump to section            Tab / Shift+Tab   next / previous section",
            "  ↑ ↓ PgUp PgDn   move cursor                Home / End        top / bottom",
            "  ← →             scroll horizontally (hex view: move one byte)",
            "  Enter           jump to the offset of the selected line in the HEX VIEW",
            "  Mouse           click sections / lines / bytes, wheel scrolls, drag the scrollbar",
            "",
            "COMMANDS  (press :  — or use the shortcut)",
            "  :open <path>          Ctrl+O    open a file (or just drag & drop it)",
            "  :goto <offset>        Ctrl+G    0x1F4, 500, 1F4h, +0x10, -16, end, 50%",
            "  :find <text>          Ctrl+F    search bytes (UTF-8), F3 = find next",
            "  :findu <text>                   search UTF-16LE text",
            "  :findhex <bytes>                search hex bytes, e.g.  4D 5A 90 00",
            "  :filter <text>        /         show only lines containing text (Esc clears)",
            "  :export [path]        Ctrl+E    save a full text report",
            "  :copy                 Ctrl+C    copy the current view  (Ctrl+Shift+C: current line)",
            "  :theme [name]         F9        Midnight, Phosphor, Amber, Solar Light",
            "  :font <size>          Ctrl +/-  zoom        :reload  F5        :quit  Ctrl+Q",
            "",
            "SAFETY  The file is opened read-only and treated purely as data. Nothing is executed,",
            "        rendered by its associated program, or sent over the network.",
            "",
            "Universal File Inspector 1.0 · MIT License                     press any key to close",
        };
        int w = Math.Min(_cols - 4, lines.Max(l => l.Length) + 4), h = Math.Min(_rows - 2, lines.Length + 2);
        int x = (_cols - w) / 2, y = (_rows - h) / 2;
        Fill(x, y, w, h, ' ', R.Normal, R.PanelBg);
        Box(x, y, w, h, R.Accent, "HELP");
        for (int i = 0; i < lines.Length && i < h - 2; i++)
            Put(x + 2, y + 1 + i, lines[i], lines[i].Length > 0 && lines[i] == lines[i].ToUpperInvariant() && !lines[i].StartsWith(" ") ? R.Title : lines[i].StartsWith("SAFETY") || lines[i].StartsWith("        ") ? R.Good : R.Normal, null, x + w - 1);
    }

    void DropOverlay()
    {
        int w = Math.Min(50, _cols - 4), h = 7, x = (_cols - w) / 2, y = (_rows - h) / 2;
        Fill(x, y, w, h, ' ', R.BarFg, R.BarBg);
        Box(x, y, w, h, R.BarFg);
        string t = "▼  RELEASE TO INSPECT  ▼";
        Put(x + (w - t.Length) / 2, y + 3, t, R.BarFg, R.BarBg);
    }

    // ================================================================== painting

    protected override void OnPaintBackground(PaintEventArgs e) { }

    SolidBrush Brush(Color c)
    {
        if (!_brushes.TryGetValue(c, out var b)) _brushes[c] = b = new SolidBrush(c);
        return b;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Compose();
        g.FillRectangle(Brush(_th[R.Bg]), ClientRectangle);
        const TextFormatFlags TF = TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine | TextFormatFlags.NoClipping | TextFormatFlags.PreserveGraphicsClipping;
        var sb = new StringBuilder(_cols);
        for (int y = 0; y < _rows; y++)
        {
            int row = y * _cols, py = y * _ch;
            // backgrounds
            int x = 0;
            while (x < _cols)
            {
                R bgr = _b[row + x]; int s = x;
                while (x < _cols && _b[row + x] == bgr) x++;
                if (bgr != R.Bg) g.FillRectangle(Brush(_th[bgr]), s * _cw, py, (x - s) * _cw, _ch);
            }
            // text
            x = 0;
            while (x < _cols)
            {
                char c = _c[row + x];
                if (c == ' ') { x++; continue; }
                if (c > 0x7E)
                {
                    if (!Prim(g, c, x * _cw, py, _th[_f[row + x]]))
                        TextRenderer.DrawText(g, c.ToString(), _font, new Point(x * _cw, py), _th[_f[row + x]], TF);
                    x++; continue;
                }
                R fg = _f[row + x]; int s = x;
                sb.Clear();
                while (x < _cols && _f[row + x] == fg && _c[row + x] <= 0x7E) { sb.Append(_c[row + x]); x++; }
                TextRenderer.DrawText(g, sb.ToString(), _font, new Point(s * _cw, py), _th[fg], TF);
            }
        }
    }

    /// <summary>Draws box-drawing and block characters as crisp primitives so borders join seamlessly.</summary>
    bool Prim(Graphics g, char c, int px, int py, Color col)
    {
        int lw = Math.Max(1, (int)Math.Round(_cw / 8.0));
        int cx = px + (_cw - lw) / 2, cy = py + (_ch - lw) / 2, r = px + _cw, b = py + _ch;
        int gx = Math.Max(2, _cw / 5), gy = Math.Max(2, _ch / 7), inset = Math.Max(1, _ch / 6);
        var br = Brush(col);
        void H(int x1, int x2, int y) { if (x2 > x1) g.FillRectangle(br, x1, y, x2 - x1, lw); }
        void V(int y1, int y2, int x) { if (y2 > y1) g.FillRectangle(br, x, y1, lw, y2 - y1); }
        switch (c)
        {
            case '─': H(px, r, cy); return true;
            case '│': V(py, b, cx); return true;
            case '┌': H(cx, r, cy); V(cy, b, cx); return true;
            case '┐': H(px, cx + lw, cy); V(cy, b, cx); return true;
            case '└': H(cx, r, cy); V(py, cy + lw, cx); return true;
            case '┘': H(px, cx + lw, cy); V(py, cy + lw, cx); return true;
            case '├': V(py, b, cx); H(cx, r, cy); return true;
            case '┤': V(py, b, cx); H(px, cx, cy); return true;
            case '┬': H(px, r, cy); V(cy, b, cx); return true;
            case '┴': H(px, r, cy); V(py, cy, cx); return true;
            case '┼': H(px, r, cy); V(py, b, cx); return true;
            case '█': g.FillRectangle(br, px, py, _cw, _ch); return true;
            case '▀': g.FillRectangle(br, px, py, _cw, _ch / 2); return true;
            case '▄': g.FillRectangle(br, px, py + _ch / 2, _cw, _ch - _ch / 2); return true;
            case '▇': g.FillRectangle(br, px, py + inset, _cw, _ch - 2 * inset); return true;
            case '░': g.FillRectangle(Brush(Color.FromArgb(55, col)), px, py + inset, _cw, _ch - 2 * inset); return true;
            case '▒': g.FillRectangle(Brush(Color.FromArgb(120, col)), px, py + inset, _cw, _ch - 2 * inset); return true;
            case '▓': g.FillRectangle(Brush(Color.FromArgb(190, col)), px, py + inset, _cw, _ch - 2 * inset); return true;
            case '═': H(px, r, cy - gy); H(px, r, cy + gy); return true;
            case '║': V(py, b, cx - gx); V(py, b, cx + gx); return true;
            case '╔': H(cx - gx, r, cy - gy); H(cx + gx, r, cy + gy); V(cy - gy, b, cx - gx); V(cy + gy, b, cx + gx); return true;
            case '╗': H(px, cx + gx + lw, cy - gy); H(px, cx - gx + lw, cy + gy); V(cy - gy, b, cx + gx); V(cy + gy, b, cx - gx); return true;
            case '╚': H(cx - gx, r, cy + gy); H(cx + gx, r, cy - gy); V(py, cy + gy + lw, cx - gx); V(py, cy - gy + lw, cx + gx); return true;
            case '╝': H(px, cx + gx + lw, cy + gy); H(px, cx - gx + lw, cy - gy); V(py, cy + gy + lw, cx + gx); V(py, cy - gy + lw, cx - gx); return true;
        }
        return false;
    }

    // ================================================================== keyboard

    protected override bool IsInputKey(Keys keyData) => true;

    protected override bool ProcessCmdKey(ref Message m, Keys keyData)
    {
        Keys key = keyData & Keys.KeyCode;
        bool ctrl = (keyData & Keys.Control) != 0, shift = (keyData & Keys.Shift) != 0;

        if (_help) { if (key is not (Keys.ControlKey or Keys.ShiftKey or Keys.Menu)) { _help = false; Invalidate(); } return true; }

        if (_cmd)
        {
            switch (key)
            {
                case Keys.Enter: _cmd = false; var t = _cmdText; if (t.Trim().Length > 0) { _hist.Remove(t); _hist.Add(t); } _histIdx = _hist.Count; Exec(t); Invalidate(); return true;
                case Keys.Escape: _cmd = false; Invalidate(); return true;
                case Keys.Back: if (_cmdText.Length > 0) _cmdText = ctrl ? "" : _cmdText[..^1]; Invalidate(); return true;
                case Keys.Up: if (_hist.Count > 0) { _histIdx = Math.Max(0, _histIdx - 1); _cmdText = _hist[_histIdx]; Invalidate(); } return true;
                case Keys.Down: if (_histIdx < _hist.Count - 1) { _histIdx++; _cmdText = _hist[_histIdx]; } else { _histIdx = _hist.Count; _cmdText = ""; } Invalidate(); return true;
                case Keys.V when ctrl: if (Clipboard.ContainsText()) _cmdText += Clipboard.GetText().Replace("\r", "").Replace("\n", " "); Invalidate(); return true;
                case Keys.Tab: return true;
            }
            return base.ProcessCmdKey(ref m, keyData);
        }

        switch (key)
        {
            case Keys.F1: _help = true; Invalidate(); return true;
            case Keys.O when ctrl: Browse(); return true;
            case Keys.F when ctrl: StartCmd("find "); return true;
            case Keys.G when ctrl: StartCmd("goto "); return true;
            case Keys.E when ctrl: Exec("export"); return true;
            case Keys.C when ctrl: Exec(shift ? "copyline" : "copy"); return true;
            case Keys.Q when ctrl: Close(); return true;
            case Keys.F3: FindNext(); return true;
            case Keys.F5: if (_s != null) Open(_s.FilePath); return true;
            case Keys.F9: Exec("theme"); return true;
            case Keys.Oemplus or Keys.Add when ctrl: Zoom(1); return true;
            case Keys.OemMinus or Keys.Subtract when ctrl: Zoom(-1); return true;
            case Keys.D0 or Keys.NumPad0 when ctrl: _pt = 10.5f; MakeFont(); SaveSettings(); return true;
            case Keys.Tab: if (_s != null) { _sec = (_sec + (shift ? NSec - 1 : 1)) % NSec; Invalidate(); } return true;
            case Keys.Escape:
                if (_s != null && _sec != HEX && _vs[_sec].Filter != null) { _vs[_sec].Filter = null; _vs[_sec].Map = null; Msg("Filter cleared", R.Dim); }
                else if (_hlStart >= 0) { _hlStart = -1; Invalidate(); }
                else if (_findPct >= 0) { _findCts?.Cancel(); _findPct = -1; Msg("Search cancelled", R.Dim); }
                return true;
        }
        if (_s == null) return base.ProcessCmdKey(ref m, keyData);
        if (Nav(key, ctrl, shift)) { Invalidate(); return true; }
        return base.ProcessCmdKey(ref m, keyData);
    }

    protected override void OnKeyPress(KeyPressEventArgs e)
    {
        char c = e.KeyChar;
        if (_help) return;
        if (_cmd) { if (c >= 0x20 && c != 0x7F) { _cmdText += c; Invalidate(); } e.Handled = true; return; }
        if (c == ':') { StartCmd(""); e.Handled = true; return; }
        if (c == '/') { StartCmd("filter "); e.Handled = true; return; }
        if (c == '?') { _help = true; Invalidate(); e.Handled = true; return; }
        if (_s != null && c >= '0' && c <= '9') { _sec = c == '0' ? 9 : c - '1'; Invalidate(); e.Handled = true; return; }
        if (_s != null && c == 'n') { FindNext(); e.Handled = true; }
    }

    void StartCmd(string prefill) { _cmd = true; _cmdText = prefill; _histIdx = _hist.Count; _blink = true; Invalidate(); }

    void Zoom(int d) { _pt = Math.Clamp(_pt + d, 7, 28); MakeFont(); SaveSettings(); Msg($"Font size {_pt:0.#} pt", R.Dim); }

    bool Nav(Keys key, bool ctrl, bool shift)
    {
        if (_sec == HEX)
        {
            long len = _s.Src.Length;
            if (len == 0) return false;
            long page = Math.Max(1, _hexRows - 1) * 16L;
            long c = _hexCur;
            switch (key)
            {
                case Keys.Left: c--; break;
                case Keys.Right: c++; break;
                case Keys.Up: c -= 16; break;
                case Keys.Down: c += 16; break;
                case Keys.PageUp: c -= page; _hexTop -= page / 16; break;
                case Keys.PageDown: c += page; _hexTop += page / 16; break;
                case Keys.Home: c = ctrl ? 0 : c / 16 * 16; break;
                case Keys.End: c = ctrl ? len - 1 : Math.Min(len - 1, c / 16 * 16 + 15); break;
                default: return false;
            }
            _hexCur = Math.Clamp(c, 0, len - 1);
            return true;
        }
        var doc = _s.Docs[_sec];
        if (doc == null) return false;
        var vs = _vs[_sec];
        int n = Count(vs, doc), h = Math.Max(1, _h - 1);
        switch (key)
        {
            case Keys.Up: vs.Cur--; break;
            case Keys.Down: vs.Cur++; break;
            case Keys.PageUp: vs.Cur -= h; vs.Top -= h; break;
            case Keys.PageDown: vs.Cur += h; vs.Top += h; break;
            case Keys.Home: vs.Cur = 0; vs.HScroll = 0; break;
            case Keys.End: vs.Cur = n - 1; break;
            case Keys.Left: vs.HScroll = Math.Max(0, vs.HScroll - (ctrl ? 40 : 8)); break;
            case Keys.Right: vs.HScroll += ctrl ? 40 : 8; break;
            case Keys.Enter: JumpFromLine(); break;
            default: return false;
        }
        vs.Cur = Math.Clamp(vs.Cur, 0, Math.Max(0, n - 1));
        vs.Top = Math.Clamp(vs.Top, 0, Math.Max(0, n - _h));
        return true;
    }

    void JumpFromLine()
    {
        var l = CurLine();
        if (l == null || l.Jump < 0) { Msg("This line has no file offset to jump to.", R.Dim); return; }
        GotoOffset(l.Jump);
    }

    void GotoOffset(long off)
    {
        if (_s == null) return;
        long len = _s.Src.Length;
        if (len == 0) return;
        _hexCur = Math.Clamp(off, 0, len - 1);
        _hexTop = Math.Max(0, _hexCur / 16 - 4);
        _sec = HEX;
        Msg($"Offset {Fmt.HxD(_hexCur)}" + (off >= len ? " (clamped to end of file)" : ""), R.Normal);
    }

    // ================================================================== mouse

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        Focus();
        if (_help) { _help = false; Invalidate(); return; }
        int cx = e.X / _cw, cy = e.Y / _ch;
        if (_s == null) { if (e.Button == MouseButtons.Left && cy > 0 && cy < _rows - 2) Browse(); return; }
        if (cx < SideW && cy >= 2 && cy < 2 + NSec) { _sec = cy - 2; Invalidate(); return; }
        if (cx == _sbX && cy >= _y0 && cy < _y0 + _h) { _sbDrag = true; ScrollTo(cy); return; }
        if (cx >= _x0 && cx < _x0 + _w && cy >= _y0 && cy < _y0 + _h)
        {
            if (_sec == HEX)
            {
                int r = cy - _hexY0;
                if (r < 0 || r >= _hexRows) return;
                int i = -1;
                if (cx >= _hexX && cx < _hexX + 49) { int rel = cx - _hexX; if (rel >= 25) rel--; i = Math.Min(15, rel / 3); }
                else if (cx >= _ascX && cx < _ascX + 16) i = cx - _ascX;
                if (i >= 0) { long o = (_hexTop + r) * 16 + i; if (o < _s.Src.Length) _hexCur = o; Invalidate(); }
                return;
            }
            var vs = _vs[_sec];
            vs.Cur = vs.Top + (cy - _y0);
            if (e.Clicks >= 2) JumpFromLine();
            Invalidate();
        }
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        if (_sbDrag && e.Button == MouseButtons.Left) ScrollTo(e.Y / _ch);
    }

    protected override void OnMouseUp(MouseEventArgs e) { base.OnMouseUp(e); _sbDrag = false; }

    void ScrollTo(int cy)
    {
        if (_s == null) return;
        double frac = Math.Clamp((cy - _y0) / (double)Math.Max(1, _h - 1), 0, 1);
        if (_sec == HEX)
        {
            long rows = (_s.Src.Length + 15) / 16;
            _hexTop = (long)(frac * Math.Max(0, rows - _hexRows));
            _hexCur = Math.Clamp(_hexTop * 16 + (_hexCur % 16), 0, Math.Max(0, _s.Src.Length - 1));
        }
        else if (_s.Docs[_sec] is Doc d)
        {
            var vs = _vs[_sec];
            int n = Count(vs, d);
            vs.Top = (int)(frac * Math.Max(0, n - _h));
            vs.Cur = Math.Clamp(vs.Top + _h / 2, 0, Math.Max(0, n - 1));
        }
        Invalidate();
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        base.OnMouseWheel(e);
        if (_s == null) return;
        int lines = -e.Delta / 40;
        if (ModifierKeys.HasFlag(Keys.Control)) { Zoom(e.Delta > 0 ? 1 : -1); return; }
        if (_sec == HEX)
        {
            long rows = (_s.Src.Length + 15) / 16;
            _hexTop = Math.Clamp(_hexTop + lines, 0, Math.Max(0, rows - _hexRows));
            long curRow = _hexCur / 16;
            if (curRow < _hexTop) _hexCur += (_hexTop - curRow) * 16;
            if (curRow >= _hexTop + _hexRows) _hexCur -= (curRow - _hexTop - _hexRows + 1) * 16;
            _hexCur = Math.Clamp(_hexCur, 0, Math.Max(0, _s.Src.Length - 1));
        }
        else if (_s.Docs[_sec] is Doc d)
        {
            var vs = _vs[_sec];
            int n = Count(vs, d);
            vs.Top = Math.Clamp(vs.Top + lines, 0, Math.Max(0, n - _h));
            vs.Cur = Math.Clamp(vs.Cur, vs.Top, Math.Max(vs.Top, Math.Min(n - 1, vs.Top + _h - 1)));
        }
        Invalidate();
    }

    // ================================================================== commands

    void Browse()
    {
        using var dlg = new OpenFileDialog { Title = "Inspect a file (read-only)", Filter = "All files (*.*)|*.*", DereferenceLinks = false, CheckFileExists = true };
        if (dlg.ShowDialog(this) == DialogResult.OK) Open(dlg.FileName);
    }

    void Exec(string line)
    {
        line = line.Trim();
        if (line.Length == 0) return;
        int sp = line.IndexOf(' ');
        string verb = (sp < 0 ? line : line[..sp]).ToLowerInvariant(), arg = sp < 0 ? "" : line[(sp + 1)..].Trim();
        switch (verb)
        {
            case "o" or "open": if (arg.Length > 0) Open(arg); else Browse(); return;
            case "help" or "?" or "h": _help = true; return;
            case "q" or "quit" or "exit": Close(); return;
            case "theme":
                {
                    int i = Array.FindIndex(Theme.All, t => t.Name.Replace(" ", "").Equals(arg.Replace(" ", ""), StringComparison.OrdinalIgnoreCase));
                    _th = i >= 0 ? Theme.All[i] : Theme.All[(Array.IndexOf(Theme.All, _th) + 1) % Theme.All.Length];
                    BackColor = _th[R.Bg]; SaveSettings(); Msg("Theme: " + _th.Name, R.Dim); return;
                }
            case "font":
                if (float.TryParse(arg, NumberStyles.Float, CultureInfo.InvariantCulture, out var f)) { _pt = Math.Clamp(f, 7, 28); MakeFont(); SaveSettings(); Msg($"Font size {_pt:0.#} pt", R.Dim); }
                else Msg("Usage: :font 11", R.Warn);
                return;
        }
        if (_s == null) { Msg("Open a file first (drag & drop or Ctrl+O).", R.Warn); return; }
        switch (verb)
        {
            case "g" or "goto" or "go":
                if (TryParseOffset(arg, out long off)) GotoOffset(off); else Msg("Usage: :goto 0x1F4 | 500 | 1F4h | +16 | -0x10 | end | 50%", R.Warn);
                return;
            case "f" or "find": if (arg.Length == 0) { Msg("Usage: :find text", R.Warn); return; } StartFind(Encoding.UTF8.GetBytes(arg), $"\"{arg}\""); return;
            case "fu" or "findu": if (arg.Length == 0) { Msg("Usage: :findu text", R.Warn); return; } StartFind(Encoding.Unicode.GetBytes(arg), $"UTF-16 \"{arg}\""); return;
            case "fx" or "findhex" or "fh":
                try
                {
                    string hex = new string(arg.Where(Uri.IsHexDigit).ToArray());
                    if (hex.Length == 0 || hex.Length % 2 == 1) throw new FormatException();
                    StartFind(Convert.FromHexString(hex), "hex " + Fmt.Bytes(Convert.FromHexString(hex), 16));
                }
                catch { Msg("Usage: :findhex 4D 5A 90 00", R.Warn); }
                return;
            case "filter" or "filt":
                {
                    int target = _sec == HEX ? (int)Sec.Strings : _sec;
                    _sec = target;
                    var vs = _vs[target];
                    vs.Filter = arg.Length == 0 ? null : arg; vs.Map = null; vs.Cur = vs.Top = 0;
                    Msg(arg.Length == 0 ? "Filter cleared" : $"Filtering {Session.Names[target]} for \"{arg}\"  (Esc clears)", R.Dim);
                    return;
                }
            case "export" or "save" or "report": Export(arg); return;
            case "copy":
                {
                    string text;
                    if (_sec == HEX)
                    {
                        var sb = new StringBuilder();
                        long start = _hexCur / 16 * 16;
                        var b = _s.Src.Bytes(start, 256);
                        for (int r = 0; r < b.Length; r += 16) { var row = b.AsSpan(r, Math.Min(16, b.Length - r)); sb.AppendLine($"{start + r:X8}  {Fmt.Bytes(row, 16).PadRight(47)}  |{Fmt.AsciiPreview(row, 16)}|"); }
                        text = sb.ToString();
                    }
                    else
                    {
                        var d = _s.Docs[_sec]; if (d == null) return;
                        var vs = _vs[_sec]; int n = Count(vs, d);
                        var sb = new StringBuilder();
                        for (int i = 0; i < n; i++) sb.AppendLine(GetLine(vs, d, i).Plain.TrimEnd());
                        text = sb.ToString();
                    }
                    try { Clipboard.SetText(text.Length == 0 ? " " : text); Msg($"Copied {Session.Names[_sec]} ({text.Length:N0} chars) to the clipboard", R.Good); } catch (Exception ex) { Msg("Clipboard error: " + ex.Message, R.Bad); }
                    return;
                }
            case "copyline":
                {
                    string t = _sec == HEX ? Fmt.Hx(_hexCur) : CurLine()?.Plain.Trim();
                    if (!string.IsNullOrEmpty(t)) { try { Clipboard.SetText(t); Msg("Copied: " + Fmt.Trunc(t, 80), R.Good); } catch { } }
                    return;
                }
            case "reload": Open(_s.FilePath); return;
            case "s" or "sec" or "section": if (int.TryParse(arg, out int sn) && sn >= 0 && sn <= 9) _sec = sn == 0 ? 9 : sn - 1; return;
        }
        if (TryParseOffset(line, out long o2)) { GotoOffset(o2); return; }
        Msg($"Unknown command '{verb}' – press F1 for help", R.Warn);
    }

    bool TryParseOffset(string a, out long off)
    {
        off = 0;
        a = a.Trim().Replace("_", "").Replace(",", "");
        if (a.Length == 0) return false;
        long len = _s.Src.Length;
        if (a.Equals("end", StringComparison.OrdinalIgnoreCase)) { off = Math.Max(0, len - 1); return true; }
        if (a.Equals("start", StringComparison.OrdinalIgnoreCase)) { off = 0; return true; }
        int sign = 0;
        if (a[0] == '+') { sign = 1; a = a[1..]; } else if (a[0] == '-') { sign = -1; a = a[1..]; }
        long v;
        if (a.EndsWith('%') && double.TryParse(a[..^1], NumberStyles.Float, CultureInfo.InvariantCulture, out double pct)) v = (long)(len * Math.Clamp(pct, 0, 100) / 100);
        else if (a.StartsWith("0x", StringComparison.OrdinalIgnoreCase) || a.StartsWith("$")) { if (!long.TryParse(a.TrimStart('$')[(a.StartsWith("$") ? 0 : 2)..], NumberStyles.HexNumber, null, out v)) return false; }
        else if (a.EndsWith("h", StringComparison.OrdinalIgnoreCase)) { if (!long.TryParse(a[..^1], NumberStyles.HexNumber, null, out v)) return false; }
        else if (!long.TryParse(a, out v)) { if (a.Any(ch => "abcdefABCDEF".Contains(ch)) && long.TryParse(a, NumberStyles.HexNumber, null, out v)) { } else return false; }
        off = sign == 0 ? v : _hexCur + sign * v;
        return true;
    }

    void StartFind(byte[] pat, string label)
    {
        _findCts?.Cancel();
        var cts = new CancellationTokenSource();
        _findCts = cts;
        _lastFind = pat; _lastFindLabel = label;
        var s = _s;
        long start = _hlStart >= 0 && _hlStart == _hexCur ? _hexCur + 1 : _hexCur + (_sec == HEX ? 1 : 0);
        if (_hlStart < 0 && _sec != HEX) start = 0;
        _findPct = 0;
        Msg($"Searching for {label}…  (Esc cancels)", R.Dim);
        Task.Run(() =>
        {
            long len = s.Src.Length, hit = -1;
            int plen = pat.Length;
            var buf = new byte[(8 << 20) + plen];
            long scanned = 0;
            foreach (var (a, b) in new[] { (start, len), (0L, Math.Min(len, start + plen - 1)) })
            {
                long off = a;
                while (off < b && !cts.IsCancellationRequested)
                {
                    int want = (int)Math.Min(buf.Length, len - off);
                    int n = s.Src.ReadAt(off, buf.AsSpan(0, want));
                    if (n < plen) break;
                    int i = buf.AsSpan(0, n).IndexOf(pat);
                    if (i >= 0 && off + i < b) { hit = off + i; break; }
                    if (i >= 0) break;
                    long adv = Math.Max(1, n - plen + 1);
                    off += adv; scanned += adv;
                    _findPct = (int)Math.Min(99, scanned * 100 / Math.Max(1, len));
                    if (n < want) break;
                }
                if (hit >= 0 || cts.IsCancellationRequested) break;
            }
            if (cts.IsCancellationRequested) return;
            BeginInvoke(() =>
            {
                if (!ReferenceEquals(s, _s)) return;
                _findPct = -1;
                if (hit < 0) { Msg($"{label} not found", R.Warn); return; }
                _hlStart = hit; _hlLen = plen;
                GotoOffset(hit);
                Msg($"Found {label} at {Fmt.HxD(hit)}{(hit < start ? " (wrapped around)" : "")}   F3 / n = next", R.Good);
            });
        });
    }

    void FindNext()
    {
        if (_lastFind == null) { StartCmd("find "); return; }
        if (_s == null) return;
        _hlStart = _hexCur;
        _sec = HEX;
        StartFind(_lastFind, _lastFindLabel);
    }

    void Export(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                using var dlg = new SaveFileDialog { Title = "Export inspection report", Filter = "Text report (*.txt)|*.txt|All files (*.*)|*.*", FileName = Path.GetFileName(_s.FilePath) + ".report.txt" };
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                path = dlg.FileName;
            }
            path = path.Trim('"');
            File.WriteAllText(path, _s.BuildReport(), new UTF8Encoding(true));
            Msg("Report saved: " + path, R.Good);
        }
        catch (Exception ex) { Msg("Export failed: " + ex.Message, R.Bad); }
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        _timer.Stop();
        _findCts?.Cancel();
        _s?.Cts.Cancel();
        base.OnFormClosed(e);
    }
}
