using System.Text;
using System.Text.RegularExpressions;

namespace Ufi.Core;

public readonly record struct StrHit(long Off, char Kind, string Text);

/// <summary>Strings extraction, embedded-file carving and indicator (IOC) extraction.</summary>
public static class Scanner
{
    public const long ScanCap = 256L << 20;
    public const int MinLen = 5, MaxStrings = 250_000, MaxStrLen = 400;

    public sealed class Result
    {
        public List<StrHit> Strings = new();
        public bool StringsCapped;
        public long Scanned;
        public List<(long Off, string What)> Carved = new();
    }

    static readonly (string Name, byte[] Sig, Func<ByteSource, long, bool> Check)[] Carve =
    {
        ("PE executable (MZ…PE)", "MZ"u8.ToArray(), (s, o) => s.Has(o, 0x40) && s.U32(o + 0x3C) is var p && p >= 0x40 && p < 0x1000 && s.Has(o + p, 4) && s.U32(o + p) == 0x4550),
        ("ELF executable", "\x7F"u8.ToArray().Concat("ELF"u8.ToArray()).ToArray(), (s, o) => s.Has(o, 20) && s.U8(o + 4) is 1 or 2 && s.U8(o + 5) is 1 or 2),
        ("ZIP local file header", "PK\x03\x04"u8.ToArray(), (s, o) => s.Has(o, 30) && s.U16(o + 4) <= 63 && s.U16(o + 26) is > 0 and < 1024),
        ("PDF document", "%PDF-"u8.ToArray(), (s, o) => true),
        ("PNG image", new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, (s, o) => true),
        ("JPEG image", new byte[] { 0xFF, 0xD8, 0xFF }, (s, o) => s.Has(o, 4) && s.U8(o + 3) is 0xE0 or 0xE1 or 0xDB or 0xEE or 0xE2),
        ("GIF image", "GIF89a"u8.ToArray(), (s, o) => true),
        ("GIF image", "GIF87a"u8.ToArray(), (s, o) => true),
        ("7-Zip archive", new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }, (s, o) => true),
        ("RAR archive", "Rar!\x1A\x07"u8.ToArray(), (s, o) => true),
        ("Cabinet archive", "MSCF\0\0\0\0"u8.ToArray(), (s, o) => true),
        ("OLE2 compound file", new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }, (s, o) => true),
        ("GZIP stream", new byte[] { 0x1F, 0x8B, 0x08 }, (s, o) => s.Has(o, 10) && s.U8(o + 3) < 0x20 && s.U8(o + 9) is <= 13 or 255),
        ("SQLite database", "SQLite format 3\0"u8.ToArray(), (s, o) => true),
        ("RTF document", "{\\rtf"u8.ToArray(), (s, o) => true),
        ("PEM block", "-----BEGIN "u8.ToArray(), (s, o) => true),
        ("BZIP2 stream", "BZh91AY&SY"u8.ToArray(), (s, o) => true),
        ("XZ stream", new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 }, (s, o) => true),
        ("Java class", new byte[] { 0xCA, 0xFE, 0xBA, 0xBE }, (s, o) => s.Has(o, 8) && s.U16(o + 6, true) is >= 45 and < 80),
        ("Windows shortcut (LNK)", new byte[] { 0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0x00 }, (s, o) => true),
        ("ISO BMFF (MP4/MOV)", "ftyp"u8.ToArray(), (s, o) => o >= 4 && s.U32(o - 4, true) is >= 8 and < 256),
        ("Nullsoft (NSIS) installer data", new byte[] { 0xEF, 0xBE, 0xAD, 0xDE, 0x4E, 0x75, 0x6C, 0x6C }, (s, o) => true),
    };

    public static Result Run(ByteSource s, string mainKind, CancellationToken ct, Action<int> progress)
    {
        var r = new Result();
        long len = Math.Min(s.Length, ScanCap);
        r.Scanned = len;
        const int Chunk = 4 << 20, Overlap = 64;
        var buf = new byte[Chunk + Overlap];

        // strings state
        var asb = new StringBuilder(); long aStart = 0;
        var usb = new[] { new StringBuilder(), new StringBuilder() };
        var uStart = new long[2];
        var low = new int[] { -1, -1 };

        var carvedSeen = new HashSet<long>();
        long off = 0;
        while (off < len)
        {
            ct.ThrowIfCancellationRequested();
            int want = (int)Math.Min(Chunk + Overlap, len - off);
            int n = s.ReadAt(off, buf.AsSpan(0, want));
            if (n <= 0) break;
            int body = (int)Math.Min(n, Chunk);   // bytes owned by this chunk
            var span = buf.AsSpan(0, n);

            // --- strings ---
            for (int i = 0; i < body; i++)
            {
                byte b = span[i];
                long o = off + i;
                bool pr = (b >= 0x20 && b < 0x7F) || b == 9;
                if (pr) { if (asb.Length == 0) aStart = o; if (asb.Length < MaxStrLen) asb.Append((char)b); else asb.Append(""); }
                else if (asb.Length > 0) { Flush(r, asb, aStart, 'A'); }

                // UTF-16LE: this byte is the high byte of the char begun at o-1 (sequence q), and the low byte of sequence (o&1)
                int q = (int)((o - 1) & 1);
                int lb = low[q];
                if (lb >= 0 && b == 0 && ((lb >= 0x20 && lb < 0x7F) || lb == 9))
                {
                    if (usb[q].Length == 0) uStart[q] = o - 1;
                    if (usb[q].Length < MaxStrLen) usb[q].Append((char)lb);
                }
                else if (lb >= 0 && usb[q].Length > 0) Flush(r, usb[q], uStart[q], 'U');
                low[(int)(o & 1)] = b;
            }

            // --- carving ---
            if (r.Carved.Count < 5000)
            {
                foreach (var (name, sig, check) in Carve)
                {
                    int from = 0;
                    while (from < body)
                    {
                        int idx = span[from..].IndexOf(sig);
                        if (idx < 0) break;
                        long at = off + from + idx;
                        from += idx + 1;
                        if (from - 1 >= body) break;
                        if (at == 0) continue;
                        if (mainKind == "zip" && sig[0] == (byte)'P') continue;
                        if (mainKind == "isobmff" && name.StartsWith("ISO")) continue;
                        bool ok; try { ok = check(s, at); } catch { ok = false; }
                        if (ok && carvedSeen.Add(at)) r.Carved.Add((at, name));
                        if (r.Carved.Count >= 5000) break;
                    }
                }
            }

            off += body;
            progress?.Invoke((int)(off * 100 / Math.Max(1, len)));
        }
        if (asb.Length > 0) Flush(r, asb, aStart, 'A');
        for (int q = 0; q < 2; q++) if (usb[q].Length > 0) Flush(r, usb[q], uStart[q], 'U');
        r.Strings.Sort((a, b) => a.Off.CompareTo(b.Off));
        r.Carved.Sort((a, b) => a.Off.CompareTo(b.Off));
        return r;
    }

    static void Flush(Result r, StringBuilder sb, long start, char kind)
    {
        if (sb.Length >= MinLen)
        {
            if (r.Strings.Count < MaxStrings) r.Strings.Add(new StrHit(start, kind, sb.ToString()));
            else r.StringsCapped = true;
        }
        sb.Clear();
    }

    // ------------------------------------------------------------------ indicators

    static readonly Regex ReUrl = new(@"\b(?:https?|ftp|hxxps?|wss?|file)://[^\s""'<>\x00`{}|\\^]{3,}", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    static readonly Regex ReIp = new(@"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?::\d{1,5})?(?![\d.])", RegexOptions.Compiled);
    static readonly Regex ReEmail = new(@"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}\b", RegexOptions.Compiled);
    static readonly Regex RePath = new(@"\b[A-Za-z]:\\[^\s""'<>|*?\x00]{2,}|\\\\[A-Za-z0-9._$-]{2,}\\[^\s""'<>|*?]+|%(?:APPDATA|TEMP|TMP|USERPROFILE|LOCALAPPDATA|PROGRAMDATA|SYSTEMROOT|WINDIR|PUBLIC|PROGRAMFILES)%\\?[^\s""'<>|*?]*", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    static readonly Regex ReReg = new(@"\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU)\\[^\s""'<>\x00]+|\bSOFTWARE\\(?:Microsoft|Wow6432Node|Policies|Classes)\\[^\s""'<>\x00]+|\bSYSTEM\\CurrentControlSet\\[^\s""'<>\x00]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    static readonly Regex ReB64 = new(@"(?:[A-Za-z0-9+/]{4}){24,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", RegexOptions.Compiled);
    static readonly Regex ReCrypto = new(@"\b(?:bc1[ac-hj-np-z02-9]{25,59}|0x[a-fA-F0-9]{40}|[a-z2-7]{56}\.onion)\b", RegexOptions.Compiled);
    static readonly Regex ReGuid = new(@"\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?", RegexOptions.Compiled);
    static readonly Regex ReDomain = new(@"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|online|site|club|tk|ml|ga|cf|gq|pw|cc|su|onion|de|uk|co|me|tv|app|dev|cloud|link|live|shop|icu|kr|jp|br|in|ir|ua|pl|fr|it|nl|es|eu|us|ca|au)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    static readonly Dictionary<string, string> Apis = BuildApis();
    static Dictionary<string, string> BuildApis()
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        void Add(string cat, string list) { foreach (var a in list.Split(' ', StringSplitOptions.RemoveEmptyEntries)) d[a] = cat; }
        Add("Process injection", "VirtualAllocEx WriteProcessMemory ReadProcessMemory CreateRemoteThread CreateRemoteThreadEx NtCreateThreadEx RtlCreateUserThread QueueUserAPC NtQueueApcThread SetThreadContext GetThreadContext NtUnmapViewOfSection ZwUnmapViewOfSection NtWriteVirtualMemory NtAllocateVirtualMemory NtMapViewOfSection VirtualProtectEx");
        Add("Memory / code loading", "VirtualAlloc VirtualProtect LoadLibraryA LoadLibraryW LoadLibraryExA LoadLibraryExW GetProcAddress LdrLoadDll LdrGetProcedureAddress HeapCreate");
        Add("Anti-debug / anti-analysis", "IsDebuggerPresent CheckRemoteDebuggerPresent NtQueryInformationProcess OutputDebugStringA OutputDebugStringW NtSetInformationThread ZwSetInformationThread GetTickCount64 QueryPerformanceCounter");
        Add("Process execution", "WinExec ShellExecuteA ShellExecuteW ShellExecuteExA ShellExecuteExW CreateProcessA CreateProcessW CreateProcessAsUserA CreateProcessAsUserW CreateProcessWithTokenW CreateProcessWithLogonW system _wsystem");
        Add("Networking", "URLDownloadToFileA URLDownloadToFileW InternetOpenA InternetOpenW InternetOpenUrlA InternetOpenUrlW InternetReadFile InternetConnectA InternetConnectW HttpOpenRequestA HttpOpenRequestW HttpSendRequestA HttpSendRequestW WinHttpOpen WinHttpConnect WinHttpSendRequest WSAStartup WSASocketA WSASocketW gethostbyname getaddrinfo DnsQuery_A DnsQuery_W FtpPutFileA");
        Add("Cryptography", "CryptEncrypt CryptDecrypt CryptAcquireContextA CryptAcquireContextW CryptGenKey CryptImportKey BCryptEncrypt BCryptDecrypt BCryptGenerateSymmetricKey CryptUnprotectData CryptProtectData");
        Add("Keylogging / spying", "SetWindowsHookExA SetWindowsHookExW GetAsyncKeyState GetKeyState GetKeyboardState GetClipboardData SetClipboardData BitBlt GetDC GetForegroundWindow GetWindowTextA GetWindowTextW keybd_event mouse_event BlockInput");
        Add("Registry / persistence", "RegSetValueExA RegSetValueExW RegCreateKeyExA RegCreateKeyExW RegDeleteKeyA RegDeleteKeyW RegOpenKeyExA RegOpenKeyExW CreateServiceA CreateServiceW StartServiceA StartServiceW OpenSCManagerA OpenSCManagerW ChangeServiceConfigA ChangeServiceConfigW");
        Add("Privilege / credentials", "AdjustTokenPrivileges OpenProcessToken LookupPrivilegeValueA LookupPrivilegeValueW DuplicateTokenEx ImpersonateLoggedOnUser LogonUserA LogonUserW MiniDumpWriteDump LsaRetrievePrivateData CredEnumerateA CredEnumerateW SamIConnect NetUserAdd NetLocalGroupAddMembers");
        Add("Process discovery", "CreateToolhelp32Snapshot Process32First Process32FirstW Process32Next Process32NextW Module32First Module32Next EnumProcesses EnumProcessModules OpenProcess");
        Add("Defense evasion", "AmsiScanBuffer AmsiInitialize EtwEventWrite NtTraceEvent SetFileTime SetFileAttributesA SetFileAttributesW MoveFileExA MoveFileExW DeleteFileA DeleteFileW");
        return d;
    }

    static readonly (string Cat, string Pattern)[] ScriptWords =
    {
        ("PowerShell", "powershell"), ("PowerShell", "-encodedcommand"), ("PowerShell", " -enc "), ("PowerShell", "invoke-expression"), ("PowerShell", "iex("),
        ("PowerShell", "downloadstring"), ("PowerShell", "downloadfile"), ("PowerShell", "invoke-webrequest"), ("PowerShell", "frombase64string"),
        ("PowerShell", "-windowstyle hidden"), ("PowerShell", "-executionpolicy bypass"), ("PowerShell", "net.webclient"), ("PowerShell", "start-process"),
        ("Shell / LOLBins", "cmd.exe /c"), ("Shell / LOLBins", "cmd /c"), ("Shell / LOLBins", "mshta"), ("Shell / LOLBins", "rundll32"), ("Shell / LOLBins", "regsvr32"),
        ("Shell / LOLBins", "certutil"), ("Shell / LOLBins", "bitsadmin"), ("Shell / LOLBins", "schtasks"), ("Shell / LOLBins", "wmic "),
        ("Shell / LOLBins", "vssadmin delete shadows"), ("Shell / LOLBins", "bcdedit"), ("Shell / LOLBins", "wevtutil cl"), ("Shell / LOLBins", "msiexec"),
        ("Shell / LOLBins", "cscript"), ("Shell / LOLBins", "wscript"), ("Shell / LOLBins", "curl "), ("Shell / LOLBins", "/bin/sh"), ("Shell / LOLBins", "/bin/bash"),
        ("Script / macro", "wscript.shell"), ("Script / macro", "shell.application"), ("Script / macro", "createobject"), ("Script / macro", "activexobject"),
        ("Script / macro", "autoopen"), ("Script / macro", "auto_open"), ("Script / macro", "document_open"), ("Script / macro", "workbook_open"),
        ("Script / macro", "eval("), ("Script / macro", "unescape("), ("Script / macro", "string.fromcharcode"), ("Script / macro", "document.write("),
        ("Script / macro", "adodb.stream"), ("Script / macro", "msxml2.xmlhttp"), ("Script / macro", "scripting.filesystemobject"),
        ("Persistence", "\\currentversion\\run"), ("Persistence", "\\startup\\"), ("Persistence", "userinit"), ("Persistence", "image file execution options"),
        ("Network", "mozilla/5.0"), ("Network", "user-agent"), ("Network", "content-type:"), ("Network", "post /"), ("Network", "get /"),
        ("Crypto / ransom", "your files have been encrypted"), ("Crypto / ransom", "bitcoin"), ("Crypto / ransom", "decrypt"), ("Crypto / ransom", ".onion"),
        ("Anti-VM", "vmware"), ("Anti-VM", "virtualbox"), ("Anti-VM", "vbox"), ("Anti-VM", "qemu"), ("Anti-VM", "sandboxie"), ("Anti-VM", "wine_get_unix_file_name"),
    };

    public sealed class Ioc
    {
        public readonly Dictionary<string, List<(string Value, long Off, int Count)>> Groups = new();
        public void Add(string group, string value, long off)
        {
            if (!Groups.TryGetValue(group, out var l)) Groups[group] = l = new();
            int i = l.FindIndex(x => x.Value == value);
            if (i >= 0) l[i] = (l[i].Value, l[i].Off, l[i].Count + 1);
            else if (l.Count < 2000) l.Add((value, off, 1));
        }
    }

    public static Ioc Indicators(List<StrHit> strings, IEnumerable<string> extra, CancellationToken ct)
    {
        var ioc = new Ioc();
        void Check(string t, long off)
        {
            foreach (Match m in ReUrl.Matches(t)) ioc.Add("URLs", m.Value.TrimEnd('.', ',', ')', ';'), off);
            foreach (Match m in ReIp.Matches(t))
            {
                string v = m.Value;
                if (v.StartsWith("0.")) continue;
                ioc.Add("IPv4 addresses", v, off);
            }
            foreach (Match m in ReEmail.Matches(t)) ioc.Add("E-mail addresses", m.Value, off);
            foreach (Match m in RePath.Matches(t)) ioc.Add("File system paths", m.Value, off);
            foreach (Match m in ReReg.Matches(t)) ioc.Add("Registry keys", m.Value, off);
            foreach (Match m in ReCrypto.Matches(t)) ioc.Add("Crypto wallets / onion", m.Value, off);
            if (t.Length < 200) foreach (Match m in ReDomain.Matches(t)) if (!m.Value.Contains("..")) ioc.Add("Domain names", m.Value.ToLowerInvariant(), off);
            if (t.Length < 60 && Apis.TryGetValue(t.Trim(), out var cat)) ioc.Add("Suspicious API: " + cat, t.Trim(), off);
            string lt = t.ToLowerInvariant();
            foreach (var (c, p) in ScriptWords) if (lt.Contains(p)) ioc.Add("Keyword: " + c, Fmt.Trunc(t.Trim(), 160), off);
            if (t.Length >= 96)
                foreach (Match m in ReB64.Matches(t))
                {
                    string note = DescribeBase64(m.Value);
                    ioc.Add("Base64 blobs", $"{m.Length} chars{note}: {Fmt.Trunc(m.Value, 70)}", off);
                }
        }
        int k = 0;
        foreach (var sh in strings)
        {
            if ((++k & 1023) == 0) ct.ThrowIfCancellationRequested();
            Check(sh.Text, sh.Off);
        }
        foreach (var e in extra ?? Enumerable.Empty<string>()) Check(e, -1);
        return ioc;
    }

    static string DescribeBase64(string b64)
    {
        try
        {
            string s = b64.Length % 4 == 0 ? b64 : b64[..(b64.Length - b64.Length % 4)];
            var bytes = Convert.FromBase64String(s.Length > 4096 ? s[..4096] : s);
            var q = Detect.Quick(bytes);
            if (q != null) return $" → decodes to {q}";
            var (isText, _, _) = Detect.SniffText(bytes);
            if (isText) return " → decodes to text: \"" + Fmt.Trunc(Encoding.UTF8.GetString(bytes).Replace('\n', ' ').Replace('\r', ' '), 50) + "\"";
            if (bytes.Length > 8 && bytes.Where((b, i) => i % 2 == 1).All(b => b == 0))
                return " → decodes to UTF-16 text: \"" + Fmt.Trunc(Encoding.Unicode.GetString(bytes), 50) + "\"";
        }
        catch { }
        return "";
    }

    public static bool IsGuidLike(string s) => ReGuid.IsMatch(s);
}
