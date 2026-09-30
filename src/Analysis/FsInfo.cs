using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Ufi.Core;

namespace Ufi.Analysis;

/// <summary>File-system level metadata: timestamps, attributes, NTFS IDs, alternate data streams, ACLs.</summary>
public static class FsInfo
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WIN32_FIND_STREAM_DATA { public long StreamSize; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)] public string cStreamName; }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    struct BY_HANDLE_FILE_INFORMATION
    {
        public uint Attrs; public long Created, Accessed, Written; public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr FindFirstStreamW(string name, int level, out WIN32_FIND_STREAM_DATA data, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool FindNextStreamW(IntPtr h, out WIN32_FIND_STREAM_DATA data);
    [DllImport("kernel32.dll")] static extern bool FindClose(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle h, out BY_HANDLE_FILE_INFORMATION info);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetCompressedFileSizeW(string name, out uint high);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint GetFinalPathNameByHandleW(SafeFileHandle h, StringBuilder buf, uint len, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool GetDiskFreeSpaceW(string root, out uint spc, out uint bps, out uint free, out uint total);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool GetVolumeInformationW(string root, StringBuilder name, int nameLen, out uint serial, out uint maxComp, out uint flags, StringBuilder fs, int fsLen);

    public sealed class Snapshot
    {
        public DateTime Created, Modified, Accessed; public FileAttributes Attrs; public long Length;
    }

    public static Snapshot Capture(string path)
    {
        var fi = new FileInfo(path);
        return new Snapshot { Created = fi.CreationTimeUtc, Modified = fi.LastWriteTimeUtc, Accessed = fi.LastAccessTimeUtc, Attrs = fi.Attributes, Length = fi.Length };
    }

    public static Doc Build(string path, Snapshot snap, Ctx ctx)
    {
        var d = new Doc();
        var fi = new FileInfo(path);
        d.H("Location");
        d.KV("Full path", fi.FullName, R.Accent);
        d.KV("Directory", fi.DirectoryName, R.Str);
        d.KV("File name", fi.Name, R.Str);
        d.KV("Name (escaped)", Fmt.Escape(fi.Name), R.Dim);
        d.KV("Name length", $"{fi.Name.Length} chars, full path {fi.FullName.Length} chars", R.Num);
        d.KV("Extension", fi.Extension.Length > 0 ? fi.Extension : "(none)", R.Value);
        try
        {
            using var h = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var sb = new StringBuilder(1024);
            if (GetFinalPathNameByHandleW(h, sb, 1024, 0) > 0) d.KV("Final path (resolved)", sb.ToString().Replace(@"\\?\", ""), R.Str);
            if (GetFileInformationByHandle(h, out var bi))
            {
                d.H("NTFS identity");
                d.KV("Volume serial number", bi.VolumeSerial.ToString("X8").Insert(4, "-"), R.Hex);
                d.KV("File ID (MFT reference)", $"0x{bi.IndexHigh:X8}{bi.IndexLow:X8}", R.Hex);
                d.KV("MFT record number", ((((ulong)bi.IndexHigh & 0xFFFF) << 32) | bi.IndexLow).ToString("N0") + $"  (sequence {bi.IndexHigh >> 16})", R.Num);
                d.KV("Hard link count", bi.Links, bi.Links > 1 ? R.Warn : R.Num);
                if (bi.Links > 1) ctx.Info("File system", $"File has {bi.Links} hard links (same data under other names)");
            }
        }
        catch (Exception ex) { d.Warn("Handle info unavailable: " + ex.Message); }

        d.H("Timestamps (captured before the file was opened)");
        d.KV("Created", Fmt.Time(snap.Created), R.Value);
        d.KV("Modified", Fmt.Time(snap.Modified), R.Value);
        d.KV("Accessed", Fmt.Time(snap.Accessed), R.Value);
        d.KV("Created (FILETIME)", Fmt.Hx(snap.Created.ToFileTimeUtc(), 16), R.Hex);
        d.KV("Modified (FILETIME)", Fmt.Hx(snap.Modified.ToFileTimeUtc(), 16), R.Hex);
        if (snap.Modified < snap.Created) d.Info("Modified < Created: the file was copied (copies keep the modified time) or timestamps were altered.");
        if (snap.Created.ToFileTimeUtc() % 10_000_000 == 0 && snap.Modified.ToFileTimeUtc() % 10_000_000 == 0)
            ctx.Info("File system", "Timestamps have whole-second precision (extracted from an archive, or possible timestomping)");
        if (snap.Modified > DateTime.UtcNow.AddMinutes(5)) ctx.Warn("File system", "Modification time lies in the future");

        d.H("Size & attributes");
        d.KV("Logical size", Fmt.Size(snap.Length), R.Num);
        try
        {
            uint lo = GetCompressedFileSizeW(path, out uint hi);
            long onDisk = (long)hi << 32 | lo;
            string root = Path.GetPathRoot(fi.FullName);
            if (GetDiskFreeSpaceW(root, out uint spc, out uint bps, out _, out _))
            {
                long cluster = (long)spc * bps;
                long alloc = (onDisk + cluster - 1) / cluster * cluster;
                d.KV("Size on disk", Fmt.Size(alloc) + $"  (cluster {cluster} bytes)", R.Num);
                if (alloc > snap.Length) d.KV("Slack space", Fmt.Size(alloc - snap.Length) + " (end of last cluster)", R.Dim);
            }
            if (onDisk != snap.Length) d.KV("Compressed / sparse size", Fmt.Size(onDisk), R.Num);
        }
        catch { }
        d.KV("Attributes", $"{Fmt.Hx((int)snap.Attrs, 8)}  {snap.Attrs}", R.Value);
        foreach (var (flag, meaning) in new (FileAttributes, string)[]
        {
            (FileAttributes.ReadOnly, "read-only"), (FileAttributes.Hidden, "HIDDEN"), (FileAttributes.System, "SYSTEM"), (FileAttributes.Archive, "archive bit set"),
            (FileAttributes.Temporary, "temporary"), (FileAttributes.SparseFile, "sparse file"), (FileAttributes.ReparsePoint, "REPARSE POINT (symlink/junction/cloud)"),
            (FileAttributes.Compressed, "NTFS-compressed"), (FileAttributes.Offline, "offline"), (FileAttributes.NotContentIndexed, "not indexed"),
            (FileAttributes.Encrypted, "EFS-encrypted"), (FileAttributes.IntegrityStream, "integrity stream (ReFS)"), (FileAttributes.NoScrubData, "no scrub"),
        })
            if ((snap.Attrs & flag) != 0) d.T("      • " + meaning, R.Str);
        if ((snap.Attrs & FileAttributes.Hidden) != 0) ctx.Warn("File system", "File is marked HIDDEN");
        if ((snap.Attrs & FileAttributes.System) != 0) ctx.Info("File system", "File has the SYSTEM attribute");
        if ((snap.Attrs & FileAttributes.ReparsePoint) != 0)
        {
            try { d.KV("Link target", fi.LinkTarget ?? "(not a symbolic link – other reparse type, e.g. OneDrive placeholder)", R.Accent); } catch { }
        }

        // Alternate data streams
        d.H("NTFS alternate data streams");
        var streams = new List<(string name, long size)>();
        IntPtr fh = FindFirstStreamW(path, 0, out var sd, 0);
        if (fh != new IntPtr(-1))
        {
            try { do streams.Add((sd.cStreamName, sd.StreamSize)); while (FindNextStreamW(fh, out sd)); }
            finally { FindClose(fh); }
        }
        foreach (var (name, size) in streams)
        {
            bool main = name == "::$DATA";
            d.KV(main ? "::$DATA (main stream)" : name, Fmt.Size(size), main ? R.Num : R.Warn);
            if (main) continue;
            string sname = name.EndsWith(":$DATA") ? name[..^6] : name;
            byte[] content = null;
            try
            {
                using var fs = new FileStream(path + sname, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                content = new byte[Math.Min(size, 64 * 1024)];
                int got = 0; while (got < content.Length) { int n = fs.Read(content, got, content.Length - got); if (n <= 0) break; got += n; }
            }
            catch (Exception ex) { d.T("      (could not read: " + ex.Message + ")", R.Dim); }
            if (content == null) continue;
            if (sname.Equals(":Zone.Identifier", StringComparison.OrdinalIgnoreCase))
            {
                string z = Encoding.UTF8.GetString(content);
                d.Sub("Mark of the Web (Zone.Identifier)");
                d.Text(z, R.Accent, "      ", 40);
                var zm = System.Text.RegularExpressions.Regex.Match(z, @"ZoneId=(\d)");
                string zone = zm.Success ? zm.Groups[1].Value switch { "0" => "Local computer", "1" => "Local intranet", "2" => "Trusted sites", "3" => "Internet", "4" => "Restricted sites", _ => "?" } : "?";
                var host = System.Text.RegularExpressions.Regex.Match(z, @"HostUrl=(.*)");
                var refr = System.Text.RegularExpressions.Regex.Match(z, @"ReferrerUrl=(.*)");
                ctx.Warn("Origin", $"Downloaded file – zone: {zone}" + (host.Success ? $", from {host.Groups[1].Value.Trim()}" : "") + (refr.Success ? $" (referrer {refr.Groups[1].Value.Trim()})" : ""));
                if (host.Success) ctx.ExtraStrings.Add(host.Groups[1].Value.Trim());
                if (refr.Success) ctx.ExtraStrings.Add(refr.Groups[1].Value.Trim());
            }
            else
            {
                ctx.Warn("File system", $"Hidden alternate data stream '{sname}' ({Fmt.Human(size)})");
                string q = Detect.Quick(content);
                d.T($"      content: {q ?? (Detect.SniffText(content).isText ? "text" : "binary")}   first bytes: {Fmt.Bytes(content, 16)}", R.Dim);
                if (Detect.SniffText(content).isText) d.Text(Encoding.UTF8.GetString(content, 0, Math.Min(content.Length, 2048)), R.Str, "        ", 20);
            }
        }
        if (streams.Count <= 1) d.T("  (no alternate streams)", R.Dim);

        // Ownership & ACL
        d.H("Owner & permissions (DACL)");
        try
        {
            var sec = fi.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
            var owner = sec.GetOwner(typeof(SecurityIdentifier));
            string ownerName = owner?.Value;
            try { ownerName = owner?.Translate(typeof(NTAccount)).Value + $"  ({owner?.Value})"; } catch { }
            d.KV("Owner", ownerName ?? "?", R.Accent);
            d.KV("Inheritance protected", sec.AreAccessRulesProtected ? "yes" : "no", R.Value);
            foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                string who = rule.IdentityReference.Value;
                try { who = rule.IdentityReference.Translate(typeof(NTAccount)).Value; } catch { }
                d.T($"      {(rule.AccessControlType == AccessControlType.Allow ? "ALLOW" : "DENY ")} {Fmt.Trunc(who, 40),-40} {rule.FileSystemRights}{(rule.IsInherited ? "  (inherited)" : "")}", rule.AccessControlType == AccessControlType.Deny ? R.Warn : R.Str);
            }
            var sddl = sec.GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Access);
            d.KV("SDDL", sddl, R.Dim);
        }
        catch (Exception ex) { d.Warn("ACL unavailable: " + ex.Message); }

        // Volume
        try
        {
            string root = Path.GetPathRoot(fi.FullName);
            var vn = new StringBuilder(261); var fsn = new StringBuilder(261);
            if (GetVolumeInformationW(root, vn, 261, out uint serial, out uint maxc, out uint vflags, fsn, 261))
            {
                d.H("Volume");
                d.KV("Root", root, R.Str);
                d.KV("Label", vn.ToString(), R.Str);
                d.KV("File system", fsn.ToString(), R.Value);
                d.KV("Serial", serial.ToString("X8").Insert(4, "-"), R.Hex);
                try { d.KV("Drive type", new DriveInfo(root).DriveType, R.Value); } catch { }
            }
        }
        catch { }

        // file name heuristics
        string nm = fi.Name;
        if (nm.IndexOfAny(new[] { '\u202E', '\u202D', '\u2066', '\u2067' }) >= 0) ctx.Bad("File name", "File name contains a right-to-left override character (disguised extension): " + Fmt.Escape(nm));
        var dbl = System.Text.RegularExpressions.Regex.Match(nm, @"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|zip|rar)(\s|_|-)*\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|hta|lnk|msi|ps1|wsf|cpl|jar|iso|img)$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (dbl.Success) ctx.Bad("File name", $"Double extension '{dbl.Value}' – the real type is the last extension");
        if (System.Text.RegularExpressions.Regex.IsMatch(nm, @"\s{5,}\.\w+$")) ctx.Warn("File name", "Many spaces before the extension (hides the real extension in Explorer)");
        if (nm.Length != nm.Trim().Length) ctx.Warn("File name", "File name has leading/trailing whitespace");
        return d;
    }
}
