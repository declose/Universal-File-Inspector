using System.Security.Cryptography;
using System.Text;
using Ufi.Core;

namespace Ufi.Parsers;

public static class PeParser
{
    sealed class Sec
    {
        public string Name; public uint VSize, VA, RawSize, RawPtr, Chars;
    }

    static readonly Dictionary<ushort, string> Machines = new()
    {
        [0x0] = "Unknown", [0x14c] = "Intel 386 (x86)", [0x8664] = "AMD64 (x64)", [0xAA64] = "ARM64", [0x1c0] = "ARM", [0x1c4] = "ARM Thumb-2 (ARMNT)",
        [0x200] = "Intel Itanium (IA-64)", [0xEBC] = "EFI byte code", [0x5064] = "RISC-V 64", [0x5032] = "RISC-V 32", [0x166] = "MIPS R4000",
        [0x1f0] = "PowerPC", [0x1f1] = "PowerPC FP", [0xA641] = "ARM64EC", [0xA64E] = "ARM64X", [0x6264] = "LoongArch 64", [0x1a2] = "Hitachi SH3", [0x1c2] = "ARM Thumb",
    };

    static readonly (ulong, string)[] CoffFlags =
    {
        (0x1, "RELOCS_STRIPPED"), (0x2, "EXECUTABLE_IMAGE"), (0x4, "LINE_NUMS_STRIPPED"), (0x8, "LOCAL_SYMS_STRIPPED"), (0x10, "AGGRESSIVE_WS_TRIM"),
        (0x20, "LARGE_ADDRESS_AWARE"), (0x80, "BYTES_REVERSED_LO"), (0x100, "32BIT_MACHINE"), (0x200, "DEBUG_STRIPPED"), (0x400, "REMOVABLE_RUN_FROM_SWAP"),
        (0x800, "NET_RUN_FROM_SWAP"), (0x1000, "SYSTEM"), (0x2000, "DLL"), (0x4000, "UP_SYSTEM_ONLY"), (0x8000, "BYTES_REVERSED_HI"),
    };

    static readonly (ulong, string)[] DllFlags =
    {
        (0x20, "HIGH_ENTROPY_VA"), (0x40, "DYNAMIC_BASE (ASLR)"), (0x80, "FORCE_INTEGRITY"), (0x100, "NX_COMPAT (DEP)"), (0x200, "NO_ISOLATION"),
        (0x400, "NO_SEH"), (0x800, "NO_BIND"), (0x1000, "APPCONTAINER"), (0x2000, "WDM_DRIVER"), (0x4000, "GUARD_CF"), (0x8000, "TERMINAL_SERVER_AWARE"),
    };

    static readonly (ulong, string)[] SecFlags =
    {
        (0x8, "NO_PAD"), (0x20, "CODE"), (0x40, "INITIALIZED_DATA"), (0x80, "UNINITIALIZED_DATA"), (0x200, "LNK_INFO"), (0x800, "LNK_REMOVE"),
        (0x1000, "LNK_COMDAT"), (0x8000, "GPREL"), (0x01000000, "LNK_NRELOC_OVFL"), (0x02000000, "DISCARDABLE"), (0x04000000, "NOT_CACHED"),
        (0x08000000, "NOT_PAGED"), (0x10000000, "SHARED"), (0x20000000, "EXECUTE"), (0x40000000, "READ"), (0x80000000, "WRITE"),
    };

    static readonly Dictionary<ushort, string> Subsystems = new()
    {
        [0] = "UNKNOWN", [1] = "NATIVE (driver / native)", [2] = "WINDOWS_GUI", [3] = "WINDOWS_CUI (console)", [5] = "OS2_CUI", [7] = "POSIX_CUI",
        [8] = "NATIVE_WINDOWS", [9] = "WINDOWS_CE_GUI", [10] = "EFI_APPLICATION", [11] = "EFI_BOOT_SERVICE_DRIVER", [12] = "EFI_RUNTIME_DRIVER",
        [13] = "EFI_ROM", [14] = "XBOX", [16] = "WINDOWS_BOOT_APPLICATION",
    };

    static readonly string[] DirNames =
    {
        "Export", "Import", "Resource", "Exception", "Security (certificate)", "Base relocation", "Debug", "Architecture",
        "Global pointer", "TLS", "Load config", "Bound import", "IAT", "Delay import", "CLR runtime (.NET)", "Reserved",
    };

    static readonly Dictionary<uint, string> ResTypes = new()
    {
        [1] = "CURSOR", [2] = "BITMAP", [3] = "ICON", [4] = "MENU", [5] = "DIALOG", [6] = "STRING", [7] = "FONTDIR", [8] = "FONT", [9] = "ACCELERATOR",
        [10] = "RCDATA", [11] = "MESSAGETABLE", [12] = "GROUP_CURSOR", [14] = "GROUP_ICON", [16] = "VERSION", [17] = "DLGINCLUDE", [19] = "PLUGPLAY",
        [20] = "VXD", [21] = "ANICURSOR", [22] = "ANIICON", [23] = "HTML", [24] = "MANIFEST",
    };

    static readonly Dictionary<uint, string> DebugTypes = new()
    {
        [0] = "UNKNOWN", [1] = "COFF", [2] = "CODEVIEW", [3] = "FPO", [4] = "MISC", [5] = "EXCEPTION", [6] = "FIXUP", [7] = "OMAP_TO_SRC", [8] = "OMAP_FROM_SRC",
        [9] = "BORLAND", [10] = "RESERVED10", [11] = "CLSID", [12] = "VC_FEATURE", [13] = "POGO", [14] = "ILTCG", [15] = "MPX", [16] = "REPRO",
        [17] = "EMBEDDED_PORTABLE_PDB", [19] = "PDBCHECKSUM", [20] = "EX_DLLCHARACTERISTICS",
    };

    static readonly string[] PackerSections = { "UPX0", "UPX1", "UPX2", "UPX!", ".aspack", ".adata", ".ASPack", ".vmp0", ".vmp1", ".vmp2", ".themida", ".winlice", ".MPRESS1", ".MPRESS2", ".petite", ".nsp0", ".nsp1", ".nsp2", "pebundle", "PEBundle", ".perplex", ".enigma1", ".enigma2", ".spack", ".packed", ".RLPack", ".yP", ".y0da", "PELOCKnt", ".boom", ".ccg", "kkrunchy", ".Upack", ".ByDwing", "ExeS", ".MaskPE", "MEW" };

    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        ctx.IsPE = true;
        // ---------------- DOS header
        d.H("DOS header (IMAGE_DOS_HEADER)");
        string[] dn = { "e_magic", "e_cblp  (bytes on last page)", "e_cp    (pages in file)", "e_crlc  (relocations)", "e_cparhdr (header paragraphs)", "e_minalloc", "e_maxalloc", "e_ss", "e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc", "e_ovno" };
        for (int i = 0; i < dn.Length; i++) d.KV(dn[i], Fmt.Hx(s.U16(i * 2), 4), R.Num, i * 2);
        d.KV("e_oemid / e_oeminfo", $"{Fmt.Hx(s.U16(0x24), 4)} / {Fmt.Hx(s.U16(0x26), 4)}", R.Num, 0x24);
        uint lfanew = s.U32(0x3C);
        d.KV("e_lfanew (PE header offset)", Fmt.HxD(lfanew), R.Num, 0x3C);

        // DOS stub text
        var stub = s.Bytes(0x40, Math.Min(lfanew, 0x400) - 0x40);
        int msg = stub.AsSpan().IndexOf("This program"u8);
        if (msg >= 0)
        {
            int end = Array.IndexOf(stub, (byte)'$', msg);
            string text = Encoding.ASCII.GetString(stub, msg, (end < 0 ? stub.Length : end) - msg).Trim();
            d.KV("DOS stub message", text, R.Str, 0x40 + msg);
        }
        else d.KV("DOS stub message", "(none – non-standard stub)", R.Warn);

        ParseRich(s, d, lfanew);

        // ---------------- COFF
        long coff = lfanew + 4;
        d.H("PE signature & COFF file header");
        d.KV("Signature", "PE\\0\\0 (" + Fmt.Hx(s.U32(lfanew), 8) + ")", R.Good, lfanew);
        ushort machine = s.U16(coff);
        ushort nsec = s.U16(coff + 2);
        uint tds = s.U32(coff + 4);
        ushort optSize = s.U16(coff + 16);
        ushort chars = s.U16(coff + 18);
        d.KV("Machine", $"{Fmt.Hx(machine, 4)}  {Fmt.Lookup(Machines, machine)}", R.Value, coff);
        d.KV("NumberOfSections", nsec, R.Num, coff + 2);
        d.KV("TimeDateStamp", $"{Fmt.Hx(tds, 8)}  {Fmt.Unix(tds)}", R.Value, coff + 4);
        d.KV("PointerToSymbolTable", Fmt.Hx(s.U32(coff + 8), 8), R.Num, coff + 8);
        d.KV("NumberOfSymbols", s.U32(coff + 12), R.Num, coff + 12);
        d.KV("SizeOfOptionalHeader", optSize, R.Num, coff + 16);
        d.KV("Characteristics", $"{Fmt.Hx(chars, 4)}  {Fmt.Flags(chars, CoffFlags)}", R.Value, coff + 18);
        bool isDll = (chars & 0x2000) != 0;


        // ---------------- Optional header
        long opt = coff + 20;
        ushort magic = s.U16(opt);
        bool pe64 = magic == 0x20B;
        d.H(pe64 ? "Optional header (PE32+ / 64-bit)" : magic == 0x10B ? "Optional header (PE32 / 32-bit)" : "Optional header (unknown magic)");
        d.KV("Magic", $"{Fmt.Hx(magic, 4)}  {(pe64 ? "PE32+" : magic == 0x10B ? "PE32" : magic == 0x107 ? "ROM image" : "INVALID")}", R.Value, opt);
        d.KV("Linker version", $"{s.U8(opt + 2)}.{s.U8(opt + 3)}", R.Value, opt + 2);
        d.KV("SizeOfCode", Fmt.HxD(s.U32(opt + 4)), R.Num, opt + 4);
        d.KV("SizeOfInitializedData", Fmt.HxD(s.U32(opt + 8)), R.Num, opt + 8);
        d.KV("SizeOfUninitializedData", Fmt.HxD(s.U32(opt + 12)), R.Num, opt + 12);
        uint ep = s.U32(opt + 16);
        d.KV("AddressOfEntryPoint (RVA)", Fmt.Hx(ep, 8), R.Num, opt + 16);
        d.KV("BaseOfCode", Fmt.Hx(s.U32(opt + 20), 8), R.Num, opt + 20);
        ulong imageBase;
        if (!pe64) { d.KV("BaseOfData", Fmt.Hx(s.U32(opt + 24), 8), R.Num, opt + 24); imageBase = s.U32(opt + 28); }
        else imageBase = s.U64(opt + 24);
        d.KV("ImageBase", Fmt.Hx(imageBase), R.Num, opt + (pe64 ? 24 : 28));
        d.KV("SectionAlignment", Fmt.Hx(s.U32(opt + 32)), R.Num, opt + 32);
        d.KV("FileAlignment", Fmt.Hx(s.U32(opt + 36)), R.Num, opt + 36);
        d.KV("OperatingSystemVersion", $"{s.U16(opt + 40)}.{s.U16(opt + 42)}", R.Value, opt + 40);
        d.KV("ImageVersion", $"{s.U16(opt + 44)}.{s.U16(opt + 46)}", R.Value, opt + 44);
        d.KV("SubsystemVersion", $"{s.U16(opt + 48)}.{s.U16(opt + 50)}", R.Value, opt + 48);
        d.KV("Win32VersionValue", s.U32(opt + 52), R.Num, opt + 52);
        d.KV("SizeOfImage", Fmt.HxD(s.U32(opt + 56)), R.Num, opt + 56);
        uint sizeOfHeaders = s.U32(opt + 60);
        d.KV("SizeOfHeaders", Fmt.HxD(sizeOfHeaders), R.Num, opt + 60);
        uint storedSum = s.U32(opt + 64);
        ushort subsys = s.U16(opt + 68);
        ushort dllc = s.U16(opt + 70);
        d.KV("Subsystem", $"{subsys}  {Fmt.Lookup(Subsystems, subsys)}", R.Value, opt + 68);
        d.KV("DllCharacteristics", $"{Fmt.Hx(dllc, 4)}  {Fmt.Flags(dllc, DllFlags)}", R.Value, opt + 70);
        long p = opt + 72;
        string[] stackNames = { "SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve", "SizeOfHeapCommit" };
        foreach (var n in stackNames) { ulong v = pe64 ? s.U64(p) : s.U32(p); d.KV(n, Fmt.Hx(v), R.Num, p); p += pe64 ? 8 : 4; }
        d.KV("LoaderFlags", Fmt.Hx(s.U32(p)), R.Num, p); p += 4;
        uint nrva = s.U32(p);
        d.KV("NumberOfRvaAndSizes", nrva, R.Num, p); p += 4;

        // checksum
        string sumText = Fmt.Hx(storedSum, 8);
        if (s.Length <= 512L << 20)
        {
            uint calc = PeChecksum(s, opt + 64);
            sumText += storedSum == 0 ? $"  (not set; computed {Fmt.Hx(calc, 8)})" : storedSum == calc ? "  ✓ matches computed" : $"  ✗ MISMATCH (computed {Fmt.Hx(calc, 8)})";
            if (storedSum != 0 && storedSum != calc) ctx.Warn("PE", "PE checksum does not match (file modified after linking, or patched)");
        }
        d.KV("CheckSum", sumText.Replace("✓", "OK").Replace("✗", "!!"), storedSum != 0 && !sumText.Contains("matches") ? R.Warn : R.Value, opt + 64);

        if ((dllc & 0x40) == 0) ctx.Info("PE", "ASLR (DYNAMIC_BASE) not enabled");
        if ((dllc & 0x100) == 0) ctx.Info("PE", "DEP (NX_COMPAT) not enabled");

        // ---------------- Data directories
        d.H("Data directories");
        d.Th(new C("#", 3, R.Dim, true), new C("Directory", 24), new C("RVA", 12), new C("Size", 12), new C("File offset", 12));
        var dirs = new (uint Rva, uint Size)[16];
        long dirTable = p;
        var sections = new List<Sec>();
        long secTable = opt + optSize;
        for (int i = 0; i < nsec && i < 96; i++)
        {
            long so = secTable + i * 40L;
            sections.Add(new Sec
            {
                Name = s.Fixed(so, 8), VSize = s.U32(so + 8), VA = s.U32(so + 12), RawSize = s.U32(so + 16), RawPtr = s.U32(so + 20), Chars = s.U32(so + 36)
            });
        }
        long Rva(uint rva)
        {
            if (rva < sizeOfHeaders) return rva;
            foreach (var sc in sections)
            {
                uint span = Math.Max(sc.VSize, sc.RawSize);
                if (rva >= sc.VA && rva < sc.VA + span)
                {
                    long delta = rva - sc.VA;
                    if (delta >= sc.RawSize) return -1;
                    return sc.RawPtr + delta;
                }
            }
            return -1;
        }
        for (int i = 0; i < Math.Min(16, (int)nrva); i++)
        {
            long e = dirTable + i * 8L;
            dirs[i] = (s.U32(e), s.U32(e + 4));
            if (dirs[i].Rva == 0 && dirs[i].Size == 0) continue;
            long fo = i == 4 ? dirs[i].Rva : Rva(dirs[i].Rva);
            d.Tr(fo >= 0 ? fo : e, new C(i.ToString(), 3, R.Dim, true), new C(DirNames[i], 24, R.Key), new C(Fmt.Hx(dirs[i].Rva, 8), 12, R.Num),
                new C(Fmt.Hx(dirs[i].Size), 12, R.Num), new C(fo >= 0 ? Fmt.Hx(fo, 8) : "(unmapped)", 12, fo >= 0 ? R.Offset : R.Warn));
        }

        // ---------------- Sections
        d.H($"Section table ({nsec} sections)");
        d.Th(new C("Name", 9), new C("VirtAddr", 10), new C("VirtSize", 10), new C("RawPtr", 10), new C("RawSize", 10), new C("Entropy", 8), new C("RWX", 4), new C("MD5", 32));
        long lastEnd = sizeOfHeaders;
        Sec epSec = null;
        foreach (var sc in sections)
        {
            double ent = sc.RawSize > 0 ? StreamStats.EntropyOf(s, sc.RawPtr, sc.RawSize) : 0;
            string md5 = sc.RawSize > 0 && sc.RawSize < 64 << 20 ? Md5(s, sc.RawPtr, sc.RawSize) : "";
            string rwx = ((sc.Chars & 0x40000000) != 0 ? "R" : "-") + ((sc.Chars & 0x80000000) != 0 ? "W" : "-") + ((sc.Chars & 0x20000000) != 0 ? "X" : "-");
            d.Tr(sc.RawPtr, new C(sc.Name, 9, R.Str), new C(Fmt.Hx(sc.VA, 8), 10, R.Num), new C(Fmt.Hx(sc.VSize, 8), 10, R.Num),
                new C(Fmt.Hx(sc.RawPtr, 8), 10, R.Offset), new C(Fmt.Hx(sc.RawSize, 8), 10, R.Num), new C(ent.ToString("0.000"), 8, ent > 7.2 ? R.Warn : R.Value),
                new C(rwx, 4, rwx == "RWX" ? R.Bad : R.Value), new C(md5, 32, R.Dim));
            d.T($"             flags: {Fmt.Hx(sc.Chars, 8)} {Fmt.Flags(sc.Chars, SecFlags)}", R.Dim, sc.RawPtr);
            if (sc.RawSize > 0) lastEnd = Math.Max(lastEnd, (long)sc.RawPtr + sc.RawSize);
            ctx.Regions.Add(("section " + sc.Name, sc.RawPtr, sc.RawSize));
            if (rwx == "RWX") ctx.Warn("PE", $"Section '{sc.Name}' is writable AND executable (common in packers / shellcode loaders)", sc.RawPtr);
            if (ent > 7.2 && sc.RawSize > 1024) ctx.Warn("PE", $"Section '{sc.Name}' has high entropy {ent:0.00} (packed or encrypted content)", sc.RawPtr);
            if (sc.RawSize == 0 && sc.VSize > 0x10000 && (sc.Chars & 0x20000000) != 0) ctx.Warn("PE", $"Executable section '{sc.Name}' has no raw data but {Fmt.Human(sc.VSize)} virtual size (unpacking stub)");
            if (PackerSections.Any(x => string.Equals(x, sc.Name, StringComparison.OrdinalIgnoreCase))) ctx.Warn("PE", $"Section name '{sc.Name}' indicates a known packer/protector");
            if (ep >= sc.VA && ep < sc.VA + Math.Max(sc.VSize, sc.RawSize)) epSec = sc;
        }
        long epOff = Rva(ep);
        if (ep != 0)
        {
            d.KV("Entry point", $"RVA {Fmt.Hx(ep, 8)} → file offset {(epOff >= 0 ? Fmt.Hx(epOff, 8) : "unmapped")} in section '{epSec?.Name ?? "(none)"}'", R.Accent, epOff);
            if (epSec == null) ctx.Warn("PE", "Entry point is outside all sections");
            else if ((epSec.Chars & 0x20000000) == 0) ctx.Warn("PE", $"Entry point section '{epSec.Name}' is not marked executable");
            else if (epSec != sections.FirstOrDefault(x => (x.Chars & 0x20000000) != 0) && sections.Count > 1) ctx.Info("PE", $"Entry point is in section '{epSec.Name}' (not the first code section)");
            if (epOff >= 0)
            {
                var epBytes = s.Bytes(epOff, 32);
                d.KV("Entry point bytes", Fmt.Bytes(epBytes, 32), R.Hex, epOff);
            }
        }

        // ---------------- Imports
        var impList = new List<string>();
        if (dirs[1].Rva != 0) ParseImports(s, d, ctx, Rva, dirs[1].Rva, pe64, impList, imageBase);
        if (dirs[13].Rva != 0) ParseDelayImports(s, d, Rva, dirs[13].Rva, pe64, imageBase);
        if (impList.Count > 0)
        {
            ctx.ImpHash = Convert.ToHexString(MD5.HashData(Encoding.ASCII.GetBytes(string.Join(",", impList)))).ToLowerInvariant();
        }
        else if (!isDll && dirs[14].Rva == 0) ctx.Warn("PE", "Executable has no import table (typical for packed or shellcode-like binaries)");

        if (dirs[0].Rva != 0) ParseExports(s, d, Rva, dirs[0].Rva, dirs[0].Size);
        if (dirs[2].Rva != 0) ParseResources(s, d, ctx, Rva, dirs[2].Rva);
        bool repro = dirs[6].Rva != 0 && ParseDebug(s, d, ctx, Rva, dirs[6].Rva, dirs[6].Size);
        var tdsDate = DateTimeOffset.FromUnixTimeSeconds(tds).UtcDateTime;
        if (tds != 0 && (tdsDate > DateTime.UtcNow.AddDays(2) || tdsDate.Year < 1995))
        {
            if (repro) ctx.Info("PE", "Reproducible (deterministic) build – the COFF TimeDateStamp is a content hash, not a date");
            else ctx.Warn("PE", $"Compile timestamp looks forged ({tdsDate:yyyy-MM-dd}) – timestomped or unusual toolchain");
        }
        else if (tds != 0) ctx.Info("PE", $"Compiled (linker timestamp) {tdsDate:yyyy-MM-dd HH:mm} UTC");
        if (dirs[9].Rva != 0) ParseTls(s, d, ctx, Rva, dirs[9].Rva, pe64, imageBase);
        if (dirs[10].Rva != 0) ParseLoadConfig(s, d, Rva, dirs[10].Rva, pe64);
        if (dirs[5].Rva != 0) ParseRelocs(s, d, Rva, dirs[5].Rva, dirs[5].Size);
        if (dirs[14].Rva != 0) ParseClr(s, d, ctx, Rva, dirs[14].Rva);

        // ---------------- Certificate / overlay
        long certEnd = 0;
        if (dirs[4].Rva != 0 && dirs[4].Size != 0)
        {
            ctx.CertOffset = dirs[4].Rva; ctx.CertSize = dirs[4].Size;
            certEnd = dirs[4].Rva + (long)dirs[4].Size;
            d.H("Security directory (Authenticode)");
            d.KV("File offset", Fmt.Hx(dirs[4].Rva, 8), R.Offset, dirs[4].Rva);
            d.KV("Size", Fmt.Size(dirs[4].Size), R.Num);
            if (s.Has(dirs[4].Rva, 8))
            {
                d.KV("WIN_CERTIFICATE.dwLength", s.U32(dirs[4].Rva), R.Num, dirs[4].Rva);
                d.KV("wRevision", Fmt.Hx(s.U16(dirs[4].Rva + 4), 4), R.Num);
                ushort ct = s.U16(dirs[4].Rva + 6);
                d.KV("wCertificateType", $"{Fmt.Hx(ct, 4)} {(ct == 2 ? "PKCS_SIGNED_DATA" : ct == 1 ? "X509" : "other")}", R.Value);
            }
            d.Info("See the SIGNATURE section for signer, certificates and trust verdict.");
        }
        long overlay = lastEnd;
        if (certEnd > 0 && ctx.CertOffset >= lastEnd && ctx.CertOffset <= lastEnd + 8) overlay = certEnd;
        if (overlay < s.Length)
        {
            long size = s.Length - overlay;
            d.H("Overlay (data appended after the image)");
            d.KV("Offset", Fmt.Hx(overlay, 8), R.Offset, overlay);
            d.KV("Size", Fmt.Size(size), R.Num);
            double oe = StreamStats.EntropyOf(s, overlay, size);
            d.KV("Entropy", oe.ToString("0.000") + "  " + StreamStats.Verdict(oe), R.Value);
            var head = s.Bytes(overlay, 4096);
            string q = Detect.Quick(head);
            d.KV("First bytes", Fmt.Bytes(head, 24), R.Hex, overlay);
            d.KV("Looks like", q ?? "(unrecognised)", q != null ? R.Accent : R.Dim);
            ctx.Regions.Add(("overlay", overlay, size));
            if (size > 1024) ctx.Warn("PE", $"Overlay of {Fmt.Human(size)} after the PE image{(q != null ? " – contains " + q : "")} (installers, droppers, SFX archives)", overlay);
        }
        else if (certEnd > 0 && certEnd < s.Length) { }

        ctx.IsDotNet = dirs[14].Rva != 0;
        var kind = isDll ? "DLL (dynamic-link library)" : subsys == 1 ? "Native / kernel driver" : subsys is 10 or 11 or 12 or 13 ? "EFI image" : subsys == 3 ? "Console executable" : "GUI executable";
        var rt = ctx.Refined ?? new FileType();
        rt.Name = $"PE{(pe64 ? "32+" : "32")} {kind}, {Fmt.Lookup(Machines, machine)}{(ctx.IsDotNet ? ", .NET assembly" : "")}";
        if (isDll) rt.Exts = new[] { "dll", "ocx", "cpl", "ax", "drv", "mui", "tlb", "node", "winmd", "sys", "exe", "efi" };
        else if (subsys == 1) rt.Exts = new[] { "sys", "exe", "dll" };
        ctx.Refined = rt;
    }

    static string Md5(ByteSource s, long off, long len)
    {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
        var buf = new byte[1 << 20];
        long done = 0;
        len = Math.Min(len, s.Length - off);
        while (done < len)
        {
            int n = s.ReadAt(off + done, buf.AsSpan(0, (int)Math.Min(buf.Length, len - done)));
            if (n <= 0) break;
            h.AppendData(buf, 0, n); done += n;
        }
        return Convert.ToHexString(h.GetHashAndReset()).ToLowerInvariant();
    }

    static uint PeChecksum(ByteSource s, long sumOff)
    {
        ulong sum = 0;
        var buf = new byte[1 << 20];
        long off = 0;
        while (off < s.Length)
        {
            int n = s.ReadAt(off, buf);
            if (n <= 0) break;
            int i = 0;
            for (; i + 1 < n; i += 2)
            {
                long o = off + i;
                if (o == sumOff || o == sumOff + 2) continue;
                sum += (uint)(buf[i] | buf[i + 1] << 8);
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            if (i < n) { sum += buf[i]; sum = (sum & 0xFFFF) + (sum >> 16); }
            off += n;
        }
        sum = (sum & 0xFFFF) + (sum >> 16);
        return (uint)(sum + (ulong)s.Length);
    }

    static void ParseRich(ByteSource s, Doc d, uint lfanew)
    {
        long end = Math.Min(lfanew, 0x1000);
        for (long p = 0x80; p + 8 <= end; p += 4)
        {
            if (s.U32(p) != 0x68636952) continue; // "Rich"
            uint key = s.U32(p + 4);
            long dans = -1;
            for (long q = p - 4; q >= 0x40; q -= 4) if ((s.U32(q) ^ key) == 0x536E6144) { dans = q; break; }
            if (dans < 0) return;
            d.H("Rich header (MSVC toolchain fingerprint)");
            d.KV("Location", $"{Fmt.Hx(dans)} – {Fmt.Hx(p + 8)}", R.Offset, dans);
            d.KV("XOR key / checksum", Fmt.Hx(key, 8), R.Num, p + 4);
            d.Th(new C("ProdID", 8, R.Dim, true), new C("Build", 8, R.Dim, true), new C("Count", 8, R.Dim, true), new C("Meaning", 40));
            for (long q = dans + 16; q + 8 <= p; q += 8)
            {
                uint id = s.U32(q) ^ key, cnt = s.U32(q + 4) ^ key;
                ushort prod = (ushort)(id >> 16), build = (ushort)id;
                d.Tr(q, new C(prod.ToString(), 8, R.Num, true), new C(build.ToString(), 8, R.Num, true), new C(cnt.ToString(), 8, R.Num, true), new C(RichProd(prod), 40, R.Dim));
            }
            return;
        }
    }

    static string RichProd(ushort p) => p switch
    {
        0 => "Unmarked objects / import count",
        1 => "Imported functions (old)",
        _ when p >= 0x0083 && p <= 0x0090 => "VS2008 (MSVC 15) tool",
        _ when p >= 0x0091 && p <= 0x009E => "VS2010 (MSVC 16) tool",
        _ when p >= 0x00A5 && p <= 0x00B4 => "VS2012 (MSVC 17) tool",
        _ when p >= 0x00B5 && p <= 0x00C8 => "VS2013 (MSVC 18) tool",
        _ when p >= 0x00FF && p <= 0x010E => "VS2015+ (MSVC 19.x) tool",
        _ => p switch { 0x5D => "Utc1500 C", 0x5E => "Utc1500 C++", 0x93 => "Linker 10", 0x9E => "Masm 10", 0x102 => "Linker 14", 0x103 => "Masm 14", 0x104 => "Utc1900 C", 0x105 => "Utc1900 C++", 0x101 => "Import (VS2015+)", 0xFF => "Cvtres 14", _ => "" }
    };

    static void ParseImports(ByteSource s, Doc d, Ctx ctx, Func<uint, long> rva, uint dirRva, bool pe64, List<string> imp, ulong imageBase)
    {
        long off = rva(dirRva);
        if (off < 0) return;
        d.H("Import table");
        int dlls = 0, funcs = 0;
        var lines = new Doc();
        for (int i = 0; i < 2000; i++)
        {
            long e = off + i * 20L;
            if (!s.Has(e, 20)) break;
            uint oft = s.U32(e), nameRva = s.U32(e + 12), ft = s.U32(e + 16);
            if (oft == 0 && nameRva == 0 && ft == 0) break;
            long no = rva(nameRva);
            string dll = no >= 0 ? s.Ascii(no, 256) : "(bad name RVA)";
            dlls++;
            uint tr = oft != 0 ? oft : ft;
            long to = rva(tr);
            var names = new List<(string, long)>();
            if (to >= 0)
            {
                int step = pe64 ? 8 : 4;
                for (int k = 0; k < 20000; k++)
                {
                    long te = to + k * (long)step;
                    if (!s.Has(te, step)) break;
                    ulong v = pe64 ? s.U64(te) : s.U32(te);
                    if (v == 0) break;
                    bool ord = pe64 ? (v & 0x8000000000000000) != 0 : (v & 0x80000000) != 0;
                    string fn;
                    long fo = te;
                    if (ord) fn = "#" + (v & 0xFFFF);
                    else
                    {
                        long ho = rva((uint)(v & 0x7FFFFFFF));
                        fn = ho >= 0 ? s.Ascii(ho + 2, 256) : "(bad RVA)";
                        if (ho >= 0) fo = ho;
                    }
                    names.Add((fn, fo));
                    string dl = dll.ToLowerInvariant();
                    foreach (var ext in new[] { ".dll", ".sys", ".ocx" }) if (dl.EndsWith(ext)) { dl = dl[..^4]; break; }
                    imp.Add(dl + "." + (ord ? "ord" + (v & 0xFFFF) : fn.ToLowerInvariant()));
                    funcs++;
                }
            }
            lines.Sub($"{dll}   ({names.Count} functions)", no);
            foreach (var (fn, fo) in names) lines.T("      " + fn, fn.StartsWith("#") ? R.Num : R.Str, fo);
        }
        d.KV("Imported DLLs", dlls, R.Num);
        d.KV("Imported functions", funcs, R.Num);
        d.Lines.AddRange(lines.Lines);
    }

    static void ParseDelayImports(ByteSource s, Doc d, Func<uint, long> rva, uint dirRva, bool pe64, ulong imageBase)
    {
        long off = rva(dirRva);
        if (off < 0) return;
        d.H("Delay-load import table");
        for (int i = 0; i < 1000; i++)
        {
            long e = off + i * 32L;
            if (!s.Has(e, 32)) break;
            uint attrs = s.U32(e), nameRva = s.U32(e + 4), intRva = s.U32(e + 16);
            if (nameRva == 0) break;
            uint Fix(uint v) => (attrs & 1) != 0 ? v : (uint)(v - imageBase);
            long no = rva(Fix(nameRva));
            string dll = no >= 0 ? s.Ascii(no, 256) : "(bad name)";
            d.Sub(dll + " (delay-loaded)", no);
            long to = rva(Fix(intRva));
            if (to < 0) continue;
            int step = pe64 ? 8 : 4;
            for (int k = 0; k < 10000; k++)
            {
                long te = to + k * (long)step;
                if (!s.Has(te, step)) break;
                ulong v = pe64 ? s.U64(te) : s.U32(te);
                if (v == 0) break;
                bool ord = pe64 ? (v & 0x8000000000000000) != 0 : (v & 0x80000000) != 0;
                if (ord) { d.T("      #" + (v & 0xFFFF), R.Num, te); continue; }
                long ho = rva(Fix((uint)v));
                d.T("      " + (ho >= 0 ? s.Ascii(ho + 2, 256) : "(bad RVA)"), R.Str, ho >= 0 ? ho : te);
            }
        }
    }

    static void ParseExports(ByteSource s, Doc d, Func<uint, long> rva, uint dirRva, uint dirSize)
    {
        long off = rva(dirRva);
        if (off < 0 || !s.Has(off, 40)) return;
        d.H("Export table");
        long nameO = rva(s.U32(off + 12));
        uint ordBase = s.U32(off + 16), nFuncs = s.U32(off + 20), nNames = s.U32(off + 24);
        uint aFuncs = s.U32(off + 28), aNames = s.U32(off + 32), aOrds = s.U32(off + 36);
        d.KV("DLL name", nameO >= 0 ? s.Ascii(nameO, 256) : "?", R.Str, nameO);
        d.KV("TimeDateStamp", Fmt.Unix(s.U32(off + 4)), R.Value);
        d.KV("Ordinal base", ordBase, R.Num);
        d.KV("Functions / names", $"{nFuncs} / {nNames}", R.Num);
        var names = new Dictionary<uint, string>();
        long no = rva(aNames), oo = rva(aOrds);
        for (uint i = 0; i < Math.Min(nNames, 50000u) && no >= 0 && oo >= 0; i++)
        {
            if (!s.Has(no + i * 4, 4) || !s.Has(oo + i * 2, 2)) break;
            long n = rva(s.U32(no + i * 4));
            names[s.U16(oo + i * 2)] = n >= 0 ? s.Ascii(n, 512) : "?";
        }
        long fo = rva(aFuncs);
        d.Th(new C("Ordinal", 8, R.Dim, true), new C("RVA", 10), new C("Name / forwarder", 60));
        for (uint i = 0; i < Math.Min(nFuncs, 50000u) && fo >= 0; i++)
        {
            if (!s.Has(fo + i * 4, 4)) break;
            uint f = s.U32(fo + i * 4);
            if (f == 0) continue;
            names.TryGetValue(i, out var nm);
            string extra = "";
            if (f >= dirRva && f < dirRva + dirSize) { long fw = rva(f); extra = " → " + (fw >= 0 ? s.Ascii(fw, 256) : "?"); }
            d.Tr(rva(f), new C((ordBase + i).ToString(), 8, R.Num, true), new C(Fmt.Hx(f, 8), 10, R.Num), new C((nm ?? "(by ordinal only)") + extra, 60, nm != null ? R.Str : R.Dim));
        }
    }

    sealed record Res(string Type, string Name, uint Lang, uint DataRva, uint Size, uint CodePage, uint TypeId);

    static void ParseResources(ByteSource s, Doc d, Ctx ctx, Func<uint, long> rva, uint dirRva)
    {
        long root = rva(dirRva);
        if (root < 0) return;
        var list = new List<Res>();
        int guard = 0;
        string EntryName(uint nameField, bool isType, out uint id)
        {
            id = 0;
            if ((nameField & 0x80000000) != 0)
            {
                long so = root + (nameField & 0x7FFFFFFF);
                return "\"" + s.Utf16(so + 2, Math.Min((int)s.U16(so), 256)) + "\"";
            }
            id = nameField;
            return isType ? Fmt.Lookup(ResTypes, nameField, "#" + nameField) : "#" + nameField;
        }
        void Walk(long dir, int depth, string type, string name, uint typeId)
        {
            if (depth > 3 || ++guard > 20000 || !s.Has(dir, 16)) return;
            int count = s.U16(dir + 12) + s.U16(dir + 14);
            for (int i = 0; i < Math.Min(count, 4096); i++)
            {
                long e = dir + 16 + i * 8L;
                if (!s.Has(e, 8)) return;
                uint nf = s.U32(e), of = s.U32(e + 4);
                string label = EntryName(nf, depth == 0, out uint id);
                if ((of & 0x80000000) != 0)
                {
                    long sub = root + (of & 0x7FFFFFFF);
                    if (depth == 0) Walk(sub, 1, label, null, id);
                    else if (depth == 1) Walk(sub, 2, type, label, typeId);
                    else Walk(sub, depth + 1, type, name, typeId);
                }
                else
                {
                    long de = root + of;
                    if (!s.Has(de, 16)) continue;
                    list.Add(new Res(type ?? label, name ?? label, depth >= 2 ? nf : 0, s.U32(de), s.U32(de + 4), s.U32(de + 8), typeId));
                }
            }
        }
        Walk(root, 0, null, null, 0);
        d.H($"Resources ({list.Count})");
        d.Th(new C("Type", 14), new C("Name", 22), new C("Lang", 6), new C("Offset", 10), new C("Size", 10), new C("Entropy", 7), new C("Content", 30));
        foreach (var r in list)
        {
            long fo = rva(r.DataRva);
            string what = "";
            double ent = 0;
            if (fo >= 0 && r.Size > 0)
            {
                var head = s.Bytes(fo, Math.Min(r.Size, 512));
                what = Detect.Quick(head) ?? "";
                if (what == "" && r.TypeId == 24) what = "XML manifest";
                if (what == "" && Detect.SniffText(head).isText) what = "text";
                ent = StreamStats.EntropyOf(s, fo, r.Size, 8 << 20);
                if (r.TypeId is 10 or 23 or 0 && (what.StartsWith("PE") || what.Contains("ZIP") || what.Contains("7-Zip") || what.Contains("RAR") || what.Contains("Cabinet")))
                    ctx.Warn("PE", $"Resource {r.Type}/{r.Name} embeds a {what} ({Fmt.Human(r.Size)})", fo);
                else if (what.StartsWith("PE")) ctx.Warn("PE", $"Resource {r.Type}/{r.Name} embeds another executable", fo);
                if (ent > 7.5 && r.Size > 16384 && r.TypeId is 10 or 0) ctx.Info("PE", $"Resource {r.Type}/{r.Name} is high-entropy ({ent:0.00}) – encrypted/compressed payload?", fo);
            }
            d.Tr(fo, new C(r.Type, 14, R.Key), new C(r.Name, 22, R.Str), new C(r.Lang.ToString(), 6, R.Num), new C(fo >= 0 ? Fmt.Hx(fo, 8) : "?", 10, R.Offset),
                new C(Fmt.Hx(r.Size), 10, R.Num), new C(ent.ToString("0.00"), 7, ent > 7.3 ? R.Warn : R.Value), new C(what, 30, R.Accent));
        }

        // version info
        var ver = list.FirstOrDefault(r => r.TypeId == 16);
        if (ver != null && rva(ver.DataRva) is long vo && vo >= 0) ParseVersion(s, d, vo, ver.Size);

        // manifest
        var man = list.FirstOrDefault(r => r.TypeId == 24);
        if (man != null && rva(man.DataRva) is long mo && mo >= 0)
        {
            string xml = Encoding.UTF8.GetString(s.Bytes(mo, Math.Min(man.Size, 65536)));
            d.H("Application manifest");
            d.Text(xml, R.Str, "    ", 300);
            var lvl = System.Text.RegularExpressions.Regex.Match(xml, "requestedExecutionLevel[^>]*level\\s*=\\s*[\"']([^\"']+)");
            if (lvl.Success)
            {
                if (lvl.Groups[1].Value == "requireAdministrator") ctx.Warn("PE", "Manifest requests administrator privileges (requireAdministrator)", mo);
                else ctx.Info("PE", "Manifest execution level: " + lvl.Groups[1].Value, mo);
            }
            if (xml.Contains("uiAccess=\"true\"")) ctx.Warn("PE", "Manifest requests uiAccess=true", mo);
        }
    }

    static void ParseVersion(ByteSource s, Doc d, long off, uint size)
    {
        d.H("Version information (VS_VERSIONINFO)");
        long end = off + size;
        long A4(long x) => (x + 3) & ~3L;
        void Block(long p, int depth, string parent)
        {
            if (depth > 4 || !s.Has(p, 6)) return;
            ushort len = s.U16(p), valLen = s.U16(p + 2), type = s.U16(p + 4);
            if (len == 0) return;
            long blockEnd = Math.Min(p + len, end);
            string key = s.Utf16Z(p + 6, 64);
            long q = A4(p + 6 + (key.Length + 1) * 2);
            if (depth == 0)
            {
                if (valLen >= 52 && s.U32(q) == 0xFEEF04BD)
                {
                    string V(long a) => $"{s.U16(a + 2)}.{s.U16(a)}.{s.U16(a + 6)}.{s.U16(a + 4)}";
                    d.KV("FileVersion (binary)", V(q + 8), R.Value, q + 8);
                    d.KV("ProductVersion (binary)", V(q + 16), R.Value, q + 16);
                    uint ff = s.U32(q + 28) & s.U32(q + 24);
                    d.KV("FileFlags", Fmt.Flags(ff, new (ulong, string)[] { (1, "DEBUG"), (2, "PRERELEASE"), (4, "PATCHED"), (8, "PRIVATEBUILD"), (0x10, "INFOINFERRED"), (0x20, "SPECIALBUILD") }), R.Value);
                    uint os = s.U32(q + 32), ft = s.U32(q + 36);
                    d.KV("FileOS", Fmt.Hx(os, 8) + (os == 0x40004 ? "  NT_WINDOWS32" : ""), R.Value);
                    d.KV("FileType", ft switch { 1 => "APP", 2 => "DLL", 3 => "DRV", 4 => "FONT", 5 => "VXD", 7 => "STATIC_LIB", _ => ft.ToString() }, R.Value);
                }
                q = A4(q + valLen);
            }
            else if (depth == 3 && parent != "VarFileInfo")
            {
                string val = valLen > 0 ? s.Utf16Z(q, Math.Min((int)valLen, 2048)) : "";
                d.KV(key, val, R.Str, q);
                return;
            }
            else if (depth == 2 && parent == "VarFileInfo")
            {
                var parts = new List<string>();
                for (int i = 0; i + 4 <= valLen; i += 4) parts.Add($"lang {Fmt.Hx(s.U16(q + i), 4)} codepage {s.U16(q + i + 2)}");
                d.KV(key, string.Join(", ", parts), R.Value, q);
                return;
            }
            else if (depth == 2) d.T($"  [{key}]", R.Dim, p);
            while (q + 6 < blockEnd)
            {
                ushort cl = s.U16(q);
                if (cl == 0) break;
                Block(q, depth + 1, depth == 0 ? s.Utf16Z(q + 6, 32) : depth == 1 ? parent == null ? key : key : key);
                q = A4(q + cl);
            }
        }
        try { Block(off, 0, null); } catch (EndOfDataException) { d.Warn("Version resource truncated"); }
    }

    static bool ParseDebug(ByteSource s, Doc d, Ctx ctx, Func<uint, long> rva, uint dirRva, uint size)
    {
        long off = rva(dirRva);
        bool repro = false;
        if (off < 0) return false;
        d.H("Debug directory");
        for (int i = 0; i < Math.Min(size / 28, 64); i++)
        {
            long e = off + i * 28L;
            if (!s.Has(e, 28)) break;
            uint type = s.U32(e + 12), dsize = s.U32(e + 16), ptr = s.U32(e + 24), ts = s.U32(e + 4);
            d.Sub($"{Fmt.Lookup(DebugTypes, type, type.ToString())}  (size {dsize}, raw {Fmt.Hx(ptr)})", ptr != 0 ? ptr : e);
            if (ts != 0) d.KV("    TimeDateStamp", Fmt.Unix(ts), R.Value, e + 4);
            if (type == 2 && s.Has(ptr, 24))
            {
                if (s.Match(ptr, "RSDS"))
                {
                    d.KV("    CodeView", "RSDS (PDB 7.0)", R.Value, ptr);
                    d.KV("    PDB GUID", Fmt.Guid(s.Bytes(ptr + 4, 16)), R.Value);
                    d.KV("    PDB age", s.U32(ptr + 20), R.Num);
                    string pdb = s.Utf8Z(ptr + 24, 1024);
                    d.KV("    PDB path", pdb, R.Str, ptr + 24);
                    ctx.Info("PE", "Debug PDB path: " + pdb, ptr + 24);
                    if (pdb.Contains("\\Users\\", StringComparison.OrdinalIgnoreCase)) ctx.Info("PE", "PDB path reveals a developer user profile directory");
                }
                else if (s.Match(ptr, "NB10")) d.KV("    PDB path (NB10)", s.Ascii(ptr + 16, 512), R.Str, ptr + 16);
            }
            if (type == 16) { repro = true; d.Info("    REPRO: deterministic build – the COFF timestamp is a hash, not a date"); }
        }
        return repro;
    }

    static void ParseTls(ByteSource s, Doc d, Ctx ctx, Func<uint, long> rva, uint dirRva, bool pe64, ulong imageBase)
    {
        long off = rva(dirRva);
        if (off < 0) return;
        d.H("TLS directory");
        int w = pe64 ? 8 : 4;
        ulong R8(long o) => pe64 ? s.U64(o) : s.U32(o);
        d.KV("StartAddressOfRawData", Fmt.Hx(R8(off)), R.Num, off);
        d.KV("EndAddressOfRawData", Fmt.Hx(R8(off + w)), R.Num);
        d.KV("AddressOfIndex", Fmt.Hx(R8(off + 2 * w)), R.Num);
        ulong cb = R8(off + 3 * w);
        d.KV("AddressOfCallBacks", Fmt.Hx(cb), R.Num);
        if (cb != 0 && cb > imageBase)
        {
            long co = rva((uint)(cb - imageBase));
            int n = 0;
            while (co >= 0 && n < 64 && s.Has(co + n * w, w))
            {
                ulong f = R8(co + n * w);
                if (f == 0) break;
                long fo = f > imageBase ? rva((uint)(f - imageBase)) : -1;
                d.KV($"  TLS callback #{n}", $"VA {Fmt.Hx(f)}  (RVA {Fmt.Hx(f - imageBase)})", R.Warn, fo);
                n++;
            }
            if (n > 0) ctx.Warn("PE", $"{n} TLS callback(s) – code that runs before the entry point (used by some malware / anti-debug)");
        }
    }

    static void ParseLoadConfig(ByteSource s, Doc d, Func<uint, long> rva, uint dirRva, bool pe64)
    {
        long off = rva(dirRva);
        if (off < 0 || !s.Has(off, 4)) return;
        d.H("Load configuration");
        uint size = s.U32(off);
        d.KV("Size", size, R.Num, off);
        d.KV("TimeDateStamp", Fmt.Unix(s.U32(off + 4)), R.Value);
        int w = pe64 ? 8 : 4;
        long cookieOff = off + (pe64 ? 0x58 : 0x3C);
        if (size > (pe64 ? 0x60 : 0x40) && s.Has(cookieOff, w)) d.KV("SecurityCookie", Fmt.Hx(pe64 ? s.U64(cookieOff) : s.U32(cookieOff)), R.Num, cookieOff);
        long seh = off + 0x40;
        if (!pe64 && size >= 0x48) d.KV("SEHandlerCount", s.U32(off + 0x44), R.Num);
        long gf = off + (pe64 ? 0x90 : 0x58);
        if (size >= (pe64 ? 0x94 : 0x5C) && s.Has(gf, 4))
        {
            uint g = s.U32(gf);
            d.KV("GuardFlags", Fmt.Hx(g, 8) + "  " + Fmt.Flags(g, new (ulong, string)[] { (0x100, "CF_INSTRUMENTED"), (0x200, "CFW_INSTRUMENTED"), (0x400, "CF_FUNCTION_TABLE_PRESENT"), (0x800, "SECURITY_COOKIE_UNUSED"), (0x1000, "PROTECT_DELAYLOAD_IAT"), (0x4000, "CF_EXPORT_SUPPRESSION_INFO_PRESENT"), (0x10000, "CF_LONGJUMP_TABLE_PRESENT"), (0x100000, "RETPOLINE_PRESENT"), (0x1000000, "EH_CONTINUATION_TABLE_PRESENT"), (0x2000000, "XFG_ENABLED") }), R.Value, gf);
        }
        _ = seh;
    }

    static void ParseRelocs(ByteSource s, Doc d, Func<uint, long> rva, uint dirRva, uint size)
    {
        long off = rva(dirRva);
        if (off < 0) return;
        int blocks = 0; long entries = 0; long p = off;
        while (p + 8 <= off + size && blocks < 100000 && s.Has(p, 8))
        {
            uint bs = s.U32(p + 4);
            if (bs < 8) break;
            blocks++; entries += (bs - 8) / 2; p += bs;
        }
        d.H("Base relocations");
        d.KV("Blocks / entries", $"{blocks} / {entries:N0}", R.Num, off);
    }

    static void ParseClr(ByteSource s, Doc d, Ctx ctx, Func<uint, long> rva, uint dirRva)
    {
        long off = rva(dirRva);
        if (off < 0 || !s.Has(off, 72)) return;
        d.H(".NET CLR header (managed assembly)");
        d.KV("cb", s.U32(off), R.Num, off);
        d.KV("Runtime version", $"{s.U16(off + 4)}.{s.U16(off + 6)}", R.Value);
        uint mdRva = s.U32(off + 8), mdSize = s.U32(off + 12), flags = s.U32(off + 16);
        d.KV("Metadata RVA / size", $"{Fmt.Hx(mdRva, 8)} / {Fmt.Hx(mdSize)}", R.Num);
        d.KV("Flags", Fmt.Hx(flags, 8) + "  " + Fmt.Flags(flags, new (ulong, string)[] { (1, "ILONLY"), (2, "32BITREQUIRED"), (4, "IL_LIBRARY"), (8, "STRONGNAMESIGNED"), (0x10, "NATIVE_ENTRYPOINT"), (0x10000, "TRACKDEBUGDATA"), (0x20000, "32BITPREFERRED") }), R.Value);
        d.KV("EntryPoint token/RVA", Fmt.Hx(s.U32(off + 20), 8), R.Num);
        d.KV("Managed resources", $"RVA {Fmt.Hx(s.U32(off + 24), 8)} size {Fmt.Hx(s.U32(off + 28))}", R.Num);
        d.KV("Strong name signature", $"RVA {Fmt.Hx(s.U32(off + 32), 8)} size {Fmt.Hx(s.U32(off + 36))}", R.Num);
        long md = rva(mdRva);
        if (md >= 0 && s.Has(md, 20) && s.U32(md) == 0x424A5342)
        {
            uint vlen = s.U32(md + 12);
            string ver = s.Ascii(md + 16, (int)Math.Min(vlen, 255));
            d.KV("Metadata signature", "BSJB", R.Good, md);
            d.KV("Target runtime", ver, R.Str, md + 16);
            long sp = md + 16 + vlen + 2;
            int ns = s.U16(sp); sp += 2;
            d.KV("Metadata streams", ns, R.Num);
            for (int i = 0; i < Math.Min(ns, 16); i++)
            {
                uint so = s.U32(sp), ss = s.U32(sp + 4);
                string name = s.Ascii(sp + 8, 32);
                d.KV("    " + name, $"offset {Fmt.Hx(so)}  size {Fmt.Size(ss)}", R.Value, md + so);
                sp = sp + 8 + ((name.Length + 4) & ~3);
            }
            ctx.Info("PE", ".NET assembly targeting " + ver + " (decompilable IL code)");
        }
    }
}
