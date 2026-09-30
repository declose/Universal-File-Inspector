using Ufi.Core;

namespace Ufi.Parsers;

public static class ElfParser
{
    static readonly Dictionary<ushort, string> Machines = new()
    {
        [0] = "None", [2] = "SPARC", [3] = "Intel 80386", [8] = "MIPS", [20] = "PowerPC", [21] = "PowerPC64", [22] = "IBM S/390", [40] = "ARM (32-bit)",
        [42] = "SuperH", [43] = "SPARC V9", [50] = "IA-64", [62] = "AMD x86-64", [183] = "AArch64", [243] = "RISC-V", [247] = "eBPF", [258] = "LoongArch",
    };
    static readonly Dictionary<byte, string> Abis = new()
    {
        [0] = "System V", [1] = "HP-UX", [2] = "NetBSD", [3] = "Linux (GNU)", [6] = "Solaris", [7] = "AIX", [8] = "IRIX", [9] = "FreeBSD", [12] = "OpenBSD", [97] = "ARM", [255] = "Standalone",
    };
    static readonly Dictionary<uint, string> PTypes = new()
    {
        [0] = "NULL", [1] = "LOAD", [2] = "DYNAMIC", [3] = "INTERP", [4] = "NOTE", [5] = "SHLIB", [6] = "PHDR", [7] = "TLS",
        [0x6474e550] = "GNU_EH_FRAME", [0x6474e551] = "GNU_STACK", [0x6474e552] = "GNU_RELRO", [0x6474e553] = "GNU_PROPERTY",
    };
    static readonly Dictionary<uint, string> STypes = new()
    {
        [0] = "NULL", [1] = "PROGBITS", [2] = "SYMTAB", [3] = "STRTAB", [4] = "RELA", [5] = "HASH", [6] = "DYNAMIC", [7] = "NOTE", [8] = "NOBITS",
        [9] = "REL", [11] = "DYNSYM", [14] = "INIT_ARRAY", [15] = "FINI_ARRAY", [16] = "PREINIT_ARRAY", [17] = "GROUP",
        [0x6ffffff6] = "GNU_HASH", [0x6ffffffd] = "VERDEF", [0x6ffffffe] = "VERNEED", [0x6fffffff] = "VERSYM",
    };

    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        byte cls = s.U8(4), data = s.U8(5);
        bool is64 = cls == 2, be = data == 2;
        d.H("ELF identification");
        d.KV("Class", is64 ? "ELF64" : cls == 1 ? "ELF32" : "invalid", R.Value, 4);
        d.KV("Data encoding", be ? "big-endian" : data == 1 ? "little-endian" : "invalid", R.Value, 5);
        d.KV("Version", s.U8(6), R.Num, 6);
        d.KV("OS/ABI", Fmt.Lookup(Abis, s.U8(7), s.U8(7).ToString()), R.Value, 7);
        d.KV("ABI version", s.U8(8), R.Num, 8);

        ushort type = s.U16(16, be), mach = s.U16(18, be);
        ulong entry, phoff, shoff; uint flags; ushort phent, phnum, shent, shnum, shstr;
        if (is64)
        {
            entry = s.U64(24, be); phoff = s.U64(32, be); shoff = s.U64(40, be); flags = s.U32(48, be);
            phent = s.U16(54, be); phnum = s.U16(56, be); shent = s.U16(58, be); shnum = s.U16(60, be); shstr = s.U16(62, be);
        }
        else
        {
            entry = s.U32(24, be); phoff = s.U32(28, be); shoff = s.U32(32, be); flags = s.U32(36, be);
            phent = s.U16(42, be); phnum = s.U16(44, be); shent = s.U16(46, be); shnum = s.U16(48, be); shstr = s.U16(50, be);
        }
        d.H("ELF header");
        string typeName = type switch { 1 => "REL (relocatable object)", 2 => "EXEC (executable)", 3 => "DYN (shared object / PIE executable)", 4 => "CORE (core dump)", _ => type.ToString() };
        d.KV("Type", typeName, R.Value, 16);
        d.KV("Machine", $"{mach}  {Fmt.Lookup(Machines, mach)}", R.Value, 18);
        d.KV("Entry point", Fmt.Hx(entry), R.Num, 24);
        d.KV("Program headers", $"offset {Fmt.Hx(phoff)}, {phnum} × {phent} bytes", R.Num, (long)phoff);
        d.KV("Section headers", $"offset {Fmt.Hx(shoff)}, {shnum} × {shent} bytes", R.Num, (long)shoff);
        d.KV("Flags", Fmt.Hx(flags, 8), R.Num);
        d.KV("Section name string table", shstr, R.Num);

        var rt = ctx.Refined ?? new FileType();
        rt.Name = $"ELF{(is64 ? "64" : "32")} {typeName}, {Fmt.Lookup(Machines, mach)}";
        ctx.Refined = rt;

        // program headers
        string interp = null;
        var notes = new List<(long off, long size)>();
        if (phnum > 0 && phoff > 0)
        {
            d.H("Program headers (segments)");
            d.Th(new C("Type", 14), new C("Offset", 12), new C("VirtAddr", 18), new C("FileSize", 12), new C("MemSize", 12), new C("Flags", 5));
            for (int i = 0; i < Math.Min((int)phnum, 512); i++)
            {
                long p = (long)phoff + i * (long)phent;
                uint pt, pf; ulong po, pv, pfs, pms;
                if (is64) { pt = s.U32(p, be); pf = s.U32(p + 4, be); po = s.U64(p + 8, be); pv = s.U64(p + 16, be); pfs = s.U64(p + 32, be); pms = s.U64(p + 40, be); }
                else { pt = s.U32(p, be); po = s.U32(p + 4, be); pv = s.U32(p + 8, be); pfs = s.U32(p + 16, be); pms = s.U32(p + 20, be); pf = s.U32(p + 24, be); }
                string fl = ((pf & 4) != 0 ? "R" : "-") + ((pf & 2) != 0 ? "W" : "-") + ((pf & 1) != 0 ? "X" : "-");
                d.Tr((long)po, new C(Fmt.Lookup(PTypes, pt, Fmt.Hx(pt)), 14, R.Key), new C(Fmt.Hx(po), 12, R.Offset), new C(Fmt.Hx(pv), 18, R.Num),
                    new C(Fmt.Hx(pfs), 12, R.Num), new C(Fmt.Hx(pms), 12, R.Num), new C(fl, 5, fl == "RWX" ? R.Bad : R.Value));
                if (pt == 3) interp = s.Ascii((long)po, (int)Math.Min(pfs, 512UL));
                if (pt == 4) notes.Add(((long)po, (long)pfs));
                if (pt == 0x6474e551 && (pf & 1) != 0) ctx.Warn("ELF", "GNU_STACK is executable (no NX protection)");
                if (pt == 1 && fl == "RWX") ctx.Warn("ELF", "Loadable segment is writable and executable");
            }
            if (interp != null) d.KV("Program interpreter", interp, R.Str);
        }

        // sections
        var secs = new List<(string name, uint type, ulong off, ulong size, uint link, ulong entsize, ulong flags)>();
        if (shnum > 0 && shoff > 0 && shoff < (ulong)s.Length)
        {
            for (int i = 0; i < Math.Min((int)shnum, 4096); i++)
            {
                long p = (long)shoff + i * (long)shent;
                if (!s.Has(p, is64 ? 64 : 40)) break;
                uint nm = s.U32(p, be), st = s.U32(p + 4, be);
                if (is64) secs.Add((nm.ToString(), st, s.U64(p + 24, be), s.U64(p + 32, be), s.U32(p + 40, be), s.U64(p + 56, be), s.U64(p + 8, be)));
                else secs.Add((nm.ToString(), st, s.U32(p + 16, be), s.U32(p + 20, be), s.U32(p + 24, be), s.U32(p + 36, be), s.U32(p + 8, be)));
            }
            if (shstr < secs.Count)
            {
                ulong strOff = secs[shstr].off;
                for (int i = 0; i < secs.Count; i++)
                    secs[i] = (s.Ascii((long)strOff + long.Parse(secs[i].name), 128), secs[i].type, secs[i].off, secs[i].size, secs[i].link, secs[i].entsize, secs[i].flags);
            }
            d.H($"Section headers ({secs.Count})");
            d.Th(new C("#", 4, R.Dim, true), new C("Name", 24), new C("Type", 14), new C("Offset", 12), new C("Size", 12), new C("Flags", 6), new C("Entropy", 7));
            for (int i = 0; i < secs.Count; i++)
            {
                var x = secs[i];
                string fl = ((x.flags & 1) != 0 ? "W" : "") + ((x.flags & 2) != 0 ? "A" : "") + ((x.flags & 4) != 0 ? "X" : "");
                double e = x.type != 8 && x.size > 0 ? StreamStats.EntropyOf(s, (long)x.off, (long)x.size, 16 << 20) : 0;
                d.Tr((long)x.off, new C(i.ToString(), 4, R.Dim, true), new C(x.name, 24, R.Str), new C(Fmt.Lookup(STypes, x.type, Fmt.Hx(x.type)), 14, R.Key),
                    new C(Fmt.Hx(x.off), 12, R.Offset), new C(Fmt.Hx(x.size), 12, R.Num), new C(fl, 6), new C(e.ToString("0.00"), 7, e > 7.2 ? R.Warn : R.Value));
            }
            if (secs.Any(x => x.name.StartsWith("UPX", StringComparison.OrdinalIgnoreCase))) ctx.Warn("ELF", "UPX-packed sections present");
            if (!secs.Any(x => x.type == 2)) ctx.Info("ELF", "Binary is stripped (no .symtab)");

            // dynamic: NEEDED libs
            foreach (var dy in secs.Where(x => x.type == 6))
            {
                if (dy.link >= secs.Count) continue;
                ulong strtab = secs[(int)dy.link].off;
                int es = is64 ? 16 : 8;
                d.H("Dynamic section");
                for (long p = (long)dy.off; p + es <= (long)(dy.off + dy.size); p += es)
                {
                    long tag = is64 ? s.I64(p, be) : s.I32(p, be);
                    ulong val = is64 ? s.U64(p + 8, be) : s.U32(p + 4, be);
                    if (tag == 0) break;
                    string label = tag switch { 1 => "NEEDED", 14 => "SONAME", 15 => "RPATH", 29 => "RUNPATH", _ => null };
                    if (label != null) d.KV(label, s.Ascii((long)(strtab + val), 512), R.Str, (long)(strtab + val));
                    if (tag == 30 && (val & 8) != 0) d.KV("FLAGS", "BIND_NOW", R.Value);
                }
            }

            // dynamic symbols
            foreach (var sy in secs.Where(x => x.type == 11 || x.type == 2))
            {
                if (sy.link >= secs.Count || sy.entsize == 0) continue;
                ulong strtab = secs[(int)sy.link].off;
                long count = (long)(sy.size / sy.entsize);
                d.H($"Symbols: {sy.name} ({count:N0})");
                d.Th(new C("Bind", 7), new C("Type", 8), new C("Def", 5), new C("Value", 18), new C("Name", 50));
                for (long i = 1; i < Math.Min(count, 5000); i++)
                {
                    long p = (long)sy.off + i * (long)sy.entsize;
                    uint nm; byte info; ushort shndx; ulong val;
                    if (is64) { nm = s.U32(p, be); info = s.U8(p + 4); shndx = s.U16(p + 6, be); val = s.U64(p + 8, be); }
                    else { nm = s.U32(p, be); val = s.U32(p + 4, be); info = s.U8(p + 12); shndx = s.U16(p + 14, be); }
                    string name = s.Ascii((long)(strtab + nm), 256);
                    if (name.Length == 0) continue;
                    string bind = (info >> 4) switch { 0 => "LOCAL", 1 => "GLOBAL", 2 => "WEAK", _ => (info >> 4).ToString() };
                    string typ = (info & 15) switch { 0 => "NOTYPE", 1 => "OBJECT", 2 => "FUNC", 3 => "SECTION", 4 => "FILE", 6 => "TLS", 10 => "IFUNC", _ => (info & 15).ToString() };
                    d.Tr(-1, new C(bind, 7, R.Key), new C(typ, 8), new C(shndx == 0 ? "UND" : "def", 5, shndx == 0 ? R.Accent : R.Dim), new C(Fmt.Hx(val), 18, R.Num), new C(name, 50, R.Str));
                }
                if (count > 5000) d.T($"  … {count - 5000:N0} more symbols not shown", R.Dim);
            }
        }

        // notes (build id)
        foreach (var (no, ns) in notes)
        {
            long p = no;
            while (p + 12 <= no + ns)
            {
                uint nsz = s.U32(p, be), dsz = s.U32(p + 4, be), nt = s.U32(p + 8, be);
                string owner = s.Ascii(p + 12, (int)Math.Min(nsz, 64));
                long desc = p + 12 + ((nsz + 3) & ~3u);
                if (owner == "GNU" && nt == 3) d.KV("GNU build-id", Fmt.HexStr(s.Bytes(desc, Math.Min(dsz, 64))), R.Value, desc);
                if (owner == "GNU" && nt == 1 && dsz >= 16) d.KV("GNU ABI tag", $"OS {s.U32(desc, be)}  kernel ≥ {s.U32(desc + 4, be)}.{s.U32(desc + 8, be)}.{s.U32(desc + 12, be)}", R.Value, desc);
                p = desc + ((dsz + 3) & ~3u);
                if (nsz > 4096 || dsz > 1 << 20) break;
            }
        }
    }
}

public static class MachOParser
{
    static readonly Dictionary<uint, string> Cpu = new()
    {
        [7] = "x86", [0x01000007] = "x86_64", [12] = "ARM", [0x0100000C] = "ARM64", [0x0200000C] = "ARM64_32", [18] = "PowerPC", [0x01000012] = "PowerPC64",
    };
    static readonly Dictionary<uint, string> FileTypes = new()
    {
        [1] = "OBJECT", [2] = "EXECUTE", [3] = "FVMLIB", [4] = "CORE", [5] = "PRELOAD", [6] = "DYLIB", [7] = "DYLINKER", [8] = "BUNDLE", [9] = "DYLIB_STUB", [10] = "DSYM", [11] = "KEXT_BUNDLE", [12] = "FILESET",
    };
    static readonly Dictionary<uint, string> Cmds = new()
    {
        [0x1] = "SEGMENT", [0x2] = "SYMTAB", [0xB] = "DYSYMTAB", [0xC] = "LOAD_DYLIB", [0xD] = "ID_DYLIB", [0xE] = "LOAD_DYLINKER", [0xF] = "ID_DYLINKER",
        [0x19] = "SEGMENT_64", [0x1B] = "UUID", [0x1D] = "CODE_SIGNATURE", [0x1E] = "SEGMENT_SPLIT_INFO", [0x21] = "ENCRYPTION_INFO", [0x24] = "VERSION_MIN_MACOSX",
        [0x25] = "VERSION_MIN_IPHONEOS", [0x26] = "FUNCTION_STARTS", [0x29] = "DATA_IN_CODE", [0x2A] = "SOURCE_VERSION", [0x2B] = "DYLIB_CODE_SIGN_DRS",
        [0x2C] = "ENCRYPTION_INFO_64", [0x32] = "BUILD_VERSION", [0x80000018] = "LOAD_WEAK_DYLIB", [0x8000001C] = "RPATH", [0x8000001F] = "REEXPORT_DYLIB",
        [0x80000022] = "DYLD_INFO_ONLY", [0x80000028] = "MAIN", [0x80000033] = "DYLD_EXPORTS_TRIE", [0x80000034] = "DYLD_CHAINED_FIXUPS", [0x22] = "DYLD_INFO",
    };

    public static void Parse(ByteSource s, Doc d, Ctx ctx)
    {
        uint m = s.U32(0, true);
        if (m == 0xCAFEBABE)
        {
            uint n = s.U32(4, true);
            d.H($"Universal (fat) binary – {n} architectures");
            for (int i = 0; i < Math.Min(n, 16u); i++)
            {
                long a = 8 + i * 20;
                uint cpu = s.U32(a, true), off = s.U32(a + 8, true), size = s.U32(a + 12, true);
                d.KV($"Slice {i}", $"{Fmt.Lookup(Cpu, cpu, Fmt.Hx(cpu))}  offset {Fmt.Hx(off)}  size {Fmt.Size(size)}", R.Value, off);
            }
            for (int i = 0; i < Math.Min(n, 16u); i++)
            {
                long a = 8 + i * 20;
                ParseSlice(s, d, ctx, s.U32(a + 8, true), $"Slice {i}: ");
            }
            return;
        }
        ParseSlice(s, d, ctx, 0, "");
    }

    static void ParseSlice(ByteSource s, Doc d, Ctx ctx, long b, string prefix)
    {
        uint m = s.U32(b, true);
        bool be = m is 0xFEEDFACE or 0xFEEDFACF;
        bool is64 = m is 0xFEEDFACF or 0xCFFAEDFE;
        uint cpu = s.U32(b + 4, be), ft = s.U32(b + 12, be), ncmds = s.U32(b + 16, be), flags = s.U32(b + 24, be);
        d.H(prefix + "Mach-O header");
        d.KV("Magic", Fmt.Hx(m, 8) + (is64 ? " (64-bit)" : " (32-bit)") + (be ? " big-endian" : " little-endian"), R.Value, b);
        d.KV("CPU type", Fmt.Lookup(Cpu, cpu, Fmt.Hx(cpu)), R.Value, b + 4);
        d.KV("File type", Fmt.Lookup(FileTypes, ft, ft.ToString()), R.Value, b + 12);
        d.KV("Load commands", $"{ncmds} ({s.U32(b + 20, be)} bytes)", R.Num);
        d.KV("Flags", Fmt.Hx(flags, 8) + "  " + Fmt.Flags(flags, new (ulong, string)[] { (1, "NOUNDEFS"), (4, "DYLDLINK"), (0x80, "TWOLEVEL"), (0x200000, "PIE"), (0x20000, "ALLOW_STACK_EXECUTION"), (0x1000000, "HAS_TLV_DESCRIPTORS"), (0x800000, "NO_HEAP_EXECUTION") }), R.Value);
        if (prefix == "")
        {
            var rt = ctx.Refined ?? new FileType();
            rt.Name = $"Mach-O {(is64 ? "64" : "32")}-bit {Fmt.Lookup(FileTypes, ft, "")}, {Fmt.Lookup(Cpu, cpu, "")}";
            ctx.Refined = rt;
        }
        d.H(prefix + "Load commands");
        long p = b + (is64 ? 32 : 28);
        bool signed = false;
        for (int i = 0; i < Math.Min(ncmds, 2000u); i++)
        {
            if (!s.Has(p, 8)) break;
            uint cmd = s.U32(p, be), size = s.U32(p + 4, be);
            string name = Fmt.Lookup(Cmds, cmd, Fmt.Hx(cmd));
            string detail = "";
            switch (cmd)
            {
                case 0x19: detail = $"{s.Fixed(p + 8, 16)}  vm {Fmt.Hx(s.U64(p + 24, be))} size {Fmt.Hx(s.U64(p + 32, be))}  file {Fmt.Hx(s.U64(p + 40, be))} size {Fmt.Hx(s.U64(p + 48, be))}"; break;
                case 0x1: detail = $"{s.Fixed(p + 8, 16)}  vm {Fmt.Hx(s.U32(p + 24, be))}  file {Fmt.Hx(s.U32(p + 32, be))} size {Fmt.Hx(s.U32(p + 36, be))}"; break;
                case 0xC or 0xD or 0x80000018 or 0x8000001F or 0xE or 0x8000001C:
                    detail = s.Ascii(p + s.U32(p + 8, be), (int)Math.Min(size, 1024)); break;
                case 0x1B: detail = Fmt.Guid(s.Bytes(p + 8, 16)); break;
                case 0x80000028: detail = "entry offset " + Fmt.Hx(s.U64(p + 8, be)); break;
                case 0x1D: detail = $"dataoff {Fmt.Hx(s.U32(p + 8, be))} size {s.U32(p + 12, be)}"; signed = true; break;
                case 0x21 or 0x2C: uint cid = s.U32(p + 16, be); detail = $"cryptid {cid}{(cid != 0 ? " (ENCRYPTED)" : "")}"; if (cid != 0) ctx.Warn("Mach-O", "Binary is FairPlay-encrypted"); break;
                case 0x32: uint mn = s.U32(p + 12, be), sdk = s.U32(p + 16, be); detail = $"platform {s.U32(p + 8, be)}  minos {mn >> 16}.{(mn >> 8) & 255}.{mn & 255}  sdk {sdk >> 16}.{(sdk >> 8) & 255}"; break;
                case 0x2: detail = $"symoff {Fmt.Hx(s.U32(p + 8, be))} nsyms {s.U32(p + 12, be)}"; break;
            }
            d.Add(p, new Seg($"  {name,-22} ", R.Key), new Seg(Fmt.Clean(detail, 300), R.Str));
            if (size < 8) break;
            p += size;
        }
        if (!signed && prefix == "") ctx.Info("Mach-O", "No code signature load command");
    }
}
