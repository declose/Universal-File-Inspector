using System.Text;

namespace Ufi.Core;

public sealed class FileType
{
    public string Kind = "unknown";      // parser key
    public string Name = "Unknown binary data";
    public string Mime = "application/octet-stream";
    public string Category = "Binary";
    public string[] Exts = Array.Empty<string>();
    public bool IsText;
    public string TextEncoding;
    public int BomLength;
    public string Confidence = "magic";

    public FileType Clone() => (FileType)MemberwiseClone();
}

public static class Detect
{
    sealed record Sig(string Kind, string Name, string Mime, string Cat, string Exts, Func<ByteSource, bool> Test);

    static Func<ByteSource, bool> M(long off, string hex)
    {
        var bytes = Convert.FromHexString(hex.Replace(" ", ""));
        return s => s.Match(off, bytes);
    }
    static Func<ByteSource, bool> A(long off, string ascii) { var b = Encoding.Latin1.GetBytes(ascii); return s => s.Match(off, b); }

    static readonly Sig[] Sigs =
    {
        new("pe", "Windows PE executable", "application/vnd.microsoft.portable-executable", "Executable", "exe,dll,sys,scr,cpl,ocx,drv,efi,mui,com,node,ax,tlb,winmd",
            s => s.Match(0, "MZ") && s.Length > 0x40 && s.U32(0x3C) is var p && p < s.Length - 4 && s.U32(p) == 0x4550),
        new("mz", "MS-DOS MZ executable", "application/x-dosexec", "Executable", "exe,com", A(0, "MZ")),
        new("elf", "ELF executable / object", "application/x-elf", "Executable", "so,o,elf,ko,bin,axf,prx,", M(0, "7F454C46")),
        new("macho", "Mach-O binary", "application/x-mach-binary", "Executable", "dylib,bundle,o,", s => s.Length >= 4 && s.U32(0, true) is 0xFEEDFACE or 0xFEEDFACF or 0xCEFAEDFE or 0xCFFAEDFE),
        new("macho", "Mach-O universal (fat) binary", "application/x-mach-binary", "Executable", "dylib,",
            s => s.Length >= 8 && s.U32(0, true) == 0xCAFEBABE && s.U32(4, true) is > 0 and < 40),
        new("class", "Java class file", "application/java-vm", "Executable", "class", s => s.Length >= 8 && s.U32(0, true) == 0xCAFEBABE && s.U16(6, true) >= 45),
        new("dex", "Android Dalvik executable (DEX)", "application/vnd.android.dex", "Executable", "dex", A(0, "dex\n")),
        new("wasm", "WebAssembly binary module", "application/wasm", "Executable", "wasm", M(0, "0061736D")),
        new("lnk", "Windows shortcut (Shell Link)", "application/x-ms-shortcut", "Shortcut", "lnk", M(0, "4C0000000114020000000000C000000000000046")),
        new("zip", "ZIP archive", "application/zip", "Archive", "zip,jar,apk,docx,xlsx,pptx,odt,ods,odp,epub,vsix,nupkg,xpi,appx,msix,ipa,kmz,whl,aar,war,ear,crx,3mf",
            s => s.Match(0, "PK\x03\x04") || s.Match(0, "PK\x05\x06") || s.Match(0, "PK\x07\x08")),
        new("pdf", "PDF document", "application/pdf", "Document", "pdf,ai", s => FindInHead(s, "%PDF-", 1024) >= 0),
        new("cfb", "OLE2 Compound File (CFB)", "application/x-ole-storage", "Document", "doc,xls,ppt,msi,msg,msp,mst,pub,vsd,db,ole,wiz,dot,xlt,pot",
            M(0, "D0CF11E0A1B11AE1")),
        new("png", "PNG image", "image/png", "Image", "png,apng", M(0, "89504E470D0A1A0A")),
        new("jpeg", "JPEG image", "image/jpeg", "Image", "jpg,jpeg,jpe,jfif", M(0, "FFD8FF")),
        new("gif", "GIF image", "image/gif", "Image", "gif", s => s.Match(0, "GIF87a") || s.Match(0, "GIF89a")),
        new("bmp", "BMP bitmap image", "image/bmp", "Image", "bmp,dib", s => s.Match(0, "BM") && s.Length >= 26 && s.U32(14) is 12 or 40 or 52 or 56 or 64 or 108 or 124),
        new("ico", "Windows icon", "image/vnd.microsoft.icon", "Image", "ico", s => s.Length >= 22 && s.U32(0) == 0x00010000 && s.U16(4) is > 0 and < 256),
        new("ico", "Windows cursor", "image/x-win-bitmap", "Image", "cur", s => s.Length >= 22 && s.U32(0) == 0x00020000 && s.U16(4) is > 0 and < 256),
        new("tiff", "TIFF image / TIFF-based RAW", "image/tiff", "Image", "tif,tiff,dng,cr2,nef,arw,orf,rw2,pef,srw", s => s.Match(0, "II*\0") || s.Match(0, "MM\0*")),
        new("riff", "RIFF container", "application/x-riff", "Media", "wav,avi,webp,ani,rmi,cdr", A(0, "RIFF")),
        new("isobmff", "ISO Base Media (MP4/MOV/HEIF)", "video/mp4", "Media", "mp4,m4a,m4v,mov,3gp,3g2,heic,heif,avif,f4v,m4b,mj2", A(4, "ftyp")),
        new("mp3", "MP3 audio (ID3 tagged)", "audio/mpeg", "Media", "mp3", A(0, "ID3")),
        new("flac", "FLAC audio", "audio/flac", "Media", "flac", A(0, "fLaC")),
        new("ogg", "Ogg container", "audio/ogg", "Media", "ogg,oga,ogv,opus,spx", A(0, "OggS")),
        new("mkv", "Matroska / WebM", "video/x-matroska", "Media", "mkv,webm,mka,mk3d", M(0, "1A45DFA3")),
        new("flv", "Flash video", "video/x-flv", "Media", "flv", A(0, "FLV\x01")),
        new("midi", "MIDI audio", "audio/midi", "Media", "mid,midi", A(0, "MThd")),
        new("aiff", "AIFF audio", "audio/aiff", "Media", "aif,aiff,aifc", s => s.Match(0, "FORM") && (s.Match(8, "AIFF") || s.Match(8, "AIFC"))),
        new("gzip", "GZIP compressed data", "application/gzip", "Archive", "gz,tgz,gzip,svgz", M(0, "1F8B")),
        new("7z", "7-Zip archive", "application/x-7z-compressed", "Archive", "7z", M(0, "377ABCAF271C")),
        new("rar", "RAR archive", "application/vnd.rar", "Archive", "rar", A(0, "Rar!\x1A\x07")),
        new("xz", "XZ compressed data", "application/x-xz", "Archive", "xz,txz", M(0, "FD377A585A00")),
        new("bz2", "BZIP2 compressed data", "application/x-bzip2", "Archive", "bz2,tbz,tbz2", s => s.Match(0, "BZh") && s.Length > 3 && s.U8(3) is >= (byte)'1' and <= (byte)'9'),
        new("zstd", "Zstandard compressed data", "application/zstd", "Archive", "zst,zstd", M(0, "28B52FFD")),
        new("lz4", "LZ4 frame", "application/x-lz4", "Archive", "lz4", M(0, "04224D18")),
        new("cab", "Microsoft Cabinet archive", "application/vnd.ms-cab-compressed", "Archive", "cab,msu", s => s.Match(0, "MSCF") && s.Length > 36 && s.U32(4) == 0),
        new("tar", "TAR archive", "application/x-tar", "Archive", "tar", s => s.Match(257, "ustar")),
        new("ar", "Unix ar archive / Debian package", "application/x-archive", "Archive", "a,lib,deb,ar", A(0, "!<arch>\n")),
        new("rpm", "RPM package", "application/x-rpm", "Archive", "rpm", M(0, "EDABEEDB")),
        new("cpio", "CPIO archive", "application/x-cpio", "Archive", "cpio", s => s.Match(0, "070701") || s.Match(0, "070707") || s.Match(0, "070702")),
        new("iso", "ISO 9660 disc image", "application/x-iso9660-image", "Disk image", "iso", A(0x8001, "CD001")),
        new("udf", "UDF disc image", "application/x-udf", "Disk image", "iso,udf", A(0x8001, "BEA01")),
        new("vhd", "Virtual Hard Disk (VHD)", "application/x-vhd", "Disk image", "vhd", A(0, "conectix")),
        new("vhdx", "Virtual Hard Disk v2 (VHDX)", "application/x-vhdx", "Disk image", "vhdx", A(0, "vhdxfile")),
        new("vmdk", "VMware disk (VMDK)", "application/x-vmdk", "Disk image", "vmdk", A(0, "KDMV")),
        new("qcow", "QEMU disk (QCOW)", "application/x-qemu-disk", "Disk image", "qcow2,qcow", A(0, "QFI\xFB")),
        new("wim", "Windows Imaging (WIM)", "application/x-ms-wim", "Disk image", "wim,esd,swm", A(0, "MSWIM\0\0\0")),
        new("squashfs", "SquashFS filesystem", "application/x-squashfs", "Disk image", "squashfs,snap,sqsh", A(0, "hsqs")),
        new("sqlite", "SQLite 3 database", "application/vnd.sqlite3", "Database", "sqlite,sqlite3,db,db3,s3db", A(0, "SQLite format 3\0")),
        new("regf", "Windows Registry hive", "application/x-ms-registry", "Database", "dat,hive,hiv,", A(0, "regf")),
        new("evtx", "Windows Event Log (EVTX)", "application/x-ms-evtx", "Log", "evtx", A(0, "ElfFile\0")),
        new("prefetch", "Windows Prefetch (compressed)", "application/x-ms-prefetch", "Log", "pf", s => s.Match(0, "MAM\x04")),
        new("prefetch", "Windows Prefetch", "application/x-ms-prefetch", "Log", "pf", A(4, "SCCA")),
        new("pcap", "PCAP network capture", "application/vnd.tcpdump.pcap", "Capture", "pcap,cap,dmp",
            s => s.Length >= 4 && s.U32(0) is 0xA1B2C3D4 or 0xD4C3B2A1 or 0xA1B23C4D or 0x4D3CB2A1),
        new("pcapng", "PCAPNG network capture", "application/x-pcapng", "Capture", "pcapng,ntar", M(0, "0A0D0D0A")),
        new("minidump", "Windows minidump", "application/x-dmp", "Dump", "dmp,mdmp", A(0, "MDMP")),
        new("psd", "Adobe Photoshop document", "image/vnd.adobe.photoshop", "Image", "psd,psb", A(0, "8BPS")),
        new("rtf", "Rich Text Format", "application/rtf", "Document", "rtf,doc", A(0, "{\\rtf")),
        new("chm", "Compiled HTML Help", "application/vnd.ms-htmlhelp", "Document", "chm", A(0, "ITSF")),
        new("djvu", "DjVu document", "image/vnd.djvu", "Document", "djvu,djv", A(0, "AT&TFORM")),
        new("ps", "PostScript document", "application/postscript", "Document", "ps,eps", A(0, "%!PS")),
        new("ttf", "TrueType font", "font/ttf", "Font", "ttf,tte,dfont", M(0, "0001000000")),
        new("otf", "OpenType font (CFF)", "font/otf", "Font", "otf", A(0, "OTTO")),
        new("woff", "WOFF web font", "font/woff", "Font", "woff", A(0, "wOFF")),
        new("woff2", "WOFF2 web font", "font/woff2", "Font", "woff2", A(0, "wOF2")),
        new("ttc", "TrueType font collection", "font/collection", "Font", "ttc", A(0, "ttcf")),
        new("jp2", "JPEG 2000 image", "image/jp2", "Image", "jp2,j2k,jpf,jpx", M(0, "0000000C6A5020200D0A870A")),
        new("jxl", "JPEG XL image", "image/jxl", "Image", "jxl", s => s.Match(0, new byte[] { 0xFF, 0x0A }) || s.Match(0, Convert.FromHexString("0000000C4A584C200D0A870A"))),
        new("dicom", "DICOM medical image", "application/dicom", "Image", "dcm,dicom", A(128, "DICM")),
        new("fits", "FITS scientific image", "image/fits", "Image", "fits,fit,fts", A(0, "SIMPLE  =")),
        new("hdf5", "HDF5 data", "application/x-hdf5", "Data", "h5,hdf5,hdf", M(0, "894844460D0A1A0A")),
        new("parquet", "Apache Parquet", "application/vnd.apache.parquet", "Data", "parquet", A(0, "PAR1")),
        new("avro", "Apache Avro container", "application/avro", "Data", "avro", A(0, "Obj\x01")),
        new("blend", "Blender project", "application/x-blender", "Data", "blend", A(0, "BLENDER")),
        new("glb", "glTF binary 3D model", "model/gltf-binary", "Data", "glb", A(0, "glTF")),
        new("swf", "Adobe Flash (SWF)", "application/x-shockwave-flash", "Executable", "swf", s => s.Match(0, "FWS") || s.Match(0, "CWS") || s.Match(0, "ZWS")),
        new("crx", "Chrome extension (CRX)", "application/x-chrome-extension", "Archive", "crx", A(0, "Cr24")),
        new("luks", "LUKS encrypted volume", "application/x-luks", "Encrypted", "luks,img", A(0, "LUKS\xBA\xBE")),
        new("pgp", "PGP/GPG armored data", "application/pgp", "Encrypted", "asc,gpg,pgp,sig", A(0, "-----BEGIN PGP")),
        new("kdbx", "KeePass database", "application/x-keepass", "Encrypted", "kdbx,kdb", M(0, "03D9A29A")),
        new("ewf", "EnCase evidence file (EWF)", "application/x-ewf", "Disk image", "e01,ex01,l01", A(0, "EVF\x09\x0D\x0A\xFF\0")),
        new("der", "DER-encoded certificate / ASN.1", "application/pkix-cert", "Certificate", "cer,crt,der,p7b,p7s,p12,pfx,spc,cat",
            s => s.Length > 16 && s.U8(0) == 0x30 && (s.U8(1) == 0x82 || s.U8(1) == 0x83 || s.U8(1) == 0x84) && s.U8(s.U8(1) - 0x80 + 2) == 0x30),
        new("pem", "PEM-encoded data", "application/x-pem-file", "Certificate", "pem,crt,cer,key,csr,pub", A(0, "-----BEGIN ")),
    };

    static long FindInHead(ByteSource s, string ascii, int max)
    {
        var head = s.Bytes(0, max);
        return head.AsSpan().IndexOf(Encoding.Latin1.GetBytes(ascii));
    }

    /// <summary>Quick magic-only identification of a byte buffer (used for embedded data / overlays).</summary>
    public static string Quick(ReadOnlySpan<byte> b)
    {
        static bool S(ReadOnlySpan<byte> b, int o, string a) => b.Length >= o + a.Length && b.Slice(o, a.Length).SequenceEqual(Encoding.Latin1.GetBytes(a));
        if (S(b, 0, "MZ")) return "PE/DOS executable (MZ)";
        if (S(b, 0, "\x7F" + "ELF")) return "ELF executable";
        if (S(b, 0, "PK\x03\x04")) return "ZIP archive";
        if (S(b, 0, "%PDF-")) return "PDF document";
        if (S(b, 0, "\x89PNG")) return "PNG image";
        if (S(b, 0, "\xFF\xD8\xFF")) return "JPEG image";
        if (S(b, 0, "GIF8")) return "GIF image";
        if (S(b, 0, "BM")) return "BMP image (?)";
        if (S(b, 0, "7z\xBC\xAF\x27\x1C")) return "7-Zip archive";
        if (S(b, 0, "Rar!")) return "RAR archive";
        if (S(b, 0, "MSCF")) return "Cabinet archive";
        if (S(b, 0, "\x1F\x8B")) return "GZIP data";
        if (S(b, 0, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")) return "OLE2 compound file";
        if (S(b, 0, "SQLite format 3")) return "SQLite database";
        if (S(b, 0, "RIFF")) return "RIFF container";
        if (S(b, 0, "ID3")) return "MP3 audio (ID3)";
        if (S(b, 0, "{\\rtf")) return "RTF document";
        if (S(b, 0, "<?xml")) return "XML document";
        if (S(b, 0, "\xFD" + "7zXZ")) return "XZ data";
        if (S(b, 0, "BZh")) return "BZIP2 data";
        if (S(b, 0, "\x28\xB5\x2F\xFD")) return "Zstandard data";
        if (S(b, 4, "ftyp")) return "MP4/MOV media";
        if (S(b, 0, "\x00\x00\x01\x00")) return "ICO icon (?)";
        if (S(b, 0, "\xCA\xFE\xBA\xBE")) return "Java class / Mach-O fat";
        if (S(b, 0, "-----BEGIN")) return "PEM data";
        if (S(b, 0, "0\x82")) return "ASN.1 / DER data (certificate?)";
        if (S(b, 0, "Nullsoft")) return "NSIS installer data";
        if (b.Length > 8 && b.Slice(0, Math.Min(b.Length, 64)).IndexOf("Inno Setup"u8) >= 0) return "Inno Setup data";
        return null;
    }

    public static FileType Run(ByteSource s, string ext)
    {
        ext = (ext ?? "").TrimStart('.').ToLowerInvariant();
        FileType ft = null;
        if (s.Length == 0)
            return new FileType { Kind = "empty", Name = "Empty file (0 bytes)", Mime = "application/x-empty", Category = "Empty", Confidence = "size" };

        foreach (var sig in Sigs)
        {
            bool hit;
            try { hit = sig.Test(s); } catch { hit = false; }
            if (!hit) continue;
            ft = new FileType { Kind = sig.Kind, Name = sig.Name, Mime = sig.Mime, Category = sig.Cat, Exts = sig.Exts.Split(',') };
            break;
        }

        // RIFF / ISO BMFF sub-types
        if (ft?.Kind == "riff" && s.Length >= 12)
        {
            string form = s.Fixed(8, 4);
            (ft.Name, ft.Mime, ft.Exts) = form switch
            {
                "WAVE" => ("WAVE audio (RIFF)", "audio/wav", new[] { "wav", "wave" }),
                "AVI " => ("AVI video (RIFF)", "video/x-msvideo", new[] { "avi" }),
                "WEBP" => ("WebP image (RIFF)", "image/webp", new[] { "webp" }),
                "ACON" => ("Animated cursor (RIFF)", "application/x-navi-animation", new[] { "ani" }),
                "RMID" => ("RIFF MIDI", "audio/midi", new[] { "rmi", "mid" }),
                _ => ($"RIFF container ({form})", ft.Mime, ft.Exts)
            };
            if (form == "WEBP") ft.Category = "Image";
        }
        if (ft?.Kind == "isobmff" && s.Length >= 12)
        {
            string brand = s.Fixed(8, 4);
            (ft.Name, ft.Mime) = brand switch
            {
                "qt" => ("QuickTime movie", "video/quicktime"),
                "heic" or "heix" or "mif1" or "msf1" or "heim" or "heis" => ("HEIF/HEIC image", "image/heic"),
                "avif" or "avis" => ("AVIF image", "image/avif"),
                "M4A" or "M4B" or "M4P" => ("MPEG-4 audio", "audio/mp4"),
                "3gp4" or "3gp5" or "3gp6" or "3g2a" => ("3GPP media", "video/3gpp"),
                "crx" => ("Canon CR3 RAW image", "image/x-canon-cr3"),
                _ => ($"MPEG-4 media (brand '{brand}')", "video/mp4")
            };
            if (ft.Mime.StartsWith("image")) ft.Category = "Image";
        }

        // MP3 without ID3: MPEG frame sync
        if (ft == null && s.Length > 4 && s.U8(0) == 0xFF && (s.U8(1) & 0xE0) == 0xE0 && (s.U8(1) & 0x06) != 0 && (ext == "mp3" || ext == "mp2" || ext == "mpga"))
            ft = new FileType { Kind = "mp3", Name = "MPEG audio (no ID3 tag)", Mime = "audio/mpeg", Category = "Media", Exts = new[] { "mp3", "mp2" } };

        // Text sniffing
        var head = s.Bytes(0, 64 * 1024);
        var (isText, enc, bom) = SniffText(head);
        if (ft == null || ft.Kind == "pem" || ft.Kind == "rtf" || ft.Kind == "pgp" || ft.Kind == "ps")
        {
            if (isText)
            {
                ft ??= ClassifyText(head, bom, enc, ext);
                ft.IsText = true; ft.TextEncoding = enc; ft.BomLength = bom;
            }
        }
        else if (ft.Kind == "mz" && isText) ft = null; // "MZ..." text file

        if (ft == null)
        {
            if (isText) { ft = ClassifyText(head, bom, enc, ext); ft.IsText = true; ft.TextEncoding = enc; ft.BomLength = bom; }
            else ft = new FileType { Confidence = "none" };
        }
        return ft;
    }

    /// <summary>Returns whether a buffer looks like text, and its probable encoding and BOM length.</summary>
    public static (bool isText, string enc, int bom) SniffText(ReadOnlySpan<byte> b)
    {
        if (b.Length >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) return (true, "UTF-8 (BOM)", 3);
        if (b.Length >= 4 && b[0] == 0xFF && b[1] == 0xFE && b[2] == 0 && b[3] == 0) return (true, "UTF-32 LE (BOM)", 4);
        if (b.Length >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 0xFE && b[3] == 0xFF) return (true, "UTF-32 BE (BOM)", 4);
        if (b.Length >= 2 && b[0] == 0xFF && b[1] == 0xFE) return (true, "UTF-16 LE (BOM)", 2);
        if (b.Length >= 2 && b[0] == 0xFE && b[1] == 0xFF) return (true, "UTF-16 BE (BOM)", 2);
        if (b.Length == 0) return (false, null, 0);

        // UTF-16 without BOM: many zero bytes at odd (LE) or even (BE) positions
        int n = Math.Min(b.Length, 8192) & ~1;
        if (n >= 16)
        {
            int zOdd = 0, zEven = 0;
            for (int i = 0; i < n; i += 2) { if (b[i] == 0) zEven++; if (b[i + 1] == 0) zOdd++; }
            int pairs = n / 2;
            if (zOdd > pairs * 0.7 && zEven < pairs * 0.05) return (true, "UTF-16 LE (no BOM)", 0);
            if (zEven > pairs * 0.7 && zOdd < pairs * 0.05) return (true, "UTF-16 BE (no BOM)", 0);
        }

        int ctrl = 0, high = 0;
        foreach (byte c in b)
        {
            if (c == 0) return (false, null, 0);
            if (c < 0x20 && c != 9 && c != 10 && c != 13 && c != 12 && c != 27 && c != 8) ctrl++;
            if (c >= 0x80) high++;
        }
        if (ctrl > b.Length / 100 + 1) return (false, null, 0);
        if (high == 0) return (true, "ASCII", 0);
        if (IsValidUtf8(b)) return (true, "UTF-8", 0);
        if (high < b.Length * 0.3) return (true, "Windows-1252 / Latin-1 (8-bit)", 0);
        return (false, null, 0);
    }

    static bool IsValidUtf8(ReadOnlySpan<byte> b)
    {
        // tolerate a truncated sequence at the very end of the sample
        int i = 0;
        while (i < b.Length)
        {
            byte c = b[i];
            int need = c < 0x80 ? 0 : (c & 0xE0) == 0xC0 ? 1 : (c & 0xF0) == 0xE0 ? 2 : (c & 0xF8) == 0xF0 ? 3 : -1;
            if (need < 0) return false;
            if (i + need >= b.Length) return true;
            for (int k = 1; k <= need; k++) if ((b[i + k] & 0xC0) != 0x80) return false;
            i += need + 1;
        }
        return true;
    }

    static FileType ClassifyText(byte[] head, int bom, string enc, string ext)
    {
        string t;
        try
        {
            t = enc != null && enc.StartsWith("UTF-16 LE") ? Encoding.Unicode.GetString(head, bom, Math.Max(0, (head.Length - bom) & ~1))
              : enc != null && enc.StartsWith("UTF-16 BE") ? Encoding.BigEndianUnicode.GetString(head, bom, Math.Max(0, (head.Length - bom) & ~1))
              : Encoding.UTF8.GetString(head, bom, head.Length - bom);
        }
        catch { t = ""; }
        string lt = t.TrimStart();
        string low = lt.Length > 4096 ? lt[..4096].ToLowerInvariant() : lt.ToLowerInvariant();
        FileType F(string kind, string name, string mime, params string[] exts) => new() { Kind = kind, Name = name, Mime = mime, Category = "Text", Exts = exts };

        if (low.StartsWith("-----begin certificate")) return F("pem", "PEM X.509 certificate", "application/x-pem-file", "pem", "crt", "cer");
        if (low.StartsWith("-----begin") && low.Contains("private key")) return F("pem", "PEM private key", "application/x-pem-file", "pem", "key");
        if (low.StartsWith("-----begin pgp")) return F("pgp", "PGP armored data", "application/pgp", "asc", "gpg", "pgp", "sig");
        if (low.StartsWith("-----begin")) return F("pem", "PEM-encoded data", "application/x-pem-file", "pem");
        if (low.StartsWith("{\\rtf")) return F("rtf", "Rich Text Format", "application/rtf", "rtf", "doc");
        if (lt.StartsWith("#!"))
        {
            string first = lt.Split('\n')[0].Trim();
            var st = F("script", "Script with shebang: " + Fmt.Trunc(first, 60), "text/x-script", "sh", "bash", "py", "pl", "rb", "js", "zsh", "");
            return st;
        }
        if (low.StartsWith("<?xml") || low.StartsWith("<svg") || (low.StartsWith("<") && low.Contains("<svg")))
        {
            if (low.Contains("<svg")) return F("xml", "SVG vector image (XML)", "image/svg+xml", "svg");
            if (low.Contains("<plist")) return F("xml", "Apple property list (XML)", "application/x-plist", "plist");
            if (low.Contains("<assembly") && low.Contains("urn:schemas-microsoft-com:asm")) return F("xml", "Windows application manifest (XML)", "application/xml", "manifest", "xml");
            if (low.Contains("<project") && low.Contains("msbuild")) return F("xml", "MSBuild project (XML)", "application/xml", "csproj", "vbproj", "proj", "props", "targets", "xml");
            return F("xml", "XML document", "application/xml", "xml", "xsd", "xsl", "xslt", "config", "resx", "csproj", "props", "targets", "nuspec", "manifest", "plist", "rss", "atom", "xaml", "svg", "kml", "gpx", "wsf", "xhtml");
        }
        if (low.StartsWith("<!doctype html") || low.StartsWith("<html") || low.Contains("<html") || low.Contains("<head>") || low.Contains("<body"))
            return F("html", "HTML document", "text/html", "html", "htm", "xhtml", "hta", "mht", "php", "aspx", "jsp");
        if ((lt.StartsWith("{") || lt.StartsWith("[")) && (ext is "json" or "geojson" or "ipynb" or "har" or "webmanifest" or "jsonc" or "" or "txt" || lt.Contains("\":")))
            return F("json", "JSON data", "application/json", "json", "geojson", "ipynb", "har", "webmanifest", "jsonc", "map", "lock");
        if (low.StartsWith("@echo off") || low.Contains("\n@echo off") || low.StartsWith("rem ") || ext is "bat" or "cmd")
            return F("script", "Windows batch script", "application/x-bat", "bat", "cmd");
        if (ext is "ps1" or "psm1" or "psd1" || low.Contains("param(") && low.Contains("$") || low.Contains("write-host") || low.Contains("get-childitem"))
            return F("script", "PowerShell script", "application/x-powershell", "ps1", "psm1", "psd1");
        if (ext is "vbs" or "vbe" or "vba" || low.Contains("wscript.") || low.Contains("createobject(") || low.StartsWith("dim ") || low.Contains("\nsub ") || low.Contains("end sub"))
            return F("script", "VBScript / Visual Basic source", "text/vbscript", "vbs", "vba", "bas", "cls", "frm");
        if (ext is "js" or "mjs" or "cjs" or "jse" || low.Contains("function(") || low.Contains("function ") && low.Contains("var ") || low.Contains("=>") && low.Contains("const "))
            return F("script", "JavaScript source", "text/javascript", "js", "mjs", "cjs", "jse", "ts", "jsx", "tsx");
        if (ext is "py" or "pyw" || low.Contains("\nimport ") || low.StartsWith("import ") || low.Contains("def ") && low.Contains("):"))
            return F("script", "Python source", "text/x-python", "py", "pyw", "pyi");
        if (low.Contains("#include") || low.Contains("int main(")) return F("text", "C / C++ source", "text/x-c", "c", "h", "cpp", "hpp", "cc", "cxx", "hh", "ino");
        if (low.Contains("using system") || low.Contains("namespace ") && low.Contains("class ")) return F("text", "C# source", "text/x-csharp", "cs");
        if (low.StartsWith("[") && low.Contains("]\n") && low.Contains("=") || ext is "ini" or "inf" or "reg" or "cfg" or "url" or "desktop")
        {
            if (low.StartsWith("windows registry editor") || low.StartsWith("regedit4")) return F("text", "Windows registry export (.reg)", "text/x-ms-regedit", "reg");
            if (low.Contains("[internetshortcut]")) return F("text", "Internet shortcut (.url)", "application/x-mswinurl", "url");
            return F("text", "INI / configuration text", "text/plain", "ini", "inf", "cfg", "conf", "url", "desktop", "reg", "toml", "properties");
        }
        if (low.StartsWith("windows registry editor") || low.StartsWith("regedit4")) return F("text", "Windows registry export (.reg)", "text/x-ms-regedit", "reg");
        if (low.StartsWith("---") || low.Contains(":\n  ") && ext is "yml" or "yaml") return F("text", "YAML document", "application/yaml", "yml", "yaml", "md");
        if (low.StartsWith("# ") || low.Contains("\n## ") || ext is "md" or "markdown") return F("text", "Markdown text", "text/markdown", "md", "markdown", "txt");
        if (low.Contains("begin:vcard")) return F("text", "vCard contact", "text/vcard", "vcf", "vcard");
        if (low.Contains("begin:vcalendar")) return F("text", "iCalendar data", "text/calendar", "ics", "ical");
        if (low.StartsWith("from ") && low.Contains("\nreceived:") || low.Contains("\nmessage-id:") || low.StartsWith("received:") || low.StartsWith("return-path:"))
            return F("text", "E-mail message (RFC 822 / EML)", "message/rfc822", "eml", "msg", "mbox", "txt");
        if (IsCsv(t)) return F("text", "CSV / delimited text", "text/csv", "csv", "tsv", "txt", "tab");
        return F("text", "Plain text", "text/plain", "txt", "log", "md", "csv", "ini", "cfg", "conf", "text", "nfo", "diz", "asc", "srt", "sub", "sql", "css", "scss", "java", "go", "rs", "rb", "php", "pl", "sh", "lua", "kt", "swift", "yaml", "yml", "toml", "gitignore", "editorconfig", "env", "properties", "license", "readme", "");
    }

    static bool IsCsv(string t)
    {
        var lines = t.Split('\n').Take(10).Where(l => l.Length > 0).ToArray();
        if (lines.Length < 3) return false;
        foreach (char d in new[] { ',', ';', '\t', '|' })
        {
            int c0 = lines[0].Count(ch => ch == d);
            if (c0 >= 1 && lines.Take(lines.Length - 1).All(l => l.Count(ch => ch == d) == c0)) return true;
        }
        return false;
    }
}
