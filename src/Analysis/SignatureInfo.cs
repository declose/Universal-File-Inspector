using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Ufi.Core;
using Ufi.Parsers;

namespace Ufi.Analysis;

/// <summary>Authenticode: WinVerifyTrust verdict (no UI, no revocation network calls) plus a full PKCS#7 dump.</summary>
public static class SignatureInfo
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WINTRUST_FILE_INFO { public uint cbStruct; public IntPtr pcwszFilePath; public IntPtr hFile; public IntPtr pgKnownSubject; }

    [StructLayout(LayoutKind.Sequential)]
    struct WINTRUST_DATA
    {
        public uint cbStruct; public IntPtr pPolicyCallbackData; public IntPtr pSIPClientData; public uint dwUIChoice; public uint fdwRevocationChecks;
        public uint dwUnionChoice; public IntPtr pFile; public uint dwStateAction; public IntPtr hWVTStateData; public IntPtr pwszURLReference;
        public uint dwProvFlags; public uint dwUIContext; public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

    static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct; public uint dwCatalogVersion; public IntPtr pcwszCatalogFilePath; public IntPtr pcwszMemberTag; public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile; public IntPtr pbCalculatedFileHash; public uint cbCalculatedFileHash; public IntPtr pcCatalogContext; public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CATALOG_INFO { public uint cbStruct; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile; }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CryptCATAdminAcquireContext2(out IntPtr hCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);
    [DllImport("wintrust.dll", SetLastError = true)]
    static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);
    [DllImport("wintrust.dll", SetLastError = true)]
    static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);
    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);
    [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);
    [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    /// <summary>Looks the file's hash up in the system catalog database and verifies the catalog signature.</summary>
    static (string catalog, int rc, string hash) VerifyCatalog(string path)
    {
        foreach (var alg in new[] { "SHA256", null })
        {
            if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, alg, IntPtr.Zero, 0)) continue;
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                var h = fs.SafeFileHandle.DangerousGetHandle();
                uint cb = 64; var hash = new byte[64];
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, h, ref cb, hash, 0)) continue;
                Array.Resize(ref hash, (int)cb);
                IntPtr info = CryptCATAdminEnumCatalogFromHash(admin, hash, cb, 0, IntPtr.Zero);
                if (info == IntPtr.Zero) continue;
                try
                {
                    var ci = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                    if (!CryptCATCatalogInfoFromContext(info, ref ci, 0)) continue;
                    string tag = Convert.ToHexString(hash);
                    IntPtr pCat = Marshal.StringToHGlobalUni(ci.wszCatalogFile), pTag = Marshal.StringToHGlobalUni(tag), pPath = Marshal.StringToHGlobalUni(path);
                    IntPtr pHash = Marshal.AllocHGlobal(hash.Length); Marshal.Copy(hash, 0, pHash, hash.Length);
                    var cat = new WINTRUST_CATALOG_INFO
                    {
                        cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(), pcwszCatalogFilePath = pCat, pcwszMemberTag = pTag, pcwszMemberFilePath = pPath,
                        hMemberFile = h, pbCalculatedFileHash = pHash, cbCalculatedFileHash = (uint)hash.Length, hCatAdmin = admin,
                    };
                    IntPtr pInfo = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
                    Marshal.StructureToPtr(cat, pInfo, false);
                    var data = new WINTRUST_DATA
                    {
                        cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(), dwUIChoice = 2, fdwRevocationChecks = 0, dwUnionChoice = 2 /*CATALOG*/,
                        pFile = pInfo, dwStateAction = 1, dwProvFlags = 0x1000 | 0x10,
                    };
                    var action = GenericVerifyV2;
                    int rc;
                    try
                    {
                        rc = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
                        data.dwStateAction = 2;
                        WinVerifyTrust(new IntPtr(-1), ref action, ref data);
                    }
                    finally { Marshal.FreeHGlobal(pInfo); Marshal.FreeHGlobal(pCat); Marshal.FreeHGlobal(pTag); Marshal.FreeHGlobal(pPath); Marshal.FreeHGlobal(pHash); }
                    return (ci.wszCatalogFile, rc, tag);
                }
                finally { CryptCATAdminReleaseCatalogContext(admin, info, 0); }
            }
            catch { }
            finally { CryptCATAdminReleaseContext(admin, 0); }
        }
        return (null, 0, null);
    }

    static (int code, string text) Verify(string path)
    {
        IntPtr pPath = Marshal.StringToHGlobalUni(path);
        var fileInfo = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = pPath };
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        Marshal.StructureToPtr(fileInfo, pFile, false);
        var data = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(), dwUIChoice = 2 /*NONE*/, fdwRevocationChecks = 0 /*NONE*/, dwUnionChoice = 1 /*FILE*/,
            pFile = pFile, dwStateAction = 1 /*VERIFY*/, dwProvFlags = 0x1000 /*CACHE_ONLY_URL_RETRIEVAL*/ | 0x10 /*REVOCATION_CHECK_NONE*/,
        };
        var action = GenericVerifyV2;
        int rc;
        try
        {
            rc = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            data.dwStateAction = 2; // CLOSE
            WinVerifyTrust(new IntPtr(-1), ref action, ref data);
        }
        finally { Marshal.FreeHGlobal(pFile); Marshal.FreeHGlobal(pPath); }
        string t = (uint)rc switch
        {
            0 => "VALID – signature verified and chains to a trusted root",
            0x800B0100 => "NOT SIGNED (no embedded signature)",
            0x800B0101 => "Certificate expired or not yet valid",
            0x800B0109 => "Chains to an UNTRUSTED root certificate",
            0x80096010 => "INVALID – file was modified after signing (hash mismatch)",
            0x800B0111 => "Explicitly distrusted (blocked certificate)",
            0x800B0004 => "Subject not trusted",
            0x800B010A => "Certificate chain could not be built",
            0x800B010C => "Certificate REVOKED",
            0x80092026 => "Blocked by security settings",
            0x800B0003 => "Subject form unknown (file type cannot carry an Authenticode signature)",
            0x80096019 => "Basic constraints violated",
            0x800B010F => "Certificate name mismatch",
            0x80096004 => "Signer certificate signature invalid",
            0x80096001 => "System-level error while verifying",
            _ => $"Verification error 0x{rc:X8}"
        };
        return (rc, t);
    }

    public static Doc Build(ByteSource s, string path, Ctx ctx)
    {
        var d = new Doc();
        d.H("Trust verdict (WinVerifyTrust, offline)");
        var (rc, text) = Verify(path);
        d.KV("Result", text, rc == 0 ? R.Good : (uint)rc is 0x800B0100 or 0x800B0003 ? R.Dim : R.Bad);
        d.KV("Status code", Fmt.Hx((uint)rc, 8), R.Num);
        d.T("  Embedded signatures only; catalog-signed system files report NOT SIGNED here. Revocation is not checked (no network).", R.Dim);
        if (rc == 0) ctx.Good("Signature", "Valid Authenticode signature");
        else if ((uint)rc == 0x80096010) ctx.Bad("Signature", "Authenticode signature is INVALID – file was tampered with after signing");
        else if ((uint)rc is 0x800B0109 or 0x800B0111 or 0x800B010C) ctx.Bad("Signature", "Signature problem: " + text);
        else if ((uint)rc == 0x800B0101) ctx.Warn("Signature", text);
        if ((uint)rc is 0x800B0100 or 0x800B0003)
        {
            (string catalog, int crc, string tag) cat = (null, 0, null);
            if (s.Length <= 512L << 20) { try { cat = VerifyCatalog(path); } catch { } }
            d.H("Catalog signature (Windows catalog database)");
            if (cat.catalog == null)
            {
                d.T("  File hash not found in any installed security catalog.", R.Dim);
                if (ctx.IsPE) ctx.Warn("Signature", "Executable is not digitally signed (neither embedded nor catalog)");
            }
            else
            {
                bool ok = cat.crc == 0;
                d.KV("Catalog file", cat.catalog, R.Accent);
                d.KV("Member tag (file hash)", cat.tag, R.Hex);
                d.KV("Catalog verdict", ok ? "VALID – file is catalog-signed" : $"0x{cat.crc:X8}", ok ? R.Good : R.Warn);
                if (ok) ctx.Good("Signature", "Catalog-signed (" + Path.GetFileName(cat.catalog) + ")");
                try
                {
                    var cms = new SignedCms(); cms.Decode(File.ReadAllBytes(cat.catalog));
                    var signer = cms.SignerInfos.Count > 0 ? cms.SignerInfos[0].Certificate : null;
                    if (signer != null) { d.KV("Catalog signer", signer.Subject, R.Str); if (ok) ctx.Info("Signature", "Signed by: " + signer.GetNameInfo(X509NameType.SimpleName, false)); }
                }
                catch { }
            }
        }

        byte[] pkcs7 = null;
        if (ctx.CertOffset > 0 && ctx.CertSize > 8)
        {
            uint len = s.U32(ctx.CertOffset);
            pkcs7 = s.Bytes(ctx.CertOffset + 8, Math.Min(len, ctx.CertSize) - 8);
        }
        if (pkcs7 == null)
        {
            try
            {
                using var c = X509CertificateLoader.LoadCertificate(X509Certificate.CreateFromSignedFile(path).Export(X509ContentType.Cert));
                d.H("Signer certificate");
                CertParser.Describe(c, d);
            }
            catch { d.T("  No embedded PKCS#7 signature blob.", R.Dim); }
            return d;
        }
        try { Dump(pkcs7, d, ctx, 0); }
        catch (Exception ex) { d.Warn("PKCS#7 decode failed: " + ex.Message); }
        return d;
    }

    static void Dump(byte[] pkcs7, Doc d, Ctx ctx, int depth)
    {
        var cms = new SignedCms();
        cms.Decode(pkcs7);
        string pre = depth > 0 ? $"Nested signature #{depth}: " : "";
        d.H(pre + "PKCS#7 SignedData");
        d.KV("Version", cms.Version, R.Num);
        string ctName = cms.ContentInfo.ContentType.Value == "1.3.6.1.4.1.311.2.1.4" ? "SpcIndirectDataContent (Authenticode)" : cms.ContentInfo.ContentType.FriendlyName;
        d.KV("Content type", $"{ctName} ({cms.ContentInfo.ContentType.Value})", R.Value);
        if (cms.ContentInfo.ContentType.Value == "1.3.6.1.4.1.311.2.1.4")
        {
            // SpcIndirectDataContent: find the digest (last OCTET STRING in the structure)
            var c = cms.ContentInfo.Content;
            for (int i = c.Length - 2; i > 0; i--)
                if (c[i] == 0x04 && c[i + 1] is 20 or 32 or 48 or 64 && i + 2 + c[i + 1] == c.Length)
                { d.KV("Authenticode digest", Convert.ToHexString(c, i + 2, c[i + 1]).ToLowerInvariant(), R.Hex); break; }
        }
        foreach (var si in cms.SignerInfos)
        {
            d.Sub("Signer");
            d.KV("    Digest algorithm", si.DigestAlgorithm.FriendlyName ?? si.DigestAlgorithm.Value, R.Value);
            d.KV("    Signature algorithm", si.SignatureAlgorithm.FriendlyName ?? si.SignatureAlgorithm.Value, R.Value);
            if (si.Certificate != null) { d.KV("    Signer", si.Certificate.Subject, R.Accent); ctx.Info("Signature", "Signed by: " + si.Certificate.GetNameInfo(X509NameType.SimpleName, false)); }
            foreach (var a in si.SignedAttributes)
            {
                string oid = a.Oid.Value;
                if (oid == "1.2.840.113549.1.9.5") d.KV("    Signing time", Fmt.Time(new Pkcs9SigningTime(a.Values[0].RawData).SigningTime.ToUniversalTime()), R.Value);
                else if (oid == "1.3.6.1.4.1.311.2.1.12")
                {
                    // SpcSpOpusInfo – program name / URL
                    var txt = System.Text.RegularExpressions.Regex.Matches(System.Text.Encoding.BigEndianUnicode.GetString(a.Values[0].RawData), @"[\x20-\x7E]{4,}").Select(m => m.Value);
                    var asc = System.Text.RegularExpressions.Regex.Matches(System.Text.Encoding.ASCII.GetString(a.Values[0].RawData), @"https?://[\x21-\x7E]+").Select(m => m.Value);
                    d.KV("    Program info", string.Join("  ", txt.Concat(asc)), R.Str);
                }
            }
            foreach (var a in si.UnsignedAttributes)
            {
                string oid = a.Oid.Value;
                if (oid == "1.3.6.1.4.1.311.3.3.1")
                {
                    if (Rfc3161TimestampToken.TryDecode(a.Values[0].RawData, out var tok, out _))
                    {
                        d.KV("    RFC 3161 timestamp", Fmt.Time(tok.TokenInfo.Timestamp.UtcDateTime), R.Good);
                        var tsc = tok.AsSignedCms().SignerInfos.Count > 0 ? tok.AsSignedCms().SignerInfos[0].Certificate : null;
                        if (tsc != null) d.KV("    Timestamp authority", tsc.Subject, R.Str);
                    }
                }
                else if (oid == "1.3.6.1.4.1.311.2.4.1" && depth < 4)
                {
                    foreach (var v in a.Values) { try { Dump(v.RawData, d, ctx, depth + 1); } catch { } }
                }
                else if (oid == "1.2.840.113549.1.9.6") d.KV("    Countersignature", "legacy PKCS#9 countersignature present", R.Value);
            }
            foreach (var cs in si.CounterSignerInfos)
            {
                d.KV("    Countersigner", cs.Certificate?.Subject ?? "?", R.Str);
                foreach (var a in cs.SignedAttributes)
                    if (a.Oid.Value == "1.2.840.113549.1.9.5") d.KV("    Countersign time", Fmt.Time(new Pkcs9SigningTime(a.Values[0].RawData).SigningTime.ToUniversalTime()), R.Good);
            }
        }
        d.H(pre + $"Certificates in signature ({cms.Certificates.Count})");
        int i2 = 0;
        foreach (var c in cms.Certificates)
        {
            d.Sub($"Certificate {++i2}");
            CertParser.Describe(c, d, "  ");
        }
    }
}
