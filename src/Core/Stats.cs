using System.Security.Cryptography;

namespace Ufi.Core;

/// <summary>Results of the full streaming pass (hashes + byte statistics).</summary>
public sealed class StreamStats
{
    public readonly long[] Hist = new long[256];
    public long Total;
    public int BlockSize;
    public List<double> Blocks = new();
    public double Entropy, Chi, Mean, Serial, Pi;
    public int Unique;
    public long RunLen; public byte RunByte; public long RunOff;
    public long Lf, Cr, CrLf;
    public List<(string Name, string Hex)> Hashes = new();

    public static double EntropyOf(ReadOnlySpan<long> hist, long total)
    {
        if (total <= 0) return 0;
        double e = 0;
        foreach (long c in hist) if (c > 0) { double p = (double)c / total; e -= p * Math.Log2(p); }
        return e;
    }

    public static double EntropyOf(ReadOnlySpan<byte> data)
    {
        Span<long> h = stackalloc long[256];
        foreach (byte b in data) h[b]++;
        return EntropyOf(h, data.Length);
    }

    /// <summary>Entropy of a file range, read in chunks (capped).</summary>
    public static double EntropyOf(ByteSource s, long off, long len, long cap = 64L << 20)
    {
        len = Math.Min(Math.Min(len, cap), s.Length - off);
        if (len <= 0) return 0;
        var h = new long[256];
        var buf = new byte[1 << 20];
        long done = 0;
        while (done < len)
        {
            int n = s.ReadAt(off + done, buf.AsSpan(0, (int)Math.Min(buf.Length, len - done)));
            if (n <= 0) break;
            for (int i = 0; i < n; i++) h[buf[i]]++;
            done += n;
        }
        return EntropyOf(h, done);
    }

    public static string Verdict(double e) => e switch
    {
        < 0.5 => "almost uniform (padding / zero-filled)",
        < 3.5 => "low (sparse or repetitive data)",
        < 5.0 => "typical text / markup",
        < 6.5 => "typical code / structured binary",
        < 7.3 => "dense (compressed media or mixed data)",
        < 7.9 => "high (compressed data)",
        _ => "very high (encrypted, packed or random data)"
    };
}

public static class StatsRunner
{
    sealed class Crc32
    {
        static readonly uint[] T = Make();
        static uint[] Make()
        {
            var t = new uint[256];
            for (uint i = 0; i < 256; i++) { uint c = i; for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1; t[i] = c; }
            return t;
        }
        uint _c = 0xFFFFFFFF;
        public void Add(ReadOnlySpan<byte> b) { uint c = _c; foreach (byte x in b) c = T[(c ^ x) & 0xFF] ^ (c >> 8); _c = c; }
        public uint Value => _c ^ 0xFFFFFFFF;
        public static uint Of(ReadOnlySpan<byte> b) { var c = new Crc32(); c.Add(b); return c.Value; }
    }

    public static uint Crc(ReadOnlySpan<byte> b) => Crc32.Of(b);

    public static StreamStats Run(ByteSource s, CancellationToken ct, Action<int> progress)
    {
        var st = new StreamStats();
        long len = s.Length;
        st.BlockSize = 256;
        while (len / st.BlockSize > 1024) st.BlockSize *= 2;

        var algs = new List<(string, IncrementalHash)>
        {
            ("MD5", IncrementalHash.CreateHash(HashAlgorithmName.MD5)),
            ("SHA-1", IncrementalHash.CreateHash(HashAlgorithmName.SHA1)),
            ("SHA-256", IncrementalHash.CreateHash(HashAlgorithmName.SHA256)),
            ("SHA-384", IncrementalHash.CreateHash(HashAlgorithmName.SHA384)),
            ("SHA-512", IncrementalHash.CreateHash(HashAlgorithmName.SHA512)),
        };
        try
        {
            if (SHA3_256.IsSupported) algs.Add(("SHA3-256", IncrementalHash.CreateHash(HashAlgorithmName.SHA3_256)));
            if (SHA3_512.IsSupported) algs.Add(("SHA3-512", IncrementalHash.CreateHash(HashAlgorithmName.SHA3_512)));
        }
        catch { }
        var crc = new Crc32();
        var sums = new SumAcc();
        var dist = new DistAcc(st.BlockSize);
        var corr = new CorrAcc();

        var bufA = new byte[4 << 20];
        long off = 0;
        int lastPct = -1;
        while (off < len)
        {
            ct.ThrowIfCancellationRequested();
            int n = s.ReadAt(off, bufA);
            if (n <= 0) break;
            var chunk = new ReadOnlyMemory<byte>(bufA, 0, n);
            long baseOff = off;

            var actions = new List<Action>();
            foreach (var (_, h) in algs) { var hh = h; actions.Add(() => hh.AppendData(chunk.Span)); }
            actions.Add(() => { crc.Add(chunk.Span); sums.Add(chunk.Span); });
            actions.Add(() => dist.Add(chunk.Span, baseOff));
            actions.Add(() => corr.Add(chunk.Span));
            Parallel.Invoke(new ParallelOptions { CancellationToken = ct }, actions.ToArray());

            off += n;
            int pct = (int)(off * 100 / Math.Max(1, len));
            if (pct != lastPct) { progress?.Invoke(pct); lastPct = pct; }
        }
        dist.Finish(st);
        var hist = st.Hist;
        st.Total = off;
        st.Entropy = StreamStats.EntropyOf(hist, off);
        st.Unique = hist.Count(c => c > 0);
        double exp = off / 256.0, chi = 0, sum = 0;
        for (int i = 0; i < 256; i++) { double d = hist[i] - exp; chi += d * d / Math.Max(exp, 1e-9); sum += (double)i * hist[i]; }
        st.Chi = chi; st.Mean = off > 0 ? sum / off : 0;
        corr.Finish(st, off);

        st.Hashes.Add(("CRC-32", crc.Value.ToString("x8")));
        st.Hashes.Add(("Adler-32", ((sums.B << 16) | sums.A).ToString("x8")));
        st.Hashes.Add(("FNV-1a 64", sums.Fnv.ToString("x16")));
        foreach (var (name, h) in algs) { st.Hashes.Add((name, Convert.ToHexString(h.GetHashAndReset()).ToLowerInvariant())); h.Dispose(); }
        progress?.Invoke(100);
        return st;
    }

    // The accumulators copy their state into locals for the hot loops (captured/heap
    // variables cannot be kept in registers, which made the naive version ~10x slower).

    sealed class SumAcc
    {
        public uint A = 1, B;
        public ulong Fnv = 0xcbf29ce484222325;
        public void Add(ReadOnlySpan<byte> sp)
        {
            uint a = A, b = B; ulong f = Fnv;
            int i = 0;
            while (i < sp.Length)
            {
                int k = Math.Min(5552, sp.Length - i);
                var blk = sp.Slice(i, k);
                foreach (byte x in blk) { a += x; b += a; f ^= x; f *= 0x100000001b3; }
                a %= 65521; b %= 65521; i += k;
            }
            A = a; B = b; Fnv = f;
        }
    }

    sealed class DistAcc
    {
        readonly int _bs;
        readonly long[] _hist = new long[256];
        readonly int[] _bh = new int[256];
        int _bc;
        readonly List<double> _blocks = new();
        long _runLen, _bestLen, _runStart, _bestOff; int _runByte = -1, _bestByte;
        long _lf, _cr, _crlf; int _prev = -1;
        public DistAcc(int blockSize) { _bs = blockSize; }

        public void Add(ReadOnlySpan<byte> sp, long baseOff)
        {
            var hist = _hist; var bh = _bh; int bc = _bc, bs = _bs;
            long runLen = _runLen, bestLen = _bestLen, runStart = _runStart, bestOff = _bestOff; int runByte = _runByte, bestByte = _bestByte;
            long lf = _lf, cr = _cr, crlf = _crlf; int prev = _prev;
            for (int i = 0; i < sp.Length; i++)
            {
                byte c = sp[i];
                hist[c]++;
                bh[c]++;
                if (++bc == bs) { _blocks.Add(BlockEntropy(bh, bc)); Array.Clear(bh); bc = 0; }
                if (c == runByte) runLen++;
                else
                {
                    if (runLen > bestLen) { bestLen = runLen; bestByte = runByte; bestOff = runStart; }
                    runByte = c; runLen = 1; runStart = baseOff + i;
                }
                if (c == 10) { if (prev == 13) crlf++; else lf++; }
                else if (prev == 13) cr++;
                prev = c;
            }
            _bc = bc; _runLen = runLen; _bestLen = bestLen; _runStart = runStart; _bestOff = bestOff; _runByte = runByte; _bestByte = bestByte;
            _lf = lf; _cr = cr; _crlf = crlf; _prev = prev;
        }

        public void Finish(StreamStats st)
        {
            if (_prev == 13) _cr++;
            if (_runLen > _bestLen) { _bestLen = _runLen; _bestByte = _runByte; _bestOff = _runStart; }
            if (_bc > 0) _blocks.Add(BlockEntropy(_bh, _bc));
            Array.Copy(_hist, st.Hist, 256);
            st.Blocks = _blocks;
            st.RunLen = _bestLen; st.RunByte = (byte)Math.Max(0, _bestByte); st.RunOff = _bestOff;
            st.Lf = _lf; st.Cr = _cr; st.CrLf = _crlf;
        }
    }

    sealed class CorrAcc
    {
        double _t1, _t2, _t3, _last, _u0; bool _first = true;
        readonly byte[] _mc = new byte[6]; int _mcn; long _mcount, _inmont;

        public void Add(ReadOnlySpan<byte> sp)
        {
            double t1 = _t1, t2 = _t2, t3 = _t3, last = _last; long mcount = _mcount, inmont = _inmont; int mcn = _mcn;
            var mc = _mc;
            const double incirc = 16777215.0 * 16777215.0;
            int i = 0;
            if (_first && sp.Length > 0) { _first = false; _u0 = sp[0]; last = 0; t2 += sp[0]; t3 += (double)sp[0] * sp[0]; last = sp[0]; mc[mcn++] = sp[0]; i = 1; }
            for (; i < sp.Length; i++)
            {
                byte c = sp[i];
                t1 += last * c; t2 += c; t3 += (double)c * c; last = c;
                mc[mcn++] = c;
                if (mcn == 6)
                {
                    mcn = 0; mcount++;
                    double x = mc[0] * 65536.0 + mc[1] * 256.0 + mc[2];
                    double y = mc[3] * 65536.0 + mc[4] * 256.0 + mc[5];
                    if (x * x + y * y <= incirc) inmont++;
                }
            }
            _t1 = t1; _t2 = t2; _t3 = t3; _last = last; _mcount = mcount; _inmont = inmont; _mcn = mcn;
        }

        public void Finish(StreamStats st, long n)
        {
            double t1 = _t1 + _last * _u0, t2 = _t2 * _t2;
            double scc = n * _t3 - t2;
            st.Serial = scc == 0 ? double.NaN : (n * t1 - t2) / scc;
            st.Pi = _mcount > 0 ? 4.0 * _inmont / _mcount : double.NaN;
        }
    }

    static double BlockEntropy(int[] h, int n)
    {
        double e = 0;
        foreach (int c in h) if (c > 0) { double p = (double)c / n; e -= p * Math.Log2(p); }
        return e;
    }
}
