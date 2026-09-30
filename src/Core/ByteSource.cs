using System.Buffers.Binary;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Ufi.Core;

public sealed class EndOfDataException : Exception
{
    public EndOfDataException(long off) : base($"read past end of data at offset 0x{off:X}") { }
}

/// <summary>
/// Thread-safe, read-only random access to a file. The file is opened with FileAccess.Read only and is
/// never executed, mapped as an image, or handed to any shell handler.
/// </summary>
public sealed class ByteSource : IDisposable
{
    const int PageBits = 16, PageSize = 1 << PageBits, MaxPages = 256;
    readonly SafeFileHandle _h;
    readonly Dictionary<long, byte[]> _pages = new();
    readonly LinkedList<long> _lru = new();
    readonly object _gate = new();
    public readonly long Length;
    public readonly string FilePath;

    public ByteSource(string path)
    {
        FilePath = path;
        _h = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, FileOptions.RandomAccess);
        Length = RandomAccess.GetLength(_h);
    }

    public void Dispose() => _h.Dispose();

    /// <summary>Uncached read (for streaming). Returns bytes read.</summary>
    public int ReadAt(long off, Span<byte> dst)
    {
        if (off >= Length || off < 0) return 0;
        int total = 0;
        while (total < dst.Length)
        {
            int n = RandomAccess.Read(_h, dst[total..], off + total);
            if (n <= 0) break;
            total += n;
        }
        return total;
    }

    byte[] Page(long idx)
    {
        lock (_gate)
        {
            if (_pages.TryGetValue(idx, out var p)) return p;
        }
        long off = idx << PageBits;
        int len = (int)Math.Min(PageSize, Length - off);
        var buf = new byte[Math.Max(len, 0)];
        ReadAt(off, buf);
        lock (_gate)
        {
            if (_pages.TryAdd(idx, buf))
            {
                _lru.AddLast(idx);
                if (_lru.Count > MaxPages) { _pages.Remove(_lru.First.Value); _lru.RemoveFirst(); }
            }
        }
        return buf;
    }

    /// <summary>Cached copy of up to dst.Length bytes. Returns count copied (clamped at EOF).</summary>
    public int Copy(long off, Span<byte> dst)
    {
        if (off < 0 || off >= Length) return 0;
        int want = (int)Math.Min(dst.Length, Length - off);
        if (want > 4 * PageSize) return ReadAt(off, dst[..want]);
        int done = 0;
        while (done < want)
        {
            long o = off + done;
            var p = Page(o >> PageBits);
            int po = (int)(o & (PageSize - 1));
            int n = Math.Min(want - done, p.Length - po);
            if (n <= 0) break;
            p.AsSpan(po, n).CopyTo(dst[done..]);
            done += n;
        }
        return done;
    }

    public byte[] Bytes(long off, long count)
    {
        if (off < 0 || off >= Length || count <= 0) return Array.Empty<byte>();
        int n = (int)Math.Min(Math.Min(count, Length - off), int.MaxValue / 2);
        var b = new byte[n];
        int got = Copy(off, b);
        if (got < n) Array.Resize(ref b, got);
        return b;
    }

    void Need(long off, int n)
    {
        if (off < 0 || off + n > Length) throw new EndOfDataException(off);
    }

    public bool Has(long off, long n) => off >= 0 && n >= 0 && off + n <= Length;

    public byte U8(long o) { Need(o, 1); return Page(o >> PageBits)[o & (PageSize - 1)]; }

    public ushort U16(long o, bool be = false)
    {
        Need(o, 2); Span<byte> b = stackalloc byte[2]; Copy(o, b);
        return be ? BinaryPrimitives.ReadUInt16BigEndian(b) : BinaryPrimitives.ReadUInt16LittleEndian(b);
    }

    public uint U24(long o, bool be = false)
    {
        Need(o, 3); Span<byte> b = stackalloc byte[3]; Copy(o, b);
        return be ? (uint)(b[0] << 16 | b[1] << 8 | b[2]) : (uint)(b[2] << 16 | b[1] << 8 | b[0]);
    }

    public uint U32(long o, bool be = false)
    {
        Need(o, 4); Span<byte> b = stackalloc byte[4]; Copy(o, b);
        return be ? BinaryPrimitives.ReadUInt32BigEndian(b) : BinaryPrimitives.ReadUInt32LittleEndian(b);
    }

    public ulong U64(long o, bool be = false)
    {
        Need(o, 8); Span<byte> b = stackalloc byte[8]; Copy(o, b);
        return be ? BinaryPrimitives.ReadUInt64BigEndian(b) : BinaryPrimitives.ReadUInt64LittleEndian(b);
    }

    public int I32(long o, bool be = false) => unchecked((int)U32(o, be));
    public long I64(long o, bool be = false) => unchecked((long)U64(o, be));

    public bool Match(long o, ReadOnlySpan<byte> sig)
    {
        if (!Has(o, sig.Length)) return false;
        Span<byte> b = sig.Length <= 256 ? stackalloc byte[sig.Length] : new byte[sig.Length];
        Copy(o, b);
        return b.SequenceEqual(sig);
    }

    public bool Match(long o, string ascii) => Match(o, Encoding.Latin1.GetBytes(ascii));

    /// <summary>Null-terminated 8-bit string (Latin-1), at most max bytes.</summary>
    public string Ascii(long o, int max)
    {
        var b = Bytes(o, max);
        int z = Array.IndexOf(b, (byte)0);
        return Encoding.Latin1.GetString(b, 0, z < 0 ? b.Length : z);
    }

    public string Utf8Z(long o, int max)
    {
        var b = Bytes(o, max);
        int z = Array.IndexOf(b, (byte)0);
        return Encoding.UTF8.GetString(b, 0, z < 0 ? b.Length : z);
    }

    /// <summary>Fixed-length string with trailing NULs/spaces trimmed.</summary>
    public string Fixed(long o, int n) => Encoding.Latin1.GetString(Bytes(o, n)).TrimEnd('\0', ' ');

    public string Utf16Z(long o, int maxChars, bool be = false)
    {
        var b = Bytes(o, maxChars * 2L);
        int n = 0;
        while (n + 1 < b.Length && (b[n] | b[n + 1]) != 0) n += 2;
        return (be ? Encoding.BigEndianUnicode : Encoding.Unicode).GetString(b, 0, n);
    }

    public string Utf16(long o, int chars, bool be = false) =>
        (be ? Encoding.BigEndianUnicode : Encoding.Unicode).GetString(Bytes(o, chars * 2L)).TrimEnd('\0');

    /// <summary>Returns a read-only Stream view of [off, off+len).</summary>
    public Stream OpenStream(long off = 0, long len = -1) => new SourceStream(this, off, len < 0 ? Length - off : len);

    sealed class SourceStream : Stream
    {
        readonly ByteSource _s; readonly long _start, _len; long _pos;
        public SourceStream(ByteSource s, long start, long len) { _s = s; _start = start; _len = Math.Max(0, Math.Min(len, s.Length - start)); }
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => _len;
        public override long Position { get => _pos; set => _pos = Math.Clamp(value, 0, _len); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            long rem = _len - _pos;
            if (rem <= 0) return 0;
            int n = (int)Math.Min(buffer.Length, rem);
            n = _s.ReadAt(_start + _pos, buffer[..n]);
            _pos += n;
            return n;
        }
        public override long Seek(long offset, SeekOrigin origin)
        {
            Position = origin switch { SeekOrigin.Begin => offset, SeekOrigin.Current => _pos + offset, _ => _len + offset };
            return _pos;
        }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

/// <summary>Sequential cursor over a ByteSource.</summary>
public sealed class Cur
{
    public readonly ByteSource S;
    public long P;
    public bool BE;
    public Cur(ByteSource s, long p, bool be = false) { S = s; P = p; BE = be; }
    public byte U8() => S.U8(P++);
    public ushort U16() { var v = S.U16(P, BE); P += 2; return v; }
    public uint U32() { var v = S.U32(P, BE); P += 4; return v; }
    public ulong U64() { var v = S.U64(P, BE); P += 8; return v; }
    public int I32() => unchecked((int)U32());
    public byte[] Bytes(int n) { var b = S.Bytes(P, n); if (b.Length < n) throw new EndOfDataException(P); P += n; return b; }
    public void Skip(long n) => P += n;
    public ulong Leb()
    {
        ulong result = 0; int shift = 0;
        while (true)
        {
            byte b = U8();
            result |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0 || shift > 63) return result;
            shift += 7;
        }
    }
}
