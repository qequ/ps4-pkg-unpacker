using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using LibOrbisPkg.Util;

namespace PkgUnpack
{
  /// <summary>
  /// Header and block offset table of a PFSC container (pfs_image.dat, the compressed inner
  /// PFS image). Immutable, so one instance is shared by every per-thread reader.
  ///
  /// Layout, all fields little-endian:
  ///   0x00 u32  magic "PFSC" (0x43534650)
  ///   0x04 u32  zero
  ///   0x08 u32  version (2 in CUSA02343; LibOrbisPkg's writer uses 6)
  ///   0x0C u32  logical block size, 0x10000
  ///   0x10 u64  block size again, 0x10000
  ///   0x18 u64  offset table offset
  ///   0x20 u64  data offset
  ///   0x28 u64  logical length, a multiple of the block size
  ///
  /// The table holds blockCount + 1 u64 offsets; block i is stored in [off[i], off[i+1]).
  /// A block stored in exactly 0x10000 bytes is verbatim; a shorter one is a zlib stream
  /// (header 48 89, Adler-32 trailer) that inflates to exactly 0x10000 bytes.
  /// </summary>
  public sealed class PfscIndex
  {
    public const uint Magic = 0x43534650;
    public const int BlockSize = 0x10000;

    public int Version { get; private set; }
    public long TableOffset { get; private set; }
    public long DataOffset { get; private set; }
    public long LogicalLength { get; private set; }
    public int BlockCount { get; private set; }
    public int CompressedBlocks { get; private set; }
    /// <summary>Blocks whose stored size is not in (0, BlockSize]; reading them throws.</summary>
    public int InvalidBlocks { get; private set; }
    public long StoredEnd => Offsets[BlockCount];
    internal long[] Offsets { get; private set; }

    public static bool HasMagic(IMemoryReader src)
    {
      var b = new byte[4];
      src.Read(0, b, 0, b.Length);
      return BitConverter.ToUInt32(b, 0) == Magic;
    }

    public static PfscIndex Read(IMemoryReader src, long storedLength)
    {
      var h = new byte[0x30];
      src.Read(0, h, 0, h.Length);
      if (BitConverter.ToUInt32(h, 0x00) != Magic)
        throw new InvalidDataException("not a PFSC container (bad magic)");
      int blockSize = BitConverter.ToInt32(h, 0x0C);
      long mirror = BitConverter.ToInt64(h, 0x10);
      if (blockSize != BlockSize || mirror != BlockSize)
        throw new InvalidDataException($"unsupported PFSC block size 0x{blockSize:X} / 0x{mirror:X}");

      var ix = new PfscIndex
      {
        Version = BitConverter.ToInt32(h, 0x08),
        TableOffset = BitConverter.ToInt64(h, 0x18),
        DataOffset = BitConverter.ToInt64(h, 0x20),
        LogicalLength = BitConverter.ToInt64(h, 0x28),
      };
      if (ix.LogicalLength <= 0 || ix.LogicalLength % BlockSize != 0)
        throw new InvalidDataException($"PFSC logical length 0x{ix.LogicalLength:X} is not block aligned");
      long blocks = ix.LogicalLength / BlockSize;
      long tableBytes = (blocks + 1) * 8;
      if (tableBytes > int.MaxValue || ix.TableOffset < h.Length || ix.TableOffset + tableBytes > ix.DataOffset)
        throw new InvalidDataException("PFSC offset table overlaps the header or the data region");

      var raw = new byte[tableBytes];
      src.Read(ix.TableOffset, raw, 0, raw.Length);
      var offsets = new long[blocks + 1];
      for (int i = 0; i < offsets.Length; i++) offsets[i] = BitConverter.ToInt64(raw, i * 8);
      if (offsets[0] != ix.DataOffset)
        throw new InvalidDataException($"PFSC block 0 starts at 0x{offsets[0]:X}, not at the data offset 0x{ix.DataOffset:X}");
      if (offsets[blocks] > storedLength)
        throw new InvalidDataException($"PFSC blocks end at 0x{offsets[blocks]:X}, past the end of the container (0x{storedLength:X})");

      int compressed = 0, invalid = 0;
      for (int i = 0; i < blocks; i++)
      {
        long stored = offsets[i + 1] - offsets[i];
        if (stored <= 0 || stored > BlockSize) invalid++;
        else if (stored < BlockSize) compressed++;
      }
      ix.BlockCount = (int)blocks;
      ix.CompressedBlocks = compressed;
      ix.InvalidBlocks = invalid;
      ix.Offsets = offsets;
      return ix;
    }
  }

  /// <summary>
  /// Reads the logical (decompressed) bytes of a PFSC container; replaces LibOrbisPkg's
  /// PFSCReader.
  ///
  /// The upstream reader inflates each block with a single DeflateStream.Read call. Since
  /// .NET 6 that call may return only part of the block, and the rest of the reused buffer
  /// keeps the previous block's bytes. Nothing throws: on CUSA02343, 7 of the first 512
  /// blocks (the flat path table among them) come back silently wrong. Its 2-byte zlib
  /// header skip followed by raw deflate is fine; that is a valid way to read zlib data.
  ///
  /// This reader inflates until the block is complete and checks every compressed block
  /// against its Adler-32 trailer, so a wrong key, a misplaced read or a damaged package
  /// fails loudly instead of producing plausible-looking output.
  ///
  /// Not thread-safe (block cache, read window): one instance per thread over a shared
  /// <see cref="PfscIndex"/>.
  /// </summary>
  public sealed class PfscReaderFixed : IMemoryReader
  {
    const int BlockSize = PfscIndex.BlockSize;
    const int WindowSize = 4 << 20;

    readonly IMemoryReader _src;
    readonly PfscIndex _index;
    readonly long[] _map;
    readonly Dictionary<int, byte[]> _cache = new Dictionary<int, byte[]>();
    readonly Queue<int> _order = new Queue<int>();
    readonly int _cacheLimit;

    byte[] _window = new byte[0];
    long _windowStart, _windowEnd;   // stored-byte range currently held in _window
    int _readAheadEnd = -1;          // exclusive block index that fetches may extend to

    /// <summary>Compressed blocks inflated and Adler-32 checked by this instance.</summary>
    public long BlocksInflated { get; private set; }

    public PfscReaderFixed(IMemoryReader src, PfscIndex index, int cacheBlocks = 64)
    {
      _src = src;
      _index = index;
      _map = index.Offsets;
      _cacheLimit = Math.Max(4, cacheBlocks);
    }

    /// <summary>
    /// Declares that the logical range [pos, pos + len) is about to be read in order, so
    /// stored bytes are fetched up to 4 MiB at a time (never past the range). Without it
    /// each block is fetched on its own, which suits scattered metadata reads.
    /// </summary>
    public void SetReadAhead(long pos, long len)
    {
      _readAheadEnd = len > 0 ? (int)Math.Min((pos + len + BlockSize - 1) / BlockSize, _index.BlockCount) : -1;
    }

    public void Read(long pos, byte[] buf, int offset, int count)
    {
      if (pos < 0 || count < 0 || pos + count > _index.LogicalLength)
        throw new ArgumentOutOfRangeException(nameof(pos),
          $"read of 0x{count:X} bytes at 0x{pos:X} is outside the PFSC image (0x{_index.LogicalLength:X} bytes)");
      if (offset < 0 || offset + count > buf.Length) throw new ArgumentException("buffer too small");

      while (count > 0)
      {
        int idx = (int)(pos / BlockSize);
        int inBlock = (int)(pos % BlockSize);
        int n = Math.Min(BlockSize - inBlock, count);
        Buffer.BlockCopy(GetBlock(idx), inBlock, buf, offset, n);
        pos += n;
        offset += n;
        count -= n;
      }
    }

    byte[] GetBlock(int idx)
    {
      byte[] block;
      if (_cache.TryGetValue(idx, out block)) return block;

      long first = _map[idx];
      long stored = _map[idx + 1] - first;
      if (stored <= 0 || stored > BlockSize || (stored < BlockSize && stored < 6))
        throw new InvalidDataException($"PFSC block {idx}: stored size {stored} is out of range");
      int at = Fetch(idx, first, (int)stored);

      // Recycle the oldest cached block's array: one 64 KiB allocation per block adds up
      // to tens of GB of garbage over a full extraction.
      if (_order.Count >= _cacheLimit)
      {
        int oldest = _order.Dequeue();
        block = _cache[oldest];
        _cache.Remove(oldest);
      }
      else block = new byte[BlockSize];

      if (stored == BlockSize) Buffer.BlockCopy(_window, at, block, 0, BlockSize);
      else Inflate(idx, at, (int)stored, block);

      _cache[idx] = block;
      _order.Enqueue(idx);
      return block;
    }

    /// <summary>Makes stored bytes [first, first + len) available in the window; returns their index in it.</summary>
    int Fetch(int idx, long first, int len)
    {
      if (first >= _windowStart && first + len <= _windowEnd) return (int)(first - _windowStart);

      int endBlock = _readAheadEnd > idx ? _readAheadEnd : idx + 1;
      long end = Math.Min(_map[endBlock], first + Math.Max(len, WindowSize));
      end = Math.Max(end, first + len);
      int n = (int)(end - first);
      if (_window.Length < n) _window = new byte[Math.Max(n, BlockSize)];
      _src.Read(first, _window, 0, n);
      _windowStart = first;
      _windowEnd = end;
      return 0;
    }

    void Inflate(int idx, int at, int stored, byte[] block)
    {
      int total = 0;
      try
      {
        using (var input = new MemoryStream(_window, at, stored, false))
        using (var zlib = new ZLibStream(input, CompressionMode.Decompress))
        {
          int r;
          while (total < BlockSize && (r = zlib.Read(block, total, BlockSize - total)) > 0)
            total += r;
        }
      }
      catch (InvalidDataException ex)
      {
        throw new InvalidDataException(
          $"PFSC block {idx}: corrupt zlib data ({ex.Message}); {stored} bytes stored at 0x{_map[idx]:X}", ex);
      }
      if (total != BlockSize)
        throw new InvalidDataException($"PFSC block {idx}: inflated to {total} bytes instead of {BlockSize}");

      int t = at + stored - 4;
      uint expected = (uint)(_window[t] << 24 | _window[t + 1] << 16 | _window[t + 2] << 8 | _window[t + 3]);
      uint actual = Adler32(block);
      if (expected != actual)
        throw new InvalidDataException($"PFSC block {idx}: Adler-32 mismatch (trailer 0x{expected:X8}, data 0x{actual:X8})");
      BlocksInflated++;
    }

    static uint Adler32(byte[] data)
    {
      const uint Mod = 65521;
      uint a = 1, b = 0;
      int i = 0;
      while (i < data.Length)
      {
        int end = Math.Min(data.Length, i + 5552); // largest run before b can overflow
        for (; i < end; i++)
        {
          a += data[i];
          b += a;
        }
        a %= Mod;
        b %= Mod;
      }
      return (b << 16) | a;
    }

    public void Dispose() { }
  }
}
