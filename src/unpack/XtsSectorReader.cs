using System;
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using LibOrbisPkg.Util;

namespace PkgUnpack
{
  /// <summary>
  /// AES-XTS-128 decrypting reader for a PFS image: 0x1000-byte sectors, the sector index as a
  /// little-endian 128-bit tweak, and sectors below <c>startSector</c> (the header block) in
  /// the clear.
  ///
  /// Output is byte-identical to LibOrbisPkg's XtsDecryptReader (checked on 32 MiB of
  /// CUSA02343), but each sector is one AES call over 4 KiB with the 256 tweaks expanded up
  /// front, instead of one call per 16-byte block plus new transforms on every Read:
  /// 583 MB/s vs 108 MB/s per thread here.
  ///
  /// Not thread-safe (scratch buffers): one instance per thread.
  /// </summary>
  internal sealed class XtsSectorReader : IMemoryReader
  {
    const int SectorSize = 0x1000;

    readonly IMemoryReader _src;
    readonly long _startSector;
    readonly ICryptoTransform _dataDecryptor;
    readonly ICryptoTransform _tweakEncryptor;
    readonly byte[] _tweak = new byte[16];
    readonly byte[] _schedule = new byte[SectorSize];
    readonly byte[] _scratch = new byte[SectorSize];
    byte[] _buf = new byte[0x20000];

    public XtsSectorReader(IMemoryReader src, byte[] dataKey, byte[] tweakKey, uint startSector)
    {
      // The tweak schedule and the XOR passes reinterpret bytes as little-endian u64s.
      if (!BitConverter.IsLittleEndian) throw new PlatformNotSupportedException("little-endian host required");
      _src = src;
      _startSector = startSector;
      using (var data = Aes.Create())
      {
        data.Mode = CipherMode.ECB;
        data.Padding = PaddingMode.None;
        data.Key = dataKey;
        _dataDecryptor = data.CreateDecryptor();
      }
      using (var tweak = Aes.Create())
      {
        tweak.Mode = CipherMode.ECB;
        tweak.Padding = PaddingMode.None;
        tweak.Key = tweakKey;
        _tweakEncryptor = tweak.CreateEncryptor();
      }
    }

    public void Read(long pos, byte[] buf, int offset, int count)
    {
      if (count <= 0) return;
      long first = pos / SectorSize;
      long last = (pos + count - 1) / SectorSize;
      long span = (last - first + 1) * SectorSize;
      if (span > int.MaxValue) throw new ArgumentOutOfRangeException(nameof(count));
      if (_buf.Length < span) _buf = new byte[span];

      _src.Read(first * SectorSize, _buf, 0, (int)span);
      for (long s = Math.Max(first, _startSector); s <= last; s++)
        DecryptSector((int)((s - first) * SectorSize), (ulong)s);
      Buffer.BlockCopy(_buf, (int)(pos - first * SectorSize), buf, offset, count);
    }

    void DecryptSector(int off, ulong sector)
    {
      Array.Clear(_tweak, 0, _tweak.Length);
      BinaryPrimitives.WriteUInt64LittleEndian(_tweak, sector);
      _tweakEncryptor.TransformBlock(_tweak, 0, 16, _tweak, 0);

      // T(j+1) = T(j) * x in GF(2^128), little-endian byte order (0x87 folds into byte 0).
      ulong lo = BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(_tweak, 0, 8));
      ulong hi = BinaryPrimitives.ReadUInt64LittleEndian(new ReadOnlySpan<byte>(_tweak, 8, 8));
      var schedule = MemoryMarshal.Cast<byte, ulong>(new Span<byte>(_schedule));
      for (int j = 0; j < schedule.Length; j += 2)
      {
        schedule[j] = lo;
        schedule[j + 1] = hi;
        ulong carry = hi >> 63;
        hi = (hi << 1) | (lo >> 63);
        lo = (lo << 1) ^ (carry * 0x87UL);
      }

      // P = D(C ^ T) ^ T for all 256 blocks at once (ECB has no chaining).
      var data = MemoryMarshal.Cast<byte, ulong>(new Span<byte>(_buf, off, SectorSize));
      var scratch = MemoryMarshal.Cast<byte, ulong>(new Span<byte>(_scratch));
      for (int i = 0; i < scratch.Length; i++) scratch[i] = data[i] ^ schedule[i];
      _dataDecryptor.TransformBlock(_scratch, 0, SectorSize, _scratch, 0);
      for (int i = 0; i < scratch.Length; i++) data[i] = scratch[i] ^ schedule[i];
    }

    public void Dispose()
    {
      _dataDecryptor.Dispose();
      _tweakEncryptor.Dispose();
    }
  }
}
