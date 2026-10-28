using System;
using System.IO;
using LibOrbisPkg.Util;
using Microsoft.Win32.SafeHandles;

namespace PkgUnpack
{
  /// <summary>
  /// Positional reads over a file handle, relative to a base offset. There is no shared
  /// stream position (RandomAccess is pread), so one handle can serve every thread, and
  /// a short read is retried until the request is complete.
  ///
  /// LibOrbisPkg's StreamReader seeks a shared Stream and accepts whatever a single Read
  /// call returns; this replaces it everywhere in PkgUnpack. With a <see cref="ChunkCache"/>
  /// the reads are served from the shared cache instead.
  /// </summary>
  internal sealed class FileWindowReader : IMemoryReader
  {
    readonly SafeFileHandle _file;
    readonly long _base;
    readonly ChunkCache _cache;

    public FileWindowReader(SafeFileHandle file, long baseOffset, ChunkCache cache = null)
    {
      _file = file;
      _base = baseOffset;
      _cache = cache;
    }

    public void Read(long pos, byte[] buf, int offset, int count)
    {
      if (_cache != null) _cache.Read(_base + pos, buf, offset, count);
      else ReadExactly(_file, _base + pos, buf, offset, count);
    }

    public static void ReadExactly(SafeFileHandle file, long at, byte[] buf, int offset, int count)
    {
      while (count > 0)
      {
        int r = RandomAccess.Read(file, new Span<byte>(buf, offset, count), at);
        if (r <= 0) throw new EndOfStreamException($"unexpected end of file at 0x{at:X}");
        at += r;
        offset += r;
        count -= r;
      }
    }

    public void Dispose() { }
  }
}
