using System;
using System.Collections.Generic;
using LibOrbisPkg.Util;

namespace PkgUnpack
{
  /// <summary>
  /// Replacement for LibOrbisPkg's ChunkedMemoryReader (Util/MemoryMapped.cs), the view used
  /// for files whose blocks are not contiguous.
  ///
  /// Upstream reads:
  ///     reader.Read((long)chunks[chunkIdx++]*chunkSize + offsetIntoChunk, buf, offset, count);
  /// i.e. the whole remaining `count` from every chunk instead of only that chunk's share.
  /// Later iterations overwrite the surplus, so the bytes come out right, but a read that
  /// spans n chunks decrypts/decompresses O(n^2) data, and near the end of the image the
  /// surplus runs past the end and throws.
  ///
  /// This version reads exactly one chunk's share per step and validates the chunk index.
  /// (CUSA02343 has no non-contiguous files, so this path is not exercised by it.)
  /// </summary>
  internal sealed class FixedChunkedReader : IMemoryReader
  {
    readonly IMemoryReader _reader;
    readonly int _chunkSize;
    readonly int[] _chunks;

    public FixedChunkedReader(IMemoryReader reader, int chunkSize, int[] chunks)
    {
      _reader = reader;
      _chunkSize = chunkSize;
      _chunks = chunks;
    }

    public void Read(long pos, byte[] buf, int offset, int count)
    {
      if (pos < 0) throw new ArgumentOutOfRangeException(nameof(pos));
      if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
      if (offset < 0 || offset + count > buf.Length) throw new ArgumentException("buffer too small");

      while (count > 0)
      {
        long chunkIdx = pos / _chunkSize;
        if (chunkIdx < 0 || chunkIdx >= _chunks.Length)
          throw new InvalidOperationException(
            $"chunk index {chunkIdx} out of range ({_chunks.Length} chunks) at pos {pos}");

        int offsetIntoChunk = (int)(pos % _chunkSize);
        int toRead = Math.Min(_chunkSize - offsetIntoChunk, count);

        _reader.Read((long)_chunks[chunkIdx] * _chunkSize + offsetIntoChunk, buf, offset, toRead);

        pos += toRead;
        offset += toRead;
        count -= toRead;
      }
    }

    public void Dispose() { }
  }
}
