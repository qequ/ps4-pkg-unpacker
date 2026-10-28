using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace PkgUnpack
{
  /// <summary>
  /// Shared read cache over the package file: 8 MiB aligned chunks, least-recently-used
  /// eviction, and two chunks of read-ahead past every chunk that is read.
  ///
  /// The source here is a USB hard disk (~62 MB/s sequential). Fetching each file's bytes on
  /// demand meant small synchronous reads, threads seeking against each other, and an idle
  /// disk whenever a thread was busy inflating: 21-32 MB/s from the disk. Large aligned reads
  /// issued ahead of the workers keep it streaming instead.
  ///
  /// Thread-safe. Used for file data only; the scattered metadata reads that build the
  /// directory tree go straight to the file.
  /// </summary>
  internal sealed class ChunkCache
  {
    public const int ChunkSize = 8 << 20;
    const int ReadAhead = 2;

    readonly SafeFileHandle _file;
    readonly long _length;
    readonly int _capacity;
    readonly object _gate = new object();
    readonly Dictionary<long, Entry> _chunks = new Dictionary<long, Entry>();
    long _clock;
    long _bytesLoaded;

    sealed class Entry
    {
      public Task<byte[]> Data;
      public long LastUse;
    }

    public ChunkCache(SafeFileHandle file, int capacityChunks)
    {
      _file = file;
      _length = RandomAccess.GetLength(file);
      _capacity = Math.Max(capacityChunks, ReadAhead + 2);
    }

    /// <summary>Bytes read from the file so far.</summary>
    public long BytesLoaded => Interlocked.Read(ref _bytesLoaded);

    public void Read(long at, byte[] buf, int offset, int count)
    {
      while (count > 0)
      {
        long k = at / ChunkSize;
        Task<byte[]> pending;
        lock (_gate)
        {
          pending = Touch(k, true);
          for (int i = 1; i <= ReadAhead; i++) Touch(k + i, false);
        }
        if (pending == null) throw new EndOfStreamException($"unexpected end of file at 0x{at:X}");

        byte[] chunk;
        try
        {
          chunk = pending.GetAwaiter().GetResult();
        }
        catch
        {
          lock (_gate) _chunks.Remove(k); // let a later read retry it
          throw;
        }
        int inChunk = (int)(at - k * ChunkSize);
        int n = Math.Min(count, chunk.Length - inChunk);
        if (n <= 0) throw new EndOfStreamException($"unexpected end of file at 0x{at:X}");
        Buffer.BlockCopy(chunk, inChunk, buf, offset, n);
        at += n;
        offset += n;
        count -= n;
      }
    }

    /// <summary>Returns chunk k, starting its load if needed. Caller holds _gate.</summary>
    Task<byte[]> Touch(long k, bool use)
    {
      if (k * ChunkSize >= _length) return null;
      Entry e;
      if (!_chunks.TryGetValue(k, out e))
      {
        e = new Entry { Data = LoadAsync(k), LastUse = ++_clock };
        _chunks[k] = e;
        Evict();
      }
      else if (use) e.LastUse = ++_clock;
      return e.Data;
    }

    /// <summary>Drops least-recently-used loaded chunks over capacity; never one still loading.</summary>
    void Evict()
    {
      while (_chunks.Count > _capacity)
      {
        long victim = -1, oldest = long.MaxValue;
        foreach (var kv in _chunks)
          if (kv.Value.Data.IsCompleted && kv.Value.LastUse < oldest)
          {
            oldest = kv.Value.LastUse;
            victim = kv.Key;
          }
        if (victim < 0) return;
        _chunks.Remove(victim);
      }
    }

    async Task<byte[]> LoadAsync(long k)
    {
      long start = k * ChunkSize;
      var data = new byte[(int)Math.Min(ChunkSize, _length - start)];
      int got = 0;
      while (got < data.Length)
      {
        int r = await RandomAccess.ReadAsync(_file, new Memory<byte>(data, got, data.Length - got), start + got)
          .ConfigureAwait(false);
        if (r <= 0) throw new EndOfStreamException($"unexpected end of file at 0x{start + got:X}");
        got += r;
      }
      Interlocked.Add(ref _bytesLoaded, data.Length);
      return data;
    }
  }
}
