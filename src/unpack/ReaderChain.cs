using System;
using System.IO;
using LibOrbisPkg.PFS;
using LibOrbisPkg.PKG;
using LibOrbisPkg.Util;
using Microsoft.Win32.SafeHandles;

namespace PkgUnpack
{
  /// <summary>
  /// The package's PFS layers, opened once:
  ///
  ///   PKG file --AES-XTS--> outer PFS --/uroot/pfs_image.dat--> PFSC container --inflate--> inner PFS
  ///
  /// Read-only after <see cref="Open"/>; every thread builds its own <see cref="ReaderChain"/>
  /// from it.
  /// </summary>
  internal sealed class PkgImage
  {
    public const int BlockSize = 0x10000;

    public SafeFileHandle File { get; private set; }
    public long PfsOffset { get; private set; }
    public PfsReader Outer { get; private set; }
    public PfsReader.File InnerFile { get; private set; }  // the outer PFS's pfs_image.dat
    public PfscIndex Pfsc { get; private set; }            // null when pfs_image.dat is not compressed
    public PfsHeader InnerHeader { get; private set; }
    public PfsReader Inner { get; private set; }           // the game's file tree

    byte[] _tweakKey, _dataKey;
    uint _xtsStartSector;
    ReaderChain _treeChain;                                // backs Inner's metadata reads

    public static PkgImage Open(Pkg pkg, SafeFileHandle file, byte[] ekpfs)
    {
      var img = new PkgImage { File = file, PfsOffset = (long)pkg.Header.pfs_image_offset };

      // LibOrbisPkg parses the outer PFS (a few metadata blocks) with its own XTS reader.
      img.Outer = new PfsReader(new FileWindowReader(file, img.PfsOffset), pkg.Header.pfs_flags, ekpfs, null, null);
      var oh = img.Outer.Header;
      if (oh.Mode.HasFlag(PfsMode.Encrypted))
      {
        var keys = Crypto.PfsGenEncKey(ekpfs, oh.Seed, (pkg.Header.pfs_flags & 0x2000000000000000UL) != 0);
        img._tweakKey = keys.Item1;
        img._dataKey = keys.Item2;
        img._xtsStartSector = oh.BlockSize / 0x1000;
      }
      img.InnerFile = img.Outer.GetFile("pfs_image.dat");
      if (img.InnerFile == null) throw new InvalidDataException("pfs_image.dat not found in the outer PFS");

      var dat = img.InnerFileView(img.OuterImage());
      if (PfscIndex.HasMagic(dat)) img.Pfsc = PfscIndex.Read(dat, img.InnerFile.size);

      img._treeChain = new ReaderChain(img);
      var hdr = new byte[0x400];
      img._treeChain.Image.Read(0, hdr, 0, hdr.Length);
      using (var ms = new MemoryStream(hdr)) img.InnerHeader = PfsHeader.ReadFromStream(ms);
      if (img.InnerHeader.Mode.HasFlag(PfsMode.Encrypted))
        throw new NotSupportedException("the inner PFS image is encrypted; only plain inner images are supported");
      img.Inner = new PfsReader(img._treeChain.Image);
      return img;
    }

    /// <summary>A fresh reader over the outer PFS image as plain bytes.</summary>
    internal IMemoryReader OuterImage(ChunkCache cache = null)
    {
      IMemoryReader r = new FileWindowReader(File, PfsOffset, cache);
      return _dataKey == null ? r : new XtsSectorReader(r, _dataKey, _tweakKey, _xtsStartSector);
    }

    /// <summary>pfs_image.dat's bytes within an outer image reader.</summary>
    internal IMemoryReader InnerFileView(IMemoryReader outer)
      => InnerFile.blocks != null
         ? (IMemoryReader)new FixedChunkedReader(outer, BlockSize, InnerFile.blocks)
         : new MemoryAccessor(outer, InnerFile.offset);
  }

  /// <summary>
  /// One thread's private reader stack over the package. XtsSectorReader and PfscReaderFixed
  /// keep per-instance buffers and caches, so a chain must never be shared between threads;
  /// the file handle and the ChunkCache underneath are safe to share.
  /// </summary>
  internal sealed class ReaderChain : IDisposable
  {
    readonly IMemoryReader _outer;

    /// <summary>The PFSC reader, or null when pfs_image.dat is stored uncompressed.</summary>
    public PfscReaderFixed Pfsc { get; }
    /// <summary>The inner PFS image as logical bytes.</summary>
    public IMemoryReader Image { get; }
    public byte[] CopyBuffer { get; } = new byte[1 << 20];

    public ReaderChain(PkgImage img, ChunkCache cache = null)
    {
      _outer = img.OuterImage(cache);
      var dat = img.InnerFileView(_outer);
      if (img.Pfsc != null)
      {
        Pfsc = new PfscReaderFixed(dat, img.Pfsc);
        Image = Pfsc;
      }
      else Image = dat;
    }

    /// <summary>The same mapping as PfsReader.File.GetView(), over this chain's readers.</summary>
    public IMemoryReader GetView(PfsReader.File f)
      => f.blocks != null
         ? (IMemoryReader)new FixedChunkedReader(Image, PkgImage.BlockSize, f.blocks)
         : new MemoryAccessor(Image, f.offset);

    public void Dispose() => _outer.Dispose();
  }
}
