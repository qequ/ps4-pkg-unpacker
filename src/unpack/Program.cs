using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LibOrbisPkg.PFS;
using LibOrbisPkg.PKG;

namespace PkgUnpack
{
  public static class Program
  {
    const string Usage = @"usage: PkgUnpack <input.pkg> <output_dir> [options]

  --list                 list every file instead of extracting
  --verify               read and check every file (Adler-32 of each compressed PFSC block);
                         writes nothing unless something fails
  --only <text>          only paths containing <text> (case-insensitive)
  --threads <n>          worker threads (default 4; files are read in on-disk order)
  --layout merged|raw    merged (default): PFS root -> <out>\, PKG entries -> <out>\sce_sys\
                         raw: <out>\Image0\ and <out>\Sc0\, like PS4 PKG Tool / orbis-pub-cmd
  --entries              only the PKG entry table (param.sfo, icons, trophies, npbind.dat, ...)
  --no-entries           skip the PKG entry table
  --passcode <32 chars>  passcode for encrypted entries (default: 32 zeros, the fake-PKG passcode)";

    sealed class Options
    {
      public string PkgPath, OutRoot, Only, Passcode = Sc0.FakePasscode;
      public int Threads = Math.Min(4, Environment.ProcessorCount);
      public bool List, Verify, EntriesOnly, NoEntries, Raw;

      public static Options Parse(string[] argv)
      {
        if (argv.Length < 2) return null;
        var o = new Options { PkgPath = argv[0], OutRoot = argv[1] };
        for (int i = 2; i < argv.Length; i++)
        {
          string a = argv[i];
          string value = i + 1 < argv.Length ? argv[i + 1] : null;
          if (a == "--list") o.List = true;
          else if (a == "--verify") o.Verify = true;
          else if (a == "--entries") o.EntriesOnly = true;
          else if (a == "--no-entries") o.NoEntries = true;
          else if (a == "--pfsc2") { } // old switch: the fixed PFSC reader is now the only one
          else if (a == "--only" && value != null) { o.Only = value; i++; }
          else if (a == "--threads" && int.TryParse(value, out o.Threads) && o.Threads > 0) i++;
          else if (a == "--layout" && (value == "merged" || value == "raw")) { o.Raw = value == "raw"; i++; }
          else if (a == "--passcode" && value != null && value.Length == 32) { o.Passcode = value; i++; }
          else
          {
            Console.Error.WriteLine($"bad option: {a}");
            return null;
          }
        }
        return o.EntriesOnly && o.NoEntries ? null : o;
      }
    }

    sealed class Target
    {
      public PfsReader.File File;  // a file in the PFS image, or
      public Sc0Entry Entry;       // a record of the PKG entry table
      public string Path;          // output path relative to the output root, '/'-separated
      public long Size;
      public long DiskOrder;       // position inside the PKG, so reads sweep forward
    }

    sealed class RunResult
    {
      public int Files;
      public long Bytes;
      public long BlocksInflated;
      public long DiskBytes;
      public double Seconds;
      public List<string> Errors = new List<string>();
    }

    static int Main(string[] argv)
    {
      Console.OutputEncoding = Encoding.UTF8;
      var o = Options.Parse(argv);
      if (o == null)
      {
        Console.Error.WriteLine(Usage);
        return 2;
      }
      try
      {
        return Run(o);
      }
      catch (Exception ex)
      {
        Console.Error.WriteLine($"FATAL: {ex.GetType().Name}: {ex.Message}");
        return 4;
      }
    }

    static int Run(Options o)
    {
      var sw = Stopwatch.StartNew();

      // ---------- 1. PKG header and entry table ----------
      Pkg pkg;
      using (var fs = File.Open(o.PkgPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        pkg = new PkgReader(fs).ReadPkg();

      // Asynchronous so ChunkCache's read-ahead is real overlapped I/O; the synchronous
      // RandomAccess reads used elsewhere work on such a handle too.
      using (var file = File.OpenHandle(o.PkgPath, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.Asynchronous))
      {
        Console.WriteLine($"PKG      : {o.PkgPath}");
        Console.WriteLine($"TITLE    : {pkg.ParamSfo?.ParamSfo?["TITLE"]}");
        Console.WriteLine($"CONTENT  : {pkg.Header.content_id}");
        Console.WriteLine($"entries  : {pkg.Header.entry_count}");
        Console.WriteLine($"pfs off  : 0x{pkg.Header.pfs_image_offset:X}   size: {pkg.Header.pfs_image_size}");

        var targets = new List<Target>();

        // ---------- 2. sce_sys metadata that lives in the entry table, outside the PFS ----------
        byte[][] keys = null;
        if (!o.NoEntries)
        {
          keys = Sc0.DeriveKeys(pkg, o.Passcode);
          int valid = keys.Count(k => k != null);
          Console.WriteLine($"passcode : {(valid == keys.Length ? "accepted" : $"only {valid}/{keys.Length} entry keys match; entries that need the others will fail")}");
          foreach (var e in Sc0.List(pkg, file))
            targets.Add(new Target
            {
              Entry = e, Path = (o.Raw ? "Sc0/" : "sce_sys/") + e.Name, Size = e.Meta.DataSize, DiskOrder = e.Meta.DataOffset,
            });
        }

        // ---------- 3. the PFS image: the game files ----------
        PkgImage img = null;
        if (!o.EntriesOnly)
        {
          var ekpfs = pkg.GetEkpfs();
          if (ekpfs == null)
          {
            Console.Error.WriteLine("FATAL: cannot recover EKPFS - this is a retail PKG and needs a passcode.");
            return 3;
          }
          Console.WriteLine($"EKPFS    : {BitConverter.ToString(ekpfs).Replace("-", "").ToLowerInvariant()}");

          img = PkgImage.Open(pkg, file, ekpfs);
          Console.WriteLine($"outer PFS: block=0x{img.Outer.Header.BlockSize:X} mode={img.Outer.Header.Mode}");
          if (img.Pfsc != null)
          {
            Console.WriteLine($"inner    : PFSC v{img.Pfsc.Version}, {img.InnerFile.size} bytes stored -> {img.Pfsc.LogicalLength} bytes, " +
                              $"{img.Pfsc.BlockCount} blocks ({img.Pfsc.CompressedBlocks} compressed)");
            if (img.Pfsc.InvalidBlocks > 0)
              Console.WriteLine($"WARNING  : {img.Pfsc.InvalidBlocks} PFSC blocks have an impossible stored size; files using them will fail");
          }
          else Console.WriteLine($"inner    : pfs_image.dat is not compressed ({img.InnerFile.size} bytes)");
          Console.WriteLine($"inner PFS: mode={img.InnerHeader.Mode} inodes={img.InnerHeader.DinodeCount}");

          string prefix = o.Raw ? "Image0/" : "";
          foreach (var f in img.Inner.GetAllFiles())
            targets.Add(new Target
            {
              File = f, Path = prefix + UrootRelative(f), Size = f.size,
              DiskOrder = f.blocks != null ? (long)f.blocks[0] * PkgImage.BlockSize : f.offset,
            });
        }

        // Merged layout: PFS files and entries share sce_sys\. The PFS copy wins (as in PS4 PKG Tool).
        if (!o.Raw)
        {
          var pfsPaths = new HashSet<string>(targets.Where(t => t.File != null).Select(t => t.Path), StringComparer.OrdinalIgnoreCase);
          foreach (var t in targets.Where(t => t.Entry != null && pfsPaths.Contains(t.Path)))
          {
            Console.WriteLine($"note     : {t.Path} is in both the PFS and the entry table; the entry goes to _sc0_conflicts/");
            t.Path = "_sc0_conflicts/" + t.Entry.Name;
          }
        }

        // The PFS is case-sensitive and NTFS is not: two paths that differ only in case would
        // overwrite each other. The first keeps its name, the others go to _case_conflicts/<n>/.
        var taken = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int clashes = 0;
        foreach (var t in targets)
        {
          if (taken.Add(t.Path)) continue;
          var moved = $"_case_conflicts/{++clashes}/{t.Path}";
          Console.WriteLine($"note     : {t.Path} differs from another path only in case; it goes to {moved}");
          t.Path = moved;
        }

        if (o.Only != null)
          targets = targets.Where(t => Contains(t.Path, o.Only) || (t.File != null && Contains(t.File.FullName, o.Only))).ToList();
        var entries = targets.Where(t => t.Entry != null).OrderBy(t => t.DiskOrder).ToList();
        var files = targets.Where(t => t.File != null).OrderBy(t => t.DiskOrder).ToList();
        Console.WriteLine($"files    : {files.Count} in the PFS ({GiB(files.Sum(t => t.Size))} GiB) + {entries.Count} PKG entries");
        Console.WriteLine();

        if (o.List)
        {
          foreach (var t in targets.OrderBy(t => t.Path, StringComparer.Ordinal))
            Console.WriteLine($"{t.Size,14}  {t.Path}{(t.Entry != null ? "   (pkg entry)" : "")}");
          return 0;
        }
        if (targets.Count == 0)
        {
          Console.Error.WriteLine("no files matched");
          return 5;
        }

        // ---------- 4a. verify: read everything, write nothing ----------
        if (o.Verify)
        {
          Console.WriteLine($"verifying {files.Count} file(s) with {o.Threads} thread(s); nothing is written");
          var failures = new List<string>();
          foreach (var t in entries)
          {
            try { Sc0.Read(file, t.Entry, keys); }
            catch (Exception ex) { failures.Add($"{t.Path}: {ex.GetType().Name}: {ex.Message}"); }
          }
          int badEntries = failures.Count;
          var r = ProcessFiles(img, files, o.Threads, null);
          failures.AddRange(r.Errors);
          Console.WriteLine();
          Console.WriteLine($"verified {r.Files}/{files.Count} files ({GiB(r.Bytes)} GiB) and {entries.Count - badEntries}/{entries.Count} " +
                            $"PKG entries in {sw.Elapsed:hh\\:mm\\:ss}");
          if (img?.Pfsc != null) Console.WriteLine($"compressed blocks inflated and Adler-32 checked: {r.BlocksInflated}");
          return Report(failures, o.OutRoot, "_verify_failures.txt", 7);
        }

        // ---------- 4b. extract ----------
        Directory.CreateDirectory(o.OutRoot);
        var errors = new List<string>();
        foreach (var t in entries)
        {
          try
          {
            var dest = Paths.Under(o.OutRoot, t.Path);
            Directory.CreateDirectory(Path.GetDirectoryName(dest));
            File.WriteAllBytes(dest, Sc0.Read(file, t.Entry, keys));
          }
          catch (Exception ex) { errors.Add($"{t.Path}: {ex.GetType().Name}: {ex.Message}"); }
        }
        if (entries.Count > 0) Console.WriteLine($"PKG entries: {entries.Count - errors.Count}/{entries.Count} written");

        if (img != null && files.Count > 0)
        {
          if (o.Only == null) CreateDirectories(img.Inner.GetURoot(), o.OutRoot, o.Raw ? "Image0/" : "", errors);
          Console.WriteLine($"extracting {files.Count} file(s) with {o.Threads} thread(s) -> {o.OutRoot}");
          Console.WriteLine();
          var r = ProcessFiles(img, files, o.Threads, o.OutRoot);
          errors.AddRange(r.Errors);
          Console.WriteLine();
          Console.WriteLine($"DONE in {sw.Elapsed:hh\\:mm\\:ss}   files={r.Files}/{files.Count}   {GiB(r.Bytes)} GiB   " +
                            $"({r.Bytes / Math.Max(1, r.Seconds) / 1e6:F0} MB/s)");
          if (img.Pfsc != null) Console.WriteLine($"compressed blocks inflated and Adler-32 checked: {r.BlocksInflated}");
          Console.WriteLine($"read from the package: {GiB(r.DiskBytes)} GiB ({r.DiskBytes / Math.Max(1, r.Seconds) / 1e6:F0} MB/s)");
        }
        return Report(errors, o.OutRoot, "_extract_errors.txt", 6);
      }
    }

    /// <summary>
    /// Reads every target through per-thread reader chains, in on-disk order, and writes it
    /// under <paramref name="outRoot"/> (or only reads it when outRoot is null).
    ///
    /// Each thread builds one chain, once (ThreadLocal), and reuses it for every file it
    /// takes. Files are handed out one at a time in package order and all chains read through
    /// one ChunkCache, so the (USB HDD) source is streamed front to back in large reads.
    /// </summary>
    static RunResult ProcessFiles(PkgImage img, List<Target> targets, int threads, string outRoot)
    {
      var result = new RunResult();
      if (targets.Count == 0) return result;

      long totalBytes = targets.Sum(t => t.Size);
      long readBytes = 0, okBytes = 0;
      int okFiles = 0;
      string current = "";
      var errors = new ConcurrentQueue<string>();
      var clock = Stopwatch.StartNew();
      var cache = new ChunkCache(img.File, 48);
      var chains = new ThreadLocal<ReaderChain>(() => new ReaderChain(img, cache), trackAllValues: true);

      TimerCallback progress = _ =>
      {
        long b = Interlocked.Read(ref readBytes);
        double rate = b / Math.Max(0.001, clock.Elapsed.TotalSeconds);
        var eta = TimeSpan.FromSeconds(rate > 0 ? (totalBytes - b) / rate : 0);
        Console.WriteLine($"  [{Volatile.Read(ref okFiles)}/{targets.Count}] {GiB(b)}/{GiB(totalBytes)} GiB  " +
                          $"{rate / 1e6:F0} MB/s  ETA {eta:hh\\:mm\\:ss}  {Volatile.Read(ref current)}");
      };

      using (new Timer(progress, null, 5000, 5000))
      {
        Parallel.ForEach(
          Partitioner.Create(targets, EnumerablePartitionerOptions.NoBuffering),
          new ParallelOptions { MaxDegreeOfParallelism = threads },
          t =>
          {
            Volatile.Write(ref current, t.Path);
            string dest = null, part = null;
            try
            {
              var chain = chains.Value;
              var view = chain.GetView(t.File);
              if (t.File.blocks == null) chain.Pfsc?.SetReadAhead(t.File.offset, t.Size);
              else chain.Pfsc?.SetReadAhead(0, 0);

              FileStream output = null;
              if (outRoot != null)
              {
                // Written under a temporary name and renamed when complete, so a failed or
                // interrupted file never sits there at full size looking finished.
                dest = Paths.Under(outRoot, t.Path);
                part = dest + ".part";
                Directory.CreateDirectory(Path.GetDirectoryName(dest));
                output = new FileStream(part, FileMode.Create, FileAccess.Write, FileShare.None, 1);
                output.SetLength(t.Size);
              }
              using (output)
              {
                var buf = chain.CopyBuffer;
                for (long pos = 0; pos < t.Size;)
                {
                  int n = (int)Math.Min(buf.Length, t.Size - pos);
                  view.Read(pos, buf, 0, n);
                  if (output != null) output.Write(buf, 0, n);
                  pos += n;
                  Interlocked.Add(ref readBytes, n);
                }
              }
              if (part != null) File.Move(part, dest, true);
              Interlocked.Increment(ref okFiles);
              Interlocked.Add(ref okBytes, t.Size);
            }
            catch (Exception ex)
            {
              errors.Enqueue($"{t.Path}: {ex.GetType().Name}: {ex.Message}");
              if (part != null)
              {
                try { File.Delete(part); } catch { }
              }
            }
          });
      }

      result.Seconds = clock.Elapsed.TotalSeconds;
      foreach (var c in chains.Values)
      {
        if (c.Pfsc != null) result.BlocksInflated += c.Pfsc.BlocksInflated;
        c.Dispose();
      }
      result.DiskBytes = cache.BytesLoaded;
      chains.Dispose();
      result.Files = okFiles;
      result.Bytes = okBytes;
      result.Errors.AddRange(errors.OrderBy(e => e, StringComparer.Ordinal));
      return result;
    }

    static void CreateDirectories(PfsReader.Dir dir, string outRoot, string prefix, List<string> errors)
    {
      foreach (var d in dir.children.OfType<PfsReader.Dir>())
      {
        string rel = prefix + d.name;
        try
        {
          Directory.CreateDirectory(Paths.Under(outRoot, rel));
        }
        catch (Exception ex)
        {
          errors.Add($"{rel}/: {ex.GetType().Name}: {ex.Message}");
          continue;
        }
        CreateDirectories(d, outRoot, rel + "/", errors);
      }
    }

    /// <summary>"/uroot/eboot.bin" -> "eboot.bin": the inner PFS's user root is the game root.</summary>
    static string UrootRelative(PfsReader.File f)
    {
      const string Root = "/uroot/";
      var full = f.FullName;
      if (!full.StartsWith(Root, StringComparison.Ordinal)) throw new InvalidDataException($"unexpected PFS path {full}");
      return full.Substring(Root.Length);
    }

    static int Report(List<string> failures, string outRoot, string fileName, int failCode)
    {
      if (failures.Count == 0)
      {
        Console.WriteLine("FAILURES: 0");
        return 0;
      }
      Console.Error.WriteLine($"FAILURES: {failures.Count}");
      foreach (var f in failures.Take(40)) Console.Error.WriteLine("  " + f);
      Directory.CreateDirectory(outRoot);
      var path = Path.Combine(outRoot, fileName);
      File.WriteAllLines(path, failures);
      Console.Error.WriteLine($"(full list written to {path})");
      return failCode;
    }

    static bool Contains(string s, string part) => s.IndexOf(part, StringComparison.OrdinalIgnoreCase) >= 0;

    static string GiB(long bytes) => (bytes / 1073741824.0).ToString("F2");
  }
}
