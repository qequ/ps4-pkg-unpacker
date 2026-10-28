using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace PkgEntries
{
  /// <summary>
  /// Standalone PKG entry-table dumper. The 0x20-byte record is the same as LibOrbisPkg's
  /// MetaEntry and OrbisPkgTool's PkgEntry:
  ///
  ///   0x00 u32 BE  EntryId
  ///   0x04 u32 BE  NameTableOffset   (byte offset into the ENTRY_NAMES blob)
  ///   0x08 u32 BE  Flags1            (bit 31 = encrypted)
  ///   0x0C u32 BE  Flags2            (bits 12-15 = encryption key index)
  ///   0x10 u32 BE  DataOffset        (absolute file offset)
  ///   0x14 u32 BE  DataSize
  ///   0x18 8 bytes padding (zero in every record of CUSA02343)
  ///
  /// It writes entry data as stored, i.e. still encrypted for license.dat, npbind.dat, ...
  /// PkgUnpack extracts and decrypts the whole table; use that for a game dump.
  /// </summary>
  public static class Program
  {
    const uint MAGIC = 0x7F434E54;

    static uint BE32(byte[] b, int o) => (uint)((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]);
    static ulong BE64(byte[] b, int o) { ulong v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | b[o + i]; return v; }

    static string Magic(byte[] b)
    {
      if (b.Length < 4) return "";
      var s = Encoding.ASCII.GetString(b, 0, 4);
      bool printable = s.All(c => c >= 0x20 && c < 0x7F);
      return printable ? $"'{s}'" : $"0x{BitConverter.ToString(b, 0, 4).Replace("-", "")}";
    }

    public static int Main(string[] argv)
    {
      if (argv.Length < 1) { Console.Error.WriteLine("usage: PkgEntries <input.pkg> [outdir]"); return 2; }
      var pkgPath = argv[0];
      var outDir = argv.Length > 1 ? argv[1] : null;

      using (var fs = File.Open(pkgPath, FileMode.Open, FileAccess.Read, FileShare.Read))
      {
        var h = new byte[0x1000];
        int hg = 0; while (hg < h.Length) { int r = fs.Read(h, hg, h.Length - hg); if (r <= 0) break; hg += r; }
        if (BE32(h, 0) != MAGIC) { Console.Error.WriteLine("not a PKG (bad CNT magic)"); return 3; }

        uint entryCount = BE32(h, 0x10);
        uint tableOff   = BE32(h, 0x18);
        ulong bodyOff   = BE64(h, 0x20);
        ulong bodySize  = BE64(h, 0x28);
        string contentId = Encoding.ASCII.GetString(h, 0x40, 0x30).TrimEnd('\0');

        Console.WriteLine($"content_id   : {contentId}");
        Console.WriteLine($"entry_count  : {entryCount}");
        Console.WriteLine($"table_offset : 0x{tableOff:X}");
        Console.WriteLine($"body         : offset 0x{bodyOff:X}  size {bodySize}");
        Console.WriteLine();

        // entry table
        fs.Position = tableOff;
        var tbl = new byte[entryCount * 0x20];
        int g = 0; while (g < tbl.Length) { int r = fs.Read(tbl, g, tbl.Length - g); if (r <= 0) break; g += r; }

        var recs = new List<(uint id, uint nameOff, uint dataOff, uint dataSize, uint flags1, uint flags2)>();
        for (int i = 0; i < entryCount; i++)
        {
          int o = i * 0x20;
          recs.Add((BE32(tbl, o), BE32(tbl, o + 4), BE32(tbl, o + 0x10), BE32(tbl, o + 0x14),
                    BE32(tbl, o + 0x08), BE32(tbl, o + 0x0C)));
        }

        // name table (ENTRY_NAMES, id 0x200)
        // NOTE: the blob begins with an empty string (offset 0 == ""), so empties must be
        // kept in the list or every subsequent offset shifts by one.
        var names = new List<string>();
        var nr = recs.FirstOrDefault(r => r.id == 0x200);
        if (nr.dataSize > 0)
        {
          fs.Position = nr.dataOff;
          var nb = new byte[nr.dataSize];
          int gg = 0; while (gg < nb.Length) { int r = fs.Read(nb, gg, nb.Length - gg); if (r <= 0) break; gg += r; }
          int s = 0;
          while (s < nb.Length)
          {
            int e = s; while (e < nb.Length && nb[e] != 0) e++;
            names.Add(Encoding.ASCII.GetString(nb, s, e - s));
            s = e + 1;
          }
        }
        string NameAt(uint off)
        {
          int s = 0;
          foreach (var n in names) { if (s == off) return n; s += n.Length + 1; }
          return "";
        }

        Console.WriteLine("idx  entryId     dataOffset   dataSize     fl1        fl2    key  name");
        Console.WriteLine("---  ----------  -----------  -----------  ---------  -----  ---  ----------------------");
        foreach (var (r, i) in recs.Select((r, i) => (r, i)))
        {
          uint key = (r.flags2 >> 12) & 0xF;
          Console.WriteLine($"{i,3}  0x{r.id:X8}  0x{r.dataOff,-9:X}  0x{r.dataSize,-9:X}  0x{r.flags1:X8} 0x{r.flags2:X4} {key,4}  {NameAt(r.nameOff)}");
        }

        if (outDir != null)
        {
          Directory.CreateDirectory(outDir);
          Console.WriteLine();
          Console.WriteLine("=== extracted (unencrypted, named) ===");
          foreach (var r in recs)
          {
            var name = NameAt(r.nameOff);
            if (string.IsNullOrEmpty(name) || r.dataSize == 0) continue;
            if ((r.flags1 & 0x80000000) != 0)
            {
              Console.WriteLine($"SKIP encrypted: {name} (key {(r.flags2 >> 12) & 0xF}; PkgUnpack decrypts it)");
              continue;
            }
            if ((r.dataSize == 0xFFFFFFFF) || ((ulong)r.dataOff + r.dataSize > (ulong)fs.Length))
            {
              Console.WriteLine($"SKIP out-of-range: {name} off=0x{r.dataOff:X} size=0x{r.dataSize:X}");
              continue;
            }

            var dest = Path.Combine(outDir, name.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(dest));
            fs.Position = r.dataOff;
            var buf = new byte[r.dataSize];
            int g2 = 0; while (g2 < buf.Length) { int rr = fs.Read(buf, g2, buf.Length - g2); if (rr <= 0) break; g2 += rr; }
            File.WriteAllBytes(dest, buf);
            Console.WriteLine($"{name,-32} {buf.Length,10} bytes   {Magic(buf)}");
          }
        }
      }
      return 0;
    }
  }
}
