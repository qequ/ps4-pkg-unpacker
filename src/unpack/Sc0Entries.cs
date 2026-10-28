using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using LibOrbisPkg.PKG;
using LibOrbisPkg.Util;
using Microsoft.Win32.SafeHandles;

namespace PkgUnpack
{
  /// <summary>One record of the PKG entry table ("Sc0"): a file stored outside the PFS image.</summary>
  internal sealed class Sc0Entry
  {
    public MetaEntry Meta;
    public byte[] Record;  // raw 32-byte table record; it is an input to the entry key
    public string Name;    // "param.sfo", "trophy/trophy01.trp", "npbind.dat", ...

    // Encrypted entries are stored padded to the AES block; DataSize is the plain length.
    public long StoredSize => Meta.Encrypted ? (Meta.DataSize + 15L) & ~15L : Meta.DataSize;
  }

  /// <summary>
  /// The PKG entry table: param.sfo, icons, trophies, npbind.dat, license.dat, ...
  ///
  /// Matches what PS4 PKG Tool's engine (OrbisPkgTool's PkgReader) extracts as Sc0: every
  /// entry except the table's own bookkeeping (digests, keys, metas, names). Names come from
  /// the ENTRY_NAMES blob, else from LibOrbisPkg's id-to-name map (license.dat, npbind.dat,
  /// ... have no name in the blob).
  ///
  /// Encrypted entries are AES-128-CBC over the 16-byte-padded data, with
  /// IV || key = SHA-256(record || dk[keyIndex]) and dk derived from the passcode. A fake PKG
  /// uses 32 zeros. LibOrbisPkg's Entry.Decrypt cannot be used: it decrypts DataSize bytes,
  /// and throws on npbind.dat (0x514 bytes, not a whole number of AES blocks).
  /// </summary>
  internal static class Sc0
  {
    public const string FakePasscode = "00000000000000000000000000000000";

    static readonly HashSet<EntryId> Bookkeeping = new HashSet<EntryId>
    {
      EntryId.DIGESTS, EntryId.ENTRY_KEYS, EntryId.IMAGE_KEY,
      EntryId.GENERAL_DIGESTS, EntryId.METAS, EntryId.ENTRY_NAMES,
    };

    public static List<Sc0Entry> List(Pkg pkg, SafeFileHandle file)
    {
      var table = new byte[pkg.Header.entry_count * 32];
      FileWindowReader.ReadExactly(file, pkg.Header.entry_table_offset, table, 0, table.Length);
      var list = new List<Sc0Entry>();
      for (int i = 0; i < pkg.Header.entry_count; i++)
      {
        var meta = pkg.Metas.Metas[i];
        if (Bookkeeping.Contains(meta.id)) continue;
        var record = new byte[32];
        Buffer.BlockCopy(table, i * 32, record, 0, record.Length);
        list.Add(new Sc0Entry { Meta = meta, Record = record, Name = NameOf(pkg, meta) });
      }
      return list;
    }

    static string NameOf(Pkg pkg, MetaEntry meta)
    {
      // Offset 0 of the name blob is the empty string, i.e. "no name".
      string name = meta.NameTableOffset != 0 ? pkg.EntryNames?.GetName(meta.NameTableOffset) : null;
      string known;
      if (string.IsNullOrEmpty(name) && EntryNames.IdToName.TryGetValue(meta.id, out known)) name = known;
      if (string.IsNullOrEmpty(name) || !Paths.IsSafeRelative(name)) name = $"entry_{(uint)meta.id:X4}.bin";
      return name;
    }

    /// <summary>The seven entry keys for a passcode; null where the PKG's ENTRY_KEYS digest rejects one.</summary>
    public static byte[][] DeriveKeys(Pkg pkg, string passcode)
    {
      var keys = new byte[7][];
      if (pkg.EntryKeys == null) return keys;
      for (uint i = 0; i < keys.Length; i++)
      {
        var dk = Crypto.ComputeKeys(pkg.Header.content_id, passcode, i);
        if (pkg.CheckDerivedKey(dk, (int)i)) keys[i] = dk;
      }
      return keys;
    }

    public static byte[] Read(SafeFileHandle file, Sc0Entry e, byte[][] keys)
    {
      var data = new byte[e.StoredSize];
      FileWindowReader.ReadExactly(file, e.Meta.DataOffset, data, 0, data.Length);
      if (!e.Meta.Encrypted) return data;

      var dk = e.Meta.KeyIndex < keys.Length ? keys[e.Meta.KeyIndex] : null;
      if (dk == null)
        throw new InvalidDataException($"entry key {e.Meta.KeyIndex} is not available (wrong passcode, or a retail PKG)");
      var ivKey = SHA256.HashData(e.Record.Concat(dk).ToArray());
      byte[] plain;
      using (var aes = Aes.Create())
      {
        aes.Key = ivKey.Skip(16).Take(16).ToArray();
        plain = aes.DecryptCbc(data, ivKey.Take(16).ToArray(), PaddingMode.None);
      }
      Array.Resize(ref plain, (int)e.Meta.DataSize);
      return plain;
    }
  }
}
