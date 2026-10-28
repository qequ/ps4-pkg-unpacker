# PS4 PKG unpacker

`PkgUnpack` turns a PS4 fake PKG (fPKG) into a game dump: the files of the PFS image, plus the
PKG entry table (`sce_sys` metadata such as `param.sfo`, icons, trophies and `npbind.dat`),
decrypted and decompressed. Every compressed block is checked against its Adler-32 checksum.

It uses [LibOrbisPkg](https://github.com/maxton/LibOrbisPkg) (vendored in
`src\LibOrbisPkg-master\`, unmodified, LGPL-3.0) to parse the PKG and PFS structures. The data
path (XTS decryption, PFSC decompression, entry decryption, I/O) is in `src\unpack\`.

> Use it on packages of games you own. It works on fake PKGs, whose keys are known; a retail
> package's keys only exist on a console.

## Usage

Build it first ([Building](#building)), then:

```powershell
dotnet bin\PkgUnpack.dll game.pkg out                     # extract everything
dotnet bin\PkgUnpack.dll game.pkg out --list              # list files, write nothing
dotnet bin\PkgUnpack.dll game.pkg out --verify            # read + check everything, write nothing
dotnet bin\PkgUnpack.dll game.pkg out --only sce_module   # paths containing "sce_module"
dotnet bin\PkgUnpack.dll game.pkg out --entries           # only the entry table (sce_sys)
```

| Option | |
|---|---|
| `--list` | print every file (size and output path) |
| `--verify` | read every file and decrypt every entry without writing; failures go to `<out>\_verify_failures.txt` |
| `--only <text>` | only paths containing `<text>` (case-insensitive) |
| `--threads <n>` | worker threads, default 4 |
| `--layout merged\|raw` | `merged` (default): PFS root to `<out>\`, entries to `<out>\sce_sys\`. `raw`: `<out>\Image0\` and `<out>\Sc0\`, like PS4 PKG Tool and orbis-pub-cmd |
| `--entries` / `--no-entries` | only / skip the PKG entry table |
| `--passcode <32 chars>` | passcode for encrypted entries; default is 32 zeros, the fake-PKG passcode |

Files are written as `name.part` and renamed when complete, so an interrupted or failed file never
looks finished. Per-file errors are collected in `<out>\_extract_errors.txt` and the exit code is 6.

Nothing is overwritten silently: in the merged layout an entry that also exists in the PFS's `sce_sys\`
goes to `<out>\_sc0_conflicts\` (the PFS copy keeps its place), and package paths that differ only in
case, which are distinct in the PFS but the same file on NTFS, go to `<out>\_case_conflicts\<n>\`.
Neither happens with CUSA02343.

## Result for CUSA02343

The package of *Uncharted: The Nathan Drake Collection* (CUSA02343, version 1.00), extracted:

```
<out>\
├── eboot.bin  big2-ps4_Shipping.elf  big3-ps4_Shipping.elf  sce_discmap.plt
├── sce_module\     libc.prx  libSceFios2.prx
├── sce_sys\        from the PFS:         keystone  disc_info.dat  about\right.sprx
│                   from the entry table: param.sfo  icon0.png  icon0_00.png  pic0.png  pic1.png
│                                         icon0.dds  icon0_00.dds  pic0.dds  pic1.dds  snd0.at9
│                                         playgo-chunk.dat  playgo-chunk.sha  playgo-manifest.xml
│                                         pronunciation.xml  pronunciation.sig  shareparam.json
│                                         psreserved.dat  trophy\trophy01-03.trp
│                                         npbind.dat  nptitle.dat  license.dat  license.info  (decrypted)
├── shareddata\
├── u1data\  u2data\  u3data\              Drake's Fortune / Among Thieves / Drake's Deception
```

Run of 2026-10-15 with the default 4 threads: 15,150 game files and 24 entries, 59.47 GiB written in
12 min 58 s (82 MB/s); 627,921 compressed blocks inflated and Adler-32 checked (every compressed block
that holds file data); **0 failures**. 42.59 GiB were read from the 41.38 GiB package at 59 MB/s, about
what the USB disk can deliver; the extra 3% are 8 MiB chunks that were evicted from the 384 MiB cache
and read again.

## What is in this package

| | |
|---|---|
| Content ID | `EP9000-CUSA02343_00-UNCHARTEDTRILOGY` |
| Type | fake PKG: entry passcode is 32 zeros, EKPFS recoverable with the fake keyset |
| Entry table | 30 records: 6 bookkeeping (digests, keys, metas, names) + 24 files, 4 of them encrypted (`license.dat`, `license.info`, `nptitle.dat`, `npbind.dat`) |
| Outer PFS | at `0x2000000`, 44,402,933,760 bytes, signed + AES-XTS encrypted, one file: `pfs_image.dat` |
| `pfs_image.dat` | PFSC v2: 44,377,993,436 bytes stored, 64,519,602,176 logical; 984,491 blocks of 64 KiB, 628,304 zlib-compressed, 356,187 stored verbatim |
| Inner PFS | plain (not signed, not encrypted): 15,488 inodes = 337 directories + 15,150 game files + `flat_path_table`; all files contiguous |
| Game files | 15,150 files, 63,851,530,200 bytes (59.47 GiB) |

## How it works

```
PKG ──AES-XTS-128──▶ outer PFS ──/uroot/pfs_image.dat──▶ PFSC ──zlib per 64 KiB block──▶ inner PFS ──▶ files
 └─ entry table ──AES-128-CBC (IV‖key = SHA-256(record ‖ dk[keyIndex]))──▶ sce_sys\
```

| File | What it does |
|---|---|
| `src\unpack\Program.cs` | options, listing, extract/verify driver |
| `src\unpack\ReaderChain.cs` | opens the PFS layers once (`PkgImage`); one private reader stack per thread (`ReaderChain`) |
| `src\unpack\ChunkCache.cs` | shared 8 MiB read cache with read-ahead: keeps the USB disk streaming |
| `src\unpack\FileWindowReader.cs` | positional, thread-safe reads that never accept a short read |
| `src\unpack\XtsSectorReader.cs` | AES-XTS, one AES call per 4 KiB sector (byte-identical to LibOrbisPkg's, ~5x faster) |
| `src\unpack\PfscReaderFixed.cs` | PFSC index (shared) and block reader: full inflate + Adler-32 check |
| `src\unpack\FixedChunkedReader.cs` | view for non-contiguous files (none in this image) |
| `src\unpack\Sc0Entries.cs` | entry table listing, naming and decryption |
| `src\unpack\Paths.cs` | refuses `..`, rooted and Windows-illegal names coming from the package |
| `src\entries\Program.cs` | `PkgEntries`, a standalone entry-table dumper (raw, not decrypted) |

## Review of 2026-10-15

Every finding below was checked against this PKG with a read-only diagnostic before the code was changed.

**Bugs fixed**

1. **Every extracted file was garbage.** The per-thread `ReaderChain` was given the raw
   `pfs_image.dat` accessor (still PFSC-compressed) instead of the decompressing reader, so file
   bytes came from the wrong place: `eboot.bin` started `5D415E41…` instead of the SELF magic
   `4F153D1D`.
2. **One reader chain per file, never released.** The chain cache was keyed by file name, so each
   file opened a new handle, re-parsed the outer PFS, loaded the 7.9 MB PFSC offset table and
   rebuilt the whole inner tree, and all of it stayed alive until the end. The previous run
   stopped at 1,481 of 15,150 files.
3. **`--verify` raced.** All threads shared one non-thread-safe reader chain; the per-thread handles
   it opened were never used, so its lock protected nothing.
4. **`sce_sys` was incomplete.** `--entries` skipped names containing `/` (all three trophies) and
   could not decrypt `license.dat`, `license.info`, `nptitle.dat` or `npbind.dat`. All 24 entries
   are now written; `npbind.dat`'s own SHA-1 footer verifies after decryption.
5. **`PkgEntries` read the entry flags from padding** (`0x18`/`0x1C`, zero in all 30 records)
   instead of `0x08`/`0x0C`.
6. Smaller: LibOrbisPkg's `StreamReader` accepted short reads; failed files were left at full
   pre-allocated size; names from the package were not sanitized; two package paths differing only in
   case would have overwritten each other without an error; a `[pfsc]` banner was printed per file.

**Corrections to the earlier analysis**

- *PFSC.* LibOrbisPkg's `PFSCReader` skips the 2-byte zlib header and inflates raw deflate, which
  is a valid way to read zlib. Its defect is a single `DeflateStream.Read` per block: on .NET 6+
  that can return part of the block, and the rest of the reused buffer keeps the previous block's
  bytes. Nothing throws; 7 of the first 512 blocks of this image come back wrong. That silent
  corruption of directory blocks is why the old reader saw 13,090 files instead of 15,150.
- *`MetaEntry.Read`* is correct. Flags are at `0x08`/`0x0C`, and `0x18..0x1F` is zero padding in
  every record.
- *PS4 PKG Tool.* `PfscCodec.cs` belongs to its FFPFSC converter and would reject this image (it
  requires PFSC version 6). PKG extraction in PS4 PKG Tool 1.8 is done by pearlxcore's
  [OrbisPkgTool](https://github.com/pearlxcore/OrbisPkgTool) library.

**Speed.** The source is a USB hard disk that reads about 62 MB/s sequentially. On-demand reads per
file reached 21-32 MB/s. Workers now read through one shared cache of 8 MiB chunks with read-ahead,
which reaches 59 MB/s.

## Comparison with PS4 PKG Tool (OrbisPkgTool engine)

| | PkgUnpack | PS4 PKG Tool 1.8 / OrbisPkgTool |
|---|---|---|
| PKG/PFS parsing | LibOrbisPkg | its own |
| XTS | one AES call per 4 KiB sector | same |
| PFSC | inflate until the block is full, Adler-32 always checked | inflate until full, Adler-32 optional (off by default) |
| Entry table | all non-bookkeeping entries, decrypted with the passcode keys | same, same naming |
| Layout | merged (default) or raw | Merged or Raw (`Image0\` + `Sc0\`) |
| Concurrency | 4 workers over a shared read-ahead cache | single-threaded |

As a cross-check, OrbisPkgTool's reader was compiled from source (on .NET 8) and run on this PKG:

- **Listing.** The finished dump on disk matches its listing exactly: the same 15,174 files
  (15,150 + 24 entries) with the same paths and sizes, 63,884,811,063 bytes on both sides, and the same
  335 directories; nothing missing, nothing extra.
- **Contents.** Byte-identical (SHA-256) for every file compared, 0 differences: 4,923 files (7.03 GiB)
  from five test extractions during the review, and 438 files (3.14 GiB) sampled from the finished
  dump: all 24 entries, the executables and modules, files from every top-level folder, and the
  largest file in the package (`u3data\...\chunk-41-tstrm.pak`, 1.38 GiB).

Uncompressed PFSC blocks and the XTS layer carry no checksum, so this comparison is what covers them.

## Building

```powershell
dotnet build build\PkgUnpack.csproj -c Release -o bin
dotnet build build\PkgEntries.csproj -c Release -o bin
```

Offline: LibOrbisPkg has no NuGet dependencies and `build\nuget.config` clears all package sources.
Target is .NET 8.

## License

The unpacker's own code (`src\unpack\`, `src\entries\`, `build\`) is under the [MIT license](LICENSE).
[LibOrbisPkg](https://github.com/maxton/LibOrbisPkg), vendored unmodified in `src\LibOrbisPkg-master\`,
keeps its own license, the LGPL-3.0 ([LICENSE.txt](src/LibOrbisPkg-master/LICENSE.txt)).
