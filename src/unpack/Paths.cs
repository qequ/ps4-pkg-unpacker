using System;
using System.Collections.Generic;
using System.IO;

namespace PkgUnpack
{
  /// <summary>
  /// Output path checks. File names come from the package, so a damaged or hostile PKG could
  /// carry "..", rooted paths or names Windows cannot create; refuse those instead of
  /// writing outside the output directory.
  /// </summary>
  internal static class Paths
  {
    static readonly char[] Invalid = Path.GetInvalidFileNameChars();
    static readonly HashSet<string> Reserved = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
      "CON", "PRN", "AUX", "NUL",
      "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
      "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    /// <summary>True when every '/'-separated component is a plain, Windows-legal file name.</summary>
    public static bool IsSafeRelative(string rel)
    {
      if (string.IsNullOrEmpty(rel)) return false;
      foreach (var part in rel.Split('/'))
      {
        if (part.Length == 0 || part == "." || part == "..") return false;
        if (part.IndexOfAny(Invalid) >= 0 || part.EndsWith(".") || part.EndsWith(" ")) return false;
        if (Reserved.Contains(Path.GetFileNameWithoutExtension(part))) return false;
      }
      return true;
    }

    /// <summary>The full path of a '/'-separated relative path under <paramref name="root"/>.</summary>
    public static string Under(string root, string rel)
    {
      if (!IsSafeRelative(rel)) throw new InvalidDataException($"refusing unsafe path from the package: '{rel}'");
      return Path.Combine(root, rel.Replace('/', Path.DirectorySeparatorChar));
    }
  }
}
