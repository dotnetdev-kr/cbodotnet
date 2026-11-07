using System.Formats.Tar;
using System.Diagnostics.CodeAnalysis;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace Community.DotNet.Up;

internal static partial class SafeFiles
{
    internal const string Owner = "cbodotnetup-v1";
    internal static string StatExecutable => File.Exists("/usr/bin/stat") ? "/usr/bin/stat" : "/bin/stat";
    internal static void Require([DoesNotReturnIf(false)] bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
    internal static bool Exists(string path) => File.Exists(path) || Directory.Exists(path) || new FileInfo(path).LinkTarget is not null;
    internal static bool Link(string path) => new FileInfo(path).LinkTarget is not null || new DirectoryInfo(path).LinkTarget is not null;
    internal static void OrdinaryPath(string path)
    {
        path = Path.GetFullPath(path);
        for (string? current = path; current is not null; current = Path.GetDirectoryName(current))
        {
            Require(!Link(current), "Refusing a symbolic link in an owned path: " + current);
            if (Path.GetPathRoot(current) == current) break;
        }
    }
    internal static string Under(string root, string relative)
    {
        Require(relative.Length is > 0 and <= 2048 && !relative.Contains('\\') && !relative.StartsWith('/')
            && relative.Split('/').All(s => s.Length > 0 && s is not "." and not ".." && !s.Any(char.IsControl)),
            "Unsafe relative path: " + relative);
        var target = Path.GetFullPath(Path.Combine(root, relative));
        Require(target.StartsWith(Path.GetFullPath(root) + Path.DirectorySeparatorChar, StringComparison.Ordinal), "Path escaped its owned root");
        return target;
    }
    internal static void PrivateDirectory(string path, bool preserveExistingMode = false)
    {
        OrdinaryPath(path);
        var existed = Directory.Exists(path);
        Directory.CreateDirectory(path);
        if (OperatingSystem.IsLinux())
        {
            var mode = File.GetUnixFileMode(path);
            Require((mode & (UnixFileMode.GroupWrite | UnixFileMode.OtherWrite)) == 0, "Owned directory is writable by another user: " + path);
            Require(Command(StatExecutable, ["--format=%u", "--", path]).Trim() == GetEuid().ToString(), "Owned directory belongs to another user");
            // The musl and glibc namespaces may share an explicitly selected
            // owned parent. Validate its owner and write protection without
            // changing the other libc's existing directory permissions.
            if (!preserveExistingMode || !existed)
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }
    internal static string Hash(string path)
    {
        using var input = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(input));
    }
    internal static string Hash(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    internal static void Atomic(string path, byte[] data, bool executable = false)
    {
        OrdinaryPath(path);
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { file.Write(data); file.Flush(true); }
            if (OperatingSystem.IsLinux()) File.SetUnixFileMode(temporary, executable ? (UnixFileMode)0x1ED : (UnixFileMode)0x180);
            File.Move(temporary, path, true);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    internal static void Write<T>(string path, T value, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type) => Atomic(path, JsonSerializer.SerializeToUtf8Bytes(value, type));
    internal static T Read<T>(string path, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type)
    {
        OrdinaryPath(path);
        Require(new FileInfo(path).Length <= 32 * 1024 * 1024, "Oversized local metadata");
        return Parse(File.ReadAllBytes(path), type);
    }
    internal static T Parse<T>(byte[] bytes, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> type)
    {
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 48 });
        CheckJson(document.RootElement);
        return JsonSerializer.Deserialize(bytes, type) ?? throw new InvalidOperationException("Empty metadata");
    }
    internal static void CheckJson(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in value.EnumerateObject()) { Require(names.Add(item.Name), "Duplicate JSON property"); CheckJson(item.Value); }
        }
        else if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) CheckJson(item);
    }
    internal static string Command(string executable, IEnumerable<string> arguments, string? workingDirectory = null)
    {
        var start = new System.Diagnostics.ProcessStartInfo(executable) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, WorkingDirectory = workingDirectory ?? Environment.CurrentDirectory };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = System.Diagnostics.Process.Start(start) ?? throw new InvalidOperationException("Cannot start " + executable);
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(60_000)) { process.Kill(true); throw new InvalidOperationException("Verification process timed out"); }
        Require(process.ExitCode == 0, executable + " failed: " + error.GetAwaiter().GetResult().Trim());
        return output.GetAwaiter().GetResult();
    }
    internal static void Extract(string archive, string destination, string expectedRoot)
        => ExtractCore(archive, destination, expectedRoot, false);
    internal static void ExtractProvider(string archive, string destination)
        => ExtractCore(archive, destination, "rootfs", true);
    private static void ExtractCore(string archive, string destination, string expectedRoot, bool provider)
    {
        Require(!Exists(destination), "Extraction destination already exists");
        PrivateDirectory(destination);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var links = new List<(string Path, string Target, bool Hard)>();
        var modes = new List<(string Path, UnixFileMode Mode)>();
        long expanded = 0;
        using var raw = File.OpenRead(archive);
        using var gzip = new GZipStream(raw, CompressionMode.Decompress);
        using var tar = new TarReader(gzip);
        TarEntry? entry;
        while ((entry = tar.GetNextEntry(false)) is not null)
        {
            var name = entry.Name.TrimEnd('/');
            Require(name == expectedRoot || name.StartsWith(expectedRoot + '/', StringComparison.Ordinal)
                || provider && name == "provider-manifest.json" && entry.EntryType is TarEntryType.RegularFile or TarEntryType.V7RegularFile,
                "Unexpected archive root");
            var path = Under(destination, name);
            Require(seen.Count < 200_000 && seen.Add(name), "Duplicate entry or excessive archive entries");
            Require(((int)entry.Mode & ~0x1FF) == 0 && entry.Length >= 0, "Unsafe archive mode or length");
            expanded = checked(expanded + entry.Length);
            Require(expanded <= 8L * 1024 * 1024 * 1024, "Expanded archive exceeds size limit");
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            switch (entry.EntryType)
            {
                case TarEntryType.Directory:
                    Require(!File.Exists(path), "Archive directory conflicts with a file");
                    Directory.CreateDirectory(path); modes.Add((path, entry.Mode)); break;
                case TarEntryType.RegularFile:
                case TarEntryType.V7RegularFile:
                    using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    { entry.DataStream?.CopyTo(output); Require(output.Length == entry.Length, "Truncated archive file"); }
                    if (OperatingSystem.IsLinux()) File.SetUnixFileMode(path, entry.Mode);
                    break;
                case TarEntryType.SymbolicLink:
                case TarEntryType.HardLink:
                    Require(!Exists(path) && !string.IsNullOrEmpty(entry.LinkName) && !entry.LinkName.Contains('\\') && !Path.IsPathRooted(entry.LinkName), "Unsafe archive link");
                    var hard = entry.EntryType == TarEntryType.HardLink;
                    var target = hard ? Under(destination, entry.LinkName) : Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, entry.LinkName));
                    Require(target.StartsWith(Path.Combine(destination, expectedRoot) + Path.DirectorySeparatorChar, StringComparison.Ordinal), "Archive link escapes its root");
                    links.Add((path, hard ? target : entry.LinkName, hard)); break;
                default: throw new InvalidOperationException("Unsupported archive entry type: " + entry.EntryType);
            }
        }
        var remainder = new byte[8192];
        while (gzip.Read(remainder) != 0) { } // Validate gzip trailer/CRC even when the TAR end marker appeared first.
        // Links are created only after all regular files, so an archive can never write through one.
        foreach (var item in links.Where(l => l.Hard))
        {
            OrdinaryPath(item.Target);
            Require(File.Exists(item.Target) && !Directory.Exists(item.Target) && !Exists(item.Path), "Hard link target is absent or unsafe");
            Require(OperatingSystem.IsLinux() && NativeLink(item.Target, item.Path) == 0, "Cannot preserve archive hard link");
        }
        foreach (var item in links.Where(l => !l.Hard))
        { OrdinaryPath(Path.GetDirectoryName(item.Path)!); Require(!Exists(item.Path), "Conflicting archive link"); File.CreateSymbolicLink(item.Path, item.Target); }
        foreach (var item in modes.OrderByDescending(item => item.Path.Length))
            if (OperatingSystem.IsLinux()) File.SetUnixFileMode(item.Path, item.Mode);
        Require(Directory.Exists(Path.Combine(destination, expectedRoot)), "Archive has no payload root");
    }
    internal static InventoryItem[] Inventory(string root)
    {
        var result = new List<InventoryItem>();
        void Visit(string directory)
        {
            foreach (var path in Directory.EnumerateFileSystemEntries(directory).Order(StringComparer.Ordinal))
            {
                var relative = Path.GetRelativePath(root, path).Replace('\\', '/');
                var link = new FileInfo(path).LinkTarget;
                if (link is not null) result.Add(new(relative, "link", 0, 0, "", link));
                else if (Directory.Exists(path)) { result.Add(new(relative, "directory", Mode(path), 0, "", null)); Visit(path); }
                else { result.Add(new(relative, "file", Mode(path), new FileInfo(path).Length, Hash(path), null)); }
            }
        }
        Visit(root); return result.OrderBy(item => item.Path, StringComparer.Ordinal).ToArray();
    }
    internal static int Mode(string path) => OperatingSystem.IsLinux() ? (int)File.GetUnixFileMode(path) : 0;
    internal static void DeleteTree(string root)
    {
        OrdinaryPath(root);
        // No recursive operation follows symlinks. Only a caller-authenticated owned root reaches here.
        foreach (var path in Directory.EnumerateFileSystemEntries(root))
            if (Link(path) || !Directory.Exists(path)) File.Delete(path); else DeleteTree(path);
        Directory.Delete(root);
    }
    [LibraryImport("libc", EntryPoint = "geteuid")] internal static partial uint GetEuid();
    [LibraryImport("libc", EntryPoint = "link", StringMarshalling = StringMarshalling.Utf8)] private static partial int NativeLink(string oldPath, string newPath);
}
