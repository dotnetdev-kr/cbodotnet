using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;

namespace Community.DotNet.Up;

internal sealed record NativeElf(ushort Machine, string Interpreter);

internal static class NativeHost
{
    internal static bool IsMusl(string rid) => rid is "linux-musl-x64" or "linux-musl-arm64";
    internal static bool IsRid(string rid) => rid is "linux-x64" or "linux-arm64" or "linux-musl-x64" or "linux-musl-arm64";
    internal static string Architecture(string rid) => rid.EndsWith("-x64", StringComparison.Ordinal) ? "x64" : "aarch64";
    internal static string Rid => Identify(ReadElf("/proc/self/exe"), RuntimeInformation.ProcessArchitecture);

    // Check the running native image, rather than inferring its ABI from an
    // installed loader or an OS name. In particular gcompat cannot make a
    // glibc executable an admitted musl executable.
    internal static string Identify(NativeElf elf, Architecture architecture)
    {
        var machine = architecture switch { System.Runtime.InteropServices.Architecture.X64 => 62,
            System.Runtime.InteropServices.Architecture.Arm64 => 183, _ => 0 };
        SafeFiles.Require(machine != 0 && elf.Machine == machine, "Only matching native Linux x64 and AArch64 images are supported");
        return elf.Interpreter switch
        {
            "/lib/ld-musl-x86_64.so.1" when machine == 62 => "linux-musl-x64",
            "/lib/ld-musl-aarch64.so.1" when machine == 183 => "linux-musl-arm64",
            "/lib64/ld-linux-x86-64.so.2" when machine == 62 => "linux-x64",
            "/lib/ld-linux-aarch64.so.1" or "/lib64/ld-linux-aarch64.so.1" when machine == 183 => "linux-arm64",
            _ => throw new InvalidOperationException("The native executable has an unqualified libc interpreter")
        };
    }

    internal static void RequireRid(string path, string rid)
    {
        SafeFiles.Require(IsRid(rid), "Unsupported native executable RID");
        var architecture = Architecture(rid) == "x64" ? System.Runtime.InteropServices.Architecture.X64 : System.Runtime.InteropServices.Architecture.Arm64;
        SafeFiles.Require(Identify(ReadElf(path), architecture) == rid, "Native executable CPU/libc differs from the signed RID");
    }

    internal static NativeElf ReadElf(string path)
    {
        using var input = File.OpenRead(path);
        var header = new byte[64];
        SafeFiles.Require(input.Read(header) == header.Length && header.AsSpan(0, 4).SequenceEqual(new byte[] { 0x7f, 69, 76, 70 })
            && header[4] == 2 && header[5] == 1 && header[6] == 1
            && BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(16)) is 2 or 3
            && BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(52)) == 64
            && BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(20)) == 1,
            "A complete little-endian ELF64 native executable is required");
        var table = BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(32));
        var entrySize = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(54));
        var count = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(56));
        SafeFiles.Require(table >= 64 && entrySize is >= 56 and <= 128 && count is > 0 and <= 1024
            && table <= (ulong)input.Length && (ulong)entrySize * count <= (ulong)input.Length - table,
            "Malformed native ELF program table");
        string? interpreter = null;
        var entry = new byte[entrySize];
        for (var index = 0; index < count; index++)
        {
            input.Position = (long)(table + (ulong)(index * entrySize)); input.ReadExactly(entry);
            if (BinaryPrimitives.ReadUInt32LittleEndian(entry) != 3) continue;
            var offset = BinaryPrimitives.ReadUInt64LittleEndian(entry.AsSpan(8));
            var size = BinaryPrimitives.ReadUInt64LittleEndian(entry.AsSpan(32));
            SafeFiles.Require(interpreter is null && size is >= 2 and <= 512 && offset <= (ulong)input.Length
                && size <= (ulong)input.Length - offset, "Malformed or duplicate native ELF interpreter");
            var bytes = new byte[(int)size]; input.Position = (long)offset; input.ReadExactly(bytes);
            SafeFiles.Require(bytes[^1] == 0 && bytes[..^1].All(value => value is >= 32 and <= 126), "Malformed native ELF interpreter path");
            interpreter = Encoding.ASCII.GetString(bytes, 0, bytes.Length - 1);
        }
        SafeFiles.Require(interpreter is not null, "Native executable has no dynamic libc interpreter");
        return new(BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(18)), interpreter!);
    }

    internal static Target Qualify(string os, string version, string rid, string? alpineRelease, IEnumerable<string> packages)
    {
        SafeFiles.Require(IsRid(rid), "Unsupported Linux CPU/libc RID");
        if (IsMusl(rid))
        {
            SafeFiles.Require(os == "alpine" && version == "3.24.4" && alpineRelease?.Trim() == "3.24.4",
                "Only native Alpine 3.24.4 is qualified for musl cbodotnetup");
            SafeFiles.Require(!packages.Intersect(new[] { "gcompat", "libc6-compat", "glibc" }, StringComparer.Ordinal).Any(),
                "Glibc compatibility layers are forbidden on the qualified musl host");
        }
        else SafeFiles.Require(new[] { ("ubuntu", "24.04"), ("debian", "13"), ("fedora", "45"), ("rocky", "9.8") }.Contains((os, version)),
            "This operating system/version is not qualified for glibc cbodotnetup");
        return new(os, version, rid);
    }
}
