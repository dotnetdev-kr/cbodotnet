using System.Formats.Tar;
using System.IO.Compression;
using System.Text.Json;
using Community.DotNet.Up;

var passed = 0;
void Check(bool value, string name) { if (!value) throw new Exception("FAILED: " + name); passed++; }
void Reject(Action action, string name)
{
    try { action(); } catch (Exception e) when (e is InvalidOperationException or IOException or JsonException or ArgumentException) { passed++; return; }
    throw new Exception("FAILED (accepted): " + name);
}
var temporary = Path.Combine(Path.GetTempPath(), "cbodotnetup-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(temporary);
try
{
    Reject(() => SafeFiles.Under(temporary, "../outside"), "parent traversal");
    Reject(() => SafeFiles.Under(temporary, "/absolute"), "absolute path");
    Reject(() => SafeFiles.Under(temporary, "a\\b"), "backslash path");
    Reject(() => SafeFiles.Under(temporary, "a//b"), "empty path component");
    Reject(() => SafeFiles.Under(temporary, "a/./b"), "dot component");
    Reject(() => SafeFiles.Parse(System.Text.Encoding.UTF8.GetBytes("{\"sequence\":1,\"sequence\":2}"), UpJson.Default.HighWater), "duplicate JSON property");
    Reject(() => SafeFiles.Parse(System.Text.Encoding.UTF8.GetBytes("{\"sequence\":1,\"sha256\":\"a\",\"ignored\":true}"), UpJson.Default.HighWater), "unknown metadata field");
    var now = DateTimeOffset.UtcNow;
    var sha = new string('a', 64);
    var releaseBase = "https://github.com/dotnetdev-kr/cbodotnet/releases/download/";
    var sdk = new SdkRelease("10.0.403", 2, "linux-x64", "cbodotnet-10.0.403-linux-x64-r2",
        new(releaseBase + "distribution-archive-sdk-10.0.403-r2/cbodotnet-sdk-10.0.403-linux-x64-branded-r2.tar.gz", 1, sha), sha,
        new(releaseBase + "sdk-10.0.403/release-manifest.json", 1, sha), JsonDocument.Parse("{\"runId\":\"123\"}").RootElement.Clone(),
        new(releaseBase + "sdk-10.0.403/evidence-x64.tar.gz", 1, sha), ["LICENSE.txt", "ThirdPartyNotices.txt"],
        "community-build-no-additional-security-maintenance", ["libicu"], [new("rocky", "9.8", "linux-x64")], false);
    var tool = new ToolRelease("0.1.0", "linux-x64", new(releaseBase + "cbodotnetup-v0.1.0/cbodotnetup-linux-x64", 1, sha), new(releaseBase + "cbodotnetup-v0.1.0/cbodotnetup-linux-x64.LICENSE.txt", 1, sha));
    var catalog = new Catalog(1, "cbodotnetup-installation-catalog", 1, now.AddMinutes(-1), now.AddDays(30), Trust.Fingerprint, [], [sdk], [tool], new() { ["10.0"] = "10.0.403-r2" });
    Trust.Validate(catalog, now); passed++;
    Trust.Admit(catalog, sdk, new("rocky", "9.8", "linux-x64")); passed++;
    Reject(() => Trust.Admit(catalog, sdk, new("rocky", "9.8", "linux-arm64")), "wrong actual CPU");
    Reject(() => Trust.Admit(catalog, sdk, new("ubuntu", "24.04", "linux-x64")), "unqualified actual OS");
    Reject(() => Trust.Admit(catalog with { Revoked = [sdk.Id] }, sdk, new("rocky", "9.8", "linux-x64")), "revoked SDK");
    Reject(() => Trust.Admit(catalog, sdk with { RequiresLegacyProvider = true }, new("rocky", "9.8", "linux-x64")), "unavailable legacy provider");
    Trust.Advance(3, sha, new(3, sha)); passed++;
    Trust.Advance(4, sha, new(3, sha)); passed++;
    Reject(() => Trust.Advance(2, sha, new(3, sha)), "replayed older catalog");
    Reject(() => Trust.Advance(3, new string('b', 64), new(3, sha)), "conflicting catalog sequence");
    Reject(() => Trust.Validate(catalog with { Tools = [tool with { Notices = tool.Notices with { Url = releaseBase + "other/notices" } }] }, now), "unbound tool notices");
    Reject(() => Trust.Validate(catalog with { ExpiresAt = now.AddSeconds(-1) }, now), "expired catalog");
    Reject(() => Trust.Validate(catalog with { IssuedAt = now.AddMinutes(6) }, now), "future catalog");
    Reject(() => Trust.Validate(catalog with { ExpiresAt = now.AddDays(32) }, now), "unbounded catalog validity");
    Reject(() => Trust.Validate(catalog with { SigningFingerprint = new string('A', 40) }, now), "unrelated signer");
    Reject(() => Trust.Validate(catalog with { Sequence = 0 }, now), "nonpositive catalog sequence");
    Reject(() => Trust.Validate(catalog with { Sdks = [sdk, sdk] }, now), "duplicate identity");
    Reject(() => Trust.Validate(catalog with { Sdks = [sdk with { Rid = "linux-musl-x64" }] }, now), "musl admission");
    Reject(() => Trust.Validate(catalog with { Sdks = [sdk with { ArchiveRoot = "../../outside" }] }, now), "conflicting archive root");
    Reject(() => Trust.Validate(catalog with { Sdks = [sdk with { SourceManifestSha256 = new string('b', 64) }] }, now), "source hash mismatch");
    Reject(() => Trust.Validate(catalog with { Channels = new() { ["10.0"] = "10.0.999-r1" } }, now), "unqualified channel target");
    foreach (var url in new[] { "http://github.com/dotnetdev-kr/cbodotnet/releases/download/a/b", "https://github.com/other/project/releases/download/a/b", releaseBase + "a/../secret", releaseBase + "a/b?token=x", releaseBase + "a/b#fragment", "https://github.com:444/dotnetdev-kr/cbodotnet/releases/download/a/b" })
        Reject(() => Trust.AssetValid(new(url, 1, sha)), "untrusted asset URL " + url);
    Reject(() => Trust.AssetValid(new(releaseBase + "a/b", 0, sha)), "empty artifact");
    Reject(() => Trust.AssetValid(new(releaseBase + "a/b", 2L * 1024 * 1024 * 1024, sha)), "oversized artifact");
    Reject(() => Trust.AssetValid(new(releaseBase + "a/b", 1, new string('A', 64))), "noncanonical hash");

    void Archive(string name, Action<TarWriter> write)
    {
        using var raw = File.Create(Path.Combine(temporary, name)); using var gzip = new GZipStream(raw, CompressionLevel.Fastest);
        using var tar = new TarWriter(gzip); write(tar);
    }
    void FileEntry(TarWriter tar, string name, string value = "verified")
    {
        using var data = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(value));
        tar.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, name) { DataStream = data, Mode = (UnixFileMode)0x1A4 });
    }
    Archive("good.tar.gz", tar => FileEntry(tar, "root/payload/LICENSE.txt"));
    var extracted = Path.Combine(temporary, "extracted"); SafeFiles.Extract(Path.Combine(temporary, "good.tar.gz"), extracted, "root");
    Check(File.ReadAllText(Path.Combine(extracted, "root/payload/LICENSE.txt")) == "verified", "byte-preserving extraction");
    var before = SafeFiles.Inventory(extracted); File.AppendAllText(Path.Combine(extracted, "root/payload/LICENSE.txt"), "changed");
    Check(!before.SequenceEqual(SafeFiles.Inventory(extracted)), "installed tampering detected");
    Archive("parent.tar.gz", tar => FileEntry(tar, "root/../../outside"));
    Reject(() => SafeFiles.Extract(Path.Combine(temporary, "parent.tar.gz"), Path.Combine(temporary, "parent"), "root"), "archive traversal");
    Archive("duplicate.tar.gz", tar => { FileEntry(tar, "root/a"); FileEntry(tar, "root/a"); });
    Reject(() => SafeFiles.Extract(Path.Combine(temporary, "duplicate.tar.gz"), Path.Combine(temporary, "duplicate"), "root"), "archive duplicate");
    Archive("symlink.tar.gz", tar => tar.WriteEntry(new PaxTarEntry(TarEntryType.SymbolicLink, "root/link") { LinkName = "../../outside" }));
    Reject(() => SafeFiles.Extract(Path.Combine(temporary, "symlink.tar.gz"), Path.Combine(temporary, "bad-link"), "root"), "archive symlink escape");
    Archive("absolute.tar.gz", tar => tar.WriteEntry(new PaxTarEntry(TarEntryType.SymbolicLink, "root/link") { LinkName = "/etc/passwd" }));
    Reject(() => SafeFiles.Extract(Path.Combine(temporary, "absolute.tar.gz"), Path.Combine(temporary, "absolute"), "root"), "absolute archive symlink");
    Archive("fifo.tar.gz", tar => tar.WriteEntry(new PaxTarEntry(TarEntryType.Fifo, "root/pipe")));
    Reject(() => SafeFiles.Extract(Path.Combine(temporary, "fifo.tar.gz"), Path.Combine(temporary, "fifo"), "root"), "archive special device");
    Archive("setuid.tar.gz", tar => tar.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, "root/a") { Mode = (UnixFileMode)0x9ED }));
    Reject(() => SafeFiles.Extract(Path.Combine(temporary, "setuid.tar.gz"), Path.Combine(temporary, "setuid"), "root"), "setuid archive file");
    var truncated = File.ReadAllBytes(Path.Combine(temporary, "good.tar.gz")); File.WriteAllBytes(Path.Combine(temporary, "truncated.tar.gz"), truncated[..(truncated.Length / 2)]);
    Reject(() => SafeFiles.Extract(Path.Combine(temporary, "truncated.tar.gz"), Path.Combine(temporary, "truncated"), "root"), "truncated gzip/tar");
    var state = Path.Combine(temporary, "state.json"); SafeFiles.Write(state, new HighWater(3, sha), UpJson.Default.HighWater);
    Check(SafeFiles.Read(state, UpJson.Default.HighWater) == new HighWater(3, sha), "atomic state roundtrip");
    using (var held = new FileStream(Path.Combine(temporary, "lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
        Reject(() => { using var conflicting = new FileStream(Path.Combine(temporary, "lock"), FileMode.Open, FileAccess.ReadWrite, FileShare.None); }, "concurrent lock acquisition");
    Console.WriteLine($"cbodotnetup security tests passed: {passed}");
}
finally { SafeFiles.DeleteTree(temporary); }
