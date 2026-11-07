using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Community.DotNet.Up;

internal static class MuslAdmissionTests
{
    internal static byte[] Elf(string rid, string marker = "fixture")
    {
        var x64 = rid.EndsWith("-x64", StringComparison.Ordinal);
        var interpreter = NativeHost.IsMusl(rid) ? x64 ? "/lib/ld-musl-x86_64.so.1" : "/lib/ld-musl-aarch64.so.1"
            : x64 ? "/lib64/ld-linux-x86-64.so.2" : "/lib/ld-linux-aarch64.so.1";
        var value = Encoding.ASCII.GetBytes(interpreter + "\0");
        var bytes = new byte[120 + value.Length + marker.Length];
        new byte[] { 0x7f, 69, 76, 70, 2, 1, 1 }.CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(16), 3);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(18), (ushort)(x64 ? 62 : 183));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(20), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(32), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(52), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(54), 56);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(56), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(64), 3);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(72), 120);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(96), (ulong)value.Length);
        value.CopyTo(bytes, 120); Encoding.ASCII.GetBytes(marker).CopyTo(bytes, 120 + value.Length);
        return bytes;
    }

    internal static void Run(Action<bool, string> check, Action<Action, string> reject, string temporary, SdkRelease baseline, Catalog bridge)
    {
        const string releaseBase = "https://github.com/dotnetdev-kr/cbodotnet/releases/download/";
        var now = DateTimeOffset.UtcNow;
        var sha = new string('a', 64);
        SdkRelease Sdk(string rid)
        {
            var arch = NativeHost.Architecture(rid);
            return baseline with { Revision = 1, Rid = rid, ArchiveRoot = $"cbodotnet-10.0.403-linux-musl-{arch}-r1",
                Archive = new(releaseBase + $"distribution-musl-archive-sdk-10.0.403-r1/cbodotnet-sdk-10.0.403-linux-musl-{arch}-r1.tar.gz", 1, sha),
                SourceManifestSha256 = MuslSupport.SourceSha256,
                SourceManifest = new(MuslSupport.SourcePrefix + "release-manifest.json", 1, MuslSupport.SourceSha256),
                Evidence = new(MuslSupport.SourcePrefix + $"cbodotnet-musl-sdk-10.0.403-linux-musl-{arch}-r1-evidence.tar.gz", 1, sha),
                Producer = JsonSerializer.SerializeToElement(new { libc = "musl", targetRid = rid }),
                Targets = [new("alpine", "3.24.4", rid)], Dependencies = MuslSupport.Dependencies };
        }
        ToolRelease Tool(string version, string rid, string digest = "a") => new(version, rid,
            new(releaseBase + $"cbodotnetup-v{version}/cbodotnetup-{rid}", 1, new string(digest[0], 64)),
            new(releaseBase + $"cbodotnetup-v{version}/cbodotnetup-{rid}.LICENSE.txt", 1, sha));
        var sdks = new[] { Sdk("linux-musl-x64"), Sdk("linux-musl-arm64") };
        var catalog = bridge with { SchemaVersion = 4, Libc = "musl", Sequence = 990, IssuedAt = now.AddMinutes(-1), ExpiresAt = now.AddDays(30),
            Sdks = sdks, Tools = [Tool("0.5.0", "linux-musl-x64"), Tool("0.5.0", "linux-musl-arm64")], Channels = new() { ["10.0"] = "10.0.403-r1" } };
        Trust.ValidateActive(catalog, now);
        check(true, "Separate schema-4 native-musl catalog validates without changing glibc generations");
        Trust.Validate(catalog with { Sdks = sdks.Select(sdk => sdk with { Dependencies = sdk.Dependencies.Order(StringComparer.Ordinal).ToArray() }).ToArray() }, now);
        check(true, "Signed musl dependencies may use canonical sorted order without changing the closed native package set");
        var json = JsonSerializer.Serialize(bridge, UpJson.Default.Catalog);
        check(!json.Contains("libc", StringComparison.Ordinal), "Older glibc catalog serialization omits the schema-4 root libc member");
        foreach (var value in new[] { catalog with { Libc = null }, catalog with { Libc = "glibc" }, catalog with { SchemaVersion = 3 },
            catalog with { CompatibilityCatalog = new(releaseBase + "catalog/other.json", 1, sha) },
            catalog with { Sdks = [baseline] }, catalog with { Tools = [bridge.Tools[0]] },
            catalog with { Tools = [Tool("0.4.0", "linux-musl-x64")] } })
            reject(() => Trust.Validate(value, now), "Cross-libc, obsolete or provider-bearing musl catalog is rejected");
        foreach (var change in new Func<SdkRelease, SdkRelease>[] {
            sdk => sdk with { SdkVersion = "9.0.123" }, sdk => sdk with { Revision = 2 },
            sdk => sdk with { RequiresLegacyProvider = true }, sdk => sdk with { SourceManifestSha256 = sha, SourceManifest = sdk.SourceManifest with { Sha256 = sha } },
            sdk => sdk with { Targets = [new("alpine", "3.24.3", sdk.Rid)] },
            sdk => sdk with { Dependencies = ["gcompat"] },
            sdk => sdk with { Producer = JsonSerializer.SerializeToElement(new { libc = "glibc", targetRid = sdk.Rid }) },
            sdk => sdk with { Archive = baseline.Archive }, sdk => sdk with { Evidence = baseline.Evidence } })
            reject(() => Trust.Validate(catalog with { Sdks = [change(sdks[0])] }, now), "Only exact initial qualified musl identities are admitted");
        Trust.Admit(catalog, sdks[0], new("alpine", "3.24.4", "linux-musl-x64"));
        reject(() => Trust.Admit(catalog, sdks[0], new("alpine", "3.24.4", "linux-x64")), "Glibc RID cannot select musl SDK");
        reject(() => Trust.Admit(catalog, sdks[0], new("alpine", "3.24.4", "linux-musl-arm64")), "Foreign native CPU cannot select musl SDK");
        reject(() => Trust.Admit(catalog with { Revoked = [sdks[0].Id] }, sdks[0], sdks[0].Targets[0]), "Musl SDK revocation is honored");

        foreach (var rid in new[] { "linux-x64", "linux-arm64", "linux-musl-x64", "linux-musl-arm64" })
        {
            var file = Path.Combine(temporary, "elf-" + rid); File.WriteAllBytes(file, Elf(rid));
            NativeHost.RequireRid(file, rid);
            var architecture = rid.EndsWith("-x64", StringComparison.Ordinal) ? Architecture.X64 : Architecture.Arm64;
            check(NativeHost.Identify(NativeHost.ReadElf(file), architecture) == rid, "ELF interpreter and native machine establish the exact libc RID");
            reject(() => NativeHost.RequireRid(file, rid.Contains("musl", StringComparison.Ordinal) ? rid.Replace("musl-", "", StringComparison.Ordinal) : rid.Replace("linux-", "linux-musl-", StringComparison.Ordinal)),
                "A glibc executable cannot be relabeled as musl or vice versa");
            reject(() => NativeHost.Identify(NativeHost.ReadElf(file), architecture == Architecture.X64 ? Architecture.Arm64 : Architecture.X64), "ELF CPU must match the active process architecture");
        }
        foreach (var bytes in new[] { Encoding.ASCII.GetBytes("truncated"), Elf("linux-musl-x64")[..100], new byte[200] })
        {
            var file = Path.Combine(temporary, "bad-elf"); File.WriteAllBytes(file, bytes);
            reject(() => NativeHost.ReadElf(file), "Truncated or malformed native ELF cannot be activated");
        }
        check(NativeHost.Qualify("alpine", "3.24.4", "linux-musl-x64", "3.24.4\n", ["musl"]).Rid == "linux-musl-x64", "Exact Alpine point release is admitted");
        foreach (var package in new[] { "gcompat", "libc6-compat", "glibc" })
            reject(() => NativeHost.Qualify("alpine", "3.24.4", "linux-musl-x64", "3.24.4", [package]), "Alpine compatibility providers cannot authorize musl admission");
        reject(() => NativeHost.Qualify("alpine", "3.24.4", "linux-x64", "3.24.4", []), "Glibc execution on Alpine is rejected");
        reject(() => NativeHost.Qualify("ubuntu", "24.04", "linux-musl-x64", null, []), "Musl execution on unqualified glibc distribution is rejected");
        reject(() => NativeHost.Qualify("alpine", "3.24.4", "linux-musl-x64", "3.24.3", []), "Alpine release files must agree");

        var source = JsonSerializer.SerializeToNode(new { schemaVersion = 1, kind = "musl-sdk-producer-release", repository = "dotnetdev-kr/cbodotnet", libc = "musl",
            sdkVersion = "10.0.403", producerRevision = 1, tag = MuslSupport.SourceTag,
            architectures = new { x64 = new { targetRid = sdks[0].Rid, provenance = sdks[0].Producer,
                evidence = new { name = Path.GetFileName(new Uri(sdks[0].Evidence.Url).AbsolutePath), size = sdks[0].Evidence.Size, sha256 = sdks[0].Evidence.Sha256 } } } })!;
        void ValidateSource(JsonNode node) { using var document = JsonDocument.Parse(node.ToJsonString()); MuslSupport.ValidateSource(document.RootElement, sdks[0]); }
        ValidateSource(source); check(true, "Musl source producer and evidence agree with signed SDK admission");
        foreach (var mutation in new Action<JsonNode>[] { value => value["libc"] = "glibc", value => value["tag"] = "sdk-10.0.403",
            value => value["architectures"]!["x64"]!["targetRid"] = "linux-x64",
            value => value["architectures"]!["x64"]!["evidence"]!["sha256"] = new string('b', 64) })
        { var changed = source.DeepClone(); mutation(changed); reject(() => ValidateSource(changed), "Source producer substitution is rejected"); }

        var plan = JsonSerializer.SerializeToNode(new { schemaVersion = 1, kind = "musl-distribution-plan", libc = "musl", producerRevision = 1,
            sourceReleaseTag = MuslSupport.SourceTag, sourceManifestUrl = sdks[0].SourceManifest.Url, channel = "archive", variant = "alpine-3.24" })!;
        void ValidateArchive(JsonNode node) { using var document = JsonDocument.Parse(node.ToJsonString()); MuslSupport.ValidateArchive(document.RootElement, sdks[0]); }
        ValidateArchive(plan); check(true, "Existing independent musl archive metadata does not require glibc provider fields");
        foreach (var mutation in new Action<JsonNode>[] { value => value["libc"] = "glibc", value => value["producerRevision"] = 2,
            value => value["compatibility"] = new JsonObject { ["required"] = false }, value => value["variant"] = "alpine-3.24.3" })
        { var changed = plan.DeepClone(); mutation(changed); reject(() => ValidateArchive(changed), "Musl archive cannot substitute glibc/provider/other Alpine provenance"); }

        // Explicit shared roots must preserve the other libc's complete state,
        // including selection, staging, provider directories and replay records.
        var shared = Path.Combine(temporary, "shared-libc-state"); Directory.CreateDirectory(shared);
        File.WriteAllText(Path.Combine(shared, "owner"), SafeFiles.Owner + "\n");
        foreach (var path in new[] { "cache/catalog.json", "cache/v2/high-water.json", "cache/v3/catalog.json", "toolchains/foreign/receipt.json",
            "toolchains-v2/foreign/receipt.json", "toolchains-v3/foreign/receipt.json", "providers/foreign/provider.json", "staging/foreign/owner", "selection.json", "shell-enabled", "bin/foreign" })
        { var file = Path.Combine(shared, path); Directory.CreateDirectory(Path.GetDirectoryName(file)!); File.WriteAllText(file, "foreign state: " + path); }
        var before = SafeFiles.Inventory(shared);
        using (var manager = new Manager(shared, sdks[0].Targets[0]))
        {
            check(manager.Installed().Length == 0, "Musl inventory never parses glibc SDK receipts");
            manager.Collect();
            var receipt = new Receipt(3, SafeFiles.Owner, sdks[0], sha, catalog.Sequence, now);
            var directory = Path.Combine(shared, "toolchains-v4", sdks[0].Id); Directory.CreateDirectory(directory);
            SafeFiles.Write(Path.Combine(directory, "receipt.json"), receipt, UpJson.Default.Receipt);
            check(ProviderSupport.Equal(manager.Installed().Single().Release, sdks[0], UpJson.Default.SdkRelease), "Musl receipts use the isolated v4 namespace and schema");
            var wrong = Path.Combine(shared, "toolchains-v4", baseline.Id); Directory.CreateDirectory(wrong);
            SafeFiles.Write(Path.Combine(wrong, "receipt.json"), receipt with { Release = baseline }, UpJson.Default.Receipt);
            reject(() => manager.Installed(), "Glibc SDK receipt cannot enter musl installation state"); SafeFiles.DeleteTree(wrong);
        }
        var after = SafeFiles.Inventory(shared).ToDictionary(item => item.Path, StringComparer.Ordinal);
        check(before.All(item => after.TryGetValue(item.Path, out var value) && value == item), "Musl operations preserve every preexisting glibc byte, mode, link and inventory entry");
        check(!Directory.Exists(Path.Combine(shared, "cache", "v4", "gpg")), "Musl catalog and replay state remain separate from all glibc caches");
        if (OperatingSystem.IsLinux())
        {
            var unsafeCache = Path.Combine(temporary, "unsafe-shared-cache"); Directory.CreateDirectory(unsafeCache);
            File.SetUnixFileMode(unsafeCache, (UnixFileMode)0x1FF);
            reject(() => SafeFiles.PrivateDirectory(unsafeCache, preserveExistingMode: true), "Preserving a shared directory never admits group/other write permissions");
            check(File.GetUnixFileMode(unsafeCache) == (UnixFileMode)0x1FF, "Rejected unsafe shared directory retains its original mode");
        }
        Transactions(check, reject, temporary, catalog);
    }

    private static void Transactions(Action<bool, string> check, Action<Action, string> reject, string temporary, Catalog catalog)
    {
        foreach (var rid in new[] { "linux-musl-x64", "linux-musl-arm64" })
        {
            var directory = Path.Combine(temporary, "musl-self-" + rid); Directory.CreateDirectory(directory);
            var binary = Path.Combine(directory, "cbodotnetup"); var notices = binary + ".LICENSE.txt";
            var oldBytes = Elf(rid, "0.5.0"); var newBytes = Elf(rid, "0.5.1");
            var noticeBytes = Encoding.UTF8.GetBytes("native runtime license");
            Asset Fixture(string url, byte[] value) => new(url, value.Length, SafeFiles.Hash(value));
            ToolRelease Tool(string version, byte[] bytes)
            {
                var url = $"https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-v{version}/cbodotnetup-{rid}";
                return new(version, rid, Fixture(url, bytes), Fixture(url + ".LICENSE.txt", noticeBytes));
            }
            var oldTool = Tool("0.5.0", oldBytes); var newTool = Tool("0.5.1", newBytes);
            var admission = catalog with { Tools = [oldTool, newTool] };
            var resources = new Dictionary<string, byte[]> { [newTool.Binary.Url] = newBytes, [newTool.Notices.Url] = noticeBytes };
            Task Fetch(Asset asset, string path) { File.WriteAllBytes(path, resources[asset.Url]); return Task.CompletedTask; }
            void Reset()
            {
                File.WriteAllBytes(binary, oldBytes); File.WriteAllBytes(notices, noticeBytes);
                SafeFiles.Write(binary + ".ownership.json", new ToolOwnership(SafeFiles.Owner, binary, oldTool.Version,
                    oldTool.Binary.Sha256, oldTool.Notices.Sha256, null, null), UpJson.Default.ToolOwnership);
            }
            Reset();
            using var manager = new Manager(Path.Combine(directory, "data"), new("alpine", "3.24.4", rid), Fetch);
            manager.SelfUpdate(admission, binary).GetAwaiter().GetResult();
            check(File.ReadAllBytes(binary).SequenceEqual(newBytes) && File.ReadAllBytes(binary + ".previous").SequenceEqual(oldBytes),
                "Native musl update retains the exact same-libc recovery binary on both CPUs");
            reject(() => manager.SelfRollback(admission with { Revoked = ["tool/0.5.0/" + rid] }, binary), "Revoked musl tool cannot be restored");
            manager.SelfRollback(admission, binary);
            check(File.ReadAllBytes(binary).SequenceEqual(oldBytes) && !File.Exists(binary + ".previous"), "Musl tool recovery restores exact native bytes and consumes recovery state");
            var wrongLibc = Elf(rid.Replace("musl-", "", StringComparison.Ordinal));
            resources[newTool.Binary.Url] = wrongLibc;
            var wrongAdmission = admission with { Tools = [oldTool, newTool with { Binary = Fixture(newTool.Binary.Url, wrongLibc) }] };
            reject(() => manager.SelfUpdate(wrongAdmission, binary).GetAwaiter().GetResult(), "Signed musl RID cannot relabel a downloaded glibc executable");
            check(File.ReadAllBytes(binary).SequenceEqual(oldBytes) && File.ReadAllBytes(notices).SequenceEqual(noticeBytes)
                && !File.Exists(binary + ".previous"), "Rejected cross-libc update preserves the active native executable, notices and recovery state");
            var wrongCpu = Elf(rid == "linux-musl-x64" ? "linux-musl-arm64" : "linux-musl-x64");
            resources[newTool.Binary.Url] = wrongCpu;
            wrongAdmission = admission with { Tools = [oldTool, newTool with { Binary = Fixture(newTool.Binary.Url, wrongCpu) }] };
            reject(() => manager.SelfUpdate(wrongAdmission, binary).GetAwaiter().GetResult(), "Signed musl RID cannot relabel another native CPU executable");
            resources[newTool.Binary.Url] = newBytes;
            manager.SelfUpdate(admission, binary).GetAwaiter().GetResult();
            check(File.ReadAllBytes(binary).SequenceEqual(newBytes), "Musl tool can reupgrade after recovery and rejected foreign downloads");
        }
    }
}
