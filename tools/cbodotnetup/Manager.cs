using System.Diagnostics;
using System.Text.Json;

namespace Community.DotNet.Up;

internal sealed class Manager : IDisposable
{
    internal readonly string Root;
    private readonly string toolchains;
    private readonly string cache;
    private readonly string staging;
    private readonly FileStream lease;
    private readonly Trust trust;
    private readonly Target host;
    private readonly Func<Asset, string, Task>? downloadOverride;
    // Internal dependency injection is used by file-transaction tests; the CLI supplies no overrides.
    internal Manager(string? rootOverride = null, Target? hostOverride = null, Func<Asset, string, Task>? downloadOverride = null)
    {
        host = hostOverride ?? Trust.Host();
        this.downloadOverride = downloadOverride;
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var xdg = Environment.GetEnvironmentVariable("XDG_DATA_HOME");
        Root = rootOverride ?? Environment.GetEnvironmentVariable("CBODOTNETUP_HOME") ?? Path.Combine(xdg ?? Path.Combine(home, ".local", "share"), "cbodotnetup");
        SafeFiles.Require(Path.IsPathFullyQualified(Root) && !Root.Any(char.IsControl), "Use an absolute user-local cbodotnetup root");
        Root = Path.GetFullPath(Root).TrimEnd('/');
        SafeFiles.Require(!Root.Split('/').Any(part => part is "dotnetup" or ".dotnet"), "The official dotnet/dotnetup state roots are reserved");
        SafeFiles.Require(!new[] { "/", "/opt", "/usr", "/etc", "/var", home, "/opt/cbodotnet", "/usr/share/dotnet" }.Contains(Root)
            && !Root.StartsWith("/opt/", StringComparison.Ordinal) && !Root.StartsWith("/usr/", StringComparison.Ordinal)
            && !Root.StartsWith("/etc/", StringComparison.Ordinal) && !Root.StartsWith("/var/", StringComparison.Ordinal), "Refusing a system or unrelated installation root");
        SafeFiles.PrivateDirectory(Root);
        var owner = Path.Combine(Root, "owner");
        if (!File.Exists(owner))
        {
            SafeFiles.Require(!Directory.EnumerateFileSystemEntries(Root).Any(), "Existing directory is not owned by cbodotnetup");
            SafeFiles.Atomic(owner, System.Text.Encoding.UTF8.GetBytes(SafeFiles.Owner + "\n"));
        }
        SafeFiles.OrdinaryPath(owner);
        SafeFiles.Require(File.ReadAllText(owner) == SafeFiles.Owner + "\n", "Installation ownership marker differs");
        var lockPath = Path.Combine(Root, "operation.lock"); SafeFiles.OrdinaryPath(lockPath);
        try { lease = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
        catch (IOException) { throw new InvalidOperationException("Another cbodotnetup operation is running; retry after it completes"); }
        toolchains = Path.Combine(Root, "toolchains"); cache = Path.Combine(Root, "cache"); staging = Path.Combine(Root, "staging");
        foreach (var path in new[] { toolchains, cache, staging }) SafeFiles.PrivateDirectory(path);
        trust = new Trust(cache);
    }
    public void Dispose() => lease.Dispose();
    private async Task Download(Asset asset, string path)
    {
        if (downloadOverride is null) { await Trust.DownloadAsset(asset, path); return; }
        Trust.AssetValid(asset); SafeFiles.OrdinaryPath(path);
        await downloadOverride(asset, path);
        SafeFiles.Require(new FileInfo(path).Length == asset.Size && SafeFiles.Hash(path) == asset.Sha256, "Downloaded artifact is corrupt, truncated or has conflicting bytes");
    }
    internal Task<Catalog> Catalog(string? file, bool refresh) => trust.Load(file, refresh);
    private string PathFor(SdkRelease sdk) => SafeFiles.Under(toolchains, sdk.Id);
    private Selection Selections() => File.Exists(Path.Combine(Root, "selection.json"))
        ? SafeFiles.Read(Path.Combine(Root, "selection.json"), UpJson.Default.Selection) : new(new(StringComparer.Ordinal), []);
    private void SaveSelection(Selection value) => SafeFiles.Write(Path.Combine(Root, "selection.json"), value, UpJson.Default.Selection);
    internal Receipt[] Installed()
    {
        var result = new List<Receipt>();
        foreach (var version in Directory.EnumerateDirectories(toolchains))
        {
            SafeFiles.OrdinaryPath(version);
            foreach (var directory in Directory.EnumerateDirectories(version))
            {
                SafeFiles.OrdinaryPath(directory);
                var receipt = SafeFiles.Read(Path.Combine(directory, "receipt.json"), UpJson.Default.Receipt);
                SafeFiles.Require(receipt.Owner == SafeFiles.Owner && receipt.SchemaVersion == 1
                    && PathFor(receipt.Release) == directory && receipt.Release.Rid == host.Rid, "Unowned or conflicting toolchain state");
                result.Add(receipt);
            }
        }
        return result.OrderByDescending(r => Version.Parse(r.Release.SdkVersion)).ThenByDescending(r => r.Release.Revision).ToArray();
    }
    private void VerifyInstalled(Receipt receipt, Catalog catalog, bool allowRevoked = false)
    {
        var sdk = receipt.Release; var path = PathFor(sdk); SafeFiles.OrdinaryPath(path);
        SafeFiles.Require(allowRevoked || !catalog.Revoked.Contains(sdk.Id), "This SDK release was revoked; select another verified release");
        var retained = Path.Combine(path, "catalog.json");
        Trust.VerifySignature(retained, retained + ".asc", cache);
        var original = SafeFiles.Read(retained, UpJson.Default.Catalog); Trust.Validate(original, DateTimeOffset.UtcNow, false);
        SafeFiles.Require(SafeFiles.Hash(retained) == receipt.CatalogSha256 && original.Sequence == receipt.CatalogSequence
            && original.Sdks.Contains(sdk, SdkComparer.Instance), "Installed receipt differs from its signed admission");
        var expected = SafeFiles.Read(Path.Combine(path, "inventory.json"), UpJson.Default.InventoryItemArray);
        SafeFiles.Require(expected.SequenceEqual(SafeFiles.Inventory(Path.Combine(path, "content"))), "Installed bytes, modes, links or file inventory changed; removal/update is refused");
    }
    private sealed class SdkComparer : IEqualityComparer<SdkRelease>
    {
        internal static readonly SdkComparer Instance = new();
        public bool Equals(SdkRelease? x, SdkRelease? y) => x is not null && y is not null
            && JsonSerializer.SerializeToUtf8Bytes(x, UpJson.Default.SdkRelease).AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(y, UpJson.Default.SdkRelease));
        public int GetHashCode(SdkRelease value) => value.Id.GetHashCode(StringComparison.Ordinal);
    }
    internal SdkRelease Resolve(Catalog catalog, string version)
    {
        var possible = catalog.Sdks.Where(s => s.Rid == host.Rid && (s.SdkVersion == version || $"{s.SdkVersion}-r{s.Revision}" == version)).OrderByDescending(s => s.Revision).ToArray();
        SafeFiles.Require(possible.Length > 0, "Exact SDK/version is not admitted in the signed catalog: " + version);
        var sdk = possible[0];
        Trust.Admit(catalog, sdk, host);
        return sdk;
    }
    internal async Task Install(Catalog catalog, string version, string? channel = null)
    {
        Trust.Validate(catalog, DateTimeOffset.UtcNow);
        var sdk = Resolve(catalog, version); var path = PathFor(sdk);
        if (Directory.Exists(path))
        {
            var previous = SafeFiles.Read(Path.Combine(path, "receipt.json"), UpJson.Default.Receipt);
            SafeFiles.Require(SdkComparer.Instance.Equals(previous.Release, sdk), "Existing identity has conflicting catalog bytes");
            VerifyInstalled(previous, catalog); Activate(sdk, channel); Console.WriteLine("Already installed and verified: " + sdk.Id); return;
        }
        var work = Path.Combine(staging, Guid.NewGuid().ToString("N")); SafeFiles.PrivateDirectory(work);
        SafeFiles.Atomic(Path.Combine(work, "owner"), System.Text.Encoding.UTF8.GetBytes(SafeFiles.Owner));
        try
        {
            Console.WriteLine("Downloading verified Community Build SDK " + sdk.Id);
            await Download(sdk.SourceManifest, Path.Combine(work, "source.json"));
            using (var source = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(work, "source.json"))))
            {
                SafeFiles.Require(source.RootElement.GetProperty("sdkVersion").GetString() == sdk.SdkVersion, "Canonical source manifest SDK differs");
            }
            var archive = Path.Combine(work, "sdk.tar.gz"); await Download(sdk.Archive, archive);
            var prepared = Path.Combine(work, "prepared"); SafeFiles.PrivateDirectory(prepared);
            var content = Path.Combine(prepared, "content"); SafeFiles.Extract(archive, content, sdk.ArchiveRoot);
            var root = Path.Combine(content, sdk.ArchiveRoot);
            foreach (var name in new[] { "cbodotnet", "cbodotnet-" + sdk.Series, "dotnet", "payload/dotnet", "distribution.json", "LICENSE.wrapper.txt", "payload/LICENSE.txt", "payload/ThirdPartyNotices.txt" })
            { var file = SafeFiles.Under(root, name); SafeFiles.OrdinaryPath(file); SafeFiles.Require(File.Exists(file), "Required SDK host, wrapper, provenance or notice is absent"); }
            using (var provenance = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(root, "distribution.json"))))
            {
                var p = provenance.RootElement;
                SafeFiles.Require(p.GetProperty("sdkVersion").GetString() == sdk.SdkVersion && p.GetProperty("packageRevision").GetInt32() == sdk.Revision
                    && p.GetProperty("sourceManifestSha256").GetString() == sdk.SourceManifestSha256
                    && p.GetProperty("targetRid").GetString() == host.Rid && !p.GetProperty("compatibility").GetProperty("required").GetBoolean()
                    && JsonElement.DeepEquals(p.GetProperty("producer"), sdk.Producer), "Archive provenance differs from signed catalog");
            }
            File.Copy(Path.Combine(cache, "catalog.json"), Path.Combine(prepared, "catalog.json")); File.Copy(Path.Combine(cache, "catalog.json.asc"), Path.Combine(prepared, "catalog.json.asc"));
            SafeFiles.Write(Path.Combine(prepared, "inventory.json"), SafeFiles.Inventory(content), UpJson.Default.InventoryItemArray);
            var receipt = new Receipt(1, SafeFiles.Owner, sdk, SafeFiles.Hash(Path.Combine(cache, "catalog.json")), catalog.Sequence, DateTimeOffset.UtcNow);
            SafeFiles.Write(Path.Combine(prepared, "receipt.json"), receipt, UpJson.Default.Receipt);
            SafeFiles.Atomic(Path.Combine(prepared, "owner"), System.Text.Encoding.UTF8.GetBytes(SafeFiles.Owner));
            SafeFiles.PrivateDirectory(Path.GetDirectoryName(path)!);
            Directory.Move(prepared, path); // Same-filesystem activation. A crash before this rename cannot expose a partial SDK.
            Activate(sdk, channel); Console.WriteLine("Installed " + sdk.Id);
        }
        finally { SafeFiles.DeleteTree(work); }
    }
    private void Activate(SdkRelease sdk, string? channel = null)
    {
        var selected = Selections(); selected.Active[sdk.SdkVersion] = sdk.Id;
        if (channel is not null) selected = selected with { TrackedChannels = selected.TrackedChannels.Append(channel).Distinct().Order().ToArray() };
        SaveSelection(selected);
        if (File.Exists(Path.Combine(Root, "shell-enabled"))) Shell(true);
    }
    internal Receipt Select(string? version, Catalog catalog, bool series = false, bool allowRevoked = false)
    {
        var installed = Installed(); var selection = Selections();
        var candidates = installed.Where(r => version is null || (series ? r.Release.Series == version : r.Release.SdkVersion == version || $"{r.Release.SdkVersion}-r{r.Release.Revision}" == version)).ToArray();
        SafeFiles.Require(candidates.Length > 0, "No matching Community Build SDK is installed");
        var chosen = candidates[0];
        if (version is null || !version.Contains("-r", StringComparison.Ordinal))
        {
            if (selection.Active.TryGetValue(chosen.Release.SdkVersion, out var id)) chosen = candidates.FirstOrDefault(r => r.Release.Id == id) ?? chosen;
        }
        VerifyInstalled(chosen, catalog, allowRevoked); return chosen;
    }
    internal int Run(Catalog catalog, string? version, string[] arguments, bool series = false)
    {
        var sdk = Select(version, catalog, series).Release;
        var launcher = Path.Combine(PathFor(sdk), "content", sdk.ArchiveRoot, "cbodotnet");
        var start = new ProcessStartInfo(launcher) { UseShellExecute = false };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        // Existing signed archive wrapper sets the selected host root and branding itself.
        using var child = Process.Start(start) ?? throw new InvalidOperationException("Cannot execute the installed SDK");
        child.WaitForExit(); return child.ExitCode;
    }
    internal void Remove(Catalog catalog, string version)
    {
        var receipt = Select(version, catalog, allowRevoked: true); var sdk = receipt.Release; var path = PathFor(sdk);
        var trash = Path.Combine(staging, Guid.NewGuid().ToString("N"));
        Directory.Move(path, trash); SafeFiles.DeleteTree(trash);
        var parent = Path.GetDirectoryName(path)!; if (!Directory.EnumerateFileSystemEntries(parent).Any()) Directory.Delete(parent);
        var selected = Selections(); selected.Active.Remove(sdk.SdkVersion); SaveSelection(selected);
        if (File.Exists(Path.Combine(Root, "shell-enabled"))) Shell(true);
        Console.WriteLine("Removed " + sdk.Id);
    }
    internal void Rollback(Catalog catalog, string version)
    { var receipt = Select(version, catalog); Activate(receipt.Release); Console.WriteLine("Selected retained verified SDK " + receipt.Release.Id); }
    internal async Task Update(Catalog catalog)
    {
        var channels = Selections().TrackedChannels;
        SafeFiles.Require(channels.Length > 0, "No tracked channels; use install --channel 10.0");
        foreach (var channel in channels)
        { SafeFiles.Require(catalog.Channels.TryGetValue(channel, out var version), "Tracked channel is unavailable in the current signed catalog"); await Install(catalog, version!, channel); }
    }
    internal void Shell(bool enable)
    {
        var bin = Path.Combine(Root, "bin"); SafeFiles.PrivateDirectory(bin);
        var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Cannot find the running installer binary");
        var expected = Installed().Select(r => "cbodotnet-" + r.Release.Series).Append("cbodotnet").Distinct().ToHashSet(StringComparer.Ordinal);
        foreach (var path in Directory.EnumerateFileSystemEntries(bin))
            SafeFiles.Require(new FileInfo(path).LinkTarget == executable && (Path.GetFileName(path) == "cbodotnet" || Path.GetFileName(path).StartsWith("cbodotnet-", StringComparison.Ordinal)), "Refusing to replace/remove an unrelated shell file: " + path);
        foreach (var path in Directory.EnumerateFileSystemEntries(bin))
            if (!enable || !expected.Contains(Path.GetFileName(path))) File.Delete(path);
        if (enable)
        {
            foreach (var name in expected)
            {
                var path = Path.Combine(bin, name);
                if (!SafeFiles.Exists(path)) File.CreateSymbolicLink(path, executable);
            }
            SafeFiles.Atomic(Path.Combine(Root, "shell-enabled"), System.Text.Encoding.UTF8.GetBytes(SafeFiles.Owner));
            Console.WriteLine("Add this directory to PATH explicitly: " + bin);
        }
        else { File.Delete(Path.Combine(Root, "shell-enabled")); Console.WriteLine("Removed owned aliases"); }
    }
    internal void Collect()
    {
        foreach (var directory in Directory.EnumerateDirectories(staging))
        {
            SafeFiles.OrdinaryPath(directory);
            SafeFiles.Require(Guid.TryParseExact(Path.GetFileName(directory), "N", out _) && File.ReadAllText(Path.Combine(directory, "owner")) == SafeFiles.Owner, "Unowned staging directory; leaving it intact");
            SafeFiles.DeleteTree(directory);
        }
        Console.WriteLine("Removed abandoned owned staging data; retained installed SDKs");
    }
    internal void Doctor(Catalog catalog)
    {
        foreach (var receipt in Installed()) VerifyInstalled(receipt, catalog);
        Console.WriteLine($"cbodotnetup 0.1.0; {host.Os} {host.VersionId}; {host.Rid}\nRoot: {Root}\nPinned signer: {Trust.Fingerprint}\nInstalled SDKs verified: {Installed().Length}");
    }
    internal async Task SelfUpdate(Catalog catalog, string? executableOverride = null)
    {
        Trust.Validate(catalog, DateTimeOffset.UtcNow);
        var executable = executableOverride ?? Environment.ProcessPath!; SafeFiles.OrdinaryPath(executable);
        var ownershipPath = executable + ".ownership.json";
        var ownership = SafeFiles.Read(ownershipPath, UpJson.Default.ToolOwnership);
        SafeFiles.Require(ownership.Owner == SafeFiles.Owner && ownership.Path == executable && ownership.Sha256 == SafeFiles.Hash(executable), "Tool is not owned by the verified bootstrap; reinstall it using get-cbodotnetup.py");
        var notices = executable + ".LICENSE.txt"; SafeFiles.OrdinaryPath(notices);
        SafeFiles.Require(ownership.NoticesSha256 == SafeFiles.Hash(notices), "Installed tool license/notice bytes changed");
        var latest = catalog.Tools.Where(t => t.Rid == host.Rid && !catalog.Revoked.Contains("tool/" + t.Version + '/' + t.Rid)).OrderByDescending(t => Version.Parse(t.Version)).FirstOrDefault();
        SafeFiles.Require(latest is not null, "No admitted tool release for this architecture");
        SafeFiles.Require(Version.Parse(latest!.Version) >= Version.Parse(ownership.Version), "Tool downgrade refused");
        if (latest.Version == ownership.Version) { SafeFiles.Require(latest.Binary.Sha256 == ownership.Sha256 && latest.Notices.Sha256 == ownership.NoticesSha256, "Conflicting bytes under the existing tool identity"); Console.WriteLine("Installer is current"); return; }
        var incoming = executable + "." + Guid.NewGuid().ToString("N") + ".tmp";
        var incomingNotices = incoming + ".LICENSE.txt";
        try
        {
            await Download(latest.Binary, incoming); if (OperatingSystem.IsLinux()) File.SetUnixFileMode(incoming, (UnixFileMode)0x1ED);
            await Download(latest.Notices, incomingNotices);
            var noticeBytes = File.ReadAllBytes(incomingNotices);
            SafeFiles.Require(noticeBytes.LongLength == latest.Notices.Size && SafeFiles.Hash(noticeBytes) == latest.Notices.Sha256, "Updated runtime notices differ from the signed catalog");
            var previous = executable + ".previous";
            if (SafeFiles.Exists(previous)) SafeFiles.Require(!SafeFiles.Link(previous) && ownership.PreviousSha256 == SafeFiles.Hash(previous), "Previous recovery tool is not owned");
            File.Copy(executable, previous, true); if (OperatingSystem.IsLinux()) File.SetUnixFileMode(previous, (UnixFileMode)0x1ED);
            var previousNotices = previous + ".LICENSE.txt"; SafeFiles.OrdinaryPath(previousNotices);
            if (File.Exists(previousNotices)) SafeFiles.Require(catalog.Tools.Any(t => t.Version == ownership.PreviousVersion && t.Rid == host.Rid && t.Notices.Sha256 == SafeFiles.Hash(previousNotices)), "Previous tool notices are not owned");
            File.Copy(notices, previousNotices, true);
            SafeFiles.Atomic(notices, noticeBytes);
            File.Move(incoming, executable, true);
            SafeFiles.Write(ownershipPath, new ToolOwnership(SafeFiles.Owner, executable, latest.Version, latest.Binary.Sha256, latest.Notices.Sha256, ownership.Version, ownership.Sha256), UpJson.Default.ToolOwnership);
            Console.WriteLine("Updated installer to " + latest.Version + "; retained " + previous);
        }
        finally { if (File.Exists(incoming)) File.Delete(incoming); if (File.Exists(incomingNotices)) File.Delete(incomingNotices); }
    }

    internal void SelfRollback(Catalog catalog, string? executableOverride = null)
    {
        Trust.Validate(catalog, DateTimeOffset.UtcNow);
        var executable = executableOverride ?? Environment.ProcessPath!; SafeFiles.OrdinaryPath(executable);
        var ownershipPath = executable + ".ownership.json"; var ownership = SafeFiles.Read(ownershipPath, UpJson.Default.ToolOwnership);
        SafeFiles.Require(ownership.Owner == SafeFiles.Owner && ownership.Path == executable && ownership.Sha256 == SafeFiles.Hash(executable), "Current tool ownership differs");
        var target = catalog.Tools.SingleOrDefault(t => t.Version == ownership.PreviousVersion && t.Rid == host.Rid);
        SafeFiles.Require(target is not null && !catalog.Revoked.Contains("tool/" + target.Version + '/' + target.Rid), "No retained unrevoked tool revision is admitted in the current catalog");
        var previous = executable + ".previous"; var notices = previous + ".LICENSE.txt";
        SafeFiles.OrdinaryPath(previous); SafeFiles.OrdinaryPath(notices);
        SafeFiles.Require(ownership.PreviousSha256 == SafeFiles.Hash(previous) && target!.Binary.Sha256 == ownership.PreviousSha256
            && target.Notices.Sha256 == SafeFiles.Hash(notices), "Retained recovery executable/notices differ from signed admission");
        SafeFiles.Atomic(executable + ".LICENSE.txt", File.ReadAllBytes(notices));
        SafeFiles.Atomic(executable, File.ReadAllBytes(previous), true);
        SafeFiles.Write(ownershipPath, new ToolOwnership(SafeFiles.Owner, executable, target.Version, target.Binary.Sha256, target.Notices.Sha256, null, null), UpJson.Default.ToolOwnership);
        File.Delete(previous); File.Delete(notices);
        Console.WriteLine("Restored retained installer " + target.Version);
    }
}
