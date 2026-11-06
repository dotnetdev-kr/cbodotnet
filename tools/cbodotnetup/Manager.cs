using System.Diagnostics;
using System.Text.Json;

namespace Community.DotNet.Up;

internal sealed class Manager : IDisposable
{
    internal readonly string Root;
    private readonly string toolchains;
    private readonly string modernToolchains;
    private readonly string providerToolchains;
    private readonly string cache;
    private readonly string staging;
    private readonly FileStream lease;
    private readonly Trust trust;
    private readonly ProviderStore providers;
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
        toolchains = Path.Combine(Root, "toolchains"); modernToolchains = Path.Combine(Root, "toolchains-v2");
        providerToolchains = Path.Combine(Root, "toolchains-v3");
        // The released 0.1 client must retain its own catalog/high-water and SDK namespace.
        // It cannot validate v2 admissions after a tool rollback, so it must not enumerate them.
        var legacyCache = Path.Combine(Root, "cache"); SafeFiles.PrivateDirectory(legacyCache);
        cache = Path.Combine(legacyCache, "v3"); staging = Path.Combine(Root, "staging");
        foreach (var path in new[] { toolchains, modernToolchains, providerToolchains, Path.Combine(legacyCache, "v2"), cache, staging }) SafeFiles.PrivateDirectory(path);
        trust = new Trust(cache);
        providers = new ProviderStore(Path.Combine(Root, "providers"), staging, cache, trust, Download);
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
    private string PathFor(SdkRelease sdk) => SafeFiles.Under(sdk.RequiresLegacyProvider ? providerToolchains : Trust.ArchiveSchema(sdk) == 1 ? toolchains : modernToolchains, sdk.Id);
    private Selection Selections() => File.Exists(Path.Combine(Root, "selection.json"))
        ? SafeFiles.Read(Path.Combine(Root, "selection.json"), UpJson.Default.Selection) : new(new(StringComparer.Ordinal), []);
    private void SaveSelection(Selection value) => SafeFiles.Write(Path.Combine(Root, "selection.json"), value, UpJson.Default.Selection);
    internal Receipt[] Installed()
    {
        var result = new List<Receipt>();
        foreach (var version in new[] { toolchains, modernToolchains, providerToolchains }.SelectMany(Directory.EnumerateDirectories))
        {
            SafeFiles.OrdinaryPath(version);
            foreach (var directory in Directory.EnumerateDirectories(version))
            {
                SafeFiles.OrdinaryPath(directory);
                var receipt = SafeFiles.Read(Path.Combine(directory, "receipt.json"), UpJson.Default.Receipt);
                SafeFiles.Require(receipt.Owner == SafeFiles.Owner && receipt.SchemaVersion == (receipt.Release.RequiresLegacyProvider ? 2 : 1)
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
        if (sdk.RequiresLegacyProvider)
        {
            var required = ProviderSupport.For(allowRevoked ? original : catalog, sdk, host, allowRevoked);
            var references = SafeFiles.Read(Path.Combine(path, "providers.json"), UpJson.Default.ProviderReferences);
            SafeFiles.Require(receipt.SchemaVersion == 2 && original.SchemaVersion == 3 && references.SchemaVersion == 1
                && references.SdkId == sdk.Id && references.ProviderIds.SequenceEqual(required.Select(p => p.Id)),
                "Legacy SDK provider references differ from signed admission");
            var retainedBinding = ProviderSupport.For(original, sdk, host, true);
            SafeFiles.Require(references.ProviderIds.SequenceEqual(retainedBinding.Select(p => p.Id)), "Retained SDK provider binding changed");
            if (!allowRevoked)
            {
                ProviderSupport.CheckOwnedRoot(Root); ProviderSupport.CheckHost(required);
            }
            foreach (var provider in required) providers.Verify(provider);
        }
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
    internal async Task Install(Catalog catalog, string version, string? channel = null, bool allowLegacyProviders = false)
    {
        Trust.Validate(catalog, DateTimeOffset.UtcNow);
        var sdk = Resolve(catalog, version); var path = PathFor(sdk);
        if (Directory.Exists(path))
        {
            var previous = SafeFiles.Read(Path.Combine(path, "receipt.json"), UpJson.Default.Receipt);
            SafeFiles.Require(SdkComparer.Instance.Equals(previous.Release, sdk), "Existing identity has conflicting catalog bytes");
            VerifyInstalled(previous, catalog); Activate(sdk, channel); Console.WriteLine("Already installed and verified: " + sdk.Id); return;
        }
        var required = sdk.RequiresLegacyProvider ? ProviderSupport.For(catalog, sdk, host) : [];
        if (sdk.RequiresLegacyProvider)
        {
            SafeFiles.Require(allowLegacyProviders, "This SDK requires signed private legacy providers. Install explicitly with: cbodotnetup install "
                + sdk.SdkVersion + "-r" + sdk.Revision + " --with-legacy-providers");
            await providers.Ensure(catalog, required);
        }
        var admission = !sdk.RequiresLegacyProvider && catalog.SchemaVersion == 3 ? await trust.Compatibility(catalog) : catalog;
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
                    && p.GetProperty("targetRid").GetString() == host.Rid && p.GetProperty("compatibility").GetProperty("required").GetBoolean() == sdk.RequiresLegacyProvider
                    && JsonElement.DeepEquals(p.GetProperty("producer"), sdk.Producer), "Archive provenance differs from signed catalog");
                if (sdk.RequiresLegacyProvider)
                {
                    foreach (var provider in required)
                    {
                        var item = p.GetProperty(provider.ProviderId == ProviderSupport.BaseId ? "compatibility" : "nativeHttpCompatibility");
                        SafeFiles.Require(item.GetProperty("required").GetBoolean() && item.GetProperty("providerId").GetString() == provider.ProviderId
                            && item.GetProperty("root").GetString() == provider.Root && item.GetProperty("policySha256").GetString() == provider.PolicySha256
                            && item.GetProperty("companionName").GetString() == Path.GetFileName(new Uri(provider.Archive.Url).AbsolutePath),
                            "Archive provider provenance differs from signed catalog");
                    }
                }
            }
            trust.Retain(admission, prepared);
            SafeFiles.Write(Path.Combine(prepared, "inventory.json"), SafeFiles.Inventory(content), UpJson.Default.InventoryItemArray);
            var receipt = new Receipt(sdk.RequiresLegacyProvider ? 2 : 1, SafeFiles.Owner, sdk, SafeFiles.Hash(Path.Combine(prepared, "catalog.json")), admission.Sequence, DateTimeOffset.UtcNow);
            SafeFiles.Write(Path.Combine(prepared, "receipt.json"), receipt, UpJson.Default.Receipt);
            if (sdk.RequiresLegacyProvider) SafeFiles.Write(Path.Combine(prepared, "providers.json"),
                new ProviderReferences(1, sdk.Id, required.Select(p => p.Id).ToArray()), UpJson.Default.ProviderReferences);
            SafeFiles.Atomic(Path.Combine(prepared, "owner"), System.Text.Encoding.UTF8.GetBytes(SafeFiles.Owner));
            SafeFiles.PrivateDirectory(Path.GetDirectoryName(path)!);
            Directory.Move(prepared, path); // Same-filesystem activation. A crash before this rename cannot expose a partial SDK.
            Activate(sdk, channel); Console.WriteLine("Installed " + sdk.Id);
        }
        finally { SafeFiles.DeleteTree(work); }
    }
    private void Activate(SdkRelease sdk, string? channel = null)
    {
        var selected = Selections(); selected.Active[sdk.Series] = sdk.Id;
        if (channel is not null) selected = selected with { TrackedChannels = selected.TrackedChannels.Append(channel).Distinct().Order().ToArray() };
        SaveSelection(selected);
        if (File.Exists(Path.Combine(Root, "shell-enabled"))) Shell(true);
    }
    internal Receipt Select(string? version, Catalog catalog, bool series = false, bool allowRevoked = false)
    {
        var chosen = Choose(Installed(), Selections(), version, series);
        if (!allowRevoked) Trust.Admit(catalog, chosen.Release, host);
        VerifyInstalled(chosen, catalog, allowRevoked); return chosen;
    }
    internal static Receipt Choose(Receipt[] installed, Selection selection, string? version, bool series = false)
    {
        installed = installed.OrderByDescending(r => Version.Parse(r.Release.SdkVersion)).ThenByDescending(r => r.Release.Revision).ToArray();
        var candidates = installed.Where(r => version is null || (series ? r.Release.Series == version : r.Release.SdkVersion == version || $"{r.Release.SdkVersion}-r{r.Release.Revision}" == version)).ToArray();
        SafeFiles.Require(candidates.Length > 0, "No matching Community Build SDK is installed");
        var chosen = candidates[0];
        if (version is null || !version.Contains("-r", StringComparison.Ordinal))
        {
            if (selection.Active.TryGetValue(chosen.Release.Series, out var id)) chosen = candidates.FirstOrDefault(r => r.Release.Id == id && r.Release.Series == chosen.Release.Series) ?? chosen;
        }
        return chosen;
    }
    internal int Run(Catalog catalog, string? version, string[] arguments, bool series = false)
    {
        var sdk = SelectForRun(catalog, version, arguments, series).Release;
        var archive = Path.Combine(PathFor(sdk), "content", sdk.ArchiveRoot);
        var payload = Path.Combine(archive, "payload");
        // Historical consumer wrappers declare the Core3 curl companion but do
        // not activate its environment. Keep those bytes immutable and launch
        // the verified payload host with the manager's complete child scope.
        var start = SdkInvocation.Create(Path.Combine(archive, "cbodotnet"), payload, sdk.SdkVersion, arguments,
            sdk.RequiresLegacyProvider ? sdk.Rid : null);
        var required = sdk.RequiresLegacyProvider ? ProviderSupport.For(catalog, sdk, host) : [];
        ProviderEnvironment.Apply(start, host, required.ToDictionary(p => p.ProviderId, p => providers.Verify(p), StringComparer.Ordinal));
        SdkInvocation.WriteBrand(arguments);
        return RunChild(start);
    }
    internal static int RunChild(ProcessStartInfo start)
    {
        using var child = Process.Start(start) ?? throw new InvalidOperationException("Cannot execute the installed SDK");
        child.WaitForExit(); return child.ExitCode;
    }
    internal Receipt SelectForRun(Catalog catalog, string? version, string[] arguments, bool series = false,
        string? workingDirectory = null)
    {
        // An explicit version or versioned alias takes precedence. Runtime/native
        // host commands keep the existing default and do not engage SDK discovery.
        if (version is not null || !SdkInvocation.UsesSdk(arguments)) return Select(version, catalog, series);
        var request = ProjectSdkResolver.Discover(workingDirectory ?? Directory.GetCurrentDirectory());
        if (request is null || !request.HasSelection) return Select(null, catalog);
        var installed = Installed();
        var resolved = ProjectSdkResolver.SelectVersion(request, installed.Select(r => r.Release.SdkVersion));
        if (resolved is null) throw new InvalidOperationException(MissingProjectSdk(request, catalog));
        var selected = Choose(installed, Selections(), resolved);
        // Select first, then validate; a revoked/corrupt winner must not silently
        // fall back to a different SDK or an official/package-managed root.
        Trust.Admit(catalog, selected.Release, host);
        VerifyInstalled(selected, catalog);
        return selected;
    }
    private string MissingProjectSdk(ProjectSdkRequest request, Catalog catalog)
    {
        var available = catalog.Sdks.Where(s => s.Rid == host.Rid && s.Targets.Contains(host)
            && !catalog.Revoked.Contains(s.Id) && (!s.RequiresLegacyProvider || ProviderSupport.Eligible(catalog, s, host))).ToArray();
        var matching = ProjectSdkResolver.SelectVersion(request, available.Select(s => s.SdkVersion));
        var message = $"No installed Community Build SDK matches '{request.Version ?? "latest"}' with rollForward '{request.RollForward}' in {request.GlobalJsonPath}.";
        if (!string.IsNullOrWhiteSpace(request.ErrorMessage)) message += " " + request.ErrorMessage;
        var install = available.Where(s => s.SdkVersion == matching).OrderByDescending(s => s.Revision).FirstOrDefault();
        return message + (matching is null
            ? " No matching SDK is admitted in the cached signed catalog. Review the project pin or explicitly refresh with cbodotnetup list --available."
            : $" Install it explicitly with: cbodotnetup install {install!.SdkVersion}-r{install.Revision}{(install.RequiresLegacyProvider ? " --with-legacy-providers" : "")}. SDK selection never installs or downloads an SDK automatically.");
    }
    internal void Remove(Catalog catalog, string version)
    {
        var receipt = Select(version, catalog, allowRevoked: true); var sdk = receipt.Release; var path = PathFor(sdk);
        var trash = Path.Combine(staging, Guid.NewGuid().ToString("N"));
        Directory.Move(path, trash); SafeFiles.DeleteTree(trash);
        var parent = Path.GetDirectoryName(path)!; if (!Directory.EnumerateFileSystemEntries(parent).Any()) Directory.Delete(parent);
        var selected = Selections();
        if (selected.Active.GetValueOrDefault(sdk.Series) == sdk.Id) selected.Active.Remove(sdk.Series);
        SaveSelection(selected);
        if (File.Exists(Path.Combine(Root, "shell-enabled"))) Shell(true);
        Console.WriteLine("Removed " + sdk.Id);
    }
    internal void Rollback(Catalog catalog, string version)
    { var receipt = Select(version, catalog); Activate(receipt.Release); Console.WriteLine("Selected retained verified SDK " + receipt.Release.Id); }
    internal async Task Update(Catalog catalog, bool allowLegacyProviders = false)
    {
        var channels = Selections().TrackedChannels;
        SafeFiles.Require(channels.Length > 0, "No tracked channels; use install --channel 10.0");
        foreach (var channel in channels)
        {
            SafeFiles.Require(catalog.Channels.TryGetValue(channel, out var version), "Tracked channel is unavailable in the current signed catalog");
            var consent = allowLegacyProviders;
            if (!consent)
            {
                var prior = Installed().FirstOrDefault(r => r.Release.RequiresLegacyProvider && r.Release.Series == channel);
                if (prior is not null)
                {
                    var signed = Path.Combine(PathFor(prior.Release), "catalog.json");
                    SafeFiles.Require(File.Exists(signed) && File.Exists(signed + ".asc"),
                        "Tracked legacy receipt has no retained signed admission; review and reinstall with explicit provider consent");
                    // A fabricated or damaged receipt must not authorize a new
                    // provider download when a channel advances to another revision.
                    VerifyInstalled(prior, catalog, allowRevoked: true);
                    consent = true;
                }
            }
            await Install(catalog, version!, channel, allowLegacyProviders: consent);
        }
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
        var referenced = new HashSet<string>(StringComparer.Ordinal);
        foreach (var receipt in Installed().Where(r => r.Release.RequiresLegacyProvider))
        {
            var original = SafeFiles.Read(Path.Combine(PathFor(receipt.Release), "catalog.json"), UpJson.Default.Catalog);
            VerifyInstalled(receipt, original, allowRevoked: true);
            foreach (var id in SafeFiles.Read(Path.Combine(PathFor(receipt.Release), "providers.json"), UpJson.Default.ProviderReferences).ProviderIds) referenced.Add(id);
        }
        providers.Collect(referenced);
        Console.WriteLine("Removed abandoned owned staging data and unreferenced verified providers; retained installed SDKs");
    }
    internal void Doctor(Catalog catalog)
    {
        foreach (var receipt in Installed()) VerifyInstalled(receipt, catalog);
        providers.Doctor();
        Console.WriteLine($"cbodotnetup {Program.CurrentVersion}; {host.Os} {host.VersionId}; {host.Rid}\nRoot: {Root}\nPinned signer: {Trust.Fingerprint}\nInstalled SDKs verified: {Installed().Length}");
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
