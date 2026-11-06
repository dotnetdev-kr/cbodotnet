namespace Community.DotNet.Up;

// Provider objects are immutable and separately owned. SDK receipts are the
// reference set; crashes can leave unreferenced objects, never partial SDKs.
internal sealed class ProviderStore
{
    private readonly string root;
    private readonly string staging;
    private readonly string scratch;
    private readonly Trust trust;
    private readonly Func<Asset, string, Task> download;
    internal ProviderStore(string root, string staging, string scratch, Trust trust, Func<Asset, string, Task> download)
    {
        this.root = root; this.staging = staging; this.scratch = scratch; this.trust = trust; this.download = download;
        SafeFiles.PrivateDirectory(root);
    }
    private string PathFor(ProviderRelease provider) => SafeFiles.Under(root, provider.Id);
    private void VerifySource(string directory, ProviderRelease provider)
    {
        var source = Path.Combine(directory, "source-manifest.json"); var signature = source + ".asc";
        SafeFiles.OrdinaryPath(source); SafeFiles.OrdinaryPath(signature);
        SafeFiles.Require(new FileInfo(source).Length == provider.SourceManifest.Size && SafeFiles.Hash(source) == provider.SourceManifest.Sha256
            && new FileInfo(signature).Length == provider.SourceSignature.Size && SafeFiles.Hash(signature) == provider.SourceSignature.Sha256,
            "Retained provider source metadata changed");
        Trust.VerifySignature(source, signature, scratch); ProviderSupport.ValidateSource(source, provider);
    }
    internal string Verify(ProviderRelease provider)
    {
        var directory = PathFor(provider); SafeFiles.OrdinaryPath(directory);
        SafeFiles.OrdinaryPath(Path.Combine(directory, "owner"));
        SafeFiles.Require(File.ReadAllText(Path.Combine(directory, "owner")) == SafeFiles.Owner, "Provider object ownership differs");
        var receipt = SafeFiles.Read(Path.Combine(directory, "receipt.json"), UpJson.Default.ProviderReceipt);
        SafeFiles.Require(receipt.SchemaVersion == 1 && receipt.Owner == SafeFiles.Owner
            && ProviderSupport.Equal(receipt.Release, provider, UpJson.Default.ProviderRelease), "Provider object identity differs from signed admission");
        var admission = Path.Combine(directory, "catalog.json");
        SafeFiles.OrdinaryPath(admission); SafeFiles.OrdinaryPath(admission + ".asc");
        Trust.VerifySignature(admission, admission + ".asc", scratch);
        var original = SafeFiles.Read(admission, UpJson.Default.Catalog); Trust.Validate(original, DateTimeOffset.UtcNow, false);
        SafeFiles.Require(original.SchemaVersion == 3 && original.Sequence == receipt.CatalogSequence && SafeFiles.Hash(admission) == receipt.CatalogSha256
            && original.Providers!.Any(p => ProviderSupport.Equal(p, provider, UpJson.Default.ProviderRelease)),
            "Provider receipt differs from its retained signed catalog");
        var content = Path.Combine(directory, "content");
        var inventory = SafeFiles.Read(Path.Combine(directory, "inventory.json"), UpJson.Default.InventoryItemArray);
        SafeFiles.Require(inventory.SequenceEqual(SafeFiles.Inventory(content)), "Provider bytes, modes, links or inventory changed");
        VerifySource(directory, provider); ProviderSupport.ValidateContent(content, provider);
        return ProviderSupport.ContentRoot(content, provider);
    }
    internal async Task Ensure(Catalog catalog, IEnumerable<ProviderRelease> providers)
    {
        var required = providers.ToArray(); ProviderSupport.CheckHost(required);
        foreach (var provider in required)
        {
            var destination = PathFor(provider);
            if (Directory.Exists(destination)) { Verify(provider); continue; }
            SafeFiles.OrdinaryPath(destination);
            var work = Path.Combine(staging, Guid.NewGuid().ToString("N")); SafeFiles.PrivateDirectory(work);
            SafeFiles.Atomic(Path.Combine(work, "owner"), System.Text.Encoding.UTF8.GetBytes(SafeFiles.Owner));
            try
            {
                var prepared = Path.Combine(work, "prepared"); SafeFiles.PrivateDirectory(prepared);
                await download(provider.SourceManifest, Path.Combine(prepared, "source-manifest.json"));
                await download(provider.SourceSignature, Path.Combine(prepared, "source-manifest.json.asc"));
                VerifySource(prepared, provider);
                var archive = Path.Combine(work, "provider.tar.gz"); await download(provider.Archive, archive);
                var content = Path.Combine(prepared, "content"); SafeFiles.ExtractProvider(archive, content);
                ProviderSupport.ValidateContent(content, provider); trust.Retain(catalog, prepared);
                SafeFiles.Write(Path.Combine(prepared, "inventory.json"), SafeFiles.Inventory(content), UpJson.Default.InventoryItemArray);
                SafeFiles.Write(Path.Combine(prepared, "receipt.json"), new ProviderReceipt(1, SafeFiles.Owner, provider,
                    SafeFiles.Hash(Path.Combine(prepared, "catalog.json")), catalog.Sequence, DateTimeOffset.UtcNow), UpJson.Default.ProviderReceipt);
                SafeFiles.Atomic(Path.Combine(prepared, "owner"), System.Text.Encoding.UTF8.GetBytes(SafeFiles.Owner));
                SafeFiles.PrivateDirectory(Path.GetDirectoryName(destination)!);
                Directory.Move(prepared, destination);
            }
            finally { SafeFiles.DeleteTree(work); }
        }
    }
    private IEnumerable<(string Directory, ProviderRelease Provider)> Objects()
    {
        foreach (var version in Directory.EnumerateDirectories(root))
        {
            SafeFiles.OrdinaryPath(version);
            foreach (var directory in Directory.EnumerateDirectories(version))
            {
                SafeFiles.OrdinaryPath(directory);
                var receipt = SafeFiles.Read(Path.Combine(directory, "receipt.json"), UpJson.Default.ProviderReceipt);
                SafeFiles.Require(receipt.Owner == SafeFiles.Owner && receipt.SchemaVersion == 1 && PathFor(receipt.Release) == directory,
                    "Unowned or misplaced provider object; leaving it intact");
                yield return (directory, receipt.Release);
            }
        }
    }
    internal void Doctor() { foreach (var item in Objects()) Verify(item.Provider); }
    internal void Collect(ISet<string> referenced)
    {
        foreach (var item in Objects().ToArray())
        {
            Verify(item.Provider);
            if (referenced.Contains(item.Provider.Id)) continue;
            var version = Path.GetDirectoryName(item.Directory)!;
            SafeFiles.DeleteTree(item.Directory);
            if (!Directory.EnumerateFileSystemEntries(version).Any()) Directory.Delete(version);
        }
    }
}
