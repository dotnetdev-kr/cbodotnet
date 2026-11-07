using System.Text.Json;
using System.Text.Json.Serialization;

namespace Community.DotNet.Up;

internal sealed record Asset(string Url, long Size, string Sha256);
internal sealed record Target(string Os, string VersionId, string Rid);
internal sealed record SdkRelease(string SdkVersion, int Revision, string Rid, string ArchiveRoot,
    Asset Archive, string SourceManifestSha256, Asset SourceManifest, JsonElement Producer,
    Asset Evidence, string[] LicensePaths, string SecuritySupport, string[] Dependencies,
    Target[] Targets, bool RequiresLegacyProvider)
{
    [JsonIgnore] public string Id => $"{SdkVersion}-r{Revision}/{Rid}";
    [JsonIgnore] public string Series => string.Join('.', SdkVersion.Split('.')[..2]);
}
internal sealed record ToolRelease(string Version, string Rid, Asset Binary, Asset Notices);
internal sealed record Catalog(int SchemaVersion, string Kind, long Sequence, DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt, string SigningFingerprint, string[] Revoked,
    SdkRelease[] Sdks, ToolRelease[] Tools, Dictionary<string, string> Channels,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] Asset? CompatibilityCatalog = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ProviderRelease[]? Providers = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] ProviderBinding[]? ProviderBindings = null,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Libc = null);
internal sealed record ProviderRelease(string ProviderId, string Version, int Revision, string Rid, string Root,
    Asset Archive, string ManifestSha256, string PolicySha256, string Libc, string MinimumGlibc,
    string CpuBaseline, string[] CpuFlags, Target[] Targets, string SecuritySupport, JsonElement Manifest,
    Asset SourceManifest, Asset SourceSignature)
{
    [JsonIgnore] public string Id => $"{ProviderId}-r{Revision}/{Rid}";
}
internal sealed record ProviderBinding(string SdkId, string SourceManifestSha256, string ArchiveSha256, string[] ProviderIds);
internal sealed record Receipt(int SchemaVersion, string Owner, SdkRelease Release, string CatalogSha256,
    long CatalogSequence, DateTimeOffset InstalledAt);
internal sealed record ProviderReceipt(int SchemaVersion, string Owner, ProviderRelease Release,
    string CatalogSha256, long CatalogSequence, DateTimeOffset InstalledAt);
internal sealed record ProviderReferences(int SchemaVersion, string SdkId, string[] ProviderIds);
internal sealed record InventoryItem(string Path, string Kind, int Mode, long Size, string Sha256, string? Link);
internal sealed record HighWater(long Sequence, string Sha256);
internal sealed record ToolOwnership(string Owner, string Path, string Version, string Sha256,
    string NoticesSha256, string? PreviousVersion, string? PreviousSha256);
internal sealed record Selection(Dictionary<string, string> Active, string[] TrackedChannels);

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = true, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
[JsonSerializable(typeof(Catalog))]
[JsonSerializable(typeof(Receipt))]
[JsonSerializable(typeof(ProviderReceipt))]
[JsonSerializable(typeof(ProviderReferences))]
[JsonSerializable(typeof(InventoryItem[]))]
[JsonSerializable(typeof(HighWater))]
[JsonSerializable(typeof(ToolOwnership))]
[JsonSerializable(typeof(Selection))]
internal partial class UpJson : JsonSerializerContext;
