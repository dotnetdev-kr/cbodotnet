using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Community.DotNet.Up;

internal static partial class ProviderSupport
{
    internal const string BaseId = "rocky9-20261104";
    internal const string CurlId = "rocky8-curl-20261104";
    internal static readonly string[] X64Flags = ["cx16", "lahf_lm", "popcnt", "pni", "ssse3", "sse4_1", "sse4_2"];
    internal static string Revocation(ProviderRelease provider) => "provider/" + provider.Id;
    internal static bool Equal<T>(T first, T second, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> info)
        => JsonSerializer.SerializeToUtf8Bytes(first, info).AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(second, info));
    private static bool Hash(string? value) => value is not null && Regex.IsMatch(value, "^[a-f0-9]{64}$", RegexOptions.CultureInvariant);
    internal static void Validate(Catalog catalog)
    {
        if (catalog.SchemaVersion != 3)
        {
            SafeFiles.Require(catalog.CompatibilityCatalog is null && catalog.Providers is null && catalog.ProviderBindings is null,
                "Provider metadata requires the separate schema-3 feed"); return;
        }
        SafeFiles.Require(catalog.CompatibilityCatalog is not null && catalog.Providers is { Length: <= 32 }
            && catalog.ProviderBindings is { Length: <= 32 }, "Schema-3 provider admission is incomplete");
        Trust.AssetValid(catalog.CompatibilityCatalog!, 8 * 1024 * 1024);
        SafeFiles.Require(catalog.CompatibilityCatalog!.Url == $"https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-catalog-{catalog.Sequence}/catalog-v2.json",
            "The compatible catalog must be the exact immutable schema-2 projection");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var provider in catalog.Providers!)
        {
            SafeFiles.Require(provider is not null && provider.ProviderId is BaseId or CurlId && provider.Version == "2026.11.4"
                && provider.Revision > 0 && provider.Rid is "linux-x64" or "linux-arm64" && ids.Add(provider.Id)
                && provider.Libc == "glibc" && Version.TryParse(provider.MinimumGlibc, out var minimum) && minimum.Build == -1
                && minimum >= new Version(provider.ProviderId == BaseId ? "2.34" : "2.17")
                && provider.Root == "/usr/lib/cbodotnet/compat/" + (provider.ProviderId == BaseId ? "rocky9" : "curl-rocky8")
                && Hash(provider.ManifestSha256) && Hash(provider.PolicySha256)
                && provider.SecuritySupport == "community-build-no-additional-security-maintenance"
                && provider.Targets is { Length: > 0 } && provider.Targets.Distinct().Count() == provider.Targets.Length
                && provider.Targets.All(t => t is not null && t.Rid == provider.Rid && new[] { ("ubuntu", "24.04"), ("debian", "13"), ("fedora", "45"), ("rocky", "9.8") }.Contains((t.Os, t.VersionId)))
                && provider.Manifest.ValueKind == JsonValueKind.Object && provider.CpuFlags is not null,
                "Malformed, cross-libc or duplicate legacy provider admission");
            var x64Base = provider.Rid == "linux-x64" && provider.ProviderId == BaseId;
            SafeFiles.Require(provider.CpuBaseline == (provider.Rid == "linux-arm64" ? "armv8-a" : x64Base ? "x86-64-v2" : "x86-64")
                && provider.CpuFlags.SequenceEqual(x64Base ? X64Flags : []), "Unsupported provider CPU baseline");
            var manifest = provider.Manifest;
            SafeFiles.Require(manifest.GetProperty("schemaVersion").GetInt32() == 1
                && manifest.GetProperty("providerId").GetString() == provider.ProviderId
                && manifest.GetProperty("providerRoot").GetString() == provider.Root
                && manifest.GetProperty("architecture").GetString() == (provider.Rid == "linux-x64" ? "x64" : "aarch64")
                && manifest.GetProperty("policySha256").GetString() == provider.PolicySha256
                && manifest.GetProperty("signingFingerprint").GetString() == (provider.ProviderId == BaseId
                    ? "21CB256AE16FC54C6E652949702D426D350D275D" : "7051C470A929F454CEBE37B715AF5DAC6D745A60")
                && manifest.GetProperty("packages").ValueKind == JsonValueKind.Array
                && manifest.GetProperty("sourcePackages").ValueKind == JsonValueKind.Array
                && manifest.GetProperty("files").ValueKind == JsonValueKind.Array,
                "Provider vendor inputs or policy differ from the signed provider record");
            Trust.AssetValid(provider.Archive); Trust.AssetValid(provider.SourceManifest, 8 * 1024 * 1024);
            Trust.AssetValid(provider.SourceSignature, 64 * 1024);
            var sourceVersion = provider.ProviderId == BaseId ? "5.0.214" : "3.1.426";
            var prefix = $"https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-{sourceVersion}-r2/";
            SafeFiles.Require(provider.SourceManifest.Url == prefix + "distribution-manifest.json"
                && provider.SourceSignature.Url == provider.SourceManifest.Url + ".asc"
                && provider.Archive.Url == prefix + (provider.ProviderId == BaseId ? "cbodotnet-compat-rocky9-" : "cbodotnet-compat-curl-rocky8-")
                    + provider.Version + "-linux-" + (provider.Rid == "linux-x64" ? "x64" : "aarch64") + ".tar.gz",
                "Provider archive/source origin differs from the reviewed immutable companion release");
        }
        var sdkIds = new HashSet<string>(StringComparer.Ordinal); var used = new HashSet<string>(StringComparer.Ordinal);
        foreach (var binding in catalog.ProviderBindings!)
        {
            SafeFiles.Require(binding is not null, "A legacy SDK provider binding is null");
            var sdk = catalog.Sdks.SingleOrDefault(s => s.Id == binding.SdkId);
            SafeFiles.Require(sdk is not null && sdk.RequiresLegacyProvider && sdk.SdkVersion is "5.0.214" or "3.1.426" or "3.0.103"
                && sdkIds.Add(binding.SdkId) && binding.SourceManifestSha256 == sdk.SourceManifestSha256
                && binding.ArchiveSha256 == sdk.Archive.Sha256 && binding.ProviderIds is { Length: > 0 and <= 2 }
                && binding.ProviderIds.Distinct().Count() == binding.ProviderIds.Length,
                "Provider binding differs from its exact SDK/source/archive identity");
            var expected = sdk.SdkVersion.StartsWith("3.", StringComparison.Ordinal) ? new[] { BaseId, CurlId } : [BaseId];
            var providers = binding.ProviderIds.Select(id => catalog.Providers!.SingleOrDefault(p => p.Id == id)).ToArray();
            SafeFiles.Require(providers.All(p => p is not null && p.Rid == sdk.Rid && sdk.Targets.All(p.Targets.Contains))
                && providers.Select(p => p!.ProviderId).SequenceEqual(expected), "SDK provider set, order or target coverage is incomplete");
            foreach (var id in binding.ProviderIds) used.Add(id);
        }
        SafeFiles.Require(catalog.Sdks.Where(s => s.RequiresLegacyProvider).Select(s => s.Id).ToHashSet(StringComparer.Ordinal).SetEquals(sdkIds)
            && used.SetEquals(ids), "Every legacy SDK and provider must have an exact binding");
    }
    internal static ProviderRelease[] For(Catalog catalog, SdkRelease sdk, Target host, bool allowRevoked = false)
    {
        SafeFiles.Require(catalog.SchemaVersion == 3 && catalog.ProviderBindings is not null && catalog.Providers is not null,
            "This SDK needs the schema-3 signed provider catalog; refresh with list --available");
        var binding = catalog.ProviderBindings!.SingleOrDefault(b => b.SdkId == sdk.Id);
        SafeFiles.Require(binding is not null && binding.SourceManifestSha256 == sdk.SourceManifestSha256
            && binding.ArchiveSha256 == sdk.Archive.Sha256, "SDK has no exact authenticated provider binding");
        return binding.ProviderIds.Select(id =>
        {
            var provider = catalog.Providers!.SingleOrDefault(p => p.Id == id);
            SafeFiles.Require(provider is not null && provider.Rid == host.Rid && provider.Targets.Contains(host)
                && (allowRevoked || !catalog.Revoked.Contains(Revocation(provider))), "Legacy provider is revoked or not individually qualified for this host");
            return provider;
        }).ToArray();
    }
    internal static bool Eligible(Catalog catalog, SdkRelease sdk, Target host)
    {
        try { _ = For(catalog, sdk, host); return true; }
        catch (InvalidOperationException) { return false; }
    }
    internal static void CheckCapabilities(ProviderRelease provider, string glibc, IEnumerable<IEnumerable<string>> processorFlags)
    {
        SafeFiles.Require(provider.Libc == "glibc" && Version.TryParse(glibc, out var actual)
            && actual >= Version.Parse(provider.MinimumGlibc), "Legacy provider ABI requires glibc >= " + provider.MinimumGlibc);
        if (provider.CpuFlags.Length == 0) return;
        var rows = processorFlags.Select(flags => flags.ToHashSet(StringComparer.Ordinal)).ToArray();
        SafeFiles.Require(rows.Length > 0 && rows.All(flags => provider.CpuFlags.All(flag => flags.Contains(flag)
            || flag == "pni" && flags.Contains("sse3"))), "Legacy provider ABI requires an x86-64-v2 CPU on every processor");
    }
    internal static void CheckHost(IEnumerable<ProviderRelease> providers)
    {
        SafeFiles.Require(OperatingSystem.IsLinux(), "Legacy providers require the qualified glibc Linux host");
        var glibc = Marshal.PtrToStringAnsi(GlibcVersion()) ?? "";
        var rows = File.ReadLines("/proc/cpuinfo").Where(line => line.StartsWith("flags", StringComparison.Ordinal) && line.Contains(':'))
            .Select(line => line[(line.IndexOf(':') + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries)).ToArray();
        foreach (var provider in providers) CheckCapabilities(provider, glibc, rows);
    }
    internal static void CheckOwnedRoot(string root)
    {
        SafeFiles.Require(!string.IsNullOrEmpty(root) && root.StartsWith("/", StringComparison.Ordinal)
            && !root.Any(c => char.IsControl(c) || c is ':' or ';' or '$'),
            "Legacy provider roots cannot contain loader separators (: or ;) or $ tokens. Choose an ordinary absolute CBODOTNETUP_HOME; spaces are supported.");
    }
    [LibraryImport("libc.so.6", EntryPoint = "gnu_get_libc_version")] private static partial IntPtr GlibcVersion();

    internal static void ValidateSource(string source, ProviderRelease provider)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(source)); SafeFiles.CheckJson(document.RootElement);
        var value = document.RootElement; var name = Path.GetFileName(new Uri(provider.Archive.Url).AbsolutePath);
        SafeFiles.Require(value.GetProperty("schemaVersion").GetInt32() == 1
            && value.GetProperty("kind").GetString() == "branded-consumer-archive-publication"
            && value.GetProperty("status").GetString() == "validated-complete-matrix"
            && value.GetProperty("repository").GetString() == "dotnetdev-kr/cbodotnet"
            && value.GetProperty("signingFingerprint").GetString() == Trust.Fingerprint,
            "Provider source manifest identity differs");
        var identity = value.GetProperty("identity"); var version = provider.ProviderId == BaseId ? "5.0.214" : "3.1.426";
        SafeFiles.Require(identity.GetProperty("channel").GetString() == "archive" && identity.GetProperty("packageRevision").GetInt32() == 2
            && identity.GetProperty("sdkVersion").GetString() == version && identity.GetProperty("sourceReleaseTag").GetString() == "sdk-" + version
            && Hash(identity.GetProperty("sourceManifestSha256").GetString()), "Provider source release/producer identity differs");
        var assets = value.GetProperty("assets").EnumerateArray().Where(a => a.GetProperty("name").GetString() == name).ToArray();
        SafeFiles.Require(assets.Length == 1 && assets[0].GetProperty("size").GetInt64() == provider.Archive.Size
            && assets[0].GetProperty("sha256").GetString() == provider.Archive.Sha256, "Provider archive is not bound by its original signed source manifest");
        var field = provider.ProviderId == BaseId ? "compatibility" : "nativeHttpCompatibility";
        var rows = value.GetProperty(field).EnumerateArray().Where(a => a.GetProperty("architecture").GetString()
            == (provider.Rid == "linux-x64" ? "x64" : "aarch64") && a.GetProperty("asset").GetString() == name).ToArray();
        SafeFiles.Require(rows.Length == 1 && JsonElement.DeepEquals(rows[0].GetProperty("record").GetProperty("manifest"), provider.Manifest),
            "Provider manifest differs from the original signed source record");
        var record = rows[0].GetProperty("record"); var companion = record.GetProperty("companion");
        SafeFiles.Require(record.GetProperty("schemaVersion").GetInt32() == 1 && record.GetProperty("providerRoot").GetString() == provider.Root
            && record.GetProperty("policySha256").GetString() == provider.PolicySha256
            && companion.GetProperty("path").GetString() == name && companion.GetProperty("size").GetInt64() == provider.Archive.Size
            && companion.GetProperty("sha256").GetString() == provider.Archive.Sha256, "Provider source companion descriptor differs");
    }
    internal static string ContentRoot(string content, ProviderRelease provider) => SafeFiles.Under(content, "rootfs/" + provider.Root.TrimStart('/'));
    internal static void ValidateContent(string content, ProviderRelease provider)
    {
        var outer = Path.Combine(content, "provider-manifest.json"); var root = ContentRoot(content, provider);
        SafeFiles.OrdinaryPath(root); SafeFiles.OrdinaryPath(outer);
        var inner = Path.Combine(root, "provider-manifest.json"); SafeFiles.OrdinaryPath(inner);
        SafeFiles.Require(SafeFiles.Hash(outer) == provider.ManifestSha256 && File.ReadAllBytes(outer).AsSpan().SequenceEqual(File.ReadAllBytes(inner)),
            "Provider outer/inner manifest hashes differ");
        using var document = JsonDocument.Parse(File.ReadAllBytes(outer)); SafeFiles.CheckJson(document.RootElement);
        SafeFiles.Require(JsonElement.DeepEquals(document.RootElement, provider.Manifest), "Provider extracted manifest differs from signed catalog");
        var actual = SafeFiles.Inventory(root).Where(i => i.Path != "provider-manifest.json").ToDictionary(i => i.Path, StringComparer.Ordinal);
        var expected = provider.Manifest.GetProperty("files").EnumerateArray().ToArray();
        SafeFiles.Require(actual.Count == expected.Length, "Provider contains missing or unaccounted files");
        foreach (var row in expected)
        {
            var name = row.GetProperty("path").GetString()!; _ = SafeFiles.Under(root, name);
            SafeFiles.Require(actual.TryGetValue(name, out var item), "Provider manifest file is missing: " + name);
            var type = row.GetProperty("type").GetString();
            SafeFiles.Require(type == "symlink" ? item.Kind == "link" && item.Link == row.GetProperty("target").GetString()
                : item.Kind == type && (!OperatingSystem.IsLinux() || item.Mode == Convert.ToInt32(row.GetProperty("mode").GetString()![2..], 8))
                    && (type != "file" || item.Size == row.GetProperty("size").GetInt64() && item.Sha256 == row.GetProperty("sha256").GetString()),
                "Provider file bytes, mode or link differs: " + name);
        }
        var rootRelative = Path.GetRelativePath(content, root).Replace('\\', '/');
        foreach (var item in SafeFiles.Inventory(content))
            SafeFiles.Require(item.Path == "provider-manifest.json" && item.Kind == "file"
                || item.Path == rootRelative || rootRelative.StartsWith(item.Path + '/', StringComparison.Ordinal) && item.Kind == "directory"
                || item.Path.StartsWith(rootRelative + '/', StringComparison.Ordinal), "Provider rootfs contains an unrelated path");
        foreach (var name in provider.ProviderId == BaseId ? new[] { "LICENSE.openssl.txt", "LICENSE.icu.txt", "NOTICE.txt", "openssl.cnf", "lib/libssl.so.1.1", "lib/libcrypto.so.1.1" }
            : ["LICENSE.curl.txt", "NOTICE.txt", "lib/libcurl.so.4.5.0"])
            SafeFiles.Require(File.Exists(SafeFiles.Under(root, name)), "Provider notice or required native component is absent: " + name);
    }
}
