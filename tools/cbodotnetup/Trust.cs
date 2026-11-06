using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Community.DotNet.Up;

internal sealed partial class Trust
{
    internal const string Fingerprint = "D7D154B4B33C19A82B95B13688135410ACD9C0EA";
    internal const string CatalogUrl = "https://dotnetdev.kr/cbodotnet/cbodotnetup/v3/catalog.json";
    private readonly string cache;
    private string? localCatalogDirectory;
    internal Trust(string cache) { this.cache = cache; SafeFiles.PrivateDirectory(cache); }
    [GeneratedRegex(@"^[a-f0-9]{64}$", RegexOptions.CultureInvariant)] private static partial Regex ShaPattern();
    [GeneratedRegex(@"^[1-9][0-9]*\.[0-9]+\.[0-9]+$", RegexOptions.CultureInvariant)] internal static partial Regex VersionPattern();
    internal static string Rid => RuntimeInformation.ProcessArchitecture switch
    { Architecture.X64 => "linux-x64", Architecture.Arm64 => "linux-arm64", _ => throw new InvalidOperationException("Only Linux x64 and AArch64 are supported") };
    internal static Target Host()
    {
        SafeFiles.Require(OperatingSystem.IsLinux() && SafeFiles.GetEuid() != 0, "Use cbodotnetup as a regular Linux user; do not run it with sudo");
        var os = File.ReadAllLines("/etc/os-release").Where(s => s.Contains('='))
            .Select(s => s.Split('=', 2)).ToDictionary(p => p[0], p => p[1].Trim('"'));
        var target = new Target(os.GetValueOrDefault("ID", ""), os.GetValueOrDefault("VERSION_ID", ""), Rid);
        SafeFiles.Require(new[] { ("ubuntu", "24.04"), ("debian", "13"), ("fedora", "45"), ("rocky", "9.8") }
            .Contains((target.Os, target.VersionId)), "This operating system/version is not qualified for cbodotnetup");
        SafeFiles.Require(!Directory.EnumerateFiles("/lib", "ld-musl-*.so.1").Any(), "musl is not supported");
        return target;
    }
    internal static void AssetValid(Asset asset, long maximum = 1024L * 1024 * 1024)
    {
        SafeFiles.Require(asset is not null && asset.Size is > 0 && asset.Size <= maximum
            && asset.Sha256 is not null && ShaPattern().IsMatch(asset.Sha256), "Malformed asset identity");
        SafeFiles.Require(Uri.TryCreate(asset.Url, UriKind.Absolute, out var uri)
            && uri.Scheme == "https" && uri.Host == "github.com" && uri.IsDefaultPort && uri.UserInfo == ""
            && uri.Query == "" && uri.Fragment == "" && uri.AbsolutePath.StartsWith("/dotnetdev-kr/cbodotnet/releases/download/", StringComparison.Ordinal)
            && uri.AbsolutePath.Split('/').Length == 7 && uri.AbsolutePath.Split('/').Skip(5).All(s => s.Length > 0 && s.All(c => char.IsAsciiLetterOrDigit(c) || "._+-".Contains(c))),
            "Only immutable project release assets are accepted");
    }
    // The schema, rather than a new receipt field, binds the archive naming contract.
    // Keeping SDK records unchanged lets the released v1 client continue reading its own receipts.
    internal static int ArchiveSchema(SdkRelease sdk)
    {
        SafeFiles.Require(sdk is not null && sdk.SdkVersion is not null && VersionPattern().IsMatch(sdk.SdkVersion)
            && sdk.Revision > 0 && sdk.Rid is "linux-x64" or "linux-arm64", "Malformed SDK archive identity");
        AssetValid(sdk.Archive);
        var arch = sdk.Rid == "linux-x64" ? "x64" : "aarch64";
        var prefix = $"https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-{sdk.SdkVersion}-r{sdk.Revision}/cbodotnet-sdk-{sdk.SdkVersion}-linux-{arch}";
        return sdk.Archive.Url == prefix + $"-branded-r{sdk.Revision}.tar.gz" ? 1
            : sdk.Archive.Url == prefix + $"-r{sdk.Revision}.tar.gz" ? 2
            : throw new InvalidOperationException("Catalog source/archive identity mismatch or unsupported archive naming");
    }
    internal static void Validate(Catalog catalog, DateTimeOffset now, bool fresh = true)
    {
        SafeFiles.Require(catalog is not null && catalog.SchemaVersion is 1 or 2 or 3 && catalog.Kind == "cbodotnetup-installation-catalog"
            && catalog.Sequence > 0 && catalog.SigningFingerprint == Fingerprint && catalog.IssuedAt.Offset == TimeSpan.Zero
            && catalog.ExpiresAt.Offset == TimeSpan.Zero && catalog.IssuedAt <= now.AddMinutes(5)
            && catalog.ExpiresAt > catalog.IssuedAt && catalog.ExpiresAt - catalog.IssuedAt <= TimeSpan.FromDays(31)
            && (!fresh || now < catalog.ExpiresAt), "Catalog identity, freshness or expiry is invalid; refresh the signed catalog");
        SafeFiles.Require(catalog.Sdks is { Length: > 0 and <= 128 } && catalog.Tools is { Length: > 0 and <= 64 }
            && catalog.Revoked is not null && catalog.Channels is not null && catalog.Revoked.Distinct().Count() == catalog.Revoked.Length,
            "Incomplete or excessive catalog");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var sdk in catalog.Sdks)
        {
            SafeFiles.Require(sdk is not null && sdk.SdkVersion is not null && VersionPattern().IsMatch(sdk.SdkVersion) && sdk.Revision > 0 && sdk.Rid is "linux-x64" or "linux-arm64"
                && sdk.ArchiveRoot == $"cbodotnet-{sdk.SdkVersion}-linux-{(sdk.Rid == "linux-x64" ? "x64" : "aarch64")}-r{sdk.Revision}"
                && ids.Add(sdk.Id) && sdk.SourceManifestSha256 is not null && ShaPattern().IsMatch(sdk.SourceManifestSha256)
                && sdk.SourceManifest is not null && sdk.SourceManifest.Sha256 == sdk.SourceManifestSha256
                && sdk.LicensePaths is not null && sdk.LicensePaths.SequenceEqual(new[] { "LICENSE.txt", "ThirdPartyNotices.txt" })
                && sdk.SecuritySupport == "community-build-no-additional-security-maintenance"
                && sdk.Targets is { Length: > 0 } && sdk.Targets.Distinct().Count() == sdk.Targets.Length
                && sdk.Targets.All(t => t is not null && t.Rid == sdk.Rid && new[] { ("ubuntu", "24.04"), ("debian", "13"), ("fedora", "45"), ("rocky", "9.8") }.Contains((t.Os, t.VersionId)))
                && sdk.Dependencies is { Length: > 0 } && sdk.Dependencies.All(d => !string.IsNullOrWhiteSpace(d))
                && sdk.Producer.ValueKind == JsonValueKind.Object,
                "Malformed, unqualified or duplicate SDK catalog entry");
            AssetValid(sdk.Archive); AssetValid(sdk.SourceManifest, 8 * 1024 * 1024); AssetValid(sdk.Evidence);
            SafeFiles.Require(ArchiveSchema(sdk) == (catalog.SchemaVersion == 1 ? 1 : 2)
                && sdk.SourceManifest.Url == $"https://github.com/dotnetdev-kr/cbodotnet/releases/download/sdk-{sdk.SdkVersion}/release-manifest.json", "Catalog source/archive identity mismatch");
        }
        foreach (var tool in catalog.Tools)
        {
            SafeFiles.Require(tool is not null && tool.Version is not null && Regex.IsMatch(tool.Version, @"^(0|[1-9][0-9]*)\.[0-9]+\.[0-9]+$", RegexOptions.CultureInvariant) && tool.Rid is "linux-x64" or "linux-arm64"
                && ids.Add("tool/" + tool.Version + '/' + tool.Rid), "Duplicate or malformed tool identity");
            AssetValid(tool.Binary, 128 * 1024 * 1024);
            AssetValid(tool.Notices, 8 * 1024 * 1024);
            SafeFiles.Require(tool.Binary.Url.EndsWith($"/cbodotnetup-v{tool.Version}/cbodotnetup-{tool.Rid}", StringComparison.Ordinal), "Tool identity does not match its immutable release URL");
            SafeFiles.Require(tool.Notices.Url == tool.Binary.Url + ".LICENSE.txt", "Native runtime notices are not bound to the tool release");
        }
        foreach (var channel in catalog.Channels)
            SafeFiles.Require(Regex.IsMatch(channel.Key, @"^[1-9][0-9]*\.[0-9]+$", RegexOptions.CultureInvariant)
                && catalog.Sdks.Any(s => s.Series == channel.Key && $"{s.SdkVersion}-r{s.Revision}" == channel.Value), "Channel refers to an unqualified SDK");
        ProviderSupport.Validate(catalog);
    }
    internal static void ValidateActive(Catalog catalog, DateTimeOffset now, bool fresh = true)
    {
        Validate(catalog, now, fresh);
        SafeFiles.Require(catalog.SchemaVersion is 2 or 3,
            "cbodotnetup requires a schema-2 bridge or schema-3 catalog; schema-1 catalogs are only for retained SDK receipts and cbodotnetup 0.1");
    }
    internal static void Admit(Catalog catalog, SdkRelease sdk, Target host)
    {
        SafeFiles.Require(sdk.Rid == host.Rid && sdk.Targets.Contains(host) && !catalog.Revoked.Contains(sdk.Id), "SDK is revoked or this OS/architecture is not individually qualified");
        if (sdk.RequiresLegacyProvider) _ = ProviderSupport.For(catalog, sdk, host);
    }
    internal static void Advance(long sequence, string sha, HighWater previous) => SafeFiles.Require(sequence > previous.Sequence
        || (sequence == previous.Sequence && sha == previous.Sha256), "Catalog rollback or conflicting sequence rejected");
    internal static byte[] PublicKey()
    {
        using var input = Assembly.GetExecutingAssembly().GetManifestResourceStream("cbodotnetup.public-key.asc")!;
        using var output = new MemoryStream(); input.CopyTo(output); return output.ToArray();
    }
    internal static void VerifySignature(string data, string signature, string scratch)
    {
        var home = Path.Combine(scratch, "gpg-" + Guid.NewGuid().ToString("N"));
        SafeFiles.PrivateDirectory(home);
        try
        {
            var key = Path.Combine(home, "public.asc"); File.WriteAllBytes(key, PublicKey());
            var keyring = Path.Combine(home, "trusted.gpg");
            SafeFiles.Command("/usr/bin/gpg", ["--no-options", "--batch", "--no-autostart", "--homedir", home, "--dearmor", "--output", keyring, key]);
            var result = SafeFiles.Command("/usr/bin/gpgv", ["--homedir", home, "--keyring", keyring, "--status-fd", "1", signature, data]);
            SafeFiles.Require(result.Split('\n').Count(line => line.StartsWith("[GNUPG:] VALIDSIG " + Fingerprint + " ", StringComparison.Ordinal)) == 1
                && !result.Contains("REVKEYSIG", StringComparison.Ordinal) && !result.Contains("EXPKEYSIG", StringComparison.Ordinal)
                && !result.Contains("KEYEXPIRED", StringComparison.Ordinal) && !result.Contains("EXPSIG", StringComparison.Ordinal), "Signature is not from the pinned live project key");
        }
        finally { SafeFiles.DeleteTree(home); }
    }
    internal static async Task<byte[]> Download(string url, long maximum)
    {
        using var handler = new HttpClientHandler { AllowAutoRedirect = false, AutomaticDecompression = DecompressionMethods.All, UseCookies = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(15) };
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(15));
        client.DefaultRequestHeaders.UserAgent.ParseAdd("cbodotnetup/" + Program.CurrentVersion);
        var uri = new Uri(url);
        for (var hop = 0; hop < 6; hop++)
        {
            SafeFiles.Require(uri.Scheme == "https" && uri.IsDefaultPort && uri.UserInfo == "" && uri.Fragment == ""
                && new[] { "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "dotnetdev.kr" }.Contains(uri.Host), "Untrusted download or redirect");
            using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            if ((int)response.StatusCode is >= 300 and < 400)
            { uri = new Uri(uri, response.Headers.Location ?? throw new InvalidOperationException("Missing redirect target")); continue; }
            response.EnsureSuccessStatusCode();
            SafeFiles.Require(response.Content.Headers.ContentLength is null || response.Content.Headers.ContentLength <= maximum, "Download exceeds its declared size bound");
            using var output = new MemoryStream();
            using var input = await response.Content.ReadAsStreamAsync(deadline.Token);
            var buffer = new byte[128 * 1024]; int read;
            while ((read = await input.ReadAsync(buffer, deadline.Token)) != 0)
            { SafeFiles.Require(output.Length + read <= maximum, "Download exceeded its size bound"); output.Write(buffer, 0, read); }
            return output.ToArray();
        }
        throw new InvalidOperationException("Too many HTTPS redirects");
    }
    internal static async Task DownloadAsset(Asset asset, string destination)
    {
        AssetValid(asset);
        var bytes = await Download(asset.Url, asset.Size);
        SafeFiles.Require(bytes.LongLength == asset.Size && SafeFiles.Hash(bytes) == asset.Sha256, "Downloaded artifact is corrupt, truncated or has conflicting bytes");
        using var file = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        await file.WriteAsync(bytes); file.Flush(true);
    }
    internal async Task<Catalog> Load(string? file, bool refresh)
    {
        var selectedCache = File.Exists(Path.Combine(cache, "catalog.json")) ? cache : CacheFor(2);
        var incoming = Path.Combine(cache, "incoming-" + Guid.NewGuid().ToString("N"));
        if (refresh || file is not null)
        {
            SafeFiles.PrivateDirectory(incoming);
            try
            {
                if (file is null)
                {
                    File.WriteAllBytes(Path.Combine(incoming, "catalog.json"), await Download(CatalogUrl, 8 * 1024 * 1024));
                    File.WriteAllBytes(Path.Combine(incoming, "catalog.json.asc"), await Download(CatalogUrl + ".asc", 64 * 1024));
                }
                else
                {
                    SafeFiles.OrdinaryPath(file); SafeFiles.OrdinaryPath(file + ".asc");
                    SafeFiles.Require(new FileInfo(file).Length <= 8 * 1024 * 1024 && new FileInfo(file + ".asc").Length <= 64 * 1024, "Oversized local catalog/signature");
                    File.Copy(file, Path.Combine(incoming, "catalog.json")); File.Copy(file + ".asc", Path.Combine(incoming, "catalog.json.asc"));
                }
                var data = Path.Combine(incoming, "catalog.json");
                VerifySignature(data, data + ".asc", incoming);
                var value = SafeFiles.Read(data, UpJson.Default.Catalog); ValidateActive(value, DateTimeOffset.UtcNow);
                SafeFiles.Require(file is not null || value.SchemaVersion == 3, "The default endpoint must provide schema-3 admission");
                Store(value, data); selectedCache = CacheFor(value.SchemaVersion);
                localCatalogDirectory = file is not null && value.SchemaVersion == 3 ? Path.GetDirectoryName(Path.GetFullPath(file)) : null;
            }
            finally { SafeFiles.DeleteTree(incoming); }
        }
        var path = Path.Combine(selectedCache, "catalog.json"); var signature = path + ".asc";
        SafeFiles.Require(File.Exists(path) && File.Exists(signature), "No authenticated catalog is cached; run list --available online");
        VerifySignature(path, signature, cache);
        var catalog = SafeFiles.Read(path, UpJson.Default.Catalog); ValidateActive(catalog, DateTimeOffset.UtcNow, refresh || file is not null);
        var watermark = SafeFiles.Read(Path.Combine(selectedCache, "high-water.json"), UpJson.Default.HighWater);
        SafeFiles.Require(catalog.Sequence == watermark.Sequence && SafeFiles.Hash(path) == watermark.Sha256, "Cached catalog does not match its high-water record");
        return catalog;
    }
    internal string CacheFor(int schema) => schema == 3 ? cache : Path.Combine(Path.GetDirectoryName(cache)!, "v2");
    private void Store(Catalog value, string data)
    {
        var directory = CacheFor(value.SchemaVersion); SafeFiles.PrivateDirectory(directory);
        var sha = SafeFiles.Hash(data); var high = Path.Combine(directory, "high-water.json");
        if (File.Exists(high)) Advance(value.Sequence, sha, SafeFiles.Read(high, UpJson.Default.HighWater));
        SafeFiles.Write(high, new HighWater(value.Sequence, sha), UpJson.Default.HighWater);
        SafeFiles.Atomic(Path.Combine(directory, "catalog.json"), File.ReadAllBytes(data));
        SafeFiles.Atomic(Path.Combine(directory, "catalog.json.asc"), File.ReadAllBytes(data + ".asc"));
    }
    internal void Retain(Catalog value, string destination)
    {
        var source = Path.Combine(CacheFor(value.SchemaVersion), "catalog.json");
        VerifySignature(source, source + ".asc", cache);
        var actual = SafeFiles.Read(source, UpJson.Default.Catalog);
        SafeFiles.Require(ProviderSupport.Equal(value, actual, UpJson.Default.Catalog), "Cached admission changed before activation");
        File.Copy(source, Path.Combine(destination, "catalog.json")); File.Copy(source + ".asc", Path.Combine(destination, "catalog.json.asc"));
    }
    internal static void ValidateCompatibility(Catalog value, Catalog compatible)
    {
        ValidateActive(compatible, DateTimeOffset.UtcNow);
        var modern = value.Sdks.Where(s => !s.RequiresLegacyProvider).ToArray();
        var legacy = value.Sdks.Where(s => s.RequiresLegacyProvider).Select(s => s.Id).ToHashSet(StringComparer.Ordinal);
        bool Relevant(string key) => !key.StartsWith("provider/", StringComparison.Ordinal) && !legacy.Contains(key);
        SafeFiles.Require(value.SchemaVersion == 3 && compatible.SchemaVersion == 2
            && value.Sequence == compatible.Sequence && value.IssuedAt == compatible.IssuedAt && value.ExpiresAt == compatible.ExpiresAt
            && modern.Length == compatible.Sdks.Length && modern.All(s => compatible.Sdks.Any(c => ProviderSupport.Equal(s, c, UpJson.Default.SdkRelease)))
            && value.Tools.Length == compatible.Tools.Length && value.Tools.All(t => compatible.Tools.Contains(t))
            && value.Revoked.Where(Relevant).ToHashSet(StringComparer.Ordinal).SetEquals(compatible.Revoked.Where(Relevant))
            && compatible.Channels.Count == value.Channels.Count(c => modern.Any(s => s.Series == c.Key))
            && compatible.Channels.All(c => value.Channels.TryGetValue(c.Key, out var version) && version == c.Value),
            "Compatible schema-2 projection differs from modern SDK/tool admission");
    }
    internal async Task<Catalog> Compatibility(Catalog value)
    {
        if (value.SchemaVersion == 2) return value;
        SafeFiles.Require(value.SchemaVersion == 3 && value.CompatibilityCatalog is not null, "No compatible modern SDK admission is available");
        var asset = value.CompatibilityCatalog!; var destination = Path.Combine(CacheFor(2), "catalog.json");
        SafeFiles.OrdinaryPath(destination);
        if (!File.Exists(destination) || SafeFiles.Hash(destination) != asset.Sha256)
        {
            var scratch = Path.Combine(cache, "compatible-" + Guid.NewGuid().ToString("N")); SafeFiles.PrivateDirectory(scratch);
            try
            {
                var data = Path.Combine(scratch, "catalog.json");
                var local = localCatalogDirectory is null ? null : Path.Combine(localCatalogDirectory, "catalog-v2.json");
                if (local is not null && (SafeFiles.Exists(local) || SafeFiles.Exists(local + ".asc")))
                {
                    SafeFiles.OrdinaryPath(local); SafeFiles.OrdinaryPath(local + ".asc");
                    SafeFiles.Require(new FileInfo(local).Length == asset.Size && SafeFiles.Hash(local) == asset.Sha256
                        && new FileInfo(local + ".asc").Length is > 0 and <= 64 * 1024,
                        "Adjacent compatible catalog differs from signed schema-3 binding");
                    File.Copy(local, data); File.Copy(local + ".asc", data + ".asc");
                }
                else
                {
                    await DownloadAsset(asset, data);
                    File.WriteAllBytes(data + ".asc", await Download(asset.Url + ".asc", 64 * 1024));
                }
                VerifySignature(data, data + ".asc", scratch);
                var compatible = SafeFiles.Read(data, UpJson.Default.Catalog); ValidateCompatibility(value, compatible); Store(compatible, data);
            }
            finally { SafeFiles.DeleteTree(scratch); }
        }
        VerifySignature(destination, destination + ".asc", cache);
        SafeFiles.Require(new FileInfo(destination).Length == asset.Size && SafeFiles.Hash(destination) == asset.Sha256,
            "Compatible catalog bytes differ from signed schema-3 binding");
        var result = SafeFiles.Read(destination, UpJson.Default.Catalog); ValidateCompatibility(value, result); return result;
    }
}
