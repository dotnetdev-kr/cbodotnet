using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Community.DotNet.Up;

internal sealed partial class Trust
{
    internal const string Fingerprint = "D7D154B4B33C19A82B95B13688135410ACD9C0EA";
    internal const string CatalogUrl = "https://dotnetdev.kr/cbodotnet/cbodotnetup/catalog.json";
    private readonly string cache;
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
        SafeFiles.Require(asset is not null && asset.Size is > 0 && asset.Size <= maximum && ShaPattern().IsMatch(asset.Sha256), "Malformed asset identity");
        var uri = new Uri(asset.Url, UriKind.Absolute);
        SafeFiles.Require(uri.Scheme == "https" && uri.Host == "github.com" && uri.IsDefaultPort && uri.UserInfo == ""
            && uri.Query == "" && uri.Fragment == "" && uri.AbsolutePath.StartsWith("/dotnetdev-kr/cbodotnet/releases/download/", StringComparison.Ordinal)
            && uri.AbsolutePath.Split('/').Length == 7 && uri.AbsolutePath.Split('/').Skip(5).All(s => s.Length > 0 && s.All(c => char.IsAsciiLetterOrDigit(c) || "._+-".Contains(c))),
            "Only immutable project release assets are accepted");
    }
    internal static void Validate(Catalog catalog, DateTimeOffset now, bool fresh = true)
    {
        SafeFiles.Require(catalog.SchemaVersion == 1 && catalog.Kind == "cbodotnetup-installation-catalog"
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
            SafeFiles.Require(VersionPattern().IsMatch(sdk.SdkVersion) && sdk.Revision > 0 && sdk.Rid is "linux-x64" or "linux-arm64"
                && sdk.ArchiveRoot == $"cbodotnet-{sdk.SdkVersion}-linux-{(sdk.Rid == "linux-x64" ? "x64" : "aarch64")}-r{sdk.Revision}"
                && ids.Add(sdk.Id) && ShaPattern().IsMatch(sdk.SourceManifestSha256) && sdk.SourceManifest.Sha256 == sdk.SourceManifestSha256
                && sdk.LicensePaths.SequenceEqual(new[] { "LICENSE.txt", "ThirdPartyNotices.txt" })
                && sdk.SecuritySupport == "community-build-no-additional-security-maintenance"
                && sdk.Targets.Length > 0 && sdk.Targets.Distinct().Count() == sdk.Targets.Length
                && sdk.Targets.All(t => t.Rid == sdk.Rid && new[] { ("ubuntu", "24.04"), ("debian", "13"), ("fedora", "45"), ("rocky", "9.8") }.Contains((t.Os, t.VersionId)))
                && sdk.Dependencies.Length > 0 && sdk.Producer.ValueKind == JsonValueKind.Object,
                "Malformed, unqualified or duplicate SDK catalog entry");
            AssetValid(sdk.Archive); AssetValid(sdk.SourceManifest, 8 * 1024 * 1024); AssetValid(sdk.Evidence);
            SafeFiles.Require(sdk.Archive.Url.EndsWith($"/distribution-archive-sdk-{sdk.SdkVersion}-r{sdk.Revision}/cbodotnet-sdk-{sdk.SdkVersion}-linux-{(sdk.Rid == "linux-x64" ? "x64" : "aarch64")}-branded-r{sdk.Revision}.tar.gz", StringComparison.Ordinal)
                && sdk.SourceManifest.Url.EndsWith($"/sdk-{sdk.SdkVersion}/release-manifest.json", StringComparison.Ordinal), "Catalog source/archive identity mismatch");
        }
        foreach (var tool in catalog.Tools)
        {
            SafeFiles.Require(Regex.IsMatch(tool.Version, @"^(0|[1-9][0-9]*)\.[0-9]+\.[0-9]+$", RegexOptions.CultureInvariant) && tool.Rid is "linux-x64" or "linux-arm64"
                && ids.Add("tool/" + tool.Version + '/' + tool.Rid), "Duplicate or malformed tool identity");
            AssetValid(tool.Binary, 128 * 1024 * 1024);
            AssetValid(tool.Notices, 8 * 1024 * 1024);
            SafeFiles.Require(tool.Binary.Url.EndsWith($"/cbodotnetup-v{tool.Version}/cbodotnetup-{tool.Rid}", StringComparison.Ordinal), "Tool identity does not match its immutable release URL");
            SafeFiles.Require(tool.Notices.Url == tool.Binary.Url + ".LICENSE.txt", "Native runtime notices are not bound to the tool release");
        }
        foreach (var channel in catalog.Channels)
            SafeFiles.Require(Regex.IsMatch(channel.Key, @"^[1-9][0-9]*\.[0-9]+$", RegexOptions.CultureInvariant)
                && catalog.Sdks.Any(s => s.Series == channel.Key && $"{s.SdkVersion}-r{s.Revision}" == channel.Value), "Channel refers to an unqualified SDK");
    }
    internal static void Admit(Catalog catalog, SdkRelease sdk, Target host)
    {
        SafeFiles.Require(sdk.Rid == host.Rid && sdk.Targets.Contains(host) && !catalog.Revoked.Contains(sdk.Id), "SDK is revoked or this OS/architecture is not individually qualified");
        SafeFiles.Require(!sdk.RequiresLegacyProvider, "This SDK needs a separately qualified legacy provider; cbodotnetup does not install native dependencies automatically");
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
        client.DefaultRequestHeaders.UserAgent.ParseAdd("cbodotnetup/0.1.0");
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
        var path = Path.Combine(cache, "catalog.json"); var signature = path + ".asc";
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
                var value = SafeFiles.Read(data, UpJson.Default.Catalog); Validate(value, DateTimeOffset.UtcNow);
                var sha = SafeFiles.Hash(data); var high = Path.Combine(cache, "high-water.json");
                if (File.Exists(high))
                {
                    var previous = SafeFiles.Read(high, UpJson.Default.HighWater);
                    Advance(value.Sequence, sha, previous);
                }
                // A crash between these writes fails closed against high-water on the next read.
                SafeFiles.Write(high, new HighWater(value.Sequence, sha), UpJson.Default.HighWater);
                SafeFiles.Atomic(path, File.ReadAllBytes(data)); SafeFiles.Atomic(signature, File.ReadAllBytes(data + ".asc"));
            }
            finally { SafeFiles.DeleteTree(incoming); }
        }
        SafeFiles.Require(File.Exists(path) && File.Exists(signature), "No authenticated catalog is cached; run list --available online");
        VerifySignature(path, signature, cache);
        var catalog = SafeFiles.Read(path, UpJson.Default.Catalog); Validate(catalog, DateTimeOffset.UtcNow, refresh || file is not null);
        var watermark = SafeFiles.Read(Path.Combine(cache, "high-water.json"), UpJson.Default.HighWater);
        SafeFiles.Require(catalog.Sequence == watermark.Sequence && SafeFiles.Hash(path) == watermark.Sha256, "Cached catalog does not match its high-water record");
        return catalog;
    }
}
