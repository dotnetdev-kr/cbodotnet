using System.Text.Json;

namespace Community.DotNet.Up;

internal static class MuslSupport
{
    internal const string SourceSha256 = "04b3ff71eec9a508c65bf5c22c13f189def3ba576e55f5593cff7378224c3344";
    internal const string SourceTag = "musl-sdk-10.0.403-r1";
    internal const string SourcePrefix = "https://github.com/dotnetdev-kr/cbodotnet/releases/download/" + SourceTag + "/";
    internal static readonly string[] Dependencies = ["musl", "ca-certificates", "libgcc", "libstdc++", "libssl3", "libcrypto3",
        "icu-libs", "icu-data-full", "tzdata", "krb5-libs", "zlib", "brotli-libs", "lttng-ust"];

    internal static void Validate(SdkRelease sdk)
    {
        var architecture = NativeHost.Architecture(sdk.Rid);
        SafeFiles.Require(sdk.SdkVersion == "10.0.403" && sdk.Revision == 1 && !sdk.RequiresLegacyProvider
            && sdk.SourceManifestSha256 == SourceSha256 && sdk.SourceManifest.Url == SourcePrefix + "release-manifest.json"
            && sdk.Dependencies.Length == Dependencies.Length && sdk.Dependencies.ToHashSet(StringComparer.Ordinal).SetEquals(Dependencies)
            && sdk.Targets.SequenceEqual(new[] { new Target("alpine", "3.24.4", sdk.Rid) })
            && sdk.Evidence.Url == SourcePrefix + $"cbodotnet-musl-sdk-10.0.403-linux-musl-{architecture}-r1-evidence.tar.gz"
            && sdk.Producer.TryGetProperty("libc", out var libc) && libc.GetString() == "musl"
            && sdk.Producer.TryGetProperty("targetRid", out var rid) && rid.GetString() == sdk.Rid,
            "Only the independently qualified initial native Alpine SDK is admitted");
    }

    internal static void ValidateSource(JsonElement source, SdkRelease sdk)
    {
        SafeFiles.CheckJson(source);
        SafeFiles.Require(source.GetProperty("schemaVersion").GetInt32() == 1
            && source.GetProperty("kind").GetString() == "musl-sdk-producer-release"
            && source.GetProperty("repository").GetString() == "dotnetdev-kr/cbodotnet"
            && source.GetProperty("libc").GetString() == "musl" && source.GetProperty("sdkVersion").GetString() == sdk.SdkVersion
            && source.GetProperty("producerRevision").GetInt32() == 1 && source.GetProperty("tag").GetString() == SourceTag,
            "Musl source manifest identity differs from qualified admission");
        var entry = source.GetProperty("architectures").GetProperty(NativeHost.Architecture(sdk.Rid));
        var evidence = entry.GetProperty("evidence");
        SafeFiles.Require(entry.GetProperty("targetRid").GetString() == sdk.Rid
            && JsonElement.DeepEquals(entry.GetProperty("provenance"), sdk.Producer)
            && evidence.GetProperty("name").GetString() == Path.GetFileName(new Uri(sdk.Evidence.Url).AbsolutePath)
            && evidence.GetProperty("size").GetInt64() == sdk.Evidence.Size && evidence.GetProperty("sha256").GetString() == sdk.Evidence.Sha256,
            "Musl source manifest producer/evidence differs from signed catalog");
    }

    internal static void ValidateArchive(JsonElement plan, SdkRelease sdk)
    {
        SafeFiles.CheckJson(plan);
        SafeFiles.Require(plan.GetProperty("schemaVersion").GetInt32() == 1 && plan.GetProperty("kind").GetString() == "musl-distribution-plan"
            && plan.GetProperty("libc").GetString() == "musl" && plan.GetProperty("producerRevision").GetInt32() == 1
            && plan.GetProperty("sourceReleaseTag").GetString() == SourceTag && plan.GetProperty("sourceManifestUrl").GetString() == sdk.SourceManifest.Url
            && plan.GetProperty("channel").GetString() == "archive" && plan.GetProperty("variant").GetString() == "alpine-3.24"
            && !plan.TryGetProperty("compatibility", out _) && !sdk.RequiresLegacyProvider,
            "Musl archive is not the independently qualified native Alpine payload");
    }
}
