using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Community.DotNet.Up;

internal sealed record ProjectSdkRequest(string GlobalJsonPath, string? Version, string RollForward,
    bool AllowPrerelease, string[]? Paths, string? ErrorMessage, bool HasSelection);

// Selection rules follow the .NET 10.0.14 host's sdk_resolver.cpp and fx_ver.cpp.
// Malformed configuration and external SDK search paths deliberately fail closed.
internal static class ProjectSdkResolver
{
    private const int MaximumBytes = 1024 * 1024;
    private static readonly string[] Policies = ["disable", "patch", "feature", "minor", "major",
        "latestPatch", "latestFeature", "latestMinor", "latestMajor"];

    internal static ProjectSdkRequest? Discover(string workingDirectory)
    {
        SafeFiles.Require(Path.IsPathFullyQualified(workingDirectory), "Project SDK discovery requires an absolute working directory");
        var directory = Path.GetFullPath(workingDirectory);
        SafeFiles.Require(Directory.Exists(directory), "Project SDK working directory does not exist: " + directory);
        // Resolve neither configuration nor cwd through aliases to another directory tree.
        // This also makes the ancestry used here unambiguous for the launched native host.
        for (string? current = directory; current is not null; current = Path.GetDirectoryName(current))
        {
            SafeFiles.Require(!SafeFiles.Link(current), "Project SDK discovery refuses a symbolic link in the working directory ancestry: " + current);
            if (Path.GetPathRoot(current) == current) break;
        }
        for (string? current = directory; current is not null; current = Path.GetDirectoryName(current))
        {
            var path = Path.Combine(current, "global.json");
            SafeFiles.Require(!SafeFiles.Link(path), "Project SDK discovery refuses a symbolic link global.json: " + path);
            FileAttributes? attributes;
            try { attributes = File.GetAttributes(path); }
            catch (FileNotFoundException) { attributes = null; }
            catch (DirectoryNotFoundException) { attributes = null; }
            // File.Exists masks access failures. Such failures must not let a parent
            // global.json silently replace an unreadable nearer configuration.
            if (attributes is not null)
            {
                SafeFiles.Require((attributes.Value & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) == 0,
                    "Expected a regular global.json file: " + path);
                var length = new FileInfo(path).Length;
                SafeFiles.Require(length is > 0 and <= MaximumBytes, "global.json must be a nonempty file no larger than 1 MiB: " + path);
                using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                var bytes = new byte[MaximumBytes + 1];
                var count = 0;
                while (count < bytes.Length)
                {
                    var read = input.Read(bytes, count, bytes.Length - count);
                    if (read == 0) break;
                    count += read;
                }
                SafeFiles.Require(count <= MaximumBytes, "global.json exceeds the 1 MiB limit: " + path);
                return Parse(path, bytes.AsMemory(0, count));
            }
            if (Path.GetPathRoot(current) == current) break;
        }
        return null;
    }

    internal static ProjectSdkRequest Parse(string path, string json) => Parse(path, Encoding.UTF8.GetBytes(json));

    private static ProjectSdkRequest Parse(string path, ReadOnlyMemory<byte> bytes)
    {
        SafeFiles.Require(bytes.Length <= MaximumBytes, "global.json exceeds the 1 MiB limit: " + path);
        if (bytes.Span.StartsWith(new byte[] { 0xEF, 0xBB, 0xBF })) bytes = bytes[3..];
        try
        {
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions
            { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = false, MaxDepth = 48 });
            var root = document.RootElement;
            Require(root.ValueKind == JsonValueKind.Object, path, "expected a JSON object");
            CheckDuplicates(root, path);
            var sdk = Value(root, "sdk");
            if (sdk is null) return new(path, null, "latestMajor", true, null, null, false);
            Require(sdk.Value.ValueKind == JsonValueKind.Object, path, "sdk must be an object or null");
            var versionValue = Value(sdk.Value, "version");
            var version = String(versionValue, path, "sdk.version");
            SdkVersion? requested = null;
            if (version is not null)
            {
                Require(SdkVersion.TryParse(version, out requested), path,
                    "sdk.version must be a full SDK version (for example, 10.0.100)");
            }
            var policyValue = Value(sdk.Value, "rollForward");
            var policyName = String(policyValue, path, "sdk.rollForward");
            var policy = policyName is null ? (version is null ? "latestMajor" : "patch")
                : Policies.FirstOrDefault(p => p.Equals(policyName, StringComparison.OrdinalIgnoreCase));
            Require(policy is not null, path, "sdk.rollForward is not a supported policy");
            Require(version is not null || policy == "latestMajor", path, "sdk.rollForward requires sdk.version unless it is latestMajor");
            var prereleaseValue = Value(sdk.Value, "allowPrerelease");
            Require(prereleaseValue is null || prereleaseValue.Value.ValueKind is JsonValueKind.True or JsonValueKind.False,
                path, "sdk.allowPrerelease must be a boolean or null");
            var allowPrerelease = prereleaseValue?.GetBoolean() ?? true;
            if (requested?.Prerelease is not null) allowPrerelease = true;
            var pathsValue = Value(sdk.Value, "paths");
            string[]? paths = null;
            if (pathsValue is not null)
            {
                const string limitation = "cbodotnetup supports sdk.paths only as a nonempty array of literal '$host$' entries; remove sdk.paths to use owned installed SDKs. Relative, absolute, and external SDK roots are not admitted";
                Require(pathsValue.Value.ValueKind == JsonValueKind.Array, path, limitation);
                var items = pathsValue.Value.EnumerateArray().ToArray();
                Require(items.Length > 0 && items.All(p => p.ValueKind == JsonValueKind.String && p.GetString() == "$host$"), path, limitation);
                paths = items.Select(p => p.GetString()!).ToArray();
            }
            var errorMessage = String(Value(sdk.Value, "errorMessage"), path, "sdk.errorMessage");
            var hasSelection = versionValue is not null || policyValue is not null || prereleaseValue is not null || pathsValue is not null;
            return new(path, version, policy!, allowPrerelease, paths, errorMessage, hasSelection);
        }
        catch (JsonException error)
        {
            throw new InvalidOperationException($"Invalid global.json '{path}': {error.Message}", error);
        }
    }

    // The caller supplies only its owned, qualified installed inventory. No path is
    // opened and no installation, download, receipt, or active selection is changed.
    internal static string? SelectVersion(ProjectSdkRequest? request, IEnumerable<string> versions)
    {
        var candidates = versions.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).Select(value =>
        {
            SafeFiles.Require(SdkVersion.TryParse(value, out var parsed),
                "Invalid installed SDK version: " + value);
            return (Text: value, Version: parsed);
        }).ToArray();
        SdkVersion? requested = null;
        if (request?.Version is not null)
            SafeFiles.Require(SdkVersion.TryParse(request.Version, out requested),
                "Invalid requested SDK version: " + request.Version);
        var policy = request?.RollForward ?? "latestMajor";
        SafeFiles.Require(Policies.Contains(policy, StringComparer.Ordinal), "Invalid project SDK roll-forward policy");
        var allowPrerelease = (request?.AllowPrerelease ?? true) || requested?.Prerelease is not null;
        if (requested is not null && policy is "patch" or "disable")
        {
            var exact = candidates.FirstOrDefault(c => c.Text == request!.Version);
            if (exact.Version is not null) return exact.Text;
        }
        if (policy == "disable") return null;
        var useLatest = requested is null || policy.StartsWith("latest", StringComparison.Ordinal);
        (string Text, SdkVersion Version)? best = null;
        foreach (var candidate in candidates)
        {
            var current = candidate.Version;
            if (!allowPrerelease && current.Prerelease is not null) continue;
            if (requested is not null)
            {
                if (current.CompareTo(requested) < 0) continue;
                if (policy is "patch" or "latestPatch" && !current.SameBand(requested)) continue;
                if (policy is "feature" or "latestFeature" && (current.Major != requested.Major || current.Minor != requested.Minor)) continue;
                if (policy is "minor" or "latestMinor" && current.Major != requested.Major) continue;
            }
            if (best is null || ((useLatest || current.SameBand(best.Value.Version))
                ? current.CompareTo(best.Value.Version) > 0 : current.CompareTo(best.Value.Version) < 0)) best = candidate;
        }
        return best?.Text;
    }

    private static JsonElement? Value(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null ? value : null;
    private static string? String(JsonElement? value, string path, string name)
    {
        Require(value is null || value.Value.ValueKind == JsonValueKind.String, path, name + " must be a string or null");
        return value?.GetString();
    }
    private static void Require(bool condition, string path, string message) =>
        SafeFiles.Require(condition, $"Invalid global.json '{path}': {message}");
    private static void CheckDuplicates(JsonElement value, string path)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                Require(names.Add(property.Name), path, "duplicate JSON property: " + property.Name);
                CheckDuplicates(property.Value, path);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray()) CheckDuplicates(item, path);
    }

    private sealed record SdkVersion(int Major, int Minor, int Patch, string? Prerelease) : IComparable<SdkVersion>
    {
        internal int FeatureBand => Patch / 100;
        internal bool SameBand(SdkVersion other) => Major == other.Major && Minor == other.Minor && FeatureBand == other.FeatureBand;
        internal static bool TryParse(string value, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out SdkVersion? version)
        {
            version = null;
            if (string.IsNullOrEmpty(value)) return false;
            var buildAt = value.IndexOf('+');
            if (buildAt >= 0 && !Identifiers(value[(buildAt + 1)..], false)) return false;
            var withoutBuild = buildAt < 0 ? value : value[..buildAt];
            var preAt = withoutBuild.IndexOf('-');
            var prerelease = preAt < 0 ? null : withoutBuild[(preAt + 1)..];
            if (prerelease is not null && !Identifiers(prerelease, true)) return false;
            var core = (preAt < 0 ? withoutBuild : withoutBuild[..preAt]).Split('.');
            if (core.Length != 3 || !Number(core[0], out var major) || !Number(core[1], out var minor) || !Number(core[2], out var patch)) return false;
            version = new(major, minor, patch, prerelease);
            return true;
        }
        private static bool Number(string text, out int value)
        {
            value = 0;
            return text.Length > 0 && (text.Length == 1 || text[0] != '0') && text.All(char.IsAsciiDigit)
                && int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);
        }
        private static bool Identifiers(string value, bool prerelease) => value.Split('.').All(id => id.Length > 0
            && id.All(c => char.IsAsciiLetterOrDigit(c) || c == '-')
            && (!prerelease || !id.All(char.IsAsciiDigit) || ((id.Length == 1 || id[0] != '0')
                && ulong.TryParse(id, NumberStyles.None, CultureInfo.InvariantCulture, out _))));
        private static bool NumericIdentifier(string value, out uint number)
        {
            number = 0;
            if (!ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)) return false;
            // The supported Linux hosts use std::stoul (64 bits) and assign it to
            // unsigned (32 bits) in try_stou. Preserve that host comparison behavior.
            number = unchecked((uint)parsed);
            return true;
        }
        public int CompareTo(SdkVersion? other)
        {
            if (other is null) return 1;
            var result = Major.CompareTo(other.Major);
            if (result == 0) result = Minor.CompareTo(other.Minor);
            if (result == 0) result = Patch.CompareTo(other.Patch);
            if (result != 0) return result;
            if (Prerelease is null || other.Prerelease is null)
                return Prerelease is null ? (other.Prerelease is null ? 0 : 1) : -1;
            var first = Prerelease.Split('.'); var second = other.Prerelease.Split('.');
            for (var i = 0; i < Math.Min(first.Length, second.Length); i++)
            {
                if (first[i] == second[i]) continue;
                var firstNumeric = NumericIdentifier(first[i], out var firstNumber);
                var secondNumeric = NumericIdentifier(second[i], out var secondNumber);
                result = firstNumeric && secondNumeric ? (firstNumber > secondNumber ? 1 : -1)
                    : firstNumeric != secondNumeric ? (firstNumeric ? -1 : 1) : StringComparer.Ordinal.Compare(first[i], second[i]);
                if (result != 0) return result;
            }
            return first.Length.CompareTo(second.Length);
        }
    }
}
