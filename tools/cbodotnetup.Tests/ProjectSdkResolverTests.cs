using System.Text.Json;
using Community.DotNet.Up;

internal static class ProjectSdkResolverTests
{
    internal static void Run(Action<bool, string> check, Action<Action, string> reject, string temporary)
    {
        const string path = "/project/global.json";
        ProjectSdkRequest Parse(string text) => ProjectSdkResolver.Parse(path, text);
        var defaults = Parse("{}");
        check(!defaults.HasSelection && defaults.Version is null && defaults.RollForward == "latestMajor" && defaults.AllowPrerelease,
            "global.json without SDK settings preserves default selection");
        check(!Parse("{\"sdk\":{}}").HasSelection && !Parse("{\"sdk\":null}").HasSelection,
            "empty and null sdk sections preserve defaults");
        check(!Parse("{\"sdk\":{\"version\":null,\"rollForward\":null,\"allowPrerelease\":null,\"paths\":null,\"errorMessage\":\"project instructions\"}}").HasSelection,
            "null settings and errorMessage alone do not override defaults");
        var comments = Parse("\uFEFF{/* block */\"sdk\":{// line\n\"version\":\"10.0.100\"},\"msbuild-sdks\":{\"Example.Sdk\":\"2.0\"},\"test\":{\"runner\":\"Microsoft.Testing.Platform\"}}");
        check(comments.HasSelection && comments.Version == "10.0.100" && comments.RollForward == "patch",
            "BOM and host-supported comments coexist with unrelated global.json metadata");
        var caseInsensitive = Parse("{\"sdk\":{\"version\":\"10.0.100\",\"rollForward\":\"LATESTFEATURE\"}}");
        check(caseInsensitive.RollForward == "latestFeature", "host rollForward spelling is case insensitive");
        check(Parse("{\"sdk\":{\"version\":\"10.0.100-preview.1\",\"allowPrerelease\":false}}").AllowPrerelease,
            "explicit prerelease request permits prereleases even when allowPrerelease is false");
        check(!Parse("{\"sdk\":{\"allowPrerelease\":false}}").AllowPrerelease,
            "allowPrerelease alone filters the latest installed SDK");
        check(Parse("{\"sdk\":{\"paths\":[\"$host$\",\"$host$\"]}}").Paths!.Length == 2,
            "literal host search paths stay within the owned installed SDK inventory");
        check(Parse("{\"sdk\":{\"errorMessage\":\"Use the project SDK.\",\"futureHostSetting\":true}}").ErrorMessage == "Use the project SDK.",
            "custom missing-SDK text is retained and unrelated SDK settings are not install commands");
        foreach (var json in new[]
        {
            "", "[]", "null", "{", "{} garbage", "{\"sdk\":{},}", "{\"sdk\":{\"version\":\"10.0.100\",}}",
            "{\"sdk\":false}", "{\"sdk\":{\"version\":10}}", "{\"sdk\":{\"allowPrerelease\":\"false\"}}",
            "{\"sdk\":{\"rollForward\":1}}", "{\"sdk\":{\"rollForward\":\"unknown\"}}", "{\"sdk\":{\"rollForward\":\"patch\"}}",
            "{\"sdk\":{\"errorMessage\":true}}", "{\"sdk\":{},\"sdk\":{}}", "{\"sdk\":{\"version\":null,\"version\":\"10.0.100\"}}",
            "{\"msbuild-sdks\":{\"Example\":\"1\",\"Example\":\"2\"}}"
        }) reject(() => Parse(json), "invalid global.json fails closed: " + json);
        foreach (var version in new[] { "10", "10.0", "10.0.x", "10.0.100.0", "10.0.099", "010.0.100", "10.00.100", " 10.0.100", "10.0.100 ", "10.0.100-", "10.0.100-preview..1", "10.0.100-preview.01", "10.0.100-preview.18446744073709551616", "10.0.100+", "10.0.100+meta+other", "10.0.100-한글", "2147483648.0.100" })
            reject(() => Parse(JsonSerializer.Serialize(new { sdk = new { version } })), "invalid full SDK version fails closed: " + version);
        foreach (var paths in new object[] { Array.Empty<string>(), new[] { ".dotnet", "$host$" }, new[] { "/usr/share/dotnet" }, new[] { "../sdk" }, new[] { "$HOST$" }, new[] { "" }, new object[] { "$host$", false }, "$host$", false })
            reject(() => Parse(JsonSerializer.Serialize(new { sdk = new { paths } })), "external or malformed SDK search paths are rejected");
        reject(() => Parse(new string(' ', 1024 * 1024) + "{}"), "oversized global.json is rejected");
        reject(() => Parse("{\"other\":" + new string('[', 49) + "0" + new string(']', 49) + "}"), "global.json nesting is bounded");
        reject(() => ProjectSdkResolver.SelectVersion(defaults, ["10.0.100", "corrupt"]), "invalid installed SDK metadata is never silently skipped");
        check(ProjectSdkResolver.SelectVersion(null, ["9.0.200", "10.0.100-preview.1", "10.0.100"]) == "10.0.100",
            "SDK release sorts above its prerelease");
        check(ProjectSdkResolver.SelectVersion(Parse("{\"sdk\":{\"allowPrerelease\":false}}"), ["10.0.100", "11.0.100-preview.1"]) == "10.0.100",
            "latest SDK excludes prereleases when requested");
        check(ProjectSdkResolver.SelectVersion(Parse("{\"sdk\":{\"version\":\"9.0.0\",\"rollForward\":\"latestFeature\"}}"), ["9.0.123", "10.0.403"]) == "9.0.123",
            "full semantic version with feature band zero can be a roll-forward lower bound");
        check(ProjectSdkResolver.SelectVersion(Parse("{\"sdk\":{\"version\":\"9.0.99\",\"rollForward\":\"feature\"}}"), ["9.0.123", "9.0.200"]) == "9.0.123",
            "feature roll-forward accepts a full patch lower bound below the first SDK band");
        check(ProjectSdkResolver.SelectVersion(Parse("{\"sdk\":{\"version\":\"10.0.100+requested\",\"rollForward\":\"disable\"}}"), ["10.0.100+other"]) is null,
            "disable requires the exact SDK directory version including build metadata");
        check(ProjectSdkResolver.SelectVersion(Parse("{\"sdk\":{\"version\":\"10.0.100+requested\",\"rollForward\":\"patch\"}}"), ["10.0.100+other"]) == "10.0.100+other",
            "fallback semantic precedence ignores build metadata as the host does");

        var directory = Path.Combine(temporary, "project-sdk-discovery");
        var middle = Path.Combine(directory, "repository");
        var leaf = Path.Combine(middle, "src");
        Directory.CreateDirectory(Path.Combine(middle, ".git"));
        Directory.CreateDirectory(leaf);
        var outerGlobal = Path.Combine(directory, "global.json");
        var innerGlobal = Path.Combine(middle, "global.json");
        File.WriteAllText(outerGlobal, "{\"sdk\":{\"version\":\"9.0.100\"}}");
        var discovered = ProjectSdkResolver.Discover(leaf);
        check(discovered?.GlobalJsonPath == outerGlobal && discovered.Version == "9.0.100", "cwd ancestor SDK discovery crosses a git boundary");
        File.WriteAllText(innerGlobal, "{\"sdk\":{}}");
        discovered = ProjectSdkResolver.Discover(leaf);
        check(discovered?.GlobalJsonPath == innerGlobal && !discovered.HasSelection, "nearest empty global.json masks an ancestor SDK request");
        File.WriteAllText(innerGlobal, "{");
        reject(() => ProjectSdkResolver.Discover(leaf), "malformed nearest global.json never falls back to a parent request");
        File.WriteAllText(innerGlobal, "");
        reject(() => ProjectSdkResolver.Discover(leaf), "empty discovered global.json fails closed");
        File.Delete(innerGlobal);
        Directory.CreateDirectory(innerGlobal);
        reject(() => ProjectSdkResolver.Discover(leaf), "directory named global.json is not a configuration file");
        Directory.Delete(innerGlobal);
        reject(() => ProjectSdkResolver.Discover("relative-project"), "discovery requires an unambiguous absolute working directory");
        reject(() => ProjectSdkResolver.Discover(Path.Combine(directory, "missing")), "discovery rejects a missing working directory");
        if (OperatingSystem.IsLinux())
        {
            File.CreateSymbolicLink(innerGlobal, outerGlobal);
            reject(() => ProjectSdkResolver.Discover(leaf), "symlink global.json cannot redirect project discovery");
            File.Delete(innerGlobal);
            File.CreateSymbolicLink(innerGlobal, Path.Combine(directory, "missing-global.json"));
            reject(() => ProjectSdkResolver.Discover(leaf), "dangling global.json symlink never falls back to a parent request");
            File.Delete(innerGlobal);
            var alias = Path.Combine(directory, "alias");
            Directory.CreateSymbolicLink(alias, middle);
            reject(() => ProjectSdkResolver.Discover(Path.Combine(alias, "src")), "symlink working directory ancestry is rejected explicitly");
            Directory.Delete(alias);
            if (SafeFiles.GetEuid() != 0)
            {
                File.WriteAllText(innerGlobal, "{}");
                File.SetUnixFileMode(innerGlobal, UnixFileMode.None);
                var refused = false;
                try { ProjectSdkResolver.Discover(leaf); }
                catch (UnauthorizedAccessException) { refused = true; }
                finally { File.SetUnixFileMode(innerGlobal, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
                check(refused, "unreadable nearest global.json never falls back to a parent request");
                File.Delete(innerGlobal);
            }
        }
        var root = Path.GetPathRoot(directory)!;
        var rootRequest = ProjectSdkResolver.Discover(root);
        check(rootRequest is null || rootRequest.GlobalJsonPath == Path.Combine(root, "global.json"), "SDK discovery stops at the filesystem root");

        RunReferenceCases(check, reject);
    }

    private static void RunReferenceCases(Action<bool, string> check, Action<Action, string> reject)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "fixtures", "project-sdk-reference.json");
        using var fixture = JsonDocument.Parse(File.ReadAllBytes(path));
        check(fixture.RootElement.GetProperty("schemaVersion").GetInt32() == 1, "project SDK host reference fixture schema");
        foreach (var item in fixture.RootElement.GetProperty("cases").EnumerateArray())
        {
            var name = item.GetProperty("name").GetString()!;
            var versions = item.GetProperty("versions").EnumerateArray().Select(v => v.GetString()!).ToArray();
            ProjectSdkRequest? Request()
            {
                if (item.TryGetProperty("configurationText", out var text)) return ProjectSdkResolver.Parse("/reference/global.json", text.GetString()!);
                var configuration = item.GetProperty("configuration");
                return configuration.ValueKind == JsonValueKind.Null ? null : ProjectSdkResolver.Parse("/reference/global.json", configuration.GetRawText());
            }
            if (item.TryGetProperty("failClosed", out var failClosed) && failClosed.GetBoolean())
            {
                reject(() => ProjectSdkResolver.SelectVersion(Request(), versions), "project SDK reference deliberately fails closed: " + name);
                continue;
            }
            var expected = item.GetProperty("expectedVersion");
            check(ProjectSdkResolver.SelectVersion(Request(), versions) == (expected.ValueKind == JsonValueKind.Null ? null : expected.GetString()),
                "project SDK matches native host reference: " + name);
        }
    }
}
