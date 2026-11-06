using Community.DotNet.Up;

internal static class ProjectAdmissionTests
{
    internal static void Run(Action<bool, string> check, string temporary, SdkRelease baseline, Catalog catalog)
    {
        const string prefix = "https://github.com/dotnetdev-kr/cbodotnet/releases/download/";
        SdkRelease Release(string version) => baseline with
        {
            SdkVersion = version, Revision = 2, ArchiveRoot = $"cbodotnet-{version}-linux-x64-r2",
            Archive = baseline.Archive with { Url = prefix + $"distribution-archive-sdk-{version}-r2/cbodotnet-sdk-{version}-linux-x64-r2.tar.gz" },
            SourceManifest = baseline.SourceManifest with { Url = prefix + $"sdk-{version}/release-manifest.json" }
        };
        var lower = Release("9.0.123"); var absent = Release("8.0.133");
        var project = Path.Combine(temporary, "project-admission"); Directory.CreateDirectory(project);
        var file = Path.Combine(project, "global.json");
        var root = Path.Combine(temporary, "project-owned-inventory"); var downloads = 0;
        using var manager = new Manager(root, new("rocky", "9.8", "linux-x64"), (_, _) => { downloads++; throw new Exception("Unexpected download"); });
        foreach (var release in new[] { baseline, lower })
        {
            var directory = Path.Combine(root, "toolchains-v2", release.Id); Directory.CreateDirectory(directory);
            SafeFiles.Write(Path.Combine(directory, "receipt.json"), new Receipt(1, SafeFiles.Owner, release,
                new string('a', 64), 1, DateTimeOffset.UtcNow), UpJson.Default.Receipt);
        }
        // These are receipt-only test inventories. A selected revoked/unqualified
        // SDK must be rejected before signature execution or a fallback to SDK10.
        var admitted = catalog with { Sdks = [baseline, lower, absent] };
        File.WriteAllText(file, "{\"sdk\":{\"version\":\"9.0.123\",\"rollForward\":\"disable\"}}");
        bool Fails(Catalog value, string text)
        {
            try { manager.SelectForRun(value, null, ["--version"], workingDirectory: project); }
            catch (InvalidOperationException error) { return error.Message.Contains(text, StringComparison.Ordinal); }
            return false;
        }
        check(Fails(admitted with { Revoked = [lower.Id] }, "SDK is revoked"), "Revoked project winner fails before execution instead of choosing installed SDK10");
        var receipt = Path.Combine(root, "toolchains-v2", lower.Id, "receipt.json");
        SafeFiles.Write(receipt, new Receipt(1, SafeFiles.Owner, lower with { Targets = [new("ubuntu", "24.04", "linux-x64")] },
            new string('a', 64), 1, DateTimeOffset.UtcNow), UpJson.Default.Receipt);
        check(Fails(admitted, "not individually qualified"), "Unqualified actual project host is rejected before SDK execution");
        File.WriteAllText(file, "{\"sdk\":{\"version\":\"8.0.133\",\"rollForward\":\"disable\",\"errorMessage\":\"Project setup required.\"}}");
        check(Fails(admitted, "cbodotnetup install 8.0.133-r2"), "Missing admitted SDK gets an exact explicit install action without hidden installation");
        check(Fails(admitted with { Sdks = [baseline, lower, absent, absent with { Revision = 3 }],
            Revoked = [(absent with { Revision = 3 }).Id] }, "cbodotnetup install 8.0.133-r2"),
            "Missing SDK action names an admitted revision even when a later revision is revoked");
        check(Fails(admitted, "Project setup required."), "Project missing-SDK message supplements the actionable diagnostic");
        File.WriteAllText(file, "{\"sdk\":{\"version\":\"99.0.999\",\"rollForward\":\"disable\"}}");
        check(Fails(admitted, "cbodotnetup list --available"), "Unavailable project SDK suggests catalog review instead of an inadmissible install");
        check(downloads == 0 && !File.Exists(Path.Combine(root, "selection.json")) && File.ReadAllText(file).Contains("99.0.999", StringComparison.Ordinal),
            "Project admission errors preserve project and active-selection state without downloads");
    }
}
