namespace Community.DotNet.Up;

internal static class Program
{
    internal const string CurrentVersion = "0.2.0";
    internal static async Task<int> Main(string[] args)
    {
        try
        {
            var invoked = Path.GetFileName(Environment.GetCommandLineArgs()[0]);
            var alias = invoked == "cbodotnet" || invoked.StartsWith("cbodotnet-", StringComparison.Ordinal);
            if (!alias && args.SequenceEqual(new[] { "--version" })) { Console.WriteLine(CurrentVersion); return 0; }
            if (args.Length == 0 && invoked != "cbodotnet" && !invoked.StartsWith("cbodotnet-", StringComparison.Ordinal)
                || !alias && (args.SequenceEqual(new[] { "--help" }) || args.SequenceEqual(new[] { "help" })))
            {
                Console.WriteLine($"""
                    cbodotnetup {CurrentVersion} — Community Build of .NET (built by .NET Dev)
                    list [--available]                 List installed or authenticated available SDKs
                    install VERSION[-rN]               Install an exact qualified SDK
                    install --channel X.Y              Install and track a signed Community channel
                    run VERSION[-rN] -- [SDK ARGS]      Execute an installed SDK without PATH changes
                    remove VERSION[-rN]                Remove one verified owned installation
                    update                             Update tracked channels; retain prior SDKs
                    rollback VERSION-rN                Select a retained, verified SDK revision
                    doctor                             Verify installed files and report host/trust
                    gc                                 Collect abandoned owned staging data
                    shell enable|disable               Manage opt-in aliases in the user data bin
                    self update|rollback               Authenticate an update or retained tool recovery
                    --catalog FILE                     Use a local project-signed catalog and .asc
                    """); return 0;
            }
            string? catalogFile = null;
            var values = args.ToList();
            var catalogIndex = values.IndexOf("--catalog");
            // Only global options before the run separator belong to the manager.
            if (!alias && catalogIndex >= 0 && (values.IndexOf("--") < 0 || catalogIndex < values.IndexOf("--")))
            { SafeFiles.Require(catalogIndex + 1 < values.Count, "--catalog requires a path"); catalogFile = Path.GetFullPath(values[catalogIndex + 1]); values.RemoveRange(catalogIndex, 2); }
            using var manager = new Manager();
            var refresh = !alias && (values.Contains("--available") || values.FirstOrDefault() is "install" or "update" || values.SequenceEqual(new[] { "self", "update" }) || values.SequenceEqual(new[] { "self", "rollback" }));
            var catalog = await manager.Catalog(catalogFile, refresh);
            SafeFiles.Require(!catalog.Revoked.Contains("tool/" + CurrentVersion + '/' + Trust.Rid), "This installer release is revoked; run the independently trusted bootstrap for a newer release");
            if (alias) return manager.Run(catalog, invoked == "cbodotnet" ? null : invoked[10..], args, true);
            SafeFiles.Require(values.Count > 0, "A command is required");
            switch (values[0])
            {
                case "list" when values.Count == 1:
                    foreach (var receipt in manager.Installed()) Console.WriteLine(receipt.Release.Id); break;
                case "list" when values.SequenceEqual(new[] { "list", "--available" }):
                    foreach (var sdk in catalog.Sdks.Where(s => s.Rid == Trust.Rid).OrderByDescending(s => Version.Parse(s.SdkVersion)))
                        Console.WriteLine(sdk.Id + (catalog.Revoked.Contains(sdk.Id) ? " [revoked]" : sdk.RequiresLegacyProvider ? " [requires separate legacy provider]" : "")); break;
                case "install" when values.Count == 2: await manager.Install(catalog, values[1]); break;
                case "install" when values.Count == 3 && values[1] == "--channel":
                    SafeFiles.Require(catalog.Channels.TryGetValue(values[2], out var version), "Unknown signed Community channel"); await manager.Install(catalog, version!, values[2]); break;
                case "run" when values.Count >= 3 && values[2] == "--": return manager.Run(catalog, values[1], values.Skip(3).ToArray());
                case "remove" when values.Count == 2: manager.Remove(catalog, values[1]); break;
                case "rollback" when values.Count == 2 && values[1].Contains("-r", StringComparison.Ordinal): manager.Rollback(catalog, values[1]); break;
                case "update" when values.Count == 1: await manager.Update(catalog); break;
                case "doctor" when values.Count == 1: manager.Doctor(catalog); break;
                case "gc" when values.Count == 1: manager.Collect(); break;
                case "shell" when values.Count == 2 && values[1] is "enable" or "disable": manager.Shell(values[1] == "enable"); break;
                case "self" when values.SequenceEqual(new[] { "self", "update" }): await manager.SelfUpdate(catalog); break;
                case "self" when values.SequenceEqual(new[] { "self", "rollback" }): manager.SelfRollback(catalog); break;
                default: throw new InvalidOperationException("Unknown command or arguments; use cbodotnetup --help");
            }
            return 0;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        { Console.Error.WriteLine("cbodotnetup: " + exception.Message); return exception.Message == "No matching Community Build SDK is installed" ? 127 : 1; }
    }
}
