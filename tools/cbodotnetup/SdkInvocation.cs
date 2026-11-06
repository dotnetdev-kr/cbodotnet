using System.Diagnostics;

namespace Community.DotNet.Up;

internal static class SdkInvocation
{
    internal const string Brand = "Community Build of .NET (built by .NET Dev)";
    private static bool RuntimeOption(string value) => value is "--fx-version" or "--roll-forward"
        or "--additional-deps" or "--additionalprobingpath" or "--depsfile" or "--runtimeconfig";
    private static bool Application(string value) => value.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
        || value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);

    internal static bool UsesSdk(string[] arguments)
    {
        if (arguments.Length == 0) return true;
        var first = arguments[0];
        if (first is "exec" or "--list-sdks" or "--list-runtimes") return false;
        if (RuntimeOption(first))
        {
            var position = 0;
            while (position < arguments.Length && RuntimeOption(arguments[position])) position += 2;
            SafeFiles.Require(position < arguments.Length && Application(arguments[position]),
                "Runtime options require an explicit application DLL or EXE. Use exec [RUNTIME OPTIONS] APP.dll; SDK commands use the selected owned CLI.");
            return false;
        }
        return !Application(first);
    }

    internal static ProcessStartInfo Create(string wrapper, string payload, string version, string[] arguments, string? legacyRid = null)
    {
        if (legacyRid is not null) SafeFiles.Require(legacyRid is "linux-x64" or "linux-arm64", "Unsupported owned payload host RID");
        var rawHost = legacyRid is not null && !arguments.SequenceEqual(new[] { "--cbodotnet-info" });
        var start = new ProcessStartInfo(rawHost ? Path.Combine(payload, "dotnet") : wrapper) { UseShellExecute = false };
        if (rawHost) BindHost(start, payload, legacyRid!);
        var sdk = Path.Combine(payload, "sdk", version);
        if (UsesSdk(arguments) && !arguments.SequenceEqual(new[] { "--cbodotnet-info" }))
        {
            var entrypoint = Path.Combine(sdk, "dotnet.dll");
            SafeFiles.OrdinaryPath(entrypoint);
            SafeFiles.Require(File.Exists(entrypoint), "The verified installed SDK entrypoint is missing: " + entrypoint);
            // Use the immutable wrapper for root/provider setup, then bind the
            // managed CLI directly so the native muxer cannot select another SDK.
            start.ArgumentList.Add("exec"); start.ArgumentList.Add(entrypoint);
        }
        else if (Application(arguments[0]) || RuntimeOption(arguments[0]))
        {
            // Even a missing application must remain runtime dispatch: the bare
            // muxer could otherwise retry SDK resolution using project paths.
            start.ArgumentList.Add("exec");
        }
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        if (UsesSdk(arguments))
        {
            var bound = new[] { "MSBUILD_EXE_PATH", "DOTNET_MSBUILD_SDK_RESOLVER_SDKS_DIR",
                "DOTNET_MSBUILD_SDK_RESOLVER_SDKS_VER", "DOTNET_MSBUILD_SDK_RESOLVER_CLI_DIR",
                "MSBUILDALTERNATESDKRESOLVERDIRECTORY", "MSBUILDADDITIONALSDKRESOLVERSFOLDER",
                "MSBuildSDKsPath", "MSBuildExtensionsPath", "MSBuildExtensionsPath32", "MSBuildExtensionsPath64" };
            // MSBuild property names are case insensitive even on Linux, where
            // environment keys can otherwise coexist with different casing.
            foreach (var name in start.Environment.Keys.Where(key => bound.Contains(key, StringComparer.OrdinalIgnoreCase)).ToArray())
                start.Environment.Remove(name);
            start.Environment["MSBuildSDKsPath"] = Path.Combine(sdk, "Sdks");
            foreach (var name in new[] { "MSBuildExtensionsPath", "MSBuildExtensionsPath32", "MSBuildExtensionsPath64" })
                start.Environment[name] = sdk;
        }
        return start;
    }

    internal static void WriteBrand(string[] arguments)
    {
        // The selected host sees exec plus an absolute DLL, so reproduce the
        // wrapper's SDK banner rules. Its custom identity path owns its output.
        if (!UsesSdk(arguments) || arguments.SequenceEqual(new[] { "--cbodotnet-info" })) return;
        if (arguments.SequenceEqual(new[] { "--version" })) Console.Error.WriteLine(Brand);
        else if (arguments.Length == 0 || arguments.Length == 1 && arguments[0] is "--info" or "--help" or "-h" or "help")
            Console.WriteLine(Brand);
    }
    internal static void BindHost(ProcessStartInfo start, string payload, string rid)
    {
        SafeFiles.Require(rid is "linux-x64" or "linux-arm64", "Unsupported owned payload host RID");
        var host = Path.Combine(payload, "dotnet"); SafeFiles.OrdinaryPath(host);
        SafeFiles.Require(File.Exists(host), "The verified installed payload host is missing: " + host);
        var bound = new[] { "DOTNET_ROOT", "DOTNET_HOST_PATH", "DOTNET_MULTILEVEL_LOOKUP" };
        foreach (var name in start.Environment.Keys.Where(n => n.StartsWith("DOTNET_ROOT_", StringComparison.OrdinalIgnoreCase)
            || bound.Contains(n, StringComparer.OrdinalIgnoreCase)).ToArray())
            start.Environment.Remove(name);
        start.Environment["DOTNET_ROOT"] = payload;
        start.Environment[rid == "linux-x64" ? "DOTNET_ROOT_X64" : "DOTNET_ROOT_ARM64"] = payload;
        start.Environment["DOTNET_HOST_PATH"] = host;
        start.Environment["DOTNET_MULTILEVEL_LOOKUP"] = "0";
    }
}
