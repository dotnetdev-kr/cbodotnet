using Community.DotNet.Up;

internal static class SdkInvocationTests
{
    internal static void Run(Action<bool, string> check, Action<Action, string> reject, string temporary)
    {
        var root = Path.Combine(temporary, "owned SDK with spaces");
        var sdk = Path.Combine(root, "payload", "sdk", "10.0.403"); Directory.CreateDirectory(sdk);
        var entrypoint = Path.Combine(sdk, "dotnet.dll"); File.WriteAllText(entrypoint, "test-only entrypoint");
        var wrapper = Path.Combine(root, "cbodotnet");
        var arguments = new[] { "build", "project with spaces.csproj", "--", "--available", "--catalog" };
        var plan = SdkInvocation.Create(wrapper, Path.Combine(root, "payload"), "10.0.403", arguments);
        check(plan.FileName == wrapper && !plan.UseShellExecute
            && plan.ArgumentList.SequenceEqual(new[] { "exec", entrypoint }.Concat(arguments)),
            "SDK launch binds the exact owned entrypoint and preserves argument boundaries");
        check(plan.Environment["MSBuildSDKsPath"] == Path.Combine(sdk, "Sdks")
            && plan.Environment["MSBuildExtensionsPath"] == sdk, "MSBuild discovery is bound to the selected owned SDK");
        foreach (var args in new[] { Array.Empty<string>(), new[] { "--version" }, new[] { "--info" }, new[] { "--help" }, new[] { "restore" } })
            check(SdkInvocation.UsesSdk(args), "SDK command engages project selection: " + string.Join(' ', args));
        foreach (var args in new[] { new[] { "app.dll" }, new[] { "application.EXE" }, new[] { "exec", "app.dll" },
            new[] { "--list-sdks" }, new[] { "--list-runtimes" }, new[] { "--roll-forward", "Major", "app.dll" } })
        {
            check(!SdkInvocation.UsesSdk(args), "Native runtime command does not engage SDK project selection");
            var nativeArgs = args[0] is "exec" or "--list-sdks" or "--list-runtimes" ? args : new[] { "exec" }.Concat(args);
            check(SdkInvocation.Create(wrapper, Path.Combine(root, "payload"), "10.0.403", args).ArgumentList.SequenceEqual(nativeArgs),
                "Native application dispatch cannot reenter SDK resolution even if its file is missing");
        }
        foreach (var args in new[] { new[] { "--roll-forward", "LatestMajor", "build" },
            new[] { "--fx-version", "10.0.14", "--version" }, new[] { "--runtimeconfig", "other.json" },
            new[] { "--additionalprobingpath", "--version" } })
            reject(() => SdkInvocation.Create(wrapper, Path.Combine(root, "payload"), "10.0.403", args),
                "Runtime-option prefix cannot bypass SDK binding: " + string.Join(' ', args));
        check(SdkInvocation.Create(wrapper, Path.Combine(root, "payload"), "10.0.403", ["--cbodotnet-info"])
            .ArgumentList.SequenceEqual(new[] { "--cbodotnet-info" }), "Community identity remains owned by the original wrapper");
        var payload = Path.Combine(root, "payload"); var payloadHost = Path.Combine(payload, "dotnet");
        File.WriteAllText(payloadHost, "test-only non-executable payload host marker");
        foreach (var rid in new[] { "linux-x64", "linux-arm64" })
        {
            var direct = SdkInvocation.Create(wrapper, payload, "10.0.403", arguments, rid);
            check(direct.FileName == payloadHost && direct.ArgumentList.SequenceEqual(new[] { "exec", entrypoint }.Concat(arguments)),
                "Legacy managed SDK launch binds the verified payload host instead of an incomplete historical wrapper");
            check(direct.Environment["DOTNET_ROOT"] == payload && direct.Environment["DOTNET_HOST_PATH"] == payloadHost
                && direct.Environment["DOTNET_MULTILEVEL_LOOKUP"] == "0"
                && direct.Environment[rid == "linux-x64" ? "DOTNET_ROOT_X64" : "DOTNET_ROOT_ARM64"] == payload
                && !direct.Environment.ContainsKey(rid == "linux-x64" ? "DOTNET_ROOT_ARM64" : "DOTNET_ROOT_X64")
                && !direct.Environment.ContainsKey("DOTNET_ROOT_X86"), "Raw legacy host discovery cannot select another architecture or system root");
            foreach (var args in new[] { new[] { "exec", "application.dll" }, new[] { "application.dll" }, new[] { "--list-runtimes" } })
                check(SdkInvocation.Create(wrapper, payload, "10.0.403", args, rid).FileName == payloadHost,
                    "Legacy runtime/application dispatch also uses the verified payload host");
            check(SdkInvocation.Create(wrapper, payload, "10.0.403", ["--cbodotnet-info"], rid).FileName == wrapper,
                "Only the original archive identity command retains the immutable legacy wrapper");
        }
        File.Delete(payloadHost);
        reject(() => SdkInvocation.Create(wrapper, payload, "10.0.403", ["--version"], "linux-x64"),
            "Missing verified raw payload host cannot fall back to the archive wrapper or system dotnet");
        var names = new[] { "MSBUILD_EXE_PATH", "DOTNET_MSBUILD_SDK_RESOLVER_CLI_DIR", "MSBUILDALTERNATESDKRESOLVERDIRECTORY", "MSBuildSDKsPath" };
        var previous = names.ToDictionary(n => n, Environment.GetEnvironmentVariable);
        try
        {
            foreach (var name in names) Environment.SetEnvironmentVariable(name, "/untrusted/sdk");
            var isolated = SdkInvocation.Create(wrapper, Path.Combine(root, "payload"), "10.0.403", ["build"]);
            check(names.Take(3).All(n => !isolated.Environment.ContainsKey(n))
                && isolated.Environment["MSBuildSDKsPath"] == Path.Combine(sdk, "Sdks"), "Ambient SDK/engine overrides cannot redirect the selected child");
            check(names.All(n => Environment.GetEnvironmentVariable(n) == "/untrusted/sdk"), "Child binding does not mutate the caller environment");
            if (!OperatingSystem.IsWindows())
            {
                var variants = new[] { "MSBUILDSDKSPATH", "MSBUILDEXTENSIONSPATH", "dotnet_msbuild_sdk_resolver_cli_dir" };
                var savedVariants = variants.ToDictionary(n => n, Environment.GetEnvironmentVariable);
                try
                {
                    foreach (var name in variants) Environment.SetEnvironmentVariable(name, "/untrusted/case-variant");
                    var bound = SdkInvocation.Create(wrapper, Path.Combine(root, "payload"), "10.0.403", ["build"]);
                    check(variants.All(n => !bound.Environment.ContainsKey(n))
                        && bound.Environment["MSBuildSDKsPath"] == Path.Combine(sdk, "Sdks"),
                        "Linux case variants cannot override the owned MSBuild properties");
                }
                finally { foreach (var name in variants) Environment.SetEnvironmentVariable(name, savedVariants[name]); }
            }
        }
        finally { foreach (var name in names) Environment.SetEnvironmentVariable(name, previous[name]); }
        foreach (var args in new[] { new[] { "run", "--", "--available" }, new[] { "run", "9.0.123", "--", "--available" },
            new[] { "run", "--", "build", "--", "--catalog", "input" }, new[] { "list" }, new[] { "doctor" } })
            check(!Community.DotNet.Up.Program.RefreshesCatalog(args), "Run/diagnostic arguments do not implicitly refresh or access the network");
        foreach (var args in new[] { new[] { "list", "--available" }, new[] { "install", "9.0.123" }, new[] { "update" }, new[] { "self", "update" } })
            check(Community.DotNet.Up.Program.RefreshesCatalog(args), "Explicit catalog maintenance retains online behavior");
        File.Delete(entrypoint);
        reject(() => SdkInvocation.Create(wrapper, Path.Combine(root, "payload"), "10.0.403", ["build"]),
            "Missing owned CLI entrypoint cannot fall back to a system SDK");
    }
}
