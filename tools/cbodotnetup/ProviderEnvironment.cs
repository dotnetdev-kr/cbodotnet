using System.Diagnostics;

namespace Community.DotNet.Up;

internal static class ProviderEnvironment
{
    internal static readonly string[] Scoped = ["LD_LIBRARY_PATH", "OPENSSL_CONF", "CLR_OPENSSL_VERSION_OVERRIDE", "CLR_ICU_VERSION_OVERRIDE", "SSL_CERT_FILE"];
    internal static void Apply(ProcessStartInfo start, Target host, IReadOnlyDictionary<string, string> roots)
    {
        foreach (var root in roots.Values) ProviderSupport.CheckOwnedRoot(root);
        // A nested manager may inherit an archive wrapper's scope. Restore its
        // caller first, including the distinction between unset and empty.
        if (start.Environment.TryGetValue("CBODOTNET_COMPAT_SCOPE", out var scope) && scope == "rocky9")
        {
            foreach (var name in Scoped)
            {
                var saved = "CBODOTNET_COMPAT_SAVED_" + name;
                if (start.Environment.TryGetValue(saved + "_SET", out var present) && present == "1")
                    start.Environment[name] = start.Environment.TryGetValue(saved + "_VALUE", out var value) ? value ?? "" : "";
                else start.Environment.Remove(name);
            }
        }
        foreach (var name in start.Environment.Keys.Where(n => n is "CBODOTNET_COMPAT_SCOPE" or "CBODOTNET_COMPAT_ROOT" or "CBODOTNET_CURL_COMPAT_ROOT"
            || n.StartsWith("CBODOTNET_COMPAT_SAVED_", StringComparison.Ordinal)).ToArray()) start.Environment.Remove(name);
        if (!roots.TryGetValue(ProviderSupport.BaseId, out var baseRoot)) return;
        // Save the restored caller, not the provider-prefixed environment. A
        // nested modern selection must be able to recover unset/empty/value
        // exactly after either a successful or failing legacy application.
        foreach (var name in Scoped)
        {
            var saved = "CBODOTNET_COMPAT_SAVED_" + name;
            if (start.Environment.TryGetValue(name, out var original))
            {
                start.Environment[saved + "_SET"] = "1";
                start.Environment[saved + "_VALUE"] = original ?? "";
            }
            else start.Environment[saved + "_SET"] = "0";
        }
        start.Environment["CBODOTNET_COMPAT_SCOPE"] = "rocky9";
        start.Environment["CBODOTNET_COMPAT_ROOT"] = baseRoot;
        var prefix = baseRoot + "/lib";
        if (roots.TryGetValue(ProviderSupport.CurlId, out var curlRoot))
        {
            start.Environment["CBODOTNET_CURL_COMPAT_ROOT"] = curlRoot;
            start.Environment["CLR_ICU_VERSION_OVERRIDE"] = "67";
            prefix = curlRoot + "/lib:" + prefix;
        }
        start.Environment["LD_LIBRARY_PATH"] = prefix + (start.Environment.TryGetValue("LD_LIBRARY_PATH", out var callerPath)
            && !string.IsNullOrEmpty(callerPath) ? ":" + callerPath : "");
        start.Environment["OPENSSL_CONF"] = baseRoot + "/openssl.cnf";
        start.Environment["CLR_OPENSSL_VERSION_OVERRIDE"] = "1.1";
        if (!start.Environment.ContainsKey("SSL_CERT_FILE"))
            start.Environment["SSL_CERT_FILE"] = host.Os == "rocky" ? "/etc/pki/tls/certs/ca-bundle.crt" : "/etc/ssl/certs/ca-certificates.crt";
    }
}
