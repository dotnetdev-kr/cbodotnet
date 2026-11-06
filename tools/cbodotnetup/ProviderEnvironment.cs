using System.Diagnostics;

namespace Community.DotNet.Up;

internal static class ProviderEnvironment
{
    internal static readonly string[] Scoped = ["LD_LIBRARY_PATH", "OPENSSL_CONF", "CLR_OPENSSL_VERSION_OVERRIDE", "CLR_ICU_VERSION_OVERRIDE", "SSL_CERT_FILE"];
    internal static void Apply(ProcessStartInfo start, Target host, IReadOnlyDictionary<string, string> roots)
    {
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
        start.Environment["CBODOTNET_COMPAT_ROOT"] = baseRoot;
        if (roots.TryGetValue(ProviderSupport.CurlId, out var curlRoot)) start.Environment["CBODOTNET_CURL_COMPAT_ROOT"] = curlRoot;
        if (!start.Environment.ContainsKey("SSL_CERT_FILE"))
            start.Environment["SSL_CERT_FILE"] = host.Os == "rocky" ? "/etc/pki/tls/certs/ca-bundle.crt" : "/etc/ssl/certs/ca-certificates.crt";
    }
}
