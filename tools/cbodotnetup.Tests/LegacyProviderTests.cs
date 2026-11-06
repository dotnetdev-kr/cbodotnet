using System.Diagnostics;
using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Community.DotNet.Up;

internal static class LegacyProviderTests
{
    internal static void Run(Action<bool, string> check, Action<Action, string> reject, string temporary, Catalog bridge, SdkRelease baseline)
    {
        var fixture = Path.Combine(AppContext.BaseDirectory, "fixtures/legacy-providers.json");
        using var document = JsonDocument.Parse(File.ReadAllBytes(fixture)); var data = document.RootElement;
        var providers = JsonSerializer.Deserialize(data.GetProperty("providers"), UpJson.Default.ProviderReleaseArray)!;
        var bindings = JsonSerializer.Deserialize(data.GetProperty("providerBindings"), UpJson.Default.ProviderBindingArray)!;
        var legacy = data.GetProperty("sdks").EnumerateArray().Select(row =>
        {
            var version = row.GetProperty("sdkVersion").GetString()!; var rid = row.GetProperty("rid").GetString()!;
            var sha = row.GetProperty("sourceManifestSha256").GetString()!;
            return baseline with { SdkVersion = version, Revision = row.GetProperty("revision").GetInt32(), Rid = rid,
                ArchiveRoot = row.GetProperty("archiveRoot").GetString()!, Archive = JsonSerializer.Deserialize(row.GetProperty("archive"), UpJson.Default.Asset)!,
                SourceManifestSha256 = sha, SourceManifest = new($"https://github.com/dotnetdev-kr/cbodotnet/releases/download/sdk-{version}/release-manifest.json", 1, sha),
                Targets = JsonSerializer.Deserialize(row.GetProperty("targets"), UpJson.Default.TargetArray)!, RequiresLegacyProvider = true };
        }).ToArray();
        var catalog = bridge with { SchemaVersion = 3, Sequence = 773, Sdks = [baseline, .. legacy], Providers = providers, ProviderBindings = bindings,
            CompatibilityCatalog = new("https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-catalog-773/catalog-v2.json", 1, new string('b', 64)),
            Channels = new() { ["10.0"] = baseline.SdkVersion + "-r" + baseline.Revision, ["5.0"] = "5.0.214-r2", ["3.1"] = "3.1.426-r2", ["3.0"] = "3.0.103-r2" } };
        Trust.Validate(catalog, DateTimeOffset.UtcNow); check(true, "Actual four public provider records and six SDK bindings satisfy the C# contract");
        Trust.Validate(catalog with { Sdks = [baseline], Providers = [], ProviderBindings = [], Channels = bridge.Channels }, DateTimeOffset.UtcNow);
        check(true, "A future schema-3 withdrawal can retain modern SDKs with empty provider admission");
        var host = new Target("rocky", "9.8", "linux-x64"); var sdk5 = legacy.Single(s => s.SdkVersion == "5.0.214" && s.Rid == host.Rid);
        var core3 = legacy.Single(s => s.SdkVersion == "3.1.426" && s.Rid == host.Rid);
        check(ProviderSupport.For(catalog, sdk5, host).Select(p => p.ProviderId).SequenceEqual(new[] { ProviderSupport.BaseId }), "SDK5 binds only its approved base companion");
        check(ProviderSupport.For(catalog, core3, host).Select(p => p.ProviderId).SequenceEqual(new[] { ProviderSupport.BaseId, ProviderSupport.CurlId }), "Core3 binds base then native HTTP companion");
        Trust.Admit(catalog, sdk5, host); check(true, "Legacy SDK admission requires an explicit exact provider binding");
        var baseIndex = Array.FindIndex(providers, p => p.ProviderId == ProviderSupport.BaseId && p.Rid == host.Rid); var original = providers[baseIndex];
        foreach (var mutate in new Func<ProviderRelease, ProviderRelease>[] {
            p => p with { Libc = "musl" }, p => p with { Root = "/usr/lib" }, p => p with { Rid = "linux-musl-x64" },
            p => p with { ManifestSha256 = "invalid" }, p => p with { PolicySha256 = new string('f',64) },
            p => p with { CpuBaseline = "x86-64" }, p => p with { CpuFlags = ["cx16"] },
            p => p with { SourceSignature = p.SourceSignature with { Url = p.SourceManifest.Url } },
            p => p with { Archive = p.Archive with { Url = p.Archive.Url.Replace("sdk-5.0.214-r2", "sdk-3.1.426-r2", StringComparison.Ordinal) } },
            p => p with { Targets = [new("ubuntu", "22.04", host.Rid)] } })
        {
            var changed = providers.ToArray(); changed[baseIndex] = mutate(original);
            reject(() => Trust.Validate(catalog with { Providers = changed }, DateTimeOffset.UtcNow), "Provider source/libc/root/ABI/target identity is closed");
        }
        reject(() => Trust.Validate(bridge with { Providers = providers }, DateTimeOffset.UtcNow), "Provider records cannot enter a schema-2 bridge");
        reject(() => Trust.Validate(catalog with { Providers = providers.Skip(1).ToArray() }, DateTimeOffset.UtcNow), "A missing provider cannot satisfy all legacy bindings");
        reject(() => Trust.Validate(catalog with { ProviderBindings = bindings.Skip(1).ToArray() }, DateTimeOffset.UtcNow), "Every legacy SDK requires a binding");
        var wrong = bindings.ToArray(); wrong[0] = wrong[0] with { SourceManifestSha256 = new string('f', 64) };
        reject(() => Trust.Validate(catalog with { ProviderBindings = wrong }, DateTimeOffset.UtcNow), "Provider binding cannot substitute the SDK source");
        wrong = bindings.ToArray(); wrong[0] = wrong[0] with { ProviderIds = [original.Id, original.Id] };
        reject(() => Trust.Validate(catalog with { ProviderBindings = wrong }, DateTimeOffset.UtcNow), "Duplicate references cannot replace the required provider set");
        reject(() => Trust.Admit(catalog with { Revoked = [sdk5.Id] }, sdk5, host), "Revoked legacy SDK is rejected");
        reject(() => Trust.Admit(catalog with { Revoked = [ProviderSupport.Revocation(original)] }, sdk5, host), "Revoked provider is rejected before execution");
        reject(() => ProviderSupport.For(bridge, sdk5, host), "A modern bridge cannot admit private legacy dependencies");
        check(!ProviderSupport.Eligible(catalog with { Revoked = [ProviderSupport.Revocation(original)] }, sdk5, host), "Missing-SDK diagnostics skip revoked providers without downloading");
        ProviderSupport.CheckCapabilities(original, "2.34", [ProviderSupport.X64Flags, ProviderSupport.X64Flags]); check(true, "Exact minimum glibc and all processors satisfy provider ABI");
        ProviderSupport.CheckCapabilities(original, "2.41", [ProviderSupport.X64Flags.Select(f => f == "pni" ? "sse3" : f)]); check(true, "Linux SSE3 spelling preserves x64-v2 eligibility");
        reject(() => ProviderSupport.CheckCapabilities(original, "2.33", [ProviderSupport.X64Flags]), "glibc below minimum is rejected");
        reject(() => ProviderSupport.CheckCapabilities(original, "2.41", [ProviderSupport.X64Flags, ["cx16"]]), "One incompatible CPU rejects provider execution");
        var incompatible = providers.Select(p => p with { MinimumGlibc = "999.0" }).ToArray();
        Trust.Validate(catalog with { Providers = incompatible }, DateTimeOffset.UtcNow); check(true, "A signed stricter ABI restriction remains structurally valid");
        reject(() => ProviderSupport.CheckCapabilities(incompatible[baseIndex], "2.41", [ProviderSupport.X64Flags]), "Stricter signed ABI requirements fail on the actual capability vector");
        ProviderSupport.CheckOwnedRoot("/owned/provider with spaces");check(true,"Spaces remain supported in owned legacy provider roots");
        foreach(var root in new[]{"/owned/with:separator","/owned/with;separator","/owned/$ORIGIN","/owned/$LIB","/owned/$PLATFORM","/owned/control\nvalue"})
        {
            var child=new ProcessStartInfo("unused-test-child");child.Environment["LD_LIBRARY_PATH"]="/caller/original:paths;$ORIGIN";
            reject(()=>ProviderEnvironment.Apply(child,host,new Dictionary<string,string>{{ProviderSupport.BaseId,root}}),
                "Owned provider root cannot redirect ld.so through separators, expansion tokens or controls");
            check(child.Environment["LD_LIBRARY_PATH"]=="/caller/original:paths;$ORIGIN",
                "Unsafe owned provider root rejection precedes child mutation and does not sanitize explicit caller library paths");
        }
        var projected = bridge with { Sequence = catalog.Sequence, IssuedAt = catalog.IssuedAt, ExpiresAt = catalog.ExpiresAt };
        Trust.ValidateCompatibility(catalog, projected); check(true, "Compatible projection preserves exact modern SDK/tool admissions");
        reject(() => Trust.ValidateCompatibility(catalog, projected with { Sequence = projected.Sequence - 1 }), "Compatible catalog cannot replay another generation");
        reject(() => Trust.ValidateCompatibility(catalog, projected with { Sdks = [baseline with { Dependencies = ["changed"] }] }), "Compatible catalog cannot change the modern SDK record");
        var serialized = JsonSerializer.Serialize(projected, UpJson.Default.Catalog);
        check(!serialized.Contains("providers", StringComparison.Ordinal) && !serialized.Contains("compatibilityCatalog", StringComparison.Ordinal), "Schema-2 bridge serialization omits all provider fields for strict old clients");
        SourceManifest(check, reject, temporary, original);

        var owned = Path.Combine(temporary, "legacy-consent"); var downloads = 0;
        using (var manager = new Manager(owned, host, (_, _) => { downloads++; throw new Exception("Unexpected provider download"); }))
        {
            reject(() => manager.Install(catalog, "5.0.214-r2").GetAwaiter().GetResult(), "Initial legacy install requires explicit provider consent before any download");
            SafeFiles.Write(Path.Combine(owned, "selection.json"), new Selection(new(), ["5.0"]), UpJson.Default.Selection);
            reject(() => manager.Update(catalog).GetAwaiter().GetResult(), "A stale tracked legacy channel without a receipt cannot grant provider consent");
            check(downloads == 0 && !Directory.EnumerateFileSystemEntries(Path.Combine(owned,"toolchains-v3")).Any()
                && !Directory.EnumerateFileSystemEntries(Path.Combine(owned,"providers")).Any(), "Consent rejection preserves empty owned activation roots");
            var forged = sdk5 with { Revision = 1 };
            var priorPath = Path.Combine(owned, "toolchains-v3", forged.Id); Directory.CreateDirectory(priorPath);
            SafeFiles.Write(Path.Combine(priorPath, "receipt.json"), new Receipt(2, SafeFiles.Owner, forged,
                new string('a', 64), 1, DateTimeOffset.UtcNow), UpJson.Default.Receipt);
            var unsignedRejected = false;
            try { manager.Update(catalog).GetAwaiter().GetResult(); }
            catch (InvalidOperationException error) { unsignedRejected = error.Message.Contains("no retained signed admission", StringComparison.Ordinal); }
            check(unsignedRejected && downloads == 0,
                "An unverified previous-revision receipt cannot grant consent for a newly tracked provider installation");
        }
        var discover = Path.Combine(temporary, "legacy-namespace");
        using (var manager = new Manager(discover, host))
        {
            var receipt = new Receipt(2, SafeFiles.Owner, sdk5, new string('a',64), 773, DateTimeOffset.UtcNow);
            var path = Path.Combine(discover,"toolchains-v3",sdk5.Id); Directory.CreateDirectory(path);
            SafeFiles.Write(Path.Combine(path,"receipt.json"),receipt,UpJson.Default.Receipt);
            check(ProviderSupport.Equal(manager.Installed().Single().Release, sdk5, UpJson.Default.SdkRelease), "Legacy receipt discovery is isolated in its schema-3 namespace");
            var bad = Path.Combine(discover,"toolchains-v2",sdk5.Id); Directory.CreateDirectory(bad);
            SafeFiles.Write(Path.Combine(bad,"receipt.json"),receipt,UpJson.Default.Receipt);
            reject(() => manager.Installed(), "Provider-dependent receipts cannot appear in the old client namespace");
            SafeFiles.DeleteTree(bad);
        }
        Extraction(check, reject, temporary, original);
        EnvironmentIsolation(check, temporary);
    }

    private static void SourceManifest(Action<bool,string> check, Action<Action,string> reject, string temporary, ProviderRelease provider)
    {
        var name=Path.GetFileName(new Uri(provider.Archive.Url).AbsolutePath);
        var row=JsonSerializer.SerializeToNode(new { architecture="x64",asset=name,record=new {
            schemaVersion=1,providerRoot=provider.Root,policySha256=provider.PolicySha256,
            companion=new { path=name,size=provider.Archive.Size,sha256=provider.Archive.Sha256 },manifest=provider.Manifest } })!;
        var value=JsonSerializer.SerializeToNode(new {schemaVersion=1,kind="branded-consumer-archive-publication",status="validated-complete-matrix",repository="dotnetdev-kr/cbodotnet",
            signingFingerprint=Trust.Fingerprint,identity=new {channel="archive",packageRevision=2,sdkVersion="5.0.214",sourceReleaseTag="sdk-5.0.214",sourceManifestSha256=new string('a',64)},
            assets=new[]{new {name,size=provider.Archive.Size,sha256=provider.Archive.Sha256}} })!;
        value["compatibility"]=new JsonArray(row);
        var source=Path.Combine(temporary,"provider-source-structure.json");File.WriteAllText(source,value.ToJsonString());
        ProviderSupport.ValidateSource(source,provider);check(true,"Provider source manifest binds exact companion bytes, policy, root and original producer release");
        foreach(var change in new Action<JsonNode>[] {
            item=>item["identity"]!["sdkVersion"]="3.1.426",item=>item["assets"]![0]!["sha256"]=new string('f',64),
            item=>item["compatibility"]![0]!["record"]!["providerRoot"]="/usr/lib/unrelated",
            item=>item["compatibility"]![0]!["record"]!["manifest"]!["providerId"]="substituted" })
        {
            var changed=value.DeepClone();change(changed);File.WriteAllText(source,changed.ToJsonString());
            reject(()=>ProviderSupport.ValidateSource(source,provider),"Provider source/manifest substitution is rejected before companion extraction");
        }
    }

    private static void Extraction(Action<bool,string> check, Action<Action,string> reject, string temporary, ProviderRelease original)
    {
        var files = new Dictionary<string,string> { ["LICENSE.openssl.txt"]="license", ["LICENSE.icu.txt"]="license", ["NOTICE.txt"]="notice",
            ["openssl.cnf"]="configuration", ["lib/libcrypto.so.1.1.1k"]="synthetic non-executable crypto marker", ["lib/libssl.so.1.1.1k"]="synthetic non-executable SSL marker" };
        var links = new Dictionary<string,string> { ["lib/libcrypto.so.1.1"]="libcrypto.so.1.1.1k", ["lib/libssl.so.1.1"]="libssl.so.1.1.1k" };
        var rows = new JsonArray(JsonSerializer.SerializeToNode(new { path="lib", type="directory", mode="0o755" }));
        foreach (var item in files) rows.Add(JsonSerializer.SerializeToNode(new { path=item.Key,type="file",mode="0o644",size=Encoding.UTF8.GetByteCount(item.Value),sha256=SafeFiles.Hash(Encoding.UTF8.GetBytes(item.Value)) }));
        foreach (var item in links) rows.Add(JsonSerializer.SerializeToNode(new { path=item.Key,type="symlink",mode="0o777",target=item.Value }));
        var node = JsonNode.Parse(original.Manifest.GetRawText())!; node["files"] = rows;
        var bytes = Encoding.UTF8.GetBytes(node.ToJsonString()); using var manifest = JsonDocument.Parse(bytes);
        var provider = original with { Manifest = manifest.RootElement.Clone(), ManifestSha256 = SafeFiles.Hash(bytes) };
        var prefix = "rootfs/" + provider.Root.TrimStart('/');
        string Archive(string tag, Action<TarWriter>? extra = null)
        {
            var archive = Path.Combine(temporary,tag+".tar.gz"); using var raw=File.Create(archive); using var gzip=new GZipStream(raw,CompressionLevel.Fastest); using var tar=new TarWriter(gzip);
            void FileEntry(string path, byte[] data) { using var input = new MemoryStream(data);tar.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile,path) { DataStream=input,Mode=(UnixFileMode)0x1A4 }); }
            FileEntry("provider-manifest.json",bytes);
            foreach(var path in new[]{"rootfs","rootfs/usr","rootfs/usr/lib","rootfs/usr/lib/cbodotnet","rootfs/usr/lib/cbodotnet/compat",prefix,prefix+"/lib"})
                tar.WriteEntry(new PaxTarEntry(TarEntryType.Directory,path) {Mode=(UnixFileMode)0x1ED});
            FileEntry(prefix+"/provider-manifest.json",bytes);
            foreach(var item in files) FileEntry(prefix+"/"+item.Key,Encoding.UTF8.GetBytes(item.Value));
            foreach(var item in links) tar.WriteEntry(new PaxTarEntry(TarEntryType.SymbolicLink,prefix+"/"+item.Key){LinkName=item.Value,Mode=(UnixFileMode)0x1FF});
            extra?.Invoke(tar); return archive;
        }
        var content=Path.Combine(temporary,"provider-extract-good"); SafeFiles.ExtractProvider(Archive("provider-good"),content); ProviderSupport.ValidateContent(content,provider);
        check(true,"Separate provider archive preserves the complete authenticated rootfs and manifest bytes");
        File.AppendAllText(Path.Combine(content,prefix,"NOTICE.txt"),"tampered");
        reject(()=>ProviderSupport.ValidateContent(content,provider),"Changed provider bytes fail inventory validation");
        var extraArchive=Archive("provider-extra",tar=>{using var input=new MemoryStream([1]);tar.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile,"rootfs/etc/unrelated"){DataStream=input,Mode=(UnixFileMode)0x1A4});});
        var extraContent=Path.Combine(temporary,"provider-extract-extra"); SafeFiles.ExtractProvider(extraArchive,extraContent);
        reject(()=>ProviderSupport.ValidateContent(extraContent,provider),"A companion cannot add an unrelated rootfs path");
        var escape=Archive("provider-escape",tar=>tar.WriteEntry(new PaxTarEntry(TarEntryType.SymbolicLink,prefix+"/escape"){LinkName="../../../../../../../../outside",Mode=(UnixFileMode)0x1FF}));
        reject(()=>SafeFiles.ExtractProvider(escape,Path.Combine(temporary,"provider-extract-escape")),"Provider links cannot escape their extracted object");
        var badTop=Archive("provider-top",tar=>tar.WriteEntry(new PaxTarEntry(TarEntryType.Directory,"other-root"){Mode=(UnixFileMode)0x1ED}));
        reject(()=>SafeFiles.ExtractProvider(badTop,Path.Combine(temporary,"provider-extract-top")),"Only rootfs and the ordinary outer manifest are provider archive roots");
    }

    private static void EnvironmentIsolation(Action<bool,string> check, string temporary)
    {
        var names = ProviderEnvironment.Scoped.Concat(ProviderEnvironment.Scoped.SelectMany(n=>new[]{"CBODOTNET_COMPAT_SAVED_"+n+"_SET","CBODOTNET_COMPAT_SAVED_"+n+"_VALUE"}))
            .Concat(new[]{"CBODOTNET_COMPAT_SCOPE","CBODOTNET_COMPAT_ROOT","CBODOTNET_CURL_COMPAT_ROOT"}).ToArray();
        var saved=names.ToDictionary(n=>n,Environment.GetEnvironmentVariable);
        try
        {
            foreach(var original in new string?[]{null,"","/caller/value with spaces"})
            {
                foreach(var name in ProviderEnvironment.Scoped)
                {
                    Environment.SetEnvironmentVariable(name,"/inherited/legacy/value");
                    Environment.SetEnvironmentVariable("CBODOTNET_COMPAT_SAVED_"+name+"_SET",original is null?"0":"1");
                    Environment.SetEnvironmentVariable("CBODOTNET_COMPAT_SAVED_"+name+"_VALUE",original);
                }
                Environment.SetEnvironmentVariable("CBODOTNET_COMPAT_SCOPE","rocky9");
                Environment.SetEnvironmentVariable("CBODOTNET_COMPAT_ROOT","/untrusted/base");
                Environment.SetEnvironmentVariable("CBODOTNET_CURL_COMPAT_ROOT","/untrusted/curl");
                var parent=names.ToDictionary(n=>n,Environment.GetEnvironmentVariable);
                var roots=new Dictionary<string,string>{{ProviderSupport.BaseId,"/owned/base"},{ProviderSupport.CurlId,"/owned/curl"}};
                ProcessStartInfo Plan(bool legacy, ProcessStartInfo? inherited = null)
                {
                    var start=new ProcessStartInfo(OperatingSystem.IsLinux()?"/bin/sh":"unused-test-child"){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true};
                    if(inherited is not null)
                    {
                        start.Environment.Clear();foreach(var item in inherited.Environment) start.Environment[item.Key]=item.Value;
                    }
                    ProviderEnvironment.Apply(start,new("fedora","45","linux-x64"),legacy?roots:new Dictionary<string,string>());return start;
                }
                var expectedPath="/owned/curl/lib:/owned/base/lib"+(string.IsNullOrEmpty(original)?"":":"+original);
                foreach(var legacy in new[]{true,false})
                {
                    var plan=Plan(legacy);
                    check(legacy
                        ?plan.Environment["LD_LIBRARY_PATH"]==expectedPath&&plan.Environment["OPENSSL_CONF"]=="/owned/base/openssl.cnf"
                            &&plan.Environment["CLR_OPENSSL_VERSION_OVERRIDE"]=="1.1"&&plan.Environment["CLR_ICU_VERSION_OVERRIDE"]=="67"
                            &&plan.Environment["SSL_CERT_FILE"]==(original??"/etc/ssl/certs/ca-certificates.crt")
                        :ProviderEnvironment.Scoped.All(n=>original is null?!plan.Environment.ContainsKey(n):plan.Environment[n]==original),
                        "Legacy scope binds curl before base while preserving the caller CA; modern scope restores all caller values");
                    check(legacy
                        ?plan.Environment["CBODOTNET_COMPAT_SCOPE"]=="rocky9"&&plan.Environment["CBODOTNET_COMPAT_ROOT"]=="/owned/base"
                            &&plan.Environment["CBODOTNET_CURL_COMPAT_ROOT"]=="/owned/curl"
                            &&ProviderEnvironment.Scoped.All(n=>plan.Environment["CBODOTNET_COMPAT_SAVED_"+n+"_SET"]==(original is null?"0":"1")
                                &&(original is null?!plan.Environment.ContainsKey("CBODOTNET_COMPAT_SAVED_"+n+"_VALUE")
                                    :plan.Environment["CBODOTNET_COMPAT_SAVED_"+n+"_VALUE"]==original))
                        :!plan.Environment.ContainsKey("CBODOTNET_COMPAT_SCOPE")&&!plan.Environment.Keys.Any(n=>n.StartsWith("CBODOTNET_COMPAT_SAVED_",StringComparison.Ordinal))
                            &&!plan.Environment.ContainsKey("CBODOTNET_COMPAT_ROOT")&&!plan.Environment.ContainsKey("CBODOTNET_CURL_COMPAT_ROOT"),
                        "Only approved provider roots enter legacy children; modern children carry no provider scope");
                }
                var scopedLegacy=Plan(true);var nestedModern=Plan(false,scopedLegacy);
                check(ProviderEnvironment.Scoped.All(n=>original is null?!nestedModern.Environment.ContainsKey(n):nestedModern.Environment[n]==original)
                    &&!nestedModern.Environment.ContainsKey("CBODOTNET_COMPAT_SCOPE")&&!nestedModern.Environment.ContainsKey("CBODOTNET_COMPAT_ROOT"),
                    "A modern manager nested inside a raw legacy child restores the pre-provider caller, never a curl/base prefix");
                var nestedLegacy=Plan(true,scopedLegacy);
                check(nestedLegacy.Environment["LD_LIBRARY_PATH"]==expectedPath
                    &&nestedLegacy.Environment["CBODOTNET_COMPAT_SAVED_LD_LIBRARY_PATH_SET"]==(original is null?"0":"1"),
                    "Nested legacy selection saves the original caller instead of stacking provider prefixes");
                var sdk5=Plan(true,scopedLegacy);
                ProviderEnvironment.Apply(sdk5,new("rocky","9.8","linux-x64"),new Dictionary<string,string>{{ProviderSupport.BaseId,"/owned/base"}});
                check(sdk5.Environment["LD_LIBRARY_PATH"]=="/owned/base/lib"+(string.IsNullOrEmpty(original)?"":":"+original)
                    &&!sdk5.Environment.ContainsKey("CBODOTNET_CURL_COMPAT_ROOT")
                    &&(original is null?!sdk5.Environment.ContainsKey("CLR_ICU_VERSION_OVERRIDE"):sdk5.Environment["CLR_ICU_VERSION_OVERRIDE"]==original),
                    "Nested SDK5 selection removes Core3 curl and ICU overrides while retaining its required base provider");
                if(OperatingSystem.IsLinux())
                {
                    foreach(var code in new[]{0,7})
                    {
                        var legacy=Plan(true);legacy.ArgumentList.Add("-c");legacy.ArgumentList.Add("test \"$CBODOTNET_COMPAT_ROOT\" = /owned/base || exit 91; test \"$CBODOTNET_COMPAT_SCOPE\" = rocky9 || exit 92; test \"$LD_LIBRARY_PATH\" = \"$1\" || exit 95; exit "+code);
                        legacy.ArgumentList.Add("legacy-environment-probe");legacy.ArgumentList.Add(expectedPath);
                        check(Manager.RunChild(legacy)==code,"Actual legacy child success/failure uses the same launch path as Manager.Run");
                        check(names.All(n=>Environment.GetEnvironmentVariable(n)==parent[n]),"Legacy child exit never changes caller process environment");
                        var modern=Plan(false,legacy);modern.ArgumentList.Add("-c");modern.ArgumentList.Add("test \"${CBODOTNET_COMPAT_ROOT+x}\" != x || exit 93; test \"${CBODOTNET_COMPAT_SCOPE+x}\" != x || exit 96; test \"${LD_LIBRARY_PATH-}\" = \"$1\" || exit 94");
                        modern.ArgumentList.Add("test-child");modern.ArgumentList.Add(original??"");
                        check(Manager.RunChild(modern)==0,"An actual nested modern child restores the original caller environment after either legacy exit");
                    }
                    var missing=Plan(true);missing.FileName=Path.Combine(temporary,"nonexistent-provider-test-child");var failed=false;
                    try {Manager.RunChild(missing);}catch(System.ComponentModel.Win32Exception){failed=true;}
                    check(failed&&names.All(n=>Environment.GetEnvironmentVariable(n)==parent[n]),"Actual child start failure preserves every caller environment value");
                }
                check(names.All(n=>Environment.GetEnvironmentVariable(n)==parent[n]),"Environment planning preserves all original caller values");
            }
        }
        finally {foreach(var name in names) Environment.SetEnvironmentVariable(name,saved[name]);}
    }
}
