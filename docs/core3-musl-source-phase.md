# Core3.1 musl source and certificate checkpoint

This extends the [initial issue35 investigation](core3-musl-investigation.md), preserving its committed files. Native ARM64 compiles the SDK tasks, MSBuild, Roslyn, CLI, NuGet, VSTest and F# components from their pinned sources. Fresh original CLI/toolset builds now generate their real archives, and original core-sdk composition produces a private SDK3.1.426 using those outputs and the source-built native CLR/JIT/crossgen. Its archive passes C#/VB/F#/FSI, ASP.NET HTTP, TLS and real LTTng consumers with normal ReadyToRun. Imported framework/host/package inputs, local assembly-version placeholders, branding and localization still prevent source SDK qualification. The [machine-readable checkpoint](core3-musl-source-phase.json) records actual commands, input/output hashes, failed attempts and pending gates; every qualification/admission flag remains false.

The new [source probe](../scripts/core3-musl-source-probe.py) and [experimental input pins](../profiles/experimental/core3-musl-source.json) reproduce four bounded modes. These ran on native ARM64 Alpine3.24.4 under local rootful Podman in the D-backed task WSL distro, with non-root containers, dropped capabilities and no emulation. Final native x64/ARM64 GHA Docker qualification remains separate.

| Actual proof | Result and limit |
| --- | --- |
| Source components | Original SDK tasks `netcoreapp2.1` and core-sdk tasks `netcoreapp3.1` compile. These are component outputs. |
| Source package | Original SDK task project compiles **both** original TFMs (`netcoreapp2.1`, `net472`) and packs `Microsoft.NET.Sdk.3.1.426-servicing.22566.17.nupkg`. All96 members are hashed; the package contains no ELF or bootstrap performance-test SDK directories. |
| Source-generated SDK metadata | Original core-sdk `BuildCoreSdkTasks;GenerateBundledVersionsProps` generates SDK3.1.426 and `NETCoreSdkRuntimeIdentifier=linux-musl-arm64`. Its source metadata was not patched. |
| Certificate validation | Shared [reviewed fixture](../scripts/musl-negative-certificates.cs) uses default `SslStream` with no permissive callback. A trusted localhost control connects; self-signed/untrusted, expired, wrong-hostname and invalid-CA certificates reject. Invalid-CA `X509Chain` reports `InvalidBasicConstraints`, exercising the OpenSSL3 error mapping. |
| Runtime-only repetition | The same compiled fixture passes with normal `COMPlus_ReadyToRun=1`, full ICU, no SDK/compiler/dev packages, `--network=none` and loopback TLS. Shared full ELF closure passes. Temporary public test roots/intermediates live only in an ephemeral HOME/CurrentUser store and are removed in `finally`. |
| Source MSBuild/compiler/tooling | Exact MSBuild16.7.3 six-project solution builds its five packages. Source Roslyn retains its genuine `3.7.0-dev.20570.4` version; its compiler runs in the minimal runtime with all13 original resource cultures. CLI builds seven local packages and NuGet builds fifteen. These are component proofs, without full corresponding-source closure. |
| Source VSTest | Exact source `c1b6b2c` plus its seven original source-build patches produces `16.7.0-dev`, without relabeling it as the original publisher's16.7.1 request. Its188 managed products are IL-only. English and all13 explicit UI cultures run in the SDK-free minimal consumer with normal ReadyToRun. |
| Source F# | Exact source `3ef6f0b5` plus all four original source-build patches reproduces buildtools Proto → compiler Proto → Release compiler/interpreter → `Microsoft.FSharp.Compiler.10.10.0-dev.nupkg`. The tracked probe's17 source commands pass. Its separate minimal consumer runs compiler help, compiles/runs an F# application and executes an FSI bigint script; all four commands pass with normal ReadyToRun. F# localization remains pending. |
| Original toolset consumer | Original redist restore, original `tool_fsc` restore and original redist build all pass using actual source-built F# `10.10.0-dev` instead of the unavailable publisher stamp. The855-file diagnostic layout contains other imported managed components; it is not a complete source-built SDK. |
| Fresh full SDK composition | New source61 generates the original toolset internal/langpack archives. Original core-sdk source plus all nine upstream patches restores and builds; source54 native components and source61 toolset bytes are actually consumed. Its143,922,130-byte private archive passes ordinary source SDK compilation/runtime checks and archive-only LTTng with GC80/80/native control1. This remains a mixed input experiment with all admission gates closed. |

The original outer SDK project also copies bootstrap SDK siblings for its performance tests. Those diagnostic copies are outside the component package, are **not** fresh compilation outputs, and are excluded from the retained source-output selection. A first attempted removal hook did not eliminate every sibling; the actual package-member audit determines the scope. Component package bytes can differ across these diagnostic runs because temporary source paths and generated package metadata differ. This is not a bit-reproducible build claim.

The private bootstrap imports SDK3.1.425 PE/data only and excludes every ELF from that glibc SDK archive. Its native host/runtime is official linux-musl-arm64 runtime3.1.32 with the already reviewed branch-native OpenSSL3 and original-manifest trace candidates. Only the imported private bootstrap disables ReadyToRun. Its original `NETCoreSdkRuntimeIdentifier=linux-arm64` metadata receives an exact hash-guarded private adaptation to musl; final source-generated metadata already produces musl directly. The original SDK/core-sdk `global.json` remains SDK3.1.425 plus Arcade1.0.0-beta.22558.6.

The probe records every MSBuild property. Package mode passes the native musl RID, `ToolsRID`, `ProductMonikerRid`, `CoreSetupRid`, ARM64 architecture and disables the portable-glibc fallback. Explicit source commit hashes and component suffix are recorded; `GitCommitCount=0` is synthetic archive-only diagnostic metadata, and must be replaced with real Git-derived release provenance in a complete producer. SourceLink/control-manager queries and shared compilation are disabled for these unpacked-source probes. Normal final SDK optimization and apphost remain required.

Restored NuGet archives, byte lengths, whole-file SHA256/SHA512 and feed metadata are retained. The [actual-cache reader](../scripts/core3_musl_restore_inputs.py) follows every original `project.assets.json` packageFolders root instead of assuming HOME is the only cache. VSTest uses a second repository-local cache. Every used package's NuGet content hash is recomputed from its unchanged retained archive. Signed-package contentHash excludes the signature entry and adjusts ZIP metadata; it differs from the signed ZIP's whole-file SHA512. The [data-only reader](../scripts/musl_nuget_content_hash.py) matches actual trusted `NuGet.Packaging.GetContentHash` results for all151 retained VSTest inputs. It does not verify signature trust. Focused tests reject forged content hashes, undeclared caches, escaped paths and malformed ZIP structures.

The authenticated VSTest input snapshot has19 assets files,151 retained packages across two caches and629 actual package bindings. The original toolset replay has8 assets files,269 retained packages and574 bindings. The tracked F# source run has13 assets files,117 packages and896 bindings. Complete package-byte capture does not establish complete corresponding-source/license coverage. Foreign restored runtime/tool assets remain inventoried separately; neither restore nor mere presence proves execution or shipment.

For reproduction, mount the repository read-only at `/repo`, the original native investigation inputs at `/inputs`, and the new SDK425 input plus writable output directory at `/phase`. Use the exact worker and minimal-consumer image IDs in the JSON, derived from the previously committed container recipes. The worker modes share these arguments:

```sh
python3 /repo/scripts/core3-musl-source-probe.py \
  --mode source-package \
  --inputs-dir /inputs --bootstrap-inputs-dir /phase \
  --native-evidence /inputs/candidate-verified \
  --trace-evidence /inputs/trace-verified \
  --output-dir /phase/new-source-package
```

`source-components` compiles the two component DLLs; `negative` compiles and runs the shared certificate fixture. Use new empty output directories. Source restore uses the original official configured feeds without package-version changes. The runtime-only mode runs in the separate minimal-consumer image, with the previously audited SDK-free runtime at `/runtime`, the `negative` mode's application output at `/application`, and network disabled:

```sh
python3 /repo/scripts/core3-musl-source-probe.py \
  --mode negative-consumer --runtime-dir /runtime \
  --application-dir /application --output-dir /phase/new-certificate-consumer
```

The earlier MSBuild/Arcade restore blockers are resolved for these component experiments. Original [CLI source](https://github.com/dotnet/cli/tree/cca488d5d530e6ec291134abe3462fed613a4429) requests an unavailable MSBuild preview by default; the [authoritative source-build graph](https://github.com/dotnet/source-build/blob/ab8b115b5658237ee8916ae3586600b39fb2fd19/eng/Version.Details.xml) coherently builds MSBuild16.7.3 from [commit2f374e28](https://github.com/dotnet/msbuild/tree/2f374e28ea8abbeee841bf805955a72a39c88b81). Its original resolver, compiled unchanged as private infrastructure, selects pinned imported Arcade1.0.0-beta.22558.6. Exact original component `global.json` files remain untouched. This is an explicit private bootstrap override, not a claim to have source-built Arcade or reproduced a missing publisher package. Approximate NuGet matches remain rejected.

The [F# source/consumer probe](../scripts/core3-musl-fsharp-probe.py) and [input profile](../profiles/experimental/core3-musl-fsharp.json) reproduce the new F# result. Mount a writable fresh native work directory separately from the evidence directory. Its source mode requires the successful exact-source MSBuild component run and five-package feed; their actual package identities/hashes are recorded. Imported SDK/Arcade remain private bootstrap inputs with ReadyToRun disabled there only.

```sh
python3 /repo/scripts/core3-musl-fsharp-probe.py --mode source \
  --inputs-dir /inputs --bootstrap-inputs-dir /phase \
  --msbuild-run-dir /phase/msbuild-resolver-five \
  --arcade-package /phase/reusable-package/restored-packages/microsoft.dotnet.arcade.sdk/1.0.0-beta.22558.6/microsoft.dotnet.arcade.sdk.1.0.0-beta.22558.6.nupkg \
  --work-dir /native-work/new-fsharp-source --output-dir /phase/new-fsharp-source
```

The exact F# source archive is `fsharp31.tar.gz` under bootstrap inputs. The original `source-build31.tar.gz`, musl runtime and existing reviewed native candidates are under `/inputs`. Every source command's exit status is saved before collection, so later copy or inventory failures cannot erase it. In the separate minimal-consumer image, disable networking and omit the SDK/compiler packages:

```sh
python3 /repo/scripts/core3-musl-fsharp-probe.py --mode consumer \
  --inputs-dir /inputs --bootstrap-inputs-dir /phase \
  --source-evidence-dir /phase/new-fsharp-source \
  --work-dir /tmp/new-fsharp-consumer --output-dir /phase/new-fsharp-consumer
```

Direct F# compiler fixtures use `--simpleresolution`, matching original `Microsoft.FSharp.NetSdk.targets` and `FSharp.Profiles.props`. The helper normalizes the SDK tar's `./packs` prefix and requires the actual targeting references before compiling. Earlier fixtures that omitted these inputs failed and remain recorded. Source package bytes may differ between runs because source paths and generated package metadata differ; there is no byte-identical rebuild claim. The original toolset replay consumed the earlier38 F# package; the tracked50 source/51 consumer pair independently verifies its freshly produced package.

The [VSTest source-data helper](../scripts/core3_musl_vstest_resources.py) checks the complete pinned original archive and all252 XLF files. It preserves18 neutral XLF files and converts234 localized XLF files, containing5460 original targets, into literal RESX source. All234 generated RESX hashes match the successfully compiled native VSTest run. The original projects then compile all13 satellite cultures; no binary satellite is imported. Altered XLF/neutral RESX, extra XLF files and attempts to overwrite generated files are rejected.

```sh
python3 /repo/scripts/core3_musl_vstest_resources.py \
  --source-dir /native-work/original-patched-vstest \
  --source-archive /phase/vstest31.tar.gz --receipt /phase/new-vstest-resources.json
```

Use the seven original VSTest patches from source-build `ab8b115b`, followed by [the one-line neutral UI culture patch](../patches/core3-musl/0003-preserve-declared-vstest-ui-culture.patch). Original `CreateSpecificCulture` maps explicit `zh-Hans`/`zh-Hant` to regional cultures whose current ICU parent chains omit those script-neutral resources. `GetCultureInfo` preserves the requested culture. All13 explicit cultures pass; arbitrary regional Chinese fallback is not qualified. Build/publish the original `src/{vstest.console,testhost,datacollector}` projects, pack the original `Microsoft.TestPlatform.Build` project, then run original `src/package/package.csproj` publish and `Microsoft.TestPlatform.CLI.csproj` pack. Actual full commands, project adaptations, local feed fingerprints and the genuine `16.7.0-dev` version are in the checkpoint evidence. Linux source packaging keeps the native Core TestHost outputs and omits unbuilt Windows .NET Framework TestHost copies; this is recorded as a bounded layout adaptation.

Complete pristine CLI/toolset/MSBuild sources and actual Arcade SDK source archives/licenses were retained separately. The published glibc **source-only** release archive was also verified and inspected; it contains prior producer source adaptations, for example an MSBuild SDK422 bootstrap adaptation where pristine upstream requests420. No compiled glibc output, or prior adapted source as a compiled input, was reused here. Exploratory direct CLI/toolset/MSBuild attempts explicitly invoked private425 while retaining their original global pins; those overrides and the single retired-feed transport mapping are recorded, not hidden as pristine upstream behavior.

The [native source/consumer probe](../scripts/core3-musl-native-probe.py) and [native experiment profile](../profiles/experimental/core3-musl-native.json) now reproduce the complete CoreCLR3.1 native build from exact source `c17d273a`. Fresh tracked54 compiles all six original Release targets: CLR, JIT, DAC, DBI, LTTng provider and crossgen. Its full native command succeeds in469.21 seconds at two jobs with stock Clang20, original `-O3`, global `-Werror`, ReadyToRun, profiling and tracing enabled. The original GNU C++ VLA warning stays visible through a specific `-Wno-error=vla-cxx-extension`; optimization and runtime features remain enabled.

The [native compatibility patch](../patches/core3-musl/0004-coreclr31-clang20-native-compat.patch) follows the existing two-file PAL typed-null patch. It backports the exact two upstream metadata allocation-marker hunks, makes existing raw-memory destinations explicit without changing their addresses or byte counts, and corrects invalid template member names and runtime-only DAC cache mutators. Independent native checks compare every initialized field and byte in the34-row register table, and prove the original ZapNodeType already has unsigned-int storage, size, alignment and identical named-value bytes. Explicit enum storage permits the existing computed crossgen node codes. No vendor native output enters this build.

Original `eng/empty.csproj:GenerateNativeVersionFile` produces the dated community native identity `4.700.26.55804` with the actual source commit, using private pinned SDK8.0.131. The original global SDK/Arcade pins stay unchanged. Its netcoreapp2.0 version-only reference restore emits the original visible NU1903 warning; that runtime is neither executed nor shipped. The actual assets input snapshot retains11 packages and all bindings. Original Arcade22114 is an SDK resolver input outside those assets caches; separate tracked57 authenticates its unchanged1.16MB archive, publisher `184ce2c7`, and MIT metadata. Future source mode captures it inline. This additional accounting leaves completed54–56 evidence untouched and does not claim package signature trust or complete corresponding source.

Fresh SDK-free tracked55 verifies all17 ELF dependency closures, cold generics/floating point/SIMD/threadpool/GC/reflection/full-ICU behavior, and real source crossgen IL-to-R2R compilation. The generated PE has a124-byte native header and runs with normal ReadyToRun enabled. Separate tracked56 records2555 decoded DotNETRuntime events,80 GCStart/80 GCEnd and one independent native LTTng control. Both consumers run non-root with networking disabled, no capabilities, no SDK/compiler, and no preload or ptrace relaxation. They explicitly overlay the new native outputs onto original host/managed runtime3.1.32 with the already source-built OpenSSL compatibility input; they are not completed source SDKs. Earlier separate native consumers also pass the negative TLS/certificate fixture, genuine source F#/FSI and source Roslyn/VSTest with all13 explicit cultures.

The source worker needs full LLVM20 including llvm-ar/link and the LTTng headers. Mount a fresh writable native work directory, repository read-only and evidence outside the worktree. The pinned SDK8 archive is private version/fixture tooling; SDK425 supplies test-only3.1 targeting references. Record an actual dated community attempt:

```sh
python3 /repo/scripts/core3-musl-native-probe.py --mode source \
  --source-archive /inputs/coreclr31.tar.gz --bootstrap-sdk /bootstrap.tar.gz \
  --targeting-sdk /phase/bootstrap-sdk425.tar.gz --official-build-id 20261108.4 \
  --work-dir /native-work/new-clr31 --output-dir /phase/new-clr31
```

In the separate minimal image, use a new work/evidence directory and normal container isolation:

```sh
python3 /repo/scripts/core3-musl-native-probe.py --mode consumer \
  --native-evidence-dir /phase/new-clr31 --runtime-archive /inputs/product-runtime.tar.gz \
  --crypto-native /inputs/candidate-verified/candidate-native/corefx31-OpenSsl.so \
  --work-dir /tmp/new-clr31-consumer --output-dir /phase/new-clr31-consumer
```

Repeat with `--mode lttng` in the separate SDK/compiler-free tracing image and fresh directories. Native artifact bytes can differ because generated version/build paths differ; this is not a bit-reproducible claim. Original source Git identity, all27 modified source file fingerprints, native-version output, compiler commands,498 generated source files, original inputs and earlier failed attempts are retained.

F# localization, complete managed framework/core-sdk/ASP.NET source production and used-source/license review, the independent Core3.0 native branch, final native two-CPU producer/consumer qualification and all distribution admission remain pending. No release workflow, SDK10 dependency policy or published product changes are part of this checkpoint.

## Fresh SDK composition and archive consumers

After the old task WSL was deleted, source61 rebuilt the CLI/toolset from retained pinned source archives and genuine component feeds in a newly created D-backed native environment. It did not reuse the old855-file layout or claim that deleted source/cache inputs survived. New image identities and staging fingerprints are retained separately. All34 source/restore/pack commands pass. Redist Pack produces only the CLI Runtime package, so six original child projects are explicitly packed before toolset restore; the latter actually consumes all seven unchanged new CLI packages and the source NuGet/VSTest/F# feeds. The original toolset Build;Pack generates its internal and language-pack ZIPs, totaling41,702,939 bytes. Their complete member inventories contain no ELF. The new actual-input snapshot has16 project assets,273 retained packages and1,069 bindings.

Original core-sdk `e81f6c85` plus all nine original source-build patches performs full redist composition. Its existing `file://` blob mechanism consumes the actual fresh toolset ZIP. Its native musl runtime archive is explicitly mixed: original host/managed framework inputs remain imported, five native runtime components equal source54 outputs, and OpenSSL compatibility equals the previously source-built branch input. Original crossgen remains enabled and actually uses source54 crossgen/JIT bytes. A public ASP.NET archive contains an additional glibc runtime; the first attempt rejects it. The subsequent adapter extracts only the original `shared/Microsoft.AspNetCore.App` component, verifies that component contains no ELF and records every excluded combined-runtime member. ASP.NET's managed binaries remain imported corresponding-source gaps.

Core-sdk's original source-build patch requests PlatformAbstractions3.1.32, which is unavailable from public feeds. Source64 compiles the unchanged original `core-setup/f94bb2c3` PlatformAbstractions project for both netstandard1.3 and netstandard2.0. Original CommonManaged/Versions properties naturally generate3.1.32; no package/assembly version override is used. The original source-build `AlwaysPackEvenIfNotServicing` rule matters: the servicing6 entry records the last-produced package and normally skips packaging; it does not assign the source version. Private directory adapters select existing pinned Arcade infrastructure. Its local assembly version42.42.42.42 is explicitly retained, and this package is build-task infrastructure rather than a qualified product component.

Original core-sdk Restore, original musl runtime-package Restore and Build pass; Build takes115.24 seconds. The retained143,922,130-byte SDK archive has1,874 files,19 ELF and387 ReadyToRun managed assemblies. Its five native runtime hashes, actual source crossgen/JIT inputs and consumed toolset ZIP are independently checked. SDK65 retains20 scoped project assets,306 unchanged packages and1,164 bindings. The [actual-cache reader](../scripts/core3_musl_restore_inputs.py) now accepts explicit source project roots and records them. NUnit3.DotNetNew.Template1.5.3 embeds its publisher's historical Windows `obj/project.assets.json` as a package member. The new accounting proves that member's bytes match the unchanged package ZIP, retains it separately and does not treat it as a restore performed here. External cache paths are still rejected; six focused tests include this real regression and an outside-worktree search-root control.

Current implementation fingerprints refer to the scoped reader and its tests. Exact pre-change Git blob bytes are retained separately with their commit, blob identity and hashes for historical source/native evidence. Completed earlier proof files remain unchanged.

Archive-only SDK66/67 consumers run non-root, with network disabled, dropped capabilities, normal ReadyToRun and no other SDK mounted. SDK info/version and source MSBuild pass. Default C# and VB console projects build and execute; source FSI executes a script. An ordinary F# template first reports its missing4.7.2 dependency against an empty offline feed. The follow-up uses an unchanged, pinned public FSharp.Core4.7.2 archive as a test-only feed, with no template or version override; F# builds and executes. This test dependency is not inserted into the SDK archive. An ordinary ASP.NET project builds and serves HTTP200 `Hello World!`. A source-SDK-compiled loopback TLS client/server both negotiate TLS1.2 using the source OpenSSL compatibility component.

Separate SDK68 runs in the new SDK/compiler-free tracing image. The candidate archive itself compiles the netcoreapp3.1 GC workload. With no overlays, host SDK, networking or security overrides, decoded output contains2,541 DotNETRuntime events,80 GCStart,80 GCEnd and exactly one independent native LTTng control; the managed workload prints READY/DONE. The original seven-SDK tracing worker is copied only as a bounded private adapter with its exact3.1 target and separate session name; the public seven route remains unchanged.

This checkpoint does not fix the85 local42.42.42.42 managed assemblies, rebuild all imported dependencies, add CLI branding or complete F# localization. Seven primary placeholder outputs account for the affected CLI assemblies/satellites and both SDK task TFMs. The next source build must use original dated official-build version properties and compile branding from original resource sources before repeating actual toolset/core-sdk composition. No vendor PE is relabeled. Full host/framework/ASP.NET and package source/license closure, all13 F# cultures, independent3.0 source production, normal native x64/ARM64 qualification and every distribution gate remain pending.
