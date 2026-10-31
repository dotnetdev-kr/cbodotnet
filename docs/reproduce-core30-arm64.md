# Reproduce the native Linux ARM64 .NET Core 3.0 build

Status snapshot: **2026-10-31, Asia/Seoul**. SDK **3.0.103** with runtime/ASP.NET **3.0.3** was built, validated and collected successfully in the separate native ARM64 environment. Both local framework origins, the native-runtime audit, all **52 upstream cases**, six functional checks in three Linux user spaces and the final delivery audit passed. Completion is incremental: retained dependencies from a failed full attempt, followed by the original supported targeted Toolset and CoreSDK adapters. The unchanged SDK is **157,285,088 bytes**, SHA-256 `c93b542b20700f97345462d569bfee31d8c6a1fc12756f75d38ba87e94ec83c5`. See the [build report](build-report-3.0.103-arm64.md) for evidence and dependencies.

## 1. Use the separate native workspace

Use ARM64 Windows, PowerShell 7.3+, native ARM64 WSL 2, Podman and an unprivileged Linux user. The current installation uses the existing D-backed `cbodotnet-net7-arm64` distribution, user `build` and a separate Core 3.0 workspace. The [fresh WSL initializer](../scripts/Initialize-Net7Wsl.ps1) is available for a new installation; it refuses to replace an existing distribution. It is not a prerequisite to recreate a distribution already used by other builds.

```powershell
$distro = 'cbodotnet-net7-arm64'
$workspace = '/home/build/cbodotnet/core30'
$linuxProject = '/mnt/d/Projects/cbodotnet'
$source = "$workspace/work/source-build-3.0.103"
$inputs = "$workspace/inputs"
```

Run the public entry point from the project directory:

```powershell
./scripts/Invoke-Core30Build.ps1 -Mode Acquire -Distribution $distro `
    -LinuxWorkspaceRoot $workspace -CpuAffinity '4,5'
```

Select two CPUs available to the native container if the current `4,5` pair differs on a new host. Each invocation records the selected affinity and uses two MSBuild workers. Acquisition creates the exact full-history source-build root at `40de72d1087a1d05dfd39c87f888a0611ec6c60f`, selects the native container, and acquires pinned sources through [clone-legacy-sources.py](../scripts/clone-legacy-sources.py). It retains full-history bare stores, recursive submodule revisions and non-overwriting export receipts. The actual current acquisition produced 28 unique exports from 29 declarations.

The source tag is **`v3.0.103.1-SDK`**. It corrects the original release's ASP.NET selection and still targets SDK `3.0.103`/runtime `3.0.3`. This direct `dotnet/source-build` graph uses `bin/src` and `bin/arm64/Release`; it does not use a VMR or the .NET 6/7 source generator.

Unprivileged actions mount the dedicated workspace as a whole, preserving source/input absolute paths and atomic retry recovery across their directories. The project path is mounted separately. Native sysroot preparation alone uses a privileged container and a read-only source mount.

## 2. Retain the original bootstrap inputs and prepare

Place the original PSB archive in the private inputs directory before `Prepare`. This command downloads only when that path is absent:

```powershell
$psb = "$inputs/Private.SourceBuilt.Artifacts.0.1.0-3.0.100.tar.gz"
$psbUrl = 'https://dotnetcli.blob.core.windows.net/source-built-artifacts/assets/Private.SourceBuilt.Artifacts.0.1.0-3.0.100.tar.gz'
wsl.exe -d $distro -u build --exec bash -c `
    'if [[ ! -e "$1" && ! -L "$1" ]]; then curl --fail --location --output "$1" "$2"; fi' `
    core30-psb $psb $psbUrl
if ($LASTEXITCODE) { throw 'The original PSB download failed.' }

./scripts/Invoke-Core30Build.ps1 -Mode Prepare -Distribution $distro `
    -LinuxWorkspaceRoot $workspace -CpuAffinity '4,5'
```

The bootstrap helper requires exactly **469,688,508 bytes** and SHA-256 `e8542ab2d6c4383b8c2aee8cdb86cd1952a542f8633df57082054bf48588a09b`. It rejects a partial or different existing file. Preserve that evidence before separately obtaining a correct input; do not overwrite an unknown archive.

[prepare-core30-bootstrap.py](../scripts/prepare-core30-bootstrap.py) downloads and verifies the official ARM64 SDK **3.0.100** against its pinned SHA-512. It preserves the original SDK/PSB archives and root `global.json`, extracts the genuine retained Arcade **1.0.0-beta.19381.1** package, builds/installs the original integrated XPlat SDK resolver, and probes the actual selected Arcade tool. The completed bootstrap contract and environment file live under `inputs/bootstrap-state`. Retained Arcade is an explicit different bootstrap input from the root's unavailable `19359.6` declaration and the product graph's `19463.3` dependency.

The Bionic builder is pinned by [arm64-core30.Containerfile](../containers/arm64-core30.Containerfile) and [the profile](../profiles/dotnet-3.0.103-linux-arm64.json). It supplies native Clang/LLVM 6, GNU binutils, Python 2.7/3.6, CMake 3.10, OpenSSL 1.1 and ICU 60. The harness exports `LANG=C.UTF-8`, `LC_ALL=C.UTF-8` and `NUGET_XMLDOC_MODE=none` before legacy tools and restores. No newer Python interpreter is assumed inside this image.

`Prepare` independently generates an ARM64 Xenial sysroot from the pinned CoreFX script with `arm64 xenial no-lldb`. The script's original hash, authenticated Release signature, signing fingerprint, current/removed Ubuntu archive keyrings, packages, files and symlinks are retained under `reports/sysroot`. Existing sysroots are verified rather than recreated. The current root has 17,026 files and 5,225 symlinks. Package authentication stays enabled and no CPU emulation is used.

The original automatic rootfs target must remain explicitly skipped because its default is another architecture/suite. The prepared ARM64 target root supplies native headers/libraries; the Bionic container's user space is not the final target ABI policy.

## 3. Run the original product graph

```powershell
./scripts/Invoke-Core30Build.ps1 -Mode Build -Distribution $distro `
    -LinuxWorkspaceRoot $workspace -CpuAffinity '4,5'
```

The public [build-core30.sh](../scripts/build-core30.sh) preserves the normal root graph, `FetchSources`, original component patches, package-creation guards and reports. It selects `RootRepo=core-sdk`, `Platform=arm64`, `TargetRid=linux-arm64`, `PortableBuild=true`, `NativeArm64Host=true` and `DotNetBuildFromSource=true`. An explicit complete executable wrapper binds the frozen Git acquisition command. The normal `FetchSources` target still invokes and validates that adapter.

Each native producer receives its supported compiler/cross argument and the signed target root. CoreCLR uses its main locally built ARM64 crossgen for native CoreLib and emits the original transport packages. CoreSetup native-image construction remains enabled. CoreFX compiler/cross switches are separate singleword arguments because the old shell driver reparses whitespace. Actual final compiler, shared-framework and ABI evidence remain required.

The completed CoreSDK [patch manifest](../patches/core30/manifest.json) has **31 active patches**, numbered `0001`–`0018` and `0020`–`0032`, SHA-256 `1249f5f35c199408724258d902078fe99ac85af1892b163a69f657d6704c899d`. The exact chain passed 1,404 bounded checks. No `0019` CMake-cache patch is active: actual Bionic CMake accepted the pinned cache. The guarded applicator checks root/component pins, upstream patch inputs, exact patch hashes and original-to-final chains before mutation. It rejects unknown target contents and does not synthesize product completion markers.

Restore maps **nine exact reviewed retired service indexes** to official `dotnet-public`: the five common endpoints, CoreCLR, and the observed Toolset nested SDK's VSTest/MSBuild/container-tools endpoints. It preserves local sources, package versions and blob-asset URLs. Supported additional official sources provide historical engineering dependencies. Bootstrap-Arcade projects receive a scoped local-first restore override. Explicit `DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER=1` avoids the historical CLI driver's Curl default while retaining certificate validation.

Two bootstrap dependency decisions are explicit:

- SourceLink keeps its original `1.0.0-beta2-19322-03` dependency until a real locally built Common version exists. Its exact `Microsoft.SourceLink.Vsts.Git` package is available from Microsoft's `myget-legacy` feed. A different retained PSB version is not substituted.
- CoreCLR selects genuine retained `Microsoft.NETCore.Platforms` **3.0.0** for both tooling and the packaging RID graph, using `CbodotnetBootstrapPlatformsVersion`. The original RC2 declaration is unavailable from the checked feeds. [prepare-core30-platforms.py](../scripts/prepare-core30-platforms.py) proves the original PSB, real package identity, source commit and `runtime.json`; it does not relabel a package or suppress NU1603.

The pinned Arcade GenAPI hook selects only the original project and normal project references with `ExcludeFromSourceBuild=false`, retaining `net472;netcoreapp2.1`. An earlier packaging run stopped on MSB3644 for missing .NET Framework 4.7.2 reference assemblies.

[prepare-core30-framework-refs.py](../scripts/prepare-core30-framework-refs.py) prepares the fixed official **Microsoft.NETFramework.ReferenceAssemblies.net472 1.0.3** reference-only input under `inputs/core30-framework-refs`. Its archive is **20,790,130 bytes**, SHA-256 `ffa0a5570a39f911399164d0581ffddef99b5e3dfbaa5f220e5ce22969bcf57c`; all 374 original package entries and extracted bytes are verified. Patch `0023` passes `TargetFrameworkRootPath=<extracted>/build/` and imports the package's original `Microsoft.NETFramework.ReferenceAssemblies.net472.targets` through `CustomAfterMicrosoftCommonTargets`, scoped only to the extra GenAPI command. It preserves both original target frameworks and introduces no product SDK/runtime reference override.

The actual `net472-preflight-20261030T2007118961889Z` probe passed with SDK 3.0.100: all ten resolved references came from that fixed input, no framework DLL was copied into the output, the input stayed unchanged and no Windows output was executed. Retry 17 subsequently built/packaged both original GenAPI frameworks and verified producer/feed/cache byte equality. Its retained construction report explicitly marks the tool's host configuration invalid: the added modern `RollForward=Major` property conflicted with the original `rollForwardOnNoCandidateFx=2`, and direct native execution confirmed rejection. This led to 147 CoreFX errors despite successful package construction/restoration.

Patch `0024` removes only that added property and preserves the original **`rollForwardOnNoCandidateFx=2`** template. [verify-core30-genapi.py](../scripts/verify-core30-genapi.py) checks the exact single-policy runtime configuration, verifies both original framework payloads against the source-produced package, binds the verified native ARM64 bootstrap, runs `--help`, and generates actual bounded DataAnnotations PNSE source before normal package publication and CoreFX use. Home/CLI/XDG state uses private native `/tmp` directories of mode `0700`, certificate generation is disabled, and inherited runtime-policy overrides are cleared. It does not rewrite package/configuration bytes or execute a Windows output.

The original `RemoveBuiltPackagesFromCache` target preserves the cached nupkg and clears its extracted files/markers before normal NuGet re-extraction. Patch `0025` uses the supported rebuild operation only for the GenAPI project and its references to regenerate stale runtime output. The actual native execution guard passed. Independent replay of successful CoreFX attempt 19 recorded all **35 `GenerateNotSupportedSource` Exec tasks successful**, using the locally produced `1.0.0-beta.19463.3` GenAPI package. No custom cache-content edit or `GenerateReferenceAssemblySource` execution is claimed.

Native selectors preserve actual image generation: CoreSetup produced **162 native images and 162 perfmaps**, and ASP.NET produced **130 of each**. CoreSetup accepts its pinned Linux default `OSGroup=Unix` with the verified native ARM64 host RID. ASP.NET uses its existing `CrossgenToolPackagePath=crossgen` override. CoreSDK requires its guarded target-time tool/JIT selection because the old target overwrites ordinary evaluation-time globals; its original R2R task groups remain enabled. The final adapter also flows the genuine ARM64 ASP.NET package version into the original generic archive-version alias.

Before CoreSDK restore, [prepare-core30-template-inputs.py](../scripts/prepare-core30-template-inputs.py) supplies two exact external template inputs from fully hashed official SDK archives: `Microsoft.DotNet.Test.ProjectTemplates.2.2` **1.0.2-beta4.19155.2** from **2.2.207 Linux x64**, and `.3.0` **1.0.2-beta4.19354.2** from **3.0.100 Linux ARM64**. It extracts only architecture-neutral template package data, preserves package versions, records original archive/member hashes, and does not execute any x64 binary or label these inputs source-produced. The public build harness prepares and verifies this local feed.

## 4. Retain failed attempts and retry inputs

Every action creates a unique directory under `artifacts/3.0.103-linux-arm64/reports/runs/`, with frozen scripts/patches/profile, image and seccomp provenance, command/status/resource logs, source/bootstrap checks and retry receipts. Failed attempts remain available.

The source-build graph expects new package identities to enter the root feed during each invocation. [prepare-core30-retry.py](../scripts/prepare-core30-retry.py) first evaluates the pinned adapters and proves every affected feed package against a real component producer by package identity, verified component revision and full archive bytes. Only after the complete preflight passes does it move those published copies to a private `inputs/retry-quarantine/<attempt>` directory. Producer packages and native/object caches remain available to the cached rebuild; the original new-package guard remains enabled.

The retained `build-20261030T1954220084617Z` retry proved and preserved **56 packages**, including the Standard transport and shipping/symbol outputs. The helper proves Standard's nonshipping transport from pinned `packages.builds` and `IsShipping=false`, and proves symbol subdirectories from the original Arcade packaging target. A basename or restored-cache match alone is insufficient. Earlier incomplete producer preflights preserved their reports and moved no feed packages.

The per-attempt environment policy retains the host's default seccomp policy and adds only native AArch64 `fchmodat2` permission when necessary. Its base/result hashes and host libseccomp interpretation are recorded. It does not disable seccomp or alter a future SDK archive.

The measured completion was a supported incremental recovery rather than a new complete root invocation. Full attempt `build-20261030T2129210024446Z` retained its genuine failed status after completing the required dependencies. Exact Docker SDK **1.1.0** restoration was verified separately, then original `repos/toolset.proj /t:Build /p:SkipRepoReferences=true` succeeded in `targeted-toolset-20261030T2239473242267Z`. Its two genuine local transport ZIPs remain bound to the **30-patch** construction manifest `e5228aaf5ef81bcc6877c60a3ccfdd71030d43e8b24714fcd22d2eaeed6baa5b`.

Original `repos/core-sdk.proj /t:Build /p:SkipRepoReferences=true` then succeeded in **`build-20261030T2306588329132Z`**. Its preflight proved **301 feed packages with zero moves**, and the actual producer archive equals its original outer copy. The SDK's 31-patch manifest preserves all 30 Toolset patches and adds only the reviewed consumer-side `0032` version alias. Both commands use the private bootstrap contract, original SDK 3.0.100 MSBuild, the normal Release/ARM64/portable/native-host properties and two workers. Frozen command arrays, scripts, manifests, bootstrap/closure proofs and logs are retained in those attempt directories. The SDK adapter reported zero warnings/errors and **1:18.71** inner elapsed time; this is a cached incremental timing.

The public `Build` command above remains the starting point for a fresh workspace. The completed experiment does not establish a clean first-invocation full build. Reusing the targeted path requires independently proving the completed dependency set and transport bytes first; setting `SkipRepoReferences=true` alone is insufficient. Do not create a successful full-root marker or replace the retained failed attempt's status.

## 5. Compare actual output and prove origins

The actual successful raw archive path is:

```text
/home/build/cbodotnet/core30/work/source-build-3.0.103/bin/arm64/Release/dotnet-sdk-3.0.103-linux-arm64.tar.gz
```

Compare the final archive's runtime and ASP.NET trees with the actual local archives using [inspect-sdk-construction9.py](../scripts/inspect-sdk-construction9.py) and explicit `--runtime-version 3.0.3`. The actual comparison passed for **188 runtime and 134 ASP.NET entries**. Run analysis helpers on the WSL host when they require newer Python; do not assume Bionic supplies it.

The separate final origin procedure must also prove the split CoreCLR/CoreFX/CoreSetup chain: component outputs, produced NuGet transports, outer feed copies, CoreSetup's recorded resolution metadata, native CoreLib and every resulting runtime DLL/shared library/native host. Where original package cleanup removed extracted consumer files, bind the retained original nupkg to producer/feed bytes and preserve the exact upstream cleanup contract; do not claim absent live files were hashed. CoreSDK's closed logs must show successful actual local archive-copy tasks with matching retained destination bytes. Incremental reuse must identify the invocation that performed each copy. ASP.NET's local installer output and blob copy are required; an absent root asset-feed copy is not replaced with an inferred record.

The bounded reader uses analysis SDK 9.0.121 under private native `/tmp` `HOME`, `DOTNET_CLI_HOME` and mode-0700 `XDG_RUNTIME_DIR`, with certificate generation disabled. Actual complete replays and the combined origin audit passed. Frozen tools belong under `reports/origin-tools/final-core30`, and construction results under `reports/construction`. Completion evidence binds the successful targeted SDK invocation, original failed full22 status/log, genuine Toolset30 prefix, no-move dependency plan and external retained templates.

Runtime copy evidence comes from preserved failed **`build-20261030T2257015115994Z`**, while the ASP.NET task comes from successful **`build-20261030T2306588329132Z`**. The former replay reads 19,902 events and the latter 32,859. The final invocation must still contain the exact local runtime candidate, and retained runtime producer/blob/destination bytes must remain identical: **87,323,211 bytes**, SHA-256 `ae0496dd81226f099c770c013e8d3c2fd82a878d8b1e4e66ec56008c0fbf90d8`. A URL candidate alone does not establish a completed copy; the earlier successful task and authentic failed invocation must also be retained. ASP.NET must have its completed successful task in the final replay.

The native audit passed **180 runtime payloads**: 164 CoreFX managed assemblies with 162 actual native-image transformations, 13 native/CoreLib payloads and three CoreSetup host outputs. All three live transport caches were absent. Exact quarantine nupkgs are bound to CoreSetup's assets SHA-512 and earlier completed producer-equality receipts, with the original cleanup target preserved. One historical `System.Runtime.CompilerServices.Unsafe` IL generation differs from the later current output; the audit traces its original producer receipt to old IL, real native image, runtime archive and final SDK. It does not assert live-cache verification or equality across those distinct generations. Initial failed audit/tools and amendment inventories remain preserved under `reports/origin-tools/amendments/20261030T2324302546225Z`.

Direct adapter invocation bypasses the root `AfterTargets=Build` aggregate-report trigger. After the SDK is complete, run the original report-only target using the verified bootstrap environment and the same original global properties:

```bash
"$source/.dotnet/dotnet" "$source/.dotnet/sdk/3.0.100/MSBuild.dll" \
  "$source/build.proj" /t:ReportPrebuiltUsage /m:2 /nr:false \
  /p:RootRepo=core-sdk /p:SkipRepoReferences=true \
  /p:Configuration=Release /p:Platform=arm64 /p:TargetOS=Linux \
  /p:TargetRid=linux-arm64 /p:PortableBuild=true /p:NativeArm64Host=true
```

Run it inside the same pinned Bionic image after loading the verified bootstrap contract, with private home/CLI/XDG state and certificate generation disabled. The controlled wrapper verifies the unchanged report-target closure and SDK archive, disables network, records a unique report invocation and refuses existing aggregate output. It runs no product `Build` target. Actual `prebuilt-report-20261030T2313406407023Z` passed. Preserve the original baseline and all raw aggregate/conflict reports: the snapshot contains **7,399 raw usage rows**, **359 raw identity/version pairs**, **51 new and 24 removed baseline entries**, **486 project-assets ZIP members** and **29 version snapshots**. The verified preservation archive contains **58 members**, including **36 original report/baseline files** and source controls. No conflict-report directory was produced. `RootRepo=core-sdk` omits the historical `known-good` empty final leaf, so its extra post-last-project conflict-detection coverage is not claimed. PSB classification and online reference exclusions also prevent treating this report as a clean or zero-prebuilt result.

## 6. Execute the complete fresh-SDK smoke suite

After a complete SDK is available:

```powershell
./scripts/Invoke-Core30Build.ps1 -Mode Test -Distribution $distro `
    -LinuxWorkspaceRoot $workspace -CpuAffinity '4,5' `
    -LinuxSdkArchive "$source/bin/arm64/Release/dotnet-sdk-3.0.103-linux-arm64.tar.gz"
```

[prepare-core30-smoke.py](../scripts/prepare-core30-smoke.py) verifies the pinned routed source, extracts the selected archive into a fresh private test root, validates SDK/runtime identity and probes the actual built-in certificate tool. A private script/configuration copy supplies official feed routing and `dotnet dev-certs https`; all original test command functions remain byte-identical. SDK/certificate-tool fingerprints and local producer comparisons are recorded. The SDK archive is unchanged.

The actual full invocation **`test-20261030T2313422949049Z` passed all 52 local/online cases, 156 commands and two HTTPS certificate setups**, with **zero exclusions** and upstream exit **0**. Both phases and every HTTP/HTTPS case remained enabled. The helper requires exact counts, ordered completion, all terminal markers and unchanged recorded inputs. Its passed summary SHA-256 is `0f5539b50aa37be5916ea642ac51bb047cd76685711e0eb138e7b28e5d805eec`. Logs and selected inputs are retained; private homes and certificate keys are excluded.

The built-in development-certificate assembly is proven against the actual local ASP.NET output and source-produced `dotnet-dev-certs.3.0.3-servicing.26530.1.nupkg`: **64,512 bytes**, SHA-256 `b928790f8cf8d54b4f581767f7112f5937a011d0f2cc373e2b5f5208370267bf`. Source/revision, full package hashes and real help-probe execution are recorded. This is a test-only replacement of unavailable preview-tool acquisition, preserving every original test command/assertion and HTTPS case. The older suite has no later XML-documentation assertion or source-build license/poison classes. Its local phase permits recorded public feeds and does not establish an offline build.

## 7. Verify and collect the exact final archive

The unchanged archive passed all six functional checks in native **Ubuntu 22.04, Ubuntu 24.04 and Debian 13**, with measured RID **`linux-arm64`** in all three. Use [verify-sdk.sh](../scripts/verify-sdk.sh) with `--expected-version 3.0.103 --framework netcoreapp3.0 --expected-rid linux-arm64 --max-glibc 2.23`. Its 19 AArch64 ELF files require at most **GLIBC 2.17, GLIBCXX 3.4.21 and CXXABI 1.3.7**. Preserve both the verifier's `verification.json` and ABI ledger.

Each actual run supplied the unchanged original .NET 5 Focal OpenSSL 1.1 bundle separately, read-only, through `LD_LIBRARY_PATH` and `OPENSSL_CONF`. The dependency contract records `libssl1.1:arm64` **1.1.1f-1ubuntu2.24** and configuration package `openssl` **1.1.1f-1ubuntu2.16**; external libcrypto requires GLIBC **2.25**. Debian 13 additionally used the original Core 3.1 Focal `libicu66:arm64` **66.1-2ubuntu2.1** bundle with `CLR_ICU_VERSION_OVERRIDE=66` and its library path; it requires GLIBC **2.29**. Preserve original producer image IDs, hashes, licenses and configuration without relabeling those inputs or inserting them into the SDK tarball. `fr-FR` formatting passed with globalization enabled. These are controlled dependency results, not stock OpenSSL-3-only/ICU-76 compatibility or an SDK-wide GLIBC 2.29 requirement.

Actual results live in `reports/verify-ubuntu22`, `verify-ubuntu24` and `verify-debian13-icu66`. The initial matrix-driver policy lookup stopped before SDK execution; its preserved correction selects the exact successful-build seccomp policy under `reports/verification-security` and changes no SDK/policy bytes. Native user spaces share the WSL kernel; untested operating systems and workloads require their own checks.

Only after actual build, origin and test evidence passes should [collect-artifacts.py](../scripts/collect-artifacts.py) copy the archive unchanged. Execute its **public project path** so the rebuild-input inventory refers to the real repository; a nested frozen copy is provenance, not the execution entry point. For the direct Core 3.0 contract it checks the pinned root/manifest, component revision metadata, exact SDK/framework versions and required native archive headers. Collection records reports and construction declarations but does not independently evaluate test/origin success.

Use the actual immutable build image ID from the successful attempt's `derived-image.json`:

```powershell
$release = "$linuxProject/artifacts/3.0.103-linux-arm64"
# Set this from the actual successful attempt; the current builder ID is recorded above.
$buildImageId = '76ce8f5b3968c8dde354bcf7ed2e583e26ba6b7ea6d56d6dad0569cd650330af'
wsl.exe -d $distro -u build --exec python3 "$linuxProject/scripts/collect-artifacts.py" `
    --source-dir $source --profile "$linuxProject/profiles/dotnet-3.0.103-linux-arm64.json" `
    --reports-dir "$release/reports" --output-dir $release --build-image-id $buildImageId
```

The collected archive is [cbodotnet-sdk-3.0.103-linux-arm64-build.1.tar.gz](../artifacts/3.0.103-linux-arm64/cbodotnet-sdk-3.0.103-linux-arm64-build.1.tar.gz), accompanied by manifest and SHA-256/SHA-512 files. Final collection and strict delivery audit passed: the SDK bytes, both checksums, all **7,663 report files**, **185 current build-input records** and exact current profile contents were verified. For a new build, refresh collection after all report/project-input writes stop and repeat that audit. The tested SDK's SHA-512 is `cebc95c4782c1402185511c66b306726c239f3b0037da0dcd39b558550d189faa29a4bf2fbbaeb07f34e665233da482bc929a09e90fc15ff6567e001c0010087`. Generated outputs remain excluded from Git; this local completion does not publish a binary release.

The legacy graph uses an official bootstrap SDK, historical previously source-built tooling, reference packages and online binary dependencies. `sourceOnly=true` describes that graph mode. A clean bootstrap, zero-prebuilt construction, Stage 2 build, performance parity and bit-for-bit reproducibility are outside the current verified scope.
