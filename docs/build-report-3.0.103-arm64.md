# .NET Core 3.0.103 native Linux ARM64 build report

Status snapshot: **2026-10-31, Asia/Seoul**. Native Linux ARM64 SDK **3.0.103**, with runtime and ASP.NET **3.0.3**, was built, validated and collected successfully. The unchanged SDK archive is **157,285,088 bytes**, SHA-256 **`c93b542b20700f97345462d569bfee31d8c6a1fc12756f75d38ba87e94ec83c5`**. Both local framework origins, the split native audit, all **52 upstream smoke cases**, six functional checks in each of three Linux user spaces and the strict final delivery audit passed. Completion used original supported adapters over retained dependencies: the earlier full graph remains failed, followed by successful targeted Toolset and CoreSDK builds. The [reproducer](reproduce-core30-arm64.md) records the commands and dependency scope.

## Selected sources

| Input | Pinned selection |
| --- | --- |
| SDK | `3.0.103` |
| Runtime and ASP.NET | `3.0.3` |
| Source-build tag | `v3.0.103.1-SDK` |
| Annotated tag object | `83c8eccc8cb7fcd2cfdc28223d7d08e74268881c` |
| Source-build root | `40de72d1087a1d05dfd39c87f888a0611ec6c60f` |
| CoreCLR | `259ce7d4619478cfefe7b0c0f6fa765f765f7e37` |
| CoreFX | `a4238c9819075be9bff74e009da802ce47233f38` |
| CoreSetup | `c03f2fe62663edec83d1bc12b4e9f11bd3de5d0e` |
| ASP.NET | `bd1e14b7d16b798de8a874189c89afed755a266c` |
| CoreSDK | `ca71659745c368343b726acc43e6f332f000b0ff` |
| Product Arcade | `ce459ae07c3d7a1e68251268855e0bc7b3d97f75` |

The [corrected source-build tag](https://github.com/dotnet/source-build/tree/v3.0.103.1-SDK) names SDK `3.0.103` and runtime `3.0.3`. Its tag message explains that the earlier tag contained an incorrect ASP.NET version. The extra `.1` belongs to the source tag; it does not change the SDK or runtime version. The coordinated pins come from the root's [dependency manifest](https://github.com/dotnet/source-build/blob/40de72d1087a1d05dfd39c87f888a0611ec6c60f/eng/Version.Details.xml).

This generation builds `dotnet/source-build` directly. It has no applicable VMR route and does not use the .NET 6/7 installer-generated source-tree procedure. The full-history Git acquisition adapter completed **28 unique exports from 29 pinned declarations**, including recursive pinned submodules. Export receipts retain source URLs, revisions, archive fingerprints and initial inventories. The normal upstream `FetchSources`, revision metadata and component patch targets remain active.

## Native environment and bootstrap

The build uses the existing ARM64 WSL distribution `cbodotnet-net7-arm64`, Linux user `build`, and its separate `/home/build/cbodotnet/core30` workspace. The root checkout is `work/source-build-3.0.103`; component exports are under `bin/src`. Container mounts retain those absolute paths.

The native Bionic builder is based on `mcr.microsoft.com/dotnet/core/sdk:3.0.103-bionic-arm64v8`, pinned by manifest digest `sha256:0d56b2a713c65b541414c8f97ffc1ff614bc6af6375e4119d64001e8854e4b81`. The built image ID is `76ce8f5b3968c8dde354bcf7ed2e583e26ba6b7ea6d56d6dad0569cd650330af`. It provides Clang/LLVM 6, GNU binutils, CMake 3.10, Python 2.7/3.6, OpenSSL 1.1 and ICU 60. The harness sets `LANG=C.UTF-8` and `LC_ALL=C.UTF-8` before legacy Python or MSBuild tools run. Current project helpers used inside this image support Python 3.6.

The independently prepared Xenial ARM64 sysroot uses the pinned CoreFX generator, SHA-256 `395f773f920364a83890d885783661f68bd59b1961cffd724a643709183ae83d`, with `arm64 xenial no-lldb`. Its retained preparation log authenticates the Release signature with signing fingerprint `790BC7277767219C42C86F933B4FE6ACC0B21F32`. Verification covered **17,026 files and 5,225 symlinks**. The current and removed Ubuntu archive keyrings are recorded. Package signature checking remained enabled; the native ARM64 debootstrap wrapper did not emulate another CPU.

The original automatic rootfs target defaults to another architecture/suite. An explicit compatibility gate selects the preserved signed sysroot instead. The final SDK's measured GLIBC maximum is **2.17**, passing the **2.23** profile ceiling. External verification libraries have separate requirements below.

Private bootstrap preparation passed in `reports/runs/bootstrap-20261030T1717129891479Z/core30-bootstrap.json`:

| Bootstrap input | Actual identity |
| --- | --- |
| Official ARM64 SDK | `3.0.100`, 113,669,548 bytes, SHA-256 `ffcd9db434dab9f068bbf229a4e20f935cab0b48b28e4a83c114c6c1f0f5f6f6` |
| Original PSB archive | `Private.SourceBuilt.Artifacts.0.1.0-3.0.100.tar.gz`, 469,688,508 bytes, SHA-256 `e8542ab2d6c4383b8c2aee8cdb86cd1952a542f8633df57082054bf48588a09b` |
| Actual retained Arcade SDK | `1.0.0-beta.19381.1`, 149,380 bytes, SHA-256 `1dd51e1be96cc1c95697fca77467d92a7c17906661d6be910e20b2e1f60da70f` |

The root declares bootstrap Arcade `1.0.0-beta.19359.6`, while its product graph pins Arcade `1.0.0-beta.19463.3`. The current setup explicitly uses the different genuine retained `19381.1` bootstrap package, whose nuspec records commit `8f3c22397990aeb20a88690b51dad4b33f21e7ff`. It builds and installs the upstream integrated XPlat SDK resolver, probes the actual selected tool, and preserves the original SDK/PSB archives and root `global.json`. This preparation does not build the SDK product.

The root task assembly also implements SDK resolution. Every new root process refreshes and installs its reviewed current output at the normal path before loading tasks, preventing stale same-name assemblies after feed-task changes. That operation and its loading probe are recorded separately from the original bootstrap receipt.

## Active compatibility changes

The completed CoreSDK invocation uses **31 active patches**, numbered `0001`–`0018` and `0020`–`0032`, manifest SHA-256 `1249f5f35c199408724258d902078fe99ac85af1892b163a69f657d6704c899d`. The exact chain passed 1,404 bounded checks; the final native ASP.NET version-alias fixture passed 37 checks across six cases. The proposed `0019` CMake-cache change is absent: the actual Bionic CMake configured the original cache successfully. Trial files remain only in ignored research.

| Area | Recorded changes |
| --- | --- |
| Native construction | Explicit ARM64 host/sysroot/Clang forwarding, main native CoreLib crossgen and original CoreCLR NuGet packaging; native CoreSetup, ASP.NET and CoreSDK tool/JIT selection preserves native-image and perfmap construction. |
| Native compiler compatibility | The upstream GDBJIT array base-size query is backported without disabling GDBJIT; CoreFX compiler and cross switches pass as independent singleword arguments. |
| SDK composition | The CoreSDK adapter selects the actual ASP.NET ARM64 installer RID and flows its genuine version into the original archive-version alias, retaining deferred version evaluation and overwrite protection. |
| Acquisition and restore | The complete explicit Git command survives the old Darc producer; exact retired indexes and bootstrap-only restore sources use recorded official/local feeds. |
| Bootstrap dependencies | The original SourceLink bootstrap version flows until a real local Common version exists; CoreCLR tooling explicitly selects a genuine retained Platforms package. |
| Managed tooling and tests | A pinned-source GenAPI build hook, scoped official `net472` metadata and original host-policy preservation/native execution guard passed actual tool use; original smoke-suite routing remains a separate final gate. |

Every patch application checks the source pins, original/intermediate/final target hashes, upstream patch inputs and complete staged chains. Unknown edits are rejected. Normal upstream patches and generated configuration/version changes still run; 31 authored patches do not mean that only 31 source files changed during the graph.

Nine exact retired NuGet service indexes are mapped to the official `dotnet-public` index: the five original common mappings, the CoreCLR index, and the actual Toolset nested SDK's VSTest, MSBuild and container-tools indexes. Local feeds and non-package blob URLs are preserved. Supported additional sources include nuget.org and Microsoft's `dotnet-public`, `dotnet-eng`, `dotnet-tools` and `myget-legacy` indexes. The harness selects supported SocketsHttpHandler while preserving TLS certificate validation. Feed repairs retain requested versions; the explicit Platforms tooling selection below is a separately disclosed exception.

The pinned SourceLink bootstrap dependency is `1.0.0-beta2-19322-03`. The actual `Microsoft.SourceLink.Vsts.Git` package was retrieved from the official `myget-legacy` feed, 286,682 bytes, SHA-256 `82c8206b5cb78bf95040619f35f5ac8562651d3623e0856cea0185a714182cca`. A different PSB SourceLink version is not substituted.

CoreCLR originally requests Platforms `3.0.0-rc2.19461.13`. Exact current-feed probes could not retrieve it. The original PSB contains real `Microsoft.NETCore.Platforms` **3.0.0**, 10,669 bytes, SHA-256 `80c1d7c6075d91a16310751dbc84dc9bfd0bfe23fe8bf52bdc245d8cf50ec57f`, with `runtime.json` SHA-256 `c38956f91e505ce6c65f717f79c3b638ae2805c8a801126bd72a24c6b62fbaec` and source commit `4ac4c0367003fe3973a3648eb0715ddb0e3bbcea`. An explicit property selects that real tooling/RID-graph input for both consumers. Its package identity is preserved and NU1603 is not suppressed. Product SDK/runtime version properties remain `3.0.103`/`3.0.3`.

## Actual progress and retry preservation

The native CoreCLR run passed the previous compiler failure, generated the main ARM64 CoreLib native image and performance map, and produced local `3.0.3-servicing` runtime/CoreCLR/JIT transport packages. Separate final byte-chain audits remain required beyond these component milestones.

The historical graph requires newly published feed identities on each invocation. Before retries, `prepare-core30-retry.py` evaluates the selected pinned adapters and requires exact package identity, verified component revision and full byte equality to actual local producer outputs before moving a feed copy into a private recovery directory. The original new-package guard remains enabled. Native/object caches and producer packages remain in place.

In `build-20261030T1954220084617Z`, the retry preflight **proved and preserved all 56 published packages**. This includes `Microsoft.Private.Standard.2.1.0-prerelease.26530.1`, `NETStandard.Library.2.1.0`, and their symbol packages. The additional Standard output contract is established from pinned `packages.builds`, the `IsShipping=false` transport project and Arcade's symbol-output producer; it is not inferred from a coincidentally named cache file. Earlier incomplete preflights moved no packages and remain retained.

The same attempt ran the pinned Arcade GenAPI hook. Its `netcoreapp2.1` DLL compiled, then the original `net472` target failed with MSB3644 because the .NET Framework 4.7.2 reference assemblies were unavailable. The hook keeps the original GenAPI/Cci.Extensions sources and `net472;netcoreapp2.1` target frameworks and uses `ExcludeFromSourceBuild=false`.

Patch `0023` supplies explicit official **Microsoft.NETFramework.ReferenceAssemblies.net472 1.0.3** compilation input: **20,790,130 bytes**, SHA-256 `ffa0a5570a39f911399164d0581ffddef99b5e3dfbaa5f220e5ce22969bcf57c`. The preparation helper verifies all **374 original package entries** and extracted bytes. Only the extra GenAPI command receives `TargetFrameworkRootPath=<extracted>/build/` and `CustomAfterMicrosoftCommonTargets=<extracted>/build/Microsoft.NETFramework.ReferenceAssemblies.net472.targets`; the latter is the package's original reference-resolution metadata. Product reference selection and both original GenAPI frameworks remain unchanged. This is a disclosed prebuilt reference-only input.

The actual `reports/net472-preflight-20261030T2007118961889Z` preflight passed: private bootstrap SDK **3.0.100** compiled a `net472` managed probe, all ten resolved references came from the fixed input, no framework DLL was copied into the output, the original input remained unchanged, and no Windows output was executed.

Retry 17, `build-20261030T2008595120376Z`, then built and packaged **both original GenAPI frameworks**. Its retained `genapi-construction.json` proves complete producer/feed/restored-package byte equality and ordinary version flow, while explicitly recording `hostConfigurationStructurallyValid=false`. CoreFX tool invocations failed with 147 errors: the added modern `RollForward=Major` property collided with the original `rollForwardOnNoCandidateFx=2` template. A direct native launch independently rejected the dual-policy runtime configuration. Package construction and consumer restoration therefore did not establish usable GenAPI execution.

Patch `0024` removes only the added `RollForward` property and retains the original template value **`rollForwardOnNoCandidateFx=2`**. [verify-core30-genapi.py](../scripts/verify-core30-genapi.py) requires that exact single policy, verifies both original framework payloads and the packaged/runtime-output configuration, binds the actual verified ARM64 bootstrap, runs native `--help`, and performs real bounded DataAnnotations PNSE source generation before normal package publication/CoreFX use. It uses private native `/tmp` home/CLI/XDG directories of mode `0700`, disables certificate generation and clears inherited host-policy overrides. No Windows output is executed and no package or runtimeconfig bytes are rewritten.

The original `RemoveBuiltPackagesFromCache` target preserves the prior cached nupkg and clears the matching extracted package files and markers; ordinary NuGet restore re-extracts the rebuilt package. Patch `0025` uses the supported rebuild operation only for GenAPI and its project references to regenerate stale runtime output. The actual native help/API-generation guard then passed. Successful CoreFX attempt 19 used local GenAPI `1.0.0-beta.19463.3`: producer/feed/cache bytes match SHA-256 `adc3405a8023124f92f35ebf27ef11db98fdf1f8932306915564670b1de28bf8`. Independent replay of the closed CoreFX binlog recorded **35 successful `GenerateNotSupportedSource` Exec tasks**. No `GenerateReferenceAssemblySource` execution is claimed.

CoreFX produced transport version **`4.6.0-servicing.20067.1`**. CoreSetup attempt 21 completed native crossgen, normal versions-file generation and runtime/reference packaging, producing **162 native images and 162 perfmaps** in their separate original directories. The selectors recognize the pinned default `OSGroup=Unix` as well as explicit Linux while checking the ARM64 host RID. No versions file was synthesized.

ASP.NET attempt 22 completed **130 native images and 130 perfmaps**. Its internal runtime archive is 7,874,155 bytes, SHA-256 `80efab006ae2ac6f4ec386107212ac0c9dbf8600b4de012f8237707c0775ec02`. These source-produced component archives precede the separate final shared-framework comparison and actual CoreSDK input-copy proof.

## Successful incremental SDK closure

The full attempt `build-20261030T2129210024446Z` completed the required component dependencies but failed in Toolset restore. Its original failed status and full log remain unchanged. An exact-version Microsoft.Docker.Sdk **1.1.0** restore preflight passed before invoking the original Toolset adapter directly.

`targeted-toolset-20261030T2239473242267Z` then passed the original `repos/toolset.proj /t:Build /p:SkipRepoReferences=true` invocation. It produced and published byte-identical internal and language-pack ZIPs, respectively **31,150,251** and **7,151,454 bytes**. Its genuine construction used the **30-patch** manifest `e5228aaf5ef81bcc6877c60a3ccfdd71030d43e8b24714fcd22d2eaeed6baa5b`. The original archive adapter's `SkipEnsurePackagesCreated=true` remains unchanged because these outputs are ZIPs, rather than NuGet packages.

The successful CoreSDK attempt **`build-20261030T2306588329132Z`** ran the original `repos/core-sdk.proj /t:Build /p:SkipRepoReferences=true` over those verified dependencies. Its 31-patch manifest preserves the exact Toolset 30-patch prefix and adds only the consumer-side `0032` ARM64 ASP.NET version alias. The complete dependency-feed preflight proved **301 packages and moved zero**. The original adapter reported **zero warnings and zero errors**; its inner elapsed time was **1:18.71**, and the complete targeted helper ran from **23:07:01.564564 to 23:08:44.766062 UTC**. These are incremental timings, not a cold full build. The final producer archive and normal outer copy match the SDK size/hash above.

Two unavailable exact test-template packages were retained as explicit external inputs by [prepare-core30-template-inputs.py](../scripts/prepare-core30-template-inputs.py): `Microsoft.DotNet.Test.ProjectTemplates.2.2` **1.0.2-beta4.19155.2** from the fully hashed official **2.2.207 Linux x64 SDK**, and `.3.0` **1.0.2-beta4.19354.2** from the official **3.0.100 Linux ARM64 SDK**. Only architecture-neutral template nupkgs were extracted. No x64 SDK/runtime was executed, no emulation was used, package versions were preserved and these inputs are not labeled source-produced.

This supported incremental closure does not create a successful full-root marker. The normal root `AfterTargets=Build` aggregate-report trigger is not invoked by direct adapter targeting. A separate original root `ReportPrebuiltUsage` invocation passed in `prebuilt-report-20261030T2313406407023Z`, with unchanged baseline policy, `RootRepo=core-sdk` and `SkipRepoReferences=true`. No product `Build` target ran during that reporting step. This root selection omits the historical `known-good` dummy final leaf, so its additional post-last-project conflict-detection coverage is not claimed.

The preserved aggregate contains **7,399 raw usage rows**, **359 distinct case-folded ID/raw-version pairs**, and baseline differences of **51 new rows and 24 removed identities**. Its assets ZIP contains **486 project-assets entries**, and **29 package-version snapshots** are retained. There are **36 original report/baseline files**, plus pinned/current producer/schema controls in a verified **58-member preservation archive**. No conflict-report directory was produced. These are original scanner/baseline results, rather than a zero-prebuilt claim: PSB packages can be classified as source-built by the original target, references are excluded from that scanner when online, and static/test resources may remain in its coverage. Raw versions are not independently normalized as NuGet semantic versions.

## Verified framework and native origins

`reports/construction/origin-evidence.json` and `native-component-origin.json` passed for the exact SDK hash above. Every **188 runtime** and **134 ASP.NET** shared-framework entry matches the respective local archive, with no missing, additional or changed entries. The core runtime archive is **87,323,211 bytes**, SHA-256 `ae0496dd81226f099c770c013e8d3c2fd82a878d8b1e4e66ec56008c0fbf90d8`; CoreSetup writes this producer directly to the root assets feed. ASP.NET's original installer archive and root blob copy match separately; no absent ASP.NET asset-feed copy is invented.

The runtime's successful sole-local-copy task occurred in **the earlier failed CoreSDK attempt `build-20261030T2257015115994Z`**. The final successful `230658` invocation records the exact same local runtime candidate and reuses the unchanged destination. Its ASP.NET copy task completed successfully in the final invocation. Separate complete closed-binlog replays read **19,902 earlier events** and **32,859 final events**, with two and one completed selected download tasks respectively. The audit requires the authentic earlier failed status, preserved pre-alias manifest/binlog inventory, successful runtime task, exact source/destination hashes and final candidate. It does not attribute both copy tasks to the final invocation or promote the earlier failed build to success.

The separate native audit covers **all 180 selected runtime payloads**: **164 CoreFX managed assemblies**, including **162 verified native-image transformations**, **13 native/CoreLib payloads**, and **three CoreSetup host outputs**. Native CoreLib differs from its IL input, and completed native-image generation is tied to actual output paths and logs. All three extracted transport caches were absent at final inspection. The original upstream cache-removal target and root properties were verified; exact packages retained in retry quarantine are bound to CoreSetup's recorded assets SHA-512 and completed earlier producer-equality receipts. No missing live cache file is claimed to have been inspected.

One consumed `System.Runtime.CompilerServices.Unsafe` IL payload differs from the later current producer output. Its evidence is explicitly historical: the completed original producer receipt pins that package generation, whose original IL leads to the actual native image and unchanged runtime/SDK bytes. Other selected historical/current payload comparisons match. This is incremental provenance across real retained generations, rather than an assertion that every current output or package generation is identical.

The initial failed audit and its original frozen tools remain preserved under `reports/origin-tools/amendments/20261030T2324302546225Z`. Reviewed helper amendments and their before/after inventories explain the corrected cache-generation and cross-attempt task attribution; source/product/SDK bytes were not changed to satisfy the audit.

## Native matrix and external dependencies

The unchanged SDK passed all six functional checks in **Ubuntu 22.04, Ubuntu 24.04 and Debian 13 ARM64** user spaces sharing the WSL kernel. The checks cover console DLL execution, native apphost execution, RSA-SHA256 signing/verification, cryptographic random bytes, `fr-FR` decimal formatting and ASP.NET loopback HTTP. All three measured RIDs are **`linux-arm64`**. Every one of the **19 ELF files is AArch64**; maximum requirements are **GLIBC `2.17`, GLIBCXX `3.4.21` and CXXABI `1.3.7`**. Each run records both verification/smoke status as passed and preserves the original SDK hash.

| Verification user space | Measured RID | Explicit external inputs | Result |
| --- | --- | --- | --- |
| Ubuntu 22.04 | `linux-arm64` | Original .NET 5 Focal OpenSSL 1.1 bundle | All six checks passed |
| Ubuntu 24.04 | `linux-arm64` | Same unchanged OpenSSL 1.1 bundle | All six checks passed |
| Debian 13 | `linux-arm64` | Same OpenSSL 1.1 bundle plus original Core 3.1 Focal ICU 66 bundle | All six checks passed, with globalization enabled |

OpenSSL libraries/configuration retain their original .NET 5 producer identity, image `d7f3d9624f9f2ec9d6dfb3c0ed1743eab582378d0a4ee40dfb0bc9e66bed288a`: `libssl1.1:arm64` **1.1.1f-1ubuntu2.24**, and the `openssl` configuration package **1.1.1f-1ubuntu2.16**. The separately supplied libcrypto requires GLIBC **2.25**. Debian uses original Core 3.1 ICU producer image `ab750d90bdf890c078039cf6f52d3dd44862f3df8f6cdaf4ea771a802e18e3a0`, package `libicu66:arm64` **66.1-2ubuntu2.1**, with explicit `CLR_ICU_VERSION_OVERRIDE=66`; those external libraries require GLIBC **2.29**. These inputs are outside the SDK archive and are not relabeled as Core 3.0 products. Their requirements do not change the measured SDK-only GLIBC 2.17 result. No stock OpenSSL-3-only or Debian ICU-76 compatibility is claimed, and invariant globalization was not used.

Reports are retained under `reports/verify-ubuntu22`, `verify-ubuntu24` and `verify-debian13-icu66`, with original dependency contracts and licenses under `verification-compat`/`verification-icu`. A first matrix-driver policy-path preflight stopped before SDK execution. The corrected driver reused the exact successful-build seccomp policy, separately preserved under `verification-security`; the SDK and policy bytes were unchanged.

## Release evidence

| Gate | Current result |
| --- | --- |
| Final SDK archive | Passed: original targeted CoreSDK adapter; 157,285,088 bytes, SHA-256 `c93b542b20700f97345462d569bfee31d8c6a1fc12756f75d38ba87e94ec83c5` |
| Fresh full graph invocation | Not claimed; failed full22 and successful targeted Toolset/CoreSDK closure retained separately |
| Complete runtime and ASP.NET framework comparisons | Passed: all 188 runtime and 134 ASP.NET entries match their local component archives |
| Split CoreCLR/CoreFX/CoreSetup local byte chain | Passed: all 180 selected payloads; historical input-generation scope disclosed above |
| Actual successful CoreSDK local archive-copy tasks | Passed: runtime in earlier failed `225701`; ASP.NET in final successful `230658`, both with unchanged exact archive bytes |
| Original 52-case local/online smoke suite | Passed: all 52 cases, 156 commands, two certificate setups, zero exclusions, upstream exit 0 |
| Ubuntu 22.04, Ubuntu 24.04 and Debian 13 native matrix | Passed: all six checks in each environment, explicit external inputs above |
| SDK ABI measurements | Passed: 19 AArch64 ELF files; GLIBC 2.17 / GLIBCXX 3.4.21 / CXXABI 1.3.7 |
| Final collection and delivery audit | Passed: unchanged SDK, both checksum files, all 7,663 report files and 185 current build-input records verified |
| Original aggregate report and preservation | Passed: 7,399 raw rows; 51 new and 24 removed baseline entries; coverage limitations above |

The full suite **`test-20261030T2313422949049Z` passed with upstream exit 0**: all **52 original cases and 156 commands**, both local/online phases, two certificate setups, every HTTP/HTTPS case and **zero exclusions**. It uses a fresh extraction of the same SDK archive and private home/CLI/XDG state. The passed summary is `reports/runs/test-20261030T2313422949049Z/core30-smoke-summary.json`, SHA-256 `0f5539b50aa37be5916ea642ac51bb047cd76685711e0eb138e7b28e5d805eec`. SDK SHA-512 is `cebc95c4782c1402185511c66b306726c239f3b0037da0dcd39b558550d189faa29a4bf2fbbaeb07f34e665233da482bc929a09e90fc15ff6567e001c0010087`.

The test-only certificate adapter uses this fresh SDK's built-in `dotnet dev-certs https`, rather than obtaining the unavailable original preview tool. Its **64,512-byte** assembly, SHA-256 `b928790f8cf8d54b4f581767f7112f5937a011d0f2cc373e2b5f5208370267bf`, matches the actual pinned ASP.NET producer and the locally produced `dotnet-dev-certs.3.0.3-servicing.26530.1.nupkg` member. Producer source/revision, complete package equality and actual help execution are recorded separately. All original command functions/assertions and HTTPS cases remain enabled; private certificate keys are not archived. This older suite has no later license/poison classes or XML-documentation assertion. Its local phase still uses permitted recorded package feeds and is not an offline-build test.

The bounded reader compiled and ran with SDK 9.0.121 under private native `/tmp` homes and with certificate generation disabled. The final origin results above bind its actual completed replays and all retained archive fingerprints; the separate native audit discloses historical/current generation differences.

The collected archive is [cbodotnet-sdk-3.0.103-linux-arm64-build.1.tar.gz](../artifacts/3.0.103-linux-arm64/cbodotnet-sdk-3.0.103-linux-arm64-build.1.tar.gz). The strict final audit verified complete report membership, both checksum files, exact profile contents and all current input bytes. Its profile SHA-256 is `6cd24fdc157c70b56241685c2fb0ce3557c20f1e146a70320b50d8c275922ef0`; manifest SHA-256 is `07cdb8568de65ef19fe73e7340fcff96cbe104e5596d42cae56801fdbf199582`. These are local generated artifacts; they are excluded from Git and have not been published as a binary release.

The graph uses an official bootstrap SDK, historical previously source-built tooling, reference packages and online binary dependencies. `sourceOnly=true` identifies the legacy graph mode. Native verification uses the explicit dependencies above; the original prebuilt report records nonzero usage and baseline differences. No zero-prebuilt, clean-bootstrap, Stage 2, performance-parity or bit-for-bit reproducibility claim is made.
