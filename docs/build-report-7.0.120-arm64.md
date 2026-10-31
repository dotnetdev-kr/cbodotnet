# .NET SDK 7.0.120 Linux ARM64 build report

Status snapshot: **2026-10-31, Asia/Seoul**. SDK `7.0.120` built successfully with both locally built `7.0.20` shared frameworks. The unchanged archive passed six native checks on Ubuntu 22.04, Ubuntu 24.04 and Debian 13. The upstream smoke run completed with **41 passed, zero failed and one skipped**. Four recorded source patches and preserved recovery steps were required. Local archive-copy and final-byte evidence establish the two included frameworks' origins; they do not establish an entirely prebuilt-free build or byte equivalence with Microsoft's SDK. The [reproduction guide](reproduce-net7-arm64.md) gives the public procedure.

## Pinned inputs and intended construction

| Item | Selected value |
| --- | --- |
| SDK / installer tag | `7.0.120` / `v7.0.120` |
| Installer commit | `25b977658c06fd0217ec0bc0714398bb9d0a7bb0` |
| Latest published .NET 7 SDK across feature bands | `7.0.410` |
| Shared runtime / release date | `7.0.20` / 2024-05-28 |
| Runtime source commit | `0fb6ac59fb1edbe4ed3ad62661df0eb7eacd7903` |
| ASP.NET source commit | `d9ba962869d1b1c410ea476b02de2f8e27eec762` |
| SDK component commit | `a06803c09702777c6550fede13c8bdc52d780191` |
| Native bootstrap SDK | `7.0.118`, Linux ARM64 |
| Expected original PSB input | `7.0.118`, `centos.8-x64` |
| Build system | Generated legacy installer source-build |
| Host / target | Native ARM64 / `linux-arm64` |
| Compiler / target sysroot | LLVM 16 / independently generated ARM64 Xenial |
| Intended maximum GLIBC requirement | `2.23`; measured maximum `2.17` |
| Parallelism | Two selected CPUs, `DOTNET_PROCESSOR_COUNT=2`, MSBuild `/m:2` |

The [profile](../profiles/dotnet-7.0.120-linux-arm64.json) records configuration and the measured shared-framework construction. .NET 7 uses the installer repository's source-build generator because it predates the VMR build route used for newer releases. Both included shared frameworks match the local build archives, and successful installer copy tasks identify those local inputs. The proof below is scoped to these frameworks. [Official generation workflow](https://github.com/dotnet/installer/blob/v7.0.120/src/SourceBuild/README.md), [component dependency metadata](https://github.com/dotnet/installer/blob/v7.0.120/eng/Version.Details.xml).

The build is configured as `sourceOnly=true` and online. Preparation uses an official bootstrap SDK, previously source-built artifacts and explicit official native-package substitutions; reference packages and other external inputs also remain. No zero-prebuilt construction claim follows from that profile label. Runtime source-build sets `NoPgoOptimize=true`, so Release configuration does not establish identical optimization inputs or performance compared with Microsoft's SDK.

## Independent environment and preparation status

The active WSL distribution is **`cbodotnet-net7-arm64`**, imported to D-backed storage with Linux user `build`, UID:GID `1000:1000`, and native ARM64 execution. Its Ubuntu 22.04 ARM64 rootfs input is 324,314,721 bytes, SHA-256 `7d7cd98abef266eb4a0f999feb6951997b564241939ad3adb29b1159224d8a08`. Source, inputs and container home reside below `/home/build/cbodotnet/net7/`, separately from .NET 8/9/10 environments.

The new [Initialize-Net7Wsl.ps1](../scripts/Initialize-Net7Wsl.ps1) and [initialize-net7-host.sh](../scripts/initialize-net7-host.sh) make this pinned fresh-environment setup reusable. They refuse existing names/installation targets and preserve installation logs. They were added after the current environment was created and received static checks; no second import or overwrite was attempted to validate them against the active distribution.

The independent installer checkout is `work/installer-v7.0.120`; the generated source tree is `work/source-v7.0.120`. Container mounts are `/installer` and the source parent `/work`, yielding generated root `/work/source-v7.0.120`. Generated component Git folders and `git-info/*.props` agree with the pinned revisions. The generated root itself need not be a Git repository.

[arm64-net7.Containerfile](../containers/arm64-net7.Containerfile) uses official base digest `sha256:7ef8f6ee1b9982511349757443eb4844f0db4f8cef1aff6148a7ba1c25d7c6f4`, selects LLVM 16 explicitly and includes current/historical Ubuntu archive keys. The actual derived image ID is **`f5d51031836414245009084e7bb78edc8daf305af750f5e75a5af885b95828d8`**, recorded in `reports/derived-image.json`. The Bash harness supplies `CppCompilerAndLinker=/usr/bin/clang-16` and absolute clang/clang++ compiler paths, matching the updated profile.

The independent signed Xenial sysroot completed at `2026-10-30T11:59:13.532556Z`. Its unchanged runtime generator has SHA-256 `515ca92a06354898bfff4edf524292595eb75bef3668325d381b4c4bcdc1d979`. `reports/sysroot/sysroot-provenance.json` records `packageSignatureVerification=true`, `emulation=false`, source identities and keyring hashes; file, symlink and package inventories are preserved alongside it. No prior release's sysroot result is reused as .NET 7 evidence.

The unprivileged container policy is copied from the host default with one additional `fchmodat2` allow rule. Its SHA-256 is `433ff4d41a88c0c37acf4372cfd84b13399c3a831037ee269141508d1538f990`, derived from base policy `27e6dbb7d478e222144af8ac0dd4ea2423f1d01f8d8adde053f8831371106740`. The report records native syscall `452`, libseccomp `2.5.3`, preserved default action and all other rules, and `seccompUnconfined=false`. Host policy is unchanged; only the separate sysroot-creation invocation is privileged.

Final collection exposed intermittent failure in the host's external library-discovery probe; a subsequent `ldconfig -p` exited with signal 11. The helper now falls back to the installed `libseccomp.so.2` SONAME and retains all native API and exact-policy checks. A forced-discovery-failure check passed with the same policy hash; `reports/collection-attempts/` preserves the observation and recovery.

## Source generation completed

The initial generation attempt, `generate-20261030T114255355972904Z`, failed because the generation destination itself was mounted directly. Upstream removes and recreates that destination, which cannot succeed for a bind-mount root. Its failed log/status remains preserved. The harness now mounts the parent `/work` and passes `/work/source-v7.0.120` as the external destination.

Attempt **`generate-20261030T114531125967663Z`** completed with exit code **0**, starting at `2026-10-30T11:45:31Z` and finishing at `2026-10-30T11:49:57.780989Z`. The retained GNU time report records **4 minutes 26.56 seconds** for source generation, not SDK compilation. It used the pinned installer commit, `PreserveTarballGitFolders=true`, `ConvertInternalRepos=true`, Release configuration and two selected CPUs.

The generated source archive is `/installer/artifacts/packages/Release/Shipping/dotnet-sdk-source-7.0.120.tar.gz`, **1,113,766,136 bytes**, SHA-256 **`ee70257d468cac9d972006c29d775eb25606ccae48bd735126c55385c793c346`**. This is source input, not a runnable SDK distribution.

[source7-provenance.py](../scripts/source7-provenance.py) recorded the archive, `git-info` fingerprints and **25 component revisions** in `reports/generation/generation.json` at `2026-10-30T11:53:14.702435Z`. Verification passed against the separate generator checkout and generated components. This snapshot establishes generated input provenance; later build injections and the recorded compatibility patches still form part of the effective worktree.

## Bootstrap preparation completed

Generated preparation requires `./prep.sh --bootstrap` explicitly. Default `prep.sh` downloads inputs and installs SDK `7.0.118` but does not transform the original PSB. Because the explicit bootstrap block can process an existing original, [prepare-source7.sh](../scripts/prepare-source7.sh) first prepares, uses [bootstrap7-inputs.py](../scripts/bootstrap7-inputs.py) to preserve originals, then bootstraps and fingerprints the result. The tagged project replaces packages for three portable RIDs, including thirteen ARM64 downloads. [Preparation script](https://github.com/dotnet/installer/blob/v7.0.120/src/SourceBuild/tarball/content/prep.sh), [bootstrap package declarations](https://github.com/dotnet/installer/blob/v7.0.120/src/SourceBuild/tarball/content/eng/bootstrap/buildBootstrapPreviouslySB.csproj).

[Invoke-Net7Build.ps1](../scripts/Invoke-Net7Build.ps1) exposes `Generate`, `Prepare`, `Build`, `Test` and `Collect`. The bootstrap marker completed at `2026-10-30T12:06:54.415568Z`. Action `prepare-20261030T1209125549121Z` then verified the existing prepared inputs with exit code 0, from `12:09:14Z` to `12:09:18.284201Z`. That short action duration is verification, not the initial sysroot/bootstrap construction time.

| Bootstrap input | Bytes | SHA-256 |
| --- | --- | --- |
| Original `Private.SourceBuilt.Artifacts.7.0.118.centos.8-x64.tar.gz` | 1,019,244,017 | `0a4e8447c72047bf7d73d0766abba315d64976fdc8aef7236ddee0bbb62dfa5d` |
| Transformed `Private.SourceBuilt.Artifacts.Bootstrap.tar.gz` | 1,297,468,798 | `df96f78f3bb560e7c7885e94562538c49811dd412e066f6f44647486a15167b6` |

The preserved inventory contains thirteen ARM64 package entries: core runtime, ASP.NET runtime, host and crossgen2 `7.0.18`, plus earlier explicitly overridden IL/tool packages. These are bootstrap inputs, separate from the intended final runtime `7.0.20`. Reports fingerprint versioned SDK inputs and archives; upstream tool initialization may install another pinned runtime and replace unversioned host files, so those host observations are recorded separately.

## Prepared compatibility changes

Four fixed patches are applied against exact official source bytes. The initial three were applied before the first product build. The second build's schema-version-2 report records those three as already applied and the fourth metadata patch as newly applied, with all target hashes verified. The first invocation's original three-patch report remains intact.

| Target | Purpose | Patch SHA-256 |
| --- | --- | --- |
| `src/runtime/eng/native/configureplatform.cmake` | Recognize ARM64 Linux cross-component hosts | `cf868ca40e38523ad9f00d8e3c3342cd850066da2b526336a5748c1ffa99a4c9` |
| `repos/runtime.proj` | Honor explicit runtime portability | `1b310cabca1b64c13e265a9a434f7e83bb435786f1fc683d346fe18f03b311d2` |
| `repos/aspnetcore.proj` | Honor explicit ASP.NET portability | `43f6269e6e18728402ebbcb1d5db88c2fffc4739509e26d7a6cec8440ef36f47` |
| Externals' IdentityModel producer patch | Use pinned source time for valid assembly metadata | `8ff2c066cf5a8e0b63123b9c9135779fc7323e84acbc734b447ac2a55276690f` |

The host branch is an exact two-line case present in the pinned .NET 9 source. It preserves required cross-component tools rather than skipping their consumers. [Upstream host case](https://github.com/dotnet/dotnet/blob/v9.0.123/src/runtime/eng/native/configureplatform.cmake#L30).

The runtime adapter correction is necessary because .NET 7's `SourceBuildNonPortable=true` actually forces `SourceBuildPortable=false` and forwards `--portablebuild false`. This differs from the narrower RID-default behavior seen in the later .NET 8 build. The ASP.NET correction avoids adding an already portable target RID again to its implicit runtime/crossgen2 dependencies. Both adapter changes honor explicit `PortableBuild=true` while preserving empty/false defaults; ReadyToRun and the local tool graph remain enabled. [Runtime semantics](https://github.com/dotnet/runtime/blob/0fb6ac59fb1edbe4ed3ad62661df0eb7eacd7903/eng/SourceBuild.props#L11), [ASP.NET dependency lists](https://github.com/dotnet/aspnetcore/blob/d9ba962869d1b1c410ea476b02de2f8e27eec762/eng/Dependencies.props#L109).

[apply-net7-patches.py](../scripts/apply-net7-patches.py) verifies the separate installer checkout, four generated component Git revisions and metadata files, the pinned externals commit epoch, fixed target hashes and patch hashes/scopes before mutation. It supports idempotent `apply`, strict `verify`, and new external JSON reports. It preserves unrelated changes and refuses unknown target content. A prepared patch set is not proof that an actual build succeeded.

The actual original file SHA-256 values matched the staged constants: runtime host configuration `30922041dcfcfd30145c30154176e46d7cb8a043a1af540768c087ee8e984c62`, runtime adapter `27a4eeb93c0b179b08971dcfe59b7242efc006b242248f9f34f73f22df777d38`, and ASP.NET adapter `aa4507e8a1b142dc7b465d29f5d6f993b8ffef86330d9926a82581d8e3dcbb40`.

## First product build: external metadata overflow

Attempt **`build-20261030T1211140323225Z`** ran from `2026-10-30T12:11:20Z` to `2026-10-30T12:19:15.466827Z` and finished with exit code **1**. GNU time recorded **7 minutes 55.19 seconds**. Its patch report confirms successful application of the initial three compatibility fixes. Completed dependencies remain reusable; this invocation does not establish a finished SDK or native-runtime build.

The failure occurred in source-build-externals' `azure-activedirectory-identitymodel-extensions-for-dotnet` recipe. Its injected `updateAssemblyInfo.sh` uses the current year minus 2019 followed by `MMDD` as the assembly file-version revision. On 2026-10-30 it generated `AssemblyFileVersion("6.35.0.71030")`, exceeding the UInt16 revision range and producing `CS7035` in `Microsoft.IdentityModel.Abstractions/Properties/AssemblyInfo.cs:9`. The same generated file retained `AssemblyVersion("6.35.0")`; the recipe explicitly sets NuGet `Version=6.35.0`.

[Patch 0004](../patches/net7/0004-use-pinned-identitymodel-metadata-date.patch) replaces exactly one injected date line in the pinned externals producer patch. It uses the UTC commit timestamp of source-build-externals `522d361e1cd703f1e8e526f5306e4ed18de1da41`: epoch **`1713290279`**, `2024-04-16T17:57:59Z`. The regenerated producer logged file version **`6.35.0.50416`** and informational version `6.35.0.50416175759`, preserving binding AssemblyVersion and explicit NuGet version **`6.35.0`**. It does not suppress the compiler check or hand-edit generated assembly attributes. [Pinned producer](https://github.com/dotnet/source-build-externals/blob/522d361e1cd703f1e8e526f5306e4ed18de1da41/patches/azure-activedirectory-identitymodel-extensions-for-dotnet/0002-Port-updateAssemblyInfo.ps1-to-bash-version.patch#L24).

The producer target's original SHA-256 is `60d0fbc924edbaa5fbef6802caf48fa2e38327cfdb08f1bda5efae0f4cd3518b`; verified patched SHA-256 is `9ef15f847dea2aed5033d7168e3268070dfb69e2809ab4ef2c30ef30ddcfab25`. Project-fixture application and actual-tree checks passed, including the component/metadata/epoch guard. The failed externals inner state was preserved and quarantined before regeneration, while other completed components remained cached.

## Second product build: external fix passed, execution interrupted

Attempt **`build-20261030T1228453809137Z`** applied the fourth patch and successfully completed source-build-externals. Its retained log confirms the corrected metadata values above, and the root log records that component's completed build and cleanup before advancing to runtime.

The attempt has **no `build-status.json` and no completed resource report**. Its last runtime log update, `2026-10-30T12:40:36Z`, stopped during native-library compilation at 84%. When inspected at `2026-10-30T14:51:16.8853254Z`, the original execution session was absent, the dedicated WSL distribution had recently restarted, no compiler/dotnet process remained, and the auto-remove Podman container was configured with PID 0. The exact reason for the restart is not established. These observations establish an interruption, not an upstream compiler failure or successful build result.

`reports/runs/build-20261030T1228453809137Z/interruption.json` records `exitCode=null` and the observed evidence. Component logs were preserved in that attempt's `component-logs.tar.gz`. No synthetic upstream status or complete build duration was assigned to the interrupted action.

The public `Invoke-Net7Build.ps1 -Mode Build` entry point started a new attempt, **`build-20261030T1452052076170Z`**, against the retained workspace, revalidating the generated inputs and four-patch state before incremental compilation.

## Third product build completed

The third attempt completed with exit code **0**, from `2026-10-30T14:52:11Z` to `2026-10-30T15:15:21.250616Z`. GNU time recorded **23 minutes 9.81 seconds**. This is a cached resumption after the earlier attempts, not a cold full-build duration. The runtime component completed in 9 minutes 20.59 seconds within that resumption; the remaining graph, including ASP.NET, SDK and installer, then completed.

Retained native configuration shows clang 16 invoking `--target=aarch64-linux-gnu --gcc-toolchain=/inputs/arm64-xenial/usr --sysroot=/inputs/arm64-xenial`. The target command/CMake evidence is under `reports/native-config/`; final ABI inspection is recorded separately below.

The generated binary SDK is `/work/source-v7.0.120/artifacts/arm64/Release/dotnet-sdk-7.0.120-linux-arm64.tar.gz`. Collection preserved its bytes as `artifacts/7.0.120-linux-arm64/cbodotnet-sdk-7.0.120-linux-arm64-build.1.tar.gz`, with checksum files and a provenance manifest. Its SHA-512 is `c4b94d7886411c774d0abebb8e075b4446effc8d86cf05c3a7407d09c3e1bdbe10cbbbfc17fa285ad4abeb735eb0d97448e6d77378f3a62b2d6ced880ad4cf16`.

| Archive | Bytes | SHA-256 |
| --- | --- | --- |
| SDK `7.0.120`, `linux-arm64` | 231,025,583 | `e1a84338e21cb061e0d12ef3331f00e18c0a38fd4f8f72dcf428ee548dd34249` |
| Core runtime `7.0.20`, `linux-arm64` | 63,505,946 | `7cb5484fc3c9e24b31f907615773859f40b49096dcc4729494ac77e292f17803` |
| ASP.NET internal runtime `7.0.20`, `linux-arm64` | 9,499,323 | `5bb644c1c54b0d6d7b8e8af463e9c5190f7bce7f6e69cc60d21ec2a0a8bd5eed` |

The final generated tree is not a pristine tagged checkout or a worktree with only four changed files. `reports/generated-worktree/summary.json` covers 25 component Git repositories and **513 modified tracked component files**, plus fingerprints of **31 selected generated-root/metadata files**. Those 31 are an inventory, not another changed-file count. Per-component diffs preserve upstream version/configuration injections alongside authored changes; the generated root itself is not a Git repository. The four-patch chain and this effective-state capture remain distinct evidence.

## Local shared-framework origins verified

`reports/construction/shared-framework-identity.json` matches all **184 core-runtime entries** and **138 ASP.NET entries** against the local archives, including regular-file bytes and link targets. The core archive under `Release/runtime/` matches its local blob-feed copy. The ASP.NET input is the retained local-feed `aspnetcore-runtime-internal-7.0.20-linux-arm64.tar.gz` product asset.

The installer adapter supplies a local blob-feed base URL, while this tag also includes external fallback candidates. The audit therefore inspected actual task execution rather than treating candidate parameters as proof. A bounded installer-binlog replay completed **71,729 events**, retaining **two successful `DownloadFile` tasks** with matching start, local `Copying`, and successful finish events. Neither selected task recorded a network attempt. The binary-log SHA-256 is `cfd7b49b5900323dc3906f0ba8bac2b6305d9494bda4265310114fd0be86b9e7`. [Tagged candidate construction](https://github.com/dotnet/installer/blob/v7.0.120/src/redist/targets/GenerateLayout.targets#L372).

Before cleanup, `reports/installer-download-observations.jsonl` captured stable full-file hashes at `2026-10-30T15:13:15Z` for both actual installer destinations below `src/installer/artifacts/source-build/self/src/artifacts/obj/redist/Release/downloads/`. Each destination matched the corresponding local-feed archive by size and SHA-256. The completed task source/destination paths match these historical receipts exactly. Later cleanup removed the destinations, so the report preserves the observations rather than inferring their bytes from missing files.

`reports/construction/origin-evidence.json` combines those task records and receipts with the archive comparisons, current local archive/feed hashes, pinned generator/component identities, the externals commit epoch, all four patches and component-log fingerprints. It passed for both included frameworks and binds the SDK SHA-256 above. The generic comparison report still says `originVerified=false` because byte comparison alone does not establish origin; the separate origin report supplies that additional evidence. No build targets or SDK files were changed during the audit.

## Native verification passed on three user spaces

The same collected SDK hash passed all six independent checks on native ARM64 Ubuntu 22.04, Ubuntu 24.04 and Debian 13: console DLL execution, apphost execution, RSA SHA-256 signing/verification, cryptographic random bytes, `fr-FR` ICU formatting and ASP.NET loopback HTTP. Restore used isolated caches with no package sources, plus private home/CLI/runtime directories.

| User space | Result | Host-reported RID |
| --- | --- | --- |
| Ubuntu 22.04 | Six checks passed | `ubuntu.22.04-arm64` |
| Ubuntu 24.04 | Six checks passed | `linux-arm64` |
| Debian 13 | Six checks passed | `linux-arm64` |

The archive target is `linux-arm64`; the Ubuntu 22.04 row records the actual host-reported RID rather than replacing it with the archive name. Each verifier report inspected **22 AArch64 ELF files**, with maximum requirements **GLIBC `2.17`, GLIBCXX `3.4.21`, CXXABI `1.3.7`**, passing the intended GLIBC ceiling `2.23`. Reports are under `reports/verify-ubuntu22/`, `verify-ubuntu24/` and `verify-debian13/`.

Debian verification ultimately used the existing Debian 13 image in the `Ubuntu-22.04` WSL Podman store, config identity `1383974698d236a954edfe90d4e701c8d6b30004775973b6cf79cb2182ed9548`. Two container launches in the new store failed with an unknown-image lookup before SDK execution. Between them, one explicit OCI load returned exit code 0, but the subsequent image lookup still failed; the cause is not established. Retained launch/import logs describe environment setup failures rather than failed SDK scenarios. The successful Debian run tested the same SDK hash as the Ubuntu runs.

These user spaces share the WSL kernel. ELF symbol maxima exclude archive members and managed PE images and do not establish every kernel or dynamically loaded dependency requirement. Results do not certify all Linux distributions, workloads, NativeAOT applications or external packages.

## Upstream smoke tests completed

Attempt **`test-20261030T1522486604890Z`** completed with exit code **0**, from `2026-10-30T15:22:55Z` to `2026-10-30T15:26:21.193929Z`. GNU time recorded **3 minutes 25.79 seconds**. The preserved summary records **42 total, 41 passed, zero failed and one skipped**, with 65 test-output files retained. `PoisonTests.VerifyUsage` was skipped because `SMOKE_TESTS_POISON_REPORT_PATH` was absent. Stage 2 and poisoning validation were not run.

All **12 OmniSharp scenarios passed** with external test fixture **OmniSharp `1.39.6`**, `omnisharp-linux-arm64-net6.0.tar.gz`, 41,382,979 bytes, SHA-256 `6e097febba7dc2a1422f1cb992e358a063412c05a08eb6719388561e3a75c734`. The helper verifies extracted members and adds only the test-output launcher symlink `run -> OmniSharp`, matching the unchanged suite's expected filename. No suite-code patch, OmniSharp exclusion or Mono installation was used. The fixture is a declared external test input, not an SDK component or an upstream-default fixture claim.

The xUnit runner reports bootstrap runtime **`7.0.18`**. The scenario children use the freshly built **SDK `7.0.120`**; bounded stdout in the retained summary records that distinction. The runner's runtime version is not the version of the SDK/runtime artifact under test.

The exact official SDK comparison baseline was separately verified against release metadata: 190,303,803 bytes, SHA-512 `f530f794afe3c3b9bd87b8ed509a1a13b1c8fe6f2bc6e6cce3e8cd6b56327c0ff27fc138122c2dad68770cc5015737e007ef5706599c189ef0cc7521cbf0b654`. Its acquisition record is `reports/test-inputs/official-sdk-baseline.json`.

This tag has one `SdkContentTests.CompareMsftToSb` comparison method. It passed in warning mode with an explicit **baseline-mismatch warning** and `SucceededWithIssues` output. The current normalized official-versus-community layout diff contains **49 added and 98 removed entries**; the historical expected baseline contains **102 added and 94 removed entries**. `reports/sdk-comparison/summary.json` and retained diffs record that mismatch. The passed method therefore establishes neither agreement with the expected layout baseline nor SDK archive byte equivalence.

## Prebuilt reporting and scope

The upstream aggregate and its inputs were preserved under `reports/prebuilt-usage/`; the current parsed aggregate reports **zero usage rows**. `coverage.json` records **2,212 assets JSON files in a nonempty ZIP**, **27 package-version snapshots**, and **25 embedded component reports with zero rows**. The declared default `tools-local/prebuilt-baseline.xml` is absent. Report parsing and baseline absence do not establish that no prebuilt inputs were consumed.

Previously source-built archives are classified as source-built by the report's design, and reference packages are excluded from its candidate set. This build explicitly used the official bootstrap SDK, transformed previous-build archives and official native-package substitutions. A zero-row aggregate therefore does not mean zero external binaries. The aggregate/report coverage assessment and optional poisoning/baseline checks must remain distinct from the verified local origins of the final two shared frameworks.

## Recorded results

| Evidence | Current result |
| --- | --- |
| WSL environment | Dedicated D-backed native ARM64 distribution active; user `build`, UID:GID `1000:1000` |
| Actual generator command and resolved component identities | Passed; successful second attempt and 25-component provenance snapshot recorded |
| Derived native build image | Recorded immutable image ID above |
| Independent signature-verified sysroot | Completed, signature verification and inventories recorded |
| Original/transformed bootstrap archive fingerprints | Recorded above; prepared-input verification passed |
| Four-patch chain | All four applied and verified; corrected externals metadata/build passed |
| Complete root build status and timings | Third attempt passed; 23:09.81 cached resumption |
| SDK archive identity, runtime versions and checksums | `7.0.120`, both frameworks `7.0.20`; recorded above |
| Local core-runtime and ASP.NET final-byte provenance | Passed: 184/138 entries, completed local-copy tasks and destination receipts |
| ELF architecture and required symbol versions | 22 AArch64 ELF files; `2.17` / `3.4.21` / `1.3.7` maxima |
| Native Linux functional scenarios | All six checks passed on all three tested user spaces |
| Upstream smoke counts | Passed: 41 passed, zero failed, one poisoning skip |
| SDK comparison scope | One warning-mode method passed with explicit baseline mismatch; current normalized diff 49 added / 98 removed |
| Actual upstream prebuilt report | Zero aggregate rows with coverage/inputs preserved; no zero-prebuilt claim |

Failed and interrupted attempts remain preserved alongside the successful build and tests. SDK archives, reports, caches and workspaces remain local and excluded from Git. No publication, Stage 2, poisoning pass or entirely prebuilt-free construction is claimed.
