# Preparing and building .NET SDK 7.0.120 on ARM64

Status snapshot: **2026-10-31, Asia/Seoul**. SDK `7.0.120` built successfully with both locally built `7.0.20` shared frameworks. The unchanged SDK passed six native checks on Ubuntu 22.04, Ubuntu 24.04 and Debian 13. The upstream smoke run completed with **41 passed, zero failed and one skipped**. Four fixed patches and the recorded recovery steps were required. See the [build report](build-report-7.0.120-arm64.md) for archive hashes, local-copy provenance and validation limits.

## Selected source and isolated environment

The [profile](../profiles/dotnet-7.0.120-linux-arm64.json) selects installer `v7.0.120`, commit `25b977658c06fd0217ec0bc0714398bb9d0a7bb0`. It is the selected final 1xx SDK, rather than the latest .NET 7 SDK across all feature bands (`7.0.410`). The corresponding runtime and ASP.NET version is `7.0.20`; the recorded release date is 2024-05-28. This project continues community builds independently of Microsoft's support lifecycle.

The measured output is `cbodotnet-sdk-7.0.120-linux-arm64-build.1.tar.gz`, **231,025,583 bytes**, SHA-256 **`e1a84338e21cb061e0d12ef3331f00e18c0a38fd4f8f72dcf428ee548dd34249`**. Its 184 core-runtime and 138 ASP.NET shared-framework entries match locally built archives, with separate completed installer-copy and destination-fingerprint evidence. This does not establish that every bootstrap/package input was rebuilt.

.NET 7 predates the VMR build path used here for .NET 8 and later. Its official installer repository generates a source-build tree from pinned component repositories. Use that legacy source-build path; do not label it a .NET 7 VMR checkout or substitute a .NET 8 regular-build command. [Official generation workflow](https://github.com/dotnet/installer/blob/v7.0.120/src/SourceBuild/README.md), [source templates](https://github.com/dotnet/installer/tree/v7.0.120/src/SourceBuild/tarball/content).

The workspace uses a dedicated D-backed WSL 2 import, `cbodotnet-net7-arm64`, with Linux user `build` and UID:GID `1000:1000`. Its Ubuntu 22.04 ARM64 rootfs input is 324,314,721 bytes, SHA-256 `7d7cd98abef266eb4a0f999feb6951997b564241939ad3adb29b1159224d8a08`. Preserve the import and environment reports separately from the existing .NET 8/9/10 distributions and inputs. Execution is native ARM64.

```text
/home/build/cbodotnet/net7/
  work/installer-v7.0.120/   # Pinned installer generator checkout
  work/source-v7.0.120/      # Independently generated source-build tree
  inputs/                   # Target sysroot, originals and comparison baseline
  container-home/           # Build user's home and caches
```

The container mounts the installer checkout at `/installer`, the entire source parent at `/work`, the dedicated inputs at `/inputs`, and the project at `/project`. The generated tree is therefore **`/work/source-v7.0.120`**. Mounting its parent is essential: the upstream generator removes and recreates its destination, so the destination itself must not be a bind mount. Reports belong under `artifacts/7.0.120-linux-arm64/reports/` in the project.

[arm64-net7.Containerfile](../containers/arm64-net7.Containerfile) derives from the pinned official Ubuntu 24.04 ARM64 base and explicitly selects LLVM/clang/LLD 16. The older runtime's automatic compiler list recognizes LLVM 16; its documented minimum CMake is 3.14.5. Host headers are separate from the independently generated ARM64 Xenial target sysroot. The observed derived image ID is `f5d51031836414245009084e7bb78edc8daf305af750f5e75a5af885b95828d8`; retain the inspected image/package records for each run. [Runtime requirements](https://github.com/dotnet/runtime/blob/0fb6ac59fb1edbe4ed3ad62661df0eb7eacd7903/docs/workflow/requirements/linux-requirements.md), [compiler discovery](https://github.com/dotnet/runtime/blob/0fb6ac59fb1edbe4ed3ad62661df0eb7eacd7903/eng/common/native/init-compiler.sh#L74).

## Windows entry point

For a new machine or another fresh dedicated distribution, [Initialize-Net7Wsl.ps1](../scripts/Initialize-Net7Wsl.ps1) downloads and verifies the pinned ARM64 rootfs, imports WSL 2 into the project's ignored `.build/wsl/net7/distro` storage, and invokes [initialize-net7-host.sh](../scripts/initialize-net7-host.sh) to create the `build` account and install host packages:

```powershell
./scripts/Initialize-Net7Wsl.ps1
```

This initializer is fresh-only: existing distribution names and installation paths are refused. It does not stop, move, unregister or overwrite an existing distribution. Its installation reports use `artifacts/reports/wsl-installation/<attempt>/`. The currently active environment was established before this reusable initializer was added; the script has static checks, rather than a second import run against that existing environment. The build wrapper passes `--user build` explicitly and does not require restarting WSL to activate the configured default account.

[Invoke-Net7Build.ps1](../scripts/Invoke-Net7Build.ps1) exposes five explicit modes:

```powershell
Set-Location D:\Projects\cbodotnet
Get-Help ./scripts/Invoke-Net7Build.ps1 -Full
./scripts/Invoke-Net7Build.ps1 -Mode Generate
./scripts/Invoke-Net7Build.ps1 -Mode Prepare
./scripts/Invoke-Net7Build.ps1 -Mode Build
./scripts/Invoke-Net7Build.ps1 -Mode Test
./scripts/Invoke-Net7Build.ps1 -Mode Collect
```

Run each later mode after inspecting the preceding action's actual result. `Generate` prepares the pinned checkout/image and creates or verifies the external generated tree. `Prepare` creates or verifies the independent signed sysroot and performs the two-step bootstrap preparation. `Build` applies the fixed patches after provenance checks and builds the SDK; `Test` invokes the tagged smoke tests; `Collect` preserves the produced SDK bytes and records provenance. Generation and preparation completed; product-build failures, interruptions and resumed attempts are recorded separately.

Defaults are `-Distribution cbodotnet-net7-arm64`, `-LinuxUser build`, and workspace `<Linux HOME>/cbodotnet/net7`. For another dedicated environment, supply the same existing distribution, user and absolute `-LinuxWorkspaceRoot` consistently. Ordinary containers run as the unprivileged user with the recorded default-derived seccomp policy plus one `fchmodat2` allow rule; only sysroot creation uses the dedicated privileged root container. Host policy and other seccomp rules remain unchanged. The policy and image reports are retained per action.

The policy helper falls back to the installed `libseccomp.so.2` SONAME when the external library-discovery probe fails. Final collection encountered an intermittent WSL `ldconfig` failure; a forced-fallback check verified the same native architecture, syscall number, library version and policy hash. Evidence is retained under `reports/collection-attempts/`.

## Generate the source-build tree

Verify the installer checkout's exact Git commit. Choose a new generation destination outside that checkout and preserve any failed destination before retrying. The official command shape, inside the prepared container, is:

```bash
cd /installer
./build.sh /p:Configuration=Release /p:ArcadeBuildTarball=true \
  /p:TarballDir=/work/source-v7.0.120 \
  /p:PreserveTarballGitFolders=true /p:ConvertInternalRepos=true
```

The generator resolves the tagged dependency metadata and applies the tag's existing source-build patches. `ConvertInternalRepos=true` converts declared internal repository locations to their public counterparts. Record every resolved component revision and the generator command. Preserve the generated component Git folders and `git-info/*.props`; the generated root itself need not have a Git repository. [Dependency declarations](https://github.com/dotnet/installer/blob/v7.0.120/eng/Version.Details.xml).

Verified component revisions include runtime `0fb6ac59fb1edbe4ed3ad62661df0eb7eacd7903`, ASP.NET `d9ba962869d1b1c410ea476b02de2f8e27eec762`, and SDK `a06803c09702777c6550fede13c8bdc52d780191`. [source7-provenance.py](../scripts/source7-provenance.py) records/verifies the source archive, generated Git metadata and 25 component revisions through `reports/generation/generation.json`. The recorded successful generation is `generate-20261030T114531125967663Z`, completed at `2026-10-30T11:49:57.780989Z`; the earlier direct destination-mount failure remains preserved.

## Prepare the target sysroot and bootstrap

[prepare-sysroot7.sh](../scripts/prepare-sysroot7.sh) uses the runtime producer's unchanged `eng/common/cross/build-rootfs.sh arm64 xenial` generator. Run it only in the dedicated native ARM64 root preparation container, with source and project read-only and separate writable input/report mounts. It refuses an existing sysroot target because upstream recreates that target recursively. The current and historical Ubuntu archive keyrings are combined while signature verification remains enabled. Preserve generator, keyring, package, file, and symlink inventories; do not reuse another release's prepared sysroot as evidence for this run.

Generated .NET 7 preparation differs from .NET 8: **bootstrap transformation is opt-in**. The `Prepare` mode uses [prepare-source7.sh](../scripts/prepare-source7.sh) and [bootstrap7-inputs.py](../scripts/bootstrap7-inputs.py) for preservation, transformation and fingerprint checks. Its original upstream first step runs in the generated root:

```bash
cd /work/source-v7.0.120
./prep.sh
```

This installs native SDK `7.0.118` and downloads the generated `packages/archive/archiveArtifacts.txt` inputs. The expected original artifacts archive is `Private.SourceBuilt.Artifacts.7.0.118.centos.8-x64.tar.gz`. Preserve an independently byte-checked original outside the `packages/archive/Private.SourceBuilt.Artifacts*` discovery glob, along with its package-version XML and hashes. Then run:

```bash
./prep.sh --bootstrap
```

In this tag, `--bootstrap` still performs transformation when the original archive already exists. The transformed `Private.SourceBuilt.Artifacts.Bootstrap.tar.gz` replaces portable/native packages with official package-feed inputs for `linux-x64`, `linux-musl-x64`, and `linux-arm64`. Thirteen ARM64 package downloads are declared. Record both original and transformed hashes and the actual resulting package versions. The override file pins some earlier tool-package versions; those are bootstrap inputs, separate from the final `7.0.20` runtime. [Preparation](https://github.com/dotnet/installer/blob/v7.0.120/src/SourceBuild/tarball/content/prep.sh), [bootstrap project](https://github.com/dotnet/installer/blob/v7.0.120/src/SourceBuild/tarball/content/eng/bootstrap/buildBootstrapPreviouslySB.csproj), [version overrides](https://github.com/dotnet/installer/blob/v7.0.120/src/SourceBuild/tarball/content/eng/bootstrap/OverrideBootstrapVersions.props).

The signed sysroot completed at `2026-10-30T11:59:13.532556Z`; the bootstrap marker completed at `2026-10-30T12:06:54.415568Z`. `prepare-20261030T1209125549121Z` subsequently verified the prepared inputs with exit code 0. That short validation action is not the duration of initial sysroot/bootstrap construction. Its report preserves original and transformed archive fingerprints and thirteen ARM64 entries, including runtime/host/crossgen2 `7.0.18` and explicitly overridden earlier tools.

The profile's `sourceOnly=true` identifies this legacy source-build path. It does not establish that every dependency was rebuilt. The upstream SDK, previously source-built artifacts, official bootstrap substitutions, reference packages, host toolchain and online inputs must remain disclosed.

## Apply the four fixed source-build patches

[apply-net7-patches.py](../scripts/apply-net7-patches.py) accepts the separate installer and generated source roots:

```bash
python3 /project/scripts/apply-net7-patches.py apply \
  --installer-dir /installer --source-dir /work/source-v7.0.120 \
  --reports-dir /project/artifacts/7.0.120-linux-arm64/reports/patches/first-apply
```

The helper verifies the installer revision; generated installer/runtime/ASP.NET/externals Git revisions and `git-info` entries; the pinned externals commit timestamp; and all four target/patch hashes and fixed scopes before its first change. Unknown content is rejected. Repeating `apply` on exact patched content changes nothing; `verify` requires all four patched hashes. Unrelated changes are preserved. Optional `net7-patches-apply.json` or `net7-patches-verify.json` reports must be new and outside both source roots. New reports use schema version 2; the first build's original three-patch report remains intact. The second build applied the fourth producer patch and successfully rebuilt that external component.

The patches are deliberately distinct:

- The runtime [host-detection backport](../patches/net7/0001-support-arm64-cross-components-host.patch) adds the Linux `aarch64` cross-component host case already present in the pinned .NET 9 source. It retains required host tools and their consumers.
- The [runtime adapter correction](../patches/net7/0002-preserve-portable-runtime-target.patch) honors explicit `PortableBuild=true`. In .NET 7, `SourceBuildNonPortable=true` actually sets `SourceBuildPortable=false` and forwards `--portablebuild false`; it is not merely a default RID flag. Empty/false outer settings retain the original behavior. [Runtime source-build arguments](https://github.com/dotnet/runtime/blob/0fb6ac59fb1edbe4ed3ad62661df0eb7eacd7903/eng/SourceBuild.props#L11).
- The [ASP.NET adapter correction](../patches/net7/0003-preserve-portable-aspnetcore-target.patch) honors explicit portability and prevents appending `linux-arm64` twice to implicit runtime/crossgen2 dependency lists. It retains the local tool graph and ReadyToRun compilation. [Dependency lists](https://github.com/dotnet/aspnetcore/blob/d9ba962869d1b1c410ea476b02de2f8e27eec762/eng/Dependencies.props#L109).
- The [IdentityModel metadata correction](../patches/net7/0004-use-pinned-identitymodel-metadata-date.patch) changes one injected producer line to use the UTC timestamp of pinned source-build-externals commit `522d361e1cd703f1e8e526f5306e4ed18de1da41`, epoch `1713290279`. Its existing wall-clock calculation produced invalid file revision `71030` in 2026. The source-derived date yields `AssemblyFileVersion 6.35.0.50416` and informational version `6.35.0.50416175759`. Binding `AssemblyVersion 6.35.0` and the recipe's explicit NuGet version `6.35.0` remain unchanged. Generated `AssemblyInfo.cs` is regenerated through its producer rather than edited by hand.

Before retrying the first failed build, preserve its logs and quarantine only the failed externals component's `artifacts/source-build/` state. Its patch-application checkpoint otherwise skips or attempts to reapply the already-injected script. Regenerate that failed inner component through the updated producer while retaining other completed components. Do not disable the compiler's version checks or change the final SDK archive to bypass this failure.

That recovery succeeded for source-build-externals in `build-20261030T1228453809137Z`: its producer logged file version `6.35.0.50416` and the component completed. The same attempt later stopped during runtime native-library compilation. Its original process/session was absent after a WSL restart; no upstream `build-status.json` or completed timing report exists. Preserve `interruption.json` and component logs, record the exit result as unknown, and use the public `-Mode Build` command to create a new attempt against the retained inputs. Do not label that interruption as a compiler failure or invent an overall duration.

Resumed attempt `build-20261030T1452052076170Z` completed with exit code 0, from `2026-10-30T14:52:11Z` to `2026-10-30T15:15:21.250616Z`. Its 23-minute 9.81-second duration measures cached resumption; it is not a cold full-build measurement. The original failed and interrupted attempts remain preserved.

## Build and inspect actual outputs

The intended generated-root command is:

```bash
cd /work/source-v7.0.120
export ROOTFS_DIR=/inputs/arm64-xenial
export CC=/usr/bin/clang-16 CXX=/usr/bin/clang++-16
export CLR_CC=/usr/bin/clang-16 CLR_CXX=/usr/bin/clang++-16
export CppCompilerAndLinker=/usr/bin/clang-16
export PortableBuild=true CrossBuild=true DOTNET_PROCESSOR_COUNT=2
export BUILD_SOURCEVERSION=25b977658c06fd0217ec0bc0714398bb9d0a7bb0
taskset --cpu-list 0,1 ./build.sh --clean-while-building --online -- \
  /p:Configuration=Release /p:Platform=arm64 /p:TargetOS=Linux \
  /p:TargetRid=linux-arm64 /p:PortableBuild=true /p:CrossBuild=true /m:2
```

Use the actual permitted CPU list rather than assuming CPUs `0,1`. The generated entry point requires the literal `--` before additional MSBuild properties. Exported properties retain cross/sysroot intent in nested processes, but actual native command lines and CMake settings must confirm the sysroot and portable SSL policy. Source-build runtime arguments set `NoPgoOptimize=true`; Release configuration does not promise Microsoft's optimization inputs, performance or bytes.

Expected SDK output is under `/work/source-v7.0.120/artifacts/arm64/Release/`. The generated **source archive** is a separate product: the recorded `dotnet-sdk-source-7.0.120.tar.gz` is 1,113,766,136 bytes, SHA-256 `ee70257d468cac9d972006c29d775eb25606ccae48bd735126c55385c793c346`, under `/installer/artifacts/packages/Release/Shipping/`. It is not a completed SDK binary archive.

A generated archive alone does not establish root completion. Preserve failed and successful root status, logs, timings, source differences, generated configuration, image identity, input fingerprints and component metadata in separate UTC-stamped action reports. Legacy source-build changes component configuration in place; distinguish those upstream injections from the four authored patches instead of assuming a pristine worktree. This run's final capture covers 25 component repositories and 513 modified tracked component files, plus 31 selected generated-root/metadata files, under `reports/generated-worktree/`. The latter is an inventory, not a second changed-file count.

Before collection, verify SDK `7.0.120`, archive target `linux-arm64`, actual included runtime versions, archive sizes/checksums, and local shared-framework origins. Compare SDK core/ASP.NET entries against locally produced runtime archives and inspect recorded installer input resolution; filenames alone are insufficient. The recorded SDK contains both frameworks `7.0.20`. Its 22 inspected ELF files are AArch64, with maximum requirements GLIBC `2.17`, GLIBCXX `3.4.21` and CXXABI `1.3.7`, passing the intended GLIBC ceiling `2.23`.

This installer supplies both local and external fallback download candidates, so candidate URI parameters alone do not establish which archive was consumed. Preserve the installer binlog, inspect actual resolution/destination hashes, and combine that evidence with final shared-framework byte comparisons. The ASP.NET archive name used by this layout is `aspnetcore-runtime-internal-7.0.20-linux-arm64.tar.gz`; use the actual locally generated archive rather than assuming the public-baseline filename. [Tagged fallback construction](https://github.com/dotnet/installer/blob/v7.0.120/src/redist/targets/GenerateLayout.targets#L372).

For this SDK, the bounded replay completed 71,729 events and proved two successful local `Copying` tasks without network attempts. The destination watcher captured stable full-file hashes matching the local feed before cleanup removed those files. `reports/construction/origin-evidence.json` combines those exact path/hash receipts, task start/finish evidence, local archive hashes, final 184/138 shared-entry comparisons and pinned source/four-patch identities. Repeat that combined evidence for a new SDK; a missing destination after cleanup cannot supply proof by itself.

Run independent `net7.0` console DLL/apphost, cryptography, ICU and ASP.NET HTTP checks on native ARM64 Linux user spaces. All six checks passed on Ubuntu 22.04, Ubuntu 24.04 and Debian 13 against the same archive hash. Ubuntu 22.04 reports host RID `ubuntu.22.04-arm64`; the other two runs report `linux-arm64`. Record the observed host RID separately from the portable archive target. When invoking the independent verifier, supply the actual expected host RID:

```bash
bash /project/scripts/verify-sdk.sh \
  --archive /project/artifacts/7.0.120-linux-arm64/cbodotnet-sdk-7.0.120-linux-arm64-build.1.tar.gz \
  --output-dir /project/artifacts/7.0.120-linux-arm64/reports/verify-new-ubuntu22 \
  --expected-version 7.0.120 --expected-rid ubuntu.22.04-arm64 \
  --framework net7.0 --max-glibc 2.23
```

Use a new report directory for another invocation. The Debian run used the existing Debian 13 image in the `Ubuntu-22.04` WSL Podman store after two new-store container launches failed image lookup. An explicit OCI load between those launches returned exit code 0 without resolving the lookup; its cause is not established. These pre-execution failures remain recorded separately from the successful SDK checks. The user spaces share the WSL kernel, and symbol maxima do not certify all kernel/dynamic-library requirements or untested distributions/workloads.

Run this tag's `--run-smoke-test` entry point separately, using a verified exact official SDK archive only as a comparison input. Record actual passes, failures, skips and content differences. Its comparison environment supports `SMOKE_TESTS_MSFT_SDK_TARBALL_PATH` and `SMOKE_TESTS_WARN_SDK_CONTENT_DIFFS`; do not infer .NET 8-only test coverage or strict-CI behavior from their names. [Tagged smoke configuration](https://github.com/dotnet/installer/blob/v7.0.120/src/SourceBuild/tarball/content/test/Microsoft.DotNet.SourceBuild.SmokeTests/Config.cs).

Acquire the exact official comparison baseline inside the prepared container with `/project` and `/inputs` mounted:

```bash
python3 /project/scripts/fetch-test-sdk.py \
  --profile /project/profiles/dotnet-7.0.120-linux-arm64.json \
  --inputs-dir /inputs \
  --reports-dir /project/artifacts/7.0.120-linux-arm64/reports/test-inputs-reproduction
```

Choose a new report directory for each acquisition; the recorded run's existing `reports/test-inputs/official-sdk-baseline.json` must remain preserved. The helper checks the archive against official release-metadata SHA-512 and writes a separate comparison-input receipt.

The wrapper's `Test` mode defaults to `/inputs/official-sdk/dotnet-sdk-7.0.120-linux-arm64.tar.gz` for `-OfficialSdkArchivePath`. An empty parameter omits that comparison input, so optional SDK-content tests skip rather than download a baseline. `Collect` uses the separate installer root, generated source root, generation report and inspected immutable image identity. Recollect after final reports are closed so the manifest inventories the complete evidence set.

The harness uses [prepare-net7-test-tools.py](../scripts/prepare-net7-test-tools.py) to provide pinned OmniSharp `1.39.6` ARM64 `net6.0` test assets, verify extracted members, and add the launcher symlink `run -> OmniSharp` expected by the unchanged suite. No suite-code exclusion, OmniSharp skip or Mono installation is used. The xUnit runner uses bootstrap runtime `7.0.18`; scenario children use the freshly built SDK `7.0.120` through the recorded isolated smoke SDK directory.

Test attempt `test-20261030T1522486604890Z` completed with exit code 0 in 3 minutes 25.79 seconds: **42 total, 41 passed, zero failed and one skipped**. All 12 OmniSharp cases passed. Poisoning was skipped because `SMOKE_TESTS_POISON_REPORT_PATH` was absent; Stage 2 was not run.

The single `SdkContentTests.CompareMsftToSb` method passed in warning mode with an explicit baseline-mismatch warning and `SucceededWithIssues`. Its current normalized layout diff has **49 added and 98 removed entries**, versus **102 added and 94 removed** in the historical expected baseline. Keep `reports/sdk-comparison/summary.json` and its diffs; this passed method does not establish baseline agreement or complete SDK equivalence.

Retain the prebuilt aggregate, assets ZIP, package-version snapshots and component reports. `reports/prebuilt-usage/coverage.json` records 2,212 assets JSON files, 27 snapshots and 25 embedded component reports. The aggregate has zero usage rows, but previously source-built inputs are classified as source-built and reference packages are excluded by design. The default baseline is absent. Zero reported rows do not mean zero external binaries or prove a poisoning/baseline-validation pass.

SDK construction and the stated native/upstream checks completed within these scopes. Generated workspaces, inputs, reports and binary archives remain local and excluded from Git. No publication, Stage 2, poisoning pass or entirely prebuilt-free construction is claimed.
