# Preparing and building .NET SDK 8.0.133 on ARM64

Status snapshot: **2026-10-30, Asia/Seoul**. The full root build completed for SDK `8.0.133` with both locally built `8.0.33` shared frameworks. The unchanged archive passed functional and ABI checks on native ARM64 Ubuntu 22.04, Ubuntu 24.04, and Debian 13. Final upstream smoke tests completed with **44 passed, zero failed, and two skipped**. The two compatibility patches below are required, together with the documented container, retry-state, and producer-metadata corrections. See the [build report](build-report-8.0.133-arm64.md) for measured results and limitations.

## 1. Selected version and build scope

| Item | Selected value |
| --- | --- |
| SDK / VMR tag | `8.0.133` / `v8.0.133` |
| VMR commit | `7d1bf90885cff22e7da72b27e9848e42fd3cb1ae` |
| Selection date | 2026-10-30 |
| Latest published .NET 8 SDK recorded during selection | `8.0.427`, released 2026-10-25 |
| Selected shared runtime version | `8.0.33` |
| Bootstrap SDK | `8.0.131` |
| Previously source-built artifacts input | `8.0.131-servicing.26422.1`, initially `centos.9-x64` |
| Host / intended target | Native Linux ARM64 / `linux-arm64` |
| Build system | Legacy VMR source-build orchestration |
| Compiler / target sysroot | Native clang 18 / ARM64 Ubuntu 16.04 Xenial |
| Intended maximum required GLIBC symbol version | `2.23`, subject to inspecting the actual archive |
| Parallelism | Two selected CPUs through `taskset`, `DOTNET_PROCESSOR_COUNT=2`, and MSBuild `/m:2` |
| Derived image tag | `localhost/cbodotnet-arm64:8.0.133` |

The [profile](../profiles/dotnet-8.0.133-linux-arm64.json) pins the source and declares the intended build configuration. `8.0.133` is the latest published 1xx SDK selected with a matching VMR tag; it is not the newest SDK across all .NET 8 feature bands. The SDK selection and the shared runtime version are separate inputs. [Official release metadata](https://builds.dotnet.microsoft.com/dotnet/release-metadata/8.0/releases.json), [selected VMR source](https://github.com/dotnet/dotnet/tree/v8.0.133), [bootstrap configuration](https://github.com/dotnet/dotnet/blob/v8.0.133/global.json).

.NET 8 uses `prep.sh` followed by the older source-build `build.sh`. This tag does not expose the .NET 9/10 regular VMR build mode. The profile's `sourceOnly=true` describes that construction path; it does not certify that every dependency was rebuilt or that no prebuilt package was consumed. Preparation uses an upstream SDK, previously source-built artifacts, bootstrap substitutions, reference packages, and other dependencies. The selected build also passes `--online`, which permits online package sources. Prebuilt-usage reports and actual component provenance must be reviewed before making stronger claims.

The source-build graph builds the core runtime and ASP.NET Core. In product source-build mode, the installer selects local shared-framework assets and excludes its external archive fallback. For the recorded SDK archive, final byte comparisons match all 184 core-runtime and 143 ASP.NET entries, and actual installer `DownloadFile` task records select both local archives. Preserve and repeat those checks for a new output. [Installer adapter](https://github.com/dotnet/dotnet/blob/v8.0.133/repo-projects/installer.proj#L40), [layout and fallback rules](https://github.com/dotnet/dotnet/blob/v8.0.133/src/installer/src/redist/targets/GenerateLayout.targets#L383).

The runtime's source-build defaults set `NoPgoOptimize=true`. A successful Release build would not establish identical optimization inputs, performance, or bytes compared with Microsoft's SDK. This setting does not establish that all runtime dynamic PGO is absent. [Runtime source-build defaults](https://github.com/dotnet/dotnet/blob/v8.0.133/src/runtime/Directory.Build.props#L302).

## 2. Isolated workspace and container

Use the existing Windows ARM64 host with a native ARM64 Linux WSL 2 distribution. The default distribution is `Ubuntu-22.04`; the wrapper requires Linux `aarch64` and discovers the default user's home and UID:GID.

```text
<Linux HOME>/cbodotnet/net8/
  work/
    dotnet-v8.0.133/       # Pinned VMR checkout and upstream build outputs
  inputs/
    arm64-xenial/         # Independently generated target sysroot
    official-sdk/         # Optional released SDK comparison baseline
  container-home/         # Build user's home and dependency caches
```

Keep the .NET 8 source, sysroot reports, and container home separate from .NET 9 and .NET 10. Do not substitute another version's already prepared workspace. The .NET 8 sysroot uses the selected tag's own generator and has its own recorded inventories.

| WSL location | Container location |
| --- | --- |
| `<Linux HOME>/cbodotnet/net8/work/dotnet-v8.0.133` | `/vmr` |
| `<Linux HOME>/cbodotnet/net8/inputs` | `/inputs` |
| `<Linux HOME>/cbodotnet/net8/container-home` | `/home/build` |
| Windows project translated by `wslpath` | `/project` |
| Project's `artifacts/8.0.133-linux-arm64/reports/sysroot` | `/reports`, read-only during ordinary build containers |

[arm64-net8.Containerfile](../containers/arm64-net8.Containerfile) starts from the official ARM64 base pinned at `sha256:7ef8f6ee1b9982511349757443eb4844f0db4f8cef1aff6148a7ba1c25d7c6f4`. It adds clang/LLVM/LLDB 18, CMake, native libraries, autotools, archive utilities, and reporting tools. It verifies both clang and GCC can invoke the unversioned `ld.lld` linker. The prepared derived image ID is `1be55e7358c9e3f9a58f28db1df08e36a56ec9fbb175ccfab8dc69f22cce4a70`. The runtime documentation requires CMake 3.20 or newer; the actual image ID and installed package versions identify a run more precisely than the base digest alone. [Tagged Linux requirements](https://github.com/dotnet/dotnet/blob/v8.0.133/src/runtime/docs/workflow/requirements/linux-requirements.md).

### Archive-tool compatibility with the older Podman host

On this host, Podman `3.4.4`'s default seccomp policy caused Ubuntu 24.04 `tar` to fail SDK extraction with `Cannot change mode ... Operation not permitted`. The original SDK archive also failed extraction into a fresh directory and with `--same-permissions`. A fresh complete extraction succeeded unchanged when only `fchmodat2` was additionally allowed.

The wrapper invokes [prepare-net8-seccomp.py](../scripts/prepare-net8-seccomp.py) on native ARM64 to derive `/inputs/seccomp-net8-fchmodat2.json` from `/usr/share/containers/seccomp.json`. It verifies the host libseccomp resolves native `fchmodat2` to syscall `452`, preserves every existing rule and default action, and adds exactly one allow rule. Ordinary .NET 8 preparation/build/test containers use this policy; the host default and privileged sysroot invocation are unchanged. The recorded output SHA-256 is `433ff4d41a88c0c37acf4372cfd84b13399c3a831037ee269141508d1538f990`, derived from base SHA-256 `27e6dbb7d478e222144af8ac0dd4ea2423f1d01f8d8adde053f8831371106740`. A different host policy requires its own report rather than assuming those hashes apply.

Keep `reports/seccomp-net8.json` and the per-attempt base/derived policy snapshots. The workaround does not use `seccomp=unconfined`, grant build containers privilege, change archive bytes, or patch upstream tar commands.

## 3. Prepare the environment and bootstrap inputs

The implemented [Windows wrapper](../scripts/Invoke-Net8Build.ps1) exposes separate `Prepare`, `Build`, and `Test` modes. `Prepare` installs host prerequisites, verifies or clones the pinned source, builds the image, creates or validates the dedicated sysroot, and runs upstream preparation in its own recorded attempt. `Build` and `Test` require those inputs and do not implicitly install tools or prepare the workspace.

```powershell
Set-Location D:\Projects\cbodotnet
Get-Help ./scripts/Invoke-Net8Build.ps1 -Full
./scripts/Invoke-Net8Build.ps1 -Mode Prepare
```

For a different existing distribution or isolated parent, pass `-Distribution` and an absolute Linux `-LinuxWorkspaceRoot` consistently in all modes. The default workspace is `<Linux HOME>/cbodotnet/net8`. The profile is fixed to this version; `-ProfilePath` is not a generic version override.

### Signed Xenial target sysroot

[prepare-sysroot8.sh](../scripts/prepare-sysroot8.sh) invokes the original tagged generator:

```bash
./eng/common/cross/build-rootfs.sh arm64 xenial \
  --rootfsdir /inputs/arm64-xenial
```

The generator uses debootstrap and chroot in a dedicated native ARM64 root container. Only this sysroot-preparation container receives `--privileged`; the source and project are read-only for that invocation. Build and test processes run without that privilege as the discovered Linux UID:GID. No architecture emulation is needed.

The Containerfile combines the current Ubuntu archive keyring with the removed historical archive keys needed by Xenial. The helper checks that union, keeps package signature verification enabled, and does not pass `--skipsigcheck`. Successful preparation records the generator hash, arguments, keyring hashes, package versions, regular-file hashes, and complete symlink inventory. Existing sysroots must match these records before reuse.

The observed sysroot preparation completed at `2026-10-30T01:54:11.102957Z`. Its generator SHA-256 is `c60908c01f9c171c74b72e3acc4bb222e659477e365b4efe86e27111ba7a0f51`. The recorded `sysroot-provenance.json` has `packageSignatureVerification=true` and `emulation=false`; full file and symlink inventories were checked before the subsequent preparation and build.

The upstream generator recreates its target recursively. The helper therefore refuses an existing target, including a dangling symlink, instead of retrying destructively. Preserve failed inputs and reports and investigate before selecting a new dedicated workspace.

### Original upstream bootstrap transformation

After the image and sysroot are ready, run the selected tag's original preparation:

```bash
./prep.sh
```

Its default behavior installs SDK `8.0.131`, downloads the previously source-built archive declared in `eng/Versions.props`, and runs `eng/bootstrap/buildBootstrapPreviouslySB.csproj`. Although the starting archive is named for `centos.9-x64`, the bootstrap project replaces runtime/native packages with portable package inputs for six Unix RIDs, including `linux-arm64`. The other RIDs are `linux-x64`, `linux-musl-x64`, `linux-musl-arm64`, `osx-x64`, and `osx-arm64`. Their presence is an input transformation, not a claim that this project builds or distributes those architectures.

Do not preseed an untransformed archive in `prereqs/packages/archive/` and assume preparation will bootstrap it. This tag's `prep.sh` skips both downloading and the associated bootstrap transformation when an artifacts archive already exists. The build helper rejects a leftover non-bootstrap archive rather than accepting an incomplete ARM64 preparation. Do not use `--no-bootstrap` or `--no-artifacts` to bypass that check. [Preparation script](https://github.com/dotnet/dotnet/blob/v8.0.133/prep.sh), [bootstrap package transformation](https://github.com/dotnet/dotnet/blob/v8.0.133/eng/bootstrap/buildBootstrapPreviouslySB.csproj).

[watch-bootstrap8.py](../scripts/watch-bootstrap8.py) preserves the original without preseeding an archive that changes upstream behavior. Its `watch` action creates a hidden hard link inside the same archive directory as soon as the download file appears. That link retains the original inode when upstream replaces or deletes its named input, and its `.cbodotnet-original-` prefix does not match the upstream `Private.SourceBuilt.Artifacts*` discovery pattern. The `finalize` action preserves the completed archive under `/inputs/original-bootstrap/`, using a hard link when possible or a checked copy across filesystems. It validates both tar archives, records their hashes and package-version data, and writes `/inputs/bootstrap8-prepared.json` only after successful upstream preparation.

`Build` and `Test` require the bootstrap archive, SDK `8.0.131`, and that successful marker. The preservation helper's `verify` action rechecks the original and transformed archive fingerprints, and each action gets its own `bootstrap-inputs.json` report. The marker is not a substitute for the actual files or the recorded preparation exit status.

The observed preparation attempt, `prepare-20261030T0159583003611Z`, exited successfully at `2026-10-30T02:04:41.191612Z`. Its input report records:

| Input | Bytes | SHA-256 |
| --- | --- | --- |
| Original `Private.SourceBuilt.Artifacts.8.0.131-servicing.26422.1.centos.9-x64.tar.gz` | 728,976,053 | `e39d2656832923af11d00a2bd32a10326ab84a0dfd20307a8491d8af3f9e720c` |
| Transformed `Private.SourceBuilt.Artifacts.Bootstrap.tar.gz` | 1,465,776,388 | `4747ec5b5c26ef0df81d72546c7bea556bd1955f9d91d1586a4fa91d5f5cbd09` |

The transformed inventory includes 13 Linux ARM64 package files, including `Microsoft.NETCore.App.Runtime.linux-arm64 8.0.31`, the ARM64 host/crossgen2 packs, and NativeAOT bootstrap tools. These are previous-release bootstrap inputs, separate from the target runtime `8.0.33`. The input fingerprints record retrieved content; they do not constitute publisher signature verification.

## 4. Build the intended portable ARM64 SDK

After successful preparation:

```powershell
./scripts/Invoke-Net8Build.ps1 -Mode Build
```

The container uses rootful Podman with `--cgroup-manager=cgroupfs --events-backend=file`, `--cgroups=disabled`, and the default Linux user's UID:GID. The build's working directory is `/vmr`, with a separate `/home/build` home. It remains a local WSL/container build.

The [Bash wrapper](../scripts/build-vmr8.sh) exports the target and compiler settings across nested component processes and limits native build parallelism with CPU affinity:

```bash
export ROOTFS_DIR=/inputs/arm64-xenial
export CLR_CC=/usr/bin/clang-18 CLR_CXX=/usr/bin/clang++-18
export CppCompilerAndLinker=/usr/bin/clang-18
export PortableBuild=true CrossBuild=true
export DOTNET_PROCESSOR_COUNT=2
export BUILD_SOURCEVERSION=7d1bf90885cff22e7da72b27e9848e42fd3cb1ae

taskset --cpu-list 0,1 ./build.sh --clean-while-building --online -- \
  /p:Configuration=Release /p:Platform=arm64 /p:TargetOS=Linux \
  /p:TargetRid=linux-arm64 /p:PortableBuild=true /p:CrossBuild=true /m:2
```

The wrapper selects the actual allowed CPU list; `0,1` illustrates the command shape. `DOTNET_PROCESSOR_COUNT` and MSBuild node limits alone do not constrain native tools that call `nproc`.

.NET 8 accepts additional MSBuild properties only after its literal `--` separator. Do not copy the .NET 9 root `--rid`/`--ci` switches or .NET 10 `--arch`/`--os` switches into this command. This tag's component orchestration already supplies CI mode and source-build properties to inner builds. It also preserves the component build identities pinned by the selected revision.

The wrapper verifies the pinned Git commit before exporting `BUILD_SOURCEVERSION` from that verified value. Arcade's official `RepositoryInfo.targets` uses this input for `RepositoryCommit` when source-control queries are disabled and otherwise falls back to forty zeros. The official installer VMR pipeline passes the same environment input into its build container. Retain it when reproducing the command directly; it is required for truthful reusable-artifact revision metadata. The command and status reports record its value. [Revision default](https://github.com/dotnet/dotnet/blob/v8.0.133/src/arcade/src/Microsoft.DotNet.Arcade.Sdk/tools/RepositoryInfo.targets#L26), [official pipeline pass-through](https://github.com/dotnet/dotnet/blob/v8.0.133/src/installer/eng/pipelines/templates/jobs/vmr-build.yml#L239).

### Meaning of the legacy nonportable flag

The runtime adapter passes `SourceBuildNonPortable=true`, but this does not unconditionally force `PortableBuild=false`. In this exact revision, its functional consumer in Arcade sets `TargetRid` from the host only when `TargetRid` is empty. The adapter already supplies the explicit target RID. The root `PortableBuild=true` calculation selects `linux-arm64`, and the exported portability properties retain that intent in nested processes. No vendor patch is assumed necessary for this legacy flag. [Runtime adapter](https://github.com/dotnet/dotnet/blob/v8.0.133/repo-projects/runtime.proj#L24), [conditional RID default](https://github.com/dotnet/dotnet/blob/v8.0.133/src/arcade/src/Microsoft.DotNet.Arcade.Sdk/tools/SourceBuild/SourceBuildArcade.targets#L57).

Runtime native command generation adds `-cross` when the MSBuild `CrossBuild` property is true and adds `-portablebuild=false` when `PortableBuild` is not true. Inspect the actual native commands and CMake cache before accepting the sysroot policy. A portable RID or supplied property alone does not prove the final ABI ceiling. This tag has no .NET 9-style source-build injection of system Brotli, and its Linux native defaults use bundled libraries. [CoreCLR native arguments](https://github.com/dotnet/dotnet/blob/v8.0.133/src/runtime/src/coreclr/runtime.proj#L32).

### ARM64 host cross-component compatibility

The first build confirmed clang 18 was invoked with `--gcc-toolchain=/inputs/arm64-xenial/usr` and `--sysroot=/inputs/arm64-xenial` for target native code. Main CoreCLR native compilation reached 100% and completed successfully. The subsequent host cross-component configuration failed because this .NET 8 CMake branch recognizes only x86 host processors. It rejected `aarch64` while building the tools selected by `CrossBuild=true`, even though the host and target CPU architecture are both ARM64.

[0001-support-arm64-cross-components-host.patch](../patches/net8/0001-support-arm64-cross-components-host.patch) backports the exact two-line `aarch64` host case already present in the selected .NET 9 source. It retains the expected host-tool graph and output locations. It does not disable the target sysroot, skip host-tool requirements, or alter the `SourceBuildNonPortable` flag. The separate host helpers may use host libraries, so final SDK ABI inspection remains required rather than assuming every generated build tool is a portable redistributable. [Pinned .NET 9 host detection](https://github.com/dotnet/dotnet/blob/v9.0.123/src/runtime/eng/native/configureplatform.cmake#L30).

[apply-net8-patches.py](../scripts/apply-net8-patches.py) applies or verifies the fixed compatibility chain, including the ASP.NET adapter correction described below. Its direct container invocation is:

```bash
python3 /project/scripts/apply-net8-patches.py apply \
  --source-dir /vmr \
  --reports-dir /project/artifacts/8.0.133-linux-arm64/reports/patches/first-apply
```

The helper verifies the exact VMR commit, each original/patched file hash, and both patch hashes. Each patch permits exactly two added lines in its one fixed tracked file. Every input is checked before any file is changed. Repeating `apply` on exact patched content makes no source change; `verify` requires both patched hashes. It preserves unrelated source changes and rejects other edits to either target rather than overwriting them. Optional report output must be outside the VMR, and `net8-patches-apply.json` or `net8-patches-verify.json` must be a new file for that invocation. New reports use schema version 2 with a per-patch array; historical one-patch reports remain preserved. Source commit identity plus the recorded patch chain describes the modified build input; do not describe it as an unchanged tagged source tree.

The failed first attempt and its native configuration evidence remain under `reports/runs/build-20261030T0206158376987Z/` and `reports/native-config/`. Its total timed duration was 11 minutes 33.72 seconds; the runtime component reported 6 minutes 54.18 seconds. Before a retry, preserve component logs and inspect the failed host-specific CMake cache. Any quarantine should move only the verified affected generated host-object directory within the dedicated workspace, retaining the already completed target native objects and other inputs.

### ASP.NET portable-target propagation

The second attempt completed the runtime and additional dependencies, then failed in ASP.NET shared-framework generation with `Could not find crossgen2 tools/crossgen2`. The local runtime had produced the expected `Microsoft.NETCore.App.Crossgen2.linux-arm64 8.0.33` package, including its executable. The missing directory prefix in that error identified an empty generated package-root property rather than an absent tool binary.

The legacy VMR adapter calculated its own ASP.NET `PortableBuild=false` when the requested target RID was unchanged. ASP.NET then appended that RID to lists that already contained portable `linux-arm64` runtime/crossgen2 references. Both duplicate references were marked implicit, and the SDK's duplicate-reference check removed them, leaving the package path properties absent. [Adapter](https://github.com/dotnet/dotnet/blob/v8.0.133/repo-projects/aspnetcore.proj#L9), [dependency lists](https://github.com/dotnet/dotnet/blob/v8.0.133/src/aspnetcore/eng/Dependencies.props#L108), [duplicate-reference handling](https://github.com/dotnet/dotnet/blob/v8.0.133/src/sdk/src/Tasks/Microsoft.NET.Build.Tasks/CheckForImplicitPackageReferenceOverrides.cs).

[0002-preserve-portable-aspnetcore-target.patch](../patches/net8/0002-preserve-portable-aspnetcore-target.patch) makes the adapter honor an explicitly supplied outer `PortableBuild=true`. Empty or false settings retain its original behavior. It keeps ReadyToRun compilation enabled and uses the locally built crossgen2 package; no external tool replacement or filename wrapper is introduced. This source-build producer disables NativeAOT for crossgen2 but publishes a managed single-file executable, so that setting does not imply a DLL-only package.

The second attempt is preserved at `reports/runs/build-20261030T0230238210439Z/`, with an elapsed root-command time of 18 minutes 33.59 seconds. The third attempt, `build-20261030T0300329409492Z`, records the first patch as already applied and the second as newly applied, with both target hashes verified. It packaged the SDK successfully, then failed at root SDK-symbol extraction under the original seccomp policy after 14 minutes 41.84 seconds. It reused completed component outputs; that duration is not a cold full-build measurement.

### Preserve symbol inputs across packaging retries

The next attempt, `build-20261030T0333546335877Z`, used the derived policy but exposed a separate retry-state issue at `build.proj:75`. The earlier root action had already extracted and deleted `Release/Symbols.*.tar.gz`, while its copy-completed checkpoint prevented recopying them. Its filename expression then received no symbol archive. Twenty original archives remained in the local blob feed.

The build/test harness now invokes [restore-net8-symbol-inputs.py](../scripts/restore-net8-symbol-inputs.py) before the upstream action. It copies only retained matching symbol archives in the fixed ARM64 Release paths, verifies the pinned commit, rejects links or different existing destinations, and writes a new external `net8-symbol-inputs.json` with sizes and SHA-256/SHA-512 values. Exact existing copies can be reused. The direct container command is:

```bash
python3 /project/scripts/restore-net8-symbol-inputs.py \
  --source-dir /vmr --reports-dir /absolute/new/action-report-directory
```

The report directory must already exist outside the VMR; its `net8-symbol-inputs.json` must be new. This recovery leaves SDK bytes and upstream symbol checks intact. The fifth attempt, `build-20261030T0339397739347Z`, restored 20 retained archives and completed root packaging with exit code 0. Its 35.95-second duration measures cached resumption and finalization. The SDK archive hash remained unchanged, so the recorded native checks and shared-framework comparisons still apply.

## 5. Test only after an SDK exists

The older entry point provides source-build smoke tests through `--run-smoke-test`. This is distinct from the .NET 9 `UnifiedBuild.Tests` and scenario-test orchestration. The wrapper's test mode is:

```powershell
./scripts/Invoke-Net8Build.ps1 -Mode Test
```

When an official SDK comparison baseline is used, acquire the exact `8.0.133` Linux ARM64 archive separately, verify it against official release metadata, and keep it in `/inputs/official-sdk/`. The existing [baseline downloader](../scripts/fetch-test-sdk.py) accepts the .NET 8 profile. The baseline is a comparison input, not a community build artifact or the bootstrap SDK. The wrapper supplies `SMOKE_TESTS_MSFT_SDK_TARBALL_PATH`; its `-OfficialSdkArchivePath` parameter defaults to `/inputs/official-sdk/dotnet-sdk-8.0.133-linux-arm64.tar.gz` and accepts another absolute container path. Passing an empty string leaves that environment input absent, so upstream skippable SDK-content tests skip their comparisons. They do not download a baseline automatically. Record such skips rather than treating them as content-comparison passes.

The smoke-test environment uses `RUNNING_IN_CI=true`, `SMOKE_TESTS_RUNNING_IN_CI=true`, and `SMOKE_TESTS_WARN_SDK_CONTENT_DIFFS=true`. The smoke-specific CI input enables strict reusable-artifact revision validation. A successful invocation with differences treated as warnings would not establish full equivalence to Microsoft's SDK. Record actual counts, skips, comparison differences, and limitations. Do not describe a build as having passed Stage 2 or prebuilt-baseline validation merely because the corresponding source or configuration exists.

The first recorded invocation, `test-20261030T0342164439757Z`, ran 46 tests: 43 passed, one failed, and two skipped. The sole failure was strict validation of a forty-zero `.version` commit in the newly generated previously source-built artifacts tarball. Its functional scenarios, SourceLink, ReadyToRun, archive ownership, debug-symbol checks, and official SDK comparison methods passed. The failed TRX and logs remain preserved.

After adding the verified producer revision input, recovery preserved that zero-commit tarball and only the two empty `package-source-build/Build.complete` and `dotnet/Build.complete` producer checkpoints under `/inputs/recovery/zero-commit-psb-20261030/`. It retained compiled-component checkpoints and SDK bytes. `reports/psb-commit-recovery.json` records the operation. The sixth build, `build-20261030T0349478257751Z`, reran the upstream producer and completed with exit code 0 in 52.84 seconds of cached regeneration/finalization. The regenerated reusable-artifacts `.version` contains the exact VMR commit and `8.0.133-servicing.26523.1`; `reports/construction/psb-metadata.json` records its archive hashes and exact version text. No tarball contents or test assertions were edited.

Final invocation `test-20261030T0353117156658Z` completed with exit code 0: **46 total, 44 passed, zero failed, two skipped**. Its root elapsed time was 3 minutes 43.09 seconds. The strict revision check passed. License scanning was skipped because `SMOKE_TESTS_LICENSE_SCAN_PATH` was absent, and poisoning was skipped because `SMOKE_TESTS_POISON_REPORT_PATH` was absent. Each run retains its own `upstream-tests-summary.json`, TRX, logs, and output archive.

Both SDK comparison methods matched the tagged upstream baselines without recorded baseline warnings. The normalized file-list diff is 19,432 bytes, with 16 added and 221 removed paths expected by that baseline. The filtered assembly-version lists are byte-identical, and their diff is empty. Independent diff checks record valid exit codes and empty stderr under each run's `content-comparisons/`, covering the upstream helper's stdout-only behavior. Normalization, exclusions, and omitted assembly revision fields limit these checks; they do not establish archive byte equivalence. No Stage 2, license-scan, poisoning, or comprehensive prebuilt-baseline validation pass is claimed.

Independently extract the final community archive and run [verify-sdk.sh](../scripts/verify-sdk.sh) with explicit .NET 8 options:

```bash
bash /project/scripts/verify-sdk.sh \
  --archive /absolute/path/to/the/collected-sdk.tar.gz \
  --output-dir /new/empty/report-directory \
  --expected-version 8.0.133 --expected-rid linux-arm64 \
  --framework net8.0 --max-glibc 2.23
```

The verifier checks SDK identity, archive content, ELF architecture and required symbol versions, console DLL/apphost execution, RSA, random bytes, ICU formatting, and ASP.NET loopback HTTP. It creates private writable home, CLI, and package-cache directories, plus a mode-`0700` `XDG_RUNTIME_DIR` for native user-scoped mutexes. This matters for .NET 8 in containers whose synthetic UID has passwd home `/`; a private `HOME` alone did not prevent the first Debian 13 `NuGet-Migrations` mutex failure.

The recorded archive passed all six functional checks on native ARM64 Ubuntu 22.04, Ubuntu 24.04, and Debian 13. Its 19 inspected ELF files are AArch64, with maximum requirements `GLIBC_2.17`, `GLIBCXX_3.4.21`, and `CXXABI_1.3.7`, below the intended GLIBC ceiling. Repeat the checks for each new archive. These environments share the WSL kernel; results provide bounded compatibility evidence rather than certify every Linux distribution, workload, NativeAOT application, or external package. ELF symbol maxima do not establish all dynamic-library or kernel requirements.

## 6. Preserve evidence and collect the actual archive

Reports belong under `artifacts/8.0.133-linux-arm64/reports/`, separate from the VMR and inputs. Preserve environment/image records, independent sysroot inventories, bootstrap preparation evidence, and every failed or successful action in its own UTC-stamped `runs/prepare-*`, `runs/build-*`, or `runs/test-*` directory. Each action records its command, log, resource usage, status, image/profile snapshots, bootstrap-input fingerprints, applicable patch-chain verification, derived seccomp provenance, and retained symbol-input recovery. All six build attempts and both test invocations are retained. The fifth build first completed packaging; the sixth regenerated revision metadata; the second test invocation passed. Upstream component logs can be overwritten on retry; archive them before another attempt or test invocation. A generated SDK archive is not evidence of root action completion; inspect its separate status.

This legacy build's expected SDK output area is `artifacts/arm64/Release/` in the VMR checkout, not the newer `artifacts/assets/Release/Sdk/` layout. Locate the actual generated SDK, verify its version and RID, and inspect its contents before collection. [Legacy output properties](https://github.com/dotnet/dotnet/blob/v8.0.133/Directory.Build.props), [SDK tarball discovery](https://github.com/dotnet/dotnet/blob/v8.0.133/build.proj#L186).

Preserve the complete VMR working-tree diff as well as the authored patch files. This run has 108 modified tracked files: the two compatibility patches plus 106 upstream-generated configuration changes. `reports/source-worktree.json`, `source-worktree.diff`, and `source-worktree-status.txt` inventory them and match the saved sixth-attempt state. Do not describe the checkout as an unchanged tag or discard the generated configuration before recording it.

Collection must recognize the legacy profile and retain its source-build construction label; do not change `sourceOnly` to `false` merely to bypass a collector guard. Preserve the upstream tarball bytes, then generate community archive naming, SHA-256/SHA-512 files, and a manifest with actual inputs, source changes, component construction, and report digests. Refresh that manifest after final root and test actions so it includes the complete evidence set.

Inside the prepared build container with the existing `/vmr` and `/project` mounts, run:

```bash
build_image_id=$(python3 -c 'import json; print(json.load(open("/project/artifacts/8.0.133-linux-arm64/reports/derived-image.json"))["imageId"])')
python3 /project/scripts/collect-artifacts.py \
  --source-dir /vmr \
  --profile /project/profiles/dotnet-8.0.133-linux-arm64.json \
  --output-dir /project/artifacts/8.0.133-linux-arm64 \
  --reports-dir /project/artifacts/8.0.133-linux-arm64/reports \
  --build-image-id "$build_image_id" --build-revision 1
```

The recorded immutable image ID is `1be55e7358c9e3f9a58f28db1df08e36a56ec9fbb175ccfab8dc69f22cce4a70`. The command reads the actual inspected ID for the current run; do not replace it with a mutable image tag or reuse a previous run's image record after rebuilding. The collector verifies the pinned Git commit and exact legacy archive selection. Its manifest records source changes and report hashes; it does not independently certify construction or execute the SDK.

For the recorded output, `reports/construction/shared-framework-identity.json` confirms all 184 core-runtime and 143 ASP.NET entries match the local archives. `reports/construction/origin-evidence.json` adds matching local blob-feed hashes and actual `DownloadFile` task URI records from the retained installer binlog. The bounded replay completed 48,633 events without executing build targets. The combined evidence is scoped to these two shared frameworks; it does not prove every SDK build input was rebuilt.

Also retain the upstream `artifacts/prebuilt-report/{prebuilt-usage.xml,annotated-usage.xml}` byte-for-byte under `reports/prebuilt-usage/`, with hashes and a parsed summary. This run records 31 usage entries for nine package/version identities across 23 assets files. Known reference packages are excluded by the upstream task, and creator annotations match package IDs independently of the used version. A creator annotation does not erase an older prebuilt usage. The [build report](build-report-8.0.133-arm64.md#recorded-prebuilt-package-usages) lists actual identities and explains coverage; do not label this a zero-prebuilt or approved-baseline result.

The collected SDK is `cbodotnet-sdk-8.0.133-linux-arm64-build.1.tar.gz`, 242,266,582 bytes, with SHA-256 `8c9ab2e845e7ca16d6a185d47d2131fd43f3f147827c0fa56ae5552a9e52490e`. It contains SDK `8.0.133`, RID `linux-arm64`, and both shared frameworks `8.0.33`. Root packaging and the recorded upstream smoke invocation completed successfully within the stated scope. Generated archives, reports, caches, and workspaces remain local and excluded from Git. The project continues to include .NET 5 and later regardless of Microsoft lifecycle status; this experiment establishes only the selected .NET 8 ARM64 result.
