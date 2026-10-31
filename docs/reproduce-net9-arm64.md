# Preparing and building .NET SDK 9.0.123 on ARM64

Procedure and status snapshot: **2026-10-30, Asia/Seoul**. The .NET 9.0.123 Linux ARM64 SDK has been built and collected, and SDK/application/ABI validation has passed in Ubuntu 22.04, Ubuntu 24.04, and Debian 13 ARM64 user spaces. The separate clean-source scan passed. The upstream test invocation exited successfully with 500 UnifiedBuild tests passed and 34 discovered scenarios: 32 passed, two skipped, zero failures or errors. See the [build report](build-report-9.0.123-arm64.md) for the recorded result and limitations. Run each step separately and inspect its actual result before proceeding.

## 1. Selected version and construction scope

| Item | Selected value |
| --- | --- |
| SDK / VMR tag | `9.0.123` / `v9.0.123` |
| VMR commit | `9f04b57d1366e21b3178648493d6edffeff2216e` |
| Selection snapshot | 2026-10-30; latest published 1xx SDK with the selected VMR tag |
| Latest published .NET 9 SDK recorded in the profile | `9.0.320`, released 2026-10-25; no matching VMR tag was found during selection |
| Runtime version recorded for both selections | `9.0.22` |
| Bootstrap SDK | `9.0.121` |
| Source-built artifacts version recorded in the profile | `9.0.121-servicing.26421.1` |
| Host / target | Native Linux ARM64 / `linux-arm64` |
| Build mode | Ordinary VMR build with `--ci`; `sourceOnly=false`, `CrossBuild=true`, `PortableBuild=true` |
| Compiler / target sysroot | Native ARM64 clang 18 / ARM64 Ubuntu 16.04 Xenial |
| Intended maximum required GLIBC symbol version | `2.23`, subject to inspection of the actual output |
| Parallelism | Two selected CPUs through `taskset`, `DOTNET_PROCESSOR_COUNT=2`, and MSBuild `/m:2` |
| Derived image tag | `localhost/cbodotnet-arm64:9.0.123` |

The [profile](../profiles/dotnet-9.0.123-linux-arm64.json) records the selection and pinned inputs. Choosing `9.0.123` is a VMR 1xx build selection, not a claim that it is the newest .NET 9 SDK across all feature bands. `9.0.320` is a different SDK feature band; the shared runtime version does not make the two source layouts or tooling versions interchangeable. Preserve the tag and commit for this procedure rather than substituting a later download or moving branch.

Unlike the .NET 10.0.403 4xx profile, this .NET 9 1xx VMR contains runtime sources. The collected SDK's `Microsoft.NETCore.App 9.0.22` matches the locally published runtime archive, while its `Microsoft.AspNetCore.App 9.0.22` matches the SDK adapter's preserved upstream download. These identities were checked across all 186 core-runtime and 143 ASP.NET shared-framework entries, alongside the actual download task recorded in the build binlog. This is an ordinary build with mixed component construction and upstream bootstrap/package inputs; it does not enable source-only mode. [Tagged SDK adapter](https://github.com/dotnet/dotnet/blob/v9.0.123/repo-projects/sdk.proj), [tagged build entry point](https://github.com/dotnet/dotnet/blob/v9.0.123/build.sh).

## 2. Prerequisites and isolated workspace

Use PowerShell 7.3 or later on the Windows ARM64 host and an existing native ARM64 WSL Linux distribution. The default distribution is `Ubuntu-22.04`. The wrapper checks `uname -s` and `uname -m` and requires `Linux` / `aarch64`.

The [Windows wrapper](../scripts/Invoke-Net9Build.ps1) queries the default WSL user's `HOME`, UID, and GID. It does not assume a Windows or Linux username. The observed preparation and build use UID:GID `1000:1000`; another installation uses its actual default Linux user.

The default workspace is independent of the .NET 10 workspace:

```text
<Linux HOME>/cbodotnet/net9/
  work/
    dotnet-v9.0.123/       # Pinned source and upstream build outputs
  inputs/
    arm64-xenial/         # Target headers and libraries
    official-sdk/        # Matching Microsoft SDK used only as a test baseline
  container-home/         # Build user's home and dependency caches
```

| WSL location | Container location |
| --- | --- |
| `<Linux HOME>/cbodotnet/net9/work/dotnet-v9.0.123` | `/vmr` |
| `<Linux HOME>/cbodotnet/net9/inputs` | `/inputs` |
| `<Linux HOME>/cbodotnet/net9/container-home` | `/home/build` |
| Project directory translated by `wslpath` | `/project` |
| Project's `artifacts/9.0.123-linux-arm64/reports/sysroot` | `/reports`, read-only during build and test |

Do not point this profile at the .NET 10 source, Bionic sysroot, or container home. To select another location, pass an absolute Linux path with `-LinuxWorkspaceRoot` and use it consistently in all three modes. `-Distribution` selects another existing WSL distribution, and `-ImageName` selects the local derived image tag. The fixed profile and Bash wrappers must be updated together when selecting a different SDK revision; `-ProfilePath` is not a generic version override.

## 3. Prepare explicitly

From Windows PowerShell:

```powershell
Set-Location D:\Projects\cbodotnet
Get-Help ./scripts/Invoke-Net9Build.ps1 -Full

./scripts/Invoke-Net9Build.ps1 -Mode Prepare
```

For a separate workspace, the equivalent invocation is:

```powershell
./scripts/Invoke-Net9Build.ps1 -Mode Prepare `
  -Distribution Ubuntu-22.04 `
  -LinuxWorkspaceRoot '/home/<user>/cbodotnet/net9'
```

Replace `<user>` with the actual Linux username, or omit this parameter to use the automatically discovered home. Do not run preparation concurrently with a build in the same workspace.

`Prepare` performs the following work:

1. Installs WSL host prerequisites, including Podman, Git, Python, and download/archive tools, through root `apt-get`.
2. Creates the separate workspace directories, clones the source only if absent, and verifies the exact VMR commit.
3. Pulls the base image by the profile's digest, checks that it is Linux ARM64, and builds [arm64-net9.Containerfile](../containers/arm64-net9.Containerfile).
4. Creates the Xenial sysroot only when it does not already exist, then verifies its file hashes and complete file/symlink inventories.
5. Records the derived image and the WSL/container environment inventories.

The base reference is `mcr.microsoft.com/dotnet-buildtools/prereqs@sha256:7ef8f6ee1b9982511349757443eb4844f0db4f8cef1aff6148a7ba1c25d7c6f4`. The derived image adds native runtime prerequisites, clang/LLVM/LLDB 18, CMake, debootstrap, and reporting tools. It installs the unversioned `lld` package alongside `lld-18`, then checks `gcc -fuse-ld=lld -Wl,--version` to ensure `ld.lld` is available on `PATH`. It also checks the inherited Node installation is at least version 20. Additional `apt-get` packages are not locked solely by the base digest; use the actual image ID and hashes in `reports/derived-image.json` when identifying a run.

### Signed Xenial preparation

[prepare-sysroot9.sh](../scripts/prepare-sysroot9.sh) uses the pinned tag's original generator:

```bash
./eng/common/cross/build-rootfs.sh arm64 xenial \
  --rootfsdir /inputs/arm64-xenial
```

This procedure uses the generator's original debootstrap/chroot path in a dedicated native ARM64 root container. Only this sysroot-creation container receives `--privileged`. The source and project are mounted read-only during that step; the inputs and sysroot report directories are writable. The build and test containers do not receive `--privileged`.

Xenial metadata uses historical Ubuntu signing keys. The Containerfile preserves the original current keyring as `cbodotnet-current-ubuntu-archive.gpg` and combines it with `ubuntu-archive-removed-keys.gpg` in `ubuntu-archive-keyring.gpg`. The preparation script verifies that union before invoking the generator. Package signature verification stays enabled; it does not pass `--skipsigcheck`, use architecture emulation, or modify the tagged generator.

Preparation records the generator hash, arguments, keyring hashes, package versions, every regular file hash, and the symlink inventory. Existing sysroots are validated against those records. A missing report, different file set, changed symlink, or bad hash is an error. The wrapper does not delete an incomplete or different sysroot to retry: preserve it and use a new dedicated workspace after investigating the failure.

## 4. Build using the prepared environment

After `Prepare` completes successfully:

```powershell
./scripts/Invoke-Net9Build.ps1 -Mode Build
```

Pass the same `-Distribution`, `-LinuxWorkspaceRoot`, and `-ImageName` values if preparation used overrides. `Build` and `Test` require existing source, inputs, image, and sysroot reports; they do not install host tools or implicitly rerun preparation.

The wrapper uses a rootful Podman engine with `--cgroup-manager=cgroupfs --events-backend=file`. Engine commands execute as WSL root, while the build process executes with the default Linux user's UID:GID and `HOME=/home/build`. Containers use `--cgroups=disabled --network=host`. This is a native ARM64 build without x64 emulation, and it does not change the WSL memory settings or VHD location.

[build-vmr9.sh](../scripts/build-vmr9.sh) exports `ROOTFS_DIR=/inputs/arm64-xenial`, selects `/usr/bin/clang-18` and `/usr/bin/clang++-18` through `CLR_CC` and `CLR_CXX`, and unsets `NUGET_XMLDOC_MODE` so that SDK XML documentation is not skipped. It also exports `CppCompilerAndLinker=/usr/bin/clang-18`: the NativeAOT MSBuild targets select their compiler independently of `CLR_CC` and otherwise probe the unversioned `clang` name before falling back to GCC. This explicit property keeps NativeAOT's `--gcc-toolchain` sysroot argument on the intended Clang compiler. The compiler property is recorded in each attempt's command report. [Tagged NativeAOT compiler selection](https://github.com/dotnet/dotnet/blob/v9.0.123/src/runtime/src/coreclr/nativeaot/BuildIntegration/Microsoft.NETCore.Native.Unix.targets).

The wrapper also exports `PortableBuild=true` and records it, in addition to the root command-line property. Component adapters launch separate build processes; the root `/p:PortableBuild=true` alone did not reach the runtime adapter during the observed attempt. The runtime adapter requests system Brotli whenever its evaluated `PortableBuild` is not `true`. Exporting the property carries the portable policy through those processes and keeps the runtime on its bundled Brotli sources, which are appropriate for the Xenial target sysroot. Do not add a newer distribution's Brotli library to the sysroot to work around a missing portability setting. [Tagged runtime adapter](https://github.com/dotnet/dotnet/blob/v9.0.123/src/runtime/eng/DotNetBuild.props).

The root `--ci` flag selects the upstream `ContinuousIntegrationBuild=true` behavior while execution remains in the local WSL/Podman environment. The VMR forwards this mode to component scripts. ASP.NET Core's npm Build target runs `--update-versions` only in this mode; that upstream script enumerates packages and writes `packagesToPack.json` and `renames.json`, which the subsequent Pack target requires. The flag enables this normal generation sequence without synthesizing those files or disabling npm packages. It is independent of hosting the build on GitHub Actions. [Tagged component flag forwarding](https://github.com/dotnet/dotnet/blob/v9.0.123/repo-projects/Directory.Build.props), [tagged npm targets](https://github.com/dotnet/dotnet/blob/v9.0.123/src/aspnetcore/eng/Npm.Workspace.nodeproj).

The profile sets a maximum CPU count of two. The script selects up to two CPUs from the process's allowed affinity set, applies `taskset`, and also sets the .NET and MSBuild parallelism limits. The observed command selected CPUs `0,1`:

```bash
taskset --cpu-list 0,1 ./build.sh \
  --configuration Release --rid linux-arm64 \
  --ci --clean-while-building --binaryLog \
  /p:TargetArchitecture=arm64 /p:TargetOS=linux \
  /p:CrossBuild=true /p:PortableBuild=true /m:2
```

This is the recorded command shape; the Bash wrapper selects the actual affinity list. Native components can call `nproc` independently of MSBuild, which is why `/m:2` alone is insufficient to express the intended limit. The .NET 9 entry point uses `--rid` and MSBuild properties rather than the .NET 10 wrapper's root `--arch`/`--os` interface. It preserves upstream versioning instead of introducing a new official build stamp. The final incremental attempt, `build-20261029T1647214393954Z`, completed successfully in 8 minutes 29 seconds after retaining previously completed component outputs.

An intended GLIBC ceiling of `2.23`, a portable RID, or a successful sysroot preparation does not establish the resulting SDK's ABI. That must be checked after an archive exists.

The observed failed attempts are preserved separately:

| Attempt | Elapsed time | Failure and correction |
| --- | --- | --- |
| First full invocation | 29m 24s | Runtime NativeAOT `cdacreader` could not find `ld.lld`; the image now supplies the unversioned linker name. |
| Second invocation | 2m 08s | NativeAOT's fallback GCC rejected `--gcc-toolchain`; the wrapper now explicitly selects Clang. |
| Third invocation | 2m 10s | CoreCLR CMake requested system Brotli absent from Xenial; the wrapper now exports the portable property. |
| Fourth invocation | 33m 17s | Runtime completed in 27m 26s and EF Core in 1m 59s; ASP.NET Core failed after 3m 29s when npm Pack could not find `packagesToPack.json`. The wrapper now passes `--ci` so the preceding Build target generates its manifests. |

Each failed attempt retains its logs, exit status, resource reports, and snapshots of component logs before retrying. These corrections leave the pinned VMR sources unchanged; the successful final attempt is recorded separately above. The CI mode was enabled after reaching ASP.NET Core, and the incremental retry retains outputs from previously completed components. This run does not establish that those earlier outputs were rebuilt with the final flags or that a clean rebuild would produce identical bytes.

When retrying after a CMake configuration change, inspect the affected `CMakeCache.txt` first. Removing the erroneous command-line argument does not clear a cached `CLR_CMAKE_USE_SYSTEM_BROTLI=true` value. Preserve the failed attempt and move only its affected generated native object directory to a separate location within the dedicated workspace, after verifying the absolute source and destination paths. The observed third attempt's stale configuration was preserved under `<Linux HOME>/cbodotnet/net9/failed-native-obj/build-20261029T1606568891663Z` before the next invocation. Let the corrected build regenerate that object directory; retain source, sysroot, dependency caches, and unrelated component outputs. The wrapper does not perform this quarantine automatically.

## 5. Prepare the test baseline and run upstream tests afterward

For this ordinary VMR profile (`sourceOnly=false`), the upstream test scope is `UnifiedBuild.Tests` and `scenario-tests`. It is not the full-source `SmokeTests` path. .NET 9 also uses a separate BinaryToolKit CLI for source binary scanning; the .NET 10 common-test task injection mechanism does not apply to this tag. Run that scan separately as described below.

### Official SDK comparison baseline

[fetch-test-sdk.py](../scripts/fetch-test-sdk.py) selects the official SDK matching the profile's exact SDK version and RID from Microsoft's release metadata. It downloads the archive over HTTPS and verifies its SHA-512 against that metadata, or verifies an existing copy. It records the archive URL, bytes, SHA-512, metadata URL, and metadata SHA-256 in `official-sdk-baseline.json`.

Inside an ARM64 build container with the same `/inputs` and `/project` mounts, the acquisition command is:

```bash
python3 /project/scripts/fetch-test-sdk.py \
  --profile /project/profiles/dotnet-9.0.123-linux-arm64.json \
  --inputs-dir /inputs \
  --reports-dir /project/artifacts/9.0.123-linux-arm64/reports/test-inputs
```

The selected archive is `/inputs/official-sdk/dotnet-sdk-9.0.123-linux-arm64.tar.gz` in the container, corresponding to `<Linux HOME>/cbodotnet/net9/inputs/official-sdk/dotnet-sdk-9.0.123-linux-arm64.tar.gz` in WSL. An acquisition record with `sha512Verified=true` has been produced for this input. This is the official comparison SDK, not the community build output or the `9.0.121` bootstrap SDK. Fetching it does not establish build or test success.

### Run tests with the matching baseline

Test mode requires an existing official SDK archive and supplies it through the upstream property `/p:UBTestsMsftSdkArchivePath=/inputs/official-sdk/dotnet-sdk-9.0.123-linux-arm64.tar.gz`. The default path matches the acquisition step above. Fetch and verify this input before testing; the harness checks that the file exists but does not replace the downloader's SHA-512 verification.

Once the community build has actually finished successfully, invoke:

```powershell
./scripts/Invoke-Net9Build.ps1 -Mode Test
```

If the verified baseline is stored elsewhere within a mounted container path, pass `-OfficialSdkArchivePath '/absolute/container/path/sdk.tar.gz'`. This parameter uses the container path, not the corresponding Windows or WSL host path.

Test mode invokes the same pinned VMR entry point with `--test` and preserves a separate test attempt directory. The observed `test-20261029T1702000484091Z` invocation exited with code `0` and an MSBuild elapsed time of 6m 59.40s. All 500 `UnifiedBuild.Tests` passed. The scenario result reports 34 discovered tests: 32 passed, zero errors, zero failures, and two explicit skips (`VerifyWorkloadCmd` and `VerifyAspireTemplate`), with a scenario duration of 334.8305 seconds. Platform-filtered tests excluded before discovery are outside those totals. These tests do not replace extracting and testing the final community SDK archive.

The default upstream `UBTestsWarnOnContentDiffs=true` remains in effect. SDK comparisons inspect normalized archive paths and managed assembly identity versions, and differences covered by this setting can be warnings. These results do not establish identical file hashes or identical IL. Package comparisons and scenario execution have their own assertions and exclusions; preserve the TRX, scenario XML, difference reports, and logs when describing the result.

### Separate source binary scan

[scan-clean-source9.sh](../scripts/scan-clean-source9.sh) runs the pinned tag's standalone [BinaryToolKit CLI](https://github.com/dotnet/dotnet/blob/v9.0.123/eng/tools/BinaryToolKit/Program.cs) in `validate` mode. The target must be a separate, pristine checkout of `9f04b57d1366e21b3178648493d6edffeff2216e`. The tool enumerates filesystem contents without applying Git ignore rules, so scanning the warm build checkout would also inspect generated outputs and caches. Keep the clean checkout unchanged and mount it read-only at `/clean9`.

Run this command in the prepared ARM64 container, with the existing build checkout at `/vmr`, clean checkout at `/clean9`, project at `/project`, and the same build user's home/cache mount. The report parent must exist, while the selected report directory must not already exist. The example uses a new retry directory to preserve the first diagnostic run:

```bash
bash /project/scripts/scan-clean-source9.sh \
  --source-dir /vmr \
  --clean-source-dir /clean9 \
  --reports-dir /project/artifacts/9.0.123-linux-arm64/reports/source-binaries-retry1
```

The script invokes the bootstrap SDK `9.0.121` from the build checkout to build and execute the pinned scanner. It sets both the invoking directory and the application's `RunWorkingDirectory` to the clean target:

```bash
cd /clean9
/vmr/.dotnet/dotnet run \
  --project /vmr/eng/tools/BinaryToolKit -c Release \
  --property RunWorkingDirectory=/clean9 -- \
  validate /clean9 \
  -o /project/artifacts/9.0.123-linux-arm64/reports/source-binaries-retry1 \
  -ab /clean9/eng/allowed-vmr-binaries.txt -l Debug
```

It requires both checkouts to use the pinned commit, verifies that the scanner and allowlists match that source, rejects ignored or untracked files in the scan target, and records clean-state checks and allowlist hashes before and after the scan. `status.json` and `scan.log` record the actual result. The upstream validator creates `NewBinaries.txt` only when unexpected binaries are found; its absence together with a successful exit and integrity checks is the expected clean result. Any generated `Updatedallowed-*.txt` files remain review outputs and do not replace the checked-in allowlists. Never use BinaryToolKit's `clean` mode for this validation.

The first actual scan, preserved under `reports/source-binaries`, failed with 1,871 reported binary files while the target checkout and allowlists remained unchanged. This included `.git` objects, images, signing keys, and other files covered by the existing allowlists. The wrapper had executed from `/vmr` while scanning `/clean9`. In this tag's `Microsoft.Extensions.FileSystemGlobbing` 8.0.0, in-memory candidate paths are resolved against process CWD; the mismatched directory prevented the relative allowlist patterns from matching. The wrapper now executes from `/clean9` explicitly. The original failure remains preserved; no allowlist entries or scanner assertions were changed to hide it. [Tagged scanner](https://github.com/dotnet/dotnet/blob/v9.0.123/eng/tools/BinaryToolKit/DetectBinaries.cs), [globbing path normalization](https://github.com/dotnet/runtime/blob/v8.0.0/src/libraries/Microsoft.Extensions.FileSystemGlobbing/src/InMemoryDirectoryInfo.cs).

The corrected scan completed successfully on 2026-10-30 (Asia/Seoul), with its evidence preserved under `reports/source-binaries-retry1`. The command, tool, and log pipeline exited with code `0`; both source revisions matched the pinned commit; the target remained pristine before and after; and all four recorded allowlist hashes remained unchanged. `NewBinaries.txt` was absent as expected for zero unexpected binaries. This is a successful source inventory check, not an SDK build, package-content comparison, or SDK execution result.

Both scan attempts emitted restore warning `NU1603`: the infrastructure project requested `System.CommandLine` `2.0.0-beta4.24126.1`, and the configured feeds resolved `2.0.0-beta4.25121.105` instead. The warning is retained in `scan.log`. The scanner source and allowlists remained pinned, while this infrastructure dependency was resolved to an available later prerelease package; the scan result does not establish exact dependency-version reproduction.

## 6. Preserve and inspect reports

Reports are written to the project directory, separate from source and inputs:

```text
artifacts/9.0.123-linux-arm64/reports/
  derived-image.json
  wsl-environment.json
  build-environment.json
  test-inputs/
    official-sdk-baseline.json
  sysroot/
    sysroot-prepare-<UTC timestamp>-<process ID>.log
    sysroot-files.sha256
    sysroot-file-list.sha256
    sysroot-symlinks.tsv
    sysroot-packages.tsv
    sysroot-provenance.json
  runs/
    build-<UTC timestamp>/
      build-command.txt
      build-resources.txt
      build.log
      build-status.json
    test-<UTC timestamp>/
      test-command.txt
      test-resources.txt
      test.log
      test-status.json
```

The wrapper prints the selected attempt directory. Every `Build` or `Test` invocation gets a new UTC-stamped directory. The Bash wrapper refuses to overwrite an existing action report. Interrupted or failed attempts remain available; do not delete them to make a retry look clean. The source, sysroot, container home, and rootful Podman storage are preserved between wrapper invocations. The upstream `--clean-while-building` option can remove intermediate build products as part of the build itself.

`derived-image.json` records the inspected image ID, base reference, Containerfile/profile hashes, source commit, and default Linux UID:GID. The environment JSON files are preparation snapshots. These top-level records can be refreshed by later invocations, while the attempt directories and original sysroot provenance preserve their separate evidence.

`sysroot-file-list.sha256` checks the checksum-list file against its recorded digest; `sysroot-files.sha256` inventories the sysroot files. Build and test preparation checks both digests and the complete file/symlink sets with the same `/inputs` and `/reports` mounts. The package inventory and generator/keyring hashes provide additional provenance.

Each completed action writes a status JSON containing start/finish times, exit code, source commit, target RID, `sourceOnly=false`, and CPU count. A missing status file or empty resource report during an active or interrupted attempt is not evidence of success. Inspect the action's log and terminal result as well. GNU time records the invoked command's resource usage; it is not by itself a complete measurement of every concurrent process or the workspace disk peak.

Generated reports, inputs, workspaces, caches, and SDK archives remain local and are excluded from Git. Preserve the per-attempt evidence and the original sysroot reports when retrying with the same prepared workspace.

## 7. Collect and validate the generated SDK

The successful build produced `artifacts/assets/Release/Sdk/9.0.123-servicing.26523.1/dotnet-sdk-9.0.123-linux-arm64.tar.gz` in the VMR checkout. Its flat `artifacts/assets/Release/` copy has identical content. [collect-artifacts.py](../scripts/collect-artifacts.py) checks both candidate locations and copies the archive without repacking it. The profile's explicit construction declaration records the locally rebuilt core runtime and upstream ASP.NET runtime fallback.

From the Windows project root, the collection command is:

```powershell
$distribution = 'Ubuntu-22.04'
$linuxHome = (& wsl.exe --distribution $distribution --exec printenv HOME).Trim()
$linuxProject = (& wsl.exe --distribution $distribution --exec wslpath -a -u (Get-Location).Path).Trim()
$linuxRoot = "$linuxHome/cbodotnet/net9"
$linuxRelease = "$linuxProject/artifacts/9.0.123-linux-arm64"
$imageId = (Get-Content -Raw ./artifacts/9.0.123-linux-arm64/reports/derived-image.json |
    ConvertFrom-Json).imageId

& wsl.exe --distribution $distribution --exec python3 `
    "$linuxProject/scripts/collect-artifacts.py" `
    --source-dir "$linuxRoot/work/dotnet-v9.0.123" `
    --output-dir $linuxRelease --reports-dir "$linuxRelease/reports" `
    --profile "$linuxProject/profiles/dotnet-9.0.123-linux-arm64.json" `
    --build-image-id $imageId --build-revision 1
if ($LASTEXITCODE -ne 0) { throw 'Artifact collection failed.' }
```

The collected files are:

```text
artifacts/9.0.123-linux-arm64/
  cbodotnet-sdk-9.0.123-linux-arm64-build.1.tar.gz
  SHA256SUMS
  SHA512SUMS
  build-manifest.json
  reports/
```

The archive is **189,195,292 bytes**, with SHA-256 `d1f70738b4982e6b0313eb320a5ac7c5f1eae925a5808dbc7504963c35de15ee`. The collector verifies the pinned source commit, records the dirty build worktree and rebuild inputs, and inventories the reports present at collection time. It does not interpret those reports or turn later test results into a success claim. Preserve later reports separately, or deliberately refresh the manifest after all checks finish.

### Native SDK and ABI checks

[verify-sdk.sh](../scripts/verify-sdk.sh) extracts the archive privately, uses an isolated writable home and caches, restores generated smoke applications with no NuGet package sources, and checks SDK identity plus console DLL/apphost execution, RSA SHA-256 signing and verification, random bytes, `fr-FR` formatting, and ASP.NET loopback HTTP. The .NET 9 options must be explicit because the script's default framework is `net10.0`.

The observed Ubuntu 22.04 WSL command used the following options and report directory:

```powershell
$archive = 'cbodotnet-sdk-9.0.123-linux-arm64-build.1.tar.gz'
$options = @('--expected-version', '9.0.123', '--expected-rid', 'linux-arm64',
    '--framework', 'net9.0', '--max-glibc', '2.23')

& wsl.exe --distribution $distribution --exec bash `
    "$linuxProject/scripts/verify-sdk.sh" `
    --archive "$linuxRelease/$archive" `
    --output-dir "$linuxRelease/reports/verify-ubuntu22-retry1" @options
if ($LASTEXITCODE -ne 0) { throw 'Ubuntu 22.04 SDK verification failed.' }
```

Ubuntu 24.04 and Debian 13 used the prepared ARM64 images, with the archive/scripts read-only and each report directory writable:

```powershell
$linuxUid = (& wsl.exe --distribution $distribution --exec id -u).Trim()
$linuxGid = (& wsl.exe --distribution $distribution --exec id -g).Trim()
$verificationImages = [ordered]@{
    ubuntu24 = '01cf05ece807f9454ef617dc1438685602ef994849cd63e3e21152762dfee551'
    debian13 = '1383974698d236a954edfe90d4e701c8d6b30004775973b6cf79cb2182ed9548'
}
foreach ($environment in $verificationImages.Keys) {
    $report = "$linuxRelease/reports/verify-$environment-retry1"
    & wsl.exe --distribution $distribution --exec mkdir -p $report
    if ($LASTEXITCODE -ne 0) { throw 'Cannot create verification report directory.' }
    $podmanArguments = @('podman', '--cgroup-manager=cgroupfs', '--events-backend=file',
        'run', '--rm', '--cgroups=disabled', '--network=host',
        '--user', "${linuxUid}:${linuxGid}",
        '--volume', "${linuxRelease}:/artifacts:ro",
        '--volume', "${linuxProject}/scripts:/scripts:ro",
        '--volume', "${report}:/reports", $verificationImages[$environment],
        'bash', '/scripts/verify-sdk.sh', '--archive', "/artifacts/$archive",
        '--output-dir', '/reports') + $options
    & wsl.exe --distribution $distribution --user root --exec @podmanArguments
    if ($LASTEXITCODE -ne 0) { throw "$environment SDK verification failed." }
}
```

Use a new, empty report directory for each rerun; the verifier refuses to overwrite existing results. The image IDs above identify the actual local images and must exist in Podman storage. Rebuild the Ubuntu image using preparation, or build the existing [Debian verification Containerfile](../containers/verify-debian.Containerfile) on another installation and record its new image ID.

All three final reports (`verify-ubuntu22-retry1`, `verify-ubuntu24-retry1`, and `verify-debian13-retry1`) passed. Each reports SDK `9.0.123`, RID `linux-arm64`, six passed functional checks, and 20 AArch64 ELF files. Maximum required symbol versions are GLIBC `2.17`, GLIBCXX `3.4.21`, and CXXABI `1.3.7`; GLIBC passes the profile's `2.23` ceiling. The initial Debian run exposed an unwritable inherited home; the verifier now sets a private writable home, and the three final runs used that corrected verifier.

These are native ARM64 user-space checks sharing the WSL kernel. Symbol maxima and successful smoke applications do not certify every Linux distribution, dynamically loaded dependency, workload, NativeAOT application, or external NuGet package. The archive remains local and excluded from Git; no binary release or website publication is implied by collection and validation.
