# Reproducing the .NET SDK 10.0.403 build on ARM64

As of 2026-10-28. This document describes the implemented execution procedure. Refer to the [build report](build-report-10.0.403-arm64.md) for actual build and validation status and results. Run the collection and validation commands below after an SDK archive has been generated; the presence of a command here does not imply that it succeeded.

## 1. Pinned build scope

| Item | Value |
| --- | --- |
| SDK / VMR | `10.0.403` / `v10.0.403` |
| VMR commit | `5a2162bea6845eabc1fc721624a43568c65db3b1` |
| Host / target | Native Linux ARM64 / `linux-arm64` |
| Configuration | Standard VMR build, `sourceOnly=false`, `CrossBuild=true`, `PortableBuild=true` |
| Shared inputs | VMR-pinned upstream portable runtime `10.0.14` and shared SDK package `10.0.114-servicing.26522.126` |
| Bootstrap SDK | `10.0.401` |
| Compiler / sysroot | ARM64 clang 18 / ARM64 Bionic, targeting a glibc 2.27 baseline |
| Build parallelism | `DOTNET_PROCESSOR_COUNT=2`, MSBuild `/m:2` |
| Derived image | `localhost/cbodotnet-arm64:10.0.403` |
| Final build image ID | `92f8771e40e362c7417be68f4a257fe58d83c060abfcdd8c86f8f423c2bc245e` |

This profile builds SDK components and reuses the public upstream shared runtime. It does not claim a source-only rebuild that includes the 1xx runtime. Pinned values are in the [profile](../profiles/dotnet-10.0.403-linux-arm64.json), and the image configuration is in the [.NET 10 Containerfile](../containers/arm64-net10.Containerfile). Rebuilding the image may produce a different derived image ID as additional packages change, so use the ID recorded for the actual execution. The versioned filename was introduced after the recorded local build; its recipe contents are unchanged.

## 2. Prepare and build from Windows PowerShell

Open PowerShell 7.3 or later and change to the project directory. An existing `Ubuntu-22.04` WSL distribution is required.

```powershell
Set-Location D:\Projects\cbodotnet
Get-Help ./scripts/Invoke-Arm64Build.ps1 -Full

./scripts/Invoke-Arm64Build.ps1 -Mode Prepare
./scripts/Invoke-Arm64Build.ps1 -Mode Build

# Scan the original source from the same tag, separately from the build cache.
$scan = ./scripts/Invoke-CleanSourceScan.ps1
./scripts/Invoke-Arm64Build.ps1 -Mode Test -BinariesReportFile $scan.ContainerReportFile
```

Run each mode separately and check the preceding step's result. `Test` invokes the standard VMR test entry point; separate SDK archive validation is also required. Use `-Distribution` to select another WSL distribution or `-LinuxWorkspaceRoot` to change the Linux workspace. The current wrapper and Bash scripts jointly enforce this pinned version; update the related files together when selecting a different version.

The [source scan wrapper](../scripts/Invoke-CleanSourceScan.ps1) uses a separate pristine checkout of the same commit and its original allowlist. The `NewBinaries.txt` produced by the actual upstream `BinaryToolTask` must be empty for the check to pass. The scan covers the original binary set in the pinned tag. Text feed adjustments and automatic tool configuration changes made during the actual build are preserved separately in `vmr-working-tree.patch`. If new source patches or binaries are added to this profile, design a source scan procedure that also covers those changes. Separating the scan input addresses the upstream scanner's detection of NuGet caches in a warm checkout as source binaries.

NuGet XML documentation is needed for SDK IntelliSense and assembly, so do not use `NUGET_XMLDOC_MODE=skip`. The final build script unsets that variable. If an earlier cache already omitted XML files, the [recovery tool](../scripts/restore-package-xml.py) verifies the existing nupkg SHA-512 values and CRCs and restores only missing XML files. A newly prepared final image does not need this recovery step.

The [PowerShell wrapper](../scripts/Invoke-Arm64Build.ps1):

- Queries the default WSL user's `HOME`, UID, and GID without hardcoding a username.
- Installs host tools such as Podman and Git as root in `Prepare`, clones the source only when absent, and verifies the commit SHA.
- Uses rootful Podman storage. Engine commands run as WSL `root`, while container processes run with the default Linux user's UID:GID.
- Checks the base image digest and ARM64 architecture, then builds the derived image. Records the actual image ID and Containerfile/profile hashes in `reports/derived-image.json`.
- Generates the sysroot with signature verification when absent. For an existing sysroot, verifies the checksum list itself, every file hash, and the file/symlink inventories. Does not automatically delete incomplete or different inputs.
- Validates prepared inputs in `Build` and `Test`, adjusts feeds, and runs [build-vmr.sh](../scripts/build-vmr.sh).

Default Linux paths and container mounts:

| WSL path | Container path |
| --- | --- |
| `<Linux HOME>/cbodotnet/work/dotnet-v10.0.403` | `/vmr` |
| `<Linux HOME>/cbodotnet/inputs` | `/inputs` |
| `<Linux HOME>/cbodotnet/container-home` | `/home/build` |
| This project's WSL path | `/project` |

The Podman engine uses `--cgroup-manager=cgroupfs --events-backend=file`; running containers use `--cgroups=disabled --network=host`. Separate cgroup memory limits, which failed in this WSL environment, are not applied. The Bash wrapper limits build parallelism. This procedure does not change Windows/WSL memory settings or the VHD location.

## 3. Feed adjustments and retries

[configure-feeds.py](../scripts/configure-feeds.py) changes the `dotnet-public` feed URI for general public packages to NuGet.org and sets `maxHttpRequestsPerSource=8`. It does not change VMR-pinned package versions. Original and adjusted file hashes, the Git patch, and the list of changed generated configurations are recorded in `reports/feed-adjustments.json` and `.patch`.

The script adjusts source configurations and existing `artifacts/obj/*/NuGet.config` files, then invalidates `artifacts/obj/*/UpdateNuGetConfig.complete` markers on every invocation. This prevents the upstream build from reusing stale generated configurations. For normal retries, use the wrapper's `-Mode Build`.

Microsoft servicing inputs unavailable on NuGet.org have their URLs, versions, and SHA-256 values pinned in the profile's `additionalPackages`. [fetch-pinned-inputs.py](../scripts/fetch-pinned-inputs.py) downloads them in `Prepare` and verifies their hashes, nuspecs, and ZIP contents offline in `Build` and `Test`. The files are exposed through the regular `pinned-microsoft` feed at `/inputs/nuget`. The only package currently pinned this way is `NETStandard.Library.NETFramework/2.0.1-servicing-26011-01`.

To separate the bad initial state from the first two attempts, the root `artifacts/obj` directory was preserved as `artifacts/obj-attempts-1-2`. `--quarantine-build-state` is not a normal retry option and refuses to run if a backup of that name already exists. Do not repeatedly use this option in the current workspace or delete the existing backup to retry. Preserve failure logs separately and confirm that no build is running before restarting.

## 4. Collect the generated SDK archive

[collect-artifacts.py](../scripts/collect-artifacts.py) recursively searches nested directories under `artifacts/assets/Release/Sdk/`. It also checks the root `artifacts/assets/Release/` directory. If multiple archives match the SDK version and RID, it accepts them only when their content hashes are identical. Expect a path such as `artifacts/assets/Release/Sdk/<nested path>/dotnet-sdk-10.0.403-linux-arm64.tar.gz`; do not assume a fixed flat output path.

The following PowerShell example runs the collector with the same mounts as the build. First confirm that `Build` succeeded and the SDK archive exists.

```powershell
$distribution = 'Ubuntu-22.04'
$linuxHome = (& wsl.exe --distribution $distribution --exec printenv HOME).Trim()
$linuxUid = (& wsl.exe --distribution $distribution --exec id -u).Trim()
$linuxGid = (& wsl.exe --distribution $distribution --exec id -g).Trim()
$linuxProject = (& wsl.exe --distribution $distribution --exec wslpath -a -u (Get-Location).Path).Trim()
$linuxRoot = "$linuxHome/cbodotnet"
$linuxRelease = "$linuxProject/artifacts/10.0.403-linux-arm64"
$containerRelease = '/project/artifacts/10.0.403-linux-arm64'
$imageId = (Get-Content -Raw ./artifacts/10.0.403-linux-arm64/reports/derived-image.json |
    ConvertFrom-Json).imageId

$podmanPrefix = @('--distribution', $distribution, '--user', 'root', '--exec',
    'podman', '--cgroup-manager=cgroupfs', '--events-backend=file')
$runArguments = @('run', '--rm', '--cgroups=disabled', '--network=host',
    '--user', "${linuxUid}:${linuxGid}", '--env', 'HOME=/home/build',
    '--volume', "${linuxRoot}/work/dotnet-v10.0.403:/vmr",
    '--volume', "${linuxRoot}/inputs:/inputs",
    '--volume', "${linuxRoot}/container-home:/home/build",
    '--volume', "${linuxProject}:/project", '--workdir', '/vmr')
$collectArguments = @($imageId, 'python3', '/project/scripts/collect-artifacts.py',
    '--source-dir', '/vmr', '--output-dir', $containerRelease,
    '--reports-dir', "$containerRelease/reports",
    '--profile', '/project/profiles/dotnet-10.0.403-linux-arm64.json',
    '--build-image-id', $imageId, '--build-revision', '1')
& wsl.exe @podmanPrefix @runArguments @collectArguments
if ($LASTEXITCODE -ne 0) { throw 'Artifact collection failed.' }
```

The collector copies the SDK archive under the following name without changing its contents. It refuses to replace an existing archive with different contents.

```text
artifacts/10.0.403-linux-arm64/
  cbodotnet-sdk-10.0.403-linux-arm64-build.1.tar.gz
  SHA256SUMS
  SHA512SUMS
  build-manifest.json
  reports/
```

`build-manifest.json` records the source SHA, whether the worktree has changes, the profile, script and Containerfile hashes, the actual image ID, shared inputs, archive hashes, and original archive location. Symbols and deb/rpm packages are listed only as discovered candidates; the collector neither copies them nor verifies that the symbols match the SDK. Successful collection is separate from functional and compatibility test success.

Verify the archive checksums in the preceding PowerShell session:

```powershell
& wsl.exe --distribution $distribution --cd $linuxRelease --exec sha256sum --check SHA256SUMS
if ($LASTEXITCODE -ne 0) { throw 'SHA-256 verification failed.' }
& wsl.exe --distribution $distribution --cd $linuxRelease --exec sha512sum --check SHA512SUMS
if ($LASTEXITCODE -ne 0) { throw 'SHA-512 verification failed.' }
```

## 5. Validate in three ARM64 environments

The validation targets are WSL Ubuntu 22.04, the Ubuntu 24.04 prerequisite container used for the build, and a separate Debian 13 (trixie) container. The Debian validation image uses a [separate Containerfile](../containers/verify-debian.Containerfile) containing only runtime dependencies, Python, readelf, and curl, without an installed SDK. The following commands describe the procedure; consult each report for the actual outcome.

The validation tool extracts the archive into a temporary directory and invokes the SDK by absolute path. It checks console restore/build/publish with isolated NuGet sources and caches, DLL and apphost execution, and a real ASP.NET Core HTTP response. It records the full ELF inventory and GLIBC/GLIBCXX/CXXABI requirements and requires the main `dotnet` executable to be AArch64. If ELF files for other targets are included, distinguish them through the inventory's `elfMachine` column.

These commands use the variables from the preceding PowerShell session. Each report path must be new or an empty directory; use a new suffix when repeating checks.

```powershell
$archiveName = 'cbodotnet-sdk-10.0.403-linux-arm64-build.1.tar.gz'
$verificationFlags = @('--expected-version', '10.0.403', '--expected-rid', 'linux-arm64',
    '--max-glibc', '2.27')

# Run in the current Ubuntu 22.04 WSL distribution.
$wslVerification = @('--distribution', $distribution, '--exec', 'bash',
    "$linuxProject/scripts/verify-sdk.sh", '--archive', "$linuxRelease/$archiveName",
    '--output-dir', "$linuxRelease/reports/verify-wsl-ubuntu22") + $verificationFlags
& wsl.exe @wslVerification
if ($LASTEXITCODE -ne 0) { throw 'Ubuntu 22.04 SDK verification failed.' }

# Run in the Ubuntu 24.04 ARM64 build image.
$ubuntuVerification = @($imageId, 'bash', '/project/scripts/verify-sdk.sh',
    '--archive', "$containerRelease/$archiveName",
    '--output-dir', "$containerRelease/reports/verify-ubuntu24") + $verificationFlags
& wsl.exe @podmanPrefix @runArguments @ubuntuVerification
if ($LASTEXITCODE -ne 0) { throw 'Ubuntu 24.04 SDK verification failed.' }

# Prepare and run the separate Debian 13 ARM64 validation image.
& wsl.exe @podmanPrefix build --network=host --file "$linuxProject/containers/verify-debian.Containerfile" `
    --tag localhost/cbodotnet-verify-debian:13 $linuxProject
if ($LASTEXITCODE -ne 0) { throw 'Debian verification image preparation failed.' }
$debianImageId = (& wsl.exe @podmanPrefix image inspect --format '{{.Id}}' `
    localhost/cbodotnet-verify-debian:13).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Debian image inspection failed.' }
& wsl.exe @podmanPrefix image inspect $debianImageId |
    Set-Content ./artifacts/10.0.403-linux-arm64/reports/verify-debian13-image.json -Encoding utf8NoBOM
$debianVerification = @($debianImageId, 'bash', '/project/scripts/verify-sdk.sh',
    '--archive', "$containerRelease/$archiveName",
    '--output-dir', "$containerRelease/reports/verify-debian13") + $verificationFlags
& wsl.exe @podmanPrefix @runArguments @debianVerification
if ($LASTEXITCODE -ne 0) { throw 'Debian 13 SDK verification failed.' }
```

The Debian validation image ID at preparation time was `1383974698d236a954edfe90d4e701c8d6b30004775973b6cf79cb2182ed9548`. Record the actual ID again if rebuilding it. GLIBC 2.27 is the profile's intended upper bound for required GLIBC symbol versions. ABI inspection alone does not establish support for every Linux distribution with that version or for every workload; report it separately from the actual OS and feature coverage.

Review `status.txt`, `verification.json`, `abi-summary.json`, `elf-abi.tsv`, and console/HTTP logs in each validation directory. Results produced with `--no-smoke` do not count as passing functional tests. After testing, rerun the collector with the same inputs to retain the identical archive while incorporating final report hashes into the manifest.
