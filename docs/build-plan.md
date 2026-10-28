# Local environment and .NET 10 build experiment plan

Review date: 2026-10-28. The commands below were candidates for a later implementation phase and were not executed during the initial review.

This document preserves that initial review. For the .NET 10.0.403 ARM64 portable build and verification subsequently completed at the user's request, see the [build report](build-report-10.0.403-arm64.md). Use the [reproduction procedure](reproduce-arm64.md) for the current build commands.

## 1. Initial inspection of this PC

| Item | Observation | Implication |
| --- | --- | --- |
| Windows/process architecture | ARM64 / ARM64 | Distinguish Windows x64 emulation from the Linux CPU environment |
| Host resources | About 31.6 GiB physical RAM, 12 logical CPUs | Candidate for one ARM64 build experiment |
| WSL | 2.7.13.0; Ubuntu-22.04 uses WSL 2 | Experiments can start in the existing Ubuntu distribution |
| Linux | Ubuntu 22.04.5 LTS, `uname -m=aarch64`, glibc 2.35 | Native ARM64 source-build environment |
| WSL resources | About 15 GiB RAM, 4 GiB swap, 12 CPUs | Measure actual peaks and suitable parallelism during the build |
| Free Windows disk space | About 114 GiB on C: and 433-434 GiB on D: | Allow for caches, images, and logs |
| WSL root filesystem | About 1 TB virtual capacity; `df` reports about 955 GiB free | This differs from the host's physical free space |
| WSL VHD location | Under `AppData\Local\wsl` in the user profile on C: | Growth of the root filesystem consumes space on C: |
| Installed tools found | Git 2.34.1 series, Python 3.10 series | Some basic tools were already available |
| Dependencies not found | clang, CMake, gcc, and OpenSSL/ICU/Brotli/zlib development packages | Build dependencies needed installation |
| Windows Docker | Client present; server connection returned permission denied | A usable Linux engine was not confirmed |
| `wslc` | Not found on PATH or in common installation locations | It was not assumed to be an available build tool |

Memory and disk figures reflect the inspection time. Package inspection used `dpkg-query` and did not collect a complete inventory of installed packages. The Docker connection error alone does not establish that no engine is installed.

## 2. Source location and resource preparation

Keep VMR sources and intermediate build output in WSL's Linux filesystem, for example `~/src/dotnet-v10.0.114`. Keep this documentation project at `D:\Projects\cbodotnet` and copy final artifacts as needed. This follows the official recommendation to use the Linux filesystem when Linux tools operate on large numbers of files. [WSL filesystem guidance](https://learn.microsoft.com/en-us/windows/wsl/interop).

The general source-build guidance specifies about 80 GB for a typical build, about 30 GB with `--clean-while-building`, and a minimum recommended 8 GB of RAM. These are not measurements of this project including all bootstrap inputs, containers, Stage 2 output, and logs. [Source-build resource requirements](https://github.com/dotnet/source-build/blob/main/Documentation/system-requirements.md).

The inspected WSL memory allocation was sufficient to begin the first experiment. With 114 GiB free on C:, a single experiment using cleanup could be considered. For ongoing builds, the recommendation was a separate WSL distribution with adequate space on D:, or a VHD moved using supported management tools. **Even when the VHD resides on D:, keep build paths inside the Linux filesystem.** Do not interpret the 955 GiB reported by `df` as physical free space. [WSL virtual disks](https://learn.microsoft.com/en-us/windows/wsl/disk-space).

An initial runner budget of 24-32 GB RAM and about 200 GB or more of SSD workspace was proposed. This is an estimate allowing for caches, symbols, and Stage 2, rather than an official minimum. Adjust it using the first experiment's peak RSS, peak disk use, and elapsed time. On this PC, start with the existing 15 GiB WSL allocation and, if needed, check Windows memory availability before increasing the WSL limit. Changes to `.wslconfig` affect other WSL distributions too and require a restart. [WSL resource settings](https://learn.microsoft.com/en-us/windows/wsl/wsl-config).

No VHD relocation, memory setting changes, or WSL shutdown were performed during the initial review.

## 3. Candidate dependencies for a direct Ubuntu build

The following is a starting point combining the runtime dependencies in the pinned tag with VMR's Brotli dependency and smoke-test tools. It is not a final package list guaranteed to build the entire VMR. Validate the ordinary native SDK profile first, then reassess tool requirements when adding WASM or other profiles. [Linux requirements at the same tag](https://github.com/dotnet/dotnet/blob/v10.0.114/src/runtime/docs/workflow/requirements/linux-requirements.md), [VMR README](https://github.com/dotnet/dotnet/blob/v10.0.114/README.md), [smoke-test tools](https://github.com/dotnet/dotnet/blob/v10.0.114/test/Microsoft.DotNet.SourceBuild.Tests/README.md).

```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential clang cmake cpio curl git \
  libicu-dev liblttng-ust-dev libssl-dev libkrb5-dev \
  lld lldb llvm ninja-build pigz python-is-python3 \
  libbrotli-dev zlib1g-dev elfutils file
```

CMake 3.20 or later is required. After installation, record `clang --version`, `cmake --version`, `ldd --version`, and package versions. The same runtime documentation requires Clang 16 or later for WASM, so Ubuntu's default clang must not be assumed sufficient for every profile. Use the VMR's bootstrap script rather than installing an arbitrary latest SDK. The reviewed tag's `global.json` specifies bootstrap SDK `10.0.112`. [global.json](https://github.com/dotnet/dotnet/blob/v10.0.114/global.json).

Official prerequisite containers are an alternative to installing dependencies directly. Select an image after checking its execution architecture, required tools, digest, and Linux volume configuration. The presence of the Windows Docker client alone does not mean the container path is ready.

## 4. First native ARM64 experiment

The following candidate commands are intended for **Bash inside Ubuntu-22.04**. Use separate checkouts and artifact paths for each profile.

```bash
set -euo pipefail
mkdir -p ~/src
git clone --depth 1 --branch v10.0.114 \
  https://github.com/dotnet/dotnet.git ~/src/dotnet-v10.0.114
cd ~/src/dotnet-v10.0.114

test "$(git rev-parse HEAD)" = \
  "0427b9abbead3fa64c6655eb4290c537397131fa"

./build.sh --help
./prep-source-build.sh
./build.sh -sb --configuration Release \
  --arch arm64 --os linux \
  --clean-while-building --binaryLog

./build.sh -sb --test
```

The options were confirmed in the [tagged build.sh](https://github.com/dotnet/dotnet/blob/v10.0.114/build.sh) and [test README](https://github.com/dotnet/dotnet/blob/v10.0.114/test/Microsoft.DotNet.SourceBuild.Tests/README.md). Also check `--help` in the selected checkout before execution.

The expected default output of this experiment is `ubuntu.22.04-arm64`. Since `prep-source-build.sh` adjusts bootstrap inputs for the host, do not specify an unverified PSB archive RID merely because the host is ARM64. If downloads fail or require private inputs, investigate the relevant URLs, input versions, and public alternatives. [Preparation implementation](https://github.com/dotnet/dotnet/blob/v10.0.114/prep-source-build.sh).

Look for the SDK archive under `artifacts/assets/Release/Sdk/` first. Source-build may also create compatibility copies, so avoid distributing the same file twice. Confirm versions, RIDs, and hashes from the actual artifact inventory instead of hardcoding example versions from the README into filenames. [PublishSourceBuild.props](https://github.com/dotnet/dotnet/blob/v10.0.114/eng/PublishSourceBuild.props).

## 5. Sysroot build experiments for public distribution

The following are candidates to validate on a **separate x64 Linux runner**. Resolve container digests from OCI manifests; do not use the tags below alone to pin public builds.

| SDK target | Reference image tag | `ROOTFS_DIR` |
| --- | --- | --- |
| `linux-x64` | `azurelinux-3.0-net10.0-cross-amd64` | `/crossrootfs/x64` |
| `linux-arm64` | `azurelinux-3.0-net10.0-cross-arm64` | `/crossrootfs/arm64` |

The image repository is `mcr.microsoft.com/dotnet-buildtools/prereqs`. [Image declarations at the pinned tag](https://github.com/dotnet/dotnet/blob/v10.0.114/eng/pipelines/templates/variables/vmr-build.yml#L179).

Verify the source SHA and prepare bootstrap inputs inside each profile's container before evaluating these build commands. For ARM64:

```bash
export ROOTFS_DIR=/crossrootfs/arm64
./prep-source-build.sh
./build.sh -sb --configuration Release \
  --arch arm64 --os linux \
  --clean-while-building --binaryLog \
  /p:CrossBuild=true /p:PortableBuild=true
```

For the x64 profile, change the rootfs to `/crossrootfs/x64` and `--arch` to `x64`. `CrossBuild=true` is required even when the CPU architecture is unchanged if an external sysroot is used. Set `PortableBuild=true` explicitly to override the default source-only RID calculation for a build on the same CPU architecture. Both properties exist in the implementation, but **completion and ABI compatibility of this source-only combination were unverified in the initial review**. If source-only support blocks the experiment, compare the standard VMR build with the same inputs to narrow down the failure, and record any changes in prebuilt inputs. [Cross-building instructions](https://github.com/dotnet/source-build/blob/main/Documentation/cross-building.md), [tagged RID properties](https://github.com/dotnet/dotnet/blob/v10.0.114/eng/RuntimeIdentifier.props).

Do not assume these x64-host images can run in WSL on Windows ARM64. Test an ARM64 SDK built on an x64 runner on actual ARM64 Linux or WSL.

## 6. SDK validation and success criteria

After the VMR build succeeds, extract the SDK into a clean directory and inspect it using its absolute path. Isolate `DOTNET_ROOT`, PATH, the NuGet cache, and the working directory so another installed `dotnet` cannot mask the result. The minimum checks are:

1. Verify archive integrity, SDK/runtime/target RID, ELF CPU architecture, and dynamic dependencies.
2. Save `dotnet --info`, `--list-sdks`, and `--list-runtimes` output.
3. Restore, build, run, and publish a new `net10.0` console project, then execute the produced application.
4. Build and publish an ASP.NET Core project, then verify its response with an actual HTTP request.
5. Run upstream source-build smoke tests and record failures and reasons for skipped tests.
6. For public profiles, validate any additional features declared supported, such as ReadyToRun and NativeAOT, on each target CPU.
7. Establish the minimum ABI using ELF versioned symbols and tests on supported operating systems.

Distinguish tests that use network restores from tests using only local packages. Passing upstream smoke tests does not establish support for every OS or workload. Some native Linux tests require `eu-readelf` and `file`. [Test README](https://github.com/dotnet/dotnet/blob/v10.0.114/test/Microsoft.DotNet.SourceBuild.Tests/README.md).

For Stage 2, rebuild the same SHA in a fresh working directory using the Stage 1 SDK, `Private.SourceBuilt.Artifacts.*.tar.gz`, and other required inputs. Use the tagged `--with-sdk` and `--with-packages` options and the official procedure; retain shared-component inputs for bands that require them. Validate a network-isolated rebuild separately after acquiring all necessary inputs. Measure Stage 2 success and byte-for-byte equality separately. [Stage 2 procedure](https://github.com/dotnet/source-build/blob/main/Documentation/how-to-stage2-build.md).

For cross-builds, **distinguish the CPU architecture of the SDK executed during the build from that of the SDK being distributed**. On an x64 runner, bootstrap inputs supplied through `--with-sdk` and `--with-packages` must match the x64 host. Inputs supplied through `--with-shared-components` must match the target CPU. Do not directly reuse an ARM64 SDK produced on x64 as the bootstrap SDK on that same x64 host. Plan separate checks: a cross-build using separately acquired x64 bootstrap inputs, and a native rebuild on an ARM64 host using the produced SDK. [Cross-Build Input Architectures](https://github.com/dotnet/source-build/blob/main/Documentation/feature-band-source-building.md#cross-build-input-architectures).

| Stage | Pass criteria | Evidence to retain |
| --- | --- | --- |
| Local ARM64 PoC | Native archive, SDK execution, upstream tests | SHA, commands, tool versions, binlog, resource use |
| Public-profile PoC | Both RIDs produced, ABI inspected, tests on each CPU | Image digests, sysroot identifiers, test results |
| Rebuild | Stage 2 succeeds from the same source | Bootstrap/PSB hashes, build and comparison results |
| Start of automation | Repeatable success for both targets using the same manifest | Retry policy, resource and time budgets |

## 7. Evaluating wslc

The official documentation states that `wslc.exe` is included with WSL **2.9.3 or later**. No usable installation path was found with the installed 2.7.13 version. If needed, update WSL and validate support with `wslc version` and a test container. No update was performed during the initial review. [Official getting-started instructions](https://learn.microsoft.com/en-us/windows/wsl/tutorials/wsl-containers).

wslc is an option for managing the container execution environment. Differences between host and target CPUs, sysroots, and bootstrap inputs still require separate solutions. Compare it with the Docker approach after checking the execution CPU, volumes, and resource settings of the actual VMR image. The official documentation also states that `.wslconfig` settings do not apply to wslc containers, so configure container resources separately. [WSL configuration guidance](https://learn.microsoft.com/en-us/windows/wsl/wsl-config).
