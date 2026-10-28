# Technical feasibility of distributing .NET SDK binaries for Linux

Review date: 2026-10-28. In this document, **confirmed** means verified through official sources or local inspection, **recommendation** means a proposed project design, and **unverified** means something that still requires an actual build experiment.

Subsequent validation: following the user's choice of the 4xx band, a standard .NET 10.0.403 VMR build was completed on an ARM64 host with a Bionic sysroot. The resulting SDK reuses portable shared runtimes and passed a glibc 2.27 ABI ceiling check and execution checks in three Linux user-space environments. The sections below preserve the initial review; see the [build report](build-report-10.0.403-arm64.md) for actual results.

## 1. Assessment and recommended path

**The project is technically feasible.** The .NET VMR provides the source and infrastructure needed to build the complete SDK, and source-build officially supports ARM64 and x64. The existing WSL environment runs Linux ARM64 and is suitable for an initial native ARM64 experiment. [VMR README](https://github.com/dotnet/dotnet/blob/v10.0.114/README.md), [source-build requirements](https://github.com/dotnet/source-build/blob/main/Documentation/system-requirements.md).

The initial recommended sequence was:

1. Complete a VMR source-build and SDK tests on the local Ubuntu 22.04 ARM64 environment.
2. Add an x64 Linux build runner and produce `linux-x64` and `linux-arm64` artifacts using the upstream .NET 10 sysroot profiles as references.
3. Run the SDK and applications on each target CPU to establish the support scope that can be published.
4. Implement automation with the same inputs and a download page containing two platform rows.

This assessment does not mean that the current PC can build both architectures natively. Building the complete SDK from ARM64 to x64, and using emulation, remain separate experiments. Separate native builders for each architecture are also an option, but portable binaries require the same ABI policy on both runners.

## 2. Initial product scope

| Item | Recommended scope |
| --- | --- |
| Source | `dotnet/dotnet` VMR, with a release tag and commit SHA pinned for each release |
| Version | .NET 10; SDK `10.0.1xx` for the first experiment that builds all components from source |
| Targets | `linux-arm64` and `linux-x64` for glibc Linux |
| Display names | AArch64 (ARM64), x64 (x86-64) |
| Format | A complete SDK `.tar.gz`, SHA-256, and source/build information |
| Initial use cases | C# CLI, ordinary console and ASP.NET Core development and execution |
| Additional validation | NativeAOT, ReadyToRun, diagnostics/profiling, and external NuGet packages/tools |
| Later scope | Alpine/musl, ARM32, Windows/macOS, installer packages, and mobile/WASM workloads |

The intended simplification concerns the download page and the number of supported platforms. It does not involve deleting SDK directories such as `packs`, `templates`, `sdk`, or `shared`, or removing license files to reduce size. Workloads, tools, and packages installed separately from the SDK need their own acquisition paths and compatibility checks.

## 3. Build policies to borrow from OpenJDK

JDK 27 GA's `jib-profiles.js` declares the target OS/CPU, devkit, build devkit, and Boot JDK for Linux x64 and AArch64. Its default build targets include product, test, and static-library bundles, with debug symbols handled as separate artifacts. [JDK 27 GA profiles](https://github.com/openjdk/jdk/blob/jdk-27-ga/make/conf/jib-profiles.js).

| OpenJDK reference | Policy for this .NET project |
| --- | --- |
| `linux-x64` and `linux-aarch64` profiles | Declare target RID, host CPU, sysroot, and tool versions in build profiles |
| Pinned Boot JDK and devkit | Pin the bootstrap SDK, PSB packages, and container digest |
| Default `release` build | Use VMR `--configuration Release` and a CoreCLR-based SDK |
| Product bundle | Validate and distribute the SDK `.tar.gz` produced by the VMR |
| Separate symbol and test bundles | Store the user SDK, symbols, test results, and logs separately |
| Distinct host and target tools | Distinguish tools executed during the build from binaries distributed for the target |

OpenJDK's default JVM variant is server and its default debug level is release. Names such as `fastdebug`, `slowdebug`, and `optimized` describe HotSpot build configurations and should not be mapped directly to .NET options. In particular, `optimized` is a release variant with additional debug code. [JDK build instructions](https://github.com/openjdk/jdk/blob/jdk-27-ga/doc/building.md), [HotSpot configuration](https://github.com/openjdk/jdk/blob/jdk-27-ga/make/autoconf/hotspot.m4).

## 4. Choosing a VMR build mode

| Mode | Characteristics | Role proposed in the initial review |
| --- | --- | --- |
| Standard VMR build | Starts with `./build.sh`; upstream calls this a Microsoft-based build, which may use prebuilt dependencies | Compare functionality and upstream configurations |
| Source-only/source-build | Runs `./prep-source-build.sh`, then `./build.sh -sb`; intended for distribution maintainers rebuilding from source | Preferred initial candidate for the first PoC and public builds |
| Source-only with a sysroot | Adds a target sysroot and portable-build policy to source-build | Candidate for portable glibc Linux distribution; actual build success must be established |

`-sb` sets `DotNetBuildSourceOnly=true`. The preparation script downloads a bootstrap SDK and previously source-built (PSB) packages, so the initial build requires binary inputs and network access. Record and retain those inputs, then validate a Stage 2 build in a fresh directory using the SDK and PSB packages from Stage 1. [Tagged build.sh](https://github.com/dotnet/dotnet/blob/v10.0.114/build.sh), [prep-source-build.sh](https://github.com/dotnet/dotnet/blob/v10.0.114/prep-source-build.sh), [Stage 2 instructions](https://github.com/dotnet/source-build/blob/main/Documentation/how-to-stage2-build.md).

Bootstrap SDKs and packages for a cross-build must be executable on the build host. An ARM64 SDK output cannot directly serve as the bootstrap SDK on an x64 host; host and target inputs must be selected separately. See the Stage 2 section in the [build experiment plan](build-plan.md).

Source-only builds use different optimization inputs from the official SDK. Native PGO packages and some ReadyToRun MIBC inputs are restricted, so a successful `Release` build does not establish identical performance or bytes compared with official binaries. This does not mean that all runtime dynamic PGO is absent. [nativepgo.targets](https://github.com/dotnet/dotnet/blob/v10.0.114/src/runtime/eng/nativepgo.targets), [codeOptimization.targets](https://github.com/dotnet/dotnet/blob/v10.0.114/src/runtime/eng/codeOptimization.targets).

## 5. Feasibility by platform

| Build host to SDK target | Assessment | Evidence and conditions |
| --- | --- | --- |
| WSL Ubuntu ARM64 to Ubuntu ARM64 | Recommended first experiment | Native Linux build on a supported CPU; tools must be installed and an actual build completed |
| Linux x64 to Linux x64 with a pinned sysroot | Recommended public-build candidate | The upstream .NET 10 pipeline includes this configuration |
| Linux x64 to Linux ARM64 with a pinned sysroot | Recommended public-build candidate | The upstream pipeline includes this configuration; native ARM64 testing is separate |
| Linux ARM64 to Linux x64 | Unverified | The `--arch x64` option alone does not establish support for building the complete SDK in this direction |
| Emulating an x64 container on ARM64 | Supplementary experiment | CPU translation, image execution, performance, and complete build success require separate validation |
| Windows ARM64 directly to a Linux SDK | Outside the initial approach | Perform Linux builds in WSL or on a Linux runner |

The upstream .NET 10 pipeline includes x64 and ARM64 sysroot builds on an x64 Linux pool. The `azurelinux-3.0-net10.0-cross-amd64` and `...cross-arm64` images are useful references, but `cross-arm64` describes the target and must not be assumed to run on an ARM64 host. Verify each profile's OCI execution architecture and digest. [Pipeline](https://github.com/dotnet/dotnet/blob/v10.0.114/eng/pipelines/templates/stages/vmr-verticals.yml#L443), [image variables](https://github.com/dotnet/dotnet/blob/v10.0.114/eng/pipelines/templates/variables/vmr-build.yml#L179), [cross ARM64 Dockerfile](https://github.com/dotnet/dotnet-buildtools-prereqs-docker/blob/main/src/azurelinux/3.0/net10.0/cross/arm64/Dockerfile).

The existence of that pipeline does not establish that an independent source-only profile has already been validated on this PC. Use both the pipeline's standard build configurations and the source-only cross-build instructions when designing the experiment. [Official cross-building instructions](https://github.com/dotnet/source-build/blob/main/Documentation/cross-building.md).

## 6. Linux compatibility boundaries

The tagged `eng/RuntimeIdentifier.props` defaults native source-only builds to `PortableBuild=false`. On this PC, the expected default output for that experiment is an `ubuntu.22.04-arm64` SDK. Confirm the actual filename and RID from the build output. [RID calculation](https://github.com/dotnet/dotnet/blob/v10.0.114/eng/RuntimeIdentifier.props).

Setting `--rid linux-arm64` or `/p:PortableBuild=true`, or renaming a file, does not lower its ABI requirements. Whether a binary linked against Ubuntu 22.04's glibc 2.35 runs on an older glibc is a separate question. Public build profiles must pin and document:

- The sysroot, libc family, and actual minimum required `GLIBC_*`, `GLIBCXX_*`, and `CXXABI_*` symbol versions.
- Dynamic dependencies such as OpenSSL, ICU, and zlib, and their required installation packages.
- Supported distributions, versions, and CPUs, and the combinations actually tested.
- Validation coverage for additional features such as NativeAOT and diagnostics.

Under the initial plan, any published result from the first native experiment would be described only as an experimental build produced and validated on Ubuntu 22.04 ARM64. Establish the minimum glibc version of a portable release through sysroot selection and ELF analysis. `linux-*` denotes a glibc target; Alpine's `linux-musl-*` support is a separate scope. [Source-build packaging instructions](https://github.com/dotnet/source-build/blob/main/Documentation/packaging-installation.md), [cross-building instructions](https://github.com/dotnet/source-build/blob/main/Documentation/cross-building.md).

## 7. .NET 10 feature bands and version pinning

The initial review used `v10.0.114` and commit `0427b9abbead3fa64c6655eb4290c537397131fa`. Compare both values when checking out the source. [Official tag ref](https://api.github.com/repos/dotnet/dotnet/git/ref/tags/v10.0.114).

For the first experiment that builds all components from source, the initial recommendation was `10.0.1xx`. Other SDK bands may omit shared component sources, including runtime sources, and consume 1xx outputs instead. When extending the project to 4xx or other bands, follow the shared input versions specified by that revision's `eng/Versions.props` and `eng/Version.Details.props`. [Feature-band source-building instructions](https://github.com/dotnet/source-build/blob/main/Documentation/feature-band-source-building.md), [tagged shared-component condition](https://github.com/dotnet/dotnet/blob/v10.0.114/Directory.Build.props#L62).

Record SDK and runtime versions separately. Do not use moving inputs such as `main`, `release/10.0.1xx`, or a container's `latest` tag as public release identifiers. Links to `main` in this document provide current general guidance; pin the reviewed revision as part of implementation.

## 8. Questions for the experiments to resolve

| Uncertainty | Experiment | Completion criterion |
| --- | --- | --- |
| Completing a local native build | One ARM64 source-build | SDK archive produced and upstream smoke tests passed |
| Acquiring bootstrap inputs | Preparation downloads and input manifest | Input versions, hashes, and reuse paths retained |
| Portable source-only configuration | Both sysroot profiles on an x64 runner | Archives for both targets, with actual RIDs and ELF files inspected |
| Compatibility and functional differences | Execution on target CPUs and distributions | Tests passed for the declared features and operating systems |
| Automation resources | Measure time, peak RAM, and peak disk use | Runner sizing and retention policy based on measurements |
| Ability to rebuild | Stage 2 at the same SHA | Rebuild and tests passed using the produced SDK |

At the end of the initial review, technical assessment was complete, but a successful full build, portable Linux support, performance parity, and byte-for-byte reproducibility had not yet been measured. Subsequent results are recorded in the build report linked above.
