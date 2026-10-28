# cbodotnet — .NET SDK builds for Linux

This project builds and validates Linux SDKs from the .NET VMR (`dotnet/dotnet`) and packages them as archives. It provides scripts and build records for .NET 10.0.403 Linux ARM64, with an archive built and validated locally. Linux x64 builds and a download website remain future work.

All repository documentation, code comments, and contributor-facing text are maintained in English.

**A native ARM64 build and portable SDK validation have been completed on Windows ARM64 with WSL 2.** The build uses an explicit sysroot, and the generated ELF files have a maximum glibc requirement of 2.27. The archive, checksums, and manifest are generated under `artifacts/10.0.403-linux-arm64`.

Generated archives, reports, downloaded inputs, and local build workspaces are excluded from Git. After cloning, follow the [reproduction guide](docs/reproduce-arm64.md) to build the archive, or provide an existing archive path to the test launcher. Binary releases are a separate publishing step.

## Documentation

| Document | Contents |
| --- | --- |
| [Technical feasibility and build profiles](docs/feasibility.md) | OpenJDK comparisons, VMR build modes, architecture and compatibility decisions |
| [Local environment and build experiment plan](docs/build-plan.md) | Measurements from this PC, required tools, candidate commands, and success criteria |
| [Automation and distribution design](docs/distribution-design.md) | Build, validation, and publishing for both architectures, artifacts, and a minimal download page |
| [Using the SDK with wslc](docs/test-wslc.md) | Architecture-specific CMD launchers, a persistent workspace, console and web apps, and access from Windows |

## Using the built SDK

On Windows ARM64 with PowerShell 7.3 or later and wslc 3.0.3 or later installed, run this command from the project root:

```powershell
.\scripts\start-wslc-arm64.cmd
```

This opens Bash in `/work` with the SDK from the locally built archive installed. After leaving with `exit`, run the same CMD again to resume work with your files. The Windows x64 launcher is `scripts/start-wslc-x64.cmd`; its x64 archive has not been built yet. See the [wslc guide](docs/test-wslc.md) for archive, name, and port options and instructions for running web apps.

## Current implementation

**10.0.403, the latest .NET 10.0.4xx version at the time of selection,** was built as a portable `linux-arm64` SDK on ARM64. It passed console, apphost, and ASP.NET HTTP checks in ARM64 user spaces on Ubuntu 22.04, Ubuntu 24.04, and Debian 13. The project includes the [build report](docs/build-report-10.0.403-arm64.md), [pinned profile](profiles/dotnet-10.0.403-linux-arm64.json), [build script](scripts/build-vmr.sh), and [verification script](scripts/verify-sdk.sh).

The complete commands are documented in the [ARM64 build reproduction guide](docs/reproduce-arm64.md).

The build uses the official Ubuntu 24.04 ARM64 image and an ARM64 Bionic sysroot. This is a regular VMR build: it builds SDK components from the VMR and reuses the upstream portable shared runtime inputs specified by the 4xx tag. It is distinct from a source-only build that also rebuilds the entire runtime.

## Initial feasibility review

- Review date: **2026-10-28**, Asia/Seoul.
- .NET 10 review baseline: `v10.0.114`, VMR commit `0427b9abbead3fa64c6655eb4290c537397131fa`. This is the fixed baseline used for the review, not a value to hardcode as the latest release in future automation.
- Completed during the review: official documentation and tagged build script inspection, read-only host and WSL inspection, and design documentation.
- Planned next steps at that point: native ARM64 build experiment → sysroot builds for both targets on an x64 runner → native validation → automation and distribution implementation.

This section records the initial documentation phase. The build report tracks the scope and results of the subsequent implementation. The website has not been published.

The requested [JDK 27 distribution page](https://jdk.java.net/27/) is the reference for a minimal download page. The research tools received HTTP 403 and could not inspect its contents. Build profile analysis used the [official JDK 27 GA profiles](https://github.com/openjdk/jdk/blob/jdk-27-ga/make/conf/jib-profiles.js) and the [.NET 10 VMR](https://github.com/dotnet/dotnet/tree/v10.0.114).
