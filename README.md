# cbodotnet — .NET SDK builds for Linux

This project aims to keep building and providing community Linux SDK binaries for **every .NET major version from .NET 5 onward, plus .NET Core 3.0 and 3.1**, independently of Microsoft's support lifecycle. It uses the .NET VMR (`dotnet/dotnet`) where applicable and version-specific legacy build paths where needed. The intended architectures are Linux ARM64 and x64; inclusion in that scope does not mean a working build is already available.

The current portable target is **glibc Linux**, with release-specific system-library requirements. `linux-arm64` describes the package target; a distro-specific RID printed by an older SDK describes its detected host. Neither proves compatibility with every Linux system or musl/Alpine. The [Linux portability review](docs/linux-portability-review.md) separates the target, measured ABI, native execution results and required OpenSSL/ICU inputs.

All repository documentation, code comments, and contributor-facing text are maintained in English.

The [legacy build progress](docs/legacy-build-progress.md) records the ongoing .NET 6, .NET 5, .NET Core 3.1 and .NET Core 3.0 ARM64 work. Source selection and prepared containers are distinguished from completed SDK builds.

**Project direction, 2026-10-30, expanded 2026-10-31:** establish and validate the environment for each version in local WSL and containers before migrating the build profiles to CI. Microsoft end-of-support dates remain descriptive metadata, not criteria for excluding a version or ending community build availability. Version-specific legacy research and implementation stages are recorded in the progress guide; a researched route is distinct from a completed SDK build.

The [.NET 10 CI guide](docs/ci-net10.md) describes the manual native ARM64 GitHub Actions pipeline, fresh source/input snapshots, upstream and three-user-space validation, and optional unpublished draft delivery. A [complete hosted run](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41191037279) passed every build and validation gate; its downloaded artifact also passed independent local verification. Other versions and native x64 retain their independent migration work.

The [version-specific CI matrix](docs/ci-matrix.md) extends source-inclusive build and validation to the other ARM64 profiles. Fresh hosted qualification is tracked separately from implementation and historical local builds. Native x64 remains a separate target.

**Native ARM64 builds and SDK validation have been completed for .NET Core 3.0.103, 3.1.426 and .NET 5.0.214, 6.0.136, 7.0.120, 8.0.133, 9.0.123, and 10.0.403 on Windows ARM64 with WSL 2.** Each version has its own container and sysroot profile. Archives, checksums, manifests and validation reports are generated under `artifacts/<version>-linux-arm64`. The .NET 5/Core 3.x modern-distribution tests use explicit OpenSSL 1.1 inputs; Core 3.x on Debian 13 additionally uses recorded ICU 66. Core 3.0's supported incremental completion and separate failed/full/targeted evidence remain explicit. Final strict delivery audits passed for all four newly completed legacy targets.

Generated archives, reports, downloaded inputs, and local build workspaces are excluded from Git. After cloning, follow the [.NET Core 3.0](docs/reproduce-core30-arm64.md), [.NET Core 3.1](docs/reproduce-core31-arm64.md), [.NET 5](docs/reproduce-net5-arm64.md), [.NET 6](docs/reproduce-net6-arm64.md), [.NET 7](docs/reproduce-net7-arm64.md), [.NET 8](docs/reproduce-net8-arm64.md), [.NET 9](docs/reproduce-net9-arm64.md), or [.NET 10](docs/reproduce-arm64.md) reproduction guide. Each guide records its actual completed gates. Existing archives can be selected by the test launcher when its user space supplies the version's required dependencies. Binary releases are a separate publishing step.

Existing release manifests retain their historical collection inputs. The .NET 10 recipe was subsequently renamed to `containers/arm64-net10.Containerfile` with identical contents; the launcher now uses that path. Previous delivery audits describe their recorded input snapshots, while a future build or CI run must collect its own current orchestration inputs and manifest.

## Documentation

| Document | Contents |
| --- | --- |
| [Technical feasibility and build profiles](docs/feasibility.md) | OpenJDK comparisons, VMR build modes, architecture and compatibility decisions |
| [Local environment and build experiment plan](docs/build-plan.md) | Measurements from this PC, required tools, candidate commands, and success criteria |
| [Automation and distribution design](docs/distribution-design.md) | Build, validation, and publishing for both architectures, artifacts, and a minimal download page |
| [Using the SDK with wslc](docs/test-wslc.md) | Architecture-specific CMD launchers, a persistent workspace, console and web apps, and access from Windows |
| [.NET Core 3.0 ARM64 build report](docs/build-report-3.0.103-arm64.md) | Actual incremental SDK completion, split native producers, retained bootstrap/reference/template inputs and remaining validation |
| [.NET Core 3.0 ARM64 reproduction](docs/reproduce-core30-arm64.md) | Corrected source tag, native Bionic toolchain, signed sysroot, guarded source adaptations and validation procedure |
| [.NET Core 3.1 ARM64 build report](docs/build-report-3.1.426-arm64.md) | Split runtime construction, completed local copies, all 52 upstream cases, ABI and explicit OpenSSL/ICU inputs |
| [.NET Core 3.1 ARM64 reproduction](docs/reproduce-core31-arm64.md) | Direct source-build, retained inputs, signed sysroot, guarded legacy fixes, collection and verification |
| [.NET 5 ARM64 build report](docs/build-report-5.0.214-arm64.md) | Direct source-build, local framework origin, full upstream suite, XML recovery and explicit OpenSSL dependencies |
| [.NET 5 ARM64 reproduction](docs/reproduce-net5-arm64.md) | Isolated Focal toolchain, signed sysroot, retained bootstrap, cache recovery, build and verification |
| [.NET 6 ARM64 build report](docs/build-report-6.0.136-arm64.md) | Generated source-build, local runtime and ASP.NET origin, four patches, archive identity, tests and ABI |
| [.NET 6 ARM64 reproduction](docs/reproduce-net6-arm64.md) | Separate bootstrap and signed sysroot, single portable runtime graph, build, collection and verification |
| [.NET 7 ARM64 build report](docs/build-report-7.0.120-arm64.md) | Generated installer source-build, local shared runtimes, four compatibility patches, archive identity, and validation |
| [.NET 7 ARM64 reproduction](docs/reproduce-net7-arm64.md) | Dedicated WSL environment, source generation, ARM64 bootstrap, signed sysroot, build, collection, and tests |
| [.NET 8 ARM64 build report](docs/build-report-8.0.133-arm64.md) | Legacy VMR source-build, local shared runtimes, compatibility fixes, archive identity, and validation |
| [.NET 8 ARM64 reproduction](docs/reproduce-net8-arm64.md) | Separate bootstrap inputs, native container, signed Xenial sysroot, build, collection, and tests |
| [.NET 9 ARM64 build report](docs/build-report-9.0.123-arm64.md) | Actual build, mixed runtime construction, archive identity, tests, ABI results, and limitations |
| [.NET 9 ARM64 reproduction](docs/reproduce-net9-arm64.md) | Isolated WSL/container workspace, signed Xenial sysroot, build corrections, collection, and verification |
| [GitHub Actions migration assessment](docs/github-actions-migration.md) | Later CI migration after local version-specific environments are established, runner capacity, and required changes |
| [.NET 10 CI operation](docs/ci-net10.md) | Manual native ARM64 build, actual evidence gates, runner configuration, artifacts and optional draft delivery |
| [.NET version coverage](docs/dotnet-version-coverage.md) | Completed Core 3.x/.NET 5+ profiles, researched older and future build paths, and remaining environment work |
| [Linux ARM64/x64 version floor](docs/architecture-version-floor.md) | Core 2.1/2.2 SDK evidence, the Core 3.0 support transition, and the separate requirements for a verified two-architecture community release |
| [Linux portability review](docs/linux-portability-review.md) | Actual artifact targets, host RID detection, ELF dependencies, native verification and generic glibc Linux limitations |

## Using the built SDK

On Windows ARM64 with PowerShell 7.3 or later and wslc 3.0.3 or later installed, run this command from the project root:

```powershell
.\scripts\start-wslc-arm64.cmd
```

This opens Bash in `/work` with the SDK from the locally built archive installed. After leaving with `exit`, run the same CMD again to resume work with your files. The Windows x64 launcher is `scripts/start-wslc-x64.cmd`; its x64 archive has not been built yet. See the [wslc guide](docs/test-wslc.md) for archive, name, and port options and instructions for running web apps.

The launcher defaults to the .NET 10 archive. Select the collected .NET 9 archive with a separate container name:

```powershell
.\scripts\start-wslc-arm64.cmd `
  -ArchivePath '.\artifacts\9.0.123-linux-arm64\cbodotnet-sdk-9.0.123-linux-arm64-build.1.tar.gz' `
  -Name cbodotnet-sdk9-test-arm64 -Port 5001
```

The recorded .NET 9 validation used WSL and Podman user spaces; the command above selects that archive for a wslc session.

Select the collected .NET 8 archive in the same way:

```powershell
.\scripts\start-wslc-arm64.cmd `
  -ArchivePath '.\artifacts\8.0.133-linux-arm64\cbodotnet-sdk-8.0.133-linux-arm64-build.1.tar.gz' `
  -Name cbodotnet-sdk8-test-arm64 -Port 5002
```

Select the collected .NET 7 archive with another workspace:

```powershell
.\scripts\start-wslc-arm64.cmd `
  -ArchivePath '.\artifacts\7.0.120-linux-arm64\cbodotnet-sdk-7.0.120-linux-arm64-build.1.tar.gz' `
  -Name cbodotnet-sdk7-test-arm64 -Port 5003
```

The recorded .NET 7 validation used WSL and Podman; this example selects its archive for a wslc session.

## Current implementation

**3.0.103 with runtime/ASP.NET 3.0.3** was collected unchanged as a 157,285,088-byte native ARM64 SDK. All 188 runtime/134 ASP.NET entries and the 180-payload native chain passed their origin audits. The complete upstream suite passed **52 cases and 156 commands, with two certificate setups and zero exclusions**. Six native functional checks passed in Ubuntu 22.04, Ubuntu 24.04 and Debian 13 with explicit OpenSSL 1.1 inputs; Debian additionally used recorded ICU 66. Its 19 AArch64 ELF files require at most GLIBC `2.17`, GLIBCXX `3.4.21` and CXXABI `1.3.7`. Copy evidence spans the earlier failed runtime-copy invocation and final successful ASP.NET-copy invocation. Supported targeted adapters reuse verified dependencies with distinct statuses/manifests preserved. The strict final delivery audit passed. The [build report](docs/build-report-3.0.103-arm64.md) discloses historical generations and external ABI requirements; a fresh clean full build is not claimed.

**3.1.426, the final published .NET Core 3.1 SDK,** was built with local runtime and ASP.NET 3.1.32. The complete 52-case upstream suite passed. Both shared frameworks match their local producer archives and completed CoreSDK copies; a separate 180-member audit traces CoreCLR/CoreFX/CoreSetup native outputs and actual native-image generation. Six native functional checks passed in Ubuntu 22.04, Ubuntu 24.04 and Debian 13. Its 19 AArch64 ELF files require at most GLIBC `2.17`, GLIBCXX `3.4.21` and CXXABI `1.3.7`. All three user spaces used explicit OpenSSL 1.1 inputs; Debian 13 additionally used exact Focal ICU 66 with globalization enabled. These external libraries remain outside the unchanged SDK. See the [build report](docs/build-report-3.1.426-arm64.md) for dependencies, preserved failures and nonzero prebuilt findings.

**5.0.214, the final SDK band represented by the serviced .NET 5 source-build branch,** was built with local runtime and ASP.NET 5.0.17. All 68 upstream smoke cases passed, and six native functional checks passed in each of Ubuntu 22.04, Ubuntu 24.04 and Debian 13 using explicit, byte-recorded OpenSSL 1.1 compatibility inputs. Its 18 AArch64 ELF files require at most GLIBC `2.17`, GLIBCXX `3.4.21` and CXXABI `1.3.7`. Crypto requires the supported legacy OpenSSL ABI; the [build report](docs/build-report-5.0.214-arm64.md) records that dependency, local framework provenance and all bootstrap inputs. SDK 5.0.408 is the latest published SDK across bands.

**6.0.136, the latest published .NET 6 1xx SDK,** was built with local runtime and ASP.NET 6.0.36. The unchanged archive passed six functional checks in Ubuntu 22.04, Ubuntu 24.04 and Debian 13 ARM64 user spaces. Its 22 ELF files require at most GLIBC `2.17`, GLIBCXX `3.4.21` and CXXABI `1.3.7`. Upstream smoke tests passed 41, with one poison-report test skipped. The [build report](docs/build-report-6.0.136-arm64.md) records the source generation, four ARM64 bootstrap replacements, single portable runtime graph and completed local installer-copy proof. SDK 6.0.428 is the latest published SDK across bands; bootstrap and online inputs remain part of this build.

**7.0.120, the latest published .NET 7 1xx SDK,** was built for `linux-arm64` using the pinned `dotnet/installer` source-build generator, native clang 16, and a signed Xenial sysroot. It predates the VMR build route. Its archive passed SDK identity, console/apphost, RSA, random bytes, ICU formatting, and ASP.NET HTTP checks in Ubuntu 22.04, Ubuntu 24.04, and Debian 13 ARM64 user spaces. Its 22 ELF files are AArch64, with maximum required versions GLIBC `2.17`, GLIBCXX `3.4.21`, and CXXABI `1.3.7`. See the [build report](docs/build-report-7.0.120-arm64.md), [profile](profiles/dotnet-7.0.120-linux-arm64.json), and [reproduction guide](docs/reproduce-net7-arm64.md).

Both shared frameworks, `Microsoft.NETCore.App 7.0.20` and `Microsoft.AspNetCore.App 7.0.20`, match local runtime archives. Successful installer copy tasks and retained download hashes establish the local inputs. Four guarded patches preserve ARM64 host-tool detection, runtime/ASP.NET portability, and valid source-derived IdentityModel file-version metadata. The build uses upstream bootstrap and online package inputs; it does not establish zero-prebuilt construction. `7.0.410` is the latest published .NET 7 SDK across feature bands.

The .NET 7 upstream smoke invocation passed 41 tests with one poisoning-input test skipped and no failures. It used an explicitly pinned compatible OmniSharp fixture with a recorded launcher symlink and an exact-version official SDK layout baseline in warning mode. Stage 2 was not run.

**8.0.133, the latest published .NET 8 1xx SDK with a matching VMR tag at selection,** was built for `linux-arm64` using the legacy VMR source-build graph, native clang 18, and a signed Xenial sysroot. The collected archive passed SDK identity, console/apphost, RSA, random bytes, ICU formatting, and ASP.NET HTTP checks in Ubuntu 22.04, Ubuntu 24.04, and Debian 13 ARM64 user spaces. Its 19 ELF files are AArch64, with maximum required versions GLIBC `2.17`, GLIBCXX `3.4.21`, and CXXABI `1.3.7`. See the [build report](docs/build-report-8.0.133-arm64.md), [profile](profiles/dotnet-8.0.133-linux-arm64.json), and [reproduction guide](docs/reproduce-net8-arm64.md) for the final build/test status and limitations.

Both `Microsoft.NETCore.App 8.0.33` and `Microsoft.AspNetCore.App 8.0.33` match the locally built runtime archives; installer binlog records confirm local file inputs. This build still consumes the upstream bootstrap SDK, transformed previously source-built artifacts, reference packages, and online package inputs. Two recorded compatibility patches preserve ARM64 host-tool detection and the portable ASP.NET target. `8.0.133` is a 1xx selection; `8.0.427` was the latest published SDK across .NET 8 feature bands at selection.

The .NET 8 upstream smoke invocation passed 44 tests with two skipped and no failures. The skips require separate license-scan and poisoning-analysis inputs. The strict source-artifact commit check passed after supplying the official build-revision environment input; Stage 2 was not run.

**9.0.123, the latest published .NET 9 1xx SDK with the selected VMR tag,** was built as a portable `linux-arm64` SDK using native ARM64 clang 18 and a signed Xenial sysroot. It passed SDK identity, console/apphost, RSA signing, random bytes, ICU formatting, and ASP.NET HTTP checks on Ubuntu 22.04, Ubuntu 24.04, and Debian 13 ARM64 user spaces. Its 20 ELF files are AArch64, with maximum required versions GLIBC `2.17`, GLIBCXX `3.4.21`, and CXXABI `1.3.7`; the GLIBC result passes the profile's `2.23` ceiling. These checks do not certify complete OS compatibility. See the [build report](docs/build-report-9.0.123-arm64.md), [profile](profiles/dotnet-9.0.123-linux-arm64.json), and [reproduction guide](docs/reproduce-net9-arm64.md).

This ordinary VMR build rebuilds `Microsoft.NETCore.App 9.0.22` locally and includes the upstream `Microsoft.AspNetCore.App 9.0.22` through the tag's SDK fallback. It also consumes upstream bootstrap and package inputs. `9.0.123` is a 1xx selection; the selection snapshot records `9.0.320` as the newest SDK across .NET 9 feature bands.

The .NET 9 upstream test invocation passed 500 UnifiedBuild tests and 32 scenarios, with two scenarios skipped. The separate clean-source binary scan also passed. The build report describes the comparison policy and test exclusions.

**10.0.403, the latest .NET 10.0.4xx version at the time of selection,** was built as a portable `linux-arm64` SDK on ARM64. It passed console, apphost, and ASP.NET HTTP checks in ARM64 user spaces on Ubuntu 22.04, Ubuntu 24.04, and Debian 13. The project includes the [build report](docs/build-report-10.0.403-arm64.md), [pinned profile](profiles/dotnet-10.0.403-linux-arm64.json), [build script](scripts/build-vmr.sh), and [verification script](scripts/verify-sdk.sh).

The complete commands are documented in the [ARM64 build reproduction guide](docs/reproduce-arm64.md).

The build uses the official Ubuntu 24.04 ARM64 image and an ARM64 Bionic sysroot. This is a regular VMR build: it builds SDK components from the VMR and reuses the upstream portable shared runtime inputs specified by the 4xx tag. It is distinct from a source-only build that also rebuilds the entire runtime.

Other majors need their own source, bootstrap, toolchain, sysroot, and validation profiles. Linux x64 builds and a download website also remain future work.

## Initial feasibility review

- Review date: **2026-10-28**, Asia/Seoul.
- .NET 10 review baseline: `v10.0.114`, VMR commit `0427b9abbead3fa64c6655eb4290c537397131fa`. This is the fixed baseline used for the review, not a value to hardcode as the latest release in future automation.
- Completed during the review: official documentation and tagged build script inspection, read-only host and WSL inspection, and design documentation.
- Planned next steps at that point: native ARM64 build experiment → sysroot builds for both targets on an x64 runner → native validation → automation and distribution implementation.

This section records the initial documentation phase. The build report tracks the scope and results of the subsequent implementation. The website has not been published.

The requested [JDK 27 distribution page](https://jdk.java.net/27/) is the reference for a minimal download page. The research tools received HTTP 403 and could not inspect its contents. Build profile analysis used the [official JDK 27 GA profiles](https://github.com/openjdk/jdk/blob/jdk-27-ga/make/conf/jib-profiles.js) and the [.NET 10 VMR](https://github.com/dotnet/dotnet/tree/v10.0.114).
