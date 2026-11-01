# Original local SDK artifact portability review

This document preserves the original local artifact inspection and execution evidence. All eight later CI SDK archives passed six functional checks in each recorded native Linux user space; their source deliveries and exact results are recorded separately in the [CI qualification results](ci-matrix-results.md). The original readelf inspection and WSL observations below are not retroactively presented as CI evidence.

Review date: **2026-10-31**. This review covers the eight collected **Linux ARM64, glibc** SDK archives listed below. It uses their actual `build-manifest.json`, embedded build profiles, ELF ABI tables and successful native verification reports. No SDK was rebuilt or modified for this review. A separate read-only archive inspection rechecked every archive's SHA-256 against its manifest before and after inspecting ELF headers.

**All eight artifacts target generic glibc Linux ARM64 rather than one named distribution. They are not universal Linux binaries.** The same archive bytes ran in the recorded Ubuntu 22.04, Ubuntu 24.04 and Debian 13 user spaces, subject to the dependencies and execution conditions below. Core 3.0, Core 3.1 and .NET 5 needed explicitly supplied legacy OpenSSL libraries; Core 3 on Debian 13 also needed an ICU compatibility prefix. Later native x64 CI artifacts and their measurements are recorded separately in the [x64 results](ci-x64-results.md). This original review does not cover musl artifacts.

## Artifact-level findings

Every manifest records `targetRid=linux-arm64`; every profile declares `libc=glibc` and a portable build. The sysroot is an input to compilation, not a restriction requiring that distribution on the user's machine. The build host and target sysroot are separate: using an Ubuntu build container does not by itself make the output Ubuntu-specific. See the version-specific profiles and reports for the actual exported properties, native tool selection and construction changes.

The ABI values below are the **maximum required symbol versions observed in regular ELF files shipped inside the SDK**. They are not a tested minimum OS specification. All inspected ELF machines are AArch64.

| SDK / included runtime | Build profile | Target sysroot / declared GLIBC ceiling | ELF files | Observed GLIBC / GLIBCXX / CXXABI maxima | Portability verdict |
| --- | --- | --- | ---: | --- | --- |
| [Core 3.0.103 / 3.0.3](build-report-3.0.103-arm64.md) | [Profile](../profiles/dotnet-3.0.103-linux-arm64.json) | Xenial / `2.23` | 19 | `2.17` / `3.4.21` / `1.3.7` | Generic glibc ARM64; the verified execution scope requires the recorded legacy dependencies. |
| [Core 3.1.426 / 3.1.32](build-report-3.1.426-arm64.md) | [Profile](../profiles/dotnet-3.1.426-linux-arm64.json) | Xenial / `2.23` | 19 | `2.17` / `3.4.21` / `1.3.7` | Generic glibc ARM64; legacy dependencies and older RID selection remain relevant. |
| [.NET 5.0.214 / 5.0.17](build-report-5.0.214-arm64.md) | [Profile](../profiles/dotnet-5.0.214-linux-arm64.json) | Xenial / `2.23` | 18 | `2.17` / `3.4.21` / `1.3.7` | Generic glibc ARM64; verified with a separate OpenSSL 1.1 prefix. |
| [.NET 6.0.136 / 6.0.36](build-report-6.0.136-arm64.md) | [Profile](../profiles/dotnet-6.0.136-linux-arm64.json) | Xenial / `2.23` | 22 | `2.17` / `3.4.21` / `1.3.7` | Generic glibc ARM64; passed the three recorded modern user spaces without the legacy compatibility bundles. |
| [.NET 7.0.120 / 7.0.20](build-report-7.0.120-arm64.md) | [Profile](../profiles/dotnet-7.0.120-linux-arm64.json) | Xenial / `2.23` | 22 | `2.17` / `3.4.21` / `1.3.7` | Generic glibc ARM64; passed the three recorded modern user spaces without the legacy compatibility bundles. |
| [.NET 8.0.133 / 8.0.33](build-report-8.0.133-arm64.md) | [Profile](../profiles/dotnet-8.0.133-linux-arm64.json) | Xenial / `2.23` | 19 | `2.17` / `3.4.21` / `1.3.7` | Generic glibc ARM64; passed the recorded environments with the documented container-policy/private-state handling. |
| [.NET 9.0.123 / 9.0.22](build-report-9.0.123-arm64.md) | [Profile](../profiles/dotnet-9.0.123-linux-arm64.json) | Xenial / `2.23` | 20 | `2.17` / `3.4.21` / `1.3.7` | Generic glibc ARM64; passed the three recorded modern user spaces. |
| [.NET 10.0.403 / 10.0.14](build-report-10.0.403-arm64.md) | [Profile](../profiles/dotnet-10.0.403-linux-arm64.json) | Bionic / `2.27` | 24 | `2.27` / `3.4.22` / `1.3.7` | Generic glibc ARM64 with a higher measured ABI requirement; passed the three recorded modern user spaces. |

The .NET 9 ordinary VMR build constructs the core runtime locally and reuses its recorded upstream ASP.NET input. The .NET 10 ordinary build reuses the VMR-pinned portable shared runtime inputs. Those construction differences do not invalidate their measured archive ABI or execution results, but `sourceOnly=false` must not be relabeled as an entirely source-built runtime. Conversely, a legacy `sourceOnly=true` invocation does not establish zero binary inputs or portability by itself. The current .NET 10 recipe is [arm64-net10.Containerfile](../containers/arm64-net10.Containerfile); the original artifact manifests retain their historical input records.

## What the ELF headers establish

The additional inspection used GNU `readelf` 2.38 on private temporary copies of regular ELF members, without executing them. All eight archives had the same observed program-interpreter path, **`/lib/ld-linux-aarch64.so.1`**. The `dotnet` hosts directly require the glibc loader and conventional SONAMEs such as `libc.so.6`, `libstdc++.so.6`, `libgcc_s.so.1`, `libm.so.6`, `libdl.so.2` and `libpthread.so.0`. Recorded RPATH/RUNPATH values were limited to `$ORIGIN` and, for some archives, `$ORIGIN/netcoredeps`; no absolute build-workspace library search path was observed.

This is consistent with relocatable glibc ARM64 bundles, not binaries tied to an Ubuntu directory layout or release name. It does not remove the requirement for a compatible loader and library ABI. The .NET 10 archive really has higher required GLIBC symbols, including in `libcoreclr.so` and `libclrjit.so`, and higher GLIBCXX requirements in shipped host components. It should not inherit the lower `2.17` claim from the older archives.

Other shipped ELF members reference libraries such as zlib, Kerberos/GSSAPI, libcurl in Core 3, and the optional LTTng trace provider's dependencies. A union of `DT_NEEDED` entries is not a claim that every optional component was exercised. OpenSSL and ICU can be loaded dynamically and need not appear in a host's `DT_NEEDED` list. Their absence from that list therefore does not mean the SDK is independent of them. The old readelf emitted debug-format warnings for some .NET 6–8 members; its program/dynamic-header queries completed, and this review makes no debug-information validation claim.

These archives are not `linux-musl-arm64` builds. A musl-only distribution such as Alpine has a different libc/loader target; no Alpine run, glibc compatibility-layer solution or musl repack is established by these results. Microsoft's [RID catalog](https://learn.microsoft.com/en-us/dotnet/core/rid-catalog) distinguishes the glibc Linux and musl targets. Manual installations still require suitable native system dependencies; see the [Linux manual installation dependency guidance](https://learn.microsoft.com/en-us/dotnet/core/install/linux-scripted-manual#dependencies), while using the historical profile's actual dependency versions for older SDKs.

## Archive RID versus runtime-reported RID

The archive RID describes the build target. An older CLI can compute and report a distribution RID at execution time even when its archive is the generic `linux-arm64` artifact. The observed values below came from successful `verification.json` files, not from filename assumptions.

| SDK | Ubuntu 22.04 | Ubuntu 24.04 | Debian 13 |
| --- | --- | --- | --- |
| Core 3.0.103 | `linux-arm64` | `linux-arm64` | `linux-arm64` |
| Core 3.1.426 | `ubuntu.22.04-arm64` | `linux-arm64` | `linux-arm64` |
| .NET 5.0.214 | `linux-arm64` | `linux-arm64` | `linux-arm64` |
| .NET 6.0.136 | `ubuntu.22.04-arm64` | `ubuntu.24.04-arm64` | `linux-arm64` |
| .NET 7.0.120 | `ubuntu.22.04-arm64` | `linux-arm64` | `linux-arm64` |
| .NET 8.0.133 | `linux-arm64` | `linux-arm64` | `linux-arm64` |
| .NET 9.0.123 | `linux-arm64` | `linux-arm64` | `linux-arm64` |
| .NET 10.0.403 | `linux-arm64` | `linux-arm64` | `linux-arm64` |

The older host's RID graph and fallback behavior explain why a generic fallback may also appear on a newer distribution. Neither a distro RID nor a generic fallback alone establishes whether every native package asset resolves correctly. .NET 8 changed host asset selection and the default SDK RID graph toward portable RIDs; see the primary [host behavior change](https://learn.microsoft.com/en-us/dotnet/core/compatibility/deployment/8.0/rid-asset-list) and [SDK RID graph change](https://learn.microsoft.com/en-us/dotnet/core/compatibility/sdk/8.0/rid-graph). Do not reject an otherwise verified older archive merely because its actual reported RID includes `ubuntu`, or treat `linux-arm64` output as a compatibility certificate.

## Execution conditions and system dependencies

**Core 3.0, Core 3.1 and .NET 5:** all three recorded user spaces supplied the separately verified Focal OpenSSL 1.1 libraries and configuration through a read-only compatibility prefix. Those libraries are outside the SDK tarball. The particular supplied `libcrypto` additionally requires GLIBC `2.25`, so the complete verification stack cannot be described as requiring only the SDK's observed `2.17` symbol maximum. These runs do not demonstrate execution on an OpenSSL-3-only installation without the compatibility inputs.

**Core 3.0 and Core 3.1 on Debian 13:** the pinned runtime was built against ICU 55 headers and its original loader searches only through ICU major 75. Debian 13's ICU 76 is outside that range. These runs supplied the exact separate Focal ICU 66 `uc`, `i18n` and data libraries, with `CLR_ICU_VERSION_OVERRIDE=66`, and retained globalization. The ICU compatibility libraries have their own ABI requirements, including GLIBC `2.29` for some members; they are not part of the SDK archive's ABI table. Ubuntu 22.04/24.04 used their recorded system ICU environment instead. The source loader, sysroot-header and compatibility-prefix contracts are retained in the Core 3 reports.

**.NET 6–10:** the successful modern user-space runs did not use those project-supplied legacy OpenSSL/ICU bundles. This establishes operation with the normal dependencies present in those recorded environments, not an installation with no dependencies or a guarantee for every package combination. In particular, the .NET 10 results support the recorded Ubuntu 22.04, Ubuntu 24.04 and Debian 13 environments without the legacy prefixes; they do not prove an untouched minimal OS image will contain every required library.

Container security and writable runtime state also matter. The preserved .NET 8 investigations distinguish an old Podman seccomp policy's `fchmodat2` denial from a Debian named-mutex failure resolved with private native `XDG_RUNTIME_DIR` state. Subsequent old-version container checks retain their explicit narrow policy and private execution state. These are recorded execution conditions, not a requirement to rebuild a different SDK for each distribution. Full diagnostics/LTTng behavior is outside the native smoke matrix.

## What was tested, and what remains open

For Core 3.0/3.1 and .NET 5–9, the successful independent reports record six checks: console DLL execution, console apphost execution, RSA/SHA-256 signing and verification, cryptographic random bytes, ICU-backed French decimal formatting and ASP.NET loopback HTTP. Their restores use isolated caches and no NuGet sources. The older .NET 10 verification schema records successful console/apphost and HTTP smoke work and ELF ABI checks; it has no six-check `functionalChecks` object. This review does not retroactively claim that later verifier's explicit crypto/ICU coverage for .NET 10.

All three original environments share the WSL 2 Linux kernel and ARM64 host. They provide useful distribution **user-space** coverage, not three independent kernels or physical platforms. This original ARM64 review does not establish native x64 results; later native x64 CI evidence is recorded separately. These checks do not certify every glibc distribution, a minimum-kernel version, musl, NativeAOT, workloads, all diagnostics, external native NuGet packages or every optional SDK component. Xenial/Bionic sysroot use is not an execution test on Ubuntu 16.04/18.04.

SDK-host compatibility is also separate from an application's deployment compatibility. Choosing an application RID changes asset selection for that application; it does not change the already-built SDK host's libc or CPU. A published app's runtime, apphost and native package dependencies need their own verification on the target environment, even when the SDK itself runs successfully.

The local evidence is under `artifacts/<SDK>-linux-arm64/`: the root `build-manifest.json` binds the archive hash, and `reports/verify-*/` contains `verification.json`, `abi-summary.json`, `elf-abi.tsv` and smoke output. Those generated artifacts are not committed. Use these exact successful directories:

| SDKs | Ubuntu 22.04 report | Ubuntu 24.04 report | Debian 13 report |
| --- | --- | --- | --- |
| Core 3.0 / Core 3.1 | `verify-ubuntu22` | `verify-ubuntu24` | `verify-debian13-icu66` |
| .NET 5 / 6 / 7 / 8 | `verify-ubuntu22` | `verify-ubuntu24` | `verify-debian13` |
| .NET 9 | `verify-ubuntu22-retry1` | `verify-ubuntu24-retry1` | `verify-debian13-retry1` |
| .NET 10 | `verify-wsl-ubuntu22` | `verify-ubuntu24` | `verify-debian13-retry1` |

Keep failed attempts and compatibility-input receipts alongside those results. The appropriate distribution statement is **“Linux ARM64 (glibc), validated in the recorded environments with the stated dependencies”**. Broader distribution coverage requires corresponding native execution and dependency evidence, not a change to the archive's name.
