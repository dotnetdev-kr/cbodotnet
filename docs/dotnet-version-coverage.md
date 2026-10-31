# Build-method coverage for legacy .NET Core and .NET 5 onward

All eight selected ARM64 profiles now have qualified source-inclusive CI deliveries. The [CI qualification records](ci-matrix-results.md) identify their hosted and downloaded verification separately from the original local build and source-capability findings below.

Research snapshot: 2026-10-29, Asia/Seoul; local implementation update: 2026-10-31. The source observations and inspected revisions below retain their research date. This document distinguishes source capabilities from locally demonstrated builds. .NET Core 3.0.103, 3.1.426 and .NET 5.0.214, 6.0.136, 7.0.120, 8.0.133, 9.0.123, and 10.0.403 Linux ARM64 SDK archives have been built and validated by this project. Their reports distinguish actual build-completion scope, upstream tests and external dependencies. See [GitHub Actions migration](github-actions-migration.md) for the later runner/workflow design.

**Project direction update, 2026-10-30:** the goal is ongoing community build availability for every .NET major version from .NET 5 onward, regardless of Microsoft's support lifecycle. Establish version-specific environments in local WSL and containers before CI migration. This supersedes earlier recommendations to exclude legacy versions or choose the build scope by Microsoft support status; it does not change the recorded source observations. The completed .NET 5 implementation and later Core 3.x scope expansion are recorded in the 2026-10-31 update below.

**Legacy implementation update, 2026-10-31:** all four requested local legacy targets are complete; details are tracked in [legacy build progress](legacy-build-progress.md). .NET 6.0.136 passed local framework origin, three-user-space verification and 41 upstream tests with one poison-report skip. .NET 5.0.214 passed all 68 upstream cases and controlled three-user-space verification. Core 3.1.426 and Core 3.0.103 passed both framework origins, split native audits, all 52 upstream cases each and three-user-space verification with explicit OpenSSL/ICU inputs. All four unchanged archives, checksums, complete report inventories, current profiles and 185 current build-input records passed final strict delivery audits. Core 3.0's failed full graph, supported incremental recovery and external input generations remain explicit.

**Architecture-floor review, 2026-10-31:** Core 3.0 is the oldest locally validated ARM64 generation, rather than a hard technical minimum. Official Core 2.1 and 2.2 metadata already contains both Linux ARM64 and x64 SDK archives. Their original ARM64 source-build graphs and ASP.NET/tool coverage need separate work; no Core 2.x community build or native x64 result is claimed. See the [architecture/version-floor assessment](architecture-version-floor.md) for primary evidence and acceptance criteria.

## What "the same method" means

The .NET 9/10 profiles combine a regular `dotnet/dotnet` VMR build (`sourceOnly=false`), native ARM64 execution, and a foreign Linux sysroot with `CrossBuild=true` and `PortableBuild=true`. They collect the resulting upstream SDK archive unchanged. Component construction differs: the .NET 10.0.403 4xx profile reuses its pinned upstream shared runtimes, while the .NET 9.0.123 1xx profile rebuilds the core runtime locally and reuses the SDK adapter's upstream ASP.NET Core runtime fallback. Neither profile is a source-only build.

The .NET 8 profile uses the older VMR source-build graph (`sourceOnly=true`), rebuilding both shared frameworks locally. It also uses native ARM64 execution and a signed Xenial sysroot and collects the SDK archive unchanged. Its online bootstrap and package inputs mean that the source-build label alone is not a claim that every binary input was rebuilt from source.

The .NET 7 profile predates that VMR route. It generates a full source-build tree from a separate pinned `dotnet/installer` checkout, then builds both shared frameworks and the SDK locally with LLVM 16. It retains the source archive, generated component revisions, explicit ARM64 bootstrap transformation, signed Xenial sysroot and four compatibility patches. Successful local installer-copy tasks, retained input hashes and final shared-framework comparisons establish the runtime origins; bootstrap and online inputs remain external.

Archive naming, checksums, manifests, ELF inspection, application tests, and release promotion can be shared across versions. Build entry points, source layout, bootstrap inputs, shared runtime acquisition, native toolchain, and ABI policy require version-specific treatment.

## Coverage matrix

| Release | Inspected build path | Relationship to the current profile | Project decision |
| --- | --- | --- | --- |
| .NET Core 1.0, 1.1 and 2.0 | Inspected official release metadata contains no Linux ARM64 SDK entries | No published two-architecture SDK baseline established by these manifests | A separate porting investigation would be needed; absence of download entries does not prove source-level impossibility |
| .NET Core 2.1 | Official SDK 2.1.300 and later ARM64/x64 archives; historical ARM64 implementation | Earliest published stable dual-architecture SDK candidate found; upstream ARM64 improvements were concentrated in 3.0 | Research candidate; no complete local SDK, ASP.NET/tool completeness, native functional or delivery verification claimed |
| .NET Core 2.2 | Direct legacy source-build, using CLI rather than the later CoreSDK adapter | Published ARM64/x64 SDKs exist, but the default ARM graph stops at CoreSetup and disables ASP.NET/runtime tool bundling | Concrete next older research target; independent guarded graph/bootstrap/tooling changes and both native targets must be validated |
| .NET Core 3.0 | Corrected `dotnet/source-build` tag `v3.0.103.1-SDK` | SDK 3.0.103/runtime 3.0.3; direct legacy graph, native compiler/crossgen adaptations and explicit retained inputs | Unchanged 157,285,088-byte SDK collected; local framework/native origins, all 52 upstream cases/156 commands, three-user-space checks and strict final delivery audit passed. Nineteen AArch64 ELF files require at most GLIBC 2.17; OpenSSL 1.1 and Debian ICU 66 remain external. No fresh full-graph success claim. |
| .NET Core 3.1 | Final serviced `dotnet/source-build` commit `ab8b115b5658237ee8916ae3586600b39fb2fd19` | SDK 3.1.426/runtime 3.1.32; split CoreCLR/CoreFX/CoreSetup graph with eleven guarded compatibility changes | Archive, both local framework origins, split native chain and all 52 upstream cases passed. Six native checks passed in three user spaces with explicit OpenSSL 1.1; Debian 13 additionally uses recorded ICU 66. |
| .NET 5 | Final serviced `dotnet/source-build` commit `d414ecb2d997a9b3f38aaaeddace30ca097e546d` | SDK 5.0.214/runtime 5.0.17; direct legacy graph, retained bootstrap and source-acquisition adaptations | SDK archive, local framework origin and all 68 upstream cases verified; six native checks passed in three Linux user spaces with explicit OpenSSL 1.1 dependencies |
| .NET 6 | Legacy `dotnet/installer` v6.0.136 | Separate generated source-build route with LLVM 16, signed Xenial sysroot and four ARM64 bootstrap replacements | ARM64 build, local framework origin, unchanged archive, three-user-space ABI/application checks and upstream smoke passed; x64 and later bands remain unvalidated |
| .NET 7 | Legacy installer and generated source-build tarball | Selected 7.0.120 1xx profile uses LLVM 16, four guarded patches, a Xenial sysroot, and locally built shared frameworks | ARM64 root build, collection, and native SDK/application/ABI checks passed in three Linux user spaces; upstream smoke passed 41 with one skipped using recorded test inputs; x64 and other bands remain unvalidated |
| .NET 8 | VMR Linux source-build orchestration | Selected 8.0.133 1xx profile uses two recorded compatibility patches, a Xenial sysroot, and locally built shared frameworks | ARM64 root build, archive collection, and native SDK/application/ABI checks passed in three Linux user spaces; upstream smoke tests passed 44 with two skipped; x64 and other bands remain unvalidated |
| .NET 9 | VMR source-build, plus historical WIP regular-build code | Selected 9.0.123 1xx regular build uses its own flags, Xenial sysroot, and mixed runtime construction | ARM64 build, archive collection, and native SDK/application/ABI checks passed in three Linux user spaces; x64 and other bands remain unvalidated |
| .NET 10 | Modern VMR regular or source-only modes; source contents vary by SDK band | The exact 10.0.403 ARM64 regular-build profile is demonstrated | Local reference implementation; other bands and x64 need their own environments and validation |
| .NET 11 | Published RC3 VMR, with full 1xx sources | Same broad modern construction model; toolchain and pinned inputs need a new profile | In scope; establish a local prerelease profile with independent build and ABI tests |
| .NET 12 | Observed VMR `main` development snapshot | Alpha source state, not an established public release | In scope as a separate development channel; no release-build claim |

The current VMR README lists Linux source-build for .NET 8/9 and regular builds for .NET 10+ (still labeled WIP in that README). Historical .NET 9 tags also contain WIP regular-build instructions and implementation. Both facts matter: code availability is evidence for an experiment, not proof of present support parity or a successful portable ARM64 build. [Current VMR platform statement](https://github.com/dotnet/dotnet/blob/main/README.md#supported-platforms), [.NET 9 tagged statement](https://github.com/dotnet/dotnet/blob/v9.0.123/README.md#supported-platforms).

## Revisions used for source inspection

| Repository | Revision | Resolved commit |
| --- | --- | --- |
| `dotnet/installer` | `v6.0.136` | `d638663530d923adbe0442604b7a6562127321e9` |
| `dotnet/source-build` | Final .NET 5 branch revision | `d414ecb2d997a9b3f38aaaeddace30ca097e546d` |
| `dotnet/source-build` | Final Core 3.1 branch revision | `ab8b115b5658237ee8916ae3586600b39fb2fd19` |
| `dotnet/source-build` | `v3.0.103.1-SDK` | `40de72d1087a1d05dfd39c87f888a0611ec6c60f` |
| `dotnet/installer` | `v7.0.120` | `25b977658c06fd0217ec0bc0714398bb9d0a7bb0` |
| `dotnet/dotnet` | `v8.0.133` | `7d1bf90885cff22e7da72b27e9848e42fd3cb1ae` |
| `dotnet/dotnet` | `v9.0.123` | `9f04b57d1366e21b3178648493d6edffeff2216e` |
| `dotnet/dotnet` | `v10.0.403` | `5a2162bea6845eabc1fc721624a43568c65db3b1` |
| `dotnet/dotnet` | `v11.0.100-rc.3.26522.148` | `5254d8bcf59917edc1e1abc33bdf2442b77b1c70` |
| `dotnet/dotnet` | Observed `main` snapshot | `d6f5bfd13f6506bf42c904108c1206b01929eae9` |

These are inspected revisions, not a list of the latest downloadable SDKs. A source-build 1xx version is a different selection from the latest SDK in a later feature band.

## .NET 5 and Core 3.x: researched direct legacy construction

These versions use direct source-build repositories rather than the newer installer-generated tree. The final .NET 5 source branch builds SDK 5.0.214/runtime 5.0.17, while 5.0.408 is the latest published SDK across bands. The final Core 3.1 branch supports SDK 3.1.426/runtime 3.1.32. Core 3.0 uses corrected v3.0.103.1-SDK. Version-specific images/profiles pin historical toolchains and bootstrap versions; the guarded Git adapter replaces unavailable Darc clone helpers while retaining upstream metadata and component builds. All three have completed framework origins and SDK tests. Core 3.0 completed a separately recorded Toolset30/CoreSDK31 incremental closure, with 301 feed packages proven and zero moved, followed by its full upstream suite, native matrix and final delivery audit; the exact completion scope remains explicit in the [build report](build-report-3.0.103-arm64.md). [Final .NET 5 source](https://github.com/dotnet/source-build/tree/d414ecb2d997a9b3f38aaaeddace30ca097e546d), [final Core 3.1 source](https://github.com/dotnet/source-build/tree/ab8b115b5658237ee8916ae3586600b39fb2fd19), [corrected Core 3.0 source](https://github.com/dotnet/source-build/tree/v3.0.103.1-SDK).

## .NET 6 and 7: legacy construction

The tagged installer READMEs describe generating a complete source-build tree and then building from that tree. Their ARM64 instructions call for bootstrap preparation:

```bash
# In the selected dotnet/installer checkout:
./build.sh /p:ArcadeBuildTarball=true \
  /p:TarballDir=/absolute/path/outside/installer

# In the generated source tree:
cd /absolute/path/outside/installer
./prep.sh --bootstrap
./build.sh --clean-while-building
```

This is the general historical sequence. The [.NET 6](reproduce-net6-arm64.md) and [.NET 7](reproduce-net7-arm64.md) guides implement their separate pinned ARM64 variants, including ordinary preparation before preserving and transforming bootstrap inputs. The separate .NET 6 archive and native tests are recorded in its [build report](build-report-6.0.136-arm64.md). Historical source-build guidance targets the oldest SDK band, 1xx. The regular installer also accepts architecture/RID options, but it assembles components with prebuilt inputs and does not have the same complete-source construction scope. Its `--linux-portable` option hardcodes `linux-x64` in both inspected versions, so it must not be used as an ARM64 switch. [.NET 6 README](https://github.com/dotnet/installer/blob/v6.0.136/README.md#build-net-from-source-source-build), [.NET 7 README](https://github.com/dotnet/installer/blob/v7.0.120/README.md#build-net-from-source-source-build), [.NET 6 option parser](https://github.com/dotnet/installer/blob/v6.0.136/run-build.sh#L33), [.NET 7 option parser](https://github.com/dotnet/installer/blob/v7.0.120/run-build.sh#L33).

The generated source-build system calculates platform/RID values, but its runtime adapter also supplies `SourceBuildNonPortable=true`. In .NET 7 that flag forces nonportable runtime construction, so the implemented adapter patch honors explicit `PortableBuild=true` while preserving default behavior. A separate ASP.NET patch preserves portability, and native compiler commands and archive inspection verify the Xenial target. The resulting 22 AArch64 ELF files require at most GLIBC `2.17`, below the profile's `2.23` ceiling. Independent .NET 6 validation found the same ABI maxima; its graph needs a single portable runtime pass, while its ASP.NET adapter already respects portability. [.NET 7 platform properties](https://github.com/dotnet/installer/blob/v7.0.120/src/SourceBuild/tarball/content/Directory.Build.props#L17), [.NET 7 runtime adapter](https://github.com/dotnet/installer/blob/v7.0.120/src/SourceBuild/tarball/content/repos/runtime.proj#L21), [.NET 6 runtime adapter](https://github.com/dotnet/installer/blob/v6.0.136/src/SourceBuild/tarball/content/repos/runtime.proj#L9).

The VMR boundary changes the implementation path, not the project's version scope. .NET 6 and .NET 7 now have separately demonstrated local legacy environments. Prefer VMR where it applies, while recording the repository, construction scope, and inputs accurately for each legacy profile.

## .NET 8: VMR with older source-build orchestration

The inspected VMR tag documents `./prep.sh` followed by `./build.sh --clean-while-building --online`. Its script has no modern `-sb`, `--arch`, or `--os` parser; extra MSBuild arguments follow `--`. Inner builds receive source-build properties such as `ArcadeBuildFromSource=true` and `DotNetBuildOffline=true`. Adding a modern `DotNetBuildSourceOnly=false` property does not create the .NET 10 regular-build path. [Tagged README](https://github.com/dotnet/dotnet/blob/v8.0.133/README.md#building), [build entry point](https://github.com/dotnet/dotnet/blob/v8.0.133/build.sh), [inner-build arguments](https://github.com/dotnet/dotnet/blob/v8.0.133/repo-projects/Directory.Build.props#L141).

Native ARM64 platform selection and portable RID calculations exist. Further inspection for the local .NET 8 experiment corrected the earlier interpretation of the runtime adapter's `SourceBuildNonPortable=true`: its functional consumer supplies a host RID only when `TargetRid` is empty. It does not override an explicit `linux-arm64` target or force `PortableBuild=false`. The implemented profile exports `PortableBuild=true`, `CrossBuild=true`, and `ROOTFS_DIR` across nested component processes and supplies the target RID explicitly. Recorded clang commands use the Xenial sysroot. The older source-build graph remains distinct from the demonstrated regular-build/shared-runtime profiles. [.NET 8 platform calculations](https://github.com/dotnet/dotnet/blob/v8.0.133/Directory.Build.props#L17), [runtime adapter](https://github.com/dotnet/dotnet/blob/v8.0.133/repo-projects/runtime.proj#L24), [legacy RID default](https://github.com/dotnet/dotnet/blob/v8.0.133/src/arcade/src/Microsoft.DotNet.Arcade.Sdk/tools/SourceBuild/SourceBuildArcade.targets#L57).

The collected `8.0.133` archive contains locally built `Microsoft.NETCore.App 8.0.33` and `Microsoft.AspNetCore.App 8.0.33`, confirmed by installer local-file input records and byte comparisons. Its 19 ELF files are AArch64 and require at most GLIBC `2.17`, GLIBCXX `3.4.21`, and CXXABI `1.3.7`, passing the profile's GLIBC `2.23` ceiling. SDK identity and six native functional checks passed in Ubuntu 22.04, Ubuntu 24.04, and Debian 13 user spaces sharing the WSL kernel. The [build report](build-report-8.0.133-arm64.md) records compatibility fixes, bootstrap/prebuilt scope, root packaging, and upstream tests; the [reproduction guide](reproduce-net8-arm64.md) provides the separate .NET 8 environment. Other bands and x64 remain unvalidated.

The final upstream source-build smoke invocation exited successfully: 46 discovered tests, 44 passed, two skipped, and zero failures. License scanning and poisoning analysis require separate inputs and were skipped. The strict reusable-artifact commit check passed with the pinned VMR revision supplied through `BUILD_SOURCEVERSION`. Stage 2 was not run.

## .NET 9: a demonstrated version-specific regular build

The inspected tag documents both the default regular build and `-sb` source-build, and its script contains an actual `sourceOnly=false` path. It uses `--rid`/`--target-rid` rather than .NET 10's root `--arch`/`--os` interface. `TargetArchitecture`, `TargetOS`, `CrossBuild`, `PortableBuild`, and `ROOTFS_DIR` are handled in the tagged build properties and adapters. [Tagged build instructions](https://github.com/dotnet/dotnet/blob/v9.0.123/README.md#building), [script](https://github.com/dotnet/dotnet/blob/v9.0.123/build.sh), [platform properties](https://github.com/dotnet/dotnet/blob/v9.0.123/Directory.Build.props#L43), [cross-build handling](https://github.com/dotnet/dotnet/blob/v9.0.123/build.proj#L14).

The inspected 1xx tree includes runtime construction and a different component graph; its SDK adapter also describes a temporary upstream ASP.NET Core fallback for regular builds. The tag pins bootstrap SDK 9.0.121. The completed ARM64 run confirms that the final SDK's core runtime matches the locally published `Microsoft.NETCore.App 9.0.22`, while its `Microsoft.AspNetCore.App 9.0.22` matches the SDK adapter's preserved upstream download. This evidence establishes the selected run's mixed construction, rather than full-source construction or reuse of both shared runtimes. [SDK component graph](https://github.com/dotnet/dotnet/blob/v9.0.123/repo-projects/sdk.proj#L35), [bootstrap SDK](https://github.com/dotnet/dotnet/blob/v9.0.123/global.json).

The [9.0.123 ARM64 profile](../profiles/dotnet-9.0.123-linux-arm64.json) uses native clang 18 and a signature-verified Xenial sysroot. Its ordinary build needs explicit NativeAOT compiler selection, portable settings propagated through component processes, and upstream `--ci` packaging mode. The latter enables npm manifest generation while the build continues locally in WSL/Podman. The final archive passed SDK version/RID, console/apphost, RSA, random bytes, ICU formatting, ASP.NET HTTP, and ELF checks in Ubuntu 22.04, Ubuntu 24.04, and Debian 13 ARM64 user spaces. All 20 ELF files are AArch64; maximum required versions are GLIBC `2.17`, GLIBCXX `3.4.21`, and CXXABI `1.3.7`, within the profile's GLIBC `2.23` ceiling. The user spaces share the WSL kernel, and these results do not certify untested distributions, workloads, or external packages. See the [build report](build-report-9.0.123-arm64.md) and [reproduction procedure](reproduce-net9-arm64.md).

The upstream test invocation exited successfully with 500 UnifiedBuild tests passed and 34 discovered scenarios: 32 passed, two skipped, zero errors or failures. The separate clean-source binary inventory scan passed with unchanged allowlists. The build report records comparison warnings, scope, and exclusions; these outcomes do not establish byte-for-byte equality with Microsoft's SDK.

`9.0.123` was selected as the latest published 1xx SDK with the selected VMR tag, not the latest SDK across all feature bands. The selection snapshot records `9.0.320` as the latest published .NET 9 SDK; no matching VMR tag was found. Other feature bands and Linux x64 need separate build and validation results.

## .NET 10 and later: feature bands are an input boundary

The current `10.0.403` is an SDK 4xx-band servicing version. Its included shared runtime is `10.0.14`. The 1xx source layout produces shared runtime components; later bands contain a reduced tooling layout and consume shared inputs pinned by that exact revision. The current package uses shared SDK package `10.0.114-servicing.26522.126`. Choosing whichever 1xx artifacts happen to be newest is not equivalent. [Current profile](../profiles/dotnet-10.0.403-linux-arm64.json), [pinned upstream inputs](https://github.com/dotnet/dotnet/blob/v10.0.403/eng/Version.Details.props), [feature-band construction guide](https://github.com/dotnet/source-build/blob/main/Documentation/feature-band-source-building.md).

Keep bootstrap SDK/previously source-built inputs separate from redistributable shared components. Source-only later-band builds need matching source-built shared components as well as the correct SDK and PSB inputs. For cross builds, tools match the host architecture while redistributable shared components match the target. These are different profiles from the project's demonstrated regular build.

General source-build summaries still describe a 1xx-only scope, while the detailed feature-band guide documents later-band workflows. Use the selected revision's actual scripts, source layout, and pinned properties to resolve that difference; do not extrapolate a historical summary into a universal prohibition or assume all bands build identically.

The latest published .NET 11 candidate inspected was SDK **11.0.100-rc.3.26522.148**, released 2026-10-25. Its VMR tag contains full 1xx sources. A `release/11.0.2xx` branch also exists with a reduced tooling layout, but branch existence or `rtm` branding does not establish a released SDK. [Official .NET 11 downloads](https://dotnet.microsoft.com/en-us/download/dotnet/11.0), [RC3 source](https://github.com/dotnet/dotnet/tree/v11.0.100-rc.3.26522.148/src), [2xx source layout](https://github.com/dotnet/dotnet/tree/release/11.0.2xx/src).

The inspected VMR `main` snapshot already declares **12.0.100 alpha.1**. This is development-source evidence, not an available .NET 12 GA release or a successful build by this project. Pin release tags for release builds and track `main` only in an explicitly separate development channel. [Pinned .NET 12 version file](https://github.com/dotnet/dotnet/blob/d6f5bfd13f6506bf42c904108c1206b01929eae9/eng/Versions.props).

## Portable ABI and native toolchain

| Release | Official x64/ARM64 glibc baseline in inspected metadata | Baseline source |
| --- | --- | --- |
| .NET 8 | 2.23 | Ubuntu 16.04 |
| .NET 9 | 2.23 | Ubuntu 16.04 |
| .NET 10 | 2.27 | Ubuntu 18.04 |
| .NET 11 | 2.27 | Ubuntu 18.04 |

These are build ABI baselines, not Microsoft support commitments for obsolete distributions. A portable RID alone does not enforce an ABI ceiling. The completed ARM64 reports record a GLIBC symbol maximum of `2.17` for Core 3.0, Core 3.1 and .NET 5-9, and `2.27` for 10.0.403. Core 2.x and native x64 community results remain unmeasured. Symbol requirements do not cover all kernel or dynamically loaded library requirements; the explicit OpenSSL/ICU compatibility inputs for older versions also have their own ABI requirements. [8.0 OS metadata](https://github.com/dotnet/core/blob/main/release-notes/8.0/supported-os.json), [9.0 metadata](https://github.com/dotnet/core/blob/main/release-notes/9.0/supported-os.json), [10.0 metadata](https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.json), [11.0 metadata](https://github.com/dotnet/core/blob/main/release-notes/11.0/supported-os.json).

The .NET 11 ARM64 cross recipe still uses Bionic, but its cross-dependency builder pins LLVM 22.1.8. That recipe is evidence of toolchain evolution, not by itself a universal compiler minimum. The project's clang-18 image therefore needs release-specific review and testing before being reused. Keep the compiler, sysroot, runtime inputs, and ABI checks together in each profile. [.NET 11 ARM64 recipe](https://github.com/dotnet/dotnet-buildtools-prereqs-docker/blob/main/src/azurelinux/3.0/net11.0/cross/arm64/Dockerfile), [LLVM builder](https://github.com/dotnet/dotnet-buildtools-prereqs-docker/blob/main/src/azurelinux/3.0/net11.0/crossdeps-builder/amd64/Dockerfile), [cross-building guidance](https://github.com/dotnet/source-build/blob/main/Documentation/cross-building.md).

## Upstream lifecycle metadata and project coverage

| Release | Microsoft status at the research snapshot | Microsoft end of support |
| --- | --- | --- |
| .NET 5 | Out of support | 2022-05-10 |
| .NET 6 | Out of support | 2024-11-12 |
| .NET 7 | Out of support | 2024-05-14 |
| .NET 8 | Maintenance | 2026-11-10 |
| .NET 9 | Maintenance | 2026-11-10 |
| .NET 10 | Active LTS | 2028-11-14 |
| .NET 11 RC3 | Go-live prerelease | RC3: 2026-11-10; GA end date not established in the inspected policy |

These are upstream lifecycle dates, retained as metadata rather than project inclusion or community build cutoff criteria. Rebuilding binaries does not extend Microsoft's support, and a community build does not imply new upstream security fixes. The inspected policy was updated 2026-10-25. Actual build-method evidence is recorded separately in the completed profiles above. [Official support policy](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core).

The requested local legacy environment/build goal is complete. Core 3.0, Core 3.1 and .NET 5–10 have actual ARM64 build/validation results, and the four newly completed legacy archives passed final collection/delivery audits. .NET 11 prereleases and .NET 12 `main` retain separate prerelease/development identities. Current ARM64 CI qualification is recorded separately in the [CI results](ci-matrix-results.md); publication, native x64 and additional version profiles remain separate work. Microsoft end of support does not remove a major version from this plan.

For any new version, completion means acquiring its pinned public inputs, building on the intended host, collecting the actual archive, and passing native SDK, application, and ABI tests for each advertised architecture. A parser option, source branch, or official download for that architecture does not establish those results for this project's build.
