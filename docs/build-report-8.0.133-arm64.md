# .NET SDK 8.0.133 Linux ARM64 build report

Status snapshot: **2026-10-30, Asia/Seoul**. The full root build completed successfully for SDK `8.0.133` with both locally built `8.0.33` shared frameworks. The unchanged SDK archive passed native functional and ABI checks on Ubuntu 22.04, Ubuntu 24.04, and Debian 13. The final upstream smoke run completed with **44 passed, zero failed, and two skipped**. Two recorded source compatibility patches were required, along with narrowly scoped container, retry-state, and producer-metadata corrections. These results do not establish an entirely prebuilt-free or byte-equivalent Microsoft SDK.

This work follows the project's direction of providing community builds for .NET 5 and later independently of Microsoft's support lifecycle. It covers one native ARM64 .NET 8 source-build experiment. Other feature bands, releases, and Linux x64 require separate implementation and measured results.

## Selected inputs and construction scope

| Item | Selected value |
| --- | --- |
| SDK / VMR tag | `8.0.133` / `v8.0.133` |
| VMR commit | `7d1bf90885cff22e7da72b27e9848e42fd3cb1ae` |
| Latest published .NET 8 SDK recorded during selection | `8.0.427`, released 2026-10-25 |
| Intended shared runtime version | `8.0.33` |
| Bootstrap SDK | `8.0.131`, native Linux ARM64 |
| Original previously source-built artifacts input | `8.0.131-servicing.26422.1`, `centos.9-x64` |
| Host / intended target | Native Linux ARM64 / `linux-arm64` |
| Build system | Legacy VMR source-build orchestration |
| Base image digest | `sha256:7ef8f6ee1b9982511349757443eb4844f0db4f8cef1aff6148a7ba1c25d7c6f4` |
| Derived image ID | `1be55e7358c9e3f9a58f28db1df08e36a56ec9fbb175ccfab8dc69f22cce4a70` |
| Target sysroot | Independently generated ARM64 Ubuntu 16.04 Xenial |
| Intended GLIBC requirement ceiling | `2.23`; measured maximum requirement `2.17` |
| CPU limit | Two selected CPUs through `taskset`, `DOTNET_PROCESSOR_COUNT=2`, and MSBuild `/m:2` |

`8.0.133` is the selected latest published 1xx SDK with a matching VMR tag. It is not presented as the newest SDK across all .NET 8 feature bands. The [profile](../profiles/dotnet-8.0.133-linux-arm64.json) records that selection and its inputs. [Official .NET 8 release metadata](https://builds.dotnet.microsoft.com/dotnet/release-metadata/8.0/releases.json), [selected VMR source](https://github.com/dotnet/dotnet/tree/v8.0.133), [bootstrap SDK configuration](https://github.com/dotnet/dotnet/blob/v8.0.133/global.json).

The `.NET 8` entry point uses `prep.sh` and the legacy source-build graph. Its `sourceOnly=true` profile label describes that path; it does not establish absence of all prebuilts. The run uses the upstream bootstrap SDK, transformed previously source-built artifacts, reference packages, and other package inputs. The build passes `--online`, allowing online sources. Prebuilt-usage evidence must be assessed before claiming a stronger construction property.

The final VMR working tree has **108 modified tracked files**: two authored compatibility patches and 106 configuration files rewritten by upstream source-build targets. Those generated changes comprise 27 warning-setting injections, 26 build-tool framework updates, 26 `global.json` updates, and 27 NuGet configuration updates. `reports/source-worktree.json` records every path and its tagged/current hashes; `source-worktree.diff` matches the preserved sixth-attempt diff exactly. The two authored patches are not the complete working-tree diff. [Upstream configuration targets](https://github.com/dotnet/dotnet/blob/v8.0.133/repo-projects/Directory.Build.targets).

Both core runtime and ASP.NET Core were built locally. The installer selected their local blob-feed archives, and final shared-framework byte comparisons match those archives. The product source-build layout excludes its external archive fallback. The measured construction evidence is described below; it does not extend to every bootstrap or package input. [Installer adapter](https://github.com/dotnet/dotnet/blob/v8.0.133/repo-projects/installer.proj#L40), [layout selection](https://github.com/dotnet/dotnet/blob/v8.0.133/src/installer/src/redist/targets/GenerateLayout.targets#L383).

Source-build defaults `NoPgoOptimize=true` in the runtime. Release configuration therefore does not establish identical optimization inputs, performance, or bytes compared with Microsoft's SDK. This does not imply that all runtime dynamic PGO is absent. [Runtime defaults](https://github.com/dotnet/dotnet/blob/v8.0.133/src/runtime/Directory.Build.props#L302).

## Environment and signed sysroot preparation

The existing Windows ARM64 host runs native ARM64 Linux through the `Ubuntu-22.04` WSL 2 distribution. The independent workspace is `/home/rkttu/cbodotnet/net8`, with separate source, inputs, and container home. The .NET 9 and .NET 10 workspaces remain separate. Build processes use the default Linux UID:GID, observed as `1000:1000`.

[arm64-net8.Containerfile](../containers/arm64-net8.Containerfile) derives from the pinned official Ubuntu 24.04 ARM64 base and adds clang/LLVM/LLDB 18, CMake, native libraries, autotools, debootstrap, and reporting utilities. Rootful Podman uses `--cgroup-manager=cgroupfs --events-backend=file` with container cgroups disabled for this WSL environment. Build and upstream preparation run without `--privileged` as the default Linux user. Only the independent sysroot-creation container receives that privilege, with source and project mounted read-only.

The selected tag's original generator ran with:

```bash
./eng/common/cross/build-rootfs.sh arm64 xenial \
  --rootfsdir /inputs/arm64-xenial
```

It completed at **`2026-10-30T01:54:11.102957Z`**. The generator SHA-256 is **`c60908c01f9c171c74b72e3acc4bb222e659477e365b4efe86e27111ba7a0f51`**. Its report records `packageSignatureVerification=true` and `emulation=false`. The image combines current and removed historical Ubuntu archive keys; no `--skipsigcheck` was used. File hashes, a complete symlink inventory, package versions, generator arguments, and keyring hashes are preserved under `reports/sysroot/`.

The [preparation helper](../scripts/prepare-sysroot8.sh) refuses an existing target because the upstream generator recreates it recursively. Subsequent actions verify the recorded sysroot inventory before reuse. These preparation results do not by themselves establish the SDK's final ABI.

## Bootstrap transformation completed

Upstream preparation attempt **`prepare-20261030T0159583003611Z`** completed with exit code **0**. It started at `2026-10-30T01:59:58Z` and finished at `2026-10-30T02:04:41.191612Z`. It installed the pinned SDK `8.0.131` and ran the original `prep.sh` bootstrap transformation.

| Input | Bytes | SHA-256 |
| --- | --- | --- |
| Original `Private.SourceBuilt.Artifacts.8.0.131-servicing.26422.1.centos.9-x64.tar.gz` | 728,976,053 | `e39d2656832923af11d00a2bd32a10326ab84a0dfd20307a8491d8af3f9e720c` |
| Transformed `Private.SourceBuilt.Artifacts.Bootstrap.tar.gz` | 1,465,776,388 | `4747ec5b5c26ef0df81d72546c7bea556bd1955f9d91d1586a4fa91d5f5cbd09` |

The original archive's `PackageVersions.props` SHA-256 is `46105945912ddf85a78a6d362e52cf807a8951dd650013ba95a88bf184ed1d50`; the transformed file's SHA-256 is `1c52b8f0052b5e0ca525a9e0381a2cdaad0111565fa7e030c8eb192c4f8b35cb`. The transformed archive inventory records 13 Linux ARM64 package files, including core runtime/host/crossgen2 packages `8.0.31` and ARM64 NativeAOT bootstrap tools. Those are earlier-release build inputs, separate from the intended final runtime `8.0.33`.

The default upstream transformation substitutes portable/native inputs for six Unix RIDs. It must not be skipped merely because the initial archive is named for x64. Conversely, an untransformed preseeded archive would cause this tag's `prep.sh` to skip the download and associated transformation. [Upstream preparation](https://github.com/dotnet/dotnet/blob/v8.0.133/prep.sh), [bootstrap project](https://github.com/dotnet/dotnet/blob/v8.0.133/eng/bootstrap/buildBootstrapPreviouslySB.csproj).

[watch-bootstrap8.py](../scripts/watch-bootstrap8.py) preserved the original download by a hidden hard link before upstream replacement. Its hidden filename does not match upstream archive discovery. Finalization retained the completed original under `/inputs/original-bootstrap/`, validated the original and transformed archives and package-version XML, and wrote `/inputs/bootstrap8-prepared.json`. Build and test actions verify both archive fingerprints against that successful marker. Hashes fingerprint retrieved content; they do not constitute publisher signature verification.

Evidence is `reports/runs/prepare-20261030T0159583003611Z/{prepare-command.txt,prepare.log,prepare-resources.txt,prepare-status.json,bootstrap-inputs.json}` and the independent sysroot reports. The [Windows wrapper](../scripts/Invoke-Net8Build.ps1) records each action separately. The [reproduction guide](reproduce-net8-arm64.md) gives its complete procedure.

## SDK build attempts and host compatibility correction

The build attempt **`build-20261030T0206158376987Z`** started after successful preparation. It exports `ROOTFS_DIR=/inputs/arm64-xenial`, `CLR_CC`/`CLR_CXX` for clang 18, `CppCompilerAndLinker=/usr/bin/clang-18`, and `PortableBuild=true`/`CrossBuild=true` for nested processes. It uses the legacy root command shape:

```bash
taskset --cpu-list 0,1 ./build.sh --clean-while-building --online -- \
  /p:Configuration=Release /p:Platform=arm64 /p:TargetOS=Linux \
  /p:TargetRid=linux-arm64 /p:PortableBuild=true /p:CrossBuild=true /m:2
```

The actual affinity list is selected from permitted CPUs and recorded per action. Root .NET 9/10 CLI options are not substituted for this tag's `--` MSBuild separator. Inner source-build orchestration supplies CI mode and the component build identities.

The legacy runtime adapter's `SourceBuildNonPortable=true` flag does not unconditionally force a nonportable runtime. Its functional Arcade consumer sets a host RID only when `TargetRid` is empty; this build supplies the explicit `linux-arm64` target. The actual native commands and CMake settings must still verify the intended sysroot use before accepting a portable artifact. [Legacy RID default](https://github.com/dotnet/dotnet/blob/v8.0.133/src/arcade/src/Microsoft.DotNet.Arcade.Sdk/tools/SourceBuild/SourceBuildArcade.targets#L57), [native argument generation](https://github.com/dotnet/dotnet/blob/v8.0.133/src/runtime/src/coreclr/runtime.proj#L32).

The first full attempt finished with exit code **1** at `2026-10-30T02:17:53.512419Z`. GNU time recorded **11 minutes 33.72 seconds** for the invoked root command; the runtime component reported **6 minutes 54.18 seconds**. Those are different scopes and must not be presented as interchangeable durations.

The saved `reports/native-config/` files show target compilation used clang 18 with `--gcc-toolchain=/inputs/arm64-xenial/usr` and `--sysroot=/inputs/arm64-xenial`. Main CoreCLR native compilation reached 100%, installed the target binaries, and logged `Repo successfully built`. The failure occurred afterward in a separate host-tool invocation with `CLR_CROSS_COMPONENTS_BUILD=1` and `-component crosscomponents`.

That .NET 8 CMake host-detection branch rejects `aarch64`, reporting that only AMD64/I386 hosts are supported for Linux cross-architecture components. The graph selects those tools when `CrossBuild=true`, including this same-CPU sysroot build. Removing cross mode would discard the intended target ABI policy, and skipping host tools without adjusting their consumers would leave expected crossgen2 helper locations missing.

The prepared [backport](../patches/net8/0001-support-arm64-cross-components-host.patch) adds the exact two-line `aarch64` host branch present in [the pinned .NET 9 source](https://github.com/dotnet/dotnet/blob/v9.0.123/src/runtime/eng/native/configureplatform.cmake#L30). It retains the existing tool graph and target sysroot policy. [apply-net8-patches.py](../scripts/apply-net8-patches.py) guards the VMR revision, original and patched file SHA-256 values, patch hash, and one-file/two-line scope. It supports idempotent application and separate verification, with new external JSON reports. No other source changes are discarded by that helper.

| Patch input | SHA-256 |
| --- | --- |
| Original `src/runtime/eng/native/configureplatform.cmake` | `e3ccca4155e4a5811576c6e3f18a5efc6aa0d49b3a352d0a98366c020fa2eab2` |
| Expected patched file | `91bb7b95d9d2e2b5d437b39290af61203419c487913e2d5ed2112ac31b421a8e` |
| Fixed patch file | `d8d94bc40c11ed96bb9cc14a9ada399929999cda9c09da86eac4a2d961c1e1e3` |

The first patch passed `git apply --check` and was applied with its expected patched hash before the second attempt. Host cross-component configuration then succeeded. The final source identity must include both the selected VMR commit and the compatibility patches. Host-only tool compilation can use host libraries, so final SDK inspection must still establish the redistribution ABI.

### Second attempt: ASP.NET package-root resolution

Attempt `build-20261030T0230238210439Z` completed the runtime and additional dependencies, including Roslyn and MSBuild, then failed at ASP.NET crossgen preparation with `Could not find crossgen2 tools/crossgen2`. It finished with exit code 1 at `2026-10-30T02:49:01.304639Z`; GNU time recorded **18 minutes 33.59 seconds** for the root invocation.

The local `Microsoft.NETCore.App.Crossgen2.linux-arm64 8.0.33` package contains `tools/crossgen2`, an ELF executable. The runtime's source-build `NativeAotSupported=false` setting causes managed single-file publishing rather than a DLL-only pack. The immediate failure was an empty `Crossgen2PackageRoot`, not a missing executable from the locally built package. No ReadyToRun disablement or upstream binary substitution was needed.

The legacy ASP.NET adapter passed `PortableBuild=false` when the selected target RID was unchanged, despite the outer portable profile. ASP.NET appended that same RID to existing portable runtime/crossgen2 dependency lists, yielding duplicate implicit references. The SDK removed both duplicates, so generated NuGet package path properties were absent. [Adapter computation](https://github.com/dotnet/dotnet/blob/v8.0.133/repo-projects/aspnetcore.proj#L9), [dependency lists](https://github.com/dotnet/dotnet/blob/v8.0.133/src/aspnetcore/eng/Dependencies.props#L108), [SDK removal logic](https://github.com/dotnet/dotnet/blob/v8.0.133/src/sdk/src/Tasks/Microsoft.NET.Build.Tasks/CheckForImplicitPackageReferenceOverrides.cs).

The second [compatibility patch](../patches/net8/0002-preserve-portable-aspnetcore-target.patch) makes the adapter retain an explicitly supplied `PortableBuild=true`. Its empty/false defaults are preserved. The locally built crossgen2 graph and ReadyToRun output remain enabled.

| Additional patch input | SHA-256 |
| --- | --- |
| Original `repo-projects/aspnetcore.proj` | `10bb2a651fb1176b6f4641aea93f035ab2124bbb2ef3ce32f9989fa814b99a97` |
| Expected patched adapter | `1d61d5b2b8174ece3cd85442ce0f4fc4e44134a3c7b03e2a0b7cfce5204b65f0` |
| Fixed second patch | `b03fab8085c959debc05892fb1920edaa8f514f90d4189994de23608abcc7d8a` |

### Third attempt: SDK packaged, symbols extraction failed

Attempt `build-20261030T0300329409492Z` records both patches through the helper's schema-version-2 report. The runtime host-detection backport was already applied; the ASP.NET adapter patch was newly applied at `2026-10-30T03:00:33.496876Z`. Both resulting file hashes matched their expected values. The helper checked both fixed inputs before changing either, and preserved unrelated source changes. Historical one-patch reports remain intact.

This attempt completed all component builds, including installer and package-source-build. Installer packaging succeeded with zero warnings and zero errors and produced the SDK tarball. The root invocation subsequently failed at `build.proj:120` while extracting that SDK for `CreateSdkSymbolsTarball`, with `Cannot change mode ... Operation not permitted`. It finished with exit code 1 at `2026-10-30T03:15:18.724253Z`; GNU time recorded **14 minutes 41.84 seconds**. This attempt reused already completed components and caches, so that duration is not a cold full-build measurement.

The failure reproduced in a fresh extraction directory, including with `--same-permissions`. It was not corrected by rewriting the SDK archive or changing file ownership. The older host Podman policy lacked the `fchmodat2` allowance used by Ubuntu 24.04's archive tools. Fresh extraction of the complete, unchanged SDK succeeded with a copy of the default policy plus one additional `fchmodat2` allow rule.

[prepare-net8-seccomp.py](../scripts/prepare-net8-seccomp.py) now generates and verifies that narrowly derived policy. Its base SHA-256 is `27e6dbb7d478e222144af8ac0dd4ea2423f1d01f8d8adde053f8831371106740`; the result is `433ff4d41a88c0c37acf4372cfd84b13399c3a831037ee269141508d1538f990`. The native host is ARM64, libseccomp is `2.5.3`, and the resolved syscall number is `452`. All other rules and the default action are retained. The host policy is unchanged; the build containers use the recorded derived policy without `seccomp=unconfined` or `--privileged`. Evidence is `reports/seccomp-net8.json` and each subsequent attempt's policy snapshots.

### Fourth attempt: consumed symbol archives on retry

Attempt `build-20261030T0333546335877Z` used the derived policy but failed at `build.proj:75`, where a symbol-archive filename expression received an empty value. The earlier attempt had extracted and deleted `Release/Symbols.*.tar.gz` inputs before reaching the later SDK-extraction failure. Its completed copy checkpoint prevented a retry from copying those inputs again. Twenty original symbol archives remained in the local blob feed. No third source patch or SDK archive change was introduced for this recovery.

[restore-net8-symbol-inputs.py](../scripts/restore-net8-symbol-inputs.py) now restores only exact retained `Symbols.*.tar.gz` inputs for this pinned checkout. It verifies the source commit and fixed directories, rejects symbolic links and different existing files, records SHA-256/SHA-512 and byte counts, and uses complete private copies before publishing missing inputs. Build and test actions invoke it and preserve `net8-symbol-inputs.json` in the action's report directory.

### Fifth attempt: root build completed

Attempt **`build-20261030T0339397739347Z`** restored all 20 retained local symbol archives and completed with exit code **0**. It started at `2026-10-30T03:39:44Z` and finished at `2026-10-30T03:40:20.794898Z`. GNU time recorded **35.95 seconds** for cached resumption and finalization, not a cold full build. It produced both combined and SDK symbol tarballs and packaged the 13 files in the prebuilt-package directory. The SDK tarball and its collected copy were independently rehashed afterward and both retained SHA-256 `8c9ab2e845e7ca16d6a185d47d2131fd43f3f147827c0fa56ae5552a9e52490e`.

## Packaged SDK and local framework provenance

The SDK was generated at `artifacts/arm64/Release/dotnet-sdk-8.0.133-linux-arm64.tar.gz` inside the VMR. Collection preserved its bytes as `artifacts/8.0.133-linux-arm64/cbodotnet-sdk-8.0.133-linux-arm64-build.1.tar.gz` and generated checksums and a manifest. Final collection must refresh the manifest after the remaining root and test actions.

| Generated archive | Bytes | SHA-256 |
| --- | --- | --- |
| SDK `8.0.133`, `linux-arm64` | 242,266,582 | `8c9ab2e845e7ca16d6a185d47d2131fd43f3f147827c0fa56ae5552a9e52490e` |
| Core runtime `8.0.33`, `linux-arm64` | 68,586,849 | `132ba79aad52fb6c731bdb1865ee3412cf2d2163d009c928cb604cc071db5b49` |
| ASP.NET runtime `8.0.33`, `linux-arm64` | 10,408,703 | `235655600c827bb6a3c676a8af01280944e1c2e70eb367aef7fd95fae4ea5dc9` |

The SDK SHA-512 is `e604d7de834096ca3bd768ad3058771195d7392ec244146e9506a679748d4413e5fde46ef04105d4a050f6729cd7a0b39d8da3cb1f3906dd7eab2998b3df2884`. Version inspection reports SDK `8.0.133`, RID `linux-arm64`, and shared frameworks `Microsoft.NETCore.App 8.0.33` and `Microsoft.AspNetCore.App 8.0.33`.

`reports/construction/shared-framework-identity.json` compares the actual final SDK with the local runtime archives. All **184 core-runtime entries** and **143 ASP.NET entries** match, including contents, entry types, and link targets. The runtime output archives also match the local blob-feed copies by size and SHA-256.

`reports/construction/origin-evidence.json` adds actual installer input evidence. A bounded read-only replay of the retained installer `sourcebuild.binlog` completed all **48,633 events**, yielding six URI records. Its SHA-256 is `08530177d5a7d27dcc3300037ae970a527d3bc0f676d895742185dc7a1c9c70a`. Recorded `DownloadFile` task parameters selected:

```text
file:///vmr/artifacts/obj/arm64/Release/blob-feed/assets//dotnet-runtime-8.0.33-linux-arm64.tar.gz
file:///vmr/artifacts/obj/arm64/Release/blob-feed/assets//aspnetcore-runtime-8.0.33-linux-arm64.tar.gz
```

Those records establish local origins for the two included shared frameworks when combined with the archive hashes and byte comparisons. The archive comparison utility deliberately retains its generic `originVerified=false` field: comparison alone establishes identity, and the separate origin report supplies the recorded task evidence. No build targets or project evaluation were executed during the binlog audit.

## Recorded prebuilt package usages

Upstream generated `artifacts/prebuilt-report/prebuilt-usage.xml` and `annotated-usage.xml`. Byte-exact copies and a parsed summary are retained under `reports/prebuilt-usage/`. They record **31 usage entries for nine package/version identities** across 23 `project.assets.json` files. Thirteen entries are direct dependencies and two are auto-referenced. The report groups eight entries under ASP.NET, 18 under source-build-assets, four under installer, and one under format.

| Reported package | Version | Usage entries |
| --- | --- | --- |
| `Microsoft.Build.Framework` | `17.8.43` | 2 |
| `Microsoft.Build.Tasks.Core` | `17.8.43` | 1 |
| `Microsoft.Build.Utilities.Core` | `17.8.43` | 2 |
| `Microsoft.NET.StringTools` | `17.8.43` | 2 |
| `Microsoft.VisualStudio.Setup.Configuration.Interop` | `3.2.2146` | 1 |
| `Newtonsoft.Json` | `13.0.1` | 18 |
| `System.Formats.Asn1` | `8.0.1` | 2 |
| `System.Reflection.Metadata` | `8.0.0` | 2 |
| `System.Text.Json` | `8.0.5` | 1 |

The original usage XML is 7,380 bytes with SHA-256 `929d213dd27f29651fa5e529a7d40e2349ced5411c3346b8e252e318955c3dec`. The annotated XML is 9,821 bytes with SHA-256 `be5e15f96e6c341ed05990874d00e4fdc512de69760a46cdc239351405b1b22c`.

The upstream task starts with restored package identities, excludes known source-built and reference-package identities, combines explicitly tracked package identities, and locates their asset-file usages. These are package-usage records rather than counts of distinct files shipped in the SDK. Reference packages are excluded, so the report is not a complete external-input inventory. [Usage filtering](https://github.com/dotnet/dotnet/blob/v8.0.133/eng/tools/tasks/Microsoft.DotNet.SourceBuild.Tasks.XPlat/UsageReport/WritePackageUsageData.cs#L130).

Thirty entries have a `SourceBuildPackageIdCreator` annotation. That annotation matches package IDs against source-build snapshots, independently of the recorded used version. For example, the report records MSBuild packages `17.8.43` while naming a local creator for `17.8.60`; that does not reclassify the reported usage as a locally built `17.8.43` package. The XML files establish neither a zero-prebuilt build nor poisoning/output-flow analysis or approved-baseline validation. The separately verified local origins of the two shared frameworks remain a narrower result. [Annotation logic](https://github.com/dotnet/dotnet/blob/v8.0.133/eng/tools/tasks/Microsoft.DotNet.SourceBuild.Tasks.XPlat/UsageReport/WriteUsageReports.cs#L118).

## Native validation and remaining evidence

| Evidence | Result at this snapshot |
| --- | --- |
| Root build completion | Passed; fifth attempt first succeeded, sixth regenerated correct reusable-artifact revision metadata |
| Actual SDK archive path, bytes, SHA-256/SHA-512 | Recorded above and in checksum files |
| SDK version/RID and included shared-runtime versions | `8.0.133`, `linux-arm64`, both frameworks `8.0.33` |
| Local core-runtime and ASP.NET runtime byte identity | Passed, 184 and 143 matching entries |
| Actual installer shared-runtime inputs | Both local archives confirmed by recorded `DownloadFile` task parameters |
| ELF architecture and GLIBC/GLIBCXX/CXXABI requirements | 19 AArch64 ELF files; maxima `2.17` / `3.4.21` / `1.3.7` |
| Ubuntu 22.04, Ubuntu 24.04, and Debian 13 native functional checks | All six checks passed on the unchanged SDK archive |
| Final source-build smoke invocation | Passed: 46 total, 44 passed, zero failed, two skipped |
| Upstream prebuilt-usage report | Recorded: 31 entries, nine package/version identities; no zero-prebuilt claim |

The independent verifier passed `net8.0` console DLL and apphost execution, RSA SHA-256 signing/verification, random bytes, `fr-FR` ICU formatting, and ASP.NET loopback HTTP on all three native ARM64 user spaces. Each inspected the same SDK SHA-256. Reports are under `reports/verify-ubuntu22/`, `reports/verify-ubuntu24/`, and `reports/verify-debian13/`.

The first Debian 13 executions failed during `dotnet new` with a `NuGet-Migrations` named-mutex error. In this synthetic container user, the passwd home was `/`; .NET 8's native mutex fallback used it when `XDG_RUNTIME_DIR` was absent. The verifier now creates a private mode-`0700` runtime directory alongside its private home and caches. Debian 13 then passed without changing the SDK. The failed default-policy and policy-only reports remain preserved. These are container state-isolation corrections, not SDK source changes.

The measured GLIBC symbol requirement is below the intended `2.23` ceiling. ELF symbol maxima exclude archive members and managed PE images, and do not establish kernel requirements or all dynamically loaded dependencies. These user spaces share the WSL kernel. Results do not certify every Linux distribution, workload, NativeAOT application, or external package.

Upstream smoke tests use the tag's `--run-smoke-test` path, separate from .NET 9's tests. Attempt `test-20261030T0342164439757Z` finished with exit code 1 after 4 minutes 44.16 seconds. Its 46 tests included **43 passed, one failed, and two skipped**. The sole failure, `SourceBuiltArtifactsTests.VerifyVersionFile`, found a forty-zero commit in the generated previously source-built artifacts tarball's `.version` file while strict CI validation was enabled. Root SDK packaging and functional scenarios had passed; this additional provenance check correctly remained a failed test. That failed action and its outputs remain preserved.

### Producer revision metadata corrected and smoke tests passed

The official Arcade target uses `BUILD_SOURCEVERSION` for `RepositoryCommit` when source-control queries are disabled, and falls back to forty zeros if that input is absent. The official installer VMR pipeline passes that environment variable into its build container. The Bash wrapper now verifies the pinned VMR Git commit, exports that exact value as `BUILD_SOURCEVERSION`, and records it in the command/status evidence. This supplies the existing producer input without a third source patch or test assertion change. [Repository revision default](https://github.com/dotnet/dotnet/blob/v8.0.133/src/arcade/src/Microsoft.DotNet.Arcade.Sdk/tools/RepositoryInfo.targets#L26), [official container pass-through](https://github.com/dotnet/dotnet/blob/v8.0.133/src/installer/eng/pipelines/templates/jobs/vmr-build.yml#L239).

Recovery preserved the original zero-commit reusable-artifacts tarball and exactly two empty producer checkpoints, `package-source-build/Build.complete` and `dotnet/Build.complete`, under `/inputs/recovery/zero-commit-psb-20261030/`. Compiled-component checkpoints and SDK bytes were retained. The complete action is recorded in `reports/psb-commit-recovery.json`.

Build attempt **`build-20261030T0349478257751Z`** regenerated the reusable-artifacts tarball through the upstream producer and completed with exit code **0**, from `2026-10-30T03:49:52Z` to `2026-10-30T03:50:45.569682Z`. Its **52.84-second** duration measures cached metadata regeneration and finalization, not a cold build. `reports/construction/root-finalization.json` records this latest completion; the fifth-attempt evidence is also preserved separately.

The regenerated `Private.SourceBuilt.Artifacts.8.0.133-servicing.26523.1.linux-arm64.tar.gz` is 729,085,053 bytes with SHA-256 `0d192f791a69b46755ea1e5956f1b5f1cc7d89bc0b35d1df687d60f742a09635`. Its actual `.version` is:

```text
7d1bf90885cff22e7da72b27e9848e42fd3cb1ae
8.0.133-servicing.26523.1
```

`reports/construction/psb-metadata.json` records its hashes, exact version text, verified producer input, and recovery-report hash. Both the original SDK output and collected SDK copy were rehashed afterward and remain unchanged.

Final smoke attempt **`test-20261030T0353117156658Z`** completed with exit code **0**, from `2026-10-30T03:53:17Z` to `2026-10-30T03:57:00.340036Z`. Its TRX records **46 total, 44 passed, zero failed, and two skipped**. GNU time recorded **3 minutes 43.09 seconds** for the root invocation; the test runner reported `3.5043` minutes for the test execution. It also packaged 164 smoke-test prerequisite files. The previously failing strict revision check passed using the regenerated tarball.

Passing smoke tests included C#/F#/VB console, apphost and ReadyToRun scenarios; web and test templates; format; watch; OmniSharp; SourceLink; native debug symbols; archive ownership; and the official-SDK content comparison test methods. `LicenseScanTests.ScanForLicenses` was skipped because `SMOKE_TESTS_LICENSE_SCAN_PATH` was absent; `PoisonTests.VerifyUsage` was skipped because `SMOKE_TESTS_POISON_REPORT_PATH` was absent. Each invocation retains its own logs, TRX summary, and output archive under `reports/runs/`.

The exact official `8.0.133` ARM64 baseline was downloaded separately and verified against the release metadata SHA-512. Its size is 208,743,871 bytes, with SHA-512 `479cde028a0eb017a0a1423901476df4e9d43c912f03c1038b894fa4c753db26d7847d7ccebb0387f4aea62534eff929f7a0b055b0ed3db0abce70ac91625746`; acquisition evidence is `reports/test-inputs/official-sdk-baseline.json`. It is a comparison input, not the community output. An empty official-baseline path would skip the skippable SDK-content comparisons rather than download a baseline.

Both invocations' actual comparison outputs matched the tagged upstream baselines without recorded baseline warnings. The file-list diff is 19,432 bytes and includes 16 added and 221 removed normalized paths; it exactly matches the upstream expected differences. The assembly-version diff and its expected baseline are empty. Independently preserved, filtered assembly lists are byte-identical at 185,028 bytes each. These comparisons normalize paths/versions, apply exclusions, and omit assembly revision components and some unmatched files; they do not establish archive byte equivalence.

The upstream diff helper returns `git diff` stdout without validating its exit code or surfacing stderr. To bound that blind spot, each invocation's `content-comparisons/` evidence additionally preserves the actual lists and independently checks the diff commands: file-list comparison returns the valid difference code `1`, assembly comparison returns `0`, and both have empty stderr. The final invocation's comparison results are consistent with the first. [Upstream helper limitation](https://github.com/dotnet/dotnet/blob/v8.0.133/test/Microsoft.DotNet.SourceBuild.SmokeTests/BaselineHelper.cs#L80).

No Stage 2, license-scan, poisoning, or comprehensive prebuilt-baseline validation pass is claimed.

Generated inputs, caches, reports, and SDK archives remain local and ignored by Git. No GitHub CI service, binary publication, or download website is implied by these results.
