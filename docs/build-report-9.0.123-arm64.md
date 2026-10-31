# .NET SDK 9.0.123 Linux ARM64 build report

Status snapshot: **2026-10-30, Asia/Seoul**. **SDK build, archive collection, and validation in three ARM64 user-space environments completed.** All 20 shipped ELF files are AArch64, the selected GLIBC ceiling passed, and all six functional checks passed in each environment. Upstream ordinary-build tests recorded 500 passes, and template scenarios recorded 32 passes and 2 skips, with no failures.

This work implements the project's direction of providing community builds for .NET 5 and later independently of Microsoft's support lifecycle. This report covers one native ARM64 .NET 9 build; other versions and Linux x64 require their own build and validation evidence.

## Selected inputs

| Item | Selected value |
| --- | --- |
| SDK / VMR tag | `9.0.123` / `v9.0.123` |
| VMR commit | `9f04b57d1366e21b3178648493d6edffeff2216e` |
| Selection date | 2026-10-30 |
| Latest published .NET 9 SDK recorded during selection | `9.0.320`, released 2026-10-25 |
| Runtime recorded for both SDK selections | `9.0.22` |
| Bootstrap SDK | `9.0.121`, Linux ARM64 |
| Source-built artifacts input recorded in the profile | `9.0.121-servicing.26421.1` |
| Host / target | Native Linux ARM64 / `linux-arm64` |
| Build mode | Ordinary VMR build; `sourceOnly=false`, `CrossBuild=true`, `PortableBuild=true` |
| Base image | `mcr.microsoft.com/dotnet-buildtools/prereqs:ubuntu-24.04-arm64` |
| Base digest | `sha256:7ef8f6ee1b9982511349757443eb4844f0db4f8cef1aff6148a7ba1c25d7c6f4` |
| Current derived image ID | `01cf05ece807f9454ef617dc1438685602ef994849cd63e3e21152762dfee551` |
| Compiler / CMake | ARM64 clang 18.1.3 / CMake 3.28.3 |
| Target sysroot | ARM64 Ubuntu 16.04 Xenial |
| Selected GLIBC ceiling / observed maximum requirement | `2.23` / `2.17` |
| Build CPU limit | Two selected CPUs through `taskset`, `DOTNET_PROCESSOR_COUNT=2`, and MSBuild `/m:2` |

`9.0.123` is the latest published 1xx SDK selected with a matching VMR tag. No matching VMR tag for `9.0.320` was found during selection. The selection does not describe `9.0.123` as the newest SDK across all .NET 9 feature bands. Both releases record runtime `9.0.22`; their SDK tools and feature bands remain different. The [profile](../profiles/dotnet-9.0.123-linux-arm64.json) pins the selected source and inputs.

Primary references: [official .NET 9 release metadata](https://builds.dotnet.microsoft.com/dotnet/release-metadata/9.0/releases.json), [selected VMR tag](https://github.com/dotnet/dotnet/tree/v9.0.123), [bootstrap configuration](https://github.com/dotnet/dotnet/blob/v9.0.123/global.json), and [.NET 9 supported OS metadata](https://github.com/dotnet/core/blob/main/release-notes/9.0/supported-os.json).

## Environment prepared

The existing Windows ARM64 host uses the `Ubuntu-22.04` WSL 2 distribution and rootful Podman. The .NET 9 workspace is isolated at `/home/rkttu/cbodotnet/net9`; the previous .NET 10 workspace and Bionic sysroot remain separate. The selected VMR checkout is `/home/rkttu/cbodotnet/net9/work/dotnet-v9.0.123`.

The container runs natively on ARM64. Build processes use the default WSL user's UID:GID, observed as `1000:1000`, and a separate persistent container home. Rootful Podman uses `--cgroup-manager=cgroupfs --events-backend=file`, with container cgroups disabled for this WSL environment. Build and test containers do not receive `--privileged`. The CPU affinity limit also covers native scripts that call `nproc` independently of MSBuild.

The [Containerfile](../containers/arm64-net9.Containerfile) adds clang/LLVM/LLDB 18, native runtime prerequisites, debootstrap, and reporting tools to the pinned official base. It verifies the inherited Node installation is at least version 20 and that the unversioned LLD invocation works. The actual preparation observed Node 20.20.2 and npm 10.8.2. The base digest pins the starting image; additional package installation is identified by the derived image ID and recorded environment inventory rather than assumed to be locked by the base digest alone.

The tagged `eng/common/cross/build-rootfs.sh` created `/inputs/arm64-xenial` with `arm64 xenial --rootfsdir /inputs/arm64-xenial`. This historical generator uses debootstrap and chroot in a dedicated native ARM64 privileged preparation container. No architecture emulation was used. Ubuntu archive signature verification remained enabled. The container combines the current and removed Ubuntu archive keyrings to verify Xenial's historical signatures instead of disabling the check.

Preparation completed at `2026-10-29T15:22:47Z` (2026-10-30 in Asia/Seoul). The generator SHA-256 is `78e9d3d820f63aca93b702035343eb1002fee839feb108d81694a881aea3d3b1`. Reports preserve the generator arguments, keyring hashes, package inventory, regular-file hashes, and symlink inventory. Subsequent build invocations verify the complete sysroot inventory before starting.

See the [reproduction procedure](reproduce-net9-arm64.md) and [Windows wrapper](../scripts/Invoke-Net9Build.ps1) for preparation and execution commands.

## Build attempts and corrections

Per-attempt evidence is under `artifacts/9.0.123-linux-arm64/reports/runs/`. Failed attempts retain their command, output, exit status, resource report, and archived component logs before a retry overwrites upstream log paths. UTC timestamps in the directory names identify attempts; the report date uses Asia/Seoul.

| Attempt directory | Result at this snapshot | Observed issue and correction |
| --- | --- | --- |
| `build-20261029T1525173541202Z` | Wrapper stopped before invoking the VMR | Corrected the CPU-affinity helper syntax; this was not an SDK build result. |
| `build-20261029T1526017465807Z` | Failed, exit 1 | NativeAOT's `cdacreader` linker probe could not find `ld` through `gcc -fuse-ld=lld`. Added the unversioned `lld` package and verified that invocation in the derived image. |
| `build-20261029T1602364269868Z` | Failed, exit 1 | NativeAOT selected `gcc` while passing clang's `--gcc-toolchain` argument. Exported `CppCompilerAndLinker=/usr/bin/clang-18`, separately from `CLR_CC` and `CLR_CXX`. |
| `build-20261029T1606568891663Z` | Failed, exit 1 | CoreCLR configuration selected system Brotli, which is absent from the Xenial sysroot. Exported `PortableBuild=true` so the nested component process retains the intended portable build setting. |
| `build-20261029T1611120664657Z` | Failed, exit 1 | Runtime completed successfully, then ASP.NET packaging could not find `packagesToPack.json`. Its generation is conditional on `ContinuousIntegrationBuild=true`; the packaging step requires it. |
| `build-20261029T1647214393954Z` | Passed, exit 0 | Enabled the root `--ci` switch so the normal ASP.NET manifest-generation step runs. SDK assembly and publishing completed. |

The successful attempt took **8 minutes 30.19 seconds**, as measured by its GNU time report. It reused completed components and package caches, including the runtime built during the preceding attempt. The preceding failed attempt took approximately 33 minutes 17 seconds and completed runtime compilation before reaching the ASP.NET packaging error. These measurements are retry durations, not a cold-build benchmark.

The final attempt enabled `--ci` after earlier components had been cached with the prior CI setting. This result establishes that the local artifact was produced and tested; it does not demonstrate a clean build from an empty workspace using one uniform CI setting, or bitwise reproducibility. A future cold build should start with the final recorded configuration. The selected commit stayed fixed, while the VMR's generated tracked changes remain recorded by collection: the manifest reports a dirty working tree with 671 tracked changes. The separate pristine source scan described below concerns another checkout.

The wrapper preserves upstream component build identities. It uses the .NET 9 root entry point's `--rid linux-arm64 --ci` and MSBuild target properties, with exported `CppCompilerAndLinker=/usr/bin/clang-18` and `PortableBuild=true`. It does not apply a new global official-build stamp. The CI switch is used locally; no GitHub CI migration was performed.

## Component construction

This SDK contains a **locally built `Microsoft.NETCore.App 9.0.22` shared runtime** and a **reused upstream `Microsoft.AspNetCore.App 9.0.22` shared runtime**. The .NET 9 1xx VMR includes and builds runtime sources. Its SDK adapter receives a local asset base URL, while the tagged layout explicitly selects an upstream ASP.NET shared-runtime fallback in ordinary VMR mode. Actual recorded SDK task inputs and final archive byte comparisons corroborate those source rules. [SDK adapter](https://github.com/dotnet/dotnet/blob/v9.0.123/repo-projects/sdk.proj), [runtime publishing rules](https://github.com/dotnet/dotnet/blob/v9.0.123/src/runtime/eng/Publishing.props), [SDK layout rules](https://github.com/dotnet/dotnet/blob/v9.0.123/src/sdk/src/Installer/redist-installer/targets/GenerateLayout.targets).

The successful SDK assembly binlog recorded these `DownloadFile` task URI parameters:

```text
file:///vmr/artifacts/assets/Release/Runtime/9.0.22-dev.26522.18/dotnet-runtime-9.0.22-linux-arm64.tar.gz
https://ci.dot.net/public/aspnetcore/Runtime/9.0.22-servicing.26523.14/aspnetcore-runtime-9.0.22-linux-arm64.tar.gz
```

The local runtime build completed in the preceding attempt, and its published archive remained available for SDK assembly. The ASP.NET download was captured from the SDK's actual download directory before cleanup: 42,487,848 bytes, SHA-256 `44d498606b4d97d6f24c34889e6f85da48b180aa3ebb807d795e1ddf0d306077`. The binlog also records the upstream download URL and the matching destination path. A local ASP.NET repository build alone would not have proved the final shared-runtime selection.

[inspect-sdk-construction9.py](../scripts/inspect-sdk-construction9.py) confirmed exact shared-framework entry sets and regular-file SHA-256 values. The comparison report at `reports/construction/shared-framework-identity.json` retains `originVerified=false` because that generic utility checks byte identity alone. The separate `reports/construction/origin-evidence.json` corroborates component origins using the actual task URI events, preserved download, local runtime build record, and matching archive contents. The complete bounded binlog replay processed 684,674 events; its source binlog SHA-256 is `f97192aa77595da9eefe708082e8e6d70d1193654157431ec9cdf2e99ac5a726`. Evidence is preserved in `reports/shared-inputs/sdk-urls.jsonl` and `sdk-urls-status.json`.

| Construction evidence | Current result |
| --- | --- |
| Final `Microsoft.NETCore.App/9.0.22` versus local runtime archive | All 186 entries identical |
| Final `Microsoft.AspNetCore.App/9.0.22` versus captured upstream archive | All 143 entries identical |
| Build/publish/download records corroborating those inputs | Recorded and linked in `origin-evidence.json` |
| Collector construction declaration | Local .NET runtime and reused upstream ASP.NET runtime, `sourceOnly=false` |

This ordinary build also consumes upstream bootstrap and package inputs. The byte comparisons cover the two shared-framework trees, rather than every file in the SDK, and do not establish an entirely source-built SDK.

## Separate clean-source binary scan

The standalone .NET 9 BinaryToolKit validation **passed** against a separate pristine checkout at the selected commit. The successful report is `reports/source-binaries-retry1/status.json`, with exit code 0, unchanged allowlists, and a clean target before and after scanning. The upstream tool produced no `NewBinaries.txt`, which is its normal behavior when it finds no unexpected binaries. No empty report was synthesized.

The first scan attempt ran the tool with its working directory in the warm build checkout and reported 1,871 unexpected binaries. That failed report remains at `reports/source-binaries/`. The corrected invocation sets `RunWorkingDirectory=/clean9` as well as passing `/clean9` to `validate`; the successful scan then operated on the pristine target. Both original allowlists were preserved unchanged. The scanner restore also recorded `NU1603`: its requested `System.CommandLine` version was unavailable and NuGet resolved the reported compatible version. The scan log preserves that warning.

This validation uses [scan-clean-source9.sh](../scripts/scan-clean-source9.sh) and the tag's standalone BinaryToolKit API. It is separate from `./build.sh --test`; it does not establish absence of prebuilt dependencies in ordinary VMR mode, validate the produced SDK, or make this a source-only build.

## SDK archive and execution validation

The collector copied the VMR-produced SDK archive unchanged. Its two upstream archive candidates had identical bytes and hashes. The community archive is distinct from the official Microsoft comparison archive used by upstream tests.

| Item | Current result |
| --- | --- |
| Original VMR SDK archive path | `artifacts/assets/Release/Sdk/9.0.123-servicing.26523.1/dotnet-sdk-9.0.123-linux-arm64.tar.gz` |
| Collected community archive | `artifacts/9.0.123-linux-arm64/cbodotnet-sdk-9.0.123-linux-arm64-build.1.tar.gz` |
| Archive size | **189,195,292 bytes**, approximately **180.4 MiB** |
| Actual SDK version / RID | `9.0.123` / `linux-arm64` |
| Shared runtime versions | .NET and ASP.NET Core `9.0.22` |
| License and third-party notices | `LICENSE.txt` (1,116 bytes) and `ThirdPartyNotices.txt` (77,438 bytes) present; `reports/archive-layout.json` |
| ELF architecture and file count | All **20** ELF files are **AArch64** |
| Maximum required external symbol versions | `GLIBC_2.17`, `GLIBCXX_3.4.21`, `CXXABI_1.3.7` |

SHA-256:

```text
d1f70738b4982e6b0313eb320a5ac7c5f1eae925a5808dbc7504963c35de15ee
```

SHA-512:

```text
2dfa57f70fff9ac616fc45eaa28c00f474486481c1288a0092b46b8ec793ca65f63e496da75809b49483e084e0cfd47c65ad844f28b39c48e3d73ddbec532090
```

Validation used the collected archive with SDK `9.0.123`, RID `linux-arm64`, framework `net9.0`, and GLIBC ceiling `2.23`. The [SDK verifier](../scripts/verify-sdk.sh) checked SDK identity and native ELF dependencies, built and ran a console DLL and apphost, exercised RSA signing and verification, cryptographic randomness, and ICU-backed French decimal formatting, and ran an ASP.NET HTTP smoke test with isolated caches and an empty NuGet source list. All six functional checks passed in every environment.

| ARM64 user-space environment | Identity / ELF ABI | Console DLL / apphost | Crypto / ICU | ASP.NET HTTP |
| --- | --- | --- | --- | --- |
| WSL Ubuntu 22.04 | Passed | Passed | Passed | Passed |
| Ubuntu 24.04 container | Passed | Passed | Passed | Passed |
| Debian 13 container | Passed | Passed | Passed | Passed |

The final reports are `reports/verify-ubuntu22-retry1/verification.json`, `reports/verify-ubuntu24-retry1/verification.json`, and `reports/verify-debian13-retry1/verification.json`. Each report records the same archive SHA-256 and confirms that the extracted SDK contents match the archive. The ELF scan found no additional symbolic GLIBC requirements and passed the `2.23` ceiling. An observed `GLIBC_2.17` maximum does not by itself certify support for a distribution using glibc 2.17.

The first Debian verification stopped while building the console project because its inherited home pointed to `/root`, which the unprivileged verifier could not use for the SDK's mutex/cache state. The verifier now isolates `HOME` along with its caches in the temporary workspace. The failed report is retained, and the final verification passed in all three environments after that correction.

These environments share the WSL kernel. Symbol maxima and these smoke tests provide bounded compatibility evidence rather than a guarantee for every Linux distribution, workload, or third-party application. They do not validate NativeAOT publication or optional workloads.

## Upstream test baseline and results

The matching official Microsoft SDK `9.0.123` Linux ARM64 archive has been acquired solely for comparison tests. [fetch-test-sdk.py](../scripts/fetch-test-sdk.py) selected it from official release metadata and verified the archive's SHA-512. Its report is `reports/test-inputs/official-sdk-baseline.json`; the archive is isolated under `<Linux workspace>/inputs/official-sdk/` and is 206,564,317 bytes. The source build's bootstrap SDK remains the separate pinned `9.0.121` input.

For this ordinary build, `--test` runs `UnifiedBuild.Tests` and `scenario-tests`, with `/p:UBTestsMsftSdkArchivePath` pointing to the verified released comparison SDK. It does not run the source-only `SourceBuild.SmokeTests` path. The .NET 9 tag does not provide the .NET 10 `BinariesReportFile` integration.

The comparison tests inspect archive entry names and managed assembly versions; they do not establish bitwise equivalence or compare all managed code contents. The upstream `UBTestsWarnOnContentDiffs=true` default remains in effect. Moreover, the tagged package comparisons contain filename and assembly-loop defects: one package-content test overwrites its test listing instead of writing the baseline listing, assembly comparison reads its temporary lists in reversed roles, and the assembly loop can stop at the first non-managed ZIP entry. The common diff helper checks Git's stdout without validating its exit code or stderr, so a Git failure can appear as an empty difference. These limitations also qualify comparisons that use that helper. [Package comparison source](https://github.com/dotnet/dotnet/blob/v9.0.123/test/Microsoft.DotNet.UnifiedBuild.Tests/NugetPackageContentTests.cs#L47-L112), [diff helper](https://github.com/dotnet/dotnet/blob/v9.0.123/test/Microsoft.DotNet.UnifiedBuild.Tests/BaselineHelper.cs#L80-L85), [warning-policy default](https://github.com/dotnet/dotnet/blob/v9.0.123/test/Microsoft.DotNet.UnifiedBuild.Tests/Microsoft.DotNet.UnifiedBuild.Tests.csproj#L6).

The recorded 500 passes are the actual test-runner result. They do not establish complete NuGet package-content or assembly equivalence. The independent SDK execution, shared-framework byte comparisons, and ELF ABI results above remain separately supported.

The complete upstream test invocation at `reports/runs/test-20261029T1702000484091Z` finished with exit code 0 in **6 minutes 59.40 seconds**. Its scenario XML records **34 total cases: 32 passed, 2 skipped, 0 failed, and 0 errors**, with a duration of approximately **334.83 seconds**. The two explicit skips are `VerifyWorkloadCmd` and `VerifyAspireTemplate`. MultiTFM and platform-specific exclusions apply before execution and are not counted among those two skips.

| Test group | Result | Evidence |
| --- | --- | --- |
| `UnifiedBuild.Tests` | **500 passed, 0 failed, 0 skipped** | `reports/upstream-tests/Results/Microsoft.DotNet.UnifiedBuild.Tests.trx`; comparison limitations above apply |
| `scenario-tests` | **32 passed, 2 skipped, 0 failed, 0 errors** | `reports/upstream-tests/Results/scenario-tests/2026-10-29_17_03_08.xml` |
| Separate clean-source BinaryToolKit validation | Passed | `reports/source-binaries-retry1/status.json` |

Generated SDK archives, inputs, caches, and reports remain local and are ignored by Git. No publication or GitHub CI migration is recorded by this report.
