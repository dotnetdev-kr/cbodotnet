# .NET 5.0.214 native ARM64 build report

Snapshot: 2026-10-31, Asia/Seoul. The portable Linux ARM64 SDK build, local shared-framework origin audit, complete upstream shell smoke suite and three controlled native verification runs passed.

| Artifact | Value |
| --- | --- |
| SDK | `5.0.214`, `linux-arm64` |
| Shared frameworks | Microsoft.NETCore.App `5.0.17`; Microsoft.AspNetCore.App `5.0.17` |
| Collected archive | `artifacts/5.0.214-linux-arm64/cbodotnet-sdk-5.0.214-linux-arm64-build.1.tar.gz` |
| Bytes | `228004027` |
| SHA-256 | `ac3350e3a87a79de5aedaa632d3eca7e8054e4d76d15681da5980ea90589429c` |
| SHA-512 | `06e49e8681f103648834cc40559fc48cb596b6947f5f4b8b7404d606f7dc30c572251225fa76597259d7149e953129f7794f716828c31399f07d8a0323e81e42` |

The collected archive is a byte-exact copy of the produced `dotnet-sdk-5.0.214-linux-arm64.tar.gz`. Its manifest and checksum files accompany it. This report describes this specific artifact; another build needs its own matching origin and verification evidence.

## Source selection and environment

The final `release/5.0` [source-build graph](https://github.com/dotnet/source-build/tree/d414ecb2d997a9b3f38aaaeddace30ca097e546d) coordinates SDK `5.0.214` and runtime `5.0.17`. SDK `5.0.408` is the latest published SDK across all feature bands. The selected 2xx version is the final full graph represented by this branch. There is no `v5.0.214-SDK` tag; the branch commit is pinned instead. This version builds the `dotnet/source-build` repository directly, using its committed dependency manifest and normal build targets.

| Input | Revision or identity |
| --- | --- |
| Source-build root | `d414ecb2d997a9b3f38aaaeddace30ca097e546d` |
| Runtime | `6a984143635bde23e728abaaccbde52f5ea8fa3e` |
| ASP.NET Core | `02c6de4ba6022025fcda7581415f310f8c73cdc3` |
| SDK component | `3fdf76c35026e311b7edc245d4b3d9e812fe532e` |
| Installer component | `430330f7c5428f031b4a835be3dcf5945f55a56a` |
| Bootstrap SDK | Official Linux ARM64 SDK `5.0.212` |
| Retained bootstrap Arcade | `5.0.0-beta.20431.1`, source commit `6eec4404c2df5bfa46e5da52383c881c5cca3a9f` |
| Container base | ARM64 Focal SDK image digest `a4028735b2ed1209c9116cebc74ae1c2fb27ea7d24b1be3f495fee0bac27dd52` |
| Actual builder image | `d7f3d9624f9f2ec9d6dfb3c0ed1743eab582378d0a4ee40dfb0bc9e66bed288a` |

The workspace was `/home/build/cbodotnet/net5` in the dedicated ARM64 WSL2 distribution `cbodotnet-net7-arm64`. Source, inputs and container state were isolated from the other SDK versions. One workspace mount preserves the absolute paths and allows atomic cache preservation. The graph declares 28 dependencies and exported 27 pinned repositories, respecting the upstream ignored-repository configuration. Full-history bare stores supply the upstream Git commit-count metadata. A guarded direct-Git acquisition adapter replaces unavailable Darc acquisition while retaining the real `FetchSources` target and its completion behavior.

Native compilation used Clang 9 and the signed ARM64 Xenial sysroot. The original sysroot generator SHA-256 is `bd94cd8083b3b9ddcb7e3187181f296254e7c227e1a117a83940f29e5d8a61ef`. The provenance report records valid Release signatures, package versions, file hashes and symlink targets. Package signature verification remained enabled. Execution was native ARM64; the debootstrap wrapper does not imply CPU emulation.

The actual compiler commands contain `--target=aarch64-linux-gnu`, `--gcc-toolchain=.../arm64-xenial/usr` and `--sysroot=.../arm64-xenial`. The root selects `PortableBuild=true`, `CrossBuild=true`, `UseSystemLibraries=false` and `UseSystemLibunwind=false`. Native work remained on CPUs `4,5`. The upstream source-build configuration disables PGO optimization; official-binary performance parity and bit-for-bit reproducibility are outside these results.

## Build changes and recovery

Five exact, guarded product patches cover four files:

1. Run the main native ARM64 crossgen for CoreLib in same-system sysroot mode. The actual log records successful native CoreLib generation with that executable.
2. Condition the upstream ASP.NET nonportable runtime-reference patch on `PortableBuild` so the existing portable reference remains unique.
3. Preserve an explicit source-clone command during the upstream target's execution.
4. Route the retired dotnet-core index and its old myget alias to the official dotnet-public feed.
5. Extend that mapping to the remaining reviewed tools and nuget-build service indexes.

The applicator validates pinned source inputs, patch digests, original/intermediate/final hashes and complete staged patch chains before applying pending transitions. The normal upstream component patch chain and build-time configuration injections remain active. The authored patch count is not a count of every changed source file.

Bootstrap preparation preserves the original SDK/previous-source-build archives and root `global.json`. It extracts the exact retained Arcade package, builds and installs the upstream custom SDK resolver, then proves that the old requested Arcade version resolves to the retained version. Resolver restore and compilation use separate MSBuild evaluations. The normal root driver uses `DotNetBuildFromSource=true`, as required by this retained source-built toolset. A subsequent upstream resolver reinstall is accepted only with a matching local build output, pinned producer and successful completion marker; the original prepared receipt remains unchanged.

The Focal SDK base inherited `NUGET_XMLDOC_MODE=skip`. The first full graph reached SDK publishing with the correct locally built F# compiler package, but NuGet had omitted `FSharp.Core.xml` from its extracted cache. The package itself contained the file. Recovery sets `NUGET_XMLDOC_MODE=none`, verifies unchanged retained archives, preserves the affected cache version directories with complete file receipts and stages the same archives in an owned local feed. Normal NuGet restore performs the new extraction. The successful recovery preserved 344 affected package directories covering 1,680 missing XML documentation files.

Signed-package metadata uses NuGet's canonical content hash. The bounded helper verified 257 signed packages through the private SDK's `PackageArchiveReader.GetContentHash` API, while independently checking raw archive SHA-512 against `.nupkg.sha512`. Those two hash meanings remain distinct. Earlier failed preflight reports were retained. The shared helper additionally records a narrowly reviewed duplicate SDK icon case needed by Core 3.1; this .NET 5 smoke run used its original frozen helper snapshot.

The successful root attempt was `build-20261030T1841295823486Z`, finishing at `2026-10-30T18:44:42Z`. Its upstream cached continuation took `2:56.10`; this is not a cold full-build duration. Earlier attempts retained the completed runtime, ASP.NET and compiler work. Runtime compilation and packaging took approximately `16:42.55`; ASP.NET took approximately `6:55.76` in the earlier graph attempt.

## Shared-framework construction

The framework identity report and separate origin report establish:

| Framework | Exact matching shared-tree entries | Completed local installer copies |
| --- | ---: | ---: |
| Microsoft.NETCore.App 5.0.17 | 186 | 1 |
| Microsoft.AspNetCore.App 5.0.17 | 139 | 1 |

The closed installer `artifacts/log/Release/Build.binlog` replay read 33,847 events and retained two successful `DownloadFile` tasks. Each required one local `Copying` event between its own start and successful finish. Stable full-file hashes bind each consumed local blob to the actual installer destination and to the compared framework archive. Runtime also has a matching asset-feed copy; this ASP.NET version publishes directly to the local blob layout, with no duplicate asset-feed archive claimed.

The local archives are 93,508,616 bytes for runtime and 8,277,654 bytes for ASP.NET. The final SDK's shared trees match every compared file hash and symlink target. The comparison utility alone reports `originVerified=false`; the separate successful task and copy audit supplies the construction proof. The public profile records `upstreamSharedRuntimeReused=false` for the SDK SHA-256 above.

## Functional and native results

The complete upstream shell suite passed in `test-20261030T1905120983768Z`: 68 cases started and finished, covering 34 local-source and 34 online-source cases, both HTTPS certificate setups and XML documentation checks. Its upstream command exited zero; execution took `12:44.43`. The retained outputs archive contains 292 log/configuration/binlog files. The suite exercises C#, F# and VB templates, builds, runs, unit tests and publish paths, including cross-RID publishes that can consume external test packages. The local-source phase also permits the configured public feeds.

One separate test-only patch changes the `setupDevCerts` function to use the fresh SDK's built-in `dotnet dev-certs https`. The original preview global tool was unavailable on the checked official feeds. Original/adapted scripts, exact patch scope and hashes are retained; every HTTPS case and assertion remains present. The SDK tool DLL matches both the actual ASP.NET build output and local package member: SHA-256 `abfc01ecb14d7f8d47caccfca8d5ff18a03afcb5283dcc0ae00312ed450847a5`. Test preparation extracts the actual archive afresh and preserves prior test directories. Completion requires all 68 cases, two certificate setups, exact terminal markers and unchanged archive/tool bytes. Stage 2 was not run.

| Native environment | Reported SDK RID | Six functional checks | Shipped ELF ABI |
| --- | --- | --- | --- |
| Ubuntu 22.04 | `linux-arm64` | Passed | 18 AArch64; GLIBC 2.17; GLIBCXX 3.4.21; CXXABI 1.3.7 |
| Ubuntu 24.04 | `linux-arm64` | Passed | Same |
| Debian 13 | `linux-arm64` | Passed | Same |

The six checks cover console DLL/apphost execution, RSA SHA-256 signing and verification, cryptographic randomness, French decimal formatting and an ASP.NET loopback HTTP request. All runs bind the same SDK archive. Initial Ubuntu RID assumptions stopped before the functional tests; their reports remain under `verification-attempts`. The pinned CLI falls back to its build RID when the shared framework does not support the current host RID.

These are controlled OpenSSL 1.1 runs. The separate compatibility input exports `libssl.so.1.1`, `libcrypto.so.1.1`, copyright and configuration from the exact builder image. The library package is `1.1.1f-1ubuntu2.24`; the configuration package is `1.1.1f-1ubuntu2.16`, both ARM64 and the same upstream OpenSSL `1.1.1f`. Exact package ownership, file hashes and environment mappings are recorded. The SDK archive remains unchanged. These results cover the supplied dependencies rather than stock OpenSSL-3-only crypto environments. No extra ICU libraries were supplied: the compiled Linux ICU loader searches majors 50–85, and the native globalization checks passed.

## Binary-input audit and retained evidence

The upstream prebuilt report contains 10,467 usage rows and 305 distinct case-insensitive-ID/exact-version-string pairs. The online baseline comparison reports two new entries, for `Microsoft.DotNet.SignTool 5.0.0-beta.20459.8` and `Microsoft.SymbolUploader.Build.Task 1.1.142502`, plus 104 removed baseline identities. The build logs report the baseline differences as nonfatal warnings, including `SucceededWithIssues`; the baseline was preserved. Raw version-pair counts and NuGet semantic identity counts have different meanings.

The audit preserves 37 report files, 30 version snapshots and an assets ZIP with 816 `project.assets.json` members. These reports, the official bootstrap SDK, retained Arcade input, restored packages and XML-recovery archives make the binary inputs visible. This is an online source-build graph with binary bootstrap/dependency inputs. No entirely prebuilt-free build or clean-baseline claim is made.

Evidence is under `artifacts/5.0.214-linux-arm64/reports/`: `construction/`, `prebuilt-audit/`, `sysroot/`, `runs/`, `verification-compat-input-retry2/` and the three `verify-*` directories. Frozen audit sources and private-analysis-state declarations are in `origin-tools/final-net5/`. The archive manifest inventories the retained reports and records direct-root/component identities. See [the reproduction procedure](reproduce-net5-arm64.md) for commands and input contracts.
