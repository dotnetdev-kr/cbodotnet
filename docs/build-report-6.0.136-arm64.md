# .NET SDK 6.0.136 ARM64 build report

Status snapshot: **2026-10-31, Asia/Seoul**. SDK `6.0.136` for portable Linux ARM64 passed the complete root source-build graph, both shared-framework origin audits, upstream smoke tests and independent native checks in Ubuntu 22.04, Ubuntu 24.04 and Debian 13. The unchanged archive and checksums were collected. Reproduction commands are in the [.NET 6 reproducer](reproduce-net6-arm64.md).

## Produced archive and source identity

The unmodified upstream output is `artifacts/arm64/Release/dotnet-sdk-6.0.136-linux-arm64.tar.gz` in the generated source tree:

| Field | Recorded value |
| --- | --- |
| SDK | `6.0.136` |
| Runtime / ASP.NET | `6.0.36` |
| Target | `linux-arm64`, glibc |
| Archive bytes | `219,157,249` |
| Archive SHA-256 | `099fc4f37a1ae1f8b722b2f918b9f2fa4d137f91790d2c1e987d1c4cd630f3ba` |
| Collected filename | `cbodotnet-sdk-6.0.136-linux-arm64-build.1.tar.gz` |
| Generator | `dotnet/installer`, `v6.0.136` |
| Generator commit | `d638663530d923adbe0442604b7a6562127321e9` |
| Runtime commit | `f1dd57165bfd91875761329ac3a8b17f6606ad18` |
| ASP.NET commit | `64ea4108e7dcf1ca575f8dd2028363b0b1ef6ebc` |
| SDK component commit | `1d205826ddc14c8f868eb6373e7a6bafcb9fe5be` |

This selects the final 1xx installer source-build graph. The newest published SDK across .NET 6 feature bands is `6.0.428`; it is a different SDK version. This project continues community build work independently of the upstream support lifecycle.

The generated full-source archive contains 26 component revisions. It is 1,132,801,701 bytes, SHA-256 `e1b43aeb3e61cc030b570b2e5f2ed99b32b9ffa72cb3ee27320c7dcc58ee901c`, recorded in `reports/generation/generation.json`. The generator completed its source archive in **5 minutes 9.24 seconds**. Component Git folders and `git-info` metadata were preserved; later actions verified them against the separate pinned installer checkout.

## Native environment and target inputs

Execution used the D-backed WSL 2 distribution `cbodotnet-net7-arm64`, user `build`, UID:GID `1000:1000`, with isolated .NET 6 work and inputs under `/home/build/cbodotnet/net6`. This reused an existing native ARM64 Linux environment without reusing its .NET 7 source/sysroot as .NET 6 evidence. No CPU emulation was used.

The Ubuntu 24.04 ARM64 builder image was `f5d51031836414245009084e7bb78edc8daf305af750f5e75a5af885b95828d8`, derived from official prerequisites digest `sha256:7ef8f6ee1b9982511349757443eb4844f0db4f8cef1aff6148a7ba1c25d7c6f4`. Actual tool output recorded clang **16.0.6** and CMake **3.28.3**. Build affinity was CPUs `0,1` with `/m:2` and `DOTNET_PROCESSOR_COUNT=2`.

The independent ARM64 Xenial sysroot completed at `2026-10-30T16:05:48.753383Z`. Its unchanged runtime generator SHA-256 is `efaddf18971de883465ef172297cbb9821b2568fc2f41f360a0ba2e74eaa3704`. Signature verification remained enabled; reports retain generator/keyring identities, target package versions, **19,323 file hashes** and **5,332 symlink entries**. Separate final ELF verification found maximum GLIBC `2.17`, within the selected `2.23` ceiling.

Unprivileged build/test containers used the host-derived seccomp policy with only `fchmodat2` additionally allowed, SHA-256 `433ff4d41a88c0c37acf4372cfd84b13399c3a831037ee269141508d1538f990`. The host default and all other policy rules remained unchanged. Fresh sysroot preparation alone used the dedicated privileged root container with source inputs read-only.

## Bootstrap preservation and actual resolution

The original native bootstrap SDK was `6.0.135`. Preparation first used upstream `prep.sh`, preserved the original archive outside its discovery glob, then explicitly ran `prep.sh --bootstrap`. .NET 6 declares four ARM64 `PackageReference` substitutions in `scripts/bootstrap/buildBootstrapPreviouslySB.csproj`.

| Input | Bytes | SHA-256 |
| --- | ---: | --- |
| Original `Private.SourceBuilt.Artifacts.6.0.135.centos.7-x64.tar.gz` | 4,149,235,810 | `9b6befe3f7aab2bdb876940c89cc7bc738fa3e96effef619b701da9e8768fdb9` |
| Transformed `Private.SourceBuilt.Artifacts.Bootstrap.tar.gz` | 4,160,349,330 | `c1ebe70daa7ce98ef20450e1b89715497976d6750d96b75ab9eb5738715e95a8` |

The transformed archive's ARM64 entries are ILAsm and ILDAsm `6.0.36-servicing.24502.8`, TestHost `6.0.25-servicing.23520.6`, and System.IO.Ports native runtime `4.7.0`. Restore reported `NU1603` because requested IL SDK/ILAsm/ILDAsm `6.0.35-servicing.24467.1` was unavailable and the `6.0.36-servicing.24502.8` approximate best match resolved. `NU1604` also reported references without inclusive lower bounds. These actual resolutions are retained rather than replaced with the requested versions in this report.

Preparation completed at `2026-10-30T16:29:04Z`, recorded in `reports/runs/prepare-20261030T1626063659764Z/bootstrap-inputs.json`. The original archive, source/version declarations, versioned SDK files, resolved replacements and transformed archive have independent fingerprints. An additional runtime initialization may replace an unversioned host executable; its original observation is not treated as an immutable versioned SDK input.

## Four fixed patches and the successful retry

The build uses [four guarded patches](../profiles/dotnet-6.0.136-linux-arm64.json): native ARM64 CoreCLR host detection, explicit runtime portability, and two graph conditions selecting a single portable runtime pass. The graph patches condition both the runtime dependency and the direct `known-good` reference to `runtime-portable` on `PortableBuild != true`. The regular runtime node remains required and builds the portable output. Default/nonportable behavior remains available.

The first attempt's native child work succeeded, but the second portable runtime pass produced identities already copied by the first. The unchanged outer `EnsurePackagesCreated` guard rejected that result. The fix changed the graph instead of disabling the guard or manufacturing a completion marker.

Before retrying, the recovery verified feed payloads against the three actual runtime intermediate ZIP archives, preserved those archives and logs, and moved **43 runtime-owned feed/semaphore files** to an isolated quarantine. Unrelated outputs and source inputs remained in place. Evidence is in `reports/runs/runtime-graph-recovery-20261030T171952826987Z/recovery.json`.

The patch applicator preflights ordered exact hash states in a separate temporary Git worktree before changing source files. It accepts pristine content, the recorded two-patch state, or the final four-patch state. The existing first two patch files were retained unchanged. Schema 3 records the ordered runtime adapter transition and the final states of all three target files.

Successful attempt **`build-20261030T1724287684045Z`** ran from `2026-10-30T17:24:43Z` to `2026-10-30T17:45:25.798604Z`, exit code **0**. Upstream reported **20 minutes 41.79 seconds**, **115 warnings** and **zero errors**; GNU time measured **20 minutes 42.30 seconds** and maximum RSS **2,170,268 KiB**. This resumed verified earlier component outputs and is not a clean-build timing measurement.

The actual command was:

```bash
./build.sh --clean-while-building --online -- \
  /p:Configuration=Release /p:Platform=arm64 /p:TargetOS=Linux \
  /p:TargetRid=linux-arm64 /p:PortableBuild=true /p:CrossBuild=true /m:2
```

`BUILD_SOURCEVERSION` was the pinned installer commit. Shipping native compilation used explicit LLVM 16 compiler paths and the recorded target sysroot. The independent ABI and functionality results below verify the produced archive separately.

## Local shared-framework origin passed

`reports/construction/shared-framework-identity.json` compared all regular-file bytes and symbolic-link targets under the final SDK's two shared-framework directories:

| Framework | Version | Identical entries |
| --- | --- | ---: |
| `Microsoft.NETCore.App` | `6.0.36` | 181 |
| `Microsoft.AspNetCore.App` | `6.0.36` | 134 |

Neither comparison had missing, additional or changed entries. The selected local runtime archive was 62,893,168 bytes, SHA-256 `cbba686bf749cd39a944643dcfebb05a8cb7187e7f64d2b4e16c169dc05e5f19`. The ASP.NET internal archive was 8,791,935 bytes, SHA-256 `6a77f1c18dc7d3b8e35a30d2eb0e7c3fcff49af86eadee2a217bd3162d64236f`.

The installer command selected `CoreSetupRid=linux-arm64`, `AspNetCoreInstallerRid=linux-arm64`, and the local `file:///work/source-v6.0.136/artifacts/obj/arm64/Release/blob-feed/assets/` base. Those candidate parameters alone were not accepted as origin proof.

The observer captured both actual installer destinations at `2026-10-30T17:42:11Z` before cleanup, with stable full-file hashes equal to the local feed. The closed installer binlog was preserved from `src/installer/artifacts/buildLogs/source-build/self/src/artifacts/sourcebuild.binlog` and replayed without project evaluation. For each framework, the audit required **one completed sole-local-copy `DownloadFile` task**, with matching start, `Copying` source/destination and successful finish, plus matching destination bytes. Neither accepted task contained a network attempt.

`reports/construction/origin-evidence.json` passed and binds those task events, historical destination observations, local archive/feed hashes, SDK member comparisons, pinned source/generation metadata, all four patches and component-log fingerprints to SDK SHA-256 `099fc4f37a1ae1f8b722b2f918b9f2fa4d137f91790d2c1e987d1c4cd630f3ba`.

The comparison utility still correctly records `originVerified=false`: byte comparison alone does not prove origin. The separate origin report supplies the completed task and destination evidence. It does not claim that every dependency used to build those components was rebuilt from source.

## Prebuilt reporting

The preserved aggregate reports **zero usage rows, zero new entries and zero removed entries**, with **34 reports preserved**. Coverage records **2,798 assets JSON files**, **33 project-directory entries** and **28 package-version snapshots**. All eight reviewed .NET 6 usage-report source files are byte-identical to the .NET 7 versions; the observed default baseline path and nonfatal aggregate continuation policy also match.

The declared default `tools-local/prebuilt-baseline.xml` is **absent** from this generated tree. The original validator uses an empty baseline usage set when its selected file is missing. The retained controls and summary document this default/fallback scope; no MSBuild property overrides were reevaluated during the preservation audit. Zero new/removed entries therefore do not demonstrate agreement with a populated historical baseline.

The aggregate classifier subtracts previously source-built bootstrap packages and reference packages from its candidate set. Zero rows do not mean zero external binaries or prove complete scanner coverage. The build explicitly used the official SDK, transformed prior-build artifacts and native substitutions, reference packages, host tools and online feeds.

## Upstream tests, native verification and collection

The actual upstream suite ran in attempt `test-20261030T1752110359200Z`, from `2026-10-30T17:52:38Z` to `2026-10-30T17:56:59.335930Z`, exit code **0**. It reported **42 total, 41 passed, zero failed and one skipped**, in **4.1059 minutes**. The skipped case was `PoisonTests.VerifyUsage`, because no `SMOKE_TESTS_POISON_REPORT_PATH` was supplied. Poisoning was not performed.

All twelve OmniSharp scenarios passed with the pinned external `1.39.6` ARM64 net6.0 fixture and its recorded `run -> OmniSharp` launcher adapter. No test implementation or scenario exclusion was added. The xUnit runner used bootstrap runtime `.NET 6.0.35`; scenario commands exercised the freshly extracted built SDK `6.0.136`. Upstream packaged **215 smoke-test prerequisites** for later use.

Each independent native run checked console DLL execution, native apphost execution, RSA SHA-256 signing and verification, cryptographic random bytes, `fr-FR` decimal formatting and ASP.NET loopback HTTP. All six checks passed in each user space, with the same archive hash and matched extracted content:

| Native user space | Reported host RID | Functional checks | ELF result |
| --- | --- | --- | --- |
| Ubuntu 22.04 ARM64 | `ubuntu.22.04-arm64` | 6 passed | 22 AArch64 files |
| Ubuntu 24.04 ARM64 | `ubuntu.24.04-arm64` | 6 passed | 22 AArch64 files |
| Debian 13 ARM64 | `linux-arm64` | 6 passed | 22 AArch64 files |

The maximum required symbol versions were **GLIBC `2.17`, GLIBCXX `3.4.21` and CXXABI `1.3.7`**. The `2.23` GLIBC ceiling passed. These are distinct container user spaces sharing the native WSL kernel. Symbol inspection covers regular ELF files in the SDK, excluding archive members, and does not establish every kernel or dynamically loaded dependency requirement.

The first Ubuntu 24.04 verification expected host RID `linux-arm64` and stopped at the identity assertion before its functional tests. Its reports remain under `reports/verification-attempts/ubuntu24-rid-assumption/`. A second attempt used the observed `ubuntu.24.04-arm64` RID and passed; the SDK archive was unchanged.

Final collection used the public `Invoke-Net6Build.ps1 -Mode Collect` container, retaining the generator's recorded `/installer` and `/work` paths. An earlier direct host invocation correctly rejected the immutable generation archive path because `/installer` was absent in that environment; the failed attempt was preserved. The collector's path or identity checks were not relaxed. `build-manifest.json`, `SHA256SUMS` and `SHA512SUMS` accompany the unchanged **219,157,249-byte** archive.

| Check | Recorded result |
| --- | --- |
| Complete root build | Passed |
| Both SDK shared-framework tree comparisons | Passed: 181 / 134 entries |
| Completed local installer consumption and destination hashes | Passed for both frameworks |
| Prebuilt aggregate and coverage preservation | Recorded; bootstrap/reference exclusions remain |
| Upstream smoke suite | Passed: 42 total, 41 passed, one poison case skipped |
| Independent native SDK/ABI verification | Passed: Ubuntu 22.04, Ubuntu 24.04 and Debian 13 |
| Unchanged final collection and checksums | Passed |
| Offline Stage 2 / poisoning | Not run |

The official SDK comparison input was a separately SHA-512-verified `6.0.136` archive, 171,088,243 bytes, recorded in `reports/test-inputs/official-sdk-baseline.json`. The actual `SdkContentTests.CompareMsftToSb` method **passed in explicit warning mode with a baseline mismatch and `SucceededWithIssues`**. Its current normalized layout diff contains **101 added and 141 removed entries**; the historical expected diff contains **120 added and 141 removed entries**. These are normalized/excluded layout entries, not binary equality or API compatibility results. The suite's result remains 41 passed, one skipped and zero failed.

`reports/sdk-comparison/summary.json` inventories **29 preserved evidence/control files**, including the original completed TRX, its full comparison stdout/stderr, both complete diffs, normalized input lists, exclusions, test/policy source controls and the official-input receipt. Original file copies have byte-exact SHA-256/SHA-512 inventories; the community and official archive fingerprints were independently rechecked. This snapshot did not rerun a test, modify source/cache inputs or change the SDK archive.

No offline Stage 2 build, clean bootstrap certificate, universal Linux compatibility claim, workload validation or complete elimination of prebuilts follows from these results.
