# Building .NET SDK 6.0.136 on ARM64 Linux

Status snapshot: **2026-10-31, Asia/Seoul**. The complete legacy source-build graph produced SDK `6.0.136` with runtime and ASP.NET `6.0.36`. Both local framework origin audits, the upstream smoke suite and independent native checks in Ubuntu 22.04, Ubuntu 24.04 and Debian 13 passed. The unchanged archive was collected with checksums. See the [build report](build-report-6.0.136-arm64.md) for measured results and validation limits.

## Source and environment

The [profile](../profiles/dotnet-6.0.136-linux-arm64.json) pins `dotnet/installer` tag `v6.0.136`, commit `d638663530d923adbe0442604b7a6562127321e9`. This is the selected final 1xx source-build generation, coordinated with runtime `6.0.36`. The latest published .NET 6 SDK across feature bands is `6.0.428`; this build does not relabel its output as that SDK. The project provides community builds independently of the upstream support lifecycle.

.NET 6 uses the installer repository to generate the complete source-build tree. It is not the VMR build path used here for .NET 8 and later. The upstream [generation instructions](https://github.com/dotnet/installer/blob/v6.0.136/src/SourceBuild/README.md), [dependency manifest](https://github.com/dotnet/installer/blob/v6.0.136/eng/Version.Details.xml) and [source templates](https://github.com/dotnet/installer/tree/v6.0.136/src/SourceBuild/tarball/content) define that route.

The recorded host is native Windows ARM64 with the existing D-backed WSL 2 distribution `cbodotnet-net7-arm64`. Linux user `build` has UID:GID `1000:1000`. The .NET 6 workspace, source tree, inputs, container home and reports are separate from the .NET 7 workspace:

```text
/home/build/cbodotnet/net6/
  work/installer-v6.0.136/   # Pinned generator checkout
  work/source-v6.0.136/      # Generated full source-build tree
  inputs/                   # Independent sysroot and preserved bootstrap inputs
  container-home/           # Version-specific home and caches
```

For a fresh machine, establish a native ARM64 WSL environment with Podman and an unprivileged build account first. The fresh-only initializer and storage requirements are documented in the [.NET 7 reproducer](reproduce-net7-arm64.md). An existing distribution must not be reimported or overwritten. The .NET 6 wrapper accepts another existing distribution through `-Distribution`, together with a consistent `-LinuxUser` and absolute `-LinuxWorkspaceRoot`.

[arm64-net6.Containerfile](../containers/arm64-net6.Containerfile) uses the official Ubuntu 24.04 ARM64 prerequisites base, digest `sha256:7ef8f6ee1b9982511349757443eb4844f0db4f8cef1aff6148a7ba1c25d7c6f4`, with LLVM/clang/LLD 16. The observed derived image is `f5d51031836414245009084e7bb78edc8daf305af750f5e75a5af885b95828d8`. The pinned runtime's compiler discovery supports LLVM 16. Target headers and libraries come from an independently prepared ARM64 Xenial sysroot, separate from the container's host libraries.

## Public Windows entry point

[Invoke-Net6Build.ps1](../scripts/Invoke-Net6Build.ps1) provides the following modes:

```powershell
Set-Location D:\Projects\cbodotnet
Get-Help ./scripts/Invoke-Net6Build.ps1 -Full
./scripts/Invoke-Net6Build.ps1 -Mode Generate
./scripts/Invoke-Net6Build.ps1 -Mode Prepare
./scripts/Invoke-Net6Build.ps1 -Mode Build
./scripts/Invoke-Net6Build.ps1 -Mode Test
```

Run later modes after the preceding action succeeds. Defaults select the existing `cbodotnet-net7-arm64` distribution, user `build`, workspace `<Linux HOME>/cbodotnet/net6`, and image `localhost/cbodotnet-arm64:6.0.136`.

The generator checkout mounts at `/installer`; the generated source parent mounts at `/work`, inputs at `/inputs`, and this project at `/project`. The generated root is therefore `/work/source-v6.0.136`. Mounting the parent matters because upstream removes and recreates its generation destination.

Build and test processes run as the selected unprivileged UID:GID. Only fresh sysroot preparation uses a dedicated privileged root container with read-only source mounts. The .NET 6 seccomp helper derives the host policy with one additional `fchmodat2` allow rule, preserving the default action and every other rule. The recorded policy SHA-256 is `433ff4d41a88c0c37acf4372cfd84b13399c3a831037ee269141508d1538f990`; it is not an unconfined policy.

Every action has a unique directory below `artifacts/6.0.136-linux-arm64/reports/runs/`, including commands, status, resource measurements, image/policy provenance and frozen rebuild inputs. Existing input archives, failed attempts and source trees are retained.

## Generate and seal the complete sources

`Generate` uses the upstream command shape:

```bash
cd /installer
./build.sh /p:Configuration=Release /p:ArcadeBuildTarball=true \
  /p:TarballDir=/work/source-v6.0.136 \
  /p:PreserveTarballGitFolders=true /p:ConvertInternalRepos=true
```

[source6-provenance.py](../scripts/source6-provenance.py) records the generated archive, all `git-info` files and **26 component revisions** in `reports/generation/generation.json`. Later modes verify that snapshot and the separate installer checkout. The generated root need not itself be a Git repository.

Critical revisions include runtime `f1dd57165bfd91875761329ac3a8b17f6606ad18`, ASP.NET `64ea4108e7dcf1ca575f8dd2028363b0b1ef6ebc`, SDK `1d205826ddc14c8f868eb6373e7a6bafcb9fe5be`, and source-build `7649ca7106e7e91ac06f169626bf01a77c2258eb`. The recorded source archive is `dotnet-sdk-source-6.0.136.tar.gz`, 1,132,801,701 bytes, SHA-256 `e1b43aeb3e61cc030b570b2e5f2ed99b32b9ffa72cb3ee27320c7dcc58ee901c`.

## Prepare an independent signed sysroot

[prepare-sysroot6.sh](../scripts/prepare-sysroot6.sh) verifies the generated installer/runtime identities and the unchanged runtime producer before running:

```bash
./eng/common/cross/build-rootfs.sh arm64 xenial --rootfsdir /inputs/arm64-xenial
```

The helper refuses an existing target because upstream recreates that target recursively. Current and historical Ubuntu archive keyrings are combined while package signature verification remains enabled. Its recorded generator SHA-256 is `efaddf18971de883465ef172297cbb9821b2568fc2f41f360a0ba2e74eaa3704`.

Retain `reports/sysroot/sysroot-provenance.json`, package versions, complete file hashes and symlink inventories. [verify-sysroot6.py](../scripts/verify-sysroot6.py) checks the exact recorded file/link sets and bytes before subsequent actions. The ARM64 target executes natively; the upstream qemu-debootstrap wrapper does not imply emulation on this ARM64 host.

## Preserve the original bootstrap before transformation

In this generation, ARM64 bootstrap transformation is explicit. [prepare-source6.sh](../scripts/prepare-source6.sh) and [bootstrap6-inputs.py](../scripts/bootstrap6-inputs.py) perform the sequence:

```bash
cd /work/source-v6.0.136
./prep.sh
# Preserve and verify the original archives outside the upstream discovery glob.
./prep.sh --bootstrap
```

The first step initializes native SDK `6.0.135` and downloads `Private.SourceBuilt.Artifacts.6.0.135.centos.7-x64.tar.gz`. The wrapper preserves it under `/inputs/original-bootstrap6/` before upstream removes it during transformation. A verified preparation marker and the actual `Private.SourceBuilt.Artifacts.Bootstrap.tar.gz` are required for later actions; finding an arbitrary or incomplete original archive is insufficient.

.NET 6's project is **`scripts/bootstrap/buildBootstrapPreviouslySB.csproj`**, not the .NET 7 `eng/bootstrap` path. Its ARM64 substitutions are four `PackageReference` entries. The observed transformed archive contains:

| ARM64 bootstrap package | Observed version |
| --- | --- |
| `runtime.linux-arm64.Microsoft.NETCore.ILAsm` | `6.0.36-servicing.24502.8` |
| `runtime.linux-arm64.Microsoft.NETCore.ILDAsm` | `6.0.36-servicing.24502.8` |
| `runtime.linux-arm64.Microsoft.NETCore.TestHost` | `6.0.25-servicing.23520.6` |
| `runtime.linux-arm64.runtime.native.System.IO.Ports` | `4.7.0` |

Restore emitted `NU1603`: the requested `6.0.35-servicing.24467.1` IL SDK/ILAsm/ILDAsm packages were unavailable, and the actual resolution was `6.0.36-servicing.24502.8`. It also emitted `NU1604` for references without inclusive lower bounds. Preserve these warnings and the resolved archive inventory; do not describe requested versions as the versions actually acquired.

The original archive was 4,149,235,810 bytes, SHA-256 `9b6befe3f7aab2bdb876940c89cc7bc738fa3e96effef619b701da9e8768fdb9`. The transformed archive was 4,160,349,330 bytes, SHA-256 `c1ebe70daa7ce98ef20450e1b89715497976d6750d96b75ab9eb5738715e95a8`. Preparation reports also fingerprint the versioned SDK files and bootstrap sources. An unversioned host executable can change when upstream initializes additional pinned runtimes, so its initial fingerprint is recorded as an observation.

## Apply the four guarded patches and build once per runtime target

[apply-net6-patches.py](../scripts/apply-net6-patches.py) applies four fixed patches across three files:

- [0001](../patches/net6/0001-support-arm64-cross-components-host.patch) recognizes the native Linux ARM64 build host for required CoreCLR cross-components.
- [0002](../patches/net6/0002-preserve-portable-runtime-target.patch) honors explicit `PortableBuild=true` while retaining the runtime adapter's original nonportable default.
- [0003](../patches/net6/0003-build-portable-runtime-once.patch) conditions the runtime node's `runtime-portable` dependency on `PortableBuild != true`.
- [0004](../patches/net6/0004-select-one-portable-runtime-root.patch) applies the same condition to the direct root reference in `known-good.proj`.

For an explicitly portable SDK, the regular runtime node now builds the portable outputs once. False or unset portability preserves the original graph. The .NET 6 ASP.NET adapter does not force `PortableBuild=false`, so the .NET 7 ASP.NET patch is not copied. No unrelated IdentityModel/date patch is used.

The patch helper verifies pinned source identities, fixed patch scopes and every file/patch hash. It stages complete ordered transitions in a separate temporary Git worktree before its first source write. It accepts pristine files, the exact earlier two-patch state and the exact final state; unknown edits fail. Reports use `net6-patches-apply.json` schema 3. Package-creation checks remain enabled.

[build-source6.sh](../scripts/build-source6.sh) exports `PortableBuild=true`, `CrossBuild=true`, `TargetRid=linux-arm64`, `ROOTFS_DIR=/inputs/arm64-xenial`, `BUILD_SOURCEVERSION=d638663530d923adbe0442604b7a6562127321e9`, and explicit LLVM 16 compiler paths. The actual build is:

```bash
./build.sh --clean-while-building --online -- \
  /p:Configuration=Release /p:Platform=arm64 /p:TargetOS=Linux \
  /p:TargetRid=linux-arm64 /p:PortableBuild=true /p:CrossBuild=true /m:2
```

The recorded build uses CPUs `0,1`. Its successful retry completed the complete root graph in **20 minutes 41.79 seconds**. It reused verified component outputs from earlier attempts; this duration is not a clean-build benchmark.

An earlier attempt built both portable runtime passes with identical identities. The child succeeded, but the outer `EnsurePackagesCreated` check correctly rejected the second pass because no new identities appeared. The correction changed the graph rather than suppressing that check. For the recorded cached recovery, 43 verified runtime-owned feed/semaphore files were moved to an isolated quarantine; payloads were checked against their actual intermediate ZIP members and all three intermediate archives/logs were retained. Fresh runs with all four patches do not need that historical recovery.

## Verify the output and its component origins

The upstream output is:

```text
/work/source-v6.0.136/artifacts/arm64/Release/dotnet-sdk-6.0.136-linux-arm64.tar.gz
```

The reusable comparison command is:

```bash
python3 /project/scripts/inspect-sdk-construction9.py \
  --sdk-archive /work/source-v6.0.136/artifacts/arm64/Release/dotnet-sdk-6.0.136-linux-arm64.tar.gz \
  --runtime-archive /work/source-v6.0.136/artifacts/arm64/Release/runtime/dotnet-runtime-6.0.36-linux-arm64.tar.gz \
  --aspnetcore-archive /work/source-v6.0.136/artifacts/obj/arm64/Release/blob-feed/assets/aspnetcore-runtime-internal-6.0.36-linux-arm64.tar.gz \
  --runtime-version 6.0.36 --reports-dir /project/artifacts/6.0.136-linux-arm64/reports/construction
```

The utility's filename retains its original .NET 9 naming; its explicit archive/version interface also compares this output. Byte identity alone intentionally leaves `originVerified=false`.

For a local-origin claim, additionally preserve the actual installer's completed `DownloadFile` events. Each selected task must have a start, exactly one local `Copying` attempt and a successful finish, with no network attempt. Source and destination paths must resolve to the expected local archive and installer location, and their full-file hashes must match. Capture destinations before cleanup; candidate URL properties or missing post-cleanup files do not prove which input was used.

The recorded observer captured both destinations at `2026-10-30T17:42:11Z`. The completed log replay and `reports/construction/origin-evidence.json` independently passed for **181 core-runtime entries and 134 ASP.NET entries**. Per-run audit tool sources and the closed installer binlog are preserved under `reports/origin-tools/final-net6/`. Upstream cleanup retains closed child logs below `src/installer/artifacts/buildLogs/`; do not copy or replay a live binlog.

After the origin audit and upstream tests, collect without repacking, then verify that exact collected archive in each native user space:

```powershell
./scripts/Invoke-Net6Build.ps1 -Mode Collect
```

The profile's construction declaration must contain the collector's explicit boolean and the verified evidence note. Provisional or unknown construction declarations must not be silently converted into an origin claim. The collector checks the installer, generated-source snapshot and archive digests; functionality and ABI checks remain separate. Run collection through this public wrapper: the sealed generation record contains the container path `/installer/artifacts/packages/Release/Shipping/dotnet-sdk-source-6.0.136.tar.gz`, so invoking the collector outside those mounts correctly fails. Preserve an unsuccessful collection attempt rather than rewriting that record.

`Test` uses a fresh extracted SDK directory and the actual upstream suite. It supplies the pinned OmniSharp `1.39.6` native ARM64 net6.0 fixture with the recorded `run -> OmniSharp` launcher adapter, without excluding those scenarios. An exact official `6.0.136` archive is an optional layout-comparison baseline, separate from the community output. `SMOKE_TESTS_WARN_SDK_CONTENT_DIFFS=true` changes only that content comparison to warning mode; retain any mismatch diagnostics.

The recorded suite passed **41 of 42 cases**, with zero failures and one `PoisonTests.VerifyUsage` skip because no poison report was supplied. All twelve OmniSharp scenarios passed. Upstream retained **215 smoke-test prerequisites**. The runner used bootstrap runtime `6.0.35`, while the tested SDK scenarios used the freshly extracted `6.0.136` archive. Preserve `reports/runs/test-20261030T1752110359200Z/test.log`, its status, tool-input records and original test results when auditing that run.

The actual `SdkContentTests.CompareMsftToSb` result is **Passed with a warning-mode baseline mismatch and `SucceededWithIssues`**. The normalized current official/community layout diff has **101 added/141 removed entries**, while the historical expected diff has **120 added/141 removed entries**. No equal-layout, binary equality or API compatibility result follows from that passed method. `reports/sdk-comparison/summary.json` retains exact fingerprints for 29 original/derived evidence and control files: original TRX, full stdout/stderr, full actual/baseline diffs, normalized lists, exclusions, test/policy sources and input receipts. This was an evidence-preservation operation with no test rerun or source/cache/SDK change.

Run [verify-sdk.sh](../scripts/verify-sdk.sh) with `--framework net6.0`, the exact SDK version, and `--max-glibc 2.23` on each recorded native user space. It checks ELF requirements and isolated console/apphost, cryptography, ICU and HTTP scenarios. The host-reported RID is evidence and may differ from the archive's portable RID.

For example, in a native Ubuntu 22.04 verification container with project mounted at `/project` and the collected release at `/artifacts`, use a new report directory:

```bash
bash /project/scripts/verify-sdk.sh \
  --archive /artifacts/cbodotnet-sdk-6.0.136-linux-arm64-build.1.tar.gz \
  --output-dir /artifacts/reports/verify-ubuntu22-new \
  --expected-version 6.0.136 --expected-rid ubuntu.22.04-arm64 \
  --framework net6.0 --max-glibc 2.23
```

For the recorded Ubuntu 24.04 user space the expected host RID is `ubuntu.24.04-arm64`; Debian 13 reports `linux-arm64`. All three passed six functional checks and inspection of **22 AArch64 ELF files**. Maximum required versions were **GLIBC `2.17`, GLIBCXX `3.4.21` and CXXABI `1.3.7`**. Their reports are `reports/verify-ubuntu22/`, `reports/verify-ubuntu24/` and `reports/verify-debian13/`. An initial Ubuntu 24.04 RID assumption failed before functional checks and remains in `reports/verification-attempts/ubuntu24-rid-assumption/`; correcting the expected RID required no SDK change.

The final archive is **219,157,249 bytes**, SHA-256 `099fc4f37a1ae1f8b722b2f918b9f2fa4d137f91790d2c1e987d1c4cd630f3ba`. Collection copies it unchanged and writes `build-manifest.json`, `SHA256SUMS` and `SHA512SUMS` beside it.

The source-build route uses an upstream SDK, transformed previous-build artifacts, reference packages, host tools and online inputs. `sourceOnly=true` does not mean every input was rebuilt, that the build is clean-bootstrapped, or that an offline Stage 2/poisoning run passed. Keep prebuilt-report classification, local framework origin, functionality and distribution compatibility as separate results.

The prebuilt aggregate's zero usage/new/removed counts also have a baseline limit: the declared default `tools-local/prebuilt-baseline.xml` is absent, and the pinned validator falls back to an empty usage set when its selected file is missing. The preservation audit records that default/fallback behavior without reevaluating MSBuild overrides. Those zero counts are not agreement with a populated historical baseline or proof that bootstrap/reference/online binary inputs were eliminated.
