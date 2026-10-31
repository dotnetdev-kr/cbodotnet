# Moving the current builds to GitHub Actions

Assessment snapshot: **2026-10-31, Asia/Seoul**. This review covers the actual Linux ARM64 profiles for Core 3.0/3.1 and .NET 5–10, their wrappers/containers, retained resource records and current official GitHub documentation. No workflow, remote CI run or publication is implemented by this assessment.

**Implementation follow-up:** the [.NET 10 CI guide](ci-net10.md) records a [successful native hosted ARM64 run](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41191037279) and independent verification of its downloaded artifact. The regular .NET 10 profile completed preparation through final collection in 56 minutes 13 seconds, including a 45-minute 30-second SDK build and all upstream/native gates. The guide records actual resource observations and their scope. The requirements below remain the checklist for other profiles; the other version adapters and native x64 have not thereby been migrated.

**The Linux stages can move to GitHub Actions, but the current repository is not yet an unattended full-matrix pipeline.** Native hosted ARM64 and x64 machines exist. Remaining work includes Linux orchestration, durable historical inputs, a clean run of each final configuration and capacity measurements. A larger native Linux runner is the recommended first full-build pilot. Standard runners can validate produced SDKs, but their advertised 14 GB disk allocation is not an established full-build budget.

The current local results cover ARM64 only. Native x64 needs independent profiles, images, bootstrap/sysroot inputs and validation; changing `runs-on` or adding a matrix does not implement it. Community availability remains independent of Microsoft's support lifecycle. See [version coverage](dotnet-version-coverage.md), the [Linux portability review](linux-portability-review.md) and the separate [version-floor assessment](architecture-version-floor.md).

## Version-specific assessment

All eight selected profiles have local SDK archives and recorded upstream/native validation. All need a Linux replacement for their Windows/WSL orchestration. These conclusions do not cover every feature band of each major release.

| Profile and evidence | Actual reusable build path | CI recommendation and remaining gate |
| --- | --- | --- |
| [.NET 10.0.403](build-report-10.0.403-arm64.md) | Regular VMR, `sourceOnly=false`; Ubuntu 24.04/LLVM 18, signed Bionic target root. Local SDK components consume exact upstream portable runtime/ASP.NET packages. [Container](../containers/arm64-net10.Containerfile), [Bash](../scripts/build-vmr.sh). | First regular-build pilot. Preserve 4xx shared inputs, exceptional package hash, feed/XML handling and actual pristine-source scan. This does not migrate a complete source-only runtime build. |
| [.NET 9.0.123](build-report-9.0.123-arm64.md) | Regular VMR, `sourceOnly=false`; LLVM 18, signed Xenial root. Core runtime is local; ASP.NET uses the tagged upstream fallback. [Container](../containers/arm64-net9.Containerfile), [Bash](../scripts/build-vmr9.sh). | Separate regular-build adapter: `--rid`, NativeAOT compiler selection and `--ci` packaging differ from .NET 10. Run empty with final flags; local success reused earlier outputs. |
| [.NET 8.0.133](build-report-8.0.133-arm64.md) | Legacy VMR source-build, `sourceOnly=true`; LLVM 18, signed Xenial root, two source patches, original/transformed bootstrap retained. Both shared frameworks are local. [Container](../containers/arm64-net8.Containerfile), [Bash](../scripts/build-vmr8.sh). | First source-build-family pilot. Keep `prep.sh`, legacy property forwarding, pinned `BUILD_SOURCEVERSION`, strict reusable-artifact identity and symbol-input retry handling. Modern regular-build flags are not substitutes. |
| [.NET 7.0.120](build-report-7.0.120-arm64.md) | Installer-generated source tree; LLVM 16, signed Xenial root, ARM64 bootstrap transformation and four patches. Both frameworks are local. [Container](../containers/arm64-net7.Containerfile), [Bash](../scripts/build-source7.sh). | Portable stages, with extra source-generation storage. Port `Generate`, original-input preservation, explicit bootstrap transformation and collection separately; retain sealed generation records. |
| [.NET 6.0.136](build-report-6.0.136-arm64.md) | Separate installer-generated tree; LLVM 16, signed Xenial root, four ARM64 bootstrap replacements and four patches, including the single portable runtime graph. Both frameworks are local. [Container](../containers/arm64-net6.Containerfile), [Bash](../scripts/build-source6.sh). | Same orchestration family as .NET 7, with its own graph/bootstrap contract. Preserve actual test/baseline scope and the `/installer`/`/work` aliases required by generation records and collection. |
| [.NET 5.0.214](build-report-5.0.214-arm64.md) | Direct `dotnet/source-build`; Focal/LLVM 9, signed Xenial root, explicit bootstrap/feed/acquisition changes and local frameworks. [Container](../containers/arm64-net5.Containerfile), [Bash](../scripts/build-source5.sh). | Feasible legacy pilot after historical inputs/finalization tools are packaged. Full-history acquisition, XML-cache recovery, all 68 original cases and controlled OpenSSL 1.1 validation remain required. |
| [Core 3.1.426](build-report-3.1.426-arm64.md) | Direct split CoreCLR/CoreFX/CoreSetup graph; Focal/LLVM 9, signed Xenial root, eleven patches. [Container](../containers/arm64-core31.Containerfile), [Bash](../scripts/build-core31.sh). | Feasible legacy pilot with separate native-component origins and all 52 upstream cases. Retain OpenSSL 1.1 on modern user spaces and ICU 66 for Debian 13. Cold execution remains unmeasured. |
| [Core 3.0.103](build-report-3.0.103-arm64.md) | Direct split-runtime graph; Bionic/LLVM 6/GNU linker, signed Xenial root, 31 patches. Success used a verified incremental dependency/Toolset/CoreSDK closure. [Container](../containers/arm64-core30.Containerfile), [Bash](../scripts/build-core30.sh). | Highest migration risk. First complete a fresh final-configuration root build, or implement an independently verified staged closure. Preserve external templates, bootstrap/reference inputs and historical origin receipts; the local failed full graph must remain failed. |

`sourceOnly=true` describes the selected legacy graph mode. Bootstrap SDKs, previously source-built artifacts, reference packages and online inputs remain external. It does not establish clean bootstrapping, Stage 2, zero-prebuilt construction, offline operation or bitwise reproducibility. .NET 9/10 have separately disclosed framework reuse.

## Current runner options

GitHub lists the following standard Linux VM resources. Standard public compute is free; private usage draws from included usage and billing. [Standard runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

| Scope | Native ARM64 labels | Native x64 labels | CPU / RAM / advertised SSD |
| --- | --- | --- | --- |
| Public | `ubuntu-22.04-arm`, `ubuntu-24.04-arm`, `ubuntu-26.04-arm` | `ubuntu-22.04`, `ubuntu-24.04`, `ubuntu-26.04` | 4 / 16 GB / 14 GB |
| Private | Same architecture-specific labels | Same x64 labels | 2 / 8 GB / 14 GB |

Use an explicit host label and record the actual image/kernel; the label does not freeze image updates. The version-specific container supplies the toolchain. `ubuntu-slim` is unsuitable: it is an unprivileged container with a 15-minute limit and lacks the required privileged mount/container capabilities. Hosted Linux VMs provide passwordless sudo; an actual engine/sysroot preparation probe is still required. [Runner capabilities](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

Larger Ubuntu runners offer both architectures at **2 CPU / 8 GB / 75 GB**, **4 / 16 GB / 150 GB** and **8 / 32 GB / 300 GB**, plus larger sizes. Start a measured pilot at **4/16/150**; consider **8/32/300** for full-history source trees and retained failure evidence. These are recommendations, not measured minimums. Organization-configured names/groups select larger runners. [Specifications](https://docs.github.com/en/actions/reference/runners/larger-runners).

Larger runners require an organization/enterprise on Team or Enterprise Cloud and are billed for public repositories. Current Linux ARM64 rates are USD **0.008/minute** for four cores and **0.014/minute** for eight; x64 rates are **0.012** and **0.022**. The organization's actual plan, access and budget were not inspected. [Availability/billing](https://docs.github.com/en/actions/concepts/runners/larger-runners), [rates](https://docs.github.com/en/billing/reference/actions-runner-pricing).

Hosted jobs, including larger runners, have a **six-hour** execution limit; self-hosted jobs allow **five days**, within an overall **35-day** workflow limit. The later regular .NET 10 pilot completed a fresh hosted run within that limit; the other profiles still need their own cold measurements. Keep preparation/build/test on one sufficiently sized worker initially: transferring partial build state between jobs requires verified dependency/producer records. [Actions limits](https://docs.github.com/en/actions/reference/limits).

Dedicated native self-hosted Linux workers offer operator-selected disk and longer jobs. GitHub does not charge their compute, while the operator maintains the machines. Use disposable workers restricted to trusted builds; keep untrusted public PRs away from a persistent developer PC. JIT registration alone does not clean reused hardware. [Self-hosted runners](https://docs.github.com/en/actions/concepts/runners/self-hosted-runners), [security guidance](https://docs.github.com/en/actions/reference/security/secure-use#hardening-for-self-hosted-runners).

## Resource evidence and limits

The initial .NET 10 experiment retained the following allocated sizes, measured with `du -sx --block-size=1`:

| Retained directory | Decimal GB |
| --- | ---: |
| VMR workspace | 12.248 |
| Separate pristine checkout | 2.067 |
| Inputs/sysroot | 0.760 |
| Container home/package cache | 4.615 |
| Total | 19.690 |

This historical footprint already exceeds 14 GB, but includes failed state and a separate scan checkout. It is neither a cold-build peak nor an irreducible minimum. Container layers share storage and must not simply be added. Equivalent complete disk/cgroup-memory high-water measurements are absent for the other profiles.

Actual resource reports also show why final retry timings cannot size CI:

| Recorded command | Elapsed | Scope |
| --- | --- | --- |
| .NET 10 final build | 3m 37.21s | Warm incremental completion |
| .NET 9 final build | 8m 30.19s | Reused runtime and caches |
| .NET 8 final metadata build | 52.84s | Reusable-artifact regeneration |
| .NET 7 successful build | 23m 9.81s | Cached resumption |
| .NET 6 successful build | 20m 42.30s | Reused earlier components |
| Core 3.0 final CoreSDK target | 1m 18.71s | Inner targeted adapter; earlier full attempt failed after 25m 1.50s |

Records are under each release's `reports/runs/`, or .NET 10's `reports/build-resources.txt`; linked build reports describe the attempts. .NET 5/Core 3.1 also reused outputs. GNU time's maximum RSS is not a concurrent process-tree/cgroup peak. Failure/fix/wait intervals are not cold-build benchmarks.

Upstream source-build guidance specifies about **80 GB disk**, about **30 GB with cleanup**, and at least **8 GB RAM**. These are planning guidance, not measurements of every profile or the regular .NET 10 build. Sample disk usage across source, full-history stores, generation archives, sysroot, image layers, caches, reports and SDK extraction, plus cgroup memory and cold download/build/test times. Deleting preinstalled hosted tools does not establish guaranteed capacity. [Source-build requirements](https://github.com/dotnet/source-build/blob/main/Documentation/system-requirements.md).

## Missing Linux orchestration

`Invoke-Arm64Build.ps1`, `Invoke-Net*Build.ps1` and `Invoke-Core*Build.ps1` call `wsl.exe`, translate Windows paths and write local report paths. Installing PowerShell on Ubuntu does not make them portable. Implement a Linux driver around their stages and existing Bash/Python tools, with explicit version adapters. WSL/wslc remain local development and interactive-consumer tools.

| Concern | Required CI behavior |
| --- | --- |
| Sources/images | Verify root/component commits, generated snapshots and patch chains. Legacy acquisition requires full history and pinned submodules. Select the version's Containerfile, inspect native architecture and record the actual derived image. .NET 10 uses `containers/arm64-net10.Containerfile`. |
| Preparation | Run version-specific feed/input helpers and signed sysroot preparation. .NET 6/7 need generation first; .NET 8 retains its own preparation/bootstrap sequence. Preserve original PSB bytes before transformation. |
| Paths/UID | Use native storage and the actual nonroot build UID:GID. Core 3.x/.NET 5 receipts bind absolute destinations: keep identical host/container paths and one whole workspace bind for atomic quarantine. .NET 6/7 need stable `/installer` and `/work` aliases through collection. |
| Affinity/home | Retain two workers initially, selecting CPUs from the allowed set. Core 3.0's wrapper default `4,5` fails on a four-CPU VM; Core 3.1's `2,3` cannot be assumed on a two-CPU VM. Use private native home/CLI/cache directories and mode-0700 `XDG_RUNTIME_DIR`. |
| Proof/finalization | Port transient installer-input observation, closed-binlog replay, native-component origins and complete report preservation. Some accepted finalization/observer/replay orchestration currently lives in ignored research scripts or frozen reports: inventory, review and check in reusable Linux equivalents before unattended CI parity. |
| Collection | Invoke the strict collector with each system's roots, generation report and image identity. Preserve unchanged archives and failure records. Collection does not replace origin, ABI or functional tests. |

Some acquisition helpers need modern host Python while Core 3.0 intentionally supplies Python 3.6 for historical tools. Keep each helper's tested interpreter, UTF-8 filesystem locale, XML documentation policy and supported HTTP-handler settings. Use genuine local XML-cache recovery rather than edited package content or the runner's global SDK/cache/certificates.

## Containers and privilege boundaries

Prefer a modern Ubuntu host job that runs checkout/upload Actions on the host and explicitly launches the pinned product containers. This accommodates separate root-only preparation, nonroot builds, exact bind paths, host networking and per-profile policies. GitHub job containers support Docker options, but default to `sh`, and do not support `--network`/`--entrypoint` options. Making the entire job privileged would widen the current boundary: only legacy signed debootstrap preparation uses a privileged container. .NET 10's extraction-based preparation is a different implementation. [Job container behavior](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container).

Host-side Actions avoid injecting their modern Node runtime into Bionic: Node 24 Linux binaries require GLIBC 2.28+, above Core 3.0's builder. Changing the historical builder's libc for an Action is unnecessary when it executes on the host. [Checkout runtime](https://github.com/actions/checkout), [Node 24 platforms](https://github.com/nodejs/node/blob/v24.x/BUILDING.md#platform-list).

The closest initial engine port is rootful Podman. Docker is another candidate after equivalent behavior is tested. Legacy seccomp helpers default to `/usr/share/containers/seccomp.json`, require AArch64 syscall 452 and preserve the baseline while allowing the required `fchmodat2` rule. A Docker-only host does not automatically supply that Podman policy path. Record/probe a validated engine/policy; do not silently omit it or use `seccomp=unconfined`. Reassess WSL's `--cgroups=disabled` workaround for CI. Privileged legacy Git checks retain the selected source owner's context, SHA/blob checks and recorded `SUDO_UID` handling. Keep package authentication and sysroot file/symlink inventories.

## Inputs and validation parity

Base digests do not completely lock these environments: recipes still run unversioned `apt-get install`. Preserve accepted derived images by registry digest and installed-package inventory, or establish package snapshots before rebuilding. Retain original SDK/PSB archives, source exports, exact hashes and signing-key provenance. Optional caches accelerate acquisition; an evictable cache must not be the sole source of a historical required input.

The .NET 10 recipe was renamed from `arm64.Containerfile` to `arm64-net10.Containerfile` without changing its contents. The eight existing release manifests retain their original collection inputs and paths; their pre-rename delivery audits remain historical evidence, rather than assertions that every input equals the current worktree. The rename neither rebuilds an SDK nor validates CI. Each pilot must freeze the actual orchestration revision/files before execution and collect a fresh manifest for that run, preserving the earlier production records.

A bounded local preservation check retained all eight original manifests/checksums and recovered exact recorded build-input bytes for six releases. Older .NET 9 records lack recoverable copies of two historical helper versions, and .NET 8 lacks one; their expected hashes remain recorded. These pre-existing helper-source gaps do not change the SDK bytes or native test results, but prevent claiming complete historical input recovery for those two collections. Future CI must preserve the actual orchestration source bytes, not only their hashes, together with the run's manifests and evidence.

Core 3.0 demonstrates the issue: unavailable exact test-template versions were recovered unchanged from official SDK 2.2.207 x64 and 3.0.100 ARM64 archives. Only architecture-neutral nupkg data from the x64 archive is used; no x64 execution occurs. Its bootstrap Arcade differs explicitly from the root declaration, and GenAPI uses an official reference-only .NET Framework package. Retired feed mappings preserve requested versions and TLS. Keep those contracts; a newer package or omitted template changes the profile. See the [Core 3.0 report](build-report-3.0.103-arm64.md).

Preserve actual upstream scope: .NET 10's 13 common and .NET 9's 500 ordinary-build tests require genuine pristine-source scan reports, with separate scenario exclusions. .NET 8 passed 44/46 with license/poison checks skipped; .NET 6/7 passed 41/42 with poisoning skipped and recorded baseline/warning limits. .NET 5 ran 68 shell cases; Core 3.x ran 52 each without later generations' extra test classes. Uniform green totals would misstate coverage.

Native validation consumes the identical collected archive in Ubuntu 22.04, Ubuntu 24.04 and Debian 13. Keep ABI inspection and all six functional checks. .NET 5/Core 3.x use explicit OpenSSL 1.1; Core 3.x Debian additionally uses the recorded ICU 66 prefix. Those libraries remain external, with independent hashes/licenses/GLIBC requirements. Preserve real globalization tests and observed RIDs. Local containers shared the WSL kernel; CI adds host/kernel evidence without certifying every distribution.

## Artifacts and later delivery

Upload a few run-specific SDK/evidence bundles. The current artifact Action allows **500 artifacts per job**, not 500 report files; it skips hidden files by default and ZIP upload loses executable permissions. Preserve transferred source/sysroot state as verified tar archives, including symlinks/inventories. Keep SDK `tar.gz` bytes unchanged and avoid redundant compression. [Artifact behavior](https://github.com/actions/upload-artifact#limitations).

Public retention is **1–90 days**, private **1–400**, default 90. Durable provenance/input storage must outlive workflow expiry. Artifact, cache and image storage have separate allowances/billing; free public standard compute is not a complete storage plan. [Retention](https://docs.github.com/en/organizations/managing-organization-settings/configuring-the-retention-period-for-github-actions-artifacts-and-logs-in-your-organization), [billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

Current SDK archives span **157,285,088–242,266,582 bytes**, below Releases' **under-2-GiB per-file** limit. A release permits **1,000 assets**, without a documented total-size/bandwidth cap. Bundle report inventories; split evidence archives exceeding the per-file limit. [Release quotas](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#storage-and-bandwidth-quotas).

A later publisher should recheck verified archives and attach manifests, checksums, test summaries and licenses. Grant release-write capability there, separately from building. Identify source/profile/build revision and disclose reused/external inputs. Workflow success or an attestation alone does not prove source-only construction. No release, registry publication or website change is part of this review.

## Recommended sequence and acceptance

1. Review/check in missing Linux orchestration and finalization tools; freeze accepted image/input contracts and remove dependence on a developer workspace or ignored scripts.
2. Pilot .NET 10 regular-build and .NET 8 source-build separately on native ARM64 larger runners, one profile at a time. Keep final flags/checks and two workers; measure cold resources/downloads.
3. Migrate .NET 9, independent .NET 6/7 generation/bootstrap, then .NET 5/Core 3.1. Establish a fresh final Core 3.0 graph or formally verified staged closure before unattended scheduling.
4. Implement native x64 locally and in an independent CI pilot, including architecture-specific image/input/syscall/ELF/host-tool validation.
5. Separate lightweight untrusted PR checks, trusted full builds, native validation and later release promotion. Keep per-attempt failures and optional input caches keyed by architecture/version/profile/image.

Acceptance requires a fresh runner to execute acquisition, preparation, product construction, applicable source/prebuilt/origin checks, upstream tests, native archive verification and strict collection, preserving complete evidence and a measured time/disk/memory/cost envelope. Cached local success establishes the starting point; the first CI pilot must establish the rest.
