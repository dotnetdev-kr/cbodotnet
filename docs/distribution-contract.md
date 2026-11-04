# Downstream distribution contract

Specification version: **2**. This specification and the checked-in
[machine-readable contract](../releases/distribution-contract.json) resolve the
foundation work in [issue #2](https://github.com/dotnetdev-kr/cbodotnet/issues/2),
under [epic #1](https://github.com/dotnetdev-kr/cbodotnet/issues/1). Changes to the
installation identity, architecture mapping, immutable input identity or trust
requirements require a new contract version and review.

The initial packaging input is the already-qualified **SDK 10.0.403** release.
This contract defines preparation rules; successful planning alone does not
authorize publication. SDK 10.0.403's published APT, RPM and OCI targets are recorded
with native and public verification evidence in
[distribution status](../releases/downstream-status.json). Additional targets
require their own complete downstream gates.
[Issue #7](https://github.com/dotnetdev-kr/cbodotnet/issues/7) supplies
those shared gates; [OCI #3](https://github.com/dotnetdev-kr/cbodotnet/issues/3),
[APT #4](https://github.com/dotnetdev-kr/cbodotnet/issues/4),
[RPM #5](https://github.com/dotnetdev-kr/cbodotnet/issues/5) and
[Arch recipe validation #6](https://github.com/dotnetdev-kr/cbodotnet/issues/6)
supply channel implementation. Authenticated AUR publication is separately
tracked in [issue #10](https://github.com/dotnetdev-kr/cbodotnet/issues/10).

## Installation identity and coexistence

| Item | Contract v2 | SDK 10 example |
| --- | --- | --- |
| Debian/RPM package | `cbodotnet-sdk-<major>.<minor>` | `cbodotnet-sdk-10.0` |
| AUR binary recipe | `cbodotnet-sdk-<major>.<minor>-bin` | `cbodotnet-sdk-10.0-bin` |
| Complete SDK root | `/opt/cbodotnet/<major>.<minor>` | `/opt/cbodotnet/10.0` |
| Explicit launcher | `/usr/bin/cbodotnet-<major>.<minor>` | `/usr/bin/cbodotnet-10.0` |
| Common launcher | `/usr/bin/cbodotnet`, owned by `cbodotnet-host` | Highest installed numeric major/minor |
| OCI command directory | `/usr/local/bin` | `cbodotnet-10.0`, `cbodotnet`, `dotnet` |
| OCI repository | `ghcr.io/dotnetdev-kr/cbodotnet-sdk` | SDK images only |
| Immutable OCI tag | `<sdk>-<variant>-r<revision>` | `10.0.403-debian13-r1` |

Each root contains one complete installation: `dotnet`, `host`, `shared`, `sdk`,
templates, packs, NuGet payloads and their applicable upstream license and notice
files. Preserve the qualified archive's hierarchy. Install no fragment of the
SDK into an existing Microsoft, distribution or other cbodotnet minor root.

SDK 10's CLI creates an empty `metadata/` directory under its root on first use.
Package preparation adds this directory explicitly (mode `0755`, package owner
root), before making the installation available to users. It is recorded as
`additionalDirectories` in the plan; no qualified SDK file is changed. This
also avoids depending on a non-root user's permission to create directories in
a package-owned root. Other added files or directories require their own
recorded ownership and purpose.

One major/minor package owns one root and launcher. SDK patches and feature bands
within that minor are upgrades of the package, not concurrently installed
packages. Prepare and validate a complete replacement root, then switch it as a
unit under the package manager's transaction and recovery mechanism. Never
overlay new files onto an old SDK tree: removed files must not survive an
upgrade. Do not claim that a package transaction makes already-running processes
atomic; document normal package-manager interruption and recovery behavior.
Different major/minor roots and launchers coexist. To keep two exact SDKs within
the same minor, use separately extracted, verified archives in separately chosen
roots, or exact OCI digests. Packages for different architectures cannot share
the same minor root on one host.

The [launcher template](../scripts/cbodotnet-launcher.sh.in) executes its absolute
root's `dotnet` with unchanged arguments, clears inherited `DOTNET_ROOT_X64`,
`DOTNET_ROOT_ARM64` and `DOTNET_ROOT_X86`, then sets `DOTNET_ROOT` and the applicable
architecture-specific variable to that root. It sets `DOTNET_HOST_PATH` to the
absolute host and `DOTNET_MULTILEVEL_LOOKUP=0`. It
must fail if that host is missing or cannot execute. It must never find a host
through `PATH`, another installed SDK, a user-supplied `DOTNET_ROOT` or a global
`dotnet` installation. Verify the actual selected host, runtime and SDK paths;
printing the expected version alone does not prove isolation.

Packages may own the launcher, their minor root and separately recorded package
documentation/metadata. They must not write or replace `/usr/bin/dotnet`,
`/usr/share/dotnet`, `/usr/lib/dotnet`, Microsoft/distribution package files,
another minor root, shell profiles or a global `global.json`. They must not
register an `update-alternatives` default, declare that they provide/replace
official `dotnet` packages. The shared `cbodotnet-host` package owns the
unversioned `cbodotnet` dispatcher; individual SDK packages depend on that
component and own only their versioned launcher and root.
Reject any package plan attempting such a namespace or file ownership collision.

The [common dispatcher](../scripts/cbodotnet-default.sh.in) selects the highest
installed numeric major/minor with both an ordinary executable host and matching
versioned launcher. For example, `10.10` sorts after `10.2`. Malformed names,
linked roots/hosts and incomplete installations are ignored. After removal of
the selected SDK it chooses the highest remaining usable installation; with
none available it fails with an explicit error. A versioned command always
selects its own root. Removing an SDK never deletes the shared dispatcher owned
by `cbodotnet-host`. This is an executable command usable from scripts and any
shell, so it does not require a shell-specific alias or profile edit.

OCI command preparation pins all three names to the image's selected SDK,
regardless of other roots. Set the image `PATH` to prefer `/usr/local/bin` over
the SDK root and use its versioned, `cbodotnet` and `dotnet` wrappers. Keep the
original SDK host at `/opt/cbodotnet/<series>/dotnet` to avoid recursion. The
[command staging helper](../scripts/distribution_commands.py) inventories
command paths, owning component, modes, byte sizes and SHA-256 hashes; a matching
retry succeeds and a conflicting existing command fails before writes begin.

Removal deletes only files owned by that minor package. Shared parent
directories may be removed only when empty. Preserve other SDKs, user projects,
NuGet caches, user configuration and other minor launchers. Do not use an
unbounded recursive removal of `/opt/cbodotnet`.

Users can select the explicit launcher directly. An optional session-local
selection for SDK 10 is:

```bash
export DOTNET_ROOT=/opt/cbodotnet/10.0
export PATH="$DOTNET_ROOT:$PATH"
```

Set the applicable `DOTNET_ROOT_X64` or `DOTNET_ROOT_ARM64` to the same root when
launching architecture-specific apphosts. This is an explicit user choice;
installers do not edit login shells. Restore the previous environment to return
to the previous selection. Directly placing the SDK root on PATH bypasses
distribution-wrapper branding; prefer `cbodotnet` or a versioned command for
the branded public entry point. Container images set `DOTNET_ROOT` to the same
isolated root and prefer the wrapper bin directory on PATH.

## CLI identity

[Issue #8](https://github.com/dotnetdev-kr/cbodotnet/issues/8) records the
[upstream analysis and output policy](cli-branding.md). Public launchers display
**Community Build of .NET (built by .NET Dev)** in top-level information/help.
Standalone `--version` preserves the original numeric stdout and prints the
identity on stderr. `--cbodotnet-info` emits JSON with the contract version,
installed SDK identity, target RID, source tag/manifest digest and package
revision. Normal build/run/application calls forward arguments, streams and
exit status without a banner. Application arguments such as `app.dll --version`
are not intercepted as launcher options.

Branding is separately accounted wrapper metadata. SDK binaries, numeric
product versions, original diagnostics, licenses and notices remain unchanged.
Direct underlying-host or apphost execution bypasses wrapper branding. Any
future compiled branding requires a fresh source build and full requalification.

## Canonical source and package versions

The source boundary is a complete, public, stable GitHub Release named
`sdk-<SDK version>`, its exact `release-manifest.json`, `SHA256SUMS`, and selected
SDK archive. Actions transport artifacts are not downstream distribution inputs.
The initial source is
[sdk-10.0.403](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/sdk-10.0.403).
Its manifest bytes are pinned to SHA-256
`16f9d534cf572531b52c9296b1c3652432e6f1f8a8b1614c326e007c07c79c3d`.

| Public architecture | RID | SDK SHA-256 | SDK bytes |
| --- | --- | --- | --- |
| `x64` | `linux-x64` | `0ff27ca9775fb8d3c83fce60ad511754956f311a950878dcbc05bd6737a4bc09` | 224,606,406 |
| `aarch64` | `linux-arm64` | `410491f0166109c2c3d115705ab64601cec56c3b1c1995267d3b16567f9c0d5b` | 217,817,416 |

Before using an SDK, validate the public release API metadata, complete manifest,
all checksum entries and selected local archive. Reject draft/prerelease inputs,
missing architectures, wrong asset names, unexpected RIDs, mismatched sizes or
digests, unqualified versions and producer identities that differ from
[qualified-builds.json](../releases/qualified-builds.json). A valid checksum beside
an untrusted archive does not independently authenticate its producer. The
reviewed manifest pin and qualified producer record are trust inputs.

The [contract consumer](../scripts/distribution_contract.py) and
[planning command](../scripts/distribution-contract.py) implement these checks
without rebuilding or executing downloaded SDK code. Use the command's `--help`
for its required local API response, manifest, checksum and archive inputs.
Planning produces preparation metadata; it cannot grant promotion approval.

| Channel | Conversion for stable SDK `10.0.403`, revision `1` |
| --- | --- |
| Debian | `Version: 10.0.403-1`; variant is a separate repository/publication identity |
| RPM | `Version: 10.0.403`, `Release: 1.cbot.<variant>`; no epoch |
| AUR | `pkgver=10.0.403`, `pkgrel=1` |
| OCI | `10.0.403-debian13-r1`, then immutable image/index digests |

Accept only exact stable SDK versions present in the reviewed qualification
catalog and contract. A higher upstream SDK number or matching major/minor is
insufficient. A new qualified SDK changes the SDK version; a packaging-only fix
increments the positive integer package revision while retaining the source
manifest and SDK digests. Revisions are not an excuse to rebuild or modify SDK
payloads. Never publish different bytes for an existing immutable identity.
Mutable OCI tags such as `latest`, `10.0` and unsuffixed SDK aliases are deferred.

## Architecture and target policy

| Public archive | .NET RID | Debian | RPM | AUR mapping | OCI platform |
| --- | --- | --- | --- | --- | --- |
| `x64` | `linux-x64` | `amd64` | `x86_64` | `x86_64` | `linux/amd64` |
| `aarch64` | `linux-arm64` | `arm64` | `aarch64` | `aarch64` | `linux/arm64` |

These are identity conversions, not compatibility approvals. Reject unknown
architectures rather than selecting a default. AUR recipes have passed native
validation on Arch Linux `x86_64`; public AUR submission remains deferred to
[issue #10](https://github.com/dotnetdev-kr/cbodotnet/issues/10). The `aarch64`
mapping does not qualify Arch Linux ARM. Never use architecture `any` for these
native SDKs.

| Channel | Target | Initial SDK/architectures | Current status |
| --- | --- | --- | --- |
| Debian package | Ubuntu 24.04 | 10.0.403, `amd64` and `arm64` | Published; native lifecycle and public repository checks passed |
| Debian package | Debian 13 | 10.0.403, `amd64` and `arm64` | Published; native lifecycle and public repository checks passed |
| OCI | Debian 13, variant `debian13` | 10.0.403, `linux/amd64` and `linux/arm64` | Published; native image and anonymous digest-pull checks passed |
| RPM | Fedora 45 and Rocky Linux 9.8 | 10.0.403, `x86_64` and `aarch64` | Published; signed packages/metadata and native HTTPS DNF checks passed |
| AUR | Arch Linux rolling | 10.0.403, `x86_64` only | Native recipe build/lifecycle validation passed; AUR submission deferred to issue #10 |

Ubuntu 22.04 has archive evidence, but is not an initial package target.
Every target requires its own reviewed, explicit matrix; generic glibc execution
is insufficient. Musl/Alpine is excluded until a
separately qualified musl SDK exists. Reject unlisted channel/OS/version/SDK
combinations with an unsupported-target error. There is no force-publication
option in contract v2. Adding a target requires reviewed mapping changes and its
own downstream evidence before promotion.

## Dependency evidence and lifecycle

The following is the existing **archive user-space** dependency matrix for both
architectures, derived from the
[AArch64](ci-matrix-results.md) and [x64](ci-x64-results.md) qualification records,
the [matrix policy](ci-matrix.md), and the guarded
[verification recipe](../containers/verify-net10.Containerfile). It does not
claim successful installation of a package or consumer container.

| Qualified SDKs | Ubuntu 22.04 | Ubuntu 24.04 | Debian 13 |
| --- | --- | --- | --- |
| 10.0.403, 9.0.123, 8.0.133, 7.0.120, 6.0.136 | Stock ICU 70, OpenSSL 3 | Stock ICU 74, OpenSSL 3 | Stock ICU 76, OpenSSL 3 |
| 5.0.214 | Stock ICU 70; recorded external OpenSSL 1.1 | Stock ICU 74; recorded external OpenSSL 1.1 | Stock ICU 76; recorded external OpenSSL 1.1 |
| 3.1.426, 3.0.103 | Stock ICU 70; recorded external OpenSSL 1.1 | Stock ICU 74; recorded external OpenSSL 1.1 | Recorded external ICU 66 and OpenSSL 1.1 |

The corresponding stock package names are `libicu70`/`libssl3` on Ubuntu 22.04,
`libicu74`/`libssl3t64` on Ubuntu 24.04 and `libicu76`/`libssl3t64` on Debian 13.
Common verification dependencies include `libc6`, `libstdc++6`, `zlib1g`,
`libgssapi-krb5-2`, `libgcc-s1` and CA certificates. Python, binutils, curl and
verification tools are test infrastructure, not automatically SDK runtime
dependencies. Resolve and record actual system package versions, needed ELF
libraries and available SONAMEs per OS and architecture; do not turn this table
into a distro-independent `Depends` string. Record optional diagnostic,
profiling, debugger and workload dependencies separately when claiming them.

| SDK | Observed maximum GLIBC, x64 / AArch64 | GLIBCXX | CXXABI |
| --- | --- | --- | --- |
| 10.0.403 | 2.27 / 2.27 | 3.4.22 | 1.3.7 |
| 9.0.123, 8.0.133, 7.0.120 | 2.17 / 2.17 | 3.4.21 | 1.3.7 |
| 6.0.136, 5.0.214 | 2.16 / 2.17 | 3.4.21 | 1.3.7 |
| 3.1.426, 3.0.103 | 2.14 / 2.17 | 3.4.21 | 1.3.7 |

These maxima are ABI observations, not tested minimum distributions or kernels.
The three user spaces share the native runner kernel. Their six functional
checks do not establish compatibility with every optional component.

Contract v2 enables downstream preparation only for SDK 10.0.403. Other SDKs
fail closed pending a reviewed target-specific dependency policy. In particular,
do not silently bundle obsolete OpenSSL/ICU libraries, disable globalization,
disable signature checks or reuse the SDK 10 container base to make legacy SDKs
appear compatible. .NET Core 3.x and .NET 5/6/7 have ended upstream support;
continued cbodotnet availability does not provide upstream security maintenance.
Publication records must state the applicable upstream lifecycle status and the
date/source of that assessment. Compatibility testing and security support are
separate claims.

## Payload preservation and publication records

Packaging consumes the exact archive bytes, never a fresh SDK build. Validate
archive member names, duplicates, link targets/chains and permission bits before
extracting into a fresh private root. Reject escaping paths, absolute or cyclic
links, entries beneath symlink parents, devices, FIFOs and special permission
bits. The [SDK verifier](../scripts/verify-sdk.sh) records the existing guarded
archive policy; transport-bundle layout is a different format.

Compare the final installed SDK tree against the verified archive, including
file bytes, executable modes and link identities. Disable binary stripping,
debug splitting, post-install rewriting and other packaging transforms that
change qualified payloads. Package-manager ownership metadata and necessary
wrapper/package metadata are separately accounted for; additions must not
replace SDK files. Retain all original license and third-party notice bytes,
identify their paths, and link the exact architecture-specific corresponding
source archive and source evidence. The repository license alone does not
describe every SDK component's license.

The planning command emits a source-bound `prepared-unqualified` record with
`publicationAllowed: false`: contract version, SDK/target identity, package
revision/root/launcher, source manifest digest and URL, SDK/source/evidence
descriptors, qualified producer, dependencies and notice paths. This is the
common input for Debian and OCI preparation, not a publication record.

The final downstream artifact record defined in issue #7 must additionally
bind the complete set of fields below before promotion:

- Contract/schema version, channel, status and orchestration commit/workflow
  identity, including run and attempt.
- SDK version, public architecture, target RID, channel architecture,
  distribution/version/variant and positive package revision.
- Source repository, release tag/URL, exact manifest SHA-256, SDK archive
  name/URL/size/SHA-256, source and evidence archive descriptors, and the original
  qualified producer commit/run/attempt/artifact identity.
- Package name/version or OCI tag, downstream artifact URL, byte size and
  SHA-256; OCI platform image digests, pinned base distribution/image digest and
  complete multi-platform index digest when applicable.
- Signing key fingerprint or OCI signer/certificate identity, signature or
  attestation location, package-owned extra-file inventory, license/notice
  paths and corresponding-source links.
- Per-target dependency observations, native architecture, test report
  URL/digest, install/build/runtime/upgrade/removal/coexistence results, lifecycle
  assessment and final promotion/post-publication verification outcome.

The immutable artifact identity is the tuple **SDK version + target RID + source
release tag and manifest digest + package revision + channel/platform/OS
variant**. Preparation records must remain visibly unqualified. A successful
plan or checksum check cannot be relabeled as a successful package installation.

## Channel trust, corrections and rollback

APT/RPM metadata, RPM packages and downstream manifests use the
[approved distribution signing identity](distribution-signing.md). Published
endpoints, immutable image digests and verification receipts are recorded in
[distribution status](../releases/downstream-status.json). Additional SDK/OS/CPU
targets require separate reviewed admission before availability is declared.
AUR publication remains deferred to issue #10. Every enabled channel follows
this trust model:

| Channel | Required verification and source linkage |
| --- | --- |
| APT | Project-controlled repository with signed `InRelease` metadata binding package indexes and package hashes. Use a dedicated keyring and `signed-by`; publish and verify the full signing-key fingerprint. |
| RPM | Signed packages with `gpgcheck=1` and signed repository metadata with `repo_gpgcheck=1`. Verify the pinned project signing fingerprint and exact SDK/source identity before installation. |
| AUR | Reviewed PKGBUILD and generated matching `.SRCINFO`, exact non-`SKIP` SDK SHA-256 and verified canonical source manifest/producer identity. AUR distributes a recipe; it is not a project binary repository or a signature on the downloaded SDK. |
| OCI | Pull and verify immutable platform/index digests. Bind provenance/attestation to the exact repository, publishing workflow identity and source SDK/manifest digests; document signer or certificate trust roots and verification commands. |

Distribute full key fingerprints through the reviewed project documentation and
an independently trusted project channel. Downloading a key and trusting its
adjacent fingerprint from the same unverified location is insufficient. Scope
private signing material to protected signing/promotion jobs, restrict publisher
permissions, and keep credentials out of build/test logs and untrusted PR jobs.

Before rotation, publish the successor key/fingerprint, validity and overlap
window through the established trust channels. Retain verifiability of existing
artifacts. Test repository refresh and installation with the new identity before
retiring the old one. On compromise, revoke the identity, stop promotion, publish
the affected artifact/digest list and signed status correction, and document the
replacement trust bootstrap. Do not conceal revocation by replacing old bytes.

Promotion must stage complete objects/indexes, validate the whole advertised
matrix and then expose the channel version. Reusing an existing identity is
allowed only when its immutable digests agree; a conflict is a hard failure.
OCI dual-platform tags require both verified descriptors. APT/RPM indexes must
resolve to all referenced published packages before metadata promotion. Channels
have independent outcomes; success in one does not complete the epic.

For a packaging defect, publish a new revision and preserve the prior record. For
a new SDK, consume a new qualified release rather than replacing a release
archive. Mark revoked or unsuitable artifacts unavailable for new promotion,
retain an auditable reason and publish corrected status. Rollback selects a
previously verified package version/revision or OCI digest explicitly; it never
rewrites an existing immutable object. Test downgrade/recovery behavior before
advertising rollback. Repository inclusion policies remain separate from this
project's own signed package repositories.

## Required downstream smoke evidence

Each claimed distro/version, architecture, SDK and channel combination must
produce an independently recorded report. Use native workers for both Linux
architectures where available; any alternative must document why its execution
and dependency results represent the claimed target.

1. Verify canonical release inputs before extraction; reject unknown
   architectures, altered manifest/archive digests, unsupported targets,
   unqualified producers and conflicting namespaces in negative tests.
2. Prepare a clean target with recorded OS/kernel/architecture and resolved
   native package versions. Install an official or distribution `dotnet` at its
   normal independent path and record its package identity, bytes and behavior.
3. Install the cbodotnet root and launcher. As a non-root user, confirm the
   expected SDK version, RID, host path, SDK list and runtime paths. Start with
   misleading inherited `DOTNET_ROOT`/`PATH` selections and demonstrate that the
   explicit launcher still uses its own host. A missing cbodotnet host must fail.
4. Create, restore with no external feeds, build and run a console DLL and
   apphost in a fresh writable directory. Exercise RSA/SHA-256, random bytes,
   ICU formatting and an isolated local ASP.NET HTTP scenario. Record any
   optional component exclusions explicitly.
5. Compare installed SDK payload bytes/modes/links and license/notice files
   with the source archive. Check package file ownership and that the official
   `dotnet` path and behavior remain unchanged.
6. Upgrade a packaging revision without stale SDK files; verify a failed
   upgrade's recovery behavior. Remove the cbodotnet package/root/launcher and
   repeat the official installation's integrity and execution checks. Preserve
   other minor roots and user files.
7. After promotion, download the public signed package or pull the public
   image by digest, repeat the appropriate installation/execution checks and
   publish the report. Local preparation results alone do not complete this gate.

The [native contract integration test](../scripts/test-distribution-coexistence.py)
and [two-architecture workflow](../.github/workflows/distribution-contract.yml)
exercise root/launcher coexistence and removal using the unchanged qualified
SDK beside an independent official SDK. Record an actual successful execution
before claiming that this behavior has been demonstrated.
The [recorded foundation run](distribution-contract-validation.json) on
2026-11-04 passed on native AArch64, Ubuntu 22.04.5 under WSL, using official SDK
10.0.100 and qualified cbodotnet 10.0.403. Host/runtime isolation, offline build,
payload preservation, missing-host failure and removal preserved the official
installation. The existing verifier also passed console DLL/apphost, HTTP,
crypto and globalization checks. The planned Ubuntu 24.04 variant in that run
is preparation metadata; Ubuntu 22.04.5 is the actual tested user space.
The version 2 run additionally passed both native command names and all three
OCI command names in separate private prefixes, including branding, exact
numeric version stdout, JSON provenance and SDK payload preservation. This
tests the OCI command layout with the real SDK, not a built consumer image.

Real package/image qualification is separate from those historical foundation
results. Native jobs in
[the initial delivery run](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41765223368)
passed the Ubuntu 24.04/Debian 13 APT installation lifecycle and Debian 13 OCI
checks on x64 and AArch64. The
[public recovery and verification run](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41772357482)
reused the exact frozen signed publication bytes, verified anonymous native OCI
digest pulls and installed the published signed APT archives on the complete
matrix. The status finalizer authenticated those receipts and refreshed Pages;
[hosted HTTPS APT verification](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41773673150)
then passed all four native OS/architecture targets, including strict installed
file verification. The four reports are preserved in the
[public installation record](distribution-publication-validation.json).
Immutable source/command/artifact bindings and public archive/image results
are retained in [distribution status](../releases/downstream-status.json).

RPM qualification passed on native x64 and AArch64 workers in pinned Fedora 45
and Rocky Linux 9.8 user-space containers. The
[native build and signing run](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41784038274)
completed all four lifecycle targets and froze the signed revision 1 bytes.
Its original post-publication verifier failed; the
[successful recovery run](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41787695177)
reused those exact signed bytes without rebuilding or signing again, installed
the public packages on all four targets and activated the status receipts.
[Pages deployment](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41788312381)
then succeeded, and
[hosted HTTPS DNF verification](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41788510887)
passed all four targets with package and metadata signature checking enabled.
The [retained RPM publication record](rpm-publication-validation.json) includes
the exact reports and immutable source, artifact, signing and repository bindings.
The [Arch validation record](aur-validation.json) separately records the completed
native x86_64 recipe build/lifecycle scope of issue #6; authenticated AUR
publication remains in [issue #10](https://github.com/dotnetdev-kr/cbodotnet/issues/10).

Copyable instructions expose only channels marked published after complete
native and public verification. Each additional SDK/target and AUR publication
requires its own installation, lifecycle, dependency and publication gates.
Include the signing identity, source links, lifecycle limits, selection,
uninstall and rollback procedure with every published channel.
