# SDK and Platform Support Lifecycle

**Policy reviewed:** 2026-11-10

This policy describes cbodotnet project lifecycle states. It does not replace
Microsoft's [official .NET support policy](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core)
or establish support from a Linux distribution vendor. Microsoft requires the
latest upstream patch to remain vendor-supported; the Community SDK versions
listed here are immutable, separately qualified builds and are not an automatic
mirror of later upstream servicing.

## Project States

| State | Entry criteria | Meaning |
| --- | --- | --- |
| Active | The upstream line is in active support and the project has a currently verified release for the exact published SDK version. | The line may be considered for planned qualification work. This is not a promise to ship every upstream patch, a security backport, or a response time. |
| Maintenance-only | The upstream line is in its final maintenance period or is end-of-support, while qualified Community releases remain available. | No feature work or routine SDK refresh is planned. Maintainers may address release-integrity or delivery breakage when capacity permits; there is no servicing commitment, vulnerability-remediation promise, or SLA. |
| Archived | Maintainers explicitly end new qualification and release work for a line or target. | Existing immutable assets and evidence remain historical records unless withdrawn for integrity or legal reasons. No new target or revision is implied. |

Project state is independent of artifact availability and qualification. A
published receipt means only that the exact recorded artifact passed the
recorded project gates. It does not promise future maintenance or vendor
support. No currently published SDK line is marked Archived in this initial
policy snapshot.

## SDK Lines

The upstream dates below were checked against Microsoft's support policy on
2026-11-10. The upstream state is not a Community maintenance promise.

| Community SDK | Project state | Upstream lifecycle at review | Upstream end of support |
| --- | --- | --- | --- |
| 10.0.403 | Active | LTS, active support | 2028-11-14 |
| 9.0.123 | Maintenance-only | STS; end date is the review date | 2026-11-10 |
| 8.0.133 | Maintenance-only | LTS; end date is the review date | 2026-11-10 |
| 7.0.120 | Maintenance-only | STS, ended | 2024-05-14 |
| 6.0.136 | Maintenance-only | LTS, ended | 2024-11-12 |
| 5.0.214 | Maintenance-only | STS, ended | 2022-05-10 |
| 3.1.426 | Maintenance-only | LTS, ended | 2022-12-13 |
| 3.0.103 | Maintenance-only | STS, ended | 2020-03-03 |

The official policy is the source for upstream lifecycle changes. On or after
an end-of-support date, treat the upstream line as unsupported even if this
project continues to distribute a previously qualified build. The project does
not restore upstream servicing by rebuilding or republishing an SDK.

## Qualified Targets

Target qualification is per exact SDK revision, CPU, operating system and
channel. Use the linked records rather than inferring that a line supports every
target in a family:

- The [verified distribution matrix](all-sdk-distributions.md) links the exact
  glibc archive, APT, RPM, OCI and Arch recipe revisions. Generic archive
  qualification covers Ubuntu 22.04, Ubuntu 24.04 and Debian 13 on x64 and
  AArch64; Core 3 archive revisions additionally record Fedora 45 and Rocky
  Linux 9.8. APT targets Ubuntu 24.04 and Debian 13; RPM targets Fedora 45 and
  Rocky Linux 9.8; OCI uses Debian 13. AUR publication remains deferred.
- The [Alpine/musl matrix](alpine-musl.md) and
  [signed musl availability receipts](../releases/musl-status.json) are
  authoritative for Alpine 3.24.4 archives, APK repositories and OCI images on
  x64 and AArch64. A missing receipt is not a qualification.
- The [release scorecard](https://dotnetdev.kr/cbodotnet/#qualification-scorecard)
  summarizes current per-SDK cells and links their evidence. The
  [archive status](../releases/archive-status.json),
  [downstream signed receipts](../releases/downstream-status.json),
  [glibc producer catalog](../releases/qualified-builds.json) and
  [musl producer catalog](../releases/qualified-musl-builds.json) remain the
  exact machine-readable sources.
- `cbodotnetup` has a separate signed admission catalog and its own native
  installation matrix. SDK qualification, package publication and installer
  admission are independent gates; see the
  [installer availability record](../releases/cbodotnetup-status.json).

Community testing does not imply Microsoft or distribution-vendor acceptance,
certification, security servicing, or compatibility with unlisted targets.
Workloads, NativeAOT and other optional components need their own recorded
qualification.

## State Changes and Notifications

Review this policy at each annual .NET release and when the official lifecycle
page, a signed availability feed, or project maintenance capacity materially
changes. A state change requires a reviewed repository change that updates this
table and links the relevant qualification or availability record. New or
withdrawn artifacts keep immutable history; corrected releases use a new
revision rather than replacing an existing asset.

Users can follow GitHub Releases and repository issue/release updates for
availability and lifecycle changes. The project has no separate mailing list,
incident-response SLA, or guarantee that every state transition will produce a
new SDK build. For an exact current target, check the signed status feeds and
the release scorecard before installation.