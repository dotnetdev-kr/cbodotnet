# Platform Expansion Roadmap

**Reviewed:** 2026-11-11

This roadmap prioritizes existing requests; it does not qualify a target or
promise a delivery date. The exact availability is the
[signed distribution matrix](all-sdk-distributions.md),
[musl status](../releases/musl-status.json) and
[release scorecard](https://dotnetdev.kr/cbodotnet/#qualification-scorecard).
Implementation issues remain the source of truth for each qualification.

## Intake and Ranking Rubric

Record evidence in an issue before proposing a new OS, CPU or delivery channel.
Use `High`, `Medium`, `Low` or `Unknown` for demand; do not infer downloads,
install counts or user identity from repository traffic. The project collects
no default usage telemetry. External demand evidence should come from the
[pilot in #43](https://github.com/dotnetdev-kr/cbodotnet/issues/43), public user
requests or consented downstream reports.

| Factor | Required evidence | Stop or defer when |
| --- | --- | --- |
| User demand | Named use case, affected users/projects, and a reproducible blocker or consented pilot feedback. | Demand is only presumed from a platform name, download count or maintainer preference. Mark it `Unknown` and collect feedback. |
| Upstream lifecycle | Current lifecycle state and exact SDK version from the [support policy](support-lifecycle.md). | The proposal implies vendor support, security fixes or a patch cadence the project cannot provide. EOL work needs an explicit owner and risk rationale. |
| Security and dependencies | Exact source, license, origin and maintenance status for every required library; audited ABI/ELF and trust boundary. | A required dependency is unavailable, unmaintained without a bounded exception, or would weaken source/signing gates. |
| Native qualification cost | CPU/OS matrix, measured runner, disk and memory requirements, downstream installation tests and public replay plan. | There is no matching native runner or capacity; emulation, another SDK result or a local build cannot substitute. |
| Automation fit | Existing pipeline adapter, immutable inputs, signing/promotion boundary, recovery path and explicit out-of-scope targets. | A new target requires broad workflow exceptions or silently reuses evidence from another libc, CPU or OS. |
| Maintenance ownership | A named primary maintainer and deputy willing to review lifecycle, upstream updates and incidents. | No maintainer accepts ongoing ownership. Defer rather than treating initial qualification as perpetual support. |

Prioritize by removing hard blockers first, then by demonstrated user impact and
measured capacity. This is an ordinal decision, not a weighted score: the
available backlog has no comparable user-demand dataset. The
[maintenance objectives](maintenance-objectives.md) describe the one-candidate
discovery limit, native concurrency and source/bootstrap gates; the
[contributor policy](../CONTRIBUTING.md) defines release-critical review.

## Current Backlog

| Order | Work item | Evidence and dependency | Recommendation |
| --- | --- | --- | --- |
| Complete | [#32 Alpine SDK 9/8](https://github.com/dotnetdev-kr/cbodotnet/issues/32) | Closed after native x64/AArch64 qualification and public verification of archive, APK and OCI channels. | Keep the immutable receipts as evidence; do not reopen as an expansion request. |
| Complete | [#33 Alpine SDK 7/6](https://github.com/dotnetdev-kr/cbodotnet/issues/33) | Closed after SDK 7/6 work; current availability and remaining SDK cells are in the signed musl status and matrix. | Keep published receipts; no upstream support is implied for these EOL SDKs. |
| 1 | [#10 AUR publication](https://github.com/dotnetdev-kr/cbodotnet/issues/10) | Recipe validation is complete for the eight SDK lines, but publication requires the designated maintainer account and that account's explicit review of upload/update ownership. | Lowest remaining technical qualification cost. Complete account/ownership setup first; never share credentials or infer AUR publication from recipe validation. |
| 2 | [#34 SDK 5 Alpine/musl](https://github.com/dotnetdev-kr/cbodotnet/issues/34) | Open; legacy OpenSSL/ICU/curl feasibility, generated sources, complete normal producer/source closure and both native consumers remain distinct gates. Upstream SDK 5 EOL was 2022-05-10. | Continue the existing investigation only with a named owner and source-complete dependencies. Keep availability false until the full two-CPU/public gates pass. |
| 3 | [#35 Core 3 Alpine/musl ARM64](https://github.com/dotnetdev-kr/cbodotnet/issues/35) | Open; both Core 3 lines need fresh complete producer/source evidence and native consumers. Core 3 adds native HTTP/libcurl behavior; an ARM64 source or bootstrap probe alone is not delivery qualification. Upstream EOL dates were 2022-12-13 and 2020-03-03. | Follow after #34 dependency/source findings where reusable. Require explicit ARM64 source/build feasibility and both native CPUs before any release decision. |
| Intake | [#43 external-user pilot](https://github.com/dotnetdev-kr/cbodotnet/issues/43) | No external pilot findings are recorded yet; it is open and requires real participants. | Gather consented, non-sensitive feedback before proposing any additional OS or channel beyond #10 and #32-#35. |

#32/#33 and #34/#35 are the Alpine work backlog: the former are completed and
the latter remain implementation issues. This roadmap does not reopen them or
substitute for their source, native, signing and public-verification gates.

## Admission and Reassessment

A proposal is ready for qualification planning only when it has a recorded
demand signal, an explicit support state, source/dependency feasibility, a
measured native capacity estimate and an accepted maintenance owner. Admission
still requires the complete source and license audit, both native CPU results,
real consumer installation/runtime checks, signed immutable publication and
anonymous public post-verification. Existing gates are not relaxed to improve a
roadmap rank.

Review this order after the #43 pilot or when an existing issue reaches a new
verified gate. Record changes and their evidence here, and keep actual artifact
availability in the signed feeds. If capacity, demand or ownership is unknown,
label it unknown and defer instead of fabricating precision.