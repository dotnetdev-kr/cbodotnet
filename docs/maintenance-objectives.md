# SDK Update and Maintenance Objectives

**Reviewed:** 2026-11-10

This document sets best-effort operating objectives, not a servicing or
publication guarantee. Exact project states are defined in the
[support lifecycle policy](support-lifecycle.md); exact published bytes and
qualified targets remain in the signed catalogs and receipts linked by the
[release qualification scorecard](https://dotnetdev.kr/cbodotnet/#qualification-scorecard).
Community builds do not imply Microsoft or distribution-vendor support.

## Update Objectives

| Work | Objective | Limit and exception |
| --- | --- | --- |
| Upstream discovery | Attempt one metadata check per day at 03:23 UTC. Target discovery within the next scheduled cycle after upstream publishes a stable SDK. | GitHub scheduling, outages and runner queues can delay a check. This is not a 24-hour guarantee. The latest run summary records observed versions and discovery state. |
| Candidate qualification | Start eligible candidates only through their registered, source-pinned adapter and existing two-CPU gates. | At most one SDK candidate is selected per run, with at most two native builds in parallel. Current build jobs have a 360-minute timeout; individual build/test stages are separately bounded. Missing/incompatible source, bootstrap inputs, capacity, or failed tests block admission. |
| Publication | Publish only after both native builds, full source/evidence checks, and public asset verification succeed. | There is no promised interval from upstream release to public Community release. The automatic lane covers only registered .NET 8/9 1xx and .NET 10 4xx adapter bands. Other bands and legacy SDK lines need a manual, separately qualified workflow. |
| Existing release maintenance | Preserve the verified release and channel receipts while the public artifacts remain available. | No per-SDK security patch cadence, remediation deadline or support SLA is promised. Upstream end-of-support releases receive no implied backport or vendor servicing. |

The scheduled lane checks stable metadata including upstream EOL channels. It
does not filter candidates by lifecycle state or turn an upstream release into
an admitted build. As reviewed on this date, SDK 10.0.403 is Active; SDK 9.0.123
and 8.0.133 are Maintenance-only at the upstream end-of-support boundary; SDK
7/6/5 and Core 3 are Maintenance-only and are not in the automatic update
adapter bands. A published old SDK remains available only according to its
current signed receipt and can still be withdrawn for integrity or legal
reasons.

## Capacity Basis

The objectives reflect the current automation limits rather than a staffing
promise:

- `profiles/upstream-policy.json` limits each scheduled workflow to one
  candidate SDK. The upstream workflow has a two-job maximum parallelism and
  native x64/AArch64 runners.
- The .NET 8/9 adapters require a 90-GiB planning gate; .NET 10 uses a 30-GiB
  planning gate. A missing resource budget blocks the candidate rather than
  weakening verification.
- Automatic admission has three reviewed feature-band adapters: .NET 8 and 9
  1xx, and .NET 10 4xx. A source/layout change requires a reviewed adapter and
  fresh qualification before automatic release.
- Maintainer review, source investigation and signing capacity are not
  numerically guaranteed. A release-critical review or credential custodian
  gap is a blocker; the project must not bypass it to meet a date.

## Latest State and Blocked Work

The [Upstream SDK workflow](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/upstream-sdk.yml)
is the latest-check record. Its run summary displays each observed SDK and
reason; the plan artifact is retained for 30 days. Reasons include
`pending-adapter`, `pending-source`, `pending-bootstrap`, `pending-publication-recovery`
and `candidate`. A failed run and its diagnostic artifact identify failed
qualification without changing the last published release. The
[release scorecard](https://dotnetdev.kr/cbodotnet/#qualification-scorecard)
and [signed availability receipts](../releases/downstream-status.json) remain
the source of the latest published state. An upstream `candidate` or successful
build alone is not a public release.

When a candidate stays blocked across a discovery cycle, maintainers should
open or update an issue with the exact pending reason, affected SDK band,
resource/source prerequisite and next review point. The issue is informational;
its date does not override the native qualification and signing gates. If no
maintainer capacity exists to own the prerequisite, leave the state pending and
communicate that no delivery date is available.