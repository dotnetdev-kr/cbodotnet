# Security Policy

## Private Reporting

Do not disclose an unpatched vulnerability in a public issue, discussion,
pull request, commit, or release comment. Use
[GitHub private vulnerability reporting](https://github.com/dotnetdev-kr/cbodotnet/security/advisories/new)
to send a confidential report to the repository maintainers. The repository
Security tab exposes the same channel.

Reports may cover this repository's build and release workflows, source
provenance checks, signing and verification, package/OCI publication, or
`cbodotnetup` catalogs and installation code. Include affected versions,
release tags or artifact digests, operating system/architecture, impact, and
minimal reproduction steps. Do not include passwords, access tokens, private
signing keys, personal data, or a weaponized proof of concept when a safer
reproduction is possible. Attach only files needed for triage.

## Scope and Version Guidance

cbodotnet is a community distribution project. A published build is not a
Microsoft-supported product, distribution-vendor-supported package, or promise
of vulnerability remediation. The [support lifecycle policy](docs/support-lifecycle.md)
distinguishes upstream support from project maintenance; the
[signed status feeds](https://dotnetdev.kr/cbodotnet/#qualification-scorecard)
identify the exact versions, targets and channels currently advertised.

Reports are accepted for any previously distributed version or target. Triage
prioritizes the currently advertised SDKs and release/publishing infrastructure.
`Active` means upstream servicing is active, not that cbodotnet guarantees a
patch. `Maintenance-only` includes upstream end-of-support lines: fixes may not
be available or feasible, and no new servicing commitment is created by a
report. Archived or withdrawn artifacts remain in scope for integrity and
provenance reports, but may receive no replacement build.

Upstream .NET runtime, SDK or dependency vulnerabilities should also be sent to
the relevant component publisher through its official security-reporting
channel. This repository does not speak for Microsoft or other upstream
maintainers and will coordinate private details with the reporter before
forwarding them.

## Triage and Disclosure

Maintainers aim to acknowledge a private report within five business days and
provide an initial scope/impact assessment within ten business days. These are
best-effort targets, not a response SLA; capacity, reproduction needs and
upstream coordination can delay them. If a target is missed, maintainers should
update the private advisory with the reason and next review point.

The triage checklist is:

1. Keep the report private; confirm receipt and agree on a safe contact path.
2. Reproduce the issue against exact source commits, release tags, signed
   manifests and artifact digests. Identify affected versions, channels and
   OS/CPU cells without publishing exploit details.
3. Classify impact and urgency. A suspected signing-key or artifact compromise
   immediately follows the [release incident runbook](docs/release-incident-runbook.md)
   and [signing-key compromise procedure](docs/distribution-signing.md).
4. Coordinate upstream reports where the affected code is owned by another
   project. Do not disclose the reporter's identity or private report without
   consent, except where law or an immediate safety obligation requires it.
5. Agree on a disclosure date with the reporter. Before public disclosure,
   complete the normal native, signing, source and public-verification gates for
   any replacement artifact. A patched commit or successful local test alone
   does not qualify a release.
6. Publish a GitHub Security Advisory when appropriate, then link the advisory,
   affected/fixed versions, mitigation and signed release receipts from the
   relevant release notes or incident issue. If no fix is available, state that
   clearly and provide a safe mitigation or withdrawal notice where possible.
7. Close the private advisory only after the reporter has been notified and
   the public status accurately reflects the verified remediation or remaining
   risk.

Do not promise a fix date, CVE assignment, backport, or support for an upstream
end-of-life SDK. Keep public discussion limited to the agreed disclosure until
the advisory is ready.