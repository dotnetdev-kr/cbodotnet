# Release Incident, Withdrawal and Recovery

**Reviewed:** 2026-11-10

This runbook covers public release incidents. It does not replace the
[distribution signing policy](distribution-signing.md),
[downstream release procedure](downstream-release-runbook.md),
[archive consumer verification](consumer-archives.md),
[musl release procedure](alpine-musl.md), or
[installer admission policy](cbodotnetup-design.md). The incident lead records
the affected SDK, channel, OS/CPU cell, release tag, asset digest, signer and
first-known-good/first-known-bad time before remediation.

## Severity and Communication

| Severity | Examples | Immediate action | Public update |
| --- | --- | --- | --- |
| SEV-1, trust or artifact compromise | Signing key exposure, substituted SDK/package/image bytes, invalid signed provenance, or a malicious/unsafe release. | Stop all promotion and signing jobs, revoke the affected signer where applicable, identify exact digests and stop advertising affected receipts. Escalate to repository owners immediately. | Publish a GitHub incident issue and update the download-site notice. State affected tags/digests, safe versions, user action and next update time. |
| SEV-2, incorrect or unavailable delivery | Wrong release metadata, repository indexes that cannot be authenticated, broken installer commands, or a published target that fails its claimed gate. | Pause the affected channel, preserve run and publication evidence, remove affected receipts from current availability inputs, and investigate the exact matrix cell. | Publish the affected scope, verification steps, workaround and next update time in a GitHub issue; link it from the download site. |
| SEV-3, delay without bad bytes | Delayed servicing, CI outage, pending source, quota or runner capacity issue with no evidence of compromised published assets. | Keep valid immutable releases available, mark new work pending, and do not bypass gates or publish an unqualified replacement. | Update the relevant GitHub issue or workflow status summary with the blocker and next review time. Do not label a valid release compromised. |

The incident lead owns severity, scope and user updates. The publisher operator
pauses or resumes protected workflows and updates active receipts. A second
maintainer reviews signer revocation, status changes and any replacement
revision. Only repository owners or authorized release maintainers change
GitHub Release visibility, repository permissions or protected environments.

## Containment and Withdrawal

1. Stop promotion before editing availability. Cancel queued or running
   publication jobs through GitHub Actions. For a signer incident, follow the
   [signing-key compromise procedure](distribution-signing.md) and do not sign
   with the affected key.
2. Preserve the exact workflow run, job logs, uploaded transport/frozen
   artifacts, manifests, signatures, reports, status files, release tag and
   affected asset digests. Save their URLs and hashes in the incident issue.
   Do not overwrite or delete immutable evidence.
3. Remove only affected entries from the active availability inputs:
   `releases/archive-status.json`, `releases/downstream-status.json`,
   `releases/musl-status.json`, or `releases/cbodotnetup-status.json`, as
   applicable. If every target in a channel is withdrawn, use its existing
   `not-published` state and empty publication/receipt arrays. A signed receipt
   removed from the current input remains in Git history and its original
   immutable Release remains evidence; removing a link does not revoke a file
   already downloaded or cached.
   For a base SDK release tagged `sdk-VERSION`, an authorized repository owner
   can move the affected GitHub Release back to draft. The release catalog
   excludes drafts, so the download page stops listing it; retain the tag and
   assets, and warn that cached/direct URLs may remain reachable. Do not delete
   the release as a substitute for preserving evidence.
4. For a compromised signer, also mark the fingerprint revoked in the reviewed
   signer policy, remove it from active verifier trust, publish the revocation
   certificate and affected digest list through trusted project channels, and
   follow key recovery/rotation guidance. A status edit alone does not revoke a
   signature or cached key.
5. For APT, RPM or OCI, separately disable the affected repository/tag or
   registry access using the authorized provider controls. A Pages link
   withdrawal alone does not stop clients with a configured URL or digest.
   Preserve repository snapshots and registry descriptors before changing
   visibility. Tell users to stop installs/updates from affected sources and
   remove or quarantine affected local artifacts.
6. Deploy Pages and verify the affected commands/links are absent from the
   public feeds. Verify the signed manifests and signer fingerprints of all
   unaffected records still advertised. Publish a correction notice with
   affected tags/digests, withdrawn targets, verified safe alternatives and a
   timestamp.

The JSON availability files are selection inputs, not detached signatures.
Consumers must check the current status page first, then authenticate each
advertised receipt using its detached signature and the independently trusted
key described in [distribution signing](distribution-signing.md). For musl,
also verify the separate signed public-verification manifest. For cbodotnetup,
verify the current signed catalog, sequence, expiry and key fingerprint before
installation. Do not infer availability from an old direct URL, cached package
index, mutable tag or historical scorecard row.

## Correction and Recovery

- Corrected SDK archives, packages, repositories and OCI descriptors use a new
  immutable release tag/revision and new signatures. Never replace bytes under
  an existing tag or asset name, retarget a tag, or reuse an old verification
  report for changed bytes.
- Downstream archive/package/OCI and musl channels have explicit package
   revisions; publish a higher revision through the full native and
   post-publication gates. The current base SDK schema accepts `sdk-VERSION`
   without an `rN` suffix. A corrected SDK payload for the same SDK version
   therefore needs a reviewed release-format/workflow change before publication;
   do not improvise a tag or reuse `sdk-VERSION`. Until that change is qualified,
   keep the affected SDK Release in draft and announce that no corrected build is
   available.
- Re-run every affected native build/install/public-verification gate required
  by that channel. A correction is not available until the new signed receipt
  is post-verified and Pages reflects it.
- Keep the prior incident receipt, failed run, signatures and digests in source
  history. Do not erase the forensic trail when the replacement becomes
  available.
- Resume paused workflows only after the incident lead and a second authorized
  maintainer approve the scope, signer state, correction revision and public
  communication. If no correction is qualified, keep the target withdrawn.

## Tabletop: Bad SDK Archive Digest

Use this exercise before handling a real incident. It is read-only against
production and mutates temporary copies only.

1. Inject a report that one published SDK archive has a digest mismatch. The
   incident lead identifies its version, revision and architecture; the
   publisher operator cancels promotion and records the relevant run, signed
   manifest and digest; the communication lead drafts the user notice.
2. In temporary copies of archive, downstream, musl and installer status,
   withdraw all simulated publication rows. Run
   `PYTHONPATH=scripts python3 tests/release-incident-runbook-test.py`.
3. Confirm the exercise produces no archive, APT/RPM/OCI, Alpine or installer
   links, while the repository's original receipt/status bytes and immutable
   release URLs remain unchanged.
4. Inject a corrected candidate under a new revision. Do not make it public
   during the tabletop; record the native, signature and post-verification
   gates that must pass before restoring availability.
5. Close the exercise only when the notice identifies the affected digest,
   safe alternative, user action and next update time, and two maintainers
   agree that the old bytes were not overwritten.