# Signing Key Stewardship and Trust Boundaries

**Review date:** 2026-11-10

This inventory separates project signing credentials from distribution-vendor
keys and GitHub transport metadata. No private key, secret value, recovery
certificate or sensitive account identifier belongs in this repository.

## Project-Controlled Signing Identities

| Identity | Authorizes | Public verification | Private custody and use |
| --- | --- | --- | --- |
| OpenPGP Ed25519 `D7D154B4B33C19A82B95B13688135410ACD9C0EA` | Downstream distribution manifests and detached signatures, APT/RPM metadata and RPM package signatures, consumer archive and installer catalog metadata, and the signed musl publication/verification chain. | [`releases/downstream-signing-key.asc`](../releases/downstream-signing-key.asc); full fingerprint and validity in [`releases/downstream-status.json`](../releases/downstream-status.json) and [`releases/musl-signing-policy.json`](../releases/musl-signing-policy.json). Users must verify the complete primary fingerprint through a separately trusted project channel and validate the signed manifest/receipt. | `DOWNSTREAM_SIGNING_KEY` and `DOWNSTREAM_SIGNING_REVOCATION` are GitHub Environment secrets in `downstream-release`; publishing workflows import them only in protected jobs. The key validity ends 2028-11-03. This signer does not qualify SDK source or imply Microsoft support. |
| Alpine APK RSA-4096 / RSA256 | Alpine APK package and APKINDEX signatures only. It does not sign OpenPGP distribution manifests or authorize glibc package publication. | [`releases/cbodotnet-apk-2026.rsa.pub`](../releases/cbodotnet-apk-2026.rsa.pub); SPKI SHA-256 `784ae05c3339c239f715cb0b849dead89e6a1b787a8126c738d6997227a63e20` and exact PEM SHA-256 `d464a8e7c173c1a86ad65f92abb1d56fd1f362dbcaf30b4b3929355bc6a49c2d` are bound by [`releases/musl-signing-policy.json`](../releases/musl-signing-policy.json) and the signed publication manifest. Verify the PEM pin, then use `apk verify` and signature-enforced installation. | `APK_SIGNING_KEY` is a separate secret in the same protected environment, consumed only by the APK publisher job in `.github/workflows/musl-release.yml`. Its publisher-enforced rotation cutoff is 2028-11-07. Raw APK keys have no native expiry or remote revocation mechanism. |

The OpenPGP signer and APK signer are different keys with different purposes.
Compromise or expiry of one does not authenticate, revoke or rotate the other.
The environment is restricted to the reviewed `main` branch and only the
publishing workflows reference its private key secrets. The repository API
reported 10 admin collaborators at this review, but that does not identify
which people can recover environment secrets or the revocation certificate.
The environment currently has a branch-policy protection rule and no required
reviewer rule. These controls therefore do not establish two-person signing
approval or independent key custody.

## External Trust Inputs and Non-Signatures

| Trust input | Scope and boundary |
| --- | --- |
| Rocky Linux 9 RPM key `21CB256AE16FC54C6E652949702D426D350D275D` | Verifies Rocky-signed OpenSSL/ICU RPM and source RPM inputs for the legacy compatibility provider. It is a vendor key, not a cbodotnet signing identity. See [`releases/legacy-compatibility-provider.json`](../releases/legacy-compatibility-provider.json). |
| Rocky Linux 8 RPM key `7051C470A929F454CEBE37B715AF5DAC6D745A60` | Verifies Rocky-signed curl RPM and source RPM inputs for the Core 3 native HTTP provider. It is a vendor key, not a cbodotnet signing identity. See [`releases/legacy-curl-provider.json`](../releases/legacy-curl-provider.json). |
| OS vendor package keys | Ubuntu, Debian, Fedora and other system package-manager keys authenticate vendor packages from their configured repositories. They remain vendor-controlled and are not project release keys. Exact installed package proofs are retained with each relevant native report. |
| GitHub artifact IDs and SHA-256 digests | Identify transport bytes and detect alteration relative to GitHub API metadata. They are not detached signatures or proof of a trusted source by themselves. Check the trusted workflow, repository/ref/commit, run and attempt, expected artifact ID, digest, and the project-signed release/evidence manifest. |

The signed project manifest binds producer/source identities and asset hashes;
`SHA256SUMS` detects byte changes only when obtained through an authenticated
path. For APT/RPM and APK repository metadata, users must additionally verify
the appropriate package-manager signature. An OCI digest pins image bytes but
does not replace the signed distribution/verification records that connect the
digest to the qualified source and native consumer results.

## Custody and Continuity Assessment

The checked-in policies identify public keys, secret names, protected
environment and authorized workflows. The private key values cannot be read
back from GitHub after creation, and repository administration alone does not
prove recoverability. The repository does not document an independently
verified, off-platform backup or a completed restoration drill for either
private signer. Treat loss of the environment credential or its sole recovery
path as a release-continuity risk. Never export private material into Git,
workflow artifacts, logs, issues or this policy.

Staged remediation, without changing current keys:

1. Name a primary and a deputy custodian through the existing private owner
   channel. Confirm that each can perform the required repository/environment
   administration without sharing credentials.
2. Require an independent maintainer review for protected signing environment
   changes and key rotation. Review GitHub environment protection and recovery
   access at least twice per year; record the review outcome, not secret values.
3. If an offline recovery copy is approved, store it encrypted under a
   separately controlled recovery process with two-person access. Document
   location, custody roles and revocation steps privately; do not publish those
   details in this repository.
4. Perform a scheduled recovery tabletop with a disposable test key and
   environment. Prove that a successor public key can be authenticated, signed
   test metadata can be verified, and the former key can be revoked without
   exposing production credentials. Repeat after any environment or custodian
   change.

No additional key is created or rotated by this review. A real rotation requires
explicit owner approval, an overlap period, successor-key verification through
existing trust channels, native installation checks, and preservation of the
old public key and immutable signed releases. Follow the operational procedures
in [OpenPGP distribution signing](distribution-signing.md) and
[Alpine APK signing](alpine-apk-signing.md). For suspected compromise, stop
publication and use the [release incident runbook](release-incident-runbook.md).