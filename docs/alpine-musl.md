# Alpine / musl qualification

SDK 10.0.403 revision 1 is published and independently qualified on Alpine
3.24.4, using native x86_64 and AArch64 runners. Archive, APK and OCI delivery
each passed qualification and anonymous installation from the published bytes.
The [signed final verification](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/verification-musl-sdk-10.0.403-r1)
binds all six public native reports. The separate
[musl status](../releases/musl-status.json) is authoritative for availability.

The [static musl contract](../releases/musl-distribution-contract.json) retains
`publicationAllowed: false` and `candidate-only`: it describes structural
candidates and cannot authorize a release. Source admission comes from the
[qualified producer catalog](../releases/qualified-musl-builds.json), and
availability comes from the OpenPGP-authenticated final proof and
`musl-status.json`. The SDK-series assessment also remains informational with
`qualificationAllowed: false`. These guards do not describe the published
revision as unavailable.

Existing glibc archives, distribution metadata and historical cbodotnetup feeds retain
their existing identities. The new producer tag prefix is `musl-sdk-`, consumer
tags start with `distribution-musl-`, and archives use
`cbodotnet-sdk-<version>-linux-musl-<x64|aarch64>-r<revision>.tar.gz`.
Public `aarch64` maps to the .NET RID `linux-musl-arm64`; OCI `linux/arm64` alone
does not identify libc, so Alpine images require their explicit musl tag.

## Published revision and evidence

| Stage | Published evidence | Successful workflow |
| --- | --- | --- |
| Producer | [SDK, corresponding sources and retained evidence](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/musl-sdk-10.0.403-r1) | [Native SDK producer](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/42368648443) |
| Archive | [Signed archive revision 1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-musl-archive-sdk-10.0.403-r1) | [Both native CPUs and anonymous public checks](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/42376221830) |
| APK | [Signed package, repository and lifecycle records](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-musl-apk-sdk-10.0.403-r1) | [Both native CPUs and anonymous APK installs](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/42376232763) |
| OCI | [Signed multi-platform image descriptor](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-musl-oci-sdk-10.0.403-r1) | [Both native CPUs and anonymous digest pulls](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/42376246499) |
| Final verification | [Six unchanged public reports and signed manifest](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/verification-musl-sdk-10.0.403-r1) | [Independent final verification](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/42377669287) |

The final `verification-manifest.json` SHA-256 is
`8be34fa684fa6d4a48fc74a36fe6258d7cd725dfaeb646673b1139a85950e8b3`.
It binds source manifest
`04b3ff71eec9a508c65bf5c22c13f189def3ba576e55f5593cff7378224c3344`
and the exact signed receipts for all three delivery channels. Verify the
detached OpenPGP signature with the project's reviewed public signing key.

## Evidence and support boundary

The [Alpine release table](https://www.alpinelinux.org/releases/) identifies
3.24 as a supported stable branch. Its point release and image digests are pinned
at implementation time. The [Microsoft installation guide](https://learn.microsoft.com/en-us/dotnet/core/install/linux-alpine)
and each SDK's supported-OS table can differ in update timing; consult both.
Project qualification on a newer Alpine version is described as community
qualification and does not create a Microsoft support commitment.

The SDK 10 route is a regular VMR build. Imported shared framework inputs must
be attributed to their matching VMR and package identities; rebuilding SDK tools
does not mean every bundled component was rebuilt. Qualification retains the
complete used sources and original licenses/notices, audits every payload ELF
and native dependency, and tests an SDK-free, non-root offline consumer.
Foreign target packs require explicit path/RID dispositions. Compatibility
layers, glibc loaders and the existing Rocky providers cannot establish native
musl compatibility.

Workloads and NativeAOT application compilation require separate qualification.
The [native cbodotnetup manager](cbodotnetup-musl.md) has its own NativeAOT,
SDK-free bootstrap, trust and SDK admission gates under
[#30](https://github.com/dotnetdev-kr/cbodotnet/issues/30).

## Installation

The download site's Alpine section and the signed final verification record
identify this exact SDK and packaging revision. APK signatures and
OpenPGP publication signatures use separate keys; see the
[APK signing and rotation policy](alpine-apk-signing.md).

For Alpine APK installation, download the project key over HTTPS, check its
reviewed SHA-256, and install it into the system APK trust store. The immutable
APK release below contains the same 800-byte PEM public key as the download
site's `cbodotnet-apk-2026.rsa.pub` and `apk-signing-key.json` fingerprint record.

```sh
apk add --no-cache curl ca-certificates
curl -fL https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-musl-apk-sdk-10.0.403-r1/cbodotnet-apk-2026.rsa.pub -o cbodotnet-apk-2026.rsa.pub
printf '%s\n' 'd464a8e7c173c1a86ad65f92abb1d56fd1f362dbcaf30b4b3929355bc6a49c2d  cbodotnet-apk-2026.rsa.pub' | sha256sum -c -
install -m 0644 cbodotnet-apk-2026.rsa.pub /etc/apk/keys/cbodotnet-apk-2026.rsa.pub
case "$(apk --print-arch)" in
  x86_64) arch=x64 ;;
  aarch64) arch=aarch64 ;;
  *) echo 'This CPU is not qualified' >&2; exit 1 ;;
esac
repository="https://github.com/dotnetdev-kr/cbodotnet/releases/download/musl-apk-repo-10.0.403-alpine324-${arch}-r1/APKINDEX.tar.gz"
apk add --repository "$repository" cbodotnet-sdk-10.0=10.0.403-r1
cbodotnet --info
```

The packages and index use RSA-4096/SHA-256 (`RSA256`). The public key's DER
SubjectPublicKeyInfo SHA-256 is
`784ae05c3339c239f715cb0b849dead89e6a1b787a8126c738d6997227a63e20`.
The signed aggregate authenticates separate immutable
[x64](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/musl-apk-repo-10.0.403-alpine324-x64-r1)
and [AArch64](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/musl-apk-repo-10.0.403-alpine324-aarch64-r1)
repository releases. No untrusted-package option is needed.

Key installation and APK transactions require root; application builds run as
an ordinary user. The SDK installs under `/opt/cbodotnet/10.0`, provides
`cbodotnet-10.0` and the shared `cbodotnet` selector, and preserves a separately
installed official `dotnet`. Repeating the explicit APK command pins the same
immutable revision. `apk del cbodotnet-sdk-10.0` removes that SDK; remove
`cbodotnet-host` separately when no Community SDK needs the selector.

The archive includes its own launcher and SDK tree and follows the signed
[consumer archive verification procedure](consumer-archives.md). Choose the
explicit `linux-musl-x64` or `linux-musl-aarch64` asset shown in the Alpine
section. Its manifest binds the qualified source, SDK bytes and licenses.

The OCI variant uses the explicit tag
`ghcr.io/dotnetdev-kr/cbodotnet-sdk:10.0.403-alpine324-musl-r1`.
Its signed two-platform index digest is
`sha256:4d2e44fe4543a761718d27323006c54609312c8d81bbf574dffb00b6278d4f19`.
For an immutable image invocation:

```sh
docker run --rm ghcr.io/dotnetdev-kr/cbodotnet-sdk:10.0.403-alpine324-musl-r1@sha256:4d2e44fe4543a761718d27323006c54609312c8d81bbf574dffb00b6278d4f19 cbodotnet --info
```

It defaults to the unprivileged `app` user (UID/GID 1654),
and `cbodotnet-10.0`, `cbodotnet` and `dotnet` all execute the Community CLI.
The image uses stock musl dependencies, full ICU data, the timezone database
and system CA roots. Native source-build toolchains and workspaces are excluded.

## Release gates

`musl-sdk.yml` builds the original pinned VMR independently on native x64 and
AArch64. Build and SDK-free verification images consume preserved, stock-signed
[APK index snapshots](../inputs/alpine-3.24.4/index-snapshots.json); every actual
package transaction and source/bootstrap input is retained in evidence.
The unmodified upstream binary scanner, upstream tests, corresponding sources,
ELF dependency audit and native SDK verification must all pass.

The [native host investigation](musl-native-host-validation.json) records the
Ubuntu runner's Podman/AppArmor signal-denial evidence and the isolated restore
and scanner controls. Normal producers use rootful Docker with its default
enforced AppArmor and seccomp policies, dropped capabilities and non-root users.
Admission binds the actual engine version, kernel, daemon settings and observed
process security to the retained evidence. Source-only diagnostic runs use a
separate mode that cannot enter the qualification catalog.
Producer images pin full ICU data as well as the runtime images. An offline
bootstrap preflight checks the culture assignment needed for all thirteen
localized satellite assemblies; the
[localization control](musl-localization-validation.json) records the native
English-only/full-data comparison with the original XLIFF sources.
The [test-routing control](musl-test-routing-validation.json) records the
upstream Alpine convention: SDK compilation retains its Linux base OS and
explicit musl RID, while the original test harness receives portable OS
`linux-musl` to select the native scenario graph. The original test identities,
traits and accepted skips are retained.

`musl-release.yml` then runs the `producer`, `archive`, `apk` and `oci` phases.
After the successful producer is published and admitted in the source catalog,
the three consumer channels may run in parallel. Channel-specific concurrency
serializes repeated publishers, including the canonical OCI index writer.
Consumer promotion reconstructs candidates from the admitted SDK and verifies
the actual GitHub artifact ZIP digest and native job identity before signing.
The APK signer changes only the signature envelope; original compressed control
and payload bytes remain bound to native qualification and lifecycle proof.
OCI publication binds both real platform manifests and configs to an immutable
musl index without changing historical glibc tags.

Each channel repeats installation and execution from actual anonymous public
bytes on both native CPUs. The final `verification` phase receives the three
completed channel run/attempt pairs, authenticates their API provenance and six
unchanged public reports, and publishes a separately signed verification release.
Only its reviewed status candidate can activate `musl-status.json` and the
download-site panel. A failed or fixture-only run never becomes a release input.
The [regression record](musl-regression-validation.json) preserves the existing
release assets, glibc OCI tags and provider/installer inputs for comparison
before and after musl publication.

For operators, complete publishing-workflow edits and their checks before
dispatch. Keep the reviewed publishing workflow bytes unchanged through the
final GitHub release PATCH and completion of the publication runs. Source
publication encountered [GitHub's workflow-diff permission guard](https://docs.github.com/en/rest/releases/releases#create-a-release) when those
bytes differed during publication. Preserve the exact checkout/workflow SHA
and the existing scoped job token and protected signing environment; broader
credentials are not a workaround for this sequencing requirement.

## Other SDK series

The [machine-readable assessment](../releases/musl-sdk-assessment.json) records
official release-metadata URLs, observed content hashes, exact SDK file entries
and lifecycle information as observed on 2026-11-07, alongside the independently
verified delivery disposition. This informational assessment does not authorize
admission. Upstream file existence alone is a candidate input. Lifecycle and
Alpine dependencies must be checked again when each follow-up starts.

| SDK | Current disposition | Follow-up |
| --- | --- | --- |
| 10.0.403 | Published and post-verified: Alpine 3.24.4, native x64/AArch64, archive/APK/OCI r1 | [#24](https://github.com/dotnetdev-kr/cbodotnet/issues/24) |
| 9.0.123, 8.0.133 | Pending; upstream musl SDK files exist for both CPUs | [#32](https://github.com/dotnetdev-kr/cbodotnet/issues/32) |
| 7.0.120, 6.0.136 | Pending legacy source and dependency review; upstream EOL | [#33](https://github.com/dotnetdev-kr/cbodotnet/issues/33) |
| 5.0.214 | Pending legacy musl producer and SSL/ICU/curl investigation; upstream EOL | [#34](https://github.com/dotnetdev-kr/cbodotnet/issues/34) |
| 3.1.426, 3.0.103 | Two-CPU delivery blocked pending an ARM64 musl source/bootstrap route and dependency strategy | [#35](https://github.com/dotnetdev-kr/cbodotnet/issues/35) |

Core 3 metadata lists selected x64 musl SDKs and no selected ARM64 musl SDK.
This is an input gap, not proof that a source port is impossible. Existing glibc
ARM64 results cannot fill it. The Core 3 follow-up must establish a native route
or record a reviewed scope decision before advertising any musl delivery.
No additional security maintenance is promised for EOL SDKs.
