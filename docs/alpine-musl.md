# Alpine / musl qualification

Issue [#24](https://github.com/dotnetdev-kr/cbodotnet/issues/24) develops a separate
native musl distribution. The initial candidate is SDK 10.0.403 on Alpine 3.24.4,
with real x86_64 and AArch64 runners. It is not available until producer, consumer,
APK and OCI publication and public verification gates pass. The separate
[musl status](../releases/musl-status.json) is authoritative for availability.

Existing glibc archives, distribution metadata and cbodotnetup 0.4.0 feeds retain
their existing identities. The new producer tag prefix is `musl-sdk-`, consumer
tags start with `distribution-musl-`, and archives use
`cbodotnet-sdk-<version>-linux-musl-<x64|aarch64>-r<revision>.tar.gz`.
Public `aarch64` maps to the .NET RID `linux-musl-arm64`; OCI `linux/arm64` alone
does not identify libc, so Alpine images require their explicit musl tag.

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

Workloads and NativeAOT are not qualified by the base SDK tests. cbodotnetup
bootstrap and musl SDK admission belong to
[#30](https://github.com/dotnetdev-kr/cbodotnet/issues/30).

## Installation after publication

Use these commands only after the download site's Alpine section and the
signed public verification record identify this exact revision as available.
The current candidate does not establish availability. APK signatures and
OpenPGP publication signatures use separate keys; see the
[APK signing and rotation policy](alpine-apk-signing.md).

For Alpine APK installation, download the project key over HTTPS, check its
reviewed SHA-256, and install it into the system APK trust store. The same public
key and a machine-readable fingerprint are published on the download site as
`cbodotnet-apk-2026.rsa.pub` and `apk-signing-key.json`.

```sh
apk add --no-cache curl ca-certificates
curl -fL https://dotnetdev.kr/cbodotnet/cbodotnet-apk-2026.rsa.pub -o cbodotnet-apk-2026.rsa.pub
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
Use the signed `oci-index.json` digest from the Alpine section to pin the
two-platform image. It defaults to the unprivileged `app` user (UID/GID 1654),
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

`musl-release.yml` then runs the `producer`, `archive`, `apk` and `oci` phases.
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

## Other SDK series

The [machine-readable assessment](../releases/musl-sdk-assessment.json) records
official release-metadata URLs, observed content hashes, exact SDK file entries
and lifecycle information as observed on 2026-11-07. Upstream file existence is
a candidate input, not successful cbodotnet qualification. Lifecycle and Alpine
dependencies must be checked again when each follow-up starts.

| SDK | Initial disposition | Follow-up |
| --- | --- | --- |
| 10.0.403 | Pending native producer and complete delivery qualification | [#24](https://github.com/dotnetdev-kr/cbodotnet/issues/24) |
| 9.0.123, 8.0.133 | Pending; upstream musl SDK files exist for both CPUs | [#32](https://github.com/dotnetdev-kr/cbodotnet/issues/32) |
| 7.0.120, 6.0.136 | Pending legacy source and dependency review; upstream EOL | [#33](https://github.com/dotnetdev-kr/cbodotnet/issues/33) |
| 5.0.214 | Pending legacy musl producer and SSL/ICU/curl investigation; upstream EOL | [#34](https://github.com/dotnetdev-kr/cbodotnet/issues/34) |
| 3.1.426, 3.0.103 | Two-CPU delivery blocked pending an ARM64 musl source/bootstrap route and dependency strategy | [#35](https://github.com/dotnetdev-kr/cbodotnet/issues/35) |

Core 3 metadata lists selected x64 musl SDKs and no selected ARM64 musl SDK.
This is an input gap, not proof that a source port is impossible. Existing glibc
ARM64 results cannot fill it. The Core 3 follow-up must establish a native route
or record a reviewed scope decision before advertising any musl delivery.
No additional security maintenance is promised for EOL SDKs.
