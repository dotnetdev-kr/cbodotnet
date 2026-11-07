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
