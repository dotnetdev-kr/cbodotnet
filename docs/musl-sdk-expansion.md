# Native Alpine SDK expansion

SDK 10 remains the only qualified musl distribution and the only SDK admitted
to the signed `cbodotnetup` musl catalog. Candidate profiles and successful
component experiments do not activate a source producer, download, APK, OCI
image, or installer catalog entry.

## SDK 9 and 8

Issue [#32](https://github.com/dotnetdev-kr/cbodotnet/issues/32) uses the original
tagged VMRs, in SDK 9 then SDK 8 order. The exact commits, native bootstrap
archives, stock Alpine 3.24.4 images, APK indexes, compilers and source patches
are pinned in the per-CPU `profiles/dotnet-*-linux-musl-*.json` files. Neither
route reuses a glibc bootstrap or a complete imported final SDK as its output.

`musl-sdk-expand.yml` invokes `musl-sdk-expand.py` on matching x64 and AArch64
GitHub runners. Each fresh producer must pass source preparation, original
build, scan, original upstream tests, complete corresponding-source collection,
and offline native SDK-free verification. SDK 9 records each actual shared
framework producer and compares its complete file contents with the final
SDK. SDK 8 retains both pristine and transformed source-built bootstrap inputs.
The upstream comparison SDK is test input and must differ from the built SDK.

SDK 9's build-helper MSBuild reference is updated from 17.8.29 to 17.8.43.
The helper's transitive ASN.1 reference is pinned to fixed 8.0.1. These minimal
source patches address the upstream advisories
[CVE-2025-55247](https://github.com/advisories/GHSA-w3q9-fxm7-j8fq) and
[GHSA-447r-wph3-92pm](https://github.com/advisories/GHSA-447r-wph3-92pm).
They preserve NuGet auditing and product MSBuild source identity. Actual
restored inputs and patch bytes are retained in producer evidence.

The separate `musl-release.yml` requires an explicit SDK version. Source
receiving authenticates the real workflow attempt, artifact API identity and
digest, transport envelope, sealed producer evidence, and used-source package
again. An exact source-manifest digest must then be reviewed into
`qualified-musl-builds.json` before any consumer can build. Branded archives,
per-series APK packages and distinct OCI tags need their own native and
anonymous public checks on both CPUs; six exact public reports are bound by a
separate signed final verification manifest before availability is activated.
SDK 9 or 8 installer admission requires separate qualification.

Expanded SDK APK candidates also receive the actual public SDK 10 r1 packages.
The reference's signed metadata, approved key, index, package bytes and complete
payload inventory are checked against the existing public receipt and original
qualified SDK. A fresh offline container then exercises twelve transactions
with both real Community series and the independent stock official SDK. It
checks versioned commands, branding, highest-series selection, removal fallback,
reinstall, upgrade and rollback, both complete immutable payloads, and unchanged
official SDK files. Protected promotion replays the closed proof against the
exact retained reference metadata and independently reconstructed candidate
payload; a single Community series proof cannot qualify an expanded SDK.

## Existing installer releases

Expanding the consumer helpers changes their source hashes without changing
the compiled installer. `cbodotnetup_retained_musl.py` permits the four exact
published 0.5.0/0.5.1 build reports from run 42387946152. The complete canonical
report digest must match, and every compiled source input must still match the
current source. This does not accept a new build or changed executable under an
old version. Actual binary hashes, authenticated SDK, current vulnerability
audit, and fresh native candidate/public qualifications remain required during
catalog renewal. A current build still needs the complete current helper,
container, profile and frozen APK input inventory.

## Older SDKs

Issues [#33](https://github.com/dotnetdev-kr/cbodotnet/issues/33),
[#34](https://github.com/dotnetdev-kr/cbodotnet/issues/34), and
[#35](https://github.com/dotnetdev-kr/cbodotnet/issues/35) require independent
source and native dependency work. None is admitted through the modern VMR
dispatcher. The choices reserved in the workflow fail closed until a reviewed
producer implementation exists; they are not advertised downloads.
