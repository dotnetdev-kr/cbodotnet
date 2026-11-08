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

SDK 8 also builds historical API-signature reference packages. Their exact
identities are compilation contracts; changing a reference version to silence
an advisory would change that contract. The pinned upstream
[reference-package description](https://github.com/dotnet/dotnet/blob/7d1bf90885cff22e7da72b27e9848e42fd3cb1ae/src/source-build-assets/README.md)
distinguishes these signatures from implementations. Auditing remains enabled
and every warning remains visible. Only `source-build-assets/src/referencePackages`
uses `WarningsNotAsErrors` for audit diagnostics. The producer independently
requires the exact 15 project/package/version/advisory records observed on
both native CPUs, as recorded in
[the closed disposition](../scripts/musl-reference-audit-policy.json).
An unknown or missing diagnostic fails verification. All other projects retain
their normal audit errors.

The actual ARM64 SDK 8.0.131 bootstrap was tested with a vulnerable package:
the strict control failed, the reference-scoped property preserved its visible
warning and succeeded, and a separate outside-scope control failed again.
These are development diagnostics, not SDK qualification. Protected source
admission reparses the actual build log and rechecks the final SDK, including
nested package DLLs. Signature stubs may ship as compilation references in
`ref` directories; placing one in an SDK host/runtime path fails admission.
This disposition never qualifies a vulnerable runtime implementation.

SDK 9's build-helper MSBuild reference is updated from 17.8.29 to 17.8.43.
The helper's transitive ASN.1 reference is pinned to fixed 8.0.1. These minimal
source patches address the upstream advisories
[CVE-2025-55247](https://github.com/advisories/GHSA-w3q9-fxm7-j8fq) and
[GHSA-447r-wph3-92pm](https://github.com/advisories/GHSA-447r-wph3-92pm).
They preserve NuGet auditing and product MSBuild source identity. Actual
restored inputs and patch bytes are retained in producer evidence.

Templating's coordinated NuGet references are serviced to 6.12.5 for
[the NuGet client validation update](https://github.com/advisories/GHSA-g4vj-cjjj-v7hg).
Razor's MessagePack reference stays on the compatible 2.x line at 2.5.303,
including [the later correction](https://github.com/advisories/GHSA-qhrr-8q5h-9q3h).
The nine exact package inputs are bound to their SHA512, publisher source
commit and license expression. Complete corresponding NuGet and MessagePack
Git sources, including the pinned localization submodule and required notices,
are retained with independently checked actual restore records.

The modern build image adds pinned stock `krb5-dev` headers needed to compile
the native runtime. SDK10's build recipe and runtime dependency policy remain
intact. Normal modern builds retain MSBuild diagnostics without forcing runtime
minidumps on Crossgen2 tool packages; ReadyToRun optimization remains enabled.

The separate `musl-release.yml` requires an explicit SDK version. Source
receiving authenticates the real workflow attempt, artifact API identity and
digest, transport envelope, sealed producer evidence, and used-source package
again. An exact source-manifest digest must then be reviewed into
`qualified-musl-builds.json` before any consumer can build. Branded archives,
per-series APK packages and distinct OCI tags need their own native and
anonymous public checks on both CPUs; six exact public reports are bound by a
separate signed final verification manifest before availability is activated.
SDK 9 or 8 installer admission requires separate qualification.

SDK 9's F# test tracing uses the maintained OTLP 1.15.3 exporter because the
deprecated Jaeger exporter has no fixed release for its advisory. The original
test graph, compiler activity source, spans, tags and flush/disposal lifecycle
remain intact. Native audited restoration and actual HTTP/Protobuf export were
tested. All 17 introduced package inputs retain exact corresponding sources
and notices. DiagnosticSource 10 distinguishes its published VMR commit from
the runtime component commit: protected validation checks the exact publisher
manifest and reconstructs the complete corresponding libraries Git tree.

The regular SDK 9 ASP.NET adapter also forwards the explicit portable musl
target. Crossgen2 uses the actual private SDK host RID to select its native
compiler package while retaining `linux` as the target OS. Real .NET 9 MSBuild
evaluation checked native musl, glibc-host and x64-property controls. Source-only
task exclusions remain confined to their original source-only branch;
ReadyToRun optimization and original project coverage remain enabled.

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
