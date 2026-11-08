# Core3.1 musl source and certificate checkpoint

This extends the [initial issue35 investigation](core3-musl-investigation.md), preserving its committed files. Native ARM64 now compiles a genuine `Microsoft.NET.Sdk` component package from the pinned source and runs certificate rejection tests in the separate minimal runtime image. A complete source-built SDK/toolset has **not** been produced or admitted. The [machine-readable checkpoint](core3-musl-source-phase.json) records the actual logs, commands, input/output byte hashes, failed attempts and pending gates; every qualification/admission flag remains false.

The new [source probe](../scripts/core3-musl-source-probe.py) and [experimental input pins](../profiles/experimental/core3-musl-source.json) reproduce four bounded modes. These ran on native ARM64 Alpine3.24.4 under local rootful Podman in the D-backed task WSL distro, with non-root containers, dropped capabilities and no emulation. Final native x64/ARM64 GHA Docker qualification remains separate.

| Actual proof | Result and limit |
| --- | --- |
| Source components | Original SDK tasks `netcoreapp2.1` and core-sdk tasks `netcoreapp3.1` compile. These are component outputs. |
| Source package | Original SDK task project compiles **both** original TFMs (`netcoreapp2.1`, `net472`) and packs `Microsoft.NET.Sdk.3.1.426-servicing.22566.17.nupkg`. All96 members are hashed; the package contains no ELF or bootstrap performance-test SDK directories. |
| Source-generated SDK metadata | Original core-sdk `BuildCoreSdkTasks;GenerateBundledVersionsProps` generates SDK3.1.426 and `NETCoreSdkRuntimeIdentifier=linux-musl-arm64`. Its source metadata was not patched. |
| Certificate validation | Shared [reviewed fixture](../scripts/musl-negative-certificates.cs) uses default `SslStream` with no permissive callback. A trusted localhost control connects; self-signed/untrusted, expired, wrong-hostname and invalid-CA certificates reject. Invalid-CA `X509Chain` reports `InvalidBasicConstraints`, exercising the OpenSSL3 error mapping. |
| Runtime-only repetition | The same compiled fixture passes with normal `COMPlus_ReadyToRun=1`, full ICU, no SDK/compiler/dev packages, `--network=none` and loopback TLS. Shared full ELF closure passes. Temporary public test roots/intermediates live only in an ephemeral HOME/CurrentUser store and are removed in `finally`. |

The original outer SDK project also copies bootstrap SDK siblings for its performance tests. Those diagnostic copies are outside the component package, are **not** fresh compilation outputs, and are excluded from the retained source-output selection. A first attempted removal hook did not eliminate every sibling; the actual package-member audit determines the scope. Component package bytes can differ across these diagnostic runs because temporary source paths and generated package metadata differ. This is not a bit-reproducible build claim.

The private bootstrap imports SDK3.1.425 PE/data only and excludes every ELF from that glibc SDK archive. Its native host/runtime is official linux-musl-arm64 runtime3.1.32 with the already reviewed branch-native OpenSSL3 and original-manifest trace candidates. Only the imported private bootstrap disables ReadyToRun. Its original `NETCoreSdkRuntimeIdentifier=linux-arm64` metadata receives an exact hash-guarded private adaptation to musl; final source-generated metadata already produces musl directly. The original SDK/core-sdk `global.json` remains SDK3.1.425 plus Arcade1.0.0-beta.22558.6.

The probe records every MSBuild property. Package mode passes the native musl RID, `ToolsRID`, `ProductMonikerRid`, `CoreSetupRid`, ARM64 architecture and disables the portable-glibc fallback. Explicit source commit hashes and component suffix are recorded; `GitCommitCount=0` is synthetic archive-only diagnostic metadata, and must be replaced with real Git-derived release provenance in a complete producer. SourceLink/control-manager queries and shared compilation are disabled for these unpacked-source probes. Normal final SDK optimization and apphost remain required.

Original restored NuGet archives, byte lengths, SHA256 values and feed metadata are retained. The library dependency graph also restores foreign x64 OpenSSL runtime assets. They are inventoried; no restored native ELF lies under a `tools` path, and none is in the new component package. Restore inventory is not execution proof. Complete used-source/license export and full source-built compiler/toolset provenance remain unqualified.

For reproduction, mount the repository read-only at `/repo`, the original native investigation inputs at `/inputs`, and the new SDK425 input plus writable output directory at `/phase`. Use the exact worker and minimal-consumer image IDs in the JSON, derived from the previously committed container recipes. The worker modes share these arguments:

```sh
python3 /repo/scripts/core3-musl-source-probe.py \
  --mode source-package \
  --inputs-dir /inputs --bootstrap-inputs-dir /phase \
  --native-evidence /inputs/candidate-verified \
  --trace-evidence /inputs/trace-verified \
  --output-dir /phase/new-source-package
```

`source-components` compiles the two component DLLs; `negative` compiles and runs the shared certificate fixture. Use new empty output directories. Source restore uses the original official configured feeds without package-version changes. The runtime-only mode runs in the separate minimal-consumer image, with the previously audited SDK-free runtime at `/runtime`, the `negative` mode's application output at `/application`, and network disabled:

```sh
python3 /repo/scripts/core3-musl-source-probe.py \
  --mode negative-consumer --runtime-dir /runtime \
  --application-dir /application --output-dir /phase/new-certificate-consumer
```

The full CLI/toolset path is concrete remaining work. Original [CLI source](https://github.com/dotnet/cli/tree/cca488d5d530e6ec291134abe3462fed613a4429) defaults request an unavailable MSBuild preview package; the [authoritative source-build graph](https://github.com/dotnet/source-build/blob/ab8b115b5658237ee8916ae3586600b39fb2fd19/eng/Version.Details.xml) instead coherently builds MSBuild16.7.3 from [commit2f374e28](https://github.com/dotnet/msbuild/tree/2f374e28ea8abbeee841bf805955a72a39c88b81). Exact16.7.3 also is absent from the configured public feeds. Approximate matches were rejected, and were never represented as source-built outputs. An actual six-project `MSBuild.SourceBuild.sln` attempt then reached a missing exact Arcade1.0.0-beta.21065.4 SDK. Building its compatible pinned Arcade/source-build override is the next dependency step, followed by CLI, compiler/NuGet/other toolset components and local-source core-sdk `GenerateLayout` inputs. This is no proof of an architecture blocker.

Complete pristine CLI/toolset/MSBuild sources and actual Arcade SDK source archives/licenses were retained separately. The published glibc **source-only** release archive was also verified and inspected; it contains prior producer source adaptations, for example an MSBuild SDK422 bootstrap adaptation where pristine upstream requests420. No compiled glibc output, or prior adapted source as a compiled input, was reused here. Exploratory direct CLI/toolset/MSBuild attempts explicitly invoked private425 while retaining their original global pins; those overrides and the single retired-feed transport mapping are recorded, not hidden as pristine upstream behavior.

Core3.0 and x64 certificate tests, full native CLR/JIT/crossgen and ASP.NET source production, complete used-source/license audit, final native two-CPU producer/consumer checks and all distribution admission remain pending. No release workflow, canonical SDK10 dependency policy or published product was changed by this checkpoint.
