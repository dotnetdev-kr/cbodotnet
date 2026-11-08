# Fresh SDK5 tooling and source-built ReadyToRun tools

The fresh native ARM64 experiment uses SDK source
`3fdf76c35026e311b7edc245d4b3d9e812fe532e`, its original SDK5.0.401 compiler
bootstrap, and runtime source `6a984143635bde23e728abaaccbde52f5ea8fa3e`.
The separate [alignment-backport report](musl-sdk5-clang13-backport.md) preserves
the earlier experiment and its archive identities.

The recorded normal-style native worker builds all six original Release
targets, retains their debug sidecars and 507 generated source files, and
generates the real native file version `5.0.1726.55802`. Release optimization,
PGO, tracing and normal ReadyToRun remain enabled. The worker's cold,
synchronization, source-Crossgen and LTTng controls passed. Its independent
review is `.build/sdk5-normal-worker-root-review-v1.json`.

## Fresh SDK and installer graph

This SDK revision has no checked-in `source-build.slnf`. The experiment derives
an explicitly downstream solution filter from the pristine original `sdk.sln`,
preserving its project order. It includes all 25 product C# projects and
excludes only the 31 original projects whose paths contain the case-sensitive
substrings `\Tests\` or `.UnitTests\`. The original solution, all 56 project
records, original Git blob identities and actual checkout bytes are retained.
This does not claim execution of the complete upstream source-build root graph.
It does not exclude any of the original 68 SDK smoke cases.

The original `build.sh` Release/Rebuild/Pack graph succeeded with no warnings or
errors. Binary-log replay records 214 actual Csc tasks, 682 selected tasks and
no unfinished tasks. All observed compiler source, generated source, resource
and additional-file inputs are retained separately.

The original installer graph rebuilt this fresh managed toolset with the fresh
native products. Its optional
[`0008` source-tool selector](../patches/net5-musl/0008-select-source-built-crossgen-and-jit.patch)
passes the actual source-built Crossgen and matching JIT pair at the original
task-selection boundary. It rejects absent files and non-musl use. The original
task filters and ReadyToRun settings remain unchanged. Independent replay
checked all 111 actual Crossgen commands against `/imports/crossgen` and
`/imports/native-runtime/libclrjit.so`; all record `ReadyToRun=true`.

The final 2,416-file archive is 130,237,336 bytes, SHA256
`2c2fd723fce7e8d2fe9ab802f92a6fa17c46e34ea106f3391d238584d9c5fe5c`.
It passed all 68 original NET5 smoke cases, both HTTPS setups and the complete
local/online/XML checks. The offline C#/ICU/crypto/ASP.NET/apphost checks,
system-trust TLS and negative-certificate cases, native ELF audit, 14-command
EH/Monitor/SpinLock regression and SDK-free archive-only LTTng also passed.
Tracing decoded 9,098 .NET events, 80 GC starts, 80 GC ends and one independent
native control event. Existing archives and unsuccessful attempts remain
retained; the superseded v5 attempt used publisher Crossgen and is not evidence
of source-built Crossgen consumption.

## Genuine original NuGet matrix

The SDK5-only NuGet worker builds exact original NuGet.Client source
`d525b0e670f3b6cbd5c73a35f04730a9f658c852` and its three pinned Git submodules.
Every tracked raw Git blob, commit and executable mode is checked before
compilation. Attribute-directed checkout line endings are materialized to the
original blob bytes before any compiler runs; a changed child source cannot
be accepted merely by ignoring a dirty-submodule status.

The original NuGet product glob evaluates Visual Studio-only projects before
its XPLAT filter. A retained downstream driver imports the original
`build/build.proj` and replaces only `GetXPLATProjects` with its exact original
19-project selection. It enumerates every original product declaration and
candidate, retains their original sources, and rejects conditional, inherited,
overridden or dynamic XPLAT declarations. The original `RestoreXPLAT`,
`BuildXPLAT` and `PackXPLAT` bodies and full library framework defaults remain
unchanged; execution of the entire upstream root graph is not claimed.

[`0009`](../patches/net5-musl/0009-preserve-original-nuget-unmerged-pack-matrix.patch)
extends the original unmerged source-build Pack input selection to that full
library matrix. Its three XML conditions preserve the ordinary non-source
ILMerge path. No product C# source or target framework is retargeted.

The genuine source-default version is `5.9.1-rc.8`. The worker produces exactly
19 packages and 76 managed members across net40, net45, net472, net5.0,
netcoreapp2.1 and netstandard2.0. The original project spelling `netcoreapp5.0`
is unchanged; NuGet normalizes its package framework folder to `net5.0`.
Independent replay observes 54 Csc tasks and binds all 76 package members
byte-for-byte to their actual successful compiler outputs. Compiler input
capture retains every observed source/resource/additional-file input.

## Evidence and remaining admission work

Actual local receipts are retained below
`.build/musl-legacy-assessment-20261108/`:

- `sdk5-normal-tooling-v1/restore-v3/derived-product-solution/`
- `sdk5-normal-tooling-v1/build-v1/`
- `native-clr5-normal-worker-v2/reports/build/native-runtime/`
- `genuine-sdk5-normal-native-v6/`
- `sdk5-own-components-v1/nuget-build-v8/build/`

These are native ARM64 functional and compiler-correspondence receipts.
Publisher framework inputs and existing source-built crypto keep their actual
origins. New VSTest products, complete imported managed/source/license closure,
the protected producer and independent x64 execution remain separate work.
Both CPU profiles retain false qualification, source-admission and release
availability gates. The reviewed SDK7 route and workflow files are unchanged.
