# SDK5 construction byte evidence

`scripts/musl_legacy5_evidence.py` exposes `emit(context)` for SDK5.0.214.
It retains observed inputs and describes their byte correspondence with the
actual final SDK. It imports no SDK6 source policy and grants no release or
source admission.

The context supplies exact Git source roots, the final SDK archive, toolset
ZIP, original runtime/ASP.NET imports, six native worker products and their
records, translation data, raw restored package observations, original
installer layout, and separate SDK/NuGet/VSTest/installer replay descriptions.
Every replay keeps its original process name and `sourceMountRoot`; physical
host input relocation does not change the recorded guest paths or task IDs.
There must be exactly one installer replay named `installer`.

Component evidence is emitted and revalidated through the independent SDK5
component contract. This reparses retained task events and completed status
records, and binds each raw binary log's SHA256 to its status. It does not run
the binary-log Reader again. Normal producer admission must separately bind
the actual Reader sources, bootstrap, invocation and copied event/status
outputs. Native file fingerprints are checked against the actual six-file
worker result; separate native source and ELF validation remains necessary.

The emitter records original Crossgen compilation and symbol commands,
framework paths, explicit source Crossgen/JIT paths, and actual transformed
ReadyToRun bytes. It does not disable ReadyToRun or symbol generation.
Generated data is attributed only through the original task's explicit output
parameter and equal final bytes. A generic data label cannot establish an
origin for an otherwise unmatched file.

Raw NPK observations preserve original repository and cache metadata.
Actual NPK fingerprints are checked independently. A package's single bounded
root nuspec defines its identity; retained nested nuspecs, including FSharp's
original-definition provenance, remain payload. Ambiguous root definitions,
DTDs and XML entities reject. Missing repository metadata remains absent.
Package membership alone is not a source-build claim.

Construction snapshots contain only declared ordinary files with a closed
member schema. Retrying retention verifies the exact member set, fixed
metadata, signature, byte count, SHA256 and SHA512. Changed inputs, changed
membership, truncated gzip streams and linked members reject without
overwriting the previous archive. All other retained records and inputs also
reject different existing bytes.

The output `reports/legacy-construction.json` keeps unmatched layout members,
unmapped package sources and unproven managed source origins in `unknowns`.
The emitted `qualificationAllowed`, `sourceAdmissionAllowed` and
`normalProducerInputConsumptionClaimed` fields are always false. A diagnostic
context records `constructionInputScope=diagnostic-byte-correspondence-only`;
it cannot establish whole physical toolset consumption. A normal admission
contract must require complete attribution and its own source, native,
producer-boundary and consumer evidence before accepting a release.

## Actual diagnostic checkpoint

The private v10 final archive and public v5 tooling evidence were compared
without changing either. After preserving two DrvFS read failures, a single
fresh D-drive ext4 context received 931 exact Windows input files
(817,337,697 bytes) through a bounded stream. Windows and Linux independently
checked every file's byte count, SHA256 and SHA512. Original serialized inputs,
source trees, guest paths and replay names were unchanged.

The emitter completed in 53.46 seconds. A separate retained-byte review
rechecked all 2,686 final members, 111 artifact inventories, all 548 raw package
observations, the three component proofs and all 155 Crossgen commands. There
are 2,678 mapped layout members and 1,222 managed shipping attributions:
186 SDK, 59 NuGet, 301 VSTest, 286 official translation data and 390 imported
package occurrences. NuGet's complete component proof separately contains
76 compiled package members; only 59 occur in the final SDK layout.

The checkpoint retains eight unmapped layout members, 24 unmapped package
sources and 207 unproven managed source occurrences. Four layout gaps are the
expected development configs whose public/private probing paths differ.
The remaining four are the runtime identifier graph, identifier chain and
the user-secrets/dev-certs runtime configs. No source-origin exception or
archive rewrite was applied. Framework, localization and other imported
source policies require separate SDK5 evidence. This diagnostic checkpoint
does not qualify or admit the archive.

Private receipts are under
`/var/tmp/cbodotnet-sdk5-evidence-nativefs-v4-20261109/` in the existing
`cbodotnet-net7-arm64` WSL registration: `transport-results.json`,
`emitter-result.json`, `roundtrip-results.json` and the retained `release/`.
The local checkpoint index is
`.build/sdk5-construction-evidence-checkpoint-frozen-v1.json`.
