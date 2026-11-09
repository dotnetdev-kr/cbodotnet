# Genuine local SDK5 AppInsights PCL derivation

This isolated component builds original source for a new explicit local
`Microsoft.ApplicationInsights/2.0.0-cbodotnet.1` package. It does not attribute
the original publisher DLL to a Git commit, replace SDK dependencies, change a
normal admission route, or claim a Microsoft signing operation.

The closed SDK5 policy binds the complete 437-file original Git source at
`9b5b49f2a7697a2bf38f09ca2f2c97326c49d93b`, including its original MIT license
and public-only 160-byte signing key. All 112 original PCL/shared C# inputs are
retained unchanged. The adjunct project keeps .NETPortable v4.5/Profile7,
CORE_PCL/TRACE/CODE_ANALYSIS and the original assembly identity 2.0.0.0. The
analysis condition comes from original Release RunCodeAnalysis=True and the
original reference attribute's Conditional(CODE_ANALYSIS), preserving both
original SuppressMessage annotations. Explicit deterministic
PreReleaseVersion=30671 produces file version 2.0.0.30671. Original
Signing.targets uses PublicRelease=True and DelaySign; no private key, public
signing or external signing service is used.

The original public PortableReferenceAssemblies ZIP is fingerprinted in full.
Its exact Profile7 member set has 70 files, including all 65 original DLLs and
the 65-entry FrameworkList. Every member and every assembly identity is checked.
The reference ZIP contains no embedded license; that absence remains explicit.
It is distinct from the MIT source license and the separate original Mono
target-source LICENSE. The four original published Portable target files are
checked against exact Git blobs at Mono commit
`0f53e9e151d92944cacab3e24ac359410c606df6`. The complete reference profile is
used; no netstandard or host-framework substitution is allowed.

`prepare()` makes a fresh 522-file, closed input tree and retains the unchanged
original publisher NPK. Inputs and both pre-existing bootstrap SDKs are mounted
read-only. The private worker is non-root, offline, has no capabilities or new
privileges, and uses one MSBuild worker with compiler sharing/node reuse disabled.
Only its private output and HOME are writable. Exact controlled PATH,
DOTNET_ROOT and DOTNET_HOST_PATH resolve an ordinary role-specific bootstrap
host whose full fingerprint is recorded before/after compilation. A bare logged
dotnet command is accepted only with this exact binding, not by basename. A separate compiler-window
record is required. There is no automatic retry and no change to another
producer workspace.

The App compiler uses SDK5.0.401. The inspection role uses SDK6.0.135 only to
build and run the exact frozen two-file Reader; it does not compile AppInsights.
Raw binlogs, actual process commands/exit codes, complete task events and Reader
status are retained. Each actual Reader execution fingerprints its executable
and original binlog before/after. The Reader's own Csc source/output provenance
is also checked. Re-reading serialized task JSON alone is insufficient.

The compiler guard requires the actual command and task parameters to agree:
112 original C# inputs, exactly two controlled generated metadata inputs, all
and only 65 Profile7 references, original public-key DelaySign and deterministic
language/version options. Actual Csc output must equal the retained final DLL.
Original compiler contexts and raw binlog hashes remain separate.

`musl_legacy5_appinsights_api.py` reads bounded ECMA metadata without loading an
assembly. It compares public/protected types, methods, fields, properties and
events; signatures, constraints, parameter names/defaults/constants; layout,
custom attributes, assembly identity and every contract reference. Unsupported
marshal/security/PInvoke metadata rejects. API differences prevent packaging;
they are not covered by a retargeting or source waiver. Matching API does not
claim byte-identical implementation or prove the original DLL's Git source.

Only after actual compiler/Reader evidence and API comparison pass can
`package_local()` emit a new deterministic local NPK with its own genuine PCL
DLL/PDB/XML, the original PCL dependency declarations and original MIT source
license. It does not copy the old package's other framework binaries. The
original publisher package/provenance remain separate. A later SDK5 producer
must independently prove actual local package/member consumption and all
remaining native, source, compiler and Reader guards.

The first private v2 process stopped in project evaluation at an incorrect
Microsoft.Common.props import, before any App Csc task. Its complete failed
binlog/process logs and successful frozen Reader build are preserved. The
corrected adjunct uses the existing SDK5 `Current/Microsoft.Common.props`.
Qualification and source-admission flags remain false. The v3 process also stopped before Csc: MSBuild separately
resolves the base v4.5 framework before applying the Portable profile override.
The closed input now also retains that original ZIP's exact
`v4.5/RedistList/FrameworkList.xml`; it adds no DLL or compiler reference. Both
earlier failure snapshots remain unchanged. The v4 genuine compiler succeeded,
but strict API comparison rejected the two missing analysis annotations; no NPK
was emitted. Its original compile and API delta remain preserved. Root approved
one further compiler call restoring the original analysis condition without
source edits, retargeting or an API waiver.

The final v5 original worker passed in 6.84 seconds: one App Csc and one frozen
Reader Csc, followed by two actual binary-log Reader executions. The strict
comparison passes 46 public types, 362 public/protected methods, 14 fields,
154 properties, all attributes and 21 exact contract references. API hash is
`790b628e3d2e037f95e0bc98c5e321808ef299925d0c2ac80532bd71371c7027`.
The new local NPK is 102,910 bytes, SHA-256
`2dc9113825c520275240606cb29540276e4934bf04d5572f05d3f18aa14b8cb6`.
There were two genuine App Csc calls in total, v4 and v5; v2/v3 never reached Csc.

Eleven focused tests, ten actual input/API forgeries and twelve actual
execution/host/Reader forgeries pass, plus an explicitly bound equivalent bare
host positive and its unbound negative. The first execution-control driver
removed only the legacy observation while retaining the same structured source
item; its stopped run is preserved. The corrected control removes both actual
observations and rejects. No compiler was rerun for these controls.

An independent retained execution/API/NPK roundtrip and a 1,963-file full source
packet passed in 3.24 seconds, including all 437 pristine original source files
and 522 pinned input files. The roundtrip reparses retained records; the actual
binary Reader executions are the original worker's separately recorded calls.
Existing v4 bootstrap tool fingerprints/modes are unchanged, v8 is untouched,
and no SDK-wide package version or consumer has been replaced. Root must review
and integrate the new component before a real SDK consumer run can be claimed.
