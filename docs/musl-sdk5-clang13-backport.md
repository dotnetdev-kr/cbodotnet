# SDK5 CoreCLR alignment backport on stock Alpine

SDK5's original runtime source can finish a Release build with Clang20 while
losing exception-handling clauses at run time. Methods whose IL ends on an
unaligned address skip `finally`; contended locks then retain ownership after
their owner exits. The observed SDK/MSBuild stalls came from this defect.

The correction is the original runtime commit
[`f86caa54678535ead8e1977da37025a96e2afe8a`](https://github.com/dotnet/runtime/commit/f86caa54678535ead8e1977da37025a96e2afe8a),
the release/6.0 backport of “Fix build with Clang13” (#62170/#63314).
Its three `corhlpr.h` hunks align the untyped address before casting it to the
aligned section type. Its two `bitsetasshortlong.h` hunks replace strict-aliasing
violations with typed assignments. Only the source-directory prefix changes
for runtime5's `src/coreclr/src` layout.

[`0006-backport-upstream-clang13-alignment-and-aliasing.patch`](../patches/net5-musl/0006-backport-upstream-clang13-alignment-and-aliasing.patch)
contains those exact two files and five upstream hunks. Its SHA256 is
`db205750ee5ad54be0c7e2154b339fd82df9d05edd9719bf147623348a107149`.
Both SDK5 musl CPU profiles require this correction in the native-runtime plan.
Only native ARM64 has executed the experiments below.

## Actual evidence

The runtime source is `6a984143635bde23e728abaaccbde52f5ea8fa3e`
(5.0.17). A standalone probe compiled the actual original decoder header with
its recorded Clang20/O3 command. `alignof(COR_ILMETHOD_SECT)` is 4. Before the
backport, both alignment and `GetSect` fail for offsets 1, 2 and 3; afterward
all eight observations pass. Structure size and alignment remain unchanged.

All six original native targets rebuilt successfully: CoreCLR, JIT, DAC, DBI,
LTTng provider and Crossgen. Release/O3, PGO, tracing and normal ReadyToRun stay
enabled. All six ELF files, matching debug sidecars, generated source,
configuration, commands and binary-log evidence remain retained on D. Earlier
DAC/metadata/Clang compatibility source changes are recorded separately in
that experiment; the upstream patch does not conceal them.

The original installer graph then rebuilt a fresh SDK5 archive from the
retained genuine source-built managed toolset and explicitly imported matching
publisher frameworks. Its 2,416-file inventory is unchanged: only the four
new native CLR/JIT/debugger products and the matching LTTng provider differ.
The existing source-built OpenSSL3 crypto file is unchanged.

Archive SHA256:
`0259d03e96809f8e99aa5ad053e925ee2b024f18f81f11564e7892c4ae2e13be`
(130,231,821 bytes).

This exact archive passed:

- All 68 original NET5 shell smoke cases from source-build `d414ecb`, including
  local and online restore, both HTTPS setups and XML-document checks.
- Offline C# compilation, ICU, crypto, ASP.NET HTTP and apphost execution;
  system-trust TLS and every default-SslStream negative certificate assertion.
- The complete native ELF audit in the SDK-free stock Alpine runtime image.
- Archive-only LTTng after removing the SDK/packs: 80 GC starts, 80 GC ends,
  9,098 .NET events and one independent native control event.
- The SDK5-specific semantic worker's 14 commands, using actual CLR5.0.17:
  six reflected EH clauses cover IL-end residues 0/1/2/3; normal, return,
  throw, catch and loop cleanup execute; two threads complete 20,000 Monitor
  and SpinLock increments, plus same-key and distinct-key dictionary checks.

The final installer binary log replay completed with no unfinished tasks:
111 Crossgen tasks and one Csc task. Actual compiler source/generated inputs
are retained. Crossgen remains the original matching publisher package tool;
its R2R products are not described as byte-identical local compiler outputs.

The original source tree's `global.json` is unchanged. A separate pristine
source probe also verified `GenerateRuntimeVersionFile` with its exact
SDK5.0.401 bootstrap. That private compiler bootstrap explicitly combines the
original SDK files with the matching5.0.17 framework and source-built native
stock-Alpine support; it is not an unmodified publisher distribution.

## Reusable regression worker and scope

[`musl-legacy-runtime-semantics5.py`](../scripts/musl-legacy-runtime-semantics5.py)
accepts only a completed SDK archive and compiles its own
[`fixture`](../scripts/musl-runtime-semantics5.cs) offline through that SDK.
It accepts the exact SDK5.0.214/runtime5.0.17 layout, verifies actual runtime
identity, uses normal ReadyToRun and rejects runtime execution overrides.
Each command has a bounded timeout and retained output fingerprints. It
accepts no runtime overlays, host SDK or precompiled fixture input.

Run it in the native, nonroot SDK-free Alpine3.24.4 runtime test container,
with networking disabled and the normal dropped-capability policy:

```sh
python3 /project/scripts/musl-legacy-runtime-semantics5.py \
  --archive /candidate.tar.gz --arch aarch64 \
  --output /delivery/reports/test/runtime-semantics
```

The private archive reused a retained genuine managed toolset; it does not
establish a fresh complete managed/source/license closure. The publisher
framework archives keep their original attribution even where the installer
requires `-internal-` logical filenames. Existing archives and failed attempts
remain immutable. No x64 execution, protected normal-producer success, source
admission or release availability is claimed. Both profiles keep those gates
closed. Workflow files and the reviewed SDK7 route are unchanged.

Retained local evidence:

- `.build/sdk5-clang-alignment-upstream-review/upstream-f86caa5.json`
- `.build/sdk5-clang-backport-root-review-v1.json` (independent root review)
- `.build/musl-legacy-assessment-20261108/native-clr5-clang13-backport-v22/`
- `.build/musl-legacy-assessment-20261108/native-clr5-fixed-core-consumer-v23/`
- `.build/musl-legacy-assessment-20261108/native-clr5-fixed-cold-v24/`
- `.build/musl-legacy-assessment-20261108/native-clr5-fixed-synchronization-v24/`
- `.build/musl-legacy-assessment-20261108/native-clr5-fixed-lttng-v24/`
- `.build/musl-legacy-assessment-20261108/genuine-sdk5-fixed-native-v2/`
- `.build/musl-legacy-assessment-20261108/native-clr5-normal-version-probe-v1/`

These are local proof receipts, not published release artifacts. Profile
descriptors bind the exact checked receipt bytes and keep the distinction
between functional evidence and normal source admission explicit.
