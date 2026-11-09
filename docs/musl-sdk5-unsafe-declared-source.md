# SDK5 Unsafe imported source contract

`musl_legacy5_unsafe_source_inputs.py` checks only the two fixed SDK5 layout
occurrences of System.Runtime.CompilerServices.Unsafe 5.0.0. It uses a distinct
closed SDK5 policy and executes no SDK6 or SDK7 component policy.

The complete original canonical NPK is retained with its original nuspec and
notices. Its publisher declares dotnet/runtime commit
`cf258a14b70ad9069470a108f13765e0e5988f51`. The validator requires that complete
pristine Git tree, reconstructs its Git tree identity from every baseline entry,
and verifies every archived file against its original Git blob and mode. Thirteen
selected original files bind the Unsafe IL implementation, project recipe,
references, tests, version inputs and source licenses.

The net472 SDK occurrence is byte-for-byte the canonical `lib/net45` DLL. The
Roslyn occurrence is an unchanged original ReadyToRun DLL. Its complete decoded
managed metadata and all 39 IL method bodies are compared to the canonical
`lib/netcoreapp2.0` DLL. The string heap contains the same values in a different
order, so all string columns are compared by their exact UTF-8 value. Every other
table field, metadata header, opaque GUID/blob/user-string heap, IL method
header, stack/local declaration and IL byte must match. Method RVAs resolve to
the original section-bounded method bodies. Only the exact original assembly
CustomAttribute row exchange 2↔13 is permitted, with both full tuples checked;
all other row order remains exact. Additional metadata tables or counts reject.

Both original DLLs retain their full size, SHA-256 and SHA-512 fingerprints. The
R2R native bytes are neither removed nor regenerated. Managed correspondence
does not prove derivation of the original native code, and the leaf never claims
publisher compiler observation, local rebuilding or native-code derivation.

The diagnostic derived Roslyn NPK SHA/member is retained as an observation,
separately from the canonical Unsafe source origin. Its Roslyn repository
metadata is not attributed to Unsafe. A normal producer must independently bind
its actual derived compiler container, its exact member and the final layout
bytes through the compiler/producer contract. The source result alone cannot
authorize an unknown container or qualify the SDK.

`prepare(package, original_r2r, runtime_source, destination)` creates a non-Git
data tree containing the exact original package, R2R input and comparison
records. `validate(release, manifest, package)` verifies the retained complete
source archive and returns the two full layout paths, exact DLL fingerprints,
canonical package/member, source root/commit and separate diagnostic container
observation. Qualification and source-admission flags remain false.

The actual retained packet contains 57,412 files and passed full source capture,
generic source verification and this leaf in 44.5 seconds. Eight focused tests
and eight actual input/source/IL forgery controls pass. The first control driver
selected the unrelated orchestration root for its exclusion mutation; that
driver and its stopped run are preserved. The corrected control selects the
exact runtime commit and rejects its excluded source. No full pack was repeated.
