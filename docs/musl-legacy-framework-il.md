# Historical framework implementation sources

SDK 7.0.120 preserves 114 cross-target library DLLs in
`Microsoft/Microsoft.NET.Build.Extensions`. Of these, 87 contain metadata-only
type forwarders; the other 27 contain real implementations. The latter are
covered by `musl-legacy-framework-il-policy.json` independently of the facade
policy. Their code is not waived as reference-only data.

The original SDK's `eng/Versions.props` selects
`NETStandard.Library.NETFramework` version `2.0.1-servicing-26011-01`.
`Microsoft.NET.Build.Extensions.Tasks.csproj` copies that dependency's `build`
files into the package without rewriting them. Every preserved DLL matches the
immutable original targeting package; the 27 implementation paths and original
package/member fingerprints form a closed set.

The targeting package identifies the historical corefx commit
`bd6a58d04fe8bd60452819571fd720513378ae0f`. Its original C# source has not been
recovered. The preferred source retained here is the complete upstream IL from
`dotnet/source-build-assets` commit
`eccb0828682858d8daa029ba29adce07fd70d9a7`, including its original build recipe,
notices and Git provenance. The complete package subtree is
`e149c55e5c641bbac5906cc12db0dbcfcbd778f9`. This is an explicit IL-source route;
that later source commit is not asserted to be an embedded original C# identity.

The source gate independently reads the original PEs without loading them and
matches all 5,289 method bodies (223,725 IL bytes), 55 body-free methods, method
headers and original MVIDs against the authoritative IL. The upstream IL omits
embedded resource declarations. A separate data root retains all 22 original
resource blobs, all 1,410 intrinsic resource strings and the original readable
XML directive resources. Raw inputs, decoded values, manifest names, flags and
reconstruction declarations are retained together. Custom serialized resource
objects and XML external entities are rejected.

Separate derived reconstruction IL preserves three further original metadata
details needed by modern ILAsm: the original Debuggable attribute commented out
upstream, the exact IEEE-754 bits of one private Double constant in each of two
Compression DLLs, and original permission-set blobs. The pristine upstream Git
files remain intact. Original MIT and third-party notices remain available.

An isolated native musl ILAsm diagnostic reassembled all 27 implementations.
The independent `musl-legacy-il-compare` reader then compared every declaration,
signature, custom attribute, constant, marshal/RVA datum, resource and normalized
method instruction, operand, local signature and exception region. All 27
comparisons passed. Normalization covers token/row ordering, short instruction
encodings and the InitLocals flag when no local variables exist. PE layout,
signatures, debug records and MVIDs are outside this semantic comparison.

These diagnostics do not replace the shipping DLLs and do not claim
byte-identical compilation. Final admission still requires the whole SDK's
producer, source archive and test evidence. The framework IL policy can authorize
only the 27 immutable original paths and their actual restored package/member
chain; it cannot cover arbitrary implementations or other package members.
