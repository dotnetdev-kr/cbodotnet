# SDK6 canonical framework source inputs

SDK6.0.136 uses its own source-copy recipe for the historical
`Microsoft.NET.Build.Extensions` target libraries. This is separate from the
SDK7 publisher-package route.

The original SDK commit `1d205826ddc14c8f868eb6373e7a6bafcb9fe5be`
declares `NETStandard.Library.NETFramework` version
`2.0.1-servicing-26011-01`. Its original
`Microsoft.NET.Build.Extensions.Tasks.csproj` copies the package's `build`
directory while excluding `.props` and `.targets`. The canonical package is
1,844,646 bytes, SHA-256
`218dd4c63d3f800de697bca41178827a52df0a9ec7a9b47520327d91ebc7051c`.

Independent inspection of the actual new SDK6 toolset finds exactly 114
target-library DLLs, each byte-identical to that package member:

- 87 contain literal type-forwarding metadata and no executable method bodies.
  Complete raw metadata, readable declarations and original bytes are retained.
- 27 contain real implementations. Their exact original preferred IL comes
  from source-build-assets commit
  `eccb0828682858d8daa029ba29adce07fd70d9a7`. All 5,289 method bodies match,
  together with original MVIDs, method headers and 22 embedded resources.
  Resources retain their raw bytes and complete readable values, including
  1,410 strings. Reconstruction inputs preserve metadata which a basic IL
  reassembler would otherwise lose.

The [version-specific policy](../scripts/musl-legacy6-framework-policy.json)
pins 137 original preferred-source and build files and three original SDK
recipe/version/license files, including their Git blobs. The complete
source-build-assets tree and the complete used SDK source remain separate
mandatory roots in the full source producer. Original C# recovery, local
compilation of these imported libraries and byte-identical recompilation are
not claimed.

[The SDK6 helper](../scripts/musl_legacy6_framework_inputs.py) recomputes every
derived input from the canonical package and exact original sources, then
checks the archived data, index and original Git blobs independently. It uses
the shared binary/IL decoders without calling either SDK7 package policy.
The SDK6 construction gate must also bind these exact bytes to its actual
restore, copy tasks and final SDK layout.

The real-input source-leaf roundtrip passes for 633 source/data members and
rejects missing resources, changed preferred IL with recalculated index
hashes, an SDK7 recipe root, additional derived data and missing archive
members. This partial fixture does not establish a complete Git tree or
qualify a full SDK. Full source admission, both native CPUs, original runtime
tests and signed public distribution remain required.
