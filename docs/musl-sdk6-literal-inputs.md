# SDK6 original literal inputs

The SDK `6.0.136` construction contract separately authenticates four unchanged
publisher packages. Its closed policy binds their complete size, SHA-256 and
SHA-512, original nuspec and license metadata, and exactly 128 layout files.
No package identity or publisher metadata is rewritten.

- `NETStandard.Library.Ref` 2.1.0 supplies 124 reference-pack files. Its original
  core-setup packaging commit `7d57652f33493fa022125b7f63aad0d70c52d810`
  declares standard commit `a5b5f2e1e369972c8ff1e2183979fab6099f52ef`.
  The complete source trees, all 83 explicit C# API inputs, original packaging
  declarations, licenses and notices remain required.
- The Emscripten 6.0.36 manifest supplies two literal files. Original source
  `d440134ad1037c7a3c91c78fff964078f240e08c` renders its declared 6.0.36 and
  Emscripten 2.0.23 values; the actual package bytes must match that rendering.
- The SPA and test template packages remain whole original NPKs. All 385
  template content files bind their original source bytes, exact LF-to-CRLF
  conversion where observed, and the two declared SPA project renderings.
  Their original Git sources and packaging declarations remain required.

The SPA nuspec records an aspnetcore URL with commit
`800de95e1e05a831cb64f7dba88624bac42c7ede`. That commit belongs to the separately
retained spa-templates Git tree. The contract preserves this metadata and
requires the original `64ea4108e7dcf1ca575f8dd2028363b0b1ef6ebc` ASP.NET Core
parent's `src/submodules/spa-templates` Gitlink to identify the correct source.

The independent source contract requires all six complete pristine Git trees
and 500 original file anchors. Package envelopes, icons, signatures and raw
metadata remain covered by the exact whole-package fingerprints. This is
corresponding-source and literal-byte evidence; it does not claim a reference
assembly rebuild, qualify template execution, or enable Emscripten workloads.
Actual final SDK consumption, the remaining source/import closure and both
native CPU release pipelines have separate gates.

A focused actual source archive round trip verified 26,570 files, all 128
layout mappings, all 387 literal payloads and all 83 C# API source declarations.
Five actual controls rejected changed same-version package metadata, a wrong
SPA Gitlink, a wrong API commit, another SDK version, and changed original
template source even after its source index hashes were updated to match.
