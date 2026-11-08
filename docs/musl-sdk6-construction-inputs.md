# SDK6 construction input boundaries

The SDK6 compiler and source registries are separate from SDK7 qualification.
They authenticate component inputs before the complete SDK6 producer may seal
a release. The outer SDK6 release route remains closed until all construction,
source and native consumer gates succeed.

## Actual compiler outputs

`scripts/musl_legacy6_component_evidence.py` requires original SDK6 source pins
and genuine package versions for SDK tooling, NuGet and VSTest. It reads
completed typed task records and matches each package member's exact bytes to
an actual successful, source-bearing compiler command. Both `/out` and
`/refout` are checked; a reference assembly needs the observed reference output,
not a fabricated MSBuild scalar. Skipped tasks and paths outside the source
mount cannot establish provenance.

The independently revalidated component checkpoint covers 190 SDK-tooling
members, all 72 NuGet members, and 304 VSTest members. The SDK and VSTest counts
include nine and three actual reference outputs respectively. Six unchanged
VSTest imports retain their exact independent origins. Installer ReadyToRun
uses its separately verified matching native Crossgen2 6.0.36 contract.

## Corresponding sources

The SDK6 registry pins 52 original GitHub source commits, including canonical
reference-pack, template and workload-metadata sources. Source acquisition
expands an acquired parent's exact Gitlinks before considering independent
child clones. It materializes original Git blobs only in fresh source-only
clones. Compiler worktrees keep their actual executed source changes.

The source-only imported MSBuild checkout and the patched
`msbuild-localization` compiler checkout remain separate even though their
original commit matches. A compiler checkout cannot replace the pristine
import source. Duplicate independent import roots with the same commit fail.

## Five original nonshipping PDB members

The original `Microsoft.NETCore.DotNetAppHost` 6.0.36 package contains five
Windows PDB names under `runtimes//native/`. Their exact raw package, original
names, metadata and licenses remain unchanged. A closed SDK6-only policy pins
the entire package and each PDB by size, SHA-256 and SHA-512 and confirms the
original Windows debug-symbol signature.

Only these five exact unused inputs are excluded from portable candidate
indexing. Their paths are not rewritten. Neither the raw package nor any of
the five PDB byte hashes may satisfy a final SDK or pre-ReadyToRun shipping
need. No executable or corresponding-source claim is made for these retained
debug inputs. Independent actual SDK and transformation-byte checks, plus six
shipping-origin rejection controls, verify that boundary.

The complete native SDK6 build, source/import closure, both CPU producers and
signed public consumer distributions remain separate requirements.
