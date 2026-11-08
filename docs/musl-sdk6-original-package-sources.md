# SDK 6 original package member sources

The SDK 6 musl layout includes 38 managed files from 15 original NuGet packages
whose nuspecs have no `repository` element. Each selected assembly does contain
an original full Git identity. `musl_legacy6_embedded_source_inputs.py` admits
only the exact reviewed packages, members and SDK paths; the JSON policy pins
their complete raw package and selected member size, SHA-256 and SHA-512.

Package provenance and member source identity remain separate. Original raw
packages, nuspecs, notices and license declarations are retained unchanged in
the `sdk6-embedded-origin-package-inputs` data tree. That tree has no Git commit.
Each shipping member separately requires its exact original complete Git tree
and licenses. The eight Git identities are checked against each actual PE's
embedded identity and against the archived original Git blobs. No missing
nuspec repository is synthesized, and no local compilation or byte identical
rebuild is claimed.

`System.Drawing.Common` 4.7.0 illustrates the distinction: its netstandard2.0
member names commit `02b11eeee1fbc5f3ef43a1452fe07efd25fa1715`, while its runtime
members name `0f7f38c4fd323b26da10cce95f857f77f0f09b48`. Assigning one Git commit
to that whole package would discard an actual source identity. The policy
retains both, with the literal package/member pairs for each selected SDK path.

`Microsoft.Extensions.CommandLineUtils` 1.0.1 retains its original .NET Library
EULA URL and license acceptance declaration. An unchanged upstream license
reference from the pinned VSTest `cc7fb0593127e24f55ce016fb3ac85b5b2857fec`
source is retained for that same original URL. It is explicitly a license
reference: this does not claim that VSTest restored CommandLineUtils, replace
the original binary license with a source license, or alter a publisher package.

The source contract checks the complete archived original trees, each original
source license, every retained original package and the separate license
reference. Missing roots, invented container Git identities, changed source
baselines, modified raw packages and a rehashed data license cannot pass. A
source leaf pass is separate from native SDK construction, functional testing,
the normal producer boundary and release admission.
