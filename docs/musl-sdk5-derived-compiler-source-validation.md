# SDK5 derived compiler input validation

`musl_legacy5_compiler_source_inputs.py` independently validates the three
local compiler input packages used by SDK5. It uses the fixed SDK5 constructor
recipe and the exact authenticated original SDK 5.0.214 comparison archive.
It requires complete pristine original FSharp, Roslyn, Roslyn CodeStyle and
compiler-framework source trees. Commit objects authenticate the requested
commits and trees; every source member must retain its original Git blob and
Git mode. The actual index mode must equal that authenticated baseline, and
the archived permission bits must equal the index mode. This also closes the
reviewed self-consistent executable-bit mutation of the original License.txt.
Definitions, project recipes, licenses and notices are read from that archive.

The validator derives the complete FSharp owned-asset and culture selection,
CoreCLR Roslyn compiler subtree and VB CodeStyle analyzer selection. Managed
metadata, original embedded source identities and unchanged ReadyToRun inputs
are checked. Roslyn's three framework dependencies must include their exact
separately pinned original 5.0.0 packages and corresponding runtime source.

Using those original inputs, it reconstructs deterministic package bytes and
all origin receipts in a temporary directory. The actual complete package
tree must match in length, SHA-256 and SHA-512. All actual data also needs exact
source-index and source-archive coverage. The enclosing source contract must
run `package-used-source.py` verification before this source leaf.

This establishes the source and original-byte basis for imported compiler
inputs. It does not claim that the compilers or native ReadyToRun bodies were
locally built, or that these local containers are original publisher NUPKGs.
Normal production may create a different container fingerprint only through
the same checked constructor inputs and recipe; a diagnostic container hash
is not the canonical source identity of an embedded component. This leaf does
not grant qualification or normal SDK5 admission.
