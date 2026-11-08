# SDK7 imported components without full embedded source commits

The closed policy in `scripts/musl-legacy-attributed-components.json` covers
eight exact layout members. The independent validator checks their unchanged
package members, complete original Git trees, source projects and licenses.
It cannot attribute another binary by its filename, version or a short hash.
The shipped members remain upstream imports; this is source correspondence,
not a claim that the SDK locally compiled these eight members.

| Members | Reviewed correspondence |
| --- | --- |
| ILLink net472 Unsafe | The member is byte-identical to the original Unsafe5.0.0 net45 member. That immutable package names full runtime commit `cf258a14b70ad9069470a108f13765e0e5988f51` and MIT. Its complete preferred IL source is retained. |
| Three ILLink Cecil members | Original Linker commit `19fa656d35252ccf926e6a6d783b16a2f094aaef` selects project references by default and declares Cecil Gitlink `1840b7410d37a613e684b6f9650e39e2d4950bbb`. Its source declares the actual0.11.4.0 assembly identity. The public Cecil0.11.4 package has different binaries and supplies no byte-origin claim. |
| Two MSBuild.Locator members | The exact original1.4.1 package identifies full source commit `47281c3de1c87a43ab946725d011b9dca4b6434a`; the actual embedded `1.4.1+g47281c3de1` agrees. Both layout members match that original package. |
| Two Elfie members | The original1.0.0 package has no repository field or embedded Git identity. Original publisher release source `00e6d739f5df03510ad2ef60b2afc1bfe50601b0` declares the actual1.0.0.16 file version. Independent recompilation and full code/metadata comparison establish this specific association. No commit is inserted into the original package or DLL. |

The canonical Unsafe comparison package is separately retained in a source
data tree. It is neither an observed restore input nor a layout origin and
is never executed. The source data tree has no invented Git commit. The
validator reconstructs each full Git tree, checks original Cecil Gitlink
connectivity, reopens pinned original packages and rejects changed source,
package, member or product identities.

The ILLink package has two explicitly pinned raw containers. Their24
non-signature members are byte-identical; each container's `.signature.p7s`
has its own exact fingerprint. The separate container policy records all25
member fingerprints and both whole-package identities. It changes no product,
source, Gitlink or license binding. Exactly one reviewed container must be
observed; mixed descriptors and an unlisted third container are rejected.
Actual restored bytes and signatures are retained without canonicalization.
This comparison does not claim cryptographic trust in a publisher signature.

## Elfie source review

The diagnostic compilation uses the unchanged original netstandard2.0
project and version source. `Elfie/BuildAndTestElfie.cmd` specifies the
`DELAY_SIGNED` constant, signing, delay signing and its published public key.
This original constant set omits TRACE. A Windows-style CRLF checkout is
necessary to reproduce verbatim multiline string values. The private modern
SDK's generated framework display name is explicitly empty, matching the
original TargetFrameworkAttribute; the framework itself stays netstandard2.0.

The data-only comparer in `scripts/musl-legacy-il-compare` reports zero
differences across2,779 facts,963 method bodies,20,474 instructions and the
embedded resource. It checks declarations, public/private signatures,
attributes, constants, marshal/RVA data, resolved token operands, locals and
exception regions. Target DLL code is never loaded or executed. Its scope
excludes PE layout, debug/signature bytes, MVID and metadata row ordering;
InitLocals has no effect when there are no locals. This establishes the
reviewed source association, not byte-identical compilation or a shipping
replacement. Initial unsigned/TRACE and LF-checkout mismatches are retained.

These source policies do not qualify a complete SDK, a CPU, or a release.
Actual construction, native two-CPU execution and signed consumer/public
verification remain independent gates.
