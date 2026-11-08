# SDK6 attributed component sources

The [SDK6 policy](../scripts/musl-legacy6-attributed-components.json) covers ten
exact imported members in the genuine SDK6.0.136 tooling output. Seven exact
restored packages establish their byte origins. No assembly is loaded during
inspection, and no missing package repository field is fabricated.

| Component | Shipping members | Corresponding source |
| --- | ---: | --- |
| Unsafe 5.0.0 / 6.0.0 | 4 | Exact canonical package members and their original runtime commits `cf258a14` / `4822e3c3` |
| MSBuild Locator 1.4.1 | 2 | Exact canonical member, full publisher commit `47281c3d`, and matching original short assembly identity |
| Cecil / Cecil.Pdb | 3 | The actual SDK6 Linker package at `d0662ed8` and its original `external/cecil` Gitlink to `3bef7fc7` |
| CSS Parser | 1 | The original SDK6 Razor Tool package reference, exact `1.0.0-20200708.1` input, and publisher orchestration Gitlink `522d361e` → `d6d86bcd` |

Unsafe and Locator copies in the original Roslyn or dotnet-format packages
must also match their canonical package members exactly. Every allowed
package/member pair is listed explicitly. The public Cecil package is not
substituted for the Linker project's own component. SDK7's different Cecil
source and package identities are not inherited.

The [SDK6 validator](../scripts/musl_legacy6_attributed_components.py) requires
ten complete original Git baseline trees, 47 pinned dependency/source/license
files, the declared component Gitlinks, all seven original raw packages and a
separate comparison-data root. Imported source roots must be entirely
pristine. The SDK root is the actual patched build worktree: its complete
original baseline and unchanged dependency/license declarations are checked
here; the producer's independent used-source and compiler validation binds its
product patches separately.

This is source attribution for fixed imported bytes. Local or byte-identical
compilation of these imported members is not claimed. It does not establish
native SDK compatibility, a complete successful producer or public release
admission; those gates remain separate.

Independent real-input review passes the original source packer and verifier
with 16 roots and 153,651 indexed files, followed by this ten-member validator.
The source archive is 880,595,841 bytes, SHA-256
`484448035ce67bc28d7516cd363607a72d98fa20a8f266bb726406456d90b44b`.
Missing original runtime source, an SDK7 Cecil Gitlink, a changed Git baseline
and a one-bit raw package mutation are rejected. Seven focused unit tests also
pass. This source-leaf fixture keeps whole-producer and release admission
false.
