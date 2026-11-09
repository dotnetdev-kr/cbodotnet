# SDK5 collection corresponding-source supplement

`musl_legacy5_collection_sources.py` extends the original forty-primary-source
registry with four exact original Git parents: the independent publisher
source-build-externals recipe, Json.NET 9.0.1 and 11.0.1 source revisions, and
the SDK5 preferred framework assets. The external parent retains all six real
Gitlinks, including its CSS parser source. Each parent requires its original
remote, commit and tree; the Gitlink paths and commits are closed constants.

The additional source basis comes from the distinct committed SDK5 CSS,
Newtonsoft and framework validators. The original external recipe is used as
an independent publisher source basis. It is not represented as a Gitlink
declared by the SDK5 producer. No SDK6 policy is selected.

Only new corresponding-source clones may be materialized as canonical original
Git bytes. Existing sources, compiler checkout bytes and roles are preserved.
A small real Git fixture checks original checkout attributes: an existing
compiler's CRLF script remains unchanged while only the new preferred source
is materialized as its original Git blob. The read-only actual contract checks
the ten original roots without cloning or rewriting them.

The collection caller must explicitly invoke the primary registry and this
supplement before preparing the corresponding input data trees. This helper
alone is not wired into the closed SDK5 producer collection route, and it does
not prove shipping input consumption or whole producer admission. Later local
AppInsights output requires its own real compiler and final package-consumption
binding; registering the original Gitlink does not establish that result.
