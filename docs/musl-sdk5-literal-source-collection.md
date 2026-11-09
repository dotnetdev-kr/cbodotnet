# SDK5 literal-source collection

`scripts/musl_legacy5_literal_collection.py` registers the seventeen exact Git
identities already required by the literal/template/reference/Arcade policy.
It supplements the original forty-root registry and the separate extra-source
registry. It does not activate SDK5 production or source admission.

The caller supplies its actual fresh-workspace clone and Gitlink expansion
functions. An existing commit is reused only after its repository, commit and
tree are authenticated. Its physical path, source record and role remain
unchanged. Multiple physical matches fail. Newly cloned corresponding-source
roots and their real Gitlink children receive the existing imported-source
role and exact Git-byte materialization. Existing compiler worktrees are never
materialized by this helper. The report must be fresh and outside Git trees.
Report and source-root paths reject parent traversal before conversion to
absolute paths; report destinations also retain the ordinary-path and symlink
checks before cloning or writing.

Each `selectedSources` row retains its original `literalRole`, exact identity
and actual path. The normal producer can pass that role-to-path mapping and
the nine actual original packages to the existing literal `prepare` function,
then register its returned data root. The complete packet must still pass
the generic source verifier and the unchanged literal validator, plus every
other construction/source gate. Registering a path is not compiler-use proof.

Focused tests exercise existing compiler-byte/role preservation, new Gitlink
materialization, ambiguous and redirected inputs, report boundaries and the
SDK5-only route. These are collection tests; a fresh normal producer's complete
source packet and actual product consumption remain separate requirements.
