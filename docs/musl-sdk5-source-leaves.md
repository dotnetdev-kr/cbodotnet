# SDK5 constructor and original source leaves

These independent SDK5 checks remain separate from normal producer admission.
They share archive, PE, Git-tree and task-event decoding primitives; they do
not select SDK6 or SDK7 product policies.

`musl_legacy5_construction_inputs.py` binds the construction proof to the exact
outer final SDK archive name, size, SHA256 and SHA512. Its closed artifact names
distinguish all six runtime construction products from the five shipping
runtime products, retain the separate crypto input, authenticate the original
runtime and ASP.NET archives for both native CPUs, and bind the toolset to the
SDK component compiler package. It rejects generated data impersonating a
managed PE, including files outside the SDK prefix. The current actual proof
in `.build/sdk5-construction-byte-bindings-v1/results.json` covers the final
inventory and fourteen fixed roles only; it does not close package sources or
the diagnostic layout's unresolved members.

`musl_legacy5_managed_inputs.py` captures source, resource, additional and
generated inputs separately for each original component and replay name.
Context numbers remain local to their original binary log. Four original
VSTest stages retain honestly empty Reader streams. Nonempty processes that
only perform Copy or other tasks retain their actual lack of compilation.
This records observed source bytes after the completed build and makes no
compile-time hashing claim. The actual full source roundtrip in
`.build/sdk5-managed-source-contract-v2/results.json` passed for fifteen
processes, 780 compiler tasks and 6,406 snapshot files. Six actual mutation
controls cover process omission, merging, mount and fingerprint relabelling,
synthetic empty-stage inputs and a rehashed C# source change.

`musl_legacy5_installer_inputs.py` checks all 440 original installer files,
without source exclusions or deletions. It reverses six exact pinned patches
over four original XML files; every recovered file must match its original
Git blob. Exact unique hunk context permits the offset used by the original
Git patch application. All other C# and target files remain pristine. The
actual source-only result is
`.build/sdk5-installer-source-contract-v1/results.json`; the normal installer
container and command envelope require a separate check.

The complete constructor, all imported source dispositions, Reader provenance,
consumer tests and both native CPU producers must pass independent admission
before SDK5 can be published. These leaves do not open the CLI route or grant
publication permission.
