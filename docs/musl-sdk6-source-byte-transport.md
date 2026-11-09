# SDK6 source archive revalidation

SDK6.0.136 can use the existing private TAR byte transport after A6's complete
original `package-used-source.verify` succeeds. The publisher still performs
four complete A6 validations, one for each architecture during receive and
again during staging, plus the two separate full source checks during staging.
Every original validation call and its order remain unchanged.

Within one A6 invocation, the transport authenticates a private compressed copy
by its actual byte count, SHA256 and SHA512, expands it once, then retains only
an unlinked read-only descriptor. Each consumer opens fresh TAR headers and
member bytes with an independent cursor and recomputes its existing checks.
There is no cached verdict, source interpretation, Git tree or member map.
The original compressed bytes are authenticated again when the context exits.
The context is never shared across CPUs, processes or A6 invocations.

Twelve direct used-source reads in eleven active SDK6 modules use the common
opener. The compiler-input reader and canonical schema-prefix reader already
use it. The inactive old literal-input reader and separate official comparison
SDK archive reader retain their existing behavior. SDK7's validator integration
and all transport primitives are unchanged; exact session eligibility is now
SDK6.0.136 or SDK7.0.120.

Preparation requires the authenticated index-derived raw TAR bound, the exact
compressed size and a 1GiB disk reserve. The existing independent raw expansion
limit is 64GiB. No new parent, memory or disk limit is inferred. Unsupported
platforms or insufficient capacity detected before preparation retain exact
`r|gz` streaming readers and every original predicate. Authentication, copy,
I/O, gzip, expansion or consumer validation errors propagate without retrying
through another transport.

SDK6 fixtures rerun the existing SDK7 tiny archive controls and exercise actual
A6 index/member checks through both transports. They cover original headers,
modes, Unicode/PAX, symlinks, duplicate visibility, missing members, hashes,
independent positions, immutable descriptors, capacity fallback, corrupt gzip,
copy errors, original-byte mutation and cleanup. Dynamically loaded consumers
must share the canonical source-byte module.

The logical source validations remain 62 full traversals and four prefix
lookups across the protected stage. If all four sessions fit, the transport
accounting is ten full gzip decodes: six mandatory full verifiers plus four
private expansions. Fifty-six independent full raw TAR leaf scans and four
raw TAR prefix reads remain. These are counts from the call graph, not a
benchmark or a promise about elapsed time. No actual multi-gigabyte SDK6 source
input or complete original control was used to test this change. A fresh
publisher run and its release evidence require root review and authorization.
