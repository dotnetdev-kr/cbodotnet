# SDK7 source archive revalidation

The protected source publisher authenticates and validates both native SDK7
artifacts when receiving them, then independently validates them again when
staging the source release. Each validation retains its complete source, Git,
compiler, constructor, test and binary checks. The separate source verifier in
the staging phase also remains unchanged.

After the original complete source verifier succeeds, SDK7 may use a private
seekable TAR byte view during that one validator invocation. It copies the
compressed source archive into a fresh owner-only workspace while checking its
actual byte count, SHA-256 and SHA-512. It decompresses that authenticated
snapshot into a bounded private file, closes writable access, and retains only
an unlinked read-only file descriptor. Independent readers use separate
positions over those same original bytes. No source files are extracted.

Every source contract still reads the original headers and member bytes and
recomputes its existing checks. The view stores no validation result, Git tree
decision, interpreted index, source disposition or admission receipt. The
original compressed archive is fingerprinted again when the context exits.

Capacity planning authenticates the index and allows for aligned file bodies,
headers and PAX metadata. Preparation requires that upper bound plus the exact
compressed snapshot size and a 1 GiB free-space reserve; an independent 64 GiB
limit also bounds raw expansion. On unsupported platforms or insufficient
preflight capacity, the original streaming gzip readers perform all existing
checks. Authentication, decompression, I/O, expansion-overrun and cleanup
failures reject validation. They do not switch to a successful receipt.

The context applies only to SDK7. It ends before another architecture or
validator invocation starts. Shared source helpers retain their original gzip
reader when no context is active, including their use from other SDK families.
Neither the source packer nor the workflows are modified.

JSON observations on stderr report fallback reasons, compressed/raw byte counts,
preparation and context durations, temporary free/required space and Linux peak
RSS in bytes. They include no paths. Unsupported native measurements are null,
and diagnostic output failures do not change validation. A context returning or
raising is an observation, not an admission decision or release evidence.

Focused tests compare ordinary, executable, symlink, Unicode/PAX and duplicate
headers, original bytes and independent reader positions. They cover all three
compressed fingerprints, timestamp-preserving replacement, unsafe paths,
capacity fallback, corrupt gzip trailers, expansion failure, original archive
mutation, private descriptor permissions and cleanup. A small fixture confirms
that twelve independent source reads require one context decompression.

Actual normal two-CPU SDK7 artifact comparison and runtime measurement remain
required before relying on a performance improvement for publication. Small
fixture results do not establish completion within the existing job timeout.
