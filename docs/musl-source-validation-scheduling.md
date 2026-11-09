# Full SDK6 source validation scheduling

SDK6 protected publication keeps four complete independent validator calls:
both native deliveries at receipt, then both again at source staging. Each full
validator retains its original complete used-source verification and every
construction, compiler, scan, smoke, TLS, tracing, ELF and default-security
check. Source staging retains two additional complete used-source verifications.

Only SDK6 can schedule the two independent CPU validators concurrently. Native
artifact transport authentication and extraction precede receipt validation;
source/evidence packing remains serial and begins only after both stage
validators succeed. Original SDK10/9/8/7 scheduling stays serial. Completion
order does not change CPU ordering, manifest schemas, checksums or artifact bytes.

Parallel scheduling requires a main-thread Linux caller, the existing seekable
source capability, at least four measured available CPUs and eight GiB of
available RAM after visible unified-cgroup ancestor limits. Missing host data,
unaccounted hierarchies or insufficient capacity select the same full validators
in sequence. The inherited temporary filesystem must fit both source caches at
once: each conservative raw TAR bound, compressed bytes and existing source
reserve, plus one GiB of parent reserve. No parent packing competes with them.

Capacity planning uses ordinary stable bounded metadata reads and bounded
streaming index reads. Its finite parallel envelope is one MiB per source
manifest, one GiB per index,64KiB per index line and two million indexed files.
Larger envelopes select serial full validation. Malformed or changed data that
the planner reads is terminal. Index fingerprints and counts are checked for
capacity; this does not qualify source. Both child validators independently
repeat their complete original checks. No cached verdict or parsed header map
is reused, and source/evidence/SDK bytes are never reduced or repacked by the
scheduler. Child-local capacity checks also remain active.

Both children run the original command, inherited environment and working
directory in separate Python processes. Ordinary nonzero returns wait for both
already-launched processes, then fail the whole pair. Launch errors and
interruptions terminate only owned process groups, wait a finite grace period,
then kill and reap survivors. Signal handlers are restored afterward. No
received pair, source manifest or packing success follows a partial failure;
there is no retry after an attempted parallel pair.

The preceding protected attempt demonstrated working seekable caches and three
completed full validations before its120-minute limit interrupted the fourth.
Concurrency is a scheduling repair; its runtime and full publication success
must still be established by a fresh protected run using the exact native
producer artifacts. Ordinary tests use tiny real transport/index bytes and
fake child processes. They establish capacity, ordering and failure handling,
and cannot substitute for real producer/source/public qualification.

The root of the visible cgroup hierarchy is recognized conservatively from its
mount root, readable CPU/memory controller availability and the absence of both
non-root type/event interfaces. Only FileNotFoundError establishes absence;
permissions or I/O errors leave capacity unknown. Documented non-root quota and
memory-limit files are not required at that real root. Every visible non-root
ancestor must expose its readable limits; hidden namespace roots and ambiguous
views stay serial. This structural inference follows the
[Linux cgroup v2 interfaces](https://cdn.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html).
The Linux ordinary CI observation records the witness, quotas, memory, temporary
filesystem and scheduling reason using tiny fixtures before a real publication.

Both sealed SDK6/CPU/run identities are checked before either parallel or serial
child dispatch, and original post-validation identity checks remain. A first
cancel signal during reaping remains recorded and terminal; nonraising handlers
stay active until cleanup finishes. Detectable index growth is rejected before
any larger-line scheduling fallback.
