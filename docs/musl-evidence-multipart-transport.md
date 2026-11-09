# Complete musl evidence multipart transport

The native producer evidence gzip contains the original imported-input records,
reports, source manifest and complete source index. SDK6 evidence can exceed the
2 GiB physical release-asset limit even after the SDK gzip and used-source gzip
have been excluded. No evidence members are omitted to meet that limit.

`musl_release.py stage-producer` first writes the complete existing evidence
envelope in an owned private temporary directory beside the public stage. The
basename, sorted member selection and gzip compression remain the same. A gzip
smaller than 2 GiB keeps its existing filename and three-field evidence identity.
Existing SDK10, SDK9, SDK8 and SDK7 manifests, checksum ordering and release bodies
without evidence multipart transport remain unchanged.

For an envelope at least 2 GiB and smaller than 8 GiB, `evidence` instead records
the logical complete gzip filename, byte length, SHA-256 and SHA-512. Its separate
`evidenceTransport` object has these exact fields:

| Field | Meaning |
| --- | --- |
| `schemaVersion` | Integer `1` |
| `kind` | `musl-producer-evidence-exact-byte-parts` |
| `archive` | Exact copy of the logical `evidence` identity |
| `partSizeBytes` | Integer `1073741824` (1 GiB) |
| `parts` | Ordered complete fingerprints of every physical byte part |
| `descriptor` | Complete fingerprint of the canonical transport JSON asset |

Each part is named `<evidence filename>.part-0001`, followed by `0002` and so on.
Every part except the last contains exactly 1 GiB. The last contains the exact
remaining bytes. Each part has its own byte length, SHA-256 and SHA-512. There are
two through eight parts. These are contiguous slices of the existing gzip,
without decompression, recompression, member selection or content conversion.

`<evidence filename>.transport.json` is the canonical UTF-8 JSON encoding of
`evidenceTransport` without its self-referential `descriptor` field. It is bounded
below 64 KiB and authenticates both the complete archive and every ordered part.
The release manifest binds the sidecar's size and both hashes. The source gzip's
`sourceTransport` retains its existing distinct kind and source-control bindings;
the two transport types cannot substitute for each other.

Only the evidence sidecar and its parts are physical evidence release assets.
`SHA256SUMS`, the closed stage inventory, immutable uploads and both private and
public postverification enumerate those physical assets. The unpublished whole
gzip is removed with its private temporary directory and never remains in the
public stage. `downstream_release.descriptor` still requires every physical asset
to be nonempty and smaller than 2 GiB.

To restore original used sources from a qualified producer release:

```sh
python3 scripts/musl_distribution.py receive-used-source \
  --sdk-version 6.0.136 --arch x64 --output /tmp/cbodotnet-used-source
```

The consumer first authenticates the qualified release manifest, exact closed
physical asset list and checksums. For multipart evidence it validates the exact
sidecar, then streams every declared part into a fresh private temporary gzip
outside its output directory. It verifies each part's length and both hashes and
the complete concatenation's length and both hashes before parsing any evidence
control. Missing, extra, reordered, aliased, truncated, enlarged or corrupted
parts fail. There is no fallback or reuse of a previous validation result after
any failure. Partial private whole files are removed on failure.

The existing `source_controls` reader sees the authenticated complete evidence
gzip. It retains its original path, duplicate, file-type, member-count, size,
manifest/report equality and source fingerprint checks. The existing complete
used-source verifier still runs after source restoration. Imported payloads are
retained in the evidence envelope; they are not extracted by this source-control
reader. The private evidence gzip is removed after use. New multipart receipts
also record `evidenceMultipart` and the complete `evidenceArchive` identity.

Signed consumer build plans retain both logical evidence and its transport. OCI
evidence URLs and installer catalog evidence links name the actual public
transport descriptor rather than an unpublished logical whole filename. OCI
labels additionally expose the transport kind and complete archive hashes.

Small-threshold tests in `tests/musl_evidence_transport_test.py` exercise genuine
whole-byte reassembly, both hashes at both levels, canonical sidecars, malformed
transport controls, redirected paths, changes during staging, cleanup, complete
two-CPU evidence membership, real source verification, immutable publication and
both download postverification phases. They do not require large artifacts or a
producer rerun.
