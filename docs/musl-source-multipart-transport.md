# Musl used-source multipart transport

GitHub requires each release asset to be smaller than 2 GiB. A used-source gzip
that reaches that limit is transported as ordered byte parts. Its gzip bytes,
uncompressed TAR, source manifest, source index, Git baselines and file modes
remain unchanged. This transport does not change source admission or qualify a
failed producer.

Archives smaller than 2 GiB retain the existing version 1 manifest, source
descriptor, filenames, checksums and eight-asset release inventory. Binary
consumers continue to retrieve the independently qualified SDK archive.

An oversized source entry keeps its logical `source` name, size and SHA-256,
adds SHA-512, and has an explicit `sourceTransport` object. Its schema version is
1 and its kind is `musl-used-source-exact-byte-parts`. The closed object binds:

- `archive`: the unchanged whole gzip name, size, SHA-256 and SHA-512.
- `sourceManifest` and `sourceIndex`: the original filenames and complete size,
  SHA-256 and SHA-512 fingerprints retained in the evidence archive.
- `partSizeBytes`: exactly 1 GiB.
- `parts`: ordered complete fingerprints named `<archive>.part-0001`,
  `<archive>.part-0002`, and so on. Every part except the last is exactly 1 GiB;
  the last contains the remaining bytes.
- `descriptor`: the complete fingerprint of `<archive>.transport.json`.

The sidecar contains the same canonical, sorted JSON document without the
`descriptor` field. The release carries that sidecar and the parts in place of
the oversized gzip. `SHA256SUMS` inventories these actual assets. The whole
gzip's fingerprints remain bound by both the sidecar and release manifest.
The existing qualification catalog pins the exact release-manifest bytes;
consumer signatures retain that source-manifest binding.

The reviewed transport accepts whole gzip files from 2 GiB to less than 8 GiB
and at most eight parts. Unexpected fields, unsafe names, missing or reordered
parts, changed boundaries and oversized members reject. Readers authenticate
each part with both hashes, then authenticate their complete concatenation
with both hashes. A partial or corrupt reconstruction never reaches the source
validator. This does not replace the complete original source checks.

To retrieve and verify an independently qualified release:

```sh
python3 scripts/musl_distribution.py receive-used-source \
  --sdk-version 6.0.136 --arch x64 --output /path/to/fresh-directory
```

The command supports both the existing single gzip and explicit multipart
releases. It retrieves the original manifest, index and report control from
authenticated evidence, reconstructs the gzip under the original manifest's
filename, and invokes the unchanged complete `package-used-source.py` verifier.
It streams the source TAR for verification and does not unpack its source tree.
Multipart downloads stream directly into one fresh reconstruction; the command
does not retain separate part copies.

For multipart releases, OCI source URLs point to the actual transport sidecar.
The source URL's SHA-256 identifies that sidecar; separate archive SHA-256 and
SHA-512 labels identify the unchanged whole gzip. No absent logical gzip URL is
advertised.

The existing release workflow stages and uploads a closed inventory through
the scripts. Its wildcard artifact boundary already carries sidecars and byte
parts, so this adapter requires no workflow changes. Existing public releases
remain immutable.

The asset limit is documented in [GitHub's release storage limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#storage-and-bandwidth-quotas).
