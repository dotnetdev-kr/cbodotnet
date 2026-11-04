# Downstream release intake and promotion gates

[Issue #7](https://github.com/dotnetdev-kr/cbodotnet/issues/7) uses the
[shared command](../scripts/downstream-release.py),
[gate library](../scripts/downstream_release.py) and
[status/policy record](../releases/downstream-status.json) for source intake,
artifact recording, authenticated native evidence and complete-matrix staging.
The [publication backend](../scripts/downstream_publish.py) signs channel
manifests, promotes immutable GitHub Release assets and independently downloads
their public bytes. The [distribution workflow](../.github/workflows/distribution-release.yml)
also builds/tests Debian packages and consumer OCI images, signs APT metadata,
promotes the complete GHCR index and runs anonymous native digest-pull checks.

Implemented adapters do not establish availability by themselves. Treat a first
publication as pending until its public receipts and applicable native
post-publication tests pass. Only the checked-in status and its authenticated
receipts may enable website installation commands. RPM/AUR adapters remain
gated by their separate target qualification in issues #5/#6; this workflow
does not assert that those channels or the entire epic are complete.

## Receive a qualified release

Use a reviewed checkout containing the
[distribution contract](distribution-contract.md), exact manifest pin and
qualified producer catalog. Receive public GitHub Release assets, not expiring
Actions transport artifacts:

```bash
python3 scripts/downstream-release.py prepare \
  --tag sdk-10.0.403 --inputs "$PWD/.build/downstream-inputs" \
  --channel deb --variant debian-13 --arch x64 --revision 1 \
  > "$PWD/.build/downstream-plan.json"
```

Omit `--tag` to revalidate an existing input directory containing `release.json`
(the GitHub API release response), `release-manifest.json`, `SHA256SUMS` and the
canonical selected SDK archive. The command rejects draft/partial releases,
unadmitted versions, wrong architectures, changed bytes and catalog producer
substitutions. Downloaded SDKs are size- and digest-checked before becoming a
usable final file. Matching SDK/manifest/checksum retries are reused; a conflict
or partial download requires inspection rather than replacement. Local API
snapshots are consistency inputs, not a freshness guarantee. The source-release
receiver checks the public API/manifest before accepting remote inputs, and
staging revalidates the immutable manifest, SDK and qualified producer binding.

The manual [intake workflow](../.github/workflows/downstream-verify.yml) performs
this verification for x64 and AArch64 with read-only repository permissions. It
uploads preparation provenance, not a distributable package. It has no signing
key, registry permission or publishing credential. Existing native SDK tests
and launcher/coexistence checks remain necessary but cannot qualify a real
package installation or a consumer image.

## Record artifacts and generated commands

Run the [channel packager](../scripts/package-sdk.py) only on verified input bytes. Stage commands
using `distribution_commands.stage_commands`; keep the returned inventory of
absolute target paths, sizes, SHA-256s, modes and owning packages. SDK payload
files are unchanged. The common `cbodotnet` dispatcher belongs to the shared
`cbodotnet-host` package; OCI also provides `dotnet` through its private command
directory.

`package` accepts the same verified source arguments as `prepare`, plus
`--artifact`, `--orchestration`, `--commands-root` and `--commands-inventory`.
The orchestration JSON must contain repository, exact `.github/workflows/*.yml`
path, full commit SHA, run ID and attempt. This step hashes the real output
artifact and generated command files, checks their executable permissions and
ownership inventory, and records the contract's branding and command policy.
It does not build, sign or publish an artifact. A record without real generated
commands cannot pass the validation/staging gate.

## Authenticate real installation evidence

Each prepublication report must be produced after real channel installation
on its actual target. It contains schema version 1, `phase: prepublication`,
`scope: channel-installation`, `status: passed`, the current `contractVersion`,
and exact matching copies of
the packaged record's identity, artifact, source, producer, orchestration,
branding, commands and extra-file inventory. Its target records actual OS ID,
version, public architecture, native execution, and resolved versions of all
required native dependencies.

Every required check is an explicit `passed` result. This includes payload
integrity, host/runtime selection, offline build/run, HTTP/crypto/globalization,
non-root execution, official .NET coexistence, upgrade, removal, command aliases,
CLI branding and numeric version stdout compatibility. Channel policy adds
package-manager/repository or OCI base/config/platform checks. Post-publication
checks are deliberately not prerequisites for this earlier stage.

Private-prefix extraction/removal reports are foundation evidence, never
substitutes for actual package-manager/image installation. Wrong OS, emulation,
missing native libraries, an unrecorded command change or a partial advertised
matrix fails closed.

Sign the exact report bytes with a separately protected evidence signer. The
`validate` command requires `--package`, `--artifact`, `--report`, `--signature`,
`--keyring`, `--commands-root` and `--inputs`. It regenerates the entire canonical
plan from the original local API/manifest/checksum/SDK inputs, rehashes the SDK
and actual output/command bytes, and rejects any substituted source descriptors,
provenance, branding or command policy in editable package/report JSON. It
uses `gpgv` on private snapshots of the exact report/signature bytes to verify
the detached signature against an explicitly supplied
public keyring. The primary fingerprint must be active in reviewed
`evidenceSigners` policy, within its trust window, and authorized for that exact
report-producing workflow. A JSON `passed` field or a caller-provided checksum
is insufficient. The approved signer is configured in the status/policy record;
the [signing policy](distribution-signing.md) records its full fingerprint,
validity, protected environment and rotation/revocation procedure. The reviewed
[public key](../releases/downstream-signing-key.asc) is the trust input; a key
adjacent to an arbitrary downloaded artifact is not an independent trust root.

Each signer entry is keyed by its independently verified full primary
fingerprint and contains `state`, `notBefore`, `notAfter` (UTC timestamps) and
the exact authorized workflow path. Review the fingerprint and trust window
through the established project trust channel before importing its public key.
Keep signing private keys in protected jobs separate from untrusted packaging
and smoke-test execution. The signature binds the reported workflow identity;
the trusted signer is responsible for attesting that workflow's actual result.

`gpgv` treats its explicit keyring as trusted and does not independently enforce
key expiry or revocation. The gate additionally checks reviewed trust windows,
active/revoked policy and signature status. Remove compromised signers from the
active policy/keyring, stop staging, retain the affected digest list and publish
a reviewed revocation notice. Rotate through a documented overlap window, test
the successor identity and preserve old records. See the
[GnuPG verifier documentation](https://www.gnupg.org/documentation/manuals/gnupg/gpgv.html).

## Stage a complete matrix

`stage --items items.json --ledger /absolute/existing/ledger` accepts a JSON
array. Each item supplies `packagePath`, `artifactPath`, `reportPath`,
`signaturePath`, `keyringPath`, `commandsRoot` and `inputsDirectory`. Staging reauthenticates all
reports and output files, requires one source/channel/version/revision, and
matches the entire reviewed `candidateMatrix`. A Debian candidate currently
requires both architectures on Ubuntu 24.04 and Debian 13; OCI requires both on
Debian 13. RPM/AUR have no admitted matrices yet.

Only the complete transaction is exposed as a local immutable ledger record.
Matching retries reuse the record. A different artifact, report or signature
under an existing staged channel/version/revision is a hard conflict; inspect
and increment the packaging revision rather than replacing the record.

## Sign and publish one channel

The [publication command](../scripts/downstream-publish.py) accepts the same
matrix item format and independently repeats the stage checks before signing.
Its `bundle` operation requires a fresh output directory, the exact native
evidence commit, approved signing fingerprint and explicit binary public
keyring. `--extra-assets` can name the signed APT/RPM repository archives or OCI
index descriptor, all included in the signed asset inventory. For example:

```bash
python3 scripts/downstream-publish.py bundle \
  --items /absolute/items.json --output /absolute/bundle-deb \
  --target-commit "$NATIVE_COMMIT" --signing-key "$SIGNING_FINGERPRINT" \
  --keyring /absolute/trusted-public.gpg --extra-assets /absolute/repository-assets.json

python3 scripts/downstream-publish.py publish \
  --bundle /absolute/bundle-deb --target-commit "$NATIVE_COMMIT" \
  --keyring /absolute/trusted-public.gpg > /absolute/deb-publication.json
```

Repository asset entries have `path`, `kind` and `variants`, such as
`{"path":"/absolute/apt-debian-13.tar.gz","kind":"apt-repository","variants":["debian-13"]}`.
The repository helper produces flat `apt-<variant>.tar.gz` archives containing
`InRelease`, `Release.gpg`, package indexes and their referenced package pool.
RPM repositories require verified RPM payload signatures as well as signed
repository metadata; a signed index alone cannot replace package signatures.

One bundle contains one channel/version/revision. Its tag is
`distribution-<channel>-sdk-<version>-r<revision>`, for example
`distribution-deb-sdk-10.0.403-r1`. Channel outcomes remain independent. The
signed `distribution-manifest.json` binds the full target matrix, exact source
release/manifest, contract version, producer/workflow identities, generated
commands, output artifacts, native reports, signatures and repository archives.
The public signing key and detached manifest signature accompany it.

The publisher uses a fresh private snapshot of the verified bundle. It creates
or resumes a draft, accepts an existing object only when downloaded bytes agree,
and never uses an overwrite/clobber upload. Missing assets in a draft can be
received; an already-public partial release cannot be repaired in place.
Pending draft tags are resolved by database identity while REST caches settle.
Only after every draft asset is independently re-downloaded and verified does
the release become public. Every public asset is then downloaded anonymously
and checked again. A failure does not produce a `published-postverified` receipt.

The compatibility `downstream-release.py publish` command accepts `--staged`,
`--bundle`, `--keyring` and `--target-commit` and checks that the signed bundle
matches the staged identity before dispatching the same backend. An unknown,
disabled or incomplete publisher configuration fails explicitly.

## Run the native and protected publication workflow

Run the complete native matrix without signing or publishing first:

```bash
gh workflow run distribution-release.yml --repo dotnetdev-kr/cbodotnet --ref main \
  -f tag=sdk-10.0.403 -f revision=1 -f publish=false
```

The x64 and AArch64 jobs build packages from the qualified SDK bytes, install
them in the Ubuntu 24.04/Debian 13 user spaces, and test the real package
lifecycle. They also build a digest-pinned Debian 13 image and test all three
branded commands, non-root use, offline console/HTTP/crypto/globalization,
payload preservation and image lifecycle. Native artifacts retain the exact
reports, command inventories and inputs required for revalidation.

An authorized manual dispatch with `publish=true` uses the main-only
`downstream-release` environment. The signing job alone receives the approved
`DOWNSTREAM_SIGNING_KEY` environment secret and write-scoped release/registry
permissions. It revalidates native artifacts, builds signed APT repositories,
authenticates reports, stages full matrices and promotes GHCR and signed
per-channel release bundles. The imported private key is removed after the job.

To resume a failed promotion without rebuilding native images/packages, supply
`source_run_id` and `source_run_attempt` for the original successful native
matrix. The publisher checks the source repository, main branch, dispatch
workflow, exact native job outcomes and original commit/run/attempt identity.
The signed publication retains that native evidence commit; it does not claim
that an old artifact was built by the newer retry commit.

Before any GitHub Release assets are published, the workflow uploads the exact
signed channel bundles, OCI descriptor and promotion metadata as
`downstream-frozen-promotion-<run>-<attempt>` for 14 days. The upload contains
public artifacts/signatures and excludes private key directories. This frozen
artifact is the recovery boundary once signing has succeeded: re-signing later
would create different signature bytes under the same immutable release name.

For a failure after this upload, use `promotion_run_id` and
`promotion_run_attempt` instead of `source_run_id`. The recovery driver verifies
the trusted main workflow, the exact successful freeze-upload step and the
GitHub API artifact SHA-256 before safely extracting the original bytes. It
rechecks current contract/source admission and both signed bundles, then resumes
publication without importing a private key or generating new signatures.
Matching already-published bytes are reused. Native-source recovery and frozen
promotion recovery are mutually exclusive inputs.

Post-publication jobs pull the public OCI index by digest on both native
architectures with an empty Docker credential configuration, compare the image
config against the tested native image, and repeat non-root aliases and an
offline build/run. APT must also pass installation from its actual hosted
signed repository before its availability is advertised. Publication receipts
and these post-publication results are separate evidence; successful upload
alone is insufficient.

## Activate website availability and recover failures

After both native post-publication jobs succeed, the workflow's finalizer runs
[distribution-status.py](../scripts/distribution-status.py). It independently
authenticates the signed receipts, requires both exact OCI digest reports and
all APT archive/OS/architecture results, and retains the public test results
with each immutable receipt. It merges those receipts and their exact
`publications` into the current main-branch status using the observed file SHA
as a concurrent-update lease. A changed existing SDK/revision is rejected;
matching retries retain history. Other unfinished channels remain deferred or
unpublished. The finalizer then explicitly dispatches Pages, because a status
commit made with `GITHUB_TOKEN` does not trigger another workflow automatically.

For a controlled recovery, the same command accepts downloaded publication and
post-verification artifact directories and an exact successful run/attempt.
Without `--write` it prints the candidate status for review; `--write` requires
the trusted main publication workflow and successful publish/both-native job
outcomes before committing and refreshing Pages. `--channel deb` or
`--channel oci` can activate one independently verified channel.

The Pages builder independently checks the approved signing key,
manifest pin/signature, canonical URLs, complete matrix and publication rows
derived from the signed records. It downloads repository archives by their
signed SHA-256, extracts only safe ordinary members and verifies APT signatures
before serving them under `/packages/deb/<variant>/`. Proposed links, partial
matrices and unsigned receipt assertions cannot enable installation commands.

Keep unsuccessful channels `not-published` or `deferred`, with no public
installation claim. Before retrying, inspect the failed stage and retain the
original immutable bundle when possible. Reuse of matching bytes is idempotent;
a conflicting existing tag/package/revision requires investigation and a new
packaging revision. Do not delete or silently replace the original evidence to
make a retry appear successful.

Rollback selects a previously verified version/revision/digest, never rewrites
an immutable object. Test downgrade and interruption recovery per channel.
If only one channel publishes successfully, record that channel's outcome and
retain the others' failure state. This sequence does not complete the entire
epic until every required channel and its publication tests are implemented.
