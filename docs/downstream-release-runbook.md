# Downstream release intake and promotion gates

[Issue #7](https://github.com/dotnetdev-kr/cbodotnet/issues/7) is implemented in
stages. The [shared command](../scripts/downstream-release.py),
[gate library](../scripts/downstream_release.py) and
[status/policy record](../releases/downstream-status.json) currently provide
source intake, artifact recording, authenticated evidence validation and local
matrix staging. Remote packagers, package/repository signatures, publishers and
post-publication verification remain channel integration work under issues
#3, #4, #5 and #6. No channel is advertised as published. A local `staged`
record is not a public release or compatibility claim.

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
snapshots are consistency inputs, not a freshness guarantee; the future remote
publisher must recheck the current public release state before promotion.

The manual [intake workflow](../.github/workflows/downstream-verify.yml) performs
this verification for x64 and AArch64 with read-only repository permissions. It
uploads preparation provenance, not a distributable package. It has no signing
key, registry permission or publishing credential. Existing native SDK tests
and launcher/coexistence checks remain necessary but cannot qualify a real
package installation or a consumer image.

## Record artifacts and generated commands

Run the future channel packager only on verified input bytes. Stage commands
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
is insufficient. The repository currently configures **no trusted signers**.

Each future signer entry is keyed by its independently verified full primary
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

## Stage a complete matrix; integrate publishers separately

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

`publish --staged ...` fails explicitly because no publisher adapter is
configured. Before enabling an adapter, implement package/metadata signing,
atomic repository or OCI-index promotion, conflicting remote-digest rejection,
and independently observable post-publication download/pull verification. Bind
post-install results and immutable public digests into the publication record.
Update channel status and website commands only after those gates succeed.
The checked-in status stays `not-published` meanwhile; it contains no invented
repository URLs, keys or container tags.

Rollback selects a previously verified version/revision/digest, never rewrites
an immutable object. Test downgrade and interruption recovery per channel.
If only one channel publishes successfully, record that channel's outcome and
retain the others' failure state. This sequence does not complete the entire
epic until every required channel and its publication tests are implemented.
