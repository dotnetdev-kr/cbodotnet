# cbodotnetup design and upstream decision

The implementation is original cbodotnet code under the repository MIT license.
It is informed by [dotnet/sdk at a24d0c644c5ff9f5e1df9b661f1fe8cdf35f253c](https://github.com/dotnet/sdk/tree/a24d0c644c5ff9f5e1df9b661f1fe8cdf35f253c/src/Installer/dotnetup),
the exact reference recorded in issue11. No upstream source files or patches are
copied into this implementation. There is no dependency on its internal,
non-packable installation project or .NET12 alpha/Arcade bootstrap. A maintained
fork would inherit those moving build/trust dependencies. This small independent
adapter targets .NET10 and keeps the existing Community Build trust boundary.

Upstream separates its NativeAOT entry point and management library. Its
[signature policy](https://github.com/dotnet/sdk/blob/a24d0c644c5ff9f5e1df9b661f1fe8cdf35f253c/documentation/general/dotnetup/signature-verification.md)
authenticates Microsoft CMS manifests and SHA512 artifacts. Those identities,
feeds, update state, locks and telemetry are not reused. The installer has no
telemetry. All network requests carry only a product User-Agent, without GitHub
credentials. Project OpenPGP signatures authenticate SHA256-bounded Community
SDK archives, native tool binaries, runtime notices and their source links.

## Build and maintenance inputs

[The policy](../releases/cbodotnetup-policy.json) pins the reference, build SDK,
runtime, exact SDK archive revisions, OS/CPU admission matrix and signing
workflow. Native x64
and AArch64 builds use the already authenticated SDK10.0.403 revision3 archive in
the existing digest-pinned Rocky Linux9.8 images. NativeAOT runtime10.0.14 is
explicit, including the [Brotli security fix](https://github.com/advisories/GHSA-p3jp-9v83-76w9).
NuGet auditing and compiler warnings remain errors. Invariant globalization
removes the installer's ICU requirement; installed SDKs still need their OS
dependencies. This is a glibc build, qualified on each advertised OS, with no
musl/Windows/macOS admission.

Each native build retains source input hashes, exact source/run/attempt, SDK
archive descriptor, image digest, resolved NuGet SHA512 input records and lock
file, binary/notice hashes and original package licenses/notices. The release
includes both native build records and the exact source archive. The adjacent
signed `.LICENSE.txt` is installed with the tool. Review a newly pinned upstream
snapshot for layout, extraction, interruption and trust-policy changes; port
applicable behavior independently and rerun the security/native matrix. Do not
replace the reference silently or claim upstream code was imported.

## Catalog and trust

Both catalog generations contain a monotonic sequence, UTC issue/expiry times (maximum
31 days), signer, revocations, admitted SDKs, native tools and tracked Community
channels. Each SDK binds its exact version/revision, RID, archive root,
HTTPS URL/size/SHA256, canonical source manifest, producer, evidence, notices,
native dependencies, EOL/support boundary and individually admitted OS versions.
Tool releases bind binary and native-runtime notice assets under immutable tags.

The 0.2 migration uses a versioned schema2 endpoint,
`/cbodotnet/cbodotnetup/v2/catalog.json`, for neutral SDK archive filenames.
The original `/cbodotnet/cbodotnetup/catalog.json` stays schema1 and retains
SDK10.0.403 revision2 with its original filename, plus compatible authenticated
tool update records. Schema2 initially admits the separately qualified neutral
SDK10 revision3. SDK9/8/7/6 expansion uses the same strict schema and independently
qualified neutral revision2 archives; every advertised SDK/OS/CPU cell requires
its own installer evidence. The full five-SDK matrix has 40 cells, including the
eight existing SDK10 regression cells. Archive/package qualification establishes
inputs without replacing native installer admission.
Canonical naming is versioned and bound to exact SDK/source/revision identity.
Historical unbranded trial archives remain inadmissible.

The current and legacy SDK admission policies are independent. Extending the
schema2 SDK list must leave schema1's SDK10 revision2 records unchanged in shape
and scope. The immutable 0.2.0 NativeAOT executables and their notices can be
reused when only catalog admission changes; any binary/source/runtime change
still requires a new immutable tool version. Admission binds the exact SDK
revision, source hash, OS version and native CPU. Unsupported or revoked cells
remain outside activation, with no implicit selection of another SDK or root.

The catalog's security-support declaration describes the Community maintenance
boundary. Upstream series lifecycle and current-patch requirements are recorded
separately in the [user guide](cbodotnetup.md#sdk-admission-and-lifecycle). A
successful native test on Fedora45, Rocky9.8 or an upstream EOL SDK does not
establish a vendor support commitment.

Old 0.1.0 clients validate every catalog entry strictly, including SDK URL
spelling. Adding new fields, neutral URLs or musl entries to their shared feed
could prevent self-update itself. New metadata therefore belongs to the new
endpoint. The new client can verify retained schema1 admissions without
weakening schema2's canonical-name checks. Receipt/SDK JSON remains compatible
with the old owned-state model; signed catalog schema distinguishes admission.

Versioned cache/high-water paths isolate the two sequence/hash histories:
`cache/` for schema1 and `cache/v2/` for schema2. They are not interchangeable,
even if the two publication sequences happen to have equal numeric values.
Refreshing one feed must not replace the other's cache or watermark. The
shared operation lock still serializes all mutations across client generations.

The existing project public key is embedded independently in the bootstrap and
NativeAOT binary. GnuPG runs with an isolated keyring, explicit pinned identity,
no automatic key retrieval and no user gpg configuration. Invalid, revoked or
expired keys/signatures fail. Duplicate JSON fields, excessive metadata,
expired/future catalogs, older sequences and conflicting same-sequence bytes
fail. New installation/update requires a fresh signed catalog. Local execution
uses the last authenticated cached catalog without contacting the network;
expiry does not disable already installed SDK execution. Offline use cannot
discover new revocations; the last accepted revocation list remains enforced.

The private key stays only in the existing protected `downstream-release`
environment and approved `distribution-release.yml` workflow. Candidate signing
precedes native qualification but does not enable availability. Immutable
publication requires actual native evidence for every advertised SDK/OS/CPU
cell. Activation requires a second pass over the same cells using anonymous
public binary/archive downloads, and
independently authenticates actual report artifact ZIP size/digest and job IDs.
The site verifies catalog and bootstrap signatures/inventories before serving
the feed. Expired feed content is removed from newly generated pages.

The weekly catalog-renewal workflow requests this same protected signing and
qualification path. It reuses exact previously published native tool/build
inputs, independently verifies their signed frozen inventory and rechecks
current official NuGet vulnerability data. Expired Actions artifacts are not
the only recovery source. Previous signed tool entries and revocations are
retained; a conflicting existing tool identity fails. A new runtime/CVE or
binary source change requires new build qualification and an immutable tool
version rather than a waiver. Renewal repeats native/public installation
qualification before activating a new sequence; source PRs also run the core
tests on both native architectures.

Renewal signs and verifies both feeds, preserving the schema1 upgrade route and
prior tool/revocation identities while refreshing bounded validity. The normal
lifetime is 30 days. There is no automatic legacy-feed retirement: an explicit
announced owner decision must define the support/upgrade window and a trusted
bootstrap recovery route. Failed maintenance does not extend signatures or
silently disable freshness checks.

## Ownership and transactions

The data root is `$XDG_DATA_HOME/cbodotnetup` (default
`$HOME/.local/share/cbodotnetup`). `CBODOTNETUP_HOME` can name another dedicated,
ordinary, user-owned root. System paths, official `.dotnet`/`dotnetup` state,
symlinked ancestors, unrelated non-empty roots and writable-by-other-user owned
directories are rejected. Root execution is refused.

`toolchains/<sdk>-r<revision>/<rid>/content/<archive-root>/` retains historical
schema1 SDK installations. Neutral SDKs use the separate `toolchains-v2/`
namespace with the same layout. The new client verifies both; 0.1.0 enumerates
only its original namespace, preserving usable tool rollback without attempting
to parse a schema2 retained admission. No SDK root is moved or rewritten during
a tool upgrade. A shared default selection that names a revision invisible to
the old client falls back to a compatible retained installation. Without a
retained schema1 SDK, the old client reports no installed matching SDK rather
than executing a neutral or official SDK implicitly.

Receipt, signed admission and installed file inventory
are separate. Process locks serialize mutation and managed execution. Downloads
have size/time limits and HTTPS origin/redirect restrictions. Extraction
rejects traversal, links escaping the root, duplicate paths, special devices,
privileged modes, excessive counts/expansion and truncation; links are created
after regular files. Staging and activation share a filesystem. Active roots
are exposed only by an atomic directory rename; conflicting identities fail.
Native qualification kills a real user install during download, verifies that
no partial SDK was activated and the package baseline remains intact, retries
successfully, then collects that actual owned abandoned stage offline.

Retry verifies the existing inventory and signed admission. Removal first
authenticates ownership/inventory, moves the owned root out of the active
namespace and deletes without following links. Revoked roots can be removed,
while installation/execution remains blocked. Garbage collection only removes
marked UUID staging roots. SDK revisions remain until explicitly removed, and
rollback selects a retained verified revision. Default aliases still choose
the highest installed SDK series. Shell integration is explicit and never
edits shell startup files or replaces unrelated commands.

Authenticated self-update replaces an owned bootstrap executable only after
verifying both binary and notices, retaining the prior executable/notices.
Self-rollback requires the retained version to remain admitted and unrevoked.
Both current and legacy catalogs retain the tool identities needed to verify
the 0.1.0 to 0.2 upgrade, rollback and re-upgrade route. Public qualification
must exercise the actual released old binary, its schema1 SDK installation,
the authenticated new executable and neutral SDK, and return to the old tool
without modifying either SDK namespace. An old binary cannot validate a new
catalog merely because the same project key signed it.
An interrupted tool replacement can be repaired by rerunning the pinned
bootstrap with a fresh signed catalog. The user data/SDK roots are independent
of this repair. There is no unsigned override or automatic native dependency
download. Additional SDK versions require a new per-target installer admission.

The [modern SDK qualification evidence](cbodotnetup-modern-sdk-validation.json)
records 40 candidate and 40 public SDK/OS/CPU cells using the unchanged 0.2.0
executable. Additional SDKs use independent test roots and run alongside SDK10
one at a time. The harness disconnects the disposable container's network for
functional and removal checks and reaps the actual worker process during
interruption injection. This keeps the process holding the operation lock in
the killed session instead of leaving a runuser/PAM child alive.

A candidate that fails public qualification remains immutable and unactivated,
with a release notice directing users to the active feed. Corrected validation
publishes a fresh signed catalog sequence; it does not replace the earlier
catalog or its native-qualification asset. Feed activation still requires all
advertised cells to pass the anonymous public phase.
