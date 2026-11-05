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
runtime, initial SDK admission, OS/CPU matrix and signing workflow. Native x64
and AArch64 builds use the already authenticated branded SDK10.0.403 archive in
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

Catalog schema1 contains a monotonic sequence, UTC issue/expiry times (maximum
31 days), signer, revocations, admitted SDKs, native tools and tracked Community
channels. Each SDK binds its exact version/revision, RID, archive root,
HTTPS URL/size/SHA256, canonical source manifest, producer, evidence, notices,
native dependencies, EOL/support boundary and individually admitted OS versions.
Tool releases bind binary and native-runtime notice assets under immutable tags.

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
publication requires all eight actual native targets. Activation requires a
second eight-target pass using anonymous public binary/archive downloads, and
independently authenticates actual report artifact ZIP size/digest and job IDs.
The site verifies catalog and bootstrap signatures/inventories before serving
the feed. Expired feed content is removed from newly generated pages.

## Ownership and transactions

The data root is `$XDG_DATA_HOME/cbodotnetup` (default
`$HOME/.local/share/cbodotnetup`). `CBODOTNETUP_HOME` can name another dedicated,
ordinary, user-owned root. System paths, official `.dotnet`/`dotnetup` state,
symlinked ancestors, unrelated non-empty roots and writable-by-other-user owned
directories are rejected. Root execution is refused.

`toolchains/<sdk>-r<revision>/<rid>/content/<archive-root>/` retains the original
branded archive tree. Receipt, signed admission and installed file inventory
are separate. Process locks serialize mutation and managed execution. Downloads
have size/time limits and HTTPS origin/redirect restrictions. Extraction
rejects traversal, links escaping the root, duplicate paths, special devices,
privileged modes, excessive counts/expansion and truncation; links are created
after regular files. Staging and activation share a filesystem. Active roots
are exposed only by an atomic directory rename; conflicting identities fail.

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
An interrupted tool replacement can be repaired by rerunning the pinned
bootstrap with a fresh signed catalog. The user data/SDK roots are independent
of this repair. There is no unsigned override or automatic native dependency
download. Additional SDK versions require a new per-target installer admission.
