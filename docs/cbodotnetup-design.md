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

All three catalog generations contain a monotonic sequence, UTC issue/expiry times (maximum
31 days), signer, revocations, admitted SDKs, native tools and tracked Community
channels. Each SDK binds its exact version/revision, RID, archive root,
HTTPS URL/size/SHA256, canonical source manifest, producer, evidence, notices,
native dependencies, EOL/support boundary and individually admitted OS versions.
Tool releases bind binary and native-runtime notice assets under immutable tags.

The original `/cbodotnet/cbodotnetup/catalog.json` stays schema1 and retains
SDK10.0.403 revision2 with its original filename and compatible tool updates.
The 0.2/0.3 schema2 endpoint, `/cbodotnet/cbodotnetup/v2/catalog.json`, remains
modern-only: neutral SDK10 revision3 and independently qualified SDK9/8/7/6
revision2 archives. The 0.4 schema3 endpoint,
`/cbodotnet/cbodotnetup/v3/catalog.json`, adds exact private provider and legacy
SDK bindings. Its eight-SDK contract contains 64 cells: the existing 40 modern
regressions plus 24 SDK5/Core3 additions. Every advertised cell needs its own
installer evidence; archive/package qualification alone establishes inputs.
Canonical naming is versioned and bound to exact SDK/source/revision identity.
Historical unbranded trial archives remain inadmissible.

The three SDK admission policies are independent. Extending schema3 must leave
the older feeds' SDK records unchanged in shape and scope. Schema3 hash-binds
a separately signed `catalog-v2.json` projection containing its exact modern
SDK and tool records. Modern installations retain that compatible admission,
so their receipt shape and verification remain usable by 0.2/0.3. Immutable
native executables can be reused only when catalog admission changes without
a binary/source/runtime change; provider support requires the new 0.4 tool.
Admission binds the exact SDK
revision, source hash, OS version and native CPU. Unsupported or revoked cells
remain outside activation, with no implicit selection of another SDK or root.

The catalog's security-support declaration describes the Community maintenance
boundary. Upstream series lifecycle and current-patch requirements are recorded
separately in the [user guide](cbodotnetup.md#sdk-admission-and-lifecycle). A
successful native test on Fedora45, Rocky9.8 or an upstream EOL SDK does not
establish a vendor support commitment.

Old 0.1.0 clients validate every catalog entry strictly, including SDK URL
spelling; 0.2/0.3 also reject unknown provider fields. Unsupported records in
their active feeds could prevent self-update itself. Provider metadata belongs
only to schema3. The new client can verify retained schema1/2 admissions without
weakening canonical-name checks. Modern SDK/receipt JSON remains unchanged;
legacy provider references occupy a separate namespace rather than extending
files that an older client enumerates.

Versioned cache/high-water paths isolate three sequence/hash histories:
`cache/` for schema1, `cache/v2/` for schema2 and `cache/v3/` for schema3.
They are not interchangeable even when publication sequences have equal values.
Refreshing one feed must not replace the other's cache or watermark. The
shared operation lock still serializes all mutations across client generations.

A tool updated by 0.3 initially has only authenticated schema2 state. Until its
first explicit schema3 refresh, 0.4 can use that modern-only cache offline.
An existing corrupt/conflicting schema3 cache does not fall back silently.
An explicit modern install from schema3 authenticates its bound schema2
projection before activation. A local signed catalog bundle can provide the
adjacent projection and signature; otherwise that install downloads the
canonical bound asset. Read-only execution never acquires it implicitly.

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

Renewal signs and verifies all three feeds, preserving older upgrade routes and
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
schema1 SDK installations. Modern neutral SDKs use `toolchains-v2/` with the
same layout and compatible schema2 receipts. Legacy SDKs use `toolchains-v3/`,
retaining their signed schema3 admission and a separate exact provider-reference
file. Shared immutable companions occupy `providers/<provider-id>-rN/<rid>/`.
The 0.4 client verifies all namespaces; older clients enumerate only those they
understand. No SDK root is moved or rewritten during a tool upgrade.
A shared default selection that names a revision invisible to
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
marked UUID staging roots and unreferenced verified provider objects. SDK revisions remain until explicitly removed, and
rollback selects a retained verified revision. With no project SDK request,
default aliases choose the highest installed SDK series. The 0.3 and later tools
add the [project selection contract](cbodotnetup-project-selection.md): exact
`run` and versioned aliases precede the nearest cwd/ancestor `global.json`,
which precedes the installed default. The resolver searches only the owned
qualified inventory, fails closed on malformed configuration or symlinked
discovery paths, and accepts `sdk.paths` only as literal `$host$` entries.
Selection is offline and does not mutate project files or installation state.
Shell integration is explicit and never edits startup files or replaces
unrelated commands.

Modern SDK commands pass through the retained signed wrapper to `exec` the
selected SDK's `dotnet.dll`. Legacy commands use the verified payload host
directly: the historical archive wrapper declares Core3's curl requirement
without activating its environment. The manager supplies the complete private
provider scope rather than modifying the immutable wrapper. Only
`--cbodotnet-info` retains that wrapper's original distribution-identity output.
Owned DOTNET root/architecture/host variables and MSBuild SDK/extension paths
prevent a second initial SDK choice when project or solution ancestry differs
from cwd. Workload resolution stays enabled. Native-only lists and
application/`exec` dispatch keep the selected payload host.
Branding streams are preserved, while managed `--info`
intentionally omits the muxer's appended host/runtime footer. This controls
the initial CLI/MSBuild choice, rather than sandboxing custom targets or tools.
The source change requires a new immutable tool release and full native/public
qualification; it does not change existing SDK archives or published tools.

Authenticated self-update replaces an owned bootstrap executable only after
verifying both binary and notices, retaining the prior executable/notices.
Self-rollback requires the retained version to remain admitted and unrevoked.
All three catalogs retain the tool identities needed for compatible upgrade,
rollback and re-upgrade. Public qualification
must exercise the actual released old binary, its schema1 SDK installation,
the authenticated new executable and neutral SDK, and return to the old tool
without modifying retained SDK/provider state. The 0.4 gate also exercises an
actual 0.3 client returning to its modern SDK while private legacy installations
remain intact, then re-upgrading to execute those installations again.
An old binary cannot validate a new
catalog merely because the same project key signed it.
An interrupted tool replacement can be repaired by rerunning the pinned
bootstrap with a fresh signed catalog. The user data/SDK roots are independent
of this repair. There is no unsigned override or implicit system dependency
provisioning. Private legacy companion downloads require explicit consent;
project selection never grants it. Additional SDK versions require a new
per-target installer admission.

## Private legacy provider contract

The [provider design and source review](cbodotnetup-legacy-providers.md) and
[admission policy](../releases/cbodotnetup-provider-policy.json) bind four exact
SSL/ICU/curl objects across six legacy SDK/RID records. A provider record pins
its immutable archive, raw manifest, original signed consumer source publication,
vendor RPM/SRPM sources and signing identities, notices, native ABI/CPU limits
and individually admitted targets. SDK bindings separately pin the SDK source
and archive hashes. Ordinary package installation success is not provider
admission, and no system provider or caller-supplied root is imported.

`install ... --with-legacy-providers` explicitly authorizes the reviewed private
companions. Host glibc and every processor's x64-v2 features are checked before
provider download/extraction. Owned runtime roots reject `:`, `;`, `$` and
controls because [native loader](https://www.man7.org/linux/man-pages/man8/ld.so.8.html)
separators or token expansion could reinterpret an
otherwise valid filesystem path; ordinary spaces remain supported. Explicit
caller library paths retain their meaning after the approved provider prefixes.

Provider objects are verified and atomically renamed before SDK activation;
the SDK's receipt and provider references then become visible in one rename.
A crash can leave an unreferenced owned object, never an active SDK referring
to a partial companion. References are derived from verified SDK receipts,
not a separately mutable count. Removing one SDK preserves every shared
dependency still referenced by another, and `gc` verifies objects before
collecting only unreferenced ones. Removal can authenticate retained original
admission after withdrawal/revocation without authorizing execution or deletion
of modified/unrelated files. Provider binding changes require a new qualified
SDK archive revision or explicit reviewed remove/reinstall with consent.

The manager restores an inherited legacy caller scope, saves each original
variable's unset/empty/value state, then constructs the selected child's full
environment. Core3's private curl path precedes the base SSL/ICU path and the
original caller library path. OpenSSL configuration, SSL1.1 and Core3 ICU67 are
bound explicitly; the caller's CA choice is preserved, or the reviewed target
bundle is used when unset. Saved scope markers let an application launch a
modern manager without carrying private prefixes into that modern child.
All changes belong to `ProcessStartInfo`, including normal exit, failing exit
and start failure; the manager's own environment is not mutated. Native tests
must observe actual private library mappings and forced Core3 CurlHandler,
in addition to the same-process core launch/restoration tests.

The [issue-29 release record](cbodotnetup-legacy-validation.json) is separate
from the preserved modern and project-selection records. It is populated from
actual completed native/public and hosted-feed evidence before release claims
or target activation.

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
