# Provider-aware installer catalog

This is the implementation contract for cbodotnetup 0.4 and
[#29](https://github.com/dotnetdev-kr/cbodotnet/issues/29). Publication remains
conditional on the independent native and anonymous public qualification gates.
The signed active feed, rather than this design document, determines availability.

## Compatible generations

Strict earlier clients reject unknown JSON members. Provider fields therefore
belong to a separate schema3 feed; no SDK or receipt fields are added to schema2.
All three signed views share one sequence, issue/expiry interval, signer, tool
records and revocation policy.

| Endpoint | Admission | Clients |
| --- | --- | --- |
| `cbodotnetup/catalog.json` | Schema1, historical SDK10 archive r2 | Original 0.1 clients and authenticated tool upgrades |
| `cbodotnetup/v2/catalog.json` | Schema2, the five modern neutral SDK archives | 0.2/0.3 clients and modern recovery |
| `cbodotnetup/v3/catalog.json` | Schema3, modern SDKs plus individually admitted SDK5/Core3 providers | 0.4 and later |

The schema3 `compatibilityCatalog` asset pins the exact size, SHA256 and immutable
release URL of `catalog-v2.json`. Its adjacent OpenPGP signature is independently
verified. The client checks that modern SDK records, tools, channels and trust
metadata agree before retaining a modern installation's schema2 admission.
Earlier signed releases and their bootstrap files remain unchanged.

Caches and high-water records are separate: schema1 retains `cache/`, schema2
retains `cache/v2/`, and schema3 uses `cache/v3/`. An authenticated schema2 cache
can still run existing modern SDKs immediately after an older client's tool
upgrade. The first explicit refresh obtains schema3; an ordinary offline run
does not contact the feed. Identical sequence numbers in different generations
cannot overwrite or conflict with each other's hash records.

## Provider and source binding

`SdkRelease` keeps its previous shape. A legacy record sets
`requiresLegacyProvider`; a schema3 `providerBindings` entry binds its exact
SDK ID, original source-manifest hash and SDK archive hash to an ordered set of
provider IDs. SDK5 requires the base OpenSSL/ICU companion. Core3 requires that
same base plus the separate native libcurl companion.

Each provider record identifies its version/revision, RID/libc, immutable
archive, raw inner-manifest SHA256, original vendor-policy hash, full manifest,
original signed distribution manifest/signature, notices, native ABI/CPU
constraints and individually admitted OS/CPU targets. Provider revocation keys
use `provider/<provider-id>-r<revision>/<rid>`. SDK and provider revocation are
checked separately. Source publication signatures and the archive's complete
manifest/inventory must agree before a provider object is committed.

The [closed admission policy](../releases/cbodotnetup-provider-policy.json) and
[provider review](cbodotnetup-legacy-providers.md) bind the existing immutable
companions, vendor RPM/SRPM origins, license inventory and maintenance decision.
System providers and arbitrary caller-supplied provider paths are not imported.
The current base requires glibc 2.34 and every exposed x64 processor to satisfy
x86-64-v2; AArch64 retains its reviewed baseline. ABI checks precede provider
downloads and extraction. These glibc companions are not Alpine/musl admission.

## Ownership, consent and transactions

Modern SDKs remain in `toolchains-v2/` with unchanged schema1 receipts and
retained signed schema2 catalogs. Legacy SDKs use `toolchains-v3/` with schema2
receipts and a separate `providers.json` reference set. Older tools consequently
continue to enumerate their known modern namespace without parsing legacy state.

Provider objects are shared under `providers/<provider-id>-r<revision>/<rid>/`.
Each has its own owner marker, immutable content, retained source publication,
signed admission, receipt and file inventory. Its archive has only the reviewed
`provider-manifest.json` and `rootfs/` tree, outside every SDK payload. Extracted
paths, links, modes, file hashes and notices are verified; no provider writes to
system library or official dotnet locations.

The first legacy installation requires explicit `--with-legacy-providers`
consent. System package prerequisites remain an explicit operator step. The
installer does not invoke a distribution package manager to repair dependencies.
Existing verified legacy receipts can authorize tracked updates; a tracked
channel alone does not silently authorize a fresh provider installation after
its SDK has been removed.

The shared operation lock covers provider and SDK transactions. Providers are
prepared and verified in owned staging directories, then committed as immutable
objects. Only after all references are ready is the SDK receipt/root atomically
activated. A crash can leave verified, unreferenced objects, but cannot advertise
a partially extracted SDK. References are derived from verified installed
receipts instead of a mutable counter. SDK removal preserves providers used by
another SDK; explicit garbage collection removes only verified unreferenced
objects and abandoned owned staging directories.

An installed SDK's provider references are immutable. Rotating a provider needs
a newly qualified SDK archive revision or an explicit consented reinstall;
changing the binding under an existing SDK identity fails closed. The initial
client accepts the reviewed provider/source set only. A future rotation that
changes that contract must review client/feed compatibility first, retaining
an authenticated old-client upgrade view and using a new versioned endpoint
when necessary.

## Execution and qualification

Provider settings are applied to `ProcessStartInfo.Environment`, after restoring
an inherited Community wrapper scope. The manager does not change its own
process environment. Canonical owned roots override arbitrary provider-root
variables; an explicit caller `SSL_CERT_FILE` is preserved, otherwise the
reviewed current OS CA path is selected. Legacy SDK/runtime commands execute the
verified payload host with complete owned OpenSSL/ICU/libcurl and native-root
settings supplied by the manager. The historical Core3 archive wrapper lacks
curl activation, so it is retained only for its early identity JSON command.
Modern SDK commands keep their archive wrapper. The selected managed CLI and
MSBuild binding from 0.3 remains in force. Modern child commands receive their
restored caller environment. Project code can still explicitly launch its own
commands; this is not a process sandbox.

Promotion requires the existing 40 modern SDK/OS/CPU cells plus up to 24 explicit
legacy cells, separately in candidate and anonymous public phases. Tests include
SDK-free bootstrap, opt-in and ABI rejection, missing/substituted/tampered
providers, provider sharing and cleanup, interruption, SDK/tool rollback,
project selection, console/apphost/ASP.NET, standard CA trust, HTTP/TLS/crypto,
full ICU, and forced Core3 CurlHandler HTTPS with an observed certificate
callback. Native source tests also exercise successful and failing child
execution in one process to detect environment leakage. A separate signed
incompatible-ABI fixture tests the ABI gate independently of signature rejection.

Actual 0.1, 0.2 and 0.3 binaries retain independently tested upgrade/recovery
paths. Public downloads, original report ZIPs, job/source identities, sources,
licenses, signature pins and the preservation of official/package-managed state
must agree before the website exposes schema3 admission.
