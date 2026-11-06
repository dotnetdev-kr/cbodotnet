# cbodotnetup legacy SDK providers

This contract implements [issue #29](https://github.com/dotnetdev-kr/cbodotnet/issues/29)
in the 0.4 tool line. Availability follows the authenticated active catalog and
the installer-specific native and anonymous public qualification records. A
provider policy or a successful package build alone does not admit an SDK.

The initial candidate matrix is SDK5.0.214, Core3.1.426 and Core3.0.103 on
Ubuntu24.04, Debian13, Fedora45 and Rocky9.8, each x64/AArch64: 24 cells.
Alpine/musl and other OS versions remain separate qualification work.

## Reviewed source and redistribution decision

The installer reuses the existing immutable, separately published companions.
It does not rebuild an old native library, install a distribution package or
replace a host library. The [installer provider policy](../releases/cbodotnetup-provider-policy.json)
pins canonical downloads, the exact existing source-policy hashes, SDK/archive
bindings, CPU requirements and the target review. The original
[SSL/ICU policy](../releases/legacy-compatibility-provider.json) and
[Core3 curl policy](../releases/legacy-curl-provider.json) remain unchanged.

| Provider identity | Required SDKs | Canonical immutable publication |
| --- | --- | --- |
| `rocky9-20261104-r1/<rid>` | 5.0.214, 3.1.426, 3.0.103 | [SDK5.0.214 archive r2](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-archive-sdk-5.0.214-r2) |
| `rocky8-curl-20261104-r1/<rid>` | 3.1.426, 3.0.103 | [SDK3.1.426 archive r2](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-archive-sdk-3.1.426-r2) |

`<rid>` is `linux-x64` or `linux-arm64`. All three original SDK publications
bind identical SSL/ICU companion bytes for a given CPU; both Core3 publications
bind identical curl companion bytes. Four provider objects can therefore be
shared across six SDK/RID records. Every SDK's own signed publication must
still bind the required companions and its exact unchanged SDK archive.

The base companion contains unchanged Rocky9 OpenSSL compatibility libraries
`1:1.1.1k-5.el9_8.6` and ICU `67.1-10.el9_6`. The curl companion contains
unchanged Rocky8 `libcurl-minimal` `7.61.1-34.el8_10.18`. Vendor key identities,
binary RPM and matching source RPM URLs/hashes, ELF identities, original
licenses, attribution and inventories are retained in `provider-manifest.json`.
OpenSSL/SSLeay, ICU and curl notices accompany the libraries; the wrapper's MIT
license does not replace them. These are the already reviewed redistributable
provider inputs, packaged under project ownership rather than a promise of
Rocky support on another distribution.

The maintenance review on **2026-11-07** checked the current official repository
listings and the RESF [OpenSSL security advisory RLSA-2026:80514](https://apollo.build.resf.org/RLSA-2026:80514)
and [curl advisory RLSA-2026:92368](https://apollo.build.resf.org/RLSA-2026:92368).
They identify the pinned `.6` and `.18` vendor backport revisions. OpenSSL1.1's
base version number alone is not evidence that these vendor fixes are absent.
The original provider documentation's older RLSA-2026:22313 reference is
historical; the installer review includes the newer OpenSSL advisory.

[Rocky's lifecycle](https://docs.rockylinux.org/releases/) establishes the vendor
maintenance context, not cross-distribution runtime qualification. Reusing
these companions does not restore upstream .NET support or promise additional
project security maintenance. The catalog retains
`community-build-no-additional-security-maintenance`; the full scope statement
remains in each original provider manifest.

## Explicit installation and prerequisites

Legacy companion installation is opt-in:

```sh
cbodotnetup install 5.0.214-r2 --with-legacy-providers
cbodotnetup install --channel 3.1 --with-legacy-providers
cbodotnetup run 3.1.426-r2 -- --version
```

Without consent, installation reports the required separately maintained
providers. Project SDK selection does not acquire consent or download a
companion automatically. It selects only an already installed, admitted SDK
and its verified owned providers. Preinstalled system or package-managed
providers are not imported. The installer does not run `apt`, `dnf`, `rpm`,
modify a system CA bundle or provision operating-system dependencies.

The complete installation requires **glibc >=2.34**. The x64 base provider
requires **x86-64-v2**: CMPXCHG16B, LAHF/SAHF, POPCNT, SSE3, SSSE3, SSE4.1 and
SSE4.2 on every exposed processor. Unknown or insufficient capability fails
before activation. AArch64 retains ARMv8-A. The curl library's own glibc2.17
maximum does not reduce its dependency on the base provider's glibc2.34 floor.
No glibc provider is inferred to work on musl.

These provider prerequisites supplement the SDK's documented OS dependencies:

| Target | Base provider dependencies | Additional Core3 curl dependencies |
| --- | --- | --- |
| Ubuntu24.04 / Debian13 | `libc6`, `libgcc-s1`, `libstdc++6`, `zlib1g`, `ca-certificates` | `libnghttp2-14`, `libgssapi-krb5-2`, `libkrb5-3`, `libk5crypto3`, `libcom-err2` |
| Fedora45 | `glibc`, `libgcc`, `libstdc++`, `zlib-ng-compat`, `ca-certificates` | `libnghttp2`, `krb5-libs`, `libcom_err` |
| Rocky9.8 | `glibc`, `libgcc`, `libstdc++`, `zlib`, `ca-certificates` | `libnghttp2`, `krb5-libs`, `libcom_err` |

The target's signed stock repositories supply those dependencies explicitly.
Native verification must check the actual loaded provider paths, not merely a
package name or SONAME. Core3 must additionally exercise its forced native
CurlHandler; a passing default SocketsHttpHandler test is insufficient.

## Signed metadata and owned storage

The schema3 catalog binds each provider's ID/version/revision/RID, canonical
archive URL/length/SHA256, raw provider-manifest hash, original source-policy
hash, libc/CPU/glibc constraints, admitted targets, complete vendor source and
license manifest, and original signed consumer publication descriptors.
Legacy SDK bindings separately pin SDK identity, original SDK source manifest,
SDK archive hash and exact required provider IDs. Modern SDKs have no provider
binding. Extra, missing, duplicate, substituted or unreviewed bindings fail.

Before staging a provider, authenticate the original project-signed
`distribution-manifest.json` and its `.asc`, and match its companion record and
asset descriptor with the catalog. The provider manifest's vendor signing key
and the consumer publication's project signing key have different roles; one
must not substitute for the other. The producer independently validates the
original vendor policy and complete companion bytes before signing admission.

Each companion has exactly two top-level entries: `provider-manifest.json` and
`rootfs/`. Outer and inner provider-manifest bytes must agree. Every file,
directory, mode and SONAME link is checked; extra paths, traversal, escaping or
unapproved links, special files and modified notices or native binaries fail. The SDK payload
remains unchanged and never contains these companions.

For an owned installer root, storage is separate:

```text
<root>/cache/v3/                       active schema3 trust/high-water state
<root>/cache/v2/                       compatible modern-only schema2 state
<root>/toolchains-v2/                  compatible modern SDK receipts
<root>/toolchains-v3/                  legacy SDK receipts and provider references
<root>/providers/<provider-id>-r1/<rid>/
    owner
    receipt.json
    inventory.json
    catalog.json, catalog.json.asc
    source-manifest.json, source-manifest.json.asc
    content/provider-manifest.json
    content/rootfs/usr/lib/cbodotnet/compat/...
```

The absolute root in the historical provider manifest describes its original
layout. Execution uses the equivalent path under that verified private
`content/rootfs/` tree. It does not write to the historical system root.
Modern installations retain the exact signed schema2 compatibility projection so
that an old 0.2/0.3 executable can still read their receipts. Old clients ignore
the separate legacy namespace rather than parsing unsupported metadata.

SDK and provider staging uses the shared operation lock. All required provider
objects must be complete and verified before the SDK receipt is atomically
activated. Interruption can leave an unreferenced owned object, never an active
SDK referring to a partial provider. SDK removal removes that installation;
`gc` derives references from verified remaining legacy receipts and removes only
unreferenced, verified owned provider objects. It does not trust an independent
mutable reference counter or remove another SDK's dependency.

## Execution and environment boundaries

The manager verifies provider receipt, signed admission, original source
publication, inventory and host compatibility before execution. User-supplied
provider roots cannot redirect it to unrelated libraries. The selected child's
environment receives the owned SSL/ICU and, for Core3, curl roots. Configuration
is applied to that child without mutating the manager's environment.

Legacy SDK/runtime commands execute the verified `payload/dotnet` host with
the complete native-root and provider environment bound by the manager.
Historical Core3 archive wrappers activate only their base provider; their curl
qualification used an externally supplied library path. The manager therefore
supplies both private prefixes directly and does not depend on the caller's
library settings. It retains the original wrapper for the early
`--cbodotnet-info` identity response and preserves all archive bytes.

The manager preserves the caller's presence and value of scoped variables in
the existing Community scope convention. A subsequent SDK selection restores that environment
before applying its own provider settings. The scope covers `LD_LIBRARY_PATH`,
`OPENSSL_CONF`, `CLR_OPENSSL_VERSION_OVERRIDE`, `CLR_ICU_VERSION_OVERRIDE` and
`SSL_CERT_FILE`. Successful and failing legacy children must leave a subsequent
modern selection and the same manager process unchanged.

The scoped TLS configuration has no host crypto-policy include, minimum TLS1.2
and security level2. This is the project's explicit compatibility policy.
The OS owns certificate updates; an explicit user `SSL_CERT_FILE` is preserved.
The reviewed Fedora45 CA location is `/etc/ssl/certs/ca-certificates.crt`, rather
than the older fallback recorded in the immutable source policy. See the
[base-provider CA-path decision](legacy-compatibility-provider.md).

This controls the initial SDK and provider launch. Project targets, extensions
and arbitrary applications can explicitly launch their own commands; this is
not a process sandbox. SDK package restore retains its normal behavior.

## Update, retirement and qualification

Operator procedure for a provider update:

1. Review vendor advisories, current package/SRPM revisions, signing identity,
   required notices and redistribution terms. Audit ELF loader/dependencies,
   glibc and CPU constraints on both native architectures.
2. Produce new immutable companion and source publication identities. Preserve
   the old policy, published bytes and URLs; never put different bytes under
   the same provider ID/revision/RID. Review the installer admission policy and
   every affected SDK binding explicitly.
   Bindings in an installed SDK receipt are immutable. A provider replacement
   needs a new qualified SDK archive revision (the SDK payload can stay
   unchanged), or an explicit reviewed remove/reinstall with consent; it is not
   a transparent provider-only migration under the same installed SDK identity.
   The 0.4 client deliberately accepts a closed provider/source contract. Review
   client compatibility before publishing a new provider identity or origin.
   When a new tool/feed generation is necessary, retain the earlier signed feed
   with compatible upgrade tool records, and publish the replacement through a
   separate versioned endpoint. Never strand older clients by putting records
   they cannot parse into their active feed. The authenticated modern-only v2
   bridge and independently pinned bootstrap remain recovery paths.
3. Requalify every advertised cell, including SDK-free bootstrap, offline
   console/apphost/ASP.NET, default HTTP, TLS/crypto/full ICU, forced Core3 curl
   HTTP, callback-observed HTTPS, ordinary CA trust, and source/inventory paths.
   Repeat actual anonymous public downloads after publication.
4. Check sharing, SDK/tool update and rollback, interruption recovery, tamper
   rejection, environment restoration, removal and coexistence with official
   and package-managed SDKs. Re-run modern SDK regressions and existing-client
   upgrade paths before feed activation.
5. To retire an unsafe object, revoke `provider/<provider-id>-rN/<rid>` in a
   fresh signed catalog and publish the replacement only after qualification.
   A revoked provider cannot be silently restored by renewal or used to admit
   a new installation. Preserve retained ownership evidence so recovery and
   cleanup remain reviewable; revocation does not authorize deleting unknown
   or modified files.

The installer has no additional telemetry or credential-sharing path for
providers. Companion requests are bounded, credential-free public release
downloads. Existing project OpenPGP signing is sufficient; this work introduces
no persistent signing credential. Native and public installer evidence, rather
than a policy declaration, determines which of the 24 cells becomes available.
