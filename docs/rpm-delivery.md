# RPM delivery and qualification

Issue [#5](https://github.com/dotnetdev-kr/cbodotnet/issues/5) prepares the qualified
.NET SDK 10.0.403 for the following exact targets. Qualification and first public
installation evidence are still pending; this document does **not** announce an
available RPM channel. Availability comes from
[`releases/downstream-status.json`](../releases/downstream-status.json), its signed
publication receipts and the target reports, rather than the presence of packaging
code or a workflow run.

| Variant | Native public architectures | RPM architectures | Required native packages |
| --- | --- | --- | --- |
| `fedora-45` | `x64`, `aarch64` | `x86_64`, `aarch64` | `glibc`, `libgcc`, `libstdc++`, `zlib-ng-compat`, `krb5-libs`, `ca-certificates`, `libicu`, `openssl3-libs` |
| `rocky-9.8` | `x64`, `aarch64` | `x86_64`, `aarch64` | `glibc`, `libgcc`, `libstdc++`, `zlib`, `krb5-libs`, `ca-certificates`, `libicu`, `openssl-libs` |

The [contract](../releases/distribution-contract.json) owns this dependency policy.
Fedora 45's default OpenSSL 4 libraries do not satisfy the qualified SDK's crypto
probe. The RPM therefore depends explicitly on Fedora's official `openssl3-libs`
compatibility package. This does not patch the SDK or bundle a private OpenSSL.
Rocky uses its official OpenSSL 3 `openssl-libs` package. Neither target inherits
compatibility from another Fedora/RHEL-family distribution or release number.

## Payload, identity and ownership

The packager revalidates the pinned public source-release manifest, SDK archive
and qualified producer catalog. It copies the SDK without rebuilding it. RPM
stripping, debug-package generation, build-ID links and install-time rewriting
are disabled; extraction of the actual RPM is compared with the staged SDK for
bytes, modes and links. The original SDK `LICENSE.txt` and
`ThirdPartyNotices.txt` remain in `/opt/cbodotnet/10.0` and are copied into the
package documentation directory. Their upstream copyright and licensing terms
remain authoritative; the SDK spec uses `LicenseRef-Dotnet-SDK-ThirdParty`.
The shared selector includes this repository's reviewed [MIT license](../LICENSE)
under `/usr/share/licenses/cbodotnet-host/`.

| Package | Version and release for revision 1 | Ownership |
| --- | --- | --- |
| `cbodotnet-sdk-10.0` | `10.0.403-1.cbot.fedora45` or `10.0.403-1.cbot.rocky9.8` | `/opt/cbodotnet/10.0`, `/usr/bin/cbodotnet-10.0`, documentation and provenance |
| `cbodotnet-host` | `1.0.0-1.cbot.fedora45` or `1.0.0-1.cbot.rocky9.8`, `noarch` | `/usr/bin/cbodotnet` and its selector license |

Distro-specific RPM releases prevent different dependency graphs from sharing
one name/epoch/version/release/architecture identity (NEVRA). The shared package
has its own version and canonical `noarch` build target; its unsigned bytes must
match across both native architectures of a variant. Promotion signs it once
and reuses those exact signed bytes.

The selector chooses the highest installed Community Build SDK series. The
versioned launcher selects the 10.0 series. RPM packages do not own
`/usr/bin/dotnet`, register system alternatives or modify an official .NET root.
Branding is supplied by the launchers: `--version` retains numeric stdout and
prints `Community Build of .NET (built by .NET Dev)` on stderr; `--info` and
`--cbodotnet-info` identify the build and qualified provenance. One complete SDK
is installed per major/minor series, so a packaging revision replaces the earlier
revision of that series.

## Native validation and protected promotion

Run the [distribution workflow](../.github/workflows/distribution-release.yml)
from `main`. The initial read-only native matrix does not sign or publish:

```bash
gh workflow run distribution-release.yml --ref main \
  -f channel=rpm -f tag=sdk-10.0.403 -f revision=1 -f publish=false
```

Both native runner jobs must succeed. Each builds and installs real RPMs in
Fedora 45 and Rocky 9.8 containers, using the architecture-specific image digests
in [`scripts/rpm-ci.py`](../scripts/rpm-ci.py). Reports record the exact OS,
native CPU and resolved dependency packages. The lifecycle checks package
ownership and integrity, unchanged SDK payload, branded aliases, non-root offline
console build/run, ASP.NET loopback HTTP, cryptography, ICU globalization and
coexistence with an independently installed official SDK. It also installs the
next real packaging revision, downgrades to the original and removes the SDK.
After provisioning, runtime checks execute with Docker `--network none`.

To promote an already successful native matrix, use its exact run and attempt:

```bash
gh workflow run distribution-release.yml --ref main \
  -f channel=rpm -f tag=sdk-10.0.403 -f revision=1 -f publish=true \
  -f source_run_id=SUCCESSFUL_NATIVE_RUN -f source_run_attempt=1
```

Only the protected main workflow and `downstream-release` environment can access
the approved [distribution signer](distribution-signing.md). Before signing any
RPM, promotion admits the complete four-target matrix, qualified source, actual
RPM headers, native reports, dependency evidence and required checks. It signs
the payloads, independently verifies their signatures, rebinds the changed package
hashes, signs repository metadata and reports, then freezes the complete signed
publication bundle before creating or resuming a release.

Repository metadata lives on Pages under `packages/rpm/<variant>/`. The
`rpm-<variant>.tar.gz` archives contain signed `repodata/repomd.xml`, its indexes,
public keys and repository manifests, without RPM blobs. Indexes point to exact
canonical package asset URLs under the immutable GitHub release
`distribution-rpm-sdk-10.0.403-r1`. SDK asset names include the variant and public
architecture; shared-host names include the variant. The signed publication
manifest binds every package and metadata archive by size and SHA-256.

Post-publication jobs anonymously retrieve those public assets and install the
signed repository in both native architectures. Only successful receipts and
target results activate availability and request a Pages refresh. After that
Pages deployment succeeds, verify the actual HTTPS repository commands:

```bash
gh workflow run rpm-site-check.yml --ref main \
  -f publication_run_id=SUCCESSFUL_PUBLICATION_RUN -f publication_run_attempt=1
```

Require both native jobs, each exercising Fedora 45 and Rocky 9.8, to pass before
announcing completion. The HTTPS check retains both metadata and payload
signature checks, runs the installed SDK offline as a non-root user and removes
the SDK while verifying official .NET coexistence.

If publication or its later checks fail after the signed bundle was frozen,
resume the original signed bytes instead of rebuilding or signing them again:

```bash
gh workflow run distribution-release.yml --ref main \
  -f channel=rpm -f tag=sdk-10.0.403 -f revision=1 -f publish=true \
  -f promotion_run_id=FROZEN_PUBLICATION_RUN -f promotion_run_attempt=1
```

Use either native-source recovery or frozen-promotion recovery, never both.
The matching frozen artifact must still exist and its freeze step must have
succeeded. Conflicting or incomplete already-public assets cannot be overwritten;
diagnose the failure and use a new packaging revision when new bytes are needed.

## Installation and package lifecycle after publication

Use these commands only after RPM is `published` in the authenticated status and
the HTTPS target checks pass. First confirm the full primary fingerprint through
the project's trusted signing-policy channel. Set `variant` for the actual OS:

```bash
variant=fedora-45 # rocky-9.8 on Rocky Linux 9.8
case "$variant" in
  fedora-45) distro=fedora45 ;;
  rocky-9.8) distro=rocky9.8 ;;
  *) exit 1 ;;
esac
sudo dnf install -y ca-certificates curl gnupg2
curl -fsSLo /tmp/cbodotnet-signing-key.asc \
  https://dotnetdev.kr/cbodotnet/distribution-signing-key.asc
test "$(gpg --show-keys --with-colons /tmp/cbodotnet-signing-key.asc | \
  awk -F: '$1=="fpr" {print $10; exit}')" = \
  D7D154B4B33C19A82B95B13688135410ACD9C0EA || exit 1
sudo rpm --import /tmp/cbodotnet-signing-key.asc
sudo tee /etc/yum.repos.d/cbodotnet.repo > /dev/null <<EOF
[cbodotnet-sdk-10.0]
name=Community Build of .NET SDK
baseurl=https://dotnetdev.kr/cbodotnet/packages/rpm/$variant/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://dotnetdev.kr/cbodotnet/distribution-signing-key.asc
EOF
sudo dnf --refresh makecache
sudo dnf --setopt=tsflags= --setopt=keepcache=True install \
  "cbodotnet-sdk-10.0-10.0.403-1.cbot.$distro" cbodotnet-host
cbodotnet --version
cbodotnet-10.0 --cbodotnet-info
```

Keep both `gpgcheck=1` and `repo_gpgcheck=1`: package signatures and repository
signatures serve separate checks. The key is ASCII armored for RPM 4 clients;
the accompanying binary keyring is used independently by `gpgv`.

Before upgrading, retain the current signed SDK RPM and its authenticated
publication manifest/signature outside disposable package-manager caches. Match
the retained file's size and SHA-256 to the verified signed manifest and inspect
`rpmkeys --checksig --verbose <file>` for an `OK` signature with no `NOKEY` or
`NOT OK`. Upgrades use the currently published repository:

```bash
sudo dnf --refresh --setopt=tsflags= --setopt=keepcache=True upgrade cbodotnet-sdk-10.0
```

To roll back to the retained revision 1 package, select the current RPM CPU name
with `rpm --eval '%{_arch}'`, then require local package signature checking:

```bash
rpm_arch=$(rpm --eval '%{_arch}')
sudo dnf --setopt=tsflags= --setopt=localpkg_gpgcheck=1 downgrade \
  "./retained/cbodotnet-sdk-10.0-10.0.403-1.cbot.$distro.$rpm_arch.rpm"
sudo dnf --setopt=clean_requirements_on_remove=False remove cbodotnet-sdk-10.0
```

SDK removal leaves the shared selector installed; it reports no available
Community Build SDK rather than falling back to official .NET. Remove the host
separately with `sudo dnf remove cbodotnet-host` when no installed Community Build
SDK depends on it. Upgrade and rollback are separate user actions from removal.

These packages add no security-maintenance commitment beyond the qualified
community build. Other Fedora releases, other RHEL derivatives and versions,
musl environments and legacy .NET versions remain unqualified. The contract
blocks legacy downstream packaging until separate channel qualification; it
does not permit bundling obsolete OpenSSL or ICU to bypass those gates.
