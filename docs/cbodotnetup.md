# cbodotnetup

`cbodotnetup` manages verified Community Build SDKs in a regular user's home.
Its Linux glibc target matrix is x64/AArch64 on Ubuntu24.04, Debian13,
Fedora45 and Rocky Linux9.8. It preserves official `dotnet`, official
`dotnetup` state and package-managed `/opt/cbodotnet` installations. NativeAOT
bootstrap does not require an installed .NET SDK.

Version [0.2.0 is published](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/cbodotnetup-v0.2.0).
The 0.2.0 catalog migration passed both an eight-target native candidate matrix
and an eight-target anonymous public binary/SDK download matrix before
[feed activation](../releases/cbodotnetup-status.json). Use the
[download site](https://dotnetdev.kr/cbodotnet/) for the active signed catalog
and bootstrap. Installer admission is scoped to each SDK, OS version and CPU;
the active signed catalog is the source of available versions.
The compatible catalog migration is recorded in
[#26](https://github.com/dotnetdev-kr/cbodotnet/issues/26) and its
[independent validation evidence](cbodotnetup-v2-validation.json). The
availability record and signed public feed determine the active revisions;
the historical 0.1.0 evidence is retained at the end of this document.

## SDK admission and lifecycle

The reviewed neutral archive inputs for
[#27](https://github.com/dotnetdev-kr/cbodotnet/issues/27) are:

| SDK | Archive revision | Community channel |
| --- | --- | --- |
| 10.0.403 | r3 | 10.0 |
| 9.0.123 | r2 | 9.0 |
| 8.0.133 | r2 | 8.0 |
| 7.0.120 | r2 | 7.0 |
| 6.0.136 | r2 | 6.0 |

Run `cbodotnetup list --available` to authenticate current admission before
installing. Published package/archive evidence establishes the inputs; installer
promotion separately requires native and anonymous public installation evidence
for every advertised SDK/OS/CPU combination. The five-SDK matrix contains 40
cells: 32 additional cells for SDK9/8/7/6 and eight SDK10 regression cells.
Unqualified or revoked combinations are refused before activation.

The [upstream lifecycle policy](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core),
reviewed on 2026-11-06, records:

| .NET series | Upstream phase on the review date | Upstream end of support |
| --- | --- | --- |
| 10 LTS | Active | 2028-11-14 |
| 9 STS | Maintenance | 2026-11-10 |
| 8 LTS | Maintenance | 2026-11-10 |
| 7 STS | Ended | 2024-05-14 |
| 6 LTS | Ended | 2024-11-12 |

These dates describe product series; upstream servicing also requires current
patches. The exact immutable Community SDK pins above have their own provenance
and qualification records. Catalogs declare
`community-build-no-additional-security-maintenance`; Community qualification
covers observed installation and runtime behavior and does not extend vendor
servicing or automatically track later upstream patches.

Microsoft's [Ubuntu](https://learn.microsoft.com/en-us/dotnet/core/install/linux-ubuntu-install)
and [Debian](https://learn.microsoft.com/en-us/dotnet/core/install/linux-debian)
installation tables include .NET10/9/8 on Ubuntu24.04 and Debian13 on the review
date. Its [supported OS table](https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.md)
lists Fedora44/43, while this project qualifies Fedora45 independently. Rocky9.8
is also an explicit Community target; an RHEL9 listing alone is not evidence for
this project's exact Rocky package/CPU combination. The SDK7/6 targets retain
their upstream EOL status even after successful Community installation tests.

The SDK9/8/7/6 expansion reuses the immutable 0.2.0 tool and publishes a new
signed schema2 catalog after qualification. The schema1 feed remains limited to
SDK10 revision2 and compatible tool records. Additional legacy-provider SDKs
and musl admission have separate work items.

## Bootstrap

Install Python3, GnuPG, CA certificates and the [SDK's OS dependencies](../releases/distribution-contract.json)
using your OS package manager. These are explicit prerequisites; the installer
does not install packages or obsolete native libraries. Do not use `sudo` to
run the bootstrap or the installed manager.

Download and review `get-cbodotnetup.py` from the verified download site or an
independently trusted repository commit. Compare its embedded public key and
fingerprint with the [signing policy](distribution-signing.md):
`D7D154B4B33C19A82B95B13688135410ACD9C0EA`. Trusting an adjacent checksum/key alone
does not establish the bootstrap trust root. The bootstrap verifies the fresh
catalog signature, then exact binary and runtime notice hashes before writing
`$HOME/.local/bin/cbodotnetup`. Existing unrelated files are refused.

```sh
python3 get-cbodotnetup.py
~/.local/bin/cbodotnetup list --available
~/.local/bin/cbodotnetup install 10.0.403
~/.local/bin/cbodotnetup run 10.0.403 -- --info
```

Add `$HOME/.local/bin` to PATH explicitly if desired. `--install-dir` chooses
another ordinary user-owned directory. For offline bootstrap, obtain an
independently authenticated `catalog.json`/`.asc`, native binary and adjacent
`cbodotnetup-<rid>.LICENSE.txt`:

```sh
python3 get-cbodotnetup.py --catalog-file ./catalog.json --binary-file ./cbodotnetup-linux-x64
```

Offline bootstrap still requires a fresh project-signed catalog. It never
accepts a custom trust key, unsigned metadata or a mismatching binary.

## Commands and paths

```sh
cbodotnetup list
cbodotnetup doctor
cbodotnetup install --channel 10.0
cbodotnetup update
cbodotnetup run 10.0.403-r2 -- --version
cbodotnetup rollback 10.0.403-r2
cbodotnetup shell enable
cbodotnetup shell disable
cbodotnetup remove 10.0.403-r2
cbodotnetup gc
cbodotnetup self update
cbodotnetup self rollback
```

The root is `$XDG_DATA_HOME/cbodotnetup`, defaulting to
`$HOME/.local/share/cbodotnetup`; `CBODOTNETUP_HOME` can select a dedicated
absolute user-owned root. `shell enable` creates only owned `cbodotnet` and
`cbodotnet-X.Y` links in `<root>/bin` and prints that directory for explicit PATH
configuration. It never creates a user-local `dotnet` alias. The common command
selects the highest installed Community SDK series; exact `run` works without
PATH changes. Branding is **Community Build of .NET (built by .NET Dev)** and
`--version` stdout remains numeric.

An exact revision names an immutable archive. Identical retries verify existing
bytes/modes/links before succeeding; conflicting state is refused. Updates keep
previous SDK roots. `rollback` selects an already retained, signed revision;
it does not silently fetch a withdrawn version. A different rollback target
becomes usable only when separately admitted and installed. Concurrent
operations fail with a retry message.

## Catalog migration and compatibility

The 0.2 client uses the versioned schema2 feed at
`https://dotnetdev.kr/cbodotnet/cbodotnetup/v2/catalog.json`. Its neutral SDK10
archive is revision3. The legacy endpoint
`https://dotnetdev.kr/cbodotnet/cbodotnetup/catalog.json` remains schema1, with
the historical SDK10 revision2 archive and compatible tool records, including
the authenticated upgrade to 0.2. No old release asset is renamed or replaced.
Historical unbranded trial SDKs are not admitted.

Existing 0.1.0 users can upgrade with `cbodotnetup self update`, then run
`cbodotnetup list --available` to authenticate the new feed before using
`cbodotnetup update` or installing a revision3 SDK. Revision2 remains retained
for explicit SDK rollback. SDK availability still requires individual OS/CPU
qualification; the new catalog format does not admit additional SDK series,
legacy providers or musl by itself.

Both client generations share the owner marker, operation lock and selection
state, but retain separate signed cache/high-water records: 0.1.0 uses
`<root>/cache/`, and 0.2 uses `<root>/cache/v2/`. Historical SDK installations
stay in `<root>/toolchains/`; neutral SDK installations use
`<root>/toolchains-v2/`. The new client verifies both namespaces. The old client
sees its original namespace only, so a retained 0.1.0 executable can operate
without parsing schema2 admissions. A shared selection naming an unseen neutral
revision falls back to an installed compatible revision in the old namespace.
Retain revision2 if recovery with the old tool must include SDK execution.

`self rollback` restores the retained, admitted and unrevoked tool executable
and notices. After returning to 0.1.0, its schema1 feed and original SDK roots
remain usable; `self update` can authenticate the upgrade again. Neutral SDK
roots remain intact for the new client. If an update is interrupted, rerun the
independently trusted current bootstrap with a fresh signed catalog to repair
the owned executable and marker; it does not erase SDK roots or bypass hashes.

The two feeds are renewed together through the protected publication workflow,
each with its own monotonic sequence/hash record and a 30-day catalog lifetime.
There is no automatic schema1 sunset. Retirement requires an announced owner
decision, a documented upgrade/support window and independently authenticated
bootstrap recovery instructions. A failed renewal does not extend either
catalog's validity. Already installed SDK execution can use an authenticated
offline cache, but new installation and self-update require a fresh catalog.
Revoking the old tool also requires reviewing its migration fixture and the
upgrade/retirement plan; renewal must never restore a revoked tool to admission.

`list --available`, installation, update and self-update obtain a fresh catalog.
`--catalog FILE` uses a local project-signed catalog and adjacent `.asc` with the
same signature/freshness/anti-rollback rules. The 0.2 client's active catalog,
including a local file, must use schema2; schema1 is accepted only for retained
SDK admission verification. Offline `run`, installed `list`,
removal and `doctor` use the last verified cache. Offline clients cannot learn
new revocations until refreshing. Signature/key revocation and known release
revocations still apply. SDKs needing unadmitted legacy providers are rejected
with an actionable dependency message.

## Recovery and removal

Interrupted SDK staging never replaces an active root. Retry the exact install;
`gc` removes abandoned marked staging data. Changed installed inventories are
refused and reported by `doctor`; inspect the cause before restoring the
original bytes or manually removing your own data. `gc` retains installed SDKs.

Self-update retains `.previous` and its notices. `self rollback` verifies the
retained bytes against the current signed tool catalog and refuses revoked
versions. If a tool update was interrupted, rerun the trusted bootstrap; it
recognizes signed recovery bytes and repairs the owned executable/marker.

To uninstall, remove each installed SDK, disable the owned shell aliases, then
remove the bootstrap-owned `cbodotnetup`, `.ownership.json`, `.LICENSE.txt` and
any verified `.previous` recovery files from its installation directory. The
data root can then be inspected and removed by its owner; no system package or
official installer state is part of this root. Keep unrelated files intact.

Key rotation/revocation follows the existing [project procedure](distribution-signing.md).
Distribute the replacement bootstrap/trust root through an independently
authenticated source. There is no automatic acceptance of an unrelated key.
The signed catalog is renewed weekly through the protected workflow, using
authenticated published build inputs, current dependency vulnerability data
and repeated native/public qualification. Failed renewal leaves the existing
immutable release intact and does not extend its expiry. Maintainers must
resolve failures before expiry. Native runtime changes require a new tool
version. Catalog maintenance and native runtime updates remain project responsibilities;
distribution does not create an upstream security-support promise for EOL SDKs.
See the [implementation and trust design](cbodotnetup-design.md).

## 0.2.0 migration validation

The [0.2.0 evidence](cbodotnetup-v2-validation.json) binds eight native candidate
and eight anonymous public installation reports to the actual job IDs, downloaded
artifact ZIPs and report hashes. All public targets exercised the released 0.1.0
bootstrap and executable, r2 installation, authenticated 0.2.0 self-update, neutral
r3 installation, SDK rollback, tool rollback to 0.1.0 and re-upgrade. Expired
signed catalogs were rejected, old cache bytes stayed unchanged, and the verified
bootstrap repaired an injected interrupted ownership commit.

The default hosted bootstrap also passed on native x64 and AArch64 without an
installed SDK, checking both hosted signed feeds against activated hashes. Core
security and file-transaction tests passed 119 checks on each native CPU. The
Python suite ran 781 tests: 776 passed and five required unavailable environment
features. Existing 71 releases and 930 assets retained their exact metadata and
identities; the latest SDK pointer remains SDK10 revision3.

## Retained 0.1.0 validation

The [independent final evidence](cbodotnetup-validation.json) authenticates the
two public immutable releases, exact tool/source/catalog/notices, signed native
dependency audit, actual job IDs and API artifact ZIP size/SHA256. All eight
native candidate targets and eight anonymous public installation targets passed.
Both native architectures also bootstrapped from the default hosted feed without
an installed SDK. Runtime checks execute as user10001 with the network disabled;
real interrupted downloads, retry/collection, actual official/package-managed
Community inventories, versioned/common aliases, HTTP/crypto/globalization and
final removal were observed.

Core security/file-transaction tests passed 73 cases on each native architecture,
including real project signatures in long paths, retained patch selection and
own-executable update/rollback with conflicting/corrupt input rejection. The
repository Python suite passed 708 tests (five environment-dependent skips).
Published native build-input reuse and a fresh official NuGet vulnerability
audit also passed, independently of expiring workflow artifact storage.
