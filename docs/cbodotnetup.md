# cbodotnetup

`cbodotnetup` manages verified Community Build SDKs in a regular user's home.
Its Linux glibc target matrix is x64/AArch64 on Ubuntu24.04, Debian13,
Fedora45 and Rocky Linux9.8. It preserves official `dotnet`, official
`dotnetup` state and package-managed `/opt/cbodotnet` installations. NativeAOT
bootstrap does not require an installed .NET SDK.

The 0.4 tool line adds explicitly opted-in
[private legacy providers](cbodotnetup-legacy-providers.md) for SDK5.0.214,
Core3.1.426 and Core3.0.103. It retains
[project SDK selection](cbodotnetup-project-selection.md) from `global.json`,
with explicit SDK/series precedence and no automatic SDK installation.
[Issue #29](https://github.com/dotnetdev-kr/cbodotnet/issues/29) has a separate
[source, redistribution and maintenance decision](cbodotnetup-legacy-providers.md#reviewed-source-and-redistribution-decision)
and installer-specific qualification gate.
Use the [activated installer status](../releases/cbodotnetup-status.json) and
[download site](https://dotnetdev.kr/cbodotnet/) for the active signed catalog
and bootstrap. Installer admission is scoped to each SDK, OS version and CPU;
the active signed catalog is the source of available versions.
The earlier compatible catalog migration is recorded in
[#26](https://github.com/dotnetdev-kr/cbodotnet/issues/26) and its
[independent evidence](cbodotnetup-v2-validation.json); the five-SDK expansion
is recorded in [#27](https://github.com/dotnetdev-kr/cbodotnet/issues/27) and its
[qualification evidence](cbodotnetup-modern-sdk-validation.json). The published
[0.3.0 tool](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/cbodotnetup-v0.3.0)
and [project-selection evidence](cbodotnetup-project-validation.json), along
with earlier validation records, remain below.

## SDK admission and lifecycle

The 0.4 contract includes the neutral archive revisions below. The active
signed catalog determines which exact SDK/OS/CPU cells are available. The
modern SDKs retain the [#27 installer evidence](cbodotnetup-modern-sdk-validation.json);
legacy additions require their own [#29 validation](cbodotnetup-legacy-validation.json).

| SDK | Archive revision | Community channel | Private provider consent |
| --- | --- | --- | --- |
| 10.0.403 | r3 | 10.0 | None |
| 9.0.123 | r2 | 9.0 | None |
| 8.0.133 | r2 | 8.0 | None |
| 7.0.120 | r2 | 7.0 | None |
| 6.0.136 | r2 | 6.0 | None |
| 5.0.214 | r2 | 5.0 | `--with-legacy-providers`: SSL/ICU companion |
| 3.1.426 | r2 | 3.1 | `--with-legacy-providers`: SSL/ICU and curl companions |
| 3.0.103 | r2 | 3.0 | `--with-legacy-providers`: SSL/ICU and curl companions |

Run `cbodotnetup list --available` to authenticate current admission before
installing. Published package/archive evidence establishes the inputs; installer
promotion separately requires native and anonymous public installation evidence
for every advertised SDK/OS/CPU combination. The eight-SDK contract has 64
cells: 40 modern regressions and 24 legacy-provider additions.
Unqualified or revoked combinations are refused before activation.

The [upstream lifecycle policy](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core),
reviewed on 2026-11-07, records:

| .NET series | Upstream phase on the review date | Upstream end of support |
| --- | --- | --- |
| 10 LTS | Active | 2028-11-14 |
| 9 STS | Maintenance | 2026-11-10 |
| 8 LTS | Maintenance | 2026-11-10 |
| 7 STS | Ended | 2024-05-14 |
| 6 LTS | Ended | 2024-11-12 |
| 5 STS | Ended | 2022-05-10 |
| Core 3.1 LTS | Ended | 2022-12-13 |
| Core 3.0 STS | Ended | 2020-03-03 |

These dates describe product series; upstream servicing also requires current
patches. The exact immutable Community SDK pins above have their own provenance
and qualification records. Catalogs declare
`community-build-no-additional-security-maintenance`; Community qualification
covers observed installation and runtime behavior and does not extend vendor
servicing or automatically track later upstream patches.

The 2026-11-06 modern-target review found .NET10/9/8 in Microsoft's
[Ubuntu](https://learn.microsoft.com/en-us/dotnet/core/install/linux-ubuntu-install)
and [Debian](https://learn.microsoft.com/en-us/dotnet/core/install/linux-debian)
installation tables for Ubuntu24.04 and Debian13. Its
[supported OS table](https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.md)
listed Fedora44/43, while this project qualifies Fedora45 independently. Rocky9.8
is also an explicit Community target; an RHEL9 listing alone is not evidence for
this project's exact Rocky package/CPU combination. SDK7/6/5 and Core3 retain
their upstream EOL status even after successful Community installation tests.

The original SDK9/8/7/6 expansion reused the immutable 0.2.0 tool and activated
the [historical schema2 catalog](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/cbodotnetup-catalog-42213550406).
The schema1 feed remains limited to
SDK10 revision2 and compatible tool records. The schema2 feed remains
modern-only. The schema3 provider contract extends the installer without
adding unsupported SDK records to either older feed. Musl admission remains
a separate work item.

## Bootstrap

Install Python3, GnuPG, CA certificates and the [SDK's OS dependencies](../releases/distribution-contract.json)
using your OS package manager. These are explicit prerequisites; the installer
does not provision system packages or replace host libraries. Legacy consent
allows only the separately authenticated private companions described below.
Do not use `sudo` to run the bootstrap or the installed manager.

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
cbodotnetup list --available
cbodotnetup install --channel 10.0
cbodotnetup install --channel 9.0
cbodotnetup install 5.0.214-r2 --with-legacy-providers
cbodotnetup install --channel 3.1 --with-legacy-providers
cbodotnetup update
cbodotnetup update --with-legacy-providers
cbodotnetup run -- build
cbodotnetup run 9.0.123-r2 -- --version
cbodotnetup rollback 9.0.123-r2
cbodotnetup shell enable
cbodotnetup shell disable
cbodotnetup remove 9.0.123-r2
cbodotnetup gc
cbodotnetup self update
cbodotnetup self rollback
```

The root is `$XDG_DATA_HOME/cbodotnetup`, defaulting to
`$HOME/.local/share/cbodotnetup`; `CBODOTNETUP_HOME` can select a dedicated
absolute user-owned root. `shell enable` creates only owned `cbodotnet` and
`cbodotnet-X.Y` links in `<root>/bin` and prints that directory for explicit PATH
configuration. It never creates a user-local `dotnet` alias. Exact `run` works
without PATH changes. In versions 0.3 and later, the common alias and `run --` use the
nearest cwd/ancestor `global.json` SDK request; without one they preserve the
highest installed Community SDK series and active revision. Explicit `run`
versions and versioned aliases take precedence. See the
[project SDK selection contract](cbodotnetup-project-selection.md) for policy,
ownership restrictions and the managed `--info` output boundary. Earlier tools
retain their published default selection behavior. Branding is **Community
Build of .NET (built by .NET Dev)** and `--version` stdout remains numeric.

From a project directory, `cbodotnetup run -- build` or `cbodotnet build` uses
the nearest cwd/ancestor SDK request. `cbodotnet-9.0 build` selects the installed
9.0 series, and `cbodotnetup run 10.0.403-r3 -- build` selects that exact archive
despite a different project pin. Missing SDKs produce an explicit install
action. Relative or absolute `sdk.paths` roots are unsupported; omit the field
or use literal `$host$` entries to keep selection within verified owned SDKs.

An exact revision names an immutable archive. Identical retries verify existing
bytes/modes/links before succeeding; conflicting state is refused. Updates keep
previous SDK roots. `rollback` selects an already retained, signed revision;
it does not silently fetch a withdrawn version. A different rollback target
becomes usable only when separately admitted and installed. Concurrent
operations fail with a retry message.

## Explicit legacy-provider installation

The first installation of SDK5 or Core3 requires `--with-legacy-providers`.
This authorizes only the exact signed user-scoped companions bound to that
SDK and host. Existing system/package providers and caller-supplied provider
roots are not imported. The SDK payload remains unchanged. These installations
require glibc >=2.34 and, on x64, x86-64-v2 on every exposed processor, plus the
[documented stock OS dependencies](cbodotnetup-legacy-providers.md#explicit-installation-and-prerequisites).
Owned legacy provider paths must not contain `:`, `;`, `$` or control
characters, because the native loader interprets separators and expansion
tokens. Choose an ordinary `CBODOTNETUP_HOME`; spaces remain supported.
The signed metadata, source/license review and runtime requirements are
explained in the [provider contract](cbodotnetup-legacy-providers.md).

An identical installed SDK retry verifies its retained providers. A tracked
legacy channel can reuse its existing receipt's consent during `update`.
Removing that SDK leaves the tracked channel but does not preserve implicit
permission to download its providers again: use
`cbodotnetup update --with-legacy-providers` or an explicitly opted-in install
to restore it. Project selection never downloads a missing provider or SDK.

Providers are shared only by exact authenticated identity. Removing one SDK
does not remove another SDK's dependency. After SDK removal, `gc` verifies the
remaining references and collects only unreferenced owned provider objects.
The child's provider environment is isolated; successful, failing and
unstartable children do not rewrite the manager's caller environment. An
explicit user `SSL_CERT_FILE` is preserved; otherwise the reviewed target CA
bundle is selected. Official dotnet and the system CA bundle remain under
their existing owners.

The manager runs the verified legacy payload host with this complete child
environment. The standalone Core3 archive wrapper correction is tracked in
[#31](https://github.com/dotnetdev-kr/cbodotnet/issues/31); this tool release
preserves the existing r2 archive bytes.

## Catalog migration and compatibility

Three signed feeds preserve clients that validate unknown fields strictly:

| Client line | Feed below `https://dotnetdev.kr/cbodotnet/cbodotnetup/` | Trust cache | SDK namespace |
| --- | --- | --- | --- |
| 0.1 | `catalog.json` (schema1) | `<root>/cache/` | `toolchains/`: SDK10 archive r2 |
| 0.2 / 0.3 | `v2/catalog.json` (schema2) | `<root>/cache/v2/` | `toolchains-v2/`: modern SDKs |
| 0.4 | `v3/catalog.json` (schema3) | `<root>/cache/v3/` | Existing modern namespace plus legacy `toolchains-v3/` |

The schema3 feed hash-binds its separately signed `catalog-v2.json`
compatibility projection. Modern SDK records and receipts remain unchanged,
and new modern installations retain that exact schema2 admission. An older
0.2/0.3 executable can therefore still verify them. Legacy SDK receipts and
their provider references live only in `toolchains-v3/`; immutable shared
companions live separately in `providers/`. Older clients ignore those roots.
The schema1 feed retains SDK10 revision2 with its original filename. All three
feeds retain compatible authenticated tool upgrade records. No historical
release asset is renamed or replaced, and trial SDKs are not admitted.

Existing 0.1.0 users can upgrade with `cbodotnetup self update`, then run
`cbodotnetup list --available` to authenticate the current feed before using
`cbodotnetup update` or installing another SDK. SDK10 revision2 remains retained
for explicit SDK rollback. SDK availability still requires individual OS/CPU
qualification; the new catalog format does not admit additional SDK series,
legacy providers or musl by itself.

All client generations share the owner marker, operation lock and selection
state, while their signed cache/high-water records remain separate. The 0.4
client verifies all three SDK namespaces without rewriting older receipts.
A shared selection naming an unseen revision falls back to a compatible
installed revision visible to the old client. Retain SDK10 revision2 if recovery
with 0.1.0 must include SDK execution; retain a modern installation for recovery
with 0.2/0.3. Those older tools cannot manage legacy provider installations.

After a 0.3 self-update, 0.4 can use an authenticated modern-only schema2 cache
offline until a schema3 cache has been established. `list --available` explicitly
refreshes schema3 admission. A malformed or conflicting schema3 cache does not
silently fall back. When explicitly installing a modern SDK from a local
schema3 catalog, its exact signed `catalog-v2.json`/`.asc` may be supplied
alongside it; otherwise that install obtains the canonical bound projection.
Local execution does not download the projection.

`self rollback` restores the retained, admitted and unrevoked tool executable
and notices. After returning to 0.1.0, its schema1 feed and original SDK roots
remain usable; `self update` can authenticate the upgrade again. Neutral SDK
roots and private providers remain intact for the new client. A retained 0.3
tool can run its modern SDKs while leaving legacy state untouched, then
authenticate a re-upgrade. Re-upgrade before maintaining legacy tracked
channels. If an update is interrupted, rerun the
independently trusted current bootstrap with a fresh signed catalog to repair
the owned executable and marker; it does not erase SDK roots or bypass hashes.

The three feeds are renewed together through the protected publication workflow,
each with its own monotonic sequence/hash record and a 30-day catalog lifetime.
There is no automatic schema1 sunset. Retirement requires an announced owner
decision, a documented upgrade/support window and independently authenticated
bootstrap recovery instructions. A failed renewal does not extend any
catalog's validity. Already installed SDK execution can use an authenticated
offline cache, but new installation and self-update require a fresh catalog.
Revoking the old tool also requires reviewing its migration fixture and the
upgrade/retirement plan; renewal must never restore a revoked tool to admission.

`list --available`, installation, update and self-update obtain a fresh catalog.
`--catalog FILE` uses a local project-signed catalog and adjacent `.asc` with the
same signature/freshness/anti-rollback rules. The 0.4 default endpoint requires
schema3. A local schema2 bridge is accepted for modern SDK operations and tool
recovery; schema1 is accepted only for retained SDK admission verification.
Offline `run`, installed `list`,
removal and `doctor` use the last verified cache. Offline clients cannot learn
new revocations until refreshing. Signature/key revocation and known release
revocations still apply. SDKs needing unadmitted legacy providers are rejected
with an actionable dependency message. A project request never opts into
provider installation.

## Recovery and removal

Interrupted SDK staging never replaces an active root. Retry the exact install;
`gc` removes abandoned marked staging data and unreferenced verified providers.
It preserves companions still referenced by any retained legacy SDK.
Changed installed inventories are
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

## 0.4 legacy-provider qualification

The [issue-29 independent validation record](cbodotnetup-legacy-validation.json)
is the completion record for immutable source/tool assets, the three signed
feeds, provider origins, actual native/public job and artifact identities,
hosted bootstrap and historical release preservation. Promotion requires all
64 SDK/OS/CPU cells in each phase: 40 modern regressions and 24 legacy cells.
Neither the source review nor an existing SDK/package qualification substitutes
for these installer results.

Legacy gates require explicit consent; source, signature, CPU and ABI rejection;
private crypto/ICU library mappings; offline console/apphost/ASP.NET and
HTTP/TLS/globalization; forced Core3 CurlHandler with callback and ordinary CA
validation; shared-provider lifetime; interruption recovery; immutable SDK
inventories; actual old-tool rollback/re-upgrade; and official/package-managed
coexistence. Core tests exercise successful, failing and unstartable children
through the common manager launch path, including a modern child nested in a
legacy scope, to verify caller-environment restoration in one managed process.

The immutable [0.4.0 release](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/cbodotnetup-v0.4.0)
passed all 64 cells in both the candidate and anonymous public phases of the
[native release workflow](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/42256817100).
Each phase also passed 624 native reference checks and 1,680 project-selection
cases across the 56 additional SDK cells. Actual 0.1/0.2/0.3 migration paths
remain covered; the public phase includes 0.4→0.3→0.4 recovery with installed
legacy SDKs and shared providers, preserving their receipts and selections.

The [native C# source suite](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/42256788052)
passed 436 checks on each CPU. [Repository CI](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/42256787837)
ran 872 Python tests: 868 passed and four were skipped.
After [Pages deployment](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/42261726388),
the [default hosted-feed checks](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/42262834534)
authenticated all three feeds and bootstrapped 0.4.0 on both CPUs without an
installed SDK. The activated catalog sequence is
[42256817100](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/cbodotnetup-catalog-42256817100).

Independent validation downloaded all 36 new tool/catalog assets anonymously,
matched their sizes and SHA256 hashes, and verified 16 pinned-project signatures:
12 catalog/freeze signatures, three original provider source publications and
the previous active catalog. All 77 earlier releases and 1,010 earlier assets
retained their metadata, identities and hashes. The latest SDK download remains
SDK10.0.403 archive r3.

## Retained 0.3.0 project selection validation

The [independent issue-28 evidence](cbodotnetup-project-validation.json) binds
the then-new immutable tool/source assets and paired signed catalogs to actual REST
job IDs, original ZIP/report bytes, source CI logs and release preservation.
The candidate phase passed all 40 SDK/OS/CPU cells across eight native targets.
Each qualification phase evaluates 78 matching-only native reference cases per
target (624 checks) and 30 project-selection cases per additional SDK cell
(960 checks across 32 cells). SDK10 supplies the eight migration regressions.

Project checks cover explicit/versioned/project precedence, policy matching,
unsupported paths, missing SDK diagnostics, offline argument forwarding,
owned CLI/MSBuild binding and preservation of project and installed SDK files.
Actual previous 0.2.0 binaries exercise upgrade and retained SDK state; public
qualification also requires tool rollback and re-upgrade. The original 0.1.0
migration remains a separate SDK10 regression.

The native C# source suite passed 315 checks on each CPU. Repository CI ran
830 Python tests: 826 passed and four were skipped.

The anonymous public phase also passed all 40 cells across eight native targets.
After [Pages deployment](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/42225918010),
the [default hosted-feed checks](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/42226898913)
authenticated and bootstrapped 0.3.0 on both CPUs without an installed SDK.
The activated paired catalog sequence was
[42222819193](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/cbodotnetup-catalog-42222819193).
Independent comparison preserved all 75 earlier releases and 984 earlier assets,
including their titles, bodies, file identities and hashes. The latest SDK
download remained SDK10.0.403 archive r3. All 26 new tool/catalog assets were
downloaded anonymously and matched REST/status hash pins. The signed frozen
inventory, source inputs and seven GPG signatures were verified separately.

## Retained modern SDK installation validation

The [modern SDK evidence](cbodotnetup-modern-sdk-validation.json) compares the
actual candidate and public job IDs, original artifact ZIPs and report bytes.
Each phase passed 32 additional SDK9/8/7/6 cells and eight SDK10 regression
cells. Every additional SDK was installed alongside SDK10 in its own test root;
the common alias kept SDK10 while the versioned alias and explicit run selected
the intended lower series. Offline DLL/apphost, ASP.NET/HTTP, TLS, cryptography
and full ICU checks passed, followed by removal and preservation of official
and package-managed files.

Signed revocation, invalid signatures, interrupted installations, locking,
retry/collection, tracked updates and retained selection were exercised. The
interruption harness kills and reaps the actual unprivileged worker session;
an independent Linux regression verifies immediate lock reacquisition without
sleep or lock retries. Actual 0.1.0 upgrade/rollback/re-upgrade remains covered
by the SDK10 regression in all eight public environments.

The hosted bootstrap passed on both native CPUs and authenticated the exact
five-SDK catalog. CI ran 799 Python tests: 796 passed and three were skipped;
the native core suite passed 119 checks per CPU. Existing 73 releases and 952
assets, including the unchanged 0.2.0 tool binaries, remained intact. The earlier
unactivated candidate is preserved with a notice; the active catalog sequence
is 42213550406.

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
