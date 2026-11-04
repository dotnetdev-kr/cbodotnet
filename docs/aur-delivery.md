# Arch Linux recipe build and validation

The tracked recipes prepare SDKs **10.0.403, 9.0.123, 8.0.133, 7.0.120,
6.0.136, 5.0.214, 3.1.426 and 3.0.103** for Arch Linux `x86_64` from their
independently qualified source archives. All eight passed their individual
native Arch build, runtime and package lifecycle checks. A separate native check
also passed with all eight installed together, including default version
selection and descending removal fallback. Individual, aggregate and historical
evidence are recorded below.
The recipes have **not been submitted to AUR** and do not make an AUR package
available. Issue [#6](https://github.com/dotnetdev-kr/cbodotnet/issues/6) covers
recipe development and native build/install validation. Actual account ownership,
maintainer identity, SSH authorization, repository submission and public install
verification are deferred to issue
[#10](https://github.com/dotnetdev-kr/cbodotnet/issues/10), at the user's request.
`releases/downstream-status.json` must continue to report AUR as `not-published`.

Each SDK has its own package base and shares one independent selector. Legacy
SDKs also depend on a separate compatibility package:

| Package base | Version | Ownership |
| --- | --- | --- |
| [`cbodotnet-host`](../packaging/aur/cbodotnet-host/PKGBUILD) | 1.0.0-1 | `/usr/bin/cbodotnet`, the shared SDK selector |
| [`cbodotnet-sdk-10.0-bin`](../packaging/aur/cbodotnet-sdk-10.0-bin/PKGBUILD) | 10.0.403-1 | `/opt/cbodotnet/10.0`, `/usr/bin/cbodotnet-10.0`, source provenance and original notices |
| [`cbodotnet-sdk-9.0-bin`](../packaging/aur/cbodotnet-sdk-9.0-bin/PKGBUILD) | 9.0.123-1 | `/opt/cbodotnet/9.0`, `/usr/bin/cbodotnet-9.0` and retained notices |
| [`cbodotnet-sdk-8.0-bin`](../packaging/aur/cbodotnet-sdk-8.0-bin/PKGBUILD) | 8.0.133-1 | `/opt/cbodotnet/8.0`, `/usr/bin/cbodotnet-8.0` and retained notices |
| [`cbodotnet-sdk-7.0-bin`](../packaging/aur/cbodotnet-sdk-7.0-bin/PKGBUILD) | 7.0.120-1 | `/opt/cbodotnet/7.0`, `/usr/bin/cbodotnet-7.0` and retained notices |
| [`cbodotnet-sdk-6.0-bin`](../packaging/aur/cbodotnet-sdk-6.0-bin/PKGBUILD) | 6.0.136-1 | `/opt/cbodotnet/6.0`, `/usr/bin/cbodotnet-6.0` and retained notices |
| [`cbodotnet-sdk-5.0-bin`](../packaging/aur/cbodotnet-sdk-5.0-bin/PKGBUILD) | 5.0.214-1 | `/opt/cbodotnet/5.0`, `/usr/bin/cbodotnet-5.0` and retained notices |
| [`cbodotnet-sdk-3.1-bin`](../packaging/aur/cbodotnet-sdk-3.1-bin/PKGBUILD) | 3.1.426-1 | `/opt/cbodotnet/3.1`, `/usr/bin/cbodotnet-3.1` and retained notices |
| [`cbodotnet-sdk-3.0-bin`](../packaging/aur/cbodotnet-sdk-3.0-bin/PKGBUILD) | 3.0.103-1 | `/opt/cbodotnet/3.0`, `/usr/bin/cbodotnet-3.0` and retained notices |
| [`cbodotnet-compat-rocky9`](../packaging/aur/cbodotnet-compat-rocky9/PKGBUILD) | 2026.11.4-1 | Separate OpenSSL 1.1/ICU 67 provider under `/usr/lib/cbodotnet/compat/rocky9`; no SDK payload |
| [`cbodotnet-compat-curl-rocky8`](../packaging/aur/cbodotnet-compat-curl-rocky8/PKGBUILD) | 2026.11.4-1 | Core 3.0/3.1-only curl provider under `/usr/lib/cbodotnet/compat/curl-rocky8`; no SDK payload |

Separating the shared host package base allows future SDK series to depend on
the same selector without tying its version or ownership to one SDK release.
These packages do not own `/usr/bin/dotnet` or change an existing official .NET root.
The common `cbodotnet` command selects the highest installed Community Build SDK
series; `cbodotnet-10.0` selects this series explicitly.

## Build locally on Arch Linux

Run these commands on native Arch Linux `x86_64`, from this repository. Review the
PKGBUILDs and their local source files first. `makepkg` must run as an ordinary
user. Only dependency installation and `pacman` installation/removal need root.
Arch requires a complete system upgrade rather than a partial upgrade.

```bash
sudo pacman -Syu --needed base-devel python namcap curl ca-certificates \
  glibc libgcc libstdc++ zlib krb5 icu openssl libnghttp2 e2fsprogs rpm-tools gnupg binutils

cd packaging/aur/cbodotnet-host
makepkg --verifysource
makepkg --printsrcinfo > .SRCINFO
makepkg --cleanbuild --noconfirm
namcap PKGBUILD cbodotnet-host-1.0.0-1-any.pkg.tar.zst
sudo pacman -U ./cbodotnet-host-1.0.0-1-any.pkg.tar.zst

cd ../cbodotnet-sdk-10.0-bin
makepkg --verifysource
makepkg --printsrcinfo > .SRCINFO
makepkg --cleanbuild --noconfirm
namcap PKGBUILD cbodotnet-sdk-10.0-bin-10.0.403-1-x86_64.pkg.tar.zst
sudo pacman -U ./cbodotnet-sdk-10.0-bin-10.0.403-1-x86_64.pkg.tar.zst

cbodotnet --version
cbodotnet-10.0 --info
cbodotnet --cbodotnet-info
```

The default package extension in the official Arch build environment is
`.pkg.tar.zst`; `makepkg --packagelist` reports the actual filename if local
configuration changes it. `--version` keeps the numeric SDK version on stdout
and emits `Community Build of .NET (built by .NET Dev)` on stderr. Information
commands include the branding and exact qualified source identity.

The example selects SDK 10; use the corresponding package base and launcher
from the table for another admitted series. Before building SDK 5.0 or Core
3.0/3.1, build and install `packaging/aur/cbodotnet-compat-rocky9` using the same
`makepkg --verifysource`, `makepkg --cleanbuild` and `pacman -U` sequence.
Those SDK recipes require exactly `cbodotnet-compat-rocky9=2026.11.4-1`.
Its pinned signed Rocky binary/source RPMs, licenses, scoped TLS configuration,
and maintenance limits are recorded in the
[separate provider policy](legacy-compatibility-provider.md).
The provider requires **x86-64-v2** CPU features; its shared launcher preflight
rejects unsupported or unknown CPUs before loading the libraries. It does not
restore upstream .NET/OpenSSL support or promise additional security fixes.
The qualified SDK binaries retain their original CPU baseline and bytes.

Core 3.0/3.1 additionally require exactly
`cbodotnet-compat-curl-rocky8=2026.11.4-1`. Build and install that recipe after the
base provider, then build the selected Core 3 SDK recipe. The separate
[curl provider policy](legacy-curl-provider.md) authenticates current Rocky 8
binary/source RPMs with the independently pinned Rocky 8 key and preserves the
original curl notice. This private curl uses the base provider's OpenSSL 1.1;
stock Arch `curl` and `libnghttp2` remain declared runtime dependencies.
The original optional `System.Net.Http.Native.so` is retained unchanged. Its
selectable CurlHandler is exercised with the private compatible curl, including
real HTTP, HTTPS certificate callbacks, default system trust and TLS 1.2.
SDK 5 and modern SDKs do not load this second provider.

Keep earlier locally built package files before changing `pkgrel`. Upgrade with
`sudo pacman -U ./<new-package-file>` and roll back with
`sudo pacman -U ./<retained-old-package-file>`. The automated test builds real
revisions 1 and 2 and performs both operations. Remove the SDK with
`sudo pacman -R cbodotnet-sdk-10.0-bin`; the shared selector remains installed and
reports that no Community Build SDK is available. Remove it separately with
`sudo pacman -R cbodotnet-host` when no other Community Build SDK depends on it.
Remove the independently installed compatibility package only after all legacy
SDKs depending on it are removed. Changing its reviewed version requires a new
matching legacy SDK package revision and native verification; keep both package
files when retaining a rollback pair.

## Source integrity and updates

Every local source file and downloaded release asset has a non-`SKIP` SHA-256
checksum. The recipe downloads the immutable SDK archive, canonical
`release-manifest.json` and its `SHA256SUMS`. The standalone `verify-source.py`
binds the SDK, corresponding source and evidence descriptors, qualified producer
identity and both-architecture release matrix to the reviewed local
`distribution.json`. It rejects unsafe archive members and mutated extraction
caches before packaging.

The package copies the complete qualified SDK tree without rebuilding or patching
it. Explicit `!strip`, `!debug`, `!lto`, `!zipman`, `!purge`, `docs`, `libtool`,
`staticlibs` and `emptydirs` options preserve its existing bytes, modes, links,
documentation and static libraries. Original `LICENSE.txt` and
`ThirdPartyNotices.txt` remain in the SDK root and are also installed under
`/usr/share/licenses/cbodotnet-sdk-10.0-bin/`.
Arch metadata identifies the original SDK MIT license as `MIT` and the retained
aggregate third-party notice as `LicenseRef-Dotnet-ThirdPartyNotices`, using
current SPDX-compatible identifiers.
Original SDK `metadata` contents and modes are preserved. Additional directories
are created only when explicitly admitted for that release; the seven additional
SDKs do not receive a metadata overlay.

For a packaging-only change, increment the SDK package revision and regenerate
its wrapper, policy, checksums and actual `.SRCINFO` together. Do not change the
SDK version, qualified archive or SDK bytes. The host package has its own version
and revision, changed only when its selector changes. A new SDK version first
requires independently qualified producer evidence and an admitted manifest pin
in the [distribution contract](../releases/distribution-contract.json). Then
regenerate the complete recipe source tree from that verified intake, review the
result, rerun native validation and regenerate `.SRCINFO` with real `makepkg`.
Editing only `pkgver`, checksum strings or `.SRCINFO` does not qualify a release.

## Native and rolling compatibility evidence

The `aur` channel of the
[distribution workflow](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/distribution-release.yml)
runs `scripts/aur-ci.py native` on a native x64 GitHub runner. It starts from the
official Arch `base-devel` amd64 image pinned in `scripts/aur_delivery.py`, then
performs `pacman -Syu`. The report records the immutable starting image, actual
Arch OS metadata, resolved dependency versions, makepkg/pacman versions and
native runtime linkage. The current image pin was resolved from official Docker
registry metadata for Arch image `20261101.0.620205`.
The minimal container image's `NoExtract` exclusions are disabled so the test
uses normal full-package extraction, including source provenance and notices;
`pacman -Qkk` must report zero altered files for every selected SDK, selector and
required compatibility package.
After provisioning dependencies, the driver snapshots that disposable container
and runs the entire build and installed lifecycle with Docker `--network none`.
Only loopback is present, which still permits the local ASP.NET HTTP probe.
`makepkg` verifies its pre-populated, hash-pinned source cache, and the report
records `networkForBuild: none`.

Validation performs actual non-root `makepkg --verifysource`, `.SRCINFO`
generation and package builds; `namcap`; `pacman` ownership/integrity checks;
byte/mode/link comparison against the qualified SDK; branded aliases; a non-root
offline DLL and direct apphost build/run using the selected SDK's actual target
framework; ASP.NET loopback HTTP; TLS 1.2; RSA cryptography and enabled ICU
globalization; independent official SDK 10.0.100 coexistence; real revision
upgrade, rollback, reinstall and removal. Legacy preparation authenticates and
installs the separate provider first; offline validation rebuilds its recipe and
checks that its installed bytes, modes, links and root ownership remain unchanged
through SDK lifecycle transitions. It retains the two, three or four recipe source trees, a recipe-only
archive, build/lint logs and machine-readable reports as workflow artifacts.
Those artifacts and reports are build evidence, not a publication receipt.

The current individual qualifications all passed on native Arch `x86_64`:

| SDK | Successful workflow run, attempt 1 |
| --- | --- |
| 10.0.403 | [41853894668](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41853894668) |
| 9.0.123 | [41853906025](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41853906025) |
| 8.0.133 | [41853919683](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41853919683) |
| 7.0.120 | [41853930923](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41853930923) |
| 6.0.136 | [41853945892](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41853945892) |
| 5.0.214 | [41870678817](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41870678817) |
| 3.1.426 | [41890026843](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41890026843) |
| 3.0.103 | [41890068173](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41890068173) |

The [all-SDK evidence](aur-all-sdk-validation.json) retains their exact original
reports, source commits and successful run attempts, artifact identifiers and
independently verified API ZIP hashes. Encoding each `exactReport` as documented
in that file recovers the original report bytes and SHA-256. These are
authenticated GitHub CI results; they are not signed publication receipts.
The base provider-only
[run 41865718558](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41865718558)
and curl addon-only
[run 41889193725](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41889193725)
also passed real makepkg, namcap and pacman integrity/lifecycle checks without
downloading, building or executing an SDK. Those reports are retained separately
and do not substitute for the individual SDK qualifications.

The read-only
[all-SDK coinstallation workflow](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/aur-coinstall-check.yml)
requires the successful base-provider run and all eight individual SDK proofs
before downloading SDK inputs. Core 3 reports must also pass the independent
source-pinned curl/provider and forced-handler runtime evidence gate.
[Aggregate run 41892598873, attempt 1](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41892598873)
passed from source commit
[`ae58dec`](https://github.com/dotnetdev-kr/cbodotnet/commit/ae58dec180ff183f6bd9fa96970808a51324fd48).
It installed all eight Community SDKs together, compared their qualified
payloads, exercised every versioned alias and selected SDK 10.0.403 through
`cbodotnet`. Removing SDKs in descending order selected 9.0.123, 8.0.133,
7.0.120, 6.0.136, 5.0.214, 3.1.426 and 3.0.103 in turn; after the last removal
the selector returned 127. Both providers remained unchanged through all 17
checkpoints, followed by final shared-package removal. Each source archive was
received once, package builds ran without external networking, and no SDK source
was rebuilt. The aggregate reuses the independently admitted individual runtime
proofs above rather than repeating their application tests.

The existing independently verified official SDK 10.0.100 archive installation
and its `dotnet` selection stayed unchanged throughout. This baseline does not
claim ownership by an Arch vendor package. The aggregate's exact original report,
prerequisite source/artifact bindings, provider policy hashes and API-verified
ZIP hash are also retained in [the all-SDK evidence](aur-all-sdk-validation.json).

The historical SDK 10.0.403 native lifecycle passed on 2026-11-04 in
[run 41779636849, attempt 1](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41779636849),
using source commit
[`95dbe62`](https://github.com/dotnetdev-kr/cbodotnet/commit/95dbe62d3ca9acb3a92e31f896d4b7b321688188).
The retained [validation evidence](aur-validation.json) includes the exact
original report, source/run/commit identity, artifact ID and API SHA-256,
recipe-file hashes, actual `.SRCINFO` hashes, native target/dependency versions
and reviewed lint findings. An independent download matched the artifact API
digest, and both recipe trees and actual `.SRCINFO` bytes matched the tracked
sources exactly. Tested runtime dependencies included OpenSSL 3.6.5-1 and ICU
78.3-1. The original report's pacman version display field is empty because that
command starts its output with a blank line; the executed pacman lifecycle and
integrity checks passed, and future capture strips leading whitespace. The
original report and its digest remain unchanged.

The complete raw `namcap` output is retained. The current official `elfpaths`
rule classifies every ELF under `/opt` as questionable, reporting the summary
`ELF files outside of a valid path ('opt/').` at error severity. The validator
reviews only that exact summary for the SDK binary package because the reviewed
contract requires `/opt/cbodotnet/<major.minor>` isolation. It records the finding and
rationale as `passed-with-reviewed-findings`, then verifies the entire installed
SDK payload independently. All other error-level findings, including missing
dependencies, continue to fail validation. No namcap rule is disabled.

The weekly
[Arch runtime check](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/aur-runtime-check.yml)
repeats the same clean native lifecycle against fully updated Arch packages.
Reports identify that actual weekly workflow, rather than borrowing the release
workflow's identity. A failure blocks any future AUR submission until reviewed;
the rolling distribution and tested dependency versions cannot be treated as a
permanent compatibility guarantee. The weekly workflow has read-only repository
permissions and does not sign, submit or publish packages.

Primary references: [makepkg](https://man.archlinux.org/man/makepkg.8.en),
[PKGBUILD](https://man.archlinux.org/man/PKGBUILD.5.en),
[SRCINFO](https://wiki.archlinux.org/title/.SRCINFO), and
[AUR submission guidelines](https://wiki.archlinux.org/title/AUR_submission_guidelines).
The [Arch container guide](https://wiki.archlinux.org/title/Install_Arch_Linux_via_Docker)
also describes the minimal image's `NoExtract` policy.
