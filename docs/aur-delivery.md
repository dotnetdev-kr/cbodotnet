# Arch Linux recipe build and validation

The tracked recipes prepare the qualified .NET SDK 10.0.403 for Arch Linux
`x86_64`. They have **not been submitted to AUR** and do not make an AUR package
available. Issue [#6](https://github.com/dotnetdev-kr/cbodotnet/issues/6) covers
recipe development and native build/install validation. Actual account ownership,
maintainer identity, SSH authorization, repository submission and public install
verification are deferred to issue
[#10](https://github.com/dotnetdev-kr/cbodotnet/issues/10), at the user's request.
`releases/downstream-status.json` must continue to report AUR as `not-published`.

There are two independent package bases:

| Package base | Version | Ownership |
| --- | --- | --- |
| [`cbodotnet-host`](../packaging/aur/cbodotnet-host/PKGBUILD) | 1.0.0-1 | `/usr/bin/cbodotnet`, the shared SDK selector |
| [`cbodotnet-sdk-10.0-bin`](../packaging/aur/cbodotnet-sdk-10.0-bin/PKGBUILD) | 10.0.403-1 | `/opt/cbodotnet/10.0`, `/usr/bin/cbodotnet-10.0`, source provenance and original notices |

Separating the shared host package base allows future SDK series to depend on
the same selector without tying its version or ownership to one SDK release.
Neither package owns `/usr/bin/dotnet` or changes an existing official .NET root.
The common `cbodotnet` command selects the highest installed Community Build SDK
series; `cbodotnet-10.0` selects this series explicitly.

## Build locally on Arch Linux

Run these commands on native Arch Linux `x86_64`, from this repository. Review the
PKGBUILDs and their local source files first. `makepkg` must run as an ordinary
user. Only dependency installation and `pacman` installation/removal need root.
Arch requires a complete system upgrade rather than a partial upgrade.

```bash
sudo pacman -Syu --needed base-devel python namcap curl ca-certificates \
  glibc libgcc libstdc++ zlib krb5 icu openssl

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

Keep earlier locally built package files before changing `pkgrel`. Upgrade with
`sudo pacman -U ./<new-package-file>` and roll back with
`sudo pacman -U ./<retained-old-package-file>`. The automated test builds real
revisions 1 and 2 and performs both operations. Remove the SDK with
`sudo pacman -R cbodotnet-sdk-10.0-bin`; the shared selector remains installed and
reports that no Community Build SDK is available. Remove it separately with
`sudo pacman -R cbodotnet-host` when no other Community Build SDK depends on it.

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
`pacman -Qkk` must verify every file owned by these two packages.
After provisioning dependencies, the driver snapshots that disposable container
and runs the entire build and installed lifecycle with Docker `--network none`.
Only loopback is present, which still permits the local ASP.NET HTTP probe.
`makepkg` verifies its pre-populated, hash-pinned source cache, and the report
records `networkForBuild: none`.

Validation performs actual non-root `makepkg --verifysource`, `.SRCINFO`
generation and package builds; `namcap`; `pacman` ownership/integrity checks;
byte/mode/link comparison against the qualified SDK; branded aliases; a non-root
offline console build/run; ASP.NET loopback HTTP; RSA cryptography and ICU
globalization; independent official .NET SDK coexistence; real revision upgrade,
rollback and removal. It retains the two recipe source trees, a recipe-only
archive, build/lint logs and machine-readable reports as workflow artifacts.
Those artifacts and reports are build evidence, not a publication receipt.

The complete raw `namcap` output is retained. The current official `elfpaths`
rule classifies every ELF under `/opt` as questionable, reporting the summary
`ELF files outside of a valid path ('opt/').` at error severity. The validator
reviews only that exact summary for the SDK binary package because the reviewed
contract requires `/opt/cbodotnet/10.0` isolation. It records the finding and
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
