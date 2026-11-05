# cbodotnetup

`cbodotnetup` manages verified Community Build SDKs in a regular user's home.
Initial admission is SDK10.0.403 on Linux glibc x64/AArch64: Ubuntu24.04,
Debian13, Fedora45 and Rocky Linux9.8. It preserves official `dotnet`, official
`dotnetup` state and package-managed `/opt/cbodotnet` installations. NativeAOT
bootstrap does not require an installed .NET SDK.

Version [0.1.0 is published](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/cbodotnetup-v0.1.0).
Both the eight-target native candidate matrix and a second eight-target matrix
using anonymous public binary/SDK downloads passed before
[feed activation](../releases/cbodotnetup-status.json). Use the
[download site](https://dotnetdev.kr/cbodotnet/) for the active signed catalog
and bootstrap. Other SDKs already have package distributions; installer
admission remains individually scoped and initially includes SDK10.0.403 only.

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
it does not silently fetch a withdrawn version. Initial availability has one
SDK/revision; a different rollback target becomes usable only when separately
admitted and installed. Concurrent operations fail with a retry message.

`list --available`, installation, update and self-update obtain a fresh catalog.
`--catalog FILE` uses a local project-signed catalog and adjacent `.asc` with the
same signature/freshness/anti-rollback rules. Offline `run`, installed `list`,
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

## Retained validation

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
