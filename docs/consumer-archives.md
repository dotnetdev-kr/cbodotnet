# Consumer SDK archives

Consumer archives provide the Community Build command interface around an
unchanged, qualified SDK. Each version has its own immutable
`distribution-archive-sdk-V-rN` release, separate from the original `sdk-V`
producer release. A consumer release is available only after its signed complete
matrix and both native public installation reports have passed. Source admission
or a successful local build alone does not advertise an archive as available.

The admitted source versions are 3.0.103, 3.1.426, 5.0.214, 6.0.136, 7.0.120,
8.0.133, 9.0.123 and 10.0.403, each for `x64` and `aarch64`. Admission is recorded
in the [distribution contract](../releases/distribution-contract.json); it does
not restore upstream support for older .NET releases or qualify another OS.
The [installation website](https://dotnetdev.kr/cbodotnet/) is the source of
verified consumer download choices.

## Layout and commands

New archive plans use `archiveNamingVersion: 2` and the filename
`cbodotnet-sdk-V-linux-ARCH-rN.tar.gz`. For example, the 10.0.403 x64 revision 3
release is named `cbodotnet-sdk-10.0.403-linux-x64-r3.tar.gz`. Its complete native
and public qualification is recorded in the
[archive and website audit](neutral-archive-validation.json). Extracting it creates:

```text
cbodotnet-10.0.403-linux-x64-r3/
  cbodotnet
  cbodotnet-10.0
  dotnet
  distribution.json
  README.txt
  LICENSE.wrapper.txt
  payload/
    dotnet
    host/
    sdk/
    shared/
    LICENSE.txt
    ThirdPartyNotices.txt
```

Run `./cbodotnet`, `./cbodotnet-10.0` or `./dotnet` from the extracted directory.
All three pin the archive's SDK root, retain numeric `--version` stdout, and
print `Community Build of .NET (built by .NET Dev)` on stderr for that option.
`--info` includes branding; `--cbodotnet-info` reports the exact SDK version,
revision, architecture, source manifest pin and actual relocated payload root.
The directory can be moved, including to a path containing spaces, without
rewriting its SDK or launchers. Explicit PATH selection and launcher symlinks
are supported; shell startup files and system alternatives are not modified.

The internal `payload/dotnet` keeps its original filename and bytes. Renaming it
would disrupt the host's SDK/runtime layout. The consumer entrypoints set
`DOTNET_ROOT`, the architecture-specific root and `DOTNET_HOST_PATH`, and execute
that explicit host. The
[.NET environment-variable reference](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-environment-variables)
describes host and apphost root selection. For a compiled apphost invoked
directly, set `DOTNET_ROOT` to the absolute `payload/` directory. The archive
root itself contains wrappers and is not the runtime root. Legacy apphosts also
need their complete native-provider environment; setting `DOTNET_ROOT` alone
does not supply OpenSSL, ICU or Core3 curl. The wrapper sets that environment
for CLI-launched applications.

Original file bytes, modes and links are compared with the qualified SDK during
protected promotion. Only an explicitly admitted empty metadata directory may
be added when the source SDK lacks it. Original notices remain under `payload/`;
the wrapper license does not replace the licenses of SDK components. Archive
layout 2 separately includes `LICENSE.wrapper.txt`, the exact project's MIT
copyright and permission notice, checked before and after native execution.
Archive naming version 2 changes the external filename, while archive layout 2
and the SDK payload preservation rules remain in effect. Historical plans
without `archiveNamingVersion` use naming version 1 and retain their original
`-branded-rN.tar.gz` filenames. Their public URLs, signed manifests, native
reports, asset identities and hashes remain unchanged. A new packaging revision
supersedes an earlier release only after its own complete native/public validation.

## Separate legacy compatibility companion

SDK 3.0, 3.1 and 5.0 require the separately distributed
`cbodotnet-compat-rocky9` companion described in the
[provider policy](legacy-compatibility-provider.md). It contains exact pinned
Rocky-maintained OpenSSL 1.1 and ICU 67 library bytes, original licenses and
source-package references. It is a project repackaging rather than a
Rocky-supported cross-distribution product. It is never inserted into the SDK
payload and does not replace system OpenSSL or ICU.

Each required native companion is a separate asset, such as
`cbodotnet-compat-rocky9-2026.11.4-linux-aarch64.tar.gz`, in the signed consumer
publication. Extract it into a separate prefix. Its root is
`rootfs/usr/lib/cbodotnet/compat/rocky9` below that prefix; select it for one
command with an absolute path:

```sh
CBODOTNET_COMPAT_ROOT=/absolute/companion/rootfs/usr/lib/cbodotnet/compat/rocky9 \
  /absolute/cbodotnet-5.0.214-linux-aarch64-r2/cbodotnet --info
```

Alternatively, an independently installed project compatibility package owns
the managed default `/usr/lib/cbodotnet/compat/rocky9`. Required SDK launchers fail
with a clear message if the companion is missing. Their compatibility variables
are scoped to the selected SDK process; selecting another Community SDK restores
the original caller environment. The admitted user spaces are recorded per
archive revision. The compatibility libraries' GLIBC requirement is independent
of the original SDK's recorded minimum.

Core 3.0 and 3.1 additionally contain an optional native `CurlHandler` whose
`System.Net.Http.Native.so` requires the older Curl/OpenSSL interface. A modern
stock `libcurl.so.4` alone does not qualify that interface. Core3 therefore
requires a second, separate `cbodotnet-compat-curl-rocky8` companion under the
[native HTTP provider policy](../releases/legacy-curl-provider.json), containing
exact pinned maintained Rocky Linux 8 curl bytes and its original copyright
and permission notice. It depends on the unchanged SSL/ICU companion; SDK5 does
not use this addon. Candidate policy and build output remain unavailable until
their complete native and public qualification passes.

For a qualified Core3 release, authenticate both companions before extraction.
The second archive is named
`cbodotnet-compat-curl-rocky8-2026.11.4-linux-aarch64.tar.gz`. Select separate
absolute roots for one command:

```sh
CBODOTNET_COMPAT_ROOT=/absolute/base/rootfs/usr/lib/cbodotnet/compat/rocky9 \
CBODOTNET_CURL_COMPAT_ROOT=/absolute/http/rootfs/usr/lib/cbodotnet/compat/curl-rocky8 \
  /absolute/cbodotnet-3.1.426-linux-aarch64-r3/cbodotnet --info
```

Core3 revision3 plans use `archiveLauncherVersion: 2`. These launchers activate
both verified companions from the two root variables, including when the caller
has no preconfigured loader environment. They verify the closed provider tree,
component hashes, configuration and notices before executing the SDK. Required
provider roots must be ordinary absolute paths without symlinked ancestors,
control characters, `:`, `;` or `$`; spaces are supported. An invalid, missing
or substituted provider fails before the payload host starts. These internal
checks supplement verification against the signed publication manifest; they
do not authenticate an unverified downloaded wrapper.

The managed default for the second package is
`/usr/lib/cbodotnet/compat/curl-rocky8`. Neither companion enters `payload/` or
replaces system libraries. Core3 launchers scope the private Curl root before
the private SSL/ICU root, followed by the caller's original library path. An
unset `SSL_CERT_FILE` selects the readable stock CA bundle at
`/etc/ssl/certs/ca-certificates.crt` or `/etc/pki/tls/certs/ca-bundle.crt`.
Explicit empty or custom certificate settings are retained. A nested modern
Community SDK restores the original caller's unset, empty or custom scoped
values rather than retaining a legacy library path.

Native preparation installs the reviewed stock
transitive dependencies through authenticated OS repositories before networking
is disabled. Validation additionally forces the actual native CurlHandler and
checks HTTP, callback HTTPS, ordinary certificate trust and TLS 1.2, with exact
native HTTP/Curl hashes and loaded-library paths. Missing either provider or
failed native HTTP evidence blocks qualification.

The revision3 qualification matrix includes Ubuntu22.04, Ubuntu24.04,
Debian13, Fedora45 and Rocky9.8 on native x64/AArch64 for both Core3 SDKs:
20 cells in each candidate/public phase. Ubuntu22.04 remains a regression
target alongside the four newer distribution targets. Provider requirements
remain glibc>=2.34 and x86-64-v2 on x64; these glibc companions do not establish
Alpine/musl support.

Historical revision2 wrappers activated only the SSL/ICU base. The earlier
runtime tests supplied curl through their outer environment, which left the
root-variable-only scenario untested. [Issue #31](https://github.com/dotnetdev-kr/cbodotnet/issues/31)
tracks the correction and comparison against actual signed r2 inputs. Original
r2 archives, signatures and reports retain their bytes and recorded test
preconditions. The independent `cbodotnetup` 0.4.0 installer already constructs
its complete private child environment and keeps its separately qualified r2
SDK/provider pins; archive publication does not change those pins.

## Authentication and immutable publication

Confirm the full project fingerprint through a trusted project-owner channel:
`D7D154B4B33C19A82B95B13688135410ACD9C0EA`. The
[signing policy](distribution-signing.md) records its ownership and validity.
Verify `distribution-manifest.json.asc` with that pinned public identity, then
verify the exact size and SHA-256 of the selected archive and any required
companion against the signed manifest. The original release manifest and
`source-SHA256SUMS` are retained as signed assets and bind the public SDK, used
source archives, qualification evidence and original native producers.

The new manifest also binds both consumer archive hashes, generated command
inventories and signed native installation reports. The private signing key is
available only to the existing protected main distribution workflow. Complete
signed bundles are uploaded as frozen recovery artifacts before any public
release write; recovery reuses those exact bytes and signatures. Existing tags
or public assets are never overwritten. Public-byte verification alone remains
pending consumer availability until both native public installation jobs pass.

The original eight `sdk-*` releases remain immutable producer inputs. Their
titles and bodies identify the unbranded archives as experimental and not
recommended for direct installation. Their tags, stable-release flags,
manifests, source archives, evidence and SDK bytes stay unchanged.

`cbodotnetup` has independent revision admission in the
[installer policy](../releases/cbodotnetup-policy.json), including scheduled
catalog renewal. The 0.4.0 tool retains the Core3 r2 SDK/provider inputs and
supplies its own complete scoped child environment. Its signed historical
schema1 feed still admits SDK10.0.403 r2 for actual 0.1.0 clients and their
verified upgrade path. Publishing a new archive revision does not automatically
change installer admission or invalidate existing installations.

## Repeatable native checks

The read-only entrypoint is:

```sh
python3 scripts/consumer-archive-ci.py native \
  --tag sdk-10.0.403 --revision 3 --arch x64 --workspace /fresh/workspace
```

Run it as the matching native non-root GitHub Actions producer in
[the distribution workflow](../.github/workflows/distribution-release.yml).
It receives the exact qualified archive, builds the consumer archive, and tests
all three aliases before and after relocation in each admitted OS container.
After dependency preparation, Docker `--network none` is mandatory. A non-root
user restores without external package feeds, builds and executes DLL and
apphost forms, and exercises loopback HTTP/TLS 1.2, RSA, cryptographic randomness
and ICU formatting. SDK and compatibility-provider inventories must remain
unchanged. Small raw reports are retained separately from the native transport.

Protected promotion rechecks source pins, the qualified producer catalog,
original payload inventories and exact reviewed wrapper bytes. It requires
both complete native reports and every admitted user space. Missing evidence,
another source identity or an unexpected compatibility artifact blocks signing
and publication.

Launcher contract2 also authenticates and retains the actual r2 comparison
archive. The same forced-Curl HTTPS program must fail through its clean-caller
r2 wrapper and pass through r3. Runtime checks then select the retained physical
revisions in order r2→r3→r2→r3, extract r3 afresh, compare every installed
byte/mode/link, and remove the owned SDK roots and selector. Provider trees,
stock dependencies, package inventory/database and deliberately created
unrelated user files retain their before/after state. Reports record the actual
presence or absence of protected global dotnet paths and identify this as an
archive lifecycle gate. Actual official-package installation/coexistence has
separate [APT](apt-delivery.md) and [RPM](rpm-delivery.md) qualification.

## Core3 revision3 validation

Together, [Core3.1.426 r3](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-archive-sdk-3.1.426-r3)
and [Core3.0.103 r3](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-archive-sdk-3.0.103-r3)
passed all 20 SDK/OS/CPU cells in each candidate and anonymous public phase.
The [independent validation record](core3-archive-curl-validation.json) binds
actual source/run/job identities, original report ZIPs, exact SDK payload and
wrapper inventories, reviewed official image indexes and 12 project signatures.
It independently verifies all 30 new public assets and preservation of the
79 earlier releases and 1,046 earlier assets. The homepage's four new Core3
archive links passed live verification after the final Pages deployment.

Source CI ran 893 Python tests: 889 passed and four were skipped. The existing
installer feeds and policies, package/OCI availability and legacy provider
policies retain their exact bytes. The latest SDK download remains SDK10 r3.
