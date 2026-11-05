# Historical preparation for the seven additional SDKs

This document and its JSON are the original planning snapshot. Current
production admission and published revisions are recorded in the
[verified delivery matrix](all-sdk-distributions.md) and signed status receipts.
The pending and blocked descriptions below describe the audit's original state.

This 2026-11-04 audit prepares SDKs **9.0.123, 8.0.133, 7.0.120, 6.0.136,
5.0.214, 3.1.426 and 3.0.103** for the existing Linux distribution channels.
The [machine-readable preparation record](../releases/additional-sdk-preparation.json)
contains seven source records, fourteen exact producer bindings, forty-two
previous archive observations and **77 proposed channel/OS/architecture rows**.
It does not admit releases to the production contract, execute a package build,
qualify a target or publish additional SDKs. At the time of this audit,
production admission was limited to SDK 10.0.403.
Registered follow-up work is tracked by
[epic 12](https://github.com/dotnetdev-kr/cbodotnet/issues/12).

The audit downloaded the small public release manifests and `SHA256SUMS`, checked
their byte lengths and SHA-256 against the public GitHub release asset API,
matched SDK/source/evidence descriptors to those manifests and API records, and
compared both producer identities with
[qualified-builds.json](../releases/qualified-builds.json). It did not redownload
the large SDK/source/evidence archives or execute their SDKs. Runtime and ABI
observations below come from the existing
[AArch64 qualification records](ci-matrix-results.md) and
[x64 qualification records](ci-x64-results.md), not a new compatibility run.
Local profile and distribution-contract JSON hashes use Git's LF text form,
accepting equivalent Windows CRLF checkouts. Public manifest and archive hashes
continue to bind their exact original bytes.

## Exact inputs and preserved source origins

The JSON records every public SDK/source/evidence filename, byte length, digest,
asset ID and URL; source repository/commit; original producer commit, run,
attempt and artifact ID; and the profiles used for preparation. Each public
manifest SHA below was checked against its downloaded bytes.

| SDK / runtime | Source construction | Public release manifest SHA-256 |
| --- | --- | --- |
| 9.0.123 / 9.0.22 [#16](https://github.com/dotnetdev-kr/cbodotnet/issues/16) | Ordinary VMR; local core runtime, consumed upstream ASP.NET archive | `d7d68c0e8aedeb0b261f9d22dfc1aec73bc359919835caa16d7df70dc9238be9` |
| 8.0.133 / 8.0.33 [#17](https://github.com/dotnetdev-kr/cbodotnet/issues/17) | VMR source-build; both local shared frameworks | `6df02b36738250943cc4ae3ee32f6da4ec1c37a56fa6b248c08aeddff7760f6c` |
| 7.0.120 / 7.0.20 [#18](https://github.com/dotnetdev-kr/cbodotnet/issues/18) | Installer-generated source-build; both local shared frameworks | `b82e5c10814606e50f3682f0787452362cc6d82ee01ed0f652691a98f98e2e30` |
| 6.0.136 / 6.0.36 [#19](https://github.com/dotnetdev-kr/cbodotnet/issues/19) | Installer-generated source-build; both local shared frameworks | `5e9404de6bde02aed938951182da03380ae37f7b506a8fbf46a186d4bca484fd` |
| 5.0.214 / 5.0.17 [#20](https://github.com/dotnetdev-kr/cbodotnet/issues/20) | Direct source-build at the pinned `release/5.0` commit | `2a98666b057b5e8c2c8ef149c5ebca7528c2048d7cc1aa38611d48d0d104c67f` |
| 3.1.426 / 3.1.32 [#21](https://github.com/dotnetdev-kr/cbodotnet/issues/21) | Direct source-build at the pinned `release/3.1` commit | `70049972a8781c309fae40e5f68d74847d0a9a590d36de4f25ecc2ad50578b09` |
| 3.0.103 / 3.0.3 [#22](https://github.com/dotnetdev-kr/cbodotnet/issues/22) | Direct source-build, corrected `v3.0.103.1-SDK` source tag | `3bac912a788bf38320cb45bfe6a62b3da0dbcaf50bb564a370ae7c5a09fb5e98` |

The corrected Core 3.0 source tag still produces **SDK 3.0.103**, not SDK
3.0.103.1. SDK 5.0.214 and Core 3.1.426 have exact branch commits rather than
invented release tags. Keep the existing bootstrap/prebuilt disclosures,
framework origins, original suite skips and comparison gaps. Packaging does not
establish Stage 2, a clean bootstrap, zero prebuilt use or equality with every
Microsoft SDK payload.

## ABI observations and native dependency gaps

These are maximum required symbol versions observed in regular ELF files in the
exact qualified SDK archives. A compatible glibc version alone does not prove
OpenSSL loading, ICU loading, optional diagnostics, package installation or OCI
execution. External compatibility libraries have their own ABI requirements.

| SDK | x64 GLIBC maximum | AArch64 GLIBC maximum | GLIBCXX maximum | CXXABI maximum |
| --- | --- | --- | --- | --- |
| 9.0.123 | 2.17 | 2.17 | 3.4.21 | 1.3.7 |
| 8.0.133 | 2.17 | 2.17 | 3.4.21 | 1.3.7 |
| 7.0.120 | 2.17 | 2.17 | 3.4.21 | 1.3.7 |
| 6.0.136 | 2.16 | 2.17 | 3.4.21 | 1.3.7 |
| 5.0.214 | 2.16 | 2.17 | 3.4.21 | 1.3.7 |
| 3.1.426 | 2.14 | 2.17 | 3.4.21 | 1.3.7 |
| 3.0.103 | 2.14 | 2.17 | 3.4.21 | 1.3.7 |

SDKs 9/8/7/6 already passed the six archive-level functional checks in Ubuntu
22.04, Ubuntu 24.04 and Debian 13 on both native architectures with stock
libraries. None of those results is a DEB/RPM/AUR installation or consumer OCI
qualification. Fedora 45, Rocky 9.8 and Arch rolling still need actual native
runtime observations for every additional SDK.

The existing .NET 10 package dependency names are recorded only as candidate
provider names in the JSON. For Fedora 45 the reference provider is
[`openssl3-libs`](https://packages.fedoraproject.org/pkgs/openssl3/openssl3-libs/fedora-45-updates.html);
the distribution's default OpenSSL 4 already failed .NET 10's installed runtime
probe. This does not prove that any additional SDK accepts either library set.
Check the pinned loader, resolve actual package versions and execute crypto/HTTP
before making a compatibility claim.

SDK 5 and Core 3 archive checks used separately recorded Focal OpenSSL 1.1
libraries/configuration on all three user spaces. Core 3 additionally used ICU
66 on Debian 13; Ubuntu 24.04 used stock ICU 74. The pinned Core 3 loader searches
only through ICU major 75. Debian's
[`libicu76`](https://packages.debian.org/trixie/libicu76), Fedora's
[`libicu` 78](https://packages.fedoraproject.org/pkgs/icu/libicu/fedora-45.html)
and [Arch's ICU 78](https://archlinux.org/packages/core/x86_64/icu/) therefore
create an explicit compatibility-provider gate for Core 3. This is an inference
from the recorded loader limit and provider majors, not a newly executed failure
on Fedora or Arch. Rocky's recorded ICU 67 is within that search range, but its
Core 3 execution and OpenSSL provider still remain untested.

No OpenSSL 1.1 or compatible ICU package is approved by this preparation. The
historical verification mount is not a production dependency solution. A
follow-up must record provider source, license, package/signature/hash, ABI,
configuration, search path, availability on each architecture and maintenance
scope. Keep compatibility libraries separate from unchanged SDK payloads and
leave targets blocked if no reviewed distributable provider exists. OpenSSL
1.1.1's public support ended in 2023; its
[upstream notice](https://openssl-library.org/post/2023-06-15-1.1.1-eol-reminder/)
requires third-party maintenance expectations to be checked separately.

## Proposed channel matrix

Every row below expands to x64 and AArch64 except Arch/AUR, which is x64 only.
There are four APT, four RPM, two OCI and one AUR row per SDK: 77 total.
Ubuntu 22.04 archive observations remain evidence references outside this
proposed installation matrix. AUR publication remains separately tracked by
[issue 10](https://github.com/dotnetdev-kr/cbodotnet/issues/10).

`A` means an existing archive pass with stock libraries and **pending native
channel qualification**. `U` means unknown runtime behavior on that distribution
and pending channel qualification. `L` means blocked pending an external
OpenSSL 1.1 provider; `L+I` adds the Core 3 ICU provider gate. All 77 rows currently
have `qualification: not-qualified` and `published: false`.

| SDK | APT Ubuntu 24.04 | APT Debian 13 | RPM Fedora 45 | RPM Rocky 9.8 | OCI Debian 13 | AUR Arch rolling x64 |
| --- | --- | --- | --- | --- | --- | --- |
| 9.0.123 | A | A | U | U | A | U |
| 8.0.133 | A | A | U | U | A | U |
| 7.0.120 | A | A | U | U | A | U |
| 6.0.136 | A | A | U | U | A | U |
| 5.0.214 | L | L | L | L | L | L |
| 3.1.426 | L | L+I | L+I | L | L+I | L+I |
| 3.0.103 | L | L+I | L+I | L | L+I | L+I |

## Work waves and registered issues

The read-only [preparation CLI](../scripts/prepare-additional-sdks.py) validates
the complete record before filtering it. It independently pins the seven
audited public manifest hashes, reconstructs their preserved JSON bytes, checks
their assets/producers against the record and qualified catalog, and rejects
missing/duplicate/unsupported targets or qualification/publication flags.
The resulting plans use a distinct inert planning schema; actual package builds
still require production admission and `verified_plan` with the real SDK bytes.

```bash
python3 scripts/prepare-additional-sdks.py --output /tmp/additional-sdk-plans.json
python3 scripts/prepare-additional-sdks.py --sdk 8.0.133 --channel oci \
  --variant debian-13 --arch aarch64 --output /tmp/net8-debian13-arm-preparation.json
```

Output files must be new. The first command prepares all 77 rows locally with
`status: prepared-unqualified`, `execution: not-run`, and build/publication
permissions false. Neither command downloads archives, installs packages,
changes the production contract or publishes a release.

The JSON retains the initial work descriptions in `waveDrafts` and one
`issueDraft` per SDK, now linked to their registered issue numbers and URLs,
with stable keys, dependencies and acceptance criteria. Registration does not
mean that native qualification or SDK publication has started.

1. **Wave 0: shared admission and verifier preparation, [#13](https://github.com/dotnetdev-kr/cbodotnet/issues/13).** Review each exact
   manifest and both producers, then explicitly parameterize the current
   .NET-10-only smoke framework, root/alias expectations and OCI image checks.
   The current DEB/OCI and AUR probes compile `net10.0`; RPM verification also
   supplies `--framework net10.0`. Merely passing an older release tag to those
   drivers would not prove the intended SDK. Preserve the independently pinned
   official 10.0.100 comparison or another reviewed comparison SDK, family-specific
   host RID behavior and the existing qualified ABI ceilings. Do not run
   unchanged drivers and interpret their failure as an SDK compatibility result.
2. **Wave 1: 9.0.123, 8.0.133, 7.0.120, then 6.0.136.** Begin with the existing
   stock-library Ubuntu/Debian archive evidence, perform real APT installs and
   Debian OCI execution, then independently qualify both RPM distributions and
   Arch. Issues [#16](https://github.com/dotnetdev-kr/cbodotnet/issues/16),
   [#17](https://github.com/dotnetdev-kr/cbodotnet/issues/17),
   [#18](https://github.com/dotnetdev-kr/cbodotnet/issues/18) and
   [#19](https://github.com/dotnetdev-kr/cbodotnet/issues/19) cover the respective
   eleven-row SDK matrices. Shared provider names and
   glibc ceilings do not complete the new targets.
3. **Wave 2: 5.0.214, [#20](https://github.com/dotnetdev-kr/cbodotnet/issues/20).** Resolve the OpenSSL 1.1 provider policy
   [#14](https://github.com/dotnetdev-kr/cbodotnet/issues/14) first, then execute
   the admitted channel matrix. Its recorded ICU search range is 50 through 85;
   that is a loader observation, not an ICU 78 functional qualification.
4. **Wave 3: 3.1.426 [#21](https://github.com/dotnetdev-kr/cbodotnet/issues/21), then 3.0.103 [#22](https://github.com/dotnetdev-kr/cbodotnet/issues/22).** Reuse the reviewed external-crypto policy,
   resolve the additional ICU gate [#15](https://github.com/dotnetdev-kr/cbodotnet/issues/15)
   and qualify each selected target. Preserve
   the corrected Core 3.0 source tag and exact version-specific legacy evidence.

Each admitted channel target needs source and payload integrity; actual native
dependency providers; all intended aliases and compatible numeric version
stdout; branded information; non-root offline console/DLL/apphost execution;
HTTP, RSA and ICU checks; SDK-version coexistence with .NET 10 and official
`dotnet`; package upgrade/rollback/removal or immutable OCI digest proof; trusted
report/package/repository signatures; and anonymous post-publication and hosted
HTTPS verification. Test the highest-series `cbodotnet` selector and exact
versioned launchers when several series coexist. Preserve shared host ownership
when removing one SDK. Do not extend x64-only AUR or glibc evidence to ARM AUR or
musl.

The [upstream support policy](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core)
currently ends .NET 8/9 maintenance on 2026-11-10 and lists 7/6/5/Core 3 as out of
support. The community build and compatibility qualification do not extend
Microsoft's lifecycle or promise additional security maintenance. Record that
scope in the eventual package/CLI metadata for each selected version.
