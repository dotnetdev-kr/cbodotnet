These are unpublished source-port candidates for issue #35. They do not qualify a runtime or SDK.

`0001-branch-native-openssl3.patch` applies to the exact CoreFX commits in `profiles/experimental/core3-musl.json`. Build with `FEATURE_DISTRO_AGNOSTIC_SSL=OFF` against the pinned Alpine OpenSSL3 headers/libraries. The OID parsing implementation comes from `CryptoNative_LookupFriendlyNameByOid` in [dotnet/runtime f1dd57165bfd91875761329ac3a8b17f6606ad18](https://github.com/dotnet/runtime/blob/f1dd57165bfd91875761329ac3a8b17f6606ad18/src/libraries/Native/Unix/System.Security.Cryptography.Native/openssl.c). The X509 changes preserve the old managed INVALID_CA value 24 while translating OpenSSL3's value 79 in both directions. This is an API adaptation; it does not provide another SSL library or change a loader/soname.

`0002-clang20-typed-null.patch` makes two existing pointer arguments explicit for modern musl headers and Clang20 template deduction. It changes no CPU feature selection or pointer value.

`0003-preserve-declared-vstest-ui-culture.patch` applies to VSTest `c1b6b2c1ab4c8f181f3cb1a436afb6428009c7ab`. It preserves an explicit neutral UI culture with `GetCultureInfo`, allowing original `zh-Hans`/`zh-Hant` resources to resolve under current ICU. All13 explicit original cultures pass the minimal native consumer; arbitrary regional Chinese fallback remains unqualified. See the [managed source checkpoint](../../docs/core3-musl-source-phase.md).


`0004-coreclr31-clang20-native-compat.patch` applies only to original CoreCLR3.1
`c17d273aa03d4b9d14c92248a91f0d0faa881b98`, after `0002`. It preserves the
original Release/native feature graph while fixing concrete modern compiler
diagnostics and the upstream metadata allocation marker. Existing raw-memory
destinations, one-bit register encoding and unsigned enum storage retain their
original byte/ABI behavior. The GNU C++ VLA compatibility diagnostic stays
visible. The tracked [native probe](../../scripts/core3-musl-native-probe.py)
builds six original targets and separately tests real R2R and managed LTTng
events. These diagnostic consumers overlay original host/managed runtime
inputs; complete SDK/source/license and two-CPU admission remain closed.

The original .NET Foundation MIT licenses/notices remain in the complete CoreFX/CoreCLR/runtime donor archives. The investigation helper retains and hashes every notice in those archives. Keep those source archives with generated source, patch receipts, native artifacts and probe logs. No clean-bootstrap, extra security maintenance, Microsoft support, or release qualification is claimed.

`0005-cli31-community-branding.patch` applies to CLI
`cca488d5d530e6ec291134abe3462fed613a4429`. It compiles branding from29 original
source/resource files, preserves numeric version stdout and original13-culture
welcome translations, and prints version branding on stderr. Original version
targets generate the dated assembly/package identities; no PE is restamped.

`0006-fsharp31-spanish-format-placeholder.patch` applies to F#
`3ef6f0b514198c0bfa6c2c09fefe41a740b024d5` after its four original source-build
patches. It corrects only a malformed Spanish format placeholder while keeping
the translated sentence. Strict original localized Release builds and actual
FSC/FSI messages pass for all13 cultures. The [source preparation helper](../../scripts/core3_musl_community_sources.py)
checks exact input/patch/file hashes and leaves original global SDK pins intact.
These additions do not close the private archive's imported source/license or
native two-CPU release gates.


`0007`–`0010` target exact CoreCLR3.0
`259ce7d4619478cfefe7b0c0f6fa765f765f7e37`, after0002 and0004. Those two common
patches are now separately checked/built on3.0; this does not inherit3.1 proof.
0007 backports the five upstream f86caa alignment/aliasing statements.0008
makes one existing raw memset destination explicit.0009 backports the original
3.1 common-symbol CMake default, and0010 backports its three DAC pointer
wrappers. Public patch bytes equal the private patches used in the actual
six-target LLVM20 Release build, including original upstream whitespace.
The [separate3.0 profile](../../profiles/experimental/core30-musl-native.json)
and [native checkpoint](../../docs/core3-musl-source-phase.md) retain concrete
before/after controls, default-trust certificate tests, source crossgen and
actual GC LTTng evidence. Original host/managed framework inputs are explicit
diagnostic overlays; a complete source SDK and native two-CPU release producer
remain unqualified.
