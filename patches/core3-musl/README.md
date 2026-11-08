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

