# Separate Core 3 native HTTP dependency

The Core 3.0.103 and 3.1.426 SDKs retain their original
`System.Net.Http.Native.so` files. Those files require the `CURL_OPENSSL_3`
symbol namespace from `libcurl.so.4`. A current stock library can have the same
SONAME while lacking that namespace. Installing a package named libcurl alone
does not prove that this native handler can load.

Core 3 can select CurlHandler instead of its default SocketsHttpHandler.
[Microsoft documents the native handlers' removal in .NET 5](https://devblogs.microsoft.com/dotnet/net-5-new-networking-improvements/).
Default HTTP tests therefore cannot replace an explicit Core 3 CurlHandler
test. The [original ELF diagnostic](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41876635671)
retains the exact source components, required symbol versions and failing stock
loader output. This work is tracked in [issue 23](https://github.com/dotnetdev-kr/cbodotnet/issues/23).

## Candidate provider

The separately owned `cbodotnet-compat-curl-rocky8` candidate uses unchanged,
vendor-signed Rocky 8 `libcurl-minimal` **7.61.1-34.el8_10.18** bytes. The
[pinned policy](../releases/legacy-curl-provider.json) records both binary RPMs,
their source RPM, full SHA-256 values, public key, MIT license, ELF properties
and the four exact original SDK native-HTTP component hashes. Original curl
copyright and permission text accompany the library.

The original RPM signing identity is
`7051C470A929F454CEBE37B715AF5DAC6D745A60`. The source packages are authenticated
in an isolated database containing only that pinned vendor key. The vendor's
[security update](https://errata.rockylinux.org/RLSA-2026:92368) describes this
revision. Project DEB/RPM packages, companions and publication manifests use the
separate approved project distribution signing identity.

The candidate has unversioned curl exports and uses OpenSSL 1.1. Its existing
[SSL/ICU companion](legacy-compatibility-provider.md) supplies the exact private
OpenSSL 1.1 implementation. A Rocky 9 curl candidate using OpenSSL 3 failed the
real Core 3 custom-certificate path and was rejected. The successful candidate's
HTTP, callback HTTPS, ordinary certificate trust and TLS 1.2 paths passed the
[initial dual-native Debian 13 probe](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41881478644).
That probe establishes feasibility, not a completed package/channel rollout.

The [libcurl ABI policy](https://curl.se/libcurl/abi.html) explains its SONAME
compatibility boundary. Native functional evidence remains mandatory: neither
an unchanged SONAME nor the absence of versioned exports proves all runtime
behavior. The library's measured GLIBC requirement is at most 2.17; the complete
Core 3 installation still inherits the separate SSL/ICU provider's GLIBC 2.34
and x64-v2 requirements.

## Installation boundary

The package owns `/usr/lib/cbodotnet/compat/curl-rocky8` independently of the SDK
and the SSL/ICU provider. It depends on the exact reviewed base-provider version
and stock nghttp2, Kerberos and compression libraries. It does not replace the
system libcurl, OpenSSL, CA bundle or official dotnet files.

Only Core 3 launchers prepend this private curl directory after saving the
caller's environment. Selecting another Community SDK restores that caller
environment. The default HTTP handler is unchanged. The SDK 5 provider policy,
wrapper bytes and archive metadata remain unchanged.

Core 3 consumer archives require two separate authenticated companions: the
existing SSL/ICU companion and
`cbodotnet-compat-curl-rocky8-2026.11.4-linux-<architecture>.tar.gz`. A caller can
select a separately extracted curl root with `CBODOTNET_CURL_COMPAT_ROOT`.
The signed consumer manifest must bind both assets; the curl root is outside
`payload/`. See the [consumer archive instructions](consumer-archives.md).

Before a target becomes available, native package/image/archive tests must
verify both managed inventories and source pins, actual loaded-library paths,
non-root offline forced CurlHandler HTTP and HTTPS, an exercised certificate
callback, normal CA trust with no callback, and TLS 1.2. Install, upgrade,
rollback, removal, official-dotnet coexistence and all-eight selector tests also
apply. Public installation repeats the mandatory provider and native-handler
checks against the signed released bytes.

The library is a project repackaging of maintained vendor inputs. It does not
restore upstream .NET Core support or promise additional security maintenance.
New vendor revisions require reviewed pins and fresh native evidence. AUR
submission remains deferred under [issue 10](https://github.com/dotnetdev-kr/cbodotnet/issues/10).
