# Separate dependencies for .NET 5 and Core 3

The candidate `cbodotnet-compat-rocky9` provider supplies OpenSSL 1.1 and ICU 67
outside the SDK, at `/usr/lib/cbodotnet/compat/rocky9`. It supports the work to
qualify the unchanged SDKs 5.0.214, 3.1.426 and 3.0.103 on the current channel
targets. **Building this provider is not a completed runtime qualification or a
publication claim.** Availability must follow the target-specific native and
public installation evidence.

The [pinned discovery record](../releases/legacy-compatibility-provider.json)
identifies the exact binary RPMs, matching source RPMs, public key, licenses,
ELF machine types, SONAMEs and maximum required GLIBC versions. Both native
architectures were downloaded and inspected without installing host packages.
All six RPMs passed their RSA/SHA-256 signatures and header/payload digests with
the independently pinned Rocky 9 primary fingerprint
`21CB256AE16FC54C6E652949702D426D350D275D`.

| Origin | x64 RPM SHA-256 | AArch64 RPM SHA-256 |
| --- | --- | --- |
| `compat-openssl11` `1:1.1.1k-5.el9_8.6`, AppStream | `d0a9dea703933955dc7872aa20f49841cea408ea5a5eb9546956c55e24a4afad` | `4164cd1cdd7e29bc3f37ed3f4bc0e29fa32716def1fbbbe540014bd49c50738f` |
| `libicu` `67.1-10.el9_6`, BaseOS | `14c314868326269c62498d149399888ce3c819efddaba79d50d2a5ac90c29b87` | `88b6b0b3b903042624beac2e0b904bab80d34b57e6d236f0f885304e54a8af4d` |

Rocky publishes [security updates for its OpenSSL 1.1 compatibility
package](https://errata.rockylinux.org/RLSA-2026:22313), while
[Fedora removed OpenSSL 1.1 from its official repositories starting with
Fedora 40](https://fedoraproject.org/wiki/Changes/RemoveOpensslCompat).
[Rocky 9's supported lifecycle](https://docs.rockylinux.org/releases/) applies
to its current minor release; it does not constitute cross-distribution support
for this project repackaging. The RHEL-compatible package is
[deprecated](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/pdf/9.6_release_notes/distribution).
This provider does not restore upstream .NET or OpenSSL support, or promise
additional security maintenance. New upstream revisions require new reviewed
pins and native verification before release.

The inspected OpenSSL and ICU binaries require at most GLIBC 2.34. That is a
necessary ABI check for the current Ubuntu 24.04, Debian 13, Fedora 45, Rocky
9.8 and Arch targets, rather than proof that their runtime behavior works.
The source RPM build flags also record **`-march=x86-64-v2`** for both x64
packages. This provider raises the legacy x64 CPU requirement to x86-64-v2;
the original SDK's CPU baseline remains unchanged. The launcher and disposable
container preparation require CMPXCHG16B, LAHF/SAHF, POPCNT, SSE3, SSSE3,
SSE4.1 and SSE4.2 on every exposed processor, and reject unknown or insufficient
CPU capabilities before loading these libraries. This follows the
[RHEL 9 CPU baseline](https://developers.redhat.com/blog/2021/01/05/building-red-hat-enterprise-linux-9-for-the-x86-64-v2-microarchitecture-level).
The AArch64 provider retains the ARMv8-A baseline.
Core 3's pinned loader searches through ICU major 75; the provider pins 67
instead of disabling globalization. The existing Ubuntu 22.04 archive test
surface also has GLIBC newer than 2.34. Musl and other operating systems remain
outside this provider policy.

The SDK archive and extracted SDK payload retain their original bytes. The
provider retains the original `libcrypto.so.1.1`, `libssl.so.1.1`,
`libicudata.so.67`, `libicui18n.so.67` and `libicuuc.so.67` binaries and SONAME
links. It includes the OpenSSL/SSLeay and ICU license texts, required attribution,
and exact source-package URLs and hashes. It does not install over stock
OpenSSL, ICU, configuration files or system `dotnet` paths.

The original Rocky `openssl11.cnf` includes a host crypto-policy file. The
separate provider instead supplies an explicitly reviewed scoped configuration
with no external include, minimum TLS 1.2 and OpenSSL security level 2. This is
a project TLS policy, not an assertion that the host distribution's complete
crypto policy is inherited. The OS continues to own and update the CA bundle.

Legacy launchers set `LD_LIBRARY_PATH`, `OPENSSL_CONF`,
`CLR_OPENSSL_VERSION_OVERRIDE=1.1` and the correct current system CA path. Core
3 launchers additionally set `CLR_ICU_VERSION_OVERRIDE=67`. An explicit user
`SSL_CERT_FILE` is preserved. The wrapper records the previous presence and
value of each scoped variable; a subsequently invoked Community Build launcher
restores that caller environment before selecting its own SDK. This avoids
propagating the legacy provider into a modern Community Build child command.
It does not intercept arbitrary external executables started by an application.

Fedora 45 supplies its stock trust bundle at
`/etc/ssl/certs/ca-certificates.crt`. The reviewed distribution contract selects
that path only for the legacy Fedora SDK packages; the immutable provider
policy and companion archives retain their historical fallback paths. Native
RPM and public-install reports bind the selected path, the original stock
bundle hash and its owning `ca-certificates` package version. A non-root,
network-isolated HTTPS probe must use ordinary certificate validation and
TLS 1.2; SDK 5 uses its normal handler, and Core 3 also exercises its forced
native CurlHandler. The probe does not modify the system trust bundle.

The separately signed companion asset is named
`cbodotnet-compat-rocky9-2026.11.4-linux-<architecture>.tar.gz`. It contains
`rootfs/usr/lib/cbodotnet/compat/rocky9/` and `provider-manifest.json`, without
an SDK payload. Relocatable consumer archives can point their wrapper at a
separate extraction using `CBODOTNET_COMPAT_ROOT`. DEB/RPM delivery installs an
independently owned provider package; the SDK package declares that dependency.
The Arch recipe builds only the separate provider package from pinned inputs.
AUR submission remains subject to issue 10.

Preparation uses [`legacy_compat.py`](../scripts/legacy_compat.py):

```bash
python3 scripts/legacy_compat.py --arch aarch64 --variant debian-13 \
  --output /tmp/compat-build --cache /tmp/compat-inputs
python3 scripts/package-sdk.py --inputs /tmp/qualified-sdk \
  --channel deb --variant debian-13 --arch aarch64 --revision 1 \
  --compatibility-build /tmp/compat-build/provider-build.json \
  --output /tmp/sdk-package-build
```

The provider builder verifies the full primary key identity in disposable GPG
and RPM databases, including the binary and matching source RPM signatures,
before reading selected cpio members. It checks file hashes, modes, native
machine type, dynamic dependencies and licenses against the source pins. SDK
packaging consumes an explicit prepared build record and performs no hidden
provider download. The container-only `provision` API installs the separate
package, and `assert_unchanged` checks all installed provider bytes, modes,
links and ownership after the SDK lifecycle transitions.

Before a target is advertised, native x64 and AArch64 probes must prove the
correct aliases and branding, offline build/apphost execution, RSA, HTTPS/TLS
with the selected provider and enabled ICU, plus install, upgrade, rollback and
removal without altering the independent official SDK. Arch has its existing
x64-only delivery scope. Published consumers must also verify the project
signature and artifact hashes and repeat the public installation checks.
