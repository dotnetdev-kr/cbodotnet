# Verified SDK distributions

The table tracks the activated, signed and publicly post-verified distribution
revisions for each exact SDK. All eight current archive releases use neutral
filenames and have passed both native public installation jobs. The
[archive status](../releases/archive-status.json) records their availability.
The underlying SDK bytes, modes, links and original notices remain unchanged.
Packaging adds Community Build launchers and provenance.

APT covers Ubuntu 24.04 and Debian 13 on x64/AArch64; RPM covers Fedora 45 and
Rocky Linux 9.8 on x64/AArch64. OCI uses Debian 13 on linux/amd64 and linux/arm64.
Archives are natively tested in Ubuntu 22.04, Ubuntu 24.04 and Debian 13.
Arch recipes are built and tested on x86_64; AUR publication remains
[issue #10](https://github.com/dotnetdev-kr/cbodotnet/issues/10).

| SDK | SDK archive | APT | RPM | OCI | Arch native build |
| --- | --- | --- | --- | --- | --- |
| 10.0.403 | [r3](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-archive-sdk-10.0.403-r3) | [r3](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-deb-sdk-10.0.403-r3) | [r2](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-rpm-sdk-10.0.403-r2) | [r3](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-oci-sdk-10.0.403-r3) | [Passed](aur-all-sdk-validation.json) |
| 9.0.123 | [r2](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-archive-sdk-9.0.123-r2) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-deb-sdk-9.0.123-r1) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-rpm-sdk-9.0.123-r1) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-oci-sdk-9.0.123-r1) | [Passed](aur-all-sdk-validation.json) |
| 8.0.133 | [r2](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-archive-sdk-8.0.133-r2) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-deb-sdk-8.0.133-r1) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-rpm-sdk-8.0.133-r1) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-oci-sdk-8.0.133-r1) | [Passed](aur-all-sdk-validation.json) |
| 7.0.120 | [r2](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-archive-sdk-7.0.120-r2) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-deb-sdk-7.0.120-r1) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-rpm-sdk-7.0.120-r1) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-oci-sdk-7.0.120-r1) | [Passed](aur-all-sdk-validation.json) |
| 6.0.136 | [r2](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-archive-sdk-6.0.136-r2) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-deb-sdk-6.0.136-r1) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-rpm-sdk-6.0.136-r1) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-oci-sdk-6.0.136-r1) | [Passed](aur-all-sdk-validation.json) |
| 5.0.214 | [r2](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-archive-sdk-5.0.214-r2) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-deb-sdk-5.0.214-r1) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-rpm-sdk-5.0.214-r1) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-oci-sdk-5.0.214-r1) | [Passed](aur-all-sdk-validation.json) |
| 3.1.426 | [r2](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-archive-sdk-3.1.426-r2) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-deb-sdk-3.1.426-r1) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-rpm-sdk-3.1.426-r1) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-oci-sdk-3.1.426-r1) | [Passed](aur-all-sdk-validation.json) |
| 3.0.103 | [r2](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-archive-sdk-3.0.103-r2) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-deb-sdk-3.0.103-r1) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-rpm-sdk-3.0.103-r1) | [r1](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-oci-sdk-3.0.103-r1) | [Passed](aur-all-sdk-validation.json) |

Published channel coverage is **32/32**. The current receipts and exact source pins are in
[package/OCI status](../releases/downstream-status.json),
[archive status](../releases/archive-status.json) and the
[distribution contract](../releases/distribution-contract.json). Use the
[download site](https://dotnetdev.kr/cbodotnet/) for authenticated commands.

The new archives use `archiveNamingVersion: 2` and filenames such as
`cbodotnet-sdk-10.0.403-linux-x64-r3.tar.gz`. Previously signed archives keep
their original `-branded-` names, asset bytes, URLs and qualification evidence.
`cbodotnetup` 0.1.0 deliberately remains on the separately qualified signed
SDK10.0.403 archive r2 through the explicit `archiveRevisions` entry in its
[policy](../releases/cbodotnetup-policy.json); archive publication does not
automatically expand installer admission.

Installed commands are `cbodotnet-X.Y` and `cbodotnet`; the common command
selects the highest installed Community SDK series. OCI and archive-local
wrappers additionally expose `dotnet`. System package delivery preserves the
official `dotnet` command and its package ownership. All wrappers display
**Community Build of .NET (built by .NET Dev)**; numeric `--version` stdout
remains unchanged.

## Installation and dependencies

- [APT installation, retention and removal](apt-delivery.md)
- [RPM installation and rollback](rpm-delivery.md)
- [OCI digest pulls and non-root execution](oci-delivery.md)
- [Relocatable SDK archives and separate companions](consumer-archives.md)
- [Arch recipe lifecycle and all-eight coexistence](aur-delivery.md)

SDK 5 and Core 3 require the separately packaged
[Rocky 9 OpenSSL/ICU provider](legacy-compatibility-provider.md). Its complete
installation requires glibc 2.34, and x64 requires x86-64-v2. Core 3 also
requires the separate [Rocky 8 native HTTP provider](legacy-curl-provider.md).
Native and public tests execute actual non-root offline builds, apphosts,
HTTP, crypto, globalization and TLS; Core 3 additionally exercises its forced
CurlHandler with callback HTTPS and ordinary CA trust. Fedora 45 legacy RPMs
bind the stock CA bundle path and its package/hash in signed evidence.

These are project-operated repositories. Distribution does not restore
upstream support for EOL runtimes or establish official distro acceptance.
The original framework/bootstrap/source-construction disclosures remain
[recorded separately](additional-sdk-preparation.md).

## Retained proof

The [neutral archive and website audit](neutral-archive-validation.json)
authenticates all eight new archive revisions, sixteen real public native jobs
and their exact report ZIPs. It also records preservation of the prior 63
releases and 832 assets, the final Pages build and deployment, all sixteen live
download links, desktop/mobile layout checks and the unchanged signed
`cbodotnetup` 0.1.0 feed.

[The retained release validation](all-sdk-release-validation.json) independently
authenticates all 32 signed release cells before the neutral archive filename
revision, actual public native report ZIPs and all-eight package coexistence on
four operating systems and two CPUs. It remains historical evidence and does
not claim qualification of the new archive revisions.
The aggregate proves exact aliases, versioned roots, descending removal
fallback, strict package integrity, unchanged SDK/provider inventories,
legacy-to-modern environment restoration and preservation of the actual
package-managed official SDK through final Community package purge.

SDK10 revision3 APT/OCI retain the original successful publisher and both
native consumers. Their original finalizer failed on delayed GitHub API
metadata; [status-only recovery](https://github.com/dotnetdev-kr/cbodotnet/commit/a1990cb4bb447d88c9e794ae21916dfe49eea9ae)
used the unchanged verifier and preserved the failed job record, original
frozen signed bytes and source provenance. The final proof records this
history explicitly; no SDK rebuild or replacement signature was created.

The [Arch all-eight proof](aur-all-sdk-validation.json) retains actual
makepkg/namcap/install/lifecycle reports and selector fallback; its independent
official SDK baseline is an authenticated archive, not an Arch-owned package.

All eight original unbranded source releases have experimental/do-not-use
warnings in their titles and bodies. Their [warning audit](original-release-warnings.json)
preserves exact original asset identities and hashes. Use the branded
distributions above; the source releases remain immutable provenance inputs.
