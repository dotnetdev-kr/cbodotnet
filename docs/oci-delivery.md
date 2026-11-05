# Consumer SDK images

The public SDK image repository is
`ghcr.io/dotnetdev-kr/cbodotnet-sdk`. The
[verified delivery matrix](all-sdk-distributions.md) lists exact published SDKs
and immutable image releases. Each uses a digest-pinned Debian 13 glibc base on native `linux/amd64` and
`linux/arm64`. One versioned tag resolves to the complete two-platform index.
Public architecture names `x64` and `aarch64` map to those OCI platforms.

The current SDK 10 image is **revision 3**, `10.0.403-debian13-r3`, at:

```text
sha256:c9335fa52f22ead1ffd8f5f12fa1e3c406df672dcae1cfeda724087655d37873
```

It includes the complete wrapper license and restores a caller's environment
when a modern Community SDK is invoked from a legacy Community process.
The original signed revision 2 remains public at:

```text
sha256:c945ebf6da10c3c2ccefef91062df0832597260d8b2efb7e97ea9bf2c522afd9
```

Revision 2 adds explicit license/notice/source labels and records the exact SDK
listing, image ownership and consumer configuration before publication and after
anonymous digest pull. The [native publication run](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41831153506)
passed both architectures, protected signing/publication, anonymous native
functional checks and status activation. The
[retained validation record](oci-publication-validation.json) includes exact
reports, independently checked artifact ZIP hashes, signed source/configuration
bindings and registry metadata. The
[published status and receipts](../releases/downstream-status.json) and
[installation website](https://dotnetdev.kr/cbodotnet/) identify the current
verified image. Revision 1 remains immutable at
`sha256:11939c01e8cf35aa21a56dd1f2365832cc71012d2a3e3142f9be5e3d1aed897d`.

## Pull and run

Use an exact index digest from an authenticated publication receipt. Docker
selects the matching verified native platform; specify `--platform` explicitly
when checking a particular platform.

```bash
image=ghcr.io/dotnetdev-kr/cbodotnet-sdk@sha256:c9335fa52f22ead1ffd8f5f12fa1e3c406df672dcae1cfeda724087655d37873
docker pull "$image"
docker run --rm "$image" cbodotnet --info
docker run --rm "$image" cbodotnet-10.0 --list-sdks
docker run --rm "$image" dotnet --version
docker run --rm "$image" id -u
```

All three command names select `/opt/cbodotnet/10.0`. `--list-sdks` must show
only `10.0.403 [/opt/cbodotnet/10.0/sdk]`. `--version` keeps `10.0.403` on stdout
and prints `Community Build of .NET (built by .NET Dev)` on stderr. The default
command is `cbodotnet --info`, the working directory is `/work`, and the default
user is `app` (UID/GID 1654). The SDK and launchers are root-owned; application
work belongs in the writable working directory.

An offline application example:

```bash
docker run --rm --network none "$image" sh -ec '
  mkdir -p /work/smoke && cd /work/smoke
  dotnet new console --framework net10.0 --no-restore
  printf "<configuration><packageSources><clear /></packageSources></configuration>" > NuGet.Config
  dotnet restore --configfile NuGet.Config
  dotnet build --no-restore
  dotnet bin/Debug/net10.0/smoke.dll
'
```

## Verify provenance

The [distribution signing policy](distribution-signing.md) documents the trusted
primary fingerprint and trust bootstrap. The OpenPGP-signed
`distribution-manifest.json` binds the exact source release, qualified producer,
SDK/source/evidence archive hashes, native reports and OCI index descriptor.
The descriptor binds the public index, both platform manifests and their tested
image configuration digests. The same signed SDK manifest pin is used by every
package channel.

The current public signed record is under
[distribution-oci-sdk-10.0.403-r2](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-oci-sdk-10.0.403-r2).
The previous [revision 1 record](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-oci-sdk-10.0.403-r1)
remains available for explicit rollback and audit.
To inspect it, first authenticate the public key fingerprint through the trusted
project-owner channel, then verify the detached manifest signature with that
dedicated keyring. Verify the downloaded `oci-index.json` size and SHA-256 against
the signed manifest before using its `repository` and `digest` as the pull
reference. `docker buildx imagetools inspect "$image"` must show exactly
`linux/amd64` and `linux/arm64`.

Image labels link the project repository, exact qualified SDK release, SDK
version, base image digest, archive/manifest digests and, from revision 2,
corresponding source/evidence assets and the notice references below. These
labels describe the image; the signed manifest authenticates their tested image
configuration digest. `dotnet --cbodotnet-info` exposes the isolated SDK root,
release and manifest identity inside the image.

## Licenses and notices

The original SDK `LICENSE.txt` records the MIT license. The complete
`ThirdPartyNotices.txt` retains the applicable component notices and license
terms. Both files remain unchanged under `/opt/cbodotnet/10.0/`; source delivery
and native checks verify their presence and exact bytes.

Revision 2 uses the OCI license expression
`MIT AND LicenseRef-Dotnet-ThirdPartyNotices`. The local `LicenseRef` names the
retained aggregate notice, rather than representing every bundled component as
MIT-only. Custom labels identify both original file paths and link this notice
explanation, the qualified source archive and producer evidence. Inspect the
complete retained notices when redistributing the SDK or an image derived from
it.

The Debian base and its installed system packages retain their own copyright
and license notices, including those under `/usr/share/doc`. The SDK license
expression describes the qualified SDK payload; it does not replace the base
distribution's package licenses.

## Compatibility, lifecycle and corrections

Each listed consumer image covers its exact SDK on the recorded Debian 13 glibc
base. Archive execution on another user space does not qualify that space as an
image base. The SDK 5 and Core 3 images use the separately authenticated legacy
providers recorded in the delivery matrix. Musl/Alpine, runtime-only and
ASP.NET-only image variants require independent qualification.
Continued Community Build availability does not extend Microsoft's security
maintenance or promise vulnerability remediation after upstream end of support.
The [contract](distribution-contract.md) records those support boundaries.

Packaging changes use a new `rN` revision and new immutable index/configuration
digests. Publication accepts matching retries and rejects conflicting existing
platform or index tags. Rollback selects the previous verified digest explicitly;
it does not rewrite an existing tag. Mutable `latest`, `10.0` and unsuffixed SDK
aliases remain deferred. `docker run --rm` removes the disposable container after
execution; `docker image rm "$image"` removes its local cached reference.

## Release validation

Native runners verify the qualified archive and safely extract it without SDK
recompilation. They compare installed payload bytes, modes and links, then test
all command aliases, exact SDK listings, branding, non-root console/HTTP/crypto/
ICU execution, official SDK coexistence, image upgrade/rollback and removal.
Image configuration checks cover the selected platform, `/work`, non-root user,
`PATH`, `DOTNET_ROOT`, default command, source/license labels, SDK/launcher
ownership, credential environment keys and accidental source-build tools.
After publication, both native jobs anonymously pull the public index by digest,
compare the configuration with the tested native image, repeat the metadata,
ownership and SDK-list checks, and build/run offline as the default user.
The published-image test runs both DLL and apphost forms, checks the selected
runtime/root/RID, starts a loopback ASP.NET server, and exercises RSA signatures,
cryptographic randomness and ICU formatting with external networking disabled.

An OCI-only promotion uses `--channel oci` and freezes only `bundle-oci`,
`oci-index.json` and `promotion.json`. It stages a complete two-architecture
matrix and rejects unexpected Debian bundles before publication. The protected
workflow signs and publishes a new OCI revision without repackaging APT.
