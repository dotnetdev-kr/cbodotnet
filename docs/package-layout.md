# Verified downstream package preparation

The [packager](../scripts/package-sdk.py) accepts an exact qualified release
input directory, channel, OS variant, public architecture and package revision.
It uses the common intake validator before opening SDK bytes. RPM and AUR
preparation adapters exist but remain unavailable through the checked-in
contract until their own targets and native dependency policies are admitted.

```bash
python3 scripts/package-sdk.py --inputs "$PWD/.build/inputs" \
  --channel deb --variant debian-13 --arch x64 --revision 1 \
  --output "$PWD/.build/debian13-x64-r1"
```

The output contains `rootfs/`, the verified plan, command and SDK inventories,
`package-build.json`, a versioned SDK `.deb` and `cbodotnet-host_1.0.0-1_all.deb`.
The SDK package owns its complete `/opt/cbodotnet/10.0` root and explicit
`/usr/bin/cbodotnet-10.0`. It depends on the shared host package, which owns
`/usr/bin/cbodotnet` and no SDK files. Removing one SDK does not remove the
selector or another installed SDK. Neither component owns system `dotnet`.
The architecture-independent shared package is reproducible across SDK patches,
architectures and packaging revisions.

No maintainer script rewrites SDK bytes or edits shell profiles. The builder
preserves executable modes, links, templates, libraries, licenses and notices,
adds the separately accounted empty `metadata/` directory and command files,
and compares the extracted final `.deb` against the staged qualified payload.
Its [dpkg-deb invocation](https://manpages.debian.org/unstable/dpkg/dpkg-deb.1.en.html)
sets root ownership and a fixed source epoch. The generated wrapper inventory
is available to the common release gate. Signing APT metadata happens after the
native install, upgrade, non-root use, coexistence and removal matrix passes.

## OCI context

Use channel `oci`, variant `debian-13`, and supply
`--base-image debian:13@sha256:<reviewed-index-digest>`. The output copies the
[runtime Containerfile](../containers/sdk-runtime.Containerfile), unchanged SDK
root and all three public command names. `package-build.json` records the exact
base, SDK/source manifest hashes, labels and build arguments. The image runs as
the non-root `app` user with a writable `/work`. Its PATH prefers the wrapper
directory, so `dotnet`, `cbodotnet` and `cbodotnet-10.0` select the same branded
CLI. Building a context does not qualify or publish an image.

## Signed repositories

[Repository preparation](../scripts/package-repository.py) rehashes every package
listed in the build records and requires both architectures for every advertised
variant. It refuses conflicting shared package bytes and mixed source/revision
inputs. Supply the full reviewed signing fingerprint and a protected signing
home; no key is generated or implicitly trusted by this command.

```bash
python3 scripts/package-repository.py --channel deb \
  --package-builds x64/package-build.json aarch64/package-build.json \
  --signing-key "$PROJECT_SIGNING_FINGERPRINT" --gnupg-home "$GNUPGHOME" \
  --output "$PWD/.build/repositories"
```

Each APT variant has a flat repository with `Packages`, `Packages.gz`, signed
`InRelease`, detached `Release.gpg`, a public archive keyring and `pool/` files.
The helper uses [apt-ftparchive](https://manpages.debian.org/unstable/apt-utils/apt-ftparchive.1.en.html)
to bind package hashes, verifies its generated GPG metadata and emits
`apt-<variant>.tar.gz`. The common publisher signs the bundle descriptor before
the website may expose it. Package-manager installation from the published
signed repository remains a separate post-publication check.

The RPM adapter disables stripping, debug splitting, build-id links and automatic
dependency inference; it requires a reviewed RPM dependency list and compares
the actual extracted RPM payload. RPM repository preparation additionally
requires all package signatures to verify against an isolated database containing
only the selected project's public key, generates `createrepo_c` SHA-256
metadata and signs `repomd.xml`. It cannot convert a Debian runtime test into
Fedora/RHEL compatibility evidence.

The AUR adapter pins the SDK SHA-256 and local launcher/provenance inputs,
disables stripping/debug transformations, and emits a PKGBUILD and `.SRCINFO`.
Real `makepkg`, clean Arch installation and authenticated AUR submission remain
the AUR channel's gates. No AUR submission occurs during recipe preparation.
