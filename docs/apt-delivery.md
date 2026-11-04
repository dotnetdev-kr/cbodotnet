# APT delivery and qualification

The qualified .NET SDK **10.0.403, packaging revision 1**, is published for
Ubuntu 24.04 and Debian 13 on native `amd64` and `arm64`. The immutable source
and publication receipts are recorded in
[`releases/downstream-status.json`](../releases/downstream-status.json).
The [initial publication evidence](distribution-publication-validation.json)
retains the original signed package and public installation checks. This work
strengthens installation instructions and validation without replacing those
revision 1 packages or rebuilding the SDK.

## Configure the signed repository

Use the repository matching the installed OS. These are flat repositories:
`Suites: ./` is required, and there is no `Components` field. The
[APT sources documentation](https://manpages.debian.org/trixie/apt/sources.list.5.en.html)
describes this deb822 layout and per-source `Signed-By` trust.

First confirm the project fingerprint through a trusted project-owner channel.
The [signing policy](distribution-signing.md) records its ownership and expiry.
The key is separate from Ubuntu and Microsoft package-signing identities.

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg gpgv
key=$(mktemp)
curl --fail --location --proto '=https' --tlsv1.2 \
  https://dotnetdev.kr/cbodotnet/cbodotnet-archive-keyring.gpg -o "$key"
fingerprints=$(gpg --batch --show-keys --with-colons "$key" | \
  awk -F: '$1=="pub" { primary=1; next } $1=="fpr" && primary { print $10; primary=0 }')
test "$fingerprints" = D7D154B4B33C19A82B95B13688135410ACD9C0EA || { rm -f "$key"; exit 1; }
sudo install -m 0644 "$key" /usr/share/keyrings/cbodotnet-archive-keyring.gpg
rm "$key"
```

On **Ubuntu 24.04**, set `variant=ubuntu-24.04`; on **Debian 13**, set
`variant=debian-13`. Run the following in the same shell after choosing the
matching value. Remove the project's old one-line source if previously used,
so it cannot conflict with the new source's signing options.

```sh
variant=ubuntu-24.04
case "$(dpkg --print-architecture)" in amd64|arm64) ;; *) exit 1 ;; esac
sudo rm -f /etc/apt/sources.list.d/cbodotnet.list
sudo tee /etc/apt/sources.list.d/cbodotnet.sources >/dev/null <<EOF
Types: deb
URIs: https://dotnetdev.kr/cbodotnet/packages/deb/$variant
Suites: ./
Architectures: $(dpkg --print-architecture)
Signed-By: /usr/share/keyrings/cbodotnet-archive-keyring.gpg
EOF
sudo apt-get update
sudo apt-get install cbodotnet-sdk-10.0=10.0.403-1 cbodotnet-host=1.0.0-1
```

The [installation website](https://dotnetdev.kr/cbodotnet/) gives the matching
commands for each published target. It derives availability from verified
publication receipts. Other OS releases and SDK versions require their own
qualified matrix before publication.

## Commands, payload and coexistence

| Package | Version | Ownership |
| --- | --- | --- |
| `cbodotnet-sdk-10.0` | `10.0.403-1` | `/opt/cbodotnet/10.0`, `/usr/bin/cbodotnet-10.0`, SDK notices and provenance |
| `cbodotnet-host` | `1.0.0-1`, architecture `all` | `/usr/bin/cbodotnet` and the shared selector license |

Both `cbodotnet-10.0` and `cbodotnet` select the Community SDK. `--version`
prints the numeric SDK version on stdout and
`Community Build of .NET (built by .NET Dev)` on stderr. `--info` identifies
the SDK root and RID; `--cbodotnet-info` exposes its pinned source manifest,
SDK version and packaging revision. The selector chooses the highest installed
Community SDK series. There is one installed SDK version per major/minor series.

The SDK archive is copied without recompilation or rewriting. Original
`LICENSE.txt` and `ThirdPartyNotices.txt` remain in the SDK root and are also
installed in `/usr/share/doc/cbodotnet-sdk-10.0/`. Their original terms govern
the SDK components. Native packaging checks compare extracted package bytes,
modes and links with the qualified archive; installed checks require clean
`dpkg --verify` output and unchanged notice copies.

APT packages do not own `/usr/bin/dotnet`, alter system alternatives, modify
shell startup files or write to an official SDK root. Coexistence validation
installs a real package-managed `dotnet-sdk-10.0` first. Ubuntu uses its
[official distribution feed](https://learn.microsoft.com/en-us/dotnet/core/install/linux-ubuntu-install?pivots=os-linux-ubuntu-2404&tabs=dotnet10)
and `/usr/lib/dotnet`; Debian uses the
[Microsoft Debian feed](https://learn.microsoft.com/en-us/dotnet/core/install/linux-debian?tabs=dotnet10)
and `/usr/share/dotnet`. The Debian comparison feed has its own scoped keyring
and reviewed Microsoft 2025 signing fingerprint
`AA86F75E427A19DD33346403EE4D7792F748182B`.
The evidence records the actual official candidate version rather than assuming
it equals the Community SDK version.

## Remove, retain and roll back

Remove the SDK while keeping the shared selector. After removing the last
package-managed Community SDK, purge the SDK and shared selector if desired:

```sh
sudo apt-get remove cbodotnet-sdk-10.0
sudo apt-get purge cbodotnet-sdk-10.0 cbodotnet-host
```

After removing the last Community SDK, the retained selector fails with exit
code 127. It does not fall back to an official `dotnet`. Purging both packages
removes the Community SDK root and commands; official SDK packages remain.

Retain an approved version before an upgrade if later rollback is needed.
While the authenticated repository and its exact version are available, save
the package files in a user-owned directory:

```sh
mkdir -p "$HOME/cbodotnet-retained/10.0.403-1"
cd "$HOME/cbodotnet-retained/10.0.403-1"
apt-get download cbodotnet-sdk-10.0=10.0.403-1 cbodotnet-host=1.0.0-1
```

Retain the repository's verified `InRelease` and `Packages` alongside those
files. Verify `InRelease` with the pinned project key, then verify the
`Packages` size and SHA-256 against its signed Release entry, and each DEB
against its matching package/version/architecture entry in `Packages`. A hash
downloaded beside a DEB without this authenticated chain is insufficient.
The hosted verifier performs these checks before retention and repeats each
DEB size and SHA-256 check immediately before offline reinstallation.

For a future rollback, substitute the previously retained, authenticated
version and both corresponding absolute DEB paths:

```sh
sudo apt-get install --allow-downgrades \
  "$HOME/cbodotnet-retained/10.0.403-1/cbodotnet-sdk-10.0_10.0.403-1_$(dpkg --print-architecture).deb" \
  "$HOME/cbodotnet-retained/10.0.403-1/cbodotnet-host_1.0.0-1_all.deb"
cbodotnet-10.0 --version
cbodotnet-10.0 --cbodotnet-info
```

[APT documents exact-version downloads and `--allow-downgrades`](https://manpages.debian.org/trixie/apt/apt-get.8.en.html).
Only revision 1 is currently published. The hosted lifecycle check proves
authenticated removal and reinstallation of that same revision. Earlier
packaging upgrade/rollback fixtures are native build checks, not claims that
another public APT revision exists.

## Validation boundaries

The read-only [APT completeness workflow](../.github/workflows/apt-completeness.yml)
repeats native package build, extraction, lifecycle and actual official-package
coexistence checks on both architectures and both OS targets. It does not sign
or publish replacement packages. The
[hosted HTTPS workflow](../.github/workflows/distribution-site-check.yml)
installs the current public revision through the deb822 source and then runs
the build and lifecycle phase with Docker `--network none` as a non-root SDK
user. It exercises DLL and apphost execution, ASP.NET Core loopback HTTP,
RSA signing/verification, cryptographic randomness and ICU formatting.

Compact reports retain official package owners and versions, the command link
and binary SHA-256, and complete official-root/package-inventory digests.
Those baselines must remain unchanged after Community installation, offline
execution, SDK removal, authenticated cached reinstallation and purge.
The detailed private comparison state stays inside the disposable container.
These runs use pinned target user-space containers on native CPU workers and
share the runner's kernel; they do not independently qualify distribution kernels.
The new completeness runs must pass before issue #4 is closed; the initial
publication evidence above remains the record of the original revision.
