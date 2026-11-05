# cbodotnet

[Homepage and downloads](https://dotnetdev.kr/cbodotnet/) · [Releases](https://github.com/dotnetdev-kr/cbodotnet/releases) · [CI/CD](https://github.com/dotnetdev-kr/cbodotnet/actions)

[![Repository checks](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/checks.yml/badge.svg?branch=main)](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/checks.yml)
[![Linux AArch64 SDK builds](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/sdk-matrix.yml/badge.svg?branch=main)](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/sdk-matrix.yml)
[![Linux x64 SDK builds](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/sdk-x64.yml/badge.svg?branch=main)](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/sdk-x64.yml)
[![Upstream SDK tracking](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/upstream-sdk.yml/badge.svg?branch=main)](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/upstream-sdk.yml)
[![Release publication](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/publish-releases.yml/badge.svg?branch=main)](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/publish-releases.yml)
[![Download Pages](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/pages.yml/badge.svg?branch=main)](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/pages.yml)

Community .NET SDK builds for **glibc Linux AArch64 and x64**, independently of Microsoft's support lifecycle. The project covers .NET 5 onward and .NET Core 3.0/3.1, using the .NET VMR where available and pinned legacy source-build graphs where needed.

**Builds run exclusively in GitHub Actions.** All eight selected SDK versions have passed native hosted builds and independent SDK/source delivery verification on both architectures.

## Download

[Download builds](https://dotnetdev.kr/cbodotnet/) or open [GitHub Releases](https://github.com/dotnetdev-kr/cbodotnet/releases). Each version includes both SDK archives, the actual used sources for each architecture, complete qualification evidence, `SHA256SUMS` and `release-manifest.json`.

Public names use `aarch64`. The official .NET RID remains `linux-arm64`; upstream package names, container-platform identities and historical evidence retain that spelling. SDK/source payload bytes are preserved when public filenames change.

## Package repositories and containers

Versioned Community Build SDKs use signed project-operated APT repositories
for **Ubuntu 24.04 and Debian 13** (`amd64`, `arm64`), signed RPM repositories
for **Fedora 45 and Rocky Linux 9.8** (`x86_64`, `aarch64`), and Debian 13-based
GHCR SDK images (`linux/amd64`, `linux/arm64`). The
[verified delivery matrix](docs/all-sdk-distributions.md) lists the exact
published SDKs and revisions. Use the
[verified installation commands](https://dotnetdev.kr/cbodotnet/) and
[distribution status and receipts](releases/downstream-status.json).
The [Arch x86_64 recipes](docs/aur-delivery.md) have passed native build, installation
and lifecycle validation; authenticated AUR submission is tracked separately in
[issue #10](https://github.com/dotnetdev-kr/cbodotnet/issues/10).

The [original additional SDK preparation audit](docs/additional-sdk-preparation.md)
retains the source pins and dependency decisions for SDKs 9, 8, 7, 6, 5 and Core
3.1/3.0. Current availability comes from the signed publication receipts and
delivery matrix above. The [cbodotnetup per-user SDK manager](docs/cbodotnetup.md)
provides a signed, SDK-free bootstrap for **SDK10.0.403** on the same four
Ubuntu/Debian/Fedora/Rocky versions and both native CPUs. It installs into user
data roots, with explicit shell aliases and authenticated updates/recovery.
See the [tool release](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/cbodotnetup-v0.1.0)
and [activated installer status](releases/cbodotnetup-status.json). Additional
SDK installer admissions remain separate from their package qualification.

The package contract provides `cbodotnet-X.Y` and a common `cbodotnet` command
selecting the highest installed SDK series. OCI images expose
`cbodotnet-X.Y`, `cbodotnet` and `dotnet` for the same SDK. Public launchers show
**Community Build of .NET (built by .NET Dev)** in information/help; numeric
`--version` stdout remains compatible. [CLI identity](docs/cli-branding.md)
explains the branding and source-provenance boundary.

## Build

Choose an architecture, open its workflow, and select **Run workflow** on `main`:

| Architecture | Workflow | Default native runner |
| --- | --- | --- |
| AArch64 | [Linux AArch64 SDK matrix](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/sdk-matrix.yml) | `ubuntu-24.04-arm` |
| x64 | [Linux x64 SDK matrix](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/sdk-x64.yml) | `ubuntu-24.04` |

Alternatively, use an authenticated GitHub CLI:

```bash
gh workflow run sdk-matrix.yml --repo dotnetdev-kr/cbodotnet --ref main -f target=all -f create_draft=false
gh workflow run sdk-x64.yml --repo dotnetdev-kr/cbodotnet --ref main -f target=all -f create_draft=false
```

Select `all` or one target:

| Target | SDK |
| --- | --- |
| `net10` | [10.0.403](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/sdk-10.0.403) |
| `net9` | [9.0.123](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/sdk-9.0.123) |
| `net8` | [8.0.133](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/sdk-8.0.133) |
| `net7` | [7.0.120](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/sdk-7.0.120) |
| `net6` | [6.0.136](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/sdk-6.0.136) |
| `net5` | [5.0.214](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/sdk-5.0.214) |
| `core31` | [3.1.426](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/sdk-3.1.426) |
| `core30` | [3.0.103](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/sdk-3.0.103) |

Each workflow builds at most two selected profiles concurrently. Every run uses fresh inputs and must pass its own build, upstream tests, source-delivery and native verification gates.

Actions artifacts retain run-specific transport bundles for **14 days**. Public Releases preserve qualified downloads. The [publication workflow](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/publish-releases.yml) promotes the exact recorded producers in [the qualification catalog](releases/qualified-builds.json), independently verifies both deliveries, and publishes only a complete release. Retries accept matching assets and refuse overwrites. The [Pages workflow](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/pages.yml) lists complete public releases and refreshes after publication.

To resume a failed publication without rebuilding, dispatch the publication workflow with the original `staged_run_id` and `staged_run_attempt`. It requires that target's successful verification/upload job and its exact unexpired, digest-checked artifact, and retains the original publication commit.

## Upstream updates

The [upstream workflow](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/upstream-sdk.yml) checks official stable SDK metadata every day at **03:23 UTC**, including end-of-life channels. Constrained adapters cover successors to .NET 8.0.133/9.0.123 in their 1xx bands and .NET 10.0.403 in its 4xx band. Each new SDK needs both native builds, actual used sources and complete verification before automatic publication. All three generated baseline adapters have passed both native hosted builds and independent SDK/source verification and release staging.

Other bands and new major versions remain visible as `pending-adapter`; missing exact source tags remain `pending-source`, and unavailable bootstrap inputs remain `pending-bootstrap`. An incompatible source layout requires a qualified adapter update. [Automation and recovery details](docs/upstream-automation.md) describe the admission gates and retry behavior.

## Compatibility

`linux-arm64` and `linux-x64` are generic **glibc** package targets. Native checks cover Ubuntu 22.04, Ubuntu 24.04 and Debian 13 user spaces. Kernel, system-library and optional component requirements still apply; these results do not cover musl/Alpine or every Linux distribution.

Branded .NET 5 and Core 3.x distributions use a separately authenticated
[OpenSSL/ICU provider](docs/legacy-compatibility-provider.md); Core 3 additionally
uses a separate [native HTTP provider](docs/legacy-curl-provider.md). These
providers require glibc 2.34 and, on x64, x86-64-v2. Historical source-archive
checks used different recorded inputs. Packaging preserves those source and
framework disclosures and does not restore upstream support for EOL runtimes.

## Copyright and license

Copyright (c) 2026 cbodotnet contributors. This repository's build automation and project documentation are licensed under the [MIT License](LICENSE), matching the [upstream .NET VMR license](https://github.com/dotnet/dotnet/blob/main/LICENSE.TXT).

SDK archives and corresponding source bundles retain their upstream copyrights, licenses and third-party notices. This repository's MIT license does not replace those terms; preserve the notices accompanying each distributed component.

## Documentation

- [Downstream distribution contract and rollout](docs/distribution-contract.md)
- [CLI branding and command aliases](docs/cli-branding.md)
- [Consumer SDK images and provenance](docs/oci-delivery.md)
- [Signed APT repositories, package coexistence and rollback](docs/apt-delivery.md)
- [Signed RPM repositories and qualification](docs/rpm-delivery.md)
- [Validated Arch recipes and deferred AUR publication](docs/aur-delivery.md)
- [Additional SDK sources, dependency gates and preparation plans](docs/additional-sdk-preparation.md)
- [Current verified SDK distribution matrix](docs/all-sdk-distributions.md)
- [Core 3 native HTTP and its separate libcurl dependency](docs/legacy-curl-provider.md)
- [Downstream verification and promotion runbook](docs/downstream-release-runbook.md)
- [AArch64 CI, source delivery and verification](docs/ci-matrix.md)
- [x64 CI, source delivery and verification](docs/ci-x64.md)
- [AArch64 qualification results and artifact links](docs/ci-matrix-results.md)
- [x64 qualification results and artifact links](docs/ci-x64-results.md)

Documentation and code comments are maintained in English. Generated archives, downloaded inputs and build workspaces are excluded from Git.
