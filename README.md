# cbodotnet

Community .NET SDK builds for **glibc Linux AArch64 and x64**, independently of Microsoft's support lifecycle. The project covers .NET 5 onward and .NET Core 3.0/3.1, using the .NET VMR where available and pinned legacy source-build graphs where needed.

**Builds run exclusively in GitHub Actions.** All eight selected SDK versions have passed native hosted builds and independent SDK/source delivery verification on both architectures.

## Download

[Download builds](https://dotnetdev.kr/cbodotnet/) or open [GitHub Releases](https://github.com/dotnetdev-kr/cbodotnet/releases). Each version includes both SDK archives, the actual used sources for each architecture, complete qualification evidence, `SHA256SUMS` and `release-manifest.json`.

Public names use `aarch64`. The official .NET RID remains `linux-arm64`; upstream package names, container-platform identities and historical evidence retain that spelling. SDK/source payload bytes are preserved when public filenames change.

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

The [upstream workflow](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/upstream-sdk.yml) checks official stable SDK metadata every day at **03:23 UTC**, including end-of-life channels. New .NET 10.0.4xx versions after 10.0.403 can derive a constrained adapter, build on both native architectures, verify actual used sources and publish automatically. Other bands and new major versions remain visible as `pending-adapter`; missing exact source tags remain `pending-source`. An incompatible source layout requires a qualified adapter update. [Automation and recovery details](docs/upstream-automation.md) describe the admission gates and retry behavior.

## Compatibility

`linux-arm64` and `linux-x64` are generic **glibc** package targets. Native checks cover Ubuntu 22.04, Ubuntu 24.04 and Debian 13 user spaces. Kernel, system-library and optional component requirements still apply; these results do not cover musl/Alpine or every Linux distribution.

.NET 5 and Core 3.x verification requires the recorded external OpenSSL 1.1 inputs. Core 3.x on Debian 13 additionally uses ICU 66. Exact dependencies, framework construction and ABI measurements are recorded with each qualified delivery.

## Documentation

- [AArch64 CI, source delivery and verification](docs/ci-matrix.md)
- [x64 CI, source delivery and verification](docs/ci-x64.md)
- [AArch64 qualification results and artifact links](docs/ci-matrix-results.md)
- [x64 qualification results and artifact links](docs/ci-x64-results.md)

Documentation and code comments are maintained in English. Generated archives, downloaded inputs and build workspaces are excluded from Git.
