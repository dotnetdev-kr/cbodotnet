# cbodotnet

Community .NET SDK builds for **glibc Linux ARM64 and x64**, independently of Microsoft's support lifecycle. The project covers .NET 5 onward and .NET Core 3.0/3.1, using the .NET VMR where available and pinned legacy source-build graphs where needed.

**Builds run exclusively in GitHub Actions.** All eight selected SDK versions have passed native hosted builds and independent SDK/source delivery verification on both architectures.

## Build

Choose an architecture, open its workflow, and select **Run workflow** on `main`:

| Architecture | Workflow | Default native runner |
| --- | --- | --- |
| ARM64 | [Linux ARM64 SDK matrix](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/sdk-matrix.yml) | `ubuntu-24.04-arm` |
| x64 | [Linux x64 SDK matrix](https://github.com/dotnetdev-kr/cbodotnet/actions/workflows/sdk-x64.yml) | `ubuntu-24.04` |

Alternatively, use an authenticated GitHub CLI:

```bash
gh workflow run sdk-matrix.yml --repo dotnetdev-kr/cbodotnet --ref main -f target=all -f create_draft=false
gh workflow run sdk-x64.yml --repo dotnetdev-kr/cbodotnet --ref main -f target=all -f create_draft=false
```

Select `all` or one target:

| Target | SDK |
| --- | --- |
| `net10` | 10.0.403 |
| `net9` | 9.0.123 |
| `net8` | 8.0.133 |
| `net7` | 7.0.120 |
| `net6` | 6.0.136 |
| `net5` | 5.0.214 |
| `core31` | 3.1.426 |
| `core30` | 3.0.103 |

Each workflow builds at most two selected profiles concurrently. Every run uses fresh inputs and must pass its own build, upstream tests, source-delivery and native verification gates.

## Download

Open a successful workflow run and download `sdk-TARGET-linux-ARCH-RUN-ATTEMPT` from **Artifacts**. The delivery contains the SDK archive, actual used source archive, checksums, source index, manifests and validation reports. Actions artifacts are retained for **14 days**; historical result records remain in this repository.

Follow the CI guide to verify and extract the transport bundle. Install the inner `cbodotnet-sdk-*.tar.gz` archive on a matching Linux architecture. Optional unpublished drafts require `create_draft=true`; public release publication is a separate action.

## Compatibility

`linux-arm64` and `linux-x64` are generic **glibc** package targets. Native checks cover Ubuntu 22.04, Ubuntu 24.04 and Debian 13 user spaces. Kernel, system-library and optional component requirements still apply; these results do not cover musl/Alpine or every Linux distribution.

.NET 5 and Core 3.x verification requires the recorded external OpenSSL 1.1 inputs. Core 3.x on Debian 13 additionally uses ICU 66. Exact dependencies, framework construction and ABI measurements are recorded with each qualified delivery.

## Documentation

- [ARM64 CI, source delivery and verification](docs/ci-matrix.md)
- [x64 CI, source delivery and verification](docs/ci-x64.md)
- [ARM64 qualification results and artifact links](docs/ci-matrix-results.md)
- [x64 qualification results and artifact links](docs/ci-x64-results.md)

Documentation and code comments are maintained in English. Generated archives, downloaded inputs and build workspaces are excluded from Git.
