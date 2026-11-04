# CLI identity and command aliases

The distribution identity is **Community Build of .NET (built by .NET Dev)**.
[Distribution contract version 2](distribution-contract.md) provides this identity
through separately tracked launchers while retaining the exact qualified SDK
payload. The machine-readable policy is in
[distribution-contract.json](../releases/distribution-contract.json).

## Why the initial implementation uses launchers

The upstream SDK 10.0.403
[command dispatcher](https://github.com/dotnet/sdk/blob/v10.0.403/src/Cli/dotnet/Program.cs#L157)
handles top-level version and information requests. Its
[information formatter](https://github.com/dotnet/sdk/blob/v10.0.403/src/Cli/dotnet/CommandLineInfo.cs#L15)
prints `Product.Version` for `--version`, and SDK version, commit, workload,
MSBuild, RID and base-path information for `--info`. Help contains upstream
`dotnet` usage strings in
[CliUsage.cs](https://github.com/dotnet/sdk/blob/v10.0.403/src/Cli/dotnet/CliUsage.cs).
The [native host](https://github.com/dotnet/runtime/blob/v10.0.0/src/native/corehost/fxr/fx_muxer.cpp#L1060)
also contributes information output. These are multiple compiled components,
not one editable distribution display-name file.

Changing compiled version strings or SDK assemblies would change qualified
archive contents. It could also affect version-dependent tooling. The upstream
[driver documentation](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet)
describes the selected SDK version as potentially dependent on `global.json`
and distinguishes SDK commands from application execution. The distribution
therefore preserves version output and forwards application arguments.

The initial implementation adds a distribution header and separate provenance
output around the preserved host. This is distribution branding, not a change
to upstream product versions or a new claim of security maintenance. Original
copyrights, licenses and notices remain intact.

## Visible behavior

| Invocation through a public launcher | Standard output | Standard error |
| --- | --- | --- |
| No arguments | Identity header, then original host usage | Original host errors, if any |
| Sole `--info` | Identity header, then original SDK/host details | Original errors, if any |
| Sole `--help`, `-h` or `help` | Identity header, then original help | Original errors, if any |
| Sole `--version` | Original numeric selected SDK version | Identity header, then original errors, if any |
| Sole `--cbodotnet-info` | One JSON distribution/provenance record | Errors only |
| Build, run or application execution | Original command output | Original command errors |

For example, an interactive `cbodotnet-10.0 --version` displays the identity and
the numeric SDK version. A script capturing stdout still receives the original
version string. Capturing stderr together with stdout also captures branding;
scripts that need only the version should capture stdout separately.

The JSON command records the distribution brand, contract version, installed
SDK version, target RID, SDK root, source release tag, pinned manifest SHA-256,
package revision and wrapper-only scope. It describes the installed
distribution; it does not claim that a project's `global.json` can select that
SDK successfully. The host must exist and be executable before the launcher
serves this metadata. The JSON command does not execute the SDK CLI.

Branding is applied only to the complete top-level invocations shown above.
Arguments such as `app.dll --version`, `build --help` and
`run -- --cbodotnet-info` continue to reach their original command or application.
They do not trigger distribution output. Ordinary commands retain their
standard streams and exit status; the launcher ultimately replaces itself with
the absolute selected host.

## Alias selection and ownership

Native packages provide `cbodotnet-<major>.<minor>` for explicit selection.
The shared `cbodotnet` dispatcher belongs to the separate `cbodotnet-host`
package. It selects the highest installed numeric major/minor with a usable
cbodotnet installation. Removing that SDK selects the next remaining usable
version; removing all SDKs produces an error. It never forwards to a system
`dotnet` installation. Users needing stable selection across installations use
the versioned command.

OCI images provide `cbodotnet-<major>.<minor>`, `cbodotnet` and `dotnet` for the
same selected SDK. The image's wrapper bin directory must precede the SDK root
in `PATH`. The preserved SDK root itself still contains the original `dotnet`
host. `DOTNET_HOST_PATH` identifies that host for internal SDK operations,
avoiding recursive wrapper calls and duplicate banners.

The [command installer](../scripts/distribution_commands.py) separately
inventories generated command files. Native package mode does not add or
replace the host's `dotnet` command. The installed wrappers remain separate
from the qualified SDK archive and are included in downstream provenance and
validation under [issue #7](https://github.com/dotnetdev-kr/cbodotnet/issues/7).

## Boundaries and verification

Direct invocation of `/opt/cbodotnet/<series>/dotnet`, application apphosts,
runtime assembly versions, SDK-generated files and upstream help content
retain their original identity and behavior. They can bypass public-launcher
branding. The initial implementation does not replace all upstream `dotnet`
words or compiled product information.

Native branding inside host binaries or SDK assemblies would require a
source change, a fresh complete build/source qualification and new immutable
release inputs. Existing qualified archives must not be rewritten in place.

[Branding regression tests](../tests/distribution_branding_test.py) exercise
numeric stdout, visible identity, provenance JSON, argument and stream
preservation, shell-safe roots, explicit architecture selection and missing-host
failure without official fallback. Command alias tests and native coexistence
checks complement these tests. A passing wrapper test does not qualify an APT,
RPM, AUR or OCI publication; each channel retains its own installation,
dependency, signing and post-publication requirements.
