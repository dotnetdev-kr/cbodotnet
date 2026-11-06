# Project SDK selection

This contract applies to the 0.3 tool line and implements
[#28](https://github.com/dotnetdev-kr/cbodotnet/issues/28). Public availability
still follows the authenticated active feed and release qualification. Earlier
tools keep their published selection behavior.

## Invocation and precedence

SDK commands select from SDKs already installed and owned by `cbodotnetup`.
The first applicable row wins:

| Priority | Invocation or configuration | Selection |
| --- | --- | --- |
| 1 | `cbodotnetup run 9.0.123-r2 -- build` | The exact installed version and archive revision. |
| 1 | `cbodotnetup run 9.0.123 -- build` | That installed SDK version, retaining its active revision when applicable. |
| 2 | `cbodotnet-9.0 build` | The installed 9.0 series and its active revision; project SDK settings do not override the named series. |
| 3 | `cbodotnet build` or `cbodotnetup run -- build` | The nearest ancestor `global.json` SDK request, when present. |
| 4 | The same automatic invocation without an SDK request | The highest installed Community SDK series, preserving its active revision. |

Explicit SDK and versioned-alias invocations do not discover project SDK
settings. An incompatible or malformed project SDK request therefore does not
override an explicit choice. Selection does not update a channel, change an
active revision, install an SDK or contact the catalog server. Signature,
revocation, ownership, inventory and host admission checks still apply before
execution. A failed selected SDK verification is an error, rather than a reason
to execute an official or package-managed installation.

For automatic SDK selection, discovery begins at the process's current working
directory, checks `global.json` there, then checks every parent through the
filesystem root. It does not stop at a Git repository or home directory. The
first file ends the search: a nearer `{}`, `{"sdk": null}` or `{"sdk": {}}`
masks a parent's SDK request and keeps the default selection. A malformed
nearer file fails instead of falling back to a parent. Naming a project or
solution on the command line does not change this discovery starting point.

Native-only `--list-sdks` and `--list-runtimes`, application execution and
native `exec` retain host dispatch. They use the explicit SDK/series or the
installed default root without automatic project SDK selection. The native
host's lists describe that selected payload, not every separately owned SDK
root. `--cbodotnet-info` keeps the archive wrapper's distribution identity
command and uses project selection for automatic invocation.

Application DLL/EXE invocations are bound to native `exec` dispatch, including
when the file is missing. Runtime options such as `--roll-forward` require an
explicit DLL/EXE application target; otherwise use `exec [RUNTIME OPTIONS]
APP.dll`. Bare runtime options cannot redirect an SDK command through a second
native SDK search.

## SDK policy

The accepted fields are `sdk.version`, `sdk.rollForward`,
`sdk.allowPrerelease`, `sdk.paths` and `sdk.errorMessage`. Unknown fields and
unrelated sections such as `msbuild-sdks`, `test` and `workload` are not manager
installation instructions. The selected SDK remains responsible for its own
project features.

`version` requires a full three-part SDK version, such as `9.0.123`, optionally
with a prerelease/build suffix. Lower bounds such as `9.0.0` are accepted for
roll-forward matching; they do not admit a new SDK release into the catalog.
Wildcards, ranges and a major/minor shorthand are invalid. A Community archive
revision suffix is not a project revision selector: use an explicit manager
argument when pinning `-r2`. For a version
`major.minor.patch`, the feature band is `patch / 100`, rounded down.

Matching follows the [.NET 10.0.14 host resolver](https://github.com/dotnet/runtime/blob/v10.0.14/src/native/corehost/fxr/sdk_resolver.cpp):

| `rollForward` | Installed SDK match |
| --- | --- |
| `disable` | Exact SDK version only. |
| `patch` | Exact version first; otherwise the latest patch in its feature band. |
| `feature` | The nearest compatible feature band in the same major/minor, then its latest patch. |
| `minor` | The nearest compatible minor/feature band in the same major, then its latest patch. |
| `major` | The nearest compatible major/minor/feature band, then its latest patch. |
| `latestPatch` | The highest compatible patch in the requested feature band. |
| `latestFeature` | The highest compatible feature band/patch in the same major/minor. |
| `latestMinor` | The highest compatible minor/feature band/patch in the same major. |
| `latestMajor` | The highest compatible installed SDK. |

Candidates never roll backward from the requested version. A specified version
defaults to `patch`; no specified version defaults to `latestMajor`. Only
`latestMajor` may be explicitly specified without a version. Policy names are
case-insensitive. `allowPrerelease` defaults to `true` for this command-line
tool. An explicit prerelease request enables prerelease matching even when
`allowPrerelease` is `false`, matching the host. Prerelease comparison uses the
host's numeric/ordinal rules, and a stable version sorts after its prereleases.
These rules are tested independently of catalog admission: the current catalog admits no
preview SDK, so accepting a preview request does not make one installable.

## Configuration and ownership limits

The resolver accepts UTF-8 JSON, an optional UTF-8 BOM and `//` or `/* */`
comments. It rejects trailing commas, duplicate properties, incorrect field
types, invalid versions/policies, excessive nesting, unreadable files and files
over 1 MiB. Core version components are bounded to nonnegative signed 32-bit
integers. Numeric prerelease identifiers larger than an unsigned 64-bit integer
are rejected explicitly instead of passing an overflowing value to the native
resolver. Missing or `null` SDK fields are treated as absent. A symbolic link
in the discovered working-directory ancestry or at `global.json` is rejected;
the resolver does not follow a configuration link into another tree.

This strict error behavior is deliberate. The native host can warn and use the
latest SDK after some malformed settings; `cbodotnetup` fails before launching
an SDK so a broken project pin cannot silently choose another version.

The [.NET global.json documentation](https://learn.microsoft.com/en-us/dotnet/core/tools/global-json)
describes ordered custom SDK roots, including paths relative to the file and
the special `$host$` entry. This manager supports `paths` only when it is absent,
`null`, or a nonempty array consisting entirely of literal `"$host$"` entries.
Here `$host$` keeps selection within the manager's verified owned installations.
An empty array, non-string entry, relative or absolute root is rejected with an
actionable diagnostic. Even a path naming another Community archive is not an
admission mechanism. No external directory or symlink is searched for SDKs, and
no official installation is imported.

When no eligible installed SDK matches, the error identifies the configuration,
requested version and policy and gives an explicit signed-catalog installation
action. `errorMessage`, when supplied, adds project context; it cannot replace
the manager's trust or installation guidance. A request that has no admitted
release must wait for separate qualification rather than downloading from an
arbitrary URL. Installed roots still need valid retained signed admission and
an unchanged inventory, and known revocations remain enforced offline. An
offline client learns later revocations only after an explicit catalog refresh.

## One initial SDK choice for CLI and MSBuild

The ordinary .NET muxer begins `global.json` discovery at cwd, while its desktop
MSBuild project resolver can begin at the solution or project directory. This
distinction is documented in the [global.json reference](https://learn.microsoft.com/en-us/dotnet/core/tools/global-json).
Passing a selected wrapper straight to the muxer would also let the muxer reject
an explicitly selected SDK because of a conflicting project request.

For SDK commands, the manager therefore invokes the original authenticated
archive wrapper with `exec <payload>/sdk/<version>/dotnet.dll`. The wrapper
retains its owned native host, architecture-specific roots and compatibility
settings. The manager binds the child's `MSBuildSDKsPath` and
`MSBuildExtensionsPath` to that SDK and removes inherited resolver-directory and
MSBuild-executable overrides. It does not rewrite `global.json` or the SDK.

The SDK's [CLI forwarding implementation](https://github.com/dotnet/sdk/blob/a24d0c644c5ff9f5e1df9b661f1fe8cdf35f253c/src/Cli/Microsoft.DotNet.Cli.Utils/MSBuildForwardingAppWithoutLogging.cs)
uses its own MSBuild and SDK directory; the Linux
[workload resolver](https://github.com/dotnet/sdk/blob/a24d0c644c5ff9f5e1df9b661f1fe8cdf35f253c/src/Resolvers/Microsoft.NET.Sdk.WorkloadMSBuildSdkResolver/WorkloadSdkResolver.cs)
also derives the SDK root from the running CLI. Workload resolution remains
enabled. Project/solution workload metadata does not reselect the initial CLI
SDK. Microsoft documents the relevant host and MSBuild bindings in the
[environment-variable reference](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-environment-variables).

Branding stays **Community Build of .NET (built by .NET Dev)**. With a single
`--version` argument, stdout remains the numeric SDK version and branding goes
to stderr. No arguments and single help/info arguments retain branding on
stdout. `--info` reports the selected managed SDK and its Base Path; it omits
the native muxer's appended Host/runtime/global.json footer. Use the native
list commands for runtimes or SDK directories in the selected payload and
`--cbodotnet-info` for archive identity.

This binds the initial SDK CLI and its MSBuild. It is not a process sandbox:
project targets, installed tools, extensions and applications can explicitly
launch other commands or implement their own configuration rules. Their file,
network and package operations retain the normal SDK behavior. In particular,
the manager does not promise to make a project's NuGet restore offline merely
because its own SDK selection is offline.

## Upstream review and validation boundary

The pinned [dotnetup channel resolver](https://github.com/dotnet/sdk/blob/a24d0c644c5ff9f5e1df9b661f1fe8cdf35f253c/src/Installer/dotnetup.Library/GlobalJsonChannelResolver.cs)
derives installation channels: its default is a feature-band channel, and
several policies derive an exact installation version. It is not the native
installed-SDK matching algorithm and does not use `allowPrerelease` to select
an installation channel. This implementation keeps the existing upstream pin
but independently implements installed-version matching against the host
reference.

An isolated ARM64 architecture probe used Community SDK10.0.403/runtime10.0.14.
The ordinary muxer rejected a cwd pin to SDK9 with `disable`; direct selected
CLI execution reported SDK10. An offline build, MSBuild SDK-path inspection
and application execution also kept SDK10 when a nested project's separate
`global.json` named an external harmless SDK sentinel. No project or SDK
installation files were rewritten by selection. This establishes the launch
strategy, not release admission. Native candidate and anonymous public
qualification remain separate release gates for every advertised OS/CPU/SDK
combination; their final reports determine what can be activated.
