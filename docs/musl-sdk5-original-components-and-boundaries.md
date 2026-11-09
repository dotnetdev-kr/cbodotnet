# SDK5 original components and worker boundaries

`musl_legacy5_component_inputs.py` checks every original SDK, NuGet and VSTest
Git file against the authenticated tree. The actual roundtrip in
`.build/sdk5-original-component-source-contract-v2/results.json` covers
2,760 SDK files with three exact declared changes, 4,951 NuGet files across
four Git roots with one reviewed patch, and 1,773 pristine VSTest files.
NuGet's derived driver must select exactly the original nineteen XPLAT
projects. Added files, deletions, source exclusions and arbitrary C# or target
edits cannot replace this full-tree correspondence.

Git applies the reviewed NuGet Pack project patch using the original CRLF
checkout rule. The validator permits uniform CRLF recovery only for that
specific XML target, then requires its complete reversed file to equal the
original Git blob. It preserves the actual source archive bytes. Mixed
encoding and other paths are rejected; compiler worktrees are never rewritten
by the validator.

`musl_legacy5_boundaries.py` checks exact source-worker command envelopes,
including the explicit bootstrap role, readonly bootstrap mounts, image,
network, environment, workdir and source mounts. Private Podman observations
are distinguished from normal producer boundaries. The current actual
prepare-only checkpoint in `.build/sdk5-worker-boundary-controls-v1/results.json`
covers three private preparation workers and thirteen mutation controls. It
uses an explicitly diagnostic path projection and does not claim a complete
source manifest or Reader provenance.

The installer envelope carries both `_InitializeDotNetCli=/bootstrap` and
`DotNetBuildFromSource=true`, alongside its existing install directory and
package cache variables. The first selects the original `tools.sh` early
return and `/bootstrap/dotnet` MSBuild tool. The second reaches the original
shell `restore-toolset.sh` source-build branch, which skips the optional
.NET 2.1.0 test toolset. An MSBuild property alone does not select that shell
branch. The offline probe sources both original scripts and confirms the
pinned SDK 5.0.401 and runtime 5.0.17 before the actual installer command.

The separate private installer-only v7 attempt passed in 115.97 seconds using
a fresh installer checkout and independently checked readonly v4 inputs.
Every reused input's length, SHA-256, SHA-512 and mode agreed before and after
execution. The earlier v4, v5 and v6 failures are retained. This suffix is a
partial development check; it does not establish a successful whole private
producer or a normal producer run.

The separate Reader guard checks copied source and clear NuGet configuration,
the offline SDK6.0.135 inspection-tool build, all fifteen original replay
invocations, and the full fingerprints of the original inputs and outputs
consumed by component evidence. Its actual complete positive remains pending;
private v4 stopped before Reader execution. Validation reparses serialized evidence and does not
execute the binary Reader again. These helpers are not a normal SDK5 admission
route and grant neither qualification nor publication permission.
