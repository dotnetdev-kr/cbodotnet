# SDK6 source-built MSBuild localization

SDK6 uses the exact MSBuild source commit
`85d71072f8fa22cc761d6b65954da263364bee4d` to build the original localization
project. Its downstream package is `Microsoft.Build.Localization` version
`17.0.4-cbodotnet.1`. The unavailable publisher version
`17.0.4-preview-24422-07` is not recreated or assigned to new binaries.

The original build SDK, `Microsoft.DotNet.Arcade.Sdk` version
`6.0.0-beta.24176.9`, is also unavailable from the original public feeds.
The reviewed build-only patch changes that one declaration in `global.json` to
public version `6.0.0-beta.24204.4`. The worker authenticates the complete
downloaded package by size, SHA-256 and SHA-512 and retains it unchanged.
Its corresponding Arcade source is
`bd9b4590681e602535ed414e98a17e6ba121dca4`. Original product C#, target
frameworks, assembly versions, public key tokens and translation files remain
unchanged.

## Independent evidence

The worker `scripts/musl-legacy6-localization.py` runs the original localization
project with the pinned SDK6 bootstrap, under the normal non-root native
producer mounts. It preserves the original and adapted `global.json`, exact
patch, build commands, actual binary log and raw package inputs.

The separate `scripts/musl_legacy6_localization_inputs.py` contract requires:

- Complete original MSBuild and Arcade Git trees, original licenses and 87
  source/build anchors. The only allowed MSBuild source change is the reviewed
  Arcade declaration.
- The genuine downstream package identity and original MIT declaration. Its
  nuspec has no repository element; no publisher metadata is fabricated.
- All 52 resource-only satellites across the original 13 cultures, with ABI
  `15.1.0.0`, token `b03f5f7f11d50a3a` and original `netstandard1.3` layout.
- Every original resource stream and key set, with all 19,929 compiled strings
  equal to their original XLF translation text.
- Completed replay of the actual build log and a byte-exact package-member
  binding to each actual satellite Csc output and its trusted bootstrap target.
- Separately archived actual compiler inputs, including generated inputs, and
  independent verification that the final SDK consumed these exact members.

The policy is specific to SDK `6.0.136`. Shared helpers decode bytes, XML and
typed task events; SDK7 package versions or source predicates are not reused.
The source-only imported MSBuild root remains separate from the patched
`msbuild-localization` compiler root, even though their original commit matches.

## Verified checkpoint and remaining release gates

The normal worker completed with 72 original Csc tasks and 52 packaged
satellites. An independent source archive round trip checked 6,103 files,
both original Git trees, the exact public build SDK package, all compiler
bindings and all 19,929 XLF strings. Boundary tests reject substituted versions,
invented repository metadata, missing languages and changed build inputs.

This component checkpoint does not admit a release. Actual SDK consumption,
the complete SDK6 source/import closure, both native CPU producers and each
signed public consumer verification remain required by the release pipeline.
