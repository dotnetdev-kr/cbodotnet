# Legacy musl source input review

The source readers in this document verify candidate input evidence. They do
not qualify an SDK, admit a release, or replace native build and consumer tests.
SDK 6, SDK 5 and Core 3 require their own reviewed construction contracts.

[`musl_managed_metadata.py`](../scripts/musl_managed_metadata.py) reads PE and
ECMA-335 assembly identity, source attributes and references as bounded data.
It never loads an input assembly, resolves its references or executes its code.
ReadyToRun metadata can be inspected without disabling ReadyToRun in a consumer.
Native PE files have a separate review boundary; they cannot pass as managed
assemblies through this reader. Tests cover damaged sections, heap pointers,
constructor encodings, duplicate streams and attribute payloads. Development
comparison against a trusted `System.Reflection.Metadata` reader matched all
631 managed DLL/EXE inputs in the actual SDK 7 candidate, including attributes
and assembly references. That comparison is an implementation diagnostic.

A NuGet container identifies byte origin. Its repository metadata alone does
not identify the source of every DLL bundled inside it. Legacy admission must
independently bind embedded component source identities to retained, exact
source roots. A missing source identity remains unresolved until its specific
source chain or readable-data policy has been reviewed. Imported components
are not described as locally rebuilt.

The [additional SDK7 component registry](../scripts/musl-legacy-sdk7-component-sources.json)
pins corresponding sources independently of their NuGet container. The
[registration helper](../scripts/musl_legacy_component_sources.py) expands exact
Git submodules before requesting another clone, then registers nested consumers
before construction evidence is emitted. It uses the producer's recorded clone
boundary. Existing exact submodule sources are reused without a duplicate clone.
Fresh corresponding-source clones retain literal Git blob bytes even when
checkout attributes request different line endings. Per-file materialization
records preserve checkout and retained hashes. This step is confined to new
corresponding-source clones and their nested consumers.

[`musl_legacy_manifest_inputs.py`](../scripts/musl_legacy_manifest_inputs.py)
uses a [closed policy](../scripts/musl-legacy-workload-manifest-policy.json) for
eight immutable SDK 7 workload-manifest packages. Only sixteen unchanged JSON
and MSBuild XML source files may enter their approved SDK layout locations.
The complete original packages, metadata, licenses and all emitted source bytes
are retained as the `workload-manifest-data` tree. JSON comments and trailing
commas are parsed without altering retained bytes or string values. XML entities,
unexpected entries, changed packages, executable inputs and path redirections
are rejected. The source archive must contain all 73 original package and
extracted input files with their exact hashes.

The manifest tree represents readable source actually shipped. It has no Git
commit and makes no claim that publisher Git history was verified. In particular,
the declared Emsdk commit was unavailable from its public Git and official API
when reviewed; no replacement commit was selected. Available upstream templates
and repository facts remain separate investigation evidence. No workload binary
or workload-support claim is authorized by this data policy.

[`musl_legacy_msbuild_resources.py`](../scripts/musl_legacy_msbuild_resources.py)
authenticates the immutable `Microsoft.Build.Localization` 17.4.8 package.
Its 52 satellite assemblies contain resource data only. All 20,280 strings are
compared with their own project's XLF targets from the complete original
MSBuild `6918b863aa37ad0699f98482fbab9f7a52e65a92` source: 19,591 match
exactly and 689 differ only by CRLF/LF. The package, original satellite bytes,
nuspec and decoded text remain retained alongside 78 pinned original XLF files
and the MIT license. Different projects cannot supply substitute translations.
The package's missing repository field is preserved. This policy neither
claims local compilation nor authorizes primary MSBuild implementation DLLs.

[`musl_legacy_compiler_inputs.py`](../scripts/musl_legacy_compiler_inputs.py)
retains every observed `Sources`, `Resources`, `EmbeddedFiles` and
`AdditionalFiles` item from completed Csc/Fsc tasks, including generated
assembly metadata and copied source consumers under `artifacts`. It records
bytes observed after the completed build; compile-time hashing is not claimed.
The independent reader recomputes task coverage from retained binary-log
replays and checks all source copies against the used-source index and archive.
Source-less template metadata compilations are explicit and may not conceal
source operands or response files. They do not establish source compilation
for a primary shipping implementation.
Scalar `GeneratedFilesOutputPath` messages must agree with the actual Csc
command. Their readable generated outputs, including explicitly empty output
directories, receive separate coverage. Two original VSTest aggregate-package
analyzer paths that do not exist in its exact Git tree have explicit observed
absence records. Source and resource inputs cannot use that exception.

The musl CLI uses the .NET MSBuild host. Its scoped layout excludes the two
Full MSBuild `net472` task directories from the SDK and Razor SDK. Mono/Full
MSBuild host task execution is outside this layout's scope. Cross-target
reference packs and `Microsoft.NET.Build.Extensions/net46*/lib` inputs retain
their separate reviewed dispositions. The original VSTest source-build package
targets the Core VSTest host and substitutes its Core `TestHost` layout for the
publisher's `TestHostNetFramework` layout. Full/Mono .NET Framework test execution
is outside this Alpine distribution's scope. This is the original source-build
package's TFM selection; equivalent publisher-wide test-host support is not
claimed. All 114 original Build.Extensions target-library files remain
unchanged in the scoped SDK candidate.

[`musl_legacy_facade_inputs.py`](../scripts/musl_legacy_facade_inputs.py)
uses a [closed literal metadata policy](../scripts/musl-legacy-facade-policy.json)
for 87 unique method-free type-forwarding assemblies from one immutable,
actually restored Build.Extensions package. It retains the original package,
PEs, complete metadata, decoded declarations, readable forwarding IL and MIT
text. Data has a distinct source role with no Git commit or local compilation
claim. A missing original Git object is not replaced with another commit.
Historical layout paths include duplicate Framework test-host locations; only
present, exact reviewed products can use this correspondence. Real executable
implementations, linked resources, methods, fields and native CLI bodies fail
the data-only boundary. Independent comparison with the framework PEReader
matches all 87 metadata blocks, 3,881 exported-type declarations and 1,143
custom attributes, including complete references and scope handles.

[`musl_legacy_globbing_inputs.py`](../scripts/musl_legacy_globbing_inputs.py)
binds the exact Globbing 1.1.1 binary's actual `CommitHash` to complete original
FileSystem sources and the version-declared Common shared C# sources. The
retired shared-source package itself was not recovered; its complete preferred
source and original version declaration are retained. Original binary-license
metadata, the raw publisher license and its corresponding VSTest Git text are
preserved separately from Apache source licenses. An unchanged publisher CLI
package supplies comparison evidence for the identical DLL and raw license;
it supplies no SDK layout member. The closed source/license policy rejects a
missing Common root, changed license bytes or forged source Git blobs.

The metadata layout follows [ECMA-335, Partition II](https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf)
and the pinned runtime's [metadata size calculations](https://github.com/dotnet/runtime/blob/0fb6ac59fb1edbe4ed3ad62661df0eb7eacd7903/src/libraries/System.Reflection.Metadata/src/System/Reflection/Metadata/Ecma335/MetadataSizes.cs).
