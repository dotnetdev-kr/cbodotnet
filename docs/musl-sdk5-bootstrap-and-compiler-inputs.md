# SDK5 compiler bootstrap and imported compiler inputs

SDK5's regular producer uses two separate compiler bootstraps. Native runtime,
SDK, NuGet and installer projects select the original SDK5.0.401. The original
VSTest graph selects SDK6.0.135; SDK6 also runs the read-only binary-log and
translation inspection tools. This does not retarget the product projects.

`musl_legacy5_bootstrap.py` reconstructs the SDK5 compiler bootstrap from the
closed official SDK5.0.401 and runtime5.0.17 archive pins. Every original SDK
file remains unchanged. The matching runtime is a separate recorded addition,
with its original CoreCLR, JIT, DAC and DBI preserved byte for byte. Exactly two
support libraries are replaced by recorded SDK-free source builds: stock
OpenSSL3 crypto and stock LTTng-UST1 tracing support. Their actual source worker
commands, inputs, outputs, licenses and fingerprints remain explicit. This is a
derived compiler bootstrap; it is not described as an unmodified publisher SDK
tree. No earlier private SDK archive is an input.

The actual reconstruction receipt is
`.build/sdk5-bootstrap-official-reconstruction-v2/results.json`. Its 2,780
original SDK files and 186 matching framework files passed retention checks.
The separate `managed-selection-v1/results.json` records successful SDK5.0.401,
runtime5.0.17 and MSBuild16.11 execution under the standard container security
settings. These ARM64 observations do not establish an x64 result.

`musl_legacy5_compiler_inputs.py` creates three local inputs from the authenticated
matching SDK5.0.214 musl archive. It preserves the original file bytes and native
ReadyToRun headers. Native ReadyToRun architecture and the actual RTR header
are checked; foreign images, header stripping and ELF payloads are rejected.

| Local input | Original component source | Scope |
| --- | --- | --- |
| Microsoft.FSharp.Compiler11.3.2-beta.21102.9 | fsharp7ce7132f1459095e635194d09d6f73265352029a | Every owned asset in the original nuspec, original dependency/content contracts and thirteen resource cultures |
| Microsoft.Net.Compilers.Toolset3.9.0-6.21273.1 | roslynf8111b17631aa5e2703dc11acd671c6ea22c3af1 | Complete SDK CoreCLR compiler subtree and original build props; desktop/net472 compiler payload is not provided |
| Microsoft.CodeAnalysis.VisualBasic.CodeStyle3.8.0-5.20519.18 | roslyn4c195c3ac1974edcefa76774d7a59a2350ec55fa | Exact VB/shared IL-only analyzers, resource cultures and original source props |

Each input is explicitly a local derived package. It does not impersonate an
original publisher NUPKG or claim the compiler was locally built. Full preferred
Git source roots, original package definitions and license/notice files are
retained separately from the imported SDK bytes.

Fresh producer checkouts use explicit component modes before compilation.
NuGet and the other managed components retain their reviewed canonical Git
byte contract. The native runtime keeps its original declared Windows
checkout encoding: only `.cmd`, `.bat` and `.sln` files with original
`eol=crlf` attributes may differ from their Git blobs, and recovering uniform
LF must reproduce the exact blob. All other runtime bytes remain exact.
The helper never rewrites an existing build attempt. Four small Git-clone
tests and the actual fresh 56,719-file runtime checkout in
`.build/sdk5-runtime-checkout-mode-v6/results.json` passed without executing a
compiler; all 310 original Windows files remained unchanged and Git's native
pristine-source precondition passed.

Roslyn's three framework dependencies remain separately attributed to runtime
cf258a14b70ad9069470a108f13765e0e5988f51. Their exact original5.0.0 NUPKGs are
pinned and retained inside the provenance inputs. SDK ReadyToRun files are not
claimed byte identical to NUPKG IL files. The preparation helper checks assembly
identity, attributes, references and definition counts against the appropriate
original member. Only the ordering of complete AssemblyMetadata key/value
pairs is normalized; duplicate pairs and values remain significant. This is a
source-chain observation, not a claim of a complete IL or native-code comparison.

Actual ARM64 preparation passed at
`.build/sdk5-public-derived-compiler-inputs-v3/results.json`: 93 F# SDK members
(86 managed),71 Roslyn members (62 managed), and56 VB CodeStyle members
(56 managed). Earlier v1/v2 failed checks are preserved. Seven focused tests
cover official archive pins, confined paths, foreign ReadyToRun architecture,
embedded source identity, metadata pair boundaries and honest local package
metadata.

`musl_legacy5_replay.py` preserves every compiler process and its original event
contexts. The unchanged reader returns1 when it observed no selected tasks.
Only four original VSTest stages can legitimately have that outcome; their
complete build success, input binary-log hash and zero unfinished tasks are
still required. The original reader result is retained rather than relabelled.

The independent native leaf has also passed against an actual complete source
packet: `.build/sdk5-native-source-contract-v6/revalidation-v3.json` binds all
six ELF products and their debug sidecars, 1,602 compiler commands, 56,719
original runtime files and 508 generated source files. It recovers the seven
reviewed changed files to their original Git blobs. This isolated source
observation does not establish final SDK consumption or complete producer
admission.

These inputs and the version-isolated producer remain unqualified. The complete
construction inventory, all imported and generated corresponding source,
normal producer boundaries and both native CPU builds still require independent
admission before public SDK5 publication. Distribution branding remains the
existing wrapper contract; original producer assembly metadata is preserved.
