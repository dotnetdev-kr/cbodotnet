# Linux ARM64 and x64 SDK version floor

Research date: **2026-10-31, Asia/Seoul**. This is a source and release-metadata assessment. It does not add a completed .NET Core 2.x build, an x64 validation result, or a new release policy.

## Finding

**.NET Core 3.0 is not a hard technical minimum for producing Linux ARM64 and x64 SDKs.** Microsoft's release metadata already contains both architectures for the .NET Core 2.1 release line, including stable SDK **2.1.300**, and for .NET Core 2.2. Core 3.0 marks the supported and feature-complete Linux ARM64 transition described by upstream maintainers. It is also this project's oldest locally built and validated ARM64 SDK generation.

These are different boundaries:

| Question | Evidence-based answer |
| --- | --- |
| Earliest stable release line with published SDK archives for both Linux architectures in the inspected metadata | .NET Core **2.1**, starting with SDK **2.1.300** on 2018-05-30 |
| First upstream supported and feature-complete Linux ARM64 generation in the inspected maintainer record | .NET Core **3.0** |
| Oldest SDK generation this project has rebuilt and validated on ARM64 | .NET Core **3.0**, SDK 3.0.103 |
| Oldest generation this project has rebuilt and validated on both architectures | Not established: the current project measurements cover ARM64; x64 needs independent build and native validation |
| Lower boundary for a future community experiment | Core **2.2**, then **2.1**, have concrete upstream SDK/bootstrap and source evidence; neither is a completed project profile |

Microsoft support status is evidence about historical engineering coverage. It does not determine community inclusion, and Microsoft's support lifecycle is not a reason to exclude an older version from investigation.

## Published artifacts before 3.0

The inspected release metadata is pinned to `dotnet/core` commit **01914ed2ae6d90431de09928423e517fcf639f70**. The SDK check examines the actual `sdk`/`sdks` file objects with `rid=linux-arm64` and `rid=linux-x64`, rather than inferring SDK availability from runtime entries or a generic download-page label.

| Core release line | Linux ARM64 SDK evidence | Linux x64 SDK evidence | Interpretation |
| --- | --- | --- | --- |
| 1.0, 1.1 | No ARM64 SDK entries in the inspected release metadata | Published x64 SDKs | No established dual-architecture SDK route from these release manifests; this does not prove an independent port impossible |
| 2.0 | No ARM64 SDK entries in its 15 recorded releases | Published x64 SDKs | Below the published ARM64 SDK boundary found in this review |
| 2.1 | Stable 2.1.300; later 2.1.818 and 2.1.526 entries include ARM64 archives and SHA-512 hashes | Matching SDK versions have x64 archives | A real SDK implementation and bootstrap candidate exists before 3.0; project reconstruction and functionality remain unmeasured |
| 2.2 | Stable 2.2.100; later 2.2.207 and 2.2.110 entries include ARM64 archives and SHA-512 hashes | Matching SDK versions have x64 archives | A concrete next legacy source-build investigation |
| 3.0 | SDK 3.0.100 and later ARM64 archives; ARM64 ASP.NET runtime entries also exist | Matching x64 archives | Broader upstream ARM64 coverage and the oldest completed local ARM64 generation |

Sources: pinned release metadata for [1.0](https://github.com/dotnet/core/blob/01914ed2ae6d90431de09928423e517fcf639f70/release-notes/1.0/releases.json), [1.1](https://github.com/dotnet/core/blob/01914ed2ae6d90431de09928423e517fcf639f70/release-notes/1.1/releases.json), [2.0](https://github.com/dotnet/core/blob/01914ed2ae6d90431de09928423e517fcf639f70/release-notes/2.0/releases.json), [2.1](https://github.com/dotnet/core/blob/01914ed2ae6d90431de09928423e517fcf639f70/release-notes/2.1/releases.json), [2.2](https://github.com/dotnet/core/blob/01914ed2ae6d90431de09928423e517fcf639f70/release-notes/2.2/releases.json) and [3.0](https://github.com/dotnet/core/blob/01914ed2ae6d90431de09928423e517fcf639f70/release-notes/3.0/releases.json).

The release-line distinction matters: not every SDK whose version starts with `2.1` belongs to the Core 2.1 runtime generation. Use the coordinated SDK/runtime release record; the first stable Core 2.1 SDK here is **2.1.300**.

During this review, HTTP HEAD requests to the official **2.1.300** and **2.2.207** Linux ARM64 SDK archive URLs returned **200**. This checks current endpoint availability only. No archive was downloaded, hash-verified, extracted, or executed for this assessment; HTTP success is not proof of usable SDK contents. The earlier 2.2.207 x64 archive used as a template-only input for Core 3.0 remains separate from any Core 2.x product build.

## Why 3.0 is a stronger baseline

The upstream [ARM64 status issue](https://github.com/dotnet/runtime/issues/11042) explicitly records initial ARM64 work in 2.1, the absence of ARM64 maintenance on 2.x branches, and concentration of ARM64 improvements in 3.0. A maintainer identifies 3.0 Preview 1 as providing both the Linux ARM64 runtime and SDK; the issue was closed as feature-complete for 3.0. The [3.0 release announcement](https://devblogs.microsoft.com/dotnet/announcing-net-core-3-0/) identifies supported Linux ARM64 operation and its kernel requirement. This describes architecture engineering coverage at the time, separately from today's end-of-support dates.

This difference had functional consequences. [Runtime issue 10933](https://github.com/dotnet/runtime/issues/10933) records ARM64 compiler crashes in Core 2.1 and 2.2 SDKs, including a diagnosed JIT argument-layout bug. Upstream maintainers state that ARM64 was outside 2.x support and close the issue on that basis. This historical report does not establish that every later 2.x binary fails, or that a community backport cannot fix the problem. It establishes that archive publication alone is insufficient acceptance evidence.

The 2.1 and 2.2 metadata also contains no ARM64 `aspnetcore-runtime` archive entries, while 3.0 does. That is a packaging and coverage difference, not proof that managed ASP.NET applications or a community ASP.NET build cannot work. A profile promising the current SDK, core runtime, ASP.NET runtime, tools and native tests must establish those components explicitly.

## The older source-build route needs separate work

The inspected `dotnet/source-build` **release/2.2** revision is **2ea940c21cfb258ad514660d856b558655ea1f92**, whose update targets SDK **2.2.109**. This selection differs from the latest SDK across feature bands and from the separate 2.2.207 bootstrap/archive example.

Its original [CLI adapter](https://github.com/dotnet/source-build/blob/2ea940c21cfb258ad514660d856b558655ea1f92/repos/cli.proj) builds the SDK through `Prepare;Compile;Package`. It predates the later CoreSDK packaging adapter. The adapter accepts the target RID and locally built CoreSetup input, demonstrating an SDK construction path rather than only a runtime build.

However, the default [known-good graph](https://github.com/dotnet/source-build/blob/2ea940c21cfb258ad514660d856b558655ea1f92/repos/known-good.proj) selects only `core-setup` for ARM platforms, while its other branch includes CLI, SDK, MSBuild, Roslyn and FSharp. A successful default ARM build would therefore not establish a complete SDK build. The CLI adapter also disables the ASP.NET runtime and bundled dotnet tools. Those original exclusions must be recorded or replaced by separately verified construction; they cannot silently satisfy this project's existing completeness claims.

The graph restriction is not unique to 2.x: the original [Core 3.0 known-good graph](https://github.com/dotnet/source-build/blob/40de72d1087a1d05dfd39c87f888a0611ec6c60f/repos/known-good.proj) also stops at CoreSetup for ARM. This project's completed 3.0 work explicitly selected `RootRepo=core-sdk` and introduced reviewed native adaptations. Consequently, a restricted default graph is a bring-up requirement, rather than proof that an older SDK cannot be built. Core 3.0's stronger baseline comes from its upstream architecture maturity, broader product graph and the project's actual validation results.

The declared [bootstrap SDK](https://github.com/dotnet/source-build/blob/2ea940c21cfb258ad514660d856b558655ea1f92/DotnetCLIVersion.txt) is **2.1.504**. The original [bootstrap script](https://github.com/dotnet/source-build/blob/2ea940c21cfb258ad514660d856b558655ea1f92/init-tools.sh) recognizes `aarch64`, selects ARM64 inputs, and permits an explicit `DotNetBootstrapCliTarPath`; it also emits an unsupported-CPU warning. These capabilities justify an experiment, not a claim that its full ARM64 graph works unchanged. Retired feeds, component histories, old build tools, native crossgen, signed sysroots and runtime/compiler defects require version-specific review.

The pinned [2.2 CLI driver](https://github.com/dotnet/cli/blob/586f23c400725c4677f266a3c1cea0b2bcf076e0/run-build.sh) defaults its architecture to x64, and its [crossgen properties](https://github.com/dotnet/cli/blob/586f23c400725c4677f266a3c1cea0b2bcf076e0/build/CrossGen.props) select x64-host tools for ARM64 targets. Native ARM64 execution needs explicit host/tool selection changes. The corresponding [CoreCLR build](https://github.com/dotnet/coreclr/blob/3ff59088019cc8ff4ddf857f7b1e4d2af2e010af/build.sh) already contains ARM64 host and runtime support; this is a legacy graph and tooling integration problem, rather than evidence that a new ARM64 instruction-set port is required.

The inspected Core 2.1 serviced source revision **388a313f566b9d7e1272f4d010e67ca7c67a0db2** targets SDK **2.1.526**, separately from the 2.1.818 metadata example. Its [known-good graph](https://github.com/dotnet/source-build/blob/388a313f566b9d7e1272f4d010e67ca7c67a0db2/repos/known-good.proj) has the same ARM restriction, and its [bootstrap script](https://github.com/dotnet/source-build/blob/388a313f566b9d7e1272f4d010e67ca7c67a0db2/init-tools.sh) defaults to x64 inputs. An explicit bootstrap archive override exists, but a native ARM64 bootstrap and the complete graph still require their own implementation and verification. Later published SDK versions must not be attributed to these older source revisions without checking their coordinated component versions.

## Acceptance and next step

Keep **3.0 as the currently demonstrated ARM64 baseline**, while treating **2.1 as the earliest published dual-architecture SDK candidate found**. Investigate **2.2 first** because its complete SDK adapter and ARM64 bootstrap selection are concrete and closer to the completed 3.0 environment. Then assess 2.1 against its own pinned graph. This is a research sequence, not a decision to exclude 2.1 or earlier community ports.

Before advertising an older version as a verified two-architecture release:

1. Pin the source-build revision, coordinated product versions, patches and authentic bootstrap inputs for each architecture.
2. Prove which graph produces the complete SDK, core runtime, ASP.NET runtime and included tools, documenting any intentional scope differences.
3. Build and run the SDK on native ARM64 and native x64, including compiler, language/template, application, crypto, globalization and upstream tests.
4. Preserve local component origins, actual archive bytes, dependency requirements, ELF architecture/ABI results, checksums and delivery manifests for both targets.

A newer x64 SDK cross-publishing an application for an old ARM64 runtime, an ARM32 SDK running on an ARM64 CPU, or an old SDK hosted on a substituted newer runtime does not by itself establish the corresponding version-coherent native ARM64 SDK distribution. The established [version coverage](dotnet-version-coverage.md) and [Core 3.0 build report](build-report-3.0.103-arm64.md) retain their actual measured scope.
