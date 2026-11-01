# Native Linux x64 CI qualification records

Qualification requires actual hosted product builds and complete independent verification of their downloaded SDK/source deliveries. The table distinguishes those results from implementation, fixture and workflow checks. A pending row is not a qualified x64 SDK.

| Profile | SDK | Hosted run | Downloaded delivery |
| --- | --- | --- | --- |
| .NET 10 | 10.0.403 | [41301145771](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41301145771), passed | Independent download verification in progress |
| .NET 9 | 9.0.123 | [41295430879](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41295430879), passed | Independent download verification in progress |
| .NET 8 | 8.0.133 | [41295751388](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41295751388), passed | Passed; [artifact 13081274822](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41295751388/artifacts/13081274822) |
| .NET 7 | 7.0.120 | [41299659746](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41299659746), in progress | Pending |
| .NET 6 | 6.0.136 | [41297567596](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41297567596), passed | Pending independent download verification |
| .NET 5 | 5.0.214 | [41297570076](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41297570076), failed collection metadata | Pending replacement |
| .NET Core 3.1 | 3.1.426 | [41303151426](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41303151426), failed CoreSetup configuration | Pending replacement |
| .NET Core 3.0 | 3.0.103 | [41303153448](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41303153448), failed CoreSetup configuration | Pending replacement |

The [x64 guide](ci-x64.md) describes the native workers, version-specific construction, source delivery and trusted portable verifier. Qualification must bind each artifact to its exact orchestration commit, source revision, run and attempt. Original ARM64 records remain separately available in the [ARM64 results](ci-matrix-results.md).

## Qualified SDK and source SHA-256

| SDK | SDK archive | Source archive |
| --- | --- | --- |
| 8.0.133 | `dc86cedd8f8cf5153e21b21576f3616c01a88f85952789f483f05751304ccad3` | `e5e8d29f9b2272573ddc6e568ba85d925641da2f52a5512e035d7f8e3ac9554a` |

.NET 8's qualified run used orchestration commit `14211bf22a49ca454740780c28c181e880bf7cbf`. Its unchanged SDK archive was 247,823,416 bytes, and its 601,769,524-byte source archive covered 313,832 files in 31 roots. The 1,034,283,728-byte GitHub ZIP matched SHA-256 `6e5c16897f852a7ead3474cb367ba12d673aa7a72764dae29cb174dadf292f6a`; complete independent downloaded delivery verification passed with the expected producer commit, run and attempt.

The original .NET 8 suite had 46 results: 44 passed with the original license-scan and Poison skips. All three user spaces passed six functional checks using stock libraries with no dependency or diagnostic overrides. All 19 SDK ELF files were x64, with maximum requirements GLIBC 2.17, GLIBCXX 3.4.21 and CXXABI 1.3.7. Build took 79m05s, tests 8m42s and user-space verification 115s. During 384 post-preparation whole-runner samples, minimum free disk was 70,925,672,448 bytes and maximum `MemTotal - MemAvailable` was 7,416,115,200 bytes. These observations are not an isolated process-tree peak or a guaranteed minimum capacity.

## Preserved initial failures

| Profile | Initial failed run | Preparation failure |
| --- | --- | --- |
| .NET 7 | [41295753622](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41295753622) | Missing upstream x64 Xenial source list |
| .NET 6 | [41295755838](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41295755838) | Unsupported generator argument selected ARM defaults |
| .NET 5 | [41295758152](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41295758152) | Xenial archive HTTPS trust |
| .NET Core 3.1 | [41295433032](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41295433032) | Xenial archive HTTPS trust |
| .NET Core 3.0 | [41295434962](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41295434962) | Xenial archive HTTPS trust |

The initial .NET 5/Core 3.x runs authenticated the Ubuntu archive but stopped before product compilation because Xenial's initial CA bundle could not verify its current HTTPS certificate. The replacement producer retains and fingerprints the working container CA bundle and requires explicit peer/hostname verification and unchanged package signature verification.

The initial .NET 6 generator silently selected its default ARM target for an unsupported x64 argument. The .NET 7 generator selected amd64 but lacked the requested x64 Xenial source list. Their replacements use an explicit native amd64 producer with the exact pinned upstream package set, authenticated archive, recorded source-list transport adaptation and complete inventories. These failed runs remain failed; replacement runs must independently qualify.

| Profile | Subsequent failed run | Build failure |
| --- | --- | --- |
| .NET 7 | [41297565182](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41297565182) | Bootstrap ILAsm package RID mismatch |
| .NET Core 3.1 | [41297572302](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41297572302) | CoreCLR cross objcopy selection omitted x86_64 |
| .NET Core 3.0 | [41297574501](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41297574501) | Retired MyGet system-commandline index |

These subsequent runs passed the corrected signed sysroot preparation. Core 3.0 then stopped at a retired MyGet system-commandline index with an invalid TLS certificate. Core 3.1 passed its Clang 9/sysroot compiler checks but stopped in CoreCLR's architecture-detection branch. Their retained diagnostic ZIPs independently matched the GitHub API SHA-256 values; safe transport extraction passed and complete delivery verification correctly rejected the missing product/source deliveries. Neither is a qualified SDK.

The subsequent .NET 7 run also passed native preparation. Its source-build reference-package adapter selected a `linux-x64` ILAsm package while the unchanged original bootstrap archive contains the `centos.8-x64` build tool. The bootstrap tool RID and final portable SDK RID must remain distinct. The retained failure is not a qualified SDK.

The bounded corrections add x86_64 to the existing prefixed CoreCLR objcopy selection in the byte-identical Core 3.0/3.1 branches, explicitly preserve the local/official restore policy in Core 3.0's native online Roslyn command, and select the original CentOS ILAsm tool in .NET 7's x64-only adapter patch. They preserve the original project graph, package versions, ARM manifests, TLS verification and portable product target. Exact original Git blobs, patch input/output hashes, MSBuild property evaluation and CMake tool selection were checked before replacement dispatches. Fresh hosted runs and downloaded SDK/source qualification remain required.

The initial [.NET 10 run](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41295429028) completed its product build, all 13 common tests and the 36 original scenarios (34 passed and two original skips). Its subsequent source-binding helper incorrectly read the target RID from Git checkout metadata. Source delivery and native user-space qualification were not reached. Its diagnostic ZIP matched the GitHub API digest, but this failed run is not a complete SDK/source qualification.

The source-binding correction keeps architecture selection separate from Git identity. Complete default-ARM64 and explicit-x64 regressions exercise genuine archive selection with a foreign-architecture candidate, pristine Git identities, both framework markers and the resulting source roots/report. The failed product run remains preserved; its fresh replacement must complete source delivery and native verification independently.

The next [Core 3.0 run](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41299664194) passed Roslyn and native CoreCLR construction, then strictly rejected an approximate external GenAPI version during CoreFX restore. The reviewed local GenAPI producer's target condition still selected ARM64 only. Its x64 correction must retain the exact source/package version, original outputs and native help/reference-generation validation. Required delivery evidence must also establish that the local producer executed. No version approximation or NU1603 relaxation is accepted.

The next [Core 3.1 run](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41299661978) passed its native compiler/ABI checks but encountered the corresponding missing x86_64 objcopy branch in CoreFX. The Core 3.0 and 3.1 fixes extend that exact existing prefixed-tool selection. Full adapter review distinguished the generic local GenAPI producer from the three remaining intentional ARM-specific ASP.NET/CoreSDK overrides; the native x64 defaults for those overrides remain intact.

The corrected Core 3.0 producer retains the original Arcade source package version `1.0.0-beta.19463.3`. Its normal generated version aliases override CoreFX's external `1.0.0-beta.19577.5` default once the local producer executes. Native MSBuild checks covered the real guard and both version aliases. Delivery additionally requires the actual retained nupkg, its source commit and original framework payloads, native bootstrap identity, successful help, real generated reference source and matching execution logs. A full verifier regression exercises package retention through the final JSON report write. These checks do not qualify a product until its replacement hosted run and downloaded delivery pass.

The next [.NET 5 run](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41297570076) completed its product build, full upstream suite and 141,799-file source archive, then stopped because the minimal x64 profile omitted the collector's required coordinated runtime version. All three legacy x64 profiles now declare the original fixed runtime versions 5.0.17, 3.1.32 and 3.0.3. Preparation reuses the actual collector's pinned manifest/layout/runtime contract before image construction; generated component exports remain mandatory during normal collection. Real-contract regression tests cover all six ARM64/x64 profiles, malformed declarations and the distinction between early validation and complete collection.

The subsequent [Core 3.0](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41303153448) and [Core 3.1](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41303151426) failures reached the same missing cross objcopy selector in CoreSetup after successful native compiler/ABI checks. Core 3.0's local GenAPI verifier and CoreFX stage had passed. Exact x64-only CoreSetup patches now select the existing prefixed GNU tool. Full authenticated source review covered all 2,319 Core 3.0 and 2,351 Core 3.1 CMake files with their component patches applied. The three active CoreCLR/CoreFX/CoreSetup selections are covered; the copied Diagnostics selector is dormant because this profile builds its managed client only. No unselected target branch was changed.
