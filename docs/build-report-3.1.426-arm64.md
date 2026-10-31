# .NET Core SDK 3.1.426 ARM64 build report

Status snapshot: **2026-10-31, Asia/Seoul**. The full root graph, framework origin audits and complete 52-case upstream suite passed. The unchanged SDK archive was collected. Native Ubuntu 22.04, Ubuntu 24.04 and Debian 13 checks passed with explicitly recorded external dependencies. See the [reproducer](reproduce-core31-arm64.md) for practical commands and compatibility limits.

## Produced archive and source identity

| Field | Actual value |
| --- | --- |
| SDK | `3.1.426` |
| Runtime / ASP.NET | `3.1.32` |
| Target archive RID | `linux-arm64` |
| SDK archive bytes | `164,066,330` |
| SDK SHA-256 | `8fa6c9406a2c38ab98955c83bb8d6908750f9454b61164dfb981951f0bfbbde5` |
| Collected filename | `cbodotnet-sdk-3.1.426-linux-arm64-build.1.tar.gz` |
| Source-build root | `ab8b115b5658237ee8916ae3586600b39fb2fd19` |
| CoreCLR | `c17d273aa03d4b9d14c92248a91f0d0faa881b98` |
| CoreFX | `b58ef0a19eca6269799664d6288be14b7f0cef3e` |
| CoreSetup | `f94bb2c3ff432dcc4a6229eca2f978197bf06150` |
| ASP.NET | `3eeb12e106b9e913c3a4dec1a7d16da7b74149eb` |
| CoreSDK | `e81f6c85654f91c5eab0cb78386db4b32df63b4b` |

The source-build `release/3.1` root coordinates the final published SDK version. This is the direct legacy source-build route, with separate runtime components. The recorded acquisition retained 30 complete exports for 31 declarations, full-history root metadata, bare stores and original inventories.

## Environment, fixes and completed build

The native ARM64 host used the D-backed WSL 2 distribution `cbodotnet-net7-arm64`, user `build`, UID:GID `1000:1000`, and isolated workspace `/home/build/cbodotnet/core31`. No CPU emulation was used.

The Focal builder used official digest `sha256:a4028735b2ed1209c9116cebc74ae1c2fb27ea7d24b1be3f495fee0bac27dd52`, derived image `ab750d90bdf890c078039cf6f52d3dd44862f3df8f6cdaf4ea771a802e18e3a0`. LLVM 9 compiler/tool aliases include `llvm-objdump`. The previous derived image without that alias and its failed native configuration remain recorded.

The independent Xenial sysroot contains 17,026 file records and 5,225 symlinks. Signature verification remained enabled; four retained `InRelease` files and nine required development-package checks passed. The preserved producer succeeded before a wrapper postcondition rejected its actual successful signature wording. A strictly scoped finalizer authenticated that exact log and completed target without rerunning debootstrap or waiving any package requirement.

Eleven guarded changes address target forwarding, same-architecture native crossgen and packaging, explicit source acquisition, five retired feed indexes, old shell argument splitting, complete silent CMake cross-probe metadata and the forced legacy bootstrap HTTP handler. Earlier patch manifests and failed attempts remain retained. No component build, native-image generation or package-creation guard was disabled.

The official SDK base's inherited `NUGET_XMLDOC_MODE=skip` was overridden with `none`. The verified cache recovery preserved 322 package directories and restored from byte-identical retained archives. Canonical signed-package hash verification passed for 231 packages through SDK `3.1.422`'s NuGet API. An earlier attempt's cross-device rename was retained; using one whole workspace bind fixed atomic preservation without changing package bytes or the quarantine protocol.

Successful root attempt **`build-20261030T1846197895069Z`** completed with exit code **0**, reported duration **2 minutes 39.29 seconds**, **17 warnings** and zero errors. This final retry reused the already completed native and component outputs; it is not a clean-build timing measurement. The preceding attempts, native logs, exact patches and original image/input provenance are retained.

## Both shared-framework origins passed

The final SDK's shared-framework contents match the selected local archives without missing, additional or changed entries: **188 runtime entries and 140 ASP.NET entries**. The comparisons are recorded in `reports/construction/framework-comparison/shared-framework-identity.json`.

The runtime archive is 86,589,039 bytes, SHA-256 `1ec534baf77b4b2af35eebb9a215f086840153ebf4047b9b9f8d7266dcc18557`. ASP.NET's original internal archive is 8,188,620 bytes, SHA-256 `89e7684c4e9543fac1fe1d238baae7c3bf20d1b23421bcd1ec5e159bca93e54c`. Producer/archive/destination hashes are retained in `reports/construction/retained-core-sdk-inputs.json`.

The actual CoreSDK downloads remain under its `artifacts/obj/redist/Release/downloads`. Runtime publication comes from CoreSetup's direct assets output and local `blobs/Runtime/3.1.32` path; ASP.NET publication comes from its original component installer archive and `blobs/aspnetcore/Runtime/3.1.32`. The absence of a second ASP.NET assets-feed copy is recorded explicitly.

The closed CoreSDK binlog, 2,932,053 bytes, SHA-256 `269b234e342b8ff3c03e68ab94465b0055b0284742cf715442ef3363fe42c66a`, replayed **32,761 events** without evaluating a project. It produced two completed framework `DownloadFile` tasks and 12 execution-evidence events. Each framework had one sole local `Copying` attempt with a successful finish, matching retained destination bytes and no accepted network attempt. `reports/construction/origin-evidence.json` passed for this exact SDK hash.

The replay tool's initial offline compilation used SDK `9.0.121` and produced zero warnings/errors. Its compile transcript, source and binary hashes are preserved. That first compilation omitted a private `HOME` and displayed SDK developer-certificate initialization; no existing certificate store was cleaned. The actual final replay used a private native `/tmp` home, CLI state and runtime directory of mode `0700`, with automatic certificate generation disabled.

## Split runtime construction passed separately

`reports/construction/native-component-origin.json` binds **180 selected runtime/archive/SDK members** to the actual local component pipeline:

- Three component-produced CoreCLR/JIT/CoreFX packages match the root feed, actual CoreSetup cache archives and resolved asset SHA-512 values.
- All 164 CoreFX managed package assemblies match their local CoreFX outputs and restored inputs. Of these, 162 passed through completed CoreSetup native-image generation; those generated files match the runtime and SDK members.
- Thirteen native/CoreLib payloads match the actual CoreCLR/CoreFX outputs, packages, restored inputs and final runtime/SDK members.
- Three CoreSetup host outputs match their final `dotnet`, hostfxr and hostpolicy members.

CoreLib's IL input is **3,139,584 bytes** and its native output is **11,648,512 bytes**, with different hashes. The actual crossgen executable is ELF64 AArch64, and its preserved log records both native-image and perf-map success. This proves that the packaged CoreLib did not come from the old IL-copy fallback.

These comparisons supply component construction evidence in addition to the complete shared-framework tree comparisons. They do not establish that every tool, reference assembly, bootstrap SDK or package used by those builds was itself rebuilt locally.

## Prebuilt findings remain visible

The original upstream report schema records **7,126 raw and annotated usage rows**, **263 generated-baseline usage rows**, **one new baseline entry** and **86 removed entries**. The new entry is `Microsoft.NETCore.Platforms/3.0.0-preview9.19416.11` in the actual CoreFX external.runtime assets.

The root warnings also identify Arcade SDK/SignTool cache entries without matching origin nupkgs. They report 52 forbidden test usages from one preserved acquisition-staging asset file. That file is byte-identical to the committed NuGet.Client `e3675c6173f0e3e4f13272c814ff33c590defba9` unit-test resource: 156,766 bytes, SHA-256 `38c3a29c2a077b686707b74408d0ad4af4f96eaf45760cc8863698d2e1adb921`. The contextual fixture proof does not remove the original rows, other production findings or baseline differences.

The prebuilt audit preserves **132 original report files**, the pinned unchanged online baseline, **41 project-directory entries**, **33 package snapshots** and **489 archived project.assets.json members**. These describe scanner coverage and classification; they are not a count of all binaries used or a clean-bootstrap certificate.

The upstream warning/continuation policy remains unchanged. No generated baseline was installed to make the report clean. The source-only online build still uses an official bootstrap SDK, reference packages and other binary dependencies.

## Complete upstream smoke suite passed

Attempt `test-20261030T1918428256883Z` ran from `2026-10-30T19:18:43Z` to `2026-10-30T19:31:29.632381Z`, about **12 minutes 46.63 seconds**, exit code zero. It completed all **52 template starts and finishes**, **28 web startup-ready markers**, **two HTTPS certificate setups**, both local/online source passes and the final success marker. No test category or case was excluded.

The fresh SDK check matched all **1,789 regular-file/symlink entries** after suite execution. The test-only certificate adaptation used the SDK's built-in tool with its recorded source/package identities; every byte outside that setup function remained pinned. The archive `upstream-smoke-outputs.tar.gz` retains **228 original files**, 112,116,542 bytes, SHA-256 `01afc4922a4310483c5ea3c3f0ac93581044366ef8597c45bd1d72182d302e54`.

The first two Test attempts failed in preparation and executed zero suite cases. One exposed two identical `packageIcon.png` entries in four newly source-built Web SDK packages; the cache guard's exception is limited to those exact 7,006-byte icon copies. The next exposed one Python 3.8 GNU long-name directory header ending in `/`. Extraction now normalizes one trailing slash only for directory entries. Strict file/link/path and normalized-duplicate guards remain; the actual Focal preparation fixture passed 21 checks. The SDK archive was unchanged throughout.

## Native matrix and final collection

The exact archive passed six independent checks on native Ubuntu 22.04: console DLL and apphost execution, RSA SHA-256 signing/verification, cryptographic random bytes, `fr-FR` decimal formatting and ASP.NET loopback HTTP. The reported host RID was `ubuntu.22.04-arm64`. Inspection found **19 AArch64 ELF files**, with maxima **GLIBC `2.17`, GLIBCXX `3.4.21` and CXXABI `1.3.7`**. The selected SDK GLIBC ceiling `2.23` passed.

This run used the separately verified Focal OpenSSL 1.1 library/configuration bundle from the original .NET 5 verification contract, without modifying the SDK. The bundle's libcrypto additionally requires GLIBC `2.25`; that is an external verification dependency, not a member of the SDK archive or its measured ELF ceiling. Its source-image, package/file identities and consumer prefix remain part of the evidence. These results do not establish stock OpenSSL-3-only Ubuntu compatibility.

| User space | Actual reported RID | Functional checks | ICU dependency |
| --- | --- | --- | --- |
| Ubuntu 22.04 ARM64 | `ubuntu.22.04-arm64` | 6 passed | Native ICU 70 |
| Ubuntu 24.04 ARM64 | `linux-arm64` | 6 passed | Native ICU 74 |
| Debian 13 ARM64 | `linux-arm64` | 6 passed | Separate verified Focal ICU 66 |

All three used the explicit OpenSSL 1.1 bundle and the same SDK hash. Each recorded 19 AArch64 ELF files and maxima GLIBC `2.17`, GLIBCXX `3.4.21` and CXXABI `1.3.7`. They share the WSL kernel and do not establish every kernel, `dlopen` dependency or workload requirement.

The initial Debian run stopped at `dotnet --info` because its stock ICU 76 was outside the old loader's automatic search. The pinned CoreCLR shim uses the compile-time ICU 55 major plus 20, giving a maximum of 75. The failed `reports/verify-debian13/` remains intact. No SDK code, invariant-globalization switch or archive was changed.

The retry supplied three unmodified ICU libraries and copyright from exact builder `ab750d90bdf890c078039cf6f52d3dd44862f3df8f6cdaf4ea771a802e18e3a0`, package `libicu66` `66.1-2ubuntu2.1`. Original source SONAME symlinks, package ownership, ELF requirements and hashes are retained in `reports/verification-icu-export/core31-verification-icu.json` and `reports/verification-icu/compatibility-inputs.json`. The latter is 9,188 bytes, SHA-256 `dab6517bb1e4305733cd818da514a16acc4c87b6ab0d0b81e41fbc3448ddafb1`.

The ICU prefix is mounted read-only and selected explicitly with `CLR_ICU_VERSION_OVERRIDE=66`, alongside the separate OpenSSL prefix. Real `fr-FR` formatting and all other checks passed at `2026-10-30T19:43:12.428264Z`; reports are in `reports/verify-debian13-icu66/`. The uc/i18n libraries require at most GLIBC `2.29`, an external verification dependency distinct from the SDK's own ELF ceiling. Ubuntu 22.04/24.04 need no extra ICU prefix.

Final collection copied the original **164,066,330-byte** tarball without modification and produced `build-manifest.json`, `SHA256SUMS` and `SHA512SUMS`. Construction is now an explicit verified declaration in the public profile; collection still does not infer test success from report presence. The per-run origin tools, original failures and dependency contracts remain available for review.

| Check | Result at this snapshot |
| --- | --- |
| Full root graph | Passed |
| Complete framework comparisons and completed local consumption | Passed |
| Split CoreCLR/CoreFX/CoreSetup construction audit | Passed: 180 selected final members |
| Original prebuilt/conflict data | Nonzero findings; preserved without changing policy |
| Full 52-case upstream shell suite | Passed, including local/online and HTTPS cases |
| Independent native Ubuntu 22.04 functionality and ELF ABI checks | Passed with explicit OpenSSL 1.1 dependencies |
| Native Ubuntu 24.04 / Debian 13 checks | Passed with the explicit dependency contracts above |
| Unchanged final collection/checksums | Passed |
| Offline Stage 2 / poisoning / clean bootstrap | Not performed |

The original runtime's external OpenSSL/ICU policy remains relevant for consumers. No universal Linux, stock OpenSSL-3-only or stock Debian 13 ICU 76 compatibility claim follows from these controlled checks.
