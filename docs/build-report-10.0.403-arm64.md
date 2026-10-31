# .NET SDK 10.0.403 Linux ARM64 build report

As of 2026-10-28, Asia/Seoul. **SDK build and validation completed.** Execution checks passed in three ARM64 user-space environments, all 13/13 VMR common tests passed, and template scenarios recorded 34 passes, 2 skips, and 0 failures.

## Selected inputs

| Item | Pinned value |
| --- | --- |
| SDK | 10.0.403, the latest stable 10.0.4xx release when checked |
| VMR tag / SHA | `v10.0.403` / `5a2162bea6845eabc1fc721624a43568c65db3b1` |
| Corresponding 1xx | `v10.0.114` / `0427b9abbead3fa64c6655eb4290c537397131fa` |
| Bootstrap SDK | 10.0.401, Linux ARM64 |
| Shared runtime | Upstream portable 10.0.14, using the VMR-pinned `10.0.14-servicing.26522.126` input |
| Host / target | Linux ARM64 / `linux-arm64`, without x64 emulation |
| Base image | `mcr.microsoft.com/dotnet-buildtools/prereqs:ubuntu-24.04-arm64` |
| Base image digest | `sha256:7ef8f6ee1b9982511349757443eb4844f0db4f8cef1aff6148a7ba1c25d7c6f4` |
| Final derived image ID | `92f8771e40e362c7417be68f4a257fe58d83c060abfcdd8c86f8f423c2bc245e` |
| Compiler / CMake | ARM64 clang 18.1.3 / CMake 3.28.3 |
| Sysroot | ARM64 Bionic, targeting a glibc 2.27 baseline |
| Build mode | Standard VMR build, `sourceOnly=false`, `CrossBuild=true`, `PortableBuild=true` |
| Build identity | `--branding release --official-build-id 20261028.1` |

Sources for these selections: [official release](https://github.com/dotnet/dotnet/releases/tag/v10.0.403), [tag SHA](https://api.github.com/repos/dotnet/dotnet/git/ref/tags/v10.0.403), [bootstrap configuration](https://github.com/dotnet/dotnet/blob/v10.0.403/global.json), [shared inputs](https://github.com/dotnet/dotnet/blob/v10.0.403/eng/Version.Details.xml), and [.NET 10 libc baseline](https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.json).

## Environment prepared

- Installed Podman, Skopeo, and validation tools in the existing Ubuntu-22.04 WSL 2 distribution. The WSL version, memory settings, and VHD location were not changed.
- Pinned the official ARM64 prerequisite image by digest and confirmed that it runs natively on ARM64.
- Added LLD and the Python dependencies for rootfs generation through the [.NET 10 Containerfile](../containers/arm64-net10.Containerfile). The recipe was subsequently given this versioned filename without changing its contents. The environment reports record the actual additional package versions.
- Cloned the VMR to `/home/rkttu/cbodotnet/work/dotnet-v10.0.403` in WSL and verified its SHA.
- Used the rootfs generator from the selected tag to verify the Release signatures and checksums of ARM64 Bionic packages and extract the sysroot. No chroot, QEMU, or x64 execution was used.
- Ran container builds as a regular user with the same UID/GID as the WSL file owner. After NuGet downloads failed with the initial parallelism of 6, retries used build parallelism of 2 and a limit of 8 concurrent requests per feed.

Explicit cgroup resource limits failed with Podman 3.4.4 in WSL, so containers run with `--cgroups=disabled`. No separate container RAM limit was applied; execution remains within WSL's approximately 15GiB limit. Resource usage and free space on the host drive are monitored.

The first attempt failed after approximately 23 minutes because several Azure NuGet mirror requests timed out or returned incomplete ZIP files. Roslyn's PowerShell 7.6.0 failure was also a NuGet package acquisition failure during `dotnet tool restore`. For general public packages, the existing `dotnet-public` key was pointed at NuGet.org, and both source and generated configurations were updated before retrying. Package versions were not changed. The [feed adjustment script](../scripts/configure-feeds.py) records the original and adjusted hashes and patch. The first attempt's logs were preserved under `reports/attempt-1`.

The second attempt exposed an incremental configuration marker issue: the local Arcade feed was missing from generated configurations, allowing some tools to resolve to 11.0. The existing root `artifacts/obj` directory was preserved as `obj-attempts-1-2` and regenerated. Subsequent Roslyn and Razor restore results confirmed selection of the exact Xliff version `10.0.0-beta.26528.101`. The retry tooling invalidates `UpdateNuGetConfig.complete` to prevent this issue from recurring.

The third attempt built every component preceding the SDK, then stopped because SDK restore could not find `NETStandard.Library.NETFramework/2.0.1-servicing-26011-01` on NuGet.org. The same version was retrieved from its original public Azure feed, and its SHA-256, `218dd4c63d3f800de697bca41178827a52df0a9ec7a9b47520327d91ebc7051c`, nuspec, and ZIP integrity were verified. The [pinned input downloader](../scripts/fetch-pinned-inputs.py) exposes this package through the regular `pinned-microsoft` feed at `/inputs/nuget`. It does not label a prebuilt package as source-built. The hash fingerprints the content retrieved from the public URL; it does not constitute publisher signature verification.

Failure records from all four unsuccessful attempts were preserved under `reports/attempt-1` through `attempt-4`.

The fourth attempt failed during SDK assembly because the initial `NUGET_XMLDOC_MODE=skip` setting had omitted `FSharp.Core.xml` from the cache. The setting was removed from the Containerfile and explicitly unset during builds. After verifying the original nupkg SHA-512 values and ZIP CRCs, 2,763 missing XML files were restored. The fifth build succeeded in the final image. Its duration was 3 minutes 36.77 seconds, reusing previously built components and downloaded packages; this is not a cold-build duration.

## Final SDK archive and execution checks

- File: `artifacts/10.0.403-linux-arm64/cbodotnet-sdk-10.0.403-linux-arm64-build.1.tar.gz`.
- Size: **217,684,872 bytes**, approximately **207.6MiB**.
- SHA-256: `4d13fd4c83c596b88ddfffdf20ca80dfc0bad37abdcec425daea28c77a7d8da6`.
- Actual SDK/RID: `10.0.403` / `linux-arm64`, including runtime/ASP.NET Core `10.0.14`.
- Copied the VMR-produced archive without modification. Confirmed that it contains `LICENSE.txt` and `ThirdPartyNotices.txt`.
- All 24 ELF files are AArch64. The highest required external symbol versions are `GLIBC_2.27`, `GLIBCXX_3.4.22`, and `CXXABI_1.3.7`; no additional symbolic GLIBC requirements were found.

| User-space environment | Console DLL and apphost | ASP.NET HTTP | Report |
| --- | --- | --- | --- |
| WSL Ubuntu 22.04 | Passed | Passed | `reports/verify-wsl-ubuntu22/verification.json` |
| Ubuntu 24.04 ARM64 container | Passed | Passed | `reports/verify-ubuntu24/verification.json` |
| Debian 13 ARM64 container | Passed | Passed | `reports/verify-debian13-retry1/verification.json` |

All three checks restored, built, published, and ran projects using built-in frameworks with an empty NuGet source list and isolated caches. The three environments share the same WSL 2 kernel, so these results do not represent independent validation on different kernels or physical machines. This portable SDK has been validated through ABI symbol inspection and execution within these user-space environments. NativeAOT, workloads, and the full set of diagnostic features require separate validation.

The first Debian check exposed a race between creation of the background HTTP log and the readiness check. The validation tool was changed to create the log first, then the entire check was rerun against the same archive and passed. The initial failed tool report was also preserved.

The initial 12/13 VMR common-test result came from detecting the warm source checkout's NuGet cache as source binaries. A separate pristine checkout of the same commit was scanned with the original allowlist and the actual upstream `BinaryToolTask`, producing a verified `NewBinaries.txt` of 0 bytes. All 13/13 common tests passed when given that actual report. Neither the source nor the allowlist was modified, and no failure report was replaced with an empty file. The initial failure is preserved under `reports/vmr-test-warm-cache`.

The full VMR test command completed with exit code 0. The template scenario XML records 36 total, 34 passed, 0 failed, 2 skipped, and 0 errors. The upstream-skipped cases are `VerifyWorkloadCmd` and `VerifyAspireTemplate`. Scenarios requiring MultiTFM or packages for other RIDs were excluded by the upstream default filters. The original `Microsoft.DotNet.Tests.trx`, `scenario-tests.xml`, actual commands, logs, and validation summary are available in the release's `reports` directory.

## Reproduction and delivery scope

Follow the [reproduction procedure](reproduce-arm64.md): Prepare → Build → clean source scan → Test → collect/verify. The final `build-manifest.json`, `SHA256SUMS`, `SHA512SUMS`, and SDK archive are under `artifacts/10.0.403-linux-arm64`. No website or remote release was published.

This is the first ARM64 package. Its validation covers the glibc ABI inspection and user-space environments described above. A source-only rebuild of the entire runtime, Stage 2, byte-for-byte reproducibility, NativeAOT, additional workloads, and the full set of diagnostic features are outside the completed scope.

## Build scope

This distribution **builds SDK components and reuses the upstream shared runtime**. The 4xx VMR does not contain all shared runtime sources. To avoid inheriting the ABI of an Ubuntu 24.04 source-built shared archive, this initial implementation uses the public portable shared packages pinned by the VMR.

Rebuilding the entire runtime and SDK in source-only mode requires separately building matching 1xx portable shared artifacts and providing them as inputs to the 4xx build. That work is not included in the success claims for this profile. [Shared runtime acquisition in a standard VMR build](https://github.com/dotnet/dotnet/blob/v10.0.403/src/sdk/src/Layout/redist/targets/RestoreLayout.targets#L294).

## Validation records and artifacts

The build log is recorded at `artifacts/10.0.403-linux-arm64/reports/build.log`. The same directory stores environment information, sysroot file hashes and symlink inventories, commands, resource usage, and exit codes. Validation of the generated artifacts covers:

1. Actual SDK version, RID, included runtime, and archive SHA-256.
2. Shipped ELF architectures, library dependencies, and GLIBC/GLIBCXX/CXXABI symbol requirements.
3. Console and ASP.NET Core restore/build/publish/execution using only built-in frameworks and isolated, empty NuGet caches.
4. SDK and HTTP execution results in the selected ARM64 Linux user-space environments.
5. Standard VMR common and scenario test results, including skip reasons.

`PortableBuild=true` and a sysroot alone do not establish support for every Linux distribution. Public support claims must reflect ELF inspection and actual execution results.
