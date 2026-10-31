# Reproduce the .NET 5 native ARM64 build

This procedure builds SDK `5.0.214` with runtime and ASP.NET Core `5.0.17` from the final pinned `dotnet/source-build` 5.0 graph. It uses native ARM64 WSL2 and a Focal container, retaining the older target ABI through an independently prepared signed Xenial sysroot. The verified run and its limits are recorded in [the build report](build-report-5.0.214-arm64.md).

SDK `5.0.408` is the newest published 5.0 SDK across all bands. The final complete graph in the [release/5.0 source-build branch](https://github.com/dotnet/source-build/tree/d414ecb2d997a9b3f38aaaeddace30ca097e546d) targets `5.0.214`. This direct repository route predates the .NET 6/7 installer source-generation workflow and the .NET 8 VMR workflow.

## 1. Prepare the host and private inputs

Use PowerShell 7.3 or newer with a native ARM64 WSL2 Ubuntu 22.04 host containing Git, Podman, Python 3, curl, binutils and the normal Linux container prerequisites. The observed host is the dedicated `cbodotnet-net7-arm64` distribution, running user `build`. The NET5 workspace is separate:

```text
/home/build/cbodotnet/net5/
  work/source-build-5.0.214/
  inputs/
  container-home/
```

The public harness mounts this entire workspace once at the same absolute container path. Keep source and inputs within that single mount so cache preservation can use atomic renames. Put compiler inputs and active source trees on the WSL filesystem; the project and collected reports can remain on the Windows project drive.

The original previous-source-build archive must be present before `Prepare`. For a fresh workspace, download the named input when absent; existing inputs are verified and reused by the preparation helper. From the project root:

```powershell
$distro = 'cbodotnet-net7-arm64'
$linuxRoot = '/home/build/cbodotnet/net5'
$psb = 'Private.SourceBuilt.Artifacts.0.1.0-5.0.213-1682896-20220325.6.tar.gz'
wsl.exe -d $distro -u build --exec mkdir -p "$linuxRoot/inputs"
wsl.exe -d $distro -u build --exec curl --fail --location --retry 3 `
  --output "$linuxRoot/inputs/$psb" `
  "https://builds.dotnet.microsoft.com/source-built-artifacts/assets/$psb"
wsl.exe -d $distro -u build --exec sha256sum "$linuxRoot/inputs/$psb"
```

Its exact size is `2542770679` bytes and SHA-256 is `11c3038cb5d317a404634d4f03813641230b38828f1d09d971028422cde5a408`. The preparation helper verifies these values and preserves the original archive. The selected managed Arcade member is `Microsoft.DotNet.Arcade.Sdk.5.0.0-beta.20431.1.nupkg`, 381,694 bytes, SHA-256 `1d74b9f3bb3964e178f37ceba4a94783378be45d273d7884c295283ed7dab738`.

The official ARM64 bootstrap SDK is `5.0.212`. Preparation downloads it when absent and checks the release-metadata SHA-512:

```text
5abdcda5a647d742664bfffe018d027bd3bc9dc5b3730472a86667a841aa5763b4c3b4f8f654912d170984b3a2d2d2074ba784a0795bad1174674e5e0ce624b9
```

## 2. Prepare the source graph, tools and sysroot

```powershell
.\scripts\Invoke-Net5Build.ps1 -Mode Prepare
```

The harness clones the root at `d414ecb2d997a9b3f38aaaeddace30ca097e546d`, checks the profile and container architecture, builds the container if needed, prepares the private bootstrap, acquires pinned component sources and creates the sysroot only when absent. Every invocation writes a new `reports/runs/prepare-*` directory containing frozen inputs and execution evidence.

The source acquisition adapter keeps the upstream manifest, full-history Git metadata, recursive submodule pins and normal build target contracts. The graph has 28 declarations and 27 exported repositories after the upstream ignored-repository rule. It replaces unavailable Darc tooling through `SkipAcquireDarc=true` and an immutable native wrapper path. The later production build still executes its real `FetchSources` target.

`prepare-net5-bootstrap.py` preserves `global.json`, selects retained Arcade `5.0.0-beta.20431.1`, builds the upstream `SourceBuild.MSBuildSdkResolver` and installs it into a private official SDK working copy. Restore and build are separate evaluations so restored framework references are available. An isolated probe requests the old declared Arcade `5.0.0-beta.20426.4` and must resolve the real retained toolset. The contract is retained in `inputs/bootstrap-state/`.

The container recipe is [arm64-net5.Containerfile](../containers/arm64-net5.Containerfile). Its base is the ARM64 Focal SDK image at digest `a4028735b2ed1209c9116cebc74ae1c2fb27ea7d24b1be3f495fee0bac27dd52`. The verified derived image is `d7f3d9624f9f2ec9d6dfb3c0ed1743eab582378d0a4ee40dfb0bc9e66bed288a`. Clang 9, LLVM 9 and CMake meeting the runtime's `3.14.5` minimum are available. Record the actual image ID for each new build.

`prepare-sysroot5.sh` invokes the original pinned runtime `eng/common/cross/build-rootfs.sh arm64 xenial --rootfsdir ...` after verifying the generator and source-list Git objects. The current and retained Ubuntu archive keyrings allow signature verification for historical packages. The helper requires a valid Release signature and emits file hashes, symlink targets, package versions and provenance under `reports/sysroot/`. It uses a privileged container for preparation; the product build runs as the unprivileged Linux user. Native ARM64 execution is retained.

## 3. Build the portable SDK

```powershell
.\scripts\Invoke-Net5Build.ps1 -Mode Build
```

The important effective root properties are:

```text
Configuration=Release
Platform=arm64
TargetOS=Linux
TargetRid=linux-arm64
DotNetBuildFromSource=true
PortableBuild=true
CrossBuild=true
UseSystemLibraries=false
UseSystemLibunwind=false
BuildPortableRuntime=false
BuildPortableSdk=false
ContinuousIntegrationBuild=true
```

`BuildPortableRuntime=false` selects the single portable root graph rather than an additional side graph. `BuildPortableSdk` is declared by the legacy root but has no working consumer. Actual portability comes from `PortableBuild=true`, the sysroot and downstream compiler/property propagation. The build exports the full Clang 9 paths and `ROOTFS_DIR`; generated native commands must show the AArch64 target, Xenial GCC toolchain and Xenial sysroot. The normal main ARM64 crossgen remains active for CoreLib.

Five guarded patches under `patches/net5/` provide the same-ARM64 CoreLib crossgen selection, unique portable ASP.NET runtime reference, explicit clone-command preservation and exact retired-feed mappings. Original/intermediate/final hashes and complete staged patch chains are verified before a pending patch is applied. The normal upstream patch graph remains active. Public dotnet-eng is added for the exact retained XliffTasks version; requested package versions are unchanged.

The harness exports `NUGET_XMLDOC_MODE=none` to retain XML documentation. On an existing cache created with the SDK image's inherited `skip` setting, `prepare-legacy-xmldoc-recovery.py`:

1. Finds missing XML documentation with an existing assembly sibling, excluding unrelated OPC metadata.
2. Checks the exact original archive against its SHA-512 receipt; signed metadata hashes are computed independently through the pinned bootstrap SDK's NuGet API.
3. Inventories and atomically preserves affected cache version directories.
4. Stages unchanged original archives in `inputs/xmldoc-recovery/feed` and lets normal NuGet restore extract them with documentation enabled.

The helper records every input and move. A single workspace bind is required even when source and inputs share the same host filesystem. Existing prepared inputs, unknown source edits, changed archives and unrecognized recovery state are guarded. The reviewed duplicate SDK icon metadata exception is limited to two byte-identical regular `packageIcon.png` entries with the recorded exact length and hash; code/XML/unknown duplicate entries remain rejected.

The graph runs online and uses official bootstrap/reference/package inputs. The post-build downloads of the old external reference and previous-source-build bundles are skipped after their required inputs have been supplied. Source and dependency builds, metadata, package production and prebuilt auditing remain active. Each build attempt retains commands, status, resource measurements and source/tool snapshots. Cached continuations retain their actual timing scope.

## 4. Verify framework identity and consumption

The produced SDK is:

```text
work/source-build-5.0.214/artifacts/arm64/Release/dotnet-sdk-5.0.214-linux-arm64.tar.gz
```

For a new artifact, run the shared-tree comparison into a new report directory:

```powershell
$linuxProject = '/mnt/d/Projects/cbodotnet'
$source = "$linuxRoot/work/source-build-5.0.214"
wsl.exe -d $distro -u build --exec python3 "$linuxProject/scripts/inspect-sdk-construction9.py" `
  --sdk-archive "$source/artifacts/arm64/Release/dotnet-sdk-5.0.214-linux-arm64.tar.gz" `
  --runtime-archive "$source/artifacts/arm64/Release/runtime/dotnet-runtime-5.0.17-linux-arm64.tar.gz" `
  --aspnetcore-archive "$source/artifacts/obj/arm64/Release/blobs/aspnetcore/Runtime/5.0.17/aspnetcore-runtime-internal-5.0.17-linux-arm64.tar.gz" `
  --runtime-version 5.0.17 `
  --reports-dir "$linuxProject/artifacts/5.0.214-linux-arm64/reports/construction"
```

The utility's filename reflects its first use; the explicit version selects .NET 5 correctly. It proves byte identity rather than component origin. The separate bounded origin audit replays the closed direct installer's `artifacts/log/Release/Build.binlog`, requiring successful `DownloadFile` tasks with actual local copy events and matching destination bytes. The current run's frozen reader, combiner and evidence are retained under `reports/origin-tools/final-net5/` and `reports/construction/`.

The runtime and ASP.NET consumed blobs are under `artifacts/obj/arm64/Release/blobs/Runtime/5.0.17/` and `blobs/aspnetcore/Runtime/5.0.17/`. ASP.NET has no separate asset-feed archive in this route. Preserve actual destination hashes before cleanup. Bind each new construction declaration to its own successful copy audit, two-framework comparison and SDK SHA-256.

## 5. Run the complete upstream suite

```powershell
.\scripts\Invoke-Net5Build.ps1 -Mode Test
```

This invokes the unchanged upstream `RunSmokeTest` target. Preparation requires `known-good` root metadata, extracts the actual SDK archive afresh and preserves prior `builtCli` and `testing-smoke` directories. Consumer projects receive a clean native-build environment. The complete default Linux suite covers 68 template cases across the local-source and online-source phases, including HTTP/HTTPS and XML documentation checks.

The test-only patch in `patches/net5-tests/` changes only certificate-tool setup: the fresh SDK's built-in `dotnet dev-certs https` replaces an unavailable preview global tool. Exact original/adapted scripts, source/tool/package hashes and the command probe are retained. The finalizer requires 68 completed cases, both certificate setups, exact success lines and unchanged SDK archive/tool bytes. The verified run passed all cases and established byte equality between its built-in certificate tool and the local ASP.NET output/package. No test exclusions were used. Stage 2 has a separate scope and was not executed in this run.

## 6. Record native compatibility and collect

The old runtime's OpenSSL shim searches OpenSSL 1.x. For modern verification systems, [export-net5-verification-compat.py](../scripts/export-net5-verification-compat.py) exports only the exact builder's `libssl.so.1.1`, `libcrypto.so.1.1`, copyright and configuration into a separate input directory. Run it inside its pinned builder with a new external reports directory and the host's exact `podman image inspect` JSON:

```text
python3 /project/scripts/export-net5-verification-compat.py \
  --destination /inputs/verification-compat \
  --reports-dir /reports/compat-export-new \
  --image-inspect /reports/source-image-inspect.json \
  --consumer-directory /verification-compat
```

These are container mount aliases for this exporter command; the build itself keeps its actual absolute workspace paths. The helper is deliberately bound to the recorded immutable builder. Its contract records separate exact library/configuration package revisions, licenses, architecture and file hashes. The observed packages share upstream `1.1.1f`, with library revision `1ubuntu2.24` and configuration revision `1ubuntu2.16`. Review and pin another builder before using it as an export source.

Mount the compatibility directory read-only at `/verification-compat`, set `LD_LIBRARY_PATH=/verification-compat/lib` and `OPENSSL_CONF=/verification-compat/openssl.cnf`, then run the public verifier on each native ARM64 environment:

```text
bash /project/scripts/verify-sdk.sh \
  --archive /artifacts/cbodotnet-sdk-5.0.214-linux-arm64-build.1.tar.gz \
  --output-dir /reports/verify-new \
  --expected-version 5.0.214 --expected-rid linux-arm64 \
  --framework net5.0 --max-glibc 2.23
```

Record the image/OS identity, actual compatibility-prefix mapping and input contract separately. The observed Ubuntu 22.04, Ubuntu 24.04 and Debian 13 runs passed all six functional checks with the same archive and 18 AArch64 ELFs. Their maxima are GLIBC `2.17`, GLIBCXX `3.4.21` and CXXABI `1.3.7`. No ICU compatibility libraries were added. These checks use the declared OpenSSL 1.1 inputs and do not establish stock OpenSSL-3-only crypto compatibility.

After construction and verification evidence is complete, run the collector from its public project location. That location supplies the real project root for the rebuild-input inventory:

```powershell
$imageId = (Get-Content "artifacts/5.0.214-linux-arm64/reports/runs/YOUR_BUILD_ATTEMPT/execution-environment.json" -Raw | ConvertFrom-Json).imageId
wsl.exe -d $distro -u build --exec python3 "$linuxProject/scripts/collect-artifacts.py" `
  --source-dir $source `
  --output-dir "$linuxProject/artifacts/5.0.214-linux-arm64" `
  --profile "$linuxProject/profiles/dotnet-5.0.214-linux-arm64.json" `
  --reports-dir "$linuxProject/artifacts/5.0.214-linux-arm64/reports" `
  --build-image-id $imageId
```

The collector verifies the direct root, committed output layout, dependency manifest, critical component exports/revision metadata and archive body. It copies the SDK without repacking, creates checksums and inventories reports plus rebuild inputs. Origin and functionality are supplied by the separate reports. Refresh collection after the final reports and profile metadata are closed.

Keep the prebuilt baseline audit alongside those results. This run retained 10,467 usage rows, two new baseline entries and 104 removed identities under the upstream nonfatal policy. Source-only mode describes the build graph while its binary bootstrap/dependency inputs remain visible in the manifest and audit reports.
