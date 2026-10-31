# Building .NET Core SDK 3.1.426 on ARM64 Linux

Status snapshot: **2026-10-31, Asia/Seoul**. The full root build, framework origin audits and complete 52-case upstream suite passed for SDK `3.1.426` with runtime and ASP.NET `3.1.32`. The unchanged archive was collected. Six native checks passed in Ubuntu 22.04, Ubuntu 24.04 and Debian 13 with explicit compatibility inputs. Measured results and dependency limits are in the [build report](build-report-3.1.426-arm64.md).

## The pinned direct source-build route

The [profile](../profiles/dotnet-3.1.426-linux-arm64.json) selects `dotnet/source-build` branch `release/3.1`, commit `ab8b115b5658237ee8916ae3586600b39fb2fd19`. This complete graph targets the final published SDK `3.1.426`, coordinated with runtime `3.1.32`. Community build work continues independently of the upstream support lifecycle.

This generation builds the source-build repository directly. It predates both the installer-generated .NET 6/7 source tree and the later VMR route. The pinned [dependency manifest](https://github.com/dotnet/source-build/blob/ab8b115b5658237ee8916ae3586600b39fb2fd19/eng/Version.Details.xml), [root build](https://github.com/dotnet/source-build/blob/ab8b115b5658237ee8916ae3586600b39fb2fd19/build.proj) and [repository adapters](https://github.com/dotnet/source-build/tree/ab8b115b5658237ee8916ae3586600b39fb2fd19/repos) define the production graph. It has separate CoreCLR, CoreFX and CoreSetup components.

The recorded workspace is isolated on the D-backed native ARM64 WSL distribution `cbodotnet-net7-arm64`, user `build`, UID:GID `1000:1000`:

```text
/home/build/cbodotnet/core31/
  work/source-build-3.1.426/
  inputs/
  container-home/
```

[arm64-core31.Containerfile](../containers/arm64-core31.Containerfile) pins the official ARM64 SDK `3.1.426-focal-arm64v8` base by digest `sha256:a4028735b2ed1209c9116cebc74ae1c2fb27ea7d24b1be3f495fee0bac27dd52`. This Ubuntu 20.04 user space supplies the OpenSSL 1.1 and ICU generation needed to execute the old bootstrap SDK. The compiler is LLVM 9, with explicit aliases under `/opt/cbodotnet/llvm9/bin`, including `llvm-objdump`; Python 2 remains available for old native scripts. Target headers and libraries come from an independent signed ARM64 Xenial sysroot.

The unmodified crypto shim has an OpenSSL 1.0/1.1 dependency policy. Running this SDK on an OpenSSL-3-only distribution needs separate compatibility work or declared compatible libraries. A portable archive RID or GLIBC ceiling alone does not establish that compatibility.

## Public Windows entry point

[Invoke-Core31Build.ps1](../scripts/Invoke-Core31Build.ps1) provides:

```powershell
Set-Location D:\Projects\cbodotnet
./scripts/Invoke-Core31Build.ps1 -Mode Acquire
./scripts/Invoke-Core31Build.ps1 -Mode Prepare
./scripts/Invoke-Core31Build.ps1 -Mode Build
./scripts/Invoke-Core31Build.ps1 -Mode Test
```

Use each later mode after its prerequisite succeeds. Defaults select the existing distribution above, workspace `<Linux HOME>/cbodotnet/core31`, image `localhost/cbodotnet-arm64:3.1.426`, CPUs `2,3` and two MSBuild workers. Distribution, Linux user, workspace and affinity can be selected explicitly. Establish a native WSL/Podman host first; the [.NET 7 reproducer](reproduce-net7-arm64.md) documents the fresh-only host initializer. Do not reimport an existing distribution.

All source, input and project paths retain their exact absolute host paths inside containers. Initial source-export receipts contain those destinations. Unprivileged actions bind the complete dedicated workspace once, so preserving a cache directory from `work` into `inputs` remains an atomic same-mount rename. Separate binds of those two directories can return `EXDEV` even on one host ext4 filesystem. The privileged sysroot action separately mounts source read-only and inputs read-write.

Ordinary build/test actions use the selected unprivileged UID:GID and a host-derived seccomp policy with only `fchmodat2` additionally allowed. The recorded policy SHA-256 is `433ff4d41a88c0c37acf4372cfd84b13399c3a831037ee269141508d1538f990`. The default action and all other rules remain intact.

Each action creates a unique directory under `artifacts/3.1.426-linux-arm64/reports/runs/`, containing status, command/resource logs, image/policy provenance and a frozen copy of rebuild inputs. Failed attempts are retained.

## Acquire complete source exports

`Acquire` checks out the pinned full-history root and uses [clone-legacy-sources.py](../scripts/clone-legacy-sources.py) to acquire the exact manifest revisions, including the toolset. The recorded acquisition produced **30 exports from 31 dependency declarations**. Bare stores, commit markers, initial inventories and immutable acquisition receipts remain available.

Repository paths retain the original URI basename, including `NuGet.Client` casing. Canonical lowercase URLs are used for identity comparisons, not to reconstruct export paths. The normal upstream `FetchSources` target remains enabled. A reviewed Git adapter replaces the unavailable historical Darc helper without manufacturing source-completion markers.

Each build attempt creates an immutable executable wrapper for `DarcCloneCommand`. The MSBuild property contains only that single path: the old Arcade shell driver splits multiword property values even when callers quote them. A guarded root target change preserves the explicit executable instead of overwriting it with the historical Darc DLL command. Only the pinned literal credential placeholders are accepted by the public Git adapter.

## Prepare bootstrap and signed target libraries

`Prepare` initializes the pinned native SDK `3.1.422` through the upstream tool script. This selected online route skips downloading the legacy previously source-built and reference-package archives; it still restores binary dependencies from the recorded public feeds.

[prepare-sysroot-core31.sh](../scripts/prepare-sysroot-core31.sh) verifies the root manifest, original CoreFX producer blobs and selected source owner, then invokes the unchanged producer:

```bash
ROOTFS_DIR=/home/build/cbodotnet/core31/inputs/arm64-xenial \
  ./cross/build-rootfs.sh arm64 xenial no-lldb
```

The fresh producer refuses an existing target. Ubuntu archive signature checks remain enabled, using the current and retained historical archive keys. The recorded sysroot has **17,026 files and 5,225 symlinks**, nine required development-package checks and independent verification of four retained `InRelease` files. Later actions run [verify-sysroot-core31.py](../scripts/verify-sysroot-core31.py) against exact file/link inventories.

The actual first producer completed, but its wrapper expected a different successful debootstrap signature message. [finalize-sysroot-core31.py](../scripts/finalize-sysroot-core31.py) recovered only that exact owned attempt: it checked the preserved log hash, authenticated signing fingerprint, unchanged producers, installed packages, ARM64 libc and absence of active nested mounts before creating new inventories. It neither reran the producer nor turned a package failure into success. Future preparation recognizes the actual authenticated message directly. Root Git checks explicitly retain the verified source owner's `SUDO_UID=1000` context; they do not modify global safe-directory configuration.

## Build with the guarded compatibility changes

[apply-core31-patches.py](../scripts/apply-core31-patches.py) verifies all fixed source identities, original Git blobs, upstream patch lists and local patch hashes. It stages complete ordered hash transitions before changing source. Earlier six-, seven-, nine- and ten-patch manifests are retained, so retries accept only known reviewed states.

The eleven changes in [patches/core31](../patches/core31/manifest.json) address:

- CoreCLR, CoreFX and CoreSetup forwarding of the independent target sysroot.
- Actual native ARM64 CoreLib crossgen and perf-map generation during same-architecture sysroot builds, with correct packaging of the primary native tools.
- Preservation of the explicit source-acquisition executable.
- Mapping five exact retired package indexes to the official public mirror while preserving requested versions and local source-built precedence.
- Separate singleword CoreFX compiler/cross properties, plus forwarding of that cross property to its native script.
- Complete captured-output cache metadata for three silent CoreFX cross feature probes, preserving their existing upstream exit results and actual compile/link checks.
- Preservation of an explicit bootstrap HTTP-handler choice instead of forcing the old CurlHandler workaround.

The last change retains the historical standalone default, while the harness explicitly sets `DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER=1`. The official `3.1.422` bootstrap otherwise fails loading the forced CurlHandler's absent native shim. This changes bootstrap transport selection; it does not replace the SDK's locally built runtime libraries.

The recorded production command shape is:

```bash
./build.sh /p:Configuration=Release /p:Platform=arm64 /p:TargetOS=Linux \
  /p:TargetRid=linux-arm64 /p:PortableBuild=true \
  /p:SkipAcquireDarc=true /p:DarcCloneCommand=/absolute/immutable-wrapper.sh \
  /p:SkipDownloadingReferencePackages=true \
  /p:SkipDownloadingPreviouslySourceBuiltPackages=true /m:2
```

The harness sets the pinned `BUILD_SOURCEVERSION`, explicit LLVM 9 paths and `ROOTFS_DIR`. Each native adapter forwards its own cross switch. Do not substitute a global cross flag for verifying that component forwarding.

The base image inherits `NUGET_XMLDOC_MODE=skip`; the harness explicitly selects `none`. [prepare-legacy-xmldoc-recovery.py](../scripts/prepare-legacy-xmldoc-recovery.py) preserves affected extracted cache versions, stages byte-identical retained archives into a local recovery feed, and lets normal NuGet restore extract them again. It verifies raw SHA-512 sidecars and computes signed-package canonical content hashes through the actual private SDK's NuGet API. Source packages and SDK archives are not rewritten. The successful initial recovery preserved **322 affected package directories**, including **231 signed-package hash checks**.

## Preserve complete framework origin evidence

The upstream output is:

```text
/home/build/cbodotnet/core31/work/source-build-3.1.426/artifacts/arm64/Release/dotnet-sdk-3.1.426-linux-arm64.tar.gz
```

`inspect-sdk-construction9.py` accepts explicit versions and also compares this older layout:

```bash
python3 /project/scripts/inspect-sdk-construction9.py \
  --sdk-archive /absolute/dotnet-sdk-3.1.426-linux-arm64.tar.gz \
  --runtime-archive /absolute/blobs/Runtime/3.1.32/dotnet-runtime-3.1.32-linux-arm64.tar.gz \
  --aspnetcore-archive /absolute/blobs/aspnetcore/Runtime/3.1.32/aspnetcore-runtime-internal-3.1.32-linux-arm64.tar.gz \
  --runtime-version 3.1.32 --reports-dir /absolute/new/framework-comparison
```

The report directory must be new. Byte equality alone intentionally does not claim origin. Require the actual closed CoreSDK binlog's completed `DownloadFile` tasks, sole local `Copying` attempts, matching source/destination hashes and every final SDK framework entry. The old task logs a network attempt as `Attempting download`; an audit must recognize that form and every fallback attempt.

Runtime archives are written directly to the root assets feed by CoreSetup's `DotNetOutputBlobFeedDir`, then published under `blobs/Runtime/3.1.32`. ASP.NET's original archive remains in its component's `artifacts/installers/Release`, and its published archive is under `blobs/aspnetcore/Runtime/3.1.32`. ASP.NET need not have an additional assets-feed copy. Both actual CoreSDK inputs remain in its `artifacts/obj/redist/Release/downloads` directory.

The recorded origin tools are frozen under `reports/origin-tools/final-core31/`. They separately prove **180 runtime members** through component-produced packages, actual CoreSetup cache inputs, native outputs and completed native-image transformations. The preserved CoreSDK binlog is replayed without project evaluation. Developer analysis tools must run with private `HOME`, `DOTNET_CLI_HOME`, an `XDG_RUNTIME_DIR` of mode `0700`, and `DOTNET_GENERATE_ASPNET_CERTIFICATE=false`.

## Run the full upstream suite and collect

`Test` retains the unchanged upstream `RunSmokeTest` target. [prepare-core31-tests.py](../scripts/prepare-core31-tests.py) requires exactly the expected archive, independently verifies a fresh SDK extraction, preserves any previous `testing-smoke` tree and leaves the upstream workspace absent so the script freshly extracts its SDK. Finalization compares that actual SDK tree against the verified archive inventory.

The separate [test-only patch](../patches/core31-tests/0001-use-built-sdk-dev-certs.patch) uses the built-in SDK `dev-certs https` command for certificate setup. Its tool assembly, local producer source and available package/output matches are recorded. Every other byte of the pinned smoke script remains unchanged. No HTTPS, local, online, language or template case is excluded.

The recorded successful attempt `test-20261030T1918428256883Z` completed **52 template cases**, **28 web startup-ready records**, **two HTTPS certificate setups**, both local/online pass markers and final suite success. Finalization matched all **1,789 SDK file/link entries** to the prepared archive inventory. It retained 228 original output files in `upstream-smoke-outputs.tar.gz`. The old suite has different coverage from the modern xUnit suites; do not substitute their test counts or claims.

Two earlier preflights stopped before executing any suite case. The shared cache guard first rejected byte-identical duplicate icon metadata in four source-built Web SDK packages; its bounded handling accepts only the two exact known icon copies and preserves other duplicate/link rejection. The extraction guard then exposed Python 3.8's retained trailing slash on one GNU long-name directory header. The helper normalizes only that single trailing directory slash, keeping file, symlink, traversal and normalized-duplicate checks intact. Both failures and their frozen input copies remain available.

After origin and smoke evidence passes, collect with [collect-artifacts.py](../scripts/collect-artifacts.py), using the current public profile's verified construction declaration. It checks the direct pinned root, dependency metadata, exact archive version/RID and required SDK/runtime body entries before copying the tarball unchanged. Future unverified profiles must retain their unknown declaration until their evidence passes. The recorded collection is `cbodotnet-sdk-3.1.426-linux-arm64-build.1.tar.gz`, 164,066,330 bytes, SHA-256 `8fa6c9406a2c38ab98955c83bb8d6908750f9454b61164dfb981951f0bfbbde5`, with `SHA256SUMS`, `SHA512SUMS` and `build-manifest.json`.

The recorded Ubuntu 22.04 run passed all six functional checks and found **19 AArch64 ELF files**, with maximum requirements GLIBC `2.17`, GLIBCXX `3.4.21` and CXXABI `1.3.7`. The observed host RID was `ubuntu.22.04-arm64`. It supplied the unchanged, separately verified Focal OpenSSL 1.1 bundle from the .NET 5 verification input contract. The bundle remains outside the SDK; its `libcrypto` has its own GLIBC `2.25` requirement. Retain that contract and every file hash when reusing these libraries, and record each new user space's actual host RID rather than assuming the archive RID.

Ubuntu 24.04 also passed with that OpenSSL bundle and native ICU 74. Its observed RID was `linux-arm64`. Debian 13 initially failed before application checks because its ICU 76 is outside the loader's automatic range: the pinned CoreCLR shim searches up to its ICU 55 compile-time major plus 20. The failed report remains in `reports/verify-debian13/`.

[export-core31-verification-icu.py](../scripts/export-core31-verification-icu.py) exports a separate ICU 66 prefix from the exact recorded Focal builder. The caller supplies that image's host inspection receipt; the helper checks its ID, OS, native package/version/ownership, original SONAME symlinks, ELF dependencies, file hashes and copyright. In that producer container, its interface is:

```bash
python3 /project/scripts/export-core31-verification-icu.py \
  --destination /inputs/verification-icu --reports-dir /reports/icu-export \
  --image-inspect /reports/icu-export/source-image-inspect.json \
  --consumer-directory /verification-icu
```

Mount source inputs and report paths appropriately; use a new report directory. The resulting contract retains `libicu66` `66.1-2ubuntu2.1`, with uc/i18n/data libraries and copyright. It copies library bytes under their `.so.66` SONAMEs as regular files and does not alter the SDK. The uc/i18n libraries have their own maximum GLIBC requirement `2.29`, separate from the SDK's measured `2.17`.

For Debian verification, mount both dependency prefixes read-only and compose their environment explicitly:

```bash
LD_LIBRARY_PATH=/verification-icu/lib:/verification-compat/lib \
OPENSSL_CONF=/verification-compat/openssl.cnf CLR_ICU_VERSION_OVERRIDE=66 \
bash /tools/verify-sdk.sh \
  --archive /artifacts/cbodotnet-sdk-3.1.426-linux-arm64-build.1.tar.gz \
  --output-dir /reports --expected-version 3.1.426 \
  --framework netcoreapp3.1 --max-glibc 2.23
```

The controlled Debian retry passed all six checks, including real `fr-FR` globalization, with RID `linux-arm64` and the same 19 AArch64 ELF/ABI results. Its reports are in `reports/verify-debian13-icu66/`, with ICU export and file contracts retained separately. Invariant globalization was not used. Ubuntu 22.04/24.04 use their native ICU and need no ICU prefix. All three user spaces share the WSL kernel; these results do not certify untested OS/library combinations.

Preserve the original prebuilt/conflict reports and online baseline. The recorded audit retains 132 original reports, 41 project-directory entries, 33 package snapshots and 489 archived assets JSON files. It has nonzero usages, baseline differences and cache-conflict warnings. Static test-resource context is recorded separately and does not erase those findings. This online source-build route is not a clean bootstrap, an offline Stage 2 or a prebuilt-free certificate.
