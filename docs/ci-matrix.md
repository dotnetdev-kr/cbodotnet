# Version-specific AArch64 CI and source delivery

GitHub Actions is the supported build environment. The [matrix workflow](../.github/workflows/sdk-matrix.yml) runs the pinned profiles on fresh native Linux AArch64 workers; the [x64 workflow](ci-x64.md) supplies the matching native x64 jobs. Version adapters retain their original upstream tests, source construction policy and required compatibility inputs. Every new run must pass its own build and downloaded delivery verification.

The matrix enables .NET 5–10 and .NET Core 3.0/3.1. Select `all` for all eight profiles or one pinned version. All eight selected AArch64 profiles have passed actual hosted and downloaded delivery qualification. The [qualification records](ci-matrix-results.md) identify their exact runs and commits, including .NET 10's matching source revision for reused shared inputs. A previous successful build does not establish a new run's result.

## Run a pinned profile

Open the workflow in GitHub Actions, choose **Run workflow**, select `main`, and choose a target. An authenticated GitHub CLI can dispatch the same workflow:

```bash
gh workflow run sdk-matrix.yml --repo dotnetdev-kr/cbodotnet --ref main \
  -f target=all -f create_draft=false
```

The default is a native `ubuntu-24.04-arm` worker. Repository variable `SDK_BUILD_RUNNER_JSON` can explicitly select an existing native worker. Host preparation records disk before and after its fixed hosted-only cleanup list. The 90-GiB gate for legacy profiles is an initial planning threshold, not a measured guarantee. There is no automatic paid-runner fallback. The workflow preserves failures and serializes duplicate requests for the same target.

Build and bootstrap commands run inside the workflow's pinned Linux containers. The scripts, recipes, profiles and patches are shared CI implementation inputs; they are not a separate local build setup. No developer-machine SDK or source cache is used to establish a qualified run.

## Pinned versions and construction

| Target | SDK | Source route | Shared frameworks |
| --- | --- | --- | --- |
| `net10` | 10.0.403 | Regular VMR 4xx | Pinned upstream runtime and ASP.NET; matching complete 1xx sources included |
| `net9` | 9.0.123 | Regular VMR | Locally produced runtime; pinned upstream ASP.NET |
| `net8` | 8.0.133 | Legacy VMR source-build | Locally produced runtime and ASP.NET |
| `net7` | 7.0.120 | Installer-generated source-build | Locally produced runtime and ASP.NET |
| `net6` | 6.0.136 | Installer-generated source-build | Locally produced runtime and ASP.NET |
| `net5` | 5.0.214 | Direct legacy source-build | Locally produced runtime and ASP.NET |
| `core31` | 3.1.426 | Direct legacy source-build | Locally produced runtime and ASP.NET |
| `core30` | 3.0.103 | Direct legacy source-build | Locally produced runtime and ASP.NET |

"Locally produced" identifies producer and installer-copy work inside the current CI runner. Bootstrap SDKs, previously source-built artifacts, reference packages and online inputs remain explicit. No profile's name or source-build flag establishes zero-prebuilt construction, Stage 2 or reproducibility.

## Compatibility and required gates

The public architecture names are `aarch64` and `x64`. Project profile/Containerfile names, Actions artifact labels and release downloads use these names. The official .NET target RIDs remain `linux-arm64` and `linux-x64`; package identifiers, OCI/Debian architecture values and original authenticated delivery paths retain their upstream names. `--arch aarch64` selects the official `linux-arm64` identity; the legacy `--arch arm64` alias remains accepted for historical verification.

The product target is generic glibc Linux. An older SDK may print a distribution-specific host RID; that does not change the package target. Builds use signed Xenial sysroots with GLIBC ceilings of 2.23, or Bionic/2.27 for .NET 10, to isolate target headers and libraries from the newer build host. Symbol maxima are measurements, not tested minimum operating-system versions.

Each successful run requires ordered build, scan or explicit scan-applicability, original upstream tests, source packaging, native user-space verification and final collection/evidence gates. The unchanged SDK is checked in Ubuntu 22.04, Ubuntu 24.04 and Debian 13 user spaces. Six functional checks cover console DLL/apphost execution, RSA/SHA-256, random bytes, ICU formatting and ASP.NET HTTP, alongside ELF/ABI inspection. Separate user spaces share the runner kernel; they do not establish support for every kernel, distribution, workload, diagnostic component or external native package. Musl/Alpine is outside this qualification.

.NET 5 and Core 3.x use recorded external OpenSSL 1.1 inputs in all three user spaces. Core 3.x on Debian 13 additionally selects a recorded ICU 66 prefix; Ubuntu uses stock ICU. These dependencies stay outside the unchanged SDK archive and do not establish stock OpenSSL 3-only compatibility. Exact versions, selected overrides and per-architecture measurements are in the [AArch64 results](ci-matrix-results.md) and [x64 results](ci-x64-results.md).

The .NET 9/10 scenario runner uses an explicit outer completion fence for the [upstream xUnit XML race](https://github.com/xunit/xunit/issues/2090). It waits until the existing XML sink finishes processing the final message; test assertions, filters, skips and failure status remain unchanged. The original and patched runner, helper fingerprint and actual captured source are bound by the delivery evidence. Raw test results and counters must still pass the version-specific gates.

The pinned .NET 9 graph declares 262 shipping packages. Its fresh original downloader produces 260 usable comparison baselines and two zero-byte cache entries, for `Microsoft.DotNet.Common.ProjectTemplates.9.0` and `Microsoft.EntityFrameworkCore.Tasks`. The gate requires both original comparison methods for exactly those 260 package IDs plus both SDK facts: 522 passing common results, followed by all 34 scenario results. It binds the actual generated manifest, original test sources, runtime configuration, initially absent cache and all retained cache bytes. The two unavailable baselines remain explicit comparison gaps; they are not counted as passing package comparisons. Historical 500-result local runs had a different baseline cache and do not establish this fresh coverage.

## Actual used sources

After successful build and upstream tests, and before native verification/final collection, [source packaging](../scripts/package-used-source.py) captures the actual source roots declared by each adapter:

- Git working trees include modified tracked files, nonignored new files and explicit deletion records.
- Exported legacy consumers are paired with their actual bare Git origin store and pinned commit, without pretending that a minimal `.git/HEAD` marker is a complete checkout.
- Generated consumer trees retain source inputs while explicit build outputs, caches and Git object stores are excluded.
- Orchestration sources and frozen input records are included, with original commit objects, baseline tree identities and recursively captured pinned submodule consumers, including valid empty checkouts.
- The .NET 10 4xx checkout omits reused runtime/ASP.NET sources, so a second full 1xx VMR checkout is retained at the shared package's exact commit. Both actual SDK `.version` markers must identify it; its source role records that these frameworks remain upstream inputs rather than local rebuilds.

`sources/source-manifest.json` binds a source tarball and `source-index.jsonl`. The index identifies each file or symlink, mode and content hashes; the original Git trees can be reconstructed from baseline metadata. The same source manifest is retained in `reports/ci/used-source.json` and bound by final collection and the version gate. These are source snapshots, not offline bootstrap bundles or claims that reused upstream binaries were rebuilt locally.

Source archives preserve actual checkout bytes. Pristine orchestration permits only the exact committed CMD/BAT CRLF representation. The corresponding .NET 10 shared VMR also has 987 explicitly audited Git `eol=crlf` paths in [the pinned checkout policy](../scripts/net10-shared-source-crlf.json). That exception requires its exact role, commit, tree and path, plus uniform reversible CRLF and canonical Git blob equality. Updating the shared source pin requires a new complete attribute audit; other content changes are rejected.

Every successful outer transport bundle contains the SDK, both SDK checksums, complete reports, source files and the validation envelope. Both transport checksums and the complete source payload are rechecked before optional unpublished draft creation. These architecture-specific matrix drafts default off and remain unpublished. The separate [upstream workflow](upstream-automation.md) can publish an admitted version after both architectures pass. Assets or tags are never overwritten.

## Downloaded delivery verification

From a trusted checkout at the build's orchestration commit, or a later trusted verifier supporting its recorded contract, download the run-specific artifact's three transport files. Always supply the original producer commit, run and attempt. Then run:

```bash
python3 scripts/ci-delivery.py \
  --arch aarch64 \
  --download-dir /absolute/download \
  --destination /absolute/new-verification-directory \
  --target net7 --sdk-version 7.0.120 \
  --expected-project-commit FULL_SHA \
  --expected-run-id RUN_ID --expected-run-attempt ATTEMPT
```

The extractor refuses existing destinations, unexpected transport files, path escapes, links, special files, duplicate members and insufficient extraction capacity. It executes trusted repository verification code, not code from the downloaded source archive. The common validator requires the complete source payload and delegates SDK, upstream-result and construction checks to the matching version adapter.

For `gh run download`, select the exact artifact name `sdk-TARGET-linux-aarch64-RUN-ATTEMPT`; historical runs use `linux-arm64`, and x64 uses `linux-x64`. Download and unzip the Actions artifact first: the three files consumed by `ci-delivery.py` are its transport `.tar.gz`, `.sha256` and `.sha512`. Transport and inner archive paths retain the official .NET RID so original evidence remains unchanged. Install the inner `cbodotnet-sdk-*.tar.gz` after delivery verification, rather than installing the outer transport bundle.

Actions artifacts are retained for 14 days. Permanent qualified downloads are available in the [download index](https://dotnetdev.kr/cbodotnet/). Historical qualification records retain the exact original build identity after an Actions download expires; dispatch a new run when a new delivery is needed. Optional matrix draft creation uses `create_draft=true`, requires all selected builds to pass and revalidates the downloaded artifact. Joint-architecture public publication uses the separate promotion or upstream workflow.
