# Version-specific ARM64 CI and source delivery

The [matrix workflow](../.github/workflows/sdk-matrix.yml) runs the existing pinned profiles on fresh native Linux ARM64 workers. Version adapters retain their original upstream tests, source construction policy and required compatibility inputs. A workflow file or local fixture pass is not a completed hosted build. Each version must pass its own fresh run and downloaded delivery verification.

The matrix enables .NET 5–10 and .NET Core 3.0/3.1. Select `all` for all eight profiles or one pinned version. All eight selected ARM64 profiles have passed actual hosted and downloaded delivery qualification. The [qualification records](ci-matrix-results.md) identify their exact runs and commits, including .NET 10's matching source revision for reused shared inputs. Every new run must pass its own gates; no historical local success is promoted into a new CI result.

```bash
gh workflow run sdk-matrix.yml --repo dotnetdev-kr/cbodotnet --ref main \
  -f target=net7 -f create_draft=false
```

The default is a native `ubuntu-24.04-arm` worker. Repository variable `SDK_BUILD_RUNNER_JSON` can explicitly select an existing native worker. Host preparation records disk before and after its fixed hosted-only cleanup list. The 90-GiB gate for legacy profiles is an initial planning threshold, not a measured guarantee. There is no automatic paid-runner fallback. The workflow preserves failures and serializes duplicate requests for the same target.

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

Every successful outer transport bundle contains the SDK, both SDK checksums, complete reports, source files and the validation envelope. Both transport checksums and the complete source payload are rechecked before optional unpublished draft creation. Drafts default off and are never automatically published. Assets or tags are never overwritten.

## Downloaded delivery verification

From a trusted checkout at the build's orchestration commit, or a later trusted verifier supporting its recorded contract, download the run-specific artifact's three transport files. Always supply the original producer commit, run and attempt. Then run:

```bash
python3 scripts/ci-delivery.py \
  --download-dir /absolute/download \
  --destination /absolute/new-verification-directory \
  --target net7 --sdk-version 7.0.120 \
  --expected-project-commit FULL_SHA \
  --expected-run-id RUN_ID --expected-run-attempt ATTEMPT
```

The extractor refuses existing destinations, unexpected transport files, path escapes, links, special files, duplicate members and insufficient extraction capacity. It executes trusted repository verification code, not code from the downloaded source archive. The common validator requires the complete source payload and delegates SDK, upstream-result and construction checks to the matching version adapter.
