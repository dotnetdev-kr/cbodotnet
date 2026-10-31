# Version-specific ARM64 CI and source delivery

The [matrix workflow](../.github/workflows/sdk-matrix.yml) runs the existing pinned profiles on fresh native Linux ARM64 workers. Version adapters retain their original upstream tests, source construction policy and required compatibility inputs. A workflow file or local fixture pass is not a completed hosted build. Each version must pass its own fresh run and downloaded delivery verification.

The initial matrix integration enables .NET 6 and .NET 7 while the remaining family adapters are reviewed. The existing [.NET 10 workflow](ci-net10.md) is also being qualified with source delivery. Additional selectors will be enabled with their implementations; no historical local success is promoted into a new CI result.

```bash
gh workflow run sdk-matrix.yml --repo dotnetdev-kr/cbodotnet --ref main \
  -f target=net7 -f create_draft=false
```

The default is a native `ubuntu-24.04-arm` worker. Repository variable `SDK_BUILD_RUNNER_JSON` can explicitly select an existing native worker. Host preparation records disk before and after its fixed hosted-only cleanup list. The 90-GiB gate for legacy profiles is an initial planning threshold, not a measured guarantee. There is no automatic paid-runner fallback. The workflow preserves failures and serializes duplicate requests for the same target.

## Actual used sources

After successful build and upstream tests, and before native verification/final collection, [source packaging](../scripts/package-used-source.py) captures the actual source roots declared by each adapter:

- Git working trees include modified tracked files, nonignored new files and explicit deletion records.
- Exported legacy consumers are paired with their actual bare Git origin store and pinned commit, without pretending that a minimal `.git/HEAD` marker is a complete checkout.
- Generated consumer trees retain source inputs while explicit build outputs, caches and Git object stores are excluded.
- Orchestration sources and frozen input records are included, with original commit objects, baseline tree identities and submodule mappings.

`sources/source-manifest.json` binds a source tarball and `source-index.jsonl`. The index identifies each file or symlink, mode and content hashes; the original Git trees can be reconstructed from baseline metadata. The same source manifest is retained in `reports/ci/used-source.json` and bound by final collection and the version gate. These are source snapshots, not offline bootstrap bundles or claims that reused upstream binaries were rebuilt locally.

Every successful outer transport bundle contains the SDK, both SDK checksums, complete reports, source files and the validation envelope. Both transport checksums and the complete source payload are rechecked before optional unpublished draft creation. Drafts default off and are never automatically published. Assets or tags are never overwritten.

## Downloaded delivery verification

From a trusted checkout at the build's orchestration commit, download the run-specific artifact's three transport files. Then run:

```bash
python3 scripts/ci-delivery.py \
  --download-dir /absolute/download \
  --destination /absolute/new-verification-directory \
  --target net7 --sdk-version 7.0.120 \
  --expected-project-commit FULL_SHA \
  --expected-run-id RUN_ID --expected-run-attempt ATTEMPT
```

The extractor refuses existing destinations, unexpected transport files, path escapes, links, special files, duplicate members and insufficient extraction capacity. It executes trusted repository verification code, not code from the downloaded source archive. The common validator requires the complete source payload and delegates SDK, upstream-result and construction checks to the matching version adapter.
