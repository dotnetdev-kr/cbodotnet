# Native Linux x64 CI and source delivery

The [x64 workflow](../.github/workflows/sdk-x64.yml) provides separate native x64 jobs for the same eight pinned SDK versions as the AArch64 matrix. All eight have passed actual hosted builds and complete independent downloaded SDK/source qualification, recorded in the [x64 results](ci-x64-results.md). Build environments, bootstrap inputs, sysroots, package identities, ELF checks and native user-space results are selected explicitly for x64. These qualifications apply to their exact pinned inputs and run identities.

## Run a pinned profile

From an authenticated checkout, dispatch one profile or `all`:

```bash
gh workflow run sdk-x64.yml --repo dotnetdev-kr/cbodotnet --ref main \
  -f target=net10 -f create_draft=false
```

Targets are `net10`, `net9`, `net8`, `net7`, `net6`, `net5`, `core31` and `core30`. The default `all` matrix runs at most two selected jobs concurrently. The workflow requires the exact dispatched `main` commit and records the run and attempt separately. Duplicate requests for a target are serialized.

The default worker is native `ubuntu-24.04`. Repository variable `SDK_X64_BUILD_RUNNER_JSON` can select an existing native worker explicitly. Host preparation records capacity before and after its fixed GitHub-hosted-only cleanup list. The 30-GiB .NET 10 and 90-GiB other-family preparation thresholds are initial planning gates, not measured x64 minimum requirements. There is no automatic paid-runner fallback. Each build uses fresh source, input, report and delivery directories.

## Version-specific construction

| SDK | Source route | Intended target sysroot |
| --- | --- | --- |
| 10.0.403 | Regular VMR 4xx; matching complete 1xx sources accompany reused shared inputs | Signed amd64 Bionic |
| 9.0.123 | Regular VMR; local core runtime and explicitly reused upstream ASP.NET input | Signed amd64 Xenial |
| 8.0.133 | Legacy VMR source-build | Signed amd64 Xenial |
| 7.0.120 | Pinned installer source generator and source-build | Signed amd64 Xenial |
| 6.0.136 | Pinned installer source generator and source-build | Signed amd64 Xenial |
| 5.0.214 | Direct legacy source-build | Signed amd64 Xenial |
| 3.1.426 | Direct legacy source-build | Signed amd64 Xenial |
| 3.0.103 | Direct legacy source-build | Signed amd64 Xenial |

Native x64 builds still use the selected sysroot and portable cross-build properties to isolate target headers and libraries from the newer build container. The intended GLIBC ceilings are 2.27 for .NET 10 and 2.23 for the other profiles. Actual symbol maxima and successful execution belong to each qualified artifact's reports.

The original Core 3.x and .NET 6 sysroot generators do not support amd64; the .NET 7 generator lacks its x64 Xenial source list. These x64 paths use explicit signed debootstrap producers with pinned upstream package sets and complete file, symlink and package inventories. Their recorded current producer CA bundle enables verified HTTPS inside the old sysroot while package signatures, peer verification and hostname verification remain active. Exact-state x64-only source patches add missing legacy toolchain, cross try-run and native host construction support. The ARM patch manifests remain independent.

.NET 6 and 7 retain their original native x64 previously source-built bootstrap archives without byte changes. The .NET 7 bootstrap package RID is `centos.8-x64`; its reference-package adapter explicitly selects that original ILAsm build tool while the product target remains independently required to be portable `linux-x64`. This input RID does not determine the product's compatibility. Bootstrap SDKs, reference packages and online inputs remain disclosed; these builds do not establish zero-prebuilt construction or Stage 2.

Core 3.0's x64 path also runs the pinned local Arcade GenAPI producer and its native help/reference-generation verifier. It retains the actual source-built tool package and execution evidence, preserves both original framework outputs and host policy, and uses the normal generated version aliases for CoreFX consumption. Delivery rejects a missing producer, changed package or external version substitution.

All original upstream test assertions and version-specific coverage gates remain active. Architecture-specific .NET 9 package identities have a separate exact expected policy; its fresh generated manifest and baseline availability must pass the real x64 run. The native verifier runs six functional checks in each of Ubuntu 22.04, Ubuntu 24.04 and Debian 13 user spaces, together with ELF and ABI inspection. Legacy OpenSSL/ICU compatibility inputs are supplied separately and recorded with their native amd64 identities where required.

## Artifacts and independent verification

Successful deliveries include the unchanged SDK archive, SDK checksums, complete validation reports, and the actual used source archive with its file index and source manifest. Source capture follows the [common source delivery contract](ci-matrix.md#actual-used-sources). It records actual patched inputs, original Git baseline identities and declared generated-source exclusions. Corresponding sources for reused frameworks retain their explicit input role.

The uploaded artifact name is `sdk-TARGET-linux-x64-RUN-ATTEMPT`. Download its three transport files to a new directory, then use trusted verifier code with the original producer identity:

```bash
python3 scripts/ci-delivery.py \
  --arch x64 --target net10 --sdk-version 10.0.403 \
  --download-dir /absolute/download \
  --destination /absolute/new-verification-directory \
  --expected-project-commit FULL_ORCHESTRATION_SHA \
  --expected-run-id RUN_ID --expected-run-attempt ATTEMPT
```

The verifier checks both transport hashes, safe extraction, the exact x64 source target, SDK identity and every matching family gate. It executes trusted checkout code; downloaded source and orchestration files are evidence. AArch64 remains the default for existing commands, so x64 delivery verification requires explicit `--arch x64`.

Actions artifacts use 14-day retention; permanent qualified downloads are available in the [download index](https://dotnetdev.kr/cbodotnet/). Optional matrix drafts remain unpublished, default off, require all selected builds to pass, revalidate the downloaded SDK/source delivery and refuse existing tags or assets. Joint-architecture public publication uses the separate promotion or [upstream workflow](upstream-automation.md).
