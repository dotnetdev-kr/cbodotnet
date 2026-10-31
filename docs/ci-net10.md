# .NET 10 ARM64 CI and draft delivery

The [workflow](../.github/workflows/net10-sdk.yml) builds the pinned SDK 10.0.403 profile on a native Linux ARM64 GitHub Actions worker. Each fresh run must complete every gate before it can produce a validated delivery. Historical local release manifests remain evidence of their original builds.

This is the regular VMR 4xx build. It consumes the pinned upstream shared runtime and ASP.NET inputs declared in the profile. It does not establish a source-only build, Stage 2, zero prebuilt usage, x64 coverage, workload support, or compatibility with every Linux distribution.

## Current source-inclusive qualification

The [source-inclusive matrix run 41211183670](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41211183670), at orchestration commit `5721c5989e277d98b6af7c782d1b660459f8298e`, passed every hosted gate and complete independent downloaded delivery verification. It includes the actual build sources and the complete matching 1xx VMR sources for reused shared inputs. The [qualification record](ci-matrix-results.md) provides its artifact link, SDK/source hashes, tests and measured resources. This newer SDK archive and source delivery are separate from the earlier pilot below.

## Historical SDK-only pilot

The [successful hosted run](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41191037279), at orchestration commit `1d24bc32770753f13e59c6a0927585ac0d3805d6`, passed preparation, SDK build, pristine-source scan, upstream tests, all six functional checks on each of Ubuntu 22.04, Ubuntu 24.04 and Debian 13, final collection, the complete evidence gate, and artifact upload. All 13 common tests passed; the 36 scenarios contained 34 passes and the two declared skips. All 24 shipped ELF files were AArch64, with maximum requirements GLIBC 2.27, GLIBCXX 3.4.22 and CXXABI 1.3.7.

The downloaded artifact ZIP matched its API SHA-256. Its transport checksums, the exact committed draft extraction step and `verify-release` also passed independently in local WSL. The SDK archive was copied unchanged:

```text
File: cbodotnet-sdk-10.0.403-linux-arm64-build.41191037279.tar.gz
Bytes: 217811134
SHA-256: fc17e73548d5c135bafa13a898e739fa8db58687723063a4cec4c5a97a51405b
```

The run used `create_draft=false`. Draft creation and release-asset upload were not exercised; the downloaded artifact and local qualification did not create a release.

| Observation from the qualified run | Value |
| --- | --- |
| Preparation stage | 1 min 29.85 sec |
| SDK build stage | 45 min 30.01 sec |
| Pristine-source scan stage | 32.28 sec |
| Upstream test stage | 7 min 4.51 sec |
| Three-user-space verification stage | 1 min 32.66 sec |
| Final collection stage | 3.22 sec |
| Preparation start through final collection | 56 min 13.37 sec |
| Free disk after host preparation | 120.943 GiB |
| Minimum free disk in 220 periodic samples | 94.732 GiB |
| Maximum sampled host memory usage | 8.032 GiB |

The elapsed interval excludes earlier host preparation and later upload/local qualification. The resource monitor covers build, scan, tests and user-space verification; it stops before final collection. Memory usage is the sampled host `MemTotal - MemAvailable`, including the operating system and other runner activity. Disk observations cover the host filesystem. Neither value is an isolated build-process peak or a guaranteed minimum capacity.

### Initial pilot correction

The [first hosted run](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41186712404), at orchestration commit `719ddffe39c02bcbb9a8c87e228c694f18c3ec17`, completed the SDK build, pristine-source binary scan and upstream tests. All 13 common tests passed; the 36 scenarios contained 34 passes and the two declared skips. It did not produce a validated delivery: verification stopped before running its first user-space test because Podman legitimately retained both a platform manifest and an OCI index in `RepoDigests`.

The corrected selector uses the exact inspected `Digest` with its matching repository reference. Additional valid index references are allowed. Regression tests replay the original inspection, and the delivery gate binds that digest to the actual verification image build and execution.

## Run the workflow

The workflow uses `workflow_dispatch` on `main`. From an authenticated checkout:

```bash
gh workflow run net10-sdk.yml --repo dotnetdev-kr/cbodotnet --ref main -f create_draft=false
gh run list --repo dotnetdev-kr/cbodotnet --workflow net10-sdk.yml
gh run watch --repo dotnetdev-kr/cbodotnet RUN_ID --exit-status
```

The default runner is `ubuntu-24.04-arm`. Preparation installs host prerequisites and measures free disk after its bounded cleanup of unused tools on a disposable GitHub-hosted VM. The 30-GiB capacity gate is a planning threshold, not a measured promise that the complete graph fits. The resource monitor records actual disk and memory observations and stops before final collection. Failure retains its reports and never enables draft creation.

For a larger native worker, set repository variable `NET10_BUILD_RUNNER_JSON` to a JSON runner label or label array, for example:

```json
["self-hosted", "Linux", "ARM64", "cbodotnet"]
```

The worker needs a nonroot account, passwordless `sudo`, native `aarch64`, at least two allowed CPUs, network access to the pinned public inputs, and adequate fresh disk. Hosted cleanup is disabled for a self-hosted worker. Each run uses a new workspace and delivery directory; existing SDK outputs, source caches and reports are refused rather than reused. The workflow serializes builds and does not cancel an active build when another is queued.

See GitHub's [manual workflow instructions](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow) for the equivalent UI action.

## What must pass

The [driver](../scripts/ci-net10.sh) executes `prepare`, `build`, `scan`, `test`, `verify`, and `collect` in order. A dated `OfficialBuildId` uses the workflow run number; the archive revision uses the numeric run ID. Run attempt is recorded separately. The original profile is frozen unchanged; an effective copy may change only `build.officialBuildId`.

Before tools or feeds change, `freeze` preserves canonical committed Git blobs for the orchestration files, workflow, profile and container recipes in `reports/ci-inputs/project`. File bytes and Git modes reconstruct the original Git tree, and the retained commit object must hash to the expected orchestration commit. The checkout must clean to each original blob through Git's attributes. Its actual byte fingerprints are also retained: nonexecuted CMD/BAT files may have the repository's CRLF checkout representation, while executed CI code must already match its canonical blob exactly. The subsequent stages execute the frozen canonical scripts. Source starts as a pristine checkout of VMR commit `5a2162bea6845eabc1fc721624a43568c65db3b1`.

The final [evidence gate](../scripts/ci-net10-evidence.py) requires:

- Successful, ordered, identity-bound current-run stage receipts and a single immutable builder image.
- Authenticated Bionic ARM64 sysroot generation with `--force-check-gpg`, actual signature success records, and independent complete file and symlink inventories.
- The original upstream binary scanner, built in this run, executed against a separate pristine source checkout mounted read only. Its output must be absent before execution and generated empty afterward. The real command, nonempty log and binlog, tool assembly, and both original imported allowlists are retained. An empty file alone is insufficient.
- All 13 actual common TRX results, including `BinaryScanTest.ScanForBinaries`, passing; all 36 actual scenario results, with 34 passing and only the pinned workload and Aspire skips. Raw results and counters must agree.
- The unchanged SDK archive tested on Ubuntu 22.04, Ubuntu 24.04 and Debian 13 user spaces. Each must pass console DLL and apphost execution, RSA signing and verification, cryptographic random generation, French decimal formatting and ASP.NET loopback HTTP. All ELF files must be AArch64, with maximum requirements no higher than GLIBC 2.27, GLIBCXX 3.4.22 and CXXABI 1.3.7.
- Exact SDK SHA-256 and SHA-512 sidecars, complete report membership and digests, the effective profile, current frozen rebuild inputs, and the final collection receipt. Collection runs after all report writers stop; its own receipt and logs remain outside the inventoried reports tree.

These are separate Linux user spaces sharing the runner kernel. Reported `linux-arm64` identifies the observed runtime RID; it does not establish distribution support. Verification records the actual images and installed system dependencies. No historical local validation is promoted into a new CI pass.

The bounded synthetic gate fixtures run without building an SDK:

```bash
python3 tests/ci_net10_evidence_test.py
```

They test a real clean Git checkout with CRLF-smudged CMD files, raw result omissions and unexpected skips, fabricated scan evidence, altered SDK bytes, skipped functional checks, added unbound files, forbidden profile changes, and a resealed workflow that no longer belongs to the claimed Git commit.

## Download and revalidate

New source-inclusive runs capture the actual post-test VMR checkout, applied source/configuration changes, orchestration sources, and frozen input records before native verification. Because the 4xx tree omits runtime and ASP.NET sources, a separate full 1xx VMR checkout at `0427b9abbead3fa64c6655eb4290c537397131fa` supplies corresponding sources for the reused shared inputs. Both actual SDK `.version` markers must match that commit. Its explicit source role preserves the distinction from a local framework rebuild. The `sources/` directory contains a source `.tar.gz`, `source-index.jsonl`, and `source-manifest.json`; an identical manifest is included in the inventoried reports. The index binds every archived file or symlink, its mode and content hashes. Original Git commit objects, baseline tree identities, deleted paths and submodule mappings identify the source origins. Git object stores and build/package caches are excluded; this is not an offline bootstrap bundle. The historical SDK-only pilot `41191037279` predates this addition and must not be presented as source-inclusive evidence.

The workflow uploads a run-specific outer `.tar.gz` bundle and its transport SHA-256/SHA-512 files, including failed-run evidence when available. A successful bundle contains the unchanged SDK tarball, its two checksum files, `build-manifest.json`, `collect-receipt.json`, `ci-validation.json`, and the complete reports/source snapshot. Artifact retention is 14 days.

If verification fails after provisional collection, the failure bundle also preserves a complete candidate under `failure-candidate/`, after checking its SDK hashes and sidecars. Its `status.json` explicitly marks it `unvalidated-candidate`. This diagnostic copy does not establish a validated delivery. Failed or incomplete candidate preservation emits a warning while ordinary failure reports remain available.

After checking transport hashes and safely extracting the outer bundle, use the trusted verifier from the same orchestration commit:

```bash
python3 scripts/ci-net10-evidence.py verify-release \
  --release-dir /absolute/10.0.403-linux-arm64 \
  --expected-project-commit FULL_ORCHESTRATION_SHA \
  --expected-run-id RUN_ID --expected-run-attempt RUN_ATTEMPT
```

This rechecks the portable bundle and validation envelope without the original VMR checkout, builder image or build machine paths. It validates the frozen Git objects and complete inventories as well as the real test evidence. Execute trusted checked-out verification code, not code taken from an untrusted download.

## Optional unpublished draft

`create_draft` defaults to `false`. A deliberate dispatch with `create_draft=true` enables the separate draft job only after the build job and evidence gate pass on trusted `main` in `dotnetdev-kr/cbodotnet`. The draft job alone receives `contents: write`. It downloads the exact artifact ID from this run, validates both transport hashes, rejects unsafe outer archive members, and runs `verify-release` again.

It then creates a new unpublished draft with a unique run/attempt tag and the exact orchestration commit. Existing releases, tags and assets are refused. It does not publish a public release or mark it latest. Draft assets remain mutable in GitHub; the retained checksums and validation envelope identify the reviewed bytes. Publishing requires a separate deliberate action.
