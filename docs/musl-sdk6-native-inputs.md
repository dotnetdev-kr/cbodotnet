# SDK6 native source and version consumption

The native SDK6 worker builds the five original Release products from runtime
commit `f1dd57165bfd91875761329ac3a8b17f6606ad18`: CoreCLR, JIT, DAC, DBI and the
matching trace provider. Its two recorded source adaptations preserve runtime
behavior and object layout while making the original DAC and metadata code
compile with the current native toolchain. ReadyToRun, tracing, Release
optimization and the original PGO configuration remain enabled.

## Actual compiled version input

The first normal worker experiment generated an honest dated `_version.c` and
version header. A later independent audit found that the original
`build-runtime.sh` configure phase invokes `GenerateRuntimeVersionFile` again
through `eng/native/build-commons.sh`. That second invocation lacked the
original version/build properties and produced `42.42.42.42424` in the actual
CMake `version.c`. The original v2 files remain private diagnostic evidence;
their first generated header does not establish the final ELF file version.

The corrected worker forwards the exact Version, OfficialBuildId,
ContinuousIntegrationBuild and UseSharedCompilation properties through the
original configure command. It verifies that the actual compiled `version.c`
and runtime header equal the first dated producer's bytes. All five final ELF
files must contain that dated version and exact source commit and must not
contain the fallback marker. No post-build version replacement is used.

The fresh native ARM64 v3 build passes all five targets. Each final ELF embeds
`6.0.3626.55901` and the original source commit. It retains five matching debug
sidecars, the actual command records/logs, version binlog, CMake cache,
compilation database and 617 generated inputs. The old v2 fallback is retained
as an explicit negative control.

## Complete native corresponding source

The isolated native contract archives and verifies all 57,781 source files:
the complete pinned runtime Git baseline, both exact reversible patches,
617 generated native inputs and the actual orchestration source. The runtime's
original `.gitattributes` requires CRLF for solution and Windows command files;
their canonical bytes must still recover the exact original Git blob. C++
sources receive no general line-ending exception.

The verifier binds all five ELF files and debug sidecars using their actual
GNU build identities and debug-link CRCs, the original Release/PGO cache,
3,256 compiler commands and 33 actual configure-stage version-source entries.
Normal producer validation also requires the archived runtime host path to map
to the worker's exact source directory through its actual container volume.
An additional mount cannot shadow a source subtree. The outer producer gate
separately enforces the common container security and stage policies.

Native-only validation explicitly returns `fullSdkConsumption: false`. Full
validation requires an actual final SDK member inventory, every one of the
five shared-runtime products, and byte equality of every duplicate native
copy. Nine focused tests cover source substitutions, distinct compiler-output
path bases, feature/optimization changes, debug identity/CRC mismatches and
missing or substituted final SDK copies. Later optimization overrides and
additional nonfallback version markers are rejected explicitly. The retained full source round trip
is `.build/sdk6-native-source-contract-v1/results.json`.

## Remaining full SDK gates

This is native component evidence. Final SDK consumption of these exact five files, archive-only
runtime/TLS/tracing checks, both normal native CPUs and every signed public
consumer gate remain mandatory. Earlier SDK6 archives containing the old
native experiment cannot satisfy the corrected native consumption contract.
