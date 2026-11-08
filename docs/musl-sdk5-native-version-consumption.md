# SDK5 native version consumption correction

The earlier private SDK5 experiments generated the dated upstream
`artifacts/obj/_version.c` and `runtime_version.h`, but that was insufficient
evidence of the version actually compiled into the native products. All six
retained ELF products contain `42.42.42.42424` and the correct runtime source
commit. Their functional tests remain recorded; their dated native version
claims are superseded by this finding. None of those experiments qualified a
release or complete source admission.

The original `eng/native/build-commons.sh` invokes `GenerateRuntimeVersionFile`
again during configure. It writes `version.c` into the actual CoreCLR object
directory and a separate `runtime_version.h` into its parent. The previous
worker passed the product version and official build ID only to the first
invocation. The second invocation therefore produced the fallback version.

The corrected worker forwards the same version, official build ID, continuous
integration and compiler-process arguments through the original configure
wrapper's supported unprocessed MSBuild arguments. It does not override CMake's
original version-source selection or edit a generated source afterward.

Before compiling, the worker requires both actual configure-generated inputs
to equal their dated upstream counterparts byte for byte and checks the actual
compiler database's version-source operands. It retains the configure-stage
version producer's own binlog. After compiling, every one of the six ELF files
must contain exactly the dated version/source marker, with no fallback or mixed
version marker. The actual source/header fingerprints, compiler rows and ELF
observations are retained in `native-version-consumption.json`.

Five regression tests reject a correct first header hiding a fallback second
source, a changed actual header, an unrelated compiler operand, and missing,
fallback or mixed ELF version strings. A fresh complete native build and its
subsequent cold, synchronization, tracing and final archive tests are required
before normal admission. Existing archives and historical proof files remain
unchanged, and both CPU profiles keep their qualification and release gates
closed.

The corrected ARM64 native worker completed in the retained
`native-clr5-normal-worker-v3` experiment. Both original version producers emit
the same 125-byte source and 374-byte header, and the compiler database consumes
that actual configure-stage `version.c`. Every native ELF, including Crossgen
and the LTTng provider, contains exactly
`5.0.1726.55802 @Commit: 6a984143635bde23e728abaaccbde52f5ea8fa3e`.
Both version-producer binlogs and all six matching debug sidecars are retained.

The subsequent private SDK archive `genuine-sdk5-own-components-v9` contains
the exact new native bytes and passes offline build/run, TLS, ELF, all fourteen
exception/synchronization checks, and actual LTTng observation of 80 GC start,
80 GC end and one independent control event. Its unchanged original 68-case
suite detects a separate missing Worker SDK layout directory. That failure and
the archive are preserved while the original managed layout build order is
corrected. This intermediate archive is neither a complete SDK validation nor a
release candidate. No x64 native execution has been claimed.
