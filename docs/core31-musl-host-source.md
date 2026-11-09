# Original Core3.1 host source component

The [bounded worker](../scripts/core31_musl_host_source.py) builds the five
original Core3.1 host products on native ARM64 Alpine3.24.4: dotnet, apphost,
libhostfxr, libhostpolicy and libnethost. This component checkpoint does not
qualify a complete SDK or a public distribution. The exact retained result is
in the [evidence inventory](core31-musl-host-source.json).

Use original core-setup commit `f94bb2c3ff432dcc4a6229eca2f978197bf06150`,
tree `a2cd9841d6f8f666a0767f56a3636800866d2072` (998 files), with its original
Arcade1.0.0-beta.22314.5 package and original product/global version inputs.
The separately pinned SDK8.0.131 is only an MSBuild version-generation tool.
It is not a source-produced SDK3.1 product. The worker authenticates the full
bootstrap archive and extracted member bytes before execution.

Two exact source adaptations remain explicit: preserve the portable musl RID,
and qualify four existing move calls with std:: for Clang20. No warning is
disabled. Original Release optimization, Werror, stack protection, RELRO/NOW,
debug symbols and generated native version sources remain required. The two
publisher-forced CRLF solution checkouts are authenticated together before
materializing their exact original Git bytes. All998 source bytes and modes
are checked before the adaptations and after the build.

Run in a separate native Alpine builder as UID1000 with exactly two assigned
CPUs, 4GiB total memory/swap, 512PID limit, dropped capabilities and
no-new-privileges. Retain normal container security policies. Mount only the
worker/auditor code, original Git store, original Arcade package, authenticated
bootstrap archive/tree, frozen signed APK indexes at `/indexes`, and separate
fresh work/report directories. The explicit worker invocation is:

```sh
python3 /project/scripts/core31_musl_host_source.py \
  --source-git /inputs/core-setup.git \
  --bootstrap /bootstrap --bootstrap-archive /inputs/bootstrap-sdk.tar.gz \
  --arcade-package /inputs/microsoft.dotnet.arcade.sdk.1.0.0-beta.22314.5.nupkg \
  --work-dir /work/source-host --output-dir /reports/evidence \
  --official-build-id 20261109.6 --execute-reviewed-host-build
```

Use process-scoped Git safe.directory for that one read-only Git store if its
owner differs. Do not change global Git settings or reuse prior output. Bound
the whole container to900seconds. The original build has a600second limit;
after every command, the worker enforces2GiB work and256MiB retained-report
budgets. Global RLIMIT_FSIZE must retain normal inherited infinity: a separate
identical-input version-tool comparison showed the private256MiB global limit
caused SIGXFSZ in anonymous W^X code mappings. No W^X setting was disabled.

The [ELF adapter](../scripts/core31_musl_host_elf.py) invokes the existing
complete provider-specific musl auditor. Every dynamic dependency must resolve
to exact stock packages authenticated against both frozen signed indexes.
GCC's GLIBC_2.0 unwind namespace is allowed only through the existing verified
libgcc provider rule. Actual glibc, compatibility providers and loader changes
remain rejected. Five actual built/installed ELF pairs, their BuildIDs,
debuglink CRCs/DBG files, generated version bytes and compiler/link inputs are
bound together. Two real assets files, eight package inputs and five actual
NuGet content-hash bindings are retained separately from preferred-source
admission.

The reviewed original v8 attempt passed in90.03seconds (native build68.69s),
producing FileVersion3.100.3226.55906 and106 compiler rows including nine native
version compilations. An independent read-only review checked all998 source
files, five products/debug pairs and the complete three-provider proof. The
earlier v7 attempt remains failed despite its separate successful post-audit.
The published worker and ELF adapter relocate only their source/pin paths;
reversing those relocations reconstructs the actual executed bytes. Their
published paths have not been used for an additional host compilation.

Complete SDK/framework/ASP.NET construction, all used preferred-source and
bootstrap contracts, normal Docker producers on both native CPUs and signed
public consumer verification remain pending. The preserved Core3.0 runtime
failure is separate; this component result does not resolve it.
