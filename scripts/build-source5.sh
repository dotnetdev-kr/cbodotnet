#!/usr/bin/env bash
set -euo pipefail
source_dir=''
inputs_dir=''
reports_dir=''
profile=''
sysroot_reports=''
action=build
cpu_affinity=4,5
max_cpu=2
root_logger=false
arch=arm64
while (($#)); do
  (($# >= 2)) || { echo 'Every option requires a value.' >&2; exit 2; }
  case "$1" in
    --arch) arch=$2 ;;
    --source-dir) source_dir=$2 ;;
    --inputs-dir) inputs_dir=$2 ;;
    --reports-dir) reports_dir=$2 ;;
    --profile) profile=$2 ;;
    --sysroot-reports-dir) sysroot_reports=$2 ;;
    --action) action=$2 ;;
    --cpu-affinity) cpu_affinity=$2 ;;
    --max-cpu-count) max_cpu=$2 ;;
    --root-pipeline-logger) root_logger=$2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift 2
done
[[ $action == prepare || $action == build || $action == test ]]
[[ $root_logger == true || $root_logger == false ]]
[[ $source_dir == /* && $inputs_dir == /* && $reports_dir == /* && $profile == /* && $sysroot_reports == /* ]]
[[ $max_cpu == 2 && $cpu_affinity == 4,5 ]]
case "$arch" in arm64) expected_uname=aarch64; native_host_property=NativeArm64Host ;; x64) expected_uname=x86_64; native_host_property=NativeX64Host ;; *) echo 'Unsupported native architecture.' >&2; exit 2 ;; esac
[[ $(uname -s) == Linux && $(uname -m) == "$expected_uname" && $(id -u) != 0 ]]
export CBODOTNET_LEGACY_ARCH=$arch
arch_args=()
[[ $arch == arm64 ]] || arch_args=(--arch x64)
source_dir=$(realpath -e "$source_dir")
inputs_dir=$(realpath -e "$inputs_dir")
profile=$(realpath -e "$profile")
mkdir -p "$reports_dir"
reports_dir=$(realpath -e "$reports_dir")
[[ $reports_dir != "$source_dir" && $reports_dir != "$source_dir"/* && $reports_dir != "$inputs_dir" && $reports_dir != "$inputs_dir"/* ]]
for name in "$action.log" "$action-status.json" "$action-command.txt" "$action-resources.txt"; do
  [[ ! -e $reports_dir/$name && ! -L $reports_dir/$name ]] || { echo 'Refusing a previous action report.' >&2; exit 1; }
done
helpers=$(dirname "$(realpath -e "${BASH_SOURCE[0]}")")
sysroot_verifier=("$helpers/verify-sysroot5.py")
[[ $arch == arm64 ]] || sysroot_verifier=("$helpers/verify-legacy-x64-sysroot.py" --family net5)
commit=d414ecb2d997a9b3f38aaaeddace30ca097e546d
started=$(date -u +%FT%TZ)
phase=preflight
finish() {
  result=$?
  trap - EXIT
  python3 - "$reports_dir/$action-status.json" "$action" "$started" "$result" "$phase" "$source_dir" "$cpu_affinity" "$root_logger" <<'PY'
import datetime,json,sys
path,action,started,code,phase,source,affinity,logger=sys.argv[1:]
record={'action':action,'startedAtUtc':started,'finishedAtUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'exitCode':int(code),'lastPhase':phase,'sourceRoot':source,
        'sourceCommit':'d414ecb2d997a9b3f38aaaeddace30ca097e546d','sdkVersion':'5.0.214',
        'buildSystem':'legacy-source-build-direct','sourceOnly':True,'online':True,'rootDotNetBuildFromSource':True,
        'targetRid':'linux-'+__import__('os').environ['CBODOTNET_LEGACY_ARCH'],'cpuAffinity':affinity,'maxCpuCount':2,
        'portableBuild':action in ('build','test'),'crossBuild':action in ('build','test'),
        'rootPipelineLogger':logger=='true','productBuildExecuted':phase=='upstream-build'}
with open(path,'x',encoding='utf-8') as output:
    json.dump(record,output,indent=2)
    output.write('\n')
PY
  exit "$result"
}
trap finish EXIT
[[ $(git -C "$source_dir" rev-parse HEAD) == "$commit" ]]
python3 - "$cpu_affinity" <<'PY'
import os,sys
required=set(map(int,sys.argv[1].split(',')))
if not required.issubset(os.sched_getaffinity(0)):
    raise SystemExit('The isolated CPU affinity is unavailable')
PY
export DOTNET_PROCESSOR_COUNT=$max_cpu BUILD_SOURCEVERSION=$commit
export CC=/usr/bin/clang-9 CXX=/usr/bin/clang++-9 CLR_CC=/usr/bin/clang-9 CLR_CXX=/usr/bin/clang++-9
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_NOLOGO=1
# The retained SDK base sets skip; SDK/F# layouts require XML documentation.
export NUGET_XMLDOC_MODE=none
# The pinned XliffTasks prerelease remains on the official engineering feed.
export RestoreAdditionalProjectSources=https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-eng/nuget/v3/index.json
if [[ $action != prepare ]]; then
  phase=xml-documentation-cache-recovery
  python3 "$helpers/prepare-legacy-xmldoc-recovery.py" --source-dir "$source_dir" --inputs-dir "$inputs_dir" --reports-dir "$reports_dir" --profile "$profile" --dotnet "$inputs_dir/sdk-5.0.212/dotnet"
  export RestoreAdditionalProjectSources="$inputs_dir/xmldoc-recovery/feed;$RestoreAdditionalProjectSources"
fi
mkdir "$reports_dir/bootstrap"
phase=bootstrap
bootstrap_action=verify
[[ $action != prepare ]] || bootstrap_action=prepare
taskset --cpu-list "$cpu_affinity" python3 "$helpers/prepare-net5-bootstrap.py" "${arch_args[@]}" "$bootstrap_action" \
  --source-dir "$source_dir" --inputs-dir "$inputs_dir" --reports-dir "$reports_dir/bootstrap" --profile "$profile"
contract=$inputs_dir/bootstrap-state/net5-bootstrap-contract.json
source "$inputs_dir/bootstrap-state/net5-bootstrap-env.sh"
export PATH="$DOTNET_INSTALL_DIR:$PATH"
if [[ $root_logger == true && $action == build ]]; then
  eval "$(python3 - "$contract" <<'PY'
import json,shlex,sys
for key,value in json.load(open(sys.argv[1]))['rootPipelineLoggerEnvironment'].items():
    print('export '+key+'='+shlex.quote(value))
PY
)"
fi
phase=source-acquisition-adapter
invocations=$inputs_dir/invocations
mkdir -p "$invocations"
invocation=$invocations/$(basename "$reports_dir")
[[ ! -e $invocation && ! -L $invocation ]] || { echo 'Use a new attempt directory for the immutable adapter.' >&2; exit 1; }
mkdir "$invocation"
wrapper=$invocation/darc-clone
[[ $wrapper != *[[:space:]]* ]] || { echo 'The legacy source adapter requires a wrapper path without whitespace.' >&2; exit 1; }
python3 - "$wrapper" "$helpers/clone-legacy-sources.py" "$profile" "$source_dir" "$reports_dir/source-acquisition" <<'PY'
import os,pathlib,shlex,sys
wrapper,cloner,profile,source,reports=sys.argv[1:]
arguments=['python3',cloner,'--profile',profile,'--source-dir',source,'--reports-dir',reports,
           '--git-dir-folder',source+'/.git/modules/src','--include-toolset','--depth','0']
with pathlib.Path(wrapper).open('x',encoding='utf-8') as output:
    output.write('#!/usr/bin/env bash\nset -euo pipefail\nexec '+' '.join(map(shlex.quote,arguments))+' "$@"\n')
os.chmod(wrapper,0o755)
PY
cp -- "$wrapper" "$reports_dir/darc-clone-wrapper.sh"
mapfile -t bootstrap_args < <(python3 - "$contract" <<'PY'
import json,sys
for argument in json.load(open(sys.argv[1]))['msbuildArguments']:
    print(argument)
PY
)
if [[ $action == prepare ]]; then
  # Populate exact inputs now; the product build still runs its real FetchSources
  # target and adapter verification rather than synthesizing a completion marker.
  phase=source-prepare
  args=(taskset --cpu-list "$cpu_affinity" "$wrapper" --repos-folder "$source_dir/artifacts/src")
else
  phase=sysroot-verification
  python3 "${sysroot_verifier[@]}" --sysroot "$inputs_dir/$arch-xenial" --reports-dir "$sysroot_reports"
  phase=compatibility-patches
  python3 "$helpers/apply-net5-patches.py" "${arch_args[@]}" apply --source-dir "$source_dir" --reports-dir "$reports_dir"
  if [[ $action == test ]]; then
    phase=fresh-test-setup
    python3 "$helpers/prepare-net5-tests.py" "${arch_args[@]}" prepare --source-dir "$source_dir" --inputs-dir "$inputs_dir" --reports-dir "$reports_dir"
    # Generated consumer projects should not inherit native producer switches.
    unset PortableBuild CrossBuild ROOTFS_DIR CC CXX CLR_CC CLR_CXX
  else
    export PortableBuild=true CrossBuild=true ROOTFS_DIR=$inputs_dir/$arch-xenial
  fi
  args=(taskset --cpu-list "$cpu_affinity" ./build.sh --with-sdk "$DOTNET_INSTALL_DIR")
  [[ $action != test ]] || args+=(--run-smoke-test)
  [[ $root_logger != true || $action != build ]] || args+=(--ci)
  args+=(/p:Configuration=Release /p:Platform=$arch /p:TargetOS=Linux /p:TargetRid=linux-$arch
    /p:DotNetBuildFromSource=true
    /p:PortableBuild=true /p:CrossBuild=true /p:UseSystemLibraries=false /p:UseSystemLibunwind=false
    /p:BuildPortableRuntime=false /p:BuildPortableSdk=false /p:ContinuousIntegrationBuild=true
    /p:SkipAcquireDarc=true "/p:DarcCloneCommand=$wrapper"
    /p:SkipDownloadingReferencePackages=true /p:SkipDownloadingPreviouslySourceBuiltPackages=true
    "${bootstrap_args[@]}" "/m:$max_cpu")
fi
{
  printf 'Source commit: %s\nBUILD_SOURCEVERSION=%s\nCPU affinity=%s\n' "$commit" "$BUILD_SOURCEVERSION" "$cpu_affinity"
  printf 'PortableBuild=%s CrossBuild=%s ROOTFS_DIR=%s\n' "${PortableBuild:-}" "${CrossBuild:-}" "${ROOTFS_DIR:-}"
  printf 'CC=%s CXX=%s\nDarcCloneCommand=%s\n' "${CC:-}" "${CXX:-}" "$wrapper"
  printf 'RestoreAdditionalProjectSources=%s\n' "$RestoreAdditionalProjectSources"
  printf 'NUGET_XMLDOC_MODE=%s\n' "$NUGET_XMLDOC_MODE"
  printf 'Command: '; printf '%q ' "${args[@]}"; printf '\n'
  clang-9 --version
  cmake --version
} | tee "$reports_dir/$action-command.txt"
cd "$source_dir"
[[ $action != build ]] || phase=upstream-build
[[ $action != test ]] || phase=upstream-test
set +e
/usr/bin/time -v -o "$reports_dir/$action-resources.txt" "${args[@]}" 2>&1 | tee "$reports_dir/$action.log"
codes=("${PIPESTATUS[@]}")
set -e
code=${codes[0]}
if ((code == 0 && codes[1] != 0)); then code=${codes[1]}; fi
if [[ $action == test ]]; then
  set +e
  python3 "$helpers/prepare-net5-tests.py" "${arch_args[@]}" finalize --source-dir "$source_dir" --inputs-dir "$inputs_dir" --reports-dir "$reports_dir" --upstream-exit-code "$code"
  validation=$?
  set -e
  if ((code == 0 && validation != 0)); then code=$validation; fi
fi
exit "$code"
