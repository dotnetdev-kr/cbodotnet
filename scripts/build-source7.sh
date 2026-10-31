#!/usr/bin/env bash
set -euo pipefail
installer_dir=''
source_dir=''
reports_dir=''
action=build
official_sdk=''
max_cpu=2
while (($#)); do
  (($# >= 2)) || { echo 'Every option requires a value.' >&2; exit 2; }
  case "$1" in
    --installer-dir) installer_dir=$2 ;;
    --source-dir) source_dir=$2 ;;
    --reports-dir) reports_dir=$2 ;;
    --action) action=$2 ;;
    --official-sdk-archive) official_sdk=$2 ;;
    --max-cpu-count) max_cpu=$2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift 2
done
[[ $action == generate || $action == prepare || $action == build || $action == test ]]
[[ $installer_dir == /* && $source_dir == /* && $reports_dir == /* && $max_cpu =~ ^[1-9][0-9]?$ ]]
[[ $(uname -s) == Linux && $(uname -m) == aarch64 && $(id -u) != 0 ]]
installer_dir=$(realpath -e "$installer_dir")
commit=25b977658c06fd0217ec0bc0714398bb9d0a7bb0
[[ $(git -C "$installer_dir" rev-parse HEAD) == "$commit" ]]
mkdir -p "$reports_dir"
reports_dir=$(realpath -e "$reports_dir")
[[ $reports_dir != "$installer_dir" && $reports_dir != "$installer_dir"/* && $reports_dir != "$source_dir" && $reports_dir != "$source_dir"/* ]]
for name in "$action.log" "$action-status.json" "$action-command.txt" "$action-resources.txt"; do
  [[ ! -e $reports_dir/$name && ! -L $reports_dir/$name ]] || { echo 'Refusing to overwrite a previous action report.' >&2; exit 1; }
done
helpers=$(dirname "$(realpath -e "${BASH_SOURCE[0]}")")
export BUILD_SOURCEVERSION=$commit DOTNET_PROCESSOR_COUNT=$max_cpu
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_NOLOGO=1
export CC=/usr/bin/clang-16 CXX=/usr/bin/clang++-16 CLR_CC=/usr/bin/clang-16 CLR_CXX=/usr/bin/clang++-16
export CppCompilerAndLinker=/usr/bin/clang-16
if [[ $action == build || $action == test ]]; then
  export PortableBuild=true CrossBuild=true
else
  unset PortableBuild CrossBuild ROOTFS_DIR
fi
unset SMOKE_TESTS_MSFT_SDK_TARBALL_PATH SMOKE_TESTS_EXCLUDE_OMNISHARP SMOKE_TESTS_DOTNET_DIR
cpu_affinity=$(python3 - "$max_cpu" <<'PY'
import os,sys
print(','.join(map(str, sorted(os.sched_getaffinity(0))[:int(sys.argv[1])])) )
PY
)
if [[ $action == generate ]]; then
  # The upstream generator removes and recreates this directory. Mount its parent.
  [[ $source_dir == /work/source-v7.0.120 && -d /work && ! -L $source_dir ]]
  args=(taskset --cpu-list "$cpu_affinity" ./build.sh /p:Configuration=Release /p:ArcadeBuildTarball=true
    "/p:TarballDir=$source_dir" /p:PreserveTarballGitFolders=true /p:ConvertInternalRepos=true "/m:$max_cpu")
  cd "$installer_dir"
else
  source_dir=$(realpath -e "$source_dir")
  python3 "$helpers/source7-provenance.py" verify --installer-dir "$installer_dir" --source-dir "$source_dir" --reports-dir /project/artifacts/7.0.120-linux-arm64/reports/generation
  if [[ $action == prepare ]]; then
    args=(bash "$helpers/prepare-source7.sh" "$source_dir" /inputs "$reports_dir")
  else
    [[ -d /inputs/arm64-xenial/usr/include ]]
    export ROOTFS_DIR=/inputs/arm64-xenial
    python3 "$helpers/apply-net7-patches.py" apply --source-dir "$source_dir" --installer-dir "$installer_dir" --reports-dir "$reports_dir"
    python3 "$helpers/bootstrap7-inputs.py" verify --source-dir "$source_dir" --inputs-dir /inputs --report "$reports_dir/bootstrap-inputs.json"
    args=(taskset --cpu-list "$cpu_affinity" ./build.sh --clean-while-building --online)
    if [[ $action == test ]]; then
      python3 "$helpers/prepare-net7-test-tools.py" --source-dir "$source_dir" --inputs-dir /inputs --reports-dir "$reports_dir"
      [[ -z $official_sdk || ( $official_sdk == /* && -f $official_sdk ) ]]
      export RUNNING_IN_CI=true SMOKE_TESTS_WARN_SDK_CONTENT_DIFFS=true
      export SMOKE_TESTS_DOTNET_DIR="$source_dir/artifacts/smoke-sdks/$(basename "$reports_dir")/sdk"
      [[ ! -e $SMOKE_TESTS_DOTNET_DIR && ! -L $SMOKE_TESTS_DOTNET_DIR ]] || { echo 'A test must use a fresh extracted SDK directory.' >&2; exit 1; }
      mkdir -p "$(dirname "$SMOKE_TESTS_DOTNET_DIR")"
      [[ -z $official_sdk ]] || export SMOKE_TESTS_MSFT_SDK_TARBALL_PATH=$official_sdk
      args+=(--run-smoke-test)
    fi
    args+=(-- /p:Configuration=Release /p:Platform=arm64 /p:TargetOS=Linux /p:TargetRid=linux-arm64
      /p:PortableBuild=true /p:CrossBuild=true "/m:$max_cpu")
  fi
  cd "$source_dir"
fi
{
  printf 'Installer commit: %s\nBUILD_SOURCEVERSION=%s\nCPU affinity=%s\n' "$commit" "$BUILD_SOURCEVERSION" "$cpu_affinity"
  printf 'PortableBuild=%s CrossBuild=%s ROOTFS_DIR=%s\n' "${PortableBuild:-}" "${CrossBuild:-}" "${ROOTFS_DIR:-}"
  printf 'CppCompilerAndLinker=%s\n' "$CppCompilerAndLinker"
  printf 'SMOKE_TESTS_DOTNET_DIR=%s\nSMOKE_TESTS_MSFT_SDK_TARBALL_PATH=%s\n' "${SMOKE_TESTS_DOTNET_DIR:-}" "${SMOKE_TESTS_MSFT_SDK_TARBALL_PATH:-}"
  printf 'Command: '; printf '%q ' "${args[@]}"; printf '\n'
  clang-16 --version
  cmake --version
} | tee "$reports_dir/$action-command.txt"
started=$(date -u +%FT%TZ)
set +e
/usr/bin/time -v -o "$reports_dir/$action-resources.txt" "${args[@]}" 2>&1 | tee "$reports_dir/$action.log"
codes=("${PIPESTATUS[@]}")
set -e
code=${codes[0]}
if ((code == 0 && codes[1] != 0)); then code=${codes[1]}; fi
if [[ $action == generate && $code == 0 ]]; then
  set +e
  python3 "$helpers/source7-provenance.py" snapshot --installer-dir "$installer_dir" --source-dir "$source_dir" --reports-dir /project/artifacts/7.0.120-linux-arm64/reports/generation
  code=$?
  set -e
fi
python3 - "$reports_dir/$action-status.json" "$action" "$started" "$code" "$commit" "$max_cpu" "$official_sdk" "${SMOKE_TESTS_DOTNET_DIR:-}" <<'PY'
import datetime,json,sys
path,action,started,code,commit,cpus,baseline,test_sdk=sys.argv[1:]
record={'action':action,'startedAt':started,'finishedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'exitCode':int(code),'installerCommit':commit,'buildSourceVersion':commit,'maxCpuCount':int(cpus),
        'buildSystem':'legacy-installer-source-build','sourceOnly':True,'targetRid':'linux-arm64',
        'portableBuild':action in ('build','test'),'crossBuild':action in ('build','test'),
        'officialSdkArchive':baseline or None,'onlineBuild':action in ('build','test'),
        'smokeTestsSdkDirectory':test_sdk or None}
if action == 'test':
    record['testToolsReport']='net7-test-tools.json'
with open(path,'w') as output:
    json.dump(record,output,indent=2)
    output.write('\n')
PY
exit "$code"
