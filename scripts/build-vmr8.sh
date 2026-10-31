#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: build-vmr8.sh --source-dir DIR --sysroot DIR --reports-dir DIR
                     [--action prepare|build|test] [--max-cpu-count N]
                     [--official-sdk-archive /absolute/path/sdk.tar.gz]
Run the pinned .NET 8.0.133 legacy VMR source-build on native Linux ARM64.
Prepare invokes the original prep.sh, which replaces its downloaded PSB archive
with a bootstrapped archive. Preserve the original download before replacement.
The report directory must not contain reports for the selected action already.
EOF
}

source_dir=''
sysroot_dir=''
reports_dir=''
action=build
max_cpu_count=2
official_sdk_archive=''
existing_archives=()
while (($#)); do
  case "$1" in
    --source-dir|--sysroot|--reports-dir|--action|--max-cpu-count|--official-sdk-archive)
      (($# >= 2)) || { usage >&2; exit 2; }
      case "$1" in
        --source-dir) source_dir=$2 ;;
        --sysroot) sysroot_dir=$2 ;;
        --reports-dir) reports_dir=$2 ;;
        --action) action=$2 ;;
        --max-cpu-count) max_cpu_count=$2 ;;
        --official-sdk-archive) official_sdk_archive=$2 ;;
      esac
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ $action == prepare || $action == build || $action == test ]] || { usage >&2; exit 2; }
[[ $max_cpu_count =~ ^[1-9][0-9]*$ && ${#max_cpu_count} -le 3 ]] || { echo 'A positive CPU count of at most 999 is required.' >&2; exit 2; }
[[ $source_dir == /* && $sysroot_dir == /* && $reports_dir == /* ]] || { echo 'Absolute source, sysroot and report paths are required.' >&2; exit 2; }
[[ $(uname -s) == Linux && $(uname -m) == aarch64 ]] || { echo 'Native Linux ARM64 is required.' >&2; exit 1; }
source_dir=$(realpath -e "$source_dir")
sysroot_dir=$(realpath -e "$sysroot_dir")
[[ -f $source_dir/build.sh && -f $source_dir/prep.sh && -d $sysroot_dir/usr/include ]] || { echo 'Source/sysroot is incomplete.' >&2; exit 1; }
expected_commit=7d1bf90885cff22e7da72b27e9848e42fd3cb1ae
[[ $(git -C "$source_dir" rev-parse HEAD) == "$expected_commit" ]] || { echo 'VMR commit mismatch.' >&2; exit 1; }
if [[ -n $official_sdk_archive ]]; then
  [[ $action == test && $official_sdk_archive == /* && -f $official_sdk_archive ]] || { echo 'An existing official SDK archive at an absolute path is supported only in test mode.' >&2; exit 2; }
fi
if [[ $action == prepare ]]; then
  # Upstream prep skips bootstrapping when any PSB archive already exists.
  shopt -s nullglob
  existing_archives=("$source_dir"/prereqs/packages/archive/Private.SourceBuilt.Artifacts.*.tar.gz)
  shopt -u nullglob
  (( ${#existing_archives[@]} <= 1 )) || { echo 'Multiple PSB archives exist; preserve them and inspect the workspace before preparation.' >&2; exit 1; }
  if (( ${#existing_archives[@]} == 1 )); then
    [[ ${existing_archives[0]##*/} == Private.SourceBuilt.Artifacts.Bootstrap.tar.gz ]] || { echo 'An existing non-bootstrap PSB archive would make upstream prep skip ARM64 bootstrapping. Preserve it and resolve the incomplete preparation explicitly.' >&2; exit 1; }
  fi
else
  [[ -x $source_dir/.dotnet/dotnet && -d $source_dir/.dotnet/sdk/8.0.131 && -f $source_dir/prereqs/packages/archive/Private.SourceBuilt.Artifacts.Bootstrap.tar.gz && -f $(dirname "$sysroot_dir")/bootstrap8-prepared.json ]] || { echo 'Run successful preparation with recorded bootstrap hashes before build or test.' >&2; exit 1; }
fi
for tool in clang-18 clang++-18 cmake cpio file python3 taskset; do
  command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done
[[ -x /usr/bin/time ]] || { echo 'GNU time is required to record resource usage.' >&2; exit 1; }
mkdir -p "$reports_dir"
reports_dir=$(realpath -e "$reports_dir")
[[ $reports_dir != "$source_dir" && $reports_dir != "$source_dir"/* && $reports_dir != "$sysroot_dir" && $reports_dir != "$sysroot_dir"/* ]] || { echo 'Reports must be outside the source and sysroot.' >&2; exit 2; }
for name in "$action-command.txt" "$action-resources.txt" "$action.log" "$action-status.json" bootstrap-inputs.json net8-patches-notice.txt net8-patches-apply.json net8-symbol-inputs.json; do
  [[ ! -e $reports_dir/$name && ! -L $reports_dir/$name ]] || { echo "Refusing to overwrite a previous report: $reports_dir/$name" >&2; exit 1; }
done
bootstrap_helper=$(dirname "$(realpath -e "${BASH_SOURCE[0]}")")/watch-bootstrap8.py
inputs_dir=$(dirname "$sysroot_dir")
[[ -f $bootstrap_helper ]] || { echo 'Missing .NET 8 bootstrap preservation helper.' >&2; exit 1; }
if [[ $action != prepare ]]; then
  patch_helper=$(dirname "$bootstrap_helper")/apply-net8-patches.py
  [[ -f $patch_helper ]] || { echo 'Missing .NET 8 pinned backport helper.' >&2; exit 1; }
  printf '%s\n' 'The .NET 8 legacy source-build profile applies two recorded compatibility patches for ARM64 cross-components host detection and portable ASP.NET Core package selection.' | tee "$reports_dir/net8-patches-notice.txt"
  python3 "$patch_helper" apply --source-dir "$source_dir" --reports-dir "$reports_dir"
  python3 "$bootstrap_helper" verify --source-dir "$source_dir" --inputs-dir "$inputs_dir" --report "$reports_dir/bootstrap-inputs.json"
  symbol_helper=$(dirname "$bootstrap_helper")/restore-net8-symbol-inputs.py
  [[ -f $symbol_helper ]] || { echo 'Missing .NET 8 retained symbol-input helper.' >&2; exit 1; }
  python3 "$symbol_helper" --source-dir "$source_dir" --reports-dir "$reports_dir"
fi

export ROOTFS_DIR=$sysroot_dir
export CLR_CC=/usr/bin/clang-18 CLR_CXX=/usr/bin/clang++-18
export CppCompilerAndLinker=/usr/bin/clang-18
# Component builds are separate processes; retain these settings in their environment.
export PortableBuild=true CrossBuild=true
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_NOLOGO=1 DOTNET_PROCESSOR_COUNT=$max_cpu_count
# Arcade uses this fallback for the source-built-artifacts packaging project,
# whose SCM queries are disabled. Component projects retain their own commits.
export BUILD_SOURCEVERSION=$expected_commit
unset NUGET_XMLDOC_MODE SMOKE_TESTS_MSFT_SDK_TARBALL_PATH
if [[ $action == test ]]; then
  export RUNNING_IN_CI=true SMOKE_TESTS_RUNNING_IN_CI=true SMOKE_TESTS_WARN_SDK_CONTENT_DIFFS=true
  [[ -z $official_sdk_archive ]] || export SMOKE_TESTS_MSFT_SDK_TARBALL_PATH=$official_sdk_archive
fi
cpu_affinity=$(python3 - "$max_cpu_count" <<'PY'
import os
import sys
allowed = sorted(os.sched_getaffinity(0))
print(','.join(str(cpu) for cpu in allowed[:int(sys.argv[1])]))
PY
)

if [[ $action == prepare ]]; then
  args=(taskset --cpu-list "$cpu_affinity" ./prep.sh)
else
  # .NET 8 accepts extra MSBuild properties only after its literal -- separator.
  args=(taskset --cpu-list "$cpu_affinity" ./build.sh --clean-while-building --online)
  [[ $action != test ]] || args+=(--run-smoke-test)
  args+=(-- /p:Configuration=Release /p:Platform=arm64 /p:TargetOS=Linux
    /p:TargetRid=linux-arm64 /p:PortableBuild=true /p:CrossBuild=true "/m:$max_cpu_count")
fi
cd "$source_dir"
{
  printf 'Source commit: %s\n' "$expected_commit"
  printf 'Host: %s %s\n' "$(uname -s)" "$(uname -m)"
  printf 'ROOTFS_DIR=%q\n' "$ROOTFS_DIR"
  printf 'CppCompilerAndLinker=%q\n' "$CppCompilerAndLinker"
  printf 'PortableBuild=%s; CrossBuild=%s\n' "$PortableBuild" "$CrossBuild"
  printf 'DOTNET_PROCESSOR_COUNT=%s\n' "$DOTNET_PROCESSOR_COUNT"
  printf 'BUILD_SOURCEVERSION=%s\n' "$BUILD_SOURCEVERSION"
  printf 'CPU affinity=%s\n' "$cpu_affinity"
  if [[ $action == test ]]; then
    printf 'RUNNING_IN_CI=%s\nSMOKE_TESTS_RUNNING_IN_CI=%s\nSMOKE_TESTS_WARN_SDK_CONTENT_DIFFS=%s\n' "$RUNNING_IN_CI" "$SMOKE_TESTS_RUNNING_IN_CI" "$SMOKE_TESTS_WARN_SDK_CONTENT_DIFFS"
    printf 'SMOKE_TESTS_MSFT_SDK_TARBALL_PATH=%q\n' "${SMOKE_TESTS_MSFT_SDK_TARBALL_PATH:-}"
  fi
  printf 'Command: '; printf '%q ' "${args[@]}"; printf '\n'
  clang-18 --version
  cmake --version
} | tee "$reports_dir/$action-command.txt"
watcher_pid=''
stop_watcher() {
  if [[ -n $watcher_pid ]]; then
    if kill -0 "$watcher_pid" 2>/dev/null; then kill "$watcher_pid" 2>/dev/null || true; fi
    wait "$watcher_pid" 2>/dev/null || true
    watcher_pid=''
  fi
}
trap stop_watcher EXIT
if [[ $action == prepare && ${#existing_archives[@]} == 0 ]]; then
  python3 "$bootstrap_helper" watch --source-dir "$source_dir" --inputs-dir "$inputs_dir" > "$reports_dir/bootstrap-preservation-watch.log" 2>&1 &
  watcher_pid=$!
fi
started_at=$(date -u +%FT%TZ)
set +e
/usr/bin/time -v -o "$reports_dir/$action-resources.txt" "${args[@]}" 2>&1 | tee "$reports_dir/$action.log"
pipeline_status=("${PIPESTATUS[@]}")
exit_code=${pipeline_status[0]}
if ((exit_code == 0 && pipeline_status[1] != 0)); then exit_code=${pipeline_status[1]}; fi
set -e
stop_watcher
if [[ $action == prepare && $exit_code == 0 ]]; then
  set +e
  python3 "$bootstrap_helper" finalize --source-dir "$source_dir" --inputs-dir "$inputs_dir" --report "$reports_dir/bootstrap-inputs.json" 2>&1 | tee -a "$reports_dir/$action.log"
  final_status=("${PIPESTATUS[@]}")
  set -e
  if ((final_status[0] != 0)); then exit_code=${final_status[0]};
  elif ((final_status[1] != 0)); then exit_code=${final_status[1]}; fi
fi
python3 - "$reports_dir/$action-status.json" "$action" "$started_at" "$exit_code" "$expected_commit" "$max_cpu_count" "$official_sdk_archive" <<'PY'
import datetime
import json
import sys

path, action, started, code, commit, processors, baseline = sys.argv[1:]
record = {'action': action, 'startedAt': started,
          'finishedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'exitCode': int(code), 'sourceCommit': commit,
          'buildSystem': 'legacy-vmr-source-build', 'sourceOnly': True,
          'targetRid': 'linux-arm64', 'maxCpuCount': int(processors),
          'portableBuildEnvironment': True, 'crossBuildEnvironment': True,
          'buildSourceVersion': commit,
          'onlineBuild': action in ('build', 'test')}
if action == 'test':
    record.update({'officialSdkArchive': baseline or None, 'runningInCi': True,
                   'smokeTestsRunningInCi': True,
                   'warnOnSdkContentDiffs': True})
with open(path, 'w', encoding='utf-8') as stream:
    json.dump(record, stream, indent=2)
    stream.write('\n')
PY
exit "$exit_code"
