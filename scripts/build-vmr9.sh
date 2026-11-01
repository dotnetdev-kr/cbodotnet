#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: build-vmr9.sh --source-dir DIR --sysroot DIR --reports-dir DIR
                     [--action build|test] [--max-cpu-count N]
                     [--arch arm64|x64]
                     [--official-sdk-archive /absolute/path/sdk.tar.gz]
Run the pinned .NET 9.0.123 VMR on a matching native Linux host using a prepared sysroot.
The report directory must not already contain reports for the selected action.
This is the ordinary VMR build; it does not enable source-only mode.
EOF
}

source_dir=''
sysroot_dir=''
reports_dir=''
action=build
max_cpu_count=2
official_sdk_archive=''
arch=arm64
while (($#)); do
  case "$1" in
    --source-dir|--sysroot|--reports-dir|--action|--max-cpu-count|--official-sdk-archive|--arch)
      (($# >= 2)) || { usage >&2; exit 2; }
      case "$1" in
        --source-dir) source_dir=$2 ;;
        --sysroot) sysroot_dir=$2 ;;
        --reports-dir) reports_dir=$2 ;;
        --action) action=$2 ;;
        --max-cpu-count) max_cpu_count=$2 ;;
        --official-sdk-archive) official_sdk_archive=$2 ;;
        --arch) arch=$2 ;;
      esac
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ $action == build || $action == test ]] || { usage >&2; exit 2; }
[[ $max_cpu_count =~ ^[1-9][0-9]*$ && ${#max_cpu_count} -le 3 ]] || { echo 'A positive CPU count of at most 999 is required.' >&2; exit 2; }
[[ $source_dir == /* && $sysroot_dir == /* && $reports_dir == /* ]] || { echo 'Absolute source, sysroot and report paths are required.' >&2; exit 2; }
case "$arch" in arm64) native_machine=aarch64 ;; x64) native_machine=x86_64 ;; *) usage >&2; exit 2 ;; esac
[[ $(uname -s) == Linux && $(uname -m) == "$native_machine" ]] || { echo 'A native Linux host matching --arch is required.' >&2; exit 1; }
source_dir=$(realpath -e "$source_dir")
sysroot_dir=$(realpath -e "$sysroot_dir")
[[ -f $source_dir/build.sh && -d $sysroot_dir/usr/include ]] || { echo 'Source/sysroot is incomplete.' >&2; exit 1; }
expected_commit=9f04b57d1366e21b3178648493d6edffeff2216e
[[ $(git -C "$source_dir" rev-parse HEAD) == "$expected_commit" ]] || { echo 'VMR commit mismatch.' >&2; exit 1; }
if [[ $action == test ]]; then
  [[ $official_sdk_archive == /* && -f $official_sdk_archive ]] || { echo 'Test mode requires an existing official SDK archive at an absolute path.' >&2; exit 2; }
elif [[ -n $official_sdk_archive ]]; then
  echo '--official-sdk-archive requires test mode.' >&2
  exit 2
fi
for tool in clang-18 clang++-18 cmake cpio file python3 taskset; do
  command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done
[[ -x /usr/bin/time ]] || { echo 'GNU time is required to record resource usage.' >&2; exit 1; }
mkdir -p "$reports_dir"
reports_dir=$(realpath -e "$reports_dir")
[[ $reports_dir != "$source_dir" && $reports_dir != "$source_dir"/* && $reports_dir != "$sysroot_dir" && $reports_dir != "$sysroot_dir"/* ]] || { echo 'Reports must be outside the source and sysroot.' >&2; exit 2; }
for name in "$action-command.txt" "$action-resources.txt" "$action.log" "$action-status.json"; do
  [[ ! -e $reports_dir/$name && ! -L $reports_dir/$name ]] || { echo "Refusing to overwrite a previous report: $reports_dir/$name" >&2; exit 1; }
done

export ROOTFS_DIR=$sysroot_dir
export CLR_CC=/usr/bin/clang-18 CLR_CXX=/usr/bin/clang++-18
# NativeAOT uses this MSBuild property independently of CLR_CC/CLR_CXX.
export CppCompilerAndLinker=/usr/bin/clang-18
# Component builds are separate processes; retain portability in their environment.
export PortableBuild=true
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_NOLOGO=1 DOTNET_PROCESSOR_COUNT=$max_cpu_count
unset NUGET_XMLDOC_MODE
cpu_affinity=$(python3 - "$max_cpu_count" <<'PY'
import os
import sys
allowed = sorted(os.sched_getaffinity(0))
print(','.join(str(cpu) for cpu in allowed[:int(sys.argv[1])]))
PY
)

# This tag uses --rid and MSBuild properties, rather than .NET 10's CLI flags.
# Preserve upstream official versioning; do not synthesize a new package stamp.
# Native build scripts call nproc independently of the MSBuild node count.
args=(taskset --cpu-list "$cpu_affinity" ./build.sh --configuration Release --rid "linux-$arch"
  --ci --clean-while-building --binaryLog
  "/p:TargetArchitecture=$arch" /p:TargetOS=linux
  /p:CrossBuild=true /p:PortableBuild=true "/m:$max_cpu_count")
[[ $action != test ]] || args+=(--test "/p:UBTestsMsftSdkArchivePath=$official_sdk_archive")
cd "$source_dir"
{
  printf 'Source commit: %s\n' "$expected_commit"
  printf 'Host: %s %s\n' "$(uname -s)" "$(uname -m)"
  printf 'ROOTFS_DIR=%q\n' "$ROOTFS_DIR"
  printf 'CppCompilerAndLinker=%q\n' "$CppCompilerAndLinker"
  printf 'PortableBuild=%s\n' "$PortableBuild"
  printf 'DOTNET_PROCESSOR_COUNT=%s\n' "$DOTNET_PROCESSOR_COUNT"
  printf 'CPU affinity=%s\n' "$cpu_affinity"
  printf 'Command: '; printf '%q ' "${args[@]}"; printf '\n'
  clang-18 --version
  cmake --version
} | tee "$reports_dir/$action-command.txt"
started_at=$(date -u +%FT%TZ)
set +e
/usr/bin/time -v -o "$reports_dir/$action-resources.txt" "${args[@]}" 2>&1 | tee "$reports_dir/$action.log"
pipeline_status=("${PIPESTATUS[@]}")
exit_code=${pipeline_status[0]}
if ((exit_code == 0 && pipeline_status[1] != 0)); then exit_code=${pipeline_status[1]}; fi
set -e
python3 - "$reports_dir/$action-status.json" "$action" "$started_at" "$exit_code" "$expected_commit" "$max_cpu_count" "$arch" <<'PY'
import datetime
import json
import sys

path, action, started, code, commit, processors, architecture = sys.argv[1:]
with open(path, 'w', encoding='utf-8') as stream:
    json.dump({'action': action, 'startedAt': started,
               'finishedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'exitCode': int(code), 'sourceCommit': commit,
               'sourceOnly': False, 'targetRid': 'linux-' + architecture,
               'maxCpuCount': int(processors)}, stream, indent=2)
    stream.write('\n')
PY
exit "$exit_code"
