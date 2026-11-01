#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: build-vmr.sh --source-dir DIR --sysroot DIR --reports-dir DIR [--action build|test]
                    [--binaries-report /absolute/clean-source/NewBinaries.txt]
                    [--build-id YYYYMMDD.N] [--arch arm64|x64]
Run the pinned .NET 10.0.403 VMR profile on a matching native Linux host.
The source and sysroot must already exist. No source-only claim is made.
EOF
}

source_dir=''
sysroot_dir=''
reports_dir=''
action=build
binaries_report=''
build_id='20261028.1'
arch=arm64
while (($#)); do
  case "$1" in
    --source-dir|--sysroot|--reports-dir|--action|--binaries-report|--build-id|--arch)
      (($# >= 2)) || { usage >&2; exit 2; }
      case "$1" in
        --source-dir) source_dir=$2 ;;
        --sysroot) sysroot_dir=$2 ;;
        --reports-dir) reports_dir=$2 ;;
        --action) action=$2 ;;
        --binaries-report) binaries_report=$2 ;;
        --build-id) build_id=$2 ;;
        --arch) arch=$2 ;;
      esac
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ $action == build || $action == test ]] || { usage >&2; exit 2; }
[[ $build_id =~ ^[0-9]{8}\.[1-9][0-9]*$ ]] || { echo 'Build ID must use YYYYMMDD.N with a positive revision.' >&2; exit 2; }
if [[ -n $binaries_report ]]; then
  [[ $action == test && $binaries_report == /* && -f $binaries_report ]] || { echo 'A real clean-source report is required in test mode.' >&2; exit 2; }
fi
[[ -n $source_dir && -n $sysroot_dir && -n $reports_dir ]] || { usage >&2; exit 2; }
case "$arch" in arm64) native=aarch64 ;; x64) native=x86_64 ;; *) echo 'Unsupported architecture.' >&2; exit 2 ;; esac
[[ $(uname -s) == Linux && $(uname -m) == "$native" ]] || { echo 'A matching native Linux host is required.' >&2; exit 1; }
source_dir=$(realpath -e "$source_dir")
sysroot_dir=$(realpath -e "$sysroot_dir")
mkdir -p "$reports_dir"
reports_dir=$(realpath -e "$reports_dir")
[[ -f $source_dir/build.sh && -d $sysroot_dir/usr/include ]] || { echo 'Source/sysroot is incomplete.' >&2; exit 1; }
expected_commit=5a2162bea6845eabc1fc721624a43568c65db3b1
[[ $(git -C "$source_dir" rev-parse HEAD) == "$expected_commit" ]] || { echo 'VMR commit mismatch.' >&2; exit 1; }
for tool in clang-18 clang++-18 cmake cpio file python3; do
  command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done

export ROOTFS_DIR=$sysroot_dir
export CLR_CC=/usr/bin/clang-18 CLR_CXX=/usr/bin/clang++-18
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_NOLOGO=1
unset NUGET_XMLDOC_MODE
export DOTNET_PROCESSOR_COUNT=2

args=(./build.sh --configuration Release --arch "$arch" --os linux
  --branding release --official-build-id "$build_id"
  --clean-while-building --binaryLog
  /p:CrossBuild=true /p:PortableBuild=true /m:2)
[[ $action != test ]] || args+=(--test)
[[ -z $binaries_report ]] || args+=("/p:BinariesReportFile=$binaries_report")
cd "$source_dir"
{
  printf 'Source commit: %s\n' "$expected_commit"
  printf 'Host: %s %s\n' "$(uname -s)" "$(uname -m)"
  printf 'ROOTFS_DIR=%q\n' "$ROOTFS_DIR"
  printf 'Command: '; printf '%q ' "${args[@]}"; printf '\n'
  clang-18 --version
  cmake --version
} | tee "$reports_dir/$action-command.txt"
started_at=$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat())')
set +e
if [[ -x /usr/bin/time ]]; then
  /usr/bin/time -v -o "$reports_dir/$action-resources.txt" "${args[@]}" 2>&1 | tee "$reports_dir/$action.log"
  pipeline_status=("${PIPESTATUS[@]}")
else
  "${args[@]}" 2>&1 | tee "$reports_dir/$action.log"
  pipeline_status=("${PIPESTATUS[@]}")
fi
exit_code=${pipeline_status[0]}
if ((exit_code == 0 && pipeline_status[1] != 0)); then exit_code=${pipeline_status[1]}; fi
set -e
python3 - "$reports_dir/$action-status.json" "$action" "$started_at" "$exit_code" "$expected_commit" "$build_id" "$arch" <<'PY'
import datetime, json, sys
path, action, started, code, commit, build_id, arch = sys.argv[1:]
with open(path, 'w', encoding='utf-8') as stream:
    json.dump({'action': action, 'startedAt': started,
               'finishedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'exitCode': int(code), 'sourceCommit': commit,
               'sourceOnly': False, 'targetRid': 'linux-'+arch, 'officialBuildId': build_id}, stream, indent=2)
    stream.write('\n')
PY
exit "$exit_code"
