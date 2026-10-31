#!/usr/bin/env bash
set -euo pipefail
source_dir=''
inputs_dir=''
reports_dir=''
sysroot_reports=''
profile=''
action=build
cpu_affinity=2,3
max_cpu=2
while (($#)); do
  (($# >= 2)) || { echo 'Every option requires a value.' >&2; exit 2; }
  case "$1" in
    --source-dir) source_dir=$2 ;;
    --inputs-dir) inputs_dir=$2 ;;
    --reports-dir) reports_dir=$2 ;;
    --sysroot-reports) sysroot_reports=$2 ;;
    --profile) profile=$2 ;;
    --action) action=$2 ;;
    --cpu-affinity) cpu_affinity=$2 ;;
    --max-cpu-count) max_cpu=$2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift 2
done
[[ $action == acquire || $action == prepare || $action == build || $action == test ]]
[[ $(uname -s) == Linux && $(uname -m) == aarch64 && $(id -u) != 0 ]]
[[ $max_cpu == 2 && $cpu_affinity =~ ^[0-9]+,[0-9]+$ ]]
for path in "$source_dir" "$inputs_dir" "$reports_dir" "$profile"; do
  [[ $path == /* && $path != / && $path != *[!A-Za-z0-9_./-]* && ! -L $path ]] || { echo 'Absolute ordinary control paths without shell metacharacters are required.' >&2; exit 2; }
done
source_dir=$(realpath -e "$source_dir")
inputs_dir=$(realpath -e "$inputs_dir")
reports_dir=$(realpath -e "$reports_dir")
profile=$(realpath -e "$profile")
[[ $reports_dir != "$source_dir" && $reports_dir != "$source_dir"/* && $inputs_dir != "$source_dir" && $inputs_dir != "$source_dir"/* ]]
helpers=$(dirname "$(realpath -e "${BASH_SOURCE[0]}")")
commit=ab8b115b5658237ee8916ae3586600b39fb2fd19
[[ $(git -C "$source_dir" rev-parse --show-toplevel) == "$source_dir" && $(git -C "$source_dir" rev-parse HEAD) == "$commit" ]]
for name in "$action.log" "$action-status.json" "$action-command.txt" "$action-resources.txt"; do
  [[ ! -e $reports_dir/$name && ! -L $reports_dir/$name ]] || { echo 'Refusing a previous action report.' >&2; exit 1; }
done
python3 - "$cpu_affinity" "$max_cpu" <<'PY'
import os, sys
cpus = [int(item) for item in sys.argv[1].split(',')]
if len(set(cpus)) != int(sys.argv[2]) or not set(cpus).issubset(os.sched_getaffinity(0)):
    raise SystemExit('The requested two distinct CPUs are not available to this container')
PY
export DOTNET_PROCESSOR_COUNT=$max_cpu BUILD_SOURCEVERSION=$commit
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_NOLOGO=1 DOTNET_MULTILEVEL_LOOKUP=0
# The historical SDK image otherwise strips package XML documentation during restore.
export NUGET_XMLDOC_MODE=none
export DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER=1
export CC=/usr/bin/clang-9 CXX=/usr/bin/clang++-9
export PATH="/opt/cbodotnet/llvm9/bin:$PATH"
# Each legacy producer receives its own recorded cross switch through the
# adapters. A global CROSSCOMPILE flag would obscure component forwarding.
unset CROSSCOMPILE CrossBuild ROOTFS_DIR
started=$(date -u +%FT%TZ)
finish() {
  code=$?
  trap - EXIT
  python3 - "$reports_dir/$action-status.json" "$action" "$started" "$code" "$cpu_affinity" "$source_dir" "${ROOTFS_DIR:-}" <<'PY'
import datetime, json, sys
path, action, started, code, affinity, source, rootfs = sys.argv[1:]
record = {'schemaVersion': 1, 'action': action, 'startedAtUtc': started,
          'finishedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'exitCode': int(code), 'sourceCommit': 'ab8b115b5658237ee8916ae3586600b39fb2fd19',
          'sourceDirectory': source, 'buildSystem': 'legacy-source-build-direct',
          'sourceOnly': True, 'targetRid': 'linux-arm64', 'maxCpuCount': 2,
          'cpuAffinity': affinity, 'sysroot': rootfs or None, 'emulation': False,
          'nugetXmlDocMode': 'none',
          'bootstrapHttpHandler': 'SocketsHttpHandler',
          'additionalProjectSource': 'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-eng/nuget/v3/index.json' if action in ('build', 'test') else None,
          'scope': 'Actual action result; SDK provenance, functionality and ABI verification are separate.'}
with open(path, 'x') as output:
    json.dump(record, output, indent=2); output.write('\n')
PY
  exit "$code"
}
trap finish EXIT
cd "$source_dir"
if [[ $action == acquire ]]; then
  args=(taskset --cpu-list "$cpu_affinity" python3 "$helpers/clone-legacy-sources.py" clone
    --profile "$profile" --source-dir "$source_dir" --reports-dir "$reports_dir/acquisition"
    --repos-folder "$source_dir/artifacts/src" --git-dir-folder "$source_dir/.git/modules/src"
    --include-toolset --depth 0)
elif [[ $action == prepare ]]; then
  # Use the same upstream entry point as the first recorded bootstrap attempt.
  args=(taskset --cpu-list "$cpu_affinity" bash -c 'set -eo pipefail; source "$1/eng/common/tools.sh"; InitializeDotNetCli true; "$1/.dotnet/dotnet" --info' bootstrap "$source_dir")
else
  [[ $sysroot_reports == /* && -d $sysroot_reports && ! -L $sysroot_reports ]]
  # The exact historical XliffTasks version is retained on the official
  # engineering feed. NuGet appends this source without changing version pins.
  python3 "$helpers/prepare-legacy-xmldoc-recovery.py" --source-dir "$source_dir" --inputs-dir "$inputs_dir" \
    --reports-dir "$reports_dir" --profile "$profile" --dotnet "$source_dir/.dotnet/dotnet"
  export RestoreAdditionalProjectSources="$inputs_dir/xmldoc-recovery/feed;https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-eng/nuget/v3/index.json"
  export ROOTFS_DIR=$inputs_dir/arm64-xenial
  python3 "$helpers/verify-sysroot-core31.py" --sysroot "$ROOTFS_DIR" --reports-dir "$sysroot_reports"
  python3 "$helpers/core31-inputs.py" --source-dir "$source_dir" --profile "$profile" --require-bootstrap --report "$reports_dir/core31-inputs.json"
  python3 "$helpers/apply-core31-patches.py" apply --source-dir "$source_dir" --profile "$profile" --reports-dir "$reports_dir"
  if [[ $action == test ]]; then
    python3 "$helpers/prepare-core31-tests.py" prepare --source-dir "$source_dir" --inputs-dir "$inputs_dir" --reports-dir "$reports_dir"
    # Consumer projects must not inherit native producer compiler/sysroot switches.
    unset PortableBuild CrossBuild CROSSCOMPILE ROOTFS_DIR CC CXX CLR_CC CLR_CXX
  fi
  # Arcade's old shell driver reparses whitespace in MSBuild properties. Give
  # it a single executable path; the wrapper retains the frozen argument list
  # and passes upstream FetchSources' appended arguments through unchanged.
  clone_wrapper=$inputs_dir/core31-tools/darc-clone-$(basename "$reports_dir").sh
  python3 - "$clone_wrapper" "$helpers/clone-legacy-sources.py" "$profile" "$source_dir" "$reports_dir" <<'PY'
import hashlib, json, os, pathlib, shlex, sys
wrapper, cloner, profile, source, reports = map(pathlib.Path, sys.argv[1:])
for path in [wrapper, cloner, profile, source, reports]:
    if not path.is_absolute() or any(item.is_symlink() for item in [path] + list(path.parents)):
        raise SystemExit('The acquisition wrapper requires absolute ordinary control paths')
if not cloner.is_file() or not profile.is_file() or not source.is_dir() or not reports.is_dir():
    raise SystemExit('The frozen acquisition inputs are incomplete')
wrapper.parent.mkdir(exist_ok=True)
if not wrapper.parent.is_dir():
    raise SystemExit('The acquisition tools path is not an ordinary directory')
command = ['/usr/bin/python3', str(cloner), 'clone', '--profile', str(profile),
           '--source-dir', str(source), '--reports-dir', str(reports / 'acquisition'),
           '--git-dir-folder', str(source / '.git/modules/src'), '--include-toolset', '--depth', '0']
content = ('#!/usr/bin/env bash\nset -euo pipefail\nexec ' + ' '.join(shlex.quote(value) for value in command) + ' "$@"\n').encode()
copy = reports / 'darc-clone-wrapper.sh'
record = reports / 'core31-darc-wrapper.json'
if any(path.exists() or path.is_symlink() for path in [wrapper, copy, record]):
    raise SystemExit('Refusing an existing acquisition wrapper or wrapper report')
with wrapper.open('xb') as output:
    output.write(content)
os.chmod(str(wrapper), 0o755)
with copy.open('xb') as output:
    output.write(content)
metadata = {'schemaVersion': 1, 'wrapperPath': str(wrapper), 'wrapperSha256': hashlib.sha256(content).hexdigest(),
            'wrapperBytes': len(content), 'wrapperMode': '0755', 'frozenCommand': command,
            'frozenClonerSha256': hashlib.sha256(cloner.read_bytes()).hexdigest(),
            'frozenProfileSha256': hashlib.sha256(profile.read_bytes()).hexdigest(),
            'upstreamArgumentsForwarded': True, 'msbuildPropertyValue': str(wrapper),
            'reason': 'The legacy Arcade shell driver splits a multiword DarcCloneCommand property.'}
with record.open('x') as output:
    json.dump(metadata, output, indent=2); output.write('\n')
PY
  [[ $clone_wrapper != *[!A-Za-z0-9_./-]* && -x $clone_wrapper ]]
  args=(taskset --cpu-list "$cpu_affinity" ./build.sh)
  [[ $action != test ]] || args+=(--run-smoke-test)
  args+=(/p:Configuration=Release /p:Platform=arm64 /p:TargetOS=Linux /p:TargetRid=linux-arm64
    /p:PortableBuild=true /p:SkipAcquireDarc=true "/p:DarcCloneCommand=$clone_wrapper"
    /p:SkipDownloadingReferencePackages=true /p:SkipDownloadingPreviouslySourceBuiltPackages=true "/m:$max_cpu")
fi
{
  printf 'Source commit: %s\nCPU affinity: %s\nROOTFS_DIR=%s\n' "$commit" "$cpu_affinity" "${ROOTFS_DIR:-}"
  printf 'RestoreAdditionalProjectSources=%s\n' "${RestoreAdditionalProjectSources:-}"
  printf 'NUGET_XMLDOC_MODE=%s\n' "$NUGET_XMLDOC_MODE"
  printf 'DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER=%s\n' "$DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER"
  printf 'Command: '; printf '%q ' "${args[@]}"; printf '\n'
  clang --version
  cmake --version
} | tee "$reports_dir/$action-command.txt"
set +e
/usr/bin/time -v -o "$reports_dir/$action-resources.txt" "${args[@]}" 2>&1 | tee "$reports_dir/$action.log"
codes=("${PIPESTATUS[@]}")
set -e
code=${codes[0]}
if ((code == 0 && codes[1] != 0)); then code=${codes[1]}; fi
if [[ $action == test ]]; then
  set +e
  python3 "$helpers/prepare-core31-tests.py" finalize --source-dir "$source_dir" --inputs-dir "$inputs_dir" \
    --reports-dir "$reports_dir" --upstream-exit-code "$code"
  validation=$?
  set -e
  if ((code == 0 && validation != 0)); then code=$validation; fi
fi
((code == 0)) || exit "$code"
if [[ $action == acquire || $action == prepare ]]; then
  verification=(python3 "$helpers/core31-inputs.py" --source-dir "$source_dir" --profile "$profile" --report "$reports_dir/core31-inputs.json")
  [[ $action != prepare ]] || verification+=(--require-bootstrap)
  "${verification[@]}"
fi
