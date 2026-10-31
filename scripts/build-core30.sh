#!/usr/bin/env bash
set -euo pipefail
export LANG=C.UTF-8 LC_ALL=C.UTF-8
source_dir=''
inputs_dir=''
reports_dir=''
sysroot_reports=''
profile=''
action=build
cpu_affinity=2,3
max_cpu=2
sdk_archive=''
allow_cold_feed=false
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
    --sdk-archive) sdk_archive=$2 ;;
    --allow-cold-feed) allow_cold_feed=$2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift 2
done
[[ $action == acquire || $action == prepare || $action == build || $action == test ]]
[[ $allow_cold_feed == true || $allow_cold_feed == false ]]
[[ $allow_cold_feed == false || $action == build ]]
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
commit=40de72d1087a1d05dfd39c87f888a0611ec6c60f
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
export NUGET_XMLDOC_MODE=none
export DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER=1
# The retained Arcade tool requests XliffTasks 1.0.0-beta.19252.1, whose exact
# historical package remains on Microsoft's engineering feed.
export RestoreAdditionalProjectSources='https://api.nuget.org/v3/index.json;https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public/nuget/v3/index.json;https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-eng/nuget/v3/index.json;https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-tools/nuget/v3/index.json;https://pkgs.dev.azure.com/dnceng/public/_packaging/myget-legacy/nuget/v3/index.json'
export CC=/usr/bin/clang-6.0 CXX=/usr/bin/clang++-6.0
export PATH="/opt/cbodotnet/llvm6/bin:$PATH"
export XDG_RUNTIME_DIR=$inputs_dir/core30-runtime
mkdir -p "$XDG_RUNTIME_DIR"
chmod 0700 "$XDG_RUNTIME_DIR"
# Each legacy producer receives its own recorded cross switch through the
# adapters. A global CROSSCOMPILE flag would obscure component forwarding.
unset CROSSCOMPILE CrossBuild ROOTFS_DIR
started=$(date -u +%FT%TZ)
finish() {
  code=$?
  trap - EXIT
  python3 - "$reports_dir/$action-status.json" "$action" "$started" "$code" "$cpu_affinity" "$source_dir" "${ROOTFS_DIR:-}" "$NUGET_XMLDOC_MODE" "$DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER" <<'PY'
import datetime, json, sys
path, action, started, code, affinity, source, rootfs, xml_mode, http_handler = sys.argv[1:]
record = {'schemaVersion': 1, 'action': action, 'startedAtUtc': started,
          'finishedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'exitCode': int(code), 'sourceCommit': '40de72d1087a1d05dfd39c87f888a0611ec6c60f',
          'sourceDirectory': source, 'buildSystem': 'legacy-source-build-direct',
          'sourceOnly': True, 'targetRid': 'linux-arm64', 'maxCpuCount': 2,
          'cpuAffinity': affinity, 'sysroot': rootfs or None, 'emulation': False,
          'nugetXmlDocumentationMode': xml_mode,
          'socketsHttpHandlerSelection': http_handler,
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
    --repos-folder "$source_dir/bin/src" --git-dir-folder "$source_dir/.git/modules/src"
    --include-toolset --depth 0)
elif [[ $action == prepare ]]; then
  mkdir "$reports_dir/bootstrap"
  args=(taskset --cpu-list "$cpu_affinity" python3 "$helpers/prepare-core30-bootstrap.py" prepare
    --source-dir "$source_dir" --inputs-dir "$inputs_dir" --reports-dir "$reports_dir/bootstrap" --profile "$profile")
else
  [[ $sysroot_reports == /* && -d $sysroot_reports && ! -L $sysroot_reports ]]
  export ROOTFS_DIR=$inputs_dir/arm64-xenial
  python3 "$helpers/verify-sysroot-core30.py" --sysroot "$ROOTFS_DIR" --reports-dir "$sysroot_reports"
  python3 "$helpers/core30-inputs.py" --source-dir "$source_dir" --profile "$profile" --require-bootstrap --inputs-dir "$inputs_dir" --report "$reports_dir/core30-inputs.json"
  # core30-inputs verifies these exact environment bytes against the original
  # completed bootstrap contract before this file is sourced.
  source "$inputs_dir/bootstrap-state/core30-bootstrap-env.sh"
  python3 "$helpers/apply-core30-patches.py" apply --source-dir "$source_dir" --profile "$profile" --reports-dir "$reports_dir"
  # The original resolver and XPlat tasks share an assembly identity. Install
  # the reviewed current task output before starting the fresh root process.
  mkdir "$reports_dir/resolver-refresh"
  python3 "$helpers/refresh-core30-resolver.py" --source-dir "$source_dir" --inputs-dir "$inputs_dir" --reports-dir "$reports_dir/resolver-refresh" --profile "$profile"
  if [[ $action == test ]]; then
    umask 077
    [[ $sdk_archive == /* && $sdk_archive != *[!A-Za-z0-9_./-]* && -f $sdk_archive && ! -L $sdk_archive ]] || { echo 'Test requires an explicit ordinary SDK archive.' >&2; exit 2; }
    test_root=$inputs_dir/core30-tests/$(basename "$reports_dir")
    python3 "$helpers/prepare-core30-smoke.py" --source-dir "$source_dir" --inputs-dir "$inputs_dir" --reports-dir "$reports_dir" --sdk-archive "$sdk_archive" --test-root "$test_root"
    export SOURCE_BUILD_SMOKE_ARCH=arm64 SOURCE_BUILD_SMOKE_TEST_DIR=$test_root/testing-smoke
    export DOTNET_CLI_HOME=$test_root/testing-smoke/home
    export XDG_RUNTIME_DIR=$test_root/runtime
    export SOURCE_BUILD_SMOKE_SOURCE_ROOT=$source_dir SOURCE_BUILD_SMOKE_NUGET_CONFIG=$reports_dir/test-inputs/NuGet.Config.template
    args=(taskset --cpu-list "$cpu_affinity" bash "$test_root/smoke-test.sh" --projectOutput
      --configuration Release --archiveRestoredPackages --dotnetDir "$test_root/sdk" --prodConBlobFeedUrl '')
  else
  mkdir "$reports_dir/retained-test-templates"
  python3 "$helpers/prepare-core30-template-inputs.py" --inputs-dir "$inputs_dir" --reports-dir "$reports_dir/retained-test-templates"
  export RestoreAdditionalProjectSources="$RestoreAdditionalProjectSources;$inputs_dir/core30-retained-test-templates/feed"
  mkdir "$reports_dir/coreclr-platforms"
  python3 "$helpers/prepare-core30-platforms.py" --source-dir "$source_dir" --inputs-dir "$inputs_dir" --reports-dir "$reports_dir/coreclr-platforms" --profile "$profile"
  mkdir "$reports_dir/net472-references"
  python3 "$helpers/prepare-core30-framework-refs.py" --source-dir "$source_dir" --inputs-dir "$inputs_dir" --reports-dir "$reports_dir/net472-references" --profile "$profile"
  mkdir "$reports_dir/genapi-validation"
  mkdir "$reports_dir/retry-inputs"
  retry_args=(python3 "$helpers/prepare-core30-retry.py" --source-dir "$source_dir" --inputs-dir "$inputs_dir" --reports-dir "$reports_dir/retry-inputs" --profile "$profile")
  [[ $allow_cold_feed != true ]] || retry_args+=(--allow-cold-feed)
  "${retry_args[@]}"
  # Arcade's old shell driver reparses whitespace in MSBuild properties. Give
  # it a single executable path; the wrapper retains the frozen argument list
  # and passes upstream FetchSources' appended arguments through unchanged.
  clone_wrapper=$inputs_dir/core30-tools/darc-clone-$(basename "$reports_dir").sh
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
           '--repos-folder', str(source / 'bin/src'),
           '--git-dir-folder', str(source / '.git/modules/src'), '--include-toolset', '--depth', '0']
content = ('#!/usr/bin/env bash\nset -euo pipefail\nexec ' + ' '.join(shlex.quote(value) for value in command) + ' "$@"\n').encode()
copy = reports / 'darc-clone-wrapper.sh'
record = reports / 'core30-darc-wrapper.json'
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
            'upstreamArgumentsForwarded': True, 'upstreamAppendedArgumentsRequired': False,
            'completePinnedAcquisitionArgumentsBound': True, 'msbuildPropertyValue': str(wrapper),
            'reason': 'The legacy Arcade shell driver splits a multiword DarcCloneCommand property.'}
with record.open('x') as output:
    json.dump(metadata, output, indent=2); output.write('\n')
PY
  [[ $clone_wrapper != *[!A-Za-z0-9_./-]* && -x $clone_wrapper ]]
  args=(taskset --cpu-list "$cpu_affinity" ./build.sh)
  args+=(/p:Configuration=Release /p:Platform=arm64 /p:TargetOS=Linux /p:TargetRid=linux-arm64
    /p:RootRepo=core-sdk /p:NativeArm64Host=true /p:PortableBuild=true /p:DotNetBuildFromSource=true /p:SkipAcquireDarc=true /p:SkipGenerateRootFs=true
    /p:CbodotnetBootstrapPlatformsVersion=3.0.0
    "/p:CbodotnetFrameworkReferenceRoot=$inputs_dir/core30-framework-refs/extracted/build/"
    "/p:CbodotnetGenApiVerifier=$helpers/verify-core30-genapi.py" "/p:CbodotnetGenApiReportDirectory=$reports_dir/genapi-validation"
    "/p:CbodotnetInputVerificationReport=$reports_dir/core30-inputs.json"
    "/p:DarcCloneCommand=$clone_wrapper" "/p:ArmEnvironmentVariables=ROOTFS_DIR=$ROOTFS_DIR"
    /p:ArcadeBootstrapVersion=1.0.0-beta.19381.1 "/p:ArcadeBootstrapDir=$inputs_dir/bootstrap-packages/" "/m:$max_cpu")
  fi
fi
{
  printf 'Source commit: %s\nCPU affinity: %s\nROOTFS_DIR=%s\n' "$commit" "$cpu_affinity" "${ROOTFS_DIR:-}"
  printf 'RestoreAdditionalProjectSources=%s\n' "$RestoreAdditionalProjectSources"
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
  python3 "$helpers/prepare-core30-smoke.py" --summarize --source-dir "$source_dir" --inputs-dir "$inputs_dir" --reports-dir "$reports_dir" --sdk-archive "$sdk_archive" --test-root "$test_root" --upstream-exit-code "$code"
fi
((code == 0)) || exit "$code"
if [[ $action == acquire || $action == prepare ]]; then
  verification=(python3 "$helpers/core30-inputs.py" --source-dir "$source_dir" --profile "$profile" --report "$reports_dir/core30-inputs.json")
  [[ $action != prepare ]] || verification+=(--require-bootstrap --inputs-dir "$inputs_dir")
  "${verification[@]}"
fi
