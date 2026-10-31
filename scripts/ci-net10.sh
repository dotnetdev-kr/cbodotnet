#!/usr/bin/env bash
# Run the pinned .NET 10 profile on a fresh native ARM64 Linux CI worker.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

usage() {
  cat <<'HELP'
Usage: ci-net10.sh prepare|build|scan|test|verify|collect
                    --workspace ABS --output-dir ABS
                    --build-id YYYYMMDD.N --build-revision POSITIVEINT

Requires a nonroot native ARM64 Linux account with passwordless sudo access to
rootful Podman. Workspaces and delivery directories must be fresh for prepare.
No SDK, source cache, prior report or existing delivery is deleted or replaced.
The six stages run in order. Final collection writes its receipt outside reports.
HELP
}
die() { printf 'error: %s\n' "$*" >&2; exit 2; }
[[ ${1:-} != --help && ${1:-} != -h ]] || { usage; exit 0; }
stage=${1:-}; [[ $# == 0 ]] || shift
case "$stage" in prepare|build|scan|test|verify|collect) ;; *) usage >&2; exit 2 ;; esac
workspace='' output='' build_id='' revision=''
while (($#)); do
  case "$1" in
    --workspace|--output-dir|--build-id|--build-revision)
      (($# >= 2)) || die "Missing value: $1"
      case "$1" in --workspace) workspace=$2 ;; --output-dir) output=$2 ;; --build-id) build_id=$2 ;; --build-revision) revision=$2 ;; esac
      shift 2 ;;
    *) die "Unknown argument: $1" ;;
  esac
done
[[ $build_id =~ ^[0-9]{8}\.[1-9][0-9]*$ ]] || die 'A build ID in YYYYMMDD.N form is required.'
[[ $revision =~ ^[1-9][0-9]*$ ]] || die 'A positive build revision is required.'
for value in "$workspace" "$output"; do
  [[ $value == /* && $value != / && $value != *:* && $value != *$'\n'* && $value != *$'\r'* ]] || die 'Use non-root absolute paths without volume delimiters.'
done
for tool in python3 git realpath uname id sudo podman taskset sha256sum; do command -v "$tool" >/dev/null || die "Missing host tool: $tool"; done
[[ $(uname -s) == Linux && $(uname -m) == aarch64 ]] || die 'A native Linux ARM64 host is required; emulation is not accepted.'
uid=$(id -u); gid=$(id -g)
[[ $uid != 0 ]] || die 'Run the driver as the nonroot checkout owner.'
project=$(realpath -e "$(dirname "${BASH_SOURCE[0]}")/..")
python3 - "$workspace" "$output" <<'PY'
import pathlib, sys
for value in sys.argv[1:]:
    path = pathlib.Path(value)
    if any(p.is_symlink() for p in [path, *path.parents]):
        raise SystemExit('Symlinks in CI workspace/delivery paths are not allowed')
PY
workspace=$(realpath -m "$workspace"); output=$(realpath -m "$output")
[[ $workspace != "$output" && $workspace != "$output"/* && $output != "$workspace"/* ]] || die 'Workspace and delivery must be separate directories.'
project_commit=$(git -C "$project" rev-parse HEAD)
[[ -z $(git -C "$project" status --porcelain --untracked-files=all) ]] || die 'The current orchestration checkout must be pristine.'
source_commit=5a2162bea6845eabc1fc721624a43568c65db3b1
run_id=${GITHUB_RUN_ID:-$revision}; run_attempt=${GITHUB_RUN_ATTEMPT:-1}
[[ $run_id =~ ^[1-9][0-9]*$ && $run_attempt =~ ^[1-9][0-9]*$ ]] || die 'Run identity must contain positive integers.'
workflow_ref=${GITHUB_WORKFLOW_REF:-local}
source_dir=$workspace/source
shared_source_dir=$workspace/shared-vmr-source
clean_dir=$workspace/clean-source
inputs=$workspace/inputs
home=$workspace/home
candidate=$workspace/candidate
state=$workspace/ci-net10-state.json
reports=$output/reports
snapshot=$reports/ci-inputs/project
profile=$reports/ci-inputs/effective-profile.json
engine=(sudo -n -- podman --cgroup-manager=cgroupfs --events-backend=file)
cpus=$(python3 - <<'PY'
import os
cpus = sorted(os.sched_getaffinity(0))
if len(cpus) < 2:
    raise SystemExit('At least two allowed CPUs are required')
print(','.join(map(str, cpus[:2])))
PY
)

# Refuse symlinked roots or ancestors before creating any run-owned directory.
python3 - "$workspace" "$output" "$build_id" <<'PY'
import datetime, pathlib, sys
for value in sys.argv[1:3]:
    path = pathlib.Path(value)
    if any(p.is_symlink() for p in [path, *path.parents]):
        raise SystemExit('Symlinks in CI workspace/delivery paths are not allowed')
datetime.datetime.strptime(sys.argv[3].split('.')[0], '%Y%m%d')
PY
if [[ $stage == prepare ]]; then
  for path in "$workspace" "$output"; do
    [[ ! -e $path || ( -d $path && -z $(find "$path" -mindepth 1 -maxdepth 1 -print -quit) ) ]] || die "Prepare requires a fresh empty directory: $path"
  done
  mkdir -p -- "$source_dir" "$inputs" "$home/.xdg" "$candidate" "$reports/ci/stages" "$reports/ci/logs"
  rmdir -- "$source_dir"
  chmod 700 "$home" "$home/.xdg"
else
  [[ -f $state && -d $snapshot && -f $profile ]] || die 'Prepare must complete in this exact workspace first.'
fi
receipt=$reports/ci/stages/$stage.json
[[ $stage != collect ]] || receipt=$output/collect-receipt.json
[[ ! -e $receipt && ! -L $receipt ]] || die "Refusing a previous stage receipt: $receipt"
mkdir -p -- "$reports/ci/logs"
commands=$reports/ci/logs/$stage-commands.jsonl
log=$reports/ci/logs/$stage.log
if [[ $stage == collect ]]; then commands=$output/collect-commands.jsonl; log=$output/collect.log; fi
[[ ! -e $commands && ! -L $commands && ! -e $log && ! -L $log ]] || die 'Refusing existing stage logs.'
facts=$(mktemp "$workspace/stage-facts.XXXXXXXX")
printf '{}\n' > "$facts"
started=$(python3 -c 'import datetime; print(datetime.datetime.now(datetime.timezone.utc).isoformat())')
image_id=''

fact() {
  python3 - "$facts" "$1" "${2:-}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); data = json.loads(p.read_text())
data[sys.argv[2]] = json.loads(sys.argv[3])
p.write_text(json.dumps(data) + '\n')
PY
}
path_fact() {
  python3 - "$facts" "$1" "$2" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); data = json.loads(p.read_text())
data.setdefault('paths', {})[sys.argv[2]] = sys.argv[3]
p.write_text(json.dumps(data) + '\n')
PY
}
run() {
  python3 - "$commands" "$@" <<'PY'
import json, sys
with open(sys.argv[1], 'a', encoding='utf-8') as out:
    out.write(json.dumps(sys.argv[2:]) + '\n')
PY
  printf 'Running:' | tee -a "$log"
  printf ' %q' "$@" | tee -a "$log"
  printf '\n' | tee -a "$log"
  local result
  set +e
  "$@" 2>&1 | tee -a "$log"
  local status=("${PIPESTATUS[@]}")
  set -e
  result=${status[0]}
  ((result != 0 || status[1] == 0)) || result=${status[1]}
  return "$result"
}
finish() {
  local code=$?
  trap - EXIT
  set +e
  python3 - "$receipt" "$facts" "$commands" "$stage" "$code" "$started" "$source_commit" "$project_commit" "$build_id" "$revision" "$run_id" "$run_attempt" "$image_id" "$workspace" "$output" "$cpus" <<'PY'
import datetime, hashlib, json, pathlib, sys
(target, facts, commands, stage, code, started, source, project, build, revision,
 run_id, attempt, image, workspace, output, cpus) = sys.argv[1:]
record = json.loads(pathlib.Path(facts).read_text())
record.update({'schemaVersion': 1, 'stage': stage, 'status': 'passed' if code == '0' else 'failed',
               'exitCode': int(code), 'sourceCommit': source, 'projectCommit': project,
               'buildId': build, 'buildRevision': revision, 'runId': run_id, 'runAttempt': attempt,
               'imageId': image or None, 'startedAtUtc': started,
               'finishedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'environment': {'nativeArchitecture': 'aarch64', 'uid': __import__('os').getuid(),
                               'gid': __import__('os').getgid(), 'allowedCpuSelection': cpus,
                               'workspace': workspace, 'delivery': output},
               'commands': [json.loads(line) for line in pathlib.Path(commands).read_text().splitlines()]
                           if pathlib.Path(commands).is_file() else []})
if stage == 'collect' and code == '0':
    p = pathlib.Path(output) / 'build-manifest.json'
    data = p.read_bytes()
    record['manifest'] = {'path': 'build-manifest.json', 'bytes': len(data),
                          'sha256': hashlib.sha256(data).hexdigest(), 'sha512': hashlib.sha512(data).hexdigest()}
    for key, name in [('log', 'collect.log'), ('commandsFile', 'collect-commands.jsonl')]:
        data = (pathlib.Path(output) / name).read_bytes()
        record[key] = {'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                       'sha512': hashlib.sha512(data).hexdigest()}
with open(target, 'x', encoding='utf-8') as out:
    json.dump(record, out, indent=2); out.write('\n')
PY
  local receipt_code=$?
  rm -f -- "$facts"
  ((receipt_code == 0)) || code=$receipt_code
  exit "$code"
}
trap finish EXIT

if [[ $stage != prepare ]]; then
  python3 - "$state" "$project_commit" "$build_id" "$revision" "$workspace" "$output" "$run_id" "$run_attempt" "$reports" "$stage" <<'PY'
import hashlib, json, pathlib, sys
state, project, build, revision, workspace, output, run_id, attempt, reports, stage = sys.argv[1:]
s = json.loads(pathlib.Path(state).read_text())
for key, value in [('projectCommit', project), ('buildId', build), ('buildRevision', revision),
                   ('workspace', workspace), ('output', output), ('runId', run_id), ('runAttempt', attempt)]:
    if s.get(key) != value: raise SystemExit('CI run identity changed: ' + key)
previous = {'build': 'prepare', 'scan': 'build', 'test': 'scan', 'verify': 'test', 'collect': 'verify'}[stage]
p = json.loads((pathlib.Path(reports) / 'ci/stages' / (previous + '.json')).read_text())
if p.get('status') != 'passed' or p.get('exitCode') != 0:
    raise SystemExit('The previous stage did not pass: ' + previous)
snapshot = pathlib.Path(reports) / 'ci-inputs/snapshot.json'
if hashlib.sha256(snapshot.read_bytes()).hexdigest() != s['snapshotSha256']:
    raise SystemExit('The frozen orchestration snapshot changed')
snap = json.loads(snapshot.read_text())
for row in snap['projectFiles'] + [snap['originalProfile'], snap['effectiveProfile']]:
    path = pathlib.Path(output) / row['path']
    if path.is_symlink() or not path.is_file(): raise SystemExit('A frozen source file is missing/redirected')
    data = path.read_bytes()
    if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256'] or hashlib.sha512(data).hexdigest() != row['sha512']:
        raise SystemExit('A frozen orchestration input changed: ' + row['path'])
PY
  image_id=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["imageId"])' "$state")
  [[ $(git -C "$source_dir" rev-parse HEAD) == "$source_commit" ]] || die 'The VMR source commit changed.'
fi

container() {
  local mode=$1 network=$2; shift 2
  local source_mount=$source_dir:/vmr inputs_mount=$inputs:/inputs
  [[ $mode != readonly ]] || { source_mount+=:ro; inputs_mount+=:ro; }
  run "${engine[@]}" run --rm --interactive --network="$network" --user "$uid:$gid" \
    --env HOME=/home/build --env DOTNET_CLI_HOME=/home/build --env XDG_RUNTIME_DIR=/home/build/.xdg \
    --env LANG=C.UTF-8 --env LC_ALL=C.UTF-8 --env DOTNET_PROCESSOR_COUNT=2 \
    --env PYTHONDONTWRITEBYTECODE=1 \
    --env DOTNET_CLI_TELEMETRY_OPTOUT=1 --env DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
    --env DOTNET_GENERATE_ASPNET_CERTIFICATE=false \
    --volume "$project:/project:ro" --volume "$source_mount" --volume "$inputs_mount" \
    --volume "$home:/home/build" --volume "$output:/delivery" --volume "$candidate:/candidate" --workdir /vmr \
    "$image_id" taskset --cpu-list "$cpus" "$@"
}
inspect_image() {
  local reference=$1 destination=$2
  "${engine[@]}" image inspect "$reference" > "$destination"
  python3 - "$destination" <<'PY'
import json, re, sys
rows = json.load(open(sys.argv[1]))
if len(rows) != 1 or rows[0]['Architecture'] != 'arm64' or rows[0]['Os'] != 'linux':
    raise SystemExit('A native linux/arm64 image is required')
value = rows[0]['Id']
if not re.fullmatch(r'(sha256:)?[a-f0-9]{64}', value): raise SystemExit('Invalid immutable image ID')
print(value)
PY
}
validate_sysroot() {
  git -C "$source_dir" diff --no-ext-diff --quiet HEAD -- eng/common/cross/build-rootfs.sh eng/common/cross/install-debs.py || die 'The signed sysroot producer changed.'
  container readonly none python3 - /delivery/reports/prepare <<'PY'
import hashlib, json, os, pathlib, re, subprocess, sys
r = pathlib.Path(sys.argv[1]); root = pathlib.Path('/inputs/arm64-bionic')
expected = {}
for line in (r / 'sysroot-files.sha256').read_text().splitlines():
    m = re.fullmatch(r'([a-f0-9]{64})  (.+)', line)
    if not m: raise SystemExit('Invalid sysroot checksum entry')
    p = pathlib.Path(m[2])
    if p == root or root not in p.parents or str(p) in expected: raise SystemExit('Invalid sysroot inventory path')
    expected[str(p)] = m[1]
files, links = {}, set()
for directory, dirs, names in os.walk(root, followlinks=False):
    for name in dirs + names:
        p = pathlib.Path(directory) / name
        if p.is_symlink(): links.add(str(p) + '\t' + os.readlink(p))
        elif p.is_file(): files[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()
if not expected or files != expected or links != set((r / 'sysroot-symlinks.tsv').read_text().splitlines()):
    raise SystemExit('The complete signed sysroot inventory changed')
line = (r / 'sysroot-file-list.sha256').read_text().strip().split('  ', 1)
if len(line) != 2 or line[1] != str(r / 'sysroot-files.sha256') or line[0] != hashlib.sha256((r / 'sysroot-files.sha256').read_bytes()).hexdigest():
    raise SystemExit('The sysroot checksum-list control differs')
log = (r / 'sysroot-prepare.log').read_text()
if ('--force-check-gpg' not in log or '--skipsigcheck' in log or 'Signature verified successfully.' not in log
        or '--keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg' not in log):
    raise SystemExit('Actual upstream signed-package verification evidence is absent')
def fp(path):
    data = path.read_bytes()
    return {'path': path.relative_to(pathlib.Path('/delivery')).as_posix(), 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest(), 'sha512': hashlib.sha512(data).hexdigest()}
def preserve(path, data):
    if path.is_symlink(): raise SystemExit('A preserved sysroot input is redirected')
    if path.exists():
        if path.read_bytes() != data: raise SystemExit('A preserved sysroot input differs')
    else:
        with path.open('xb') as out: out.write(data)
control_dir = r / 'sysroot-inputs'; control_dir.mkdir(exist_ok=True)
producers = []
for relative, blob in [('eng/common/cross/build-rootfs.sh', '3150ccac6fcd7859a55e10fa0742cfc4de5e3075'),
                       ('eng/common/cross/install-debs.py', '1d1dfabf7dc92d8e374d4304f36061c6e3e10b1b')]:
    data = subprocess.check_output(['git', '-C', '/vmr', 'show', 'HEAD:' + relative])
    actual_blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    if actual_blob != blob or (pathlib.Path('/vmr') / relative).read_bytes() != data:
        raise SystemExit('A signed sysroot producer differs from its pinned original Git blob')
    destination = control_dir / pathlib.Path(relative).name; preserve(destination, data)
    producers.append(dict(fp(destination), originalPath=relative, gitBlobSha1=blob))
keyring = pathlib.Path('/usr/share/keyrings/ubuntu-archive-keyring.gpg')
preserved_keyring = control_dir / keyring.name; preserve(preserved_keyring, keyring.read_bytes())
keyring_record = dict(fp(preserved_keyring), originalPath=str(keyring),
                     installedPackage=subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', 'ubuntu-keyring'], text=True))
report = {'status': 'passed', 'sourceCommit': '5a2162bea6845eabc1fc721624a43568c65db3b1',
          'files': len(files), 'symlinks': len(links), 'signatureVerificationRequired': True,
          'signatureSuccessRecords': log.count('Signature verified successfully.'),
          'producerInputs': producers, 'producerInputsMatchPinnedGit': True, 'signingKeyring': keyring_record,
          'inventory': {name: fp(r / name) for name in ['sysroot-files.sha256', 'sysroot-file-list.sha256',
                        'sysroot-symlinks.tsv', 'sysroot-prepare.log']},
          'scope': 'Actual signed upstream package extraction and complete current file/symlink verification.'}
p = r / 'sysroot-validation.json'
if not p.exists(): p.write_text(json.dumps(report, indent=2) + '\n')
else:
    if json.loads(p.read_text()) != report: raise SystemExit('The recorded sysroot validation differs')
PY
}

case "$stage" in
prepare)
  run git clone --depth 1 --branch v10.0.403 -- https://github.com/dotnet/dotnet "$source_dir"
  [[ $(git -C "$source_dir" rev-parse HEAD) == "$source_commit" ]] || die 'The fetched VMR tag has an unexpected commit.'
  run python3 "$project/scripts/ci-net10-evidence.py" freeze --project-root "$project" --source-dir "$source_dir" \
    --release-dir "$output" --build-id "$build_id" --build-revision "$revision" --run-id "$run_id" \
    --run-attempt "$run_attempt" --project-commit "$project_commit" --workflow-ref "$workflow_ref"
  python3 - "$snapshot" "$profile" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1]); p = json.loads(pathlib.Path(sys.argv[2]).read_text())
expected = 'mcr.microsoft.com/dotnet-buildtools/prereqs@sha256:7ef8f6ee1b9982511349757443eb4844f0db4f8cef1aff6148a7ba1c25d7c6f4'
if (p['sdkVersion'] != '10.0.403' or p['source']['commit'] != '5a2162bea6845eabc1fc721624a43568c65db3b1'
        or p['target']['rid'] != 'linux-arm64' or p['build']['sourceOnly'] is not False):
    raise SystemExit('Only the selected .NET 10 ordinary ARM64 profile is supported')
line = next(x.strip() for x in (root / 'containers/arm64-net10.Containerfile').read_text().splitlines() if x.startswith('FROM '))
if line != 'FROM ' + expected or p['container']['repository'] + '@' + p['container']['digest'] != expected:
    raise SystemExit('The profile and immutable product base differ')
PY
  mkdir -p "$reports/prepare"
  run python3 "$snapshot/scripts/ci-net10-shared-source.py" prepare --profile "$profile" \
    --destination "$shared_source_dir" --report "$reports/prepare/shared-source-checkout.json"
  base=mcr.microsoft.com/dotnet-buildtools/prereqs@sha256:7ef8f6ee1b9982511349757443eb4844f0db4f8cef1aff6148a7ba1c25d7c6f4
  run "${engine[@]}" pull "$base"
  inspect_image "$base" "$reports/prepare/base-image.json" >/dev/null
  run "${engine[@]}" build --network=host --file "$snapshot/containers/arm64-net10.Containerfile" \
    --tag "localhost/cbodotnet-net10-ci:$run_id-$run_attempt" "$snapshot"
  image_id=$(inspect_image "localhost/cbodotnet-net10-ci:$run_id-$run_attempt" "$reports/prepare/build-image.json")
  container write host python3 /delivery/reports/ci-inputs/project/scripts/fetch-pinned-inputs.py \
    --profile /delivery/reports/ci-inputs/effective-profile.json --inputs-dir /inputs --reports-dir /delivery/reports/prepare
  container write host bash /delivery/reports/ci-inputs/project/scripts/prepare-sysroot.sh /vmr /inputs /delivery/reports/prepare
  validate_sysroot
  container readonly none bash /delivery/reports/ci-inputs/project/scripts/inventory-environment.sh \
    --workspace /vmr --output /delivery/reports/prepare/build-environment.json
  python3 - "$state" "$project_commit" "$build_id" "$revision" "$run_id" "$run_attempt" "$workspace" "$output" "$image_id" "$reports/ci-inputs/snapshot.json" <<'PY'
import hashlib, json, pathlib, sys
path, project, build, revision, run_id, attempt, workspace, output, image, snapshot = sys.argv[1:]
with open(path, 'x') as out:
    json.dump({'projectCommit': project, 'buildId': build, 'buildRevision': revision,
               'runId': run_id, 'runAttempt': attempt, 'workspace': workspace, 'output': output,
               'imageId': image, 'snapshotSha256': hashlib.sha256(pathlib.Path(snapshot).read_bytes()).hexdigest()}, out, indent=2)
PY
  path_fact sysrootValidation reports/prepare/sysroot-validation.json
  path_fact buildImage reports/prepare/build-image.json
  path_fact baseImage reports/prepare/base-image.json
  path_fact sharedSourceCheckout reports/prepare/shared-source-checkout.json
  ;;
build|test)
  validate_sysroot
  container write none python3 /delivery/reports/ci-inputs/project/scripts/fetch-pinned-inputs.py \
    --profile /delivery/reports/ci-inputs/effective-profile.json --inputs-dir /inputs --reports-dir "/delivery/reports/$stage" --offline
  container write host python3 /delivery/reports/ci-inputs/project/scripts/configure-feeds.py --source-dir /vmr --reports-dir "/delivery/reports/$stage"
  if [[ $stage == test ]]; then
    container write none python3 /delivery/reports/ci-inputs/project/scripts/prepare-scenario-report-fence.py \
      apply --version 10 --source-dir /vmr --reports-dir /delivery/reports/test/scenario-report-fence
    path_fact scenarioReportFence reports/test/scenario-report-fence/scenario-report-fence.json
  fi
  args=(bash /delivery/reports/ci-inputs/project/scripts/build-vmr.sh --source-dir /vmr --sysroot /inputs/arm64-bionic \
    --reports-dir "/delivery/reports/$stage" --action "$stage" --build-id "$build_id")
  [[ $stage != test ]] || args+=(--binaries-report /delivery/reports/scan/NewBinaries.txt)
  container write host "${args[@]}"
  path_fact "${stage}Status" "reports/$stage/$stage-status.json"
  if [[ $stage == test ]]; then
    mkdir -p "$reports/test/upstream-results"
    cp -- "$source_dir/artifacts/TestResults/Release/Microsoft.DotNet.Tests.trx" "$reports/test/upstream-results/common.trx"
    mapfile -d '' -t scenarios < <(find "$source_dir/artifacts/TestResults/Release/scenario-tests" -maxdepth 1 -type f -name '*.xml' -print0)
    ((${#scenarios[@]} == 1)) || die 'Exactly one fresh upstream scenario XML is required.'
    cp -- "${scenarios[0]}" "$reports/test/upstream-results/scenarios.xml"
    python3 - "$reports/test/upstream-results" <<'PY'
import pathlib, sys, xml.etree.ElementTree as E
p = pathlib.Path(sys.argv[1]); common = E.parse(p / 'common.trx').getroot()
c = common.find('.//{http://microsoft.com/schemas/VisualStudio/TeamTest/2010}Counters')
if c is None or int(c.get('total', 0)) == 0 or int(c.get('failed', 0)) or int(c.get('error', 0)):
    raise SystemExit('The real upstream common tests did not pass')
tests = E.parse(p / 'scenarios.xml').getroot().findall('assembly')
if not tests or sum(int(x.get('total', 0)) for x in tests) == 0 or any(int(x.get('failed', 0)) or int(x.get('errors', 0)) for x in tests):
    raise SystemExit('The real upstream scenario tests did not pass')
PY
    path_fact commonTrx reports/test/upstream-results/common.trx
    path_fact scenarioXml reports/test/upstream-results/scenarios.xml
    run python3 "$snapshot/scripts/ci-net10-shared-source.py" bind --profile "$profile" --source-dir "$source_dir" \
      --shared-source-dir "$shared_source_dir" --prepare-report "$reports/prepare/shared-source-checkout.json" \
      --roots-output "$reports/ci/source-roots.json" --report "$reports/ci/shared-input-source.json"
    path_fact sharedInputSource reports/ci/shared-input-source.json
  fi
  ;;
scan)
  [[ -z $(git -C "$source_dir" diff --no-ext-diff HEAD -- eng/tools/BinaryToolKit eng/allowed-vmr-binaries.txt eng/allowed-sb-binaries.txt) ]] || die 'The original scanner source/allowlists changed.'
  run git clone --local --no-hardlinks --branch v10.0.403 -- "$source_dir" "$clean_dir"
  [[ $(git -C "$clean_dir" rev-parse HEAD) == "$source_commit" && -z $(git -C "$clean_dir" status --porcelain --untracked-files=all --ignored=matching) ]] || die 'The scan checkout is not pristine.'
  mkdir -p "$reports/scan" "$reports/ci/scan-inputs"
  [[ ! -e $reports/scan/NewBinaries.txt && ! -L $reports/scan/NewBinaries.txt ]] || die 'The scan report must not exist before the upstream task.'
  cp -- "$source_dir/artifacts/bin/BinaryToolKit/Release/BinaryToolKit.dll" "$reports/ci/scan-inputs/BinaryToolKit.dll"
  cp -- "$clean_dir/eng/allowed-vmr-binaries.txt" "$clean_dir/eng/allowed-sb-binaries.txt" "$reports/ci/scan-inputs/"
  run "${engine[@]}" run --rm --network=none --user "$uid:$gid" --env HOME=/home/build --env DOTNET_CLI_HOME=/home/build \
    --env XDG_RUNTIME_DIR=/home/build/.xdg --env DOTNET_GENERATE_ASPNET_CERTIFICATE=false \
    --env DOTNET_CLI_TELEMETRY_OPTOUT=1 --env LANG=C.UTF-8 --env LC_ALL=C.UTF-8 \
    --env DOTNET_PROCESSOR_COUNT=2 --volume "$home:/home/build" --volume "$source_dir:/vmr:ro" --volume "$clean_dir:/clean:ro" \
    --volume "$project:/project:ro" --volume "$output:/delivery" --workdir /tmp "$image_id" taskset --cpu-list "$cpus" \
    /vmr/.dotnet/dotnet msbuild /delivery/reports/ci-inputs/project/scripts/scan-clean-source.proj \
    /p:ScanReportDirectory=/delivery/reports/scan /verbosity:minimal /nologo \
    /bl:/delivery/reports/scan/scan.binlog '/flp:logfile=/delivery/reports/scan/scan.log;verbosity=normal'
  [[ -f $reports/scan/NewBinaries.txt && ! -s $reports/scan/NewBinaries.txt ]] || die 'The real upstream scanner must generate an empty report.'
  [[ -z $(git -C "$clean_dir" status --porcelain --untracked-files=all --ignored=matching) ]] || die 'The read-only scan checkout changed.'
  cmp -- "$source_dir/artifacts/bin/BinaryToolKit/Release/BinaryToolKit.dll" "$reports/ci/scan-inputs/BinaryToolKit.dll"
  for name in allowed-vmr-binaries.txt allowed-sb-binaries.txt; do
    cmp -- "$clean_dir/eng/$name" "$reports/ci/scan-inputs/$name"
    git -C "$clean_dir" show "HEAD:eng/$name" | cmp -- - "$reports/ci/scan-inputs/$name"
  done
  python3 - "$output" "$source_commit" "$commands" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
def fp(relative):
    p = root / relative; b = p.read_bytes()
    return {'path': relative, 'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest(), 'sha512': hashlib.sha512(b).hexdigest()}
record = {'mode': 'Validate', 'sourceCommit': sys.argv[2], 'cleanSourceCommit': sys.argv[2],
          'sourceMountedReadOnly': True, 'originalAllowlistUsed': True, 'worktreeCleanBeforeScan': True,
          'worktreeCleanAfterScan': True, 'reportAbsentBefore': True, 'exitCode': 0, 'allowlistsMatchPinnedGit': True,
          'commands': [json.loads(line) for line in pathlib.Path(sys.argv[3]).read_text().splitlines()],
          'report': fp('reports/scan/NewBinaries.txt'), 'toolAssembly': fp('reports/ci/scan-inputs/BinaryToolKit.dll'),
          'allowedBinaries': fp('reports/ci/scan-inputs/allowed-vmr-binaries.txt'),
          'allowedSourceBuildBinaries': fp('reports/ci/scan-inputs/allowed-sb-binaries.txt'),
          'scanLog': fp('reports/scan/scan.log'), 'scanBinlog': fp('reports/scan/scan.binlog')}
with (root / 'reports/scan/scan-execution.json').open('x') as out: json.dump(record, out, indent=2); out.write('\n')
PY
  for pair in scanExecution:reports/scan/scan-execution.json report:reports/scan/NewBinaries.txt toolAssembly:reports/ci/scan-inputs/BinaryToolKit.dll allowedBinaries:reports/ci/scan-inputs/allowed-vmr-binaries.txt allowedSourceBuildBinaries:reports/ci/scan-inputs/allowed-sb-binaries.txt scanLog:reports/scan/scan.log scanBinlog:reports/scan/scan.binlog; do path_fact "${pair%%:*}" "${pair#*:}"; done
  ;;
verify)
  container readonly none python3 /delivery/reports/ci-inputs/project/scripts/collect-artifacts.py --source-dir /vmr \
    --output-dir /candidate --reports-dir /delivery/reports --profile /delivery/reports/ci-inputs/effective-profile.json \
    --build-image-id "$image_id" --build-revision "$revision"
  cp -- "$candidate/build-manifest.json" "$reports/ci/candidate-build-manifest.json"
  for spec in ubuntu22:ubuntu:22.04:libicu70:libssl3 ubuntu24:ubuntu:24.04:libicu74:libssl3t64 debian13:debian:13:libicu76:libssl3t64; do
    IFS=: read -r name distribution version icu ssl <<< "$spec"
    reference=docker.io/library/$distribution:$version
    run "${engine[@]}" pull "$reference"
    base_id=$(inspect_image "$reference" "$reports/ci/$name-base-image.json")
    pinned=$(python3 - "$reports/ci/$name-base-image.json" "$distribution" <<'PY'
import json, re, sys
r = json.load(open(sys.argv[1]))[0]
digest = r.get('Digest')
if not isinstance(digest, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
    raise SystemExit('The inspected verification manifest digest is required')
selected = 'docker.io/library/' + sys.argv[2] + '@' + digest
references = r.get('RepoDigests')
if not isinstance(references, list) or references.count(selected) != 1:
    raise SystemExit('The inspected manifest must have one exact repository digest binding')
print(selected)
PY
)
    tag=localhost/cbodotnet-net10-verify-$name:$run_id-$run_attempt
    run "${engine[@]}" build --network=host --file "$snapshot/containers/verify-net10.Containerfile" \
      --build-arg "BASE_IMAGE=$pinned" --build-arg "ICU_PACKAGE=$icu" --build-arg "SSL_PACKAGE=$ssl" --tag "$tag" "$snapshot"
    verify_id=$(inspect_image "$tag" "$reports/ci/$name-verification-image.json")
    run "${engine[@]}" run --rm --interactive --network=none --user "$uid:$gid" --env LANG=C.UTF-8 --env LC_ALL=C.UTF-8 \
      --env DOTNET_CLI_TELEMETRY_OPTOUT=1 --env DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 --env DOTNET_GENERATE_ASPNET_CERTIFICATE=false \
      --volume "$candidate:/artifacts:ro" --volume "$output:/delivery" --workdir /tmp "$verify_id" \
      taskset --cpu-list "$cpus" bash -s -- "$verify_id" "$name" "$icu" "$ssl" "$revision" <<'VERIFY'
set -euo pipefail
python3 - "$1" "$2" "$3" "$4" <<'PY'
import json, os, pathlib, platform, subprocess, sys
os_release = {}
for line in pathlib.Path('/etc/os-release').read_text().splitlines():
    if '=' in line:
        key, value = line.split('=', 1); os_release[key] = value.strip('"')
packages = [sys.argv[3], sys.argv[4], 'libc6', 'libstdc++6', 'zlib1g', 'libgssapi-krb5-2']
versions = subprocess.check_output(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\n', *packages], text=True)
record = {'imageId': sys.argv[1], 'architecture': platform.machine(),
          'osRelease': {'ID': os_release['ID'], 'VERSION_ID': os_release['VERSION_ID']},
          'installedPackages': dict(line.split('\t', 1) for line in versions.splitlines()),
          'environmentOverrides': {key: os.environ.get(key) for key in ['LD_LIBRARY_PATH', 'DOTNET_ROOT',
              'DOTNET_SYSTEM_GLOBALIZATION_INVARIANT', 'CLR_ICU_VERSION_OVERRIDE', 'DOTNET_EnableDiagnostics',
              'COMPlus_EnableDiagnostics']}, 'uid': os.getuid(), 'gid': os.getgid()}
with pathlib.Path('/delivery/reports/ci/' + sys.argv[2] + '-userland.json').open('x') as out:
    json.dump(record, out, indent=2); out.write('\n')
PY
exec bash /delivery/reports/ci-inputs/project/scripts/verify-sdk.sh \
  --archive "/artifacts/cbodotnet-sdk-10.0.403-linux-arm64-build.$5.tar.gz" \
  --output-dir "/delivery/reports/verify-$2" --expected-version 10.0.403 --expected-rid linux-arm64 --framework net10.0 --max-glibc 2.27
VERIFY
    path_fact "$name" "reports/verify-$name/verification.json"
  done
  python3 - "$output" <<'PY'
import json, pathlib, sys
r = pathlib.Path(sys.argv[1]); expected = json.loads((r / 'reports/ci/candidate-build-manifest.json').read_text())['sdkArchive']['sha256']
checks = {'consoleDllExecution', 'consoleApphostExecution', 'rsaSha256SignAndVerify', 'cryptographicRandomBytes', 'frFrDecimalFormatting', 'aspNetCoreLoopbackHttp'}
for name in ['ubuntu22', 'ubuntu24', 'debian13']:
    v = json.loads((r / 'reports' / ('verify-' + name) / 'verification.json').read_text())
    if (v['verificationStatus'] != 'passed' or set(v['functionalChecks']) != checks or set(v['functionalChecks'].values()) != {'passed'}
            or v['archive']['sha256'] != expected or not v['archive']['sdkContentMatched'] or v['reportedRid'] != 'linux-arm64'):
        raise SystemExit('A required independent native verification did not pass')
PY
  path_fact candidateManifest reports/ci/candidate-build-manifest.json
  ;;
collect)
  # No writers may add/modify reports once this final inventory starts. Its own
  # commands, log and receipt deliberately live at the delivery root instead.
  container readonly none python3 /delivery/reports/ci-inputs/project/scripts/collect-artifacts.py --source-dir /vmr \
    --output-dir /delivery --reports-dir /delivery/reports --profile /delivery/reports/ci-inputs/effective-profile.json \
    --build-image-id "$image_id" --build-revision "$revision"
  python3 - "$output" "$candidate" <<'PY'
import json, pathlib, sys
r = pathlib.Path(sys.argv[1]); old = json.loads((pathlib.Path(sys.argv[2]) / 'build-manifest.json').read_text())
new = json.loads((r / 'build-manifest.json').read_text())
for key in ['bytes', 'sha256', 'sha512']:
    if old['sdkArchive'][key] != new['sdkArchive'][key]: raise SystemExit('The SDK changed after independent native verification')
PY
  ;;
esac
