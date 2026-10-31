#!/usr/bin/env bash
# Prepare a native Linux CI host and observe resources without installing an SDK.
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: ci-net10-host.sh prepare|monitor --workspace DIR --reports-dir DIR
                          [--minimum-free-gib 30] [--interval-seconds 15]
Preparation installs host tools and records a 30-GiB planning capacity gate.
Only disposable GitHub-hosted VMs permit the fixed unused-tool cleanup list.
Monitor writes until SIGTERM/SIGINT; stop and wait before final collection.
HELP
}

action=${1:-}
[[ $action == prepare || $action == monitor ]] || { usage >&2; exit 2; }
shift
workspace=''
reports_dir=''
minimum_free_gib=30
interval_seconds=15
while (($#)); do
  (($# >= 2)) || { usage >&2; exit 2; }
  case "$1" in
    --workspace) workspace=$2 ;;
    --reports-dir) reports_dir=$2 ;;
    --minimum-free-gib) minimum_free_gib=$2 ;;
    --interval-seconds) interval_seconds=$2 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift 2
done
[[ $(uname -s) == Linux && $(uname -m) == aarch64 && $(id -u) != 0 ]] || {
  echo 'An unprivileged native Linux ARM64 runner is required.' >&2; exit 2;
}
[[ $minimum_free_gib =~ ^[1-9][0-9]*$ && $interval_seconds =~ ^[1-9][0-9]*$ ]] || exit 2
((minimum_free_gib >= 30 && interval_seconds <= 60)) || exit 2
[[ -x /usr/bin/python3 ]] || { echo 'System Python 3 is required.' >&2; exit 2; }
for path in "$workspace" "$reports_dir"; do
  [[ $path == /* && $path != / && $path != *$'\n'* && $path != *$'\r'* ]] || exit 2
done
/usr/bin/python3 - "$workspace" "$reports_dir" <<'PY'
from pathlib import Path
import sys
for value in sys.argv[1:]:
    path = Path(value)
    if '..' in path.parts or any(item.is_symlink() for item in [path] + list(path.parents)):
        raise SystemExit('Ordinary absolute paths without symlink ancestors are required')
if Path(sys.argv[1]) == Path(sys.argv[2]):
    raise SystemExit('The workspace and reports directory must differ')
PY

if [[ $action == monitor ]]; then
  [[ -d $workspace && -d $reports_dir ]] || exit 2
  exec /usr/bin/python3 - "$workspace" "$reports_dir" "$interval_seconds" <<'PY'
import datetime
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import time

workspace, reports = map(Path, sys.argv[1:3])
interval = int(sys.argv[3])
log_path = reports / 'resources.jsonl'
status_path = reports / 'monitor.json'
if any(path.exists() or path.is_symlink() for path in (log_path, status_path)):
    raise SystemExit('Refusing an existing resource observation')
stopping = False
samples = 0
minimum_free = None

def stop(signum, frame):
    global stopping
    stopping = True

for signum in (signal.SIGTERM, signal.SIGINT):
    signal.signal(signum, stop)

def sample():
    global samples, minimum_free
    disk = shutil.disk_usage(workspace)
    memory = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        name, value = line.split(':', 1)
        if name in ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree'):
            memory[name + 'Bytes'] = int(value.split()[0]) * 1024
    cgroup = {}
    for name in ('memory.current', 'memory.peak', 'memory.max'):
        path = Path('/sys/fs/cgroup') / name
        if path.is_file():
            cgroup[name] = path.read_text().strip()
    record = {'capturedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'workspace': str(workspace), 'disk': disk._asdict(), 'memory': memory,
              'runnerCgroup': cgroup, 'scope': 'Runner observations, not an isolated build process-tree peak'}
    output.write(json.dumps(record, sort_keys=True) + '\n')
    output.flush()
    samples += 1
    minimum_free = disk.free if minimum_free is None else min(minimum_free, disk.free)

with log_path.open('x', encoding='utf-8') as output:
    sample()
    while not stopping:
        deadline = time.monotonic() + interval
        while not stopping and time.monotonic() < deadline:
            time.sleep(min(0.5, max(0, deadline - time.monotonic())))
        if not stopping:
            sample()
    sample()
with status_path.open('x', encoding='utf-8') as output:
    json.dump({'status': 'stopped', 'pid': os.getpid(), 'samples': samples,
               'minimumObservedFreeBytes': minimum_free,
               'scope': 'Periodic runner samples; not a continuous disk or per-build memory maximum'}, output, indent=2)
    output.write('\n')
PY
fi

[[ ! -e $reports_dir && ! -L $reports_dir ]] || {
  echo 'Preparation reports must use a new directory.' >&2; exit 2;
}
mkdir -p -- "$workspace" "$(dirname "$reports_dir")"
mkdir -- "$reports_dir"
for tool in sudo apt-get git tar; do command -v "$tool" >/dev/null; done
sudo -n true
df -B1 -- "$workspace" / > "$reports_dir/disk-before.txt"
hosted_cleanup=false
if [[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]; then
  hosted_cleanup=true
fi
cleanup_record=$reports_dir/cleanup.jsonl
: > "$cleanup_record"
# These fixed host installations are unused: all product tools run in the image.
# Never derive a recursive deletion target from a workflow input or environment.
for target in /usr/share/dotnet /usr/lib/jvm /usr/share/swift /opt/az \
              /usr/local/share/powershell /usr/lib/llvm-16 /usr/lib/llvm-17 /usr/lib/llvm-18; do
  result=not-present
  allocated=0
  if [[ $hosted_cleanup != true ]]; then
    result=retained-non-hosted-runner
  elif [[ -L $target ]]; then
    result=retained-symlink
  elif [[ -e $target ]]; then
    [[ -d $target && $(realpath -e -- "$target") == "$target" ]] || {
      echo "Refusing a noncanonical cleanup target: $target" >&2; exit 2;
    }
    # A fixed target must not contain this run's workspace, reports or runner.
    for protected in "$workspace" "$reports_dir" "${GITHUB_WORKSPACE:-/}" "${RUNNER_TEMP:-/}"; do
      [[ $protected != "$target" && $protected != "$target"/* ]] || {
        echo "Cleanup target contains an active runner path: $target" >&2; exit 2;
      }
    done
    allocated=$(sudo -n du -sx --block-size=1 -- "$target" | cut -f1)
    sudo -n rm -rf --one-file-system -- "$target"
    result=removed-fixed-unused-host-tool
  fi
  /usr/bin/python3 - "$cleanup_record" "$target" "$result" "$allocated" <<'PY'
import json
import sys
with open(sys.argv[1], 'a', encoding='utf-8') as output:
    output.write(json.dumps({'path': sys.argv[2], 'result': sys.argv[3],
                             'allocatedBytesBefore': int(sys.argv[4])}) + '\n')
PY
done
df -B1 -- "$workspace" / > "$reports_dir/disk-after-cleanup.txt"
set +e
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update 2>&1 | tee "$reports_dir/apt-update.log"
statuses=("${PIPESTATUS[@]}")
set -e
((statuses[0] == 0 && statuses[1] == 0)) || exit 1
set +e
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  podman git python3 curl ca-certificates xz-utils zstd binutils file \
  gpgv ubuntu-keyring time jq uidmap slirp4netns fuse-overlayfs 2>&1 | tee "$reports_dir/apt-install.log"
statuses=("${PIPESTATUS[@]}")
set -e
((statuses[0] == 0 && statuses[1] == 0)) || exit 1
df -B1 -- "$workspace" / > "$reports_dir/disk-after.txt"
sudo -n podman --version > "$reports_dir/podman-version.txt"
git --version > "$reports_dir/git-version.txt"
/usr/bin/python3 --version > "$reports_dir/python-version.txt"
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Status}\n' \
  podman git python3 curl ca-certificates xz-utils zstd binutils file gpgv \
  ubuntu-keyring time jq uidmap slirp4netns fuse-overlayfs > "$reports_dir/host-packages.tsv"
/usr/bin/python3 - "$workspace" "$reports_dir" "$minimum_free_gib" "$hosted_cleanup" <<'PY'
import datetime
import json
import os
from pathlib import Path
import platform
import shutil
import sys

workspace, reports = map(Path, sys.argv[1:3])
minimum = int(sys.argv[3]) * 1024**3
usage = shutil.disk_usage(workspace)
passed = usage.free >= minimum
record = {'status': 'passed' if passed else 'insufficient-disk',
          'capturedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'workspace': str(workspace), 'host': {'architecture': platform.machine(),
          'kernel': platform.release(), 'uid': os.getuid(), 'gid': os.getgid()},
          'runId': os.environ.get('GITHUB_RUN_ID'), 'runAttempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
          'runnerEnvironment': os.environ.get('RUNNER_ENVIRONMENT', 'unknown'),
          'fixedHostedCleanupEnabled': sys.argv[4] == 'true',
          'disk': usage._asdict(), 'minimumFreeBytes': minimum,
          'capacityPolicy': 'minimumFreeBytes is a planning gate, not a measured cold-build maximum',
          'sdkInstalledOnHost': False, 'paidRunnerFallback': False}
with (reports / 'host-preparation.json').open('x', encoding='utf-8') as output:
    json.dump(record, output, indent=2); output.write('\n')
if not passed:
    raise SystemExit('Insufficient free disk for the cold-build pilot. Configure an existing larger/self-hosted runner explicitly; no paid fallback is selected.')
PY
echo 'Native ARM64 host preparation passed; no host SDK was installed.'
