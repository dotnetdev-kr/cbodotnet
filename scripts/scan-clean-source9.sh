#!/usr/bin/env bash
set -euo pipefail

# This standalone .NET 9 source scan is not part of upstream ./build.sh --test.
usage() {
  echo 'Usage: scan-clean-source9.sh --source-dir /vmr --clean-source-dir /clean9 --reports-dir /new/external/report'
}
fail() { echo "$*" >&2; exit 2; }
source_arg='' clean_arg='' reports_arg='' arch=arm64
while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --arch)
      [[ $# -ge 2 && ( $2 == arm64 || $2 == x64 ) ]] || fail 'Expected --arch arm64 or x64.'
      arch=$2; shift 2 ;;
    --source-dir|--clean-source-dir|--reports-dir)
      [[ $# -ge 2 && $2 == /* ]] || fail "An absolute path is required for $1."
      case "$1" in
        --source-dir) source_arg=$2 ;;
        --clean-source-dir) clean_arg=$2 ;;
        --reports-dir) reports_arg=$2 ;;
      esac
      shift 2 ;;
    *) fail "Unknown argument: $1" ;;
  esac
done
[[ -n $source_arg && -n $clean_arg && -n $reports_arg ]] || { usage >&2; exit 2; }
case "$arch" in arm64) native_machine=aarch64 ;; x64) native_machine=x86_64 ;; esac
[[ $(uname -s) == Linux && $(uname -m) == "$native_machine" ]] || fail 'A native Linux host matching --arch is required.'
for tool in git realpath python3 sha256sum tee cmp file; do
  command -v "$tool" >/dev/null || fail "Missing tool: $tool"
done
source_dir=$(realpath -e "$source_arg")
clean_dir=$(realpath -e "$clean_arg")
reports_dir=$(realpath -m "$reports_arg")
[[ -d $source_dir && -d $clean_dir && ! $source_dir -ef $clean_dir ]] || fail 'Separate source directories are required.'
[[ $source_dir != "$clean_dir"/* && $clean_dir != "$source_dir"/* ]] || fail 'Source directories must not contain each other.'
[[ $reports_dir != / && $reports_dir != "$source_dir" && $reports_dir != "$source_dir"/* && $reports_dir != "$clean_dir" && $reports_dir != "$clean_dir"/* ]] || fail 'Reports must be outside both source trees.'
[[ ! -e $reports_arg && ! -L $reports_arg && ! -e $reports_dir && ! -L $reports_dir ]] || fail 'Refusing an existing report path.'
[[ -d $(dirname "$reports_dir") ]] || fail 'The report parent directory must already exist.'
mkdir -- "$reports_dir"

expected_sha=9f04b57d1366e21b3178648493d6edffeff2216e
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
phase=preflight source_sha='' clean_sha='' sdk_version='' tool_exit='' tee_exit=''
finish() {
  local result=$?
  trap - EXIT
  if ! python3 - "$reports_dir" "$started" "$phase" "$result" "$source_dir" "$clean_dir" "$source_sha" "$clean_sha" "$sdk_version" "$tool_exit" "$tee_exit" "$expected_sha" <<'PY'
import datetime
import json
import pathlib
import sys

out, started, phase, code, source, clean, source_sha, clean_sha, sdk, tool, tee, expected = sys.argv[1:]
out = pathlib.Path(out)
report = out / "NewBinaries.txt"
before, after = out / "allowlists-before.sha256", out / "allowlists-after.sha256"
def pristine(name):
    path = out / name
    return path.stat().st_size == 0 if path.exists() else None
record = {
    "schemaVersion": 1,
    "validation": "dotnet9-clean-source-binaries",
    "upstreamTestIntegration": False,
    "mode": "validate",
    "status": "passed" if code == "0" else "failed",
    "phase": phase,
    "startedAtUtc": started,
    "completedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "exitCode": int(code),
    "toolExitCode": int(tool) if tool else None,
    "teeExitCode": int(tee) if tee else None,
    "expectedCommit": expected,
    "sourceDirectory": source,
    "sourceCommit": source_sha,
    "cleanSourceDirectory": clean,
    "cleanSourceCommit": clean_sha,
    "sourceDirtyBefore": None if pristine("source-status-before.txt") is None else not pristine("source-status-before.txt"),
    "cleanPristineBefore": pristine("clean-status-before.txt"),
    "cleanPristineAfter": pristine("clean-status-after.txt"),
    "sdkVersion": sdk,
    "workingDirectory": clean,
    "command": json.loads((out / "command.json").read_text()) if (out / "command.json").exists() else None,
    "allowlistsUnchanged": before.read_bytes() == after.read_bytes() if before.exists() and after.exists() else None,
    "newBinariesReport": {
        "exists": report.exists() or report.is_symlink(),
        "isSymlink": report.is_symlink(),
        "bytes": report.stat().st_size if report.is_file() else None,
    },
}
with (out / "status.json").open("x", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2)
    stream.write("\n")
PY
  then result=1; fi
  exit "$result"
}
trap finish EXIT
git_read() { git --no-optional-locks -c safe.directory="$1" -c core.fsmonitor=false -C "$1" "${@:2}"; }
for directory in "$source_dir" "$clean_dir"; do
  [[ $(realpath -e "$(git_read "$directory" rev-parse --show-toplevel)") == "$directory" ]] || fail 'Each source path must be its Git top level.'
done
source_sha=$(git_read "$source_dir" rev-parse HEAD)
clean_sha=$(git_read "$clean_dir" rev-parse HEAD)
[[ $source_sha == "$expected_sha" && $clean_sha == "$expected_sha" ]] || fail 'Both checkouts must use the pinned .NET 9 commit.'
git_read "$source_dir" status --porcelain=v1 --untracked-files=all > "$reports_dir/source-status-before.txt"
git_read "$clean_dir" status --porcelain=v1 --untracked-files=all --ignored=matching > "$reports_dir/clean-status-before.txt"
[[ ! -s $reports_dir/clean-status-before.txt ]] || fail 'The scan target must be pristine, including ignored and untracked files.'
git_read "$source_dir" diff --no-ext-diff --quiet HEAD -- eng/tools/BinaryToolKit eng/allowed-vmr-binaries.txt eng/allowed-sb-binaries.txt || fail 'The scanner and its allowlists must match the pinned source.'
git_read "$source_dir" status --porcelain=v1 --untracked-files=all -- eng/tools/BinaryToolKit > "$reports_dir/scanner-status-before.txt"
[[ ! -s $reports_dir/scanner-status-before.txt ]] || fail 'The scanner directory must contain only pinned source files.'
dotnet=$source_dir/.dotnet/dotnet
[[ -x $dotnet ]] || fail 'The build checkout must contain its .NET 9 bootstrap SDK.'
cd "$source_dir"
sdk_version=$("$dotnet" --version)
[[ $sdk_version == 9.0.121 ]] || fail "Expected the pinned bootstrap SDK 9.0.121, found: $sdk_version"
printf '%s\n' "$sdk_version" > "$reports_dir/sdk-version.txt"
uname -a > "$reports_dir/environment.txt"
allowlists=("$source_dir/eng/allowed-vmr-binaries.txt" "$source_dir/eng/allowed-sb-binaries.txt" "$clean_dir/eng/allowed-vmr-binaries.txt" "$clean_dir/eng/allowed-sb-binaries.txt")
sha256sum -- "${allowlists[@]}" > "$reports_dir/allowlists-before.sha256"

# The tag's globbing library resolves candidate paths against process CWD.
# Run in the scan target so its unchanged relative allowlist patterns apply.
# Use the .NET 9 CLI API verbatim. Never pass its destructive "clean" mode.
command=("$dotnet" run --project "$source_dir/eng/tools/BinaryToolKit" -c Release --property "RunWorkingDirectory=$clean_dir" -- validate "$clean_dir" -o "$reports_dir" -ab "$clean_dir/eng/allowed-vmr-binaries.txt" -l Debug)
printf '%q ' "${command[@]}" > "$reports_dir/command.txt"
printf '\n' >> "$reports_dir/command.txt"
python3 - "$reports_dir/command.json" "${command[@]}" <<'PY'
import json
import pathlib
import sys
pathlib.Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:], indent=2) + "\n", encoding="utf-8")
PY
phase=scan
cd "$clean_dir"
set +e
"${command[@]}" 2>&1 | tee "$reports_dir/scan.log"
pipeline_status=("${PIPESTATUS[@]}")
set -e
tool_exit=${pipeline_status[0]}
tee_exit=${pipeline_status[1]}
printf '%s\n' "$tool_exit" > "$reports_dir/tool-exit-code.txt"

phase=postcheck
postcheck_failed=0
sha256sum -- "${allowlists[@]}" > "$reports_dir/allowlists-after.sha256" || postcheck_failed=1
cmp -s "$reports_dir/allowlists-before.sha256" "$reports_dir/allowlists-after.sha256" || postcheck_failed=1
git_read "$clean_dir" status --porcelain=v1 --untracked-files=all --ignored=matching > "$reports_dir/clean-status-after.txt" || postcheck_failed=1
[[ ! -s $reports_dir/clean-status-after.txt ]] || postcheck_failed=1
[[ $(git_read "$source_dir" rev-parse HEAD) == "$expected_sha" && $(git_read "$clean_dir" rev-parse HEAD) == "$expected_sha" ]] || postcheck_failed=1
# The upstream validator creates NewBinaries.txt only when it finds new binaries.
# Do not synthesize an empty report to make a failed scan appear successful.
if [[ -e $reports_dir/NewBinaries.txt || -L $reports_dir/NewBinaries.txt ]]; then
  [[ -f $reports_dir/NewBinaries.txt && ! -L $reports_dir/NewBinaries.txt && ! -s $reports_dir/NewBinaries.txt ]] || postcheck_failed=1
fi
[[ $tool_exit == 0 ]] || exit "$tool_exit"
[[ $tee_exit == 0 ]] || exit "$tee_exit"
[[ $postcheck_failed == 0 ]] || { echo 'Source integrity or binary report postcheck failed.' >&2; exit 1; }
phase=complete
echo "Validated pristine .NET 9 sources; reports: $reports_dir"
