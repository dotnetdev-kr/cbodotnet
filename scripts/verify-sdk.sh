#!/usr/bin/env bash
# Inspect a locally built SDK and run isolated native ARM64 smoke tests.
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: verify-sdk.sh (--sdk-dir /absolute/sdk | --archive /absolute/sdk.tar.gz)
                     --output-dir /absolute/report [options]

  --sdk-dir PATH          Existing extracted SDK. May be combined with --archive.
  --archive PATH          SDK tar.gz; extracted privately if --sdk-dir is absent.
  --output-dir PATH       New or empty report directory (absolute path).
  --expected-version VER  Require dotnet --version to equal this SDK version.
  --expected-rid RID      Require dotnet --info to report this RID.
  --framework TFM         Smoke test framework (default: net10.0).
  --max-glibc VERSION     Fail if any shipped ELF requires a newer GLIBC version.
  --no-smoke             Inspect ELF/SDK identity without console and HTTP tests.
  --help                 Show this help.

Requires native ARM64 Linux, Python 3, readelf, tar and curl (for HTTP smoke).
Outputs verification.json, abi-summary.json, elf-abi.tsv and text build logs.
Smoke restores use an empty NuGet source list, isolated caches and a temporary
workspace. This validates the SDK's built-in framework support, not workloads
or arbitrary external packages. ABI symbol maxima are evidence, not a full OS
compatibility guarantee. An optional archive is hashed; with --sdk-dir it must
contain exactly the supplied SDK files for the archive result to pass.
HELP
}

die() { printf 'error: %s\n' "$*" >&2; exit 2; }
sdk_dir=''
archive=''
output_dir=''
expected_version=''
expected_rid=''
framework='net10.0'
max_glibc=''
run_smoke=true
while (($#)); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --sdk-dir|--archive|--output-dir|--expected-version|--expected-rid|--framework|--max-glibc)
      (($# >= 2)) || die "missing value for $1"
      case "$1" in
        --sdk-dir) sdk_dir=$2 ;;
        --archive) archive=$2 ;;
        --output-dir) output_dir=$2 ;;
        --expected-version) expected_version=$2 ;;
        --expected-rid) expected_rid=$2 ;;
        --framework) framework=$2 ;;
        --max-glibc) max_glibc=$2 ;;
      esac
      shift 2 ;;
    --no-smoke) run_smoke=false; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ $(uname -s) == Linux && $(uname -m) =~ ^(aarch64|arm64)$ ]] || die 'native ARM64 Linux is required'
[[ -n "$sdk_dir" || -n "$archive" ]] || die '--sdk-dir or --archive is required'
[[ "$output_dir" == /* ]] || die '--output-dir must be an absolute path'
[[ "$framework" =~ ^net[0-9]+\.[0-9]+$ ]] || die '--framework must be a framework such as net10.0'
[[ -z "$max_glibc" || "$max_glibc" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die 'invalid --max-glibc version'
for tool in python3 readelf tar; do command -v "$tool" >/dev/null 2>&1 || die "$tool is required"; done
if "$run_smoke"; then command -v curl >/dev/null 2>&1 || die 'curl is required for HTTP smoke'; fi
if [[ -n "$sdk_dir" ]]; then
  [[ "$sdk_dir" == /* && -d "$sdk_dir" ]] || die '--sdk-dir must be an existing absolute directory'
  sdk_dir=$(cd -- "$sdk_dir" && pwd -P)
fi
if [[ -n "$archive" ]]; then
  [[ "$archive" == /* && -f "$archive" ]] || die '--archive must be an existing absolute file'
  archive=$(realpath -- "$archive")
fi
if [[ -e "$output_dir" ]]; then
  [[ -d "$output_dir" && ! -L "$output_dir" ]] || die '--output-dir must be a directory, not a symlink'
  [[ -z $(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit) ]] || die '--output-dir must be empty'
fi
mkdir -p -- "$output_dir"
output_dir=$(cd -- "$output_dir" && pwd -P)
if [[ -n "$sdk_dir" && ( "$output_dir" == "$sdk_dir" || "$output_dir" == "$sdk_dir"/* ) ]]; then
  die '--output-dir must be outside the SDK directory'
fi
temporary_dir=$(mktemp -d -- "${TMPDIR:-/tmp}/cbodotnet-verify.XXXXXXXX")
temporary_dir=$(cd -- "$temporary_dir" && pwd -P)
server_pid=''
cleanup() {
  local result=$?
  trap - EXIT
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if ((result != 0)); then printf 'FAILED (exit %s)\n' "$result" > "$output_dir/status.txt"; fi
  # This directory is exclusively created by mktemp above; never delete input/output.
  if [[ -d "$temporary_dir" && "$temporary_dir" != / && ${temporary_dir##*/} == cbodotnet-verify.* ]]; then
    rm -rf -- "$temporary_dir"
  fi
  exit "$result"
}
trap cleanup EXIT

# Validate archive paths and links before extraction; reject device nodes/FIFOs.
if [[ -n "$archive" ]]; then
  python3 - "$archive" "$temporary_dir/extracted" "$sdk_dir" "$output_dir/archive.json" <<'PY'
import collections
import hashlib
import json
import pathlib
import posixpath
import sys
import tarfile

archive, extraction, existing, metadata = sys.argv[1:]
root = pathlib.Path(existing or extraction).resolve()
def safe_name(name):
    normalized = posixpath.normpath(name)
    if name.startswith("/") or normalized == ".." or normalized.startswith("../"):
        raise SystemExit("unsafe archive path: " + name)
    return normalized

with tarfile.open(archive, "r:gz") as tar:
    members = tar.getmembers()
    names = set()
    for member in members:
        normalized = safe_name(member.name)
        if normalized in names and normalized != ".":
            raise SystemExit("duplicate archive member: " + member.name)
        names.add(normalized)
        if member.isdev() or member.isfifo() or not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            raise SystemExit("unsupported archive member: " + member.name)
        if member.mode & 0o7000:
            raise SystemExit("special permission bits in archive member: " + member.name)
        if member.issym():
            if member.linkname.startswith("/"):
                raise SystemExit("absolute archive symlink: " + member.name)
            safe_name(posixpath.join(posixpath.dirname(normalized), member.linkname))
        if member.islnk():
            safe_name(member.linkname)
    # Resolve all symlink chains lexically and prohibit links used as parent paths.
    links = {safe_name(m.name): m.linkname for m in members if m.issym()}
    def resolve_links(name):
        pending = collections.deque(pathlib.PurePosixPath(name).parts)
        resolved = []
        link_count = 0
        while pending:
            component = pending.popleft()
            if component in ("", "."):
                continue
            if component == "..":
                if not resolved:
                    raise SystemExit("archive link escapes extraction directory: " + name)
                resolved.pop()
                continue
            resolved.append(component)
            prefix = "/".join(resolved)
            if prefix in links:
                link_count += 1
                if link_count > 40:
                    raise SystemExit("cyclic or excessive archive link chain: " + name)
                resolved.pop()
                pending.extendleft(reversed(pathlib.PurePosixPath(links[prefix]).parts))
        return "/".join(resolved)
    for member in members:
        normalized = safe_name(member.name)
        parts = pathlib.PurePosixPath(normalized).parts
        for length in range(1, len(parts)):
            if str(pathlib.PurePosixPath(*parts[:length])) in links:
                raise SystemExit("archive member beneath symlink: " + member.name)
        if member.issym():
            resolve_links(posixpath.join(posixpath.dirname(normalized), member.linkname))
        if member.islnk():
            resolve_links(member.linkname)
    if not existing:
        root.mkdir(parents=True)
        # Paths/link targets were checked above; extracting into a private empty directory.
        tar.extractall(root, members=members, numeric_owner=False)
    else:
        expected = set()
        for member in members:
            normalized = safe_name(member.name)
            if normalized == "." or member.isdir():
                continue
            expected.add(normalized)
            target = root / normalized
            if member.issym():
                if not target.is_symlink() or target.readlink().as_posix() != member.linkname:
                    raise SystemExit("SDK/archive symlink mismatch: " + normalized)
            elif member.isfile() or member.islnk():
                if not target.is_file() or target.is_symlink():
                    raise SystemExit("SDK/archive file mismatch: " + normalized)
                source = tar.extractfile(member)
                source_digest = hashlib.file_digest(source, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else None
                if source_digest is None:
                    digest = hashlib.sha256()
                    for block in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(block)
                    source_digest = digest.hexdigest()
                digest = hashlib.sha256()
                with target.open("rb") as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(block)
                if digest.hexdigest() != source_digest:
                    raise SystemExit("SDK/archive content mismatch: " + normalized)
        actual = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_symlink() or path.is_file()}
        if actual != expected:
            raise SystemExit("SDK directory has extra or missing files relative to archive")
digest = hashlib.sha256()
with open(archive, "rb") as handle:
    for block in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(block)
pathlib.Path(metadata).write_text(json.dumps({"path": archive, "sizeBytes": pathlib.Path(archive).stat().st_size,
                                           "sha256": digest.hexdigest(), "sdkContentMatched": True}, indent=2) + "\n")
PY
  if [[ -z "$sdk_dir" ]]; then sdk_dir="$temporary_dir/extracted"; fi
fi
[[ -x "$sdk_dir/dotnet" ]] || die "SDK executable not found: $sdk_dir/dotnet"

# Read four magic bytes per file; invoke readelf only for actual ELF files.
python3 - "$sdk_dir" "$output_dir" "$max_glibc" <<'PY'
import csv
import json
import os
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1]).resolve()
report = pathlib.Path(sys.argv[2])
ceiling = sys.argv[3]
prefixes = ("GLIBC", "GLIBCXX", "CXXABI")
maxima = {prefix: None for prefix in prefixes}
requirements = {prefix: set() for prefix in prefixes}
symbolic_glibc_requirements = set()
machines = {}
rows = []
dotnet_seen = False
for directory, subdirectories, files in os.walk(root, followlinks=False):
    subdirectories.sort()
    for name in subdirectories:
        directory_link = pathlib.Path(directory) / name
        if directory_link.is_symlink() and not directory_link.resolve().is_relative_to(root):
            raise SystemExit("SDK directory symlink escapes its root: " + str(directory_link.relative_to(root)))
    for name in sorted(files):
        path = pathlib.Path(directory) / name
        relative = str(path.relative_to(root))
        if path.is_symlink():
            if not path.resolve().is_relative_to(root):
                raise SystemExit("SDK symlink escapes its root: " + relative)
            continue
        with path.open("rb") as handle:
            if handle.read(4) != b"\x7fELF":
                continue
        result = subprocess.run(["readelf", "--wide", "--file-header", "--version-info", "--dynamic", str(path)],
                                capture_output=True, text=True, env={**os.environ, "LC_ALL": "C"})
        if result.returncode:
            raise SystemExit("readelf failed for " + relative + ": " + result.stderr)
        machine = re.search(r"^\s*Machine:\s*(.+)$", result.stdout, re.MULTILINE)
        machine = machine.group(1).strip() if machine else "unknown"
        machines[machine] = machines.get(machine, 0) + 1
        if relative == "dotnet":
            dotnet_seen = True
            if machine != "AArch64":
                raise SystemExit("dotnet executable is not AArch64: " + machine)
        needed = re.findall(r"\(NEEDED\).*?\[(.*?)\]", result.stdout)
        # Version definitions describe what a file provides. Only version-needs
        # entries express external ABI requirements, so ignore definitions.
        needs = result.stdout.split("Version needs section", 1)
        needed_versions = needs[1] if len(needs) == 2 else ""
        symbolic_glibc_requirements.update(re.findall(r'\bGLIBC_(?![0-9])([A-Za-z_][A-Za-z0-9_]*)\b', needed_versions))
        row = [relative, machine, ",".join(needed)]
        for prefix in prefixes:
            versions = set(re.findall(r"\b" + prefix + r"_([0-9]+(?:\.[0-9]+)+)\b", needed_versions))
            requirements[prefix].update(versions)
            key = lambda value: tuple(int(part) for part in value.split("."))
            row.append(max(versions, key=key) if versions else "")
        rows.append(row)
if not dotnet_seen:
    raise SystemExit("SDK dotnet is not a regular ELF executable")
for prefix in prefixes:
    if requirements[prefix]:
        maxima[prefix] = max(requirements[prefix], key=lambda value: tuple(int(part) for part in value.split(".")))
with (report / "elf-abi.tsv").open("w", newline="") as handle:
    writer = csv.writer(handle, delimiter="\t")
    writer.writerow(["path", "elfMachine", "neededLibraries", "maxGLIBC", "maxGLIBCXX", "maxCXXABI"])
    writer.writerows(rows)
ceiling_ok = not ceiling or not maxima["GLIBC"] or tuple(map(int, maxima["GLIBC"].split("."))) <= tuple(map(int, ceiling.split(".")))
if ceiling and symbolic_glibc_requirements:
    # DT_RELR has a symbolic ABI requirement rather than a GLIBC_2.x name.
    # Unknown symbolic requirements must be reviewed instead of silently passed.
    unsupported = symbolic_glibc_requirements - {"ABI_DT_RELR"}
    if unsupported or ("ABI_DT_RELR" in symbolic_glibc_requirements and tuple(map(int, ceiling.split("."))) < (2, 36)):
        ceiling_ok = False
summary = {"elfFileCount": len(rows), "machines": machines, "maximumRequiredVersions": maxima,
           "symbolicGlibcRequirements": sorted(symbolic_glibc_requirements),
           "glibcCeiling": ceiling or None, "glibcCeilingPassed": ceiling_ok,
           "scope": "Regular ELF files inside the SDK, excluding archive members and PE managed images.",
           "limitations": ["ABI symbol maxima do not cover kernel requirements, runtime dlopen dependencies or complete OS support.",
                           "Relocatable objects and foreign-target ELF files, if shipped, are included in the table."]}
(report / "abi-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
if not ceiling_ok:
    raise SystemExit("SDK GLIBC requirement exceeds requested ceiling")
PY

export DOTNET_ROOT="$sdk_dir"
export DOTNET_ROOT_ARM64="$sdk_dir"
export DOTNET_MULTILEVEL_LOOKUP=0
export DOTNET_CLI_HOME="$temporary_dir/cli-home"
export NUGET_PACKAGES="$temporary_dir/nuget/packages"
export NUGET_HTTP_CACHE_PATH="$temporary_dir/nuget/http-cache"
export NUGET_PLUGINS_CACHE_PATH="$temporary_dir/nuget/plugins-cache"
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=true
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1
export DOTNET_CLI_UI_LANGUAGE=en-US
export LC_ALL=C
export PATH="$sdk_dir:$PATH"
mkdir -p -- "$temporary_dir/work" "$DOTNET_CLI_HOME" "$NUGET_PACKAGES"
cd -- "$temporary_dir/work"
dotnet="$sdk_dir/dotnet"
"$dotnet" --info > "$output_dir/dotnet-info.txt" 2>&1
"$dotnet" --list-sdks > "$output_dir/dotnet-sdks.txt" 2>&1
"$dotnet" --list-runtimes > "$output_dir/dotnet-runtimes.txt" 2>&1
sdk_version=$("$dotnet" --version)
[[ -z "$expected_version" || "$sdk_version" == "$expected_version" ]] || die "expected SDK $expected_version, got $sdk_version"
reported_rid=$(sed -n 's/^[[:space:]]*RID:[[:space:]]*//p' "$output_dir/dotnet-info.txt" | head -n 1)
[[ -z "$expected_rid" || "$reported_rid" == "$expected_rid" ]] || die "expected RID $expected_rid, got $reported_rid"

if "$run_smoke"; then
  cat > NuGet.Config <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<configuration><packageSources><clear /></packageSources></configuration>
XML
  {
    "$dotnet" new console --name ConsoleSmoke --framework "$framework" --no-restore
    "$dotnet" restore ConsoleSmoke/ConsoleSmoke.csproj --configfile NuGet.Config
    "$dotnet" build ConsoleSmoke/ConsoleSmoke.csproj --configuration Release --no-restore
    "$dotnet" publish ConsoleSmoke/ConsoleSmoke.csproj --configuration Release --no-restore \
      --self-contained false --output "$temporary_dir/console-publish"
  } > "$output_dir/console-build.log" 2>&1
  "$dotnet" "$temporary_dir/console-publish/ConsoleSmoke.dll" > "$output_dir/console-run.txt" 2>&1
  [[ $(cat "$output_dir/console-run.txt") == 'Hello, World!' ]] || die 'console smoke returned unexpected output'
  "$temporary_dir/console-publish/ConsoleSmoke" > "$output_dir/console-apphost-run.txt" 2>&1
  [[ $(cat "$output_dir/console-apphost-run.txt") == 'Hello, World!' ]] || die 'console apphost returned unexpected output'

  {
    "$dotnet" new web --name WebSmoke --framework "$framework" --no-restore
    cat > WebSmoke/Program.cs <<'CS'
var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://127.0.0.1:0");
var app = builder.Build();
app.MapGet("/health", () => "cbodotnet-smoke-ok");
app.Run();
CS
    "$dotnet" restore WebSmoke/WebSmoke.csproj --configfile NuGet.Config
    "$dotnet" build WebSmoke/WebSmoke.csproj --configuration Release --no-restore
    "$dotnet" publish WebSmoke/WebSmoke.csproj --configuration Release --no-restore \
      --self-contained false --output "$temporary_dir/web-publish"
  } > "$output_dir/web-build.log" 2>&1
  : > "$output_dir/web-server.log"
  "$dotnet" "$temporary_dir/web-publish/WebSmoke.dll" > "$output_dir/web-server.log" 2>&1 &
  server_pid=$!
  listen_url=''
  for ((attempt=0; attempt<120; attempt++)); do
    kill -0 "$server_pid" 2>/dev/null || die 'ASP.NET Core process exited before readiness'
    listen_url=$(sed -n 's/.*Now listening on: \(http:\/\/127\.0\.0\.1:[0-9][0-9]*\).*/\1/p' "$output_dir/web-server.log" | head -n 1)
    if [[ -n "$listen_url" ]]; then break; fi
    sleep 0.25
  done
  [[ -n "$listen_url" ]] || die 'ASP.NET Core readiness timed out'
  curl --fail --silent --show-error --max-time 10 "$listen_url/health" > "$output_dir/web-response.txt"
  [[ $(cat "$output_dir/web-response.txt") == 'cbodotnet-smoke-ok' ]] || die 'ASP.NET Core HTTP response mismatch'
  kill "$server_pid"
  wait "$server_pid" || true
  server_pid=''
fi

python3 - "$sdk_dir" "$output_dir" "$sdk_version" "$expected_version" "$framework" "$run_smoke" "$expected_rid" <<'PY'
import datetime
import json
import pathlib
import platform
import sys

sdk, destination, version, expected, framework, smoke, expected_rid = sys.argv[1:]
report = pathlib.Path(destination)
info = (report / "dotnet-info.txt").read_text()
rid = next((line.split(":", 1)[1].strip() for line in info.splitlines() if line.strip().startswith("RID:")), None)
document = {
    "schemaVersion": 1, "verificationStatus": "passed",
    "verifiedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "hostArchitecture": platform.machine(), "sdkDirectory": sdk,
    "sdkVersion": version, "expectedVersion": expected or None, "reportedRid": rid,
    "expectedRid": expected_rid or None,
    "framework": framework, "smokeStatus": "passed" if smoke == "true" else "skipped",
    "smokeRestore": "isolated caches with no NuGet package sources" if smoke == "true" else None,
    "abi": json.loads((report / "abi-summary.json").read_text()),
    "archive": json.loads((report / "archive.json").read_text()) if (report / "archive.json").exists() else None,
    "limitations": ["Does not certify support for untested Linux distributions, workloads, NativeAOT or external NuGet packages.",
                    "Does not replace upstream VMR source-build tests or Stage 2 validation."],
}
(report / "verification.json").write_text(json.dumps(document, indent=2) + "\n")
PY
printf 'PASSED\n' > "$output_dir/status.txt"
printf 'Verification report: %s/verification.json\n' "$output_dir"
