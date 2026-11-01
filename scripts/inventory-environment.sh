#!/usr/bin/env bash
# Capture only build-related environment details; do not dump process secrets.
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  printf 'error: python3 is required\n' >&2
  exit 2
fi

exec python3 - "$@" <<'PY'
import argparse
import datetime
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description="Record a native Linux build environment as JSON.")
parser.add_argument("--arch", choices=("arm64", "x64"), default="arm64")
parser.add_argument("--output", type=pathlib.Path, help="Absolute JSON output path; defaults to stdout.")
parser.add_argument("--workspace", type=pathlib.Path, default=pathlib.Path.cwd(), help="Workspace whose disk capacity is measured.")
args = parser.parse_args()
machines = {"arm64": ("aarch64", "arm64"), "x64": ("x86_64",)}
if platform.system() != "Linux" or platform.machine().lower() not in machines[args.arch]:
    parser.error("this build profile requires native " + args.arch + " Linux")
if args.output is not None and not args.output.is_absolute():
    parser.error("--output must be an absolute path")
if not args.workspace.is_absolute() or not args.workspace.is_dir():
    parser.error("--workspace must be an existing absolute directory")

def command(argv):
    if shutil.which(argv[0]) is None:
        return {"available": False}
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=15, env={**os.environ, "LC_ALL": "C"})
        return {"available": True, "path": shutil.which(argv[0]), "exitCode": result.returncode,
                "output": (result.stdout + result.stderr).strip()}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": True, "error": str(exc)}

os_release = {}
for line in pathlib.Path("/etc/os-release").read_text().splitlines():
    if "=" in line and not line.startswith("#"):
        key, value = line.split("=", 1)
        os_release[key] = value.strip('"')
memory = {}
for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
    key, value = line.split(":", 1)
    if key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
        memory[key + "Bytes"] = int(value.split()[0]) * 1024

tools = {
    name: command(argv) for name, argv in {
        "git": ["git", "--version"], "clang": ["clang", "--version"],
        "cmake": ["cmake", "--version"], "gcc": ["gcc", "--version"],
        "lld": ["ld.lld", "--version"], "readelf": ["readelf", "--version"],
        "file": ["file", "--version"], "ninja": ["ninja", "--version"],
        "libc": ["ldd", "--version"], "python": ["python3", "--version"],
        "tar": ["tar", "--version"], "curl": ["curl", "--version"],
    }.items()
}
packages = command(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\n",
                    "build-essential", "clang*", "cmake", "llvm*", "lld*", "libssl-dev", "libicu-dev",
                    "libbrotli-dev", "libkrb5-dev", "liblttng-ust-dev", "zlib1g-dev", "elfutils", "file"])
disks = []
for path in dict.fromkeys((args.workspace.resolve(), pathlib.Path("/"), pathlib.Path("/mnt/c"), pathlib.Path("/mnt/d"))):
    if path.is_dir():
        usage = shutil.disk_usage(path)
        disks.append({"path": str(path), "totalBytes": usage.total, "usedBytes": usage.used, "freeBytes": usage.free})

document = {
    "schemaVersion": 1,
    "capturedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "host": {"system": platform.system(), "architecture": platform.machine(), "kernel": platform.release(),
             "logicalCpuCount": os.cpu_count(), "osRelease": os_release, "memory": memory},
    "workspace": str(args.workspace.resolve()),
    "disks": disks,
    "tools": tools,
    "packages": packages,
    "buildConfiguration": {key: os.environ[key] for key in ("ROOTFS_DIR", "CC", "CXX") if key in os.environ},
    "notes": ["Reserve CI runner disk capacity for source, downloaded inputs, intermediate output and final deliveries.",
              "This inventory records installed tools and does not establish build compatibility."],
}
encoded = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
if args.output is None:
    sys.stdout.write(encoded)
else:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=args.output.parent, delete=False) as handle:
        handle.write(encoded)
        temporary = pathlib.Path(handle.name)
    try:
        temporary.replace(args.output)
    finally:
        temporary.unlink(missing_ok=True)
    print(args.output)
PY
