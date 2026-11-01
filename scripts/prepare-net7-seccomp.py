#!/usr/bin/env python3
"""Derive the matching native Linux build policy by allowing only fchmodat2 additionally.

The host's default seccomp policy stays unchanged. Existing output policies must
match the deterministic result exactly; different inputs require a new output.
"""

import argparse
import copy
import ctypes
import ctypes.util
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import tempfile


ARCH_SPEC = importlib.util.spec_from_file_location('ci_arch_seccomp', Path(__file__).with_name('ci_arch.py'))
ARCH = importlib.util.module_from_spec(ARCH_SPEC); ARCH_SPEC.loader.exec_module(ARCH)

def digests(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest()}


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key in the source policy: " + key)
        result[key] = value
    return result


def atomic_write(path, content):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("Output must be a regular file: " + str(path))
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(content)
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-policy", type=Path, default=Path("/usr/share/containers/seccomp.json"))
    parser.add_argument("--output-policy", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--arch", choices=["arm64","x64"], default="arm64")
    args = parser.parse_args()
    identity = ARCH.get_arch(args.arch)
    seccomp_arch = "SCMP_ARCH_AARCH64" if args.arch == "arm64" else "SCMP_ARCH_X86_64"
    if platform.system() != "Linux" or platform.machine() != identity["uname"]:
        raise ValueError("A matching native Linux host is required")
    for path in (args.source_policy, args.output_policy, args.report):
        if not path.is_absolute() or path.is_symlink():
            raise ValueError("Absolute paths without symbolic links are required")
    source = args.source_policy.resolve(strict=True)
    output = args.output_policy.parent.resolve(strict=True) / args.output_policy.name
    report = args.report.parent.resolve(strict=True) / args.report.name
    if len({source, output, report}) != 3 or not source.is_file():
        raise ValueError("The source policy and two output files must be separate regular-file paths")
    source_bytes = source.read_bytes()
    baseline = json.loads(source_bytes, object_pairs_hook=reject_duplicate_keys)
    if not isinstance(baseline, dict) or baseline.get("defaultAction") != "SCMP_ACT_ERRNO":
        raise ValueError("The base policy must retain its default SCMP_ACT_ERRNO denial")
    if not isinstance(baseline.get("syscalls"), list) or not baseline["syscalls"]:
        raise ValueError("The base policy must contain syscall rules")
    arch_map = baseline.get("archMap", [])
    architectures = baseline.get("architectures", [])
    if not (seccomp_arch in architectures or any(
            isinstance(entry, dict) and entry.get("architecture") == seccomp_arch for entry in arch_map)):
        raise ValueError("The base policy does not declare selected native architecture support")

    # An external ldconfig probe may miss a library that the runtime loader can
    # resolve. Keep the same native API checks below.
    library_name = ctypes.util.find_library("seccomp") or "libseccomp.so.2"
    library = ctypes.CDLL(library_name)
    library.seccomp_arch_native.restype = ctypes.c_uint32
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    native_architecture = library.seccomp_arch_native()
    syscall_number = library.seccomp_syscall_resolve_name(b"fchmodat2")
    if native_architecture != (0xC0000000 | identity["machine"]) or syscall_number != 452:
        raise ValueError("The host must resolve selected native fchmodat2 to syscall 452")

    class Version(ctypes.Structure):
        _fields_ = [("major", ctypes.c_uint), ("minor", ctypes.c_uint), ("micro", ctypes.c_uint)]

    library.seccomp_version.restype = ctypes.POINTER(Version)
    version = library.seccomp_version().contents
    matches = []
    for rule in baseline["syscalls"]:
        if not isinstance(rule, dict) or not isinstance(rule.get("names"), list):
            raise ValueError("Unsupported syscall-rule shape in the base policy")
        if "fchmodat2" in rule["names"]:
            matches.append(rule)
    if len(matches) > 1:
        raise ValueError("The base policy contains multiple fchmodat2 rules")
    if matches and (matches[0].get("action") != "SCMP_ACT_ALLOW" or matches[0].get("args")
                    or matches[0].get("includes") or matches[0].get("excludes")):
        raise ValueError("The base policy has a restricted or denied fchmodat2 rule; it will not be replaced")
    policy = copy.deepcopy(baseline)
    added_rule = {"names": ["fchmodat2"], "action": "SCMP_ACT_ALLOW"}
    if not matches:
        policy["syscalls"].append(added_rule)
    restored = copy.deepcopy(policy)
    if not matches:
        restored["syscalls"].pop()
    if restored != baseline:
        raise ValueError("The derived policy changed more than the single intended rule")
    if sum("fchmodat2" in rule["names"] for rule in policy["syscalls"]) != 1:
        raise ValueError("The derived policy must have exactly one fchmodat2 rule")
    output_bytes = (json.dumps(policy, indent=2, sort_keys=True) + "\n").encode("utf-8")
    reused = output.exists()
    if reused:
        if not output.is_file() or output.read_bytes() != output_bytes:
            raise ValueError("Existing policy differs from the derived result; preserve it and choose a new workspace/output path")
    else:
        atomic_write(output, output_bytes)
    record = {"schemaVersion": 1, "preparedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status": "verified-existing" if reused else "created", "nativeArchitecture": identity["uname"],
              "libseccomp": {"library": library_name, "version": f"{version.major}.{version.minor}.{version.micro}",
                             "nativeArchitectureToken": hex(native_architecture), "fchmodat2SyscallNumber": syscall_number},
              "basePolicy": {"path": str(source), **digests(source_bytes)},
              "outputPolicy": {"path": str(output), **digests(output_bytes)},
              "defaultAction": policy["defaultAction"], "defaultErrnoRet": policy.get("defaultErrnoRet"),
              "addedRuleCount": 0 if matches else 1, "addedRule": None if matches else added_rule,
              "allOtherRulesUnchanged": True, "fchmodat2RuleCount": 1, "seccompUnconfined": False,
              "scope": "Only the .NET 7 unprivileged build/test/preparation containers use this derived policy. The host default policy and privileged sysroot preparation are unchanged."}
    atomic_write(report, (json.dumps(record, indent=2) + "\n").encode("utf-8"))
    print(json.dumps({"status": record["status"], "policy": str(output),
                      "sha256": record["outputPolicy"]["sha256"], "addedRuleCount": record["addedRuleCount"]}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, AttributeError, json.JSONDecodeError) as error:
        raise SystemExit("error: " + str(error))
