#!/usr/bin/env python3
"""Apply or verify the fixed .NET 8 ARM64 compatibility patches.

Only two pinned source files can change. Unrelated tracked or untracked changes
are preserved. Optional reports must be new and outside the VMR checkout;
every invocation records its actual action separately.
"""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys


COMMIT = "7d1bf90885cff22e7da72b27e9848e42fd3cb1ae"
PATCHES = [
    {
        "target": "src/runtime/eng/native/configureplatform.cmake",
        "originalSha256": "e3ccca4155e4a5811576c6e3f18a5efc6aa0d49b3a352d0a98366c020fa2eab2",
        "patchedSha256": "91bb7b95d9d2e2b5d437b39290af61203419c487913e2d5ed2112ac31b421a8e",
        "name": "0001-support-arm64-cross-components-host.patch",
        "patchSha256": "d8d94bc40c11ed96bb9cc14a9ada399929999cda9c09da86eac4a2d961c1e1e3",
        "reference": "https://github.com/dotnet/dotnet/blob/v9.0.123/src/runtime/eng/native/configureplatform.cmake#L30",
        "upstreamVmrCommit": "9f04b57d1366e21b3178648493d6edffeff2216e",
        "purpose": "Recognize Linux aarch64 hosts for runtime cross-component build tools.",
    },
    {
        "target": "repo-projects/aspnetcore.proj",
        "originalSha256": "10bb2a651fb1176b6f4641aea93f035ab2124bbb2ef3ce32f9989fa814b99a97",
        "patchedSha256": "1d61d5b2b8174ece3cd85442ce0f4fc4e44134a3c7b03e2a0b7cfce5204b65f0",
        "name": "0002-preserve-portable-aspnetcore-target.patch",
        "patchSha256": "b03fab8085c959debc05892fb1920edaa8f514f90d4189994de23608abcc7d8a",
        "reference": "https://github.com/dotnet/dotnet/blob/v8.0.133/repo-projects/aspnetcore.proj#L9",
        "purpose": "Honor explicit PortableBuild=true without changing the adapter's empty/false defaults.",
    },
]


class PatchError(Exception):
    pass


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(source, *arguments):
    process = subprocess.run(
        ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(source), *arguments],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        encoding="utf-8", errors="replace",
    )
    if process.returncode:
        raise PatchError("Git command failed: " + " ".join(arguments[:2])
                         + ": " + process.stderr.strip())
    return process.stdout.strip()


def run(args, record):
    if not args.source_dir.is_absolute():
        raise PatchError("An absolute source directory is required")
    source = args.source_dir.resolve(strict=True)
    if not source.is_dir():
        raise PatchError("Source must be an existing directory")
    if Path(git(source, "rev-parse", "--show-toplevel")).resolve(strict=True) != source:
        raise PatchError("Source must be the VMR Git top level")
    actual_commit = git(source, "rev-parse", "HEAD")
    if actual_commit != COMMIT:
        raise PatchError("Source commit does not match the pinned .NET 8 VMR")
    record.update({"sourceDirectory": str(source), "sourceCommit": actual_commit, "patches": []})
    pending = []
    # Check every input before changing any file, including an already-applied patch.
    for specification in PATCHES:
        relative = specification["target"]
        target = source / relative
        if not target.is_file() or target.is_symlink() or not target.resolve(strict=True).is_relative_to(source):
            raise PatchError("The fixed target must be a regular file inside the VMR: " + relative)
        if git(source, "ls-files", "--error-unmatch", "--", relative) != relative:
            raise PatchError("The fixed source file is not tracked: " + relative)
        patch = Path(__file__).resolve().parent.parent / "patches" / "net8" / specification["name"]
        if not patch.is_file() or patch.is_symlink() or digest(patch) != specification["patchSha256"]:
            raise PatchError("Patch SHA-256 mismatch: " + specification["name"])
        before = digest(target)
        item = {**specification, "patch": str(patch), "beforeSha256": before, "changed": False}
        record["patches"].append(item)
        if before not in (specification["originalSha256"], specification["patchedSha256"]):
            raise PatchError("Unknown target content; preserve and inspect it: " + relative)
        if before == specification["originalSha256"]:
            if args.action == "verify":
                raise PatchError("A required compatibility patch has not been applied: " + specification["name"])
            if git(source, "apply", "--numstat", str(patch)) != "2\t0\t" + relative:
                raise PatchError("Each fixed patch must add two lines to only its expected file")
            git(source, "apply", "--check", "--whitespace=error-all", str(patch))
        pending.append((target, patch, item))
    for target, patch, item in pending:
        if item["beforeSha256"] == item["originalSha256"]:
            git(source, "apply", "--whitespace=error-all", str(patch))
            item.update({"changed": True, "result": "applied"})
            record["changed"] = True
        else:
            item["result"] = "already-applied" if args.action == "apply" else "verified"
        item["afterSha256"] = digest(target)
        if item["afterSha256"] != item["patchedSha256"]:
            raise PatchError("Patched source SHA-256 verification failed: " + item["target"])
    record["result"] = "applied" if record["changed"] else ("verified" if args.action == "verify" else "already-applied")
    record["status"] = "passed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["apply", "verify"])
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--reports-dir", type=Path,
                        help="Optional external directory; net8-patches-ACTION.json must not already exist")
    args = parser.parse_args()
    report = None
    stream = None
    if args.reports_dir is not None:
        try:
            if not args.reports_dir.is_absolute():
                raise PatchError("An absolute report directory is required")
            report_root = args.reports_dir.resolve()
            source = args.source_dir.resolve(strict=True)
            if report_root == Path(report_root.anchor) or report_root == source or report_root.is_relative_to(source):
                raise PatchError("Reports must be outside the VMR and not at a filesystem root")
            report_root.mkdir(parents=True, exist_ok=True)
            report = report_root / ("net8-patches-" + args.action + ".json")
            stream = report.open("x", encoding="utf-8")
        except (OSError, ValueError, PatchError) as error:
            parser.exit(1, "error: " + str(error) + "\n")
    record = {"schemaVersion": 2, "action": args.action,
              "startedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status": "failed", "changed": False,
              "expectedSourceCommit": COMMIT,
              "scope": "Two fixed compatibility patches: Linux ARM64 host-tool detection and explicit ASP.NET portable-target propagation. Each adds two lines to one pinned file; unrelated changes are preserved."}
    result = 0
    try:
        run(args, record)
    except (OSError, ValueError, PatchError) as error:
        record["error"] = str(error)
        print("error: " + str(error), file=sys.stderr)
        result = 1
    finally:
        record["finishedAtUtc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        if stream is not None:
            try:
                json.dump(record, stream, indent=2)
                stream.write("\n")
            finally:
                stream.close()
    if result == 0:
        print(json.dumps({"status": record["status"], "result": record["result"],
                          "patches": [{"target": item["target"], "sha256": item["afterSha256"],
                                       "result": item["result"]} for item in record["patches"]],
                          "report": str(report) if report is not None else None}))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
