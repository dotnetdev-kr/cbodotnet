#!/usr/bin/env python3
"""Apply or verify the fixed .NET 6 ARM64 source-build compatibility patches.

The generated source root need not be a Git repository. Its component Git
identities and git-info files, the separate installer checkout, all target
hashes, and every patch are verified before changing any of the three files.
Ordered patches for the same file are staged together before any source write.
Pristine, previously patched and final exact file states are accepted.
Unrelated source changes are preserved. Optional reports must be new and
outside both source directories.
"""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


INSTALLER_COMMIT = "d638663530d923adbe0442604b7a6562127321e9"
COMPONENTS = {
    "installer": INSTALLER_COMMIT,
    "runtime": "f1dd57165bfd91875761329ac3a8b17f6606ad18",
}
PATCHES = [
    {
        "target": "src/runtime/eng/native/configureplatform.cmake",
        "name": "0001-support-arm64-cross-components-host.patch",
        "originalSha256": "d429e0f8938220774e1c9055302f822e30a5e6e7c54c574a6eb70314a4e1afe7",
        "patchedSha256": "d63071b7dba2537db696ab6d4f1d43e86719de2e27f7c0d32548c26392d93c90",
        "patchSha256": "00fed1b880f80dba95cfc8a50734b197afe9c234cd23dd394524a3811f6ec6c5",
        "addedLines": 2,
        "removedLines": 0,
        "purpose": "Recognize native Linux ARM64 hosts for required runtime cross-components.",
        "reference": "https://github.com/dotnet/dotnet/blob/v9.0.123/src/runtime/eng/native/configureplatform.cmake#L30"
    },
    {
        "target": "repos/runtime.proj",
        "name": "0002-preserve-portable-runtime-target.patch",
        "originalSha256": "678f7db445ca9f994f433ba8acca0a07bf89658b526524ac302d690a294dd982",
        "patchedSha256": "cfcc3328232decb4fe21f793d0b32a3aba20b18240d189ef8cac3c681ca76db5",
        "patchSha256": "80cc92244c4ec6df240a81e081e1fa1d5f83bce3546f9c0d2f068f0f3fbf586c",
        "addedLines": 3,
        "removedLines": 1,
        "purpose": "Honor explicit PortableBuild=true while retaining the adapter's nonportable default.",
        "reference": "https://github.com/dotnet/runtime/blob/f1dd57165bfd91875761329ac3a8b17f6606ad18/eng/SourceBuild.props#L11"
    },
    {
        "target": "repos/runtime.proj",
        "name": "0003-build-portable-runtime-once.patch",
        "originalSha256": "cfcc3328232decb4fe21f793d0b32a3aba20b18240d189ef8cac3c681ca76db5",
        "patchedSha256": "9db1dff67519149645063a92b3efa207b37cc4b3906bcfbe0a7b8b7251f0a4e4",
        "patchSha256": "3312390ac9e81d24497fb21187d90a4cfd1c34ff531886876e1171758755cd00",
        "addedLines": 1,
        "removedLines": 1,
        "purpose": "Build one portable runtime when explicitly requested, preserving the original dual graph otherwise.",
        "reference": "https://github.com/dotnet/installer/blob/d638663530d923adbe0442604b7a6562127321e9/src/SourceBuild/tarball/content/repos/runtime.proj"
    },
    {
        "target": "repos/known-good.proj",
        "name": "0004-select-one-portable-runtime-root.patch",
        "originalSha256": "6506b0bd44ba6b03dd7c5b4c50797ce7430a2e1865448576c45f4a7bfb5ba992",
        "patchedSha256": "618f58c9fc5631e48d4ad27e6ba7d2aa3795f05597120d94789739f61435376a",
        "patchSha256": "7dff4418b2ed2661fdd80c7ef8c81975400e897f84aa2320407d1be7a9cb5670",
        "addedLines": 1,
        "removedLines": 1,
        "purpose": "Omit the redundant portable runtime root only when the regular runtime node already builds portable outputs.",
        "reference": "https://github.com/dotnet/installer/blob/d638663530d923adbe0442604b7a6562127321e9/src/SourceBuild/tarball/content/repos/known-good.proj"
    }
]


class PatchError(Exception):
    pass


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(arguments, directory):
    process = subprocess.run(arguments, cwd=directory, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    if process.returncode:
        raise PatchError("Command failed: " + " ".join(arguments[:3]) + ": " + process.stderr.strip())
    return process.stdout.strip()


def git(directory, *arguments):
    return command(["git", "--no-optional-locks", "-c", "core.fsmonitor=false", *arguments], directory)


def ordinary_directory(path):
    if not path.is_absolute() or path.is_symlink():
        raise PatchError("An absolute ordinary directory is required: " + str(path))
    resolved = path.resolve(strict=True)
    if not resolved.is_dir() or resolved == Path(resolved.anchor):
        raise PatchError("An existing directory below the filesystem root is required")
    return resolved


def fixed_path(root, relative, directory=False):
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise PatchError("Symbolic links are not allowed in fixed source paths: " + relative)
    if not current.resolve(strict=True).is_relative_to(root):
        raise PatchError("A fixed path escaped its source directory: " + relative)
    if not (current.is_dir() if directory else current.is_file()):
        raise PatchError("Missing fixed source path: " + relative)
    return current


def verify_repository(directory, expected):
    if Path(git(directory, "rev-parse", "--show-toplevel")).resolve(strict=True) != directory:
        raise PatchError("Unexpected component Git top level: " + str(directory))
    if git(directory, "rev-parse", "HEAD") != expected:
        raise PatchError("Component Git commit mismatch: " + str(directory))


def verify_identity(source, installer, record):
    if source == installer or source.is_relative_to(installer) or installer.is_relative_to(source):
        raise PatchError("Installer and generated source must be separate workspaces")
    verify_repository(installer, INSTALLER_COMMIT)
    identities = []
    for name, expected in COMPONENTS.items():
        component = fixed_path(source, "src/" + name, directory=True)
        verify_repository(component, expected)
        metadata = fixed_path(source, "git-info/" + name + ".props")
        matches = ET.parse(metadata).getroot().findall("./PropertyGroup/GitCommitHash")
        if len(matches) != 1 or matches[0].text != expected:
            raise PatchError("Generated git-info revision mismatch: " + name)
        identity = {"repository": name, "commit": expected,
                    "directory": str(component), "metadata": str(metadata),
                    "metadataSha256": digest(metadata)}
        identities.append(identity)
    record.update({"installerDirectory": str(installer), "sourceDirectory": str(source),
                   "installerCommit": INSTALLER_COMMIT, "components": identities})


def run(args, record):
    source = ordinary_directory(args.source_dir)
    installer = ordinary_directory(args.installer_dir)
    verify_identity(source, installer, record)
    record["patches"] = []
    groups = {}
    for specification in PATCHES:
        target = fixed_path(source, specification["target"])
        patch_root = Path(__file__).resolve().parent.parent / "patches" / "net6"
        patch = fixed_path(patch_root, specification["name"])
        if digest(patch) != specification["patchSha256"]:
            raise PatchError("Patch SHA-256 mismatch: " + specification["name"])
        before = digest(target)
        item = {**specification, "patch": str(patch), "observedTargetSha256": before, "changed": False}
        record["patches"].append(item)
        expected_stat = "{}\t{}\t{}".format(specification["addedLines"],
                                              specification["removedLines"], specification["target"])
        if git(source, "apply", "--numstat", str(patch)) != expected_stat:
            raise PatchError("A patch changed its fixed one-file scope: " + specification["name"])
        groups.setdefault(specification["target"], []).append((target, patch, item))
    record["patchChains"] = []
    planned = []
    for relative, chain in groups.items():
        states = [chain[0][2]["originalSha256"]]
        for _, _, item in chain:
            if item["originalSha256"] != states[-1]:
                raise PatchError("Patch chain does not have contiguous exact states: " + relative)
            states.append(item["patchedSha256"])
        observed = digest(chain[0][0])
        if len(set(states)) != len(states) or observed not in states:
            raise PatchError("Unknown target content; preserve and inspect it: " + relative)
        state = states.index(observed)
        if args.action == "verify" and state != len(chain):
            raise PatchError("A required patch is not applied: " + relative)
        record["patchChains"].append({"target": relative, "acceptedSha256States": states,
                                     "observedSha256": observed, "finalSha256": states[-1],
                                     "pendingPatchCount": len(chain) - state})
        for index, (target, patch, item) in enumerate(chain):
            item["required"] = index >= state
            if item["required"]:
                item["beforeSha256"] = states[index]
                planned.append((target, patch, item))
            else:
                item.update({"beforeSha256": observed, "afterSha256": states[-1],
                             "result": "represented-by-later-patch" if index + 1 < len(chain)
                             else ("already-applied" if args.action == "apply" else "verified")})
    # Simulate every remaining transition in a separate Git worktree. This
    # validates ordered contexts and final bytes for both fresh clones and the
    # exact prior two-patch state before the first actual source write.
    with tempfile.TemporaryDirectory(prefix="net6-patch-preflight-",
                                     dir=str(args.reports_dir) if args.reports_dir else None) as temporary:
        stage = Path(temporary)
        git(stage, "init", "--quiet")
        for relative, chain in groups.items():
            staged = stage / relative
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(chain[0][0].read_bytes())
        for _, patch, item in planned:
            staged = stage / item["target"]
            if digest(staged) != item["beforeSha256"]:
                raise PatchError("Staged patch chain input mismatch")
            git(stage, "apply", "--check", "--whitespace=error-all", str(patch))
            git(stage, "apply", "--whitespace=error-all", str(patch))
            if digest(staged) != item["patchedSha256"]:
                raise PatchError("Staged patch chain result mismatch")
        for summary in record["patchChains"]:
            if digest(stage / summary["target"]) != summary["finalSha256"]:
                raise PatchError("Staged final source SHA-256 mismatch")
    for summary in record["patchChains"]:
        if digest(source / summary["target"]) != summary["observedSha256"]:
            raise PatchError("A source target changed after complete preflight")
    for target, patch, item in planned:
        if digest(target) != item["beforeSha256"]:
            raise PatchError("A target changed during ordered application")
        git(source, "apply", "--whitespace=error-all", str(patch))
        item.update({"changed": True, "result": "applied", "afterSha256": digest(target)})
        record["changed"] = True
        if item["afterSha256"] != item["patchedSha256"]:
            raise PatchError("Patched source SHA-256 mismatch: " + item["target"])
    record["status"] = "passed"
    record["result"] = "applied" if record["changed"] else ("verified" if args.action == "verify" else "already-applied")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["apply", "verify"])
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--installer-dir", type=Path, required=True)
    parser.add_argument("--reports-dir", type=Path,
                        help="Optional external directory; net6-patches-ACTION.json must be new")
    args = parser.parse_args()
    stream = None
    report = None
    try:
        if args.reports_dir is not None:
            if not args.reports_dir.is_absolute() or args.reports_dir.is_symlink():
                raise PatchError("An absolute ordinary report directory is required")
            report_root = args.reports_dir.resolve()
            for protected in (args.source_dir.resolve(strict=True), args.installer_dir.resolve(strict=True)):
                if report_root == protected or report_root.is_relative_to(protected):
                    raise PatchError("Reports must be outside both source workspaces")
            if report_root == Path(report_root.anchor):
                raise PatchError("Reports cannot use a filesystem root")
            report_root.mkdir(parents=True, exist_ok=True)
            report = report_root / ("net6-patches-" + args.action + ".json")
            stream = report.open("x", encoding="utf-8")
    except (OSError, ValueError, PatchError) as error:
        parser.exit(1, "error: " + str(error) + "\n")
    record = {"schemaVersion": 3, "action": args.action,
              "startedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "expectedInstallerCommit": INSTALLER_COMMIT, "status": "failed", "changed": False,
              "scope": "Four fixed patches for native ARM64 host detection, explicit runtime portability and one portable runtime graph node; exact ordered source states, all identities and all patches are preflighted before mutation."}
    result = 0
    try:
        run(args, record)
    except (OSError, ValueError, ET.ParseError, PatchError) as error:
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
