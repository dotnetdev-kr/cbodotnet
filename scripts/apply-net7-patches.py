#!/usr/bin/env python3
"""Apply or verify the selected fixed .NET 7 source-build compatibility patches.

The generated source root need not be a Git repository. Its component Git
identities and git-info files, the separate installer checkout, all target
hashes, and every patch are verified before changing any selected source file.
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
import xml.etree.ElementTree as ET


INSTALLER_COMMIT = "25b977658c06fd0217ec0bc0714398bb9d0a7bb0"
COMPONENTS = {
    "installer": INSTALLER_COMMIT,
    "runtime": "0fb6ac59fb1edbe4ed3ad62661df0eb7eacd7903",
    "aspnetcore": "d9ba962869d1b1c410ea476b02de2f8e27eec762",
    "source-build-externals": "522d361e1cd703f1e8e526f5306e4ed18de1da41",
}
PATCHES = [
    {
        "target": "src/runtime/eng/native/configureplatform.cmake",
        "name": "0001-support-arm64-cross-components-host.patch",
        "originalSha256": "30922041dcfcfd30145c30154176e46d7cb8a043a1af540768c087ee8e984c62",
        "patchedSha256": "be392904a9de2b3361721f38eea6e8aab266c68d544e17ebad3a46c28773198a",
        "patchSha256": "cf868ca40e38523ad9f00d8e3c3342cd850066da2b526336a5748c1ffa99a4c9",
        "addedLines": 2,
        "removedLines": 0,
        "purpose": "Recognize native Linux ARM64 hosts for required runtime cross-components.",
        "reference": "https://github.com/dotnet/dotnet/blob/v9.0.123/src/runtime/eng/native/configureplatform.cmake#L30",
    },
    {
        "target": "repos/runtime.proj",
        "name": "0002-preserve-portable-runtime-target.patch",
        "originalSha256": "27a4eeb93c0b179b08971dcfe59b7242efc006b242248f9f34f73f22df777d38",
        "patchedSha256": "2271eb09fa070777c16fd664f720082babc02790743fd324c381592454f04d71",
        "patchSha256": "1b310cabca1b64c13e265a9a434f7e83bb435786f1fc683d346fe18f03b311d2",
        "addedLines": 3,
        "removedLines": 1,
        "purpose": "Honor explicit PortableBuild=true without changing nonportable adapter defaults.",
        "reference": "https://github.com/dotnet/runtime/blob/0fb6ac59fb1edbe4ed3ad62661df0eb7eacd7903/eng/SourceBuild.props#L11",
    },
    {
        "target": "repos/aspnetcore.proj",
        "name": "0003-preserve-portable-aspnetcore-target.patch",
        "originalSha256": "aa4507e8a1b142dc7b465d29f5d6f993b8ffef86330d9926a82581d8e3dcbb40",
        "patchedSha256": "bb125fb416783e0c924ca35a4d6c7513dcef09153a911e3d65daa4b81e85c841",
        "patchSha256": "43f6269e6e18728402ebbcb1d5db88c2fffc4739509e26d7a6cec8440ef36f47",
        "addedLines": 3,
        "removedLines": 1,
        "purpose": "Honor explicit PortableBuild=true and avoid duplicate implicit runtime packages.",
        "reference": "https://github.com/dotnet/aspnetcore/blob/d9ba962869d1b1c410ea476b02de2f8e27eec762/eng/Dependencies.props#L109",
    },
    {
        "target": "src/source-build-externals/patches/azure-activedirectory-identitymodel-extensions-for-dotnet/0002-Port-updateAssemblyInfo.ps1-to-bash-version.patch",
        "name": "0004-use-pinned-identitymodel-metadata-date.patch",
        "originalSha256": "60d0fbc924edbaa5fbef6802caf48fa2e38327cfdb08f1bda5efae0f4cd3518b",
        "patchedSha256": "9ef15f847dea2aed5033d7168e3268070dfb69e2809ab4ef2c30ef30ddcfab25",
        "patchSha256": "8ff2c066cf5a8e0b63123b9c9135779fc7323e84acbc734b447ac2a55276690f",
        "addedLines": 1,
        "removedLines": 1,
        "sourceCommitEpoch": 1713290279,
        "purpose": "Derive valid, reproducible IdentityModel file metadata from the pinned externals source timestamp.",
        "reference": "https://github.com/dotnet/source-build-externals/blob/522d361e1cd703f1e8e526f5306e4ed18de1da41/patches/azure-activedirectory-identitymodel-extensions-for-dotnet/0002-Port-updateAssemblyInfo.ps1-to-bash-version.patch#L24",
    },
]


X64_PATCHES = [
    {
        "target": "src/runtime/eng/native/tryrun.cmake",
        "name": "0005-support-linux-x64-cross-tryrun.patch",
        "originalSha256": "cc17b90941b3ded658ce702ae1ebb854078074f8058ce596460d99dcfd69bfea",
        "patchedSha256": "e98811f2f7b7f749bce406a1ae84302e1c8b326049b87ccf54c8fd7e65ee07db",
        "patchSha256": "ea23441ce857838b96db854d9a028a9a3cef26665bbbc2c0bfa1c0f283255cd6",
        "addedLines": 3,
        "removedLines": 3,
        "purpose": "Backport Linux x64 cross try-run selection and its functional robust-pthread cache from the newer runtime.",
        "reference": "https://github.com/dotnet/dotnet/blob/7d1bf90885cff22e7da72b27e9848e42fd3cb1ae/src/runtime/eng/native/tryrun.cmake#L92"
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
        if name == "source-build-externals":
            epoch = git(component, "show", "-s", "--format=%ct", "HEAD")
            if epoch != "1713290279":
                raise PatchError("Pinned externals commit timestamp mismatch")
            identity["commitEpoch"] = int(epoch)
        identities.append(identity)
    record.update({"installerDirectory": str(installer), "sourceDirectory": str(source),
                   "installerCommit": INSTALLER_COMMIT, "components": identities})


def run(args, record):
    source = ordinary_directory(args.source_dir)
    installer = ordinary_directory(args.installer_dir)
    verify_identity(source, installer, record)
    if getattr(args, "arch", "arm64") == "x64":
        record["targetArchitecture"] = "x64"
        record["scope"] = "Four common fixed compatibility patches plus one exact Linux x64 CMake backport; component identities, source metadata and all hashes are preflighted before mutation."
    record["patches"] = []
    pending = []
    for specification in PATCHES + (X64_PATCHES if getattr(args, "arch", "arm64") == "x64" else []):
        target = fixed_path(source, specification["target"])
        patch_root = Path(__file__).resolve().parent.parent / "patches" / "net7"
        patch = fixed_path(patch_root, specification["name"])
        if digest(patch) != specification["patchSha256"]:
            raise PatchError("Patch SHA-256 mismatch: " + specification["name"])
        before = digest(target)
        item = {**specification, "patch": str(patch), "beforeSha256": before, "changed": False}
        record["patches"].append(item)
        if before not in (specification["originalSha256"], specification["patchedSha256"]):
            raise PatchError("Unknown target content; preserve and inspect it: " + specification["target"])
        expected_stat = "{}\t{}\t{}".format(specification["addedLines"],
                                              specification["removedLines"], specification["target"])
        if git(source, "apply", "--numstat", str(patch)) != expected_stat:
            raise PatchError("A patch changed its fixed one-file scope: " + specification["name"])
        if before == specification["originalSha256"]:
            if args.action == "verify":
                raise PatchError("A required patch is not applied: " + specification["name"])
            git(source, "apply", "--check", "--whitespace=error-all", str(patch))
        pending.append((target, patch, item))
    # All identities, target hashes, patch scopes and pending applications pass
    # before the first source file is changed. Other worktree files are retained.
    for target, patch, item in pending:
        if digest(target) != item["beforeSha256"]:
            raise PatchError("A target changed after preflight: " + item["target"])
        if item["beforeSha256"] == item["originalSha256"]:
            git(source, "apply", "--whitespace=error-all", str(patch))
            item.update({"changed": True, "result": "applied"})
            record["changed"] = True
        else:
            item["result"] = "already-applied" if args.action == "apply" else "verified"
        item["afterSha256"] = digest(target)
        if item["afterSha256"] != item["patchedSha256"]:
            raise PatchError("Patched source SHA-256 mismatch: " + item["target"])
    record["status"] = "passed"
    record["result"] = "applied" if record["changed"] else ("verified" if args.action == "verify" else "already-applied")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["apply", "verify"])
    parser.add_argument("--arch", choices=["arm64", "x64"], default="arm64")
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--installer-dir", type=Path, required=True)
    parser.add_argument("--reports-dir", type=Path,
                        help="Optional external directory; net7-patches-ACTION.json must be new")
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
            report = report_root / ("net7-patches-" + args.action + ".json")
            stream = report.open("x", encoding="utf-8")
    except (OSError, ValueError, PatchError) as error:
        parser.exit(1, "error: " + str(error) + "\n")
    record = {"schemaVersion": 2, "action": args.action,
              "startedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "expectedInstallerCommit": INSTALLER_COMMIT, "status": "failed", "changed": False,
              "scope": "Four fixed patches for native ARM64 host detection, explicit runtime/ASP.NET portability and source-derived IdentityModel metadata; generated component identities, externals commit timestamp and all source hashes are checked before mutation."}
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
