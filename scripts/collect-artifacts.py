#!/usr/bin/env python3
"""Collect an unchanged VMR SDK archive and its provenance metadata.

Collection verifies the source commit and archive selection. SDK identity,
functionality, ABI compatibility and symbol matching require separate tests.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


class CollectionError(Exception):
    pass


def digest_file(path):
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            sha256.update(chunk)
            sha512.update(chunk)
    return {"bytes": size, "sha256": sha256.hexdigest(), "sha512": sha512.hexdigest()}


def file_record(path, root, include_hashes=True):
    record = {"path": path.relative_to(root).as_posix()}
    record.update(digest_file(path) if include_hashes else {"bytes": path.stat().st_size})
    return record


def regular_files(root):
    if not root.is_dir():
        return []
    return sorted(path for path in root.rglob("*") if path.is_file() and not path.is_symlink())


def git_output(source, *arguments):
    try:
        return subprocess.run(
            ["git", "-C", str(source), *arguments], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace",
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise CollectionError("Cannot verify the VMR Git state: " + str(error)) from error


def contains_token(name, token):
    return re.search(r"(?<![A-Za-z0-9])" + re.escape(token) + r"(?![A-Za-z0-9])", name) is not None


def is_symbol_candidate(path):
    return (re.search(r"symbol|symstore|debuginfo|debugsymbols", path.name, re.IGNORECASE) is not None
            or path.suffix.lower() in {".pdb", ".dbg", ".debug"})


def select_sdk(source, version, rid):
    release_root = source / "artifacts" / "assets" / "Release"
    # Prefer the SDK output directory, while also checking older/root layouts.
    roots = [release_root / "Sdk", release_root]
    candidates = []
    seen = set()
    for root in roots:
        for path in regular_files(root):
            if path in seen:
                continue
            seen.add(path)
            if (path.name.startswith("dotnet-sdk-" + version + "-")
                    and path.name.endswith(".tar.gz")
                    and contains_token(path.name, rid)
                    and not is_symbol_candidate(path)):
                candidates.append(path)
    if not candidates:
        raise CollectionError("No SDK .tar.gz matches SDK " + version + " and RID " + rid
                              + " under " + str(release_root))
    records = [file_record(path, source) for path in candidates]
    identities = {(item["bytes"], item["sha256"], item["sha512"]) for item in records}
    if len(identities) != 1:
        names = ", ".join(item["path"] for item in records)
        raise CollectionError("Conflicting, nonidentical SDK archive candidates: " + names)
    return candidates[0], records, release_root


def atomic_text(path, content):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=path.parent, prefix=".collect-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def copy_unchanged(source, destination, expected):
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_file():
            raise CollectionError("Output SDK path is not a regular file: " + str(destination))
        if digest_file(destination) != expected:
            raise CollectionError("Refusing to replace a different SDK archive: " + str(destination))
        return
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".collect-", delete=False) as stream:
            temporary = Path(stream.name)
        shutil.copyfile(source, temporary)
        if digest_file(temporary) != expected:
            raise CollectionError("SDK archive changed during collection or copying")
        os.replace(temporary, destination)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def collect(args):
    source = args.source_dir.resolve(strict=True)
    profile_path = args.profile.resolve(strict=True)
    reports = args.reports_dir.resolve(strict=True)
    output = args.output_dir.resolve()
    if not source.is_dir() or not reports.is_dir() or not profile_path.is_file():
        raise CollectionError("Source/reports must be existing directories and profile must be a file")
    if args.output_dir.is_symlink():
        raise CollectionError("Output directory must not be a symlink")
    # Reports may be a child of the output directory: generated archives,
    # manifests and checksums then remain outside the report inventory.
    # Reject the inverse layout, which would inventory our own outputs.
    if output == reports or reports in output.parents:
        raise CollectionError("Output directory must not equal or be inside the reports directory")
    if not re.fullmatch(r"(?:sha256:)?[0-9a-fA-F]{64}", args.build_image_id):
        raise CollectionError("--build-image-id must be an immutable SHA-256 image ID")

    profile_bytes = profile_path.read_bytes()
    profile = json.loads(profile_bytes.decode("utf-8-sig"))
    version = profile.get("sdkVersion", "")
    rid = profile.get("target", {}).get("rid", "")
    commit = profile.get("source", {}).get("commit", "")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", version):
        raise CollectionError("Profile must declare a valid sdkVersion")
    if not re.fullmatch(r"linux-(?:arm64|x64)", rid):
        raise CollectionError("Profile target RID must be linux-arm64 or linux-x64")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        raise CollectionError("Profile must pin a full VMR commit SHA")
    if profile.get("build", {}).get("sourceOnly") is not False:
        raise CollectionError("This collector requires the non-source-only build profile")
    actual_commit = git_output(source, "rev-parse", "HEAD").lower()
    if actual_commit != commit.lower():
        raise CollectionError("VMR HEAD does not match the profile commit")
    worktree_status = git_output(source, "status", "--porcelain", "--untracked-files=no")

    sdk, candidates, release_root = select_sdk(source, version, rid)
    if output == release_root or release_root in output.parents:
        raise CollectionError("Output directory must be outside the upstream artifact search directory")
    expected_digest = {key: candidates[0][key] for key in ("bytes", "sha256", "sha512")}
    filename = "cbodotnet-sdk-" + version + "-" + rid + "-build." + args.build_revision + ".tar.gz"

    project = Path(__file__).resolve().parent.parent
    rebuild_files = regular_files(project / "scripts") + regular_files(project / "containers")
    inputs = [file_record(path, project) for path in sorted(set(rebuild_files))]
    profile_hash = {"bytes": len(profile_bytes),
                    "sha256": hashlib.sha256(profile_bytes).hexdigest(),
                    "sha512": hashlib.sha512(profile_bytes).hexdigest()}
    report_files = [file_record(path, reports) for path in regular_files(reports)]
    architecture = rid.rsplit("-", 1)[1]
    architecture_names = {"arm64": ("arm64", "aarch64"), "x64": ("x64", "amd64", "x86_64")}[architecture]
    versions = {version}
    runtime_version = profile.get("upstreamInputs", {}).get("runtime")
    if isinstance(runtime_version, str):
        versions.add(runtime_version)
    packages = []
    symbols = []
    for path in regular_files(release_root):
        if is_symbol_candidate(path):
            symbols.append(file_record(path, source, include_hashes=False))
        if (path.suffix.lower() in {".deb", ".rpm"}
                and any(contains_token(path.name, value) for value in versions)
                and any(contains_token(path.name, value) for value in architecture_names)):
            packages.append(file_record(path, source))

    manifest = {
        "schemaVersion": 1,
        "collectedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "collected; SDK verification is separate",
        "sdkVersion": version,
        "targetRid": rid,
        "buildRevision": args.build_revision,
        "sourceOnly": False,
        "source": {
            "repository": profile["source"].get("repository"),
            "tag": profile["source"].get("tag"),
            "expectedCommit": commit.lower(),
            "actualCommit": actual_commit,
            "commitVerified": True,
            "worktreeDirty": bool(worktree_status),
            "trackedChangeCount": len(worktree_status.splitlines()) if worktree_status else 0,
        },
        "construction": {
            "upstreamSharedRuntimeReused": True,
            "sharedComponents": profile["build"].get("sharedComponents"),
            "declaredUpstreamInputs": profile.get("upstreamInputs", {}),
            "note": "Shared runtime inputs are declared by the profile; they were not rebuilt from 1xx sources in this build.",
        },
        "buildImage": {"id": args.build_image_id.lower(), "baseImage": profile.get("container", {})},
        "profile": {"path": str(profile_path), **profile_hash, "contents": profile},
        "rebuildInputs": inputs,
        "sdkArchive": {
            "path": filename, **expected_digest,
            "upstreamPath": sdk.relative_to(source).as_posix(),
            "identicalCandidates": candidates,
            "copiedWithoutModification": True,
            "identityCheck": "Expected SDK version and RID matched in the upstream filename; archive contents require SDK verification.",
        },
        "reports": {"root": str(reports), "files": report_files,
                    "note": "Digest inventory only; collection does not evaluate report contents or assert test success."},
        "otherArtifacts": {
            "packages": {"copied": False, "files": packages},
            "symbolCandidates": {"copied": False, "matchingVerified": False, "files": symbols,
                                 "note": "Informative candidates only; matching to this SDK has not been verified."},
        },
    }

    output.mkdir(parents=True, exist_ok=True)
    copy_unchanged(sdk, output / filename, expected_digest)
    atomic_text(output / "SHA256SUMS", expected_digest["sha256"] + "  " + filename + "\n")
    atomic_text(output / "SHA512SUMS", expected_digest["sha512"] + "  " + filename + "\n")
    atomic_text(output / "build-manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"archive": str(output / filename), **expected_digest,
                      "manifest": str(output / "build-manifest.json")}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--reports-dir", type=Path, required=True)
    parser.add_argument("--build-image-id", required=True)
    parser.add_argument("--build-revision", default="1")
    args = parser.parse_args()
    if not re.fullmatch(r"[1-9][0-9]*", args.build_revision):
        parser.error("--build-revision must be a positive integer")
    try:
        collect(args)
    except (CollectionError, OSError, ValueError, KeyError, TypeError) as error:
        print("error: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
