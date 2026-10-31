#!/usr/bin/env python3
"""Restore retained symbol archives consumed by the legacy .NET 8 finalizer.

Only fixed Symbols.*.tar.gz inputs are copied from the pinned build's blob feed.
Existing identical files are reused; different files and symlinks are refused.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


COMMIT = "7d1bf90885cff22e7da72b27e9848e42fd3cb1ae"
NAME = re.compile(r"Symbols\.[A-Za-z0-9][A-Za-z0-9_.+-]*\.tar\.gz\Z")


def fingerprint(path):
    sha256, sha512 = hashlib.sha256(), hashlib.sha512()
    size = 0
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(data)
            sha256.update(data)
            sha512.update(data)
    return {"bytes": size, "sha256": sha256.hexdigest(), "sha512": sha512.hexdigest()}


def git(source, *arguments):
    process = subprocess.run(
        ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(source), *arguments],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return process.stdout.strip()


def fixed_directory(source, relative):
    current = source
    for part in Path(relative).parts:
        current /= part
        if current.is_symlink():
            raise ValueError("Symbol input/output directories must not contain symlinks: " + str(current))
        if current.exists() and not current.is_dir():
            raise ValueError("A fixed symbol directory is not a directory: " + str(current))
    if not current.resolve(strict=False).is_relative_to(source):
        raise ValueError("A symbol path escaped the pinned checkout")
    return current


def regular_file(path):
    if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("A symbol archive must be a regular file without symlinks: " + str(path))


def copy_unchanged(source, destination, expected):
    if destination.exists() or destination.is_symlink():
        regular_file(destination)
        if fingerprint(destination) != expected:
            raise ValueError("Refusing a different existing symbol archive: " + str(destination))
        return "reused"
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".net8-symbol-copy-", delete=False) as output:
            temporary = Path(output.name)
            with source.open("rb") as stream:
                sha256, sha512, size = hashlib.sha256(), hashlib.sha512(), 0
                for data in iter(lambda: stream.read(1024 * 1024), b""):
                    output.write(data)
                    size += len(data)
                    sha256.update(data)
                    sha512.update(data)
            output.flush()
            os.fsync(output.fileno())
        actual = {"bytes": size, "sha256": sha256.hexdigest(), "sha512": sha512.hexdigest()}
        if actual != expected:
            raise ValueError("A retained symbol archive changed during copying: " + str(source))
        # Linking a complete private temporary file publishes it atomically and
        # cannot overwrite another file that appeared after the initial check.
        try:
            os.link(temporary, destination)
        except FileExistsError:
            regular_file(destination)
            if fingerprint(destination) != expected:
                raise ValueError("A different symbol archive appeared during copying: " + str(destination))
            return "reused"
        return "copied"
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--reports-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.source_dir.is_absolute() or args.source_dir.is_symlink():
        raise ValueError("The source must be an absolute directory without a symbolic link")
    source = args.source_dir.resolve(strict=True)
    if not source.is_dir() or Path(git(source, "rev-parse", "--show-toplevel")).resolve(strict=True) != source:
        raise ValueError("The source must be the VMR Git top level")
    if git(source, "rev-parse", "HEAD") != COMMIT:
        raise ValueError("The source does not match the pinned .NET 8 commit")
    if not args.reports_dir.is_absolute() or args.reports_dir.is_symlink():
        raise ValueError("Reports must use an absolute external directory without a symbolic link")
    reports = args.reports_dir.resolve(strict=True)
    if not reports.is_dir() or reports == source or reports.is_relative_to(source):
        raise ValueError("Reports must be in an existing directory outside the VMR")
    report_path = reports / "net8-symbol-inputs.json"
    if report_path.exists() or report_path.is_symlink():
        raise ValueError("Refusing to overwrite an existing symbol-input report")
    assets = fixed_directory(source, "artifacts/obj/arm64/Release/blob-feed/assets")
    output = fixed_directory(source, "artifacts/arm64/Release")
    inputs = sorted(assets.glob("Symbols.*.tar.gz")) if assets.is_dir() else []
    record = {"schemaVersion": 1, "recordedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "sourceCommit": COMMIT, "sourceDirectory": str(source), "retainedAssetsDirectory": str(assets),
              "outputDirectory": str(output), "status": "no-retained-inputs" if not inputs else "restored",
              "files": [], "copied": 0, "reused": 0,
              "scope": "Restore byte-identical retained symbol archives for legacy finalization retries. No SDK archive is changed, no symbol checks are disabled, and differing existing files are never replaced."}
    if inputs:
        output.mkdir(parents=True, exist_ok=True)
    for archive in inputs:
        if not NAME.fullmatch(archive.name):
            raise ValueError("Unsupported symbol archive name: " + archive.name)
        regular_file(archive)
        expected = fingerprint(archive)
        destination = output / archive.name
        result = copy_unchanged(archive, destination, expected)
        record["files"].append({"source": str(archive.relative_to(source)),
                                "destination": str(destination.relative_to(source)), "result": result, **expected})
        record[result] += 1
    with report_path.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"status": record["status"], "copied": record["copied"], "reused": record["reused"],
                      "report": str(report_path)}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit("error: " + str(error))
