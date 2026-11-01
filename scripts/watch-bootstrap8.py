#!/usr/bin/env python3
"""Preserve and fingerprint the original and bootstrapped .NET 8 PSB inputs.

The watcher links inside the same source bind mount before upstream prep deletes
its original archive. Finalization then preserves it under the inputs mount.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import time
from urllib.parse import urlparse
import xml.etree.ElementTree as ET


COMMIT = "7d1bf90885cff22e7da72b27e9848e42fd3cb1ae"


def fingerprint(path):
    sha256, sha512 = hashlib.sha256(), hashlib.sha512()
    size = 0
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(data)
            sha256.update(data)
            sha512.update(data)
    return {"bytes": size, "sha256": sha256.hexdigest(), "sha512": sha512.hexdigest()}


def archive_record(path, require_runtime=False, arch='arm64'):
    if arch not in ('arm64', 'x64'):
        raise ValueError('Unsupported bootstrap architecture')
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        versions = [member for member in members if member.name.lstrip("./") == "PackageVersions.props"]
        if len(versions) != 1:
            raise ValueError("Expected one PackageVersions.props in " + str(path))
        with archive.extractfile(versions[0]) as stream:
            version_bytes = stream.read()
        ET.fromstring(version_bytes)
        names = [member.name.rsplit("/", 1)[-1].lower() for member in members if member.isfile()]
        packages = [name for name in names if name.endswith(".nupkg") and "linux-" + arch in name]
        if require_runtime and not any(name.startswith("microsoft.netcore.app.runtime.linux-" + arch + ".") for name in packages):
            raise ValueError("The bootstrapped archive lacks a native runtime package for " + arch)
    key = 'linuxArm64Packages' if arch == 'arm64' else 'linuxX64Packages'
    return {**fingerprint(path), "packageVersionsSha256": hashlib.sha256(version_bytes).hexdigest(), key: sorted(packages)}


def atomic_json(path, record):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        json.dump(record, stream, indent=2)
        stream.write("\n")
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["watch", "finalize", "verify"])
    parser.add_argument('--arch', choices=['arm64', 'x64'], default='arm64')
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--inputs-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    source = args.source_dir.resolve(strict=True)
    inputs = args.inputs_dir.resolve(strict=True)
    urls = [node.text for node in ET.parse(source / "eng/Versions.props").iter()
            if node.tag.rsplit("}", 1)[-1] == "PrivateSourceBuiltArtifactsUrl"]
    if len(urls) != 1 or not urls[0]:
        raise ValueError("Expected the pinned original PSB URL")
    original_name = Path(urlparse(urls[0]).path).name
    if original_name != "Private.SourceBuilt.Artifacts.8.0.131-servicing.26422.1.centos.9-x64.tar.gz":
        raise ValueError("Original PSB URL does not match the pinned .NET 8 input")
    archive_dir = source / "prereqs/packages/archive"
    original = archive_dir / original_name
    sidecar = archive_dir / (".cbodotnet-original-" + original_name)
    preserved_dir = inputs / "original-bootstrap"
    preserved = preserved_dir / original_name
    bootstrap = archive_dir / "Private.SourceBuilt.Artifacts.Bootstrap.tar.gz"
    marker = inputs / "bootstrap8-prepared.json"
    if args.action == "watch":
        deadline = time.monotonic() + 7200
        while time.monotonic() < deadline:
            if original.is_file():
                try:
                    os.link(original, sidecar)
                except FileExistsError:
                    if not os.path.samefile(original, sidecar):
                        raise ValueError("Refusing a different existing original-archive sidecar")
                print(json.dumps({"status": "linked", "source": str(original), "sidecar": str(sidecar)}), flush=True)
                return 0
            if sidecar.is_file() or preserved.is_file():
                print(json.dumps({"status": "already-preserved", "source": str(original)}), flush=True)
                return 0
            time.sleep(0.05)
        raise ValueError("Original PSB download was not observed before the preservation timeout")
    if args.action == "finalize":
        preserved_dir.mkdir(exist_ok=True)
        if not preserved.is_file():
            if not sidecar.is_file():
                raise ValueError("The original PSB archive was not preserved")
            temporary = preserved_dir / (original_name + ".copying")
            if temporary.exists() or temporary.is_symlink():
                raise ValueError("Refusing an existing incomplete original-archive copy")
            try:
                os.link(sidecar, temporary)
            except OSError as error:
                if error.errno != 18:
                    raise
                shutil.copyfile(sidecar, temporary)
            if fingerprint(temporary) != fingerprint(sidecar):
                raise ValueError("The original PSB archive changed during preservation")
            os.replace(temporary, preserved)
        elif sidecar.is_file() and not os.path.samefile(sidecar, preserved):
            if fingerprint(sidecar) != fingerprint(preserved):
                raise ValueError("A different original PSB archive already exists in inputs")
        record = {"schemaVersion": 1, "preparedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "sourceCommit": COMMIT, "bootstrapSdk": "8.0.131", "originalUrl": urls[0],
                  "originalArchive": {"path": str(preserved), **archive_record(preserved, arch=args.arch)},
                  "bootstrapArchive": {"relativePath": str(bootstrap.relative_to(source)),
                                       **archive_record(bootstrap, require_runtime=True, arch=args.arch)},
                  "note": "Successful upstream prep replaced native/portable inputs using official packages; hashes record content, not publisher signature verification."}
        if args.arch != 'arm64':
            record.update(architecture=args.arch, targetRid='linux-' + args.arch)
        atomic_json(marker, record)
    else:
        record = json.loads(marker.read_text())
        if record["sourceCommit"] != COMMIT or record["bootstrapSdk"] != "8.0.131":
            raise ValueError("Bootstrap preparation marker does not match the pinned source")
        if record.get('architecture', 'arm64') != args.arch or (args.arch != 'arm64' and record.get('targetRid') != 'linux-' + args.arch):
            raise ValueError('Bootstrap preparation architecture differs')
        for path, expected in [(bootstrap, record["bootstrapArchive"]), (preserved, record["originalArchive"])]:
            actual = fingerprint(path)
            if any(actual[key] != expected[key] for key in actual):
                raise ValueError("Prepared bootstrap input changed: " + str(path))
    if args.report:
        if args.report.exists() or args.report.is_symlink():
            raise ValueError("Refusing an existing bootstrap report")
        atomic_json(args.report, record)
    print(json.dumps({"status": "passed", "action": args.action, "marker": str(marker),
                      "bootstrapSha256": record["bootstrapArchive"]["sha256"]}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, tarfile.TarError, ET.ParseError, KeyError) as error:
        raise SystemExit("error: " + str(error))
