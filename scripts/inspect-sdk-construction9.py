#!/usr/bin/env python3
"""Compare .NET 9 SDK shared frameworks with explicitly selected input archives.

This records byte identity, not independent proof of an archive's origin. Pair
the report with the VMR build/publish logs and SDK download records before
describing a component as locally built or reused from upstream.
"""

import argparse
import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile


def sha256_stream(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def archive_record(path):
    with path.open("rb") as stream:
        digest = sha256_stream(stream)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest}


def normalized_name(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("Unsafe archive entry: " + name)
    return path.as_posix()


def shared_tree(path, prefix):
    records = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = normalized_name(member.name)
            if not name.startswith(prefix + "/") or member.isdir():
                continue
            relative = name[len(prefix) + 1:]
            if relative in records:
                raise ValueError("Duplicate archive entry: " + name)
            if member.isfile() or member.islnk():
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("Cannot read archive entry: " + name)
                with stream:
                    digest = sha256_stream(stream)
                records[relative] = {"type": "file", "sha256": digest}
            elif member.issym():
                records[relative] = {"type": "symlink", "target": member.linkname}
            else:
                raise ValueError("Unsupported shared-framework entry: " + name)
    if not records:
        raise ValueError("No shared-framework entries found for " + prefix + " in " + str(path))
    return records


def compare(sdk, candidate, framework, version):
    prefix = "shared/" + framework + "/" + version
    sdk_files = shared_tree(sdk, prefix)
    input_files = shared_tree(candidate, prefix)
    sdk_names, input_names = set(sdk_files), set(input_files)
    missing = sorted(input_names - sdk_names)
    additional = sorted(sdk_names - input_names)
    changed = sorted(name for name in sdk_names & input_names if sdk_files[name] != input_files[name])
    return {
        "framework": framework,
        "version": version,
        "prefix": prefix,
        "inputArchive": archive_record(candidate),
        "sdkEntryCount": len(sdk_files),
        "inputEntryCount": len(input_files),
        "identical": not (missing or additional or changed),
        "missingFromSdk": missing,
        "additionalInSdk": additional,
        "changedEntries": changed,
        "sdkEntries": sdk_files,
        "inputEntries": input_files,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-archive", type=Path, required=True)
    parser.add_argument("--runtime-archive", type=Path, required=True)
    parser.add_argument("--aspnetcore-archive", type=Path, required=True)
    parser.add_argument("--runtime-version", default="9.0.22")
    parser.add_argument("--reports-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        sdk, runtime, aspnet = [path.resolve(strict=True) for path in
                               (args.sdk_archive, args.runtime_archive, args.aspnetcore_archive)]
        if not all(path.is_file() for path in (sdk, runtime, aspnet)):
            raise ValueError("All archive arguments must be existing regular files")
        if args.reports_dir.exists() or args.reports_dir.is_symlink():
            raise ValueError("The report directory must not already exist")
        comparisons = [compare(sdk, runtime, "Microsoft.NETCore.App", args.runtime_version),
                       compare(sdk, aspnet, "Microsoft.AspNetCore.App", args.runtime_version)]
        passed = all(item["identical"] for item in comparisons)
        report = {
            "schemaVersion": 1,
            "recordedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "passed" if passed else "failed",
            "sdkArchive": archive_record(sdk),
            "comparisons": comparisons,
            "scope": "Exact shared-framework entry paths, regular-file SHA-256 values, and symbolic-link targets. Directory metadata and archive compression are not compared.",
            "originVerified": False,
            "note": "Byte identity establishes matching archive contents. Component origin requires separate build/publish and download evidence; input filenames alone do not prove provenance.",
        }
        args.reports_dir.mkdir(parents=True, exist_ok=False)
        report_path = args.reports_dir / "shared-framework-identity.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"report": str(report_path), "status": report["status"],
                          "components": [{"framework": item["framework"], "entries": item["sdkEntryCount"],
                                          "identical": item["identical"]} for item in comparisons]}))
        return 0 if passed else 1
    except (OSError, ValueError, tarfile.TarError) as error:
        parser.exit(2, "error: " + str(error) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
