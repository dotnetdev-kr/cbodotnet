#!/usr/bin/env python3
"""Collect an unchanged SDK archive and its provenance metadata.

Collection verifies the source commit and archive selection. SDK identity,
functionality, ABI compatibility and symbol matching require separate tests.

Profiles may optionally declare a construction object with these fields:
  upstreamSharedRuntimeReused: required JSON boolean
  note: required nonempty string describing the construction evidence
  sharedComponents: optional string or null (defaults to build.sharedComponents)
  declaredUpstreamInputs: optional object (defaults to upstreamInputs)
Unknown construction fields are rejected. Omitting the object preserves the
original .NET 10 shared-runtime metadata. Collection records these declarations
without independently verifying how the components were constructed.

.NET 8 legacy source-build profiles must explicitly declare sourceOnly=true,
build.system="legacy-vmr-source-build", Release configuration, the dotnet/dotnet
repository, and construction metadata. Their SDK search is limited to the
matching artifacts/<architecture>/Release directory, excluding bootstrap inputs.

.NET 6 and .NET 7 generated source-build profiles use build.system=
"legacy-installer-source-build" and pin dotnet/installer instead. They require
--generated-source-dir and --generation-report. The report must declare the
installerCommit and sourceArchive {path, sha256, bytes}; collection verifies the
archive digest and the generated installer's Git metadata separately from the
installer checkout. Other profile modes reject these two arguments.

.NET 5 and Core 3.0/3.1 use "legacy-source-build-direct" with a supported
dotnet/source-build root commit, PortableBuild=true, explicit construction
metadata and legacySource {componentManifest, componentCommits}. Collection
verifies committed layout/manifest inputs and generated critical-component
revision metadata. The direct archive must contain the expected SDK and shared
framework versions and matching native ELF architecture. This identifies its
body; local framework construction/origin still requires separate verification.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET


class CollectionError(Exception):
    pass


DIRECT_SOURCE_CONTRACTS = {
    "5.0.214": {"commit": "d414ecb2d997a9b3f38aaaeddace30ca097e546d",
                "base": "artifacts", "properties": "Directory.Build.props", "runtimeVersion": "5.0.17",
                "components": ("runtime", "aspnetcore", "installer", "sdk")},
    "3.1.426": {"commit": "ab8b115b5658237ee8916ae3586600b39fb2fd19",
                "base": "artifacts", "properties": "Directory.Build.props", "runtimeVersion": "3.1.32",
                "components": ("coreclr", "corefx", "core-setup", "aspnetcore", "core-sdk", "sdk")},
    "3.0.103": {"commit": "40de72d1087a1d05dfd39c87f888a0611ec6c60f",
                "base": "bin", "properties": "dir.props", "runtimeVersion": "3.0.3",
                "components": ("coreclr", "corefx", "core-setup", "aspnetcore", "core-sdk", "sdk")},
}


def construction_metadata(profile):
    metadata = {
        "upstreamSharedRuntimeReused": True,
        "sharedComponents": profile["build"].get("sharedComponents"),
        "declaredUpstreamInputs": profile.get("upstreamInputs", {}),
        "note": "Shared runtime inputs are declared by the profile; they were not rebuilt from 1xx sources in this build.",
    }
    if "construction" not in profile:
        return metadata
    declared = profile["construction"]
    if not isinstance(declared, dict):
        raise CollectionError("Profile construction must be an object when present")
    unknown = set(declared) - set(metadata)
    if unknown:
        raise CollectionError("Unknown profile construction field(s): " + ", ".join(sorted(unknown)))
    if type(declared.get("upstreamSharedRuntimeReused")) is not bool:
        raise CollectionError("Profile construction.upstreamSharedRuntimeReused must be an explicit JSON boolean")
    note = declared.get("note")
    if not isinstance(note, str) or not note.strip():
        raise CollectionError("Profile construction.note must be a nonempty string")
    if "sharedComponents" in declared and declared["sharedComponents"] is not None and not isinstance(declared["sharedComponents"], str):
        raise CollectionError("Profile construction.sharedComponents must be a string or null")
    if "declaredUpstreamInputs" in declared and not isinstance(declared["declaredUpstreamInputs"], dict):
        raise CollectionError("Profile construction.declaredUpstreamInputs must be an object")
    metadata.update(declared)
    return metadata


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
        raise CollectionError("Cannot verify the source Git state: " + str(error)) from error


def contains_token(name, token):
    return re.search(r"(?<![A-Za-z0-9])" + re.escape(token) + r"(?![A-Za-z0-9])", name) is not None


def is_symbol_candidate(path):
    return (re.search(r"symbol|symstore|debuginfo|debugsymbols", path.name, re.IGNORECASE) is not None
            or path.suffix.lower() in {".pdb", ".dbg", ".debug"})


def legacy_source_build(profile):
    source_only = profile.get("build", {}).get("sourceOnly")
    system = profile.get("build", {}).get("system")
    if source_only is False:
        if system in {"legacy-vmr-source-build", "legacy-installer-source-build", "legacy-source-build-direct"}:
            raise CollectionError("Legacy source-build profiles must explicitly declare build.sourceOnly=true")
        return False
    if source_only is not True:
        raise CollectionError("Profile build.sourceOnly must be an explicit JSON boolean")
    systems = {
        "legacy-vmr-source-build": (("8.0.",), "https://github.com/dotnet/dotnet"),
        "legacy-installer-source-build": (("6.0.", "7.0."), "https://github.com/dotnet/installer"),
        "legacy-source-build-direct": (("5.0.", "3.1.", "3.0."), "https://github.com/dotnet/source-build"),
    }
    expected = systems.get(system)
    if (expected is None
            or not profile.get("sdkVersion", "").startswith(expected[0])
            or profile["build"].get("configuration") != "Release"
            or profile.get("source", {}).get("repository") not in {
                expected[1], expected[1] + ".git"}
            or "construction" not in profile):
        raise CollectionError("Source-only collection requires a supported explicit legacy Release build system, its pinned source repository, and construction metadata")
    if system == "legacy-source-build-direct":
        contract = DIRECT_SOURCE_CONTRACTS.get(profile["sdkVersion"])
        if (contract is None or profile.get("source", {}).get("commit") != contract["commit"]
                or profile["build"].get("portableBuild") is not True):
            raise CollectionError("Direct source-build collection requires its exact supported source commit and explicit PortableBuild=true")
    return True


def git_blob(source, commit, relative):
    try:
        return subprocess.run(["git", "-C", str(source), "show", commit + ":" + relative], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise CollectionError("Cannot read a pinned source Git blob: " + relative) from error


def fixed_source_path(root, relative, directory=False):
    path = root
    for part in Path(relative).parts:
        if part in {".", ".."} or Path(relative).is_absolute():
            raise CollectionError("Unsafe fixed source path")
        path = path / part
        if path.is_symlink():
            raise CollectionError("A fixed source path must not traverse symlinks: " + relative)
    if not (path.is_dir() if directory else path.is_file()):
        raise CollectionError("Missing fixed source input: " + relative)
    return path


def direct_source_metadata(source, profile, require_exports=True):
    version = profile["sdkVersion"]
    contract = DIRECT_SOURCE_CONTRACTS[version]
    commit = contract["commit"]
    if Path(git_output(source, "rev-parse", "--show-toplevel")).resolve() != source:
        raise CollectionError("Direct --source-dir must be the pinned source-build Git root")
    declared = profile.get("legacySource")
    if not isinstance(declared, dict) or declared.get("componentManifest") != "eng/Version.Details.xml":
        raise CollectionError("Direct profiles must declare legacySource.componentManifest=eng/Version.Details.xml")
    pins = declared.get("componentCommits")
    required = set(contract["components"])
    if not isinstance(pins, dict) or not required.issubset(pins):
        raise CollectionError("Direct profile critical component pins are incomplete")
    wrong_generation = {"coreclr", "corefx", "core-setup"} if version.startswith("5.") else {"runtime", "installer"}
    if wrong_generation.intersection(pins):
        raise CollectionError("Direct component provenance must match the unified .NET 5 or split Core 3.x source graph")
    if profile.get("upstreamInputs", {}).get("runtime") != contract["runtimeVersion"]:
        raise CollectionError("Direct profiles must declare the exact coordinated upstreamInputs.runtime version")
    relative = "eng/Version.Details.xml"
    manifest = fixed_source_path(source, relative)
    committed = git_blob(source, commit, relative)
    if manifest.read_bytes() != committed:
        raise CollectionError("Direct dependency manifest differs from the pinned Git object")
    try:
        dependency_root = ET.fromstring(committed)
    except ET.ParseError as error:
        raise CollectionError("Cannot parse the pinned direct dependency manifest") from error
    repositories = {}
    for entry in dependency_root.iter():
        if entry.tag.rsplit("}", 1)[-1] != "Dependency":
            continue
        fields = {child.tag.rsplit("}", 1)[-1]: child.text or "" for child in entry}
        url, sha = fields.get("Uri", ""), fields.get("Sha", "")
        if not re.fullmatch(r"[0-9a-f]{40}", sha) or not re.fullmatch(r"https://github\.com/[^/]+/[^/]+", url):
            raise CollectionError("Every pinned direct dependency must have a public GitHub URI and exact SHA")
        name = url.rstrip("/").rsplit("/", 1)[-1]
        name = name[:-4] if name.endswith(".git") else name
        repositories.setdefault(name.lower(), []).append({"repository": url, "commit": sha, "basename": name})
    properties_bytes = git_blob(source, commit, contract["properties"])
    properties = ET.fromstring(properties_bytes)
    expected = {"OutputPath": "$(BaseOutputPath)$(Platform)/$(Configuration)/",
                "ClonedSubmoduleDirectory": "$(BaseOutputPath)src/",
                "GitInfoOutputDir": "$(BaseOutputPath)git-info/",
                "BaseOutputPath": "$(ProjectDir)bin/" if contract["base"] == "bin" else "$(ArtifactsDir)"}
    for name, value in expected.items():
        matches = [element.text or "" for element in properties.iter() if element.tag.rsplit("}", 1)[-1] == name]
        if matches != [value]:
            raise CollectionError("The pinned direct output/source layout differs for " + name)
    if contract["base"] == "artifacts":
        matches = [element.text or "" for element in properties.iter() if element.tag.rsplit("}", 1)[-1] == "ArtifactsDir"]
        if matches != ["$(ProjectDir)artifacts/"]:
            raise CollectionError("The direct artifacts base differs from its pinned contract")
    critical, validated_pins = {}, {}
    for name, value in pins.items():
        if not isinstance(name, str) or not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
            raise CollectionError("Direct component pins must be exact named SHA strings")
        matches = [item for item in repositories.get(name.lower(), []) if item["commit"] == value]
        unique = {(item["repository"], item["commit"]) for item in matches}
        if len(unique) != 1:
            raise CollectionError("A direct component pin does not uniquely match the committed manifest: " + name)
        validated_pins[name] = value
        if name not in required:
            continue
        repository = matches[0]
        export_relative = contract["base"] + "/src/" + repository["basename"] + "." + value
        metadata_relative = contract["base"] + "/git-info/" + name + ".props"
        if not require_exports:
            critical[name] = {"repository": repository["repository"], "commit": value,
                              "exportRoot": export_relative, "gitInfo": metadata_relative,
                              "generatedMetadataVerification": "deferred-to-normal-collection"}
            continue
        export = fixed_source_path(source, export_relative, directory=True)
        head = fixed_source_path(export, ".git/HEAD")
        if head.read_text().strip() != value:
            raise CollectionError("A direct critical component export has another commit marker: " + name)
        metadata = fixed_source_path(source, metadata_relative)
        values = [element.text or "" for element in ET.parse(metadata).getroot().iter()
                  if element.tag.rsplit("}", 1)[-1] == "GitCommitHash"]
        if values != [value]:
            raise CollectionError("Generated direct component revision metadata differs: " + name)
        critical[name] = {"repository": repository["repository"], "commit": value,
                          "exportRoot": export_relative, "gitInfo": file_record(metadata, source)}
    result = {"root": str(source), "sourceCommit": commit, "manifest": file_record(manifest, source),
            "committedLayout": {"path": contract["properties"], "sha256": hashlib.sha256(properties_bytes).hexdigest(),
                                "artifactBase": contract["base"]},
            "declaredComponentCommits": validated_pins, "criticalComponents": critical,
            "scope": "Pinned direct root, unchanged dependency manifest, committed output layout and critical export/revision metadata. These checks do not attest successful local framework construction or an unchanged current component tree."}
    if not require_exports:
        result["generatedComponentMetadataDeferred"] = True
        result["scope"] = "Early reuse of the normal collector's exact runtime, dependency-pin and committed-layout contract. Generated critical exports/revision metadata remain mandatory during normal collection; no product build or SDK qualification is claimed."
    return result


def direct_archive_identity(archive, version, rid):
    runtime = DIRECT_SOURCE_CONTRACTS[version]["runtimeVersion"]
    expected_machine = {"linux-arm64": 183, "linux-x64": 62}[rid]
    prefix = "sdk/" + version + "/"
    native_paths = {"dotnet", "host/fxr/" + runtime + "/libhostfxr.so",
                    "shared/Microsoft.NETCore.App/" + runtime + "/libcoreclr.so"}
    required_files = native_paths | {prefix + "dotnet.dll", prefix + "MSBuild.dll", prefix + ".version",
        "shared/Microsoft.NETCore.App/" + runtime + "/System.Private.CoreLib.dll",
        "shared/Microsoft.NETCore.App/" + runtime + "/Microsoft.NETCore.App.deps.json",
        "shared/Microsoft.AspNetCore.App/" + runtime + "/Microsoft.AspNetCore.App.deps.json"}
    seen, files, machines = set(), set(), {}
    versions = {"sdk": set(), "Microsoft.NETCore.App": set(), "Microsoft.AspNetCore.App": set()}
    version_file, count, total = None, 0, 0
    try:
        with tarfile.open(archive, "r|gz") as bundle:
            for member in bundle:
                count += 1; total += max(0, member.size)
                if count > 200000 or total > 16 * 1024 ** 3:
                    raise CollectionError("The direct SDK archive exceeds bounded inspection limits")
                name = member.name
                while name.startswith("./"):
                    name = name[2:]
                path = PurePosixPath(name)
                if not name or name == ".":
                    if member.isdir():
                        continue
                    raise CollectionError("Invalid empty direct SDK archive entry")
                if path.is_absolute() or ".." in path.parts or "\\" in name:
                    raise CollectionError("Unsafe direct SDK archive member path")
                normalized = path.as_posix()
                if normalized in seen:
                    raise CollectionError("Duplicate direct SDK archive member: " + normalized)
                seen.add(normalized)
                if (len(path.parts) >= 2 and path.parts[0] == "sdk"
                        and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", path.parts[1])):
                    versions["sdk"].add(path.parts[1])
                if len(path.parts) >= 3 and path.parts[0] == "shared" and path.parts[1] in versions:
                    versions[path.parts[1]].add(path.parts[2])
                if not member.isfile():
                    continue
                files.add(normalized)
                if normalized in native_paths:
                    stream = bundle.extractfile(member)
                    header = stream.read(20) if stream else b""
                    if (len(header) != 20 or header[:4] != b"\x7fELF" or header[4:6] != b"\x02\x01"
                            or int.from_bytes(header[18:20], "little") != expected_machine):
                        raise CollectionError("The direct SDK contains an unexpected native ELF architecture: " + normalized)
                    machines[normalized] = {"class": 64, "endianness": "little", "machine": expected_machine}
                if normalized == prefix + ".version":
                    if member.size > 65536:
                        raise CollectionError("The direct SDK version marker is unexpectedly large")
                    stream = bundle.extractfile(member)
                    data = stream.read() if stream else b""
                    if version not in data.decode("utf-8-sig").splitlines():
                        raise CollectionError("The direct SDK version marker does not contain the selected exact SDK version")
                    version_file = {"path": normalized, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    except (tarfile.TarError, OSError, EOFError, UnicodeError) as error:
        raise CollectionError("Cannot inspect the direct SDK archive body: " + str(error)) from error
    if not required_files.issubset(files):
        raise CollectionError("The direct archive is missing required SDK/framework files: " + ", ".join(sorted(required_files - files)))
    if versions != {"sdk": {version}, "Microsoft.NETCore.App": {runtime}, "Microsoft.AspNetCore.App": {runtime}}:
        raise CollectionError("The direct SDK/framework version directories differ from the coordinated source graph")
    return {"sdkVersion": version, "runtimeVersion": runtime, "targetRid": rid, "elfHeaders": machines,
            "sdkVersionFile": version_file, "archiveMembers": count,
            "versionDirectories": {key: sorted(value) for key, value in versions.items()},
            "scope": "Archive member identity and native ELF headers only. Framework origins, ABI compatibility and functionality require separate verification."}


def generated_source_metadata(source, generated_path, report_path, commit):
    if generated_path is None or report_path is None:
        raise CollectionError(".NET 6/7 collection requires --generated-source-dir and --generation-report")
    if generated_path.is_symlink() or not generated_path.is_dir():
        raise CollectionError("Generated source root must be an existing directory, not a symlink")
    generated = generated_path.resolve(strict=True)
    if generated == source:
        raise CollectionError("Generated source root must differ from the installer Git checkout")
    if Path(git_output(source, "rev-parse", "--show-toplevel")).resolve() != source:
        raise CollectionError("--source-dir must be the pinned installer Git checkout root")

    git_info = generated / "git-info"
    installer = generated / "src" / "installer"
    for directory in (git_info, generated / "src", installer):
        if directory.is_symlink() or not directory.is_dir():
            raise CollectionError("Generated source directory is absent or a symlink: " + str(directory))
    metadata_files = (git_info / "installer.props", git_info / "AllRepoVersions.props")
    for path, property_name in zip(metadata_files, ("GitCommitHash", "installerGitCommitHash")):
        if path.is_symlink() or not path.is_file():
            raise CollectionError("Generated Git metadata must be a regular file: " + str(path))
        try:
            values = [element.text or "" for element in ET.parse(path).getroot().iter(property_name)]
        except ET.ParseError as error:
            raise CollectionError("Cannot parse generated Git metadata: " + str(path)) from error
        if len(values) != 1 or values[0].strip().lower() != commit.lower():
            raise CollectionError("Generated " + property_name + " does not uniquely match the pinned installer commit")

    # Upstream normally removes Git objects while retaining lightweight metadata.
    # If generation preserved a usable repository, verify its own HEAD and root;
    # never allow Git discovery to substitute an enclosing checkout.
    installer_git = installer / ".git"
    git_head_verified = False
    if installer_git.exists() or installer_git.is_symlink():
        if installer_git.is_symlink() or not installer_git.is_dir():
            raise CollectionError("Generated installer .git must be a directory, not a symlink or Git indirection file")
        objects = installer_git / "objects"
        if objects.exists() or objects.is_symlink():
            if objects.is_symlink() or not objects.is_dir():
                raise CollectionError("Generated installer Git objects must be a directory, not a symlink")
            if Path(git_output(installer, "rev-parse", "--show-toplevel")).resolve() != installer:
                raise CollectionError("Generated installer Git root does not match src/installer")
            if git_output(installer, "rev-parse", "HEAD").lower() != commit.lower():
                raise CollectionError("Generated installer HEAD does not match the pinned installer commit")
            git_head_verified = True

    if report_path.is_symlink() or not report_path.is_file():
        raise CollectionError("Generation report must be an existing regular JSON file, not a symlink")
    report_path = report_path.resolve(strict=True)
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes.decode("utf-8-sig"))
    if (not isinstance(report, dict) or not isinstance(report.get("installerCommit"), str)
            or report["installerCommit"].lower() != commit.lower()):
        raise CollectionError("Generation report installerCommit must match the pinned installer commit")
    archive_record = report.get("sourceArchive")
    if (not isinstance(archive_record, dict)
            or not isinstance(archive_record.get("path"), str)
            or not isinstance(archive_record.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-fA-F]{64}", archive_record["sha256"])
            or type(archive_record.get("bytes")) is not int or archive_record["bytes"] <= 0):
        raise CollectionError("Generation report sourceArchive must declare path, SHA-256 and positive integer bytes")
    archive = Path(archive_record["path"])
    if not archive.is_absolute() or archive.is_symlink() or not archive.is_file() or not archive.name.endswith(".tar.gz"):
        raise CollectionError("Generation sourceArchive.path must name an existing absolute regular .tar.gz file")
    archive = archive.resolve(strict=True)
    actual_digest = digest_file(archive)
    if (actual_digest["sha256"] != archive_record["sha256"].lower()
            or actual_digest["bytes"] != archive_record["bytes"]):
        raise CollectionError("Generation source archive differs from the report digest or byte count")
    return generated, {
        "root": str(generated),
        "installerCommit": commit.lower(),
        "installerGitHeadVerified": git_head_verified,
        "installerGitMetadata": "preserved repository" if git_head_verified else "Git objects absent; commit verified from generated props",
        "gitInfoFiles": [file_record(path, generated) for path in regular_files(git_info)],
        "sourceArchive": {"path": str(archive), **actual_digest, "digestVerified": True},
        "generationReport": {"path": str(report_path), "bytes": len(report_bytes),
                             "sha256": hashlib.sha256(report_bytes).hexdigest(),
                             "sha512": hashlib.sha512(report_bytes).hexdigest(), "contents": report},
        "scope": "Installer revision, generated Git metadata and declared source archive integrity. This does not prove an unchanged generated tree or byte-for-byte build reproducibility.",
    }


def select_sdk(source, version, rid, legacy=False, release_base="artifacts", exact_name=False):
    if legacy:
        architecture = rid.rsplit("-", 1)[1]
        release_root = source / release_base / architecture / "Release"
        roots = [release_root]
    else:
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
                    and (not exact_name or path.name == "dotnet-sdk-" + version + "-" + rid + ".tar.gz")
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
    if not isinstance(profile, dict):
        raise CollectionError("Profile must contain a JSON object")
    version = profile.get("sdkVersion", "")
    rid = profile.get("target", {}).get("rid", "")
    commit = profile.get("source", {}).get("commit", "")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", version):
        raise CollectionError("Profile must declare a valid sdkVersion")
    if not re.fullmatch(r"linux-(?:arm64|x64)", rid):
        raise CollectionError("Profile target RID must be linux-arm64 or linux-x64")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        raise CollectionError("Profile must pin a full source commit SHA")
    legacy = legacy_source_build(profile)
    installer_source_build = legacy and profile["build"].get("system") == "legacy-installer-source-build"
    direct_source_build = legacy and profile["build"].get("system") == "legacy-source-build-direct"
    if version.startswith(("6.0.", "7.0.")) and not installer_source_build:
        raise CollectionError(".NET 6/7 collection requires an explicit legacy-installer-source-build profile")
    if version.startswith(("5.0.", "3.1.", "3.0.")) and not direct_source_build:
        raise CollectionError(".NET 5/Core 3.x collection requires an explicit legacy-source-build-direct profile")
    generated_path = getattr(args, "generated_source_dir", None)
    generation_report = getattr(args, "generation_report", None)
    if not installer_source_build and (generated_path is not None or generation_report is not None):
        raise CollectionError("--generated-source-dir and --generation-report are only valid for .NET 6/7 legacy-installer-source-build")
    construction = construction_metadata(profile)
    actual_commit = git_output(source, "rev-parse", "HEAD").lower()
    if actual_commit != commit.lower():
        raise CollectionError("Source HEAD does not match the profile commit")
    worktree_status = git_output(source, "status", "--porcelain", "--untracked-files=no")

    artifact_source = source
    generated_metadata = None
    direct_metadata = None
    if installer_source_build:
        artifact_source, generated_metadata = generated_source_metadata(source, generated_path, generation_report, commit)
        directory = artifact_source
        for part in ("artifacts", rid.rsplit("-", 1)[1], "Release"):
            directory = directory / part
            if directory.is_symlink():
                raise CollectionError("Generated SDK output directories must not be symlinks: " + str(directory))
    if direct_source_build:
        if args.source_dir.is_symlink():
            raise CollectionError("The direct source root must not be a symlink")
        try:
            direct_metadata = direct_source_metadata(source, profile)
        except ET.ParseError as error:
            raise CollectionError("Cannot parse direct source layout/revision metadata") from error
        directory = artifact_source
        for part in (DIRECT_SOURCE_CONTRACTS[version]["base"], rid.rsplit("-", 1)[1], "Release"):
            directory = directory / part
            if directory.is_symlink():
                raise CollectionError("Direct SDK output directories must not be symlinks")
    sdk, candidates, release_root = select_sdk(artifact_source, version, rid, legacy,
        release_base=DIRECT_SOURCE_CONTRACTS[version]["base"] if direct_source_build else "artifacts",
        exact_name=direct_source_build)
    if output == release_root or release_root in output.parents:
        raise CollectionError("Output directory must be outside the upstream artifact search directory")
    expected_digest = {key: candidates[0][key] for key in ("bytes", "sha256", "sha512")}
    archive_identity = None
    if direct_source_build:
        archive_identity = direct_archive_identity(sdk, version, rid)
        if digest_file(sdk) != expected_digest:
            raise CollectionError("Direct SDK archive changed during body inspection")
    filename = "cbodotnet-sdk-" + version + "-" + rid + "-build." + args.build_revision + ".tar.gz"

    project = Path(__file__).resolve().parent.parent
    rebuild_files = (regular_files(project / "scripts") + regular_files(project / "containers")
                     + regular_files(project / "patches"))
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
            symbols.append(file_record(path, artifact_source, include_hashes=False))
        if (path.suffix.lower() in {".deb", ".rpm"}
                and any(contains_token(path.name, value) for value in versions)
                and any(contains_token(path.name, value) for value in architecture_names)):
            packages.append(file_record(path, artifact_source))

    manifest = {
        "schemaVersion": 1,
        "collectedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "collected; SDK verification is separate",
        "sdkVersion": version,
        "targetRid": rid,
        "buildRevision": args.build_revision,
        "sourceOnly": profile["build"]["sourceOnly"],
        "source": {
            "repository": profile["source"].get("repository"),
            "tag": profile["source"].get("tag"),
            "expectedCommit": commit.lower(),
            "actualCommit": actual_commit,
            "commitVerified": True,
            "worktreeDirty": bool(worktree_status),
            "trackedChangeCount": len(worktree_status.splitlines()) if worktree_status else 0,
        },
        "construction": construction,
        "buildImage": {"id": args.build_image_id.lower(), "baseImage": profile.get("container", {})},
        "profile": {"path": str(profile_path), **profile_hash, "contents": profile},
        "rebuildInputs": inputs,
        "sdkArchive": {
            "path": filename, **expected_digest,
            "upstreamPath": sdk.relative_to(artifact_source).as_posix(),
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
    if legacy:
        manifest["buildSystem"] = profile["build"]["system"]
        manifest["sdkArchive"]["searchRoot"] = release_root.relative_to(artifact_source).as_posix()
    if generated_metadata is not None:
        manifest["generatedSource"] = generated_metadata
        manifest["sdkArchive"]["upstreamRoot"] = str(artifact_source)
    if direct_metadata is not None:
        manifest["directSource"] = direct_metadata
        manifest["sdkArchive"]["bodyIdentity"] = archive_identity
        manifest["sdkArchive"]["identityCheck"] = "Expected SDK/framework version paths, SDK version marker and native ELF architecture matched; local component origins, functionality and ABI verification are separate."

    output.mkdir(parents=True, exist_ok=True)
    copy_unchanged(sdk, output / filename, expected_digest)
    atomic_text(output / "SHA256SUMS", expected_digest["sha256"] + "  " + filename + "\n")
    atomic_text(output / "SHA512SUMS", expected_digest["sha512"] + "  " + filename + "\n")
    atomic_text(output / "build-manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"archive": str(output / filename), **expected_digest,
                      "manifest": str(output / "build-manifest.json")}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--generated-source-dir", type=Path,
                        help=".NET 6/7 only: generated source tree containing git-info and artifacts/<architecture>/Release")
    parser.add_argument("--generation-report", type=Path,
                        help=".NET 6/7 only: generation JSON declaring installerCommit and sourceArchive {path, sha256, bytes}")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True,
                        help="Pinned JSON build profile, optionally including construction declarations described above")
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
