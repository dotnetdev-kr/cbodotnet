#!/usr/bin/env python3
"""Prepare and verify the private .NET Core 3.0 source-build bootstrap tools.

The original SDK/PSB archives and pinned root global.json remain unchanged.
Only the upstream SDK resolver is built; no SDK product graph is executed.
Requires native Linux ARM64 and Python 3.6 or newer.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shlex
import stat
import subprocess
import tarfile
import tempfile
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile


OWNER = "cbodotnet-core30-bootstrap-v1"
SOURCE_COMMIT = "40de72d1087a1d05dfd39c87f888a0611ec6c60f"
SDK_VERSION = "3.0.100"
SDK_NAME = "dotnet-sdk-3.0.100-linux-arm64.tar.gz"
SDK_URL = "https://builds.dotnet.microsoft.com/dotnet/Sdk/3.0.100/" + SDK_NAME
SDK_SHA512 = "18c3bc07c4486381f54d4b40eb8401bf56c14fef5febc4639e3134d74ce66172d1e66c2dea9684ad727f08e9dd7e89d74535a8642fb2a2203445483293f3b3c3"
PSB_NAME = "Private.SourceBuilt.Artifacts.0.1.0-3.0.100.tar.gz"
PSB_BYTES = 469688508
PSB_SHA256 = "e8542ab2d6c4383b8c2aee8cdb86cd1952a542f8633df57082054bf48588a09b"
ARCADE_VERSION = "1.0.0-beta.19381.1"
ARCADE_COMMIT = "8f3c22397990aeb20a88690b51dad4b33f21e7ff"
ARCADE_NAME = "Microsoft.DotNet.Arcade.Sdk." + ARCADE_VERSION + ".nupkg"
ARCADE_BYTES = 149380
ARCADE_SHA256 = "1dd51e1be96cc1c95697fca77467d92a7c17906661d6be910e20b2e1f60da70f"
RESOLVER = "SourceBuild.MSBuildSdkResolver"
TASK_ASSEMBLY = "Microsoft.DotNet.SourceBuild.Tasks.XPlat"
RESOLVER_PROJECT = "tools-local/tasks/" + TASK_ASSEMBLY + "/" + TASK_ASSEMBLY + ".csproj"
SOURCE_FILES = ["global.json", "eng/Version.Details.xml", "eng/common/tools.sh",
                "Directory.Build.props", "Directory.Build.targets", "dir.props",
                RESOLVER_PROJECT,
                "tools-local/tasks/" + TASK_ASSEMBLY + "/SourceBuiltSdkResolver.cs"]


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def fingerprint(path):
    sha256, sha512, size = hashlib.sha256(), hashlib.sha512(), 0
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            sha256.update(data)
            sha512.update(data)
            size += len(data)
    return {"bytes": size, "sha256": sha256.hexdigest(), "sha512": sha512.hexdigest()}


def write_json(path, value):
    with path.open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")


def identical_or_new(path, contents):
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != contents:
            raise ValueError("Refusing an unknown or different existing input: " + str(path))
    else:
        with path.open("xb") as output:
            output.write(contents)


def contained(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def directory(value, create=False):
    path = Path(value)
    if not path.is_absolute() or path == Path(path.anchor):
        raise ValueError("Absolute directories below the filesystem root are required")
    for candidate in [path] + list(path.parents):
        if candidate.is_symlink():
            raise ValueError("A control directory or ancestor is a symlink: " + str(candidate))
    if create:
        path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError("An ordinary directory is required: " + str(path))
    return path.resolve(strict=True)


def ordinary_file(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("An ordinary file is required: " + str(path))
    directory(path.parent)
    return path


def git(root, *arguments):
    command = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(root)] + list(arguments)
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise ValueError("Source identity Git check failed: " + result.stderr.decode("utf-8", "replace")[-4000:])
    return result.stdout


def identity(source, profile_path):
    profile = json.loads(ordinary_file(profile_path).read_text(encoding="utf-8"))
    if (profile.get("sdkVersion") != "3.0.103" or
            profile.get("source", {}).get("commit") != SOURCE_COMMIT or
            profile["source"].get("repository") != "https://github.com/dotnet/source-build"):
        raise ValueError("The profile must select the pinned .NET Core 3.0.103 source-build graph")
    if Path(git(source, "rev-parse", "--show-toplevel").decode().strip()).resolve() != source:
        raise ValueError("The source directory is not the Git top level")
    if git(source, "rev-parse", "HEAD").decode().strip() != SOURCE_COMMIT:
        raise ValueError("The source-build checkout does not match the pinned commit")
    records = []
    for relative in SOURCE_FILES:
        path = ordinary_file(source / relative)
        original = git(source, "show", SOURCE_COMMIT + ":" + relative)
        if path.read_bytes() != original:
            raise ValueError("Pinned bootstrap source differs from its Git object: " + relative)
        records.append(dict({"path": relative}, **fingerprint(path)))
    global_json = json.loads((source / "global.json").read_text(encoding="utf-8"))
    if (global_json["tools"]["dotnet"] != SDK_VERSION or
            global_json["msbuild-sdks"]["Microsoft.DotNet.Arcade.Sdk"] != "1.0.0-beta.19359.6"):
        raise ValueError("The original bootstrap SDK/Arcade declarations are unexpected")
    manifest = ET.parse(str(source / "eng/Version.Details.xml")).getroot()
    arcade = manifest.find("./ToolsetDependencies/Dependency[@Name='Microsoft.DotNet.Arcade.Sdk']")
    if (arcade is None or arcade.findtext("Sha") != "ce459ae07c3d7a1e68251268855e0bc7b3d97f75" or
            arcade.get("Version") != "1.0.0-beta.19463.3"):
        raise ValueError("The current manifest does not pin the original product Arcade source")
    return records


def safe_name(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name:
        raise ValueError("Unsafe archive member path: " + name)
    return str(path)


def source_inventory(root, output):
    count, total = 0, 0
    with output.open("x", encoding="utf-8") as stream:
        for current, directories, files in os.walk(str(root), followlinks=False):
            directories.sort()
            files.sort()
            links = [name for name in directories if (Path(current) / name).is_symlink()]
            for name in links:
                directories.remove(name)
            for name in sorted(files + links):
                path = Path(current) / name
                mode = path.lstat().st_mode
                row = {"path": path.relative_to(root).as_posix(), "mode": oct(stat.S_IMODE(mode))}
                if stat.S_ISLNK(mode):
                    row.update({"kind": "symlink", "target": os.readlink(str(path))})
                elif stat.S_ISREG(mode):
                    row.update(fingerprint(path))
                    row["kind"] = "file"
                    total += row["bytes"]
                else:
                    raise ValueError("Unexpected bootstrap filesystem entry")
                stream.write(json.dumps(row, sort_keys=True) + "\n")
                count += 1
    return dict({"path": str(output), "entries": count, "fileBytes": total}, **fingerprint(output))


def extract_sdk(archive, stage):
    seen = set()
    with tarfile.open(str(archive), "r:gz") as stream:
        for member in stream:
            name = safe_name(member.name)
            if name == "." and member.isdir():
                continue
            if name in seen:
                raise ValueError("Repeated SDK archive member: " + name)
            seen.add(name)
            target = stage / name
            for parent in target.parents:
                if parent == stage:
                    break
                if parent.is_symlink():
                    raise ValueError("SDK archive member traverses a symbolic link")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with stream.extractfile(member) as original, target.open("xb") as output:
                    for block in iter(lambda: original.read(1024 * 1024), b""):
                        output.write(block)
                os.chmod(str(target), member.mode & 0o777)
            elif member.issym():
                link = PurePosixPath(member.linkname)
                if link.is_absolute() or not contained((target.parent / member.linkname).resolve(), stage):
                    raise ValueError("The SDK archive link escapes its private tree")
                target.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(member.linkname, str(target))
            else:
                raise ValueError("Unsupported SDK archive member type: " + name)
    if "dotnet" not in seen or "sdk/3.0.100/MSBuild.dll" not in seen:
        raise ValueError("The SDK archive lacks the pinned driver and SDK")


def official_sdk_archive(inputs):
    cache = directory(inputs / "official-sdk", create=True)
    target = cache / SDK_NAME
    if not target.exists() and not target.is_symlink():
        descriptor, temporary = tempfile.mkstemp(prefix=".core30-sdk-download-", dir=str(cache))
        os.close(descriptor)
        staged = Path(temporary)
        try:
            with urllib.request.urlopen(SDK_URL, timeout=120) as response, staged.open("wb") as output:
                if not response.geturl().startswith("https://"):
                    raise ValueError("The official SDK URL redirected outside HTTPS")
                size = 0
                for data in iter(lambda: response.read(1024 * 1024), b""):
                    size += len(data)
                    if size > 1024 * 1024 * 1024:
                        raise ValueError("The SDK download exceeds the input size bound")
                    output.write(data)
            if fingerprint(staged)["sha512"] != SDK_SHA512:
                raise ValueError("The downloaded SDK differs from official release metadata")
            try:
                os.link(str(staged), str(target))
            except FileExistsError:
                pass
        finally:
            staged.unlink()
    record = fingerprint(ordinary_file(target))
    if record["sha512"] != SDK_SHA512:
        raise ValueError("The retained SDK archive differs from official release metadata")
    return target, record


def retained_arcade(inputs, state):
    archive = ordinary_file(inputs / PSB_NAME)
    archive_info = fingerprint(archive)
    if archive_info["bytes"] != PSB_BYTES or archive_info["sha256"] != PSB_SHA256:
        raise ValueError("The original PSB archive differs from the pinned retained input")
    packages = directory(inputs / "bootstrap-packages", create=True)
    selected = packages / ARCADE_NAME
    if not selected.exists() and not selected.is_symlink():
        with tarfile.open(str(archive), "r|gz") as source:
            for member in source:
                if member.name == ARCADE_NAME:
                    if not member.isfile() or member.size != ARCADE_BYTES:
                        raise ValueError("Unexpected retained Arcade archive member")
                    data = source.extractfile(member).read()
                    if hashlib.sha256(data).hexdigest() != ARCADE_SHA256:
                        raise ValueError("The retained Arcade member hash does not match")
                    identical_or_new(selected, data)
                    break
            else:
                raise ValueError("The exact retained Arcade package is absent")
    package_info = fingerprint(ordinary_file(selected))
    if package_info["bytes"] != ARCADE_BYTES or package_info["sha256"] != ARCADE_SHA256:
        raise ValueError("The selected Arcade package differs from the retained member")
    destination = packages / "microsoft.dotnet.arcade.sdk" / ARCADE_VERSION
    receipt = state / "arcade-package.json"
    if destination.exists() or destination.is_symlink():
        directory(destination)
        if not receipt.is_file() or receipt.is_symlink():
            raise ValueError("Refusing an unrecognized existing Arcade package directory")
        previous = json.loads(receipt.read_text(encoding="utf-8"))
        if previous.get("package") != package_info or previous.get("destination") != str(destination):
            raise ValueError("Existing Arcade package identity differs")
        rows = previous["members"]
        actual = []
        for current, directories, files in os.walk(str(destination)):
            if any((Path(current) / name).is_symlink() for name in directories):
                raise ValueError("An extracted Arcade package directory is a symbolic link")
            for name in files:
                path = ordinary_file(Path(current) / name)
                actual.append(path.relative_to(destination).as_posix())
        if set(actual) != set(item["path"] for item in rows):
            raise ValueError("Existing Arcade package membership differs")
        for row in rows:
            if fingerprint(ordinary_file(destination / row["path"])) != row["fingerprint"]:
                raise ValueError("An extracted Arcade package file changed")
        return destination, selected, package_info, archive_info
    stage = directory(packages / (".arcade-stage-" + uuid.uuid4().hex), create=True)
    members, seen = [], set()
    with zipfile.ZipFile(str(selected)) as package:
        nuspec = ET.fromstring(package.read("Microsoft.DotNet.Arcade.Sdk.nuspec"))
        namespace = {"n": "http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd"}
        repository = nuspec.find("n:metadata/n:repository", namespace)
        if (nuspec.findtext("n:metadata/n:id", namespaces=namespace) != "Microsoft.DotNet.Arcade.Sdk" or
                nuspec.findtext("n:metadata/n:version", namespaces=namespace) != ARCADE_VERSION or
                repository is None or repository.get("commit") != ARCADE_COMMIT):
            raise ValueError("The retained Arcade nuspec does not match the pinned source")
        for entry in package.infolist():
            name = safe_name(entry.filename)
            if name in seen or stat.S_ISLNK(entry.external_attr >> 16):
                raise ValueError("Repeated or linked Arcade package member")
            seen.add(name)
            target = stage / name
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as output:
                    output.write(package.read(entry))
                members.append({"path": name, "fingerprint": fingerprint(target)})
    required = ["sdk/Sdk.props", "sdk/Sdk.targets", "tools/Build.proj", "tools/netcoreapp2.1/Microsoft.DotNet.Arcade.Sdk.dll"]
    if any(item not in seen for item in required):
        raise ValueError("The retained Arcade package lacks the required actual tool layout")
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage.rename(destination)
    write_json(receipt, {"package": package_info, "destination": str(destination), "members": members,
                         "sourceCommit": ARCADE_COMMIT, "recordedAtUtc": now()})
    return destination, selected, package_info, archive_info


def sdk_tree(source, inputs, state, archive, archive_info):
    # This root predates --with-sdk and hardcodes .dotnet for its alternate
    # targets. The original SDK is installed at that required ordinary path.
    destination = source / ".dotnet"
    receipt = state / "sdk-tree.json"
    if destination.exists() or destination.is_symlink():
        directory(destination)
        if not receipt.is_file() or receipt.is_symlink():
            raise ValueError("Refusing an unrecognized existing SDK working directory")
        previous = json.loads(receipt.read_text(encoding="utf-8"))
        if previous.get("archive") != archive_info or previous.get("destination") != str(destination):
            raise ValueError("The SDK working directory has a different input identity")
        initial = previous["initialInventory"]
        if fingerprint(ordinary_file(Path(initial["path"]))) != {key: initial[key] for key in ("bytes", "sha256", "sha512")}:
            raise ValueError("The initial SDK inventory is missing or changed")
    else:
        stage = directory(source / (".core30-sdk-stage-" + uuid.uuid4().hex), create=True)
        extract_sdk(archive, stage)
        initial = source_inventory(stage, state / "sdk-original-members.jsonl")
        original_files = []
        for relative in ["dotnet", "sdk/" + SDK_VERSION + "/MSBuild.dll", "sdk/" + SDK_VERSION + "/MSBuild.runtimeconfig.json",
                         "sdk/" + SDK_VERSION + "/Sdks/Microsoft.NET.Sdk/Sdk/Sdk.props",
                         "sdk/" + SDK_VERSION + "/Sdks/Microsoft.NET.Sdk/Sdk/Sdk.targets"]:
            original_files.append({"path": relative, "fingerprint": fingerprint(ordinary_file(stage / relative))})
        stage.rename(destination)
        previous = {"archive": archive_info, "destination": str(destination), "initialInventory": initial,
                    "originalStableFiles": original_files,
                    "recordedAtUtc": now(), "scope": "Initial official SDK extraction. The working copy subsequently gains the upstream source-built resolver and may be updated by the upstream product build."}
        write_json(receipt, previous)
    return destination, previous


def run(arguments, cwd, environment, log, commands):
    record = {"arguments": [str(item) for item in arguments], "workingDirectory": str(cwd), "startedAtUtc": now(), "log": str(log)}
    commands.append(record)
    print("Running bootstrap step: " + log.name, flush=True)
    with log.open("xb") as output:
        result = subprocess.run(record["arguments"], cwd=str(cwd), env=environment, stdout=output, stderr=subprocess.STDOUT)
    record.update({"exitCode": result.returncode, "finishedAtUtc": now(), "logFingerprint": fingerprint(log)})
    if result.returncode:
        raise ValueError("Bootstrap command failed; inspect " + str(log))


def environment_contract(source, inputs, sdk, arcade):
    home = directory(inputs / "bootstrap-home", create=True)
    runtime = directory(inputs / "bootstrap-state/runtime", create=True)
    os.chmod(str(runtime), 0o700)
    environment = {
        "HOME": str(home), "DOTNET_CLI_HOME": str(home), "XDG_RUNTIME_DIR": str(runtime),
        "DOTNET_INSTALL_DIR": str(sdk), "DotNetCoreSdkDir": str(sdk), "SDK_VERSION": SDK_VERSION,
        "DOTNET_MULTILEVEL_LOOKUP": "0", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1", "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        "DOTNET_NOLOGO": "1", "NUGET_PACKAGES": str(source / "packages/restored"),
        "BUILD_SOURCEVERSION": SOURCE_COMMIT,
        "SOURCE_BUILT_SDK_ID_ARCADE": "Microsoft.DotNet.Arcade.Sdk",
        "SOURCE_BUILT_SDK_VERSION_ARCADE": ARCADE_VERSION, "SOURCE_BUILT_SDK_DIR_ARCADE": str(arcade),
        "_InitializeToolset": str(arcade / "tools/Build.proj"),
    }
    return {"schemaVersion": 1, "owner": OWNER, "sourceRoot": str(source), "sourceCommit": SOURCE_COMMIT,
            "environment": environment, "buildScriptArguments": [],
            "msbuildArguments": ["/p:ArcadeBootstrapVersion=" + ARCADE_VERSION,
                                 "/p:ArcadeBootstrapDir=" + str(inputs / "bootstrap-packages") + "/"],
            "rootPipelineLoggerEnvironment": {"_InitializeBuildTool": str(sdk / "dotnet"),
                                               "_InitializeBuildToolCommand": "msbuild", "_InitializeBuildToolFramework": "netcoreapp2.1"},
            "rootPipelineLoggerPolicy": "Apply the additional logger environment only when root CI/pipeline logging is enabled. It selects the retained netcoreapp2.1 task assembly.",
            "retainedArcadeSelection": {"originalGlobalVersion": "1.0.0-beta.19359.6",
                                       "originalManifestVersion": "1.0.0-beta.19463.3",
                                       "originalManifestCommit": "ce459ae07c3d7a1e68251268855e0bc7b3d97f75",
                                       "retainedVersion": ARCADE_VERSION, "retainedCommit": ARCADE_COMMIT,
                                       "exactOriginalBootstrapToolReused": False},
            "scope": "Bootstrap tools only; no product build or framework source-origin claim. Preserve global.json and the product manifest. Explicitly select the retained PSB Arcade tool, whose source commit differs from both original declarations, through the original SDK resolver and bootstrap properties."}


def verify_completed(state, source_records, archive_info, psb_info, arcade_info, sdk, contract):
    completed = json.loads(ordinary_file(state / "prepared.json").read_text(encoding="utf-8"))
    if (completed["sourceFiles"] != source_records or completed["sdkArchive"] != archive_info or
            completed["psbArchive"] != psb_info or completed["arcadePackage"] != arcade_info or completed["contract"] != contract):
        raise ValueError("The completed bootstrap inputs or environment contract differ")
    for row in completed["stableSdkFiles"]:
        if fingerprint(ordinary_file(sdk / row["path"])) != row["fingerprint"]:
            raise ValueError("A stable bootstrap SDK/resolver file changed: " + row["path"])
    for name, row in completed["contractFiles"].items():
        if fingerprint(ordinary_file(state / name)) != row:
            raise ValueError("A frozen bootstrap contract file changed")
    return completed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "verify"])
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--inputs-dir", required=True, type=Path)
    parser.add_argument("--reports-dir", required=True, type=Path)
    parser.add_argument("--profile", required=True, type=Path)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine().lower() not in ("aarch64", "arm64"):
        raise ValueError("Run the helper in the native Linux ARM64 build environment")
    source, inputs = directory(args.source_dir), directory(args.inputs_dir, create=True)
    reports = directory(args.reports_dir, create=True)
    if (contained(inputs, source) or contained(source, inputs) or contained(reports, inputs) or
            contained(inputs, reports) or contained(reports, source) or contained(source, reports)):
        raise ValueError("Source, private inputs and reports must be separate directories")
    report_path = reports / "core30-bootstrap.json"
    if report_path.exists() or report_path.is_symlink():
        raise ValueError("Use a new reports directory for each bootstrap attempt")
    source_records = identity(source, args.profile)
    state_path = inputs / "bootstrap-state"
    if state_path.exists() and not (state_path / "owner.json").exists() and list(directory(state_path).iterdir()):
        raise ValueError("Refusing an unrecognized nonempty bootstrap state directory")
    state = directory(state_path, create=True)
    ownership = {"owner": OWNER, "sourceCommit": SOURCE_COMMIT, "sourceRoot": str(source), "inputsDirectory": str(inputs)}
    identical_or_new(state / "owner.json", (json.dumps(ownership, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    report = {"schemaVersion": 1, "action": args.action, "startedAtUtc": now(), "status": "running", "commands": [],
              "sourceRoot": str(source), "sourceCommit": SOURCE_COMMIT, "sourceFiles": source_records,
              "helper": dict({"path": str(Path(__file__).resolve())}, **fingerprint(Path(__file__).resolve())),
              "profile": dict({"path": str(args.profile)}, **fingerprint(ordinary_file(args.profile))),
              "scope": "Official bootstrap extraction, retained Arcade selection, upstream SDK resolver build/install and isolated bootstrap probe. No SDK product graph is built."}
    try:
        if args.action == "verify":
            ordinary_file(state / "prepared.json")
            ordinary_file(inputs / "official-sdk" / SDK_NAME)
            ordinary_file(inputs / "bootstrap-packages" / ARCADE_NAME)
            directory(inputs / "bootstrap-packages/microsoft.dotnet.arcade.sdk" / ARCADE_VERSION)
            directory(source / ".dotnet")
        sdk_archive, sdk_info = official_sdk_archive(inputs)
        arcade, arcade_archive, arcade_info, psb_info = retained_arcade(inputs, state)
        sdk, sdk_receipt = sdk_tree(source, inputs, state, sdk_archive, sdk_info)
        contract = environment_contract(source, inputs, sdk, arcade)
        environment = os.environ.copy()
        for key in list(environment):
            if key.startswith("SOURCE_BUILT_SDK_") or key.startswith("_Initialize"):
                environment.pop(key, None)
        environment.update(contract["environment"])
        environment["PATH"] = str(sdk) + os.pathsep + environment.get("PATH", "")
        report.update({"sdkArchive": dict({"path": str(sdk_archive)}, **sdk_info),
                       "psbArchive": dict({"path": str(inputs / PSB_NAME)}, **psb_info),
                       "arcadePackage": dict({"path": str(arcade_archive)}, **arcade_info),
                       "sdkWorkingDirectory": str(sdk), "sdkInitialExtraction": sdk_receipt,
                       "contract": contract})
        already_prepared = (state / "prepared.json").is_file()
        if args.action == "verify" and not already_prepared:
            raise ValueError("No completed bootstrap setup exists")
        if already_prepared:
            completed = verify_completed(state, source_records, sdk_info, psb_info, arcade_info, sdk, contract)
        else:
            for row in sdk_receipt["originalStableFiles"]:
                if fingerprint(ordinary_file(sdk / row["path"])) != row["fingerprint"]:
                    raise ValueError("An original SDK driver changed before bootstrap completion")
            initialize = ('set -euo pipefail\nunset _InitializeDotNetCli\n'
                          'source ./eng/common/tools.sh\nInitializeDotNetCli true\n'
                          'test "$_InitializeDotNetCli" = "$DOTNET_INSTALL_DIR"\n'
                          '"$_InitializeDotNetCli/dotnet" --version\n')
            run(["bash", "-c", initialize], source, environment, reports / "initialize-dotnet.log", report["commands"])
            version = subprocess.check_output([str(sdk / "dotnet"), "--version"], cwd=str(source), env=environment).decode().strip()
            if version != SDK_VERSION:
                raise ValueError("The private bootstrap SDK version is unexpected")
            output = directory(state / "resolver-bin", create=True)
            intermediate = directory(state / "resolver-obj", create=True)
            installed = sdk / "sdk" / SDK_VERSION / "SdkResolvers" / RESOLVER / (RESOLVER + ".dll")
            built = output / (TASK_ASSEMBLY + ".dll")
            if installed.exists() and (installed.is_symlink() or not built.is_file() or fingerprint(installed) != fingerprint(built)):
                raise ValueError("Refusing an unrecognized existing custom SDK resolver")
            resolver_command = [str(sdk / "dotnet"), str(sdk / "sdk" / SDK_VERSION / "MSBuild.dll"), str(source / RESOLVER_PROJECT),
                                "/p:Configuration=Debug",
                                "/p:DotNetCliToolDir=" + str(sdk) + "/", "/p:SDK_VERSION=" + SDK_VERSION,
                                "/p:OutputPath=" + str(output) + "/", "/p:BaseIntermediateOutputPath=" + str(intermediate) + "/",
                                "/p:AppendTargetFrameworkToOutputPath=false", "/p:RestoreSources=https://api.nuget.org/v3/index.json",
                                "/m:2", "/nr:false"]
            # Restore generates NETStandard.Library reference imports. A new
            # MSBuild evaluation must load them before compiling the resolver.
            run(resolver_command + ["/t:Restore", "/bl:" + str(reports / "resolver-restore.binlog")],
                source, environment, reports / "restore-resolver.log", report["commands"])
            run(resolver_command + ["/t:Build", "/bl:" + str(reports / "resolver.binlog")],
                source, environment, reports / "build-resolver.log", report["commands"])
            # Core 3.0 installs the XPlat task DLL under the resolver filename.
            # Invoke the pinned upstream copy target rather than inventing a
            # resolver assembly or modifying its C# implementation.
            namespace = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}
            original_init = ET.fromstring(git(source, "show", SOURCE_COMMIT + ":tools-local/init-build.proj"))
            current_init = ET.parse(str(ordinary_file(source / "tools-local/init-build.proj"))).getroot()
            target_selector = "m:Target[@Name='InstallSourceBuildSdkResolver']"
            original_target, current_target = original_init.find(target_selector, namespace), current_init.find(target_selector, namespace)
            if (original_target is None or current_target is None or
                    ET.tostring(original_target) != ET.tostring(current_target)):
                raise ValueError("The original resolver installation target changed")
            run([str(sdk / "dotnet"), str(sdk / "sdk" / SDK_VERSION / "MSBuild.dll"),
                 str(source / "tools-local/init-build.proj"), "/t:InstallSourceBuildSdkResolver",
                 "/p:SDK_VERSION=" + SDK_VERSION, "/p:XPlatSourceBuildTasksAssembly=" + str(built),
                 "/nr:false", "/bl:" + str(reports / "resolver-install.binlog")], source, environment,
                reports / "install-resolver.log", report["commands"])
            if fingerprint(ordinary_file(installed)) != fingerprint(ordinary_file(built)):
                raise ValueError("The installed resolver differs from its actual upstream build output")
            completed = {"sourceFiles": source_records, "sdkArchive": sdk_info, "psbArchive": psb_info,
                         "arcadePackage": arcade_info, "contract": contract,
                         "resolverEvaluation": "Restore and Build run in separate MSBuild processes; the original init-build InstallSourceBuildSdkResolver target then installs the untouched XPlat task assembly as the resolver DLL.",
                         "resolverBuildOutput": dict({"path": str(built)}, **fingerprint(built)), "stableSdkFiles": []}
            stable = ["sdk/" + SDK_VERSION + "/MSBuild.dll", "sdk/" + SDK_VERSION + "/MSBuild.runtimeconfig.json",
                      "sdk/" + SDK_VERSION + "/Sdks/Microsoft.NET.Sdk/Sdk/Sdk.props",
                      "sdk/" + SDK_VERSION + "/Sdks/Microsoft.NET.Sdk/Sdk/Sdk.targets",
                      "sdk/" + SDK_VERSION + "/SdkResolvers/" + RESOLVER + "/" + RESOLVER + ".dll"]
            for relative in stable:
                completed["stableSdkFiles"].append({"path": relative, "fingerprint": fingerprint(ordinary_file(sdk / relative))})
        probe = reports / "arcade-probe"
        probe.mkdir()
        project, location = probe / "probe.proj", probe / "toolset-location.txt"
        project.write_text('<Project Sdk="Microsoft.DotNet.Arcade.Sdk/1.0.0-beta.19359.6"/>\n', encoding="utf-8")
        run([str(sdk / "dotnet"), str(sdk / "sdk" / SDK_VERSION / "MSBuild.dll"), str(project),
             "/t:__WriteToolsetLocation", "/p:__ToolsetLocationOutputFile=" + str(location), "/v:diag", "/nr:false",
             "/bl:" + str(reports / "arcade-probe.binlog")], source, environment,
            reports / "arcade-probe.log", report["commands"])
        expected_location = arcade / "tools/Build.proj"
        if Path(ordinary_file(location).read_text(encoding="utf-8-sig").strip()).resolve() != expected_location:
            raise ValueError("The bootstrap probe resolved another toolset")
        probe_text = (reports / "arcade-probe.log").read_text(encoding="utf-8", errors="replace")
        if "SourceBuiltSdkResolver" not in probe_text or ARCADE_VERSION not in probe_text or "1.0.0-beta.19359.6" not in probe_text:
            raise ValueError("The probe did not record the real source-built resolver/version")
        report["bootstrapProbe"] = {"resolvedToolset": str(expected_location), "actualArcadeVersion": ARCADE_VERSION,
                                    "locationFile": fingerprint(location), "passed": True}
        if identity(source, args.profile) != source_records:
            raise ValueError("Pinned source/global.json files changed during setup")
        if not already_prepared:
            contract_bytes = (json.dumps(contract, indent=2, sort_keys=True) + "\n").encode("utf-8")
            shell = "#!/usr/bin/env bash\n# Frozen .NET Core 3.0 bootstrap environment; product build flags are supplied separately.\n"
            shell += "\n".join("export " + key + "=" + shlex.quote(value) for key, value in sorted(contract["environment"].items())) + "\n"
            identical_or_new(state / "core30-bootstrap-contract.json", contract_bytes)
            identical_or_new(state / "core30-bootstrap-env.sh", shell.encode("utf-8"))
            completed["contractFiles"] = {name: fingerprint(state / name) for name in ("core30-bootstrap-contract.json", "core30-bootstrap-env.sh")}
            completed["recordedAtUtc"] = now()
            write_json(state / "prepared.json", completed)
        report.update({"status": "passed", "alreadyPrepared": already_prepared,
                       "preparedReceipt": dict({"path": str(state / "prepared.json")}, **fingerprint(state / "prepared.json")),
                       "productBuildExecuted": False, "globalJsonPreserved": True})
    except Exception as error:
        report.update({"status": "failed", "error": str(error)})
        raise
    finally:
        report["finishedAtUtc"] = now()
        write_json(report_path, report)
    print(json.dumps({"status": report["status"], "report": str(report_path), "contract": str(state / "core30-bootstrap-contract.json"), "productBuildExecuted": False}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, ET.ParseError, zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        raise SystemExit("error: " + str(error))
