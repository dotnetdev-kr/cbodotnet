#!/usr/bin/env python3
"""Acquire pinned legacy source-build inputs without the retired Darc package.

This Python 3.6-compatible adapter replaces only Darc's depth-zero clone
operation. Upstream FetchSources, metadata generation, patches and component
builds remain responsible for their own work and completion markers.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urljoin, urlparse
import uuid
import xml.etree.ElementTree as ET


ROOT_REPOSITORY = "https://github.com/dotnet/source-build"
SOURCE_PINS = {
    "5.0.214": "d414ecb2d997a9b3f38aaaeddace30ca097e546d",
    "3.1.426": "ab8b115b5658237ee8916ae3586600b39fb2fd19",
    "3.0.103": "40de72d1087a1d05dfd39c87f888a0611ec6c60f",
}
OWNER = "cbodotnet-legacy-source-cloner-v1"
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
EMPTY_GIT_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


class CloneError(Exception):
    pass


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
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def contained(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def ordinary_path(value, existing=False):
    path = Path(value)
    if not path.is_absolute():
        raise CloneError("Absolute paths are required: " + str(path))
    for item in [path] + list(path.parents):
        if item.is_symlink():
            raise CloneError("Symbolic links are not permitted in control paths: " + str(item))
    path = path.resolve(strict=existing)
    if path == Path(path.anchor):
        raise CloneError("A directory below the filesystem root is required")
    if existing and not path.is_dir():
        raise CloneError("An existing ordinary directory is required: " + str(path))
    return path


def git(arguments, directory=None, allow_failure=False):
    environment = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_COUNT"):
        environment.pop(key, None)
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_TERMINAL_PROMPT"] = "0"
    command = ["git", "-c", "core.fsmonitor=false", "-c", "protocol.ext.allow=never",
               "-c", "protocol.file.allow=never"] + [str(arg) for arg in arguments]
    process = subprocess.run(command, cwd=str(directory) if directory else None,
                             env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.returncode and not allow_failure:
        message = process.stderr.decode("utf-8", "replace")[-12000:].strip()
        raise CloneError("Git operation failed ({0}): {1}".format(arguments[0], message))
    return process.returncode, process.stdout


def git_text(arguments, directory=None):
    return git(arguments, directory)[1].decode("utf-8").strip()


def canonical_url(value, parent=None):
    if value.startswith("git@github.com:"):
        value = "https://github.com/" + value[len("git@github.com:"):]
    if value.startswith("git://github.com/"):
        value = "https://github.com/" + value[len("git://github.com/"):]
    if value.startswith("./") or value.startswith("../"):
        if parent is None:
            raise CloneError("A relative repository URL requires its pinned parent")
        value = urljoin(parent.rstrip("/") + "/", value)
    parsed = urlparse(value)
    parts = parsed.path.strip("/").split("/")
    if (parsed.scheme != "https" or parsed.netloc.lower() != "github.com"
            or parsed.query or parsed.fragment or len(parts) != 2):
        raise CloneError("Only public GitHub HTTPS source repositories are supported: " + value)
    owner, name = parts
    if name.endswith(".git"):
        name = name[:-4]
    if not all(re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", item) for item in (owner, name)):
        raise CloneError("Unsupported repository path: " + value)
    return "https://github.com/{0}/{1}".format(owner.lower(), name.lower())


def basename(url):
    name = urlparse(url).path.rstrip("/").rsplit("/", 1)[-1]
    return name[:-4] if name.endswith(".git") else name


def committed_file(root, commit, relative):
    return git(["show", commit + ":" + relative], root)[1]


def local_elements(root, name):
    """Read old MSBuild XML namespaces without changing modern XML handling."""
    return [element for element in root.iter() if element.tag.rsplit("}", 1)[-1] == name]


def core30_layout(root, commit):
    """Verify the corrected 3.0 source tag's older acquisition/layout contract."""
    properties_path = "dir.props"
    properties = ET.fromstring(committed_file(root, commit, properties_path))
    expected_properties = {
        "BaseOutputPath": "$(ProjectDir)bin/",
        "ClonedSubmoduleDirectory": "$(BaseOutputPath)src/",
        "ClonedSubmoduleGitRootDirectory": "$(ProjectDir).git/modules/src/",
    }
    for name, expected in expected_properties.items():
        values = [(element.text or "").strip() for element in local_elements(properties, name)]
        if values != [expected]:
            raise CloneError("The pinned Core 3.0 source layout differs for " + name)
    acquisition_path = "tools-local/init-build.proj"
    initialization = ET.fromstring(committed_file(root, commit, acquisition_path))
    fetch_targets = [element for element in local_elements(initialization, "Target")
                     if element.get("Name") == "FetchSources"]
    if len(fetch_targets) != 1:
        raise CloneError("Expected the pinned Core 3.0 FetchSources target")
    fetch = fetch_targets[0]
    arguments = " ".join(" ".join(element.text or "" for element in local_elements(fetch, "DarcCloneArguments")).split())
    for required in ("--repos-folder $(ClonedSubmoduleDirectory)",
                     "--git-dir-folder $(ClonedSubmoduleGitRootDirectory)",
                     "--include-toolset", "--depth 0", "--ignore-repos"):
        if required not in arguments:
            raise CloneError("The pinned Core 3.0 source acquisition contract lacks " + required)
    return {
        "generation": "core30-source-build",
        "propertyDefinitions": properties_path,
        "ignoredRepositoryDeclarations": acquisition_path,
        "ignoredRepositoryTarget": "FetchSources",
        "requiredExportSubdirectory": "bin/src",
        "requiredGitStoreSubdirectory": ".git/modules/src",
        "metadataTask": "tools-local/tasks/Microsoft.DotNet.SourceBuild.Tasks.XPlat/WriteSourceRepoProperties.cs",
        "metadataPolicy": "Retain full-history URL-basename.git stores and URL-basename.SHA source exports for the pinned upstream metadata task.",
    }, fetch


def source_identity(args):
    root = ordinary_path(args.source_dir, existing=True)
    profile_path = Path(args.profile)
    if not profile_path.is_absolute() or profile_path.is_symlink() or not profile_path.is_file():
        raise CloneError("An absolute ordinary profile file is required")
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    expected = SOURCE_PINS.get(profile.get("sdkVersion"))
    if expected is None or profile.get("source", {}).get("commit") != expected:
        raise CloneError("The profile does not select a supported pinned legacy source-build revision")
    if canonical_url(profile["source"]["repository"]) != ROOT_REPOSITORY:
        raise CloneError("Unexpected source-build repository in profile")
    top = Path(git_text(["rev-parse", "--show-toplevel"], root)).resolve()
    if top != root or git_text(["rev-parse", "HEAD"], root) != expected:
        raise CloneError("Source-build checkout identity does not match the profile")
    if args.repo and canonical_url(args.repo) != ROOT_REPOSITORY:
        raise CloneError("The Darc repository argument does not match the pinned source-build root")
    if args.version and args.version != expected:
        raise CloneError("The Darc version argument must be the pinned source-build commit")
    manifest_relative = "eng/Version.Details.xml"
    committed = committed_file(root, expected, manifest_relative)
    manifest_path = root / manifest_relative
    if manifest_path.is_symlink() or manifest_path.read_bytes() != committed:
        raise CloneError("The working dependency manifest differs from the pinned Git object")
    manifest_hash = hashlib.sha256(committed).hexdigest()
    dependency_root = ET.fromstring(committed)
    dependencies = []
    for group in ("ToolsetDependencies", "ProductDependencies"):
        for entry in dependency_root.findall("./" + group + "/Dependency"):
            url, sha = entry.findtext("Uri"), entry.findtext("Sha")
            if not url or not sha or not SHA_PATTERN.match(sha):
                raise CloneError("Every dependency must have a repository and exact commit")
            dependencies.append({"name": entry.get("Name"), "version": entry.get("Version"),
                                 "group": group, "repository": url, "canonicalRepository": canonical_url(url),
                                 "commit": sha, "repoNames": [item.text for item in entry.findall("RepoName")]})
    if not dependencies:
        raise CloneError("The pinned dependency manifest is empty")
    layout = None
    if profile["sdkVersion"] == "3.0.103":
        layout, ignore_scope = core30_layout(root, expected)
        ignored_elements = local_elements(ignore_scope, "IgnoredRepos")
    else:
        targets_relative = "Directory.Build.targets"
        targets = committed_file(root, expected, targets_relative)
        ignored_elements = ET.fromstring(targets).iter("IgnoredRepos")
    ignored = set()
    for element in ignored_elements:
        for value in (element.text or "").split(";"):
            if value and value != "$(IgnoredRepos)":
                ignored.add(value.rstrip("/").lower().replace(".git", ""))
    requested = []
    for value in args.ignore_repos:
        requested.extend(item.rstrip("/").lower().replace(".git", "") for item in value.split(";") if item)
    if any(item not in ignored for item in requested):
        raise CloneError("Additional ignored repositories would change the pinned source graph")
    for item in dependencies:
        item["ignoredByUpstreamClone"] = item["canonicalRepository"] in ignored
    return root, profile_path, profile, expected, manifest_hash, dependencies, sorted(ignored), layout


def safe_member_path(root, name):
    relative = PurePosixPath(name)
    if relative.is_absolute() or not relative.parts or any(part in (".", "..", ".git") for part in relative.parts):
        raise CloneError("Unsafe archive path: " + name)
    target = root.joinpath(*relative.parts)
    if not contained(target, root):
        raise CloneError("Archive path escaped its source directory: " + name)
    for parent in list(target.parents):
        if parent == root:
            break
        if parent.is_symlink():
            raise CloneError("Archive path traverses a symbolic link: " + name)
    return target


def extract_archive(archive, destination, empty_git_tree=None):
    if empty_git_tree is not None:
        # Git commit archives include a PAX commit header. Python 3.10 rejects
        # that header when no file follows it. Only proven empty Git trees use
        # the tree-object archive form, which must contain complete zero blocks.
        if empty_git_tree != EMPTY_GIT_TREE:
            raise CloneError("An empty tar requires the canonical verified empty Git tree")
        size = archive.stat().st_size
        if size < 1024 or size % 512:
            raise CloneError("An empty tar must contain at least two complete zero blocks")
        with archive.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                if any(block):
                    raise CloneError("The verified empty Git tree produced nonzero tar content")
        return
    with archive.open("rb") as stream:
        if not any(stream.read(1024)):
            raise CloneError("An empty tar was not bound to a verified empty Git tree")
    with tarfile.open(str(archive), "r:") as source:
        for member in source:
            target = safe_member_path(destination, member.name.rstrip("/"))
            if member.isdir():
                if target.exists() and (target.is_symlink() or not target.is_dir()):
                    raise CloneError("Archive directory conflicts with another entry")
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as stream, target.open("xb") as output:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        output.write(block)
                os.chmod(str(target), member.mode & 0o777)
            elif member.issym():
                target.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(member.linkname, str(target))
            else:
                raise CloneError("Unsupported Git archive member type: " + member.name)


def metadata(directory, repository, sha):
    git_dir = directory / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text(sha, encoding="utf-8")
    (git_dir / "config").write_text('[remote "origin"]\nurl = "' + repository + '"', encoding="utf-8")


def inventory(directory, output):
    count, total_bytes = 0, 0
    with output.open("x", encoding="utf-8") as stream:
        for current, directories, files in os.walk(str(directory), followlinks=False):
            directories.sort()
            files.sort()
            if ".git" in directories:
                directories.remove(".git")
            links = [name for name in directories if (Path(current) / name).is_symlink()]
            for name in links:
                directories.remove(name)
            for name in sorted(files + links):
                path = Path(current) / name
                info = path.lstat()
                record = {"path": path.relative_to(directory).as_posix(), "mode": oct(stat.S_IMODE(info.st_mode))}
                if stat.S_ISLNK(info.st_mode):
                    record.update({"kind": "symlink", "target": os.readlink(str(path))})
                elif stat.S_ISREG(info.st_mode):
                    record.update(fingerprint(path))
                    record["kind"] = "file"
                    total_bytes += record["bytes"]
                else:
                    raise CloneError("Unexpected source filesystem entry: " + str(path))
                stream.write(json.dumps(record, sort_keys=True) + "\n")
                count += 1
    record = {"path": str(output), "entries": count, "fileBytes": total_bytes,
              "scope": "Initial exported source files and symlinks, including pinned submodules; generated .git markers are excluded."}
    record.update(fingerprint(output))
    return record


class Acquirer(object):
    def __init__(self, root, stores, exports, reports, commit, manifest_hash):
        self.root, self.stores, self.exports, self.reports = root, stores, exports, reports
        self.commit, self.manifest_hash = commit, manifest_hash
        self.store_records = {}
        self.store_owners = {}
        self.receipts = ordinary_path(stores / ".cbodotnet-legacy-exports")
        self.receipts.mkdir(exist_ok=True)

    def store(self, repository, sha, submodule=False):
        canonical = canonical_url(repository)
        if submodule:
            owner, name = urlparse(canonical).path.strip("/").split("/")
            path = self.stores / ".cbodotnet-submodules" / owner / (name + ".git")
        else:
            path = self.stores / (basename(repository) + ".git")
        ordinary_path(path)
        key = str(path)
        if key in self.store_owners and self.store_owners[key] != canonical:
            raise CloneError("Different repositories would share a bare-store basename")
        self.store_owners[key] = canonical
        marker = path / "cbodotnet-legacy-source.json"
        expected_marker = {"owner": OWNER, "sourceRootCommit": self.commit,
                           "repository": canonical, "fullCommitHistory": True}
        if path.exists():
            if not marker.is_file() or marker.is_symlink() or json.loads(marker.read_text(encoding="utf-8")) != expected_marker:
                raise CloneError("Refusing an unrecognized existing bare store: " + str(path))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            git(["init", "--bare", "--quiet", path])
            git(["--git-dir=" + str(path), "remote", "add", "origin", canonical])
            write_json(marker, expected_marker)
        prefix = ["--git-dir=" + str(path)]
        if git_text(prefix + ["rev-parse", "--is-bare-repository"]) != "true":
            raise CloneError("The retained source store is not bare")
        if canonical_url(git_text(prefix + ["remote", "get-url", "origin"])) != canonical:
            raise CloneError("The retained source store has another remote")
        if git_text(prefix + ["rev-parse", "--is-shallow-repository"]) != "false":
            raise CloneError("Shallow source stores cannot preserve upstream GitCommitCount")
        exists = git(prefix + ["cat-file", "-e", sha + "^{commit}"], allow_failure=True)[0] == 0
        if not exists:
            print("Fetching full commit history: {0} @ {1}".format(canonical, sha), flush=True)
            git(prefix + ["fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "origin", sha])
        if git_text(prefix + ["rev-parse", sha + "^{commit}"]) != sha:
            raise CloneError("Fetched source does not match the pinned commit")
        count = int(git_text(prefix + ["rev-list", "--count", sha]))
        self.store_records[(canonical, sha)] = {"repository": canonical, "commit": sha,
                                               "bareStore": str(path), "commitCount": count,
                                               "fullCommitHistory": True}
        return path

    def submodules(self, store, sha, repository):
        prefix = ["--git-dir=" + str(store)]
        tree = git(prefix + ["ls-tree", "-r", "-z", sha])[1]
        links = {}
        for entry in tree.split(b"\0"):
            if entry:
                header, path = entry.split(b"\t", 1)
                mode, kind, value = header.decode("ascii").split(" ")
                if mode == "160000":
                    if kind != "commit" or not SHA_PATTERN.match(value):
                        raise CloneError("Invalid submodule Git object")
                    links[path.decode("utf-8")] = value
        modules_present = git(prefix + ["cat-file", "-e", sha + ":.gitmodules"], allow_failure=True)[0] == 0
        if not links and not modules_present:
            return []
        code, config = git(prefix + ["config", "--null", "--blob", sha + ":.gitmodules",
                                     "--get-regexp", r"^submodule\..*\.(path|url)$"], allow_failure=True)
        if code == 1 and not links:
            return []
        if code:
            raise CloneError("Pinned gitlinks lack readable .gitmodules declarations")
        sections = {}
        for entry in config.split(b"\0"):
            if entry:
                key, value = entry.decode("utf-8").split("\n", 1)
                section, field = key[len("submodule."):].rsplit(".", 1)
                if field in sections.setdefault(section, {}):
                    raise CloneError("Repeated submodule configuration field")
                sections[section][field] = value
        result = []
        for name, values in sorted(sections.items()):
            path, url = values.get("path"), values.get("url")
            if not path or not url or path not in links:
                raise CloneError("A submodule declaration lacks a unique pinned gitlink and URL")
            safe_member_path(Path("/placeholder"), path)
            result.append({"name": name, "path": path, "declaredRepository": url,
                           "repository": canonical_url(url, repository), "commit": links.pop(path)})
        if links:
            raise CloneError("A pinned submodule lacks a unique .gitmodules declaration")
        return result

    def populate(self, destination, repository, sha, relative="", ancestry=()):
        canonical = canonical_url(repository)
        if len(ancestry) > 20 or (canonical, sha) in ancestry:
            raise CloneError("Recursive submodule cycle or excessive nesting")
        store = self.store(repository, sha, submodule=bool(relative))
        git_tree = git_text(["--git-dir=" + str(store), "rev-parse", sha + "^{tree}"])
        empty_tree = git_tree == EMPTY_GIT_TREE
        if empty_tree and git(["--git-dir=" + str(store), "ls-tree", "-r", "-z", sha])[1]:
            raise CloneError("The canonical empty tree unexpectedly has tracked entries")
        archive_reference = sha + "^{tree}" if empty_tree else sha
        descriptor, temporary = tempfile.mkstemp(prefix=".archive-", suffix=".tar", dir=str(self.reports))
        os.close(descriptor)
        archive = Path(temporary)
        try:
            git(["--git-dir=" + str(store), "archive", "--format=tar", "--output=" + str(archive), archive_reference])
            archive_info = fingerprint(archive)
            extract_archive(archive, destination, git_tree if empty_tree else None)
        finally:
            archive.unlink()
        record = {"repository": repository, "canonicalRepository": canonical, "commit": sha,
                  "relativePath": relative, "gitTree": git_tree,
                  "archiveReference": archive_reference, "emptyGitTreeArchive": empty_tree,
                  "sourceArchive": archive_info, "sourceArchiveRetained": False, "submodules": []}
        for module in self.submodules(store, sha, canonical):
            target = safe_member_path(destination, module["path"])
            if target.exists():
                if target.is_symlink() or not target.is_dir() or list(target.iterdir()):
                    raise CloneError("A submodule destination is not an empty Git archive placeholder")
            else:
                target.mkdir(parents=True)
            child_relative = "/".join(item for item in (relative, module["path"]) if item)
            child = self.populate(target, module["repository"], module["commit"], child_relative,
                                  ancestry + ((canonical, sha),))
            child.update({"submoduleName": module["name"], "declaredRepository": module["declaredRepository"]})
            record["submodules"].append(child)
        metadata(destination, repository, sha)
        return record

    def acquire(self, repository, sha):
        destination = self.exports / (basename(repository) + "." + sha)
        ordinary_path(destination)
        receipt_key = hashlib.sha256(str(destination).encode("utf-8")).hexdigest()
        receipt = self.receipts / (receipt_key + ".json")
        identity = {"owner": OWNER, "sourceRootCommit": self.commit, "manifestSha256": self.manifest_hash,
                    "repository": canonical_url(repository), "commit": sha, "destination": str(destination)}
        if destination.exists():
            if not destination.is_dir() or receipt.is_symlink() or not receipt.is_file():
                raise CloneError("Refusing an unrecognized existing source export: " + str(destination))
            previous = json.loads(receipt.read_text(encoding="utf-8"))
            if previous.get("identity") != identity:
                raise CloneError("Existing source-export provenance does not match")
            inventory_record = previous["initialInventory"]
            inventory_file = Path(inventory_record["path"])
            if inventory_file.is_symlink() or not inventory_file.is_file() or fingerprint(inventory_file)["sha256"] != inventory_record["sha256"]:
                raise CloneError("Initial source inventory is missing or changed")
            if (destination / ".git").is_symlink():
                raise CloneError("Existing source Git metadata must be an ordinary directory")
            head = destination / ".git" / "HEAD"
            if head.is_symlink() or not head.is_file() or head.read_text(encoding="utf-8").strip() != sha:
                raise CloneError("Existing source export has another commit marker")
            self.store(repository, sha)
            return {"identity": identity, "initialExport": previous,
                    "result": "reused-recorded-export-without-overwriting-current-files",
                    "currentTreeContentRevalidated": False}
        if receipt.exists() or receipt.is_symlink():
            raise CloneError("An export receipt exists but its source directory is absent")
        stage = self.exports / (".cbodotnet-stage-" + uuid.uuid4().hex)
        stage.mkdir()
        try:
            tree = self.populate(stage, repository, sha)
            inventory_file = self.reports / (receipt_key + "-initial-source-inventory.jsonl")
            initial_inventory = inventory(stage, inventory_file)
            completed = {"identity": identity, "recordedAtUtc": now(), "source": tree,
                         "initialInventory": initial_inventory,
                         "metadataPolicy": "Minimal .git/HEAD and origin config markers are generated for each pinned export. Upstream WriteSourceRepoProperties still generates version and SourceLink metadata from retained full-history bare stores."}
            # A completed receipt is published after the atomic source-directory rename.
            # If interrupted between these operations, the unknown destination is refused.
            os.rename(str(stage), str(destination))
            write_json(receipt, completed)
        except Exception:
            # Keep incomplete staging directories for diagnosis; never reset or remove them.
            raise
        return {"identity": identity, "initialExport": completed, "result": "exported-pinned-source",
                "currentTreeContentRevalidated": True}


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("operation", nargs="?", choices=["clone"])
    value.add_argument("--profile", required=True)
    value.add_argument("--source-dir", default=os.getcwd())
    value.add_argument("--reports-dir", required=True)
    value.add_argument("--repo")
    value.add_argument("--version")
    value.add_argument("--depth", type=int, choices=[0], default=0)
    value.add_argument("--depth0", dest="depth", action="store_const", const=0)
    value.add_argument("--include-toolset", action="store_true")
    value.add_argument("--repos-folder", required=True)
    value.add_argument("--git-dir-folder")
    value.add_argument("--ignore-repos", action="append", default=[])
    value.add_argument("--debug", action="store_true")
    value.add_argument("--azdev-pat")
    value.add_argument("--github-pat")
    return value


def main(argv=None):
    args = parser().parse_args(argv)
    if any(value not in (None, "bogus") for value in (args.azdev_pat, args.github_pat)):
        raise CloneError("Private repository credentials are not accepted by this public-source adapter")
    root, profile_path, profile, commit, manifest_hash, dependencies, ignored, layout = source_identity(args)
    stores = ordinary_path(args.git_dir_folder or str(root / ".git/modules/src"))
    if stores != root / ".git/modules/src":
        raise CloneError("The bare-store root must match the upstream metadata layout: .git/modules/src")
    exports, report_root = ordinary_path(args.repos_folder), ordinary_path(args.reports_dir)
    if layout is not None and exports != root / layout["requiredExportSubdirectory"]:
        raise CloneError("Core 3.0 exports must match the pinned bin/src layout")
    if (contained(root, exports) or contained(exports, root / ".git")
            or contained(exports, report_root) or contained(report_root, exports)
            or contained(report_root, root)):
        raise CloneError("Source exports, Git stores and external reports must have separate safe locations")
    stores.mkdir(parents=True, exist_ok=True)
    exports.mkdir(parents=True, exist_ok=True)
    report_root.mkdir(parents=True, exist_ok=True)
    reports = report_root / ("source-clone-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8])
    reports.mkdir()
    report = {"schemaVersion": 1, "adapter": OWNER, "status": "running", "startedAtUtc": now(),
              "sdkVersion": profile["sdkVersion"], "sourceRoot": str(root), "sourceRootCommit": commit,
              "profile": dict({"path": str(profile_path)}, **fingerprint(profile_path)),
              "manifest": {"path": "eng/Version.Details.xml", "sha256": manifest_hash,
                           "gitBlob": git_text(["rev-parse", commit + ":eng/Version.Details.xml"], root)},
              "depth": 0, "includeToolset": True, "reposFolder": str(exports), "gitDirFolder": str(stores),
              "upstreamIgnoredRepositories": ignored, "dependencies": dependencies, "sourceCopies": [],
              "scope": "Pinned root-manifest source acquisition only. Upstream FetchSources and subsequent metadata, patches and component builds remain active. Initial source inventories do not describe later patched/build-modified working trees."}
    if layout is not None:
        report["sourceLayoutContract"] = layout
    write_json(reports / "started.json", report)
    acquirer = Acquirer(root, stores, exports, reports, commit, manifest_hash)
    seen = set()
    try:
        for dependency in dependencies:
            key = (dependency["canonicalRepository"], dependency["commit"])
            if not dependency["ignoredByUpstreamClone"] and key not in seen:
                seen.add(key)
                report["sourceCopies"].append(acquirer.acquire(dependency["repository"], dependency["commit"]))
                print("Prepared pinned source: " + dependency["repository"], flush=True)
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["error"] = str(error)
        raise
    finally:
        report["bareStores"] = sorted(acquirer.store_records.values(), key=lambda item: (item["repository"], item["commit"]))
        report["finishedAtUtc"] = now()
        write_json(reports / "source-clone.json", report)
    print(json.dumps({"status": report["status"], "report": str(reports / "source-clone.json"),
                      "sourceCopies": len(report["sourceCopies"]), "declaredDependencies": len(dependencies)}))
    return report


if __name__ == "__main__":
    try:
        main()
    except (CloneError, OSError, ValueError, KeyError, ET.ParseError) as error:
        raise SystemExit("error: " + str(error))
