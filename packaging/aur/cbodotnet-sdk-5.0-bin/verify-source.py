#!/usr/bin/env python3
"""Verify canonical SDK inputs before safe, byte-preserving extraction."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import shutil
import stat
import tarfile
import tempfile

def require(value, message):
    if not value:
        raise ValueError(message)


def sha256(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def snapshot(root):
    """Include names, file bytes, links and permissions, without following links."""
    result = {}
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root).as_posix()
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            result[relative] = ['link', mode, os.readlink(path)]
        elif path.is_file():
            result[relative] = ['file', mode, sha256(path)]
        elif path.is_dir():
            result[relative] = ['directory', mode]
        else:
            raise ValueError('Unexpected installed file type: ' + str(path))
    return result


def extract_sdk(archive_path, destination):
    """Extract only ordinary members and contained file links into a fresh root."""
    require(not destination.exists() and not destination.is_symlink(), 'SDK root must be fresh')
    with tarfile.open(archive_path, 'r:gz') as archive:
        entries = archive.getmembers()
        require(0 < len(entries) <= 200000, 'Unexpected SDK archive member count')
        members = {}
        for entry in entries:
            name = posixpath.normpath(entry.name)
            path = PurePosixPath(name)
            require(not path.is_absolute() and '..' not in path.parts
                    and not any(c in entry.name for c in '\\:\0\r\n'), 'Unsafe SDK archive member')
            require(name not in members, 'Duplicate SDK archive member')
            require((entry.isdir() or entry.isfile() or entry.issym() or entry.islnk())
                    and not entry.mode & 0o7000, 'Unsafe SDK archive type or permission bits')
            require(name != '.' or entry.isdir(), 'Invalid SDK archive root')
            members[name] = entry
        # Requiring links to ordinary files avoids cycles, directory links and
        # link-parent extraction attacks while retaining ordinary SDK file links.
        for name, entry in members.items():
            for parent in PurePosixPath(name).parents:
                if str(parent) in members:
                    require(members[str(parent)].isdir(), 'SDK member has a non-directory parent')
            if entry.issym() or entry.islnk():
                require(not entry.linkname.startswith('/')
                        and not any(c in entry.linkname for c in '\\:\0\r\n'), 'Unsafe SDK link')
                target = posixpath.normpath(posixpath.join(posixpath.dirname(name), entry.linkname)
                                           if entry.issym() else entry.linkname)
                require(target in members and members[target].isfile(), 'SDK link must name an ordinary archive file')
        require(sum(entry.size for entry in entries) + 512 * 1024**2
                < shutil.disk_usage(destination.parent).free, 'Insufficient SDK extraction space')
        destination.mkdir(mode=0o755)
        for name, entry in members.items():
            if name == '.':
                continue
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if entry.isdir():
                path.mkdir(exist_ok=True)
            elif entry.isfile():
                with archive.extractfile(entry) as source, path.open('xb') as output:
                    shutil.copyfileobj(source, output)
            else:
                continue
            os.chmod(path, entry.mode & 0o777)
        for name, entry in members.items():
            if entry.issym():
                (destination / name).symlink_to(entry.linkname)
            elif entry.islnk():
                os.link(destination / posixpath.normpath(entry.linkname), destination / name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--checksums', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    policy = json.loads(args.policy.read_bytes())
    require(sha256(args.manifest) == policy['sourceManifestSha256'], 'Pinned source manifest changed')
    manifest = json.loads(args.manifest.read_bytes())
    require(manifest['schemaVersion'] == 1 and manifest['repository'] == 'dotnetdev-kr/cbodotnet'
            and manifest['sdkVersion'] == policy['sdkVersion'] and manifest['tag'] == policy['sourceReleaseTag']
            and set(manifest['architectures']) == {'x64', 'aarch64'}, 'Incomplete canonical SDK release')
    row = manifest['architectures']['x64']
    require(row['sdk'] == {key: policy['sdk'][key] for key in ('name', 'size', 'sha256')}
            and row['source'] == {key: policy['source'][key] for key in ('name', 'size', 'sha256')}
            and row['evidence'] == {key: policy['evidence'][key] for key in ('name', 'size', 'sha256')}
            and row['provenance'] == policy['producer'] and row['provenance']['targetRid'] == 'linux-x64',
            'Release assets or qualified producer differ from reviewed policy')
    require(args.checksums.stat().st_size == manifest['checksums']['size']
            and sha256(args.checksums) == manifest['checksums']['sha256'], 'Canonical checksums changed')
    expected = {value[kind]['name']: value[kind]['sha256'] for value in manifest['architectures'].values()
                for kind in ('sdk', 'source', 'evidence')}
    observed = {}
    for line in args.checksums.read_text(encoding='ascii').splitlines():
        digest, name = line.split('  ', 1)
        require(name not in observed, 'Duplicate source checksum')
        observed[name] = digest
    require(observed == expected, 'Source checksum matrix differs from manifest')
    require(args.archive.name == row['sdk']['name'] and args.archive.stat().st_size == row['sdk']['size']
            and sha256(args.archive) == row['sdk']['sha256'], 'Qualified SDK archive changed')
    destination = args.destination.absolute()
    require(destination.parent.is_dir() and not any(path.is_symlink() for path in [destination, *destination.parents]),
            'An ordinary SDK extraction destination is required')
    if destination.exists():
        with tempfile.TemporaryDirectory(prefix='cbodotnet-aur-cache-') as temporary:
            fresh = Path(temporary) / 'sdk'
            extract_sdk(args.archive, fresh)
            require(snapshot(destination) == snapshot(fresh), 'SDK source cache changed; rebuild with makepkg --cleanbuild')
    else:
        extract_sdk(args.archive, destination)


if __name__ == '__main__':
    main()
