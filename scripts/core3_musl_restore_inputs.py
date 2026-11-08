"""Capture experimental Core3's actual project.assets package input closure.

Multiple upstream repositories choose caches outside HOME/.nuget/packages.
Every declared packageFolders root must lie in the isolated native worktree.
Retain unchanged complete nupkg bytes and independently bind every actual
assets contentHash. This is input accounting, not corresponding-source,
signature trust, execution, SDK qualification or release admission evidence.
"""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath

from musl_nuget_content_hash import content_hash


def require(value, message):
    if not value:
        raise ValueError('Core3 restore inputs: ' + message)


def ordinary(path):
    path = Path(path).absolute()
    require(not any(item.is_symlink() for item in (path, *path.parents)),
            'symlink control paths are not accepted')
    return path.resolve()


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)


def snapshot(work, output, *, asset_roots=None):
    work, output = ordinary(work), ordinary(output)
    require(work.is_dir() and output.is_dir() and not output.is_relative_to(work),
            'separate existing work and evidence directories are required')
    search_roots = [ordinary(root) for root in asset_roots] if asset_roots is not None else [work]
    require(search_roots and all(root.is_relative_to(work) and root.is_dir() for root in search_roots),
            'assets search roots must be existing directories inside the isolated worktree')
    # Templates can contain their publisher's old obj/project.assets.json inside
    # an unchanged package member. Callers composing an SDK declare their actual
    # project roots rather than treating those cached examples as new restores.
    paths = {path for root in search_roots for path in root.rglob('project.assets.json')}
    assets, roots, packages, native = [], set(), [], []
    for path in sorted(paths):
        require(path.is_file() and not path.is_symlink(), 'an assets file is not an ordinary file')
        raw = path.read_bytes()
        require(len(raw) <= 32 * 1024 * 1024, 'an assets file exceeds the bound')
        data = json.loads(raw)
        folders = [ordinary(name) for name in data.get('packageFolders', {})]
        require(folders and all(root.is_relative_to(work) and root.is_dir() for root in folders),
                'declared package caches must exist inside the isolated worktree')
        roots.update(folders)
        relative = path.relative_to(work).as_posix()
        write_new(output / 'actual-project-assets' / relative, raw)
        libraries = {name: row for name, row in data.get('libraries', {}).items()
                     if row.get('type') == 'package'}
        assets.append(dict(path=relative, sha256=hashlib.sha256(raw).hexdigest(),
                           packageFolders=list(map(str, folders)), libraries=libraries))
    require(assets, 'no actual assets files were found')
    by_input = {}
    for index, cache in enumerate(sorted(roots)):
        for path in sorted(cache.rglob('*.nupkg')):
            require(path.is_file() and not path.is_symlink(), 'a package input is not an ordinary file')
            raw = path.read_bytes()
            relative = path.relative_to(cache)
            target = output / 'actual-restored-packages' / str(index) / relative
            write_new(target, raw)
            metadata = path.parent / '.nupkg.metadata'
            if metadata.is_file():
                require(not metadata.is_symlink(), 'package metadata is a symlink')
                write_new(target.parent / '.nupkg.metadata', metadata.read_bytes())
            row = dict(cache=cache.relative_to(work).as_posix(), path=relative.as_posix(),
                       retained=target.relative_to(output).as_posix(), bytes=len(raw),
                       sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest(),
                       nugetContentHash=content_hash(raw),
                       metadata=json.loads(metadata.read_text()) if metadata.is_file() else None)
            packages.append(row)
            by_input[str(path)] = row
        for path in sorted(cache.rglob('*')):
            if not path.is_file() or path.is_symlink():
                continue
            with path.open('rb') as stream:
                header = stream.read(20)
            if header[:4] == b'\x7fELF':
                native.append(dict(cache=cache.relative_to(work).as_posix(),
                    path=path.relative_to(cache).as_posix(), machine=int.from_bytes(header[18:20], 'little'),
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                    classification='Restored input; execution and product use are not inferred'))
    bindings = []
    for asset in assets:
        for identity, library in sorted(asset['libraries'].items()):
            require(isinstance(identity, str) and identity.count('/') == 1, 'invalid package identity')
            package_id, version = identity.rsplit('/', 1)
            relative = PurePosixPath(library.get('path', identity.lower()))
            require(not relative.is_absolute() and '..' not in relative.parts and '\\' not in str(relative),
                    'an assets package path escapes its cache')
            expected = library.get('sha512')
            require(isinstance(expected, str), 'an assets package content hash is absent')
            try:
                decoded = base64.b64decode(expected, validate=True)
            except ValueError as error:
                raise ValueError('Core3 restore inputs: invalid base64 content hash') from error
            require(len(decoded) == 64, 'an assets content hash is not SHA-512')
            matches = []
            for root in asset['packageFolders']:
                path = Path(root) / str(relative) / (package_id.lower() + '.' + version.lower() + '.nupkg')
                if not path.exists():
                    continue
                require(path.is_file() and not path.is_symlink(), 'a used input is not an ordinary file')
                row = by_input.get(str(path))
                require(row is not None and row['nugetContentHash'] == expected,
                        'actual package differs from the assets content hash: ' + identity)
                matches.append(row)
            require(matches, 'actual package bytes are missing: ' + identity)
            require(len({row['sha512'] for row in matches}) == 1,
                    'multiple declared caches contain different bytes for the same used package')
            row = matches[0]
            bindings.append(dict(assets=asset['path'], package=identity, assetsContentHash=expected,
                retained=row['retained'], sha256=row['sha256'], sha512=row['sha512'],
                nugetContentHash=row['nugetContentHash']))
    require(packages and bindings, 'no actual restored package bindings were found')
    record = dict(schemaVersion=2, qualification=False, releaseAdmission=False, sourceSdkProduct=False,
        scope='Actual assets content hashes are recomputed from unchanged retained package bytes. Whole-file fingerprints remain distinct from signed-package content hashes; no signature trust, corresponding-source closure or product qualification is inferred.',
        assetSearchRoots=[root.relative_to(work).as_posix() for root in search_roots],
        assets=assets, cacheRoots=[root.relative_to(work).as_posix() for root in sorted(roots)],
        packages=packages, usedPackageBindings=bindings, elfs=native)
    write_new(output / 'actual-component-restore-closure.json', (json.dumps(record, indent=2) + '\n').encode())
    return record
