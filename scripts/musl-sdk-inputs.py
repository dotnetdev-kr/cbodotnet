#!/usr/bin/env python3
"""Snapshot actual repository NuGet inputs immediately before VMR cache cleanup."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re


def record(cache, output, repository):
    if not re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9._-]*', repository):
        raise ValueError('Invalid pinned VMR repository identity')
    if not cache.is_absolute() or '..' in cache.parts or any(p.is_symlink() for p in [cache, *cache.parents]):
        raise ValueError('An ordinary absolute NuGet cache is required')
    packages = []
    for path in sorted(cache.rglob('*.nupkg')):
        if path.is_symlink() or not path.is_file():
            raise ValueError('A cached NuGet input is redirected')
        before = path.stat()
        hashes = {name: hashlib.new(name) for name in ('sha256', 'sha512')}
        with path.open('rb') as source:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                for digest in hashes.values():
                    digest.update(block)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError('A restored input changed while being recorded')
        metadata = path.parent / '.nupkg.metadata'
        origin = json.loads(metadata.read_text()).get('source') if metadata.is_file() else None
        packages.append(dict(path=path.relative_to(cache).as_posix(), bytes=after.st_size,
                        source=origin, **{name: value.hexdigest() for name, value in hashes.items()}))
    if not packages:
        print('No restored packages in ' + str(cache))
        return
    body = dict(schemaVersion=1, repository=repository, cache=str(cache), packages=packages,
                scope='Actual restored package bytes observed before upstream VMR CleanupRepo removes this cache.')
    encoded = (json.dumps(body, sort_keys=True, indent=2) + '\n').encode()
    name = repository + '-' + hashlib.sha256(encoded).hexdigest() + '.json'
    output.mkdir(parents=True, exist_ok=True)
    destination = output / name
    if destination.exists():
        if destination.is_symlink() or destination.read_bytes() != encoded:
            raise ValueError('Refusing a conflicting restored-input record')
    else:
        with destination.open('xb') as stream:
            stream.write(encoded)
    print('Recorded ' + str(len(packages)) + ' restored packages: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--repository', required=True)
    args = parser.parse_args()
    record(args.cache, args.output_dir, args.repository)


if __name__ == '__main__':
    main()

