#!/usr/bin/env python3
"""Recover missing XML documentation from verified, already-cached NuGet ZIPs."""
import argparse
import base64
import hashlib
import json
import pathlib
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--cache-root', type=pathlib.Path, action='append', required=True)
parser.add_argument('--report', type=pathlib.Path, required=True)
args = parser.parse_args()
records = []
packages = 0
for cache in args.cache_root:
    if not cache.is_dir():
        continue
    cache = cache.resolve()
    for package in sorted(cache.glob('*/*/*.nupkg')):
        if package.is_symlink() or not package.resolve().is_relative_to(cache):
            raise SystemExit('Unsafe package cache entry')
        hash_path = package.with_suffix('.nupkg.sha512')
        if not hash_path.is_file():
            continue
        with zipfile.ZipFile(package) as archive:
            missing = []
            for entry in archive.infolist():
                relative = pathlib.PurePosixPath(entry.filename)
                if (entry.is_dir() or not entry.filename.lower().endswith('.xml')
                        or len(relative.parts) < 2):
                    continue
                if relative.is_absolute() or '..' in relative.parts:
                    raise SystemExit('Unsafe XML entry in NuGet package')
                target = package.parent.joinpath(*relative.parts)
                if not target.resolve().is_relative_to(package.parent.resolve()):
                    raise SystemExit('XML target escapes package directory')
                if not target.exists():
                    missing.append((entry, target))
            if not missing:
                continue
            digest = hashlib.sha512()
            with package.open('rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(block)
            if base64.b64encode(digest.digest()).decode() != hash_path.read_text().strip():
                raise SystemExit(f'Cached package hash mismatch: {package}')
            packages += 1
            for entry, target in missing:
                content = archive.read(entry)  # ZIP CRC is checked on read.
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as stream:
                    stream.write(content)
                records.append({'package': str(package), 'entry': entry.filename,
                                'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()})
args.report.parent.mkdir(parents=True, exist_ok=True)
args.report.write_text(json.dumps({'packagesRepaired': packages, 'restoredFiles': records}, indent=2) + '\n', encoding='utf-8')
print(f'Recovered {len(records)} missing XML files from {packages} cached packages.')
