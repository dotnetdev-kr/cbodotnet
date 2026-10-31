#!/usr/bin/env python3
"""Fetch the matching official SDK as a checksum-verified test baseline only."""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import tempfile
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--profile', type=Path, required=True)
parser.add_argument('--inputs-dir', type=Path, required=True)
parser.add_argument('--reports-dir', type=Path, required=True)
args = parser.parse_args()
profile = json.loads(args.profile.read_text(encoding='utf-8-sig'))
version = profile['sdkVersion']
rid = profile['target']['rid']
if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version) or rid not in ('linux-arm64', 'linux-x64'):
    parser.error('A stable SDK version and Linux ARM64/x64 profile are required')
channel = '.'.join(version.split('.')[:2])
metadata_url = f'https://builds.dotnet.microsoft.com/dotnet/release-metadata/{channel}/releases.json'
with urllib.request.urlopen(metadata_url, timeout=120) as response:
    metadata_bytes = response.read()
metadata = json.loads(metadata_bytes)
candidates = {}
for release in metadata['releases']:
    sdks = [release.get('sdk', {}), *release.get('sdks', [])]
    for sdk in sdks:
        if sdk.get('version') != version:
            continue
        for item in sdk.get('files', []):
            if item.get('rid') == rid and item['url'].endswith('.tar.gz'):
                candidates[item['url']] = item
if len(candidates) != 1:
    raise SystemExit(f'Expected one published SDK {version}/{rid}; found {len(candidates)}')
item = next(iter(candidates.values()))
expected = item['hash'].lower()
if not re.fullmatch(r'[0-9a-f]{128}', expected) or not item['url'].startswith('https://'):
    raise SystemExit('Official metadata lacks an HTTPS URL and SHA-512')
directory = args.inputs_dir.resolve() / 'official-sdk'
directory.mkdir(parents=True, exist_ok=True)
target = directory / f'dotnet-sdk-{version}-{rid}.tar.gz'

def sha512(path):
    digest = hashlib.sha512()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()

if not target.exists():
    staged = None
    try:
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as stream:
            staged = Path(stream.name)
            with urllib.request.urlopen(item['url'], timeout=120) as response:
                for chunk in iter(lambda: response.read(1024 * 1024), b''):
                    stream.write(chunk)
        if sha512(staged) != expected:
            raise SystemExit('Official SDK test baseline SHA-512 mismatch')
        staged.replace(target)
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)
if not target.is_file() or target.is_symlink() or sha512(target) != expected:
    raise SystemExit('Existing official SDK test baseline failed verification')
args.reports_dir.mkdir(parents=True, exist_ok=True)
record = {
    'fetchedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'purpose': 'Official SDK comparison baseline only; not the community build output',
    'version': version, 'rid': rid, 'url': item['url'], 'path': str(target),
    'bytes': target.stat().st_size, 'sha512': expected, 'sha512Verified': True,
    'metadataUrl': metadata_url,
    'metadataSha256': hashlib.sha256(metadata_bytes).hexdigest(),
}
(args.reports_dir / 'official-sdk-baseline.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
print(json.dumps(record, indent=2))
