#!/usr/bin/env python3
"""Fetch and verify the exact supplementary NuGet inputs in the build profile."""
import argparse
import hashlib
import json
import pathlib
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--profile', type=pathlib.Path, required=True)
parser.add_argument('--inputs-dir', type=pathlib.Path, required=True)
parser.add_argument('--reports-dir', type=pathlib.Path, required=True)
parser.add_argument('--offline', action='store_true')
args = parser.parse_args()
profile = json.loads(args.profile.read_text(encoding='utf-8-sig'))
feed = args.inputs_dir.resolve() / 'nuget'
feed.mkdir(parents=True, exist_ok=True)
records = []
expected_names = {item['fileName'] for item in profile.get('additionalPackages', [])}
if {path.name for path in feed.glob('*.nupkg')} - expected_names:
    raise SystemExit('Pinned input feed contains unlisted NuGet packages')
for item in profile.get('additionalPackages', []):
    name = item['fileName']
    if pathlib.Path(name).name != name or not name.endswith('.nupkg'):
        raise SystemExit('Invalid locked package filename')
    path = feed / name
    if not path.exists():
        if args.offline:
            raise SystemExit(f'Missing pinned input; run Prepare first: {name}')
        staged = None
        try:
            with tempfile.NamedTemporaryFile(dir=feed, delete=False) as target:
                staged = pathlib.Path(target.name)
                with urllib.request.urlopen(item['url'], timeout=120) as source:
                    for block in iter(lambda: source.read(1024 * 1024), b''):
                        target.write(block)
            if hashlib.sha256(staged.read_bytes()).hexdigest() != item['sha256']:
                raise SystemExit(f'Downloaded input hash mismatch: {name}')
            staged.replace(path)
        finally:
            if staged is not None:
                staged.unlink(missing_ok=True)
    content = path.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    if digest != item['sha256']:
        raise SystemExit(f'Pinned input hash mismatch: {name}')
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise SystemExit(f'Corrupt NuGet ZIP: {name}')
        nuspecs = [entry for entry in archive.namelist() if entry.endswith('.nuspec')]
        if len(nuspecs) != 1:
            raise SystemExit(f'Ambiguous NuGet metadata: {name}')
        fields = {entry.tag.rsplit('}', 1)[-1]: entry.text
                  for entry in ET.fromstring(archive.read(nuspecs[0])).iter()}
        if fields.get('id', '').lower() != item['id'].lower() or fields.get('version') != item['version']:
            raise SystemExit(f'NuGet identity mismatch: {name}')
    records.append({**item, 'sizeBytes': len(content), 'sha256Verified': True,
                    'sha512': hashlib.sha512(content).hexdigest(), 'archiveIntegrityVerified': True,
                    'hashOrigin': 'Content fingerprint recorded from the public upstream URL, not a publisher signature'})
args.reports_dir.mkdir(parents=True, exist_ok=True)
(args.reports_dir / 'pinned-inputs.json').write_text(json.dumps({
    'feed': '/inputs/nuget', 'packages': records}, indent=2) + '\n', encoding='utf-8')
print(f'Verified {len(records)} locked NuGet input(s).')
