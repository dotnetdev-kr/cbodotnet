#!/usr/bin/env python3
"""Apply and record the selected public NuGet mirror and connection limit."""
import argparse
import hashlib
import json
import pathlib
import subprocess
import xml.etree.ElementTree as ET

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source-dir', type=pathlib.Path, required=True)
parser.add_argument('--reports-dir', type=pathlib.Path, required=True)
parser.add_argument('--quarantine-build-state', action='store_true',
                    help='Preserve existing root artifacts/obj under a new name before rebuilding')
args = parser.parse_args()
source = args.source_dir.resolve(strict=True)
reports = args.reports_dir.resolve()
commit = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
if commit != '5a2162bea6845eabc1fc721624a43568c65db3b1':
    raise SystemExit('VMR commit mismatch')
if args.quarantine_build_state:
    state = source / 'artifacts' / 'obj'
    backup = source / 'artifacts' / 'obj-attempts-1-2'
    if state.is_symlink() or backup.exists() or backup.is_symlink():
        raise SystemExit('Refusing unsafe or existing build-state backup path')
    if state.is_dir():
        if not state.resolve().is_relative_to(source):
            raise SystemExit('Build state is outside the selected VMR')
        state.rename(backup)
        print(f'Preserved previous build state at {backup}')
old = 'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public/nuget/v3/index.json'
new = 'https://api.nuget.org/v3/index.json'
paths = [source / 'NuGet.config', *sorted((source / 'src').glob('*/NuGet.config')),
         *sorted((source / 'artifacts' / 'obj').glob('*/NuGet.config'))]
records = []
for path in paths:
    if not path.is_file():
        continue
    relative = path.relative_to(source).as_posix()
    generated = relative.startswith('artifacts/')
    original = path.read_bytes() if generated else subprocess.check_output(
        ['git', '-C', str(source), 'show', f'HEAD:{relative}'])
    text = original.decode('utf-8-sig')
    document = ET.fromstring(text)
    if document.find('packageSources') is None:
        continue
    text = text.replace(old, new)
    entry = '    <add key="maxHttpRequestsPerSource" value="8" />\n'
    current_limit = document.find("config/add[@key='maxHttpRequestsPerSource']")
    if current_limit is not None:
        if current_limit.get('value') != '8':
            raise SystemExit(f'Unexpected HTTP limit in {relative}')
    elif document.find('config') is not None:
        text = text.replace('</config>', entry + '  </config>', 1)
    else:
        text = text.replace('</configuration>', '  <config>\n' + entry + '  </config>\n</configuration>', 1)
    prefix = b'\xef\xbb\xbf' if original.startswith(b'\xef\xbb\xbf') else b''
    previous_encoded = prefix + text.encode('utf-8')
    if document.find("packageSources/add[@key='pinned-microsoft']") is None:
        text = text.replace('</packageSources>', '    <add key="pinned-microsoft" value="/inputs/nuget" />\n  </packageSources>', 1)
    encoded = prefix + text.encode('utf-8')
    ET.fromstring(encoded)
    current = path.read_bytes()
    if current not in (original, previous_encoded, encoded):
        raise SystemExit(f'Refusing unexpected local changes: {relative}')
    path.write_bytes(encoded)
    records.append({'path': relative, 'originalSha256': hashlib.sha256(original).hexdigest(),
                    'adjustedSha256': hashlib.sha256(encoded).hexdigest(),
                    'generated': generated,
                    'publicFeedReplaced': old in original.decode('utf-8-sig')})
invalidated = []
state_root = source / 'artifacts' / 'obj'
for marker in sorted(state_root.glob('*/UpdateNuGetConfig.complete')):
    if marker.is_symlink() or not marker.resolve().is_relative_to(state_root.resolve()):
        raise SystemExit(f'Unsafe generated cache marker: {marker}')
    marker.unlink()
    invalidated.append(marker.relative_to(source).as_posix())
reports.mkdir(parents=True, exist_ok=True)
(reports / 'feed-adjustments.json').write_text(json.dumps({
    'sourceCommit': commit, 'publicFeed': new, 'maxHttpRequestsPerSource': 8,
    'pinnedMicrosoftFeed': '/inputs/nuget',
    'packageVersionsChanged': False, 'files': records,
    'invalidatedGeneratedConfigMarkers': invalidated}, indent=2) + '\n', encoding='utf-8')
patch = subprocess.check_output(['git', '-C', str(source), 'diff', '--no-ext-diff', '--',
                                 *[record['path'] for record in records if not record['generated']]])
(reports / 'feed-adjustments.patch').write_bytes(patch)
print(f'Configured and recorded {len(records)} NuGet configuration files.')
