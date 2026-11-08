#!/usr/bin/env python3
"""Prepare exact test-only native OmniSharp inputs for the original NET8 cases."""
import argparse
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SOURCE = '7d1bf90885cff22e7da72b27e9848e42fd3cb1ae'
TARGET = 'test/Microsoft.DotNet.SourceBuild.SmokeTests/Config.cs'
ORIGINAL_SHA = 'e3dadc33e8321c8a850a00a78973e9cdeacb651df0a80fe0e2063c8ced102e7c'
OLD = "TargetRid.Split('-')[1]"
NEW = "TargetRid.Split('-')[^1]"
DESTINATION = 'test/Microsoft.DotNet.SourceBuild.SmokeTests/bin/Release/net8.0/OmniSharpTests'
PINS = {
    'aarch64': (47154376, '4d01b45029809331854d7b27b5a45af72a49ad7da75b6aff77abc0ece0b72f62', 'arm64'),
    'x64': (49095403, '2350c1cfc7aa8e20389037ddc5b520c69f46ba43bcde892479877c1944695d14', 'x64'),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fingerprint(path):
    with path.open('rb') as stream:
        sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    return dict(bytes=path.stat().st_size, sha256=sha)


def utilities():
    spec = importlib.util.spec_from_file_location('net8_musl_original_fixture_archive', ROOT / 'scripts/prepare-net7-test-tools.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def patched(original):
    require(hashlib.sha256(original).hexdigest() == ORIGINAL_SHA, 'Unknown original NET8 test RID parser')
    text = original.decode('utf-8')
    require(text.count(OLD) == 1, 'Original NET8 architecture parser anchor differs')
    return text.replace(OLD, NEW).encode('utf-8')


def fixture(arch):
    size, sha, cpu = PINS[arch]
    name = 'omnisharp-linux-musl-' + cpu + '-net6.0.tar.gz'
    return dict(name=name, bytes=size, sha256=sha,
                url='https://github.com/OmniSharp/omnisharp-roslyn/releases/download/v1.39.14/' + name)


def verify(reports, arch, helper=Path(__file__)):
    record = json.loads((reports / 'net8-test-inputs.json').read_text())
    original, adjusted = reports / 'Config.original.cs', reports / 'Config.adjusted.cs'
    require(adjusted.read_bytes() == patched(original.read_bytes()), 'Recorded NET8 RID parser adaptation differs')
    pin = fixture(arch)
    archive = reports / pin['name']
    require(fingerprint(archive) == {k: pin[k] for k in ('bytes', 'sha256')}, 'Original musl OmniSharp fixture differs')
    require(record == dict(schemaVersion=1, sourceCommit=SOURCE, architecture=arch, target=TARGET,
        original=fingerprint(original), adjusted=fingerprint(adjusted), helper=fingerprint(helper),
        fixture=pin, originalMembers=utilities().archive_inventory(archive),
        assertionsChanged=False, caseRowsChanged=False, runtimeOverrides=False,
        source='Original NET8 test project; only the musl RID architecture parser and exact native test fixture are adapted.'),
        'NET8 test-only input receipt differs')
    return record


def prepare(source, reports, arch):
    require(source.is_absolute() and source.is_dir() and not any(p.is_symlink() for p in [source, *source.parents]),
            'An ordinary absolute pinned source checkout is required')
    git = lambda *args: subprocess.check_output(['git', '-C', str(source), *args])
    require(git('rev-parse', 'HEAD').decode().strip() == SOURCE, 'NET8 test source commit differs')
    original = git('show', 'HEAD:' + TARGET)
    adjusted = patched(original)
    target = source / TARGET
    require(target.is_file() and not target.is_symlink() and target.read_bytes() == original, 'Fresh original NET8 parser required')
    require(reports.is_absolute() and not reports.exists() and source not in reports.parents
            and not any(p.is_symlink() for p in reports.parents), 'Use a fresh ordinary external report path')
    destination = source / DESTINATION
    require(not destination.exists() and not any(p.is_symlink() for p in destination.parents), 'Fresh original OmniSharp fixture path required')
    reports.mkdir(parents=True)
    pin = fixture(arch)
    archive = reports / pin['name']
    with urllib.request.urlopen(pin['url'], timeout=120) as incoming, archive.open('xb') as output:
        total = 0
        while data := incoming.read(1024 * 1024):
            total += len(data)
            require(total <= pin['bytes'], 'Official NET8 test fixture exceeds the reviewed bound')
            output.write(data)
    require(fingerprint(archive) == {k: pin[k] for k in ('bytes', 'sha256')}, 'Downloaded official NET8 fixture differs')
    inventory = utilities().archive_inventory(archive, destination)
    for name, data in [('Config.original.cs', original), ('Config.adjusted.cs', adjusted)]:
        (reports / name).write_bytes(data)
    (reports / 'rid-parser.patch').write_text(''.join(difflib.unified_diff(
        original.decode().splitlines(True), adjusted.decode().splitlines(True), fromfile='a/' + TARGET, tofile='b/' + TARGET)))
    target.write_bytes(adjusted)
    record = dict(schemaVersion=1, sourceCommit=SOURCE, architecture=arch, target=TARGET,
        original=fingerprint(reports / 'Config.original.cs'), adjusted=fingerprint(reports / 'Config.adjusted.cs'),
        helper=fingerprint(Path(__file__)), fixture=pin, originalMembers=inventory,
        assertionsChanged=False, caseRowsChanged=False, runtimeOverrides=False,
        source='Original NET8 test project; only the musl RID architecture parser and exact native test fixture are adapted.')
    (reports / 'net8-test-inputs.json').write_text(json.dumps(record, indent=2) + '\n')
    verify(reports, arch)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--reports', type=Path, required=True)
    parser.add_argument('--arch', choices=sorted(PINS), required=True)
    args = parser.parse_args()
    prepare(args.source, args.reports, args.arch)
    print('Prepared exact original NET8 musl test input; assertions and case rows unchanged.')


if __name__ == '__main__':
    main()
