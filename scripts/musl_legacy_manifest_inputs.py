"""Retain exact readable workload manifests without inventing Git provenance.

Only the eight reviewed package fingerprints are accepted. Their complete
original packages and every readable emitted JSON/MSBuild source are retained.
This policy neither imports workload binaries nor qualifies workload support.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import xml.etree.ElementTree as ET
import zipfile

FP = ('bytes', 'sha256', 'sha512')
ROOT_NAME = 'workload-manifest-data'
ROLE = 'readable-workload-manifest-source-inputs'
KIND = 'readable-workload-manifest'
POLICY_PATH = Path(__file__).with_name('musl-legacy-workload-manifest-policy.json')


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), sha512=hashlib.sha512(data).hexdigest())


def portable(name):
    require(isinstance(name, str) and name and '\\' not in name and ':' not in name and not any(c in name for c in '\0\r\n'),
            'Ordinary portable source input name required')
    path = PurePosixPath(name)
    require(not path.is_absolute() and '..' not in path.parts and path.as_posix() == name,
            'Source input path escapes its root')
    return name


def ordinary(path):
    path = Path(path).absolute()
    require(path.is_file() and not any(item.is_symlink() for item in (path, *path.parents)),
            'Ordinary unchanged manifest input required')
    return path


def policy():
    value = json.loads(POLICY_PATH.read_bytes())
    require(value['schemaVersion'] == 1 and value['sdkVersion'] == '7.0.120'
            and value['sourceRoot'] == ROOT_NAME and value['sourceRole'] == ROLE
            and len(value['packages']) == 8 and sum(len(row['layout']) for row in value['packages']) == 16,
            'Closed eight-package source policy required')
    return value['packages']


def jsonc(text):
    """Parse SDK JSON comments/trailing commas while preserving string bytes."""
    require(len(text) <= 65536, 'Bounded readable workload JSON required')
    output, index, quoted, escape = [], 0, False, False
    while index < len(text):
        char = text[index]
        if quoted:
            output.append(char)
            if escape: escape = False
            elif char == '\\': escape = True
            elif char == '"': quoted = False
            index += 1; continue
        if char == '"': quoted = True; output.append(char); index += 1; continue
        if text.startswith('//', index):
            end = text.find('\n', index + 2); end = len(text) if end < 0 else end
            output.extend(' ' * (end - index)); index = end; continue
        if text.startswith('/*', index):
            end = text.find('*/', index + 2); require(end >= 0, 'Unterminated JSON source comment')
            output.extend('\n' if c == '\n' else ' ' for c in text[index:end + 2]); index = end + 2; continue
        output.append(char); index += 1
    require(not quoted and not escape, 'Unterminated JSON source string')
    cleaned = ''.join(output); output, index, quoted, escape = [], 0, False, False
    while index < len(cleaned):
        char = cleaned[index]
        if quoted:
            output.append(char)
            if escape: escape = False
            elif char == '\\': escape = True
            elif char == '"': quoted = False
        elif char == '"': quoted = True; output.append(char)
        elif char == ',':
            look = index + 1
            while look < len(cleaned) and cleaned[look].isspace(): look += 1
            if look >= len(cleaned) or cleaned[look] not in '}]': output.append(char)
        else: output.append(char)
        index += 1
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate workload source JSON key'); result[key] = value
        return result
    result = json.loads(''.join(output), object_pairs_hook=unique)
    require(isinstance(result, dict), 'Workload manifest JSON object required')
    return result


def inspect(path):
    path = ordinary(path)
    require(path.stat().st_size <= 1024**2, 'Bounded original manifest package required')
    fp = fingerprint(path.read_bytes())
    rows = [row for row in policy() if row['fingerprint'] == fp]
    require(len(rows) == 1, 'Unreviewed readable-manifest package bytes')
    row = rows[0]
    expected = {entry['member']: entry for entry in row['entries']}
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(len(entries) == len(expected) and len({entry.filename for entry in entries}) == len(entries),
                'Manifest package has extra or duplicate entries')
        for entry in entries:
            name = portable(entry.filename)
            require(name in expected and not entry.is_dir() and (entry.external_attr >> 16) & 0o170000 != 0o120000
                    and entry.file_size <= 1024**2, 'Unexpected or redirected manifest package entry')
            raw = archive.read(entry)
            require(all(fingerprint(raw)[key] == expected[name][key] for key in FP)
                    and not raw.startswith((b'MZ', b'\x7fELF')), 'Manifest source/package entry bytes differ')
            if name == 'data/WorkloadManifest.json': jsonc(raw.decode('utf-8-sig'))
            if name == 'data/WorkloadManifest.targets':
                text = raw.decode('utf-8-sig')
                require('<!DOCTYPE' not in text.upper() and '<!ENTITY' not in text.upper(), 'Unsafe manifest XML source')
                require(ET.fromstring(text).tag.rsplit('}', 1)[-1] == 'Project', 'MSBuild source Project required')
    return row


def tree_files(row):
    result = {'packages/' + row['fingerprint']['sha256'] + '.nupkg': row['fingerprint']}
    result.update({'files/' + row['id'] + '/' + entry['member']: {key: entry[key] for key in FP}
                   for entry in row['entries']})
    return result


def prepare_tree(paths, destination):
    """Copy actual unchanged inputs and complete readable source, never execute."""
    destination = Path(destination).absolute(); observed = {}
    for path in paths:
        path = ordinary(path); fp = fingerprint(path.read_bytes())
        if not any(fp == row['fingerprint'] for row in policy()): continue
        row = inspect(path); observed[row['key']] = row
        bodies = {'packages/' + fp['sha256'] + '.nupkg': path.read_bytes()}
        with zipfile.ZipFile(path) as archive:
            bodies.update({'files/' + row['id'] + '/' + name: archive.read(name) for name in archive.namelist()})
        for relative, raw in bodies.items():
            target = destination / portable(relative); target.parent.mkdir(parents=True, exist_ok=True)
            require(not any(item.is_symlink() for item in (target, *target.parents)), 'Redirected source tree output')
            require(not target.exists() or target.read_bytes() == raw, 'Refusing to replace different manifest source')
            if not target.exists(): target.write_bytes(raw)
    require(set(observed) == {row['key'] for row in policy()}, 'All eight actual manifest inputs must be retained')
    expected = {name for row in policy() for name in tree_files(row)}
    require({path.relative_to(destination).as_posix() for path in destination.rglob('*') if path.is_file()} == expected,
            'Manifest source tree contains unexpected files')
    return dict(name=ROOT_NAME, kind='tree', path=str(destination), role=ROLE)


def validate_sources(release, manifest):
    roots = [root for root in manifest['roots'] if root['name'] == ROOT_NAME]
    require(len(roots) == 1 and roots[0]['kind'] == 'tree' and roots[0]['role'] == ROLE
            and roots[0].get('commit') is None, 'Literal manifest source tree may not claim Git provenance')
    expected = {ROOT_NAME + '/' + name: fp for row in policy() for name, fp in tree_files(row).items()}
    observed = {}
    with (Path(release) / 'sources' / portable(manifest['index']['path'])).open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'].startswith(ROOT_NAME + '/'):
                observed[row['path']] = row
    require(observed.keys() == expected.keys() and all(all(observed[name].get(key) == fp[key] for key in FP)
            for name, fp in expected.items()), 'Complete original packages and readable source bytes must be in the verified used-source archive')


def validate_artifact(release, artifact):
    require(artifact['kind'] == KIND and artifact['sourceRoot'] == ROOT_NAME and artifact['sourceCommit'] is None,
            'Readable manifest artifact role differs')
    path = ordinary(Path(release) / portable(artifact['path']))
    require(all(fingerprint(path.read_bytes())[key] == artifact[key] for key in FP), 'Readable source artifact identity differs')
    return inspect(path)
