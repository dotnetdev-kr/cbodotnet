"""Exact-byte multipart delivery of an unchanged used-source gzip archive."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import tarfile

from downstream_release import encoded, ordinary_file, require

KIND = 'musl-used-source-exact-byte-parts'
MAX_RELEASE_BYTES = 2 ** 31
PART_BYTES = 1024 ** 3
MAX_ARCHIVE_BYTES = 8 * 1024 ** 3
MAX_DESCRIPTOR_BYTES = 16 * 1024 ** 2
CHUNK_BYTES = 1024 ** 2
FIELDS = ('name', 'size', 'sha256', 'sha512')


def hashes():
    return {name: hashlib.new(name) for name in ('sha256', 'sha512')}


def digest_record(name, size, digests):
    return dict(name=name, size=size, **{key: digest.hexdigest() for key, digest in digests.items()})


def fingerprint(path, name=None):
    path = ordinary_file(path); before = path.stat(); digests = hashes(); size = 0
    with path.open('rb') as stream:
        for raw in iter(lambda: stream.read(CHUNK_BYTES), b''):
            size += len(raw)
            for digest in digests.values(): digest.update(raw)
    require((before.st_size, before.st_mtime_ns) == (path.stat().st_size, path.stat().st_mtime_ns),
            'Source transport input changed during fingerprinting')
    return digest_record(name or path.name, size, digests)


def asset(row):
    """Release APIs use the existing three-field physical-asset descriptor."""
    return {key: row[key] for key in ('name', 'size', 'sha256')}


def descriptor(row, name=None, *, maximum=MAX_ARCHIVE_BYTES):
    require(isinstance(row, dict) and set(row) == set(FIELDS)
            and isinstance(row.get('name'), str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,220}', row['name'])
            and (name is None or row['name'] == name)
            and type(row.get('size')) is int and 0 < row['size'] < maximum
            and isinstance(row.get('sha256'), str) and re.fullmatch('[a-f0-9]{64}', row['sha256'])
            and isinstance(row.get('sha512'), str) and re.fullmatch('[a-f0-9]{128}', row['sha512']),
            'Invalid complete source transport fingerprint')
    return row


def document(transport):
    return {key: value for key, value in transport.items() if key != 'descriptor'}


def validate(entry):
    transport = entry.get('sourceTransport')
    require(isinstance(transport, dict) and set(transport) == {
        'schemaVersion', 'kind', 'archive', 'sourceManifest', 'sourceIndex', 'partSizeBytes', 'parts', 'descriptor'}
        and type(transport['schemaVersion']) is int and transport['schemaVersion'] == 1 and transport['kind'] == KIND,
        'An explicit closed source multipart transport is required')
    original = descriptor(transport['archive'])
    require(original == entry.get('source') and original['name'].endswith('.tar.gz')
            and MAX_RELEASE_BYTES <= original['size'] < MAX_ARCHIVE_BYTES,
            'Multipart source must bind the unchanged oversized whole gzip')
    descriptor(transport['sourceManifest'], 'source-manifest.json', maximum=MAX_DESCRIPTOR_BYTES)
    descriptor(transport['sourceIndex'], 'source-index.jsonl')
    require(type(transport['partSizeBytes']) is int and transport['partSizeBytes'] == PART_BYTES
            and 0 < PART_BYTES < MAX_RELEASE_BYTES, 'Source multipart chunk size changed')
    parts = transport['parts']
    count = (original['size'] + PART_BYTES - 1) // PART_BYTES
    require(isinstance(parts, list) and 2 <= count <= 8 and len(parts) == count,
            'Missing or unexpected source multipart members')
    for position, row in enumerate(parts):
        name = original['name'] + '.part-' + str(position + 1).zfill(4)
        descriptor(row, name, maximum=MAX_RELEASE_BYTES)
        require(row['size'] == min(PART_BYTES, original['size'] - position * PART_BYTES),
                'Source multipart order, boundary or size differs')
    raw = encoded(document(transport))
    expected = digest_record(original['name'] + '.transport.json', len(raw), {
        name: hashlib.new(name, raw) for name in ('sha256', 'sha512')})
    require(descriptor(transport['descriptor'], expected['name'], maximum=MAX_DESCRIPTOR_BYTES) == expected,
            'Source transport descriptor does not bind its exact canonical document')
    return transport


def validate_sidecar(entry, raw):
    transport = validate(entry)
    require(isinstance(raw, bytes) and raw == encoded(document(transport)),
            'Source transport sidecar differs from the authenticated release manifest')
    return transport


def source_assets(entry):
    if 'sourceTransport' not in entry:
        return [entry['source']]
    transport = validate(entry)
    return [asset(transport['descriptor']), *(asset(row) for row in transport['parts'])]


def stage(path, output, name, source_manifest, source_index, expected):
    """Copy once into either the legacy gzip or ordered immutable byte parts."""
    path = ordinary_file(path); output = Path(output).absolute(); before = path.stat()
    require(output.is_dir() and not any(p.is_symlink() for p in (output, *output.parents)),
            'Ordinary source multipart staging directory required')
    require(0 < before.st_size < MAX_ARCHIVE_BYTES, 'Used-source gzip exceeds its reviewed transport bound')
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,190}\.tar\.gz', name) is not None,
            'Canonical source gzip transport name required')
    if before.st_size < MAX_RELEASE_BYTES:
        target = output / name
        require(not target.exists(), 'Fresh source staging file required')
        shutil.copyfile(path, target)
        original = fingerprint(target, name)
        require(all(original[key] == expected['bytes' if key == 'size' else key] for key in ('size', 'sha256', 'sha512')),
                'Legacy source staging copy differs from the original source archive')
        return asset(original), None
    parts, size, whole = [], 0, hashes()
    with path.open('rb') as stream:
        while size < before.st_size:
            part_name = name + '.part-' + str(len(parts) + 1).zfill(4)
            part_size, digests = 0, hashes()
            with (output / part_name).open('xb') as target:
                while part_size < PART_BYTES and size < before.st_size:
                    raw = stream.read(min(CHUNK_BYTES, PART_BYTES - part_size, before.st_size - size))
                    require(raw, 'Original source gzip truncated during multipart staging')
                    target.write(raw); part_size += len(raw); size += len(raw)
                    for digest in digests.values(): digest.update(raw)
                    for digest in whole.values(): digest.update(raw)
            parts.append(digest_record(part_name, part_size, digests))
        require(not stream.read(1), 'Original source gzip grew during multipart staging')
    original = digest_record(name, size, whole)
    require(all(original[key] == expected['bytes' if key == 'size' else key] for key in ('size', 'sha256', 'sha512'))
            and (before.st_size, before.st_mtime_ns) == (path.stat().st_size, path.stat().st_mtime_ns),
            'Multipart source differs from the original source archive')
    transport = dict(schemaVersion=1, kind=KIND, archive=original,
        sourceManifest=fingerprint(source_manifest), sourceIndex=fingerprint(source_index),
        partSizeBytes=PART_BYTES, parts=parts)
    raw = encoded(transport)
    sidecar = output / (name + '.transport.json')
    with sidecar.open('xb') as stream: stream.write(raw)
    transport['descriptor'] = fingerprint(sidecar)
    validate(dict(source=original, sourceTransport=transport))
    return original, transport


def authenticate(entry, open_part, output=None):
    """Authenticate each bounded part and the complete concatenation before use."""
    transport = validate(entry); target = None; destination = None
    if output is not None:
        destination = Path(output).absolute()
        require(not destination.exists() and destination.parent.is_dir()
                and not any(p.is_symlink() for p in (destination, *destination.parents)),
                'Fresh ordinary reconstructed source gzip required')
        target = destination.open('xb')
    size, whole = 0, hashes()
    try:
        for row in transport['parts']:
            part_size, digests = 0, hashes()
            with open_part(row) as stream:
                while raw := stream.read(min(CHUNK_BYTES, row['size'] - part_size + 1)):
                    part_size += len(raw)
                    require(part_size <= row['size'], 'Source multipart member exceeds its authenticated size')
                    for digest in digests.values(): digest.update(raw)
                    for digest in whole.values(): digest.update(raw)
                    size += len(raw)
                    if target is not None: target.write(raw)
            require(digest_record(row['name'], part_size, digests) == row,
                    'Source multipart member size or SHA-256/SHA-512 differs')
        actual = digest_record(transport['archive']['name'], size, whole)
        require(actual == transport['archive'], 'Reconstructed source gzip size or SHA-256/SHA-512 differs')
        return actual
    except BaseException:
        if target is not None:
            target.close(); target = None
            destination.unlink()
        raise
    finally:
        if target is not None: target.close()


def verify_directory(directory, entry):
    directory = Path(directory).absolute(); transport = validate(entry)
    sidecar = ordinary_file(directory / transport['descriptor']['name'])
    require(sidecar.stat().st_size == transport['descriptor']['size'], 'Source multipart sidecar size differs')
    validate_sidecar(entry, sidecar.read_bytes())
    def open_part(row):
        path = ordinary_file(directory / row['name'])
        require(path.stat().st_size == row['size'], 'Source multipart physical member size differs')
        return path.open('rb')
    return authenticate(entry, open_part)


def source_controls(evidence, output=None, entry=None):
    """Stream original source controls from evidence, never source TAR members."""
    wanted = {'sources/source-manifest.json': MAX_DESCRIPTOR_BYTES, 'sources/source-index.jsonl': 2**31,
        'reports/ci/used-source.json': MAX_DESCRIPTOR_BYTES}
    found, names, metadata = {}, set(), {}
    with tarfile.open(ordinary_file(evidence), 'r|gz') as archive:
        for member in archive:
            name = member.name
            require(isinstance(name, str) and name and name not in names and len(names) < 100000
                    and not any(c in name for c in '\\:\0\r\n') and not name.startswith('/')
                    and all(part not in ('', '.', '..') for part in name.split('/')) and member.isfile(),
                    'Unsafe or duplicate source evidence member')
            names.add(name)
            if name not in wanted: continue
            require(0 < member.size <= wanted[name], 'Oversized source evidence control')
            digests, size = hashes(), 0
            body = bytearray() if name != 'sources/source-index.jsonl' else None
            target = None
            if output is not None:
                target_path = Path(output).absolute() / name
                require(not any(p.is_symlink() for p in (target_path, *target_path.parents)), 'Redirected source control output')
                target_path.parent.mkdir(parents=True, exist_ok=True); target = target_path.open('xb')
            try:
                with archive.extractfile(member) as source:
                    for raw in iter(lambda: source.read(CHUNK_BYTES), b''):
                        size += len(raw)
                        for digest in digests.values(): digest.update(raw)
                        if body is not None: body.extend(raw)
                        if target is not None: target.write(raw)
            finally:
                if target is not None: target.close()
            require(size == member.size, 'Truncated source evidence control')
            found[name] = digest_record(name.rsplit('/', 1)[-1], size, digests)
            if body is not None: metadata[name] = bytes(body)
    require(found.keys() == wanted.keys(), 'Original complete source manifest/index/control are required')
    require(metadata['sources/source-manifest.json'] == metadata['reports/ci/used-source.json'],
            'Original source manifest differs from its inventoried report control')
    original = json.loads(metadata['sources/source-manifest.json'])
    if entry is not None:
        transport = validate(entry)
        require(found['sources/source-manifest.json'] == transport['sourceManifest']
                and found['sources/source-index.jsonl'] == transport['sourceIndex'],
                'Multipart original source control fingerprint differs')
        require(original['archive']['bytes'] == transport['archive']['size']
                and all(original['archive'][key] == transport['archive'][key] for key in ('sha256', 'sha512'))
                and original['index']['path'] == transport['sourceIndex']['name']
                and original['index']['bytes'] == transport['sourceIndex']['size']
                and all(original['index'][key] == transport['sourceIndex'][key] for key in ('sha256', 'sha512')),
                'Multipart original whole archive or index binding differs')
        provenance = entry['provenance']
        require(original.get('projectCommit') == provenance['projectCommit']
                and str(original.get('runId')) == str(provenance['runId'])
                and str(original.get('runAttempt')) == str(provenance['runAttempt'])
                and original.get('targetRid') == entry['targetRid'],
                'Multipart source controls differ from their exact producer identity')
    return original
