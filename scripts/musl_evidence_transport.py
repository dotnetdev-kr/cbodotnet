"""Exact-byte multipart delivery of the complete producer evidence envelope."""
from contextlib import contextmanager
import hashlib
from pathlib import Path
import re
import tempfile

from downstream_release import encoded, ordinary_file, require
from musl_source_transport import asset, descriptor, digest_record, fingerprint, hashes

KIND = 'musl-producer-evidence-exact-byte-parts'
MAX_RELEASE_BYTES = 2 ** 31
PART_BYTES = 1024 ** 3
MAX_ARCHIVE_BYTES = 8 * 1024 ** 3
MAX_DESCRIPTOR_BYTES = 64 * 1024
CHUNK_BYTES = 1024 ** 2


def document(transport):
    return {key: value for key, value in transport.items() if key != 'descriptor'}


def validate(entry):
    transport = entry.get('evidenceTransport')
    require(isinstance(transport, dict) and set(transport) == {
        'schemaVersion', 'kind', 'archive', 'partSizeBytes', 'parts', 'descriptor'}
        and type(transport['schemaVersion']) is int and transport['schemaVersion'] == 1
        and transport['kind'] == KIND, 'An explicit closed evidence multipart transport is required')
    original = descriptor(transport['archive'], maximum=MAX_ARCHIVE_BYTES)
    require(original == entry.get('evidence') and original['name'].endswith('-evidence.tar.gz')
            and MAX_RELEASE_BYTES <= original['size'] < MAX_ARCHIVE_BYTES,
            'Multipart evidence must bind the unchanged oversized complete envelope')
    require(type(transport['partSizeBytes']) is int and transport['partSizeBytes'] == PART_BYTES
            and 0 < PART_BYTES < MAX_RELEASE_BYTES, 'Evidence multipart chunk size changed')
    parts = transport['parts']; count = (original['size'] + PART_BYTES - 1) // PART_BYTES
    require(isinstance(parts, list) and 2 <= count <= 8 and len(parts) == count,
            'Missing or unexpected evidence multipart members')
    for position, row in enumerate(parts):
        descriptor(row, original['name'] + '.part-' + str(position + 1).zfill(4), maximum=MAX_RELEASE_BYTES)
        require(row['size'] == min(PART_BYTES, original['size'] - position * PART_BYTES),
                'Evidence multipart order, boundary or size differs')
    raw = encoded(document(transport))
    expected = digest_record(original['name'] + '.transport.json', len(raw), {
        name: hashlib.new(name, raw) for name in ('sha256', 'sha512')})
    require(descriptor(transport['descriptor'], expected['name'], maximum=MAX_DESCRIPTOR_BYTES) == expected,
            'Evidence transport descriptor does not bind its exact canonical document')
    return transport


def validate_sidecar(entry, raw):
    transport = validate(entry)
    require(isinstance(raw, bytes) and raw == encoded(document(transport)),
            'Evidence transport sidecar differs from the authenticated release manifest')
    return transport


def evidence_assets(entry):
    if 'evidenceTransport' not in entry:
        row = entry['evidence']
        require(isinstance(row, dict) and set(row) == {'name', 'size', 'sha256'}
                and isinstance(row.get('name'), str)
                and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,181}-evidence\.tar\.gz', row['name']) is not None
                and isinstance(row.get('sha256'), str) and re.fullmatch('[a-f0-9]{64}', row['sha256'])
                and type(row.get('size')) is int and 0 < row['size'] < MAX_RELEASE_BYTES,
                'Oversized or extended evidence requires explicit evidence transport')
        return [row]
    transport = validate(entry)
    return [asset(transport['descriptor']), *(asset(row) for row in transport['parts'])]


def stage(path, output, name):
    """Preserve every gzip byte; only physical asset boundaries may change."""
    path = ordinary_file(path); before = path.stat(); output = Path(output).absolute()
    require(output.is_dir() and not any(p.is_symlink() for p in (output, *output.parents)),
            'Ordinary evidence multipart staging directory required')
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,181}-evidence\.tar\.gz', name) is not None,
            'Canonical complete evidence gzip name required')
    require(0 < before.st_size < MAX_ARCHIVE_BYTES, 'Complete evidence exceeds its reviewed transport bound')
    parts, size, whole = [], 0, hashes()
    multipart = before.st_size >= MAX_RELEASE_BYTES
    with path.open('rb') as stream:
        while size < before.st_size:
            part_name = name + '.part-' + str(len(parts) + 1).zfill(4) if multipart else name
            part_size, digests = 0, hashes()
            boundary = PART_BYTES if multipart else before.st_size
            with (output / part_name).open('xb') as target:
                while part_size < boundary and size < before.st_size:
                    raw = stream.read(min(CHUNK_BYTES, boundary - part_size, before.st_size - size))
                    require(raw, 'Complete evidence truncated during staging')
                    target.write(raw); part_size += len(raw); size += len(raw)
                    for digest in digests.values(): digest.update(raw)
                    for digest in whole.values(): digest.update(raw)
            parts.append(digest_record(part_name, part_size, digests))
        require(not stream.read(1), 'Complete evidence grew during staging')
    require((before.st_size, before.st_mtime_ns) == (path.stat().st_size, path.stat().st_mtime_ns),
            'Complete evidence changed during staging')
    original = digest_record(name, size, whole)
    if not multipart:
        return asset(original), None
    transport = dict(schemaVersion=1, kind=KIND, archive=original, partSizeBytes=PART_BYTES, parts=parts)
    raw = encoded(transport); sidecar = output / (name + '.transport.json')
    with sidecar.open('xb') as stream: stream.write(raw)
    transport['descriptor'] = fingerprint(sidecar)
    validate(dict(evidence=original, evidenceTransport=transport))
    return original, transport


def authenticate(entry, open_part, output):
    """Reassemble once into a fresh private file, checking both hashes at both levels."""
    transport = validate(entry); destination = Path(output).absolute()
    require(not destination.exists() and destination.parent.is_dir()
            and not any(p.is_symlink() for p in (destination, *destination.parents)),
            'Fresh ordinary reconstructed evidence gzip required')
    size, whole = 0, hashes()
    target = destination.open('xb')
    try:
        with target:
            for row in transport['parts']:
                part_size, digests = 0, hashes()
                with open_part(row) as stream:
                    while raw := stream.read(min(CHUNK_BYTES, row['size'] - part_size + 1)):
                        part_size += len(raw)
                        require(part_size <= row['size'], 'Evidence multipart member exceeds its authenticated size')
                        for digest in digests.values(): digest.update(raw)
                        for digest in whole.values(): digest.update(raw)
                        size += len(raw); target.write(raw)
                require(digest_record(row['name'], part_size, digests) == row,
                        'Evidence multipart member size or SHA-256/SHA-512 differs')
            actual = digest_record(transport['archive']['name'], size, whole)
            require(actual == transport['archive'], 'Reconstructed complete evidence size or SHA-256/SHA-512 differs')
        return actual
    except BaseException:
        if destination.exists(): destination.unlink()
        raise


@contextmanager
def materialize(entry, open_part, *, temporary_parent):
    """An owned temporary whole is never a public staging or retained consumer asset."""
    temporary_parent = Path(temporary_parent).absolute()
    require(temporary_parent.is_dir() and not any(p.is_symlink() for p in (temporary_parent, *temporary_parent.parents)),
            'Ordinary parent for private evidence materialization required')
    with tempfile.TemporaryDirectory(prefix='musl-evidence-private-', dir=temporary_parent) as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        output = directory / validate(entry)['archive']['name']
        authenticate(entry, open_part, output)
        yield output


@contextmanager
def materialize_directory(directory, entry):
    directory = Path(directory).absolute()
    require(directory.is_dir() and not any(p.is_symlink() for p in (directory, *directory.parents)),
            'Ordinary evidence physical asset directory required')
    evidence_assets(entry)
    if 'evidenceTransport' not in entry:
        path = ordinary_file(directory / entry['evidence']['name'])
        require(asset(fingerprint(path)) == entry['evidence'], 'Complete evidence physical bytes differ')
        yield path
        return
    transport = validate(entry); sidecar = ordinary_file(directory / transport['descriptor']['name'])
    require(sidecar.stat().st_size == transport['descriptor']['size'], 'Evidence multipart sidecar size differs')
    validate_sidecar(entry, sidecar.read_bytes())
    def open_part(row):
        path = ordinary_file(directory / row['name'])
        require(path.stat().st_size == row['size'], 'Evidence multipart physical member size differs')
        return path.open('rb')
    with materialize(entry, open_part, temporary_parent=directory.parent) as path:
        yield path
