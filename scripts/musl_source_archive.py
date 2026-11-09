"""Optional private seekable byte transport for SDK6/SDK7 source revalidation.

This caches no validation result or source interpretation. Every consumer still
reads and checks the original TAR headers and member bytes independently.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import time

try:
    import resource
except ImportError:
    resource = None

FP = ('bytes', 'sha256', 'sha512')
MAX_RAW_BYTES = 64 * 1024**3
RESERVE_BYTES = 1024**3
BLOCK = 1024**2
_ACTIVE = ContextVar('musl_source_archive_bytes', default=None)


def require(value, message):
    if not value:
        raise ValueError(message)


def portable(value):
    require(isinstance(value, str) and value and not any(c in value for c in '\\\0\r\n')
            and not PurePosixPath(value).is_absolute()
            and all(part not in ('', '.', '..') for part in value.split('/')),
            'Ordinary relative source archive path required')
    return value


def ordinary(path, *, directory=False):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)),
            'Source archive byte transport forbids linked paths')
    mode = path.lstat().st_mode
    require(stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode),
            'Ordinary source archive byte transport path required')
    return path


def identity(descriptor):
    require(type(descriptor.get('bytes')) is int and descriptor['bytes'] > 0
            and all(isinstance(descriptor.get(key), str)
                    and re.fullmatch('[a-f0-9]{' + str(length) + '}', descriptor[key])
                    for key, length in (('sha256', 64), ('sha512', 128))),
            'Exact source archive byte fingerprints required')
    return {key: descriptor[key] for key in FP}


def fingerprint(path):
    hashes = {key: hashlib.new(key) for key in FP[1:]}
    size = 0
    with ordinary(path).open('rb') as stream:
        for raw in iter(lambda: stream.read(BLOCK), b''):
            size += len(raw)
            for digest in hashes.values():
                digest.update(raw)
    return dict(bytes=size, **{key: digest.hexdigest() for key, digest in hashes.items()})


def expansion_bound(release, manifest):
    """Capacity planning only; the original source verifier remains mandatory."""
    expected = identity(manifest['index'])
    hashes = {key: hashlib.new(key) for key in FP[1:]}
    size, count, bound = 0, 0, 10240
    path = ordinary(Path(release) / 'sources' / portable(manifest['index']['path']))
    with path.open('rb') as stream:
        for line in stream:
            size += len(line)
            for digest in hashes.values():
                digest.update(line)
            row = json.loads(line)
            require(type(row.get('bytes')) is int and row['bytes'] >= 0
                    and row.get('mode') in ('100644', '100755', '120000')
                    and isinstance(row.get('path'), str), 'Source capacity index row differs')
            payload = 0 if row['mode'] == '120000' else row['bytes']
            # Regular header, aligned body, and conservative path/link/size PAX
            # header allowance. The enforced absolute limit is independent of
            # these index-derived planning numbers.
            pax = 1024 + 2 * len(row['path'].encode('utf-8'))
            if row['mode'] == '120000':
                pax += 2 * row['bytes']
            bound += 512 + (payload + 511) // 512 * 512 + 512 + (pax + 511) // 512 * 512
            count += 1
    observed = dict(bytes=size, **{key: digest.hexdigest() for key, digest in hashes.items()})
    require(observed == expected and count == manifest.get('files'),
            'Source capacity index fingerprints or count differ')
    return bound


def supported():
    return os.name == 'posix' and hasattr(os, 'pread') and hasattr(os, 'O_NOFOLLOW')


def max_rss_bytes():
    """Linux ru_maxrss is KiB; unavailable measurements remain explicit null."""
    try:
        if resource is not None and sys.platform.startswith('linux'):
            return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024
    except (AttributeError, OSError, OverflowError, TypeError, ValueError):
        pass
    return None


def temporary_free_bytes(parent):
    try:
        return shutil.disk_usage(parent).free if parent is not None else None
    except (OSError, ValueError):
        return None


def observe(event, **values):
    """Best-effort stderr diagnostics, never evidence or an admission verdict."""
    try:
        print(json.dumps(dict(kind='musl-source-byte-transport-observation', event=event,
                              platform=sys.platform, maxRssBytes=max_rss_bytes(), **values),
                         sort_keys=True), file=sys.stderr, flush=True)
    except (OSError, TypeError, ValueError):
        pass


def copy_authenticated(source, destination, expected):
    """Authenticate exactly the compressed bytes copied, not two path stats."""
    hashes = {key: hashlib.new(key) for key in FP[1:]}
    size = 0
    with ordinary(source).open('rb') as incoming, destination.open('xb') as outgoing:
        for raw in iter(lambda: incoming.read(BLOCK), b''):
            size += len(raw)
            require(size <= expected['bytes'], 'Compressed source snapshot exceeds authenticated size')
            for digest in hashes.values():
                digest.update(raw)
            outgoing.write(raw)
    observed = dict(bytes=size, **{key: digest.hexdigest() for key, digest in hashes.items()})
    require(observed == expected, 'Compressed source snapshot fingerprints differ')


def readonly_unlinked(path):
    """Return the sole retained, read-only descriptor of a private byte file."""
    path.chmod(0o400)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_uid == os.getuid() and before.st_mode & 0o077 == 0,
            'Private ordinary source byte file required')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0))
    try:
        after = os.fstat(descriptor)
        require((before.st_dev, before.st_ino, before.st_size) == (after.st_dev, after.st_ino, after.st_size),
                'Private source byte file changed while opening')
        path.unlink()
        require(os.fstat(descriptor).st_nlink == 0, 'Private source byte file must be unlinked')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class ReadAt(io.RawIOBase):
    """Independent positions over one unlinked read-only file descriptor."""
    def __init__(self, descriptor, size):
        self.descriptor, self.size, self.position = descriptor, size, 0

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.position

    def seek(self, offset, whence=os.SEEK_SET):
        self._checkClosed()
        require(type(offset) is int and whence in (os.SEEK_SET, os.SEEK_CUR, os.SEEK_END),
                'Ordinary source byte seek required')
        position = offset + (0 if whence == os.SEEK_SET else self.position if whence == os.SEEK_CUR else self.size)
        require(position >= 0, 'Negative source byte seek forbidden')
        self.position = position
        return position

    def read(self, size=-1):
        self._checkClosed()
        require(type(size) is int, 'Ordinary source byte read size required')
        remaining = max(0, self.size - self.position)
        raw = os.pread(self.descriptor, remaining if size < 0 else min(size, remaining), self.position)
        self.position += len(raw)
        return raw

    def readinto(self, buffer):
        raw = self.read(len(buffer))
        buffer[:len(raw)] = raw
        return len(raw)


@contextmanager
def _source_session(release, manifest, temporary_parent, observations):
    """Optimize SDK6/SDK7, after the caller's complete original source verify.

    Unsupported platforms or insufficient preflight capacity retain the exact
    original gzip reader. Authentication, I/O and expansion failures never do.
    """
    require(_ACTIVE.get() is None, 'Nested source byte sessions are forbidden')
    require(manifest.get('sdkVersion') in ('6.0.136', '7.0.120'), 'Only reviewed SDK6/SDK7 source byte sessions are supported')
    if not supported():
        observe('fallback', reason='unsupported-platform', mode='gzip')
        yield False
        return
    release = ordinary(release, directory=True)
    source = ordinary(release / 'sources' / portable(manifest['archive']['path']))
    expected = identity(manifest['archive'])
    parent = ordinary(temporary_parent or tempfile.gettempdir(), directory=True)
    require(release not in (parent, *parent.parents),
            'Source byte workspace must be outside the delivery tree')
    observations['temporaryParent'] = parent
    bound = expansion_bound(release, manifest)
    required = bound + expected['bytes'] + RESERVE_BYTES
    available = None if bound > MAX_RAW_BYTES else shutil.disk_usage(parent).free
    if bound > MAX_RAW_BYTES or required > available:
        observe('fallback', reason='preflight-capacity', mode='gzip', rawBoundBytes=bound,
                compressedBytes=expected['bytes'], requiredTemporaryBytes=required,
                temporaryFreeBytes=available)
        yield False
        return
    with tempfile.TemporaryDirectory(prefix='cbodotnet-source-view-', dir=parent) as temporary:
        private = ordinary(temporary, directory=True)
        private.chmod(0o700)
        require(private.stat().st_mode & 0o077 == 0, 'Owner-only source byte workspace required')
        compressed, raw = private / 'authenticated.gz', private / 'source.tar'
        copy_authenticated(source, compressed, expected)
        compressed_fd = readonly_unlinked(compressed)
        size = 0
        with os.fdopen(compressed_fd, 'rb') as incoming, gzip.GzipFile(fileobj=incoming, mode='rb') as decoded, raw.open('xb') as outgoing:
            for block in iter(lambda: decoded.read(BLOCK), b''):
                size += len(block)
                require(size <= min(bound, MAX_RAW_BYTES), 'Source byte expansion exceeds its bounded capacity')
                outgoing.write(block)
        descriptor = readonly_unlinked(raw)
        token = _ACTIVE.set((source, expected, descriptor, size))
        try:
            observations['preparedAt'] = time.monotonic()
            observe('prepared', mode='seekable', rawBytes=size, compressedBytes=expected['bytes'],
                    preparationSeconds=round(observations['preparedAt'] - observations['startedAt'], 6),
                    requiredTemporaryBytes=required, temporaryFreeBytes=temporary_free_bytes(parent))
            yield True
        finally:
            _ACTIVE.reset(token)
            os.close(descriptor)
            require(fingerprint(source) == expected, 'Original compressed source bytes changed during revalidation')


@contextmanager
def source_session(release, manifest, *, temporary_parent=None):
    """Keep the bool transport API; observations never replace validation."""
    observations = dict(startedAt=time.monotonic())
    returned, mode = False, 'unprepared'
    try:
        with _source_session(release, manifest, temporary_parent, observations) as enabled:
            mode = 'seekable' if enabled else 'gzip'
            yield enabled
        returned = True
    finally:
        finished = time.monotonic()
        prepared = observations.get('preparedAt')
        observe('completed', mode=mode, outcome='returned' if returned else 'raised',
                durationSeconds=round(finished - observations['startedAt'], 6),
                revalidationSeconds=round(finished - prepared, 6) if prepared is not None else None,
                temporaryFreeBytes=temporary_free_bytes(observations.get('temporaryParent')))


@contextmanager
def open_source_archive(release, manifest):
    """Open headers and bytes afresh; never return a cached validation verdict."""
    path = Path(release).absolute() / 'sources' / portable(manifest['archive']['path'])
    active = _ACTIVE.get()
    if active is None:
        with tarfile.open(path, 'r|gz') as archive:
            yield archive
        return
    source, expected, descriptor, size = active
    require(path == source and identity(manifest['archive']) == expected,
            'Source byte session belongs to another archive identity')
    with ReadAt(descriptor, size) as view, tarfile.open(fileobj=view, mode='r:') as archive:
        yield archive
