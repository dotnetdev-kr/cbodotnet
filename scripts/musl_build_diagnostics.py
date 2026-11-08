"""Retain bounded source-assets failure evidence without changing build policy."""
import hashlib
import json
import os
from pathlib import Path
import stat


def capture(source, output):
    source, output = Path(source), Path(output)
    output.mkdir(parents=True, exist_ok=True)
    relative = 'src/source-build-assets/'
    inner = relative + 'artifacts/source-build/self/src/'
    paths = {relative + name for name in ('eng/Build.props', 'Directory.Build.props', 'Directory.Build.targets',
        'src/referencePackages/Directory.Build.props', 'src/referencePackages/Directory.Build.targets')}
    paths.update(inner + name for name in ('eng/Build.props', 'Directory.Build.props', 'Directory.Build.targets',
        'src/referencePackages/Directory.Build.props', 'src/referencePackages/Directory.Build.targets',
        'artifacts/sourcebuild.binlog'))
    paths.update((relative + 'artifacts/log/Release/Build.binlog', 'artifacts/logs/source-build-assets.log'))
    component = source / relative / 'artifacts'
    for pattern in ('*.binlog', '*.nuget.dgspec.json'):
        for path in component.rglob(pattern):
            if len(paths) >= 256: break
            paths.add(path.relative_to(source).as_posix())
    result = dict(schemaVersion=1, kind='bounded-source-assets-diagnostics', qualificationAllowed=False,
                  sourceAdmissionAllowed=False, files=[], skipped=[])
    total = 0
    for name in sorted(paths):
        path = source / name
        try:
            if any(parent.is_symlink() for parent in (path, *path.parents)):
                raise ValueError('Redirected source diagnostic path')
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as stream:
                before = os.fstat(stream.fileno())
                limit = 256 * 1024**2 if name.endswith('.binlog') else 16 * 1024**2
                if not stat.S_ISREG(before.st_mode) or before.st_size > limit or len(result['files']) >= 128 or total + before.st_size > 512 * 1024**2:
                    raise ValueError('Nonordinary or oversized source diagnostic')
                destination = output / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256(); size = 0
                with destination.open('xb') as target:
                    for block in iter(lambda: stream.read(1024 * 1024), b''):
                        target.write(block); digest.update(block); size += len(block)
                after = os.fstat(stream.fileno())
                if size != before.st_size or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    raise ValueError('Source diagnostic changed during capture')
                total += size
                result['files'].append(dict(path=name, bytes=size, sha256=digest.hexdigest()))
        except (OSError, ValueError) as error:
            result['skipped'].append(dict(path=name, reason=str(error)))
    (output / 'capture.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
