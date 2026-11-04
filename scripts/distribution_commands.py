#!/usr/bin/env python3
"""Stage isolated versioned, common and container cbodotnet commands."""
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat

from distribution_contract import launcher_text

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def absolute_posix(value):
    value = str(value)
    path = PurePosixPath(value)
    require(path.is_absolute() and str(path) == value and '..' not in path.parts
            and value != '/' and not any(c in value for c in '\\:\0\r\n'), 'Unsafe command installation path')
    return value


def default_launcher_text(root_parent='/opt/cbodotnet', bin_dir='/usr/bin'):
    """Return a POSIX shell dispatcher without a Python runtime dependency."""
    root_parent = absolute_posix(root_parent)
    bin_dir = absolute_posix(bin_dir)
    template = (ROOT / 'scripts/cbodotnet-default.sh.in').read_text(encoding='utf-8')
    replacements = {'@ROOT_PARENT@': shlex.quote(root_parent), '@BIN_DIR@': shlex.quote(bin_dir)}
    return re.sub(r'@(?:ROOT_PARENT|BIN_DIR)@', lambda match: replacements[match[0]], template)


def forwarding_launcher_text(target):
    """Pin container aliases to an explicit versioned launcher, never PATH."""
    return '#!/bin/sh\nexec ' + shlex.quote(absolute_posix(target)) + ' "$@"\n'


def stage_commands(prefix, plan, mode='package', runtime_prefix=None):
    """Stage wrapper files and return their added-file inventory.

    ``prefix`` is the package/image staging tree. Normal generated wrappers use
    final absolute runtime paths. Set ``runtime_prefix=prefix`` only to execute
    the same layout in a private-prefix test. SDK packages own versioned
    launchers; the separately installed cbodotnet-host package owns the common
    launcher. OCI aliases select the image's explicit SDK even if another root
    happens to be present.
    """
    require(mode in {'package', 'oci'}, 'Unknown command staging mode')
    require(isinstance(plan, dict), 'A verified preparation plan is required')
    version = plan.get('sdkVersion', '')
    require(isinstance(version, str) and re.fullmatch(r'[1-9][0-9]*\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)', version),
            'An exact stable SDK version is required')
    series = '.'.join(version.split('.')[:2])
    require(all(len(part) <= 9 for part in series.split('.')), 'SDK series exceeds supported command selection range')
    package = plan.get('package', {})
    require(package.get('root') == '/opt/cbodotnet/' + series
            and package.get('launcher') == '/usr/bin/cbodotnet-' + series
            and package.get('name') == 'cbodotnet-sdk-' + series, 'Command namespace collision')
    arch = plan.get('architecture', {}).get('public')
    require(arch in {'x64', 'aarch64'}, 'Unknown public architecture')
    prefix = Path(prefix).absolute()
    require(prefix != Path('/') and prefix.is_dir()
            and not any(path.is_symlink() for path in [prefix, *prefix.parents]), 'An ordinary command staging prefix is required')
    if runtime_prefix is not None:
        runtime_prefix = absolute_posix(runtime_prefix)

    def runtime(path):
        return (runtime_prefix.rstrip('/') + path) if runtime_prefix is not None else path

    versioned = package['launcher']
    default = '/usr/bin/cbodotnet'
    files = {
        versioned: (launcher_text(runtime(package['root']), arch, plan=plan), package['name']),
        default: (default_launcher_text(runtime('/opt/cbodotnet'), runtime('/usr/bin')), 'cbodotnet-host'),
    }
    if mode == 'oci':
        # One image advertises one SDK; every image command pins that SDK.
        forward = forwarding_launcher_text(runtime(versioned))
        files[default] = (forward, 'cbodotnet-host')
        for name in ('cbodotnet-' + series, 'cbodotnet', 'dotnet'):
            files['/usr/local/bin/' + name] = (forward, package['name'])

    # Check every target before writing anything, including matching reruns.
    prepared = []
    for relative, (content, owner) in sorted(files.items()):
        path = prefix / relative.lstrip('/')
        require(prefix in path.parents and not any(parent.is_symlink() for parent in [path, *path.parents]),
                'Command staging path contains a link')
        require(all(not parent.exists() or parent.is_dir() for parent in path.parents), 'Command parent is not a directory')
        data = content.encode('utf-8')
        if path.exists():
            require(path.is_file() and path.read_bytes() == data and stat.S_IMODE(path.stat().st_mode) == 0o755,
                    'Refusing to replace a conflicting command: ' + relative)
        prepared.append((path, data, relative, owner))
    inventory = []
    for path, data, relative, owner in prepared:
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as stream:
                stream.write(data)
            os.chmod(path, 0o755)
        inventory.append({'path': relative, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                          'mode': '0755', 'owner': owner})
    return inventory
