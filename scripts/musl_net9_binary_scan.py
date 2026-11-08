"""Honor the pinned NET9 BinaryToolKit's absence-on-zero result contract.

NET9 writes NewBinaries.txt only when detections exist and exits nonzero.
The original file is never synthesized. A separate observation binds the
successful invocation, original source and both actual updated policy files.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

SOURCE_COMMIT = '9f04b57d1366e21b3178648493d6edffeff2216e'
SOURCE_PATH = 'eng/tools/BinaryToolKit/BinaryTool.cs'
SOURCE = dict(bytes=3944, sha256='5f415cd32684b19a58e56e775e4113da2aacddf0948dcbefeb9ecf68e442aecf')
SOURCE_BLOB = '67907a22f3420acaebd6fa2a300e73ccdc15d328'
REPORT = 'original-net9-binary-scan.json'
UPDATED = ('Updatedallowed-vmr-binaries.txt', 'Updatedallowed-sb-binaries.txt')
COMMAND = ['/vmr/.dotnet/dotnet', '/vmr/artifacts/bin/BinaryToolKit/Release/BinaryToolKit.dll',
           'validate', '/clean', '-o', '/delivery/reports/scan', '-ab',
           '/clean/eng/allowed-vmr-binaries.txt', '-l', 'Debug']


def require(value, message):
    if not value: raise ValueError(message)


def observed_command():
    spec = importlib.util.spec_from_file_location('net9_scan_observation_primitives',
                                                   Path(__file__).with_name('musl-sdk.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module.Producer.observed_command(COMMAND)


def fingerprint(path):
    path = Path(path)
    require(path.is_file() and not any(parent.is_symlink() for parent in (path, *path.parents))
            and path.stat().st_size <= 16 * 1024**2,
            'Bounded ordinary original NET9 scan evidence required')
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def prepare(release):
    directory = Path(release) / 'reports/scan'
    require(not any(parent.is_symlink() for parent in (directory, *directory.parents)),
            'Original NET9 scan output may not redirect')
    require(all(not (directory / name).exists() and not (directory / name).is_symlink()
                for name in ('NewBinaries.txt', REPORT, 'scan.log', *UPDATED)),
            'Original NET9 validation requires fresh scan outputs')


def check_command(command):
    require(command.count('musl-sdk-observed-command') == 1
            and command[command.index('musl-sdk-observed-command') + 1:] == COMMAND
            and command.count('run') == 1,
            'Exact independent offline read-only original NET9 validation invocation required')
    # Parse engine options, rather than accepting a safe option followed by an
    # overriding network/mount/security flag. No unrecognized engine option is
    # permitted on this single version-specific scan route.
    index = command.index('run') + 1
    flags, values, environment, mounts = [], {}, {}, {}
    while index < len(command) and command[index].startswith('-'):
        option = command[index]; index += 1
        if option in ('--rm', '--network=none', '--cap-drop=all', '--security-opt=no-new-privileges'):
            require(option not in flags, 'Duplicate original NET9 container policy option')
            flags.append(option)
        elif re.fullmatch(r'--cpuset-cpus=[0-9]+(?:,[0-9]+)*', option):
            require('cpuset' not in values, 'Duplicate original NET9 CPU selection')
            values['cpuset'] = option
        else:
            require(option in ('--user', '--volume', '--env', '--workdir') and index < len(command),
                    'Unreviewed original NET9 container policy option')
            value = command[index]; index += 1
            if option == '--env':
                key, separator, body = value.partition('=')
                require(separator and key not in environment, 'Duplicate or invalid original NET9 environment')
                environment[key] = body
            elif option == '--volume':
                fields = value.split(':')
                require(len(fields) in (2, 3) and fields[0].startswith('/') and fields[1] not in mounts,
                        'Duplicate or invalid original NET9 mount')
                mounts[fields[1]] = fields[2] if len(fields) == 3 else 'rw'
            else:
                require(option not in values, 'Duplicate original NET9 container selection')
                values[option] = value
    require(set(flags) == {'--rm', '--network=none', '--cap-drop=all', '--security-opt=no-new-privileges'}
            and re.fullmatch(r'([1-9][0-9]*):\1', values.get('--user', ''))
            and values.get('--workdir') == '/clean'
            and mounts == {'/home/build': 'rw', '/vmr': 'ro', '/clean': 'ro', '/project': 'ro',
                           '/delivery': 'rw', '/diag': 'rw'},
            'Exact unique original NET9 non-root offline read-only container boundary required')
    roots = [key for key in environment if key in ('DOTNET_ROOT_ARM64', 'DOTNET_ROOT_X64')]
    require(len(roots) == 1 and environment == {
        'HOME': '/home/build', 'DOTNET_ROOT': '/vmr/.dotnet', roots[0]: '/vmr/.dotnet',
        'DOTNET_HOST_PATH': '/vmr/.dotnet/dotnet', 'MSBUILDDEBUGPATH': '/diag', 'MSBUILDDEBUGCOMM': '1'},
        'Exact private native NET9 scan bootstrap environment required')
    require(index + 4 < len(command) and re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', command[index])
            and command[index + 1:] == observed_command(),
            'Original NET9 scan must use the observed command in the immutable native image')


def observation(release, command, exit_code):
    require(exit_code == 0 and type(exit_code) is int,
            'Original NET9 BinaryToolKit must complete with exit code zero')
    check_command(command)
    directory = Path(release) / 'reports/scan'
    require(not (directory / 'NewBinaries.txt').exists() and not (directory / 'NewBinaries.txt').is_symlink(),
            'Original NET9 must leave NewBinaries.txt absent when no binaries are detected')
    log = directory / 'scan.log'
    log_fp = fingerprint(log)
    diagnostic_mounts = [value for index, value in enumerate(command)
                         if index > 0 and command[index - 1] == '--volume' and value.endswith(':/diag')]
    require(len(diagnostic_mounts) == 1, 'One actual original NET9 exit-code observation mount required')
    match = re.search(r'/reports/diagnostics/(container-[0-9]{4}):/diag$', diagnostic_mounts[0])
    require(match is not None, 'Original NET9 exit-code observation must use the retained diagnostic path')
    exit_path = Path(release) / 'reports/diagnostics' / match.group(1) / 'exit-code.txt'
    exit_fp = fingerprint(exit_path)
    require(exit_path.read_bytes() == b'0\n', 'Actual original NET9 binary validation exit code must be zero')
    text = log.read_text()
    require(all(marker in text for marker in ('in Validate mode', "Detecting binaries in '/clean'",
                'Finished binary detection.', 'Finished all binary tasks.'))
            and not any(marker in text for marker in ('ERROR:', 'fail: BinaryTool', 'New binaries:')),
            'Actual original NET9 binary validation did not complete cleanly')
    updated = {}
    for name in UPDATED:
        updated[name] = fingerprint(directory / name)
        require(updated[name]['bytes'] > 0 and ('/delivery/reports/scan/' + name) in text,
                'Both actual original NET9 updated policy reports are required')
    return dict(schemaVersion=1, kind='original-net9-binary-scan', sourceCommit=SOURCE_COMMIT,
                status='passed', exitCode=0, command=command,
                originalSource=dict(path=SOURCE_PATH, gitBlobSha1=SOURCE_BLOB, **SOURCE),
                newBinariesReport=dict(present=False, detectedBinaries=0,
                    basis='original-source-writes-report-only-for-nonzero-detections'),
                log=log_fp, exitCodeObservation=dict(path=exit_path.relative_to(release).as_posix(), **exit_fp),
                updatedPolicies=updated)


def record(release, source, command, exit_code):
    actual = fingerprint(Path(source) / SOURCE_PATH)
    require(all(actual[key] == value for key, value in SOURCE.items()),
            'Pinned original NET9 binary validation source differs')
    result = observation(release, command, exit_code)
    with (Path(release) / 'reports/scan' / REPORT).open('x') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')
    return result


def validate(release, commands, source_entries):
    selected = [command for command in commands if COMMAND[1] in command]
    require(len(selected) == 1, 'One actual original NET9 binary validation command required')
    require(source_entries.get(SOURCE_PATH) == dict(mode='100644', blob=SOURCE_BLOB),
            'Complete pristine source inventory must bind the pinned original NET9 validation contract')
    result = observation(release, selected[0], 0)
    require(json.loads((Path(release) / 'reports/scan' / REPORT).read_text()) == result,
            'Independent original NET9 binary scan observation differs')
    return result
