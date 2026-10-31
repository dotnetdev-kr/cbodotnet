#!/usr/bin/env python3
"""Validate and inventory the one completed Core 3.1 sysroot recovery attempt.

This finalizer never runs debootstrap, apt, the producer or a build target. It
accepts only the recorded native ARM64 Xenial attempt whose frozen wrapper
rejected the older authenticated signature-log wording after production.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import tempfile


SOURCE = Path('/home/build/cbodotnet/core31/work/source-build-3.1.426')
ROOTFS = Path('/home/build/cbodotnet/core31/inputs/arm64-xenial')
REPORTS = Path('/mnt/d/Projects/cbodotnet/artifacts/3.1.426-linux-arm64/reports/sysroot')
SOURCE_COMMIT = 'ab8b115b5658237ee8916ae3586600b39fb2fd19'
COREFX_COMMIT = 'b58ef0a19eca6269799664d6288be14b7f0cef3e'
LOG_NAME = 'sysroot-prepare-20261030T164151-1.log'
LOG_SHA256 = '978dd13f8d1965dcf0e48afbe31390cd07f67bb0f2b0205db7f8846d0de5e516'
HELPER_SHA256 = 'd4477cd1023068825836d5de3ad5e1aff939f07c4c41b4206f5c9d03b8490c35'
SIGNING_FINGERPRINT = '790BC7277767219C42C86F933B4FE6ACC0B21F32'
PACKAGES = ['build-essential', 'symlinks', 'libicu-dev', 'liblttng-ust-dev',
            'libunwind8-dev', 'libcurl4-openssl-dev', 'libkrb5-dev', 'libssl-dev', 'zlib1g-dev']
OUTPUTS = ['sysroot-files.sha256', 'sysroot-file-list.sha256', 'sysroot-symlinks.tsv',
           'sysroot-packages.tsv', 'sysroot-recovery.json', 'sysroot-provenance.json']


def digest(path):
    value, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk); size += len(chunk)
    return {'path': str(path), 'bytes': size, 'sha256': value.hexdigest()}


def ordinary(path, directory=False):
    if not path.is_absolute():
        raise ValueError('Absolute paths are required')
    for ancestor in [path] + list(path.parents):
        if ancestor.is_symlink():
            raise ValueError('Symlinks are not allowed in control paths: ' + str(path))
    if not (path.is_dir() if directory else path.is_file()):
        raise ValueError('Missing ordinary control path: ' + str(path))
    return path.resolve(strict=True)


def run(*arguments):
    process = subprocess.run([str(arg) for arg in arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.returncode:
        raise ValueError('Validation command failed: ' + str(arguments[0]) + ': ' + process.stderr.decode('utf-8', 'replace'))
    return process.stdout


def git(source, *arguments):
    return run('git', '--no-optional-locks', '-c', 'safe.directory=' + str(source), '-C', source, *arguments)


def mount_decode(value):
    return re.sub(r'\\([0-7]{3})', lambda match: chr(int(match.group(1), 8)), value)


def assert_unmounted(rootfs):
    nested = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split()
        if len(fields) < 6:
            raise ValueError('Malformed mount information')
        mount = Path(mount_decode(fields[4]))
        if mount == rootfs or rootfs in mount.parents:
            nested.append(str(mount))
    if nested:
        raise ValueError('The completed sysroot still contains active mounts: ' + ', '.join(nested))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--sysroot', type=Path, required=True)
    parser.add_argument('--reports-dir', type=Path, required=True)
    parser.add_argument('--owner-uid', type=int, required=True)
    parser.add_argument('--owner-gid', type=int, required=True)
    parser.add_argument('--original-helper-exit-code', type=int, choices=[1], required=True,
                        help='Explicitly record the observed original wrapper exit code')
    parser.add_argument('--producer-exit-code', type=int, choices=[0], required=True,
                        help='Explicitly record the observed producer pipeline exit code')
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'aarch64' or os.geteuid() != 0:
        raise ValueError('A native Linux ARM64 privileged validation container is required')
    source, rootfs, reports = (ordinary(args.source_dir, True), ordinary(args.sysroot, True), ordinary(args.reports_dir, True))
    if (source, rootfs, reports) != (SOURCE, ROOTFS, REPORTS):
        raise ValueError('This recovery helper accepts only the exact recorded source, target and report paths')
    if args.owner_uid != 1000 or args.owner_gid != 1000 or source.stat().st_uid != args.owner_uid:
        raise ValueError('The recorded unprivileged source owner is UID:GID1000:1000')
    os.environ['SUDO_UID'] = str(args.owner_uid)
    for name in OUTPUTS:
        destination = reports / name
        if destination.exists() or destination.is_symlink():
            raise ValueError('Refusing an existing finalization output: ' + str(destination))
    if git(source, 'rev-parse', '--show-toplevel').decode().strip() != str(source) or git(source, 'rev-parse', 'HEAD').decode().strip() != SOURCE_COMMIT:
        raise ValueError('Pinned source-build checkout mismatch')
    manifest = ordinary(source / 'eng/Version.Details.xml')
    if manifest.read_bytes() != git(source, 'show', SOURCE_COMMIT + ':eng/Version.Details.xml'):
        raise ValueError('Pinned root manifest changed')
    corefx = ordinary(source / 'artifacts/src' / ('corefx.' + COREFX_COMMIT), True)
    bare = ordinary(source / '.git/modules/src/corefx.git', True)
    inputs = []
    for relative in ['cross/build-rootfs.sh', 'cross/arm64/sources.list.xenial']:
        path = ordinary(corefx / relative)
        original = run('git', '-c', 'safe.directory=' + str(bare), '--git-dir=' + str(bare), 'show', COREFX_COMMIT + ':' + relative)
        if path.read_bytes() != original:
            raise ValueError('The producer input differs from its pinned CoreFX blob: ' + relative)
        inputs.append(digest(path))
    helper, log = ordinary(reports / 'prepare-sysroot-core31.sh'), ordinary(reports / LOG_NAME)
    if digest(helper)['sha256'] != HELPER_SHA256 or digest(log)['sha256'] != LOG_SHA256:
        raise ValueError('The exact frozen producer wrapper or preserved log differs')
    lines = log.read_text().splitlines()
    signature = 'I: Valid Release signature (key id ' + SIGNING_FINGERPRINT + ')'
    invocation = 'I: Running command: debootstrap --arch arm64 xenial ' + str(rootfs) + ' http://ports.ubuntu.com/'
    if (lines.count(signature) != 1 or lines.count('I: Checking Release signature') != 1
            or lines.index(signature) <= lines.index('I: Checking Release signature') or invocation not in lines
            or not any('Base system installed successfully.' in line for line in lines)):
        raise ValueError('The recorded authenticated ARM64 Xenial production evidence is incomplete')
    assert_unmounted(rootfs)
    # Xenial intentionally links /etc/os-release to its in-rootfs /usr copy.
    os_release_path = (rootfs / 'etc/os-release').resolve(strict=True)
    if rootfs not in os_release_path.parents or not os_release_path.is_file():
        raise ValueError('The OS-release link must resolve to an ordinary file within the target')
    os_release = os_release_path.read_text()
    if not re.search(r'^ID=ubuntu$', os_release, re.M) or not re.search(r'^VERSION_ID="16\.04"$', os_release, re.M):
        raise ValueError('The target is not the recorded Ubuntu Xenial rootfs')
    if run('chroot', rootfs, 'dpkg', '--print-architecture').decode().strip() != 'arm64':
        raise ValueError('The target package architecture is not ARM64')
    statuses = run('chroot', rootfs, 'dpkg-query', '-W', '-f=${binary:Package}\t${Status}\t${Version}\t${Architecture}\n', *(PACKAGES + ['libc6'])).decode().splitlines()
    package_records = []
    for line in statuses:
        fields = line.split('\t')
        if len(fields) != 4 or fields[1] != 'install ok installed' or fields[3] not in ('arm64', 'all'):
            raise ValueError('A required target package is not fully installed: ' + line)
        package_records.append(dict(zip(['package', 'status', 'version', 'architecture'], fields)))
    names = {record['package'].split(':')[0] for record in package_records}
    libc = [record for record in package_records if record['package'].split(':')[0] == 'libc6']
    if names != set(PACKAGES + ['libc6']) or len(libc) != 1 or libc[0]['architecture'] != 'arm64' or not re.match(r'^2\.23(?:-|$)', libc[0]['version']):
        raise ValueError('The complete required package set and ARM64 libc2.23 must be present')
    packages = run('chroot', rootfs, 'dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${Architecture}\n')
    keyring = ordinary(Path('/usr/share/keyrings/ubuntu-archive-keyring.gpg'))
    current = ordinary(Path('/usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg'))
    historical = ordinary(Path('/usr/share/keyrings/ubuntu-archive-removed-keys.gpg'))
    if keyring.read_bytes() != current.read_bytes() + historical.read_bytes():
        raise ValueError('The verification keyring differs from the declared current/historical union')
    signed_releases = []
    for suite in ['xenial', 'xenial-updates', 'xenial-backports', 'xenial-security']:
        path = ordinary(rootfs / 'var/lib/apt/lists' / ('ports.ubuntu.com_ubuntu-ports_dists_' + suite + '_InRelease'))
        status = run('gpgv', '--status-fd', '1', '--keyring', keyring, path).decode()
        fingerprints = re.findall(r'^\[GNUPG:\] VALIDSIG ([A-F0-9]{40}) ', status, re.M)
        if SIGNING_FINGERPRINT not in fingerprints:
            raise ValueError('Retained target archive signature lacks the expected signing fingerprint: ' + suite)
        signed_releases.append(dict(digest(path), validSigningFingerprints=fingerprints))
    assert_unmounted(rootfs)
    staging = Path(tempfile.mkdtemp(prefix='.core31-finalization-', dir=str(reports)))
    file_lines, link_lines, special_entries, owned_paths = [], [], [], [rootfs]
    for current_dir, directories, files in os.walk(str(rootfs), followlinks=False):
        for name in sorted(directories + files):
            path = Path(current_dir) / name
            if '\n' in str(path) or '\t' in str(path) or '\\' in str(path):
                raise ValueError('Unsupported inventory path')
            owned_paths.append(path)
            if path.is_symlink():
                target = os.readlink(str(path))
                if '\n' in target or '\t' in target:
                    raise ValueError('Unsupported inventory symlink target')
                link_lines.append(str(path) + '\t' + target + '\n')
            elif path.is_file():
                file_lines.append(digest(path)['sha256'] + '  ' + str(path) + '\n')
            elif not path.is_dir():
                info = path.lstat()
                # Debootstrap creates static /dev nodes. Record their metadata
                # without opening a device or treating it as a hashable file.
                if rootfs / 'dev' not in path.parents or not (stat.S_ISCHR(info.st_mode) or stat.S_ISBLK(info.st_mode)):
                    raise ValueError('Unexpected special entry in the completed sysroot: ' + str(path))
                special_entries.append({'path': str(path), 'kind': 'character' if stat.S_ISCHR(info.st_mode) else 'block',
                                        'mode': oct(stat.S_IMODE(info.st_mode)), 'major': os.major(info.st_rdev), 'minor': os.minor(info.st_rdev)})
    if not file_lines:
        raise ValueError('The completed sysroot has no ordinary files')
    inventory = ''.join(sorted(file_lines)).encode()
    (staging / 'sysroot-files.sha256').write_bytes(inventory)
    (staging / 'sysroot-file-list.sha256').write_text(hashlib.sha256(inventory).hexdigest() + '  ' + str(reports / 'sysroot-files.sha256') + '\n')
    (staging / 'sysroot-symlinks.tsv').write_text(''.join(sorted(link_lines)))
    (staging / 'sysroot-packages.tsv').write_bytes(packages)
    recovered = {'schemaVersion': 1, 'finalizedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 'reason': 'The unchanged producer completed, but its frozen wrapper expected the newer Release signature verified wording instead of Focal debootstrap Valid Release signature.',
                 'originalHelper': dict(digest(helper), observedExitCode=args.original_helper_exit_code),
                 'producer': {'observedPipelineExitCode': args.producer_exit_code, 'rerun': False},
                 'historicalExitCodeEvidence': 'Explicit caller-supplied observations, retained separately from the current validation result.',
                 'originalLog': digest(log), 'authenticatedSignatureLine': signature,
                 'signingKeyFingerprint': SIGNING_FINGERPRINT, 'requiredPackages': package_records,
                 'retainedReleaseSignatures': signed_releases, 'nestedMounts': [], 'currentValidation': 'passed',
                 'ownershipChange': {'target': str(rootfs), 'uid': args.owner_uid, 'gid': args.owner_gid, 'followSymlinks': False},
                 'producerInputs': inputs, 'finalizer': digest(Path(__file__).resolve())}
    recovered['staticDeviceNodes'] = special_entries
    provenance = {'sourceCommit': SOURCE_COMMIT, 'corefxCommit': COREFX_COMMIT,
                  'generator': str((corefx / 'cross/build-rootfs.sh').relative_to(source)),
                  'generatorSha256': inputs[0]['sha256'], 'generatorArguments': ['arm64', 'xenial', 'no-lldb'],
                  'generatorEnvironment': {'ROOTFS_DIR': str(rootfs)}, 'packageSignatureVerification': True,
                  'signingKeyFingerprint': SIGNING_FINGERPRINT, 'emulation': False, 'qemuDebootstrapWrapper': True,
                  'logFile': str(log), 'keyrings': [digest(path) for path in [keyring, current, historical]],
                  'gitOwnerContext': {'sourceOwnerUid': args.owner_uid, 'sudoUid': args.owner_uid, 'globalGitConfigurationChanged': False},
                  'finalizedAtUtc': recovered['finalizedAtUtc'], 'recoveryReport': 'sysroot-recovery.json',
                  'files': len(file_lines), 'symlinks': len(link_lines), 'staticDeviceNodes': len(special_entries)}
    for name, record in [('sysroot-recovery.json', recovered), ('sysroot-provenance.json', provenance)]:
        (staging / name).write_text(json.dumps(record, indent=2) + '\n')
    # Only this exact newly produced rootfs changes ownership. Never traverse
    # symlink targets or change unrelated source/input caches.
    for path in owned_paths:
        os.chown(str(path), args.owner_uid, args.owner_gid, follow_symlinks=False)
    for name in OUTPUTS:
        output = reports / name
        if output.exists() or output.is_symlink():
            raise ValueError('A finalization output appeared during validation')
    for name in OUTPUTS:
        path = staging / name
        os.chown(str(path), args.owner_uid, args.owner_gid)
        os.link(str(path), str(reports / name))
    print(json.dumps({'status': 'passed', 'sysroot': str(rootfs), 'files': len(file_lines),
                      'symlinks': len(link_lines), 'recoveryReport': str(reports / 'sysroot-recovery.json'),
                      'producerRerun': False}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit('error: ' + str(error))
