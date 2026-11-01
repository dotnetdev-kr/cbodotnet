#!/usr/bin/env python3
"""Export the fixed Focal builder's OpenSSL 1.1 as separate verification inputs."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import stat
import subprocess
import uuid

import runpy
LEGACY_ARCH = runpy.run_path(str(Path(__file__).with_name('ci_legacy_arch.py')))
ARCH = LEGACY_ARCH['selected_arch']()


IMAGE = 'd7f3d9624f9f2ec9d6dfb3c0ed1743eab582378d0a4ee40dfb0bc9e66bed288a'
OWNER = 'cbodotnet-net5-verification-openssl11-v1'
FILES = [(('/usr/lib/' + ARCH['libdir'] + '/libssl.so.1.1'), 'lib/libssl.so.1.1', 'libssl1.1'),
         (('/usr/lib/' + ARCH['libdir'] + '/libcrypto.so.1.1'), 'lib/libcrypto.so.1.1', 'libssl1.1'),
         ('/usr/share/doc/libssl1.1/copyright', 'LICENSE.openssl.txt', 'libssl1.1'),
         ('/etc/ssl/openssl.cnf', 'openssl.cnf', 'openssl')]


def digest(path):
    result, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
            size += len(block)
    return {'bytes': size, 'sha256': result.hexdigest()}


def directory(path):
    if not path.is_absolute() or path == Path(path.anchor):
        raise ValueError('An absolute ordinary directory below the filesystem root is required')
    for parent in [path] + list(path.parents):
        if parent.is_symlink():
            raise ValueError('A control path is a symbolic link')
    if not path.is_dir():
        raise ValueError('Missing ordinary directory: ' + str(path))
    return path.resolve(strict=True)


def file(path):
    directory(path.parent)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Missing ordinary file: ' + str(path))
    return path


def command(*args):
    process = subprocess.run(list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.returncode:
        raise ValueError('Input inspection failed: ' + process.stderr.decode('utf-8', 'replace')[-2000:])
    return process.stdout.decode('utf-8')


def write(path, value):
    with path.open('x', encoding='utf-8') as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write('\n')


def os_identity(path=Path('/etc/os-release'), target=Path('/usr/lib/os-release')):
    directory(path.parent)
    if path.is_symlink():
        link = os.readlink(str(path))
        if link not in ('../usr/lib/os-release', str(target)) or path.resolve(strict=True) != target:
            raise ValueError('The OS identity symlink has an unexpected target')
        actual = file(target)
        proof = {'path': str(path), 'kind': 'symlink', 'linkTarget': link, 'resolvedPath': str(actual)}
    else:
        actual = file(path)
        proof = {'path': str(path), 'kind': 'file', 'resolvedPath': str(actual)}
    proof.update(digest(actual))
    return actual.read_text(), proof


def inspect_inputs(image_inspect, consumer):
    inspected = json.loads(file(image_inspect).read_text())
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise ValueError('One host-supplied Podman image-inspection record is required')
    image = inspected[0]
    if (image.get('Id', '').replace('sha256:', '') != IMAGE or image.get('Architecture') != ARCH['image'] or image.get('Os') != 'linux'):
        raise ValueError('The host image-inspection receipt does not select the fixed Focal builder')
    os_release, os_proof = os_identity()
    if not re.search(r'^VERSION_ID="?20\.04"?$', os_release, re.MULTILINE):
        raise ValueError('Run inside the fixed Ubuntu Focal build image')
    packages = []
    for name in ['libssl1.1', 'openssl']:
        values = command('dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\t${source:Package}\t${source:Version}', name).split('\t')
        if len(values) != 6 or values[2] != ARCH['deb'] or values[3] != 'ii ' or values[4] != 'openssl':
            raise ValueError('The expected installed native OpenSSL package differs')
        packages.append(dict(zip(['package', 'version', 'architecture', 'status', 'sourcePackage', 'sourceVersion'], values)))
    upstream_versions = [row['version'].split(':')[-1].rsplit('-', 1)[0] for row in packages]
    if upstream_versions != ['1.1.1f', '1.1.1f']:
        raise ValueError('The library/configuration packages do not share the fixed OpenSSL 1.1.1f upstream version')
    entries = []
    for original, relative, owner in FILES:
        path = file(Path(original))
        owned = command('dpkg-query', '-S', original).strip()
        if not owned.startswith(owner + ':') and not owned.startswith(owner + ':' + ARCH['deb'] + ':'):
            raise ValueError('The declared OpenSSL input is owned by a different package')
        row = dict({'sourcePath': original, 'path': relative, 'packageOwnership': owned,
                    'mode': oct(stat.S_IMODE(path.stat().st_mode))}, **digest(path))
        if relative.startswith('lib/'):
            header = command('readelf', '-h', original)
            if not re.search(r'Machine:\s+' + re.escape(ARCH['elf']) + r'\s*$', header, re.MULTILINE):
                raise ValueError('A compatibility input is not AArch64 ELF')
            versions = command('readelf', '--version-info', original)
            requirements = sorted(set(re.findall(r'\bGLIBC_(\d+(?:\.\d+)+)', versions)), key=lambda value: tuple(map(int, value.split('.'))))
            row.update({'elfMachine': ARCH['elf'], 'glibcVersionRequirements': requirements,
                        'maximumGlibcRequirement': requirements[-1] if requirements else None,
                        'dynamicSection': command('readelf', '-d', original)})
        entries.append(row)
    config = Path('/etc/ssl/openssl.cnf').read_text()
    if re.search(r'^\s*\.include\b', config, re.MULTILINE):
        raise ValueError('The OpenSSL configuration references an unexported include')
    environment = {'LD_LIBRARY_PATH': consumer + '/lib', 'OPENSSL_CONF': consumer + '/openssl.cnf'}
    return {'schemaVersion': 1, 'owner': OWNER, 'producerImageId': IMAGE,
            'hostImageInspection': dict({'path': str(image_inspect)}, **digest(image_inspect)),
            'imageIdentityScope': 'The immutable image ID is checked against the host-supplied Podman inspection receipt. The helper cannot independently query its containing image.',
            'osRelease': os_release, 'osReleaseIdentity': os_proof, 'packages': packages, 'files': entries,
            'packageCompatibility': {'upstreamVersion': '1.1.1f',
                                     'libraryPackageVersion': packages[0]['version'],
                                     'configurationPackageVersion': packages[1]['version'],
                                     'policy': 'Keep each exact package revision and file hash. The fixed Focal image has an updated library security revision and an older configuration package from the same upstream OpenSSL 1.1.1f family.'},
            'consumerDirectory': consumer, 'consumerEnvironment': environment,
            'icuCompatibilityLibraries': [],
            'scope': 'External OpenSSL 1.1 dependencies for controlled verification only. Mount this directory read-only beside the SDK; the SDK archive is not changed. Results using these inputs do not establish stock OpenSSL-3-only OS compatibility. The OS continues to provide its normal CA trust store.'}


def export(destination, contract):
    environment_text = '#!/usr/bin/env bash\n# Separate NET5 verification inputs; mount at the recorded consumer path.\n'
    environment_text += '\n'.join('export ' + key + '=' + shlex.quote(value) for key, value in sorted(contract['consumerEnvironment'].items())) + '\n'
    owner = {'owner': OWNER, 'producerImageId': IMAGE}
    if destination.exists() or destination.is_symlink():
        directory(destination)
        if json.loads(file(destination / 'owner.json').read_text()) != owner:
            raise ValueError('Refusing an unrecognized compatibility input directory')
        previous = json.loads(file(destination / 'compatibility-inputs.json').read_text())
        for key in ['owner', 'producerImageId', 'osRelease', 'osReleaseIdentity', 'packages', 'files', 'consumerDirectory', 'consumerEnvironment']:
            if previous[key] != contract[key]:
                raise ValueError('Retained compatibility inputs have a different identity')
        expected = {row['path'] for row in contract['files']} | {'owner.json', 'compatibility-inputs.json', 'verification-env.sh'}
        observed = set()
        for path in destination.rglob('*'):
            if path.is_symlink():
                raise ValueError('A retained compatibility input is a symbolic link')
            if path.is_file():
                observed.add(path.relative_to(destination).as_posix())
        if observed != expected:
            raise ValueError('Retained compatibility input membership differs')
        for row in contract['files']:
            if digest(file(destination / row['path'])) != {key: row[key] for key in ['bytes', 'sha256']}:
                raise ValueError('A retained compatibility input changed')
        if file(destination / 'verification-env.sh').read_text() != environment_text:
            raise ValueError('The compatibility environment changed')
        return 'verified-existing'
    stage = destination.parent / ('.net5-verification-compat-' + uuid.uuid4().hex)
    stage.mkdir()
    for row in contract['files']:
        target = stage / row['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(row['sourcePath'], str(target))
        os.chmod(str(target), int(row['mode'], 8))
        if digest(target) != {key: row[key] for key in ['bytes', 'sha256']}:
            raise ValueError('A compatibility input copy differs')
    write(stage / 'owner.json', owner)
    write(stage / 'compatibility-inputs.json', contract)
    with (stage / 'verification-env.sh').open('x', encoding='utf-8') as output:
        output.write(environment_text)
    stage.rename(destination)
    return 'exported'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=['arm64', 'x64'], default='arm64')
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--reports-dir', required=True, type=Path)
    parser.add_argument('--image-inspect', required=True, type=Path)
    parser.add_argument('--consumer-directory', default='/verification-compat')
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine().lower() not in (ARCH['uname'], ARCH['arch']):
        raise ValueError('Run in the native ARM64 Focal builder')
    reports = directory(args.reports_dir)
    destination = args.destination
    directory(destination.parent)
    if destination == reports or destination in reports.parents or reports in destination.parents:
        raise ValueError('Compatibility inputs and reports must be separate')
    if (not args.consumer_directory.startswith('/') or args.consumer_directory == '/' or
            '..' in Path(args.consumer_directory).parts or re.search(r'[\s:\x00]', args.consumer_directory)):
        raise ValueError('An absolute consumer mount path without whitespace is required')
    report = reports / 'net5-verification-compat.json'
    if report.exists() or report.is_symlink():
        raise ValueError('Use a new compatibility export report directory')
    record = {'startedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'status': 'failed',
              'destination': str(destination), 'sdkArchiveModified': False}
    try:
        contract = inspect_inputs(args.image_inspect, args.consumer_directory.rstrip('/'))
        record.update({'inputContract': contract, 'result': export(destination, contract), 'status': 'passed',
                       'contractFingerprint': digest(destination / 'compatibility-inputs.json')})
    except (OSError, ValueError, KeyError) as error:
        record['error'] = str(error)
    record['finishedAtUtc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    write(report, record)
    print(json.dumps({'status': record['status'], 'report': str(report), 'error': record.get('error')}))
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
