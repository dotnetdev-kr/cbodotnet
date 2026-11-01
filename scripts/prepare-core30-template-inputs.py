#!/usr/bin/env python3
"""Retain exact historical test-template data from official SDK archives."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile

import runpy
LEGACY_ARCH = runpy.run_path(str(Path(__file__).with_name('ci_legacy_arch.py')))
ARCH = LEGACY_ARCH['selected_arch']()

OWNER = 'cbodotnet-core30-retained-test-templates-v1'
ARCHIVES = {
    '2.2.207': {'name': 'dotnet-sdk-2.2.207-linux-x64.tar.gz', 'architecture': 'x64', 'bytes': 169751938,
        'sha256': '4fb5fb9956e9e019c3eef093cc65c676df9874f715c76eb8638f3aa057ba28cd',
        'sha512': '9d70b4a8a63b66da90544087199a0f681d135bf90d43ca53b12ea97cc600a768b0a3d2f824cfe27bd3228e058b060c63319cd86033be8b8d27925283f99de958'},
    '3.0.100': {'name': 'dotnet-sdk-3.0.100-linux-arm64.tar.gz', 'architecture': ARCH['arch'], 'bytes': 113669548,
        'sha256': 'ffcd9db434dab9f068bbf229a4e20f935cab0b48b28e4a83c114c6c1f0f5f6f6',
        'sha512': '18c3bc07c4486381f54d4b40eb8401bf56c14fef5febc4639e3134d74ce66172d1e66c2dea9684ad727f08e9dd7e89d74535a8642fb2a2203445483293f3b3c3'}}
if ARCH['arch'] == 'x64':
    ARCHIVES['3.0.100'] = {'name': LEGACY_ARCH['sdk_pin']('3.0.100', 'x64')['name'], 'architecture': 'x64',
        'bytes': 113463755, 'sha256': '12098fe29d5c857fd6093b1fd63eda9f91b92798e3748fcedc0e0727f1ac01c2',
        'sha512': LEGACY_ARCH['sdk_pin']('3.0.100', 'x64')['sha512']}
PACKAGES = [
    {'id': 'Microsoft.DotNet.Test.ProjectTemplates.2.2', 'version': '1.0.2-beta4.19155.2', 'sdk': '2.2.207',
     'member': './sdk/2.2.207/Templates/microsoft.dotnet.test.projecttemplates.2.2.1.0.2-beta4.19155.2.nupkg',
     'bytes': 25973, 'sha256': 'bb716df012db30807648d79f773ace4182eb509a1e8091c30780724511860800',
     'repositoryCommit': '6876f35678603837f67294f80c2a6e0e4b52f178'},
    {'id': 'Microsoft.DotNet.Test.ProjectTemplates.3.0', 'version': '1.0.2-beta4.19354.2', 'sdk': '3.0.100',
     'member': './templates/3.0.0/microsoft.dotnet.test.projecttemplates.3.0.1.0.2-beta4.19354.2.nupkg',
     'bytes': 26061, 'sha256': 'f211de478ffb096fa60dedfa112a646b7c95364e6bf07e189f8c5bf54e170f05',
     'repositoryCommit': '83f94a1a6c85622594527d9d3ee36886f6e11ed4'}]


def ordinary(path, is_directory=False):
    if not path.is_absolute() or any(p.is_symlink() for p in [path] + list(path.parents)):
        raise ValueError('An absolute ordinary path without symbolic-link ancestors is required')
    if not (path.is_dir() if is_directory else path.is_file()):
        raise ValueError('Missing ordinary input: ' + str(path))
    return path


def fingerprint(path):
    before = path.stat()
    sha256, sha512 = hashlib.sha256(), hashlib.sha512()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            sha256.update(block); sha512.update(block)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('Input changed during hashing')
    return {'bytes': after.st_size, 'sha256': sha256.hexdigest(), 'sha512': sha512.hexdigest()}


def validate_package(data, expected):
    if len(data) != expected['bytes'] or hashlib.sha256(data).hexdigest() != expected['sha256']:
        raise ValueError('The exact retained template package bytes differ')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError('Duplicate retained package member')
        nuspecs = [n for n in names if '/' not in n and n.lower().endswith('.nuspec')]
        if len(nuspecs) != 1:
            raise ValueError('The retained package identity is ambiguous')
        metadata = next(n for n in ET.fromstring(archive.read(nuspecs[0])) if n.tag.rsplit('}', 1)[-1] == 'metadata')
        fields = {n.tag.rsplit('}', 1)[-1]: n for n in metadata}
        if (fields['id'].text != expected['id'] or fields['version'].text != expected['version'] or
                fields['repository'].get('commit') != expected['repositoryCommit']):
            raise ValueError('The retained template ID/version/source metadata differs')
        if any(n.lower().endswith(('.exe', '.dll', '.so')) for n in names):
            raise ValueError('Only architecture-neutral template data is expected')


def select_member(archive, expected):
    matches = []
    with tarfile.open(str(archive), 'r|gz') as source:
        for member in source:
            if member.name == expected['member']:
                if not member.isfile() or member.size != expected['bytes']:
                    raise ValueError('The exact template archive member is not an ordinary expected file')
                matches.append(source.extractfile(member).read())
    if len(matches) != 1:
        raise ValueError('The original SDK archive must contain exactly one selected template member')
    validate_package(matches[0], expected)
    return matches[0]


def prepare(inputs, reports, sdk22_archive=None):
    ordinary(inputs, True); ordinary(reports, True)
    report = reports / 'core30-test-template-inputs.json'
    if report.exists() or report.is_symlink():
        raise ValueError('Use a fresh template-input report directory')
    root = inputs / 'core30-retained-test-templates'
    if root.is_symlink(): raise ValueError('The owned input path cannot be a symbolic link')
    root.mkdir(exist_ok=True)
    ordinary(root, True)
    owner = root / 'owner.json'
    expected_owner = {'owner': OWNER, 'inputsDirectory': str(inputs), 'scope': 'External official SDK template data only; no executable SDK2.2 content is extracted or run.'}
    owner_bytes = (json.dumps(expected_owner, indent=2, sort_keys=True) + '\n').encode()
    if owner.exists():
        if ordinary(owner).read_bytes() != owner_bytes: raise ValueError('The input-directory ownership differs')
    elif list(root.iterdir()):
        raise ValueError('Refusing an unowned retained-input directory')
    else:
        with owner.open('xb') as output: output.write(owner_bytes)
    feed = root / 'feed'
    feed.mkdir(exist_ok=True); ordinary(feed, True)
    expected_names = {p['id'] + '.' + p['version'] + '.nupkg' for p in PACKAGES}
    if any(p.name not in expected_names or not p.is_file() or p.is_symlink() for p in feed.iterdir()):
        raise ValueError('Unexpected or unsafe file in the owned template-only feed')
    records, archive_records = [], []
    for expected in PACKAGES:
        target = feed / (expected['id'] + '.' + expected['version'] + '.nupkg')
        if target.exists():
            validate_package(ordinary(target).read_bytes(), expected)
        else:
            spec = ARCHIVES[expected['sdk']]
            url = 'https://builds.dotnet.microsoft.com/dotnet/Sdk/' + expected['sdk'] + '/' + spec['name']
            if expected['sdk'] == '3.0.100':
                archive = ordinary(inputs / 'official-sdk' / spec['name'])
            else:
                cache = root / 'downloads'
                cache.mkdir(exist_ok=True); ordinary(cache, True)
                archive = cache / spec['name']
                if not archive.exists():
                    staged = cache / (spec['name'] + '.partial-' + uuid.uuid4().hex)
                    if sdk22_archive is not None:
                        shutil.copyfile(str(ordinary(sdk22_archive)), str(staged))
                    else:
                        with urllib.request.urlopen(url, timeout=120) as response, staged.open('xb') as output:
                            shutil.copyfileobj(response, output)
                    if fingerprint(ordinary(staged)) != {k: spec[k] for k in ('bytes', 'sha256', 'sha512')}:
                        raise ValueError('The official SDK2.2 template-data archive failed its full hashes')
                    staged.rename(archive)
                ordinary(archive)
            info = fingerprint(archive)
            if info != {k: spec[k] for k in ('bytes', 'sha256', 'sha512')}:
                raise ValueError('The exact original SDK archive differs')
            data = select_member(archive, expected)
            with target.open('xb') as output: output.write(data)
            archive_records.append(dict({'path': str(archive), 'url': url, 'sdkVersion': expected['sdk'], 'archiveArchitecture': spec['architecture'], 'member': expected['member'], 'executableContentExtracted': False}, **info))
        records.append(dict({'path': str(target), 'id': expected['id'], 'version': expected['version'], 'sourceProduced': False,
                             'role': 'genuine-retained-official-sdk-template-input', 'architectureNeutralTemplateData': True,
                             'archiveSdkVersion': expected['sdk'], 'archiveMember': expected['member']}, **fingerprint(target)))
    receipt = root / 'template-inputs.json'
    receipt_bytes = (json.dumps({'owner': OWNER, 'packages': PACKAGES, 'archives': ARCHIVES}, indent=2, sort_keys=True) + '\n').encode()
    if receipt.exists():
        if ordinary(receipt).read_bytes() != receipt_bytes: raise ValueError('The fixed template contract receipt differs')
    else:
        with receipt.open('xb') as output: output.write(receipt_bytes)
    result = {'schemaVersion': 1, 'status': 'passed', 'feedDirectory': str(feed), 'packages': records, 'verifiedArchivesThisInvocation': archive_records,
              'contractReceipt': dict({'path': str(receipt)}, **fingerprint(receipt)),
              'scope': 'Exact original template nupkgs retained as external build inputs. No version changes, source-built label, product-source edits, SDK binary replacement, archive execution or emulation.'}
    with report.open('x') as output: json.dump(result, output, indent=2); output.write('\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=['arm64', 'x64'], default='arm64')
    parser.add_argument('--inputs-dir', type=Path, required=True)
    parser.add_argument('--reports-dir', type=Path, required=True)
    parser.add_argument('--sdk22-archive', type=Path)
    args = parser.parse_args()
    result = prepare(args.inputs_dir, args.reports_dir, args.sdk22_archive)
    print(json.dumps({'status': result['status'], 'feedDirectory': result['feedDirectory'], 'packages': len(result['packages'])}))
