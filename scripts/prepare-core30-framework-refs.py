#!/usr/bin/env python3
"""Verify and extract a fixed official prebuilt net472 reference-only input."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

VERSION = '1.0.3'
NAME = 'microsoft.netframework.referenceassemblies.net472.1.0.3.nupkg'
URL = 'https://api.nuget.org/v3-flatcontainer/microsoft.netframework.referenceassemblies.net472/1.0.3/' + NAME
BYTES = 20790130
SHA256 = 'ffa0a5570a39f911399164d0581ffddef99b5e3dfbaa5f220e5ce22969bcf57c'
TARGET = 'build/Microsoft.NETFramework.ReferenceAssemblies.net472.targets'
TARGET_SHA256 = '94498f7f27b5309fbe79b2eb0707c9a964cee5e0acdb27dfb12d621b38aaa084'


def entries(archive, helper):
    result, seen = [], set()
    for item in archive.infolist():
        name = helper['safe_name'](item.filename)
        mode = item.external_attr >> 16
        if name in seen or stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
            raise ValueError('Duplicate or unsafe reference-package member: ' + name)
        if item.is_dir():
            raise ValueError('The fixed reference package unexpectedly contains an explicit directory entry')
        seen.add(name)
        result.append((name, item))
    if len(result) != 374 or sum(item.file_size for _, item in result) != 115693493:
        raise ValueError('The fixed reference-package entry count/size differs')
    if hashlib.sha256(archive.read(TARGET)).hexdigest() != TARGET_SHA256:
        raise ValueError('The original package reference-resolution metadata differs')
    return result


def archive_inventory(archive, members):
    files = []
    for name, item in members:
        sha256, sha512, size = hashlib.sha256(), hashlib.sha512(), 0
        with archive.open(item) as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                size += len(block)
                sha256.update(block)
                sha512.update(block)
        files.append({'path': name, 'fingerprint': {'bytes': size, 'sha256': sha256.hexdigest(), 'sha512': sha512.hexdigest()}})
    return files


def verify_tree(root, receipt, helper, expected_files=None):
    if expected_files is None:
        package = helper['ordinary_file'](root.parent / NAME)
        if helper['fingerprint'](package)['sha256'] != SHA256 or package.stat().st_size != BYTES:
            raise ValueError('The fixed reference archive changed before extracted-tree verification')
        with zipfile.ZipFile(str(package)) as archive:
            expected_files = archive_inventory(archive, entries(archive, helper))
    if receipt['files'] != expected_files:
        raise ValueError('The extraction receipt differs from the independently fixed archive inventory')
    expected = {row['path']: row['fingerprint'] for row in expected_files}
    expected_directories = {parent.as_posix() for name in expected for parent in Path(name).parents if parent != Path('.')}
    observed = set()
    def fail_walk(error):
        raise error
    for current, directories, files in os.walk(str(root), followlinks=False, onerror=fail_walk):
        for name in directories:
            path = helper['directory'](Path(current) / name)
            if path.relative_to(root).as_posix() not in expected_directories:
                raise ValueError('An unexpected reference-package directory exists')
        for name in files:
            path = helper['ordinary_file'](Path(current) / name)
            relative = path.relative_to(root).as_posix()
            if relative not in expected or helper['fingerprint'](path) != expected[relative]:
                raise ValueError('An extracted reference-package file differs: ' + relative)
            observed.add(relative)
    if observed != set(expected):
        raise ValueError('The extracted reference-package file membership differs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source-dir', 'inputs-dir', 'reports-dir', 'profile']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--package', type=Path)
    args = parser.parse_args()
    helper = runpy.run_path(str(Path(__file__).resolve().with_name('prepare-core30-bootstrap.py')))
    identity = runpy.run_path(str(Path(__file__).resolve().with_name('core30-inputs.py')))['verify'](args.source_dir, args.profile)
    directory, ordinary, fingerprint = helper['directory'], helper['ordinary_file'], helper['fingerprint']
    source, inputs, reports = directory(args.source_dir), directory(args.inputs_dir), directory(args.reports_dir)
    if source == reports or source in reports.parents or source == inputs or source in inputs.parents:
        raise ValueError('Use separate external input and fresh report directories')
    output = reports / 'core30-net472-reference-input.json'
    if output.exists() or output.is_symlink():
        raise ValueError('Refusing a previous reference-input report')
    profile = json.loads(ordinary(args.profile).read_text())['build']['net472ReferenceAssemblies']
    if profile['packageVersion'] != VERSION or profile['packageSha256'] != SHA256 or profile['packageUrl'] != URL:
        raise ValueError('The explicit prebuilt reference input differs from the fixed profile')
    record = {'schemaVersion': 1, 'status': 'running', 'sourceCommit': identity['sourceCommit'],
              'startedAtUtc': helper['now'](), 'url': URL, 'packageVersion': VERSION,
              'prebuiltInput': True, 'executedReferenceBinaries': False,
              'scope': 'Original official prebuilt .NET Framework4.7.2 reference assemblies/metadata for the explicit GenAPI net472 compilation only. All original374 package files are retained. No Windows output or reference assembly is executed, no GenAPI target framework is omitted, and no product SDK/runtime reference override is introduced.'}
    try:
        root = directory(inputs / 'core30-framework-refs', create=True)
        owner = {'owner': 'cbodotnet-core30-net472-refs-v1', 'sourceDirectory': str(source),
                 'sourceCommit': identity['sourceCommit'], 'packageSha256': SHA256}
        helper['identical_or_new'](root / 'owner.json', (json.dumps(owner, indent=2, sort_keys=True) + '\n').encode())
        package = root / NAME
        if not package.exists() and not package.is_symlink():
            if args.package:
                supplied = ordinary(args.package)
                if fingerprint(supplied)['sha256'] != SHA256 or supplied.stat().st_size != BYTES:
                    raise ValueError('The supplied fixed reference-package bytes differ')
                helper['identical_or_new'](package, supplied.read_bytes())
            else:
                partial = root / (NAME + '.partial')
                if partial.exists() or partial.is_symlink():
                    raise ValueError('Preserve the interrupted reference-package download before retrying')
                with urllib.request.urlopen(URL, timeout=30) as response, partial.open('xb') as target:
                    size = 0
                    for block in iter(lambda: response.read(1024 * 1024), b''):
                        size += len(block)
                        if size > BYTES:
                            raise ValueError('The fixed reference-package download exceeds its declared size')
                        target.write(block)
                if fingerprint(partial)['sha256'] != SHA256 or partial.stat().st_size != BYTES:
                    raise ValueError('The downloaded fixed reference-package bytes differ')
                os.rename(str(partial), str(package))
        info = fingerprint(ordinary(package))
        if info['bytes'] != BYTES or info['sha256'] != SHA256:
            raise ValueError('The cached reference-package bytes differ')
        extracted, receipt_path = root / 'extracted', root / 'extraction.json'
        with zipfile.ZipFile(str(package)) as archive:
            members = entries(archive, helper)
            trusted_files = archive_inventory(archive, members)
            nuspec_name = 'Microsoft.NETFramework.ReferenceAssemblies.net472.nuspec'
            metadata = next(item for item in ET.fromstring(archive.read(nuspec_name)) if item.tag.rsplit('}', 1)[-1] == 'metadata')
            fields = {item.tag.rsplit('}', 1)[-1]: item.text for item in metadata}
            if fields['id'] != 'Microsoft.NETFramework.ReferenceAssemblies.net472' or fields['version'] != VERSION or fields['developmentDependency'] != 'true':
                raise ValueError('The official reference-package identity differs')
            if extracted.exists() or extracted.is_symlink():
                directory(extracted)
                receipt = json.loads(ordinary(receipt_path).read_text())
                if receipt['identity'] != owner or receipt['package'] != info or len(receipt['files']) != 374:
                    raise ValueError('The extracted reference-package ownership/identity differs')
                verify_tree(extracted, receipt, helper, trusted_files)
                reused = True
            else:
                if receipt_path.exists() or receipt_path.is_symlink():
                    raise ValueError('An extraction receipt exists without its original directory')
                extracted.mkdir()
                for name, entry in members:
                    target = extracted / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(entry) as original, target.open('xb') as destination:
                        for block in iter(lambda: original.read(1024 * 1024), b''):
                            destination.write(block)
                    os.chmod(str(target), 0o644)
                receipt = {'identity': owner, 'package': info, 'files': trusted_files}
                helper['write_json'](receipt_path, receipt)
                verify_tree(extracted, receipt, helper, trusted_files)
                reused = False
        target = ordinary(extracted / TARGET)
        if fingerprint(target)['sha256'] != TARGET_SHA256:
            raise ValueError('The extracted original reference-resolution metadata differs')
        record.update({'status': 'passed', 'package': dict({'path': str(package)}, **info),
                       'extractedDirectory': str(extracted), 'entriesVerified': len(receipt['files']), 'reused': reused,
                       'extractionReceipt': dict({'path': str(receipt_path)}, **fingerprint(receipt_path)),
                       'packageLicenseUrl': fields['licenseUrl'], 'originalNuspec': dict({'path': str(extracted / nuspec_name)}, **fingerprint(extracted / nuspec_name)),
                       'originalResolutionTargets': dict({'path': str(target)}, **fingerprint(target)),
                       'referenceRoot': str(extracted / 'build') + '/', 'customAfterMicrosoftCommonTargets': str(target),
                       'frameworkList': dict({'path': str(extracted / 'build/.NETFramework/v4.7.2/RedistList/FrameworkList.xml')}, **fingerprint(extracted / 'build/.NETFramework/v4.7.2/RedistList/FrameworkList.xml'))})
        return 0
    except Exception as error:
        record.update({'status': 'failed', 'error': str(error)})
        raise
    finally:
        record['finishedAtUtc'] = helper['now']()
        helper['write_json'](output, record)
        print(json.dumps({'status': record['status'], 'report': str(output)}))


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, ET.ParseError, zipfile.BadZipFile) as error:
        raise SystemExit('error: ' + str(error))
