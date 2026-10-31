#!/usr/bin/env python3
"""Preserve XML-skipped legacy NuGet caches and retain their exact restore inputs."""

import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import uuid
import xml.etree.ElementTree as ET
import zipfile


PINS = {'5.0.214': 'd414ecb2d997a9b3f38aaaeddace30ca097e546d',
        '3.1.426': 'ab8b115b5658237ee8916ae3586600b39fb2fd19',
        '3.0.103': '40de72d1087a1d05dfd39c87f888a0611ec6c60f'}
OWNER = 'cbodotnet-legacy-xmldoc-recovery-v1'
ICON_SHA256 = '3356b59b6d9c24db3a22398c0fb3430724052fe75ae5e8430ee8ede2fb713356'
HASH_SOURCE = r'''using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using NuGet.Packaging;

internal static class Program
{
    private static int Main()
    {
        int failed = 0;
        string path;
        while ((path = Console.ReadLine()) != null)
        {
            try
            {
                string contentHash;
                using (var reader = new PackageArchiveReader(path))
                    contentHash = reader.GetContentHash(CancellationToken.None);
                byte[] hash;
                using (var stream = File.OpenRead(path))
                using (var algorithm = SHA512.Create())
                    hash = algorithm.ComputeHash(stream);
                Console.WriteLine(JsonSerializer.Serialize(new { path, contentHash,
                    archiveSha512 = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant(),
                    packagingAssembly = typeof(PackageArchiveReader).Assembly.FullName }));
            }
            catch (Exception error)
            {
                failed = 1;
                Console.WriteLine(JsonSerializer.Serialize(new { path, error = error.ToString() }));
            }
        }
        return failed;
    }
}
'''
HASH_PROJECT = '''<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <UseAppHost>false</UseAppHost>
    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="$(MSBuildToolsPath)/NuGet*.dll"><Private>true</Private></Reference>
    <Reference Include="$(MSBuildToolsPath)/System.Security.Cryptography.Pkcs.dll" Condition="Exists('$(MSBuildToolsPath)/System.Security.Cryptography.Pkcs.dll')"><Private>true</Private></Reference>
  </ItemGroup>
</Project>
'''


def fingerprint(path):
    before = path.stat()
    sha256, sha512 = hashlib.sha256(), hashlib.sha512()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            sha256.update(block)
            sha512.update(block)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('A cache input changed during inspection')
    return {'bytes': after.st_size, 'sha256': sha256.hexdigest(), 'sha512': sha512.hexdigest()}


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


def write(path, value):
    with path.open('x', encoding='utf-8') as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write('\n')


def git(source, *args):
    process = subprocess.run(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-C', str(source)] + list(args),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.returncode:
        raise ValueError('Pinned source identity check failed')
    return process.stdout


def inspect_archive(archive, metadata_observations=None):
    file(archive)
    package_dir = directory(archive.parent)
    expected_name = package_dir.parent.name + '.' + package_dir.name + '.nupkg'
    if archive.name != expected_name:
        raise ValueError('The cached archive name differs from its package directory')
    with zipfile.ZipFile(str(archive)) as stream:
        entries = {}
        duplicate_icon = False
        for entry in stream.infolist():
            path = PurePosixPath(entry.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in entry.filename:
                raise ValueError('A cached package has an unsafe member')
            kind = stat.S_IFMT(entry.external_attr >> 16)
            if kind == stat.S_IFLNK:
                raise ValueError('A cached package has linked members')
            if entry.filename in entries:
                previous = entries[entry.filename]
                if (entry.filename != 'packageIcon.png' or duplicate_icon or entry.is_dir() or previous.is_dir()
                        or kind not in (0, stat.S_IFREG) or stat.S_IFMT(previous.external_attr >> 16) not in (0, stat.S_IFREG)
                        or entry.file_size != 7006 or previous.file_size != 7006
                        or hashlib.sha256(stream.read(previous)).hexdigest() != ICON_SHA256
                        or hashlib.sha256(stream.read(entry)).hexdigest() != ICON_SHA256):
                    raise ValueError('A cached package has an unreviewed repeated member: ' + entry.filename)
                duplicate_icon = True
                continue
            entries[entry.filename] = entry
        names = set(entries)
        signed = '.signature.p7s' in names
        missing = []
        for name, entry in entries.items():
            if not name.lower().endswith('.xml') or entry.is_dir():
                continue
            adjacent = [name[:-4] + extension for extension in ['.dll', '.exe']]
            paired = next((candidate for candidate in adjacent if candidate in names and (package_dir / candidate).is_file()), None)
            if paired and not (package_dir / name).exists():
                missing.append({'path': name, 'bytes': entry.file_size, 'pairedAssembly': paired})
        if duplicate_icon and metadata_observations is not None:
            metadata_observations.append(dict({'archive': str(archive), 'member': 'packageIcon.png',
                                               'entries': 2, 'memberBytes': 7006, 'memberSha256': ICON_SHA256,
                                               'missingXmlDocumentation': bool(missing),
                                               'policy': 'Only the proven byte-identical regular SDK icon pair is accepted. Code, XML, linked, third or unknown duplicate entries remain rejected.'},
                                              **fingerprint(archive)))
        if not missing:
            return None
        nuspecs = [entry for name, entry in entries.items() if '/' not in name and name.lower().endswith('.nuspec')]
        if len(nuspecs) != 1:
            raise ValueError('A cached package lacks one root nuspec identity')
        root = ET.fromstring(stream.read(nuspecs[0]))
        metadata = next((item for item in root if item.tag.split('}')[-1] == 'metadata'), None)
        values = {item.tag.split('}')[-1]: item.text for item in metadata} if metadata is not None else {}
        if (values.get('id') or '').lower() != package_dir.parent.name:
            raise ValueError('The cached archive package ID differs')
    actual = fingerprint(archive)
    checksum = file(package_dir / (archive.name + '.sha512'))
    expected = base64.b64decode(checksum.read_text().strip(), validate=True).hex()
    if expected != actual['sha512']:
        raise ValueError('The retained archive differs from its NuGet SHA-512 receipt')
    metadata_path = package_dir / '.nupkg.metadata'
    source = None
    content_hash = None
    require_signed_hash = False
    if metadata_path.exists() or metadata_path.is_symlink():
        metadata = json.loads(file(metadata_path).read_text())
        source = metadata.get('source')
        content_hash = metadata.get('contentHash')
        if content_hash and base64.b64decode(content_hash, validate=True).hex() != actual['sha512']:
            if not signed:
                raise ValueError('An unsigned archive differs from its NuGet content-hash receipt: ' + str(archive))
            require_signed_hash = True
    return dict({'packageId': values['id'], 'packageVersion': values.get('version'),
                 'cacheVersionDirectory': str(package_dir), 'archive': str(archive),
                 'archiveName': archive.name, 'originalRestoreSource': source,
                 'signedPackage': signed, 'nugetContentHashReceipt': content_hash,
                 'requiresSignedContentHash': require_signed_hash,
                 'missingXmlDocumentation': missing, 'sha512Receipt': fingerprint(checksum)}, **actual)


def canonical_hashes(packages, dotnet, inputs, reports, expected_sdk):
    if dotnet is None:
        raise ValueError('Signed package content-hash verification requires --dotnet with the private bootstrap SDK')
    file(dotnet)
    version = subprocess.check_output([str(dotnet), '--version'], cwd=str(inputs)).decode().strip()
    if version != expected_sdk or version not in ('5.0.212', '3.1.422', '3.0.100'):
        raise ValueError('The signed-package verifier requires a pinned legacy bootstrap SDK')
    framework = 'net5.0' if version.startswith('5.') else 'netcoreapp' + '.'.join(version.split('.')[:2])
    sdk = directory(dotnet.parent / 'sdk' / version)
    references = [dict({'path': str(file(path))}, **fingerprint(path)) for path in sorted(sdk.glob('NuGet*.dll'))]
    if not any(Path(row['path']).name == 'NuGet.Packaging.dll' for row in references):
        raise ValueError('The private SDK lacks NuGet.Packaging.dll')
    owner = {'owner': 'cbodotnet-nuget-content-hash-v1', 'sdkVersion': version, 'dotnet': str(dotnet),
             'sourceSha256': hashlib.sha256(HASH_SOURCE.encode()).hexdigest(),
             'projectSha256': hashlib.sha256(HASH_PROJECT.encode()).hexdigest(), 'sdkNuGetAssemblies': references}
    controls = [('Program.cs', HASH_SOURCE), ('ContentHash.csproj', HASH_PROJECT),
                ('Directory.Build.props', '<Project/>\n'), ('Directory.Build.targets', '<Project/>\n'),
                ('NuGet.Config', '<configuration><packageSources><clear/></packageSources></configuration>\n'),
                ('global.json', json.dumps({'sdk': {'version': version, 'rollForward': 'disable'}},
                                           indent=2, sort_keys=True) + '\n')]
    parent = inputs / 'nuget-content-hash'
    if not parent.exists():
        parent.mkdir()
    directory(parent)
    tool = parent / version
    if tool.exists() or tool.is_symlink():
        directory(tool)
        if json.loads(file(tool / 'owner.json').read_text()) != owner:
            raise ValueError('The retained NuGet content-hash tool has a different identity')
    else:
        tool.mkdir()
        write(tool / 'owner.json', owner)
        for name, text in controls:
            with (tool / name).open('x', encoding='utf-8') as output:
                output.write(text)
    for name, expected_text in controls:
        if file(tool / name).read_bytes() != expected_text.encode('utf-8'):
            raise ValueError('A retained canonical hash verifier control file changed: ' + name)
    binary = tool / ('bin/Release/' + framework + '/ContentHash.dll')
    ready = tool / 'ready.json'
    if ready.exists():
        receipt = json.loads(file(ready).read_text())
        for row in receipt['outputs']:
            if fingerprint(file(Path(row['path']))) != {key: row[key] for key in ['bytes', 'sha256', 'sha512']}:
                raise ValueError('The retained canonical hash verifier output changed')
    else:
        environment = os.environ.copy()
        environment['RestoreAdditionalProjectSources'] = ''
        environment['RestoreSources'] = ''
        environment['DOTNET_MULTILEVEL_LOOKUP'] = '0'
        arguments = [str(dotnet), 'build', str(tool / 'ContentHash.csproj'), '--configuration', 'Release',
                     '/p:TargetFramework=' + framework, '/p:RestoreConfigFile=' + str(tool / 'NuGet.Config'),
                     '/m:2', '/nr:false', '/verbosity:minimal']
        with (reports / 'nuget-content-hash-build.log').open('xb') as output:
            process = subprocess.run(arguments, cwd=str(tool), env=environment, stdout=output, stderr=subprocess.STDOUT)
        if process.returncode:
            raise ValueError('The bounded canonical content-hash verifier failed to build; inspect its retained log')
        outputs = [dict({'path': str(file(path))}, **fingerprint(path)) for path in sorted(binary.parent.iterdir()) if path.is_file()]
        write(ready, {'owner': owner, 'arguments': arguments, 'outputs': outputs})
    request = '\n'.join(row['archive'] for row in packages) + '\n'
    with (reports / 'nuget-content-hash-requests.txt').open('x', encoding='utf-8') as output:
        output.write(request)
    process = subprocess.run([str(dotnet), str(file(binary))], input=request.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with (reports / 'nuget-content-hash-results.jsonl').open('xb') as output:
        output.write(process.stdout)
    with (reports / 'nuget-content-hash-stderr.log').open('xb') as output:
        output.write(process.stderr)
    if process.returncode:
        raise ValueError('The SDK NuGet canonical content-hash API failed; inspect its retained results')
    rows = [json.loads(line) for line in process.stdout.decode().splitlines()]
    if len(rows) != len(packages) or [row['path'] for row in rows] != [row['archive'] for row in packages]:
        raise ValueError('The canonical content-hash response identities differ')
    for package, row in zip(packages, rows):
        if row.get('archiveSha512') != package['sha512'] or row.get('contentHash') != package['nugetContentHashReceipt']:
            raise ValueError('A signed package differs from its canonical NuGet receipt: ' + package['archive'])
        package['canonicalContentHashVerification'] = row
    return {'sdkVersion': version, 'framework': framework, 'owner': owner,
            'binary': dict({'path': str(binary)}, **fingerprint(binary)), 'verifiedSignedPackages': len(rows),
            'semantics': 'Raw archive SHA-512 remains checked against .nupkg.sha512. Signed metadata contentHash is independently computed through the actual SDK NuGet PackageArchiveReader.GetContentHash API.'}


def inventory(package, output):
    root = Path(package['cacheVersionDirectory'])
    count = 0
    for current, subdirs, files in os.walk(str(root), followlinks=False):
        subdirs.sort()
        for name in subdirs + sorted(files):
            path = Path(current) / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise ValueError('An affected cache contains a linked or special entry')
            if stat.S_ISREG(mode):
                row = dict({'package': root.parent.name + '/' + root.name,
                            'path': path.relative_to(root).as_posix(), 'mode': oct(stat.S_IMODE(mode))}, **fingerprint(path))
                output.write(json.dumps(row, sort_keys=True) + '\n')
                count += 1
    return count


def recover(source, inputs, reports, commit, dotnet=None, inspect_only=False):
    cache = source / 'packages/restored'
    for path in [cache] + list(cache.parents):
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise ValueError('The cache or an ancestor is linked or is not a directory')
    cache_initially_absent = not cache.exists()
    manifest = file(source / 'eng/Version.Details.xml')
    if manifest.read_bytes() != git(source, 'show', commit + ':eng/Version.Details.xml'):
        raise ValueError('The pinned source dependency manifest differs')
    global_json = file(source / 'global.json')
    if global_json.read_bytes() != git(source, 'show', commit + ':global.json'):
        raise ValueError('The pinned root bootstrap SDK declaration differs')
    expected_sdk = json.loads(global_json.read_text(encoding='utf-8-sig'))['tools']['dotnet']
    recovery = inputs / 'xmldoc-recovery'
    owner = {'owner': OWNER, 'sourceRoot': str(source), 'sourceCommit': commit, 'cacheDirectory': str(cache),
             'sourceManifest': fingerprint(manifest)}
    if recovery.exists() or recovery.is_symlink():
        directory(recovery)
        if json.loads(file(recovery / 'owner.json').read_text()) != owner:
            raise ValueError('Refusing an unrecognized XML recovery directory')
        index = json.loads(file(recovery / 'feed-index.json').read_text())
        directory(recovery / 'feed')
        if {path.name for path in (recovery / 'feed').iterdir()} != set(index):
            raise ValueError('The retained recovery feed membership differs')
        for name, row in index.items():
            if fingerprint(file(recovery / 'feed' / name)) != {key: row[key] for key in ['bytes', 'sha256', 'sha512']}:
                raise ValueError('A retained recovery feed archive changed')
    else:
        recovery.mkdir()
        (recovery / 'feed').mkdir()
        (recovery / 'attempts').mkdir()
        write(recovery / 'owner.json', owner)
        index = {}
        write(recovery / 'feed-index.json', index)
    if cache.exists() and cache.stat().st_dev != recovery.stat().st_dev:
        raise ValueError('Atomic cache preservation requires inputs and cache on the same filesystem')
    attempt = recovery / 'attempts' / reports.name
    attempt.mkdir()
    preserved = attempt / 'preserved-cache'
    preserved.mkdir()
    packages, metadata_observations = [], []
    for archive in sorted(cache.glob('*/*/*.nupkg')):
        package = inspect_archive(archive, metadata_observations)
        if package is not None:
            packages.append(package)
    pending = [row for row in packages if row['requiresSignedContentHash']]
    content_hash_provider = canonical_hashes(pending, dotnet, inputs, reports, expected_sdk) if pending else None
    if inspect_only:
        return {'status': 'passed', 'inspectionOnly': True, 'owner': owner, 'packages': packages,
                'archiveMetadataObservations': metadata_observations,
                'canonicalContentHashProvider': content_hash_provider, 'affectedPackages': len(packages),
                'cacheInitiallyAbsent': cache_initially_absent,
                'missingXmlDocumentationFiles': sum(len(row['missingXmlDocumentation']) for row in packages),
                'scope': 'Archive integrity and signed canonical content-hash inspection only. No cache directory is moved and no recovery feed package is copied.'}
    receipt = reports / 'xmldoc-preserved-members.jsonl'
    with receipt.open('x', encoding='utf-8') as output:
        for package in packages:
            package['preservedFileCount'] = inventory(package, output)
            directory_path = Path(package['cacheVersionDirectory'])
            package['directoryIdentity'] = {'device': directory_path.stat().st_dev, 'inode': directory_path.stat().st_ino}
            package['preservedDirectory'] = str(preserved / directory_path.parent.name / directory_path.name)
            if package['archiveName'] in index and any(index[package['archiveName']][key] != package[key] for key in ['bytes', 'sha256', 'sha512']):
                raise ValueError('A package identity conflicts with the retained recovery feed')
    plan = {'owner': owner, 'packages': packages, 'inventory': dict({'path': str(receipt)}, **fingerprint(receipt)),
            'archiveMetadataObservations': metadata_observations,
            'cacheInitiallyAbsent': cache_initially_absent,
            'canonicalContentHashProvider': content_hash_provider,
            'recoveryDirectory': str(recovery), 'restoreFeed': str(recovery / 'feed'),
            'requiredEnvironment': {'NUGET_XMLDOC_MODE': 'none'},
            'scope': 'Preserve affected extracted cache directories and restore normally from byte-identical retained original archives. No XML, assembly, package version or SDK archive is edited. OPC metadata XML without an assembly sibling is excluded.'}
    write(reports / 'xmldoc-recovery-plan.json', plan)
    for package in packages:
        target = recovery / 'feed' / package['archiveName']
        if not target.exists():
            staged = recovery / 'feed' / ('.stage-' + uuid.uuid4().hex)
            shutil.copyfile(package['archive'], str(staged))
            if fingerprint(staged) != {key: package[key] for key in ['bytes', 'sha256', 'sha512']}:
                raise ValueError('A staged recovery archive differs')
            staged.rename(target)
        index[package['archiveName']] = {key: package[key] for key in ['packageId', 'packageVersion', 'bytes', 'sha256', 'sha512']}
    staged_index = recovery / ('feed-index-' + uuid.uuid4().hex + '.json')
    write(staged_index, index)
    os.replace(str(staged_index), str(recovery / 'feed-index.json'))
    for package in packages:
        original, destination = Path(package['cacheVersionDirectory']), Path(package['preservedDirectory'])
        if fingerprint(file(Path(package['archive']))) != {key: package[key] for key in ['bytes', 'sha256', 'sha512']}:
            raise ValueError('A cache archive changed after the complete preservation plan')
        if (original.stat().st_dev, original.stat().st_ino) != (package['directoryIdentity']['device'], package['directoryIdentity']['inode']):
            raise ValueError('A cache directory changed after the complete preservation plan')
        destination.parent.mkdir(parents=True, exist_ok=True)
        original.rename(destination)
        if (destination.stat().st_dev, destination.stat().st_ino) != (package['directoryIdentity']['device'], package['directoryIdentity']['inode']):
            raise ValueError('Cache preservation did not retain directory identity')
    plan.update({'status': 'passed', 'affectedPackages': len(packages),
                 'missingXmlDocumentationFiles': sum(len(row['missingXmlDocumentation']) for row in packages),
                 'retainedFeedPackages': len(index)})
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', required=True, type=Path)
    parser.add_argument('--inputs-dir', required=True, type=Path)
    parser.add_argument('--reports-dir', required=True, type=Path)
    parser.add_argument('--profile', required=True, type=Path)
    parser.add_argument('--dotnet', type=Path)
    parser.add_argument('--inspect-only', action='store_true')
    args = parser.parse_args()
    source, inputs, reports = [directory(path) for path in [args.source_dir, args.inputs_dir, args.reports_dir]]
    for left, right in [(source, inputs), (source, reports), (inputs, reports)]:
        if left == right or left in right.parents or right in left.parents:
            raise ValueError('Source, inputs and reports must be separate')
    profile = json.loads(file(args.profile).read_text(encoding='utf-8-sig'))
    commit = PINS.get(profile.get('sdkVersion'))
    if not commit or profile.get('source', {}).get('commit') != commit or profile['source'].get('repository') != 'https://github.com/dotnet/source-build':
        raise ValueError('An exact supported legacy source-build profile is required')
    if git(source, 'rev-parse', 'HEAD').decode().strip() != commit:
        raise ValueError('The legacy source-build checkout differs')
    report = reports / 'legacy-xmldoc-recovery.json'
    if report.exists() or report.is_symlink():
        raise ValueError('Use a new XML recovery reports directory')
    record = {'startedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'status': 'failed'}
    try:
        record.update(recover(source, inputs, reports, commit, args.dotnet, args.inspect_only))
    except (OSError, ValueError, KeyError, ET.ParseError, zipfile.BadZipFile) as error:
        record['error'] = str(error)
    record['finishedAtUtc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    write(report, record)
    print(json.dumps({'status': record['status'], 'report': str(report), 'restoreFeed': record.get('restoreFeed'),
                      'affectedPackages': record.get('affectedPackages'), 'error': record.get('error')}))
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
