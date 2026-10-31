#!/usr/bin/env python3
"""Prepare an explicitly retained CoreCLR tooling/RID-graph dependency.

The unavailable original RC2 declaration stays in the source. A real retained
3.0.0 package from the original PSB is restored under its actual identity.
"""

import argparse
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile


CORECLR_COMMIT = '259ce7d4619478cfefe7b0c0f6fa765f765f7e37'
ORIGINAL_VERSION = '3.0.0-rc2.19461.13'
VERSION = '3.0.0'
NAME = 'Microsoft.NETCore.Platforms.' + VERSION + '.nupkg'
PACKAGE_BYTES = 10669
PACKAGE_SHA256 = '80c1d7c6075d91a16310751dbc84dc9bfd0bfe23fe8bf52bdc245d8cf50ec57f'
RUNTIME_JSON_SHA256 = 'c38956f91e505ce6c65f717f79c3b638ae2805c8a801126bd72a24c6b62fbaec'
PACKAGE_SOURCE_COMMIT = '4ac4c0367003fe3973a3648eb0715ddb0e3bbcea'


def package_identity(data):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = [name for name in archive.namelist() if '/' not in name and name.endswith('.nuspec')]
        if len(names) != 1:
            raise ValueError('The retained package must have one root nuspec')
        metadata = next((item for item in ET.fromstring(archive.read(names[0]))
                         if item.tag.rsplit('}', 1)[-1] == 'metadata'), None)
        fields = {item.tag.rsplit('}', 1)[-1]: item for item in metadata}
        repository = fields.get('repository')
        result = {'id': fields['id'].text, 'version': fields['version'].text,
                  'repositoryCommit': repository.get('commit') if repository is not None else None,
                  'runtimeJsonSha256': hashlib.sha256(archive.read('runtime.json')).hexdigest()}
    if result != {'id': 'Microsoft.NETCore.Platforms', 'version': VERSION,
                  'repositoryCommit': PACKAGE_SOURCE_COMMIT, 'runtimeJsonSha256': RUNTIME_JSON_SHA256}:
        raise ValueError('The retained package identity or RID graph differs')
    return result


def inventory(root, ordinary, fingerprint):
    result = []
    for current, directories, files in os.walk(str(root), followlinks=False):
        for name in sorted(directories):
            path = Path(current) / name
            if path.is_symlink():
                raise ValueError('A fixed NuGet cache directory contains a symlink')
        for name in sorted(files):
            path = ordinary(Path(current) / name)
            result.append(dict({'path': path.relative_to(root).as_posix()}, **fingerprint(path)))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['source-dir', 'inputs-dir', 'reports-dir', 'profile']:
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    helpers = Path(__file__).resolve().parent
    helper = runpy.run_path(str(helpers / 'prepare-core30-bootstrap.py'))
    inputs_helper = runpy.run_path(str(helpers / 'core30-inputs.py'))
    directory, ordinary, fingerprint = helper['directory'], helper['ordinary_file'], helper['fingerprint']
    identity = inputs_helper['verify'](args.source_dir, args.profile)
    source, inputs, reports = directory(args.source_dir), directory(args.inputs_dir), directory(args.reports_dir)
    report_path = reports / 'core30-platforms-input.json'
    if report_path.exists() or report_path.is_symlink() or source == reports or source in reports.parents:
        raise ValueError('Use a fresh external preparation report directory')
    selected = json.loads(ordinary(args.profile).read_text())['build']['retainedCoreClrPlatforms']
    if selected['originalVersion'] != ORIGINAL_VERSION or selected['selectedVersion'] != VERSION or selected['packageSha256'] != PACKAGE_SHA256:
        raise ValueError('The explicit retained tooling input differs from the reviewed profile')
    component = directory(source / ('bin/src/coreclr.' + CORECLR_COMMIT))
    upstream_patch = ordinary(source / 'patches/coreclr/0004-Patch-Helix-dependency-out.patch')
    if upstream_patch.read_bytes() != helper['git'](source, 'show', identity['sourceCommit'] + ':patches/coreclr/0004-Patch-Helix-dependency-out.patch'):
        raise ValueError('The original upstream CoreCLR tooling patch changed')
    with tempfile.TemporaryDirectory(prefix='core30-platforms-source-proof-', dir=str(reports)) as temporary:
        stage = Path(temporary)
        helper['git'](stage, 'init', '--quiet')
        for relative in ['eng/Tools.props', 'global.json']:
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(helper['git'](source, '--git-dir=' + str(source / '.git/modules/src/coreclr.git'),
                                            'show', CORECLR_COMMIT + ':' + relative))
        helper['git'](stage, 'apply', '--check', '--whitespace=error-all', str(upstream_patch))
        helper['git'](stage, 'apply', '--whitespace=error-all', str(upstream_patch))
        patched_tools = (stage / 'eng/Tools.props').read_bytes()
    source_files = []
    for relative in ['eng/Versions.props', 'eng/Tools.props', 'src/.nuget/packaging.props']:
        path = ordinary(component / relative)
        original = helper['git'](source, '--git-dir=' + str(source / '.git/modules/src/coreclr.git'),
                                 'show', CORECLR_COMMIT + ':' + relative)
        accepted = [original, patched_tools] if relative == 'eng/Tools.props' else [original]
        if path.read_bytes() not in accepted:
            raise ValueError('The original CoreCLR tooling declaration/consumer changed: ' + relative)
        source_files.append(dict({'path': str(path), 'originalGitSha256': hashlib.sha256(original).hexdigest(),
                                  'upstreamToolsPatchApplied': relative == 'eng/Tools.props' and path.read_bytes() == patched_tools}, **fingerprint(path)))
    record = {'schemaVersion': 1, 'status': 'running', 'sourceCommit': identity['sourceCommit'],
              'coreClrCommit': CORECLR_COMMIT, 'startedAtUtc': helper['now'](), 'commands': [],
              'originalDeclaredVersion': ORIGINAL_VERSION, 'selectedRealVersion': VERSION,
              'originalSourceFiles': source_files,
              'originalUpstreamToolsPatch': dict({'path': str(upstream_patch)}, **fingerprint(upstream_patch)),
              'unavailability': selected['unavailability'],
              'scope': 'External retained bootstrap input for the CoreCLR engineering tool reference and its packaging runtime.json RID graph. The package keeps its real3.0.0 identity. SDK3.0.103/runtime3.0.3 product versions, native build, crossgen and package-generation targets remain enabled.'}
    try:
        archive = ordinary(inputs / 'Private.SourceBuilt.Artifacts.0.1.0-3.0.100.tar.gz')
        archive_info = fingerprint(archive)
        if archive_info['bytes'] != helper['PSB_BYTES'] or archive_info['sha256'] != helper['PSB_SHA256']:
            raise ValueError('The original PSB archive identity differs')
        root = directory(inputs / 'core30-platforms', create=True)
        owner = {'owner': 'cbodotnet-core30-platforms-v1', 'sourceDirectory': str(source),
                 'sourceCommit': identity['sourceCommit'], 'packageSha256': PACKAGE_SHA256, 'version': VERSION}
        helper['identical_or_new'](root / 'owner.json', (json.dumps(owner, sort_keys=True, indent=2) + '\n').encode())
        feed = directory(root / 'feed', create=True)
        package = feed / NAME
        if package.exists() or package.is_symlink():
            data = ordinary(package).read_bytes()
        else:
            found = []
            with tarfile.open(str(archive), 'r:gz') as stream:
                for member in stream:
                    if member.name == NAME:
                        if not member.isfile() or member.size != PACKAGE_BYTES:
                            raise ValueError('The exact retained package tar entry differs')
                        found.append(stream.extractfile(member).read())
            if len(found) != 1:
                raise ValueError('The original PSB must contain one exact retained package')
            data = found[0]
            if len(data) != PACKAGE_BYTES or hashlib.sha256(data).hexdigest() != PACKAGE_SHA256:
                raise ValueError('The retained package bytes differ')
            helper['identical_or_new'](package, data)
        if len(data) != PACKAGE_BYTES or hashlib.sha256(data).hexdigest() != PACKAGE_SHA256:
            raise ValueError('The retained cached package bytes differ')
        if sorted(path.name for path in feed.iterdir()) != [NAME]:
            raise ValueError('The fixed retained tooling feed contains unexpected entries')
        package_info = package_identity(data)
        record.update({'sourceArchive': dict({'path': str(archive)}, **archive_info),
                       'sourceArchiveMember': NAME, 'localFeedPackage': dict({'path': str(package)}, **fingerprint(package)),
                       'packageIdentity': package_info})
        packages = directory(source / 'packages/restored')
        cache = packages / 'microsoft.netcore.platforms' / VERSION
        for candidate in [cache, cache.parent]:
            if candidate.is_symlink():
                raise ValueError('The fixed NuGet cache path contains a symlink')
        cached_archive = cache / ('microsoft.netcore.platforms.' + VERSION + '.nupkg')
        runtime = cache / 'runtime.json'
        exact = (cache.is_dir() and not cache.is_symlink() and cached_archive.is_file() and not cached_archive.is_symlink()
                 and runtime.is_file() and not runtime.is_symlink()
                 and fingerprint(ordinary(cached_archive))['sha256'] == PACKAGE_SHA256
                 and fingerprint(ordinary(runtime))['sha256'] == RUNTIME_JSON_SHA256)
        if cache.exists() or cache.is_symlink():
            directory(cache)
            previous = inventory(cache, ordinary, fingerprint)
            if not exact:
                quarantine = directory(root / 'quarantine', create=True) / reports.parent.name
                if quarantine.exists() or quarantine.is_symlink() or cache.stat().st_dev != quarantine.parent.stat().st_dev:
                    raise ValueError('A cache preservation path exists or crosses filesystems')
                os.rename(str(cache), str(quarantine))
                record['preservedPreviousCache'] = {'original': str(cache), 'preserved': str(quarantine), 'files': previous}
        if not exact:
            project = reports / 'restore-platforms.csproj'
            project.write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>netcoreapp3.0</TargetFramework>'
                               '<DisableImplicitFrameworkReferences>true</DisableImplicitFrameworkReferences></PropertyGroup>'
                               '<ItemGroup><PackageReference Include="Microsoft.NETCore.Platforms" Version="3.0.0"/></ItemGroup></Project>\n')
            command = [str(source / '.dotnet/dotnet'), str(source / '.dotnet/sdk/3.0.100/MSBuild.dll'), str(project),
                       '/t:Restore', '/p:RestoreSources=' + str(feed), '/p:RestorePackagesPath=' + str(packages),
                       '/p:RestoreAdditionalProjectSources=', '/p:RestoreAdditionalSources=', '/p:RestoreNoCache=true',
                       '/p:RestoreForce=true', '/m:1', '/nr:false', '/v:minimal']
            helper['run'](command, source, os.environ.copy(), reports / 'restore-platforms.log', record['commands'])
        if fingerprint(ordinary(cached_archive))['sha256'] != PACKAGE_SHA256 or fingerprint(ordinary(runtime))['sha256'] != RUNTIME_JSON_SHA256:
            raise ValueError('The actual restored package or RID graph differs from the retained PSB input')
        record.update({'status': 'passed', 'existingExactCacheReused': exact,
                       'restoredArchive': dict({'path': str(cached_archive)}, **fingerprint(cached_archive)),
                       'restoredRuntimeGraph': dict({'path': str(runtime)}, **fingerprint(runtime))})
        return 0
    except Exception as error:
        record.update({'status': 'failed', 'error': str(error)})
        raise
    finally:
        record['finishedAtUtc'] = helper['now']()
        helper['write_json'](report_path, record)
        print(json.dumps({'status': record['status'], 'report': str(report_path)}))


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError, zipfile.BadZipFile) as error:
        raise SystemExit('error: ' + str(error))
