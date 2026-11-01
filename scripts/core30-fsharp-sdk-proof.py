#!/usr/bin/env python3
"""Prove the pinned Core 3.0 root's direct, text-only FSharp.NET.Sdk package.

This reads original Git/source/package inputs only. The root helper packs
straight into the published feed, so no independent producer-copy pair or
compiler/bootstrap construction is inferred for this metadata package.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import xml.etree.ElementTree as ET
import zipfile

import runpy
LEGACY_ARCH = runpy.run_path(str(Path(__file__).with_name('ci_legacy_arch.py')))
ARCH = LEGACY_ARCH['selected_arch']()


ROOT = '40de72d1087a1d05dfd39c87f888a0611ec6c60f'
PACKAGE_ID = 'FSharp.NET.Sdk'
VERSION = '1.0.4-bundled-0100'
NAME = PACKAGE_ID + '.' + VERSION + '.nupkg'
HELPER = 'src/netcorecli-fsc/'
PAYLOADS = ('Sdk/Sdk.OnRestore.targets', 'Sdk/Sdk.props', 'Sdk/Sdk.targets')
CONTROLS = ('dir.props', 'repos/netcorecli-fsc.proj',
            HELPER + 'FSharp.NET.Sdk.csproj', HELPER + 'FSharp.NET.Sdk.nuspec')
NUSPEC = PACKAGE_ID + '.nuspec'
MANIFEST_RELATION = 'http://schemas.microsoft.com/packaging/2010/07/manifest'
CORE_RELATION = 'http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties'


def ordinary(path, directory=False):
    if not isinstance(path, Path) or not path.is_absolute() or '..' in path.parts:
        raise ValueError('An absolute ordinary input path is required')
    if any(item.is_symlink() for item in [path] + list(path.parents)):
        raise ValueError('A proof input must not traverse symbolic links')
    if not (path.is_dir() if directory else path.is_file()):
        raise ValueError('Missing ordinary proof input: ' + str(path))
    return path


def fingerprint(path):
    ordinary(path)
    before = path.stat(); a, b = hashlib.sha256(), hashlib.sha512()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            a.update(block); b.update(block)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('A direct-producer proof input changed while reading')
    return {'bytes': after.st_size, 'sha256': a.hexdigest(), 'sha512': b.hexdigest()}


def git(source, *arguments):
    process = subprocess.run(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
                              '-C', str(source)] + list(arguments), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.returncode:
        raise ValueError('The pinned root Git proof failed')
    return process.stdout


def xml(data):
    if len(data) > 16384 or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise ValueError('Unsupported direct-package XML metadata')
    try:
        return ET.fromstring(data)
    except ET.ParseError as error:
        raise ValueError('Invalid direct-package XML metadata') from error


def local_name(node):
    return node.tag.rsplit('}', 1)[-1]


def semantic(node):
    return node.tag, tuple(sorted(node.attrib.items())), (node.text or '').strip(), tuple(semantic(row) for row in node)


def values(document, name):
    return [row.text or '' for row in document.iter() if local_name(row) == name]


def require_values(document, expected):
    for name, value in expected.items():
        if values(document, name) != [value]:
            raise ValueError('The pinned direct-producer property contract differs: ' + name)


def validate_opc(contents, core_name, metadata):
    relation_root = xml(contents['_rels/.rels'])
    namespace = 'http://schemas.openxmlformats.org/package/2006/relationships'
    if relation_root.tag != '{' + namespace + '}Relationships' or relation_root.attrib or len(relation_root) != 2:
        raise ValueError('Unexpected direct-package relationship metadata')
    expected = {MANIFEST_RELATION: '/' + NUSPEC, CORE_RELATION: '/' + core_name}
    found, ids = {}, set()
    for row in relation_root:
        if (row.tag != '{' + namespace + '}Relationship' or set(row.attrib) != {'Type', 'Target', 'Id'}
                or row.get('Type') in found or not re.fullmatch(r'R[0-9A-F]{16}', row.get('Id', ''))
                or row.get('Id') in ids or len(row)):
            raise ValueError('Unexpected direct-package relationship')
        found[row.get('Type')] = row.get('Target'); ids.add(row.get('Id'))
    if found != expected:
        raise ValueError('Direct-package metadata relationships differ')
    types = xml(contents['[Content_Types].xml'])
    namespace = 'http://schemas.openxmlformats.org/package/2006/content-types'
    wanted = {'rels': 'application/vnd.openxmlformats-package.relationships+xml',
              'psmdcp': 'application/vnd.openxmlformats-package.core-properties+xml',
              'targets': 'application/octet', 'props': 'application/octet', 'nuspec': 'application/octet'}
    observed = {}
    if types.tag != '{' + namespace + '}Types' or types.attrib:
        raise ValueError('Unexpected direct-package content type root')
    for row in types:
        if (row.tag != '{' + namespace + '}Default' or set(row.attrib) != {'Extension', 'ContentType'}
                or row.get('Extension') in observed or len(row)):
            raise ValueError('Unexpected direct-package content type')
        observed[row.get('Extension')] = row.get('ContentType')
    if observed != wanted:
        raise ValueError('Direct-package content types differ')
    core = xml(contents[core_name])
    namespace = 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties'
    dc = 'http://purl.org/dc/elements/1.1/'
    expected = {'{' + dc + '}creator': metadata['authors'], '{' + dc + '}description': metadata['description'],
                '{' + dc + '}identifier': PACKAGE_ID, '{' + namespace + '}version': VERSION,
                '{' + namespace + '}keywords': metadata['tags'],
                '{' + namespace + '}lastModifiedBy': 'NuGet.Build.Tasks.Pack, Version=5.3.0.4, Culture=neutral, PublicKeyToken=31bf3856ad364e35;'}
    observed = {}
    if core.tag != '{' + namespace + '}coreProperties' or core.attrib:
        raise ValueError('Unexpected direct-package core properties root')
    for row in core:
        if row.tag in observed or row.attrib or len(row):
            raise ValueError('Unexpected direct-package core property')
        observed[row.tag] = row.text or ''
    if observed != expected:
        raise ValueError('Direct-package core properties differ')


def prove(source, package):
    """Return exact direct-producer evidence or reject without modifying inputs."""
    ordinary(source, directory=True); ordinary(package)
    if (git(source, 'rev-parse', 'HEAD').decode().strip() != ROOT
            or Path(git(source, 'rev-parse', '--show-toplevel').decode().strip()).resolve() != source):
        raise ValueError('The exact pinned Core 3.0 root is required')
    expected_package = source / ('bin/obj/' + ARCH['arch'] + '/Release/blob-feed/packages') / NAME
    if package != expected_package:
        raise ValueError('Only the exact direct feed output can use this producer contract')
    if package.stat().st_size > 65536:
        raise ValueError('The text-only direct package exceeds its size bound')
    documents, source_records = {}, []
    for relative in CONTROLS + tuple(HELPER + name for name in PAYLOADS):
        path = ordinary(source / relative)
        pinned = git(source, 'show', ROOT + ':' + relative)
        if path.read_bytes() != pinned:
            raise ValueError('A pinned direct-producer source changed: ' + relative)
        documents[relative] = pinned
        source_records.append({'path': str(path), 'repositoryPath': relative,
                               'matchesPinnedGitBlob': True, **fingerprint(path)})
    sdk_files = [path.relative_to(source / HELPER).as_posix()
                 for path in sorted((source / HELPER / 'Sdk').rglob('*')) if path.is_file() or path.is_symlink()]
    if sdk_files != sorted(PAYLOADS):
        raise ValueError('The direct Sdk source payload inventory differs')
    require_values(xml(documents['dir.props']), {
        'SourceBuiltPackagesPath': '$(SourceBuiltBlobFeedDir)packages/',
        'SourceBuiltBlobFeedDir': '$(IntermediatePath)blob-feed/'})
    adapter = xml(documents['repos/netcorecli-fsc.proj'])
    require_values(adapter, {
        'ProjectDirectory': '$(SubmoduleDirectory)$(RepositoryName)/',
        'PackagesOutput': '$(SourceBuiltPackagesPath)', 'RepoApiImplemented': 'false',
        'BuildCommand': '$(DotnetToolCommand) pack -c $(Configuration) --output $(SourceBuiltPackagesPath) --no-build FSharp.NET.Sdk.csproj /p:NuspecFile=FSharp.NET.Sdk.nuspec $(OutputArgs) $(RedirectRepoOutputToLog)'})
    require_values(xml(documents[HELPER + 'FSharp.NET.Sdk.csproj']), {
        'TargetFramework': 'netcoreapp2.0', 'DisableImplicitFrameworkReferences': 'true', 'IncludeBuildOutput': 'false'})
    nuspec = xml(documents[HELPER + 'FSharp.NET.Sdk.nuspec'])
    original_metadata = next((row for row in nuspec if local_name(row) == 'metadata'), None)
    file_groups = [row for row in nuspec if local_name(row) == 'files']
    if (original_metadata is None or len(file_groups) != 1 or len(file_groups[0]) != 1
            or file_groups[0][0].attrib != {'src': 'Sdk/**/*', 'target': 'Sdk/'}):
        raise ValueError('The pinned nuspec does not exclusively select Sdk text payloads')
    fields = {local_name(row): row.text or '' for row in original_metadata}
    if fields.get('id') != PACKAGE_ID or fields.get('version') != VERSION:
        raise ValueError('The pinned direct-package identity differs')
    before = fingerprint(package)
    try:
        with zipfile.ZipFile(str(package)) as archive:
            if len(archive.infolist()) != 7:
                raise ValueError('The direct package must contain exactly seven known members')
            contents, seen = {}, set()
            for entry in archive.infolist():
                name = entry.filename; parsed = PurePosixPath(name)
                if (parsed.is_absolute() or '..' in parsed.parts or parsed.as_posix() != name or '\\' in name
                        or '\x00' in name or name.casefold() in seen or entry.is_dir() or entry.flag_bits & 1
                        or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG)
                        or entry.file_size > 16384):
                    raise ValueError('An ambiguous, linked or unsafe direct-package member is present')
                seen.add(name.casefold()); contents[name] = archive.read(entry)
            core = [name for name in contents if re.fullmatch(r'package/services/metadata/core-properties/[0-9a-f]{32}\.psmdcp', name)]
            if len(core) != 1 or set(contents) != set(PAYLOADS) | {NUSPEC, '_rels/.rels', '[Content_Types].xml', core[0]}:
                raise ValueError('The direct package has unexpected or missing members')
    except zipfile.BadZipFile as error:
        raise ValueError('The direct package ZIP is invalid') from error
    actual_nuspec = xml(contents[NUSPEC])
    if (actual_nuspec.tag != nuspec.tag or actual_nuspec.attrib or len(actual_nuspec) != 1
            or semantic(actual_nuspec[0]) != semantic(original_metadata)):
        raise ValueError('The packed nuspec metadata differs from its exact original declaration')
    validate_opc(contents, core[0], fields)
    payload_records = []
    for member in PAYLOADS:
        data = contents[member]
        if data != documents[HELPER + member]:
            raise ValueError('A direct SDK text payload differs from its pinned source: ' + member)
        payload_records.append({'member': member, 'repositoryPath': HELPER + member, 'bytes': len(data),
                                'sha256': hashlib.sha256(data).hexdigest(), 'matchesCurrentAndPinnedSource': True})
    if fingerprint(package) != before:
        raise ValueError('The direct producer output changed during proof')
    return {'status': 'passed', 'sourceCommit': ROOT,
            'producerPath': str(package),
            'packageIdentity': {'id': PACKAGE_ID, 'version': VERSION, 'repositoryCommit': None},
            'package': dict({'path': str(package)}, **before), 'sourceControls': source_records,
            'payloads': payload_records, 'archiveMemberCount': len(contents),
            'directProducerContract': {'kind': 'pinned-root-sdk-text-package-direct-feed-output',
                                       'repository': 'https://github.com/dotnet/source-build', 'commit': ROOT,
                                       'adapter': 'repos/netcorecli-fsc.proj', 'projectDirectory': str(source / HELPER),
                                       'outputDirectory': str(expected_package.parent), 'independentArchiveCopyClaimed': False,
                                       'compiledAssemblyPayloads': 0, 'bootstrapCopy': False, 'compilerConstructionClaimed': False,
                                       'scope': 'The original root-owned no-build pack emits this exact metadata/text package directly into the feed. All real Sdk payload bytes match pinned root Git sources; NuGet metadata has the original identity and package relationships. This is not a separate F# compiler build, bootstrap copy or independent archive-copy proof.'}}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=['arm64', 'x64'], default='arm64')
    parser.add_argument('--source-dir', required=True, type=Path)
    parser.add_argument('--package', required=True, type=Path)
    arguments = parser.parse_args()
    print(json.dumps(prove(arguments.source_dir, arguments.package), indent=2))
