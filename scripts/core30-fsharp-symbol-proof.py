#!/usr/bin/env python3
"""Prove the exact pinned FSharp compiler's publisher-generated symbol copy."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import subprocess
import xml.etree.ElementTree as ET
import zipfile

import runpy
LEGACY_ARCH = runpy.run_path(str(Path(__file__).with_name('ci_legacy_arch.py')))
ARCH = LEGACY_ARCH['selected_arch']()

ROOT = '40de72d1087a1d05dfd39c87f888a0611ec6c60f'
FSHARP = '0422ff293bb2cc722fe5021b85ef50378a9af823'
ARCADE = 'ce459ae07c3d7a1e68251268855e0bc7b3d97f75'
PACKAGE_ID = 'Microsoft.FSharp.Compiler'
VERSION = '10.6.0'
NAME = PACKAGE_ID + '.' + VERSION + '.symbols.nupkg'
REGULAR_NAME = PACKAGE_ID + '.' + VERSION + '.nupkg'
PUBLISHER = 'src/Microsoft.DotNet.Arcade.Sdk/tools/Publish.proj'
FSHARP_CONTROLS = ('src/fsharp/FSharp.Compiler.nuget/Microsoft.FSharp.Compiler.csproj',
                   'src/fsharp/FSharp.Compiler.nuget/Microsoft.FSharp.Compiler.nuspec')


def ordinary(path, directory=False):
    if not isinstance(path, Path) or not path.is_absolute() or '..' in path.parts:
        raise ValueError('An absolute ordinary proof input is required')
    if any(p.is_symlink() for p in [path] + list(path.parents)):
        raise ValueError('A symbol proof input must not traverse symbolic links')
    if not (path.is_dir() if directory else path.is_file()):
        raise ValueError('Missing ordinary symbol proof input: ' + str(path))
    return path


def fingerprint(path):
    ordinary(path)
    before = path.stat(); a, b = hashlib.sha256(), hashlib.sha512()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            a.update(block); b.update(block)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError('A symbol proof input changed while reading')
    return {'bytes': after.st_size, 'sha256': a.hexdigest(), 'sha512': b.hexdigest()}


def git(source, *arguments):
    result = subprocess.run(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-C', str(source)] + list(arguments),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise ValueError('The pinned symbol-package source Git check failed')
    return result.stdout


def local_name(node):
    return node.tag.rsplit('}', 1)[-1]


def xml(data):
    if len(data) > 1024 * 1024 or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise ValueError('Unsupported symbol-package XML control')
    try:
        return ET.fromstring(data)
    except ET.ParseError as error:
        raise ValueError('Invalid symbol-package XML control') from error


def pinned(source, path, commit, relative, repository=None):
    ordinary(path)
    args = [] if repository is None else ['--git-dir=' + str(source / ('.git/modules/src/' + repository + '.git'))]
    original = git(source, *(args + ['show', commit + ':' + relative]))
    if path.read_bytes() != original:
        raise ValueError('A pinned symbol producer control changed: ' + relative)
    return {'path': str(path), 'repositoryPath': relative, 'commit': commit,
            'matchesPinnedGitBlob': True, **fingerprint(path)}


def publisher_contract(data):
    document = xml(data)
    properties = [x for x in document.iter() if local_name(x) == 'SymbolPackagesDir']
    if len(properties) != 1 or properties[0].text != '$(ArtifactsTmpDir)SymbolPackages\\':
        raise ValueError('The pinned symbol-package temporary directory contract differs')
    targets = {x.get('Name'): x for x in document if local_name(x) == 'Target'}
    before = targets['BeforePublish']
    copies = [x for x in before if local_name(x) == 'Copy']
    expected_copy = {'SourceFiles': "@(SymbolPackagesToGenerate->'%(OriginalPackage)')",
                     'DestinationFiles': '@(SymbolPackagesToGenerate)'}
    if len(copies) != 1 or copies[0].attrib != expected_copy:
        raise ValueError('The original byte-copy symbol generation contract differs')
    unions = [x for x in before.iter() if local_name(x) == 'ItemsToPushToBlobFeed']
    if len(unions) != 1 or unions[0].get('Include') != '@(PackagesToPublish);@(ExistingSymbolPackages);@(SymbolPackagesToGenerate)':
        raise ValueError('The original symbol publication union differs')
    rebound = [x for x in before.iter() if local_name(x) == 'PackagesToPublish' and x.get('Include') == '@(ItemsToPushToBlobFeed)']
    if len(rebound) != 1:
        raise ValueError('The original published-package union is not preserved')
    storage = targets['PublishToSourceBuildStorage']
    expected_storage = [
        {'SourceFiles': '@(PackagesToPublish)', 'DestinationFolder': '$(DotNetOutputBlobFeedDir)packages'},
        {'SourceFiles': '@(ExistingSymbolPackages);@(SymbolPackagesToGenerate)', 'DestinationFolder': '$(DotNetOutputBlobFeedDir)assets'}]
    if [x.attrib for x in storage if local_name(x) == 'Copy'] != expected_storage:
        raise ValueError('The original source-build symbol publication destinations differ')
    return {'symbolPackagesDir': properties[0].text, 'generationCopy': expected_copy,
            'publicationUnion': unions[0].get('Include'), 'storageCopies': expected_storage}


def prove(source, package):
    """Return this exact local symbol-copy chain, or reject without modifying it."""
    ordinary(source, directory=True)
    expected = source / ('bin/obj/' + ARCH['arch'] + '/Release/blob-feed/packages') / NAME
    if package != expected:
        raise ValueError('Only the exact selected FSharp compiler symbol feed package is supported')
    ordinary(package)
    if (git(source, 'rev-parse', 'HEAD').decode().strip() != ROOT or
            Path(git(source, 'rev-parse', '--show-toplevel').decode().strip()).resolve() != source):
        raise ValueError('The pinned Core 3.0 root source is required')
    fsharp = ordinary(source / ('bin/src/fsharp.' + FSHARP), directory=True)
    arcade = ordinary(source / ('bin/src/arcade.' + ARCADE), directory=True)
    for directory, commit in [(fsharp, FSHARP), (arcade, ARCADE)]:
        if ordinary(directory / '.git/HEAD').read_text().strip() != commit:
            raise ValueError('The selected symbol producer export identity differs')
    controls = [pinned(source, source / 'repos/fsharp.proj', ROOT, 'repos/fsharp.proj')]
    for relative in FSHARP_CONTROLS:
        controls.append(pinned(source, fsharp / relative, FSHARP, relative, 'fsharp'))
    publisher = arcade / PUBLISHER
    controls.append(pinned(source, publisher, ARCADE, PUBLISHER, 'arcade'))
    installed = ordinary(source / 'Tools/source-built/Microsoft.DotNet.Arcade.Sdk/tools/Publish.proj')
    if installed.read_bytes() != publisher.read_bytes():
        raise ValueError('The actual source-built Arcade publisher differs from its pinned source')
    controls.append({'path': str(installed), 'matchesPinnedGitBlob': True, **fingerprint(installed)})
    contract = publisher_contract(publisher.read_bytes())
    producer = ordinary(fsharp / 'artifacts/tmp/Release/SymbolPackages' / NAME)
    shipping = ordinary(fsharp / 'artifacts/packages/Release/Shipping' / REGULAR_NAME)
    asset = ordinary(source / ('bin/obj/' + ARCH['arch'] + '/Release/blob-feed/assets') / NAME)
    paths = {'shippingOriginal': shipping, 'generatedSymbolCopy': producer,
             'publishedAsset': asset, 'publishedFeedPackage': package}
    rows = {name: dict({'path': str(path)}, **fingerprint(path)) for name, path in paths.items()}
    if len({(x['bytes'], x['sha256'], x['sha512']) for x in rows.values()}) != 1:
        raise ValueError('The complete Shipping/symbol-copy/asset/feed archive bytes differ')
    if not 0 < rows['publishedFeedPackage']['bytes'] < 128 * 1024 * 1024:
        raise ValueError('The selected symbol archive exceeds the bounded compiler-package size')
    try:
        with zipfile.ZipFile(str(package)) as archive:
            seen = set()
            if not 1 <= len(archive.infolist()) <= 4096:
                raise ValueError('Unexpected compiler symbol package member count')
            if sum(x.file_size for x in archive.infolist()) > 512 * 1024 * 1024:
                raise ValueError('Expanded compiler symbol contents exceed the size bound')
            for entry in archive.infolist():
                name = PurePosixPath(entry.filename)
                canonical = name.as_posix() + ('/' if entry.is_dir() else '')
                if (name.is_absolute() or '..' in name.parts or '\\' in entry.filename or '\x00' in entry.filename
                        or canonical != entry.filename or entry.filename.casefold() in seen or entry.flag_bits & 1
                        or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                    raise ValueError('An ambiguous or unsafe compiler symbol archive member is present')
                seen.add(entry.filename.casefold())
            nuspecs = [n for n in archive.namelist() if '/' not in n and n.endswith('.nuspec')]
            if nuspecs != [PACKAGE_ID + '.nuspec']:
                raise ValueError('The exact selected compiler nuspec is required')
            metadata = [x for x in xml(archive.read(nuspecs[0])) if local_name(x) == 'metadata']
            if len(metadata) != 1:
                raise ValueError('The compiler package metadata is ambiguous')
            fields = {}
            for node in metadata[0]:
                name = local_name(node)
                if name in fields:
                    raise ValueError('Duplicate compiler package metadata field')
                fields[name] = node
            if (fields['id'].text != PACKAGE_ID or fields['version'].text != VERSION or
                    fields['repository'].get('commit') != FSHARP or
                    fields['repository'].get('url') != 'https://github.com/Microsoft/visualfsharp'):
                raise ValueError('The compiler symbol package identity/source pin differs')
    except (zipfile.BadZipFile, KeyError) as error:
        raise ValueError('Invalid pinned compiler symbol package') from error
    for name, path in paths.items():
        if fingerprint(path) != {k: rows[name][k] for k in ('bytes', 'sha256', 'sha512')}:
            raise ValueError('A whole-archive symbol proof input changed')
    return {'status': 'passed', 'sourceCommit': ROOT, 'componentCommit': FSHARP,
            'componentDirectory': str(fsharp), 'producerPath': str(producer),
            'packageIdentity': {'id': PACKAGE_ID, 'version': VERSION, 'repositoryCommit': FSHARP},
            'sourceControls': controls, 'publisherCommit': ARCADE, 'publisherContract': contract,
            'archives': rows, 'wholeArchivesByteIdentical': True,
            'role': 'source-produced-compiler-package-with-original-arcade-generated-symbol-copy',
            'scope': 'Only this exact pinned FSharp compiler symbol package is accepted. Original Arcade copies the ordinary Portable-PDB-containing package to a symbol filename and publishes both byte-identical copies. This is not a blanket symbol exclusion, retained bootstrap input, independent compiler rebuild or completed SDK claim.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=['arm64', 'x64'], default='arm64')
    parser.add_argument('--source-dir', required=True, type=Path)
    parser.add_argument('--package', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prove(args.source_dir, args.package), indent=2))
