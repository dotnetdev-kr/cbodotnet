#!/usr/bin/env python3
"""Build the pinned .NET 9/8 VMRs natively on stock Alpine; never publish or sign."""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time
from types import SimpleNamespace
import urllib.request
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET
import zipfile

sys.dont_write_bytecode = True
import musl_version_routes as R

ROOT = R.ROOT
spec = importlib.util.spec_from_file_location('modern_musl_secure_primitives', ROOT / 'scripts/musl-sdk.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
require, fingerprint, write, load_json, git, ordinary = P.require, P.fingerprint, P.write, P.load_json, P.git, P.ordinary
STAGES = ['prepare', 'build', 'scan', 'test', 'collect', 'verify']
NET8_PSB = dict(url='https://builds.dotnet.microsoft.com/source-built-artifacts/assets/'
    'Private.SourceBuilt.Artifacts.8.0.131-servicing.26422.1.centos.9-x64.tar.gz', bytes=728976053,
    sha256='e39d2656832923af11d00a2bd32a10326ab84a0dfd20307a8491d8af3f9e720c',
    sha512='07164022578785da51138e1201973163579da27fbe6e99645257ac39dcf68a1532a3646005b20e098e6fee90c8cb47c4a1b82dbc58ec73b6ca2a991e3a12c83a')


def module(name, filename):
    return P.module(name, filename)


def download(record, path):
    with urllib.request.urlopen(record['url'], timeout=120) as incoming, path.open('xb') as target:
        shutil.copyfileobj(incoming, target, 1024 * 1024)
    require(fingerprint(path)['sha512'] == record['sha512'], 'Pinned official input SHA512 differs')
    return dict(record, **fingerprint(path))


def inventory_cache(cache):
    rows = []
    for path in sorted(cache.rglob('*.nupkg')):
        require(not path.is_symlink(), 'Restored input redirects outside cache')
        metadata_path = path.parent / '.nupkg.metadata'
        metadata = load_json(metadata_path) if metadata_path.is_file() else {}
        rows.append(dict(path=path.relative_to(cache).as_posix(), source=metadata.get('source'), **fingerprint(path)))
    return rows


def net8_source_built_artifacts_url(props):
    root = ET.parse(props).getroot()
    require(root.tag in ('Project', '{http://schemas.microsoft.com/developer/msbuild/2003}Project'),
            'Pinned NET8 versions XML root differs')
    urls = [node.text for node in root.iter()
            if node.tag.rsplit('}', 1)[-1] == 'PrivateSourceBuiltArtifactsUrl']
    expected = NET8_PSB['url']
    require(urls == [expected], 'Pinned NET8 PSB URL differs')
    return urls[0]


def net8_psb_record(path):
    record = dict(url=NET8_PSB['url'], **fingerprint(path))
    require(record == NET8_PSB, 'Reviewed NET8 PSB input bytes differ')
    return record


def validate_net8_psb_records(release):
    for name in ('original-psb.json', 'actual-prep-psb.json'):
        require(load_json(release / 'reports/prepare' / name) == NET8_PSB,
                'Reviewed NET8 PSB download/prep input identity differs')


def serviced_package(path, source, package):
    """Bind each reviewed servicing input to its publisher's exact source."""
    actual = fingerprint(path)
    require(all(actual[key] == package[key] for key in ('bytes', 'sha512')),
            'Serviced package bytes differ: ' + package['id'])
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if name.lower().endswith('.nuspec')]
        require(len(names) == 1, 'One serviced package nuspec required')
        raw = archive.read(names[0])
    metadata = ET.fromstring(raw)
    metadata = metadata.find('{*}metadata')
    repository, license = metadata.find('{*}repository'), metadata.find('{*}license')
    publisher = source.get('publisher', source)
    require(metadata.findtext('{*}id', '').lower() == package['id']
            and metadata.findtext('{*}version') == package['version']
            and repository is not None and repository.get('commit') == publisher['commit']
            and repository.get('url', '').removesuffix('.git').rstrip('/') == publisher['repository']
            and license is not None and license.get('type') == 'expression' and license.text == package['license'],
            'Serviced package publisher source/license identity differs: ' + package['id'])
    return dict(package, sha256=actual['sha256'], nuspecSha256=hashlib.sha256(raw).hexdigest(),
                repository=publisher['repository'], repositoryCommit=publisher['commit'])


def validate_publisher_source_map(source, path, baseline=None):
    """Bind a VMR-published package to its complete pristine component source.

    A publisher commit and the component commit are distinct identities. The
    reviewed VMR manifest identifies the component; its entire libraries Git
    tree must also match the independently reconstructed source archive tree.
    """
    publisher = source['publisher']
    require(set(publisher) == {'repository', 'commit', 'sourceManifest', 'componentPath', 'identicalLibraryTree'}
            and publisher['repository'] == 'https://github.com/dotnet/dotnet'
            and set(publisher['sourceManifest']) == {'path', 'sha256'}
            and publisher['sourceManifest']['path'] == 'src/source-manifest.json'
            and fingerprint(path)['sha256'] == publisher['sourceManifest']['sha256'],
            'Reviewed publisher source-manifest bytes differ')
    manifest = load_json(path)
    components = [row for row in manifest['repositories'] if row['path'] == publisher['componentPath']]
    require(len(components) == 1 and components[0]['remoteUri'] == source['repository']
            and components[0]['commitSha'] == source['commit'], 'Publisher/component source identity mapping differs')
    tree = publisher['identicalLibraryTree']
    require(set(tree) == {'sourcePath', 'publisherPath', 'tree'}
            and tree['sourcePath'] == 'src/libraries'
            and tree['publisherPath'] == 'src/' + publisher['componentPath'] + '/' + tree['sourcePath']
            and re.fullmatch('[a-f0-9]{40}', tree['tree']), 'Reviewed publisher/component library tree scope differs')
    if baseline is not None:
        require(baseline and module('modern_publisher_source_tree', 'package-used-source.py').baseline_tree(baseline) == tree['tree'],
                'Complete corresponding source library Git tree differs from the package publisher')


def pristine_corresponding_checkout(checkout, commit):
    # Git can report a forced-CRLF solution as modified after exact Git-blob
    # serialization even when `git diff` is empty. Permit only that precise
    # checkout state; every other tracked/untracked change remains forbidden.
    status = subprocess.check_output(['git', '-C', str(checkout), 'status', '--porcelain', '--untracked-files=all'], text=True)
    for row in status.splitlines():
        require(row.startswith(' M ') and row[3:].endswith('.sln'), 'Corresponding serviced package source changed')
        relative = row[3:]
        path = checkout / relative
        raw = subprocess.check_output(['git', '-C', str(checkout), 'show', commit + ':' + relative])
        require(path.is_file() and not path.is_symlink() and path.read_bytes() == raw,
                'Canonical corresponding solution differs from its exact Git blob')


def validate_serviced_inputs(release, profile, source_manifest):
    sources = profile.get('supplementalSourceGit', [])
    if not sources:
        return
    report = load_json(release / 'reports/serviced-inputs.json')
    require(set(report) == {'schemaVersion', 'sdkVersion', 'gitSources'} and report['schemaVersion'] == 1
            and report['sdkVersion'] == profile['sdkVersion'] and len(report['gitSources']) == len(sources),
            'Serviced package/source review envelope differs')
    restored = load_json(release / 'reports/restored-inputs.json')['packages']
    notice_rows, mapped_baselines = {}, {}
    wanted = {source['name'] + '/' + name for source in sources for name in source['requiredNotices']}
    mapped = [source for source in sources if 'publisher' in source]
    wanted.update('serviced-publisher-metadata/' + source['name'] + '-source-manifest.json' for source in mapped)
    with (release / 'sources' / source_manifest['index']['path']).open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'] in wanted:
                notice_rows[row['path']] = row
            for source in mapped:
                prefix = source['name'] + '/' + source['publisher']['identicalLibraryTree']['sourcePath'] + '/'
                if row['path'].startswith(prefix):
                    require(row.get('baseline'), 'Corresponding library source is not an original Git member')
                    mapped_baselines.setdefault(source['name'], {})[row['path'][len(prefix):]] = row['baseline']
    require(set(notice_rows) == wanted, 'Corresponding serviced package licenses must be archived')
    for expected, actual in zip(sources, report['gitSources']):
        map_fields = {'publisher', 'publisherSourceManifest'} if 'publisher' in expected else set()
        require(set(actual) == {'name', 'repository', 'commit', 'role', 'requiredNotices', 'packages', 'tree', 'notices'} | map_fields
                and all(actual[key] == expected[key] for key in ('name', 'repository', 'commit', 'role', 'requiredNotices')),
                'Serviced package corresponding source identity differs')
        roots = [root for root in source_manifest['roots'] if root['name'] == expected['name']]
        require(len(roots) == 1 and roots[0].get('commit') == expected['commit']
                and roots[0].get('tree') == actual['tree'] and roots[0].get('role') == expected['role'],
                'Complete exact serviced package Git source must be retained')
        if map_fields:
            require(actual['publisher'] == expected['publisher'], 'Serviced publisher source map registry differs')
            descriptor = actual['publisherSourceManifest']
            relative = 'reports/serviced-inputs/source-maps/' + expected['name'] + '-source-manifest.json'
            require(set(descriptor) == {'path', 'bytes', 'sha256', 'sha512'} and descriptor['path'] == relative,
                    'Closed publisher source-map descriptor required')
            path = ordinary(release / relative)
            require(all(descriptor[key] == value for key, value in fingerprint(path).items())
                    and all(notice_rows['serviced-publisher-metadata/' + path.name][key] == descriptor[key]
                            for key in ('bytes', 'sha256', 'sha512')), 'Publisher source map is absent from complete used sources')
            validate_publisher_source_map(expected, path, mapped_baselines.get(expected['name']))
        require(len(actual['notices']) == len(expected['requiredNotices'])
                and len(actual['packages']) == len(expected['packages']), 'Serviced source review is incomplete')
        for name, notice in zip(expected['requiredNotices'], actual['notices']):
            require(set(notice) == {'path', 'bytes', 'sha256', 'sha512'} and notice['path'] == name
                    and all(notice_rows[expected['name'] + '/' + name][key] == notice[key]
                            for key in ('bytes', 'sha256', 'sha512')), 'Serviced source license bytes differ')
        for package, row in zip(expected['packages'], actual['packages']):
            filename = package['id'] + '.' + package['version'] + '.nupkg'
            relative = 'reports/serviced-inputs/packages/' + filename
            require(set(row) == {'id', 'version', 'bytes', 'sha512', 'license', 'sha256', 'nuspecSha256',
                                'repository', 'repositoryCommit', 'path', 'actualRestoreRecords'}
                    and row['path'] == relative, 'Serviced package record shape/path differs')
            metadata = serviced_package(release / relative, expected, package)
            require(all(row[key] == value for key, value in metadata.items()), 'Serviced package metadata differs')
            require(row['actualRestoreRecords'] and all(record in restored
                    and Path(record['path']).name.lower() == filename
                    and all(record[key] == row[key] for key in ('bytes', 'sha256', 'sha512'))
                    for record in row['actualRestoreRecords']), 'Serviced package lacks actual restored-byte evidence')


def validate_additional_inputs(release, profile, source_manifest=None):
    """Authenticate the exact imported target-support package and retained IL.

    The package is an unchanged upstream input. Its complete original IL,
    project, nuspec and licenses are retained; no local rebuild is claimed.
    """
    packages = profile.get('additionalPackages', [])
    if not packages:
        return None
    require(profile['sdkVersion'] == '9.0.123' and packages == R.NET9_ADDITIONAL_PACKAGES,
            'Unreviewed additional targeting input')
    report = load_json(release / 'reports/prepare/pinned-inputs.json')
    require(set(report) == {'feed', 'packages'} and report['feed'] == '/inputs/nuget'
            and len(report['packages']) == len(packages), 'Exact pinned targeting input report required')
    for expected, observed in zip(packages, report['packages']):
        require(observed == dict(expected, sizeBytes=expected['bytes'], sha256Verified=True,
            archiveIntegrityVerified=True, hashOrigin='Content fingerprint recorded from the public upstream URL, not a publisher signature'),
            'Pinned targeting input download/identity proof differs')
        path = release / 'pinned-inputs/nuget' / expected['fileName']
        require(fingerprint(path) == {key: expected[key] for key in ('bytes', 'sha256', 'sha512')},
                'Retained exact targeting package bytes differ')
        with zipfile.ZipFile(path) as archive:
            require(archive.testzip() is None, 'Pinned targeting ZIP integrity differs')
            names = [name for name in archive.namelist() if name.lower().endswith('.nuspec')]
            require(len(names) == 1 and archive.getinfo(names[0]).file_size < 1024**2, 'One bounded targeting nuspec required')
            raw = archive.read(names[0])
            require(b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'Unsafe targeting package metadata')
            metadata = ET.fromstring(raw).find('{*}metadata')
            require(metadata is not None and metadata.findtext('{*}id') == expected['id']
                    and metadata.findtext('{*}version') == expected['version'], 'Pinned targeting package identity differs')
    if source_manifest is None:
        return None
    restored = load_json(release / 'reports/restored-inputs.json')['packages']
    roots = [row for row in source_manifest['roots'] if row['name'] == 'vmr']
    require(len(roots) == 1 and roots[0]['kind'] == 'git' and roots[0]['commit'] == R.VERSIONS['9.0.123']['source'],
            'Pinned targeting support needs its complete original VMR source')
    proof = []
    for expected in packages:
        correspondence = expected['correspondingSource']
        prefix = correspondence['root'] + '/' + correspondence['path'] + '/'
        selected, retained = {}, []
        with (release / 'sources' / source_manifest['index']['path']).open() as stream:
            for line in stream:
                row = json.loads(line)
                if row['path'].startswith(prefix):
                    name = row['path'][len(prefix):]
                    require(name not in selected and row.get('baseline', {}).get('mode') in ('100644', '100755'),
                            'Duplicate or non-ordinary corresponding targeting source')
                    selected[name] = row
                if row['path'] == 'pinned-targeting-inputs/nuget/' + expected['fileName']:
                    retained.append({key: row[key] for key in ('bytes', 'sha256', 'sha512')})
        fp = {key: expected[key] for key in ('bytes', 'sha256', 'sha512')}
        packer = module('modern_targeting_source_tree', 'package-used-source.py')
        require(retained == [fp] and selected and packer.baseline_tree({name: row['baseline'] for name, row in selected.items()}) == correspondence['tree'],
                'Complete original targeting package and exact IL source Git tree must be retained')
        actual = set()
        with tarfile.open(release / 'sources' / source_manifest['archive']['path'], 'r|gz') as archive:
            for entry in archive:
                if not entry.name.startswith(prefix):
                    continue
                name = entry.name[len(prefix):]
                if name not in selected:
                    continue
                require(entry.isfile() and entry.size <= 64 * 1024**2 and name not in actual,
                        'Ordinary complete targeting source archive member required')
                raw = archive.extractfile(entry).read()
                require(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == selected[name]['baseline']['blob'],
                        'Corresponding targeting IL/project/license source differs from its pristine Git blob')
                actual.add(name)
        require(actual == selected.keys() and {'LICENSE.TXT', 'THIRD-PARTY-NOTICES.TXT',
                'netstandard.library.netframework.nuspec'} <= actual, 'Complete original targeting code and notices are absent')
        matches = [row for row in restored if Path(row['path']).name.lower() == expected['fileName']
                   and all(row.get(key) == expected[key] for key in fp)]
        require(matches, 'Pinned targeting package was not actually restored unchanged')
        proof.append(dict(package=expected, actualRestoreRecords=matches, sourceFiles=len(selected),
            sourceRoot='vmr', sourceCommit=roots[0]['commit'], sourceTree=correspondence['tree'],
            localBuildClaimed=False, byteIdenticalCompilationClaimed=False))
    return dict(schemaVersion=1, sdkVersion=profile['sdkVersion'], packages=proof)


def configure_feeds(source, reports, sdk):
    """Record the same public mirror choice without using the SDK10-only helper."""
    require(git(source, 'rev-parse', 'HEAD') == R.VERSIONS[sdk]['source'], 'Pinned feed source commit differs')
    old = 'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public/nuget/v3/index.json'
    new = 'https://api.nuget.org/v3/index.json'
    records = []
    for path in [source / 'NuGet.config', *sorted((source / 'src').glob('*/NuGet.config'))]:
        if not path.is_file():
            continue
        relative = path.relative_to(source).as_posix()
        original = subprocess.check_output(['git', '-C', str(source), 'show', 'HEAD:' + relative])
        text = original.decode('utf-8-sig')
        document = ET.fromstring(text)
        if document.find('packageSources') is None:
            continue
        text = text.replace(old, new)
        if sdk.startswith('9.'):
            require(document.find("packageSources/add[@key='pinned-microsoft']") is None,
                    'Pinned source unexpectedly defines the downstream exact-package feed')
            text = text.replace('</packageSources>', '    <add key="pinned-microsoft" value="/inputs/nuget" />\n  </packageSources>', 1)
        entry = '    <add key="maxHttpRequestsPerSource" value="8" />\n'
        limit = document.find("config/add[@key='maxHttpRequestsPerSource']")
        if limit is not None:
            require(limit.get('value') == '8', 'Unexpected pinned connection limit')
        elif document.find('config') is not None:
            text = text.replace('</config>', entry + '  </config>', 1)
        else:
            text = text.replace('</configuration>', '  <config>\n' + entry + '  </config>\n</configuration>', 1)
        adjusted = (b'\xef\xbb\xbf' if original.startswith(b'\xef\xbb\xbf') else b'') + text.encode('utf-8')
        ET.fromstring(adjusted)
        current = path.read_bytes()
        require(current == adjusted or current.replace(b'\r\n', b'\n') == original.replace(b'\r\n', b'\n'),
                'Unexpected preexisting NuGet configuration changes: ' + relative)
        path.write_bytes(adjusted)
        records.append(dict(path=relative, originalSha256=hashlib.sha256(original).hexdigest(),
                            adjustedSha256=hashlib.sha256(adjusted).hexdigest(), publicFeedReplaced=old in original.decode('utf-8-sig')))
    write(reports / 'feed-adjustments.json', dict(sourceCommit=R.VERSIONS[sdk]['source'],
        publicFeed=new, maxHttpRequestsPerSource=8, packageVersionsChanged=False, files=records))
    reports.joinpath('feed-adjustments.patch').write_bytes(subprocess.check_output(
        ['git', '-C', str(source), 'diff', '--no-ext-diff', '--', *[r['path'] for r in records]]))


def upstream_sdk_record(sdk, arch):
    """The original upstream SDK is only an independently hashed test baseline."""
    rid = R.ARCHITECTURES[arch]['rid']
    hashes = {
        ('9.0.123', 'x64'): 'cc448791a4dde3d0c114f233d6c0e3d0f924145cdd4c4b72bdff4f40c2fae7a7680ec5bec2883e604236e108095e0b4ffd5e9859f14c051bdab4deb9869eb7cd',
        ('9.0.123', 'aarch64'): '8772b5fd3912cf9568a30a4dab6bdfaf929b6936e78335eac15e366129df1e4d1cd45814bf0f111eadc62a2f481f2188ab4f0c724dd224098e39e4e6c89ccc12',
        ('8.0.133', 'x64'): '8a825832a2dab888b94f7cc05959998385ef8ee244def3628cff62feee49902ba4bacd0d7c229063ce6c64c16af9bfd1dcf29f7a6fd7b29b18284a54fac27744',
        ('8.0.133', 'aarch64'): '64bd84abf1baf1f24f0a1d412c0f61e3ac60b4eedc5312e8630cc1822c83d2c1c11a40b006defc9ad9d4c22a2b39b457b5132ea58fb842d9dde6918876f04cc7',
    }
    return dict(version=sdk, rid=rid, url='https://builds.dotnet.microsoft.com/dotnet/Sdk/' + sdk
                + '/dotnet-sdk-' + sdk + '-' + rid + '.tar.gz', sha512=hashes[sdk, arch])


def archive_files(path, prefix=''):
    """Compare every file/link byte without extracting or accepting external names."""
    rows = {}
    with tarfile.open(path, 'r:gz') as stream:
        for entry in stream:
            name = entry.name.removeprefix('./')
            if not name.startswith(prefix) or entry.isdir():
                continue
            key = name[len(prefix):]
            require(key and '\\' not in key and ':' not in key and not key.startswith('/')
                    and '..' not in Path(key).parts and key not in rows, 'Unsafe/duplicate framework member')
            if entry.issym():
                require(not entry.linkname.startswith('/') and '..' not in Path(entry.linkname).parts,
                        'Framework link escapes archive')
                rows[key] = dict(kind='symlink', target=entry.linkname)
            else:
                require(entry.isfile() or entry.islnk(), 'Unexpected framework archive entry')
                incoming = stream.extractfile(entry)
                require(incoming is not None, 'Framework hardlink is unresolved')
                digest = hashlib.sha256()
                size = 0
                for block in iter(lambda: incoming.read(1024 * 1024), b''):
                    size += len(block)
                    digest.update(block)
                rows[key] = dict(kind='file', bytes=size, sha256=digest.hexdigest())
    return rows


class Producer(P.Producer):
    """Inherit only the version-independent secure execution/stage primitives."""
    def __init__(self, args):
        self.args, self.sdk = args, args.sdk_version
        self.route = R.VERSIONS[self.sdk]
        self.diagnostic_ptrace = args.diagnostic_ptrace
        self.id = P.identity(args.arch)
        self.workspace, self.output = ordinary(args.workspace), ordinary(args.output_dir)
        require(self.workspace != self.output and self.workspace not in self.output.parents
                and self.output not in self.workspace.parents, 'Separate ordinary source and delivery paths required')
        self.profile_path = ROOT / 'profiles' / ('dotnet-' + self.sdk + '-linux-musl-' + args.arch + '.json')
        self.profile = R.profile(self.sdk, args.arch)
        self.source, self.home = self.workspace / 'source', self.workspace / 'home'
        self.inputs, self.image_context = self.workspace / 'inputs', self.workspace / 'image-context'
        self.reports = self.output / 'reports'
        self.image = self.verify_image = None
        self.project = git(ROOT, 'rev-parse', 'HEAD')
        self.engine, self.commands = P.container_engine(self.diagnostic_ptrace), []

    def container_security_options(self, *, source):
        cpus = sorted(os.sched_getaffinity(0))[:2]
        require(len(cpus) == 2, 'Two matching native CPUs are required')
        return super().container_security_options(source=source) + ['--cpuset-cpus=' + ','.join(map(str, cpus))]

    def diagnostic_options(self):
        # Crossgen2 tool packs intentionally omit createdump. Enabling runtime
        # dumps globally makes their valid ReadyToRun invocations fail before
        # compilation. Preserve MSBuild diagnostics in every normal build.
        path = self.reports / 'diagnostics' / ('container-' + str(len(self.commands)).zfill(4))
        path.mkdir(parents=True)
        options = ['--volume', str(path) + ':/diag', '--env', 'MSBUILDDEBUGPATH=/diag',
                   '--env', 'MSBUILDDEBUGCOMM=1']
        if self.diagnostic_ptrace:
            options += ['--env', 'DOTNET_DbgEnableMiniDump=1', '--env', 'DOTNET_DbgMiniDumpType=1',
                        '--env', 'DOTNET_DbgMiniDumpName=/diag/dotnet_%e_%p_%t.dmp',
                        '--env', 'DOTNET_EnableCrashReport=1', '--env', 'DOTNET_CreateDumpDiagnostics=1']
        return options

    def prepare(self):
        require(platform.system() == 'Linux' and platform.machine() == self.id['machine'] and os.getuid() != 0,
                'An unprivileged matching native Linux host is required')
        require(not git(ROOT, 'status', '--porcelain', '--untracked-files=all'), 'Pristine orchestration checkout required')
        require(not self.output.exists() and not self.source.exists(), 'Fresh source and delivery paths required')
        self.output.mkdir(parents=True)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.home.mkdir(mode=0o700)
        self.inputs.mkdir()
        self.record_container_engine()
        P.prepare_image_context(self.profile, self.image_context)
        self.run(['git', 'clone', '--depth', '1', '--branch', 'v' + self.sdk, '--',
                  'https://github.com/dotnet/dotnet', str(self.source)], self.reports / 'prepare/source.log')
        require(git(self.source, 'rev-parse', 'HEAD') == self.route['source'], 'Pinned VMR tag moved')
        self.build_image()
        self.prepare_runtime_image()
        self.container(['sh', '-ec', 'cp -a /cbodotnet-apks /delivery/reports/prepare/apks; '
            'apk info -vv > /delivery/reports/prepare/installed-packages.txt; '
            'cp -a /etc/apk/keys /delivery/reports/prepare/apk-keys; '
            'cp /etc/apk/repositories /delivery/reports/prepare/repositories; '
            'test "$(cat /etc/alpine-release)" = 3.24.4; '
            '! apk info -e gcompat; ! apk info -e libc6-compat; '
            'test ! -e /lib/ld-linux-x86-64.so.2; test ! -e /lib/ld-linux-aarch64.so.1; '
            '/usr/bin/clang-20 --version; cmake --version'], log=self.reports / 'prepare/native-tools.log')
        archive = self.inputs / 'bootstrap-sdk.tar.gz'
        write(self.reports / 'prepare/bootstrap.json', download(self.profile['bootstrap'], archive))
        dotnet = self.source / '.dotnet'
        dotnet.mkdir()
        with tarfile.open(archive, 'r:gz') as stream:
            stream.extractall(dotnet, filter='data')
        self.container(['/vmr/.dotnet/dotnet', '--info'], network='none', log=self.reports / 'prepare/bootstrap-info.log')
        self.container(['/vmr/.dotnet/dotnet', 'msbuild', '-version'], network='none',
                       log=self.reports / 'prepare/bootstrap-msbuild.log')
        self.container(['/vmr/.dotnet/dotnet', 'msbuild', '/project/scripts/probe-source-cultures.proj',
            '/p:SourceCultureReport=/delivery/reports/prepare/source-cultures.json',
            '/t:ProbeSourceCultures', '/nr:false', '/nologo'], network='none', log=self.reports / 'prepare/source-cultures.log')
        cultures = load_json(self.reports / 'prepare/source-cultures.json')
        require({r['culture'] for r in cultures['resources']} == set(P.SOURCE_CULTURES)
                and all(r['withCulture'] for r in cultures['resources'])
                and cultures['msbuildToolsPath'] == '/vmr/.dotnet/sdk/' + self.route['bootstrap'],
                'Exact native bootstrap must resolve all 13 source translation cultures using full ICU')
        write(self.reports / 'prepare/official-sdk.json', download(upstream_sdk_record(self.sdk, self.args.arch),
                                                                  self.inputs / 'official-sdk.tar.gz'))
        if self.sdk.startswith('9.'):
            self.container(['python3', '/project/scripts/fetch-pinned-inputs.py', '--profile',
                '/project/' + self.profile_path.relative_to(ROOT).as_posix(), '--inputs-dir', '/delivery/pinned-inputs',
                '--reports-dir', '/delivery/reports/prepare'])
            validate_additional_inputs(self.output, self.profile)
            shutil.copytree(self.output / 'pinned-inputs/nuget', self.inputs / 'nuget')
        configure_feeds(self.source, self.reports / 'prepare/feeds', self.sdk)
        if self.route['sourceOnly']:
            # Download/preserve the pristine PSB before original prep replaces it.
            url = net8_source_built_artifacts_url(self.source / 'eng/Versions.props')
            original = self.inputs / 'original-psb.tar.gz'
            with urllib.request.urlopen(url, timeout=120) as incoming, original.open('xb') as target:
                shutil.copyfileobj(incoming, target, 1024 * 1024)
            write(self.reports / 'prepare/original-psb.json', net8_psb_record(original))
            # prep skips transformation when an archive already exists; leave its
            # destination absent and verify its download equals the preserved input.
            sidecar = self.inputs / 'actual-prep-psb.tar.gz'
            finished = threading.Event()
            def retain_prep_download():
                path = self.source / 'prereqs/packages/archive' / url.rsplit('/', 1)[-1]
                while not finished.wait(.02):
                    try:
                        os.link(path, sidecar)
                        return
                    except FileNotFoundError:
                        continue
            watcher = threading.Thread(target=retain_prep_download, daemon=True)
            watcher.start()
            try:
                self.container(['./prep.sh', '--no-sdk'], log=self.reports / 'prepare/prep.log')
            finally:
                finished.set()
                watcher.join()
            require(sidecar.is_file() and fingerprint(sidecar) == fingerprint(original),
                    'The original prep PSB download differs from its preserved pristine upstream input')
            write(self.reports / 'prepare/actual-prep-psb.json', net8_psb_record(sidecar))
            transformed = self.source / 'prereqs/packages/archive/Private.SourceBuilt.Artifacts.Bootstrap.tar.gz'
            require(transformed.is_file(), 'Original NET8 prep did not produce the bootstrap PSB')
            write(self.reports / 'prepare/transformed-psb.json', dict(path=transformed.relative_to(self.source).as_posix(),
                                                                   **fingerprint(transformed)))
        else:
            targets = self.source / 'repo-projects/Directory.Build.targets'
            original = targets.read_bytes()
            adjusted = P.instrument_input_recording(original)
            targets.write_bytes(adjusted)
            write(self.reports / 'prepare/input-recording-hook.json', dict(path='repo-projects/Directory.Build.targets',
                  sourceCommit=self.route['source'], originalSha256=hashlib.sha256(original).hexdigest(),
                  adjustedSha256=hashlib.sha256(adjusted).hexdigest(), beforeTarget='CleanupRepo'))
        for patch in self.profile['build']['patches']:
            self.run(['git', '-C', str(self.source), 'apply', '--check', str(ROOT / patch['path'])])
            self.run(['git', '-C', str(self.source), 'apply', str(ROOT / patch['path'])])
        self.prepare_serviced_inputs()
        write(self.reports / 'prepare/source-patches.json', dict(sourceCommit=self.route['source'],
            patches=self.profile['build']['patches'], packageAuditEnabled=True,
            scope='Recorded minimal source adaptations; final SDK MSBuild remains built from the pinned product sources.'))
        write(self.reports / 'prepare/identity.json', dict(schemaVersion=2, sdkVersion=self.sdk,
            sourceCommit=self.route['source'], targetRid=self.id['rid'], libc='musl', architecture=self.args.arch,
            projectCommit=self.project, runId=self.args.run_id, runAttempt=self.args.run_attempt,
            buildId=self.args.build_id, diagnosticPtrace=self.diagnostic_ptrace,
            sourceAppArmorPolicy='unconfined' if self.diagnostic_ptrace else 'engine-default',
            consumerAppArmorPolicy='engine-default', sourceSeccompPolicy='engine-default', consumerSeccompPolicy='engine-default',
            nativeKernelVersion=platform.release(), nativeArchitecture=platform.machine(), emulation=False,
            bootstrapRoot='/vmr/.dotnet', containerEngine=self.engine_record, imageId=self.image,
            verificationImageId=self.verify_image, profile=dict(path=self.profile_path.name, **fingerprint(self.profile_path))))
        if self.args.host_reports:
            shutil.copytree(ordinary(self.args.host_reports), self.reports / 'ci-host')

    def prepare_serviced_inputs(self):
        sources = self.profile.get('supplementalSourceGit', [])
        if not sources:
            return
        directory = self.workspace / 'supplemental-sources'
        directory.mkdir()
        packages = self.reports / 'serviced-inputs/packages'
        packages.mkdir(parents=True)
        rows = []
        for source in sources:
            checkout = directory / source['name']
            commands = [
                ['git', 'init', str(checkout)],
                ['git', '-C', str(checkout), 'remote', 'add', 'origin', source['repository']],
                ['git', '-C', str(checkout), 'fetch', '--depth', '1', 'origin', source['commit']],
                ['git', '-C', str(checkout), 'checkout', '--detach', 'FETCH_HEAD'],
                ['git', '-C', str(checkout), 'submodule', 'update', '--init', '--recursive', '--depth', '1']]
            for index, command in enumerate(commands):
                self.run(command, self.reports / 'prepare' / (source['name'] + '-' + str(index) + '.log'))
            require(git(checkout, 'rev-parse', 'HEAD') == source['commit']
                    and not git(checkout, 'status', '--porcelain', '--untracked-files=all'),
                    'Corresponding serviced package source must be pristine')
            # Some publisher repos request CRLF solution checkouts. These are
            # attribution sources, never the working VMR: retain the exact Git
            # blob so the protected pristine-source gate needs no new exception.
            for relative in git(checkout, 'ls-files', '-z', '--', '*.sln').split('\0'):
                if not relative:
                    continue
                path = checkout / relative
                raw = subprocess.check_output(['git', '-C', str(checkout), 'show', source['commit'] + ':' + relative])
                actual = path.read_bytes()
                require(actual == raw or actual.replace(b'\r\n', b'\n') == raw,
                        'Corresponding solution checkout differs beyond canonical Git line endings')
                if actual != raw:
                    path.write_bytes(raw)
            pristine_corresponding_checkout(checkout, source['commit'])
            notices = [dict(path=name, **fingerprint(checkout / name)) for name in source['requiredNotices']]
            publisher_map = {}
            if 'publisher' in source:
                publisher = source['publisher']
                mapping = self.reports / 'serviced-inputs/source-maps' / (source['name'] + '-source-manifest.json')
                mapping.parent.mkdir(exist_ok=True)
                url = 'https://raw.githubusercontent.com/dotnet/dotnet/' + publisher['commit'] + '/src/source-manifest.json'
                with urllib.request.urlopen(url, timeout=120) as response:
                    raw = response.read(1024 * 1024 + 1)
                require(0 < len(raw) <= 1024 * 1024, 'Publisher source manifest exceeds its bound')
                mapping.write_bytes(raw)
                validate_publisher_source_map(source, mapping)
                require(git(checkout, 'rev-parse', 'HEAD:' + publisher['identicalLibraryTree']['sourcePath'])
                        == publisher['identicalLibraryTree']['tree'], 'Original component library tree differs from reviewed publisher tree')
                publisher_map['publisherSourceManifest'] = dict(path=mapping.relative_to(self.output).as_posix(), **fingerprint(mapping))
            imported = []
            for package in source['packages']:
                name = package['id'] + '.' + package['version'] + '.nupkg'
                path = packages / name
                download(dict(url='https://api.nuget.org/v3-flatcontainer/' + package['id'] + '/'
                              + package['version'] + '/' + name, sha512=package['sha512']), path)
                imported.append(dict(serviced_package(path, source, package), path=path.relative_to(self.output).as_posix()))
            rows.append(dict(source, tree=git(checkout, 'rev-parse', 'HEAD^{tree}'), notices=notices, packages=imported, **publisher_map))
        write(self.reports / 'prepare/serviced-inputs.json', dict(schemaVersion=1, sdkVersion=self.sdk, gitSources=rows))

    def build_image(self):
        # Keep the SDK10 recipe immutable; modern runtime builds also need krb5-dev.
        recipe = ROOT / 'containers' / (self.args.arch + '-modern-musl.Containerfile')
        tag = 'localhost/cbodotnet-modern-musl-build:' + self.sdk + '-' + self.args.run_id + '-' + self.args.arch
        self.run(self.engine + ['build', '--network=host', '--file', str(recipe), '--tag', tag, str(self.image_context)],
                 self.reports / 'prepare/image-build.log')
        inspect = json.loads(self.run(self.engine + ['image', 'inspect', tag], capture=True))
        require(len(inspect) == 1 and inspect[0]['Architecture'] == self.id['image'] and inspect[0]['Os'] == 'linux',
                'Actual build image must match the native CPU')
        self.image = inspect[0]['Id']
        write(self.reports / 'prepare/build-image.json', inspect)

    def build_command(self, test=False):
        return R.build_command(self.sdk, self.args.arch, test, '/inputs/official-sdk.tar.gz' if test else None)

    def build(self):
        try:
            self.container(self.build_command(), log=self.reports / 'build/build.log')
        finally:
            if self.route['sourceOnly']:
                try:
                    module('modern_source_failure_diagnostics', 'musl_build_diagnostics.py').capture(
                        self.source, self.reports / 'diagnostics/source-assets')
                except Exception as error:
                    write(self.reports / 'diagnostics/source-assets-capture-error.json',
                          dict(kind='source-assets-diagnostic-capture-error', error=str(error), qualificationAllowed=False))
        if self.route['sourceOnly']:
            log = self.reports / 'build/reference-audit.log'
            shutil.copyfile(self.source / 'artifacts/logs/source-build-assets.log', log)
            module('modern_reference_audit', 'musl_reference_audit.py').warning_graph(log.read_text())
        if not self.route['sourceOnly']:
            # The NET9 tools traversal builds only its task/resolver projects;
            # its standalone original BinaryToolKit must be built explicitly.
            self.container(['/vmr/.dotnet/dotnet', 'build', '/vmr/eng/tools/BinaryToolKit/BinaryToolKit.csproj',
                '--configuration', 'Release'], log=self.reports / 'build/binary-toolkit-build.log')

    def scan(self):
        self.clean = self.workspace / 'clean-source'
        self.run(['git', 'clone', '--local', '--no-hardlinks', '--branch', 'v' + self.sdk,
                  '--', str(self.source), str(self.clean)])
        require(git(self.clean, 'rev-parse', 'HEAD') == self.route['source']
                and not git(self.clean, 'status', '--porcelain', '--untracked-files=all', '--ignored=matching'),
                'Independent source audit requires an unchanged pristine checkout')
        # NET8 has no BinaryToolKit/allowed-vmr policy. Inventory every pinned
        # source file/header instead of asserting an invented zero-binary scan.
        support = module('modern_source_inventory', 'ci_vmr89_support.py')
        record = support.write_source_header_inventory(self.clean, self.output)
        if not self.route['sourceOnly']:
            record['scope'] = 'Complete pristine pinned NET9 source Git-kind/header inventory, alongside the original standalone BinaryToolKit validation.'
        write(self.reports / 'scan/pinned-source-inventory.json', record)
        if not self.route['sourceOnly']:
            argv = self.engine + ['run', '--rm', '--network=none', '--user', str(os.getuid()) + ':' + str(os.getgid()),
                *self.container_security_options(source=True), '--env', 'HOME=/home/build',
                '--volume', str(self.home) + ':/home/build', '--volume', str(self.source) + ':/vmr:ro',
                '--volume', str(self.clean) + ':/clean:ro', '--volume', str(ROOT) + ':/project:ro',
                '--volume', str(self.output) + ':/delivery', '--workdir', '/clean'] + self.bootstrap_environment() + self.diagnostic_options()
            argv += [self.image] + self.observed_command(['/vmr/.dotnet/dotnet',
                '/vmr/artifacts/bin/BinaryToolKit/Release/BinaryToolKit.dll', 'validate', '/clean',
                '-o', '/delivery/reports/scan', '-ab', '/clean/eng/allowed-vmr-binaries.txt', '-l', 'Debug'])
            self.run(argv, self.reports / 'scan/scan.log')
            P.validate_default_container_policy(self.output, list(map(str, argv)))
            report = self.reports / 'scan/NewBinaries.txt'
            require(report.is_file() and not report.read_bytes(), 'Original NET9 upstream binary scan failed')
        require(not git(self.clean, 'status', '--porcelain', '--untracked-files=all', '--ignored=matching'),
                'Independent source audit changed its pristine checkout')

    def test(self):
        major = self.sdk.split('.')[0]
        if major == '9':
            self.container(['python3', '/project/scripts/prepare-scenario-report-fence.py', 'apply', '--version', '9',
                '--source-dir', '/vmr', '--reports-dir', '/delivery/reports/test/scenario-report-fence'])
        self.container(self.build_command(True), log=self.reports / 'test/test.log')
        base = self.source / ('test/Microsoft.DotNet.SourceBuild.SmokeTests/TestResults' if major == '8'
                              else 'artifacts/TestResults/Release')
        results = list(base.glob('*.trx'))
        require(len(results) == 1, 'One actual fresh original upstream TRX required')
        shutil.copyfile(results[0], self.reports / 'test/common.trx')
        scenario = None
        if major == '9':
            scenarios = list((base / 'scenario-tests').glob('*.xml'))
            require(len(scenarios) == 1, 'One actual fresh NET9 scenario XML required')
            scenario = self.reports / 'test/scenarios.xml'
            shutil.copyfile(scenarios[0], scenario)
        write(self.reports / 'test/upstream-summary.json', R.parse_upstream_results(
            self.sdk, self.args.arch, self.reports / 'test/common.trx', scenario))

    def collect(self):
        collector = module('modern_artifact_collector', 'collect-artifacts.py')
        upstream, candidates, _ = collector.select_sdk(self.source, self.sdk, self.id['rid'], exact_name=True)
        fp = fingerprint(upstream)
        require(all({key: row[key] for key in fp} == fp for row in candidates), 'Conflicting upstream output SDK archives')
        self.archive = self.output / ('cbodotnet-sdk-' + self.sdk + '-linux-musl-' + self.args.arch
                                      + '-build.' + self.args.run_id + '.tar.gz')
        shutil.copyfile(upstream, self.archive)
        require(fingerprint(self.archive) == fp and fp['sha512'] != upstream_sdk_record(self.sdk, self.args.arch)['sha512'],
                'SDK must be a newly built unchanged output, never the upstream comparison archive')
        if self.route['sourceOnly']:
            audit = module('modern_reference_payload_audit', 'musl_reference_audit.py')
            write(self.reports / 'build/reference-audit.json', audit.report(self.output, self.archive))
        self.collect_construction()
        records = []
        for path in sorted((self.reports / 'restored-inputs').glob('*.json')):
            record = load_json(path)
            require(record.get('schemaVersion') == 1 and record.get('packages'), 'Invalid pre-cleanup restored input record')
            records.extend(dict(repository=record['repository'], cache=record['cache'], **row) for row in record['packages'])
        for cache in [self.home / '.nuget/packages', self.source / '.packages',
                      *sorted((self.source / 'src').glob('*/artifacts/.packages')),
                      *sorted((self.source / 'src').glob('*/artifacts/sb/package-cache'))]:
            records.extend(dict(cache=str(cache), **row) for row in inventory_cache(cache))
        write(self.reports / 'restored-inputs.json', dict(schemaVersion=1, packages=records))
        require(records, 'Actual restored upstream input byte inventory required')
        (self.reports / 'ci-inputs').mkdir(exist_ok=True)
        shutil.copyfile(self.reports / 'restored-inputs.json', self.reports / 'ci-inputs/restored-inputs.json')
        support = module('modern_consumer_roots', 'ci_vmr89_support.py')
        roots, ledger = support.consumer_roots(self.source, self.sdk.split('.')[0])
        roots[0]['role'] = 'built-sdk-vmr-source-and-corresponding-imported-input-source'
        if self.sdk.startswith('9.'):
            roots.append(dict(name='pinned-targeting-inputs', path=str(self.output / 'pinned-inputs'), kind='tree',
                              role='actual-unchanged-imported-targeting-support-package-inputs'))
        sources = self.profile.get('supplementalSourceGit', [])
        if sources:
            servicing = load_json(self.reports / 'prepare/serviced-inputs.json')
            for source, row in zip(sources, servicing['gitSources']):
                checkout = self.workspace / 'supplemental-sources' / source['name']
                pristine_corresponding_checkout(checkout, source['commit'])
                roots.append(dict(name=source['name'], path=str(checkout), kind='git',
                                  expectedCommit=source['commit'], role=source['role']))
                for package in row['packages']:
                    filename = Path(package['path']).name
                    matches = [record for record in records if Path(record['path']).name.lower() == filename
                               and all(record[key] == package[key] for key in ('bytes', 'sha256', 'sha512'))]
                    require(matches, 'Serviced package was not actually restored: ' + filename)
                    package['actualRestoreRecords'] = matches
            write(self.reports / 'serviced-inputs.json', servicing)
            if any('publisher' in source for source in sources):
                roots.append(dict(name='serviced-publisher-metadata', path=str(self.reports / 'serviced-inputs/source-maps'),
                                  kind='tree', role='corresponding-serviced-package-publisher-component-source-map'))
        roots_file = self.reports / 'source-roots.json'
        write(roots_file, dict(schemaVersion=1, roots=roots))
        write(self.reports / 'ci-inputs/source-exclusions.json', dict(exclusions=ledger))
        packer = module('modern_used_source_packer', 'package-used-source.py')
        (self.reports / 'ci').mkdir(exist_ok=True)
        packer.pack(SimpleNamespace(project_root=ROOT, project_commit=self.project, output_dir=self.output / 'sources',
            roots_json=roots_file, sdk_version=self.sdk, target_rid=self.id['rid'], run_id=self.args.run_id,
            run_attempt=self.args.run_attempt))
        source_manifest = packer.verify(SimpleNamespace(release_dir=self.output, expected_project_commit=self.project,
            expected_run_id=self.args.run_id, expected_run_attempt=self.args.run_attempt, expected_target_rid=self.id['rid']))
        if self.sdk.startswith('9.'):
            write(self.reports / 'additional-inputs.json', validate_additional_inputs(self.output, self.profile, source_manifest))
        write(self.output / 'producer-sdk.json', dict(schemaVersion=1, kind='musl-sdk-build', producerRevision=1,
            sdkVersion=self.sdk, architecture=self.args.arch, targetRid=self.id['rid'], libc='musl',
            sourceCommit=self.route['source'], projectCommit=self.project, runId=self.args.run_id,
            runAttempt=self.args.run_attempt, imageId=self.image, sdk=dict(name=self.archive.name, **fp)))

    def collect_construction(self):
        self.replay_construction()
        runtime = self.route['runtime']
        components = []
        manifest = load_json(self.source / 'src/source-manifest.json')
        mapped = {r['path']: r['commitSha'] for r in manifest['repositories']}
        require(mapped['runtime'] == self.route['runtimeSource'] and mapped['aspnetcore'] == self.route['aspnetSource'],
                'Pinned component sources differ')
        destination = self.reports / 'construction/archives'
        destination.mkdir(parents=True)
        for framework, prefix, component, must_build in [
                ('Microsoft.NETCore.App', 'dotnet-runtime-', 'runtime', True),
                ('Microsoft.AspNetCore.App', 'aspnetcore-runtime-', 'aspnetcore', self.route['sourceOnly'])]:
            basename = prefix + runtime + '-' + self.id['rid'] + '.tar.gz'
            sdk_files = archive_files(self.archive, 'shared/' + framework + '/' + runtime + '/')
            require(len(sdk_files) >= 100, 'Complete final shared framework required')
            matches = []
            for path in sorted(self.source.rglob(basename)):
                require(not path.is_symlink(), 'Component origin archive is redirected')
                files = archive_files(path, 'shared/' + framework + '/' + runtime + '/')
                if files != sdk_files:
                    continue
                relative = path.relative_to(self.source).as_posix()
                local = relative.startswith('src/' + component + '/artifacts/') and '/downloads/' not in relative
                matches.append(dict(sourceRelativePath=relative, origin='rebuilt' if local else 'upstream-or-feed',
                                    **fingerprint(path)))
            require(matches and (not must_build or any(row['origin'] == 'rebuilt' for row in matches)),
                    'Final shared framework lacks complete byte identity with its required local producer: ' + framework)
            selected = next((row for row in matches if row['origin'] == 'rebuilt'), matches[0])
            tasks = [json.loads(line) for line in (self.reports / 'construction/downloads-tasks.jsonl').read_text().splitlines() if line]
            attempts = []
            for task in tasks:
                events = task.get('events', [])
                if task.get('succeeded') is not True or task.get('taskName') != 'DownloadFile':
                    continue
                require(events and events[0]['kind'] == 'task-started' and events[-1]['kind'] == 'task-finished'
                        and events[-1].get('succeeded') is True, 'Actual successful DownloadFile event boundaries required')
                candidates = [e for e in events if e.get('kind') in ('local-copy-attempt', 'network-download-attempt')]
                for event in candidates:
                    origin, consumed = event.get('source', ''), event.get('destination', '')
                    if not origin.endswith('/' + basename) or not consumed.endswith('/' + basename):
                        continue
                    require(len(candidates) == 1 and consumed.startswith('/vmr/'), 'Ambiguous or external consumed component archive')
                    received = self.source / consumed.removeprefix('/vmr/')
                    require(received.is_file() and fingerprint(received)['sha256'] == selected['sha256'],
                            'Actual consumed component bytes differ from the proven local producer/final SDK')
                    if event['kind'] == 'local-copy-attempt':
                        local = unquote(urlsplit(origin).path) if origin.startswith('file:') else origin
                        require(local.startswith('/vmr/artifacts/'), 'Actual component copy must originate from this build feed')
                        feed = self.source / local.removeprefix('/vmr/')
                        require(feed.is_file() and fingerprint(feed)['sha256'] == selected['sha256']
                                and selected['origin'] == 'rebuilt', 'Actual local feed bytes lack their rebuilt component producer')
                    else:
                        uri = urlsplit(origin)
                        require(not must_build and framework == 'Microsoft.AspNetCore.App' and uri.scheme == 'https'
                                and uri.hostname == 'ci.dot.net' and uri.path.startswith('/public/aspnetcore/Runtime/' + runtime)
                                and not uri.username and not uri.password and not uri.query and not uri.fragment,
                                'Unexpected imported component download origin')
                    attempts.append(dict(context=task['context'], event=event,
                        consumed=dict(path=consumed, **fingerprint(received))))
            require(len(attempts) == 1, 'One successful actual consumed component archive required: ' + framework)
            source = self.source / selected['sourceRelativePath']
            retained = destination / (selected['sha256'] + '.tar.gz')
            if not retained.exists():
                shutil.copyfile(source, retained)
            components.append(dict(component=framework, sourceCommit=mapped[component], runtimeVersion=runtime,
                origin=selected['origin'], completeFileCount=len(sdk_files), selected=selected, matches=matches,
                actualConsumption=attempts[0],
                archive=dict(path=retained.relative_to(self.output).as_posix(), **fingerprint(retained))))
        write(self.reports / 'construction.json', dict(schemaVersion=2, sdkSource=self.route['source'],
            sourceOnly=self.route['sourceOnly'], crossBuild=False, runtimeVersion=runtime,
            bootstrapSdk=self.route['bootstrap'], components=components,
            note='SDK and core runtime are genuinely rebuilt. Actual imported inputs and complete corresponding sources are retained; no source-purity claim.'))

    def replay_construction(self):
        """Retain/replay actual installer DownloadFile tasks using the native bootstrap."""
        relative = ('src/installer/artifacts/source-build/self/src/artifacts/sourcebuild.binlog'
                    if self.route['sourceOnly'] else 'src/sdk/artifacts/buildLogs/log/Release/source-inner-build.binlog')
        source = self.source / relative
        require(source.is_file() and source.stat().st_size > 0 and not source.is_symlink(),
                'Actual original SDK consumer binlog required')
        report = self.reports / 'construction'
        report.mkdir(parents=True)
        shutil.copyfile(source, report / 'consumer.binlog')
        analysis = report / 'analysis'
        shutil.copytree(ROOT / 'scripts/musl-modern-reader', analysis)
        (analysis / 'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>\n')
        major = self.sdk.split('.')[0]
        sdk = '/vmr/.dotnet/sdk/' + self.route['bootstrap']
        self.container(['/vmr/.dotnet/dotnet', 'build', '/delivery/reports/construction/analysis/Reader.csproj',
            '--configuration', 'Release', '--configfile', '/delivery/reports/construction/analysis/NuGet.Config',
            '/p:BootstrapMajor=' + major, '/p:BootstrapSdkDir=' + sdk], network='none',
            log=report / 'reader-build.log')
        self.container(['/vmr/.dotnet/dotnet', '/delivery/reports/construction/analysis/bin/Release/net' + major + '.0/Reader.dll',
            '/delivery/reports/construction/consumer.binlog', sdk, '/delivery/reports/construction/downloads',
            self.route['runtime'], self.id['rid']], network='none', log=report / 'reader-replay.log')
        replay = load_json(report / 'downloads-status.json')
        require(replay.get('completedReplay') is True and replay.get('buildSucceeded') is True
                and replay.get('unfinishedTasks') == 0 and replay.get('completedDownloadTasks', 0) >= 2
                and replay.get('inputSha256') == fingerprint(report / 'consumer.binlog')['sha256'],
                'Complete successful actual consumer binlog replay required')

    def verify(self):
        require(self.verify_image is not None, 'SDK-free verification image must be frozen in prepare')
        arch = R.ARCHITECTURES[self.args.arch]['upstream']
        self.container(['sh', '-ec', '! command -v dotnet; ! apk info -e gcompat; ! apk info -e libc6-compat; '
            'test "$(cat /etc/alpine-release)" = 3.24.4; '
            'bash /project/scripts/verify-sdk.sh --archive /delivery/' + self.archive.name
            + ' --output-dir /delivery/reports/verify/sdk --expected-version ' + self.sdk
            + ' --expected-rid ' + self.id['rid'] + ' --arch ' + arch + ' --framework net' + self.sdk.split('.')[0] + '.0; '
            'python3 /project/scripts/musl-sdk-audit.py --archive /delivery/' + self.archive.name
            + ' --output /delivery/reports/verify/elf.json --arch ' + self.args.arch],
            network='none', source=False, image=self.verify_image, log=self.reports / 'verify/native.log')

    def seal(self):
        require(not self.diagnostic_ptrace, 'Diagnostic runs may never qualify')
        for stage in STAGES:
            require(load_json(self.reports / 'stages' / (stage + '.json'))['status'] == 'passed', 'Required stage failed')
        rows = [dict(path=p.relative_to(self.output).as_posix(), **fingerprint(p))
                for p in sorted(self.output.rglob('*')) if p.is_file() and not p.is_symlink()]
        write(self.output / 'producer-validation.json', dict(schemaVersion=2, producerRevision=1,
            kind='musl-sdk-producer-validation', status='passed', diagnosticPtrace=False, sdkVersion=self.sdk,
            architecture=self.args.arch, targetRid=self.id['rid'], libc='musl', sourceCommit=self.route['source'],
            projectCommit=self.project, runId=self.args.run_id, runAttempt=self.args.run_attempt,
            allRequiredStages=STAGES, files=rows))
        validate(self.output)

    def execute(self):
        for name in STAGES:
            self.stage(name, getattr(self, name))
            if self.diagnostic_ptrace and name == 'build':
                write(self.output / 'producer-validation.json', dict(schemaVersion=2, status='diagnostic-only',
                    productionQualification=False, diagnosticPtrace=True, sdkVersion=self.sdk,
                    sourceCommit=self.route['source'], architecture=self.args.arch))
                return
        self.seal()


def validate(release):
    """Admission independently replays report interpretation and binds all bytes."""
    release = ordinary(release)
    result = load_json(release / 'producer-validation.json')
    require(result.get('diagnosticPtrace') is False, 'Diagnostic/unspecified source construction cannot qualify')
    require(result.get('schemaVersion') == 2 and result.get('producerRevision') == 1
            and result.get('kind') == 'musl-sdk-producer-validation' and result.get('status') == 'passed'
            and result.get('sdkVersion') in R.VERSIONS and result.get('architecture') in R.ARCHITECTURES,
            'Unexpected modern producer identity')
    sdk, arch = result['sdkVersion'], result['architecture']
    profile = R.profile(sdk, arch)
    route, identity = R.VERSIONS[sdk], R.ARCHITECTURES[arch]
    require(result.get('sourceCommit') == route['source'] and result.get('targetRid') == identity['rid']
            and result.get('libc') == 'musl' and result.get('allRequiredStages') == STAGES
            and re.fullmatch('[a-f0-9]{40}', result.get('projectCommit', ''))
            and all(re.fullmatch('[1-9][0-9]*', result.get(k, '')) for k in ('runId', 'runAttempt')),
            'Exact reviewed source/RID/run and all six stages required')
    P.delivery_index(release, result.get('files'))
    stages = {}
    previous = None
    for name in STAGES:
        stage = load_json(release / 'reports/stages' / (name + '.json'))
        require(stage.get('stage') == name and stage.get('status') == 'passed' and isinstance(stage.get('commands'), list)
                and (stage['commands'] or name == 'collect'), 'Missing actual successful stage: ' + name)
        start, finish = (dt.datetime.fromisoformat(stage[k]) for k in ('startedAtUtc', 'finishedAtUtc'))
        require(start.tzinfo is not None and finish >= start and (previous is None or start >= previous),
                'Stage timestamps differ')
        previous, stages[name] = finish, stage
    prepare = load_json(release / 'reports/prepare/identity.json')
    require(all(prepare.get(k) == result[k] for k in ('sdkVersion', 'architecture', 'sourceCommit', 'targetRid',
             'libc', 'projectCommit', 'runId', 'runAttempt')) and prepare.get('emulation') is False
             and prepare.get('nativeArchitecture') == identity['machine'] and prepare.get('diagnosticPtrace') is False,
             'Actual native prepared source identity differs')
    P.validate_container_engine(release, prepare, stages, P.identity(arch))
    profile_path = ROOT / 'profiles' / ('dotnet-' + sdk + '-linux-musl-' + arch + '.json')
    require(prepare.get('profile') == dict(path=profile_path.name, **fingerprint(profile_path)), 'Reviewed profile bytes differ')
    bootstrap = load_json(release / 'reports/prepare/bootstrap.json')
    require(all(bootstrap.get(k) == v for k, v in profile['bootstrap'].items()), 'Original native bootstrap input differs')
    if route['sourceOnly']:
        validate_net8_psb_records(release)
    patches = load_json(release / 'reports/prepare/source-patches.json')
    require(patches.get('sourceCommit') == route['source'] and patches.get('patches') == profile['build']['patches']
            and patches.get('packageAuditEnabled') is True, 'Reviewed source patch/audit disposition differs')
    cultures = load_json(release / 'reports/prepare/source-cultures.json')
    require(cultures.get('schemaVersion') == 1 and cultures.get('kind') == 'native-bootstrap-source-cultures'
            and cultures.get('status') == 'observed' and cultures.get('msbuildRuntimeType') == 'Core'
            and cultures.get('msbuildToolsPath') == '/vmr/.dotnet/sdk/' + route['bootstrap']
            and len(cultures.get('resources', [])) == 13
            and sorted(cultures['resources'], key=lambda r: r['culture'])
            == sorted([dict(resource='CommunityProbe.' + c + '.resx', culture=c, withCulture=True)
                       for c in P.SOURCE_CULTURES], key=lambda r: r['culture']), 'Exact native source-culture readiness differs')
    full_icu = next(p for p in profile['buildPackages'] if p['P'] == 'icu-data-full')
    installed = (release / 'reports/prepare/installed-packages.txt').read_text().splitlines()
    require(any(line == 'icu-data-full-' + full_icu['V'] or line.startswith('icu-data-full-' + full_icu['V'] + ' - ')
                for line in installed) and not any(line.startswith('icu-data-en-') for line in installed),
            'Actual native source builder must use pinned full ICU data')
    roots_environment = {'DOTNET_ROOT=/vmr/.dotnet', 'DOTNET_ROOT_' + ('ARM64' if arch == 'aarch64' else 'X64')
                         + '=/vmr/.dotnet', 'DOTNET_HOST_PATH=/vmr/.dotnet/dotnet'}
    for name, test in [('build', False), ('test', True)]:
        expected = R.build_command(sdk, arch, test, '/inputs/official-sdk.tar.gz' if test else None)
        commands = [c[c.index('musl-sdk-observed-command') + 1:] for c in stages[name]['commands']
                    if 'musl-sdk-observed-command' in c and './build.sh' in c]
        require(commands == [expected], 'Actual original native build/test invocation differs')
        require(all(roots_environment <= set(c) for c in stages[name]['commands'] if './build.sh' in c),
                'Every native source TaskHost must resolve the exact private bootstrap root')
    summary = R.parse_upstream_results(sdk, arch, release / 'reports/test/common.trx',
                                      release / 'reports/test/scenarios.xml' if sdk.startswith('9.') else None)
    require(load_json(release / 'reports/test/upstream-summary.json') == summary, 'Actual upstream result interpretation differs')
    producer = load_json(release / 'producer-sdk.json')
    require(all(producer.get(k) == result[k] for k in ('sdkVersion', 'architecture', 'sourceCommit', 'targetRid',
             'libc', 'projectCommit', 'runId', 'runAttempt', 'producerRevision')), 'SDK producer identity differs')
    name = 'cbodotnet-sdk-' + sdk + '-linux-musl-' + arch + '-build.' + result['runId'] + '.tar.gz'
    archive = release / name
    require(producer.get('sdk') == dict(name=name, **fingerprint(archive)), 'Actual newly built SDK bytes differ')
    if route['sourceOnly']:
        module('modern_reference_admission', 'musl_reference_audit.py').validate(release, archive)
    construction = load_json(release / 'reports/construction.json')
    require(construction.get('sdkSource') == route['source'] and construction.get('sourceOnly') is route['sourceOnly']
            and construction.get('crossBuild') is False and construction.get('runtimeVersion') == route['runtime']
            and len(construction.get('components', [])) == 2, 'Actual component construction identity differs')
    require({r['component'] for r in construction['components']} == {'Microsoft.NETCore.App', 'Microsoft.AspNetCore.App'},
            'Both distinct complete shared framework origins are mandatory')
    replay = load_json(release / 'reports/construction/downloads-status.json')
    require(replay.get('completedReplay') is True and replay.get('buildSucceeded') is True
            and replay.get('unfinishedTasks') == 0 and replay.get('completedDownloadTasks', 0) >= 2
            and replay.get('inputSha256') == fingerprint(release / 'reports/construction/consumer.binlog')['sha256'],
            'Actual complete successful consumer binlog replay differs')
    tasks = [json.loads(line) for line in (release / 'reports/construction/downloads-tasks.jsonl').read_text().splitlines() if line]
    for row in construction['components']:
        framework = row['component']
        require(framework in ('Microsoft.NETCore.App', 'Microsoft.AspNetCore.App'), 'Unexpected shared component')
        expected_source = route['runtimeSource' if framework == 'Microsoft.NETCore.App' else 'aspnetSource']
        require(row['sourceCommit'] == expected_source and (row['origin'] == 'rebuilt'
                or (sdk.startswith('9.') and framework == 'Microsoft.AspNetCore.App')),
                'Required locally rebuilt framework lacks provenance')
        actual = row.get('actualConsumption', {})
        require(actual.get('consumed', {}).get('sha256') == row['archive']['sha256']
                and any(task.get('context') == actual.get('context') and task.get('succeeded') is True
                        and actual.get('event') in task.get('events', []) for task in tasks),
                'Actual successful consumer event must bind the unchanged component archive')
        retained = release / row['archive']['path']
        require(all(row['archive'].get(k) == v for k, v in fingerprint(retained).items())
                and archive_files(retained, 'shared/' + framework + '/' + route['runtime'] + '/')
                == archive_files(archive, 'shared/' + framework + '/' + route['runtime'] + '/'),
                'Complete actual framework archive bytes differ')
    packer = module('modern_admission_sources', 'package-used-source.py')
    packer.verify(SimpleNamespace(release_dir=release, expected_project_commit=result['projectCommit'],
        expected_run_id=result['runId'], expected_run_attempt=result['runAttempt'], expected_target_rid=identity['rid']))
    source_manifest = load_json(release / 'sources/source-manifest.json')
    source_roots = [r for r in source_manifest['roots'] if r['name'] == 'vmr']
    require(len(source_roots) == 1 and source_roots[0]['commit'] == route['source'], 'Actual retained complete VMR source differs')
    validate_serviced_inputs(release, profile, source_manifest)
    if sdk.startswith('9.'):
        require(load_json(release / 'reports/additional-inputs.json') == validate_additional_inputs(release, profile, source_manifest),
                'Independent additional targeting package/source interpretation differs')
    scan = load_json(release / 'reports/scan/pinned-source-inventory.json')
    require(scan.get('sourceCommit') == route['source'] and scan.get('pristineBefore') is True
            and scan.get('pristineAfter') is True and scan.get('sourceTree') == source_roots[0]['tree'],
            'Independent pristine pinned-source scan differs')
    index = release / scan['files']['path']
    require(all(scan['files'].get(k) == v for k, v in fingerprint(index).items()), 'Complete source-header inventory bytes differ')
    entries = {}
    for line in index.read_text().splitlines():
        row = json.loads(line)
        require(row['path'] not in entries and row['gitMode'] in ('100644', '100755', '120000'),
                'Duplicate/invalid source inventory Git entry')
        entries[row['path']] = dict(mode=row['gitMode'], blob=row['gitBlobSha1'])
    require(len(entries) == scan['fileCount'] and packer.baseline_tree(entries) == scan['sourceTree'],
            'Complete independent source inventory must reconstruct the retained original Git tree')
    if sdk.startswith('9.'):
        require((release / 'reports/scan/NewBinaries.txt').read_bytes() == b''
                and any('/vmr/artifacts/bin/BinaryToolKit/Release/BinaryToolKit.dll' in c and '--network=none' in c
                        and '/clean' in c and 'validate' in c for c in stages['scan']['commands']),
                'Original NET9 clean-source binary validation must pass independently offline')
    smoke = load_json(release / 'reports/verify/sdk/verification.json')
    require(smoke.get('verificationStatus') == 'passed' and smoke.get('smokeStatus') == 'passed'
            and smoke.get('sdkVersion') == sdk and smoke.get('reportedRid') == identity['rid']
            and smoke.get('archive', {}).get('sha256') == producer['sdk']['sha256']
            and all(smoke.get('functionalChecks', {}).get(k) == 'passed' for k in
                    ('consoleDllExecution', 'consoleApphostExecution', 'rsaSha256SignAndVerify',
                     'cryptographicRandomBytes', 'frFrDecimalFormatting', 'aspNetCoreLoopbackHttp')),
            'Actual native offline SDK-free functional verification differs')
    elf = load_json(release / 'reports/verify/elf.json')
    loader = '/lib/ld-musl-' + identity['machine'] + '.so.1'
    require(elf.get('status') == 'passed' and elf.get('libc') == 'musl' and elf.get('architecture') == arch
            and elf.get('loader') == loader and elf.get('uid', 0) > 0 and elf.get('foreignTargetExceptions') == []
            and elf.get('closure', {}).get('status') == 'passed' and elf['closure'].get('nonHostElfCount') == 0,
            'Complete native stock-APK ELF closure differs')
    actual = P.sdk_elf_inventory(archive, 62 if arch == 'x64' else 183, loader)
    rows = {r['path']: r for r in elf.get('files', [])}
    require(len(rows) == len(actual) == elf.get('elfCount') and set(rows) == set(actual)
            and all(all(rows[path].get(k) == v for k, v in row.items()) for path, row in actual.items()),
            'Complete ELF inventory must bind unchanged final SDK bytes')
    require(any('--network=none' in c and prepare['verificationImageId'] in c for c in stages['verify']['commands']),
            'Native verification must use the pre-frozen SDK-free image offline')
    require(not any(roots_environment & set(c) for c in stages['verify']['commands']),
            'Final SDK-free verification may not inherit private bootstrap roots')
    print('Modern native musl producer source, original tests, used sources, ELF and final SDK bytes verified.')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('run')
    run.add_argument('--sdk-version', choices=sorted(R.VERSIONS), required=True)
    run.add_argument('--arch', choices=sorted(R.ARCHITECTURES), required=True)
    run.add_argument('--workspace', type=Path, required=True)
    run.add_argument('--output-dir', type=Path, required=True)
    run.add_argument('--host-reports', type=Path)
    run.add_argument('--diagnostic-ptrace', action='store_true')
    for name in ('build-id', 'run-id', 'run-attempt'):
        run.add_argument('--' + name, required=True)
    check = commands.add_parser('validate')
    check.add_argument('--release-dir', type=Path, required=True)
    feed = commands.add_parser('configure-feeds')
    feed.add_argument('--sdk-version', choices=sorted(R.VERSIONS), required=True)
    feed.add_argument('--source-dir', type=Path, required=True)
    feed.add_argument('--reports-dir', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'run':
        require(re.fullmatch(r'[0-9]{8}\.[1-9][0-9]*', args.build_id)
                and all(re.fullmatch('[1-9][0-9]*', item) for item in (args.run_id, args.run_attempt)), 'Invalid run/build identity')
        Producer(args).execute()
    elif args.command == 'validate':
        validate(args.release_dir)
    else:
        configure_feeds(args.source_dir, args.reports_dir, args.sdk_version)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, tarfile.TarError) as error:
        raise SystemExit('error: ' + str(error))
