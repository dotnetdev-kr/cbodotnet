"""Version-specific native source routes and modern musl admission boundaries."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import musl_version_routes as R
SPEC = importlib.util.spec_from_file_location('modern_musl_sdk_tests', ROOT / 'scripts/musl-modern-sdk.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class OriginalRestoreCaches(unittest.TestCase):
    def test_sdk8_original_cache_bytes_are_observed_when_old_search_roots_are_empty(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source, home = root / 'vmr', root / 'home'
            package = source / 'prereqs/packages/restored/original.package/1.0/original.package.1.0.nupkg'
            package.parent.mkdir(parents=True); package.write_bytes(b'actual original restore cache bytes')
            (package.parent / '.nupkg.metadata').write_text(json.dumps(dict(source='https://original.example/feed')))
            records = [row for cache in M.restored_cache_roots(source, home, '8.0.133', 'aarch64') for row in M.inventory_cache(cache)]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]['sha256'], hashlib.sha256(package.read_bytes()).hexdigest())
            self.assertEqual(records[0]['source'], 'https://original.example/feed')

    def test_sdk8_retains_original_archived_and_native_platform_cache_roots(self):
        for architecture, cpu in [('aarch64', 'arm64'), ('x64', 'x64')]:
            with tempfile.TemporaryDirectory() as temporary:
                source, home = Path(temporary) / 'vmr', Path(temporary) / 'home'
                inner = source / 'src/runtime/artifacts/source-build/self/package-cache'; inner.mkdir(parents=True)
                roots = M.restored_cache_roots(source, home, '8.0.133', architecture)
                self.assertIn(source / 'prereqs/packages/previouslyRestored', roots)
                self.assertIn(source / 'artifacts/obj' / cpu / 'Release/nuget-packages', roots)
                self.assertIn(inner, roots)
                self.assertEqual(len(roots), len(set(roots)))
                self.assertNotIn(source / 'artifacts/obj' / cpu / 'Release/blob-feed/packages', roots)

    def test_sdk9_cache_route_keeps_its_existing_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, home = Path(temporary) / 'vmr', Path(temporary) / 'home'
            roots = M.restored_cache_roots(source, home, '9.0.123', 'x64')
            self.assertEqual(roots, [home / '.nuget/packages', source / '.packages'])


class NativeRoutes(unittest.TestCase):
    def test_all_four_routes_use_exact_native_bootstrap_and_stock_dependencies(self):
        for sdk in R.VERSIONS:
            for arch in R.ARCHITECTURES:
                with self.subTest(sdk=sdk, arch=arch):
                    value = R.profile(sdk, arch)
                    original = json.loads((ROOT / 'profiles' / ('dotnet-10.0.403-linux-musl-' + arch + '.json')).read_text())
                    self.assertEqual(value['container'], original['container'])
                    self.assertEqual(value['apkIndexes'], original['apkIndexes'])
                    self.assertEqual([p for p in value['buildPackages'] if p['P'] != 'krb5-dev'], original['buildPackages'])
                    with tarfile.open(ROOT / value['apkIndexes']['main']['snapshotPath']) as stream:
                        index = stream.extractfile('APKINDEX').read().decode()
                    blocks = [dict(line.split(':', 1) for line in block.splitlines() if ':' in line)
                              for block in index.split('\n\n')]
                    kerberos = next(p for p in blocks if p.get('P') == 'krb5-dev')
                    expected = {key: kerberos[key] for key in ('P', 'V', 'A', 'D', 'L', 'o', 'c')}
                    self.assertEqual([dict(expected, repository='main')],
                                     [p for p in value['buildPackages'] if p['P'] == 'krb5-dev'])
                    self.assertEqual(value['runtimePackages'], original['runtimePackages'])
                    self.assertFalse(value['build']['crossBuild'])
                    self.assertEqual('pending', value['qualification']['status'])
                    self.assertEqual(1, value['qualification']['producerRevision'])
                    self.assertFalse(value['qualification']['securityMaintenanceBeyondUpstreamEol'])

    def test_servicing_sources_are_exact_coordinated_package_and_license_pins(self):
        for arch in R.ARCHITECTURES:
            value = R.profile('9.0.123', arch)
            sources = value['supplementalSourceGit']
            self.assertEqual(['serviced-nuget', 'serviced-messagepack', 'serviced-opentelemetry',
                              'serviced-telemetry-extensions', 'serviced-diagnosticsource'], [s['name'] for s in sources])
            self.assertEqual({'6.12.5'}, {p['version'] for p in sources[0]['packages']})
            self.assertEqual(7, len(sources[0]['packages']))
            self.assertEqual({'2.5.303'}, {p['version'] for p in sources[1]['packages']})
            self.assertEqual({'messagepack', 'messagepack.annotations'}, {p['id'] for p in sources[1]['packages']})
            self.assertEqual(4, len(sources[2]['packages']))
            self.assertEqual({'1.15.3'}, {p['version'] for p in sources[2]['packages']})
            self.assertEqual(12, len(sources[3]['packages']))
            self.assertEqual({'9.0.0'}, {p['version'] for p in sources[3]['packages']})
            self.assertEqual(['system.diagnostics.diagnosticsource'], [p['id'] for p in sources[4]['packages']])
            self.assertEqual('b0f34d51fccc69fd334253924abd8d6853fad7aa', sources[4]['publisher']['commit'])
            self.assertEqual('60629d14374c56f1cb51819049ad1fa529307f8d', sources[4]['commit'])
            changed = copy.deepcopy(value)
            changed['supplementalSourceGit'][1]['commit'] = '0' * 40
            with mock.patch.object(R.json, 'loads', return_value=changed), self.assertRaisesRegex(ValueError, 'registry'):
                R.profile('9.0.123', arch)

    def test_normal_diagnostics_preserve_msbuild_without_breaking_crossgen2(self):
        with tempfile.TemporaryDirectory() as temporary:
            for diagnostic in (False, True):
                producer = M.Producer.__new__(M.Producer)
                producer.reports = Path(temporary) / str(diagnostic)
                producer.commands = []
                producer.diagnostic_ptrace = diagnostic
                options = producer.diagnostic_options()
                self.assertIn('MSBUILDDEBUGPATH=/diag', options)
                self.assertIn('MSBUILDDEBUGCOMM=1', options)
                dumps = [value for value in options if value.startswith(('DOTNET_Dbg', 'DOTNET_CreateDump', 'DOTNET_EnableCrash'))]
                self.assertEqual(5 if diagnostic else 0, len(dumps))

    def test_net8_shipping_json_servicing_rejects_unreviewed_package_source(self):
        for arch in R.ARCHITECTURES:
            value = R.profile('8.0.133', arch)
            source = value['supplementalSourceGit'][-1]
            self.assertEqual('serviced-bootstrap-runtime', source['name'])
            self.assertEqual('1219a42122cf5190c7f512850557e38c422430dc', source['commit'])
            self.assertEqual([('system.formats.asn1', '8.0.2', 'MIT'), ('system.text.json', '8.0.6', 'MIT')],
                             [(p['id'], p['version'], p['license']) for p in source['packages']])
            M.validate_net8_package_origin(source, '8.0.133')
            with self.assertRaisesRegex(ValueError, 'origin'):
                M.validate_net8_package_origin(source, '9.0.123')
            changed = copy.deepcopy(value)
            changed['supplementalSourceGit'][-1]['packages'][0]['version'] = '7.0.1'
            with mock.patch.object(R.json, 'loads', return_value=changed), self.assertRaisesRegex(ValueError, 'registry'):
                R.profile('8.0.133', arch)

    def test_version_specific_commands_keep_real_native_musl_graph(self):
        for sdk in R.VERSIONS:
            for arch, identity in R.ARCHITECTURES.items():
                command = R.build_command(sdk, arch)
                self.assertIn('CrossBuild=false', command)
                self.assertIn('/p:CrossBuild=false', command)
                self.assertIn('/p:PortableBuild=true', command)
                self.assertNotIn('--clean-while-building', command)
                self.assertFalse(any('xenial' in item or item.startswith('ROOTFS_DIR=') for item in command))
                self.assertFalse(any('NuGetAudit' in item for item in command))
                if sdk.startswith('9.'):
                    self.assertIn(identity['rid'], command)
                    self.assertIn('/p:TargetOS=linux-musl', command)
                    self.assertNotIn('--arch', command)
                else:
                    self.assertIn('/p:TargetRid=' + identity['rid'], command)
                    self.assertIn('/p:Platform=' + identity['upstream'], command)
                    self.assertIn('--online', command)
                    self.assertNotIn('--source-only', command)
                    self.assertEqual(['--with-sdk', '/vmr/.dotnet'], command[command.index('--with-sdk'):command.index('--with-sdk') + 2])

    def test_upstream_baseline_is_explicit_and_does_not_become_the_built_sdk(self):
        for sdk in R.VERSIONS:
            for arch in R.ARCHITECTURES:
                with self.assertRaisesRegex(ValueError, 'comparison archive'):
                    R.build_command(sdk, arch, True, '/inputs/glibc-sdk.tar.gz')
                command = R.build_command(sdk, arch, True, '/inputs/official-sdk.tar.gz')
                self.assertIn('--test' if sdk.startswith('9.') else '--run-smoke-test', command)
                record = M.upstream_sdk_record(sdk, arch)
                self.assertIn(R.ARCHITECTURES[arch]['rid'], record['url'])
                self.assertEqual(128, len(record['sha512']))


class SourceAndArchiveSafety(unittest.TestCase):
    def psb_fixture(self, root, mutation=None):
        source = copy.deepcopy(R.profile('8.0.133', 'x64')['supplementalSourceGit'][-1])
        rows = []
        for package in source['packages']:
            name = package['id'] + '.' + package['version'] + '.nupkg'
            content = io.BytesIO()
            with zipfile.ZipFile(content, 'w') as archive:
                archive.writestr('Package.nuspec', '<package><metadata><id>' + package['id'] + '</id><version>'
                    + package['version'] + '</version><license type="expression">MIT</license><repository url="'
                    + source['repository'] + '" commit="' + source['commit'] + '" /></metadata></package>')
            raw = content.getvalue()
            package.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())
            rows.append((M.NET8_PSB_PACKAGE_MEMBERS[name], raw))
        path = root / 'original.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            for index, (name, raw) in enumerate(rows):
                if index == 0 and mutation == 'missing':
                    continue
                if index == 0 and mutation in ('traversal', 'nested', 'backslash', 'case'):
                    name = {'traversal': '../' + name, 'nested': 'nested/' + name,
                            'backslash': '..\\' + name, 'case': name.lower()}[mutation]
                member = tarfile.TarInfo(name); member.size = len(raw)
                if index == 0 and mutation == 'link':
                    member.type = tarfile.LNKTYPE; member.linkname = rows[1][0]; member.size = 0
                archive.addfile(member, io.BytesIO(raw))
                if index == 0 and mutation == 'duplicate':
                    archive.addfile(member, io.BytesIO(raw))
        directory = root / 'retained'; directory.mkdir()
        return source, path, directory

    def test_psb_extracts_only_exact_closed_members_without_nuget_download(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, path, directory = self.psb_fixture(Path(temporary))
            with mock.patch.object(M, 'net8_psb_record') as pinned, mock.patch.object(M, 'download') as download:
                M.extract_net8_psb_packages(path, directory, source, '8.0.133')
            pinned.assert_called_once_with(path)
            download.assert_not_called()
            self.assertEqual(set(M.NET8_PSB_PACKAGE_MEMBERS), {p.name for p in directory.iterdir()})
            for package in source['packages']:
                row = M.serviced_package(directory / (package['id'] + '.' + package['version'] + '.nupkg'), source, package)
                self.assertEqual(source['commit'], row['repositoryCommit'])

    def test_psb_rejects_duplicate_redirected_missing_and_wrong_package_bytes(self):
        for mutation in ('duplicate', 'traversal', 'nested', 'backslash', 'case', 'link', 'missing', 'sha256'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                source, path, directory = self.psb_fixture(Path(temporary), mutation)
                if mutation == 'sha256':
                    source['packages'][0]['sha256'] = '0' * 64
                with mock.patch.object(M, 'net8_psb_record'), self.assertRaises(ValueError):
                    M.extract_net8_psb_packages(path, directory, source, '8.0.133')

    def test_psb_rejects_wrong_archive_origin_or_sdk_before_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, path, directory = self.psb_fixture(Path(temporary))
            with mock.patch.object(M, 'net8_psb_record', side_effect=ValueError('input bytes differ')) as pinned:
                with self.assertRaisesRegex(ValueError, 'input bytes'):
                    M.extract_net8_psb_packages(path, directory, source, '8.0.133')
            pinned.assert_called_once_with(path)
            self.assertFalse(list(directory.iterdir()))
            with self.assertRaisesRegex(ValueError, 'origin'):
                M.extract_net8_psb_packages(path, directory, source, '9.0.123')
            source['packageOrigin']['archive']['sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'origin'):
                M.extract_net8_psb_packages(path, directory, source, '8.0.133')

    def test_corresponding_solution_serialization_accepts_only_exact_git_blob(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            subprocess.run(['git', 'init', str(checkout)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (checkout / '.gitattributes').write_text('*.sln text eol=crlf\n', newline='\n')
            (checkout / 'Product.sln').write_bytes(b'original solution\n')
            subprocess.run(['git', '-C', str(checkout), 'add', '.'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['git', '-C', str(checkout), '-c', 'user.name=Fixture', '-c',
                'user.email=fixture@example.invalid', 'commit', '-m', 'Pinned corresponding source'],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            commit = M.git(checkout, 'rev-parse', 'HEAD')
            (checkout / 'Product.sln').unlink()
            subprocess.run(['git', '-C', str(checkout), 'checkout', '--', 'Product.sln'], check=True)
            (checkout / 'Product.sln').write_bytes(subprocess.check_output(['git', '-C', str(checkout), 'show', commit + ':Product.sln']))
            M.pristine_corresponding_checkout(checkout, commit)
            (checkout / 'Product.sln').write_bytes(b'replaced solution\n')
            with self.assertRaisesRegex(ValueError, 'exact Git blob'):
                M.pristine_corresponding_checkout(checkout, commit)
            (checkout / 'Product.sln').write_bytes(b'original solution\n')
            (checkout / 'injected.cs').write_text('unreviewed')
            with self.assertRaisesRegex(ValueError, 'source changed'):
                M.pristine_corresponding_checkout(checkout, commit)

    def test_publisher_vmr_component_mapping_requires_exact_manifest_and_library_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'source-manifest.json'
            source = dict(repository='https://github.com/dotnet/runtime', commit='a' * 40)
            document = dict(repositories=[dict(path='runtime', remoteUri=source['repository'], commitSha=source['commit'])])
            path.write_text(json.dumps(document))
            baseline = {'Product.cs': dict(mode='100644', blob='1' * 40)}
            tree = M.module('test_mapped_source_tree', 'package-used-source.py').baseline_tree(baseline)
            source['publisher'] = dict(repository='https://github.com/dotnet/dotnet', commit='b' * 40,
                sourceManifest=dict(path='src/source-manifest.json', sha256=M.fingerprint(path)['sha256']),
                componentPath='runtime', identicalLibraryTree=dict(sourcePath='src/libraries',
                    publisherPath='src/runtime/src/libraries', tree=tree))
            M.validate_publisher_source_map(source, path, baseline)
            for mutation in (dict(Product=dict(mode='100644', blob='2' * 40)), {}):
                with self.assertRaisesRegex(ValueError, 'corresponding source library'):
                    M.validate_publisher_source_map(source, path, mutation)
            document['repositories'][0]['commitSha'] = 'c' * 40
            path.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, 'manifest bytes'):
                M.validate_publisher_source_map(source, path, baseline)
            source['publisher']['sourceManifest']['sha256'] = M.fingerprint(path)['sha256']
            with self.assertRaisesRegex(ValueError, 'component source identity'):
                M.validate_publisher_source_map(source, path, baseline)

    def test_net8_original_and_actual_prep_bytes_are_both_pinned(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary)
            prepare = release / 'reports/prepare'
            prepare.mkdir(parents=True)
            for name in ('original-psb.json', 'actual-prep-psb.json'):
                (prepare / name).write_text(json.dumps(M.NET8_PSB))
            M.validate_net8_psb_records(release)
            fp = {key: M.NET8_PSB[key] for key in ('bytes', 'sha256', 'sha512')}
            with mock.patch.object(M, 'fingerprint', return_value=fp):
                self.assertEqual(M.NET8_PSB, M.net8_psb_record(release / 'input.tar.gz'))
            for changed in (dict(M.NET8_PSB, bytes=M.NET8_PSB['bytes'] - 1),
                            dict(M.NET8_PSB, sha512='0' * 128), dict(M.NET8_PSB, sha256='0' * 64),
                            dict(M.NET8_PSB, unreviewed=True)):
                for name in ('original-psb.json', 'actual-prep-psb.json'):
                    (prepare / name).write_text(json.dumps(changed))
                    with self.assertRaisesRegex(ValueError, 'PSB download/prep'):
                        M.validate_net8_psb_records(release)
                    (prepare / name).write_text(json.dumps(M.NET8_PSB))
            with mock.patch.object(M, 'fingerprint', return_value=dict(fp, sha512='0' * 128)):
                with self.assertRaisesRegex(ValueError, 'PSB input bytes'):
                    M.net8_psb_record(release / 'input.tar.gz')

    def test_net8_psb_selector_accepts_original_msbuild_namespace_and_exact_url_only(self):
        expected = ('https://builds.dotnet.microsoft.com/source-built-artifacts/assets/'
                    'Private.SourceBuilt.Artifacts.8.0.131-servicing.26422.1.centos.9-x64.tar.gz')
        # The pinned NET8 eng/Versions.props uses this MSBuild namespace;
        # ElementTree's raw tag is consequently not the unqualified name.
        document = ('<Project ToolsVersion="14.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
                    '<PropertyGroup><PrivateSourceBuiltArtifactsUrl>' + expected + '</PrivateSourceBuiltArtifactsUrl>'
                    '</PropertyGroup></Project>')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'Versions.props'
            path.write_text(document)
            self.assertEqual(expected, M.net8_source_built_artifacts_url(path))
            for changed in (document.replace('https://builds.dotnet.microsoft.com', 'https://example.com'),
                            document.replace('8.0.131-servicing.26422.1', '8.0.132-servicing.26422.1'),
                            document.replace('</PropertyGroup>', '<PrivateSourceBuiltArtifactsUrl>' + expected
                                             + '</PrivateSourceBuiltArtifactsUrl></PropertyGroup>'),
                            document.replace('PrivateSourceBuiltArtifactsUrl', 'PrivateSourceBuiltSdkUrl')):
                path.write_text(changed)
                with self.assertRaisesRegex(ValueError, 'Pinned NET8 PSB URL differs'):
                    M.net8_source_built_artifacts_url(path)

    def test_serviced_package_rejects_wrong_corresponding_source_license_or_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'package.nupkg'
            source = dict(repository='https://github.com/MessagePack-CSharp/MessagePack-CSharp', commit='a' * 40)
            package = dict(id='messagepack', version='2.5.303', license='MIT')
            raw = ('<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata>'
                   '<id>MessagePack</id><version>2.5.303</version><license type="expression">MIT</license>'
                   '<repository url="' + source['repository'] + '.git" commit="' + source['commit'] + '" />'
                   '</metadata></package>').encode()
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('MessagePack.nuspec', raw)
            package.update({key: value for key, value in M.fingerprint(path).items() if key in ('bytes', 'sha512')})
            self.assertEqual(source['commit'], M.serviced_package(path, source, package)['repositoryCommit'])
            for changed_source, changed_package in [(dict(source, commit='b' * 40), package),
                                                     (source, dict(package, license='Apache-2.0')),
                                                     (source, dict(package, sha512='0' * 128))]:
                with self.assertRaisesRegex(ValueError, 'Serviced package'):
                    M.serviced_package(path, changed_source, changed_package)

    def test_servicing_admission_requires_actual_restore_and_archived_license(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary)
            packages = release / 'reports/serviced-inputs/packages'
            packages.mkdir(parents=True)
            source = dict(name='serviced-sample', repository='https://github.com/example/source', commit='a' * 40,
                          role='source-for-serviced-imported-package', requiredNotices=['LICENSE'])
            path = packages / 'sample.1.0.1.nupkg'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('Sample.nuspec', '<package><metadata><id>Sample</id><version>1.0.1</version>'
                    '<license type="expression">MIT</license><repository url="https://github.com/example/source" commit="'
                    + source['commit'] + '" /></metadata></package>')
            fp = M.fingerprint(path)
            package = dict(id='sample', version='1.0.1', license='MIT', bytes=fp['bytes'], sha512=fp['sha512'])
            source['packages'] = [package]
            profile = dict(sdkVersion='9.0.123', supplementalSourceGit=[source])
            restored = dict(path='sample/1.0.1/sample.1.0.1.nupkg', source='https://api.nuget.org/v3/index.json', **fp)
            M.write(release / 'reports/restored-inputs.json', dict(packages=[restored]))
            notice = dict(path='LICENSE', bytes=3, sha256='b' * 64, sha512='c' * 128)
            row = dict(M.serviced_package(path, source, package), path=path.relative_to(release).as_posix(), actualRestoreRecords=[restored])
            report = dict(schemaVersion=1, sdkVersion='9.0.123', gitSources=[dict(source, tree='d' * 40, notices=[notice], packages=[row])])
            M.write(release / 'reports/serviced-inputs.json', report)
            (release / 'sources').mkdir()
            (release / 'sources/source-index.jsonl').write_text(json.dumps(dict(notice, path='serviced-sample/LICENSE')) + '\n')
            manifest = dict(index=dict(path='source-index.jsonl'), roots=[dict(name=source['name'], commit=source['commit'], tree='d' * 40, role=source['role'])])
            M.validate_serviced_inputs(release, profile, manifest)
            row['actualRestoreRecords'] = []
            (release / 'reports/serviced-inputs.json').write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, 'actual restored'):
                M.validate_serviced_inputs(release, profile, manifest)
            row['actualRestoreRecords'] = [restored]
            (release / 'reports/serviced-inputs.json').write_text(json.dumps(report))
            (release / 'sources/source-index.jsonl').write_text(json.dumps(dict(notice, path='serviced-sample/OTHER')) + '\n')
            with self.assertRaisesRegex(ValueError, 'licenses must be archived'):
                M.validate_serviced_inputs(release, profile, manifest)

    def test_feed_adjustment_accepts_only_canonical_git_crlf_and_records_exact_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'source'
            source.mkdir()
            original = b'<configuration>\n<packageSources><clear /></packageSources>\n</configuration>\n'
            (source / 'NuGet.config').write_bytes(original.replace(b'\n', b'\r\n'))
            def process(command):
                return original if 'show' in command else b'diff\n'
            with mock.patch.object(M, 'git', return_value=R.VERSIONS['9.0.123']['source']), mock.patch.object(M.subprocess, 'check_output', side_effect=process):
                M.configure_feeds(source, Path(temporary) / 'reports', '9.0.123')
                record = json.loads((Path(temporary) / 'reports/feed-adjustments.json').read_text())
                self.assertFalse(record['packageVersionsChanged'])
                self.assertIn(b'maxHttpRequestsPerSource', (source / 'NuGet.config').read_bytes())
                self.assertEqual('/inputs/nuget', ET.parse(source / 'NuGet.config').getroot().find("packageSources/add[@key='pinned-microsoft']").get('value'))
                (source / 'NuGet.config').write_bytes(original + b'<!-- unreviewed -->')
                with self.assertRaisesRegex(ValueError, 'preexisting'):
                    M.configure_feeds(source, Path(temporary) / 'other', '9.0.123')

    def archive(self, path, entries):
        with tarfile.open(path, 'w:gz') as stream:
            for name, value in entries:
                entry = tarfile.TarInfo(name)
                entry.size = len(value)
                stream.addfile(entry, io.BytesIO(value))

    def test_complete_framework_byte_comparison_detects_changed_or_missing_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prefix = 'shared/Microsoft.NETCore.App/9.0.22/'
            self.archive(root / 'a.tar.gz', [(prefix + 'core.dll', b'original'), (prefix + 'other.dll', b'other')])
            self.archive(root / 'b.tar.gz', [(prefix + 'core.dll', b'changed'), (prefix + 'other.dll', b'other')])
            self.assertNotEqual(M.archive_files(root / 'a.tar.gz', prefix), M.archive_files(root / 'b.tar.gz', prefix))
            self.archive(root / 'unsafe.tar.gz', [(prefix + '../outside', b'escape')])
            with self.assertRaisesRegex(ValueError, 'Unsafe'):
                M.archive_files(root / 'unsafe.tar.gz', prefix)

    def test_diagnostic_or_incomplete_modern_evidence_cannot_qualify(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for marker in ({}, {'diagnosticPtrace': True}, {'diagnosticPtrace': 0}):
                (root / 'producer-validation.json').write_text(json.dumps(marker))
                with self.subTest(marker=marker), self.assertRaisesRegex(ValueError, 'Diagnostic'):
                    M.validate(root)


class AdditionalTargetingSupport(unittest.TestCase):
    def fixture(self, release):
        expected = copy.deepcopy(R.NET9_ADDITIONAL_PACKAGES[0])
        path = release / 'pinned-inputs/nuget' / expected['fileName']
        path.parent.mkdir(parents=True)
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr('input.nuspec', '<package><metadata><id>' + expected['id'] + '</id><version>' + expected['version'] + '</version></metadata></package>')
        expected.update(M.fingerprint(path))
        bodies = {'LICENSE.TXT': b'original license', 'THIRD-PARTY-NOTICES.TXT': b'original notices',
                  'netstandard.library.netframework.nuspec': b'original package project',
                  'build/net461/lib/System.Runtime.il': b'original complete IL source'}
        baseline = {name: dict(mode='100644', blob=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())
                    for name, raw in bodies.items()}
        packer = M.module('targeting_fixture_git_tree', 'package-used-source.py')
        expected['correspondingSource']['tree'] = packer.baseline_tree(baseline)
        prefix = 'vmr/' + expected['correspondingSource']['path'] + '/'
        rows = [dict(path=prefix + name, baseline=baseline[name]) for name in bodies]
        rows.append(dict(path='pinned-targeting-inputs/nuget/' + expected['fileName'], **M.fingerprint(path)))
        (release / 'sources').mkdir()
        (release / 'sources/index.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
        archive = release / 'sources/retained.tar.gz'
        with tarfile.open(archive, 'w:gz') as stream:
            for name, raw in bodies.items():
                item = tarfile.TarInfo(prefix + name); item.size = len(raw)
                stream.addfile(item, io.BytesIO(raw))
        report = dict(feed='/inputs/nuget', packages=[dict(expected, sizeBytes=expected['bytes'], sha256Verified=True,
            archiveIntegrityVerified=True, hashOrigin='Content fingerprint recorded from the public upstream URL, not a publisher signature')])
        M.write(release / 'reports/prepare/pinned-inputs.json', report)
        M.write(release / 'reports/restored-inputs.json', dict(packages=[dict(path=expected['fileName'], **M.fingerprint(path))]))
        manifest = dict(roots=[dict(name='vmr', kind='git', commit=R.VERSIONS['9.0.123']['source'])],
                        index=dict(path='index.jsonl'), archive=dict(path=archive.name))
        return expected, dict(sdkVersion='9.0.123', additionalPackages=[expected]), manifest, rows

    def test_exact_imported_package_complete_source_and_actual_restore_are_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary)
            expected, profile, manifest, rows = self.fixture(release)
            with mock.patch.object(R, 'NET9_ADDITIONAL_PACKAGES', [expected]):
                self.assertIsNone(M.validate_additional_inputs(release, profile))
                proof = M.validate_additional_inputs(release, profile, manifest)
                self.assertEqual(4, proof['packages'][0]['sourceFiles'])
                self.assertFalse(proof['packages'][0]['localBuildClaimed'])
                self.assertFalse(proof['packages'][0]['byteIdenticalCompilationClaimed'])
                index = release / 'sources/index.jsonl'
                original = index.read_bytes()
                for selected in (rows[:-1], rows[1:]):
                    index.write_text(''.join(json.dumps(row) + '\n' for row in selected))
                    with self.assertRaisesRegex(ValueError, 'complete original targeting package|Complete original targeting package'):
                        M.validate_additional_inputs(release, profile, manifest)
                index.write_bytes(original)
                (release / 'reports/restored-inputs.json').write_text('{"packages": []}')
                with self.assertRaisesRegex(ValueError, 'actually restored unchanged'):
                    M.validate_additional_inputs(release, profile, manifest)
                path = release / 'pinned-inputs/nuget' / expected['fileName']
                path.write_bytes(path.read_bytes() + b'changed input wrapper')
                with self.assertRaisesRegex(ValueError, 'package bytes differ'):
                    M.validate_additional_inputs(release, profile)

    def test_sdk8_has_no_added_pinned_feed_or_input_requirement(self):
        self.assertIsNone(M.validate_additional_inputs(Path('/not-read'), dict(sdkVersion='8.0.133', additionalPackages=[])))
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'source'; source.mkdir()
            original = b'<configuration><packageSources><clear /></packageSources></configuration>'
            (source / 'NuGet.config').write_bytes(original)
            with mock.patch.object(M, 'git', return_value=R.VERSIONS['8.0.133']['source']), mock.patch.object(M.subprocess, 'check_output', side_effect=lambda argv: original if 'show' in argv else b'diff'):
                M.configure_feeds(source, Path(temporary) / 'reports', '8.0.133')
            self.assertIsNone(ET.parse(source / 'NuGet.config').getroot().find("packageSources/add[@key='pinned-microsoft']"))


class OriginalTestGraph(unittest.TestCase):
    def test_consumer_log_requires_original_inner_or_source_only_build_layout(self):
        paths = {'9.0.123': 'src/sdk/artifacts/log/Release/source-inner-build.binlog',
                 '8.0.133': 'src/installer/artifacts/source-build/self/src/artifacts/sourcebuild.binlog'}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wrong = root / 'src/sdk/artifacts/buildLogs/log/Release/source-inner-build.binlog'
            wrong.parent.mkdir(parents=True)
            wrong.write_bytes(b'wrong-build-route')
            outer = root / 'src/sdk/artifacts/log/Release/Build.binlog'
            outer.parent.mkdir(parents=True)
            outer.write_bytes(b'successful-outer-orchestrator-with-no-download-tasks')
            for sdk, relative in paths.items():
                with self.assertRaisesRegex(ValueError, 'Actual original SDK consumer'):
                    M.consumer_binlog(root, sdk)
                expected = root / relative
                expected.parent.mkdir(parents=True, exist_ok=True)
                expected.touch()
                with self.assertRaisesRegex(ValueError, 'Actual original SDK consumer'):
                    M.consumer_binlog(root, sdk)
                expected.write_bytes(b'actual-original-build-log')
                self.assertEqual(expected, M.consumer_binlog(root, sdk))
            with self.assertRaisesRegex(ValueError, 'Unreviewed'):
                M.consumer_binlog(root, '7.0.120')

    def test_sdk9_outer_diagnostic_is_preserved_before_missing_inner_log_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            producer = M.Producer.__new__(M.Producer)
            producer.sdk = '9.0.123'
            producer.source = root / 'source'
            producer.reports = root / 'reports'
            outer = producer.source / 'src/sdk/artifacts/log/Release/Build.binlog'
            outer.parent.mkdir(parents=True)
            original = b'actual-outer-exec-invokes-separate-inner-build'
            outer.write_bytes(original)
            with self.assertRaisesRegex(ValueError, 'Actual original SDK consumer'):
                producer.replay_construction()
            report = producer.reports / 'construction'
            self.assertEqual(original, (report / 'orchestrator.binlog').read_bytes())
            receipt = json.loads((report / 'orchestrator.json').read_text())
            self.assertIs(receipt['diagnosticOnly'], True)
            self.assertEqual(hashlib.sha256(original).hexdigest(), receipt['sha256'])
            self.assertFalse((report / 'consumer.binlog').exists())

    def test_net8_missing_tests_or_new_skips_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            trx = Path(temporary) / 'test.trx'
            ns = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'
            root = ET.Element('{' + ns + '}TestRun')
            rows = ET.SubElement(root, '{' + ns + '}Results')
            for index in range(44):
                ET.SubElement(rows, '{' + ns + '}UnitTestResult', executionId=str(index), testName='Test.' + str(index), outcome='Passed')
            for index, name in enumerate(('LicenseScanTests.ScanForLicenses', 'PoisonTests.VerifyUsage'), 44):
                ET.SubElement(rows, '{' + ns + '}UnitTestResult', executionId=str(index), testName=name, outcome='NotExecuted')
            summary = ET.SubElement(root, '{' + ns + '}ResultSummary')
            ET.SubElement(summary, '{' + ns + '}Counters', total='46', executed='44', passed='44', failed='0')
            ET.ElementTree(root).write(trx)
            self.assertEqual(44, R.parse_upstream_results('8.0.133', 'x64', trx)['passed'])
            rows.remove(rows[0])
            ET.ElementTree(root).write(trx)
            with self.assertRaises(ValueError):
                R.parse_upstream_results('8.0.133', 'x64', trx)

    def test_failed_net8_image_preparation_retains_unchanged_sdk_and_remains_failed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk = root / 'actual-built-sdk.tar.gz'
            sdk.write_bytes(b'unchanged actual producer output')
            fingerprint = M.fingerprint(sdk)
            producer = object.__new__(M.Producer)
            producer.sdk = '8.0.133'
            producer.args = SimpleNamespace(run_id='123', arch='aarch64')
            producer.source = root / 'source'
            producer.reports = root / 'reports'
            producer.reports.mkdir()
            producer.output = root
            producer.image_context = root / 'image-context'
            producer.image = 'sha256:' + 'a' * 64
            producer.engine = ['docker']
            producer.id = dict(rid='linux-musl-arm64', image='arm64')
            producer.route = dict(sourceOnly=True, source='b' * 40)
            producer.run = mock.Mock(side_effect=RuntimeError('derived image preparation failed'))
            producer.container = mock.Mock()
            collector = SimpleNamespace(select_sdk=lambda *args, **kwargs: (sdk, [fingerprint], None))
            parent = SimpleNamespace(bind_parent=lambda *args: 'localhost/cbodotnet-musl-parent:123-aarch64-builder')
            def module(name, filename):
                return {'musl_local_image.py': parent, 'collect-artifacts.py': collector}[filename]
            with mock.patch.object(M, 'module', side_effect=module):
                with self.assertRaisesRegex(RuntimeError, 'derived image preparation failed'):
                    producer.test()
            retained = producer.reports / 'test/failure/sdk.tar.gz'
            self.assertEqual(fingerprint, M.fingerprint(retained))
            record = json.loads(retained.with_name('sdk.json').read_bytes())
            self.assertFalse(record['qualificationAllowed'])
            self.assertFalse(record['sourceAdmissionAllowed'])
            self.assertFalse(record['releasePublished'])
            self.assertFalse((root / 'producer-validation.json').exists())
            producer.container.assert_not_called()


if __name__ == '__main__':
    unittest.main()
