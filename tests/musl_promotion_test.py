"""Authenticated native origins, complete rebuilds and immutable musl promotion."""
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import musl_archive as ARCHIVE
import musl_contract as CONTRACT
import musl_promotion as PROMOTION
from downstream_release import descriptor, encoded
from musl_archive_test import prepared_inputs

SIGNER = 'D7D154B4B33C19A82B95B13688135410ACD9C0EA'
ORIGIN = dict(repository=CONTRACT.REPOSITORY, workflow=PROMOTION.WORKFLOW, commit='a'*40, runId='123', runAttempt='2')
ENVIRONMENT = dict(GITHUB_ACTIONS='true', GITHUB_REPOSITORY=CONTRACT.REPOSITORY, GITHUB_REF='refs/heads/main',
    GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_WORKFLOW_REF=CONTRACT.REPOSITORY+'/'+PROMOTION.WORKFLOW+'@refs/heads/main',
    GITHUB_SHA='a'*40, GITHUB_WORKFLOW_SHA='a'*40, GITHUB_JOB='freeze_archive', GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='2')


def source_inputs(directory):
    catalog = prepared_inputs(directory)
    manifest = json.loads((directory / 'release-manifest.json').read_bytes())
    first = manifest['architectures']['x64']['sdk']
    other = manifest['architectures']['aarch64']['sdk']
    shutil.copyfile(directory / first['name'], directory / other['name'])
    other.update(size=first['size'], sha256=first['sha256'])
    names = [entry[kind]['name'] for entry in manifest['architectures'].values() for kind in CONTRACT.KINDS]
    sums = ''.join(hashlib.sha256((directory / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in names).encode()
    (directory / 'SHA256SUMS').write_bytes(sums)
    manifest['checksums'] = descriptor(directory / 'SHA256SUMS')
    raw = encoded(manifest)
    (directory / 'release-manifest.json').write_bytes(raw)
    release = json.loads((directory / 'release.json').read_bytes())
    for asset in release['assets']:
        actual = descriptor(directory / asset['name'])
        asset.update(size=actual['size'], digest='sha256:' + actual['sha256'])
    (directory / 'release.json').write_bytes(encoded(release))
    catalog['builds'][0]['sourceManifestSha256'] = hashlib.sha256(raw).hexdigest()
    return catalog


def native_report(build):
    plan = build['plan']
    arch = ARCHIVE.plan_architecture(plan)
    elf = dict(status='passed', native=True, architecture=arch, targetRid=plan['targetRid'], libc='musl')
    elf_raw = encoded(elf)
    offline = dict(schemaVersion=1, scope='musl-consumer-archive-offline', status='passed', native=True,
        architecture=arch, libc='musl', targetRid=plan['targetRid'], identity=ARCHIVE.identity(plan), archive=build['artifact'],
        networkForBuild='none', uid=10001, gid=10001,
        checks=dict.fromkeys(ARCHIVE.REPORT_CHECKS-{'system-trust-https'}, 'passed'),
        functionalChecks=dict.fromkeys(ARCHIVE.FUNCTIONAL_CHECKS, 'passed'),
        payload='/qualification/relocated musl archive/payload', cli='/qualification/relocated musl archive/cbodotnet',
        trustProbe='/qualification/system-trust/bin/Debug/net10.0/Trust.dll',
        commands=[dict(command=name, targetRid=plan['targetRid'], sdkRoot='/qualification/relocated musl archive/payload')
                  for name in ('dotnet', 'cbodotnet', 'cbodotnet-10.0')],
        dependencies=[name+'-'+version for name,version in ARCHIVE.RUNTIME_PACKAGES.items()],
        caBundle=dict(name='ca-certificates.crt',size=1234,sha256='e'*64),
        elfAudit=dict(name='elf-audit.json',size=len(elf_raw),sha256=hashlib.sha256(elf_raw).hexdigest()))
    return dict(schemaVersion=1, scope='musl-consumer-archive-installation', status='passed', native=True,
        architecture=arch, libc='musl', targetRid=plan['targetRid'], networkForBuild='none', identity=ARCHIVE.identity(plan),
        artifact=build['artifact'], orchestration=copy.deepcopy(ORIGIN),
        checks=dict.fromkeys(ARCHIVE.REPORT_CHECKS, 'passed'), functionalChecks=dict.fromkeys(ARCHIVE.FUNCTIONAL_CHECKS, 'passed'),
        userSpaces=[dict(variant='alpine-3.24', alpineVersion='3.24.4', base=ARCHIVE.BASES[arch], status='passed',
            imageId='sha256:'+'c'*64, uid=10001, gid=10001,
            systemTrustHttps=dict(status='passed', url=ARCHIVE.trust_url(arch), network='default-only-after-offline-build', outputSha256='d'*64),
            elfAudit=elf, offline=offline)])


class FakeReleases:
    gh = 'fixture-gh'
    def __init__(self):
        self.release = None
        self.objects = {}
        self.posts = []
        self.uploads = []
        self.publish_count = 0
        self.tag_commit = None
    def api(self, endpoint, method='GET', body=None):
        if method == 'POST':
            self.posts.append(copy.deepcopy(body))
            self.release = dict(body, id=1234, html_url=f'https://github.com/{CONTRACT.REPOSITORY}/releases/tag/{body["tag_name"]}', assets=[])
            return copy.deepcopy(self.release)
        if self.release is not None and endpoint.startswith('repos/'+CONTRACT.REPOSITORY+'/git/ref/tags/'):
            if not self.release['draft']:
                return dict(ref='refs/tags/'+self.release['tag_name'],object=dict(type='commit',
                    sha=self.tag_commit or self.release['target_commitish']))
        return None
    def find(self, tag):
        return copy.deepcopy(self.release)
    def get(self, release):
        return copy.deepcopy(self.release)
    def upload(self, release, path):
        raw = Path(path).read_bytes()
        self.objects[path.name] = raw
        self.uploads.append(path.name)
        self.release['assets'].append(dict(id=len(self.uploads), name=path.name, size=len(raw), state='uploaded',
            digest='sha256:'+hashlib.sha256(raw).hexdigest(),
            browser_download_url=f'https://github.com/{CONTRACT.REPOSITORY}/releases/download/{release["tag_name"]}/{path.name}'))
    def download(self, asset, destination, public=False):
        Path(destination).write_bytes(self.objects[asset['name']])
    def publish(self, release):
        self.publish_count += 1
        self.release['draft'] = False
        return copy.deepcopy(self.release)


class MuslPromotionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.catalog = source_inputs(self.inputs)
        self.catalog_patch = mock.patch.object(CONTRACT, 'load_qualification_catalog', return_value=self.catalog)
        self.catalog_patch.start()
        self.addCleanup(self.catalog_patch.stop)
        self.candidates = {}
        for arch in CONTRACT.ARCHITECTURES:
            directory = self.root / ('native-' + arch)
            build = ARCHIVE.build_archive(self.inputs, arch, 1, directory)
            # Native transports retain only the closed three-file result.
            shutil.rmtree(directory / build['directory'])
            (directory / 'qualification-report.json').write_bytes(encoded(native_report(build)))
            self.candidates[arch] = dict(directory=directory, transport=dict(artifactId=100 if arch == 'x64' else 101))

    def fake_sign(self, arguments, **kwargs):
        Path(arguments[arguments.index('--output') + 1]).write_bytes(b'fixture-detached-signature')

    def bundle(self, output=None):
        output = output or self.root / 'bundle'
        with mock.patch.object(PROMOTION, 'validate_elf_report'), \
             mock.patch.object(PROMOTION.subprocess, 'run', side_effect=self.fake_sign), \
             mock.patch.object(PROMOTION, 'verify_report_signature', return_value=SIGNER):
            manifest = PROMOTION.create_bundle(self.candidates, ORIGIN, output, keyring=self.root / 'keyring.gpg',
                target_commit='a'*40, source_receiver=lambda arch, directory: self.inputs)
        return manifest

    def test_protected_main_current_job_gate_rejects_other_contexts(self):
        with mock.patch.dict(PROMOTION.os.environ, ENVIRONMENT, clear=True):
            self.assertEqual(ORIGIN, PROMOTION.protected())
        for field, value in (('GITHUB_JOB', 'native_archive'), ('GITHUB_REF', 'refs/heads/topic'),
                             ('GITHUB_WORKFLOW_SHA', 'b'*40), ('GITHUB_EVENT_NAME', 'pull_request')):
            with self.subTest(field=field), mock.patch.dict(PROMOTION.os.environ, dict(ENVIRONMENT, **{field: value}), clear=True):
                with self.assertRaisesRegex(ValueError, 'Only protected main'):
                    PROMOTION.protected()

    def test_in_progress_run_is_allowed_only_for_the_exact_protected_current_run(self):
        run = dict(id=123, run_attempt=2, path=PROMOTION.WORKFLOW, head_sha='a'*40, head_branch='main',
            event='workflow_dispatch', repository=dict(full_name=CONTRACT.REPOSITORY),
            head_repository=dict(full_name=CONTRACT.REPOSITORY), status='in_progress', conclusion=None)
        self.assertEqual('a'*40, PROMOTION.validate_native_run(run, 123, 2, current=ORIGIN))
        for current in (None, dict(ORIGIN, runAttempt='1'), dict(ORIGIN, commit='b'*40)):
            with self.subTest(current=current), self.assertRaises(ValueError):
                PROMOTION.validate_native_run(run, 123, 2, current=current)
        run.update(status='completed', conclusion='failure')
        with self.assertRaises(ValueError):
            PROMOTION.validate_native_run(run, 123, 2, current=ORIGIN)

    def test_a_successful_run_with_only_one_native_job_cannot_supply_a_matrix(self):
        run = dict(id=123, run_attempt=2, path=PROMOTION.WORKFLOW, head_sha='a'*40, head_branch='main',
            event='workflow_dispatch', repository=dict(full_name=CONTRACT.REPOSITORY),
            head_repository=dict(full_name=CONTRACT.REPOSITORY), status='completed', conclusion='success')
        api = mock.Mock()
        api.api.side_effect = [run, dict(jobs=[dict(id=1, name='Qualify musl archive native x64', status='completed', conclusion='success')])]
        with self.assertRaisesRegex(ValueError, 'Both exact native'):
            PROMOTION.native_identity(api, 123, 2)

    def test_native_candidate_is_reconstructed_from_exact_qualified_source(self):
        item = self.candidates['x64']
        with mock.patch.object(PROMOTION, 'validate_elf_report') as native_elf:
            build, report = PROMOTION.verify_candidate(item['directory'], 'x64', ORIGIN, self.inputs)
            native_elf.assert_called_once()
        self.assertEqual('musl', build['plan']['libc'])
        self.assertEqual(ORIGIN, report['orchestration'])
        archive = item['directory'] / build['artifact']['name']
        archive.write_bytes(archive.read_bytes() + b'changed')
        with self.assertRaisesRegex(ValueError, 'archive bytes changed'):
            PROMOTION.verify_candidate(item['directory'], 'x64', ORIGIN, self.inputs)

    def test_actual_native_report_writer_roundtrips_through_the_promotion_validator(self):
        directory = self.candidates['x64']['directory']
        build = json.loads((directory/'package-build.json').read_bytes())
        fixture = native_report(build)
        workspace = self.root/'native-roundtrip'
        commands = []
        def docker(arguments, **kwargs):
            arguments = list(map(str, arguments))
            commands.append(arguments)
            if arguments[:2] == ['docker','info']:
                return 'x86_64\n'
            if arguments[:3] == ['docker','image','inspect']:
                return json.dumps([dict(Architecture='amd64',Os='linux',Id='sha256:'+'c'*64)])
            if arguments[:2] == ['docker','run'] and '--network=none' in arguments:
                (workspace/'offline-report.json').write_bytes(encoded(fixture['userSpaces'][0]['offline']))
                (workspace/'elf-audit.json').write_bytes(encoded(fixture['userSpaces'][0]['elfAudit']))
                return 'installed-passed\n'
            if arguments[:2] == ['docker','run'] and '--network=default' in arguments:
                return 'system-root-count=118\nsystem-trust-https-passed\n'
            return ''
        with mock.patch.object(ARCHIVE.platform,'system',return_value='Linux'), \
             mock.patch.object(ARCHIVE.platform,'machine',return_value='x86_64'), \
             mock.patch.object(ARCHIVE,'run',side_effect=docker):
            report = ARCHIVE.native(directory,'x64',workspace)
        report['orchestration'] = copy.deepcopy(ORIGIN)
        self.assertEqual('passed',report['userSpaces'][0]['status'])
        self.assertEqual('none',report['userSpaces'][0]['offline']['networkForBuild'])
        self.assertEqual(build['artifact'],report['artifact'])
        self.assertEqual(report,PROMOTION.validate_native_report(report,build,ORIGIN))
        self.assertTrue(any('--network=none' in command and '10001:10001' in command for command in commands))

    def test_offline_worker_cannot_synthesize_passed_from_wrong_network_source_or_probe(self):
        build = json.loads((self.candidates['x64']['directory']/'package-build.json').read_bytes())
        fixture = native_report(build)
        original = fixture['userSpaces'][0]['offline']
        for key,value in (('status','failed'),('networkForBuild','default'),('identity',{}),('archive',{}),
                          ('uid',0),('cli','/bin/sh'),('functionalChecks',{})):
            changed = copy.deepcopy(original)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                ARCHIVE.validate_offline_report(changed,build,'x64',elf_audit=fixture['userSpaces'][0]['elfAudit'])

    def test_untrusted_artifact_name_cannot_route_a_read_outside_the_candidate(self):
        directory = self.candidates['x64']['directory']
        path = directory / 'package-build.json'
        build = json.loads(path.read_bytes())
        build['artifact']['name'] = '/outside/private-material'
        path.write_bytes(encoded(build))
        with mock.patch.object(PROMOTION, 'descriptor') as inspected:
            with self.assertRaisesRegex(ValueError, 'artifact name differs'):
                PROMOTION.verify_candidate(directory, 'x64', ORIGIN, self.inputs)
        inspected.assert_not_called()

    def test_modified_build_source_or_native_functional_checks_cannot_be_signed(self):
        item = self.candidates['x64']
        path = item['directory'] / 'package-build.json'
        original = path.read_bytes()
        build = json.loads(original)
        build['plan']['sourceManifestSha256'] = '0'*64
        path.write_bytes(encoded(build))
        with self.assertRaisesRegex(ValueError, 'independently reconstructed'):
            PROMOTION.verify_candidate(item['directory'], 'x64', ORIGIN, self.inputs)
        path.write_bytes(original)
        report_path = item['directory'] / 'qualification-report.json'
        report = json.loads(report_path.read_bytes())
        report['functionalChecks']['tls12LoopbackHandshake'] = 'skipped'
        report_path.write_bytes(encoded(report))
        with self.assertRaisesRegex(ValueError, 'mandatory native musl'):
            PROMOTION.verify_candidate(item['directory'], 'x64', ORIGIN, self.inputs)

    def test_compression_differences_preserve_identical_qualified_consumer_tree(self):
        directory = self.candidates['x64']['directory']
        build_path = directory / 'package-build.json'
        build = json.loads(build_path.read_bytes())
        archive = directory / build['artifact']['name']
        original = archive.read_bytes()
        archive.write_bytes(gzip.compress(gzip.decompress(original), compresslevel=1, mtime=0))
        self.assertNotEqual(original, archive.read_bytes())
        build['artifact'] = descriptor(archive)
        build_path.write_bytes(encoded(build))
        report_path = directory / 'qualification-report.json'
        report = json.loads(report_path.read_bytes())
        report['artifact'] = build['artifact']
        report['userSpaces'][0]['offline']['archive'] = build['artifact']
        report_path.write_bytes(encoded(report))
        with mock.patch.object(PROMOTION, 'validate_elf_report'):
            actual, _ = PROMOTION.verify_candidate(directory, 'x64', ORIGIN, self.inputs)
        self.assertEqual(build['artifact'], actual['artifact'])

    def test_rehashed_archive_with_changed_wrapper_is_rejected_by_exact_tree_comparison(self):
        directory = self.candidates['x64']['directory']
        build_path = directory / 'package-build.json'
        build = json.loads(build_path.read_bytes())
        archive_path = directory / build['artifact']['name']
        changed = io.BytesIO()
        with tarfile.open(archive_path, 'r:gz') as source, tarfile.open(fileobj=changed, mode='w:gz') as target:
            for entry in source:
                if entry.isfile():
                    raw = source.extractfile(entry).read()
                    if entry.name == build['directory'] + '/cbodotnet':
                        raw = b'#!/bin/sh\necho changed-wrapper\n'
                    entry.size = len(raw)
                    target.addfile(entry, io.BytesIO(raw))
                else:
                    target.addfile(entry)
        archive_path.write_bytes(changed.getvalue())
        build['artifact'] = descriptor(archive_path)
        build_path.write_bytes(encoded(build))
        report_path = directory / 'qualification-report.json'
        report = json.loads(report_path.read_bytes())
        report['artifact'] = build['artifact']
        report['userSpaces'][0]['offline']['archive'] = build['artifact']
        report_path.write_bytes(encoded(report))
        with self.assertRaisesRegex(ValueError, 'archive tree differs'):
            PROMOTION.verify_candidate(directory, 'x64', ORIGIN, self.inputs)

    def test_partial_matrix_alias_source_run_and_tampered_frozen_bytes_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'Both native'):
            PROMOTION.create_bundle({'x64': self.candidates['x64']}, ORIGIN, self.root / 'partial',
                keyring=self.root / 'keyring', target_commit='a'*40)
        manifest = self.bundle()
        self.assertEqual(2, len(manifest['records']))
        self.assertEqual(4, len(manifest['assets']))
        path = self.root / 'bundle' / manifest['assets'][0]['name']
        path.write_bytes(path.read_bytes() + b'changed')
        with mock.patch.object(PROMOTION, 'verify_report_signature', return_value=SIGNER):
            with self.assertRaisesRegex(ValueError, 'Frozen musl asset bytes changed'):
                PROMOTION.validate_bundle(self.root / 'bundle', self.root / 'keyring')

    def test_private_and_anonymous_public_bytes_are_checked_without_latest_or_overwrite(self):
        manifest = self.bundle()
        api = FakeReleases()
        with mock.patch.dict(PROMOTION.os.environ, dict(ENVIRONMENT, GITHUB_JOB='publish_archive'), clear=True), \
             mock.patch.object(PROMOTION, 'verify_report_signature', return_value=SIGNER), \
             mock.patch.object(PROMOTION, 'native_identity', return_value=({}, ORIGIN, {})):
            first = PROMOTION.publish_bundle(self.root / 'bundle', self.root / 'keyring', api=api)
            uploads = list(api.uploads)
            second = PROMOTION.publish_bundle(self.root / 'bundle', self.root / 'keyring', api=api)
        self.assertEqual(uploads, api.uploads)
        self.assertEqual(1, api.publish_count)
        self.assertEqual('false', api.posts[0]['make_latest'])
        self.assertEqual('published-public-bytes-verified', first['status'])
        self.assertEqual(first, second)
        self.assertNotIn('verification', first)
        self.assertEqual(manifest['identity'], first['identity'])

    def test_existing_remote_digest_conflict_never_uploads_or_replaces_assets(self):
        manifest = self.bundle()
        api = FakeReleases()
        title, body = PROMOTION.publication_metadata(manifest)
        api.release = dict(id=5, tag_name=manifest['tag'], name=title, body=body,
            target_commitish=manifest['targetCommit'], prerelease=False, draft=True,
            assets=[dict(name=manifest['assets'][0]['name'], size=manifest['assets'][0]['size'], digest='sha256:'+'0'*64)])
        with mock.patch.dict(PROMOTION.os.environ, ENVIRONMENT, clear=True), \
             mock.patch.object(PROMOTION, 'verify_report_signature', return_value=SIGNER), \
             mock.patch.object(PROMOTION, 'native_identity', return_value=({}, ORIGIN, {})):
            with self.assertRaisesRegex(ValueError, 'Refusing to replace conflicting'):
                PROMOTION.publish_bundle(self.root / 'bundle', self.root / 'keyring', api=api)
        self.assertEqual([], api.uploads)
        self.assertEqual(0, api.publish_count)

    def test_actual_published_tag_commit_is_verified_before_accepting_a_resume(self):
        self.bundle()
        api = FakeReleases()
        with mock.patch.dict(PROMOTION.os.environ, ENVIRONMENT, clear=True), \
             mock.patch.object(PROMOTION, 'verify_report_signature', return_value=SIGNER), \
             mock.patch.object(PROMOTION, 'native_identity', return_value=({}, ORIGIN, {})):
            PROMOTION.publish_bundle(self.root/'bundle',self.root/'keyring',api=api)
            uploads = list(api.uploads)
            api.tag_commit = 'b'*40
            with self.assertRaisesRegex(ValueError,'Actual musl tag ref points to another commit'):
                PROMOTION.publish_bundle(self.root/'bundle',self.root/'keyring',api=api)
        self.assertEqual(uploads,api.uploads)

    def test_flat_transport_rejects_an_extra_file_even_with_a_valid_api_digest(self):
        origin = copy.deepcopy(ORIGIN)
        run = dict(id=123, run_attempt=2, head_sha='a'*40)
        jobs = {arch: dict(id=index + 1, name='Qualify musl archive native '+arch)
                for index, arch in enumerate(CONTRACT.ARCHITECTURES)}
        objects, artifacts = {}, []
        for index, (arch, item) in enumerate(self.candidates.items()):
            content = io.BytesIO()
            with zipfile.ZipFile(content, 'w') as archive:
                for path in item['directory'].iterdir():
                    archive.writestr(path.name, path.read_bytes())
                archive.writestr('extra.sh', b'not allowed')
            raw = content.getvalue()
            objects[index] = raw
            artifacts.append(dict(id=index+1, name=PROMOTION.artifact_name(arch, origin), expired=False,
                size_in_bytes=len(raw), digest='sha256:'+hashlib.sha256(raw).hexdigest(),
                workflow_run=dict(id=123, head_sha='a'*40, head_branch='main', repository_id=10, head_repository_id=10)))
        api = mock.Mock()
        api.api.return_value = dict(artifacts=artifacts)
        with mock.patch.object(PROMOTION, 'native_identity', return_value=(run, origin, jobs)):
            with self.assertRaisesRegex(ValueError, 'missing, duplicate or unexpected'):
                PROMOTION.receive_candidates(api, 123, 2, 1, self.root / 'received',
                    downloader=lambda artifact, path: path.write_bytes(objects[artifact['id']-1]))


if __name__ == '__main__':
    unittest.main()
