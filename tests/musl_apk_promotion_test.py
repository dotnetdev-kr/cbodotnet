"""Real RSA APK/control/payload binding and immutable two-CPU promotion."""
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import musl_apk_promotion as M
import musl_archive as ARCHIVE
import musl_contract as CONTRACT
import musl_distribution as DISTRIBUTION
import musl_package_native as NATIVE
import musl_packages as APK
import musl_release as RELEASE
from downstream_release import descriptor, encoded
from musl_promotion_test import source_inputs, ORIGIN, ENVIRONMENT, FakeReleases, SIGNER
from musl_packages_test import tar_bytes


def data_stream(tree):
    output = io.BytesIO()
    def canonical(row):
        row.uid = row.gid = 0
        row.uname = row.gname = ''
        row.mtime = int(APK.SOURCE_DATE_EPOCH)
        row.pax_headers = {}
        return row
    with tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(tree.rglob('*')):
            archive.add(path, arcname=path.relative_to(tree).as_posix(), recursive=False, filter=canonical)
    return gzip.compress(output.getvalue(), mtime=0)


def native_report(build):
    plan = build['plan']; arch = plan['architecture']['public']
    packages = [{k:v for k,v in row.items() if k != 'kind'} for row in build['packages']]
    elf = dict(status='passed', native=True, libc='musl', architecture=arch, targetRid=plan['targetRid'],
               hostElfCount=1, nonHostElfCount=0, stockLibraries=[dict(path='/lib/libc.musl.so', sha256='f'*64)])
    functional = dict.fromkeys(ARCHIVE.FUNCTIONAL_CHECKS, 'passed')
    offline = dict(schemaVersion=1, scope='musl-apk-offline', status='passed', native=True, architecture=arch,
        libc='musl', targetRid=plan['targetRid'], identity=ARCHIVE.identity(plan), networkForBuild='none', uid=10001, gid=10001,
        checks=dict.fromkeys(NATIVE.APK_CHECKS-{'system-trust-https'}, 'passed'), functionalChecks=functional,
        packages=packages, payload=plan['package']['root'], cli='/usr/bin/cbodotnet',
        trustProbe='/qualification/system-trust/bin/Debug/net10.0/Trust.dll',
        commands=[dict(command=name, sdkRoot=plan['package']['root'], targetRid=plan['targetRid'])
                  for name in ('cbodotnet', 'cbodotnet-10.0')],
        dependencies=[name+'-'+version for name,version in ARCHIVE.RUNTIME_PACKAGES.items()],
        caBundle=dict(name='ca-certificates.crt', size=1234, sha256='c'*64),
        negativeCases={name:dict(status='rejected', exitCode=1, diagnostic='BAD signature') for name in M.NEGATIVE_CASES})
    return dict(schemaVersion=1, scope='musl-apk-installation', status='passed', native=True, architecture=arch,
        libc='musl', targetRid=plan['targetRid'], identity=ARCHIVE.identity(plan), networkForBuild='none',
        artifact=M.package_artifact(build), orchestration=copy.deepcopy(ORIGIN),
        checks=dict.fromkeys(NATIVE.APK_CHECKS, 'passed'), functionalChecks=functional,
        userSpaces=[dict(variant='alpine-3.24', alpineVersion='3.24.4', base=ARCHIVE.BASES[arch],
            imageId='sha256:'+'d'*64, uid=10001, gid=10001, offline=offline, elfAudit=elf,
            systemTrustHttps=dict(status='passed', url=ARCHIVE.trust_url(arch), outputSha256='e'*64))])


def lifecycle(first, second):
    plan = first['plan']
    def install(build):
        index = build['repository']
        return dict(operation='install-or-select', version=build['plan']['package']['version'],
                    sourceIndex=dict(name=index['path'], size=index['size'], sha256=index['sha256']))
    return dict(schemaVersion=1, scope='musl-apk-lifecycle', status='passed', native=True,
        architecture=plan['architecture']['public'], libc='musl', targetRid=plan['targetRid'],
        identity=ARCHIVE.identity(plan), signingKey=first['signingKey'], orchestration=copy.deepcopy(ORIGIN),
        events=[install(first), dict(operation='reinstall', version=plan['package']['version']),
            install(second), install(first), dict(operation='remove-sdk-retain-explicit-host', status='passed'),
            install(first), dict(operation='remove-sdk-and-host', status='passed')],
        official=dict(version='10.0.303', owner='/usr/bin/dotnet is owned by dotnet-host-10.0.14-r0',
            host=dict(name='dotnet', size=1234, sha256='b'*64), completeTreePreserved=True))


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl'), 'Linux OpenSSL and modes required')
class ApkPromotionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='ephemeral-apk-promotion-tests-')
        cls.base = Path(cls.temporary.name)
        cls.inputs = cls.base / 'inputs'; cls.inputs.mkdir()
        cls.catalog = source_inputs(cls.inputs)
        cls.private = cls.base / 'fixture.rsa'
        cls.public = cls.base / 'build.rsa.pub'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:4096',
                        '-out', str(cls.private)], check=True, capture_output=True)
        cls.private.chmod(0o600)
        subprocess.run(['openssl', 'pkey', '-in', str(cls.private), '-pubout', '-out', str(cls.public)],
                       check=True, capture_output=True)
        cls.target_public = cls.base / 'approved-fixture.rsa.pub'
        cls.target_public.write_bytes(cls.public.read_bytes())
        cls.policy = copy.deepcopy(RELEASE.load_signing_policy())
        identity = APK.public_key_identity(cls.target_public)
        cls.policy['apkSigner'].update(publicKeyName=identity['filename'], publicKeySha256=identity['sha256'],
            spkiDerSha256=identity['spkiSha256'])
        cls.candidates = {}
        with mock.patch.object(CONTRACT, 'load_qualification_catalog', return_value=cls.catalog):
            for arch in CONTRACT.ARCHITECTURES:
                directory = cls.base / arch; directory.mkdir()
                builds = []
                for revision, label in [(1, 'build'), (2, 'upgrade')]:
                    destination = directory / label; destination.mkdir()
                    repo = destination / 'repository'; repo.mkdir()
                    plan, sdk = DISTRIBUTION.intake_plan(cls.inputs, arch, 'apk', revision)
                    stage = cls.base / ('canonical-' + arch + '-' + label)
                    trees, commands, payload = M.canonical_package_trees(plan, sdk, stage)
                    packages = []
                    for kind in ('host', 'sdk'):
                        name = 'cbodotnet-host' if kind == 'host' else plan['package']['name']
                        version = APK.HOST_VERSION if kind == 'host' else plan['package']['version']
                        cpu = 'noarch' if kind == 'host' else plan['architecture']['apk']
                        data = data_stream(trees[kind])
                        dependencies = ['busybox'] if kind == 'host' else ['cbodotnet-host>=' + APK.HOST_VERSION, *plan['dependencies']]
                        info = f'pkgname = {name}\npkgver = {version}\narch = {cpu}\ndatahash = {hashlib.sha256(data).hexdigest()}\n'
                        info += ''.join('depend = ' + value + '\n' for value in dependencies)
                        control = gzip.compress(tar_bytes([('.PKGINFO', info.encode(), 'file')]), mtime=0)
                        package = repo / (name + '-' + version + '.apk')
                        package.write_bytes(NATIVE.signature_prefix(control, cls.private, cls.public) + control + data)
                        packages.append(dict(APK.verify_apk(package, cls.public), kind=kind))
                        recipe = destination / 'aports/cbodotnet' / kind / 'APKBUILD'
                        recipe.parent.mkdir(parents=True)
                        source = recipe.parent / 'payload.tar.gz'
                        APK.stage_source_archive(trees[kind], source)
                        with source.open('rb') as stream:
                            digest = APK.stream_digest(stream, 'sha512')
                        recipe.write_text(APK.recipe(plan, kind, digest))
                    blocks = []
                    for row in packages:
                        blocks.append(f"C:{row['indexIdentity']}\nP:{row['name']}\nV:{row['version']}\nA:{row['architecture']}\nS:{row['size']}\n")
                    index = gzip.compress(tar_bytes([('APKINDEX', '\n'.join(blocks).encode(), 'file')]), mtime=0)
                    (repo / 'APKINDEX.tar.gz').write_bytes(NATIVE.signature_prefix(index, cls.private, cls.public) + index)
                    build = dict(schemaVersion=1, channel='apk', libc='musl', plan=plan, packages=packages,
                        commandInventory=commands, payloadPreserved=True, publicationQualified=False,
                        credentialPurpose='ephemeral-build-candidate', signingKey=APK.public_key_identity(cls.public),
                        publicKeyAsset=APK.descriptor(cls.public), repository=APK.verify_index(repo / 'APKINDEX.tar.gz', cls.public, packages))
                    for name, value in [('package-build.json', build), ('plan.json', plan),
                                        ('payload-inventory.json', payload), ('command-inventory.json', commands)]:
                        (destination / name).write_bytes(encoded(value))
                    builds.append(build)
                shutil.copyfile(cls.public, directory / 'build.rsa.pub')
                for name, value in [('qualification-report.json', native_report(builds[0])),
                    ('lifecycle-report.json', lifecycle(*builds)), ('orchestration.json', ORIGIN)]:
                    (directory / name).write_bytes(encoded(value))
                cls.candidates[arch] = dict(directory=directory, transport=dict(artifactId=100 if arch == 'x64' else 101))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.temporary_work = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_work.cleanup)
        self.root = Path(self.temporary_work.name)
        self.items = {}
        for arch, item in self.candidates.items():
            target = self.root / arch
            shutil.copytree(item['directory'], target)
            self.items[arch] = dict(directory=target, transport=copy.deepcopy(item['transport']))
        for target, name, value in [(CONTRACT, 'load_qualification_catalog', self.catalog),
                                    (RELEASE, 'load_signing_policy', self.policy)]:
            patch = mock.patch.object(target, name, return_value=value)
            patch.start(); self.addCleanup(patch.stop)

    def bundle(self):
        original_run = subprocess.run
        def command(arguments, **kwargs):
            if arguments[0] == 'gpg':
                Path(arguments[arguments.index('--output') + 1]).write_bytes(b'fixture-detached-signature')
                return subprocess.CompletedProcess(arguments, 0)
            return original_run(arguments, **kwargs)
        with mock.patch.object(M.PROMOTION, 'validate_elf_report'), \
             mock.patch.object(M.subprocess, 'run', side_effect=command), \
             mock.patch.object(M, 'verify_report_signature', return_value=SIGNER):
            return M.create_bundle(self.items, ORIGIN, self.root / 'bundle', apk_private_key=self.private,
                apk_public_key=self.target_public, keyring=self.root / 'keyring.gpg', target_commit='a'*40,
                policy=self.policy, source_receiver=lambda arch, target: self.inputs)

    def test_original_candidate_binds_real_rsa_payload_recipe_and_lifecycle(self):
        with mock.patch.object(M.PROMOTION, 'validate_elf_report') as inspect:
            first, second, report, life = M.verify_candidate(self.items['x64']['directory'], 'x64', ORIGIN, self.inputs)
        inspect.assert_called_once()
        self.assertEqual(1, first['plan']['packageRevision'])
        self.assertEqual(2, second['plan']['packageRevision'])
        self.assertEqual('passed', report['status'])
        self.assertEqual(7, len(life['events']))

    def test_both_cpus_freeze_only_r1_and_keep_native_to_permanent_digest_bridge(self):
        manifest = self.bundle()
        self.assertEqual('apk', manifest['identity']['channel'])
        self.assertEqual({'x64', 'aarch64'}, {r['architecture'] for r in manifest['records']})
        self.assertFalse(any('10.0.403-r2.apk' in a['name'] for a in manifest['assets']))
        for row in manifest['records']:
            self.assertEqual(row['build']['priorNativePackages'][1]['sha256'], row['nativeBuild']['packages'][1]['sha256'])
            self.assertNotEqual(row['nativeBuild']['packages'][1]['sha256'], row['build']['packages'][1]['sha256'])
            self.assertEqual(row['nativeBuild']['packages'][1]['controlSha256'], row['build']['packages'][1]['controlSha256'])
            self.assertEqual(row['nativeBuild']['packages'][1]['dataSha256'], row['build']['packages'][1]['dataSha256'])
            self.assertEqual('approved-fixture.rsa.pub', row['build']['publicKeyAsset']['name'])
        with mock.patch.object(M, 'verify_report_signature', return_value=SIGNER):
            self.assertEqual(manifest, M.validate_bundle(self.root / 'bundle', self.root / 'keyring.gpg', policy=self.policy))

    def test_temporary_trust_identity_cannot_be_used_as_permanent_signer(self):
        with self.assertRaisesRegex(ValueError, 'approved exact PEM'):
            M.create_bundle(self.items, ORIGIN, self.root / 'rejected', apk_private_key=self.private,
                apk_public_key=self.public, keyring=self.root / 'keyring.gpg', target_commit='a'*40,
                policy=self.policy, source_receiver=lambda arch, target: self.inputs)
        self.assertFalse((self.root / 'rejected').exists())

    def test_unqualified_source_tampered_package_recipe_and_extra_credentials_are_rejected(self):
        for kind in ('source', 'package', 'recipe', 'source-gzip', 'extra'):
            with self.subTest(kind=kind):
                copied = self.root / ('changed-' + kind)
                shutil.copytree(self.items['x64']['directory'], copied)
                if kind == 'source':
                    path = copied / 'build/package-build.json'; value = json.loads(path.read_bytes())
                    value['plan']['sourceManifestSha256'] = '0'*64; path.write_bytes(encoded(value))
                elif kind == 'package':
                    path = next((copied / 'build/repository').glob('*sdk*.apk')); path.write_bytes(path.read_bytes() + b'tamper')
                elif kind == 'recipe':
                    path = copied / 'build/aports/cbodotnet/sdk/APKBUILD'; path.write_text(path.read_text() + '\nrm -rf /\n')
                elif kind == 'source-gzip':
                    path = copied / 'build/aports/cbodotnet/sdk/payload.tar.gz'; path.write_bytes(path.read_bytes() + b'tamper')
                else:
                    (copied / 'build.rsa').write_bytes(b'private key must never be transported')
                with mock.patch.object(M.PROMOTION, 'validate_elf_report'), self.assertRaises(ValueError):
                    M.verify_candidate(copied, 'x64', ORIGIN, self.inputs)

    def test_native_report_requires_signature_negatives_full_runtime_and_lifecycle_order(self):
        directory = self.items['x64']['directory']
        build = json.loads((directory / 'build/package-build.json').read_bytes())
        upgrade = json.loads((directory / 'upgrade/package-build.json').read_bytes())
        report = json.loads((directory / 'qualification-report.json').read_bytes())
        for field in ('negative', 'functional', 'network', 'packages'):
            changed = copy.deepcopy(report)
            offline = changed['userSpaces'][0]['offline']
            if field == 'negative': offline['negativeCases'].pop('missing-key')
            elif field == 'functional': offline['functionalChecks']['tls12LoopbackHandshake'] = 'skipped'
            elif field == 'network': offline['networkForBuild'] = 'default'
            else: offline['packages'][0]['sha256'] = '0'*64
            with self.subTest(field=field), self.assertRaises(ValueError):
                M.validate_native_report(changed, build, ORIGIN)
        changed = json.loads((directory / 'lifecycle-report.json').read_bytes())
        changed['events'][2], changed['events'][3] = changed['events'][3], changed['events'][2]
        with self.assertRaisesRegex(ValueError, 'reinstall/upgrade/rollback'):
            M.validate_lifecycle(changed, build, upgrade, ORIGIN, build['signingKey'])

    def test_actual_source_gzip_can_reencode_but_cannot_add_unbound_files(self):
        directory = self.items['x64']['directory']
        work = directory / 'build/aports/cbodotnet/sdk'
        source = work / 'payload.tar.gz'
        plain = gzip.decompress(source.read_bytes())
        original = source.read_bytes()
        source.write_bytes(gzip.compress(plain, compresslevel=1, mtime=1234))
        self.assertNotEqual(original, source.read_bytes())
        plan = json.loads((directory / 'build/plan.json').read_bytes())
        (work / 'APKBUILD').write_text(APK.recipe(plan, 'sdk', hashlib.sha512(source.read_bytes()).hexdigest()))
        with mock.patch.object(M.PROMOTION, 'validate_elf_report'):
            M.verify_candidate(directory, 'x64', ORIGIN, self.inputs)
        # A recipe with an updated valid source hash still cannot smuggle a file
        # outside the complete package tree which was reconstructed from the SDK.
        output = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as incoming, tarfile.open(fileobj=output, mode='w:') as archive:
            for row in incoming:
                archive.addfile(row, incoming.extractfile(row) if row.isfile() else None)
            row = tarfile.TarInfo('rootfs/usr/unbound'); row.mode = 0o644; row.size = 4
            archive.addfile(row, io.BytesIO(b'evil'))
        source.write_bytes(gzip.compress(output.getvalue(), mtime=0))
        (work / 'APKBUILD').write_text(APK.recipe(plan, 'sdk', hashlib.sha512(source.read_bytes()).hexdigest()))
        with mock.patch.object(M.PROMOTION, 'validate_elf_report'), self.assertRaisesRegex(ValueError, 'complete canonical package tree'):
            M.verify_candidate(directory, 'x64', ORIGIN, self.inputs)

    def test_signed_asset_byte_changes_and_unreferenced_r2_are_rejected(self):
        manifest = self.bundle()
        directory = self.root / 'bundle'
        selected = directory / manifest['records'][0]['artifactAsset']
        selected.write_bytes(selected.read_bytes() + b'tamper')
        with mock.patch.object(M, 'verify_report_signature', return_value=SIGNER), self.assertRaisesRegex(ValueError, 'bytes changed'):
            M.validate_bundle(directory, self.root / 'keyring.gpg', policy=self.policy)
        (directory / 'extra-r2.apk').write_bytes(b'unreviewed')
        with mock.patch.object(M, 'verify_report_signature', return_value=SIGNER), self.assertRaisesRegex(ValueError, 'closed set'):
            M.validate_bundle(directory, self.root / 'keyring.gpg', policy=self.policy)

    def test_protected_job_and_exact_two_successful_native_jobs_are_required(self):
        environment = dict(ENVIRONMENT, GITHUB_JOB='freeze_apk')
        with mock.patch.dict(M.os.environ, environment, clear=True):
            self.assertEqual(ORIGIN, M.protected())
        for field, value in [('GITHUB_JOB', 'native_apk'), ('GITHUB_REF', 'refs/heads/topic'), ('GITHUB_WORKFLOW_SHA', 'b'*40)]:
            with self.subTest(field=field), mock.patch.dict(M.os.environ, dict(environment, **{field:value}), clear=True):
                with self.assertRaisesRegex(ValueError, 'Only protected main'):
                    M.protected()
        run = dict(id=123, run_attempt=2, path=M.WORKFLOW, head_sha='a'*40, head_branch='main', event='workflow_dispatch',
            repository=dict(full_name=M.REPOSITORY), head_repository=dict(full_name=M.REPOSITORY), status='completed', conclusion='success')
        jobs = [dict(id=i+1, name='Qualify musl APK native '+arch, status='completed', conclusion='success', head_sha='a'*40,
                    runner_id=100+i, runner_name='GitHub Actions '+str(100+i), runner_group_name='GitHub Actions',
                    labels=[M.RUNNER_LABELS[arch]], started_at='2026-11-07T00:00:00Z', completed_at='2026-11-07T00:10:00Z')
                for i,arch in enumerate(CONTRACT.ARCHITECTURES)]
        api = mock.Mock(); api.api.side_effect = [run, dict(jobs=jobs)]
        self.assertEqual(ORIGIN, M.native_identity(api, 123, 2)[1])
        api.api.side_effect = [run, dict(jobs=jobs[:1])]
        with self.assertRaisesRegex(ValueError, 'Both exact native APK'):
            M.native_identity(api, 123, 2)
        jobs[0]['labels'] = ['self-hosted', M.RUNNER_LABELS['x64']]
        api.api.side_effect = [run, dict(jobs=jobs)]
        with self.assertRaisesRegex(ValueError, 'exact native GitHub-hosted CPU'):
            M.native_identity(api, 123, 2)

    def test_repository_publication_is_immutable_idempotent_and_checks_real_tag_commit(self):
        path = self.root / 'prefixed.apk'; path.write_bytes(b'signed fixture package')
        api = FakeReleases()
        tag = 'musl-apk-repo-10.0.403-alpine324-x64-r1'
        files = {'sdk.apk':path}
        first = M.publish_release(api, tag, 'a'*40, 'Fixture repository', 'Immutable fixture', files)
        self.assertFalse(first['draft'])
        self.assertEqual('false', api.posts[0]['make_latest'])
        self.assertEqual(['sdk.apk'], api.uploads)
        M.publish_release(api, tag, 'a'*40, 'Fixture repository', 'Immutable fixture', files)
        self.assertEqual(1, api.publish_count)
        path.write_bytes(b'different bytes')
        with self.assertRaisesRegex(ValueError, 'replace an immutable'):
            M.publish_release(api, tag, 'a'*40, 'Fixture repository', 'Immutable fixture', files)
        api.tag_commit = 'b'*40
        with self.assertRaisesRegex(ValueError, 'tag ref points to another commit'):
            M.publish_release(api, tag, 'a'*40, 'Fixture repository', 'Immutable fixture', files)


if __name__ == '__main__':
    unittest.main()
