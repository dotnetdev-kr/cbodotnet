"""Exercise the submitted AUR source verifier and recipe-only transport boundary."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import aur_delivery as AUR
import distribution_contract as CONTRACT
from release_catalog_test import fixture

SPEC = importlib.util.spec_from_file_location('aur_ci', ROOT / 'scripts/aur-ci.py')
CI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI)


class AurRecipeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        release, manifest, manifest_bytes, checksums = fixture()
        contract = copy.deepcopy(CONTRACT.load_contract())
        contract['releases']['10.0.403']['manifestSha256'] = hashlib.sha256(manifest_bytes).hexdigest()
        catalog = {'schemaVersion': 1, 'repository': 'dotnetdev-kr/cbodotnet', 'builds': [
            {'target': 'net10', 'sdkVersion': '10.0.403', 'architectures': {
                arch: {key: row['provenance'][key] for key in ('projectCommit', 'runId', 'runAttempt', 'artifactId')}
                for arch, row in manifest['architectures'].items()}}]}
        sdk = self.directory / manifest['architectures']['x64']['sdk']['name']
        sdk.write_bytes(b'sdkx64')
        self.plan = CONTRACT.verified_plan(release, manifest_bytes, checksums, sdk, 'aur', 'arch-rolling', 'x64',
            contract=contract, catalog=catalog)
        self.plan['checksums'] = manifest['checksums']

    def recipes(self):
        output = self.directory / 'recipes'
        sources = AUR.write_sources(self.plan, output)
        return output, sources

    def test_recipe_owns_isolated_host_and_sdk_and_preserves_qualified_payload(self):
        _, sources = self.recipes()
        sdk = (sources['sdk'] / 'PKGBUILD').read_text()
        host = (sources['host'] / 'PKGBUILD').read_text()
        self.assertIn('pkgname=cbodotnet-sdk-10.0-bin', sdk)
        self.assertIn("arch=('x86_64')", sdk)
        for option in ('!strip', '!debug', '!lto', '!purge', 'staticlibs', 'libtool', 'docs'):
            self.assertIn("'" + option + "'", sdk)
        self.assertNotIn('SKIP', sdk + host)
        self.assertNotIn('/usr/bin/dotnet', sdk + host)
        self.assertIn('cp -a --no-preserve=ownership', sdk)
        self.assertIn('cbodotnet-host>=1.0.0', sdk)
        self.assertIn('ThirdPartyNotices.txt', sdk)
        self.assertNotIn('sdk-', host)

    def test_additional_sdk_recipe_preserves_its_existing_metadata_directory(self):
        self.plan['additionalDirectories'] = []
        _, sources = self.recipes()
        sdk = (sources['sdk'] / 'PKGBUILD').read_text()
        self.assertNotIn('install -dm755 "$pkgdir/opt/cbodotnet/10.0/metadata"', sdk)
        self.assertIn('cp -a --no-preserve=ownership', sdk)

    def test_legacy_recipe_requires_explicit_provider(self):
        self.plan['sdkVersion'] = '3.1.426'
        self.plan['package'].update(name='cbodotnet-sdk-3.1', root='/opt/cbodotnet/3.1',
                                    launcher='/usr/bin/cbodotnet-3.1', aurName='cbodotnet-sdk-3.1-bin')
        with self.assertRaisesRegex(ValueError, 'explicit authenticated'):
            self.recipes()

    def test_package_integrity_requires_all_summaries_and_rejects_ten_altered_files(self):
        good = 'first: 200 total files, 0 altered files\nsecond: 10 total files, 0 altered files\n'
        CI.verify_package_integrity(good, 2)
        for output in [good.replace('0 altered', '10 altered', 1), good.splitlines()[0], '',
                       good.replace('0 altered', '1 altered', 1)]:
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, 'integrity'):
                CI.verify_package_integrity(output, 2)

    def test_both_actual_srcinfo_files_are_required_and_sdk_cache_is_never_submitted(self):
        output, sources = self.recipes()
        with self.assertRaisesRegex(ValueError, '.SRCINFO'):
            AUR.recipe_archive(output, self.directory / 'missing.tar.gz')
        for source in sources.values():
            (source / '.SRCINFO').write_text('pkgbase = ' + source.name + '\npkgname = ' + source.name + '\n')
            (source / 'cached-sdk.tar.gz').write_bytes(b'not a source submission')
            (source / 'package.pkg.tar.zst').write_bytes(b'not a source submission')
            (source / 'src').mkdir()
            (source / 'src/secret').write_bytes(b'not submitted')
        first = self.directory / 'first.tar.gz'
        second = self.directory / 'second.tar.gz'
        AUR.recipe_archive(output, first)
        AUR.recipe_archive(output, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with tarfile.open(first) as archive:
            names = archive.getnames()
        self.assertIn('cbodotnet-sdk-10.0-bin/.SRCINFO', names)
        self.assertIn('cbodotnet-host/.SRCINFO', names)
        self.assertFalse(any('cached' in name or 'secret' in name or '.pkg.tar' in name for name in names))

    def test_weekly_report_identifies_actual_weekly_workflow(self):
        with mock.patch.dict(os.environ, GITHUB_WORKFLOW_REF='dotnetdev-kr/cbodotnet/.github/workflows/aur-runtime-check.yml@refs/heads/main',
                GITHUB_SHA='a' * 40, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1'):
            self.assertEqual('.github/workflows/aur-runtime-check.yml', CI.workflow_identity()['workflow'])
        with mock.patch.dict(os.environ, GITHUB_WORKFLOW_REF='another/repo/.github/workflows/aur-runtime-check.yml@main'):
            with self.assertRaisesRegex(ValueError, 'actual GitHub'):
                CI.workflow_identity()

    def test_only_exact_sdk_opt_layout_lint_is_reviewed_and_never_hides_dependency_errors(self):
        expected = "cbodotnet-sdk-10.0-bin E: ELF files outside of a valid path ('opt/')."
        self.assertEqual('elfpaths', AUR.review_namcap(expected, 'cbodotnet-sdk-10.0-bin', True)[0]['rule'])
        for package, binary, output in [('cbodotnet-host', True, expected), ('cbodotnet-sdk-10.0-bin', False, expected),
                ('cbodotnet-sdk-10.0-bin', True, expected + '\ncbodotnet-sdk-10.0-bin E: Missing dependency libicu'),
                ('cbodotnet-sdk-10.0-bin', True, expected.replace("'opt/'", "'usr/share/'"))]:
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, 'Unreviewed namcap'):
                AUR.review_namcap(output, package, binary)

    def test_native_validation_rejects_stale_tracked_recipe_or_srcinfo(self):
        recipes, sources = self.recipes()
        tracked = self.directory / 'tracked'
        import shutil
        shutil.copytree(recipes, tracked)
        AUR.verify_tracked_sources(recipes, tracked)
        for source in sources.values():
            (source / '.SRCINFO').write_text('actual makepkg output')
            (tracked / source.name / '.SRCINFO').write_text('actual makepkg output')
        AUR.verify_tracked_sources(recipes, tracked, srcinfo=True)
        (tracked / sources['sdk'].name / '.SRCINFO').write_text('stale metadata')
        with self.assertRaisesRegex(ValueError, 'differs from reviewed'):
            AUR.verify_tracked_sources(recipes, tracked, srcinfo=True)
        (tracked / sources['sdk'].name / 'PKGBUILD').write_text('unbuilt recipe edit')
        with self.assertRaisesRegex(ValueError, 'differs from reviewed'):
            AUR.verify_tracked_sources(recipes, tracked)


class SubmittedVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.archive = self.directory / 'cbodotnet-sdk-10.0.403-linux-x64.tar.gz'
        with tarfile.open(self.archive, 'w:gz') as archive:
            entry = tarfile.TarInfo('dotnet')
            entry.mode = 0o755
            entry.size = 3
            archive.addfile(entry, io.BytesIO(b'sdk'))
        self.verifier = self.directory / 'verify-source.py'
        self.verifier.write_text(AUR.source_verifier(), encoding='utf-8')
        self.pin()

    def pin(self):
        sdk = dict(name=self.archive.name, size=self.archive.stat().st_size, sha256=AUR.sha256(self.archive))
        row = dict(sdk=sdk, source=dict(name='source', size=1, sha256='a' * 64),
                   evidence=dict(name='evidence', size=1, sha256='b' * 64), provenance=dict(targetRid='linux-x64'))
        arm = dict(sdk=dict(name='arm-sdk', size=1, sha256='c' * 64), source=dict(name='arm-source', size=1, sha256='d' * 64),
                   evidence=dict(name='arm-evidence', size=1, sha256='e' * 64))
        checksum = ''.join(value[kind]['sha256'] + '  ' + value[kind]['name'] + '\n' for value in (row, arm) for kind in ('sdk', 'source', 'evidence'))
        (self.directory / 'SHA256SUMS').write_text(checksum, encoding='ascii')
        manifest = dict(schemaVersion=1, repository='dotnetdev-kr/cbodotnet', sdkVersion='10.0.403', tag='sdk-10.0.403',
            architectures=dict(x64=row, aarch64=arm), checksums=dict(size=len(checksum), sha256=AUR.sha256(self.directory / 'SHA256SUMS')))
        (self.directory / 'release-manifest.json').write_text(json.dumps(manifest))
        policy = dict(sdkVersion='10.0.403', sourceReleaseTag='sdk-10.0.403', sourceManifestSha256=AUR.sha256(self.directory / 'release-manifest.json'),
                      sdk=sdk, source=row['source'], evidence=row['evidence'], producer=row['provenance'])
        (self.directory / 'distribution.json').write_text(json.dumps(policy))

    def verify(self):
        return subprocess.run([sys.executable, self.verifier, '--policy', self.directory / 'distribution.json', '--manifest',
            self.directory / 'release-manifest.json', '--checksums', self.directory / 'SHA256SUMS', '--archive', self.archive,
            '--destination', self.directory / 'sdk'], capture_output=True, text=True)

    def test_standalone_verifier_preserves_executable_mode_and_rejects_mutated_cache(self):
        result = self.verify()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(b'sdk', (self.directory / 'sdk/dotnet').read_bytes())
        if os.name != 'nt':
            self.assertEqual(0o755, (self.directory / 'sdk/dotnet').stat().st_mode & 0o777)
        self.assertEqual(0, self.verify().returncode)
        (self.directory / 'sdk/dotnet').write_bytes(b'BAD')
        result = self.verify()
        self.assertNotEqual(0, result.returncode)
        self.assertIn('SDK source cache changed', result.stderr)

    def test_corrupt_source_is_rejected_before_extraction(self):
        self.archive.write_bytes(b'!' * self.archive.stat().st_size)
        result = self.verify()
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Qualified SDK archive changed', result.stderr)
        self.assertFalse((self.directory / 'sdk').exists())

    def test_even_correctly_pinned_archive_cannot_extract_parent_traversal(self):
        with tarfile.open(self.archive, 'w:gz') as archive:
            entry = tarfile.TarInfo('../escaped')
            entry.size = 1
            archive.addfile(entry, io.BytesIO(b'x'))
        self.pin()
        result = self.verify()
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Unsafe SDK archive member', result.stderr)
        self.assertFalse((self.directory / 'escaped').exists())


if __name__ == '__main__':
    unittest.main()
