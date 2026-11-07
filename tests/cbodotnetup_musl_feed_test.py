"""The default Alpine feed smoke must bootstrap the native ABI and cache."""
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import cbodotnetup_release as UP
import musl_archive as ARCHIVE


class HostedMuslFeedTests(unittest.TestCase):
    def exercise(self, *, arch='x64', libc='musl', missing_musl=False,
                 metadata_change=None, result_change=None):
        bootstrap = b'authenticated public bootstrap fixture\n'
        sequence = 877
        catalogs = {}
        for generation in (1, 2, 3, 4):
            value = dict(schemaVersion=generation, sequence=sequence,
                         sdks=[dict(sdkVersion=version) for version in (('10.0.403',) if generation in (1, 4) else ('10.0.403', '9.0.123'))])
            if generation == 4:
                value['libc'] = 'musl'
            catalogs['v' + str(generation)] = UP.encoded(value)
        status = dict(status='published-postverified', version='0.5.1', catalogSequence=sequence,
                      catalogSha256=hashlib.sha256(catalogs['v3']).hexdigest(),
                      compatibilityCatalogSha256=hashlib.sha256(catalogs['v2']).hexdigest(),
                      legacyCatalogSha256=hashlib.sha256(catalogs['v1']).hexdigest(),
                      muslCatalogSha256=hashlib.sha256(catalogs['v4']).hexdigest(),
                      catalogRelease=dict(assets=[dict(name='get-cbodotnetup.py', size=len(bootstrap), sha256=hashlib.sha256(bootstrap).hexdigest())]))
        if missing_musl:
            del status['muslCatalogSha256']
        if metadata_change:
            metadata_change(status, catalogs)
        calls = []
        requests = []
        verified = []
        real_load = UP.load
        def load(path):
            return status if Path(path) == UP.ROOT / 'releases/cbodotnetup-status.json' else real_load(path)
        def fetch(url, bound):
            requests.append((url, bound))
            if url.endswith('/get-cbodotnetup.py'):
                return bootstrap
            if url.endswith('.asc'):
                return b'public signature fixture'
            generation = re.search(r'/v([234])/catalog\.json$', url)
            return catalogs['v' + generation[1] if generation else 'v1']
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / 'feed'
            def run(arguments, **options):
                command = list(map(str, arguments))
                calls.append(command)
                if command[0] != 'docker':
                    return SimpleNamespace(stdout='', returncode=0)
                script = command[-1]
                active = 'v4' if libc == 'musl' else 'v3'
                cache = re.search(r"root=Path\('([^']+)'\)", script)
                self.assertIsNotNone(cache, 'Generated consumer must read its actual authenticated cache')
                expected_cache = '/home/cbot-feed/.local/share/' + ('cbodotnetup-musl/cache/v4' if libc == 'musl' else 'cbodotnetup/cache/v3')
                self.assertEqual(cache[1], expected_cache)
                if libc == 'musl':
                    self.assertEqual(command[-4], ARCHIVE.BASES[arch])
                    self.assertIn('test "$(cat /etc/alpine-release)" = 3.24.4', script)
                    self.assertIn('apk add --no-cache python3 ca-certificates gnupg gpgv coreutils', script)
                    self.assertIn('adduser -D -u 10001 cbot-feed', script)
                    self.assertNotRegex(script, r'apt-get|runuser|useradd|cbodotnetup/cache/')
                    self.assertIn("su -s /bin/sh cbot-feed -c 'python3 /feed/get-cbodotnetup.py'", script)
                    for suffix in ('--version', 'list --available', 'doctor'):
                        self.assertIn("su -s /bin/sh cbot-feed -c '/home/cbot-feed/.local/bin/cbodotnetup " + suffix + "'", script)
                else:
                    self.assertEqual(command[-4], UP.MULTI.BASES['ubuntu-24.04'][arch])
                    self.assertIn('apt-get install', script)
                    self.assertIn('runuser -u cbot-feed', script)
                    self.assertNotIn('cbodotnetup-musl/cache/', script)
                self.assertEqual(script.count('test ! -e /usr/bin/dotnet'), 2)
                value = json.loads(catalogs[active])
                result = dict(status='passed', catalogSha256=hashlib.sha256(catalogs[active]).hexdigest(),
                              sequence=value['sequence'], bootstrapWithoutSdk=True,
                              sdkVersions=sorted({sdk['sdkVersion'] for sdk in value['sdks']}))
                if result_change:
                    result_change(result, status)
                UP.save(workspace / 'result.json', result)
                return SimpleNamespace(stdout='', returncode=0)
            with patch.object(UP, 'load', side_effect=load), patch.object(UP, 'public_metadata', side_effect=fetch), \
                    patch.object(UP, 'run', side_effect=run), patch.object(UP, 'load_status', return_value={}), \
                    patch.object(UP, 'verify_report_signature', side_effect=lambda path, *args: verified.append(Path(path).name)):
                UP.feed_smoke(SimpleNamespace(arch=arch, libc=libc, workspace=workspace))
            return real_load(workspace / 'report.json'), calls, requests, verified

    def test_both_native_alpine_cpus_use_sdk_free_default_bootstrap_v4_cache_and_exact_hosted_bytes(self):
        for arch in ('x64', 'aarch64'):
            report, calls, requests, verified = self.exercise(arch=arch)
            self.assertEqual(report['libc'], 'musl')
            self.assertEqual(report['baseImage'], ARCHIVE.BASES[arch])
            self.assertEqual(report['catalogUrl'], 'https://dotnetdev.kr/cbodotnet/cbodotnetup/v4/catalog.json')
            self.assertEqual(report['catalogSha256'], report['muslCatalogSha256'])
            self.assertEqual(set(verified), {'catalog-v1.json', 'catalog-v2.json', 'catalog-v3.json', 'catalog-v4.json'})
            self.assertEqual(sum(command[0] == 'docker' for command in calls), 1)
            self.assertTrue(any(url.endswith('/v4/catalog.json.asc') for url, unused in requests))

    def test_glibc_default_hosted_bootstrap_keeps_its_original_native_images_and_cache(self):
        for arch in ('x64', 'aarch64'):
            report, unused, unused_requests, verified = self.exercise(arch=arch, libc='glibc')
            self.assertEqual(report['libc'], 'glibc')
            self.assertTrue(report['catalogUrl'].endswith('/v3/catalog.json'))
            self.assertEqual(len(verified), 4)

    def test_musl_cannot_claim_success_from_glibc_cache_wrong_sequence_or_missing_sdk(self):
        for mutate in (lambda result, status: result.update(catalogSha256=status['catalogSha256']),
                       lambda result, status: result.update(sequence=result['sequence'] - 1),
                       lambda result, status: result.update(sdkVersions=['9.0.123'])):
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.exercise(result_change=mutate)
        with self.assertRaisesRegex(ValueError, 'not publicly qualified'):
            self.exercise(missing_musl=True)

    def test_changed_public_v4_bytes_or_schema_sequence_cannot_use_activated_hash(self):
        def changed_bytes(status, catalogs):
            catalogs['v4'] += b' '
        with self.assertRaisesRegex(ValueError, 'activated signed bytes'):
            self.exercise(metadata_change=changed_bytes)
        for field, value in (('schemaVersion', 3), ('sequence', 876)):
            def changed_identity(status, catalogs):
                content = json.loads(catalogs['v4'])
                content[field] = value
                catalogs['v4'] = UP.encoded(content)
                status['muslCatalogSha256'] = hashlib.sha256(catalogs['v4']).hexdigest()
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'schema/sequence'):
                self.exercise(metadata_change=changed_identity)


if __name__ == '__main__':
    unittest.main()
