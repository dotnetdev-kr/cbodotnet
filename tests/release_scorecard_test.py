"""Scorecards must preserve verified identities and never infer failure."""
from pathlib import Path
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import release_scorecard as S


def catalog_release(version='10.0.403'):
    architectures = {}
    for architecture, rid in (('x64', 'linux-x64'), ('aarch64', 'linux-arm64')):
        architectures[architecture] = dict(provenance=dict(targetRid=rid, projectCommit='a' * 40),
            source=dict(url='https://example.invalid/' + architecture + '-source', sha256='b' * 64),
            evidence=dict(url='https://example.invalid/' + architecture + '-evidence', sha256='c' * 64))
    return dict(sdkVersion=version, architectures=architectures, releaseUrl='https://example.invalid/release',
        manifestUrl='https://example.invalid/manifest', checksumsUrl='https://example.invalid/checksums')


class ScorecardTests(unittest.TestCase):
    def setUp(self):
        self.catalog = dict(repository='dotnetdev-kr/cbodotnet', generatedAt='2026-11-10T00:00:00Z',
            releases=[catalog_release()])
        self.archives = [dict(sdkVersion='10.0.403', architecture='x64', userSpaces=['ubuntu-24.04'],
            archiveUrl='https://example.invalid/archive', manifestUrl='https://example.invalid/consumer-manifest',
            signatureUrl='https://example.invalid/consumer-signature', signingFingerprint='D' * 40)]
        self.policy = dict(channels={
            'deb': dict(status='published', candidateMatrix=[dict(architecture='x64', variant='ubuntu-24.04'),
                dict(architecture='aarch64', variant='ubuntu-24.04')]),
            'rpm': dict(status='failed', candidateMatrix=[dict(architecture='x64', variant='fedora-45')]),
            'aur': dict(status='not-published', candidateMatrix=[dict(architecture='x64', variant='arch-rolling')])})
        self.downstream = dict(channels={'deb': dict(publications=[dict(sdkVersion='10.0.403', channel='deb',
            variant='ubuntu-24.04', architecture='x64', status='published-postverified',
            artifactUrl='https://example.invalid/deb', manifestUrl='https://example.invalid/deb-manifest',
            signatureUrl='https://example.invalid/deb-signature', verificationReportUrl='https://example.invalid/deb-report',
            signingFingerprint='E' * 40, sourceManifestSha256='f' * 64)])})
        self.musl = dict(publications=[dict(identity=dict(sdkVersion='10.0.403', channel='archive',
            sourceManifestSha256='1' * 64), records=[dict(architecture=architecture)
            for architecture in ('x64', 'aarch64')], manifestUrl='https://example.invalid/musl-manifest',
            signatureUrl='https://example.invalid/musl-signature', signingFingerprint='2' * 40,
            verification=dict(manifestUrl='https://example.invalid/musl-verification'))])
        self.musl_qualification = dict(builds=[dict(sdkVersion='10.0.403', sourceReleaseTag='musl-sdk-10.0.403-r1',
            sourceManifestSha256='1' * 64)])

    def test_cells_separate_passed_pending_unsupported_and_explicit_failure(self):
        result = S.build(self.catalog, self.archives, self.policy, self.downstream, self.musl,
            self.musl_qualification)
        release = result['releases'][0]
        cells = {(cell['libc'], cell['channel'], cell['architecture'], cell['target']): cell
            for cell in release['cells']}
        self.assertEqual('passed', cells['glibc', 'archive', 'x64', 'ubuntu-24.04']['status'])
        self.assertEqual('pending', cells['glibc', 'archive', 'aarch64', 'native archive consumer']['status'])
        self.assertEqual('passed', cells['glibc', 'deb', 'x64', 'ubuntu-24.04']['status'])
        self.assertEqual('pending', cells['glibc', 'deb', 'aarch64', 'ubuntu-24.04']['status'])
        self.assertEqual('failed', cells['glibc', 'rpm', 'x64', 'fedora-45']['status'])
        self.assertEqual('passed', cells['musl', 'archive', 'aarch64', 'Alpine 3.24.4']['status'])
        self.assertEqual('pending', cells['musl', 'apk', 'x64', 'Alpine 3.24.4']['status'])
        self.assertIn(dict(libc='glibc', channel='aur', architecture='aarch64', target='arch-rolling',
            status='unsupported'), result['plannedCells'])
        self.assertEqual('b' * 64, release['glibcSourceIdentity']['x64']['sourceSha256'])
        self.assertEqual('1' * 64, release['muslSourceIdentity']['sourceManifestSha256'])

    def test_missing_records_are_not_promoted_to_passed_or_failed(self):
        self.downstream['channels']['deb']['publications'].clear()
        self.policy['channels']['rpm']['status'] = 'not-published'
        result = S.build(self.catalog, self.archives, self.policy, self.downstream, dict(publications=[]),
            dict(builds=[]))
        release = result['releases'][0]
        deb = [cell for cell in release['cells'] if cell['channel'] == 'deb']
        self.assertEqual({'pending'}, {cell['status'] for cell in deb})
        musl = [cell for cell in release['cells'] if cell['libc'] == 'musl']
        self.assertEqual({'unsupported'}, {cell['status'] for cell in musl})
        self.assertTrue(all(cell['status'] != 'failed' for cell in release['cells']))

    def test_render_escapes_values_and_links_all_evidence(self):
        result = S.build(self.catalog, self.archives, self.policy, self.downstream, self.musl,
            self.musl_qualification)
        markup = S.render(result)
        self.assertIn('href="https://example.invalid/deb-signature"', markup)
        self.assertIn('href="https://example.invalid/musl-verification"', markup)
        self.assertIn('class="score-status score-failed"', markup)
        self.assertIn('musl-sdk-10.0.403-r1', markup)
        self.assertIn('1' * 64, markup)
        self.assertIn('https://github.com/dotnetdev-kr/cbodotnet/blob/main/releases/cbodotnetup-status.json', markup)
        self.assertIn('SDK qualification is separate from cbodotnetup admission', markup)

    def test_publish_replaces_one_marker_and_writes_the_scorecard_feed(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / 'index.html').write_text('before ' + S.MARKER + ' after', encoding='utf-8')
            feeds = {'releases.json': self.catalog, 'archive-status.json': dict(archives=self.archives),
                'downstream-status.json': self.downstream, 'musl-status.json': self.musl}
            for name, value in feeds.items():
                (output / name).write_text(json.dumps(value), encoding='utf-8')
            result = S.publish(output)
            document = (output / 'index.html').read_text(encoding='utf-8')
            saved = json.loads((output / 'qualification-scorecard.json').read_text(encoding='utf-8'))
        self.assertEqual(result, saved)
        self.assertNotIn(S.MARKER, document)
        self.assertIn('id="qualification-scorecard"', document)

    def test_publish_rejects_missing_or_ambiguous_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            (output / 'index.html').write_text('no marker', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'exactly one scorecard marker'):
                S.publish(output)


if __name__ == '__main__':
    unittest.main()