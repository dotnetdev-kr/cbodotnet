"""Require authenticated receipts and both native public verifiers before advertising channels."""
import base64
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import distribution_status as STATUS
from downstream_release import load_status, PREPUBLICATION_CHECKS, encoded


class DistributionStatusTests(unittest.TestCase):
    def setUp(self):
        self.policy = copy.deepcopy(load_status())
        for name, channel in self.policy['channels'].items():
            channel.update(status='deferred' if name in {'rpm', 'aur'} else 'not-published', publications=[], receipts=[])
        self.index = dict(schemaVersion=1, repository='ghcr.io/dotnetdev-kr/cbodotnet-sdk',
                          tag='10.0.403-debian13-r1', digest='sha256:' + 'a' * 64,
                          platforms=[dict(os='linux', architecture=arch, digest='sha256:' + 'b' * 64,
                                          configDigest='sha256:' + 'c' * 64) for arch in ('amd64', 'arm64')])
        self.receipts = []
        for channel in ('deb', 'oci'):
            identity = dict(channel=channel, sdkVersion='10.0.403', packageRevision=1,
                            sourceReleaseTag='sdk-10.0.403', sourceManifestSha256='d' * 64)
            self.receipts.append(dict(schemaVersion=1, repository=STATUS.REPOSITORY, status='published-postverified',
                identity=identity, tag=STATUS.release_tag(channel, '10.0.403', 1), manifestSha256='e' * 64,
                assets=[dict(name='apt-' + variant + '.tar.gz', size=123, sha256='f' * 64)
                        for variant in ('ubuntu-24.04', 'debian-13')],
                publications=[dict(channel=channel, sdkVersion='10.0.403', packageRevision=1,
                    variant=row['variant'], architecture=row['architecture']) for row in self.policy['channels'][channel]['candidateMatrix']]))
        checks = {name: 'passed' for name in PREPUBLICATION_CHECKS | set(self.policy['channels']['deb']['requiredChecks'])}
        checks['upgrade'] = 'verified-before-publication'
        self.reports = [dict(schemaVersion=1, status='passed', architecture=arch,
            repository=self.index['repository'], digest=self.index['digest'], checks=sorted(STATUS.POST_CHECKS),
            aptTargets=[dict(variant=variant, architecture=arch, status='passed', repositorySha256='f' * 64,
                             checks=copy.deepcopy(checks)) for variant in ('ubuntu-24.04', 'debian-13')]) for arch in ('x64', 'aarch64')]
        self.proof = dict(runId='123', runAttempt='1', commit='1' * 40,
                          url=f'https://github.com/{STATUS.REPOSITORY}/actions/runs/123/attempts/1')

    def verify(self, policy, output, public_key):
        return {'channels': {'oci': {'image': copy.deepcopy(self.index)}}}

    def activate(self, receipts=None, reports=None, index=None, policy=None, verifier=None):
        return STATUS.activate_status(policy if policy is not None else self.policy,
            receipts if receipts is not None else self.receipts, reports if reports is not None else self.reports,
            index if index is not None else self.index, self.proof, verifier=verifier or self.verify)

    def test_success_preserves_deferred_channels_and_persists_public_native_proof(self):
        result = self.activate()
        self.assertEqual('published', result['channels']['deb']['status'])
        self.assertEqual('published', result['channels']['oci']['status'])
        self.assertEqual('deferred', result['channels']['rpm']['status'])
        self.assertEqual([], result['channels']['aur']['publications'])
        evidence = result['channels']['deb']['receipts'][0]['postVerification']
        self.assertEqual(self.proof, evidence['workflow'])
        self.assertEqual(2, len(evidence['reports']))
        self.assertEqual('not-published', self.policy['channels']['deb']['status'])

    def test_matching_retry_is_idempotent_and_history_retains_older_revision(self):
        first = self.activate()
        self.assertEqual(first, self.activate(policy=first))
        newer = copy.deepcopy(self.receipts)
        for receipt in newer:
            receipt['identity']['packageRevision'] = 2
            receipt['tag'] = STATUS.release_tag(receipt['identity']['channel'], '10.0.403', 2)
            for publication in receipt['publications']:
                publication['packageRevision'] = 2
        self.index['tag'] = '10.0.403-debian13-r2'
        second = self.activate(receipts=newer, policy=first)
        self.assertEqual([1, 2], [row['identity']['packageRevision'] for row in second['channels']['deb']['receipts']])
        self.assertEqual(8, len(second['channels']['deb']['publications']))

    def test_same_immutable_identity_with_different_receipt_is_rejected(self):
        first = self.activate()
        altered = copy.deepcopy(self.receipts)
        altered[0]['manifestSha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'Conflicting receipt'):
            self.activate(receipts=altered, policy=first)

    def test_missing_duplicate_failed_or_wrong_digest_native_reports_are_rejected(self):
        for change in (lambda value: value.pop(), lambda value: value.append(copy.deepcopy(value[0])),
                       lambda value: value[0].update(status='failed'),
                       lambda value: value[0].update(digest='sha256:' + '0' * 64)):
            reports = copy.deepcopy(self.reports)
            change(reports)
            with self.assertRaises(ValueError):
                self.activate(reports=reports)

    def test_apt_targets_must_match_native_archives_and_all_runtime_checks(self):
        mutations = [lambda report: report['aptTargets'].pop(),
                     lambda report: report['aptTargets'][0].update(architecture='other'),
                     lambda report: report['aptTargets'][0].update(repositorySha256='0' * 64),
                     lambda report: report['aptTargets'][0]['checks'].update(**{'cli-branding': 'failed'}),
                     lambda report: report['aptTargets'][0]['checks'].update(upgrade='untested')]
        for change in mutations:
            reports = copy.deepcopy(self.reports)
            change(reports[0])
            with self.assertRaises(ValueError):
                self.activate(reports=reports)

    def test_authentication_or_signed_index_mismatch_blocks_status_activation(self):
        with self.assertRaisesRegex(ValueError, 'signature'):
            self.activate(verifier=mock.Mock(side_effect=ValueError('signature rejected')))
        with self.assertRaisesRegex(ValueError, 'authenticated signed'):
            self.activate(verifier=mock.Mock(return_value={'channels': {'oci': {'image': {'digest': 'wrong'}}}}))

    def test_receipt_channel_versions_cannot_be_mixed_or_duplicated(self):
        for receipts in (self.receipts + self.receipts[:1], copy.deepcopy(self.receipts)):
            if len(receipts) == 2:
                receipts[1]['identity']['packageRevision'] = 2
                receipts[1]['tag'] = STATUS.release_tag('oci', '10.0.403', 2)
            with self.assertRaises(ValueError):
                self.activate(receipts=receipts)

    def test_one_channel_can_activate_without_advertising_an_unfinished_other_channel(self):
        result = self.activate(receipts=self.receipts[:1])
        self.assertEqual('published', result['channels']['deb']['status'])
        self.assertEqual('not-published', result['channels']['oci']['status'])

    def metadata_v2(self):
        for platform in self.index['platforms']:
            platform.update(metadataPolicyVersion=2, sdkRoot='/opt/cbodotnet/10.0', labels={
                'org.opencontainers.image.licenses': 'MIT AND LicenseRef-Dotnet-ThirdPartyNotices',
                'kr.dotnetdev.cbodotnet.sdk.sha256': 'f' * 64})
        for report in self.reports:
            platform = next(row for row in self.index['platforms']
                            if row['architecture'] == {'x64': 'amd64', 'aarch64': 'arm64'}[report['architecture']])
            report.update(checks=sorted(STATUS.POST_CHECKS_V2),
                networkForBuild='none', functionalChecks={name: 'passed' for name in STATUS.OCI_FUNCTIONAL_CHECKS},
                imageConfig=dict(architecture=platform['architecture'], user='app', workdir='/work',
                                 sdkRoot=platform['sdkRoot'], labels=copy.deepcopy(platform['labels'])),
                imageFiles=dict(ownership='root:root:0755', sourceBuildToolchain='absent', credentialEnvironment='absent'))

    def test_oci_only_metadata_revision_requires_complete_signed_public_proof_and_preserves_apt(self):
        self.metadata_v2()
        result = self.activate(receipts=self.receipts[1:])
        self.assertEqual('published', result['channels']['oci']['status'])
        self.assertEqual(self.policy['channels']['deb'], result['channels']['deb'])
        for mutate in (lambda report: report['checks'].remove('sdk-list-paths'),
                       lambda report: report['checks'].remove('http-crypto-globalization'),
                       lambda report: report['functionalChecks'].update(rsaSha256SignAndVerify='failed'),
                       lambda report: report.update(networkForBuild='enabled'),
                       lambda report: report['imageConfig']['labels'].update(**{'kr.dotnetdev.cbodotnet.sdk.sha256': '0' * 64}),
                       lambda report: report['imageConfig'].update(user='0'),
                       lambda report: report['imageFiles'].update(sourceBuildToolchain='present')):
            reports = copy.deepcopy(self.reports)
            mutate(reports[0])
            with self.subTest(mutation=mutate), self.assertRaisesRegex(ValueError, 'OCI public metadata'):
                self.activate(receipts=self.receipts[1:], reports=reports)

    def test_oci_metadata_policy_cannot_be_downgraded_on_one_platform(self):
        self.metadata_v2()
        del self.index['platforms'][0]['metadataPolicyVersion']
        with self.assertRaisesRegex(ValueError, 'mixed or silently downgraded'):
            self.activate(receipts=self.receipts[1:])

    def test_new_oci_revision_cannot_downgrade_both_platforms_to_legacy_metadata(self):
        self.receipts[1]['identity']['packageRevision'] = 2
        self.receipts[1]['tag'] = STATUS.release_tag('oci', '10.0.403', 2)
        self.index['tag'] = '10.0.403-debian13-r2'
        with self.assertRaisesRegex(ValueError, 'complete metadata policy 2'):
            self.activate(receipts=self.receipts[1:])

    def fake_api(self, fail_update=False, bad_job=False):
        class API:
            def __init__(inner):
                inner.calls = []

            def api(inner, endpoint, method='GET', body=None):
                inner.calls.append((endpoint, method, copy.deepcopy(body)))
                if '/actions/runs/' in endpoint and '/jobs?' not in endpoint:
                    return dict(repository=dict(full_name=STATUS.REPOSITORY), head_repository=dict(full_name=STATUS.REPOSITORY),
                                head_branch='main', event='workflow_dispatch', path='.github/workflows/distribution-release.yml', head_sha='1' * 40)
                if '/jobs?' in endpoint:
                    names = ['Sign, promote and post-verify immutable distributions',
                             'Anonymous digest pull and non-root smoke on x64', 'Anonymous digest pull and non-root smoke on aarch64']
                    return {'jobs': [dict(name=name, conclusion='failure' if bad_job and 'x64' in name else 'success') for name in names]}
                if method == 'GET':
                    return dict(type='file', path=STATUS.STATUS_PATH, encoding='base64', sha='2' * 40,
                                content=base64.b64encode(encoded(self.policy)).decode())
                if method == 'PUT':
                    if fail_update:
                        raise ValueError('Concurrent status change; expected SHA does not match')
                    return {'commit': {'sha': '3' * 40}}
                return None
        return API()

    def test_remote_status_write_uses_observed_sha_lease_then_dispatches_pages(self):
        api = self.fake_api()
        result = STATUS.update_repository_status(self.receipts, self.reports, self.index, '123', '1', api=api, verifier=self.verify)
        puts = [row for row in api.calls if row[1] == 'PUT']
        self.assertEqual(1, len(puts))
        self.assertEqual('2' * 40, puts[0][2]['sha'])
        self.assertEqual('main', puts[0][2]['branch'])
        self.assertEqual('published', json.loads(base64.b64decode(puts[0][2]['content']))['channels']['deb']['status'])
        self.assertTrue(api.calls[-1][0].endswith('/pages.yml/dispatches'))
        self.assertTrue(result['pagesDispatched'])

    def test_failed_post_job_or_concurrent_status_change_never_dispatches_pages(self):
        for api in (self.fake_api(bad_job=True), self.fake_api(fail_update=True)):
            with self.assertRaises(ValueError):
                STATUS.update_repository_status(self.receipts, self.reports, self.index, '123', '1', api=api, verifier=self.verify)
            self.assertFalse(any('/pages.yml/dispatches' in row[0] for row in api.calls))


class RpmStatusTests(unittest.TestCase):
    def setUp(self):
        self.policy = copy.deepcopy(load_status())
        # Exercise first RPM activation independently of the live immutable
        # publication ledger, while retaining the existing APT/OCI channels.
        self.policy['channels']['rpm'].update(status='not-published', publications=[], receipts=[])
        identity = dict(channel='rpm', sdkVersion='10.0.403', packageRevision=1,
                        sourceReleaseTag='sdk-10.0.403', sourceManifestSha256='d' * 64)
        self.receipt = dict(schemaVersion=1, repository=STATUS.REPOSITORY, status='published-postverified',
            identity=identity, tag=STATUS.release_tag('rpm', '10.0.403', 1), manifestSha256='e' * 64,
            assets=[dict(name='rpm-' + variant + '.tar.gz', size=123, sha256='f' * 64)
                    for variant in ('fedora-45', 'rocky-9.8')],
            publications=[dict(channel='rpm', sdkVersion='10.0.403', packageRevision=1,
                variant=row['variant'], architecture=row['architecture']) for row in self.policy['channels']['rpm']['candidateMatrix']])
        checks = {name: 'passed' for name in PREPUBLICATION_CHECKS | set(self.policy['channels']['rpm']['requiredChecks'])}
        checks['upgrade'] = 'verified-before-publication'
        self.reports = [dict(schemaVersion=1, status='passed', architecture=arch,
            rpmTargets=[dict(variant=variant, architecture=arch, status='passed', repositorySha256='f' * 64,
                             checks=copy.deepcopy(checks)) for variant in ('fedora-45', 'rocky-9.8')]) for arch in ('x64', 'aarch64')]

    def activate(self, reports=None):
        return STATUS.activate_status(self.policy, [self.receipt], reports if reports is not None else self.reports,
                                      verifier=mock.Mock(return_value={'channels': {'rpm': {}}}))

    def test_rpm_activation_preserves_already_published_apt_oci_and_unpublished_aur(self):
        result = self.activate()
        self.assertEqual('published', result['channels']['rpm']['status'])
        self.assertEqual(self.policy['channels']['deb'], result['channels']['deb'])
        self.assertEqual(self.policy['channels']['oci'], result['channels']['oci'])
        self.assertEqual('not-published', result['channels']['aur']['status'])

    def test_every_public_rpm_distro_signature_architecture_and_digest_is_required(self):
        mutations = [lambda report: report['rpmTargets'].pop(),
                     lambda report: report['rpmTargets'][0].update(architecture='aarch64'),
                     lambda report: report['rpmTargets'][0].update(repositorySha256='0' * 64),
                     lambda report: report['rpmTargets'][0]['checks'].update(**{'package-signatures': 'failed'}),
                     lambda report: report['rpmTargets'][0]['checks'].update(**{'repository-metadata': 'missing'}),
                     lambda report: report['rpmTargets'][0]['checks'].update(upgrade='not-tested')]
        for change in mutations:
            reports = copy.deepcopy(self.reports)
            change(reports[0])
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.activate(reports)

    def test_missing_or_duplicate_native_rpm_worker_cannot_activate(self):
        for reports in (self.reports[:1], [self.reports[0], self.reports[0]]):
            with self.assertRaises(ValueError):
                self.activate(reports)

    def test_rpm_status_requires_its_own_trusted_successful_jobs(self):
        metadata = dict(repository=dict(full_name=STATUS.REPOSITORY), head_repository=dict(full_name=STATUS.REPOSITORY),
                        head_branch='main', event='workflow_dispatch', path='.github/workflows/distribution-release.yml', head_sha='1' * 40)
        names = ['Sign and publish RPM distributions', 'Verify public RPM repositories on native x64',
                 'Verify public RPM repositories on native aarch64']
        api = mock.Mock()
        api.api.side_effect = [metadata, {'jobs': [dict(name=name, conclusion='success') for name in names]}]
        self.assertEqual('123', STATUS.validate_workflow_run(api, '123', '1', ['rpm'])['runId'])
        for jobs in ([], [dict(name=name, conclusion='failure' if 'x64' in name else 'success') for name in names]):
            api.api.side_effect = [metadata, {'jobs': jobs}]
            with self.assertRaises(ValueError):
                STATUS.validate_workflow_run(api, '123', '1', ['rpm'])


if __name__ == '__main__':
    unittest.main()
