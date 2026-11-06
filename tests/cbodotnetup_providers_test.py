import copy
import hashlib
import io
from pathlib import Path, PurePosixPath
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import cbodotnetup_providers as P


class ProviderAdmissionTests(unittest.TestCase):
    def inputs(self):
        policy = P.load_policy(); sdks = []
        for version, source in policy['sdkSources'].items():
            for rid, arch in P.ARCHITECTURES.items():
                sdks.append(dict(sdkVersion=version, revision=2, rid=rid,
                    archive=copy.deepcopy(source['archives'][rid]), archiveRoot=f'cbodotnet-{version}-linux-{arch}-r2',
                    sourceManifestSha256=source['sourceManifestSha256'], requiresLegacyProvider=True,
                    targets=[dict(os=v.rsplit('-', 1)[0], versionId=v.rsplit('-', 1)[1], rid=rid) for v in P.VARIANTS]))
        sdks.append(dict(sdkVersion='10.0.403', revision=3, rid='linux-x64', requiresLegacyProvider=False))
        bindings = P._bindings(sdks, policy)
        needed = {identity for binding in bindings for identity in binding['providerIds']}
        providers = [P._provider_record(*identity.rsplit('-r1/', 1), sdks, policy) for identity in sorted(needed)]
        return dict(schemaVersion=3, sdks=sdks, providers=providers, providerBindings=bindings,
                    channels={'10.0': '10.0.403-r3', '5.0': '5.0.214-r2', '3.1': '3.1.426-r2', '3.0': '3.0.103-r2'}), policy

    def test_all_six_legacy_sdk_records_share_only_four_exact_provider_identities(self):
        catalog, policy = self.inputs()
        self.assertEqual(P.validate_provider_catalog(catalog, policy=policy), 4)
        self.assertEqual(len(catalog['providerBindings']), 6)
        self.assertTrue(all(not row['sdkId'].startswith('10.') for row in catalog['providerBindings']))
        self.assertEqual(sum(len(p['targets']) for p in catalog['providers']), 16)

    def test_offline_validation_never_downloads_or_reauthenticates_a_source(self):
        catalog, policy = self.inputs()
        with patch.object(P, 'get_bytes', side_effect=AssertionError('Network forbidden')), \
                patch.object(P, '_authenticated_source', side_effect=AssertionError('Network forbidden')):
            self.assertEqual(P.validate_provider_catalog(catalog, policy=policy), 4)

    def test_modern_only_catalog_needs_no_companion_or_binding(self):
        catalog, policy = self.inputs(); sdks = catalog['sdks'][-1:]
        with patch.object(P, '_authenticated_source') as authenticate, patch.object(P, '_obtain') as obtain:
            self.assertEqual(P.catalog_provider_metadata(sdks, policy=policy), ([], []))
        authenticate.assert_not_called(); obtain.assert_not_called()

    def test_policy_cannot_substitute_provider_abi_source_asset_or_consent(self):
        mutations = [lambda value: value.update(libc='musl'),
            lambda value: value.update(consentOption='automatic'),
            lambda value: value['maintenance'].update(preinstalledProvidersAccepted=True),
            lambda value: value['providers']['rocky9-20261104'].update(minimumGlibc='2.17'),
            lambda value: value['providers']['rocky9-20261104']['architectures']['linux-x64'].update(cpuFlags=[]),
            lambda value: value['providers']['rocky8-curl-20261104']['sourceSignature'].update(sha256='0'*64)]
        for mutate in mutations:
            value = P.load_policy(); mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): P.validate_policy(value)

    def test_provider_metadata_cannot_substitute_vendor_library_license_or_signature(self):
        mutations = [lambda row: row['archive'].update(sha256='0'*64),
            lambda row: row.update(libc='musl'), lambda row: row.update(minimumGlibc='2.17'),
            lambda row: row.update(manifestSha256='0'*64),
            lambda row: row['sourceManifest'].update(url='https://github.com/other/project/releases/download/x/manifest.json'),
            lambda row: row['manifest']['packages'][0]['files'][0].update(sha256='0'*64),
            lambda row: row['manifest']['files'][0].update(sha256='0'*64),
            lambda row: row['manifest']['sourcePackages'][0].update(sha256='0'*64),
            lambda row: row['manifest'].update(signingFingerprint='0'*40)]
        for mutate in mutations:
            catalog, policy = self.inputs(); row = next(p for p in catalog['providers'] if p['providerId'] == 'rocky9-20261104')
            mutate(row)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): P.validate_provider_catalog(catalog, policy=policy)

    def test_binding_cannot_omit_curl_duplicate_a_sdk_or_change_its_source(self):
        mutations = [lambda rows: rows.pop(), lambda rows: rows.append(copy.deepcopy(rows[0])),
            lambda rows: rows[0].update(providerIds=[]), lambda rows: rows[0].update(archiveSha256='0'*64),
            lambda rows: rows[0].update(sourceManifestSha256='0'*64)]
        for mutate in mutations:
            catalog, policy = self.inputs(); mutate(catalog['providerBindings'])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): P.validate_provider_catalog(catalog, policy=policy)

    def test_missing_or_extra_provider_does_not_form_a_valid_admission(self):
        for extra in (False, True):
            catalog, policy = self.inputs()
            if extra: catalog['providers'].append(copy.deepcopy(catalog['providers'][0]))
            else: catalog['providers'].pop()
            with self.subTest(extra=extra), self.assertRaises(ValueError): P.validate_provider_catalog(catalog, policy=policy)

    def test_provider_targets_cannot_escape_the_sdk_os_cpu_cells(self):
        for target in [dict(os='alpine', versionId='3.24', rid='linux-x64'),
                       dict(os='ubuntu', versionId='24.04', rid='linux-arm64')]:
            catalog, policy = self.inputs(); catalog['sdks'][0]['targets'][0] = target
            with self.subTest(target=target), self.assertRaises(ValueError): P.validate_provider_catalog(catalog, policy=policy)

    def test_shared_base_survives_one_sdk_removal_and_unreferenced_curl_is_not_advertised(self):
        catalog, policy = self.inputs(); sdks = [sdk for sdk in catalog['sdks'] if not sdk['sdkVersion'].startswith('3.')]
        bindings = P._bindings(sdks, policy)
        needed = {identity for row in bindings for identity in row['providerIds']}
        providers = [P._provider_record(*identity.rsplit('-r1/', 1), sdks, policy) for identity in sorted(needed)]
        catalog.update(sdks=sdks, providerBindings=bindings, providers=providers)
        self.assertEqual(P.validate_provider_catalog(catalog, policy=policy), 2)
        self.assertTrue(all(row['providerId'] == 'rocky9-20261104' for row in providers))

    def test_schema2_projection_has_only_modern_sdks_and_no_new_members(self):
        catalog, policy = self.inputs()
        catalog['compatibilityCatalog'] = dict(url='https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-catalog-123/catalog-v2.json',
                                                size=123, sha256='a'*64)
        projected = {key: copy.deepcopy(value) for key, value in catalog.items()
                     if key not in {'providers', 'providerBindings', 'compatibilityCatalog'}}
        projected.update(schemaVersion=2, sdks=catalog['sdks'][-1:], channels={'10.0': '10.0.403-r3'})
        self.assertEqual(P.validate_provider_catalog(catalog, projected, policy=policy), 4)
        for mutate in [lambda value: value.update(providers=[]), lambda value: value.update(compatibilityCatalog=catalog['compatibilityCatalog']),
                       lambda value: value['sdks'].append(catalog['sdks'][0]),
                       lambda value: value['channels'].update({'5.0': '5.0.214-r2'})]:
            changed = copy.deepcopy(projected); mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError): P.validate_provider_catalog(catalog, changed, policy=policy)

    def test_reconstructed_manifest_retains_both_license_and_native_http_source_pins(self):
        base = P.expected_manifest('rocky9-20261104', 'linux-x64')
        curl = P.expected_manifest('rocky8-curl-20261104', 'linux-arm64')
        self.assertEqual(len(base['files']), 15); self.assertEqual(len(curl['files']), 5)
        self.assertEqual({row['path'] for row in base['files'] if row['path'].startswith('LICENSE.')},
                         {'LICENSE.openssl.txt', 'LICENSE.icu.txt'})
        self.assertEqual(curl['baseProvider']['providerId'], base['providerId'])
        self.assertEqual(set(curl['nativeHttpComponents']), {'3.0.103', '3.1.426'})


class CompanionSafetyTests(unittest.TestCase):
    ROOT = '/usr/lib/cbodotnet/compat/test-fixture'

    def archive(self, *, mutation=None, duplicate=False, extra=None, changed_manifest=False):
        body = b'unchanged fixture library'
        manifest = dict(files=[dict(path='lib', type='directory', mode='0o755'),
            dict(path='lib/libfixture.so.1.0', type='file', mode='0o755', size=len(body), sha256=hashlib.sha256(body).hexdigest()),
            dict(path='lib/libfixture.so.1', type='symlink', mode='0o777', target='libfixture.so.1.0')])
        raw_manifest = P.encoded(manifest); relative = 'rootfs' + self.ROOT
        rows = [('provider-manifest.json', tarfile.REGTYPE, 0o644, raw_manifest)]
        rows += [(name, tarfile.DIRTYPE, 0o755, b'') for name in
                 [str(path) for path in reversed(PurePosixPath(relative).parents) if str(path) != '.'] + [relative]]
        rows += [(relative+'/lib', tarfile.DIRTYPE, 0o755, b''),
                 (relative+'/lib/libfixture.so.1.0', tarfile.REGTYPE, 0o755, body),
                 (relative+'/lib/libfixture.so.1', tarfile.SYMTYPE, 0o777, b''),
                 (relative+'/provider-manifest.json', tarfile.REGTYPE, 0o644,
                  raw_manifest+b' ' if changed_manifest else raw_manifest)]
        if duplicate: rows.append(rows[-1])
        if extra is not None: rows.append((extra, tarfile.REGTYPE, 0o644, b'unexpected'))
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            for name, kind, mode, content in rows:
                member = tarfile.TarInfo(name); member.type=kind; member.mode=mode; member.uid=member.gid=0
                if kind == tarfile.SYMTYPE: member.linkname='libfixture.so.1.0'
                if kind == tarfile.REGTYPE: member.size=len(content)
                if mutation is not None: mutation(member)
                archive.addfile(member, io.BytesIO(content) if member.isfile() else None)
        return output.getvalue(), manifest

    def test_exact_separate_rootfs_and_matching_manifests_are_accepted_without_extraction(self):
        raw, manifest = self.archive()
        self.assertEqual(P.validate_companion(raw, manifest, self.ROOT), hashlib.sha256(P.encoded(manifest)).hexdigest())

    def test_duplicate_extra_escape_and_mismatched_manifests_are_rejected(self):
        options = [dict(duplicate=True), dict(extra='../outside'), dict(extra='rootfs/etc/openssl.cnf'), dict(changed_manifest=True)]
        for option in options:
            raw, manifest = self.archive(**option)
            with self.subTest(option=option), self.assertRaises(ValueError): P.validate_companion(raw, manifest, self.ROOT)

    def test_wrong_ownership_modes_hardlinks_and_symlink_targets_are_rejected(self):
        mutations = [lambda member: setattr(member, 'uid', 1),
            lambda member: setattr(member, 'mode', 0o777) if member.isfile() else None,
            lambda member: setattr(member, 'linkname', '../../outside') if member.issym() else None,
            lambda member: setattr(member, 'type', tarfile.LNKTYPE) if member.issym() else None]
        for mutation in mutations:
            raw, manifest = self.archive(mutation=mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): P.validate_companion(raw, manifest, self.ROOT)

    def test_modified_download_and_cache_fail_before_becoming_source_inputs(self):
        correct = b'pinned companion bytes'
        asset = dict(url='https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-5.0.214-r2/fixture.tar.gz',
                     size=len(correct), sha256=hashlib.sha256(correct).hexdigest())
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(P, 'get_bytes', return_value=b'tampered bytes'):
                with self.assertRaisesRegex(ValueError, 'download differs'): P._obtain(asset, directory)
            self.assertEqual(list(directory.iterdir()), [])
            with patch.object(P, 'get_bytes', return_value=correct) as download:
                self.assertEqual(P._obtain(asset, directory), correct)
                self.assertEqual(P._obtain(asset, directory), correct)
                self.assertEqual(download.call_count, 1)
            next(directory.iterdir()).write_bytes(b'tampered cache')
            with patch.object(P, 'get_bytes', side_effect=AssertionError('Must not overwrite retained cache')):
                with self.assertRaisesRegex(ValueError, 'cache bytes differ'): P._obtain(asset, directory)


if __name__ == '__main__':
    unittest.main()
