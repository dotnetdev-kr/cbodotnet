"""Portable data-only Core3.1 policy and private bootstrap accounting checks."""
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import musl_legacy31_construction as construction


def fingerprint(raw):
    return {
        'bytes': len(raw),
        'sha256': hashlib.sha256(raw).hexdigest(),
        'sha512': hashlib.sha512(raw).hexdigest(),
    }


class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = construction.load_policy(
            SCRIPTS / 'musl-legacy31-construction-policy.json')

    def test_import_and_policy_are_from_the_exported_scripts_directory(self):
        self.assertEqual(
            Path(construction.__file__).resolve(),
            (SCRIPTS / 'musl_legacy31_construction.py').resolve())
        self.assertEqual(self.policy['sdkVersion'], '3.1.426')
        self.assertEqual(
            self.policy['status'], 'unregistered-incomplete-source-contract')

    def test_current_policy_reports_explicit_gaps_and_no_admission(self):
        result = construction.readiness(self.policy)
        self.assertEqual(result['status'],
                         'unregistered-incomplete-Core3.1-contract')
        self.assertTrue(result['unresolved'])
        for field in ('normalAdmissionAllowed', 'sourceAdmissionAllowed',
                      'releaseAdmissionAllowed'):
            self.assertIs(result[field], False)
        self.assertTrue(any(
            isinstance(row, dict) and row.get('scope') == 'bootstrap:x64'
            for row in result['unresolved']))

    def test_historical_reference_claims_cannot_promote_current_policy(self):
        policy = copy.deepcopy(self.policy)
        reference = policy['historicalReferenceEvidence']
        for field in ('normalAdmissionAllowed', 'sourceAdmissionAllowed',
                      'releaseAdmissionAllowed'):
            reference[field] = True
        reference['completeCorrespondingSourceClosure'] = True
        result = construction.readiness(policy)
        self.assertTrue(result['unresolved'])
        self.assertIs(result['normalAdmissionAllowed'], False)
        self.assertIs(result['sourceAdmissionAllowed'], False)
        self.assertIs(result['releaseAdmissionAllowed'], False)

    def test_a_reference_archive_descriptor_is_not_a_ready_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'reference.json'
            path.write_text(json.dumps(
                self.policy['historicalReferenceEvidence']['finalArchive']),
                encoding='utf-8')
            with self.assertRaisesRegex(construction.ValidationError,
                                        'own Core3.1 policy required'):
                construction.load_policy(path)

    def test_policy_cannot_enable_admission_or_relabel_another_sdk(self):
        for field in ('normalAdmissionEnabled', 'sourceAdmissionAllowed',
                      'releaseAdmissionAllowed'):
            with self.subTest(field=field):
                policy = copy.deepcopy(self.policy)
                policy[field] = True
                with self.assertRaisesRegex(construction.ValidationError,
                                            'remain unregistered and closed'):
                    construction.readiness(policy)
        policy = copy.deepcopy(self.policy)
        policy['sdkVersion'] = '7.0.120'
        with self.assertRaisesRegex(construction.ValidationError,
                                    'another SDK cannot be relabeled'):
            construction.readiness(policy)


class BootstrapSelectionTests(unittest.TestCase):
    PROPERTY = 'sdk/3.1.425/Microsoft.NETCoreSdk.BundledVersions.props'
    TASK = 'sdk/3.1.425/Microsoft.Build.dll'
    REFERENCE = 'packs/ReferencePack/ref/netcoreapp3.1/reference.dll'
    TEMPLATE = 'templates/project.nupkg'
    RENAMED_ELF = 'sdk/3.1.425/Roslyn/disguised-managed.dll'
    ORIGINAL_PROPS = (
        b'<Project><PropertyGroup><NETCoreSdkRuntimeIdentifier>'
        b'linux-arm64</NETCoreSdkRuntimeIdentifier>'
        b'</PropertyGroup></Project>\n')
    ADAPTED_PROPS = (
        b'<Project><PropertyGroup><NETCoreSdkRuntimeIdentifier>'
        b'linux-musl-arm64</NETCoreSdkRuntimeIdentifier>'
        b'</PropertyGroup></Project>\n')
    BOUNDS = {
        'archiveBytes': 32 * 1024,
        'members': 16,
        'memberBytes': 4096,
        'expandedBytes': 64 * 1024,
    }

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        # Prefix-only format fixtures are bytes for accounting, never binaries
        # to execute. The expected four-member selection is declared explicitly.
        self.selected_bytes = {
            self.PROPERTY: self.ORIGINAL_PROPS,
            self.TASK: b'MZ-tiny-managed-task-fixture\n',
            self.REFERENCE: b'MZ-tiny-reference-assembly-fixture\n',
            self.TEMPLATE: b'tiny-template-data-fixture\n',
        }
        archive_members = {
            **self.selected_bytes,
            self.RENAMED_ELF: b'\x7fELF-tiny-native-member-with-managed-suffix\n',
            'dotnet': b'\x7fELF-tiny-native-host-fixture\n',
            'README.txt': b'root data outside the selected SDK prefixes\n',
        }
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, raw in archive_members.items():
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                member.mode = 0o644
                member.mtime = 0
                archive.addfile(member, io.BytesIO(raw))
        archive_raw = gzip.compress(stream.getvalue(), mtime=0)
        self.archive = self.root / 'tiny-private-sdk.tar.gz'
        self.archive.write_bytes(archive_raw)
        self.policy = copy.deepcopy(construction.load_policy(
            SCRIPTS / 'musl-legacy31-construction-policy.json'))
        self.policy['bootstrap']['architectures']['aarch64']['sdkArchive'].update(
            fingerprint(archive_raw))
        adaptation = self.policy['bootstrap']['privateRidAdaptation']
        adaptation['originalSha256'] = fingerprint(self.ORIGINAL_PROPS)['sha256']
        adaptation['adaptedSha256'] = fingerprint(self.ADAPTED_PROPS)['sha256']
        self.materialized = {}
        for name, raw in self.selected_bytes.items():
            path = self.root / 'materialized' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            self.materialized[name] = path

    def verify(self):
        return construction.verify_bootstrap_sdk_selection(
            self.policy, 'aarch64', self.archive,
            self.materialized, self.BOUNDS)

    def test_actual_pe_and_data_bytes_are_accounted_and_renamed_elf_excluded(self):
        result = self.verify()
        self.assertEqual(result['status'],
                         'byte-accounted-private-bootstrap-SDK-selection-unqualified')
        self.assertEqual(result['selectedMembers'], {
            name: fingerprint(raw) for name, raw in self.selected_bytes.items()})
        self.assertEqual(result['sdkArchive'],
                         fingerprint(self.archive.read_bytes()))
        self.assertEqual(set(result['excludedEverySdkElf']),
                         {self.RENAMED_ELF, 'dotnet'})
        self.assertNotIn(self.RENAMED_ELF, result['selectedMembers'])
        self.assertNotIn('README.txt', result['selectedMembers'])
        self.assertEqual(result['explicitPrivateRidAdaptations'], [])
        self.assertIs(result['product'], False)
        self.assertIs(result['bootstrapAdmissionAllowed'], False)
        self.assertIs(result['normalAdmissionAllowed'], False)
        self.assertIs(
            result['privateNativeRuntimeAndCompilerSourceLicenseProofQualified'],
            False)

    def test_excluded_elf_cannot_be_supplied_under_a_managed_looking_name(self):
        path = self.root / 'renamed-elf.dll'
        path.write_bytes(b'\x7fELF-tiny-native-member-with-managed-suffix\n')
        self.materialized[self.RENAMED_ELF] = path
        with self.assertRaisesRegex(construction.ValidationError,
                                    'exactly selected SDK PE/data'):
            self.verify()

    def test_each_required_materialized_member_is_mandatory(self):
        del self.materialized[self.REFERENCE]
        with self.assertRaisesRegex(construction.ValidationError,
                                    'exactly selected SDK PE/data'):
            self.verify()

    def test_actual_materialized_mutation_is_not_hidden_by_unchanged_archive(self):
        self.materialized[self.TASK].write_bytes(b'MZ-mutated-task-fixture\n')
        with self.assertRaisesRegex(construction.ValidationError,
                                    'bootstrap member changed'):
            self.verify()

    def test_whole_archive_mutation_fails_before_member_accounting(self):
        self.archive.write_bytes(self.archive.read_bytes() + b'changed')
        with self.assertRaisesRegex(construction.ValidationError,
                                    'whole archive fingerprint differs'):
            self.verify()

    def test_exact_private_rid_adaptation_accounts_actual_adapted_bytes(self):
        self.materialized[self.PROPERTY].write_bytes(self.ADAPTED_PROPS)
        result = self.verify()
        self.assertEqual(result['explicitPrivateRidAdaptations'], [self.PROPERTY])
        self.assertEqual(result['selectedMembers'][self.PROPERTY],
                         fingerprint(self.ADAPTED_PROPS))
        self.assertIs(result['normalAdmissionAllowed'], False)

    def test_rid_adaptation_requires_both_exact_original_and_adapted_hashes(self):
        for field in ('originalSha256', 'adaptedSha256'):
            with self.subTest(field=field):
                previous = self.policy['bootstrap']['privateRidAdaptation'][field]
                try:
                    self.policy['bootstrap']['privateRidAdaptation'][field] = '0' * 64
                    self.materialized[self.PROPERTY].write_bytes(self.ADAPTED_PROPS)
                    with self.assertRaisesRegex(construction.ValidationError,
                                                'private RID adaptation differs'):
                        self.verify()
                finally:
                    self.policy['bootstrap']['privateRidAdaptation'][field] = previous

    def test_unapproved_rid_or_other_props_edit_is_rejected(self):
        for changed in (
                self.ADAPTED_PROPS.replace(b'linux-musl-arm64', b'linux-musl-x64'),
                self.ADAPTED_PROPS + b'<!-- an extra change -->\n'):
            with self.subTest(changed=changed):
                self.materialized[self.PROPERTY].write_bytes(changed)
                with self.assertRaisesRegex(construction.ValidationError,
                                            'private RID adaptation differs'):
                    self.verify()

    def test_another_cpu_cannot_reuse_the_arm64_bootstrap_identity(self):
        with self.assertRaisesRegex(construction.ValidationError,
                                    'per-CPU bootstrap archive remains unresolved'):
            construction.verify_bootstrap_sdk_selection(
                self.policy, 'x64', self.archive,
                self.materialized, self.BOUNDS)


if __name__ == '__main__':
    unittest.main()
