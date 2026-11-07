"""Exercise signed v2 APK bytes, strict trust, namespace and immutable staging."""
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import musl_packages as APK
from musl_contract import ARCHITECTURES, NATIVE_DEPENDENCIES
from distribution_contract import BRANDING


def tar_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for name, content, kind in entries:
            member = tarfile.TarInfo(name)
            member.mode, member.uid, member.gid, member.mtime = 0o755 if kind == 'directory' else 0o644, 0, 0, 1700000000
            if kind == 'directory':
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            else:
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


@unittest.skipUnless(os.name == 'posix' and shutil.which('openssl'), 'Linux OpenSSL and filesystem modes required')
class MuslPackagesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys_temp = tempfile.TemporaryDirectory(prefix='ephemeral-apk-tests-')
        cls.keys = Path(cls.keys_temp.name)
        cls.key = cls.keys / 'fixture.rsa'
        cls.public = cls.keys / 'fixture.rsa.pub'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:4096',
                        '-out', str(cls.key)], check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(cls.key), '-pubout', '-out', str(cls.public)],
                       check=True, capture_output=True)
        cls.wrong_private = cls.keys / 'wrong.rsa'
        cls.wrong_public = cls.keys / 'wrong.rsa.pub'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:4096',
                        '-out', str(cls.wrong_private)], check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(cls.wrong_private), '-pubout', '-out', str(cls.wrong_public)],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.keys_temp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def signed(self, compressed, suffix=b'', signature_type='RSA256'):
        content = self.directory / 'signable.gz'
        signature = self.directory / 'signature'
        content.write_bytes(compressed)
        subprocess.run(['openssl', 'dgst', '-sha256' if signature_type == 'RSA256' else '-sha1',
            '-sign', str(self.key), '-out', str(signature), str(content)], check=True, capture_output=True)
        sigtar = tar_bytes([('.SIGN.' + signature_type + '.' + self.public.name, signature.read_bytes(), 'file')])
        # abuild-tar --cut omits tar end markers in the signature/control streams.
        sigtar = sigtar[:1024]
        return gzip.compress(sigtar, mtime=0) + compressed + suffix

    def apk(self, payload=None, duplicate_version=False, signature_type='RSA256'):
        payload = payload or [('usr', b'', 'directory'), ('usr/bin', b'', 'directory'), ('usr/bin/cbodotnet', b'fixture', 'file')]
        data = gzip.compress(tar_bytes(payload), mtime=0)
        info = ('pkgname = cbodotnet-host\npkgver = 1.0.0-r1\narch = noarch\n'
                + ('pkgver = 1.0.0-r2\n' if duplicate_version else '')
                + 'datahash = ' + hashlib.sha256(data).hexdigest() + '\n').encode()
        control = gzip.compress(tar_bytes([('.PKGINFO', info, 'file')])[:1024], mtime=0)
        path = self.directory / 'cbodotnet-host-1.0.0-r1.apk'
        path.write_bytes(self.signed(control, data, signature_type))
        return path

    def index(self, rows, mutate=None):
        blocks = []
        for row in rows:
            fields = dict(C=row['indexIdentity'], P=row['name'], V=row['version'], A=row['architecture'], S=str(row['size']))
            if mutate:
                mutate(fields)
            blocks.append(''.join(k + ':' + v + '\n' for k, v in fields.items()))
        content = gzip.compress(tar_bytes([('APKINDEX', '\n'.join(blocks).encode(), 'file')]), mtime=0)
        path = self.directory / 'APKINDEX.tar.gz'
        path.write_bytes(self.signed(content))
        return path

    def plan(self, channel='apk', arch='x64'):
        archive = self.directory / f'cbodotnet-sdk-10.0.403-linux-musl-{arch}-r1.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            for name, content, mode in [('dotnet', b'#!/bin/sh\nprintf "10.0.403\\n"\n', 0o755),
                ('LICENSE.txt', b'original license', 0o644), ('ThirdPartyNotices.txt', b'original notices', 0o644)]:
                member = tarfile.TarInfo(name)
                member.size, member.mode = len(content), mode
                tar.addfile(member, io.BytesIO(content))
        return dict(schemaVersion=1, contractVersion=1, status='prepared-unqualified', publicationAllowed=False,
            libc='musl', sdkVersion='10.0.403', producerRevision=1, packageRevision=1,
            architecture=copy.deepcopy(ARCHITECTURES[arch]), targetRid=ARCHITECTURES[arch]['rid'],
            variant='alpine-3.24', channel=channel,
            package=dict(name='cbodotnet-sdk-10.0', version='10.0.403-r1', root='/opt/cbodotnet/10.0', launcher='/usr/bin/cbodotnet-10.0'),
            sdk=dict(name=archive.name, size=archive.stat().st_size, sha256=hashlib.sha256(archive.read_bytes()).hexdigest()),
            branding=copy.deepcopy(BRANDING), dependencies=list(NATIVE_DEPENDENCIES),
            licensePaths=['LICENSE.txt','ThirdPartyNotices.txt'], sourceReleaseTag='musl-sdk-10.0.403-r1',
            sourceManifestSha256='a'*64), archive

    def test_rsa256_package_and_index_bind_exact_identity_and_payload(self):
        path = self.apk()
        row = APK.verify_apk(path, self.public, {'name':'cbodotnet-host', 'version':'1.0.0-r1', 'architecture':'noarch'})
        self.assertEqual(3, len(APK.payload_snapshot(path, row)))
        index = APK.verify_index(self.index([row]), self.public, [row])
        self.assertEqual(1, index['packages'])
        self.assertEqual('SHA-256', row['signingKey']['digestAlgorithm'])

    def test_package_control_tampering_and_legacy_sha1_signature_are_rejected(self):
        path = self.apk()
        data = bytearray(path.read_bytes())
        data[45] ^= 1
        path.write_bytes(data)
        with self.assertRaises(ValueError):
            APK.verify_apk(path, self.public)
        with self.assertRaisesRegex(ValueError, 'reviewed RSA256'):
            APK.verify_apk(self.apk(signature_type='RSA'), self.public)

    def test_payload_tampering_is_rejected_even_when_control_signature_is_valid(self):
        path = self.apk()
        path.write_bytes(path.read_bytes() + b'unsigned-data')
        with self.assertRaisesRegex(ValueError, 'payload checksum'):
            APK.verify_apk(path, self.public)

    def test_duplicate_pkginfo_identity_and_signed_traversal_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'ambiguous APK identity'):
            APK.verify_apk(self.apk(duplicate_version=True), self.public)
        path = self.apk(payload=[('../outside', b'bad', 'file')])
        row = APK.verify_apk(path, self.public)
        with self.assertRaisesRegex(ValueError, 'Unsafe APK payload'):
            APK.payload_snapshot(path, row)

    def test_wrong_key_and_unexpected_key_filename_are_rejected(self):
        # A wrong key with the expected filename must fail cryptographically.
        keydir = self.directory / 'wrong-key'
        keydir.mkdir()
        wrong = keydir / self.public.name
        wrong.write_bytes(self.wrong_public.read_bytes())
        with self.assertRaisesRegex(ValueError, 'RSA256 signature verification failed'):
            APK.verify_apk(self.apk(), wrong)
        renamed = self.directory / 'different.rsa.pub'
        renamed.write_bytes(self.public.read_bytes())
        with self.assertRaisesRegex(ValueError, 'reviewed RSA256'):
            APK.verify_apk(self.apk(), renamed)

    def test_signed_index_wrong_checksum_size_or_package_set_are_rejected(self):
        row = APK.verify_apk(self.apk(), self.public)
        for key, value in [('C', 'Q1'+'a'*28), ('S', '1'), ('P', 'dotnet-host')]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'exact signed package set'):
                APK.verify_index(self.index([row], lambda fields: fields.update({key:value})), self.public, [row])
        path = self.index([row])
        path.write_bytes(path.read_bytes() + b'unsigned')
        with self.assertRaisesRegex(ValueError, 'trailing unsigned'):
            APK.verify_index(path, self.public, [row])

    def test_staging_preserves_sdk_and_official_dotnet_namespace(self):
        plan, archive = self.plan()
        output, rootfs, commands, payload = APK.stage_payload(plan, archive, self.directory/'stage')
        self.assertEqual({'/usr/bin/cbodotnet','/usr/bin/cbodotnet-10.0'}, {x['path'] for x in commands})
        self.assertFalse((rootfs/'usr/bin/dotnet').exists())
        self.assertEqual(payload, APK.sdk_tools().snapshot(rootfs/'opt/cbodotnet/10.0'))
        text = (rootfs/'usr/bin/cbodotnet-10.0').read_text()
        self.assertIn('linux-musl-x64', text)
        self.assertIn('"libc":"musl"', text)

    def test_glibc_compatibility_dependency_namespace_and_changed_archive_are_rejected(self):
        plan, archive = self.plan()
        for change in [lambda p:p.update(libc='glibc'), lambda p:p['dependencies'].append('gcompat'),
                       lambda p:p['package'].update(launcher='/usr/bin/dotnet')]:
            altered = copy.deepcopy(plan)
            change(altered)
            with self.assertRaises(ValueError):
                APK.stage_payload(altered, archive, self.directory/'invalid')
        archive.write_bytes(archive.read_bytes()+b'changed')
        with self.assertRaisesRegex(ValueError, 'archive changed'):
            APK.stage_payload(plan, archive, self.directory/'invalid')

    def test_apkbuild_preserves_payload_and_does_not_provide_official_dotnet(self):
        plan, _ = self.plan()
        recipe = APK.recipe(plan, 'sdk', 'a'*128)
        self.assertIn('pkgver=10.0.403\npkgrel=1', recipe)
        self.assertIn('!strip !dbg !tracedeps', recipe)
        self.assertIn('LicenseRef-Dotnet-SDK-ThirdParty', recipe)
        self.assertNotIn('replaces=', recipe)
        self.assertNotIn('provides=', recipe)
        host = APK.recipe(plan, 'host', 'b'*128)
        self.assertIn('arch="noarch"', host)
        self.assertEqual('https://github.com/dotnetdev-kr/cbodotnet/releases/download/musl-apk-repo-10.0.403-alpine324-x64-r1/APKINDEX.tar.gz',
                         APK.repository_url('10.0.403','x64',1))

    def test_oci_context_uses_only_reviewed_cpu_digest_and_all_three_aliases(self):
        plan, archive = self.plan('oci')
        with self.assertRaisesRegex(ValueError, 'CPU pin'):
            APK.build_oci_context(plan, archive, self.directory/'wrong-base', APK.BASE_IMAGES['aarch64'])
        result = APK.build_oci_context(plan, archive, self.directory/'oci', APK.BASE_IMAGES['x64'])
        self.assertFalse(result['publicationQualified'])
        commands = {x['path'] for x in result['commandInventory']}
        self.assertTrue({'/usr/local/bin/cbodotnet-10.0','/usr/local/bin/cbodotnet','/usr/local/bin/dotnet'} <= commands)
        self.assertIn('USER app', (self.directory/'oci/Containerfile').read_text())


if __name__ == '__main__':
    unittest.main()
