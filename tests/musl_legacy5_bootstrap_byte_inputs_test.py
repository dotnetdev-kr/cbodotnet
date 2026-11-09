from pathlib import Path
import io
import os
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import musl_legacy5_bootstrap_byte_inputs as V


class OriginalDualBootstrapBytes(unittest.TestCase):
    def fixture(self):
        fp=dict(bytes=1,sha256='a'*64,sha512='b'*128);framework={V.PREFIX+name:dict(mode=0o755,**fp)for name in (*V.C.CORE,*V.C.SUPPORT.values())};sdk={'sdk/5.0.401/dotnet.dll':dict(mode=0o644,**fp)}
        adaptations=[dict(path=V.PREFIX+filename,originalOfficial=fp,component=name,sourceCommit=V.C.SOURCE,bootstrapRoleOnly=True,productVersionMetadataQualified=False)for name,filename in V.C.SUPPORT.items()]
        return sdk,framework,adaptations

    def test_constructor_and_all_three_roles_are_distinct_sdk5_policy(self):
        V.constructor_policy();self.assertEqual(V.C.pin('legacy5','aarch64')['version'],'5.0.401');self.assertEqual(V.C.pin('runtime','aarch64')['version'],'5.0.17');self.assertEqual(V.C.pin('vstest','aarch64')['version'],'6.0.135')

    def test_original_archive_cpu_pin_is_checked_before_parsing(self):
        with tempfile.TemporaryDirectory()as tmp:
            path=Path(tmp)/'untrusted.tar.gz';path.write_bytes(b'untrusted')
            with self.assertRaisesRegex(ValueError,'exact native pin'):V.original_inventory(path,'legacy5','aarch64')

    def test_matching_runtime_is_separate_and_official_clr_is_preserved(self):
        sdk,framework,adaptations=self.fixture();receipt=V.composition(sdk,framework,{}, {},adaptations,'aarch64');self.assertTrue(receipt['officialClrJitDebuggerPreserved']);self.assertFalse(receipt['claimedUnmodifiedPublisherSdkTree'])
        sdk[V.PREFIX+'unreviewed.dll']=next(iter(sdk.values()))
        with self.assertRaises(ValueError):V.composition(sdk,framework,{}, {},adaptations,'aarch64')

    def test_only_both_exact_source_support_roles_may_replace_originals(self):
        sdk,framework,adaptations=self.fixture()
        for rows in (adaptations[:1],adaptations+[adaptations[0]],[dict(row,sourceCommit='0'*40)for row in adaptations],[dict(row,bootstrapRoleOnly=False)for row in adaptations]):
            with self.subTest(rows=rows),self.assertRaises(ValueError):V.composition(sdk,framework,{}, {},rows,'aarch64')

    def test_actual_tree_checks_modes_bytes_and_links(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);path=root/'tool';path.write_bytes(b'actual');path.chmod(0o755);actual=V.actual_tree(root);self.assertEqual(actual['tool']['mode'],0o755);self.assertEqual(actual['tool']['bytes'],6)
            (root/'redirect').symlink_to(path)
            with self.assertRaisesRegex(ValueError,'links are forbidden'):V.actual_tree(root)

    def test_changed_constructor_cannot_redefine_original_input_rules(self):
        with tempfile.TemporaryDirectory()as tmp:
            path=Path(tmp)/'constructor.py';path.write_bytes(b'changed')
            with patch.object(V.C,'__file__',str(path)),self.assertRaises(ValueError):V.constructor_policy()

    def test_native_support_command_contract_preserves_original_cpu_sources_and_two_workers(self):
        crypto=V.support_commands('crypto','aarch64');self.assertEqual(crypto[2][-2:],['--parallel','2']);self.assertIn('-DFEATURE_DISTRO_AGNOSTIC_SSL=OFF',crypto[1])
        trace=V.support_commands('trace','aarch64',['traceptprov.cpp']);self.assertIn('-DTARGET_ARM64=1',trace[1]);self.assertIn('/work/work/runtime/src/coreclr/src/vm/ClrEtwAll.man',trace[0]);self.assertIn('-O2',trace[1])
        for names in ([],['traceptprov.cpp','traceptprov.cpp'],['../traceptprov.cpp']):
            with self.subTest(names=names),self.assertRaises(ValueError):V.support_commands('trace','x64',names)

    def test_actual_posix_fifo_cannot_disappear_from_the_bootstrap_inventory(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);(root/'tool').write_bytes(b'regular data');os.mkfifo(root/'unexpected.fifo')
            with self.assertRaisesRegex(ValueError,'Only regular files and directories'):V.actual_tree(root)

    def test_actual_posix_special_permission_bits_are_rejected_without_masking(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);path=root/'non-executed-data';path.write_bytes(b'plain fixture data');path.chmod(0o755);self.assertEqual(V.actual_tree(root)['non-executed-data']['mode'],0o755)
            for mode in (0o4755,0o2755,0o1755):
                path.chmod(mode)
                with self.subTest(mode=oct(mode)),self.assertRaisesRegex(ValueError,'special permission bits'):V.actual_tree(root)
            path.chmod(0o755);root.chmod(0o1700)
            with self.assertRaisesRegex(ValueError,'special permission bits'):V.actual_tree(root)
            root.chmod(0o700)

    def test_original_archive_special_permissions_are_rejected_for_files_and_directories(self):
        with tempfile.TemporaryDirectory()as tmp:
            for kind in ('file','directory'):
                path=Path(tmp)/(kind+'.tar.gz')
                with tarfile.open(path,'w:gz')as archive:
                    member=tarfile.TarInfo('tool');member.mode=0o4755;member.type=tarfile.DIRTYPE if kind=='directory'else tarfile.REGTYPE;member.size=0 if kind=='directory'else 4;archive.addfile(member,None if kind=='directory'else io.BytesIO(b'data'))
                with self.subTest(kind=kind),patch.object(V.C,'checked_archive',return_value={}),self.assertRaisesRegex(ValueError,'archive special permission bits'):V.original_inventory(path,'legacy5','aarch64')


if __name__=='__main__':unittest.main()
