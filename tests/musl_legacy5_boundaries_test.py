import copy
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import musl_legacy5_boundaries as G


class ExactSDK5WorkerBoundaries(unittest.TestCase):
    def fixture(self, diagnostic=False, bootstrap='6'):
        roots = [dict(name=n, originalPath='/private/workspace/work/'+n, kind='git') for n in ('sdk','nuget','vstest','installer','runtime')]
        roots += [dict(name='orchestration', originalPath='/project-source', kind='git'),
            dict(name='actual-managed-package-inputs', originalPath='/private/delivery/imported-inputs', kind='tree', role='actual-imported-managed-inputs')]
        manifest = dict(roots=roots); prepare = dict(sdkVersion=G.CE.SDK, diagnosticPodman=diagnostic, diagnosticPtrace=False, imageId='sha256:'+'1'*64)
        record = dict(sdkVersion=G.CE.SDK); inner = ['/bootstrap/dotnet','build','/delivery/reports/build/reader/Reader.csproj']
        engine = ['sudo','-n','--','podman','--cgroup-manager=cgroupfs','--events-backend=file'] if diagnostic else G.B.P.DOCKER_ENGINE
        call = G.expected_source_worker(engine,'1000:1000',G.worker_paths(manifest),prepare['imageId'],
            '/private/delivery/reports/diagnostics/container-0088',inner,bootstrap=bootstrap,network='none')
        return call,inner,record,prepare,manifest

    def test_exact_sdk5_readonly_bootstrap_offline_worker(self):
        call,inner,record,prepare,manifest=self.fixture()
        self.assertTrue(G.validate_source_worker(call,inner,record,prepare,manifest,bootstrap='6',network='none')['normalProducerBoundaryValidated'])

    def test_aliases_extra_mounts_runtime_environment_and_security_options_reject(self):
        call,inner,record,prepare,manifest=self.fixture(); image=call.index(prepare['imageId'])
        for injected in [ ['--mount','type=bind,source=/foreign,target=/work/work/runtime'],
            ['--volume=/foreign:/work/work/runtime'], ['--env','DOTNET_ROOT=/foreign'],
            ['--env=DOTNET_ROOT=/foreign'], ['-e','COMPlus_ReadyToRun=0'], ['--privileged'],
            ['--security-opt','seccomp=unconfined'], ['-w','/foreign'] ]:
            changed=call[:image]+injected+call[image:]
            with self.subTest(injected=injected),self.assertRaises(ValueError):
                G.validate_source_worker(changed,inner,record,prepare,manifest,bootstrap='6',network='none')

    def test_native_bootstrap_and_both_product_dotnet_mounts_cannot_be_relabelled(self):
        call,inner,record,prepare,manifest=self.fixture(bootstrap='5')
        G.validate_source_worker(call,inner,record,prepare,manifest,bootstrap='5',network='none')
        for target in ['/private/workspace/inputs/bootstrap5:/bootstrap:ro',
                       '/private/workspace/inputs/bootstrap5:/work/work/sdk/.dotnet:ro',
                       '/private/workspace/inputs/bootstrap5:/work/work/installer/.dotnet:ro']:
            changed=list(call);changed[changed.index(target)]=target.replace('/inputs/bootstrap5','/inputs/foreign')
            with self.subTest(target=target),self.assertRaises(ValueError):
                G.validate_source_worker(changed,inner,record,prepare,manifest,bootstrap='5',network='none')

    def test_private_diagnostic_observation_never_establishes_normal_boundary(self):
        call,inner,record,prepare,manifest=self.fixture(diagnostic=True)
        result=G.validate_source_worker(call,inner,record,prepare,manifest,bootstrap='6',network='none',diagnostic=True)
        self.assertFalse(result['normalProducerBoundaryValidated']);self.assertTrue(result['diagnosticOnly'])
        with self.assertRaises(ValueError): G.validate_source_worker(call,inner,record,prepare,manifest,bootstrap='6',network='none')

    def test_source_root_roles_and_workspace_aliases_are_closed(self):
        call,inner,record,prepare,manifest=self.fixture()
        for name,edit in [('runtime',lambda r:r.update(originalPath='/private/foreign')),
                          ('actual-managed-package-inputs',lambda r:r.update(role='source-for-other-data'))]:
            changed=copy.deepcopy(manifest);edit(next(r for r in changed['roots']if r['name']==name))
            with self.subTest(name=name),self.assertRaises(ValueError):
                G.validate_source_worker(call,inner,record,prepare,changed,bootstrap='6',network='none')

    def test_installer_only_uses_exact_upstream_preinitialized_bootstrap_mode(self):
        _,_,record,prepare,manifest=self.fixture();record.update(architecture='aarch64',targetRid='linux-musl-arm64')
        inner=G.installer_command(record);call=G.expected_source_worker(G.B.P.DOCKER_ENGINE,'1000:1000',G.worker_paths(manifest),
            prepare['imageId'],'/private/delivery/reports/diagnostics/container-0099',inner,bootstrap='5',
            workdir='/work/work/installer',environment=G.installer_environment())
        G.validate_installer(record,prepare,manifest,dict(build=dict(commands=[call])))
        for value in ('_InitializeDotNetCli=/foreign','_InitializeBuildTool=/bootstrap/dotnet'):
            changed=list(call);changed[changed.index('_InitializeDotNetCli=/bootstrap')]=value
            with self.subTest(value=value),self.assertRaises(ValueError):G.validate_installer(record,prepare,manifest,dict(build=dict(commands=[changed])))
        index=call.index('_InitializeDotNetCli=/bootstrap');missing=call[:index-1]+call[index+1:]
        with self.assertRaises(ValueError):G.validate_installer(record,prepare,manifest,dict(build=dict(commands=[missing])))
        changed=list(call);changed[changed.index('DotNetBuildFromSource=true')]='DotNetBuildFromSource=false'
        with self.assertRaises(ValueError):G.validate_installer(record,prepare,manifest,dict(build=dict(commands=[changed])))

    def test_copied_reader_source_clear_config_and_parent_build_hooks(self):
        with tempfile.TemporaryDirectory()as tmp:
            release=Path(tmp);directory=release/'reports/build/reader';directory.mkdir(parents=True)
            archived={'orchestration/scripts/musl-legacy-reader/Program.cs':b'original Reader source',
                      'orchestration/scripts/musl-legacy-reader/Reader.csproj':b'original Reader project'}
            for name in ('Program.cs','Reader.csproj'):(directory/name).write_bytes(archived['orchestration/scripts/musl-legacy-reader/'+name])
            (directory/'NuGet.Config').write_bytes(G.READER_CONFIG);G.validate_reader_sources(release,archived)
            (directory/'Program.cs').write_bytes(b'changed Reader')
            with self.assertRaises(ValueError):G.validate_reader_sources(release,archived)
            (directory/'Program.cs').write_bytes(archived['orchestration/scripts/musl-legacy-reader/Program.cs'])
            (release/'reports/Directory.Build.targets').write_bytes(b'new build hook')
            with self.assertRaises(ValueError):G.validate_reader_sources(release,archived)


if __name__ == '__main__':unittest.main()
