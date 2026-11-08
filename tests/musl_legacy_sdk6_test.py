import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk6_normal_producer_interface_test', ROOT / 'scripts/musl_legacy_sdk6.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)
BOUNDARY = M.module('sdk6_producer_independent_boundary_test', 'musl_legacy6_boundaries.py')


@unittest.skipUnless(__import__('os').name == 'posix', 'Normal source-worker mounts use native Linux paths')
class SDK6SourceWorkerInterfaceTests(unittest.TestCase):
    def test_generated_worker_envelopes_pass_independent_source_mapping_and_observed_security_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            producer = M.Producer.__new__(M.Producer)
            producer.sdk_work = base / 'work/sdk-build'
            (producer.sdk_work / 'sdk/.dotnet').mkdir(parents=True)
            producer.output, producer.workspace, producer.home = base / 'delivery', base, base / 'home'
            producer.reports = producer.output / 'reports'
            producer.uid = producer.gid = 1000
            producer.engine = M.P.DOCKER_ENGINE
            producer.image, producer.diagnostic, producer.commands = 'sha256:' + '1' * 64, False, []
            producer.observed_command = lambda args: args

            def record_without_execution(argv, log=None):
                # Unit fixture: do not launch a container or claim kernel evidence.
                producer.commands.append(list(map(str, argv)))
                values = [value for value in argv if value.endswith(':/diag')]
                self.assertEqual(len(values), 1)
                directory = Path(values[0].removesuffix(':/diag'))
                (directory / 'process-status.txt').write_text(
                    'Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\nNoNewPrivs:\t1\nSeccomp:\t2\n'
                    + ''.join(name + ':\t0000000000000000\n' for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')))
                (directory / 'apparmor-current.txt').write_text('docker-default (enforce)\n')
            producer.run = record_without_execution
            roots = [dict(name='orchestration', originalPath=str(M.ROOT))]
            commits = dict(sdk=BOUNDARY.SDK_SOURCE, nuget='451e9bc27184dc49d04e975122c9e7189d525872',
                vstest='cc7fb0593127e24f55ce016fb3ac85b5b2857fec', runtime='f1dd57165bfd91875761329ac3a8b17f6606ad18',
                **{'msbuild-localization':'85d71072f8fa22cc761d6b65954da263364bee4d'})
            roots += [dict(name=name, commit=commit, originalPath=str(producer.sdk_work / 'sdk' if name == 'sdk' else base / 'work' / name))
                for name, commit in commits.items()]
            with mock.patch.object(M.os, 'getuid', return_value=1000):
                for worker, name in [('nuget', 'nuget'), ('vstest', 'vstest'), ('localization', 'msbuild-localization'), ('coreclr', 'runtime')]:
                    output = 'native-runtime' if worker == 'coreclr' else name
                    arguments = ['python3', '/project/scripts/musl-legacy6-' + worker + '.py', '--sdk', '6.0.136',
                        '--arch', 'aarch64', '--source', '/work/work/' + name, '--dotnet', '/bootstrap/dotnet',
                        '--output', '/delivery/reports/build/' + output]
                    if worker in ('localization', 'coreclr'): arguments += ['--build-id', '20261109.1']
                    producer.source_worker(arguments, log=producer.reports / 'build' / (name + '.log'))
            stages = dict(build=dict(commands=producer.commands))
            record = dict(sdkVersion='6.0.136', architecture='aarch64', targetRid='linux-musl-arm64', buildId='20261109.1')
            BOUNDARY.validate_source_workers(record, dict(imageId=producer.image), stages, dict(roots=roots))
            for original in producer.commands:
                changed = copy.deepcopy(original); changed[changed.index('--user') + 1] = '0:0'
                with self.assertRaisesRegex(ValueError, 'must be non-root'):
                    M.P.validate_default_container_policy(producer.output, changed)


if __name__ == '__main__': unittest.main()
