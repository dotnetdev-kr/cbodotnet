import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sdk6_boundaries_test', ROOT / 'scripts/musl_legacy6_boundaries.py')
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class SDK6NormalBoundaryTests(unittest.TestCase):
    def test_elf_closure_direct_call_cannot_omit_or_substitute_actual_archive_members(self):
        record = dict(sdkVersion='6.0.136', architecture='aarch64', targetRid='linux-musl-arm64', sdk=dict(name='actual-sdk.tar.gz'))
        rows = [dict(path='dotnet', sha256='1' * 64, interpreter='/lib/ld-musl-aarch64.so.1'),
                dict(path='shared/libnative.so', sha256='2' * 64, interpreter=None)]
        actual = {row['path']:{key:row[key] for key in ('sha256', 'interpreter')} for row in rows}
        def report(selected):
            return dict(violations=[], emulation=False, nativeArchitecture='aarch64', symlinks=[], elfCount=len(selected), files=selected,
                closure=dict(schemaVersion=1, scope='musl-complete-payload-elf-closure', native=True, libc='musl',
                    architecture='aarch64', targetRid='linux-musl-arm64', symlinks=[], hostElfCount=len(selected), elfFiles=copy.deepcopy(selected)))
        altered = copy.deepcopy(rows); altered[0]['sha256'] = '3' * 64
        interpreter = copy.deepcopy(rows); interpreter[0]['interpreter'] = None
        for selected in (rows[:-1], altered, interpreter, rows + [rows[0]]):
            with self.subTest(rows=selected), mock.patch.object(M.P, 'sdk_elf_inventory', return_value=actual), \
                 mock.patch.object(M.tarfile, 'open', side_effect=AssertionError('Forged report reached provider closure')):
                with self.assertRaisesRegex(ValueError, 'Every actual SDK6 ELF'):
                    M.validate_elf_closure(ROOT, record, {}, report(selected))

    def source_fixture(self):
        record = dict(sdkVersion='6.0.136', architecture='aarch64', targetRid='linux-musl-arm64', buildId='20261109.1')
        prepare = dict(imageId='sha256:' + '1' * 64)
        commits = dict(sdk=M.SDK_SOURCE, nuget='451e9bc27184dc49d04e975122c9e7189d525872',
            vstest='cc7fb0593127e24f55ce016fb3ac85b5b2857fec', runtime='f1dd57165bfd91875761329ac3a8b17f6606ad18',
            **{'msbuild-localization':'85d71072f8fa22cc761d6b65954da263364bee4d'})
        roots = [dict(name=name, commit=commit, originalPath='/build/work/' + ('sdk-build/sdk' if name == 'sdk' else name))
            for name, commit in commits.items()]
        roots.append(dict(name='orchestration', originalPath='/project-source'))
        calls = []
        for worker, name in [('nuget', 'nuget'), ('vstest', 'vstest'), ('localization', 'msbuild-localization'), ('coreclr', 'runtime')]:
            call = M.P.DOCKER_ENGINE + ['run', '--network=host', '--volume', '/build:/work',
                '--volume', '/build/work/sdk-build/sdk/.dotnet:/bootstrap:ro', '--volume', '/project-source:/project:ro',
                prepare['imageId'], 'python3', '/project/scripts/musl-legacy6-' + worker + '.py', '--sdk', '6.0.136',
                '--arch', 'aarch64', '--source', '/work/work/' + name, '--dotnet', '/bootstrap/dotnet',
                '--output', '/delivery/reports/build/' + ('native-runtime' if worker == 'coreclr' else name)]
            if worker in ('localization', 'coreclr'): call += ['--build-id', record['buildId']]
            calls.append(call)
        return record, prepare, dict(build=dict(commands=calls)), dict(roots=roots)

    def test_source_workers_bind_original_source_and_read_only_exact_bootstrap(self):
        record, prepare, stages, manifest = self.source_fixture()
        M.validate_source_workers(record, prepare, stages, manifest)
        cases = []
        changed = copy.deepcopy(stages); call = changed['build']['commands'][0]; call[call.index('/bootstrap/dotnet')] = '/host/dotnet'; cases.append(changed)
        changed = copy.deepcopy(stages); call = changed['build']['commands'][0]; call[call.index('/build/work/sdk-build/sdk/.dotnet:/bootstrap:ro')] = '/build/work/sdk-build/sdk/.dotnet:/bootstrap'; cases.append(changed)
        changed = copy.deepcopy(stages); call = changed['build']['commands'][0]; call[call.index('/build:/work')] = '/other:/work'; cases.append(changed)
        changed = copy.deepcopy(stages); changed['build']['commands'][0] += ['--volume', '/hidden:/work/work/nuget/src']; cases.append(changed)
        changed = copy.deepcopy(stages); changed['build']['commands'].append(changed['build']['commands'][0]); cases.append(changed)
        for changed in cases:
            with self.subTest(command=changed['build']['commands'][0][-4:]), self.assertRaises(ValueError):
                M.validate_source_workers(record, prepare, changed, manifest)

    def fixture(self, release):
        record = dict(sdkVersion='6.0.136', architecture='aarch64', targetRid='linux-musl-arm64', sdk=dict(name='actual-sdk.tar.gz'))
        prepare = dict(imageId='sha256:' + '1' * 64, verificationImageId='sha256:' + '2' * 64)
        directory = release / 'reports/prepare'; directory.mkdir(parents=True)
        for name, field in [('image.json', 'imageId'), ('verify_image.json', 'verificationImageId')]:
            (directory / name).write_text(json.dumps([dict(Id=prepare[field], Architecture='arm64', Os='linux')]))
        mounts = [value for host, target, mode in [('project', '/project', ':ro'), ('release', '/delivery', ''),
            ('home', '/home/build', ''), ('diag', '/diag', '')] for value in ('--volume', '/' + host + ':' + target + mode)]
        calls = []
        environment = dict(HOME='/home/build', DOTNET_CLI_HOME='/home/build', DOTNET_CLI_TELEMETRY_OPTOUT='1',
            DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1', DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_PROCESSOR_COUNT='2',
            PYTHONDONTWRITEBYTECODE='1', MSBUILDDEBUGPATH='/diag', MSBUILDDEBUGCOMM='1')
        env_args = [value for key, data in environment.items() for value in ('--env', key + '=' + data)]
        for worker, mode, network in [('verify-sdk.sh', None, 'none'), ('musl-sdk-audit.py', None, 'none'),
            ('musl-legacy-functional.py', 'offline', 'none'), ('musl-legacy-functional.py', 'tls', 'host')]:
            call = M.P.DOCKER_ENGINE + ['run', '--network=' + network, *mounts, *env_args, prepare['verificationImageId'],
                '/project/scripts/' + worker, *([mode] if mode else []), '--archive', '/delivery/actual-sdk.tar.gz']
            if worker == 'verify-sdk.sh':
                call += ['--expected-version', '6.0.136', '--expected-rid', 'linux-musl-arm64', '--framework', 'net6.0', '--arch', 'arm64']
            calls.append(call)
        return record, prepare, dict(verify=dict(commands=calls))

    def test_other_sdk_cannot_select_any_sdk6_normal_consumer_or_stage_policy(self):
        wrong = dict(sdkVersion='7.0.120', architecture='aarch64', targetRid='linux-musl-arm64')
        for function, args in [(M.validate_stages, ({},)), (M.validate_verification_boundary, ({}, {})),
            (M.validate_functional, ({},)), (M.validate_original_smoke, ({},)),
            (M.validate_scan_applicability, ({},)), (M.validate_lttng, ({}, {})),
            (M.validate_elf_closure, ({}, {}))]:
            with self.subTest(function=function.__name__), self.assertRaisesRegex(ValueError, 'independent SDK6 native identity'):
                function(ROOT / 'does-not-exist', wrong, *args)

    def test_cold_verifiers_reject_workspace_framework_archive_and_runtime_overrides(self):
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary); record, prepare, stages = self.fixture(release)
            M.validate_verification_boundary(release, record, prepare, stages)
            cases = []
            changed = copy.deepcopy(stages); changed['verify']['commands'][0] += ['--volume', '/build:/work']; cases.append(changed)
            changed = copy.deepcopy(stages); call = changed['verify']['commands'][0]; call[call.index('net6.0')] = 'net7.0'; cases.append(changed)
            changed = copy.deepcopy(stages); call = changed['verify']['commands'][0]; call[call.index('/delivery/actual-sdk.tar.gz')] = '/delivery/other.tar.gz'; cases.append(changed)
            changed = copy.deepcopy(stages); changed['verify']['commands'][0] += ['--env', 'DOTNET_ROOT=/host-sdk']; cases.append(changed)
            changed = copy.deepcopy(stages); call = changed['verify']['commands'][-1]; call[call.index('--network=host')] = '--network=none'; cases.append(changed)
            for override in (['--env', 'COMPlus_ReadyToRun=0'], ['--env', 'DOTNET_ReadyToRun=0'],
                             ['--env-file', '/tmp/hidden.env'], ['--env=COMPlus_ReadyToRun=0'],
                             ['-e', 'COMPlus_ReadyToRun=0'], ['-eCOMPlus_ReadyToRun=0'], ['--env', 'HOME=/home/build']):
                changed = copy.deepcopy(stages); call = changed['verify']['commands'][0]
                index = call.index(prepare['verificationImageId']); call[index:index] = override; cases.append(changed)
            for changed in cases:
                with self.subTest(command=changed['verify']['commands'][0][-4:]), self.assertRaises(ValueError):
                    M.validate_verification_boundary(release, record, prepare, changed)


if __name__ == '__main__': unittest.main()
