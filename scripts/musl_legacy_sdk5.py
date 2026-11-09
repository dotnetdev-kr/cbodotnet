"""Version-isolated SDK5 preparation and genuine original product producer.

Shared code supplies container/observation primitives only. SDK5 has its own
dual bootstrap, external product filter, original shell tests and compiler
process evidence. Source admission remains a separate complete validator.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
from types import SimpleNamespace
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


L = module('sdk5_container_observation_primitives', 'musl-legacy-sdk.py')
B = module('sdk5_explicit_bootstrap_inputs', 'musl_legacy5_bootstrap.py')
P, require, fingerprint, write = L.P, L.require, L.fingerprint, L.write
SDK = '5.0.214'
COMMITS = dict(nuget='d525b0e670f3b6cbd5c73a35f04730a9f658c852',
               vstest='99b911a57a02fc5d2eeef23e9ab8cbea4505678b')


def materialize_original_checkout(source, commit, preserve_windows=False):
    """Retain exact Git bytes, plus the runtime's declared Windows checkout.

    The native worker checks Git's attribute-aware pristine status. Restoring
    LF Git blobs over its declared CRLF Windows files makes that status dirty,
    even though the source bytes are authentic. Only the original runtime's
    .cmd/.bat/.sln files with an explicit eol=crlf rule may keep their original
    uniform checkout encoding; every compiler source byte remains exact.
    """
    import hashlib
    source = Path(source)
    git = ['git', '-c', 'safe.directory=' + str(source), '-C', str(source)]
    require(subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip() == commit,
            'Exact original SDK5 source commit required')
    require(not subprocess.check_output(git + ['ls-files', '--others', '--exclude-standard'], text=True),
            'Unexpected original SDK5 checkout inputs')
    changed, windows, children, count = [], [], [], 0
    for entry in subprocess.check_output(git + ['ls-tree', '-rz', '--full-tree', commit]).split(b'\0'):
        if not entry: continue
        header, encoded = entry.split(b'\t', 1); mode, kind, blob = header.decode().split(); member = encoded.decode()
        path = source / member
        if kind == 'commit':
            require(path.is_dir() and not path.is_symlink(), 'Original SDK5 Gitlink is redirected')
            children.append(dict(path=member, **materialize_original_checkout(path, blob, preserve_windows)))
            continue
        if mode == '120000':
            require(path.is_symlink(), 'Original SDK5 source link differs')
            raw = os.readlink(path).encode()
        else:
            require(mode in ('100644', '100755') and path.is_file()
                    and not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary original SDK5 source required')
            if mode == '100755': require(path.stat().st_mode & 0o111, 'Original SDK5 executable source mode required')
            raw = path.read_bytes()
        actual = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if actual != blob:
            require(mode != '120000', 'Original SDK5 source link target differs')
            original = subprocess.check_output(git + ['cat-file', 'blob', blob])
            require(b'\r' not in original and b'\0' not in original
                    and raw == original.replace(b'\n', b'\r\n'), 'Fresh SDK5 checkout changed more than original line endings')
            row = dict(path=member, gitBlob=blob, checkoutSha256=hashlib.sha256(raw).hexdigest(),
                       preferredSha256=hashlib.sha256(original).hexdigest())
            attribute = subprocess.check_output(git + ['check-attr', '-z', 'eol', '--', member]).split(b'\0')
            if preserve_windows:
                require(member.lower().endswith(('.cmd', '.bat', '.sln'))
                        and attribute == [encoded, b'eol', b'crlf', b''],
                        'SDK5 runtime checkout transforms are restricted to declared original Windows files')
                windows.append(row)
            else:
                path.write_bytes(original); changed.append(row)
                require(path.read_bytes() == original, 'Original SDK5 source materialization changed bytes')
        count += 1
    return dict(commit=commit, files=count, submodules=children, canonicalized=changed,
                originalWindowsCheckout=windows, allOtherTrackedRawGitBlobsIdentical=True,
                untrackedInputs=False, gitEolStatusNotUsedAsSourceSubstitute=True)


class Producer(L.Producer):
    def __init__(self, args):
        require(args.sdk_version == SDK, 'The version-isolated SDK5 producer requires5.0.214')
        super().__init__(args)
        self.selected = dict(self.selected, **COMMITS, nugetVersion='5.9.1-rc.8', vstestVersion='16.9.4-dev')
        self.sdk_work = self.work
        self.boot5 = self.inputs / 'bootstrap5'
        self.boot6 = self.inputs / 'bootstrap6'

    def clone(self, name, repository, commit):
        """Canonicalize only this fresh checkout, before any compiler runs."""
        source = super().clone(name, repository, commit)
        raw = materialize_original_checkout(source, commit, preserve_windows=name == 'runtime')
        write(self.reports / 'prepare/source-materialization' / (name + '.json'),
              dict(sourceCommit=commit, beforeAnyCompiler=True, originalRawTree=raw))
        return source

    def source_worker(self, arguments, *, bootstrap, log, workdir='/tmp', environment=None, network='host'):
        require(bootstrap in ('5', '6', None), 'An explicit SDK5 source-worker bootstrap role required')
        require(network in ('host', 'none'), 'An explicit source or offline SDK5 worker network required')
        log.parent.mkdir(parents=True, exist_ok=True)
        if os.getuid() == 0: os.chown(log.parent, self.uid, self.gid)
        argv = self.engine + ['run', '--rm', '--network=' + network, '--user', str(self.uid) + ':' + str(self.gid),
            '--cap-drop=all', '--security-opt=no-new-privileges', '--env', 'HOME=/home/build',
            '--env', 'DOTNET_CLI_HOME=/home/build', '--env', 'DOTNET_CLI_TELEMETRY_OPTOUT=1',
            '--env', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1', '--env', 'DOTNET_MULTILEVEL_LOOKUP=0',
            '--env', 'DOTNET_PROCESSOR_COUNT=2', '--env', 'PYTHONDONTWRITEBYTECODE=1',
            '--volume', str(ROOT) + ':/project:ro', '--volume', str(self.workspace) + ':/work',
            '--volume', str(self.output) + ':/delivery', '--volume', str(self.home) + ':/home/build', '--workdir', workdir]
        if bootstrap is not None:
            argv += ['--volume', str(self.boot5 if bootstrap == '5' else self.boot6) + ':/bootstrap:ro', '--env', 'DOTNET_ROOT=/bootstrap']
        if bootstrap == '5':
            argv += ['--volume', str(self.boot5) + ':/work/work/sdk/.dotnet:ro',
                     '--volume', str(self.boot5) + ':/work/work/installer/.dotnet:ro']
        for name, value in (environment or {}).items(): argv += ['--env', name + '=' + value]
        options = self.diagnostic_options()
        if os.getuid() == 0: os.chown(Path(options[1].removesuffix(':/diag')), self.uid, self.gid)
        argv += options + [self.image] + self.observed_command(arguments)
        self.run(argv, log=log)
        if not self.diagnostic: P.validate_default_container_policy(self.output, list(map(str, argv)))

    def _images(self):
        P.prepare_image_context(self.stock_profile, self.image_context)
        for suffix, field in [('', 'image'), ('-runtime', 'verify_image')]:
            tag = 'localhost/cbodotnet-sdk5-musl-' + field + ':' + self.args.run_id + '-' + self.args.arch
            self.run(self.engine + ['build', '--network=host', '--file',
                str(ROOT / 'containers' / (self.args.arch + '-net10-musl' + suffix + '.Containerfile')),
                '--tag', tag, str(self.image_context)], self.reports / 'prepare' / (field + '.log'))
            rows = json.loads(self.run(self.engine + ['image', 'inspect', tag], capture=True))
            require(len(rows) == 1 and rows[0]['Architecture'] == self.id['image'], 'Native SDK5 builder/runtime image CPU differs')
            setattr(self, field, rows[0]['Id']); write(self.reports / 'prepare' / (field + '.json'), rows)
        parent = module('sdk5_local_image_parent', 'musl_local_image.py').bind_parent(self, self.verify_image, 'runtime')
        for recipe, field in [('legacy-musl-smoke.Containerfile', 'test_image'), ('legacy-musl-tracing.Containerfile', 'tracing_image')]:
            tag = 'localhost/cbodotnet-sdk5-musl-' + field + ':' + self.args.run_id + '-' + self.args.arch
            self.run(self.engine + ['build', '--network=host', '--file', str(ROOT / 'containers' / recipe),
                '--build-arg', 'RUNTIME_IMAGE=' + parent, '--tag', tag, str(self.image_context)], self.reports / 'prepare' / (field + '.log'))
            rows = json.loads(self.run(self.engine + ['image', 'inspect', tag], capture=True))
            require(len(rows) == 1 and rows[0]['Architecture'] == self.id['image'], 'Native SDK5 consumer image CPU differs')
            setattr(self, field, rows[0]['Id']); write(self.reports / 'prepare' / (field + '.json'), rows)

    def _official_inputs(self):
        fetch = L.T.M.fetch
        for series in ('5.0', '6.0'):
            fetch('https://builds.dotnet.microsoft.com/dotnet/release-metadata/' + series + '/releases.json',
                  self.inputs / ('releases-' + series + '.json'), 4 * 1024**2)
        self.bootstrap_archives = {}
        for role in ('legacy5', 'runtime', 'vstest'):
            pin = B.pin(role, self.args.arch); target = self.inputs / Path(pin['url']).name
            fetch(pin['url'], target, 512 * 1024**2, pin['sha512'])
            self.bootstrap_archives[role] = target
        document = json.loads((self.inputs / 'releases-5.0.json').read_text())
        release = next(r for r in document['releases'] if r['runtime']['version'] == '5.0.17')
        self.framework_inputs = {'runtime': self.bootstrap_archives['runtime']}; records = []
        for kind in ('runtime', 'aspnetcore-runtime'):
            item = next(f for f in release[kind]['files'] if f['rid'] == self.id['rid'] and f['name'].endswith('.tar.gz'))
            target = self.inputs / Path(item['url']).name
            records.append(dict(component=kind, origin='official-matching-native-framework', **fetch(item['url'], target, 128 * 1024**2, item['hash'])))
            self.framework_inputs[kind] = target
        selected = next(f for release in document['releases'] for sdk in release.get('sdks', [release.get('sdk', {})])
                        if sdk.get('version') == SDK for f in sdk['files'] if f['rid'] == self.id['rid'] and f['name'].endswith('.tar.gz'))
        self.official = self.inputs / 'official-comparison-sdk.tar.gz'
        records.append(dict(component='official-sdk-comparison-only', origin='not-a-producer-payload',
                            **fetch(selected['url'], self.official, 512 * 1024**2, selected['hash'])))
        write(self.reports / 'prepare/imports.json', dict(inputs=records))

    def prepare(self):
        if not self.diagnostic:
            require(not P.git(ROOT, 'status', '--porcelain', '--untracked-files=all'), 'Normal SDK5 producer requires pristine orchestration')
        for root in (self.workspace, self.output):
            require(not root.exists() or root.is_dir() and not any(root.iterdir()), 'Fresh empty SDK5 workspace/delivery required')
        for path in (self.work, self.inputs, self.home, self.reports / 'prepare', self.reports / 'diagnostics'):
            path.mkdir(parents=True, exist_ok=True)
        self.home.chmod(0o700); self.record_container_engine(); self._images()
        for name, repository, commit in [
            ('sdk', 'https://github.com/dotnet/sdk', self.selected['sdk']),
            ('installer', 'https://github.com/dotnet/installer', self.selected['installer']),
            ('runtime', 'https://github.com/dotnet/runtime', self.selected['runtimeCommit']),
            ('aspnetcore', 'https://github.com/dotnet/aspnetcore', self.selected['aspnetcore']),
            ('nuget', 'https://github.com/NuGet/NuGet.Client', COMMITS['nuget']),
            ('vstest', 'https://github.com/microsoft/vstest', COMMITS['vstest']),
            ('source-build', 'https://github.com/dotnet/source-build', self.profile['source']['commit'])]:
            self.clone(name, repository, commit)
        compilers = module('sdk5_exact_matching_compiler_inputs', 'musl_legacy5_compiler_inputs.py')
        self.compiler_roots = {name: self.clone('compiler-' + name, repository, commit)
                               for name, (repository, commit) in compilers.SOURCES.items()}
        self.feed.mkdir(); self._official_inputs()
        # These SDK-free native compiler inputs break the old-runtime/SDK
        # bootstrap cycle without using any earlier private SDK archive.
        if os.getuid() == 0: self.run(['chown', '-R', str(self.uid) + ':' + str(self.gid), str(self.workspace), str(self.output)])
        for component in ('crypto', 'trace'):
            self.source_worker(['python3', '/project/scripts/musl-legacy-native.py', component, '--sdk', SDK,
                '--arch', self.args.arch, '--source', '/work/work/runtime',
                '--output', '/delivery/reports/prepare/bootstrap-' + component], bootstrap=None,
                log=self.reports / 'prepare' / ('bootstrap-' + component + '.log'))
            self.sources['bootstrap-' + component + '-inputs'] = dict(name='bootstrap-' + component + '-inputs', kind='tree',
                path=str(self.reports / 'prepare' / ('bootstrap-' + component)), role='actual-source-native-compiler-bootstrap-support')
        B.compose(self.bootstrap_archives['legacy5'], self.bootstrap_archives['runtime'],
            self.reports / 'prepare/bootstrap-crypto', self.reports / 'prepare/bootstrap-trace', self.boot5,
            self.reports / 'prepare/bootstrap5-composition.json', self.args.arch)
        license_dir = self.reports / 'prepare/bootstrap-source-licenses'; license_dir.mkdir()
        licenses = []
        for name in ('LICENSE.TXT', 'THIRD-PARTY-NOTICES.TXT'):
            raw = subprocess.check_output(['git', '-c', 'safe.directory=' + str(self.runtime), '-C', str(self.runtime),
                                           'show', self.selected['runtimeCommit'] + ':' + name])
            require((self.runtime / name).read_bytes() == raw, 'Original SDK5 bootstrap support license source differs')
            target = license_dir / name; target.write_bytes(raw)
            licenses.append(dict(path=name, sourceRoot='runtime', sourceCommit=self.selected['runtimeCommit'], **fingerprint(target)))
        write(license_dir / 'origin.json', dict(kind='original-runtime-bootstrap-support-license-inputs', licenses=licenses,
              sourceSupportUsedOnlyAsExplicitCompilerBootstrap=True, qualificationAllowed=False, sourceAdmissionAllowed=False))
        self.sources['bootstrap-source-licenses'] = dict(name='bootstrap-source-licenses', kind='tree', path=str(license_dir),
            role='original-native-bootstrap-support-source-license-inputs')
        checked = B.checked_archive(self.bootstrap_archives['vstest'], 'vstest', self.args.arch)
        self.boot6.mkdir(); files = B.unpack(self.bootstrap_archives['vstest'], self.boot6)
        write(self.reports / 'prepare/bootstrap6.json', dict(kind='official-private-component-compiler-bootstrap',
              archive=checked, files=files, payloadRole=False, qualificationAllowed=False))
        (self.work / 'sdk/.dotnet').mkdir(); (self.installer / '.dotnet').mkdir()
        if os.getuid() == 0: self.run(['chown', '-R', str(self.uid) + ':' + str(self.gid), str(self.workspace), str(self.output)])
        write(self.reports / 'prepare/identity.json', dict(schemaVersion=1, sdkVersion=SDK, targetRid=self.id['rid'], libc='musl',
            projectCommit=self.project, sourceCommit=self.selected['installer'], sdkSourceCommit=self.selected['sdk'],
            runtimeSourceCommit=self.selected['runtimeCommit'], runId=self.args.run_id, runAttempt=self.args.run_attempt,
            architecture=self.args.arch, buildId=self.args.build_id, emulation=False, diagnosticPodman=self.diagnostic,
            diagnosticPtrace=False, containerEngine=self.engine_record, sourceAppArmorPolicy='engine-default',
            consumerAppArmorPolicy='engine-default', sourceSeccompPolicy='engine-default', consumerSeccompPolicy='engine-default',
            imageId=self.image, verificationImageId=self.verify_image, tracingImageId=self.tracing_image,
            profile=dict(path=self.profile_path.name, **fingerprint(self.profile_path)),
            bootstrapScope='explicit-derived-SDK5.0.401-and-separate-official-VStest6.0.135', previousPrivateSdkArchiveUsed=False))
        for role, image in [('builder', self.image), ('runtime', self.verify_image), ('original-tests', self.test_image), ('tracing-tests', self.tracing_image)]:
            self.container(['sh', '-ec', '! command -v dotnet; ! apk info -e gcompat; ! apk info -e libc6-compat; '
                'test "$(cat /etc/alpine-release)" = 3.24.4; '
                'cp -a /cbodotnet-apks /delivery/reports/prepare/' + role + '-apks; '
                'apk info -vv > /delivery/reports/prepare/' + role + '-installed-packages.txt; '
                'cp -a /etc/apk/keys /delivery/reports/prepare/' + role + '-apk-keys'],
                source=False, image=image, network='none', log=self.reports / 'prepare' / (role + '-inventory.log'))
        self.container(['sh', '-ec', 'cp -a /cbodotnet-trace-test-apks /delivery/reports/prepare/tracing-test-apks'],
            source=False, image=self.tracing_image, network='none', log=self.reports / 'prepare/tracing-apk-inventory.log')
        if self.args.host_reports:
            require(self.args.host_reports.is_dir() and not self.args.host_reports.is_symlink(), 'Ordinary original SDK5 host preflight reports required')
            shutil.copytree(self.args.host_reports, self.reports / 'prepare/host')
        self.source_worker(['/bootstrap/dotnet', 'msbuild', '/project/scripts/probe-source-cultures.proj',
            '/p:SourceCultureReport=/delivery/reports/prepare/source-cultures.json'], bootstrap='5',
            log=self.reports / 'prepare/source-cultures.log')

    def _run_component(self, name, worker, bootstrap):
        directory = self.reports / 'build' / name
        self.source_worker(['python3', '/project/scripts/' + worker, '--sdk', SDK, '--arch', self.args.arch,
            '--source', '/work/work/' + name, '--dotnet', '/bootstrap/dotnet', '--output',
            '/delivery/reports/build/' + name], bootstrap=bootstrap, log=self.reports / 'build' / (name + '.log'))
        result = json.loads((directory / 'results.json').read_text())
        require(result['status'] == 'passed' and result['sourceCommit'] == COMMITS[name], 'Exact SDK5 source component failed: ' + name)
        return directory, result

    def build(self):
        cpu = 'arm64' if self.args.arch == 'aarch64' else 'x64'; feed_rows = []
        for name, worker, role, count in [('nuget', 'musl-legacy5-nuget.py', '5', 19),
                                         ('vstest', 'musl-legacy5-vstest.py', '6', 2)]:
            directory, result = self._run_component(name, worker, role)
            packages = sorted((directory / 'source-built-feed').glob('*.nupkg'))
            require(len(packages) == count, 'Complete original SDK5 source package matrix required: ' + name)
            for path in packages:
                destination = self.feed / path.name; shutil.copyfile(path, destination)
                require(fingerprint(destination) == fingerprint(path), 'Genuine SDK5 source package changed during retention')
                feed_rows.append(dict(file=path.name, component=name, sourceCommit=COMMITS[name],
                    origin='genuine-original-sdk5-component-source-build', retained=path.relative_to(self.output).as_posix(), **fingerprint(path)))
            if (directory / 'generated').is_dir():
                self.sources[name + '-generated'] = dict(name=name + '-generated', kind='tree', path=str(directory / 'generated'),
                    role='generated-managed-component-source')
        compilers = module('sdk5_prepare_matching_compiler_inputs', 'musl_legacy5_compiler_inputs.py')
        baseline_dir = self.inputs / 'compiler-baseline-packages'; baseline_dir.mkdir()
        baselines = {}
        for filename, (identity, size, sha) in compilers.BASELINES.items():
            path = baseline_dir / (identity + '.5.0.0.nupkg')
            # The diagnostic Microsoft archive fetcher intentionally rejects
            # NuGet URLs. These three original packages have their own closed
            # complete-byte identities and bounded public transport.
            url = 'https://api.nuget.org/v3-flatcontainer/' + identity + '/5.0.0/' + path.name
            with urllib.request.urlopen(url, timeout=90) as response: raw = response.read(size + 1)
            require(len(raw) == size and compilers.fp(raw)['sha256'] == sha, 'Downloaded original SDK5 compiler baseline differs')
            with path.open('xb') as stream: stream.write(raw)
            require(path.stat().st_size == size and fingerprint(path)['sha256'] == sha, 'Original SDK5 compiler baseline package differs')
            baselines[filename] = path
        derived = self.reports / 'build/derived-compiler-inputs'
        inputs = compilers.prepare(self.official, self.args.arch, self.compiler_roots, baselines, derived)
        for row in inputs['inputs']:
            path = derived / row['package']['path']; shutil.copyfile(path, self.feed / path.name)
            feed_rows.append(dict(file=path.name, component='matching-original-sdk-derived-compiler-input', sourceCommit=row['sourceCommit'],
                originalPublisherNupkg=False, compilerLocallySourceBuiltClaimed=False,
                retained=path.relative_to(self.output).as_posix(), **fingerprint(path)))
        self.sources['derived-compiler-inputs'] = dict(name='derived-compiler-inputs', kind='tree', path=str(derived),
            role='explicit-original-sdk-derived-compiler-inputs-and-preferred-source-definitions')
        write(self.reports / 'build/bootstrap-feed.json', dict(schemaVersion=1, sdkVersion=SDK, packages=feed_rows))
        translations = self.reports / 'build/nuget-translation-data'
        # The translation decoder uses SDK6 as an isolated read-only inspection
        # tool. SDK/NuGet/installer product compilation still selects SDK5.401.
        self.source_worker(['python3', '/project/scripts/musl-legacy5-nuget-resources.py', '--sdk-archive',
            '/work/inputs/official-comparison-sdk.tar.gz', '--arch', self.args.arch, '--source', '/work/work/nuget',
            '--dotnet', '/bootstrap/dotnet', '--output', '/delivery/reports/build/nuget-translation-data'], bootstrap='6',
            log=self.reports / 'build/nuget-translation-data.log')
        self.sources['nuget-translation-data'] = dict(name='nuget-translation-data', kind='tree', path=str(translations),
            role='actual-imported-translation-data-and-generated-readable-source')
        self.source_worker(['python3', '/project/scripts/musl-legacy5-tooling.py', '--sdk', SDK, '--arch', self.args.arch,
            '--workspace', '/work/work', '--dotnet', '/bootstrap/dotnet', '--feed', '/work/inputs/bootstrap-feed',
            '--translation-data', '/delivery/reports/build/nuget-translation-data', '--output', '/delivery/reports/build/sdk'],
            bootstrap='5', log=self.reports / 'build/sdk.log')
        tooling = json.loads((self.reports / 'build/sdk/results.json').read_text())
        require(tooling['status'] == 'passed' and tooling['original68SmokeExclusions'] == [], 'Original SDK5 product graph failed')
        native = self.reports / 'build/native-runtime'
        self.source_worker(['python3', '/project/scripts/musl-legacy-coreclr5.py', '--sdk', SDK, '--arch', self.args.arch,
            '--source', '/work/work/runtime', '--dotnet', '/bootstrap/dotnet', '--build-id', self.args.build_id,
            '--output', '/delivery/reports/build/native-runtime'], bootstrap='5', log=self.reports / 'build/native-runtime.log')
        native_result = json.loads((native / 'results.json').read_text())
        require(native_result['status'] == 'passed' and native_result['nativeVersionCompilationAndAllSixElfsVerified'],
            'Original SDK5 full native graph/version consumption failed')
        self.sources['native-runtime-generated'] = dict(name='native-runtime-generated', kind='tree', path=str(native / 'generated'),
            role='generated-native-component-source')
        imports = self.inputs / 'installer-components'; imports.mkdir()
        toolset = self.work / 'sdk/artifacts/packages/Release/NonShipping/dotnet-toolset-internal-5.0.214-ci.zip'
        require(toolset.is_file(), 'The original SDK5 redist did not create its actual toolset')
        shutil.copyfile(toolset, imports / toolset.name)
        for kind, path in self.framework_inputs.items():
            shutil.copyfile(path, imports / path.name)
            if kind == 'aspnetcore-runtime': shutil.copyfile(path, imports / ('aspnetcore-runtime-internal-5.0.17-' + self.id['rid'] + '.tar.gz'))
        for name in ('crossgen', 'libcoreclrtraceptprovider.so'): shutil.copy2(native / name, imports / name)
        # Worker report copies intentionally retain bytes without executable
        # mode; this separate construction tool is subsequently executed.
        (imports / 'crossgen').chmod(0o755)
        shutil.copy2(self.reports / 'prepare/bootstrap-crypto/libSystem.Security.Cryptography.Native.OpenSsl.so',
                     imports / 'libSystem.Security.Cryptography.Native.OpenSsl.so')
        (imports / 'native-runtime').mkdir()
        for name in ('libcoreclr.so', 'libclrjit.so', 'libmscordaccore.so', 'libmscordbi.so'):
            shutil.copy2(native / name, imports / 'native-runtime' / name)
        patches = ['patches/net5-musl/0002-copy-local-source-built-components.patch',
            'patches/net5-musl/0003-scope-msi-only-package-to-windows.patch', 'patches/net5-musl/0004-scope-windows-layout-projects.patch',
            'patches/net7-musl/0006-copy-matching-source-built-native-runtime.patch',
            'patches/net5-musl/0008-select-source-built-crossgen-and-jit.patch',
            'patches/net5-musl/0010-prefer-matching-framework-for-source-crossgen.patch']
        for name in patches:
            patch = ROOT / name
            self.run(['git', '-C', str(self.installer), 'apply', '--check', str(patch)])
            self.run(['git', '-C', str(self.installer), 'apply', str(patch)])
        command = ['./build.sh', '--configuration', 'Release', '--restore', '--rebuild', '--pack', '--projects',
            '/work/work/installer/src/redist/redist.csproj', '/p:ArcadeBuildFromSource=false', '/p:DotNetBuildFromSource=true',
            '/p:DotNetBuildOffline=true', '/p:MicrosoftDotnetToolsetInternalPackageVersion=5.0.214-ci', '/p:Version=5.0.214',
            '/p:Architecture=' + cpu, '/p:OSName=linux-musl', '/p:PortableOSName=linux-musl', '/p:Rid=' + self.id['rid'],
            '/p:HostRid=' + self.id['rid'], '/p:SharedFrameworkRid=' + self.id['rid'], '/p:CoreSetupRid=' + self.id['rid'],
            '/p:UsePortableLinuxSharedFramework=false', '/p:SkipBuildingInstallers=true',
            '/p:RestoreAdditionalProjectSources=/work/inputs/bootstrap-feed', '/p:UseSharedCompilation=false', '/m:2',
            '/bl:/delivery/reports/build/installer.binlog', '/p:CommunityMuslComponentRoot=/work/inputs/installer-components',
            '/p:CommunityMuslNativeTraceProvider=/work/inputs/installer-components/libcoreclrtraceptprovider.so',
            '/p:CommunityMuslNativeCrypto=/work/inputs/installer-components/libSystem.Security.Cryptography.Native.OpenSsl.so',
            '/p:CommunityMuslNativeRuntimeRoot=/work/inputs/installer-components/native-runtime',
            '/p:EmitCompilerGeneratedFiles=true', '/p:CommunityMuslNativeCrossgenPath=/work/inputs/installer-components/crossgen']
        self.source_worker(command, bootstrap='5', workdir='/work/work/installer', log=self.reports / 'build/installer.log',
            environment=dict(DOTNET_INSTALL_DIR='/work/work/installer/.dotnet', NUGET_PACKAGES='/work/work/installer/.packages',
                             _InitializeDotNetCli='/bootstrap', DotNetBuildFromSource='true'))
        archive = self.installer / 'artifacts/packages/Release/Shipping' / ('dotnet-sdk-' + SDK + '-' + self.id['rid'] + '.tar.gz')
        require(archive.is_file(), 'The original SDK5 installer did not produce its archive')
        self.archive = self.output / ('cbodotnet-sdk-' + SDK + '-linux-musl-' + self.args.arch + '-build.' + self.args.run_id + '.tar.gz')
        shutil.copyfile(archive, self.archive); require(fingerprint(archive) == fingerprint(self.archive), 'Retained SDK5 archive changed')
        write(self.reports / 'build/construction.json', dict(schemaVersion=1, sdkVersion=SDK, sourceOnly=False,
            sdkArchive=dict(name=self.archive.name, **fingerprint(self.archive)), toolingZip=dict(name=toolset.name, **fingerprint(toolset)),
            sourceGraph='external derived original SDK5 product solution filter then original redist project',
            originalRootSourceBuildGraphClaimed=False, originalProductsBuiltBeforeRedist=True, shippingNativeProducts=5,
            additionalSourceCrossgenConstructionInput=True, originalFullSdkUsedAsPayload=False,
            sourcePatches=[dict(path=name, **fingerprint(ROOT / name)) for name in patches],
            inputs=[dict(path=p.relative_to(imports).as_posix(), **fingerprint(p)) for p in sorted(imports.rglob('*')) if p.is_file()]))
        self.replay_build_logs()

    def replay_build_logs(self):
        reader = self.reports / 'build/reader'; shutil.copytree(ROOT / 'scripts/musl-legacy-reader', reader)
        (reader / 'NuGet.Config').write_text('<configuration><packageSources><clear/></packageSources></configuration>\n')
        if os.getuid() == 0: self.run(['chown', '-R', str(self.uid) + ':' + str(self.gid), str(reader)])
        self.source_worker(['/bootstrap/dotnet', 'build', '/delivery/reports/build/reader/Reader.csproj', '-c', 'Release',
            '/p:BootstrapMajor=6', '/p:BootstrapSdkDir=/bootstrap/sdk/6.0.135', '/p:UseSharedCompilation=false'],
            bootstrap='6', network='none', log=self.reports / 'build/reader-build.log')
        inputs = [('sdk', name, self.reports / 'build/sdk' / (name + '.binlog'), '/work/work/sdk') for name in ('sdk', 'redist')]
        inputs += [('nuget', 'original-library-matrix', self.reports / 'build/nuget/original-library-matrix.binlog', '/work/work/nuget'),
                   ('installer', 'installer', self.reports / 'build/installer.binlog', '/work/work/installer')]
        vstest = json.loads((self.reports / 'build/vstest/results.json').read_text())
        inputs += [('vstest', row['name'], self.reports / 'build/vstest' / (row['name'] + '.binlog'), '/work/work/vstest')
                   for row in vstest['commands']]
        self.component_replays = {name: [] for name in ('sdk', 'nuget', 'installer', 'vstest')}
        for component, name, binlog, mount in inputs:
            directory = self.reports / 'build' / component / 'replay'; directory.mkdir(parents=True, exist_ok=True)
            if os.getuid() == 0: os.chown(directory, self.uid, self.gid)
            prefix = directory / name; guest = '/delivery/' + prefix.relative_to(self.output).as_posix()
            self.source_worker(['python3', '/project/scripts/musl_legacy5_replay.py', '--name', name,
                '--dotnet', '/bootstrap/dotnet', '--reader', '/delivery/reports/build/reader/bin/Release/net6.0/Reader.dll',
                '--sdk-dir', '/bootstrap/sdk/6.0.135', '--binlog', '/delivery/' + binlog.relative_to(self.output).as_posix(),
                '--prefix', guest], bootstrap='6', network='none', log=directory / (name + '.log'))
            row = dict(name=name, sourceMountRoot=mount, binlog=str(binlog),
                status=str(prefix) + '-status.json', tasks=str(prefix) + '-tasks.jsonl')
            self.component_replays[component].append(row)
        write(self.reports / 'build/component-replays.json', dict(schemaVersion=1, components=self.component_replays,
            originalProcessIdentitiesPreserved=True, syntheticMergedReplay=False))

    def scan(self):
        origin = self.reports / 'build/sdk/derived-product-solution/origin.json'
        selection = json.loads(origin.read_text())
        require(selection['kind'] == 'downstream-sdk5-external-derived-product-solution-filter'
            and selection['sourceCommit'] == self.selected['sdk'] and selection['includedCount'] == 25
            and selection['excludedOriginalTestProjects'] == 31 and selection['original68SmokeExclusions'] == []
            and selection['checkedInSourceBuildFilterClaimed'] is False,
            'Exact original SDK5 external product filter/source inventory required')
        write(self.reports / 'scan-applicability.json', dict(status='not-applicable', sdkVersion=SDK,
            reason='Original SDK5 regular product/installer graphs do not contain VMR BinaryToolKit scanning.',
            noEmptyVmrScanReportManufactured=True, actualImportedInputsRequireInventory=True,
            sourceCommit=self.selected['sdk'], derivedFilterOrigin=dict(path=origin.relative_to(self.output).as_posix(), **fingerprint(origin)),
            checkedInSourceBuildSolutionFilterClaimed=False))

    def smoke_worker(self, command, feed, workspace):
        """Expose only the pinned shell suite, actual feed and fresh workspace."""
        log = self.reports / 'test/original-smoke.log'; log.parent.mkdir(parents=True, exist_ok=True)
        if os.getuid() == 0: os.chown(log.parent, self.uid, self.gid)
        argv = self.engine + ['run', '--rm', '--network=host', '--user', str(self.uid) + ':' + str(self.gid),
            '--cap-drop=all', '--security-opt=no-new-privileges', '--env', 'HOME=/home/build',
            '--env', 'DOTNET_CLI_HOME=/home/build', '--env', 'DOTNET_CLI_TELEMETRY_OPTOUT=1',
            '--env', 'DOTNET_MULTILEVEL_LOOKUP=0', '--env', 'DOTNET_PROCESSOR_COUNT=2', '--env', 'COMPlus_ReadyToRun=1',
            '--env', 'PYTHONDONTWRITEBYTECODE=1', '--volume', str(ROOT) + ':/project:ro',
            '--volume', str(self.output) + ':/delivery', '--volume', str(self.home) + ':/home/build',
            '--volume', str(self.work / 'source-build') + ':/source-suite:ro', '--volume', str(feed) + ':/local-feed:ro',
            '--volume', str(workspace) + ':/workspace', '--volume', str(self.archive) + ':/candidate.tar.gz:ro']
        options = self.diagnostic_options()
        if os.getuid() == 0: os.chown(Path(options[1].removesuffix(':/diag')), self.uid, self.gid)
        self.run(argv + options + [self.test_image] + self.observed_command(command), log=log)
        if not self.diagnostic: P.validate_default_container_policy(self.output, list(map(str, self.commands[-1])))

    def test(self):
        require(self.archive is not None, 'The actual SDK5 installer archive is required')
        feed = self.inputs / 'original-smoke-feed'; feed.mkdir(); packages = {}
        for source in (self.work / 'sdk/.packages', self.installer / '.packages', self.feed):
            for path in sorted(source.rglob('*.nupkg')):
                require(not path.is_symlink(), 'An actual SDK5 consumer package input is redirected')
                if path.name.endswith('.symbols.nupkg'): continue
                name = path.name.lower(); actual = fingerprint(path)
                if name in packages:
                    require(packages[name]['fingerprint'] == actual, 'Different SDK5 consumer package bytes share an identity')
                    continue
                destination = feed / name
                try: os.link(path, destination)
                except OSError: shutil.copyfile(path, destination)
                packages[name] = dict(path=str(path), fingerprint=actual)
        write(self.reports / 'test/original-smoke-feed.json', dict(packages=packages, sourcePackageInputsCopiedUnchanged=True))
        tooling = self.reports / 'build/sdk/results.json'; installer = self.reports / 'build/construction.json'
        identity = dict(sdkVersion=SDK, architecture=self.args.arch, sdkSourceBuildSucceeded=True, installerBuildSucceeded=True,
            sdkSourceResult=fingerprint(tooling), installerResult=fingerprint(installer), sdkArchive=fingerprint(self.archive),
            sdkSource=self.selected['sdk'], installerSource=self.selected['installer'],
            originalRootSourceBuildGraphClaimed=False, originalProductGraphCompletedBeforeRedistPackaging=True)
        write(self.reports / 'test/original-smoke-build-identity.json', identity)
        workspace = self.work / 'original-smoke-workspace'; workspace.mkdir()
        if os.getuid() == 0: self.run(['chown', '-R', str(self.uid) + ':' + str(self.gid), str(workspace), str(feed)])
        self.smoke_worker(['python3', '/project/scripts/musl-legacy-smoke5.py', '--arch', self.args.arch,
            '--source-suite', '/source-suite', '--sdk-archive', '/candidate.tar.gz',
            '--local-feed', '/local-feed', '--build-identity', '/delivery/reports/test/original-smoke-build-identity.json',
            '--workspace', '/workspace', '--output', '/delivery/reports/test/original-smoke'], feed, workspace)
        self.container(['python3', '/project/scripts/musl-legacy5-lttng.py', '--sdk', SDK, '--arch', self.args.arch,
            '--archive', '/delivery/' + self.archive.name, '--output', '/delivery/reports/test/native-lttng'],
            source=False, image=self.tracing_image, network='none', log=self.reports / 'test/native-lttng.log')
        self.container(['python3', '/project/scripts/musl-legacy-runtime-semantics5.py', '--arch', self.args.arch,
            '--archive', '/delivery/' + self.archive.name, '--output', '/delivery/reports/test/runtime-semantics'],
            source=False, image=self.verify_image, network='none', log=self.reports / 'test/runtime-semantics.log')

    def collect(self):
        raise ValueError('SDK5 complete construction/source collection must be installed before normal admission')

    def seal(self):
        raise ValueError('SDK5 complete independent source/construction admission is not yet installed')
