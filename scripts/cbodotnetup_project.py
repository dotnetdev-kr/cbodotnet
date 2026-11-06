"""Native project-SDK reference and offline owned-installation qualification.

Reference fixtures contain only empty SDK marker files. They exercise the native
host's matching algorithm and never qualify or execute a preview/synthetic SDK.
The same reviewed cases are consumed by the C# resolver tests.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from downstream_release import require


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tools/cbodotnetup.Tests/fixtures/project-sdk-reference.json'
POLICIES = ('disable', 'patch', 'feature', 'minor', 'major', 'latestPatch',
            'latestFeature', 'latestMinor', 'latestMajor')
REFERENCE_SCOPE = 'isolated-sdk-matching-reference'
PROJECT_SCOPE = 'offline-owned-project-sdk-selection'
PROJECT_CHECKS = ('highest-without-project', 'nearest-ancestor', 'nearest-file-boundary',
                  'exact-project-pin', 'patch-roll-forward', 'major-roll-forward',
                  'feature-band-rejection', 'missing-sdk-no-install', 'missing-admitted-sdk-no-install', 'malformed-fail-closed',
                  'comments', 'prerelease-policy', 'host-paths', 'external-path-rejection',
                  'symlink-rejection', 'versioned-alias-precedence', 'explicit-run-precedence',
                  'sdk-info-selection', 'sdk-arguments-offline', 'msbuild-owned-sdk', 'msbuild-project-conflict',
                  'runtime-options-sdk-rejection', 'missing-app-runtime-dispatch', 'runtime-options-missing-app',
                  'project-files-preserved', 'owned-state-preserved', 'payload-inventory-preserved')
VERSION = re.compile(r'[1-9][0-9]*\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[A-Za-z0-9.-]+)?')


def reference_fixture():
    value = json.loads(FIXTURE.read_bytes())
    require(value['schemaVersion'] == 1 and value['scope'] == REFERENCE_SCOPE,
            'Project SDK reference fixture has another schema/scope')
    cases = value['cases']
    require(isinstance(cases, list) and 9 <= len(cases) <= 512
            and len({row['name'] for row in cases}) == len(cases),
            'Project SDK reference cases are absent or duplicated')
    require({row.get('policy') for row in cases if row.get('category') == 'rollForward'} == set(POLICIES),
            'All nine SDK roll-forward policies need native reference cases')
    for case in cases:
        require(isinstance(case['versions'], list) and case['versions']
                and len(set(case['versions'])) == len(case['versions'])
                and all(isinstance(version, str) and VERSION.fullmatch(version) for version in case['versions']),
                'Reference SDK markers need unique safe version-directory names')
        require('configuration' in case or isinstance(case.get('configurationText'), str),
                'Reference project configuration is missing')
        require(case['expectedVersion'] is None or case['expectedVersion'] in case['versions'],
                'Reference resolver expectation is outside its SDK inventory')
        native = case.get('nativeExpectedVersion', case['expectedVersion'])
        require(native is None or native in case['versions'], 'Native reference expectation is outside its SDK inventory')
        require(not case.get('failClosed') or case['expectedVersion'] is None,
                'A fail-closed case cannot admit an SDK')
    return value


def configuration_bytes(case):
    if 'configurationText' in case:
        return case['configurationText'].encode('utf-8')
    value = case['configuration']
    return None if value is None else json.dumps(value, separators=(',', ':')).encode('utf-8')


def qualify_reference(payload, workspace):
    """Resolve shared matching-only cases through the admitted SDK10 hostfxr API."""
    payload, workspace = Path(payload), Path(workspace)
    require(payload.is_dir() and not payload.is_symlink() and not workspace.exists(),
            'An existing SDK payload and fresh isolated reference workspace are required')
    libraries = list((payload / 'host/fxr').glob('*/libhostfxr.so'))
    require(len(libraries) == 1 and libraries[0].is_file() and not libraries[0].is_symlink(),
            'One ordinary admitted native hostfxr reference library is required')
    library_path = libraries[0]
    fixture = reference_fixture()
    native = ctypes.CDLL(str(library_path))
    result_callback = ctypes.CFUNCTYPE(None, ctypes.c_int, ctypes.c_char_p)
    error_callback = ctypes.CFUNCTYPE(None, ctypes.c_char_p)
    resolve = native.hostfxr_resolve_sdk2
    resolve.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, result_callback]
    resolve.restype = ctypes.c_int32
    set_error = native.hostfxr_set_error_writer
    set_error.argtypes = [ctypes.c_void_p]
    set_error.restype = ctypes.c_void_p
    flush = ctypes.CDLL(None).fflush
    flush.argtypes = [ctypes.c_void_p]
    flush.restype = ctypes.c_int
    workspace.mkdir(parents=True)
    rows = []
    for index, case in enumerate(fixture['cases']):
        cell = workspace / str(index)
        host, project = cell / 'host', cell / 'project'
        project.mkdir(parents=True)
        for version in case['versions']:
            sdk = host / 'sdk' / version
            sdk.mkdir(parents=True)
            (sdk / 'dotnet.dll').touch()
        config = configuration_bytes(case)
        if config is not None:
            (project / 'global.json').write_bytes(config)
        values, errors = {}, []

        @result_callback
        def capture(key, value):
            values[key] = value.decode('utf-8') if value else None

        @error_callback
        def capture_error(value):
            if value:
                errors.append(value.decode('utf-8'))

        previous = set_error(ctypes.cast(capture_error, ctypes.c_void_p))
        try:
            # The native API prints installed marker names on failed matching.
            # Keep those matching-only fixtures out of the qualification log.
            with tempfile.TemporaryFile() as output:
                flush(None)
                saved = os.dup(1)
                try:
                    os.dup2(output.fileno(), 1)
                    code = resolve(bytes(host), bytes(project), 0, capture)
                finally:
                    flush(None)
                    os.dup2(saved, 1)
                    os.close(saved)
        finally:
            set_error(previous)
        resolved = Path(values[0]).name if values.get(0) else None
        expected = case.get('nativeExpectedVersion', case['expectedVersion'])
        state = case.get('nativeState', 'not_found' if config is None else 'valid')
        require(resolved == expected and values.get(3) == state
                and (code == 0) == (resolved is not None),
                'Native SDK reference differs for ' + case['name'] + ': '
                + json.dumps(dict(code=code, version=resolved, state=values.get(3), errors=errors)))
        rows.append(dict(name=case['name'], expectedVersion=case['expectedVersion'],
                         nativeExpectedVersion=expected, resolvedVersion=resolved,
                         nativeState=state, exitCode=code, failClosed=case.get('failClosed', False)))
    return dict(schemaVersion=1, scope=REFERENCE_SCOPE, status='passed',
                fixtureSha256=hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
                fixtureKind='empty-SDK-markers-matching-only-no-SDK-execution',
                library=dict(relativePath=library_path.relative_to(payload).as_posix(),
                             size=library_path.stat().st_size,
                             sha256=hashlib.sha256(library_path.read_bytes()).hexdigest()),
                cases=rows)


def validate_reference_evidence(value):
    """Bind a native proof to the exact shared C#/native matching fixture."""
    fixture = reference_fixture()
    require(value['schemaVersion'] == 1 and value['scope'] == REFERENCE_SCOPE and value['status'] == 'passed'
            and value['fixtureSha256'] == hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
            and value['fixtureKind'] == 'empty-SDK-markers-matching-only-no-SDK-execution',
            'Native project-SDK reference has another fixture or scope')
    library = value['library']
    require(re.fullmatch(r'host/fxr/[0-9]+\.[0-9]+\.[0-9]+/libhostfxr\.so', library['relativePath'])
            and type(library['size']) is int and library['size'] > 0
            and re.fullmatch('[a-f0-9]{64}', library['sha256']), 'Native SDK reference library identity is incomplete')
    require(len(value['cases']) == len(fixture['cases']), 'Native project-SDK reference cases are incomplete')
    for case, row in zip(fixture['cases'], value['cases']):
        expected = case.get('nativeExpectedVersion', case['expectedVersion'])
        state = case.get('nativeState', 'not_found' if configuration_bytes(case) is None else 'valid')
        require(row['name'] == case['name'] and row['expectedVersion'] == case['expectedVersion']
                and row['nativeExpectedVersion'] == row['resolvedVersion'] == expected
                and row['nativeState'] == state and row['failClosed'] is case.get('failClosed', False)
                and type(row['exitCode']) is int and (row['exitCode'] == 0) == (expected is not None),
                'Native SDK reference case differs from the shared resolver fixture')
    return len(value['cases'])


def _snapshot(directory):
    rows = []
    for path in sorted(Path(directory).rglob('*')):
        name = path.relative_to(directory).as_posix()
        if path.is_symlink(): rows.append((name, 'link', os.readlink(path)))
        elif path.is_file(): rows.append((name, 'file', hashlib.sha256(path.read_bytes()).hexdigest()))
        elif path.is_dir(): rows.append((name, 'directory'))
        else: raise ValueError('Unexpected special file in project fixture')
    return hashlib.sha256(json.dumps(rows, separators=(',', ':')).encode()).hexdigest()


def owned_sdk_state(root):
    root = Path(root)
    paths = [root / 'owner', root / 'selection.json']
    for namespace in ('toolchains', 'toolchains-v2'):
        paths.extend((root / namespace).glob('*/*/*.json'))
        paths.extend((root / namespace).glob('*/*/*.asc'))
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths) if path.is_file() and not path.is_symlink()}


def qualify_project_selection(root, binary, sdk, baseline, workspace, execute):
    """Run real admitted SDKs offline; execute is the harness's unprivileged runner."""
    root, binary, workspace = Path(root), Path(binary), Path(workspace)
    require(not workspace.exists() and sdk['sdkVersion'] != baseline['sdkVersion'],
            'Project selection needs a fresh workspace and two different admitted SDKs')
    workspace.mkdir(parents=True)
    alias = root / 'bin/cbodotnet'
    lower, higher = sdk['sdkVersion'], baseline['sdkVersion']
    series = '.'.join(lower.split('.')[:2])
    lower_exact = lower + '-r' + str(sdk['revision'])
    higher_exact = higher + '-r' + str(baseline['revision'])
    state_before = owned_sdk_state(root)
    execute(root, [binary, 'doctor'])
    rows = []

    def invoke(directory, arguments):
        return execute(root, ['sh', '-ec', 'cd "$1"; shift; exec "$@"',
                              'cbodotnetup-project', str(directory), *arguments], check=False)

    def project(name, configuration=None, *, raw=None):
        directory = workspace / name
        directory.mkdir()
        if raw is not None or configuration is not None:
            (directory / 'global.json').write_text(raw if raw is not None else json.dumps(configuration), encoding='utf-8')
        return directory

    def observe(name, directory, expected, arguments=None, *, error=None):
        before = _snapshot(workspace)
        result = invoke(directory, arguments or [alias, '--version'])
        require(_snapshot(workspace) == before, 'SDK selection modified project fixture: ' + name)
        if expected is None:
            require(result.returncode != 0 and not result.stdout.strip()
                    and (error is None or error in result.stderr),
                    'Invalid project SDK request was accepted or diagnosed without context: ' + name
                    + '\n' + result.stdout[-1000:] + '\n' + result.stderr[-2000:])
        else:
            require(result.returncode == 0 and result.stdout == expected + '\n'
                    and result.stderr == 'Community Build of .NET (built by .NET Dev)\n',
                    'Project SDK selected another installation or lost branding: ' + name
                    + '\n' + result.stdout[-1000:] + '\n' + result.stderr[-2000:])
        rows.append(dict(name=name, status='passed', expectedVersion=expected, exitCode=result.returncode))

    no_project = project('without-project')
    observe('highest-without-project', no_project, higher)
    pinned = project('pinned', dict(sdk=dict(version=lower, rollForward='disable')))
    nested = pinned / 'nested/child'; nested.mkdir(parents=True)
    observe('nearest-ancestor', nested, lower)
    observe('exact-project-pin', pinned, lower)
    nearest = pinned / 'nearest'; nearest.mkdir(); (nearest / 'global.json').write_text('{}')
    observe('nearest-file-boundary', nearest, higher)
    prior = lower.rsplit('.', 1)[0] + '.' + str(int(lower.rsplit('.', 1)[1]) - 1)
    observe('patch-roll-forward', project('patch', dict(sdk=dict(version=prior, rollForward='latestPatch'))), lower)
    unavailable_band = lower.rsplit('.', 1)[0] + '.' + str((int(lower.rsplit('.', 1)[1]) // 100 + 1) * 100)
    observe('major-roll-forward', project('major', dict(sdk=dict(version=unavailable_band, rollForward='major'))), higher)
    observe('feature-band-rejection', project('band', dict(sdk=dict(version=unavailable_band, rollForward='patch'))), None, error='global.json')
    observe('missing-sdk-no-install', project('missing', dict(sdk=dict(version='99.0.999', rollForward='disable'))), None, error='cbodotnetup list --available')
    cached = json.loads((root / 'cache/v2/catalog.json').read_bytes())
    missing_admitted = next((release for release in cached['sdks'] if release['rid'] == sdk['rid']
                             and release['sdkVersion'] not in (lower, higher)
                             and not release['requiresLegacyProvider']
                             and release['sdkVersion']+'-r'+str(release['revision'])+'/'+release['rid'] not in cached['revoked']), None)
    require(missing_admitted is not None, 'A third admitted, uninstalled SDK is required for actionable missing-project proof')
    observe('missing-admitted-sdk-no-install', project('missing-admitted', dict(sdk=dict(
            version=missing_admitted['sdkVersion'], rollForward='disable'))), None,
            error='cbodotnetup install '+missing_admitted['sdkVersion'])
    observe('malformed-fail-closed', project('malformed', raw='{"sdk":'), None, error='global.json')
    observe('trailing-comma-fail-closed', project('trailing-comma', raw='{"sdk":{"version":"'+lower+'",},}'), None, error='global.json')
    observe('comments', project('comments', raw='{// permitted comment\n"sdk":{/*project*/"version":"'+lower+'"}}'), lower)
    observe('prerelease-policy', project('stable', dict(sdk=dict(version=lower, allowPrerelease=False))), lower)
    observe('host-paths', project('host-paths', dict(sdk=dict(version=lower, paths=['$host$']))), lower)
    external = project('external-sdk-root')
    unqualified = external / 'sdk' / higher
    unqualified.mkdir(parents=True)
    (unqualified / 'dotnet.dll').write_text('Unqualified marker; this SDK must never execute.\n')
    for name, paths in [('relative-path-rejection', ['../external-sdk-root']),
                        ('absolute-path-rejection', [str(external)]),
                        ('empty-paths-rejection', [])]:
        observe(name, project(name, dict(sdk=dict(version=lower, paths=paths))), None, error='sdk.paths')
    linked = workspace / 'linked-sdk-root'; linked.symlink_to(external, target_is_directory=True)
    observe('symlink-path-rejection', project('linked-path', dict(sdk=dict(version=lower, paths=[str(linked)]))), None, error='sdk.paths')
    linked_global = project('linked-global'); (linked_global / 'global.json').symlink_to(pinned / 'global.json')
    observe('symlink-global-rejection', linked_global, None, error='symbolic link')
    high_project = project('high-pin', dict(sdk=dict(version=higher, rollForward='disable')))
    observe('versioned-alias-precedence', high_project, lower, [root / ('bin/cbodotnet-' + series), '--version'])
    observe('explicit-run-precedence', pinned, higher, [binary, 'run', higher_exact, '--', '--version'])
    observe('explicit-run-lower-precedence', high_project, lower, [binary, 'run', lower_exact, '--', '--version'])
    observe('runtime-options-sdk-rejection', pinned, None,
            [alias, '--roll-forward', 'LatestMajor', '--version'], error='Runtime options require an explicit application')
    for name, arguments in [('missing-app-runtime-dispatch', ['missing.dll']),
                             ('runtime-options-missing-app', ['--roll-forward', 'LatestMajor', 'missing.dll'])]:
        before = _snapshot(workspace)
        runtime = invoke(workspace / 'missing', [binary, 'run', higher_exact, '--', *arguments])
        require(runtime.returncode == 129 and not runtime.stdout.strip()
                and "The application to execute does not exist: 'missing.dll'" in runtime.stderr
                and _snapshot(workspace) == before,
                'Missing application reentered SDK resolution instead of native runtime dispatch: ' + name
                + '\n' + runtime.stdout[-1000:] + '\n' + runtime.stderr[-2000:])
        rows.append(dict(name=name, status='passed', expectedVersion=higher, exitCode=runtime.returncode))
    before = _snapshot(workspace)
    forwarded = invoke(pinned, [binary, 'run', lower_exact, '--', '--available'])
    require(forwarded.returncode != 0 and 'dotnet---available' in forwarded.stdout+forwarded.stderr
            and _snapshot(workspace) == before,
            'An SDK argument was intercepted as an installer refresh or changed project files: '
            + forwarded.stdout[-2000:] + forwarded.stderr[-2000:])
    rows.append(dict(name='sdk-arguments-offline', status='passed', expectedVersion=lower, exitCode=forwarded.returncode))

    before = _snapshot(workspace)
    information = invoke(pinned, [alias, '--cbodotnet-info'])
    require(information.returncode == 0 and _snapshot(workspace) == before, 'Project identity command failed or changed files')
    identity = json.loads(information.stdout)
    require(identity['sdkVersion'] == lower and identity['packageRevision'] == sdk['revision']
            and identity['sourceManifestSha256'] == sdk['sourceManifestSha256']
            and identity['qualifiedPayloadModified'] is False, 'Project identity differs from admitted SDK bytes')
    info = invoke(pinned, [alias, '--info'])
    require(info.returncode == 0 and _snapshot(workspace) == before
            and re.search(r'^\s*Version:\s+' + re.escape(lower) + r'\s*$', info.stdout, re.MULTILINE),
            'Project SDK --info did not describe the selected SDK: ' + info.stdout[-2000:] + info.stderr[-2000:])
    rows.append(dict(name='sdk-info-selection', status='passed', expectedVersion=lower, exitCode=0))

    msbuild = pinned / 'msbuild'; msbuild.mkdir()
    (msbuild / 'global.json').write_text(json.dumps(dict(sdk=dict(version=higher, rollForward='disable'))))
    project_file = msbuild / 'Inspect.csproj'
    project_text = ('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net'+lower.split('.')[0]
                            +'.0</TargetFramework></PropertyGroup><Target Name="InspectCommunitySdk">'
                            '<Message Importance="high" Text="CBODOTNETUP_SDK=$(NETCoreSdkVersion)" />'
                            '<Message Importance="high" Text="CBODOTNETUP_PATH=$(MSBuildSDKsPath)" />'
                            '</Target></Project>')
    project_file.write_text(project_text)
    plain_project = pinned / 'Inspect.csproj'; plain_project.write_text(project_text)
    for name, command, release, entry in [('msbuild-owned-sdk', [alias], sdk, plain_project),
                                          ('msbuild-project-conflict', [alias], sdk, project_file),
                                          ('msbuild-explicit-override', [binary, 'run', higher_exact, '--'], baseline, project_file)]:
        before = _snapshot(workspace)
        launch = [*command, 'msbuild', entry, '-t:InspectCommunitySdk', '-nologo', '-verbosity:minimal']
        if name == 'msbuild-owned-sdk':
            launch = ['env', 'MSBUILDSDKSPATH=/untrusted/sdk', 'MSBUILDEXTENSIONSPATH=/untrusted/sdk',
                      'dotnet_msbuild_sdk_resolver_cli_dir=/untrusted/sdk', *launch]
        result = invoke(pinned, launch)
        expected = release['sdkVersion']
        selected = root / 'toolchains-v2' / (expected + '-r' + str(release['revision'])) / release['rid'] / 'content' / release['archiveRoot'] / 'payload/sdk' / expected / 'Sdks'
        require(result.returncode == 0 and 'CBODOTNETUP_SDK='+expected in result.stdout
                and 'CBODOTNETUP_PATH='+str(selected) in result.stdout and _snapshot(workspace) == before,
                'MSBuild re-resolved another SDK or changed project files: ' + name
                + '\n' + result.stdout[-3000:] + '\n' + result.stderr[-3000:])
        rows.append(dict(name=name, status='passed', expectedVersion=expected, exitCode=0))
    execute(root, [binary, 'doctor'])
    require(owned_sdk_state(root) == state_before, 'Project selection changed installed receipts or active selections')
    proof = dict(schemaVersion=1, scope=PROJECT_SCOPE, status='passed', sdkVersion=lower, baselineVersion=higher,
                network='none', checks=dict.fromkeys(PROJECT_CHECKS, 'passed'), cases=rows,
                identity=identity, projectFilesSha256=_snapshot(workspace),
                missingAdmittedSdk=dict(sdkVersion=missing_admitted['sdkVersion'], revision=missing_admitted['revision'],
                                        rid=missing_admitted['rid'], sourceManifestSha256=missing_admitted['sourceManifestSha256']),
                projectFilesUnchanged=True, ownedStateUnchanged=True, ownedPayloadsUnchanged=True,
                ownedPayloadVerification='signed-receipt-and-inventory-doctor-before-and-after')
    validate_project_evidence(proof, sdk, baseline, cached)
    return proof


def validate_project_evidence(value, sdk, baseline, catalog=None):
    require(value['schemaVersion'] == 1 and value['scope'] == PROJECT_SCOPE and value['status'] == 'passed'
            and value['sdkVersion'] == sdk['sdkVersion'] and value['baselineVersion'] == baseline['sdkVersion']
            and value['network'] == 'none' and value['checks'] == dict.fromkeys(PROJECT_CHECKS, 'passed')
            and value['projectFilesUnchanged'] is True and value['ownedStateUnchanged'] is True
            and value['ownedPayloadsUnchanged'] is True
            and value['ownedPayloadVerification'] == 'signed-receipt-and-inventory-doctor-before-and-after'
            and re.fullmatch('[a-f0-9]{64}', value['projectFilesSha256']), 'Project SDK native proof is incomplete')
    identity = value['identity']
    require(identity['sdkVersion'] == sdk['sdkVersion'] and identity['packageRevision'] == sdk['revision']
            and identity['targetRid'] == sdk['rid'] and identity['sourceManifestSha256'] == sdk['sourceManifestSha256']
            and identity['qualifiedPayloadModified'] is False, 'Project SDK evidence differs from admitted source/revision/RID')
    missing = value['missingAdmittedSdk']
    require(missing['sdkVersion'] not in (sdk['sdkVersion'], baseline['sdkVersion'])
            and VERSION.fullmatch(missing['sdkVersion']) and missing['rid'] == sdk['rid']
            and type(missing['revision']) is int and missing['revision'] > 0
            and re.fullmatch('[a-f0-9]{64}', missing['sourceManifestSha256']),
            'Missing-project diagnostic must refer to a third admitted uninstalled SDK')
    if catalog is not None:
        admitted = [release for release in catalog['sdks'] if all(release[key] == missing[key] for key in missing)]
        require(len(admitted) == 1 and not admitted[0]['requiresLegacyProvider']
                and missing['sdkVersion']+'-r'+str(missing['revision'])+'/'+missing['rid'] not in catalog['revoked'],
                'Actionable missing SDK differs from the authenticated admitted catalog')
    expected = {name: sdk['sdkVersion'] for name in ('nearest-ancestor', 'exact-project-pin', 'patch-roll-forward',
                'comments', 'prerelease-policy', 'host-paths', 'versioned-alias-precedence',
                'explicit-run-lower-precedence', 'sdk-info-selection', 'sdk-arguments-offline',
                'msbuild-owned-sdk', 'msbuild-project-conflict')}
    expected.update(dict.fromkeys(('highest-without-project', 'nearest-file-boundary', 'major-roll-forward',
                                  'explicit-run-precedence', 'msbuild-explicit-override',
                                  'missing-app-runtime-dispatch', 'runtime-options-missing-app'), baseline['sdkVersion']))
    expected.update(dict.fromkeys(('feature-band-rejection', 'missing-sdk-no-install', 'missing-admitted-sdk-no-install', 'malformed-fail-closed',
                'trailing-comma-fail-closed', 'relative-path-rejection', 'absolute-path-rejection',
                'empty-paths-rejection', 'symlink-path-rejection', 'symlink-global-rejection',
                'runtime-options-sdk-rejection'), None))
    rows = value['cases']
    require(len(rows) == len(expected) and {row['name'] for row in rows} == set(expected),
            'Project SDK proof cases are missing, duplicated or unexpected')
    for row in rows:
        native_missing = row['name'] in ('missing-app-runtime-dispatch', 'runtime-options-missing-app')
        require(row['status'] == 'passed' and row['expectedVersion'] == expected[row['name']]
                and type(row['exitCode']) is int
                and (row['exitCode'] == 129 if native_missing else
                     (row['exitCode'] == 0) == (row['expectedVersion'] is not None and row['name'] != 'sdk-arguments-offline')),
                'Project SDK case outcome differs from its admitted installed SDK inventory')
    return len(rows)
