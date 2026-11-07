"""Native Alpine NativeAOT builds and actual SDK-free installer qualification.

Only matching-CPU Linux containers produce native evidence. Host-side helpers
authenticate inputs before launching containers; disposable consumers are the
only processes permitted to install system APK baselines.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import subprocess
import tarfile
import time

import musl_archive as ARCHIVE
import cbodotnetup_musl as MUSL
from downstream_release import descriptor, encoded, ordinary_file, require
from musl_contract import ARCHITECTURES

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'releases/cbodotnetup-policy.json'
USER = 'cbot-musl'
UID = 10001
CONTAINERFILE = ROOT / 'containers/cbodotnetup-musl.Containerfile'
COMMON_PACKAGES = dict(ARCHIVE.RUNTIME_PACKAGES, python3='3.14.10-r1',
    gpg='2.4.9-r1', gpgv='2.4.9-r1', binutils='2.45.1-r1', coreutils='9.11-r0', **{'su-exec': '0.3-r0'})
BUILD_PACKAGES = dict(COMMON_PACKAGES, **{'build-base': '0.5-r4', 'clang20': '20.1.8-r3',
    'lld20': '20.1.8-r1', 'zlib-dev': '1.4-r0'})
CHECKS = MUSL.CHECKS


def load(path):
    return json.loads(ordinary_file(Path(path)).read_bytes())


def save(path, value):
    Path(path).write_bytes(encoded(value))


def release_tools():
    # Lazy import avoids a release orchestration/module import cycle.
    import cbodotnetup_release
    return cbodotnetup_release


def native_host(arch, engine='docker'):
    require(arch in ARCHITECTURES and platform.system() == 'Linux'
        and platform.machine() == ('x86_64' if arch == 'x64' else 'aarch64'),
        'A matching native Linux CPU is required for musl installer evidence')
    observed = run([engine, 'info', '--format', '{{.Host.Arch}}' if engine == 'podman' else '{{.Architecture}}']).strip()
    require(observed in ({'x86_64', 'amd64'} if arch == 'x64' else {'aarch64', 'arm64'}),
        'The container server must use the same native CPU')


def engine_name():
    value = os.environ.get('CBODOTNETUP_CONTAINER_ENGINE', 'docker')
    require(value in {'docker', 'podman'}, 'Only reviewed native container engines are supported')
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        require(value == 'docker', 'Release CI requires default-policy native Docker')
    return value


def run(arguments, *, capture=True, **kwargs):
    result = subprocess.run(list(map(str, arguments)), check=False, text=True,
        stdout=subprocess.PIPE if capture else None, stderr=subprocess.STDOUT if capture else None, **kwargs)
    require(result.returncode == 0, 'Native musl command failed: ' + str(arguments[0])
        + ('\n' + (result.stdout or '')[-9000:] if capture else ' (exit ' + str(result.returncode) + ')'))
    return result.stdout if capture else ''


def fresh(path):
    path = Path(path).absolute()
    require(path.parent.is_dir() and not path.exists() and not path.is_symlink()
        and not any(parent.is_symlink() for parent in path.parents), 'A fresh ordinary workspace is required')
    path.mkdir(mode=0o755)
    return path


def profile(arch):
    require(arch in ARCHITECTURES, 'Unknown musl installer architecture')
    value = load(ROOT / f'profiles/dotnet-10.0.403-linux-musl-{arch}.json')
    require(value['target'] == dict(rid=ARCHITECTURES[arch]['rid'], libc='musl')
        and value['container']['version'] == '3.24.4', 'Unreviewed musl toolchain profile')
    return value


def prepare_context(arch, destination):
    specification = importlib.util.spec_from_file_location('installer_musl_sdk', ROOT / 'scripts/musl-sdk.py')
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    selected = profile(arch)
    module.prepare_image_context(selected, destination)
    shutil.copyfile(CONTAINERFILE, destination / 'Containerfile')
    return selected


def image(arch, workspace, *, build=False):
    engine = engine_name()
    native_host(arch, engine)
    selected = prepare_context(arch, workspace / 'image-context')
    packages = BUILD_PACKAGES if build else COMMON_PACKAGES
    require(all(re.fullmatch(r'[a-zA-Z0-9+_.-]+', name)
        and re.fullmatch(r'[a-zA-Z0-9+_.-]+', version) for name, version in packages.items()),
        'Unsafe Alpine package version pin')
    tag = 'localhost/cbodotnetup-musl-' + ('build' if build else 'consumer') + ':' + arch + '-' + str(time.time_ns())
    arguments = [engine, 'build', '--pull=false', '-t', tag,
        '--build-arg', 'BASE_IMAGE=' + ARCHIVE.BASES[arch],
        '--build-arg', 'MAIN_INDEX_SHA256=' + selected['apkIndexes']['main']['sha256'],
        '--build-arg', 'COMMUNITY_INDEX_SHA256=' + selected['apkIndexes']['community']['sha256'],
        '--build-arg', 'APK_PACKAGES=' + ' '.join(name + '=' + version for name, version in packages.items()),
        '-f', workspace / 'image-context/Containerfile', workspace / 'image-context']
    run(arguments, capture=False)
    info = json.loads(run([engine, 'image', 'inspect', tag]))[0]
    require(info['Architecture'] == ('amd64' if arch == 'x64' else 'arm64') and info['Os'] == 'linux',
        'The prepared musl installer image must match the native CPU')
    image_id = info['Id']
    if re.fullmatch(r'[a-f0-9]{64}', image_id): image_id = 'sha256:' + image_id
    require(re.fullmatch(r'sha256:[a-f0-9]{64}', image_id), 'Exact native build image content identity is required')
    return engine, tag, image_id


def build_inputs(arch):
    selected = profile(arch)
    names = ['scripts/cbodotnetup_musl_native.py', 'scripts/cbodotnetup_musl.py',
        'scripts/musl-sdk.py', 'scripts/musl_archive.py', 'scripts/seed-musl-apk-cache.sh',
        'containers/cbodotnetup-musl.Containerfile', f'profiles/dotnet-10.0.403-linux-musl-{arch}.json']
    names += [row['snapshotPath'] for row in selected['apkIndexes'].values()]
    return {name: hashlib.sha256(ordinary_file(ROOT / name).read_bytes()).hexdigest() for name in names}


def prepare_sdk(arch, workspace):
    from cbodotnetup_musl import authenticated_musl_sdk
    archive, proof = authenticated_musl_sdk(arch, workspace / 'sdk-input')
    sdk_root = workspace / 'build-sdk'
    ARCHIVE.tools().extract_sdk(archive, sdk_root)
    root = sdk_root / proof['archiveRoot'] / 'payload'
    ordinary_file(root / 'dotnet')
    require(proof['targetRid'] == ARCHITECTURES[arch]['rid'], 'Authenticated build SDK has another RID')
    return root, proof


def copy_sources(workspace):
    source = workspace / 'source'
    (source / 'tools').mkdir(parents=True)
    for name in ('cbodotnetup', 'cbodotnetup.Tests'):
        shutil.copytree(ROOT / 'tools' / name, source / 'tools' / name, ignore=shutil.ignore_patterns('bin', 'obj'))
    shutil.copyfile(ROOT / 'tools/global.json', source / 'tools/global.json')
    (source / 'releases').mkdir()
    shutil.copyfile(ROOT / 'releases/downstream-signing-key.asc', source / 'releases/downstream-signing-key.asc')
    # Restore sources are explicit and credential-free. Exact framework/compiler
    # versions and all actual package hashes are retained in the output.
    (source / 'NuGet.Config').write_text('<configuration><packageSources><clear />'
        '<add key="nuget.org" value="https://api.nuget.org/v3/index.json" />'
        '</packageSources></configuration>\n', encoding='utf-8')
    return source


def build_identity(workspace):
    """Rootful container servers still compile and test as an ordinary user."""
    uid, gid = (os.getuid(), os.getgid()) if os.getuid() != 0 else (UID, UID)
    if os.getuid() == 0:
        os.chown(workspace, uid, gid)
        for name in ('source', 'output'):
            directory = workspace / name
            if directory.exists():
                os.chown(directory, uid, gid)
                for path in directory.rglob('*'):
                    if not path.is_symlink(): os.chown(path, uid, gid)
    return str(uid) + ':' + str(gid)


def build_script(rid, sdk, runtime, *, publish=True, output='/work/output', version=None):
    require(rid in {row['rid'] for row in ARCHITECTURES.values()} and re.fullmatch(r'10\.0\.[0-9]+', runtime),
        'An exact reviewed musl RID/runtime version is required')
    binary = 'cbodotnetup-' + rid
    require(output in {'/work/output', '/work/output/baseline'}
        and (version is None or re.fullmatch(r'0\.[0-9]+\.[0-9]+', version)), 'Unreviewed build output/version')
    version_option = '' if version is None else ' -p:Version=' + version
    script = f'''set -eu
export DOTNET_ROOT={shlex.quote(str(Path(sdk).parent))} DOTNET_CLI_HOME=/work/dotnet-home NUGET_PACKAGES=/work/nuget
export HOME=/work/dotnet-home DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_NOLOGO=1
mkdir -p "$HOME"
cd /work/source/tools/cbodotnetup
{shlex.quote(str(sdk))} run --project ../cbodotnetup.Tests --configuration Release -p:RuntimeFrameworkVersion={runtime}
'''
    if publish:
        script += f'''{shlex.quote(str(sdk))} publish --configuration Release --runtime {rid} --self-contained true --output {output} \\
  -p:RuntimeFrameworkVersion={runtime} -p:IlcPackageVersion={runtime} -p:IlcTreatWarningsAsErrors=true -p:RestorePackagesWithLockFile=true{version_option}
cp obj/project.assets.json {output}/native-package-inputs.json
cp packages.lock.json {output}/native-packages.lock.json
mv {output}/cbodotnetup {output}/{binary}
{output}/{binary} --version
python3 /project/scripts/cbodotnetup_musl_native.py record-build --arch {('x64' if rid.endswith('x64') else 'aarch64')} --output {output} --cache /work/nuget
'''
    return script


def source_check(arch, workspace):
    workspace = fresh(workspace)
    engine, tag, image_id = image(arch, workspace, build=True)
    sdk, proof = prepare_sdk(arch, workspace)
    copy_sources(workspace)
    sdk_path = Path('/work') / sdk.relative_to(workspace) / 'dotnet'
    command = [engine, 'run', '--rm', '--user', build_identity(workspace),
        '--cap-drop=ALL', '--security-opt=no-new-privileges', '-v', str(workspace) + ':/work',
        '-v', str(ROOT) + ':/project:ro', tag, 'sh', '-ec',
        build_script(ARCHITECTURES[arch]['rid'], sdk_path, load(POLICY)['nativeRuntime'], publish=False)]
    run(command, capture=False)
    report = dict(schemaVersion=1, kind='cbodotnetup-musl-source-check', status='passed', architecture=arch,
        rid=ARCHITECTURES[arch]['rid'], libc='musl', container=ARCHIVE.BASES[arch], imageId=image_id,
        authenticatedSdk=proof, sourceInputs=release_tools().tool_inputs(), buildInputs=build_inputs(arch))
    save(workspace / 'source-check.json', report)
    return report


def native_packages(cache, assets):
    """Bind every restored library to the actual downloaded bytes and origin."""
    rows = []
    for identity, record in sorted(assets['libraries'].items()):
        if record['type'] != 'package':
            continue
        name, version = identity.lower().split('/', 1)
        directory = Path(cache) / name / version
        package = ordinary_file(directory / (name + '.' + version + '.nupkg'))
        content = package.read_bytes()
        digest = hashlib.sha512(content).digest()
        metadata = load(directory / '.nupkg.metadata')
        # NuGet's content hash excludes package signature metadata. The archive
        # byte hash deliberately differs after author/repository signing.
        content_hash = record['sha512']
        require(isinstance(content_hash, str) and re.fullmatch(r'[A-Za-z0-9+/]{86}==', content_hash)
            and metadata.get('contentHash') == content_hash,
            'NuGet assets contentHash differs from restored package metadata')
        download_hash = base64.b64encode(digest).decode()
        require(ordinary_file(directory / (package.name + '.sha512')).read_text().strip() == download_hash,
            'NuGet download hash differs from actual archive bytes')
        origin = metadata['source']
        require(origin == 'https://api.nuget.org/v3/index.json', 'Unreviewed NativeAOT package origin')
        rows.append(dict(id=name, version=version, source=origin, **descriptor(package),
            sha512=hashlib.sha512(content).hexdigest(), downloadHash=download_hash, contentHash=content_hash))
    require(rows and any(row['id'] == 'microsoft.dotnet.ilcompiler' for row in rows),
        'Actual NativeAOT compiler packages are required')
    return rows


def record_build(arch, output, cache):
    """Runs as the ordinary native build user inside the pinned Alpine image."""
    ARCHIVE.native_guard(arch)
    output = Path(output)
    rid = ARCHITECTURES[arch]['rid']
    binary = output / ('cbodotnetup-' + rid)
    audit = ARCHIVE.audit_elf(output, arch, entrypoint=binary.name)
    require(audit['hostElfCount'] >= 1 and not audit['nonHostElfCount'], 'Native tool contains foreign ELF inputs')
    audit['scope'] = 'cbodotnetup-musl-native-tool-elf-closure'
    audit['staticArchiveScope'] = 'Published tool ELF and its complete native runtime dependency closure.'
    save(output / 'tool-elf-audit.json', audit)
    packages = native_packages(cache, load(output / 'native-package-inputs.json'))
    runtime = load(POLICY)['nativeRuntime']
    require(all(row['version'] == runtime for row in packages if row['id'] == 'microsoft.dotnet.ilcompiler'
        or row['id'].startswith('runtime.') and '.microsoft.dotnet.ilcompiler' in row['id']),
        'NativeAOT compiler/runtime inputs differ from the reviewed runtime pin')
    save(output / 'native-package-hashes.json', packages)
    notices = [('cbodotnet/LICENSE', ordinary_file(ROOT / 'LICENSE').read_text(encoding='utf-8'))]
    third_party = output / 'third-party'
    third_party.mkdir()
    for package in packages:
        directory = Path(cache) / package['id'] / package['version']
        for name in ('LICENSE.TXT', 'LICENSE.txt', 'LICENSE', 'THIRD-PARTY-NOTICES.TXT', 'THIRD-PARTY-NOTICES.txt', 'THIRD-PARTY-NOTICES'):
            path = directory / name
            if path.is_file():
                target = third_party / package['id'] / package['version'] / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
                notices.append((target.relative_to(output).as_posix(), path.read_text(encoding='utf-8')))
    require(any('NOTICES' in name for name, unused in notices), 'Actual NativeAOT runtime third-party notices are required')
    (output / (binary.name + '.LICENSE.txt')).write_text('\n\n'.join('===== ' + name + ' =====\n' + text
        for name, text in notices), encoding='utf-8')
    apk_root = Path('/cbodotnet-apks')
    toolchain = dict(baseImage=ARCHIVE.BASES[arch], apkInputs=[descriptor(path) for path in sorted(apk_root.glob('*.apk'))],
        indexes=[descriptor(path) for path in sorted(apk_root.glob('APKINDEX.*.tar.gz'))],
        installedPackages=(apk_root / 'installed-packages.txt').read_text().splitlines(),
        clang=run(['clang', '--version']).splitlines()[0], lld=run(['ld.lld', '--version']).strip())
    require(toolchain['apkInputs'] and len(toolchain['indexes']) == 2, 'Exact stock APK inputs must be retained')
    save(output / 'toolchain-inputs.json', toolchain)


def build_tool(arch, workspace, output=None):
    workspace = fresh(workspace)
    engine, tag, image_id = image(arch, workspace, build=True)
    sdk, proof = prepare_sdk(arch, workspace)
    copy_sources(workspace)
    built = fresh(workspace / 'output')
    sdk_path = Path('/work') / sdk.relative_to(workspace) / 'dotnet'
    command = [engine, 'run', '--rm', '--user', build_identity(workspace),
        '--cap-drop=ALL', '--security-opt=no-new-privileges', '-v', str(workspace) + ':/work',
        '-v', str(ROOT) + ':/project:ro', tag, 'sh', '-ec',
        build_script(ARCHITECTURES[arch]['rid'], sdk_path, load(POLICY)['nativeRuntime'])]
    run(command, capture=False)
    policy = load(POLICY)
    require(run([engine, 'run', '--rm', '--network=none', '--user', str(UID), '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '-v', str(built) + ':/tool:ro', tag,
        '/tool/cbodotnetup-' + ARCHITECTURES[arch]['rid'], '--version']).strip() == policy['version'],
        'Native binary version differs from reviewed release')
    baseline_command = command[:-4] + [tag, 'sh', '-ec', build_script(ARCHITECTURES[arch]['rid'], sdk_path,
        policy['nativeRuntime'], output='/work/output/baseline', version='0.5.0')]
    # A separate real NativeAOT compile provides the first musl recovery tool.
    # The source is identical and the assembly version override is recorded.
    run(baseline_command, capture=False)
    baseline_directory = built / 'baseline'
    require(run([engine, 'run', '--rm', '--network=none', '--user', str(UID), '--cap-drop=ALL',
        '--security-opt=no-new-privileges', '-v', str(baseline_directory) + ':/tool:ro', tag,
        '/tool/cbodotnetup-' + ARCHITECTURES[arch]['rid'], '--version']).strip() == '0.5.0',
        'Actual baseline NativeAOT binary did not use the explicit version override')
    shutil.copyfile(ROOT / 'LICENSE', built / 'LICENSE')
    baseline_provenance = dict(schemaVersion=1, kind='cbodotnetup-native-build', version='0.5.0',
        versionOverride='-p:Version=0.5.0', architecture=arch, rid=ARCHITECTURES[arch]['rid'], libc='musl',
        source=release_tools().source_identity(), sourceInputs=release_tools().tool_inputs(), buildInputs=build_inputs(arch),
        authenticatedSdk=proof, buildSdk=proof['archive'], nativeRuntime=policy['nativeRuntime'], container=ARCHIVE.BASES[arch], securityTests='passed',
        nativePackages=load(baseline_directory / 'native-package-hashes.json'),
        elfAudit=load(baseline_directory / 'tool-elf-audit.json'),
        toolchain=dict(load(baseline_directory / 'toolchain-inputs.json'), imageId=image_id),
        artifacts=[dict(descriptor(path), path=path.relative_to(baseline_directory).as_posix())
            for path in sorted(baseline_directory.rglob('*')) if path.is_file()])
    save(baseline_directory / 'provenance.json', baseline_provenance)
    baseline = dict(version='0.5.0', **{key: dict(descriptor(baseline_directory / name), path='baseline/' + name)
        for key, name in (('binary', 'cbodotnetup-' + ARCHITECTURES[arch]['rid']),
            ('notices', 'cbodotnetup-' + ARCHITECTURES[arch]['rid'] + '.LICENSE.txt'), ('provenance', 'provenance.json'))})
    report = dict(schemaVersion=1, kind='cbodotnetup-native-build', version=policy['version'], architecture=arch,
        rid=ARCHITECTURES[arch]['rid'], libc='musl', source=release_tools().source_identity(),
        buildSdk=proof['archive'], nativeRuntime=policy['nativeRuntime'], container=ARCHIVE.BASES[arch],
        securityTests='passed', sourceInputs=release_tools().tool_inputs(), buildInputs=build_inputs(arch),
        authenticatedSdk=proof, baseline=baseline, toolchain=dict(load(built / 'toolchain-inputs.json'), imageId=image_id),
        nativePackages=load(built / 'native-package-hashes.json'), elfAudit=load(built / 'tool-elf-audit.json'),
        artifacts=[dict(descriptor(path), path=path.relative_to(built).as_posix())
            for path in sorted(built.rglob('*')) if path.is_file()])
    save(built / 'build.json', report)
    if output is not None and Path(output).absolute() != built:
        destination = Path(output).absolute()
        require(not destination.exists() and not any(parent.is_symlink() for parent in [destination, *destination.parents]),
            'Refusing to replace a musl build output')
        shutil.copytree(built, destination)
    return report


def prepare_apk_baseline(arch, output):
    """Download only the exact project-signed public APK baseline for this CPU."""
    import musl_site
    from musl_distribution import download_asset
    from musl_package_native import approved_signer
    output = fresh(output)
    receipts = [row for row in musl_site.load_status()['publications']
        if row['identity']['channel'] == 'apk' and row['identity']['sdkVersion'] == '10.0.403'
        and row['identity']['packageRevision'] == 1]
    require(len(receipts) == 1, 'The exact signed public Community APK baseline is required')
    receipt = receipts[0]
    manifest = musl_site.authenticate_receipt(receipt)
    records = [row for row in manifest['records'] if row['architecture'] == arch]
    require(len(records) == 1, 'One matching native public APK record is required')
    record = records[0]
    key_name = record['repository']['keyName']
    assets = {row['name']: row for row in receipt['assets']}
    names = [key_name, 'apk-' + arch + '--APKINDEX.tar.gz']
    names += ['apk-' + arch + '--' + row['path'] for row in record['build']['packages']]
    for name in names:
        require(name in assets, 'Authenticated APK baseline asset is absent')
        destination = key_name if name == key_name else name.split('--', 1)[1]
        download_asset(assets[name]['url'], output / destination, assets[name])
    approved_signer(output / key_name)
    result = dict(manifestSha256=receipt['manifestSha256'], keyName=key_name,
        packages=record['build']['packages'], sourceManifestSha256=receipt['identity']['sourceManifestSha256'])
    save(output / 'baseline.json', result)
    return result


def user_arguments(arguments):
    environment = ['HOME=/home/' + USER, 'USER=' + USER, 'LOGNAME=' + USER,
        'DOTNET_CLI_HOME=/home/' + USER + '/cli', 'NUGET_PACKAGES=/home/' + USER + '/nuget',
        'DOTNET_CLI_TELEMETRY_OPTOUT=1', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1', 'DOTNET_NOLOGO=1',
        'DOTNET_CLI_UI_LANGUAGE=en-US', 'DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=true', 'LC_ALL=C',
        'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin']
    return ['su-exec', str(UID) + ':' + str(UID), 'env', '-i', *environment, *map(str, arguments)]


def user(arguments, *, check=True):
    result = subprocess.run(user_arguments(arguments), text=True, capture_output=True)
    if check:
        require(result.returncode == 0, 'Native musl installer command failed: ' + shlex.join(list(map(str, arguments)))
            + '\n' + result.stdout[-6000:] + result.stderr[-6000:])
    return result


def own(path, *, directory=False):
    path = Path(path)
    if directory:
        created = []
        parent = path
        while not parent.exists():
            created.append(parent)
            parent = parent.parent
        path.mkdir(parents=True, exist_ok=True)
        for parent in created: os.chown(parent, UID, UID)
    os.chown(path, UID, UID)
    return path


def baseline_inventories(home, bundle, arch):
    """Markers prove preservation only; retained foreign SDKs are never executed."""
    roots = [home / '.dotnet', home / '.local/share/dotnetup', home / 'unrelated-sdk',
        home / '.local/share/cbodotnetup']
    for path in roots:
        own(path, directory=True)
        marker = path / 'preservation-only.txt'
        marker.write_text('Unrelated retained state; not an executable SDK fixture.\n')
        own(marker)
    glibc_rid = 'linux-x64' if arch == 'x64' else 'linux-arm64'
    foreign = bundle / 'tools' / glibc_rid / ('cbodotnetup-' + glibc_rid)
    if foreign.is_file():
        retained = own(home / '.local/bin/retained-glibc', directory=True) / 'cbodotnetup'
        shutil.copyfile(foreign, retained)
        retained.chmod(0o755)
        own(retained)
        roots.append(retained.parent)
    api = ARCHIVE.tools()
    return roots, {str(path): api.snapshot(path) for path in roots}


def install_packages(state):
    """Mutations are confined to a disposable rootful native Alpine container."""
    require(os.geteuid() == 0 and (Path('/.dockerenv').exists() or Path('/run/.containerenv').exists()),
        'System baseline installation requires a disposable qualification container')
    # The cache contains the reviewed stock repository indexes. Resolve the
    # official Alpine package before switching to the signed project index.
    run(['apk', '--cache-dir', '/cbodotnet-apks', 'fetch', '--recursive', '--output', '/cbodotnet-apks',
        'dotnet10-sdk=10.0.303-r2'])
    run(['apk', '--cache-dir', '/cbodotnet-apks', 'add', '--no-network',
        *sorted(Path('/cbodotnet-apks').glob('*.apk')), 'dotnet10-sdk=10.0.303-r2'])
    official = Path('/usr/bin/dotnet')
    require(run([official, '--version']).strip() == '10.0.303', 'The independent official Alpine SDK differs')
    baseline = Path('/qualification/package-baseline')
    plan = load(baseline / 'baseline.json')
    target = Path('/etc/apk/keys') / plan['keyName']
    require(not target.exists(), 'Refusing to replace a system APK trust key')
    shutil.copyfile(baseline / plan['keyName'], target)
    run(['apk', '--no-network', '--repository', baseline / 'APKINDEX.tar.gz', 'add',
        *[row['name'] + '=' + row['version'] for row in plan['packages']]])
    official_snapshot = ARCHIVE.tools().snapshot(official.resolve().parent)
    community_snapshot = ARCHIVE.tools().snapshot(Path('/opt/cbodotnet'))
    return dict(version='10.0.303', owner=run(['apk', 'info', '--who-owns', official]).strip(),
        host=descriptor(official.resolve()), root=str(official.resolve().parent), tree=official_snapshot), community_snapshot


def current_paths(bundle, arch):
    rid = ARCHITECTURES[arch]['rid']
    return (bundle / 'catalog-musl.json', bundle / 'catalog-musl-baseline.json',
        bundle / 'tools' / rid / ('cbodotnetup-' + rid),
        bundle / 'tools' / rid / 'baseline' / ('cbodotnetup-' + rid))


def installed_payload(root, sdk):
    return root / 'toolchains-v4' / (sdk['sdkVersion'] + '-r' + str(sdk['revision'])) / sdk['rid'] / 'content' / sdk['archiveRoot'] / 'payload'


def container_install(bundle, arch, state, *, public=False):
    ARCHIVE.native_guard(arch)
    require(os.geteuid() == 0 and not Path('/usr/bin/dotnet').exists() and not Path('/opt/cbodotnet').exists(),
        'The consumer bootstrap must start without an SDK')
    bundle = Path(bundle)
    state = fresh(state)
    home = Path('/home') / USER
    binary = home / '.local/bin/cbodotnetup'
    root = home / '.local/share/cbodotnetup-musl'
    catalog_file, baseline_file, candidate, baseline_binary = current_paths(bundle, arch)
    catalog = load(catalog_file)
    sdk = next(row for row in catalog['sdks'] if row['rid'] == ARCHITECTURES[arch]['rid'])
    exact = sdk['sdkVersion'] + '-r' + str(sdk['revision'])
    preserved_roots, preserved = baseline_inventories(home, bundle, arch)
    baseline_bootstrap = ['python3', bundle / 'get-cbodotnetup.py', '--catalog-file', baseline_file]
    if not public:
        baseline_bootstrap += ['--binary-file', baseline_binary]
    user(baseline_bootstrap)
    require(user([binary, '--version']).stdout.strip() == '0.5.0', 'Actual musl baseline tool was not bootstrapped')
    require(not Path('/usr/bin/dotnet').exists(), 'SDK-free bootstrap installed a system SDK')
    # Also retain foreign namespaces inside the explicit manager root. These
    # preservation markers are deliberately non-executable and never admitted.
    for relative in ('toolchains-v2', 'toolchains-v3', 'cache/v2', 'cache/v3', 'bin'):
        retained = own(root / relative, directory=True)
        marker = retained / 'foreign-state-preservation-only.txt'
        marker.write_text('Retained glibc namespace; no SDK execution claimed.\n')
        own(marker)
        preserved[str(retained)] = ARCHIVE.tools().snapshot(retained)
    old_binary = descriptor(binary)['sha256']
    old_ownership = Path(str(binary) + '.ownership.json').read_bytes()
    old_notice = Path(str(binary) + '.LICENSE.txt').read_bytes()
    old_executable = binary.read_bytes()
    bootstrap = ['python3', bundle / 'get-cbodotnetup.py', '--catalog-file', catalog_file]
    manager = [binary, '--catalog', catalog_file]
    if public:
        user([*manager, 'self', 'update'])
    else:
        bootstrap += ['--binary-file', candidate]
        user(bootstrap)
    require(user([binary, '--version']).stdout.strip() == load(POLICY)['version'], 'Musl baseline migration did not activate current tool')
    official, community = install_packages(state)
    user([*manager, 'list', '--available'])
    user([binary, 'doctor'])
    require(user([*manager, 'install', '99.0.999'], check=False).returncode != 0, 'Unqualified SDK was accepted')
    bad = home / 'modified-catalog.json'
    bad.write_bytes(catalog_file.read_bytes() + b' ')
    shutil.copyfile(str(catalog_file) + '.asc', str(bad) + '.asc')
    require(user([binary, '--catalog', bad, 'list', '--available'], check=False).returncode != 0, 'Modified catalog signature was accepted')
    # Both negative cases use real signed inputs; no mislabeled binary is run.
    require(user(['python3', bundle / 'get-cbodotnetup.py', '--catalog-file', bundle / 'catalog.json'], check=False).returncode != 0,
        'Musl bootstrap admitted the glibc catalog')
    require(user([binary, '--catalog', bundle / 'catalog.json', 'list', '--available'], check=False).returncode != 0,
        'Musl native client admitted the glibc catalog')
    other_arch = 'aarch64' if arch == 'x64' else 'x64'
    other_binary = current_paths(bundle, other_arch)[2]
    require(user(['python3', bundle / 'get-cbodotnetup.py', '--catalog-file', catalog_file, '--binary-file', other_binary], check=False).returncode != 0,
        'Musl bootstrap admitted a tool built for the other CPU')
    require(descriptor(binary)['sha256'] == descriptor(candidate)['sha256'], 'Rejected bootstrap changed the current tool')
    log = state / 'interrupted-install.log'
    interrupted = False
    with log.open('w') as stream:
        child = subprocess.Popen(user_arguments([*manager, 'install', exact]), stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            deadline = time.monotonic() + 90
            while child.poll() is None and time.monotonic() < deadline:
                staging = root / 'staging-v4'
                if staging.is_dir() and any((path / 'source.json').is_file() for path in staging.iterdir() if path.is_dir()):
                    os.killpg(child.pid, signal.SIGKILL)
                    interrupted = True
                    break
                time.sleep(0.02)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=30)
    require(interrupted and not installed_payload(root, sdk).exists(), 'Interrupted download exposed a partial SDK root: ' + log.read_text()[-3000:])
    user([*manager, 'install', '--channel', '10.0'])
    payload = installed_payload(root, sdk)
    original_inventory = ARCHIVE.tools().snapshot(payload)
    user([*manager, 'install', exact])
    user([*manager, 'update'])
    require(ARCHIVE.tools().snapshot(payload) == original_inventory, 'Idempotent installation/channel update changed actual SDK bytes')
    # With one admitted SDK revision, rollback proves restoring its retained
    # activation after a lost selection, without inventing another SDK release.
    selection_file = root / 'selection-v4.json'
    selection = load(selection_file)
    selection['active'] = {}
    save(selection_file, selection)
    user([*manager, 'rollback', exact])
    require(load(selection_file)['active']['10.0'] == exact + '/' + sdk['rid'], 'Rollback did not restore retained SDK selection')
    require(user([binary, 'list']).stdout.strip() == exact + '/' + sdk['rid'], 'Installed musl SDK list identity differs')
    user([binary, 'shell', 'enable'])
    if not public:
        # Materialize the authenticated retained-tool transaction boundary for
        # candidate rollback. The public phase performs the actual HTTPS update.
        previous = Path(str(binary) + '.previous')
        previous.write_bytes(old_executable)
        previous.chmod(0o755)
        own(previous)
        previous_notice = Path(str(previous) + '.LICENSE.txt')
        previous_notice.write_bytes(old_notice)
        own(previous_notice)
        ownership_path = Path(str(binary) + '.ownership.json')
        ownership = load(ownership_path)
        ownership.update(previousVersion='0.5.0', previousSha256=old_binary)
        save(ownership_path, ownership)
    user([*manager, 'self', 'rollback'])
    require(user([binary, '--version']).stdout.strip() == '0.5.0', 'Tool rollback did not restore the actual baseline binary')
    require(user([binary, 'run', exact, '--', '--version']).stdout == sdk['sdkVersion'] + '\n', 'Tool rollback changed the installed SDK')
    if public:
        user([*manager, 'self', 'update'])
    else:
        user(bootstrap)
    require(user([binary, '--version']).stdout.strip() == load(POLICY)['version'], 'Musl tool could not re-upgrade')
    # Interrupt the executable/ownership receipt commit boundary. The signed
    # bootstrap must recognize current admitted bytes and repair stale ownership.
    ownership_path = Path(str(binary) + '.ownership.json')
    ownership_path.write_bytes(old_ownership)
    require(user([*manager, 'self', 'update'], check=False).returncode != 0, 'Stale executable ownership was accepted')
    user(bootstrap)
    user([binary, 'doctor'])
    require(ARCHIVE.tools().snapshot(payload) == original_inventory, 'Tool recovery changed actual SDK bytes')
    wrapper = home / 'run-owned-sdk.sh'
    wrapper.write_text('#!/bin/sh\nexec ' + shlex.quote(str(binary)) + ' run ' + shlex.quote(exact) + ' -- "$@"\n')
    wrapper.chmod(0o755)
    own(wrapper)
    save(state / 'installed.json', dict(sdk=sdk, exact=exact, rid=sdk['rid'], payload=str(payload), cli=str(wrapper),
        officialBaseline=official, communityInventory=community, preserved=preserved, preservedRoots=list(map(str, preserved_roots)),
        originalInventory=original_inventory, catalogSha256=descriptor(catalog_file)['sha256'],
        freezeSha256=descriptor(bundle / 'freeze.json')['sha256'], bootstrapSha256=descriptor(bundle / 'get-cbodotnetup.py')['sha256'],
        binarySha256=descriptor(binary)['sha256'], bootstrapBinarySource='public-https' if public else 'protected-frozen-candidate',
        migration=dict(status='passed', protocol='actual-musl-0.5.0-self-update-rollback-reupgrade' if public else 'musl-0.5.0-frozen-bootstrap-migration',
            oldVersion='0.5.0', newVersion=load(POLICY)['version'], oldBinarySha256=old_binary, sdkRollback='passed',
            interruptedOwnershipRecovery='passed', rollbackScope='Retained actual10.0.403-r1 selection restoration; tracked channel update idempotence',
            candidateToolRollback='Authenticated actual baseline bytes at retained-tool transaction boundary' if not public else 'Actual HTTPS self update retained baseline executable')))


def container_offline(bundle, arch, state):
    """Exercise every actual SDK probe with the container network disconnected."""
    import fcntl
    from sdk_runtime import validate_smoke_output
    ARCHIVE.native_guard(arch)
    require(not Path('/sys/class/net/eth0').exists(), 'Offline qualification still has a network interface')
    state = Path(state)
    installed = load(state / 'installed.json')
    sdk = installed['sdk']
    payload = Path(installed['payload'])
    home = Path('/home') / USER
    binary = home / '.local/bin/cbodotnetup'
    root = home / '.local/share/cbodotnetup-musl'
    exact = installed['exact']
    aliases = []
    for name in ('cbodotnet', 'cbodotnet-10.0'):
        alias = root / 'bin-v4' / name
        output = user([alias, '--version'])
        require(output.stdout == sdk['sdkVersion'] + '\n' and output.stderr == ARCHIVE.BRANDING['displayName'] + '\n',
            'User-local musl alias version/branding differs')
        info = json.loads(user([alias, '--cbodotnet-info']).stdout)
        require(info['targetRid'] == sdk['rid'] and info['sourceManifestSha256'] == sdk['sourceManifestSha256'],
            'User-local alias escaped the admitted musl source/root')
        aliases.append(info)
    plan = dict(sdkVersion=sdk['sdkVersion'], architecture=arch, libc='musl', targetRid=sdk['rid'])
    output = user(['sh', '-ec', ARCHIVE.full_smoke_script(plan, payload, Path(installed['cli']), home / 'offline-project')]).stdout
    functional = validate_smoke_output(output)
    require(output.count('published-full-icu-calendars-timezones-passed') >= 2, 'Full ICU/timezone probes did not execute through both DLL and apphost')
    functional.update(fullIcuCulturesAndCalendars='passed', timeZoneDatabase='passed')
    (state / 'functional.txt').write_text(output)
    user(['sh', '-ec', ARCHIVE.trust_probe_script(plan, payload, Path(installed['cli']), home / 'system-trust')])
    target_policy = []
    sdk_audit = ARCHIVE.audit_elf(payload, arch, target_policy)
    tool_audit_root = own(home / 'tool-audit', directory=True)
    shutil.copyfile(binary, tool_audit_root / binary.name)
    tool_audit = ARCHIVE.audit_elf(tool_audit_root, arch, entrypoint=binary.name)
    tool_audit['scope'] = 'cbodotnetup-musl-native-tool-elf-closure'
    save(state / 'elf-audit.json', sdk_audit)
    save(state / 'tool-elf-audit.json', tool_audit)
    notice = payload / 'LICENSE.txt'
    original = notice.read_bytes()
    notice.write_bytes(original + b'changed')
    require(user([binary, 'doctor'], check=False).returncode != 0, 'Doctor accepted modified installed SDK bytes')
    notice.write_bytes(original)
    with (root / 'operation.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(user([binary, 'list'], check=False).returncode != 0, 'Installer ignored another process operation lock')
    staging = root / 'staging-v4'
    require(any(staging.iterdir()), 'Actual interrupted install left no owned staging evidence')
    user([binary, 'gc'])
    require(not list(staging.iterdir()), 'Garbage collection did not remove interrupted owned staging')
    user([binary, 'doctor'])
    require(ARCHIVE.tools().snapshot(payload) == installed['originalInventory'], 'Offline probes changed the qualified SDK payload')
    save(state / 'offline.json', dict(status='passed', functionalChecks=functional, aliases=aliases,
        elfAudit=sdk_audit, toolElfAudit=tool_audit, trustProbe=str(home / 'system-trust/bin/Debug/net10.0/Trust.dll')))


def container_finish(bundle, arch, state):
    ARCHIVE.native_guard(arch)
    state = Path(state)
    installed = load(state / 'installed.json')
    offline = load(state / 'offline.json')
    home = Path('/home') / USER
    binary = home / '.local/bin/cbodotnetup'
    root = home / '.local/share/cbodotnetup-musl'
    trust = user([installed['cli'], offline['trustProbe']]).stdout
    require('system-trust-https-passed' in trust and re.search(r'system-root-count=[1-9][0-9]+', trust),
        'Actual SDK HTTPS did not use stock system trust')
    (state / 'system-trust.txt').write_text(trust)
    user([binary, 'remove', installed['exact']])
    require(user([binary, 'list']).stdout == '', 'Removed musl SDK remains advertised')
    result = user([root / 'bin-v4/cbodotnet', '--version'], check=False)
    require(result.returncode != 0 and not result.stdout, 'Empty owned selector fell back to another SDK')
    user([binary, 'shell', 'disable'])
    official = installed['officialBaseline']
    official_path = Path('/usr/bin/dotnet')
    require(run([official_path, '--version']).strip() == official['version']
        and run(['apk', 'info', '--who-owns', official_path]).strip() == official['owner']
        and descriptor(official_path.resolve()) == official['host']
        and ARCHIVE.tools().snapshot(Path(official['root'])) == official['tree'], 'User installer changed the independent official Alpine SDK')
    require(ARCHIVE.tools().snapshot(Path('/opt/cbodotnet')) == installed['communityInventory'], 'User installer changed the signed Community APK payload')
    require(run(['/usr/bin/cbodotnet', '--version']).strip() == installed['sdk']['sdkVersion'], 'Signed APK selector changed during user-local lifecycle')
    require(all(ARCHIVE.tools().snapshot(Path(name)) == snapshot for name, snapshot in installed['preserved'].items()),
        'User installer changed retained official/unrelated/glibc state')
    report = dict(schemaVersion=1, scope='cbodotnetup-native-installation', status='passed', variant='alpine-3.24',
        architecture=arch, libc='musl', rid=installed['rid'], native=True, baseImage=ARCHIVE.BASES[arch],
        orchestration=release_tools().source_identity(), networkForBuild='none', userId=UID,
        checks=dict.fromkeys(CHECKS, 'passed'), functionalChecks=offline['functionalChecks'], aliases=offline['aliases'],
        officialBaseline={key: value for key, value in official.items() if key != 'tree'},
        officialAfterRemoval=dict(version=official['version'], owner=official['owner'], completeTreePreserved=True),
        packageManagedCommunityIntegrity='unchanged', crossLibcStatePreserved=True,
        preservedStateScope='Complete inventory of independent official/APK trees and non-executable foreign/unrelated preservation markers; no foreign SDK execution',
        elfAudit=offline['elfAudit'], toolElfAudit=offline['toolElfAudit'],
        systemTrustHttps=dict(status='passed', url=ARCHIVE.trust_url(arch), outputSha256=hashlib.sha256(trust.encode()).hexdigest()),
        **{key: installed[key] for key in ('catalogSha256', 'freezeSha256', 'bootstrapSha256', 'binarySha256', 'bootstrapBinarySource', 'migration')})
    save(state / 'report.json', report)
    return report


def validate_qualification_report(value, bundle, arch, public=False):
    bundle = Path(bundle)
    catalog = load(bundle / 'catalog-musl.json')
    rid = ARCHITECTURES[arch]['rid']
    current = next(tool for tool in catalog['tools'] if tool['rid'] == rid and tool['version'] == load(POLICY)['version'])
    baseline = next(tool for tool in catalog['tools'] if tool['rid'] == rid and tool['version'] == '0.5.0')
    require(value.get('schemaVersion') == 1 and value.get('scope') == 'cbodotnetup-native-installation'
        and value.get('status') == 'passed' and value.get('variant') == 'alpine-3.24'
        and value.get('architecture') == arch and value.get('libc') == 'musl' and value.get('rid') == rid
        and value.get('native') is True and value.get('baseImage') == ARCHIVE.BASES[arch]
        and value.get('networkForBuild') == 'none' and value.get('userId') == UID
        and value.get('checks') == dict.fromkeys(CHECKS, 'passed')
        and value.get('functionalChecks') == dict.fromkeys(ARCHIVE.FUNCTIONAL_CHECKS, 'passed')
        and value.get('catalogSha256') == descriptor(bundle / 'catalog-musl.json')['sha256']
        and value.get('bootstrapSha256') == descriptor(bundle / 'get-cbodotnetup.py')['sha256']
        and value.get('freezeSha256') == descriptor(bundle / 'freeze.json')['sha256']
        and value.get('binarySha256') == current['binary']['sha256']
        and value.get('bootstrapBinarySource') == ('public-https' if public else 'protected-frozen-candidate')
        and value.get('packageManagedCommunityIntegrity') == 'unchanged' and value.get('crossLibcStatePreserved') is True,
        'Incomplete native musl installer qualification')
    migration = value.get('migration', {})
    require(migration.get('status') == 'passed' and migration.get('oldVersion') == '0.5.0'
        and migration.get('newVersion') == load(POLICY)['version'] and migration.get('oldBinarySha256') == baseline['binary']['sha256']
        and migration.get('protocol') == ('actual-musl-0.5.0-self-update-rollback-reupgrade' if public else 'musl-0.5.0-frozen-bootstrap-migration')
        and migration.get('sdkRollback') == migration.get('interruptedOwnershipRecovery') == 'passed',
        'Actual musl baseline migration and interrupted recovery evidence is required')
    for name in ('elfAudit', 'toolElfAudit'):
        audit = value.get(name, {})
        require(audit.get('status') == 'passed' and audit.get('native') is True and audit.get('libc') == 'musl'
            and audit.get('architecture') == arch and audit.get('targetRid') == rid
            and audit.get('elfFiles') and audit.get('stockLibraries'), 'Actual native SDK/tool complete ELF closure is required')
    tool_entries = [row for row in value['toolElfAudit']['elfFiles'] if row.get('path') == 'cbodotnetup']
    require(len(tool_entries) == 1 and tool_entries[0].get('sha256') == current['binary']['sha256']
        and tool_entries[0].get('interpreter') == ARCHITECTURES[arch]['interpreter']
        and tool_entries[0].get('machine') == ARCHITECTURES[arch]['elfMachine'],
        'Native tool ELF closure does not bind the actual published tool bytes/CPU/interpreter')
    require(value.get('systemTrustHttps', {}).get('status') == 'passed'
        and value['systemTrustHttps'].get('url') == ARCHIVE.trust_url(arch)
        and re.fullmatch(r'[a-f0-9]{64}', value['systemTrustHttps'].get('outputSha256', '')),
        'Actual stock-system-trust HTTPS evidence is required')
    return value


def qualify(bundle, arch, workspace, public=False):
    bundle = Path(bundle).resolve(strict=True)
    release_tools().verify_bundle(bundle)
    workspace = fresh(workspace)
    engine, tag, image_id = image(arch, workspace)
    prepare_apk_baseline(arch, workspace / 'package-baseline')
    mounts = ['-v', str(ROOT) + ':/project:ro', '-v', str(bundle) + ':/bundle:ro', '-v', str(workspace) + ':/qualification']
    environment = [part for name in ('GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT') for part in ('-e', name)]
    arguments = [engine, 'create', '--user', '0', '--cap-drop=ALL', '--cap-add=CHOWN', '--cap-add=SETUID', '--cap-add=SETGID',
        '--cap-add=DAC_OVERRIDE', '--cap-add=FOWNER', '--cap-add=KILL',
        '--security-opt=no-new-privileges', *mounts, *environment, tag, 'sleep', 'infinity']
    container = run(arguments).strip()
    common = ['python3', '/project/scripts/cbodotnetup_musl_native.py']
    options = ['--bundle', '/bundle', '--arch', arch, '--workspace', '/qualification/installed']
    try:
        run([engine, 'start', container])
        run([engine, 'exec', container, *common, 'container-install', *options, *(['--public'] if public else [])], capture=False)
        network = 'podman' if engine == 'podman' else 'bridge'
        run([engine, 'network', 'disconnect', network, container])
        run([engine, 'exec', container, *common, 'container-offline', *options], capture=False)
        run([engine, 'network', 'connect', network, container])
        run([engine, 'exec', container, *common, 'container-finish', *options], capture=False)
        report = load(workspace / 'installed/report.json')
        validate_qualification_report(report, bundle, arch, public)
        return report
    finally:
        subprocess.run([engine, 'rm', '--force', container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('build', 'source-check', 'qualify', 'container-install', 'container-offline', 'container-finish', 'record-build'):
        command = commands.add_parser(name)
        command.add_argument('--arch', choices=tuple(ARCHITECTURES), required=True)
        if name == 'record-build':
            command.add_argument('--output', type=Path, required=True)
            command.add_argument('--cache', type=Path, required=True)
        else:
            command.add_argument('--workspace', type=Path, required=True)
        if name in ('qualify', 'container-install', 'container-offline', 'container-finish'):
            command.add_argument('--bundle', type=Path, required=True)
        if name in ('qualify', 'container-install'):
            command.add_argument('--public', action='store_true')
    args = parser.parse_args()
    if args.command == 'build': result = build_tool(args.arch, args.workspace)
    elif args.command == 'source-check': result = source_check(args.arch, args.workspace)
    elif args.command == 'record-build': result = record_build(args.arch, args.output, args.cache)
    elif args.command == 'qualify': result = qualify(args.bundle, args.arch, args.workspace, args.public)
    elif args.command == 'container-install': result = container_install(args.bundle, args.arch, args.workspace, public=args.public)
    elif args.command == 'container-offline': result = container_offline(args.bundle, args.arch, args.workspace)
    else: result = container_finish(args.bundle, args.arch, args.workspace)
    if result is not None: print(json.dumps(dict(status=result.get('status', 'passed'), architecture=args.arch)))


if __name__ == '__main__':
    main()
