#!/usr/bin/env python3
"""Exercise real downstream installations and promote their verified CI outputs."""
import argparse
from datetime import datetime, timezone
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
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile

from distribution_contract import load_contract, validate_qualified_producers
from downstream_release import encoded, local_intake, package_record, receive_release, PREPUBLICATION_CHECKS
from downstream_release import stage_records
from sdk_runtime import audit_core3_http_libraries, runtime_policy, series as sdk_series, smoke_script, validate_host_rid, validate_smoke_output
from downstream_release import oci_wrapper_license

ROOT = Path(__file__).resolve().parents[1]
DEBIAN_BASE = 'debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4'
UBUNTU_BASE = 'ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852'
BRAND = 'Community Build of .NET (built by .NET Dev)'


def progress(message):
    print('distribution-ci: ' + message, flush=True)


def require(value, message):
    if not value:
        raise ValueError(message)


def selected_channels(args, *, native=False):
    mode = getattr(args, 'channel', 'deb-oci')
    require(mode in ({'deb-oci', 'deb', 'oci'} if native else {'deb-oci', 'oci'}),
            'Unsupported distribution channel selection')
    if mode == 'deb':
        return ('deb',)
    return ('oci',) if mode == 'oci' else ('deb', 'oci')


def validate_sdk_listing(output, version, sdk_root):
    require(output.splitlines() == [version + ' [' + sdk_root + '/sdk]'],
            'SDK listing includes another version/root or a global dotnet fallback')


def validate_image_config(image, architecture, sdk_root, labels=None):
    require(image.get('Architecture') == architecture and image.get('Os') == 'linux', 'Image architecture metadata mismatch')
    config = image.get('Config', {})
    require(config.get('WorkingDir') == '/work' and config.get('User') in {'app', '1654', '1654:1654'},
            'Consumer image must select its writable work directory and non-root app user')
    environment = dict(value.split('=', 1) for value in config.get('Env', []) if '=' in value)
    require(environment.get('PATH', '').split(':')[0] == '/usr/local/bin' and environment.get('DOTNET_ROOT') == sdk_root,
            'Image bypasses the branded command/root policy')
    require(not any(re.search(r'TOKEN|SECRET|PASSWORD|PRIVATE_KEY|^GITHUB_|^GH_|^AWS_', name, re.I) for name in environment),
            'Consumer image contains a credential environment key')
    require(config.get('Cmd') == ['cbodotnet', '--info'], 'Consumer image default command differs from the documented SDK CLI')
    if labels is not None:
        require(labels and all(config.get('Labels', {}).get(key) == value for key, value in labels.items()),
                'Consumer image labels differ from qualified source, license or notice metadata')
    return dict(architecture=architecture, user=config['User'], workdir=config['WorkingDir'], sdkRoot=sdk_root,
                labels=labels or {})


def inspect_consumer_files(reference, sdk_root, *, wrapper_license=None):
    versioned = '/usr/bin/cbodotnet-' + Path(sdk_root).name
    ownership = run(['docker', 'run', '--rm', '--user', '0', reference, 'stat', '-c', '%u:%g:%a',
                     sdk_root, sdk_root + '/dotnet', versioned, '/usr/bin/cbodotnet'])
    require(ownership.splitlines() == ['0:0:755'] * 4, 'SDK/command ownership or permissions changed')
    run(['docker', 'run', '--rm', reference, 'sh', '-ec',
         'for tool in gcc g++ clang make cmake git; do if command -v "$tool" >/dev/null 2>&1; then '
         'echo "Unexpected source-build toolchain program: $tool" >&2; exit 1; fi; done'])
    result = dict(ownership='root:root:0755', sourceBuildToolchain='absent', credentialEnvironment='absent')
    if wrapper_license is not None:
        require(wrapper_license == oci_wrapper_license(), 'OCI wrapper license descriptor differs from the project LICENSE')
        path = wrapper_license['path']
        value = run(['docker', 'run', '--rm', '--network', 'none', reference, 'sh', '-ec',
            'test -f ' + path + ' && test ! -L ' + path + ' && stat -c "%u:%g:%a" ' + path + ' && sha256sum ' + path])
        require(value.splitlines() == ['0:0:644', wrapper_license['sha256'] + '  ' + path],
                'OCI wrapper MIT license bytes, ownership or permissions differ')
        result['wrapperLicense'] = dict(wrapper_license, ownership='0:0:644', status='passed')
    if sdk_root in {'/opt/cbodotnet/3.0', '/opt/cbodotnet/3.1'}:
        result['nativeHttpLibraries'] = inspect_core3_image_http(reference, sdk_root)
    return result


def inspect_core3_image_http(reference, sdk_root):
    """Read the production image before any test bootstrap can install curl."""
    require(sdk_root in {'/opt/cbodotnet/3.0', '/opt/cbodotnet/3.1'}, 'Core3 production HTTP audit requires its exact isolated root')
    from legacy_compat import environment
    scoped = environment(dict(sdkVersion=Path(sdk_root).name + '.0', variant='debian-13'))
    prefix = shlex.join(['env', *[name + '=' + value for name, value in scoped.items()], 'ldd'])
    root = shlex.quote(sdk_root)
    script = ('set -eu\ntest "$(id -u)" = 1654\nfound=0\nfor file in '
        + root + '/shared/Microsoft.NETCore.App/*/System.Net.Http.Native.so '
        + root + '/shared/Microsoft.NETCore.App/*/libSystem.Net.Http.Native.so; do\n'
        '  [ -f "$file" ] || continue\n  found=1\n  printf "CBODOTNET_NATIVE_HTTP=%s\\n" "$file"\n'
        '  sha256sum "$file"\n  ' + prefix + ' "$file"\ndone\ntest "$found" = 1\n')
    output = run(['docker', 'run', '--rm', '--network', 'none', reference, 'sh', '-ec', script])
    sections = output.split('CBODOTNET_NATIVE_HTTP=')
    require(not sections[0].strip() and len(sections) > 1, 'Production Core3 image lacks its native HTTP audit')
    libraries = []; names = set()
    for section in sections[1:]:
        lines = section.splitlines()
        require(len(lines) >= 3, 'Incomplete production Core3 native HTTP proof')
        path = lines[0]
        require(re.fullmatch(re.escape(sdk_root) + r'/shared/Microsoft\.NETCore\.App/[0-9][A-Za-z0-9.+-]*/(?:lib)?System\.Net\.Http\.Native\.so', path)
                and path not in names, 'Unexpected or duplicated production Core3 native HTTP object')
        names.add(path)
        checksum = re.fullmatch(r'([a-f0-9]{64})  ' + re.escape(path), lines[1])
        linked = '\n'.join(lines[2:])
        provider = re.search(r'^\s*libcurl\.so\.4\s+=>\s+(/\S+)\s+\(', linked, re.MULTILINE)
        require(checksum is not None and 'not found' not in linked and provider is not None,
                'Production Core3 image lacks a resolved stock libcurl.so.4: ' + path + '\n' + linked)
        libraries.append(dict(path=path.removeprefix(sdk_root + '/'), sha256=checksum[1], ldd=linked,
                              libcurlProviderPath=provider[1]))
    return dict(status='passed', user='1654', network='none', libraries=libraries)


def qualified_oci_labels(index, architecture, manifest_bytes=None, contract=None, catalog=None):
    """Reconstruct labels from the independently pinned canonical SDK manifest."""
    from channel_packages import oci_labels
    match = re.fullmatch(r'([1-9][0-9]*\.[0-9]+\.[0-9]+)-debian13-r([1-9][0-9]*)', index.get('tag', ''))
    require(match is not None, 'An immutable Debian 13 SDK image tag is required')
    version, revision = match[1], int(match[2])
    contract = contract if contract is not None else load_contract()
    admitted = contract['releases'].get(version)
    require(admitted is not None, 'Published OCI SDK source is not admitted')
    base = 'https://github.com/dotnetdev-kr/cbodotnet/releases/download/sdk-' + version + '/'
    if manifest_bytes is None:
        with urllib.request.urlopen(base + 'release-manifest.json', timeout=60) as incoming:
            manifest_bytes = incoming.read(8 * 1024**2 + 1)
    require(len(manifest_bytes) <= 8 * 1024**2 and hashlib.sha256(manifest_bytes).hexdigest() == admitted['manifestSha256'],
            'Published OCI source manifest differs from the independent contract pin')
    source = json.loads(manifest_bytes)
    require(source.get('repository') == 'dotnetdev-kr/cbodotnet' and source.get('sdkVersion') == version
            and source.get('tag') == 'sdk-' + version, 'Published OCI source identity differs')
    validate_qualified_producers(source, admitted['target'], catalog)
    require(architecture in {'amd64', 'arm64'}, 'Unsupported OCI source architecture')
    row = source['architectures']['x64' if architecture == 'amd64' else 'aarch64']
    plan = dict(sdkVersion=version, packageRevision=revision, sourceReleaseTag=source['tag'],
        package=dict(root='/opt/cbodotnet/' + '.'.join(version.split('.')[:2])), branding=contract['branding'],
        sourceManifestUrl=base + 'release-manifest.json', sourceManifestSha256=admitted['manifestSha256'])
    for kind in ('sdk', 'source', 'evidence'):
        plan[kind] = dict(row[kind], url=base + row[kind]['name'])
    return oci_labels(plan)


def public_smoke_script(version='10.0.403', sdk_root=None):
    """Exercise DLL and apphost, loopback ASP.NET, RSA/random and ICU offline."""
    from legacy_compat import environment
    return smoke_script(version, sdk_root or '/opt/cbodotnet/' + sdk_series(version), 'app',
                        runtime_env=environment(dict(sdkVersion=version, variant='debian-13')))


def run_public_functional_smoke(reference, version='10.0.403', sdk_root=None):
    output = run(['docker', 'run', '--rm', '--network', 'none', reference, 'sh', '-ec', public_smoke_script(version, sdk_root)])
    return dict(validate_smoke_output(output), nonRootRuntimeRoot='passed')


def validate_published_metadata(index, expected):
    labels = expected.get('labels')
    revision = re.fullmatch(r'([1-9][0-9]*\.[0-9]+\.[0-9]+)-debian13-r([1-9][0-9]*)', index.get('tag', ''))
    require(revision is not None, 'An immutable supported SDK image tag is required')
    if int(revision[2]) >= 2 or revision[1] != '10.0.403':
        require(expected.get('metadataPolicyVersion') == 2 and labels and expected.get('sdkRoot') == '/opt/cbodotnet/' + sdk_series(revision[1]),
                'New OCI revisions require the complete metadata policy; legacy fallback is allowed only for r1')
    if revision[1] != '10.0.403' or int(revision[2]) >= 3:
        require(expected.get('wrapperLicense') == oci_wrapper_license(), 'New OCI descriptor lacks the exact project wrapper license')
    elif 'wrapperLicense' in expected:
        require(expected['wrapperLicense'] == oci_wrapper_license(), 'Published OCI wrapper license descriptor differs')
    if expected.get('metadataPolicyVersion') == 2:
        qualified = qualified_oci_labels(index, expected['architecture'])
        base_label = labels.get('org.opencontainers.image.base.name', '')
        require(re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}', base_label)
                and labels == dict(qualified, **{'org.opencontainers.image.base.name': base_label}),
                'Published image descriptor differs from complete qualified source/license/notice labels')
    return labels


def run(command, *, cwd=None, env=None, input=None):
    result = subprocess.run([str(item) for item in command], cwd=cwd, env=env, input=input,
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError('Command failed: ' + str(command[0]) + '\n' + result.stdout[-6000:] + result.stderr[-6000:])
    return result.stdout


def digest(path, algorithm='sha256'):
    value = hashlib.new(algorithm)
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def inventory(root):
    value = {}
    for path in sorted(Path(root).rglob('*')):
        mode = stat.S_IMODE(path.lstat().st_mode)
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            value[name] = ['link', mode, os.readlink(path)]
        elif path.is_file():
            value[name] = ['file', mode, digest(path)]
        elif path.is_dir():
            value[name] = ['directory', mode]
        else:
            raise ValueError('Unexpected installation object: ' + name)
    return value


def extractor():
    spec = importlib.util.spec_from_file_location('coexistence_extract', ROOT / 'scripts/test-distribution-coexistence.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.extract_sdk


def official_archive(directory, arch):
    directory = Path(directory)
    url = 'https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/10.0/releases.json'
    with urllib.request.urlopen(url, timeout=60) as response:
        metadata = json.load(response)
    rid = 'linux-arm64' if arch == 'aarch64' else 'linux-x64'
    candidates = [item for release in metadata['releases'] for sdk in release.get('sdks', [])
                  if sdk['version'] == '10.0.100' for item in sdk['files']
                  if item['rid'] == rid and item['name'].endswith('.tar.gz')]
    require(len({item['url'] for item in candidates}) == 1, 'Ambiguous official comparison SDK')
    item = candidates[0]
    path = directory / 'official-sdk.tar.gz'
    if not path.exists():
        urllib.request.urlretrieve(item['url'], path)
    require(digest(path, 'sha512') == item['hash'].lower(), 'Official comparison SDK checksum mismatch')
    (directory / 'official-source.json').write_bytes(encoded(dict(version='10.0.100', url=item['url'], sha512=item['hash'])))
    return path


def user_command(arguments, directory):
    return ['runuser', '-u', 'cbot-smoke', '--', 'env', 'HOME=/home/cbot-smoke',
            'DOTNET_CLI_HOME=/home/cbot-smoke', 'NUGET_PACKAGES=/home/cbot-smoke/.nuget/packages',
            'DOTNET_CLI_TELEMETRY_OPTOUT=1', 'DOTNET_NOLOGO=1', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1',
            'DOTNET_CLI_UI_LANGUAGE=en', 'LC_ALL=C', *map(str, arguments)]


def installation_context(args):
    require(os.geteuid() == 0 and Path('/.dockerenv').is_file(), 'Installation tests require a disposable root container')
    delivery = args.delivery.resolve()
    plan = json.loads((delivery / 'plan.json').read_bytes())
    architecture = plan['architecture']['public']
    require(platform.machine() in ({'aarch64', 'arm64'} if architecture == 'aarch64' else {'x86_64'}), 'Native architecture mismatch')
    os_release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    expected_os = load_contract()['operatingSystems'][args.variant]
    require(os_release['ID'].strip('"') == expected_os['id'] and os_release['VERSION_ID'].strip('"') == expected_os['versionId'],
            'Installation executed on another OS/version')
    require(plan['variant'] == args.variant and plan['channel'] == args.mode, 'Installed channel/variant differs from its source plan')
    return delivery, plan, architecture, expected_os


def require_offline_runtime():
    require({path.name for path in Path('/sys/class/net').iterdir()} == {'lo'},
            'Installed runtime/lifecycle proof requires Docker --network none')


def strict_dpkg_integrity(names):
    require(not run(['dpkg', '-V', *names]).strip(), 'Installed package failed full dpkg integrity verification')


def observed_dependencies(plan, mode, compatibility=None):
    result = {}
    for name in plan['dependencies']:
        if mode == 'oci' and name == 'cbodotnet-compat-rocky9':
            from legacy_compat import load_policy, assert_unchanged, runtime_environment
            provider = load_policy()
            require(isinstance(compatibility, dict) and compatibility.get('required') is True
                    and compatibility.get('packages') == provider['architectures'][plan['architecture']['public']]['packages']
                    and compatibility.get('signingFingerprint') == provider['signingFingerprint'],
                    'OCI compatibility dependency lacks authenticated native source versions')
            runtime_environment(plan, compatibility)
            require(assert_unchanged(compatibility)['status'] == 'passed', 'OCI managed compatibility dependency changed')
            sources = [str(row.get('epoch', 0)) + ':' + row['version'] + '-' + row['release'] + '.' + row['architecture']
                       for row in compatibility['packages']]
            result[name] = provider['version'] + ' (isolated managed OCI tree; Rocky RPM sources: ' + ', '.join(sources) + ')'
        else:
            result[name] = run(['dpkg-query', '-W', '-f=${Version}', name]).strip()
            require(result[name], 'Installed native dependency has no observed package version: ' + name)
    return result


def prepare_installed(args):
    delivery, plan, architecture, _ = installation_context(args)
    run(['useradd', '--create-home', '--uid', '10001', 'cbot-smoke'])
    work = Path('/home/cbot-smoke/project')
    work.mkdir()
    run(['chown', '-R', 'cbot-smoke:cbot-smoke', str(work)])
    if args.mode == 'deb':
        from apt_official import bootstrap
        progress('install the official SDK through its signed native package repository')
        baseline = bootstrap(args.variant, architecture, 'cbot-smoke', delivery / 'official-state.json')
        official = Path(baseline['officialRoot'])
        official_version = baseline['sdkVersion']
        official_before = None
    else:
        official = Path('/usr/share/dotnet')
        require(not official.exists(), 'Comparison official root must be fresh')
        official.parent.mkdir(parents=True, exist_ok=True)
        extractor()(Path('/delivery/official-sdk.tar.gz'), official)
        (official / 'metadata').mkdir(exist_ok=True)
        if not Path('/usr/bin/dotnet').exists():
            Path('/usr/bin/dotnet').symlink_to(official / 'dotnet')
        official_version = '10.0.100'
        require(run(user_command([official / 'dotnet', '--version'], work), cwd=work).strip() == official_version,
                'Official comparison SDK failed')
        official_before = inventory(official)
        baseline = dict(officialRoot=str(official), sdkVersion=official_version, provider='official-archive')
    sdk = Path(plan['package']['root'])
    compatibility = None
    if runtime_policy(plan['sdkVersion'], architecture)['legacy']:
        from legacy_compat import provision
        compatibility = provision(plan, delivery, user='cbot-smoke')
    if args.mode == 'deb':
        progress('install native packages from ' + ('the authenticated repository' if (delivery / 'repository').is_dir() else 'the verified local package files'))
        # Minimal distro container bases intentionally omit most /usr/share/doc
        # entries. Include this package's notices/provenance so strict dpkg
        # verification covers every file we own instead of masking exclusions.
        Path('/etc/dpkg/dpkg.cfg.d/zz-cbodotnet-validation').write_text(
            'path-include=/usr/share/doc/cbodotnet-*\n')
        packages = sorted((delivery / 'packages').glob('*.deb'))
        require(len(packages) == (3 if compatibility else 2), 'SDK, shared host and any required compatibility package are required')
        if (delivery / 'repository').is_dir():
            shutil.copy2(delivery / 'repository/cbodotnet-archive-keyring.gpg', '/usr/share/keyrings/cbodotnet-validation.gpg')
            repository_location = 'file://' + str(delivery / 'repository')
            if (delivery / 'repository-url.txt').exists():
                from published_apt import repository_url
                repository_location = repository_url(args.variant, plan['sdkVersion'], plan['packageRevision'],
                    (delivery / 'repository-url.txt').read_text().strip())
            Path('/etc/apt/sources.list.d/cbodotnet-validation.list').write_text(
                'deb [signed-by=/usr/share/keyrings/cbodotnet-validation.gpg] ' + repository_location + ' ./\n')
            run(['apt-get', 'update'])
            run(['apt-get', 'install', '-y', plan['package']['name'] + '=' + plan['package']['version'], 'cbodotnet-host=1.0.0-1'])
        else:
            run(['apt-get', 'install', '-y', *map(str, packages)])
        strict_dpkg_integrity([plan['package']['name'], 'cbodotnet-host'])
    require(sdk.is_dir(), 'Installed SDK root is missing')
    expected = Path(tempfile.mkdtemp(prefix='cbot-payload-')) / 'sdk'
    extractor()(Path('/delivery/inputs') / plan['sdk']['name'], expected)
    for name in plan['additionalDirectories']:
        (expected / name).mkdir(mode=0o755, exist_ok=True)
    require(inventory(expected) == inventory(sdk), 'Installed SDK bytes/modes differ from qualified archive')
    shutil.rmtree(expected.parent)
    (delivery / 'installation-state.json').write_bytes(encoded(dict(schemaVersion=1, status='prepared',
        mode=args.mode, variant=args.variant, architecture=architecture, sdkBefore=inventory(sdk),
        officialBaseline=baseline, officialBefore=official_before, compatibilityState=compatibility)))


def assert_removed_deb(plan):
    require(not Path(plan['package']['root']).exists() and Path('/usr/bin/cbodotnet').is_file()
            and not Path(plan['package']['launcher']).exists(), 'Removal damaged shared ownership or left SDK payload')
    result = subprocess.run(user_command(['cbodotnet', '--version'], Path('/home/cbot-smoke')), text=True, capture_output=True)
    require(result.returncode == 127 and not result.stdout, 'Removed SDK fell back to another dotnet host')
    strict_dpkg_integrity(['cbodotnet-host'])


def deb_lifecycle(plan, delivery, sdk_before, as_user, official_check):
    packages = sorted((delivery / 'packages').glob('*.deb'))
    expected = 3 if sdk_series(plan['sdkVersion']) in {'3.0', '3.1', '5.0'} else 2
    require(len(packages) == expected, 'All original immutable packages are required for lifecycle validation')
    sdk = Path(plan['package']['root'])
    phases = ['after-install', 'after-runtime']

    def installed_revision(revision):
        identity = json.loads(as_user(['cbodotnet', '--cbodotnet-info']))
        require(identity['packageRevision'] == revision and identity['sdkVersion'] == plan['sdkVersion']
                and identity['sourceManifestSha256'] == plan['sourceManifestSha256'], 'Package lifecycle selected another revision/source')
        require(inventory(sdk) == sdk_before, 'Packaging lifecycle changed qualified SDK payload')
        strict_dpkg_integrity([plan['package']['name'], 'cbodotnet-host'])

    if not (delivery / 'post-publication').exists():
        progress('upgrade the installed SDK packaging revision')
        upgrades = sorted((delivery / 'upgrade').glob('*.deb'))
        require(len(upgrades) == expected, 'A real next-revision upgrade is required')
        # APT's --no-download handling breaks direct local-DEB pathname
        # acquisition. Docker --network none and the loopback-only guard
        # enforce the offline boundary while these exact local files install.
        run(['apt-get', 'install', '-y', *map(str, upgrades)])
        installed_revision(plan['packageRevision'] + 1)
        official_check('after-upgrade')
        phases.append('after-upgrade')
        progress('roll back to the original immutable packaging revision')
        run(['apt-get', 'install', '-y', '--allow-downgrades', *map(str, packages)])
        installed_revision(plan['packageRevision'])
        official_check('after-rollback')
        phases.append('after-rollback')
    progress('remove only the versioned SDK package and preserve the official installation')
    run(['apt-get', 'remove', '-y', plan['package']['name']])
    assert_removed_deb(plan)
    official_check('after-remove')
    phases.append('after-remove')
    progress('reinstall the original package before exercising an installed-package purge')
    run(['apt-get', 'install', '-y', *map(str, packages)])
    require(run(['dpkg-query', '-W', '-f=${Status}', plan['package']['name']]).strip() == 'install ok installed',
            'Purge fixture must reinstall the actual SDK package first')
    installed_revision(plan['packageRevision'])
    official_check('after-reinstall')
    phases.append('after-reinstall')
    progress('purge the installed SDK package and retain shared host ownership')
    run(['apt-get', 'purge', '-y', plan['package']['name']])
    assert_removed_deb(plan)
    query = subprocess.run(['dpkg-query', '-W', '-f=${Status}', plan['package']['name']], text=True, capture_output=True)
    require(query.returncode == 1 or query.returncode == 0 and query.stdout.strip().split()[-2:] == ['ok', 'not-installed'],
            'SDK purge retained an installed package or configuration-only record')
    official_check('after-purge')
    phases.append('after-purge')
    return phases


def installed(args):
    if getattr(args, 'phase', 'lifecycle') == 'prepare':
        return prepare_installed(args)
    require_offline_runtime()
    delivery, plan, architecture, expected_os = installation_context(args)
    state = json.loads((delivery / 'installation-state.json').read_bytes())
    require(state.get('status') == 'prepared' and state['mode'] == args.mode and state['variant'] == args.variant
            and state['architecture'] == architecture, 'Runtime fixture differs from prepared native installation')
    work = Path('/home/cbot-smoke/project')
    official = Path(state['officialBaseline']['officialRoot'])
    official_version = state['officialBaseline']['sdkVersion']
    sdk = Path(plan['package']['root'])
    sdk_before = state['sdkBefore']
    official_proofs = []
    compatibility_proofs = []
    runtime_env = {}
    if runtime_policy(plan['sdkVersion'], architecture)['legacy']:
        from legacy_compat import runtime_environment, assert_unchanged as assert_compatibility
        require(state.get('compatibilityState'), 'Prepared managed compatibility provider state is missing')
        runtime_env = runtime_environment(plan, state['compatibilityState'])

    def as_user(command, cwd=work):
        return run(user_command(command, cwd), cwd=cwd)

    def official_check(phase):
        if args.mode == 'deb':
            from apt_official import assert_unchanged
            proof = assert_unchanged(delivery / 'official-state.json')
            require(proof.get('status') == 'passed', 'Official package-manager installation changed')
            require(as_user(['dotnet', '--version'], Path('/home/cbot-smoke')).strip() == official_version,
                    'Native package took over official dotnet selection')
        else:
            require(inventory(official) == state['officialBefore'], 'cbodotnet modified the official installation')
            proof = dict(status='passed', provider='official-archive')
        require(as_user([official / 'dotnet', '--version'], Path('/home/cbot-smoke')).strip() == official_version,
                'Official SDK version changed after a lifecycle transition')
        official_proofs.append(dict(phase=phase, **proof))
        if runtime_env:
            compatibility_proofs.append(dict(phase=phase, **assert_compatibility(state['compatibilityState'])))

    official_check('after-install')
    versioned = 'cbodotnet-' + '.'.join(plan['sdkVersion'].split('.')[:2])
    names = [versioned, 'cbodotnet'] + (['dotnet'] if args.mode == 'oci' else [])
    for name in names:
        result = subprocess.run(user_command([name, '--version'], work), cwd=work, text=True, capture_output=True)
        require(result.returncode == 0 and result.stdout == plan['sdkVersion'] + '\n' and result.stderr.strip() == BRAND,
                'Version stdout/branding mismatch: ' + name)
        info = as_user([name, '--info'])
        require(info.startswith(BRAND + '\n') and str(sdk) in info, 'Alias host root mismatch')
        validate_host_rid(info, plan['sdkVersion'], architecture, args.variant)
        identity = json.loads(as_user([name, '--cbodotnet-info']))
        require(identity['sourceManifestSha256'] == plan['sourceManifestSha256'] and identity['sdkVersion'] == plan['sdkVersion']
                and identity['packageRevision'] == plan['packageRevision'] and identity['sdkRoot'] == str(sdk),
                'Alias source provenance mismatch')
        validate_sdk_listing(as_user([name, '--list-sdks']), plan['sdkVersion'], str(sdk))
    policy = runtime_policy(plan['sdkVersion'], architecture)
    reported_rid = validate_host_rid(info, plan['sdkVersion'], architecture, args.variant)
    output = as_user(['sh', '-ec', smoke_script(plan['sdkVersion'], str(sdk), 'cbot-smoke',
                     cli='cbodotnet', workdir=str(work / 'functional'), runtime_env=runtime_env)])
    functional_evidence = validate_smoke_output(output)
    native_http_libraries = audit_core3_http_libraries(plan['sdkVersion'], sdk, runtime_env=runtime_env, runner=run)
    abi_directory = work / 'abi-verification'
    as_user(['env', *[name + '=' + value for name, value in runtime_env.items()], 'bash', ROOT / 'scripts/verify-sdk.sh', '--sdk-dir', sdk, '--output-dir', abi_directory,
             '--expected-version', plan['sdkVersion'], '--expected-rid', reported_rid, '--framework', policy['framework'],
             '--max-glibc', policy['maxGlibc'], '--arch', 'arm64' if architecture == 'aarch64' else 'x64', '--no-smoke'])
    verification = json.loads((abi_directory / 'verification.json').read_bytes())
    require(verification['verificationStatus'] == 'passed' and verification['abi']['glibcCeilingPassed'],
            'Installed SDK native ABI verification failed')
    require(inventory(sdk) == sdk_before, 'Installed execution modified qualified SDK payload')
    official_check('after-runtime')
    if args.mode == 'deb':
        strict_dpkg_integrity([plan['package']['name'], 'cbodotnet-host'])
        phases = deb_lifecycle(plan, delivery, sdk_before, as_user, official_check)
        require([row['phase'] for row in official_proofs] == phases, 'Official package proof omits a lifecycle transition')
    dependencies = observed_dependencies(plan, args.mode, state.get('compatibilityState'))
    checks = {name: 'passed' for name in PREPUBLICATION_CHECKS}
    checks['sdk-list-paths'] = 'passed'
    checks['offline-network'] = 'passed'
    checks.update({name: 'passed' for name in (['package-integrity', 'package-manager-install', 'repository-metadata']
                                             if args.mode == 'deb' else ['image-config', 'oci-platforms', 'pinned-base-image'])})
    # OCI upgrade/removal are validated by the outer driver against whole images.
    if args.mode == 'oci':
        checks.pop('upgrade')
        checks.pop('removal')
    else:
        checks['repository-metadata'] = 'pending-signing-stage'
        checks['rollback'] = 'passed'
        checks.update({'official-package-coexistence': 'passed', 'installed-package-purge': 'passed'})
        if (delivery / 'post-publication').exists():
            checks['upgrade'] = 'verified-before-publication'
            checks['rollback'] = 'verified-before-publication'
            checks['repository-metadata'] = 'passed'
    result = {'schemaVersion': 1, 'status': 'passed', 'target': dict(osId=expected_os['id'], versionId=expected_os['versionId'],
               architecture=architecture, native=True, dependencies=dependencies), 'checks': checks, 'commandNames': names,
              'networkForBuild': 'none', 'officialComparison': state['officialBaseline'], 'officialCoexistence': official_proofs,
              'functionalChecks': functional_evidence, 'runtimePolicy': policy, 'abi': verification['abi'],
              'compatibilityProvider': compatibility_proofs}
    if native_http_libraries:
        result['nativeHttpLibraries'] = native_http_libraries
    (delivery / 'installation-result.json').write_bytes(encoded(result))


def orchestration():
    ref = os.environ.get('GITHUB_WORKFLOW_REF', 'dotnetdev-kr/cbodotnet/.github/workflows/distribution-release.yml@refs/heads/main')
    prefix = 'dotnetdev-kr/cbodotnet/'
    require(ref.startswith(prefix) and '@' in ref, 'Actual workflow provenance is required')
    workflow = ref.removeprefix(prefix).split('@', 1)[0]
    require(workflow in {'.github/workflows/distribution-release.yml', '.github/workflows/apt-completeness.yml'},
            'Unsupported native evidence workflow')
    return dict(repository='dotnetdev-kr/cbodotnet', workflow=workflow,
                commit=os.environ['GITHUB_SHA'], runId=os.environ['GITHUB_RUN_ID'], runAttempt=os.environ['GITHUB_RUN_ATTEMPT'])


def container_lifecycle(workspace, delivery, base, variant, mode):
    """Provision with networking, then run all installed SDK checks offline."""
    cid = image = None
    try:
        progress('provision native ' + variant + ' ' + mode + ' installation')
        cid = run(['docker', 'create', '--user', '0', '--entrypoint', '/bin/bash',
                   '-v', f'{ROOT}:/repo:ro', '-v', f'{workspace}:/delivery', base,
                   '/repo/scripts/verify-channel-install.sh', '/repo', '/delivery/' + delivery.name,
                   variant, mode, 'prepare']).strip()
        run(['docker', 'start', '--attach', cid])
        require(json.loads(run(['docker', 'inspect', cid]))[0]['State']['ExitCode'] == 0,
                'Native installation provisioning failed')
        image = run(['docker', 'commit', cid]).strip()
        run(['docker', 'run', '--rm', '--network', 'none', '--user', '0', '--entrypoint', '/bin/bash',
             '-v', f'{ROOT}:/repo:ro', '-v', f'{workspace}:/delivery', image,
             '/repo/scripts/verify-channel-install.sh', '/repo', '/delivery/' + delivery.name,
             variant, mode, 'lifecycle'])
    finally:
        if cid:
            subprocess.run(['docker', 'rm', '--force', cid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if image:
            subprocess.run(['docker', 'image', 'rm', image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def copy_commands(build, target):
    rows = json.loads((build / 'command-inventory.json').read_bytes())
    target.mkdir()
    for row in rows:
        source = build / 'rootfs' / row['path'].lstrip('/')
        destination = target / row['path'].lstrip('/')
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    (target.parent / 'commands.json').write_bytes(encoded(rows))
    return rows


def record(delivery, artifact, result, commands, inputs):
    plan = json.loads((delivery / 'plan.json').read_bytes())
    rows = json.loads((delivery / 'commands.json').read_bytes())
    packaged = package_record(plan, artifact, orchestration(), extra_files={'root': commands, 'inventory': rows})
    report = {'schemaVersion': 1, 'phase': 'prepublication', 'scope': 'channel-installation',
              **result, **{name: packaged[name] for name in ('contractVersion', 'identity', 'artifact', 'source', 'producer',
                                                           'orchestration', 'branding', 'commands', 'extraFiles')}}
    (delivery / 'package.json').write_bytes(encoded(packaged))
    (delivery / 'report.json').write_bytes(encoded(report))
    return dict(packagePath=str(delivery / 'package.json'), artifactPath=str(artifact), reportPath=str(delivery / 'report.json'),
                commandsRoot=str(commands), inputsDirectory=str(inputs))


def prepare_compatibility(workspace, delivery, base, version, architecture, variant):
    """Build the explicit reviewed companion before SDK staging, never during it."""
    if not runtime_policy(version, architecture)['legacy']:
        return []
    output = '/delivery/' + delivery.name + '/compatibility-build'
    command = ('set -eu; export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; '
               'apt-get install -y --no-install-recommends python3 rpm rpm2cpio gnupg binutils ca-certificates; '
               'python3 /repo/scripts/legacy_compat.py --arch ' + architecture + ' --variant ' + variant
               + ' --output ' + output + '; chown -R ' + str(os.getuid()) + ':' + str(os.getgid()) + ' ' + output)
    run(['docker', 'run', '--rm', '--user', '0', '-v', f'{ROOT}:/repo:ro', '-v', f'{workspace}:/delivery',
         base, 'sh', '-ec', command])
    return ['--compatibility-build', delivery / 'compatibility-build/provider-build.json']


def oci_build_arguments(base_image, metadata):
    version = metadata['plan']['sdkVersion']
    expected = dict(BASE_IMAGE=base_image, SDK_SERIES=sdk_series(version))
    require(metadata.get('buildArgs') == expected and metadata['plan']['package']['root'] == '/opt/cbodotnet/' + expected['SDK_SERIES'],
            'OCI build arguments differ from the selected SDK series/root or pinned base')
    arguments = ['docker', 'build']
    for key, value in expected.items():
        arguments.extend(['--build-arg', key + '=' + value])
    arguments.extend(['--label', 'org.opencontainers.image.base.name=' + base_image])
    for key, value in metadata['labels'].items():
        arguments.extend(['--label', key + '=' + value])
    return arguments


def native(args):
    channels = selected_channels(args, native=True)
    require(os.getuid() != 0 and platform.machine() in ({'aarch64', 'arm64'} if args.arch == 'aarch64' else {'x86_64'}),
            'A matching non-root native Linux producer is required')
    workspace = args.workspace.resolve()
    require(not workspace.exists(), 'Native delivery workspace must be fresh')
    workspace.mkdir(parents=True)
    inputs = workspace / 'inputs'
    progress('receive the exact qualified SDK source release for ' + args.arch)
    receive_release(args.tag, inputs, 'oci' if channels == ('oci',) else 'deb', 'debian-13', args.arch, args.revision)
    if 'oci' in channels:
        progress('verify the independent official SDK comparison archive for OCI')
        official_archive(workspace, args.arch)
    items = []
    for variant, base in ([('ubuntu-24.04', args.ubuntu_base), ('debian-13', args.debian_base)] if 'deb' in channels else []):
        delivery = workspace / ('deb-' + variant)
        delivery.mkdir()
        compatibility_args = prepare_compatibility(workspace, delivery, base, args.tag[4:], args.arch, variant)
        for revision, name in [(args.revision, 'build'), (args.revision + 1, 'upgrade-build')]:
            progress('build ' + variant + ' ' + args.arch + ' packaging revision ' + str(revision))
            run([sys.executable, ROOT / 'scripts/package-sdk.py', '--inputs', inputs, '--channel', 'deb', '--variant', variant,
                 '--arch', args.arch, '--revision', revision, '--output', delivery / name, *compatibility_args])
        build = delivery / 'build'
        shutil.copy2(build / 'plan.json', delivery / 'plan.json')
        copy_commands(build, delivery / 'commands')
        for source_name, target_name in [('build', 'packages'), ('upgrade-build', 'upgrade')]:
            (delivery / target_name).mkdir()
            for package in (delivery / source_name).glob('*.deb'):
                shutil.copy2(package, delivery / target_name / package.name)
            for companion in (delivery / source_name).glob('cbodotnet-compat-*.tar.gz'):
                shutil.copy2(companion, delivery / target_name / companion.name)
            shutil.copy2(delivery / source_name / 'package-build.json', delivery / target_name / 'package-build.json')
        progress('execute the complete installed lifecycle on native ' + variant + ' ' + args.arch)
        container_lifecycle(workspace, delivery, base, variant, 'deb')
        result = json.loads((delivery / 'installation-result.json').read_bytes())
        artifact = next(path for path in (delivery / 'packages').glob('*.deb') if path.name.startswith('cbodotnet-sdk-'))
        # The signed release bundler prefixes public names by variant/arch;
        # transport and repository generation share this one canonical file.
        items.append(record(delivery, artifact, result, delivery / 'commands', inputs))
        progress('passed native ' + variant + ' installation, upgrade, rollback and removal')
        # SDK payloads are already carried by packages and source input archives.
        # Keep only wrapper files needed for independent record validation.
        for name in ('build', 'upgrade-build'):
            shutil.rmtree(delivery / name)
        shutil.rmtree(delivery / 'upgrade')
    if 'oci' not in channels:
        (workspace / 'items.json').write_bytes(encoded(items))
        print(json.dumps(dict(status='passed', architecture=args.arch, channels=list(channels), items=len(items))))
        return
    delivery = workspace / 'oci-debian-13'
    delivery.mkdir()
    compatibility_args = prepare_compatibility(workspace, delivery, args.debian_base, args.tag[4:], args.arch, 'debian-13')
    build = delivery / 'build'
    progress('prepare the pinned Debian 13 OCI image for ' + args.arch)
    run([sys.executable, ROOT / 'scripts/package-sdk.py', '--inputs', inputs, '--channel', 'oci', '--variant', 'debian-13',
         '--arch', args.arch, '--revision', args.revision, '--output', build, '--base-image', args.debian_base, *compatibility_args])
    shutil.copy2(build / 'plan.json', delivery / 'plan.json')
    copy_commands(build, delivery / 'commands')
    tag = 'cbodotnet-verified:' + args.arch
    require('@sha256:' in args.debian_base, 'OCI base must be pinned by digest')
    metadata = json.loads((build / 'package-build.json').read_bytes())
    build_arguments = oci_build_arguments(args.debian_base, metadata)
    progress('build the exact-version OCI image from the verified payload')
    run([*build_arguments, '--tag', tag, '--file', build / 'Containerfile', build])
    image = json.loads(run(['docker', 'image', 'inspect', tag]))[0]
    expected_arch = 'amd64' if args.arch == 'x64' else 'arm64'
    labels = dict(metadata['labels'], **{'org.opencontainers.image.base.name': args.debian_base})
    config_evidence = validate_image_config(image, expected_arch, metadata['plan']['package']['root'], labels)
    require(metadata.get('wrapperLicense') == oci_wrapper_license(), 'New OCI context lacks the project wrapper MIT license')
    file_evidence = inspect_consumer_files(tag, metadata['plan']['package']['root'], wrapper_license=metadata['wrapperLicense'])
    functional_evidence = run_public_functional_smoke(tag, args.tag[4:], metadata['plan']['package']['root'])
    require(run(['docker', 'run', '--rm', tag, 'id', '-u']).strip() == '1654', 'Consumer image does not execute as its non-root user')
    progress('execute native OCI aliases, payload, non-root, HTTP, cryptography and globalization checks')
    container_lifecycle(workspace, delivery, tag, 'debian-13', 'oci')
    result = json.loads((delivery / 'installation-result.json').read_bytes())
    result['imageConfig'] = config_evidence
    result['imageFiles'] = file_evidence
    result['functionalChecks'] = functional_evidence
    result['imageFunctionalNetwork'] = 'none'
    result['checks'].update({'image-labels': 'passed', 'image-ownership': 'passed', 'image-no-build-secrets': 'passed', 'image-no-source-build-toolchain': 'passed'})
    result['checks']['image-wrapper-license'] = 'passed'
    # Upgrade through a separately built packaging revision, then roll back by
    # selecting the original immutable image without rewriting either image.
    upgrade_build = delivery / 'upgrade-build'
    progress('build the next OCI packaging revision and verify immutable rollback')
    run([sys.executable, ROOT / 'scripts/package-sdk.py', '--inputs', inputs, '--channel', 'oci', '--variant', 'debian-13',
         '--arch', args.arch, '--revision', args.revision + 1, '--output', upgrade_build, '--base-image', args.debian_base, *compatibility_args])
    upgrade_tag = tag + '-upgrade'
    upgrade_metadata = json.loads((upgrade_build / 'package-build.json').read_bytes())
    upgrade_arguments = oci_build_arguments(args.debian_base, upgrade_metadata)
    run([*upgrade_arguments, '--tag', upgrade_tag, '--file', upgrade_build / 'Containerfile', upgrade_build])
    upgraded_image = json.loads(run(['docker', 'image', 'inspect', upgrade_tag]))[0]
    validate_image_config(upgraded_image, expected_arch, upgrade_metadata['plan']['package']['root'],
                          dict(upgrade_metadata['labels'], **{'org.opencontainers.image.base.name': args.debian_base}))
    require(upgrade_metadata.get('wrapperLicense') == oci_wrapper_license(), 'Upgrade OCI context lacks the project wrapper MIT license')
    result['imageUpgradeFiles'] = inspect_consumer_files(upgrade_tag, upgrade_metadata['plan']['package']['root'],
                                                       wrapper_license=upgrade_metadata['wrapperLicense'])
    for name in ('cbodotnet-' + sdk_series(args.tag[4:]), 'cbodotnet', 'dotnet'):
        validate_sdk_listing(run(['docker', 'run', '--rm', upgrade_tag, name, '--list-sdks']), args.tag[4:], upgrade_metadata['plan']['package']['root'])
    upgraded = json.loads(run(['docker', 'run', '--rm', '--entrypoint', 'cbodotnet', upgrade_tag, '--cbodotnet-info']))
    require(upgraded['packageRevision'] == args.revision + 1, 'Container upgrade did not select the next packaging revision')
    require(run(['docker', 'run', '--rm', '--entrypoint', 'cbodotnet', tag, '--version']).strip() == args.tag[4:],
            'Immutable image rollback selected another SDK')
    container_id = run(['docker', 'create', '--entrypoint', 'cbodotnet', tag, '--version']).strip()
    run(['docker', 'start', '--attach', container_id])
    run(['docker', 'rm', container_id])
    require(not run(['docker', 'ps', '--all', '--filter', 'id=' + container_id, '--format', '{{.ID}}']).strip(),
            'Container removal left a container behind')
    result['checks'].update(upgrade='passed', rollback='passed', removal='passed')
    artifact = delivery / ('cbodotnet-sdk-' + args.arch + '.image.tar')
    run(['docker', 'save', '--output', artifact, tag])
    progress('export the verified native image for protected promotion')
    (delivery / 'image.json').write_bytes(encoded(dict(tag=tag, id=image['Id'], architecture=expected_arch,
        base=args.debian_base, sdkVersion=args.tag[4:], sdkRoot=metadata['plan']['package']['root'], labels=labels,
        wrapperLicense=metadata['wrapperLicense'])))
    items.append(record(delivery, artifact, result, delivery / 'commands', inputs))
    shutil.rmtree(build)
    shutil.rmtree(upgrade_build)
    (workspace / 'official-sdk.tar.gz').unlink()
    (workspace / 'items.json').write_bytes(encoded(items))
    print(json.dumps(dict(status='passed', architecture=args.arch, items=len(items))))


def registry_manifest(reference, missing=False):
    result = subprocess.run(['docker', 'buildx', 'imagetools', 'inspect', reference, '--format', '{{json .Manifest}}'],
                            text=True, capture_output=True)
    if result.returncode:
        message = (result.stdout + result.stderr).lower()
        if missing and any(value in message for value in ('not found', 'manifest unknown', 'name unknown')):
            return None
        raise RuntimeError('Registry inspection failed for ' + reference + ': ' + result.stderr[-1000:])
    descriptor = json.loads(result.stdout)
    raw = json.loads(run(['docker', 'buildx', 'imagetools', 'inspect', reference, '--raw']))
    require(isinstance(descriptor.get('digest'), str) and descriptor['digest'].startswith('sha256:'), 'Registry returned no immutable digest')
    return descriptor, raw


def push_images(items, output):
    require(len(items) == 2 and {item['package']['architecture'] for item in items} == {'x64', 'aarch64'},
            'Both native verified images are required before GHCR promotion')
    repository = 'ghcr.io/dotnetdev-kr/cbodotnet-sdk'
    identity = items[0]['package']['identity']
    tag = identity['sdkVersion'] + '-debian13-r' + str(identity['packageRevision'])
    token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')
    require(token and os.environ.get('GITHUB_ACTOR'), 'Scoped registry credentials are unavailable')
    run(['docker', 'login', 'ghcr.io', '--username', os.environ['GITHUB_ACTOR'], '--password-stdin'], input=token + '\n')
    platforms = []
    for item in items:
        delivery = Path(item['packagePath']).parent
        image = json.loads((delivery / 'image.json').read_bytes())
        run(['docker', 'load', '--input', item['artifactPath']])
        require(json.loads(run(['docker', 'image', 'inspect', image['tag']]))[0]['Id'] == image['id'], 'Transport changed the tested image')
        reference = repository + ':' + tag + '-' + image['architecture']
        existing = registry_manifest(reference, missing=True)
        if existing is None:
            run(['docker', 'tag', image['tag'], reference])
            run(['docker', 'push', reference])
        current = registry_manifest(reference)
        require(current[1].get('config', {}).get('digest') == image['id'],
                'Refusing an immutable image tag with a different verified image config')
        platform_row = dict(os='linux', architecture=image['architecture'], digest=current[0]['digest'], configDigest=image['id'])
        if image.get('labels'):
            platform_row.update(labels=image['labels'], sdkRoot=image['sdkRoot'], metadataPolicyVersion=2)
        require(image.get('wrapperLicense') == oci_wrapper_license(), 'New registry promotion lacks the project wrapper license')
        platform_row['wrapperLicense'] = image['wrapperLicense']
        platforms.append(platform_row)
    platforms.sort(key=lambda row: row['architecture'])
    index_reference = repository + ':' + tag
    existing = registry_manifest(index_reference, missing=True)
    if existing is None:
        run(['docker', 'buildx', 'imagetools', 'create', '--tag', index_reference,
             *[repository + '@' + row['digest'] for row in platforms]])
    current = registry_manifest(index_reference)
    expected = {(row['os'], row['architecture'], row['digest']) for row in platforms}
    observed = {(row.get('platform', {}).get('os'), row.get('platform', {}).get('architecture'), row.get('digest'))
                for row in current[1].get('manifests', [])}
    require(len(current[1].get('manifests', [])) == 2 and observed == expected,
            'Refusing a partial or conflicting immutable multi-platform index')
    result = dict(schemaVersion=1, repository=repository, tag=tag, digest=current[0]['digest'], platforms=platforms)
    (output / 'oci-index.json').write_bytes(encoded(result))
    return result


def sign_report(path, key):
    signature = Path(str(path) + '.sig')
    require(not signature.exists(), 'A report signature already exists')
    run(['gpg', '--batch', '--yes', '--local-user', key, '--output', signature, '--detach-sign', path])
    return signature


def unpack_deliveries(received):
    for archive_path in sorted(received.rglob('native-*.tar.gz')):
        with tarfile.open(archive_path, 'r:gz') as archive:
            entries = archive.getmembers()
            require(entries and sum(entry.size for entry in entries) < 8 * 1024**3, 'Unexpected native transport size')
            for entry in entries:
                path = Path(entry.name)
                require(not path.is_absolute() and '..' not in path.parts and not entry.issym()
                        and (entry.isdir() or entry.isfile() or entry.islnk()) and not entry.mode & 0o7000,
                        'Unsafe native CI transport member')
                if entry.islnk():
                    target = Path(entry.linkname)
                    require(not target.is_absolute() and '..' not in target.parts, 'Unsafe native CI hard link')
            archive.extractall(received, filter='data')
    deliveries = sorted(received.glob('delivery-*'))
    require(len(deliveries) == 2, 'Both native delivery artifacts are required')
    items = []
    for delivery in deliveries:
        for item in json.loads((delivery / 'items.json').read_bytes()):
            old_prefix = Path(item['inputsDirectory']).parent
            rebased = {key: str(delivery / Path(value).relative_to(old_prefix)) for key, value in item.items()}
            rebased['package'] = json.loads(Path(rebased['packagePath']).read_bytes())
            items.append(rebased)
    return items


def check_repository(repository, keyring):
    for variant in ('ubuntu-24.04', 'debian-13'):
        directory = repository / variant
        signed_release = run(['gpgv', '--keyring', keyring, '--output', '-', directory / 'InRelease'])
        require(signed_release == (directory / 'Release').read_text(), 'Signed APT release differs from indexed release')
        for line in signed_release.splitlines():
            parts = line.split()
            if len(parts) == 3 and len(parts[0]) == 64:
                checksum, size, name = parts
                require(name in {'Packages', 'Packages.gz'}, 'Unexpected APT index member')
                path = directory / name
                require(path.stat().st_size == int(size) and digest(path) == checksum, 'APT index changed after signing')
        for block in (directory / 'Packages').read_text().split('\n\n'):
            fields = dict(line.split(': ', 1) for line in block.splitlines() if ': ' in line and not line.startswith(' '))
            if fields:
                name = Path(fields['Filename'])
                require(not name.is_absolute() and '..' not in name.parts, 'Unsafe APT pool reference')
                path = directory / name
                require(path.stat().st_size == int(fields['Size']) and digest(path) == fields['SHA256'], 'APT index references a changed package')


def promote(args):
    require(os.environ.get('GITHUB_REF') == 'refs/heads/main' and os.environ.get('GITHUB_REPOSITORY') == 'dotnetdev-kr/cbodotnet',
            'Only the protected main workflow may publish')
    output = args.output.resolve()
    require(not output.exists(), 'Promotion output must be fresh')
    output.mkdir(parents=True)
    channels = selected_channels(args)
    items = unpack_deliveries(args.received.resolve())
    require({item['package']['identity']['channel'] for item in items} == set(channels),
            'Native transport contains missing or unexpected distribution channels')
    source_identity = orchestration()
    if args.source_run:
        require(args.source_run.isdecimal() and args.source_attempt.isdecimal(), 'An exact prior run/attempt is required')
        source = json.loads(run(['gh', 'api', f'repos/dotnetdev-kr/cbodotnet/actions/runs/{args.source_run}']))
        require(source.get('head_branch') == 'main' and source.get('event') == 'workflow_dispatch'
                and source.get('path') == '.github/workflows/distribution-release.yml'
                and source.get('repository', {}).get('full_name') == 'dotnetdev-kr/cbodotnet'
                and source.get('head_repository', {}).get('full_name') == 'dotnetdev-kr/cbodotnet',
                'Only a trusted native matrix from main may be resumed')
        jobs = json.loads(run(['gh', 'api', f'repos/dotnetdev-kr/cbodotnet/actions/runs/{args.source_run}/attempts/{args.source_attempt}/jobs?per_page=100']))['jobs']
        for arch in ('x64', 'aarch64'):
            matches = [job for job in jobs if job['name'] == 'Install packages and OCI on native ' + arch]
            require(len(matches) == 1 and matches[0].get('conclusion') == 'success', 'Resumed native installation matrix did not pass')
        source_identity.update(commit=source['head_sha'], runId=args.source_run, runAttempt=args.source_attempt)
    require({item['package']['architecture'] for item in items} == {'x64', 'aarch64'}, 'Native architecture matrix is incomplete')
    require(all(item['package']['orchestration'] == source_identity for item in items), 'Native artifact belongs to another workflow run/commit')
    repository = output / 'repositories'
    if 'deb' in channels:
        builds = sorted(args.received.resolve().glob('delivery-*/deb-*/packages/package-build.json'))
        run([sys.executable, ROOT / 'scripts/package-repository.py', '--channel', 'deb', '--package-builds', *builds,
             '--signing-key', args.signing_key, '--output', repository])
        from apt_release import prepare_flat_repositories
        prepare_flat_repositories(repository, args.signing_key, args.keyring)
        check_repository(repository, args.keyring)
    for item in items:
        report_path = Path(item['reportPath'])
        report = json.loads(report_path.read_bytes())
        if item['package']['identity']['channel'] == 'deb':
            report['checks']['repository-metadata'] = 'passed'
            report_path.write_bytes(encoded(report))
        item['signaturePath'] = str(sign_report(report_path, args.signing_key))
        item['keyringPath'] = str(args.keyring.resolve())
    ledger = output / 'ledger'
    ledger.mkdir()
    for channel in channels:
        stage_records([item for item in items if item['package']['identity']['channel'] == channel], ledger)
    oci_items = [item for item in items if item['package']['identity']['channel'] == 'oci']
    index = push_images(oci_items, output)
    # The transport tar was fully gated above. Public records point at compact
    # registry descriptors binding that tested config to its immutable digest.
    for item in oci_items:
        delivery = Path(item['packagePath']).parent
        image = json.loads((delivery / 'image.json').read_bytes())
        platform_row = next(row for row in index['platforms'] if row['architecture'] == image['architecture'])
        descriptor_path = delivery / ('oci-' + image['architecture'] + '.json')
        descriptor_path.write_bytes(encoded(dict(schemaVersion=1, repository=index['repository'],
            indexDigest=index['digest'], **platform_row, nativeTransport=item['package']['artifact'])))
        plan = json.loads((delivery / 'plan.json').read_bytes())
        inventory_rows = json.loads((delivery / 'commands.json').read_bytes())
        packaged = package_record(plan, descriptor_path, source_identity,
                                  extra_files={'root': item['commandsRoot'], 'inventory': inventory_rows})
        old_report = json.loads(Path(item['reportPath']).read_bytes())
        for key in ('contractVersion', 'identity', 'artifact', 'source', 'producer', 'orchestration', 'branding', 'commands', 'extraFiles'):
            old_report[key] = packaged[key]
        Path(item['packagePath']).write_bytes(encoded(packaged))
        item['package'] = packaged
        item['artifactPath'] = str(descriptor_path)
        item['reportPath'] = str(delivery / 'registry-report.json')
        Path(item['reportPath']).write_bytes(encoded(old_report))
        item['signaturePath'] = str(sign_report(Path(item['reportPath']), args.signing_key))
    from downstream_publish import create_bundle
    manifests = []
    for channel in channels:
        selected = [item for item in items if item['package']['identity']['channel'] == channel]
        from apt_release import release_tag as flat_tag
        extra = ([dict(path=str(path), kind='apt-repository', variants=[path.name.removeprefix('apt-').removesuffix('.tar.gz')],
                       delivery='github-release-flat', releaseTag=flat_tag(path.name.removeprefix('apt-').removesuffix('.tar.gz'),
                           selected[0]['package']['identity']['sdkVersion'], selected[0]['package']['identity']['packageRevision']))
                  for path in sorted(repository.glob('apt-*.tar.gz'))] if channel == 'deb' else
                 [dict(path=str(output / 'oci-index.json'), kind='oci-descriptor', variants=['debian-13'])])
        bundle = output / ('bundle-' + channel)
        manifests.append(create_bundle(selected, bundle, source_identity['commit'], args.signing_key, args.keyring, extra_assets=extra))
    (output / 'promotion.json').write_bytes(encoded(dict(schemaVersion=1, status='signed-and-frozen',
        sourceOrchestration=source_identity, publisherCommit=os.environ['GITHUB_SHA'],
        channels={manifest['identity']['channel']: manifest['tag'] for manifest in manifests},
        ociIndexSha256=digest(output / 'oci-index.json'))))
    if args.stage_only:
        print(json.dumps(dict(status='signed-and-frozen', targetCommit=source_identity['commit'], digest=index['digest'])))
    else:
        publish_staged(argparse.Namespace(promotion=output, keyring=args.keyring, frozen_run='', frozen_attempt='1', channel=getattr(args, 'channel', 'deb-oci')))


def receive_frozen(run_id, attempt, destination, *, channels=('deb', 'oci'),
                   publisher_job='Sign, promote and post-verify immutable distributions',
                   freeze_step='Freeze signed promotion bytes before publication',
                   artifact_prefix='downstream-frozen-promotion'):
    """Fetch and authenticate the actual immutable artifact ZIP before extraction."""
    require(run_id.isdecimal() and attempt.isdecimal(), 'An exact frozen run/attempt is required')
    run_metadata = json.loads(run(['gh', 'api', f'repos/dotnetdev-kr/cbodotnet/actions/runs/{run_id}']))
    require(run_metadata.get('head_branch') == 'main' and run_metadata.get('event') == 'workflow_dispatch'
            and run_metadata.get('path') == '.github/workflows/distribution-release.yml'
            and run_metadata.get('repository', {}).get('full_name') == 'dotnetdev-kr/cbodotnet'
            and run_metadata.get('head_repository', {}).get('full_name') == 'dotnetdev-kr/cbodotnet',
            'Frozen publication artifacts must originate from the trusted main workflow')
    jobs = json.loads(run(['gh', 'api', f'repos/dotnetdev-kr/cbodotnet/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100']))['jobs']
    publishers = [job for job in jobs if job['name'] == publisher_job]
    require(len(publishers) == 1 and any(step['name'] == freeze_step
            and step.get('conclusion') == 'success' for step in publishers[0].get('steps', [])),
            'The selected workflow attempt did not preserve complete signed bundles')
    artifacts = json.loads(run(['gh', 'api', f'repos/dotnetdev-kr/cbodotnet/actions/runs/{run_id}/artifacts?per_page=100']))['artifacts']
    expected_name = artifact_prefix + '-' + run_id + '-' + attempt
    artifacts = [item for item in artifacts if item.get('name') == expected_name]
    require(len(artifacts) == 1 and artifacts[0].get('expired') is False, 'An exact unexpired frozen artifact is required')
    artifact = artifacts[0]
    require(type(artifact.get('id')) is int and artifact['id'] > 0
            and re.fullmatch(r'sha256:[a-f0-9]{64}', artifact.get('digest', '')), 'Frozen artifact has no independent API digest')
    destination = Path(destination).absolute()
    require(not destination.exists() and not any(path.is_symlink() for path in [destination, *destination.parents]),
            'Frozen artifact extraction requires a fresh ordinary directory')
    with tempfile.TemporaryDirectory(prefix='cbodotnet-frozen-') as temporary:
        archive_path = Path(temporary) / 'artifact.zip'
        with archive_path.open('xb') as stream:
            result = subprocess.run(['gh', 'api', f'repos/dotnetdev-kr/cbodotnet/actions/artifacts/{artifact["id"]}/zip'],
                                    stdout=stream, stderr=subprocess.PIPE, timeout=900)
        require(result.returncode == 0, 'Frozen artifact download failed')
        require('sha256:' + digest(archive_path) == artifact['digest'], 'Frozen artifact ZIP differs from the GitHub API digest')
        with zipfile.ZipFile(archive_path) as archive:
            entries = archive.infolist()
            names = set()
            require(entries and sum(entry.file_size for entry in entries) < 8 * 1024**3, 'Unexpected frozen artifact extraction size')
            allowed_roots = {'bundle-' + channel for channel in channels} | {'promotion.json'}
            if 'oci' in channels:
                allowed_roots.add('oci-index.json')
            for entry in entries:
                name = entry.filename.rstrip('/')
                path = Path(name)
                mode = entry.external_attr >> 16
                require(name and not path.is_absolute() and '..' not in path.parts
                        and str(path) == name and not any(char in name for char in '\\:\0\r\n')
                        and path.parts[0] in allowed_roots
                        and name not in names and not mode & 0o7000
                        and stat.S_IFMT(mode) in {0, stat.S_IFDIR, stat.S_IFREG}, 'Unsafe frozen artifact member')
                require(path.parts[0] in {'bundle-' + channel for channel in channels} or len(path.parts) == 1,
                        'Frozen artifact metadata cannot contain child paths')
                names.add(name)
            destination.mkdir(parents=True)
            for entry in entries:
                target = destination / entry.filename
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(entry) as incoming, target.open('xb') as outgoing:
                        shutil.copyfileobj(incoming, outgoing)


def publish_staged(args):
    """Publish exactly frozen signed bytes, including after a partial publication."""
    from downstream_publish import validate_bundle, publish_bundle
    require(os.environ.get('GITHUB_REF') == 'refs/heads/main' and os.environ.get('GITHUB_REPOSITORY') == 'dotnetdev-kr/cbodotnet',
            'Only the protected main workflow may publish')
    promotion = args.promotion.resolve()
    channels = selected_channels(args)
    if args.frozen_run:
        receive_frozen(args.frozen_run, args.frozen_attempt, promotion, channels=channels)
    require(promotion.is_dir() and not any(path.is_symlink() for path in [promotion, *promotion.parents]),
            'An ordinary frozen promotion directory is required')
    metadata = json.loads((promotion / 'promotion.json').read_bytes())
    require(set(metadata.get('channels', {})) == set(channels)
            and {path.name for path in promotion.glob('bundle-*')} == {'bundle-' + channel for channel in channels},
            'Frozen promotion contains missing or unexpected channels')
    manifests = {channel: validate_bundle(promotion / ('bundle-' + channel), args.keyring) for channel in channels}
    require(all(manifest['identity']['channel'] == channel for channel, manifest in manifests.items()),
            'Frozen signed manifest belongs to another selected channel')
    first = manifests[channels[0]]
    target_commit = first['targetCommit']
    require(all(manifest['targetCommit'] == target_commit
                    and manifest['identity']['sdkVersion'] == first['identity']['sdkVersion']
                    and manifest['identity']['packageRevision'] == first['identity']['packageRevision']
                    and manifest['identity']['sourceManifestSha256'] == first['identity']['sourceManifestSha256']
                    for manifest in manifests.values()), 'Frozen channels contain different verified source identities')
    require(all(metadata['channels'][channel] == manifest['tag'] for channel, manifest in manifests.items()),
            'Frozen channel tags differ from their signed manifests')
    oci_assets = {row['name']: row for row in manifests['oci']['assets']}
    require('oci-index.json' in oci_assets and digest(promotion / 'oci-index.json') == oci_assets['oci-index.json']['sha256'],
            'Frozen index metadata differs from its signed publication manifest')
    for channel in channels:
        progress('publish or resume the exact frozen ' + channel + ' release bytes')
        if channel == 'deb' and any(row.get('delivery') == 'github-release-flat' for row in manifests[channel].get('repositories', [])):
            from apt_release import publish_flat_repositories
            flat = publish_flat_repositories(promotion / 'bundle-deb', args.keyring)
            (promotion / 'flat-apt-publication.json').write_bytes(encoded(flat))
        receipt = publish_bundle(promotion / ('bundle-' + channel), args.keyring, target_commit)
        (promotion / (channel + '-publication.json')).write_bytes(encoded(receipt))
    index = json.loads((promotion / 'oci-index.json').read_bytes())
    print(json.dumps(dict(status='published-and-bytes-postverified', targetCommit=target_commit, digest=index['digest'])))


def postverify(args):
    index = json.loads(args.index.read_bytes())
    expected_arch = 'amd64' if args.arch == 'x64' else 'arm64'
    require(platform.machine() in ({'aarch64', 'arm64'} if args.arch == 'aarch64' else {'x86_64'}), 'Post-pull verifier must be native')
    reference = index['repository'] + '@' + index['digest']
    # A newly created GHCR package starts private. Allow a bounded window for
    # its owner to expose that first publication, while always testing without
    # credentials and never treating an authenticated pull as public success.
    for attempt in range(25):
        try:
            run(['docker', 'pull', '--platform', 'linux/' + expected_arch, reference])
            break
        except RuntimeError:
            if attempt == 24:
                raise
            time.sleep(5)
    actual = json.loads(run(['docker', 'image', 'inspect', reference]))[0]
    expected = next(row for row in index['platforms'] if row['architecture'] == expected_arch)
    require(actual['Architecture'] == expected_arch and actual['Id'] == expected['configDigest'], 'Pulled image differs from qualified native image')
    labels = validate_published_metadata(index, expected)
    identity = re.fullmatch(r'([1-9][0-9]*\.[0-9]+\.[0-9]+)-debian13-r([1-9][0-9]*)', index['tag'])
    require(identity is not None, 'Published OCI identity is invalid')
    version, revision = identity[1], int(identity[2])
    sdk_root = '/opt/cbodotnet/' + sdk_series(version)
    source_pin = load_contract()['releases'][version]['manifestSha256']
    config_evidence = validate_image_config(actual, expected_arch, sdk_root, labels)
    file_evidence = inspect_consumer_files(reference, sdk_root, wrapper_license=expected.get('wrapperLicense'))
    require(run(['docker', 'run', '--rm', reference, 'id', '-u']).strip() != '0', 'Published image defaults to root')
    for name in ('cbodotnet-' + sdk_series(version), 'cbodotnet', 'dotnet'):
        result = subprocess.run(['docker', 'run', '--rm', '--network', 'none', reference, name, '--version'], text=True, capture_output=True)
        require(result.returncode == 0 and result.stdout == version + '\n' and result.stderr.strip() == BRAND,
                'Published alias/branding mismatch: ' + name)
        validate_sdk_listing(run(['docker', 'run', '--rm', '--network', 'none', reference, name, '--list-sdks']), version, sdk_root)
        info = run(['docker', 'run', '--rm', '--network', 'none', reference, name, '--info'])
        require(info.startswith(BRAND + '\n') and sdk_root in info,
                'Published alias info selected another host/root/RID')
        validate_host_rid(info, version, args.arch, 'debian-13')
        branding = json.loads(run(['docker', 'run', '--rm', '--network', 'none', reference, name, '--cbodotnet-info']))
        require(branding['sdkVersion'] == version and branding['packageRevision'] == revision
                and branding['sdkRoot'] == sdk_root and branding['sourceManifestSha256'] == source_pin,
                'Published alias identity differs from authenticated source/revision')
    functional_evidence = run_public_functional_smoke(reference, version, sdk_root)
    apt_results = postverify_apt(args) if args.deb_receipt is not None else []
    checks = ['anonymous-pull', 'native-config', 'non-root', 'command-aliases', 'cli-branding', 'offline-build-run',
              'sdk-list-paths', 'image-ownership', 'image-no-build-secrets', 'image-no-source-build-toolchain',
              'console-apphost', 'http-crypto-globalization', 'sdk-info-root-rid']
    if labels:
        checks.append('image-labels')
    if expected.get('wrapperLicense'):
        checks.append('image-wrapper-license')
    args.output.write_bytes(encoded(dict(schemaVersion=1, status='passed', architecture=args.arch, aptTargets=apt_results,
        repository=index['repository'], digest=index['digest'], imageConfig=config_evidence, imageFiles=file_evidence,
        functionalChecks=functional_evidence, networkForBuild='none', checks=checks)))
    print(json.dumps(dict(status='passed', architecture=args.arch, digest=index['digest'])))


def published_apt_location(metadata, plan):
    if metadata.get('delivery') is None:
        return None
    from apt_release import release_tag as repository_tag, repository_url
    require(metadata.get('delivery') == 'github-release-flat' and metadata.get('kind') == 'apt-repository'
            and metadata.get('variants') == [plan['variant']]
            and metadata.get('releaseTag') == repository_tag(plan['variant'], plan['sdkVersion'], plan['packageRevision']),
            'Signed flat APT repository tag differs from exact SDK/variant/revision')
    return repository_url(plan['variant'], plan['sdkVersion'], plan['packageRevision'])


def postverify_apt(args):
    from downstream_release import verify_report_signature, load_status
    from downstream_publish import MANIFEST, SIGNATURE
    receipt = json.loads(args.deb_receipt.read_bytes())
    require(receipt.get('status') == 'published-postverified' and receipt['identity']['channel'] == 'deb', 'A published Debian receipt is required')
    from downstream_publish import release_tag
    require(receipt.get('repository') == 'dotnetdev-kr/cbodotnet'
            and receipt['tag'] == release_tag('deb', receipt['identity']['sdkVersion'], receipt['identity']['packageRevision']),
            'Published APT receipt repository/tag differs from its exact identity')
    workspace = args.output.parent / ('published-apt-' + args.arch)
    require(not workspace.exists(), 'Published installation workspace must be fresh')
    workspace.mkdir()
    base = 'https://github.com/dotnetdev-kr/cbodotnet/releases/download/' + receipt['tag'] + '/'
    for name in (MANIFEST, SIGNATURE):
        urllib.request.urlretrieve(base + name, workspace / name)
    require(digest(workspace / MANIFEST) == receipt['manifestSha256'], 'Published manifest differs from signed receipt')
    keyring = workspace / 'trusted.gpg'
    run(['gpg', '--batch', '--yes', '--dearmor', '--output', keyring, ROOT / 'releases/downstream-signing-key.asc'])
    signer = verify_report_signature(workspace / MANIFEST, workspace / SIGNATURE, keyring,
                                     load_status(), '.github/workflows/distribution-release.yml')
    manifest = json.loads((workspace / MANIFEST).read_bytes())
    require(signer == manifest['signingFingerprint'] == receipt['signingFingerprint']
            and manifest['identity'] == receipt['identity'] and manifest['tag'] == receipt['tag']
            and manifest['repository'] == receipt['repository'], 'Published APT manifest identity/signer differs from its receipt')
    inputs = workspace / 'inputs'
    sdk_version = receipt['identity']['sdkVersion']
    receive_release('sdk-' + sdk_version, inputs, 'deb', 'debian-13', args.arch, receipt['identity']['packageRevision'])
    artifacts = {row['name']: row for row in manifest['assets']}
    results = []
    for variant, base_image in [('ubuntu-24.04', UBUNTU_BASE), ('debian-13', DEBIAN_BASE)]:
        metadata = [row for row in manifest['repositories'] if row['kind'] == 'apt-repository' and variant in row['variants']]
        require(len(metadata) == 1, 'Published APT variant is absent or ambiguous')
        name = metadata[0]['asset']
        require('/' not in name and '\\' not in name, 'Unsafe published repository asset name')
        archive = workspace / name
        urllib.request.urlretrieve(base + name, archive)
        require(archive.stat().st_size == artifacts[name]['size'] and digest(archive) == artifacts[name]['sha256'], 'Published APT repository digest mismatch')
        delivery = workspace / variant
        delivery.mkdir()
        repository = delivery / 'repository'
        repository.mkdir()
        with tarfile.open(archive, 'r:gz') as incoming:
            for member in incoming.getmembers():
                relative = Path(member.name)
                require(not relative.is_absolute() and '..' not in relative.parts and (member.isdir() or member.isfile())
                        and not member.mode & 0o7000, 'Unsafe signed repository archive member')
            incoming.extractall(repository, filter='data')
        from published_apt import verify_packages_index, package_descriptors, verify_cache_file
        release_text = run(['gpgv', '--keyring', keyring, '--output', '-', repository / 'InRelease'])
        index_bytes = (repository / 'Packages').read_bytes()
        verify_packages_index(release_text, index_bytes)
        plan = local_intake(inputs, 'deb', variant, args.arch, receipt['identity']['packageRevision'])
        (delivery / 'plan.json').write_bytes(encoded(plan))
        (delivery / 'post-publication').touch()
        (delivery / 'packages').mkdir()
        expected_arch = plan['architecture']['deb']
        location = published_apt_location(metadata[0], plan)
        flat = location is not None
        if location:
            (delivery / 'repository-url.txt').write_text(location)
        descriptors = package_descriptors(index_bytes, sdk_version, plan['packageRevision'], expected_arch, flat=flat)
        for item in descriptors:
            path = repository / item['filename']
            verify_cache_file(path, item)
            shutil.copy2(path, delivery / 'packages' / path.name)
        container_lifecycle(workspace, delivery, base_image, variant, 'deb')
        result = json.loads((delivery / 'installation-result.json').read_bytes())
        require(result['status'] == 'passed', 'Published APT installation did not pass')
        results.append(dict(variant=variant, architecture=args.arch, repositorySha256=artifacts[name]['sha256'],
                            status='passed', checks=result['checks']))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('native')
    command.add_argument('--workspace', type=Path, required=True)
    command.add_argument('--channel', choices=('deb-oci', 'deb', 'oci'), default='deb-oci')
    command.add_argument('--tag', default='sdk-10.0.403')
    command.add_argument('--revision', type=int, default=1)
    command.add_argument('--arch', choices=('x64', 'aarch64'), required=True)
    command.add_argument('--debian-base', default=DEBIAN_BASE)
    command.add_argument('--ubuntu-base', default=UBUNTU_BASE)
    command = commands.add_parser('installed')
    command.add_argument('--delivery', type=Path, required=True)
    command.add_argument('--variant', required=True)
    command.add_argument('--mode', choices=('deb', 'oci'), required=True)
    command.add_argument('--phase', choices=('prepare', 'lifecycle'), default='lifecycle')
    command = commands.add_parser('promote')
    command.add_argument('--channel', choices=('deb-oci', 'oci'), default='deb-oci')
    command.add_argument('--received', type=Path, required=True)
    command.add_argument('--output', type=Path, required=True)
    command.add_argument('--signing-key', required=True)
    command.add_argument('--keyring', type=Path, required=True)
    command.add_argument('--source-run', default='')
    command.add_argument('--source-attempt', default='1')
    command.add_argument('--stage-only', action='store_true')
    command = commands.add_parser('publish-staged')
    command.add_argument('--channel', choices=('deb-oci', 'oci'), default='deb-oci')
    command.add_argument('--promotion', type=Path, required=True)
    command.add_argument('--keyring', type=Path, required=True)
    command.add_argument('--frozen-run', default='')
    command.add_argument('--frozen-attempt', default='1')
    command = commands.add_parser('postverify')
    command.add_argument('--index', type=Path, required=True)
    command.add_argument('--arch', choices=('x64', 'aarch64'), required=True)
    command.add_argument('--output', type=Path, required=True)
    command.add_argument('--deb-receipt', type=Path)
    args = parser.parse_args()
    try:
        {'native': native, 'installed': installed, 'promote': promote, 'publish-staged': publish_staged, 'postverify': postverify}[args.command](args)
    except (ValueError, OSError, RuntimeError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
