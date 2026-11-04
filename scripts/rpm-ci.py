#!/usr/bin/env python3
"""Build and prove qualified RPM installations on native Fedora and Rocky Linux."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import urllib.request

from distribution_contract import load_contract
from sdk_runtime import runtime_policy, smoke_script, validate_host_rid, validate_smoke_output
from downstream_release import (encoded, local_intake, package_record, receive_release,
                                PREPUBLICATION_CHECKS, verify_report_signature, load_status)

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('rpm_shared_ci', ROOT / 'scripts/distribution-ci.py')
SHARED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SHARED)
BASES = {
    'fedora-45': {
        'x64': 'quay.io/fedora/fedora:45@sha256:ea0998f4c945b85c2134793cda4fac35ee394f0d677a04c5b1fe769e13f959b8',
        'aarch64': 'quay.io/fedora/fedora:45@sha256:0b22780214954d098cffee33d7c5658ca99d8de06d231b2a00ebfda501b27a30'},
    'rocky-9.8': {
        'x64': 'quay.io/rockylinux/rockylinux:9.8@sha256:ed654c694190a670bb5c33f68995b862214fc96ffbdca95e07a8935ba0a3717d',
        'aarch64': 'quay.io/rockylinux/rockylinux:9.8@sha256:67492e5a371d9db7c2ffb2708abae92147fb900900832a7ed3fb2ac4df9ec052'},
}
BRAND = 'Community Build of .NET (built by .NET Dev)'
PATH = '/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def progress(message):
    print('rpm-ci: ' + message, flush=True)


def run(command, **kwargs):
    return SHARED.run(command, **kwargs)


def load(path):
    return json.loads(Path(path).read_bytes())


def save(path, value):
    Path(path).write_bytes(encoded(value))


def expected_native(arch):
    return {'x86_64'} if arch == 'x64' else {'aarch64', 'arm64'}


def validate_target(plan, release=None, machine=None):
    release = release if release is not None else {
        key: value.strip('"') for key, value in (line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)}
    machine = machine or platform.machine()
    expected = load_contract()['operatingSystems'][plan['variant']]
    require(release.get('ID') == expected['id'] and release.get('VERSION_ID') == expected['versionId'],
            'RPM proof executed on another distro/version')
    require(machine in expected_native(plan['architecture']['public']), 'RPM proof requires its native architecture')
    return expected


def package_paths(delivery, directory='packages'):
    values = sorted((Path(delivery) / directory).glob('*.rpm'))
    require(len(values) in {2, 3} and sum(path.name.startswith('cbodotnet-host-') for path in values) == 1
            and sum(path.name.startswith('cbodotnet-sdk-') for path in values) == 1
            and sum(path.name.startswith('cbodotnet-compat-rocky9-') for path in values) == len(values) - 2,
            'SDK, common-host and any reviewed compatibility RPMs are required')
    return values


def rpm_version(name):
    return run(['rpm', '-q', '--queryformat', '%{VERSION}-%{RELEASE}', name]).strip()


def required_package_identities(plan, revision=None):
    revision = plan['packageRevision'] if revision is None else revision
    release = plan['package']['rpmRelease']
    match = re.fullmatch(r'[1-9][0-9]*(\.cbot\.[a-z0-9.]+)', release)
    require(match is not None, 'Reviewed RPM release format is required')
    result = {
        plan['package']['name']: [plan['sdkVersion'], str(revision) + match[1], plan['architecture']['rpm']],
        'cbodotnet-host': ['1.0.0', '1' + match[1], 'noarch'],
    }
    if runtime_policy(plan['sdkVersion'], 'x64')['legacy']:
        from legacy_compat import load_policy
        provider = load_policy()
        result[provider['packageName']] = [provider['version'], '1' + match[1], plan['architecture']['rpm']]
    return result


def package_identities(plan, revision=None):
    result = {}
    for name, wanted in required_package_identities(plan, revision).items():
        fields = run(['rpm', '-q', '--queryformat', '%{VERSION}\t%{RELEASE}\t%{ARCH}', name]).strip().split('\t')
        require(fields == wanted, 'Installed RPM identity differs from reviewed version/release/architecture: ' + name)
        result[name] = dict(version=fields[0], release=fields[1], architecture=fields[2])
    return result


def cached_packages(plan, cache=Path('/var/cache')):
    expected = required_package_identities(plan)
    selected = {}
    # DNF preserves the public location basename, including our release asset
    # prefixes. Package headers, rather than filenames, identify signature proofs.
    for path in sorted(cache.rglob('*.rpm')):
        fields = run(['rpm', '-qp', '--queryformat', '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}', path]).strip().split('\t')
        require(len(fields) == 4, 'A cached RPM has an invalid package identity')
        name = fields[0]
        if name not in expected:
            continue
        require(fields[1:] == expected[name] and name not in selected,
                'Cached signed RPM identity is duplicated or differs from the reviewed version/release/architecture')
        selected[name] = path
    require(set(selected) == set(expected), 'Signed DNF installation must retain both package signature proofs')
    return [selected[name] for name in sorted(selected)]


def verify_package_signature(path):
    value = run(['rpmkeys', '--checksig', '--verbose', path])
    # RPM4 prints "Signature" while RPM6 prints "signature". Require an
    # explicitly successful signature line as well as rpmkeys' successful exit.
    require(re.search(r'\bsignature\b[^\n]*:\s*OK\s*$', value, re.IGNORECASE | re.MULTILINE)
            and not re.search(r'\b(?:NOKEY|NOT\s+OK|NOTFOUND|NOTTRUSTED|BAD|FAILED)\b', value, re.IGNORECASE),
            'An RPM payload signature failed: ' + str(path) + '\n' + value)
    return value


def strict_integrity(names):
    output = run(['rpm', '-V', *names])
    require(not output.strip(), 'Installed RPM integrity verification reported changed or missing files: ' + output)


def retain_signed_packages(delivery, paths):
    retained = Path(delivery) / 'retained-packages'
    retained.mkdir()
    result = []
    for source in paths:
        require(source.is_file() and not source.is_symlink(), 'Signed RPM cache must contain ordinary package files')
        verify_package_signature(source)
        expected = SHARED.digest(source)
        destination = retained / source.name
        require(not destination.exists(), 'Duplicate retained signed RPM filename')
        shutil.copyfile(source, destination)
        require(source.stat().st_size == destination.stat().st_size and SHARED.digest(destination) == expected,
                'Retained signed RPM bytes differ from authenticated cache')
        result.append(destination)
    return result


def local_transaction(paths, action='install', signed=False):
    # Unsigned files are admitted only in the isolated producer test, after
    # source/package digests are verified. Public repositories always require
    # both package and repository signatures.
    return run(['dnf', '-y', *repository_options(), '--setopt=install_weak_deps=False', '--setopt=tsflags=',
                '--setopt=localpkg_gpgcheck=' + ('1' if signed else '0'), action, *map(str, paths)])


def repository_options(enabled=None):
    # Fedora's DNF5 renamed these options; Rocky 9 retains DNF4.
    modern = Path('/usr/bin/dnf5').exists()
    values = ['--disable-repo=*' if modern else '--disablerepo=*']
    if enabled:
        values.append(('--enable-repo=' if modern else '--enablerepo=') + enabled)
    return values


def as_user(arguments, cwd=Path('/home/cbot-smoke'), runtime_env=None):
    return run(['runuser', '-u', 'cbot-smoke', '--', 'env', 'PATH=' + PATH,
                'HOME=/home/cbot-smoke', 'DOTNET_CLI_HOME=/home/cbot-smoke',
                'NUGET_PACKAGES=/home/cbot-smoke/.nuget/packages', 'DOTNET_CLI_TELEMETRY_OPTOUT=1',
                'DOTNET_NOLOGO=1', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1', 'DOTNET_CLI_UI_LANGUAGE=en',
                'DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=1',
                *[name + '=' + value for name, value in (runtime_env or {}).items()], *map(str, arguments)], cwd=cwd)


def observed_dependencies(plan):
    result = {}
    for name in plan['dependencies']:
        value = run(['rpm', '-q', '--whatprovides', '--queryformat', '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n', name]).strip()
        require(value and 'not installed' not in value and 'no package provides' not in value, 'Unavailable native RPM dependency: ' + name)
        result[name] = value
    return result


def check_aliases(plan):
    series = '.'.join(plan['sdkVersion'].split('.')[:2])
    root = plan['package']['root']
    for command in ('cbodotnet-' + series, 'cbodotnet'):
        value = subprocess.run(['runuser', '-u', 'cbot-smoke', '--', 'env', 'PATH=' + PATH,
                                'HOME=/home/cbot-smoke', 'DOTNET_CLI_TELEMETRY_OPTOUT=1',
                                'DOTNET_NOLOGO=1', command, '--version'], text=True, capture_output=True)
        require(value.returncode == 0 and value.stdout == plan['sdkVersion'] + '\n' and value.stderr.strip() == BRAND,
                'RPM alias version/branding mismatch: ' + command)
        identity = json.loads(as_user([command, '--cbodotnet-info']))
        require(identity['sdkVersion'] == plan['sdkVersion'] and identity['packageRevision'] == plan['packageRevision']
                and identity['sourceManifestSha256'] == plan['sourceManifestSha256'] and identity['sdkRoot'] == root,
                'RPM alias selected another qualified root/revision')
        info = as_user([command, '--info'])
        require(info.startswith(BRAND + '\n') and root in info,
                'RPM alias host/runtime information differs from the expected root')
        validate_host_rid(info, plan['sdkVersion'], plan['architecture']['public'], plan['variant'])
        SHARED.validate_sdk_listing(as_user([command, '--list-sdks']), plan['sdkVersion'], root)


def source_payload(plan, delivery):
    expected = Path(tempfile.mkdtemp(prefix='cbot-rpm-payload-')) / 'sdk'
    SHARED.extractor()(Path('/delivery/inputs') / plan['sdk']['name'], expected)
    for name in plan['additionalDirectories']:
        (expected / name).mkdir(mode=0o755, exist_ok=True)
    require(SHARED.inventory(expected) == SHARED.inventory(Path(plan['package']['root'])),
            'RPM installation changed qualified SDK bytes or modes')
    shutil.rmtree(expected.parent)


def native_libraries(plan, output, runtime_env=None):
    root = Path(plan['package']['root'])
    selected = [root / 'dotnet']
    for pattern in ('host/fxr/*/libhostfxr.so', 'shared/Microsoft.NETCore.App/*/libcoreclr.so',
                    'shared/Microsoft.NETCore.App/*/libhostpolicy.so', 'shared/Microsoft.NETCore.App/*/libSystem.Native.so',
                    'shared/Microsoft.NETCore.App/*/libSystem.Globalization.Native.so',
                    'shared/Microsoft.NETCore.App/*/libSystem.Security.Cryptography.Native.OpenSsl.so'):
        selected.extend(sorted(root.glob(pattern)))
    require(len(selected) >= 7, 'The complete baseline native runtime library set is required')
    rows = []
    for path in selected:
        value = run(['ldd', path], env=dict(os.environ, **(runtime_env or {})))
        require('not found' not in value, 'Unresolved baseline native library: ' + str(path))
        rows.append({'path': path.relative_to(root).as_posix(), 'ldd': value})
    save(output / 'native-libraries.json', rows)


def prepare_installed(args):
    require(os.geteuid() == 0 and Path('/.dockerenv').is_file(), 'A disposable root RPM container is required')
    delivery = args.delivery.resolve()
    plan = load(delivery / 'plan.json')
    validate_target(plan)
    run(['useradd', '--create-home', '--uid', '10001', 'cbot-smoke'])
    from rpm_official import bootstrap
    progress('install the official SDK through the signed stock distribution RPM repositories')
    official_baseline = bootstrap(plan['variant'], plan['architecture']['public'], 'cbot-smoke', delivery / 'official-state.json')
    compatibility = None
    if runtime_policy(plan['sdkVersion'], plan['architecture']['public'])['legacy']:
        from legacy_compat import provision
        compatibility = provision(plan, delivery, user='cbot-smoke')
    published = args.published == 'yes'
    if published:
        # Legacy RPM4 imports ASCII-armored public keys; gpgv separately uses
        # the binary keyring to authenticate repository metadata.
        key = delivery / 'repository/cbodotnet-rpm-signing-key.asc'
        expected_key = (delivery / 'expected-fingerprint.txt').read_text().strip()
        require(re.fullmatch(r'[A-F0-9]{40,64}', expected_key), 'An authenticated repository fingerprint is required')
        text = run(['gpg', '--batch', '--show-keys', '--with-colons', key])
        primary = []
        wanted = False
        for line in text.splitlines():
            fields = line.split(':')
            if fields[0] == 'pub': wanted = True
            elif fields[0] == 'fpr' and wanted:
                primary.append(fields[9]); wanted = False
        require(primary == [expected_key], 'DNF repository key differs from the reviewed primary fingerprint')
        run(['rpmkeys', '--import', key])
        base_url = (delivery / 'repository-url.txt').read_text().strip() if (delivery / 'repository-url.txt').exists() else 'file://' + str(delivery / 'repository')
        require(base_url.startswith('https://') or base_url.startswith('file:///delivery/'), 'Unsupported DNF repository location')
        Path('/etc/yum.repos.d/cbodotnet-validation.repo').write_text('[cbodotnet-validation]\nname=Community Build of .NET validation\n'
            + 'baseurl=' + base_url.rstrip('/') + '/\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file://' + str(key) + '\n')
        run(['dnf', '-y', '--refresh', *repository_options('cbodotnet-validation'), 'makecache'])
        release = plan['package']['rpmRelease']
        run(['dnf', '-y', *repository_options('cbodotnet-validation'), '--setopt=tsflags=',
             '--setopt=keepcache=True', 'install', plan['package']['name'] + '-' + plan['sdkVersion'] + '-' + release, 'cbodotnet-host'])
        cached = cached_packages(plan)
        for path in cached:
            verify_package_signature(path)
        save(delivery / 'package-signatures.json', {'status': 'passed', 'signingFingerprint': expected_key,
                                                  'packages': [dict(name=path.name, sha256=SHARED.digest(path)) for path in cached]})
    else:
        build = load(delivery / 'packages/package-build.json')
        for package in build['packages']:
            path = delivery / 'packages' / package['path']
            require(path.stat().st_size == package['size'] and SHARED.digest(path) == package['sha256'], 'Unsigned staging package differs from its build record')
        local_transaction(package_paths(delivery))
    save(delivery / 'installed-package-identities.json', package_identities(plan))
    source_payload(plan, delivery)
    strict_integrity([plan['package']['name'], 'cbodotnet-host'])
    save(delivery / 'sdk-before.json', SHARED.inventory(Path(plan['package']['root'])))
    save(delivery / 'installed-state.json', dict(published=published, osRelease=Path('/etc/os-release').read_text(),
                                              compatibilityState=compatibility, officialBaseline=official_baseline))


def lifecycle(args):
    require(os.geteuid() == 0 and Path('/.dockerenv').is_file(), 'A disposable root RPM container is required')
    require({path.name for path in Path('/sys/class/net').iterdir()} == {'lo'}, 'Runtime proof requires Docker --network none')
    delivery = args.delivery.resolve()
    plan = load(delivery / 'plan.json')
    target = validate_target(plan)
    state = load(delivery / 'installed-state.json')
    official = Path(state['officialBaseline']['officialRoot'])
    official_version = state['officialBaseline']['sdkVersion']
    official_proofs = []
    compatibility_proofs = []

    def official_check(phase):
        from rpm_official import assert_unchanged
        proof = assert_unchanged(delivery / 'official-state.json')
        require(proof['status'] == 'passed' and as_user(['dotnet', '--version']).strip() == official_version,
                'RPM lifecycle changed official package-manager dotnet selection')
        official_proofs.append(dict(phase=phase, **proof))
        if state.get('compatibilityState'):
            from legacy_compat import assert_unchanged as assert_provider
            compatibility_proofs.append(dict(phase=phase, **assert_provider(state['compatibilityState'])))

    root = Path(plan['package']['root'])
    official_check('after-install')
    check_aliases(plan)
    report = Path('/home/cbot-smoke/verification')
    arch = 'x64' if plan['architecture']['public'] == 'x64' else 'arm64'
    policy = runtime_policy(plan['sdkVersion'], plan['architecture']['public'])
    runtime_env = {}
    if policy['legacy']:
        from legacy_compat import runtime_environment, assert_unchanged as assert_compatibility
        require(state.get('compatibilityState'), 'Prepared RPM compatibility provider state is missing')
        runtime_env = runtime_environment(plan, state['compatibilityState'])
    reported_rid = validate_host_rid(as_user(['cbodotnet', '--info']), plan['sdkVersion'], plan['architecture']['public'], plan['variant'])
    functional = validate_smoke_output(as_user(['sh', '-ec', smoke_script(plan['sdkVersion'], str(root), 'cbot-smoke',
                    cli='cbodotnet', workdir='/home/cbot-smoke/functional', runtime_env=runtime_env)]))
    as_user(['bash', ROOT / 'scripts/verify-sdk.sh', '--sdk-dir', root, '--output-dir', report,
             '--expected-version', plan['sdkVersion'], '--expected-rid', reported_rid, '--framework', policy['framework'],
             '--max-glibc', policy['maxGlibc'], '--arch', arch, '--no-smoke'], runtime_env=runtime_env)
    verification = load(report / 'verification.json')
    require(verification['verificationStatus'] == 'passed' and verification['abi']['glibcCeilingPassed'], 'Installed RPM native SDK ABI verification failed')
    reports = delivery / 'reports'
    shutil.copytree(report, reports)
    native_libraries(plan, reports, runtime_env=runtime_env)
    dependencies = observed_dependencies(plan)
    strict_integrity([plan['package']['name'], 'cbodotnet-host'])
    require(SHARED.inventory(root) == load(delivery / 'sdk-before.json'), 'SDK execution modified qualified RPM payload')
    official_check('after-runtime')
    if not state['published']:
        progress('upgrade RPM revision then downgrade to the original immutable RPM')
        local_transaction(package_paths(delivery, 'upgrade'))
        upgraded = dict(plan, packageRevision=plan['packageRevision'] + 1)
        check_aliases(upgraded)
        package_identities(plan, revision=plan['packageRevision'] + 1)
        require(SHARED.inventory(root) == load(delivery / 'sdk-before.json'), 'RPM upgrade changed SDK payload')
        strict_integrity(list(required_package_identities(plan)))
        official_check('after-upgrade')
        original_sdk = [path for path in package_paths(delivery) if path.name.startswith('cbodotnet-sdk-')]
        local_transaction(original_sdk, action='downgrade')
        check_aliases(plan)
        package_identities(plan)
        require(SHARED.inventory(root) == load(delivery / 'sdk-before.json'), 'RPM rollback changed SDK payload')
        strict_integrity([plan['package']['name'], 'cbodotnet-host'])
        official_check('after-rollback')
    originals = retain_signed_packages(delivery, cached_packages(plan)) if state['published'] else package_paths(delivery)
    run(['dnf', '-y', *repository_options(), '--setopt=clean_requirements_on_remove=False', 'remove', plan['package']['name']])
    require(not root.exists() and Path('/usr/bin/cbodotnet').is_file() and not Path(plan['package']['launcher']).exists(), 'RPM removal violated versioned/shared ownership')
    value = subprocess.run(['runuser', '-u', 'cbot-smoke', '--', 'cbodotnet', '--version'], text=True, capture_output=True)
    require(value.returncode == 127 and not value.stdout, 'Removed RPM SDK fell back to an official host')
    strict_integrity(['cbodotnet-host'])
    official_check('after-remove')
    progress('reinstall the original RPM before verifying complete installed-package erasure')
    local_transaction(originals, signed=state['published'])
    package_identities(plan)
    check_aliases(plan)
    require(SHARED.inventory(root) == load(delivery / 'sdk-before.json'), 'RPM reinstallation changed qualified SDK payload')
    strict_integrity(list(required_package_identities(plan)))
    official_check('after-reinstall')
    run(['dnf', '-y', *repository_options(), '--setopt=clean_requirements_on_remove=False', 'remove', plan['package']['name']])
    require(not root.exists() and not Path(plan['package']['launcher']).exists(), 'Installed RPM erasure left SDK payload or configuration')
    erased = subprocess.run(['rpm', '-q', plan['package']['name']], text=True, capture_output=True)
    require(erased.returncode == 1, 'Installed RPM erasure did not remove the package database record')
    strict_integrity(['cbodotnet-host'] + (['cbodotnet-compat-rocky9'] if state.get('compatibilityState') else []))
    official_check('after-erasure')
    checks = {name: 'passed' for name in PREPUBLICATION_CHECKS}
    checks.update({'rpm-integrity': 'passed', 'dnf-install': 'passed', 'package-integrity': 'passed',
                   'package-manager-install': 'passed', 'rollback': 'passed',
                   'official-package-coexistence': 'passed', 'installed-package-erasure': 'passed',
                   'package-signatures': 'passed' if state['published'] else 'pending-signing-stage',
                   'repository-metadata': 'passed' if state['published'] else 'pending-signing-stage'})
    if state['published']:
        checks.update(upgrade='verified-before-publication', rollback='verified-before-publication')
    result = dict(schemaVersion=1, status='passed', target=dict(osId=target['id'], versionId=target['versionId'],
        architecture=plan['architecture']['public'], native=True, dependencies=dependencies, osRelease=state['osRelease']),
        checks=checks, functionalChecks=functional, runtimePolicy=policy, abi=verification['abi'], networkForBuild='none',
        officialComparison=state['officialBaseline'], officialCoexistence=official_proofs)
    result['packageIdentities'] = load(delivery / 'installed-package-identities.json')
    if runtime_env:
        result['compatibilityProvider'] = compatibility_proofs
    save(delivery / 'installation-result.json', result)
    # Only evidence ownership changes; never SDK payload modes or package bytes.
    uid, gid = (int(value) for value in os.environ.get('BUILDER_OWNER', '1001:1001').split(':'))
    for path in [delivery / 'installation-result.json', *reports.rglob('*'), reports]:
        os.chown(path, uid, gid)


def build_in_container(args):
    delivery = args.delivery.resolve()
    plan = load(delivery / 'plan.json')
    validate_target(plan)
    compatibility_args = []
    if runtime_policy(plan['sdkVersion'], plan['architecture']['public'])['legacy']:
        from legacy_compat import build_provider
        output = delivery / 'compatibility-build'
        build_provider(plan['architecture']['public'], output, variant=plan['variant'])
        compatibility_args = ['--compatibility-build', output / 'provider-build.json']
    for revision, name in [(plan['packageRevision'], 'build'), (plan['packageRevision'] + 1, 'upgrade-build')]:
        progress('build ' + plan['variant'] + ' RPM revision ' + str(revision))
        run(['python3', ROOT / 'scripts/package-sdk.py', '--inputs', '/delivery/inputs', '--channel', 'rpm',
             '--variant', plan['variant'], '--arch', plan['architecture']['public'], '--revision', revision, '--output', delivery / name,
             *compatibility_args])
        directory = delivery / ('packages' if name == 'build' else 'upgrade')
        directory.mkdir()
        for path in (delivery / name).glob('*.rpm'):
            shutil.copy2(path, directory / path.name)
        for path in (delivery / name).glob('cbodotnet-compat-*.tar.gz'):
            shutil.copy2(path, directory / path.name)
        shutil.copy2(delivery / name / 'package-build.json', directory / 'package-build.json')
    SHARED.copy_commands(delivery / 'build', delivery / 'commands')
    shutil.rmtree(delivery / 'build')
    shutil.rmtree(delivery / 'upgrade-build')


def record(delivery, inputs):
    plan = load(delivery / 'plan.json')
    manifest = load(delivery / 'packages/package-build.json')
    artifact = delivery / 'packages' / next(row['path'] for row in manifest['packages'] if row['kind'] == 'sdk')
    ref = os.environ.get('GITHUB_WORKFLOW_REF', 'dotnetdev-kr/cbodotnet/.github/workflows/distribution-release.yml@refs/heads/main')
    workflow = ref.split('@', 1)[0].removeprefix('dotnetdev-kr/cbodotnet/')
    orchestration = dict(repository='dotnetdev-kr/cbodotnet', workflow=workflow, commit=os.environ['GITHUB_SHA'],
                         runId=os.environ['GITHUB_RUN_ID'], runAttempt=os.environ['GITHUB_RUN_ATTEMPT'])
    packaged = package_record(plan, artifact, orchestration,
                             extra_files={'root': delivery / 'commands', 'inventory': load(delivery / 'commands.json')})
    result = load(delivery / 'installation-result.json')
    report = {**result, 'phase': 'prepublication', 'scope': 'channel-installation',
              **{key: packaged[key] for key in ('contractVersion', 'identity', 'artifact', 'source', 'producer', 'orchestration', 'branding', 'commands', 'extraFiles')}}
    save(delivery / 'package.json', packaged)
    save(delivery / 'report.json', report)
    return dict(packagePath=str(delivery / 'package.json'), artifactPath=str(artifact), reportPath=str(delivery / 'report.json'),
                commandsRoot=str(delivery / 'commands'), inputsDirectory=str(inputs))


def container_lifecycle(workspace, delivery, base, published=False):
    owner = str(os.getuid()) + ':' + str(os.getgid())
    cid = None
    image = None
    try:
        progress('prepare native installed ' + delivery.name)
        cid = run(['docker', 'create', '--user', '0', '-v', f'{ROOT}:/repo:ro', '-v', f'{workspace}:/delivery',
                   base, 'bash', '/repo/scripts/verify-rpm-install.sh', '/repo', '/delivery/' + delivery.name,
                   load(delivery / 'plan.json')['variant'], 'prepare-published' if published else 'prepare']).strip()
        run(['docker', 'start', '--attach', cid])
        code = json.loads(run(['docker', 'inspect', cid]))[0]['State']['ExitCode']
        require(code == 0, 'RPM installation container failed')
        image = run(['docker', 'commit', cid]).strip()
        run(['docker', 'run', '--rm', '--network', 'none', '--user', '0', '-e', 'BUILDER_OWNER=' + owner,
             '-v', f'{ROOT}:/repo:ro', '-v', f'{workspace}:/delivery', image,
             'bash', '/repo/scripts/verify-rpm-install.sh', '/repo', '/delivery/' + delivery.name,
             load(delivery / 'plan.json')['variant'], 'smoke'])
    finally:
        if cid:
            subprocess.run(['docker', 'rm', '--force', cid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if image:
            subprocess.run(['docker', 'image', 'rm', image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def native(args):
    require(os.getuid() != 0 and platform.machine() in expected_native(args.arch), 'A matching non-root native Linux producer is required')
    workspace = args.workspace.resolve()
    require(not workspace.exists(), 'RPM delivery workspace must be fresh')
    workspace.mkdir(parents=True)
    inputs = workspace / 'inputs'
    variants = [args.variant] if args.variant else list(BASES)
    if args.inputs:
        source = args.inputs.resolve()
        first = local_intake(source, 'rpm', variants[0], args.arch, args.revision)
        inputs.mkdir()
        for name in ('release.json', 'release-manifest.json', 'SHA256SUMS', first['sdk']['name']):
            shutil.copy2(source / name, inputs / name)
    else:
        receive_release(args.tag, inputs, 'rpm', variants[0], args.arch, args.revision)
    items = []
    for variant in variants:
        plan = local_intake(inputs, 'rpm', variant, args.arch, args.revision)
        delivery = workspace / ('rpm-' + variant)
        delivery.mkdir()
        save(delivery / 'plan.json', plan)
        progress('build native RPMs for ' + variant + ' ' + args.arch)
        base = BASES[variant][args.arch]
        run(['docker', 'run', '--rm', '--user', '0', '-e', 'BUILDER_UID=' + str(os.getuid()), '-e', 'BUILDER_GID=' + str(os.getgid()),
             '-v', f'{ROOT}:/repo:ro', '-v', f'{workspace}:/delivery', base,
             'bash', '/repo/scripts/verify-rpm-install.sh', '/repo', '/delivery/' + delivery.name, variant, 'build'])
        container_lifecycle(workspace, delivery, base)
        items.append(record(delivery, inputs))
        shutil.rmtree(delivery / 'upgrade')
        progress('passed native RPM install/build/HTTP/upgrade/rollback/removal for ' + variant)
    save(workspace / 'items.json', items)
    print(json.dumps(dict(status='passed', architecture=args.arch, variants=variants)))


def validate_receipt(receipt, contract=None):
    from downstream_publish import MANIFEST, SIGNATURE, PUBLIC_KEY, REPOSITORY, release_tag
    require(receipt.get('schemaVersion') == 1 and receipt.get('status') == 'published-postverified'
            and receipt.get('repository') == REPOSITORY and receipt.get('publicationAllowed') is True,
            'A published receipt for the exact RPM project is required')
    identity = receipt['identity']
    require(identity.get('channel') == 'rpm', 'A published RPM receipt is required')
    tag = release_tag('rpm', identity['sdkVersion'], identity['packageRevision'])
    require(receipt.get('tag') == tag, 'RPM receipt tag differs from immutable channel identity')
    contract = contract if contract is not None else load_contract()
    admitted = contract['releases'].get(identity['sdkVersion'], {})
    require(admitted.get('manifestSha256') == identity.get('sourceManifestSha256')
            and identity.get('sourceReleaseTag') == 'sdk-' + identity['sdkVersion'],
            'RPM receipt source is no longer admitted')
    base = f'https://github.com/{REPOSITORY}/releases/download/{tag}/'
    require(receipt.get('releaseUrl') == f'https://github.com/{REPOSITORY}/releases/tag/{tag}'
            and receipt.get('manifestUrl') == base + MANIFEST and receipt.get('signatureUrl') == base + SIGNATURE
            and receipt.get('publicKeyUrl') == base + PUBLIC_KEY
            and re.fullmatch(r'[a-f0-9]{64}', receipt.get('manifestSha256', '')),
            'RPM receipt URLs or manifest digest differ from canonical publication')
    return base


def bind_signed_receipt(receipt, manifest, signer, directory, contract=None):
    from downstream_publish import MANIFEST, SIGNATURE, REPOSITORY, publication_rows
    from downstream_release import descriptor
    contract = contract if contract is not None else load_contract()
    base = validate_receipt(receipt, contract)
    require(manifest.get('schemaVersion') == 1 and manifest.get('status') == 'validated-complete-matrix'
            and manifest.get('repository') == REPOSITORY and manifest.get('contractVersion') == contract['schemaVersion']
            and manifest.get('identity') == receipt['identity'] and manifest.get('tag') == receipt['tag']
            and signer == manifest.get('signingFingerprint') == receipt.get('signingFingerprint'),
            'Signed RPM manifest differs from receipt identity, contract, or signer')
    require(all(all(row['record']['identity'].get(key) == value for key, value in manifest['identity'].items())
                for row in manifest['records']), 'Signed RPM target identity differs from the publication source')
    require(receipt.get('repositories') == manifest.get('repositories')
            and receipt.get('publications') == publication_rows(manifest, receipt['manifestSha256'], base),
            'RPM receipt targets or repositories differ from the signed manifest')
    assets = manifest['assets'] + [descriptor(directory / name) for name in (MANIFEST, SIGNATURE)]
    names = [item['name'] for item in assets]
    require(len(names) == len(set(names)), 'Duplicate signed RPM publication asset')
    expected = [dict(item, url=base + item['name']) for item in assets]
    supplied = receipt.get('assets')
    require(isinstance(supplied, list) and len(supplied) == len(expected)
            and sorted(supplied, key=lambda item: item['name']) == sorted(expected, key=lambda item: item['name']),
            'RPM receipt assets differ from authenticated publication bytes')


def hosted_repository_url(base, variant, version, revision):
    require(base.rstrip('/') == 'https://dotnetdev.kr/cbodotnet/packages/rpm' and variant in BASES
            and re.fullmatch(r'[1-9][0-9]*\.[0-9]+\.[0-9]+', version)
            and type(revision) is int and revision > 0, 'Published DNF endpoint must match canonical project/variant/SDK/revision')
    location = base.rstrip('/') + '/' + variant
    return location if version == '10.0.403' and revision == 1 else location + '/sdk-' + version + '-r' + str(revision)


def postverify(args):
    from downstream_publish import MANIFEST, SIGNATURE
    receipt = load(args.receipt)
    base_url = validate_receipt(receipt)
    require(platform.machine() in expected_native(args.arch), 'Published RPM proof requires a matching native worker')
    workspace = args.workspace.resolve()
    require(not workspace.exists(), 'RPM post-verification workspace must be fresh')
    workspace.mkdir(parents=True)
    for name in (MANIFEST, SIGNATURE):
        urllib.request.urlretrieve(base_url + name, workspace / name)
    require(SHARED.digest(workspace / MANIFEST) == receipt['manifestSha256'], 'RPM publication manifest changed')
    keyring = workspace / 'trusted.gpg'
    run(['gpg', '--batch', '--yes', '--dearmor', '--output', keyring, ROOT / 'releases/downstream-signing-key.asc'])
    manifest = load(workspace / MANIFEST)
    workflow = manifest['records'][0]['record']['orchestration']['workflow']
    signer = verify_report_signature(workspace / MANIFEST, workspace / SIGNATURE, keyring, load_status(), workflow)
    bind_signed_receipt(receipt, manifest, signer, workspace)
    candidates = {(row['variant'], row['architecture']) for row in load_status()['channels']['rpm']['candidateMatrix']}
    observed = [(row['record']['identity']['variant'], row['record']['architecture']) for row in manifest['records']]
    require(len(set(observed)) == len(observed) and set(observed) == candidates, 'Published RPM matrix differs from current reviewed targets')
    variants = [args.variant] if args.variant else list(BASES)
    inputs = workspace / 'inputs'
    receive_release('sdk-' + receipt['identity']['sdkVersion'], inputs, 'rpm', variants[0], args.arch, receipt['identity']['packageRevision'])
    assets = {item['name']: item for item in manifest['assets']}
    reports = []
    targets = []
    for variant in variants:
        metadata = [item for item in manifest['repositories'] if item['kind'] == 'rpm-repository' and variant in item['variants']]
        require(len(metadata) == 1, 'A single published RPM repository is required per variant')
        name = metadata[0]['asset']
        require(re.fullmatch(r'[A-Za-z0-9._+-]+', name), 'Unsafe RPM repository asset name')
        archive = workspace / name
        urllib.request.urlretrieve(base_url + name, archive)
        require(archive.stat().st_size == assets[name]['size'] and SHARED.digest(archive) == assets[name]['sha256'], 'RPM repository bundle differs from signed publication')
        delivery = workspace / ('rpm-' + variant)
        delivery.mkdir()
        repository = delivery / 'repository'
        repository.mkdir()
        with tarfile_open(archive) as incoming:
            for member in incoming.getmembers():
                path = Path(member.name)
                require(not path.is_absolute() and '..' not in path.parts and (member.isdir() or member.isfile())
                        and not member.mode & 0o7000, 'Unsafe signed RPM repository member')
            incoming.extractall(repository, filter='data')
        run(['gpgv', '--keyring', keyring, repository / 'repodata/repomd.xml.asc', repository / 'repodata/repomd.xml'])
        if args.repository_base:
            (delivery / 'repository-url.txt').write_text(hosted_repository_url(args.repository_base, variant,
                receipt['identity']['sdkVersion'], receipt['identity']['packageRevision']))
        plan = local_intake(inputs, 'rpm', variant, args.arch, receipt['identity']['packageRevision'])
        save(delivery / 'plan.json', plan)
        (delivery / 'expected-fingerprint.txt').write_text(signer + '\n')
        container_lifecycle(workspace, delivery, BASES[variant][args.arch], published=True)
        result = load(delivery / 'installation-result.json')
        result.update(variant=variant, architecture=args.arch, sdkVersion=plan['sdkVersion'], packageRevision=plan['packageRevision'],
                      signingFingerprint=signer, repositorySha256=assets[name]['sha256'],
                      scope='published-https-dnf-installation' if args.repository_base else 'published-dnf-installation')
        output = workspace / ('published-rpm-' + variant + '-' + args.arch + '.json')
        save(output, result)
        reports.append(str(output))
        targets.append(result)
    summary = args.output if args.output is not None else workspace.parent / ('published-' + args.arch + '.json')
    save(summary, dict(schemaVersion=1, status='passed', architecture=args.arch, rpmTargets=targets))
    print(json.dumps(dict(status='passed', architecture=args.arch, reports=reports)))


def tarfile_open(path):
    import tarfile
    return tarfile.open(path, 'r:gz')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('native')
    command.add_argument('--workspace', type=Path, required=True)
    command.add_argument('--inputs', type=Path)
    command.add_argument('--tag', default='sdk-10.0.403')
    command.add_argument('--revision', type=int, default=1)
    command.add_argument('--arch', choices=('x64', 'aarch64'), required=True)
    command.add_argument('--variant', choices=tuple(BASES))
    command = commands.add_parser('postverify')
    command.add_argument('--receipt', type=Path, required=True)
    command.add_argument('--workspace', type=Path, required=True)
    command.add_argument('--arch', choices=('x64', 'aarch64'), required=True)
    command.add_argument('--variant', choices=tuple(BASES))
    command.add_argument('--repository-base')
    command.add_argument('--output', type=Path)
    for name in ('build-in-container', 'prepare-installed', 'lifecycle'):
        command = commands.add_parser(name)
        command.add_argument('--delivery', type=Path, required=True)
        if name == 'prepare-installed': command.add_argument('--published', choices=('yes', 'no'), default='no')
    args = parser.parse_args()
    try:
        {'native': native, 'postverify': postverify, 'build-in-container': build_in_container,
         'prepare-installed': prepare_installed, 'lifecycle': lifecycle}[args.command](args)
    except (ValueError, OSError, RuntimeError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
