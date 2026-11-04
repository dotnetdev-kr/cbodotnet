#!/usr/bin/env python3
"""Validate hosted APT beside real official packages in disposable containers."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import urllib.request

from distribution_contract import load_contract
from downstream_release import encoded, require
from sdk_runtime import series as sdk_series, smoke_script, validate_host_rid, validate_smoke_output

ROOT = Path(__file__).resolve().parents[1]
BRAND = 'Community Build of .NET (built by .NET Dev)'
USER = 'cbot-apt-smoke'
STATE = Path('/var/lib/cbodotnet-apt-validation')
KEYRING = '/usr/share/keyrings/cbodotnet-archive-keyring.gpg'
APT_CACHE = Path('/var/cache/apt/archives')


def run(arguments, *, cwd=None, env=None):
    result = subprocess.run([str(value) for value in arguments], cwd=cwd, env=env, text=True, capture_output=True)
    require(result.returncode == 0, 'Command failed: ' + str(arguments[0]) + '\n' + result.stdout[-6000:] + result.stderr[-6000:])
    return result.stdout


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024**2), b''):
            value.update(block)
    return value.hexdigest()


def repository_url(variant, version, revision, requested=None):
    require(variant in {'ubuntu-24.04', 'debian-13'} and type(revision) is int and revision > 0,
            'Unsupported published APT repository identity')
    sdk_series(version)
    pages = 'https://dotnetdev.kr/cbodotnet/packages/deb/' + variant
    immutable = ('https://github.com/dotnetdev-kr/cbodotnet/releases/download/repository-deb-'
                 + variant + '-sdk-' + version + '-r' + str(revision) + '/')
    chosen = requested or (pages if version == '10.0.403' else immutable)
    require(chosen in ({pages, immutable} if version == '10.0.403' else {immutable}),
            'Published APT repository must match its exact variant/SDK/revision')
    return chosen.rstrip('/')


def deb822_source(repository, architecture, version=None, revision=None, variant=None):
    if version is not None:
        repository_url(variant, version, revision, repository if repository.endswith('/') else repository + '/' if repository.startswith('https://github.com/') else repository)
    else:
        require(repository in {'https://dotnetdev.kr/cbodotnet/packages/deb/ubuntu-24.04',
                               'https://dotnetdev.kr/cbodotnet/packages/deb/debian-13'}, 'Unsupported published APT target')
    require(architecture in {'amd64', 'arm64'}, 'Unsupported published APT target')
    return f'Types: deb\nURIs: {repository}\nSuites: ./\nArchitectures: {architecture}\nSigned-By: {KEYRING}\n'


def verify_primary_fingerprint(output, expected):
    fingerprints, primary = [], False
    for line in output.splitlines():
        parts = line.split(':')
        if parts[0] == 'pub':
            primary = True
        elif parts[0] == 'fpr' and primary:
            require(len(parts) > 9, 'Malformed published APT key fingerprint')
            fingerprints.append(parts[9])
            primary = False
    require(fingerprints == [expected], 'Published APT keyring primary identities differ from reviewed policy')


def verify_packages_index(release, packages):
    require('SHA256:' in release.splitlines(), 'Signed APT Release lacks SHA-256 metadata')
    rows, active = [], False
    for line in release.splitlines():
        if line == 'SHA256:':
            active = True
            continue
        if active and line and not line.startswith(' '):
            active = False
        if active:
            fields = line.split()
            if len(fields) == 3 and fields[2] == 'Packages':
                rows.append(fields)
    require(len(rows) == 1 and rows[0][0] == hashlib.sha256(packages).hexdigest() and int(rows[0][1]) == len(packages),
            'APT Packages differs from signed Release size/SHA-256')


def package_descriptors(packages, sdk, revision, architecture, flat=False):
    name = 'cbodotnet-sdk-' + '.'.join(sdk.split('.')[:2])
    expected = {(name, sdk + '-' + str(revision), architecture), ('cbodotnet-host', '1.0.0-1', 'all')}
    if sdk_series(sdk) in {'3.0', '3.1', '5.0'}:
        from legacy_compat import load_policy
        provider = load_policy()
        expected.add((provider['packageName'], provider['version'] + '-1', architecture))
    selected = {}
    for block in packages.decode('utf-8').split('\n\n'):
        fields = {}
        for line in block.splitlines():
            if line and not line.startswith((' ', '\t')) and ': ' in line:
                key, value = line.split(': ', 1)
                require(key not in fields, 'Duplicate APT package metadata field')
                fields[key] = value
        identity = tuple(fields.get(key) for key in ('Package', 'Version', 'Architecture'))
        if identity not in expected:
            continue
        filename = fields.get('Filename', '')
        path = PurePosixPath(filename)
        canonical = '_'.join(identity) + '.deb'
        location_allowed = filename in {canonical, './' + canonical} if flat else str(path) == filename and path.parts and path.parts[0] == 'pool'
        require(identity not in selected and location_allowed and not path.is_absolute()
                and '..' not in path.parts
                and not any(c in filename for c in '\\:\0\r\n')
                and re.fullmatch(r'[a-f0-9]{64}', fields.get('SHA256', '')) and int(fields.get('Size', '0')) > 0,
                'Incomplete or unsafe authenticated APT package descriptor')
        selected[identity] = dict(package=identity[0], version=identity[1], architecture=identity[2],
            filename=filename, size=int(fields['Size']), sha256=fields['SHA256'])
    require(set(selected) == expected, 'Authenticated APT index lacks the exact SDK revision or shared host')
    return list(selected.values())


def verify_cache_file(path, descriptor):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size == descriptor['size']
            and digest(path) == descriptor['sha256'], 'Retained Debian package differs from authenticated repository bytes')


def reinstall_cached_packages(state):
    # --no-download also disables APT's local-file acquisition. Restore the
    # authenticated archive cache instead, then select exact indexed versions.
    for descriptor in state['authenticatedPackages']:
        retained = STATE / 'cache' / descriptor['cacheFile']
        verify_cache_file(retained, descriptor)
        archive = APT_CACHE / descriptor['cacheFile']
        require(not archive.is_symlink(), 'Unexpected linked APT package cache entry')
        shutil.copyfile(retained, archive)
        verify_cache_file(archive, descriptor)
    run(['apt-get', 'install', '-y', '--no-download',
        *[item['package'] + '=' + item['version'] for item in state['authenticatedPackages']]])


def inventory(root):
    rows, files, links, size = [], 0, 0, 0
    for path in sorted(Path(root).rglob('*')):
        mode = stat.S_IMODE(path.lstat().st_mode)
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            rows.append([name, 'link', mode, os.readlink(path)]); links += 1
        elif path.is_file():
            rows.append([name, 'file', mode, digest(path)]); files += 1; size += path.stat().st_size
        else:
            require(path.is_dir(), 'Unexpected SDK filesystem object')
            rows.append([name, 'directory', mode])
    return dict(sha256=hashlib.sha256(encoded(rows)).hexdigest(), entries=len(rows), files=files, links=links, bytes=size)


def user_run(arguments, *, cwd=None, sdk_root=None):
    environment = dict(os.environ, HOME='/home/' + USER, DOTNET_CLI_HOME='/home/' + USER,
        NUGET_PACKAGES='/home/' + USER + '/.nuget/packages', DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1',
        DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1', DOTNET_CLI_UI_LANGUAGE='en', LC_ALL='C')
    if sdk_root:
        environment.update(DOTNET_ROOT=sdk_root, DOTNET_ROOT_X64=sdk_root, DOTNET_ROOT_ARM64=sdk_root)
    return run(['runuser', '-u', USER, '--', *arguments], cwd=cwd or Path('/home/' + USER), env=environment)


def assert_community(args, state):
    root = Path(state['sdkRoot'])
    for command in ('cbodotnet-' + state['series'], 'cbodotnet'):
        result = subprocess.run(['runuser', '-u', USER, '--', 'env', 'HOME=/home/' + USER,
            'DOTNET_CLI_TELEMETRY_OPTOUT=1', 'DOTNET_NOLOGO=1', command, '--version'], text=True, capture_output=True)
        require(result.returncode == 0 and result.stdout == args.sdk + '\n' and result.stderr == BRAND + '\n', 'Community version/branding stream changed')
        info = json.loads(user_run([command, '--cbodotnet-info']))
        require(info['sdkVersion'] == args.sdk and info['packageRevision'] == args.revision and info['sdkRoot'] == str(root)
                and info['targetRid'] == ('linux-x64' if args.arch == 'x64' else 'linux-arm64')
                and info['sourceManifestSha256'] == state['sourceManifestSha256'] and info['qualifiedPayloadModified'] is False,
                'Installed Community SDK provenance differs from reviewed identity')
        require(user_run([command, '--list-sdks']).splitlines() == [args.sdk + ' [' + str(root / 'sdk') + ']'], 'Community command fell back to another SDK root')
        details = user_run([command, '--info'])
        require(details.startswith(BRAND + '\n') and str(root) in details, 'Community host/root/RID differs')
        validate_host_rid(details, args.sdk, args.arch, args.variant)
    require(run(['dpkg-query', '-S', '/usr/bin/cbodotnet']).split(': ', 1)[0] == 'cbodotnet-host', 'Shared selector has another package owner')
    require(run(['dpkg-query', '-S', '/usr/bin/cbodotnet-' + state['series']]).split(': ', 1)[0] == state['package'], 'Versioned selector has another package owner')
    for package, version in ((state['package'], args.sdk + '-' + str(args.revision)), ('cbodotnet-host', '1.0.0-1')):
        require(run(['dpkg-query', '-W', '-f=${Version}\n', package]).strip() == version,
                'Installed package version differs from the authenticated repository selection')
    for notice in ('LICENSE.txt', 'ThirdPartyNotices.txt'):
        require((root / notice).read_bytes() == (Path('/usr/share/doc') / state['package'] / notice).read_bytes(), 'Original license/notice copy changed')
    verification = run(['dpkg', '-V', *[item['package'] for item in state['authenticatedPackages']]])
    require(not verification, 'Installed Community SDK package integrity failed:\n' + verification)
    return info


def download(url, path, maximum=16 * 1024**2):
    with urllib.request.urlopen(url, timeout=60) as incoming, Path(path).open('xb') as output:
        value = incoming.read(maximum + 1)
        require(len(value) <= maximum, 'Published repository metadata exceeds its bound')
        output.write(value)


def install(args):
    from apt_official import bootstrap, public_summary, assert_unchanged
    require(not STATE.exists(), 'Hosted APT validation state must be fresh')
    STATE.mkdir(mode=0o755)
    series = '.'.join(args.sdk.split('.')[:2])
    package = 'cbodotnet-sdk-' + series
    architecture = 'amd64' if args.arch == 'x64' else 'arm64'
    repository = repository_url(args.variant, args.sdk, args.revision, getattr(args, 'repository', None))
    run(['useradd', '--create-home', '--user-group', '--uid', '10001', USER])
    Path('/etc/dpkg/dpkg.cfg.d/zz-cbodotnet-validation-docs').write_text(
        'path-include=/usr/share/doc/cbodotnet-*\npath-include=/usr/share/doc/dotnet-*\n'
        'path-include=/usr/share/doc/aspnetcore-*\npath-include=/usr/share/doc/netstandard-*\n')
    official_state = STATE / 'official.json'
    official = public_summary(bootstrap(args.variant, args.arch, USER, official_state))
    download('https://dotnetdev.kr/cbodotnet/cbodotnet-archive-keyring.gpg', KEYRING, 1024**2)
    verify_primary_fingerprint(run(['gpg', '--batch', '--show-keys', '--with-colons', KEYRING]), args.fingerprint)
    old = Path('/etc/apt/sources.list.d/cbodotnet.list')
    require(not old.is_symlink(), 'Unexpected linked legacy Community source configuration')
    old.unlink(missing_ok=True)
    source_file = Path('/etc/apt/sources.list.d/cbodotnet.sources')
    require(not source_file.is_symlink(), 'Unexpected linked Community source configuration')
    source_file.write_text(deb822_source(repository, architecture, args.sdk, args.revision, args.variant))
    download(repository + '/InRelease', STATE / 'InRelease')
    release = run(['gpgv', '--keyring', KEYRING, '--output', '-', STATE / 'InRelease'])
    download(repository + '/Packages', STATE / 'Packages')
    packages_bytes = (STATE / 'Packages').read_bytes()
    verify_packages_index(release, packages_bytes)
    descriptors = package_descriptors(packages_bytes, args.sdk, args.revision, architecture, flat=repository.startswith('https://github.com/'))
    run(['apt-get', 'update'])
    names = [item['package'] + '=' + item['version'] for item in descriptors]
    run(['apt-get', 'install', '-y', '--download-only', *names])
    cache = STATE / 'cache'; cache.mkdir()
    for descriptor in descriptors:
        filename = descriptor['package'] + '_' + descriptor['version'] + '_' + descriptor['architecture'] + '.deb'
        source = APT_CACHE / filename
        verify_cache_file(source, descriptor)
        shutil.copyfile(source, cache / filename)
        descriptor.update(cacheFile=filename, url=repository + '/' + descriptor['filename'])
    run(['apt-get', 'install', '-y', *names])
    state = dict(series=series, sdkRoot='/opt/cbodotnet/' + series, package=package, officialBaseline=official,
        sourceManifestSha256=load_contract()['releases'][args.sdk]['manifestSha256'], repository=repository,
        deb822=source_file.read_text(), authenticatedPackages=descriptors,
        repositoryMetadata=dict(inReleaseSha256=digest(STATE / 'InRelease'), packagesSha256=digest(STATE / 'Packages')))
    state['compatibilityState'] = None
    if sdk_series(args.sdk) in {'3.0', '3.1', '5.0'}:
        from legacy_compat import provision
        run(['apt-get', 'install', '-y', '--no-install-recommends', 'rpm', 'rpm2cpio', 'binutils', 'gnupg'])
        state['compatibilityState'] = provision(dict(sdkVersion=args.sdk, variant=args.variant,
            architecture=dict(public=args.arch)), STATE, user=USER)
    state['communityIdentity'] = assert_community(args, state)
    state['communityInventory'] = inventory(Path(state['sdkRoot']))
    state['officialStages'] = [dict(stage='after-community-install', result=assert_unchanged(official_state))]
    state['compatibilityStages'] = []
    if state['compatibilityState']:
        from legacy_compat import assert_unchanged as assert_provider
        state['compatibilityStages'].append(dict(stage='after-community-install', result=assert_provider(state['compatibilityState'])))
    work = Path('/home/' + USER + '/project'); work.mkdir()
    run(['chown', '-R', USER + ':' + USER, work])
    (STATE / 'state.json').write_bytes(encoded(state))


def smoke(args):
    from apt_official import assert_unchanged
    require({path.name for path in Path('/sys/class/net').iterdir()} == {'lo'}, 'Offline APT proof requires Docker --network none')
    state = json.loads((STATE / 'state.json').read_bytes())
    official_state = STATE / 'official.json'
    root = state['sdkRoot']; work = Path('/home/' + USER + '/project')
    assert_community(args, state)
    runtime_env = {}
    compatibility_proofs = state.get('compatibilityStages', [])
    if state.get('compatibilityState'):
        from legacy_compat import runtime_environment, assert_unchanged as assert_provider
        runtime_env = runtime_environment(dict(sdkVersion=args.sdk, variant=args.variant, architecture=dict(public=args.arch)), state['compatibilityState'])

    def official_check(stage):
        state['officialStages'].append(dict(stage=stage, result=assert_unchanged(official_state)))
        if runtime_env:
            compatibility_proofs.append(dict(stage=stage, result=assert_provider(state['compatibilityState'])))

    functional = validate_smoke_output(user_run(['sh', '-ec', smoke_script(args.sdk, root, USER,
        cli='cbodotnet', workdir=str(work), runtime_env=runtime_env)], cwd=work))
    require(inventory(Path(root)) == state['communityInventory'], 'Offline execution changed the installed Community payload')
    assert_community(args, state)
    official_check('after-offline-sdk-execution')
    run(['apt-get', 'remove', '-y', state['package']])
    require(not Path(root).exists() and Path('/usr/bin/cbodotnet').is_file() and not Path('/usr/bin/cbodotnet-' + state['series']).exists(), 'SDK removal damaged shared selector ownership or left payload')
    missing = subprocess.run(['runuser', '-u', USER, '--', 'cbodotnet', '--version'], text=True, capture_output=True)
    require(missing.returncode == 127 and not missing.stdout, 'Removed Community SDK fell back to official dotnet')
    official_check('after-community-sdk-removal')
    reinstall_cached_packages(state)
    assert_community(args, state)
    require(inventory(Path(root)) == state['communityInventory'], 'Cached exact-version reinstall changed the Community payload')
    official_check('after-authenticated-cached-reinstall')
    run(['apt-get', 'purge', '-y', state['package'], 'cbodotnet-host'])
    require(not Path(root).exists() and not Path('/usr/bin/cbodotnet').exists() and not Path('/usr/bin/cbodotnet-' + state['series']).exists(), 'Community purge left SDK or command files')
    official_check('after-community-purge')
    result = dict(schemaVersion=1, status='passed', scope='published-https-apt-installation', variant=args.variant,
        sdkVersion=args.sdk, packageRevision=args.revision, architecture=args.arch, signingFingerprint=args.fingerprint,
        sourceManifestSha256=state['sourceManifestSha256'], repository=state['repository'], sourceFormat='deb822-flat',
        sourceConfiguration=state['deb822'], networkForBuild='none', communityIdentity=state['communityIdentity'],
        communityInventory=state['communityInventory'], authenticatedRetainedPackages=state['authenticatedPackages'],
        repositoryMetadata=state['repositoryMetadata'], officialBaseline=state['officialBaseline'], officialStages=state['officialStages'],
        functionalChecks=functional, compatibilityProvider=compatibility_proofs,
        checks=['https-signed-apt-install','pinned-key','deb822-scoped-source','command-aliases','cli-branding',
            'version-stdout-compatible','sdk-root-rid','non-root-offline-build-run','package-integrity','original-notices',
            'official-package-coexistence','official-root-package-inventory-unchanged','removal','shared-host-ownership',
            'authenticated-cached-reinstall','purge'])
    args.report.write_bytes(encoded(result))
    print(json.dumps(dict(status='passed', variant=args.variant, architecture=args.arch, officialVersion=state['officialBaseline']['sdkVersion'])))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('install','smoke'))
    parser.add_argument('--variant', required=True); parser.add_argument('--sdk', required=True)
    parser.add_argument('--revision', type=int, required=True); parser.add_argument('--fingerprint', required=True)
    parser.add_argument('--arch', choices=('x64','aarch64'), required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--repository')
    args = parser.parse_args()
    require(os.geteuid() == 0 and Path('/.dockerenv').is_file(), 'A disposable root Docker container is required')
    contract = load_contract()
    require(args.sdk in contract['releases'] and args.revision > 0 and args.variant in contract['channels']['deb']['variants'], 'Unsupported published APT identity')
    os_release = dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    expected = contract['operatingSystems'][args.variant]
    require(os_release['ID'].strip('"') == expected['id'] and os_release['VERSION_ID'].strip('"') == expected['versionId'], 'Published APT verifier executed another OS/version')
    require(platform.machine() in ({'x86_64'} if args.arch == 'x64' else {'aarch64','arm64'}), 'Published APT verifier requires matching native execution')
    require(run(['dpkg', '--print-architecture']).strip() == ('amd64' if args.arch == 'x64' else 'arm64'),
            'Published APT verifier requires the matching native package architecture')
    require(re.fullmatch(r'[A-F0-9]{40,64}',args.fingerprint), 'Exact project signing fingerprint required')
    {'install':install,'smoke':smoke}[args.phase](args)


if __name__ == '__main__':
    main()
