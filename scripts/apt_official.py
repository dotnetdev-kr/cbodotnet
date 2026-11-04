#!/usr/bin/env python3
"""Install an official SDK only in disposable APT containers and prove coexistence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tempfile
import urllib.request

MICROSOFT_FINGERPRINT = 'AA86F75E427A19DD33346403EE4D7792F748182B'
UBUNTU_FINGERPRINT = 'F6ECB3762474EDA9D21B7022871920D1991BC93C'
SDK_PACKAGE = 'dotnet-sdk-10.0'
MICROSOFT_KEY_URL = 'https://packages.microsoft.com/keys/microsoft-2025.asc'
MICROSOFT_KEYRING = '/usr/share/keyrings/cbodotnet-official-microsoft-2025.gpg'
MICROSOFT_SOURCE = '/etc/apt/sources.list.d/cbodotnet-official-microsoft.sources'
POLICIES = {
    'ubuntu-24.04': dict(osId='ubuntu', versionId='24.04', provider='ubuntu', root='/usr/lib/dotnet',
        owner='dotnet-host-10.0', keyring='/usr/share/keyrings/ubuntu-archive-keyring.gpg',
        fingerprint=UBUNTU_FINGERPRINT, suite='noble-updates', component='main',
        references=['https://learn.microsoft.com/en-us/dotnet/core/install/linux-ubuntu-install?pivots=os-linux-ubuntu-2404&tabs=dotnet10',
                    'https://packages.ubuntu.com/noble-updates/dotnet-sdk-10.0']),
    'debian-13': dict(osId='debian', versionId='13', provider='microsoft', root='/usr/share/dotnet',
        owner='dotnet-host', keyring=MICROSOFT_KEYRING, fingerprint=MICROSOFT_FINGERPRINT,
        suite='trixie', component='main', repository='https://packages.microsoft.com/debian/13/prod',
        references=['https://learn.microsoft.com/en-us/dotnet/core/install/linux-debian?tabs=dotnet10',
                    'https://learn.microsoft.com/en-us/linux/packages',
                    'https://packages.microsoft.com/config/debian/13/prod.list'])}


def require(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024**2), b''):
            result.update(block)
    return result.hexdigest()


def run(command, *, input=None, text=True, cwd=None):
    environment = dict(os.environ, LC_ALL='C', DEBIAN_FRONTEND='noninteractive')
    result = subprocess.run(list(map(str, command)), input=input, text=text, cwd=cwd, env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=900)
    if result.returncode:
        error = result.stderr if text else result.stderr.decode(errors='replace')
        raise RuntimeError('Official SDK command failed: ' + str(command[0]) + '\n' + error[-5000:])
    return result.stdout


def os_release():
    return dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                if '=' in line and not line.startswith('#'))


def guard(variant, architecture, user):
    require(variant in POLICIES and architecture in {'x64', 'aarch64'}, 'Unsupported official SDK verification target')
    require(os.name == 'posix' and os.geteuid() == 0 and Path('/.dockerenv').is_file(),
            'Official SDK bootstrap and assertions require a disposable root Docker container')
    policy = POLICIES[variant]
    release = os_release()
    require(release.get('ID', '').strip('"') == policy['osId']
            and release.get('VERSION_ID', '').strip('"') == policy['versionId'], 'Wrong official SDK target OS/version')
    require(platform.machine() in ({'x86_64'} if architecture == 'x64' else {'aarch64', 'arm64'})
            and run(['dpkg', '--print-architecture']).strip() == ('amd64' if architecture == 'x64' else 'arm64'),
            'Official SDK comparison requires the exact native architecture')
    require(isinstance(user, str) and re.fullmatch(r'[a-z_][a-z0-9_-]*', user), 'An existing ordinary test user is required')
    import pwd
    account = pwd.getpwnam(user)
    require(account.pw_uid > 0 and Path(account.pw_dir).is_dir(), 'The official SDK test user must be non-root with a home')
    return policy, dict(name=user, uid=account.pw_uid, gid=account.pw_gid, home=account.pw_dir)


def ordinary(path, *, fresh=False):
    path = Path(path).absolute()
    require(not any(item.is_symlink() for item in [path, *path.parents]), 'Official SDK state/config path contains a link')
    require(path.parent.is_dir() and (not path.exists() if fresh else path.is_file()),
            'Use a fresh ordinary state path' if fresh else 'An ordinary official SDK state/config file is required')
    return path


def primary_fingerprints(listing):
    fingerprints, primary = [], False
    for line in listing.splitlines():
        fields = line.split(':')
        if fields[0] == 'pub':
            primary = True
        elif fields[0] == 'sub':
            primary = False
        elif fields[0] == 'fpr' and primary:
            require(len(fields) > 9 and re.fullmatch(r'[A-F0-9]{40,64}', fields[9]), 'Malformed repository primary fingerprint')
            fingerprints.append(fields[9])
            primary = False
    return fingerprints


def microsoft_source(architecture):
    require(architecture in {'x64', 'aarch64'}, 'Unsupported Microsoft APT architecture')
    return ('Types: deb\nURIs: https://packages.microsoft.com/debian/13/prod\nSuites: trixie\nComponents: main\n'
            + 'Architectures: ' + ('amd64' if architecture == 'x64' else 'arm64') + '\nSigned-By: ' + MICROSOFT_KEYRING + '\n')


def write_config(path, data):
    path = Path(path)
    require(not any(item.is_symlink() for item in [path, *path.parents]), 'Official repository configuration contains a link')
    if path.exists():
        require(path.is_file() and path.read_bytes() == data, 'Conflicting official repository configuration')
    else:
        with path.open('xb') as output:
            output.write(data)
        path.chmod(0o644)


def configure_microsoft(architecture):
    with urllib.request.urlopen(MICROSOFT_KEY_URL, timeout=60) as response:
        require(response.geturl() == MICROSOFT_KEY_URL, 'Unexpected Microsoft repository key redirect')
        key = response.read(1024**2 + 1)
    require(0 < len(key) <= 1024**2, 'Microsoft repository key exceeds its bound')
    with tempfile.TemporaryDirectory(prefix='cbodotnet-official-key-') as home:
        command = ['gpg', '--batch', '--no-options', '--homedir', home]
        listing = run([*command, '--with-colons', '--show-keys'], input=key, text=False).decode()
        require(primary_fingerprints(listing) == [MICROSOFT_FINGERPRINT], 'Microsoft repository key differs from the reviewed primary fingerprint')
        binary = run([*command, '--dearmor'], input=key, text=False)
    write_config(MICROSOFT_KEYRING, binary)
    write_config(MICROSOFT_SOURCE, microsoft_source(architecture).encode())


def verify_microsoft_release(cached, keyring, repository):
    # APT's verifier accepts PMC's current InRelease. Some GnuPG versions
    # reject its armor framing despite reporting a good signature, so use the
    # independently signed binary Release and bind it to APT's exact cleartext.
    downloaded = {}
    for name, bound in (('Release', 8 * 1024**2), ('Release.gpg', 1024**2)):
        url = repository + '/dists/trixie/' + name
        with urllib.request.urlopen(url, timeout=60) as response:
            require(response.geturl() == url, 'Unexpected official Release metadata redirect')
            data = response.read(bound + 1)
        require(0 < len(data) <= bound, 'Official Release metadata exceeds its bound')
        downloaded[name] = data
    header, marker, body = cached.read_bytes().partition(b'\n\n')
    require(header.startswith(b'-----BEGIN PGP SIGNED MESSAGE-----\n') and marker,
            'Malformed cached Microsoft InRelease')
    cleartext, marker, _ = body.partition(b'-----BEGIN PGP SIGNATURE-----')
    require(marker and cleartext.endswith(b'\n'), 'Cached Microsoft release lacks its signature boundary')
    cleartext = b'\n'.join(line[2:] if line.startswith(b'- ') else line for line in cleartext[:-1].split(b'\n'))
    require(cleartext == downloaded['Release'], 'Signed official Release differs from APT cached metadata')
    with tempfile.TemporaryDirectory(prefix='cbodotnet-official-release-') as temporary:
        root = Path(temporary)
        for name, data in downloaded.items():
            (root / name).write_bytes(data)
        status = run(['gpgv', '--status-fd', '1', '--keyring', keyring, root / 'Release.gpg', root / 'Release'])
    return status, dict(releaseSignatureUrl=repository + '/dists/trixie/Release.gpg',
                        signedReleaseSha256=hashlib.sha256(downloaded['Release']).hexdigest())


def repository_policy(variant, architecture):
    policy = POLICIES[variant]
    if variant == 'debian-13':
        repository = policy['repository']
        profile = Path(MICROSOFT_SOURCE)
        require(profile.read_text() == microsoft_source(architecture), 'Microsoft APT source differs from the scoped policy')
    else:
        repository = ('http://archive.ubuntu.com/ubuntu' if architecture == 'x64'
                      else 'http://ports.ubuntu.com/ubuntu-ports')
        profile = ordinary('/etc/apt/sources.list.d/ubuntu.sources')
        text = profile.read_text()
        require(repository in text and 'Signed-By: ' + policy['keyring'] in text
                and 'noble' in text, 'Ubuntu official SDK must use the pinned image distro sources and keyring')
    keyring = ordinary(policy['keyring'])
    release_name = repository.split('://', 1)[1].replace('/', '_') + '_dists_' + policy['suite'] + '_InRelease'
    release = ordinary(Path('/var/lib/apt/lists') / release_name)
    if variant == 'debian-13':
        signatures, signature_evidence = verify_microsoft_release(release, keyring, repository)
    else:
        signatures = run(['gpgv', '--status-fd', '1', '--keyring', keyring, release])
        signature_evidence = {}
    valid = [line.split() for line in signatures.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
    require(valid and all(row[2] == policy['fingerprint'] or row[-1] == policy['fingerprint'] for row in valid),
            'Official APT release was not signed by the reviewed repository identity')
    return dict(repository=repository, suite=policy['suite'], component=policy['component'],
        keyring=str(keyring), signingFingerprint=policy['fingerprint'], keyringSha256=digest(keyring),
        releaseSha256=digest(release), profileFiles=[dict(path=str(profile), sha256=digest(profile))],
        primaryReferences=policy['references'], **signature_evidence)


def candidate(policy_text, source, architecture):
    match = re.search(r'^\s*Candidate:\s+(\S+)\s*$', policy_text, re.M)
    require(match is not None and match[1] != '(none)', 'Official SDK package has no candidate')
    version, selected, approved = match[1], False, False
    for line in policy_text.splitlines():
        row = re.fullmatch(r'\s*(?:\*\*\*\s+)?(\S+)\s+\d+\s*', line)
        if row:
            selected = row[1] == version
        elif selected and (source['repository'] + ' ') in line and (source['suite'] + '/' + source['component']) in line:
            approved |= (' ' + ('amd64' if architecture == 'x64' else 'arm64') + ' Packages') in line
    require(approved, 'Official SDK candidate does not come from the reviewed repository/suite/architecture')
    return version


def file_metadata(path):
    value = Path(path).lstat()
    return dict(mode=format(stat.S_IMODE(value.st_mode), '04o'), uid=value.st_uid, gid=value.st_gid)


def root_inventory(root):
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), 'Official SDK root is not an ordinary directory')
    result, counts = hashlib.sha256(), dict(entries=0, files=0, links=0, bytes=0)
    for path in [root, *sorted(root.rglob('*'))]:
        row = dict(path=path.relative_to(root).as_posix(), **file_metadata(path))
        if path.is_symlink():
            row.update(kind='link', target=os.readlink(path)); counts['links'] += 1
        elif path.is_file():
            row.update(kind='file', sha256=digest(path), size=path.stat().st_size)
            counts['files'] += 1; counts['bytes'] += row['size']
        else:
            require(path.is_dir(), 'Unexpected object in the official SDK installation')
            row['kind'] = 'directory'
        result.update(encoded(row)); counts['entries'] += 1
    return dict(sha256=result.hexdigest(), **counts)


def package_owner(path):
    lines = run(['dpkg-query', '--search', path]).strip().splitlines()
    require(len(lines) == 1 and ': ' in lines[0] and lines[0].rsplit(': ', 1)[1] == path,
            'Official dotnet path has missing or ambiguous package ownership')
    return lines[0].rsplit(': ', 1)[0]


def official_version(account):
    # No repository global.json or caller-supplied DOTNET_ROOT may select cbodotnet.
    with tempfile.TemporaryDirectory(prefix='cbodotnet-official-cli-') as directory:
        os.chown(directory, account['uid'], account['gid'])
        command = ['runuser', '-u', account['name'], '--', 'env', '-i', 'HOME=' + account['home'],
            'PATH=/usr/bin:/bin:/usr/sbin:/sbin', 'DOTNET_CLI_HOME=' + account['home'], 'LC_ALL=C',
            'DOTNET_CLI_TELEMETRY_OPTOUT=1', 'DOTNET_NOLOGO=1', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1',
            'DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=true', '/usr/bin/dotnet']
        version = run([*command, '--version'], cwd=directory).strip()
        listing = run([*command, '--list-sdks'], cwd=directory).strip().splitlines()
    require(re.fullmatch(r'10\.0\.[0-9]+', version), 'Official SDK bootstrap did not select an installed stable SDK 10.0')
    return version, listing


def validate_dpkg_baseline(output):
    # Minimal image exclusions can omit documentation while dpkg exits zero.
    # Retain that exact baseline, but never admit changed hashes or missing
    # runtime/config files as an acceptable preinstallation state.
    allowed = (r'missing\s+/usr/share/(?:doc/(?:dotnet-|aspnetcore-|netstandard-)[^\s]+'
               r'|man/man[1-9]/dotnet[^\s]*|lintian/overrides/(?:dotnet-|aspnetcore-|netstandard-)[^\s]+)')
    require(all(re.fullmatch(allowed, line) for line in output.splitlines()),
            'Official package baseline contains corruption outside minimal-image documentation exclusions')


def capture(policy, account, architecture):
    command = Path('/usr/bin/dotnet')
    require(command.is_symlink(), 'Official package must own the preinstalled /usr/bin/dotnet symlink')
    root = Path(policy['root'])
    require(command.resolve() == root / 'dotnet' and command.resolve().is_file(), 'Official command resolves outside its reviewed package root')
    owner = package_owner(str(command))
    require(owner.split(':', 1)[0] == policy['owner'] and package_owner(str(command.resolve())) == owner,
            'Official dotnet command or binary has another package owner')
    version, listing = official_version(account)
    require(listing and all(re.fullmatch(r'10\.0\.[0-9]+ \[' + re.escape(str(root)) + r'/sdk\]', line) for line in listing)
            and version + ' [' + str(root) + '/sdk]' in listing, 'Official SDK discovery escaped its package-owned root')
    packages = []
    for line in run(['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n']).splitlines():
        fields = line.split('\t')
        if fields[0].startswith(('dotnet-', 'aspnetcore-', 'netstandard-')) and fields[-1] == 'installed':
            require(len(fields) == 4, 'Malformed installed official package record')
            packages.append(dict(zip(('name', 'version', 'architecture', 'status'), fields)))
    packages.sort(key=lambda row: (row['name'], row['architecture']))
    require(any(row['name'] == SDK_PACKAGE for row in packages)
            and all(row['architecture'] in {'all', 'amd64' if architecture == 'x64' else 'arm64'} for row in packages),
            'Official package inventory lacks the native SDK')
    verification = run(['dpkg', '--verify', *[row['name'] for row in packages]])
    require(len(verification.encode()) <= 128 * 1024, 'Official package verification baseline exceeds its bound')
    validate_dpkg_baseline(verification)
    return dict(officialRoot=str(root), sdkVersion=version, sdkListing=listing,
        command=dict(path=str(command), owner=owner, linkTarget=os.readlink(command), resolvedPath=str(command.resolve()),
                     sha256=digest(command.resolve()), **file_metadata(command)),
        packages=packages, packageInventorySha256=hashlib.sha256(encoded(packages)).hexdigest(),
        rootInventory=root_inventory(root), dpkgVerificationOutput=verification)


def public_summary(state):
    keys = ('variant', 'architecture', 'officialRoot', 'sdkVersion', 'sdkListing', 'command', 'packages',
            'packageInventorySha256', 'rootInventory', 'provider', 'source')
    return {key: state[key] for key in keys}


def bootstrap(variant, architecture, user, state_path):
    policy, account = guard(variant, architecture, user)
    state_path = ordinary(state_path, fresh=True)
    require(not os.path.lexists('/usr/bin/dotnet') and not Path(policy['root']).exists(),
            'Official comparison must start without an unpackaged or preexisting dotnet installation')
    print('apt-official: provision package-managed SDK for ' + variant + '/' + architecture, file=sys.stderr, flush=True)
    run(['apt-get', 'update', '-qq'])
    run(['apt-get', 'install', '-y', '--no-install-recommends', 'ca-certificates', 'curl', 'gnupg'])
    if variant == 'debian-13':
        configure_microsoft(architecture)
        run(['apt-get', 'update', '-qq'])
    source = repository_policy(variant, architecture)
    package_policy = run(['apt-cache', 'policy', SDK_PACKAGE])
    version = candidate(package_policy, source, architecture)
    run(['apt-get', 'install', '-y', '--no-install-recommends', SDK_PACKAGE + '=' + version])
    state = dict(schemaVersion=1, scope='official-deb-coexistence', variant=variant, architecture=architecture,
                 testUser=account, provider=policy['provider'], source=dict(source, candidateVersion=version,
                     aptPolicySha256=hashlib.sha256(package_policy.encode()).hexdigest()), **capture(policy, account, architecture))
    with state_path.open('xb') as output:
        output.write(encoded(state))
    state_path.chmod(0o644)
    return state


def assert_unchanged(state_path):
    state_path = ordinary(state_path)
    require(state_path.stat().st_size <= 1024**2, 'Official coexistence state exceeds its bound')
    state = json.loads(state_path.read_bytes())
    require(state.get('schemaVersion') == 1 and state.get('scope') == 'official-deb-coexistence', 'Invalid official coexistence baseline')
    policy, account = guard(state['variant'], state['architecture'], state['testUser']['name'])
    require(account == state['testUser'] and state['officialRoot'] == policy['root'] and state['provider'] == policy['provider'],
            'Official coexistence target or ordinary user changed')
    current = capture(policy, account, state['architecture'])
    require(all(current[key] == state[key] for key in current), 'Official package owner, command, version, payload or dpkg verification changed')
    expected_profiles = [MICROSOFT_SOURCE] if state['variant'] == 'debian-13' else ['/etc/apt/sources.list.d/ubuntu.sources']
    require(state['source']['keyring'] == policy['keyring'] and state['source']['signingFingerprint'] == policy['fingerprint']
            and digest(ordinary(policy['keyring'])) == state['source']['keyringSha256']
            and [row['path'] for row in state['source']['profileFiles']] == expected_profiles
            and all(digest(ordinary(row['path'])) == row['sha256'] for row in state['source']['profileFiles']),
            'Official package repository trust or source configuration changed')
    return dict(schemaVersion=1, status='passed', checks=['official-package-ownership', 'official-command-link',
        'official-sdk-version', 'official-sdk-payload', 'official-package-inventory', 'official-dpkg-baseline'], **public_summary(state))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    install = commands.add_parser('bootstrap')
    install.add_argument('--variant', choices=tuple(POLICIES), required=True)
    install.add_argument('--arch', choices=('x64', 'aarch64'), required=True)
    install.add_argument('--user', required=True)
    install.add_argument('--state', type=Path, required=True)
    verify = commands.add_parser('assert-unchanged')
    verify.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = bootstrap(args.variant, args.arch, args.user, args.state) if args.command == 'bootstrap' else assert_unchanged(args.state)
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Official SDK coexistence rejected: ' + str(error) + '\n')
    print(json.dumps(public_summary(result) if args.command == 'bootstrap' else result, sort_keys=True))


if __name__ == '__main__':
    main()
