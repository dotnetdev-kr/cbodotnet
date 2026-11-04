"""Prove coexistence with the SDK installed from pinned-image stock RPM feeds."""
import configparser
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import tempfile
from urllib.parse import urlsplit

from apt_official import (digest, encoded, file_metadata, ordinary, primary_fingerprints,
                          root_inventory, run)

POLICIES = {
    'fedora-45': dict(osId='fedora', versionId='45', repositories=['fedora', 'updates'],
        fingerprint='4F50A6114CD5C6976A7F1179655A4B02F577861E',
        key='/usr/share/pki/rpm-gpg/RPM-GPG-KEY-fedora-45-primary',
        roots=['/usr/lib64/dotnet', '/usr/share/dotnet'],
        references=['https://packages.fedoraproject.org/pkgs/dotnet10.0/dotnet-sdk-10.0/fedora-45.html',
                    'https://learn.microsoft.com/en-us/dotnet/core/install/linux-fedora?tabs=dotnet10']),
    'rocky-9.8': dict(osId='rocky', versionId='9.8', repositories=['baseos', 'appstream'],
        fingerprint='21CB256AE16FC54C6E652949702D426D350D275D',
        key='/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9',
        roots=['/usr/lib64/dotnet', '/usr/share/dotnet'],
        references=['https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/Packages/d/',
                    'https://dl.rockylinux.org/pub/rocky/9/AppStream/aarch64/os/Packages/d/',
                    'https://docs.redhat.com/en/documentation/net/10.0/html-single/getting_started_with_.net_10.0_on_rhel_9/index'])}
SDK_PACKAGE = 'dotnet-sdk-10.0'
REPOSITORY_DIRECTORIES = ('/etc/yum.repos.d', '/usr/share/dnf5/repos.d')


def require(value, message):
    if not value:
        raise ValueError(message)


def guard(variant, architecture, user):
    require(variant in POLICIES and architecture in {'x64', 'aarch64'}, 'Unsupported official RPM target')
    require(os.name == 'posix' and os.geteuid() == 0 and Path('/.dockerenv').is_file(),
            'Official RPM assertions require a disposable root Docker container')
    policy = POLICIES[variant]
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release.get('ID', '').strip('"') == policy['osId'] and release.get('VERSION_ID', '').strip('"') == policy['versionId'],
            'Official RPM comparison OS differs')
    require(platform.machine() in ({'x86_64'} if architecture == 'x64' else {'aarch64', 'arm64'}),
            'Official RPM comparison requires the native architecture')
    require(isinstance(user, str) and re.fullmatch(r'[a-z_][a-z0-9_-]*', user), 'An existing ordinary RPM test user is required')
    import pwd
    account = pwd.getpwnam(user)
    require(account.pw_uid > 0 and Path(account.pw_dir).is_dir(), 'RPM comparison requires an ordinary user with a home')
    return policy, dict(name=user, uid=account.pw_uid, gid=account.pw_gid, home=account.pw_dir)


def repository_options(policy):
    modern = Path('/usr/bin/dnf5').exists()
    return ['--disable-repo=*' if modern else '--disablerepo=*',
            *[('--enable-repo=' if modern else '--enablerepo=') + name for name in policy['repositories']]]


def repository_policy(variant, architecture):
    policy = POLICIES[variant]
    selected = {}
    files = sorted({path for directory in REPOSITORY_DIRECTORIES for path in Path(directory).glob('*.repo')})
    for path in files:
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(path.read_text())
        for name in policy['repositories']:
            if not parser.has_section(name):
                continue
            require(name not in selected, 'Official repository ID is configured more than once')
            row = parser[name]
            require(row.get('gpgcheck') == '1', 'Official RPM feed must require package signatures')
            locations = [row.get(key) for key in ('metalink', 'mirrorlist', 'baseurl') if row.get(key)]
            allowed = {'mirrors.fedoraproject.org'} if variant == 'fedora-45' else {'mirrors.rockylinux.org', 'dl.rockylinux.org'}
            require(locations and all(urlsplit(value).hostname in allowed and urlsplit(value).scheme in {'http', 'https'} for value in locations),
                    'Official RPM feed does not use its stock distribution origin')
            key = row.get('gpgkey', '').replace('$releasever', policy['versionId'].split('.')[0]).replace('$basearch', 'x86_64' if architecture == 'x64' else 'aarch64')
            require(key.startswith('file:///') and Path(key[7:]).resolve() == Path(policy['key']).resolve(),
                    'Official RPM feed selects another signing key')
            selected[name] = dict(path=str(path), sha256=digest(path), locations=locations,
                                  packageSignaturesRequired=True, repositoryMetadataSignaturesRequired=row.get('repo_gpgcheck', '0') == '1')
    require(set(selected) == set(policy['repositories']), 'The complete stock official RPM feeds are required')
    key = Path(policy['key'])
    require(key.is_file() and primary_fingerprints(run(['gpg', '--batch', '--show-keys', '--with-colons', key])) == [policy['fingerprint']],
            'Official distribution RPM signing key fingerprint differs')
    return dict(repositories=selected, key=str(key), keySha256=digest(key), signingFingerprint=policy['fingerprint'],
                primaryReferences=policy['references'])


def official_version(account):
    with tempfile.TemporaryDirectory(prefix='cbodotnet-official-rpm-') as directory:
        os.chown(directory, account['uid'], account['gid'])
        command = ['runuser', '-u', account['name'], '--', 'env', '-i', 'HOME=' + account['home'],
            'PATH=/usr/bin:/bin:/usr/sbin:/sbin', 'DOTNET_CLI_HOME=' + account['home'], 'LC_ALL=C',
            'DOTNET_CLI_TELEMETRY_OPTOUT=1', 'DOTNET_NOLOGO=1', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1',
            'DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=true', '/usr/bin/dotnet']
        version = run([*command, '--version'], cwd=directory).strip()
        listing = run([*command, '--list-sdks'], cwd=directory).strip().splitlines()
    require(re.fullmatch(r'10\.0\.[0-9]+', version), 'Stock RPM feed did not install stable official SDK10')
    return version, listing


def package_owner(path):
    value = run(['rpm', '-qf', '--queryformat', '%{NAME}', str(path)]).strip()
    require(re.fullmatch(r'dotnet-host(?:-10\.0)?', value), 'Official host path has another or ambiguous RPM owner')
    return value


def capture(policy, account, architecture):
    command = Path('/usr/bin/dotnet')
    require(command.is_symlink(), 'Official RPM must own the original dotnet symlink')
    resolved = command.resolve(strict=True)
    root = resolved.parent
    require(str(root) in policy['roots'] and resolved.name == 'dotnet' and resolved.is_file(), 'Official RPM command resolves outside its stock package root')
    owner = package_owner(command)
    require(package_owner(resolved) == owner, 'Official host/link ownership differs')
    version, listing = official_version(account)
    require(listing and all(re.fullmatch(r'10\.0\.[0-9]+ \[' + re.escape(str(root)) + r'/sdk\]', line) for line in listing)
            and version + ' [' + str(root) + '/sdk]' in listing, 'Official RPM SDK discovery escaped its package root')
    rows = []
    for line in run(['rpm', '-qa', '--queryformat', '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n']).splitlines():
        fields = line.split('\t')
        if fields[0].startswith(('dotnet-', 'aspnetcore-', 'netstandard-')):
            require(len(fields) == 4, 'Malformed official RPM package identity')
            rows.append(dict(zip(('name', 'version', 'release', 'architecture'), fields)))
    rows.sort(key=lambda row: (row['name'], row['architecture']))
    require(any(row['name'] == SDK_PACKAGE for row in rows)
            and all(row['architecture'] in {'noarch', 'x86_64' if architecture == 'x64' else 'aarch64'} for row in rows),
            'Official native SDK RPM inventory differs')
    verification = run(['rpm', '-V', *[row['name'] for row in rows]])
    require(not verification.strip(), 'Official RPM integrity baseline contains changed or missing files')
    return dict(officialRoot=str(root), sdkVersion=version, sdkListing=listing,
        command=dict(path=str(command), owner=owner, linkTarget=os.readlink(command), resolvedPath=str(resolved),
                     sha256=digest(resolved), **file_metadata(command)), packages=rows,
        packageInventorySha256=hashlib.sha256(encoded(rows)).hexdigest(), rootInventory=root_inventory(root), rpmVerificationOutput=verification)


def cached_signature_proofs(packages):
    expected = {row['name']: row for row in packages}
    found = {}
    for path in Path('/var/cache').rglob('*.rpm'):
        fields = run(['rpm', '-qp', '--queryformat', '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}', path]).strip().split('\t')
        if fields[0] not in expected:
            continue
        require(dict(zip(('name', 'version', 'release', 'architecture'), fields)) == expected[fields[0]] and fields[0] not in found,
                'Cached official RPM identity differs or is duplicated')
        verification = run(['rpmkeys', '--checksig', '--verbose', path])
        require(re.search(r'\bsignature\b[^\n]*:\s*OK\s*$', verification, re.I | re.M)
                and not re.search(r'\b(?:NOKEY|NOT\s+OK|NOTFOUND|NOTTRUSTED|BAD|FAILED)\b', verification, re.I),
                'Official cached RPM signature failed')
        found[fields[0]] = dict(name=path.name, size=path.stat().st_size, sha256=digest(path), verification=verification)
    require(set(found) == set(expected), 'Each installed official RPM needs its independently verified cached package')
    return [found[name] for name in sorted(found)]


def public_summary(state):
    return {key: state[key] for key in ('variant', 'architecture', 'officialRoot', 'sdkVersion', 'sdkListing', 'command',
        'packages', 'packageInventorySha256', 'rootInventory', 'provider', 'source', 'packageSignatures')}


def bootstrap(variant, architecture, user, state_path):
    policy, account = guard(variant, architecture, user)
    state_path = ordinary(state_path, fresh=True)
    require(not os.path.lexists('/usr/bin/dotnet'), 'Official RPM comparison must start without dotnet')
    source = repository_policy(variant, architecture)
    run(['rpmkeys', '--import', policy['key']])
    run(['dnf', '-y', *repository_options(policy), '--setopt=gpgcheck=1', '--setopt=keepcache=True',
         '--setopt=install_weak_deps=False', '--setopt=tsflags=', 'install', SDK_PACKAGE])
    current = capture(policy, account, architecture)
    state = dict(schemaVersion=1, scope='official-rpm-coexistence', variant=variant, architecture=architecture,
        testUser=account, provider=policy['osId'] + '-stock-dnf', source=source,
        packageSignatures=cached_signature_proofs(current['packages']), **current)
    with state_path.open('xb') as stream:
        stream.write(encoded(state))
    state_path.chmod(0o644)
    return state


def assert_unchanged(state_path):
    state_path = ordinary(state_path)
    require(state_path.stat().st_size <= 1024**2, 'Official RPM baseline exceeds its bound')
    state = json.loads(state_path.read_bytes())
    require(state.get('schemaVersion') == 1 and state.get('scope') == 'official-rpm-coexistence', 'Invalid official RPM baseline')
    policy, account = guard(state['variant'], state['architecture'], state['testUser']['name'])
    require(account == state['testUser'] and state['source'] == repository_policy(state['variant'], state['architecture']),
            'Official RPM test user or repository trust/configuration changed')
    current = capture(policy, account, state['architecture'])
    require(all(current[key] == state[key] for key in current), 'Official RPM owner, command, version, files or package inventory changed')
    return dict(schemaVersion=1, status='passed', checks=['official-rpm-ownership', 'official-command-link',
        'official-sdk-version', 'official-sdk-payload', 'official-package-inventory', 'official-rpm-integrity'], **public_summary(state))
