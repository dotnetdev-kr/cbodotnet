#!/usr/bin/env python3
"""Build an isolated, separately owned provider from pinned signed Rocky RPMs."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'releases/legacy-compatibility-provider.json'
FINGERPRINT = '21CB256AE16FC54C6E652949702D426D350D275D'
PROVIDER_ROOT = '/usr/lib/cbodotnet/compat/rocky9'
PACKAGE_NAME = 'cbodotnet-compat-rocky9'
VERSION = '2026.11.4'
EPOCH = 1700000000


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n', encoding='utf-8', newline='\n')
    Path(path).chmod(0o644)


def descriptor(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'An ordinary provider artifact is required')
    return {'path': path.name, 'size': path.stat().st_size, 'sha256': digest(path)}


def load_policy():
    policy = json.loads(POLICY.read_bytes())
    require(policy.get('schemaVersion') == 1 and policy.get('packageName') == PACKAGE_NAME
            and policy.get('version') == VERSION and policy.get('root') == PROVIDER_ROOT
            and policy.get('signingFingerprint') == FINGERPRINT,
            'Unreviewed compatibility provider identity')
    require(set(policy['architectures']) == {'x64', 'aarch64'}, 'Both native provider architectures are required')
    for item in [policy['key'], *policy['sources'],
                 *[item for arch in policy['architectures'].values() for item in arch['packages']]]:
        require(re.fullmatch(r'[A-Za-z0-9._+-]+', item['name'])
                and type(item['size']) is int and 0 < item['size'] < 100_000_000
                and re.fullmatch(r'[a-f0-9]{64}', item['sha256'])
                and item['url'].startswith('https://dl.rockylinux.org/pub/rocky/'),
                'Unsafe compatibility source descriptor')
    config = policy['opensslConfiguration']
    require(hashlib.sha256(config['content'].encode()).hexdigest() == config['sha256']
            and config['minimumProtocol'] == 'TLSv1.2' and config['securityLevel'] == 2
            and '.include' not in config['content'], 'Unreviewed scoped OpenSSL policy')
    return policy


def required(plan):
    return '.'.join(plan.get('sdkVersion', '').split('.')[:2]) in {'5.0', '3.1', '3.0'}


def package_requirement(channel, variant=None):
    if channel == 'deb':
        return PACKAGE_NAME + ' (= ' + VERSION + '-1)'
    if channel == 'rpm':
        require(variant in {'fedora-45', 'rocky-9.8'}, 'Unknown provider RPM dependency variant')
        return PACKAGE_NAME + ' = ' + VERSION + '-1.cbot.' + variant.replace('-', '')
    require(channel == 'aur', 'Unknown provider dependency package format')
    return PACKAGE_NAME + '=' + VERSION + '-1'


def environment(plan, root=PROVIDER_ROOT):
    if not required(plan):
        return {}
    require(isinstance(root, str) and root.startswith('/') and root != '/'
            and str(PurePosixPath(root)) == root and '..' not in PurePosixPath(root).parts,
            'An absolute isolated provider root is required')
    policy = load_policy()
    variant = plan.get('variant')
    require(variant in policy['environment']['systemCaBundles'], 'Unreviewed provider operating system')
    result = {'LD_LIBRARY_PATH': root + '/lib', 'OPENSSL_CONF': root + '/openssl.cnf',
              'CLR_OPENSSL_VERSION_OVERRIDE': '1.1',
              'SSL_CERT_FILE': policy['environment']['systemCaBundles'][variant]}
    if plan['sdkVersion'].startswith('3.'):
        result['CLR_ICU_VERSION_OVERRIDE'] = '67'
    return result


def cpu_preflight(architecture, cpuinfo=None):
    """The repackaged x64 RHEL9 libraries require more than the SDK's ISA floor."""
    require(architecture in {'x64', 'aarch64'}, 'Unknown provider CPU architecture')
    if architecture == 'aarch64':
        return {'architecture': architecture, 'baseline': 'armv8-a', 'status': 'passed'}
    text = Path('/proc/cpuinfo').read_text() if cpuinfo is None else cpuinfo
    rows = [set(line.split(':', 1)[1].split()) for line in text.splitlines()
            if re.match(r'^flags\s*:', line)]
    needed = {'cx16', 'lahf_lm', 'popcnt', 'pni', 'ssse3', 'sse4_1', 'sse4_2'}
    require(rows, 'Cannot establish the compatibility provider x86-64-v2 CPU floor')
    for flags in rows:
        if 'sse3' in flags:
            flags.add('pni')
        require(needed <= flags, 'Compatibility provider requires x86-64-v2 CPU features on every exposed processor')
    return {'architecture': architecture, 'baseline': 'x86-64-v2', 'status': 'passed', 'cpuFlagRowsChecked': len(rows)}


def cpu_launcher_preflight():
    return '''# Rocky9 x64 compatibility binaries were compiled for x86-64-v2.
_cbodotnet_cpu_seen=0
if [ -r /proc/cpuinfo ]; then
  while IFS= read -r _cbodotnet_cpu_line; do
    case "$_cbodotnet_cpu_line" in flags*:*)
      _cbodotnet_cpu_flags=
      for _cbodotnet_cpu_flag in ${_cbodotnet_cpu_line#*:}; do
        _cbodotnet_cpu_flags="$_cbodotnet_cpu_flags $_cbodotnet_cpu_flag"
      done
      _cbodotnet_cpu_flags="$_cbodotnet_cpu_flags "
      for _cbodotnet_cpu_required in cx16 lahf_lm popcnt ssse3 sse4_1 sse4_2; do
        case "$_cbodotnet_cpu_flags" in *" $_cbodotnet_cpu_required "*) ;;
          *) echo "cbodotnet: legacy compatibility provider requires an x86-64-v2 CPU" >&2; exit 70 ;;
        esac
      done
      case "$_cbodotnet_cpu_flags" in *" pni "*|*" sse3 "*) ;;
        *) echo "cbodotnet: legacy compatibility provider requires an x86-64-v2 CPU" >&2; exit 70 ;;
      esac
      _cbodotnet_cpu_seen=1 ;;
    esac
  done < /proc/cpuinfo
fi
[ "$_cbodotnet_cpu_seen" = 1 ] || { echo "cbodotnet: cannot establish x86-64-v2 compatibility CPU features" >&2; exit 70; }
unset _cbodotnet_cpu_seen _cbodotnet_cpu_line _cbodotnet_cpu_flags _cbodotnet_cpu_flag _cbodotnet_cpu_required
'''


def launcher_environment(plan):
    """Return a scoped POSIX fragment shared by package and relocatable wrappers."""
    scoped = ('LD_LIBRARY_PATH', 'OPENSSL_CONF', 'CLR_OPENSSL_VERSION_OVERRIDE', 'CLR_ICU_VERSION_OVERRIDE', 'SSL_CERT_FILE')
    lines = ['# Restore the caller environment before selecting another Community Build SDK.',
             'if [ "${CBODOTNET_COMPAT_SCOPE-}" = rocky9 ]; then']
    for name in scoped:
        saved = 'CBODOTNET_COMPAT_SAVED_' + name
        lines += ['  if [ "${' + saved + '_SET-}" = 1 ]; then',
                  '    ' + name + '="${' + saved + '_VALUE-}"; export ' + name,
                  '  else unset ' + name + '; fi',
                  '  unset ' + saved + '_SET ' + saved + '_VALUE']
    lines += ['  unset CBODOTNET_COMPAT_SCOPE', 'fi']
    if not required(plan):
        return '\n'.join(lines) + '\n'
    architecture = plan.get('architecture')
    architecture = architecture.get('public') if isinstance(architecture, dict) else architecture
    require(architecture in {'x64', 'aarch64'}, 'An explicit native architecture is required for the legacy launcher')
    if architecture == 'x64':
        lines.append(cpu_launcher_preflight().rstrip('\n'))
    values = environment(plan)
    names = ['lib/libcrypto.so.1.1', 'lib/libssl.so.1.1', 'openssl.cnf', 'provider-manifest.json']
    if plan['sdkVersion'].startswith('3.'):
        names += ['lib/libicuuc.so.67', 'lib/libicui18n.so.67', 'lib/libicudata.so.67']
    lines += ['# Separate compatibility provider; qualified SDK bytes remain unchanged.',
             '_cbodotnet_compat=${CBODOTNET_COMPAT_ROOT:-' + PROVIDER_ROOT + '}',
             'case "$_cbodotnet_compat" in /*) ;; *) echo "cbodotnet: compatibility provider root must be absolute" >&2; exit 70 ;; esac']
    for name in names:
        lines += ['[ -r "$_cbodotnet_compat/' + name + '" ] || { echo "cbodotnet: install the separately distributed '
                  + PACKAGE_NAME + ' compatibility provider" >&2; exit 70; }']
    for name in scoped:
        saved = 'CBODOTNET_COMPAT_SAVED_' + name
        lines += ['if [ "${' + name + '+x}" = x ]; then',
                  '  export ' + saved + '_SET=1 ' + saved + '_VALUE="$' + name + '"',
                  'else export ' + saved + '_SET=0; unset ' + saved + '_VALUE; fi']
    lines.append('export CBODOTNET_COMPAT_SCOPE=rocky9')
    lines += ['export LD_LIBRARY_PATH="$_cbodotnet_compat/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"',
              'export OPENSSL_CONF="$_cbodotnet_compat/openssl.cnf"',
              'export CLR_OPENSSL_VERSION_OVERRIDE=1.1',
              'export SSL_CERT_FILE="${SSL_CERT_FILE-' + values['SSL_CERT_FILE'] + '}"']
    if 'CLR_ICU_VERSION_OVERRIDE' in values:
        lines.append('export CLR_ICU_VERSION_OVERRIDE=67')
    return '\n'.join(lines) + '\n'


def fetch(item, cache):
    cache = Path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    require(not any(path.is_symlink() for path in [cache, *cache.parents]), 'Provider cache contains a symlink')
    destination = cache / item['name']
    if destination.exists() or destination.is_symlink():
        require(destination.is_file() and not destination.is_symlink()
                and destination.stat().st_size == item['size'] and digest(destination) == item['sha256'],
                'Retained compatibility source bytes differ')
        return destination
    with tempfile.NamedTemporaryFile(prefix='.provider-', dir=cache, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            request = urllib.request.Request(item['url'], headers={'User-Agent': 'cbodotnet-provider-audit/1'})
            with urllib.request.urlopen(request, timeout=120) as response:
                require(response.geturl().startswith('https://dl.rockylinux.org/pub/rocky/'),
                        'Unexpected compatibility source redirect')
                size = 0
                while True:
                    data = response.read(1024 * 1024)
                    if not data:
                        break
                    size += len(data)
                    require(size <= item['size'], 'Compatibility source exceeds pinned length')
                    stream.write(data)
            stream.flush()
            require(size == item['size'] and digest(temporary) == item['sha256'], 'Compatibility source checksum differs')
            temporary.chmod(0o644)
            temporary.rename(destination)
        finally:
            temporary.unlink(missing_ok=True)
    return destination


def verify_sources(policy, architecture, cache, work):
    """Verify full key identity and RPM signatures using disposable key databases."""
    require(architecture in policy['architectures'], 'Unknown native provider architecture')
    key = fetch(policy['key'], cache)
    home = work / 'gnupg'
    home.mkdir(mode=0o700)
    listing = subprocess.check_output(['gpg', '--no-options', '--homedir', str(home), '--batch',
                                       '--with-colons', '--show-keys', str(key)], stderr=subprocess.PIPE, text=True)
    primaries, pending = [], False
    for line in listing.splitlines():
        fields = line.split(':')
        if fields[0] == 'pub':
            pending = True
        elif fields[0] == 'fpr' and pending:
            primaries.append(fields[9]); pending = False
    require(primaries == [FINGERPRINT], 'Compatibility key primary fingerprint differs')
    database = work / 'rpmdb'
    database.mkdir(mode=0o700)
    subprocess.run(['rpmdb', '--dbpath', str(database), '--initdb'], check=True, stdout=subprocess.PIPE)
    subprocess.run(['rpmkeys', '--dbpath', str(database), '--import', str(key)], check=True, stdout=subprocess.PIPE)
    items = [*policy['architectures'][architecture]['packages'], *policy['sources']]
    paths = {}
    for item in items:
        path = fetch(item, cache)
        verification = subprocess.check_output(['rpmkeys', '--dbpath', str(database), '--checksig', '--verbose', str(path)],
                                                stderr=subprocess.STDOUT, text=True)
        require('RSA/SHA256 Signature, key ID 350d275d: OK' in verification
                and 'Payload SHA256 digest: OK' in verification
                and not any(value in verification for value in ('NOKEY', 'NOT OK', 'BAD', 'NOTTRUSTED')),
                'Compatibility RPM lacks the approved valid signature and payload digest')
        paths[item['name']] = path
    return paths


def cpio_members(data):
    """Parse bounded newc entries without extracting paths supplied by an RPM."""
    position = 0
    seen = set()
    while position + 110 <= len(data):
        header = data[position:position + 110]
        require(header[:6] in {b'070701', b'070702'}, 'Unsupported RPM cpio format')
        values = [int(header[index:index + 8], 16) for index in range(6, 110, 8)]
        mode, size, name_size = values[1], values[6], values[11]
        require(0 < name_size <= 4096 and size <= 100_000_000, 'Unbounded RPM cpio entry')
        position += 110
        require(position + name_size <= len(data), 'Truncated RPM cpio filename')
        raw = data[position:position + name_size]
        require(raw.endswith(b'\0'), 'Unterminated RPM cpio filename')
        name = raw[:-1].decode('utf-8')
        position = (position + name_size + 3) & ~3
        require(position + size <= len(data), 'Truncated RPM cpio contents')
        content = data[position:position + size]
        position = (position + size + 3) & ~3
        if name == 'TRAILER!!!':
            return
        name = name[2:] if name.startswith('./') else name
        path = PurePosixPath(name)
        require(name and not path.is_absolute() and str(path) == name and '..' not in path.parts
                and name not in seen and '\\' not in name and '\0' not in name,
                'Unsafe or duplicate RPM cpio member')
        seen.add(name)
        yield name, mode, content
    raise ValueError('RPM cpio archive lacks a complete trailer')


def inspect_elf(path, item, architecture):
    data = path.read_bytes()
    require(data[:6] == b'\x7fELF\x02\x01' and int.from_bytes(data[18:20], 'little') == architecture['elfMachine']
            and len(data) == item['size'] and hashlib.sha256(data).hexdigest() == item['sha256'],
            'Provider ELF identity, architecture or bytes differ')
    dynamic = subprocess.check_output(['readelf', '-dW', str(path)], text=True)
    versions = subprocess.check_output(['readelf', '--version-info', '-W', str(path)], text=True)
    require(re.findall(r'\(SONAME\).*?\[(.*?)\]', dynamic) == item['soname']
            and re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic) == item['needed'], 'Provider ELF dynamic dependencies differ')
    glibcs = set(re.findall(r'\bGLIBC_([0-9.]+)', versions))
    maximum = max(glibcs, key=lambda value: tuple(map(int, value.split('.')))) if glibcs else None
    require(maximum == item['glibcMaximum'], 'Provider GLIBC ABI differs')


def tree_inventory(root, owners=False):
    result = []
    root = Path(root)
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        row = {'path': path.relative_to(root).as_posix(), 'mode': oct(stat.S_IMODE(info.st_mode))}
        if owners:
            row.update(uid=info.st_uid, gid=info.st_gid)
        if path.is_symlink():
            row.update(type='symlink', target=os.readlink(path))
        elif path.is_file():
            row.update(type='file', size=info.st_size, sha256=digest(path))
        elif path.is_dir():
            row.update(type='directory')
        else:
            raise ValueError('Unexpected special provider file')
        result.append(row)
    return result


def inventory_digest(inventory):
    return hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def notice_text(policy):
    return ('Community Build of .NET separately managed compatibility provider.\n'
            'This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit (https://www.openssl.org/).\n'
            'This product includes cryptographic software written by Eric Young (eay@cryptsoft.com).\n'
            'Original OpenSSL/SSLeay and ICU notices are retained in LICENSE.openssl.txt and LICENSE.icu.txt.\n'
            'Native binary bytes originate in the pinned signed Rocky Linux 9 RPMs; this is a project repackaging, not a Rocky-supported cross-distribution product.\n'
            + policy['securityScope'] + '\n')


def validate_tree(root, policy, architecture):
    """Check prepared payload bytes against independent source pins, not its report."""
    require(root.is_dir() and not any(path.is_symlink() for path in [root, *root.parents]), 'Provider tree path contains a symlink')
    expected = {'lib', 'NOTICE.txt', 'openssl.cnf', 'provider-manifest.json'}
    for package in policy['architectures'][architecture]['packages']:
        for item in package['files']:
            path = root / 'lib' / PurePosixPath(item['path']).name
            require(path.is_file() and not path.is_symlink() and stat.S_IMODE(path.stat().st_mode) == 0o755,
                    'Prepared provider ELF mode differs')
            inspect_elf(path, item, policy['architectures'][architecture])
            link = root / 'lib' / item['soname'][0]
            require(link.is_symlink() and os.readlink(link) == path.name, 'Prepared provider SONAME link differs')
            expected.update([str(path.relative_to(root)), str(link.relative_to(root))])
        filename = 'LICENSE.openssl.txt' if package['packageName'] == 'compat-openssl11' else 'LICENSE.icu.txt'
        original = package['licenses'][0]
        path = root / filename
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == original['size']
                and digest(path) == original['sha256'], 'Prepared provider license differs')
        expected.add(filename)
    require({row['path'] for row in tree_inventory(root)} == expected, 'Prepared provider has unaccounted files')
    for filename, content in [('openssl.cnf', policy['opensslConfiguration']['content']), ('NOTICE.txt', notice_text(policy))]:
        path = root / filename
        require(path.is_file() and not path.is_symlink() and path.read_bytes() == content.encode(), 'Prepared provider configuration or notice differs')
    require(all(row['mode'] == ('0o755' if row['path'] == 'lib' else '0o644')
                for row in tree_inventory(root) if '/' not in row['path']), 'Prepared provider metadata mode differs')


def stage_provider(architecture, output, cache=None):
    policy = load_policy()
    output = Path(output).absolute()
    require(not output.exists() and output.parent.is_dir()
            and not any(path.is_symlink() for path in [output, *output.parents]), 'Use a fresh ordinary provider output')
    output.mkdir(mode=0o755)
    cache = Path(cache).absolute() if cache is not None else output / 'source-cache'
    with tempfile.TemporaryDirectory(prefix='cbodotnet-provider-') as temporary:
        paths = verify_sources(policy, architecture, cache, Path(temporary))
        root = output / 'rootfs' / PROVIDER_ROOT.lstrip('/')
        (root / 'lib').mkdir(parents=True)
        for package in policy['architectures'][architecture]['packages']:
            payload = subprocess.check_output(['rpm2cpio', str(paths[package['name']])])
            entries = {name: (mode, content) for name, mode, content in cpio_members(payload)}
            for item in package['files']:
                require(item['path'] in entries, 'Pinned provider ELF is absent')
                mode, content = entries[item['path']]
                require(stat.S_ISREG(mode) and stat.S_IMODE(mode) == 0o755, 'Unexpected provider ELF mode')
                target = root / 'lib' / PurePosixPath(item['path']).name
                target.write_bytes(content); target.chmod(0o755)
                inspect_elf(target, item, policy['architectures'][architecture])
                soname = item['soname'][0]
                link_path = str(PurePosixPath(item['path']).parent / soname)
                require(entries.get(link_path, (0, b''))[1] == target.name.encode()
                        and stat.S_ISLNK(entries[link_path][0]), 'Provider SONAME link differs')
                (root / 'lib' / soname).symlink_to(target.name)
            for item in package['licenses']:
                mode, content = entries[item['path']]
                require(stat.S_ISREG(mode) and len(content) == item['size']
                        and hashlib.sha256(content).hexdigest() == item['sha256'], 'Provider license bytes differ')
                target = root / ('LICENSE.openssl.txt' if package['packageName'] == 'compat-openssl11' else 'LICENSE.icu.txt')
                target.write_bytes(content); target.chmod(0o644)
        (root / 'openssl.cnf').write_text(policy['opensslConfiguration']['content'], encoding='utf-8', newline='\n')
        (root / 'NOTICE.txt').write_text(notice_text(policy), encoding='utf-8', newline='\n')
        for directory in [output / 'rootfs', *[path for path in (output / 'rootfs').rglob('*') if path.is_dir()]]:
            directory.chmod(0o755)
        for path in root.iterdir():
            if path.is_file() and not path.is_symlink():
                path.chmod(0o644)
        manifest = {'schemaVersion': 1, 'providerId': policy['providerId'], 'architecture': architecture,
                    'providerRoot': PROVIDER_ROOT, 'policySha256': hashlib.sha256(POLICY.read_text().replace('\r\n', '\n').encode()).hexdigest(),
                    'signingFingerprint': FINGERPRINT, 'packages': policy['architectures'][architecture]['packages'],
                    'sourcePackages': policy['sources'], 'key': policy['key'], 'opensslConfiguration': policy['opensslConfiguration'],
                    'securityScope': policy['securityScope'], 'files': tree_inventory(root)}
        write_json(root / 'provider-manifest.json', manifest)
    for path in root.rglob('*'):
        if path.is_file() and not path.is_symlink() and path.parent != root / 'lib':
            path.chmod(0o644)
    write_json(output / 'provider-manifest.json', manifest)
    validate_tree(root, policy, architecture)
    return output, root, manifest


def companion_tar(output, architecture):
    name = f'{PACKAGE_NAME}-{VERSION}-linux-{architecture}.tar.gz'
    destination = output / name
    import gzip
    with destination.open('xb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=EPOCH) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                for path in [output / 'provider-manifest.json', output / 'rootfs', *sorted((output / 'rootfs').rglob('*'))]:
                    info = archive.gettarinfo(str(path), arcname=path.relative_to(output).as_posix())
                    info.uid = info.gid = 0; info.uname = info.gname = ''; info.mtime = EPOCH
                    if info.isfile():
                        with path.open('rb') as stream:
                            archive.addfile(info, stream)
                    else:
                        archive.addfile(info)
    return descriptor(destination)


def build_deb(output, architecture):
    stage = output / 'deb-package'
    shutil.copytree(output / 'rootfs', stage, symlinks=True)
    control = stage / 'DEBIAN'
    control.mkdir()
    control.joinpath('control').write_text(
        f'Package: {PACKAGE_NAME}\nVersion: {VERSION}-1\nArchitecture: '
        + {'x64': 'amd64', 'aarch64': 'arm64'}[architecture]
        + '\nMaintainer: .NET Dev contributors\nSection: libs\nPriority: optional\n'
        'Depends: libc6 (>= 2.34), libgcc-s1, libstdc++6, zlib1g, ca-certificates\n'
        'Description: Separate Rocky-origin OpenSSL 1.1 and ICU 67 provider for Community Build legacy SDKs\n', encoding='utf-8')
    sums = [hashlib.md5(path.read_bytes()).hexdigest() + '  ' + path.relative_to(stage).as_posix()
            for path in sorted(stage.rglob('*')) if path.is_file() and not path.is_symlink() and control not in path.parents]
    (control / 'md5sums').write_text('\n'.join(sums) + '\n', encoding='ascii')
    destination = output / f'{PACKAGE_NAME}_{VERSION}-1_{"amd64" if architecture == "x64" else "arm64"}.deb'
    subprocess.run(['dpkg-deb', '--root-owner-group', '-Zxz', '-z6', '--build', str(stage), str(destination)],
                   check=True, stdout=subprocess.PIPE, env=dict(os.environ, SOURCE_DATE_EPOCH=str(EPOCH), TZ='UTC', LC_ALL='C'))
    return descriptor(destination)


def build_rpm(output, architecture, variant):
    from channel_packages import rpm_build_directories, rpm_build_macros, deterministic_tar, run_rpmbuild
    require(variant in {'fedora-45', 'rocky-9.8'}, 'Unreviewed compatibility RPM variant')
    top = rpm_build_directories(output)
    deterministic_tar(output / 'rootfs', top / 'SOURCES/provider.tar.gz')
    dependency = 'zlib-ng-compat' if variant == 'fedora-45' else 'zlib'
    native = {'x64': 'x86_64', 'aarch64': 'aarch64'}[architecture]
    release = '1.cbot.' + variant.replace('-', '')
    spec = top / 'SPECS/provider.spec'
    spec.write_text(rpm_build_macros() + f'''
Name: {PACKAGE_NAME}
Version: {VERSION}
Release: {release}
Summary: Separate Rocky-origin compatibility libraries for Community Build legacy SDKs
License: LicenseRef-OpenSSL-SSLeay AND Apache-2.0 AND Unicode-DFS-2016 AND BSD-2-Clause AND BSD-3-Clause AND LicenseRef-Fedora-Public-Domain
URL: https://dotnetdev.kr/cbodotnet/
Source0: provider.tar.gz
BuildArch: {native}
AutoReqProv: no
Requires: glibc >= 2.34, libgcc, libstdc++, {dependency}, ca-certificates
%description
Project repackaging of separately maintained signed Rocky Linux 9 libraries.
Original binary bytes, licenses and exact source/package provenance are retained.
%prep
%build
%install
mkdir -p "%{{buildroot}}"
tar -xzf "%{{SOURCE0}}" -C "%{{buildroot}}"
%files
%defattr(-,root,root,-)
{PROVIDER_ROOT}
''', encoding='utf-8', newline='\n')
    run_rpmbuild(spec, top, native)
    packages = list((top / 'RPMS').rglob('*.rpm'))
    require(len(packages) == 1, 'Compatibility RPM output differs')
    target = output / packages[0].name
    shutil.copyfile(packages[0], target)
    return descriptor(target)


def arch_recipe(policy, architecture='x64'):
    require(architecture == 'x64', 'Arch delivery is qualified separately for x64 only')
    packages = policy['architectures'][architecture]['packages']
    sources = [*packages, *policy['sources'], policy['key']]
    files = '\n'.join('  "' + item['url'] + '"' for item in sources)
    sums = ' '.join("'" + item['sha256'] + "'" for item in sources)
    selected = []
    for package in packages:
        for item in package['files']:
            selected += ['  install -Dm755 "' + package['packageName'] + '/' + item['path'] + '" "$dest/lib/' + PurePosixPath(item['path']).name + '"',
                         '  ln -s ' + shlex.quote(PurePosixPath(item['path']).name) + ' "$dest/lib/' + item['soname'][0] + '"']
        selected += ['  install -Dm644 "' + package['packageName'] + '/' + package['licenses'][0]['path']
                     + '" "$dest/LICENSE.' + ('openssl' if package['packageName'] == 'compat-openssl11' else 'icu') + '.txt"']
    # The recipe uses the same staged, reviewed metadata/configuration files.
    return f'''# Separate provider; no SDK binaries are included or rebuilt.
pkgname={PACKAGE_NAME}
pkgver={VERSION}
pkgrel=1
pkgdesc='Separately managed Rocky-origin OpenSSL 1.1 and ICU 67 for Community Build legacy SDKs'
arch=('x86_64')
url='https://dotnetdev.kr/cbodotnet/'
license=('LicenseRef-OpenSSL-SSLeay' 'Apache-2.0' 'Unicode-DFS-2016' 'BSD-2-Clause' 'BSD-3-Clause' 'LicenseRef-Fedora-Public-Domain')
depends=('glibc>=2.34' 'libgcc' 'libstdc++' 'zlib' 'ca-certificates')
makedepends=('rpm-tools' 'gnupg')
options=('!strip' '!debug' '!lto')
source=(
{files}
  'openssl.cnf' 'NOTICE.txt' 'provider-manifest.json')
sha256sums=({sums}
  '{policy['opensslConfiguration']['sha256']}' '@NOTICE_SHA256@' '@MANIFEST_SHA256@')
noextract=({' '.join(shlex.quote(item['name']) for item in sources)})
prepare() {{
  local fpr
  fpr=$(gpg --batch --with-colons --show-keys RPM-GPG-KEY-Rocky-9 | awk -F: '$1=="pub"{{primary=1;next}} primary&&$1=="fpr"{{print $10;primary=0}}')
  [[ "$fpr" == '{FINGERPRINT}' ]]
  mkdir -p "$srcdir/rpmdb"
  rpmdb --dbpath "$srcdir/rpmdb" --initdb
  rpmkeys --dbpath "$srcdir/rpmdb" --import RPM-GPG-KEY-Rocky-9
  local rpm
  for rpm in *.rpm; do rpmkeys --dbpath "$srcdir/rpmdb" --checksig "$rpm"; done
  mkdir -p compat-openssl11 libicu
  bsdtar -xf {shlex.quote(packages[0]['name'])} -C compat-openssl11
  bsdtar -xf {shlex.quote(packages[1]['name'])} -C libicu
}}
package() {{
  local dest="$pkgdir{PROVIDER_ROOT}"
  mkdir -p "$dest/lib"
{chr(10).join(selected)}
  install -m644 openssl.cnf NOTICE.txt provider-manifest.json "$dest/"
}}
'''


def arch_srcinfo(policy, notice_hash, manifest_hash):
    sources = [*policy['architectures']['x64']['packages'], *policy['sources'], policy['key']]
    lines = ['pkgbase = ' + PACKAGE_NAME,
             '\tpkgdesc = Separately managed Rocky-origin OpenSSL 1.1 and ICU 67 for Community Build legacy SDKs',
             '\tpkgver = ' + VERSION, '\tpkgrel = 1', '\turl = https://dotnetdev.kr/cbodotnet/', '\tarch = x86_64']
    fields = {'license': ['LicenseRef-OpenSSL-SSLeay', 'Apache-2.0', 'Unicode-DFS-2016', 'BSD-2-Clause', 'BSD-3-Clause', 'LicenseRef-Fedora-Public-Domain'],
              'makedepends': ['rpm-tools', 'gnupg'], 'depends': ['glibc>=2.34', 'libgcc', 'libstdc++', 'zlib', 'ca-certificates'],
              'noextract': [item['name'] for item in sources], 'options': ['!strip', '!debug', '!lto'],
              'source': [item['url'] for item in sources] + ['openssl.cnf', 'NOTICE.txt', 'provider-manifest.json'],
              'sha256sums': [item['sha256'] for item in sources] + [policy['opensslConfiguration']['sha256'], notice_hash, manifest_hash]}
    for key, values in fields.items():
        lines += ['\t' + key + ' = ' + value for value in values]
    return '\n'.join([*lines, '', 'pkgname = ' + PACKAGE_NAME, ''])


def build_provider(architecture, output, cache=None, variant=None):
    output, root, manifest = stage_provider(architecture, output, cache)
    result = {'schemaVersion': 1, 'providerRoot': PROVIDER_ROOT, 'architecture': architecture, 'variant': variant,
              'policySha256': manifest['policySha256'], 'manifest': manifest,
              'companion': companion_tar(output, architecture), 'packages': []}
    if variant in {'ubuntu-24.04', 'debian-13'}:
        result['packages'].append({**build_deb(output, architecture), 'kind': 'compatibility', 'name': PACKAGE_NAME,
                                   'version': VERSION + '-1', 'architecture': {'x64': 'amd64', 'aarch64': 'arm64'}[architecture]})
    elif variant in {'fedora-45', 'rocky-9.8'}:
        result['packages'].append({**build_rpm(output, architecture, variant), 'kind': 'compatibility', 'name': PACKAGE_NAME,
                                   'version': VERSION, 'release': '1.cbot.' + variant.replace('-', ''),
                                   'architecture': {'x64': 'x86_64', 'aarch64': 'aarch64'}[architecture]})
    elif variant == 'arch-rolling':
        text = arch_recipe(load_policy(), architecture)
        for filename in ('openssl.cnf', 'NOTICE.txt', 'provider-manifest.json'):
            shutil.copyfile(root / filename, output / filename)
        text = text.replace('@NOTICE_SHA256@', digest(output / 'NOTICE.txt')).replace('@MANIFEST_SHA256@', digest(output / 'provider-manifest.json'))
        (output / 'PKGBUILD').write_text(text, encoding='utf-8', newline='\n')
        (output / '.SRCINFO').write_text(arch_srcinfo(load_policy(), digest(output / 'NOTICE.txt'), digest(output / 'provider-manifest.json')),
                                       encoding='utf-8', newline='\n')
        result['recipe'] = descriptor(output / 'PKGBUILD')
        result['srcinfo'] = descriptor(output / '.SRCINFO')
    else:
        require(variant is None, 'Unknown compatibility provider packaging variant')
    write_json(output / 'provider-build.json', result)
    return result


def verified_build(path, plan, channel):
    """Bind an explicit prepared artifact to this exact provider policy and target."""
    path = Path(path).absolute()
    require(path.is_file() and not any(item.is_symlink() for item in [path, *path.parents]),
            'An ordinary prepared compatibility build record is required')
    record = json.loads(path.read_bytes())
    policy = load_policy()
    policy_hash = hashlib.sha256(POLICY.read_text().replace('\r\n', '\n').encode()).hexdigest()
    require(record.get('schemaVersion') == 1 and record.get('providerRoot') == PROVIDER_ROOT
            and record.get('architecture') == plan['architecture']['public'] and record.get('policySha256') == policy_hash,
            'Prepared compatibility provider identity differs')
    manifest = record['manifest']
    require(manifest.get('schemaVersion') == 1 and manifest.get('providerId') == policy['providerId']
            and manifest.get('providerRoot') == PROVIDER_ROOT and manifest.get('architecture') == record['architecture']
            and manifest['policySha256'] == policy_hash and manifest['signingFingerprint'] == FINGERPRINT
            and manifest.get('key') == policy['key'] and manifest.get('securityScope') == policy['securityScope']
            and manifest['packages'] == policy['architectures'][record['architecture']]['packages']
            and manifest['sourcePackages'] == policy['sources'] and manifest['opensslConfiguration'] == policy['opensslConfiguration'],
            'Prepared compatibility source provenance differs')
    require(channel in {'deb', 'rpm', 'oci'}, 'Unknown compatibility packaging channel')
    if channel in {'deb', 'rpm'}:
        require(record.get('variant') == plan['variant'] and len(record['packages']) == 1, 'Prepared compatibility package target differs')
        package = record['packages'][0]
        require(package.get('kind') == 'compatibility' and package.get('name') == PACKAGE_NAME
                and package.get('architecture') == plan['architecture'][channel]
                and package.get('version') == (VERSION + '-1' if channel == 'deb' else VERSION)
                and package['path'].endswith('.' + ('deb' if channel == 'deb' else 'rpm')),
                'Prepared compatibility package identity differs')
        if channel == 'rpm':
            require(package.get('release') == '1.cbot.' + plan['variant'].replace('-', ''),
                    'Prepared compatibility RPM release differs')
    for item in [record['companion'], *record['packages']]:
        require(re.fullmatch(r'[A-Za-z0-9._+-]+', item['path']), 'Unsafe compatibility artifact filename')
        require(descriptor(path.parent / item['path']) == {key: item[key] for key in ('path', 'size', 'sha256')},
                'Prepared compatibility artifact bytes differ')
    require(record['companion']['path'] == f'{PACKAGE_NAME}-{VERSION}-linux-{record["architecture"]}.tar.gz',
            'Prepared compatibility companion name differs')
    root = path.parent / 'rootfs' / PROVIDER_ROOT.lstrip('/')
    validate_tree(root, policy, record['architecture'])
    expected = manifest['files']
    require(tree_inventory(root) == sorted([*expected, {
        'path': 'provider-manifest.json', 'type': 'file', 'mode': '0o644',
        'size': (root / 'provider-manifest.json').stat().st_size, 'sha256': digest(root / 'provider-manifest.json')}], key=lambda row: row['path'])
        and json.loads((root / 'provider-manifest.json').read_bytes()) == manifest
        and json.loads((path.parent / 'provider-manifest.json').read_bytes()) == manifest,
        'Prepared compatibility tree differs')
    verify_companion(path.parent / record['companion']['path'], path.parent)
    return path.parent, record


def verify_companion(archive_path, prepared):
    """Compare the actual companion archive with its independently checked tree."""
    prepared = Path(prepared)
    expected = {('rootfs/' + row['path']): row for row in tree_inventory(prepared / 'rootfs')}
    expected['rootfs'] = {'type': 'directory', 'mode': '0o755'}
    expected['provider-manifest.json'] = {'type': 'file', 'mode': '0o644', **descriptor(prepared / 'provider-manifest.json')}
    seen = set()
    with tarfile.open(archive_path, 'r:gz') as archive:
        for member in archive:
            require(member.name in expected and member.name not in seen and member.uid == 0 and member.gid == 0,
                    'Compatibility companion contains an unexpected member or ownership')
            seen.add(member.name)
            item = expected[member.name]
            require(oct(member.mode) == item['mode'], 'Compatibility companion mode differs')
            if item['type'] == 'file':
                require(member.isfile() and member.size == item['size'], 'Compatibility companion file type/length differs')
                result = hashlib.sha256()
                with archive.extractfile(member) as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b''):
                        result.update(block)
                require(result.hexdigest() == item['sha256'], 'Compatibility companion file bytes differ')
            elif item['type'] == 'symlink':
                require(member.issym() and member.linkname == item['target'], 'Compatibility companion link differs')
            else:
                require(member.isdir(), 'Compatibility companion directory differs')
    require(seen == set(expected), 'Compatibility companion is incomplete')


def read_state(state):
    return json.loads(Path(state).read_bytes()) if not isinstance(state, dict) else state


def runtime_environment(plan, state):
    if not required(plan):
        return {}
    state = read_state(state)
    require(state.get('providerRoot') == PROVIDER_ROOT and state.get('architecture') == plan['architecture']['public'],
            'Compatibility state does not match SDK plan')
    require(state.get('policySha256') == hashlib.sha256(POLICY.read_text().replace('\r\n', '\n').encode()).hexdigest(),
            'Compatibility state policy changed')
    cpu_preflight(state['architecture'])
    return environment(plan)


def assert_unchanged(state):
    state = read_state(state)
    if state.get('required') is False:
        return {'status': 'not-required'}
    require(state.get('providerRoot') == PROVIDER_ROOT, 'Unexpected managed compatibility root')
    actual = tree_inventory(Path(PROVIDER_ROOT), owners=True)
    require(actual == state['files'] and inventory_digest(actual) == state['treeSha256'], 'Managed compatibility provider changed')
    cpu = cpu_preflight(state['architecture'])
    return {'status': 'passed', 'providerRoot': PROVIDER_ROOT, 'architecture': state['architecture'], 'cpu': cpu,
            'treeSha256': state['treeSha256'], 'policySha256': state['policySha256'],
            'signingFingerprint': state['signingFingerprint']}


def provision(plan, delivery, user=None):
    """Network-only preparation inside an exact disposable native target container."""
    if not required(plan):
        return {'required': False}
    require(os.name == 'posix' and os.geteuid() == 0 and Path('/.dockerenv').is_file(),
            'Compatibility installation requires a disposable root container')
    architecture = plan['architecture']['public']
    require(platform.machine() == {'x64': 'x86_64', 'aarch64': 'aarch64'}[architecture], 'Native provider architecture required')
    cpu = cpu_preflight(architecture)
    variant = plan['variant']
    values = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    identity = values['ID'].strip('"') + '-' + values.get('VERSION_ID', 'rolling').strip('"')
    require(identity == variant, 'Compatibility installation operating system differs')
    delivery = Path(delivery)
    delivery.mkdir(parents=True, exist_ok=True)
    managed = Path(PROVIDER_ROOT)
    require(not any(path.is_symlink() for path in [managed, *managed.parents]), 'Managed compatibility provider path contains a symlink')
    output = delivery / 'compatibility-provider'
    result = build_provider(architecture, output, cache=delivery / 'compatibility-sources', variant=variant)
    if managed.exists():
        require(managed.is_dir() and tree_inventory(managed) == tree_inventory(output / 'rootfs' / PROVIDER_ROOT.lstrip('/')),
                'Existing managed compatibility provider differs from authenticated payload')
    elif variant in {'ubuntu-24.04', 'debian-13'}:
        subprocess.run(['apt-get', 'install', '-y', str(output / result['packages'][0]['path'])], check=True)
    elif variant in {'fedora-45', 'rocky-9.8'}:
        subprocess.run(['dnf', '-y', 'install', str(output / result['packages'][0]['path']), '--setopt=localpkg_gpgcheck=0'], check=True)
    else:
        require(user is not None, 'Arch provider recipe requires an ordinary build user')
        import pwd
        account = pwd.getpwnam(user)
        for path in [output, *output.rglob('*')]:
            os.chown(path, account.pw_uid, account.pw_gid, follow_symlinks=False)
        subprocess.run(['runuser', '-u', user, '--', 'makepkg', '--nodeps', '--noconfirm', '--cleanbuild'], cwd=output, check=True)
        packages = list(output.glob('*.pkg.tar.zst'))
        require(len(packages) == 1, 'Arch provider package output differs')
        subprocess.run(['pacman', '-U', '--noconfirm', str(packages[0])], check=True)
        result['packages'] = [descriptor(packages[0])]
    root = Path(PROVIDER_ROOT)
    require(tree_inventory(root) == tree_inventory(output / 'rootfs' / PROVIDER_ROOT.lstrip('/')),
            'Installed provider differs from authenticated staged payload')
    inventory = tree_inventory(root, owners=True)
    require(all(item['uid'] == 0 and item['gid'] == 0 for item in inventory), 'Managed provider must be owned by root')
    state = {'schemaVersion': 1, 'required': True, 'providerRoot': PROVIDER_ROOT, 'architecture': architecture,
             'variant': variant, 'policySha256': result['policySha256'], 'signingFingerprint': FINGERPRINT,
             'packages': result['manifest']['packages'], 'sourcePackages': result['manifest']['sourcePackages'],
             'packageArtifact': result['packages'][0], 'files': inventory, 'treeSha256': inventory_digest(inventory),
             'environment': environment(plan), 'cpu': cpu}
    state_path = delivery / 'compatibility-state.json'
    write_json(state_path, state); state_path.chmod(0o644)
    assert_unchanged(state)
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=['x64', 'aarch64'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--variant', choices=['ubuntu-24.04', 'debian-13', 'fedora-45', 'rocky-9.8', 'arch-rolling'])
    args = parser.parse_args()
    result = build_provider(args.arch, args.output, args.cache, args.variant)
    print(json.dumps({'companion': result['companion'], 'packages': result['packages']}, sort_keys=True))


if __name__ == '__main__':
    main()
