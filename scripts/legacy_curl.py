#!/usr/bin/env python3
"""Separately own current Rocky8 curl bytes for Core3's optional native handler."""
import argparse
import gzip
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

import legacy_compat as BASE

POLICY = BASE.ROOT / 'releases/legacy-curl-provider.json'
PACKAGE_NAME = 'cbodotnet-compat-curl-rocky8'
VERSION = '2026.11.4'
PROVIDER_ROOT = '/usr/lib/cbodotnet/compat/curl-rocky8'
FINGERPRINT = '7051C470A929F454CEBE37B715AF5DAC6D745A60'
KIND = 'native-http-compatibility'
require, digest, descriptor, write_json = BASE.require, BASE.digest, BASE.descriptor, BASE.write_json
tree_inventory, inventory_digest = BASE.tree_inventory, BASE.inventory_digest


def policy_hash():
    return hashlib.sha256(POLICY.read_text().replace('\r\n', '\n').encode()).hexdigest()


def load_policy():
    value = json.loads(POLICY.read_text(encoding='utf-8-sig'))
    require(value.get('schemaVersion') == 1 and value.get('providerId') == 'rocky8-curl-20261104'
            and value.get('packageName') == PACKAGE_NAME and value.get('version') == VERSION
            and value.get('packageRevision') == 1 and value.get('root') == PROVIDER_ROOT
            and value.get('signingFingerprint') == FINGERPRINT and value.get('sdkSeries') == ['3.0', '3.1']
            and set(value.get('architectures', {})) == {'x64', 'aarch64'}, 'Unreviewed native HTTP provider identity')
    base = value['baseProvider']; expected = BASE.load_policy()
    require(base == dict(providerId=expected['providerId'], packageName=BASE.PACKAGE_NAME, version=BASE.VERSION,
                         root=BASE.PROVIDER_ROOT, policySha256=hashlib.sha256(BASE.POLICY.read_text().replace('\r\n', '\n').encode()).hexdigest()),
            'Native HTTP provider requires the exact unchanged reviewed SSL/ICU provider')
    require(value['key']['name'] == 'RPM-GPG-KEY-Rocky-8'
            and value['key']['sha256'] == 'ef1ca99bba38bb2869a06fbf46860fcdaeece796be98f8dfb0160b84bdbc69ab'
            and value['key']['size'] == 1672, 'Native HTTP public key differs')
    require(isinstance(value.get('sources'), list) and len(value['sources']) == 1
            and isinstance(value.get('nativeHttpComponents'), dict)
            and set(value['nativeHttpComponents']) == {'3.0.103', '3.1.426'},
            'The exact native HTTP source/component matrix is required')
    for arch, row in value['architectures'].items():
        require(row.get('elfMachine') == {'x64': 62, 'aarch64': 183}[arch]
                and isinstance(row.get('packages'), list) and len(row['packages']) == 1,
                'One exact native HTTP source package per architecture is required')
        package = row['packages'][0]
        require(package.get('packageName') == 'libcurl-minimal' and package.get('epoch') == 0
                and package.get('version') == '7.61.1' and package.get('release') == '34.el8_10.18'
                and package.get('sourcePackage') == value['sources'][0]['name']
                and isinstance(package.get('files'), list) and len(package['files']) == 1
                and isinstance(package.get('licenses'), list) and len(package['licenses']) == 1,
                'Native HTTP source ELF/notice package shape differs')
        item = package['files'][0]
        require(item.get('path') == 'usr/lib64/libcurl.so.4.5.0' and item.get('soname') == ['libcurl.so.4']
                and item.get('glibcMaximum') == '2.17' and item.get('curlVersionDefinitions') == []
                and type(item.get('size')) is int and item['size'] > 0
                and re.fullmatch(r'[a-f0-9]{64}', item.get('sha256', ''))
                and isinstance(item.get('needed'), list) and item['needed']
                and all(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9._-]+', name) for name in item['needed'])
                and {'libssl.so.1.1', 'libcrypto.so.1.1'} <= set(item['needed']),
                'Native HTTP source ELF identity/ABI differs')
        notice = package['licenses'][0]
        require(notice.get('path') == 'usr/share/licenses/libcurl-minimal/COPYING' and notice.get('size') == 1088
                and notice.get('sha256') == '5f3849ec38ddb927e79f514bf948890c41b8d1407286a49609b8fb1585931095',
                'Native HTTP original copyright/permission pin differs')
    for item in [value['key'], *value['sources'], *[package for row in value['architectures'].values() for package in row['packages']]]:
        require(re.fullmatch(r'[A-Za-z0-9._+-]+', item['name']) and type(item['size']) is int and item['size'] > 0
                and re.fullmatch(r'[a-f0-9]{64}', item['sha256'])
                and item['url'].startswith('https://dl.rockylinux.org/pub/rocky/')
                and item['url'].endswith('/' + item['name']), 'Unreviewed native HTTP source descriptor')
    for version, rows in value['nativeHttpComponents'].items():
        require(version in {'3.0.103', '3.1.426'} and set(rows) == {'x64', 'aarch64'}, 'Unreviewed native HTTP SDK component matrix')
        for row in rows.values():
            require(re.fullmatch(r'shared/Microsoft\.NETCore\.App/[0-9.]+/System\.Net\.Http\.Native\.so', row['path'])
                    and re.fullmatch(r'[a-f0-9]{64}', row['sha256']), 'Unreviewed original native HTTP component')
    return value


def required(plan):
    return plan['sdkVersion'].startswith(('3.0.', '3.1.'))


def architecture(plan):
    value = plan.get('architecture')
    value = value.get('public') if isinstance(value, dict) else value
    require(value in {'x64', 'aarch64'}, 'An explicit native HTTP provider architecture is required')
    return value


def plan_policy(plan):
    if not required(plan):
        return None
    policy = load_policy()
    require(plan['sdkVersion'] in policy['nativeHttpComponents'], 'Unreviewed Core3 native HTTP SDK component')
    return dict(required=True, providerId=policy['providerId'], root=PROVIDER_ROOT, policySha256=policy_hash(),
                companionName=f'{PACKAGE_NAME}-{VERSION}-linux-{architecture(plan)}.tar.gz',
                baseProviderId=policy['baseProvider']['providerId'])


def runtime_pins(plan):
    if not required(plan):
        return None
    policy = load_policy(); arch = architecture(plan)
    native = policy['nativeHttpComponents'][plan['sdkVersion']][arch]
    curl = policy['architectures'][arch]['packages'][0]['files'][0]
    return dict(nativeHttp=dict(native), curl=dict(path='lib/' + PurePosixPath(curl['path']).name, sha256=curl['sha256']))


def package_requirement(channel, variant=None):
    if channel == 'deb':
        return PACKAGE_NAME + ' (= ' + VERSION + '-1)'
    if channel == 'rpm':
        require(variant in {'fedora-45', 'rocky-9.8'}, 'Unreviewed native HTTP RPM variant')
        return PACKAGE_NAME + ' = ' + VERSION + '-1.cbot.' + variant.replace('-', '')
    require(channel == 'aur', 'Unknown native HTTP dependency package format')
    return PACKAGE_NAME + '=' + VERSION + '-1'


def environment(plan, root=PROVIDER_ROOT, base_environment=None):
    result = dict(base_environment or {})
    if not required(plan):
        return result
    require(isinstance(root, str) and root.startswith('/') and root != '/' and str(PurePosixPath(root)) == root
            and '..' not in PurePosixPath(root).parts, 'An absolute isolated native HTTP root is required')
    if base_environment is None:
        result = BASE.environment(plan)
    result['LD_LIBRARY_PATH'] = root + '/lib' + (':' + result['LD_LIBRARY_PATH'] if result.get('LD_LIBRARY_PATH') else '')
    return result


def launcher_environment(plan):
    """Append after the base scope; that scope restores both private prefixes."""
    if not required(plan):
        return ''
    return '''# Core3's optional native CurlHandler requires the separate reviewed curl ABI.
_cbodotnet_curl_root=${CBODOTNET_CURL_COMPAT_ROOT:-''' + PROVIDER_ROOT + '''}
case "$_cbodotnet_curl_root" in /*) ;; *) echo "cbodotnet: native HTTP provider root must be absolute" >&2; exit 70 ;; esac
if [ ! -f "$_cbodotnet_curl_root/lib/libcurl.so.4.5.0" ] || [ ! -f "$_cbodotnet_curl_root/provider-manifest.json" ]; then
  echo "cbodotnet: missing separate native HTTP provider; install cbodotnet-compat-curl-rocky8 or set CBODOTNET_CURL_COMPAT_ROOT" >&2
  exit 70
fi
export LD_LIBRARY_PATH="$_cbodotnet_curl_root/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
unset _cbodotnet_curl_root
'''


def notice_text(policy):
    return ('Community Build of .NET separately managed Core3 native HTTP compatibility provider.\n'
            'Original libcurl binary bytes and COPYRIGHT AND PERMISSION NOTICE originate in the pinned signed Rocky Linux 8 RPMs.\n'
            'The original curl notice is retained in LICENSE.curl.txt; exact source RPMs are recorded in provider-manifest.json.\n'
            'This is a project repackaging, not a Rocky-supported cross-distribution product.\n'
            + policy['securityScope'] + '\n')


def manifest_for_tree(root, policy, arch):
    return dict(schemaVersion=1, providerId=policy['providerId'], providerRoot=PROVIDER_ROOT, architecture=arch,
        policySha256=policy_hash(), signingFingerprint=FINGERPRINT, key=policy['key'],
        packages=policy['architectures'][arch]['packages'], sourcePackages=policy['sources'], baseProvider=policy['baseProvider'],
        nativeHttpComponents=policy['nativeHttpComponents'], securityScope=policy['securityScope'],
        files=[row for row in tree_inventory(root) if row['path'] != 'provider-manifest.json'])


def validate_rootfs_shape(rootfs):
    relative = PurePosixPath(PROVIDER_ROOT.lstrip('/'))
    parents = {str(path) for path in relative.parents if str(path) != '.'}
    expected = parents | {str(relative)} | {str(relative) + '/' + row['path']
        for row in tree_inventory(Path(rootfs) / str(relative))}
    rows = tree_inventory(rootfs)
    require({row['path'] for row in rows} == expected and all(row['type'] == 'directory' and row['mode'] == '0o755'
        for row in rows if row['path'] in parents | {str(relative)}), 'Unaccounted native HTTP provider rootfs paths')


def validate_tree(root, policy, arch):
    root = Path(root)
    require(root.is_dir() and not any(path.is_symlink() for path in [root, *root.parents]), 'Native HTTP provider tree contains a symlink')
    expected = {'lib', 'LICENSE.curl.txt', 'NOTICE.txt', 'provider-manifest.json'}
    package = policy['architectures'][arch]['packages'][0]
    for item in package['files']:
        path = root / 'lib' / PurePosixPath(item['path']).name
        require(path.is_file() and not path.is_symlink() and stat.S_IMODE(path.stat().st_mode) == 0o755, 'Native HTTP ELF mode differs')
        BASE.inspect_elf(path, item, policy['architectures'][arch])
        link = root / 'lib' / item['soname'][0]
        require(link.is_symlink() and os.readlink(link) == path.name, 'Native HTTP SONAME differs')
        expected.update([str(path.relative_to(root)), str(link.relative_to(root))])
    license = package['licenses'][0]; path = root / 'LICENSE.curl.txt'
    require(path.is_file() and not path.is_symlink() and path.stat().st_size == license['size']
            and digest(path) == license['sha256'], 'Native HTTP original copyright/permission notice differs')
    require((root / 'NOTICE.txt').read_bytes() == notice_text(policy).encode()
            and {row['path'] for row in tree_inventory(root)} == expected, 'Unaccounted native HTTP provider files or notice')
    require(all(row['mode'] == ('0o755' if row['path'] == 'lib' else '0o644')
                for row in tree_inventory(root) if '/' not in row['path']), 'Native HTTP provider metadata mode differs')
    require(json.loads((root / 'provider-manifest.json').read_bytes()) == manifest_for_tree(root, policy, arch),
            'Native HTTP provider manifest differs from independently pinned sources and actual tree')


def stage_provider(arch, output, cache=None):
    policy = load_policy(); output = Path(output).absolute()
    require(arch in policy['architectures'] and not output.exists() and output.parent.is_dir()
            and not any(path.is_symlink() for path in [output, *output.parents]), 'Use a fresh ordinary native HTTP provider output')
    output.mkdir(); cache = Path(cache).absolute() if cache is not None else output / 'source-cache'
    root = output / 'rootfs' / PROVIDER_ROOT.lstrip('/'); (root / 'lib').mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix='cbodotnet-curl-source-') as temporary:
        paths = BASE.verify_sources(policy, arch, cache, Path(temporary), trusted_fingerprint=FINGERPRINT)
        package = policy['architectures'][arch]['packages'][0]
        entries = {name: (mode, data) for name, mode, data in BASE.cpio_members(
            subprocess.check_output(['rpm2cpio', str(paths[package['name']])]))}
        for item in package['files']:
            mode, data = entries[item['path']]
            require(stat.S_ISREG(mode) and stat.S_IMODE(mode) == 0o755, 'Native HTTP source ELF type/mode differs')
            path = root / 'lib' / PurePosixPath(item['path']).name; path.write_bytes(data); path.chmod(0o755)
            BASE.inspect_elf(path, item, policy['architectures'][arch])
            name = str(PurePosixPath(item['path']).parent / item['soname'][0]); mode, target = entries[name]
            require(stat.S_ISLNK(mode) and target == path.name.encode(), 'Native HTTP source SONAME differs')
            (root / 'lib' / item['soname'][0]).symlink_to(path.name)
        item = package['licenses'][0]; mode, data = entries[item['path']]
        require(stat.S_ISREG(mode) and len(data) == item['size'] and hashlib.sha256(data).hexdigest() == item['sha256'],
                'Native HTTP source copyright/permission notice differs')
        (root / 'LICENSE.curl.txt').write_bytes(data); (root / 'NOTICE.txt').write_text(notice_text(policy), encoding='utf-8', newline='\n')
    for path in [output / 'rootfs', *list((output / 'rootfs').rglob('*'))]:
        if path.is_dir():
            path.chmod(0o755)
        elif path.is_file() and not path.is_symlink() and path.parent != root / 'lib':
            path.chmod(0o644)
    manifest = manifest_for_tree(root, policy, arch)
    write_json(root / 'provider-manifest.json', manifest); write_json(output / 'provider-manifest.json', manifest)
    (root / 'provider-manifest.json').chmod(0o644); (output / 'provider-manifest.json').chmod(0o644)
    validate_tree(root, policy, arch)
    validate_rootfs_shape(output / 'rootfs')
    return output, root, manifest


def companion_tar(output, arch):
    destination = output / f'{PACKAGE_NAME}-{VERSION}-linux-{arch}.tar.gz'
    with destination.open('xb') as stream, gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=BASE.EPOCH) as compressed:
        with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
            for path in [output / 'provider-manifest.json', output / 'rootfs', *sorted((output / 'rootfs').rglob('*'))]:
                info = archive.gettarinfo(str(path), arcname=path.relative_to(output).as_posix())
                info.uid = info.gid = 0; info.uname = info.gname = ''; info.mtime = BASE.EPOCH
                if info.isfile():
                    with path.open('rb') as incoming:
                        archive.addfile(info, incoming)
                else:
                    archive.addfile(info)
    return descriptor(destination)


def build_deb(output, arch, variant):
    from channel_packages import control
    stage = output / 'deb-package'; shutil.copytree(output / 'rootfs', stage, symlinks=True)
    notice = stage / 'usr/share/doc' / PACKAGE_NAME; notice.mkdir(parents=True)
    root = output / 'rootfs' / PROVIDER_ROOT.lstrip('/')
    for source, target in [('LICENSE.curl.txt', 'copyright'), ('NOTICE.txt', 'NOTICE.txt'), ('provider-manifest.json', 'provider-manifest.json')]:
        shutil.copyfile(root / source, notice / target)
    dependencies = [BASE.package_requirement('deb'), *load_policy()['stockDependencies'][variant]]
    dependencies = ['libc6 (>= 2.17)' if item == 'libc6' else item for item in dependencies]
    native = {'x64': 'amd64', 'aarch64': 'arm64'}[arch]
    control(stage, {'Package': PACKAGE_NAME, 'Version': VERSION + '-1', 'Architecture': native,
        'Maintainer': '.NET Dev contributors', 'Section': 'libs', 'Priority': 'optional',
        'Depends': ', '.join(dependencies), 'Description': 'Separate maintained Rocky-origin libcurl for Core3 native HTTP'})
    destination = output / f'{PACKAGE_NAME}_{VERSION}-1_{native}.deb'
    subprocess.run(['dpkg-deb', '--root-owner-group', '-Zxz', '-z6', '--build', stage, destination], check=True,
        stdout=subprocess.PIPE, env=dict(os.environ, SOURCE_DATE_EPOCH=str(BASE.EPOCH), TZ='UTC', LC_ALL='C'))
    return descriptor(destination)


def build_rpm(output, arch, variant):
    from channel_packages import deterministic_tar, rpm_build_directories, rpm_build_macros, run_rpmbuild
    stage = output / 'rpm-package'; shutil.copytree(output / 'rootfs', stage, symlinks=True)
    notice = stage / 'usr/share/licenses' / PACKAGE_NAME; notice.mkdir(parents=True)
    shutil.copyfile(stage / PROVIDER_ROOT.lstrip('/') / 'LICENSE.curl.txt', notice / 'COPYING')
    top = rpm_build_directories(output); deterministic_tar(stage, top / 'SOURCES/native-http.tar.gz')
    dependencies = [BASE.package_requirement('rpm', variant), *load_policy()['stockDependencies'][variant]]
    native = {'x64': 'x86_64', 'aarch64': 'aarch64'}[arch]; release = '1.cbot.' + variant.replace('-', '')
    spec = top / 'SPECS/native-http.spec'
    spec.write_text(rpm_build_macros() + f'''
Name: {PACKAGE_NAME}
Version: {VERSION}
Release: {release}
Summary: Separate maintained Rocky-origin libcurl for Core3 native HTTP
License: curl
URL: https://dotnetdev.kr/cbodotnet/
Source0: native-http.tar.gz
BuildArch: {native}
AutoReqProv: no
Requires: {', '.join(dependencies)}
%description
Project repackaging of the exact signed current Rocky Linux 8.10 curl library.
The unmodified SDK, stock libraries, and separate SSL/ICU provider remain separately owned.
%prep
%build
%install
mkdir -p "%{{buildroot}}"
tar -xzf "%{{SOURCE0}}" -C "%{{buildroot}}"
%files
%defattr(-,root,root,-)
{PROVIDER_ROOT}
%license /usr/share/licenses/{PACKAGE_NAME}/COPYING
''', encoding='utf-8', newline='\n')
    run_rpmbuild(spec, top, native)
    packages = list((top / 'RPMS').rglob('*.rpm')); require(len(packages) == 1, 'Native HTTP RPM output differs')
    destination = output / packages[0].name; shutil.copyfile(packages[0], destination)
    return descriptor(destination)


def arch_recipe(policy, arch='x64'):
    require(arch == 'x64', 'Arch native HTTP provider is admitted only for x64')
    package = policy['architectures'][arch]['packages'][0]; sources = [package, *policy['sources'], policy['key']]
    urls = '\n'.join('  ' + shlex.quote(item['url']) for item in sources)
    hashes = ' '.join(shlex.quote(item['sha256']) for item in sources)
    dependencies = ' '.join(shlex.quote(item) for item in [BASE.package_requirement('aur'), *policy['stockDependencies']['arch-rolling']])
    elf = PurePosixPath(package['files'][0]['path']).name
    return f'''# Separate current Rocky8 curl provider; no SDK binaries are included or rebuilt.
pkgname={PACKAGE_NAME}
pkgver={VERSION}
pkgrel=1
pkgdesc='Separately managed Rocky-origin curl for Core3 native HTTP'
arch=('x86_64')
url='https://dotnetdev.kr/cbodotnet/'
license=('curl')
depends=({dependencies})
makedepends=('rpm-tools' 'gnupg')
options=('!strip' '!debug' '!lto')
source=(
{urls}
  'NOTICE.txt' 'provider-manifest.json')
sha256sums=({hashes} '@NOTICE_SHA256@' '@MANIFEST_SHA256@')
noextract=({' '.join(shlex.quote(item['name']) for item in sources)})
prepare() {{
  local fpr
  fpr=$(gpg --batch --with-colons --show-keys {policy['key']['name']} | awk -F: '$1=="pub"{{primary=1;next}} primary&&$1=="fpr"{{print $10;primary=0}}')
  [[ "$fpr" == '{FINGERPRINT}' ]]
  mkdir -p "$srcdir/rpmdb"
  rpmdb --dbpath "$srcdir/rpmdb" --initdb
  rpmkeys --dbpath "$srcdir/rpmdb" --import {policy['key']['name']}
  local rpm
  for rpm in *.rpm; do rpmkeys --dbpath "$srcdir/rpmdb" --checksig "$rpm"; done
  mkdir -p libcurl-minimal
  bsdtar -xf {shlex.quote(package['name'])} -C libcurl-minimal
}}
package() {{
  local dest="$pkgdir{PROVIDER_ROOT}"
  install -Dm755 "$srcdir/libcurl-minimal/usr/lib64/{elf}" "$dest/lib/{elf}"
  ln -s {elf} "$dest/lib/libcurl.so.4"
  install -Dm644 "$srcdir/libcurl-minimal/usr/share/licenses/libcurl-minimal/COPYING" "$dest/LICENSE.curl.txt"
  install -Dm644 "$srcdir/libcurl-minimal/usr/share/licenses/libcurl-minimal/COPYING" "$pkgdir/usr/share/licenses/$pkgname/COPYING"
  install -Dm644 "$srcdir/NOTICE.txt" "$dest/NOTICE.txt"
  install -Dm644 "$srcdir/provider-manifest.json" "$dest/provider-manifest.json"
}}
'''


def arch_srcinfo(policy, notice_hash, manifest_hash):
    package = policy['architectures']['x64']['packages'][0]; sources = [package, *policy['sources'], policy['key']]
    lines = ['pkgbase = ' + PACKAGE_NAME]
    fields = [('pkgdesc', ['Separately managed Rocky-origin curl for Core3 native HTTP']), ('pkgver', [VERSION]),
        ('pkgrel', ['1']), ('url', ['https://dotnetdev.kr/cbodotnet/']), ('arch', ['x86_64']), ('license', ['curl']),
        ('makedepends', ['rpm-tools', 'gnupg']), ('depends', [BASE.package_requirement('aur'), *policy['stockDependencies']['arch-rolling']]),
        ('noextract', [item['name'] for item in sources]), ('options', ['!strip', '!debug', '!lto']),
        ('source', [*[item['url'] for item in sources], 'NOTICE.txt', 'provider-manifest.json']),
        ('sha256sums', [*[item['sha256'] for item in sources], notice_hash, manifest_hash])]
    for key, values in fields:
        lines.extend('\t' + key + ' = ' + value for value in values)
    return '\n'.join([*lines, '', 'pkgname = ' + PACKAGE_NAME, ''])


def build_provider(arch, output, cache=None, variant=None):
    require(variant is None or variant in {'ubuntu-24.04', 'debian-13', 'fedora-45', 'rocky-9.8', 'arch-rolling'},
            'Unknown native HTTP packaging variant')
    require(variant != 'arch-rolling' or arch == 'x64', 'Arch native HTTP delivery requires x64')
    output, root, manifest = stage_provider(arch, output, cache)
    result = dict(schemaVersion=1, providerRoot=PROVIDER_ROOT, architecture=arch, variant=variant,
                  policySha256=manifest['policySha256'], manifest=manifest, companion=companion_tar(output, arch), packages=[])
    if variant in {'ubuntu-24.04', 'debian-13'}:
        result['packages'] = [dict(**build_deb(output, arch, variant), kind=KIND, name=PACKAGE_NAME,
            version=VERSION + '-1', architecture={'x64': 'amd64', 'aarch64': 'arm64'}[arch])]
    elif variant in {'fedora-45', 'rocky-9.8'}:
        result['packages'] = [dict(**build_rpm(output, arch, variant), kind=KIND, name=PACKAGE_NAME,
            version=VERSION, release='1.cbot.' + variant.replace('-', ''), architecture={'x64': 'x86_64', 'aarch64': 'aarch64'}[arch])]
    elif variant == 'arch-rolling':
        for name in ('NOTICE.txt', 'provider-manifest.json'):
            shutil.copyfile(root / name, output / name)
        text = arch_recipe(load_policy()).replace('@NOTICE_SHA256@', digest(output / 'NOTICE.txt')).replace('@MANIFEST_SHA256@', digest(output / 'provider-manifest.json'))
        (output / 'PKGBUILD').write_text(text, encoding='utf-8', newline='\n')
        (output / '.SRCINFO').write_text(arch_srcinfo(load_policy(), digest(output / 'NOTICE.txt'), digest(output / 'provider-manifest.json')),
                                      encoding='utf-8', newline='\n')
        result.update(recipe=descriptor(output / 'PKGBUILD'), srcinfo=descriptor(output / '.SRCINFO'))
    write_json(output / 'provider-build.json', result)
    return result


def verified_build(path, plan, channel):
    require(required(plan), 'Only Core3 uses the separate native HTTP provider')
    path = Path(path).absolute()
    require(path.is_file() and not any(item.is_symlink() for item in [path, *path.parents]),
            'Ordinary prepared native HTTP build record required')
    record = json.loads(path.read_bytes()); arch = architecture(plan); policy = load_policy()
    require(record.get('schemaVersion') == 1 and record.get('providerRoot') == PROVIDER_ROOT
            and record.get('architecture') == arch and record.get('policySha256') == policy_hash(),
            'Prepared native HTTP provider identity differs')
    root = path.parent / 'rootfs' / PROVIDER_ROOT.lstrip('/'); validate_tree(root, policy, arch)
    validate_rootfs_shape(path.parent / 'rootfs')
    require(record.get('manifest') == json.loads((root / 'provider-manifest.json').read_bytes())
            == json.loads((path.parent / 'provider-manifest.json').read_bytes()), 'Prepared native HTTP manifest differs')
    require(channel in {'deb', 'rpm', 'oci'}, 'Unknown native HTTP packaging channel')
    if channel in {'deb', 'rpm'}:
        require(record.get('variant') == plan['variant'] and len(record['packages']) == 1,
                'Prepared native HTTP package target differs')
        item = record['packages'][0]
        require(item.get('kind') == KIND and item.get('name') == PACKAGE_NAME
                and item.get('architecture') == plan['architecture'][channel]
                and item.get('version') == (VERSION + '-1' if channel == 'deb' else VERSION)
                and item['path'].endswith('.' + channel), 'Prepared native HTTP package identity differs')
        if channel == 'rpm':
            require(item.get('release') == '1.cbot.' + plan['variant'].replace('-', ''), 'Prepared native HTTP RPM release differs')
    for item in [record['companion'], *record['packages']]:
        require(re.fullmatch(r'[A-Za-z0-9._+-]+', item['path'])
                and descriptor(path.parent / item['path']) == {key: item[key] for key in ('path', 'size', 'sha256')},
                'Prepared native HTTP artifact bytes or filename differ')
    require(record['companion']['path'] == plan_policy(plan)['companionName'], 'Prepared native HTTP companion name differs')
    BASE.verify_companion(path.parent / record['companion']['path'], path.parent)
    return path.parent, record


def verify_companion(archive_path, prepared):
    prepared = Path(prepared)
    manifest = json.loads((prepared / 'provider-manifest.json').read_bytes())
    validate_tree(prepared / 'rootfs' / PROVIDER_ROOT.lstrip('/'), load_policy(), manifest['architecture'])
    validate_rootfs_shape(prepared / 'rootfs')
    BASE.verify_companion(archive_path, prepared)


def runtime_environment(plan, state, base_environment=None):
    if not required(plan):
        return dict(base_environment or {})
    state = BASE.read_state(state)
    require(state.get('providerRoot') == PROVIDER_ROOT and state.get('architecture') == architecture(plan)
            and state.get('policySha256') == policy_hash(), 'Native HTTP state differs from the selected SDK/policy')
    BASE.cpu_preflight(architecture(plan))
    return environment(plan, base_environment=base_environment)


def assert_unchanged(state):
    state = BASE.read_state(state)
    if state.get('required') is False:
        return {'status': 'not-required'}
    policy = load_policy(); arch = state['architecture']
    require(state.get('providerRoot') == PROVIDER_ROOT and state.get('policySha256') == policy_hash()
            and state.get('signingFingerprint') == FINGERPRINT, 'Native HTTP provider state identity changed')
    validate_tree(Path(PROVIDER_ROOT), policy, arch)
    rows = tree_inventory(Path(PROVIDER_ROOT), owners=True)
    require(rows == state['files'] and inventory_digest(rows) == state['treeSha256']
            and all(row['uid'] == 0 and row['gid'] == 0 for row in rows), 'Managed native HTTP provider changed')
    return dict(required=True, status='passed', providerRoot=PROVIDER_ROOT, architecture=arch, policySha256=policy_hash(),
        treeSha256=state['treeSha256'], signingFingerprint=FINGERPRINT, baseProviderId=policy['baseProvider']['providerId'],
        sourcePackages=policy['architectures'][arch]['packages'], sourceRpmPackages=policy['sources'],
        cpu=BASE.cpu_preflight(arch))


def provision(plan, delivery, user=None):
    if not required(plan):
        return {'required': False}
    require(os.name == 'posix' and os.geteuid() == 0 and Path('/.dockerenv').is_file(),
            'Native HTTP installation requires a disposable root container')
    arch = architecture(plan); require(platform.machine() == {'x64': 'x86_64', 'aarch64': 'aarch64'}[arch],
                                       'Native HTTP provider architecture differs')
    BASE.cpu_preflight(arch); variant = plan['variant']
    values = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    BASE.validate_operating_system(values, variant)
    BASE.validate_tree(Path(BASE.PROVIDER_ROOT), BASE.load_policy(), arch)
    delivery = Path(delivery); delivery.mkdir(parents=True, exist_ok=True)
    managed = Path(PROVIDER_ROOT)
    require(not any(path.is_symlink() for path in [managed, *managed.parents]), 'Managed native HTTP path contains a symlink')
    output = delivery / 'native-http-provider'
    if output.exists():
        parent, record = verified_build(output / 'provider-build.json', plan,
                                       'deb' if variant in {'ubuntu-24.04', 'debian-13'} else 'rpm' if variant in {'fedora-45', 'rocky-9.8'} else 'oci')
        require(parent == output and record['variant'] == variant, 'Retained native HTTP preparation target differs')
    else:
        record = build_provider(arch, output, cache=delivery / 'native-http-sources', variant=variant)
    source = output / 'rootfs' / PROVIDER_ROOT.lstrip('/')
    if variant == 'arch-rolling' and not record['packages']:
        # Retain a real authenticated preparation artifact even when an exact
        # provider is already installed. Building it must not reinstall or
        # replace that existing package or its database metadata.
        require(user is not None, 'Native HTTP Arch preparation requires an ordinary build user')
        import pwd
        account = pwd.getpwnam(user)
        policy = load_policy()
        for item in [*policy['architectures'][arch]['packages'], *policy['sources'], policy['key']]:
            cached = BASE.fetch(item, delivery / 'native-http-sources')
            destination = output / item['name']
            if destination.exists():
                require(destination.is_file() and not destination.is_symlink() and digest(destination) == item['sha256'],
                        'Retained Arch native HTTP source cache differs')
            else:
                shutil.copyfile(cached, destination)
        for path in [output, *output.rglob('*')]:
            os.chown(path, account.pw_uid, account.pw_gid, follow_symlinks=False)
        subprocess.run(['runuser', '-u', user, '--', 'makepkg', '--nodeps', '--noconfirm', '--cleanbuild'], cwd=output, check=True)
        packages = list(output.glob('*.pkg.tar.zst')); require(len(packages) == 1, 'Native HTTP Arch package output differs')
        original = policy['architectures'][arch]['packages'][0]['files'][0]
        member = PROVIDER_ROOT.lstrip('/') + '/lib/' + PurePosixPath(original['path']).name
        packaged = subprocess.check_output(['bsdtar', '-xOf', str(packages[0]), member])
        require(hashlib.sha256(packaged).hexdigest() == original['sha256'], 'Arch native HTTP package changed original ELF bytes')
        record['packages'] = [dict(**descriptor(packages[0]), kind=KIND, name=PACKAGE_NAME, version=VERSION + '-1', architecture='x86_64')]
        write_json(output / 'provider-build.json', record)
        (output / 'provider-build.json').chmod(0o644)
    if managed.exists():
        require(managed.is_dir() and tree_inventory(managed) == tree_inventory(source),
                'Existing native HTTP provider differs from authenticated original bytes')
    elif variant in {'ubuntu-24.04', 'debian-13'}:
        subprocess.run(['apt-get', 'install', '-y', str(output / record['packages'][0]['path'])], check=True)
    elif variant in {'fedora-45', 'rocky-9.8'}:
        subprocess.run(['dnf', '-y', 'install', str(output / record['packages'][0]['path']), '--setopt=localpkg_gpgcheck=0'], check=True)
    else:
        subprocess.run(['pacman', '-U', '--noconfirm', str(output / record['packages'][0]['path'])], check=True)
    require(tree_inventory(managed) == tree_inventory(source), 'Installed native HTTP provider bytes/modes/links differ')
    rows = tree_inventory(managed, owners=True)
    require(all(row['uid'] == 0 and row['gid'] == 0 for row in rows), 'Managed native HTTP provider must remain root-owned')
    policy = load_policy()
    state = dict(schemaVersion=1, required=True, providerRoot=PROVIDER_ROOT, architecture=arch, variant=variant,
        policySha256=policy_hash(), signingFingerprint=FINGERPRINT, baseProviderId=policy['baseProvider']['providerId'],
        packages=policy['architectures'][arch]['packages'], sourcePackages=policy['sources'], packageArtifact=record['packages'][0],
        files=rows, treeSha256=inventory_digest(rows), environment=environment(plan))
    path = delivery / 'native-http-state.json'; write_json(path, state); path.chmod(0o644)
    assert_unchanged(state)
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=('x64', 'aarch64'), required=True); parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path); parser.add_argument('--variant', choices=('ubuntu-24.04', 'debian-13', 'fedora-45', 'rocky-9.8', 'arch-rolling'))
    arguments = parser.parse_args()
    result = build_provider(arguments.arch, arguments.output, arguments.cache, arguments.variant)
    print(json.dumps({'companion': result['companion'], 'packages': result['packages']}, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
