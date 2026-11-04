#!/usr/bin/env python3
"""Package verified SDK bytes without modifying the SDK or system dotnet."""
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile

from distribution_commands import stage_commands, default_launcher_text
from distribution_contract import sha256_file

ROOT = Path(__file__).resolve().parents[1]
HOST_VERSION = '1.0.0-1'
SOURCE_DATE_EPOCH = '1700000000'


def require(value, message):
    if not value:
        raise ValueError(message)


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n', encoding='utf-8', newline='\n')


def descriptor(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'An ordinary package file is required')
    return {'path': path.name, 'size': path.stat().st_size, 'sha256': sha256_file(path)}


def sdk_tools():
    spec = importlib.util.spec_from_file_location('cbodotnet_sdk_tree', ROOT / 'scripts/test-distribution-coexistence.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_plan_archive(plan, archive):
    require(plan.get('status') == 'prepared-unqualified' and plan.get('publicationAllowed') is False,
            'A verified preparation plan is required')
    require(plan.get('architecture', {}).get('public') in {'x64', 'aarch64'}, 'Unknown architecture')
    version = plan.get('sdkVersion', '')
    require(re.fullmatch(r'[1-9][0-9]*\.[0-9]+\.[0-9]+', version), 'An exact SDK version is required')
    series = '.'.join(version.split('.')[:2])
    require(plan['package']['root'] == '/opt/cbodotnet/' + series
            and plan['package']['launcher'] == '/usr/bin/cbodotnet-' + series
            and plan['package']['name'] == 'cbodotnet-sdk-' + series, 'Package namespace collision')
    archive = Path(archive).absolute()
    require(archive.is_file() and not any(path.is_symlink() for path in [archive, *archive.parents]), 'Ordinary SDK archive required')
    require(archive.name == plan['sdk']['name'] and archive.stat().st_size == plan['sdk']['size']
            and sha256_file(archive) == plan['sdk']['sha256'], 'Qualified SDK archive changed')
    return archive


def fresh_output(output):
    output = Path(output).absolute()
    require(output != Path('/') and output.parent.is_dir() and not output.exists()
            and not any(path.is_symlink() for path in [output, *output.parents]), 'Use a fresh ordinary output directory')
    output.mkdir(mode=0o755)
    return output


def stage_payload(plan, archive, output, mode='package'):
    archive = verify_plan_archive(plan, archive)
    require(mode in {'package', 'oci'}, 'Unknown staging mode')
    output = fresh_output(output)
    rootfs = output / 'rootfs'
    sdk = rootfs / plan['package']['root'].lstrip('/')
    sdk.parent.mkdir(parents=True)
    tools = sdk_tools()
    tools.extract_sdk(archive, sdk)
    require((sdk / 'dotnet').is_file() and not (sdk / 'dotnet').is_symlink()
            and os.access(sdk / 'dotnet', os.X_OK), 'SDK archive lacks executable host')
    payload = tools.snapshot(sdk)
    for name in plan['licensePaths']:
        path = sdk / name
        require(path.is_file() and not path.is_symlink(), 'SDK license/notice is missing: ' + name)
    for name in plan['additionalDirectories']:
        relative = PurePosixPath(name)
        require(str(relative) == name and not relative.is_absolute() and '..' not in relative.parts
                and name not in {'', '.'}, 'Unsafe added metadata directory')
        path = sdk / name
        require(not path.exists() and not path.is_symlink() and path.parent.is_dir(), 'Metadata would overlay qualified SDK')
        path.mkdir(mode=0o755)
    commands = stage_commands(rootfs, plan, mode=mode)
    package_doc = rootfs / 'usr/share/doc' / plan['package']['name']
    package_doc.mkdir(parents=True)
    write_json(package_doc / 'distribution.json', plan)
    for name in plan['licensePaths']:
        shutil.copyfile(sdk / name, package_doc / name)
        (package_doc / name).chmod(0o644)
    current = tools.snapshot(sdk)
    for name, expected in payload.items():
        require(current.get(name) == expected, 'Packaging changed qualified SDK member: ' + name)
    require(set(current) - set(payload) == set(plan['additionalDirectories']), 'Unaccounted SDK additions')
    write_json(output / 'plan.json', plan)
    write_json(output / 'command-inventory.json', commands)
    write_json(output / 'payload-inventory.json', payload)
    return output, rootfs, commands, payload


def copy_tree(source, destination):
    # Same-filesystem hard links avoid duplicating immutable SDK bytes. Builders
    # below never run stripping, post-install rewriting or in-place transforms.
    shutil.copytree(source, destination, symlinks=True, copy_function=os.link)


def control(root, fields):
    directory = root / 'DEBIAN'
    directory.mkdir()
    (directory / 'control').write_text(''.join(key + ': ' + str(value) + '\n' for key, value in fields.items()), encoding='utf-8')
    sums = []
    for path in sorted(root.rglob('*')):
        if path.is_file() and not path.is_symlink() and directory not in path.parents:
            sums.append(hashlib.md5(path.read_bytes()).hexdigest() + '  ' + path.relative_to(root).as_posix() + '\n')
    (directory / 'md5sums').write_text(''.join(sums), encoding='ascii')


def compatibility_input(plan, prepared, channel):
    from legacy_compat import required, verified_build
    if required(plan):
        require(prepared is not None, 'Legacy SDK packaging requires an explicit authenticated compatibility build')
        return verified_build(prepared, plan, channel)
    require(prepared is None, 'Modern SDK packaging does not accept a legacy compatibility provider')
    return None


def attach_compatibility(result, output, prepared):
    if prepared is None:
        return
    parent, record = prepared
    for item in [*record['packages'], record['companion']]:
        destination = output / item['path']
        require(not destination.exists(), 'Compatibility artifact would overwrite another package')
        shutil.copyfile(parent / item['path'], destination)
    result['packages'].append(record['packages'][0])
    result['compatibilityAsset'] = record['companion']
    result['compatibility'] = {'required': True, 'providerRoot': record['providerRoot'],
                               'policySha256': record['policySha256'], 'architecture': record['architecture']}


def native_http_input(plan, prepared, channel):
    if plan['sdkVersion'].startswith(('3.0.', '3.1.')):
        import legacy_curl
        require(prepared is not None, 'Core3 packaging requires an explicit authenticated native HTTP build')
        return legacy_curl.verified_build(prepared, plan, channel)
    require(prepared is None, 'Only Core3 packaging accepts the native HTTP provider')
    return None


def attach_native_http(result, output, prepared):
    if prepared is None:
        return
    parent, record = prepared
    for item in [*(record['packages'] if 'packages' in result else []), record['companion']]:
        destination = output / item['path']
        require(not destination.exists(), 'Native HTTP artifact would overwrite another output')
        shutil.copyfile(parent / item['path'], destination)
    if 'packages' in result:
        require(len(record['packages']) == 1, 'A standalone native HTTP package is required')
        result['packages'].append(record['packages'][0])
    result['nativeHttpCompatibilityAsset'] = record['companion']
    result['nativeHttpCompatibility'] = {'required': True, 'providerRoot': record['providerRoot'],
        'policySha256': record['policySha256'], 'architecture': record['architecture']}


def sdk_dependencies(plan, channel):
    from legacy_compat import PACKAGE_NAME, package_requirement
    result = list(plan.get({'rpm': 'rpmDependencies', 'aur': 'aurDependencies'}.get(channel, 'dependencies'), []))
    result = [package_requirement(channel, plan.get('variant')) if item == PACKAGE_NAME else item for item in result]
    if plan['sdkVersion'].startswith(('3.0.', '3.1.')):
        import legacy_curl
        result = [legacy_curl.package_requirement(channel, plan.get('variant')) if item == legacy_curl.PACKAGE_NAME else item for item in result]
    return result


def build_deb(plan, archive, output, compatibility_build=None, native_http_build=None):
    require(plan['channel'] == 'deb', 'Debian builder requires an admitted Debian plan')
    prepared = compatibility_input(plan, compatibility_build, 'deb')
    native_http = native_http_input(plan, native_http_build, 'deb')
    output, rootfs, commands, payload = stage_payload(plan, archive, output)
    sdk_stage = output / 'sdk-package'
    copy_tree(rootfs, sdk_stage)
    (sdk_stage / 'usr/bin/cbodotnet').unlink()
    host_stage = output / 'host-package'
    (host_stage / 'usr/bin').mkdir(parents=True)
    shutil.copyfile(rootfs / 'usr/bin/cbodotnet', host_stage / 'usr/bin/cbodotnet')
    (host_stage / 'usr/bin/cbodotnet').chmod(0o755)
    host_doc = host_stage / 'usr/share/doc/cbodotnet-host'
    host_doc.mkdir(parents=True)
    shutil.copyfile(ROOT / 'LICENSE', host_doc / 'copyright')
    common = {'Section': 'devel', 'Priority': 'optional', 'Maintainer': '.NET Dev contributors',
              'Homepage': 'https://dotnetdev.kr/cbodotnet/'}
    dependencies = sdk_dependencies(plan, 'deb')
    control(host_stage, {'Package': 'cbodotnet-host', 'Version': HOST_VERSION, 'Architecture': 'all', **common,
                         'Description': 'Shared command selector for Community Build of .NET'})
    control(sdk_stage, {'Package': plan['package']['name'], 'Version': plan['package']['version'],
                        'Architecture': plan['architecture']['deb'], **common,
                        'Depends': ', '.join(['cbodotnet-host (>= ' + HOST_VERSION + ')', *dependencies]),
                        'Description': 'Community Build of .NET (built by .NET Dev) SDK ' + plan['sdkVersion']})
    environment = dict(os.environ, SOURCE_DATE_EPOCH=SOURCE_DATE_EPOCH, TZ='UTC', LC_ALL='C')
    packages = []
    for kind, tree, name, version, arch in [
            ('host', host_stage, 'cbodotnet-host', HOST_VERSION, 'all'),
            ('sdk', sdk_stage, plan['package']['name'], plan['package']['version'], plan['architecture']['deb'])]:
        path = output / f'{name}_{version}_{arch}.deb'
        subprocess.run(['dpkg-deb', '--root-owner-group', '-Zxz', '-z6', '--build', str(tree), str(path)],
                       check=True, env=environment, stdout=subprocess.PIPE)
        packages.append({**descriptor(path), 'kind': kind, 'name': name, 'version': version, 'architecture': arch})
    # dpkg-deb must preserve every qualified member; inspect actual package bytes.
    verification = output / 'deb-verified'
    subprocess.run(['dpkg-deb', '--extract', str(output / packages[1]['path']), str(verification)], check=True)
    require(sdk_tools().snapshot(verification / plan['package']['root'].lstrip('/'))
            == sdk_tools().snapshot(rootfs / plan['package']['root'].lstrip('/')), 'Debian package changed SDK bytes or modes')
    result = {'schemaVersion': 1, 'channel': 'deb', 'plan': plan, 'packages': packages,
              'commandInventory': commands, 'payloadPreserved': True, 'publicationQualified': False}
    attach_compatibility(result, output, prepared)
    attach_native_http(result, output, native_http)
    write_json(output / 'package-build.json', result)
    return result


def oci_labels(plan):
    """Describe the qualified SDK and retained notices without flattening licenses."""
    documentation = 'https://github.com/dotnetdev-kr/cbodotnet/blob/main/docs/oci-delivery.md'
    root = plan['package']['root']
    return {'org.opencontainers.image.title': plan['branding']['displayName'],
            'org.opencontainers.image.source': 'https://github.com/dotnetdev-kr/cbodotnet',
            'org.opencontainers.image.version': plan['sdkVersion'],
            'org.opencontainers.image.url': 'https://github.com/dotnetdev-kr/cbodotnet/releases/tag/' + plan['sourceReleaseTag'],
            'org.opencontainers.image.documentation': documentation,
            'org.opencontainers.image.licenses': 'MIT AND LicenseRef-Dotnet-ThirdPartyNotices',
            'kr.dotnetdev.cbodotnet.license.path': root + '/LICENSE.txt',
            'kr.dotnetdev.cbodotnet.notices.path': root + '/ThirdPartyNotices.txt',
            'kr.dotnetdev.cbodotnet.notices.url': documentation + '#licenses-and-notices',
            'kr.dotnetdev.cbodotnet.source.url': plan['source']['url'],
            'kr.dotnetdev.cbodotnet.source.sha256': plan['source']['sha256'],
            'kr.dotnetdev.cbodotnet.evidence.url': plan['evidence']['url'],
            'kr.dotnetdev.cbodotnet.evidence.sha256': plan['evidence']['sha256'],
            'kr.dotnetdev.cbodotnet.sdk.url': plan['sdk']['url'],
            'kr.dotnetdev.cbodotnet.sdk.sha256': plan['sdk']['sha256'],
            'kr.dotnetdev.cbodotnet.manifest.url': plan['sourceManifestUrl'],
            'kr.dotnetdev.cbodotnet.manifest.sha256': plan['sourceManifestSha256'],
            'kr.dotnetdev.cbodotnet.package.revision': str(plan['packageRevision'])}


def build_oci_context(plan, archive, output, base_image, compatibility_build=None, native_http_build=None):
    require(plan['channel'] == 'oci', 'OCI builder requires an admitted OCI plan')
    require(isinstance(base_image, str) and re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}', base_image),
            'OCI base must be pinned by SHA-256 digest')
    require(plan['variant'] == 'debian-13', 'OCI runtime template is qualified only for the Debian 13 candidate')
    prepared = compatibility_input(plan, compatibility_build, 'oci')
    native_http = native_http_input(plan, native_http_build, 'oci')
    output, rootfs, commands, payload = stage_payload(plan, archive, output, mode='oci')
    wrapper_license_path = '/usr/share/licenses/cbodotnet-host/LICENSE'
    wrapper_license = rootfs / wrapper_license_path.lstrip('/')
    wrapper_license.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / 'LICENSE', wrapper_license)
    wrapper_license.chmod(0o644)
    if prepared is not None:
        parent, provider = prepared
        provider_root = rootfs / provider['providerRoot'].lstrip('/')
        provider_root.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(parent / 'rootfs' / provider['providerRoot'].lstrip('/'), provider_root, symlinks=True)
    if native_http is not None:
        native_parent, native_provider = native_http
        native_root = rootfs / native_provider['providerRoot'].lstrip('/')
        native_root.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(native_parent / 'rootfs' / native_provider['providerRoot'].lstrip('/'), native_root, symlinks=True)
    shutil.copyfile(ROOT / 'containers/sdk-runtime.Containerfile', output / 'Containerfile')
    labels = oci_labels(plan)
    result = {'schemaVersion': 1, 'channel': 'oci', 'plan': plan, 'baseImage': base_image,
              'context': '.', 'containerfile': 'Containerfile', 'labels': labels,
              'buildArgs': {'BASE_IMAGE': base_image, 'SDK_SERIES': '.'.join(plan['sdkVersion'].split('.')[:2])},
              'wrapperLicense': {'path': wrapper_license_path, 'sha256': sha256_file(wrapper_license)},
              'commandInventory': commands, 'payloadPreserved': True, 'publicationQualified': False}
    if prepared is not None:
        result['compatibility'] = {'required': True, 'providerRoot': provider['providerRoot'],
                                   'policySha256': provider['policySha256'], 'architecture': provider['architecture']}
        result['compatibilityAsset'] = provider['companion']
        shutil.copyfile(parent / provider['companion']['path'], output / provider['companion']['path'])
    attach_native_http(result, output, native_http)
    write_json(output / 'package-build.json', result)
    return result


def render_rpm_spec(plan, source_name='payload.tar.gz'):
    """Render an executable RPM adapter; caller must supply admitted RPM evidence."""
    require(plan['channel'] == 'rpm', 'RPM spec requires an admitted RPM plan')
    require(re.fullmatch(r'[A-Za-z0-9._-]+', source_name), 'Unsafe RPM source filename')
    arch = plan['architecture']['rpm']
    name = plan['package']['name']
    version = plan['sdkVersion']
    release = rpm_release(plan)
    root = plan['package']['root']
    launcher = plan['package']['launcher']
    dependencies = plan.get('rpmDependencies')
    require(isinstance(dependencies, list) and dependencies and all(re.fullmatch(r'[A-Za-z0-9_().+<>= -]+', item) for item in dependencies),
            'Reviewed RPM-specific dependencies are required')
    dependencies = sdk_dependencies(plan, 'rpm')
    return rpm_build_macros() + f'''
Name: {name}
Version: {version}
Release: {release}
Summary: Community Build of .NET SDK built by .NET Dev
License: LicenseRef-Dotnet-SDK-ThirdParty
URL: https://dotnetdev.kr/cbodotnet/
Source0: {source_name}
BuildArch: {arch}
AutoReqProv: no
Requires: cbodotnet-host >= {HOST_VERSION}
Requires: {', '.join(dependencies)}

%description
Qualified Community Build of .NET SDK. Original SDK licenses and notices are
retained under {root}; this package preserves all qualified payload bytes.

%prep

%build

%install
mkdir -p "%{{buildroot}}"
tar -xzf "%{{SOURCE0}}" -C "%{{buildroot}}"

%files
%defattr(-,root,root,-)
{root}
{launcher}
/usr/share/doc/{name}
'''


def rpm_release(plan, shared=False):
    """Different distro dependency graphs must never share one RPM NEVRA."""
    variant = plan.get('variant', '')
    require(isinstance(variant, str) and re.fullmatch(r'[a-z][a-z0-9]*-[1-9][0-9]*(?:\.[0-9]+)?', variant),
            'A reviewed RPM distribution/version variant is required')
    revision = HOST_VERSION.rsplit('-', 1)[1] if shared else plan.get('packageRevision')
    require((type(revision) is int and revision > 0) or (shared and re.fullmatch(r'[1-9][0-9]*', revision)),
            'RPM packaging revision must be positive')
    release = str(revision) + '.cbot.' + variant.replace('-', '')
    if not shared and 'rpmRelease' in plan.get('package', {}):
        require(plan['package']['rpmRelease'] == release, 'RPM release differs from canonical distro identity')
    return release


def rpm_build_macros():
    # RPM 6 defaults to format v6. Explicit v4 remains installable on Rocky's
    # RPM 4 and allows one protected signer to handle both admitted variants.
    return '''%global _rpmformat 4
%global debug_package %{nil}
%global __spec_install_post %{nil}
%global __os_install_post %{nil}
%global _build_id_links none
%global _enable_debug_packages 0
%global _openpgp_autosign_id %{nil}
%global _buildhost reproducible.cbodotnet.invalid
%global use_source_date_epoch_as_buildtime 1
%global clamp_mtime_to_source_date_epoch 1
%global build_mtime_policy clamp_to_source_date_epoch
%global _binary_payload w6.xzdio
%global _binary_filedigest_algorithm 8
'''


def render_rpm_host_spec(plan):
    version = HOST_VERSION.rsplit('-', 1)[0]
    release = rpm_release(plan, shared=True)
    # RPM records native compiler flags even for a shell-only noarch package.
    # The selector compiles nothing, so omit that irrelevant native header.
    return rpm_build_macros() + '%global optflags %{nil}\n' + f'''
Name: cbodotnet-host
Version: {version}
Release: {release}
Summary: Shared command selector for Community Build of .NET
License: MIT
URL: https://dotnetdev.kr/cbodotnet/
Source0: host.tar.gz
BuildArch: noarch
AutoReqProv: no
Requires: /bin/sh
%description
Shared cbodotnet SDK selector. Does not replace system dotnet.
%prep
%build
%install
mkdir -p "%{{buildroot}}"
tar -xzf "%{{SOURCE0}}" -C "%{{buildroot}}"
%files
%defattr(-,root,root,-)
/usr/bin/cbodotnet
%dir /usr/share/licenses/cbodotnet-host
%license /usr/share/licenses/cbodotnet-host/LICENSE
'''


def render_aur(plan):
    require(plan['channel'] == 'aur' and plan['architecture']['public'] == 'x64', 'Initial AUR adapter requires admitted x64 plan')
    name = plan['package']['name'] + '-bin'
    version, revision = plan['sdkVersion'], plan['packageRevision']
    require(plan.get('aurDependencies'), 'Reviewed Arch-specific dependencies are required')
    require(all(re.fullmatch(r'[A-Za-z0-9@._+-]+', item) for item in plan['aurDependencies']), 'Unsafe AUR dependency')
    dependencies = sdk_dependencies(plan, 'aur')
    depends = ' '.join("'" + item + "'" for item in dependencies)
    source = plan['sdk']['url']
    require(source.startswith('https://github.com/dotnetdev-kr/cbodotnet/releases/download/'), 'Unexpected AUR SDK URL')
    launcher = 'cbodotnet-' + '.'.join(version.split('.')[:2])
    added_directories = []
    for directory in plan['additionalDirectories']:
        require(re.fullmatch(r'[A-Za-z0-9._/-]+', directory) and '..' not in PurePosixPath(directory).parts
                and not directory.startswith('/') and str(PurePosixPath(directory)) == directory,
                'Unsafe AUR metadata directory')
        added_directories.append('  install -dm755 "$pkgdir' + plan['package']['root'] + '/' + directory + '"')
    metadata_commands = '\n'.join(added_directories)
    text = f'''# Qualified binary SDK; source provenance is retained in distribution.json.
pkgname={name}
pkgver={version}
pkgrel={revision}
pkgdesc='Community Build of .NET (built by .NET Dev) SDK'
arch=('x86_64')
url='https://dotnetdev.kr/cbodotnet/'
license=('MIT' 'Apache-2.0')
depends=({depends} 'cbodotnet-host')
options=('!strip' '!debug' '!lto')
source_x86_64=('{source}')
sha256sums_x86_64=('{plan['sdk']['sha256']}')
noextract=('{plan['sdk']['name']}')

package() {{
  install -d "$pkgdir{plan['package']['root']}" "$pkgdir/usr/bin"
  bsdtar -xf "$srcdir/{plan['sdk']['name']}" -C "$pkgdir{plan['package']['root']}"
{metadata_commands}
  install -m755 "$startdir/{launcher}" "$pkgdir/usr/bin/{launcher}"
}}
'''
    srcinfo = f'pkgbase = {name}\n\tpkgdesc = Community Build of .NET (built by .NET Dev) SDK\n\tpkgver = {version}\n\tpkgrel = {revision}\n\turl = https://dotnetdev.kr/cbodotnet/\n\tarch = x86_64\n\tlicense = MIT\n\tlicense = Apache-2.0\n'
    srcinfo += ''.join('\tdepends = ' + item + '\n' for item in [*dependencies, 'cbodotnet-host'])
    srcinfo += '\toptions = !strip\n\toptions = !debug\n\toptions = !lto\n'
    srcinfo += f'\tsource_x86_64 = {source}\n\tsha256sums_x86_64 = {plan["sdk"]["sha256"]}\n\tnoextract = {plan["sdk"]["name"]}\n\npkgname = {name}\n'
    return text, srcinfo


def deterministic_tar(source, destination, excluded_suffixes=()):
    """Produce a portable root-owned archive containing one ordinary staged tree."""
    source, destination = Path(source), Path(destination)
    with destination.open('xb') as stream:
        with gzip.GzipFile(fileobj=stream, filename='', mode='wb', mtime=int(SOURCE_DATE_EPOCH)) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                for path in sorted(source.rglob('*')):
                    if destination == path or path.name.endswith(excluded_suffixes):
                        continue
                    info = archive.gettarinfo(str(path), arcname=path.relative_to(source).as_posix())
                    require(info.isfile() or info.isdir() or info.issym(), 'Unexpected staged archive member')
                    info.uid = info.gid = 0
                    info.uname = info.gname = 'root'
                    info.mtime = int(SOURCE_DATE_EPOCH)
                    if info.isfile():
                        with path.open('rb') as incoming:
                            archive.addfile(info, incoming)
                    else:
                        archive.addfile(info)
    return descriptor(destination)


def rpm_build_directories(output):
    top = output / 'rpmbuild'
    for name in ('BUILD', 'BUILDROOT', 'RPMS', 'SOURCES', 'SPECS', 'SRPMS'):
        (top / name).mkdir(parents=True)
    return top


def stage_common_rpm(plan, output, top):
    """The standalone check and SDK packager use exactly one selector payload."""
    tree = output / 'rpm-host-tree'
    (tree / 'usr/bin').mkdir(parents=True)
    command = tree / 'usr/bin/cbodotnet'
    command.write_text(default_launcher_text(), encoding='utf-8', newline='\n')
    command.chmod(0o755)
    (tree / 'usr/share/licenses/cbodotnet-host').mkdir(parents=True)
    license = tree / 'usr/share/licenses/cbodotnet-host/LICENSE'
    shutil.copyfile(ROOT / 'LICENSE', license)
    license.chmod(0o644)
    deterministic_tar(tree, top / 'SOURCES/host.tar.gz')
    spec = top / 'SPECS/host.spec'
    spec.write_text(render_rpm_host_spec(plan), encoding='utf-8')
    return tree, spec


def run_rpmbuild(spec, top, target):
    subprocess.run(['rpmbuild', '--define', '_topdir ' + str(top), '--target', target, '-bb', str(spec)],
                   check=True, env=dict(os.environ, SOURCE_DATE_EPOCH=SOURCE_DATE_EPOCH, TZ='UTC', LC_ALL='C'),
                   stdout=subprocess.PIPE)


def extract_rpm(package, destination):
    destination.mkdir()
    with subprocess.Popen(['rpm2cpio', str(package)], stdout=subprocess.PIPE) as producer:
        subprocess.run(['cpio', '--extract', '--make-directories', '--no-absolute-filenames', '--no-preserve-owner', '--quiet'],
                       cwd=destination, stdin=producer.stdout, check=True)
        producer.stdout.close()
        require(producer.wait() == 0, 'RPM extraction failed')


def build_common_rpm(variant, output):
    """Build the exact noarch selector without receiving or extracting an SDK."""
    plan = {'channel': 'rpm', 'variant': variant}
    release = rpm_release(plan, shared=True)
    require(re.fullmatch(r'[A-Za-z0-9_./-]+', str(Path(output).absolute())), 'RPM build directory must use a shell-safe path')
    output = fresh_output(output)
    top = rpm_build_directories(output)
    tree, spec = stage_common_rpm(plan, output, top)
    run_rpmbuild(spec, top, 'noarch')
    packages = list((top / 'RPMS').rglob('*.rpm'))
    require(len(packages) == 1, 'Common builder must produce exactly one noarch RPM')
    target = output / packages[0].name
    shutil.copyfile(packages[0], target)
    version = HOST_VERSION.rsplit('-', 1)[0]
    identity = subprocess.check_output(['rpm', '--query', '--package', '--queryformat',
        '%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n', str(target)]).decode().splitlines()
    require(identity == ['cbodotnet-host', version, release, 'noarch'], 'Common RPM has another package identity')
    extract_rpm(target, output / 'rpm-host-verified')
    require(sdk_tools().snapshot(output / 'rpm-host-verified') == sdk_tools().snapshot(tree),
            'RPM shared package changed selector bytes or modes')
    row = dict(descriptor(target), kind='host', name='cbodotnet-host', version=version, release=release, architecture='noarch')
    result = dict(schemaVersion=1, channel='rpm', variant=variant, packages=[row], payloadPreserved=True, publicationQualified=False)
    write_json(output / 'common-package-build.json', result)
    return result


def build_rpm(plan, archive, output, compatibility_build=None, native_http_build=None):
    """Build real RPM payloads only after a target-specific plan is admitted."""
    require(plan['channel'] == 'rpm', 'RPM builder requires an admitted RPM plan')
    prepared = compatibility_input(plan, compatibility_build, 'rpm')
    native_http = native_http_input(plan, native_http_build, 'rpm')
    require(re.fullmatch(r'[A-Za-z0-9_./-]+', str(Path(output).absolute())), 'RPM build directory must use a shell-safe path')
    spec = render_rpm_spec(plan)
    output, rootfs, commands, payload = stage_payload(plan, archive, output)
    top = rpm_build_directories(output)
    sdk_tree = output / 'rpm-sdk-tree'
    copy_tree(rootfs, sdk_tree)
    (sdk_tree / 'usr/bin/cbodotnet').unlink()
    deterministic_tar(sdk_tree, top / 'SOURCES/payload.tar.gz')
    sdk_spec = top / 'SPECS/sdk.spec'
    sdk_spec.write_text(spec, encoding='utf-8')
    host_tree, host_spec = stage_common_rpm(plan, output, top)
    require((host_tree / 'usr/bin/cbodotnet').read_bytes() == (rootfs / 'usr/bin/cbodotnet').read_bytes(),
            'Shared RPM selector differs from the generated command inventory')
    environment = dict(os.environ, SOURCE_DATE_EPOCH=SOURCE_DATE_EPOCH, TZ='UTC', LC_ALL='C')
    for path in (host_spec, sdk_spec):
        target = 'noarch' if path == host_spec else plan['architecture']['rpm']
        run_rpmbuild(path, top, target)
    packages = []
    for path in sorted((top / 'RPMS').rglob('*.rpm')):
        target = output / path.name
        shutil.copyfile(path, target)
        values = subprocess.check_output(['rpm', '--query', '--package', '--queryformat',
                                          '%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n', str(target)], env=environment).decode().splitlines()
        require(len(values) == 4, 'RPM package has an invalid identity')
        name, version, release, architecture = values
        kind = 'host' if name == 'cbodotnet-host' else 'sdk'
        require(name == ('cbodotnet-host' if kind == 'host' else plan['package']['name'])
                and release == rpm_release(plan, shared=kind == 'host')
                and architecture == ('noarch' if kind == 'host' else plan['architecture']['rpm']),
                'RPM package differs from the reviewed distro identity')
        packages.append({**descriptor(target), 'kind': kind, 'name': name, 'version': version,
                         'release': release, 'architecture': architecture})
    require(len(packages) == 2, 'RPM builder did not produce exactly the SDK and shared host packages')
    verification = output / 'rpm-verified'
    for item in packages:
        destination = verification if item['kind'] == 'sdk' else output / 'rpm-host-verified'
        extract_rpm(output / item['path'], destination)
    require(sdk_tools().snapshot(verification / plan['package']['root'].lstrip('/'))
            == sdk_tools().snapshot(rootfs / plan['package']['root'].lstrip('/')), 'RPM package changed SDK bytes or modes')
    require(sdk_tools().snapshot(output / 'rpm-host-verified') == sdk_tools().snapshot(host_tree),
            'RPM shared package changed selector bytes or modes')
    result = {'schemaVersion': 1, 'channel': 'rpm', 'plan': plan, 'packages': packages,
              'commandInventory': commands, 'payloadPreserved': True, 'publicationQualified': False}
    attach_compatibility(result, output, prepared)
    attach_native_http(result, output, native_http)
    write_json(output / 'package-build.json', result)
    return result


def build_aur_recipe(plan, archive, output):
    require(plan['channel'] == 'aur', 'AUR preparation requires an admitted Arch plan')
    output, rootfs, commands, payload = stage_payload(plan, archive, output)
    text, srcinfo = render_aur(plan)
    (output / 'PKGBUILD').write_text(text, encoding='utf-8')
    (output / '.SRCINFO').write_text(srcinfo, encoding='utf-8')
    launcher = Path(plan['package']['launcher']).name
    shutil.copyfile(rootfs / plan['package']['launcher'].lstrip('/'), output / launcher)
    (output / launcher).chmod(0o755)
    # Local launcher and provenance inputs are also pinned by makepkg source
    # verification; a maintainer must not edit them independently of the recipe.
    shutil.copyfile(output / 'plan.json', output / 'distribution.json')
    local_names = [launcher, 'distribution.json']
    local_sums = [sha256_file(output / name) for name in local_names]
    additions = 'source=(' + ' '.join("'" + name + "'" for name in local_names) + ')\n'
    additions += 'sha256sums=(' + ' '.join("'" + value + "'" for value in local_sums) + ')\n'
    text = text.replace('\npackage() {', '\n' + additions + '\npackage() {')
    text = text.replace('license=(\'MIT\' \'Apache-2.0\')', "license=('custom')")
    text = text.replace('\n}', '\n  install -d "$pkgdir/usr/share/doc/' + plan['package']['name'] + '"\n'
                        '  install -m644 "$srcdir/distribution.json" "$pkgdir/usr/share/doc/' + plan['package']['name'] + '/distribution.json"\n}')
    srcinfo = srcinfo.replace('\tlicense = MIT\n\tlicense = Apache-2.0\n', '\tlicense = custom\n')
    marker = '\npkgname = '
    extra = ''.join('\tsource = ' + name + '\n' for name in local_names)
    extra += ''.join('\tsha256sums = ' + value + '\n' for value in local_sums)
    srcinfo = srcinfo.replace(marker, extra + marker)
    (output / 'PKGBUILD').write_text(text, encoding='utf-8')
    (output / '.SRCINFO').write_text(srcinfo, encoding='utf-8')
    result = {'schemaVersion': 1, 'channel': 'aur', 'plan': plan, 'recipe': descriptor(output / 'PKGBUILD'),
              'srcinfo': descriptor(output / '.SRCINFO'), 'commandInventory': commands,
              'publicationQualified': False, 'aurSubmissionPerformed': False}
    write_json(output / 'package-build.json', result)
    return result


def gpg_command(home, *arguments):
    command = ['gpg', '--batch', '--yes', '--pinentry-mode', 'loopback', '--passphrase', '']
    if home is not None:
        command += ['--homedir', str(Path(home).absolute())]
    return [*command, *arguments]


def validate_package_builds(paths, channel):
    builds = []
    for path in paths:
        path = Path(path).absolute()
        require(path.is_file() and not any(item.is_symlink() for item in [path, *path.parents]), 'Ordinary package build record required')
        build = json.loads(path.read_bytes())
        require(build.get('schemaVersion') == 1 and build.get('channel') == channel
                and build.get('payloadPreserved') is True, 'Unverified package build record')
        packages = build.get('packages', [])
        kinds = {item.get('kind') for item in packages}
        require((len(packages) == 2 and kinds == {'host', 'sdk'})
                or (len(packages) == 3 and kinds == {'host', 'sdk', 'compatibility'})
                or (len(packages) == 4 and kinds == {'host', 'sdk', 'compatibility', 'native-http-compatibility'}),
                'SDK/shared host and optional separate compatibility packages are required')
        native_http_required = build['plan']['sdkVersion'].startswith(('3.0.', '3.1.'))
        require(('native-http-compatibility' in kinds) == native_http_required,
                'Core3 requires its separately owned native HTTP compatibility package')
        if 'compatibility' in kinds:
            from legacy_compat import required, PACKAGE_NAME, VERSION, PROVIDER_ROOT, POLICY
            require(required(build['plan']) and build.get('compatibility', {}).get('required') is True
                    and build['compatibility'].get('providerRoot') == PROVIDER_ROOT
                    and build['compatibility'].get('policySha256') == hashlib.sha256(POLICY.read_text().replace('\r\n', '\n').encode()).hexdigest(),
                    'Unreviewed compatibility package attachment')
            item = next(row for row in packages if row['kind'] == 'compatibility')
            require(item.get('name') == PACKAGE_NAME and item.get('architecture') == build['plan']['architecture'][channel]
                    and item.get('version') == (VERSION + '-1' if channel == 'deb' else VERSION),
                    'Compatibility package identity differs')
            if channel == 'rpm':
                require(item.get('release') == '1.cbot.' + build['plan']['variant'].replace('-', ''), 'Compatibility RPM variant differs')
            companion = build.get('compatibilityAsset', {})
            require(re.fullmatch(r'[A-Za-z0-9._+-]+', companion.get('path', ''))
                    and descriptor(path.parent / companion['path']) == {key: companion[key] for key in ('path', 'size', 'sha256')},
                    'Compatibility companion bytes differ')
        if native_http_required:
            import legacy_curl
            policy = legacy_curl.plan_policy(build['plan'])
            attachment = build.get('nativeHttpCompatibility', {})
            require(attachment.get('required') is True and attachment.get('providerRoot') == policy['root']
                    and attachment.get('policySha256') == policy['policySha256'], 'Native HTTP provider attachment differs')
            item = next(row for row in packages if row['kind'] == legacy_curl.KIND)
            require(item.get('name') == legacy_curl.PACKAGE_NAME
                    and item.get('architecture') == build['plan']['architecture'][channel]
                    and item.get('version') == (legacy_curl.VERSION + '-1' if channel == 'deb' else legacy_curl.VERSION),
                    'Native HTTP package identity differs')
            if channel == 'rpm':
                require(item.get('release') == '1.cbot.' + build['plan']['variant'].replace('-', ''), 'Native HTTP RPM variant differs')
            companion = build.get('nativeHttpCompatibilityAsset', {})
            require(companion.get('path') == policy['companionName']
                    and descriptor(path.parent / companion['path']) == {key: companion[key] for key in ('path', 'size', 'sha256')},
                    'Native HTTP companion bytes differ')
        for item in build['packages']:
            require(re.fullmatch(r'[A-Za-z0-9._+-]+', item['path']), 'Unsafe package filename')
            package = path.parent / item['path']
            require(descriptor(package) == {key: item[key] for key in ('path', 'size', 'sha256')}, 'Package bytes differ from build record')
        builds.append((path.parent, build))
    require(builds, 'At least one package build is required')
    first = builds[0][1]['plan']
    require(all(all(build['plan'][key] == first[key] for key in ('sdkVersion', 'packageRevision', 'sourceManifestSha256'))
                for _, build in builds), 'Repository inputs must use one immutable SDK/revision/source')
    targets = [(build['plan']['variant'], build['plan']['architecture']['public']) for _, build in builds]
    require(len(set(targets)) == len(targets), 'Duplicate repository matrix member')
    variants = sorted({variant for variant, _ in targets})
    require(all({arch for variant, arch in targets if variant == selected} == {'x64', 'aarch64'} for selected in variants),
            'Repository promotion requires both architectures for every advertised variant')
    return builds, first, variants


def build_repositories(paths, channel, output, signing_key, gnupg_home=None, rpm_asset_base_url=None):
    require(channel in {'deb', 'rpm'}, 'Unsupported signed repository channel')
    require(re.fullmatch(r'[A-Fa-f0-9]{40,64}', signing_key), 'A full independently reviewed signing fingerprint is required')
    builds, first, variants = validate_package_builds(paths, channel)
    remote_rpm = channel == 'rpm' and rpm_asset_base_url is not None
    require(channel == 'rpm' or rpm_asset_base_url is None, 'RPM asset URLs cannot be used for another channel')
    if remote_rpm:
        expected_base = ('https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-rpm-sdk-'
                         + first['sdkVersion'] + '-r' + str(first['packageRevision']) + '/')
        require(isinstance(rpm_asset_base_url, str) and rpm_asset_base_url.rstrip('/') + '/' == expected_base,
                'RPM package asset base must be the canonical immutable project release URL')
        rpm_asset_base_url = expected_base
    output = fresh_output(output)
    public_key = subprocess.check_output(gpg_command(gnupg_home, '--export', signing_key))
    require(public_key, 'Repository signing identity has no exportable public key')
    archives, package_assets = [], {}
    for variant in variants:
        require(re.fullmatch(r'[a-z]+-[0-9]+(?:\.[0-9]+)?', variant), 'Unsafe repository OS variant')
        repository = output / variant
        pool = repository if remote_rpm else repository / 'pool'
        pool.mkdir(parents=True)
        packages = {}
        for parent, build in builds:
            if build['plan']['variant'] != variant:
                continue
            for item in build['packages']:
                require(item['path'].endswith('.rpm' if channel == 'rpm' else '.deb'), 'Unexpected repository package format')
                canonical = item['path']
                public_arch = build['plan']['architecture']['public']
                if remote_rpm:
                    prefix = ('rpm-' + variant + '--' if item['kind'] == 'host'
                              else 'rpm-' + variant + '-' + public_arch + '--')
                    canonical = prefix + item['path']
                destination = pool / canonical
                source = parent / item['path']
                if destination.exists():
                    require(sha256_file(destination) == item['sha256'], 'Conflicting shared package identity')
                else:
                    shutil.copyfile(source, destination)
                if remote_rpm:
                    packages[canonical] = {'sha256': item['sha256'], 'size': item['size'],
                                           'url': rpm_asset_base_url + canonical}
                    package_assets[canonical] = {'sourcePath': str(destination), 'assetName': canonical,
                                                'size': item['size'], 'sha256': item['sha256'], 'variant': variant,
                                                'architecture': 'noarch' if item['kind'] == 'host' else public_arch,
                                                'kind': item['kind']}
                else:
                    packages[item['path']] = item['sha256']
        (repository / 'cbodotnet-archive-keyring.gpg').write_bytes(public_key)
        if channel == 'deb':
            indexes = subprocess.check_output(['apt-ftparchive', 'packages', 'pool'], cwd=repository)
            (repository / 'Packages').write_bytes(indexes)
            with (repository / 'Packages.gz').open('xb') as stream:
                with gzip.GzipFile(fileobj=stream, filename='', mode='wb', mtime=int(SOURCE_DATE_EPOCH)) as compressed:
                    compressed.write(indexes)
            release = subprocess.check_output([
                'apt-ftparchive', '-o', 'APT::FTPArchive::Release::Origin=cbodotnet',
                '-o', 'APT::FTPArchive::Release::Label=Community Build of .NET',
                '-o', 'APT::FTPArchive::Release::Architectures=amd64 arm64 all',
                '-o', 'APT::FTPArchive::Release::Description=Community Build of .NET (built by .NET Dev)',
                'release', '.'], cwd=repository)
            (repository / 'Release').write_bytes(release)
            subprocess.run(gpg_command(gnupg_home, '--local-user', signing_key, '--digest-algo', 'SHA256',
                                       '--clearsign', '--output', str(repository / 'InRelease'), str(repository / 'Release')), check=True)
            subprocess.run(gpg_command(gnupg_home, '--local-user', signing_key, '--digest-algo', 'SHA256',
                                       '--armor', '--detach-sign', '--output', str(repository / 'Release.gpg'), str(repository / 'Release')), check=True)
            subprocess.run(['gpgv', '--keyring', str(repository / 'cbodotnet-archive-keyring.gpg'),
                            str(repository / 'Release.gpg'), str(repository / 'Release')], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            archive_name = 'apt-' + variant + '.tar.gz'
        else:
            # Repository metadata signing never substitutes for RPM payload signatures.
            # RPM 4 imports armored OpenPGP keys; gpgv independently uses the
            # binary keyring above. Keep both forms available to repository clients.
            armored_key = repository / 'cbodotnet-rpm-signing-key.asc'
            armored_key.write_bytes(subprocess.check_output(gpg_command(gnupg_home, '--armor', '--export', signing_key)))
            database = output / ('.rpm-keyring-' + variant)
            database.mkdir(mode=0o700)
            subprocess.run(['rpm', '--dbpath', str(database), '--initdb'], check=True, stdout=subprocess.PIPE)
            subprocess.run(['rpmkeys', '--dbpath', str(database), '--import', str(armored_key)],
                           check=True, stdout=subprocess.PIPE)
            for package in pool.glob('*.rpm'):
                status = subprocess.check_output(['rpmkeys', '--dbpath', str(database), '--checksig', '--verbose', str(package)],
                                                 stderr=subprocess.STDOUT).decode()
                require('Signature' in status and 'NOKEY' not in status and 'NOT OK' not in status,
                        'RPM repository requires independently verified package signatures')
            # Current createrepo defaults to zstd while older releases use
            # gzip. Pin the XML format consumed by both admitted clients and
            # our independent metadata validator.
            command = ['createrepo_c', '--checksum', 'sha256', '--general-compress-type', 'gz', '--no-database']
            if remote_rpm:
                command += ['--baseurl', rpm_asset_base_url]
            subprocess.run([*command, str(repository)], check=True, stdout=subprocess.PIPE)
            metadata = repository / 'repodata/repomd.xml'
            subprocess.run(gpg_command(gnupg_home, '--local-user', signing_key, '--digest-algo', 'SHA256',
                                       '--armor', '--detach-sign', '--output', str(metadata) + '.asc', str(metadata)), check=True)
            subprocess.run(['gpgv', '--keyring', str(repository / 'cbodotnet-archive-keyring.gpg'),
                            str(metadata) + '.asc', str(metadata)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            archive_name = 'rpm-' + variant + '.tar.gz'
        write_json(repository / 'repository-manifest.json', {'schemaVersion': 1, 'channel': channel,
                   'sdkVersion': first['sdkVersion'], 'packageRevision': first['packageRevision'],
                   'variant': variant, 'architectures': ['x64', 'aarch64'], 'signingFingerprint': signing_key.upper(),
                   'sourceManifestSha256': first['sourceManifestSha256'], 'packages': packages,
                   **({'assetBaseUrl': rpm_asset_base_url} if remote_rpm else {})})
        archives.append({**deterministic_tar(repository, output / archive_name, ('.rpm',) if remote_rpm else ()),
                         'variant': variant, 'channel': channel})
    result = {'schemaVersion': 1, 'channel': channel, 'sdkVersion': first['sdkVersion'],
              'packageRevision': first['packageRevision'], 'signingFingerprint': signing_key.upper(), 'archives': archives,
              **({'packageAssets': [package_assets[name] for name in sorted(package_assets)]} if remote_rpm else {})}
    write_json(output / 'repository-build.json', result)
    return result
