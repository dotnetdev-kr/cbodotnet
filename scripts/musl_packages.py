"""Build immutable musl APK/OCI candidates; publication needs independent receipts.

Alpine 3.24 uses apk-tools 3 but abuild 3.17 still emits v2 gzip/tar APKs.
Both package control and repository index signatures must explicitly use RSA256.
These helpers never generate credentials or authorize publication.
"""
import base64
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import zlib

from distribution_commands import default_launcher_text, forwarding_launcher_text
from distribution_contract import BRANDING, sha256_file
from musl_contract import ARCHITECTURES, REPOSITORY, version_revision
from channel_packages import descriptor, fresh_output, sdk_tools, write_json

ROOT = Path(__file__).resolve().parents[1]
HOST_VERSION = '1.0.0-r1'
SOURCE_DATE_EPOCH = '1700000000'
KEY_NAME = 'cbodotnet-apk-2026.rsa.pub'
MAX_CONTROL_BYTES = 8 * 1024**2
BASE_IMAGES = {
    'x64': 'alpine:3.24.4@sha256:0f49f331d9212aff11b932863be4eb01cdf962969aa86dab7d1ee21ac6f5f52b',
    'aarch64': 'alpine:3.24.4@sha256:1829893486be257df5049ab3b7fc95afbd0fc09d89803cbc580bda1ba5386b29',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def ordinary(path):
    path = Path(path).absolute()
    require(path.is_file() and not any(p.is_symlink() for p in [path, *path.parents]), 'Ordinary file required')
    return path


def stream_digest(stream, algorithm='sha256'):
    digest = hashlib.new(algorithm)
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        digest.update(block)
    return digest.hexdigest()


def validate_plan(plan, channel=None):
    require(isinstance(plan, dict) and plan.get('status') == 'prepared-unqualified'
            and plan.get('publicationAllowed') is False and plan.get('libc') == 'musl',
            'An explicit unqualified musl preparation plan is required')
    version, revision = plan.get('sdkVersion'), plan.get('packageRevision')
    version_revision(version, revision)
    arch = plan.get('architecture', {}).get('public')
    require(arch in ARCHITECTURES and plan['architecture'] == ARCHITECTURES[arch]
            and plan.get('targetRid') == ARCHITECTURES[arch]['rid'], 'Musl CPU/RID mapping differs')
    require(plan.get('variant') == 'alpine-3.24' and plan.get('channel') in {'apk', 'oci'}
            and (channel is None or plan['channel'] == channel), 'Unreviewed Alpine packaging target')
    series = '.'.join(version.split('.')[:2])
    package = plan.get('package', {})
    require(package.get('name') == 'cbodotnet-sdk-' + series
            and package.get('root') == '/opt/cbodotnet/' + series
            and package.get('launcher') == '/usr/bin/cbodotnet-' + series
            and package.get('version') == f'{version}-r{revision}', 'APK installation namespace differs')
    require(plan.get('branding') == BRANDING and plan.get('licensePaths') == ['LICENSE.txt', 'ThirdPartyNotices.txt'],
            'Branding and original license inventory are required')
    dependencies = plan.get('dependencies')
    require(isinstance(dependencies, list) and dependencies and len(set(dependencies)) == len(dependencies)
            and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]*', x) for x in dependencies)
            and not any(x in {'gcompat', 'libc6-compat'} or x.startswith('cbodotnet-compat') for x in dependencies),
            'Reviewed stock Alpine dependencies are required')
    require(re.fullmatch(r'[a-f0-9]{64}', plan.get('sourceManifestSha256', '')) is not None,
            'Exact musl source manifest digest is required')
    return series, arch


def launcher_text(plan):
    """Share the musl archive wrapper's identity and isolated host selection."""
    validate_plan(plan)
    from musl_archive import launcher_text as musl_launcher
    return musl_launcher(plan, root=plan['package']['root'])


def stage_payload(plan, archive, output, mode='package'):
    series, arch = validate_plan(plan, 'apk' if mode == 'package' else 'oci')
    require(mode in {'package', 'oci'}, 'Unknown command staging mode')
    archive = ordinary(archive)
    expected = plan.get('sdk', {})
    require(archive.name == expected.get('name') and archive.stat().st_size == expected.get('size')
            and sha256_file(archive) == expected.get('sha256'), 'Qualified musl SDK archive changed')
    output = fresh_output(output)
    rootfs = output / 'rootfs'
    sdk = rootfs / plan['package']['root'].lstrip('/')
    sdk.parent.mkdir(parents=True)
    tools = sdk_tools()
    tools.extract_sdk(archive, sdk)
    require((sdk / 'dotnet').is_file() and not (sdk / 'dotnet').is_symlink()
            and os.access(sdk / 'dotnet', os.X_OK), 'Missing executable musl SDK host')
    payload = tools.snapshot(sdk)
    for name in plan['licensePaths']:
        require((sdk / name).is_file() and not (sdk / name).is_symlink(), 'Original SDK notice is missing')
    commands = {plan['package']['launcher']: launcher_text(plan), '/usr/bin/cbodotnet': default_launcher_text()}
    if mode == 'oci':
        forward = forwarding_launcher_text(plan['package']['launcher'])
        commands['/usr/bin/cbodotnet'] = forward
        commands.update({'/usr/local/bin/' + name: forward for name in ('cbodotnet-' + series, 'cbodotnet', 'dotnet')})
    inventory = []
    for name, content in sorted(commands.items()):
        path = rootfs / name.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8', newline='\n')
        path.chmod(0o755)
        inventory.append({'path': name, 'sha256': sha256_file(path), 'mode': '0755',
                          'owner': 'cbodotnet-host' if name == '/usr/bin/cbodotnet' else plan['package']['name']})
    doc = rootfs / 'usr/share/doc' / plan['package']['name']
    doc.mkdir(parents=True)
    write_json(doc / 'distribution.json', plan)
    for name in plan['licensePaths']:
        shutil.copyfile(sdk / name, doc / name)
    require(tools.snapshot(sdk) == payload, 'Packaging modified qualified SDK bytes or modes')
    write_json(output / 'plan.json', plan)
    write_json(output / 'payload-inventory.json', payload)
    write_json(output / 'command-inventory.json', inventory)
    return output, rootfs, inventory, payload


def public_key_identity(public_key):
    key = ordinary(public_key)
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9@._+-]*\.rsa\.pub', key.name), 'Canonical APK public key filename required')
    der = subprocess.run(['openssl', 'pkey', '-pubin', '-in', str(key), '-outform', 'DER'],
                         check=True, capture_output=True).stdout
    details = subprocess.run(['openssl', 'pkey', '-pubin', '-in', str(key), '-text', '-noout'],
                             check=True, capture_output=True, text=True).stdout
    require(re.search(r'Public-Key:\s*\(4096 bit\)', details) is not None
            and 'Modulus:' in details, 'A dedicated RSA-4096 APK trust key is required')
    return {'filename': key.name, 'algorithm': 'RSA-4096', 'signatureType': 'RSA256',
            'digestAlgorithm': 'SHA-256', 'spkiSha256': hashlib.sha256(der).hexdigest(), 'sha256': sha256_file(key)}


def gzip_member(stream, limit=MAX_CONTROL_BYTES):
    """Read one bounded gzip member, retaining the exact signed compressed bytes."""
    start = stream.tell()
    decoder = zlib.decompressobj(31)
    plain = bytearray()
    while not decoder.eof:
        chunk = stream.read(65536)
        require(chunk, 'Truncated APK gzip member')
        require(stream.tell() - start <= 2 * limit, 'Compressed APK metadata exceeds its size limit')
        try:
            plain.extend(decoder.decompress(chunk, limit + 1 - len(plain)))
        except zlib.error as error:
            raise ValueError('Invalid APK gzip member') from error
        require(len(plain) <= limit and not decoder.unconsumed_tail, 'APK metadata exceeds its size limit')
    end = stream.tell() - len(decoder.unused_data)
    stream.seek(start)
    compressed = stream.read(end - start)
    return compressed, bytes(plain)


def tar_files(data):
    values = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
            for member in archive:
                require(member.isfile() and member.name not in values and member.size <= MAX_CONTROL_BYTES
                        and '/' not in member.name and '\\' not in member.name
                        and not member.mode & 0o7000, 'Unexpected APK metadata member')
                values[member.name] = archive.extractfile(member).read()
    except tarfile.TarError as error:
        raise ValueError('Invalid APK metadata tar') from error
    return values


def verify_signed_v2(path, public_key):
    """Verify the first RSA256 signature and return its exact content gzip member."""
    path, key = ordinary(path), ordinary(public_key)
    identity = public_key_identity(key)
    with path.open('rb') as stream:
        _, signature_tar = gzip_member(stream, 128 * 1024)
        signatures = tar_files(signature_tar)
        name = '.SIGN.RSA256.' + key.name
        require(set(signatures) == {name} and len(signatures[name]) == 512,
                'APK must contain exactly the reviewed RSA256 signature')
        compressed, content = gzip_member(stream)
        data_offset = stream.tell()
    with tempfile.TemporaryDirectory(prefix='cbodotnet-apk-verify-') as temp:
        directory = Path(temp)
        (directory / 'signature').write_bytes(signatures[name])
        (directory / 'content.gz').write_bytes(compressed)
        result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(key), '-signature',
            str(directory / 'signature'), str(directory / 'content.gz')], capture_output=True)
        require(result.returncode == 0, 'APK RSA256 signature verification failed')
    return identity, compressed, content, data_offset


def parse_pkginfo(data):
    fields = {}
    for line in data.decode('utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        require(' = ' in line, 'Malformed APK package metadata')
        key, value = line.split(' = ', 1)
        fields.setdefault(key, []).append(value)
    for key in ('pkgname', 'pkgver', 'arch', 'datahash'):
        require(len(fields.get(key, [])) == 1, 'Missing or ambiguous APK identity: ' + key)
    require(re.fullmatch(r'[a-f0-9]{64}', fields['datahash'][0]), 'APK data SHA-256 is absent')
    return fields


def verify_apk(path, public_key, expected=None):
    identity, control, plain, offset = verify_signed_v2(path, public_key)
    files = tar_files(plain)
    require(set(files) == {'.PKGINFO'}, 'APK install hooks or unexpected control members are not admitted')
    fields = parse_pkginfo(files['.PKGINFO'])
    with Path(path).open('rb') as stream:
        stream.seek(offset)
        digest = stream_digest(stream)
    require(digest == fields['datahash'][0] and Path(path).stat().st_size > offset,
            'APK payload checksum differs from its signed control')
    row = {**descriptor(path), 'name': fields['pkgname'][0], 'version': fields['pkgver'][0],
        'architecture': fields['arch'][0], 'controlSha256': hashlib.sha256(control).hexdigest(),
        'indexIdentity': 'Q1' + base64.b64encode(hashlib.sha1(control).digest()).decode(),
        'dataSha256': digest, 'signingKey': identity, 'metadata': fields, 'dataOffset': offset}
    if expected is not None:
        require(all(row[key] == value for key, value in expected.items()), 'APK package identity differs from its plan')
    return row


def verify_index(path, public_key, packages):
    identity, compressed, plain, offset = verify_signed_v2(path, public_key)
    require(offset == Path(path).stat().st_size, 'Repository index has trailing unsigned content')
    files = tar_files(plain)
    require(set(files) <= {'DESCRIPTION', 'APKINDEX'} and 'APKINDEX' in files,
            'Unexpected repository index contents')
    expected = {(row['name'], row['version']): row for row in packages}
    require(len(expected) == len(packages), 'Duplicate package identity in repository')
    native_arches = {row['architecture'] for row in packages if row['architecture'] != 'noarch'}
    require(len(native_arches) <= 1 and native_arches <= {'x86_64', 'aarch64'}, 'Mixed native CPU APK repository')
    seen = set()
    for block in files['APKINDEX'].decode('utf-8').strip().split('\n\n'):
        fields = {}
        for line in block.splitlines():
            require(len(line) >= 2 and line[1] == ':' and line[0] not in fields, 'Malformed APKINDEX record')
            fields[line[0]] = line[2:]
        key = (fields.get('P'), fields.get('V'))
        row = expected.get(key)
        require(row is not None and key not in seen and fields.get('C') == row['indexIdentity']
                and int(fields.get('S', '-1')) == row['size']
                and fields.get('A') in ({'noarch', *native_arches} if row['architecture']=='noarch' else {row['architecture']}),
                'APKINDEX does not bind the exact signed package set')
        seen.add(key)
    require(seen == set(expected), 'Incomplete APK repository index')
    return {**descriptor(path), 'signingKey': identity, 'packages': len(seen), 'format': 'apk-v2'}


def payload_snapshot(path, row):
    """Stream a package payload without extracting untrusted paths or large buffers."""
    result = {}
    total_size = 0
    with ordinary(path).open('rb') as stream:
        stream.seek(row['dataOffset'])
        with tarfile.open(fileobj=stream, mode='r|gz') as archive:
            for member in archive:
                total_size += member.size
                require(len(result) < 200000 and total_size <= 8 * 1024**3, 'APK payload exceeds reviewed bounds')
                name = member.name.rstrip('/')
                relative = PurePosixPath(name)
                require(name and str(relative) == name and not relative.is_absolute() and '..' not in relative.parts
                        and not any(c in name for c in '\\:\0\r\n') and name not in result
                        and not member.mode & 0o7000 and member.uid == member.gid == 0,
                        'Unsafe APK payload path, owner, mode or duplicate member')
                mode = member.mode & 0o777
                if member.isfile():
                    result[name] = ['file', mode, stream_digest(archive.extractfile(member))]
                elif member.isdir():
                    result[name] = ['directory', mode]
                elif member.issym():
                    result[name] = ['link', mode, member.linkname]
                elif member.islnk():
                    require(member.linkname in result and result[member.linkname][0] == 'file', 'Unsafe APK hard link')
                    result[name] = list(result[member.linkname])
                else:
                    raise ValueError('Unexpected APK payload file type')
    for name in result:
        require(all(str(parent) not in result or result[str(parent)][0] == 'directory'
                    for parent in PurePosixPath(name).parents), 'APK member has a non-directory parent')
        row = result[name]
        if row[0] == 'link':
            import posixpath
            target = posixpath.normpath(posixpath.join(posixpath.dirname(name), row[2]))
            require(not row[2].startswith('/') and not any(c in row[2] for c in '\\:\0\r\n')
                    and target in result and result[target][0] == 'file', 'Unsafe APK symbolic link')
    return result


def recipe(plan, kind, source_sha512):
    series, arch = validate_plan(plan, 'apk')
    require(kind in {'sdk', 'host'} and re.fullmatch(r'[a-f0-9]{128}', source_sha512), 'Invalid APK source identity')
    name = plan['package']['name'] if kind == 'sdk' else 'cbodotnet-host'
    version = plan['sdkVersion'] if kind == 'sdk' else HOST_VERSION.split('-r')[0]
    revision = plan['packageRevision'] if kind == 'sdk' else int(HOST_VERSION.split('-r')[1])
    dependencies = ['cbodotnet-host>=' + HOST_VERSION, *plan['dependencies']] if kind == 'sdk' else ['busybox']
    license_name = 'LicenseRef-Dotnet-SDK-ThirdParty' if kind == 'sdk' else 'MIT'
    return f'''# Generated from an authenticated musl preparation plan. Do not edit SDK bytes.
pkgname={name}
pkgver={version}
pkgrel={revision}
pkgdesc="Community Build of .NET (built by .NET Dev) {'SDK ' + version if kind == 'sdk' else 'shared command selector'}"
url="https://dotnetdev.kr/cbodotnet/"
arch="{ARCHITECTURES[arch]['apk'] if kind == 'sdk' else 'noarch'}"
license="{license_name}"
depends="{' '.join(dependencies)}"
# Immutable payload; all native dependency auditing happens before admission.
# LicenseRef names the retained original SDK licenses/ThirdPartyNotices.
# This third-party package intentionally owns only its reviewed /opt namespace.
options="!strip !dbg !tracedeps{' !spdx !fhs' if kind == 'sdk' else ''}"
source="payload.tar.gz"
builddir="$srcdir"
sha512sums="{source_sha512}  payload.tar.gz"

build() {{ :; }}
check() {{ test -d "$srcdir/rootfs/usr/bin"; }}
package() {{
    mkdir -p "$pkgdir"
    cp -a "$srcdir/rootfs/." "$pkgdir/"
}}
'''


def stage_source_archive(tree,destination):
    """Canonical abuild source input, independent of work path and wall clock."""
    tree=Path(tree).absolute()
    destination=Path(destination).absolute()
    require(tree.is_dir() and not any(p.is_symlink() for p in [tree,*tree.parents])
        and not destination.exists() and destination.parent.is_dir()
        and not any(p.is_symlink() for p in destination.parents),'Fresh ordinary APK source paths required')
    def canonical(row):
        row.uid=row.gid=0
        row.uname=row.gname=''
        row.mtime=int(SOURCE_DATE_EPOCH)
        row.pax_headers={}
        return row
    with destination.open('xb') as raw,gzip.GzipFile(filename='',fileobj=raw,mode='wb',compresslevel=9,mtime=int(SOURCE_DATE_EPOCH)) as compressed:
        with tarfile.open(fileobj=compressed,mode='w',format=tarfile.PAX_FORMAT) as archive:
            archive.add(tree,arcname='rootfs',filter=canonical)
    return destination


def build_apk(plan, archive, output, private_key, public_key, fixture=False):
    """Run unprivileged abuild in an already provisioned, isolated Alpine builder."""
    series, arch = validate_plan(plan, 'apk')
    require(platform.system() == 'Linux' and os.geteuid() != 0
            and platform.machine() in ({'aarch64', 'arm64'} if arch == 'aarch64' else {'x86_64'}),
            'APK assembly requires a matching native, unprivileged Alpine builder')
    require(Path('/etc/alpine-release').read_text().strip() == '3.24.4', 'Pinned Alpine 3.24.4 builder required')
    key, public = ordinary(private_key), ordinary(public_key)
    identity = public_key_identity(public)
    # Check pairing without printing private material or embedding its path in the report.
    actual = subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'],
                            check=True, capture_output=True).stdout
    require(hashlib.sha256(actual).hexdigest() == identity['spkiSha256'], 'APK private/public key mismatch')
    output, rootfs, commands, payload = stage_payload(plan, archive, output)
    require(not any(c.isspace() for c in str(output)), 'abuild output directory cannot contain whitespace')
    trust = output / 'apk-trust'
    trust.mkdir()
    shutil.copyfile(public, trust / public.name)
    sdk_tree = output / 'sdk-rootfs'
    shutil.copytree(rootfs, sdk_tree, symlinks=True, copy_function=os.link)
    (sdk_tree / 'usr/bin/cbodotnet').unlink()
    host_tree = output / 'host-rootfs'
    (host_tree / 'usr/bin').mkdir(parents=True)
    shutil.copyfile(rootfs / 'usr/bin/cbodotnet', host_tree / 'usr/bin/cbodotnet')
    (host_tree / 'usr/bin/cbodotnet').chmod(0o755)
    host_license = host_tree / 'usr/share/licenses/cbodotnet-host/LICENSE'
    host_license.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / 'LICENSE', host_license)
    config = output / 'abuild.conf'
    config.write_text('export sigtype=RSA256\nPACKAGER_PRIVKEY=' + shlex.quote(str(key))
        + '\nPACKAGER_PUBKEY=' + shlex.quote(str(public)) + '\nPACKAGER=".NET Dev contributors"\n', encoding='utf-8')
    config.chmod(0o600)
    environment = dict(os.environ, SOURCE_DATE_EPOCH=SOURCE_DATE_EPOCH, TZ='UTC', LC_ALL='C',
        sigtype='RSA256', PACKAGER_PRIVKEY=str(key), PACKAGER_PUBKEY=str(public),
        APK='apk --keys-dir ' + str(trust),
        ABUILD_USERCONF=str(config), REPODEST=str(output / 'abuild-repository'), SRCDEST=str(output / 'distfiles'))
    packages = []
    repository = output / 'repository'
    repository.mkdir()
    for kind, tree in [('host', host_tree), ('sdk', sdk_tree)]:
        work = output / 'aports' / 'cbodotnet' / kind
        work.mkdir(parents=True)
        source = work / 'payload.tar.gz'
        stage_source_archive(tree,source)
        with source.open('rb') as stream:
            source_digest = stream_digest(stream, 'sha512')
        (work / 'APKBUILD').write_text(recipe(plan, kind, source_digest), encoding='utf-8')
        # -d avoids privileged dependency installation; clean consumer apk transactions
        # independently resolve the runtime graph. No --allow-untrusted is used.
        subprocess.run(['abuild', '-d', '-f'], cwd=work, env=environment, check=True)
        name = plan['package']['name'] if kind == 'sdk' else 'cbodotnet-host'
        version = plan['package']['version'] if kind == 'sdk' else HOST_VERSION
        filename = name + '-' + version + '.apk'
        matches = list((output / 'abuild-repository').rglob(filename))
        require(len(matches) == 1, 'Ambiguous abuild output')
        destination = repository / filename
        shutil.copyfile(matches[0], destination)
        row = verify_apk(destination, public, {'name': name, 'version': version,
                         'architecture': ARCHITECTURES[arch]['apk'] if kind == 'sdk' else 'noarch'})
        require(payload_snapshot(destination, row) == sdk_tools().snapshot(tree), 'APK changed staged bytes, owners or modes')
        packages.append({**row, 'kind': kind})
    build_index(repository, packages, public, key)
    require(sdk_tools().snapshot(rootfs / plan['package']['root'].lstrip('/')) == payload, 'APK build changed SDK input')
    result = dict(schemaVersion=1, channel='apk', libc='musl', plan=plan, packages=packages,
        commandInventory=commands, payloadPreserved=True, publicationQualified=False,
        credentialPurpose='ephemeral-fixture' if fixture else 'native-candidate', signingKey=identity,
        repository=verify_index(repository / 'APKINDEX.tar.gz', public, packages))
    shutil.copyfile(public,output/public.name)
    result['publicKeyAsset']=descriptor(output/public.name)
    write_json(output / 'package-build.json', result)
    return result


def build_index(repository, packages, public_key, private_key):
    repository = Path(repository).absolute()
    require(repository.is_dir() and not any(p.is_symlink() for p in [repository, *repository.parents]), 'Ordinary repository required')
    require(not (repository / 'APKINDEX.tar.gz').exists(), 'Refusing to replace an existing signed index')
    public, private = ordinary(public_key), ordinary(private_key)
    for row in packages:
        current = verify_apk(repository / row['path'], public)
        require(all(current[k] == row[k] for k in ('name', 'version', 'architecture', 'sha256', 'size', 'indexIdentity')),
                'Package changed before indexing')
    with tempfile.TemporaryDirectory(prefix='apk-index-trust-') as temporary:
        shutil.copyfile(public, Path(temporary) / public.name)
        subprocess.run(['apk', '--keys-dir', temporary, 'index', '--output', 'APKINDEX.tar.gz',
                        *[row['path'] for row in packages]], cwd=repository, check=True)
    subprocess.run(['abuild-sign', '-t', 'RSA256', '-k', str(private), '-p', str(public), 'APKINDEX.tar.gz'],
                   cwd=repository, check=True, env=dict(os.environ, SOURCE_DATE_EPOCH=SOURCE_DATE_EPOCH))
    return verify_index(repository / 'APKINDEX.tar.gz', public, packages)


def repository_tag(version, arch, revision):
    version_revision(version, revision)
    require(arch in ARCHITECTURES, 'Unknown public musl architecture')
    return f'musl-apk-repo-{version}-alpine324-{arch}-r{revision}'


def repository_url(version, arch, revision):
    return f'https://github.com/{REPOSITORY}/releases/download/{repository_tag(version, arch, revision)}/APKINDEX.tar.gz'


def build_oci_context(plan, archive, output, base_image):
    series, arch = validate_plan(plan, 'oci')
    require(re.fullmatch(r'(?:docker\.io/)?(?:library/)?alpine:3\.24\.4@sha256:[a-f0-9]{64}', base_image),
            'An exact reviewed Alpine 3.24.4 image digest is required')
    require(base_image == BASE_IMAGES[arch], 'Alpine base image differs from reviewed CPU pin')
    output, rootfs, commands, payload = stage_payload(plan, archive, output, mode='oci')
    license_path = rootfs / 'usr/share/licenses/cbodotnet-host/LICENSE'
    license_path.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / 'LICENSE', license_path)
    shutil.copyfile(ROOT / 'containers/sdk-alpine-runtime.Containerfile', output / 'Containerfile')
    labels = {'org.opencontainers.image.title': BRANDING['displayName'],
        'org.opencontainers.image.source': 'https://github.com/' + REPOSITORY,
        'org.opencontainers.image.version': plan['sdkVersion'],
        'org.opencontainers.image.licenses': 'MIT AND LicenseRef-Dotnet-ThirdPartyNotices',
        'kr.dotnetdev.cbodotnet.libc': 'musl', 'kr.dotnetdev.cbodotnet.rid': plan['targetRid'],
        'kr.dotnetdev.cbodotnet.sdk.sha256': plan['sdk']['sha256'],
        'kr.dotnetdev.cbodotnet.manifest.sha256': plan['sourceManifestSha256'],
        'kr.dotnetdev.cbodotnet.license.path': plan['package']['root'] + '/LICENSE.txt',
        'kr.dotnetdev.cbodotnet.notices.path': plan['package']['root'] + '/ThirdPartyNotices.txt'}
    release_url='https://github.com/'+REPOSITORY+'/releases/tag/'+plan['sourceReleaseTag']
    asset_url='https://github.com/'+REPOSITORY+'/releases/download/'+plan['sourceReleaseTag']+'/'
    labels.update({'org.opencontainers.image.url': release_url,
        'org.opencontainers.image.documentation': 'https://github.com/'+REPOSITORY+'/blob/main/docs/alpine-musl.md',
        'kr.dotnetdev.cbodotnet.sdk.url': asset_url+plan['sdk']['name'],
        'kr.dotnetdev.cbodotnet.manifest.url': asset_url+'release-manifest.json',
        'kr.dotnetdev.cbodotnet.package.revision': str(plan['packageRevision'])})
    for kind in ('source','evidence'):
        if kind in plan:
            labels['kr.dotnetdev.cbodotnet.'+kind+'.url']=asset_url+plan[kind]['name']
            labels['kr.dotnetdev.cbodotnet.'+kind+'.sha256']=plan[kind]['sha256']
    from musl_archive import RUNTIME_PACKAGES
    dependencies = [name + '=' + RUNTIME_PACKAGES[name] for name in plan['dependencies']]
    result = dict(schemaVersion=1, channel='oci', libc='musl', plan=plan, baseImage=base_image,
        context='.', containerfile='Containerfile', labels=labels,
        buildArgs=dict(BASE_IMAGE=base_image, SDK_SERIES=series, APK_DEPENDENCIES=' '.join(dependencies)),
        commandInventory=commands, payloadPreserved=True, publicationQualified=False)
    write_json(output / 'package-build.json', result)
    return result
