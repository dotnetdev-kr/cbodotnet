#!/usr/bin/env python3
"""Generate auditable AUR source trees and test native Arch package lifecycles."""
import hashlib
import gzip
import importlib.util
import inspect
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

from distribution_commands import default_launcher_text, stage_commands
from distribution_contract import launcher_text
from downstream_release import encoded, require

ROOT = Path(__file__).resolve().parents[1]
ARCH_BASE = 'archlinux:base-devel@sha256:3942e1ff7ee3c41bdbcb6647ed850e199caae0c56dd18a4d3fa9bb9f3d2311f1'
HOST_VERSION = '1.0.0'
OPTIONS = ('!strip', '!debug', '!lto', '!zipman', '!purge', 'docs', 'libtool', 'staticlibs', 'emptydirs')


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sdk_tools():
    spec = importlib.util.spec_from_file_location('aur_sdk_tools', ROOT / 'scripts/test-distribution-coexistence.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_verifier():
    """Vendor only the reviewed standalone SDK extraction primitives, never repo imports."""
    tools = sdk_tools()
    header = ('#!/usr/bin/env python3\n'
              '"""Verify canonical SDK inputs before safe, byte-preserving extraction."""\n'
              'import argparse\nimport hashlib\nimport json\nimport os\n'
              'from pathlib import Path, PurePosixPath\nimport posixpath\nimport shutil\n'
              'import stat\nimport tarfile\nimport tempfile\n\n')
    functions = '\n\n'.join(inspect.getsource(getattr(tools, name)) for name in ('require', 'sha256', 'snapshot', 'extract_sdk'))
    return header + functions + '''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--checksums', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    policy = json.loads(args.policy.read_bytes())
    require(sha256(args.manifest) == policy['sourceManifestSha256'], 'Pinned source manifest changed')
    manifest = json.loads(args.manifest.read_bytes())
    require(manifest['schemaVersion'] == 1 and manifest['repository'] == 'dotnetdev-kr/cbodotnet'
            and manifest['sdkVersion'] == policy['sdkVersion'] and manifest['tag'] == policy['sourceReleaseTag']
            and set(manifest['architectures']) == {'x64', 'aarch64'}, 'Incomplete canonical SDK release')
    row = manifest['architectures']['x64']
    require(row['sdk'] == {key: policy['sdk'][key] for key in ('name', 'size', 'sha256')}
            and row['source'] == {key: policy['source'][key] for key in ('name', 'size', 'sha256')}
            and row['evidence'] == {key: policy['evidence'][key] for key in ('name', 'size', 'sha256')}
            and row['provenance'] == policy['producer'] and row['provenance']['targetRid'] == 'linux-x64',
            'Release assets or qualified producer differ from reviewed policy')
    require(args.checksums.stat().st_size == manifest['checksums']['size']
            and sha256(args.checksums) == manifest['checksums']['sha256'], 'Canonical checksums changed')
    expected = {value[kind]['name']: value[kind]['sha256'] for value in manifest['architectures'].values()
                for kind in ('sdk', 'source', 'evidence')}
    observed = {}
    for line in args.checksums.read_text(encoding='ascii').splitlines():
        digest, name = line.split('  ', 1)
        require(name not in observed, 'Duplicate source checksum')
        observed[name] = digest
    require(observed == expected, 'Source checksum matrix differs from manifest')
    require(args.archive.name == row['sdk']['name'] and args.archive.stat().st_size == row['sdk']['size']
            and sha256(args.archive) == row['sdk']['sha256'], 'Qualified SDK archive changed')
    destination = args.destination.absolute()
    require(destination.parent.is_dir() and not any(path.is_symlink() for path in [destination, *destination.parents]),
            'An ordinary SDK extraction destination is required')
    if destination.exists():
        with tempfile.TemporaryDirectory(prefix='cbodotnet-aur-cache-') as temporary:
            fresh = Path(temporary) / 'sdk'
            extract_sdk(args.archive, fresh)
            require(snapshot(destination) == snapshot(fresh), 'SDK source cache changed; rebuild with makepkg --cleanbuild')
    else:
        extract_sdk(args.archive, destination)


if __name__ == '__main__':
    main()
'''


def write_sources(plan, output):
    require(plan['channel'] == 'aur' and plan['variant'] == 'arch-rolling'
            and plan['architecture']['public'] == 'x64', 'Initial AUR delivery requires native Arch x86_64 admission')
    output = Path(output).absolute()
    require(not output.exists() and output.parent.is_dir(), 'A fresh AUR source output is required')
    version, revision = plan['sdkVersion'], plan['packageRevision']
    series = '.'.join(version.split('.')[:2])
    name = plan['package'].get('aurName', 'cbodotnet-sdk-' + series + '-bin')
    require(name == 'cbodotnet-sdk-' + series + '-bin', 'Unexpected AUR package namespace')
    dependencies = plan.get('aurDependencies', plan['dependencies'])
    require(dependencies and all(re.fullmatch(r'[A-Za-z0-9@._+-]+', value) for value in dependencies), 'Reviewed Arch dependencies required')
    host = output / 'cbodotnet-host'
    sdk = output / name
    host.mkdir(parents=True)
    sdk.mkdir()
    (host / 'cbodotnet').write_text(default_launcher_text(), encoding='utf-8', newline='\n')
    shutil.copyfile(ROOT / 'LICENSE', host / 'LICENSE')
    (sdk / ('cbodotnet-' + series)).write_text(launcher_text(plan['package']['root'], 'x64', plan=plan), encoding='utf-8', newline='\n')
    (sdk / 'distribution.json').write_bytes(encoded(plan))
    (sdk / 'verify-source.py').write_text(source_verifier(), encoding='utf-8', newline='\n')
    host_build = f'''# Maintainer: .NET Dev contributors (https://dotnetdev.kr/)
pkgname=cbodotnet-host
pkgver={HOST_VERSION}
pkgrel=1
pkgdesc='Shared command selector for Community Build of .NET'
arch=('any')
url='https://dotnetdev.kr/cbodotnet/'
license=('MIT')
depends=('bash')
options=('!strip' '!debug' '!lto')
source=('cbodotnet' 'LICENSE')
sha256sums=('{sha256(host / 'cbodotnet')}' '{sha256(host / 'LICENSE')}')

package() {{
  install -Dm755 "$srcdir/cbodotnet" "$pkgdir/usr/bin/cbodotnet"
  install -Dm644 "$srcdir/LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}}
'''
    (host / 'PKGBUILD').write_text(host_build, encoding='utf-8', newline='\n')
    local_names = ['cbodotnet-' + series, 'distribution.json', 'verify-source.py']
    source = ' '.join("'" + value + "'" for value in [*local_names,
        'release-manifest.json::' + plan['sourceManifestUrl'],
        'SHA256SUMS::' + plan['sourceManifestUrl'].rsplit('/', 1)[0] + '/SHA256SUMS'])
    # The source checksum descriptor is part of the exact reviewed manifest.
    checksum = plan.get('checksums')
    require(checksum and re.fullmatch(r'[a-f0-9]{64}', checksum['sha256']), 'Reviewed SHA256SUMS descriptor required')
    hashes = [*(sha256(sdk / value) for value in local_names), plan['sourceManifestSha256'], checksum['sha256']]
    quoted_hashes = ' '.join("'" + value + "'" for value in hashes)
    quoted_dependencies = ' '.join("'" + value + "'" for value in [*dependencies, 'cbodotnet-host>=' + HOST_VERSION])
    quoted_options = ' '.join("'" + value + "'" for value in OPTIONS)
    sdk_build = f'''# Maintainer: .NET Dev contributors (https://dotnetdev.kr/)
# Qualified prebuilt SDK; distribution.json records corresponding source/evidence.
pkgname={name}
pkgver={version}
pkgrel={revision}
pkgdesc='Community Build of .NET (built by .NET Dev) SDK'
arch=('x86_64')
url='https://dotnetdev.kr/cbodotnet/'
license=('custom')
depends=({quoted_dependencies})
makedepends=('python')
options=({quoted_options})
source=({source})
sha256sums=({quoted_hashes})
source_x86_64=('{plan['sdk']['url']}')
sha256sums_x86_64=('{plan['sdk']['sha256']}')
noextract=('{plan['sdk']['name']}')

prepare() {{
  python "$srcdir/verify-source.py" --policy "$srcdir/distribution.json" \\
    --manifest "$srcdir/release-manifest.json" --checksums "$srcdir/SHA256SUMS" \\
    --archive "$srcdir/{plan['sdk']['name']}" --destination "$srcdir/sdk-{version}"
}}

package() {{
  install -dm755 "$pkgdir{plan['package']['root']}"
  cp -a --no-preserve=ownership "$srcdir/sdk-{version}/." "$pkgdir{plan['package']['root']}/"
  install -dm755 "$pkgdir{plan['package']['root']}/metadata"
  install -Dm755 "$srcdir/cbodotnet-{series}" "$pkgdir/usr/bin/cbodotnet-{series}"
  install -Dm644 "$srcdir/distribution.json" "$pkgdir/usr/share/doc/$pkgname/distribution.json"
  install -Dm644 "$srcdir/sdk-{version}/LICENSE.txt" "$pkgdir/usr/share/licenses/$pkgname/LICENSE.txt"
  install -Dm644 "$srcdir/sdk-{version}/ThirdPartyNotices.txt" "$pkgdir/usr/share/licenses/$pkgname/ThirdPartyNotices.txt"
}}
'''
    (sdk / 'PKGBUILD').write_text(sdk_build, encoding='utf-8', newline='\n')
    return {'host': host, 'sdk': sdk}


def generate_srcinfo(directory, command=None):
    directory = Path(directory)
    invocation = [*(command or []), 'makepkg', '--printsrcinfo']
    result = subprocess.check_output(invocation, cwd=directory)
    require(result.startswith(b'pkgbase = ') and b'pkgname = ' in result, 'makepkg did not generate .SRCINFO')
    (directory / '.SRCINFO').write_bytes(result)
    return result


def verify_tracked_sources(recipes, tracked, srcinfo=False):
    """Make the native build evidence cover the reviewed checked-in recipes."""
    recipes, tracked = Path(recipes), Path(tracked)
    require(tracked.is_dir(), 'Reviewed tracked AUR recipe trees are required')
    for base in recipes.iterdir():
        expected_base = tracked / base.name
        require(expected_base.is_dir() and not expected_base.is_symlink(), 'Tracked AUR package base is missing')
        for expected in expected_base.iterdir():
            if expected.name == '.SRCINFO' and not srcinfo:
                continue
            require(expected.is_file() and not expected.is_symlink(), 'Tracked AUR source must be an ordinary file')
            actual = base / expected.name
            require(actual.is_file() and not actual.is_symlink() and actual.read_bytes() == expected.read_bytes(),
                    'Generated or actual makepkg AUR source differs from reviewed tracked recipe: ' + base.name + '/' + expected.name)
        if srcinfo:
            require((expected_base / '.SRCINFO').is_file(), 'Actual makepkg metadata must match tracked .SRCINFO')


def review_namcap(output, package_base, binary_package=False):
    """Review only namcap's known /opt layout diagnostic for the isolated SDK.

    Arch namcap 3.6 ELFPaths labels every ELF under opt/ as questionable and
    emits this summary at E severity. The distribution contract requires that
    exact isolated root. All dependency and other ELF diagnostics stay errors.
    """
    errors = [line for line in output.splitlines() if re.search(r'\bE: ', line)]
    expected = package_base + " E: ELF files outside of a valid path ('opt/')."
    reviewed = []
    if binary_package and re.fullmatch(r'cbodotnet-sdk-[1-9][0-9]*\.[0-9]+-bin', package_base):
        if errors.count(expected) == 1:
            errors.remove(expected)
            reviewed.append(dict(diagnostic=expected, rule='elfpaths',
                reason='The reviewed contract isolates the complete unmodified SDK under /opt/cbodotnet/<series>; '
                       'native installation independently verifies all qualified payload bytes, modes and links.'))
    require(not errors, 'Unreviewed namcap error:\n' + '\n'.join(errors))
    return reviewed


def recipe_archive(recipe_root, destination):
    recipe_root, destination = Path(recipe_root), Path(destination)
    allowed = {'PKGBUILD', '.SRCINFO', 'cbodotnet', 'LICENSE', 'distribution.json', 'verify-source.py'}
    bases = sorted(recipe_root.iterdir())
    require(len(bases) == 2 and {base.name for base in bases if base.name == 'cbodotnet-host'} == {'cbodotnet-host'}
            and sum(bool(re.fullmatch(r'cbodotnet-sdk-[1-9][0-9]*\.[0-9]+-bin', base.name)) for base in bases) == 1,
            'Both independent reviewed AUR package bases are required')
    for base in bases:
        require((base / 'PKGBUILD').is_file() and (base / '.SRCINFO').is_file(), 'Actual makepkg .SRCINFO is required for each package base')
    sources = []
    # Repeated builds of identical reviewed recipes produce identical bytes.
    with destination.open('xb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as compressed, \
            tarfile.open(fileobj=compressed, mode='w') as archive:
        for base in bases:
            require(base.is_dir() and not base.is_symlink(), 'Unexpected AUR source package base')
            for path in sorted(base.iterdir()):
                if path.name not in allowed and not re.fullmatch(r'cbodotnet-[1-9][0-9]*\.[0-9]+', path.name):
                    continue
                require(path.is_file() and not path.is_symlink(), 'Only ordinary reviewed AUR source files may be submitted')
                entry = archive.gettarinfo(path, arcname=path.relative_to(recipe_root).as_posix())
                entry.uid = entry.gid = entry.mtime = 0
                entry.uname = entry.gname = ''
                entry.mode = 0o644
                with path.open('rb') as contents:
                    archive.addfile(entry, contents)
                sources.append({'path': path.relative_to(recipe_root).as_posix(), 'sha256': sha256(path)})
    require(len(sources) >= 8, 'Incomplete AUR source submission')
    return {'path': destination.name, 'size': destination.stat().st_size, 'sha256': sha256(destination), 'sources': sources}
