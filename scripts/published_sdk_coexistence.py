"""Observe all eight authenticated public SDK packages together; never publish."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import tempfile

from distribution_contract import ARCHITECTURES, load_contract, validate_qualified_producers
from distribution_site import extract_repository
from distribution_status import validate_postverification
from downstream_publish import MANIFEST, SIGNATURE, REPOSITORY, publication_rows, release_tag
from downstream_release import descriptor, encoded, load_status, require, verify_report_signature
from release_catalog import get_bytes, validate_release
from sdk_runtime import series, smoke_program, smoke_script, validate_host_rid, validate_smoke_output
import published_apt as APT

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ('10.0.403', '9.0.123', '8.0.133', '7.0.120', '6.0.136', '5.0.214', '3.1.426', '3.0.103')
TARGETS = {'ubuntu-24.04': 'deb', 'debian-13': 'deb', 'fedora-45': 'rpm', 'rocky-9.8': 'rpm'}
USER = 'cbot-multi-sdk'
BRAND = 'Community Build of .NET (built by .NET Dev)'
SPEC = importlib.util.spec_from_file_location('coexistence_rpm', ROOT / 'scripts/rpm-ci.py')
RPM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RPM)
BASES = {**RPM.BASES,
    'ubuntu-24.04': {arch: RPM.SHARED.UBUNTU_BASE for arch in ARCHITECTURES},
    'debian-13': {arch: RPM.SHARED.DEBIAN_BASE for arch in ARCHITECTURES}}


def load(path):
    return json.loads(Path(path).read_bytes())


def save(path, value):
    Path(path).write_bytes(encoded(value))


def run(arguments, **kwargs):
    return APT.run(arguments, **kwargs)


def selected_receipts(policy, contract):
    """Fail before network/container work when any current package is unqualified."""
    require(set(VERSIONS) <= set(contract['releases']), 'All eight source SDKs must be admitted')
    selected = []
    for channel in ('deb', 'rpm'):
        configuration = policy['channels'][channel]
        require(configuration.get('status') == 'published', 'Both package channels must be published')
        rows = configuration.get('receipts', [])
        keys = [(row['identity']['sdkVersion'], row['identity']['packageRevision']) for row in rows]
        require(len(set(keys)) == len(keys), 'Duplicate immutable package receipts')
        for version in VERSIONS:
            candidates = [row for row in rows if row['identity']['sdkVersion'] == version]
            require(candidates, 'Missing published ' + channel + ' SDK ' + version)
            receipt = max(candidates, key=lambda row: row['identity']['packageRevision'])
            identity = receipt['identity']
            require(receipt.get('schemaVersion') == 1 and receipt.get('repository') == REPOSITORY
                    and receipt.get('status') == 'published-postverified' and receipt.get('publicationAllowed') is True
                    and identity.get('channel') == channel and type(identity.get('packageRevision')) is int
                    and identity['packageRevision'] > 0 and identity.get('sourceReleaseTag') == 'sdk-' + version
                    and identity.get('sourceManifestSha256') == contract['releases'][version]['manifestSha256'],
                    'Current receipt is not a qualified, admitted public package')
            if version == '10.0.403':
                require(identity['packageRevision'] >= (3 if channel == 'deb' else 2),
                        'All-eight coexistence requires SDK10 packages with legacy child-environment restoration')
            tag = release_tag(channel, version, identity['packageRevision'])
            base = f'https://github.com/{REPOSITORY}/releases/download/{tag}/'
            require(receipt.get('tag') == tag and receipt.get('manifestUrl') == base + MANIFEST
                    and receipt.get('signatureUrl') == base + SIGNATURE
                    and re.fullmatch(r'[a-f0-9]{64}', receipt.get('manifestSha256', '')),
                    'Noncanonical current receipt identity or source URL')
            verification = receipt.get('postVerification', {})
            validate_postverification(policy, [receipt], verification.get('reports', []))
            proof = verification.get('workflow', {})
            require(re.fullmatch(r'[a-f0-9]{40}', proof.get('commit', ''))
                    and re.fullmatch(r'[1-9][0-9]*', str(proof.get('runId', '')))
                    and re.fullmatch(r'[1-9][0-9]*', str(proof.get('runAttempt', '')))
                    and proof.get('url') == f'https://github.com/{REPOSITORY}/actions/runs/{proof["runId"]}/attempts/{proof["runAttempt"]}',
                    'Current receipt lacks exact completed native publication provenance')
            selected.append(receipt)
    return selected


def asset_map(rows):
    require(isinstance(rows, list), 'Signed asset descriptors are required')
    result = {}
    for row in rows:
        require(set(row) == {'name', 'size', 'sha256'} and re.fullmatch(r'[A-Za-z0-9._+-]+', row['name'])
                and type(row['size']) is int and row['size'] > 0
                and re.fullmatch(r'[a-f0-9]{64}', row['sha256']) and row['name'] not in result,
                'Invalid or duplicated signed asset descriptor')
        result[row['name']] = row
    return result


def verified_manifest(receipt, manifest, directory, signer, source, policy, contract):
    identity = receipt['identity']
    channel, version = identity['channel'], identity['sdkVersion']
    require(manifest.get('schemaVersion') == 1 and manifest.get('status') == 'validated-complete-matrix'
            and manifest.get('repository') == REPOSITORY and manifest.get('identity') == identity
            and manifest.get('tag') == receipt['tag'] and manifest.get('contractVersion') == contract['schemaVersion']
            and signer == manifest.get('signingFingerprint') == receipt.get('signingFingerprint'),
            'Signed package publication identity or signer changed')
    assets = asset_map(manifest['assets'])
    expected = {(row['variant'], row['architecture']) for row in policy['channels'][channel]['candidateMatrix']}
    actual = []
    for entry in manifest['records']:
        record = entry['record']; arch = record['architecture']; row = record['identity']
        actual.append((row['variant'], arch))
        require(all(row.get(key) == value for key, value in identity.items()) and arch in ARCHITECTURES
                and row.get('targetRid') == ARCHITECTURES[arch]['rid']
                and record.get('producer') == source['architectures'][arch]['provenance']
                and all(record['source'].get(key) == source['architectures'][arch][key] for key in ('sdk', 'source', 'evidence'))
                and record['source'].get('sourceManifestUrl') == source['manifestUrl'],
                'Signed package source/producer differs from the qualified public SDK')
        artifact = assets.get(entry['artifactAsset'], {})
        require(all(artifact.get(key) == record['artifact'].get(key) for key in ('size', 'sha256')),
                'Signed package artifact differs from its qualified installation record')
    require(len(actual) == len(set(actual)) and set(actual) == expected, 'Incomplete or duplicated signed package matrix')
    base = receipt['manifestUrl'].removesuffix(MANIFEST)
    expected_assets = [*assets.values(), descriptor(directory / MANIFEST), descriptor(directory / SIGNATURE)]
    supplied = receipt.get('assets', [])
    require(len(supplied) == len(expected_assets)
            and sorted(supplied, key=lambda row: row['name']) == sorted(
                [dict(row, url=base + row['name']) for row in expected_assets], key=lambda row: row['name'])
            and receipt.get('publications') == publication_rows(manifest, receipt['manifestSha256'], base)
            and receipt.get('repositories') == manifest.get('repositories'),
            'Receipt assets, targets or repositories differ from the authenticated manifest')
    repositories = manifest.get('repositories', [])
    for variant in contract['channels'][channel]['variants']:
        matches = [row for row in repositories if row.get('kind') == ('apt-repository' if channel == 'deb' else 'rpm-repository')
                   and row.get('variants') == [variant]]
        require(len(matches) == 1 and matches[0].get('asset') in assets, 'Missing exact signed repository variant')
        if channel == 'deb':
            from apt_release import release_tag as apt_tag
            row = matches[0]
            require(row.get('delivery') == 'github-release-flat'
                    and row.get('releaseTag') == apt_tag(variant, version, identity['packageRevision']),
                    'Aggregate qualification requires the current immutable flat APT publication')
            flat = asset_map(row.get('flatAssets'))
            require({'InRelease', 'Release', 'Release.gpg', 'Packages', 'Packages.gz', 'repository-manifest.json',
                     'cbodotnet-archive-keyring.gpg'} <= set(flat), 'Incomplete signed flat APT repository')
    return manifest


def fetch(url, path, maximum=16 * 1024**2, expected=None, api=False):
    data = get_bytes(url, maximum, token=(os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')) if api else None, api=api)
    if expected:
        require(len(data) == expected['size'] and hashlib.sha256(data).hexdigest() == expected['sha256'],
                'Public package metadata bytes differ from their signed descriptor')
    Path(path).write_bytes(data)
    return data


def preflight(directory, *, receive=False, policy=None, contract=None, catalog=None):
    policy = policy or load_status(); contract = contract or load_contract()
    selected = selected_receipts(policy, contract)
    directory = Path(directory)
    if receive:
        require(not directory.exists(), 'Fresh preflight directory required')
        directory.mkdir(parents=True)
    require(directory.is_dir() and not directory.is_symlink(), 'Ordinary authenticated preflight directory required')
    catalog = catalog or load(ROOT / 'releases/qualified-builds.json')
    sources = {}
    for version in VERSIONS:
        location = directory / 'sources' / version
        if receive:
            location.mkdir(parents=True)
            fetch(f'https://api.github.com/repos/{REPOSITORY}/releases/tags/sdk-{version}', location / 'release.json', api=True)
            base = f'https://github.com/{REPOSITORY}/releases/download/sdk-{version}/'
            fetch(base + 'release-manifest.json', location / 'release-manifest.json', 8 * 1024**2)
            fetch(base + 'SHA256SUMS', location / 'SHA256SUMS', 64 * 1024)
        raw = (location / 'release-manifest.json').read_bytes()
        require(hashlib.sha256(raw).hexdigest() == contract['releases'][version]['manifestSha256'], 'Pinned public SDK manifest changed')
        source = validate_release(load(location / 'release.json'), raw, (location / 'SHA256SUMS').read_bytes(), REPOSITORY)
        require(source['sdkVersion'] == version, 'Source SDK identity changed')
        validate_qualified_producers(source, contract['releases'][version]['target'], catalog)
        sources[version] = source
    rows = []
    with tempfile.TemporaryDirectory(prefix='cbodotnet-coexistence-key-') as temporary:
        keyring = Path(temporary) / 'trusted.gpg'
        run(['gpg', '--batch', '--yes', '--dearmor', '--output', keyring, ROOT / 'releases/downstream-signing-key.asc'])
        for receipt in selected:
            identity = receipt['identity']; channel = identity['channel']; version = identity['sdkVersion']
            location = directory / channel / version
            if receive:
                location.mkdir(parents=True)
                fetch(receipt['manifestUrl'], location / MANIFEST)
                fetch(receipt['signatureUrl'], location / SIGNATURE, 1024**2)
            require(APT.digest(location / MANIFEST) == receipt['manifestSha256'], 'Pinned public distribution manifest changed')
            signer = verify_report_signature(location / MANIFEST, location / SIGNATURE, keyring, policy,
                '.github/workflows/distribution-release.yml', historical=True)
            manifest = verified_manifest(receipt, load(location / MANIFEST), location, signer, sources[version], policy, contract)
            rows.append(dict(channel=channel, sdkVersion=version, packageRevision=identity['packageRevision'],
                manifestSha256=receipt['manifestSha256'], signingFingerprint=signer,
                sourceManifestSha256=identity['sourceManifestSha256'], manifest=manifest))
    result = dict(schemaVersion=1, status='authenticated-inputs-only', publicationAllowed=False,
        versions=list(VERSIONS), sourceCatalogSha256=hashlib.sha256(encoded(catalog)).hexdigest(), publications=rows)
    if receive:
        save(directory / 'verified-plan.json', result)
    else:
        require(load(directory / 'verified-plan.json') == result, 'Frozen aggregate inputs differ from current source/publication policy')
    return result


def target_rows(plan, variant):
    channel = TARGETS[variant]
    rows = [row for row in plan['publications'] if row['channel'] == channel]
    require([row['sdkVersion'] for row in rows] == list(VERSIONS), 'Aggregate target lacks all eight exact SDKs')
    return rows


def check_container(variant, arch, offline=False):
    require(os.geteuid() == 0 and Path('/.dockerenv').is_file(), 'Disposable root Docker container required')
    require(platform.machine() in ({'x86_64'} if arch == 'x64' else {'aarch64', 'arm64'}), 'Matching native CPU required')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    expected = load_contract()['operatingSystems'][variant]
    require(release.get('ID', '').strip('"') == expected['id'] and release.get('VERSION_ID', '').strip('"') == expected['versionId'],
            'Aggregate container OS/version differs from reviewed target')
    if TARGETS[variant] == 'deb':
        require(run(['dpkg', '--print-architecture']).strip() == ARCHITECTURES[arch]['deb'], 'Wrong native DPKG architecture')
    else:
        require(run(['rpm', '--eval', '%{_arch}']).strip() == ARCHITECTURES[arch]['rpm'], 'Wrong native RPM architecture')
    if offline:
        require({path.name for path in Path('/sys/class/net').iterdir()} == {'lo'}, 'Aggregate runtime/removal proof requires --network none')


def user_run(arguments, cwd=None):
    # Deliberately begin without compatibility variables. Each wrapper must scope
    # its own provider and restore this environment before invoking another SDK.
    return run(['runuser', '-u', USER, '--', 'env', '-i', 'PATH=/usr/local/bin:/usr/bin:/bin',
        'HOME=/home/' + USER, 'DOTNET_CLI_HOME=/home/' + USER, 'NUGET_PACKAGES=/home/' + USER + '/.nuget/packages',
        'DOTNET_CLI_TELEMETRY_OPTOUT=1', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1', 'DOTNET_NOLOGO=1',
        'DOTNET_CLI_UI_LANGUAGE=en', 'LC_ALL=C', *arguments], cwd=cwd or '/home/' + USER)


def public_repository(row, variant):
    matching = [item for item in row['manifest']['repositories'] if item['variants'] == [variant]]
    require(len(matching) == 1, 'One signed repository is required for each aggregate SDK')
    return matching[0]


def prepare_apt(rows, variant, arch, state, keyring):
    architecture = ARCHITECTURES[arch]['deb']; packages = {}
    for row in rows:
        version, revision = row['sdkVersion'], row['packageRevision']
        repository = public_repository(row, variant)
        from apt_release import repository_url
        base = repository_url(variant, version, revision).rstrip('/')
        assets = asset_map(repository['flatAssets'])
        location = state / version; location.mkdir()
        for name in ('InRelease', 'Packages'):
            fetch(base + '/' + name, location / name, expected=assets[name])
        release = run(['gpgv', '--keyring', keyring, '--output', '-', location / 'InRelease'])
        raw = (location / 'Packages').read_bytes()
        APT.verify_packages_index(release, raw)
        descriptors = APT.package_descriptors(raw, version, revision, architecture, flat=True)
        for item in descriptors:
            item = dict(item, url=base + '/' + item['filename'])
            signed = assets.get(item['filename'].removeprefix('./'))
            require(signed is not None and all(signed[key] == item[key] for key in ('size', 'sha256')),
                    'APT package index differs from the signed immutable repository asset')
            key = (item['package'], item['version'], item['architecture'])
            require(key not in packages or all(packages[key][field] == item[field] for field in ('size', 'sha256')),
                    'Shared package NEVRA has different bytes across SDK repositories')
            packages[key] = item
        Path('/etc/apt/sources.list.d/cbodotnet-' + series(version) + '.sources').write_text(
            APT.deb822_source(base, architecture, version, revision, variant).replace(APT.KEYRING, str(keyring)))
    run(['apt-get', 'update'])
    wanted = [name + '=' + version for name, version, _ in packages]
    run(['apt-get', 'install', '-y', '--no-install-recommends', '--download-only', *wanted])
    for (name, version, architecture), item in packages.items():
        path = Path('/var/cache/apt/archives') / (name + '_' + version + '_' + architecture + '.deb')
        APT.verify_cache_file(path, item)
    run(['apt-get', 'install', '-y', '--no-install-recommends', *wanted])
    return list(packages.values())


def prepare_rpm(rows, variant, arch, state, keyring):
    from rpm_repository import verify_repository
    allowed = {}; expected = {}
    key = state / 'rpm-signing-key.asc'
    key.write_bytes((ROOT / 'releases/downstream-signing-key.asc').read_bytes())
    run(['rpmkeys', '--import', key])
    for row in rows:
        version, revision = row['sdkVersion'], row['packageRevision']; manifest = row['manifest']
        repository = public_repository(row, variant); assets = asset_map(manifest['assets'])
        base = f'https://github.com/{REPOSITORY}/releases/download/{manifest["tag"]}/'
        archive = state / (version + '.tar.gz')
        fetch(base + repository['asset'], archive, 16 * 1024**2, assets[repository['asset']])
        location = state / version
        extract_repository(archive, location)
        metadata = verify_repository(location, keyring, assets, base)
        public = RPM.hosted_repository_url('https://dotnetdev.kr/cbodotnet/packages/rpm', variant, version, revision)
        for name in ('repomd.xml', 'repomd.xml.asc'):
            expected_file = location / 'repodata' / name
            observed = location / ('live-' + name)
            fetch(public + '/repodata/' + name, observed, expected=descriptor(expected_file))
        repo_id = 'cbodotnet-' + series(version)
        Path('/etc/yum.repos.d/' + repo_id + '.repo').write_text('[' + repo_id + ']\nname=Community SDK ' + version
            + '\nbaseurl=' + public + '/\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file://' + str(key) + '\n')
        suffix = '.cbot.' + variant.replace('-', '')
        expected['cbodotnet-sdk-' + series(version)] = (version, str(revision) + suffix, ARCHITECTURES[arch]['rpm'])
        expected['cbodotnet-host'] = ('1.0.0', '1' + suffix, 'noarch')
        if series(version) in {'3.0', '3.1', '5.0'}:
            from legacy_compat import PACKAGE_NAME, VERSION
            expected[PACKAGE_NAME] = (VERSION, '1' + suffix, ARCHITECTURES[arch]['rpm'])
        if series(version) in {'3.0', '3.1'}:
            from legacy_curl import PACKAGE_NAME, VERSION
            expected[PACKAGE_NAME] = (VERSION, '1' + suffix, ARCHITECTURES[arch]['rpm'])
        for filename in metadata['packages']:
            item = assets[filename]
            allowed.setdefault((item['size'], item['sha256']), []).append(base + filename)
    wanted = [name + '-' + version + '-' + release + '.' + architecture
              for name, (version, release, architecture) in expected.items()]
    run(['dnf', '-y', '--refresh', '--setopt=gpgcheck=1', '--setopt=keepcache=True',
         '--setopt=install_weak_deps=False', '--setopt=tsflags=', 'install', *wanted])
    selected = {}
    for path in sorted(Path('/var/cache').rglob('*.rpm')):
        fields = run(['rpm', '-qp', '--queryformat', '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}', path]).strip().split('\t')
        require(len(fields) == 4, 'Malformed cached RPM header')
        name = fields[0]
        if name not in expected:
            continue
        require(tuple(fields[1:]) == expected[name], 'Cached public RPM has another package identity')
        item = dict(package=name, version=fields[1], release=fields[2], architecture=fields[3], size=path.stat().st_size, sha256=APT.digest(path))
        require((item['size'], item['sha256']) in allowed, 'DNF downloaded bytes absent from signed publication manifests')
        require(name not in selected or item == selected[name], 'Shared cached RPM identity has conflicting bytes')
        RPM.verify_package_signature(path)
        selected[name] = item
    require(set(selected) == set(expected), 'Every installed Community RPM needs an authenticated cached signature proof')
    return list(selected.values())


def integrity(packages, channel):
    names = [item['package'] for item in packages]
    if channel == 'rpm':
        RPM.strict_integrity(names)
    else:
        require(not run(['dpkg', '-V', *names]).strip(), 'Installed aggregate Debian package integrity failed')


def installed_identity(row, variant, arch, default=False):
    version = row['sdkVersion']; command = 'cbodotnet' if default else 'cbodotnet-' + series(version)
    root = '/opt/cbodotnet/' + series(version)
    output = user_run([command, '--cbodotnet-info']); info = json.loads(output)
    require(info['sdkVersion'] == version and info['sdkRoot'] == root and info['packageRevision'] == row['packageRevision']
            and info['sourceManifestSha256'] == row['sourceManifestSha256'] and info['targetRid'] == ARCHITECTURES[arch]['rid']
            and info['qualifiedPayloadModified'] is False, 'Versioned/default selection escaped its exact public SDK identity')
    require(user_run([command, '--list-sdks']).splitlines() == [version + ' [' + root + '/sdk]'], 'Alias resolved another SDK root')
    result = subprocess.run(['runuser', '-u', USER, '--', 'env', '-i', 'PATH=/usr/bin:/bin', 'HOME=/home/' + USER,
        'DOTNET_NOLOGO=1', 'DOTNET_CLI_TELEMETRY_OPTOUT=1', command, '--version'], capture_output=True, text=True)
    require(result.returncode == 0 and result.stdout == version + '\n' and result.stderr == BRAND + '\n', 'CLI numeric version or branding changed')
    details = user_run([command, '--info'])
    require(details.startswith(BRAND + '\n') and root in details, 'Community info branding/root changed')
    validate_host_rid(details, version, arch, variant)
    package = 'cbodotnet-sdk-' + series(version)
    path = '/usr/bin/cbodotnet' if default else '/usr/bin/cbodotnet-' + series(version)
    owner = run(['dpkg-query', '-S', path]).split(': ', 1)[0] if TARGETS[variant] == 'deb' else run(['rpm', '-qf', '--queryformat', '%{NAME}', path]).strip()
    require(owner == ('cbodotnet-host' if default else package), 'Shared/versioned command ownership changed')
    return info


def install(args):
    check_container(args.variant, args.arch)
    plan = preflight(args.preflight); rows = target_rows(plan, args.variant)
    state = args.workspace; require(not state.exists(), 'Fresh installed aggregate state required'); state.mkdir()
    run(['useradd', '--create-home', '--uid', '10001', USER])
    if TARGETS[args.variant] == 'deb':
        from apt_official import bootstrap, public_summary, assert_unchanged
        Path('/etc/dpkg/dpkg.cfg.d/zz-cbodotnet-validation').write_text('path-include=/usr/share/doc/cbodotnet-*\n'
            'path-include=/usr/share/doc/dotnet-*\npath-include=/usr/share/doc/aspnetcore-*\npath-include=/usr/share/doc/netstandard-*\n')
    else:
        from rpm_official import bootstrap, public_summary, assert_unchanged
    official = public_summary(bootstrap(args.variant, args.arch, USER, state / 'official-state.json'))
    keyring = state / 'trusted.gpg'
    run(['gpg', '--batch', '--yes', '--dearmor', '--output', keyring, ROOT / 'releases/downstream-signing-key.asc'])
    keyring.chmod(0o644)
    print('published-sdk-coexistence: install all eight authenticated public SDKs on ' + args.variant, flush=True)
    packages = (prepare_apt if TARGETS[args.variant] == 'deb' else prepare_rpm)(rows, args.variant, args.arch, state, keyring)
    integrity(packages, TARGETS[args.variant])
    from downstream_release import require_published_provider_roots
    require_published_provider_roots(dict(sdkVersion='3.0.103'))
    from legacy_compat import provision
    compatibility = provision(dict(sdkVersion='3.0.103', variant=args.variant, architecture=dict(public=args.arch)), state, user=USER)
    import legacy_curl
    native_http = legacy_curl.provision(dict(sdkVersion='3.0.103', variant=args.variant,
        architecture=dict(public=args.arch)), state, user=USER)
    roots = {row['sdkVersion']: APT.inventory(Path('/opt/cbodotnet') / series(row['sdkVersion'])) for row in rows}
    identities = [installed_identity(row, args.variant, args.arch) for row in rows]
    installed_identity(rows[0], args.variant, args.arch, default=True)
    save(state / 'installed.json', dict(packages=packages, inventories=roots, identities=identities,
        officialBaseline=official, officialStages=[dict(stage='all-eight-installed', result=assert_unchanged(state / 'official-state.json'))],
        compatibilityState=compatibility, nativeHttpState=native_http))


def nested_environment_script():
    """A real Core3 process invokes the modern wrapper without changing its env."""
    work = '/home/' + USER + '/nested-modern'
    modern = smoke_script(VERSIONS[0], '/opt/cbodotnet/10.0', USER, cli='cbodotnet-10.0', workdir=work)
    original = smoke_program('/opt/cbodotnet/10.0', USER, 'net10.0')
    assertion = ('if(new[]{"LD_LIBRARY_PATH","OPENSSL_CONF","CLR_OPENSSL_VERSION_OVERRIDE","CLR_ICU_VERSION_OVERRIDE",'
                 '"SSL_CERT_FILE","CBODOTNET_COMPAT_SCOPE"}.Any(name=>Environment.GetEnvironmentVariable(name)!=null)'
                 ' || Environment.GetEnvironmentVariables().Keys.Cast<string>().Any(name=>name.StartsWith("CBODOTNET_COMPAT_SAVED_")))'
                 ' throw new Exception("Legacy environment leaked into modern child");\n')
    marker = ' public static async Task Main(string[] args) {\n'
    require(marker in original, 'Shared modern smoke entry point changed')
    modern = modern.replace(original, original.replace(marker, marker + assertion))
    parent = '''using System; using System.Diagnostics;
public static class Program { public static void Main() {
 if(Environment.GetEnvironmentVariable("CBODOTNET_COMPAT_SCOPE")!="rocky9" ||
    Environment.GetEnvironmentVariable("CLR_OPENSSL_VERSION_OVERRIDE")!="1.1" ||
    !typeof(object).Assembly.Location.StartsWith("/opt/cbodotnet/3.0/shared/")) throw new Exception("Parent did not enter legacy runtime/scope");
 var start=new ProcessStartInfo("/usr/bin/cbodotnet-10.0","CHILD dll") {
  UseShellExecute=false, RedirectStandardOutput=true, RedirectStandardError=true, WorkingDirectory="WORK" };
 using(var child=Process.Start(start)) { string output=child.StandardOutput.ReadToEnd(); string error=child.StandardError.ReadToEnd();
  child.WaitForExit(); if(child.ExitCode!=0 || !output.Contains("published-tls12-passed") ||
   !output.Contains("published-offline-dll-http-crypto-icu-passed")) throw new Exception("Modern child failed: "+output+error);
 }
 Console.WriteLine("legacy-to-modern-child-environment-tls-passed");
} }
'''.replace('CHILD', work + '/bin/Debug/net10.0/Smoke.dll').replace('WORK', work)
    legacy = '/home/' + USER + '/nested-legacy'
    return modern + '\nmkdir -p ' + legacy + '\ncd ' + legacy + '''
cat > global.json <<'GLOBAL'
{"sdk":{"version":"3.0.103","rollForward":"disable"}}
GLOBAL
cat > NuGet.Config <<'NUGET'
<configuration><packageSources><clear /></packageSources></configuration>
NUGET
cat > Parent.csproj <<'PROJECT'
<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>netcoreapp3.0</TargetFramework></PropertyGroup></Project>
PROJECT
cat > Program.cs <<'PROGRAM'
''' + parent + '''PROGRAM
cbodotnet-3.0 restore --configfile NuGet.Config
cbodotnet-3.0 build --no-restore
cbodotnet-3.0 bin/Debug/netcoreapp3.0/Parent.dll
'''


def smoke(args):
    check_container(args.variant, args.arch, offline=True)
    rows = target_rows(preflight(args.preflight), args.variant); state = load(args.workspace / 'installed.json')
    if TARGETS[args.variant] == 'deb':
        from apt_official import assert_unchanged
    else:
        from rpm_official import assert_unchanged
    from legacy_compat import assert_unchanged as provider_unchanged, runtime_environment
    import legacy_curl
    observations = []; provider_stages = []; native_http_stages = []

    def baseline(stage):
        state['officialStages'].append(dict(stage=stage, result=assert_unchanged(args.workspace / 'official-state.json')))
        provider_stages.append(dict(stage=stage, result=provider_unchanged(state['compatibilityState'])))
        native_http_stages.append(dict(stage=stage, result=legacy_curl.assert_unchanged(state['nativeHttpState'])))

    for row in rows:
        version = row['sdkVersion']; root = '/opt/cbodotnet/' + series(version)
        print('published-sdk-coexistence: offline runtime ' + version, flush=True)
        environment = runtime_environment(dict(sdkVersion=version, variant=args.variant, architecture=dict(public=args.arch)),
            state['compatibilityState']) if series(version) in {'3.0', '3.1', '5.0'} else {}
        native_curl = None
        if series(version) in {'3.0', '3.1'}:
            native_plan = dict(sdkVersion=version, variant=args.variant, channel=TARGETS[args.variant],
                architecture=dict(public=args.arch))
            environment = legacy_curl.runtime_environment(native_plan, state['nativeHttpState'], base_environment=environment)
            from sdk_runtime import forced_curl_script, validate_forced_curl_output
            output = user_run(['sh', '-ec', forced_curl_script(version, root, USER, cli='cbodotnet-' + series(version),
                workdir='/home/' + USER + '/curl-' + series(version), runtime_env=environment,
                curl_root=legacy_curl.PROVIDER_ROOT, user_id=10001)])
            native_curl = validate_forced_curl_output(output, version, root, legacy_curl.PROVIDER_ROOT, 10001, args.arch)
        output = user_run(['sh', '-ec', smoke_script(version, root, USER, cli='cbodotnet-' + series(version),
            workdir='/home/' + USER + '/smoke-' + series(version), runtime_env=environment)])
        checks = validate_smoke_output(output)
        require(APT.inventory(Path(root)) == state['inventories'][version], 'Offline execution changed a public SDK payload')
        observations.append(dict(sdkVersion=version, identity=installed_identity(row, args.variant, args.arch), functionalChecks=checks,
            inventory=state['inventories'][version]))
        if native_curl:
            observations[-1]['nativeCurlHandler'] = native_curl
    installed_identity(rows[0], args.variant, args.arch, default=True)
    nested = user_run(['sh', '-ec', nested_environment_script()])
    require('legacy-to-modern-child-environment-tls-passed' in nested, 'Genuine legacy-to-modern child transition did not pass')
    baseline('all-eight-offline-runtime-and-nested-tls')
    integrity(state['packages'], TARGETS[args.variant])
    fallback = []
    remaining = list(rows)
    while remaining:
        removed = remaining.pop(0); version = removed['sdkVersion']; package = 'cbodotnet-sdk-' + series(version)
        print('published-sdk-coexistence: remove ' + version + ' and verify selector fallback', flush=True)
        if TARGETS[args.variant] == 'deb':
            run(['apt-get', 'remove', '-y', package])
        else:
            run(['dnf', '-y', *RPM.repository_options(), '--setopt=clean_requirements_on_remove=False', 'remove', package])
        require(not Path('/opt/cbodotnet', series(version)).exists()
                and not Path('/usr/bin/cbodotnet-' + series(version)).exists(), 'Removed SDK left an executable/payload')
        require(Path('/usr/bin/cbodotnet').is_file(), 'SDK removal damaged the shared selector')
        if remaining:
            selection = installed_identity(remaining[0], args.variant, args.arch, default=True)
            for row in remaining:
                installed_identity(row, args.variant, args.arch)
                require(APT.inventory(Path('/opt/cbodotnet', series(row['sdkVersion']))) == state['inventories'][row['sdkVersion']],
                        'Removing another SDK changed a remaining public payload')
        else:
            absent = subprocess.run(['runuser', '-u', USER, '--', 'cbodotnet', '--version'], capture_output=True, text=True)
            require(absent.returncode == 127 and not absent.stdout, 'Empty Community selector fell back to official dotnet')
            selection = None
        fallback.append(dict(removed=version, selected=selection, status='passed'))
        baseline('removed-' + version)
        removed_packages = {'cbodotnet-sdk-' + series(row['sdkVersion']) for row in rows if row not in remaining}
        integrity([item for item in state['packages'] if item['package'] not in removed_packages], TARGETS[args.variant])
    if TARGETS[args.variant] == 'deb':
        run(['apt-get', 'purge', '-y', *['cbodotnet-sdk-' + series(version) for version in VERSIONS],
             'cbodotnet-host', 'cbodotnet-compat-rocky9', legacy_curl.PACKAGE_NAME])
    else:
        run(['dnf', '-y', *RPM.repository_options(), '--setopt=clean_requirements_on_remove=False',
             'remove', 'cbodotnet-host', 'cbodotnet-compat-rocky9', legacy_curl.PACKAGE_NAME])
    require(not Path('/usr/bin/cbodotnet').exists() and not Path('/usr/lib/cbodotnet/compat/rocky9').exists()
            and not Path(legacy_curl.PROVIDER_ROOT).exists(), 'Community shared package purge left managed runtime files')
    state['officialStages'].append(dict(stage='all-community-packages-purged', result=assert_unchanged(args.workspace / 'official-state.json')))
    result = dict(schemaVersion=1, status='passed', scope='published-eight-sdk-coexistence-observation', publicationAllowed=False,
        variant=args.variant, architecture=args.arch, channel=TARGETS[args.variant], networkForBuild='none', versions=list(VERSIONS),
        sources=[{key: row[key] for key in ('sdkVersion', 'packageRevision', 'manifestSha256', 'sourceManifestSha256', 'signingFingerprint')} for row in rows],
        authenticatedPackages=state['packages'], sdkObservations=observations, selectorFallback=fallback,
        legacyToModernChildEnvironmentAndTls='passed', officialBaseline=state['officialBaseline'], officialStages=state['officialStages'],
        compatibilityProvider=provider_stages, nativeHttpCompatibilityProvider=native_http_stages,
        checks=['all-eight-public-package-installation', 'signed-source-and-producer-pins',
            'sdk10-default-selection', 'all-versioned-alias-roots', 'non-root-offline-tfm-crypto-icu-http-tls',
            'legacy-to-modern-child-environment-restoration', 'descending-removal-selector-fallback', 'official-package-baseline-unchanged',
            'unchanged-public-sdk-payloads', 'strict-package-integrity', 'shared-host-and-provider-purge'])
    save(args.workspace / 'report.json', result)


def bootstrap_script(variant):
    if TARGETS[variant] == 'deb':
        return ('set -eu\nexport DEBIAN_FRONTEND=noninteractive\napt-get update -qq\n'
            'apt-get install -y --no-install-recommends python3 curl ca-certificates util-linux passwd binutils gnupg gpgv rpm rpm2cpio\n')
    return ('set -eu\nexport PATH=/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin\n'
        'dnf -y --setopt=install_weak_deps=False --setopt=tsflags= install python3 rpm-build rpm-sign cpio tar gzip xz shadow-utils util-linux '
        + ('curl-minimal' if variant == 'rocky-9.8' else 'curl') + ' ca-certificates binutils findutils gnupg2\n'
        + ('dnf -y install python3.12\nmkdir -p /usr/local/bin\nln -s /usr/bin/python3.12 /usr/local/bin/python3\n' if variant == 'rocky-9.8' else ''))


def native(args):
    # Authentication deliberately precedes every Docker invocation.
    preflight(args.preflight)
    require(args.variant in TARGETS and args.arch in ARCHITECTURES
            and platform.machine() in ({'x86_64'} if args.arch == 'x64' else {'aarch64', 'arm64'}), 'Exact native aggregate target required')
    workspace = args.workspace.resolve(); require(not workspace.exists(), 'Fresh aggregate workspace required'); workspace.mkdir(parents=True)
    cid = image = None
    common = ['--variant', args.variant, '--arch', args.arch, '--preflight', '/preflight', '--workspace', '/delivery/installed']
    mounts = ['-v', f'{ROOT}:/repo:ro', '-v', f'{args.preflight.resolve()}:/preflight:ro', '-v', f'{workspace}:/delivery']
    command = ['python3', '/repo/scripts/published-sdk-coexistence.py']
    try:
        script = bootstrap_script(args.variant) + 'exec ' + shlex.join(command + ['install', *common])
        cid = run(['docker', 'create', '--user', '0', *mounts, BASES[args.variant][args.arch], 'sh', '-ec', script]).strip()
        run(['docker', 'start', '--attach', cid])
        require(json.loads(run(['docker', 'inspect', cid]))[0]['State']['ExitCode'] == 0, 'Aggregate public package installation failed')
        image = run(['docker', 'commit', cid]).strip()
        run(['docker', 'run', '--rm', '--network', 'none', '--user', '0', *mounts, image, *command, 'smoke', *common])
        result = load(workspace / 'installed/report.json')
        require(result['status'] == 'passed', 'Aggregate SDK observation failed')
        save(workspace / 'report.json', result)
    finally:
        if cid:
            subprocess.run(['docker', 'rm', '--force', cid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if image:
            subprocess.run(['docker', 'image', 'rm', image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('prepare'); command.add_argument('--workspace', type=Path, required=True)
    for phase in ('native', 'install', 'smoke'):
        command = commands.add_parser(phase)
        command.add_argument('--preflight', type=Path, required=True); command.add_argument('--workspace', type=Path, required=True)
        command.add_argument('--variant', choices=tuple(TARGETS), required=True)
        command.add_argument('--arch', choices=tuple(ARCHITECTURES), required=True)
    args = parser.parse_args()
    if args.command == 'prepare':
        result = preflight(args.workspace, receive=True)
        print(json.dumps(dict(status=result['status'], versions=result['versions'], publications=len(result['publications']))))
    else:
        {'native': native, 'install': install, 'smoke': smoke}[args.command](args)
