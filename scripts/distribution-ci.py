#!/usr/bin/env python3
"""Exercise real downstream installations and promote their verified CI outputs."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

from distribution_contract import load_contract
from downstream_release import encoded, local_intake, package_record, receive_release, PREPUBLICATION_CHECKS
from downstream_release import stage_records

ROOT = Path(__file__).resolve().parents[1]
DEBIAN_BASE = 'debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4'
UBUNTU_BASE = 'ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852'
BRAND = 'Community Build of .NET (built by .NET Dev)'


def require(value, message):
    if not value:
        raise ValueError(message)


def run(command, *, cwd=None, env=None, input=None):
    result = subprocess.run([str(item) for item in command], cwd=cwd, env=env, input=input,
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise RuntimeError('Command failed: ' + str(command[0]) + '\n' + result.stdout[-6000:] + result.stderr[-6000:])
    return result.stdout


def digest(path, algorithm='sha256'):
    value = hashlib.new(algorithm)
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def inventory(root):
    value = {}
    for path in sorted(Path(root).rglob('*')):
        mode = stat.S_IMODE(path.lstat().st_mode)
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            value[name] = ['link', mode, os.readlink(path)]
        elif path.is_file():
            value[name] = ['file', mode, digest(path)]
        elif path.is_dir():
            value[name] = ['directory', mode]
        else:
            raise ValueError('Unexpected installation object: ' + name)
    return value


def extractor():
    spec = importlib.util.spec_from_file_location('coexistence_extract', ROOT / 'scripts/test-distribution-coexistence.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.extract_sdk


def official_archive(directory, arch):
    directory = Path(directory)
    url = 'https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/10.0/releases.json'
    with urllib.request.urlopen(url, timeout=60) as response:
        metadata = json.load(response)
    rid = 'linux-arm64' if arch == 'aarch64' else 'linux-x64'
    candidates = [item for release in metadata['releases'] for sdk in release.get('sdks', [])
                  if sdk['version'] == '10.0.100' for item in sdk['files']
                  if item['rid'] == rid and item['name'].endswith('.tar.gz')]
    require(len({item['url'] for item in candidates}) == 1, 'Ambiguous official comparison SDK')
    item = candidates[0]
    path = directory / 'official-sdk.tar.gz'
    if not path.exists():
        urllib.request.urlretrieve(item['url'], path)
    require(digest(path, 'sha512') == item['hash'].lower(), 'Official comparison SDK checksum mismatch')
    (directory / 'official-source.json').write_bytes(encoded(dict(version='10.0.100', url=item['url'], sha512=item['hash'])))
    return path


def user_command(arguments, directory):
    return ['runuser', '-u', 'cbot-smoke', '--', 'env', 'HOME=/home/cbot-smoke',
            'DOTNET_CLI_HOME=/home/cbot-smoke', 'NUGET_PACKAGES=/home/cbot-smoke/.nuget/packages',
            'DOTNET_CLI_TELEMETRY_OPTOUT=1', 'DOTNET_NOLOGO=1', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1',
            'DOTNET_CLI_UI_LANGUAGE=en', 'LC_ALL=C', *map(str, arguments)]


def installed(args):
    require(os.geteuid() == 0, 'Installation tests require a disposable root container')
    delivery = args.delivery.resolve()
    plan = json.loads((delivery / 'plan.json').read_bytes())
    architecture = plan['architecture']['public']
    require(platform.machine() in ({'aarch64', 'arm64'} if architecture == 'aarch64' else {'x86_64'}), 'Native architecture mismatch')
    os_release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    expected_os = load_contract()['operatingSystems'][args.variant]
    require(os_release['ID'].strip('"') == expected_os['id'] and os_release['VERSION_ID'].strip('"') == expected_os['versionId'],
            'Installation executed on another OS/version')
    run(['useradd', '--create-home', '--uid', '10001', 'cbot-smoke'])
    official = Path('/usr/share/dotnet')
    require(not official.exists(), 'Comparison official root must be fresh')
    official.parent.mkdir(parents=True, exist_ok=True)
    extractor()(Path('/delivery/official-sdk.tar.gz'), official)
    (official / 'metadata').mkdir(exist_ok=True)
    if not Path('/usr/bin/dotnet').exists():
        Path('/usr/bin/dotnet').symlink_to(official / 'dotnet')
    work = Path('/home/cbot-smoke/project')
    work.mkdir()
    run(['chown', '-R', 'cbot-smoke:cbot-smoke', str(work)])

    def as_user(command, cwd=work):
        return run(user_command(command, cwd), cwd=cwd)

    require(as_user([official / 'dotnet', '--version']).strip() == '10.0.100', 'Official comparison SDK failed')
    official_before = inventory(official)
    sdk = Path(plan['package']['root'])
    if args.mode == 'deb':
        packages = sorted((delivery / 'packages').glob('*.deb'))
        require(len(packages) == 2, 'Both SDK and shared host packages are required')
        run(['apt-get', 'install', '-y', *map(str, packages)])
    require(sdk.is_dir(), 'Installed SDK root is missing')
    expected = Path(tempfile.mkdtemp(prefix='cbot-payload-')) / 'sdk'
    extractor()(Path('/delivery/inputs') / plan['sdk']['name'], expected)
    for name in plan['additionalDirectories']:
        (expected / name).mkdir(mode=0o755, exist_ok=True)
    require(inventory(expected) == inventory(sdk), 'Installed SDK bytes/modes differ from qualified archive')
    shutil.rmtree(expected.parent)
    sdk_before = inventory(sdk)
    versioned = 'cbodotnet-' + '.'.join(plan['sdkVersion'].split('.')[:2])
    names = [versioned, 'cbodotnet'] + (['dotnet'] if args.mode == 'oci' else [])
    for name in names:
        result = subprocess.run(user_command([name, '--version'], work), cwd=work, text=True, capture_output=True)
        require(result.returncode == 0 and result.stdout == plan['sdkVersion'] + '\n' and result.stderr.strip() == BRAND,
                'Version stdout/branding mismatch: ' + name)
        info = as_user([name, '--info'])
        require(info.startswith(BRAND + '\n') and str(sdk) in info and plan['targetRid'] in info, 'Alias host/RID mismatch')
        identity = json.loads(as_user([name, '--cbodotnet-info']))
        require(identity['sourceManifestSha256'] == plan['sourceManifestSha256'] and identity['sdkVersion'] == plan['sdkVersion'],
                'Alias source provenance mismatch')
    (work / 'global.json').write_text(json.dumps({'sdk': {'version': plan['sdkVersion'], 'rollForward': 'disable'}}))
    (work / 'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>')
    (work / 'Smoke.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType>'
                                     '<TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>')
    (work / 'Program.cs').write_text('using System; using System.Globalization; using System.Security.Cryptography;\n'
                                    'Console.WriteLine(Environment.ProcessPath); Console.WriteLine(typeof(object).Assembly.Location);\n'
                                    'using var rsa = RSA.Create(); var b = RandomNumberGenerator.GetBytes(32);\n'
                                    'var s = rsa.SignData(b, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);\n'
                                    'if(!rsa.VerifyData(b,s,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1)) throw new Exception();\n'
                                    'Console.WriteLine(1234.5m.ToString("N1",CultureInfo.GetCultureInfo("fr-FR"))); Console.WriteLine("crypto-passed");')
    run(['chown', '-R', 'cbot-smoke:cbot-smoke', str(work)])
    as_user(['cbodotnet', 'restore', '--configfile', 'NuGet.Config'])
    as_user(['cbodotnet', 'build', '--no-restore'])
    output = as_user(['cbodotnet', work / 'bin/Debug/net10.0/Smoke.dll'])
    require(output.splitlines()[0] == str(sdk / 'dotnet') and str(sdk / 'shared') in output
            and 'crypto-passed' in output and '234,5' in output, 'Installed non-root application smoke failed')
    http = work / 'http'
    http.mkdir()
    (http / 'Http.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net10.0</TargetFramework>'
                                     '</PropertyGroup></Project>')
    (http / 'Program.cs').write_text('using Microsoft.AspNetCore.Builder; var b=WebApplication.CreateBuilder(args);'
                                    'var a=b.Build(); a.MapGet("/",()=>"cbodotnet-http-passed"); a.Run();')
    run(['chown', '-R', 'cbot-smoke:cbot-smoke', str(http)])
    as_user(['cbodotnet', 'restore', '--configfile', str(work / 'NuGet.Config')], http)
    as_user(['cbodotnet', 'build', '--no-restore'], http)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    log = (delivery / 'http.log').open('w')
    process = subprocess.Popen(user_command(['cbodotnet', http / 'bin/Debug/net10.0/Http.dll', '--urls', f'http://127.0.0.1:{port}'], http),
                               cwd=http, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        response = ''
        for _ in range(100):
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}', timeout=1) as incoming:
                    response = incoming.read().decode()
                break
            except OSError:
                time.sleep(.1)
        require(response == 'cbodotnet-http-passed', 'Installed ASP.NET loopback HTTP smoke failed')
    finally:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=15)
        log.close()
    require(inventory(sdk) == sdk_before, 'Installed execution modified qualified SDK payload')
    require(inventory(official) == official_before, 'cbodotnet modified the official installation')
    if args.mode == 'deb':
        require(as_user(['dotnet', '--version'], Path('/home/cbot-smoke')).strip() == '10.0.100', 'Native package took over official dotnet')
        run(['dpkg', '-V', plan['package']['name'], 'cbodotnet-host'])
        upgrades = sorted((delivery / 'upgrade').glob('*.deb'))
        require(len(upgrades) == 2, 'A real next-revision upgrade is required')
        run(['apt-get', 'install', '-y', *map(str, upgrades)])
        identity = json.loads(as_user(['cbodotnet', '--cbodotnet-info']))
        require(identity['packageRevision'] == plan['packageRevision'] + 1, 'Package upgrade selected another revision')
        require(inventory(sdk) == sdk_before, 'Packaging-only upgrade changed qualified SDK payload')
        run(['apt-get', 'remove', '-y', plan['package']['name']])
        require(not sdk.exists() and Path('/usr/bin/cbodotnet').is_file(), 'Removal damaged shared-command ownership or left SDK payload')
        result = subprocess.run(user_command(['cbodotnet', '--version'], Path('/home/cbot-smoke')), text=True, capture_output=True)
        require(result.returncode == 127 and not result.stdout, 'Removed SDK fell back to another dotnet host')
    require(as_user([official / 'dotnet', '--version'], Path('/home/cbot-smoke')).strip() == '10.0.100'
            and inventory(official) == official_before, 'Official SDK changed after lifecycle tests')
    dependencies = {name: run(['dpkg-query', '-W', '-f=${Version}', name]).strip() for name in plan['dependencies']}
    checks = {name: 'passed' for name in PREPUBLICATION_CHECKS}
    checks.update({name: 'passed' for name in (['package-integrity', 'package-manager-install', 'repository-metadata']
                                             if args.mode == 'deb' else ['image-config', 'oci-platforms', 'pinned-base-image'])})
    # OCI upgrade/removal are validated by the outer driver against whole images.
    if args.mode == 'oci':
        checks.pop('upgrade')
        checks.pop('removal')
    else:
        checks['repository-metadata'] = 'pending-signing-stage'
    result = {'schemaVersion': 1, 'status': 'passed', 'target': dict(osId=expected_os['id'], versionId=expected_os['versionId'],
               architecture=architecture, native=True, dependencies=dependencies), 'checks': checks, 'commandNames': names}
    (delivery / 'installation-result.json').write_bytes(encoded(result))


def orchestration():
    return dict(repository='dotnetdev-kr/cbodotnet', workflow='.github/workflows/distribution-release.yml',
                commit=os.environ['GITHUB_SHA'], runId=os.environ['GITHUB_RUN_ID'], runAttempt=os.environ['GITHUB_RUN_ATTEMPT'])


def copy_commands(build, target):
    rows = json.loads((build / 'command-inventory.json').read_bytes())
    target.mkdir()
    for row in rows:
        source = build / 'rootfs' / row['path'].lstrip('/')
        destination = target / row['path'].lstrip('/')
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    (target.parent / 'commands.json').write_bytes(encoded(rows))
    return rows


def record(delivery, artifact, result, commands, inputs):
    plan = json.loads((delivery / 'plan.json').read_bytes())
    rows = json.loads((delivery / 'commands.json').read_bytes())
    packaged = package_record(plan, artifact, orchestration(), extra_files={'root': commands, 'inventory': rows})
    report = {'schemaVersion': 1, 'phase': 'prepublication', 'scope': 'channel-installation',
              **result, **{name: packaged[name] for name in ('contractVersion', 'identity', 'artifact', 'source', 'producer',
                                                           'orchestration', 'branding', 'commands', 'extraFiles')}}
    (delivery / 'package.json').write_bytes(encoded(packaged))
    (delivery / 'report.json').write_bytes(encoded(report))
    return dict(packagePath=str(delivery / 'package.json'), artifactPath=str(artifact), reportPath=str(delivery / 'report.json'),
                commandsRoot=str(commands), inputsDirectory=str(inputs))


def native(args):
    workspace = args.workspace.resolve()
    require(not workspace.exists(), 'Native delivery workspace must be fresh')
    workspace.mkdir(parents=True)
    inputs = workspace / 'inputs'
    receive_release(args.tag, inputs, 'deb', 'debian-13', args.arch, args.revision)
    official_archive(workspace, args.arch)
    items = []
    for variant, base in [('ubuntu-24.04', args.ubuntu_base), ('debian-13', args.debian_base)]:
        delivery = workspace / ('deb-' + variant)
        delivery.mkdir()
        for revision, name in [(args.revision, 'build'), (args.revision + 1, 'upgrade-build')]:
            run([sys.executable, ROOT / 'scripts/package-sdk.py', '--inputs', inputs, '--channel', 'deb', '--variant', variant,
                 '--arch', args.arch, '--revision', revision, '--output', delivery / name])
        build = delivery / 'build'
        shutil.copy2(build / 'plan.json', delivery / 'plan.json')
        copy_commands(build, delivery / 'commands')
        for source_name, target_name in [('build', 'packages'), ('upgrade-build', 'upgrade')]:
            (delivery / target_name).mkdir()
            for package in (delivery / source_name).glob('*.deb'):
                shutil.copy2(package, delivery / target_name / package.name)
            shutil.copy2(delivery / source_name / 'package-build.json', delivery / target_name / 'package-build.json')
        run(['docker', 'run', '--rm', '-v', f'{ROOT}:/repo:ro', '-v', f'{workspace}:/delivery',
             base, 'bash', '/repo/scripts/verify-channel-install.sh', '/repo', '/delivery/' + delivery.name, variant, 'deb'])
        result = json.loads((delivery / 'installation-result.json').read_bytes())
        artifact = next(path for path in (delivery / 'packages').glob('*.deb') if path.name.startswith('cbodotnet-sdk-'))
        public = delivery / (variant + '-' + artifact.name)
        os.link(artifact, public)
        items.append(record(delivery, public, result, delivery / 'commands', inputs))
        # SDK payloads are already carried by packages and source input archives.
        # Keep only wrapper files needed for independent record validation.
        for name in ('build', 'upgrade-build'):
            shutil.rmtree(delivery / name)
        shutil.rmtree(delivery / 'upgrade')
    delivery = workspace / 'oci-debian-13'
    delivery.mkdir()
    build = delivery / 'build'
    run([sys.executable, ROOT / 'scripts/package-sdk.py', '--inputs', inputs, '--channel', 'oci', '--variant', 'debian-13',
         '--arch', args.arch, '--revision', args.revision, '--output', build, '--base-image', args.debian_base])
    shutil.copy2(build / 'plan.json', delivery / 'plan.json')
    copy_commands(build, delivery / 'commands')
    tag = 'cbodotnet-verified:' + args.arch
    require('@sha256:' in args.debian_base, 'OCI base must be pinned by digest')
    metadata = json.loads((build / 'package-build.json').read_bytes())
    build_arguments = ['docker', 'build', '--build-arg', 'BASE_IMAGE=' + args.debian_base,
                       '--label', 'org.opencontainers.image.base.name=' + args.debian_base]
    for key, value in metadata.get('labels', {}).items():
        build_arguments.extend(['--label', key + '=' + value])
    run([*build_arguments, '--tag', tag, '--file', build / 'Containerfile', build])
    image = json.loads(run(['docker', 'image', 'inspect', tag]))[0]
    expected_arch = 'amd64' if args.arch == 'x64' else 'arm64'
    require(image['Architecture'] == expected_arch and image['Os'] == 'linux', 'Image architecture metadata mismatch')
    run(['docker', 'run', '--rm', '--user', '0', '--entrypoint', '/bin/bash',
         '-v', f'{ROOT}:/repo:ro', '-v', f'{workspace}:/delivery', tag,
         '/repo/scripts/verify-channel-install.sh', '/repo', '/delivery/' + delivery.name, 'debian-13', 'oci'])
    result = json.loads((delivery / 'installation-result.json').read_bytes())
    # Upgrade through a separately built packaging revision, then roll back by
    # selecting the original immutable image without rewriting either image.
    upgrade_build = delivery / 'upgrade-build'
    run([sys.executable, ROOT / 'scripts/package-sdk.py', '--inputs', inputs, '--channel', 'oci', '--variant', 'debian-13',
         '--arch', args.arch, '--revision', args.revision + 1, '--output', upgrade_build, '--base-image', args.debian_base])
    upgrade_tag = tag + '-upgrade'
    run(['docker', 'build', '--build-arg', 'BASE_IMAGE=' + args.debian_base, '--tag', upgrade_tag,
         '--file', upgrade_build / 'Containerfile', upgrade_build])
    upgraded = json.loads(run(['docker', 'run', '--rm', '--entrypoint', 'cbodotnet', upgrade_tag, '--cbodotnet-info']))
    require(upgraded['packageRevision'] == args.revision + 1, 'Container upgrade did not select the next packaging revision')
    require(run(['docker', 'run', '--rm', '--entrypoint', 'cbodotnet', tag, '--version']).strip() == args.tag[4:],
            'Immutable image rollback selected another SDK')
    container_id = run(['docker', 'create', '--entrypoint', 'cbodotnet', tag, '--version']).strip()
    run(['docker', 'start', '--attach', container_id])
    run(['docker', 'rm', container_id])
    require(not run(['docker', 'ps', '--all', '--filter', 'id=' + container_id, '--format', '{{.ID}}']).strip(),
            'Container removal left a container behind')
    result['checks'].update(upgrade='passed', removal='passed')
    artifact = delivery / ('cbodotnet-sdk-' + args.arch + '.image.tar')
    run(['docker', 'save', '--output', artifact, tag])
    (delivery / 'image.json').write_bytes(encoded(dict(tag=tag, id=image['Id'], architecture=expected_arch,
                                                    base=args.debian_base, sdkVersion=args.tag[4:])))
    items.append(record(delivery, artifact, result, delivery / 'commands', inputs))
    shutil.rmtree(build)
    shutil.rmtree(upgrade_build)
    (workspace / 'official-sdk.tar.gz').unlink()
    (workspace / 'items.json').write_bytes(encoded(items))
    print(json.dumps(dict(status='passed', architecture=args.arch, items=len(items))))


def registry_manifest(reference, missing=False):
    result = subprocess.run(['docker', 'buildx', 'imagetools', 'inspect', reference, '--format', '{{json .Manifest}}'],
                            text=True, capture_output=True)
    if result.returncode:
        message = (result.stdout + result.stderr).lower()
        if missing and any(value in message for value in ('not found', 'manifest unknown', 'name unknown')):
            return None
        raise RuntimeError('Registry inspection failed for ' + reference + ': ' + result.stderr[-1000:])
    descriptor = json.loads(result.stdout)
    raw = json.loads(run(['docker', 'buildx', 'imagetools', 'inspect', reference, '--raw']))
    require(isinstance(descriptor.get('digest'), str) and descriptor['digest'].startswith('sha256:'), 'Registry returned no immutable digest')
    return descriptor, raw


def push_images(items, output):
    require(len(items) == 2 and {item['package']['architecture'] for item in items} == {'x64', 'aarch64'},
            'Both native verified images are required before GHCR promotion')
    repository = 'ghcr.io/dotnetdev-kr/cbodotnet-sdk'
    identity = items[0]['package']['identity']
    tag = identity['sdkVersion'] + '-debian13-r' + str(identity['packageRevision'])
    token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')
    require(token and os.environ.get('GITHUB_ACTOR'), 'Scoped registry credentials are unavailable')
    run(['docker', 'login', 'ghcr.io', '--username', os.environ['GITHUB_ACTOR'], '--password-stdin'], input=token + '\n')
    platforms = []
    for item in items:
        delivery = Path(item['packagePath']).parent
        image = json.loads((delivery / 'image.json').read_bytes())
        run(['docker', 'load', '--input', item['artifactPath']])
        require(json.loads(run(['docker', 'image', 'inspect', image['tag']]))[0]['Id'] == image['id'], 'Transport changed the tested image')
        reference = repository + ':' + tag + '-' + image['architecture']
        existing = registry_manifest(reference, missing=True)
        if existing is None:
            run(['docker', 'tag', image['tag'], reference])
            run(['docker', 'push', reference])
        current = registry_manifest(reference)
        require(current[1].get('config', {}).get('digest') == image['id'],
                'Refusing an immutable image tag with a different verified image config')
        platforms.append(dict(os='linux', architecture=image['architecture'], digest=current[0]['digest'], configDigest=image['id']))
    platforms.sort(key=lambda row: row['architecture'])
    index_reference = repository + ':' + tag
    existing = registry_manifest(index_reference, missing=True)
    if existing is None:
        run(['docker', 'buildx', 'imagetools', 'create', '--tag', index_reference,
             *[repository + '@' + row['digest'] for row in platforms]])
    current = registry_manifest(index_reference)
    expected = {(row['os'], row['architecture'], row['digest']) for row in platforms}
    observed = {(row.get('platform', {}).get('os'), row.get('platform', {}).get('architecture'), row.get('digest'))
                for row in current[1].get('manifests', [])}
    require(len(current[1].get('manifests', [])) == 2 and observed == expected,
            'Refusing a partial or conflicting immutable multi-platform index')
    result = dict(schemaVersion=1, repository=repository, tag=tag, digest=current[0]['digest'], platforms=platforms)
    (output / 'oci-index.json').write_bytes(encoded(result))
    return result


def sign_report(path, key):
    signature = Path(str(path) + '.sig')
    require(not signature.exists(), 'A report signature already exists')
    run(['gpg', '--batch', '--yes', '--local-user', key, '--output', signature, '--detach-sign', path])
    return signature


def unpack_deliveries(received):
    for archive_path in sorted(received.rglob('native-*.tar.gz')):
        with tarfile.open(archive_path, 'r:gz') as archive:
            entries = archive.getmembers()
            require(entries and sum(entry.size for entry in entries) < 8 * 1024**3, 'Unexpected native transport size')
            for entry in entries:
                path = Path(entry.name)
                require(not path.is_absolute() and '..' not in path.parts and not entry.issym()
                        and (entry.isdir() or entry.isfile() or entry.islnk()) and not entry.mode & 0o7000,
                        'Unsafe native CI transport member')
                if entry.islnk():
                    target = Path(entry.linkname)
                    require(not target.is_absolute() and '..' not in target.parts, 'Unsafe native CI hard link')
            archive.extractall(received, filter='data')
    deliveries = sorted(received.glob('delivery-*'))
    require(len(deliveries) == 2, 'Both native delivery artifacts are required')
    items = []
    for delivery in deliveries:
        for item in json.loads((delivery / 'items.json').read_bytes()):
            old_prefix = Path(item['inputsDirectory']).parent
            rebased = {key: str(delivery / Path(value).relative_to(old_prefix)) for key, value in item.items()}
            rebased['package'] = json.loads(Path(rebased['packagePath']).read_bytes())
            items.append(rebased)
    return items


def check_repository(repository, keyring):
    for variant in ('ubuntu-24.04', 'debian-13'):
        directory = repository / variant
        signed_release = run(['gpgv', '--keyring', keyring, '--output', '-', directory / 'InRelease'])
        require(signed_release == (directory / 'Release').read_text(), 'Signed APT release differs from indexed release')
        for line in signed_release.splitlines():
            parts = line.split()
            if len(parts) == 3 and len(parts[0]) == 64:
                checksum, size, name = parts
                require(name in {'Packages', 'Packages.gz'}, 'Unexpected APT index member')
                path = directory / name
                require(path.stat().st_size == int(size) and digest(path) == checksum, 'APT index changed after signing')
        for block in (directory / 'Packages').read_text().split('\n\n'):
            fields = dict(line.split(': ', 1) for line in block.splitlines() if ': ' in line and not line.startswith(' '))
            if fields:
                name = Path(fields['Filename'])
                require(not name.is_absolute() and '..' not in name.parts, 'Unsafe APT pool reference')
                path = directory / name
                require(path.stat().st_size == int(fields['Size']) and digest(path) == fields['SHA256'], 'APT index references a changed package')


def promote(args):
    require(os.environ.get('GITHUB_REF') == 'refs/heads/main' and os.environ.get('GITHUB_REPOSITORY') == 'dotnetdev-kr/cbodotnet',
            'Only the protected main workflow may publish')
    output = args.output.resolve()
    require(not output.exists(), 'Promotion output must be fresh')
    output.mkdir(parents=True)
    items = unpack_deliveries(args.received.resolve())
    source_identity = orchestration()
    if args.source_run:
        require(args.source_run.isdecimal() and args.source_attempt.isdecimal(), 'An exact prior run/attempt is required')
        source = json.loads(run(['gh', 'api', f'repos/dotnetdev-kr/cbodotnet/actions/runs/{args.source_run}']))
        require(source.get('head_branch') == 'main' and source.get('event') == 'workflow_dispatch'
                and source.get('path') == '.github/workflows/distribution-release.yml'
                and source.get('repository', {}).get('full_name') == 'dotnetdev-kr/cbodotnet'
                and source.get('head_repository', {}).get('full_name') == 'dotnetdev-kr/cbodotnet',
                'Only a trusted native matrix from main may be resumed')
        jobs = json.loads(run(['gh', 'api', f'repos/dotnetdev-kr/cbodotnet/actions/runs/{args.source_run}/attempts/{args.source_attempt}/jobs?per_page=100']))['jobs']
        for arch in ('x64', 'aarch64'):
            matches = [job for job in jobs if job['name'] == 'Install packages and OCI on native ' + arch]
            require(len(matches) == 1 and matches[0].get('conclusion') == 'success', 'Resumed native installation matrix did not pass')
        source_identity.update(commit=source['head_sha'], runId=args.source_run, runAttempt=args.source_attempt)
    require({item['package']['architecture'] for item in items} == {'x64', 'aarch64'}, 'Native architecture matrix is incomplete')
    require(all(item['package']['orchestration'] == source_identity for item in items), 'Native artifact belongs to another workflow run/commit')
    builds = sorted(args.received.resolve().glob('delivery-*/deb-*/packages/package-build.json'))
    repository = output / 'repositories'
    run([sys.executable, ROOT / 'scripts/package-repository.py', '--channel', 'deb', '--package-builds', *builds,
         '--signing-key', args.signing_key, '--output', repository])
    check_repository(repository, args.keyring)
    for item in items:
        report_path = Path(item['reportPath'])
        report = json.loads(report_path.read_bytes())
        if item['package']['identity']['channel'] == 'deb':
            report['checks']['repository-metadata'] = 'passed'
            report_path.write_bytes(encoded(report))
        item['signaturePath'] = str(sign_report(report_path, args.signing_key))
        item['keyringPath'] = str(args.keyring.resolve())
    ledger = output / 'ledger'
    ledger.mkdir()
    for channel in ('deb', 'oci'):
        stage_records([item for item in items if item['package']['identity']['channel'] == channel], ledger)
    oci_items = [item for item in items if item['package']['identity']['channel'] == 'oci']
    index = push_images(oci_items, output)
    # The transport tar was fully gated above. Public records point at compact
    # registry descriptors binding that tested config to its immutable digest.
    for item in oci_items:
        delivery = Path(item['packagePath']).parent
        image = json.loads((delivery / 'image.json').read_bytes())
        platform_row = next(row for row in index['platforms'] if row['architecture'] == image['architecture'])
        descriptor_path = delivery / ('oci-' + image['architecture'] + '.json')
        descriptor_path.write_bytes(encoded(dict(schemaVersion=1, repository=index['repository'],
            indexDigest=index['digest'], **platform_row, nativeTransport=item['package']['artifact'])))
        plan = json.loads((delivery / 'plan.json').read_bytes())
        inventory_rows = json.loads((delivery / 'commands.json').read_bytes())
        packaged = package_record(plan, descriptor_path, source_identity,
                                  extra_files={'root': item['commandsRoot'], 'inventory': inventory_rows})
        old_report = json.loads(Path(item['reportPath']).read_bytes())
        for key in ('contractVersion', 'identity', 'artifact', 'source', 'producer', 'orchestration', 'branding', 'commands', 'extraFiles'):
            old_report[key] = packaged[key]
        Path(item['packagePath']).write_bytes(encoded(packaged))
        item['package'] = packaged
        item['artifactPath'] = str(descriptor_path)
        item['reportPath'] = str(delivery / 'registry-report.json')
        Path(item['reportPath']).write_bytes(encoded(old_report))
        item['signaturePath'] = str(sign_report(Path(item['reportPath']), args.signing_key))
    from downstream_publish import create_bundle, publish_bundle
    for channel in ('deb', 'oci'):
        selected = [item for item in items if item['package']['identity']['channel'] == channel]
        extra = ([dict(path=str(path), kind='apt-repository', variants=[path.name.removeprefix('apt-').removesuffix('.tar.gz')])
                  for path in sorted(repository.glob('apt-*.tar.gz'))] if channel == 'deb' else
                 [dict(path=str(output / 'oci-index.json'), kind='oci-descriptor', variants=['debian-13'])])
        bundle = output / ('bundle-' + channel)
        create_bundle(selected, bundle, source_identity['commit'], args.signing_key, args.keyring, extra_assets=extra)
        receipt = publish_bundle(bundle, args.keyring, source_identity['commit'])
        (output / (channel + '-publication.json')).write_bytes(encoded(receipt))
    print(json.dumps(dict(status='published-and-bytes-postverified', digest=index['digest'])))


def postverify(args):
    index = json.loads(args.index.read_bytes())
    expected_arch = 'amd64' if args.arch == 'x64' else 'arm64'
    require(platform.machine() in ({'aarch64', 'arm64'} if args.arch == 'aarch64' else {'x86_64'}), 'Post-pull verifier must be native')
    reference = index['repository'] + '@' + index['digest']
    run(['docker', 'pull', '--platform', 'linux/' + expected_arch, reference])
    actual = json.loads(run(['docker', 'image', 'inspect', reference]))[0]
    expected = next(row for row in index['platforms'] if row['architecture'] == expected_arch)
    require(actual['Architecture'] == expected_arch and actual['Id'] == expected['configDigest'], 'Pulled image differs from qualified native image')
    require(run(['docker', 'run', '--rm', reference, 'id', '-u']).strip() != '0', 'Published image defaults to root')
    for name in ('cbodotnet-10.0', 'cbodotnet', 'dotnet'):
        result = subprocess.run(['docker', 'run', '--rm', reference, name, '--version'], text=True, capture_output=True)
        require(result.returncode == 0 and result.stdout == '10.0.403\n' and result.stderr.strip() == BRAND,
                'Published alias/branding mismatch: ' + name)
    smoke = ('mkdir -p /work/smoke && cd /work/smoke && '
             'printf \'<configuration><packageSources><clear /></packageSources></configuration>\' > NuGet.Config && '
             'printf \'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Exe</OutputType></PropertyGroup></Project>\' > Smoke.csproj && '
             'printf \'System.Console.WriteLine("published-offline-passed");\' > Program.cs && '
             'dotnet restore --configfile NuGet.Config && dotnet build --no-restore && dotnet bin/Debug/net10.0/Smoke.dll')
    require('published-offline-passed' in run(['docker', 'run', '--rm', '--network', 'none', reference, 'sh', '-ec', smoke]),
            'Published non-root offline build failed')
    args.output.write_bytes(encoded(dict(schemaVersion=1, status='passed', architecture=args.arch,
                                        repository=index['repository'], digest=index['digest'], checks=['anonymous-pull', 'native-config', 'non-root', 'command-aliases', 'cli-branding', 'offline-build-run'])))
    print(json.dumps(dict(status='passed', architecture=args.arch, digest=index['digest'])))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('native')
    command.add_argument('--workspace', type=Path, required=True)
    command.add_argument('--tag', default='sdk-10.0.403')
    command.add_argument('--revision', type=int, default=1)
    command.add_argument('--arch', choices=('x64', 'aarch64'), required=True)
    command.add_argument('--debian-base', default=DEBIAN_BASE)
    command.add_argument('--ubuntu-base', default=UBUNTU_BASE)
    command = commands.add_parser('installed')
    command.add_argument('--delivery', type=Path, required=True)
    command.add_argument('--variant', required=True)
    command.add_argument('--mode', choices=('deb', 'oci'), required=True)
    command = commands.add_parser('promote')
    command.add_argument('--received', type=Path, required=True)
    command.add_argument('--output', type=Path, required=True)
    command.add_argument('--signing-key', required=True)
    command.add_argument('--keyring', type=Path, required=True)
    command.add_argument('--source-run', default='')
    command.add_argument('--source-attempt', default='1')
    command = commands.add_parser('postverify')
    command.add_argument('--index', type=Path, required=True)
    command.add_argument('--arch', choices=('x64', 'aarch64'), required=True)
    command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        {'native': native, 'installed': installed, 'promote': promote, 'postverify': postverify}[args.command](args)
    except (ValueError, OSError, RuntimeError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
