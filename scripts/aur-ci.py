#!/usr/bin/env python3
"""Build and validate both AUR package bases without submitting them to AUR."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import subprocess
import sys
import tempfile

from aur_delivery import ARCH_BASE, generate_srcinfo, recipe_archive, review_namcap, sdk_tools, verify_tracked_sources, write_sources
from distribution_commands import stage_commands
from downstream_release import encoded, local_intake, package_record, receive_release, PREPUBLICATION_CHECKS, require
import legacy_compat
import sdk_runtime

ROOT = Path(__file__).resolve().parents[1]
BRAND = 'Community Build of .NET (built by .NET Dev)'


def native_tools():
    spec = importlib.util.spec_from_file_location('aur_native_tools', ROOT / 'scripts/distribution-ci.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def progress(message):
    print('aur-ci: ' + message, flush=True)


def verify_package_integrity(output, expected_count):
    altered = re.findall(r'\b([0-9]+) altered files\b', output)
    require(len(altered) == expected_count and all(int(value) == 0 for value in altered),
            'Installed package integrity failed: ' + output)


def workflow_identity():
    reference = os.environ.get('GITHUB_WORKFLOW_REF', '')
    prefix = 'dotnetdev-kr/cbodotnet/'
    require(reference.startswith(prefix), 'The actual GitHub workflow reference is required')
    workflow = reference[len(prefix):].split('@', 1)[0]
    require(re.fullmatch(r'\.github/workflows/[a-z0-9-]+\.yml', workflow), 'Unexpected workflow identity')
    return dict(repository='dotnetdev-kr/cbodotnet', workflow=workflow, commit=os.environ['GITHUB_SHA'],
                runId=os.environ['GITHUB_RUN_ID'], runAttempt=os.environ['GITHUB_RUN_ATTEMPT'])


def build_recipe(directory, label, logs, build_records, tools):
    """Use one source/build/lint path for full SDK and provider-only validation."""
    progress('makepkg verification and build: ' + label)
    generate_srcinfo(directory, ['runuser', '-u', 'cbot-smoke', '--'])
    def as_user(command):
        return tools.run(tools.user_command(command, directory), cwd=directory)
    source = as_user(['makepkg', '--verifysource', '--noconfirm'])
    (logs / (label + '-source.log')).write_text(source)
    built = as_user(['makepkg', '--cleanbuild', '--noconfirm'])
    (logs / (label + '-build.log')).write_text(built)
    packages = list(directory.glob('*.pkg.tar.zst'))
    require(len(packages) == 1, 'Exactly one binary package must be produced per independent AUR pkgbase')
    analyses, reviewed = [], []
    for target in (directory / 'PKGBUILD', packages[0]):
        lint = subprocess.run(['namcap', str(target)], text=True, capture_output=True)
        output = lint.stdout + lint.stderr
        analyses.append(output)
        (logs / (label + '-namcap.log')).write_text('\n'.join(analyses))
        require(lint.returncode == 0, 'namcap invocation failed for ' + target.name + ':\n' + '\n'.join(output.splitlines()[-12:]))
        reviewed.extend(review_namcap(output, directory.name, binary_package=target == packages[0]))
    build_records.append(dict(pkgbase=directory.name, revision=label, package=packages[0].name,
        sha256=tools.digest(packages[0]), srcinfoSha256=tools.digest(directory / '.SRCINFO'),
        sourceVerification='passed', makepkg='passed', namcap='passed-with-reviewed-findings' if reviewed else 'passed',
        namcapReviewedFindings=reviewed, namcapOutput=analyses))
    return packages[0]


def verify_provider_notices(run):
    for filename in ('LICENSE.openssl.txt', 'LICENSE.icu.txt', 'NOTICE.txt'):
        notice = Path('/usr/share/licenses') / legacy_compat.PACKAGE_NAME / filename
        require(notice.is_file() and notice.read_bytes() == (Path(legacy_compat.PROVIDER_ROOT) / filename).read_bytes()
                and run(['pacman', '-Qoq', notice]).strip() == legacy_compat.PACKAGE_NAME,
                'Separate provider original license/notice ownership differs')
    original = (Path(legacy_compat.PROVIDER_ROOT) / 'LICENSE.icu.txt').read_bytes()
    for filename, content in legacy_compat.icu_license_sections(original).items():
        notice = Path('/usr/share/licenses') / legacy_compat.PACKAGE_NAME / filename
        require(notice.is_file() and notice.read_bytes() == content
                and run(['pacman', '-Qoq', notice]).strip() == legacy_compat.PACKAGE_NAME,
                'Separate provider component notice or ownership differs')


def compatibility_native(args):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.getuid() != 0,
            'A native non-root Linux x86_64 producer is required')
    workspace = args.workspace.resolve()
    require(not workspace.exists(), 'A fresh provider-only validation workspace is required')
    workspace.mkdir(parents=True)
    # This selects the reviewed provider policy without receiving, building or
    # executing any SDK archive. It is not an SDK qualification plan/report.
    plan = dict(sdkVersion='5.0.214', architecture={'public': 'x64'}, channel='aur', variant='arch-rolling', providerOnly=True)
    (workspace / 'plan.json').write_bytes(encoded(plan))
    run = native_tools().run
    docker = ['--platform', 'linux/amd64', '-e', 'AUR_OUTPUT_UID=' + str(os.getuid()),
              '-e', 'AUR_OUTPUT_GID=' + str(os.getgid()), '-v', f'{ROOT}:/repo:ro', '-v', f'{workspace}:/delivery']
    prepared = None
    container = run(['docker', 'create', *docker, ARCH_BASE, 'bash', '/repo/scripts/verify-aur-install.sh', '/repo', '/delivery', 'prepare']).strip()
    try:
        run(['docker', 'start', '--attach', container])
        state = json.loads(run(['docker', 'inspect', '--format', '{{json .State}}', container]))
        require(state.get('ExitCode') == 0 and state.get('Status') == 'exited', 'Arch provider-only preparation failed')
        prepared = run(['docker', 'commit', container]).strip()
        recipe = workspace / 'recipes' / legacy_compat.PACKAGE_NAME
        recipe.mkdir(parents=True)
        for name in ('PKGBUILD', '.SRCINFO', 'openssl.cnf', 'NOTICE.txt', 'provider-manifest.json'):
            shutil.copy2(workspace / 'compatibility-provider' / name, recipe / name)
        policy = legacy_compat.load_policy()
        for item in [*policy['architectures']['x64']['packages'], *policy['sources'], policy['key']]:
            shutil.copy2(workspace / 'compatibility-sources' / item['name'], recipe / item['name'])
        verify_tracked_sources(workspace / 'recipes', ROOT / 'packaging/aur')
        run(['docker', 'run', '--rm', '--network', 'none', *docker, prepared,
             'bash', '/repo/scripts/verify-aur-install.sh', '/repo', '/delivery', 'installed-provider'])
        verify_tracked_sources(workspace / 'recipes', ROOT / 'packaging/aur', srcinfo=True)
    finally:
        run(['docker', 'rm', '--force', container])
        if prepared:
            run(['docker', 'image', 'rm', prepared])
    progress('provider-only native source/build/namcap/pacman checks passed; no SDK qualification performed')


def compatibility_installed(args):
    require(os.geteuid() == 0 and platform.machine() == 'x86_64' and Path('/.dockerenv').is_file(),
            'A disposable native x86_64 root container is required')
    require({path.name for path in Path('/sys/class/net').iterdir()} == {'lo'}, 'Provider-only build requires Docker --network none')
    delivery = args.delivery.resolve()
    plan = json.loads((delivery / 'plan.json').read_bytes())
    require(plan.get('providerOnly') is True and plan['variant'] == 'arch-rolling', 'An explicit provider-only diagnostic is required')
    tools = native_tools()
    tools.run(['chown', '-R', 'cbot-smoke:cbot-smoke', delivery / 'recipes'])
    logs = delivery / 'makepkg-logs'
    logs.mkdir()
    records = []
    package = build_recipe(delivery / 'recipes' / legacy_compat.PACKAGE_NAME, 'compatibility', logs, records, tools)
    tools.run(['pacman', '-U', '--noconfirm', package])
    proof = legacy_compat.assert_unchanged(delivery / 'compatibility-state.json')
    verify_provider_notices(tools.run)
    integrity = tools.run(['pacman', '-Qkk', legacy_compat.PACKAGE_NAME], env=dict(os.environ, LC_ALL='C'))
    verify_package_integrity(integrity, 1)
    result = dict(schemaVersion=1, scope='provider-package-only', status='passed', sdkQualificationPerformed=False,
                  sdkArchivesDownloaded=0, sdkBuilds=0, publicationStatus='not-published', networkForBuild='none',
                  architecture='x64', startingImage=ARCH_BASE, compatibilityProvider=[proof], packageBuilds=records,
                  packageIdentity=tools.run(['pacman', '-Q', legacy_compat.PACKAGE_NAME]).strip(), packageIntegrity=integrity)
    (delivery / 'provider-only-result.json').write_bytes(encoded(result))


def native(args):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'Native Linux x86_64 is required')
    workspace = args.workspace.resolve()
    require(not workspace.exists(), 'A fresh AUR validation workspace is required')
    workspace.mkdir(parents=True)
    inputs = workspace / 'inputs'
    progress('receive and verify the exact qualified x64 SDK source release')
    plan = receive_release(args.tag, inputs, 'aur', 'arch-rolling', 'x64', args.revision)
    native_tools().official_archive(workspace, 'x64')
    (workspace / 'plan.json').write_bytes(encoded(plan))
    commands = workspace / 'commands'
    commands.mkdir()
    rows = stage_commands(commands, plan)
    (workspace / 'commands.json').write_bytes(encoded(rows))
    progress('fully update pinned Arch and provision native build/runtime dependencies')
    run = native_tools().run
    docker = ['--platform', 'linux/amd64',
        '-e', 'AUR_OUTPUT_UID=' + str(os.getuid()), '-e', 'AUR_OUTPUT_GID=' + str(os.getgid()),
        '-v', f'{ROOT}:/repo:ro', '-v', f'{workspace}:/delivery']
    prepared = None
    container = run(['docker', 'create', *docker, ARCH_BASE, 'bash', '/repo/scripts/verify-aur-install.sh', '/repo', '/delivery', 'prepare']).strip()
    try:
        run(['docker', 'start', '--attach', container])
        state = json.loads(run(['docker', 'inspect', '--format', '{{json .State}}', container]))
        require(state.get('ExitCode') == 0 and state.get('Status') == 'exited', 'Arch dependency preparation failed')
        prepared = run(['docker', 'commit', container]).strip()
        provider_build = workspace / 'compatibility-provider/provider-build.json' if legacy_compat.required(plan) else None
        for revision, name in [(args.revision, 'recipes'), (args.revision + 1, 'upgrade-recipes')]:
            recipe_plan = local_intake(inputs, 'aur', 'arch-rolling', 'x64', revision)
            recipe_plan['checksums'] = json.loads((inputs / 'release-manifest.json').read_bytes())['checksums']
            sources = write_sources(recipe_plan, workspace / name, provider_build)
            if revision == args.revision:
                verify_tracked_sources(workspace / name, ROOT / 'packaging/aur')
            # makepkg rechecks every source checksum without external networking.
            for source in ('release-manifest.json', 'SHA256SUMS', plan['sdk']['name']):
                shutil.copy2(inputs / source, sources['sdk'] / source)
            if 'compatibility' in sources:
                policy = legacy_compat.load_policy()
                for item in [*policy['architectures']['x64']['packages'], *policy['sources'], policy['key']]:
                    shutil.copy2(workspace / 'compatibility-sources' / item['name'], sources['compatibility'] / item['name'])
        progress('disable external networking for actual makepkg, lint, install and complete SDK lifecycle tests')
        run(['docker', 'run', '--rm', '--network', 'none', *docker, prepared,
             'bash', '/repo/scripts/verify-aur-install.sh', '/repo', '/delivery', 'installed'])
    finally:
        run(['docker', 'rm', '--force', container])
        if prepared:
            run(['docker', 'image', 'rm', prepared])
    result = json.loads((workspace / 'installation-result.json').read_bytes())
    verify_tracked_sources(workspace / 'recipes', ROOT / 'packaging/aur', srcinfo=True)
    artifact = workspace / ('cbodotnet-aur-' + plan['sdkVersion'] + '-r' + str(args.revision) + '.tar.gz')
    archive = recipe_archive(workspace / 'recipes', artifact)
    result['recipeSources'] = archive['sources']
    packaged = package_record(plan, artifact, workflow_identity(), extra_files={'root': commands, 'inventory': rows})
    report = {'schemaVersion': 1, 'phase': 'prepublication', 'scope': 'channel-installation', **result,
              **{name: packaged[name] for name in ('contractVersion', 'identity', 'artifact', 'source', 'producer',
                  'orchestration', 'branding', 'commands', 'extraFiles')}}
    (workspace / 'package.json').write_bytes(encoded(packaged))
    (workspace / 'report.json').write_bytes(encoded(report))
    (workspace / 'items.json').write_bytes(encoded([dict(packagePath=str(workspace / 'package.json'),
        artifactPath=str(artifact), reportPath=str(workspace / 'report.json'), commandsRoot=str(commands),
        inputsDirectory=str(inputs))]))
    # Source inputs and the tiny reviewed recipe artifact are enough to replay
    # validation. Do not transport redundant SDK package/build/cache copies.
    for name in ('recipes', 'upgrade-recipes'):
        for base in (workspace / name).iterdir():
            for child in list(base.iterdir()):
                if child.is_dir():
                    shutil.rmtree(child)
                elif child.name.endswith(('.pkg.tar.zst', '.tar.gz', '.rpm')) or child.name in {
                        'release-manifest.json', 'SHA256SUMS', 'RPM-GPG-KEY-Rocky-9'}:
                    child.unlink()
    for name in ('compatibility-provider', 'compatibility-sources'):
        if (workspace / name).is_dir():
            shutil.rmtree(workspace / name)
    (workspace / 'official-sdk.tar.gz').unlink()
    progress('passed native Arch build, source verification, install, upgrade, rollback and removal')


def prepare(args):
    require(os.geteuid() == 0 and platform.machine() == 'x86_64' and Path('/.dockerenv').is_file(),
            'A disposable native x86_64 root container is required')
    delivery = args.delivery.resolve()
    plan = json.loads((delivery / 'plan.json').read_bytes())
    require(plan['variant'] == 'arch-rolling' and plan['channel'] == 'aur', 'Unexpected Arch preparation target')
    native_tools().run(['useradd', '--create-home', '--uid', '10001', 'cbot-smoke'])
    if legacy_compat.required(plan):
        legacy_compat.provision(plan, delivery, user='cbot-smoke')


def installed(args):
    require(os.geteuid() == 0 and platform.machine() == 'x86_64' and Path('/.dockerenv').is_file(),
            'A disposable native x86_64 root container is required')
    require({path.name for path in Path('/sys/class/net').iterdir()} == {'lo'}, 'Arch build and lifecycle validation require Docker --network none')
    delivery = args.delivery.resolve()
    plan = json.loads((delivery / 'plan.json').read_bytes())
    os_release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(os_release.get('ID', '').strip('"') == 'arch' and plan['channel'] == 'aur'
            and plan['variant'] == 'arch-rolling' and plan['architecture']['public'] == 'x64', 'Unexpected AUR native target')
    tools = native_tools()
    run = tools.run
    inventory = tools.inventory
    require(pwd.getpwnam('cbot-smoke').pw_uid == 10001, 'The prepared non-root smoke user differs')
    run(['chown', '-R', 'cbot-smoke:cbot-smoke', delivery / 'recipes', delivery / 'upgrade-recipes'])
    logs = delivery / 'makepkg-logs'
    logs.mkdir()
    build_records = []
    name = plan['package']['aurName']
    runtime_policy = sdk_runtime.policy(plan)
    compatibility_state = delivery / 'compatibility-state.json' if runtime_policy['legacy'] else None
    runtime_environment = legacy_compat.runtime_environment(plan, compatibility_state) if compatibility_state else {}
    provider_proofs = []

    def provider_unchanged(phase):
        if compatibility_state:
            provider_proofs.append({'phase': phase, **legacy_compat.assert_unchanged(compatibility_state)})

    def as_user(command, cwd=Path('/home/cbot-smoke')):
        return run(tools.user_command(command, cwd), cwd=cwd)

    def build(directory, label):
        return build_recipe(directory, label, logs, build_records, tools)

    host = build(delivery / 'recipes/cbodotnet-host', 'host')
    run(['pacman', '-U', '--noconfirm', host])
    if compatibility_state:
        companion = build(delivery / 'recipes' / legacy_compat.PACKAGE_NAME, 'compatibility')
        run(['pacman', '-U', '--noconfirm', companion])
        provider_unchanged('companion-reinstall')
        verify_provider_notices(run)
    package = build(delivery / 'recipes' / name, 'sdk')
    upgrade = build(delivery / 'upgrade-recipes' / name, 'sdk-upgrade')
    # Shared command ownership stays independent of SDK packaging revisions.
    generate_srcinfo(delivery / 'upgrade-recipes/cbodotnet-host', ['runuser', '-u', 'cbot-smoke', '--'])
    require((delivery / 'recipes/cbodotnet-host/.SRCINFO').read_bytes()
            == (delivery / 'upgrade-recipes/cbodotnet-host/.SRCINFO').read_bytes(), 'SDK revision changed shared host metadata')
    official = Path('/usr/share/dotnet')
    require(not official.exists() and not Path('/usr/bin/dotnet').exists(), 'Official comparison SDK must be fresh')
    official.parent.mkdir(exist_ok=True)
    sdk_tools().extract_sdk(delivery / 'official-sdk.tar.gz', official)
    (official / 'metadata').mkdir(exist_ok=True)
    Path('/usr/bin/dotnet').symlink_to(official / 'dotnet')
    require(as_user(['dotnet', '--version']).strip() == '10.0.100', 'Independent official comparison SDK failed')
    official_before = inventory(official)
    progress('install the actual AUR SDK binary package through pacman')
    run(['pacman', '-U', '--noconfirm', package])
    provider_unchanged('sdk-install')
    sdk = Path(plan['package']['root'])
    expected = Path(tempfile.mkdtemp(prefix='cbodotnet-aur-payload-')) / 'sdk'
    sdk_tools().extract_sdk(delivery / 'inputs' / plan['sdk']['name'], expected)
    for directory in plan['additionalDirectories']:
        (expected / directory).mkdir(mode=0o755, exist_ok=True)
    require(inventory(expected) == inventory(sdk), 'makepkg or installation changed qualified SDK bytes, links or permissions')
    shutil.rmtree(expected.parent)
    sdk_before = inventory(sdk)
    progress('verify ownership, original notices, aliases, branding and numeric stdout')
    for target, owner in [('/usr/bin/cbodotnet', 'cbodotnet-host'), (plan['package']['launcher'], name), (str(sdk / 'dotnet'), name)]:
        require(run(['pacman', '-Qoq', target]).strip() == owner, 'Package ownership collision: ' + target)
    for notice in ('LICENSE.txt', 'ThirdPartyNotices.txt'):
        require((sdk / notice).read_bytes() == (Path('/usr/share/licenses') / name / notice).read_bytes(), 'Original upstream notices changed')
    integrity_packages = [name, 'cbodotnet-host', *([legacy_compat.PACKAGE_NAME] if compatibility_state else [])]
    integrity = run(['pacman', '-Qkk', *integrity_packages], env=dict(os.environ, LC_ALL='C'))
    verify_package_integrity(integrity, len(integrity_packages))
    names = [Path(plan['package']['launcher']).name, 'cbodotnet']
    for command in names:
        result = subprocess.run(tools.user_command([command, '--version'], delivery), text=True, capture_output=True)
        require(result.returncode == 0 and result.stdout == plan['sdkVersion'] + '\n' and result.stderr.strip() == BRAND,
                'AUR CLI numeric stdout or branding changed')
        info = as_user([command, '--info'])
        require(info.startswith(BRAND + '\n') and str(sdk) in info, 'AUR host/root mismatch')
        sdk_runtime.validate_host_rid(info, plan['sdkVersion'], 'x64', 'arch-rolling')
        identity = json.loads(as_user([command, '--cbodotnet-info']))
        require(identity['sourceManifestSha256'] == plan['sourceManifestSha256'] and identity['sdkVersion'] == plan['sdkVersion'],
                'AUR qualified source identity changed')
    work = Path('/home/cbot-smoke/project')
    work.mkdir()
    run(['chown', '-R', 'cbot-smoke:cbot-smoke', work])
    script = sdk_runtime.smoke_script(plan['sdkVersion'], str(sdk), 'cbot-smoke', cli='cbodotnet',
                                      workdir=str(work), runtime_env=runtime_environment)
    output = as_user(['sh', '-ec', script], work)
    (delivery / 'offline-smoke.log').write_text(output)
    functional = sdk_runtime.validate_smoke_output(output)
    provider_unchanged('offline-dll-apphost-http-tls-crypto-icu')
    require(inventory(sdk) == sdk_before, 'SDK execution changed the qualified payload')
    require(as_user(['dotnet', '--version']).strip() == '10.0.100' and inventory(official) == official_before, 'Official dotnet coexistence failed')
    progress('upgrade, roll back and remove packages while preserving official dotnet and shared-host ownership')
    for artifact, revision in [(upgrade, plan['packageRevision'] + 1), (package, plan['packageRevision'])]:
        run(['pacman', '-U', '--noconfirm', artifact])
        identity = json.loads(as_user(['cbodotnet', '--cbodotnet-info']))
        require(identity['packageRevision'] == revision and inventory(sdk) == sdk_before, 'SDK revision upgrade/rollback changed selected identity or qualified bytes')
        provider_unchanged('upgrade' if revision > plan['packageRevision'] else 'rollback')
        require(as_user(['dotnet', '--version']).strip() == '10.0.100' and inventory(official) == official_before,
                'SDK revision transition modified the independent official SDK')
    dependencies = {dependency: run(['pacman', '-Q', dependency]).strip().split(' ', 1)[1] for dependency in plan['dependencies']}
    dynamic = run(['ldd', sdk / 'dotnet'], env=dict(os.environ, **runtime_environment))
    require('not found' not in dynamic, 'Missing native runtime dependency: ' + dynamic)
    integrity = run(['pacman', '-Qkk', *integrity_packages], env=dict(os.environ, LC_ALL='C'))
    verify_package_integrity(integrity, len(integrity_packages))
    run(['pacman', '-R', '--noconfirm', name])
    provider_unchanged('sdk-remove')
    require(not sdk.exists() and Path('/usr/bin/cbodotnet').is_file(), 'SDK removal damaged shared-host ownership or left SDK files')
    missing = subprocess.run(tools.user_command(['cbodotnet', '--version'], delivery), text=True, capture_output=True)
    require(missing.returncode == 127 and not missing.stdout, 'Removed SDK silently selected another dotnet host')
    run(['pacman', '-U', '--noconfirm', package])
    require(as_user(['cbodotnet', '--version']).strip() == plan['sdkVersion'] and inventory(sdk) == sdk_before,
            'SDK reinstall changed source payload or selection')
    provider_unchanged('sdk-reinstall')
    run(['pacman', '-R', '--noconfirm', name])
    provider_unchanged('sdk-final-remove')
    run(['pacman', '-R', '--noconfirm', 'cbodotnet-host'])
    require(not Path('/usr/bin/cbodotnet').exists() and as_user(['dotnet', '--version']).strip() == '10.0.100'
            and inventory(official) == official_before, 'AUR removal modified the independent official SDK')
    provider_unchanged('shared-host-remove')
    if compatibility_state:
        run(['pacman', '-R', '--noconfirm', legacy_compat.PACKAGE_NAME])
        require(not Path(legacy_compat.PROVIDER_ROOT).exists() and inventory(official) == official_before,
                'Separate provider removal left files or changed official SDK')
    checks = {check: 'passed' for check in PREPUBLICATION_CHECKS}
    checks.update({check: 'passed' for check in ('package-integrity', 'package-manager-install', 'source-verification', 'recipe-metadata', 'rollback', 'namcap')})
    if any(record['namcapReviewedFindings'] for record in build_records):
        checks['namcap'] = 'passed-with-reviewed-findings'
    result = dict(schemaVersion=1, status='passed', target=dict(osId='arch', versionId='rolling', architecture='x64', native=True,
        dependencies=dependencies, observedOsRelease={key: value.strip('"') for key, value in os_release.items()}, startingImage=ARCH_BASE),
        checks=checks, functionalChecks=functional, runtimePolicy=runtime_policy,
        compatibilityProvider=provider_proofs,
        compatibilityState=json.loads(compatibility_state.read_bytes()) if compatibility_state else None,
        compatibilityLifecycle=provider_proofs,
        commandNames=names, packageBuilds=build_records, nativeDependencyOutput=dynamic,
        validationTools={tool: run([tool, '--version']).strip().splitlines()[0] for tool in ('makepkg', 'pacman')},
        networkForBuild='none',
        packageManagerPolicy='full-package-extraction',
        publicationStatus='not-published')
    (delivery / 'installation-result.json').write_bytes(encoded(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('native')
    build.add_argument('--tag', required=True)
    build.add_argument('--revision', type=int, default=1)
    build.add_argument('--workspace', type=Path, required=True)
    smoke = commands.add_parser('installed')
    smoke.add_argument('--delivery', type=Path, required=True)
    preparation = commands.add_parser('prepare')
    preparation.add_argument('--delivery', type=Path, required=True)
    provider = commands.add_parser('compatibility-native')
    provider.add_argument('--workspace', type=Path, required=True)
    installed_provider = commands.add_parser('compatibility-installed')
    installed_provider.add_argument('--delivery', type=Path, required=True)
    args = parser.parse_args()
    {'native': native, 'installed': installed, 'prepare': prepare,
     'compatibility-native': compatibility_native, 'compatibility-installed': compatibility_installed}[args.command](args)


if __name__ == '__main__':
    main()
