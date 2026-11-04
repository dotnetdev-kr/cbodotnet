#!/usr/bin/env python3
"""Read-only native Arch coinstallation after all individual SDK proofs pass."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import subprocess
import sys
import zipfile

from aur_delivery import ARCH_BASE, generate_srcinfo, sdk_tools, verify_tracked_sources, write_sources
from distribution_contract import load_contract
from downstream_release import encoded, local_intake, receive_release, require
from release_catalog import get_bytes
import legacy_compat
import sdk_runtime

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'dotnetdev-kr/cbodotnet'
BRAND = 'Community Build of .NET (built by .NET Dev)'


def aur_tools():
    spec = importlib.util.spec_from_file_location('aur_coinstall_shared', ROOT / 'scripts/aur-ci.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def versions():
    selected = sorted(load_contract()['releases'], key=lambda value: tuple(map(int, value.split('.'))), reverse=True)
    require(len({'.'.join(value.split('.')[:2]) for value in selected}) == len(selected),
            'The aggregate selects one complete SDK per major/minor namespace')
    return selected


def parse_runs(text, expected):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate qualification run field')
            result[key] = value
        return result
    rows = json.loads(text, object_pairs_hook=unique)
    require(isinstance(rows, dict) and set(rows) == set(expected), 'Exactly one individual qualification for every admitted SDK is required')
    result = {}
    for version, value in rows.items():
        if type(value) is int:
            value = {'runId': value, 'attempt': 1}
        require(isinstance(value, dict) and set(value) == {'runId', 'attempt'}
                and all(type(value[key]) is int and value[key] > 0 for key in value), 'An exact positive run/attempt is required')
        result[version] = value
    require(len({(row['runId'], row['attempt']) for row in result.values()}) == len(result), 'One run cannot stand in for multiple SDK qualifications')
    return result


def api(path):
    return json.loads(get_bytes('https://api.github.com/repos/' + REPOSITORY + '/' + path, 4 * 1024**2,
                                token=os.environ.get('GH_TOKEN'), api=True))


def validate_run(run, job, workflow):
    require(run.get('status') == 'completed' and run.get('conclusion') == 'success'
            and run.get('head_branch') == 'main' and (run.get('head_repository') or {}).get('full_name') == REPOSITORY
            and run.get('path', '').split('@', 1)[0] == workflow and run.get('event') in {'push', 'workflow_dispatch'}
            and job.get('status') == 'completed' and job.get('conclusion') == 'success',
            'The exact trusted native qualification run/job must have succeeded')


def validate_report(report, version=None):
    require(report.get('status') == 'passed' and report.get('networkForBuild') == 'none'
            and report.get('publicationStatus') == 'not-published', 'The source report is not a successful offline build-only proof')
    if version is None:
        require(report.get('scope') == 'provider-package-only' and report.get('sdkQualificationPerformed') is False
                and report.get('sdkArchivesDownloaded') == 0 and report.get('sdkBuilds') == 0,
                'A real provider-only diagnostic is required')
    else:
        target = report.get('target', {})
        require(target.get('osId') == 'arch' and target.get('versionId') == 'rolling'
                and target.get('architecture') == 'x64' and target.get('native') is True
                and report.get('runtimePolicy') == sdk_runtime.runtime_policy(version, 'x64'),
                'Individual Arch SDK identity or source runtime policy differs')
        functional = report.get('functionalChecks', {})
        require(all(functional.get(key) == 'passed' for key in ('consoleDllExecution', 'consoleApphostExecution',
                'aspNetCoreLoopbackHttp', 'rsaSha256SignAndVerify', 'cryptographicRandomBytes', 'frFrDecimalFormatting',
                'tls12LoopbackHandshake')), 'The individual SDK must already have passed its complete native runtime checks')
    if version is None or version.startswith(('3.', '5.')):
        from downstream_release import validate_legacy_evidence
        validate_legacy_evidence(report, {'sdkVersion': version or '5.0.214', 'architecture': {'public': 'x64'}})


def receive_proof(run_id, attempt, directory, version=None):
    run = api(f'actions/runs/{run_id}/attempts/{attempt}')
    jobs = api(f'actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100')['jobs']
    expected = 'provider' if version is None else 'Build and install AUR recipes on native x64'
    matching = [job for job in jobs if job.get('name') == expected]
    require(len(matching) == 1, 'The exact native source job is missing or ambiguous')
    workflow = '.github/workflows/aur-compat-check.yml' if version is None else '.github/workflows/distribution-release.yml'
    validate_run(run, matching[0], workflow)
    name = (f'arch-provider-only-{run_id}-{attempt}' if version is None
            else f'downstream-aur-diagnostics-{run_id}-{attempt}')
    artifacts = api(f'actions/runs/{run_id}/artifacts?per_page=100')['artifacts']
    rows = [row for row in artifacts if row.get('name') == name and not row.get('expired')]
    require(len(rows) == 1 and 0 < rows[0].get('size_in_bytes', 0) <= 4 * 1024**2
            and str(rows[0].get('digest', '')).startswith('sha256:'), 'An authenticated bounded native diagnostic artifact is required')
    artifact = rows[0]
    path = directory / (str(run_id) + '-' + str(attempt) + '.zip')
    # gh follows GitHub's artifact redirect without forwarding an API credential
    # to the temporary storage host. Keep exact ZIP bytes for API digest binding.
    with path.open('xb') as stream:
        subprocess.run(['gh', 'api', f'repos/{REPOSITORY}/actions/artifacts/{artifact["id"]}/zip'], stdout=stream, check=True)
    require(path.stat().st_size == artifact['size_in_bytes']
            and 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest() == artifact['digest'], 'Native diagnostic ZIP differs from its GitHub API digest')
    filename = 'provider-only-result.json' if version is None else 'installation-result.json'
    with zipfile.ZipFile(path) as archive:
        require(archive.namelist().count(filename) == 1, 'Native diagnostic report is absent or duplicated')
        entry = archive.getinfo(filename)
        require(entry.file_size <= 2 * 1024**2, 'Native diagnostic report exceeds its bound')
        raw = archive.read(entry)
    report = json.loads(raw)
    validate_report(report, version)
    (directory / (str(run_id) + '-' + filename)).write_bytes(raw)
    return dict(version=version, runId=run_id, attempt=attempt, commit=run['head_sha'], artifactId=artifact['id'],
                artifactSha256=artifact['digest'], reportSha256=hashlib.sha256(raw).hexdigest())


def native(args):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.getuid() != 0,
            'A native non-root x86_64 Linux producer is required')
    workspace = args.workspace.resolve()
    require(not workspace.exists(), 'A fresh aggregate coinstallation workspace is required')
    workspace.mkdir(parents=True)
    require(args.provider_run_id > 0 and args.provider_attempt > 0, 'An exact positive provider run/attempt is required')
    proof_directory = workspace / 'prerequisite-proofs'
    proof_directory.mkdir()
    selected = versions()
    individual = parse_runs(args.qualification_runs, selected)
    proofs = [receive_proof(args.provider_run_id, args.provider_attempt, proof_directory)]
    for version in selected:
        row = individual[version]
        proofs.append(receive_proof(row['runId'], row['attempt'], proof_directory, version))
    (workspace / 'prerequisites.json').write_bytes(encoded(proofs))
    (workspace / 'inputs').mkdir()
    plans = []
    for version in selected:
        plan = receive_release('sdk-' + version, workspace / 'inputs' / version, 'aur', 'arch-rolling', 'x64', 1)
        plan['checksums'] = json.loads((workspace / 'inputs' / version / 'release-manifest.json').read_bytes())['checksums']
        plans.append(plan)
    (workspace / 'coinstall-plans.json').write_bytes(encoded(plans))
    # The normal preparation entrypoint creates the non-root user and separately
    # authenticated provider; no SDK is installed until external networking ends.
    (workspace / 'plan.json').write_bytes(encoded(dict(sdkVersion='5.0.214', architecture={'public': 'x64'},
        channel='aur', variant='arch-rolling', coinstallationOnly=True)))
    tools = aur_tools().native_tools()
    tools.official_archive(workspace, 'x64')
    docker = ['--platform', 'linux/amd64', '-e', 'AUR_OUTPUT_UID=' + str(os.getuid()),
              '-e', 'AUR_OUTPUT_GID=' + str(os.getgid()), '-v', f'{ROOT}:/repo:ro', '-v', f'{workspace}:/delivery']
    prepared = None
    container = tools.run(['docker', 'create', *docker, ARCH_BASE, 'bash', '/repo/scripts/verify-aur-install.sh', '/repo', '/delivery', 'prepare']).strip()
    try:
        tools.run(['docker', 'start', '--attach', container])
        state = json.loads(tools.run(['docker', 'inspect', '--format', '{{json .State}}', container]))
        require(state.get('ExitCode') == 0 and state.get('Status') == 'exited', 'Aggregate Arch preparation failed')
        prepared = tools.run(['docker', 'commit', container]).strip()
        tools.run(['docker', 'run', '--rm', '--network', 'none', *docker, prepared,
                   'bash', '/repo/scripts/verify-aur-install.sh', '/repo', '/delivery', 'installed-coinstall'])
    finally:
        tools.run(['docker', 'rm', '--force', container])
        if prepared:
            tools.run(['docker', 'image', 'rm', prepared])


def installed(args):
    require(os.geteuid() == 0 and platform.machine() == 'x86_64' and Path('/.dockerenv').is_file(),
            'A disposable native x86_64 root container is required')
    require({path.name for path in Path('/sys/class/net').iterdir()} == {'lo'}, 'Aggregate installation requires Docker --network none')
    require(pwd.getpwnam('cbot-smoke').pw_uid == 10001, 'Prepared ordinary smoke user differs')
    delivery = args.delivery.resolve()
    plans = json.loads((delivery / 'coinstall-plans.json').read_bytes())
    require([plan['sdkVersion'] for plan in plans] == versions(), 'The aggregate must contain every admitted SDK in descending order')
    shared = aur_tools()
    tools = shared.native_tools()
    run = tools.run
    logs = delivery / 'makepkg-logs'
    logs.mkdir()
    (delivery / 'recipes').mkdir()
    records, installed_roots, checkpoints, provider_proofs = [], {}, [], []
    baseline = Path('/usr/share/dotnet')
    require(not baseline.exists() and not Path('/usr/bin/dotnet').exists(), 'The independent official archive baseline must be fresh')
    baseline.parent.mkdir(exist_ok=True)
    sdk_tools().extract_sdk(delivery / 'official-sdk.tar.gz', baseline)
    (baseline / 'metadata').mkdir(exist_ok=True)
    Path('/usr/bin/dotnet').symlink_to(baseline / 'dotnet')
    original_link = os.readlink('/usr/bin/dotnet')
    def as_user(command):
        return subprocess.run(tools.user_command(command, Path('/home/cbot-smoke')), text=True, capture_output=True)
    warmed = as_user(['dotnet', '--version'])
    require(warmed.returncode == 0 and warmed.stdout == '10.0.100\n', 'The independently verified official comparison archive failed')
    official = tools.inventory(baseline)
    def assert_baseline(phase):
        result = as_user(['dotnet', '--version'])
        require(result.returncode == 0 and result.stdout == '10.0.100\n' and tools.inventory(baseline) == official
                and Path('/usr/bin/dotnet').is_symlink() and os.readlink('/usr/bin/dotnet') == original_link,
                'Community coinstallation changed the existing verified official archive installation')
        provider_proofs.append(dict(phase=phase, **legacy_compat.assert_unchanged(delivery / 'compatibility-state.json')))
    def assert_command(command, plan):
        result = as_user([command, '--version'])
        require(result.returncode == 0 and result.stdout == plan['sdkVersion'] + '\n' and result.stderr.strip() == BRAND,
                'Coexisting Community SDK command selected another SDK or branding')
    assert_baseline('before-install')
    for index, plan in enumerate(plans):
        version = plan['sdkVersion']
        inputs = delivery / 'inputs' / version
        require(local_intake(inputs, 'aur', 'arch-rolling', 'x64', 1) == {key: value for key, value in plan.items() if key != 'checksums'},
                'Aggregate source plan differs from independently reverified input bytes')
        recipe_root = delivery / 'recipes' / version
        sources = write_sources(plan, recipe_root,
            delivery / 'compatibility-provider/provider-build.json' if legacy_compat.required(plan) else None)
        verify_tracked_sources(recipe_root, ROOT / 'packaging/aur')
        for name in ('release-manifest.json', 'SHA256SUMS', plan['sdk']['name']):
            os.link(inputs / name, sources['sdk'] / name)
        run(['chown', '-R', 'cbot-smoke:cbot-smoke', recipe_root])
        if index == 0:
            host = shared.build_recipe(sources['host'], 'shared-host', logs, records, tools)
            run(['pacman', '-U', '--noconfirm', host])
        package = shared.build_recipe(sources['sdk'], version, logs, records, tools)
        run(['pacman', '-U', '--noconfirm', package])
        root = Path(plan['package']['root'])
        expected = sources['sdk'] / 'src' / ('sdk-' + version)
        for name in plan['additionalDirectories']:
            (expected / name).mkdir(mode=0o755, exist_ok=True)
        require(tools.inventory(root) == tools.inventory(expected), 'Aggregate package changed qualified SDK bytes, modes or links')
        installed_roots[version] = tools.inventory(root)
        assert_command(plan['package']['launcher'], plan)
        assert_command('cbodotnet', plans[0])
        assert_baseline('install-' + version)
        shared.verify_package_integrity(run(['pacman', '-Qkk', plan['package']['aurName'], 'cbodotnet-host', legacy_compat.PACKAGE_NAME],
                                           env=dict(os.environ, LC_ALL='C')), 3)
        generate_srcinfo(sources['host'], ['runuser', '-u', 'cbot-smoke', '--'])
        if 'compatibility' in sources:
            generate_srcinfo(sources['compatibility'], ['runuser', '-u', 'cbot-smoke', '--'])
        verify_tracked_sources(recipe_root, ROOT / 'packaging/aur', srcinfo=True)
        checkpoints.append(dict(phase='install', sdkVersion=version, defaultSdk=plans[0]['sdkVersion']))
        # Only declared scratch trees/source cache files are removed. Installed
        # /opt roots remain simultaneously present; each SDK source is fetched once.
        shutil.rmtree(recipe_root)
        (inputs / plan['sdk']['name']).unlink()
    for plan in plans:
        assert_command(plan['package']['launcher'], plan)
        require(tools.inventory(Path(plan['package']['root'])) == installed_roots[plan['sdkVersion']],
                'Installing another Community SDK changed an existing Community SDK payload')
    assert_command('cbodotnet', plans[0])
    for index, plan in enumerate(plans):
        run(['pacman', '-R', '--noconfirm', plan['package']['aurName']])
        require(not Path(plan['package']['root']).exists() and not Path(plan['package']['launcher']).exists(),
                'Descending removal left SDK files or command ownership')
        if index + 1 < len(plans):
            assert_command('cbodotnet', plans[index + 1])
            expected_default = plans[index + 1]['sdkVersion']
        else:
            result = as_user(['cbodotnet', '--version'])
            require(result.returncode == 127 and not result.stdout, 'The empty selector fell back to another dotnet installation')
            expected_default = None
        assert_baseline('remove-' + plan['sdkVersion'])
        checkpoints.append(dict(phase='remove', sdkVersion=plan['sdkVersion'], defaultSdk=expected_default))
    run(['pacman', '-R', '--noconfirm', 'cbodotnet-host', legacy_compat.PACKAGE_NAME])
    require(not Path('/usr/bin/cbodotnet').exists() and not Path(legacy_compat.PROVIDER_ROOT).exists()
            and tools.inventory(baseline) == official and as_user(['dotnet', '--version']).stdout == '10.0.100\n',
            'Final shared package removal changed the official archive baseline')
    result = dict(schemaVersion=1, scope='community-sdk-coinstallation', status='passed', architecture='x64',
        sdkVersions=[plan['sdkVersion'] for plan in plans], simultaneouslyInstalledSdkCount=len(plans),
        highestDefaultSdk=plans[0]['sdkVersion'], descendingRemovalFallback=checkpoints,
        versionedAliases='passed', qualifiedPayloadsUnchanged=True, networkForBuild='none', sourceArchivesReceived=len(plans),
        perSdkScratchCleanup=True, sdkSourcesRebuilt=0, publicationStatus='not-published', packageBuilds=records,
        compatibilityProvider=provider_proofs, prerequisiteProofs=json.loads((delivery / 'prerequisites.json').read_bytes()),
        sources=[dict(sdkVersion=plan['sdkVersion'], sourceManifestSha256=plan['sourceManifestSha256'],
                      sdk=plan['sdk'], qualifiedProducer=plan['producer'],
                      payloadInventorySha256=hashlib.sha256(encoded(installed_roots[plan['sdkVersion']])).hexdigest())
                 for plan in plans],
        officialComparison=dict(kind='existing-verified-official-archive-installation', sdkVersion='10.0.100',
                                root=str(baseline), unchanged=True, packageManagerOwnershipClaimed=False))
    (delivery / 'coinstall-result.json').write_bytes(encoded(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    producer = commands.add_parser('native')
    producer.add_argument('--workspace', type=Path, required=True)
    producer.add_argument('--provider-run-id', type=int, required=True)
    producer.add_argument('--provider-attempt', type=int, default=1)
    producer.add_argument('--qualification-runs', required=True)
    smoke = commands.add_parser('installed')
    smoke.add_argument('--delivery', type=Path, required=True)
    args = parser.parse_args()
    {'native': native, 'installed': installed}[args.command](args)


if __name__ == '__main__':
    main()
