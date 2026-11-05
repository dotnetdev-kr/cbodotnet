"""Native SDK-free installer builds and the authenticated Community installation feed."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import urllib.request

from consumer_archive import sdk_tools
from consumer_archive_site import authenticate_receipt, load_archive_status, postverified_receipt
from distribution_contract import load_contract, validate_qualified_producers
from downstream_release import encoded, load_status, require
from release_catalog import get_bytes, validate_release
import published_sdk_coexistence as MULTI

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'releases/cbodotnetup-policy.json'
WORKFLOW = '.github/workflows/distribution-release.yml'
CHECKS = ('sdk-free-bootstrap', 'signature-authentication', 'source-producer-linkage', 'exact-version-install',
          'idempotent-install', 'owned-paths', 'official-package-coexistence', 'community-package-coexistence',
          'offline-build-runtime', 'http-crypto-globalization', 'branded-aliases', 'rollback', 'removal',
          'tamper-rejection', 'signature-rejection', 'concurrency', 'interrupted-activation', 'unqualified-rejection')


def load(path):
    return json.loads(Path(path).read_bytes())


def save(path, value):
    Path(path).write_bytes(encoded(value))


def run(arguments, **kwargs):
    return subprocess.run(list(map(str, arguments)), check=True, text=True, **kwargs)


def descriptor(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'An ordinary artifact is required')
    return dict(name=path.name, size=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def source_identity():
    result = dict(repository=os.environ.get('GITHUB_REPOSITORY'), commit=os.environ.get('GITHUB_SHA'),
                  workflow=WORKFLOW, runId=os.environ.get('GITHUB_RUN_ID'), runAttempt=os.environ.get('GITHUB_RUN_ATTEMPT'))
    require(result['repository'] == 'dotnetdev-kr/cbodotnet' and re.fullmatch('[a-f0-9]{40}', result['commit'] or '')
            and all(re.fullmatch('[1-9][0-9]*', result[k] or '') for k in ('runId', 'runAttempt')), 'Exact protected workflow provenance required')
    return result


def tool_inputs():
    paths=[p for p in (ROOT/'tools').rglob('*') if p.is_file() and not {'bin','obj'} & set(p.relative_to(ROOT/'tools').parts)]
    paths += [POLICY, ROOT/'releases/downstream-signing-key.asc', ROOT/'LICENSE']
    return {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


def selected_archive(version):
    rows = [r for r in load_archive_status()['publications'] if r['identity']['sdkVersion'] == version]
    require(rows, 'No published branded SDK source')
    receipt = max(rows, key=lambda r: r['identity']['packageRevision'])
    require(receipt['status'] == 'published-postverified', 'Source archive is not post-verified')
    manifest = authenticate_receipt(receipt, historical=True)
    postverified_receipt(receipt, receipt['postVerification']['reports'], manifest, source=receipt['postVerification']['workflow'])
    return receipt, manifest


def fetch_asset(item, destination):
    path = Path(destination)
    require(not path.exists(), 'Refusing to replace an artifact input')
    with urllib.request.urlopen(item['url'], timeout=120) as source, path.open('xb') as target:
        total = 0
        while block := source.read(1024 * 1024):
            total += len(block); require(total <= item['size'] <= 1024**3, 'Artifact exceeded signed size')
            target.write(block)
    actual = descriptor(path)
    require(all(actual[k] == item[k] for k in ('size', 'sha256')), 'Artifact failed exact signed size/SHA256')


def build(args):
    policy = load(POLICY); arch = args.arch
    require(platform.machine() in ({'x86_64'} if arch == 'x64' else {'aarch64', 'arm64'}), 'Native build architecture mismatch')
    workspace = args.workspace.resolve(); require(not workspace.exists(), 'Fresh build workspace required'); workspace.mkdir(parents=True)
    receipt, manifest = selected_archive(policy['buildSdk'])
    record = next(r for r in manifest['records'] if r['architecture'] == arch)
    artifact = next(a for a in receipt['assets'] if a['name'] == record['artifactAsset'])
    fetch_asset(artifact, workspace / 'sdk.tar.gz')
    sdk_tools().extract_sdk(workspace / 'sdk.tar.gz', workspace / 'build-sdk')
    source = workspace / 'source'; (source / 'tools').mkdir(parents=True)
    for name in ('cbodotnetup', 'cbodotnetup.Tests'):
        shutil.copytree(ROOT / 'tools' / name, source / 'tools' / name, ignore=shutil.ignore_patterns('bin', 'obj'))
    shutil.copyfile(ROOT / 'tools/global.json', source / 'tools/global.json')
    (source / 'releases').mkdir(); shutil.copyfile(ROOT / 'releases/downstream-signing-key.asc', source / 'releases/downstream-signing-key.asc')
    output = workspace / 'output'; output.mkdir()
    rid = 'linux-x64' if arch == 'x64' else 'linux-arm64'
    sdk = '/build-sdk/' + record['build']['directory'] + '/payload/dotnet'
    command = f'''set -eu
dnf -y --setopt=install_weak_deps=False install clang lld gcc gcc-c++ binutils zlib-devel openssl-devel libicu python3 gnupg2 tar gzip
export DOTNET_ROOT=$(dirname {sdk}) DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_NOLOGO=1
export DOTNET_CLI_HOME=/work/dotnet-home NUGET_PACKAGES=/work/nuget
cd /work/source/tools/cbodotnetup
{sdk} run --project ../cbodotnetup.Tests --configuration Release -p:RuntimeFrameworkVersion={policy['nativeRuntime']}
{sdk} publish --configuration Release --runtime {rid} --self-contained true --output /work/output \\
  -p:RuntimeFrameworkVersion={policy['nativeRuntime']} -p:IlcTreatWarningsAsErrors=true -p:RestorePackagesWithLockFile=true
cp obj/project.assets.json /work/output/native-package-inputs.json
cp packages.lock.json /work/output/native-packages.lock.json
python3 - <<'PY'
from pathlib import Path
import shutil
out=Path('/work/output/third-party');out.mkdir()
for package in sorted(Path('/work/nuget').glob('*/*')):
    for name in ('LICENSE.TXT','LICENSE.txt','LICENSE','THIRD-PARTY-NOTICES.TXT','THIRD-PARTY-NOTICES.txt','THIRD-PARTY-NOTICES'):
        source=package/name
        if source.is_file():
            target=out/package.parent.name/package.name/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
assert any(out.rglob('*NOTICES*')), 'Native runtime third-party notices are required'
PY
/work/output/cbodotnetup --version
'''
    run(['docker', 'run', '--rm', '--user', '0', '-v', str(workspace) + ':/work', '-v', str(workspace / 'build-sdk') + ':/build-sdk:ro',
         MULTI.BASES['rocky-9.8'][arch], 'sh', '-ec', command])
    binary = output / 'cbodotnetup'; require(binary.is_file(), 'NativeAOT build produced no binary')
    binary.rename(output / ('cbodotnetup-' + rid))
    shutil.copyfile(ROOT / 'LICENSE', output / 'LICENSE')
    report = dict(schemaVersion=1, kind='cbodotnetup-native-build', version=policy['version'], architecture=arch, rid=rid,
                  source=source_identity(), buildSdk=artifact, nativeRuntime=policy['nativeRuntime'],
                  container=MULTI.BASES['rocky-9.8'][arch], securityTests='passed', sourceInputs=tool_inputs(),
                  artifacts=[descriptor(p) | dict(path=p.relative_to(output).as_posix()) for p in sorted(output.rglob('*')) if p.is_file()])
    save(output / 'build.json', report)
    print(json.dumps(dict(status='built-native-sdk-free-binary', architecture=arch, binary=descriptor(output / ('cbodotnetup-' + rid)))))


def catalog(output, builds, *, now=None, sequence=None):
    policy = load(POLICY); now = now or datetime.now(timezone.utc)
    source = source_identity(); sequence = sequence or int(source['runId'])
    require(set(builds) == {'x64', 'aarch64'}, 'Both native builds are mandatory')
    tools = []
    for arch, directory in builds.items():
        report = load(directory / 'build.json'); rid = 'linux-x64' if arch == 'x64' else 'linux-arm64'
        require(report['sourceInputs'] == tool_inputs() and report['source']['repository'] == source['repository']
                and report['source']['workflow'] == WORKFLOW and report['version'] == policy['version'] and report['architecture'] == arch
                and report['rid'] == rid and report['securityTests'] == 'passed', 'Native build provenance or checks differ')
        for asset in report['artifacts']:
            actual = descriptor(directory / asset['path'])
            require(all(actual[k] == asset[k] for k in ('name', 'size', 'sha256')), 'Native artifact differs from its exact build')
        item = descriptor(directory / ('cbodotnetup-' + rid))
        tools.append(dict(version=policy['version'], rid=rid, binary=dict(url='https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-v' + policy['version'] + '/' + item['name'], **{k:item[k] for k in ('size','sha256')})))
    sdks = []; contract = load_contract()
    for version in policy['initialSdkVersions']:
        receipt, manifest = selected_archive(version)
        canonical = get_bytes('https://github.com/dotnetdev-kr/cbodotnet/releases/download/sdk-' + version + '/release-manifest.json', 8 * 1024**2)
        require(hashlib.sha256(canonical).hexdigest() == contract['releases'][version]['manifestSha256'], 'Canonical source pin differs')
        for record in manifest['records']:
            plan = record['build']['plan']; arch = record['architecture']; rid = plan['targetRid']
            require(plan['sourceManifestSha256'] == contract['releases'][version]['manifestSha256'] and not plan['compatibility']['required'], 'Legacy or unreviewed initial SDK admission')
            item = next(a for a in receipt['assets'] if a['name'] == record['artifactAsset'])
            sdks.append(dict(sdkVersion=version, revision=receipt['identity']['packageRevision'], rid=rid,
                archiveRoot=record['build']['directory'], archive={k:item[k] for k in ('url','size','sha256')},
                sourceManifestSha256=plan['sourceManifestSha256'], sourceManifest=dict(url=plan['sourceManifestUrl'],size=len(canonical),sha256=plan['sourceManifestSha256']),
                producer=plan['producer'], evidence={k:plan['evidence'][k] for k in ('url','size','sha256')},
                licensePaths=plan['licensePaths'], securitySupport=plan['securitySupport'],
                dependencies=sorted({name for variant in policy['targets'] for name in contract['operatingSystems'][variant]['dependencies']}),
                targets=[dict(os=contract['operatingSystems'][v]['id'],versionId=contract['operatingSystems'][v]['versionId'],rid=rid) for v in policy['targets']], requiresLegacyProvider=False))
    value=dict(schemaVersion=1,kind='cbodotnetup-installation-catalog',sequence=sequence,
        issuedAt=now.isoformat().replace('+00:00','Z'),expiresAt=(now+timedelta(days=policy['catalogLifetimeDays'])).isoformat().replace('+00:00','Z'),
        signingFingerprint=policy['signingFingerprint'],revoked=[],sdks=sdks,tools=tools,
        channels={'.'.join(s['sdkVersion'].split('.')[:2]):s['sdkVersion']+'-r'+str(s['revision']) for s in sdks})
    save(output / 'catalog.json', value); return value


def main():
    parser=argparse.ArgumentParser(description=__doc__); commands=parser.add_subparsers(dest='command',required=True)
    command=commands.add_parser('build'); command.add_argument('--arch',choices=('x64','aarch64'),required=True); command.add_argument('--workspace',type=Path,required=True)
    args=parser.parse_args()
    if args.command=='build':build(args)


if __name__=='__main__':main()
