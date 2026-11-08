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
import shlex
import signal
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import urllib.parse
import zipfile
import io

from consumer_archive import sdk_tools, FUNCTIONAL_CHECKS
from consumer_archive_site import authenticate_receipt, load_archive_status, postverified_receipt
from distribution_contract import load_contract, native_dependencies, validate_qualified_producers
from downstream_release import encoded, load_status, require
from downstream_release import verify_report_signature
from downstream_publish import GitHubReleases, verify_remote_assets, read_leased_json
from release_catalog import get_bytes, validate_release
import published_sdk_coexistence as MULTI

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'releases/cbodotnetup-policy.json'
WORKFLOW = '.github/workflows/distribution-release.yml'
# Fedora's earlier qualification manifests were removed upstream. Keep historical
# package/archive build pins intact; this is the installer consumer qualification
# environment, independently reviewed from the official Fedora 45 image index.
QUALIFICATION_BASES = {**MULTI.BASES, 'fedora-45': {
    'x64': 'quay.io/fedora/fedora:45@sha256:e736b5d06f96f7560b82d106444cb00eb5dd735f30b2c15e575213a218810e18',
    'aarch64': 'quay.io/fedora/fedora:45@sha256:3b6688e40d0135e24c94d663ea781a569b0b8f331c0a7e12cb4e4090d8cd0885'}}
LEGACY_BOOTSTRAP = dict(
    url='https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-catalog-41952285282/get-cbodotnetup.py',
    size=11478,sha256='534b549030a3b24e31c631f2df279730a0e2f7166a0c45114d245d477e184409')
CATALOG_ASSETS = ('catalog.json','catalog.json.asc','catalog-v1.json','catalog-v1.json.asc',
                  'catalog-v2.json','catalog-v2.json.asc',
                  'catalog-musl.json','catalog-musl.json.asc',
                  'catalog-musl-baseline.json','catalog-musl-baseline.json.asc',
                  'catalog-v1-bootstrap.json','catalog-v1-bootstrap.json.asc',
                  'catalog-v1-expired.json','catalog-v1-expired.json.asc',
                  'catalog-v2-tool-0.2.json','catalog-v2-tool-0.2.json.asc',
                  'catalog-v2-tool-0.3.json','catalog-v2-tool-0.3.json.asc',
                  'catalog-v3-revoked.json','catalog-v3-revoked.json.asc',
                  'catalog-v3-provider-revoked.json','catalog-v3-provider-revoked.json.asc',
                  'catalog-v3-provider-incompatible.json','catalog-v3-provider-incompatible.json.asc',
                  'catalog-v2-revoked.json','catalog-v2-revoked.json.asc','get-cbodotnetup-v0.1.0.py')
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
    provider_policy=ROOT/'releases/cbodotnetup-provider-policy.json'
    if provider_policy.exists():paths.append(provider_policy)
    musl_policy=ROOT/'releases/cbodotnetup-musl-policy.json'
    if musl_policy.exists():paths.append(musl_policy)
    return {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


def selected_archive(version, *, policy=None):
    policy = policy if policy is not None else load(POLICY)
    revision = policy.get('archiveRevisions', {}).get(version)
    require(type(revision) is int and 0 < revision < 2**31, 'A reviewed installer archive revision pin is required')
    rows = [r for r in load_archive_status()['publications'] if r['identity']['sdkVersion'] == version
            and r['identity']['packageRevision'] == revision]
    require(len(rows) == 1, 'The exact pinned installer SDK archive must be published once')
    receipt = rows[0]
    require(receipt['status'] == 'published-postverified', 'Source archive is not post-verified')
    manifest = authenticate_receipt(receipt, historical=True)
    postverified_receipt(receipt, receipt['postVerification']['reports'], manifest, source=receipt['postVerification']['workflow'])
    return receipt, manifest


def fetch_asset(item, destination):
    path = Path(destination)
    require(re.fullmatch(r'https://github\.com/dotnetdev-kr/cbodotnet/releases/download/[A-Za-z0-9_.+-]+/[A-Za-z0-9_.+-]+',item['url']), 'Only immutable project release assets may be downloaded')
    require(not path.exists(), 'Refusing to replace an artifact input')
    with urllib.request.urlopen(item['url'], timeout=120) as source, path.open('xb') as target:
        total = 0
        while block := source.read(1024 * 1024):
            total += len(block); require(total <= item['size'] <= 1024**3, 'Artifact exceeded signed size')
            target.write(block)
    actual = descriptor(path)
    require(all(actual[k] == item[k] for k in ('size', 'sha256')), 'Artifact failed exact signed size/SHA256')


def public_metadata(url,maximum):
    """Explicit credential-free origins, separate from the GitHub-only metadata reader."""
    uri=urllib.parse.urlsplit(url)
    nuget=uri.netloc=='api.nuget.org' and (uri.path=='/v3/vulnerabilities/index.json' or re.fullmatch(r'/v3-vulnerabilities/[0-9.]+/(?:[0-9.]+/)?vulnerability\.(?:base|update)\.json',uri.path))
    site=uri.netloc=='dotnetdev.kr' and uri.path in {
        '/cbodotnet/cbodotnetup/get-cbodotnetup.py',
        '/cbodotnet/cbodotnetup/catalog.json','/cbodotnet/cbodotnetup/catalog.json.asc',
        '/cbodotnet/cbodotnetup/v2/catalog.json','/cbodotnet/cbodotnetup/v2/catalog.json.asc',
        '/cbodotnet/cbodotnetup/v3/catalog.json','/cbodotnet/cbodotnetup/v3/catalog.json.asc',
        '/cbodotnet/cbodotnetup/v4/catalog.json','/cbodotnet/cbodotnetup/v4/catalog.json.asc'}
    require(uri.scheme=='https' and not uri.query and not uri.fragment and (nuget or site),'Untrusted installer public metadata origin/path')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):raise ValueError('Unexpected installer metadata redirect')
    request=urllib.request.Request(url,headers={'User-Agent':'cbodotnetup-public-verification','Accept-Encoding':'identity'})
    with urllib.request.build_opener(NoRedirect()).open(request,timeout=60) as incoming:
        data=incoming.read(maximum+1);encoding=incoming.headers.get('Content-Encoding','identity').lower()
    require(0<len(data)<=maximum,'Installer public metadata exceeds its bound')
    if encoding=='gzip':
        import gzip
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:data=compressed.read(maximum+1)
        require(0<len(data)<=maximum,'Decompressed installer metadata exceeds its bound')
    else:require(encoding in ('','identity'),'Unsupported installer metadata content encoding')
    return data


def build(args):
    if getattr(args,'libc','glibc')=='musl':
        from cbodotnetup_musl_native import build_tool
        return build_tool(args.arch,args.workspace)
    policy = load(POLICY); arch = args.arch
    require(platform.machine() in ({'x86_64'} if arch == 'x64' else {'aarch64', 'arm64'}), 'Native build architecture mismatch')
    workspace = args.workspace.resolve(); require(not workspace.exists(), 'Fresh build workspace required'); workspace.mkdir(parents=True)
    receipt, manifest = selected_archive(policy['buildSdk'], policy=policy)
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
    notices=[('cbodotnet/LICENSE',(ROOT/'LICENSE').read_text())]
    notices += [(p.relative_to(output).as_posix(),p.read_text(errors='strict')) for p in sorted((output/'third-party').rglob('*')) if p.is_file()]
    (output/('cbodotnetup-'+rid+'.LICENSE.txt')).write_text('\n\n'.join('===== '+name+' =====\n'+text for name,text in notices),encoding='utf-8')
    report = dict(schemaVersion=1, kind='cbodotnetup-native-build', version=policy['version'], architecture=arch, rid=rid,
                  source=source_identity(), buildSdk=artifact, nativeRuntime=policy['nativeRuntime'],
                  container=MULTI.BASES['rocky-9.8'][arch], securityTests='passed', sourceInputs=tool_inputs(),
                  artifacts=[descriptor(p) | dict(path=p.relative_to(output).as_posix()) for p in sorted(output.rglob('*')) if p.is_file()])
    save(output / 'build.json', report)
    print(json.dumps(dict(status='built-native-sdk-free-binary', architecture=arch, binary=descriptor(output / ('cbodotnetup-' + rid)))))


def source_check(args):
    if getattr(args,'libc','glibc')=='musl':
        from cbodotnetup_musl_native import source_check as musl_source_check
        return musl_source_check(args.arch,args.workspace)
    require(platform.machine() in ({'x86_64'} if args.arch=='x64' else {'aarch64','arm64'}),'Native source-test CPU mismatch')
    workspace=args.workspace.resolve();require(not workspace.exists(),'Fresh source-test workspace required');workspace.mkdir(parents=True)
    policy=load(POLICY)
    receipt,manifest=selected_archive(policy['buildSdk'],policy=policy)
    record=next(r for r in manifest['records'] if r['architecture']==args.arch)
    asset=next(a for a in receipt['assets'] if a['name']==record['artifactAsset'])
    fetch_asset(asset,workspace/'sdk.tar.gz');sdk_tools().extract_sdk(workspace/'sdk.tar.gz',workspace/'sdk')
    root=workspace/'sdk'/record['build']['directory']/'payload'
    environment=dict(os.environ,DOTNET_ROOT=str(root),DOTNET_CLI_HOME=str(workspace/'home'),NUGET_PACKAGES=str(workspace/'nuget'),
        DOTNET_CLI_TELEMETRY_OPTOUT='1',DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',DOTNET_NOLOGO='1')
    run([root/'dotnet','run','--project',ROOT/'tools/cbodotnetup.Tests','--configuration','Release',
        '-p:RuntimeFrameworkVersion='+load(POLICY)['nativeRuntime']],cwd=ROOT/'tools',env=environment)


def feed_smoke(args):
    status=load(ROOT/'releases/cbodotnetup-status.json');require(status['status']=='published-postverified','A fully activated installer is required')
    workspace=args.workspace.resolve();require(not workspace.exists(),'Fresh public feed workspace required');workspace.mkdir(parents=True)
    descriptor_expected=next(a for a in status['catalogRelease']['assets'] if a['name']=='get-cbodotnetup.py')
    raw=public_metadata('https://dotnetdev.kr/cbodotnet/cbodotnetup/get-cbodotnetup.py',descriptor_expected['size'])
    require(len(raw)==descriptor_expected['size'] and hashlib.sha256(raw).hexdigest()==descriptor_expected['sha256'],'Default public bootstrap differs from authenticated publication')
    (workspace/'get-cbodotnetup.py').write_bytes(raw)
    provider_aware='compatibilityCatalogSha256' in status
    generations=(('v3','catalogSha256'),('v2','compatibilityCatalogSha256'),('v1','legacyCatalogSha256')) if provider_aware else (('v2','catalogSha256'),('v1','legacyCatalogSha256'))
    if 'muslCatalogSha256' in status:generations+=(('v4','muslCatalogSha256'),)
    musl=getattr(args,'libc','glibc')=='musl'
    require(not musl or 'muslCatalogSha256' in status,'The musl hosted feed is not publicly qualified')
    for generation,key in generations:
        url='https://dotnetdev.kr/cbodotnet/cbodotnetup/'+(generation+'/' if generation!='v1' else '')+'catalog.json'
        data=public_metadata(url,8*1024**2)
        require(hashlib.sha256(data).hexdigest()==status[key],'Hosted catalog generation differs from activated signed bytes')
        catalog_value=json.loads(data)
        require(catalog_value['schemaVersion']==int(generation[1:]) and catalog_value['sequence']==status['catalogSequence'],'Hosted catalog schema/sequence differs')
        (workspace/('catalog-'+generation+'.json')).write_bytes(data)
        (workspace/('catalog-'+generation+'.json.asc')).write_bytes(public_metadata(url+'.asc',64*1024))
    keyring=workspace/'trusted.gpg'
    run(['gpg','--batch','--yes','--dearmor','--output',keyring,ROOT/'releases/downstream-signing-key.asc'],capture_output=True)
    for generation,unused in generations:
        data=workspace/('catalog-'+generation+'.json')
        verify_report_signature(data,Path(str(data)+'.asc'),keyring,load_status(),WORKFLOW)
    script='''set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends python3 ca-certificates gnupg gpgv passwd util-linux
test ! -e /usr/bin/dotnet
useradd --create-home --uid 10001 cbot-feed
runuser -u cbot-feed -- python3 /feed/get-cbodotnetup.py
runuser -u cbot-feed -- /home/cbot-feed/.local/bin/cbodotnetup --version
runuser -u cbot-feed -- /home/cbot-feed/.local/bin/cbodotnetup list --available
runuser -u cbot-feed -- /home/cbot-feed/.local/bin/cbodotnetup doctor
test ! -e /usr/bin/dotnet
python3 - <<'PY'
from pathlib import Path
import hashlib,json
root=Path('/home/cbot-feed/.local/share/cbodotnetup/cache/v2')
catalog=json.loads((root/'catalog.json').read_bytes())
Path('/feed/result.json').write_text(json.dumps(dict(status='passed',catalogSha256=hashlib.sha256((root/'catalog.json').read_bytes()).hexdigest(),sequence=catalog['sequence'],bootstrapWithoutSdk=True,sdkVersions=sorted({s['sdkVersion'] for s in catalog['sdks']}))))
PY
'''
    active_generation='v3' if provider_aware else 'v2'
    if provider_aware:script=script.replace('cbodotnetup/cache/v2','cbodotnetup/cache/v3')
    image=MULTI.BASES['ubuntu-24.04'][args.arch]
    if musl:
        import musl_archive
        active_generation='v4';image=musl_archive.BASES[args.arch]
        script=script.replace('export DEBIAN_FRONTEND=noninteractive\napt-get update -qq\napt-get install -y --no-install-recommends python3 ca-certificates gnupg gpgv passwd util-linux',
            'test "$(cat /etc/alpine-release)" = 3.24.4\napk add --no-cache python3 ca-certificates gnupg gpgv coreutils')
        script=script.replace('useradd --create-home --uid 10001 cbot-feed','adduser -D -u 10001 cbot-feed')
        script=script.replace('runuser -u cbot-feed -- python3 /feed/get-cbodotnetup.py',"su -s /bin/sh cbot-feed -c 'python3 /feed/get-cbodotnetup.py'")
        for command in ('--version','list --available','doctor'):
            script=script.replace('runuser -u cbot-feed -- /home/cbot-feed/.local/bin/cbodotnetup '+command,"su -s /bin/sh cbot-feed -c '/home/cbot-feed/.local/bin/cbodotnetup "+command+"'")
        script=script.replace('cbodotnetup/cache/'+('v3' if provider_aware else 'v2'),'cbodotnetup-musl/cache/v4')
    run(['docker','run','--rm','--user','0','-v',f'{workspace}:/feed',image,'sh','-ec',script])
    expected_sha=status['muslCatalogSha256' if musl else 'catalogSha256']
    result=load(workspace/'result.json');require(result['catalogSha256']==expected_sha and result['sequence']==status['catalogSequence'],'Default hosted catalog differs from exact activated version')
    require(result['sdkVersions']==sorted({sdk['sdkVersion'] for sdk in load(workspace/('catalog-'+active_generation+'.json'))['sdks']}),
            'Hosted bootstrap did not authenticate every activated SDK series')
    result.update(scope='cbodotnetup-default-public-feed',architecture=args.arch,version=status['version'],catalogSequence=status['catalogSequence'],catalogUrl='https://dotnetdev.kr/cbodotnet/cbodotnetup/'+active_generation+'/catalog.json',legacyCatalogSha256=status['legacyCatalogSha256'],pairedHostedFeeds='passed')
    if provider_aware:result.update(compatibilityCatalogSha256=status['compatibilityCatalogSha256'],providerAwareHostedFeeds='passed')
    result.update(libc='musl' if musl else 'glibc',baseImage=image)
    if musl:result.update(muslCatalogSha256=status['muslCatalogSha256'])
    save(workspace/'report.json',result)


def catalog(output, builds, *, now=None, sequence=None):
    policy = load(POLICY); now = now or datetime.now(timezone.utc)
    source = source_identity(); sequence = sequence or int(source['runId'])
    musl_builds={key:value for key,value in builds.items() if key.startswith('linux-musl-')}
    builds={key:value for key,value in builds.items() if not key.startswith('linux-musl-')}
    builds={({'linux-x64':'x64','linux-arm64':'aarch64'}.get(key,key)):value for key,value in builds.items()}
    require(set(builds) == {'x64', 'aarch64'}, 'Both native glibc builds are mandatory')
    tools = []
    for arch, directory in builds.items():
        report = load(directory / 'build.json'); rid = 'linux-x64' if arch == 'x64' else 'linux-arm64'
        observed={k:v for k,v in report['sourceInputs'].items() if k!='releases/cbodotnetup-policy.json'}
        expected={k:v for k,v in tool_inputs().items() if k!='releases/cbodotnetup-policy.json'}
        require(observed == expected and report['source']['repository'] == source['repository']
                and report['source']['workflow'] == WORKFLOW and report['version'] == policy['version'] and report['architecture'] == arch
                and report['rid'] == rid and report['securityTests'] == 'passed' and report['nativeRuntime']==policy['nativeRuntime']
                and report['container']==MULTI.BASES['rocky-9.8'][arch]
                and report['buildSdk']['name'].startswith('cbodotnet-sdk-'+policy['buildSdk']+'-'), 'Native build provenance or checks differ')
        for asset in report['artifacts']:
            actual = descriptor(directory / asset['path'])
            require(all(actual[k] == asset[k] for k in ('name', 'size', 'sha256')), 'Native artifact differs from its exact build')
        item = descriptor(directory / ('cbodotnetup-' + rid))
        notice=descriptor(directory/('cbodotnetup-'+rid+'.LICENSE.txt'))
        tools.append(dict(version=policy['version'], rid=rid,
            binary=dict(url='https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-v' + policy['version'] + '/' + item['name'], **{k:item[k] for k in ('size','sha256')}),
            notices=dict(url='https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-v' + policy['version'] + '/' + notice['name'], **{k:notice[k] for k in ('size','sha256')})))
    provider_aware=stable_version(policy['version'])>=stable_version('0.4.0')
    modern_versions=policy.get('modernSdkVersions',policy['initialSdkVersions'])
    modern_policy=dict(policy,initialSdkVersions=modern_versions,
        archiveRevisions={version:policy['archiveRevisions'][version] for version in modern_versions},
        sdkTargets={version:policy['sdkTargets'][version] for version in modern_versions})
    sdks = catalog_sdks(modern_policy if provider_aware else policy, schema=2)
    legacy_versions = list(policy['legacyArchiveRevisions'])
    legacy_policy = dict(policy, initialSdkVersions=legacy_versions,
        archiveRevisions=policy['legacyArchiveRevisions'],
        sdkTargets={version:policy['sdkTargets'][version] for version in legacy_versions})
    legacy_sdks = catalog_sdks(legacy_policy, schema=1)
    previous=previous_catalog()
    if previous:
        current={(t['version'],t['rid']):t for t in tools}
        for tool in previous['tools']:
            key=(tool['version'],tool['rid'])
            require(key not in current or current[key]==tool,'A published tool identity has conflicting bytes')
            if key not in current:tools.append(tool)
    require(len(tools)<=64,'Review signed tool retention before exceeding the catalog bound')
    revoked=sorted(set(policy.get('revoked',[]))|set(previous['revoked'] if previous else []))
    if previous:require(sequence>previous['sequence'],'A renewed catalog must advance the published sequence')
    common=dict(kind='cbodotnetup-installation-catalog',sequence=sequence,
        issuedAt=now.isoformat().replace('+00:00','Z'),expiresAt=(now+timedelta(days=policy['catalogLifetimeDays'])).isoformat().replace('+00:00','Z'),
        signingFingerprint=policy['signingFingerprint'],revoked=revoked,tools=tools)
    compatibility=dict(schemaVersion=2,**common,sdks=sdks,
        channels={'.'.join(s['sdkVersion'].split('.')[:2]):s['sdkVersion']+'-r'+str(s['revision']) for s in sdks})
    value=compatibility
    if provider_aware:
        from cbodotnetup_providers import catalog_provider_metadata
        all_sdks=catalog_sdks(policy,schema=3)
        providers,bindings=catalog_provider_metadata(all_sdks)
        save(output/'catalog-v2.json',compatibility)
        projection=descriptor(output/'catalog-v2.json')
        value=dict(schemaVersion=3,**common,sdks=all_sdks,
            channels={'.'.join(s['sdkVersion'].split('.')[:2]):s['sdkVersion']+'-r'+str(s['revision']) for s in all_sdks},
            compatibilityCatalog=dict(url=f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-catalog-{sequence}/catalog-v2.json',
                **{key:projection[key] for key in ('size','sha256')}),providers=providers,providerBindings=bindings)
    legacy=dict(schemaVersion=1,**common,sdks=legacy_sdks,
        channels={'.'.join(s['sdkVersion'].split('.')[:2]):s['sdkVersion']+'-r'+str(s['revision']) for s in legacy_sdks})
    old_tools=[t for t in tools if t['version']=='0.1.0' and 'tool/'+t['version']+'/'+t['rid'] not in revoked]
    require({t['rid'] for t in old_tools}=={'linux-x64','linux-arm64'} and len(old_tools)==2 and sequence>2,
            'Actual 0.1.0 binaries for both CPUs must remain authenticated for migration qualification')
    bootstrap=dict(legacy,sequence=sequence-1,tools=old_tools)
    expired=dict(bootstrap,sequence=sequence-2,
        issuedAt=(now-timedelta(days=32)).isoformat().replace('+00:00','Z'),
        expiresAt=(now-timedelta(days=2)).isoformat().replace('+00:00','Z'))
    revoked_fixture=dict(compatibility,revoked=sorted(set(compatibility['revoked'])|{
        f'{sdk["sdkVersion"]}-r{sdk["revision"]}/{sdk["rid"]}' for sdk in sdks
        if sdk['sdkVersion'] not in legacy_versions}))
    save(output/'catalog.json',value);save(output/'catalog-v1.json',legacy)
    save(output/'catalog-v1-bootstrap.json',bootstrap);save(output/'catalog-v1-expired.json',expired)
    save(output/'catalog-v2-revoked.json',revoked_fixture)
    if stable_version(policy['version'])>=stable_version('0.3.0'):
        prior_tools=[t for t in tools if t['version']=='0.2.0' and 'tool/'+t['version']+'/'+t['rid'] not in revoked]
        require(len(prior_tools)==2 and {t['rid'] for t in prior_tools}=={'linux-x64','linux-arm64'},
                'Actual 0.2.0 binaries for both CPUs must remain authenticated for project SDK upgrade qualification')
        save(output/'catalog-v2-tool-0.2.json',dict(compatibility,sequence=sequence-1,tools=prior_tools))
    if provider_aware:
        prior_tools=[t for t in tools if t['version']=='0.3.0' and 'tool/'+t['version']+'/'+t['rid'] not in revoked]
        require(len(prior_tools)==2 and {t['rid'] for t in prior_tools}=={'linux-x64','linux-arm64'},
                'Actual 0.3.0 binaries for both CPUs must remain authenticated for provider-aware upgrade qualification')
        save(output/'catalog-v2-tool-0.3.json',dict(compatibility,sequence=sequence-1,tools=prior_tools))
        save(output/'catalog-v3-revoked.json',dict(value,revoked=sorted(set(revoked)|{
            f'{s["sdkVersion"]}-r{s["revision"]}/{s["rid"]}' for s in all_sdks if s['requiresLegacyProvider']})))
        save(output/'catalog-v3-provider-revoked.json',dict(value,revoked=sorted(set(revoked)|{
            f'provider/{p["providerId"]}-r{p["revision"]}/{p["rid"]}' for p in providers})))
        save(output/'catalog-v3-provider-incompatible.json',dict(value,
            providers=[dict(provider,minimumGlibc='999.0') for provider in providers]))
    verify_catalog_pair(output,tool_version=policy['version'])
    if stable_version(policy['version'])>=stable_version('0.5.0'):
        catalog_musl(output,musl_builds,common)
    return value


def catalog_musl(output, builds, common):
    from cbodotnetup_musl import sdk_catalog_record,validate_catalog,validate_tool_report
    policy=load(POLICY)
    require(set(builds)=={'linux-musl-x64','linux-musl-arm64'},'Both native musl builds are mandatory')
    tools=[]
    for rid,directory in builds.items():
        arch='x64' if rid.endswith('-x64') else 'aarch64'
        report=load(directory/'build.json')
        validate_tool_report(report,arch,source_inputs=tool_inputs(),version=policy['version'],native_runtime=policy['nativeRuntime'])
        baseline_report=load(directory/'baseline/provenance.json')
        validate_tool_report(baseline_report,arch,source_inputs=tool_inputs(),version='0.5.0',native_runtime=policy['nativeRuntime'])
        require(report['buildInputs']==baseline_report['buildInputs'],
                'Native musl baseline and current toolchain inputs changed')
        require(baseline_report['source']==report['source'] and baseline_report['sourceInputs']==report['sourceInputs']
                and report['source']['repository']=='dotnetdev-kr/cbodotnet' and report['source']['workflow']==WORKFLOW,
                'Musl baseline and current tool must share reviewed source provenance')
        for artifact in report['artifacts']:
            actual=descriptor(directory/artifact['path'])
            require(all(actual[key]==artifact[key] for key in ('name','size','sha256')),'Musl artifact differs from its native build')
        for version,base in ((policy['version'],directory),('0.5.0',directory/'baseline')):
            item=descriptor(base/('cbodotnetup-'+rid));notice=descriptor(base/('cbodotnetup-'+rid+'.LICENSE.txt'))
            tools.append(dict(version=version,rid=rid,binary=dict(url=f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-v{version}/'+item['name'],**{k:item[k] for k in ('size','sha256')}),
                notices=dict(url=f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-v{version}/'+notice['name'],**{k:notice[k] for k in ('size','sha256')})))
    previous=previous_musl_catalog()
    revoked=set(common['revoked'])
    if previous:
        require(common['sequence']>previous['sequence'],'A renewed musl catalog must advance the published sequence')
        revoked.update(previous['revoked'])
        current={(t['version'],t['rid']):t for t in tools}
        for tool in previous['tools']:
            key=(tool['version'],tool['rid'])
            require(key not in current or current[key]==tool,'A published musl tool identity has conflicting bytes')
            if key not in current:tools.append(tool)
    sdks=[sdk_catalog_record(arch) for arch in ('x64','aarch64')]
    value=dict(common,schemaVersion=4,libc='musl',tools=tools,revoked=sorted(revoked),sdks=sdks,channels={'10.0':'10.0.403-r1'})
    validate_catalog(value,expected_sdks=sdks)
    save(output/'catalog-musl.json',value)
    baseline=dict(value,sequence=value['sequence']-1,tools=[t for t in tools if t['version']=='0.5.0'])
    validate_catalog(baseline,expected_sdks=sdks)
    save(output/'catalog-musl-baseline.json',baseline)


def verify_musl_pair(bundle):
    from cbodotnetup_musl import validate_catalog
    current=load(Path(bundle)/'catalog.json');value=load(Path(bundle)/'catalog-musl.json')
    validate_catalog(value)
    require(all(value[key]==current[key] for key in ('kind','sequence','issuedAt','expiresAt','signingFingerprint'))
            and set(current['revoked'])<=set(value['revoked']),
            'Separate libc catalogs differ in their trust or freshness')
    expected=dict(value,sequence=value['sequence']-1,tools=[t for t in value['tools'] if t['version']=='0.5.0'])
    require(load(Path(bundle)/'catalog-musl-baseline.json')==expected,'Musl baseline differs from the admitted real tool pair')
    require({(v,r) for v in ('0.5.0',load(POLICY)['version']) for r in ('linux-musl-x64','linux-musl-arm64')}<={(t['version'],t['rid']) for t in value['tools']},'Actual musl tool pair is incomplete')
    return value


def previous_musl_catalog():
    path=ROOT/'releases/cbodotnetup-status.json'
    if not path.exists():return None
    status=load(path)
    if 'muslCatalogSha256' not in status:return None
    require(status['status']=='published-postverified','Previous musl installer feed is unqualified')
    assets={a['name']:a for a in status['catalogRelease']['assets']}
    with tempfile.TemporaryDirectory(prefix='cbodotnetup-prior-musl-') as temporary:
        directory=Path(temporary)
        for name in ('catalog-musl.json','catalog-musl.json.asc'):fetch_asset(assets[name],directory/name)
        key=directory/'trusted.gpg';run(['gpg','--batch','--yes','--dearmor','--output',key,ROOT/'releases/downstream-signing-key.asc'],capture_output=True)
        verify_report_signature(directory/'catalog-musl.json',directory/'catalog-musl.json.asc',key,load_status(),WORKFLOW)
        require(descriptor(directory/'catalog-musl.json')['sha256']==status['muslCatalogSha256'],'Prior musl signed catalog pin differs')
        from cbodotnetup_musl import validate_catalog
        return validate_catalog(load(directory/'catalog-musl.json'))


def reviewed_sdk_targets(policy):
    """Every SDK/CPU/OS admission is explicit; new versions inherit no host matrix."""
    versions=policy.get('initialSdkVersions');targets=policy.get('targets');arches=policy.get('architectures')
    mapping=policy.get('sdkTargets');revisions=policy.get('archiveRevisions')
    require(isinstance(versions,list) and 0<len(versions)<=64
            and all(isinstance(v,str) and re.fullmatch(r'[1-9][0-9]*\.[0-9]+\.[0-9]+',v) for v in versions)
            and len(versions)==len(set(versions)),
            'Explicit unique SDK version admission is required')
    require(isinstance(targets,list) and targets and all(isinstance(v,str) and v in MULTI.TARGETS for v in targets)
            and len(targets)==len(set(targets)) and isinstance(arches,list) and len(arches)==2
            and all(isinstance(v,str) for v in arches) and set(arches)=={'x64','aarch64'},
            'Explicit reviewed installer OS/CPU admission is required')
    require(isinstance(mapping,dict) and set(mapping)==set(versions)
            and isinstance(revisions,dict) and set(revisions)==set(versions)
            and all(type(r) is int and 0<r<2**31 for r in revisions.values()),
            'SDK target and immutable revision policy must cover exactly the admitted versions')
    for version in versions:
        cells=mapping[version]
        require(isinstance(cells,dict) and set(cells)==set(arches),
                'Each SDK needs an explicit target list for both CPUs')
        for arch in arches:
            variants=cells[arch]
            require(isinstance(variants,list) and all(isinstance(v,str) for v in variants)
                    and len(variants)==len(set(variants)) and set(variants)<=set(targets),
                    'SDK target cells are duplicated or outside the reviewed OS matrix')
        require(any(cells.values()),'An advertised SDK needs at least one explicitly admitted target cell')
    return mapping


def catalog_sdks(policy, *, schema):
    """Schema is also the closed archive naming contract; old feeds gain no new fields."""
    require(schema in (1,2,3),'Unsupported installation catalog schema')
    targets=reviewed_sdk_targets(policy)
    sdks = []; contract = load_contract()
    for version in policy['initialSdkVersions']:
        receipt, manifest = selected_archive(version, policy=policy)
        canonical = get_bytes('https://github.com/dotnetdev-kr/cbodotnet/releases/download/sdk-' + version + '/release-manifest.json', 8 * 1024**2)
        require(hashlib.sha256(canonical).hexdigest() == contract['releases'][version]['manifestSha256'], 'Canonical source pin differs')
        for record in manifest['records']:
            plan = record['build']['plan']; arch = record['architecture']; rid = plan['targetRid']
            require(arch in ('x64','aarch64') and rid=={'x64':'linux-x64','aarch64':'linux-arm64'}[arch],
                    'Archive CPU/RID differs from the explicit installer admission')
            variants=targets[version][arch]
            if not variants:continue
            required_provider=plan['compatibility']['required']
            require(plan['sourceManifestSha256'] == contract['releases'][version]['manifestSha256']
                    and (not required_provider or schema==3), 'Legacy or unreviewed initial SDK admission')
            item = next(a for a in receipt['assets'] if a['name'] == record['artifactAsset'])
            revision=receipt['identity']['packageRevision']
            expected=f'cbodotnet-sdk-{version}-linux-{arch}'+('-branded' if schema==1 else '')+f'-r{revision}.tar.gz'
            require(item['name']==expected and item['url']==f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-{version}-r{revision}/{expected}',
                    'SDK archive does not match its catalog schema/naming identity')
            sdks.append(dict(sdkVersion=version, revision=receipt['identity']['packageRevision'], rid=rid,
                archiveRoot=record['build']['directory'], archive={k:item[k] for k in ('url','size','sha256')},
                sourceManifestSha256=plan['sourceManifestSha256'], sourceManifest=dict(url=plan['sourceManifestUrl'],size=len(canonical),sha256=plan['sourceManifestSha256']),
                producer=plan['producer'], evidence={k:plan['evidence'][k] for k in ('url','size','sha256')},
                licensePaths=plan['licensePaths'], securitySupport=plan['securitySupport'],
                dependencies=sorted({name for variant in variants for name in native_dependencies(contract,version,variant)}),
                targets=[dict(os=contract['operatingSystems'][v]['id'],versionId=contract['operatingSystems'][v]['versionId'],rid=rid) for v in variants], requiresLegacyProvider=required_provider))
    return sdks


def verify_provider_catalog_generation(bundle,current):
    """Authenticate the v3 view without exposing new records to strict old clients."""
    from cbodotnetup_providers import validate_provider_catalog
    bundle=Path(bundle);compatibility=load(bundle/'catalog-v2.json')
    fields={'schemaVersion','kind','sequence','issuedAt','expiresAt','signingFingerprint','revoked','sdks','tools','channels'}
    require(set(current)==fields|{'compatibilityCatalog','providers','providerBindings'}
            and set(compatibility)==fields and compatibility['schemaVersion']==2,
            'Provider-aware catalog or compatible v2 view has another shape')
    common=fields-{'schemaVersion','sdks','channels'}
    require(all(current[key]==compatibility[key] for key in common),
            'Provider and compatible catalog trust, tools or lifetime differs')
    projection=descriptor(bundle/'catalog-v2.json')
    require(current['compatibilityCatalog']==dict(
        url=f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-catalog-{current["sequence"]}/catalog-v2.json',
        **{key:projection[key] for key in ('size','sha256')}),
        'Provider catalog does not hash-bind its immutable signed modern projection')
    validate_provider_catalog(current,compatibility)
    legacy_ids={f'{sdk["sdkVersion"]}-r{sdk["revision"]}/{sdk["rid"]}' for sdk in current['sdks'] if sdk['requiresLegacyProvider']}
    provider_ids={f'provider/{provider["providerId"]}-r{provider["revision"]}/{provider["rid"]}' for provider in current['providers']}
    expected={
        'catalog-v3-revoked.json':dict(current,revoked=sorted(set(current['revoked'])|legacy_ids)),
        'catalog-v3-provider-revoked.json':dict(current,revoked=sorted(set(current['revoked'])|provider_ids)),
        'catalog-v3-provider-incompatible.json':dict(current,providers=[dict(provider,minimumGlibc='999.0') for provider in current['providers']])}
    for name,value in expected.items():
        require(load(bundle/name)==value,'Provider rejection fixture differs from the exact signed candidate: '+name)
    old_tools=[tool for tool in compatibility['tools'] if tool['version']=='0.3.0'
               and 'tool/'+tool['version']+'/'+tool['rid'] not in compatibility['revoked']]
    require(len(old_tools)==2 and {tool['rid'] for tool in old_tools}=={'linux-x64','linux-arm64'}
            and load(bundle/'catalog-v2-tool-0.3.json')==dict(compatibility,sequence=current['sequence']-1,tools=old_tools),
            'Previous project-aware client fixture differs from the exact compatible v2 catalog')
    return compatibility


def verify_catalog_pair(bundle,*,tool_version=None):
    """A migration/renewal candidate may never strand the old client's feed."""
    current=load(Path(bundle)/'catalog.json')
    active=current
    if current['schemaVersion']==3:current=verify_provider_catalog_generation(bundle,current)
    prior_path=Path(bundle)/'catalog-v2-tool-0.2.json'
    candidate_versions=[tool_version] if tool_version is not None else [t['version'] for t in current.get('tools',[])]
    requires_prior=prior_path.exists() or Path(str(prior_path)+'.asc').exists() or any(
        stable_version(value)>=stable_version('0.3.0') for value in candidate_versions)
    if current['schemaVersion']==1:
        require(not requires_prior,'Previous-tool project SDK qualification requires a schema2 candidate')
        return current,None  # Previously published immutable bundles.
    require(current['schemaVersion']==2,'Unsupported candidate catalog schema')
    legacy=load(Path(bundle)/'catalog-v1.json')
    fields={'schemaVersion','kind','sequence','issuedAt','expiresAt','signingFingerprint','revoked','sdks','tools','channels'}
    require(set(current)==set(legacy)==fields and legacy['schemaVersion']==1,'Legacy catalog shape is not v1 compatible')
    shared=fields-{'schemaVersion','sdks','channels'}
    require(all(current[k]==legacy[k] for k in shared),'Paired catalog trust, sequence, lifetime or tools differ')
    require(current['sdks'] and legacy['sdks'],'Both catalog generations need admitted SDKs')
    require(legacy['channels']=={'10.0':'10.0.403-r2'} and len(legacy['sdks'])==2
            and {(s['sdkVersion'],s['revision'],s['rid']) for s in legacy['sdks']}
                =={('10.0.403',2,'linux-x64'),('10.0.403',2,'linux-arm64')},
            'The v1 catalog must preserve only SDK10 revision2 on both CPUs')
    for value,suffix in ((current,''),(legacy,'-branded')):
        for sdk in value['sdks']:
            arch={'linux-x64':'x64','linux-arm64':'aarch64'}.get(sdk['rid'])
            require(arch is not None,'Unsupported catalog libc/RID')
            version=sdk['sdkVersion'];revision=sdk['revision']
            expected=f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-{version}-r{revision}/cbodotnet-sdk-{version}-linux-{arch}{suffix}-r{revision}.tar.gz'
            require(sdk['archive']['url']==expected,'Cross-generation SDK archive identity')
    added_ids={f'{s["sdkVersion"]}-r{s["revision"]}/{s["rid"]}' for s in current['sdks']
               if s['sdkVersion'] not in {legacy_sdk['sdkVersion'] for legacy_sdk in legacy['sdks']}}
    revoked_path=Path(bundle)/'catalog-v2-revoked.json'
    if added_ids or revoked_path.exists():
        expected_revoked=dict(current,revoked=sorted(set(current['revoked'])|added_ids))
        require(load(revoked_path)==expected_revoked,
                'Revoked SDK test fixture differs from the exact signed candidate admissions')
    bootstrap=load(Path(bundle)/'catalog-v1-bootstrap.json')
    expected=dict(legacy,sequence=current['sequence']-1,tools=[t for t in legacy['tools'] if t['version']=='0.1.0' and 'tool/'+t['version']+'/'+t['rid'] not in legacy['revoked']])
    require(bootstrap==expected and len(bootstrap['tools'])==2 and {t['rid'] for t in bootstrap['tools']}=={'linux-x64','linux-arm64'},
            'Legacy bootstrap fixture is not bound to the paired signed migration feeds')
    issued=datetime.fromisoformat(current['issuedAt'].replace('Z','+00:00'))
    expired=dict(bootstrap,sequence=current['sequence']-2,
        issuedAt=(issued-timedelta(days=32)).isoformat().replace('+00:00','Z'),
        expiresAt=(issued-timedelta(days=2)).isoformat().replace('+00:00','Z'))
    require(load(Path(bundle)/'catalog-v1-expired.json')==expired,'Expired legacy test fixture differs from the signed migration candidate')
    if requires_prior:
        prior_tools=[t for t in current['tools'] if t['version']=='0.2.0' and 'tool/'+t['version']+'/'+t['rid'] not in current['revoked']]
        require(len(prior_tools)==2 and {t['rid'] for t in prior_tools}=={'linux-x64','linux-arm64'},
                'Actual unrevoked 0.2.0 binaries for both CPUs are required for project SDK upgrade qualification')
        expected_prior=dict(current,sequence=current['sequence']-1,tools=prior_tools)
        require(load(prior_path)==expected_prior,
                'Previous-tool test fixture differs from the exact signed schema2 candidate and 0.2.0 tool identities')
    return active,legacy


def previous_catalog():
    path=ROOT/'releases/cbodotnetup-status.json'
    if not path.exists():return None
    status=load(path);require(status['status']=='published-postverified','Previous installer feed is unqualified')
    assets={a['name']:a for a in status['catalogRelease']['assets']}
    with tempfile.TemporaryDirectory(prefix='cbodotnetup-prior-catalog-') as temporary:
        directory=Path(temporary)
        for name in ('catalog.json','catalog.json.asc'):fetch_asset(assets[name],directory/name)
        key=directory/'trusted.gpg';run(['gpg','--batch','--yes','--dearmor','--output',key,ROOT/'releases/downstream-signing-key.asc'],capture_output=True)
        verify_report_signature(directory/'catalog.json',directory/'catalog.json.asc',key,load_status(),WORKFLOW)
        require(descriptor(directory/'catalog.json')['sha256']==status['catalogSha256'],'Prior signed catalog pin differs')
        return load(directory/'catalog.json')


def stable_version(value):
    match=re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?(?:-([^+]+))?(?:\+.*)?',value.strip())
    require(match is not None,'Review an unsupported NuGet audit version')
    return tuple(int(match[i] or 0) for i in (1,2,3,4))+(0 if match[5] else 1,)


def affected(version,interval):
    require(re.fullmatch(r'\d+\.\d+\.\d+(?:\.\d+)?',version),'Native runtime package versions must be stable')
    current=stable_version(version);interval=interval.strip()
    require(interval[:1] in ('[','(') and interval[-1:] in (']',')'),'Review an unsupported NuGet vulnerability range')
    bounds=interval[1:-1].split(',')
    if len(bounds)==1:
        require(interval.startswith('[') and interval.endswith(']'),'Malformed exact vulnerability range')
        return current==stable_version(bounds[0])
    require(len(bounds)==2,'Review a compound vulnerability range')
    low,high=(b.strip() for b in bounds)
    return (not low or current>stable_version(low) or interval[0]=='[' and current==stable_version(low)) and (not high or current<stable_version(high) or interval[-1]==']' and current==stable_version(high))


def audit_native_packages(builds,output):
    """Reusing a binary never bypasses current NuGet vulnerability data."""
    index_url='https://api.nuget.org/v3/vulnerabilities/index.json'
    raw=public_metadata(index_url,1024**2);index=json.loads(raw);require(isinstance(index,list) and 0<len(index)<=16,'Unexpected NuGet vulnerability index')
    newest=max(datetime.fromisoformat(re.sub(r'(\.\d{6})\d+(?=[+-]|Z|$)',r'\1',item['@updated']).replace('Z','+00:00')) for item in index)
    now=datetime.now(timezone.utc);require(now-timedelta(days=2)<=newest<=now+timedelta(minutes=5),'NuGet vulnerability data is stale or future-dated')
    databases=[];descriptors=[]
    for item in index:
        url=item['@id'];require(url.startswith('https://api.nuget.org/v3-vulnerabilities/') and url.endswith('.json'),'Untrusted vulnerability dataset URL')
        data=public_metadata(url,32*1024**2);databases.append(json.loads(data));descriptors.append(dict(url=url,size=len(data),sha256=hashlib.sha256(data).hexdigest()))
    packages=set()
    for directory in builds.values():
        for inputs in (directory/'native-package-inputs.json',directory/'baseline/native-package-inputs.json'):
            if inputs.parent.name=='baseline' and not inputs.exists():continue
            value=load(inputs)
            packages|={tuple(k.lower().split('/',1)) for k,v in value['libraries'].items() if v['type']=='package'}
    require(packages and any(name=='microsoft.dotnet.ilcompiler' for name,_ in packages),'Actual NativeAOT package inputs are absent')
    for name,version in sorted(packages):
        for database in databases:
            for advisory in database.get(name,[]):
                require(not affected(version,advisory['versions']),'Native tool dependency is currently vulnerable: '+name+'/'+version+' '+advisory['url'])
    save(output,dict(status='passed',observedAt=now.isoformat(),indexUrl=index_url,data=descriptors,packages=[dict(name=n,version=v) for n,v in sorted(packages)]))


def sign(path):
    run(['gpg','--batch','--yes','--local-user',load(POLICY)['signingFingerprint'],'--armor','--detach-sign',path])


def verify_bundle(bundle):
    bundle=Path(bundle).resolve();manifest=load(bundle/'freeze.json')
    require(not any(p.is_symlink() for p in bundle.rglob('*')),'Frozen inputs cannot contain links')
    require(manifest['schemaVersion']==1 and manifest['kind']=='cbodotnetup-frozen-candidate'
            and manifest['source']['repository']=='dotnetdev-kr/cbodotnet' and manifest['source']['workflow']==WORKFLOW,
            'Untrusted frozen installer provenance')
    with tempfile.TemporaryDirectory(prefix='cbodotnetup-public-key-') as temporary:
        key=Path(temporary)/'trusted.gpg'
        run(['gpg','--batch','--yes','--dearmor','--output',key,ROOT/'releases/downstream-signing-key.asc'],capture_output=True)
        current,legacy=verify_catalog_pair(bundle,tool_version=manifest['version'])
        if stable_version(manifest['version'])>=stable_version('0.5.0'):verify_musl_pair(bundle)
        names=('freeze.json',)+tuple(name for name in CATALOG_ASSETS if name.endswith('.json') and (bundle/name).exists())
        for name in names:
            verify_report_signature(bundle/name,bundle/(name+'.asc'),key,load_status(),WORKFLOW)
    if legacy:
        old=descriptor(bundle/'get-cbodotnetup-v0.1.0.py')
        require(all(old[k]==LEGACY_BOOTSTRAP[k] for k in ('size','sha256')) and manifest.get('legacyBootstrap')==LEGACY_BOOTSTRAP,
                'Original released 0.1.0 bootstrap bytes or origin differ')
    indexed={a['path']:a for a in manifest['files']}
    require(len(indexed)==len(manifest['files']),'Duplicate frozen file')
    for name,item in indexed.items():
        require(not name.startswith('/') and all(p not in ('','..','.') for p in name.split('/')) and '\\' not in name,'Unsafe frozen input path')
        path=bundle/name
        require(not any(p.is_symlink() for p in (path,*path.parents)),'Frozen input contains a link')
        actual=descriptor(path);require(all(actual[k]==item[k] for k in ('name','size','sha256')),'Frozen candidate bytes changed')
    files={p.relative_to(bundle).as_posix() for p in bundle.rglob('*') if p.is_file()}
    require(files==set(indexed)|{'freeze.json','freeze.json.asc'},'Frozen candidate inventory changed')
    return manifest


def stage(args):
    output=args.output.resolve();require(not output.exists(),'Fresh signed candidate required');output.mkdir(parents=True)
    builds={};api=GitHubReleases()
    for path in args.received.rglob('build.json'):
        report=load(path);arch=report['architecture'];rid=report['rid']
        require(arch in ('x64','aarch64') and rid in ('linux-x64','linux-arm64','linux-musl-x64','linux-musl-arm64') and rid not in builds,'Ambiguous native installer build')
        source=report['source'];run_record=api.api(f'repos/dotnetdev-kr/cbodotnet/actions/runs/{source["runId"]}/attempts/{source["runAttempt"]}')
        require(run_record and run_record['head_sha']==source['commit'] and run_record['path']==WORKFLOW
                and run_record['head_branch']=='main' and run_record['event']=='workflow_dispatch'
                and run_record['repository']['full_name']=='dotnetdev-kr/cbodotnet' and run_record['head_repository']['full_name']=='dotnetdev-kr/cbodotnet', 'Native build source is not approved main')
        jobs=api.api(f'repos/dotnetdev-kr/cbodotnet/actions/runs/{source["runId"]}/attempts/{source["runAttempt"]}/jobs?per_page=100')['jobs']
        job_name=('Build SDK-free musl cbodotnetup on native ' if rid.startswith('linux-musl-') else 'Build SDK-free cbodotnetup on native ')+arch
        native=[j for j in jobs if j['name']==job_name]
        require(len(native)==1 and native[0]['status']=='completed' and native[0]['conclusion']=='success','Native build did not actually succeed')
        destination=output/'tools'/rid;shutil.copytree(path.parent,destination);builds[rid]=destination
    catalog(output,builds)
    audit_native_packages(builds,output/'native-package-audit.json')
    shutil.copyfile(ROOT/'scripts/get-cbodotnetup.py',output/'get-cbodotnetup.py')
    fetch_asset(LEGACY_BOOTSTRAP,output/'get-cbodotnetup-v0.1.0.py')
    MULTI.preflight(output/'preflight',receive=True)
    for name in CATALOG_ASSETS:
        if not name.endswith('.json'):continue
        if (output/name).exists():sign(output/name)
    freeze=dict(schemaVersion=1,kind='cbodotnetup-frozen-candidate',source=source_identity(),version=load(POLICY)['version'],
        legacyBootstrap=LEGACY_BOOTSTRAP,
        files=[descriptor(p)|dict(path=p.relative_to(output).as_posix()) for p in sorted(output.rglob('*')) if p.is_file()])
    save(output/'freeze.json',freeze);sign(output/'freeze.json');verify_bundle(output)
    print(json.dumps(dict(status='signed-frozen-unpublished',version=freeze['version'],catalog=descriptor(output/'catalog.json'))))


def user_environment():
    home='/home/'+MULTI.USER
    return dict(PATH='/usr/local/bin:/usr/bin:/bin',HOME=home,DOTNET_CLI_HOME=home,
                DOTNET_CLI_TELEMETRY_OPTOUT='1',DOTNET_NOLOGO='1',
                DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',DOTNET_CLI_UI_LANGUAGE='en')


def user_command(arguments):
    return ['runuser','-u',MULTI.USER,'--','env','-i',
            *(name+'='+value for name,value in user_environment().items()),*map(str,arguments)]


def user_process(arguments, *, stdout, extra_environment=None):
    """Start the actual worker as its session leader, without a runuser/PAM fork.

    The interruption test must kill and reap the process holding operation.lock.
    Killing a runuser wrapper's group can otherwise leave its PAM child alive.
    """
    import pwd
    account=pwd.getpwnam(MULTI.USER)
    require(os.geteuid()==0 and account.pw_uid==10001 and account.pw_gid>0,
            'A disposable root harness and dedicated unprivileged worker are required')
    environment=user_environment()
    require(extra_environment is None or set(extra_environment)<= {'CBODOTNETUP_HOME'},
            'Only an explicit SDK-manager root may supplement the clean worker environment')
    environment.update(extra_environment or {})
    return subprocess.Popen(list(map(str,arguments)),stdout=stdout,stderr=subprocess.STDOUT,
                            cwd=environment['HOME'],env=environment,user=account.pw_uid,
                            group=account.pw_gid,extra_groups=[],start_new_session=True)


def user(arguments,*,check=True):
    command=user_command(arguments)
    result=subprocess.run(command,text=True,capture_output=True,cwd='/home/'+MULTI.USER)
    if check:require(result.returncode==0,'Installer native command failed: '+shlex.join(list(map(str,arguments)))+'\n'+result.stdout[-6000:]+'\n'+result.stderr[-6000:])
    return result


def native_install(args):
    MULTI.check_container(args.variant,args.arch)
    bundle=args.bundle;verify_bundle(bundle)
    require(not Path('/usr/bin/dotnet').exists() and not Path('/opt/cbodotnet').exists(),'Bootstrap must start without an SDK')
    state=args.workspace;require(not state.exists(),'Fresh native observation state required');state.mkdir()
    run(['useradd','--create-home','--uid','10001',MULTI.USER])
    home=Path('/home')/MULTI.USER;binary=home/'.local/bin/cbodotnetup'
    rid='linux-x64' if args.arch=='x64' else 'linux-arm64'
    # Exercise the actual immutable 0.1.0 bootstrap and binary, with a fresh,
    # signed v1 fixture; the historical signed catalog itself eventually expires.
    root=home/'.local/share/cbodotnetup'
    old_catalog=bundle/'catalog-v1-bootstrap.json';legacy=bundle/'catalog-v1.json'
    user(['python3',bundle/'get-cbodotnetup-v0.1.0.py','--catalog-file',old_catalog])
    require(user([binary,'--version']).stdout.strip()=='0.1.0','The actual released legacy tool was not bootstrapped')
    old_sdk=next(s for s in load(old_catalog)['sdks'] if s['rid']==rid)
    old_exact=old_sdk['sdkVersion']+'-r'+str(old_sdk['revision'])
    old_manager=[binary,'--catalog',old_catalog]
    user([*old_manager,'list','--available']);user([*old_manager,'install',old_exact]);user([binary,'doctor'])
    old_ownership=(Path(str(binary)+'.ownership.json')).read_bytes()
    old_binary=descriptor(binary)['sha256']
    old_high=(root/'cache/high-water.json').read_bytes()
    require(user([binary,'--catalog',bundle/'catalog-v1-expired.json','list','--available'],check=False).returncode!=0,'Legacy client accepted an expired signed catalog')
    require((root/'cache/high-water.json').read_bytes()==old_high,'Rejected expired input modified legacy high-water')
    bootstrap=['python3',bundle/'get-cbodotnetup.py','--catalog-file',bundle/'catalog.json']
    if args.public:
        user([binary,'--catalog',legacy,'self','update'])
        require(Path(str(binary)+'.previous').is_file() and descriptor(Path(str(binary)+'.previous'))['sha256']==old_binary,'Actual legacy self-update did not retain the legacy executable')
    else:
        # New immutable tool URLs are not public until candidate qualification.
        # Authenticate the same frozen bytes through the offline bootstrap here;
        # the subsequent public phase must exercise real legacy self-update.
        bootstrap+=['--binary-file',bundle/'tools'/rid/('cbodotnetup-'+rid)]
        user(bootstrap)
    require(user([binary,'--version']).stdout.strip()==load(POLICY)['version'],'SDK-free migration binary failed')
    legacy_cache={name:(root/'cache'/name).read_bytes() for name in ('catalog.json','catalog.json.asc','high-water.json')}
    require(not Path('/usr/bin/dotnet').exists(),'Bootstrap silently installed a system SDK')
    catalog_value=load(bundle/'catalog.json');sdk=next(s for s in catalog_value['sdks'] if s['rid']==rid)
    version=sdk['sdkVersion'];exact=version+'-r'+str(sdk['revision'])
    project_client_migration=None
    if catalog_value['schemaVersion']==3:
        previous_root=home/'.local/share/cbodotnetup-previous-0.3'
        previous_binary=home/'.local/bin/cbodotnetup-previous-0.3/cbodotnetup'
        require(not previous_root.exists() and not previous_binary.parent.exists(),'Fresh actual 0.3 migration root required')
        project_client_migration=matrix_previous_tool_upgrade(args,previous_root,previous_binary,sdk,previous_version='0.3.0')
        matrix_user(previous_root,[previous_binary,'remove',exact])
        matrix_user(previous_root,[previous_binary,'gc'])
        require(matrix_user(previous_root,[previous_binary,'list']).stdout=='','Actual 0.3 migration left an SDK payload behind')
    bad=home/'bad-catalog.json';bad.write_bytes((bundle/'catalog.json').read_bytes()+b' ');shutil.copyfile(bundle/'catalog.json.asc',str(bad)+'.asc')
    result=user([binary,'--catalog',bad,'list','--available'],check=False);require(result.returncode!=0,'Modified catalog signature was accepted')
    require(user([binary,'--catalog',bundle/'catalog.json','install','99.0.999'],check=False).returncode!=0,'Unqualified SDK accepted')
    # A fresh user can bootstrap without an SDK. Install actual stock/package baselines before exercising the manager.
    if MULTI.TARGETS[args.variant]=='deb':
        from apt_official import bootstrap as official_bootstrap,public_summary
        Path('/etc/dpkg/dpkg.cfg.d/zz-cbodotnetup-validation').write_text('path-include=/usr/share/doc/cbodotnet-*\npath-include=/usr/share/doc/dotnet-*\npath-include=/usr/share/doc/aspnetcore-*\npath-include=/usr/share/doc/netstandard-*\n')
    else:
        from rpm_official import bootstrap as official_bootstrap,public_summary
    official=public_summary(official_bootstrap(args.variant,args.arch,MULTI.USER,state/'official.json'))
    plan=MULTI.preflight(bundle/'preflight');rows=[r for r in plan['publications'] if r['channel']==MULTI.TARGETS[args.variant] and r['sdkVersion']==version]
    require(len(rows)==1,'One exact Community package baseline required')
    key=state/'project.gpg';run(['gpg','--batch','--yes','--dearmor','--output',key,ROOT/'releases/downstream-signing-key.asc'],capture_output=True);key.chmod(0o644)
    packages=(MULTI.prepare_apt if MULTI.TARGETS[args.variant]=='deb' else MULTI.prepare_rpm)(rows,args.variant,args.arch,state,key)
    MULTI.integrity(packages,MULTI.TARGETS[args.variant])
    package_inventory=MULTI.APT.inventory(Path('/opt/cbodotnet'))
    user(['mkdir','-p',home/'.local/share/dotnetup'])
    user(['sh','-ec','printf untouched > "$HOME/.local/share/dotnetup/owner-test"'])
    # Before feed activation, use the exact project-signed catalog under qualification.
    # Public verification re-downloads these same bytes from their actual immutable release.
    manager=[binary,'--catalog',bundle/'catalog.json']
    log=state/'interrupted-install.log'
    with log.open('w') as output:
        child=user_process([*manager,'install',exact],stdout=output)
        interrupted=False
        try:
            deadline=time.monotonic()+60
            while child.poll() is None and time.monotonic()<deadline:
                if any((p/'source.json').is_file() for p in (root/'staging').iterdir() if p.is_dir()):
                    os.killpg(child.pid,signal.SIGKILL);interrupted=True;break
                time.sleep(0.02)
        finally:
            if child.poll() is None:os.killpg(child.pid,signal.SIGKILL)
            child.wait(timeout=30)
    require(interrupted and not (root/'toolchains-v2'/exact/rid).exists(),'Interrupted download exposed an active or partial SDK root; '+log.read_text()[-3000:])
    MULTI.integrity(packages,MULTI.TARGETS[args.variant])
    user([*manager,'install','--channel','10.0']);user([*manager,'install',exact]);user([*manager,'update']);user([*manager,'rollback',exact])
    require(set(user([binary,'list']).stdout.splitlines())=={old_exact+'/'+rid,exact+'/'+rid},'Migrated installed list identity differs')
    user([binary,'shell','enable']);user([*manager,'self','update'])
    user([*manager,'rollback',old_exact])
    require(user([root/'bin/cbodotnet','--version']).stdout==old_sdk['sdkVersion']+'\n','SDK rollback lost the legacy admission')
    user([*manager,'rollback',exact])
    if args.public:
        user([*manager,'self','rollback'])
        require(user([binary,'--version']).stdout.strip()=='0.1.0','Actual tool rollback did not restore the legacy executable')
        require(user([binary,'list']).stdout.strip()==old_exact+'/'+rid,'Legacy rollback enumerated incompatible neutral SDK state')
        user([binary,'doctor'])
        require(user([root/'bin/cbodotnet','--version']).stdout==old_sdk['sdkVersion']+'\n','Legacy rollback did not fall back to its retained SDK')
        user([binary,'--catalog',legacy,'self','update'])
        require(user([binary,'--version']).stdout.strip()==load(POLICY)['version'],'Legacy tool could not re-upgrade')
        user([*manager,'list','--available'])
    # Deterministically inject the self-update crash boundary after executable
    # replacement but before its ownership receipt is committed. Recovery must
    # authenticate the actual bytes; no untrusted binary is admitted by this test.
    Path(str(binary)+'.ownership.json').write_bytes(old_ownership)
    require(user([*manager,'self','update'],check=False).returncode!=0,'Conflicting tool ownership was accepted')
    user(bootstrap)
    require(user([binary,'--version']).stdout.strip()==load(POLICY)['version'],'Verified bootstrap did not repair interrupted ownership')
    user([binary,'doctor'])
    require(all((root/'cache'/name).read_bytes()==raw for name,raw in legacy_cache.items()),'New client overwrote the legacy catalog/high-water')
    migration=dict(status='passed',protocol='actual-0.1.0-self-update-rollback-reupgrade' if args.public else 'actual-0.1.0-frozen-bootstrap-migration',
        oldVersion='0.1.0',newVersion=load(POLICY)['version'],oldSdk=old_exact,newSdk=exact,
        legacyCatalogSha256=descriptor(legacy)['sha256'],legacyBootstrapSha256=descriptor(bundle/'get-cbodotnetup-v0.1.0.py')['sha256'],
        oldBinarySha256=old_binary,expiredCatalogRejection='passed',legacyCachePreserved='passed',
        interruptedOwnershipRecovery='passed',sdkRollback='passed')
    save(state/'installed.json',dict(sdk=sdk,exact=exact,rid=rid,officialBaseline=official,packages=packages,packageInventory=package_inventory,
        legacyExact=old_exact,migration=migration,projectClientMigration=project_client_migration,
        catalogSha256=descriptor(bundle/'catalog.json')['sha256'],freezeSha256=descriptor(bundle/'freeze.json')['sha256'],
        bootstrapSha256=descriptor(bundle/'get-cbodotnetup.py')['sha256'],binarySha256=descriptor(binary)['sha256'],bootstrapBinarySource='public-https' if args.public else 'protected-frozen-candidate'))


def native_smoke(args):
    MULTI.check_container(args.variant,args.arch,offline=True)
    state=load(args.workspace/'installed.json');sdk=state['sdk'];version=sdk['sdkVersion'];home=Path('/home')/MULTI.USER
    binary=home/'.local/bin/cbodotnetup';root=home/'.local/share/cbodotnetup';exact=state['exact']
    if MULTI.TARGETS[args.variant]=='deb':from apt_official import assert_unchanged
    else:from rpm_official import assert_unchanged
    observations=[]
    for alias in ('cbodotnet','cbodotnet-'+'.'.join(version.split('.')[:2])):
        result=user([root/'bin'/alias,'--version']);require(result.stdout==version+'\n' and result.stderr==MULTI.BRAND+'\n','User-local alias selected another SDK or lost branding')
        info=json.loads(user([root/'bin'/alias,'--cbodotnet-info']).stdout)
        require(info['sdkVersion']==version and info['sourceManifestSha256']==sdk['sourceManifestSha256'],'User alias source identity differs');observations.append(info)
    payload=root/'toolchains-v2'/exact/state['rid']/'content'/sdk['archiveRoot']/'payload'
    wrapper=home/'run-managed-sdk.sh';wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(str(binary))+' run '+shlex.quote(exact)+' -- "$@"\n');wrapper.chmod(0o755)
    from sdk_runtime import smoke_script,validate_smoke_output
    functional=validate_smoke_output(user(['sh','-ec',smoke_script(version,str(payload),MULTI.USER,cli=str(wrapper),workdir=str(home/'offline-cbodotnetup'))]).stdout)
    user([binary,'doctor'])
    notice=payload/'LICENSE.txt';original=notice.read_bytes();notice.write_bytes(original+b'changed')
    require(user([binary,'doctor'],check=False).returncode!=0,'Modified installed file was accepted');notice.write_bytes(original)
    # The .NET lock must interoperate with another process, not only an in-process test lock.
    import fcntl
    with (root/'operation.lock').open('a+b') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        require(user([binary,'list'],check=False).returncode!=0,'Concurrent installer operation ignored process lock')
    abandoned=list((root/'staging').iterdir());require(abandoned and all(p.is_dir() and (p/'owner').read_text()=='cbodotnetup-v1' for p in abandoned),'Actual interrupted install did not leave its owned stage')
    user([binary,'gc']);require(not list((root/'staging').iterdir()),'Abandoned owned stage was not collected')
    require(user([binary,'run',exact,'--','--version']).stdout==version+'\n','Interrupted activation affected an active SDK')
    project_reference=None
    if tuple(map(int,load(POLICY)['version'].split('.'))) >= (0,3,0):
        from cbodotnetup_project import qualify_reference
        project_reference=qualify_reference(payload,args.workspace/'project-sdk-reference')
    user([binary,'remove',exact])
    require(user([binary,'list']).stdout.strip()==state['legacyExact']+'/'+state['rid'],'Neutral SDK removal damaged the retained legacy SDK')
    user([binary,'remove',state['legacyExact']]);require(user([binary,'list']).stdout=='','Removed SDK still advertised')
    absent=user([root/'bin/cbodotnet','--version'],check=False);require(absent.returncode!=0 and not absent.stdout,'Empty user selector fell back to an official/package SDK')
    user([binary,'shell','disable'])
    require(MULTI.APT.inventory(Path('/opt/cbodotnet'))==state['packageInventory'],'User installer changed package-managed Community SDK inventory')
    MULTI.integrity(state['packages'],MULTI.TARGETS[args.variant]);official=assert_unchanged(args.workspace/'official.json')
    require((home/'.local/share/dotnetup/owner-test').read_text()=='untouched','Official installer state was changed')
    save(args.workspace/'report.json',dict(schemaVersion=1,scope='cbodotnetup-native-installation',status='passed',variant=args.variant,architecture=args.arch,
        baseImage=QUALIFICATION_BASES[args.variant][args.arch],
        orchestration=source_identity(),bootstrapBinarySource=state['bootstrapBinarySource'],
        catalogSha256=state['catalogSha256'],freezeSha256=state['freezeSha256'],bootstrapSha256=state['bootstrapSha256'],binarySha256=state['binarySha256'],
        migration=state['migration'],
        networkForBuild='none',userId=10001,checks=dict.fromkeys(CHECKS,'passed'),functionalChecks=functional,aliases=observations,
        officialBaseline=state['officialBaseline'],officialAfterRemoval=official,packageManagedCommunityIntegrity='unchanged',
        rollbackScope='signed legacy r2 and neutral r3 SDK selection; actual public 0.1.0 tool rollback and re-upgrade'))
    if project_reference is not None:
        report=load(args.workspace/'report.json');report['projectSdkReference']=project_reference
        if state.get('projectClientMigration') is not None:report['projectClientMigration']=state['projectClientMigration']
        save(args.workspace/'report.json',report)


def matrix_sdk(args):
    catalog_value=load(args.bundle/'catalog.json')
    rid='linux-x64' if args.arch=='x64' else 'linux-arm64'
    matches=[sdk for sdk in catalog_value['sdks'] if sdk['sdkVersion']==args.sdk_version and sdk['rid']==rid]
    require(len(matches)==1 and args.sdk_version!='10.0.403','One additional SDK identity is required')
    sdk=matches[0];target=load_contract()['operatingSystems'][args.variant]
    require(dict(os=target['id'],versionId=target['versionId'],rid=rid) in sdk['targets'],
            'The additional SDK does not admit the actual native OS/CPU')
    return catalog_value,sdk


def matrix_paths(args, *, revoked=False):
    home=Path('/home')/MULTI.USER
    suffix=args.sdk_version+('-revoked' if revoked else '')
    return home/'.local/share'/('cbodotnetup-matrix-'+suffix),home/'.local/bin'/('cbodotnetup-matrix-'+suffix)/'cbodotnetup'


def matrix_user(root, arguments, *, check=True):
    return user(['env','CBODOTNETUP_HOME='+str(root),*arguments],check=check)


def matrix_bootstrap(args, root, binary, catalog_file, *, published_binary=False, expected_version=None):
    command=['python3',args.bundle/'get-cbodotnetup.py','--catalog-file',catalog_file,'--install-dir',binary.parent]
    if not args.public and not published_binary:command+=['--binary-file',args.bundle/'tools'/('linux-x64' if args.arch=='x64' else 'linux-arm64')/('cbodotnetup-'+('linux-x64' if args.arch=='x64' else 'linux-arm64'))]
    matrix_user(root,command)
    require(matrix_user(root,[binary,'--version']).stdout.strip()==(expected_version or load(POLICY)['version']),
            'Additional SDK bootstrap executed another installer version')


def matrix_previous_tool_upgrade(args, root, binary, baseline, *, previous_version='0.2.0'):
    """Exercise the actual released schema2 client before installing another SDK."""
    from cbodotnetup_project import owned_sdk_state
    require(previous_version in {'0.2.0','0.3.0'},'Only actual reviewed schema2 client generations are qualified')
    previous=args.bundle/('catalog-v2-tool-'+'.'.join(previous_version.split('.')[:2])+'.json');current=args.bundle/'catalog.json'
    current_schema=load(current).get('schemaVersion',2)
    compatibility=args.bundle/'catalog-v2.json' if current_schema==3 else current
    version=load(POLICY)['version']
    require(stable_version(version)>=stable_version('0.3.0'),'Previous schema2 migration is scoped to project-aware clients')
    matrix_bootstrap(args,root,binary,previous,published_binary=True,expected_version=previous_version)
    old_binary=descriptor(binary)['sha256']
    old_catalog=load(previous)
    old_tool=next(t for t in old_catalog['tools'] if t['rid']==baseline['rid'])
    require(old_tool['version']==previous_version and old_binary==old_tool['binary']['sha256'],
            'Schema2 migration did not execute the actual admitted public '+previous_version+' binary')
    baseline_exact=baseline['sdkVersion']+'-r'+str(baseline['revision'])
    matrix_user(root,[binary,'--catalog',previous,'install','--channel','10.0'])
    matrix_user(root,[binary,'doctor'])
    state_before=owned_sdk_state(root)
    installed=root/'toolchains-v2'/baseline_exact/baseline['rid']
    retained={name:descriptor(installed/name)['sha256'] for name in ('receipt.json','inventory.json','catalog.json')}
    require(retained['catalog.json']==descriptor(previous)['sha256'],
            'Old schema2 SDK receipt did not retain its actual bootstrap catalog')
    manager=[binary,'--catalog',compatibility]
    if args.public:
        matrix_user(root,[*manager,'self','update'])
        require(matrix_user(root,[binary,'--version']).stdout.strip()==version
                and descriptor(Path(str(binary)+'.previous'))['sha256']==old_binary,
                'Actual schema2 self-update did not retain its public '+previous_version+' executable')
        matrix_user(root,[*manager,'self','rollback'])
        require(matrix_user(root,[binary,'--version']).stdout.strip()==previous_version
                and descriptor(binary)['sha256']==old_binary,
                'Actual schema2 tool rollback did not restore public '+previous_version+' bytes')
        result=matrix_user(root,[binary,'run',baseline_exact,'--','--version'])
        require(result.stdout==baseline['sdkVersion']+'\n' and result.stderr==MULTI.BRAND+'\n',
                'Rolled-back schema2 client could not execute its retained SDK from a clean user cwd')
        require(owned_sdk_state(root)==state_before,'Schema2 tool rollback changed retained SDK receipts or selection')
        matrix_user(root,[*manager,'self','update'])
    else:
        # Candidate URLs do not exist yet. The bootstrap admits only the exact
        # frozen current binary/notices; public verification runs real self-update.
        matrix_bootstrap(args,root,binary,current)
    require(matrix_user(root,[binary,'--version']).stdout.strip()==version,
            'Schema2 client failed to upgrade to the candidate/current tool')
    if current_schema==3:
        # Released schema2 clients authenticate only the compatibility feed.
        # The upgraded client must independently authenticate v3 before its
        # provider-aware operations; the original receipt/cache stays intact.
        matrix_user(root,[binary,'--catalog',current,'list','--available'])
    matrix_user(root,[binary,'doctor'])
    require(owned_sdk_state(root)==state_before and all(descriptor(installed/name)['sha256']==sha for name,sha in retained.items()),
            'Schema2 tool upgrade changed retained SDK bytes, receipts, inventory or active selection')
    proof=dict(status='passed',fromVersion=previous_version,toVersion=version,
        protocol='actual-'+previous_version+'-self-update-rollback-reupgrade' if args.public else 'protected-frozen-candidate-bootstrap-from-'+previous_version,
        oldBinarySha256=old_binary,currentBinarySha256=descriptor(binary)['sha256'],
        previousCatalogSha256=descriptor(previous)['sha256'],currentCatalogSha256=descriptor(current)['sha256'],
        baseline=dict(sdkVersion=baseline['sdkVersion'],revision=baseline['revision'],rid=baseline['rid']),
        baselineReceiptSha256=retained['receipt.json'],baselineInventorySha256=retained['inventory.json'],
        baselineCatalogSha256=retained['catalog.json'],
        baselineOwnedStateSha256=hashlib.sha256(encoded(state_before)).hexdigest(),
        baselineReceiptUnchanged=True,baselineOwnedStateUnchanged=True,baselinePayloadVerified=True,rollbackVerified=args.public)
    if current_schema==3:proof['compatibilityCatalogSha256']=descriptor(compatibility)['sha256']
    return proof


def native_matrix_install(args):
    from cbodotnetup_legacy import LEGACY_VERSIONS
    if args.sdk_version in LEGACY_VERSIONS:
        import cbodotnetup_legacy
        import sys
        return cbodotnetup_legacy.install(args,sys.modules[__name__])
    MULTI.check_container(args.variant,args.arch);verify_bundle(args.bundle)
    catalog_value,sdk=matrix_sdk(args);root,binary=matrix_paths(args)
    require(not root.exists() and not binary.parent.exists(),'Fresh independent additional-SDK user root required')
    exact=sdk['sdkVersion']+'-r'+str(sdk['revision']);series='.'.join(sdk['sdkVersion'].split('.')[:2])
    baseline=next(s for s in catalog_value['sdks'] if s['sdkVersion']=='10.0.403' and s['rid']==sdk['rid'])
    baseline_exact=baseline['sdkVersion']+'-r'+str(baseline['revision'])
    previous_upgrade=None
    if stable_version(load(POLICY)['version'])>=stable_version('0.3.0'):
        previous_upgrade=matrix_previous_tool_upgrade(args,root,binary,baseline)
    else:
        matrix_bootstrap(args,root,binary,args.bundle/'catalog.json')
        matrix_user(root,[binary,'--catalog',args.bundle/'catalog.json','install','--channel','10.0'])
    manager=[binary,'--catalog',args.bundle/'catalog.json']
    bad=root/'bad-catalog.json';bad.write_bytes((args.bundle/'catalog.json').read_bytes()+b' ')
    shutil.copyfile(args.bundle/'catalog.json.asc',str(bad)+'.asc')
    active_cache=root/('cache/v3' if catalog_value['schemaVersion']==3 else 'cache/v2')
    high=(active_cache/'high-water.json').read_bytes()
    require(matrix_user(root,[binary,'--catalog',bad,'list','--available'],check=False).returncode!=0,
            'Additional SDK accepted a modified catalog signature')
    require((active_cache/'high-water.json').read_bytes()==high,'Signature rejection changed the active catalog watermark')
    require(matrix_user(root,[*manager,'install','99.0.999'],check=False).returncode!=0,'Additional SDK resolver accepted an unqualified version')
    log=args.workspace/('sdk-'+sdk['sdkVersion']+'-interrupted.log')
    with log.open('w') as output:
        child=user_process([*manager,'install',exact],stdout=output,extra_environment={'CBODOTNETUP_HOME':str(root)})
        interrupted=False
        try:
            deadline=time.monotonic()+90
            while child.poll() is None and time.monotonic()<deadline:
                if any((stage/'source.json').is_file() for stage in (root/'staging').iterdir() if stage.is_dir()):
                    os.killpg(child.pid,signal.SIGKILL);interrupted=True;break
                time.sleep(0.02)
        finally:
            if child.poll() is None:os.killpg(child.pid,signal.SIGKILL)
            child.wait(timeout=30)
    require(interrupted and not (root/'toolchains-v2'/exact/sdk['rid']).exists(),
            'Interrupted additional SDK installation exposed a partial active root; '+log.read_text()[-3000:])
    matrix_user(root,[*manager,'install','--channel',series]);matrix_user(root,[*manager,'install',exact])
    matrix_user(root,[*manager,'update']);matrix_user(root,[*manager,'rollback',exact])
    require(set(matrix_user(root,[binary,'list']).stdout.splitlines())=={baseline_exact+'/'+sdk['rid'],exact+'/'+sdk['rid']},
            'Additional SDK install/update changed the independent installation set')
    matrix_user(root,[binary,'shell','enable'])
    # Use a separate cache/root for the same-sequence signed revocation fixture.
    # It must never replace the normal feed or poison its anti-rollback record.
    revoked_root,revoked_binary=matrix_paths(args,revoked=True)
    matrix_bootstrap(args,revoked_root,revoked_binary,args.bundle/'catalog-v2-revoked.json')
    require(matrix_user(revoked_root,[revoked_binary,'--catalog',args.bundle/'catalog-v2-revoked.json','install',exact],check=False).returncode!=0,
            'A revoked additional SDK was installed')
    require(all(not list((revoked_root/name).iterdir()) for name in ('toolchains','toolchains-v2','staging')),
            'Revoked SDK rejection wrote an active or staging installation')
    # The bootstrap and managed client serialize identical watermark records
    # with different whitespace. A valid main-catalog request may normalize it
    # during this cycle; only a sequence/hash change indicates fixture leakage.
    require(load(active_cache/'high-water.json')==json.loads(high),'Independent revoked fixture changed the normal catalog watermark')
    save(args.workspace/('sdk-'+sdk['sdkVersion']+'-state.json'),dict(sdk=sdk,exact=exact,baseline=baseline,
        baselineExact=baseline_exact,catalogSha256=descriptor(args.bundle/'catalog.json')['sha256'],
        previousToolUpgrade=previous_upgrade,
        bootstrapSha256=descriptor(args.bundle/'get-cbodotnetup.py')['sha256'],binarySha256=descriptor(binary)['sha256'],
        bootstrapBinarySource='public-https' if args.public else 'protected-frozen-candidate'))


def native_matrix_smoke(args):
    from cbodotnetup_legacy import LEGACY_VERSIONS
    if args.sdk_version in LEGACY_VERSIONS:
        import cbodotnetup_legacy
        import sys
        return cbodotnetup_legacy.smoke(args,sys.modules[__name__])
    from cbodotnetup_matrix import SDK_CHECKS
    from cbodotnetup_project import qualify_project_selection,qualify_reference
    from sdk_runtime import smoke_script,validate_smoke_output
    MULTI.check_container(args.variant,args.arch,offline=True)
    state=load(args.workspace/('sdk-'+args.sdk_version+'-state.json'));sdk=state['sdk'];root,binary=matrix_paths(args)
    exact=state['exact'];baseline_exact=state['baselineExact'];home=Path('/home')/MULTI.USER
    expected_series='.'.join(sdk['sdkVersion'].split('.')[:2]);aliases=[]
    for alias,expected in (('cbodotnet','10.0.403'),('cbodotnet-10.0','10.0.403'),('cbodotnet-'+expected_series,sdk['sdkVersion'])):
        result=matrix_user(root,[root/'bin'/alias,'--version'])
        require(result.stdout==expected+'\n' and result.stderr==MULTI.BRAND+'\n','An additional SDK alias lost branding or chose the wrong default')
        info=json.loads(matrix_user(root,[root/'bin'/alias,'--cbodotnet-info']).stdout)
        require(info['sdkVersion']==expected,'Additional SDK alias source identity differs')
        if expected==sdk['sdkVersion']:
            require(info['sourceManifestSha256']==sdk['sourceManifestSha256'] and info['packageRevision']==sdk['revision']
                    and info['targetRid']==sdk['rid'] and info['qualifiedPayloadModified'] is False,
                    'Additional SDK alias differs from the exact admitted source/revision/RID')
        aliases.append(info)
    result=matrix_user(root,[binary,'run',exact,'--','--version'])
    require(result.stdout==sdk['sdkVersion']+'\n' and result.stderr==MULTI.BRAND+'\n','Explicit additional SDK run selected another toolchain')
    payload=root/'toolchains-v2'/exact/sdk['rid']/'content'/sdk['archiveRoot']/'payload'
    wrapper=home/('run-managed-sdk-'+sdk['sdkVersion']+'.sh')
    wrapper.write_text('#!/bin/sh\nexec env CBODOTNETUP_HOME='+shlex.quote(str(root))+' '+shlex.quote(str(binary))+' run '+shlex.quote(exact)+' -- "$@"\n')
    wrapper.chmod(0o755)
    functional=validate_smoke_output(matrix_user(root,['sh','-ec',smoke_script(sdk['sdkVersion'],str(payload),MULTI.USER,
        cli=str(wrapper),workdir=str(home/('offline-cbodotnetup-'+sdk['sdkVersion'])))]).stdout)
    report=load(args.workspace/'report.json')
    if 'projectSdkReference' not in report:
        baseline=state['baseline']
        reference_payload=root/'toolchains-v2'/baseline_exact/baseline['rid']/'content'/baseline['archiveRoot']/'payload'
        report['projectSdkReference']=qualify_reference(reference_payload,args.workspace/'project-sdk-reference')
        save(args.workspace/'report.json',report)
    project_selection=qualify_project_selection(root,binary,sdk,state['baseline'],
        home/('cbodotnetup-project-selection-'+sdk['sdkVersion']),matrix_user)
    matrix_user(root,[binary,'doctor'])
    notice=payload/'LICENSE.txt';original=notice.read_bytes();notice.write_bytes(original+b'changed')
    require(matrix_user(root,[binary,'doctor'],check=False).returncode!=0,'Modified additional SDK bytes were accepted')
    notice.write_bytes(original)
    import fcntl
    with (root/'operation.lock').open('a+b') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        require(matrix_user(root,[binary,'list'],check=False).returncode!=0,'Additional SDK operation ignored its inter-process lock')
    require(list((root/'staging').iterdir()),'Additional SDK interrupted install left no owned recovery stage')
    matrix_user(root,[binary,'gc']);require(not list((root/'staging').iterdir()),'Additional SDK recovery did not collect its abandoned stage')
    matrix_user(root,[binary,'rollback',exact])
    require(matrix_user(root,[binary,'run',exact,'--','--version']).stdout==sdk['sdkVersion']+'\n','Retained additional SDK selection was not executable')
    matrix_user(root,[binary,'remove',exact])
    require(matrix_user(root,[binary,'list']).stdout.strip()==baseline_exact+'/'+sdk['rid'],'Additional SDK removal changed the retained SDK10 installation')
    require(matrix_user(root,[root/'bin/cbodotnet','--version']).stdout=='10.0.403\n','Additional SDK removal changed the highest-series default')
    require(matrix_user(root,[binary,'rollback',exact],check=False).returncode!=0,'Removed additional SDK silently selected another installation')
    matrix_user(root,[binary,'doctor']);matrix_user(root,[binary,'remove',baseline_exact])
    require(matrix_user(root,[binary,'list']).stdout=='','Additional SDK test left an installed payload')
    absent=matrix_user(root,[root/'bin/cbodotnet','--version'],check=False)
    require(absent.returncode!=0 and not absent.stdout,'Empty additional SDK root fell back to a system/package SDK')
    matrix_user(root,[binary,'shell','disable'])
    original_state=load(args.workspace/'installed.json')
    require(MULTI.APT.inventory(Path('/opt/cbodotnet'))==original_state['packageInventory'],
            'Additional SDK lifecycle modified package-managed Community files')
    MULTI.integrity(original_state['packages'],MULTI.TARGETS[args.variant])
    if MULTI.TARGETS[args.variant]=='deb':from apt_official import assert_unchanged
    else:from rpm_official import assert_unchanged
    assert_unchanged(args.workspace/'official.json')
    require((home/'.local/share/dotnetup/owner-test').read_text()=='untouched','Additional SDK changed official installer state')
    target=load_contract()['operatingSystems'][args.variant]
    observation=dict(status='passed',sdkVersion=sdk['sdkVersion'],revision=sdk['revision'],rid=sdk['rid'],
        target=dict(os=target['id'],versionId=target['versionId'],rid=sdk['rid']),variant=args.variant,architecture=args.arch,
        archive=sdk['archive'],sourceManifestSha256=sdk['sourceManifestSha256'],catalogSha256=state['catalogSha256'],
        bootstrapSha256=state['bootstrapSha256'],binarySha256=state['binarySha256'],bootstrapBinarySource=state['bootstrapBinarySource'],
        networkForBuild='none',userId=10001,checks=dict.fromkeys(SDK_CHECKS,'passed'),functionalChecks=functional,aliases=aliases,
        projectSelection=project_selection,
        previousToolUpgrade=state.get('previousToolUpgrade'),
        rollbackScope='retained exact admitted additional SDK revision; cross-revision r2/r3 and tool rollback covered by SDK10 regression')
    save(args.workspace/('sdk-'+sdk['sdkVersion']+'-observation.json'),observation)
    report=load(args.workspace/'report.json');report.setdefault('additionalSdkQualifications',[]).append(observation)
    save(args.workspace/'report.json',report)


def native(args):
    if args.variant=='alpine-3.24':
        from cbodotnetup_musl_native import qualify
        return qualify(args.bundle,args.arch,args.workspace,public=args.public)
    verify_bundle(args.bundle)
    require(platform.machine() in ({'x86_64'} if args.arch=='x64' else {'aarch64','arm64'}),'Native CPU required')
    workspace=args.workspace.resolve();require(not workspace.exists(),'Fresh native workspace required');workspace.mkdir(parents=True)
    mounts=['-v',f'{ROOT}:/repo:ro','-v',f'{args.bundle.resolve()}:/bundle:ro','-v',f'{workspace}:/delivery']
    mounts += [part for name in ('GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT') for part in ('-e',name)]
    common=['--bundle','/bundle','--variant',args.variant,'--arch',args.arch,'--workspace','/delivery/installed']
    if args.public:common+=['--public']
    command=['python3','/repo/scripts/cbodotnetup-release.py'];cid=None
    try:
        # Consumer prerequisites are explicit, before any SDK/tool execution.
        # Minimal Fedora images now provide OpenSSL 4, while the reviewed .NET
        # dependency contract requires the maintained openssl3-libs package.
        contract=load_contract()
        from distribution_contract import native_dependencies
        versions={sdk['sdkVersion'] for sdk in load(args.bundle/'catalog.json')['sdks']}
        dependencies=list(dict.fromkeys(name for version in sorted(versions)
            for name in native_dependencies(contract,version,args.variant)))
        require(dependencies and all(re.fullmatch(r'[A-Za-z0-9+_.()\-]+',name) for name in dependencies),'Unsafe or missing consumer prerequisites')
        install=['apt-get','install','-y','--no-install-recommends'] if MULTI.TARGETS[args.variant]=='deb' else ['dnf','-y','--setopt=install_weak_deps=False','--setopt=tsflags=','install']
        ready='/tmp/cbodotnetup-qualification-ready'
        script='rm -f '+ready+'\n'+MULTI.bootstrap_script(args.variant)+shlex.join(install+dependencies)+'\ntouch '+ready+'\nexec sleep infinity'
        cid=subprocess.check_output(['docker','create','--network','bridge','--user','0',*mounts,QUALIFICATION_BASES[args.variant][args.arch],'sh','-ec',script],text=True).strip()
        run(['docker','start',cid])
        deadline=time.monotonic()+900
        while True:
            info=json.loads(subprocess.check_output(['docker','inspect',cid],text=True))[0]
            if not info['State']['Running'] or time.monotonic()>=deadline:
                logs=subprocess.check_output(['docker','logs',cid],text=True,stderr=subprocess.STDOUT)
                raise ValueError('Native consumer prerequisite provisioning failed or timed out:\n'+logs[-12000:])
            if subprocess.run(['docker','exec',cid,'test','-f',ready],capture_output=True).returncode==0:break
            time.sleep(1)
        run(['docker','exec',cid,*command,'native-install',*common])
        run(['docker','network','disconnect','bridge',cid])
        run(['docker','exec',cid,*command,'native-smoke',*common])
        os_target=load_contract()['operatingSystems'][args.variant]
        actual_target=dict(os=os_target['id'],versionId=os_target['versionId'],rid='linux-x64' if args.arch=='x64' else 'linux-arm64')
        versions=list(dict.fromkeys(s['sdkVersion'] for s in load(args.bundle/'catalog.json')['sdks']
            if s['sdkVersion']!='10.0.403' and s['rid']==actual_target['rid'] and actual_target in s['targets']))
        for version in versions:
            run(['docker','network','connect','bridge',cid])
            run(['docker','exec',cid,*command,'native-matrix-install',*common,'--sdk-version',version])
            run(['docker','network','disconnect','bridge',cid])
            run(['docker','exec',cid,*command,'native-matrix-smoke',*common,'--sdk-version',version])
        shutil.copyfile(workspace/'installed/report.json',workspace/'report.json')
    finally:
        if cid:subprocess.run(['docker','rm','--force',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def qualified_reports(bundle,directory,*,public=False):
    from cbodotnetup_matrix import validate_additional_sdk_qualifications
    freeze=verify_bundle(bundle);api=GitHubReleases();reports={};proof=[]
    for path in Path(directory).rglob('report.json'):
        value=load(path);target=(value['variant'],value['architecture'])
        if target[0]=='alpine-3.24':continue
        require(target not in reports and target[0] in MULTI.TARGETS and target[1] in ('x64','aarch64'),'Duplicate or unreviewed installer target')
        require(value['schemaVersion']==1 and value['scope']=='cbodotnetup-native-installation' and value['status']=='passed'
                and value.get('baseImage')==QUALIFICATION_BASES[target[0]][target[1]]
                and value['checks']==dict.fromkeys(CHECKS,'passed') and value['networkForBuild']=='none' and value['userId']==10001
                and value['bootstrapBinarySource']==('public-https' if public else 'protected-frozen-candidate')
                and value['freezeSha256']==descriptor(Path(bundle)/'freeze.json')['sha256']
                and value['catalogSha256']==descriptor(Path(bundle)/'catalog.json')['sha256']
                and value['bootstrapSha256']==descriptor(Path(bundle)/'get-cbodotnetup.py')['sha256']
                and value['packageManagedCommunityIntegrity']=='unchanged'
                and value['functionalChecks']==dict.fromkeys(FUNCTIONAL_CHECKS,'passed'),'Incomplete native installer qualification')
        migration=value.get('migration',{})
        require(migration.get('status')=='passed' and migration.get('protocol')==('actual-0.1.0-self-update-rollback-reupgrade' if public else 'actual-0.1.0-frozen-bootstrap-migration')
                and migration.get('legacyCatalogSha256')==descriptor(Path(bundle)/'catalog-v1.json')['sha256']
                and all(migration.get(check)=='passed' for check in ('expiredCatalogRejection','legacyCachePreserved','interruptedOwnershipRecovery','sdkRollback')),
                'Actual legacy client migration/recovery evidence is required')
        rid='linux-x64' if target[1]=='x64' else 'linux-arm64'
        require(value['binarySha256']==descriptor(Path(bundle)/'tools'/rid/('cbodotnetup-'+rid))['sha256'],'Qualified binary differs from frozen bytes')
        source=value['orchestration'];run_record=api.api(f'repos/dotnetdev-kr/cbodotnet/actions/runs/{source["runId"]}/attempts/{source["runAttempt"]}')
        require(source['repository']=='dotnetdev-kr/cbodotnet' and source['workflow']==WORKFLOW and run_record['head_sha']==source['commit']
                and run_record['path']==WORKFLOW and run_record['head_branch']=='main' and run_record['repository']['full_name']=='dotnetdev-kr/cbodotnet'
                and run_record['head_repository']['full_name']=='dotnetdev-kr/cbodotnet' and run_record['event']=='workflow_dispatch','Unapproved installer verification workflow')
        jobs=api.api(f'repos/dotnetdev-kr/cbodotnet/actions/runs/{source["runId"]}/attempts/{source["runAttempt"]}/jobs?per_page=100')['jobs']
        job_name=('Verify public cbodotnetup on ' if public else 'Qualify cbodotnetup on ')+target[0]+' native '+target[1]
        selected=[j for j in jobs if j['name']==job_name]
        require(len(selected)==1 and selected[0]['status']=='completed' and selected[0]['conclusion']=='success','Actual native installer job did not succeed')
        name=('cbodotnetup-public-proof-' if public else 'cbodotnetup-native-proof-')+target[0]+'-'+target[1]+'-'+source['runId']+'-'+source['runAttempt']
        artifacts=api.api(f'repos/dotnetdev-kr/cbodotnet/actions/runs/{source["runId"]}/artifacts?per_page=100')
        selected_artifacts=[a for a in artifacts['artifacts'] if a['name']==name]
        require(len(selected_artifacts)==1 and artifacts['total_count']<=100,'Exact native report artifact is absent or ambiguous')
        artifact=selected_artifacts[0]
        raw=subprocess.check_output(['gh','api',f'repos/dotnetdev-kr/cbodotnet/actions/artifacts/{artifact["id"]}/zip'])
        require(not artifact['expired'] and len(raw)==artifact['size_in_bytes']<=32*1024**2
                and 'sha256:'+hashlib.sha256(raw).hexdigest()==artifact['digest'],'Native report ZIP changed')
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members=[m for m in archive.infolist() if m.filename=='report.json']
            require(len(members)==1 and members[0].file_size<=2*1024**2,'Actual report JSON is absent or too large')
            actual=archive.read(members[0]);require(actual==path.read_bytes(),'Supplied proof differs from the actual job report JSON')
        proof.append(dict(variant=target[0],architecture=target[1],jobId=selected[0]['id'],jobName=job_name,
            workflow=source,artifact=dict(id=artifact['id'],size=len(raw),sha256=hashlib.sha256(raw).hexdigest()),report=descriptor(path),observation=value))
        reports[target]=value
    require(set(reports)=={(v,a) for v in MULTI.TARGETS for a in ('x64','aarch64')},'All eight actual native targets are mandatory')
    catalog_value=load(Path(bundle)/'catalog.json')
    compatibility=load(Path(bundle)/'catalog-v2.json') if catalog_value['schemaVersion']==3 else None
    validate_additional_sdk_qualifications(catalog_value,list(reports.values()),tool_version=freeze['version'],
                                         compatibility_catalog=compatibility)
    if catalog_value['schemaVersion']==3:
        from cbodotnetup_legacy import validate_legacy_qualifications
        validate_legacy_qualifications(catalog_value,list(reports.values()),tool_version=freeze['version'],
                                       compatibility_catalog=compatibility)
    if stable_version(freeze['version'])>=stable_version('0.5.0'):
        proof+=qualified_musl_reports(bundle,directory,public=public)
    return proof


def qualified_musl_reports(bundle,directory,*,public=False):
    from cbodotnetup_musl_native import validate_qualification_report
    api=GitHubReleases();proof=[];seen=set()
    for path in Path(directory).rglob('report.json'):
        value=load(path)
        if value.get('variant')!='alpine-3.24':continue
        arch=value.get('architecture');require(arch in ('x64','aarch64') and arch not in seen,'Ambiguous musl native proof');seen.add(arch)
        validate_qualification_report(value,bundle,arch,public=public)
        source=value['orchestration']
        record=api.api(f'repos/dotnetdev-kr/cbodotnet/actions/runs/{source["runId"]}/attempts/{source["runAttempt"]}')
        require(source['repository']=='dotnetdev-kr/cbodotnet' and source['workflow']==WORKFLOW
            and record['head_sha']==source['commit'] and record['path']==WORKFLOW and record['head_branch']=='main'
            and record['repository']['full_name']=='dotnetdev-kr/cbodotnet' and record['head_repository']['full_name']=='dotnetdev-kr/cbodotnet'
            and record['event']=='workflow_dispatch','Unapproved musl native workflow')
        jobs=api.api(f'repos/dotnetdev-kr/cbodotnet/actions/runs/{source["runId"]}/attempts/{source["runAttempt"]}/jobs?per_page=100')['jobs']
        job_name=('Verify public cbodotnetup on ' if public else 'Qualify cbodotnetup on ')+'alpine-3.24 native '+arch
        selected=[j for j in jobs if j['name']==job_name]
        require(len(selected)==1 and selected[0]['status']=='completed' and selected[0]['conclusion']=='success','Actual musl job did not succeed')
        name=('cbodotnetup-public-proof-' if public else 'cbodotnetup-native-proof-')+'alpine-3.24-'+arch+'-'+source['runId']+'-'+source['runAttempt']
        artifacts=api.api(f'repos/dotnetdev-kr/cbodotnet/actions/runs/{source["runId"]}/artifacts?per_page=100')
        selected_artifacts=[a for a in artifacts['artifacts'] if a['name']==name]
        require(len(selected_artifacts)==1 and artifacts['total_count']<=100,'Musl proof artifact is absent or ambiguous')
        artifact=selected_artifacts[0]
        raw=subprocess.check_output(['gh','api',f'repos/dotnetdev-kr/cbodotnet/actions/artifacts/{artifact["id"]}/zip'])
        require(not artifact['expired'] and len(raw)==artifact['size_in_bytes']<=32*1024**2 and 'sha256:'+hashlib.sha256(raw).hexdigest()==artifact['digest'],'Musl proof ZIP changed')
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members=[m for m in archive.infolist() if m.filename=='report.json']
            require(len(members)==1 and members[0].file_size<=2*1024**2 and archive.read(members[0])==path.read_bytes(),'Musl proof differs from the actual job')
        proof.append(dict(variant='alpine-3.24',architecture=arch,jobId=selected[0]['id'],jobName=job_name,
            workflow=source,artifact=dict(id=artifact['id'],size=len(raw),sha256=hashlib.sha256(raw).hexdigest()),report=descriptor(path),observation=value))
    require(seen=={'x64','aarch64'},'Both actual Alpine musl native reports are mandatory')
    return proof


def upload_release(tag,target,assets,title,body):
    api=GitHubReleases();existing=api.find(tag)
    if existing is None:
        ref=api.api('repos/dotnetdev-kr/cbodotnet/git/ref/tags/'+tag)
        require(ref is None or ref['object']['type']=='commit' and ref['object']['sha']==target,'Existing tag has unrelated source')
        existing=api.api('repos/dotnetdev-kr/cbodotnet/releases','POST',dict(tag_name=tag,target_commitish=target,name=title,body=body,draft=True,prerelease=False,make_latest='false'))
    require(existing['tag_name']==tag and existing['target_commitish']==target and not existing['prerelease'],'Immutable installer release source or flags differ')
    expected=[descriptor(p) for p in assets];index={a['name']:a for a in expected}
    require(len(index)==len(expected),'Duplicate release asset name')
    current=api.get(existing)
    require(set(a['name'] for a in current['assets'])<=set(index),'Unrelated release asset exists')
    for path in assets:
        matching=[a for a in current['assets'] if a['name']==path.name]
        if matching:
            require(len(matching)==1 and matching[0]['size']==index[path.name]['size'] and matching[0]['digest']=='sha256:'+index[path.name]['sha256'],'Existing immutable release asset conflicts')
        else:
            require(current['draft'],'Cannot add bytes to an existing published installer identity');api.upload(current,path)
    current=api.get(existing);verify_remote_assets(current,index,api)
    if current['draft']:current=api.publish(current)
    current=api.get(current);verify_remote_assets(current,index,api,public=True)
    ref=api.api('repos/dotnetdev-kr/cbodotnet/git/ref/tags/'+tag)
    require(ref and ref['object']['type']=='commit' and ref['object']['sha']==target,'Published installer tag source changed')
    return dict(id=current['id'],tag=tag,targetCommit=target,url=current['html_url'],
        assets=[dict(item,url='https://github.com/dotnetdev-kr/cbodotnet/releases/download/'+tag+'/'+item['name']) for item in expected])


def pack(directory,destination):
    import gzip
    with Path(destination).open('xb') as raw,gzip.GzipFile(filename='',fileobj=raw,mode='wb',mtime=0) as compressed,tarfile.open(fileobj=compressed,mode='w|',format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(Path(directory).rglob('*')):
            require(not path.is_symlink(),'Publication source tree cannot contain links')
            info=archive.gettarinfo(str(path),path.relative_to(directory).as_posix());info.uid=info.gid=info.mtime=0;info.uname=info.gname=''
            if path.is_file():
                with path.open('rb') as incoming:archive.addfile(info,incoming)
            else:archive.addfile(info)


def publish(args):
    freeze=verify_bundle(args.bundle);proof=qualified_reports(args.bundle,args.reports)
    output=args.output;require(not output.exists(),'Fresh publication output required');output.mkdir(parents=True)
    tools=output/'tool-assets';tools.mkdir();version=freeze['version'];source=None
    musl_aware=stable_version(version)>=stable_version('0.5.0')
    targets=[('x64','linux-x64'),('aarch64','linux-arm64')]
    if musl_aware:targets += [('x64','linux-musl-x64'),('aarch64','linux-musl-arm64')]
    for arch,rid in targets:
        directory=args.bundle/'tools'/rid;build_report=load(directory/'build.json')
        if source is None:source=build_report['source']['commit']
        require(build_report['source']['commit']==source,'Both tool binaries must have one exact source commit')
        for name in ('cbodotnetup-'+rid,'cbodotnetup-'+rid+'.LICENSE.txt'):shutil.copyfile(directory/name,tools/name)
        shutil.copyfile(directory/'build.json',tools/('build-'+(rid if musl_aware else arch)+'.json'))
    shutil.copyfile(ROOT/'LICENSE',tools/'LICENSE')
    source_paths=['tools','LICENSE','releases/cbodotnetup-policy.json','releases/downstream-signing-key.asc','scripts/get-cbodotnetup.py']
    if stable_version(version)>=stable_version('0.4.0'):source_paths.append('releases/cbodotnetup-provider-policy.json')
    # Musl build provenance includes shared helpers and frozen APK snapshots.
    # Archive the exact tracked repository so their transitive inputs remain
    # available alongside the tool sources; local workspaces are never included.
    if musl_aware:source_paths=[]
    run(['git','archive','--format=tar.gz','--output',tools/'cbodotnetup-source.tar.gz',source,*source_paths])
    baseline_release=None
    if musl_aware:
        baseline=output/'baseline-assets';baseline.mkdir()
        for arch,rid in targets:
            if not rid.startswith('linux-musl-'):continue
            directory=args.bundle/'tools'/rid/'baseline'
            for name in ('cbodotnetup-'+rid,'cbodotnetup-'+rid+'.LICENSE.txt'):shutil.copyfile(directory/name,baseline/name)
            shutil.copyfile(directory/'provenance.json',baseline/('build-'+rid+'.json'))
        for name in ('LICENSE','cbodotnetup-source.tar.gz'):shutil.copyfile(tools/name,baseline/name)
        baseline_release=upload_release('cbodotnetup-v0.5.0',source,sorted(baseline.iterdir()),'cbodotnetup 0.5.0 - Alpine bootstrap qualification baseline',
            'Initial real Alpine3.24.4 NativeAOT x64/AArch64 tool binaries, retained for signed bootstrap/self-update/rollback qualification against0.5.1. '
            'Use the current project-signed default bootstrap to select the latest admitted tool. Built from the same reviewed source as0.5.1 with explicit Version=0.5.0; exact source, native package/ELF inputs and notices are included. '
            'This baseline does not admit additional SDKs or older Alpine versions. No gcompat/glibc shim is used.')
    tool_release=upload_release('cbodotnetup-v'+version,source,sorted(tools.iterdir()),'cbodotnetup '+version+' - verified Community Build SDK manager',
        'SDK-free NativeAOT installer for qualified Community Build of .NET SDKs. Verify the current project-signed installation catalog and its independently pinned OpenPGP key. '
        'Linux glibc x64/AArch64; Ubuntu24.04, Debian13, Fedora45 and Rocky9.8. Qualified SDKs:10.0.403,9.0.123,8.0.133,7.0.120,6.0.136,5.0.214,3.1.426,3.0.103. '
        'Native runtime 10.0.14; the SDK payload stays unchanged. Per-user roots preserve official and package-managed commands. '
        'Each binary has exact signed native runtime/project license and third-party notices in its adjacent .LICENSE.txt asset. '
        'Version 0.4 adds explicitly opted-in signed user-scoped legacy providers, immutable shared provider objects and per-SDK source/ABI binding. '
        'SDK5/Core3 retain their upstream EOL status. Offline global.json selection and owned CLI/MSBuild binding continue. '
        'Missing SDKs require explicit installation; project and shell files stay unchanged. The versioned schema3 feed admits legacy providers, while schema2 remains modern-only and schema1 keeps 0.1 clients able to self-update. '
        'Version0.5 adds native musl x64/AArch64 binaries and a separate schema4 feed for Alpine3.24.4/SDK10.0.403-r1 only. No glibc compatibility shim or private legacy provider is used. '
        'Build/source records are retained; current signed catalog qualification is published separately. This release does not replace the latest SDK download.')
    catalog_assets=output/'catalog-assets';catalog_assets.mkdir()
    for name in (*CATALOG_ASSETS,'freeze.json','freeze.json.asc','get-cbodotnetup.py'):
        if not (args.bundle/name).exists():continue  # Historical frozen catalog generations.
        shutil.copyfile(args.bundle/name,catalog_assets/name)
    pack(args.bundle,catalog_assets/'cbodotnetup-verification-inputs.tar.gz')
    save(catalog_assets/'native-qualification.json',dict(status='passed',targets=proof))
    catalog_value=load(args.bundle/'catalog.json')
    release=upload_release('cbodotnetup-catalog-'+str(catalog_value['sequence']),freeze['source']['commit'],sorted(catalog_assets.iterdir()),
        'cbodotnetup signed installation catalog '+str(catalog_value['sequence']),
        'Project-signed installation catalog with bounded freshness, revocation, source/producer pins and immutable SDK/tool hashes. '
        'Every admitted native OS/CPU qualification target passed before this publication. Public bootstrap/native post-verification is recorded before feed activation. '
        'catalog.json is the provider-aware schema3 feed; catalog-v2.json is modern-only schema2 and catalog-v1.json is compatible schema1. '
        'catalog-musl.json is the separate schema4 Alpine/musl feed; it never changes the schema1/2/3 glibc projections. '
        'All bootstrap, baseline, expired, revoked, incompatible and previous-tool catalogs are test-only qualification fixtures, not installation feeds. '
        'AUR publication remains deferred under issue10.')
    publication=dict(schemaVersion=1,kind='cbodotnetup-publication',status='published-public-bytes-verified',
        version=version,source=freeze['source'],toolRelease=tool_release,catalogRelease=release,nativeQualification=proof,
        catalogSequence=catalog_value['sequence'],catalogSha256=descriptor(args.bundle/'catalog.json')['sha256'],
        legacyCatalogSequence=load(args.bundle/'catalog-v1.json')['sequence'],legacyCatalogSha256=descriptor(args.bundle/'catalog-v1.json')['sha256'])
    if catalog_value['schemaVersion']==3:
        publication.update(compatibilityCatalogSequence=load(args.bundle/'catalog-v2.json')['sequence'],
                           compatibilityCatalogSha256=descriptor(args.bundle/'catalog-v2.json')['sha256'])
    if musl_aware:publication.update(muslCatalogSequence=load(args.bundle/'catalog-musl.json')['sequence'],
        muslCatalogSha256=descriptor(args.bundle/'catalog-musl.json')['sha256'],baselineToolRelease=baseline_release)
    save(output/'publication.json',publication)


def receive_public(args):
    publication=load(args.publication);assets={a['name']:a for a in publication['catalogRelease']['assets']}
    require(publication['status']=='published-public-bytes-verified','Exact public installer publication required')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    archive=args.output.parent/'public-installer-inputs.tar.gz';fetch_asset(assets['cbodotnetup-verification-inputs.tar.gz'],archive)
    sdk_tools().extract_sdk(archive,args.output);verify_bundle(args.output)
    for name in (*CATALOG_ASSETS,'get-cbodotnetup.py'):
        if not (args.output/name).exists():continue  # Historical frozen catalog generations.
        raw=get_bytes(assets[name]['url'],assets[name]['size'])
        require(hashlib.sha256(raw).hexdigest()==assets[name]['sha256'] and raw==(args.output/name).read_bytes(),'Public consumer metadata differs from the frozen signed candidate')


def receive_published_builds(args):
    status=load(ROOT/'releases/cbodotnetup-status.json');require(status['status']=='published-postverified','No qualified installer exists to renew')
    require(not args.output.exists(),'Fresh published build input directory required');args.output.mkdir(parents=True)
    assets={a['name']:a for a in status['catalogRelease']['assets']}
    archive=args.output/'prior-inputs.tar.gz';fetch_asset(assets['cbodotnetup-verification-inputs.tar.gz'],archive)
    extracted=args.output/'prior';sdk_tools().extract_sdk(archive,extracted);verify_bundle(extracted)
    for directory in sorted((extracted/'tools').iterdir()):
        require(directory.is_dir() and directory.name in ('linux-x64','linux-arm64','linux-musl-x64','linux-musl-arm64'),'Unexpected published tool RID')
        shutil.copytree(directory,args.output/('native-'+directory.name))
    # Keep only authenticated build inputs for stage(); prevent duplicate build.json discovery.
    shutil.rmtree(extracted);archive.unlink()


def activate(args):
    publication=load(args.publication);proof=qualified_reports(args.bundle,args.reports,public=True)
    require(publication['catalogSha256']==descriptor(args.bundle/'catalog.json')['sha256'],'Public installer catalog differs')
    status=dict(schemaVersion=1,kind='cbodotnetup-availability',status='published-postverified',version=publication['version'],
        catalogSequence=publication['catalogSequence'],catalogSha256=publication['catalogSha256'],toolRelease=publication['toolRelease'],
        catalogRelease=publication['catalogRelease'],nativeQualification=publication['nativeQualification'],publicNativeVerification=proof,
        source=publication['source'],postVerification=source_identity())
    require(publication['legacyCatalogSha256']==descriptor(args.bundle/'catalog-v1.json')['sha256']
            and publication['legacyCatalogSequence']==publication['catalogSequence'], 'Public legacy migration feed differs')
    status.update(legacyCatalogSequence=publication['legacyCatalogSequence'],legacyCatalogSha256=publication['legacyCatalogSha256'])
    if 'compatibilityCatalogSha256' in publication:
        require(publication['compatibilityCatalogSha256']==descriptor(args.bundle/'catalog-v2.json')['sha256']
                and publication['compatibilityCatalogSequence']==publication['catalogSequence'],
                'Public compatible modern catalog differs')
        status.update(compatibilityCatalogSequence=publication['compatibilityCatalogSequence'],
                      compatibilityCatalogSha256=publication['compatibilityCatalogSha256'])
    if 'muslCatalogSha256' in publication:
        require(publication['muslCatalogSha256']==descriptor(args.bundle/'catalog-musl.json')['sha256']
            and publication['muslCatalogSequence']==publication['catalogSequence'],'Public musl catalog differs')
        status.update(muslCatalogSequence=publication['muslCatalogSequence'],muslCatalogSha256=publication['muslCatalogSha256'],baselineToolRelease=publication['baselineToolRelease'])
    save(args.output,status)
    api=GitHubReleases();path='releases/cbodotnetup-status.json'
    content=api.api('repos/dotnetdev-kr/cbodotnet/contents/'+path+'?ref=main')
    previous,lease=read_leased_json(api,path) if content is not None else (None,None)
    require(previous is None or previous.get('catalogSequence',0)<=status['catalogSequence'],'Catalog activation would roll back availability')
    import base64
    body=dict(message='Activate independently verified cbodotnetup '+status['version']+' catalog '+str(status['catalogSequence']),content=base64.b64encode(encoded(status)).decode(),branch='main')
    if lease is not None:body['sha']=lease['sha']
    if previous!=status:api.api('repos/dotnetdev-kr/cbodotnet/contents/'+path,'PUT',body)
    api.api('repos/dotnetdev-kr/cbodotnet/actions/workflows/pages.yml/dispatches','POST',dict(ref='main'))


def main():
    parser=argparse.ArgumentParser(description=__doc__); commands=parser.add_subparsers(dest='command',required=True)
    command=commands.add_parser('build'); command.add_argument('--arch',choices=('x64','aarch64'),required=True); command.add_argument('--workspace',type=Path,required=True); command.add_argument('--libc',choices=('glibc','musl'),default='glibc')
    for name in ('source-check','feed-smoke'):
        command=commands.add_parser(name);command.add_argument('--arch',choices=('x64','aarch64'),required=True);command.add_argument('--workspace',type=Path,required=True)
        command.add_argument('--libc',choices=('glibc','musl'),default='glibc')
    command=commands.add_parser('stage');command.add_argument('--received',type=Path,required=True);command.add_argument('--output',type=Path,required=True)
    for name in ('native','native-install','native-smoke','native-matrix-install','native-matrix-smoke'):
        command=commands.add_parser(name);command.add_argument('--bundle',type=Path,required=True);command.add_argument('--workspace',type=Path,required=True)
        command.add_argument('--arch',choices=('x64','aarch64'),required=True);command.add_argument('--variant',choices=(*MULTI.TARGETS,'alpine-3.24'),required=True)
        command.add_argument('--public',action='store_true')
        if name.startswith('native-matrix-'):command.add_argument('--sdk-version',required=True)
    for name in ('publish','activate'):
        command=commands.add_parser(name);command.add_argument('--bundle',type=Path,required=True);command.add_argument('--reports',type=Path,required=True);command.add_argument('--output',type=Path,required=True)
        if name=='activate':command.add_argument('--publication',type=Path,required=True)
    command=commands.add_parser('receive-public');command.add_argument('--publication',type=Path,required=True);command.add_argument('--output',type=Path,required=True)
    command=commands.add_parser('receive-published-builds');command.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    {'build':build,'source-check':source_check,'feed-smoke':feed_smoke,'stage':stage,'native':native,'native-install':native_install,'native-smoke':native_smoke,
     'native-matrix-install':native_matrix_install,'native-matrix-smoke':native_matrix_smoke,
     'publish':publish,'receive-public':receive_public,'receive-published-builds':receive_published_builds,'activate':activate}[args.command](args)


if __name__=='__main__':main()
