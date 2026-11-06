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
from distribution_contract import load_contract, validate_qualified_producers
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
    'x64': 'quay.io/fedora/fedora:45@sha256:79dd6556b8fe1a559051fad5159d4987ead218f1914e7a5bd20350d9ea0f9e52',
    'aarch64': 'quay.io/fedora/fedora:45@sha256:daf39f8ebfd7624260f632d705c380f6abd4c6b430ee133b2187c6297f1ce444'}}
LEGACY_BOOTSTRAP = dict(
    url='https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-catalog-41952285282/get-cbodotnetup.py',
    size=11478,sha256='534b549030a3b24e31c631f2df279730a0e2f7166a0c45114d245d477e184409')
CATALOG_ASSETS = ('catalog.json','catalog.json.asc','catalog-v1.json','catalog-v1.json.asc',
                  'catalog-v1-bootstrap.json','catalog-v1-bootstrap.json.asc',
                  'catalog-v1-expired.json','catalog-v1-expired.json.asc','get-cbodotnetup-v0.1.0.py')
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
        '/cbodotnet/cbodotnetup/v2/catalog.json','/cbodotnet/cbodotnetup/v2/catalog.json.asc'}
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
    for generation,key in (('v2','catalogSha256'),('v1','legacyCatalogSha256')):
        url='https://dotnetdev.kr/cbodotnet/cbodotnetup/'+('v2/' if generation=='v2' else '')+'catalog.json'
        data=public_metadata(url,8*1024**2)
        require(hashlib.sha256(data).hexdigest()==status[key],'Hosted catalog generation differs from activated signed bytes')
        catalog_value=json.loads(data)
        require(catalog_value['schemaVersion']==(2 if generation=='v2' else 1) and catalog_value['sequence']==status['catalogSequence'],'Hosted catalog schema/sequence differs')
        (workspace/('catalog-'+generation+'.json')).write_bytes(data)
        (workspace/('catalog-'+generation+'.json.asc')).write_bytes(public_metadata(url+'.asc',64*1024))
    keyring=workspace/'trusted.gpg'
    run(['gpg','--batch','--yes','--dearmor','--output',keyring,ROOT/'releases/downstream-signing-key.asc'],capture_output=True)
    for generation in ('v1','v2'):
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
Path('/feed/result.json').write_text(json.dumps(dict(status='passed',catalogSha256=hashlib.sha256((root/'catalog.json').read_bytes()).hexdigest(),sequence=json.loads((root/'catalog.json').read_bytes())['sequence'],bootstrapWithoutSdk=True)))
PY
'''
    run(['docker','run','--rm','--user','0','-v',f'{workspace}:/feed',MULTI.BASES['ubuntu-24.04'][args.arch],'sh','-ec',script])
    result=load(workspace/'result.json');require(result['catalogSha256']==status['catalogSha256'] and result['sequence']==status['catalogSequence'],'Default hosted catalog differs from exact activated version')
    result.update(scope='cbodotnetup-default-public-feed',architecture=args.arch,version=status['version'],catalogSequence=status['catalogSequence'],catalogUrl='https://dotnetdev.kr/cbodotnet/cbodotnetup/v2/catalog.json',legacyCatalogSha256=status['legacyCatalogSha256'],pairedHostedFeeds='passed')
    save(workspace/'report.json',result)


def catalog(output, builds, *, now=None, sequence=None):
    policy = load(POLICY); now = now or datetime.now(timezone.utc)
    source = source_identity(); sequence = sequence or int(source['runId'])
    require(set(builds) == {'x64', 'aarch64'}, 'Both native builds are mandatory')
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
    sdks = catalog_sdks(policy, schema=2)
    legacy_policy = dict(policy, archiveRevisions=policy['legacyArchiveRevisions'])
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
    value=dict(schemaVersion=2,**common,sdks=sdks,
        channels={'.'.join(s['sdkVersion'].split('.')[:2]):s['sdkVersion']+'-r'+str(s['revision']) for s in sdks})
    legacy=dict(schemaVersion=1,**common,sdks=legacy_sdks,
        channels={'.'.join(s['sdkVersion'].split('.')[:2]):s['sdkVersion']+'-r'+str(s['revision']) for s in legacy_sdks})
    old_tools=[t for t in tools if t['version']=='0.1.0' and 'tool/'+t['version']+'/'+t['rid'] not in revoked]
    require({t['rid'] for t in old_tools}=={'linux-x64','linux-arm64'} and len(old_tools)==2 and sequence>2,
            'Actual 0.1.0 binaries for both CPUs must remain authenticated for migration qualification')
    bootstrap=dict(legacy,sequence=sequence-1,tools=old_tools)
    expired=dict(bootstrap,sequence=sequence-2,
        issuedAt=(now-timedelta(days=32)).isoformat().replace('+00:00','Z'),
        expiresAt=(now-timedelta(days=2)).isoformat().replace('+00:00','Z'))
    save(output/'catalog.json',value);save(output/'catalog-v1.json',legacy)
    save(output/'catalog-v1-bootstrap.json',bootstrap);save(output/'catalog-v1-expired.json',expired)
    verify_catalog_pair(output)
    return value


def catalog_sdks(policy, *, schema):
    """Schema is also the closed archive naming contract; old feeds gain no new fields."""
    require(schema in (1,2),'Unsupported installation catalog schema')
    sdks = []; contract = load_contract()
    for version in policy['initialSdkVersions']:
        receipt, manifest = selected_archive(version, policy=policy)
        canonical = get_bytes('https://github.com/dotnetdev-kr/cbodotnet/releases/download/sdk-' + version + '/release-manifest.json', 8 * 1024**2)
        require(hashlib.sha256(canonical).hexdigest() == contract['releases'][version]['manifestSha256'], 'Canonical source pin differs')
        for record in manifest['records']:
            plan = record['build']['plan']; arch = record['architecture']; rid = plan['targetRid']
            require(plan['sourceManifestSha256'] == contract['releases'][version]['manifestSha256'] and not plan['compatibility']['required'], 'Legacy or unreviewed initial SDK admission')
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
                dependencies=sorted({name for variant in policy['targets'] for name in contract['operatingSystems'][variant]['dependencies']}),
                targets=[dict(os=contract['operatingSystems'][v]['id'],versionId=contract['operatingSystems'][v]['versionId'],rid=rid) for v in policy['targets']], requiresLegacyProvider=False))
    return sdks


def verify_catalog_pair(bundle):
    """A migration/renewal candidate may never strand the old client's feed."""
    current=load(Path(bundle)/'catalog.json')
    if current['schemaVersion']==1:return current,None  # Previously published immutable bundles.
    require(current['schemaVersion']==2,'Unsupported candidate catalog schema')
    legacy=load(Path(bundle)/'catalog-v1.json')
    fields={'schemaVersion','kind','sequence','issuedAt','expiresAt','signingFingerprint','revoked','sdks','tools','channels'}
    require(set(current)==set(legacy)==fields and legacy['schemaVersion']==1,'Legacy catalog shape is not v1 compatible')
    shared=fields-{'schemaVersion','sdks','channels'}
    require(all(current[k]==legacy[k] for k in shared),'Paired catalog trust, sequence, lifetime or tools differ')
    require(current['sdks'] and legacy['sdks'],'Both catalog generations need admitted SDKs')
    for value,suffix in ((current,''),(legacy,'-branded')):
        for sdk in value['sdks']:
            arch={'linux-x64':'x64','linux-arm64':'aarch64'}.get(sdk['rid'])
            require(arch is not None,'Unsupported catalog libc/RID')
            version=sdk['sdkVersion'];revision=sdk['revision']
            expected=f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-{version}-r{revision}/cbodotnet-sdk-{version}-linux-{arch}{suffix}-r{revision}.tar.gz'
            require(sdk['archive']['url']==expected,'Cross-generation SDK archive identity')
    bootstrap=load(Path(bundle)/'catalog-v1-bootstrap.json')
    expected=dict(legacy,sequence=current['sequence']-1,tools=[t for t in legacy['tools'] if t['version']=='0.1.0' and 'tool/'+t['version']+'/'+t['rid'] not in legacy['revoked']])
    require(bootstrap==expected and len(bootstrap['tools'])==2 and {t['rid'] for t in bootstrap['tools']}=={'linux-x64','linux-arm64'},
            'Legacy bootstrap fixture is not bound to the paired signed migration feeds')
    issued=datetime.fromisoformat(current['issuedAt'].replace('Z','+00:00'))
    expired=dict(bootstrap,sequence=current['sequence']-2,
        issuedAt=(issued-timedelta(days=32)).isoformat().replace('+00:00','Z'),
        expiresAt=(issued-timedelta(days=2)).isoformat().replace('+00:00','Z'))
    require(load(Path(bundle)/'catalog-v1-expired.json')==expired,'Expired legacy test fixture differs from the signed migration candidate')
    return current,legacy


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
        value=load(directory/'native-package-inputs.json')
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
        current,legacy=verify_catalog_pair(bundle)
        names=('freeze.json','catalog.json')+ (('catalog-v1.json','catalog-v1-bootstrap.json','catalog-v1-expired.json') if legacy else ())
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
        report=load(path);arch=report['architecture'];require(arch in ('x64','aarch64') and arch not in builds,'Ambiguous native installer build')
        source=report['source'];run_record=api.api(f'repos/dotnetdev-kr/cbodotnet/actions/runs/{source["runId"]}/attempts/{source["runAttempt"]}')
        require(run_record and run_record['head_sha']==source['commit'] and run_record['path']==WORKFLOW
                and run_record['head_branch']=='main' and run_record['event']=='workflow_dispatch'
                and run_record['repository']['full_name']=='dotnetdev-kr/cbodotnet' and run_record['head_repository']['full_name']=='dotnetdev-kr/cbodotnet', 'Native build source is not approved main')
        jobs=api.api(f'repos/dotnetdev-kr/cbodotnet/actions/runs/{source["runId"]}/attempts/{source["runAttempt"]}/jobs?per_page=100')['jobs']
        native=[j for j in jobs if j['name']=='Build SDK-free cbodotnetup on native '+arch]
        require(len(native)==1 and native[0]['status']=='completed' and native[0]['conclusion']=='success','Native build did not actually succeed')
        destination=output/'tools'/report['rid'];shutil.copytree(path.parent,destination);builds[arch]=destination
    catalog(output,builds)
    audit_native_packages(builds,output/'native-package-audit.json')
    shutil.copyfile(ROOT/'scripts/get-cbodotnetup.py',output/'get-cbodotnetup.py')
    fetch_asset(LEGACY_BOOTSTRAP,output/'get-cbodotnetup-v0.1.0.py')
    MULTI.preflight(output/'preflight',receive=True)
    for name in ('catalog.json','catalog-v1.json','catalog-v1-bootstrap.json','catalog-v1-expired.json'):sign(output/name)
    freeze=dict(schemaVersion=1,kind='cbodotnetup-frozen-candidate',source=source_identity(),version=load(POLICY)['version'],
        legacyBootstrap=LEGACY_BOOTSTRAP,
        files=[descriptor(p)|dict(path=p.relative_to(output).as_posix()) for p in sorted(output.rglob('*')) if p.is_file()])
    save(output/'freeze.json',freeze);sign(output/'freeze.json');verify_bundle(output)
    print(json.dumps(dict(status='signed-frozen-unpublished',version=freeze['version'],catalog=descriptor(output/'catalog.json'))))


def user_command(arguments):
    return ['runuser','-u',MULTI.USER,'--','env','-i','PATH=/usr/local/bin:/usr/bin:/bin',
             'HOME=/home/'+MULTI.USER,'DOTNET_CLI_HOME=/home/'+MULTI.USER,'DOTNET_CLI_TELEMETRY_OPTOUT=1',
             'DOTNET_NOLOGO=1','DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1','DOTNET_CLI_UI_LANGUAGE=en',*map(str,arguments)]


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
        child=subprocess.Popen(user_command([*manager,'install',exact]),stdout=output,stderr=subprocess.STDOUT,
                               cwd=home,start_new_session=True)
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
        legacyExact=old_exact,migration=migration,
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


def native(args):
    verify_bundle(args.bundle)
    require(platform.machine() in ({'x86_64'} if args.arch=='x64' else {'aarch64','arm64'}),'Native CPU required')
    workspace=args.workspace.resolve();require(not workspace.exists(),'Fresh native workspace required');workspace.mkdir(parents=True)
    mounts=['-v',f'{ROOT}:/repo:ro','-v',f'{args.bundle.resolve()}:/bundle:ro','-v',f'{workspace}:/delivery']
    mounts += [part for name in ('GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT') for part in ('-e',name)]
    common=['--bundle','/bundle','--variant',args.variant,'--arch',args.arch,'--workspace','/delivery/installed']
    if args.public:common+=['--public']
    command=['python3','/repo/scripts/cbodotnetup-release.py'];cid=image=None
    try:
        script=MULTI.bootstrap_script(args.variant)+'exec '+shlex.join(command+['native-install',*common])
        cid=subprocess.check_output(['docker','create','--user','0',*mounts,QUALIFICATION_BASES[args.variant][args.arch],'sh','-ec',script],text=True).strip()
        run(['docker','start','--attach',cid]);info=json.loads(subprocess.check_output(['docker','inspect',cid],text=True))[0]
        require(info['State']['ExitCode']==0,'Native installer/bootstrap failed')
        image=subprocess.check_output(['docker','commit',cid],text=True).strip()
        run(['docker','run','--rm','--network','none','--user','0',*mounts,image,*command,'native-smoke',*common])
        shutil.copyfile(workspace/'installed/report.json',workspace/'report.json')
    finally:
        if cid:subprocess.run(['docker','rm','--force',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if image:subprocess.run(['docker','image','rm',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def qualified_reports(bundle,directory,*,public=False):
    freeze=verify_bundle(bundle);api=GitHubReleases();reports={};proof=[]
    for path in Path(directory).rglob('report.json'):
        value=load(path);target=(value['variant'],value['architecture'])
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
    for arch,rid in (('x64','linux-x64'),('aarch64','linux-arm64')):
        directory=args.bundle/'tools'/rid;build_report=load(directory/'build.json')
        if source is None:source=build_report['source']['commit']
        require(build_report['source']['commit']==source,'Both tool binaries must have one exact source commit')
        for name in ('cbodotnetup-'+rid,'cbodotnetup-'+rid+'.LICENSE.txt'):shutil.copyfile(directory/name,tools/name)
        shutil.copyfile(directory/'build.json',tools/('build-'+arch+'.json'))
    shutil.copyfile(ROOT/'LICENSE',tools/'LICENSE')
    run(['git','archive','--format=tar.gz','--output',tools/'cbodotnetup-source.tar.gz',source,'tools','LICENSE','releases/cbodotnetup-policy.json','releases/downstream-signing-key.asc','scripts/get-cbodotnetup.py'])
    tool_release=upload_release('cbodotnetup-v'+version,source,sorted(tools.iterdir()),'cbodotnetup '+version+' - verified Community Build SDK manager',
        'SDK-free NativeAOT installer for qualified Community Build of .NET SDKs. Verify the current project-signed installation catalog and its independently pinned OpenPGP key. '
        'Linux glibc x64/AArch64; Ubuntu24.04, Debian13, Fedora45 and Rocky9.8. Initial SDK:10.0.403. '
        'Native runtime 10.0.14; the SDK payload stays unchanged. Per-user roots preserve official and package-managed commands. '
        'Each binary has exact signed native runtime/project license and third-party notices in its adjacent .LICENSE.txt asset. '
        'Version 0.2 uses the versioned schema2 catalog for neutral SDK archive names; the schema1 feed keeps 0.1 clients able to self-update. '
        'Build/source records are retained; current signed catalog qualification is published separately. This release does not replace the latest SDK download.')
    catalog_assets=output/'catalog-assets';catalog_assets.mkdir()
    for name in (*CATALOG_ASSETS,'freeze.json','freeze.json.asc','get-cbodotnetup.py'):shutil.copyfile(args.bundle/name,catalog_assets/name)
    pack(args.bundle,catalog_assets/'cbodotnetup-verification-inputs.tar.gz')
    save(catalog_assets/'native-qualification.json',dict(status='passed',targets=proof))
    catalog_value=load(args.bundle/'catalog.json')
    release=upload_release('cbodotnetup-catalog-'+str(catalog_value['sequence']),freeze['source']['commit'],sorted(catalog_assets.iterdir()),
        'cbodotnetup signed installation catalog '+str(catalog_value['sequence']),
        'Project-signed installation catalog with bounded freshness, revocation, source/producer pins and immutable SDK/tool hashes. '
        'All eight native OS/CPU qualification targets passed before this publication. Public bootstrap/native post-verification is recorded before feed activation. '
        'catalog.json is the schema2 feed; catalog-v1.json is the compatible schema1 feed. '
        'catalog-v1-bootstrap.json and catalog-v1-expired.json are test-only migration qualification fixtures, not installation feeds. '
        'AUR publication remains deferred under issue10.')
    save(output/'publication.json',dict(schemaVersion=1,kind='cbodotnetup-publication',status='published-public-bytes-verified',
        version=version,source=freeze['source'],toolRelease=tool_release,catalogRelease=release,nativeQualification=proof,
        catalogSequence=catalog_value['sequence'],catalogSha256=descriptor(args.bundle/'catalog.json')['sha256'],
        legacyCatalogSequence=load(args.bundle/'catalog-v1.json')['sequence'],legacyCatalogSha256=descriptor(args.bundle/'catalog-v1.json')['sha256']))


def receive_public(args):
    publication=load(args.publication);assets={a['name']:a for a in publication['catalogRelease']['assets']}
    require(publication['status']=='published-public-bytes-verified','Exact public installer publication required')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    archive=args.output.parent/'public-installer-inputs.tar.gz';fetch_asset(assets['cbodotnetup-verification-inputs.tar.gz'],archive)
    sdk_tools().extract_sdk(archive,args.output);verify_bundle(args.output)
    for name in (*CATALOG_ASSETS,'get-cbodotnetup.py'):
        raw=get_bytes(assets[name]['url'],assets[name]['size'])
        require(hashlib.sha256(raw).hexdigest()==assets[name]['sha256'] and raw==(args.output/name).read_bytes(),'Public consumer metadata differs from the frozen signed candidate')


def receive_published_builds(args):
    status=load(ROOT/'releases/cbodotnetup-status.json');require(status['status']=='published-postverified','No qualified installer exists to renew')
    require(not args.output.exists(),'Fresh published build input directory required');args.output.mkdir(parents=True)
    assets={a['name']:a for a in status['catalogRelease']['assets']}
    archive=args.output/'prior-inputs.tar.gz';fetch_asset(assets['cbodotnetup-verification-inputs.tar.gz'],archive)
    extracted=args.output/'prior';sdk_tools().extract_sdk(archive,extracted);verify_bundle(extracted)
    for arch,rid in (('x64','linux-x64'),('aarch64','linux-arm64')):shutil.copytree(extracted/'tools'/rid,args.output/('native-'+arch))
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
    command=commands.add_parser('build'); command.add_argument('--arch',choices=('x64','aarch64'),required=True); command.add_argument('--workspace',type=Path,required=True)
    for name in ('source-check','feed-smoke'):
        command=commands.add_parser(name);command.add_argument('--arch',choices=('x64','aarch64'),required=True);command.add_argument('--workspace',type=Path,required=True)
    command=commands.add_parser('stage');command.add_argument('--received',type=Path,required=True);command.add_argument('--output',type=Path,required=True)
    for name in ('native','native-install','native-smoke'):
        command=commands.add_parser(name);command.add_argument('--bundle',type=Path,required=True);command.add_argument('--workspace',type=Path,required=True)
        command.add_argument('--arch',choices=('x64','aarch64'),required=True);command.add_argument('--variant',choices=tuple(MULTI.TARGETS),required=True)
        command.add_argument('--public',action='store_true')
    for name in ('publish','activate'):
        command=commands.add_parser(name);command.add_argument('--bundle',type=Path,required=True);command.add_argument('--reports',type=Path,required=True);command.add_argument('--output',type=Path,required=True)
        if name=='activate':command.add_argument('--publication',type=Path,required=True)
    command=commands.add_parser('receive-public');command.add_argument('--publication',type=Path,required=True);command.add_argument('--output',type=Path,required=True)
    command=commands.add_parser('receive-published-builds');command.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    {'build':build,'source-check':source_check,'feed-smoke':feed_smoke,'stage':stage,'native':native,'native-install':native_install,'native-smoke':native_smoke,
     'publish':publish,'receive-public':receive_public,'receive-published-builds':receive_published_builds,'activate':activate}[args.command](args)


if __name__=='__main__':main()
