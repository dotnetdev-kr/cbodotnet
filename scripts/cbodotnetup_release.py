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
import shutil
import subprocess
import tempfile
import urllib.request

from consumer_archive import sdk_tools
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


def sign(path):
    run(['gpg','--batch','--yes','--local-user',load(POLICY)['signingFingerprint'],'--armor','--detach-sign',path])


def verify_bundle(bundle):
    bundle=Path(bundle).resolve();manifest=load(bundle/'freeze.json')
    require(manifest['schemaVersion']==1 and manifest['kind']=='cbodotnetup-frozen-candidate'
            and manifest['source']['repository']=='dotnetdev-kr/cbodotnet' and manifest['source']['workflow']==WORKFLOW,
            'Untrusted frozen installer provenance')
    with tempfile.TemporaryDirectory(prefix='cbodotnetup-public-key-') as temporary:
        key=Path(temporary)/'trusted.gpg'
        run(['gpg','--batch','--yes','--dearmor','--output',key,ROOT/'releases/downstream-signing-key.asc'],capture_output=True)
        for name in ('freeze.json','catalog.json'):
            verify_report_signature(bundle/name,bundle/(name+'.asc'),key,load_status(),WORKFLOW)
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
    shutil.copyfile(ROOT/'scripts/get-cbodotnetup.py',output/'get-cbodotnetup.py')
    MULTI.preflight(output/'preflight',receive=True)
    sign(output/'catalog.json')
    freeze=dict(schemaVersion=1,kind='cbodotnetup-frozen-candidate',source=source_identity(),version=load(POLICY)['version'],
        files=[descriptor(p)|dict(path=p.relative_to(output).as_posix()) for p in sorted(output.rglob('*')) if p.is_file()])
    save(output/'freeze.json',freeze);sign(output/'freeze.json');verify_bundle(output)
    print(json.dumps(dict(status='signed-frozen-unpublished',version=freeze['version'],catalog=descriptor(output/'catalog.json'))))


def user(arguments,*,check=True):
    command=['runuser','-u',MULTI.USER,'--','env','-i','PATH=/usr/local/bin:/usr/bin:/bin',
             'HOME=/home/'+MULTI.USER,'DOTNET_CLI_HOME=/home/'+MULTI.USER,'DOTNET_CLI_TELEMETRY_OPTOUT=1',
             'DOTNET_NOLOGO=1','DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1','DOTNET_CLI_UI_LANGUAGE=en',*map(str,arguments)]
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
    bootstrap=['python3',bundle/'get-cbodotnetup.py','--catalog-file',bundle/'catalog.json','--binary-file',bundle/'tools'/rid/('cbodotnetup-'+rid)]
    user(bootstrap);require(user([binary,'--version']).stdout.strip()==load(POLICY)['version'],'SDK-free bootstrap binary failed')
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
    user([binary,'install','--channel','10.0']);user([binary,'install',exact]);user([binary,'update']);user([binary,'rollback',exact])
    require(user([binary,'list']).stdout.strip()==exact+'/'+rid,'Installed list identity differs')
    user([binary,'shell','enable']);user([binary,'self','update'])
    save(state/'installed.json',dict(sdk=sdk,exact=exact,rid=rid,officialBaseline=official,packages=packages,packageInventory=package_inventory,
        catalogSha256=descriptor(bundle/'catalog.json')['sha256'],freezeSha256=descriptor(bundle/'freeze.json')['sha256'],
        bootstrapSha256=descriptor(bundle/'get-cbodotnetup.py')['sha256'],binarySha256=descriptor(binary)['sha256']))


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
    payload=root/'toolchains'/exact/state['rid']/'content'/sdk['archiveRoot']/'payload'
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
    abandoned=root/'staging'/'0123456789abcdef0123456789abcdef';abandoned.mkdir();(abandoned/'owner').write_text('cbodotnetup-v1');(abandoned/'partial').write_bytes(b'incomplete')
    user([binary,'gc']);require(not abandoned.exists(),'Abandoned owned stage was not collected')
    require(user([binary,'run',exact,'--','--version']).stdout==version+'\n','Interrupted activation affected an active SDK')
    user([binary,'remove',exact]);require(user([binary,'list']).stdout=='','Removed SDK still advertised')
    absent=user([root/'bin/cbodotnet','--version'],check=False);require(absent.returncode!=0 and not absent.stdout,'Empty user selector fell back to an official/package SDK')
    user([binary,'shell','disable'])
    require(MULTI.APT.inventory(Path('/opt/cbodotnet'))==state['packageInventory'],'User installer changed package-managed Community SDK inventory')
    MULTI.integrity(state['packages'],MULTI.TARGETS[args.variant]);official=assert_unchanged(args.workspace/'official.json')
    require((home/'.local/share/dotnetup/owner-test').read_text()=='untouched','Official installer state was changed')
    save(args.workspace/'report.json',dict(schemaVersion=1,scope='cbodotnetup-native-installation',status='passed',variant=args.variant,architecture=args.arch,
        catalogSha256=state['catalogSha256'],freezeSha256=state['freezeSha256'],bootstrapSha256=state['bootstrapSha256'],binarySha256=state['binarySha256'],
        networkForBuild='none',userId=10001,checks=dict.fromkeys(CHECKS,'passed'),functionalChecks=functional,aliases=observations,
        officialBaseline=state['officialBaseline'],officialAfterRemoval=official,packageManagedCommunityIntegrity='unchanged',
        rollbackScope='retained exact admitted SDK revision selection; additional revisions need their own admission'))


def native(args):
    verify_bundle(args.bundle)
    require(platform.machine() in ({'x86_64'} if args.arch=='x64' else {'aarch64','arm64'}),'Native CPU required')
    workspace=args.workspace.resolve();require(not workspace.exists(),'Fresh native workspace required');workspace.mkdir(parents=True)
    mounts=['-v',f'{ROOT}:/repo:ro','-v',f'{args.bundle.resolve()}:/bundle:ro','-v',f'{workspace}:/delivery']
    common=['--bundle','/bundle','--variant',args.variant,'--arch',args.arch,'--workspace','/delivery/installed']
    command=['python3','/repo/scripts/cbodotnetup-release.py'];cid=image=None
    try:
        script=MULTI.bootstrap_script(args.variant)+'exec '+shlex.join(command+['native-install',*common])
        cid=subprocess.check_output(['docker','create','--user','0',*mounts,MULTI.BASES[args.variant][args.arch],'sh','-ec',script],text=True).strip()
        run(['docker','start','--attach',cid]);info=json.loads(subprocess.check_output(['docker','inspect',cid],text=True))[0]
        require(info['State']['ExitCode']==0,'Native installer/bootstrap failed')
        image=subprocess.check_output(['docker','commit',cid],text=True).strip()
        run(['docker','run','--rm','--network','none','--user','0',*mounts,image,*command,'native-smoke',*common])
        shutil.copyfile(workspace/'installed/report.json',workspace/'report.json')
    finally:
        if cid:subprocess.run(['docker','rm','--force',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if image:subprocess.run(['docker','image','rm',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def main():
    parser=argparse.ArgumentParser(description=__doc__); commands=parser.add_subparsers(dest='command',required=True)
    command=commands.add_parser('build'); command.add_argument('--arch',choices=('x64','aarch64'),required=True); command.add_argument('--workspace',type=Path,required=True)
    command=commands.add_parser('stage');command.add_argument('--received',type=Path,required=True);command.add_argument('--output',type=Path,required=True)
    for name in ('native','native-install','native-smoke'):
        command=commands.add_parser(name);command.add_argument('--bundle',type=Path,required=True);command.add_argument('--workspace',type=Path,required=True)
        command.add_argument('--arch',choices=('x64','aarch64'),required=True);command.add_argument('--variant',choices=tuple(MULTI.TARGETS),required=True)
    args=parser.parse_args()
    {'build':build,'stage':stage,'native':native,'native-install':native_install,'native-smoke':native_smoke}[args.command](args)


if __name__=='__main__':main()
