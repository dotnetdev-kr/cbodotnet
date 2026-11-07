"""Native candidates and guarded publication of the separately qualified musl SDK."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import urllib.error

import musl_archive as ARCHIVE
import musl_contract as CONTRACT
from downstream_release import descriptor, encoded, ordinary_file, require
from downstream_publish import GitHubReleases
from musl_release import WORKFLOW, verify_release_tag
from release_catalog import get_bytes, release_assets, validate_api_asset

ROOT = CONTRACT.ROOT


class AnonymousGitHubAPI:
    """Read public source/tag metadata without requiring or sending credentials."""
    def api(self, endpoint):
        require(isinstance(endpoint, str) and endpoint.startswith('repos/'+CONTRACT.REPOSITORY+'/')
                and not any(part in {'..','.'} for part in endpoint.split('/')),
                'An exact public project API endpoint is required')
        try:
            return json.loads(get_bytes('https://api.github.com/'+endpoint, 16*1024**2, api=True))
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise


def fresh(path):
    return ARCHIVE.fresh_directory(path)


def orchestration():
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('GITHUB_REPOSITORY') == CONTRACT.REPOSITORY
            and os.environ.get('GITHUB_REF') == 'refs/heads/main'
            and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and os.environ.get('GITHUB_WORKFLOW_REF') == CONTRACT.REPOSITORY+'/'+WORKFLOW+'@refs/heads/main'
            and os.environ.get('GITHUB_WORKFLOW_SHA') == os.environ.get('GITHUB_SHA'),
            'Native musl delivery must originate in the reviewed main-branch workflow')
    result = dict(repository=CONTRACT.REPOSITORY, workflow=WORKFLOW, commit=os.environ.get('GITHUB_SHA',''),
        runId=os.environ.get('GITHUB_RUN_ID',''), runAttempt=os.environ.get('GITHUB_RUN_ATTEMPT',''))
    require(re.fullmatch(r'[a-f0-9]{40}',result['commit'])
            and all(re.fullmatch(r'[1-9][0-9]*',result[name]) for name in ('runId','runAttempt')),
            'Exact musl delivery orchestration identity is required')
    return result


def download_asset(url, path, expected):
    """Public artifact requests never contain a GitHub authorization header."""
    require(isinstance(url,str) and url.startswith(f'https://github.com/{CONTRACT.REPOSITORY}/releases/download/'),
            'A canonical public musl release asset URL is required')
    path = Path(path)
    count = 0; digest = hashlib.sha256()
    with urllib.request.urlopen(url,timeout=120) as incoming, path.open('xb') as stream:
        for block in iter(lambda:incoming.read(4*1024**2), b''):
            count += len(block)
            require(count <= expected['size'], 'Public musl artifact exceeds its authenticated size')
            digest.update(block); stream.write(block)
    require(count == expected['size'] and digest.hexdigest() == expected['sha256'],
            'Public musl artifact differs from authenticated bytes')
    return descriptor(path)


def receive_source(architecture, output, *, anonymous=False):
    require(architecture in CONTRACT.ARCHITECTURES, 'An exact public musl CPU is required')
    catalog = CONTRACT.load_qualification_catalog()
    matches = [row for row in catalog['builds'] if row['sdkVersion']=='10.0.403' and row['producerRevision']==1]
    require(len(matches)==1, 'The initial two-CPU musl producer is not independently qualified')
    row = matches[0]; tag = row['sourceReleaseTag']
    api = AnonymousGitHubAPI() if anonymous else GitHubReleases()
    release = api.api(f'repos/{CONTRACT.REPOSITORY}/releases/tags/{tag}')
    base = f'https://github.com/{CONTRACT.REPOSITORY}/releases/download/{tag}/'
    manifest = get_bytes(base+'release-manifest.json',CONTRACT.MAX_MANIFEST_BYTES)
    checksums = get_bytes(base+'SHA256SUMS',CONTRACT.MAX_CHECKSUM_BYTES)
    source = CONTRACT.validate_producer_release(release,manifest,checksums)
    CONTRACT.require_qualified_producer(manifest,catalog=catalog)
    output = fresh(output)
    for name, raw in [('release.json',encoded(release)),('release-manifest.json',manifest),('SHA256SUMS',checksums)]:
        (output/name).write_bytes(raw)
    sdk = source['architectures'][architecture]['sdk']
    download_asset(base+sdk['name'],output/sdk['name'],sdk)
    return output


def intake_plan(inputs, architecture, channel, revision):
    inputs=Path(inputs)
    release=json.loads(ordinary_file(inputs/'release.json').read_bytes())
    manifest=ordinary_file(inputs/'release-manifest.json').read_bytes()
    sums=ordinary_file(inputs/'SHA256SUMS').read_bytes()
    source=CONTRACT.validate_producer_release(release,manifest,sums)
    sdk=inputs/source['architectures'][architecture]['sdk']['name']
    return CONTRACT.verified_plan(release,manifest,sums,sdk,channel,'alpine-3.24',architecture,revision),sdk


def assemble_apk(inputs, architecture, revision, output):
    """Assemble actual admitted SDKs with a short-lived build-only RSA key."""
    import musl_packages as APK
    require(os.geteuid()!=0,'Native APK assembly must run unprivileged')
    output=fresh(output)
    with tempfile.TemporaryDirectory(prefix='musl-ephemeral-build-key-') as temporary:
        key=Path(temporary)/'build.rsa'
        public=Path(temporary)/'build.rsa.pub'
        subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:4096','-out',str(key)],
                       check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        key.chmod(0o600)
        subprocess.run(['openssl','pkey','-in',str(key),'-pubout','-out',str(public)],check=True)
        shutil.copyfile(public,output/public.name)
        for label, selected in [('build',revision),('upgrade',revision+1)]:
            plan,sdk=intake_plan(inputs,architecture,'apk',selected)
            built=APK.build_apk(plan,sdk,output/label,key,public)
            built['credentialPurpose']='ephemeral-build-candidate'
            (output/label/'package-build.json').write_bytes(encoded(built))
    return dict(status='assembled-unpublished',architecture=architecture,privateBuildKeyRemoved=True)


def _docker_architecture(architecture):
    require(os.uname().sysname=='Linux' and os.uname().machine==('x86_64' if architecture=='x64' else 'aarch64'),
            'A matching native Linux APK/OCI host is required')
    observed=ARCHIVE.run(['docker','info','--format','{{.Architecture}}']).strip()
    require(observed in ({'x86_64','amd64'} if architecture=='x64' else {'aarch64','arm64'}),
            'A Docker server on the same native CPU is required')


def _export_apk_candidate(assembly, report, lifecycle, origin, output):
    """Export only public metadata and signed packages; build keys/configs stay out."""
    output=fresh(output)
    envelope=fresh(output/'delivery')
    for label in ('build','upgrade'):
        source=assembly/label
        destination=fresh(envelope/label)
        for name in ('package-build.json','plan.json','payload-inventory.json','command-inventory.json'):
            shutil.copyfile(ordinary_file(source/name),destination/name)
        repository=fresh(destination/'repository')
        build=json.loads((source/'package-build.json').read_bytes())
        for name in ['APKINDEX.tar.gz',*[row['path'] for row in build['packages']]]:
            require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,220}',name),'Unsafe APK candidate asset name')
            shutil.copyfile(ordinary_file(source/'repository'/name),repository/name)
        for kind in ('sdk','host'):
            recipes=destination/'aports/cbodotnet'/kind
            recipes.mkdir(parents=True)
            for name in ('APKBUILD','payload.tar.gz'):
                shutil.copyfile(ordinary_file(source/'aports/cbodotnet'/kind/name),recipes/name)
    shutil.copyfile(ordinary_file(assembly/'build.rsa.pub'),envelope/'build.rsa.pub')
    (envelope/'qualification-report.json').write_bytes(encoded(report))
    (envelope/'lifecycle-report.json').write_bytes(encoded(lifecycle))
    (envelope/'orchestration.json').write_bytes(encoded(origin))
    with tarfile.open(output/'candidate.tar.gz','w:gz',compresslevel=1) as archive:
        for path in sorted(envelope.rglob('*')):
            require(not path.is_symlink(),'APK candidate envelope may contain no links')
            if path.is_file(): archive.add(path,arcname='delivery/'+path.relative_to(envelope).as_posix(),recursive=False)
    (output/'candidate.json').write_bytes(encoded(dict(schemaVersion=1,kind='musl-apk-native-candidate-transport',
        orchestration=origin,artifact=descriptor(output/'candidate.tar.gz'))))
    return output


def apk_candidate(architecture, revision, workspace, output):
    import musl_package_native as NATIVE
    origin=orchestration(); _docker_architecture(architecture)
    workspace=fresh(workspace)
    inputs=receive_source(architecture,workspace/'inputs')
    work=fresh(workspace/'assembly-parent'); work.chmod(0o777)
    containerfile=workspace/'APK.Containerfile'
    containerfile.write_text('FROM '+ARCHIVE.BASES[architecture]+'\nRUN apk add --no-cache '
        'apk-tools=3.0.9-r0 abuild=3.17.0-r0 "!abuild-sudo" python3=3.14.10-r1 openssl=3.5.9-r0 '
        '&& addgroup -g 10001 builder && adduser -D -u 10001 -G builder builder\n',encoding='utf-8')
    context=fresh(workspace/'empty-context')
    image='cbodotnet-musl-apk-build:'+architecture+'-'+origin['runId']+'-'+origin['runAttempt']
    ARCHIVE.run(['docker','build','--pull=false','-f',containerfile,'-t',image,context])
    ARCHIVE.run(['docker','run','--rm','--network=none','--user','10001:10001','--cap-drop=ALL','--security-opt=no-new-privileges',
        '-v',str(ROOT)+':/project:ro','-v',str(inputs)+':/inputs:ro','-v',str(work)+':/assembly',
        '-e','HOME=/tmp','-e','PYTHONDONTWRITEBYTECODE=1','-w','/project',image,
        'python3','scripts/musl_distribution.py','assemble-apk','--inputs','/inputs','--arch',architecture,
        '--revision',str(revision),'--output','/assembly/native'])
    assembly=work/'native'; public=assembly/'build.rsa.pub'
    report=NATIVE.native_apk(assembly/'build',architecture,workspace/'runtime',public)
    report['orchestration']=origin
    lifecycle_dir=fresh(workspace/'lifecycle'); lifecycle_dir.chmod(0o777)
    lifecycle_file=workspace/'Lifecycle.Containerfile'
    lifecycle_file.write_text('FROM '+ARCHIVE.BASES[architecture]+'\nRUN apk add --no-cache '
        +' '.join(name+'='+version for name,version in ARCHIVE.RUNTIME_PACKAGES.items())
        +' python3=3.14.10-r1 binutils=2.45.1-r1 dotnet10-sdk=10.0.303-r2 '
        '&& addgroup -g 10001 cbot-musl && adduser -D -u 10001 -G cbot-musl cbot-musl\n',encoding='utf-8')
    lifecycle_image=image+'-lifecycle'
    ARCHIVE.run(['docker','build','--pull=false','-f',lifecycle_file,'-t',lifecycle_image,context])
    ARCHIVE.run(['docker','run','--rm','--network=none','-v',str(ROOT)+':/project:ro','-v',str(assembly)+':/candidate:ro',
        '-v',str(lifecycle_dir)+':/proof','-e','PYTHONDONTWRITEBYTECODE=1','-w','/project',lifecycle_image,
        'python3','scripts/musl_package_native.py','lifecycle-apk','--build','/candidate/build',
        '--upgrade-build','/candidate/upgrade','--arch',architecture,'--public-key','/candidate/build.rsa.pub',
        '--output','/proof/lifecycle-report.json'])
    lifecycle=json.loads(ordinary_file(lifecycle_dir/'lifecycle-report.json').read_bytes())
    lifecycle['orchestration']=origin
    _export_apk_candidate(assembly,report,lifecycle,origin,output)
    return dict(status='validated-unpublished',architecture=architecture)


def archive_candidate(architecture, revision, workspace, output):
    origin = orchestration()
    workspace = fresh(workspace)
    inputs = receive_source(architecture,workspace/'inputs')
    build_directory = workspace/'build'
    build = ARCHIVE.build_archive(inputs,architecture,revision,build_directory)
    report = ARCHIVE.native(build_directory,architecture,workspace/'qualification')
    report['orchestration'] = origin
    output = fresh(output)
    for source, name in [(build_directory/build['artifact']['name'],build['artifact']['name']),
                         (build_directory/'package-build.json','package-build.json')]:
        shutil.copyfile(source,output/name)
        require(descriptor(output/name)['sha256']==descriptor(source)['sha256'],'Musl candidate copy changed bytes')
    (output/'qualification-report.json').write_bytes(encoded(report))
    return dict(status='validated-unpublished',architecture=architecture,sourceManifestSha256=build['plan']['sourceManifestSha256'])


def public_archive(architecture, revision, workspace, output):
    """Fetch actual public signed bytes anonymously and repeat native execution."""
    import musl_promotion as PROMOTION
    origin = orchestration()
    require(architecture in CONTRACT.ARCHITECTURES, 'An exact native public archive CPU is required')
    CONTRACT.version_revision('10.0.403',revision)
    workspace = fresh(workspace)
    bundle = fresh(workspace/'public-bundle')
    tag = CONTRACT.distribution_tag('archive','10.0.403',revision)
    base = f'https://github.com/{CONTRACT.REPOSITORY}/releases/download/{tag}/'
    release = json.loads(get_bytes(f'https://api.github.com/repos/{CONTRACT.REPOSITORY}/releases/tags/{tag}',8*1024**2,api=True))
    require(release.get('tag_name')==tag and release.get('draft') is False and release.get('prerelease') is False,
            'A public stable musl archive release is required')
    remote = release_assets(release)
    manifest_raw = get_bytes(base+PROMOTION.MANIFEST,16*1024**2)
    signature_raw = get_bytes(base+PROMOTION.SIGNATURE,1024**2)
    for name,raw in [(PROMOTION.MANIFEST,manifest_raw),(PROMOTION.SIGNATURE,signature_raw)]:
        validate_api_asset(remote.get(name),name,CONTRACT.REPOSITORY,tag,content=raw)
        (bundle/name).write_bytes(raw)
    keyring = workspace/'trusted.gpg'
    subprocess.run(['gpg','--batch','--dearmor','--output',str(keyring),str(ROOT/'releases/downstream-signing-key.asc')],check=True)
    from musl_release import verify_publication_signature
    fingerprint = verify_publication_signature(bundle/PROMOTION.MANIFEST,bundle/PROMOTION.SIGNATURE,keyring)
    manifest = PROMOTION.load_json(bundle/PROMOTION.MANIFEST)
    require(manifest.get('tag')==tag and manifest.get('identity',{}).get('channel')=='archive'
            and manifest.get('signingFingerprint')==fingerprint, 'Public musl archive signature/identity differs')
    assets = manifest.get('assets')
    require(isinstance(assets,list) and 0 < len(assets) <= 100
            and len({item.get('name') for item in assets})==len(assets), 'Invalid public signed archive inventory')
    expected = {PROMOTION.MANIFEST,PROMOTION.SIGNATURE}
    for item in assets:
        name = item.get('name')
        require(isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,220}',name)
                and type(item.get('size')) is int and 0 < item['size'] < 6*1024**3
                and re.fullmatch(r'[a-f0-9]{64}',item.get('sha256','')), 'Unsafe or oversized public musl asset')
        validate_api_asset(remote.get(name),name,CONTRACT.REPOSITORY,tag,descriptor=item)
        download_asset(base+name,bundle/name,item)
        expected.add(name)
    require(set(remote)==expected, 'Public musl release has unexpected or missing assets')
    PROMOTION.validate_bundle(bundle,keyring)
    verify_release_tag(AnonymousGitHubAPI(),tag,manifest['targetCommit'])
    records = [record for record in manifest['records'] if record['architecture']==architecture]
    require(len(records)==1, 'An exact native public archive record is required')
    record = records[0]; build = record['build']
    build_directory = fresh(workspace/'build')
    (build_directory/'package-build.json').write_bytes(encoded(build))
    shutil.copyfile(bundle/record['artifactAsset'],build_directory/build['artifact']['name'])
    require(descriptor(build_directory/build['artifact']['name'])==build['artifact'], 'Public archive copy differs from actual retrieved bytes')
    report = ARCHIVE.native(build_directory,architecture,workspace/'qualification')
    report['orchestration'] = origin
    report['publicVerification'] = dict(status='passed',anonymous=True,url=base+record['artifactAsset'],
        artifactSha256=build['artifact']['sha256'],manifestSha256=hashlib.sha256(manifest_raw).hexdigest(),
        manifestUrl=base+PROMOTION.MANIFEST,signingFingerprint=fingerprint)
    output = fresh(output)
    (output/'public-report.json').write_bytes(encoded(report))
    return dict(status='public-native-verified',architecture=architecture,artifactSha256=build['artifact']['sha256'])


def public_bundle(channel, revision, workspace):
    """Authenticate the closed public signed inventory without any API token."""
    from musl_release import verify_publication_signature
    import musl_promotion as PROMOTION
    CONTRACT.version_revision('10.0.403',revision)
    bundle=fresh(workspace/'public-bundle')
    tag=CONTRACT.distribution_tag(channel,'10.0.403',revision)
    base=f'https://github.com/{CONTRACT.REPOSITORY}/releases/download/{tag}/'
    api=AnonymousGitHubAPI()
    release=api.api(f'repos/{CONTRACT.REPOSITORY}/releases/tags/{tag}')
    require(isinstance(release,dict) and release.get('tag_name')==tag
            and release.get('draft') is False and release.get('prerelease') is False,
            'An exact public stable musl distribution release is required')
    remote=release_assets(release)
    raw=get_bytes(base+PROMOTION.MANIFEST,16*1024**2)
    signature=get_bytes(base+PROMOTION.SIGNATURE,1024**2)
    for name,content in ((PROMOTION.MANIFEST,raw),(PROMOTION.SIGNATURE,signature)):
        validate_api_asset(remote.get(name),name,CONTRACT.REPOSITORY,tag,content=content)
        (bundle/name).write_bytes(content)
    keyring=workspace/'trusted.gpg'
    subprocess.run(['gpg','--batch','--dearmor','--output',str(keyring),str(ROOT/'releases/downstream-signing-key.asc')],check=True)
    fingerprint=verify_publication_signature(bundle/PROMOTION.MANIFEST,bundle/PROMOTION.SIGNATURE,keyring)
    manifest=PROMOTION.load_json(bundle/PROMOTION.MANIFEST)
    require(manifest.get('tag')==tag and manifest.get('identity',{}).get('channel')==channel
            and manifest.get('signingFingerprint')==fingerprint,'Public musl signature/identity differs')
    assets=manifest.get('assets')
    require(isinstance(assets,list) and 0<len(assets)<=100
            and len({row.get('name') for row in assets})==len(assets),'Invalid signed musl asset set')
    expected={PROMOTION.MANIFEST,PROMOTION.SIGNATURE}
    for row in assets:
        name=row.get('name')
        require(isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,220}',name)
                and type(row.get('size')) is int and 0<row['size']<6*1024**3
                and re.fullmatch(r'[a-f0-9]{64}',row.get('sha256','')),'Unsafe public musl asset descriptor')
        validate_api_asset(remote.get(name),name,CONTRACT.REPOSITORY,tag,descriptor=row)
        download_asset(base+name,bundle/name,row)
        expected.add(name)
    require(set(remote)==expected,'Public musl release has an unexpected or missing asset')
    verify_release_tag(api,tag,manifest['targetCommit'])
    return bundle,manifest,raw,fingerprint,keyring,base


def public_apk(architecture, revision, workspace, output):
    """Install the permanent signed public repository and rerun native gates."""
    import musl_apk_promotion as PROMOTION
    import musl_package_native as NATIVE
    import musl_packages as APK
    origin=orchestration(); _docker_architecture(architecture)
    workspace=fresh(workspace)
    bundle,manifest,raw,fingerprint,keyring,base=public_bundle('apk',revision,workspace)
    PROMOTION.validate_bundle(bundle,keyring)
    records=[row for row in manifest['records'] if row['architecture']==architecture]
    require(len(records)==1,'An exact native public APK record is required')
    record=records[0]; build=record['build']; repository=record['repository']
    inputs=receive_source(architecture,workspace/'source',anonymous=True)
    plan,sdk=intake_plan(inputs,architecture,'apk',revision)
    require(build['plan']==plan,'Public APK plan differs from independently authenticated source')
    context,_,_,_=APK.stage_payload(plan,sdk,workspace/'context')
    for name in ('plan.json','payload-inventory.json','command-inventory.json'):
        published=ordinary_file(bundle/('apk-'+architecture+'--'+name))
        require(published.read_bytes()==ordinary_file(context/name).read_bytes(),
                'Public APK payload/command inventory differs from independent reconstruction')
    (context/'package-build.json').write_bytes(encoded(build))
    require(json.loads(ordinary_file(bundle/record['packageBuildAsset']).read_bytes())==build,
            'Public APK permanent build metadata differs from its signed record')
    target=fresh(context/'repository')
    for name in ['APKINDEX.tar.gz',*[row['path'] for row in build['packages']]]:
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,220}',name),'Unsafe public APK filename')
        shutil.copyfile(ordinary_file(bundle/('apk-'+architecture+'--'+name)),target/name)
    key=ordinary_file(bundle/repository['keyName'])
    NATIVE.approved_signer(key)
    require(repository['keyUrl']==base+key.name
            and repository['keySha256']==descriptor(key)['sha256'],
            'Public APK trust anchor differs from the signed project key')
    report=NATIVE.native_apk(context,architecture,workspace/'qualification',key,
        public_repository=repository['url']+'APKINDEX.tar.gz')
    report['orchestration']=origin
    report['publicVerification'].update(manifestUrl=base+'distribution-manifest.json',
        manifestSha256=hashlib.sha256(raw).hexdigest(),signingFingerprint=fingerprint)
    output=fresh(output)
    (output/'public-report.json').write_bytes(encoded(report))
    return dict(status='public-native-verified',architecture=architecture,
        artifactSha256=report['artifact']['sha256'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    receive=commands.add_parser('receive-source')
    receive.add_argument('--arch',choices=tuple(CONTRACT.ARCHITECTURES),required=True)
    receive.add_argument('--output',type=Path,required=True)
    archive=commands.add_parser('archive-candidate')
    archive.add_argument('--arch',choices=tuple(CONTRACT.ARCHITECTURES),required=True)
    archive.add_argument('--revision',type=int,default=1)
    archive.add_argument('--workspace',type=Path,required=True)
    archive.add_argument('--output',type=Path,required=True)
    public=commands.add_parser('public-archive')
    public.add_argument('--arch',choices=tuple(CONTRACT.ARCHITECTURES),required=True)
    public.add_argument('--revision',type=int,default=1)
    public.add_argument('--workspace',type=Path,required=True)
    public.add_argument('--output',type=Path,required=True)
    public_apk_command=commands.add_parser('public-apk')
    public_apk_command.add_argument('--arch',choices=tuple(CONTRACT.ARCHITECTURES),required=True)
    public_apk_command.add_argument('--revision',type=int,default=1)
    public_apk_command.add_argument('--workspace',type=Path,required=True)
    public_apk_command.add_argument('--output',type=Path,required=True)
    assemble=commands.add_parser('assemble-apk')
    assemble.add_argument('--inputs',type=Path,required=True)
    assemble.add_argument('--arch',choices=tuple(CONTRACT.ARCHITECTURES),required=True)
    assemble.add_argument('--revision',type=int,default=1)
    assemble.add_argument('--output',type=Path,required=True)
    apk=commands.add_parser('apk-candidate')
    apk.add_argument('--arch',choices=tuple(CONTRACT.ARCHITECTURES),required=True)
    apk.add_argument('--revision',type=int,default=1)
    apk.add_argument('--workspace',type=Path,required=True)
    apk.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.command=='receive-source':
        result=receive_source(args.arch,args.output)
        print(json.dumps(dict(status='received-qualified',directory=str(result))))
    elif args.command=='archive-candidate':
        print(json.dumps(archive_candidate(args.arch,args.revision,args.workspace,args.output)))
    elif args.command=='public-archive':
        print(json.dumps(public_archive(args.arch,args.revision,args.workspace,args.output)))
    elif args.command=='public-apk':
        print(json.dumps(public_apk(args.arch,args.revision,args.workspace,args.output)))
    elif args.command=='assemble-apk':
        print(json.dumps(assemble_apk(args.inputs,args.arch,args.revision,args.output)))
    else:
        print(json.dumps(apk_candidate(args.arch,args.revision,args.workspace,args.output)))


if __name__=='__main__':
    main()
