"""Protected APK re-signing and native APK/OCI consumer evidence.

The native builders may use ephemeral keys. Promotion replaces only the v2
signature member; signed control and payload compressed bytes stay unchanged.
"""
import argparse
from sdk_runtime import target_framework
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.request

import musl_archive as ARCHIVE
import musl_packages as APK
from musl_contract import ARCHITECTURES, REPOSITORY
from downstream_release import descriptor, encoded, ordinary_file

ROOT = Path(__file__).resolve().parents[1]
APK_CHECKS = {'package-signature', 'index-signature', 'package-index-binding', 'payload-preservation',
    'original-notices', 'wrapper-license', 'command-aliases', 'cli-branding', 'version-stdout-compatible',
    'sdk-list-paths', 'host-root-rid', 'non-root', 'offline-network', 'offline-build-run',
    'complete-payload-elf-audit', 'stock-native-dependency-closure', 'system-trust-https', 'negative-signature-tests'}


def require(value, message):
    if not value:
        raise ValueError(message)


def package_roles(build):
    plan=build['plan']
    APK.validate_plan(plan,'apk')
    rows=build.get('packages',[])
    require(len(rows)==2 and {row.get('kind') for row in rows}=={'sdk','host'},'One SDK and one common-host APK are required')
    for row in rows:
        expected=(plan['package']['name'],plan['package']['version'],plan['architecture']['apk']) if row['kind']=='sdk' \
            else ('cbodotnet-host',APK.HOST_VERSION,'noarch')
        require((row.get('name'),row.get('version'),row.get('architecture'))==expected
            and row.get('path')==expected[0]+'-'+expected[1]+'.apk','APK role/filename differs from exact musl plan')
    return rows


def qualified_plan_source(plan):
    """A runtime pass cannot admit a fixture or another producer by inference."""
    from musl_contract import load_qualification_catalog
    rows=[row for row in load_qualification_catalog()['builds']
        if row['sdkVersion']==plan['sdkVersion'] and row['producerRevision']==plan['producerRevision']]
    require(len(rows)==1 and plan.get('kind')=='musl-distribution-plan'
        and rows[0]['sourceManifestSha256']==plan['sourceManifestSha256']
        and rows[0]['sourceReleaseTag']==plan['sourceReleaseTag']
        and rows[0]['architectures'][plan['architecture']['public']]==plan['producer'],
        'Native consumer source differs from the independently qualified musl producer')


def approved_signer(public_key, policy=None, *, now=None):
    """Raw APK keys have no expiry; enforce the reviewed publisher cutoff here."""
    if policy is None:
        # Lazy import keeps release orchestration free to import this module.
        from musl_release import validate_apk_signer
        validate_apk_signer(public_key,now=now)
        return APK.public_key_identity(public_key)
    require(policy.get('repository')==REPOSITORY and policy.get('workflow')=='.github/workflows/musl-release.yml'
        and policy.get('environment')=='downstream-release', 'Unreviewed protected APK signing scope')
    row=policy.get('apkSigner',{})
    identity=APK.public_key_identity(public_key)
    require(row.get('state')=='active' and row.get('algorithm')=='RSA4096' and row.get('signatureType')=='RSA256'
        and row.get('digest')=='SHA256' and row.get('secret')=='APK_SIGNING_KEY'
        and row.get('workflow')==policy['workflow'] and row.get('environment')==policy['environment']
        and row.get('publicKeyName')==identity['filename'] and row.get('publicKeySha256')==identity['sha256']
        and row.get('spkiDerSha256')==identity['spkiSha256'], 'APK key differs from approved permanent trust identity')
    now=now or datetime.datetime.now(datetime.timezone.utc)
    parse=lambda value:datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
    require(parse(row['createdAt'])<=now<parse(row['publisherNotAfter']), 'APK publisher key is outside its approved signing interval')
    return identity


def signature_prefix(control,key,public):
    """Canonical abuild-compatible RSA256 signature gzip member."""
    with tempfile.TemporaryDirectory(prefix='protected-apk-sign-') as temporary:
        directory=Path(temporary)
        signable=directory/'control.tar.gz'
        signature=directory/'signature'
        signable.write_bytes(control)
        subprocess.run(['openssl','dgst','-sha256','-sign',str(key),'-out',str(signature),str(signable)],
                       check=True,capture_output=True)
        value=signature.read_bytes()
        require(len(value)==512,'Unexpected RSA-4096 signature size')
        buffer=io.BytesIO()
        with tarfile.open(fileobj=buffer,mode='w',format=tarfile.USTAR_FORMAT) as archive:
            entry=tarfile.TarInfo('.SIGN.RSA256.'+public.name)
            entry.size,entry.mode,entry.uid,entry.gid,entry.mtime=len(value),0o644,0,0,int(APK.SOURCE_DATE_EPOCH)
            archive.addfile(entry,io.BytesIO(value))
        return gzip.compress(buffer.getvalue()[:1024],compresslevel=9,mtime=0)


def resign_apk(source, source_public_key, destination, private_key, public_key, *, production=True):
    """Keep exact compressed control+data; replace the signature, never execute SDKs."""
    source=APK.ordinary(source)
    prior=APK.verify_apk(source,source_public_key)
    key,public=APK.ordinary(private_key),APK.ordinary(public_key)
    identity=approved_signer(public) if production else APK.public_key_identity(public)
    require(key.stat().st_mode & 0o077 == 0,'APK private key must have owner-only permissions')
    if production:
        from musl_release import validate_apk_signer
        validate_apk_signer(public,key)
    der=subprocess.run(['openssl','pkey','-in',str(key),'-pubout','-outform','DER'],check=True,capture_output=True).stdout
    require(hashlib.sha256(der).hexdigest()==identity['spkiSha256'], 'Approved APK private/public key pairing differs')
    destination=Path(destination).absolute()
    require(not destination.exists() and destination.parent.is_dir()
        and not any(p.is_symlink() for p in [destination,*destination.parents]), 'Fresh ordinary re-signed APK output required')
    with source.open('rb') as incoming:
        APK.gzip_member(incoming,128*1024)
        control_start=incoming.tell()
        control,_=APK.gzip_member(incoming)
    prefix=signature_prefix(control,key,public)
    with destination.open('xb') as outgoing,source.open('rb') as incoming:
        outgoing.write(prefix)
        incoming.seek(control_start)
        shutil.copyfileobj(incoming,outgoing,1024*1024)
    current=APK.verify_apk(destination,public)
    require(all(current[key]==prior[key] for key in ('name','version','architecture','controlSha256','indexIdentity','dataSha256')),
            'Protected signing changed APK control, payload, or installation identity')
    return current


def resign_repository(build_directory,source_public_key,output,private_key,public_key,*,production=True):
    """Freeze signed APK/index bytes without apk-tools or SDK execution in the signer."""
    source=Path(build_directory).absolute()
    build=json.loads(ordinary_file(source/'package-build.json').read_bytes())
    package_roles(build)
    if production:
        qualified_plan_source(build['plan'])
    original=[]
    for row in build['packages']:
        current=APK.verify_apk(source/'repository'/row['path'],source_public_key)
        require(all(row[k]==current[k] for k in ('name','version','architecture','size','sha256')),
                'Native APK candidate changed before protected promotion')
        original.append(current)
    index_path=source/'repository/APKINDEX.tar.gz'
    APK.verify_index(index_path,source_public_key,original)
    _,_,plain,_=APK.verify_signed_v2(index_path,source_public_key)
    index_files=APK.tar_files(plain)
    output=APK.fresh_output(output)
    repository=output/'repository'
    repository.mkdir()
    packages=[]
    for row in build['packages']:
        current=resign_apk(source/'repository'/row['path'],source_public_key,repository/row['path'],
                           private_key,public_key,production=production)
        packages.append(dict(current,kind=row['kind']))
    lookup={(row['name'],row['version']):row for row in packages}
    blocks=[]
    for block in index_files['APKINDEX'].decode().strip().split('\n\n'):
        lines=block.splitlines()
        fields=dict(line.split(':',1) for line in lines)
        current=lookup[(fields['P'],fields['V'])]
        blocks.append('\n'.join('S:'+str(current['size']) if line.startswith('S:') else line for line in lines))
    index_files['APKINDEX']=('\n\n'.join(blocks)+'\n\n').encode()
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name,data in sorted(index_files.items()):
            row=tarfile.TarInfo(name)
            row.size,row.mode,row.uid,row.gid,row.mtime=len(data),0o644,0,0,int(APK.SOURCE_DATE_EPOCH)
            archive.addfile(row,io.BytesIO(data))
    content=gzip.compress(buffer.getvalue(),compresslevel=9,mtime=0)
    public,key=APK.ordinary(public_key),APK.ordinary(private_key)
    (repository/'APKINDEX.tar.gz').write_bytes(signature_prefix(content,key,public)+content)
    index=APK.verify_index(repository/'APKINDEX.tar.gz',public,packages)
    for name in ('plan.json','payload-inventory.json','command-inventory.json'):
        shutil.copyfile(ordinary_file(source/name),output/name)
    recipes=output/'recipes'
    recipes.mkdir()
    for kind in ('sdk','host'):
        shutil.copyfile(ordinary_file(source/'aports/cbodotnet'/kind/'APKBUILD'),recipes/(kind+'.APKBUILD'))
    result=dict(build,packages=packages,repository=index,signingKey=APK.public_key_identity(public),publicKeyAsset=descriptor(public),
        credentialPurpose='protected-publication-candidate' if production else 'ephemeral-fixture',
        priorNativePackages=[{key:row[key] for key in ('path','size','sha256','controlSha256','dataSha256')} for row in original],
        signingPreservedCompressedControlAndPayload=True,publicationQualified=False)
    APK.write_json(output/'package-build.json',result)
    shutil.copyfile(public,output/public.name)
    return result


def negative_apk_checks(package,index,public_key,workspace):
    """Use real apk verification with valid tampered gzip streams and wrong trust."""
    package,index,key=APK.ordinary(package),APK.ordinary(index),APK.ordinary(public_key)
    workspace=Path(workspace)
    workspace.mkdir()
    trust=workspace/'trust'
    trust.mkdir()
    shutil.copyfile(key,trust/key.name)
    ARCHIVE.run(['apk','--keys-dir',trust,'verify',package,index])
    results={}
    def reject(label,path,key_directory=trust):
        result=subprocess.run(['apk','--keys-dir',str(key_directory),'verify',str(path)],text=True,capture_output=True)
        require(result.returncode!=0,'apk accepted tampered or untrusted '+label)
        diagnostic=(result.stdout+result.stderr).strip()
        require(re.search(r'BAD signature|UNTRUSTED signature|integrity error',diagnostic),
                'Negative APK case failed without a signature/integrity diagnostic: '+diagnostic)
        results[label]=dict(status='rejected',exitCode=result.returncode,diagnostic=diagnostic)
    def altered_control(source,destination,is_package):
        with source.open('rb') as incoming,destination.open('xb') as outgoing:
            signature,_=APK.gzip_member(incoming,128*1024)
            _,plain=APK.gzip_member(incoming)
            outgoing.write(signature)
            outgoing.write(gzip.compress(plain+b'\0'*512,mtime=0))
            if is_package:
                shutil.copyfileobj(incoming,outgoing,1024*1024)
    bad_control=workspace/'changed-control.apk'
    altered_control(package,bad_control,True)
    reject('changed-package-control',bad_control)
    bad_index=workspace/'APKINDEX.tar.gz'
    altered_control(index,bad_index,False)
    reject('changed-index',bad_index)
    # Recompress a valid payload stream with its first ordinary file byte changed.
    # Keep the authentic control's old datahash, so actual apk must reject it.
    with package.open('rb') as incoming:
        signature,_=APK.gzip_member(incoming,128*1024)
        control,_=APK.gzip_member(incoming)
        offset=incoming.tell()
        with tarfile.open(fileobj=incoming,mode='r|gz') as archive:
            first=next((m for m in archive if m.isfile() and m.size),None)
            require(first is not None,'APK payload has no ordinary file for integrity check')
            change_at=first.offset_data
    bad_payload=workspace/'changed-payload.apk'
    with package.open('rb') as incoming,bad_payload.open('xb') as outgoing:
        outgoing.write(signature+control)
        incoming.seek(offset)
        with gzip.GzipFile(fileobj=incoming,mode='rb') as expanded,gzip.GzipFile(fileobj=outgoing,mode='wb',mtime=0,compresslevel=1) as packed:
            cursor=0
            for block in iter(lambda:expanded.read(1024*1024),b''):
                if cursor<=change_at<cursor+len(block):
                    mutable=bytearray(block)
                    mutable[change_at-cursor]^=1
                    block=bytes(mutable)
                packed.write(block)
                cursor+=len(block)
    reject('changed-package-payload',bad_payload)
    wrong=workspace/'wrong'
    wrong.mkdir()
    with tempfile.TemporaryDirectory(prefix='wrong-apk-fixture-key-') as temporary:
        private=Path(temporary)/'wrong.rsa'
        subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:4096','-out',str(private)],
                       check=True,capture_output=True)
        private.chmod(0o600)
        subprocess.run(['openssl','pkey','-in',str(private),'-pubout','-out',str(wrong/key.name)],check=True,capture_output=True)
        reject('wrong-key-same-name-package',package,wrong)
        reject('wrong-key-same-name-index',index,wrong)
    missing=workspace/'missing'
    missing.mkdir()
    reject('missing-key',index,missing)
    # Large tampered artifacts and fixture trust files are not retained.
    shutil.rmtree(workspace)
    return results


def consumer_environment(uid=10001):
    environment=dict(os.environ,HOME='/home/cbot-musl',DOTNET_CLI_HOME='/home/cbot-musl/cli',
        NUGET_PACKAGES='/home/cbot-musl/nuget',DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',
        DOTNET_CLI_TELEMETRY_OPTOUT='1',DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE='true',
        DOTNET_NOLOGO='1',DOTNET_CLI_UI_LANGUAGE='en-US',LC_ALL='C')
    for name in ('LD_LIBRARY_PATH','LD_PRELOAD','DOTNET_ROOT','DOTNET_ROOT_X64','DOTNET_ROOT_ARM64',
                 'DOTNET_HOST_PATH','SSL_CERT_FILE','SSL_CERT_DIR','DOTNET_SYSTEM_GLOBALIZATION_INVARIANT'):
        environment.pop(name,None)
    return environment


def installed_apk(build_directory,architecture,workspace,public_key,target_policy=None):
    """Execute exact installed APK bytes as non-root with the network disabled."""
    ARCHIVE.native_guard(architecture)
    require(os.geteuid()==10001 and os.getegid()==10001,'APK qualification requires actual UID/GID10001')
    require({p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'Actual network-none APK qualification required')
    build_directory,workspace=Path(build_directory),Path(workspace)
    build=json.loads(ordinary_file(build_directory/'package-build.json').read_bytes())
    plan=build['plan']
    package_roles(build)
    qualified_plan_source(plan)
    require(plan['architecture']['public']==architecture and build.get('payloadPreserved') is True
        and build.get('credentialPurpose')!='ephemeral-fixture','A real SDK APK build is required')
    key=ordinary_file(public_key)
    packages=[]
    for row in build['packages']:
        path=build_directory/'repository'/row['path']
        current=APK.verify_apk(path,key)
        require(all(current[k]==row[k] for k in ('name','version','architecture','size','sha256','controlSha256','dataSha256')),
                'Native APK input differs from authenticated build')
        packages.append(current)
    APK.verify_index(build_directory/'repository/APKINDEX.tar.gz',key,packages)
    root=Path(plan['package']['root'])
    expected=json.loads(ordinary_file(build_directory/'payload-inventory.json').read_bytes())
    require(ARCHIVE.tools().snapshot(root)==expected,'Installed APK payload differs from qualified SDK inventory')
    require(not Path('/usr/bin/dotnet').exists(),'SDK-free APK consumer unexpectedly contains an official dotnet')
    require(Path('/usr/bin/cbodotnet').read_text()==APK.default_launcher_text()
        and Path(plan['package']['launcher']).read_text()==APK.launcher_text(plan),'Installed APK command bytes differ')
    require(Path('/usr/share/licenses/cbodotnet-host/LICENSE').read_bytes()==(ROOT/'LICENSE').read_bytes(),
            'APK wrapper license differs')
    environment=consumer_environment()
    commands=[]
    for name in ('cbodotnet','cbodotnet-'+'.'.join(plan['sdkVersion'].split('.')[:2])):
        command=Path('/usr/bin')/name
        require(stat.S_IMODE(command.stat().st_mode)==0o755,'APK command mode differs')
        version=subprocess.run([str(command),'--version'],env=environment,text=True,capture_output=True)
        require(version.returncode==0 and version.stdout==plan['sdkVersion']+'\n'
            and version.stderr==APK.BRANDING['displayName']+'\n','APK alias numeric stdout/branding stderr differs')
        info=json.loads(ARCHIVE.run([command,'--cbodotnet-info'],env=environment))
        require(all(info.get(k)==v for k,v in ARCHIVE.identity(plan).items()) and info.get('sdkRoot')==str(root),
                'APK source/root/libc identity differs')
        require(ARCHIVE.run([command,'--list-sdks'],env=environment).splitlines()
            ==[plan['sdkVersion']+' ['+str(root/'sdk')+']'],'APK SDK selection escaped its root')
        detail=ARCHIVE.run([command,'--info'],env=environment)
        require(detail.startswith(APK.BRANDING['displayName']+'\n') and str(root) in detail
            and re.search(r'^\s*RID:\s*'+re.escape(plan['targetRid'])+r'\s*$',detail,re.M),'APK host root/RID differs')
        commands.append(dict(command=name,sdkRoot=str(root),targetRid=plan['targetRid']))
    elf=ARCHIVE.audit_elf(root,architecture,target_policy)
    (workspace/'elf-audit.json').write_bytes(encoded(elf))
    cli=Path('/usr/bin/cbodotnet')
    output=ARCHIVE.run(['sh','-ec',ARCHIVE.full_smoke_script(plan,root,cli,workspace/'offline-project')],env=environment)
    from sdk_runtime import validate_smoke_output
    functional=validate_smoke_output(output)
    require(output.count('published-full-icu-calendars-timezones-passed')>=2,'DLL and apphost need full ICU/timezone checks')
    functional.update(fullIcuCulturesAndCalendars='passed',timeZoneDatabase='passed')
    (workspace/'functional.txt').write_text(output)
    ARCHIVE.run(['sh','-ec',ARCHIVE.trust_probe_script(plan,root,cli,workspace/'system-trust')],env=environment)
    sdk=next(row for row in build['packages'] if row['kind']=='sdk')
    negative=negative_apk_checks(build_directory/'repository'/sdk['path'],build_directory/'repository/APKINDEX.tar.gz',key,workspace/'negative')
    require(ARCHIVE.tools().snapshot(root)==expected,'Native execution modified installed qualified SDK')
    result=dict(schemaVersion=1,scope='musl-apk-offline',status='passed',native=True,architecture=architecture,
        libc='musl',targetRid=plan['targetRid'],identity=ARCHIVE.identity(plan),networkForBuild='none',uid=os.geteuid(),gid=os.getegid(),
        checks=dict.fromkeys(APK_CHECKS-{'system-trust-https'},'passed'),functionalChecks=functional,
        commands=commands,packages=packages,negativeCases=negative,dependencies=ARCHIVE.run(['apk','info','-v']).splitlines(),
        caBundle=descriptor(Path('/etc/ssl/cert.pem').resolve(strict=True)),
        trustProbe=str(workspace/('system-trust/bin/Debug/'+target_framework(plan['sdkVersion'])+'/Trust.dll')),cli=str(cli),payload=str(root))
    (workspace/'offline-report.json').write_bytes(encoded(result))
    return result


def native_apk(build_directory,architecture,workspace,public_key,target_policy=None,public_repository=None):
    """Install through real signature-enforcing apk, then run independent native probes."""
    require(platform.system()=='Linux' and platform.machine() in ({'x86_64'} if architecture=='x64' else {'aarch64','arm64'}),
            'A matching native Linux Docker host is mandatory')
    build_directory=Path(build_directory).resolve(strict=True)
    workspace=ARCHIVE.fresh_directory(workspace)
    workspace.chmod(0o777)
    key=ordinary_file(public_key)
    build=json.loads(ordinary_file(build_directory/'package-build.json').read_bytes())
    plan=build['plan']
    package_roles(build)
    qualified_plan_source(plan)
    require(plan['architecture']['public']==architecture,'Docker architecture differs from APK plan')
    server=ARCHIVE.run(['docker','info','--format','{{.Architecture}}']).strip()
    require(server in ({'x86_64','amd64'} if architecture=='x64' else {'aarch64','arm64'}),'Docker must use matching native CPU')
    (workspace/'repository').mkdir()
    for name in ['APKINDEX.tar.gz',*[row['path'] for row in build['packages']]]:
        shutil.copyfile(ordinary_file(build_directory/'repository'/name),workspace/'repository'/name)
    shutil.copyfile(key,workspace/key.name)
    packages=[APK.verify_apk(workspace/'repository'/row['path'],key) for row in build['packages']]
    APK.verify_index(workspace/'repository/APKINDEX.tar.gz',key,packages)
    repository='/candidate/repository/APKINDEX.tar.gz'
    public_bytes=None
    if public_repository is not None:
        require(public_repository==APK.repository_url(plan['sdkVersion'],architecture,plan['packageRevision']),
                'Public APK repository escaped its immutable CPU namespace')
        repository=public_repository
        public_bytes=dict(repository=repository,packages=[dict(url=repository.rsplit('/',1)[0]+'/'+row['path'],
            name=row['path'],size=row['size'],sha256=row['sha256']) for row in packages],
            index=dict(url=repository,**descriptor(workspace/'repository/APKINDEX.tar.gz')))
        received=workspace/'anonymous-received'
        received.mkdir()
        for item in [*public_bytes['packages'],public_bytes['index']]:
            destination=received/item['name']
            with urllib.request.urlopen(item['url'],timeout=120) as incoming,destination.open('xb') as outgoing:
                size=0
                for block in iter(lambda:incoming.read(1024*1024),b''):
                    size+=len(block)
                    require(size<=item['size'],'Anonymous APK download exceeds its signed size')
                    outgoing.write(block)
            require(descriptor(destination)=={k:item[k] for k in ('name','size','sha256')},
                    'Anonymous public APK/index bytes differ from signed publication')
    pins=[name+'='+version for name,version in ARCHIVE.RUNTIME_PACKAGES.items()]
    containerfile=workspace/'Containerfile'
    containerfile.write_text('FROM '+ARCHIVE.BASES[architecture]+'\nRUN apk add --no-cache '
        +' '.join(pins)+' python3=3.14.10-r1 binutils=2.45.1-r1 openssl=3.5.9-r0 '
        '&& ! command -v dotnet && ! apk info | grep -E "^(dotnet|aspnetcore|gcompat|libc6-compat|glibc)" '
        '&& addgroup -g 10001 cbot-musl && adduser -D -u 10001 -G cbot-musl cbot-musl\n'
        'COPY repository/ /candidate/repository/\nCOPY '+key.name+' /etc/apk/keys/'+key.name+'\n'
        'RUN apk add --no-cache --repository '+shlex.quote(repository)+' '
        +shlex.quote(plan['package']['name']+'='+plan['package']['version'])+'\n',encoding='utf-8')
    image='cbodotnet-musl-apk-native:'+architecture+'-'+str(time.time_ns())
    ARCHIVE.run(['docker','build','--pull=false','--network=default','-f',containerfile,'-t',image,workspace])
    image_info=json.loads(ARCHIVE.run(['docker','image','inspect',image]))[0]
    require(image_info.get('Architecture')==('amd64' if architecture=='x64' else 'arm64') and image_info.get('Os')=='linux',
            'APK consumer image has another native CPU')
    (workspace/'target-policy.json').write_bytes(encoded(target_policy or []))
    common=['docker','run','--rm','--user','10001:10001','--cap-drop=ALL','--security-opt=no-new-privileges',
        '-v',str(ROOT)+':/project:ro','-v',str(build_directory)+':/build:ro','-v',str(workspace)+':/qualification',
        '-v',str(key)+':/trusted/'+key.name+':ro','-e','PYTHONDONTWRITEBYTECODE=1','-w','/project']
    ARCHIVE.run([*common,'--network=none',image,'python3','scripts/musl_package_native.py','installed-apk',
        '--build','/build','--arch',architecture,'--workspace','/qualification','--public-key','/trusted/'+key.name,
        '--target-policy','/qualification/target-policy.json'])
    offline=json.loads(ordinary_file(workspace/'offline-report.json').read_bytes())
    trust=ARCHIVE.run([*common,'--network=default','-e','HOME=/home/cbot-musl','-e','DOTNET_CLI_HOME=/home/cbot-musl/cli',
        image,offline['cli'],offline['trustProbe']])
    require('system-trust-https-passed' in trust,'APK real HTTPS with system CA trust failed')
    (workspace/'system-trust.txt').write_text(trust)
    sdk=next(row for row in packages if row['name']==plan['package']['name'])
    result=dict(schemaVersion=1,scope='musl-apk-installation',status='passed',native=True,architecture=architecture,
        libc='musl',targetRid=plan['targetRid'],identity=ARCHIVE.identity(plan),networkForBuild='none',
        artifact=dict(name=sdk['path'],size=sdk['size'],sha256=sdk['sha256']),
        checks=dict.fromkeys(APK_CHECKS,'passed'),functionalChecks=offline['functionalChecks'],
        userSpaces=[dict(variant='alpine-3.24',alpineVersion='3.24.4',base=ARCHIVE.BASES[architecture],imageId=image_info['Id'],
            uid=10001,gid=10001,status='passed',offline=offline,elfAudit=json.loads((workspace/'elf-audit.json').read_bytes()),
            systemTrustHttps=dict(status='passed',url=ARCHIVE.trust_url(architecture),outputSha256=hashlib.sha256(trust.encode()).hexdigest()))])
    if public_bytes is not None:
        result['publicBytes']=public_bytes
        result['publicVerification']=dict(anonymous=True,status='passed',artifactSha256=sdk['sha256'],
            sourceUrl=repository.rsplit('/',1)[0]+'/'+sdk['path'],indexUrl=repository,
            indexSha256=descriptor(workspace/'repository/APKINDEX.tar.gz')['sha256'])
    (workspace/'report.json').write_bytes(encoded(result))
    return result


def lifecycle_apk(build_directory,upgrade_directory,architecture,public_key,output):
    """Actual SDK reinstall/upgrade/rollback/removal with an independent official SDK.

    This runs in a separate disposable consumer from the SDK-free runtime proof.
    Side-by-side selector algorithm tests use the explicitly synthetic fixture
    workflow until a second real SDK series has its own musl producer admission.
    """
    ARCHIVE.native_guard(architecture)
    require(os.geteuid()==0 and (Path('/.dockerenv').exists() or Path('/run/.containerenv').exists()),
            'APK lifecycle mutation requires a disposable native qualification container')
    first,second=Path(build_directory),Path(upgrade_directory)
    builds=[json.loads(ordinary_file(path/'package-build.json').read_bytes()) for path in (first,second)]
    for build in builds:
        package_roles(build)
        qualified_plan_source(build['plan'])
        require(build['plan']['architecture']['public']==architecture
            and build.get('credentialPurpose')!='ephemeral-fixture','Real matching SDK builds required for lifecycle proof')
    plan,next_plan=[b['plan'] for b in builds]
    require(plan['sdkVersion']==next_plan['sdkVersion'] and plan['sourceManifestSha256']==next_plan['sourceManifestSha256']
        and plan['producer']==next_plan['producer'] and plan['sdk']==next_plan['sdk']
        and next_plan['packageRevision']==plan['packageRevision']+1,'Lifecycle upgrade must preserve exact qualified source SDK')
    payload=json.loads(ordinary_file(first/'payload-inventory.json').read_bytes())
    require(json.loads(ordinary_file(second/'payload-inventory.json').read_bytes())==payload,'Lifecycle upgrade changed qualified SDK payload')
    key=ordinary_file(public_key)
    for directory,build in zip((first,second),builds):
        packages=[]
        for row in build['packages']:
            actual=APK.verify_apk(directory/'repository'/row['path'],key)
            require(actual['sha256']==row['sha256'] and actual['size']==row['size'],'Lifecycle package changed')
            packages.append(actual)
        APK.verify_index(directory/'repository/APKINDEX.tar.gz',key,packages)
    key_destination=Path('/etc/apk/keys')/key.name
    require(not key_destination.exists(),'Lifecycle must not replace an existing system APK trust key')
    shutil.copyfile(key,key_destination)
    key_destination.chmod(0o644)
    official=Path('/usr/bin/dotnet')
    require(official.is_file(),'Independent stock official SDK must be preinstalled')
    official_version=ARCHIVE.run([official,'--version']).strip()
    owner=ARCHIVE.run(['apk','info','--who-owns',official]).strip()
    require('dotnet-host' in owner,'Independent official host owner differs')
    official_tree=ARCHIVE.tools().snapshot(official.resolve().parent)
    official_host=descriptor(official.resolve())
    events=[]
    environment=consumer_environment()
    def check_sdk(expected_version):
        command='/usr/bin/cbodotnet'
        result=subprocess.run(['su','cbot-musl','-c',command+' --version'],capture_output=True,text=True,env=environment)
        require(result.returncode==0 and result.stdout==expected_version+'\n'
            and result.stderr==APK.BRANDING['displayName']+'\n','Actual lifecycle SDK selection/branding differs')
        require(ARCHIVE.tools().snapshot(Path(plan['package']['root']))==payload,'Actual lifecycle changed qualified SDK bytes or modes')
    def install(directory,version,*options):
        ARCHIVE.run(['apk','--no-cache','--no-network','--repository',directory/'repository/APKINDEX.tar.gz',
            'add',*options,plan['package']['name']+'='+version,'cbodotnet-host='+APK.HOST_VERSION])
        check_sdk(plan['sdkVersion'])
        events.append(dict(operation='install-or-select',version=version,sourceIndex=descriptor(directory/'repository/APKINDEX.tar.gz')))
    install(first,plan['package']['version'])
    ARCHIVE.run(['apk','--no-cache','--no-network','--repository',first/'repository/APKINDEX.tar.gz',
        'fix','--reinstall',plan['package']['name']])
    check_sdk(plan['sdkVersion'])
    events.append(dict(operation='reinstall',version=plan['package']['version']))
    install(second,next_plan['package']['version'],'--upgrade')
    install(first,plan['package']['version'])
    ARCHIVE.run(['apk','--no-network','del',plan['package']['name']])
    require(not Path(plan['package']['root']).exists() and not Path(plan['package']['launcher']).exists(),
            'SDK root/versioned launcher remained after removal')
    result=subprocess.run(['/usr/bin/cbodotnet','--version'],capture_output=True,text=True)
    require(result.returncode==127,'Explicit retained host must fail clearly when no SDK remains')
    events.append(dict(operation='remove-sdk-retain-explicit-host',status='passed'))
    install(first,plan['package']['version'])
    ARCHIVE.run(['apk','--no-network','del',plan['package']['name'],'cbodotnet-host'])
    require(not Path('/usr/bin/cbodotnet').exists(),'Shared host command remained after explicit removal')
    events.append(dict(operation='remove-sdk-and-host',status='passed'))
    require(ARCHIVE.run([official,'--version']).strip()==official_version
        and ARCHIVE.run(['apk','info','--who-owns',official]).strip()==owner
        and descriptor(official.resolve())==official_host
        and ARCHIVE.tools().snapshot(official.resolve().parent)==official_tree,
        'Actual Community APK lifecycle changed independent official SDK')
    key_destination.unlink()
    result=dict(schemaVersion=1,scope='musl-apk-lifecycle',status='passed',native=True,architecture=architecture,
        libc='musl',targetRid=plan['targetRid'],identity=ARCHIVE.identity(plan),signingKey=APK.public_key_identity(key),
        events=events,official=dict(version=official_version,owner=owner,host=official_host,completeTreePreserved=True),
        sideBySideScope='Actual second-series musl SDK admission is separate; selector cross-series fixtures are reported independently.')
    Path(output).write_bytes(encoded(result))
    return result


def extract_image_root(archive_path,output):
    """Extract a merged OCI filesystem without host links, devices or path escapes."""
    import posixpath
    output=ARCHIVE.fresh_directory(output)
    with tarfile.open(ordinary_file(archive_path),'r:') as archive:
        entries=archive.getmembers()
        require(0<len(entries)<=300000 and sum(row.size for row in entries)<=16*1024**3,'Unbounded OCI root filesystem')
        require(sum(row.size for row in entries)+64*1024**2<shutil.disk_usage(output).free,'Insufficient OCI audit extraction space')
        members={}
        link_targets={}
        for row in entries:
            name=row.name.rstrip('/')
            path=PurePosixPath(name)
            require(name and str(path)==name and not path.is_absolute() and '..' not in path.parts
                and not any(c in name for c in '\\:\0\r\n') and name not in members,'Unsafe or duplicate OCI filesystem path')
            require(row.isfile() or row.isdir() or row.issym() or row.islnk()
                or (path.parts[0]=='dev' and (row.ischr() or row.isblk() or row.isfifo())),'Unsupported OCI filesystem member')
            members[name]=row
        for name,row in members.items():
            require(all(str(parent) not in members or members[str(parent)].isdir()
                for parent in PurePosixPath(name).parents),'OCI filesystem member has a non-directory parent')
            if row.issym() or row.islnk():
                require(not any(c in row.linkname for c in '\\:\0\r\n'),'Unsafe OCI filesystem link target')
                target=posixpath.normpath(row.linkname.lstrip('/') if row.linkname.startswith('/')
                    else posixpath.join(posixpath.dirname(name),row.linkname) if row.issym() else row.linkname)
                require(target not in {'','..'} and not target.startswith('../'),'OCI filesystem link escapes virtual root')
                link_targets[name]=target
                if row.islnk():
                    require(target in members and members[target].isfile(),'OCI hard link must reference an ordinary file')
        for name,row in members.items():
            path=output/name
            path.parent.mkdir(parents=True,exist_ok=True)
            if row.isdir():
                path.mkdir(exist_ok=True)
            elif row.isfile():
                with archive.extractfile(row) as source,path.open('xb') as target:
                    shutil.copyfileobj(source,target,1024*1024)
            else:
                continue
            path.chmod(row.mode&0o777)
        for name,row in members.items():
            path=output/name
            if row.islnk():
                os.link(output/link_targets[name],path)
            elif row.issym():
                # Anchor absolute links in the virtual image root. Relative links
                # retain their original text, preserving qualified SDK symlinks.
                target=os.path.relpath(output/link_targets[name],path.parent) if row.linkname.startswith('/') else row.linkname
                path.symlink_to(target)
    return output


def image_payload_ownership(archive_path,plan,commands):
    sdk=plan['package']['root'].lstrip('/')
    command_paths={row['path'].lstrip('/') for row in commands}
    sdk_entries=0
    command_entries=set()
    with tarfile.open(ordinary_file(archive_path),'r:') as archive:
        for row in archive:
            name=row.name.rstrip('/')
            is_sdk=name==sdk or name.startswith(sdk+'/')
            if is_sdk or name in command_paths:
                require(row.uid==row.gid==0 and not row.mode&0o7000 and (row.issym() or not row.mode&0o002),
                        'OCI SDK/launcher owner or immutable mode differs: '+name)
                if is_sdk:
                    sdk_entries+=1
                if name in command_paths:
                    command_entries.add(name)
    require(sdk_entries>0 and command_entries==command_paths,'OCI protected ownership inventory is incomplete')
    return dict(status='passed',uid=0,gid=0,sdkEntries=sdk_entries,launcherEntries=len(command_entries),
        setIdOrWorldWritableEntries=0,symlinkModes='Linux symlink permissions are ignored; contained targets and parent directories are checked.',
        method='complete-actual-image-export-header-inventory')


def native_oci(build_directory,architecture,workspace,image,target_policy=None,public_descriptor=None,*,fixture=False):
    """Test the actual production image without installing Python/readelf into it.

    Complete ELF parsing is static over its exported filesystem. A separate
    same-CPU run verifies each loadable host ELF, every stock provider's actual
    bytes/APK owner, all command aliases and the full offline runtime program.
    The static audit correctly retains native=False in the resulting report.
    """
    require(platform.system()=='Linux' and platform.machine() in ({'x86_64'} if architecture=='x64' else {'aarch64','arm64'}),
            'A matching native Linux Docker host is mandatory')
    build_directory=Path(build_directory).resolve(strict=True)
    workspace=ARCHIVE.fresh_directory(workspace)
    workspace.chmod(0o777)
    build=json.loads(ordinary_file(build_directory/'package-build.json').read_bytes())
    plan=build['plan']
    APK.validate_plan(plan,'oci')
    if not fixture:
        qualified_plan_source(plan)
    else:
        require(public_descriptor is None,'Development OCI fixture cannot produce public qualification evidence')
    require(plan['architecture']['public']==architecture,'OCI build has another native CPU')
    server=ARCHIVE.run(['docker','info','--format','{{.Architecture}}']).strip()
    require(server in ({'x86_64','amd64'} if architecture=='x64' else {'aarch64','arm64'}),'Docker must use matching native CPU')
    image_digest=None
    actual_public_descriptor=None
    if public_descriptor is not None:
        require(re.fullmatch(r'ghcr\.io/dotnetdev-kr/cbodotnet-sdk@sha256:[a-f0-9]{64}',image),
                'Public OCI qualification requires immutable canonical registry digest')
        require(public_descriptor.get('digest')==image.split('@',1)[1]
            and public_descriptor.get('architecture')==architecture,'Public OCI descriptor differs from actual native image')
        descriptor_url=(f'https://github.com/{REPOSITORY}/releases/download/distribution-musl-oci-sdk-'
            +plan['sdkVersion']+'-r'+str(plan['packageRevision'])+'/oci-index.json')
        require(public_descriptor.get('url')==descriptor_url
            and re.fullmatch(r'[a-f0-9]{64}',public_descriptor.get('artifactSha256','')),
            'Public OCI descriptor URL/hash escaped the immutable distribution release')
        with urllib.request.urlopen(descriptor_url,timeout=120) as incoming:
            raw=incoming.read(8*1024**2+1)
        require(len(raw)<=8*1024**2 and hashlib.sha256(raw).hexdigest()==public_descriptor['artifactSha256'],
                'Anonymous actual OCI descriptor bytes differ from signed release')
        (workspace/'public-oci-index.json').write_bytes(raw)
        actual_public_descriptor=json.loads(raw)
        require(actual_public_descriptor.get('repository')=='ghcr.io/'+REPOSITORY+'-sdk',
                'Actual OCI descriptor uses another registry namespace')
        platforms=actual_public_descriptor.get('platforms',{})
        if isinstance(platforms,dict):
            platform_row=platforms.get(architecture,{})
        else:
            matches=[row for row in platforms if row.get('architecture')==('amd64' if architecture=='x64' else 'arm64')]
            require(len(matches)==1,'Actual OCI descriptor has no unique matching native platform')
            platform_row=matches[0]
        require(platform_row.get('digest')==public_descriptor['digest'],'Actual OCI platform digest differs from pulled image')
        # Do not rely on authenticated caches for the anonymous public pull.
        with tempfile.TemporaryDirectory(prefix='anonymous-oci-pull-') as temporary:
            environment=dict(os.environ,DOCKER_CONFIG=temporary)
            ARCHIVE.run(['docker','pull',image],env=environment)
        image_digest=image.split('@',1)[1]
    info=json.loads(ARCHIVE.run(['docker','image','inspect',image]))[0]
    require(info.get('Architecture')==('amd64' if architecture=='x64' else 'arm64') and info.get('Os')=='linux',
            'OCI image is not the matching native Linux CPU')
    config=info.get('Config',{})
    if actual_public_descriptor is not None:
        require(platform_row.get('configDigest')==info.get('Id'),'Actual pulled OCI config differs from signed descriptor')
    require(config.get('User')=='app' and config.get('WorkingDir')=='/work' and config.get('Cmd')==['cbodotnet','--info']
        and not config.get('Entrypoint'),'OCI default user/workdir/command differs from reviewed image')
    environment=dict(value.split('=',1) for value in config.get('Env',[]))
    expected_environment=dict(PATH='/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin',
        DOTNET_ROOT=plan['package']['root'],DOTNET_CLI_TELEMETRY_OPTOUT='1',DOTNET_NOLOGO='1',DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1')
    require(environment==expected_environment,'OCI environment contains unreviewed build/signing state')
    require(all(config.get('Labels',{}).get(key)==value for key,value in build['labels'].items()),'OCI provenance/license labels differ')
    common=['docker','run','--rm','--cap-drop=ALL','--security-opt=no-new-privileges',
        '-v',str(workspace)+':/qualification','-e','HOME=/qualification/home','-e','DOTNET_CLI_HOME=/qualification/home/cli',
        '-e','NUGET_PACKAGES=/qualification/home/nuget','-e','DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=true']
    offline=[*common,'--network=none',image]
    require(ARCHIVE.run([*offline,'id','-u']).strip()=='1654' and ARCHIVE.run([*offline,'id','-g']).strip()=='1654',
            'Actual production image must run as UID/GID1654 by default')
    require(ARCHIVE.run([*offline,'cat','/etc/alpine-release']).strip()=='3.24.4','OCI image user space differs')
    interfaces=ARCHIVE.run([*offline,'sh','-ec','printf "%s\\n" /sys/class/net/*']).splitlines()
    require(interfaces==['/sys/class/net/lo'],'Actual OCI offline proof must have only loopback networking')
    inventory=ARCHIVE.run([*offline,'apk','info','-v']).splitlines()
    require(all(name+'-'+version in inventory for name,version in ARCHIVE.RUNTIME_PACKAGES.items()),'OCI stock dependency pins differ')
    require(not any(re.match(r'^(gcompat|libc6-compat|glibc)-',line) for line in inventory),'OCI image contains glibc compatibility layers')
    source_tools=('gcc','g++','clang','clang20','clang21','clang22','make','cmake','python3','abuild')
    tools=ARCHIVE.run([*offline,'sh','-ec','for tool in '+ ' '.join(source_tools)+'; do '
        'if command -v "$tool" >/dev/null 2>&1; then printf "%s\\n" "$tool"; fi; done'])
    require(not tools.strip(),'Production OCI image contains source-build tools: '+tools.strip())
    container=ARCHIVE.run(['docker','create',image]).strip()
    require(re.fullmatch(r'[a-f0-9]{12,64}',container),'Docker returned an unexpected export container ID')
    export=workspace/'image-rootfs.tar'
    try:
        ARCHIVE.run(['docker','export','--output',export,container])
    finally:
        ARCHIVE.run(['docker','rm',container])
    export_descriptor=descriptor(export)
    ownership=image_payload_ownership(export,plan,build['commandInventory'])
    root=extract_image_root(export,workspace/'image-rootfs')
    export.unlink()
    payload=root/plan['package']['root'].lstrip('/')
    expected=json.loads(ordinary_file(build_directory/'payload-inventory.json').read_bytes())
    require(ARCHIVE.tools().snapshot(payload)==expected,'Actual OCI payload differs from qualified SDK bytes/modes/links')
    require(not (root/'usr/bin/dotnet').exists(),'OCI unexpectedly owns a system /usr/bin/dotnet command')
    require((root/'usr/share/licenses/cbodotnet-host/LICENSE').read_bytes()==(ROOT/'LICENSE').read_bytes(),'OCI wrapper license differs')
    for command in build['commandInventory']:
        path=root/command['path'].lstrip('/')
        require(path.is_file() and not path.is_symlink() and APK.sha256_file(path)==command['sha256']
            and stat.S_IMODE(path.stat().st_mode)==0o755,'OCI launcher bytes/mode differ from built context')
    protected_paths=[plan['package']['root']+'/dotnet',*[row['path'] for row in build['commandInventory']]]
    live_owners=ARCHIVE.run([*offline,'stat','-c','%u:%g %a %n',*protected_paths]).splitlines()
    require(len(live_owners)==len(protected_paths) and all(line.startswith('0:0 755 ') for line in live_owners),
            'Actual OCI SDK host/launcher owner/mode differs from exported proof')
    audit=ARCHIVE.audit_elf(payload,architecture,target_policy,system_root=root,native=False)
    (workspace/'elf-audit.json').write_bytes(encoded(audit))
    commands=[]
    cli='/usr/local/bin/cbodotnet'
    runtime_root=plan['package']['root']
    series='.'.join(plan['sdkVersion'].split('.')[:2])
    for name in ('cbodotnet-'+series,'cbodotnet','dotnet'):
        path='/usr/local/bin/'+name
        version=subprocess.run([*map(str,offline),path,'--version'],capture_output=True,text=True)
        require(version.returncode==0 and version.stdout==plan['sdkVersion']+'\n'
            and version.stderr==APK.BRANDING['displayName']+'\n','OCI alias version stdout/branding differs')
        identity=json.loads(ARCHIVE.run([*offline,path,'--cbodotnet-info']))
        require(all(identity.get(k)==v for k,v in ARCHIVE.identity(plan).items()) and identity.get('sdkRoot')==runtime_root,
                'OCI alias source/root/libc identity differs')
        require(ARCHIVE.run([*offline,path,'--list-sdks']).splitlines()
            ==[plan['sdkVersion']+' ['+runtime_root+'/sdk]'],'OCI SDK selection escaped its root')
        detail=ARCHIVE.run([*offline,path,'--info'])
        require(detail.startswith(APK.BRANDING['displayName']+'\n') and runtime_root in detail
            and re.search(r'^\s*RID:\s*'+re.escape(plan['targetRid'])+r'\s*$',detail,re.M),'OCI actual host root/RID differs')
        commands.append(dict(command=name,sdkRoot=runtime_root,targetRid=plan['targetRid']))
    # Probe all loadable SDK host files with the *actual image's* musl loader.
    loader=ARCHITECTURES[architecture]['interpreter']
    dynamic=[row for row in audit['elfFiles'] if row['disposition']=='host-runtime-or-tool' and row['elfType'] in {'DYN','EXEC'}]
    script='set -eu\n'+''.join('printf '+shlex.quote('CBOT_ELF_'+str(index)+'\n')+'\n'
        +shlex.quote(loader)+' --list '+shlex.quote(runtime_root+'/'+row['path'])+'\n' for index,row in enumerate(dynamic))
    loaded=ARCHIVE.run([*offline,'sh','-ec',script])
    require('not found' not in loaded and 'Error ' not in loaded and all('CBOT_ELF_'+str(i)+'\n' in loaded for i in range(len(dynamic))),
            'Actual OCI musl loader failed a host ELF dependency probe')
    (workspace/'native-loader.txt').write_text(loaded)
    providers=[]
    for provider in audit['stockLibraries']:
        path='/'+Path(provider['path']).relative_to(root).as_posix()
        require(re.fullmatch(r'/(?:lib|usr/lib|usr/local/lib)/[A-Za-z0-9._+/-]+',path),'Unexpected stock library probe path')
        hashed=ARCHIVE.run([*offline,'sha256sum',path]).strip().split()
        owner=ARCHIVE.run([*offline,'apk','info','--who-owns',path]).strip()
        require(hashed==[provider['sha256'],path] and owner.startswith(path+' is owned by ')
            and 'cbodotnet-' not in owner,'Actual OCI stock APK owner/hash differs from static closure')
        if 'GLIBC_2.0' in provider.get('versionDefinitions',[]):
            require(owner.endswith(' is owned by libgcc-'+ARCHIVE.RUNTIME_PACKAGES['libgcc']),
                    'Reviewed GCC unwind ABI provider is not exact stock libgcc')
        providers.append(dict(path=path,sha256=hashed[0],apkOwner=owner))
    script=ARCHIVE.full_smoke_script(plan,runtime_root,cli,'/qualification/offline-project',expected_user='app')
    output=ARCHIVE.run([*offline,'sh','-ec',script])
    from sdk_runtime import validate_smoke_output
    functional=validate_smoke_output(output)
    require(output.count('published-full-icu-calendars-timezones-passed')>=2,'OCI DLL/apphost need full ICU/timezone checks')
    functional.update(fullIcuCulturesAndCalendars='passed',timeZoneDatabase='passed')
    (workspace/'functional.txt').write_text(output)
    ARCHIVE.run([*offline,'sh','-ec',ARCHIVE.trust_probe_script(plan,runtime_root,cli,'/qualification/system-trust')])
    trust=ARCHIVE.run([*common,'--network=default',image,cli,'/qualification/system-trust/bin/Debug/'+target_framework(plan['sdkVersion'])+'/Trust.dll'])
    require('system-trust-https-passed' in trust,'OCI actual HTTPS using system CA trust failed')
    (workspace/'system-trust.txt').write_text(trust)
    result=dict(schemaVersion=1,scope='musl-oci-installation',status='passed',native=True,architecture=architecture,
        libc='musl',targetRid=plan['targetRid'],identity=ARCHIVE.identity(plan),networkForBuild='none',
        image=image,imageDigest=image_digest,imageId=info['Id'],commands=commands,
        checks=dict.fromkeys((APK_CHECKS-{'package-signature','index-signature','package-index-binding','negative-signature-tests'})
            |{'oci-config','native-image-loader','native-stock-provider-ownership','root-owned-sdk','no-source-build-tools','clean-runtime-environment'},'passed'),functionalChecks=functional,
        userSpaces=[dict(variant='alpine-3.24',alpineVersion='3.24.4',uid=1654,gid=1654,status='passed',
            base=build['baseImage'],elfAudit=audit,dependencies=inventory,ownership=ownership,
            nativeImageExecution=dict(status='passed',native=True,architecture=architecture,targetRid=plan['targetRid'],
                imageId=info['Id'],dynamicElfCount=len(dynamic),loader=loader,loaderOutputSha256=hashlib.sha256(loaded.encode()).hexdigest(),
                stockLibraries=providers,export=export_descriptor,method='static-full-image-ELF-closure-plus-actual-image-loader-and-APK-owner-hash'),
            systemTrustHttps=dict(status='passed',url=ARCHIVE.trust_url(architecture),outputSha256=hashlib.sha256(trust.encode()).hexdigest()))])
    if public_descriptor is not None:
        result['publicVerification']=dict(status='passed',anonymous=True,imageDigest=image_digest,
            artifactSha256=public_descriptor['artifactSha256'],descriptorUrl=public_descriptor['url'],
            imageConfigDigest=info['Id'],indexDigest=actual_public_descriptor['digest'],
            descriptor=descriptor(workspace/'public-oci-index.json'))
    if fixture:
        result.update(scope='musl-oci-development-fixture',status='fixture-only',productionQualification=False,
            fixtureType='independent-alpine-distribution-sdk',sourceAdmissionBypassedForDevelopment=True)
        result['userSpaces'][0]['status']='fixture-only'
    (workspace/'report.json').write_bytes(encoded(result))
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    for name in ('native-apk','installed-apk'):
        child=commands.add_parser(name)
        child.add_argument('--build',type=Path,required=True)
        child.add_argument('--arch',choices=tuple(ARCHITECTURES),required=True)
        child.add_argument('--workspace',type=Path,required=True)
        child.add_argument('--public-key',type=Path,required=True)
        child.add_argument('--target-policy',type=Path)
        if name=='native-apk':
            child.add_argument('--public-repository')
    child=commands.add_parser('lifecycle-apk')
    child.add_argument('--build',type=Path,required=True)
    child.add_argument('--upgrade-build',type=Path,required=True)
    child.add_argument('--arch',choices=tuple(ARCHITECTURES),required=True)
    child.add_argument('--public-key',type=Path,required=True)
    child.add_argument('--output',type=Path,required=True)
    child=commands.add_parser('resign-repository')
    child.add_argument('--build',type=Path,required=True)
    child.add_argument('--source-public-key',type=Path,required=True)
    child.add_argument('--private-key',type=Path,required=True)
    child.add_argument('--public-key',type=Path,required=True)
    child.add_argument('--output',type=Path,required=True)
    child=commands.add_parser('native-oci')
    child.add_argument('--build',type=Path,required=True)
    child.add_argument('--arch',choices=tuple(ARCHITECTURES),required=True)
    child.add_argument('--workspace',type=Path,required=True)
    child.add_argument('--image',required=True)
    child.add_argument('--target-policy',type=Path)
    child.add_argument('--public-descriptor',type=Path)
    child.add_argument('--fixture',action='store_true')
    args=parser.parse_args()
    policy=json.loads(args.target_policy.read_bytes()) if getattr(args,'target_policy',None) else []
    if args.command=='native-oci':
        public=json.loads(args.public_descriptor.read_bytes()) if args.public_descriptor else None
        result=native_oci(args.build,args.arch,args.workspace,args.image,policy,public,fixture=args.fixture)
    elif args.command=='resign-repository':
        result=resign_repository(args.build,args.source_public_key,args.output,args.private_key,args.public_key)
        print(json.dumps({'status':'signed-unpublished','packages':len(result['packages'])}))
        return
    elif args.command=='lifecycle-apk':
        result=lifecycle_apk(args.build,args.upgrade_build,args.arch,args.public_key,args.output)
    elif args.command=='native-apk':
        result=native_apk(args.build,args.arch,args.workspace,args.public_key,policy,args.public_repository)
    else:
        result=installed_apk(args.build,args.arch,args.workspace,args.public_key,policy)
    print(json.dumps({'scope':result['scope'],'status':result['status'],'architecture':result['architecture']}))


if __name__=='__main__':
    main()
