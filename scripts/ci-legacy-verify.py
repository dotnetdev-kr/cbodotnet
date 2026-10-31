#!/usr/bin/env python3
"""Verify fresh legacy SDKs with explicit, separate OpenSSL/ICU dependencies.

Compatibility libraries are exported from this run's inspected Focal image,
never inserted into an SDK archive. Core 3.x additionally selects ICU66 on
Debian 13. These are controlled dependency tests, not stock OpenSSL3-only OS
compatibility claims. All dependency files, licenses and contracts are retained
under reports so final collection inventories their exact bytes.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

FAMILIES = {'net5':('5.0.214','net5.0'), 'core31':('3.1.426','netcoreapp3.1'),
            'core30':('3.0.103','netcoreapp3.0')}
FOCAL_BASE = 'mcr.microsoft.com/dotnet/sdk@sha256:a4028735b2ed1209c9116cebc74ae1c2fb27ea7d24b1be3f495fee0bac27dd52'
USERLANDS = [('ubuntu22','ubuntu','22.04','libicu70','libssl3'),
             ('ubuntu24','ubuntu','24.04','libicu74','libssl3t64'),
             ('debian13','debian','13','libicu76','libssl3t64')]
FUNCTIONS = {'consoleDllExecution','consoleApphostExecution','rsaSha256SignAndVerify',
             'cryptographicRandomBytes','frFrDecimalFormatting','aspNetCoreLoopbackHttp'}


def require(value, message):
    if not value: raise ValueError(message)


def ordinary(path, exists=False):
    require(path.is_absolute() and path != Path('/') and '..' not in path.parts
            and not any(p.is_symlink() for p in [path]+list(path.parents)), 'An ordinary absolute path is required: '+str(path))
    require(not exists or path.exists(), 'Missing input: '+str(path))
    return path


def fingerprint(path):
    ordinary(path, True); require(path.is_file(), 'A regular file is required')
    before=path.stat(); hashes={name:hashlib.new(name) for name in ['sha256','sha512']}
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):
            for value in hashes.values(): value.update(block)
    after=path.stat()
    require((before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns),'Input changed during hashing')
    return dict(bytes=after.st_size,**{name:value.hexdigest() for name,value in hashes.items()})


def write(path, value):
    ordinary(path); path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8') as output: json.dump(value,output,indent=2); output.write('\n')


def load(path):
    ordinary(path,True); require(path.stat().st_size < 128*1024*1024,'Oversized JSON control')
    return json.loads(path.read_text(encoding='utf-8-sig'))


def expected_rid(family, name):
    return 'ubuntu.22.04-arm64' if family=='core31' and name=='ubuntu22' else 'linux-arm64'


def manifest_reference(row, distribution):
    require(row.get('Architecture')=='arm64' and row.get('Os')=='linux','Native Linux ARM64 image required')
    digest=row.get('Digest')
    require(isinstance(digest,str) and re.fullmatch(r'sha256:[a-f0-9]{64}',digest),'An inspected manifest digest is required')
    reference='docker.io/library/'+distribution+'@'+digest
    require(isinstance(row.get('RepoDigests'),list) and row['RepoDigests'].count(reference)==1,
            'The inspected manifest needs one exact repository binding')
    return reference


def check_verification(family,name,result,archive):
    sdk,framework=FAMILIES[family]
    require(result['verificationStatus']=='passed' and result['sdkVersion']==sdk and result['framework']==framework
            and result['reportedRid']==expected_rid(family,name) and result['functionalChecks']==dict.fromkeys(FUNCTIONS,'passed')
            and result['archive']['sha256']==archive['sha256'] and result['archive']['sizeBytes']==archive['bytes']
            and result['archive']['sdkContentMatched'] is True,'Native SDK identity/functionality/archive checks failed: '+name)
    abi=result['abi']; version=lambda value:tuple(map(int,value.split('.')))
    require(abi['elfFileCount']>0 and abi['machines']=={'AArch64':abi['elfFileCount']}
            and abi['glibcCeilingPassed'] is True and abi['glibcCeiling']=='2.23' and not abi['symbolicGlibcRequirements']
            and version(abi['maximumRequiredVersions']['GLIBC'])<=version('2.23')
            and version(abi['maximumRequiredVersions']['GLIBCXX'])<=version('3.4.21')
            and version(abi['maximumRequiredVersions']['CXXABI'])<=version('1.3.7'),'Native SDK ABI policy failed: '+name)


def internal_export(args):
    require(platform.machine()=='aarch64' and platform.system()=='Linux','Native ARM64 exporter required')
    require(re.fullmatch(r'(sha256:)?[a-f0-9]{64}',args.producer_image_id),'Invalid producer image ID')
    name='export-net5-verification-compat.py' if args.kind=='openssl11' else 'export-core31-verification-icu.py'
    helper=ordinary(args.project_root/'scripts'/name,True)
    # Parameterize only the existing helpers' exact image/ownership pins. Their
    # OS, package, ELF, SONAME, config, inventory and byte checks stay intact.
    namespace={'__name__':'ci_dependency_export','__file__':str(helper)}
    exec(compile(helper.read_text(),str(helper),'exec'),namespace)
    image=args.producer_image_id.replace('sha256:','',1)
    namespace['IMAGE']=image
    namespace['OWNER']='cbodotnet-ci-legacy-'+args.kind+'-v1'
    function=namespace['inspect_inputs'] if args.kind=='openssl11' else namespace['inspect']
    contract=function(args.image_inspect,args.consumer_directory)
    require(contract['producerImageId']==image,'Exporter image binding differs')
    require(not args.destination.exists() and not args.destination.is_symlink(),'Compatibility export must be fresh')
    result=namespace['export'](args.destination,contract)
    write(args.report,dict(schemaVersion=1,status='passed',kind=args.kind,result=result,inputContract=contract,
          contractFingerprint=fingerprint(args.destination/'compatibility-inputs.json'),
          exporter=dict(path=str(helper),**fingerprint(helper)),
          adapter={'producerImageId':image,'owner':namespace['OWNER'],
                   'scope':'Only fixed helper image/owner globals are parameterized to this run\'s actual inspected image; all original dependency guards execute.'},
          sdkArchiveModified=False))


def internal_verify(args):
    require(platform.machine()=='aarch64' and os.getuid()>0,'Native nonroot verification is required')
    release={}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key,value=line.split('=',1); release[key]=value.strip('"')
    packages=subprocess.check_output(['dpkg-query','-W','-f=${binary:Package}\t${Version}\n',
                 args.icu_package,args.ssl_package,'libc6','libstdc++6','zlib1g','libgssapi-krb5-2'],universal_newlines=True)
    environment={key:os.environ.get(key) for key in ['LD_LIBRARY_PATH','OPENSSL_CONF','CLR_ICU_VERSION_OVERRIDE',
                 'DOTNET_SYSTEM_GLOBALIZATION_INVARIANT','DOTNET_ROOT','DOTNET_EnableDiagnostics','COMPlus_EnableDiagnostics']}
    write(args.userland_report,dict(schemaVersion=1,imageId=args.image_id,architecture=platform.machine(),uid=os.getuid(),gid=os.getgid(),
          osRelease={'ID':release['ID'],'VERSION_ID':release['VERSION_ID']},
          installedPackages=dict(line.split('\t',1) for line in packages.splitlines()),consumerEnvironment=environment))
    sdk,framework=FAMILIES[args.family]
    command=['bash',str(args.verifier),'--archive',str(args.archive),'--output-dir',str(args.report_dir),
             '--expected-version',sdk,'--expected-rid',expected_rid(args.family,args.name),
             '--framework',framework,'--max-glibc','2.23']
    os.execvp(command[0],command)


class Verification:
    def __init__(self,args):
        self.args=args; self.family=args.family; self.sdk,self.framework=FAMILIES[self.family]
        self.workspace=ordinary(args.workspace,True); self.output=ordinary(args.output_dir,True)
        self.project=ordinary(args.project_root,True); self.reports=self.output/'reports'
        self.frozen=self.reports/'ci-inputs/project'; self.scripts=self.frozen/'scripts'
        self.state=load(self.workspace/'ci-legacy-state.json')
        require(self.state['family']==self.family and self.state['workspace']==str(self.workspace)
                and self.state['output']==str(self.output) and self.state['sdkVersion']==self.sdk,'Wrong legacy CI run state')
        require(platform.machine()=='aarch64' and platform.system()=='Linux' and os.getuid()>0,'Native nonroot host required')
        self.uid=os.getuid(); self.gid=os.getgid(); self.source=self.workspace/'source'; self.candidate=self.workspace/'candidate'
        self.engine=['sudo','-n','--','podman','--cgroup-manager=cgroupfs','--events-backend=file']
        cpus=sorted(os.sched_getaffinity(0)); require(len(cpus)>=2,'Two allowed CPUs required'); self.cpus=','.join(map(str,cpus[:2]))
        self.summary=self.reports/'ci/legacy-verification.json'
        require(not self.summary.exists() and not self.summary.is_symlink(),'Verification receipt must be fresh')
        self.input_root=self.reports/'verification-inputs'; self.input_root.mkdir()
        self.command_file=self.reports/'ci/legacy-verification-commands.jsonl'
        self.log_file=self.reports/'ci/legacy-verification.log'
        self.commands=[]; self.log=self.log_file.open('x',encoding='utf-8'); self.journal=self.command_file.open('x',encoding='utf-8')

    def record(self,path): return dict(path=path.relative_to(self.output).as_posix(),**fingerprint(path))

    def run(self,args,capture=False):
        args=list(map(str,args)); self.commands.append(args); self.journal.write(json.dumps(args)+'\n'); self.journal.flush()
        print('Running: '+json.dumps(args),flush=True); self.log.write('Running: '+json.dumps(args)+'\n'); self.log.flush()
        process=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,universal_newlines=True)
        text=[]
        for line in process.stdout:
            self.log.write(line); self.log.flush()
            if capture: text.append(line)
            else: print(line,end='',flush=True)
        require(process.wait()==0,'Verification command failed: '+args[0])
        return ''.join(text)

    def inspect(self,reference,path):
        text=self.run(self.engine+['image','inspect',reference],capture=True); rows=json.loads(text)
        require(len(rows)==1 and rows[0]['Architecture']=='arm64' and rows[0]['Os']=='linux','One native ARM64 image required')
        require(re.fullmatch(r'(sha256:)?[a-f0-9]{64}',rows[0]['Id']),'Invalid immutable image ID')
        write(path,rows); return rows[0]

    def base_options(self,image,network='none'):
        return self.engine+['run','--rm','--network='+network,'--user',str(self.uid)+':'+str(self.gid),
            '--security-opt','seccomp='+str(self.workspace/'inputs/seccomp.json'),
            '--env','LANG=C.UTF-8','--env','LC_ALL=C.UTF-8','--env','DOTNET_CLI_TELEMETRY_OPTOUT=1',
            '--env','DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1','--env','DOTNET_GENERATE_ASPNET_CERTIFICATE=false',
            '--volume',str(self.workspace)+':'+str(self.workspace)+':ro',
            '--volume',str(self.project)+':'+str(self.project)+':ro',
            '--volume',str(self.output)+':'+str(self.output),
            '--volume',str(self.frozen)+':'+str(self.frozen)+':ro']

    def producer(self):
        report=self.input_root/'producer-image.json'
        if self.family!='core30':
            row=self.inspect(self.state['imageId'],report)
            require(row['Id'].replace('sha256:','',1)==self.state['imageId'].replace('sha256:','',1),'Fresh builder identity changed')
            return row
        # Bionic's Core3.0 builder cannot provide ICU66. This separate Focal
        # image supplies verification dependencies only; its SDK is never run.
        text='FROM '+FOCAL_BASE+'\nRUN apt-get update && apt-get install -y --no-install-recommends python3 binutils libssl1.1 openssl libicu66 ca-certificates && apt-get clean\n'
        recipe=self.input_root/'focal-compat.Containerfile'; recipe.write_text(text)
        tag='localhost/cbodotnet-ci-focal-compat:'+self.family+'-'+self.state['runId']+'-'+self.state['runAttempt']
        self.run(self.engine+['pull',FOCAL_BASE]); self.inspect(FOCAL_BASE,self.input_root/'focal-base-image.json')
        with tempfile.TemporaryDirectory(prefix='cbodotnet-focal-compat.') as context:
            shutil.copyfile(recipe,Path(context)/'Containerfile')
            self.run(self.engine+['build','--network=host','--file',Path(context)/'Containerfile','--tag',tag,context])
        return self.inspect(tag,report)

    def export(self,kind,image):
        destination=self.input_root/kind; report=self.input_root/(kind+'-export.json')
        consumer='/verification-compat' if kind=='openssl11' else '/verification-icu'
        args=self.base_options(image['Id'])+['--volume',str(self.input_root)+':'+str(self.input_root),
             image['Id'],'python3',str(self.scripts/'ci-legacy-verify.py'),'__export','--kind',kind,
             '--project-root',self.frozen,'--producer-image-id',image['Id'],'--image-inspect',self.input_root/'producer-image.json',
             '--destination',destination,'--report',report,'--consumer-directory',consumer]
        self.run(args); data=load(report); require(data['status']=='passed','Dependency export failed')
        # Validate every emitted input and refuse unbound extra members before use.
        contract=load(destination/'compatibility-inputs.json'); expected={row['path'] for row in contract['files']}|{'owner.json','compatibility-inputs.json','verification-env.sh'}
        actual={path.relative_to(destination).as_posix() for path in destination.rglob('*') if path.is_file()}
        require(actual==expected and not any(path.is_symlink() for path in destination.rglob('*')),'Exported dependency membership differs')
        for row in contract['files']:
            value=fingerprint(destination/row['path'])
            require(value['bytes']==row['bytes'] and value['sha256']==row['sha256'],'Exported compatibility library changed')
        return dict(exportReport=self.record(report),contract=self.record(destination/'compatibility-inputs.json'),
                    owner=self.record(destination/'owner.json'),files=[self.record(destination/name) for name in sorted(expected)],
                    producerImageId=image['Id'],consumerDirectory=consumer)

    def execute(self):
        profile=self.reports/'ci/effective-profile.json'; require(profile.is_file(),'Current-run local framework origin proof must precede verification')
        require(not self.candidate.exists(),'Candidate collection must use a fresh directory')
        self.run([sys.executable,self.scripts/'collect-artifacts.py','--source-dir',self.source,'--profile',profile,
                  '--output-dir',self.candidate,'--reports-dir',self.reports,'--build-image-id',self.state['imageId'],
                  '--build-revision',self.state['buildRevision']])
        candidate=load(self.candidate/'build-manifest.json'); sdk=self.candidate/candidate['sdkArchive']['path']
        original=fingerprint(sdk); require(original['sha256']==candidate['sdkArchive']['sha256'],'Candidate SDK differs')
        shutil.copyfile(self.candidate/'build-manifest.json',self.reports/'ci/candidate-build-manifest.json')
        producer=self.producer(); exports={'openssl11':self.export('openssl11',producer)}
        if self.family!='net5': exports['icu66']=self.export('icu66',producer)
        userlands={}
        for name,distribution,version,icu,ssl in USERLANDS:
            reference='docker.io/library/'+distribution+':'+version; self.run(self.engine+['pull',reference])
            base=self.inspect(reference,self.reports/'ci'/(name+'-base-image.json')); pinned=manifest_reference(base,distribution)
            tag='localhost/cbodotnet-ci-'+self.family+'-verify-'+name+':'+self.state['runId']+'-'+self.state['runAttempt']
            self.run(self.engine+['build','--network=host','--file',self.frozen/'containers/verify-net10.Containerfile',
                 '--build-arg','BASE_IMAGE='+pinned,'--build-arg','ICU_PACKAGE='+icu,'--build-arg','SSL_PACKAGE='+ssl,'--tag',tag,self.frozen/'containers'])
            image=self.inspect(tag,self.reports/'ci'/(name+'-verification-image.json'))
            environment={'LD_LIBRARY_PATH':'/verification-compat/lib','OPENSSL_CONF':'/verification-compat/openssl.cnf'}
            selected=['openssl11']
            if self.family!='net5' and name=='debian13':
                selected.append('icu66'); environment['LD_LIBRARY_PATH']+=':/verification-icu/lib'; environment['CLR_ICU_VERSION_OVERRIDE']='66'
            args=self.base_options(image['Id'])
            for kind in selected: args+=['--volume',str(self.input_root/kind)+':'+exports[kind]['consumerDirectory']+':ro']
            for key,value in environment.items(): args+=['--env',key+'='+value]
            args+=['--volume',str(self.candidate)+':/artifacts:ro','--workdir','/tmp',image['Id'],'taskset','--cpu-list',self.cpus,
                   'python3',str(self.scripts/'ci-legacy-verify.py'),'__verify','--family',self.family,'--name',name,
                   '--image-id',image['Id'],'--icu-package',icu,'--ssl-package',ssl,
                   '--userland-report',self.reports/'ci'/(name+'-userland.json'),'--verifier',self.scripts/'verify-sdk.sh',
                   '--archive','/artifacts/'+sdk.name,'--report-dir',self.reports/('verify-'+name)]
            self.run(args)
            path=self.reports/('verify-'+name)/'verification.json'; result=load(path); metadata=load(self.reports/'ci'/(name+'-userland.json'))
            check_verification(self.family,name,result,original)
            require(metadata['osRelease']=={'ID':distribution,'VERSION_ID':version} and metadata['architecture']=='aarch64'
                    and metadata['imageId']==image['Id'] and metadata['uid']==self.uid,'Actual user-space identity differs')
            for key,value in environment.items(): require(metadata['consumerEnvironment'][key]==value,'Compatibility selection differs')
            for key in ['DOTNET_SYSTEM_GLOBALIZATION_INVARIANT','DOTNET_ROOT','DOTNET_EnableDiagnostics','COMPlus_EnableDiagnostics']:
                require(metadata['consumerEnvironment'][key] is None,'Unreviewed native/runtime override: '+key)
            userlands[name]=dict(verification=self.record(path),userland=self.record(self.reports/'ci'/(name+'-userland.json')),
                 imageId=image['Id'],imageInspection=self.record(self.reports/'ci'/(name+'-verification-image.json')),
                 baseInspection=self.record(self.reports/'ci'/(name+'-base-image.json')),baseManifest=pinned,
                 osRelease=metadata['osRelease'],installedPackages=metadata['installedPackages'],consumerEnvironment=environment,
                 compatibilityInputs=selected,reportedRid=result['reportedRid'],sdkArchiveSha256=original['sha256'])
        require(fingerprint(sdk)==original,'Candidate SDK changed during verification')
        self.log.flush(); self.journal.flush()
        write(self.summary,dict(schemaVersion=1,status='passed',family=self.family,sdkVersion=self.sdk,
             sdkArchive=dict(path=sdk.name,**original),sdkArchiveUnchanged=True,producerImage=self.record(self.input_root/'producer-image.json'),
             compatibilityExports=exports,userlands=userlands,commands=self.commands,commandJournal=self.record(self.command_file),
             log=self.record(self.log_file),
             scope='Actual current-run SDK with separate read-only OpenSSL1.1 dependencies on three modern native Linux user spaces. Core3 Debian additionally uses real ICU66; no invariant globalization, diagnostic disable, TLS bypass, source substitution or SDK repacking. This does not establish stock OpenSSL3-only compatibility.'))


def main():
    if len(sys.argv)>1 and sys.argv[1]=='__export':
        parser=argparse.ArgumentParser(); parser.add_argument('--kind',choices=['openssl11','icu66'],required=True)
        for name in ['project-root','image-inspect','destination','report']: parser.add_argument('--'+name,type=Path,required=True)
        parser.add_argument('--producer-image-id',required=True); parser.add_argument('--consumer-directory',required=True)
        internal_export(parser.parse_args(sys.argv[2:])); return 0
    if len(sys.argv)>1 and sys.argv[1]=='__verify':
        parser=argparse.ArgumentParser(); parser.add_argument('--family',choices=FAMILIES,required=True)
        for name in ['name','image-id','icu-package','ssl-package']: parser.add_argument('--'+name,required=True)
        for name in ['userland-report','verifier','archive','report-dir']: parser.add_argument('--'+name,type=Path,required=True)
        internal_verify(parser.parse_args(sys.argv[2:])); return 0
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--family',choices=FAMILIES,required=True)
    for name in ['workspace','output-dir','project-root']: parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args(); task=Verification(args)
    try: task.execute()
    finally: task.log.close(); task.journal.close()
    return 0


if __name__=='__main__':
    try: raise SystemExit(main())
    except (OSError,ValueError,KeyError,TypeError,subprocess.CalledProcessError) as error: raise SystemExit('error: '+str(error))
