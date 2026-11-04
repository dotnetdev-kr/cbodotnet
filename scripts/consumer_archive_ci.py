"""Native read-only build and offline validation of branded consumer archives."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import urllib.request

from consumer_archive import (ARCHITECTURES, BRANDING, REPORT_CHECKS, REPOSITORY, ROOT, WORKFLOW, archive_stem,
    build_archive, descriptor, encoded, fresh_directory, identity, intake, load_contract, ordinary_file,
    payload_summary, require, sdk_tools,verify_wrapper_license)
from release_catalog import get_bytes, validate_release
from distribution_contract import native_dependencies, validate_qualified_producers
from sdk_runtime import audit_core3_http_libraries, smoke_script, validate_host_rid, validate_smoke_output

BASES={
 'ubuntu-22.04':'ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11',
 'ubuntu-24.04':'ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852',
 'debian-13':'debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4'}
USER='cbot-archive-smoke'
INSTALL=Path('/opt/cbodotnet-consumer-validation')


def run(arguments,*,cwd=None,env=None):
    result=subprocess.run(list(map(str,arguments)),cwd=cwd,env=env,text=True,capture_output=True)
    require(result.returncode==0,'Consumer archive command failed: '+str(arguments[0])+'\n'+result.stdout[-9000:]+result.stderr[-9000:])
    return result.stdout


def receive(tag,directory,arch):
    contract=load_contract(); version=tag.removeprefix('sdk-')
    require(tag=='sdk-'+version and version in contract['releases'] and arch in ARCHITECTURES,'Admitted exact SDK source required')
    directory=fresh_directory(directory)
    base=f'https://github.com/{REPOSITORY}/releases/download/{tag}/'
    metadata=get_bytes(base+'release-manifest.json',8*1024**2)
    require(hashlib.sha256(metadata).hexdigest()==contract['releases'][version]['manifestSha256'],'Pinned source manifest changed')
    release_bytes=get_bytes(f'https://api.github.com/repos/{REPOSITORY}/releases/tags/{tag}',8*1024**2,
        token=os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN'),api=True)
    sums=get_bytes(base+'SHA256SUMS',64*1024)
    record=validate_release(json.loads(release_bytes),metadata,sums,REPOSITORY)
    validate_qualified_producers(record,contract['releases'][version]['target'])
    for name,value in [('release.json',release_bytes),('release-manifest.json',metadata),('SHA256SUMS',sums)]:
        (directory/name).write_bytes(value)
    sdk=record['architectures'][arch]['sdk']; destination=directory/sdk['name']
    with urllib.request.urlopen(sdk['url'],timeout=60) as incoming,destination.open('xb') as output:
        digest=hashlib.sha256(); size=0
        for data in iter(lambda:incoming.read(4*1024**2),b''):
            size+=len(data); require(size<=sdk['size'],'SDK download exceeds its qualified size');digest.update(data);output.write(data)
    require(size==sdk['size'] and digest.hexdigest()==sdk['sha256'],'Downloaded SDK differs from canonical qualified bytes')


def source_identity():
    require(os.environ.get('GITHUB_REPOSITORY')==REPOSITORY and os.environ.get('GITHUB_REF')=='refs/heads/main'
        and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch'
        and os.environ.get('GITHUB_WORKFLOW_REF','').startswith(REPOSITORY+'/'+WORKFLOW+'@'),
        'Native archive evidence must originate in the reviewed main distribution workflow')
    result=dict(repository=REPOSITORY,workflow=WORKFLOW,commit=os.environ.get('GITHUB_SHA',''),
        runId=os.environ.get('GITHUB_RUN_ID',''),runAttempt=os.environ.get('GITHUB_RUN_ATTEMPT',''))
    from consumer_archive_release import workflow_identity
    return workflow_identity(result)


def guard(variant,arch):
    require(os.geteuid()==0 and Path('/.dockerenv').is_file(),'A disposable root Docker container is required')
    contract=load_contract(); expected=contract['operatingSystems'][variant]
    values=dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(values['ID'].strip('"')==expected['id'] and values['VERSION_ID'].strip('"')==expected['versionId'],'Archive target OS/version changed')
    require(platform.machine() in ({'x86_64'} if arch=='x64' else {'aarch64','arm64'})
        and run(['dpkg','--print-architecture']).strip()==ARCHITECTURES[arch]['deb'],'Exact native archive architecture required')
    return expected


def prepare(args):
    build=json.loads(ordinary_file(args.workspace/'build/package-build.json').read_bytes()); plan=build['plan']
    guard(args.variant,plan['architecture'])
    env=dict(os.environ,DEBIAN_FRONTEND='noninteractive')
    run(['apt-get','update','-qq'],env=env)
    run(['apt-get','install','-y','--no-install-recommends','python3','util-linux','passwd',
         *(['binutils'] if 'nativeHttpCompatibility' in plan else []),
         *native_dependencies(load_contract(),plan['sdkVersion'],args.variant)],env=env)
    run(['useradd','--create-home','--user-group','--uid','10001',USER])
    INSTALL.mkdir(); sdk_tools().extract_sdk(args.workspace/'build'/build['artifact']['name'],INSTALL/'original')
    provider_state=dict(required=False)
    from legacy_compat import required,PROVIDER_ROOT,tree_inventory,inventory_digest,FINGERPRINT
    if required(plan):
        companion=json.loads((args.workspace/'compat/provider-build.json').read_bytes())
        path=args.workspace/'compat'/companion['companion']['path']
        require(descriptor(path)==dict(name=companion['companion']['path'],size=companion['companion']['size'],sha256=companion['companion']['sha256']),
            'Separate compatibility companion changed')
        sdk_tools().extract_sdk(path,INSTALL/'compatibility')
        source=INSTALL/'compatibility/rootfs'/PROVIDER_ROOT.lstrip('/')
        destination=Path(PROVIDER_ROOT); destination.parent.mkdir(parents=True,exist_ok=True)
        require(not destination.exists(),'Compatibility provider root must be fresh')
        shutil.copytree(source,destination,symlinks=True)
        files=tree_inventory(destination,owners=True)
        provider_state=dict(required=True,providerRoot=PROVIDER_ROOT,architecture=plan['architecture'],variant=args.variant,
            policySha256=companion['policySha256'],signingFingerprint=FINGERPRINT,files=files,treeSha256=inventory_digest(files))
    state=dict(build=build,provider=provider_state)
    if 'nativeHttpCompatibility' in plan:
        import legacy_curl
        from consumer_archive_release import verify_compatibility
        companion,path=verify_compatibility(args.workspace/'native-http-compat/provider-build.json',plan,native_http=True)
        extracted=INSTALL/'native-http-compatibility';sdk_tools().extract_sdk(path,extracted)
        source=extracted/'rootfs'/legacy_curl.PROVIDER_ROOT.lstrip('/')
        destination=Path(legacy_curl.PROVIDER_ROOT);destination.parent.mkdir(parents=True,exist_ok=True)
        require(not destination.exists(),'Native HTTP provider root must be fresh')
        shutil.copytree(source,destination,symlinks=True)
        files=legacy_curl.tree_inventory(destination,owners=True)
        state['nativeHttpProvider']=dict(schemaVersion=1,required=True,providerRoot=legacy_curl.PROVIDER_ROOT,
            architecture=plan['architecture'],variant=args.variant,policySha256=companion['policySha256'],
            signingFingerprint=legacy_curl.FINGERPRINT,files=files,treeSha256=legacy_curl.inventory_digest(files),
            packages=companion['manifest']['packages'],sourcePackages=companion['manifest']['packages'],
            sourceRpmPackages=companion['manifest']['sourcePackages'])
    (args.workspace/(args.variant+'-prepared.json')).write_bytes(encoded(state))


def user_run(arguments,*,cwd=None,extra=None):
    environment=dict(os.environ,HOME='/home/'+USER,DOTNET_CLI_HOME='/home/'+USER,DOTNET_CLI_TELEMETRY_OPTOUT='1',
        DOTNET_NOLOGO='1',DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',DOTNET_CLI_UI_LANGUAGE='en',LC_ALL='C')
    environment.update(extra or {})
    return run(['runuser','-u',USER,'--',*arguments],cwd=cwd or '/home/'+USER,env=environment)


def relocate_tree(source,destination):
    """OverlayFS may reject renaming an otherwise ordinary committed directory."""
    source,destination=Path(source),Path(destination)
    require(source.is_dir() and not source.is_symlink() and not destination.exists() and not destination.is_symlink(),
        'Relocation requires an ordinary source and fresh destination')
    try:source.rename(destination)
    except OSError as error:
        if error.errno!=errno.EXDEV:raise
        before=sdk_tools().snapshot(source)
        shutil.copytree(source,destination,symlinks=True,copy_function=shutil.copy2)
        require(sdk_tools().snapshot(destination)==before,'Cross-device relocation changed consumer bytes, modes or links')
        shutil.rmtree(source)


def installed(args):
    state=json.loads((args.workspace/(args.variant+'-prepared.json')).read_bytes()); build=state['build']; plan=build['plan']
    guard(args.variant,plan['architecture'])
    require({item.name for item in Path('/sys/class/net').iterdir()}=={'lo'},'Actual Docker --network none is mandatory')
    root=INSTALL/'original'/build['directory']
    if build.get('archiveLayoutVersion',1)==2:verify_wrapper_license(root,build)
    from legacy_compat import assert_unchanged,environment
    runtime_env=environment(dict(plan,variant=args.variant))
    provider_before=assert_unchanged(state['provider'])
    native_http_before=None
    if 'nativeHttpCompatibility' in plan:
        import legacy_curl
        runtime_env=legacy_curl.environment(dict(plan,variant=args.variant),base_environment=runtime_env)
        native_http_before=legacy_curl.assert_unchanged(state['nativeHttpProvider'])

    def commands(tree):
        results=[]
        for name in ('dotnet','cbodotnet','cbodotnet-'+'.'.join(plan['sdkVersion'].split('.')[:2])):
            command=tree/name
            result=subprocess.run(['runuser','-u',USER,'--',str(command),'--version'],text=True,capture_output=True,
                env=dict(os.environ,**runtime_env,HOME='/home/'+USER,DOTNET_CLI_HOME='/home/'+USER,
                    DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',DOTNET_CLI_TELEMETRY_OPTOUT='1',DOTNET_NOLOGO='1'))
            require(result.returncode==0 and result.stdout==plan['sdkVersion']+'\n' and result.stderr==BRANDING['displayName']+'\n',
                'Archive alias numeric stdout / branding stderr changed')
            information=json.loads(user_run([command,'--cbodotnet-info']))
            require(all(information[key]==value for key,value in identity(plan).items()) and information['sdkRoot']==str(tree/'payload')
                and information['qualifiedPayloadModified'] is False,'Archive alias selected another source/root')
            if 'nativeHttpCompatibility' in plan:
                require(information.get('nativeHttpCompatibility')==plan['nativeHttpCompatibility'],'Archive alias omitted its native HTTP companion requirement')
            require(user_run([command,'--list-sdks']).splitlines()==[plan['sdkVersion']+' ['+str(tree/'payload/sdk')+']'],
                'Archive alias fell back to another SDK')
            info=user_run([command,'--info']);require(info.startswith(BRANDING['displayName']+'\n'),'Archive host branding absent')
            results.append(dict(command=name,observedHostRid=validate_host_rid(info,plan['sdkVersion'],plan['architecture'],args.variant)))
        return results

    commands(root)
    relocated=INSTALL/'relocated consumer archive'; relocate_tree(root,relocated)
    command_results=commands(relocated)
    payload=relocated/'payload'; tools=sdk_tools()
    observed=tools.snapshot(payload)
    require(payload_summary({key:value for key,value in observed.items() if key not in build['additionalDirectories']})==build['qualifiedPayload'],
        'Relocation changed qualified SDK payload')
    native_http=audit_core3_http_libraries(plan['sdkVersion'],payload,runtime_env,runner=run)
    work='/home/'+USER+'/offline-project'
    output=user_run(['sh','-ec',smoke_script(plan['sdkVersion'],str(payload),USER,cli=str(relocated/'cbodotnet'),workdir=work,runtime_env=runtime_env)])
    functional=validate_smoke_output(output)
    native_curl=None
    if 'nativeHttpCompatibility' in plan:
        from sdk_runtime import forced_curl_script,validate_forced_curl_output
        curl_root=plan['nativeHttpCompatibility']['root']
        forced=user_run(['sh','-ec',forced_curl_script(plan['sdkVersion'],str(payload),USER,
            cli=str(relocated/'cbodotnet'),workdir='/home/'+USER+'/native-curl-project',
            runtime_env=runtime_env,curl_root=curl_root,user_id=10001)])
        native_curl=validate_forced_curl_output(forced,plan['sdkVersion'],str(payload),curl_root,10001,plan['architecture'])
    require(tools.snapshot(payload)==observed,'Non-root runtime execution changed the SDK payload')
    provider_after=assert_unchanged(state['provider']);require(provider_before==provider_after,'SDK modified the separate compatibility provider')
    wrapper_license=verify_wrapper_license(relocated,build) if build.get('archiveLayoutVersion',1)==2 else None
    source=tools.snapshot(payload)
    require(all(source.get(name)==observed.get(name) and source[name][0]=='file'
        for name in plan['licensePaths']),'Original license/notice changed')
    report=dict(variant=args.variant,status='passed',architecture=plan['architecture'],native=True,networkForBuild='none',
        checks=dict.fromkeys(REPORT_CHECKS,'passed'),functionalChecks=functional,commands=command_results,
        nativeHttpLibraries=native_http,
        compatibility=provider_after,dependencies={name:run(['dpkg-query','-W','-f=${Version}',name]).strip()
            for name in native_dependencies(load_contract(),plan['sdkVersion'],args.variant)})
    if wrapper_license:report['wrapperLicense']=wrapper_license
    if native_http_before is not None:
        after=legacy_curl.assert_unchanged(state['nativeHttpProvider'])
        require(after==native_http_before,'SDK modified the separate native HTTP provider')
        report['nativeHttpCompatibilityProvider']=[dict(after,required=True,
            sourcePackages=state['nativeHttpProvider']['sourcePackages'],sourceRpmPackages=state['nativeHttpProvider']['sourceRpmPackages'])]
        report['nativeCurlHandler']=native_curl
    (args.workspace/(args.variant+'-report.json')).write_bytes(encoded(report))


def native(args):
    require(os.geteuid()!=0 and platform.machine() in ({'x86_64'} if args.arch=='x64' else {'aarch64','arm64'}),'A matching non-root native producer is required')
    source=source_identity(); workspace=fresh_directory(args.workspace)
    receive(args.tag,workspace/'inputs',args.arch)
    build=build_archive(workspace/'inputs',args.arch,args.revision,workspace/'build'); plan=build['plan']
    from legacy_compat import required,build_provider
    companion=None
    if required(plan): companion=build_provider(args.arch,workspace/'compat',cache=workspace/'compat-cache')
    native_http_companion=None
    if 'nativeHttpCompatibility' in plan:
        import legacy_curl
        native_http_companion=legacy_curl.build_provider(args.arch,workspace/'native-http-compat',cache=workspace/'native-http-cache')
    spaces=[]
    for variant in plan['validatedUserSpaces']:
        require(variant in BASES,'A pinned native archive user-space image is required')
        cid=None; snapshot=None
        try:
            cid=run(['docker','create','-v',f'{ROOT}:/repo:ro','-v',f'{workspace}:/delivery',BASES[variant],
                'bash','-ec','apt-get update -qq && apt-get install -y --no-install-recommends python3 && '
                f'python3 /repo/scripts/consumer-archive-ci.py prepare --workspace /delivery --variant {variant}']).strip()
            run(['docker','start','--attach',cid]);require(json.loads(run(['docker','inspect',cid]))[0]['State']['ExitCode']==0,'Archive preparation container failed')
            snapshot=run(['docker','commit',cid]).strip()
            run(['docker','run','--rm','--network','none','-v',f'{ROOT}:/repo:ro','-v',f'{workspace}:/delivery',snapshot,
                'python3','/repo/scripts/consumer-archive-ci.py','installed','--workspace','/delivery','--variant',variant])
        finally:
            if cid:subprocess.run(['docker','rm','--force',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if snapshot:subprocess.run(['docker','image','rm',snapshot],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        report=json.loads((workspace/(variant+'-report.json')).read_bytes());report['baseImage']=BASES[variant];spaces.append(report)
    result=dict(schemaVersion=1,scope='consumer-archive-installation',status='passed',architecture=args.arch,
        identity=identity(plan),artifact=build['artifact'],commands=build['commands'],qualifiedPayload=build['qualifiedPayload'],
        orchestration=source,networkForBuild='none',checks=dict.fromkeys(REPORT_CHECKS,'passed'),userSpaces=spaces,
        compatibility=dict(required=False) if companion is None else dict(required=True,policySha256=companion['policySha256'],
            companion=companion['companion'],manifest=companion['manifest']))
    if build.get('archiveLayoutVersion',1)==2:result['wrapperLicense']=build['wrapperLicense']
    if native_http_companion is not None:
        result['nativeHttpCompatibility']=dict(required=True,policySha256=native_http_companion['policySha256'],
            companion=native_http_companion['companion'],manifest=native_http_companion['manifest'])
    (workspace/'report.json').write_bytes(encoded(result))
    # Transport only source inputs, the compressed consumer archive and exact reports.
    shutil.rmtree(workspace/'build'/build['directory'])
    if companion:
        shutil.rmtree(workspace/'compat/rootfs');shutil.rmtree(workspace/'compat-cache')
    if native_http_companion is not None:
        shutil.rmtree(workspace/'native-http-compat/rootfs');shutil.rmtree(workspace/'native-http-cache')
    print(json.dumps(dict(status='passed',workspace=str(workspace),architecture=args.arch,sdkVersion=plan['sdkVersion'])))


def main():
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest='command',required=True)
    command=commands.add_parser('native');command.add_argument('--tag',required=True);command.add_argument('--revision',type=int,default=1)
    command.add_argument('--arch',choices=tuple(ARCHITECTURES),required=True);command.add_argument('--workspace',type=Path,required=True)
    for name in ('prepare','installed'):
        command=commands.add_parser(name);command.add_argument('--workspace',type=Path,required=True);command.add_argument('--variant',choices=tuple(BASES),required=True)
    args=parser.parse_args();{'native':native,'prepare':prepare,'installed':installed}[args.command](args)


if __name__=='__main__':main()
