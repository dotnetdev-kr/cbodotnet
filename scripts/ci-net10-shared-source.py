#!/usr/bin/env python3
"""Retain matching full VMR sources for .NET10's reused shared frameworks.

The selected 4xx VMR builds SDK components while consuming the public 1xx
shared-framework inputs. Their separate source checkout is not built here.
Both produced SDK shared .version markers must identify that exact checkout
before source roots are declared for packaging.
"""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import sys
import tarfile

sys.dont_write_bytecode = True

REPOSITORY='https://github.com/dotnet/dotnet'
SDK='10.0.403'
MAIN='5a2162bea6845eabc1fc721624a43568c65db3b1'
SHARED='0427b9abbead3fa64c6655eb4290c537397131fa'
ROLE='source-for-reused-shared-input'
ARCH_SPEC=importlib.util.spec_from_file_location('ci_arch_shared',Path(__file__).with_name('ci_arch.py'))
ARCH=importlib.util.module_from_spec(ARCH_SPEC); ARCH_SPEC.loader.exec_module(ARCH)


def require(value,message):
    if not value: raise ValueError(message)


def ordinary(path,exists=False):
    require(path.is_absolute() and path!=Path('/') and '..' not in path.parts
            and not any(p.is_symlink() for p in [path,*path.parents]),'An ordinary absolute path is required: '+str(path))
    require(not exists or path.exists(),'Missing input: '+str(path))
    return path


def fingerprint(path):
    ordinary(path,True); require(path.is_file(),'A regular input file is required')
    before=path.stat(); hashes={name:hashlib.new(name) for name in ['sha256','sha512']}
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):
            for value in hashes.values(): value.update(block)
    after=path.stat()
    require((before.st_size,before.st_mtime_ns)==(after.st_size,after.st_mtime_ns),'Source input changed during hashing')
    return dict(bytes=after.st_size,**{name:value.hexdigest() for name,value in hashes.items()})


def load(path): return json.loads(ordinary(path,True).read_text(encoding='utf-8-sig'))


def write(path,value):
    ordinary(path); path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x',encoding='utf-8') as out: json.dump(value,out,indent=2); out.write('\n')


def selected(profile,arch='arm64'):
    identity=ARCH.get_arch(arch)
    require(profile.get('sdkVersion')==SDK and profile.get('source',{}).get('repository')==REPOSITORY
            and profile['source'].get('commit')==MAIN and profile.get('target',{}).get('rid')==identity['rid']
            and profile.get('host',{}).get('architecture')==arch
            and profile.get('build',{}).get('sourceOnly') is False,'Only the pinned ordinary .NET10 selected-architecture profile is supported')
    require(profile.get('upstreamInputs',{}).get('sharedVmrCommit')==SHARED
            and profile['upstreamInputs'].get('runtime')=='10.0.14','Unexpected reused-framework source pin/version')
    return profile['upstreamInputs']['sharedVmrCommit']


def git(root,*args):
    return subprocess.check_output(['git','--no-optional-locks','-C',str(root),*args],text=True).strip()


def checkout_identity(root,expected):
    ordinary(root,True)
    require(root.is_dir() and git(root,'rev-parse','--show-toplevel')==str(root),'Unexpected Git worktree root')
    require(git(root,'rev-parse','HEAD')==expected,'Shared source checkout pin changed')
    require(not git(root,'status','--porcelain','--untracked-files=all','--ignored=matching'),'The shared source checkout must remain pristine')
    submodules=[]
    pending=[(root,expected)]; visited=set()
    while pending:
        current,pin=pending.pop()
        require(current not in visited and len(visited)<1024,'Duplicate/excessive nested Gitlink graph')
        visited.add(current)
        require(git(current,'rev-parse','--show-toplevel')==str(current) and git(current,'rev-parse','HEAD')==pin,
                'A nested source consumer does not match its pinned Gitlink')
        require(not git(current,'status','--porcelain','--untracked-files=all','--ignored=matching'),'A nested source consumer is dirty')
        if current!=root:
            submodules.append({'path':current.relative_to(root).as_posix(),'commit':pin,
                               'tree':git(current,'rev-parse','HEAD^{tree}'),'pristine':True})
        for entry in git(current,'ls-tree','-r','-z','HEAD').split('\0'):
            if not entry: continue
            metadata,name=entry.split('\t',1)
            mode,kind,commit=metadata.split()
            if mode!='160000': continue
            value=PurePosixPath(name)
            require(not value.is_absolute() and '..' not in value.parts and value.as_posix()==name,'Unsafe Gitlink source path')
            child=current.joinpath(*value.parts); ordinary(child,True)
            pending.append((child,commit))
    for relative in ['src/runtime','src/aspnetcore']:
        component=ordinary(root/relative,True)
        require(component.is_dir() and any(component.iterdir()),'Required reused-framework source tree is absent: '+relative)
    return dict(repository=REPOSITORY,commit=expected,tree=git(root,'rev-parse','HEAD^{tree}'),pristine=True,
                componentPaths={'runtime':'src/runtime','aspnetcore':'src/aspnetcore'},submodules=sorted(submodules,key=lambda x:x['path']))


def prepare(args):
    pin=selected(load(args.profile),getattr(args,'arch','arm64')); ordinary(args.destination)
    require(not args.destination.exists(),'Shared sources require a fresh checkout path')
    require(not args.report.exists() and not args.report.is_symlink(),'Source checkout report must be new')
    args.destination.parent.mkdir(parents=True,exist_ok=True)
    commands=[['git','init',str(args.destination)],
              ['git','-C',str(args.destination),'remote','add','origin',REPOSITORY],
              ['git','-C',str(args.destination),'fetch','--no-tags','--depth','1','origin',pin],
              ['git','-C',str(args.destination),'checkout','--detach','FETCH_HEAD'],
              ['git','-C',str(args.destination),'submodule','update','--init','--recursive','--depth','1']]
    for command in commands:
        print('Running: '+json.dumps(command),flush=True); subprocess.run(command,check=True)
    identity=checkout_identity(args.destination,pin)
    write(args.report,dict(schemaVersion=1,status='passed',role=ROLE,checkoutDirectory=str(args.destination),
          recordedAtUtc=dt.datetime.now(dt.timezone.utc).isoformat(),profile=fingerprint(args.profile),commands=commands,
          **identity,scope='Full matching VMR source checkout for reused public shared-framework inputs; no build or local-origin claim for these inputs.'))


def archive_markers(archive,profile,arch='arm64'):
    pin=selected(profile,arch); version=profile['upstreamInputs']['runtime']
    wanted={'shared/'+framework+'/'+version+'/.version':framework for framework in ['Microsoft.NETCore.App','Microsoft.AspNetCore.App']}
    found={}
    with tarfile.open(archive,'r:gz') as stream:
        for member in stream:
            name=posixpath.normpath(member.name)
            require(not member.name.startswith('/') and name!='..' and not name.startswith('../'),'Unsafe SDK archive member')
            if name not in wanted: continue
            require(name not in found and (member.isfile() or member.islnk()),'Duplicate/nonregular shared-framework marker')
            require(member.size<=4096,'Oversized shared-framework version marker')
            data=stream.extractfile(member).read(4097)
            require(len(data)<=4096,'Oversized linked shared-framework marker')
            lines=data.decode('utf-8-sig').strip().splitlines()
            require(lines==[pin,version],'SDK shared-framework marker does not match the declared reused source pin: '+name)
            found[name]=dict(path=name,framework=wanted[name],commit=lines[0],runtimeVersion=lines[1],bytes=len(data),
                             sha256=hashlib.sha256(data).hexdigest(),sha512=hashlib.sha512(data).hexdigest())
    require(set(found)==set(wanted),'Both actual SDK shared-framework .version markers are required')
    return [found[name] for name in sorted(found)]


def bind(args):
    arch=getattr(args,'arch','arm64'); identity=ARCH.get_arch(arch)
    profile=load(args.profile); pin=selected(profile,arch)
    require(git(args.source_dir,'rev-parse','HEAD')==MAIN,'The current SDK VMR source pin changed')
    identity=checkout_identity(args.shared_source_dir,pin)
    preparation=load(args.prepare_report)
    for key in ['repository','commit','tree','pristine','componentPaths','submodules']:
        require(preparation.get(key)==identity[key],'The retained shared-source preparation differs: '+key)
    require(preparation['role']==ROLE and preparation['checkoutDirectory']==str(args.shared_source_dir),'Wrong retained shared-source checkout')
    require(preparation['profile']==fingerprint(args.profile),'The selected profile changed after shared-source acquisition')
    spec=importlib.util.spec_from_file_location('ci_shared_collector',Path(__file__).with_name('collect-artifacts.py'))
    collector=importlib.util.module_from_spec(spec); spec.loader.exec_module(collector)
    archive,candidates,_=collector.select_sdk(args.source_dir,SDK,identity['rid'],False)
    before=fingerprint(archive); markers=archive_markers(archive,profile,arch)
    require(fingerprint(archive)==before,'Produced SDK archive changed while binding source markers')
    roots={'schemaVersion':1,'roots':[
        {'name':'vmr','path':str(args.source_dir),'kind':'git','expectedCommit':MAIN,'role':'built-sdk-vmr-source'},
        {'name':'shared-vmr','path':str(args.shared_source_dir),'kind':'git','expectedCommit':pin,'role':ROLE}]}
    write(args.roots_output,roots)
    write(args.report,dict(schemaVersion=1,status='passed',sdkVersion=SDK,sharedVmrCommit=pin,role=ROLE,
          sourceCommit=MAIN,sharedSource=identity,prepareReport=dict(path=str(args.prepare_report),**fingerprint(args.prepare_report)),
          sdkArchive=dict(upstreamPath=archive.relative_to(args.source_dir).as_posix(),**before),sharedMarkers=markers,
          scope='Both actual produced SDK shared-framework markers identify this separately retained full source tree. Shared runtime binaries remain reused public upstream inputs; no rebuild claim.'))


def main():
    parser=argparse.ArgumentParser(description=__doc__); commands=parser.add_subparsers(dest='action',required=True)
    prepare_parser=commands.add_parser('prepare'); prepare_parser.add_argument('--profile',type=Path,required=True)
    prepare_parser.add_argument('--arch',choices=('arm64','x64'),default='arm64')
    prepare_parser.add_argument('--destination',type=Path,required=True); prepare_parser.add_argument('--report',type=Path,required=True)
    bind_parser=commands.add_parser('bind')
    bind_parser.add_argument('--arch',choices=('arm64','x64'),default='arm64')
    for name in ['profile','source-dir','shared-source-dir','prepare-report','roots-output','report']:
        bind_parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    for name,value in vars(args).items():
        if isinstance(value,Path): ordinary(value)
    if args.action=='prepare': prepare(args)
    else: bind(args)


if __name__=='__main__':
    try: main()
    except (OSError,ValueError,KeyError,TypeError,UnicodeError,tarfile.TarError,subprocess.CalledProcessError) as error:
        raise SystemExit('error: '+str(error))
