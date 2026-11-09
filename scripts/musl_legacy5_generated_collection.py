"""Explicit, partial SDK5 data/provider source registration; no admission."""
import copy
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import re
import stat
import subprocess
from urllib.parse import urljoin,urlsplit

import musl_legacy5_collection_sources as C
import musl_legacy5_generated_data as D
import musl_legacy5_newtonsoft_source_inputs as J

require=C.require
ROLE=C.ROLE
POLICY_SHA256='be850476e37b18c5c1c5f7d6df7dec5bef1eb241f4144c806356f5e229d833d9'


def ordinary(value,*,directory=False):
    require(isinstance(value,(str,Path)),'Actual ordinary source path required')
    path=Path(value)
    require(path.is_absolute()and '..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),
        'Ordinary absolute unredirected generated-source path required')
    if path.exists():
        mode=path.lstat().st_mode
        require(not mode&0o7000 and (stat.S_ISDIR(mode)or stat.S_ISREG(mode)),'Ordinary generated-source entry required')
    if directory:require(path.is_dir(),'Actual generated-source directory required')
    return path


def origin(value):
    require(isinstance(value,str),'Actual GitHub origin required')
    parsed=urlsplit(value)
    require(parsed.scheme=='https'and parsed.netloc=='github.com'and not parsed.query and not parsed.fragment,
        'Exact public HTTPS GitHub origin required; local paths and redirect aliases are insufficient')
    parts=parsed.path.split('/');require(len(parts)==3,'Exact owner/repository GitHub origin required')
    owner,repo=parts[1],parts[2].removesuffix('.git')
    require(all(re.fullmatch('[A-Za-z0-9_.-]+',p)and p not in('.', '..')for p in(owner,repo)),
        'Ordinary literal GitHub owner/repository required')
    return owner.lower(),repo.lower()


def policy():
    path=ordinary(Path(__file__).with_name('musl-legacy5-generated-source-policy.json'));raw=path.read_bytes()
    require(hashlib.sha256(raw).hexdigest()==POLICY_SHA256,'Immutable generated-source collection policy differs')
    p=json.loads(raw);data=D.policy();publisher=J.policy()
    require(p['schemaVersion']==1 and p['sdkVersion']==D.policy()['sdkVersion']
        and p['kind']=='sdk5-generated-data-provider-corresponding-source-collection-policy'
        and p['dataPolicySha256']==D.POLICY_SHA256 and p['jsonPublisherPolicySha256']==J.POLICY_SHA256
        and len(p['sources'])==9 and sum(row['requirePreviouslyRegistered']for row in p['sources'])==4
        and p['futureAcquisitionBudgetIsProposedAndCallerEnforced']is True
        and all(p[k]is False for k in('collectionCallbackGuaranteesAcquisitionBounds','originalPackageMetadataChanged',
            'fullEmbeddedMsbuildGitShaClaimed','sourceArchiveValidated','actualProviderLoadsAuthenticated','qualificationAllowed','sourceAdmissionAllowed')),
        'Distinct exact SDK5 generated-source origins and honest proposed-budget scope required')
    for row in p['sources']:
        origin(row['repository']);require(all(re.fullmatch('[a-f0-9]{40}',row[k])for k in('commit','tree')),
            'Exact full source commit and Git tree required')
        if row['dataRole']in data['sources']:
            require(all(row[k]==data['sources'][row['dataRole']][k]for k in('repository','commit','tree')),
                'Original authored data source policy differs')
    json9=next(row for row in p['sources']if row['dataRole']=='json9-publisher')
    require(json9['commit']==publisher['distributions']['9.0.1']['sourceCommit']
        and json9['tree']==publisher['sources'][json9['commit']]['tree'],'Exact original Json9 publisher source required')
    return p


def required_sources():
    return [dict(row,name=row['futureName'],role=ROLE)for row in policy()['sources']]


def git(path,*args,optional=False):
    env=dict(os.environ,GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0')
    result=subprocess.run(['git','--no-replace-objects','-c','safe.directory='+str(path),'-C',str(path),*args],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=60)
    if optional and result.returncode==1:return b''
    require(result.returncode==0 and len(result.stdout)<=64*1024**2,'Actual local Git source identity/object read failed')
    return result.stdout


def identity(row):
    path=ordinary(row['path'],directory=True)
    require(row.get('kind')=='git'and re.fullmatch('[a-f0-9]{40}',row.get('expectedCommit','')),
        'Actual full original Git source required')
    require(Path(git(path,'rev-parse','--show-toplevel').decode().strip()).resolve()==path.resolve(),
        'Source must be the actual physical Git worktree root')
    commit=git(path,'rev-parse','HEAD').decode().strip();require(commit==row['expectedCommit'],'Actual source HEAD differs from its recorded pin')
    raw=git(path,'cat-file','commit',commit)
    require(hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==commit,'Actual original source commit object required')
    tree=raw.splitlines()[0].decode().removeprefix('tree ')
    require(re.fullmatch('[a-f0-9]{40}',tree)and git(path,'rev-parse','HEAD^{tree}').decode().strip()==tree,'Actual original source tree required')
    repository=git(path,'config','--get','remote.origin.url').decode().strip();origin(repository)
    return dict(path=str(path),repository=repository,commit=commit,tree=tree)


def inventory(sources):
    result={name:identity(row)for name,row in sources.items()if row.get('kind')=='git'}
    require(len({Path(row['path']).resolve()for row in result.values()})==len(result),'Ambiguous duplicate physical source roots')
    return result


def preserve_identities(sources,protected):
    actual=inventory(sources)
    require(all(actual.get(name)==row for name,row in protected.items()),
        'Existing actual source origin/HEAD/tree identities must remain unchanged')
    return actual


def report_outside(report,sources):
    ordinary(report)
    require(all(not report.is_relative_to(ordinary(row['path']))for row in sources.values()),
        'Generated-source report must remain outside every collected source root')


def expand(sources,callback,protected):
    rows=callback(copy.deepcopy(list(sources.values())))
    require(isinstance(rows,list)and len(rows)==len({row['name']for row in rows}),'Unique actual expanded source names required')
    expanded={row['name']:row for row in rows}
    require(all(expanded.get(name)==row for name,row in protected.items()),'Existing source records/paths/roles must remain unchanged')
    sources.clear();sources.update(expanded)


def gitlinks(sources,actual):
    links=[]
    for name,ident in actual.items():
        path=Path(ident['path']);entries=[]
        for item in git(path,'ls-tree','-rz','--full-tree',ident['commit']).split(b'\0'):
            if not item:continue
            header,encoded=item.split(b'\t',1);mode,kind,sha=header.decode().split()
            if kind=='commit':
                relative=D.CE.portable(encoded.decode());require(mode=='160000','Actual original Gitlink mode required')
                entries.append((relative,sha))
        if not entries:continue
        config=git(path,'config','--null','--blob',ident['commit']+':.gitmodules','--get-regexp',r'^submodule\..*\.(path|url)$')
        groups={}
        for item in config.split(b'\0'):
            if not item:continue
            key,value=item.decode().split('\n',1);group,field=key.rsplit('.',1)
            require(field not in groups.setdefault(group,{}),'Unique original Gitmodule properties required')
            groups[group][field]=value
        for relative,sha in entries:
            matches=[row for row in groups.values()if row.get('path')==relative]
            require(len(matches)==1 and 'url'in matches[0],'Original Gitmodule path/URL must bind every actual Gitlink')
            original_url=matches[0]['url'];resolved=urljoin(ident['repository'].removesuffix('.git')+'/',original_url)
            declared_origin=origin(resolved);child_path=path/relative
            children=[(child,row)for child,row in actual.items()if Path(row['path'])==child_path and row['commit']==sha]
            require(len(children)==1 and origin(children[0][1]['repository'])==declared_origin,
                'Actual physical Gitlink child origin/commit required')
            child=children[0][0]
            if sources[name].get('role')==ROLE:require(sources[child].get('role')==ROLE,'Fresh Gitlink must inherit corresponding-source role')
            links.append(dict(parent=name,path=relative,commit=sha,originalUrl=original_url,resolvedOrigin=resolved,child=child,
                childTree=actual[child]['tree'],physicalChildPath=str(child_path)))
    return links


def verify_fresh_tree(row):
    path=ordinary(row['path'],directory=True);files=content=symlinks=0
    for item in git(path,'ls-tree','-rz','--full-tree',row['expectedCommit']).split(b'\0'):
        if not item:continue
        header,encoded=item.split(b'\t',1);mode,kind,blob=header.decode().split()
        if kind=='commit':continue
        name=D.CE.portable(encoded.decode());target=path/name
        require(not any(p.is_symlink()for p in target.parents),'Fresh source file ancestors must not redirect')
        if mode=='120000':
            require(target.is_symlink(),'Exact original source symlink type required');raw=os.readlink(target).encode();symlinks+=1
        else:
            require(kind=='blob'and mode in('100644','100755')and target.is_file()and not target.is_symlink()
                and stat.S_IMODE(target.stat().st_mode)==(0o755 if mode=='100755'else 0o644),
                'Exact original fresh source file type/mode required')
            raw=target.read_bytes();files+=1;content+=len(raw)
        require(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==blob,'Exact original fresh source Git blob required')
    return dict(name=row['name'],regularFiles=files,contentBytes=content,symlinks=symlinks,actualGitBytesAndModesChecked=True)


def register(sdk,sources,clone,expand_submodules,report_path,*,workspace):
    require(sdk=='5.0.214','Generated data/provider source collection is SDK5-only')
    W=ordinary(workspace,directory=True);work=ordinary(W/'work',directory=True);report=ordinary(report_path)
    require(not report.exists(),'Fresh exclusive generated-source report required')
    protected=copy.deepcopy(sources);protected_paths=[ordinary(row['path'],directory=True)for row in protected.values()]
    protected_actual=inventory(sources)
    report_outside(report,sources);expand(sources,expand_submodules,protected);report_outside(report,sources)
    protected_actual=preserve_identities(sources,protected_actual)
    protected=copy.deepcopy(sources);selected=[];fresh=[]
    for expected in required_sources():
        actual=inventory(sources);gitlinks(sources,actual)
        same_commit=[name for name,row in actual.items()if row['commit']==expected['commit']]
        matching=[name for name in same_commit if origin(actual[name]['repository'])==origin(expected['repository'])]
        require(len(matching)<=1,'Ambiguous actual origin/commit source roots')
        require(matching or not same_commit,'Existing same-commit source has a conflicting actual origin')
        created=False
        if matching:name=matching[0]
        else:
            require(not expected['requirePreviouslyRegistered'],'Required prior primary/extra/literal source is absent')
            name=expected['name'];target=ordinary(work/name)
            require(name not in sources and not target.exists(),'Fresh generated-source name/path is already occupied')
            require(all(target!=old and target not in old.parents and old not in target.parents for old in protected_paths),
                'New corresponding source must not overlap an existing worktree')
            require(not report.is_relative_to(target),'Generated-source report must not enter a future source root')
            returned=clone(name,expected['repository'],expected['commit'])
            require(name in sources and ordinary(returned,directory=True)==target and ordinary(sources[name]['path'],directory=True)==target,
                'Clone callback must declare and return the exact fresh physical source destination')
            require(all(sources.get(key)==row for key,row in protected.items()),'Clone callback changed existing source metadata')
            preserve_identities(sources,protected_actual)
            sources[name]=dict(sources[name],role=ROLE);fresh.append(target);created=True
        observed=identity(sources[name])
        require(observed['commit']==expected['commit']and observed['tree']==expected['tree']
            and origin(observed['repository'])==origin(expected['repository']),'Exact actual source origin/HEAD/tree required')
        selected.append(dict(dataRole=expected['dataRole'],name=name,**observed,newlyCloned=created,
            role=sources[name].get('role','build-source'),existingRolePreserved=not created,identityBasis=expected['identityBasis']))
        expand(sources,expand_submodules,protected);report_outside(report,sources)
        preserve_identities(sources,protected_actual)
    actual=preserve_identities(sources,protected_actual);links=gitlinks(sources,actual);report_outside(report,sources)
    utility=C.PRIMARY.materializer();materialized=[];measured=[]
    for row in sources.values():
        path=Path(row['path'])
        if row.get('kind')=='git'and any(path==parent or path.is_relative_to(parent)for parent in fresh):
            require(row.get('role')==ROLE,'Only fresh corresponding-source roots may be materialized')
            materialized.append(utility.exact_git_bytes(row));measured.append(verify_fresh_tree(row))
    require(all(sources.get(name)==row for name,row in protected.items()),'Existing original source records/paths/roles changed')
    after=preserve_identities(sources,protected_actual)
    require(all(after[name]==actual[name]for name in after),'Actual source origin/HEAD/tree changed during materialization')
    result=dict(schemaVersion=1,sdkVersion=sdk,kind='partial-sdk5-generated-data-provider-source-registration',
        sourcePolicySha256=POLICY_SHA256,selectedSources=selected,actualGitlinks=links,freshMaterialization=materialized,
        freshSourceMeasurements=measured,existingSourceRecordsPathsAndRolesPreserved=True,existingActualOriginHeadTreeIdentitiesPreserved=True,
        existingCompilerWorktreesRewritten=False,
        sourceAcquisitionBudgetProposedAndCallerEnforced=True,collectionCallbackGuaranteesAcquisitionBounds=False,
        fullSourceArchiveValidated=False,actualProviderLoadsAuthenticated=False,qualificationAllowed=False,sourceAdmissionAllowed=False)
    report_outside(report,sources);report.parent.mkdir(parents=True,exist_ok=True)
    with report.open('x',encoding='utf-8',newline='\n')as stream:json.dump(result,stream,indent=2);stream.write('\n')
    return result
