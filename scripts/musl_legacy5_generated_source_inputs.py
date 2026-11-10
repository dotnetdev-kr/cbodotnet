"""Authenticate archived SDK5 generated-data/provider source trees and recipes.

This part verifies source bodies, Git objects and modes. It does not establish
actual provider loading, task execution, publisher compilation or admission.
"""
import base64
import hashlib
import json
import posixpath
import re
import tarfile

import musl_legacy5_generated_collection as G
import musl_legacy5_generated_data as D
import musl_legacy5_installer_inputs as I

B,P,require=I.B,I.P,I.require
MAX_FILE=64*1024**2
MAX_FILES=1200000
MAX_BYTES=4*1024**3
MAX_INDEX_ROWS=4000000
FP=('bytes','sha256','sha512')


def git_object(kind,raw):
    return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()


def selected_roots(manifest):
    require(manifest.get('sdkVersion')=='5.0.214'and manifest.get('targetRid')in('linux-musl-arm64','linux-musl-x64'),
        'Distinct original SDK5 source delivery required')
    roots=manifest['roots'];by_name={row['name']:row for row in roots}
    require(len(by_name)==len(roots)and all(re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]*',name)for name in by_name),
        'Unique ordinary source root names required')
    selected={};roles={}
    def include(row):
        name=row['name']
        if name in selected:return
        require(row.get('kind')in('git','git-export')and not row.get('exclude')and not row.get('deleted')
            and row.get('role')in('build-source','source-for-serviced-imported-package')
            and type(row.get('files'))is int and 0<row['files']<=MAX_FILES,
            'Complete unexcluded actual corresponding Git source required')
        commit=row.get('commit');tree=row.get('tree')
        require(isinstance(commit,str)and re.fullmatch('[a-f0-9]{40}',commit)
            and isinstance(tree,str)and re.fullmatch('[a-f0-9]{40}',tree),
            'Exact full original source commit/tree required')
        encoded=row.get('commitObjectBase64','');require(isinstance(encoded,str)and len(encoded)<=32768,
            'Bounded original Git commit object required')
        raw=base64.b64decode(encoded,validate=True)
        require(git_object('commit',raw)==commit and raw.startswith(('tree '+tree+'\n').encode()),
            'Original source Git commit object does not authenticate its tree')
        selected[name]=row;links=row.get('submodules',[])
        require(isinstance(links,list)and len(links)<=256,'Bounded complete original Gitlinks required')
        paths=set()
        for link in links:
            require(set(link)=={'path','commit','root'}and B.portable(link['path'])not in paths
                and re.fullmatch('[a-f0-9]{40}',link['commit'])and link['root']in by_name,
                'Unique actual original Gitlink child binding required')
            paths.add(link['path']);child=by_name[link['root']]
            require(child['name']!=name and child.get('commit')==link['commit'],
                'Original Gitlink must bind its actual complete child commit')
            require(row['role']!='source-for-serviced-imported-package'or child.get('role')==row['role'],
                'Original corresponding-source Gitlink child role must remain preserved')
            include(child)
    for wanted in G.policy()['sources']:
        matches=[row for row in roots if row.get('commit')==wanted['commit']]
        require(len(matches)==1 and matches[0].get('tree')==wanted['tree'],
            'One exact complete data/provider source tree required: '+wanted['dataRole'])
        row=matches[0];include(row);roles[wanted['dataRole']]=row['name']
    require(len(roles)==9 and sum(row['files']for row in selected.values())<=MAX_FILES,
        'All nine bounded generated-data/provider source origins required')
    return selected,roles


def _index(path,selected):
    indexed={};baselines={name:{}for name in selected};total=0;rows=0
    with path.open('rb')as stream:
        while raw:=stream.readline(65537):
            rows+=1;require(rows<=MAX_INDEX_ROWS,'Complete source index row-count budget exceeded')
            require(len(raw)<=65536,'Bounded source index row required')
            row=json.loads(raw);name=B.portable(row['path']);root,relative=name.split('/',1)
            if root not in selected:continue
            require(name not in indexed and type(row.get('bytes'))is int and 0<=row['bytes']<=MAX_FILE,
                'Unique bounded actual generated/provider source index entry required')
            baseline=row.get('baseline');mode=row.get('mode')
            require(isinstance(baseline,dict)and set(baseline)=={'mode','blob'}
                and baseline['mode']==mode and mode in('100644','100755','120000')
                and re.fullmatch('[a-f0-9]{40}',baseline['blob']),
                'Every archived source retains its exact original Git blob and mode')
            total+=row['bytes'];require(total<=MAX_BYTES and len(indexed)<MAX_FILES,
                'Generated/provider source index budget exceeded')
            indexed[name]=row;baselines[root][relative]=baseline
    for name,row in selected.items():
        baseline=baselines[name];require(len(baseline)==row['files'],'Complete source tree index cardinality required')
        for link in row.get('submodules',[]):
            require(link['path']not in baseline,'Gitlink cannot replace an original source file')
            baseline[link['path']]=dict(mode='160000',blob=link['commit'])
        require(P.baseline_tree(baseline)==row['tree'],'Complete original source baseline Git tree differs')
    return indexed


def _member(entry,row):
    mode=row['mode'];require(entry.uid==entry.gid==entry.mtime==0 and entry.uname==entry.gname==''
        and set(entry.pax_headers)<={'path'}and all(value==entry.name for value in entry.pax_headers.values())
        and entry.sparse is None,'Closed ordinary archived source metadata required')
    if mode=='120000':
        require(entry.issym()and entry.size==0 and entry.mode==0o777,'Exact original source symlink type/mode required')
        root=entry.name.split('/',1)[0]
        require(not entry.linkname.startswith('/')and not any(c in entry.linkname for c in'\0\r\n')
            and posixpath.normpath(posixpath.join(posixpath.dirname(entry.name),entry.linkname)).startswith(root+'/'),
            'Original source symlink must remain inside its archived root')
    else:require(entry.isfile()and entry.size==row['bytes']and entry.mode==(0o755 if mode=='100755'else 0o644),
        'Exact original archived source regular-file size/mode required')


def validate(release,manifest):
    """Caller additionally verifies the complete combined packet with P.verify."""
    release=D.ordinary(release,directory=True);selected,roles=selected_roots(manifest)
    index=B.checked(release/'sources',manifest['index']);archive_path=B.checked(release/'sources',manifest['archive'])
    indexed=_index(index,selected)
    installer=I.validate(release,manifest)
    wanted={roles[row['sourceRole']]+'/'+row['path']:key for key,row in D.policy()['sourceFiles'].items()}
    require(len(wanted)==13,'All thirteen distinct original data recipe files required')
    patches={'orchestration/'+name for name in I.PATCHES};saved={};patch_bytes={};found=set();total=0
    with tarfile.open(archive_path,'r|gz')as archive:
        for entry in archive:
            name=B.portable(entry.name);root=name.split('/',1)[0]
            if name in patches:
                require(name not in patch_bytes and entry.isfile()and 0<=entry.size<=MAX_FILE,
                    'Exact unique bounded original installer patch input required')
                raw=archive.extractfile(entry).read(MAX_FILE+1);patch_bytes[name]=raw;continue
            if root not in selected:continue
            require(name in indexed and name not in found,'Extra, missing-index or duplicate archived source entry')
            row=indexed[name];_member(entry,row)
            raw=entry.linkname.encode()if entry.issym()else archive.extractfile(entry).read(MAX_FILE+1)
            require(len(raw)<=MAX_FILE and D.fingerprint(raw)=={key:row[key]for key in FP},
                'Actual archived source whole bytes differ')
            if root!=roles['installer']:
                require(git_object('blob',raw)==row['baseline']['blob'],'Actual source body differs from its pristine original Git blob')
            total+=len(raw);require(total<=MAX_BYTES,'Generated/provider archived source byte budget exceeded')
            if name in wanted:saved[wanted[name]]=raw
            found.add(name)
    require(found==indexed.keys()and len(saved)==13 and patch_bytes.keys()==patches,
        'Complete archived source trees, recipes and original patches required')
    for patch,(sha,targets)in reversed(list(I.PATCHES.items())):
        raw=patch_bytes['orchestration/'+patch];require(hashlib.sha256(raw).hexdigest()==sha,
            'Original reviewed installer patch bytes differ')
        for key,source in D.policy()['sourceFiles'].items():
            if source['sourceRole']=='installer'and source['path']in targets:
                saved[key]=I.reverse_exact_hunks(saved[key],I.N.patch_sections(raw,targets)[source['path']],source['path'])
    originals=D.source_file_correspondence(saved)
    return dict(kind='sdk5-archive-authenticated-generated-data-provider-source-trees',
        sourceRoots={role:dict(name=name,commit=selected[name]['commit'],tree=selected[name]['tree'])for role,name in roles.items()},
        completeGitTrees=len(selected),archivedSourceFiles=len(found),archivedSourceBytes=total,
        originalRecipeFiles={key:D.fingerprint(raw)for key,raw in originals.items()},
        originalInstallerSourceGuard=installer,archivedGeneratedProviderSourceTreesValidated=True,
        wholeCombinedSourcePacketValidatedByThisPart=False,actualRuntimeLoadsAuthenticated=False,
        actualTaskChronologyAuthenticated=False,publisherCompilerExecutionClaimed=False,
        wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)
