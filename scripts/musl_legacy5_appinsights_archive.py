"""Independent finite App archive views built only from authenticated bytes.

No entry launches a compiler, Reader, runtime, container, Git or acquisition.
This module does not change the live normal/default validators or admit an SDK.
"""
from contextlib import contextmanager
import base64
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path,PurePosixPath
import posixpath
import re
import stat
import tarfile
import zipfile

import musl_legacy5_appinsights_reference_bootstrap as R
import musl_legacy5_bootstrap_byte_inputs as BYTE
import musl_source_archive as SA

N=R.N
require=N.require
FP=('bytes','sha256','sha512')
BLOCK=1024**2
MEMORY_FILE=8*1024**2
MAX_JSON=8*1024**2
MAX_INDEX_LINE=1024**2
MAX_SOURCE_FILES=2000000
MAX_SOURCE_ROOTS=4096
MAX_RAW_SOURCE=64*1024**3
ROOT=Path(__file__).resolve().parents[1]
APP_PUBLIC_ROLE='sdk5-finite-app-public-source-and-evidence'
_SOURCE_VERIFIED=object()
_ORIGIN_FACTORY=object()
_RECONSTRUCTED_FACTORY=object()


def fingerprint(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),sha512=hashlib.sha512(raw).hexdigest())


def identity(value,*,empty=False):
    require(type(value)is dict and set(value)==set(FP)and type(value['bytes'])is int
        and (0 if empty else 1)<=value['bytes']
        and all(isinstance(value[key],str)and re.fullmatch('[0-9a-f]{'+str(length)+'}',value[key])
            for key,length in(('sha256',64),('sha512',128))), 'Exact archived byte identity required')
    return dict(value)


def fields(value):
    require(isinstance(value,dict)and set(FP)<=value.keys(),'Complete archived fingerprint fields required')
    return identity({key:value[key]for key in FP},empty=True)


def ordinary(value,*,file=False,directory=False):
    path=Path(value)
    require(path.is_absolute()and '..'not in path.parts and path!=Path(path.anchor),
        'Ordinary absolute archive-view path required before normalization')
    require(not any(p.is_symlink()or getattr(p,'is_junction',lambda:False)()for p in(path,*path.parents)),
        'Linked archive-view paths are forbidden')
    if path.exists():
        mode=path.lstat().st_mode
        require(not mode&0o7000 and(stat.S_ISREG(mode)or stat.S_ISDIR(mode)),
            'Archive-view special entry/mode forbidden')
    if file:require(path.is_file(),'Archived input file missing: '+str(path))
    if directory:require(path.is_dir(),'Archive-view directory missing: '+str(path))
    return path


def portable(value):
    require(isinstance(value,str)and value and ':'not in value and not any(c in value for c in'\\\0\r\n')
        and not value.startswith('/')and value==posixpath.normpath(value)
        and all(part not in('','.','..')for part in value.split('/')),'Canonical relative archive-view member required')
    return value


def logical(value):
    require(isinstance(value,str)and value.startswith('/')and not value.startswith('//')
        and ':'not in value and not any(c in value for c in'\\\0\r\n')
        and value==posixpath.normpath(value)and all(part not in('','.','..')for part in value[1:].split('/')),
        'Original canonical POSIX logical path required')
    return value


def unique_json(raw,*,limit=MAX_JSON):
    require(isinstance(raw,bytes)and len(raw)<=limit,'Bounded immutable archived JSON required')
    def pairs(items):
        require(len(items)==len({key for key,_ in items}),'Duplicate archived JSON keys forbidden')
        return dict(items)
    return json.loads(raw,object_pairs_hook=pairs)


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')


class _FrozenDict(dict):
    def _blocked(self,*args,**kwargs):raise TypeError('Authenticated archive metadata is immutable')
    __setitem__=__delitem__=clear=pop=popitem=setdefault=update=__ior__=_blocked


class _FrozenList(list):
    def _blocked(self,*args,**kwargs):raise TypeError('Authenticated archive metadata is immutable')
    __setitem__=__delitem__=append=clear=extend=insert=pop=remove=reverse=sort=__iadd__=__imul__=_blocked


def _frozen(value):
    if type(value)is dict:return _FrozenDict({key:_frozen(item)for key,item in value.items()})
    if type(value)is list:return _FrozenList(_frozen(item)for item in value)
    return value


class Budget:
    """Explicit categories; source/public sessions never hide inside private522."""
    def __init__(self,*,private_bytes=2*1024**3,source_bytes,public_bytes,files=20000):
        require(type(private_bytes)is int and 0<private_bytes<=2*1024**3
            and type(source_bytes)is int and 0<source_bytes<=2*MAX_RAW_SOURCE
            and type(public_bytes)is int and 0<public_bytes<=MAX_RAW_SOURCE
            and type(files)is int and 0<files<=100000,'Finite measured archive-view budgets required')
        self.limits=dict(private=private_bytes,source=source_bytes,public=public_bytes)
        self.used={key:0 for key in self.limits};self.file_limit=files;self.files=0

    def reserve(self,size,category,*,file=True):
        require(type(size)is int and size>=0 and category in self.used
            and self.used[category]+size<=self.limits[category], 'Archive-view '+str(category)+' byte budget exceeded before allocation')
        require(not file or self.files<self.file_limit,'Archive-view file budget exceeded before allocation')
        self.used[category]+=size
        if file:self.files+=1


class Snapshot:
    """A bytes object or a sole owned read-only unlinked descriptor, never an opener."""
    def __init__(self):
        self.raw=None;self.fd=None;self.fingerprint=None;self.closed=True;self._witness=None

    @classmethod
    def from_bytes(cls,raw,expected,*,budget,category):
        expected=identity(expected,empty=True)
        require(type(raw)is bytes and len(raw)<=MEMORY_FILE,'Bounded immutable snapshot bytes required')
        budget.reserve(len(raw),category)
        require(fingerprint(raw)==expected,'Captured immutable bytes differ from expected identity')
        result=cls();result.raw=raw;result.fingerprint=expected;result.closed=False;return result

    @classmethod
    def capture(cls,path,expected,*,budget,category,private_root):
        expected=identity(expected,empty=True);path=ordinary(path,file=True)
        require(path.stat().st_size==expected['bytes'],'Captured source length differs')
        if expected['bytes']<=MEMORY_FILE:
            budget.reserve(expected['bytes'],category)
            with path.open('rb')as stream:
                before=os.fstat(stream.fileno());raw=stream.read(expected['bytes']+1);after=os.fstat(stream.fileno())
            require(_signature(before)==_signature(after)and len(raw)==expected['bytes'],
                'Incoming snapshot changed during its bounded read')
            require(fingerprint(raw)==expected,'Captured immutable bytes differ from expected identity')
            result=cls();result.raw=raw;result.fingerprint=expected;result.closed=False;return result
        require(SA.supported(),'Large immutable archive snapshots require owned POSIX descriptors')
        private_root=ordinary(private_root,directory=True)
        budget.reserve(expected['bytes'],category)
        require(SA.temporary_free_bytes(private_root)>=expected['bytes']+512*1024**2,
            'Insufficient measured free space for immutable snapshot plus reserve')
        target=private_root/('snapshot-'+str(budget.files))
        require(not target.exists(),'Fresh exclusive immutable snapshot path required')
        SA.copy_authenticated(path,target,expected)
        result=cls();result.fd=SA.readonly_unlinked(target);result.fingerprint=expected;result.closed=False
        require(os.fstat(result.fd).st_size==expected['bytes'],'Owned immutable snapshot length differs')
        result._witness=_signature(os.fstat(result.fd))
        return result

    @contextmanager
    def open(self):
        require(not self.closed and type(self)is Snapshot,'An actual open owned snapshot is required')
        if self.raw is not None:
            require(type(self.raw)is bytes and fingerprint(self.raw)==self.fingerprint,'Immutable byte snapshot identity changed')
            with io.BytesIO(self.raw)as stream:yield stream
        else:
            info=os.fstat(self.fd)
            require(stat.S_ISREG(info.st_mode)and info.st_nlink==0 and info.st_size==self.fingerprint['bytes'],
                'Sole owned unlinked snapshot descriptor differs')
            require(_signature(info)==self._witness,'Owned immutable snapshot witness changed')
            try:
                with io.BufferedReader(SA.ReadAt(self.fd,self.fingerprint['bytes']),buffer_size=BLOCK)as stream:yield stream
            finally:require(_signature(os.fstat(self.fd))==self._witness,'Owned immutable snapshot changed during reads')

    def bytes(self,limit=MEMORY_FILE):
        require(not self.closed and self.fingerprint['bytes']<=limit,'Snapshot exceeds bounded byte read')
        with self.open()as stream:raw=stream.read(limit+1)
        require(fingerprint(raw)==self.fingerprint,'Owned snapshot bytes differ');return raw

    def close(self):
        if not self.closed and self.fd is not None:os.close(self.fd)
        self.fd=None;self.raw=None;self.closed=True

    def __enter__(self):return self
    def __exit__(self,*_):self.close()


def _signature(info):
    return(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,
        info.st_size,info.st_mtime_ns,info.st_ctime_ns)


class FrozenView:
    """Explicit original-path map to a private, identity-witnessed physical view."""
    def __init__(self,root,*,budget,forbidden_roots=()):
        self.root=ordinary(root);require(not self.root.exists(),'Fresh exclusive archived physical view required')
        for value in forbidden_roots:
            source=ordinary(value)
            require(source!=self.root and source not in self.root.parents and self.root not in source.parents,
                'Private archived view must be outside every actual input/delivery')
        self.root.mkdir(parents=True);self.root.chmod(0o700)
        self.budget=budget;self.entries={};self.roots={};self.roles={};self.source=None;self.frozen=False;self._witness=None;self._fds=[];self._mapping=None

    def _key(self,original,namespace):
        require(namespace in('host','container','consumer'),'Closed archived path namespace required')
        if namespace=='consumer'and original=='/work/work/sdk/artifacts/bin/redist/Release/dotnet//sdk/5.0.214-ci/Microsoft.ApplicationInsights.dll':
            return(namespace,original)
        return(namespace,logical(original))

    def declare_root(self,original,relative,*,namespace='host',role=None):
        require(not self.frozen,'Frozen view cannot acquire new roots')
        key=self._key(original,namespace);relative=portable(relative)
        require(key not in self.roots and key not in self.entries,'Unique original logical root required')
        path=ordinary(self.root/relative);path.mkdir(parents=True,exist_ok=True);self.roots[key]=path
        if role is not None:
            require(isinstance(role,str)and re.fullmatch('[a-z][a-z0-9-]{0,63}',role)and role not in self.roles,'Unique archived root role required')
            self.roles[role]=key
        return path

    def add(self,original,relative,snapshot,*,mode=0o644,category='private',namespace='host'):
        require(not self.frozen and type(snapshot)is Snapshot and not snapshot.closed,'Actual captured snapshot required before view freeze')
        key=self._key(original,namespace);relative=portable(relative)
        require(key not in self.entries and key not in self.roots and mode in(0o644,0o755),
            'Unique exact ordinary archived file/mode required')
        require(len(self.entries)<2*self.budget.file_limit,'Bounded original logical map required')
        path=ordinary(self.root/relative)
        if path.exists():
            same=[row for row in self.entries.values()if row['path']==path]
            require(same and all(row['fingerprint']==snapshot.fingerprint and row['mode']==mode for row in same),
                'An archived file may alias only the same captured bytes and mode')
        else:
            self.budget.reserve(snapshot.fingerprint['bytes'],category)
            path.parent.mkdir(parents=True,exist_ok=True);hashes={key:hashlib.new(key)for key in FP[1:]};size=0
            with snapshot.open()as incoming,path.open('xb')as outgoing:
                while raw:=incoming.read(BLOCK):
                    size+=len(raw);require(size<=snapshot.fingerprint['bytes'],'Materialized snapshot grew')
                    for digest in hashes.values():digest.update(raw)
                    outgoing.write(raw)
            require(dict(bytes=size,**{key:value.hexdigest()for key,value in hashes.items()})==snapshot.fingerprint,
                'Materialized bytes differ from the same immutable source stream')
            path.chmod(mode)
            if os.name=='posix':require(stat.S_IMODE(path.stat().st_mode)==mode,'Materialized archived mode differs')
        self.entries[key]=dict(path=path,fingerprint=dict(snapshot.fingerprint),mode=mode);return path

    def path(self,original,*,namespace='host'):
        key=self._key(original,namespace)
        require(key in self.entries or key in self.roots,'Original logical path has no authenticated mapping: '+original)
        return self.entries[key]['path']if key in self.entries else self.roots[key]

    def logical_root(self,role):
        require(role in self.roles,'Authenticated archived root role missing: '+str(role));return self.roles[role][1]

    def root_path(self,role):
        require(role in self.roles,'Authenticated archived root role missing: '+str(role));return self.roots[self.roles[role]]

    @property
    def release_root(self):return self.root_path('delivery')

    def contains(self,original,*,namespace='host'):
        key=self._key(original,namespace);return key in self.entries or key in self.roots

    def bind_origin(self,original,relative,origin,*,namespace='host',category='private'):
        require(type(origin)is VerifiedOrigin,'Concrete verified source/delivery origin required')
        metadata=origin.metadata()
        require(self.source is None or self.source is origin.source,'One actual source session per archived view required')
        self.source=origin.source
        path=self.add(original,relative,origin.snapshot,mode=metadata['mode'],category=category,namespace=namespace)
        self.entries[self._key(original,namespace)]['origin']=origin;return path

    def adopt_inventory(self,original,relative,inventory,*,namespace='container'):
        """Register a verified owned BOOT tree without materializing a second tree."""
        require(not self.frozen and type(inventory)is dict and inventory,'Complete owned compiler inventory required')
        path=ordinary(self.root/portable(relative),directory=True)
        require(BYTE.actual_tree(path)==inventory,'Owned compiler tree differs before mapping registration')
        for name,row in inventory.items():
            portable(name);key=self._key(logical(original)+'/'+name,namespace)
            require(key not in self.entries and key not in self.roots and row['mode']in(0o644,0o755),
                'Unique ordinary compiler member mapping required')
            self.entries[key]=dict(path=path/name,fingerprint=fields(row),mode=row['mode'])
        return path

    def require_origin(self,original,*,namespace='host'):
        key=self._key(original,namespace)
        require(type(self.source)is SourceSession and self.source.verified and key in self.entries,
            'Actual same-session archived mapping origin required')
        origin=self.entries[key].get('origin')
        require(type(origin)is VerifiedOrigin and origin.source is self.source,
            'Arbitrary captured bytes cannot replace an authenticated archived origin')
        metadata=origin.metadata()
        require(metadata['fingerprint']==self.entries[key]['fingerprint']and metadata['mode']==self.entries[key]['mode'],
            'Archived mapping provenance no longer matches captured bytes/mode')
        return dict(metadata,originalLogicalPath=original)

    def read(self,original,limit=MAX_JSON,*,namespace='host'):
        key=self._key(original,namespace);require(key in self.entries,'An authenticated original file is required')
        row=self.entries[key];require(row['fingerprint']['bytes']<=limit,'Bounded archived file read required')
        raw=ordinary(row['path'],file=True).read_bytes()
        require(fingerprint(raw)==row['fingerprint'],'Archived mapped file bytes differ');return raw

    def checked(self,original,descriptor,*,recorded_path=None,namespace='host'):
        key=self._key(original,namespace)
        require(type(descriptor)is dict and set(descriptor)=={'path',*FP}
            and descriptor['path']==(original if recorded_path is None else recorded_path),
            'Original archived descriptor path must remain unchanged')
        require(key in self.entries and fields(descriptor)==self.entries[key]['fingerprint'],
            'Archived descriptor identity differs from actual captured mapping')
        return self.path(original,namespace=namespace)

    def _observe(self):
        rows={};actual=set()
        for parent,dirs,files in os.walk(self.root,followlinks=False):
            for name in dirs+files:
                path=ordinary(Path(parent)/name);relative=path.relative_to(self.root).as_posix()
                require(len(rows)<self.budget.file_limit*4,'Bounded physical archived view required')
                rows[relative]=_signature(path.lstat())
                if path.is_file():actual.add(path)
        require(actual=={row['path']for row in self.entries.values()},'Private archived view contains extra/unmapped files')
        rows['.']=_signature(self.root.lstat());return rows

    def _mapping_state(self):
        return canonical(dict(root=str(self.root),source=id(self.source),
            roots=[(key,str(value))for key,value in sorted(self.roots.items())],roles=sorted(self.roles.items()),
            entries=[(key,str(row['path']),row['fingerprint'],row['mode'],id(row.get('origin')))
                for key,row in sorted(self.entries.items())]))

    def freeze(self):
        require(os.name=='posix'and SA.supported(),'Frozen delegated physical views require POSIX inode/ctime semantics')
        require(not self.frozen and self._witness is None,'Archived view is already frozen')
        import resource
        limit,_=resource.getrlimit(resource.RLIMIT_NOFILE)
        require(limit==resource.RLIM_INFINITY or limit>=len({row['path']for row in self.entries.values()})+32,
            'Explicit file-descriptor budget is insufficient before frozen-view opens')
        expected_files={}
        try:
            grouped={}
            for row in self.entries.values():grouped.setdefault(row['path'],[]).append(row)
            for path,rows in sorted(grouped.items()):
                descriptor=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0));self._fds.append(descriptor)
                before=os.fstat(descriptor);hashes={key:hashlib.new(key)for key in FP[1:]};size=0
                with os.fdopen(os.dup(descriptor),'rb')as stream:
                    while raw:=stream.read(BLOCK):
                        size+=len(raw)
                        for digest in hashes.values():digest.update(raw)
                after=os.fstat(descriptor)
                require(_signature(before)==_signature(after)
                    and all(dict(bytes=size,**{key:value.hexdigest()for key,value in hashes.items()})==row['fingerprint']for row in rows),
                    'Physical archived bytes changed before view freeze')
                expected_files[path.relative_to(self.root).as_posix()]=_signature(after)
            observed=self._observe()
            require(all(observed[name]==value for name,value in expected_files.items()),'Archived input changed between hashing and witness capture')
            self._witness=observed;self._mapping=self._mapping_state();self.frozen=True;return self
        except BaseException:
            self.close();raise

    @contextmanager
    def guard(self):
        require(self.frozen and self._mapping_state()==self._mapping
            and len(self._fds)==len({row['path']for row in self.entries.values()})
            and self._observe()==self._witness,'Frozen archived view changed before delegated reads')
        try:yield self
        finally:require(self._mapping_state()==self._mapping and self._observe()==self._witness,
            'Frozen archived view changed during delegated reads')

    def close(self):
        for descriptor in self._fds:os.close(descriptor)
        self._fds=[]


def packer():
    path=ROOT/'scripts/package-used-source.py'
    spec=importlib.util.spec_from_file_location('app5_archived_original_source_predicates',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


class SourceSession:
    """SDK5-only complete verification over captured archive/index bytes."""
    def __init__(self,archive,index,manifest_raw,expected_identity,*,manifest_identity,budget,private_root):
        require(type(archive)is Snapshot and type(index)is Snapshot,'Actual immutable source/index snapshots required')
        require(fingerprint(manifest_raw)==identity(manifest_identity),'Actual manifest differs from caller-authenticated sealed identity')
        self.archive=archive;self.index=index;self.manifest_raw=manifest_raw;self.manifest=unique_json(manifest_raw)
        self._manifest_identity=dict(manifest_identity)
        self.expected=dict(expected_identity);self._verification=None;self.result=None
        self._expected_raw=canonical(self.expected);self._result_raw=None
        m=self.manifest
        require(set(self.expected)=={'sdkVersion','projectCommit','runId','runAttempt','targetRid'}
            and self.expected['sdkVersion']=='5.0.214'and all(m.get(key)==value for key,value in self.expected.items())
            and re.fullmatch('[0-9a-f]{40}',self.expected['projectCommit'])
            and m.get('schemaVersion')==1 and m.get('status')=='captured-used-source',
            'Actual SDK5 source archive/run/commit/RID identity required')
        require(fields(m['archive'])==archive.fingerprint and fields(m['index'])==index.fingerprint
            and type(m.get('files'))is int and 0<m['files']<=MAX_SOURCE_FILES
            and isinstance(m.get('roots'),list)and 0<len(m['roots'])<=MAX_SOURCE_ROOTS,
            'Complete bounded actual source archive/index identities required')
        self.raw_bound=self._expansion_bound();self.raw=self._expand(budget,private_root)
        self._raw_identity=dict(self.raw.fingerprint)
        try:self._check_tar_framing()
        except BaseException:
            self.raw.close();raise
        self.manifest=_frozen(self.manifest)
        self._identity_objects=(self.manifest,self.manifest_raw,self.archive,self.index,self.raw)

    @classmethod
    def capture(cls,release,expected_identity,manifest_identity,*,budget,private_root):
        release=ordinary(release,directory=True);private_root=ordinary(private_root,directory=True)
        require(release!=private_root and release not in private_root.parents and private_root not in release.parents,
            'Owned SDK5 source session must be separate from actual delivery')
        snapshots=[];result=None
        try:
            manifest=Snapshot.capture(release/'sources/source-manifest.json',manifest_identity,budget=budget,category='source',private_root=private_root);snapshots.append(manifest)
            raw=manifest.bytes(MAX_JSON);value=unique_json(raw)
            control=Snapshot.capture(release/'reports/ci/used-source.json',manifest_identity,budget=budget,category='source',private_root=private_root);snapshots.append(control)
            require(control.bytes(MAX_JSON)==raw,'Actual source manifest and inventoried CI control differ')
            require({path.name for path in(release/'sources').iterdir()}=={'source-manifest.json',value['archive']['path'],value['index']['path']},
                'Source artifact directory has extra or missing members')
            owned={}
            for key in('archive','index'):
                name=portable(value[key]['path']);require('/'not in name,'Source artifact must remain directly under sources')
                owned[key]=Snapshot.capture(release/'sources'/name,fields(value[key]),budget=budget,category='source',private_root=private_root)
                snapshots.append(owned[key])
            result=cls(owned['archive'],owned['index'],raw,expected_identity,manifest_identity=manifest_identity,budget=budget,private_root=private_root)
            result._owned=snapshots;result.verify();return result
        except BaseException:
            if result is not None:result.close()
            for snapshot in snapshots:snapshot.close()
            raise

    def _check_identity(self):
        require(all(a is b for a,b in zip(self._identity_objects,(self.manifest,self.manifest_raw,self.archive,self.index,self.raw)))
            and canonical(self.expected)==self._expected_raw and all(self.manifest.get(key)==value for key,value in self.expected.items())
            and fields(self.manifest['archive'])==self.archive.fingerprint and fields(self.manifest['index'])==self.index.fingerprint,
            'Owned source-session identity/manifest changed')
        require(not self.archive.closed and not self.index.closed and not self.raw.closed and self.raw.fingerprint==self._raw_identity,
            'Actual immutable source/index/raw session is closed or changed')
        if self.verified:require(self.result is self._result_object,'Actual complete source validation facts changed')

    @property
    def verified(self):
        return self._verification is _SOURCE_VERIFIED and all(not snapshot.closed for snapshot in(self.archive,self.index,self.raw))

    def _expand(self,budget,private_root):
        budget.reserve(self.raw_bound,'source')
        result=Snapshot();hashes={key:hashlib.new(key)for key in FP[1:]};size=0
        if self.raw_bound<=MEMORY_FILE:
            with self.archive.open()as incoming,gzip.GzipFile(fileobj=incoming,mode='rb')as stream:
                raw=stream.read(self.raw_bound+1)
            require(len(raw)<=self.raw_bound,'Source expansion exceeds its actual bounded index')
            result.raw=raw;result.fingerprint=fingerprint(raw)
        else:
            require(SA.supported(),'Large SDK5 source expansion requires owned POSIX byte transport')
            private_root=ordinary(private_root,directory=True);target=private_root/('source-raw-'+str(budget.files))
            require(SA.temporary_free_bytes(private_root)>=self.raw_bound+512*1024**2,
                'Insufficient measured source expansion space plus reserve')
            require(not target.exists(),'Fresh exclusive raw source path required')
            with self.archive.open()as incoming,gzip.GzipFile(fileobj=incoming,mode='rb')as decoded,target.open('xb')as outgoing:
                while raw:=decoded.read(BLOCK):
                    size+=len(raw);require(size<=self.raw_bound,'Source expansion exceeds its actual bounded index')
                    for digest in hashes.values():digest.update(raw)
                    outgoing.write(raw)
            result.fd=SA.readonly_unlinked(target);result.fingerprint=dict(bytes=size,**{key:value.hexdigest()for key,value in hashes.items()})
            result._witness=_signature(os.fstat(result.fd))
        result.closed=False;return result

    def _check_tar_framing(self):
        """Bound PAX metadata before tarfile can allocate it; cover padding too."""
        with self.raw.open()as stream:
            offset=0;count=0;previous_pax=False;pax_size=None
            while offset<self.raw.fingerprint['bytes']:
                header=stream.read(512);require(len(header)==512,'Truncated original source TAR header')
                if header==b'\0'*512:
                    tail=header+stream.read(10240)
                    require(1024<=len(tail)<=10752 and not any(tail)and stream.read(1)==b''
                        and self.raw.fingerprint['bytes']%10240==0 and not previous_pax,
                        'Complete zero-only original TAR termination required')
                    return
                info=tarfile.TarInfo.frombuf(header,'utf-8','strict')
                require(info.type in(tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.SYMTYPE,tarfile.XHDTYPE)
                    and type(info.size)is int and 0<=info.size<=2*1024**3,
                    'Unsupported or unbounded original source TAR record')
                aligned=(info.size+511)//512*512;require(offset+512+aligned<=self.raw.fingerprint['bytes'],'Truncated original source TAR body')
                if info.type==tarfile.XHDTYPE:
                    require(not previous_pax and 0<info.size<=MAX_INDEX_LINE,'Bounded single original PAX header required')
                    body=stream.read(info.size);at=0;keys=set()
                    while at<len(body):
                        space=body.find(b' ',at);require(0<space-at<=10,'Original PAX length prefix differs')
                        number=body[at:space];require(number.isdigit()and not number.startswith(b'0'),'Canonical original PAX length required')
                        length=int(number);require(length>space-at+2 and at+length<=len(body),'Truncated original PAX field')
                        record=body[space+1:at+length];require(record.endswith(b'\n')and b'='in record,'Original PAX field framing differs')
                        key,value=record[:-1].split(b'=',1);require(key in(b'path',b'linkpath',b'size')and key not in keys,
                            'Unknown or duplicate original PAX metadata forbidden')
                        keys.add(key);value.decode('utf-8','strict')
                        if key==b'size':
                            require(value.isdigit()and len(value)<=10 and int(value)<=2*1024**3,'Bounded original PAX size required')
                            pax_size=int(value)
                        at+=length
                    previous_pax=True
                else:
                    require(pax_size is None or pax_size==info.size,'Original PAX/header size disagreement forbidden')
                    require(info.type!=tarfile.SYMTYPE or info.size==0,'Source symlink cannot conceal a data body')
                    stream.seek(info.size,io.SEEK_CUR);previous_pax=False;pax_size=None;count+=1
                    require(count<=MAX_SOURCE_FILES,'Original source TAR entry count exceeds bound')
                padding=stream.read(aligned-info.size);require(not any(padding),'Unaccounted source TAR padding bytes forbidden')
                offset+=512+aligned
        raise ValueError('Original source TAR lacks complete EOF padding')

    def _lines(self):
        with self.index.open()as stream:
            for _ in range(MAX_SOURCE_FILES+1):
                line=stream.readline(MAX_INDEX_LINE+1)
                if not line:return
                require(len(line)<=MAX_INDEX_LINE and line.endswith(b'\n'),'Bounded complete original source-index line required')
                yield unique_json(line,limit=MAX_INDEX_LINE)
            raise ValueError('Source-index count exceeds its bound')

    def _expansion_bound(self):
        count=0;bound=10240
        for row in self._lines():
            name=portable(row['path']);size=row['bytes'];mode=row['mode']
            require(type(size)is int and size>=0 and mode in('100644','100755','120000'),
                'Source capacity row differs')
            pax=1024+2*len(name.encode('utf-8'))+(2*size if mode=='120000'else 0)
            payload=0 if mode=='120000'else size
            bound+=512+(payload+511)//512*512+512+(pax+511)//512*512;count+=1
            require(bound<=MAX_RAW_SOURCE,'Source capacity exceeds fixed raw-byte limit')
        require(count==self.manifest['files'],'Source capacity index count differs');return bound

    @contextmanager
    def open_archive(self):
        with self.raw.open()as stream,tarfile.open(fileobj=stream,mode='r|')as archive:yield archive

    def verify(self):
        """Original complete source predicates, without delegating a path reopen."""
        self._check_identity()
        p=packer();m=self.manifest;roots={row['name']:row for row in m['roots']}
        require(len(roots)==len(m['roots'])and'orchestration'in roots,'Unique complete source roots and orchestration required')
        for name in roots:require(portable(name)==name and '/'not in name,'Ordinary source root name required')
        orchestration=roots['orchestration']
        require(orchestration.get('kind')=='git'and orchestration.get('commit')==self.expected['projectCommit'],
            'Archived orchestration belongs to another actual project commit')
        counts={name:0 for name in roots};names=set();total=0
        allowed={name:p.pristine_crlf_paths(root)for name,root in roots.items()}
        baselines={name:{row['path']:{'mode':row['mode'],'blob':row['blob']}for row in root.get('deleted',[])}for name,root in roots.items()}
        rows=iter(self._lines())
        with self.open_archive()as archive:
            for member in archive:
                archive.members.clear()
                row=next(rows,None);require(row is not None,'Source archive has an unindexed entry')
                name=portable(member.name);require(row['path']==name and name not in names and '/'in name,
                    'Source archive order, unique indexed name or membership differs')
                root,relative=name.split('/',1);require(root in roots,'Source member belongs to an undeclared root')
                names.add(name);require(len(names)<=MAX_SOURCE_FILES,'Source count exceeds bound')
                require(type(row.get('bytes'))is int and row['bytes']>=0,'Exact indexed source length required')
                hashes={key:hashlib.new(key)for key in FP[1:]};size=0
                blob=hashlib.sha1(b'blob '+str(row['bytes']).encode()+b'\0')
                audited=relative in allowed[root]
                windows=bytearray()if(name.lower().endswith(('.cmd','.bat'))or audited)and row['bytes']<=8*1024**2 else None
                if row.get('baseline'):
                    require(relative not in baselines[root],'Deleted baseline also exists in source archive')
                    baselines[root][relative]=row['baseline']
                if row['mode']=='120000':
                    require(member.issym(),'Source symlink type differs')
                    raw=member.linkname.encode('utf-8');size=len(raw);blob.update(raw)
                    require(not member.linkname.startswith('/')and posixpath.normpath(posixpath.join(posixpath.dirname(name),member.linkname)).startswith(root+'/'),
                        'Source symlink escapes its original root')
                    if windows is not None:windows.extend(raw)
                    for digest in hashes.values():digest.update(raw)
                else:
                    require(member.isfile()and row['mode']in('100644','100755')
                        and member.mode&0o7777==(0o755 if row['mode']=='100755'else 0o644),
                        'Original source regular type/mode differs')
                    with archive.extractfile(member)as stream:
                        while raw:=stream.read(BLOCK):
                            size+=len(raw);require(size<=row['bytes'],'Source member exceeds indexed length')
                            blob.update(raw)
                            if windows is not None:windows.extend(raw)
                            for digest in hashes.values():digest.update(raw)
                require(size==row['bytes']and all(row.get(key)==value.hexdigest()for key,value in hashes.items()),
                    'Complete actual source member fingerprints differ: '+name)
                info=roots[root]
                if root=='orchestration'or info.get('role')in('source-for-reused-shared-input','source-for-serviced-imported-package'):
                    require(p.pristine_blob(row,blob.hexdigest(),bytes(windows)if windows is not None else None,audited),
                        'Original corresponding Git blob differs: '+name)
                counts[root]+=1;total+=1
        require(next(rows,None)is None and total==m['files']and all(counts[name]==root['files']for name,root in roots.items()),
            'Complete source archive/index/root counts differ')
        for name,root in roots.items():
            if root.get('role')=='source-for-serviced-imported-package':require(root.get('deleted')==[],'Serviced corresponding source cannot omit Git members')
            if root.get('kind')in('git','git-export'):
                raw=base64.b64decode(root['commitObjectBase64'],validate=True)
                require(hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==root['commit']
                    and raw.startswith(('tree '+root['tree']+'\n').encode()),'Source Git commit/tree object differs')
                for child in root.get('submodules',[]):
                    matches=[value for value in roots.values()if value['name']==child['root']and value.get('commit')==child['commit']]
                    require(len(matches)==1,'Pinned source submodule is missing')
                    if root.get('role')=='source-for-serviced-imported-package':require(matches[0].get('role')==root['role'],'Serviced submodule lost original source role')
                    baselines[name][child['path']]={'mode':'160000','blob':child['commit']}
                require(p.baseline_tree(baselines[name])==root['tree'],'Full source baseline does not reconstruct exact Git tree')
        self._verification=_SOURCE_VERIFIED
        self.result=dict(kind='sdk5-complete-immutable-source-archive-validation',files=total,identity=dict(self.expected),
            archive=dict(self.archive.fingerprint),index=dict(self.index.fingerprint),wholeProducerSourceClosure=False,
            qualificationAllowed=False,sourceAdmissionAllowed=False)
        self.result=_frozen(self.result);self._result_object=self.result
        self._result_raw=canonical(self.result)
        return dict(self.result)

    def select(self,names,*,max_total=64*1024**2,max_file=16*1024**2):
        self._check_identity()
        require(self.verified and type(names)is set and names and len(names)<=20000,'Verified closed source selection required')
        for name in names:portable(name)
        selected={};total=0;rows=iter(self._lines())
        with self.open_archive()as archive:
            for member in archive:
                archive.members.clear()
                row=next(rows,None);require(row is not None and row['path']==member.name,'Immutable source/index order differs')
                if member.name not in names:continue
                require(member.isfile()and member.name not in selected and 0<=member.size<=max_file
                    and row['mode']in('100644','100755')and member.mode&0o7777==(0o755 if row['mode']=='100755'else 0o644),
                    'Selected archived source must remain an exact ordinary file/mode')
                total+=member.size;require(total<=max_total,'Selected source byte budget exceeded before read')
                raw=archive.extractfile(member).read(max_file+1)
                require(fingerprint(raw)==fields(row),'Selected immutable source bytes differ')
                selected[member.name]=dict(raw=raw,row=row)
        require(selected.keys()==names,'Required actual indexed source member is missing')
        return selected

    def index_members(self,root_name,*,limit=20000):
        self._check_identity();require(self.verified,'Actual complete source verification required before index queries')
        require(portable(root_name)==root_name and '/'not in root_name and type(limit)is int and 0<limit<=MAX_SOURCE_FILES,
            'Closed original source root/count required')
        roots=[row for row in self.manifest['roots']if row['name']==root_name]
        require(len(roots)==1,'Registered actual source root is missing')
        result={};prefix=root_name+'/'
        for row in self._lines():
            if not row['path'].startswith(prefix):continue
            relative=portable(row['path'][len(prefix):]);require(relative not in result and len(result)<limit,
                'Bounded unique indexed source-root inventory required')
            result[relative]=row
        require(len(result)==roots[0]['files'],'Actual complete indexed source-root count differs')
        return result

    def assert_closed_root(self,root_name,expected_members,*,kind,role,commit=None):
        require(type(expected_members)is set and expected_members,'Exact expected original source-root inventory required')
        roots=[row for row in self.manifest['roots']if row['name']==root_name]
        require(len(roots)==1 and roots[0].get('kind')==kind and roots[0].get('role')==role
            and(commit is None or roots[0].get('commit')==commit),'Original source root kind/role/commit differs')
        actual=self.index_members(root_name)
        require(set(actual)==expected_members,'Original actual indexed source root has missing or extra members')
        return actual

    def assert_absent_members(self,root_name,forbidden_members):
        require(type(forbidden_members)is set,'Closed original forbidden-member set required')
        for name in forbidden_members:portable(name)
        actual=self.index_members(root_name)
        require(not(forbidden_members&actual.keys()),'Forbidden original member exists in the actual immutable source index')
        return dict(root=root_name,actualIndexedFiles=len(actual),forbiddenMembers=sorted(forbidden_members),
            absenceCheckedAgainstCompleteImmutableIndex=True)

    def root_for(self,original_path,*,kind,role):
        self._check_identity();require(self.verified,'Actual complete source verification required before root resolution')
        logical(original_path)
        matches=[row for row in self.manifest['roots']if row.get('originalPath')==original_path
            and row.get('kind')==kind and row.get('role')==role]
        require(len(matches)==1,'One actual original source root/path/kind/role required')
        return unique_json(canonical(matches[0]))

    def mint_members(self,names,*,budget,max_total=64*1024**2):
        selected=self.select(names,max_total=max_total,max_file=MEMORY_FILE);roots={row['name']:row for row in self.manifest['roots']};result={}
        for member,value in selected.items():
            root_name,relative=member.split('/',1);root=roots[root_name];row=value['row']
            require(row['mode']in('100644','100755')and isinstance(root.get('role'),str),
                'Original regular source member and registered role required for provenance')
            original=logical(root['originalPath'])+'/'+relative
            snapshot=Snapshot.from_bytes(value['raw'],fields(row),budget=budget,category='public')
            result[member]=VerifiedOrigin(_ORIGIN_FACTORY,self,snapshot,kind='source',root=root_name,member=member,
                role=root['role'],mode=0o755 if row['mode']=='100755'else 0o644,original=original)
        return result

    def mint_delivery_root(self,delivery,root_name):
        """Couple verified index membership to already captured identical D bytes."""
        require(type(delivery)is DeliverySession and delivery.source is self,'Same actual source/delivery sessions required')
        delivery.check();roots=[row for row in self.manifest['roots']if row['name']==root_name]
        require(len(roots)==1 and roots[0].get('kind')=='tree'and isinstance(roots[0].get('role'),str),
            'One actual indexed tree role required')
        root=roots[0];original=logical(root['originalPath']);prefix=delivery.original_delivery+'/'
        require(original.startswith(prefix),'Source tree must retain an exact original delivery path')
        result={}
        for relative,row in self.index_members(root_name).items():
            require(row['mode']in('100644','100755'),'Regular indexed delivery source members required')
            name=(original+'/'+relative)[len(prefix):];portable(name)
            require(name in delivery.snapshots and fields(row)==delivery._expected[name]
                and delivery.snapshots[name].fingerprint==fields(row),'Indexed source member differs from captured caller-bound delivery')
            result[relative]=VerifiedOrigin(_ORIGIN_FACTORY,self,delivery.snapshots[name],kind='source',root=root_name,
                member=root_name+'/'+relative,role=root['role'],mode=0o755 if row['mode']=='100755'else 0o644,
                original=original+'/'+relative)
        return result

    def close(self):
        self.raw.close()
        for snapshot in getattr(self,'_owned',[]):snapshot.close()

    def require_orchestration(self,context):
        require(self.verified and self.expected['projectCommit']==context['projectCommit'],
            'Original normal context requires this actual verified source project')
        sources=N.execution_sources(context.get('referenceBootstrap'))
        require(context['sources']==sources,'Original normal executed code differs from reviewed current source identities')
        selected=self.select({'orchestration/scripts/'+name for name in sources},max_total=16*1024**2,max_file=8*1024**2)
        origins={}
        for name,want in sources.items():
            member='orchestration/scripts/'+name;value=selected[member];row=value['row'];raw=value['raw']
            blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
            require(fingerprint(raw)==want and row.get('baseline')==dict(mode=row['mode'],blob=blob)
                and row['mode']in('100644','100755')
                and bool((ROOT/'scripts'/name).stat().st_mode&0o111)==(row['mode']=='100755'),
                'Original normal orchestration Git bytes or executable mode differ')
            origins[name]=dict(indexPath=member,mode=row['mode'],gitBlob=blob,**want)
        return dict(kind='actual-archived-normal-orchestration-source-bindings',projectCommit=context['projectCommit'],sources=origins,
            wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)


class VerifiedOrigin:
    """Factory-only actual source/index or caller-bound delivery provenance."""
    def __init__(self,token,source,snapshot,*,kind,root,member,role,mode,original,delivery=None):
        require(token is _ORIGIN_FACTORY and type(source)is SourceSession and source.verified
            and type(snapshot)is Snapshot and kind in('source','delivery','external')and mode in(0o644,0o755),
            'Only actual authenticated origin factories may mint mappings')
        self._token=token;self.source=source;self.snapshot=snapshot;self.kind=kind
        self.root=root;self.member=member;self.role=role;self.mode=mode;self.original=original;self.delivery=delivery
        self._fingerprint=tuple(snapshot.fingerprint[key]for key in FP)
        self._archive=tuple(source.archive.fingerprint[key]for key in FP);self._index=tuple(source.index.fingerprint[key]for key in FP)
        self._binding=(kind,root,member,role,mode,original,id(source),id(snapshot),id(delivery))

    def metadata(self):
        require(self._token is _ORIGIN_FACTORY and self.source.verified and not self.snapshot.closed,
            'Live actual archived mapping origin required')
        require(self._binding==(self.kind,self.root,self.member,self.role,self.mode,self.original,id(self.source),id(self.snapshot),id(self.delivery)),
            'Verified archived origin binding changed after minting')
        self.source._check_identity()
        require(tuple(self.source.archive.fingerprint[key]for key in FP)==self._archive
            and tuple(self.source.index.fingerprint[key]for key in FP)==self._index
            and tuple(self.snapshot.fingerprint[key]for key in FP)==self._fingerprint,
            'Source/index/member identity changed after provenance minting')
        record=None
        if self.kind=='delivery':
            require(type(self.delivery)is DeliverySession and self.delivery.source is self.source,
                'Actual same-session delivery provenance required')
            self.delivery.check();record=dict(self.delivery.record_fingerprint)
        return dict(kind=self.kind,archive=dict(zip(FP,self._archive)),index=dict(zip(FP,self._index)),
            root=self.root,member=self.member,role=self.role,mode=self.mode,fingerprint=dict(zip(FP,self._fingerprint)),
            originalArchivedPath=self.original,recordFingerprint=record)


class DeliverySession:
    """Complete actual file captures bound to the caller-authenticated inventory."""
    def __init__(self):
        self.source=None;self.record=None;self.record_raw=None;self.record_fingerprint=None;self.original_delivery=None
        self.snapshots={};self.modes={};self._owned=[];self._modes_raw=None;self._original_delivery=None;self._minted=False

    @classmethod
    def capture(cls,release,record,source,original_delivery,*,budget,private_root):
        require(type(source)is SourceSession and source.verified,'Complete actual source session required for delivery capture')
        source._check_identity();release=ordinary(release,directory=True);private_root=ordinary(private_root,directory=True)
        require(release!=private_root and release not in private_root.parents and private_root not in release.parents,
            'Delivery snapshot storage must stay outside actual delivery')
        logical(original_delivery);raw=canonical(record);require(len(raw)<=MAX_JSON,'Bounded caller-authenticated delivery record required')
        record=unique_json(raw)
        require(all(record.get(key)==value for key,value in source.expected.items()),'Caller-bound delivery/source run/commit/RID identity differs')
        rows=record.get('files');require(type(rows)is list and 0<len(rows)<=20000,'Complete bounded caller-authenticated delivery inventory required')
        expected={}
        for row in rows:
            require(type(row)is dict and set(row)=={'path',*FP},'Exact actual delivery file descriptor required')
            name=portable(row['path']);require(name not in expected and name!='producer-validation.json','Unique original delivery descriptor required')
            expected[name]=fields(row)
        actual=set()
        for parent,dirs,files in os.walk(release,followlinks=False):
            for name in dirs:ordinary(Path(parent)/name,directory=True)
            for name in files:actual.add(ordinary(Path(parent)/name,file=True).relative_to(release).as_posix())
            require(len(actual)<=20001,'Actual delivery exceeds its complete file bound')
        require(actual in(set(expected),set(expected)|{'producer-validation.json'}),'Actual delivery has missing/unbound file paths')
        result=cls();result.source=source;result.record=record;result.record_raw=raw;result.record_fingerprint=fingerprint(raw)
        result.original_delivery=original_delivery;result._original_delivery=original_delivery
        manifest=source.manifest
        reused={'sources/'+manifest['archive']['path']:source.archive,'sources/'+manifest['index']['path']:source.index}
        require(set(reused)|{'sources/source-manifest.json','reports/ci/used-source.json'}<=expected.keys(),
            'Caller delivery inventory must bind every actual source artifact/control')
        try:
            for name,want in expected.items():
                path=ordinary(release/name,file=True);mode=stat.S_IMODE(path.stat().st_mode)
                require(mode in((0o644,0o755)if os.name=='posix'else(0o444,0o666)),
                    'Ordinary actual delivery file mode required')
                if name in reused:
                    snapshot=reused[name];require(snapshot.fingerprint==want,'Caller inventory/source snapshot identity differs')
                elif name in('sources/source-manifest.json','reports/ci/used-source.json'):
                    require(fingerprint(source.manifest_raw)==want,'Actual inventoried source-manifest identity differs')
                    snapshot=Snapshot.from_bytes(source.manifest_raw,want,budget=budget,category='public');result._owned.append(snapshot)
                else:
                    snapshot=Snapshot.capture(path,want,budget=budget,category='public',private_root=private_root);result._owned.append(snapshot)
                result.snapshots[name]=snapshot;result.modes[name]=mode if os.name=='posix'else 0o644
            if 'producer-validation.json'in actual:
                path=ordinary(release/'producer-validation.json',file=True);require(path.stat().st_size<=MAX_JSON,'Bounded actual producer record required')
                observed=unique_json(path.read_bytes())
                require(observed==record or(set(record)==set(observed)|{'sdk'}and all(record[key]==value for key,value in observed.items())
                    and 'producer-sdk.json'in result.snapshots
                    and unique_json(result.snapshots['producer-sdk.json'].bytes())['sdk']==record['sdk']),
                    'Actual sealed producer record differs from caller record/actual normalized SDK descriptor')
            result.record=_frozen(result.record);result.modes=_frozen(result.modes);result.snapshots=_FrozenDict(result.snapshots)
            result._expected=_frozen(expected)
            result._identity_objects=(result.record,result.record_raw,result.record_fingerprint,result.modes,result.snapshots)
            result._record_identity=tuple(result.record_fingerprint[key]for key in FP)
            result._modes_raw=canonical(result.modes);result.check();return result
        except BaseException:
            result.close();raise

    def check(self):
        require(type(self.source)is SourceSession and self.source.verified
            and all(a is b for a,b in zip(self._identity_objects,(self.record,self.record_raw,self.record_fingerprint,self.modes,self.snapshots)))
            and tuple(self.record_fingerprint[key]for key in FP)==self._record_identity
            and self.original_delivery==self._original_delivery,'Caller-bound delivery record changed')
        self.source._check_identity()

    def mint(self,relative):
        self.check();relative=portable(relative);require(relative in self.snapshots,'Required actual delivery member is unbound')
        require(self.snapshots[relative].fingerprint==self._expected[relative]and not self.snapshots[relative].closed,
            'Actual captured delivery member no longer matches its caller inventory')
        self._minted=True
        return VerifiedOrigin(_ORIGIN_FACTORY,self.source,self.snapshots[relative],kind='delivery',root=self.original_delivery,
            member=relative,role='caller-bound-delivery-file',mode=self.modes[relative],
            original=self.original_delivery+'/'+relative,delivery=self)

    def _couple_source_modes(self,origins):
        """Source index, rather than download transport, authenticates file modes."""
        self.check();require(not self._minted,'Source modes must be authenticated before first delivery provenance mint')
        modes=dict(self.modes)
        for relative,origin in origins.items():
            require(type(origin)is VerifiedOrigin and origin.source is self.source,'Actual same-session source mode witness required')
            metadata=origin.metadata()
            require(metadata['kind']=='source'and metadata['originalArchivedPath']==self.original_delivery+'/'+relative
                and metadata['fingerprint']==self._expected[relative],'Exact indexed delivery mode origin required')
            modes[relative]=metadata['mode']
        self.modes=_frozen(modes);self._modes_raw=canonical(modes)
        self._identity_objects=(self.record,self.record_raw,self.record_fingerprint,self.modes,self.snapshots)
        return self

    def close(self):
        for snapshot in self._owned:snapshot.close()


class ReconstructedApp:
    """Factory capability after full real App inputs/BOOT/compiler predicates."""
    def __init__(self,token,*,source,view,workspace,host_roots,normal_context,application,delivery,public_root,
        public_source_root,record,capture_source_root=None):
        require(token is _RECONSTRUCTED_FACTORY,'Only actual completed reconstruction may mint an App capability')
        self._token=token;self.source=source;self.view=view;self.workspace=workspace;self.host_roots=host_roots
        self.normal_context=normal_context;self.application=application;self.delivery=delivery;self.public_root=public_root
        self.public_source_root=public_source_root;self.record=record;self.capture_source_root=capture_source_root
        self._references=(source,view,delivery)
        self._facts=self._canonical_facts()

    def _canonical_facts(self):
        return canonical(dict(application=self.application,normal_context=self.normal_context,record=self.record,
            workspace=str(self.workspace),host_roots={key:str(value)for key,value in self.host_roots.items()},
            public_root=str(self.public_root),public_source_root=self.public_source_root,capture_source_root=self.capture_source_root))

    def close(self):
        _close_origins(self.view);self.view.close();self.delivery.close();self.source.close()


def require_reconstructed(value):
    require(type(value)is ReconstructedApp and value._token is _RECONSTRUCTED_FACTORY
        and type(value.source)is SourceSession and value.source.verified
        and type(value.view)is FrozenView and value.view.frozen and value.view.source is value.source
        and type(value.delivery)is DeliverySession and value.delivery.source is value.source,
        'Actual completed same-session App reconstruction capability required; saved proofs are insufficient')
    require(value._references==(value.source,value.view,value.delivery)and value._facts==value._canonical_facts(),
        'Completed reconstruction facts or original/physical mappings changed after minting')
    value.source._check_identity();value.delivery.check();return value


def _archive_identity(receipt,role,architecture):
    BYTE.constructor_policy();pin=BYTE.C.pin(role,architecture)
    require(type(receipt)is dict and set(receipt)==set(pin)|set(FP)
        and {key:receipt[key]for key in pin}==pin and 0<receipt['bytes']<=512*1024**2,
        'Exact official original compiler archive role/CPU/pin/receipt required')
    fields(receipt);return dict(receipt)


def capture_original_archive(path,receipt,role,architecture,*,budget,private_root):
    expected=_archive_identity(receipt,role,architecture)
    # Count the actual incoming original as touched as well as the new captured
    # snapshot. No incoming-path reopen can establish later consumed bytes.
    budget.reserve(expected['bytes'],'private',file=False)
    snapshot=Snapshot.capture(path,fields(expected),budget=budget,category='private',private_root=private_root)
    return snapshot,expected


def inventory_original_stream(snapshot,receipt,role,architecture,*,prefix=None):
    """All original BYTE inventory predicates over the actual owned stream."""
    expected=_archive_identity(receipt,role,architecture)
    require(type(snapshot)is Snapshot and snapshot.fingerprint==fields(expected)
        and prefix==(BYTE.PREFIX if role=='runtime'else None),
        'Actual complete owned snapshot and exact original matching-runtime prefix required')
    files={};seen=set();total=0
    with snapshot.open()as stream,tarfile.open(fileobj=stream,mode='r|gz')as archive:
        for entry in archive:
            archive.members.clear()
            name=BYTE.C.member_name(entry.name.rstrip('/')if entry.isdir()else entry.name)
            require(entry.isfile()or entry.isdir(),'Original compiler archive links/devices are forbidden')
            require(entry.mode>=0 and not entry.mode&0o7000,'Original compiler archive special modes are forbidden')
            if name is None:
                require(entry.isdir(),'Only original archive root directory may omit its name');continue
            if entry.isdir():continue
            require(name not in seen and 0<=entry.size<=256*1024**2,'Unique bounded original compiler member required')
            seen.add(name);total+=entry.size
            require(total<=2*1024**3 and len(seen)<=100000,'Bounded complete original compiler inventory required')
            if prefix is not None and not name.startswith(prefix):continue
            hashes={key:hashlib.new(key)for key in FP[1:]};size=0
            with archive.extractfile(entry)as incoming:
                while raw:=incoming.read(BLOCK):
                    size+=len(raw);require(size<=entry.size,'Original compiler member grew')
                    for digest in hashes.values():digest.update(raw)
            require(size==entry.size,'Complete actual original compiler member bytes required')
            files[name]=dict(mode=entry.mode&0o777,bytes=size,**{key:value.hexdigest()for key,value in hashes.items()})
    require(files,'Original complete compiler inventory is empty')
    return expected,files


def materialize_inventory(snapshot,receipt,role,architecture,inventory,destination,*,budget,prefix=None,existing_inventory=None):
    """Re-read one immutable stream; reject whole budget before first write."""
    require(os.name=='posix','Original compiler file/mode reconstruction requires POSIX')
    _,actual=inventory_original_stream(snapshot,receipt,role,architecture,prefix=prefix)
    require(type(inventory)is dict and actual==inventory,'Materialized inventory must equal independently consumed original bytes')
    destination=ordinary(destination)
    if existing_inventory is None:
        require(not destination.exists(),'Fresh exclusive original compiler view required');base={}
    else:
        require(type(existing_inventory)is dict and destination.is_dir()
            and BYTE.actual_tree(destination)==existing_inventory and not(existing_inventory.keys()&inventory.keys()),
            'Explicit complete existing compiler inventory must match and remain disjoint')
        base=dict(existing_inventory)
    require(budget.files+len(inventory)<=budget.file_limit,'Original compiler view file budget exceeded before first write')
    budget.reserve(sum(row['bytes']for row in inventory.values()),'private',file=False);budget.files+=len(inventory)
    if not destination.exists():destination.mkdir(parents=True)
    written={}
    with snapshot.open()as stream,tarfile.open(fileobj=stream,mode='r|gz')as archive:
        for entry in archive:
            archive.members.clear()
            name=BYTE.C.member_name(entry.name.rstrip('/')if entry.isdir()else entry.name)
            if name not in inventory:continue
            require(entry.isfile()and name not in written,'One actual original materialized compiler member required')
            row=inventory[name];require(entry.size==row['bytes']and entry.mode&0o777==row['mode'],
                'Actual original member/mode changed in immutable view')
            target=ordinary(destination/name);require(not target.exists(),'Original compiler member would overwrite a prior entry')
            target.parent.mkdir(parents=True,exist_ok=True);hashes={key:hashlib.new(key)for key in FP[1:]};size=0
            with archive.extractfile(entry)as incoming,target.open('xb')as outgoing:
                while raw:=incoming.read(BLOCK):
                    size+=len(raw);require(size<=row['bytes'],'Actual materialized compiler member grew')
                    for digest in hashes.values():digest.update(raw)
                    outgoing.write(raw)
            require(dict(bytes=size,**{key:value.hexdigest()for key,value in hashes.items()})==fields(row),
                'Materialized compiler body differs from the same immutable source stream')
            target.chmod(row['mode']);written[name]=row
    require(written==inventory and BYTE.actual_tree(destination)==dict(base,**inventory),
        'Complete actual original compiler view bytes/modes differ')
    return dict(kind='scoped-materialized-original-compiler-archive-view',role=role,architecture=architecture,
        files=len(inventory),bytes=sum(row['bytes']for row in inventory.values()),archive=expected_archive_fields(receipt),
        wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)


def expected_archive_fields(receipt):return {key:receipt[key]for key in FP}


NORMAL_FILES=('normal-context.json','normal-prepared.json','normal-container-invocation.json',
    'normal-container-result.json','normal-app-stage.json','normal-container.log','finite-reference-prepared.json')
COMPILER_FILES=('obj/Microsoft.ApplicationInsights.dll','reader-obj/Debug/net6.0/Reader.dll',
    'reader-obj/Debug/net6.0/.NETCoreApp,Version=v6.0.AssemblyAttributes.cs',
    'reader-obj/Debug/net6.0/Reader.AssemblyInfo.cs','reader-obj/Debug/net6.0/Reader.GlobalUsings.g.cs')


def public_app_members():
    """The existing publication's complete closed name set, including export5."""
    strong,worker=N.original_validators()
    output={'actual-app-process.json','actual-reader-build-process.json','actual-reader-processes.json',
        'app-build.log','reader-build.log','app-reader.log','reader-build-reader.log','app.binlog','reader-build.binlog',
        'worker-completed.json','genuine-normal-package.json','reader/Reader.dll',
        'replay/app-status.json','replay/app-tasks.jsonl','replay/reader-build-status.json','replay/reader-build-tasks.jsonl',
        'app/Microsoft.ApplicationInsights.dll','app/Microsoft.ApplicationInsights.pdb','app/Microsoft.ApplicationInsights.xml'}
    output.update(R.IMPORTS.GENERATED);output.update(COMPILER_FILES)
    output.update(name[len('/output/'):]for name in strong.generated_metadata(worker.policy()))
    require(len(output)==29,'Closed original output29 inventory required')
    members={'product-source/'+name for name in R.policy()['publicInputNames']}
    members.update({'export-record.json','original-private-input-manifest.json','content-exclusion.json',
        'origin/historical-reference-notice.txt','product/'+N.PACKAGE,'finite-reference-use.json',
        'original-import-bindings.json','compiler-output-origins.json'})
    members.update('evidence/'+name for name in NORMAL_FILES)
    members.update('evidence/output/'+name for name in output)
    require(len(members)==493,'Closed original public493 inventory required')
    return members,output


def _bind_alias(view,original,relative,origin,*,container=None,category='private'):
    path=view.bind_origin(original,relative,origin,category=category)
    if container is not None:view.bind_origin(container,relative,origin,namespace='container',category=category)
    return path


def _external_inputs(view,source,attempt,external_inputs,*,budget,private_root):
    """Actual reacquired ZIP/NPK bodies mint only the closed nonshipping role."""
    p=R.policy();strong,worker=N.original_validators();original=worker.policy()
    require(type(external_inputs)is dict and set(external_inputs)=={'referenceZip','comparisonPackage','compilerArchives'},
        'Actual reacquired ZIP, comparison NPK and three compiler archives required')
    paths={key:ordinary(external_inputs[key],file=True)for key in('referenceZip','comparisonPackage')}
    require(paths['referenceZip']!=paths['comparisonPackage'],'Distinct actual external reference and comparison inputs required')
    pins={'reference.zip':p['referenceArchive'],'original.nupkg':original['originalPackage']['officialPackage']}
    origins={}
    for key,name in(('referenceZip','reference.zip'),('comparisonPackage','original.nupkg')):
        budget.reserve(pins[name]['bytes'],'private',file=False)
        snapshot=Snapshot.capture(paths[key],pins[name],budget=budget,category='private',private_root=private_root)
        try:
            origins[name]=VerifiedOrigin(_ORIGIN_FACTORY,source,snapshot,kind='external',root=R.ROLE,member=name,
                role=R.ROLE,mode=0o644,original='/inputs/'+name)
            _bind_alias(view,attempt+'/inputs/'+name,'app/inputs/'+name,origins[name],container='/inputs/'+name)
        except BaseException:
            snapshot.close();raise
    archive=view.path('/inputs/reference.zip',namespace='container')
    bodies={'reference-root/.NETPortable/v4.5/Profile/Profile7/'+name:raw
        for name,raw in worker.validate_reference_zip(archive,original).items()}
    bodies.update({'reference-root/.NETPortable/'+name:raw for name,raw in worker.reference_support(archive,original).items()})
    require(set(origins)|set(bodies)==set(p['privateInputFiles']),'Actual external ZIP must reproduce exactly private73 names')
    for name,raw in bodies.items():
        require(fingerprint(raw)==p['privateInputFiles'][name],'Actual reacquired reference member differs from fixed original bytes')
        snapshot=Snapshot.from_bytes(raw,p['privateInputFiles'][name],budget=budget,category='private')
        origin=VerifiedOrigin(_ORIGIN_FACTORY,source,snapshot,kind='external',root=R.ROLE,member=name,role=R.ROLE,
            mode=0o644,original='/inputs/'+name);origins[name]=origin
        _bind_alias(view,attempt+'/inputs/'+name,'app/inputs/'+name,origin,container='/inputs/'+name)
    require(all(origin.snapshot.fingerprint==p['privateInputFiles'][name]for name,origin in origins.items()),
        'Every finite nonshipping private input must equal its actual reacquired policy body')
    return origins


def _bootstrap_views(view,delivery,external_inputs,*,budget,private_root,architecture):
    snapshots={}
    try:return _bootstrap_views_impl(view,delivery,external_inputs,budget=budget,private_root=private_root,
        architecture=architecture,snapshots=snapshots)
    finally:
        for snapshot in snapshots.values():snapshot.close()


def _bootstrap_views_impl(view,delivery,external_inputs,*,budget,private_root,architecture,snapshots):
    """Reproduce both full BOOT trees from immutable actual original archives."""
    archives=external_inputs['compilerArchives']
    require(type(archives)is dict and set(archives)=={'legacy5','runtime','vstest'},'Three distinct original compiler roles required')
    paths={key:ordinary(value,file=True)for key,value in archives.items()}
    require(len(set(paths.values()))==3,'Compiler original roles must use three distinct actual files')
    receipt5=unique_json(delivery.snapshots['reports/prepare/bootstrap5-composition.json'].bytes())
    receipt6=unique_json(delivery.snapshots['reports/prepare/bootstrap6.json'].bytes())
    receipts={'legacy5':receipt5['sdkArchive'],'runtime':receipt5['matchingRuntimeArchive'],'vstest':receipt6['archive']}
    inventories={};identities={}
    for role in('legacy5','runtime','vstest'):
        snapshot,expected=capture_original_archive(paths[role],receipts[role],role,architecture,budget=budget,private_root=private_root)
        snapshots[role]=snapshot
        identities[role],inventories[role]=inventory_original_stream(snapshot,expected,role,architecture,
            prefix=BYTE.PREFIX if role=='runtime'else None)
    fifth=view.root/'bootstrap5';sixth=view.root/'bootstrap6'
    materialize_inventory(snapshots['legacy5'],receipts['legacy5'],'legacy5',architecture,inventories['legacy5'],fifth,budget=budget)
    materialize_inventory(snapshots['runtime'],receipts['runtime'],'runtime',architecture,inventories['runtime'],fifth,
        budget=budget,prefix=BYTE.PREFIX,existing_inventory=inventories['legacy5'])
    materialize_inventory(snapshots['vstest'],receipts['vstest'],'vstest',architecture,inventories['vstest'],sixth,budget=budget)
    adaptations=[];actual5=dict(inventories['legacy5'],**inventories['runtime'])
    for component in('crypto','trace'):
        library,support=BYTE.native_support(view.release_root/'reports/prepare'/('bootstrap-'+component),component,architecture)
        name=BYTE.PREFIX+BYTE.C.SUPPORT[component]
        require(name in inventories['runtime'],'Exact matching framework native counterpart required')
        adaptation=dict(path=name,originalOfficial=fields(inventories['runtime'][name]),**support);adaptations.append(adaptation)
        relative=library.relative_to(view.release_root).as_posix()
        require(relative in delivery.snapshots and delivery.snapshots[relative].fingerprint==fields(support['library']),
            'Actual source-native bootstrap replacement must be in authenticated captured D')
        target=ordinary(fifth/name,file=True)
        require(N.fingerprint(target)==fields(inventories['runtime'][name]),'Original replacement target changed before exact substitution')
        raw=delivery.snapshots[relative].bytes(MEMORY_FILE);budget.reserve(len(raw),'private')
        target.write_bytes(raw);target.chmod(0o755)
        require(N.fingerprint(target)==fields(support['library']),'Exact original source-native substitution body differs')
        actual5[name]=dict(mode=0o755,**fields(support['library']))
    expected5=BYTE.composition(inventories['legacy5'],inventories['runtime'],identities['legacy5'],identities['runtime'],adaptations,architecture)
    expected6=dict(kind='official-private-component-compiler-bootstrap',archive=identities['vstest'],files=inventories['vstest'],payloadRole=False,qualificationAllowed=False)
    require(receipt5==expected5 and receipt6==expected6,'Actual original BOOT composition receipts differ from independently consumed originals/support')
    require(BYTE.actual_tree(fifth)==actual5 and BYTE.actual_tree(sixth)==inventories['vstest'],
        'Actual complete reconstructed BOOT5/BOOT6 bytes and modes differ')
    view.declare_root('/bootstrap','bootstrap5',namespace='container',role='bootstrap')
    view.declare_root('/inspector','bootstrap6',namespace='container',role='inspector')
    view.adopt_inventory('/bootstrap','bootstrap5',actual5);view.adopt_inventory('/inspector','bootstrap6',inventories['vstest'])
    return dict(kind='actual-immutable-three-original-archive-dual-BOOT-reconstruction',originalArchives=identities,
        actualBootstrapTreesCompared=True,sdk5Files=len(actual5),inspectorFiles=len(inventories['vstest']),
        nativeSupportProducts={row['component']:row['library']for row in adaptations},
        nativeSourceValidationStillRequired=True,wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)


def _capture_view(view,source,capture_source_root,*,budget):
    import musl_legacy5_appinsights_capture as C
    require(isinstance(capture_source_root,str),'Explicit actual indexed capture source root required')
    roots=[row for row in source.manifest['roots']if row['name']==capture_source_root]
    require(len(roots)==1 and roots[0].get('kind')=='tree'and roots[0].get('role')==C.KIND,
        'One exact actual consumption-capture source tree required')
    original=logical(roots[0]['originalPath']);members=source.index_members(capture_source_root)
    origins=source.mint_members({capture_source_root+'/'+name for name in members},budget=budget,max_total=C.MAX_TOTAL)
    view.declare_root(original,'capture',role='consumption-capture')
    for name in members:view.bind_origin(original+'/'+name,'capture/'+name,origins[capture_source_root+'/'+name],category='public')
    C.validate_data(view.root_path('consumption-capture'))
    index=unique_json(view.read(original+'/capture-index.json',C.MAX_FILE));closed={'capture-index.json',*(row['member']for row in index['originalLogicalPaths'].values())}
    source.assert_closed_root(capture_source_root,closed,kind='tree',role=C.KIND)
    view.declare_root(C.MOUNT,'consumer-sdk',namespace='consumer',role='consumer-sdk')
    view.declare_root('/work/inputs/bootstrap-feed','consumer-feed',namespace='consumer',role='consumer-feed')
    for logical_path,row in index['originalLogicalPaths'].items():
        require(fields(row)==origins[capture_source_root+'/'+row['member']].snapshot.fingerprint,
            'Original capture observation differs from actual indexed content')
        relative=('consumer-feed/'+C.M.PACKAGE if logical_path=='/work/inputs/bootstrap-feed/'+C.M.PACKAGE
            else 'consumer-sdk/'+C._logical(logical_path))
        view.bind_origin(logical_path,relative,origins[capture_source_root+'/'+row['member']],namespace='consumer',category='public')
    return dict(root=capture_source_root,originalPath=original,logicalPaths=len(index['originalLogicalPaths']))


def _original_descriptor(view,original):
    return dict(path=original,**view.entries[view._key(original,'host')]['fingerprint'])


def _original_boundary_fields(view,bound,validated):
    """Compare original retained fields; never relabel reconstructed host paths."""
    require(validated['normalAppWorkerBoundaryValidated']is True and validated['parentSdkBuildValidated']is True,
        'Actual archived normal/parent predicates must pass before original fields are compared')
    context=bound['context'];attempt=context['paths']['attempt'];D=context['paths']['delivery'];diag=context['paths']['diagnostics']
    evidence={name:view.entries[view._key(name,'host')]['fingerprint']for name in validated['engineSecurityOrigins']
        if posixpath.dirname(name)in(diag,D+'/reports/prepare')}
    return dict(kind='normal-App5-Docker-boundary',context=context,
        **{key:_original_descriptor(view,attempt+'/'+name)for key,name in(('invocation','normal-container-invocation.json'),
            ('result','normal-container-result.json'),('stage','normal-app-stage.json'))},
        securityReports={name:_original_descriptor(view,diag+'/'+name)for name in('process-status.txt','apparmor-current.txt','exit-code.txt')},
        preflightOrdinaryEngineSecurityEvidence=evidence,allInspectedStageEvidenceCheckedBeforeReads=True,
        parentSdkBuildValidated=False,normalAppWorkerBoundaryValidated=True)


def _compiler_original_fields(record,workspace,attempt,role):
    """One fixed final-output path has separate original and physical witnesses."""
    suffix='app/Microsoft.ApplicationInsights.dll'if role=='app'else'reader/Reader.dll'
    physical=workspace/'output'/suffix
    require(record['finalOutput']==dict(path=str(physical),**N.fingerprint(physical)),
        'Actual compiler final output must be the fixed reconstructed ordinary body')
    result=dict(record);result['finalOutput']=dict(path=attempt+'/output/'+suffix,**fields(record['finalOutput']))
    return result


def _compiler_origins(view,workspace,bound,execution,imports):
    I=R.IMPORTS;attempt=bound['context']['paths']['attempt'];rows={};total=0
    for role,key,compiled,generated in(('app','appCompiler',COMPILER_FILES[0],()),
        ('reader-build','readerCompiler',COMPILER_FILES[1],COMPILER_FILES[2:])):
        record=execution[key];log=imports['logs'][role];expected=I.policy()['logs'][role]
        require(record['projectFile']==expected['project']and record['taskFile']==expected['compilerTarget']
            and record['compiledOutput']['path']=='/output/'+compiled and log['actualMountedInputBytesCompared']is True,
            'Original Csc project/target/intermediate/import identity differs')
        if generated:require({name for name in record['sources']if name.startswith('/output/')}=={'/output/'+name for name in generated},
            'Exactly three actual Reader generated source paths required')
        parts=record['context'].split(':')
        require(len(parts)==4 and len(record['context'])<=128 and all(str(int(part))==part for part in parts),
            'Original exact Csc context required')
        command=record['commandLine'];require(isinstance(command,str)and 0<len(command)<=1024**2,'Bounded actual Csc argv required')
        for name in(compiled,*generated):
            want=fields(record['compiledOutput'])if name==compiled else identity(record['sources']['/output/'+name])
            require(0<want['bytes']<=MEMORY_FILE and N.fingerprint(workspace/'output'/name)==want,
                'Actual retained intermediate/generated source body differs from original Csc')
            total+=want['bytes'];require(total<=16*1024**2,'Compiler output5 bound exceeded')
            rows[name]=dict(originalLogicalPath='/output/'+name,originalPhysicalPath=attempt+'/output/'+name,
                fingerprint=want,originalMode=stat.S_IMODE((workspace/'output'/name).stat().st_mode),
                role='compiled-output'if name==compiled else'generated-reader-source',compilerRole=role,
                cscContext=record['context'],projectFile=record['projectFile'],taskFile=record['taskFile'],
                commandLineFingerprint=I.fingerprint(command.encode()),rawBinlog=dict(path='/output/'+role+'.binlog',**log['binlog']))
    return dict(kind='scoped-actual-normal-App-compiler-output-origins',normalContext=_original_descriptor(view,attempt+'/normal-context.json'),
        normalSourceBoundary={key:execution['boundary'][key]for key in('invocation','result','stage')},files=rows,
        actualCurrentFilesCompared=True,originalReportPathsRewritten=False,parentSdkBuildValidated=False,
        archivedConstructionValidated=False,wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)


def validate_package_bytes(raw,bodies):
    """Compare every byte with N's unchanged deterministic ZIP writer."""
    require(type(raw)is bytes and 0<len(raw)<=MEMORY_FILE and type(bodies)is dict
        and set(bodies)=={'Microsoft.ApplicationInsights.nuspec','LICENSE',
            'lib/dotnet5.4/Microsoft.ApplicationInsights.dll','lib/dotnet5.4/Microsoft.ApplicationInsights.pdb',
            'lib/dotnet5.4/Microsoft.ApplicationInsights.xml'}
        and all(type(value)is bytes and value for value in bodies.values())
        and sum(map(len,bodies.values()))<=MEMORY_FILE,'Bounded exact five ordinary App package bodies required')
    expected=io.BytesIO()
    with zipfile.ZipFile(expected,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6)as archive:
        for name,body in sorted(bodies.items()):
            entry=zipfile.ZipInfo(name,(1980,1,1,0,0,0));entry.create_system=3;entry.external_attr=0o100644<<16;entry.compress_type=zipfile.ZIP_DEFLATED
            archive.writestr(entry,body)
    require(raw==expected.getvalue(),'Whole actual App NPK must equal the unchanged deterministic five-member writer')
    return {name:fingerprint(body)for name,body in bodies.items()}


def _validate_application(view,workspace,host_roots,bound,normal_boundary,bootstrap):
    """Run original pure compiler/API guards, then compare unchanged saved fields."""
    strong,worker=N.original_validators();I=R.IMPORTS;attempt=bound['context']['paths']['attempt'];output=workspace/'output'
    inputs=R.verify_private_inputs(workspace);processes=N.validate_process_records(output)
    actual={role:strong.compiler_record(workspace,role,host_roots)for role in('app','reader-build')}
    boundary=_original_boundary_fields(view,bound,normal_boundary)
    execution=dict(kind='actual-normal-offline-App5-and-frozen-reader-execution',boundary=boundary,
        appCompiler=_compiler_original_fields(actual['app'],workspace,attempt,'app'),
        readerCompiler=_compiler_original_fields(actual['reader-build'],workspace,attempt,'reader-build'),**processes,
        originalStrongValidator=N.STRONG_SOURCE,immutableOriginalWorkerSources=strong.WORKER_SOURCES,
        readerActuallyExecuted=True,referenceInputPreferredSourceAndLicenseClosure=False,wholeProducerSourceClosure=False,
        oldBinarySourceAttributed=False,publisherSigningClaimed=False,qualificationAllowed=False,sourceAdmissionAllowed=False)
    logs={}
    for role,key,compiler in(('app','rawAppBinlog','appCompiler'),('reader-build','rawReaderBuildBinlog','readerCompiler')):
        path=output/(role+'.binlog');require(path.stat().st_size<=I.MAX_COMPRESSED,'Bounded original binlog required')
        logs[role]=I.validate_log(path.read_bytes(),role,execution[key],host_roots=host_roots,
            compiler_record=execution[compiler],input_names=inputs['inputFiles'])
        require(not logs[role]['pendingGates'],'Every original Mono/import condition gate must pass')
    imports=dict(kind='scoped-normal-App-original-import-provenance',logs=logs,generatedReaderFiles=I.generated_reader_files(host_roots),
        normalBoundary=boundary,normalParentBuildRequiredAtAdmission=True,
        pendingGates=['archive-backed-normal-and-actual-SDK-consumption','original-three-BOOT-archive-construction'],
        actualOriginalInputsAndProcessesRead=True,bootstrapArchiveConstructionValidated=False,
        wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)
    public=view.release_root/'reports/build/appinsights'
    require(unique_json((public/'original-import-bindings.json').read_bytes())==imports,
        'Original saved import receipt differs from both actual immutable logs/105host bindings')
    origins=_compiler_origins(view,workspace,bound,execution,imports)
    require(unique_json((public/'compiler-output-origins.json').read_bytes())==origins,
        'Original saved export5 origins differ from actual Csc/generated-source facts')
    api=N.validate_api(workspace,worker);bodies=N.package_bodies(workspace,worker)
    package=output/N.PACKAGE;require(package.stat().st_size<=MEMORY_FILE,'Bounded actual genuine App NPK required')
    members=validate_package_bytes(package.read_bytes(),bodies)
    original_package=dict(path=attempt+'/output/'+N.PACKAGE,**N.fingerprint(package))
    receipt=unique_json((output/'genuine-normal-package.json').read_bytes())
    expected_receipt=dict(kind='actual-normal-genuine-App5-package',package=original_package,members=members,api=api,execution=execution,
        oldBinarySourceAttributed=False,publisherSigningClaimed=False,wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)
    require(receipt==expected_receipt,'Actual normal package receipt differs from recomputed source/compiler/process/API facts')
    exported=unique_json((public/'export-record.json').read_bytes())
    require(exported['sourceProof']==receipt and exported['retainedPrivateControlOnly']is False,
        'Public App supplier must bind this genuine normal proof; private retained proof is forbidden')
    finite=unique_json((public/'finite-reference-use.json').read_bytes())
    require(finite==dict(kind=R.KIND,role=R.role_record(),context=bound['context'],genuineNormalProof=receipt,
        privateInputManifest=_original_descriptor(view,attempt+'/input-manifest.json'),payloadRole=False,
        referencePreferredSourceEstablished=False,wholeProducerSourceClosure=False,sourceAdmissionAllowed=False),
        'Actual finite reference-use receipt differs from original logical evidence')
    scan=R.scan_public_tree(public,private_workspace=workspace,normal_imports=imports)
    require(unique_json((public/'content-exclusion.json').read_bytes())['allActualBodiesChecked']is True,
        'Original public publication must contain its explicit content exclusion receipt')
    return dict(kind='archived-genuine-App5-source-construction',package=original_package,members=members,api=api,
        execution=execution,normalBoundary=normal_boundary,originalImports=imports,compilerOutputOrigins=origins,
        actualCompilerPhysicalOutputs={role:record['finalOutput']for role,record in actual.items()},
        physicalPackage=str(package),bootstrap=bootstrap,contentExclusion=scan,
        originalLogicalPathsRewritten=False,compilerOrReaderExecuted=False,wholeProducerSourceClosure=False,
        qualificationAllowed=False,sourceAdmissionAllowed=False)


def _close_origins(view):
    if view is None:return
    snapshots={id(row['origin'].snapshot):row['origin'].snapshot for row in view.entries.values()if type(row.get('origin'))is VerifiedOrigin}
    for snapshot in snapshots.values():snapshot.close()


def reconstruct_app(release,record,external_inputs,verification_root,*,normal_context,capture_source_root,budget):
    """Construct actual closed private views; execute no product tools.

    The caller must authenticate record/normal_context before this leaf. Every
    descriptor is then tied to captured actual D/source bytes here. This entry
    establishes only this App component, never whole SDK/source admission.
    """
    import musl_legacy5_appinsights_archive_normal as AN
    import musl_legacy5_bootstrap_native_source_inputs as BN
    AN.require_posix();AN.bound_fields(normal_context);context=R.finite_context(normal_context['context'])
    require(type(budget)is Budget and type(record)is dict and record==normal_context['record']and type(record.get('sdk'))is dict,
        'Exact caller-authenticated canonical parent record including its SDK descriptor required')
    release=ordinary(release,directory=True);verification_root=ordinary(verification_root)
    require(not verification_root.exists(),'Fresh exclusive caller-selected archive verification root required')
    require(type(external_inputs)is dict and set(external_inputs)=={'referenceZip','comparisonPackage','compilerArchives'}
        and type(external_inputs['compilerArchives'])is dict and set(external_inputs['compilerArchives'])=={'legacy5','runtime','vstest'},
        'Actual complete closed five archive inputs required before writes')
    originals=[ordinary(value,file=True)for value in(external_inputs['referenceZip'],external_inputs['comparisonPackage'],*external_inputs['compilerArchives'].values())]
    require(len(set(originals))==5,'Actual five input archive roles must use distinct ordinary files')
    forbidden=[release,*originals,*map(Path,context['paths'].values()),ROOT]
    for original in forbidden:
        require(verification_root!=original and verification_root not in original.parents and original not in verification_root.parents,
            'Fresh reconstruction may not overlap incoming inputs, current code, or any original host root')
    rows=record.get('files');require(type(rows)is list,'Caller-authenticated sealed inventory required')
    manifests=[row for row in rows if row.get('path')=='sources/source-manifest.json']
    require(len(manifests)==1,'One actual caller-authenticated source manifest required')
    expected={key:record[key]for key in('sdkVersion','projectCommit','runId','runAttempt','targetRid')}
    verification_root.mkdir(mode=0o700,parents=True);private_root=verification_root/'snapshots';private_root.mkdir(mode=0o700)
    source=delivery=view=None
    try:
        source=SourceSession.capture(release,expected,fields(manifests[0]),budget=budget,private_root=private_root)
        D=logical(context['paths']['delivery']);attempt=logical(context['paths']['attempt'])
        delivery=DeliverySession.capture(release,record,source,D,budget=budget,private_root=private_root)
        public_source=source.root_for(D+'/reports/build/appinsights',kind='tree',role=APP_PUBLIC_ROLE)
        members,output_names=public_app_members()
        source.assert_closed_root(public_source['name'],members,kind='tree',role=APP_PUBLIC_ROLE)
        source_origins={};mode_origins={}
        for root in source.manifest['roots']:
            if root.get('kind')!='tree'or not isinstance(root.get('role'),str)or not root.get('originalPath','').startswith(D+'/'):continue
            origins=source.mint_delivery_root(delivery,root['name'])
            if root['name']==public_source['name']:source_origins=origins
            for origin in origins.values():
                name=origin.original[len(D)+1:]
                require(name not in mode_origins or mode_origins[name].metadata()['mode']==origin.metadata()['mode'],
                    'Overlapping actual indexed delivery modes disagree')
                mode_origins[name]=origin
        require(set(source_origins)==members,'Every closed public App file requires actual indexed and caller-bound D bytes')
        delivery._couple_source_modes(mode_origins)
        view=FrozenView(verification_root/'view',budget=budget,forbidden_roots=forbidden)
        view.declare_root(D,'delivery',role='delivery')
        for name in delivery.snapshots:view.bind_origin(D+'/'+name,'delivery/'+name,delivery.mint(name),category='public')
        workspace=view.declare_root(attempt,'app',role='app-workspace')
        view.declare_root('/inputs','app/inputs',namespace='container',role='inputs')
        view.declare_root('/output','app/output',namespace='container',role='output')
        for name in NORMAL_FILES:_bind_alias(view,attempt+'/'+name,'app/'+name,source_origins['evidence/'+name])
        _bind_alias(view,attempt+'/input-manifest.json','app/input-manifest.json',source_origins['original-private-input-manifest.json'])
        _bind_alias(view,attempt+'/origin/historical-reference-notice.txt','app/origin/historical-reference-notice.txt',
            source_origins['origin/historical-reference-notice.txt'])
        for name in R.policy()['publicInputNames']:
            _bind_alias(view,attempt+'/inputs/'+name,'app/inputs/'+name,source_origins['product-source/'+name],container='/inputs/'+name)
        _external_inputs(view,source,attempt,external_inputs,budget=budget,private_root=private_root)
        for name in output_names:_bind_alias(view,attempt+'/output/'+name,'app/output/'+name,
            source_origins['evidence/output/'+name],container='/output/'+name)
        _bind_alias(view,attempt+'/output/'+N.PACKAGE,'app/output/'+N.PACKAGE,source_origins['product/'+N.PACKAGE],container='/output/'+N.PACKAGE)
        R.verify_private_inputs(workspace);R._notice(workspace/'origin/historical-reference-notice.txt')
        bootstrap=_bootstrap_views(view,delivery,external_inputs,budget=budget,private_root=private_root,architecture=record['architecture'])
        _capture_view(view,source,capture_source_root,budget=budget)
        view.freeze();host_roots={key:view.path(key,namespace='container')for key in('/inputs','/output','/bootstrap','/inspector')}
        with view.guard():
            public=view.release_root/'reports/build/appinsights';R.validate_public_source(public)
            native=BN.validate(view.release_root,unique_json(source.manifest_raw),record)
            require(native['status']=='passed-sdk5-bootstrap-native-source-copies-and-original-generator-inputs',
                'Unchanged full native source support predicate must pass; saved receipts are insufficient')
            bootstrap=dict(bootstrap,nativeSourceValidationStillRequired=False,nativeSourceValidation=native)
            boundary=AN.validate_archived_normal_boundary(view,normal_context,source)
            application=_validate_application(view,workspace,host_roots,normal_context,boundary,bootstrap)
        return ReconstructedApp(_RECONSTRUCTED_FACTORY,source=source,view=view,workspace=workspace,host_roots=host_roots,
            normal_context=unique_json(canonical(normal_context)),application=application,delivery=delivery,
            public_root=public,public_source_root=public_source['name'],record=unique_json(canonical(record)),
            capture_source_root=capture_source_root)
    except BaseException:
        _close_origins(view)
        if view is not None:view.close()
        if delivery is not None:delivery.close()
        if source is not None:source.close()
        raise


def validate_archived_app(release,record,external_inputs,verification_root,*,normal_context,capture_source_root,
    sdk_proof_descriptor,tooling_descriptor,budget):
    """A reachable full App component predicate; whole-SDK gates remain separate."""
    import musl_legacy5_appinsights_archive_normal as AN
    app=reconstruct_app(release,record,external_inputs,verification_root,normal_context=normal_context,
        capture_source_root=capture_source_root,budget=budget)
    try:
        consumer=AN.validate_archived_sdk_consumption(app,sdk_proof_descriptor=sdk_proof_descriptor,
            tooling_descriptor=tooling_descriptor,capture_source_root=capture_source_root)
        require(consumer['actualCapturedConsumptionRecomputed']is True,'Actual archived SDK/cache/Copy consumption must be independently recomputed')
        return dict(kind='sdk5-archive-backed-genuine-App-component-construction',application=app.application,consumption=consumer,
            archivedAppComponentConstructionValidated=True,actualNormalConstructionValidated=True,
            privateInputCount=522,publicInputCount=449,externalReferenceInputCount=73,
            budget=dict(limits=budget.limits,used=budget.used,files=budget.files),
            originalLogicalPathsRewritten=False,compilerOrReaderExecuted=False,
            fullPublicConstructionValidated=False,pendingWholeSdkGates=['all-delivery-private-content-exclusion','complete-parent-SDK-source-and-construction-closure'],
            wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)
    finally:app.close()


