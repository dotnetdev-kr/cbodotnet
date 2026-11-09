"""Retain actual normal App cache/Copy observations; no archived admission."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path,PurePosixPath
import stat
import struct
import types
import zipfile

import musl_legacy5_appinsights_consumption as M
import musl_legacy5_appinsights_reference_bootstrap as R

require=M.require
FP=set(M.CE.FP)
MAX_FILE=8*1024**2
MAX_TOTAL=64*1024**2
MAX_PATHS=32
KIND='sdk5-retained-actual-normal-App-consumption-data'
MOUNT='/work/work/sdk'


def fingerprint(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),sha512=hashlib.sha512(raw).hexdigest())


def ordinary(value,*,directory=False):
    path=Path(value)
    require(path.is_absolute()and '..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),
        'Ordinary absolute unredirected capture path required')
    if path.exists():
        mode=path.lstat().st_mode
        require(not mode&0o7000 and (stat.S_ISDIR(mode)if directory else stat.S_ISREG(mode)),
            'Ordinary capture directory/file required')
    if directory:require(path.is_dir(),'Actual capture input directory required')
    return path


def body(path):
    path=ordinary(path);require(path.is_file()and path.stat().st_size<=MAX_FILE,'Bounded actual capture file required')
    with path.open('rb')as stream:
        before=os.fstat(stream.fileno());raw=stream.read(MAX_FILE+1);after=os.fstat(stream.fileno())
    require(len(raw)<=MAX_FILE and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==
        (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)and len(raw)==after.st_size,
        'Actual capture input changed during its bounded read')
    return raw


def unique_json(raw):
    def pairs(items):
        require(len(items)==len({key for key,_ in items}),'Duplicate capture JSON keys are forbidden')
        return dict(items)
    return json.loads(raw,object_pairs_hook=pairs)


def _logical(value):
    require(isinstance(value,str)and value.startswith(MOUNT+'/'),'Actual SDK Copy logical mount required')
    relative=PurePosixPath(value).relative_to(MOUNT).as_posix()
    original_double=MOUNT+'/artifacts/bin/redist/Release/dotnet//sdk/'+M.CE.SDK+'-ci/Microsoft.ApplicationInsights.dll'
    require(M.portable(relative)==relative and value in(MOUNT+'/'+relative,original_double),
        'Original validated SDK Copy path required; only its exact recorded double slash is retained')
    return relative


def code_pins():
    result={};seen=set();scripts=Path(__file__).resolve().parent
    def visit(module):
        if id(module)in seen:return
        seen.add(id(module));name=getattr(module,'__file__',None)
        if name:
            path=Path(name).resolve()
            if path.parent==scripts and path.suffix=='.py':result[path.name]=fingerprint(path.read_bytes())
        for value in vars(module).values():
            if isinstance(value,types.ModuleType)and getattr(value,'__file__',None)and Path(value.__file__).resolve().parent==scripts:visit(value)
    visit(M);visit(R);result[Path(__file__).name]=fingerprint(Path(__file__).read_bytes());return result


def observations(validated,sdk_source,feed):
    """Closed physical observations derived only after the real M validator."""
    sdk_source=ordinary(sdk_source,directory=True);feed=ordinary(feed,directory=True)
    package=validated['package'];product=validated['product'];relative='.packages/'+M.ID.lower()+'/'+M.VERSION+'/'
    rows=[dict(logical=MOUNT+'/'+relative+name,path=sdk_source/relative/name,kind=kind,expected=expected)
        for name,kind,expected in((M.PACKAGE,'cache-package',package),(M.MEMBER,'cache-product',product),
            ('.nupkg.metadata','cache-metadata',None),(M.PACKAGE+'.sha512','cache-sha512',None))]
    rows.append(dict(logical='/work/inputs/bootstrap-feed/'+M.PACKAGE,path=feed/M.PACKAGE,kind='feed-package',expected=package))
    consumers=validated['sdkConsumers']
    require([row['replayName']for row in consumers]==['sdk','redist'],'Two original SDK App consumer processes required')
    for consumer in consumers:
        require(len(consumer['actualCopies'])==4,'All four actually observed Copy edges required per process')
        for edge in consumer['actualCopies']:
            require(set(edge)=={'context','source','destination'},'Closed actual App Copy observation required')
            for field in('source','destination'):
                value=edge[field];relative_path=_logical(value)
                rows.append(dict(logical=value,path=sdk_source/relative_path,kind='copy-product',expected=product))
    require(len({row['logical']for row in rows})<=MAX_PATHS,'Bounded closed App capture path set required')
    return rows


def _metadata(buffers,paths,validated):
    prefix=MOUNT+'/.packages/'+M.ID.lower()+'/'+M.VERSION+'/'
    def raw(name):return buffers[paths[prefix+name]['member']]
    metadata=unique_json(raw('.nupkg.metadata'));content=base64.b64encode(bytes.fromhex(validated['package']['sha512'])).decode()
    require(metadata==validated['cache']['originalNugetMetadata']and metadata.get('source')=='/work/inputs/bootstrap-feed'
        and metadata.get('contentHash')==content and raw(M.PACKAGE+'.sha512').decode().strip()==content,
        'Original actual NuGet metadata/hash observations must agree')


def _package_entries(raw):
    """Walk the complete bounded directory before ZipFile allocates entries."""
    require(isinstance(raw,bytes)and 22<=len(raw)<=MAX_FILE and raw.startswith(b'PK\x03\x04')
        and raw[-22:-18]==b'PK\x05\x06'and raw[-2:]==b'\0\0',
        'One complete uncommented captured App NPK required')
    disk,central_disk,on_disk,count,size,offset,comment=struct.unpack('<4H2IH',raw[-18:])
    require(disk==central_disk==0 and on_disk==count and 0<count<=16 and comment==0 and offset+size==len(raw)-22,
        'Bounded single-disk captured App NPK directory required')
    at=offset;end=offset+size;names=set();expanded=0
    for _ in range(count):
        require(46<=end-at and raw[at:at+4]==b'PK\x01\x02','Complete captured App NPK central header required')
        made,needed,flags,method,mtime,mdate,crc,compressed,uncompressed,name_bytes,extra,entry_comment,disk_start,internal,external,local=\
            struct.unpack_from('<6H3I5H2I',raw,at+4)
        span=46+name_bytes+extra+entry_comment
        require(0<name_bytes<=4096 and span<=end-at and disk_start==0
            and method in(0,8)and not flags&1 and uncompressed<=MAX_FILE,
            'Bounded ordinary captured App NPK central entry required')
        try:name=raw[at+46:at+46+name_bytes].decode('utf-8'if flags&2048 else'cp437','strict')
        except UnicodeError as error:raise ValueError('Captured App NPK central name is not valid text')from error
        mode=external>>16
        require(name not in names and not name.startswith('/')and '\\'not in name and '\0'not in name
            and '..'not in PurePosixPath(name).parts and not mode&0o7000
            and stat.S_IFMT(mode)in(0,stat.S_IFREG,stat.S_IFDIR),
            'Unique ordinary captured App NPK central names required')
        require(local+30<=offset and raw[local:local+4]==b'PK\x03\x04',
            'Bounded captured App NPK local header required')
        local_name,local_extra=struct.unpack_from('<HH',raw,local+26)
        require(local+30+local_name+local_extra+compressed<=offset,
            'Bounded captured App NPK local member span required')
        names.add(name);expanded+=uncompressed
        require(expanded<=MAX_TOTAL,'Captured App NPK expanded budget exceeded')
        at+=span
    require(at==end and M.MEMBER in names,'Complete exact captured App NPK directory count/product required')
    return count


def _package_product(raw,product):
    """Bind the captured NPK member to the captured actual product bytes."""
    count=_package_entries(raw)
    with zipfile.ZipFile(io.BytesIO(raw))as archive:
        entries=archive.infolist();selected=[row for row in entries if row.filename==M.MEMBER]
        require(len(entries)==count and len(selected)==1 and len({row.filename for row in entries})==count,
            'One unique original App product member required in captured NPK')
        entry=selected[0];mode=entry.external_attr>>16
        require(not entry.is_dir()and not entry.flag_bits&1 and not mode&0o7000
            and stat.S_IFMT(mode)in(0,stat.S_IFREG)and entry.file_size==product['bytes']and 0<entry.file_size<=MAX_FILE,
            'Bounded ordinary captured App package member required')
        with archive.open(entry)as stream:member=stream.read(MAX_FILE+1)
    require(fingerprint(member)=={key:product[key]for key in FP},
        'Captured App package member must equal the captured actual DLL product')


def capture(release,record,proof,roots,tooling,*,app_workspace,app_host_roots,sdk_source,feed,normal_context,destination):
    """Authenticate actual normal consumption first, then publish checked buffers."""
    require(normal_context is not None,'Explicit genuine normal context required; no private capture fallback')
    destination=ordinary(destination);require(not destination.exists(),'Fresh exclusive App consumption data root required')
    input_roots=[release,app_workspace,sdk_source,feed,Path(__file__).resolve().parents[1]]
    input_roots.extend(row['path']for row in roots.values())
    input_roots.extend(app_host_roots.values())
    for value in input_roots:
        original=ordinary(value,directory=True)
        require(destination!=original and original not in destination.parents and destination not in original.parents,
            'Capture destination must be separate from all original input roots')
    code=code_pins()
    validated=M.validate(release,record,proof,roots,tooling,app_workspace=app_workspace,app_host_roots=app_host_roots,
        sdk_source=sdk_source,feed=feed,normal_context=normal_context)
    require(validated['kind']=='sdk5-genuine-local-App-actual-sdk-consumption'
        and validated['normalSourceWorkerEnvelopeValidatedByThisPart']is True
        and validated['sourceAdmissionAllowed']is validated['qualificationAllowed']is validated['wholeProducerSourceClosure']is False,
        'Actual strict normal App consumption and its limited scope required')
    observed=observations(validated,sdk_source,feed);buffers={};paths={};physical={}
    for row in observed:
        raw=body(row['path']);actual=fingerprint(raw)
        if row['expected']is not None:require(actual=={key:row['expected'][key]for key in FP},'Actual App package/product capture bytes differ')
        member='content/'+actual['sha256'];require(member not in buffers or buffers[member]==raw,'Content-addressed capture identity collision')
        buffers[member]=raw;physical[str(row['path'])]=actual
        require(sum(map(len,buffers.values()))<=MAX_TOTAL,'App capture immutable-buffer budget exceeded')
        entry=paths.setdefault(row['logical'],dict(member=member,**actual,roles=[]))
        require(all(entry[key]==actual[key]for key in FP)and entry['member']==member,'One actual byte identity per original logical path required')
        if row['kind']not in entry['roles']:entry['roles'].append(row['kind'])
    _metadata(buffers,paths,validated)
    _package_product(buffers[paths['/work/inputs/bootstrap-feed/'+M.PACKAGE]['member']],validated['product'])
    compiler_descriptor=proof['componentCompilerProofs']['sdk'];compiler_path=M.B.checked(Path(release),compiler_descriptor)
    compiler=unique_json(body(compiler_path));M.CE.replay_names('sdk',compiler['replays'])
    index=dict(schemaVersion=1,kind=KIND,originalLogicalPaths=paths,actualNormalConsumption=validated,
        existingFinalArchive=proof['sdkArchive'],existingToolset=validated['toolset'],
        originalCompilerProof=compiler_descriptor,originalConsumerReplays=compiler['replays'],captureCode=code,
        rawNugetSidecarFingerprintsAreNewCaptureObservations=True,
        dataFileMode=0o644,sourceFilesModified=False,originalReportsRewritten=False,
        archivedConstructionValidated=False,independentNormalExecutionRevalidated=False,
        wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)
    index_raw=(json.dumps(index,indent=2)+'\n').encode();require(len(index_raw)<=MAX_FILE,'Bounded closed App capture index required')
    buffers['capture-index.json']=index_raw;require(sum(map(len,buffers.values()))<=MAX_TOTAL,'App capture total publication budget exceeded')
    private=R.verify_private_inputs(Path(app_workspace));forbidden=R._forbidden(Path(app_workspace))
    for name,pin in private['privateInputFiles'].items():
        require(fingerprint(forbidden[name])=={key:pin[key]for key in FP},'Actual finite private exclusion body changed')
    with zipfile.ZipFile(io.BytesIO(forbidden['original.nupkg']))as archive:
        require(forbidden['comparison-publisher-dll']==archive.read(M.MEMBER),'Exact original private comparison member required')
    budget={'bytes':0,'entries':0}
    for name,raw in buffers.items():R.scan_content(raw,forbidden,name=name,budget=budget)
    for name,expected in physical.items():require(fingerprint(body(name))==expected,'Actual original App capture file changed before publication')
    M.B.checked(Path(release),compiler_descriptor)
    require(R.verify_private_inputs(Path(app_workspace))==private,'Actual finite private inputs changed before publication')
    require(code_pins()==code,'Actual capture validator code changed before publication')
    destination.mkdir(parents=True)
    for name,raw in buffers.items():
        path=ordinary(destination/name);path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb')as stream:stream.write(raw)
        path.chmod(0o644);require(fingerprint(body(path))==fingerprint(raw)and stat.S_IMODE(path.stat().st_mode)==0o644,
            'Published App capture bytes/mode differ from checked immutable buffers')
    return dict(kind=KIND,index=dict(path='capture-index.json',**fingerprint(index_raw)),logicalPaths=len(paths),
        contentFiles=len(buffers)-1,checkedImmutableBuffersPublished=True,archivedConstructionValidated=False,
        qualificationAllowed=False,sourceAdmissionAllowed=False)


def validate_data(root):
    """Validate retained data consistency; never trust a saved normal boolean."""
    root=ordinary(root,directory=True);index_raw=body(root/'capture-index.json');index=unique_json(index_raw)
    require(set(index)=={'schemaVersion','kind','originalLogicalPaths','actualNormalConsumption',
        'existingFinalArchive','existingToolset','originalCompilerProof','originalConsumerReplays','captureCode',
        'rawNugetSidecarFingerprintsAreNewCaptureObservations','dataFileMode','sourceFilesModified','originalReportsRewritten',
        'archivedConstructionValidated','independentNormalExecutionRevalidated','wholeProducerSourceClosure',
        'qualificationAllowed','sourceAdmissionAllowed'}and index['schemaVersion']==1 and index['kind']==KIND
        and index['dataFileMode']==0o644 and index['rawNugetSidecarFingerprintsAreNewCaptureObservations']is True
        and all(index[key]is False for key in('sourceFilesModified','originalReportsRewritten','archivedConstructionValidated',
            'independentNormalExecutionRevalidated','wholeProducerSourceClosure','qualificationAllowed','sourceAdmissionAllowed')),
        'Closed scoped actual-consumption data index required')
    paths=index['originalLogicalPaths'];require(isinstance(paths,dict)and 0<len(paths)<=MAX_PATHS,'Bounded logical capture mappings required')
    buffers={};total=len(index_raw)
    for logical,row in paths.items():
        require(set(row)=={'member','roles',*FP}and isinstance(row['roles'],list)and row['roles']
            and len(row['roles'])==len(set(row['roles']))and set(row['roles'])<=
            {'cache-package','cache-product','cache-metadata','cache-sha512','feed-package','copy-product'},
            'Closed unique actual-consumption data roles required')
        member='content/'+row['sha256'];require(row['member']==member and M.portable(member)==member,'Exact content-addressed data member required')
        if member not in buffers:
            raw=body(root/member);require(fingerprint(raw)=={key:row[key]for key in FP},'Retained actual-consumption bytes differ')
            require(stat.S_IMODE((root/member).stat().st_mode)==0o644,'Exact retained data0644 mode required')
            buffers[member]=raw;total+=len(raw);require(total<=MAX_TOTAL,'Retained capture total budget exceeded')
        require(fingerprint(buffers[member])=={key:row[key]for key in FP},'Conflicting logical content fingerprints')
    actual=set()
    for base,dirs,names in os.walk(root,followlinks=False):
        require(len(actual)+len(names)+len(dirs)<=MAX_PATHS+3,'Bounded capture entry set required')
        for name in dirs:ordinary(Path(base)/name,directory=True)
        for name in names:actual.add(ordinary(Path(base)/name).relative_to(root).as_posix())
    require(actual=={'capture-index.json',*buffers}and stat.S_IMODE((root/'capture-index.json').stat().st_mode)==0o644,
        'Complete exact retained capture file inventory required')
    validated=index['actualNormalConsumption'];prefix=MOUNT+'/.packages/'+M.ID.lower()+'/'+M.VERSION+'/'
    expected={prefix+M.PACKAGE:{'cache-package'},prefix+M.MEMBER:{'cache-product','copy-product'},
        prefix+'.nupkg.metadata':{'cache-metadata'},prefix+M.PACKAGE+'.sha512':{'cache-sha512'},
        '/work/inputs/bootstrap-feed/'+M.PACKAGE:{'feed-package'}}
    edges={(prefix+M.MEMBER,MOUNT+'/artifacts/bin/dotnet/Release/net5.0/Microsoft.ApplicationInsights.dll'),
        (prefix+M.MEMBER,MOUNT+'/artifacts/bin/redist/Release/net5.0/Microsoft.ApplicationInsights.dll'),
        (MOUNT+'/artifacts/bin/redist/Release/net5.0/Microsoft.ApplicationInsights.dll',
            MOUNT+'/artifacts/bin/redist/Release/layouts/dotnet-toolset-internal/Microsoft.ApplicationInsights.dll'),
        (MOUNT+'/artifacts/bin/redist/Release/net5.0/Microsoft.ApplicationInsights.dll',
            MOUNT+'/artifacts/bin/redist/Release/dotnet//sdk/'+M.CE.SDK+'-ci/Microsoft.ApplicationInsights.dll')}
    consumers=validated['sdkConsumers'];require([row['replayName']for row in consumers]==['sdk','redist'],'Both recorded consumer roles required')
    for consumer in consumers:
        require(len(consumer['actualCopies'])==4 and {(e['source'],e['destination'])for e in consumer['actualCopies']}==edges,
            'Retained data must include all four original Copy observations per process')
    for edge in edges:
        for logical in edge:expected.setdefault(logical,set()).add('copy-product')
    require(set(paths)==set(expected)and all(set(paths[name]['roles'])==roles for name,roles in expected.items()),
        'Complete exact original logical cache/feed/Copy mappings required')
    for name,row in paths.items():
        if set(row['roles'])&{'cache-package','feed-package'}:wanted=validated['package']
        elif set(row['roles'])&{'cache-product','copy-product'}:wanted=validated['product']
        else:continue
        require({key:row[key]for key in FP}=={key:wanted[key]for key in FP},'Retained package/product observation mismatch')
    _metadata(buffers,paths,validated)
    _package_product(buffers[paths['/work/inputs/bootstrap-feed/'+M.PACKAGE]['member']],validated['product'])
    M.CE.replay_names('sdk',index['originalConsumerReplays'])
    return dict(kind=KIND,retainedDataBytesValidated=True,logicalPaths=len(paths),contentFiles=len(buffers),
        actualNormalExecutionRevalidated=False,archivedConstructionValidated=False,wholeProducerSourceClosure=False,
        qualificationAllowed=False,sourceAdmissionAllowed=False)
