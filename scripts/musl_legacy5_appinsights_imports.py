"""Pure bounded MSBuild13/14 import decoding for the finite App5 role.

Format derived from the MIT-licensed dotnet/msbuild readers at0538acc04cc2
and85d71072f8fa, not by executing MSBuild or the retained Reader. Only actual
normal records can bind a live import proof. BOOT/archive/SDK admission remains
a separate required construction gate.
"""
import hashlib
import json
from pathlib import Path
import posixpath
import re
import stat
import struct
import zlib

import musl_legacy5_appinsights_normal as N

require=N.require
FP=N.FP
POLICY_FILE='musl-legacy5-appinsights-import-policy.json'
POLICY_SHA256='65edc5a6fd3ed0c8dbba49831289df52650ed22b9f2467d15341909d780e6484'
MAX_COMPRESSED=16*1024**2
MAX_EXPANDED=32*1024**2
MAX_RECORDS=250000
MAX_COUNT=65536
MAX_STRING=1024**2
MAX_DECODED_NODES=250000
MAX_DECODED_TEXT_BYTES=16*1024**2
MAX_MEMBERS=512
MAX_IMPORT_BYTES=16*1024**2
ENUMS=dict(buildReason=(0,1,2,3),skipReason=(0,1,2,3,4),parameterKind=(0,1,2,3,4,5),
    evaluationLocationKind=(0,1,2),evaluationPass=(0,1,2,3,4,5,6,7,8))
GENERATED=('reader-obj/Reader.csproj.nuget.g.props','reader-obj/Reader.csproj.nuget.g.targets','reader-obj/project.assets.json')
KINDS=('EndOfFile','BuildStarted','BuildFinished','ProjectStarted','ProjectFinished','TargetStarted',
    'TargetFinished','TaskStarted','TaskFinished','Error','Warning','Message','TaskCommandLine',
    'CriticalBuildMessage','ProjectEvaluationStarted','ProjectEvaluationFinished','ProjectImported',
    'ProjectImportArchive','TargetSkipped','PropertyReassignment','UninitializedPropertyRead',
    'EnvironmentVariableRead','PropertyInitialValueSet','NameValueList','String','TaskParameter')


def fingerprint(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),sha512=hashlib.sha512(raw).hexdigest())


def policy():
    raw=N.ordinary(Path(__file__).with_name(POLICY_FILE),file=True).read_bytes()
    require(hashlib.sha256(raw).hexdigest()==POLICY_SHA256,'Immutable original App import policy differs')
    p=json.loads(raw);strong,worker=N.original_validators()
    require(p['schemaVersion']==1 and p['sdkVersion']==N.SDK and set(p['logs'])=={'app','reader-build'}
        and [p['logs'][role]['format']for role in('app','reader-build')]==[13,14]
        and p['originalWorkerPolicy']==N.fingerprint(Path(worker.__file__).with_name(worker.POLICY_FILE))
        and p['generatedReaderMembers']==['/output/'+name for name in GENERATED]
        and p['closedEnums']=={name:list(values)for name,values in ENUMS.items()}
        and p['compilerReferenceRoleOnly']is True
        and all(p[key]is False for key in('bootstrapArchiveConstructionValidated','actualNormalProductionEstablishedByPolicy',
            'wholeProducerSourceClosure','qualificationAllowed','sourceAdmissionAllowed')),
        'One original finite App/Reader import contract is required')
    return p


def logical_path(value):
    require(isinstance(value,str)and value.startswith('/')and not value.startswith('//')
        and value==posixpath.normpath(value)and not any(c in value for c in ':\\\0\r\n')
        and all(part not in('','.','..')for part in value[1:].split('/')),
        'Exact canonical original import logical path required')
    require(value.startswith(('/inputs/','/output/','/bootstrap/','/inspector/')),
        'Original import escapes its four closed logical mounts')
    return value


def zip_logical_path(value):
    require(isinstance(value,str)and value.startswith('\\')and not value.startswith('\\\\')
        and '/'not in value and ':'not in value and not any(c in value for c in '\0\r\n')
        and all(part not in('','.','..')for part in value[1:].split('\\')),
        'Exact original MSBuild import ZIP logical name required')
    return logical_path('/'+value[1:].replace('\\','/'))


class _Reader:
    """Consume every original wire record; no byte/signature recovery."""
    def __init__(self,body,version):
        self.nodes=0;self.text_bytes=0;self.reserve(3,label='initial tables')
        self.body=body;self.at=4;self.version=version;self.strings=[];self.lists=[]
        self.records=[];self.archive=None;self.event_number=0

    def reserve(self,nodes,*,text_bytes=0,label='collection'):
        require(type(nodes)is int and nodes>=0 and self.nodes+nodes<=MAX_DECODED_NODES,
            'Cumulative original binlog decoded-node budget exceeded before '+label)
        require(type(text_bytes)is int and text_bytes>=0 and self.text_bytes+text_bytes<=MAX_DECODED_TEXT_BYTES,
            'Cumulative original binlog decoded-text budget exceeded before '+label)
        self.nodes+=nodes;self.text_bytes+=text_bytes

    def take(self,count):
        require(type(count)is int and 0<=count<=len(self.body)-self.at,
            'Truncated original binlog at byte '+str(self.at))
        raw=self.body[self.at:self.at+count];self.at+=count;return raw

    def integer(self):
        value=0;start=self.at
        for shift in range(0,35,7):
            byte=self.take(1)[0]
            require(shift!=28 or byte<=15,'Invalid original binlog Int32 at byte '+str(start))
            value|=(byte&127)<<shift
            if not byte&128:
                require(self.at-start==max(1,(value.bit_length()+6)//7),
                    'Noncanonical original binlog Int32 at byte '+str(start))
                return value if value<2**31 else value-2**32
        raise ValueError('Unclosed original binlog Int32 at byte '+str(start))

    def count(self,limit=MAX_COUNT):
        value=self.integer();require(0<=value<=limit,'Original binlog count exceeds its bound');return value

    def enum(self,name):
        value=self.integer();require(value in ENUMS[name],'Unsupported original binlog enum '+name);return value

    def boolean(self):
        value=self.take(1)[0];require(value in(0,1),'Original binlog Boolean must be0 or1');return bool(value)

    def string(self):
        length=self.count(MAX_STRING)
        self.reserve(2,text_bytes=length,label='string allocation')
        try:return self.take(length).decode('utf-8','strict')
        except UnicodeError as error:raise ValueError('Original binlog string is not strict UTF-8')from error

    def text(self):
        index=self.integer()
        if index in(0,1):return None if index==0 else''
        require(10<=index<10+len(self.strings),'Original binlog string record index is unbound')
        return self.strings[index-10]

    def context(self,fixed=False):
        self.reserve(24,label='context allocation')
        return list(struct.unpack('<7i',self.take(28)))if fixed else[self.integer()for _ in range(7)]

    def dictionary(self):
        index=self.integer()
        if index==0:return None
        require(10<=index<10+len(self.lists),'Original binlog name/value record index is unbound')
        return self.lists[index-10]

    def items(self):
        count=self.count();self.reserve(1+6*count,label='task item allocation')
        return[dict(value=self.text(),metadata=self.dictionary())for _ in range(count)]

    def project_items(self):
        self.reserve(1,label='project item group allocation')
        rows=[]
        for _ in range(MAX_COUNT):
            item_type=self.text()
            if not item_type:return rows
            self.reserve(4,label='project item group allocation')
            rows.append(dict(itemType=item_type,items=self.items()))
        raise ValueError('Original binlog project item groups exceed their bound')

    def common(self):
        flags=self.integer();require(0<=flags<=65535,'Unsupported original binlog field flags')
        self.reserve(1+flags.bit_count(),label='common field allocation')
        fields=dict(flags=flags)
        order=[(4,'message','text'),(1,'context','context'),(16,'threadId','integer'),
            (2,'helpKeyword','text'),(8,'senderName','text'),(32,'timestamp','timestamp'),
            (64,'subcategory','text'),(128,'code','text'),(256,'file','text'),(512,'projectFile','text'),
            (1024,'line','integer'),(2048,'column','integer'),(4096,'endLine','integer'),(8192,'endColumn','integer')]
        for bit,key,method in order:
            if not flags&bit:continue
            if method=='timestamp':
                ticks=struct.unpack('<q',self.take(8))[0];kind=self.integer()
                require(0<=ticks<=3155378975999999999 and kind in(0,1,2),'Invalid original binlog timestamp')
                fields[key]=dict(ticks=ticks,kind=kind)
            else:fields[key]=getattr(self,method)()
        if flags&16384:
            count=self.count();self.reserve(1+count,label='argument allocation')
            fields['arguments']=[self.text()for _ in range(count)]
        if flags&32768:
            fields['importance']=self.integer();require(fields['importance']in(0,1,2),'Unknown original message importance')
        return fields

    def profile(self):
        count=self.count();self.reserve(1+16*count,label='profile row allocation')
        rows=[]
        for _ in range(count):
            location=dict(zip(('element','description','evaluationDescription','file'),[self.text()for _ in range(4)]))
            location.update(kind=self.enum('evaluationLocationKind'),evaluationPass=self.enum('evaluationPass'))
            if self.boolean():location['line']=self.integer()
            location['id']=struct.unpack('<q',self.take(8))[0]
            if self.boolean():location['parentId']=struct.unpack('<q',self.take(8))[0]
            location.update(hits=self.integer(),exclusiveTicks=struct.unpack('<q',self.take(8))[0],
                inclusiveTicks=struct.unpack('<q',self.take(8))[0]);rows.append(location)
        return rows

    def event(self,kind):
        e=self.common()
        if kind==1:e['environment']=self.dictionary()
        elif kind==2:e['succeeded']=self.boolean()
        elif kind==3:
            if self.boolean():e['parentContext']=self.context()
            e.update(projectFile=self.text(),projectId=self.integer(),targets=self.text(),toolsVersion=self.text())
            if self.boolean():e['globalProperties']=self.dictionary()
            e.update(properties=self.dictionary(),items=self.project_items())
        elif kind==4:e.update(projectFile=self.text(),succeeded=self.boolean())
        elif kind==5:
            e.update(zip(('targetName','projectFile','targetFile','parentTarget'),[self.text()for _ in range(4)]))
            e['buildReason']=self.enum('buildReason')
        elif kind==6:
            e['succeeded']=self.boolean();e.update(zip(('projectFile','targetFile','targetName'),[self.text()for _ in range(3)]))
            e['outputs']=self.items()
        elif kind in(7,8):
            if kind==8:e['succeeded']=self.boolean()
            e.update(zip(('taskName','projectFile','taskFile'),[self.text()for _ in range(3)]))
        elif kind in(9,10):
            e.update(zip(('subcategory','code','file','projectFile'),[self.text()for _ in range(4)]))
            e.update(zip(('line','column','endLine','endColumn'),[self.integer()for _ in range(4)]))
        elif kind in(11,13):pass
        elif kind==12:e.update(commandLine=self.text(),taskName=self.text())
        elif kind==14:e['projectFile']=self.text()
        elif kind==15:
            e['projectFile']=self.text()
            if self.boolean():e['globalProperties']=self.dictionary()
            e.update(properties=self.dictionary(),items=self.project_items())
            if self.boolean():e['profile']=self.profile()
        elif kind==16:e.update(importIgnored=self.boolean(),importedProject=self.text(),unexpandedProject=self.text())
        elif kind==18:
            e.update(zip(('targetFile','targetName','parentTarget','condition','evaluatedCondition'),[self.text()for _ in range(5)]))
            e.update(originallySucceeded=self.boolean(),buildReason=self.enum('buildReason'))
            if self.version==14:
                e['skipReason']=self.enum('skipReason')
                if self.boolean():e['originalContext']=self.context(fixed=True)
        elif kind==19:e.update(zip(('propertyName','previousValue','newValue','location'),[self.text()for _ in range(4)]))
        elif kind==20:e['propertyName']=self.text()
        elif kind==21:e['environmentVariableName']=self.text()
        elif kind==22:e.update(zip(('propertyName','propertyValue','propertySource'),[self.text()for _ in range(3)]))
        elif kind==25:e.update(parameterKind=self.enum('parameterKind'),itemType=self.text(),items=self.items())
        else:raise ValueError('Unsupported original binlog event kind '+str(kind))
        return e

    def read(self):
        for record_number in range(MAX_RECORDS):
            self.reserve(1,label='record allocation')
            start=self.at;kind=self.integer();require(0<=kind<len(KINDS),'Unsupported original binlog record kind')
            if kind==0:
                require(self.archive is not None and self.at==len(self.body),'Complete original import archive and final EOF required')
                return self.records,self.archive
            require(self.archive is None,'Original import archive must be the final record before EOF')
            if kind==24:
                require(len(self.strings)<MAX_COUNT,'Original binlog string table exceeds its bound')
                self.strings.append(self.string())
            elif kind==23:
                require(len(self.lists)<MAX_COUNT,'Original name/value table exceeds its bound')
                count=self.count();self.reserve(3+5*count,label='name/value allocation')
                pairs=[(self.text(),self.text())for _ in range(count)]
                require(all(key is not None for key,_ in pairs)and len({key for key,_ in pairs})==len(pairs),
                    'Unique bound original name/value keys required')
                self.lists.append(dict(pairs))
            elif kind==17:
                self.reserve(8,label='import archive descriptor allocation')
                length=self.count(MAX_IMPORT_BYTES);offset=self.at;raw=self.take(length)
                self.archive=dict(raw=raw,offset=offset,end=self.at,record=record_number,fingerprint=fingerprint(raw))
            else:
                self.event_number+=1;event=self.event(kind)
                self.reserve(6+len(event),label='decoded event allocation')
                self.records.append(dict(kind=KINDS[kind],eventNumber=self.event_number,recordNumber=record_number,
                    offset=start,end=self.at,**event))
        raise ValueError('Original binlog record count exceeds its bound')


def decode_binlog(raw,expected_fingerprint,*,expected_format):
    """Decode original framed records only; this does not prove normal execution."""
    require(isinstance(raw,bytes)and 0<len(raw)<=MAX_COMPRESSED and expected_format in(13,14),
        'Bounded original MSBuild13/14 gzip bytes required')
    require(type(expected_fingerprint)is dict and set(expected_fingerprint)==set(FP)
        and fingerprint(raw)==expected_fingerprint,'Actual complete original binlog fingerprint required')
    try:
        stream=zlib.decompressobj(wbits=31);body=stream.decompress(raw,MAX_EXPANDED+1)
    except zlib.error as error:raise ValueError('Invalid complete original binlog gzip stream')from error
    require(len(body)<=MAX_EXPANDED and stream.eof and not stream.unused_data and not stream.unconsumed_tail,
        'One complete bounded original binlog gzip member required')
    require(len(body)>=4 and struct.unpack('<i',body[:4])[0]==expected_format,'Exact original binlog format/source role required')
    reader=_Reader(body,expected_format);events,archive=reader.read()
    return dict(format=expected_format,fingerprint=fingerprint(raw),expanded=body,events=events,archive=archive,
        decodedAllocation=dict(nodes=reader.nodes,textBytes=reader.text_bytes,nodeLimit=MAX_DECODED_NODES,textLimit=MAX_DECODED_TEXT_BYTES))


def _zip_entries(raw):
    """Bound central entries before allocation and account for every ZIP byte."""
    require(isinstance(raw,bytes)and 22<=len(raw)<=MAX_IMPORT_BYTES and raw.startswith(b'PK\x03\x04')
        and raw[-22:-18]==b'PK\x05\x06'and raw[-2:]==b'\0\0',
        'One complete uncommented original project-import ZIP required')
    disk,central_disk,on_disk,count,central_size,central_offset,comment=struct.unpack('<4H2IH',raw[-18:])
    require(disk==central_disk==0 and on_disk==count and 0<count<=MAX_MEMBERS and comment==0
        and central_offset+central_size==len(raw)-22,'Bounded single-disk original import ZIP directory required')
    cursor=central_offset;entries=[];expanded=0
    for _ in range(count):
        require(cursor+46<=len(raw)-22 and raw[cursor:cursor+4]==b'PK\x01\x02','Complete original import central header required')
        needed,flags,method=struct.unpack_from('<3H',raw,cursor+6)
        crc,compressed,size=struct.unpack_from('<3I',raw,cursor+16)
        name_length,extra,entry_comment,entry_disk,internal=struct.unpack_from('<5H',raw,cursor+28)
        external,offset=struct.unpack_from('<2I',raw,cursor+38)
        require(extra==entry_comment==0,'Original import ZIP extra fields and entry comments are forbidden')
        require(needed in(10,20)and flags&~(8|2048)==0 and method in(0,8)and entry_disk==internal==0
            and 0<name_length<=4096 and 0<=compressed<=MAX_IMPORT_BYTES and 0<=size<=MAX_IMPORT_BYTES,
            'Ordinary supported bounded original import ZIP entry required')
        end=cursor+46+name_length
        require(end<=len(raw)-22,'Complete original import central name required')
        name=raw[cursor+46:end];mode=external>>16
        require(not mode&0o7000 and stat.S_IFMT(mode)in(0,stat.S_IFREG)and not external&16,
            'Ordinary original import ZIP file mode required')
        require(offset+30<=central_offset and raw[offset:offset+4]==b'PK\x03\x04',
            'Complete original import local header required')
        local_needed,local_flags,local_method=struct.unpack_from('<3H',raw,offset+4)
        local_crc,local_compressed,local_size=struct.unpack_from('<3I',raw,offset+14)
        local_name,local_extra=struct.unpack_from('<2H',raw,offset+26)
        require(local_extra==0,'Original import ZIP local extra fields are forbidden')
        start=offset+30+local_name;data_end=start+compressed
        require((local_needed,local_flags,local_method)==(needed,flags,method)and local_name==name_length
            and raw[offset+30:start]==name and raw[offset+10:offset+14]==raw[cursor+12:cursor+16]
            and data_end<=central_offset,'Original import local/central metadata mismatch')
        wanted=(crc,compressed,size)
        if flags&8:
            require(all(actual in(0,want)for actual,want in zip((local_crc,local_compressed,local_size),wanted)),
                'Original import local descriptor placeholders differ')
            lengths=[]
            if data_end+12<=central_offset and struct.unpack_from('<3I',raw,data_end)==wanted:lengths.append(12)
            if data_end+16<=central_offset and raw[data_end:data_end+4]==b'PK\x07\x08'and struct.unpack_from('<3I',raw,data_end+4)==wanted:lengths.append(16)
            require(len(lengths)==1,'Exact original import data descriptor required')
            local_end=data_end+lengths[0]
        else:
            require((local_crc,local_compressed,local_size)==wanted,'Original import local/central sizes or CRC differ')
            local_end=data_end
        expanded+=size;require(expanded<=MAX_IMPORT_BYTES,'Original import expansion exceeds its bound')
        entries.append(dict(name=name,method=method,crc=crc,size=size,start=start,end=data_end,
            localStart=offset,localEnd=local_end));cursor=end
    require(cursor==len(raw)-22,'Original import central directory has extra records or padding')
    cursor=0
    for entry in sorted(entries,key=lambda row:row['localStart']):
        require(entry['localStart']==cursor,'Original import ZIP has unaccounted padding, overlap or orphan data')
        cursor=entry['localEnd']
    require(cursor==central_offset,'Original import ZIP has unaccounted data before its directory')
    return entries


def import_members(decoded,expected_members):
    """Validate logical names and strict complete container bytes without extraction."""
    raw=decoded['archive']['raw'];entries=_zip_entries(raw);members={}
    for entry in entries:
        try:original_name=entry['name'].decode('ascii','strict')
        except UnicodeError as error:raise ValueError('Original finite import member names must be ASCII')from error
        logical=zip_logical_path(original_name)
        require(logical not in members,'Unique original import logical member required')
        require(logical in expected_members,'Unknown original import member: '+logical)
        compressed=raw[entry['start']:entry['end']]
        if entry['method']==0:
            body=compressed;require(len(body)==entry['size'],'Complete original stored import member required')
        else:
            try:
                stream=zlib.decompressobj(-15);body=stream.decompress(compressed,entry['size']+1)
            except zlib.error as error:raise ValueError('Invalid original import deflate stream')from error
            require(len(body)==entry['size']and stream.eof and not stream.unused_data and not stream.unconsumed_tail,
                'One exact complete original import deflate stream required without padding')
        require(zlib.crc32(body)&0xffffffff==entry['crc'],'Complete original import member CRC required')
        require(fingerprint(body)==expected_members[logical],
            'Original import member differs from immutable original bytes: '+logical)
        members[logical]=dict(originalName=original_name,raw=body,fingerprint=fingerprint(body))
    require(set(members)==set(expected_members),'Complete original import member set required')
    return members


def _host_file(logical,roots):
    logical=logical_path(logical);matches=[N.ordinary(root,directory=True)/logical[len(prefix)+1:]
        for prefix,root in roots.items()if logical.startswith(prefix+'/')]
    require(len(matches)==1,'One actual original import mount required')
    return N.ordinary(matches[0],file=True)


def _context_key(event):
    context=event.get('context');require(type(context)is list and len(context)==7,'Actual original compiler task context required')
    return ':'.join(map(str,context[:4]))


def _false_condition(event,probe,message):
    """Original Evaluator leaves ImportIgnored=false for this explicit message."""
    arguments=event.get('arguments');line=event.get('line');column=event.get('column')
    if not(type(arguments)is list and len(arguments)==6 and event.get('message')==message
            and event.get('importedProject')is None and event.get('importIgnored')is False
            and type(line)is int and line>0 and type(column)is int and column>0):return False
    if arguments[:5]!=[probe['unexpanded'],probe['parent'],str(line),str(column),probe['condition']]:return False
    suffix=probe['unexpanded'].rsplit('.',1)[-1]
    return isinstance(arguments[5],str)and re.fullmatch(
        r"Exists\('VisualStudio[\\/]v[A-Za-z0-9._-]{0,64}[\\/]Microsoft\.Portable\.CurrentVersion\."+re.escape(suffix)+r"'\)",arguments[5])is not None


def validate_log(raw,role,expected_fingerprint,*,host_roots,compiler_record,input_names):
    """Read actual files and raw records; return a scoped import correspondence."""
    p=policy();require(role in p['logs']and set(host_roots)=={'/inputs','/output','/bootstrap','/inspector'},
        'One exact original App/Reader import role and actual four mounts required')
    expected=p['logs'][role];decoded=decode_binlog(raw,expected_fingerprint,expected_format=expected['format'])
    members=import_members(decoded,expected['originalMembers']);events=decoded['events'];origins={}
    for logical,row in members.items():
        path=_host_file(logical,host_roots)
        require(N.fingerprint(path)==row['fingerprint'],'Actual imported source bytes differ from original embedded member')
        origins[logical]=dict(originalName=row['originalName'],**row['fingerprint'])
    starts=[e for e in events if e['kind']=='TaskStarted'and e.get('taskName')=='Csc']
    ends=[e for e in events if e['kind']=='TaskFinished'and e.get('taskName')=='Csc']
    require(len(starts)==len(ends)==1 and _context_key(starts[0])==_context_key(ends[0])==compiler_record['context']
        and starts[0]['projectFile']==ends[0]['projectFile']==expected['project']
        and starts[0]['taskFile']==ends[0]['taskFile']==expected['compilerTarget']and ends[0]['succeeded']is True,
        'Parsed original Csc boundary must match the actual retained compiler context/project/target')
    require(starts[0]['eventNumber']<ends[0]['eventNumber'],'Original compiler event order differs')
    commands=[e for e in events if e['kind']=='TaskCommandLine'and e.get('taskName')=='Csc'
        and _context_key(e)==compiler_record['context']]
    require(len(commands)==1 and commands[0]['commandLine']==compiler_record['commandLine']
        and starts[0]['eventNumber']<commands[0]['eventNumber']<ends[0]['eventNumber'],
        'Raw original compiler argv must match the actually replayed compiler record')
    imports=[e for e in events if e['kind']=='ProjectImported'];successful=[];ignored=[]
    for event in imports:
        parent=logical_path(event['projectFile']);target=event.get('importedProject')
        require(parent in members,'Original import parent has no authenticated source body')
        if event['importIgnored']or target in(None,''):
            ignored.append(event);continue
        target=logical_path(target);require(target in members,'Successful original import has no authenticated source body')
        successful.append(dict(parent=parent,target=target,unexpanded=event.get('unexpandedProject'),
            eventNumber=event['eventNumber'],line=event.get('line'),context=event.get('context')))
    projects=[e for e in events if e['kind']=='ProjectStarted'and e.get('projectFile')==expected['project']]
    finishes=[e for e in events if e['kind']=='BuildFinished']
    require(projects and len(finishes)==1 and finishes[0].get('succeeded')is True,
        'Original imported project and successful complete build events required')
    required=set(members)-{expected['project']}
    if role=='reader-build':required-={'/output/'+name for name in GENERATED}
    require(required<={row['target']for row in successful},'Every original imported source must have its actual successful import event')
    mono_edges=[]
    if role=='app':
        for edge in p['monoRequiredEdges']:
            matches=[row for row in successful if all(row[key]==value for key,value in edge.items())]
            require(len(matches)==1,'One exact original Mono import expression/edge required')
            mono_edges.append(matches[0])
        sibling_order=[row['eventNumber']for row in mono_edges if row['parent']=='/inputs/portable/v4.5/Microsoft.Portable.CSharp.targets']
        require(sibling_order==sorted(sibling_order),'Original Mono CSharp sibling import order differs')
    probes=[]
    if role=='app':
        for probe in p['monoConditionalProbes']:
            observed=[e for e in ignored if e.get('projectFile')==probe['parent']and e.get('unexpandedProject')==probe['unexpanded']]
            false_evidence=[e for e in observed if _false_condition(e,probe,p['falseConditionMessage'])]
            namespace_absent=not any(name.startswith('portable/VisualStudio/')for name in input_names)
            probes.append(dict(**probe,ignoredEvents=[{k:e.get(k)for k in('eventNumber','line','message','arguments','importedProject')}for e in observed],
                explicitFalseConditionObserved=bool(false_evidence),completeTypedNamespaceHasNoCandidateFile=namespace_absent,
                validated=bool(false_evidence)and namespace_absent))
    pending=[]if all(row['validated']for row in probes)else['original-Mono-VS-conditional-absence-evidence']
    return dict(kind='scoped-actual-original-App-import-bindings',role=role,binlog=decoded['fingerprint'],format=decoded['format'],
        msbuildSourceCommit=expected['msbuildCommit'],members=origins,successfulImports=successful,monoRequiredEdges=mono_edges,conditionalProbes=probes,
        originalNonImportEvents=[{key:e.get(key)for key in('eventNumber','context','projectFile','line','column','message','arguments','importedProject','unexpandedProject','importIgnored')}for e in ignored],
        monoConditionalAbsenceValidated=not pending,pendingGates=pending,actualMountedInputBytesCompared=True,
        bootstrapArchiveConstructionValidated=False,wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)


def generated_reader_files(host_roots):
    generated={name:N.fingerprint(_host_file('/output/'+name,host_roots))for name in GENERATED}
    require(all(generated[name]==policy()['logs']['reader-build']['originalMembers']['/output/'+name]for name in GENERATED),
        'Actual current Reader generated import origins differ')
    return generated


def validate_normal_logs(workspace,host_roots,*,normal_context):
    """No descriptor-only normal positive: revalidate actual physical N evidence."""
    execution=N.verify_normal_execution(workspace,host_roots,normal_context=normal_context)
    workspace=N.ordinary(workspace,directory=True);strong,worker=N.original_validators()
    inputs=worker.verify_inputs(workspace);logs={}
    for role,key,compiler in(('app','rawAppBinlog','appCompiler'),('reader-build','rawReaderBuildBinlog','readerCompiler')):
        path=N.ordinary(workspace/'output'/(role+'.binlog'),file=True)
        require(path.stat().st_size<=MAX_COMPRESSED,'Bounded actual original App binlog required')
        logs[role]=validate_log(path.read_bytes(),role,execution[key],host_roots=host_roots,
            compiler_record=execution[compiler],input_names=inputs['files'])
    generated=generated_reader_files(host_roots)
    return dict(kind='scoped-normal-App-original-import-provenance',logs=logs,generatedReaderFiles=generated,
        normalBoundary=execution['boundary'],normalParentBuildRequiredAtAdmission=True,
        pendingGates=sorted({gate for row in logs.values()for gate in row['pendingGates']}
            |{'original-three-BOOT-archive-construction','archive-backed-normal-and-actual-SDK-consumption'}),
        actualOriginalInputsAndProcessesRead=True,bootstrapArchiveConstructionValidated=False,
        wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)
