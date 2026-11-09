"""Synthetic wire/source fixtures only; never read or replay a retained binlog."""
import copy
import gzip
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'scripts'))
import musl_legacy5_appinsights_imports as M


def integer(value):
    value&=0xffffffff;output=bytearray()
    while value>=128:output.append((value&127)|128);value>>=7
    output.append(value);return bytes(output)


class Wire:
    """Independent tiny writer for the pinned documented wire primitives."""
    def __init__(self,version=13):self.version=version;self.body=bytearray(struct.pack('<i',version));self.strings={};self.lists=0

    def text(self,value):
        if value is None:return b'\0'
        if value=='':return b'\1'
        if value not in self.strings:
            self.strings[value]=10+len(self.strings);raw=value.encode()
            self.body+=integer(24)+integer(len(raw))+raw
        return integer(self.strings[value])

    def dictionary(self,values):
        if values is None:return b'\0'
        pairs=b''.join(self.text(key)+self.text(value)for key,value in values.items())
        index=10+self.lists;self.lists+=1;self.body+=integer(23)+integer(len(values))+pairs
        return integer(index)

    def common(self,**values):
        ordered=[(4,'message'),(1,'context'),(16,'threadId'),(2,'helpKeyword'),(8,'senderName'),(32,'timestamp'),
            (64,'subcategory'),(128,'code'),(256,'file'),(512,'projectFile'),(1024,'line'),(2048,'column'),
            (4096,'endLine'),(8192,'endColumn'),(16384,'arguments'),(32768,'importance')]
        flags=sum(bit for bit,key in ordered if key in values);raw=integer(flags)
        for _,key in ordered:
            if key not in values:continue
            value=values[key]
            if key=='context':raw+=b''.join(integer(v)for v in value)
            elif key=='timestamp':raw+=struct.pack('<q',value[0])+integer(value[1])
            elif key=='arguments':raw+=integer(len(value))+b''.join(self.text(v)for v in value)
            elif key in('threadId','line','column','endLine','endColumn','importance'):raw+=integer(value)
            else:raw+=self.text(value)
        return raw

    def event(self,kind,payload):
        body=payload(self)if callable(payload)else payload
        self.body+=integer(kind)+body

    def finish(self,members=None,*,tail=b'\0',comment=b'',entry_extra=b'',entry_comment=b''):
        raw=io.BytesIO()
        with zipfile.ZipFile(raw,'w',compression=zipfile.ZIP_DEFLATED)as archive:
            for name,body in(members or{'\\inputs\\recipe\\App.PCL.proj':b'<Project />\n'}).items():
                entry=zipfile.ZipInfo('original-logical-name');entry.filename=name;entry.orig_filename=name
                entry.compress_type=zipfile.ZIP_DEFLATED;entry.extra=entry_extra;entry.comment=entry_comment
                archive.writestr(entry,body)
            archive.comment=comment
        self.body+=integer(17)+integer(len(raw.getvalue()))+raw.getvalue()+tail
        return gzip.compress(bytes(self.body),mtime=0)


def fixture(role='app',*,secret=None,probe=False):
    version=13 if role=='app' else 14;w=Wire(version)
    project='/inputs/recipe/App.PCL.proj'if role=='app'else'/inputs/reader/Reader.csproj'
    target=('/bootstrap/sdk/5.0.401/'if role=='app'else'/inspector/sdk/6.0.135/')+'Roslyn/Microsoft.CSharp.Core.targets'
    context=[1,2,3,4,5,6,-1];command='dotnet exec '+target.removesuffix('Microsoft.CSharp.Core.targets')+'bincore/csc.dll /noconfig original.cs'
    w.event(1,lambda x:x.common()+x.dictionary({'Fixture':'synthetic-only'}))
    w.event(3,lambda x:x.common()+b'\0'+x.text(project)+integer(1)+x.text('Build')+x.text('Current')+b'\0\0\0')
    w.event(16,lambda x:x.common(projectFile=project,line=1,context=context)+b'\0'+x.text(target)+x.text('$(MSBuildToolsPath)/Roslyn/Microsoft.CSharp.Core.targets'))
    probe_name='VisualStudio\\v$(VisualStudioVersion)\\Microsoft.Portable.CurrentVersion.props'
    condition="Exists('"+probe_name+"')"
    false_message='Project "{0}" was not imported by "{1}" at ({2},{3}), due to false condition; ({4}) was evaluated as ({5}).'
    if probe:w.event(16,lambda x:x.common(projectFile=project,message=false_message,context=context,line=2,column=3,
        arguments=[probe_name,project,'2','3',condition,"Exists('VisualStudio\\v16.0\\Microsoft.Portable.CurrentVersion.props')"])
        +b'\0'+x.text(None)+x.text(probe_name))
    w.event(7,lambda x:x.common(context=context)+x.text('Csc')+x.text(project)+x.text(target))
    w.event(12,lambda x:x.common(context=context,importance=0)+x.text(command)+x.text('Csc'))
    w.event(8,lambda x:x.common(context=context)+b'\1'+x.text('Csc')+x.text(project)+x.text(target))
    w.event(2,lambda x:x.common()+b'\1')
    bodies={project:b'<Project>synthetic original project</Project>\n',target:secret or b'<Project>synthetic compiler target</Project>\n'}
    raw=w.finish({'\\'+name[1:].replace('/','\\'):body for name,body in bodies.items()})
    policy=dict(logs={role:dict(format=version,project=project,compilerTarget=target,msbuildCommit='fixture-source-only',
        originalMembers={name:M.fingerprint(body)for name,body in bodies.items()})},monoRequiredEdges=[],falseConditionMessage=false_message,
        monoConditionalProbes=[dict(parent=project,unexpanded=probe_name,condition=condition)]if probe else[])
    return raw,policy,dict(context='1:2:3:4',commandLine=command),bodies


def replace_archive(raw,mutate):
    decoded=M.decode_binlog(raw,M.fingerprint(raw),expected_format=13)
    old=decoded['archive'];changed=mutate(old['raw'])
    record_start=old['offset']-len(integer(len(old['raw'])))-1
    require=unittest.TestCase().assertEqual;require(decoded['expanded'][record_start],17)
    return gzip.compress(decoded['expanded'][:record_start]+integer(17)+integer(len(changed))+changed
        +decoded['expanded'][old['end']:],mtime=0)


class OriginalWireDecoding(unittest.TestCase):
    def decode(self,raw,version=13):return M.decode_binlog(raw,M.fingerprint(raw),expected_format=version)

    def test_original_policy_has_two_explicit_sources_and105_byte_pins(self):
        p=M.policy();self.assertEqual([len(p['logs'][r]['originalMembers'])for r in('app','reader-build')],[22,83])
        self.assertEqual(len(p['monoRequiredEdges']),5)
        self.assertFalse(p['bootstrapArchiveConstructionValidated']);self.assertFalse(p['sourceAdmissionAllowed'])

    def test_both_framed_versions_preserve_raw_contexts_offsets_and_argv(self):
        for role in('app','reader-build'):
            raw,p,compiler,_=fixture(role);decoded=self.decode(raw,p['logs'][role]['format'])
            start=next(e for e in decoded['events']if e['kind']=='TaskStarted')
            self.assertEqual(start['context'],[1,2,3,4,5,6,-1])
            self.assertLess(start['offset'],start['end']);self.assertEqual(start['recordNumber']>=start['eventNumber'],True)
            self.assertEqual(next(e for e in decoded['events']if e['kind']=='TaskCommandLine')['commandLine'],compiler['commandLine'])
            self.assertEqual(len(M.import_members(decoded,p['logs'][role]['originalMembers'])),2)

    def test_all_documented_event_kinds_are_consumed_without_arbitrary_skip(self):
        for version in(13,14):
            w=Wire(version)
            for kind in range(1,26):
                if kind in(17,23,24):continue
                def payload(x):
                    c=x.common()
                    if kind==1:return c+b'\0'
                    if kind==2:return c+b'\1'
                    if kind==3:return c+b'\0'+x.text('/inputs/project')+b'\1'+x.text('Build')+x.text('Current')+b'\0\0\0'
                    if kind==4:return c+x.text('/inputs/project')+b'\1'
                    if kind==5:return c+b'\0'*5
                    if kind==6:return c+b'\1'+b'\0'*4
                    if kind==7:return c+b'\0'*3
                    if kind==8:return c+b'\1'+b'\0'*3
                    if kind in(9,10):return c+b'\0'*8
                    if kind in(11,13):return c
                    if kind==12:return c+b'\0'*2
                    if kind==14:return c+b'\0'
                    if kind==15:return c+b'\0'*5
                    if kind==16:return c+b'\1\0\0'
                    if kind==18:return c+b'\0'*(7 if version==13 else 9)
                    if kind==19:return c+b'\0'*4
                    if kind in(20,21):return c+b'\0'
                    if kind==22:return c+b'\0'*3
                    if kind==25:return c+b'\0'*3
                    raise AssertionError(kind)
                w.event(kind,payload)
            decoded=self.decode(w.finish(),version)
            self.assertEqual({e['kind']for e in decoded['events']},{M.KINDS[k]for k in range(1,26)if k not in(17,23,24)})

    def test_format14_skipped_target_uses_fixed_width_optional_original_context(self):
        w=Wire(14);original=[11,12,-1,-1,15,16,17]
        w.event(18,lambda x:x.common()+b'\0'*7+integer(1)+b'\1'+struct.pack('<7i',*original))
        w.event(11,lambda x:x.common(message='next correctly framed event'))
        decoded=self.decode(w.finish(),14)
        self.assertEqual(decoded['events'][0]['originalContext'],original)
        self.assertEqual(decoded['events'][1]['message'],'next correctly framed event')

    def test_common_flags_arguments_timestamp_and_metadata_are_preserved(self):
        w=Wire();values=dict(message='original {0}',arguments=['value'],context=[1,2,3,4,5,6,7],threadId=8,
            timestamp=(123456789,2),senderName='sender',helpKeyword='help',subcategory='sub',code='C1',file='f',
            projectFile='/inputs/project',line=1,column=2,endLine=3,endColumn=4,importance=2)
        w.event(11,lambda x:x.common(**values));event=self.decode(w.finish())['events'][0]
        for name,want in values.items():self.assertEqual(event[name],dict(ticks=want[0],kind=want[1])if name=='timestamp'else want)

    def test_nonempty_dictionary_task_items_and_profile_records_are_framed(self):
        w=Wire()
        w.event(25,lambda x:x.common()+integer(0)+x.text('References')+integer(1)+x.text('/inputs/a.dll')+x.dictionary({'Original':'true'}))
        w.event(15,lambda x:x.common()+x.text('/inputs/project')+b'\0'+x.dictionary({'P':'V'})+b'\0\1\1'
            +b'\0'*6+b'\1'+integer(7)+struct.pack('<q',8)+b'\1'+struct.pack('<q',9)+integer(10)+struct.pack('<qq',11,12))
        events=self.decode(w.finish())['events']
        self.assertEqual(events[0]['items'][0]['metadata'],{'Original':'true'})
        self.assertEqual(events[1]['profile'][0]['inclusiveTicks'],12)

    def test_unsupported_record_and_flags_never_recover_by_zip_signature(self):
        for payload in(integer(26),integer(11)+integer(65536)):
            w=Wire();w.body+=payload
            with self.subTest(payload=payload),self.assertRaisesRegex(ValueError,'Unsupported'):self.decode(w.finish())

    def test_bad_varints_utf8_and_string_indices_reject(self):
        for payload in(b'\x98\0',b'\x80'*5,b'\x18\1\xff',integer(11)+integer(4)+integer(9)):
            w=Wire();w.body+=payload
            with self.subTest(payload=payload),self.assertRaises(ValueError):self.decode(w.finish())

    def test_bad_boolean_unknown_dictionary_and_truncation_reject(self):
        for payload in(integer(2)+b'\0\2',integer(1)+b'\0'+integer(9),integer(11)+integer(32)+b'\0'):
            w=Wire();w.body+=payload
            with self.subTest(payload=payload),self.assertRaises(ValueError):self.decode(w.finish())

    def test_wrong_fingerprint_or_format_never_uses_another_parser(self):
        raw,*_=fixture()
        with self.assertRaisesRegex(ValueError,'fingerprint'):M.decode_binlog(raw,dict(M.fingerprint(raw),bytes=1),expected_format=13)
        with self.assertRaisesRegex(ValueError,'format/source'):self.decode(raw,14)

    def test_one_gzip_member_no_trailing_record_and_complete_crc_required(self):
        raw,*_=fixture()
        for changed in(raw+gzip.compress(b'next'),raw[:-3],raw[:-1]+bytes([raw[-1]^1])):
            with self.subTest(size=len(changed)),self.assertRaises(ValueError):self.decode(changed)
        w=Wire()
        with self.assertRaisesRegex(ValueError,'final record'):self.decode(w.finish(tail=integer(24)+b'\0\0'))
        w=Wire()
        with self.assertRaisesRegex(ValueError,'final EOF'):self.decode(w.finish(tail=b'\0\0'))

    def test_missing_archive_and_expansion_record_count_bounds_reject(self):
        with self.assertRaisesRegex(ValueError,'archive'):self.decode(gzip.compress(struct.pack('<i',13)+b'\0'))
        raw,*_=fixture()
        with patch.object(M,'MAX_EXPANDED',16),self.assertRaisesRegex(ValueError,'bounded'):self.decode(raw)
        with patch.object(M,'MAX_RECORDS',1),self.assertRaisesRegex(ValueError,'record count'):self.decode(raw)


class CumulativeAllocationAndEnums(unittest.TestCase):
    def decode(self,raw,version=13):return M.decode_binlog(raw,M.fingerprint(raw),expected_format=version)

    def item_records(self,count):
        w=Wire()
        for _ in range(count):
            w.event(25,lambda x:x.common()+integer(0)+x.text('Items')+integer(4)
                +b''.join(x.text('same shared item')+b'\0'for _ in range(4)))
        return w.finish()

    def test_aggregate_items_across_distinct_records_exhaust_one_budget(self):
        one=self.item_records(1);two=self.item_records(2);limit=self.decode(one)['decodedAllocation']['nodes']
        self.assertGreater(self.decode(two)['decodedAllocation']['nodes'],limit)
        with patch.object(M,'MAX_DECODED_NODES',limit):
            self.decode(one)
            with self.assertRaisesRegex(ValueError,'Cumulative.*decoded-node'):self.decode(two)

    def test_arguments_namevalues_items_and_profile_counts_reject_before_allocating_missing_bodies(self):
        payloads=[integer(11)+integer(16384)+integer(M.MAX_COUNT),
            integer(23)+integer(M.MAX_COUNT),
            integer(25)+b'\0\0\0'+integer(M.MAX_COUNT),
            integer(15)+b'\0\0\0\0\0\1'+integer(M.MAX_COUNT)]
        for payload in payloads:
            w=Wire();w.body+=payload
            with self.subTest(payload=payload[:4]),patch.object(M,'MAX_DECODED_NODES',30),\
                    self.assertRaisesRegex(ValueError,'Cumulative.*decoded-node'):self.decode(w.finish())

    def test_cumulative_string_bytes_across_records_reject_before_utf8_allocation(self):
        w=Wire();w.text('a'*24);w.text('b'*24);raw=w.finish()
        with patch.object(M,'MAX_DECODED_TEXT_BYTES',32),self.assertRaisesRegex(ValueError,'decoded-text'):self.decode(raw)

    def test_many_tiny_event_records_share_the_same_node_budget(self):
        w=Wire()
        for _ in range(6):w.event(11,lambda x:x.common())
        with patch.object(M,'MAX_DECODED_NODES',20),self.assertRaisesRegex(ValueError,'Cumulative.*decoded-node'):self.decode(w.finish())

    def test_every_enum_uses_only_the_exact_source_defined_set(self):
        for name,values in M.ENUMS.items():
            for value in values:
                reader=M._Reader(struct.pack('<i',13)+integer(value),13)
                self.assertEqual(reader.enum(name),value)
            for value in(-1,max(values)+1,127):
                reader=M._Reader(struct.pack('<i',13)+integer(value),13)
                with self.subTest(name=name,value=value),self.assertRaisesRegex(ValueError,'Unsupported.*enum'):reader.enum(name)

    def test_invalid_build_skip_and_parameter_enums_are_wired_into_event_records(self):
        payloads=[(13,integer(5)+b'\0'*5+integer(4)),
            (14,integer(18)+b'\0'*8+integer(5)),
            (13,integer(25)+b'\0'+integer(6))]
        for version,payload in payloads:
            w=Wire(version);w.body+=payload
            with self.subTest(version=version),self.assertRaisesRegex(ValueError,'Unsupported.*enum'):self.decode(w.finish(),version)

    def test_invalid_profile_enums_are_rejected_at_their_actual_event_fields(self):
        for kind,evaluation_pass in((3,0),(0,9)):
            w=Wire();w.body+=integer(15)+b'\0'*5+b'\1\1'+b'\0'*4+integer(kind)+integer(evaluation_pass)
            with self.subTest(kind=kind,evaluation_pass=evaluation_pass),self.assertRaisesRegex(ValueError,'Unsupported.*enum'):
                self.decode(w.finish())


class CompleteZipByteCoverage(unittest.TestCase):
    BODY=b'<Project />\n'
    NAME='\\inputs\\recipe\\App.PCL.proj'

    def check(self,raw):
        decoded=M.decode_binlog(raw,M.fingerprint(raw),expected_format=13)
        return M.import_members(decoded,{'/inputs/recipe/App.PCL.proj':M.fingerprint(self.BODY)})

    def test_extra_and_entry_comment_private_containers_reject(self):
        secret=gzip.compress(b'MZ\0synthetic private byte body\xff');extra=struct.pack('<HH',0xcafe,len(secret))+secret
        for kwargs in(dict(entry_extra=extra),dict(entry_comment=secret)):
            with self.subTest(kwargs=kwargs.keys()),self.assertRaisesRegex(ValueError,'extra fields.*comments'):
                self.check(Wire().finish({self.NAME:self.BODY},**kwargs))

    def test_padding_before_directory_is_rejected_even_when_all_member_bytes_match(self):
        def pad(blob):
            offset=struct.unpack_from('<I',blob,len(blob)-6)[0];padding=b'unaccounted private container padding'
            changed=bytearray(blob[:offset]+padding+blob[offset:]);struct.pack_into('<I',changed,len(changed)-6,offset+len(padding))
            return bytes(changed)
        raw=replace_archive(Wire().finish({self.NAME:self.BODY}),pad)
        with self.assertRaisesRegex(ValueError,'unaccounted data'):self.check(raw)

    def test_local_central_name_crc_and_local_extra_mismatches_reject(self):
        for field in('name','crc','extra'):
            def mutate(blob):
                data=bytearray(blob)
                if field=='name':data[30]=ord('X')
                elif field=='crc':data[14]^=1
                else:struct.pack_into('<H',data,28,1)
                return bytes(data)
            raw=replace_archive(Wire().finish({self.NAME:self.BODY}),mutate)
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'local'):self.check(raw)

    def test_hidden_tail_after_deflate_stream_rejects_with_unchanged_known_member(self):
        def mutate(blob):
            offset=struct.unpack_from('<I',blob,len(blob)-6)[0];size=struct.unpack_from('<I',blob,18)[0]
            start=30+struct.unpack_from('<H',blob,26)[0];end=start+size;tail=gzip.compress(b'synthetic forbidden tail')
            data=bytearray(blob[:end]+tail+blob[end:]);new_offset=offset+len(tail)
            struct.pack_into('<I',data,18,size+len(tail));struct.pack_into('<I',data,new_offset+20,size+len(tail))
            struct.pack_into('<I',data,len(data)-6,new_offset);return bytes(data)
        raw=replace_archive(Wire().finish({self.NAME:self.BODY}),mutate)
        with self.assertRaisesRegex(ValueError,'deflate stream.*padding'):self.check(raw)

    def test_declared_entry_count_is_bounded_before_any_directory_objects(self):
        def mutate(blob):
            data=bytearray(blob);struct.pack_into('<HH',data,len(data)-14,M.MAX_MEMBERS+1,M.MAX_MEMBERS+1);return bytes(data)
        raw=replace_archive(Wire().finish({self.NAME:self.BODY}),mutate)
        with self.assertRaisesRegex(ValueError,'Bounded single-disk'):self.check(raw)

    def test_exact_signed_and_unsigned_data_descriptors_cover_all_original_bytes(self):
        for signed in(False,True):
            def mutate(blob):
                offset=struct.unpack_from('<I',blob,len(blob)-6)[0]
                crc,compressed,size=struct.unpack_from('<3I',blob,14)
                descriptor=(b'PK\x07\x08'if signed else b'')+struct.pack('<3I',crc,compressed,size)
                data=bytearray(blob[:offset]+descriptor+blob[offset:]);new_offset=offset+len(descriptor)
                struct.pack_into('<H',data,6,8);struct.pack_into('<3I',data,14,0,0,0)
                struct.pack_into('<H',data,new_offset+8,8);struct.pack_into('<I',data,len(data)-6,new_offset)
                return bytes(data)
            result=self.check(replace_archive(Wire().finish({self.NAME:self.BODY}),mutate))
            self.assertEqual(result['/inputs/recipe/App.PCL.proj']['raw'],self.BODY)


class LogicalImports(unittest.TestCase):
    def decoded(self,raw):return M.decode_binlog(raw,M.fingerprint(raw),expected_format=13)

    def test_original_backslash_convention_is_logical_only(self):
        self.assertEqual(M.zip_logical_path('\\inputs\\source\\Original.props'),'/inputs/source/Original.props')
        for name in('/inputs/file','\\\\server\\file','C:\\file','\\inputs\\..\\file','\\inputs\\\\file','\\inputs/file','\\inputs\\.\\file'):
            with self.subTest(name=name),self.assertRaises(ValueError):M.zip_logical_path(name)

    def test_unknown_or_changed_original_zip_member_rejects(self):
        raw,p,_,_=fixture();decoded=self.decoded(raw);members=p['logs']['app']['originalMembers']
        with self.assertRaisesRegex(ValueError,'Unknown'):M.import_members(decoded,{})
        altered=copy.deepcopy(members);next(iter(altered.values()))['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'immutable'):M.import_members(decoded,altered)

    def test_zip_comment_special_mode_duplicate_and_parent_paths_reject(self):
        raw,p,_,_=fixture();expected=p['logs']['app']['originalMembers']
        with self.assertRaisesRegex(ValueError,'uncommented'):M.import_members(self.decoded(Wire().finish(comment=b'comment')),expected)
        for names in[('\\inputs\\..\\file',),('\\inputs\\same','\\inputs\\same')]:
            z=io.BytesIO()
            with warnings.catch_warnings(),zipfile.ZipFile(z,'w')as archive:
                warnings.simplefilter('ignore',UserWarning)
                for name in names:
                    entry=zipfile.ZipInfo('original-name');entry.filename=name;entry.orig_filename=name
                    entry.create_system=3;entry.external_attr=0o120777<<16;archive.writestr(entry,b'target')
            decoded={'archive':{'raw':z.getvalue()}}
            with self.assertRaises(ValueError):M.import_members(decoded,expected)

    def with_hosts(self,bodies):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);root=Path(temporary.name)
        hosts={name:root/name[1:]for name in('/inputs','/output','/bootstrap','/inspector')}
        for path in hosts.values():path.mkdir()
        for logical,body in bodies.items():
            prefix=next(p for p in hosts if logical.startswith(p+'/'));path=hosts[prefix]/logical[len(prefix)+1:]
            path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body)
        return hosts

    def test_actual_tiny_host_bytes_compiler_context_and_raw_import_edges_bind(self):
        raw,p,compiler,bodies=fixture(probe=True);hosts=self.with_hosts(bodies)
        with patch.object(M,'policy',return_value=p):
            result=M.validate_log(raw,'app',M.fingerprint(raw),host_roots=hosts,compiler_record=compiler,input_names=['source/Original.cs'])
        self.assertTrue(result['actualMountedInputBytesCompared']);self.assertTrue(result['monoConditionalAbsenceValidated'])
        self.assertFalse(result['bootstrapArchiveConstructionValidated']);self.assertFalse(result['sourceAdmissionAllowed'])

    def test_wrong_actual_source_or_compiler_context_rejects(self):
        raw,p,compiler,bodies=fixture();hosts=self.with_hosts(bodies)
        with patch.object(M,'policy',return_value=p):
            with self.assertRaisesRegex(ValueError,'compiler context'):
                M.validate_log(raw,'app',M.fingerprint(raw),host_roots=hosts,compiler_record=dict(compiler,context='9:9:9:9'),input_names=[])
            target=next(name for name in bodies if name.startswith('/bootstrap'))
            (hosts['/bootstrap']/target[len('/bootstrap/'):]).write_bytes(b'changed actual source')
            with self.assertRaisesRegex(ValueError,'Actual imported source'):
                M.validate_log(raw,'app',M.fingerprint(raw),host_roots=hosts,compiler_record=compiler,input_names=[])

    def test_missing_conditional_false_evidence_stays_explicit_pending(self):
        raw,p,compiler,bodies=fixture();hosts=self.with_hosts(bodies)
        p['monoConditionalProbes']=[dict(parent=p['logs']['app']['project'],unexpanded='VisualStudio\\Absent.props')]
        with patch.object(M,'policy',return_value=p):
            result=M.validate_log(raw,'app',M.fingerprint(raw),host_roots=hosts,compiler_record=compiler,input_names=[])
        self.assertFalse(result['monoConditionalAbsenceValidated'])
        self.assertEqual(result['pendingGates'],['original-Mono-VS-conditional-absence-evidence'])

    def test_present_candidate_namespace_cannot_claim_false_absence(self):
        raw,p,compiler,bodies=fixture(probe=True);hosts=self.with_hosts(bodies)
        with patch.object(M,'policy',return_value=p):
            result=M.validate_log(raw,'app',M.fingerprint(raw),host_roots=hosts,compiler_record=compiler,
                input_names=['portable/VisualStudio/v16.0/Microsoft.Portable.CurrentVersion.props'])
        self.assertFalse(result['monoConditionalAbsenceValidated'])

    def test_mono_edge_expression_or_parent_forgery_rejects(self):
        raw,p,compiler,bodies=fixture();hosts=self.with_hosts(bodies)
        p['monoRequiredEdges']=[dict(parent=p['logs']['app']['project'],target=p['logs']['app']['compilerTarget'],unexpanded='forged expression')]
        with patch.object(M,'policy',return_value=p),self.assertRaisesRegex(ValueError,'Mono import expression'):
            M.validate_log(raw,'app',M.fingerprint(raw),host_roots=hosts,compiler_record=compiler,input_names=[])

    def test_original_false_condition_with_false_importignored_requires_exact_six_arguments(self):
        raw,p,_,_=fixture(probe=True);decoded=M.decode_binlog(raw,M.fingerprint(raw),expected_format=13)
        event=next(e for e in decoded['events']if e['kind']=='ProjectImported'and e.get('importedProject')is None)
        probe=p['monoConditionalProbes'][0]
        self.assertFalse(event['importIgnored'])
        self.assertTrue(M._false_condition(event,probe,p['falseConditionMessage']))
        for change in('parent','condition','expanded','message','flag'):
            altered=copy.deepcopy(event)
            if change=='parent':altered['arguments'][1]='/inputs/other/project'
            elif change=='condition':altered['arguments'][4]="Exists('/outside')"
            elif change=='expanded':altered['arguments'][5]="Exists('VisualStudio\\v..\\..\\Microsoft.Portable.CurrentVersion.props')"
            elif change=='message':altered['message']='An unrelated field says false'
            else:altered['importIgnored']=True
            with self.subTest(change=change):self.assertFalse(M._false_condition(altered,probe,p['falseConditionMessage']))

    def test_descriptor_only_or_failed_normal_boundary_never_binds_an_import(self):
        with patch.object(M.N,'verify_normal_execution',side_effect=ValueError('Actual original normal records required'))as normal:
            with self.assertRaisesRegex(ValueError,'Actual original normal'):
                M.validate_normal_logs('not-real-workspace',{},normal_context={})
        normal.assert_called_once_with('not-real-workspace',{},normal_context={})

    def test_three_generated_reader_origins_are_actual_files_not_descriptors(self):
        bodies={'/output/'+name:('actual synthetic generated '+name).encode()for name in M.GENERATED}
        hosts=self.with_hosts(bodies);p=dict(logs={'reader-build':dict(originalMembers={name:M.fingerprint(body)for name,body in bodies.items()})})
        with patch.object(M,'policy',return_value=p):
            actual=M.generated_reader_files(hosts)
        self.assertEqual(set(actual),set(M.GENERATED))
        for name,row in actual.items():self.assertEqual(row,M.fingerprint(bodies['/output/'+name]))

    def test_changed_or_missing_generated_reader_origin_rejects(self):
        bodies={'/output/'+name:b'original synthetic generated input'for name in M.GENERATED}
        hosts=self.with_hosts(bodies);p=dict(logs={'reader-build':dict(originalMembers={name:M.fingerprint(body)for name,body in bodies.items()})})
        path=hosts['/output']/M.GENERATED[0];path.write_bytes(b'altered generated origin')
        with patch.object(M,'policy',return_value=p),self.assertRaisesRegex(ValueError,'generated import origins'):
            M.generated_reader_files(hosts)
        path.unlink()
        with patch.object(M,'policy',return_value=p),self.assertRaisesRegex(ValueError,'Ordinary normal App5 file'):
            M.generated_reader_files(hosts)


    def unix_mono_fixture(self,*,expression_change=None,duplicate=False,wrong_endpoint=False,condition_change=False):
        p=M.policy();expected=p['logs']['app'];project=expected['project'];target=expected['compilerTarget']
        names={project,target}|{edge[key]for edge in p['monoRequiredEdges']for key in('parent','target')}
        bodies={name:('<Project>synthetic Unix import '+name+'</Project>\n').encode()for name in names}
        expected['originalMembers']={name:M.fingerprint(body)for name,body in bodies.items()}
        context=[1,2,3,4,5,6,-1];command='dotnet exec /bootstrap/sdk/5.0.401/Roslyn/bincore/csc.dll /noconfig synthetic.cs'
        w=Wire();w.event(1,lambda x:x.common()+x.dictionary({'Fixture':'synthetic Unix source getter'}))
        w.event(3,lambda x:x.common()+b'\0'+x.text(project)+integer(1)+x.text('Build')+x.text('Current')+b'\0\0\0')
        def imported(edge):
            w.event(16,lambda x:x.common(projectFile=edge['parent'],context=context,line=1,column=1)
                +b'\0'+x.text(edge['target'])+x.text(edge['unexpanded']))
        for index in(0,1,4,2,3):
            edge=copy.deepcopy(p['monoRequiredEdges'][index])
            if expression_change is not None and index==expression_change:
                edge['unexpanded']=p['monoProjectAttributeSemantics']['originalMonoRequiredEdges'][index]['unexpanded']
            if wrong_endpoint and index==2:edge['target']=p['monoRequiredEdges'][4]['target']
            imported(edge)
            if duplicate and index==2:imported(edge)
            if index not in(4,3):continue
            probe=p['monoConditionalProbes'][0 if index==4 else 1]
            condition=probe['condition'].replace('\\','/')if condition_change else probe['condition']
            expanded=probe['condition'].replace('$(VisualStudioVersion)','16.0')
            w.event(16,lambda x:x.common(projectFile=probe['parent'],context=context,line=2,column=3,
                message=p['falseConditionMessage'],arguments=[probe['unexpanded'],probe['parent'],'2','3',condition,expanded])
                +b'\0'+x.text(None)+x.text(probe['unexpanded']))
        imported(dict(parent=p['monoRequiredEdges'][2]['target'],target=target,unexpanded='$(MSBuildToolsPath)/Roslyn/Microsoft.CSharp.Core.targets'))
        w.event(7,lambda x:x.common(context=context)+x.text('Csc')+x.text(project)+x.text(target))
        w.event(12,lambda x:x.common(context=context,importance=0)+x.text(command)+x.text('Csc'))
        w.event(8,lambda x:x.common(context=context)+b'\1'+x.text('Csc')+x.text(project)+x.text(target))
        w.event(2,lambda x:x.common()+b'\1')
        raw=w.finish({'\\'+name[1:].replace('/','\\'):body for name,body in bodies.items()})
        return raw,p,dict(context='1:2:3:4',commandLine=command),self.with_hosts(bodies)

    def test_original_unix_project_getter_changes_only_project_slashes(self):
        p=M.policy();semantics=p['monoProjectAttributeSemantics']
        self.assertEqual(semantics['projectImportElementBlob'],'0260a1eae4671c58335cfc807d33966164c17b6e')
        self.assertEqual(semantics['fileUtilitiesBlob'],'1c50ccd6106846f887a19d4c1a6fc8bfecc50552')
        for key,original_key in(('monoRequiredEdges','originalMonoRequiredEdges'),('monoConditionalProbes','originalMonoConditionalProbes')):
            self.assertEqual(p[key],[dict(row,unexpanded=row['unexpanded'].replace('\\','/'))for row in semantics[original_key]])
        self.assertTrue(all('\\'in row['condition']for row in p['monoConditionalProbes']))

    def test_five_unix_wire_edges_and_two_original_conditions_bind(self):
        raw,p,compiler,hosts=self.unix_mono_fixture()
        with patch.object(M,'policy',return_value=p):
            result=M.validate_log(raw,'app',M.fingerprint(raw),host_roots=hosts,compiler_record=compiler,input_names=[])
        self.assertEqual(len(result['monoRequiredEdges']),5)
        self.assertTrue(result['monoConditionalAbsenceValidated'])
        self.assertEqual(result['pendingGates'],[])
        self.assertFalse(result['bootstrapArchiveConstructionValidated'])

    def test_original_backslash_project_spelling_is_not_an_alternate_unix_wire_match(self):
        for index in(2,3,4):
            raw,p,compiler,hosts=self.unix_mono_fixture(expression_change=index)
            with self.subTest(index=index),patch.object(M,'policy',return_value=p),self.assertRaisesRegex(ValueError,'Mono import expression'):
                M.validate_log(raw,'app',M.fingerprint(raw),host_roots=hosts,compiler_record=compiler,input_names=[])

    def test_normalized_expression_does_not_allow_duplicate_or_wrong_endpoint(self):
        for change in('duplicate','wrong_endpoint'):
            raw,p,compiler,hosts=self.unix_mono_fixture(**{change:True})
            with self.subTest(change=change),patch.object(M,'policy',return_value=p),self.assertRaises(ValueError):
                M.validate_log(raw,'app',M.fingerprint(raw),host_roots=hosts,compiler_record=compiler,input_names=[])

    def test_condition_text_is_never_normalized_with_the_project_attribute(self):
        raw,p,compiler,hosts=self.unix_mono_fixture(condition_change=True)
        with patch.object(M,'policy',return_value=p):
            result=M.validate_log(raw,'app',M.fingerprint(raw),host_roots=hosts,compiler_record=compiler,input_names=[])
        self.assertFalse(result['monoConditionalAbsenceValidated'])
        self.assertEqual(result['pendingGates'],['original-Mono-VS-conditional-absence-evidence'])


if __name__=='__main__':unittest.main()
