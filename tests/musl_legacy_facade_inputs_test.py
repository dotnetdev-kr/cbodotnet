"""Literal metadata is data; executable or ambiguous substitutes fail closed."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('literal_facade_reader',Path(__file__).resolve().parents[1]/'scripts/musl_legacy_facade_inputs.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)


def fixture(nested=False):
    strings=bytearray(b'\0')
    def string(value):
        at=len(strings);strings.extend(value.encode()+b'\0');return at
    module,assembly,reference,namespace,name,module_type=[string(value)for value in('Sample.dll','Sample','System.Runtime','Example','Thing','<Module>')]
    child=string('Nested')
    rows={0:struct.pack('<HHHHH',0,module,1,0,0),2:struct.pack('<IHHHHH',0,module_type,0,0,1,1),
        32:struct.pack('<IHHHHIHHH',0x8004,1,0,0,0,0,0,assembly,0),
        35:struct.pack('<HHHHIHHHH',7,0,0,0,0,0,reference,0,0),
        39:struct.pack('<IIHHH',0x200000,0,name,namespace,5)}
    if nested:rows[39]+=struct.pack('<IIHHH',2,0,child,0,6)
    tables=struct.pack('<IBBBBQQ',0,2,0,0,1,sum(1<<table for table in rows),0)
    tables+=b''.join(struct.pack('<I',2 if table==39 and nested else 1)for table in sorted(rows))
    row_offsets={};position=len(tables)
    for table in sorted(rows):row_offsets[table]=position;position+=len(rows[table])
    tables+=b''.join(rows[table]for table in sorted(rows))
    streams={'#~':tables,'#Strings':bytes(strings),'#Blob':b'\0','#GUID':b'\0'*16}
    version=b'v4.0.30319\0';version+=b'\0'*(-len(version)%4)
    header=b'BSJB'+struct.pack('<HHII',1,1,0,len(version))+version+struct.pack('<HH',0,len(streams))
    names={name:name.encode()+b'\0'for name in streams};names={name:value+b'\0'*(-len(value)%4)for name,value in names.items()}
    fixed=len(header)+sum(8+len(names[name])for name in streams);content=bytearray();descriptors=[];offsets={}
    for name,body in streams.items():
        offsets[name]=0x300+fixed+len(content)
        descriptors.append(struct.pack('<II',fixed+len(content),len(body))+names[name]);content.extend(body);content.extend(b'\0'*(-len(content)%4))
    metadata=header+b''.join(descriptors)+content
    data=bytearray(8192);data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,0x80);data[0x80:0x84]=b'PE\0\0'
    struct.pack_into('<HH',data,0x84,0x14c,1);struct.pack_into('<H',data,0x94,224);struct.pack_into('<H',data,0x98,0x10b)
    struct.pack_into('<I',data,0x98+92,16);struct.pack_into('<II',data,0x98+96+14*8,0x2000,72)
    section=0x98+224;struct.pack_into('<III',data,section+12,0x2000,len(data)-0x200,0x200)
    struct.pack_into('<IIII',data,0x200,72,0,0x2100,len(metadata));struct.pack_into('<I',data,0x210,1)
    data[0x300:0x300+len(metadata)]=metadata
    return bytes(data),{table:offsets['#~']+at for table,at in row_offsets.items()}


class LiteralFacadeBoundary(unittest.TestCase):
    def test_complete_forwarding_target_and_nested_scope_are_readable(self):
        actual=M.inspect(fixture(nested=True)[0])
        self.assertEqual('Sample',actual['assembly']['name'])
        self.assertEqual('System.Runtime',actual['assemblyReferences'][0]['name'])
        self.assertEqual([dict(assemblyReference=1,name='Example.Thing'),dict(assemblyReference=1,name='Example.Thing/Nested')],
            [row['resolved']for row in actual['exportedTypes']])
        self.assertIn(".class extern forwarder 'Example.Thing/Nested'",actual['readableIL'])
        self.assertEqual(bytes.fromhex(actual['metadataBytes'])[:4],b'BSJB')
        self.assertEqual({'0','2','32','35','39'},set(actual['tableRows']))

    def test_cyclic_exports_and_nonforwarding_implementation_are_rejected(self):
        raw,positions=fixture(nested=True)
        for at,fmt,value in((positions[39]+14+12,'<H',10),(positions[39]+12,'<H',4),(positions[39],'<I',0)):
            changed=bytearray(raw)
            struct.pack_into(fmt,changed,at,value)
            with self.assertRaises(ValueError):M.inspect(bytes(changed))

    def test_native_entrypoint_and_managed_native_header_are_rejected(self):
        raw,positions=fixture()
        for at,value in((0x210,0),(0x214,1),(0x240,0x2400),(0x244,24),(0x98+16,0x2200)):
            changed=bytearray(raw);struct.pack_into('<I',changed,at,value)
            with self.assertRaises(ValueError):M.inspect(bytes(changed))

    def test_unreviewed_package_and_additional_executable_inputs_cannot_use_policy(self):
        with tempfile.TemporaryDirectory()as temporary:
            package=Path(temporary)/'substitute.nupkg';package.write_bytes(fixture()[0])
            with self.assertRaises(ValueError):M.package_bodies(package)
        raw,positions=fixture();changed=bytearray(raw)
        valid_at=raw.index(b'#~\0',0x300)-8
        tables_at=0x300+struct.unpack_from('<I',raw,valid_at)[0]
        struct.pack_into('<Q',changed,tables_at+8,struct.unpack_from('<Q',raw,tables_at+8)[0]|1<<6)
        with self.assertRaises(ValueError):M.inspect(bytes(changed))


if __name__=='__main__':unittest.main()
