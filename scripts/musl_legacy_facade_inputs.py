"""Decode closed metadata-only type forwarders without loading a CLI image.

The readable declarations are derived from the retained literal metadata.
They are not asserted to be original Git source or a locally compiled product.
Executable assemblies, linked files and native CLI bodies are rejected.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import uuid
import tarfile
from musl_source_archive import open_source_archive
import xml.etree.ElementTree as ET
import zipfile

ROOT_NAME = 'literal-type-forwarder-metadata'
ROLE = 'derived-readable-type-forwarder-source-inputs'
KIND = 'readable-type-forwarder'
FP = ('bytes', 'sha256', 'sha512')


def fingerprint(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),sha512=hashlib.sha512(raw).hexdigest())


def require(value, message):
    if not value: raise ValueError(message)


def primitives():
    spec = importlib.util.spec_from_file_location('facade_managed_metadata', Path(__file__).with_name('musl_managed_metadata.py'))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def inspect(data):
    """Return all declaration tables, raw heaps and readable forwarding IL."""
    identity = primitives().inspect(data)
    definitions = identity['definitionCounts']
    require(definitions['types'] == 1 and definitions['methods'] == definitions['fields'] == definitions['files'] == definitions['resources'] == 0
            and 0 < definitions['exportedTypes'] <= 10000 and identity['cliFlags'] & 1
            and identity['entryPoint'] == identity['managedNativeHeaderBytes'] == 0,
            'Only method-free, field-free, resource-free, metadata-only type forwarders are admitted')
    require(len(data) <= 4 * 1024**2, 'A bounded type forwarder PE is required')

    def read(fmt, at, body=data):
        require(0 <= at <= len(body) - struct.calcsize(fmt), 'Truncated type forwarder metadata')
        return struct.unpack_from(fmt, body, at)[0]
    pe = read('<I', 0x3c); optional = pe + 24
    sections, optional_size = read('<H', pe + 6), read('<H', pe + 20)
    magic = read('<H', optional); directories = optional + (96 if magic == 0x10b else 112)
    ranges = [(read('<I', optional + optional_size + i * 40 + 12),
               read('<I', optional + optional_size + i * 40 + 20),
               read('<I', optional + optional_size + i * 40 + 16)) for i in range(sections)]
    def address(rva, length=1):
        matches = [offset + rva - start for start, offset, size in ranges if start <= rva and rva + length <= start + size]
        require(len(matches) == 1 and matches[0] + length <= len(data), 'Escaped type forwarder RVA')
        return matches[0]
    cli = address(read('<I', directories + 14 * 8), 72)
    require(all(read('<Q', cli + offset) == 0 for offset in (24, 40, 48, 56, 64)),
            'A type forwarder has resource, fixup, export or native CLI code')
    imports, imported_members = [], []
    import_rva, import_size = read('<I', directories + 8), read('<I', directories + 12)
    if import_size:
        start = address(import_rva, 20)
        for i in range(8):
            at = start + i * 20; fields = [read('<I', at + offset) for offset in (0, 4, 8, 12, 16)]
            if fields == [0] * 5: break
            name_at = address(fields[3]); end = data.find(b'\0', name_at, min(name_at + 256, len(data)))
            require(end >= name_at, 'Unterminated type forwarder native import')
            imports.append(data[name_at:end].decode('ascii').lower())
            thunk = address(fields[0] or fields[4], 8)
            require(magic == 0x10b and read('<I', thunk + 4) == 0 and not read('<I', thunk) & 0x80000000,
                    'Type forwarder imports a nonstandard native thunk')
            symbol_at = address(read('<I', thunk), 3) + 2
            symbol_end = data.find(b'\0', symbol_at, min(symbol_at + 128, len(data)))
            require(symbol_end >= symbol_at, 'Unterminated type forwarder bootstrap symbol')
            imported_members.append(data[symbol_at:symbol_end].decode('ascii'))
        else: raise ValueError('Oversized type forwarder native imports')
    require(imports in ([], ['mscoree.dll']) and imported_members in ([], ['_CorDllMain']),
            'A type forwarder imports nonstandard native code')
    # Standard IL-only PE32 images have only the CLR bootstrap jmp through
    # their import address table. No other native entrypoint is accepted.
    entry_rva = read('<I', optional + 16)
    if entry_rva:
        require(magic == 0x10b and read('<H', pe + 4) == 0x14c,
                'Unreviewed native type forwarder entrypoint architecture')
        entry = address(entry_rva, 6); stub = data[entry:entry + 6]
        image_base = read('<I', optional + 28)
        iat_rva, iat_size = read('<I', directories + 12 * 8), read('<I', directories + 12 * 8 + 4)
        require(imports == ['mscoree.dll'] and stub[:2] == b'\xff\x25'
                and image_base + iat_rva <= int.from_bytes(stub[2:], 'little') < image_base + iat_rva + iat_size,
                'A type forwarder has an unrelated native entrypoint')
    metadata_at, metadata_size = address(read('<I', cli + 8), read('<I', cli + 12)), read('<I', cli + 12)
    metadata = data[metadata_at:metadata_at + metadata_size]
    at = 16 + ((read('<I', 12, metadata) + 3) & ~3)
    stream_count = read('<H', at + 2, metadata); at += 4; heaps = {}
    for unused in range(stream_count):
        offset, length = read('<I', at, metadata), read('<I', at + 4, metadata)
        end = metadata.find(b'\0', at + 8, min(at + 40, len(metadata)))
        require(end >= at + 8, 'Unterminated type forwarder stream name')
        name = metadata[at + 8:end].decode('ascii'); at = (end + 4) & ~3
        require(name in {'#~', '#Strings', '#US', '#GUID', '#Blob'} and name not in heaps
                and offset + length <= len(metadata), 'Unknown or escaped type forwarder metadata stream')
        heaps[name] = metadata[offset:offset + length]
    require('#~' in heaps and set(heaps) >= {'#Strings', '#GUID', '#Blob'}, 'Type forwarder metadata format requires review')
    tables = heaps['#~']; heap_flags = read('<B', 6, tables)
    valid, counts, position = read('<Q', 8, tables), {}, 24
    for table in range(64):
        if valid & (1 << table): counts[table] = read('<I', position, tables); position += 4
    allowed = {0, 1, 2, 10, 12, 14, 32, 35, 39}
    require(all(table in allowed or count == 0 for table, count in counts.items()) and counts.get(0) == counts.get(2) == counts.get(32) == 1,
            'Type forwarder contains an executable or unreviewed metadata table')
    def index(table): return 4 if counts.get(table, 0) >= 65536 else 2
    def coded(bits, kinds): return 4 if max(counts.get(kind, 0) for kind in kinds) >= 1 << (16 - bits) else 2
    s, g, b = (4 if heap_flags & bit else 2 for bit in (1, 2, 4))
    scope, td, mr = coded(2, [0, 26, 35, 1]), coded(2, [2, 1, 27]), coded(3, [2, 1, 26, 6, 27])
    ca_tables = [6,4,1,2,8,9,10,0,14,23,20,17,26,27,32,35,38,39,40,42,44,43]
    ca, ct, sec, impl = coded(5, ca_tables), coded(3, [6, 10]), coded(2, [2, 6, 32]), coded(2, [38, 35, 39])
    sizes = {0:2+s+g*3,1:scope+s*2,2:4+s*2+td+index(4)+index(6),10:mr+s+b,
             12:ca+ct+b,14:2+sec+b,32:16+b+s*2,35:12+b*2+s*2,39:8+s*2+impl}
    offsets = {}
    for table, count in sorted(counts.items()): offsets[table] = position; position += sizes.get(table, 0) * count
    require(position <= len(tables) and not any(tables[position:]), 'Opaque trailing type forwarder table data')
    def row(table, rid):
        require(1 <= rid <= counts.get(table, 0), 'Invalid type forwarder table reference')
        return offsets[table] + (rid - 1) * sizes[table]
    def number(width, at): return read('<I' if width == 4 else '<H', at, tables)
    def text(at):
        heap = heaps['#Strings']; require(0 <= at < len(heap), 'Escaped type forwarder string index')
        end = heap.find(b'\0', at, min(at + 8192, len(heap)))
        require(end >= at, 'Oversized or unterminated type forwarder string')
        return heap[at:end].decode('utf-8')
    def blob(at):
        heap = heaps['#Blob']; require(0 <= at < len(heap), 'Escaped type forwarder blob index')
        first = heap[at]
        if first < 0x80: length, start = first, at + 1
        elif first < 0xc0:
            length, start = ((first & 0x3f) << 8) | read('<B', at + 1, heap), at + 2
            require(length >= 0x80, 'Noncanonical type forwarder blob length')
        else:
            require(first < 0xe0 and at + 4 <= len(heap), 'Invalid type forwarder blob length')
            length, start = ((first & 0x1f) << 24) | int.from_bytes(heap[at + 1:at + 4], 'big'), at + 4
            require(length >= 0x4000, 'Noncanonical type forwarder blob length')
        require(start + length <= len(heap), 'Truncated type forwarder blob')
        return heap[start:start + length].hex()
    def guid(at):
        if not at: return None
        require(at * 16 <= len(heaps['#GUID']), 'Invalid type forwarder GUID index')
        return str(uuid.UUID(bytes_le=heaps['#GUID'][(at - 1)*16:at*16]))
    def reference(encoded, bits, kinds):
        tag, rid = encoded & ((1 << bits) - 1), encoded >> bits
        require(tag < len(kinds), 'Invalid type forwarder coded-index tag')
        table = kinds[tag]; row(table, rid)
        return dict(table=table, row=rid, token=f'0x{table:02x}{rid:06x}')
    declaration = {}
    user_strings, user = [], heaps.get('#US', b'')
    require(not user or user[0] == 0, 'Invalid type forwarder user-string heap prefix')
    cursor = 1
    while cursor < len(user) and any(user[cursor:]):
        start = cursor; first = user[cursor]; cursor += 1
        if first < 0x80: length = first
        elif first < 0xc0:
            length = ((first & 0x3f) << 8) | read('<B', cursor, user); cursor += 1
            require(length >= 0x80, 'Noncanonical user-string length')
        else:
            require(first < 0xe0 and cursor + 3 <= len(user), 'Invalid user-string length')
            length = ((first & 0x1f) << 24) | int.from_bytes(user[cursor:cursor+3], 'big'); cursor += 3
            require(length >= 0x4000, 'Noncanonical user-string length')
        require(length > 0 and length % 2 == 1 and cursor + length <= len(user) and user[cursor+length-1] in (0,1),
                'Opaque or malformed type forwarder user-string data')
        raw = user[cursor:cursor+length]
        user_strings.append(dict(offset=start,value=raw[:-1].decode('utf-16-le'),specialCharacters=raw[-1],raw=raw.hex()))
        cursor += length
    declaration['userStrings'] = user_strings
    at = row(0, 1)
    declaration['module'] = dict(generation=read('<H', at, tables), name=text(number(s, at+2)),
        mvid=guid(number(g, at+2+s)), encId=guid(number(g, at+2+s+g)), encBaseId=guid(number(g, at+2+s+g*2)))
    at = row(2, 1)
    require(read('<I', at, tables) == 0 and text(number(s, at+4)) == '<Module>' and text(number(s, at+4+s)) == ''
            and number(td, at+4+s*2) == 0 and number(index(4), at+4+s*2+td) == number(index(6), at+4+s*2+td+index(4)) == 1,
            'Type forwarder defines a nonempty module type')
    at = row(32, 1)
    declaration['assembly'] = dict(hashAlgorithm=read('<I', at, tables), version='.'.join(str(read('<H', at+4+i*2, tables))for i in range(4)),
        flags=read('<I', at+12, tables), publicKey=blob(number(b, at+16)), name=text(number(s, at+16+b)), culture=text(number(s, at+16+b+s)))
    refs=[]
    for rid in range(1,counts.get(35,0)+1):
        at=row(35,rid)
        refs.append(dict(row=rid,version='.'.join(str(read('<H',at+i*2,tables))for i in range(4)), flags=read('<I',at+8,tables),
            publicKeyOrToken=blob(number(b,at+12)), name=text(number(s,at+12+b)),culture=text(number(s,at+12+b+s)),hashValue=blob(number(b,at+12+b+s*2))))
    declaration['assemblyReferences']=refs
    types=[]
    for rid in range(1,counts.get(1,0)+1):
        at=row(1,rid); resolution=reference(number(scope,at),2,[0,26,35,1])
        require(resolution['table']in(35,1),'Type forwarder type reference has no external assembly scope')
        types.append(dict(row=rid,scope=resolution,name=text(number(s,at+scope)),namespace=text(number(s,at+scope+s))))
    def resolve_type(rid,seen):
        require(rid not in seen and len(seen)<128,'Cyclic or oversized type-forwarder attribute type scope')
        item=types[rid-1];parent=item['scope']
        if parent['table']==35:return dict(assemblyReference=parent['row'],name=(item['namespace']+'.'if item['namespace']else'')+item['name'])
        outer=resolve_type(parent['row'],seen|{rid});require(not item['namespace'],'A nested attribute type has a separate namespace')
        return dict(assemblyReference=outer['assemblyReference'],name=outer['name']+'/'+item['name'])
    for item in types:item['resolved']=resolve_type(item['row'],set())
    declaration['typeReferences']=types
    members=[]
    for rid in range(1,counts.get(10,0)+1):
        at=row(10,rid);parent=reference(number(mr,at),3,[2,1,26,6,27])
        name=text(number(s,at+mr));require(parent['table']==1 and name=='.ctor','Unreviewed non-attribute type forwarder member reference')
        members.append(dict(row=rid,parent=parent,name=name,signature=blob(number(b,at+mr+s))))
    declaration['memberReferences']=members
    custom=[]
    for rid in range(1,counts.get(12,0)+1):
        at=row(12,rid);parent=reference(number(ca,at),5,ca_tables);encoded=number(ct,at+ca)
        require(encoded&7==3,'Type forwarder custom attribute has an executable constructor')
        constructor=reference((encoded>>3)<<1|1,1,[6,10])
        custom.append(dict(row=rid,parent=parent,constructor=constructor,value=blob(number(b,at+ca+ct))))
    declaration['customAttributes']=custom
    permissions=[]
    for rid in range(1,counts.get(14,0)+1):
        at=row(14,rid);parent=reference(number(sec,at+2),2,[2,6,32])
        require(parent['table']==32,'Unreviewed type forwarder declarative security parent')
        permissions.append(dict(row=rid,action=read('<H',at,tables),parent=parent,value=blob(number(b,at+2+sec))))
    declaration['declarativeSecurity']=permissions
    exports=[]
    for rid in range(1,counts.get(39,0)+1):
        at=row(39,rid);flags=read('<I',at,tables);definition=read('<I',at+4,tables)
        implementation=reference(number(impl,at+8+s*2),2,[38,35,39])
        require(flags&~0x00200007==0 and definition==0 and implementation['table']in(35,39)
                and (implementation['table']==39 or flags&0x00200000),'A type forwarder is not a pure forwarding declaration')
        exports.append(dict(row=rid,flags=flags,typeDefId=definition,name=text(number(s,at+8)),namespace=text(number(s,at+8+s)),implementation=implementation))
    def resolve(rid,seen):
        require(rid not in seen and len(seen)<128,'Cyclic or oversized nested type forwarder')
        item=exports[rid-1];parent=item['implementation']
        if parent['table']==35:return dict(assemblyReference=parent['row'],name=(item['namespace']+'.'if item['namespace']else'')+item['name'])
        outer=resolve(parent['row'],seen|{rid});require(not item['namespace'],'Nested type forwarder has a separate namespace')
        return dict(assemblyReference=outer['assemblyReference'],name=outer['name']+'/'+item['name'])
    for item in exports:item['resolved']=resolve(item['row'],set())
    declaration['exportedTypes']=exports
    declaration['tableRows']={str(t):[tables[offsets[t]+i*sizes[t]:offsets[t]+(i+1)*sizes[t]].hex()for i in range(n)]for t,n in counts.items()if n}
    declaration['rawHeaps']={name:body.hex()for name,body in heaps.items()}
    declaration['metadataBytes']=metadata.hex()
    declaration['metadataSha256']=hashlib.sha256(metadata).hexdigest()
    declaration['identity']=identity
    declaration['nativeImports']=imports
    declaration['nativeBootstrapMembers']=imported_members
    declaration['readableIL']=readable_il(declaration)
    return declaration


def readable_il(declaration):
    """Emit inspectable IL declaration syntax; JSON retains complete raw rows."""
    quote=lambda value:"'"+value.replace('\\','\\\\').replace("'","\\'")+"'"
    lines=['// Derived literal type-forwarding metadata; no original Git or compilation claim.']
    for ref in declaration['assemblyReferences']:
        lines += ['.assembly extern '+quote(ref['name'])+' {', '  .ver '+ref['version'].replace('.',':'),
                  '  // flags='+str(ref['flags'])+' publicKeyOrToken='+ref['publicKeyOrToken']+' culture='+json.dumps(ref['culture'])+' hash='+ref['hashValue'], '}']
    assembly=declaration['assembly'];lines+=['.assembly '+quote(assembly['name'])+' {','  .ver '+assembly['version'].replace('.',':'),
       '  // flags='+str(assembly['flags'])+' hashAlgorithm='+str(assembly['hashAlgorithm'])+' publicKey='+assembly['publicKey']+' culture='+json.dumps(assembly['culture']),'}',
       '.module '+quote(declaration['module']['name']),'// module identity '+json.dumps(declaration['module'],sort_keys=True)]
    for item in declaration['typeReferences']:
        resolved=item['resolved'];ref=declaration['assemblyReferences'][resolved['assemblyReference']-1]
        lines.append('// TypeRef 0x01'+f"{item['row']:06x}"+' = ['+ref['name']+']'+resolved['name'])
    for item in declaration['memberReferences']:
        parent=declaration['typeReferences'][item['parent']['row']-1]['resolved']
        ref=declaration['assemblyReferences'][parent['assemblyReference']-1]
        lines.append('// MemberRef 0x0a'+f"{item['row']:06x}"+' = ['+ref['name']+']'+parent['name']+'::'+item['name']+' signature=('+item['signature']+')')
    for item in declaration['userStrings']:
        lines.append('// UserString #'+str(item['offset'])+' = '+json.dumps(item['value'],ensure_ascii=True)+' raw=('+item['raw']+')')
    for item in declaration['customAttributes']:
        lines.append('// .custom parent='+item['parent']['token']+' constructor='+item['constructor']['token']+' = ('+' '.join(item['value'][i:i+2]for i in range(0,len(item['value']),2))+')')
    for item in declaration['declarativeSecurity']:
        lines.append('// .permissionset action='+str(item['action'])+' parent='+item['parent']['token']+' = ('+' '.join(item['value'][i:i+2]for i in range(0,len(item['value']),2))+')')
    for item in declaration['exportedTypes']:
        resolved=item['resolved'];ref=declaration['assemblyReferences'][resolved['assemblyReference']-1]
        lines+=['.class extern forwarder '+quote(resolved['name'])+' { .assembly extern '+quote(ref['name'])+' }',
                '// ExportedType row='+str(item['row'])+' flags='+str(item['flags'])+' implementation='+item['implementation']['token']]
    return '\n'.join(lines)+'\n'


def policy():
    document=json.loads(Path(__file__).with_name('musl-legacy-facade-policy.json').read_bytes())
    require(document.get('schemaVersion')==1 and document.get('kind')=='literal-type-forwarder-metadata-policy'
        and document.get('sdkVersion')=='7.0.120' and len(document.get('layout',[]))==168 and document.get('uniquePEs')==87
        and len({row['path']for row in document['layout']})==168
        and len({row['fingerprint']['sha256']for row in document['layout']})==87
        and document['package']['fingerprint']['sha256']=='6cf5b9719e6f7e2a078fe28db1f6d28fd7e2e48ecfa53c6d6d1c17b0cf3300ad'
        and all(document.get(field)is False for field in('localBuildClaimed','originalGitSourceClaimed','byteIdenticalCompilationClaimed')),
        'The exact closed 168-layout/87-product literal metadata policy is required')
    return document


def package_bodies(package):
    """Recompute every readable declaration from the immutable primary input."""
    package=Path(package);document=policy()
    require(package.is_file()and not package.is_symlink()and package.stat().st_size==document['package']['fingerprint']['bytes'],
            'An ordinary bounded original type-forwarder package is required')
    raw=package.read_bytes();require(fingerprint(raw)==document['package']['fingerprint'],'Unreviewed type-forwarder package bytes')
    bodies={'packages/'+document['package']['fingerprint']['sha256']+'.nupkg':raw};products={}
    with zipfile.ZipFile(package)as archive:
        entries=archive.infolist();require(len(entries)<1000 and len({entry.filename for entry in entries})==len(entries),
            'Duplicate or oversized original facade package entries')
        nuspecs=[entry.filename for entry in entries if entry.filename.endswith('.nuspec')]
        require(len(nuspecs)==1,'One original type-forwarder package nuspec is required')
        nuspec=archive.read(nuspecs[0]);require(len(nuspec)<1024**2 and b'<!DOCTYPE'not in nuspec.upper()and b'<!ENTITY'not in nuspec.upper(),
            'Bounded original type-forwarder nuspec XML required')
        metadata=ET.fromstring(nuspec).find('{*}metadata');license_node=metadata.find('{*}license')
        require(metadata.findtext('{*}id')==document['package']['id'] and metadata.findtext('{*}version')==document['package']['version']
            and license_node is not None and license_node.get('type')=='expression' and license_node.text=='MIT',
            'The original immutable type-forwarder package identity and MIT license are required')
        bodies['original.nuspec']=nuspec
        for row in document['layout']:
            info=archive.getinfo(row['packageMember'])
            require(not info.is_dir() and info.file_size==row['fingerprint']['bytes'] and info.file_size<=4*1024**2
                and info.external_attr>>16&0o170000!=0o120000,'An ordinary exact original facade package member is required')
            raw=archive.read(info);require(fingerprint(raw)==row['fingerprint'],'Literal type-forwarder product bytes differ')
            sha=row['fingerprint']['sha256'];products[row['path']]=row['fingerprint']
            if 'products/'+sha+'.dll'in bodies:continue
            declaration=inspect(raw)
            bodies['products/'+sha+'.dll']=raw
            bodies['metadata/'+sha+'.bin']=bytes.fromhex(declaration['metadataBytes'])
            bodies['readable/'+sha+'.json']=(json.dumps(declaration,indent=2,ensure_ascii=False)+'\n').encode()
            bodies['declarations/'+sha+'.il']=declaration['readableIL'].encode()
    require(len(products)==168 and len([name for name in bodies if name.startswith('products/')])==87,
            'Every reviewed literal type-forwarder product must remain present')
    bodies['policy.json']=(json.dumps(document,indent=2,ensure_ascii=False)+'\n').encode()
    bodies['origin.json']=(json.dumps(dict(schemaVersion=1,kind=KIND,basis='full-derived-facade-IL',
        primaryPackage=document['package']['fingerprint'],products=87,layoutPaths=168,
        sourceCommit=None,originalGitSourceClaimed=False,localBuildClaimed=False,byteIdenticalCompilationClaimed=False),indent=2)+'\n').encode()
    return bodies,products


def prepare(package,sdk_source,destination):
    """Retain literal inputs, complete metadata/readables and the MIT text."""
    import subprocess
    sdk_source=Path(sdk_source);destination=Path(destination);document=policy()
    license=(sdk_source/'LICENSE.TXT').read_bytes();expected=document['licenseSource']
    require(fingerprint(license)=={key:expected[key]for key in FP},'Original complete MIT license bytes differ')
    original=subprocess.check_output(['git','-c','safe.directory='+str(sdk_source),'-C',str(sdk_source),
        'show',expected['sourceCommit']+':LICENSE.TXT'])
    require(license==original,'Complete MIT license must be the original pinned SDK Git text')
    bodies,products=package_bodies(package);bodies['licenses/MIT.txt']=license
    require(not destination.exists(),'A fresh literal facade source directory is required');destination.mkdir(parents=True)
    for name,body in bodies.items():
        target=destination/name;target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb')as stream:stream.write(body)
    return dict(name=ROOT_NAME,kind='tree',path=str(destination),role=ROLE)


def validate(release,manifest,package):
    """Recompute all data, then verify the complete archived literal source."""
    release=Path(release);document=policy();bodies,products=package_bodies(package)
    roots=[root for root in manifest['roots']if root['name']==ROOT_NAME]
    require(len(roots)==1 and roots[0]['kind']=='tree'and roots[0].get('role')==ROLE and roots[0].get('commit')is None,
        'Literal type-forwarding source must retain a distinct derived-data root without Git provenance')
    license=document['licenseSource'];sdk_roots=[root for root in manifest['roots']if root['name']=='sdk']
    require(len(sdk_roots)==1 and sdk_roots[0]['kind']in('git','git-export')and sdk_roots[0].get('commit')==license['sourceCommit'],
        'The complete original SDK Git source for its MIT license must remain retained')
    expected={ROOT_NAME+'/'+name:fingerprint(raw)for name,raw in bodies.items()}
    license_fp={key:license[key]for key in FP};expected[ROOT_NAME+'/licenses/MIT.txt']=license_fp
    expected[license['path']]=license_fp;index={}
    with(release/'sources'/manifest['index']['path']).open()as stream:
        for line in stream:
            row=json.loads(line)
            if row['path']in expected or row['path'].startswith(ROOT_NAME+'/'):
                require(row['path']not in index,'Duplicate literal facade source index entry');index[row['path']]=row
    require(index.keys()==expected.keys() and all(all(index[name].get(key)==value[key]for key in FP)for name,value in expected.items()),
        'Every original input, metadata table, declaration and complete MIT text must be indexed unchanged')
    require(index[license['path']].get('baseline',{}).get('blob')==license['gitBlob'],
        'Complete retained MIT text differs from the original SDK Git blob')
    found=set()
    with open_source_archive(release,manifest)as archive:
        for entry in archive:
            if entry.name not in expected:continue
            require(entry.isfile()and entry.name not in found and entry.size==expected[entry.name]['bytes']and entry.size<=16*1024**2,
                'Ordinary bounded literal facade source member required')
            raw=archive.extractfile(entry).read();require(fingerprint(raw)==expected[entry.name],'Archived literal facade source bytes differ')
            found.add(entry.name)
    require(found==expected.keys(),'Archived literal type-forwarding source is incomplete')
    return dict(kind=KIND,basis='full-derived-facade-IL',sourceRoot=ROOT_NAME,sourceCommit=None,products=products,
        allowedLayoutPaths=sorted(products),originalGitSourceClaimed=False,localBuildClaimed=False,byteIdenticalCompilationClaimed=False)
