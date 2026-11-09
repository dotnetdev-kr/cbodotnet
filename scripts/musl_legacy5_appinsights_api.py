"""Bounded SDK5 AppInsights public API comparison; input assemblies are never loaded."""
import hashlib
import json
import struct

def require(value, message):
    if not value: raise ValueError(message)


def table_view(data):
    """Read bounded ECMA-335 tables for implementation/source correspondence."""
    require(isinstance(data, bytes) and 128 <= len(data) <= 128 * 1024**2 and data[:2] == b'MZ',
            'A bounded ordinary managed PE is required')

    def read(fmt, offset, body=data):
        require(0 <= offset <= len(body) - struct.calcsize(fmt), 'Truncated managed metadata')
        return struct.unpack_from(fmt, body, offset)[0]

    pe = read('<I', 0x3c)
    require(data[pe:pe + 4] == b'PE\0\0', 'Invalid managed PE signature')
    count, optional_size = read('<H', pe + 6), read('<H', pe + 20)
    require(1 <= count <= 96, 'Invalid managed PE section count')
    optional = pe + 24
    magic = read('<H', optional)
    require(magic in (0x10b, 0x20b), 'Unsupported managed PE header')
    directory_offset = 96 if magic == 0x10b else 112
    require(optional_size >= directory_offset + 15 * 8 and optional + optional_size <= len(data),
            'Managed PE data directories are truncated')
    require(read('<I', optional + directory_offset - 4) >= 15, 'Managed PE has no CLR directory')
    sections = []
    for index in range(count):
        at = optional + optional_size + index * 40
        sections.append((read('<I', at + 12), read('<I', at + 20), read('<I', at + 16)))

    def address(rva, size):
        require(size > 0, 'Empty metadata address')
        matches = [offset + rva - start for start, offset, length in sections
                   if start <= rva and rva + size <= start + length]
        require(len(matches) == 1 and 0 <= matches[0] <= len(data) - size, 'Managed RVA escapes its section')
        return matches[0]

    cli = address(read('<I', optional + directory_offset + 14 * 8), 72)
    metadata_size = read('<I', cli + 12)
    require(20 <= metadata_size <= 64 * 1024**2, 'Invalid CLR metadata size')
    metadata_at = address(read('<I', cli + 8), metadata_size)
    metadata = data[metadata_at:metadata_at + metadata_size]
    require(metadata[:4] == b'BSJB', 'Invalid CLR metadata signature')
    version_size = read('<I', 12, metadata)
    require(1 <= version_size <= 256, 'Invalid CLR version string bound')
    cursor = 16 + ((version_size + 3) & ~3)
    stream_count = read('<H', cursor + 2, metadata)
    require(1 <= stream_count <= 16, 'Invalid CLR stream count')
    cursor += 4
    heaps, ranges = {}, []
    for unused in range(stream_count):
        relative, size = read('<I', cursor, metadata), read('<I', cursor + 4, metadata)
        end = metadata.find(b'\0', cursor + 8, min(cursor + 40, len(metadata)))
        require(end >= 0, 'Unterminated CLR stream name')
        name = metadata[cursor + 8:end].decode('ascii')
        require(name not in heaps and relative + size <= len(metadata), 'Duplicate or escaped CLR stream')
        heaps[name] = metadata[relative:relative + size]
        ranges.append((relative, relative + size))
        cursor = (end + 4) & ~3
    require(all(start >= cursor for start, end in ranges)
            and all(a[1] <= b[0] for a, b in zip(sorted(ranges), sorted(ranges)[1:])),
            'Overlapping CLR metadata streams')
    require({'#Strings', '#Blob'} <= heaps.keys() and len({'#~', '#-'} & heaps.keys()) == 1,
            'CLR metadata heaps are absent or ambiguous')
    tables = heaps.get('#~', heaps.get('#-'))
    flags = read('<B', 6, tables)
    require(flags & ~7 == 0, 'Unsupported CLR heap flags')
    valid, counts, position = read('<Q', 8, tables), {}, 24
    for table in range(64):
        if valid & (1 << table):
            counts[table] = read('<I', position, tables); position += 4
    require(all(table <= 44 and value <= 2000000 for table, value in counts.items())
            and sum(counts.values()) <= 5000000 and counts.get(32) == 1,
            'Unsupported or oversized assembly table set')
    require(all(counts.get(table, 0) == 0 for table in (3, 5, 7, 19, 22))
            and counts.get(35, 0) <= 4096, 'Unsupported pointer tables or oversized assembly references')

    def index(table):
        return 4 if counts.get(table, 0) >= 65536 else 2

    def coded(bits, kinds):
        return 4 if max(counts.get(kind, 0) for kind in kinds) >= 1 << (16 - bits) else 2

    s, g, b = (4 if flags & bit else 2 for bit in (1, 2, 4))
    td = coded(2, [2, 1, 27]); mr = coded(3, [2, 1, 26, 6, 27])
    ca = coded(5, [6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43])
    ct = coded(3, [6, 10]); impl = coded(2, [38, 35, 39]); method = coded(1, [6, 10])
    sizes = {
        0: 2 + s + g * 3, 1: coded(2, [0, 26, 35, 1]) + s * 2,
        2: 4 + s * 2 + td + index(4) + index(6), 3: index(4), 4: 2 + s + b,
        5: index(6), 6: 8 + s + b + index(8), 7: index(8), 8: 4 + s,
        9: index(2) + td, 10: mr + s + b, 11: 2 + coded(2, [4, 8, 23]) + b,
        12: ca + ct + b, 13: coded(1, [4, 8]) + b, 14: 2 + coded(2, [2, 6, 32]) + b,
        15: 6 + index(2), 16: 4 + index(4), 17: b, 18: index(2) + index(20),
        19: index(20), 20: 2 + s + td, 21: index(2) + index(23), 22: index(23),
        23: 2 + s + b, 24: 2 + index(6) + coded(1, [20, 23]), 25: index(2) + method * 2,
        26: s, 27: b, 28: 2 + coded(1, [4, 6]) + s + index(26), 29: 4 + index(4),
        30: 8, 31: 4, 32: 16 + b + s * 2, 33: 4, 34: 12,
        35: 12 + b * 2 + s * 2, 36: 4 + index(35), 37: 12 + index(35),
        38: 4 + s + b, 39: 8 + s * 2 + impl, 40: 8 + s + impl,
        41: index(2) * 2, 42: 4 + coded(1, [2, 6]) + s, 43: method + b, 44: index(42) + td}
    offsets = {}
    for table, count in sorted(counts.items()):
        offsets[table] = position; position += sizes[table] * count
    require(position <= len(tables), 'Truncated CLR metadata tables')

    def row(table, rid):
        require(1 <= rid <= counts.get(table, 0), 'Invalid CLR table row reference')
        return offsets[table] + (rid - 1) * sizes[table]

    def number(width, at):
        return read('<I' if width == 4 else '<H', at, tables)

    def text(at):
        heap = heaps['#Strings']
        require(0 <= at < len(heap), 'Invalid CLR string heap index')
        end = heap.find(b'\0', at, min(at + 4096, len(heap)))
        require(end >= 0, 'Unterminated or oversized CLR string')
        return heap[at:end].decode('utf-8')

    def compressed(body, at):
        first = read('<B', at, body)
        if first < 0x80: return first, at + 1
        if first < 0xc0:
            value = ((first & 0x3f) << 8) | read('<B', at + 1, body)
            require(value >= 0x80, 'Noncanonical CLR compressed integer')
            return value, at + 2
        require(first < 0xe0 and at + 4 <= len(body), 'Invalid CLR compressed integer')
        value = ((first & 0x1f) << 24) | int.from_bytes(body[at + 1:at + 4], 'big')
        require(value >= 0x4000, 'Noncanonical CLR compressed integer')
        return value, at + 4

    def blob(at):
        heap = heaps['#Blob']; size, start = compressed(heap, at)
        require(size <= 1024 * 1024 and start + size <= len(heap), 'Truncated or oversized CLR attribute blob')
        return heap[start:start + size]

    require(read('<I', cli + 16) & 1 and read('<I', cli + 20) == read('<I', cli + 68) == 0, 'An IL-only implementation without native code or an entrypoint is required')
    return dict(row=row, number=number, read=read, counts=counts, tables=tables, address=address,
                heaps=heaps, text=text, cli=cli, s=s, g=g, b=b, impl=impl, blob=blob, coded=coded)


def assembly_identity(data):
    v=table_view(data);at=v['row'](32,1);key=v['blob'](v['number'](v['b'],at+16))
    return dict(assemblyName=v['text'](v['number'](v['s'],at+16+v['b'])),assemblyVersion='.'.join(str(v['read']('<H',at+4+i*2,v['tables']))for i in range(4)),
        culture=v['text'](v['number'](v['s'],at+16+v['b']+v['s'])),publicKeyToken=hashlib.sha1(key).digest()[-8:][::-1].hex()if key else'')


def public_api(data):
    """Resolve public/protected signatures and their complete metadata shape."""
    v=table_view(data);row,num,read,text,blob=v['row'],v['number'],v['read'],v['text'],v['blob'];counts=v['counts'];tables=v['tables'];s,b,g=v['s'],v['b'],v['g'];coded=v['coded']
    idx=lambda t:4 if counts.get(t,0)>=65536 else 2
    references={}
    for rid in range(1,counts.get(35,0)+1):
        at=row(35,rid);flags=read('<I',at+8,tables);key=blob(num(b,at+12));references[rid]=dict(name=text(num(s,at+12+b)),version='.'.join(str(read('<H',at+i*2,tables))for i in range(4)),culture=text(num(s,at+12+b+s)),publicKeyToken=hashlib.sha1(key).digest()[-8:][::-1].hex()if flags&1 else key.hex(),flags=flags)
    at=row(32,1);key=blob(num(b,at+16));identity=dict(name=text(num(s,at+16+b)),version='.'.join(str(read('<H',at+4+i*2,tables))for i in range(4)),culture=text(num(s,at+16+b+s)),publicKeyToken=hashlib.sha1(key).digest()[-8:][::-1].hex()if key else'',flags=read('<I',at+12,tables),hashAlgorithm=read('<I',at,tables))
    require(len({r['name']for r in references.values()})==len(references)and identity['name']not in{r['name']for r in references.values()},'Unique external API assembly-reference identities required')
    nested={num(idx(2),row(41,r)):num(idx(2),row(41,r)+idx(2))for r in range(1,counts.get(41,0)+1)}
    td=coded(2,[2,1,27]);resolution=coded(2,[0,26,35,1]);types={};type_stack=set()
    def type_name(table,rid):
        require(1<=rid<=counts.get(table,0),'Invalid API type reference')
        key=(table,rid)
        if key in types:return types[key]
        require(key not in type_stack and len(type_stack)<64,'Recursive or oversized API type resolution');type_stack.add(key)
        if table==27:result=signature(blob(num(b,row(27,rid))),'type')
        elif table==2:
            at=row(2,rid);name,namespace=text(num(s,at+4)),text(num(s,at+4+s));parent=nested.get(rid)
            result=['type',identity['name'],(type_name(2,parent)[2]+'+'+name)if parent else(namespace+'.'if namespace else'')+name]
        else:
            at=row(1,rid);scope=num(resolution,at);tag,parent=scope&3,scope>>2;name,namespace=text(num(s,at+resolution)),text(num(s,at+resolution+s))
            if tag==3:outer=type_name(1,parent);result=['type',outer[1],outer[2]+'+'+name]
            elif tag==2:
                require(parent in references,'Invalid API assembly scope');result=['type',references[parent]['name'],(namespace+'.'if namespace else'')+name]
            elif tag==0:result=['type',identity['name'],(namespace+'.'if namespace else'')+name]
            else:raise ValueError('Unsupported API module-reference type scope')
        type_stack.remove(key);types[key]=result;return result
    def type_coded(value):
        if value==0:return None
        tag,rid=value&3,value>>2;require(tag in(0,1,2),'Invalid API TypeDefOrRef tag');return type_name((2,1,27)[tag],rid)
    def signature(raw,kind='method'):
        require(isinstance(raw,bytes)and len(raw)<=65536,'Bounded API signature required');position=0;depth=0
        def byte():
            nonlocal position
            require(position<len(raw),'Truncated API signature');value=raw[position];position+=1;return value
        def integer():
            first=byte()
            if first<128:return first
            if first<192:return((first&63)<<8)|byte()
            require(first<224,'Invalid API compressed integer');return((first&31)<<24)|(byte()<<16)|(byte()<<8)|byte()
        def element():
            nonlocal depth
            depth+=1;require(depth<=64,'Oversized API signature nesting');code=byte()
            if code in(1,2,3,4,5,6,7,8,9,10,11,12,13,14,22,24,25,28):result=['primitive',code]
            elif code in(17,18):result=['class-kind',code,type_coded(integer())]
            elif code in(15,16,29,69):result=['element-kind',code,element()]
            elif code in(19,30):result=['generic-parameter',code,integer()]
            elif code in(31,32):result=['modifier',code,type_coded(integer()),element()]
            elif code==21:
                classkind=byte();require(classkind in(17,18),'Invalid API generic instance');target=type_coded(integer());argc=integer();require(argc<=256,'Oversized API generic argument list');result=['generic',classkind,target,[element()for _ in range(argc)]]
            elif code==20:
                target=element();rank=integer();size_count=integer();require(rank<=64 and size_count<=rank,'Invalid API array shape');sizes=[integer()for _ in range(size_count)];bounds_count=integer();require(bounds_count<=rank,'Invalid API array bounds');result=['array',target,rank,sizes,[integer()for _ in range(bounds_count)]]
            elif code==27:result=['function-pointer',method()]
            else:raise ValueError('Unsupported API signature element '+hex(code))
            depth-=1;return result
        def method():
            call=byte();generic=integer()if call&16 else 0;count=integer();require(count<=4096,'Oversized API parameter list');returns=element();parameters=[]
            while len([p for p in parameters if p!=['sentinel']])<count:
                if position<len(raw)and raw[position]==65:byte();parameters.append(['sentinel'])
                else:parameters.append(element())
            return[call,generic,returns,parameters]
        if kind=='type':result=element()
        elif kind=='field':require(byte()==6,'Invalid API field signature');result=element()
        else:result=method()
        require(position==len(raw),'Trailing API signature data');return result
    require(all(not counts.get(t,0)for t in(13,14,28)), 'AppInsights API with no marshal/security/PInvoke metadata required')
    type_flags={r:read('<I',row(2,r),tables)for r in range(1,counts.get(2,0)+1)};visible_cache={};visible_stack=set()
    def visible_type(rid):
        if rid not in visible_cache:
            require(rid not in visible_stack and len(visible_stack)<64,'Recursive API nested-type visibility');visible_stack.add(rid)
            flag=type_flags[rid]&7;visible_cache[rid]=(flag in(2,4,7)and visible_type(nested[rid]))if rid in nested else flag==1
            visible_stack.remove(rid)
        return visible_cache[rid]
    methods={};fields={};owners={}
    for rid in range(1,counts.get(2,0)+1):
        at=row(2,rid)+4+s*2+td;field_start=num(idx(4),at);method_start=num(idx(6),at+idx(4));next_at=row(2,rid+1)+4+s*2+td if rid<counts[2]else None;field_end=num(idx(4),next_at)if next_at is not None else counts.get(4,0)+1;method_end=num(idx(6),next_at+idx(4))if next_at is not None else counts.get(6,0)+1
        for field in range(field_start,field_end):owners[(4,field)]=rid
        for method_rid in range(method_start,method_end):owners[(6,method_rid)]=rid
    for rid in range(1,counts.get(6,0)+1):
        at=row(6,rid);flags=read('<H',at+6,tables);methods[rid]=dict(name=text(num(s,at+8)),flags=flags,implFlags=read('<H',at+4,tables),signature=signature(blob(num(b,at+8+s))),owner=owners[(6,rid)])
    for rid in range(1,counts.get(4,0)+1):
        at=row(4,rid);fields[rid]=dict(name=text(num(s,at+2)),flags=read('<H',at,tables),signature=signature(blob(num(b,at+2+s)),'field'),owner=owners[(4,rid)])
    ca_kinds=[6,4,1,2,8,9,10,0,14,23,20,17,26,27,32,35,38,39,40,42,44,43];ca_width=coded(5,ca_kinds);ctor_width=coded(3,[6,10]);mr=coded(3,[2,1,26,6,27]);attributes={}
    def constructor(encoded):
        tag,rid=encoded&7,encoded>>3
        if tag==2:return[type_name(2,methods[rid]['owner']),methods[rid]['name'],methods[rid]['signature']]
        require(tag==3,'Invalid API custom-attribute constructor');at=row(10,rid);parent=num(mr,at);kind,target=parent&7,parent>>3;require(kind in(0,1,4),'Unsupported API attribute parent');typ=type_name((2,1,0,0,27)[kind],target);return[typ,text(num(s,at+mr)),signature(blob(num(b,at+mr+s)))]
    for rid in range(1,counts.get(12,0)+1):
        at=row(12,rid);parent=num(ca_width,at);tag,target=parent&31,parent>>5;require(tag<len(ca_kinds),'Invalid API custom-attribute parent');key=(ca_kinds[tag],target);attributes.setdefault(key,[]).append([constructor(num(ctor_width,at+ca_width)),blob(num(b,at+ca_width+ctor_width)).hex()])
    attrs=lambda table,rid:sorted(attributes.get((table,rid),[]),key=lambda x:json.dumps(x,sort_keys=True))
    constants={};width=coded(2,[4,8,23])
    for rid in range(1,counts.get(11,0)+1):
        at=row(11,rid);parent=num(width,at+2);tag,target=parent&3,parent>>2;require(tag<3,'Invalid API constant parent');constants[((4,8,23)[tag],target)]=[read('<H',at,tables),blob(num(b,at+2+width)).hex()]
    generic={};constraint_map={}
    for rid in range(1,counts.get(44,0)+1):
        at=row(44,rid);constraint_map.setdefault(num(idx(42),at),[]).append(type_coded(num(td,at+idx(42))))
    for rid in range(1,counts.get(42,0)+1):
        at=row(42,rid);width=coded(1,[2,6]);parent=num(width,at+4);key=((6 if parent&1 else 2),parent>>1);generic.setdefault(key,[]).append(dict(number=read('<H',at,tables),flags=read('<H',at+2,tables),name=text(num(s,at+4+width)),constraints=sorted(constraint_map.get(rid,[]),key=str),attributes=attrs(42,rid)))
    interfaces={}
    for rid in range(1,counts.get(9,0)+1):
        at=row(9,rid);interfaces.setdefault(num(idx(2),at),[]).append([type_coded(num(td,at+idx(2))),attrs(9,rid)])
    semantics={}
    for rid in range(1,counts.get(24,0)+1):
        at=row(24,rid);width=coded(1,[20,23]);parent=num(width,at+2+idx(6));key=(23 if parent&1 else 20,parent>>1);semantics.setdefault(key,[]).append((read('<H',at,tables),num(idx(6),at+2)))
    def method_record(rid):
        m=methods[rid];result={k:value for k,value in m.items()if k!='owner'};result.update(attributes=attrs(6,rid),genericParameters=sorted(generic.get((6,rid),[]),key=lambda x:x['number']),parameters=[])
        start=num(idx(8),row(6,rid)+8+s+b);end=num(idx(8),row(6,rid+1)+8+s+b)if rid<counts.get(6,0)else counts.get(8,0)+1
        for parameter in range(start,end):
            at=row(8,parameter);result['parameters'].append(dict(flags=read('<H',at,tables),sequence=read('<H',at+2,tables),name=text(num(s,at+4)),constant=constants.get((8,parameter)),attributes=attrs(8,parameter)))
        return result
    layouts={}
    for rid in range(1,counts.get(15,0)+1):
        at=row(15,rid);layouts[num(idx(2),at+6)]=[read('<H',at,tables),read('<I',at+2,tables)]
    field_offsets={num(idx(4),row(16,r)+4):read('<I',row(16,r),tables)for r in range(1,counts.get(16,0)+1)}
    properties={};events={}
    for map_table,item_table,target in [(21,23,properties),(18,20,events)]:
        for rid in range(1,counts.get(map_table,0)+1):
            at=row(map_table,rid);owner=num(idx(2),at);start=num(idx(item_table),at+idx(2));end=num(idx(item_table),row(map_table,rid+1)+idx(2))if rid<counts[map_table]else counts.get(item_table,0)+1
            for item in range(start,end):target[item]=owner
    exposed=lambda m:(m['flags']&7)in(4,5,6)
    output=[]
    for rid in range(1,counts.get(2,0)+1):
        if not visible_type(rid):continue
        at=row(2,rid);result=dict(type=type_name(2,rid),flags=type_flags[rid],base=type_coded(num(td,at+4+s*2)),interfaces=sorted(interfaces.get(rid,[]),key=str),attributes=attrs(2,rid),layout=layouts.get(rid),genericParameters=sorted(generic.get((2,rid),[]),key=lambda x:x['number']),methods=[],fields=[],properties=[],events=[])
        result['methods']=[method_record(m)for m in methods if methods[m]['owner']==rid and exposed(methods[m])]
        result['fields']=[dict({k:v for k,v in f.items()if k!='owner'},constant=constants.get((4,r)),offset=field_offsets.get(r),attributes=attrs(4,r))for r,f in fields.items()if f['owner']==rid and exposed(f)]
        for table,items,key in [(23,properties,'properties'),(20,events,'events')]:
            for item,owner in items.items():
                if owner!=rid:continue
                accessors=semantics.get((table,item),[])
                if not any(exposed(methods[m])for flag,m in accessors):continue
                at=row(table,item);detail=dict(name=text(num(s,at+2)),flags=read('<H',at,tables),attributes=attrs(table,item),accessors=sorted([[flag,method_record(m)]for flag,m in accessors],key=str),constant=constants.get((table,item)))
                detail['signature'if table==23 else'type']=signature(blob(num(b,at+2+s)))if table==23 else type_coded(num(td,at+2+s));result[key].append(detail)
        for key in('methods','fields','properties','events'):result[key]=sorted(result[key],key=lambda x:json.dumps(x,sort_keys=True))
        output.append(result)
    require(not counts.get(38,0)and not counts.get(39,0)and not counts.get(40,0),'Single-module AppInsights API without exported/resource files required')
    return dict(identity=identity,references=sorted(references.values(),key=lambda x:x['name']),assemblyAttributes=attrs(32,1),types=sorted(output,key=lambda x:str(x['type'])))


def compare(original, rebuilt):
    expected,actual=public_api(original),public_api(rebuilt)
    require(expected==actual,'Complete public/protected AppInsights API, attributes and contract references differ')
    encoded=json.dumps(actual,sort_keys=True,separators=(',',':')).encode()
    return dict(kind='complete-public-protected-api-and-contract-reference-equality',types=len(actual['types']),references=len(actual['references']),
        apiSha256=hashlib.sha256(encoded).hexdigest(),originalBinaryGitSourceClaimed=False,qualificationAllowed=False,sourceAdmissionAllowed=False)
