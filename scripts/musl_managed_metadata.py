"""Read assembly identity and source attributes without loading managed code.

This bounded ECMA-335 reader accepts ordinary assembly metadata, including
ReadyToRun PEs. It never resolves references or executes an input assembly.
Layout references: ECMA-335 II.22/II.23/II.24 and the pinned runtime's
System.Reflection.Metadata/Ecma335/MetadataSizes.cs implementation.
"""
import hashlib
import struct


ATTRIBUTES = {'System.Reflection.AssemblyInformationalVersionAttribute': 1,
              'System.Reflection.AssemblyFileVersionAttribute': 1,
              'System.Reflection.AssemblyMetadataAttribute': 2,
              'System.Reflection.AssemblyCopyrightAttribute': 1,
              'System.Reflection.AssemblyCompanyAttribute': 1}


def require(value, message):
    if not value:
        raise ValueError(message)


def inspect(data):
    """Return independently decoded identity, attributes and assembly refs."""
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

    def type_name(table, rid):
        at = row(table, rid) + (coded(2, [0, 26, 35, 1]) if table == 1 else 4)
        return text(number(s, at + s)) + '.' + text(number(s, at))

    def constructor_type(encoded):
        tag, rid = encoded & 7, encoded >> 3
        require(tag in (2, 3), 'Invalid custom attribute constructor tag')
        if tag == 3:
            at = row(10, rid); parent = number(mr, at); ptag, prid = parent & 7, parent >> 3
            if ptag not in (0, 1): return None, None
            name = type_name(2 if ptag == 0 else 1, prid)
            require(text(number(s, at + mr)) == '.ctor', 'Custom attribute member is not a constructor')
            return name, blob(number(b, at + mr + s))
        at = row(6, rid)
        require(text(number(s, at + 8)) == '.ctor', 'Custom attribute method is not a constructor')
        # Declared attribute constructors belong to the TypeDef whose method
        # list range contains this MethodDef, rather than a guessed type name.
        low, high = 1, counts.get(2, 0) + 1
        while low < high:
            middle = (low + high) // 2
            start = number(index(6), row(2, middle) + 4 + s * 2 + td + index(4))
            if start <= rid: low = middle + 1
            else: high = middle
        type_rid = low - 1
        if type_rid:
            offset = row(2, type_rid) + 4 + s * 2 + td + index(4)
            start = number(index(6), offset)
            end = number(index(6), row(2, type_rid + 1) + 4 + s * 2 + td + index(4)) if type_rid < counts[2] else counts.get(6, 0) + 1
            if start <= rid < end: return type_name(2, type_rid), blob(number(b, at + 8 + s))
        raise ValueError('Custom attribute constructor has no declaring type')

    attributes, assembly_attributes, decoded_bytes = {}, 0, 0
    for rid in range(1, counts.get(12, 0) + 1):
        at = row(12, rid)
        if number(ca, at) != ((1 << 5) | 14): continue  # HasCustomAttribute: Assembly row 1.
        assembly_attributes += 1
        require(assembly_attributes <= 256, 'Oversized assembly custom-attribute set')
        name, signature = constructor_type(number(ct, at + ca))
        if name not in ATTRIBUTES: continue
        arguments = ATTRIBUTES[name]
        require(signature == bytes([0x20, arguments, 0x01] + [0x0e] * arguments),
                'Source identity attribute has an unexpected constructor signature')
        value = blob(number(b, at + ca + ct))
        require(value[:2] == b'\x01\0', 'Invalid custom attribute prolog')
        values, cursor = [], 2
        for unused in range(arguments):
            if read('<B', cursor, value) == 0xff:
                values.append(None); cursor += 1; continue
            size, start = compressed(value, cursor)
            decoded_bytes += size
            require(size <= 65536 and decoded_bytes <= 1024 * 1024, 'Oversized source identity attribute strings')
            require(start + size <= len(value), 'Truncated custom attribute string')
            values.append(value[start:start + size].decode('utf-8')); cursor = start + size
        require(value[cursor:] == b'\0\0', 'Unexpected named or trailing source identity attribute data')
        attributes.setdefault(name, []).extend(values)
    at = row(32, 1)
    public_key = blob(number(b, at + 16))
    references = []
    for rid in range(1, counts.get(35, 0) + 1):
        ref = row(35, rid)
        references.append(dict(name=text(number(s, ref + 12 + b)),
            version='.'.join(str(read('<H', ref + index * 2, tables)) for index in range(4))))
    return dict(assemblyName=text(number(s, at + 16 + b)),
        assemblyVersion='.'.join(str(read('<H', at + 4 + index * 2, tables)) for index in range(4)),
        culture=text(number(s, at + 16 + b + s)),
        publicKeyToken=hashlib.sha1(public_key).digest()[-8:][::-1].hex() if public_key else '',
        attributes=attributes, references=references,
        definitionCounts=dict(types=counts.get(2, 0), methods=counts.get(6, 0), fields=counts.get(4, 0),
                              exportedTypes=counts.get(39, 0), files=counts.get(38, 0), resources=counts.get(40, 0)),
        cliFlags=read('<I', cli + 16), entryPoint=read('<I', cli + 20),
        managedNativeHeaderBytes=read('<I', cli + 68))
