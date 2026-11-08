"""Read NuGet ZIP32 content hashes without loading package assemblies.

NuGet contentHash is SHA-512 over the original unsigned ZIP representation.
For signed archives it excludes .signature.p7s and adjusts central-directory
offsets/counts. It is distinct from the unchanged signed file's SHA-512.
This implements NuGet.Client e3675c6173f0e3e4f13272c814ff33c590defba9:
src/NuGet.Core/NuGet.Packaging/Signing/Archive/SignedPackageArchiveUtility.cs,
GetPackageContentHash. It neither extracts entries nor verifies signatures.
ZIP64, multidisk and central-directory extensions are outside this reader.
"""
import base64
import hashlib
import struct

MAX_BYTES = 512 * 1024 * 1024
MAX_ENTRIES = 50000


def require(value, message):
    if not value:
        raise ValueError('NuGet content hash: ' + message)


def content_hash(raw):
    """Return the base64 NuGet content hash of bounded original package bytes."""
    require(isinstance(raw, bytes) and 22 <= len(raw) <= MAX_BYTES,
            'a bounded original ZIP byte string is required')
    end = raw.rfind(b'PK\x05\x06', max(0, len(raw) - 65557))
    require(end >= 0 and end + 22 <= len(raw), 'the ZIP32 end record is absent')
    _, disk, directory_disk, disk_count, count, size, start, comment = struct.unpack_from('<4s4H2IH', raw, end)
    require(disk == directory_disk == 0 and disk_count == count and 0 < count <= MAX_ENTRIES,
            'multidisk, ZIP64 or excessive entry count')
    require(end + 22 + comment == len(raw) and start + size == end,
            'the central directory or ZIP comment has invalid bounds')
    entries, position = [], start
    for _ in range(count):
        require(position + 46 <= end and raw[position:position + 4] == b'PK\x01\x02',
                'a central-directory entry is truncated')
        name_size, extra_size, comment_size, entry_disk = struct.unpack_from('<4H', raw, position + 28)
        header_size = 46 + name_size + extra_size + comment_size
        offset = struct.unpack_from('<I', raw, position + 42)[0]
        require(entry_disk == 0 and position + header_size <= end and offset + 30 <= start,
                'an entry points outside the ZIP32 file area')
        require(raw[offset:offset + 4] == b'PK\x03\x04', 'a local file header is absent')
        name = raw[position + 46:position + 46 + name_size]
        require(name and b'\0' not in name, 'an entry has an invalid name')
        entries.append(dict(name=name, position=position, size=header_size, offset=offset))
        position += header_size
    require(position == end, 'central-directory entries do not cover the declared directory')
    signatures = [row for row in entries if row['name'] == b'.signature.p7s']
    require(len(signatures) <= 1, 'multiple signature entries are ambiguous')
    if not signatures:
        # Ordinary duplicate names are not interpreted by this hash reader.
        # Their unchanged bytes are hashed; extraction/layout policy is separate.
        return base64.b64encode(hashlib.sha512(raw).digest()).decode('ascii')
    ordered = sorted(entries, key=lambda row: row['offset'])
    require(len({row['offset'] for row in entries}) == count, 'overlapping local-header offsets')
    for index, row in enumerate(ordered):
        next_offset = ordered[index + 1]['offset'] if index + 1 < count else start
        row['fileSize'] = next_offset - row['offset']
        require(row['fileSize'] >= 30, 'a local entry has invalid bounds')
    signature = signatures[0]
    remaining = [row for row in ordered if row is not signature]
    digest = hashlib.sha512()
    digest.update(raw[:ordered[0]['offset']])
    for row in remaining:
        digest.update(raw[row['offset']:row['offset'] + row['fileSize']])
    previous_end = 0
    for row in remaining:
        row['change'] = previous_end - row['offset']
        previous_end = row['offset'] + row['fileSize'] + row['change']
    for row in sorted(remaining, key=lambda item: item['position']):
        position = row['position']
        digest.update(raw[position:position + 42])
        digest.update(struct.pack('<I', row['offset'] + row['change']))
        digest.update(raw[position + 46:position + row['size']])
    digest.update(raw[end:end + 8])
    digest.update(struct.pack('<HHII', count - 1, count - 1,
                              size - signature['size'], start - signature['fileSize']))
    digest.update(raw[end + 20:])
    return base64.b64encode(digest.digest()).decode('ascii')
