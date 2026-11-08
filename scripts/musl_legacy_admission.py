"""Pure, fail-closed source admission for reviewed legacy musl producers.

This module never builds, loads or executes SDK bytes. A successful producer
proof does not authorize publication. SDK6/5 remain rejected until their exact
construction and original test contracts have been reviewed independently.
"""
import datetime as dt
import argparse
import base64
import hashlib
import importlib.util
import json
import difflib
import posixpath
from pathlib import Path, PurePosixPath
import re
import shlex
import struct
import sys
import tarfile
from types import SimpleNamespace
import xml.etree.ElementTree as ET
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


P = module('legacy_admission_secure_primitives', 'musl-sdk.py')
MANAGED = module('legacy_admission_managed_metadata', 'musl_managed_metadata.py')
MANIFEST_INPUTS = module('legacy_admission_readable_manifest_inputs', 'musl_legacy_manifest_inputs.py')
MSBUILD_RESOURCES = module('legacy_admission_msbuild_resource_inputs', 'musl_legacy_msbuild_resources.py')
COMPILER_INPUTS = module('legacy_admission_managed_compiler_inputs', 'musl_legacy_compiler_inputs.py')
FACADE_INPUTS = module('legacy_admission_literal_facade_inputs', 'musl_legacy_facade_inputs.py')
GLOBBING_INPUTS = module('legacy_admission_globbing_inputs', 'musl_legacy_globbing_inputs.py')
FRAMEWORK_IL_INPUTS = module('legacy_admission_framework_il_inputs', 'musl_legacy_framework_il_inputs.py')
ATTRIBUTED_COMPONENTS = module('legacy_admission_attributed_components', 'musl_legacy_attributed_components.py')
require, fingerprint = P.require, P.fingerprint
STAGES = ('prepare', 'build', 'scan', 'test', 'collect', 'verify')
POLICIES = {'7.0.120': dict(runtime='7.0.20',
    bootstrap='7.0.118',
    installer='25b977658c06fd0217ec0bc0714398bb9d0a7bb0',
    sdk='a06803c09702777c6550fede13c8bdc52d780191',
    runtimeCommit='0fb6ac59fb1edbe4ed3ad62661df0eb7eacd7903',
    aspnetcore='d9ba962869d1b1c410ea476b02de2f8e27eec762',
    nuget='1653cf17925473602f5460c5e4682a0dab4c4d22')}
FP = {'bytes', 'sha256', 'sha512'}
KINDS = {'sdk-toolset', 'post-crossgen-sdk', 'official-runtime', 'official-aspnet',
         'native-trace', 'native-coreclr', 'managed-package', 'nuget-translation-data', 'generated-installer-data', 'official-sdk-comparison',
         MANIFEST_INPUTS.KIND}
NATIVE_CORECLR = {
    'libcoreclr.so': 'dlls/mscoree/coreclr/libcoreclr.so',
    'libclrjit.so': 'jit/libclrjit.so',
    'libmscordaccore.so': 'dlls/mscordac/libmscordaccore.so',
    'libmscordbi.so': 'dlls/mscordbi/libmscordbi.so',
}
NATIVE_CORECLR_PATCHES = {
    'patches/net7-musl/0004-guard-runtime-only-reflection-cache-mutations-in-dac.patch':
        ('773dd9dae8c3e82d7f04831da915893210bc8cd71541cec6c98aed3918b84c34', 'src/coreclr/vm/comreflectioncache.hpp'),
    'patches/net7-musl/0005-backport-metadata-local-allocation-marker.patch':
        ('f28a687f619d6baaa746f80469080fc5ed715a46f9a540cb80aee5bafe0fcf51', 'src/coreclr/md/runtime/metamodel.cpp'),
}
BUILT_ASSEMBLIES = {'dotnet.dll', 'Microsoft.NET.Build.Tasks.dll', 'Microsoft.DotNet.SdkResolver.dll',
                    'Microsoft.NET.Sdk.WorkloadMSBuildSdkResolver.dll'}
SDK7_IMPORT_SOURCES = {
    'nuget': ('NuGet.Build.Tasks', 'https://github.com/NuGet/NuGet.Client', '1653cf17925473602f5460c5e4682a0dab4c4d22'),
    'msbuild': ('Microsoft.Build', 'https://github.com/dotnet/msbuild', '6918b863aa37ad0699f98482fbab9f7a52e65a92'),
    'roslyn': ('Microsoft.Net.Compilers.Toolset', 'https://github.com/dotnet/roslyn', '528676cdbf0bfcfdb9372dc57a047dd0edc6d4db'),
    'fsharp': ('Microsoft.FSharp.Compiler', 'https://github.com/dotnet/fsharp', '1d892dd78d5dcb261a1d26f72efb333834436a02'),
    'razor': ('Microsoft.CodeAnalysis.Razor.Tooling.Internal', 'https://github.com/dotnet/razor-compiler', '0d427c7a238c5b7b114802459db7fc56bea6357d'),
    'templating': ('Microsoft.TemplateEngine.Abstractions', 'https://github.com/dotnet/templating', '2b9392b98f8046cf84a4cb525d931ba084b783fa'),
    'roslyn-analyzers': ('Microsoft.CodeAnalysis.NetAnalyzers', 'https://github.com/dotnet/roslyn-analyzers', '31373ce8529c3d2f6b91e61585872160b0d7d7cd'),
}
# Reviewed official 7.0 metadata, both native musl CPUs. These authenticate
# imported frameworks independently of their self-reported .version markers.
SDK7_FRAMEWORK_SHA512 = {
    ('official-runtime', 'aarch64'): '552ca73467f8043d351c20d71df95ba963b32e8c75706df6f5d3fce525f3efdf1314df296c44fbedad5575782e37633998a79b2c23f7f7420f814ee2488f30a2',
    ('official-runtime', 'x64'): '31b9da08d633cd0028eb08c36ee2c5c3cb1be6d3c5e010c85ae291496fe5e818b5be59f5d47aff86ed939c260f762e57ff06934a4d0954376935b1adc799f1bf',
    ('official-aspnet', 'aarch64'): '65406e1714a3117daa342b3fd0dbcd5c3214315611eacbbd8580827f69a07a9480530320ba40692a3d6dbff832d929a1420079f1db30ca3fd67a6fd035149d04',
    ('official-aspnet', 'x64'): 'a80f31193af70d556e8d026d39d79863c8389b065fe0778e7b4360f7d1f6d36503ba52736c40e74a716c3c30500b185816ed60d79b06ae295754b67374a1fa45',
}
NUGET7_PACKAGES = {'microsoft.build.nugetsdkresolver', 'nuget.build.tasks', 'nuget.build.tasks.console',
    'nuget.build.tasks.pack', 'nuget.commandline.xplat', 'nuget.commands', 'nuget.common', 'nuget.configuration',
    'nuget.credentials', 'nuget.dependencyresolver.core', 'nuget.frameworks', 'nuget.librarymodel',
    'nuget.packagemanagement', 'nuget.packaging', 'nuget.packaging.core', 'nuget.projectmodel', 'nuget.protocol',
    'nuget.resolver', 'nuget.versioning'}
SDK7_COMPARISON_SHA512 = {
    'aarch64': '5d3124c3daf1ed1cef0c838e753637af1e52030b36630bbfa7dba176a7eca24fe9e5c4df9eff2170fa96cf63e0055df42f0950b3b5900deb282590e4b612f3fb',
    'x64': 'c508ab5310d743f57ea78611ffe354268fe883e7c673ee808daaa6dde30ba454d5d70f8191c49eb52ae4a80c062ed6490ba1d6b752fcc541b0eb7835f4eee87f',
}
NETSTANDARD21 = dict(id='netstandard.library.ref', version='2.1.0', bytes=2955681,
    sha256='46ea2fcbd10a817685b85af7ce0c397d12944bdc81209e272de1e05efd33c78a',
    sha512='26bd0eaa7aa4689246115ab7c3da0d42b204b5e0ffe1004d83760e87572f463c9dcf0a29d3bfb96968cefd27c462ee82c019fe75204a5e3f27884bd3372d9bac',
    packagingCommit='7d57652f33493fa022125b7f63aad0d70c52d810', apiCommit='a5b5f2e1e369972c8ff1e2183979fab6099f52ef',
    licenseUrl='https://github.com/dotnet/core-setup/blob/master/LICENSE.TXT')
TESTHOST_NUGET_COMMIT = '112236f486dc18a9281226e342b458079441e403'
VSTEST7_COMMIT = '79d56b02b69a582cd90428878a5e9411ab7538f5'
VSTEST7_VERSION = '17.4.1-dev'
CSS_PARSER = dict(id='microsoft.css.parser', version='1.0.0-20200708.1', bytes=53267,
    sha256='6eaaee47a12a96138731e9f42b117f62e7978982b3821290f77bd296d2903d0f',
    sha512='9d7c3180c9856bff9202cc14a10c3dce68db6617871ac683b26d26c1ad1204264e2b347765b10d33f492d2a2a158842b1c965d9fa9f7f52ce962278e31b7d4bf',
    sourceCommit='d6d86bcd8c162b1ae22ef00955ff748d028dd0ee', externalCommit='522d361e1cd703f1e8e526f5306e4ed18de1da41',
    licenseUrl='https://github.com/dotnet/cssparser/blob/master/LICENSE.txt')


def resource_only_pe(data):
    """Inspect ECMA-335 metadata without loading an imported assembly.

    The accepted table set describes resource satellites, not executable types.
    Layout: ECMA-335 II.24; resource strings follow the runtime ResourceReader.
    https://github.com/dotnet/runtime/blob/main/src/libraries/System.Private.CoreLib/src/System/Resources/ResourceReader.cs
    """
    def read(fmt, offset, body=data):
        require(0 <= offset <= len(body) - struct.calcsize(fmt), 'Truncated satellite metadata')
        return struct.unpack_from(fmt, body, offset)[0]
    require(len(data) <= 1024 * 1024 and data[:2] == b'MZ', 'Bounded managed satellite PE required')
    pe = read('<I', 0x3c)
    require(data[pe:pe + 4] == b'PE\0\0', 'Satellite PE signature differs')
    sections, optional_size = read('<H', pe + 6), read('<H', pe + 20)
    optional = pe + 24
    magic = read('<H', optional)
    require(magic in (0x10b, 0x20b), 'Unknown satellite PE optional header')
    directories = optional + (96 if magic == 0x10b else 112)
    section_rows = []
    for index in range(sections):
        position = optional + optional_size + index * 40
        section_rows.append((read('<I', position + 12), read('<I', position + 20), read('<I', position + 16)))
    def address(rva, size=1):
        matches = [offset + rva - start for start, offset, length in section_rows
                   if start <= rva and rva + size <= start + length]
        require(len(matches) == 1 and matches[0] + size <= len(data), 'Satellite RVA escapes its section')
        return matches[0]
    cli = address(read('<I', directories + 14 * 8), 72)
    flags, entry = read('<I', cli + 16), read('<I', cli + 20)
    require(flags & 1 and not flags & 16 and entry == 0
            and all(read('<Q', cli + offset) == 0 for offset in (40, 48, 56, 64)),
            'Satellite contains a native entrypoint or managed native code')
    metadata = address(read('<I', cli + 8), read('<I', cli + 12))
    require(data[metadata:metadata + 4] == b'BSJB', 'Satellite CLR metadata signature differs')
    cursor = metadata + 16 + ((read('<I', metadata + 12) + 3) & ~3)
    streams = read('<H', cursor + 2)
    cursor += 4
    heaps = {}
    for unused in range(streams):
        relative, length = read('<I', cursor), read('<I', cursor + 4)
        end = data.find(b'\0', cursor + 8, cursor + 40)
        require(end >= 0, 'Satellite stream name is unterminated')
        name = data[cursor + 8:end].decode('ascii')
        require(name not in heaps and metadata + relative + length <= len(data), 'Duplicate or escaped CLR metadata stream')
        heaps[name] = data[metadata + relative:metadata + relative + length]
        cursor = (end + 4) & ~3
    require('#Strings' in heaps and '#Blob' in heaps and bool({'#~', '#-'} & heaps.keys()), 'Satellite metadata heaps are absent')
    tables = heaps.get('#~', heaps.get('#-'))
    heap_flags = read('<B', 6, tables)
    require(heap_flags & ~7 == 0, 'Unsupported satellite metadata flags')
    valid = read('<Q', 8, tables)
    counts = {}
    position = 24
    for table in range(64):
        if valid & (1 << table):
            counts[table] = read('<I', position, tables)
            position += 4
    require(counts.get(4, 0) == counts.get(6, 0) == counts.get(38, 0) == counts.get(39, 0) == 0
            and counts.get(2) == counts.get(32) == 1, 'Satellite has executable methods, fields, extra types or linked files')
    def index(table):
        return 4 if counts.get(table, 0) >= 65536 else 2
    def coded(bits, kinds):
        return 4 if max([counts.get(kind, 0) for kind in kinds]) >= 1 << (16 - bits) else 2
    string, guid, blob = (4 if heap_flags & bit else 2 for bit in (1, 2, 4))
    sizes = {0: 2 + string + guid * 3, 1: coded(2, [0, 26, 35, 1]) + string * 2,
        2: 4 + string * 2 + coded(2, [2, 1, 27]) + index(4) + index(6),
        10: coded(3, [2, 1, 26, 6, 27]) + string + blob,
        12: coded(5, [6,4,1,2,8,9,10,0,14,23,20,17,26,27,32,35,38,39,40,42,44,43])
            + coded(3, [6, 10]) + blob,
        14: 2 + coded(2, [2, 6, 32]) + blob,
        32: 16 + blob + string * 2, 35: 12 + blob * 2 + string * 2,
        40: 8 + string + coded(2, [38, 35, 39])}
    require(all(table in sizes or count == 0 for table, count in counts.items()), 'Unknown satellite metadata table requires review')
    offsets = {}
    for table, count in sorted(counts.items()):
        offsets[table] = position
        position += sizes.get(table, 0) * count
    require(position <= len(tables), 'Satellite metadata tables are truncated')
    def number(width, offset):
        return read('<I' if width == 4 else '<H', offset, tables)
    def text(at):
        heap = heaps['#Strings']
        require(0 <= at < len(heap), 'Satellite string heap index differs')
        end = heap.find(b'\0', at)
        require(end >= at, 'Satellite string is unterminated')
        return heap[at:end].decode('utf-8')
    def compressed(body, at):
        first = read('<B', at, body)
        if first < 0x80:
            return first, at + 1
        if first < 0xc0:
            return ((first & 0x3f) << 8) | read('<B', at + 1, body), at + 2
        require(first < 0xe0, 'Invalid CLR compressed integer')
        return ((first & 0x1f) << 24) | int.from_bytes(body[at + 1:at + 4], 'big'), at + 4
    def heap_blob(at):
        heap = heaps['#Blob']
        length, start = compressed(heap, at)
        require(start + length <= len(heap), 'Satellite blob is truncated')
        return heap[start:start + length]
    definition = offsets[2]
    require(text(number(string, definition + 4)) == '<Module>'
            and text(number(string, definition + 4 + string)) == '', 'Satellite defines a non-module type')
    assembly = offsets[32]
    public_key = heap_blob(number(blob, assembly + 16))
    name = text(number(string, assembly + 16 + blob))
    culture = text(number(string, assembly + 16 + blob + string))
    version = '.'.join(str(read('<H', assembly + 4 + index * 2, tables)) for index in range(4))
    imports = []
    import_rva, import_size = read('<I', directories + 8), read('<I', directories + 12)
    if import_size:
        start = address(import_rva, 20)
        for index in range(16):
            at = start + index * 20
            fields = [read('<I', at + offset) for offset in (0, 4, 8, 12, 16)]
            if fields == [0] * 5:
                break
            string_at = address(fields[3])
            end = data.find(b'\0', string_at, string_at + 256)
            require(end >= string_at, 'Satellite native import is unterminated')
            imports.append(data[string_at:end].decode('ascii').lower())
        else:
            raise ValueError('Satellite import table exceeds its bound')
    require(all(value == 'mscoree.dll' for value in imports), 'Satellite has nonstandard native imports')
    resources = []
    resource_rva, resource_size = read('<I', cli + 24), read('<I', cli + 28)
    resource_base = address(resource_rva, resource_size) if resource_size else None
    for index in range(counts.get(40, 0)):
        at = offsets[40] + index * sizes[40]
        require(number(coded(2, [38, 35, 39]), at + 8 + string) == 0, 'Satellite resource is linked executable input')
        relative = read('<I', at, tables)
        require(resource_base is not None and relative + 4 <= resource_size, 'Satellite resource offset differs')
        size = read('<I', resource_base + relative)
        require(0 < size <= 16 * 1024**2 and relative + 4 + size <= resource_size, 'Satellite resource payload is truncated')
        resources.append(dict(name=text(number(string, at + 8)),
            data=data[resource_base + relative + 4:resource_base + relative + 4 + size]))
    return dict(assemblyName=name, assemblyVersion=version, culture=culture,
                publicKeyBase64=base64.b64encode(public_key).decode(),
                publicKeyToken=hashlib.sha1(public_key).digest()[-8:][::-1].hex(), nativeImports=imports, resources=resources)


def elf_dynamic(data):
    """Read ELF64 dynamic dependency/version data; never invoke its loader."""
    require(len(data) >= 64 and data[:6] == b'\x7fELF\x02\x01', 'Native ELF64 little-endian metadata required')
    def number(fmt, offset):
        require(0 <= offset <= len(data) - struct.calcsize(fmt), 'Truncated native ELF metadata')
        return struct.unpack_from(fmt, data, offset)[0]
    offset, width, count = number('<Q', 32), number('<H', 54), number('<H', 56)
    require(width >= 56 and count < 65536 and offset + width * count <= len(data), 'ELF program headers escape the file')
    loads, dynamic = [], []
    for index in range(count):
        position = offset + width * index
        kind, start, virtual, size = number('<I', position), number('<Q', position + 8), number('<Q', position + 16), number('<Q', position + 32)
        require(start + size <= len(data), 'ELF segment escapes the file')
        if kind == 1:
            loads.append((virtual, start, size))
        elif kind == 2:
            dynamic.append((start, size))
    require(len(dynamic) <= 1, 'Multiple native ELF dynamic segments are forbidden')
    fields = {}
    if dynamic:
        start, size = dynamic[0]
        require(size % 16 == 0, 'ELF dynamic segment is truncated')
        for position in range(start, start + size, 16):
            kind, value = number('<q', position), number('<Q', position + 8)
            if kind == 0:
                break
            fields.setdefault(kind, []).append(value)
        else:
            raise ValueError('ELF dynamic segment has no terminator')
    def one(tag, default=None):
        values = fields.get(tag, [])
        require(len(values) <= 1, 'Duplicate ELF singleton dynamic tag')
        return values[0] if values else default
    require(not any(tag in fields for tag in (0x7ffffffd, 0x7fffffff)), 'Implicit ELF filter/auxiliary loader imports are unreviewed')
    def address(virtual, length=1):
        found = [start + virtual - base for base, start, size in loads if base <= virtual and virtual + length <= base + size]
        require(len(found) == 1 and found[0] + length <= len(data), 'ELF virtual metadata escapes a file-backed load segment')
        return found[0]
    if fields:
        require(one(5) is not None and one(10) is not None and one(10) <= 16 * 1024**2, 'Bounded ELF dynamic string table required')
        strings = address(one(5), one(10))
        string_size = one(10)
    else:
        strings, string_size = 0, 0
    def text(relative):
        require(0 <= relative < string_size, 'ELF dynamic string escapes its table')
        start = strings + relative
        end = data.find(b'\0', start, strings + string_size)
        require(end >= start, 'ELF dynamic string is unterminated')
        return data[start:end].decode('utf-8')
    needed = [text(value) for value in fields.get(1, [])]
    runpaths = [part for tag in (15, 29) for value in fields.get(tag, []) for part in text(value).split(':')]
    needs, definitions = [], []
    count = one(0x6fffffff, 0)
    require(count < 10000 and bool(count) == (one(0x6ffffffe) is not None), 'ELF version-needs table/count differs')
    at = address(one(0x6ffffffe), 16) if count else 0
    for index in range(count):
        require(number('<H', at) == 1, 'Unknown ELF version-needs layout')
        auxiliary_count, file = number('<H', at + 2), text(number('<I', at + 4))
        require(0 < auxiliary_count < 10000, 'Invalid ELF version-needs auxiliary count')
        auxiliary = at + number('<I', at + 8)
        versions = []
        for item in range(auxiliary_count):
            versions.append(text(number('<I', auxiliary + 8)))
            following = number('<I', auxiliary + 12)
            require(bool(following) == (item + 1 < auxiliary_count), 'ELF version-needs auxiliary chain differs')
            auxiliary += following
        needs.append(dict(file=file, versions=versions))
        following = number('<I', at + 12)
        require(bool(following) == (index + 1 < count), 'ELF version-needs chain differs')
        at += following
    count = one(0x6ffffffd, 0)
    require(count < 10000 and bool(count) == (one(0x6ffffffc) is not None), 'ELF version-definition table/count differs')
    at = address(one(0x6ffffffc), 20) if count else 0
    for index in range(count):
        require(number('<H', at) == 1, 'Unknown ELF version-definition layout')
        auxiliary_count = number('<H', at + 6)
        require(0 < auxiliary_count < 10000, 'Invalid ELF version-definition auxiliary count')
        auxiliary = at + number('<I', at + 12)
        for item in range(auxiliary_count):
            definitions.append(text(number('<I', auxiliary)))
            following = number('<I', auxiliary + 4)
            require(bool(following) == (item + 1 < auxiliary_count), 'ELF version-definition auxiliary chain differs')
            auxiliary += following
        following = number('<I', at + 16)
        require(bool(following) == (index + 1 < count), 'ELF version-definition chain differs')
        at += following
    return dict(needed=needed, runpaths=runpaths, versionNeeds=needs,
                glibcRequirements=sorted({version for row in needs for version in row['versions'] if version.startswith('GLIBC_')}),
                versionDefinitions=sorted(set(definitions)))


def resource_strings(data):
    """Decode intrinsic string resources without BinaryFormatter or CLR loading."""
    require(len(data) < 16 * 1024**2 and data[:4] == b'\xce\xca\xef\xbe', 'Only bounded .resources string tables are admitted')
    def integer(position):
        require(0 <= position <= len(data) - 4, 'Truncated resource integer')
        return struct.unpack_from('<i', data, position)[0]
    def length(position):
        value = 0
        for shift in range(0, 35, 7):
            require(position < len(data), 'Truncated resource string length')
            byte = data[position]
            position += 1
            require(shift < 28 or byte <= 0x0f, 'Oversized resource string length')
            value |= (byte & 0x7f) << shift
            if byte < 128:
                return value, position
        raise ValueError('Invalid resource string length')
    def string_at(position, encoding):
        size, position = length(position)
        require(position + size <= len(data), 'Truncated resource string')
        return data[position:position + size].decode(encoding), position + size
    require(integer(4) == 1 and 0 <= integer(8) < len(data), 'Unknown resource manager header requires review')
    reader, position = string_at(12, 'utf-8')
    unused, position = string_at(position, 'utf-8')
    require(reader.startswith('System.Resources.ResourceReader,') and position == 12 + integer(8),
            'Custom resource readers are forbidden')
    require(integer(position) == 2, 'Only intrinsic .resources version 2 strings are admitted')
    count, types = integer(position + 4), integer(position + 8)
    require(0 <= count < 100000 and types == 0, 'Custom serialized resource types are forbidden')
    position = (position + 12 + 7) & ~7
    require(position + count * 8 + 4 <= len(data), 'Resource name index is truncated')
    name_positions = [integer(position + count * 4 + index * 4) for index in range(count)]
    data_start = integer(position + count * 8)
    names_start = position + count * 8 + 4
    require(names_start <= data_start <= len(data), 'Resource data section escapes the blob')
    rows, ranges = {}, set()
    for relative in name_positions:
        require(0 <= relative < data_start - names_start, 'Resource name offset differs')
        name, at = string_at(names_start + relative, 'utf-16-le')
        require(name not in rows and at + 4 <= data_start, 'Duplicate resource key or escaped name')
        relative_data = integer(at)
        require(0 <= relative_data < len(data) - data_start, 'Resource data offset differs')
        start = data_start + relative_data
        code, at = length(start)
        require(code == 1, 'A translation resource is not an intrinsic string')
        value, end = string_at(at, 'utf-8')
        ranges.add((start, end))
        rows[name] = dict(value=value, keySha256=hashlib.sha256(name.encode()).hexdigest(),
                          valueSha256=hashlib.sha256(value.encode()).hexdigest())
    end = data_start
    for start, finish in sorted(ranges):
        require(start == end, 'Opaque or overlapping serialized translation data is forbidden')
        end = finish
    require(end == len(data), 'Trailing opaque translation data is forbidden')
    return rows


def source_member(release, manifest, name):
    with tarfile.open(release / 'sources' / manifest['archive']['path'], 'r|gz') as archive:
        for entry in archive:
            if entry.name == name:
                require(entry.isfile() and entry.size <= 2 * 1024**2, 'Bounded ordinary corresponding source required')
                return archive.extractfile(entry).read()
    raise ValueError('Corresponding source archive member is absent')


def reviewed_netstandard_identity(path, commit):
    """One immutable legacy reference package, never a generic nuspec fallback."""
    require(commit == NETSTANDARD21['packagingCommit'] and fingerprint(path) == {key: NETSTANDARD21[key] for key in FP},
            'Unreviewed missing-repository/license package identity')
    metadata = nuspec_metadata(path)
    require(metadata.findtext('{*}id', '').lower() == NETSTANDARD21['id']
            and metadata.findtext('{*}version') == NETSTANDARD21['version']
            and metadata.find('{*}repository') is None and metadata.find('{*}license') is None
            and metadata.findtext('{*}licenseUrl') == NETSTANDARD21['licenseUrl']
            and NETSTANDARD21['packagingCommit'] in metadata.findtext('{*}description', ''),
            'Exact reviewed NETStandard reference package provenance metadata differs')
    with zipfile.ZipFile(path) as archive:
        for name, expected in [('LICENSE.TXT', 'd7a68596ab69b06f51ca278a6545148e4269a9381c26d597c13df5d88e08cf5b'),
                               ('THIRD-PARTY-NOTICES.TXT', '2e3b2cb5cb57ff44310801dd46e51dab1d35d9cfe196a9709ee8cb9c6f8e4d4a')]:
            require(archive.getinfo(name).file_size <= 1024**2 and hashlib.sha256(archive.read(name)).hexdigest() == expected,
                    'Original reference package embedded license/notice bytes differ')
    return metadata


def validate_netstandard_source_chain(release, manifest, path):
    reviewed_netstandard_identity(path, NETSTANDARD21['packagingCommit'])
    roots = {}
    for role, commit in [('packaging', NETSTANDARD21['packagingCommit']), ('api', NETSTANDARD21['apiCommit'])]:
        matches = [root for root in manifest['roots'] if root.get('kind') in {'git', 'git-export'} and root.get('commit') == commit]
        require(len(matches) == 1, 'Both complete exact NETStandard packaging and C# API Git roots are required')
        roots[role] = matches[0]['name']
    hashes = {
        'packaging/eng/Version.Details.xml': 'cbccaca953c24a1ce72b78345f5b86076654aac7f3cd0a76ec268a1ecc5ab7bb',
        'packaging/eng/Versions.props': 'be46e5e4f8c802acc88c762531a927d0a10858a89fc32d8b4788a32696aa01e5',
        'packaging/src/pkg/projects/netstandard/src/netstandard.depproj': '784b8713fe234c39ae56addcdc2f86d5240b963a46b8ae0202141a0d8b8f69d5',
        'packaging/src/pkg/projects/netstandard/pkg/NETStandard.Library.Ref.pkgproj': '856f482c23c14f7b4df449ac52a1cff2eafa034cf0eb92ce10b099c15b36d05a',
        'api/src/netstandard/ref/netstandard.csproj': '688e2261a3a38acc66a9c44d7575552bbd339b0faf92d622a9506f65a0a2b49a',
        'api/src/netstandard/pkg/NETStandard.Library.pkgproj': '81c8be7328448ed7dcb4f896df27fd634d4a6a90026e453b8c39c7d508f23dd2',
        'api/eng/Versions.props': 'ee72023f2eaed030a804038a1274828647652d5533ebf47841bb218a87e8aa21',
        'packaging/LICENSE.TXT': 'cfc21f5e8bd655ae997eec916138b707b1d290b83272c02a95c9f821b8c87310',
        'packaging/THIRD-PARTY-NOTICES.TXT': 'e7e3492d0251ce6ba47592d26f54f66d7ace8abba94881c28a2fe83ab5da303a',
        'api/LICENSE.TXT': 'cfc21f5e8bd655ae997eec916138b707b1d290b83272c02a95c9f821b8c87310',
        'api/THIRD-PARTY-NOTICES.TXT': 'fd880d29a522f238c178452b38cbf196bb5c0dab7ebfdc590b02b8e5019ebc71'}
    wanted = {roots[name.split('/', 1)[0]] + '/' + name.split('/', 1)[1]: digest for name, digest in hashes.items()}
    index = {}
    with (release / 'sources' / manifest['index']['path']).open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'] in wanted or row['path'].startswith(roots['api'] + '/'):
                index[row['path']] = row
    bodies = {}
    with tarfile.open(release / 'sources' / manifest['archive']['path'], 'r|gz') as archive:
        for entry in archive:
            if entry.name not in wanted and not (entry.name.startswith(roots['api'] + '/') and entry.name.endswith('.cs')):
                continue
            require(entry.isfile() and entry.size <= 8 * 1024**2, 'Bounded ordinary reference API/packaging source required')
            raw = archive.extractfile(entry).read()
            row = index.get(entry.name, {})
            require(row.get('baseline', {}).get('blob') == hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
                    'Corresponding NETStandard C# API/packaging source differs from its exact Git blob')
            if entry.name in wanted:
                require(hashlib.sha256(raw).hexdigest() == wanted[entry.name], 'Reviewed original reference package source chain bytes differ')
            bodies[entry.name] = raw
    require(set(wanted) <= bodies.keys(), 'Original NETStandard package dependency/source chain is incomplete')
    details = ET.fromstring(bodies[roots['packaging'] + '/eng/Version.Details.xml'])
    dependencies = [row for row in details.iter('Dependency') if row.get('Name') == 'NETStandard.Library']
    require(len(dependencies) == 1 and dependencies[0].get('Version') == '2.1.0'
            and dependencies[0].findtext('Uri') == 'https://github.com/dotnet/standard'
            and dependencies[0].findtext('Sha') == NETSTANDARD21['apiCommit'], 'Exact packaging-to-C#-API source commit chain differs')
    project = ET.fromstring(bodies[roots['api'] + '/src/netstandard/ref/netstandard.csproj'])
    compiles = [row.get('Include') for row in project.iter('Compile')]
    require(len(compiles) == 83 and len(set(compiles)) == 83 and all(isinstance(name, str) and not any(c in name for c in '*?;') for name in compiles),
            'All original 83 explicit C# reference API sources must remain declared')
    for name in compiles:
        resolved = posixpath.normpath(roots['api'] + '/src/netstandard/ref/' + name.replace('\\', '/'))
        require(resolved.startswith(roots['api'] + '/') and resolved in bodies, 'An original NETStandard C# reference API source is absent')
    with zipfile.ZipFile(path) as package:
        for name in ('LICENSE.TXT', 'THIRD-PARTY-NOTICES.TXT'):
            # The embedded upstream files use CRLF. Preserve both original
            # forms and compare only that exact line-ending transformation.
            require(package.read(name).replace(b'\r\n', b'\n') == bodies[roots['packaging'] + '/' + name].replace(b'\r\n', b'\n'),
                    'Reference package embedded and corresponding packaging license/notice text differs')
    return dict(sourceRoot=roots['packaging'], sourceCommit=NETSTANDARD21['packagingCommit'],
                allowedLayoutPrefix='packs/NETStandard.Library.Ref/2.1.0/')


def reviewed_css_identity(path, commit):
    require(commit == CSS_PARSER['sourceCommit'] and fingerprint(path) == {key: CSS_PARSER[key] for key in FP},
            'Unreviewed missing-repository CSS package identity')
    metadata = nuspec_metadata(path)
    require(metadata.findtext('{*}id', '').lower() == CSS_PARSER['id']
            and metadata.findtext('{*}version') == CSS_PARSER['version']
            and metadata.find('{*}repository') is None and metadata.find('{*}license') is None
            and metadata.findtext('{*}licenseUrl') == CSS_PARSER['licenseUrl'],
            'Original CSS package metadata/license identity differs')
    return metadata


def reviewed_globbing_identity(path, commit):
    require(commit == GLOBBING_INPUTS.COMMIT, 'Unreviewed original Globbing source identity')
    GLOBBING_INPUTS.inspect_package(path)
    return nuspec_metadata(path)


def validate_css_source_chain(release, manifest, path):
    """One declared SDK Gitlink chain; no invented package repository metadata."""
    reviewed_css_identity(path, CSS_PARSER['sourceCommit'])
    selected = {}
    for role, commit in [('sdk', POLICIES['7.0.120']['sdk']), ('external', CSS_PARSER['externalCommit']),
                         ('css', CSS_PARSER['sourceCommit'])]:
        matches = [row for row in manifest['roots'] if row.get('kind') in {'git', 'git-export'} and row.get('commit') == commit]
        require(len(matches) == 1, 'Complete exact SDK, external orchestration and CSS Git sources are required')
        selected[role] = matches[0]
    require(any(row.get('path') == 'src/cssparser' and row.get('commit') == CSS_PARSER['sourceCommit']
                and row.get('root') == selected['css']['name'] for row in selected['external'].get('submodules', [])),
            'Declared CSS Gitlink does not connect its complete corresponding source')
    hashes = {
        ('sdk', 'eng/Version.Details.xml'): 'ac48f1fc7da0874a2b556e1cc11b8ebeefe9b8a89e6a01846b877ebcc9f0bd3f',
        ('external', '.gitmodules'): 'fa169442379b39d5c461562b165cbce0655294fad3384c0e78c2bb0be7e8e63c',
        ('external', 'repos/cssparser.proj'): '6e35bff2db56e203a8219f83d82830503d0d078c814419ed263f15de5b1263e7',
        ('css', 'src/Microsoft.Css.Parser/Microsoft.Css.Parser.csproj'): '8320e792a90530ff2e1c388c51e7e232e5046f6a5b7443f6711b2057dcf671a1',
        ('css', 'azure-pipelines.yml'): '2708a9b5eda10217967b0df03122f50e55dafcae96c1bb18f6ea84a032292461',
        ('css', 'LICENSE.txt'): 'cfc21f5e8bd655ae997eec916138b707b1d290b83272c02a95c9f821b8c87310'}
    wanted = {selected[role]['name'] + '/' + name: sha for (role, name), sha in hashes.items()}
    prefix = selected['css']['name'] + '/'
    index = {}
    with (release / 'sources' / manifest['index']['path']).open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'] in wanted or row['path'].startswith(prefix):
                index[row['path']] = row
    require(sum(name.startswith(prefix) for name in index) == 284
            and sum(name.startswith(prefix) and name.endswith('.cs') for name in index) == 167
            and not selected['css'].get('deleted'), 'All original CSS source, projects, tests and licenses must be retained')
    actual = set()
    with tarfile.open(release / 'sources' / manifest['archive']['path'], 'r|gz') as archive:
        for entry in archive:
            if entry.name not in index:
                continue
            require(entry.isfile() and entry.size <= 8 * 1024**2 and entry.name not in actual,
                    'An ordinary original CSS/dependency source file is required')
            raw = archive.extractfile(entry).read()
            require(index[entry.name].get('baseline', {}).get('blob') == hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
                    'Corresponding CSS/dependency source differs from its original Git blob')
            if entry.name in wanted:
                require(hashlib.sha256(raw).hexdigest() == wanted[entry.name], 'Exact reviewed CSS source chain bytes differ')
            actual.add(entry.name)
    require(actual == index.keys() and wanted.keys() <= actual, 'Complete CSS source chain archive is missing original files')
    return dict(kind='sdk-declared-source-gitlink', sourceRoot=selected['css']['name'], sourceCommit=CSS_PARSER['sourceCommit'],
        localBuildClaimed=False, byteIdenticalCompilationClaimed=False,
        allowedLayoutPaths=['sdk/7.0.120/Sdks/Microsoft.NET.Sdk.Razor/tools/Microsoft.Css.Parser.dll'])


def validate_schema_equivalence(pristine, embedded):
    expected = [(pristine, 10723, '5d4226dd761e3854ed02d33de390713c4c9846238a1d16f4b5f38192545ea417'),
                (embedded, 10822, '67465b7ba16b9238c6793607216f311dd3aad04a7cee8eb2c4efa8f5c4ebc6e9')]
    trees = []
    for raw, size, sha in expected:
        require(len(raw) == size and hashlib.sha256(raw).hexdigest() == sha
                and b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(),
                'Unreviewed NuGet metadata schema equivalence bytes')
        text = raw.decode('utf-8')
        require(text.count('{0}') == 3, 'NuGet schema namespace placeholder scope differs')
        root = ET.fromstring(text.replace('{0}', 'urn:cbodotnet:nuspec-namespace-placeholder'))
        def canonical(node):
            exact = lambda value: None if value is None or value.isspace() else value
            return (node.tag, tuple(node.attrib.items()), exact(node.text), exact(node.tail),
                    tuple(canonical(child) for child in node))
        trees.append(canonical(root))
    require(trees[0] == trees[1], 'NuGet schema non-whitespace text, tail, attributes or child order differs')


def comparison_sdk_inventory(path, record, wanted):
    actual = fingerprint(path)
    require(record['sdkVersion'] == '7.0.120' and actual['sha512'] == SDK7_COMPARISON_SHA512[record['architecture']],
            'Retained original SDK comparison archive identity differs')
    files, captured = [], {}
    seen = set()
    with tarfile.open(path, 'r|gz') as archive:
        for entry in archive:
            if entry.isdir():
                continue
            name = portable(entry.name.removeprefix('./'))
            require(entry.isfile() and name not in seen, 'Comparison SDK must have one ordinary member per path')
            seen.add(name)
            files.append(dict(path=name, bytes=entry.size))
            if name in wanted:
                require(entry.size <= 2 * 1024**2, 'Comparison translation/notice member exceeds its bound')
                raw = archive.extractfile(entry).read()
                captured[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())
    require(set(captured) == set(wanted), 'An exact original SDK translation/omission/notice member is absent')
    return dict(archive=actual, files=files), captured


def validate_translation_data(release, record, source_manifest):
    policy = module('legacy_admission_translation_policy', 'musl-legacy-nuget-resources.py')
    directory = release / 'reports/build/nuget-translation-data'
    origin = load(directory / 'origin.json')
    require(origin.get('schemaVersion') == 1 and origin.get('kind') == 'imported-official-nuget-translation-data'
            and origin.get('sdkVersion') == record['sdkVersion'] and origin.get('architecture') == record['architecture']
            and origin.get('sourceCommit') == POLICIES[record['sdkVersion']]['nuget']
            and origin.get('sourceLicense') == 'Apache-2.0' and origin.get('cultures') == list(P.SOURCE_CULTURES)
            and all(origin.get(key) is False for key in ('primaryNuGetAssembliesImported', 'nativeComponentsImported',
                'wholeSdkUsedAsProduct', 'translationsLocallySourceBuilt', 'qualificationAllowed', 'sourceAdmissionAllowed'))
            and origin.get('officialSdk', {}).get('sha512') == policy.SHA512[record['architecture']],
            'Exact resource-only NuGet product translation input identity required')
    index = {}
    with (release / 'sources' / source_manifest['index']['path']).open() as stream:
        for line in stream:
            row = json.loads(line)
            index[row['path']] = row
    roots = {root['name']: root for root in source_manifest['roots']}
    require('nuget-translation-data' in roots and roots['nuget-translation-data'].get('kind') == 'tree',
            'Complete readable imported translation data must be retained as used sources')
    source_schemas = {row['sha256'] for name, row in index.items() if name.startswith('nuget/') and name.endswith('.xsd')}
    canonical_source = None
    def local(descriptor):
        path = checked(directory, descriptor)
        relative = 'nuget-translation-data/' + descriptor['path']
        require(relative in index and all(index[relative].get(key) == descriptor[key] for key in FP),
                'Translation data/notice is absent from the complete source archive')
        return path
    schema_proofs = origin.get('reviewedGeneratedStaticXml', [])
    require(len(schema_proofs) == 1, 'One closed reviewed generated NuGet schema proof required')
    schema = schema_proofs[0]
    require(set(schema) == {'sourcePath', 'sourceCommit', 'sourceByteIdentity', 'pristine', 'generatedEmbedded',
                'namespaceSubstitution', 'orderedQualifiedNamesAttributesAndNonWhitespaceTextEquivalent',
                'onlyWhitespaceIndentNodesIgnored', 'dtdAndEntityDeclarationsRejected'}
            and schema['sourceCommit'] == POLICIES[record['sdkVersion']]['nuget'] and schema['sourceByteIdentity'] is False
            and schema['namespaceSubstitution'] == dict(before='{0}', after='urn:cbodotnet:nuspec-namespace-placeholder', occurrencesEach=3)
            and all(schema[key] is True for key in ('orderedQualifiedNamesAttributesAndNonWhitespaceTextEquivalent',
                                                   'onlyWhitespaceIndentNodesIgnored', 'dtdAndEntityDeclarationsRejected')),
            'NuGet generated schema disposition differs')
    pristine_schema = local(schema['pristine']).read_bytes()
    embedded_schema = local(schema['generatedEmbedded']).read_bytes()
    validate_schema_equivalence(pristine_schema, embedded_schema)
    original_schema = index.get('nuget/' + portable(schema['sourcePath']), {})
    require(original_schema.get('bytes') == len(pristine_schema)
            and original_schema.get('sha256') == hashlib.sha256(pristine_schema).hexdigest(),
            'NuGet schema proof does not correspond to complete pinned source bytes')
    readable = load(local(origin['readableResources']))
    require(isinstance(readable, list) and len(readable) == 286, 'All 286 product satellite metadata rows required')
    readable_by_path = {}
    for item in readable:
        require('/resources/' in item.get('path', ''), 'Readable satellite path differs')
        relative = item['path'].rsplit('/resources/', 1)[1]
        require(relative not in readable_by_path, 'Duplicate readable satellite metadata')
        readable_by_path[relative] = item
    expected = set(policy.relative_names())
    require(len(expected) == 286 and not any('Test.Utility' in name for name in expected), 'Reviewed product translation scope differs')
    rows = origin.get('files', [])
    require(len(rows) == 286 and {row['path'] for row in rows} == expected == set(readable_by_path),
            'A product satellite is missing or an orphan/test payload was included')
    products = {}
    for row in rows:
        relative = portable(row['path'])
        path = directory / 'resources' / relative
        fp = fingerprint(path)
        require(all(row.get(key) == value for key, value in fp.items())
                and row.get('sdkMember') == 'sdk/' + record['sdkVersion'] + '/' + relative
                and row.get('origin') == 'imported-official-translation-data', 'Actual translation satellite bytes differ')
        source_name = 'nuget-translation-data/resources/' + relative
        require(source_name in index and all(index[source_name].get(key) == value for key, value in fp.items()),
                'Actual translation satellite input is absent from the source archive')
        binary = resource_only_pe(path.read_bytes())
        culture = next(part for part in PurePosixPath(relative).parts if part in P.SOURCE_CULTURES)
        claimed = row['assemblyMetadata']
        contract = PurePosixPath(relative).name == 'NuGet.VisualStudio.Contracts.resources.dll'
        version, token = ('17.4.3.0', 'b03f5f7f11d50a3a') if contract else ('6.4.3.1', '31bf3856ad364e35')
        require(binary['culture'] == culture and binary['assemblyVersion'] == version and binary['publicKeyToken'] == token
                and binary['assemblyName'] + '.dll' == PurePosixPath(relative).name
                and all(claimed.get(key) == binary[key] for key in
                        ('assemblyName', 'assemblyVersion', 'culture', 'publicKeyBase64', 'publicKeyToken', 'nativeImports'))
                and claimed.get('managedResourceOnly') is True
                and all(claimed.get(key) == 0 for key in ('methodBodies', 'extraTypes', 'fields', 'linkedResources'))
                and claimed.get('emptySatellite') is (not binary['resources']), 'Satellite executable/ABI metadata differs from its actual PE')
        data = readable_by_path[relative]
        require({item['name'] for item in data['resources']} == {item['name'] for item in binary['resources']}
                and len(data['resources']) == len(binary['resources']), 'Readable satellite resource coverage differs')
        descriptions = []
        for resource in binary['resources']:
            raw, name = resource['data'], resource['name']
            value = next(item for item in data['resources'] if item['name'] == name)
            sha = hashlib.sha256(raw).hexdigest()
            require(value['sha256'] == sha, 'Readable resource hash differs from actual embedded bytes')
            if raw[:4] == b'\xce\xca\xef\xbe':
                require(value.get('format') == 'dotnet-string-table' and value.get('entries') == resource_strings(raw),
                        'Readable translation keys/values differ from actual intrinsic resource strings')
            else:
                require(name.endswith('.xsd') and value.get('format') == 'xml-schema'
                        and raw.decode('utf-8') == value.get('text') and value.get('entries') == {}
                        and b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper()
                        and ET.fromstring(raw.decode('utf-8').replace('{0}',
                            'urn:cbodotnet:nuspec-namespace-placeholder')).tag == '{http://www.w3.org/2001/XMLSchema}schema',
                        'Opaque embedded satellite data is forbidden')
                if sha not in source_schemas:
                    if canonical_source is None:
                        sources = [name for name, item in index.items() if name.startswith('nuget/') and name.endswith('.xsd')
                            and item['bytes'] == 10723 and item['sha256'] == '5d4226dd761e3854ed02d33de390713c4c9846238a1d16f4b5f38192545ea417']
                        require(sources, 'Exact corresponding pristine NuGet schema source is absent')
                        canonical_source = source_member(release, source_manifest, sources[0])
                    validate_schema_equivalence(canonical_source, raw)
                    require(any(name.startswith('nuget-translation-data/') and name.endswith('.xsd')
                                and item['bytes'] == 10822 and item['sha256'] == sha for name, item in index.items()),
                            'Generated equivalent NuGet schema must be retained explicitly as generated data')
            description = dict(name=name, sha256=sha, format=value['format'], entryCount=len(value['entries']))
            if value['format'] == 'xml-schema':
                declaration = next(item for item in row['readableResources'] if item['name'] == name)
                source_path = portable(declaration.get('sourcePath'))
                actual_source = index.get('nuget/' + source_path, {})
                if sha in source_schemas:
                    require(actual_source.get('sha256') == sha, 'Embedded schema source path differs')
                    description.update(sourcePath=source_path, sourceByteIdentity=True)
                else:
                    require(source_path == schema['sourcePath'], 'Generated schema must use its exact reviewed corresponding source')
                    description.update(sourcePath=source_path, sourceByteIdentity=False,
                                       generatedSourcePath='static-xml-source-data/embedded-nuspec.xsd')
            descriptions.append(description)
        require(row.get('readableResources') == descriptions, 'Satellite readable source inventory differs')
        products[row['sdkMember']] = fp
    inventory = load(local(origin['originalSdkInventory']))
    require(inventory.get('archive') == {key: origin['officialSdk'][key] for key in FP}
            and isinstance(inventory.get('files'), list) and len(inventory['files']) > 1000,
            'Whole exact official SDK file inventory is required for orphan omission')
    paths = {portable(row['path']): row for row in inventory['files']}
    require(len(paths) == len(inventory['files'])
            and not any(PurePosixPath(name).name.lower() in {'test.utility.dll', 'test.utility.exe'} for name in paths),
            'A primary Test.Utility assembly exists; omission is not authorized')
    omissions = load(local(origin['explicitOrphanTestOmissions']))
    omitted = omissions.get('files', [])
    expected_omissions = {'sdk/' + record['sdkVersion'] + '/' + culture + '/Test.Utility.resources.dll' for culture in P.SOURCE_CULTURES}
    require(omissions.get('primaryTestUtilityAssemblies') == [] and len(omitted) == 13
            and {row['path'] for row in omitted} == expected_omissions,
            'Only the exact thirteen orphan unit-test satellites may be omitted')
    for row in omitted:
        require(row['path'] in paths and paths[row['path']]['bytes'] == row['bytes']
                and re.fullmatch('[a-f0-9]{64}', row.get('sha256', ''))
                and re.fullmatch('[a-f0-9]{128}', row.get('sha512', ''))
                and row.get('reason') == 'Orphan unit-test fixture satellite; no primary Test.Utility assembly exists anywhere in the original SDK',
                'The explicit orphan-test omission bytes/reason differ')
    notices = origin.get('notices', [])
    require(notices and any('nuget-source-' in row['path'] and 'license' in row['path'].lower() for row in notices)
            and {'licenses/official-sdk-LICENSE.txt', 'licenses/official-sdk-ThirdPartyNotices.txt',
                 'licenses/original-NuGet.Localization.nuspec'} <= {row['path'] for row in notices},
            'Original NuGet and official SDK source/license notices are incomplete')
    for notice in notices:
        local(notice)
    compared_names = {row['sdkMember'] for row in rows} | expected_omissions | {'LICENSE.txt', 'ThirdPartyNotices.txt'}
    compared, original_members = comparison_sdk_inventory(
        release / 'reports/construction-inputs/original-sdk-comparison.tar.gz', record, compared_names)
    require(compared['archive'] == {key: origin['officialSdk'][key] for key in FP}
            and inventory == compared, 'Whole official SDK file inventory is not the actual retained archive')
    for row in rows:
        require(original_members[row['sdkMember']] == {key: row[key] for key in FP}, 'Translation bytes differ from the authenticated official SDK member')
    for row in omitted:
        require(original_members[row['path']] == {key: row[key] for key in FP}, 'Omitted orphan test satellite hashes differ from the actual official archive')
    for name in ('LICENSE.txt', 'ThirdPartyNotices.txt'):
        notice = next(row for row in notices if row['path'] == 'licenses/official-sdk-' + name)
        require(original_members[name] == {key: notice[key] for key in FP}, 'Original SDK notice bytes differ from their actual authenticated archive')
    return products


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def portable(name):
    require(isinstance(name, str) and name and name == PurePosixPath(name).as_posix()
            and not name.startswith('/') and not any(c in name for c in ('\\', ':', '\0', '\n', '\r'))
            and '..' not in PurePosixPath(name).parts, 'Unsafe legacy evidence member')
    return name


def checked(release, descriptor):
    require(isinstance(descriptor, dict) and set(descriptor) == FP | {'path'}, 'Closed artifact descriptor required')
    path = release / portable(descriptor['path'])
    require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents))
            and all(descriptor[k] == v for k, v in fingerprint(path).items()), 'Bound legacy artifact bytes differ')
    return path


def digest_stream(stream):
    digest = hashlib.sha256()
    size = 0
    header = b''
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        if not header:
            header = block[:4]
        size += len(block)
        require(size <= 512 * 1024**2, 'Legacy input member exceeds its bound')
        digest.update(block)
    return dict(bytes=size, sha256=digest.hexdigest(), signature=header.hex())


def tar_text(path, name):
    with tarfile.open(path, 'r:gz') as archive:
        entries = [item for item in archive if item.name.removeprefix('./') == name]
        require(len(entries) == 1 and entries[0].isfile() and entries[0].size <= 16384,
                'One bounded original component version marker required')
        return archive.extractfile(entries[0]).read().decode('utf-8-sig').strip().splitlines()


def members(path, kind):
    """Hash every ordinary member; never extract or resolve archive links."""
    if kind in {'native-trace', 'native-coreclr'}:
        with path.open('rb') as stream:
            return {'': digest_stream(stream)}
    rows = {}
    if kind in {'sdk-toolset', 'managed-package'} or zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for entry in archive.infolist():
                if entry.is_dir():
                    continue
                name = portable(entry.filename.removeprefix('./'))
                require(name not in rows and (entry.external_attr >> 16) & 0o170000 != 0o120000,
                        'Duplicate or linked legacy ZIP member')
                with archive.open(entry) as incoming:
                    rows[name] = digest_stream(incoming)
    else:
        with tarfile.open(path, 'r:gz') as archive:
            for entry in archive:
                if entry.isdir():
                    continue
                name = portable(entry.name.removeprefix('./'))
                require(entry.isfile() and name not in rows, 'Duplicate or non-ordinary legacy TAR member')
                rows[name] = digest_stream(archive.extractfile(entry))
    require(rows, 'An empty legacy product/input archive is forbidden')
    return rows


def validate_stages(release, record, prepare):
    stages = {}
    previous = None
    for name in STAGES:
        stage = load(release / 'reports/stages' / (name + '.json'))
        require(stage.get('stage') == name and stage.get('status') == 'passed'
                and isinstance(stage.get('commands'), list)
                and (stage['commands'] or name in {'scan', 'collect'}), 'Actual legacy stage commands are missing')
        start, finish = (dt.datetime.fromisoformat(stage[key]) for key in ('startedAtUtc', 'finishedAtUtc'))
        require(start.tzinfo is not None and finish.tzinfo is not None and finish >= start
                and (previous is None or start >= previous), 'Legacy stage chronology differs')
        previous = finish
        stages[name] = stage
    P.validate_container_engine(release, prepare, stages, P.identity(record['architecture']))
    return stages


def validate_scan_applicability(release, record, manifest):
    report = load(release / 'reports/scan-applicability.json')
    require(set(report) == {'status', 'reason', 'sourceOnly', 'importedInputsRequireInventory', 'sourceCommit', 'sourceGraph'}
            and report['status'] == 'not-applicable' and report['sourceOnly'] is False
            and report['importedInputsRequireInventory'] is True and isinstance(report['reason'], str) and report['reason']
            and report['sourceCommit'] == POLICIES[record['sdkVersion']]['sdk'],
            'Legacy binary-scan applicability must name its actual pinned SDK source graph')
    descriptor = report['sourceGraph']
    require(set(descriptor) == FP | {'path', 'projects'} and descriptor['path'] == 'sdk/source-build.slnf',
            'The actual original regular SDK solution filter is required')
    raw = source_member(release, manifest, descriptor['path'])
    require(all(descriptor[key] == value for key, value in dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
            sha512=hashlib.sha512(raw).hexdigest()).items()), 'Original SDK solution filter bytes differ')
    rows = []
    with (release / 'sources' / manifest['index']['path']).open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'] == descriptor['path']: rows.append(row)
    blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    require(len(rows) == 1 and rows[0].get('baseline', {}).get('blob') == blob,
            'SDK solution filter differs from its original pinned Git source')
    projects = json.loads(raw)['solution']['projects']
    require(isinstance(projects, list) and projects and len(set(projects)) == len(projects)
            and descriptor['projects'] == projects
            and all(isinstance(path, str) and path and 'BinaryToolKit' not in path for path in projects),
            'Actual legacy regular SDK source graph/scanner applicability differs')


def validate_replay(release, descriptor, binlog, *, compiled, component='sdk'):
    replay = load(checked(release, descriptor))
    required = {'schemaVersion', 'completedReplay', 'buildSucceeded', 'unfinishedTasks',
                'inputSha256', 'compiledOutputs', 'transformations', 'tasks', 'sourceMountRoot'}
    require(required <= set(replay) <= required | {'generatedOutputs'}
            and replay['schemaVersion'] == 1 and replay['completedReplay'] is True
            and replay['buildSucceeded'] is True and replay['unfinishedTasks'] == 0
            and replay['inputSha256'] == fingerprint(release / binlog)['sha256']
            and isinstance(replay['compiledOutputs'], list) and isinstance(replay['transformations'], list),
            'Complete successful legacy binary-log replay required')
    require(not compiled or replay['compiledOutputs'], 'Actual SDK compilation outputs are absent')
    source_root = replay['sourceMountRoot']
    require(isinstance(source_root, str) and source_root.startswith('/') and source_root == posixpath.normpath(source_root)
            and not any(char in source_root for char in '\\\0\r\n'), 'Exact absolute build source mount required')
    tasks = read_tasks(checked(release, replay['tasks']))
    referenced = replay['compiledOutputs'] if compiled else replay['transformations'] + replay.get('generatedOutputs', [])
    for row in referenced:
        require(row.get('context') in tasks and tasks[row['context']]['succeeded'] is True,
                'Output provenance has no successful actual task context')
        task = tasks[row['context']]
        task_file = (task['taskFile'].startswith(source_root + '/') if component not in {'nuget', 'vstest'} else
                     task['taskFile'].endswith('/sdk/7.0.118/Roslyn/Microsoft.CSharp.Core.targets'))
        if component == 'vstest' and row.get('member', '').endswith('.resources.dll'):
            task_file = task_file or task['taskFile'].endswith('/sdk/7.0.118/Sdks/Microsoft.NET.Sdk/targets/Microsoft.NET.Sdk.targets')
        require(task['projectFile'].startswith(source_root + '/') and task_file,
                'Output producer task escaped the actual source mount')
        if compiled:
            outputs = task_values(task, 'OutputAssembly')
            if component == 'vstest':
                outputs = {posixpath.normpath(value if value.startswith('/') else posixpath.join(posixpath.dirname(task['projectFile']), value))
                           for value in outputs}
            require(task['taskName'] in {'Csc', 'Fsc'} and row.get('outputPath') in outputs
                    and task_values(task, 'Sources')
                    and all(value.lower() == 'false' for value in task_values(task, 'SkipCompilerExecution'))
                    and any(event['kind'] == 'command-line' and isinstance(event['text'], str) and event['text'].strip()
                            for event in task['events']), 'Compiled output lacks actual original compiler execution/input/output events')
    return replay


def read_tasks(path):
    require(path.stat().st_size <= 512 * 1024**2, 'Bounded actual binary-log task events required')
    tasks = {}
    with path.open(encoding='utf-8') as stream:
        for line in stream:
            require(len(line) <= 16 * 1024**2, 'Oversized serialized binary-log task')
            task = json.loads(line)
            require(set(task) == {'context', 'taskName', 'projectFile', 'taskFile', 'succeeded', 'events'}
                    and isinstance(task['context'], str) and re.fullmatch(r'-?[0-9]+(?::-?[0-9]+){3}', task['context'])
                    and task['context'] not in tasks and isinstance(task['taskName'], str)
                    and isinstance(task['projectFile'], str) and isinstance(task['taskFile'], str)
                    and type(task['succeeded']) is bool and isinstance(task['events'], list), 'Closed actual task event row required')
            events = task['events']
            require(len(events) >= 2 and events[0].get('kind') == 'task-started' and events[-1].get('kind') == 'task-finished'
                    and sum(event.get('kind') == 'task-started' for event in events) == 1
                    and sum(event.get('kind') == 'task-finished' for event in events) == 1
                    and events[-1].get('succeeded') is task['succeeded'], 'Actual task start/finish boundaries differ')
            previous, timestamps = -1, []
            for event in events:
                require(set(event) == {'eventNumber', 'timestamp', 'kind', 'field', 'text', 'metadata', 'succeeded'}
                        and type(event['eventNumber']) is int and event['eventNumber'] >= previous
                        and event['kind'] in {'task-started', 'task-finished', 'task-parameter', 'message', 'command-line'}
                        and isinstance(event['metadata'], dict)
                        and all(isinstance(key, str) and isinstance(value, str) for key, value in event['metadata'].items())
                        and (event['text'] is None or isinstance(event['text'], str))
                        and (event['field'] is None or isinstance(event['field'], str)), 'Malformed binary-log task event')
                stamp = event['timestamp']
                require(isinstance(stamp, str) and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?(?:Z|[+-][0-9]{2}:[0-9]{2})', stamp),
                        'Exact bounded binary-log timestamp required')
                # .NET emits 100ns precision; Python 3.10 accepts at most six
                # decimal places. Event numbers retain the original ordering.
                stamp = re.sub(r'\.([0-9]{1,7})(?=Z|[+-])', lambda match: '.' + match[1][:6].ljust(6, '0'), stamp)
                stamp = stamp.removesuffix('Z') + ('+00:00' if stamp.endswith('Z') else '')
                current = dt.datetime.fromisoformat(stamp)
                require(current.tzinfo is not None, 'Actual task timestamp timezone is absent')
                previous = event['eventNumber']
                timestamps.append(current)
            # Parallel Copy workers can enqueue messages whose creation times
            # differ from logger order. Retain actual event-number ordering and
            # independently require the task's own start/finish chronology.
            require(timestamps[-1] >= timestamps[0], 'Actual task start/finish chronology differs')
            tasks[task['context']] = task
    require(tasks, 'Actual completed binary-log task stream is empty')
    return tasks


def task_values(task, field):
    values = [event['text'] for event in task['events'] if event['kind'] == 'task-parameter' and event['field'] == field]
    prefix = 'Task Parameter:' + field + '='
    values += [event['text'][len(prefix):] for event in task['events'] if event['kind'] == 'message'
               and isinstance(event['text'], str) and event['text'].startswith(prefix)]
    return set(values)


def validate_crossgen_task(row, replay, tasks, record):
    task = tasks[row['context']]
    source = replay['sourceMountRoot']
    require(task['taskName'] == row['task'] == 'Crossgen'
            and task['projectFile'] == source + '/src/redist/redist.csproj'
            and task['taskFile'] == source + '/src/redist/targets/Crossgen.targets',
            'ReadyToRun must use the actual pinned installer Crossgen task')
    expected = source + '/artifacts/bin/redist/Release/dotnet/' + row['archivePath']
    require(row['inputPath'] == row['outputPath'] == expected
            and task_values(task, 'SourceAssembly') == task_values(task, 'DestinationPath') == {expected}
            and task_values(task, 'ReadyToRun') == {'True'}
            and task_values(task, 'Architecture') == {'arm64' if record['architecture'] == 'aarch64' else 'x64'},
            'Actual installer ReadyToRun input/output/native architecture differs')
    compiler = task_values(task, 'CrossgenPath')
    require(len(compiler) == 1, 'One actual native Crossgen2 compiler path required')
    compiler = next(iter(compiler))
    pattern = re.escape(source) + r'/\.packages(?:/[^/]+)*//?microsoft\.netcore\.app\.crossgen2\.' + re.escape(record['targetRid'])
    require(re.fullmatch(pattern + '/' + re.escape(POLICIES[record['sdkVersion']]['runtime']) + '/tools/crossgen2', compiler),
            'Actual ReadyToRun compiler must be the matching native musl runtime package')
    commands = [shlex.split(event['text'].removeprefix('> ')) for event in task['events'] if event['kind'] == 'command-line']
    require(len(commands) == 1 and commands[0][:2] == [compiler, expected]
            and commands[0].count('-o') == 1 and commands[0].count('--targetarch') == 1
            and commands[0][commands[0].index('--targetarch') + 1] == ('arm64' if record['architecture'] == 'aarch64' else 'x64')
            and PurePosixPath(commands[0][commands[0].index('-o') + 1]).name == PurePosixPath(expected).name,
            'Actual Crossgen2 command does not bind the transformed input/output')


def validate_replay_source_mount(release, replay, name, roots, stages, prepare):
    host = roots[name].get('originalPath')
    require(isinstance(host, str) and host.startswith('/') and host == posixpath.normpath(host), 'Actual source-root host path required')
    matches = []
    for call in stages['build']['commands']:
        if call[:len(P.DOCKER_ENGINE) + 1] != P.DOCKER_ENGINE + ['run'] or (name not in {'nuget', 'vstest'} and './build.sh' not in call):
            continue
        if not any(value in call for value in (prepare['imageId'], prepare['imageId'].removeprefix('sha256:'))):
            continue
        for position, value in enumerate(call):
            if value != '--volume':
                continue
            fields = call[position + 1].split(':')
            if len(fields) not in {2, 3}:
                continue
            source, guest = fields[:2]
            if host != source and not host.startswith(source.rstrip('/') + '/'):
                continue
            mapped = guest.rstrip('/') + host[len(source.rstrip('/')):]
            if mapped == replay['sourceMountRoot']:
                matches.append(call)
    if name == 'sdk':
        require(any(replay['sourceMountRoot'] + '/source-build.slnf' in call and '/p:DotNetBuildFromSource=true' in call
                    and '/p:CrossBuild=false' in call and '/p:PortableBuild=true' in call for call in matches),
                'Actual SDK compiler replay is not bound to the original native source graph/mount')
    elif name == 'installer':
        require(any(replay['sourceMountRoot'] + '/src/redist/redist.csproj' in call
                    and '/p:OSName=linux-musl' in call for call in matches),
                'Actual installer replay is not bound to its original musl redist source/mount')
    elif name == 'vstest':
        matches = [call for call in matches if '/project/scripts/musl-legacy-vstest.py' in call and '--source' in call
                   and call.count('--source') == 1 and call[call.index('--source') + 1] == replay['sourceMountRoot']]
        require(len(matches) == 1, 'Actual VSTest compiler replay is not bound to its exact source worker/mount')
        call = matches[0]
        require(call.count('--dotnet') == 1, 'One exact VSTest private bootstrap compiler is required')
        compiler_root = call[call.index('--dotnet') + 1].removesuffix('/dotnet')
        tasks = read_tasks(checked(release, replay['tasks']))
        require(all(tasks[row['context']]['taskFile'] == compiler_root + '/sdk/7.0.118/Roslyn/Microsoft.CSharp.Core.targets'
                    or row['member'].endswith('.resources.dll') and tasks[row['context']]['taskFile'] ==
                        compiler_root + '/sdk/7.0.118/Sdks/Microsoft.NET.Sdk/targets/Microsoft.NET.Sdk.targets'
                    for row in replay['compiledOutputs']), 'VSTest compilation used an unrelated bootstrap compiler')
    else:
        matches = [call for call in matches if replay['sourceMountRoot'] + '/build/build.proj' in call
                   and '-t:RestoreXPLAT,BuildXPLAT,PackXPLAT' in call and '/p:DotNetBuildFromSource=true' in call]
        require(matches, 'Actual NuGet compiler replay is not bound to the unchanged original complete library matrix')
        compiler_roots = {value.removeprefix('DOTNET_ROOT=') for call in matches for value in call if value.startswith('DOTNET_ROOT=')}
        tasks = read_tasks(checked(release, replay['tasks']))
        require(all(any(tasks[row['context']]['taskFile'] == prefix + '/sdk/7.0.118/Roslyn/Microsoft.CSharp.Core.targets'
                        for prefix in compiler_roots) for row in replay['compiledOutputs']),
                'NuGet compilation used an unrelated private bootstrap compiler')


def validate_layout_member(name, member, artifact, inventory, actual):
    if artifact['kind'] == 'managed-package' and member == '':
        require(name.lower().endswith('.nupkg') and actual['bytes'] == artifact['bytes']
                and actual['sha256'] == artifact['sha256'] and actual['signature'] == '504b0304',
                'Only an unchanged actual restored whole package may use a direct-package layout origin')
    else:
        require(member in inventory and actual == inventory[member], 'Final SDK member lacks unchanged input byte identity')


def validate_generated_task(row, replay, task, sdk_version):
    source = replay['sourceMountRoot']
    expected = source + '/artifacts/bin/redist/Release/dotnet/' + portable(row['archivePath'])
    require(task['succeeded'] is True and task['taskName'] == row['task']
            and task['projectFile'] == source + '/src/redist/redist.csproj'
            and task['taskFile'].startswith(source + '/src/redist/targets/')
            and row['outputPath'] == expected, 'Actual metadata producer task/output path differs')
    fields = {event['field'] for event in task['events'] if event['kind'] == 'task-parameter'}
    fields.update(event['text'].removeprefix('Task Parameter:').split('=', 1)[0] for event in task['events']
                  if event['kind'] == 'message' and isinstance(event['text'], str)
                  and event['text'].startswith('Task Parameter:') and '=' in event['text'] and '\n' not in event['text'])
    require(any(row['outputPath'] in task_values(task, field) for field in fields),
            'Generated metadata output is absent from the actual original task parameters')
    if row['task'] == 'ResolveAssemblyReference':
        require(row['archivePath'] == 'sdk/' + sdk_version + '/SDKPrecomputedAssemblyReferences.cache'
                and task['taskFile'] == source + '/src/redist/targets/GenerateLayout.targets'
                and task_values(task, 'AssemblyInformationCacheOutputPath') == {expected},
                'Only the pinned installer assembly-reference cache generator is reviewed')


def validate_artifact_source(artifact, roots):
    require(artifact['sourceRoot'] in roots, 'Construction source root is absent')
    root = roots[artifact['sourceRoot']]
    if artifact['kind'] == MANIFEST_INPUTS.KIND:
        require(artifact['sourceRoot'] == MANIFEST_INPUTS.ROOT_NAME and artifact['sourceCommit'] is None
                and root.get('kind') == 'tree' and root.get('role') == MANIFEST_INPUTS.ROLE and root.get('commit') is None,
                'Only reviewed literal workload source may use a non-Git construction source')
    else:
        require(root.get('kind') in {'git', 'git-export'} and re.fullmatch('[a-f0-9]{40}', artifact.get('sourceCommit') or '')
                and artifact['sourceCommit'] == root.get('commit'), 'Legacy construction input source identity differs')


def checked_restored_primary(release, restored_packages, expected):
    require(isinstance(restored_packages, list), 'Actual restored package inventory required')
    matches = [row for row in restored_packages if isinstance(row, dict) and row.get('sha256') == expected['sha256']]
    require(len(matches) == 1 and all(matches[0].get(key) == expected[key] for key in FP),
            'One unique exact actual restored component package is required: ' + expected['sha256'])
    relative = portable(matches[0].get('retained'))
    return checked(release, dict(path=relative, **{key: expected[key] for key in FP})), relative


def validate_reviewed_shipping_inputs(release, source_manifest, restored_packages):
    """Validate the four closed source leaves independently of byte-layout origins."""
    roots = {root['name']: root for root in source_manifest['roots']}
    reviewed, paths = {}, {}
    for expected, validate in ((NETSTANDARD21, validate_netstandard_source_chain),
            (CSS_PARSER, validate_css_source_chain), (MSBUILD_RESOURCES.PACKAGE, MSBUILD_RESOURCES.validate),
            (GLOBBING_INPUTS.policy()['package'], GLOBBING_INPUTS.validate)):
        package, relative = checked_restored_primary(release, restored_packages, expected)
        source = validate(release, source_manifest, package)
        require(source['sourceRoot'] in roots and roots[source['sourceRoot']].get('kind') in {'git', 'git-export'}
                and roots[source['sourceRoot']].get('commit') == source['sourceCommit'],
                'Reviewed primary input lacks its independently validated original source membership: ' + expected['sha256'])
        reviewed[expected['sha256']], paths[expected['sha256']] = source, relative
    return reviewed, paths


def validate_reviewed_shipping_bindings(release, source_manifest, reviewed, paths, shipping, actual,
                                       local_vstest=None, transformed=None, artifacts=None):
    """Bind copies after the caller validates every original Crossgen task and input/output."""
    roots = {root['name']: root for root in source_manifest['roots']}
    globbing_package = GLOBBING_INPUTS.policy()['package']
    expected_inputs = (NETSTANDARD21, CSS_PARSER, MSBUILD_RESOURCES.PACKAGE, globbing_package)
    require(set(reviewed) == set(paths) == {row['sha256'] for row in expected_inputs}, 'Complete reviewed primary source set required')
    for expected in expected_inputs:
        source, relative = reviewed[expected['sha256']], paths[expected['sha256']]
        package = checked(release, dict(path=relative, **{key: expected[key] for key in FP}))
        inventory = members(package, 'managed-package')
        for name in source.get('allowedLayoutPaths', []):
            rows = [row for row in shipping if row.get('path') == name]
            require(len(rows) == 1, 'Every reviewed primary product needs one unique shipping declaration: ' + name)
            row = rows[0]
            if expected['sha256'] == globbing_package['sha256'] and row.get('packagePath') != relative:
                # The genuine VSTest source distribution retains this dependency
                # unchanged. Its copy origin remains that actual distribution;
                # the original 1.1.1 package independently binds preferred source.
                imported = (local_vstest or {}).get('importedMembers', {}).get((row.get('packagePath'), row.get('packageMember')))
                package_fp = (local_vstest or {}).get('packagePaths', {}).get(row.get('packagePath'))
                expected = source['products'][name]; target = (transformed or {}).get(name)
                require(imported is not None and package_fp is not None and row.get('origin') == 'imported-package'
                        and row.get('sourceRoot') == 'vstest' and row.get('sourceCommit') == VSTEST7_COMMIT
                        and 'vstest' in roots and roots['vstest'].get('kind') in {'git', 'git-export'}
                        and roots['vstest'].get('commit') == VSTEST7_COMMIT
                        and row.get('componentSource') == dict(sourceRoot=source['sourceRoot'], sourceCommit=source['sourceCommit'],
                                                               basis='assembly-metadata-commit-hash')
                        and imported['sourceCommit'] == source['sourceCommit'] and name in actual
                        and all(imported[key] == expected[key] for key in ('bytes', 'sha256'))
                        and (target is None and all(actual[name][key] == expected[key] for key in ('bytes', 'sha256'))
                             or target is not None and target.get('archivePath') == name and target.get('task') == 'Crossgen'
                             and isinstance(target.get('context'), str) and target['context']
                             and target.get('inputSha256') == expected['sha256']
                             and target.get('outputSha256') == actual[name]['sha256']),
                        'Globbing must preserve its exact validated genuine VSTest copy origin and separate preferred source: ' + name)
                genuine = checked(release, dict(path=portable(row['packagePath']), **package_fp))
                with zipfile.ZipFile(genuine) as archive:
                    require(archive.getinfo(row['packageMember']).file_size == expected['bytes']
                            and ATTRIBUTED_COMPONENTS.fingerprint(archive.read(row['packageMember'])) == expected,
                            'Globbing genuine VSTest member must retain its full original fingerprint: ' + name)
                if target is not None:
                    require(target.get('input') in (artifacts or {}) and artifacts[target['input']]['kind'] == 'sdk-toolset',
                            'Globbing R2R input must be an actual validated toolset: ' + name)
                    artifact = artifacts[target['input']]
                    package_input = checked(release, {key:artifact[key] for key in FP | {'path'}})
                    with zipfile.ZipFile(package_input) as archive:
                        require(target['member'] in archive.namelist() and archive.getinfo(target['member']).file_size == expected['bytes']
                                and ATTRIBUTED_COMPONENTS.fingerprint(archive.read(target['member'])) == expected,
                                'Globbing R2R input must retain its full original fingerprint: ' + name)
                continue
            target = (transformed or {}).get(name)
            require(row.get('origin') == 'imported-package' and row.get('packagePath') == relative
                    and row.get('packageMember') in inventory and name in actual
                    and inventory[row['packageMember']]['sha256'] == (target['inputSha256'] if target else actual[name]['sha256'])
                    and (target is None and inventory[row['packageMember']]['bytes'] == actual[name]['bytes']
                         or target is not None and target.get('task') == 'Crossgen' and target.get('archivePath') == name
                         and target.get('outputSha256') == actual[name]['sha256'])
                    and row.get('sourceRoot') == source['sourceRoot'] and row.get('sourceCommit') == source['sourceCommit'],
                    'Reviewed primary product source/package/member differs from its unchanged actual shipping bytes or validated R2R input/output: '
                    + expected['sha256'] + '/' + name + '/' + str(row.get('packageMember')))


def validate_attributed_inputs(release, source_manifest, restored_packages, shipping):
    """Bind closed component source evidence to actual restored shipping inputs.

    A toolset can distribute these bytes without the original packages being
    separate layout artifacts. Their primary package provenance is retained
    independently in restored inputs and each managed shipping declaration.
    """
    policy = ATTRIBUTED_COMPONENTS.policy()
    packages, paths = {}, {}
    selected = ATTRIBUTED_COMPONENTS.selected_packages(row.get('sha256') for row in restored_packages)
    for sha in selected.values():
        expected = ATTRIBUTED_COMPONENTS.package_policy(sha)
        packages[sha], paths[sha] = checked_restored_primary(release, restored_packages, expected)
    validated = ATTRIBUTED_COMPONENTS.validate(release, source_manifest, packages)
    require(validated.get('kind') == ATTRIBUTED_COMPONENTS.KIND
            and set(validated.get('products', {})) == set(policy['products']),
            'Complete independently validated component product set required')
    roots = {root['name']: root for root in source_manifest['roots']}
    for name, product in validated['products'].items():
        rows = [row for row in shipping if row.get('path') == name]
        require(len(rows) == 1, 'Every closed component needs one unique actual shipping declaration')
        row = rows[0]
        require(row.get('origin') == 'imported-package'
                and row.get('packagePath') == paths[product['packageSha256']]
                and row.get('packageMember') == product['packageMember'],
                'Closed components must consume their exact canonical restored primary package/member')
        source = {key: product[key] for key in ('sourceRoot', 'sourceCommit', 'basis')}
        require(row.get('componentSource') == source and source['sourceRoot'] in roots
                and roots[source['sourceRoot']].get('kind') in {'git', 'git-export'}
                and roots[source['sourceRoot']].get('commit') == source['sourceCommit']
                and row.get('sourceRoot') in roots
                and roots[row['sourceRoot']].get('kind') in {'git', 'git-export'}
                and roots[row['sourceRoot']].get('commit') == row.get('sourceCommit'),
                'Closed component source membership differs from independently validated original sources')
    return validated


def validate_attributed_products_after_crossgen(release, attributed_policy, actual, transformed, artifacts):
    """Retain all original source fingerprints through an already validated R2R map."""
    declared = ATTRIBUTED_COMPONENTS.policy()['products']
    require(attributed_policy.get('kind') == ATTRIBUTED_COMPONENTS.KIND
            and set(attributed_policy.get('products', {})) == set(declared), 'All eight closed original component products required')
    for name, product in attributed_policy['products'].items():
        expected = product['fingerprint']; target = transformed.get(name)
        require(expected == declared[name]['fingerprint'] and name in actual,
                'Original component source fingerprint/product differs: ' + name)
        if target is None:
            require(all(actual[name][key] == expected[key] for key in ('bytes', 'sha256')),
                    'Untransformed original component product bytes differ: ' + name)
            continue
        require(target.get('archivePath') == name and target.get('task') == 'Crossgen'
                and isinstance(target.get('context'), str) and target['context']
                and target.get('input') in artifacts and artifacts[target['input']]['kind'] == 'sdk-toolset'
                and target.get('inputSha256') == expected['sha256']
                and target.get('outputSha256') == actual[name]['sha256'],
                'Original component source input or validated R2R output/context differs: ' + name)
        artifact = artifacts[target['input']]
        package = checked(release, {key: artifact[key] for key in FP | {'path'}})
        with zipfile.ZipFile(package) as archive:
            require(target['member'] in archive.namelist() and archive.getinfo(target['member']).file_size == expected['bytes'],
                    'Original component R2R input member/size differs: ' + name)
            raw = archive.read(target['member'])
        require(ATTRIBUTED_COMPONENTS.fingerprint(raw) == expected,
                'Original component R2R input must retain its complete canonical fingerprint: ' + name)


def validate_construction(release, record, source_manifest, stages=None, prepare=None):
    proof = load(release / 'reports/legacy-construction.json')
    require(set(proof) == {'schemaVersion', 'kind', 'sdkVersion', 'architecture', 'targetRid', 'artifacts',
                          'layout', 'sdkBuildReplay', 'installerBuildReplay', 'nugetBuildReplay', 'vstestBuildReplay', 'managedShipping', 'unknowns'}
            and proof['schemaVersion'] == 1 and proof['kind'] == 'legacy-musl-construction-proof'
            and all(proof[key] == record[key] for key in ('sdkVersion', 'architecture', 'targetRid'))
            and proof['unknowns'] == [], 'Closed reviewed legacy construction proof required')
    policy = POLICIES[record['sdkVersion']]
    roots = {root['name']: root for root in source_manifest['roots']}
    for name, commit in [('installer', policy['installer']), ('sdk', policy['sdk']),
                         ('runtime', policy['runtimeCommit']), ('aspnetcore', policy['aspnetcore']), ('nuget', policy['nuget']),
                         ('vstest', VSTEST7_COMMIT)]:
        require(name in roots and roots[name].get('kind') == 'git' and roots[name].get('commit') == commit,
                'Complete pinned legacy source root is absent: ' + name)
    local_nuget = validate_nuget_build(release, record, proof['nugetBuildReplay'], roots, stages, prepare)
    local_vstest = validate_vstest_build(release, record, proof['vstestBuildReplay'], roots, stages, prepare)
    validate_vstest_source_contract(release, source_manifest, local_vstest)
    actual = members(release / record['sdk']['name'], 'sdk')
    artifacts, inventories, manifest_inputs = proof['artifacts'], {}, {}
    restored_packages = load(release / 'reports/restored-inputs.json')['packages']
    require(isinstance(artifacts, dict) and 4 <= len(artifacts) <= 10000, 'Bounded complete construction inputs required')
    attributed_policy = validate_attributed_inputs(release, source_manifest, restored_packages, proof['managedShipping'])
    reviewed_sources, reviewed_paths = validate_reviewed_shipping_inputs(
        release, source_manifest, restored_packages)
    for name, artifact in artifacts.items():
        require(re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9._-]*', name)
                and set(artifact) == FP | {'path', 'kind', 'sourceRoot', 'sourceCommit'}
                and artifact['kind'] in KINDS,
                'Legacy construction input source identity differs')
        validate_artifact_source(artifact, roots)
        path = checked(release, {key: artifact[key] for key in FP | {'path'}})
        inventories[name] = members(path, artifact['kind'])
        if artifact['kind'] in {'managed-package', MANIFEST_INPUTS.KIND}:
            require(any(all(row.get(key) == artifact[key] for key in FP) for row in restored_packages),
                    'A package layout input was not actually restored and retained')
        if artifact['kind'] == MANIFEST_INPUTS.KIND:
            manifest_inputs[name] = MANIFEST_INPUTS.validate_artifact(release, artifact)
        elif artifact['kind'] == 'managed-package':
            if artifact['sha256'] in reviewed_sources:
                require(artifact['path'] == reviewed_paths[artifact['sha256']]
                        and artifact['sourceRoot'] == reviewed_sources[artifact['sha256']]['sourceRoot'],
                        'Reviewed layout input must name its actual canonical primary package and original source root')
            package_metadata(path, artifact['sourceCommit'], local_nuget, reviewed_sources, attributed_policy=attributed_policy)
    require(len(manifest_inputs) == 8 and {row['key'] for row in manifest_inputs.values()} == {row['key'] for row in MANIFEST_INPUTS.policy()},
            'All eight reviewed original readable workload manifest inputs are required')
    MANIFEST_INPUTS.validate_sources(release, source_manifest)
    facade_primary = FACADE_INPUTS.policy()['package']['fingerprint']
    facade_paths = {portable(row['retained']) for row in restored_packages
                    if all(row.get(key) == facade_primary[key] for key in FP)}
    require(len(facade_paths) == 1, 'The exact original facade primary input must be actually restored and retained')
    facade_path = facade_paths.pop()
    facade_policy = FACADE_INPUTS.validate(release, source_manifest,
        checked(release, dict(path=facade_path, **facade_primary)))
    framework_policy = FRAMEWORK_IL_INPUTS.validate(release, source_manifest,
        checked(release, dict(path=facade_path, **facade_primary)))
    for kind in ('sdk-toolset', 'official-runtime', 'official-aspnet', 'native-trace', 'official-sdk-comparison'):
        require(sum(item['kind'] == kind for item in artifacts.values()) == 1, 'One exact legacy component required: ' + kind)
    require(sum(item['kind'] == 'native-coreclr' for item in artifacts.values()) == len(NATIVE_CORECLR),
            'Exactly four matching source-built CoreCLR/JIT/debugger products are required')
    expected_sources = {'sdk-toolset': 'sdk', 'post-crossgen-sdk': 'installer', 'generated-installer-data': 'installer', 'official-runtime': 'runtime',
                        'official-aspnet': 'aspnetcore', 'native-trace': 'runtime', 'native-coreclr': 'runtime', 'nuget-translation-data': 'nuget',
                        'official-sdk-comparison': 'installer'}
    require(all(item['sourceRoot'] == expected_sources[item['kind']] for item in artifacts.values()
                if item['kind'] in expected_sources), 'Legacy component construction role differs')
    layout, literal_layout = {}, set()
    for row in proof['layout']:
        require(set(row) == {'path', 'input', 'member'}, 'Closed legacy layout row required')
        name = portable(row['path'])
        require(name in actual and name not in layout and row['input'] in artifacts
                and artifacts[row['input']]['kind'] != 'official-sdk-comparison', 'Final SDK member lacks an admitted input')
        artifact = artifacts[row['input']]
        if artifact['kind'] == MANIFEST_INPUTS.KIND:
            allowed = {entry['path']: entry['member'] for entry in manifest_inputs[row['input']]['layout']}
            require(allowed.get(name) == row['member'] and name in allowed,
                    'Readable workload input may supply only its reviewed literal JSON/XML layout members')
            literal_layout.add(name)
        validate_layout_member(name, row['member'], artifact, inventories[row['input']], actual[name])
        if artifact['sha256'] in reviewed_sources:
            source = reviewed_sources[artifact['sha256']]
            require(name.startswith(source['allowedLayoutPrefix']) if 'allowedLayoutPrefix' in source else name in source['allowedLayoutPaths'],
                    'Reviewed source-chain package escaped its exact permitted layout scope')
        layout[name] = row
    require(set(layout) == set(actual), 'Every actual legacy SDK file must have a construction origin')
    require(literal_layout == {entry['path'] for row in manifest_inputs.values() for entry in row['layout']},
            'Every reviewed literal workload JSON/XML source must be consumed unchanged')
    msbuild = reviewed_sources.get(MSBUILD_RESOURCES.PACKAGE['sha256'])
    require(msbuild is not None and all(name in actual and all(actual[name][key] == value[key] for key in ('bytes', 'sha256'))
                for name, value in msbuild['products'].items()),
            'All 52 actual original XLF-bound MSBuild resource-only satellites must be consumed unchanged')
    main_facades = {name: value for name, value in facade_policy['products'].items()
                    if name.startswith('sdk/7.0.120/Microsoft/Microsoft.NET.Build.Extensions/')}
    require(len(main_facades) == 87 and all(name in actual and all(actual[name][key] == value[key] for key in ('bytes', 'sha256'))
                for name, value in main_facades.items()),
            'All 87 original cross-target type-forwarding metadata products must remain unchanged')
    require(len(framework_policy['products']) == 27 and all(name in actual and all(actual[name][key] == value[key]
                for key in ('bytes', 'sha256')) for name, value in framework_policy['products'].items()),
            'All 27 original cross-target implementations require complete preferred IL and exact unchanged product bytes')
    require(len(attributed_policy['products']) == 8 and all(name in actual for name in attributed_policy['products']),
            'All eight closed imported component products must remain present')
    comparison = next(row for row in artifacts.values() if row['kind'] == 'official-sdk-comparison')
    require(comparison['path'] == 'reports/construction-inputs/original-sdk-comparison.tar.gz'
            and comparison['sha512'] == SDK7_COMPARISON_SHA512[record['architecture']],
            'Exactly authenticated original SDK comparison-only input required')
    runtime_prefix = 'shared/Microsoft.NETCore.App/' + policy['runtime'] + '/'
    aspnet_prefix = 'shared/Microsoft.AspNetCore.App/' + policy['runtime'] + '/'
    trace = runtime_prefix + 'libcoreclrtraceptprovider.so'
    require(trace in layout and artifacts[layout[trace]['input']]['kind'] == 'native-trace', 'Locally rebuilt trace provider was not consumed')
    native_paths = {runtime_prefix + name for name in NATIVE_CORECLR}
    require(all(name in layout and artifacts[layout[name]['input']]['kind'] == 'native-coreclr'
                and layout[name]['member'] == '' for name in native_paths)
            and {name for name, row in layout.items() if artifacts[row['input']]['kind'] == 'native-coreclr'} == native_paths,
            'Source-built native products may replace only their four exact matching runtime members')
    for kind, prefix in [('official-runtime', runtime_prefix), ('official-aspnet', aspnet_prefix)]:
        name = next(name for name, item in artifacts.items() if item['kind'] == kind)
        validate_official_framework(artifacts[name], record)
        expected = {p: value for p, value in inventories[name].items() if p.startswith(prefix) and p not in native_paths | {trace}}
        present = {p: value for p, value in actual.items() if p.startswith(prefix) and p not in native_paths | {trace}}
        require(len(expected) >= 50 and present == expected, 'Complete imported legacy shared framework bytes differ')
        component_source = policy['runtimeCommit'] if kind == 'official-runtime' else policy['aspnetcore']
        require(tar_text(release / artifacts[name]['path'], prefix + '.version') == [component_source, policy['runtime']],
                'Official legacy framework archive source/version marker differs')
    require(all(name.startswith((runtime_prefix, aspnet_prefix)) for name in actual if name.startswith('shared/')),
            'An unrelated bootstrap/shared framework leaked into the final SDK')
    runtime_name = next(name for name, item in artifacts.items() if item['kind'] == 'official-runtime')
    host_prefix = 'host/fxr/' + policy['runtime'] + '/'
    hosts = {name: value for name, value in inventories[runtime_name].items() if name == 'dotnet' or name.startswith(host_prefix)}
    require('dotnet' in hosts and any(name.endswith('/libhostfxr.so') for name in hosts)
            and all(actual.get(name) == value for name, value in hosts.items())
            and all(name.startswith(host_prefix) for name in actual if name.startswith('host/fxr/')),
            'Exact matching official native host/fxr bytes required')
    sdk_prefix = 'sdk/' + record['sdkVersion'] + '/'
    require(all(artifacts[row['input']]['kind'] in {'sdk-toolset', 'post-crossgen-sdk', 'nuget-translation-data',
                                                  'managed-package', 'generated-installer-data'}
                for name, row in layout.items() if name.startswith(sdk_prefix)), 'SDK CLI layout must consume its local source-produced toolset')
    built = validate_replay(release, proof['sdkBuildReplay'], 'reports/build/sdk.binlog', compiled=True)
    installed = validate_replay(release, proof['installerBuildReplay'], 'reports/build/installer.binlog', compiled=False)
    if stages is not None:
        validate_replay_source_mount(release, built, 'sdk', roots, stages, prepare)
        validate_replay_source_mount(release, installed, 'installer', roots, stages, prepare)
    COMPILER_INPUTS.validate(release, source_manifest, dict(sdk=built, nuget=local_nuget['replay'], vstest=local_vstest['replay']))
    toolsets = [name for name, item in artifacts.items() if item['kind'] == 'sdk-toolset']
    compiled = {}
    for row in built['compiledOutputs']:
        require(set(row) == {'archivePath', 'member', 'sha256', 'sourceRoot', 'sourceCommit', 'context', 'outputPath'}
                and row['sourceRoot'] == 'sdk' and row['sourceCommit'] == policy['sdk']
                and row['member'] in inventories[toolsets[0]]
                and inventories[toolsets[0]][row['member']]['sha256'] == row['sha256']
                and row['archivePath'].startswith(sdk_prefix) and row['archivePath'] not in compiled
                and row['outputPath'].startswith(built['sourceMountRoot'] + '/artifacts/')
                and PurePosixPath(row['outputPath']).name == PurePosixPath(row['archivePath']).name,
                'Rebuilt SDK output lacks original compiler/toolset provenance')
        compiled[row['archivePath']] = row['sha256']
    require(BUILT_ASSEMBLIES <= {PurePosixPath(name).name for name in compiled}, 'Complete CLI/tasks/resolver compilation evidence required')
    transformed = {}
    installed_tasks = read_tasks(checked(release, installed['tasks']))
    for row in installed['transformations']:
        require(set(row) == {'archivePath', 'input', 'member', 'inputSha256', 'outputSha256', 'task', 'context', 'inputPath', 'outputPath'}
                and row['task'] == 'Crossgen'
                and row['input'] in artifacts and artifacts[row['input']]['kind'] == 'sdk-toolset'
                and row['member'] in inventories[row['input']]
                and inventories[row['input']][row['member']]['sha256'] == row['inputSha256']
                and row['archivePath'] in actual and actual[row['archivePath']]['sha256'] == row['outputSha256']
                and row['archivePath'] not in transformed, 'ReadyToRun transformation provenance differs')
        validate_crossgen_task(row, installed, installed_tasks, record)
        transformed[row['archivePath']] = row
    for name, sha in compiled.items():
        require(name in actual and (actual[name]['sha256'] == sha or name in transformed
                and transformed[name]['inputSha256'] == sha), 'Compiled CLI output was not consumed by the final SDK')
    original_hashes = {row['sha256'] for row in inventories[toolsets[0]].values()}
    require(all(actual[name]['sha256'] in original_hashes or name in transformed
                for name, row in layout.items() if artifacts[row['input']]['kind'] == 'post-crossgen-sdk'),
            'A post-Crossgen layout file lacks unchanged-toolset or actual transformation provenance')
    generated = {}
    for row in installed.get('generatedOutputs', []):
        require(set(row) == {'archivePath', 'sha256', 'task', 'sourceRoot', 'sourceCommit', 'context', 'outputPath'}
                and row['archivePath'] in actual and row['archivePath'] not in generated
                and row['sourceRoot'] == 'installer' and row['sourceCommit'] == policy['installer']
                and row['task'] in {'WriteLinesToFile', 'GenerateBundledVersions', 'GenerateRuntimeGraph',
                                    'GenerateDepsFile', 'GenerateRuntimeConfigurationFiles', 'GenerateSdkRuntimeIdentifierChain',
                                    'CalculateTemplateVersions', 'CollatePackageDownloads', 'UpdateRuntimeConfig',
                                    'GenerateDefaultRuntimeFrameworkVersion', 'GetDependencyInfo', 'ReplaceFileContents',
                                    'ResolveAssemblyReference'}
                and actual[row['archivePath']]['sha256'] == row['sha256']
                and not row['archivePath'].lower().endswith(('.dll', '.exe', '.nupkg'))
                and not actual[row['archivePath']]['signature'].startswith(('4d5a', '7f454c46', '504b0304')),
                'Installer-generated metadata lacks actual original task/output provenance')
        task = installed_tasks[row['context']]
        validate_generated_task(row, installed, task, record['sdkVersion'])
        generated[row['archivePath']] = row
    require(all(name in generated for name, row in layout.items()
                if artifacts[row['input']]['kind'] == 'generated-installer-data'),
            'Generated layout metadata has no actual installer producer event')
    validate_reviewed_shipping_bindings(release, source_manifest, reviewed_sources, reviewed_paths,
                                       proof['managedShipping'], actual, local_vstest, transformed, artifacts)
    validate_attributed_products_after_crossgen(release, attributed_policy, actual, transformed, artifacts)
    validate_trace(release, artifacts, policy, record, source_manifest)
    validate_native_runtime(release, artifacts, policy, record, source_manifest, stages, prepare)
    validate_shipping_declarations(release, source_manifest, roots)
    if any(row.get('path') in {sdk_prefix + 'TestHostNetFramework/NuGet.Frameworks.dll', sdk_prefix + 'TestHost/NuGet.Frameworks.dll'}
           for row in proof['managedShipping']):
        validate_testhost_nuget_source(release, source_manifest)
    translation_products = (validate_translation_data(release, record, source_manifest)
                            if any(item['kind'] == 'nuget-translation-data' for item in artifacts.values()) else {})
    validate_managed_shipping(release, proof['managedShipping'], actual, compiled, transformed, roots, record,
                              translation_products=translation_products, local_nuget=local_nuget, reviewed_sources=reviewed_sources,
                              facade_policy=facade_policy, local_vstest=local_vstest, framework_policy=framework_policy,
                              attributed_policy=attributed_policy)
    return proof


def validate_official_framework(artifact, record):
    require(record['sdkVersion'] == '7.0.120'
            and artifact['sha512'] == SDK7_FRAMEWORK_SHA512[(artifact['kind'], record['architecture'])],
            'Imported framework is not the exact independently reviewed official native archive')


def validate_trace(release, artifacts, policy, record, source_manifest):
    artifact = next(item for item in artifacts.values() if item['kind'] == 'native-trace')
    directory = release / 'reports/build/native-trace'
    identity = load(directory / 'identity.json')
    require(identity.get('sdkVersion') == record['sdkVersion'] and identity.get('architecture') == record['architecture']
            and identity.get('component') == 'trace' and identity.get('sourceCommit') == policy['runtimeCommit'],
            'Own-version native trace source identity differs')
    results = load(directory / 'results.json')
    library = results.get('library', {})
    require(results.get('status') == 'passed' and library.get('path') == 'libcoreclrtraceptprovider.so'
            and all(library.get(key) == artifact[key] for key in ('bytes', 'sha256')),
            'Actual rebuilt native trace bytes differ')
    commands = results.get('commands', [])
    require(commands and all(item.get('exitCode') == 0 for item in commands)
            and any(any(str(arg).endswith('/genLttngProvider.py') for arg in item['command']) for item in commands)
            and any('-shared' in item['command'] and '-llttng-ust' in item['command']
                    and any(str(arg).endswith('.cpp') for arg in item['command']) for item in commands),
            'Actual original trace generation and native source compilation required')
    generators = [item['command'] for item in commands if any(str(arg).endswith('/genLttngProvider.py') for arg in item['command'])]
    compilers = [item['command'] for item in commands if '-shared' in item['command'] and '-llttng-ust' in item['command']]
    require(len(generators) == len(compilers) == 1 and generators[0][0] == 'python3'
            and len(generators[0]) == 6 and generators[0][2] == '--man' and generators[0][4] == '--intermediate',
            'One exact original runtime trace generator invocation required')
    generator = generators[0]
    runtime_source = generator[1].removesuffix('/src/coreclr/scripts/genLttngProvider.py')
    require(generator[1] == runtime_source + '/src/coreclr/scripts/genLttngProvider.py'
            and generator[3] == runtime_source + '/src/coreclr/vm/ClrEtwAll.man', 'Trace generator uses unrelated source inputs')
    cpu = 'ARM64' if record['architecture'] == 'aarch64' else 'AMD64'
    compiler = compilers[0]
    require(compiler[0] == 'clang++' and {'-fPIC', '-O2', '-DTARGET_' + cpu + '=1', '-DHOST_' + cpu + '=1'} <= set(compiler)
            and compiler.count('-o') == 1 and compiler[compiler.index('-o') + 1] == generator[5].removesuffix('/generated') + '/libcoreclrtraceptprovider.so',
            'Trace compiler/native target/output differs from actual generator inputs')
    generated = directory / 'generated'
    actual = {path.relative_to(generated).as_posix(): fingerprint(path) for path in generated.rglob('*') if path.is_file()}
    indexed = {}
    with (release / 'sources' / source_manifest['index']['path']).open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'].startswith('native-trace-generated/'):
                indexed[row['path'].removeprefix('native-trace-generated/')] = {key: row[key] for key in FP}
    roots = [root for root in source_manifest['roots'] if root['name'] == 'native-trace-generated']
    sources = [value.removeprefix(generator[5] + '/') for value in compiler if value.endswith('.cpp')]
    require(len(roots) == 1 and roots[0].get('kind') == 'tree' and actual and actual == indexed
            and len(sources) == 5 and len(set(sources)) == 5 and all(name in actual for name in sources)
            and set(sources) == {name for name in actual if PurePosixPath(name).name.startswith('traceptprov') and name.endswith('.cpp')},
            'Every actual generated trace C++/header source must be retained with unchanged bytes')
    for item in commands:
        require(set(item) == {'command', 'exitCode', 'log', 'bytes', 'sha256'}
                and PurePosixPath(portable(item['log'])).name == item['log']
                and all(item[key] == fingerprint(directory / item['log'])[key] for key in ('bytes', 'sha256')),
                'Native trace compilation log bytes differ')
    loaded = load(directory / 'native-load.json')
    require(loaded.get('loaded') is True and all(loaded.get(key) == artifact[key] for key in ('bytes', 'sha256')),
            'Rebuilt native trace must actually load on the stock system')


def reverse_reviewed_patch(actual, patch, relative):
    """Recover a Git baseline from an exact reviewed unified patch, without git."""
    lines, diff = actual.decode('utf-8').splitlines(True), patch.decode('utf-8').splitlines(True)
    headers = [index for index, line in enumerate(diff) if line == '--- a/' + relative + '\n']
    require(len(headers) == 1 and sum(line.startswith('--- a/') for line in diff) == 1
            and diff[headers[0] + 1] == '+++ b/' + relative + '\n', 'Reviewed native patch target differs')
    position, previous, result, hunks = headers[0] + 2, 0, [], 0
    while position < len(diff):
        match = re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n', diff[position])
        require(match is not None, 'Malformed reviewed native patch hunk')
        old_start, old_count, new_start, new_count = [int(value or '1') for value in match.groups()]
        start = new_start - 1
        require(start >= previous and old_start - 1 == len(result) + start - previous,
                'Reviewed native patch hunk coordinates differ')
        result.extend(lines[previous:start])
        position += 1
        old, new = [], []
        while position < len(diff) and not diff[position].startswith('@@ '):
            line = diff[position]
            require(line and line[0] in ' +-', 'Unknown reviewed native patch body')
            if line[0] in ' -': old.append(line[1:])
            if line[0] in ' +': new.append(line[1:])
            position += 1
        require(len(old) == old_count and len(new) == new_count and lines[start:start + new_count] == new,
                'Actual native source differs from the exact reviewed patch result')
        result.extend(old)
        previous = start + new_count
        hunks += 1
    require(hunks > 0, 'Reviewed native patch has no hunks')
    result.extend(lines[previous:])
    return ''.join(result).encode('utf-8')


def native_command_records(directory, results):
    rows, selected, previous = results.get('commands'), {}, None
    require(isinstance(rows, list) and 1 <= len(rows) <= 32, 'Bounded actual native command records required')
    for row in rows:
        require(set(row) == FP | {'name', 'command', 'startedAt', 'completedAt', 'exitCode', 'log'}
                and re.fullmatch('[a-zA-Z0-9][a-zA-Z0-9._-]*', row.get('name', ''))
                and row['name'] not in selected and row['exitCode'] == 0
                and row['log'] == row['name'] + '.log'
                and isinstance(row['command'], list) and row['command']
                and all(isinstance(arg, str) and not any(c in arg for c in '\0\r\n') for arg in row['command']),
                'Actual native command identity or successful completion differs')
        started, finished = [dt.datetime.fromisoformat(row[key]) for key in ('startedAt', 'completedAt')]
        require(started.tzinfo is not None and finished.tzinfo is not None and finished >= started
                and (previous is None or started >= previous), 'Actual native command chronology differs')
        previous = finished
        log = checked(directory, {key: row[key] for key in FP} | {'path': row['log']})
        require(load(directory / (row['name'] + '-command.json')) == row,
                'Actual native command sidecar differs from the original command record')
        selected[row['name']] = dict(row, text=log.read_text())
    return selected


def validate_native_runtime(release, artifacts, policy, record, source_manifest, stages=None, prepare=None):
    directory = release / 'reports/build/native-runtime'
    results = load(directory / 'results.json')
    targets = ['coreclr', 'clrjit', 'mscordaccore', 'mscordbi', 'coreclrtraceptprovider']
    require(results.get('schemaVersion') == 1 and results.get('kind') == 'legacy-musl-native-runtime-build'
            and results.get('status') == 'passed' and results.get('sdkVersion') == record['sdkVersion']
            and results.get('runtimeVersion') == policy['runtime'] and results.get('architecture') == record['architecture']
            and results.get('sourceCommit') == policy['runtimeCommit'] and results.get('configuration') == 'Release'
            and results.get('targets') == targets
            and results.get('upstreamMetadataBackport') == '35a39e97345abfda05e14f609759760b37ddeb4d'
            and results.get('traceProviderBuiltButImportedFromSeparateMatchingSourceWorker') is True
            and results.get('productVersionMetadataQualified') is True
            and all(results.get(key) is False for key in ('tracingDisabled', 'readyToRunDisabled', 'optimizationDisabled',
                                                        'qualificationAllowed', 'sourceAdmissionAllowed')),
            'Matching optimized source-built CoreCLR/JIT/debugger identity required')
    patches = results.get('sourcePatches', [])
    require(len(patches) == len(NATIVE_CORECLR_PATCHES) and all(set(row) == FP | {'path'} for row in patches)
            and [row['path'] for row in patches] == list(NATIVE_CORECLR_PATCHES)
            and all(row['sha256'] == NATIVE_CORECLR_PATCHES[row['path']][0]
                    and {key: row[key] for key in FP} == fingerprint(ROOT / row['path']) for row in patches),
            'Exactly the two reviewed native runtime source patches are required')
    commands = native_command_records(directory, results)
    require(all(row['text'].splitlines() and row['text'].splitlines()[0] == json.dumps(row['command'])
                for row in commands.values()), 'Original native log command header differs from its command record')
    expected_names = {'patch-check-0', 'patch-apply-0', 'patch-check-1', 'patch-apply-1', 'native-version',
                      'configure', 'build', 'compiler-version', 'cmake-version'} | {'elf-' + name for name in NATIVE_CORECLR}
    require(set(commands) == expected_names, 'Native source build omitted or added a construction command')
    configure = commands['configure']['command']
    suffix = '/src/coreclr/build-runtime.sh'
    require(configure[0].endswith(suffix), 'Original native runtime source build entry point required')
    source = configure[0].removesuffix(suffix)
    require(source.startswith('/') and source == posixpath.normpath(source) and not any(c in source for c in '\\\0\r\n'),
            'Exact native runtime source mount required')
    cpu = 'arm64' if record['architecture'] == 'aarch64' else 'x64'
    obj = source + '/artifacts/obj/coreclr/Linux.' + cpu + '.Release'
    require(configure == [source + suffix, '-' + cpu, '-release', '-component', 'runtime', '-component', 'jit',
                         '-numproc', '2', '-cmakeargs', '-DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DLIBGSS=/usr/lib/libgssapi_krb5.so.2 '
                         '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-configureonly']
            and '-- Generating done' in commands['configure']['text'] and 'CMake Error' not in commands['configure']['text']
            and commands['build']['command'] == ['cmake', '--build', obj, '--target', *targets, '--parallel', '2', '--verbose'],
            'Original optimized native CMake generation and complete target build required')
    for index, path in enumerate(NATIVE_CORECLR_PATCHES):
        prefix = ['git', '-c', 'safe.directory=' + source, '-C', source, 'apply']
        require(commands['patch-check-' + str(index)]['command'] == prefix + ['--check', '/project/' + path]
                and commands['patch-apply-' + str(index)]['command'] == prefix + ['/project/' + path],
                'Native runtime applied an unrelated source patch')
    version = commands['native-version']['command']
    require(len(version) == 11 and version[1:5] == ['msbuild', source + '/eng/empty.csproj', '/restore', '/t:GenerateRuntimeVersionFile']
            and version[5] == '/p:NativeVersionFile=' + source + '/artifacts/obj/_version.c'
            and version[6] == '/p:Version=' + policy['runtime']
            and re.fullmatch(r'/p:OfficialBuildId=[0-9]{8}\.[1-9][0-9]*', version[7])
            and version[8:11] == ['/p:ContinuousIntegrationBuild=true', '/p:UseSharedCompilation=false',
                                  '/bl:/delivery/reports/build/native-runtime/native-version.binlog'],
            'The original upstream native product version producer is required')
    # Version commands consist of the executable plus ten arguments.
    require(results.get('nativeVersionBinlog') == fingerprint(directory / 'native-version.binlog'),
            'Actual upstream native version binary log bytes differ')
    outputs = results.get('shippingFiles', [])
    require(len(outputs) == len(NATIVE_CORECLR) and {row.get('path') for row in outputs} == set(NATIVE_CORECLR)
            and len({row.get('sha256') for row in outputs}) == len(outputs),
            'All four distinct actual native source-built files are required')
    native_artifacts = [row for row in artifacts.values() if row['kind'] == 'native-coreclr']
    require(len(native_artifacts) == len(NATIVE_CORECLR), 'Exactly four source-built native construction artifacts are required')
    for row in outputs:
        require(set(row) == FP | {'path', 'buildPath'} and row['buildPath'] == obj + '/' + NATIVE_CORECLR[row['path']]
                and {key: row[key] for key in FP} == fingerprint(directory / row['path'])
                and sum(all(artifact.get(key) == row[key] for key in FP) for artifact in native_artifacts) == 1,
                'Native source product bytes or actual CMake output path differs')
        data = (directory / row['path']).read_bytes()
        require(data[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', data, 18)[0] ==
                {'aarch64': 183, 'x64': 62}[record['architecture']], 'Matching native ELF64 output required')
        dynamic = elf_dynamic(data)
        require(not any(value == 'libc.so.6' or value.startswith('ld-linux') or 'gcompat' in value for value in dynamic['needed']),
                'A source-built native runtime product imports a glibc compatibility provider')
        require(commands['elf-' + row['path']]['command'] == ['readelf', '--wide', '--file-header', '--dynamic', '--version-info',
                                                           '/delivery/reports/build/native-runtime/' + row['path']],
                'Native ELF observation examined a different source-built file')
    require(results.get('buildId') == version[7].removeprefix('/p:OfficialBuildId='),
            'The native community build identity differs from its original version producer')
    require('asmparse.cpp.o' not in commands['build']['text'], 'Unreviewed ILASM target was built in the native shipping target graph')
    validate_native_generated_source(release, directory, results, source_manifest, source, obj)
    if stages is not None:
        validate_native_build_boundary(release, record, prepare, stages, source_manifest, source, version[0])


def validate_native_generated_source(release, directory, results, manifest, source, obj):
    generated = directory / 'generated'
    require(generated.is_dir() and not generated.is_symlink(), 'Actual generated native source directory is absent')
    actual = {}
    for path in generated.rglob('*'):
        require(not path.is_symlink(), 'Linked native generated source is forbidden')
        if path.is_file(): actual[path.relative_to(generated).as_posix()] = fingerprint(path)
    require(4 <= len(actual) <= 20000 and len(actual) == results.get('generatedSourceFileCount'),
            'Complete bounded original generated native source required')
    roots = [row for row in manifest['roots'] if row['name'] == 'native-runtime-generated']
    require(len(roots) == 1 and roots[0].get('kind') == 'tree'
            and roots[0].get('role') == 'generated-native-component-source' and roots[0].get('files') == len(actual),
            'Full generated native source tree must be separately retained')
    index, targets = {}, {'runtime/' + target for digest, target in NATIVE_CORECLR_PATCHES.values()}
    targets.update('orchestration/' + path for path in NATIVE_CORECLR_PATCHES)
    with (release / 'sources' / manifest['index']['path']).open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'].startswith('native-runtime-generated/') or row['path'] in targets:
                require(row['path'] not in index, 'Duplicate native source index entry')
                index[row['path']] = row
    indexed = {name.removeprefix('native-runtime-generated/'): {key: row[key] for key in FP}
               for name, row in index.items() if name.startswith('native-runtime-generated/')}
    require(actual == indexed and targets <= index.keys(), 'Full generated and patched native source index coverage differs')
    wanted, found = set(index), {}
    with tarfile.open(release / 'sources' / manifest['archive']['path'], 'r|gz') as archive:
        for entry in archive:
            if entry.name not in wanted: continue
            require(entry.isfile() and entry.size <= 64 * 1024**2 and entry.name not in found,
                    'Native source archive member is linked, duplicated or oversized')
            raw = archive.extractfile(entry).read()
            require({key: index[entry.name][key] for key in FP} == dict(bytes=len(raw),
                    sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest()),
                    'Actual archived native source bytes differ from their source index')
            if entry.name in targets: found[entry.name] = raw
            else:
                require(raw == (generated / entry.name.removeprefix('native-runtime-generated/')).read_bytes(),
                        'Archived generated native source differs from the actual compiler input tree')
                found[entry.name] = None
    require(set(found) == wanted, 'An actual generated or patched native source archive member is missing')
    for path, (digest, target) in NATIVE_CORECLR_PATCHES.items():
        patch = found['orchestration/' + path]
        require(hashlib.sha256(patch).hexdigest() == digest, 'Archived reviewed native runtime patch bytes differ')
        pristine = reverse_reviewed_patch(found['runtime/' + target], patch, target)
        blob = hashlib.sha1(b'blob ' + str(len(pristine)).encode() + b'\0' + pristine).hexdigest()
        require(index['runtime/' + target].get('baseline', {}).get('blob') == blob,
                'Native source patch does not recover its exact original runtime Git blob')
    for name, field in [('CMakeCache.txt', 'cmakeCache'), ('compile_commands.json', 'compileCommands')]:
        require(results.get(field) == fingerprint(directory / name)
                and (generated / 'coreclr' / name).read_bytes() == (directory / name).read_bytes(),
                'Original CMake cache or compiler command byte evidence differs')
    cache = {}
    for line in (directory / 'CMakeCache.txt').read_text().splitlines():
        if not line or line.startswith(('#', '//')): continue
        match = re.fullmatch(r'([^:=]+):[^=]+=(.*)', line)
        require(match is not None and match[1] not in cache, 'Malformed or duplicate native CMake cache field')
        cache[match[1]] = match[2]
    require(cache.get('CMAKE_BUILD_TYPE') == 'Release' and cache.get('CMAKE_HOME_DIRECTORY') == source + '/src/coreclr'
            and cache.get('CMAKE_EXPORT_COMPILE_COMMANDS') == 'ON'
            and cache.get('CLR_CMAKE_TARGET_ARCH') in (None, 'arm64' if results['architecture'] == 'aarch64' else 'x64'),
            'Native compiler cache does not describe the original optimized target graph')
    compile_commands = load(directory / 'compile_commands.json')
    require(isinstance(compile_commands, list) and 100 <= len(compile_commands) <= 20000,
            'Complete original CoreCLR native compilation command matrix required')
    for row in compile_commands:
        require(set(row) == {'directory', 'command', 'file', 'output'} and row['directory'].startswith(source + '/artifacts/obj/')
                and row['file'].startswith((source + '/src/', source + '/artifacts/obj/')),
                'A native compiler command refers to an unrelated source or build directory')
        args = shlex.split(row['command'])
        require('-c' in args and '-o' in args
                and ('-O0' not in args or row['file'] == source + '/src/coreclr/ilasm/prebuilt/asmparse.cpp')
                and any(flag in args for flag in ('-O2', '-O3', '-Os'))
                and args[args.index('-c') + 1] == row['file'] and args[args.index('-o') + 1] == row['output'],
                'Original native Release compile command lost its source, output or optimization')
    header = (generated / 'runtime_version.h').read_text()
    require('#define RuntimeProductVersion ' + results['runtimeVersion'] in header
            and results['sourceCommit'] in (generated / '_version.c').read_text()
            and results.get('runtimeAssemblyVersion') == '7.0'
            and isinstance(results.get('buildId'), str) and re.fullmatch(r'[0-9]{8}\.[1-9][0-9]*', results['buildId'])
            and re.fullmatch(r'7\.0\.[0-9]+\.[0-9]+', results.get('nativeFileVersion', '')),
            'Original upstream native product, assembly, source and community file versions required')


def validate_native_build_boundary(release, record, prepare, stages, manifest, source, bootstrap):
    roots = [row for row in manifest['roots'] if row['name'] == 'runtime']
    require(len(roots) == 1 and isinstance(roots[0].get('originalPath'), str), 'Actual native runtime source host path is absent')
    host = roots[0]['originalPath']
    matches = []
    for call in stages['build']['commands']:
        if '/project/scripts/musl-legacy-coreclr.py' not in call: continue
        require(call[:len(P.DOCKER_ENGINE) + 1] == P.DOCKER_ENGINE + ['run'] and prepare['imageId'] in call,
                'Native runtime source worker did not use the frozen native builder image')
        options = {}
        for position, arg in enumerate(call):
            if arg == '--volume':
                fields = call[position + 1].split(':')
                if len(fields) in {2, 3} and (host == fields[0] or host.startswith(fields[0].rstrip('/') + '/')):
                    options['sourceMount'] = fields[1].rstrip('/') + host[len(fields[0].rstrip('/')):]
        for flag, value in [('--sdk', record['sdkVersion']), ('--arch', record['architecture']), ('--source', source),
                            ('--dotnet', bootstrap), ('--output', '/delivery/reports/build/native-runtime')]:
            require(call.count(flag) == 1 and call[call.index(flag) + 1] == value,
                    'Actual native runtime worker source/bootstrap/output identity differs')
        require(options.get('sourceMount') == source, 'Native runtime compiler input is not the archived exact runtime source')
        matches.append(call)
    require(len(matches) == 1, 'One actual original native CoreCLR/JIT/debugger source build is required')


def validate_lttng(release, record, prepare, stages):
    directory = release / 'reports/test/native-lttng'
    identity, results = load(directory / 'identity.json'), load(directory / 'results.json')
    for report in (identity, results):
        require(report.get('schemaVersion') == 1 and report.get('kind') == 'legacy-musl-lttng-session-proof'
                and report.get('sdkVersion') == record['sdkVersion'] and report.get('architecture') == record['architecture']
                and report.get('readyToRun') is True and report.get('runtimeOverlaysAccepted') is False
                and report.get('hostSdkUsed') is False and report.get('qualificationAllowed') is False
                and report.get('sourceAdmissionAllowed') is False,
                'Actual final-archive LTTng proof must retain normal ReadyToRun and no runtime overlays')
        require(all(report.get('archive', {}).get(key) == record['sdk'][key] for key in FP),
                'LTTng session tested different final SDK archive bytes')
    require(identity.get('archive', {}).get('name') == record['sdk']['name'] and identity.get('uid', 0) > 0
            and results.get('status') == 'passed' and results.get('managedExitCode') == 0,
            'Native non-root final archive LTTng workload must complete successfully')
    fixture = module('legacy_lttng_reviewed_fixture', 'musl-legacy-lttng.py')
    raw = (directory / 'Program.cs').read_bytes()
    require(raw == fixture.PROGRAM.encode() and results.get('programSha256') == hashlib.sha256(raw).hexdigest(),
            'Reviewed GC workload source differs')
    commands = native_command_records(directory, results)
    require(set(commands) == {'cold-build', 'sessiond', 'create', 'enable', 'start', 'tracepoints', 'stop', 'destroy', 'decoded'},
            'The actual cold SDK build and complete LTTng session command sequence are required')
    build = commands['cold-build']['command']
    require(len(build) == 5 and build[1] == 'build' and build[3:] == ['-c', 'Release']
            and build[0].startswith('/tmp/cbodotnet-legacy-lttng-') and build[0].endswith('/sdk/dotnet'),
            'LTTng workload must compile with the freshly extracted final SDK')
    work = build[0].removesuffix('/sdk/dotnet')
    require(build[2] == work + '/app/Probe.csproj'
            and results.get('managedCommand') == [build[0], work + '/app/bin/Release/net7.0/Probe.dll']
            and (directory / 'managed.stdout.log').read_text().splitlines() == ['READY', 'DONE'],
            'The actual final runtime did not execute the reviewed GC workload to completion')
    expected = {'sessiond': ['lttng-sessiond', '--daemonize', '--no-kernel'],
        'create': ['lttng', 'create', 'cbodotnet-legacy7', '--output=/delivery/reports/test/native-lttng/session'],
        'enable': ['lttng', 'enable-event', '--userspace', '--all'], 'start': ['lttng', 'start'],
        'tracepoints': ['lttng', 'list', '--userspace'], 'stop': ['lttng', 'stop'],
        'destroy': ['lttng', 'destroy', 'cbodotnet-legacy7'],
        'decoded': ['babeltrace2', '/delivery/reports/test/native-lttng/session']}
    require(all(commands[name]['command'] == command for name, command in expected.items()),
            'Actual LTTng session observed an unrelated source or output')
    decoded = commands['decoded']['text'].splitlines()
    observed = dict(dotnetEvents=sum('DotNETRuntime:' in line for line in decoded),
        gcStartEvents=sum('DotNETRuntime:GCStart' in line for line in decoded),
        gcEndEvents=sum('DotNETRuntime:GCEnd' in line for line in decoded),
        controlEvents=sum(fixture.CONTROL in line for line in decoded), totalDecodedLines=len(decoded),
        listedDotnetTracepoints=sum('DotNETRuntime' in line for line in commands['tracepoints']['text'].splitlines()))
    require(results.get('observed') == observed and observed['dotnetEvents'] > 0 and observed['gcStartEvents'] >= 80
            and observed['gcEndEvents'] >= 80 and observed['controlEvents'] == 1 and observed['listedDotnetTracepoints'] > 0,
            'Actual decoded .NET GC events and the independent native tracing control must both be present')
    image = load(release / 'reports/prepare/tracing-image.json')
    require(len(image) == 1 and image[0].get('Id') == prepare.get('tracingImageId')
            and image[0].get('Architecture') == P.identity(record['architecture'])['image'] and image[0].get('Os') == 'linux',
            'Immutable native SDK-free tracing image identity differs')
    calls = [call for call in stages['test']['commands'] if '/project/scripts/musl-legacy-lttng.py' in call]
    require(len(calls) == 1, 'One actual final-archive tracing test worker is required')
    call = calls[0]
    require(call[:len(P.DOCKER_ENGINE) + 1] == P.DOCKER_ENGINE + ['run']
            and call.count(prepare['tracingImageId']) == 1 and '--network=none' in call
            and [arg for arg in call if arg.startswith('--network')] == ['--network=none']
            and not any(arg.startswith(('--mount', '--volumes-from', '--device', '--entrypoint')) for arg in call),
            'Tracing test must run offline in the frozen SDK-free image without host overrides')
    mounts, environment = {}, {}
    allowed_environment = dict(HOME='/home/build', DOTNET_CLI_HOME='/home/build', DOTNET_CLI_TELEMETRY_OPTOUT='1',
        DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1', DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_PROCESSOR_COUNT='2',
        PYTHONDONTWRITEBYTECODE='1', MSBUILDDEBUGPATH='/diag', MSBUILDDEBUGCOMM='1')
    for position, arg in enumerate(call):
        if arg == '--volume':
            fields = call[position + 1].split(':')
            require(len(fields) in {2, 3} and fields[1] not in mounts, 'Unexpected tracing worker volume syntax')
            mounts[fields[1]] = fields[2] if len(fields) == 3 else 'rw'
        if arg == '--env':
            key, separator, value = call[position + 1].partition('=')
            require(separator and key not in environment and allowed_environment.get(key) == value,
                    'Tracing worker inherited an unreviewed SDK/library/runtime environment override')
            environment[key] = value
    require(mounts == {'/project': 'ro', '/delivery': 'rw', '/home/build': 'rw', '/diag': 'rw'},
            'Tracing worker exposes a build/source/bootstrap workspace')
    for flag, value in [('--sdk', record['sdkVersion']), ('--arch', record['architecture']),
                        ('--archive', '/delivery/' + record['sdk']['name']), ('--output', '/delivery/reports/test/native-lttng')]:
        require(call.count(flag) == 1 and call[call.index(flag) + 1] == value,
                'Tracing worker archive/native CPU/output identity differs')


def embedded_component_source(metadata):
    versions = metadata['attributes'].get('System.Reflection.AssemblyInformationalVersionAttribute', [])
    values = {match.lower() for value in versions for match in re.findall(r'(?i)(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])', value)}
    pairs = metadata['attributes'].get('System.Reflection.AssemblyMetadataAttribute', [])
    require(len(pairs) % 2 == 0, 'Imported managed component has incomplete assembly metadata pairs')
    commits = {value.lower() for key, value in zip(pairs[::2], pairs[1::2])
               if key == 'CommitHash' and re.fullmatch('[a-fA-F0-9]{40}', value)}
    require(len(values | commits) <= 1, 'Imported managed component has ambiguous embedded source identities')
    if values: return dict(sourceCommit=next(iter(values)), basis='assembly-informational-version')
    if commits: return dict(sourceCommit=next(iter(commits)), basis='assembly-metadata-commit-hash')
    return None


def embedded_component_commit(metadata):
    source = embedded_component_source(metadata)
    return source['sourceCommit'] if source else None


def validate_imported_component(data, row, roots, *, reviewed_sources=None, package_fp=None, attributed_policy=None):
    metadata = MANAGED.inspect(data)
    embedded_source = embedded_component_source(metadata)
    embedded = embedded_source['sourceCommit'] if embedded_source else None
    source = row.get('componentSource')
    declared = (attributed_policy or {}).get('products', {}).get(row.get('path'))
    if embedded is None and declared is not None:
        require(attributed_policy.get('kind') == ATTRIBUTED_COMPONENTS.KIND and package_fp is not None
                and package_fp['sha256'] == declared['packageSha256']
                and row.get('packageMember') == declared['packageMember'] and ATTRIBUTED_COMPONENTS.fingerprint(data) == declared['fingerprint']
                and metadata == declared['metadata'], 'Closed imported component bytes/package/member/metadata differ')
        candidate = ATTRIBUTED_COMPONENTS.declared_product(row['path'], package_fp['sha256'], row['packageMember'], data)
        require(candidate is not None and candidate['sourceCommit'] == declared['sourceCommit']
                and candidate['basis'] == declared['basis']
                and source == dict(sourceRoot=declared['sourceRoot'], sourceCommit=declared['sourceCommit'], basis=declared['basis'])
                and source['sourceRoot'] in roots and roots[source['sourceRoot']].get('kind') in {'git', 'git-export'}
                and roots[source['sourceRoot']].get('commit') == source['sourceCommit'],
                'A missing embedded identity requires the exact independently validated original component source chain')
        return metadata, declared['sourceCommit']
    if embedded is None and package_fp is not None and package_fp.get('sha256') == CSS_PARSER['sha256']:
        policy = (reviewed_sources or {}).get(CSS_PARSER['sha256'])
        require(policy is not None and policy.get('kind') == 'sdk-declared-source-gitlink'
                and source == dict(sourceRoot=policy['sourceRoot'], sourceCommit=CSS_PARSER['sourceCommit'], basis='sdk-declared-source-gitlink')
                and row['sourceRoot'] == source['sourceRoot'] and row['sourceCommit'] == source['sourceCommit']
                and row.get('path') in policy['allowedLayoutPaths'] and source['sourceRoot'] in roots
                and roots[source['sourceRoot']].get('kind') in {'git', 'git-export'}
                and roots[source['sourceRoot']].get('commit') == CSS_PARSER['sourceCommit']
                and metadata['assemblyName'] == 'Microsoft.Css.Parser' and metadata['assemblyVersion'] == '1.0.0.0'
                and metadata['publicKeyToken'] == 'adb9793829ddae60'
                and metadata['attributes'].get('System.Reflection.AssemblyInformationalVersionAttribute') == ['1.0.0-20200708.1'],
                'CSS component requires the exact independently validated SDK Gitlink/source/license chain')
        return metadata, CSS_PARSER['sourceCommit']
    if source is None:
        require(embedded is not None and embedded == row['sourceCommit'],
                'Imported component source must match its actual PE rather than only the enclosing package')
        return metadata, embedded
    require(set(source) == {'sourceRoot', 'sourceCommit', 'basis'}
            and embedded_source is not None and source['basis'] == embedded_source['basis'] and source['sourceRoot'] in roots
            and roots[source['sourceRoot']].get('kind') in {'git', 'git-export'}
            and source['sourceCommit'] == roots[source['sourceRoot']].get('commit')
            and embedded is not None and embedded == source['sourceCommit'],
            'Bundled managed component lacks its own actual embedded identity and complete corresponding Git source')
    return metadata, embedded


def validate_testhost_nuget_source(release, manifest):
    selected = {}
    for role, commit in [('test', '79d56b02b69a582cd90428878a5e9411ab7538f5'), ('nuget', TESTHOST_NUGET_COMMIT)]:
        candidates = [row for row in manifest['roots'] if row.get('kind') in {'git', 'git-export'} and row.get('commit') == commit]
        require(len(candidates) == 1, 'Exact separate TestHost NuGet dependency source roots required')
        selected[role] = candidates[0]['name']
    paths = {
        ('test', 'scripts/build/TestPlatform.Dependencies.props'): '7731e0e2a39a56b4b3501621cfbe77858c87f8b1dc8b05cbaa19c5ad0ce29c2c',
        ('test', 'src/Microsoft.TestPlatform.ObjectModel/Microsoft.TestPlatform.ObjectModel.csproj'): '85420ae550cefcabf11d61f6c3c67cbbd05b9db14aadd0acdaec3b4e2e2c1653',
        ('nuget', 'build/config.props'): 'f9ae1625662df0b3b1fc402fe1d3d5c417897a2109a41373b40a410ef9a2277a',
        ('nuget', 'src/NuGet.Core/NuGet.Frameworks/NuGet.Frameworks.csproj'): '9c3908aca7b693eacd3296f39f74d0ae0ff118e9b6c17870b22836fe858986ce'}
    for (role, path), expected in paths.items():
        body = source_member(release, manifest, selected[role] + '/' + path)
        require(hashlib.sha256(body).hexdigest() == expected, 'Original separate TestHost NuGet dependency/source declarations differ')


def reviewed_testhost_nuget(name, data, metadata, row, record, package_fp=None, local_vstest=None):
    expected = 'sdk/' + record['sdkVersion'] + '/TestHostNetFramework/NuGet.Frameworks.dll'
    old = (record['sdkVersion'] == '7.0.120' and name == expected
            and len(data) == 108936 and hashlib.sha256(data).hexdigest() == '1611987c0c3c1ec13c6f428313185eb76ad021b12fb339341e6c1539952a7e6b'
            and metadata['assemblyName'] == 'NuGet.Frameworks' and metadata['assemblyVersion'] == '5.11.0.10'
            and metadata['publicKeyToken'] == '31bf3856ad364e35' and embedded_component_commit(metadata) == TESTHOST_NUGET_COMMIT
            and package_fp is not None and package_fp['bytes'] == 9055743
            and package_fp['sha256'] == '12a6be3700ac802727aa8a1308230e0cfa4a6cb59ac66c3a9423da4270d8a475'
            and row['origin'] == 'imported-package' and row['sourceCommit'] == '79d56b02b69a582cd90428878a5e9411ab7538f5'
            and row.get('componentSource', {}).get('sourceCommit') == TESTHOST_NUGET_COMMIT)
    current = (record['sdkVersion'] == '7.0.120' and name == 'sdk/7.0.120/TestHost/NuGet.Frameworks.dll'
            and len(data) == 108920 and hashlib.sha256(data).hexdigest() == '7a71f486acbe2406aa8bcea388c58969f5df53e7977eec2e029554ed1fc9be86'
            and metadata['assemblyName'] == 'NuGet.Frameworks' and metadata['assemblyVersion'] == '5.11.0.10'
            and metadata['publicKeyToken'] == '31bf3856ad364e35' and embedded_component_commit(metadata) == TESTHOST_NUGET_COMMIT
            and local_vstest is not None and package_fp is not None and package_fp['sha256'] in local_vstest['packages']
            and (row['packagePath'], row['packageMember']) in local_vstest['importedMembers']
            and row['origin'] == 'imported-package' and row['sourceRoot'] == 'vstest' and row['sourceCommit'] == VSTEST7_COMMIT
            and row.get('componentSource', {}).get('sourceCommit') == TESTHOST_NUGET_COMMIT)
    return old or current


def validate_managed_shipping(release, shipping, actual, compiled, transformed, roots, record, *, translation_products=None, local_nuget=None, reviewed_sources=None, facade_policy=None, local_vstest=None, framework_policy=None, attributed_policy=None):
    prefix = 'sdk/' + record['sdkVersion'] + '/'
    expected = {name for name in actual if name.startswith(prefix) and name.lower().endswith(('.dll', '.exe', '.nupkg'))}
    restored = load(release / 'reports/restored-inputs.json')['packages']
    observed = set()
    package_inventories = {}
    for row in shipping:
        required = {'path', 'origin', 'sourceRoot', 'sourceCommit', 'packagePath', 'packageMember'}
        extra = ({'dataRoot', 'canonicalPrimaryPackagePath', 'canonicalPrimaryMember'}
                 if row.get('origin') == 'upstream-framework-implementation-il' else {'componentSource'})
        require(required <= set(row) <= required | extra
                and row['path'] in expected and row['path'] not in observed and row['sourceRoot'] in roots,
                'Shipping managed source coverage differs')
        if row['origin'] == 'derived-facade-metadata-source':
            require(row['sourceRoot'] == FACADE_INPUTS.ROOT_NAME and row['sourceCommit'] is None
                    and roots[row['sourceRoot']].get('kind') == 'tree' and roots[row['sourceRoot']].get('role') == FACADE_INPUTS.ROLE
                    and roots[row['sourceRoot']].get('commit') is None and 'componentSource' not in row,
                    'Derived facade declarations must retain their explicit non-Git literal metadata source role')
        else:
            require(roots[row['sourceRoot']].get('kind') in {'git', 'git-export'}
                    and re.fullmatch('[a-f0-9]{40}', row.get('sourceCommit') or '')
                    and row['sourceCommit'] == roots[row['sourceRoot']].get('commit'), 'Shipping managed source coverage differs')
        name = row['path']
        observed.add(name)
        component_commit, separate_testhost = row['sourceCommit'], False
        require('componentSource' not in row or row['origin'] == 'imported-package' and name.lower().endswith(('.dll', '.exe')),
                'Only an explicitly imported package may have separate bundled component correspondence')
        if row['origin'] == 'rebuilt-sdk':
            require(row['sourceRoot'] == 'sdk' and name in compiled and row['packagePath'] is row['packageMember'] is None,
                    'Shipping assembly is not an observed locally compiled SDK output')
        elif row['origin'] in {'rebuilt-nuget', 'rebuilt-vstest', 'imported-package'}:
            package = release / portable(row['packagePath'])
            fp = fingerprint(package)
            require(any(item.get('retained') == row['packagePath'] and all(item.get(k) == v for k, v in fp.items())
                        for item in restored), 'Shipping package bytes were not actually restored and retained')
            if fp['sha256'] not in package_inventories:
                package_inventories[fp['sha256']] = members(package, 'managed-package')
            inventory = package_inventories[fp['sha256']]
            if row['packageMember'] is None:
                require(row['origin'] == 'imported-package' and name.lower().endswith('.nupkg')
                        and name not in transformed and actual[name]['bytes'] == fp['bytes'] and actual[name]['sha256'] == fp['sha256'],
                        'A direct shipping package must be an unchanged actual restored whole nupkg')
            else:
                require(row['packageMember'] in inventory and inventory[row['packageMember']]['sha256'] ==
                        (transformed[name]['inputSha256'] if name in transformed else actual[name]['sha256']),
                        'Shipping assembly does not match its actual imported package member')
            package_metadata(package, row['sourceCommit'], local_nuget, reviewed_sources, attributed_policy=attributed_policy)
            if row['origin'] == 'imported-package' and row['packageMember'] is not None and name.lower().endswith(('.dll', '.exe')):
                with zipfile.ZipFile(package) as archive:
                    data = archive.read(row['packageMember'])
                metadata, component_commit = validate_imported_component(data, row, roots, reviewed_sources=reviewed_sources,
                                                                         package_fp=fp, attributed_policy=attributed_policy)
                separate_testhost = reviewed_testhost_nuget(name, data, metadata, row, record, fp, local_vstest)
            if row['origin'] == 'rebuilt-nuget':
                require(row['sourceRoot'] == 'nuget' and local_nuget is not None
                        and local_nuget['members'].get((fp['sha256'], row['packageMember'])) ==
                            (transformed[name]['inputSha256'] if name in transformed else actual[name]['sha256']),
                        'Rebuilt NuGet product member lacks its actual original compiler task proof')
            if row['origin'] == 'rebuilt-vstest':
                require(row['sourceRoot'] == 'vstest' and local_vstest is not None
                        and local_vstest['members'].get((fp['sha256'], row['packageMember'])) ==
                            (transformed[name]['inputSha256'] if name in transformed else actual[name]['sha256']),
                        'Rebuilt VSTest product member lacks its actual original compiler task proof')
        elif row['origin'] == 'imported-official-translation-data':
            translations = translation_products or {}
            require(row['sourceRoot'] == 'nuget' and name in translations
                    and row['packagePath'] is row['packageMember'] is None
                    and all(actual[name].get(key) == translations[name][key] for key in ('bytes', 'sha256')),
                    'Unreviewed shipping translation data or altered resource-only product bytes')
        elif row['origin'] == 'derived-facade-metadata-source':
            require(facade_policy is not None and facade_policy.get('kind') == FACADE_INPUTS.KIND
                    and facade_policy.get('basis') == 'full-derived-facade-IL' and name in facade_policy['products']
                    and name not in transformed and all(actual[name][key] == facade_policy['products'][name][key] for key in ('bytes', 'sha256')),
                    'Only the exact independently validated literal type-forwarding products may use derived source correspondence')
            declared = [item for item in FACADE_INPUTS.policy()['layout'] if item['path'] == name]
            primary = FACADE_INPUTS.policy()['package']['fingerprint']
            require(len(declared) == 1 and row['packageMember'] == declared[0]['packageMember']
                    and any(item.get('retained') == row['packagePath'] and all(item.get(key) == primary[key] for key in FP)
                            for item in restored), 'Literal facade source must name its actual restored unchanged primary package/member')
            package = checked(release, dict(path=portable(row['packagePath']), **primary))
            with zipfile.ZipFile(package) as archive:
                data = archive.read(row['packageMember'])
            require(dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), sha512=hashlib.sha512(data).hexdigest()) == declared[0]['fingerprint'],
                    'Derived facade source names different original metadata bytes')
        elif row['origin'] == 'upstream-framework-implementation-il':
            require(framework_policy is not None and framework_policy.get('kind') == FRAMEWORK_IL_INPUTS.KIND
                    and framework_policy.get('basis') == 'upstream-full-IL-source' and name in framework_policy['products']
                    and name not in transformed and all(actual[name][key] == framework_policy['products'][name][key]
                                                        for key in ('bytes', 'sha256')),
                    'Only the exact independently validated 27 implementations may use preferred upstream IL correspondence')
            require(set(row) == required | extra and row['sourceRoot'] == framework_policy['sourceRoot']
                    and row['sourceCommit'] == FRAMEWORK_IL_INPUTS.COMMIT
                    and row['dataRoot'] == FRAMEWORK_IL_INPUTS.ROOT_NAME and row['dataRoot'] in roots
                    and roots[row['dataRoot']].get('kind') == 'tree'
                    and roots[row['dataRoot']].get('role') == FRAMEWORK_IL_INPUTS.ROLE
                    and roots[row['dataRoot']].get('commit') is None,
                    'Real implementation IL and literal resource complements must retain their distinct original Git/data roles')
            declared = [item for item in FRAMEWORK_IL_INPUTS.policy()['layout'] if item['path'] == name]
            primary = FRAMEWORK_IL_INPUTS.policy()['package']['fingerprint']
            require(len(declared) == 1 and row['packagePath'] == row['canonicalPrimaryPackagePath']
                    and row['packageMember'] == row['canonicalPrimaryMember'] == declared[0]['packageMember']
                    and any(item.get('retained') == row['canonicalPrimaryPackagePath']
                            and all(item.get(key) == primary[key] for key in FP) for item in restored),
                    'Preferred IL must retain the actual restored canonical SDK-copy package/member chain')
            package = checked(release, dict(path=portable(row['canonicalPrimaryPackagePath']), **primary))
            with zipfile.ZipFile(package) as archive:
                data = archive.read(row['canonicalPrimaryMember'])
            require(dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), sha512=hashlib.sha512(data).hexdigest()) == declared[0]['fingerprint'],
                    'Preferred implementation IL names different original SDK-copy bytes')
        else:
            raise ValueError('Unreviewed shipping managed origin or translation-data policy')
        family = shipping_family(name)
        if family and row['origin'] != 'rebuilt-sdk':
            require(component_commit == (TESTHOST_NUGET_COMMIT if separate_testhost else
                                         VSTEST7_COMMIT if family == 'vstest' else SDK7_IMPORT_SOURCES[family][2]),
                    'Shipping managed family has unrelated package/source attribution: ' + family)
        if family == 'nuget' and not name.lower().endswith('.resources.dll') and not separate_testhost:
            require(row['origin'] == 'rebuilt-nuget', 'Every primary shipping NuGet assembly must consume its genuinely rebuilt original package')
        if family == 'vstest':
            require(row['origin'] == 'rebuilt-vstest', 'Every VSTest primary and resource satellite must consume its genuine original compiler output')
    require(observed == expected, 'Every shipping SDK managed member needs exact source correspondence')


def nuspec_metadata(path):
    with zipfile.ZipFile(path) as archive:
        names = [name for name in archive.namelist() if name.lower().endswith('.nuspec')]
        require(len(names) == 1 and archive.getinfo(names[0]).file_size <= 1024 * 1024, 'One bounded shipping package nuspec required')
        raw = archive.read(names[0])
    require(b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'Unsafe shipping package metadata XML')
    metadata = ET.fromstring(raw).find('{*}metadata')
    require(metadata is not None, 'Shipping package metadata is absent')
    return metadata


def package_metadata(path, commit, local_nuget=None, reviewed_sources=None, *, attributed_policy=None):
    metadata = nuspec_metadata(path)
    repository = metadata.find('{*}repository')
    sha = fingerprint(path)['sha256']
    if sha in ATTRIBUTED_COMPONENTS.policy()['packageSourceExceptions']:
        selected = [row for row in (attributed_policy or {}).get('products', {}).values() if row['packageSha256'] == sha]
        require(attributed_policy is not None and attributed_policy.get('kind') == ATTRIBUTED_COMPONENTS.KIND
                and len(selected) == 2 and all(row['sourceCommit'] == commit for row in selected)
                and ATTRIBUTED_COMPONENTS.package_source_commit(path) == commit,
                'Historical Elfie missing-nuspec provenance requires independently validated original source and complete code correspondence')
        return metadata
    if fingerprint(path)['sha256'] == NETSTANDARD21['sha256']:
        policy = (reviewed_sources or {}).get(NETSTANDARD21['sha256'])
        require(policy is not None and policy.get('sourceCommit') == NETSTANDARD21['packagingCommit'] == commit,
                'Both exact NETStandard packaging and C# API source roots must be independently validated')
        return reviewed_netstandard_identity(path, commit)
    if fingerprint(path)['sha256'] == CSS_PARSER['sha256']:
        policy = (reviewed_sources or {}).get(CSS_PARSER['sha256'])
        require(policy is not None and policy.get('kind') == 'sdk-declared-source-gitlink'
                and policy.get('sourceCommit') == CSS_PARSER['sourceCommit'] == commit,
                'CSS missing-nuspec provenance needs its independently validated complete source chain')
        return reviewed_css_identity(path, commit)
    if fingerprint(path)['sha256'] == MSBUILD_RESOURCES.PACKAGE['sha256']:
        policy = (reviewed_sources or {}).get(MSBUILD_RESOURCES.PACKAGE['sha256'])
        require(fingerprint(path) == MSBUILD_RESOURCES.PACKAGE and commit == MSBUILD_RESOURCES.COMMIT
                and policy is not None and policy.get('kind') == MSBUILD_RESOURCES.KIND
                and policy.get('basis') == 'pinned-resource-only-pe-and-original-xlf'
                and policy.get('sourceCommit') == commit and len(policy.get('products', {})) == 52
                and policy.get('localBuildClaimed') is False and policy.get('byteIdenticalCompilationClaimed') is False,
                'Missing-nuspec MSBuild resource data requires independently validated original XLF and all 52 exact satellites')
        return metadata
    if fingerprint(path)['sha256'] == GLOBBING_INPUTS.PACKAGE_SHA:
        policy = (reviewed_sources or {}).get(GLOBBING_INPUTS.PACKAGE_SHA)
        require(policy is not None and policy.get('kind') == GLOBBING_INPUTS.KIND
                and policy.get('sourceCommit') == GLOBBING_INPUTS.COMMIT == commit
                and policy.get('publisherBinaryLicensePreserved') is True
                and policy.get('sourceApacheLicenseNotSubstitutedForPublisherBinaryLicense') is True
                and policy.get('localBuildClaimed') is False and policy.get('byteIdenticalCompilationClaimed') is False,
                'Missing-nuspec Globbing provenance requires its independently verified complete own/shared source and original publisher license')
        return reviewed_globbing_identity(path, commit)
    local = (local_nuget is not None and fingerprint(path)['sha256'] in local_nuget['packages']
             and commit == POLICIES['7.0.120']['nuget'] and repository is not None and repository.get('commit') is None
             and repository.get('url') == 'https://github.com/NuGet/NuGet.Client'
             and metadata.findtext('{*}id', '').lower() in NUGET7_PACKAGES and metadata.findtext('{*}version') == '6.4.3-rc.1'
             and metadata.find('{*}license') is not None and metadata.find('{*}license').text == 'Apache-2.0')
    require(repository is not None and (repository.get('commit') == commit or local) and metadata.find('{*}license') is not None,
            'Imported shipping package source/license correspondence is unknown')
    return metadata


def validate_vstest_build(release, record, descriptor, roots, stages=None, prepare=None):
    replay = validate_replay(release, descriptor, 'reports/build/vstest.binlog', compiled=True, component='vstest')
    require(replay['transformations'] == [] and replay.get('generatedOutputs', []) == [],
            'VSTest package products must remain unchanged original managed IL')
    require(roots.get('vstest', {}).get('kind') in {'git', 'git-export'}
            and roots['vstest'].get('commit') == VSTEST7_COMMIT, 'Complete exact original VSTest source root required')
    if stages is not None:
        validate_replay_source_mount(release, replay, 'vstest', roots, stages, prepare)
        validate_vstest_worker(release, record, replay)
    inventory = load(release / 'reports/build/vstest-packages.json')
    require(set(inventory) == {'schemaVersion', 'kind', 'sdkVersion', 'sourceCommit', 'version', 'packages', 'importedMembers'}
            and inventory['schemaVersion'] == 1 and inventory['kind'] == 'rebuilt-original-vstest-source-build-core-distribution'
            and inventory['sdkVersion'] == record['sdkVersion'] == '7.0.120'
            and inventory['sourceCommit'] == VSTEST7_COMMIT and inventory['version'] == VSTEST7_VERSION,
            'Exact original Core VSTest package build inventory required')
    built = inventory['packages']
    require(len(built) == 2 and {row.get('id') for row in built} == {'Microsoft.TestPlatform.Build', 'Microsoft.TestPlatform.CLI'},
            'Both original VSTest Build and CLI products are required')
    packages, package_paths, wanted, imported = {}, {}, {}, {}
    expected_imports = {
        'contentFiles/any/net7.0/Microsoft.Extensions.DependencyModel.dll':
            (160840, '6ef18888f38be6a6203819bd96fca64101a5176ad5e0cf803558a550272383cb', 'ee54d4cbd2b305eadf6f341bdc9d4abccdb50559'),
        'contentFiles/any/net7.0/Newtonsoft.Json.dll':
            (695336, '72cf291d4bab0edd08a9b07c6173e1e7ad1abb7ab727fd7044bf6305d7515661', 'ae9fe44e1323e91bcbd185ca1a14099fba7c021f'),
        'contentFiles/any/net7.0/Microsoft.Extensions.FileSystemGlobbing.dll':
            (39416, 'd485cef178eb4e1a64a2d13fae4c5744d99b4cc429b063e9cf39a6d66d12b713', '96bf83a6c1ab6f6801130150c27282c49030c8e1'),
        'contentFiles/any/net7.0/NuGet.Frameworks.dll':
            (108920, '7a71f486acbe2406aa8bcea388c58969f5df53e7977eec2e029554ed1fc9be86', TESTHOST_NUGET_COMMIT),
        'contentFiles/any/net7.0/TestHost/Newtonsoft.Json.dll':
            (695336, '72cf291d4bab0edd08a9b07c6173e1e7ad1abb7ab727fd7044bf6305d7515661', 'ae9fe44e1323e91bcbd185ca1a14099fba7c021f'),
        'contentFiles/any/net7.0/TestHost/NuGet.Frameworks.dll':
            (108920, '7a71f486acbe2406aa8bcea388c58969f5df53e7977eec2e029554ed1fc9be86', TESTHOST_NUGET_COMMIT),
    }
    for row in built:
        require(set(row) == FP | {'id', 'version', 'file', 'origin', 'sourceCommit', 'retained'}
                and row['version'] == VSTEST7_VERSION and row['sourceCommit'] == VSTEST7_COMMIT
                and row['origin'] == inventory['kind'] and row['file'] == row['id'] + '.' + VSTEST7_VERSION + '.nupkg'
                and row['sha256'] not in packages, 'Closed unchanged original VSTest package identity required')
        path = checked(release, dict(path=row['retained'], **{key: row[key] for key in FP}))
        metadata = package_metadata(path, VSTEST7_COMMIT)
        license = metadata.find('{*}license')
        require(metadata.findtext('{*}id') == row['id'] and metadata.findtext('{*}version') == VSTEST7_VERSION
                and metadata.find('{*}repository').get('url') == 'https://github.com/microsoft/vstest'
                and license.get('type') == 'file' and license.text == 'LICENSE_NET.txt',
                'Original VSTest package source and embedded license declaration differ')
        with zipfile.ZipFile(path) as archive:
            require('LICENSE_NET.txt' in archive.namelist()
                    and (row['id'] != 'Microsoft.TestPlatform.CLI' or 'ThirdPartyNotices.txt' in archive.namelist()),
                    'Complete original VSTest MIT/license and third-party notices must remain embedded')
            for member, value in members(path, 'managed-package').items():
                if not member.lower().endswith(('.dll', '.exe')): continue
                info = MANAGED.inspect(archive.read(member)); commit = embedded_component_commit(info)
                require(info['cliFlags'] & 1 and not info['cliFlags'] & 16 and info['managedNativeHeaderBytes'] == 0,
                        'A genuine VSTest source package contains native or ReadyToRun code')
                key = (row['sha256'], member)
                if commit == VSTEST7_COMMIT:
                    if member.endswith('.resources.dll'):
                        satellite = resource_only_pe(archive.read(member))
                        require(satellite['culture'] in {'cs', 'de', 'es', 'fr', 'it', 'ja', 'ko', 'pl', 'pt-BR', 'ru', 'tr', 'zh-Hans', 'zh-Hant'},
                                'A VSTest satellite has an unexpected original culture')
                    wanted[key] = value['sha256']
                else:
                    require(row['id'] == 'Microsoft.TestPlatform.CLI' and member in expected_imports
                            and (value['bytes'], value['sha256'], commit) == expected_imports[member],
                            'Unreviewed bundled VSTest dependency source or bytes')
                    imported[(row['retained'], member)] = dict(packagePath=row['retained'], member=member, sourceCommit=commit, **value)
        packages[row['sha256']] = {key: row[key] for key in FP}
        package_paths[row['retained']] = packages[row['sha256']]
    require(len(wanted) == 301 and len(imported) == 6 and {member for package, member in imported} == set(expected_imports),
            'Every original Core VSTest product and separately imported dependency must be accounted for')
    require(len(inventory['importedMembers']) == len(imported)
            and all(imported.get((row.get('packagePath'), row.get('member'))) == row for row in inventory['importedMembers']),
            'Imported VSTest dependency inventory differs from the actual package bytes')
    actual = {}
    for row in replay['compiledOutputs']:
        require(set(row) == {'packagePath', 'member', 'sha256', 'sourceRoot', 'sourceCommit', 'context', 'outputPath'}
                and row['sourceRoot'] == 'vstest' and row['sourceCommit'] == VSTEST7_COMMIT
                and row['outputPath'].startswith(replay['sourceMountRoot'] + '/')
                and PurePosixPath(row['outputPath']).name == PurePosixPath(row['member']).name,
                'Closed original VSTest compiler/member proof required')
        require(portable(row['packagePath']) in package_paths, 'VSTest compiler proof names an unbound package path')
        fp = package_paths[row['packagePath']]; key = (fp['sha256'], portable(row['member']))
        require(fp['sha256'] in packages and key not in actual and wanted.get(key) == row['sha256'],
                'VSTest package member does not bind an actual successful original compiler output')
        actual[key] = row['sha256']
    require(actual == wanted, 'Every source-produced VSTest primary and resource satellite requires actual compiler provenance')
    return dict(packages=packages, packagePaths=package_paths, members=actual, importedMembers=imported, replay=replay)


def validate_vstest_worker(release, record, replay):
    directory = release / 'reports/build/vstest'
    report = load(directory / 'results.json')
    require(report.get('schemaVersion') == 1 and report.get('kind') == 'legacy-musl-vstest-source-build'
            and report.get('status') == 'passed' and report.get('sdkVersion') == record['sdkVersion'] == '7.0.120'
            and report.get('architecture') == record['architecture'] and report.get('sourceCommit') == VSTEST7_COMMIT
            and report.get('sourceGraph') == 'TestPlatform_BuildFromSource.sln' and report.get('version') == VSTEST7_VERSION
            and report.get('originalSourceBuildFramework') == 'net7.0'
            and report.get('originalXlfFiles') == 247 and report.get('managedPackageMembers') == 307
            and report.get('sourceCommitAttributedMembers') == 301
            and all(report.get(name) is True for name in ('importedDependenciesRequireSeparateSourceAttribution',
                    'originalSourceBuildCoreHostScope', 'originalShellUnconditionalClosedCoverageCopyNotUsed'))
            and all(report.get(name) is False for name in ('compiledResourceAssembliesImported', 'fullMonoNetFrameworkTestHostProvided',
                    'closedCoverageInputImported', 'vendorVersionRelabeled', 'readyToRunDisabled', 'qualificationAllowed', 'sourceAdmissionAllowed')),
            'Original Core VSTest source-build scope, complete cultures and separate imported dependencies are required')
    require(report.get('xlfResourceReceipt') == fingerprint(directory / 'xlf-resource-generation.json'),
            'Actual original-XLF generation receipt bytes differ')
    commands = native_command_records(directory, report)
    projects = {'original-solution-restore': ('TestPlatform_BuildFromSource.sln', 'Restore'),
        'original-solution-build': ('TestPlatform_BuildFromSource.sln', 'Build'),
        'package-publish': ('src/package/package/package.csproj', 'Publish'),
        'vstest.console-publish': ('src/vstest.console/vstest.console.csproj', 'Publish'),
        'datacollector-publish': ('src/datacollector/datacollector.csproj', 'Publish'),
        'testhost-publish': ('src/testhost/testhost.csproj', 'Publish'),
        'testhost.x86-publish': ('src/testhost.x86/testhost.x86.csproj', 'Publish'),
        'Microsoft.TestPlatform.CLI-pack': ('artifacts/Release/Microsoft.TestPlatform.CLI.csproj', 'Restore;Pack'),
        'Microsoft.TestPlatform.Build-pack': ('artifacts/Release/Microsoft.TestPlatform.Build.csproj', 'Restore;Pack')}
    require(set(commands) == set(projects), 'Every original VSTest solution, publish and original-nuspec pack command is required')
    source = replay['sourceMountRoot']
    for name, (relative, target) in projects.items():
        command = commands[name]['command']
        require(len(command) >= 16 and command[1:3] == ['msbuild', source + '/' + relative]
                and {'/p:Configuration=Release', '/p:DotNetBuildFromSource=true', '/p:LocalizedBuild=true',
                     '/p:UseSharedCompilation=false', '/p:UseAppHost=false', '/p:EmitCompilerGeneratedFiles=true',
                     '/p:NETCoreSdkRuntimeIdentifier=' + record['targetRid'], '/p:ToolsRID=' + record['targetRid'],
                     '/p:RepositoryCommit=' + VSTEST7_COMMIT, '/p:SourceRevisionId=' + VSTEST7_COMMIT,
                     '/m:2', '/nologo', '/t:' + target} <= set(command)
                and '/bl:/delivery/reports/build/vstest/' + name + '.binlog' in command
                and not any(arg.startswith(('/p:NoWarn=', '/p:DISABLE_CROSSGEN=', '/p:SkipCompilerExecution=')) for arg in command)
                and commands[name]['text'].splitlines()[0] == json.dumps(command),
                'Actual VSTest source project, native target or original command differs')
        if target == 'Publish':
            require('/p:TargetFramework=net7.0' in command and '/p:PublishDir=' + source + '/artifacts/Release/net7.0/' in command,
                    'Original Core VSTest publish target or stage differs')
        if target == 'Restore;Pack':
            require('/p:Version=' + VSTEST7_VERSION in command and '/p:CommitId=' + VSTEST7_COMMIT in command
                    and '/p:PackageOutputPath=/delivery/reports/build/vstest/source-built-feed' in command,
                    'VSTest package output must retain the genuine upstream dev version and original source identity')
    require(fingerprint(directory / 'original-solution-build.binlog')['sha256'] == replay['inputSha256'],
            'The VSTest replay is not the actual completed original solution build')
    declared = load(release / 'reports/build/vstest-packages.json')['packages']
    outputs = report.get('packages', [])
    require(len(outputs) == 2 and all(set(row) == FP | {'path'} and row['path'] ==
                'source-built-feed/' + candidate['file'] and all(row[key] == candidate[key] for key in FP)
                for row in outputs for candidate in declared if row.get('path') == 'source-built-feed/' + candidate['file'])
            and {row['path'] for row in outputs} == {'source-built-feed/' + row['file'] for row in declared},
            'Actual VSTest worker outputs differ from the unchanged compiler-bound packages')


def validate_vstest_source_contract(release, manifest, local_vstest):
    policy = load(ROOT / 'scripts/musl-legacy-vstest-source-policy.json')
    require(policy.get('schemaVersion') == 1 and policy.get('sourceCommit') == VSTEST7_COMMIT
            and policy.get('version') == VSTEST7_VERSION and len(policy.get('files', {})) == 14
            and policy.get('originalSourceBuildCoreHostScope') is True and policy.get('fullMonoNetFrameworkTestHostProvided') is False,
            'Closed original VSTest source-build Core distribution policy required')
    expected = {'vstest/' + name: value for name, value in policy['files'].items()}
    index = {}
    with (release / 'sources' / manifest['index']['path']).open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'] in expected:
                require(row['path'] not in index, 'Duplicate original VSTest source contract entry')
                index[row['path']] = row
    require(index.keys() == expected.keys() and all(index[name].get('baseline', {}).get('blob') == value['gitBlob']
                and index[name].get('bytes') == value['bytes'] and index[name].get('sha256') == value['sha256']
                for name, value in expected.items()), 'Exact original VSTest source-build, package and license Git blobs required')
    bodies = {}
    with tarfile.open(release / 'sources' / manifest['archive']['path'], 'r|gz') as archive:
        for entry in archive:
            if entry.name not in expected: continue
            require(entry.isfile() and entry.size == expected[entry.name]['bytes'] and entry.size <= 1024**2 and entry.name not in bodies,
                    'Ordinary original VSTest contract source required')
            raw = archive.extractfile(entry).read()
            require(hashlib.sha256(raw).hexdigest() == expected[entry.name]['sha256']
                    and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected[entry.name]['gitBlob'],
                    'Archived original Core VSTest contract source bytes differ')
            bodies[entry.name] = raw
    require(bodies.keys() == expected.keys(), 'Original Core VSTest distribution source is incomplete')
    for relative, package_fp in local_vstest['packagePaths'].items():
        require(any(row['packagePath'] == relative for row in local_vstest['replay']['compiledOutputs']),
                'A genuine VSTest package has no source compiler products')
        path = release / relative
        with zipfile.ZipFile(path) as package:
            require(package.read('LICENSE_NET.txt') == bodies['vstest/src/package/licenses/LICENSE_NET.txt'],
                    'VSTest original package license text was replaced or omitted')
            if 'ThirdPartyNotices.txt' in package.namelist():
                require(package.read('ThirdPartyNotices.txt') == bodies['vstest/src/package/ThirdPartyNotices.txt'],
                        'VSTest original third-party notices were replaced or omitted')


def validate_nuget_build(release, record, descriptor, roots, stages=None, prepare=None):
    replay = validate_replay(release, descriptor, 'reports/build/nuget.binlog', compiled=True, component='nuget')
    require(replay['transformations'] == [] and replay.get('generatedOutputs', []) == [], 'NuGet product compiler proof may not contain arbitrary transformations')
    if stages is not None:
        validate_replay_source_mount(release, replay, 'nuget', roots, stages, prepare)
    feed = load(release / 'reports/build/bootstrap-feed.json')['packages']
    built = [row for row in feed if row.get('origin') == 'rebuilt-exact-nuget-original-library-target-matrix']
    expected = {name + '.6.4.3-rc.1.nupkg' for name in NUGET7_PACKAGES}
    require(len(built) == 19 and {row['file'].lower() for row in built} == expected
            and all(row.get('sourceCommit') == POLICIES['7.0.120']['nuget'] for row in built),
            'Exactly nineteen original-matrix NuGet product packages must be genuinely rebuilt')
    # A complete source build emits nineteen packages; not every emitted
    # package is necessarily restored by the SDK graph. Authenticate all
    # retained outputs here, and require actual consumption separately for
    # every shipping input in validate_managed_shipping.
    retained_outputs = {}
    for row in replay['compiledOutputs']:
        require(isinstance(row.get('packagePath'), str), 'Retained rebuilt NuGet output path required')
        relative = portable(row['packagePath'])
        if relative not in retained_outputs:
            retained_outputs[relative] = fingerprint(release / relative)
    packages, wanted = {}, {}
    for row in built:
        candidates = [relative for relative, actual in retained_outputs.items() if all(actual[key] == row[key] for key in FP)]
        require(candidates, 'A genuinely rebuilt NuGet package output was not retained')
        path = release / candidates[0]
        fp = fingerprint(path)
        require(all(fp[key] == row[key] for key in FP), 'Actual consumed rebuilt NuGet package bytes differ')
        metadata = nuspec_metadata(path)
        repository, license = metadata.find('{*}repository'), metadata.find('{*}license')
        require(metadata.findtext('{*}id', '').lower() + '.6.4.3-rc.1.nupkg' == row['file'].lower()
                and metadata.findtext('{*}version') == '6.4.3-rc.1' and repository is not None
                and repository.get('url') == 'https://github.com/NuGet/NuGet.Client'
                and repository.get('commit') in (None, POLICIES['7.0.120']['nuget'])
                and license is not None and license.get('type') == 'expression' and license.text == 'Apache-2.0',
                'Original rebuilt NuGet package identity/repository/license differs')
        inventory = members(path, 'managed-package')
        primary = {member: value['sha256'] for member, value in inventory.items() if member.lower().endswith('.dll')
                   and not member.lower().endswith('.resources.dll') and shipping_family(member) == 'nuget'}
        require(primary, 'A rebuilt original NuGet product package has no primary library payload')
        wanted.update({(fp['sha256'], member): sha for member, sha in primary.items()})
        packages[fp['sha256']] = fp
    actual = {}
    for row in replay['compiledOutputs']:
        require(set(row) == {'packagePath', 'member', 'sha256', 'sourceRoot', 'sourceCommit', 'context', 'outputPath'}
                and row['sourceRoot'] == 'nuget' and row['sourceCommit'] == POLICIES['7.0.120']['nuget']
                and row['outputPath'].startswith(replay['sourceMountRoot'] + '/')
                and PurePosixPath(row['outputPath']).name == PurePosixPath(row['member']).name,
                'Closed original NuGet compiler/member source proof required')
        fp = fingerprint(release / portable(row['packagePath']))
        key = (fp['sha256'], portable(row['member']))
        require(fp['sha256'] in packages and key not in actual and wanted.get(key) == row['sha256'],
                'NuGet compiled output does not bind its actual consumed package member')
        actual[key] = row['sha256']
    require(actual == wanted, 'Every primary NuGet package DLL in every original present TFM must have actual compiler provenance')
    return dict(packages=packages, members=actual, replay=replay)


def shipping_family(path):
    name = PurePosixPath(path).name.lower()
    if name.endswith('.resources.dll'):
        name = name.removesuffix('.resources.dll') + '.dll'
    if name.startswith(('nuget.', 'microsoft.build.nugetsdkresolver')):
        return 'nuget'
    if name in {'msbuild.dll', 'microsoft.build.dll', 'microsoft.build.framework.dll',
                'microsoft.build.tasks.core.dll', 'microsoft.build.utilities.core.dll'}:
        return 'msbuild'
    if name in {'microsoft.codeanalysis.razor.dll', 'microsoft.codeanalysis.razor.compiler.dll',
                'microsoft.aspnetcore.razor.language.dll', 'microsoft.aspnetcore.mvc.razor.extensions.dll',
                'microsoft.aspnetcore.razor.utilities.shared.dll', 'microsoft.net.sdk.razor.sourcegenerators.dll'}:
        return 'razor'
    if name in {'microsoft.codeanalysis.netanalyzers.dll', 'microsoft.codeanalysis.csharp.netanalyzers.dll',
                'microsoft.codeanalysis.visualbasic.netanalyzers.dll'}:
        return 'roslyn-analyzers'
    if name in {'microsoft.codeanalysis.analyzerutilities.dll', 'microsoft.codeanalysis.elfie.dll'}:
        return None
    if name.startswith('microsoft.codeanalysis.') or name in {'microsoft.codeanalysis.dll', 'csc.dll', 'vbc.dll', 'vbcscompiler.dll'}:
        return 'roslyn'
    if name.startswith('fsharp.') or name in {'fsc.dll', 'fsi.dll'}:
        return 'fsharp'
    if name.startswith(('microsoft.templateengine.', 'microsoft.templatesearch.')):
        return 'templating'
    if name.startswith(('microsoft.testplatform.', 'microsoft.visualstudio.testplatform.')) or name in {
            'vstest.console.dll', 'testhost.dll', 'testhost.x86.dll', 'datacollector.dll'}:
        return 'vstest'
    return None


def validate_shipping_declarations(release, manifest, roots):
    raw = source_member(release, manifest, 'sdk/eng/Version.Details.xml')
    require(b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'Unsafe pinned SDK dependency declarations')
    dependencies = ET.fromstring(raw).findall('./ProductDependencies/Dependency')
    for family, (package, repository, commit) in SDK7_IMPORT_SOURCES.items():
        matches = [row for row in dependencies if row.get('Name') == package]
        require(len(matches) == 1 and matches[0].findtext('Sha') == commit,
                'Pinned SDK shipping dependency declaration differs: ' + family)
        original = matches[0].findtext('Uri')
        aliases = {'nuget': 'https://dev.azure.com/devdiv/DevDiv/_git/NuGet-NuGet.Client-Trusted',
                   'templating': 'https://dev.azure.com/dnceng/internal/_git/dotnet-templating'}
        require(original == aliases.get(family, repository)
                and any(row.get('kind') in {'git', 'git-export'} and row.get('commit') == commit for row in roots.values()),
                'Complete declared shipping component source is absent: ' + family)


def original_sdk7_cases():
    prefix = 'Microsoft.DotNet.SourceBuild.SmokeTests.'
    cases = {prefix + name for name in ('SdkContentTests.CompareMsftToSb', 'DotNetWatchTests.WatchTests',
                                       'DotNetFormatTests.FormatProject', 'PoisonTests.VerifyUsage')}
    def scenario(group, language, template, commands, no_https=False):
        return (prefix + group + '.VerifyScenario(scenario: TestScenario { Commands = ' + commands
            + ', Language = ' + language + ', NoHttps = ' + str(no_https) + ', ScenarioName = "' + group
            + '", Template = ' + template + ' })')
    for language in ('CSharp', 'FSharp', 'VB'):
        for template, commands in [('Console', 'Build | Run | PublishComplex | PublishR2R'), ('ClassLib', 'Build | Publish'),
                                   ('XUnit', 'Test'), ('NUnit', 'Test'), ('MSTest', 'Test')]:
            cases.add(scenario('BasicScenarioTests', language, template, commands))
    for language in ('CSharp', 'FSharp'):
        for template, commands, no_https in [('Web', 'Build | Run | PublishComplex', False),
                ('Mvc', 'Build | Run | Publish', True), ('WebApi', 'Build | Run | Publish', False)]:
            cases.add(scenario('WebScenarioTests', language, template, commands, no_https))
    for template in ('Razor', 'BlazorWasm', 'BlazorServer', 'Worker', 'Angular'):
        cases.add(scenario('WebScenarioTests', 'CSharp', template, 'None' if template in {'Worker', 'Angular'} else 'Build | Run | Publish'))
    for template in ('BlazorWasm', 'BlazorServer', 'ClassLib', 'Console', 'MSTest', 'Mvc', 'NUnit', 'Web', 'WebApp', 'WebApi', 'Worker', 'XUnit'):
        cases.add(prefix + 'OmniSharpTests.VerifyScenario(template: ' + template + ')')
    require(len(cases) == 42, 'Reviewed SDK7 original test universe differs')
    return cases


def validate_original_smoke(release, record, manifest):
    directory = release / 'reports/test/original-smoke'
    identity = load(directory / 'identity.json')
    require(identity.get('sdkVersion') == record['sdkVersion'] and identity.get('architecture') == record['architecture']
            and identity.get('upstreamCaseCount') == 42
            and all(identity.get('sdkArchive', {}).get(key) == record['sdk'][key] for key in ('bytes', 'sha256')),
            'Original smoke suite tested unrelated SDK bytes')
    prefix = 'installer/src/SourceBuild/tarball/content/test/Microsoft.DotNet.SourceBuild.SmokeTests/'
    index = {}
    with (release / 'sources' / manifest['index']['path']).open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'].startswith(prefix):
                require(row.get('baseline') and row['mode'] in {'100644', '100755'}, 'Original smoke source has injected or linked test code')
                index[row['path'][len(prefix):]] = row
    installer = next(root for root in manifest['roots'] if root['name'] == 'installer')
    source_path = prefix.removeprefix('installer/')
    require(index and not any(row['path'].startswith(source_path) for row in installer.get('deleted', [])),
            'An original smoke assertion/source asset was removed')
    claimed = identity.get('sourceFiles', [])
    require(len(claimed) == len(index) and {row['path'] for row in claimed} == set(index)
            and all(set(row) == {'path', 'bytes', 'sha256'} and all(row[key] == index[row['path']][key]
                    for key in ('bytes', 'sha256')) for row in claimed), 'Actual original smoke source inventory differs')
    packer = module('legacy_original_smoke_pristine', 'package-used-source.py')
    config = None
    with tarfile.open(release / 'sources' / manifest['archive']['path'], 'r|gz') as archive:
        for entry in archive:
            if not entry.name.startswith(prefix):
                continue
            relative = entry.name[len(prefix):]
            require(entry.isfile() and entry.size <= 2 * 1024**2 and relative in index, 'Original smoke source archive member differs')
            raw = archive.extractfile(entry).read()
            blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            require(packer.pristine_blob(index[relative], blob, raw, relative.endswith(('.cmd', '.bat', '.sln'))),
                    'Original smoke assertion/source bytes differ from the pinned installer Git tree')
            if relative == 'Config.cs':
                config = raw.decode('utf-8').replace('\r\n', '\n')
    require(config is not None and config.count("TargetRid.Split('-')[1]") == 1, 'Exact original RID test parser required')
    adjusted = config.replace("TargetRid.Split('-')[1]", "TargetRid.Split('-')[^1]")
    patch = ''.join(difflib.unified_diff(config.splitlines(True), adjusted.splitlines(True), fromfile='a/Config.cs', tofile='b/Config.cs'))
    require((directory / 'test-rid-parser.patch').read_text() == patch, 'Only the reviewed musl RID test-parser adjustment is allowed')
    trx = list((directory / 'trx').glob('*.trx'))
    require(len(trx) == 1, 'One complete original SDK7 smoke TRX required')
    rows = ET.parse(trx[0]).findall('.//{*}UnitTestResult')
    require(len(rows) == 42 and len({row.get('executionId') for row in rows}) == 42
            and {row.get('testName') for row in rows} == original_sdk7_cases(), 'Exact original SDK7 test universe differs')
    smoke = module('legacy_admission_original_smoke', 'ci-net67-evidence.py')
    require(smoke.smoke_results(trx[0]) == load(directory / 'summary.json'), 'Original SDK7 smoke outcomes/skip identity differ')
    fixtures = module('legacy_admission_omnisharp_fixture', 'prepare-net7-test-tools.py')
    expected = fixtures.tool_input('arm64' if record['architecture'] == 'aarch64' else 'x64')
    fixture = load(directory / 'fixture.json')
    archive = directory / 'fixture-inputs' / expected['cacheName']
    require(fixture.get('version') == '1.39.6' and fixture.get('nativeFixtureApphostExecuted') is False
            and all(fixture.get('archive', {}).get(key) == expected[key] == fingerprint(archive)[key] for key in ('bytes', 'sha256'))
            and fixture.get('originalMembers') == fixtures.archive_inventory(archive), 'Exact original managed OmniSharp fixture bytes differ')
    launcher = fixture.get('launcher', {}).get('text', '')
    require(re.fullmatch('#!/bin/sh\nexec "\\$DOTNET_ROOT/dotnet" "[^"\n]+/omnisharp/OmniSharp.dll" "\\$@"\n', launcher)
            and fixture['launcher']['bytes'] == len(launcher.encode())
            and fixture['launcher']['sha256'] == hashlib.sha256(launcher.encode()).hexdigest(),
            'The original OmniSharp fixture must use the exact tested musl host launcher')


def validate_functional(release, record, stages):
    sdk = load(release / 'reports/verify/sdk/verification.json')
    require(sdk.get('sdkVersion') == record['sdkVersion'] and sdk.get('reportedRid') == record['targetRid']
            and sdk.get('verificationStatus') == sdk.get('smokeStatus') == 'passed'
            and sdk.get('archive', {}).get('sha256') == record['sdk']['sha256']
            and all(sdk.get('functionalChecks', {}).get(name) == 'passed' for name in
                    ('consoleDllExecution', 'consoleApphostExecution', 'rsaSha256SignAndVerify',
                     'cryptographicRandomBytes', 'frFrDecimalFormatting', 'aspNetCoreLoopbackHttp')),
            'Complete archive-bound offline SDK verification required')
    functional = release / 'reports/verify/functional'
    candidate = load(functional / 'candidate.json')
    require(candidate.get('sdkVersion') == record['sdkVersion'] and candidate.get('architecture') == record['architecture']
            and all(candidate.get('archive', {}).get(k) == record['sdk'][k] for k in FP), 'Functional worker tested different SDK bytes')
    offline = load(functional / 'offline-summary.json')
    require(offline.get('status') == 'passed' and offline.get('network') == 'none'
            and offline.get('uid', 0) > 0 and offline.get('nativeArchitecture') == P.identity(record['architecture'])['machine']
            and offline.get('hostSdkUsed') is False and offline.get('compilerInstalled') is False,
            'Native SDK-free offline functional isolation differs')
    for name, marker in [('sdk-info', record['targetRid']), ('offline-build', None), ('icu', 'ICU 13 CULTURES OK'),
                         ('crypto', 'CRYPTO SHA256 RSA ECDSA AESGCM X509 OID OK'), ('aspnet', 'ASPNET HTTP OK'),
                         ('apphost', 'ICU 13 CULTURES OK'), ('tls', 'SYSTEM TRUST TLS OK')]:
        item = load(functional / (name + '.json'))
        require(item.get('exitCode') == 0 and (marker is None or marker in item.get('output', '')),
                'Legacy functional execution failed: ' + name)
    tls = load(functional / 'tls.json')
    require(tls.get('defaultTrust') is True and tls.get('certificateValidationBypass') is False,
            'Actual system TLS trust is required')
    negative = load(functional / 'negative-certificates.json')
    fixture_hash = '3c88ee9eab40b2e096b96c73316e8af8f3a58ea11b40fa72a84d6c5a4de647cc'
    require(negative.get('status') == 'passed' and negative.get('fixture') ==
            dict(path='negative-certificate-fixture.cs', sha256=fixture_hash)
            and fingerprint(functional / 'negative-certificate-fixture.cs')['sha256'] == fixture_hash
            and negative.get('readyToRun') is True and negative.get('defaultSslStream') is True
            and negative.get('certificateValidationCallback') is False and negative.get('ephemeralUserTrustStore') is True
            and negative.get('uid', 0) > 0 and negative.get('network') == 'none'
            and negative.get('nativeArchitecture') == P.identity(record['architecture'])['machine'],
            'Reviewed default-SslStream negative-certificate fixture required')
    observations = negative.get('commands', [])
    require(len(observations) == 2 and all(item.get('exitCode') == 0 for item in observations),
            'Negative certificate fixture compilation/execution failed')
    output = (functional / 'negative-execution.log').read_text()
    require(all(marker in output for marker in ('PASS trusted-control connects',
        'PASS untrusted-self-signed fails closed', 'PASS expired fails closed', 'PASS wrong-hostname fails closed',
        'PASS invalid-CA managed chain fails closed', 'PASS invalid-CA TLS fails closed',
        'PASS all certificate cases; no remote validation callback')), 'Negative certificate assertions are incomplete')
    calls = stages['verify']['commands']
    for mode, network in [('offline', '--network=none'), ('tls', '--network=host')]:
        require(any('/project/scripts/musl-legacy-functional.py' in call and mode in call and network in call for call in calls),
                'Actual functional network boundary is absent')


def validate_verification_boundary(release, record, prepare, stages):
    native = P.identity(record['architecture'])
    for name, field in [('image.json', 'imageId'), ('verify_image.json', 'verificationImageId')]:
        image = load(release / 'reports/prepare' / name)
        require(len(image) == 1 and image[0].get('Id') == prepare.get(field)
                and image[0].get('Architecture') == native['image'] and image[0].get('Os') == 'linux',
                'Prepared immutable native legacy image differs')
    calls = [call for call in stages['verify']['commands'] if call[:len(P.DOCKER_ENGINE) + 1] == P.DOCKER_ENGINE + ['run']]
    require(len(calls) == 4, 'Exactly four reviewed cold verification workers required')
    workers = {}
    forbidden_environment = {'LD_LIBRARY_PATH', 'LD_PRELOAD', 'DOTNET_ROOT', 'DOTNET_ROOT_ARM64', 'DOTNET_ROOT_X64',
                             'DOTNET_HOST_PATH', 'DOTNET_SHARED_STORE', 'DOTNET_ADDITIONAL_DEPS', 'NUGET_PACKAGES'}
    for call in calls:
        require(call.count(prepare['verificationImageId']) == 1
                and not any(value.startswith(('--mount', '--volumes-from', '--device', '--entrypoint')) for value in call),
                'Every final SDK worker must use the frozen SDK-free image')
        mounts = {}
        for index, value in enumerate(call):
            if value == '--volume':
                fields = call[index + 1].split(':')
                require(len(fields) in {2, 3} and fields[1] not in mounts, 'Unexpected cold verifier mount syntax')
                mounts[fields[1]] = fields[2] if len(fields) == 3 else 'rw'
            if value == '--env':
                require(call[index + 1].split('=', 1)[0] not in forbidden_environment,
                        'Cold verification inherited bootstrap/library/package-cache overrides')
        require(mounts == {'/project': 'ro', '/delivery': 'rw', '/home/build': 'rw', '/diag': 'rw'},
                'Cold verification exposes a build/source/bootstrap workspace')
        scripts = [script for script in ('verify-sdk.sh', 'musl-sdk-audit.py', 'musl-legacy-functional.py')
                   if '/project/scripts/' + script in call]
        require(len(scripts) == 1 and call.count('--archive') == 1
                and call[call.index('--archive') + 1] == '/delivery/' + record['sdk']['name'],
                'Cold verification worker tested an unrelated archive')
        worker = scripts[0]
        if worker == 'musl-legacy-functional.py':
            modes = [mode for mode in ('offline', 'tls') if mode in call]
            require(len(modes) == 1, 'One exact functional worker mode required')
            worker += ':' + modes[0]
        require(worker not in workers, 'Duplicate cold verification worker')
        workers[worker] = call
        network = '--network=host' if worker.endswith(':tls') else '--network=none'
        require([value for value in call if value.startswith('--network')] == [network],
                'Cold verification network boundary differs')
    require(set(workers) == {'verify-sdk.sh', 'musl-sdk-audit.py', 'musl-legacy-functional.py:offline', 'musl-legacy-functional.py:tls'},
            'A required cold verification worker is missing')
    call = workers['verify-sdk.sh']
    for flag, expected in [('--expected-version', record['sdkVersion']), ('--expected-rid', record['targetRid']),
                           ('--framework', 'net7.0'), ('--arch', 'arm64' if record['architecture'] == 'aarch64' else 'x64')]:
        require(call.count(flag) == 1 and call[call.index(flag) + 1] == expected, 'Cold SDK verifier version/RID/framework differs')


def validate_elf_closure(release, record, profile, report):
    """Recompute dynamic imports from every actual ELF and close its graph."""
    native = P.identity(record['architecture'])
    loader = '/lib/ld-musl-' + native['machine'] + '.so.1'
    machine = 'AArch64' if record['architecture'] == 'aarch64' else 'Advanced Micro Devices X86-64'
    closure = report.get('closure', {})
    require(report.get('violations') == [] and report.get('emulation') is False
            and report.get('nativeArchitecture') == native['machine']
            and closure.get('schemaVersion') == 1 and closure.get('scope') == 'musl-complete-payload-elf-closure'
            and closure.get('native') is True and closure.get('libc') == 'musl'
            and closure.get('architecture') == record['architecture'] and closure.get('targetRid') == record['targetRid']
            and closure.get('symlinks') == report.get('symlinks') == [], 'Native complete ordinary ELF closure identity differs')
    outer = {row['path']: row for row in report['files']}
    payload = {row['path']: row for row in closure.get('elfFiles', [])}
    require(len(payload) == len(closure.get('elfFiles', [])) == closure.get('hostElfCount') == len(outer)
            and set(payload) == set(outer), 'Inner/outer native ELF inventories differ')
    abi = module('legacy_actual_elf_abi_policy', 'musl_archive.py')
    found = set()
    with tarfile.open(release / record['sdk']['name'], 'r:gz') as archive:
        for entry in archive:
            name = entry.name.removeprefix('./')
            if name not in payload:
                continue
            require(entry.isfile() and entry.size <= 512 * 1024**2, 'One ordinary bounded actual ELF member required')
            raw = archive.extractfile(entry).read()
            dynamic = elf_dynamic(raw)
            require(not any(name == 'libc.so.6' or name.startswith('ld-linux') or 'gcompat' in name
                            for name in dynamic['needed']), 'Actual native ELF imports a forbidden glibc compatibility provider')
            labels = abi.reviewed_gcc_abi_labels(dynamic)
            elf_type = {1: 'REL', 2: 'EXEC', 3: 'DYN'}.get(struct.unpack_from('<H', raw, 16)[0])
            require(all(all(row.get(key) == value for key, value in dynamic.items())
                        and row.get('reviewedAbiVersionLabels') == labels and row.get('machine') == machine
                        and row.get('elfClass') == 'ELF64' and row.get('elfType') == elf_type
                        and row.get('interpreter') in (None, loader)
                        for row in (outer[name], payload[name])), 'Actual ELF dynamic dependency/version metadata differs')
            require(payload[name].get('disposition') == 'host-runtime-or-tool'
                    and payload[name].get('sha256') == outer[name]['sha256']
                    and payload[name].get('size') == len(raw)
                    and payload[name].get('dependencies') == outer[name].get('dependencies'), 'Actual native ELF payload fingerprint/disposition differs')
            found.add(name)
    require(found == set(payload), 'Actual native ELF dependency scan is incomplete')
    reference = profile['stockAlpine']
    expected_profile = 'profiles/dotnet-10.0.403-linux-musl-' + record['architecture'] + '.json'
    require(reference.get('referenceProfile') == expected_profile
            and fingerprint(ROOT / expected_profile)['sha256'] == reference.get('referenceProfileSha256'),
            'Reviewed frozen stock Alpine package profile differs')
    stock_profile = load(ROOT / expected_profile)
    packages = {row['P']: row['V'] for row in stock_profile['runtimePackages']}
    # The frozen base image and direct runtime APKs also bring stock providers
    # such as musl/zlib. Reuse the common reviewed transitive-provider pins and
    # authenticate every selected version against the frozen APK indexes.
    require(all(name not in packages or packages[name] == version for name, version in abi.RUNTIME_PACKAGES.items()),
            'Stock transitive provider versions conflict with the frozen runtime profile')
    packages.update(abi.RUNTIME_PACKAGES)
    available = set()
    for index in stock_profile['apkIndexes'].values():
        path = ROOT / index['snapshotPath']
        require(fingerprint(path)['sha256'] == index['sha256'], 'Frozen stock APK index bytes differ')
        with tarfile.open(path, 'r:gz') as archive:
            incoming = archive.extractfile('APKINDEX')
            raw = incoming.read(32 * 1024**2 + 1)
            require(len(raw) <= 32 * 1024**2, 'Frozen APK index exceeds its bound')
        for block in raw.decode().split('\n\n'):
            fields = dict(line.split(':', 1) for line in block.splitlines() if ':' in line)
            if 'P' in fields and 'V' in fields:
                available.add((fields['P'], fields['V']))
    require(all((name, version) in available for name, version in packages.items()), 'Reviewed stock provider is absent from the frozen APK indexes')
    require(not packages.keys() & {'gcompat', 'glibc', 'libc6-compat'}, 'Glibc provider profiles are forbidden')
    libraries = {row['path']: row for row in closure.get('stockLibraries', [])}
    require(libraries and len(libraries) == len(closure['stockLibraries']) and loader in libraries,
            'Complete stock native provider inventory required')
    for path, row in libraries.items():
        require(path == posixpath.normpath(path) and path.startswith(('/lib/', '/usr/lib/', '/usr/local/lib/'))
                and row.get('machine') == machine and row.get('elfClass') == 'ELF64'
                and row.get('interpreter') in (None, loader) and row.get('elfType') in {'DYN', 'EXEC', 'REL'}
                and row.get('size', 0) > 0 and re.fullmatch('[a-f0-9]{64}', row.get('sha256', ''))
                and any(row.get('apkOwner') == path + ' is owned by ' + package + '-' + version for package, version in packages.items())
                and row.get('reviewedAbiVersionLabels') == abi.reviewed_gcc_abi_labels(row),
                'Native dependency is not attributed to an exact frozen stock APK provider')
    used = set()
    for row in list(payload.values()) + list(libraries.values()):
        for runpath in row.get('runpaths', []):
            require(isinstance(runpath, str) and runpath and '\0' not in runpath, 'Unsafe native loader search path')
            origin = str(PurePosixPath(row['path']).parent)
            if not origin.startswith('/'):
                origin = '/payload/' + origin
            expanded = runpath.replace('${ORIGIN}', origin).replace('$ORIGIN', origin)
            resolved = posixpath.normpath(expanded)
            require('$' not in expanded and expanded.startswith('/')
                    and (resolved in {'/lib', '/usr/lib', '/usr/local/lib'} or resolved == '/payload' or resolved.startswith('/payload/')),
                    'Native loader search path escapes reviewed stock/payload roots')
        dependencies = row.get('dependencies', [])
        require([dependency.get('needed') for dependency in dependencies] == row.get('needed')
                and len(set(row['needed'])) == len(row['needed']), 'Native dependency edges omit/duplicate an actual DT_NEEDED import')
        for dependency in dependencies:
            require(set(dependency) == {'needed', 'resolved', 'provider', 'sha256'}, 'Closed native dependency edge required')
            if dependency['provider'] == 'stock-system':
                target = libraries.get(dependency['resolved'])
                require(target is not None and target['sha256'] == dependency['sha256'], 'Stock provider hash/closure edge differs')
                used.add(dependency['resolved'])
            else:
                matches = [target for name, target in payload.items() if dependency['resolved'].endswith('/' + name)]
                require(dependency['provider'] == 'payload' and len(matches) == 1
                        and matches[0]['sha256'] == dependency['sha256'], 'Payload native provider hash/closure edge differs')
            if any(label['file'] == dependency['needed'] for label in row['reviewedAbiVersionLabels']):
                target = libraries.get(dependency['resolved'], {})
                require(dependency['provider'] == 'stock-system' and dependency['needed'] == 'libgcc_s.so.1'
                        and 'GLIBC_2.0' in target.get('versionDefinitions', [])
                        and target.get('apkOwner', '').endswith(' is owned by libgcc-' + packages['libgcc']),
                        'Reviewed GCC unwind ABI label has the wrong actual stock provider')
    require(used == set(libraries), 'Unreferenced/incomplete native system closure inventory')


def validate(release):
    release = P.ordinary(release)
    record = load(release / 'producer-validation.json')
    require(record.get('sdkVersion') in POLICIES, 'Unreviewed legacy SDK original construction/test policy')
    require(record.get('schemaVersion') == 2 and record.get('producerRevision') == 1
            and record.get('kind') == 'musl-sdk-producer-validation' and record.get('status') == 'passed'
            and record.get('diagnosticPodman') is False and record.get('diagnosticPtrace') is False
            and record.get('qualificationAllowed') is False and record.get('sourceAdmissionAllowed') is False,
            'Diagnostic or self-admitted legacy evidence is forbidden')
    arch, sdk = record['architecture'], record['sdkVersion']
    require(arch in ('x64', 'aarch64') and record.get('targetRid') == P.identity(arch)['rid']
            and record.get('libc') == 'musl' and record.get('allRequiredStages') == list(STAGES)
            and re.fullmatch('[a-f0-9]{40}', record.get('projectCommit', ''))
            and all(re.fullmatch('[1-9][0-9]*', record.get(key, '')) for key in ('runId', 'runAttempt')),
            'Exact native legacy source/run identity required')
    P.delivery_index(release, record.get('files'))
    producer = load(release / 'producer-sdk.json')
    require(producer.get('schemaVersion') == 1 and producer.get('kind') == 'musl-sdk-build'
            and all(producer.get(key) == record[key] for key in ('sdkVersion', 'architecture', 'targetRid', 'libc',
                'sourceCommit', 'projectCommit', 'runId', 'runAttempt', 'producerRevision')),
            'Legacy producer SDK identity differs')
    descriptor = producer['sdk']
    expected_name = 'cbodotnet-sdk-' + sdk + '-linux-musl-' + arch + '-build.' + record['runId'] + '.tar.gz'
    require(set(descriptor) == FP | {'name'} and descriptor['name'] == expected_name
            and all(descriptor[key] == value for key, value in fingerprint(release / expected_name).items()),
            'Genuine final legacy SDK archive bytes differ')
    record = dict(record, sdk=descriptor)
    profile_path = ROOT / 'profiles' / ('dotnet-' + sdk + '-linux-musl-' + arch + '.json')
    profile = load(profile_path)
    prepare = load(release / 'reports/prepare/identity.json')
    require(prepare.get('profile') == dict(path=profile_path.name, **fingerprint(profile_path))
            and all(prepare.get(key) == record[key] for key in ('sdkVersion', 'architecture', 'targetRid', 'libc',
                        'sourceCommit', 'projectCommit', 'runId', 'runAttempt'))
            and prepare.get('diagnosticPodman') is False and prepare.get('diagnosticPtrace') is False
            and prepare.get('emulation') is False and prepare.get('nativeArchitecture') == P.identity(arch)['machine'],
            'Native legacy preparation/profile identity differs')
    policy = POLICIES[sdk]
    require(record['sourceCommit'] == policy['installer'] and prepare.get('sdkSourceCommit') == policy['sdk']
            and prepare.get('runtimeSourceCommit') == policy['runtimeCommit'], 'Reviewed legacy component source pins differ')
    require(profile.get('sdkVersion') == sdk and profile.get('source', {}).get('commit') == policy['installer']
            and profile.get('target') == dict(rid=record['targetRid'], libc='musl')
            and profile.get('build', {}).get('sourceOnly') is False and profile['build'].get('crossBuild') is False
            and profile['build'].get('portableBuild') is True and profile.get('stockAlpine', {}).get('pointRelease') == '3.24.4'
            and profile.get('bootstrap', {}).get('version') == policy['bootstrap'], 'Legacy regular native source/import route changed')
    stages = validate_stages(release, record, prepare)
    require(producer.get('imageId') == prepare.get('imageId'), 'Produced legacy SDK image identity differs')
    validate_verification_boundary(release, record, prepare, stages)
    bootstrap = load(release / 'reports/prepare/bootstrap.json')
    require(all(bootstrap.get(key) == profile['bootstrap'][key] for key in ('version', 'rid', 'url', 'sha512')),
            'Exact native legacy bootstrap input differs')
    source = module('legacy_admission_source_packer', 'package-used-source.py')
    manifest = source.verify(SimpleNamespace(release_dir=release, expected_project_commit=record['projectCommit'],
        expected_run_id=record['runId'], expected_run_attempt=record['runAttempt'], expected_target_rid=record['targetRid']))
    validate_scan_applicability(release, record, manifest)
    validate_construction(release, record, manifest, stages, prepare)
    validate_original_smoke(release, record, manifest)
    validate_lttng(release, record, prepare, stages)
    validate_functional(release, record, stages)
    elf = load(release / 'reports/verify/elf.json')
    native = P.identity(arch)
    loader = '/lib/ld-musl-' + native['machine'] + '.so.1'
    require(elf.get('status') == 'passed' and elf.get('libc') == 'musl' and elf.get('architecture') == arch
            and elf.get('loader') == loader and elf.get('uid', 0) > 0 and elf.get('foreignTargetExceptions') == []
            and elf.get('closure', {}).get('status') == 'passed' and elf['closure'].get('nonHostElfCount') == 0,
            'Complete native stock-provider legacy ELF closure required')
    actual = P.sdk_elf_inventory(release / descriptor['name'], 62 if arch == 'x64' else 183, loader)
    rows = {row['path']: row for row in elf.get('files', [])}
    require(len(rows) == len(actual) == elf.get('elfCount') and set(rows) == set(actual)
            and all(all(rows[path].get(key) == value for key, value in item.items()) for path, item in actual.items()),
            'Every actual legacy SDK ELF must bind unchanged archive bytes')
    validate_elf_closure(release, record, profile, elf)
    require(any('--network=none' in call and prepare['verificationImageId'] in call
                for call in stages['verify']['commands']), 'Legacy final verification must use its frozen SDK-free image')
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-dir', type=Path, required=True)
    options = parser.parse_args()
    verified = validate(options.release_dir)
    print(json.dumps({key: verified[key] for key in ('status', 'sdkVersion', 'architecture', 'targetRid',
        'projectCommit', 'sourceCommit', 'runId', 'runAttempt', 'producerRevision', 'sourceAdmissionAllowed')}, sort_keys=True))
