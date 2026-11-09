"""SDK5 Unsafe source origin, including its unchanged upstream R2R import.

The R2R body remains an opaque, fingerprinted publisher input. Complete decoded
managed metadata and all method IL are compared to the declared-source NPK;
neither a local R2R build nor native-code derivation is claimed.
"""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import xml.etree.ElementTree as ET
import zipfile

SDK = '5.0.214'
POLICY_SHA256 = 'bc876ba088964625bf379cb9c4dbeeafa2c08cbaf2257167fe5403dad1fdc9d7'
ROOT_NAME = 'sdk5-original-unsafe-source-inputs'
ROLE = 'sdk5-original-unsafe-package-and-managed-correspondence'
KIND = 'reviewed-sdk5-declared-unsafe-source-and-managed-correspondence'
FP = ('bytes', 'sha256', 'sha512')


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def ordinary(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary original SDK5 Unsafe input required')
    return path


def policy():
    raw = Path(__file__).with_name('musl-legacy5-unsafe-declared-source-policy.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == POLICY_SHA256, 'Closed SDK5 Unsafe source policy differs')
    p = json.loads(raw)
    require(p['sdkVersion'] == SDK and p['kind'] == 'sdk5-declared-unsafe-source-policy'
            and p['runtime']['commit'] == 'cf258a14b70ad9069470a108f13765e0e5988f51' and len(p['products']) == 2
            and p['sourceBasis'] == 'publisher-declared-repository-and-complete-managed-correspondence'
            and all(p[k] is False for k in ('publisherCompilerExecutionClaimed', 'localBuildClaimed', 'nativeCodeDerivationClaimed')),
            'Distinct original SDK5 Unsafe source identity required')
    return p


def managed_view(data):
    """Decode every table field present in the closed Unsafe implementation.

String heaps may be reordered by the original R2R producer. Only string indices
and MethodDef RVAs are represented by their values and method bodies. Every
other table field, header, opaque heap and every IL byte remains exact.
"""
    require(isinstance(data, bytes) and 128 <= len(data) <= 1024**2 and data[:2] == b'MZ', 'Bounded Unsafe PE required')

    def read(fmt, at, body=data):
        require(0 <= at <= len(body) - struct.calcsize(fmt), 'Truncated Unsafe PE or metadata')
        return struct.unpack_from(fmt, body, at)[0]

    pe = read('<I', 0x3c); require(data[pe:pe + 4] == b'PE\0\0', 'Invalid Unsafe PE signature')
    sections, optional = [], pe + 24
    count, optional_size, magic = read('<H', pe + 6), read('<H', pe + 20), read('<H', optional)
    require(1 <= count <= 16 and magic in (0x10b, 0x20b), 'Unsupported Unsafe PE layout')
    directory = 96 if magic == 0x10b else 112
    require(optional_size >= directory + 15 * 8 and optional + optional_size <= len(data)
            and read('<I', optional + directory - 4) >= 15, 'Truncated Unsafe PE directories')
    for index in range(count):
        at = optional + optional_size + 40 * index
        sections.append((read('<I', at + 12), read('<I', at + 16), read('<I', at + 20)))

    def address(rva, size):
        matches = [offset + rva - start for start, length, offset in sections if start <= rva and rva + size <= start + length]
        require(size > 0 and len(matches) == 1 and 0 <= matches[0] <= len(data) - size, 'Unsafe RVA escapes its original PE section')
        return matches[0]

    cli = address(read('<I', optional + directory + 14 * 8), 72)
    require(read('<I', cli) == 72 and read('<I', cli + 20) == 0, 'Unsafe CLR header or entrypoint differs')
    size = read('<I', cli + 12); require(20 <= size <= 1024**2, 'Invalid Unsafe metadata size')
    at = address(read('<I', cli + 8), size); metadata = data[at:at + size]
    require(metadata[:4] == b'BSJB', 'Invalid Unsafe metadata signature')
    version_size = read('<I', 12, metadata); require(1 <= version_size <= 256, 'Invalid Unsafe CLR version length')
    cursor = 16 + ((version_size + 3) & ~3)
    streams = read('<H', cursor + 2, metadata); require(streams == 5, 'Exact Unsafe metadata stream set required')
    metadata_header = metadata[:cursor + 4]; cursor += 4; heaps, ranges = {}, []
    for unused in range(streams):
        start, length = read('<I', cursor, metadata), read('<I', cursor + 4, metadata)
        end = metadata.find(b'\0', cursor + 8, min(cursor + 40, len(metadata)))
        require(end >= 0, 'Unterminated Unsafe metadata stream name')
        name = metadata[cursor + 8:end].decode('ascii')
        require(name not in heaps and start + length <= len(metadata), 'Duplicate or escaped Unsafe metadata stream')
        heaps[name] = metadata[start:start + length]; ranges.append((start, start + length)); cursor = (end + 4) & ~3
    require(heaps.keys() == {'#~', '#Strings', '#US', '#GUID', '#Blob'}
            and all(start >= cursor for start, end in ranges)
            and all(a[1] <= b[0] for a, b in zip(sorted(ranges), sorted(ranges)[1:])), 'Exact nonoverlapping Unsafe metadata streams required')
    tables = heaps['#~']; flags = read('<B', 6, tables)
    require(flags & ~7 == 0, 'Unsupported Unsafe heap index flags')
    valid, counts, position = read('<Q', 8, tables), {}, 24
    for table in range(64):
        if valid & (1 << table): counts[table] = read('<I', position, tables); position += 4
    require(counts == {0:1, 1:19, 2:3, 6:39, 8:69, 10:15, 12:53, 27:1, 32:1, 35:1, 42:31, 44:1}, 'Exact original Unsafe implementation table counts required')
    s, g, b = (4 if flags & bit else 2 for bit in (1, 2, 4))

    def index(table): return 4 if counts.get(table, 0) >= 65536 else 2
    def coded(bits, kinds): return 4 if max(counts.get(t, 0) for t in kinds) >= (1 << (16 - bits)) else 2
    td = coded(2, [2, 1, 27]); mr = coded(3, [2, 1, 26, 6, 27])
    ca = coded(5, [6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43]); ct = coded(3, [6, 10])
    # A string column uses ('string', width); all remaining numbers are exact.
    string = ('string', s)
    schemas = {0:[2,string,g,g,g], 1:[coded(2,[0,26,35,1]),string,string],
        2:[4,string,string,td,index(4),index(6)], 6:[4,2,2,string,b,index(8)], 8:[2,2,string],
        10:[mr,string,b], 12:[ca,ct,b], 27:[b], 32:[4,2,2,2,2,4,b,string,string],
        35:[2,2,2,2,4,b,string,string,b], 42:[2,2,coded(1,[2,6]),string], 44:[index(42),td]}

    def text(offset):
        heap = heaps['#Strings']; require(0 <= offset < len(heap), 'Unsafe string index escapes heap')
        end = heap.find(b'\0', offset); require(end >= 0, 'Unterminated Unsafe metadata string')
        return heap[offset:end].decode('utf-8')

    header, rows, methods = tables[:position], {}, []
    for table, count in counts.items():
        rows[table] = []
        for rid in range(count):
            values = []
            for column in schemas[table]:
                width = column[1] if isinstance(column, tuple) else column
                value = read('<I' if width == 4 else '<H', position, tables); position += width
                values.append(text(value) if isinstance(column, tuple) else value)
            if table == 6:
                rva = values[0]; require(rva != 0, 'All original Unsafe implementation methods need IL bodies')
                start = address(rva, 1); first = data[start]
                if first & 3 == 2: length, begin, stack, method_header, locals_token = first >> 2, start + 1, 8, 2, 0
                else:
                    method_header = read('<H', start)
                    require(first & 3 == 3 and method_header >> 12 == 3 and not method_header & 8, 'Only original Unsafe method headers without EH sections required')
                    length, begin, stack, locals_token = read('<I', start + 4), start + 12, read('<H', start + 2), read('<I', start + 8)
                require(0 < length <= 65536, 'Invalid original Unsafe IL body size'); address(rva, begin - start + length)
                methods.append(dict(header=method_header, maxStack=stack, localsToken=locals_token, il=data[begin:begin + length].hex()))
                values[0] = 'method-body-' + str(rid + 1)
            rows[table].append(values)
    require(all(value == 0 for value in tables[position:]), 'Nonzero unexplained Unsafe table suffix')
    return dict(cliFlags=read('<I', cli + 16), nativeHeaderBytes=read('<I', cli + 68),
        normalized=dict(metadataHeader=metadata_header.hex(), tablesHeader=header.hex(), rows=rows, methods=methods,
            stringValues=sorted(part.hex() for part in heaps['#Strings'].split(b'\0')),
            opaqueHeaps={name:raw.hex() for name,raw in heaps.items() if name not in ('#~', '#Strings')}))


def correspondence(original, ready_to_run):
    baseline, imported = managed_view(original), managed_view(ready_to_run)
    require(baseline['cliFlags'] == 9 and baseline['nativeHeaderBytes'] == 0
            and imported['cliFlags'] == 4 and imported['nativeHeaderBytes'] == 124, 'Exact original Unsafe IL and R2R header roles required')
    # The exact original publisher R2R metadata exchanges only these two
    # assembly CustomAttribute rows. Their complete parent/type/value tuples
    # still match; no other row order or field difference is normalized.
    attributes = imported['normalized']['rows'][12]
    require(attributes[1] == [46, 67, 650] and attributes[12] == [46, 83, 730]
            and baseline['normalized']['rows'][12][1] == [46, 83, 730]
            and baseline['normalized']['rows'][12][12] == [46, 67, 650], 'Exact original Unsafe assembly attribute permutation required')
    attributes[1], attributes[12] = attributes[12], attributes[1]
    require(baseline['normalized'] == imported['normalized'], 'Complete original Unsafe managed metadata and all IL must correspond')
    return dict(kind='complete-managed-metadata-and-il-correspondence', methods=39,
        everyTableFieldCompared=True, everyMethodBodyCompared=True, nativeBytesUnchanged=True,
        originalAssemblyAttributeRowPermutation=[2, 13], nativeCodeDerivationClaimed=False)


def source_recipe(sources, p=None):
    p = p or policy()
    require(sources.keys() == p['runtime']['files'].keys(), 'Complete original Unsafe source recipe and license files required')
    for name, expected in p['runtime']['files'].items():
        raw = sources[name]
        require(fingerprint(raw) == {k:expected[k] for k in FP}
                and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected['gitBlob'], 'Original Unsafe source recipe Git bytes differ')
    il = sources['src/libraries/System.Runtime.CompilerServices.Unsafe/src/System.Runtime.CompilerServices.Unsafe.il']
    require(b'.class public abstract auto ansi sealed beforefieldinit System.Runtime.CompilerServices.Unsafe' in il,
            'Original Unsafe IL implementation required')
    return dict(sourceBasis=p['sourceBasis'], sourceCommit=p['runtime']['commit'], selectedOriginalFiles=len(sources),
        publisherCompilerExecutionClaimed=False, localBuildClaimed=False, nativeCodeDerivationClaimed=False)


def inspect_package(path, p=None):
    p = p or policy(); path = ordinary(path)
    require(path.is_file() and path.stat().st_size == p['package']['fingerprint']['bytes'], 'Exact original SDK5 Unsafe NPK required')
    raw = path.read_bytes(); require(fingerprint(raw) == p['package']['fingerprint'], 'Original SDK5 Unsafe NPK bytes differ')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        node = p['package']['nuspec']; spec = archive.read(node['path'])
        require(fingerprint(spec) == {k:node[k] for k in FP}, 'Original Unsafe nuspec differs')
        require(b'<!DOCTYPE' not in spec.upper() and b'<!ENTITY' not in spec.upper(), 'Unsafe nuspec entities rejected')
        metadata = ET.fromstring(spec).find('{*}metadata'); repository = metadata.find('{*}repository')
        require(metadata.findtext('{*}id') == p['package']['id'] and metadata.findtext('{*}version') == p['package']['version']
                and repository is not None and dict(repository.attrib) == dict(type='git', url='git://github.com/dotnet/runtime', commit=p['runtime']['commit']),
                'Original Unsafe publisher repository declaration required')
        for name, expected in dict(p['package']['notices'], **p['package']['members']).items():
            require(fingerprint(archive.read(name)) == expected, 'Original Unsafe canonical member or notice differs')
    return raw


def declared_product(layout_path, raw):
    p = policy(); require(layout_path in p['products'], 'Exact original SDK5 Unsafe layout path required')
    row = p['products'][layout_path]
    require(fingerprint(raw) == row['fingerprint'], 'Original SDK5 Unsafe DLL bytes differ')
    return row


def bodies(package, original_r2r, recipe):
    p = policy(); require(fingerprint(package) == p['package']['fingerprint'], 'Retained original Unsafe NPK differs')
    name = next(n for n,v in p['products'].items() if v['managedCorrespondenceRequired']); declared_product(name, original_r2r)
    with zipfile.ZipFile(io.BytesIO(package)) as archive: proof = correspondence(archive.read(p['products'][name]['canonicalMember']), original_r2r)
    encode = lambda value:(json.dumps(value, indent=2) + '\n').encode()
    return {'packages/' + p['package']['fingerprint']['sha256'] + '.nupkg':package,
        'original-imported-r2r/System.Runtime.CompilerServices.Unsafe.dll':original_r2r,
        'managed-correspondence.json':encode(proof), 'source-recipe.json':encode(recipe),
        'origin.json':encode(dict(schemaVersion=1, sdkVersion=SDK, kind=KIND, policySha256=POLICY_SHA256,
            sourceBasis=p['sourceBasis'], diagnosticObservedContainer=p['products'][name]['diagnosticObservedContainer'],
            diagnosticContainerIsCanonicalSourceOrigin=False, publisherCompilerExecutionClaimed=False,
            localBuildClaimed=False, nativeCodeDerivationClaimed=False))}


def prepare(package, original_r2r, runtime_source, destination):
    p = policy(); runtime_source = ordinary(runtime_source)
    git = ['git', '-c', 'safe.directory=' + str(runtime_source), '-C', str(runtime_source)]
    require(subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip() == p['runtime']['commit'], 'Exact declared Unsafe source checkout required')
    sources = {n:ordinary(runtime_source / n).read_bytes() for n in p['runtime']['files']}
    data = bodies(inspect_package(package, p), ordinary(original_r2r).read_bytes(), source_recipe(sources, p)); destination = ordinary(destination)
    require(not destination.exists(), 'Fresh original Unsafe input tree required'); destination.mkdir(parents=True)
    for name, raw in data.items():
        path = ordinary(destination / name); path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
    return dict(name=ROOT_NAME, kind='tree', path=str(destination), role=ROLE)


def validate(release, manifest, package):
    p = policy(); release = ordinary(release); B = module('sdk5_unsafe_source_bytes', 'musl_legacy_admission.py'); P = module('sdk5_unsafe_source_tree', 'package-used-source.py')
    require(manifest.get('sdkVersion') == SDK and manifest.get('targetRid') in ('linux-musl-arm64', 'linux-musl-x64'), 'Independent SDK5 Unsafe source delivery required')
    index_path = B.checked(release / 'sources', manifest['index']); archive_path = B.checked(release / 'sources', manifest['archive'])
    roots = [r for r in manifest['roots'] if r.get('kind') in ('git', 'git-export') and r.get('commit') == p['runtime']['commit']
             and r.get('tree') == p['runtime']['tree'] and not r.get('exclude') and not r.get('deleted')]
    require(len(roots) == 1, 'Complete pristine declared Unsafe runtime Git source required'); root = roots[0]
    data_roots = [r for r in manifest['roots'] if r['name'] == ROOT_NAME]
    require(len(data_roots) == 1 and data_roots[0]['kind'] == 'tree' and data_roots[0].get('role') == ROLE
            and data_roots[0].get('commit') is None, 'Original Unsafe package container must retain its non-Git role')
    indexed, baseline = {}, {}; prefix = root['name'] + '/'
    with index_path.open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line); name = row['path']
            if name.startswith(prefix):
                require(name not in indexed and row.get('baseline'), 'Unique pristine Unsafe source baseline required')
                relative = name[len(prefix):]; indexed[name] = (True, relative, row); baseline[relative] = row['baseline']
            elif name.startswith(ROOT_NAME + '/'):
                require(name not in indexed, 'Duplicate original Unsafe data member'); indexed[name] = (False, name[len(ROOT_NAME) + 1:], row)
    for child in root.get('submodules', []): baseline[child['path']] = dict(mode='160000', blob=child['commit'])
    require(P.baseline_tree(baseline) == p['runtime']['tree'], 'Complete original Unsafe source Git tree differs')
    sources, actual, seen = {}, {}, set()
    with tarfile.open(archive_path, 'r|gz') as archive:
        for entry in archive:
            if entry.name not in indexed: continue
            source, name, expected = indexed[entry.name]
            require((entry.isfile() or entry.issym()) and entry.name not in seen and entry.size <= 64 * 1024**2, 'Bounded original Unsafe source archive member required')
            require((expected['mode'] == '120000' and entry.issym() and entry.mode == 0o777)
                    or (expected['mode'] in ('100644', '100755') and entry.isfile()
                        and entry.mode == (0o755 if expected['mode'] == '100755' else 0o644)
                        and entry.size == expected['bytes']), 'Original Unsafe source archive file type or mode differs')
            raw = entry.linkname.encode() if entry.issym() else archive.extractfile(entry).read()
            require(fingerprint(raw) == {k:expected[k] for k in FP}, 'Archived original Unsafe source bytes differ')
            if source:
                require(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == expected['baseline']['blob']
                        and expected['mode'] == expected['baseline']['mode'], 'Pristine original Unsafe source Git blob or mode differs')
                if name in p['runtime']['files']: sources[name] = raw
            else:
                require(entry.isfile(), 'Ordinary original Unsafe package data required'); actual[name] = raw
            seen.add(entry.name)
    require(seen == indexed.keys(), 'Complete original Unsafe source archive required')
    recipe = source_recipe(sources, p); original_r2r = actual.get('original-imported-r2r/System.Runtime.CompilerServices.Unsafe.dll')
    require(isinstance(original_r2r, bytes) and actual == bodies(inspect_package(package, p), original_r2r, recipe), 'Retained original Unsafe package and correspondence data differ')
    products = {name:dict(row, sourceRoot=root['name'], sourceCommit=p['runtime']['commit'], sourceBasis=p['sourceBasis'],
        canonicalPackageMember=dict(packageSha256=row['canonicalPackageSha256'], member=row['canonicalMember']),
        actualDerivedContainerMustBeValidatedByProducerContract=row['managedCorrespondenceRequired']) for name,row in p['products'].items()}
    return dict(kind=KIND, dataRoot=ROOT_NAME, products=products, publisherCompilerExecutionClaimed=False,
        localBuildClaimed=False, nativeCodeDerivationClaimed=False, qualificationAllowed=False, sourceAdmissionAllowed=False)
