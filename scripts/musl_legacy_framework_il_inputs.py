"""Corresponding preferred IL for one closed historical implementation set.

These are real implementations, not reference-only waivers. The authoritative
source-build-assets IL retains original method opcodes/tokens. Resources absent
from that IL are retained separately as exact blobs and fully readable strings
or XML. Neither original C# recovery nor local/bit-identical compilation is
claimed. Validation is offline and never loads a managed assembly.
"""
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
import tarfile
import uuid
import xml.etree.ElementTree as ET
import zipfile

ROOT_NAME = 'framework-implementation-il-inputs'
ROLE = 'upstream-full-il-and-original-resource-inputs'
KIND = 'reviewed-framework-implementation-il-source'
COMMIT = 'eccb0828682858d8daa029ba29adce07fd70d9a7'
SDK_COMMIT = 'a06803c09702777c6550fede13c8bdc52d780191'
PACKAGE_SHA = '6cf5b9719e6f7e2a078fe28db1f6d28fd7e2e48ecfa53c6d6d1c17b0cf3300ad'
CANONICAL_SHA = '218dd4c63d3f800de697bca41178827a52df0a9ec7a9b47520327d91ebc7051c'
FP = ('bytes', 'sha256', 'sha512')


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def portable(value):
    require(isinstance(value, str) and value and not any(c in value for c in '\\\0\r\n')
            and not PurePosixPath(value).is_absolute() and all(p not in ('', '.', '..') for p in value.split('/')),
            'An ordinary relative preferred-source path is required')
    return value


def ordinary(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Redirected preferred-source input is forbidden')
    return path


def module(name):
    spec = importlib.util.spec_from_file_location('framework_il_' + name, Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def policy():
    result = json.loads(Path(__file__).with_name('musl-legacy-framework-il-policy.json').read_bytes())
    require(result.get('schemaVersion') == 1 and result.get('sdkVersion') == '7.0.120'
            and result.get('kind') == 'closed-framework-implementation-preferred-il-source-policy'
            and result['package']['fingerprint']['sha256'] == PACKAGE_SHA
            and result['canonicalPackage']['fingerprint']['sha256'] == CANONICAL_SHA
            and result['preferredSource']['commit'] == COMMIT and result['sdkSource']['commit'] == SDK_COMMIT
            and len(result['layout']) == len({r['path'] for r in result['layout']}) == 27
            and len(result['preferredSource']['files']) == 137
            and result['totals'] == dict(exactMethodBodies=5289, methodILBytes=223725, noRvaMethods=55,
                                        resourceBlobs=22, resourceStrings=1410)
            and result['originalCSharpCommit'] == 'bd6a58d04fe8bd60452819571fd720513378ae0f'
            and all(result.get(k) is False for k in ('originalCSharpSourceRecovered', 'localBuildClaimed', 'byteIdenticalCompilationClaimed')),
            'The closed 27-implementation preferred-IL policy is required')
    return result


def pinned(path, identity):
    path = ordinary(path)
    require(path.is_file() and path.stat().st_size == identity['bytes'], 'An ordinary exact pinned framework input is required')
    raw = path.read_bytes(); require(fingerprint(raw) == identity, 'Immutable framework package bytes differ')
    return raw


def parse_il_methods(raw):
    """Read authoritative Ildasm token/opcode comments without executing IL."""
    require(isinstance(raw, bytes) and len(raw) <= 16 * 1024**2, 'Bounded preferred IL is required')
    methods, current = {}, None
    for line in raw.decode('utf-8-sig').splitlines():
        match = re.match(r'\s*\.method /\*([0-9A-Fa-f]{8})\*/', line)
        if match:
            token = int(match[1], 16)
            # Ildasm omits its end-of-method comment for body-free P/Invokes.
            require((current is None or current['rva'] is None and not current['body'] and current['codeSize'] is None)
                    and token >> 24 == 6 and token not in methods,
                    'Duplicate or nested original IL method declaration')
            current = dict(body=bytearray(), rva=None, codeSize=None, maxStack=None); methods[token] = current
        if current is None: continue
        for pattern, key, base in [(r'\s*// Method begins at RVA (0x[0-9A-Fa-f]+)', 'rva', 16),
                                   (r'\s*// Code size\s+(\d+)', 'codeSize', 10),
                                   (r'\s*\.maxstack\s+(\d+)', 'maxStack', 10)]:
            match = re.match(pattern, line)
            if match:
                require(current[key] is None, 'Duplicate original IL method header')
                current[key] = int(match[1], base)
        match = re.match(r'\s*(?:IL_([0-9A-Fa-f]+):\s*)?/\*\s*([0-9A-Fa-f ]*)\|\s*([^*]*)\*/', line)
        if match:
            require(match[1] is None or int(match[1], 16) == len(current['body']), 'Original IL instruction offset differs')
            opcode, operand = bytes.fromhex(match[2]), match[3].strip()
            token = re.fullmatch(r'\(([0-9A-Fa-f]{2})\)([0-9A-Fa-f]{6})', operand)
            value = int(token[1] + token[2], 16).to_bytes(4, 'little') if token else bytes.fromhex(operand)
            current['body'].extend(opcode + value)
            require(len(current['body']) <= 4 * 1024**2, 'Oversized preferred IL body')
        if '// end of method ' in line: current = None
    require(current is None or current['rva'] is None and not current['body'] and current['codeSize'] is None,
            'Unterminated original IL method')
    return methods


def resource_value(raw):
    """Decode only the two actual intrinsic resource formats in this set."""
    require(len(raw) <= 16 * 1024**2, 'Bounded original embedded resource required')
    if raw.startswith(b'<?xml'):
        require(b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'External XML entities are forbidden')
        ET.fromstring(raw)
        return dict(kind='xml', text=raw.decode('utf-8'))
    # The bounded string parser accepts ResourceTypeCode.String only; no
    # BinaryFormatter/object deserialization or opaque custom resources.
    return dict(kind='string-table', values=resource_strings(raw))


def correspondence(binary, il):
    """Bind every original method body, header/MVID and embedded resource."""
    view = table_view(binary); methods = parse_il_methods(il)
    require(len(methods) == view['counts'].get(6, 0), 'Complete preferred IL MethodDef set is required')
    rows, no_rva, il_bytes = [], 0, 0
    for rid in range(1, view['counts'].get(6, 0) + 1):
        at = view['row'](6, rid); rva = view['read']('<I', at, view['tables']); source = methods[0x06000000 | rid]
        if not rva:
            require(not source['body'] and source['codeSize'] is None, 'A body was invented for a body-free original method')
            no_rva += 1; continue
        start = view['address'](rva, 1); first = binary[start]
        if first & 3 == 2: size, begin, max_stack, flags, locals_token = first >> 2, start + 1, 8, 2, 0
        else:
            require(first & 3 == 3, 'Unsupported original IL method header')
            flags = view['read']('<H', start); size = view['read']('<I', start + 4)
            require(flags >> 12 == 3, 'An ordinary original fat IL header is required')
            begin = start + 12; max_stack = view['read']('<H', start + 2); locals_token = view['read']('<I', start + 8)
        require(size <= 4 * 1024**2 and begin + size <= len(binary), 'Escaped original IL body')
        actual = binary[begin:begin + size]
        require(bytes(source['body']) == actual and source['rva'] == rva and source['codeSize'] == size
                and source['maxStack'] == max_stack, 'Preferred upstream IL does not cover the exact original implementation')
        rows.append(dict(token=f'0x{0x06000000 | rid:08x}', rva=rva, bytes=size, sha256=hashlib.sha256(actual).hexdigest(),
                         maxStack=max_stack, headerFlags=flags, localSignatureToken=f'0x{locals_token:08x}'))
        il_bytes += size
    module_at = view['row'](0, 1); guid = view['number'](view['g'], module_at + 2 + view['s'])
    require(1 <= guid <= len(view['heaps'].get('#GUID', b'')) // 16, 'Original implementation MVID is absent')
    mvid = str(uuid.UUID(bytes_le=view['heaps']['#GUID'][(guid - 1) * 16:guid * 16]))
    require(re.search(r'// MVID: \{' + re.escape(mvid) + r'\}', il.decode('utf-8-sig'), re.I), 'Preferred IL MVID differs')
    resources, cli = [], view['cli']
    resource_rva, resource_size = view['read']('<I', cli + 24), view['read']('<I', cli + 28)
    start = view['address'](resource_rva, resource_size) if resource_size else None
    for rid in range(1, view['counts'].get(40, 0) + 1):
        at = view['row'](40, rid); offset = view['read']('<I', at, view['tables']); flags = view['read']('<I', at + 4, view['tables'])
        name = view['text'](view['number'](view['s'], at + 8))
        require(view['number'](view['impl'], at + 8 + view['s']) == 0 and start is not None and flags in (1, 2)
                and offset + 4 <= resource_size, 'Only exact original embedded managed resources are admitted')
        length = view['read']('<I', start + offset)
        require(length <= 16 * 1024**2 and offset + 4 + length <= resource_size, 'Escaped original embedded resource')
        raw = binary[start + offset + 4:start + offset + 4 + length]
        resources.append(dict(name=name, flags=flags, offset=offset, raw=raw, readable=resource_value(raw)))
    return dict(mvid=mvid, methodBodies=rows, noRvaMethods=no_rva, methodILBytes=il_bytes, resources=resources)


def origin():
    p = policy()
    return dict(schemaVersion=1, kind=KIND, basis='upstream-full-IL-source', primaryPackage=p['package'],
        canonicalTargetingPackage=p['canonicalPackage'], preferredSourceRepository=p['preferredSource']['repository'],
        preferredSourceCommit=COMMIT, originalCSharpCommit=p['originalCSharpCommit'], originalCSharpSourceRecovered=False,
        originalEmbeddedResourcesRetained=True, decodedResourceSourceRetained=True, realImplementations=27,
        localBuildClaimed=False, byteIdenticalCompilationClaimed=False)


def json_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode()


def reconstruction_il(binary, original_il, resource_directives):
    """Retain explicit original metadata lost/altered by ordinary reassembly.

    Pristine preferred Git IL is never changed. These separate derived inputs
    restore its commented original Debuggable attribute, one exact floating
    constant in each Compression DLL, and raw original permission bytes.
    """
    text = original_il.decode('utf-8-sig'); view = table_view(binary)
    text, attributes = re.subn(r'(?m)^(\s*)//\s*(\.custom[^\n]*DebuggableAttribute[^\n]*)$', r'\1\2', text)
    require(attributes == 1, 'One complete original commented Debuggable declaration must remain available')
    floats = []
    for rid in range(1, view['counts'].get(11, 0) + 1):
        at = view['row'](11, rid); width = view['coded'](2, [4, 8, 23]); parent = view['number'](width, at + 2)
        if parent & 3: continue
        field = view['row'](4, parent >> 2); name = view['text'](view['number'](view['s'], field + 2))
        if name != 'BadCompressionThreshold': continue
        value = view['blob'](view['number'](view['b'], at + 2 + width))
        require(view['read']('<H', at, view['tables']) == 0x0d and value == bytes.fromhex('000000000000f03f'),
                'Only the exact original Double 1.0 reconstruction constant is reviewed')
        floats.append(dict(field=name, originalBytes=value.hex(), explicitBits='0x3ff0000000000000'))
    if floats:
        require(len(floats) == 1, 'Exactly one closed original Compression constant is reviewed')
        text, count = re.subn(r'(\.field /\*040000[0-9A-Fa-f]{2}\*/ private static literal float64 BadCompressionThreshold = )float64\(1\)',
                             r'\g<1>float64(0x3ff0000000000000)', text)
        require(count == 1, 'Original upstream Double declaration differs')
    permissions, method_permissions = [], []
    for rid in range(1, view['counts'].get(14, 0) + 1):
        at = view['row'](14, rid); width = view['coded'](2, [2, 6, 32]); parent = view['number'](width, at + 2)
        action = view['read']('<H', at, view['tables'])
        raw = view['blob'](view['number'](view['b'], at + 2 + width))
        if action == 8 and parent == 6: permissions.append(raw.hex())
        else:
            # The two Http images also have an Assert on MethodDef 497.
            # Modern ILAsm changes assembly-name key capitalization inside
            # that serialized blob unless its exact original bytes are used.
            require((action, parent) == (3, 1989), 'Unreviewed original non-assembly permission declaration')
            token = f'{0x06000000 | (parent >> 2):08X}'
            require(token == '060001F1', 'Only the original Http assertion method is reviewed')
            start = text.find('.method /*' + token + '*/')
            finish = text.find('// end of method ', start)
            require(start >= 0 and finish > start, 'The original Http assertion method declaration is required')
            chunk = text[start:finish]
            replacement = '.permissionset assert = (' + ' '.join(f'{v:02X}' for v in raw) + ')'
            chunk, count = re.subn(r'(?m)^\s*\.permissionset assert\r?\n\s*= \{[^\n]+\}\r?$', replacement, chunk)
            require(count == 1, 'The exact original method assertion must be reconstructed in its original scope')
            text = text[:start] + chunk + text[finish:]
            method_permissions.append(dict(action=action, encodedParent=parent, methodToken='0x' + token, value=raw.hex()))
    if permissions:
        require(len(permissions) == 1, 'Exactly one original assembly permission set is reviewed')
        raw = bytes.fromhex(permissions[0]); replacement = '.permissionset reqmin = (' + ' '.join(f'{v:02X}' for v in raw) + ')'
        text, count = re.subn(r'(?m)^\s*\.permissionset reqmin\r?\n\s*= \{[^\n]+\}\r?$', replacement, text)
        require(count == 1, 'Complete original readable upstream permission declaration differs')
    text += '\n// Exact original embedded-resource complement.\n' + '\n'.join(resource_directives) + '\n'
    return text.encode(), dict(originalDebuggableDeclarationsRestored=attributes, floatingConstants=floats,
                               originalPermissionBlobs=permissions, originalMethodPermissionsRestored=method_permissions,
                               originalMethodInstructionsChanged=False)


def package_bodies(package, canonical_raw, sources):
    """Recompute readable supplemental inputs from the immutable packages."""
    p = policy(); package_raw = pinned(package, p['package']['fingerprint'])
    require(fingerprint(canonical_raw) == p['canonicalPackage']['fingerprint'], 'Canonical targeting package differs')
    bodies = {'packages/' + CANONICAL_SHA + '.nupkg': canonical_raw, 'origin.json': json_bytes(origin())}; products = {}; totals = dict(
        exactMethodBodies=0, methodILBytes=0, noRvaMethods=0, resourceBlobs=0, resourceStrings=0)
    with zipfile.ZipFile(io.BytesIO(package_raw)) as primary, zipfile.ZipFile(io.BytesIO(canonical_raw)) as canonical:
        for archive in (primary, canonical):
            entries = archive.infolist()
            require(len(entries) < 1000 and len({r.filename for r in entries}) == len(entries), 'Duplicate original framework ZIP members')
            require(all(r.file_size < 16 * 1024**2 and r.external_attr >> 16 & 0o170000 != 0o120000 for r in entries),
                    'Only ordinary bounded original framework package members are admitted')
        for row in p['layout']:
            raw = primary.read(row['packageMember'])
            require(fingerprint(raw) == row['fingerprint'] and raw == canonical.read(row['canonicalMember']),
                    'Original SDK copy must be byte-identical to its declared targeting dependency')
            il = sources[row['ilSourcePath']]; proof = correspondence(raw, il)
            require(proof['mvid'] == row['mvid'] and len(proof['methodBodies']) == row['methodBodies']
                    and proof['noRvaMethods'] == row['noRvaMethods'], 'Original framework method identity/counts differ')
            sha = row['fingerprint']['sha256']; resources, directives, il_directives = [], [], []
            for number, resource in enumerate(proof.pop('resources')):
                actual = dict(name=resource['name'], flags=resource['flags'], bytes=len(resource['raw']),
                              sha256=hashlib.sha256(resource['raw']).hexdigest(), kind=resource['readable']['kind'])
                resources.append(actual)
                stem = f'resources/{sha}/{number:02d}'
                bodies[stem + '.bin'] = resource['raw']; bodies[stem + '.json'] = json_bytes(resource['readable'])
                if resource['readable']['kind'] == 'xml': bodies[stem + '.xml'] = resource['raw']
                # This directive is readable complementary source. Actual
                # assembly/reconstruction evidence is reported separately.
                directives.append(dict(manifestName=resource['name'], flags=resource['flags'], rawInput=stem + '.bin',
                                       readableInput=stem + '.json', originalResourceOffset=resource['offset']))
                require(re.fullmatch(r'[A-Za-z0-9_.-]+', resource['name']), 'An ordinary closed original resource name is required')
                il_directives.append(".mresource " + ('public' if resource['flags'] == 1 else 'private')
                    + " '" + resource['name'] + "' as '" + stem + ".bin' {}")
                totals['resourceStrings'] += len(resource['readable'].get('values', {}))
            require(resources == row['resources'], 'Every original embedded resource must have exact full readable source')
            proof.update(resources=directives, preferredILSource=row['ilSourcePath'], originalResourceDeclarationsMissingInUpstreamIL=True)
            bodies['correspondence/' + sha + '.json'] = json_bytes(proof)
            bodies['resource-supplements/' + sha + '.json'] = json_bytes(dict(schemaVersion=1,
                kind='original-embedded-resource-complement-to-upstream-il', declarations=directives))
            bodies['resource-supplements/' + sha + '.il'] = (
                '// Original resource complement; assemble with the pristine preferred IL, from this data root.\n'
                + '\n'.join(il_directives) + '\n').encode()
            reconstruction, adjustments = reconstruction_il(raw, il, il_directives)
            bodies['reconstruction/' + sha + '.il'] = reconstruction
            bodies['reconstruction/' + sha + '.json'] = json_bytes(adjustments)
            products[row['path']] = row['fingerprint']; totals['exactMethodBodies'] += len(proof['methodBodies'])
            totals['methodILBytes'] += proof['methodILBytes']; totals['noRvaMethods'] += proof['noRvaMethods']; totals['resourceBlobs'] += len(resources)
        for name in canonical.namelist():
            if name.lower().endswith(('.nuspec', 'license.txt', 'thirdpartynotices.txt', 'third-party-notices.txt', 'version.txt', '.props', '.targets')):
                bodies['original-targeting-metadata/' + portable(name)] = canonical.read(name)
        specs = [n for n in primary.namelist() if n.endswith('.nuspec')]
        require(len(specs) == 1, 'One original SDK extensions nuspec is required')
        bodies['original-build-extensions.nuspec'] = primary.read(specs[0])
    require(totals == p['totals'], 'Complete original implementation/resource totals differ')
    bodies['correspondence-summary.json'] = json_bytes(totals)
    return bodies, products


def source_chain(sources, sdk):
    p = policy(); versions = ET.fromstring(sdk['eng/Versions.props'])
    require([r.text for r in versions.iter() if r.tag.rsplit('}', 1)[-1] == 'NETStandardLibraryNETFrameworkVersion'] == [p['canonicalPackage']['version']],
            'Original SDK targeting dependency version differs')
    project = sdk['src/Tasks/Microsoft.NET.Build.Extensions.Tasks/Microsoft.NET.Build.Extensions.Tasks.csproj']
    require(b'<PackageReference Include="NETStandard.Library.NETFramework" Version="$(NETStandardLibraryNETFrameworkVersion)"' in project
            and b'$(NuGetPackageRoot)netstandard.library.netframework\\$(NETStandardLibraryNETFrameworkVersion)\\build' in project
            and b'$(_NETStandardLibraryNETFrameworkPath)\\**\\*' in project
            and b'$(_NETStandardLibraryNETFrameworkPath)\\**\\*.props;$(_NETStandardLibraryNETFrameworkPath)\\**\\*.targets' in project
            and b'CopyAdditionalFilesToLayout' in project and b'PrepareAdditionalFilesToLayout' in project
            and b'Microsoft.NET.Build.Extensions\\%(NetStandardNetFxFile.RecursiveDir)' in project,
            'The original unchanged target-library copy recipe is required')
    require(b'BuildIlFile' in sources['src/targetPacks/Directory.Build.targets']
            and b'build-il.sh' in sources['src/targetPacks/Directory.Build.targets']
            and b'ilasm' in sources['src/targetPacks/build-il.sh']
            and b'MIT License' in sdk['LICENSE.TXT'] and b'MIT License' in sources['LICENSE.txt'],
            'Preferred IL build recipe and complete original source/binary MIT notices are required')


def prepare(package, canonical, sdk_source, assets_source, destination):
    """Retain immutable package/resource inputs alongside full pristine Git."""
    p = policy(); sources = {}; sdk = {}
    for source, declared, output in [(assets_source, p['preferredSource'], sources), (sdk_source, p['sdkSource'], sdk)]:
        source = ordinary(source)
        require(subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), '-C', str(source), 'rev-parse', 'HEAD'],
                                       text=True).strip() == declared['commit'], 'Exact preferred-source Git commit is required')
        for name, identity in declared['files'].items():
            raw = ordinary(source / portable(name)).read_bytes()
            require(fingerprint(raw) == {k: identity[k] for k in FP}
                    and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == identity['gitBlob'],
                    'Preferred source must retain its complete pristine Git bytes')
            output[name] = raw
    source_chain(sources, sdk)
    bodies, _ = package_bodies(package, pinned(canonical, p['canonicalPackage']['fingerprint']), sources)
    bodies['licenses/original-sdk-MIT.txt'] = sdk['LICENSE.TXT']
    destination = ordinary(destination); require(not destination.exists(), 'A fresh preferred-IL supplemental input tree is required')
    destination.mkdir(parents=True)
    for name, raw in bodies.items():
        target = destination / portable(name); target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream: stream.write(raw)
    return dict(name=ROOT_NAME, kind='tree', path=str(destination), role=ROLE)


def validate(release, manifest, package):
    """Validate full archived preferred IL, copy/version chain and resources."""
    p = policy(); release = ordinary(release); expected, git_paths, root_names = {}, {}, {}
    for key, declared in [('assets', p['preferredSource']), ('sdk', p['sdkSource'])]:
        matches = [r for r in manifest['roots'] if r.get('commit') == declared['commit'] and r['kind'] in ('git', 'git-export')]
        require(len(matches) == 1 and not matches[0].get('deleted'), 'Complete original preferred-IL and SDK Git roots are required')
        root_names[key] = portable(matches[0]['name'])
        for name, identity in declared['files'].items():
            path = root_names[key] + '/' + portable(name); expected[path] = {k: identity[k] for k in FP}
            git_paths[path] = (key, name, identity['gitBlob'])
    roots = [r for r in manifest['roots'] if r['name'] == ROOT_NAME]
    require(len(roots) == 1 and roots[0]['kind'] == 'tree' and roots[0].get('role') == ROLE and roots[0].get('commit') is None,
            'Original resource complements must retain a distinct data-only source root')
    index = {}
    with (release / 'sources' / portable(manifest['index']['path'])).open() as stream:
        for line in stream:
            row = json.loads(line)
            if row['path'] in expected or row['path'].startswith(ROOT_NAME + '/'):
                require(row['path'] not in index, 'Duplicate original framework source index member'); index[row['path']] = row
    require(set(expected) <= index.keys() and all(all(index[n].get(k) == value[k] for k in FP) for n, value in expected.items()),
            'Complete pinned upstream IL and original SDK copy source are required in the source index')
    actual, sources, sdk, data = set(), {}, {}, {}
    with tarfile.open(release / 'sources' / portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if entry.name not in index: continue
            require(entry.isfile() and entry.name not in actual and entry.size == index[entry.name]['bytes'] and entry.size <= 16 * 1024**2,
                    'An ordinary bounded complete preferred-source archive member is required')
            raw = archive.extractfile(entry).read(); identity = fingerprint(raw)
            require(all(index[entry.name].get(k) == identity[k] for k in FP), 'Archived implementation/source/resource bytes differ')
            actual.add(entry.name)
            if entry.name in git_paths:
                key, name, blob = git_paths[entry.name]
                require(index[entry.name].get('baseline', {}).get('blob') == blob
                        and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == blob,
                        'Full preferred IL and SDK recipe must retain exact original pristine Git blobs')
                (sources if key == 'assets' else sdk)[name] = raw
            else: data[entry.name[len(ROOT_NAME) + 1:]] = raw
    require(actual == index.keys(), 'Archived framework implementation/resource source is incomplete')
    source_chain(sources, sdk)
    canonical = data.get('packages/' + CANONICAL_SHA + '.nupkg')
    require(canonical is not None, 'Original canonical targeting package must remain in the source archive')
    bodies, products = package_bodies(package, canonical, sources); bodies['licenses/original-sdk-MIT.txt'] = sdk['LICENSE.TXT']
    require(data == bodies, 'Every raw resource and complete readable complement must match the original exact implementation')
    return dict(kind=KIND, basis='upstream-full-IL-source', sourceRoot=root_names['assets'], sourceCommit=COMMIT,
        dataRoot=ROOT_NAME, sdkSourceRoot=root_names['sdk'], sdkSourceCommit=SDK_COMMIT,
        canonicalPackage=p['canonicalPackage'], products=products, allowedLayoutPaths=sorted(products),
        originalCSharpSourceRecovered=False, originalEmbeddedResourcesRetained=True, decodedResourceSourceRetained=True,
        localBuildClaimed=False, byteIdenticalCompilationClaimed=False)


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
