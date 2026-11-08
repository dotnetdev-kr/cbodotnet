"""Derive three honest compiler inputs from the exact matching musl SDK.

These are local packages, never publisher NUPKGs or claims of local compiler
construction. Original source definitions, licenses, baseline packages and
every copied SDK member remain independently identifiable.
"""
import copy
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import struct
import subprocess
import tarfile
import xml.etree.ElementTree as ET
import zipfile

import musl_managed_metadata as MANAGED

SDK = '5.0.214'
SDK_HASHES = {
    'aarch64': '92ce80320a73f742672c99318e66cfaf375876fb8320d053cd64d6b53a9c365bb2774fecbed3714646abf6f3eba72286246013cb8d80fc087b5908fcdfbfeffb',
    'x64': '39261405f6c05216da2fbd6b3aaff1ac1ed4681bb017f0127edbf62935329acf4334ff889fce1273b65fe02d82efe4679dec050c74353717c16e7bbc10c3de24'}
SOURCES = {
    'fsharp': ('https://github.com/dotnet/fsharp', '7ce7132f1459095e635194d09d6f73265352029a'),
    'roslyn': ('https://github.com/dotnet/roslyn', 'f8111b17631aa5e2703dc11acd671c6ea22c3af1'),
    'roslyn-codestyle': ('https://github.com/dotnet/roslyn', '4c195c3ac1974edcefa76774d7a59a2350ec55fa'),
    'compiler-framework': ('https://github.com/dotnet/runtime', 'cf258a14b70ad9069470a108f13765e0e5988f51')}
BASELINES = {
    'System.Runtime.CompilerServices.Unsafe.dll': ('system.runtime.compilerservices.unsafe', 130329, '9de0114a92cf5333f110a849470a01ce13f12be70a222b4bc7b58162772c620a'),
    'System.Reflection.Metadata.dll': ('system.reflection.metadata', 1006081, '5a8f8c8aa85c3fd750e8db851ab413c3a8696c9391170a7e4c1353ab6ca11a9f'),
    'System.Collections.Immutable.dll': ('system.collections.immutable', 623075, '19dc122232cc334b957c4e7a55448b54d8295b407ffe809e4858fcfe14a56ccf')}
SPECS = {
    'fsharp': ('Microsoft.FSharp.Compiler', '11.3.2-beta.21102.9', ['src/fsharp/Microsoft.FSharp.Compiler/Microsoft.FSharp.Compiler.nuspec']),
    'roslyn': ('Microsoft.Net.Compilers.Toolset', '3.9.0-6.21273.1', ['src/NuGet/Microsoft.Net.Compilers.Toolset/Microsoft.Net.Compilers.Toolset.Package.csproj', 'src/NuGet/Microsoft.Net.Compilers.Toolset/CoreClrCompilerArtifacts.targets']),
    'roslyn-codestyle': ('Microsoft.CodeAnalysis.VisualBasic.CodeStyle', '3.8.0-5.20519.18', ['src/CodeStyle/VisualBasic/CodeFixes/build/Microsoft.CodeAnalysis.VisualBasic.CodeStyle.props', 'src/CodeStyle/VisualBasic/CodeFixes/Microsoft.CodeAnalysis.VisualBasic.CodeStyle.Fixes.vbproj'])}
PREFIXES = ('FSharp/', 'Roslyn/', 'Sdks/Microsoft.NET.Sdk/codestyle/vb/')


def require(value, message):
    if not value: raise ValueError(message)


def fp(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def file_fp(path):
    hashes = {n: hashlib.new(n) for n in ('sha256', 'sha512')}; size = 0
    with Path(path).open('rb') as stream:
        for raw in iter(lambda: stream.read(1024**2), b''):
            size += len(raw)
            for h in hashes.values(): h.update(raw)
    return dict(bytes=size, **{n: h.hexdigest() for n, h in hashes.items()})


def ordinary(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary compiler input paths required')
    return path


def member(name):
    require(isinstance(name, str) and name and not any(c in name for c in ':\\\0\r\n')
            and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')),
            'Confined ordinary compiler input member required')
    return name


def git(source, *args):
    return subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), '-C', str(source), *args])


def source_file(source, commit, relative):
    member(relative); path = ordinary(source / relative)
    raw = git(source, 'show', commit + ':' + relative)
    require(path.is_file() and path.read_bytes() == raw, 'Original preferred compiler source definition changed: ' + relative)
    return raw


def check_sources(roots):
    require(set(roots) == set(SOURCES), 'Four exact full compiler/source dependency roots required')
    for name, (repository, commit) in SOURCES.items():
        source = ordinary(roots[name])
        require(git(source, 'rev-parse', 'HEAD').decode().strip() == commit
                and git(source, 'config', '--get', 'remote.origin.url').decode().strip().removesuffix('.git') == repository,
                'Exact full compiler Git origin/commit required: ' + name)


def selected_sdk(path, architecture):
    require(architecture in SDK_HASHES, 'A reviewed native musl compiler architecture required')
    path = ordinary(path); actual = file_fp(path)
    require(0 < actual['bytes'] <= 512 * 1024**2 and actual['sha512'] == SDK_HASHES[architecture],
            'Exact official matching musl SDK archive required')
    files, seen, total = {}, set(), 0
    with tarfile.open(path, 'r|gz') as archive:
        for entry in archive:
            name = entry.name.removeprefix('./').rstrip('/') if entry.isdir() else entry.name.removeprefix('./')
            if name in ('', '.'): require(entry.isdir(), 'Only an archive root directory may omit its name'); continue
            member(name)
            require(entry.isfile() or entry.isdir(), 'Compiler comparison SDK links/devices are forbidden')
            require(name not in seen, 'Duplicate compiler comparison SDK member'); seen.add(name)
            if entry.isdir(): continue
            require(0 <= entry.size <= 128 * 1024**2, 'Bounded compiler comparison SDK file required')
            total += entry.size; require(total <= 2 * 1024**3, 'Compiler comparison SDK exceeds its expansion bound')
            prefix = 'sdk/' + SDK + '/'
            if not name.startswith(prefix): continue
            relative = name[len(prefix):]
            if not any(relative.startswith(p) for p in PREFIXES): continue
            raw = archive.extractfile(entry).read(); require(len(raw) == entry.size and not raw.startswith(b'\x7fELF'),
                'Compiler input may not import an ELF payload')
            files[relative] = raw
    require(all(any(n.startswith(p) for n in files) for p in PREFIXES), 'All three matching compiler input subtrees required')
    return files, actual


def inspect_pe(raw, architecture, expected_commit=None, il_only=False):
    info = MANAGED.inspect(raw)
    require(not info['cliFlags'] & 16, 'Managed-native compiler entry point is forbidden')
    pe = struct.unpack_from('<I', raw, 0x3c)[0]; machine = struct.unpack_from('<H', raw, pe + 4)[0]
    if info['managedNativeHeaderBytes']:
        require(not il_only and machine == (0x7b79 ^ {'aarch64': 0xaa64, 'x64': 0x8664}[architecture]),
                'Compiler ReadyToRun image is not the exact native Linux musl architecture')
        # Validate the actual managed-native header, not merely its size.
        optional = pe + 24; magic = struct.unpack_from('<H', raw, optional)[0]
        dd = optional + (96 if magic == 0x10b else 112)
        count = struct.unpack_from('<H', raw, pe + 6)[0]; size = struct.unpack_from('<H', raw, pe + 20)[0]
        sections = [struct.unpack_from('<IIII', raw, optional + size + n * 40 + 8) for n in range(count)]
        def address(rva, length):
            matches = [offset + rva - start for virtual, start, extent, offset in sections if start <= rva and rva + length <= start + extent]
            require(len(matches) == 1 and matches[0] + length <= len(raw), 'Compiler managed-native RVA escaped its section')
            return matches[0]
        cli = address(struct.unpack_from('<I', raw, dd + 14 * 8)[0], 72)
        rva, length = struct.unpack_from('<II', raw, cli + 64)
        require(length == info['managedNativeHeaderBytes'] and raw[address(rva, length):][:4] == b'RTR\0',
                'An actual unchanged ReadyToRun compiler header required')
    else:
        require(info['cliFlags'] & 1, 'Portable IL compiler input required')
    values = info['attributes'].get('System.Reflection.AssemblyInformationalVersionAttribute', [])
    if expected_commit is not None:
        require(any(expected_commit in value for value in values if value), 'Compiler input embedded source identity differs')
    return dict(machine=machine, **info)


def canonical_metadata(info):
    """AssemblyMetadata pairs are unordered attributes, never flattened strings."""
    result = copy.deepcopy(info); name = 'System.Reflection.AssemblyMetadataAttribute'
    values = result['attributes'].get(name)
    if values is not None:
        require(len(values) % 2 == 0, 'Complete original assembly-metadata key/value pairs required')
        result['attributes'][name] = sorted(zip(values[::2], values[1::2]))
    return result


def baseline(path, filename, sdk_raw):
    identity, size, sha = BASELINES[filename]; path = ordinary(path); raw = path.read_bytes()
    require(len(raw) == size and fp(raw)['sha256'] == sha, 'Exact original Roslyn baseline NUPKG required')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist(); require(len(names) == len(set(names)), 'Duplicate baseline package member')
        for name in names: member(name.rstrip('/') if name.endswith('/') else name)
        specs = [n for n in names if '/' not in n and n.endswith('.nuspec')]
        require(len(specs) == 1, 'Unique original baseline package metadata required')
        metadata = ET.fromstring(archive.read(specs[0])).find('{*}metadata'); repository = metadata.find('{*}repository')
        require(metadata.findtext('{*}id').lower() == identity and metadata.findtext('{*}version') == '5.0.0'
                and repository is not None and repository.attrib.get('commit') == SOURCES['compiler-framework'][1],
                'Exact original framework baseline source chain required')
        sdk_metadata = canonical_metadata(MANAGED.inspect(sdk_raw))
        fields = ('assemblyName', 'assemblyVersion', 'culture', 'publicKeyToken', 'attributes',
                  'references', 'definitionCounts', 'entryPoint')
        matches, exact = [], []
        for name in names:
            if not name.endswith('/' + filename): continue
            body = archive.read(name); decoded = canonical_metadata(MANAGED.inspect(body))
            if all(decoded[key] == sdk_metadata[key] for key in fields): matches.append(name)
            if body == sdk_raw: exact.append(name)
        require(matches, 'Actual SDK compiler baseline metadata has no original package counterpart')
    return raw, dict(id=identity, version='5.0.0', originalPackage=fp(raw), originalMembers=matches,
        originalByteIdenticalMembers=exact, byteIdentityClaimed=bool(exact),
        comparison='Assembly identity, attributes, references and definition counts; SDK native R2R bytes remain original and are not claimed equal to package IL',
        sourceRepository=SOURCES['compiler-framework'][0], sourceCommit=SOURCES['compiler-framework'][1])


def json_bytes(value): return (json.dumps(value, indent=2) + '\n').encode()


def package(name, contents, origin, definitions, licenses, destination):
    identity, version, unused = SPECS[name]; ns = 'http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd'
    ET.register_namespace('', ns); tag = lambda value: '{' + ns + '}' + value
    document = ET.Element(tag('package')); metadata = ET.SubElement(document, tag('metadata'))
    for key, value in [('id', identity), ('version', version), ('authors', 'cbodotnet local-derived input; original Microsoft components'),
        ('description', 'Locally derived exact matching musl SDK compiler input. This is not the original publisher nupkg. See cbodotnet-provenance/origin.json.'), ('developmentDependency', 'true')]:
        ET.SubElement(metadata, tag(key)).text = value
    ET.SubElement(metadata, tag('license'), {'type': 'expression'}).text = 'MIT'
    ET.SubElement(metadata, tag('repository'), dict(type='git', url=SOURCES[name][0], commit=SOURCES[name][1]))
    if name == 'fsharp':
        original = ET.fromstring(next(iter(definitions.values()))).find('{*}metadata')
        for child in original:
            if child.tag.rsplit('}', 1)[-1] in ('dependencies', 'contentFiles'): metadata.append(copy.deepcopy(child))
    contents[identity + '.nuspec'] = ET.tostring(document, encoding='utf-8', xml_declaration=True)
    for relative, raw in licenses.items(): contents['cbodotnet-provenance/licenses/' + relative] = raw
    origin.update(schemaVersion=1, kind='local-derived-matching-musl-sdk-managed-component-input', packageId=identity,
        packageVersion=version, sourceCommit=SOURCES[name][1], repository=SOURCES[name][0],
        originalPublisherNupkg=False, compilerLocallySourceBuiltClaimed=False, originalSdkUsedAsProduct=False,
        sourceVersionApproximation=False, nativeElfImported=False, headerStripping=False,
        originalDefinitions=[dict(path=n, **fp(raw)) for n, raw in sorted(definitions.items())],
        files=[dict(packageMember=n, **fp(raw)) for n, raw in sorted(contents.items())],
        qualificationAllowed=False, sourceAdmissionAllowed=False)
    for relative, raw in definitions.items(): contents['cbodotnet-provenance/original-definitions/' + relative] = raw
    contents['cbodotnet-provenance/origin.json'] = json_bytes(origin)
    path = destination / (identity + '.' + version + '.nupkg')
    with zipfile.ZipFile(path, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for relative, raw in sorted(contents.items()):
            member(relative); info = zipfile.ZipInfo(relative, (2000, 1, 1, 0, 0, 0)); info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16; archive.writestr(info, raw)
    result = {**origin, 'package': dict(path=path.name, **file_fp(path))}
    (destination / (identity + '.origin.json')).write_bytes(json_bytes(result))
    return result


def prepare(sdk_archive, architecture, roots, baseline_packages, destination):
    destination = ordinary(destination); require(not destination.exists(), 'Fresh derived compiler input directory required')
    check_sources(roots); require(set(baseline_packages) == set(BASELINES), 'All three separate original framework baseline packages required')
    files, original_sdk = selected_sdk(sdk_archive, architecture); destination.mkdir(parents=True)
    rid = 'linux-musl-' + {'aarch64': 'arm64', 'x64': 'x64'}[architecture]; records = []
    for name in SPECS:
        source = Path(roots[name]); commit = SOURCES[name][1]
        definitions = {relative: source_file(source, commit, relative) for relative in SPECS[name][2]}
        licenses = {relative: source_file(source, commit, relative) for relative in
            git(source, 'ls-tree', '--name-only', commit).decode().splitlines()
            if any(word in relative.lower() for word in ('license', 'notice')) and (source / relative).is_file()}
        require(licenses, 'Original compiler license/notice files required')
        contents, mapping, pe_rows, framework = {}, [], [], []
        def add(target, sdk_relative):
            require(target not in contents, 'Duplicate derived compiler asset')
            raw = files[sdk_relative]; contents[target] = raw
            mapping.append(dict(packageMember=target, sdkMember='sdk/' + SDK + '/' + sdk_relative, **fp(raw)))
            if raw.startswith(b'MZ'):
                baseline_name = PurePosixPath(sdk_relative).name if name == 'roslyn' else None
                separate = baseline_name in BASELINES
                metadata = inspect_pe(raw, architecture, None if separate else commit, name == 'roslyn-codestyle')
                pe_rows.append(dict(packageMember=target, sourceCommit=SOURCES['compiler-framework'][1] if separate else commit, metadata=metadata, **fp(raw)))
                if separate:
                    package_raw, record = baseline(baseline_packages[baseline_name], baseline_name, raw)
                    contents['cbodotnet-provenance/actual-baseline-packages/' + record['id'] + '.5.0.0.nupkg'] = package_raw
                    framework.append(dict(packageMember=target, **record))
        if name == 'fsharp':
            template = ET.fromstring(next(iter(definitions.values())))
            for item in template.iter():
                if item.tag.rsplit('}', 1)[-1] != 'file': continue
                original = item.attrib['src'].replace('\\', '/'); filename = PurePosixPath(original).name
                target = item.attrib['target'].replace('\\', '/')
                require('**/' in original or '*' not in original, 'Unreviewed original FSharp file glob')
                candidates = sorted(n for n in files if n.startswith('FSharp/') and
                    ((len(n.split('/')) == 3 and n.endswith('/' + filename)) if '**/' in original else n == 'FSharp/' + filename))
                require(candidates, 'An original owned FSharp compiler asset is absent: ' + original)
                for relative in candidates:
                    suffix = (PurePosixPath(relative).parent.name + '/' if '**/' in original else '') + filename
                    add(target + '/' + suffix, relative)
        elif name == 'roslyn':
            for relative in sorted(n for n in files if n.startswith('Roslyn/')): add('tasks/netcoreapp3.1/' + relative[len('Roslyn/'):], relative)
            require(len(framework) == 3, 'All three actual Roslyn framework baselines required')
            build = Path(SPECS[name][2][0]).parent / 'build'
            for relative in git(source, 'ls-tree', '-r', '--name-only', commit, '--', build.as_posix()).decode().splitlines():
                contents['build/' + PurePosixPath(relative).relative_to(build.as_posix()).as_posix()] = source_file(source, commit, relative)
        else:
            prefix = PREFIXES[2]
            for relative in sorted(n for n in files if n.startswith(prefix)): add('analyzers/dotnet/vb/' + relative[len(prefix):], relative)
            contents['build/Microsoft.CodeAnalysis.VisualBasic.CodeStyle.props'] = definitions[SPECS[name][2][0]]
        records.append(package(name, contents, dict(originalSdk=dict(version=SDK, rid=rid, **original_sdk),
            architecture=architecture, filesFromSdk=mapping, managedInputs=pe_rows, additionalFrameworkSources=framework,
            scope={'fsharp': 'All original nuspec owned assets, dependency/content contract and cultures',
                   'roslyn': 'Complete original SDK CoreCLR compiler subtree; no desktop/net472 compiler payload',
                   'roslyn-codestyle': 'Exact VB/shared CodeStyle IL-only analyzers and cultures'}[name]), definitions, licenses, destination))
    result = dict(schemaVersion=1, sdkVersion=SDK, inputs=records, qualificationAllowed=False, sourceAdmissionAllowed=False)
    (destination / 'inputs.json').write_bytes(json_bytes(result)); return result
