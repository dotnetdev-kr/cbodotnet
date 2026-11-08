"""SDK6's one-worker native runtime source and actual version contract.

Native-only checks do not establish final SDK consumption. Normal admission
also binds every copy of all five products to the actual SDK member inventory.
"""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import struct
import tarfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
SDK, RUNTIME = '6.0.136', '6.0.36'
COMMIT = 'f1dd57165bfd91875761329ac3a8b17f6606ad18'
TREE = 'b4f7aaf1f454cfe6fa3fae6ce17455612ff1d13b'
BACKPORT = '35a39e97345abfda05e14f609759760b37ddeb4d'
PATCHES = {
    'patches/net6-musl/0003-guard-runtime-only-reflection-cache-mutations-in-dac.patch': (
        '773dd9dae8c3e82d7f04831da915893210bc8cd71541cec6c98aed3918b84c34', 'src/coreclr/vm/comreflectioncache.hpp'),
    'patches/net6-musl/0004-backport-metadata-local-allocation-marker.patch': (
        '555f4aa0cd4cb67ce9b316081625dcb9893a812509c161ccfe06486438f37d5b', 'src/coreclr/md/runtime/metamodel.cpp')}
PRODUCTS = {'libcoreclr.so': 'dlls/mscoree/coreclr/libcoreclr.so', 'libclrjit.so': 'jit/libclrjit.so',
    'libmscordaccore.so': 'dlls/mscordac/libmscordaccore.so', 'libmscordbi.so': 'dlls/mscordbi/libmscordbi.so',
    'libcoreclrtraceptprovider.so': 'pal/src/eventprovider/lttngprovider/libcoreclrtraceptprovider.so'}
TARGETS = ['coreclr', 'clrjit', 'mscordaccore', 'mscordbi', 'coreclrtraceptprovider']
FP = ('bytes', 'sha256', 'sha512')


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def pristine_runtime(P, row, raw):
    # The pinned runtime's original .gitattributes requires CRLF for .sln,
    # .cmd and .bat. Canonical bytes must still recover the exact Git blob.
    blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    windows = row['path'].lower().endswith(('.cmd', '.bat', '.sln'))
    return P.pristine_blob(row, blob, raw if windows else None,
                           allow_audited_crlf=row['path'].lower().endswith('.sln'))


def ordinary(path):
    path = Path(path).absolute()
    require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary SDK6 native input required')
    return path


def versions(first, header, compiled, compiled_header, result):
    require(first == compiled and header == compiled_header and b'42.42.42' not in compiled,
            'Actual compiled SDK6 version inputs must equal their original dated producer')
    macros = dict(re.findall(rb'^#define (Runtime(?:Assembly|File)(?:Major|Minor|Build|Revision)Version) ([0-9]+)$', header, re.M))
    def version(kind, fields):
        keys = [('Runtime' + kind + name + 'Version').encode() for name in fields]
        require(all(key in macros for key in keys), 'Complete original native version header required')
        return '.'.join(macros[key].decode() for key in keys)
    assembly = version('Assembly', ('Major', 'Minor')); file = version('File', ('Major', 'Minor', 'Build', 'Revision'))
    require(assembly == result['runtimeAssemblyVersion'] == '6.0' and file == result['nativeFileVersion']
            and re.fullmatch(r'6\.0\.[0-9]+\.[0-9]+', file)
            and all(0 <= int(part) <= 65535 for part in file.split('.'))
            and b'#define RuntimeProductVersion 6.0.36' in header
            and re.fullmatch(r'[0-9]{8}\.[1-9][0-9]*', result['buildId']), 'Original SDK6 ABI/product/dated file version differs')
    marker = ('@(#)Version ' + file + ' @Commit: ' + COMMIT).encode()
    require(compiled.count(marker) == 1 and COMMIT.encode() in compiled, 'Original native version source must contain exact dated commit marker')
    return marker


def elf_version(raw, marker):
    require(re.findall(rb'@\(#\)Version [^\x00\r\n]+', raw) == [marker]
            and b'42.42.42.42424' not in raw, 'Actual SDK6 native ELF has missing, fallback or mixed version identities')


def sections(raw):
    require(len(raw) >= 64 and raw[:6] == b'\x7fELF\x02\x01', 'Native SDK6 ELF64 little-endian input required')
    start = struct.unpack_from('<Q', raw, 40)[0]; width, count, strings = struct.unpack_from('<HHH', raw, 58)
    require(width >= 64 and 0 < count <= 65535 and strings < count and start + width * count <= len(raw), 'Bounded native ELF section table required')
    rows = [struct.unpack_from('<IIQQQQIIQQ', raw, start + width * index) for index in range(count)]
    names = rows[strings]; require(names[4] + names[5] <= len(raw), 'Native ELF section names are truncated')
    table = raw[names[4]:names[4] + names[5]]; result = {}
    for row in rows:
        require(row[0] < len(table), 'Native ELF section name offset differs')
        end = table.find(b'\0', row[0]); require(end >= 0, 'Terminated native ELF section name required')
        name = table[row[0]:end].decode('ascii')
        if not name: continue
        require(name not in result, 'Duplicate native ELF section name')
        if row[1] == 8: continue  # SHT_NOBITS has no file body.
        require(row[4] + row[5] <= len(raw), 'Native ELF section bytes are truncated')
        result[name] = raw[row[4]:row[4] + row[5]]
    return result


def debug_binding(binary, debug, filename):
    normal, sidecar = sections(binary), sections(debug)
    require(normal.get('.note.gnu.build-id') and normal['.note.gnu.build-id'] == sidecar.get('.note.gnu.build-id'),
            'Native SDK6 ELF/debug build identities differ')
    link = normal.get('.gnu_debuglink', b''); end = link.find(b'\0')
    require(end > 0 and link[:end].decode('ascii') == filename and len(link) == ((end + 1 + 3) & ~3) + 4,
            'Exact original SDK6 debug sidecar link required')
    require(struct.unpack_from('<I', link, (end + 1 + 3) & ~3)[0] == zlib.crc32(debug) & 0xffffffff,
            'Native SDK6 debug sidecar CRC differs')


def compiler_database(rows, source, obj):
    require(isinstance(rows, list) and 100 <= len(rows) <= 20000, 'Complete bounded SDK6 native compiler database required')
    version_rows = 0; features = set()
    for row in rows:
        require(set(row) == {'directory', 'command', 'file', 'output'} and row['directory'].startswith(source + '/artifacts/obj/')
                and row['directory'] == posixpath.normpath(row['directory'])
                and row['file'].startswith((source + '/src/', source + '/artifacts/obj/'))
                and row['file'] == posixpath.normpath(row['file']), 'Native compiler input escaped the original SDK6 source/build tree')
        argv = shlex.split(row['command'])
        optimization = [arg for arg in argv if arg.startswith('-O')]
        original_optimization = ['-O3', '-O3', '-O0'] if row['file'] == source + '/src/coreclr/ilasm/prebuilt/asmparse.cpp' else ['-O3', '-O3']
        require(argv and argv[0] in ('/usr/lib/llvm20/bin/clang', '/usr/lib/llvm20/bin/clang++')
                and argv.count('-c') == argv.count('-o') == 1
                and argv.index('-c') + 1 < len(argv) and argv.index('-o') + 1 < len(argv)
                and argv[argv.index('-c') + 1] == row['file']
                and optimization == original_optimization,
                'Original SDK6 source/compiler/optimization operands differ')
        actual_output = posixpath.normpath(posixpath.join(row['directory'], argv[argv.index('-o') + 1]))
        recorded_output = posixpath.normpath(posixpath.join(obj, row['output']))
        require(actual_output == recorded_output and actual_output.startswith(source + '/artifacts/obj/'),
                'Actual SDK6 compiler output differs from its original compilation database')
        features.update(arg for arg in argv if arg in ('-DFEATURE_PGO', '-DFEATURE_READYTORUN', '-DFEATURE_EVENT_TRACE', '-DFEATURE_PERFTRACING'))
        version_rows += row['file'] == obj + '/version.c'
    require(version_rows >= 5 and features == {'-DFEATURE_PGO', '-DFEATURE_READYTORUN', '-DFEATURE_EVENT_TRACE', '-DFEATURE_PERFTRACING'},
            'Actual dated version source and original PGO/ReadyToRun/tracing definitions required')
    return dict(entries=len(rows), versionSourceEntries=version_rows)


def build_boundary(B, manifest, stages, prepare, architecture, build_id):
    roots = [row for row in manifest['roots'] if row['name'] == 'runtime']
    require(len(roots) == 1 and isinstance(roots[0].get('originalPath'), str), 'Actual archived SDK6 runtime host path required')
    host = roots[0]['originalPath']; source = '/work/work/runtime'
    require(host.startswith('/') and posixpath.normpath(host) == host, 'Normalized absolute SDK6 runtime host path required')
    calls = [call for call in stages['build']['commands'] if '/project/scripts/musl-legacy6-coreclr.py' in call]
    require(len(calls) == 1, 'One actual SDK6 native worker required')
    call = calls[0]
    require(call[:len(B.P.DOCKER_ENGINE) + 1] == B.P.DOCKER_ENGINE + ['run'] and prepare['imageId'] in call
            and not any(arg.startswith(('--mount', '--volumes-from', '--volume=', '-v')) for arg in call),
            'Actual SDK6 native worker must use the frozen native builder image')
    mapped = []
    for position, value in enumerate(call):
        if value != '--volume': continue
        require(position + 1 < len(call), 'Complete native SDK6 volume option required')
        fields = call[position + 1].split(':')
        require(len(fields) in (2, 3), 'Ordinary explicit SDK6 native volume required')
        parent, target = fields[:2]
        require(parent.startswith('/') and target.startswith('/') and parent == posixpath.normpath(parent)
                and target == posixpath.normpath(target), 'Normalized native SDK6 volume paths required')
        require(not target.startswith(source + '/'), 'An additional volume shadows archived SDK6 runtime source')
        if source == target or source.startswith(target.rstrip('/') + '/'):
            mapped.append(parent.rstrip('/') + source[len(target.rstrip('/')):])
    require(mapped == [host], 'Actual native SDK6 compiler source must be the exact archived runtime root')
    for flag, value in [('--sdk', SDK), ('--arch', architecture), ('--source', source),
                        ('--dotnet', '/bootstrap/dotnet'), ('--output', '/delivery/reports/build/native-runtime'), ('--build-id', build_id)]:
        require(call.count(flag) == 1 and call.index(flag) + 1 < len(call) and call[call.index(flag) + 1] == value,
                'Normal SDK6 native worker argument differs')


def source_inputs(release, manifest, directory, result, source, obj):
    B = module('sdk6_native_source_byte_primitives', 'musl_legacy_admission.py')
    P = module('sdk6_native_source_archive_primitives', 'package-used-source.py')
    roots = [row for row in manifest['roots'] if row['name'] == 'runtime']
    require(len(roots) == 1 and roots[0].get('kind') in ('git', 'git-export') and roots[0].get('commit') == COMMIT
            and roots[0].get('tree') == TREE and not roots[0].get('deleted'), 'Complete original SDK6 runtime Git root required')
    generated = directory / 'generated'; actual = {}
    for path in generated.rglob('*'):
        require(not path.is_symlink(), 'Linked SDK6 native generated source is forbidden')
        if path.is_file(): actual[path.relative_to(generated).as_posix()] = fingerprint(ordinary(path).read_bytes())
    generated_roots = [row for row in manifest['roots'] if row['name'] == 'native-runtime-generated']
    require(100 <= len(actual) <= 20000 and len(actual) == result['generatedSourceFileCount'] and len(generated_roots) == 1
            and generated_roots[0]['kind'] == 'tree' and generated_roots[0].get('role') == 'generated-native-component-source'
            and generated_roots[0].get('files') == len(actual), 'Complete original SDK6 generated native source tree required')
    orchestration = {'orchestration/scripts/musl-legacy6-coreclr.py'} | {'orchestration/' + name for name in PATCHES}
    indexed, baseline = {}, {}
    with (release / 'sources' / B.portable(manifest['index']['path'])).open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line); name = B.portable(row['path'])
            if name.startswith(('runtime/', 'native-runtime-generated/')) or name in orchestration:
                require(name not in indexed, 'Duplicate SDK6 native source index'); indexed[name] = row
                if name.startswith('runtime/'):
                    require(row.get('baseline'), 'Original runtime Git baseline required'); baseline[name[len('runtime/'):]] = row['baseline']
    for child in roots[0].get('submodules', []): baseline[child['path']] = dict(mode='160000', blob=child['commit'])
    require(P.baseline_tree(baseline) == TREE, 'Complete original SDK6 native source tree differs')
    require({name[len('native-runtime-generated/'):]: {key: row[key] for key in FP} for name, row in indexed.items()
             if name.startswith('native-runtime-generated/')} == actual and orchestration <= indexed.keys(),
            'All actual generated native inputs and worker/patch sources must be archived')
    seen, retained = set(), {}
    patched = {'runtime/' + target for _, target in PATCHES.values()}
    with tarfile.open(release / 'sources' / B.portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if entry.name not in indexed: continue
            require(entry.name not in seen and (entry.isfile() or entry.issym()) and entry.size <= 64 * 1024**2,
                    'Unique bounded SDK6 native source member required')
            raw = entry.linkname.encode() if entry.issym() else archive.extractfile(entry).read()
            row = indexed[entry.name]; require(fingerprint(raw) == {key: row[key] for key in FP}, 'Archived SDK6 native source bytes differ')
            if entry.name.startswith('runtime/') and entry.name not in patched:
                require(pristine_runtime(P, row, raw),
                        'An unreviewed SDK6 runtime source change is present')
            elif entry.name.startswith('native-runtime-generated/'):
                require(raw == ordinary(generated / entry.name[len('native-runtime-generated/'):]).read_bytes(), 'Archived generated native compiler input differs')
            if entry.name in orchestration or entry.name in patched: retained[entry.name] = raw
            seen.add(entry.name)
    require(seen == indexed.keys(), 'A complete SDK6 runtime/generated source archive is required')
    require(retained['orchestration/scripts/musl-legacy6-coreclr.py'] == (ROOT / 'scripts/musl-legacy6-coreclr.py').read_bytes(),
            'Archived actual SDK6 native worker differs from reviewed implementation')
    for path, (sha, target) in PATCHES.items():
        patch = retained['orchestration/' + path]; require(hashlib.sha256(patch).hexdigest() == sha, 'Archived SDK6 native source patch differs')
        original = B.reverse_reviewed_patch(retained['runtime/' + target], patch, target)
        require(indexed['runtime/' + target]['baseline']['blob'] == hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest(),
                'SDK6 native source patch does not recover its original Git blob')
    for name, field in [('CMakeCache.txt', 'cmakeCache'), ('compile_commands.json', 'compileCommands')]:
        require(result[field] == fingerprint(ordinary(directory / name).read_bytes())
                and (generated / 'coreclr' / name).read_bytes() == (directory / name).read_bytes(), 'Actual native CMake cache/database differs')
    cache = {}
    for line in (directory / 'CMakeCache.txt').read_text().splitlines():
        if not line or line.startswith(('#', '//')): continue
        match = re.fullmatch(r'([^:=]+):[^=]+=(.*)', line)
        require(match and match[1] not in cache, 'Unique original native CMake cache fields required'); cache[match[1]] = match[2]
    require(cache.get('CMAKE_BUILD_TYPE') == 'RELEASE' and cache.get('CMAKE_HOME_DIRECTORY') == source + '/src/coreclr'
            and cache.get('CMAKE_EXPORT_COMPILE_COMMANDS') == 'ON' and cache.get('CLR_CMAKE_PGO_OPTIMIZE') == '1'
            and cache.get('CLR_CMAKE_PGO_INSTRUMENT') == '0' and cache.get('CMAKE_C_COMPILER') == '/usr/lib/llvm20/bin/clang'
            and cache.get('CMAKE_CXX_COMPILER') == '/usr/lib/llvm20/bin/clang++', 'Original optimized SDK6 native configuration differs')
    return compiler_database(json.loads((directory / 'compile_commands.json').read_bytes()), source, obj)


def validate_native_only(release, manifest, record, artifacts, stages=None, prepare=None):
    B = module('sdk6_native_observation_primitives', 'musl_legacy_admission.py'); release = Path(release)
    require(record['sdkVersion'] == SDK and record['architecture'] in ('x64', 'aarch64') and record['targetRid'] ==
            ('linux-musl-arm64' if record['architecture'] == 'aarch64' else 'linux-musl-x64'), 'Exact native SDK6 CPU/RID required')
    directory = release / 'reports/build/native-runtime'; result = json.loads(ordinary(directory / 'results.json').read_bytes())
    require(result['schemaVersion'] == 1 and result['kind'] == 'legacy-musl6-coreclr-source-build' and result['status'] == 'passed'
            and result['sdkVersion'] == SDK and result['runtimeVersion'] == RUNTIME and result['architecture'] == record['architecture']
            and result['sourceCommit'] == COMMIT and result['configuration'] == 'Release' and result['targets'] == TARGETS
            and result['metadataUpstreamBackport'] == BACKPORT and result.get('productVersionMetadataQualified') is True
            and result['buildId'] == record['buildId']
            and all(result[k] is False for k in ('readyToRunDisabled', 'tracingDisabled', 'optimizationDisabled',
                'consumerRuntimeTestsProvedByNativeBuild', 'qualificationAllowed', 'sourceAdmissionAllowed')),
            'One original optimized SDK6 five-product source worker required')
    invocation = json.loads(ordinary(directory / 'invocation.json').read_bytes()); source = invocation['source']; output = '/delivery/reports/build/native-runtime'
    require(invocation['sdkVersion'] == SDK and invocation['runtimeVersion'] == RUNTIME and invocation['architecture'] == record['architecture']
            and invocation['qualificationAllowed'] is invocation['sourceAdmissionAllowed'] is False
            and source == '/work/work/runtime' and invocation['output'] == output and invocation['dotnet'] == '/bootstrap/dotnet'
            and invocation['buildId'] == result['buildId'] and invocation['sourceCommit'] == COMMIT
            and invocation['worker'] == fingerprint((ROOT / 'scripts/musl-legacy6-coreclr.py').read_bytes()),
            'Actual SDK6 native worker/source/bootstrap/output identity differs')
    cpu = 'arm64' if record['architecture'] == 'aarch64' else 'x64'; obj = source + '/artifacts/obj/coreclr/Linux.' + cpu + '.Release'
    require(len(result['sourcePatches']) == 2 and [row['path'] for row in result['sourcePatches']] == list(PATCHES), 'Exactly the two SDK6 native source patches required')
    for row in result['sourcePatches']:
        path = ROOT / row['path']; require(row['sha256'] == PATCHES[row['path']][0]
            and {k: row[k] for k in FP} == fingerprint(ordinary(path).read_bytes())
            and fingerprint(ordinary(directory / 'patches' / path.name).read_bytes()) == {k: row[k] for k in FP}, 'Actual reviewed SDK6 native source patch differs')
    commands = B.native_command_records(directory, result)
    expected = {'source-patch-1-check', 'source-patch-1-apply', 'source-patch-2-check', 'source-patch-2-apply', 'native-version', 'configure', 'build'} | {'elf-' + name for name in PRODUCTS}
    require(commands.keys() == expected and all(row['text'].splitlines()[0] == json.dumps(row['command']) for row in commands.values()), 'All original SDK6 native command observations required')
    for index, path in enumerate(PATCHES, 1):
        base = ['git', '-c', 'safe.directory=' + source, '-C', source, 'apply']; patch = output + '/patches/' + Path(path).name
        require(commands[f'source-patch-{index}-check']['command'] == base + ['--check', patch]
                and commands[f'source-patch-{index}-apply']['command'] == base + [patch], 'Native worker applied an unrelated source patch')
    properties = ['/p:Version=' + RUNTIME, '/p:OfficialBuildId=' + result['buildId'], '/p:ContinuousIntegrationBuild=true', '/p:UseSharedCompilation=false']
    require(commands['native-version']['command'] == ['/bootstrap/dotnet', 'msbuild', source + '/eng/empty.csproj', '/restore',
        '/t:GenerateRuntimeVersionFile', '/p:NativeVersionFile=' + source + '/artifacts/obj/_version.c', *properties, '/bl:' + output + '/native-version.binlog']
        and result['nativeVersionBinlog'] == fingerprint(ordinary(directory / 'native-version.binlog').read_bytes()), 'Original dated native version producer required')
    require(commands['configure']['command'] == [source + '/src/coreclr/build-runtime.sh', '-' + cpu, '-release', '-component', 'runtime', '-component', 'jit', '-numproc', '2',
        '-cmakeargs', '-DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DLIBGSS=/usr/lib/libgssapi_krb5.so.2 -DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-configureonly', *properties]
        and '-- Generating done' in commands['configure']['text'] and 'CMake Error' not in commands['configure']['text']
        and commands['build']['command'] == ['cmake', '--build', obj, '--target', *TARGETS, '--parallel', '2', '--verbose']
        and 'asmparse.cpp.o' not in commands['build']['text'], 'Original optimized SDK6 native configuration/target graph required')
    generated = directory / 'generated'
    for field, path in [('compiledVersionSource', 'coreclr/version.c'), ('compiledVersionHeader', 'compiled-runtime_version.h')]:
        require(result[field] == dict(path='generated/' + path, **fingerprint(ordinary(generated / path).read_bytes())), 'Actual compiled SDK6 version input descriptor differs')
    marker = versions((generated / '_version.c').read_bytes(), (generated / 'runtime_version.h').read_bytes(),
        (generated / 'coreclr/version.c').read_bytes(), (generated / 'compiled-runtime_version.h').read_bytes(), result)
    outputs, debug = result['shippingFiles'], result['debugFiles']; require(len(outputs) == len(debug) == 5 and {r['path'] for r in outputs} == PRODUCTS.keys()
        and {r['path'] for r in debug} == {'debug/' + name + '.dbg' for name in PRODUCTS}, 'All five original native products and matching debug sidecars required')
    native = {name: row for name, row in artifacts.items() if row.get('kind') == 'native-coreclr'}
    require(native.keys() == {'native-' + name for name in PRODUCTS}, 'Exactly five actual SDK6 native construction artifacts required')
    members = {}
    for row in outputs:
        raw = ordinary(directory / row['path']).read_bytes(); fp = fingerprint(raw)
        require({k: row[k] for k in FP} == fp and raw[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', raw, 18)[0] ==
            (183 if record['architecture'] == 'aarch64' else 62),
            'Actual dated SDK6 native ELF bytes/CPU/source identity differ')
        elf_version(raw, marker)
        artifact = native['native-' + row['path']]
        require(artifact['sourceRoot'] == 'runtime' and artifact['sourceCommit'] == COMMIT and artifact['path'] == 'reports/build/native-runtime/' + row['path']
                and all(artifact[k] == fp[k] for k in FP), 'Native SDK6 artifact does not identify its actual source-built bytes')
        require(commands['elf-' + row['path']]['command'] == ['readelf', '--wide', '--file-header', '--dynamic', '--version-info', output + '/' + row['path']], 'Native ELF observation examined a different product')
        needed = B.elf_dynamic(raw)['needed']; require(not any(v == 'libc.so.6' or v.startswith('ld-linux') or 'gcompat' in v for v in needed), 'Native product imported a glibc compatibility provider')
        sidecar = next(r for r in debug if r['path'] == 'debug/' + row['path'] + '.dbg'); debug_raw = ordinary(directory / sidecar['path']).read_bytes()
        require(fingerprint(debug_raw) == {k: sidecar[k] for k in FP}, 'Actual native debug sidecar bytes differ'); debug_binding(raw, debug_raw, row['path'] + '.dbg')
        members[row['path']] = fp
    source = source_inputs(release, manifest, directory, result, source, obj)
    if stages is not None:
        require(prepare is not None, 'Actual frozen native builder preparation required')
        build_boundary(B, manifest, stages, prepare, record['architecture'], result['buildId'])
    return dict(kind='sdk6-five-product-native-source-proof', members=members, runtimeAssemblyVersion='6.0',
        nativeFileVersion=result['nativeFileVersion'], sourceCommit=COMMIT, compilerDatabase=source, fullSdkConsumption=False)


def validate(release, manifest, record, artifacts, actual=None, stages=None, prepare=None):
    require(isinstance(actual, dict) and actual, 'Actual final SDK member inventory is required for native admission')
    result = validate_native_only(release, manifest, record, artifacts, stages, prepare)
    expected = {'shared/Microsoft.NETCore.App/' + RUNTIME + '/' + name for name in PRODUCTS}; matched = set()
    for name, row in actual.items():
        filename = PurePosixPath(name).name
        if filename not in PRODUCTS: continue
        fp = result['members'][filename]
        require(all(row[k] == fp[k] for k in ('bytes', 'sha256')), 'Final SDK retained a different native runtime product')
        matched.add(name)
    require(expected <= matched, 'Final SDK did not consume all five source-built native runtime products')
    return dict(result, fullSdkConsumption=True, consumedPaths=sorted(matched))
