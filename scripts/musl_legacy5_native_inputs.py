"""Bind SDK5's six native construction products and five shipping products.

Actual dated version inputs, compiler commands, original patched source and
debug sidecars are checked independently. Crossgen is a construction input;
final SDK consumption is a separate check of every runtime copy.
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
SDK, RUNTIME = '5.0.214', '5.0.17'
COMMIT, TREE = '6a984143635bde23e728abaaccbde52f5ea8fa3e', '40ca76ac8df97a2ee75519a1ec821957007449f0'
FP = ('bytes', 'sha256', 'sha512')
PATCHES = {
    'patches/net5-musl/0006-backport-upstream-clang13-alignment-and-aliasing.patch':
        ('db205750ee5ad54be0c7e2154b339fd82df9d05edd9719bf147623348a107149',
         ('src/coreclr/src/inc/corhlpr.h', 'src/coreclr/src/jit/bitsetasshortlong.h')),
    'patches/net5-musl/0007-adapt-native-clr5-for-clang20.patch':
        ('b53aee1f8bd38d352471e5aa87220beca4ad75bbd900ed008228f4e140b717e5',
         ('src/coreclr/src/vm/comreflectioncache.hpp', 'src/coreclr/src/md/runtime/metamodel.cpp',
          'src/coreclr/src/pal/src/init/pal.cpp', 'src/coreclr/src/pal/src/thread/process.cpp', 'src/coreclr/src/zap/zapnodetype.h'))}
PRODUCTS = {'libcoreclr.so': 'src/dlls/mscoree/coreclr/libcoreclr.so', 'libclrjit.so': 'src/jit/standalone/libclrjit.so',
    'libmscordaccore.so': 'src/dlls/mscordac/libmscordaccore.so', 'libmscordbi.so': 'src/dlls/mscordbi/libmscordbi.so',
    'libcoreclrtraceptprovider.so': 'src/pal/src/eventprovider/lttngprovider/libcoreclrtraceptprovider.so',
    'crossgen': 'src/tools/crossgen/crossgen'}
SHIPPING = set(PRODUCTS) - {'crossgen'}
TARGETS = ['coreclr', 'clrjit', 'mscordaccore', 'mscordbi', 'coreclrtraceptprovider', 'crossgen']


def require(value, message):
    if not value: raise ValueError(message)


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result); return result


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def ordinary(path):
    path = Path(path).absolute()
    require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary SDK5 native input required')
    return path


def pristine_runtime(P, row, raw):
    # Only the pinned runtime's original Windows script/solution checkout
    # rules may recover a uniform CRLF copy of the exact original Git blob.
    # Actual C/C++ and every other source byte remain strict.
    blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    windows = row['path'].lower().endswith(('.cmd', '.bat', '.sln'))
    return P.pristine_blob(row, blob, raw if windows else None,
                           allow_audited_crlf=row['path'].lower().endswith('.sln'))


def patched_source_mode(row, entry):
    """A declared byte patch does not authorize a source type/mode change."""
    baseline = row.get('baseline')
    return (isinstance(baseline, dict) and row.get('mode') in ('100644', '100755')
            and row['mode'] == baseline.get('mode') and entry.type == tarfile.REGTYPE
            and entry.sparse is None and entry.mode == (0o755 if row['mode'] == '100755' else 0o644))


def versions(first, header, compiled, compiled_header, result):
    require(first == compiled and header == compiled_header and b'42.42.42' not in compiled,
            'Actual compiled SDK5 version inputs must equal the original dated producer')
    macros = dict(re.findall(rb'^#define (Runtime(?:Assembly|File)(?:Major|Minor|Build|Revision)Version) ([0-9]+)$', header, re.M))
    def version(kind, fields):
        names = [('Runtime' + kind + part + 'Version').encode() for part in fields]
        require(all(n in macros for n in names), 'Complete original SDK5 native version header required')
        return '.'.join(macros[n].decode() for n in names)
    assembly, file = version('Assembly', ('Major', 'Minor')), version('File', ('Major', 'Minor', 'Build', 'Revision'))
    require(assembly == result['runtimeAssemblyVersion'] == '5.0' and file == result['nativeFileVersion']
        and re.fullmatch(r'5\.0\.[0-9]+\.[0-9]+', file) and all(0 <= int(v) <= 65535 for v in file.split('.'))
        and b'#define RuntimeProductVersion 5.0.17' in header and re.fullmatch(r'[0-9]{8}\.[1-9][0-9]*', result['buildId']),
        'Original SDK5 runtime ABI/product/dated file version differs')
    marker = ('@(#)Version ' + file + ' @Commit: ' + COMMIT).encode()
    require(compiled.count(marker) == 1, 'The actual SDK5 compiled version source lacks its exact dated commit marker')
    return marker


def elf_version(raw, marker):
    require(re.findall(rb'@\(#\)Version [^\x00\r\n]+', raw) == [marker] and b'42.42.42.42424' not in raw,
        'Actual SDK5 native ELF has missing, fallback or mixed version identities')


def sections(raw):
    require(len(raw) >= 64 and raw[:6] == b'\x7fELF\x02\x01', 'SDK5 ELF64 little-endian input required')
    start = struct.unpack_from('<Q', raw, 40)[0]; width, count, strings = struct.unpack_from('<HHH', raw, 58)
    require(width >= 64 and 0 < count <= 65535 and strings < count and start + width * count <= len(raw), 'Bounded SDK5 ELF section table required')
    rows = [struct.unpack_from('<IIQQQQIIQQ', raw, start + width * n) for n in range(count)]
    names = rows[strings]; require(names[4] + names[5] <= len(raw), 'SDK5 ELF section-name table is truncated')
    table = raw[names[4]:names[4] + names[5]]; result = {}
    for row in rows:
        require(row[0] < len(table), 'SDK5 ELF section-name offset differs')
        end = table.find(b'\0', row[0]); require(end >= 0, 'Terminated SDK5 ELF section name required')
        name = table[row[0]:end].decode('ascii')
        if not name: continue
        require(name not in result, 'Duplicate SDK5 ELF section name')
        if row[1] == 8: continue
        require(row[4] + row[5] <= len(raw), 'SDK5 ELF section body is truncated'); result[name] = raw[row[4]:row[4] + row[5]]
    return result


def debug_binding(binary, debug, filename):
    normal, sidecar = sections(binary), sections(debug)
    require(normal.get('.note.gnu.build-id') and normal['.note.gnu.build-id'] == sidecar.get('.note.gnu.build-id'), 'SDK5 ELF/debug build IDs differ')
    link = normal.get('.gnu_debuglink', b''); end = link.find(b'\0')
    require(end > 0 and link[:end].decode('ascii') == filename and len(link) == ((end + 4) & ~3) + 4,
        'Exact SDK5 debug sidecar filename required')
    require(struct.unpack_from('<I', link, (end + 4) & ~3)[0] == zlib.crc32(debug) & 0xffffffff, 'SDK5 debug sidecar CRC differs')


def compiler_row(row, source, obj):
    require(set(row) == {'directory', 'command', 'file', 'output'} and row['directory'].startswith(source + '/artifacts/obj/')
        and row['directory'] == posixpath.normpath(row['directory']) and row['file'].startswith((source + '/src/', source + '/artifacts/obj/'))
        and row['file'] == posixpath.normpath(row['file']), 'SDK5 native compiler source escaped the original tree')
    argv = shlex.split(row['command']); optimization = [v for v in argv if v.startswith('-O')]
    expected = ['-O3', '-O3', '-O0'] if row['file'] == source + '/src/coreclr/src/ilasm/prebuilt/asmparse.cpp' else ['-O3', '-O3']
    require(argv and argv[0] in ('/usr/lib/llvm20/bin/clang', '/usr/lib/llvm20/bin/clang++') and argv.count('-c') == argv.count('-o') == 1
        and argv.index('-c') + 1 < len(argv) and argv.index('-o') + 1 < len(argv) and argv[argv.index('-c') + 1] == row['file']
        and optimization == expected, 'Original SDK5 native compiler/optimization operands differ')
    actual = posixpath.normpath(posixpath.join(row['directory'], argv[argv.index('-o') + 1]))
    require(actual == posixpath.normpath(posixpath.join(obj, row['output'])) and actual.startswith(source + '/artifacts/obj/'),
        'Actual SDK5 compiler output differs from its original database')
    return argv


def compiler_database(rows, source, obj):
    require(isinstance(rows, list) and 100 <= len(rows) <= 20000, 'Complete bounded SDK5 native compiler database required')
    version_rows = 0; features = set()
    wanted = {'-DFEATURE_PGO', '-DFEATURE_READYTORUN', '-DFEATURE_EVENT_TRACE', '-DFEATURE_PERFTRACING'}
    for row in rows:
        argv = compiler_row(row, source, obj); features.update(v for v in argv if v in wanted); version_rows += row['file'] == obj + '/version.c'
    require(version_rows >= 6 and features == wanted, 'Actual SDK5 dated version source and PGO/ReadyToRun/tracing compiler definitions required')
    return dict(entries=len(rows), versionSourceEntries=version_rows)


def patch_sections(raw, targets):
    lines = raw.decode().splitlines(True); starts = [i for i, line in enumerate(lines) if line.startswith('--- a/')]
    require(tuple(lines[i][6:].rstrip('\n') for i in starts) == targets, 'Exact original SDK5 native patch target set required')
    result = {}
    for start, target in zip(starts, targets):
        stop = next((i for i in range(start + 1, len(lines)) if lines[i].startswith(('diff --git ', '--- a/'))), len(lines))
        require(start + 1 < stop and lines[start + 1] == '+++ b/' + target + '\n', 'Exact SDK5 patch target pair required')
        selected = lines[start:start + 2]; position = start + 2; hunks = 0
        while position < stop:
            if lines[position] == '\n' or lines[position].startswith('Subject: '):
                position += 1; continue  # Original formatting between complete unified hunks/files.
            match = re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n', lines[position])
            require(match is not None, 'Malformed SDK5 native unified patch hunk')
            old_count, new_count = int(match[2] or '1'), int(match[4] or '1')
            selected.append(lines[position]); position += 1; old, new = 0, 0
            while old < old_count or new < new_count:
                require(position < stop and lines[position] and (lines[position][0] in ' +-' or lines[position] == '\n'),
                    'Truncated SDK5 native patch body')
                # Git accepts a bare empty line as a blank context line.
                # Declared hunk extents and the recovered original Git blob
                # still bind it exactly; source bytes are never normalized.
                line = ' \n' if lines[position] == '\n' else lines[position]
                old += line[0] in ' -'; new += line[0] in ' +'
                require(old <= old_count and new <= new_count, 'SDK5 patch hunk extent differs')
                selected.append(line); position += 1
            hunks += 1
        require(hunks > 0, 'Complete original SDK5 patch hunks required')
        result[target] = ''.join(selected).encode()
    return result


def observe(directory, record):
    """Inspect worker receipts only; this does not claim archived source closure."""
    B = module('sdk5_neutral_native_observation', 'musl_legacy_admission.py'); directory = Path(directory)
    result = json.loads(ordinary(directory / 'results.json').read_bytes())
    require(record['sdkVersion'] == SDK and record['architecture'] in ('aarch64', 'x64') and record['targetRid'] ==
        ('linux-musl-arm64' if record['architecture'] == 'aarch64' else 'linux-musl-x64'), 'Exact SDK5 native CPU/RID required')
    require(result['kind'] == 'legacy-musl-native-runtime-build' and result['schemaVersion'] == 1 and result['status'] == 'passed'
        and result['sdkVersion'] == SDK and result['runtimeVersion'] == RUNTIME and result['sourceCommit'] == COMMIT
        and result['architecture'] == record['architecture'] and result['buildId'] == record['buildId'] and result['configuration'] == 'Release'
        and result['targets'] == TARGETS and result['originalGlobalJsonUnchanged'] is True and result['bootstrapSdkVersion'] == '5.0.401'
        and result['upstreamClang13Backport'] == 'f86caa54678535ead8e1977da37025a96e2afe8a'
        and result['upstreamMetadataBackport'] == '35a39e97345abfda05e14f609759760b37ddeb4d'
        and result['upstreamProductVersionMetadataVerified'] is result['nativeVersionCompilationAndAllSixElfsVerified'] is True
        and all(result[k] is False for k in ('tracingDisabled', 'readyToRunDisabled', 'optimizationDisabled', 'qualificationAllowed', 'sourceAdmissionAllowed'))
        and result['worker'] == fingerprint((ROOT / 'scripts/musl-legacy-coreclr5.py').read_bytes()), 'One exact optimized SDK5 native source worker required')
    require([p['path'] for p in result['sourcePatches']] == list(PATCHES), 'Both original SDK5 native source patches required')
    for row in result['sourcePatches']:
        require(row['sha256'] == PATCHES[row['path']][0] and {k: row[k] for k in FP} == fingerprint((ROOT / row['path']).read_bytes()), 'Reviewed SDK5 native patch bytes differ')
    source, output = '/work/work/runtime', '/delivery/reports/build/native-runtime'
    cpu = 'arm64' if record['architecture'] == 'aarch64' else 'x64'; obj = source + '/artifacts/obj/coreclr/Linux.' + cpu + '.Release'
    commands = B.native_command_records(directory, result)
    expected = {'patch-check-0', 'patch-apply-0', 'patch-check-1', 'patch-apply-1', 'source-diff-check', 'bootstrap-sdk-version',
                'native-version', 'configure', 'build', 'compiler-version', 'cmake-version'} | {'elf-' + name for name in PRODUCTS}
    require(commands.keys() == expected and all(r['text'].splitlines()[0] == json.dumps(r['command']) for r in commands.values()), 'All actual SDK5 native command observations required')
    for index, name in enumerate(PATCHES):
        base = ['git', '-c', 'safe.directory=' + source, '-C', source, 'apply']; patch = '/project/' + name
        require(commands['patch-check-' + str(index)]['command'] == base + ['--check', patch]
            and commands['patch-apply-' + str(index)]['command'] == base + [patch], 'SDK5 worker applied unrelated source patches')
    properties = ['/p:Version=' + RUNTIME, '/p:OfficialBuildId=' + result['buildId'], '/p:ContinuousIntegrationBuild=true', '/p:UseSharedCompilation=false']
    require(commands['native-version']['command'] == ['/bootstrap/dotnet', 'msbuild', source + '/eng/empty.csproj', '/restore',
        '/t:GenerateRuntimeVersionFile', '/p:NativeVersionFile=' + source + '/artifacts/obj/_version.c', *properties, '/bl:' + output + '/native-version.binlog']
        and commands['bootstrap-sdk-version']['command'] == ['/bootstrap/dotnet', '--version']
        and commands['bootstrap-sdk-version']['text'].splitlines()[1:] == ['5.0.401'], 'Original SDK5 global.json compiler and dated version invocation required')
    require(commands['source-diff-check']['command'] == ['git', '-c', 'safe.directory=' + source, '-C', source, 'diff', '--check']
        and commands['compiler-version']['command'] == ['clang', '--version'] and commands['cmake-version']['command'] == ['cmake', '--version'],
        'Original SDK5 native source/toolchain observations differ')
    require(commands['configure']['command'] == [source + '/src/coreclr/build-runtime.sh', '-' + cpu, '-release', '-numproc', '2',
        '-cmakeargs', '-DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DLIBGSS=/usr/lib/libgssapi_krb5.so.2 -DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-configureonly', *properties]
        and '-- Generating done' in commands['configure']['text'] and 'CMake Error' not in commands['configure']['text']
        and commands['build']['command'] == ['cmake', '--build', obj, '--target', *TARGETS, '--parallel', '2', '--verbose']
        and 'asmparse.cpp.o' not in commands['build']['text'], 'Original SDK5 optimized configure/target graph differs')
    for name, field in [('native-version.binlog', 'nativeVersionBinlog'), ('native-configure-version.binlog', 'nativeConfigureVersionBinlog'),
                        ('native-version-consumption.json', 'nativeVersionConsumption'), ('CMakeCache.txt', 'cmakeCache'), ('compile_commands.json', 'compileCommands')]:
        require(result[field] == fingerprint(ordinary(directory / name).read_bytes()), 'An actual SDK5 native observation changed')
    generated = directory / 'generated'
    marker = versions((generated / '_version.c').read_bytes(), (generated / 'runtime_version.h').read_bytes(),
        (generated / 'coreclr/version.c').read_bytes(), (generated / 'compiled-runtime_version.h').read_bytes(), result)
    consumption = json.loads((directory / 'native-version-consumption.json').read_bytes()); db = json.loads((directory / 'compile_commands.json').read_bytes())
    require(consumption['compiledSourceByteEqualsUpstreamGenerated'] is consumption['compiledHeaderByteEqualsUpstreamGenerated'] is True
        and consumption['sourceCommit'] == COMMIT and consumption['nativeFileVersion'] == result['nativeFileVersion']
        and consumption['compilerCommands'] == [r for r in db if r['file'] == obj + '/version.c'], 'Actual SDK5 compiled native version database differs')
    for field, file, path in [('generatedVersionSource', '_version.c', source + '/artifacts/obj/_version.c'),
                             ('actualCompiledVersionSource', 'coreclr/version.c', obj + '/version.c'),
                             ('actualCompiledRuntimeHeader', 'compiled-runtime_version.h', source + '/artifacts/obj/coreclr/runtime_version.h')]:
        require(consumption[field] == dict(buildPath=path, **fingerprint((generated / file).read_bytes())), 'SDK5 actual compiled version source/header identity differs')
    outputs = result['shippingFiles'] + result['auxiliaryFiles']; debug = result['debugSidecars']
    require(len(outputs) == len(debug) == 6 and {r['path'] for r in outputs} == PRODUCTS.keys()
        and {r['path'] for r in debug} == {name + '.dbg' for name in PRODUCTS}, 'All six SDK5 native construction products and debug sidecars required')
    members = {}
    for row in outputs:
        name = row['path']; raw = ordinary(directory / name).read_bytes(); fp = fingerprint(raw)
        require(row == dict(path=name, buildPath=obj + '/' + PRODUCTS[name], **fp) and raw[:6] == b'\x7fELF\x02\x01'
            and struct.unpack_from('<H', raw, 18)[0] == (183 if record['architecture'] == 'aarch64' else 62), 'SDK5 native product source path/bytes/CPU differ')
        elf_version(raw, marker); needed = B.elf_dynamic(raw)['needed']
        require(not any(n == 'libc.so.6' or n.startswith('ld-linux') or 'gcompat' in n for n in needed), 'A glibc provider entered SDK5 native inputs')
        require(commands['elf-' + name]['command'] == ['readelf', '--wide', '--file-header', '--dynamic', '--version-info', output + '/' + name], 'SDK5 readelf examined another native product')
        sidecar = next(r for r in debug if r['path'] == name + '.dbg'); debug_raw = ordinary(directory / sidecar['path']).read_bytes()
        require(sidecar == dict(path=name + '.dbg', buildPath=obj + '/' + PRODUCTS[name] + '.dbg', **fingerprint(debug_raw)), 'SDK5 native debug sidecar receipt differs')
        debug_binding(raw, debug_raw, name + '.dbg'); members[name] = fp
    cache = {}
    for line in (directory / 'CMakeCache.txt').read_text().splitlines():
        if not line or line.startswith(('#', '//')): continue
        match = re.fullmatch(r'([^:=]+):[^=]+=(.*)', line); require(match and match[1] not in cache, 'Unique SDK5 native CMake fields required'); cache[match[1]] = match[2]
    require(cache.get('CMAKE_BUILD_TYPE') == 'RELEASE' and cache.get('CMAKE_HOME_DIRECTORY') == source + '/src/coreclr'
        and cache.get('CMAKE_EXPORT_COMPILE_COMMANDS') == 'ON' and cache.get('CLR_CMAKE_PGO_OPTIMIZE') == '1'
        and cache.get('CLR_CMAKE_PGO_INSTRUMENT') == '0' and cache.get('CMAKE_C_COMPILER') == '/usr/lib/llvm20/bin/clang'
        and cache.get('CMAKE_CXX_COMPILER') == '/usr/lib/llvm20/bin/clang++', 'Original optimized SDK5 native CMake configuration differs')
    database = compiler_database(db, source, obj)
    for name in ('CMakeCache.txt', 'compile_commands.json'):
        require((generated / 'coreclr' / name).read_bytes() == (directory / name).read_bytes(), 'SDK5 generated CMake source/database differs')
    return dict(kind='sdk5-six-product-native-observations', members=members, shippingProducts=sorted(SHIPPING),
        sourceCrossgenConstructionOnly=True, runtimeAssemblyVersion='5.0', nativeFileVersion=result['nativeFileVersion'],
        sourceCommit=COMMIT, compilerDatabase=database, archivedSourceClosure=False, fullSdkConsumption=False)


def source_inputs(release, manifest, directory):
    B = module('sdk5_native_archive_byte_primitives', 'musl_legacy_admission.py')
    P = module('sdk5_native_original_git_primitives', 'package-used-source.py'); release, directory = Path(release), Path(directory)
    roots = [r for r in manifest['roots'] if r['name'] == 'runtime']
    require(len(roots) == 1 and roots[0]['kind'] in ('git', 'git-export') and roots[0]['commit'] == COMMIT
        and roots[0]['tree'] == TREE and not roots[0].get('deleted'), 'Complete original SDK5 runtime Git tree required')
    result = json.loads((directory / 'results.json').read_bytes()); generated = directory / 'generated'; actual = {}
    for path in generated.rglob('*'):
        require(not path.is_symlink(), 'Linked SDK5 generated native source is forbidden')
        if path.is_file(): actual[path.relative_to(generated).as_posix()] = fingerprint(ordinary(path).read_bytes())
    generated_roots = [r for r in manifest['roots'] if r['name'] == 'native-runtime-generated']
    require(100 <= len(actual) <= 20000 and len(actual) == result['generatedSourceFileCount'] and len(generated_roots) == 1
        and generated_roots[0]['kind'] == 'tree' and generated_roots[0].get('role') == 'generated-native-component-source'
        and generated_roots[0]['files'] == len(actual), 'Complete actual SDK5 generated native source tree required')
    orchestration = {'orchestration/scripts/musl-legacy-coreclr5.py'} | {'orchestration/' + name for name in PATCHES}
    indexed, baseline = {}, {}
    with (release / 'sources' / B.portable(manifest['index']['path'])).open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line); name = B.portable(row['path'])
            if name.startswith(('runtime/', 'native-runtime-generated/')) or name in orchestration:
                require(name not in indexed, 'Duplicate SDK5 native source index member'); indexed[name] = row
                if name.startswith('runtime/'):
                    require(row.get('baseline'), 'Original SDK5 runtime Git baseline required'); baseline[name[len('runtime/'):]] = row['baseline']
    for child in roots[0].get('submodules', []): baseline[child['path']] = dict(mode='160000', blob=child['commit'])
    require(P.baseline_tree(baseline) == TREE, 'Full original SDK5 runtime tree differs')
    require({name[len('native-runtime-generated/'):]: {k: row[k] for k in FP} for name, row in indexed.items()
             if name.startswith('native-runtime-generated/')} == actual and orchestration <= indexed.keys(),
        'Every SDK5 generated native input and actual worker/patch source must be archived')
    changed = {'runtime/' + target for sha, targets in PATCHES.values() for target in targets}; seen, retained = set(), {}
    with tarfile.open(release / 'sources' / B.portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if entry.name not in indexed: continue
            require(entry.name not in seen and (entry.isfile() or entry.issym()) and entry.size <= 64 * 1024**2, 'Unique bounded SDK5 native source member required')
            raw = entry.linkname.encode() if entry.issym() else archive.extractfile(entry).read(); row = indexed[entry.name]
            require(fingerprint(raw) == {k: row[k] for k in FP}, 'Archived actual SDK5 native source bytes differ')
            if entry.name in changed:
                require(patched_source_mode(row, entry),
                        'SDK5 declared patched original must retain regular type and exact Git/index/TAR mode: ' + entry.name)
            if entry.name.startswith('runtime/') and entry.name not in changed:
                require(pristine_runtime(P, row, raw), 'An unreviewed SDK5 native source change is present: ' + entry.name)
            elif entry.name.startswith('native-runtime-generated/'):
                require(raw == ordinary(generated / entry.name[len('native-runtime-generated/'):]).read_bytes(), 'Actual and archived SDK5 generated source differ')
            if entry.name in changed or entry.name in orchestration: retained[entry.name] = raw
            seen.add(entry.name)
    require(seen == indexed.keys(), 'A complete SDK5 original/runtime generated source archive required')
    require(retained['orchestration/scripts/musl-legacy-coreclr5.py'] == (ROOT / 'scripts/musl-legacy-coreclr5.py').read_bytes(), 'Archived SDK5 native worker differs')
    for path, (sha, targets) in PATCHES.items():
        patch = retained['orchestration/' + path]; require(hashlib.sha256(patch).hexdigest() == sha, 'Archived SDK5 native patch differs')
        for target, section in patch_sections(patch, targets).items():
            original = B.reverse_reviewed_patch(retained['runtime/' + target], section, target)
            require(indexed['runtime/' + target]['baseline']['blob'] == hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest(),
                'SDK5 reviewed patch does not recover its exact original Git blob')
    return dict(originalRuntimeFiles=len(baseline), generatedSourceFiles=len(actual), changedOriginalFiles=len(changed),
        archivedSourceClosure=True, originalRuntimeCommit=COMMIT, originalRuntimeTree=TREE)


def build_boundary(B, manifest, stages, prepare, record):
    roots = [r for r in manifest['roots'] if r['name'] == 'runtime']; require(len(roots) == 1, 'One actual SDK5 runtime root required')
    host = roots[0].get('originalPath'); source = '/work/work/runtime'
    require(isinstance(host, str) and host.startswith('/') and host == posixpath.normpath(host), 'Actual SDK5 archived runtime host path required')
    calls = [c for c in stages['build']['commands'] if '/project/scripts/musl-legacy-coreclr5.py' in c]
    require(len(calls) == 1, 'One original SDK5 native source worker required'); call = calls[0]
    require(call[:len(B.P.DOCKER_ENGINE) + 1] == B.P.DOCKER_ENGINE + ['run'] and prepare['imageId'] in call
        and not any(v.startswith(('--mount', '--volumes-from', '--volume=', '-v')) for v in call), 'Actual SDK5 native source worker builder differs')
    mapped = []
    for index, value in enumerate(call):
        if value != '--volume': continue
        require(index + 1 < len(call), 'Complete SDK5 source volume required'); fields = call[index + 1].split(':')
        require(len(fields) in (2, 3), 'Ordinary explicit SDK5 native source volume required'); parent, target = fields[:2]
        require(parent.startswith('/') and target.startswith('/') and parent == posixpath.normpath(parent)
            and target == posixpath.normpath(target) and not target.startswith(source + '/'), 'SDK5 source volume shadowing is forbidden')
        if source == target or source.startswith(target.rstrip('/') + '/'):
            mapped.append(parent.rstrip('/') + source[len(target.rstrip('/')):])
    require(mapped == [host], 'Actual SDK5 native compiler source must be the exact archived runtime root')
    for flag, value in [('--sdk', SDK), ('--arch', record['architecture']), ('--source', source), ('--dotnet', '/bootstrap/dotnet'),
                        ('--output', '/delivery/reports/build/native-runtime'), ('--build-id', record['buildId'])]:
        require(call.count(flag) == 1 and call.index(flag) + 1 < len(call) and call[call.index(flag) + 1] == value, 'Normal SDK5 native worker argument differs')


def validate_native_only(release, manifest, record, artifacts, stages=None, prepare=None):
    release = Path(release); directory = release / 'reports/build/native-runtime'; result = observe(directory, record)
    native = {name: row for name, row in artifacts.items() if row.get('kind') == 'native-coreclr'}
    require(native.keys() == {'native-' + name for name in SHIPPING}, 'Exactly five SDK5 shipping native construction artifacts required')
    for name, fp in result['members'].items():
        artifact = native['native-' + name] if name in SHIPPING else artifacts.get('source-crossgen')
        require(artifact and artifact.get('kind') == ('native-coreclr' if name in SHIPPING else 'native-crossgen-construction-input')
            and artifact['sourceRoot'] == 'runtime' and artifact['sourceCommit'] == COMMIT
            and artifact['path'] == 'reports/build/native-runtime/' + name and all(artifact[k] == fp[k] for k in FP),
            'SDK5 construction artifact does not identify its actual native source-built bytes')
    result.update(source_inputs(release, manifest, directory))
    if stages is not None:
        require(prepare is not None, 'Actual frozen SDK5 native preparation required')
        build_boundary(module('sdk5_native_normal_boundary_primitives', 'musl_legacy_admission.py'), manifest, stages, prepare, record)
    return result


def validate(release, manifest, record, artifacts, actual=None, stages=None, prepare=None):
    require(isinstance(actual, dict) and actual, 'Actual final SDK5 member inventory required for native admission')
    result = validate_native_only(release, manifest, record, artifacts, stages, prepare); matched = set()
    for name, row in actual.items():
        filename = PurePosixPath(name).name
        require(filename != 'crossgen', 'The SDK5 source Crossgen is construction-only')
        if filename not in SHIPPING: continue
        require(all(row[k] == result['members'][filename][k] for k in ('bytes', 'sha256')), 'Final SDK5 retained a different native product copy')
        matched.add(name)
    require({'shared/Microsoft.NETCore.App/' + RUNTIME + '/' + name for name in SHIPPING} <= matched, 'Final SDK5 did not consume all five native products')
    return dict(result, fullSdkConsumption=True, consumedPaths=sorted(matched))
