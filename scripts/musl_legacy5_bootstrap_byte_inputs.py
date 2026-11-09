"""Archive-backed validation of SDK5's two explicit compiler bootstraps.

Original tools remain imported build inputs. This byte-construction leaf does
not by itself prove complete native source compilation or normal admission.
"""
import hashlib
import json
from pathlib import Path
import stat
import tarfile

import musl_legacy5_bootstrap as C
import musl_legacy5_component_evidence as CE

B = CE.B
require = B.require
CONSTRUCTOR_SHA256 = '98c73408155f0c78fe9b50cfb811dcf3b510fcf6b8e4a4dd32b65b8ca749d306'
WORKER_SHA256 = 'eeb87300564d6e37b2189068b61af396fed83aeb2565f3e0a652c694a4394671'
PATCH_SHA256 = '296afea408f56da84952491d05c9e226bd324fee27b42c33f3b96bebcd30e3ab'
PREFIX = 'shared/Microsoft.NETCore.App/5.0.17/'


def constructor_policy():
    require(CE.fingerprint(CE.ordinary(Path(C.__file__)))['sha256'] == CONSTRUCTOR_SHA256,
            'Exact distinct SDK5 bootstrap constructor required')
    require(CE.fingerprint(CE.ordinary(C.ROOT / 'scripts/musl-legacy-native.py'))['sha256'] == WORKER_SHA256
            and CE.fingerprint(CE.ordinary(C.ROOT / 'patches/net5-musl/0001-use-stock-openssl3.patch'))['sha256'] == PATCH_SHA256,
            'Exact original SDK5 native support worker and declared port patch required')
    C.policy()


def original_inventory(path, role, architecture, prefix=None):
    """Hash original members without extracting or trusting a recorded list."""
    identity = C.checked_archive(path, role, architecture)
    files, seen, total = {}, set(), 0
    with tarfile.open(path, 'r|gz') as archive:
        for entry in archive:
            name = C.member_name(entry.name.rstrip('/') if entry.isdir() else entry.name)
            require(entry.isfile() or entry.isdir(), 'Original SDK5 bootstrap archive links/devices are forbidden')
            require(entry.mode >= 0 and not entry.mode & 0o7000, 'Original SDK5 bootstrap archive special permission bits are forbidden')
            if name is None:
                require(entry.isdir(), 'Only the original SDK5 archive root may omit its name'); continue
            if entry.isdir(): continue
            require(name not in seen and 0 <= entry.size <= 256 * 1024**2, 'One bounded ordinary original SDK5 bootstrap member required'); seen.add(name)
            total += entry.size; require(total <= 2 * 1024**3 and len(seen) <= 100000, 'Bounded complete SDK5 bootstrap inventory required')
            if prefix is not None and not name.startswith(prefix): continue
            hashes = {key: hashlib.new(key) for key in ('sha256', 'sha512')}; size = 0
            with archive.extractfile(entry) as stream:
                for block in iter(lambda: stream.read(1024**2), b''):
                    size += len(block)
                    for digest in hashes.values(): digest.update(block)
            require(size == entry.size, 'Complete original SDK5 bootstrap member bytes required')
            files[name] = dict(mode=entry.mode & 0o777, bytes=size, **{key: digest.hexdigest() for key, digest in hashes.items()})
    require(files, 'Complete original SDK5 bootstrap files are required')
    return identity, files


def composition(original_sdk, framework, sdk_identity, framework_identity, adaptations, architecture):
    require(not any(name.startswith(PREFIX) for name in original_sdk)
            and all(PREFIX + name in framework for name in C.CORE)
            and {row['component'] for row in adaptations} == set(C.SUPPORT) and len(adaptations) == 2,
            'Explicit separate matching SDK5 framework and both exact native support replacements required')
    for row in adaptations:
        name = row['component']; require(row['path'] == PREFIX + C.SUPPORT[name] and row['originalOfficial'] == {key: framework[row['path']][key] for key in CE.FP}
                and row['sourceCommit'] == C.SOURCE and row['bootstrapRoleOnly'] is True and row['productVersionMetadataQualified'] is False,
                'Exact SDK5 source-native bootstrap replacement input and role required')
    return dict(schemaVersion=1, kind='explicit-derived-sdk5-compiler-bootstrap', sdkVersion='5.0.401', architecture=architecture,
        sdkArchive=sdk_identity, matchingRuntimeArchive=framework_identity, originalSdkFiles=original_sdk, matchingFrameworkFiles=framework,
        adaptations=adaptations, originalSdkFilesUnchanged=True, officialClrJitDebuggerPreserved=True,
        bootstrapCompilerRoleOnly=True, newSourceClrProductsUsedAsBootstrap=False, previousPrivateSdkArchiveUsed=False,
        claimedUnmodifiedPublisherSdkTree=False, qualificationAllowed=False, sourceAdmissionAllowed=False)


def actual_tree(directory):
    directory = Path(directory)
    require(directory.is_dir() and not any(path.is_symlink() for path in (directory, *directory.parents)), 'Ordinary actual SDK5 compiler bootstrap directory required')
    require(not directory.lstat().st_mode & 0o7000, 'Actual SDK5 compiler bootstrap special permission bits are forbidden')
    files = {}
    for path in directory.rglob('*'):
        require(not path.is_symlink(), 'Actual SDK5 compiler bootstrap links are forbidden')
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), 'Only regular files and directories are allowed in actual SDK5 compiler bootstraps')
        require(not info.st_mode & 0o7000, 'Actual SDK5 compiler bootstrap special permission bits are forbidden')
        if stat.S_ISREG(info.st_mode): files[path.relative_to(directory).as_posix()] = dict(mode=stat.S_IMODE(info.st_mode), **CE.fingerprint(path))
    return files


def support_commands(component, architecture, generated_names=()):
    require(component in ('crypto', 'trace') and architecture in ('aarch64', 'x64'), 'Explicit SDK5 native support role and CPU required')
    output = '/delivery/reports/prepare/bootstrap-' + component
    library = output + '/' + C.SUPPORT[component]
    if component == 'crypto':
        commands = [
            ['git', '-C', output + '/source', 'apply', '/project/patches/net5-musl/0001-use-stock-openssl3.patch'],
            ['cmake', '-S', output + '/driver', '-B', output + '/obj', '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER=clang',
             '-DCMAKE_POLICY_VERSION_MINIMUM=3.5', '-DFEATURE_DISTRO_AGNOSTIC_SSL=OFF', '-DCLR_CMAKE_TARGET_LINUX=1', '-DCLR_CMAKE_TARGET_UNIX=1'],
            ['cmake', '--build', output + '/obj', '--target', 'System.Security.Cryptography.Native.OpenSsl', '--parallel', '2']]
    else:
        require(0 < len(generated_names) <= 32 and list(generated_names) == sorted(set(generated_names))
                and all(B.portable(name) == name and '/' not in name and name.startswith('traceptprov') and name.endswith('.cpp') for name in generated_names),
                'Complete ordinary generated SDK5 trace compiler input names required')
        base = '/work/work/runtime/src/coreclr/src'; generated = output + '/generated'; cpu = 'ARM64' if architecture == 'aarch64' else 'AMD64'
        flags = ['clang++', '-shared', '-fPIC', '-O2', '-DPAL_STDCPP_COMPAT=1', '-DPLATFORM_UNIX=1',
                 '-DTARGET_' + cpu + '=1', '-DHOST_' + cpu + '=1', '-DTARGET_64BIT=1', '-DHOST_64BIT=1']
        includes = [base + '/pal/inc', base + '/pal/inc/rt', base + '/inc', base + '/minipal', generated + '/lttng']
        commands = [['python3', base + '/scripts/genLttngProvider.py', '--man', base + '/vm/ClrEtwAll.man', '--intermediate', generated],
            flags + ['-I' + path for path in includes] + [generated + '/lttng/' + name for name in generated_names]
            + ['-llttng-ust', '-ldl', '-Wl,-soname,libcoreclrtraceptprovider.so', '-o', library]]
    return commands + [['readelf', '--wide', '--file-header', '--dynamic', '--version-info', library]]


def native_support(directory, component, architecture):
    library, support = C.source_support(directory, component, architecture)
    result = json.loads(CE.ordinary(directory / 'results.json').read_bytes())
    names = sorted(path.name for path in (directory / 'generated/lttng').glob('traceptprov*.cpp')) if component == 'trace' else ()
    require([row['command'] for row in result['commands']] == support_commands(component, architecture, names)
            and [row['log'] for row in result['commands']] == (['generate.log', 'build.log', 'elf.log'] if component == 'trace' else
                ['apply-patch.log', 'configure.log', 'build.log', 'elf.log']), 'Exact original SDK5 native support compile/generate/inspection commands required')
    smoke = json.loads(CE.ordinary(directory / ('native-load.json' if component == 'trace' else 'native-abi-smoke.json')).read_bytes())
    expected = dict(loaded=True, **{key: support['library'][key] for key in ('bytes', 'sha256')})
    if component == 'crypto':
        expected.update(randomStatus=1, randomNonzero=True, nativeInvalidCa=79, managedInvalidCa=24, invalidCaDescription='invalid CA certificate')
        patch = C.ROOT / 'patches/net5-musl/0001-use-stock-openssl3.patch'
        require(json.loads(CE.ordinary(directory / 'patch.json').read_bytes()) == dict(path='patches/net5-musl/0001-use-stock-openssl3.patch',
                **{key: CE.fingerprint(patch)[key] for key in ('bytes', 'sha256')}, donorRuntimeCommit='f1dd57165bfd91875761329ac3a8b17f6606ad18',
                scope='OID parsing and managed X509 error-code/error-string ABI only'), 'Exact declared original SDK5 OpenSSL port patch required')
    require(smoke == expected, 'Actual SDK5 native support load/old managed X509 ABI result differs')
    return library, support


def validate(release, record, archives, *, actual_bootstrap5=None, actual_bootstrap6=None):
    """Recompute original archive inventories, support identities and receipts."""
    release = Path(release); constructor_policy()
    require(record.get('sdkVersion') == CE.SDK and record.get('architecture') in ('aarch64', 'x64')
            and set(archives) == {'legacy5', 'runtime', 'vstest'}, 'All three distinct original SDK5 compiler bootstrap archive roles required')
    architecture = record['architecture']; inventories, identities = {}, {}
    for role in ('legacy5', 'runtime', 'vstest'):
        identities[role], inventories[role] = original_inventory(B.checked(release, archives[role]), role, architecture, PREFIX if role == 'runtime' else None)
    adaptations = []
    for name in ('crypto', 'trace'):
        library, support = native_support(release / 'reports/prepare' / ('bootstrap-' + name), name, architecture)
        path = PREFIX + C.SUPPORT[name]
        require(path in inventories['runtime'], 'Original SDK5 support replacement counterpart required')
        adaptations.append(dict(path=path, originalOfficial={key: inventories['runtime'][path][key] for key in CE.FP}, **support))
    expected5 = composition(inventories['legacy5'], inventories['runtime'], identities['legacy5'], identities['runtime'], adaptations, architecture)
    receipt5 = json.loads(CE.ordinary(release / 'reports/prepare/bootstrap5-composition.json').read_bytes())
    require(receipt5 == expected5, 'SDK5 derived bootstrap receipt must equal independently rehashed original inputs and actual source support')
    expected6 = dict(kind='official-private-component-compiler-bootstrap', archive=identities['vstest'], files=inventories['vstest'], payloadRole=False, qualificationAllowed=False)
    require(json.loads(CE.ordinary(release / 'reports/prepare/bootstrap6.json').read_bytes()) == expected6,
            'SDK5 separate VSTest/Reader bootstrap receipt must equal its exact original archive')
    require((actual_bootstrap5 is None) is (actual_bootstrap6 is None), 'Both actual SDK5 compiler bootstrap trees must be checked together')
    if actual_bootstrap5 is not None:
        expected = dict(inventories['legacy5']); require(not (expected.keys() & inventories['runtime'].keys()), 'SDK5 bootstrap source roles overlap')
        expected.update(inventories['runtime'])
        for row in adaptations: expected[row['path']] = dict(mode=0o755, **{key: row['library'][key] for key in CE.FP})
        require(actual_tree(actual_bootstrap5) == expected and actual_tree(actual_bootstrap6) == inventories['vstest'],
                'Actual SDK5 readonly compiler bootstrap trees differ from exact reconstructed byte/mode inputs')
    return dict(status='passed-sdk5-explicit-dual-bootstrap-archive-byte-construction', originalArchives=identities,
        sdk5Files=len(inventories['legacy5']), matchingFrameworkFiles=len(inventories['runtime']), inspectorFiles=len(inventories['vstest']),
        nativeSupportProducts={row['component']: row['library'] for row in adaptations}, actualBootstrapTreesCompared=actual_bootstrap5 is not None,
        nativeCompilerSourceClosureEstablishedByThisLeaf=False, wholeProducerSourceClosure=False, qualificationAllowed=False, sourceAdmissionAllowed=False)
