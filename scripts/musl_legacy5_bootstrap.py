"""Reconstruct SDK5's derived compiler bootstrap from authenticated inputs.

Official CLR/JIT/debuggers remain byte exact. The matching framework's two
native support replacements keep their actual source-worker identities.
No earlier private SDK archive is a preparation input.
"""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import shutil
import struct
import tarfile

ROOT = Path(__file__).resolve().parents[1]
POLICY_SHA = '7eff4829e1abb5386bc46f52539bb69f757057c970c81716d52a595ead0c691b'
SOURCE = '6a984143635bde23e728abaaccbde52f5ea8fa3e'
SUPPORT = {'crypto': 'libSystem.Security.Cryptography.Native.OpenSsl.so', 'trace': 'libcoreclrtraceptprovider.so'}
CORE = ('libcoreclr.so', 'libclrjit.so', 'libmscordaccore.so', 'libmscordbi.so')


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(path):
    hashes = {name: hashlib.new(name) for name in ('sha256', 'sha512')}; size = 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            size += len(block)
            for item in hashes.values(): item.update(block)
    return dict(bytes=size, **{name: item.hexdigest() for name, item in hashes.items()})


def ordinary(path, file=False):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)) and (not file or path.is_file()),
            'Ordinary SDK5 bootstrap source/archive/output required')
    return path


def policy():
    raw = ROOT.joinpath('scripts/musl-legacy5-bootstrap-inputs.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == POLICY_SHA, 'Closed SDK5 dual-bootstrap input plan differs')
    result = json.loads(raw)
    require(result['schemaVersion'] == 1 and result['sdkVersion'] == '5.0.214'
            and result['brandingScope'] == 'distribution-wrapper' and result['qualificationAllowed'] is False,
            'Exact original SDK5 bootstrap plan required')
    return result


def pin(role, architecture):
    require(role in ('legacy5', 'runtime', 'vstest') and architecture in ('aarch64', 'x64'),
            'An explicit reviewed SDK5 bootstrap role and native architecture required')
    rid = {'aarch64': 'linux-musl-arm64', 'x64': 'linux-musl-x64'}[architecture]
    plan = policy()
    return (plan['vstest']['sdk'] if role == 'vstest' else
            plan['nativeSdkNugetAndInstaller']['matchingRuntime'] if role == 'runtime' else
            plan['nativeSdkNugetAndInstaller']['sdk'])[rid]


def checked_archive(path, role, architecture):
    path = ordinary(path, file=True); expected = pin(role, architecture); actual = fingerprint(path)
    require(0 < actual['bytes'] <= 512 * 1024**2 and actual['sha512'] == expected['sha512'],
            'Actual official SDK5 bootstrap archive differs from its exact native pin')
    return {**expected, **actual}


def member_name(name):
    name = name.removeprefix('./')
    if name in ('', '.'): return None
    require(not any(c in name for c in ':\\\0\r\n') and not PurePosixPath(name).is_absolute()
            and all(part not in ('', '.', '..') for part in name.split('/')),
            'Ordinary confined SDK5 bootstrap archive member required')
    return name


def unpack(path, destination, prefix=None):
    """Read only bounded ordinary entries; never follow archived links."""
    seen, rows, total = set(), {}, 0
    with tarfile.open(path, 'r|gz') as archive:
        for entry in archive:
            name = member_name(entry.name.rstrip('/') if entry.isdir() else entry.name)
            require(entry.isfile() or entry.isdir(), 'SDK5 compiler bootstrap links/devices are forbidden')
            if name is None:
                require(entry.isdir(), 'Only an archive root directory may omit its member name')
                continue
            if entry.isdir(): continue
            require(name not in seen and 0 <= entry.size <= 256 * 1024**2, 'Unique bounded SDK5 bootstrap member required')
            seen.add(name)
            if prefix is not None and not name.startswith(prefix): continue
            total += entry.size; require(total <= 2 * 1024**3 and len(rows) < 100000, 'Bounded SDK5 bootstrap payload required')
            output = ordinary(destination / name); require(not output.exists(), 'An official bootstrap input would overwrite an existing file')
            output.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(entry) as source, output.open('xb') as target: shutil.copyfileobj(source, target)
            output.chmod(entry.mode & 0o777)
            rows[name] = dict(mode=entry.mode & 0o777, **fingerprint(output))
    require(rows, 'Official native bootstrap payload is empty')
    return rows


def source_support(directory, component, architecture):
    directory = ordinary(directory); filename = SUPPORT[component]
    identity = json.loads(ordinary(directory / 'identity.json', file=True).read_bytes())
    result = json.loads(ordinary(directory / 'results.json', file=True).read_bytes())
    require(identity['schemaVersion'] == 1 and identity['kind'] == 'legacy-musl-native-component-diagnostic'
            and identity['sdkVersion'] == '5.0.214'
            and identity['sourceCommit'] == SOURCE and identity['architecture'] == architecture
            and identity['component'] == component and identity['productVersionMetadataQualified'] is False
            and result['status'] == 'passed'
            and all(document[key] is False for document in (identity, result)
                    for key in ('qualificationAllowed', 'sourceAdmissionAllowed')),
            'Actual SDK5 bootstrap source-native support worker required')
    require(result['commands'] and all(row['exitCode'] == 0 for row in result['commands']),
            'Every actual SDK5 bootstrap native support command must pass')
    for row in result['commands']:
        log = ordinary(directory / row['log'], file=True)
        require(log.parent == directory and all(fingerprint(log)[k] == row[k] for k in ('bytes', 'sha256'))
                and json.loads(log.read_bytes().splitlines()[0]) == row['command'],
                'Actual SDK5 native support command log differs')
    library = ordinary(directory / filename, file=True); actual = fingerprint(library)
    require(result['library']['path'] == filename and all(result['library'][k] == actual[k] for k in ('bytes', 'sha256')),
            'SDK5 source-native bootstrap library differs from its real worker output')
    raw = library.read_bytes(); require(raw[:6] == b'\x7fELF\x02\x01' and len(raw) >= 64
            and struct.unpack_from('<H', raw, 18)[0] == (183 if architecture == 'aarch64' else 62),
            'SDK5 bootstrap native support has the wrong ELF CPU')
    spec = importlib.util.spec_from_file_location('sdk5_bootstrap_elf_bytes', ROOT / 'scripts/musl_legacy_admission.py')
    binary = importlib.util.module_from_spec(spec); spec.loader.exec_module(binary)
    needed = binary.elf_dynamic(raw)['needed']
    require(not any(name == 'libc.so.6' or name.startswith('ld-linux') or 'gcompat' in name
                    or name in ('libssl.so.1.1', 'libcrypto.so.1.1', 'liblttng-ust.so.0') for name in needed),
            'SDK5 compiler bootstrap may not restore an old SSL/UST or glibc compatibility provider')
    require(('libssl.so.3' in needed and 'libcrypto.so.3' in needed) if component == 'crypto' else 'liblttng-ust.so.1' in needed,
            'Actual stock SDK5 OpenSSL3/LTTng support dependency required')
    return library, dict(component=component, sourceCommit=SOURCE, sourceWorkerIdentity=fingerprint(directory / 'identity.json'),
        sourceWorkerResults=fingerprint(directory / 'results.json'), library=dict(name=filename, **actual),
        needed=needed, productVersionMetadataQualified=False, bootstrapRoleOnly=True)


def compose(sdk_archive, runtime_archive, crypto, trace, destination, receipt, architecture):
    destination, receipt = ordinary(destination), ordinary(receipt)
    require(not destination.exists() and not receipt.exists(), 'Fresh SDK5 derived bootstrap and receipt required')
    sdk_pin = checked_archive(sdk_archive, 'legacy5', architecture)
    runtime_pin = checked_archive(runtime_archive, 'runtime', architecture)
    support = {name: source_support(path, name, architecture) for name, path in [('crypto', crypto), ('trace', trace)]}
    destination.mkdir(parents=True)
    sdk_files = unpack(sdk_archive, destination)
    prefix = 'shared/Microsoft.NETCore.App/5.0.17/'
    require(not any(name.startswith(prefix) for name in sdk_files), 'Matching runtime must be a separately recorded bootstrap addition')
    framework = unpack(runtime_archive, destination, prefix)
    require(all(prefix + name in framework for name in CORE), 'All original official matching CLR/JIT/debugger inputs required')
    original_core = {name: framework[prefix + name] for name in CORE}
    adaptations = []
    for name, (library, record) in support.items():
        relative = prefix + SUPPORT[name]; require(relative in framework, 'Source-native support did not replace its exact official counterpart')
        target = destination / relative; before = fingerprint(target); shutil.copyfile(library, target); target.chmod(0o755)
        require(fingerprint(target) == fingerprint(library), 'Derived SDK5 bootstrap source support copy differs')
        adaptations.append(dict(path=relative, originalOfficial=before, **record))
    require(all(dict(mode=(destination / name).stat().st_mode & 0o777, **fingerprint(destination / name)) == expected
                for name, expected in sdk_files.items()), 'An original SDK5.0.401 file changed during bootstrap composition')
    require(all(dict(mode=(destination / (prefix + name)).stat().st_mode & 0o777,
                         **fingerprint(destination / (prefix + name))) == expected for name, expected in original_core.items()),
            'Official SDK5 compiler-bootstrap CLR/JIT/debugger bytes changed')
    result = dict(schemaVersion=1, kind='explicit-derived-sdk5-compiler-bootstrap', sdkVersion='5.0.401', architecture=architecture,
        sdkArchive=sdk_pin, matchingRuntimeArchive=runtime_pin, originalSdkFiles=sdk_files, matchingFrameworkFiles=framework,
        adaptations=adaptations, originalSdkFilesUnchanged=True, officialClrJitDebuggerPreserved=True,
        bootstrapCompilerRoleOnly=True, newSourceClrProductsUsedAsBootstrap=False, previousPrivateSdkArchiveUsed=False,
        claimedUnmodifiedPublisherSdkTree=False, qualificationAllowed=False, sourceAdmissionAllowed=False)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    with receipt.open('x', encoding='utf-8') as stream: json.dump(result, stream, indent=2); stream.write('\n')
    return result
