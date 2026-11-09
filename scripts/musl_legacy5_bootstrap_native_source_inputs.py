"""SDK5 native compiler-bootstrap source copies and generated trace inputs.

The existing byte leaf remains separate. This validator reads authenticated
runtime sources and the actual copied/generated source trees from the used
source archive; it never runs Python generators or native compilers.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import tarfile

import musl_legacy5_bootstrap_byte_inputs as BYTE
import musl_legacy5_native_inputs as NATIVE

B=BYTE.B;CE=BYTE.CE
require,portable=B.require,B.portable
FP=CE.FP
ROOT=Path(__file__).resolve().parents[1]
POLICY_SHA256='46164e1853773858ebad55b89131a54fe0bf92b1c7b25b1e4c39e7f37acb3b0c'
UNIX='src/libraries/Native/Unix/'
CRYPTO=UNIX+'System.Security.Cryptography.Native/'
ROOTS={'crypto':'bootstrap-crypto-inputs','trace':'bootstrap-trace-inputs'}
SOURCE_ROLE='actual-source-native-compiler-bootstrap-support'
OPENSSL_TARGETS=(CRYPTO+'openssl.c',CRYPTO+'pal_x509.c')
GENERATOR_NAMES=tuple('src/coreclr/src/scripts/'+n for n in ('genLttngProvider.py','genEventing.py','utilities.py'))+('src/coreclr/src/vm/ClrEtwAll.man',)
HEADER_PREFIXES=tuple('src/coreclr/src/'+name+'/' for name in ('pal/inc','inc','minipal'))


def fingerprint(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),sha512=hashlib.sha512(raw).hexdigest())


def policy():
    path=CE.ordinary(ROOT/'scripts/musl-legacy5-bootstrap-native-source-policy.json');raw=path.read_bytes()
    require(hashlib.sha256(raw).hexdigest()==POLICY_SHA256,'Closed distinct SDK5 bootstrap native source policy required')
    p=json.loads(raw)
    require(p.get('schemaVersion')==1 and p.get('sdkVersion')==CE.SDK and p.get('sourceCommit')==BYTE.C.SOURCE
            and p.get('sourceTree')==NATIVE.TREE and set(p['generatorInputs'])==set(GENERATOR_NAMES)
            and len(p['generatorOutputs'])==12 and p.get('observedArchitecture')=='aarch64'
            and len(p['generatedIncludeDirectoryFiles'])==91
            and all(p[key] is False for key in ('qualificationAllowed','sourceAdmissionAllowed')),
            'Original SDK5 generator inputs and complete expected outputs required')
    return p


def selected_runtime(name):
    return name.startswith((UNIX+'Common/',CRYPTO,*HEADER_PREFIXES)) or name==UNIX+'configure.cmake' or name in GENERATOR_NAMES


def original_runtime_bytes(relative,row,value,sections):
    base=row['baseline']
    require(row['mode']==base['mode'],'Original SDK5 bootstrap C/C++/generator source mode must match its Git baseline')
    blob=lambda data:hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
    if blob(value)!=base['blob']:
        require(relative in sections,'An undeclared SDK5 bootstrap source change is present: '+relative)
        value=B.reverse_reviewed_patch(value,sections[relative],relative)
    require(blob(value)==base['blob'],'SDK5 bootstrap source must recover its exact original Git bytes')
    return value


def source_archive(release,manifest):
    """P.verify must run first; reconstruct the full baseline tree again here."""
    BYTE.constructor_policy();release=Path(release)
    runtime=[r for r in manifest['roots'] if r['name']=='runtime']
    require(len(runtime)==1 and runtime[0].get('kind') in ('git','git-export') and runtime[0].get('commit')==BYTE.C.SOURCE
            and runtime[0].get('tree')==NATIVE.TREE and not runtime[0].get('deleted'), 'Full original SDK5 runtime source root required')
    for name in ROOTS.values():
        found=[r for r in manifest['roots'] if r['name']==name]
        require(len(found)==1 and found[0].get('kind')=='tree' and found[0].get('role')==SOURCE_ROLE,
                'Actual distinct SDK5 bootstrap support source tree required: '+name)
    orchestration={'orchestration/scripts/musl-legacy-native.py','orchestration/patches/net5-musl/0001-use-stock-openssl3.patch'}
    orchestration|={'orchestration/'+name for name in NATIVE.PATCHES}
    baseline,indexed={},{}
    index=B.checked(release/'sources',manifest['index'])
    with index.open() as stream:
        for line in stream:
            row=json.loads(line);name=portable(row['path'])
            if name.startswith('runtime/'):
                relative=name[len('runtime/'):]
                require(relative not in baseline and isinstance(row.get('baseline'),dict), 'Unique complete original SDK5 runtime baseline required')
                baseline[relative]=row['baseline']
                if selected_runtime(relative):indexed[name]=row
            elif name in orchestration or any(name.startswith(root+'/') for root in ROOTS.values()):
                require(name not in indexed,'Unique archived SDK5 bootstrap native input required');indexed[name]=row
    spec=importlib.util.spec_from_file_location('sdk5_bootstrap_original_tree',ROOT/'scripts/package-used-source.py')
    packer=importlib.util.module_from_spec(spec);spec.loader.exec_module(packer)
    for child in runtime[0].get('submodules',[]):baseline[child['path']]=dict(mode='160000',blob=child['commit'])
    require(packer.baseline_tree(baseline)==NATIVE.TREE and orchestration<=indexed.keys(), 'Complete original SDK5 runtime tree and worker/patch sources required')
    raw={};archive=B.checked(release/'sources',manifest['archive'])
    with tarfile.open(archive,'r|gz') as tar:
        for entry in tar:
            if entry.name not in indexed:continue
            row=indexed[entry.name]
            require(entry.isfile() and entry.name not in raw and 0<=entry.size<=16*1024**2
                    and row['mode'] in ('100644','100755')
                    and entry.mode==(0o755 if row['mode']=='100755' else 0o644), 'Ordinary exact-mode archived SDK5 bootstrap native input required')
            value=tar.extractfile(entry).read();require(fingerprint(value)=={k:row[k] for k in FP},'Archived SDK5 bootstrap native input bytes differ')
            raw[entry.name]=value
    require(raw.keys()==indexed.keys(),'Every SDK5 bootstrap source/archive input must be present')
    for name in orchestration:
        require(raw[name]==(ROOT/name.removeprefix('orchestration/')).read_bytes(),'Actual SDK5 native worker/patch differs from archived orchestration')
    # Later native-CoreCLR patches can affect a trace include after prepare.
    # Reverse only their declared sections, then demand the original Git blob.
    sections={}
    for path,(_,targets) in NATIVE.PATCHES.items():
        sections.update(NATIVE.patch_sections(raw['orchestration/'+path],targets))
    originals={}
    for name,value in raw.items():
        if not name.startswith('runtime/'):continue
        relative=name[len('runtime/'):];row=indexed[name];base=row['baseline']
        value=original_runtime_bytes(relative,row,value,sections)
        originals[relative]=dict(raw=value,mode=row['mode'],gitBlob=base['blob'])
    return originals,raw,indexed


def expected_driver():
    output='/delivery/reports/prepare/bootstrap-crypto';driver=output+'/driver';native=output+'/source/'+UNIX.rstrip('/')
    version=b'/* diagnostic-only component metadata; no qualified SDK version claim */\n'
    cmake=('cmake_minimum_required(VERSION 3.5)\nproject(LegacyMuslCrypto C)\n'
        'set(CMAKE_POSITION_INDEPENDENT_CODE ON)\nset(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -D_GNU_SOURCE")\n'
        'set(VERSION_FILE_PATH "'+driver+'/version.c")\n'
        'include_directories("'+native+'/Common" "${CMAKE_BINARY_DIR}/Common" "${CMAKE_BINARY_DIR}/crypto")\n'
        'include("'+native+'/configure.cmake")\n'
        'function(install_library_and_symbols name)\nendfunction()\n'
        'function(install_with_stripped_symbols name)\nendfunction()\n'
        'add_subdirectory("'+native+'/System.Security.Cryptography.Native" crypto)\n').encode()
    return {'driver/version.c':version,'driver/CMakeLists.txt':cmake}


def crypto_sources(originals,files):
    selected={name:row for name,row in originals.items() if name.startswith((UNIX+'Common/',CRYPTO)) or name==UNIX+'configure.cmake'}
    require(len(selected)==72 and set(OPENSSL_TARGETS)<=selected.keys(),'Complete original SDK5 crypto/Common/configure source selection required')
    expected={'source/'+name:row['raw'] for name,row in selected.items()}
    patch=(ROOT/'patches/net5-musl/0001-use-stock-openssl3.patch').read_bytes()
    sections=NATIVE.patch_sections(patch,OPENSSL_TARGETS)
    actual={name:row['raw'] for name,row in files.items() if name.startswith('source/')}
    require(actual.keys()==expected.keys(),'Every and only original SDK5 crypto source copy is required')
    for name,value in actual.items():
        relative=name[len('source/'):];original=selected[relative]
        require(files[name]['mode']==original['mode'],'Copied SDK5 crypto source executable mode differs from original Git')
        if relative in sections:value=B.reverse_reviewed_patch(value,sections[relative],relative)
        require(value==expected[name],'An undeclared SDK5 crypto copied-source change is present: '+relative)
    driver=expected_driver()
    driver.update({'driver/Common/'+name[len(UNIX+'Common/'):]:row['raw'] for name,row in selected.items() if name.startswith(UNIX+'Common/')})
    actual_driver={name:row['raw'] for name,row in files.items() if name.startswith('driver/')}
    require(actual_driver==driver and len(driver)==12,'Exact original SDK5 crypto driver and complete Common copy required')
    require(all(files[name]['mode']=='100644' for name in driver),'Exact SDK5 crypto driver source modes required')
    return dict(originalCopiedFiles=len(selected),declaredPatchedFiles=list(OPENSSL_TARGETS),driverFiles=len(driver))


def trace_sources(originals,files,p):
    for name,expected in p['generatorInputs'].items():
        require(name in originals and fingerprint(originals[name]['raw'])=={k:expected[k] for k in FP}
                and originals[name]['gitBlob']==expected['gitBlob'],'Exact authenticated SDK5 trace generator source/manifest required')
    generated={name[len('generated/'):]:dict(mode=0o755 if row['mode']=='100755' else 0o644,**fingerprint(row['raw']))
               for name,row in files.items() if name.startswith('generated/')}
    require(generated==p['generatorOutputs'],'All independently reconstructed original SDK5 trace CPP/header bytes and modes required')
    return dict(generatorOriginalFiles=len(p['generatorInputs']),generatedFiles=len(generated),
        originalRuntimeHeaderFiles=sum(name.startswith(HEADER_PREFIXES) for name in originals),generatorReexecutedByValidator=False)


def crypto_graph(files,p):
    included={name:0o755 if row['mode']=='100755' else 0o644 for name,row in files.items()
              if name.startswith(('obj/Common/','obj/crypto/'))}
    require(included==p['generatedIncludeDirectoryFiles'],
            'Closed SDK5 generated include-directory file names/modes required; extra shadow headers or forced-input files are forbidden')
    for name,expected in p['cryptoGeneratedBuildGraph'].items():
        require(name in files and dict(mode=0o755 if files[name]['mode']=='100755' else 0o644,**fingerprint(files[name]['raw']))==expected,
                'Exact recorded SDK5 crypto CMake object/flags/link graph required')
    cmake=files['source/'+CRYPTO+'CMakeLists.txt']['raw'].decode()
    match=re.findall(r'set\(NATIVECRYPTO_SOURCES\s+(.*?)\n\)',cmake,re.S)
    require(len(match)==1,'One original SDK5 crypto C source list required')
    names=match[0].split();require(len(names)==27 and all(re.fullmatch(r'[a-z0-9_]+\.c',name) for name in names),
            'All27 original SDK5 crypto C sources required')
    make=files['obj/crypto/CMakeFiles/objlib.dir/build.make']['raw'].decode()
    compiled=re.findall(r'\tcd [^\n]+ /usr/lib/llvm20/bin/clang [^\n]+ -c ([^\n]+)\n',make)
    prefix='/delivery/reports/prepare/bootstrap-crypto/'
    expected={prefix+'source/'+CRYPTO+name for name in names}|{prefix+'driver/version.c'}
    require(len(compiled)==28 and set(compiled)==expected,'Exact original SDK5 crypto27-source plus diagnostic-version object graph required')
    return dict(originalCryptoCompilationUnits=27,diagnosticVersionUnits=1,generatedCmakeGraphFiles=len(p['cryptoGeneratedBuildGraph']),
        sourceCompilationDatabaseInvented=False)


def validate(release,manifest,record,*,native_directory=None):
    release=Path(release);p=policy()
    require(record.get('sdkVersion')==CE.SDK and record.get('architecture')==p['observedArchitecture'],
            'SDK5 bootstrap native source graph is validated only for its observed aarch64 architecture; x64 positive is pending')
    native_directory=Path(native_directory) if native_directory is not None else release/'reports/build/native-runtime'
    native=NATIVE.source_inputs(release,manifest,native_directory)
    originals,archived,indexed=source_archive(release,manifest);result={}
    for component,root in ROOTS.items():
        directory=release/'reports/prepare'/('bootstrap-'+component)
        BYTE.native_support(directory,component,record['architecture'])
        actual=BYTE.actual_tree(directory)
        files={name[len(root)+1:]:dict(raw=raw,mode=indexed[name]['mode']) for name,raw in archived.items() if name.startswith(root+'/')}
        require({name:dict(mode=0o755 if value['mode']=='100755' else 0o644,**fingerprint(value['raw'])) for name,value in files.items()}==actual,
                'Actual native bootstrap support source/report tree must equal its complete archived bytes and modes')
        result[component]=dict(**crypto_sources(originals,files),**crypto_graph(files,p)) if component=='crypto' else trace_sources(originals,files,p)
    return dict(status='passed-sdk5-bootstrap-native-source-copies-and-original-generator-inputs',components=result,
        originalRuntimeSourceRevalidated=native,compilerDatabaseClaimed=False,compileTimeHashingClaimed=False,
        wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)
