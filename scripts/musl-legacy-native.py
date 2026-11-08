#!/usr/bin/env python3
"""Build exact legacy native components on stock Alpine for diagnostics only.

The output is never a qualified SDK. The trace-provider source and event
manifest are selected independently for each runtime. The .NET 5 crypto port
links stock OpenSSL 3 and preserves its old managed X509 error ABI.
"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
PINS={'7.0.120':'0fb6ac59fb1edbe4ed3ad62661df0eb7eacd7903',
      '6.0.136':'f1dd57165bfd91875761329ac3a8b17f6606ad18',
      '5.0.214':'6a984143635bde23e728abaaccbde52f5ea8fa3e'}


def require(value,message):
    if not value:
        raise ValueError(message)


def fingerprint(path):
    return dict(bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def write(path,value):
    with path.open('x',encoding='utf-8') as stream:
        json.dump(value,stream,indent=2)
        stream.write('\n')


def git(source,*arguments):
    return subprocess.check_output(['git','-c','safe.directory='+str(source),'-C',str(source),*arguments])


def command(output,rows,name,arguments):
    with (output/(name+'.log')).open('x') as stream:
        stream.write(json.dumps(list(map(str,arguments)))+'\n');stream.flush()
        result=subprocess.run(list(map(str,arguments)),stdout=stream,stderr=subprocess.STDOUT,timeout=180)
    rows.append(dict(command=list(map(str,arguments)),exitCode=result.returncode,log=name+'.log',
                     **fingerprint(output/(name+'.log'))))
    return result.returncode==0


def trace(args,rows):
    base=args.source/'src/coreclr'
    if args.sdk.startswith('5.'):
        base=base/'src'
    generated=args.output/'generated'
    if not command(args.output,rows,'generate',['python3',base/'scripts/genLttngProvider.py',
        '--man',base/'vm/ClrEtwAll.man','--intermediate',generated]):
        return None
    cpu='ARM64' if args.arch=='aarch64' else 'AMD64'
    includes=[base/'pal/inc',base/'pal/inc/rt',base/'inc',base/'minipal',generated/'lttng']
    sources=sorted((generated/'lttng').glob('traceptprov*.cpp'))
    require(sources,'Pinned source generator produced no trace-point provider files')
    library=args.output/'libcoreclrtraceptprovider.so'
    arguments=['clang++','-shared','-fPIC','-O2','-DPAL_STDCPP_COMPAT=1','-DPLATFORM_UNIX=1',
               '-DTARGET_'+cpu+'=1','-DHOST_'+cpu+'=1','-DTARGET_64BIT=1','-DHOST_64BIT=1']
    arguments+=['-I'+str(path) for path in includes]
    arguments+=sources+['-llttng-ust','-ldl','-Wl,-soname,libcoreclrtraceptprovider.so','-o',library]
    if not command(args.output,rows,'build',arguments):
        return None
    ctypes.CDLL(str(library))
    write(args.output/'native-load.json',dict(loaded=True,**fingerprint(library)))
    return library


def crypto_smoke(library):
    lib=ctypes.CDLL(str(library))
    random=lib.CryptoNative_GetRandomBytes
    random.argtypes,random.restype=[ctypes.c_void_p,ctypes.c_int],ctypes.c_int
    output=(ctypes.c_ubyte*32)()
    status=random(output,len(output))
    ssl=ctypes.CDLL('libcrypto.so.3')
    ssl.X509_STORE_CTX_new.restype=ctypes.c_void_p
    ssl.X509_STORE_CTX_set_error.argtypes=[ctypes.c_void_p,ctypes.c_int]
    ssl.X509_STORE_CTX_free.argtypes=[ctypes.c_void_p]
    context=ssl.X509_STORE_CTX_new()
    require(context,'Cannot create a stock OpenSSL X509 verification context')
    try:
        ssl.X509_STORE_CTX_set_error(context,79)
        lib.CryptoNative_X509StoreCtxGetError.argtypes=[ctypes.c_void_p]
        lib.CryptoNative_X509VerifyCertErrorString.argtypes=[ctypes.c_int]
        lib.CryptoNative_X509VerifyCertErrorString.restype=ctypes.c_char_p
        mapped=lib.CryptoNative_X509StoreCtxGetError(context)
        description=lib.CryptoNative_X509VerifyCertErrorString(24).decode()
        require(status==1 and any(output) and mapped==24 and description=='invalid CA certificate',
                'Native RNG or bidirectional managed X509 ABI translation failed')
        return dict(loaded=True,randomStatus=status,randomNonzero=any(output),nativeInvalidCa=79,
                    managedInvalidCa=mapped,invalidCaDescription=description,**fingerprint(library))
    finally:
        ssl.X509_STORE_CTX_free(context)


def crypto(args,rows):
    require(args.sdk=='5.0.214','Only the exact independently tested runtime5 OpenSSL3 port is supported')
    relative=Path('src/libraries/Native/Unix')
    native=args.output/'source'/relative
    native.mkdir(parents=True)
    for name in ['Common','System.Security.Cryptography.Native']:
        shutil.copytree(args.source/relative/name,native/name)
    shutil.copyfile(args.source/relative/'configure.cmake',native/'configure.cmake')
    # Always apply the recorded patch to the exact Git source, including if a
    # diagnostic source worktree already has the same local patch applied.
    for name in ['openssl.c','pal_x509.c']:
        path=relative/'System.Security.Cryptography.Native'/name
        (args.output/'source'/path).write_bytes(git(args.source,'show',PINS[args.sdk]+':'+path.as_posix()))
    patch=ROOT/'patches/net5-musl/0001-use-stock-openssl3.patch'
    if not command(args.output,rows,'apply-patch',['git','-C',args.output/'source','apply',patch]):
        return None
    write(args.output/'patch.json',dict(path=patch.relative_to(ROOT).as_posix(),**fingerprint(patch),
        donorRuntimeCommit=PINS['6.0.136'],scope='OID parsing and managed X509 error-code/error-string ABI only'))
    driver=args.output/'driver';driver.mkdir()
    shutil.copytree(native/'Common',driver/'Common')
    (driver/'version.c').write_text('/* diagnostic-only component metadata; no qualified SDK version claim */\n')
    (driver/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.5)\nproject(LegacyMuslCrypto C)\n'
        'set(CMAKE_POSITION_INDEPENDENT_CODE ON)\nset(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -D_GNU_SOURCE")\n'
        'set(VERSION_FILE_PATH "'+str(driver/'version.c')+'")\n'
        'include_directories("'+str(native/'Common')+'" "${CMAKE_BINARY_DIR}/Common" "${CMAKE_BINARY_DIR}/crypto")\n'
        'include("'+str(native/'configure.cmake')+'")\n'
        'function(install_library_and_symbols name)\nendfunction()\n'
        'function(install_with_stripped_symbols name)\nendfunction()\n'
        'add_subdirectory("'+str(native/'System.Security.Cryptography.Native')+'" crypto)\n')
    if not command(args.output,rows,'configure',['cmake','-S',driver,'-B',args.output/'obj',
        '-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_POLICY_VERSION_MINIMUM=3.5',
        '-DFEATURE_DISTRO_AGNOSTIC_SSL=OFF','-DCLR_CMAKE_TARGET_LINUX=1','-DCLR_CMAKE_TARGET_UNIX=1']):
        return None
    if not command(args.output,rows,'build',['cmake','--build',args.output/'obj','--target',
        'System.Security.Cryptography.Native.OpenSsl','--parallel','2']):
        return None
    library=args.output/'libSystem.Security.Cryptography.Native.OpenSsl.so'
    shutil.copyfile(args.output/'obj/crypto'/library.name,library)
    write(args.output/'native-abi-smoke.json',crypto_smoke(library))
    return library


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('component',choices=['trace','crypto'])
    parser.add_argument('--sdk',choices=list(PINS),required=True)
    parser.add_argument('--arch',choices=['x64','aarch64'],required=True)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    require(platform.system()=='Linux' and platform.machine()=={'x64':'x86_64','aarch64':'aarch64'}[args.arch]
        and os.getuid()!=0 and Path('/etc/alpine-release').read_text().strip()=='3.24.4',
        'Matching native non-root Alpine3.24.4 source build required')
    for path in [args.source,args.output]:
        require(path.is_absolute() and path!=Path('/') and not any(p.is_symlink() for p in [path,*path.parents]),
                'Ordinary absolute source/output paths required')
    require(git(args.source,'rev-parse','HEAD').decode().strip()==PINS[args.sdk],'Exact runtime source pin differs')
    require(not args.output.exists(),'A fresh native component output directory is required')
    args.output.mkdir(parents=True)
    write(args.output/'identity.json',dict(schemaVersion=1,kind='legacy-musl-native-component-diagnostic',
        sdkVersion=args.sdk,component=args.component,sourceCommit=PINS[args.sdk],architecture=args.arch,
        qualificationAllowed=False,sourceAdmissionAllowed=False,productVersionMetadataQualified=False))
    rows=[]
    library=(trace if args.component=='trace' else crypto)(args,rows)
    if library:
        require(command(args.output,rows,'elf',['readelf','--wide','--file-header','--dynamic','--version-info',library]),
                'Native component ELF inspection failed')
    write(args.output/'results.json',dict(status='passed' if library else 'failed',commands=rows,
        library=dict(path=library.name,**fingerprint(library)) if library else None,
        qualificationAllowed=False,sourceAdmissionAllowed=False))
    print(json.dumps(dict(status='passed' if library else 'failed',output=str(args.output))))


if __name__=='__main__':
    main()
