#!/usr/bin/env python3
"""Native APK machinery validation using explicit synthetic command fixtures.

This does not qualify a Community SDK, a runtime, or a public repository. Keys
exist only in a TemporaryDirectory and reports always say fixture-only.
"""
import argparse
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile

import musl_packages as APK
from musl_contract import ARCHITECTURES, NATIVE_DEPENDENCIES
from distribution_contract import BRANDING


def run(command, check=True):
    result = subprocess.run([str(x) for x in command], capture_output=True, text=True)
    if check and result.returncode:
        raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)
    return result


def native_architecture():
    machine = platform.machine()
    APK.require(machine in {'x86_64', 'aarch64', 'arm64'}, 'Unsupported fixture native CPU')
    return 'x64' if machine == 'x86_64' else 'aarch64'


def fixture_archive(directory, version, arch):
    archive = directory / f'cbodotnet-sdk-{version}-linux-musl-{arch}-r1.tar.gz'
    # The shell host validates packaging/selection behavior only. It is never
    # described as an independently rebuilt .NET host or used for runtime proof.
    files = [('dotnet', f'#!/bin/sh\ncase "$1" in --version) printf "%s\\n" "{version}" ;; *) printf "%s\\n" "synthetic-command-fixture" ;; esac\n'.encode(), 0o755),
             ('LICENSE.txt', b'Synthetic APK machinery fixture, not a .NET SDK.\n', 0o644),
             ('ThirdPartyNotices.txt', b'No .NET runtime files are present in this fixture.\n', 0o644)]
    with tarfile.open(archive, mode='w:gz') as tar:
        for name, content, mode in files:
            entry = tarfile.TarInfo(name)
            entry.mode, entry.size, entry.mtime = mode, len(content), int(APK.SOURCE_DATE_EPOCH)
            tar.addfile(entry, io.BytesIO(content))
    return archive


def fixture_plan(archive, version, arch, revision):
    series = '.'.join(version.split('.')[:2])
    return dict(schemaVersion=1, contractVersion=1, kind='synthetic-command-fixture', status='prepared-unqualified',
        publicationAllowed=False, libc='musl', sdkVersion=version, producerRevision=1, packageRevision=revision,
        architecture=dict(ARCHITECTURES[arch]), targetRid=ARCHITECTURES[arch]['rid'], variant='alpine-3.24', channel='apk',
        package=dict(name='cbodotnet-sdk-'+series, version=f'{version}-r{revision}',
            root='/opt/cbodotnet/'+series, launcher='/usr/bin/cbodotnet-'+series),
        sdk=dict(name=archive.name, size=archive.stat().st_size, sha256=APK.sha256_file(archive)),
        branding=dict(BRANDING), dependencies=list(NATIVE_DEPENDENCIES),
        licensePaths=['LICENSE.txt','ThirdPartyNotices.txt'], sourceReleaseTag='synthetic-command-fixture',
        sourceManifestSha256='0'*64)


def build(output):
    APK.require(os.geteuid() != 0, 'Fixture APK builds must run unprivileged')
    arch = native_architecture()
    output = APK.fresh_output(output)
    archives = output/'input'
    archives.mkdir()
    source10 = fixture_archive(archives, '10.0.403', arch)
    source9 = fixture_archive(archives, '9.0.123', arch)
    with tempfile.TemporaryDirectory(prefix='ephemeral-apk-fixture-') as temporary:
        keys = Path(temporary)
        for name in ('fixture', 'wrong'):
            key, public = keys/(name+'.rsa'), keys/(name+'.rsa.pub')
            run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:4096','-out',key])
            key.chmod(0o600)
            run(['openssl','pkey','-in',key,'-pubout','-out',public])
            shutil.copyfile(public, output/public.name)
        builds = {}
        for label, archive, version, revision in [('sdk10r1',source10,'10.0.403',1),
                ('sdk10r2',source10,'10.0.403',2), ('sdk9r1',source9,'9.0.123',1)]:
            builds[label] = APK.build_apk(fixture_plan(archive,version,arch,revision), archive,
                output/label, keys/'fixture.rsa', keys/'fixture.rsa.pub', fixture=True)
    host_hashes = {next(p['sha256'] for p in row['packages'] if p['kind']=='host') for row in builds.values()}
    APK.require(len(host_hashes)==1, 'Shared host package must be byte-identical across fixture SDKs/revisions')
    result = dict(schemaVersion=1,status='fixture-only',fixtureType='synthetic-command-fixture',
        productionQualification=False, architecture=arch, nativeMachine=platform.machine(),
        builds={key: {'packages':value['packages'], 'repository':value['repository']} for key,value in builds.items()})
    APK.write_json(output/'fixture-build.json',result)
    return result


def assert_fixture_cli(version):
    result = run(['su','builder','-c','/usr/bin/cbodotnet --version'])
    APK.require(result.stdout.strip()==version and result.stderr.strip()==BRANDING['displayName'], 'Fixture selector/branding differs')
    info = json.loads(run(['su','builder','-c','/usr/bin/cbodotnet --cbodotnet-info']).stdout)
    APK.require(info['libc']=='musl' and info['sdkVersion']==version, 'Fixture command identity differs')


def lifecycle(build_directory, output):
    APK.require(os.geteuid()==0 and (Path('/.dockerenv').exists() or Path('/run/.containerenv').exists()),
                'Lifecycle mutation is allowed only inside this disposable fixture container')
    APK.require(Path('/etc/alpine-release').read_text().strip()=='3.24.4', 'Pinned Alpine fixture container required')
    build_directory = Path(build_directory).absolute()
    record = json.loads((build_directory/'fixture-build.json').read_bytes())
    APK.require(record.get('status')=='fixture-only' and record.get('productionQualification') is False
                and record['architecture']==native_architecture(), 'Explicit matching native fixture build required')
    key = build_directory/'fixture.rsa.pub'
    key_destination = Path('/etc/apk/keys')/key.name
    APK.require(not key_destination.exists(), 'Refusing to replace an existing trust key')
    shutil.copyfile(key,key_destination)
    key_destination.chmod(0o644)
    official = Path('/usr/bin/dotnet')
    APK.require(official.is_file(), 'Independent Alpine official dotnet must be preinstalled for coexistence')
    official_version = run(['dotnet','--version']).stdout.strip()
    official_owner = run(['apk','info','--who-owns','/usr/bin/dotnet']).stdout.strip()
    APK.require('dotnet-host' in official_owner, 'Official dotnet is not owned by Alpine dotnet-host')
    official_host_hash = APK.sha256_file(official.resolve())
    official_tree = APK.sdk_tools().snapshot(official.resolve().parent)
    events=[]
    def install(label, package, version, extra=()):
        index=build_directory/label/'repository/APKINDEX.tar.gz'
        run(['apk','--no-cache','--repository',index,'add',*extra,package+'='+version])
        events.append(label+':'+package+'='+version)
    def remove(name):
        run(['apk','del',name])
        events.append('remove:'+name)
    negative={}
    with tempfile.TemporaryDirectory(prefix='apk-negative-') as temporary:
        temp=Path(temporary)
        trust=temp/'trust'
        trust.mkdir()
        shutil.copyfile(key,trust/key.name)
        sdk=next(p for p in record['builds']['sdk10r1']['packages'] if p['kind']=='sdk')
        package=build_directory/'sdk10r1/repository'/sdk['path']
        index=build_directory/'sdk10r1/repository/APKINDEX.tar.gz'
        run(['apk','--keys-dir',trust,'verify',package,index])
        def rejected(label,path,keys=trust):
            result=run(['apk','--keys-dir',keys,'verify',path],check=False)
            APK.require(result.returncode!=0, 'apk accepted the negative fixture: '+label)
            negative[label]={'exitCode':result.returncode,'diagnostic':(result.stderr+result.stdout).strip()}
        # Change signed control while retaining a syntactically valid gzip stream.
        with package.open('rb') as stream:
            sig,_=APK.gzip_member(stream)
            _,plain=APK.gzip_member(stream)
            remaining=stream.read()
        tampered=temp/'control.apk'
        tampered.write_bytes(sig+gzip.compress(plain+b'\0'*512,mtime=0)+remaining)
        rejected('changed-package-control',tampered)
        tampered=temp/'payload.apk'
        # Retain a valid gzip/tar stream so rejection proves datahash integrity,
        # rather than merely noticing a broken gzip CRC or malformed archive.
        data=bytearray(gzip.decompress(remaining))
        position=data.find(b'synthetic-command-fixture')
        APK.require(position>=0,'Missing synthetic fixture payload marker')
        data[position]=ord('S')
        with package.open('rb') as stream:
            sig,_=APK.gzip_member(stream)
            control,_=APK.gzip_member(stream)
        tampered.write_bytes(sig+control+gzip.compress(bytes(data),mtime=0))
        rejected('changed-package-payload',tampered)
        with index.open('rb') as stream:
            sig,_=APK.gzip_member(stream)
            _,plain=APK.gzip_member(stream)
        tampered=temp/'APKINDEX.tar.gz'
        tampered.write_bytes(sig+gzip.compress(plain+b'\0'*512,mtime=0))
        rejected('changed-index',tampered)
        wrong=temp/'wrong'
        wrong.mkdir()
        shutil.copyfile(build_directory/'wrong.rsa.pub',wrong/key.name)
        rejected('wrong-key-same-name-package',package,wrong)
        rejected('wrong-key-same-name-index',index,wrong)
        missing=temp/'missing'
        missing.mkdir()
        rejected('missing-key',index,missing)
    install('sdk10r1','cbodotnet-sdk-10.0','10.0.403-r1')
    # Retain the shared host explicitly in world to exercise its empty-selector
    # behavior after the final SDK is removed. Dependency-only installs may
    # legitimately auto-remove the host with the last SDK.
    install('sdk10r1','cbodotnet-host',APK.HOST_VERSION)
    assert_fixture_cli('10.0.403')
    run(['apk','--no-cache','--repository',build_directory/'sdk10r1/repository/APKINDEX.tar.gz',
         'fix','--reinstall','cbodotnet-sdk-10.0'])
    events.append('reinstall:sdk10r1')
    assert_fixture_cli('10.0.403')
    install('sdk10r2','cbodotnet-sdk-10.0','10.0.403-r2',('--upgrade',))
    assert_fixture_cli('10.0.403')
    install('sdk10r1','cbodotnet-sdk-10.0','10.0.403-r1')
    assert_fixture_cli('10.0.403')
    install('sdk9r1','cbodotnet-sdk-9.0','9.0.123-r1')
    assert_fixture_cli('10.0.403')
    remove('cbodotnet-sdk-10.0')
    assert_fixture_cli('9.0.123')
    install('sdk10r2','cbodotnet-sdk-10.0','10.0.403-r2')
    assert_fixture_cli('10.0.403')
    remove('cbodotnet-sdk-9.0')
    assert_fixture_cli('10.0.403')
    remove('cbodotnet-sdk-10.0')
    APK.require(run(['cbodotnet','--version'],check=False).returncode==127, 'Empty selector should fail clearly')
    run(['apk','info','--exists','cbodotnet-host'])
    remove('cbodotnet-host')
    APK.require(not Path('/usr/bin/cbodotnet').exists(), 'Shared selector remained after host package removal')
    APK.require(run(['dotnet','--version']).stdout.strip()==official_version
        and run(['apk','info','--who-owns','/usr/bin/dotnet']).stdout.strip()==official_owner
        and APK.sha256_file(official.resolve())==official_host_hash
        and APK.sdk_tools().snapshot(official.resolve().parent)==official_tree,
        'Community APK lifecycle changed independent official dotnet')
    key_destination.unlink()
    result=dict(schemaVersion=1,status='fixture-only',fixtureType='synthetic-command-fixture',productionQualification=False,
        architecture=native_architecture(),nativeMachine=platform.machine(),alpineRelease='3.24.4',
        apkVersion=run(['apk','--version']).stdout.strip(),abuildVersion=run(['abuild','-V']).stdout.strip(),
        official=dict(version=official_version,owner=official_owner,hostSha256=official_host_hash,preserved=True),
        nativePackageSignatureEnforcement=True,negativeCases=negative,lifecycle=events,
        scope='APK assembly/trust/lifecycle only; no SDK runtime, producer, public HTTPS or OCI qualification')
    APK.write_json(Path(output),result)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=('build','lifecycle'))
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--build',type=Path)
    args=parser.parse_args()
    result=build(args.output) if args.phase=='build' else lifecycle(args.build,args.output)
    print(json.dumps({'status':result['status'],'architecture':result['architecture'],'productionQualification':False}))


if __name__=='__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        import sys
        print(error.stdout or '',file=sys.stderr)
        print(error.stderr or '',file=sys.stderr)
        raise
