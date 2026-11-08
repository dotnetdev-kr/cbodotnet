#!/usr/bin/env python3
"""Execute bound legacy SDK candidate crypto/ICU/apphost/HTTP/TLS probes.

Run offline and tls separately so the first process has no network. Both use
the frozen SDK-free stock Alpine runtime image, an unprivileged user and a
fresh private SDK extraction. No native overlays or host SDK are accepted.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path,PurePosixPath
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('legacy_functional_probe',ROOT/'scripts/musl-legacy-assess.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=['offline','tls'])
    parser.add_argument('--archive',type=Path,required=True)
    parser.add_argument('--sdk-version',choices=list(M.VERSIONS),required=True)
    parser.add_argument('--arch',choices=['x64','aarch64'],required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    M.require(os.getuid()!=0 and platform.system()=='Linux' and platform.machine()=={'x64':'x86_64','aarch64':'aarch64'}[args.arch]
        and Path('/etc/alpine-release').read_text().strip()=='3.24.4','Native non-root Alpine3.24.4 runtime worker required')
    M.require(not any(Path(p).exists() for p in ['/usr/share/dotnet','/usr/bin/dotnet']) and
        subprocess.run(['sh','-c','command -v clang || command -v cc || command -v gcc'],stdout=subprocess.DEVNULL).returncode!=0,
        'SDK-free and compiler-free runtime image required')
    M.require(args.archive.is_file() and not args.archive.is_symlink(),'Ordinary genuine candidate SDK archive required')
    identity=M.digest(args.archive)
    if args.mode=='offline':
        M.require(not args.output.exists(),'Fresh candidate functional evidence required')
        args.output.mkdir(parents=True)
        M.write(args.output/'candidate.json',dict(schemaVersion=1,kind='legacy-musl-sdk-functional-candidate',
            sdkVersion=args.sdk_version,architecture=args.arch,archive=dict(name=args.archive.name,**identity),
            qualificationAllowed=False,sourceAdmissionAllowed=False))
    else:
        saved=json.loads((args.output/'candidate.json').read_text())
        M.require(saved['sdkVersion']==args.sdk_version and saved['architecture']==args.arch and
            all(saved['archive'].get(k)==v for k,v in identity.items()),'Online TLS archive differs from offline tested bytes')
    with tempfile.TemporaryDirectory(prefix='cbodotnet-legacy-sdk-') as temporary:
        sdk=Path(temporary)/'sdk';sdk.mkdir()
        with tarfile.open(args.archive,'r:gz') as archive:
            for member in archive.getmembers():
                path=PurePosixPath(member.name)
                M.require(not path.is_absolute() and '..' not in path.parts and (member.isfile() or member.isdir()),
                    'Only ordinary safe candidate SDK members are permitted')
            archive.extractall(sdk,filter='data')
        environment=dict(os.environ,DOTNET_ROOT=str(sdk),DOTNET_MULTILEVEL_LOOKUP='0',
            DOTNET_CLI_HOME=str(Path(temporary)/'home'),HOME=str(Path(temporary)/'home'),
            CBODOTNET_PROBE_SDK=str(sdk),CBODOTNET_PROBE_EVIDENCE=str(args.output))
        if args.mode=='offline':
            elves=[]
            for path in sorted(sdk.rglob('*')):
                if path.is_file():
                    with path.open('rb') as stream:header=stream.read(4)
                    if header==b'\x7fELF':elves.append(dict(path=path.relative_to(sdk).as_posix(),**M.digest(path)))
            M.require(elves,'No candidate native host/runtime components found')
            M.write(args.output/'elf-members.json',elves)
            result=subprocess.run(['python3','-c',M.PROBE,args.sdk_version.split('.')[0]],env=environment,
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=420)
            M.write(args.output/'offline-orchestration.json',dict(exitCode=result.returncode,output=result.stdout,
                probeSha256=hashlib.sha256(M.PROBE.encode()).hexdigest()))
            M.require(result.returncode==0,'Candidate offline functional worker failed')
            required=['sdk-info','offline-build','icu','crypto','aspnet','apphost']
            for name in required:
                M.require(json.loads((args.output/(name+'.json')).read_text()).get('exitCode')==0,
                    'Candidate functional check failed: '+name)
            fixture=ROOT/'scripts/musl-negative-certificates.cs'
            fixture_hash=hashlib.sha256(fixture.read_bytes()).hexdigest()
            M.require(fixture_hash=='3c88ee9eab40b2e096b96c73316e8af8f3a58ea11b40fa72a84d6c5a4de647cc',
                'Reviewed default-SslStream certificate fixture bytes changed')
            negative=Path(temporary)/'negative';negative.mkdir()
            shutil.copyfile(fixture,negative/'Program.cs')
            shutil.copyfile(fixture,args.output/'negative-certificate-fixture.cs')
            (negative/'Negative.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net'+
                args.sdk_version.split('.')[0]+'.0</TargetFramework><UseSharedCompilation>false</UseSharedCompilation></PropertyGroup></Project>')
            (negative/'NuGet.Config').write_text('<configuration><packageSources><clear/></packageSources></configuration>')
            negative_environment=dict(environment,COMPlus_ReadyToRun='1')
            commands=[[str(sdk/'dotnet'),'build',str(negative/'Negative.csproj'),'-c','Release','-p:UseSharedCompilation=false','-p:NuGetAudit=false'],
                [str(sdk/'dotnet'),str(negative/'bin/Release'/('net'+args.sdk_version.split('.')[0]+'.0')/'Negative.dll')]]
            observations=[]
            for index,command in enumerate(commands):
                value=subprocess.run(command,cwd=negative,env=negative_environment,capture_output=True,text=True,timeout=180)
                text=value.stdout+value.stderr
                name='negative-build.log' if index==0 else 'negative-execution.log'
                (args.output/name).write_text(text)
                observations.append(dict(command=command,exitCode=value.returncode,log=name))
                M.require(value.returncode==0,'Actual default-SslStream negative certificate fixture failed')
            M.require(all(value in text for value in ['PASS trusted-control connects','PASS untrusted-self-signed fails closed',
                'PASS expired fails closed','PASS wrong-hostname fails closed','PASS invalid-CA managed chain fails closed',
                'PASS invalid-CA TLS fails closed','PASS all certificate cases; no remote validation callback']),
                'All trusted/untrusted/expired/wrong-host/invalid-CA assertions must actually execute')
            M.write(args.output/'negative-certificates.json',dict(status='passed',commands=observations,
                fixture=dict(path='negative-certificate-fixture.cs',sha256=fixture_hash),readyToRun=True,
                defaultSslStream=True,certificateValidationCallback=False,ephemeralUserTrustStore=True,
                nativeArchitecture=platform.machine(),uid=os.getuid(),network='none'))
            M.write(args.output/'offline-summary.json',dict(status='passed',checks=required+['negative-certificates'],network='none',
                nativeArchitecture=platform.machine(),uid=os.getuid(),hostSdkUsed=False,compilerInstalled=False))
        else:
            result=subprocess.run([str(sdk/'dotnet'),str(args.output/'application/probe.dll'),'tls'],env=environment,
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=90)
            M.write(args.output/'tls.json',dict(exitCode=result.returncode,output=result.stdout,defaultTrust=True,
                certificateValidationBypass=False))
            M.require(result.returncode==0 and 'SYSTEM TRUST TLS OK' in result.stdout,'Candidate system-trust TLS failed')
    print(json.dumps(dict(status='passed',mode=args.mode,archiveSha256=identity['sha256'])))


if __name__=='__main__':main()
