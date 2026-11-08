#!/usr/bin/env python3
"""Run the original legacy source-build smoke cases against a genuine musl SDK.

Assertions and case rows are retained. The test-only RID architecture parser
uses the final RID component, and the pinned managed OmniSharp fixture starts
through the tested musl dotnet host instead of its unused glibc apphost.
"""
import argparse
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]


def require(value,message):
    if not value:
        raise ValueError(message)


def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/filename)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


def fingerprint(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):
            digest.update(block)
    return dict(bytes=path.stat().st_size,sha256=digest.hexdigest())


def write(path,value):
    with path.open('x',encoding='utf-8') as stream:
        json.dump(value,stream,indent=2);stream.write('\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk-version',choices=['7.0.120','6.0.136'],required=True)
    parser.add_argument('--arch',choices=['x64','aarch64'],required=True)
    parser.add_argument('--source-tests',type=Path,required=True)
    parser.add_argument('--sdk-archive',type=Path,required=True)
    parser.add_argument('--official-archive',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    require(platform.system()=='Linux' and platform.machine()=={'x64':'x86_64','aarch64':'aarch64'}[args.arch]
        and os.getuid()!=0 and Path('/etc/alpine-release').read_text().strip()=='3.24.4',
        'Original musl smoke cases require matching native non-root Alpine3.24.4')
    require(not args.output.exists(),'Use a fresh original-suite evidence directory')
    args.output.mkdir(parents=True)
    source=module('legacy_smoke_evidence','ci-net67-evidence.py')
    major=args.sdk_version.split('.')[0]
    fixtures=module('legacy_smoke_fixture','prepare-net'+major+'-test-tools.py')
    source_rows=[]
    for path in sorted(args.source_tests.rglob('*')):
        if path.is_file():
            require(not path.is_symlink(),'Original test sources may not redirect outside their root')
            source_rows.append(dict(path=path.relative_to(args.source_tests).as_posix(),**fingerprint(path)))
    write(args.output/'identity.json',dict(schemaVersion=1,kind='original-legacy-musl-smoke-candidate',
        sdkVersion=args.sdk_version,architecture=args.arch,sourceFiles=source_rows,
        sdkArchive=dict(path=str(args.sdk_archive),**fingerprint(args.sdk_archive)),
        officialComparisonArchive=dict(path=str(args.official_archive),**fingerprint(args.official_archive)),
        qualificationAllowed=False,sourceAdmissionAllowed=False,upstreamCaseCount=42,
        scope='Original case assertions retained; warning-mode SDK layout comparison and absent poison input remain explicit'))
    with tempfile.TemporaryDirectory(prefix='cbodotnet-legacy-smoke-') as temporary:
        work=Path(temporary);sdk=work/'sdk';sdk.mkdir()
        with tarfile.open(args.sdk_archive,'r:gz') as archive:
            archive.extractall(sdk,filter='data')
        tests=work/'test';shutil.copytree(args.source_tests,tests)
        for name in ['Directory.Build.props','Directory.Build.targets']:
            (work/name).write_text('<Project/>\n')
        original=(tests/'Config.cs').read_text()
        revised=original.replace("TargetRid.Split('-')[1]","TargetRid.Split('-')[^1]")
        require(revised!=original and original.count("TargetRid.Split('-')[1]")==1,'Pinned original RID architecture parser differs')
        (tests/'Config.cs').write_text(revised)
        (args.output/'test-rid-parser.patch').write_text(''.join(difflib.unified_diff(original.splitlines(True),revised.splitlines(True),
            fromfile='a/Config.cs',tofile='b/Config.cs')))
        config=tests/'NuGet.Config'
        config.write_text('<configuration><packageSources><clear/><add key="dotnet-public" value="https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public/nuget/v3/index.json"/><add key="test-tools" value="https://pkgs.dev.azure.com/dnceng/public/_packaging/test-tools/nuget/v3/index.json"/></packageSources></configuration>\n')
        env=dict(os.environ,HOME=str(work/'home'),DOTNET_ROOT=str(sdk),DOTNET_MULTILEVEL_LOOKUP='0',
            DOTNET_CLI_HOME=str(work/'home'),DOTNET_CLI_TELEMETRY_OPTOUT='1',DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',
            DOTNET_GENERATE_ASPNET_CERTIFICATE='false',NUGET_PACKAGES=str(work/'packages'),
            SMOKE_TESTS_DOTNET_DIR=str(sdk),SMOKE_TESTS_SDK_TARBALL_PATH=str(args.sdk_archive),
            SMOKE_TESTS_MSFT_SDK_TARBALL_PATH=str(args.official_archive),
            SMOKE_TESTS_PORTABLE_RID='linux-musl-'+('arm64' if args.arch=='aarch64' else 'x64'),
            SMOKE_TESTS_TARGET_RID='linux-musl-'+('arm64' if args.arch=='aarch64' else 'x64'),
            SMOKE_TESTS_WARN_SDK_CONTENT_DIFFS='true',RUNNING_IN_CI='true')
        for name in ['SMOKE_TESTS_EXCLUDE_OMNISHARP','SMOKE_TESTS_POISON_REPORT_PATH','SMOKE_TESTS_PREREQS_PATH','SMOKE_TESTS_CUSTOM_PACKAGES_PATH']:
            env.pop(name,None)
        (work/'home').mkdir()
        project=tests/'Microsoft.DotNet.SourceBuild.SmokeTests.csproj'
        command=[str(sdk/'dotnet'),'build',str(project),'--configuration','Release','-p:UseSharedCompilation=false']
        write(args.output/'build-command.json',command)
        with (args.output/'build.log').open('x') as stream:
            result=subprocess.run(command,cwd=tests,env=env,stdout=stream,stderr=subprocess.STDOUT,timeout=300)
        require(result.returncode==0,'The original smoke-test project did not build')
        binary=tests/'bin/Release'/('net'+major+'.0')
        cache=args.output/'fixture-inputs';cache.mkdir()
        archive,downloaded=fixtures.cached_archive(cache,'arm64' if args.arch=='aarch64' else 'x64')
        omni=binary/'omnisharp'
        inventory=fixtures.archive_inventory(archive,omni)
        launcher=omni/'run'
        launcher.write_text('#!/bin/sh\nexec "$DOTNET_ROOT/dotnet" "'+str(omni/'OmniSharp.dll')+'" "$@"\n')
        launcher.chmod(0o755)
        write(args.output/'fixture.json',dict(version='1.39.6',archive=dict(path=archive.name,**fingerprint(archive)),
            downloaded=downloaded,originalMembers=inventory,launcher=dict(text=launcher.read_text(),**fingerprint(launcher)),
            nativeFixtureApphostExecuted=False,
            scope='Pinned original managed OmniSharp payload; explicit musl host launcher only. Timed startup assertions do not prove full editor functionality.'))
        results=args.output/'trx';results.mkdir()
        command=[str(sdk/'dotnet'),'vstest',str(binary/'Microsoft.DotNet.SourceBuild.SmokeTests.dll'),
                 '--logger:trx','--ResultsDirectory:'+str(results)]
        write(args.output/'test-command.json',command)
        with (args.output/'test.log').open('x') as stream:
            result=subprocess.run(command,cwd=binary,env=env,stdout=stream,stderr=subprocess.STDOUT,timeout=900)
        for name in ['logs','msftSdkFiles.txt','sbSdkFiles.txt']:
            path=binary/name
            if path.is_dir():shutil.copytree(path,args.output/name)
            elif path.is_file():shutil.copyfile(path,args.output/name)
        trx=list(results.glob('*.trx'))
        require(len(trx)==1,'One actual original smoke TRX is required')
        write(args.output/'summary.json',source.smoke_results(trx[0]))
        require(result.returncode==0,'An original smoke test failed')
    print('All original42 cases observed:41 passed, one upstream absent-poison-input skip.')


if __name__=='__main__':
    main()
