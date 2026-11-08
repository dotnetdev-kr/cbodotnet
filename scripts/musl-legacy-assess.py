#!/usr/bin/env python3
"""Bounded upstream legacy musl diagnostics; never builds, admits or publishes an SDK.

Downloaded SDKs are imported Microsoft diagnostic inputs. A successful probe is
neither a cbodotnet source build nor release qualification. Run native only on
the matching CPU, in an SDK-free stock Alpine image selected by immutable ID.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = {'7.0.120': ('7.0', '25b977658c06fd0217ec0bc0714398bb9d0a7bb0', '0fb6ac59fb1edbe4ed3ad62661df0eb7eacd7903'),
            '6.0.136': ('6.0', 'd638663530d923adbe0442604b7a6562127321e9', 'f1dd57165bfd91875761329ac3a8b17f6606ad18'),
            '5.0.214': ('5.0', 'd414ecb2d997a9b3f38aaaeddace30ca097e546d', '6a984143635bde23e728abaaccbde52f5ea8fa3e')}
ENGINE = ['podman', '--cgroup-manager=cgroupfs', '--events-backend=file']


def require(value, message):
    if not value:
        raise ValueError(message)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def digest(path):
    hashes = {name: hashlib.new(name) for name in ('sha256', 'sha512')}
    size = 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            size += len(block)
            for value in hashes.values():
                value.update(block)
    return dict(bytes=size, **{name: value.hexdigest() for name, value in hashes.items()})


def fetch(url, path, maximum, expected=None):
    require(url.startswith(('https://builds.dotnet.microsoft.com/', 'https://raw.githubusercontent.com/dotnet/')),
            'Only official pinned diagnostic inputs may be downloaded')
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        with urllib.request.urlopen(url, timeout=60) as response, path.open('xb') as stream:
            size = 0
            while block := response.read(1024*1024):
                size += len(block)
                require(size <= maximum, 'Download exceeds its bound')
                stream.write(block)
    result = digest(path)
    require(result['bytes'] <= maximum, 'Oversized retained input')
    if expected:
        require(result['sha512'].lower() == expected.lower(), 'Official release SHA-512 mismatch')
    return dict(url=url, path=str(path), **result)


def inspect_elf(path):
    raw = subprocess.check_output(['readelf', '--wide', '--file-header', '--program-headers', '--dynamic', '--version-info', str(path)], text=True)
    def field(name):
        match = re.search(r'^\s*'+name+r':\s*(.+)$', raw, re.M)
        return match[1].strip() if match else None
    interpreter = re.search(r'\[Requesting program interpreter:\s*([^\]]+)\]', raw)
    strings = subprocess.check_output(['strings', '-a', str(path)], text=True, errors='replace')
    probes = sorted(set(line for line in strings.splitlines()
                        if re.search(r'^(?:libssl|libcrypto|libicu|libcurl)\.(?:so|dylib)', line)))
    return dict(machine=field('Machine'), elfClass=field('Class'), elfType=field('Type'),
                interpreter=interpreter[1] if interpreter else None,
                needed=re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', raw),
                glibcVersionLabels=sorted(set(re.findall(r'\bGLIBC_[0-9.]+', raw))),
                dynamicLibraryStringCandidates=probes, **digest(path))


def payload(sdk, arch, output, static_only=False):
    series, _, runtime = VERSIONS[sdk]
    rid = 'linux-musl-'+{'x64': 'x64', 'aarch64': 'arm64'}[arch]
    directory = output/sdk/arch
    require(not (directory/'payload.json').exists(), 'Use a new diagnostic report directory')
    metadata_path = output/'inputs'/('releases-'+series+'.json')
    meta = fetch('https://builds.dotnet.microsoft.com/dotnet/release-metadata/'+series+'/releases.json', metadata_path, 4*1024**2)
    document = json.loads(metadata_path.read_text())
    matches = [item for release in document['releases'] for candidate in release.get('sdks', [release.get('sdk', {})])
               if candidate.get('version') == sdk for item in candidate.get('files', []) if item.get('rid') == rid]
    # Some metadata repeats the same SDK in several release records.
    matches = list({(item['url'], item['hash']): item for item in matches}.values())
    require(len(matches) == 1, 'One exact selected musl SDK input required')
    item = matches[0]
    archive = output/'inputs'/Path(item['url']).name
    upstream = fetch(item['url'], archive, 512*1024**2, item['hash'])
    extracted = directory/'sdk'
    extracted.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as source:
        members = source.getmembers()
        names = set()
        for member in members:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and '..' not in name.parts and member.name not in names,
                    'Unsafe or duplicate archive member')
            names.add(member.name)
            require(member.isfile() or member.isdir(), 'Diagnostic extraction permits ordinary files/directories only')
        if static_only:
            selected = []
            for member in members:
                if not member.isfile():
                    continue
                with source.extractfile(member) as stream:
                    header = stream.read(4)
                if header == b'\x7fELF' or PurePosixPath(member.name).name.lower() in {'license.txt', 'thirdpartynotices.txt'}:
                    selected.append(member)
            source.extractall(extracted, members=selected, filter='data')
        else:
            source.extractall(extracted, members=members, filter='data')
    elf = []
    for path in sorted(extracted.rglob('*')):
        if path.is_file():
            with path.open('rb') as stream:
                if stream.read(4) != b'\x7fELF':
                    continue
            elf.append(dict(path=path.relative_to(extracted).as_posix(), **inspect_elf(path)))
    licenses = [dict(path=path.relative_to(extracted).as_posix(), **digest(path))
                for path in sorted(extracted.rglob('*')) if path.is_file()
                and path.name.lower() in {'license.txt', 'thirdpartynotices.txt'}]
    report = dict(schemaVersion=1, kind='upstream-legacy-musl-static-diagnostic', observedAt=datetime.now(timezone.utc).isoformat(),
                  sdkVersion=sdk, architecture=arch, rid=rid, status='inspected', qualificationAllowed=False,
                  sourceAdmissionAllowed=False, productBuildExecuted=False, nativeExecutionPerformed=False,
                  attribution='Unmodified imported Microsoft SDK for feasibility diagnostics only',
                  metadata=meta, upstreamSdk=upstream, expectedRuntimeCommit=runtime,
                  elf=elf, licenses=licenses, fullSourceRetained=False,
                  extraction='ELF and notice subset only' if static_only else 'complete ordinary SDK payload',
                  scope='Every regular ELF inspected statically; dynamic candidates are strings, not execution or transitive closure proof')
    write(directory/'payload.json', report)
    print(json.dumps(dict(sdk=sdk, arch=arch, elfCount=len(elf), archiveSha256=upstream['sha256'])), flush=True)


PROBE = r"""import hashlib,json,os,pathlib,platform,shutil,subprocess,sys
root=pathlib.Path(os.environ.get('CBODOTNET_PROBE_SDK','/sdk')); out=pathlib.Path(os.environ.get('CBODOTNET_PROBE_EVIDENCE','/evidence')); work=pathlib.Path('/tmp/legacy-probe'); work.mkdir()
def command(name,args):
 try:
  p=subprocess.run(args,cwd=work,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180)
  result=dict(command=args,exitCode=p.returncode,output=p.stdout)
 except subprocess.TimeoutExpired as error:
  result=dict(command=args,timedOut=True,output=str(error.output))
 (out/(name+'.json')).write_text(json.dumps(result,indent=2)+'\n'); return result
assert os.getuid()!=0 and pathlib.Path('/etc/alpine-release').read_text().strip()=='3.24.4'
assert not any(pathlib.Path(p).exists() for p in ['/usr/share/dotnet','/usr/bin/dotnet'])
command('environment',['sh','-c','uname -m; id; cat /etc/alpine-release; apk info -vv; ls -l /usr/lib/libssl* /usr/lib/libcrypto* /usr/lib/libicu* /usr/lib/libcurl*; cat /proc/self/status'])
closures=[]
for row in json.loads((out/'elf-members.json').read_text()):
 p=subprocess.run(['ldd',str(root/row['path'])],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
 closures.append(dict(path=row['path'],exitCode=p.returncode,output=p.stdout))
(out/'elf-closure.json').write_text(json.dumps(closures,indent=2)+'\n')
command('sdk-info',[str(root/'dotnet'),'--info'])
major=sys.argv[1]; tfm='net'+major+'.0'
(work/'probe.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>'+tfm+'</TargetFramework><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup><ItemGroup><Compile Include="Program.cs" /><FrameworkReference Include="Microsoft.AspNetCore.App" /></ItemGroup></Project>')
(work/'Program.cs').write_text('''using System; using System.Globalization; using System.Security.Cryptography; using System.Security.Cryptography.X509Certificates; using System.Text; using System.Net.Http; using System.IO; using System.Linq;
using Microsoft.AspNetCore.Hosting; using Microsoft.AspNetCore.Builder; using Microsoft.AspNetCore.Http; using Microsoft.AspNetCore.Hosting.Server.Features;
class Program { static int Main(string[] args) {
 if(args[0]=="icu") {
  foreach(var name in new[]{"cs-CZ","de-DE","es-ES","fr-FR","it-IT","ja-JP","ko-KR","pl-PL","pt-BR","ru-RU","tr-TR","zh-CN","zh-TW"}) {
   var c=CultureInfo.GetCultureInfo(name); if(c.IsNeutralCulture || c.DateTimeFormat.MonthNames[0].Length==0 || c.CompareInfo.Compare("a","A",CompareOptions.IgnoreCase)!=0) return 2;
  }
  var ko=CultureInfo.GetCultureInfo("ko-KR"); var tr=CultureInfo.GetCultureInfo("tr-TR");
  if("i".ToUpper(tr)!="İ" || new RegionInfo("ko-KR").CurrencySymbol!="₩") return 2;
  Console.WriteLine("ICU 13 CULTURES OK "+ko.DateTimeFormat.GetDayName(DayOfWeek.Monday));
 } else if(args[0]=="crypto") {
  using(var sha=SHA256.Create()) { if(Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes("abc")))!="ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=") return 3; }
  using(var rsa=RSA.Create()) {rsa.KeySize=2048; var data=Encoding.UTF8.GetBytes("musl"); var sig=rsa.SignData(data,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1); if(!rsa.VerifyData(data,sig,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1))return 4;}
  using(var ec=ECDsa.Create(ECCurve.NamedCurves.nistP256)) {var data=Encoding.UTF8.GetBytes("musl");var sig=ec.SignData(data,HashAlgorithmName.SHA256);if(!ec.VerifyData(data,sig,HashAlgorithmName.SHA256))return 4;}
  using(var aes=new AesGcm(new byte[16])) {var plain=Encoding.UTF8.GetBytes("musl");var cipher=new byte[plain.Length];var decrypted=new byte[plain.Length];var tag=new byte[16];aes.Encrypt(new byte[12],plain,cipher,tag);aes.Decrypt(new byte[12],cipher,tag,decrypted);if(!plain.SequenceEqual(decrypted))return 4;}
  using(var rsa=RSA.Create(2048)) {var request=new CertificateRequest("CN=musl probe",rsa,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);using(var cert=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddMinutes(5))) {if(!cert.HasPrivateKey || cert.GetCertHash(HashAlgorithmName.SHA256).Length!=32)return 4;}}
  if(string.IsNullOrEmpty(new Oid("2.5.4.3").FriendlyName))return 4;
  Console.WriteLine("CRYPTO SHA256 RSA ECDSA AESGCM X509 OID OK");
 } else if(args[0]=="aspnet") {
  using(var host=new WebHostBuilder().UseKestrel().UseUrls("http://127.0.0.1:0").Configure(app=>app.Run(ctx=>ctx.Response.WriteAsync("legacy musl HTTP OK"))).Build()) {
   host.Start(); var address=host.ServerFeatures.Get<IServerAddressesFeature>().Addresses.Single();
   using(var client=new HttpClient()) if(client.GetStringAsync(address).GetAwaiter().GetResult()!="legacy musl HTTP OK")return 5;
  }
  Console.WriteLine("ASPNET HTTP OK");
 } else {
  using(var client=new HttpClient()) {var value=client.GetAsync("https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json").GetAwaiter().GetResult();value.EnsureSuccessStatusCode();Console.WriteLine("SYSTEM TRUST TLS OK");}
 }
 File.WriteAllText(Path.Combine(Environment.GetEnvironmentVariable("CBODOTNET_PROBE_EVIDENCE") ?? "/evidence",args[0]+"-maps.txt"),File.ReadAllText("/proc/self/maps")); return 0;
} }''')
(work/'empty-feed').mkdir()
build=command('offline-build',[str(root/'dotnet'),'build','probe.csproj','--configuration','Release','--source',str(work/'empty-feed'),'-p:UseAppHost=true','-p:NuGetAudit=false'])
if build.get('exitCode')==0:
 for name in ['icu','crypto','aspnet']:
  command(name,[str(root/'dotnet'),str(work/'bin/Release'/tfm/'probe.dll'),name])
 command('apphost',[str(work/'bin/Release'/tfm/'probe'),'icu'])
 shutil.copytree(work/'bin/Release'/tfm,out/'application')
"""


def native(sdk, arch, output, image, probe_name, native_crypto=None, trace_provider=None):
    require(os.getuid() == 0 and platform.system() == 'Linux', 'Rootful Linux diagnostic orchestration required')
    require(platform.machine() == {'x64': 'x86_64', 'aarch64': 'aarch64'}[arch], 'Native matching CPU required')
    require(re.fullmatch(r'[a-f0-9]{64}', image), 'Immutable local image ID required')
    directory = output/sdk/arch
    input_report = json.loads((directory/'payload.json').read_text())
    require(input_report.get('extraction', 'complete ordinary SDK payload') == 'complete ordinary SDK payload',
            'Native diagnostics require the complete payload')
    require(re.fullmatch(r'native(?:-[a-z0-9]+)*', probe_name), 'Bounded native evidence name required')
    native_dir = directory/probe_name
    native_dir.mkdir()
    native_dir.chmod(0o777)
    inspect = json.loads(subprocess.check_output(ENGINE+['image','inspect',image], text=True))
    require(len(inspect)==1 and inspect[0]['Architecture']=={'x64':'amd64','aarch64':'arm64'}[arch], 'Native image architecture differs')
    write(native_dir/'image.json', inspect)
    write(native_dir/'elf-members.json',[dict(path=row['path'],sha256=row['sha256']) for row in input_report['elf']])
    command = ENGINE+['run','--rm','--interactive','--network=none','--user','1000:1000','--cap-drop=all','--security-opt=no-new-privileges',
        '--env','HOME=/tmp','--env','DOTNET_ROOT=/sdk','--env','DOTNET_CLI_TELEMETRY_OPTOUT=1',
        '--env','DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1','--env','DOTNET_NOLOGO=1',
        '--volume',str(directory/'sdk')+':/sdk:ro','--volume',str(native_dir)+':/evidence']
    overlays=[]
    runtime={'7.0.120':'7.0.20','6.0.136':'6.0.36','5.0.214':'5.0.17'}[sdk]
    for file, basename in [(native_crypto,'libSystem.Security.Cryptography.Native.OpenSsl.so'),
                           (trace_provider,'libcoreclrtraceptprovider.so')]:
        if file is not None:
            require(file.is_absolute() and file.is_file() and not file.is_symlink(), 'Ordinary exact native component input required')
            destination='/sdk/shared/Microsoft.NETCore.App/'+runtime+'/'+basename
            command+=['--volume',str(file)+':'+destination+':ro']
            overlays.append(dict(path=destination,source=str(file),**inspect_elf(file)))
    write(native_dir/'candidate-overlays.json',dict(overlays=overlays,qualificationAllowed=False,
        interpretation='Explicit locally rebuilt source component overlays for diagnostics only; original imported SDK archive is unchanged'))
    command += [image,'python3','-',sdk.split('.')[0]]
    write(native_dir/'invocation.json',dict(command=command,scriptSha256=hashlib.sha256(PROBE.encode()).hexdigest(),
          qualificationAllowed=False,sourceAdmissionAllowed=False,diagnosticEngine='rootful-podman',nativeCpu=platform.machine(),
          sdkInputSha256=input_report['upstreamSdk']['sha256']))
    result=subprocess.run(command,input=PROBE,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=420)
    write(native_dir/'orchestration.json',dict(exitCode=result.returncode,output=result.stdout))
    require(result.returncode==0, 'Native probe orchestration failed; inspect retained output')
    require(all((native_dir/name).is_file() for name in ['environment.json','sdk-info.json','offline-build.json']),
            'Container returned without executing all required diagnostic actions')
    if (native_dir/'application/probe.dll').is_file():
        tls_command = command[:-3] + ['python3','-c',
            'import json,subprocess,pathlib; p=subprocess.run(["/sdk/dotnet","/evidence/application/probe.dll","tls"],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=90); pathlib.Path("/evidence/tls.json").write_text(json.dumps(dict(exitCode=p.returncode,output=p.stdout),indent=2))']
        tls_command[tls_command.index('--network=none')] = '--network=host'
        write(native_dir/'tls-invocation.json',dict(command=tls_command,scope='Online system-trust TLS diagnostic; default trust store and no validation bypass'))
        tls_result=subprocess.run(tls_command,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
        write(native_dir/'tls-orchestration.json',dict(exitCode=tls_result.returncode,output=tls_result.stdout))
        require(tls_result.returncode==0 and (native_dir/'tls.json').is_file(),'TLS diagnostic orchestration failed')
    print(json.dumps(dict(sdk=sdk,arch=arch,nativeReport=str(native_dir))),flush=True)


def source(sdk, output):
    _, commit, runtime = VERSIONS[sdk]
    repository = 'source-build' if sdk.startswith('5.') else 'installer'
    if repository == 'source-build':
        paths = ['global.json','eng/Version.Details.xml','repos/runtime.proj','repos/runtime.common.props',
                 'repos/aspnetcore.proj','Directory.Build.props','build.sh']
    else:
        prefix = 'src/SourceBuild/tarball/content/'
        bootstrap_directory = 'eng' if sdk.startswith('7.') else 'scripts'
        paths = ['global.json'] + [prefix+name for name in ['global.json','repos/runtime.proj','repos/aspnetcore.proj',
                  'Directory.Build.props','build.sh','prep.sh',bootstrap_directory+'/bootstrap/buildBootstrapPreviouslySB.csproj']]
        if sdk.startswith('6.'):
            paths.append(prefix+'repos/runtime.common.props')
    native_prefix = 'src/native/libs/' if sdk.startswith('7.') else 'src/libraries/Native/Unix/'
    runtime_paths = [native_prefix+'System.Security.Cryptography.Native/opensslshim.c',
                     native_prefix+'System.Globalization.Native/pal_icushim.c', 'eng/native/configureplatform.cmake']
    rows=[]
    for repo, pin, files in [(repository,commit,paths),('runtime',runtime,runtime_paths)]:
        for name in files:
            url=f'https://raw.githubusercontent.com/dotnet/{repo}/{pin}/{name}'
            path=output/sdk/'source-facts'/repo/name
            try:
                rows.append(dict(repository=repo,commit=pin,relativePath=name,**fetch(url,path,4*1024**2)))
            except urllib.error.HTTPError as error:
                rows.append(dict(repository=repo,commit=pin,relativePath=name,url=url,httpStatus=error.code))
    write(output/sdk/'source-facts.json',dict(schemaVersion=1,kind='pinned-legacy-musl-source-facts',sdkVersion=sdk,
          qualificationAllowed=False,sourceAdmissionAllowed=False,fullSourceRetained=False,files=rows))


def profiles(sdk, output):
    """Write only new, explicitly non-admissible version/CPU diagnostic profiles."""
    series, commit, runtime = VERSIONS[sdk]
    bootstrap_version={'7.0.120':'7.0.118','6.0.136':'6.0.135','5.0.214':'5.0.212'}[sdk]
    metadata=json.loads((output/'inputs'/('releases-'+series+'.json')).read_text())
    for arch, cpu in [('x64','x64'),('aarch64','arm64')]:
        glibc_path=ROOT/'profiles'/f'dotnet-{sdk}-linux-{arch}.json'
        inherited=json.loads(glibc_path.read_text())
        stock_path=ROOT/'profiles'/f'dotnet-10.0.403-linux-musl-{arch}.json'
        stock=json.loads(stock_path.read_text())
        rid='linux-musl-'+cpu
        bootstrap=[item for release in metadata['releases'] for candidate in release.get('sdks',[release.get('sdk',{})])
                   if candidate.get('version')==bootstrap_version for item in candidate.get('files',[]) if item.get('rid')==rid]
        bootstrap=list({item['url']:item for item in bootstrap}.values())
        require(len(bootstrap)==1,'Exact official matching bootstrap metadata required')
        report=json.loads((output/sdk/arch/'payload.json').read_text())
        component=inherited.get('generatedSource',inherited.get('legacySource',{})).get('componentCommits',{})
        profile=dict(schemaVersion=1,kind='legacy-musl-diagnostic-profile',selectedAt='2026-11-08',sdkVersion=sdk,
            status='stock-openssl-incompatible' if sdk.startswith('5.') else 'source-producer-investigation',
            qualificationAllowed=False,sourceAdmissionAllowed=False,releaseAvailabilityAllowed=False,
            lifecycle=dict(supportPhase='eol',additionalSecurityMaintenance=False,
                eolDate={'7.0':'2024-05-14','6.0':'2024-11-12','5.0':'2022-05-10'}[series]),
            source=inherited['source'],componentCommits=component,
            host=dict(os='linux',architecture=cpu,emulation=False),target=dict(rid=rid,libc='musl'),
            container=stock['container'],
            bootstrap=dict(version=bootstrap_version,rid=rid,url=bootstrap[0]['url'],sha512=bootstrap[0]['hash'],
                           purpose='Candidate regular SDK tooling/bootstrap input; not a previously source-built glibc archive'),
            stockAlpine=dict(branch='3.24',pointRelease='3.24.4',referenceProfile=stock_path.relative_to(ROOT).as_posix(),
                            referenceProfileSha256=digest(stock_path)['sha256'],apkIndexes=stock['apkIndexes'],
                            openssl='3.5.9-r0',icu='78.1-r0',fullIcuDataRequired=True,curl='8.23.0-r0',lttngUst='2.14.2-r0'),
            build=dict(system='regular-sdk-redist-then-installer-candidate',configuration='Release',
                sourceOnly=False,crossBuild=False,portableBuild=True,maxCpuCount=2,productBuildQualified=False,
                rebuiltComponentsPlanned=['dotnet/sdk CLI, SDK tasks, resolvers and SDK redist','dotnet/installer core SDK tasks and redist'],
                importedComponentsPlanned=['matching official musl host/runtime/ASP.NET archives','pinned compiler, MSBuild, NuGet and other tool packages'],
                sourceCompleteness='Full used source/license closure has not yet been retained and verified',
                sourceBuildWrappersReusable=False,glibcPatchesAssumedApplicable=False,
                unresolved=['Every host/runtime/tool ELF must close on stock Alpine, including legacy LTTng trace provider',
                            'Native successful regular tooling and installer build on each CPU',
                            'Bind all actual imported bytes and exact matching used sources/licenses']),
            diagnostics=dict(attribution=report['attribution'],upstreamSdk=report['upstreamSdk'],
                staticReport=dict(path=(output/sdk/arch/'payload.json').relative_to(ROOT).as_posix(),
                                  **digest(output/sdk/arch/'payload.json')),
                elfCount=len(report['elf']),elfMachines=sorted(set(row['machine'] for row in report['elf'])),
                nativeExecutionPerformed=arch=='aarch64',
                nativeEvidence='Stock dependency diagnostic only; no official workflow or release proof'),
            supportScope='EOL community feasibility diagnostic on Alpine 3.24.4; not Microsoft support, source admission or release availability')
        write(ROOT/'profiles'/f'dotnet-{sdk}-linux-musl-{arch}.json',profile)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['payload','source','native','profiles'])
    parser.add_argument('--sdk',choices=list(VERSIONS),required=True)
    parser.add_argument('--arch',choices=['x64','aarch64'],default='aarch64')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--image')
    parser.add_argument('--static-only',action='store_true',help='Extract only all ELF files and notices for static inspection')
    parser.add_argument('--probe-name',default='native',help='Fresh native evidence directory name, beginning with native')
    parser.add_argument('--native-crypto',type=Path,help='Explicit locally rebuilt crypto component overlay; diagnostic only')
    parser.add_argument('--trace-provider',type=Path,help='Explicit locally rebuilt trace-provider overlay; diagnostic only')
    args=parser.parse_args()
    args.output=args.output.absolute()
    require(not any(path.is_symlink() for path in [args.output,*args.output.parents]), 'Ordinary output tree required')
    if args.action=='payload': payload(args.sdk,args.arch,args.output,args.static_only)
    elif args.action=='source': source(args.sdk,args.output)
    elif args.action=='profiles': profiles(args.sdk,args.output)
    else: native(args.sdk,args.arch,args.output,args.image or '',args.probe_name,args.native_crypto,args.trace_provider)


if __name__=='__main__':
    main()
