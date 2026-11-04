#!/usr/bin/env python3
"""Probe an unqualified signed curl candidate without changing SDK/package bytes."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import stat
import subprocess
import tempfile

import legacy_compat as COMPAT
from downstream_release import encoded, receive_release, require
from distribution_contract import sha256_file
from sdk_runtime import series, target_framework

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('curl_probe_shared', ROOT / 'scripts/distribution-ci.py')
SHARED = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(SHARED)
SPEC_RPM = importlib.util.spec_from_file_location('curl_probe_rpm', ROOT / 'scripts/rpm-ci.py')
RPM = importlib.util.module_from_spec(SPEC_RPM); SPEC_RPM.loader.exec_module(RPM)
VERSIONS = ('3.0.103', '3.1.426')
USER = 'cbot-curl-probe'
BASES = {**RPM.BASES,
    'debian-13': {arch: SHARED.DEBIAN_BASE for arch in ('x64', 'aarch64')},
    'ubuntu-24.04': {arch: SHARED.UBUNTU_BASE for arch in ('x64', 'aarch64')}}
CANDIDATES = {
    'aarch64': dict(size=227113, sha256='e04933022e3f19878ece814a01cc041d655b8931ade8d4fee248c3e016702685',
        elfSize=475792, elfSha256='c3edadf0e7f3785a04e6ef12dc170a64f88f7eba37275c729213c32d0f978b46'),
    'x64': dict(size=231462, sha256='6d19a1deff3542bf74ae0741f9fb379ee7371e5ccf0bb7b71a0749d2cc9f9fd6',
        elfSize=517040, elfSha256='6a0d187667a03530e0a67766fa28d62ebbfb5632b923b2a8af07be8071890cbe'),
}
SOURCE = dict(name='curl-7.76.1-40.el9_8.9.src.rpm', size=2570551,
    sha256='1435256d4a17b130a2727353610f6f3739b6e182c29e8b0c472186c8f8e15395',
    url='https://dl.rockylinux.org/pub/rocky/9/BaseOS/source/tree/Packages/c/curl-7.76.1-40.el9_8.9.src.rpm')


def candidate(arch):
    require(arch in CANDIDATES, 'Native public architecture required')
    rpm_arch = 'x86_64' if arch == 'x64' else arch
    name = 'libcurl-minimal-7.76.1-40.el9_8.9.' + rpm_arch + '.rpm'
    return dict(name=name, url='https://dl.rockylinux.org/pub/rocky/9/BaseOS/' + rpm_arch + '/os/Packages/l/' + name,
        **{key: CANDIDATES[arch][key] for key in ('size', 'sha256')})


def command(arguments, *, check=True, env=None, cwd=None):
    result = subprocess.run(list(map(str, arguments)), env=env, cwd=cwd, text=True, capture_output=True)
    require(not check or result.returncode == 0, 'Candidate probe command failed: ' + str(arguments[0]) + '\n' + result.stdout[-8000:] + result.stderr[-8000:])
    return dict(exitCode=result.returncode, stdout=result.stdout, stderr=result.stderr)


def save(path, value):
    Path(path).write_bytes(encoded(value))


def program(version, sdk_root, curl_root):
    return r'''using System; using System.IO; using System.Linq; using System.Net; using System.Net.Http;
using System.Net.Sockets; using System.Net.Security; using System.Security.Authentication;
using System.Security.Cryptography; using System.Security.Cryptography.X509Certificates;
using System.Threading; using System.Threading.Tasks; using System.Reflection; using System.Text; using System.Text.Json;
public static class Program {
 static string[] Maps() { return File.ReadAllLines("/proc/self/maps").Where(line=>line.Contains("libcurl") ||
  line.Contains("System.Net.Http.Native") || line.Contains("libssl") || line.Contains("libcrypto")).ToArray(); }
 public static async Task Main() {
  try {
   if(Environment.UserName!=USER || !typeof(object).Assembly.Location.StartsWith(ROOT+"/shared/")) throw new Exception("Wrong native SDK/user");
   AppContext.SetSwitch("System.Net.Http.UseSocketsHttpHandler",false);
   using(var key=RSA.Create()) { key.KeySize=2048;
    var request=new CertificateRequest("CN=localhost",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
    using(var certificate=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddDays(1)))
    using(var handler=new HttpClientHandler()) {
     handler.UseProxy=false; handler.SslProtocols=SslProtocols.Tls12; int callbacks=0;
     handler.ServerCertificateCustomValidationCallback=(message,remote,chain,errors)=> {
      Interlocked.Increment(ref callbacks); return remote!=null && remote.RawData.SequenceEqual(certificate.RawData); };
     using(var client=new HttpClient(handler)) { client.Timeout=TimeSpan.FromSeconds(10);
      await Exchange(client,certificate,false);
      var fields=typeof(HttpClientHandler).GetFields(BindingFlags.Instance|BindingFlags.NonPublic);
      string[] implementation=fields.Select(field=>field.GetValue(handler)).Where(value=>value!=null)
       .Select(value=>value.GetType().FullName).ToArray();
      if(!implementation.Any(value=>value.Contains("CurlHandler"))) throw new Exception("CurlHandler was not selected: "+string.Join(",",implementation));
      string[] maps=Maps();
      if(!maps.Any(line=>line.Contains(ROOT+"/shared/") && line.Contains("System.Net.Http.Native.so")) ||
         !maps.Any(line=>line.Contains(CURL+"/lib/libcurl.so.4.7.0"))) throw new Exception("Wrong native HTTP/candidate curl mapping");
      Console.WriteLine(JsonSerializer.Serialize(new {stage="forced-curl-http-passed-before-https",handler="CurlHandler",nativeMappings=maps}));
      await Exchange(client,certificate,true);
      if(callbacks==0) throw new Exception("HTTPS certificate callback was not executed");
      Console.WriteLine(JsonSerializer.Serialize(new {status="passed",sdkVersion=VERSION,handler="CurlHandler",
       http="passed",https="passed",tls12="passed",certificateCallbackCount=callbacks,nativeMappings=maps}));
     }
    }
   }
  } catch(Exception error) { Console.WriteLine(JsonSerializer.Serialize(new {status="failed-candidate",sdkVersion=VERSION,
    error=error.ToString(),nativeMappings=Maps()})); Environment.ExitCode=1; }
 }
 static async Task Exchange(HttpClient client,X509Certificate2 certificate,bool encrypted) {
  var listener=new TcpListener(IPAddress.Loopback,0); listener.Start();
  try {
   int port=((IPEndPoint)listener.LocalEndpoint).Port;
   var server=Task.Run(async()=> { using(var peer=await listener.AcceptTcpClientAsync()) {
    Stream stream=peer.GetStream();
    if(encrypted) { var tls=new SslStream(stream,false); await tls.AuthenticateAsServerAsync(certificate,false,SslProtocols.Tls12,false);
     if(tls.SslProtocol!=SslProtocols.Tls12) throw new Exception("Server TLS version"); stream=tls; }
    using(stream) { var header=new StringBuilder(); byte[] data=new byte[1];
     while(!header.ToString().EndsWith("\r\n\r\n")) { if(header.Length>8192 || await stream.ReadAsync(data,0,1)!=1) throw new Exception("HTTP request"); header.Append((char)data[0]); }
     string body="forced-curl-http-passed";
     byte[] response=Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "+Encoding.ASCII.GetByteCount(body)+"\r\n\r\n"+body);
     await stream.WriteAsync(response,0,response.Length); await stream.FlushAsync();
    }
   }});
   string body=await client.GetStringAsync((encrypted?"https":"http")+"://127.0.0.1:"+port+"/");
   if(body!="forced-curl-http-passed") throw new Exception("HTTP response");
   if(await Task.WhenAny(server,Task.Delay(15000))!=server) throw new Exception("Loopback server timeout"); await server;
  } finally { listener.Stop(); }
 }
}
'''.replace('USER', json.dumps(USER)).replace('ROOT', json.dumps(sdk_root)).replace('CURL', json.dumps(curl_root)).replace('VERSION', json.dumps(version))


def guard(args, offline=False):
    require(os.geteuid() == 0 and (Path('/.dockerenv').is_file() or Path('/run/.containerenv').is_file()), 'A disposable root container is required')
    require(platform.machine() in ({'x86_64'} if args.arch == 'x64' else {'aarch64', 'arm64'}), 'Exact native CPU required')
    release = dict(line.split('=',1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    from distribution_contract import load_contract
    expected = load_contract()['operatingSystems'][args.variant]
    require(release['ID'].strip('"') == expected['id'] and release['VERSION_ID'].strip('"') == expected['versionId'], 'Exact candidate probe OS required')
    if offline:
        require({path.name for path in Path('/sys/class/net').iterdir()} == {'lo'}, 'Candidate runtime requires --network none')


def prepare(args):
    guard(args)
    workspace=args.workspace; state=workspace/'state'; state.mkdir()
    command(['useradd','--create-home','--uid','10001',USER])
    COMPAT.cpu_preflight(args.arch)
    # These are separately authenticated, unmodified source-provider libraries;
    # neither candidate becomes a production policy or package in this probe.
    _,ssl_root,provider=COMPAT.stage_provider(args.arch,state/'ssl-provider')
    curl_root=state/'curl-candidate'; (curl_root/'lib').mkdir(parents=True)
    policy=dict(key=COMPAT.load_policy()['key'],sources=[SOURCE],architectures={args.arch:dict(packages=[candidate(args.arch)])})
    with tempfile.TemporaryDirectory(prefix='curl-candidate-key-') as temporary:
        paths=COMPAT.verify_sources(policy,args.arch,state/'curl-sources',Path(temporary))
    payload=subprocess.check_output(['rpm2cpio',str(paths[candidate(args.arch)['name']])])
    entries={name:(mode,data) for name,mode,data in COMPAT.cpio_members(payload)}
    mode,data=entries['usr/lib64/libcurl.so.4.7.0']
    expected=CANDIDATES[args.arch]
    require(stat.S_ISREG(mode) and len(data)==expected['elfSize'], 'Candidate curl ELF size/type differs')
    path=curl_root/'lib/libcurl.so.4.7.0';path.write_bytes(data);path.chmod(0o755)
    require(sha256_file(path)==expected['elfSha256'], 'Candidate curl ELF digest differs')
    mode,link=entries['usr/lib64/libcurl.so.4']
    require(stat.S_ISLNK(mode) and link==b'libcurl.so.4.7.0','Candidate SONAME link differs')
    (curl_root/'lib/libcurl.so.4').symlink_to('libcurl.so.4.7.0')
    for version in VERSIONS:
        destination=state/'sdks'/version;destination.parent.mkdir(exist_ok=True)
        SHARED.extractor()(workspace/'inputs'/version/('cbodotnet-sdk-'+version+'-linux-'+args.arch+'.tar.gz'),destination)
    save(state/'baseline.json',dict(candidate=candidate(args.arch),source=SOURCE,sslProvider=provider,
        curlRoot=str(curl_root),sslRoot=str(ssl_root),sdkInventories={version:SHARED.inventory(state/'sdks'/version) for version in VERSIONS}))


def runtime(args):
    guard(args,offline=True)
    workspace=args.workspace;state=workspace/'state';baseline=json.loads((state/'baseline.json').read_bytes())
    observations=[]
    for version in VERSIONS:
        sdk=state/'sdks'/version;curl_root=Path(baseline['curlRoot']);ssl_root=Path(baseline['sslRoot'])
        work=Path('/home')/USER/version;work.mkdir()
        (work/'global.json').write_bytes(encoded(dict(sdk=dict(version=version,rollForward='disable'))))
        (work/'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>\n')
        framework=target_framework(version)
        (work/'Probe.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>'+framework+'</TargetFramework><OutputType>Exe</OutputType></PropertyGroup></Project>\n')
        (work/'Program.cs').write_text(program(version,str(sdk),str(curl_root)))
        command(['chown','-R',USER+':'+USER,work])
        environment=COMPAT.environment(dict(sdkVersion=version,variant=args.variant),root=str(ssl_root))
        environment['LD_LIBRARY_PATH']=str(curl_root/'lib')+':'+environment['LD_LIBRARY_PATH']
        environment.update(DOTNET_ROOT=str(sdk),DOTNET_ROOT_X64=str(sdk),DOTNET_ROOT_ARM64=str(sdk),DOTNET_MULTILEVEL_LOOKUP='0')
        prefix=['runuser','-u',USER,'--','env','-i','PATH=/usr/local/bin:/usr/bin:/bin','HOME=/home/'+USER,
            'DOTNET_CLI_HOME=/home/'+USER,'DOTNET_NOLOGO=1','DOTNET_CLI_TELEMETRY_OPTOUT=1','DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1',
            *[name+'='+value for name,value in environment.items()]]
        dotnet=sdk/'dotnet';native=list(sdk.glob('shared/Microsoft.NETCore.App/*/System.Net.Http.Native.so'))
        require(len(native)==1,'One exact original native HTTP component required')
        loader=command(['env',*[name+'='+value for name,value in environment.items()],'ldd',native[0]],check=False)
        compilation=[];execution=None
        for arguments in ([dotnet,'restore','--configfile','NuGet.Config'],[dotnet,'build','--no-restore']):
            result=command([*prefix,*arguments],check=False,cwd=work);compilation.append(result)
            if result['exitCode']:break
        if all(row['exitCode']==0 for row in compilation) and len(compilation)==2:
            execution=command([*prefix,'DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER=0',dotnet,work/'bin/Debug'/framework/'Probe.dll'],check=False,cwd=work)
        require(SHARED.inventory(sdk)==baseline['sdkInventories'][version],'Candidate probe changed original qualified SDK bytes/modes/links')
        observed=None
        if execution:
            try:observed=json.loads(execution['stdout'].strip().splitlines()[-1])
            except (json.JSONDecodeError,IndexError):pass
        passed=bool(execution and execution['exitCode']==0 and observed and observed.get('status')=='passed')
        observations.append(dict(sdkVersion=version,source=json.loads((workspace/'inputs'/version/'source.json').read_bytes()),
            nativeHttpSha256=sha256_file(native[0]),loader=loader,applicationCompilation=compilation,execution=execution,
            observation=observed,runtimeCompatibilityPassed=passed,qualifiedSdkPayloadUnchanged=True))
    save(workspace/'curl-runtime-observation.json',dict(schemaVersion=1,scope='unqualified-curl-candidate-forced-native-handler-runtime-diagnostic',
        status='observed',architecture=args.arch,variant=args.variant,networkForExecution='none',sdkSourcesBuilt=0,packageBuilds=0,
        applicationProjectsBuilt=len(VERSIONS),publicationAllowed=False,productionProviderAdmitted=False,
        candidate=baseline['candidate'],candidateElfSha256=sha256_file(Path(baseline['curlRoot'])/'lib/libcurl.so.4.7.0'),
        candidateSigningFingerprint=COMPAT.FINGERPRINT,observations=observations,
        runtimeCompatibilityPassed=all(row['runtimeCompatibilityPassed'] for row in observations)))


def native(args):
    require(os.getuid()!=0 and platform.machine() in ({'x86_64'} if args.arch=='x64' else {'aarch64','arm64'}),'Matching native ordinary producer required')
    workspace=args.workspace.resolve();require(not workspace.exists(),'Fresh candidate runtime workspace required');workspace.mkdir(parents=True)
    (workspace/'inputs').mkdir()
    for version in VERSIONS:
        plan=receive_release('sdk-'+version,workspace/'inputs'/version,'oci','debian-13',args.arch,1)
        save(workspace/'inputs'/version/'source.json',{key:plan[key] for key in ('sdkVersion','sourceManifestSha256','producer','sdk')})
    mounts=['-v',f'{ROOT}:/repo:ro','-v',f'{workspace}:/delivery']
    if args.variant in {'debian-13','ubuntu-24.04'}:
        bootstrap='set -eu\nexport DEBIAN_FRONTEND=noninteractive\napt-get update -qq\napt-get install -y --no-install-recommends python3 ca-certificates curl util-linux passwd rpm rpm2cpio gnupg binutils libnghttp2-14 libgssapi-krb5-2 zlib1g\n'
    else:
        bootstrap='set -eu\nexport PATH=/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin\ndnf -y install python3 rpm rpm-build cpio gnupg2 binutils shadow-utils util-linux libnghttp2 krb5-libs zlib\n'
        if args.variant=='rocky-9.8':bootstrap+='dnf -y install python3.12\nmkdir -p /usr/local/bin\nln -s /usr/bin/python3.12 /usr/local/bin/python3\n'
    common=['--workspace','/delivery','--arch',args.arch,'--variant',args.variant]
    cid=image=None
    try:
        cid=command([args.engine,'create',*mounts,BASES[args.variant][args.arch],'sh','-ec',bootstrap+
            'exec '+shlex.join(['python3','/repo/scripts/core3-curl-runtime-probe.py','prepare',*common])])['stdout'].strip()
        command([args.engine,'start','--attach',cid]); require(json.loads(command([args.engine,'inspect',cid])['stdout'])[0]['State']['ExitCode']==0,'Candidate preparation failed')
        image=command([args.engine,'commit',cid])['stdout'].strip()
        command([args.engine,'run','--rm','--network','none',*mounts,image,'sh','-ec','ulimit -c 0; exec '+shlex.join(
            ['python3','/repo/scripts/core3-curl-runtime-probe.py','runtime',*common])])
    finally:
        if cid:command([args.engine,'rm','--force',cid],check=False)
        if image:command([args.engine,'image','rm',image],check=False)
    print(json.dumps(dict(report=str(workspace/'curl-runtime-observation.json'),runtimeCompatibilityPassed=json.loads((workspace/'curl-runtime-observation.json').read_bytes())['runtimeCompatibilityPassed'])))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=('native','prepare','runtime'))
    parser.add_argument('--workspace',type=Path,required=True);parser.add_argument('--arch',choices=('x64','aarch64'),required=True)
    parser.add_argument('--variant',choices=tuple(BASES),default='debian-13');parser.add_argument('--engine',choices=('docker','podman'),default='docker')
    args=parser.parse_args();{'native':native,'prepare':prepare,'runtime':runtime}[args.phase](args)

if __name__=='__main__':main()
