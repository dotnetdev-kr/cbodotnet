"""Offline native CurlHandler proofs shared by package, OCI and archive tests."""
import json
from pathlib import PurePosixPath
import re
import shlex
import base64
import io
from pathlib import Path
import os
import stat
import tarfile
import tempfile

def require(value,message):
    if not value: raise ValueError(message)


def absolute_root(value):
    require(isinstance(value,str) and value.startswith('/') and value!='/' and str(PurePosixPath(value))==value
            and '..' not in PurePosixPath(value).parts and not any(char in value for char in '\0\r\n'),
            'An ordinary absolute native Curl proof root is required')
    return value


def script(version,sdk_root,expected_user,*,cli='cbodotnet',workdir='/work/native-curl',runtime_env=None,curl_root=None,user_id=10001,_native_curl=True):
    require(version in ({'3.0.103','3.1.426'} if _native_curl else {'5.0.214'}) and user_id in {10001,1654},'A reviewed native HTTP user/SDK is required')
    for path in (sdk_root,workdir,curl_root): absolute_root(path)
    require(re.fullmatch(r'[a-z_][a-z0-9_-]*',expected_user),'An existing ordinary native Curl test user is required')
    if _native_curl:
        import legacy_curl
        policy=legacy_curl.load_policy()
        files={row['files'][0]['path'].rsplit('/',1)[-1] for arch in policy['architectures'].values() for row in arch['packages']}
        require(len(files)==1,'Both reviewed architectures require the same Curl SONAME target')
        curl_file=files.pop()
    else:
        curl_file='unused'
    fixture=workdir+'/fixture'
    exports=''
    allowed={'LD_LIBRARY_PATH','OPENSSL_CONF','CLR_OPENSSL_VERSION_OVERRIDE','CLR_ICU_VERSION_OVERRIDE','SSL_CERT_FILE',
             'DOTNET_ICU_VERSION_OVERRIDE','DOTNET_SYSTEM_GLOBALIZATION_APPLOCALICU'}
    require(runtime_env and runtime_env.get('SSL_CERT_FILE'),'Native Curl proof requires the scoped stock certificate bundle')
    for name,value in runtime_env.items():
        require(name in allowed and isinstance(value,str) and not any(char in value for char in '\0\r\n'),'Unreviewed native Curl environment')
        exports+='export '+name+'='+shlex.quote(value)+'\n'
    framework=('netcoreapp' if version.startswith('3.') else 'net')+'.'.join(version.split('.')[:2])
    project='<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>'+framework+'</TargetFramework><OutputType>Exe</OutputType></PropertyGroup></Project>'
    return ('set -eu\ntest "$(id -u)" = '+str(user_id)+'\nmkdir -p '+shlex.quote(workdir)+'\ncd '+shlex.quote(workdir)+'\n'+exports
        +'export DOTNET_ROOT='+shlex.quote(sdk_root)+'\nexport DOTNET_ROOT_X64="$DOTNET_ROOT" DOTNET_ROOT_ARM64="$DOTNET_ROOT" DOTNET_MULTILEVEL_LOOKUP=0\n'
        +'cat > global.json <<\'GLOBAL\'\n'+json.dumps(dict(sdk=dict(version=version,rollForward='disable')))+'\nGLOBAL\n'
        +'cat > NuGet.Config <<\'NUGET\'\n<configuration><packageSources><clear /></packageSources></configuration>\nNUGET\n'
        +'cat > NativeCurl.csproj <<\'PROJECT\'\n'+project+'\nPROJECT\n'
        +'cat > Program.cs <<\'PROGRAM\'\n'+program(version,sdk_root,curl_root,curl_file,fixture,expected_user,user_id,_native_curl)+'\nPROGRAM\n'
        +shlex.quote(cli)+' restore --configfile NuGet.Config\n'+shlex.quote(cli)+' build --no-restore\n'
        +shlex.quote(cli)+' bin/Debug/'+framework+'/NativeCurl.dll fixture\n'
        +'export SSL_CERT_FILE='+shlex.quote(fixture+'/trusted-ca.pem')+'\n'
        +('DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER=0 ' if _native_curl else '')+shlex.quote(cli)+' bin/Debug/'+framework+'/NativeCurl.dll\n')


def standard_trust_script(version,sdk_root,expected_user,*,cli='cbodotnet',workdir='/work/native-ca',runtime_env=None,user_id=10001):
    """Reuse the CA fixture with SDK5's normal SocketsHttpHandler transport."""
    return script(version,sdk_root,expected_user,cli=cli,workdir=workdir,runtime_env=runtime_env,
                  curl_root='/unused-native-curl-provider',user_id=user_id,_native_curl=False)


def validate_standard_trust(output,user_id=10001):
    marker='CBODOTNET_NATIVE_CA_PROOF='
    rows=[line[len(marker):] for line in output.splitlines() if line.startswith(marker)]
    require(len(rows)==1,'Exactly one completed normal-handler default-trust HTTPS proof is required')
    proof=json.loads(rows[0])
    require(proof==dict(status='passed',handler='SocketsHttpHandler',defaultTrustHttps='passed',tls12='passed',network='none',userId=user_id),
            'Normal-handler default-trust HTTPS, TLS, user or network proof failed')
    return proof


def decoded_mapping(value):
    return re.sub(r'\\([0-7]{3})',lambda match:chr(int(match[1],8)),value)


def validate(output,version,sdk_root,curl_root,user_id,architecture):
    import legacy_curl
    absolute_root(sdk_root);absolute_root(curl_root)
    pins=legacy_curl.runtime_pins(dict(sdkVersion=version,architecture=dict(public=architecture)))
    require(pins is not None and user_id in {10001,1654},'A reviewed native Curl proof target is required')
    marker='CBODOTNET_NATIVE_CURL_PROOF='
    lines=[line[len(marker):] for line in output.splitlines() if line.startswith(marker)]
    require(len(lines)==1,'Exactly one completed native CurlHandler proof is required')
    proof=json.loads(lines[0])
    require(proof.get('status')=='passed' and proof.get('handler')=='CurlHandler'
            and all(proof.get(key)=='passed' for key in ('http','https','httpsDefaultTrust','tls12'))
            and type(proof.get('callbackCount')) is int and proof['callbackCount']>=1
            and proof.get('network')=='none' and proof.get('userId')==user_id,
            'Native CurlHandler HTTP, HTTPS callback, standard trust, TLS, user or network proof failed')
    for name,root in (('nativeHttp',sdk_root),('curl',curl_root)):
        require(proof.get(name)==dict(path=root+'/'+pins[name]['path'],sha256=pins[name]['sha256']),
                'Native CurlHandler source/provider object path or SHA differs')
    mappings=proof.get('nativeMappings')
    require(isinstance(mappings,list) and mappings and all(isinstance(line,str) and '\n' not in line for line in mappings)
            and all(any(proof[name]['path'] in decoded_mapping(line) for line in mappings) for name in ('nativeHttp','curl')),
            'Native CurlHandler did not map the exact source HTTP object and reviewed Curl provider')
    return {key:proof[key] for key in ('status','handler','http','https','httpsDefaultTrust','tls12','callbackCount',
                                      'network','userId','nativeHttp','curl','nativeMappings')}


def image_provider_proof(reference,plan,runner):
    """Authenticate the actual public image tree without installing test tools."""
    import legacy_curl
    policy=legacy_curl.load_policy();root=legacy_curl.PROVIDER_ROOT
    arch=plan['architecture']['public']
    output=runner(['docker','run','--rm','--network','none',reference,'sh','-ec',
        'tar -czf - -C '+shlex.quote(root)+' . | base64 -w0'])
    require(len(output)<=4*1024**2,'Image native HTTP provider transfer exceeds its bound')
    data=base64.b64decode(output,validate=True)
    owners={};seen=set();size=0
    with tempfile.TemporaryDirectory(prefix='cbodotnet-public-curl-tree-') as temporary:
        destination=Path(temporary)/'provider';destination.mkdir()
        with tarfile.open(fileobj=io.BytesIO(data),mode='r|gz') as archive:
            for member in archive:
                name=str(PurePosixPath(member.name))
                if name=='.':
                    require(member.isdir() and member.uid==member.gid==0 and member.mode==0o755,'Image native HTTP root ownership/mode differs')
                    continue
                require(not name.startswith('/') and '..' not in PurePosixPath(name).parts and name not in seen
                        and len(seen)<16 and (member.isfile() or member.isdir() or member.issym())
                        and member.uid==member.gid==0 and not member.mode & 0o7000,'Unsafe or unowned image provider member')
                seen.add(name);size+=member.size
                require(size<=2*1024**2,'Image native HTTP provider extraction exceeds its bound')
                target=destination/name
                require(not any(path.is_symlink() for path in [target,*target.parents]),'Image provider archive traverses a symlink')
                target.parent.mkdir(parents=True,exist_ok=True)
                if member.isdir():target.mkdir(exist_ok=True)
                elif member.issym():
                    require(name=='lib/libcurl.so.4' and '/' not in member.linkname and member.linkname.startswith('libcurl.so.4.'),
                            'Image native HTTP SONAME target differs')
                    target.symlink_to(member.linkname)
                else:
                    with archive.extractfile(member) as incoming:target.write_bytes(incoming.read())
                if not member.issym():target.chmod(member.mode & 0o777)
                owners[name]=(member.uid,member.gid)
        legacy_curl.validate_tree(destination,policy,arch)
        rows=legacy_curl.tree_inventory(destination)
        for row in rows:row.update(uid=owners[row['path']][0],gid=owners[row['path']][1])
        return dict(status='passed',required=True,providerRoot=root,architecture=arch,policySha256=legacy_curl.policy_hash(),
            signingFingerprint=legacy_curl.FINGERPRINT,treeSha256=legacy_curl.inventory_digest(rows),
            sourcePackages=policy['architectures'][arch]['packages'],sourceRpmPackages=policy['sources'],
            baseProviderId=policy['baseProvider']['providerId'])

def program(version, sdk_root, curl_root, curl_file, fixture, expected_user, user_id, native_curl=True):
    return r'''using System; using System.IO; using System.Linq; using System.Net; using System.Net.Http;
using System.Net.Sockets; using System.Net.Security; using System.Security.Authentication;
using System.Security.Cryptography; using System.Security.Cryptography.X509Certificates;
using System.Threading; using System.Threading.Tasks; using System.Reflection; using System.Text; using System.Text.Json;
public static class Program {
 const bool NativeCurl=NATIVE_PROBE;
 static string Decoded(string value) { return value.Replace("\\040"," ").Replace("\\011","\t").Replace("\\012","\n").Replace("\\134","\\"); }
 static string[] Maps() { return File.ReadAllLines("/proc/self/maps").Where(line=>line.Contains("libcurl") ||
  line.Contains("System.Net.Http.Native") || line.Contains("libssl") || line.Contains("libcrypto")).ToArray(); }
 static string Hash(string path) { using(var hash=SHA256.Create()) { return BitConverter.ToString(hash.ComputeHash(File.ReadAllBytes(path))).Replace("-","").ToLowerInvariant(); } }
 static X509Certificate2 Fixture() {
  Directory.CreateDirectory(FIXTURE);
  using(var caKey=RSA.Create()) { caKey.KeySize=2048;
   var caRequest=new CertificateRequest("CN=cbodotnet ephemeral curl fixture CA",caKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
   caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));
   caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign,true));
   using(var ca=caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddDays(1))) {
    string stock=Environment.GetEnvironmentVariable("SSL_CERT_FILE");
    if(string.IsNullOrEmpty(stock) || !File.Exists(stock)) throw new Exception("Approved stock certificate bundle is missing: "+stock);
    string trust=FIXTURE+"/trusted-ca.pem";
    File.WriteAllText(trust,File.ReadAllText(stock)+"\n-----BEGIN CERTIFICATE-----\n"+
     Convert.ToBase64String(ca.Export(X509ContentType.Cert),Base64FormattingOptions.InsertLineBreaks)+"\n-----END CERTIFICATE-----\n");
    Environment.SetEnvironmentVariable("SSL_CERT_FILE",trust);
    using(var serverKey=RSA.Create()) { serverKey.KeySize=2048;
     var request=new CertificateRequest("CN=localhost",serverKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
     request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
     request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature|X509KeyUsageFlags.KeyEncipherment,true));
     request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection{new Oid("1.3.6.1.5.5.7.3.1")},true));
     var names=new SubjectAlternativeNameBuilder();names.AddDnsName("localhost");names.AddIpAddress(IPAddress.Loopback);
     request.CertificateExtensions.Add(names.Build());
     byte[] serial=new byte[16];using(var random=RandomNumberGenerator.Create()) { random.GetBytes(serial); } serial[0]&=0x7f;serial[0]|=1;
     using(var certificate=request.Create(ca,DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(12),serial)) {
      return certificate.CopyWithPrivateKey(serverKey);
     }
    }
   }
  }
 }
 public static async Task Main(string[] args) {
  try {
   if(Environment.UserName!=USER || !typeof(object).Assembly.Location.StartsWith(ROOT+"/shared/")) throw new Exception("Wrong native SDK/user");
   int uid=int.Parse(File.ReadAllLines("/proc/self/status").Single(line=>line.StartsWith("Uid:")).Split(new[]{'\t',' '},StringSplitOptions.RemoveEmptyEntries)[1]);
   if(uid!=EXPECTED_UID || !Directory.GetDirectories("/sys/class/net").Select(Path.GetFileName).OrderBy(name=>name).SequenceEqual(new[]{"lo"})) throw new Exception("Wrong native user or network namespace");
   if(args.Length==1 && args[0]=="fixture") {
    using(var certificate=Fixture()) { File.WriteAllBytes(FIXTURE+"/server.pfx",certificate.Export(X509ContentType.Pkcs12,"cbodotnet-fixture")); }
    return;
   }
   if(NativeCurl) AppContext.SetSwitch("System.Net.Http.UseSocketsHttpHandler",false);
   using(var certificate=new X509Certificate2(FIXTURE+"/server.pfx","cbodotnet-fixture",X509KeyStorageFlags.EphemeralKeySet)) {
    using(var handler=new HttpClientHandler()) {
     handler.UseProxy=false; handler.SslProtocols=SslProtocols.Tls12; int callbacks=0;
     handler.ServerCertificateCustomValidationCallback=(message,remote,chain,errors)=> {
      Interlocked.Increment(ref callbacks); return remote!=null && remote.RawData.SequenceEqual(certificate.RawData); };
     using(var client=new HttpClient(handler)) { client.Timeout=TimeSpan.FromSeconds(10);
      await Exchange(client,certificate,false);
      var fields=typeof(HttpClientHandler).GetFields(BindingFlags.Instance|BindingFlags.NonPublic);
      string[] implementation=fields.Select(field=>field.GetValue(handler)).Where(value=>value!=null)
       .Select(value=>value.GetType().FullName).ToArray();
      if(!implementation.Any(value=>value.Contains(NativeCurl?"CurlHandler":"SocketsHttpHandler"))) throw new Exception("Expected HTTP handler was not selected: "+string.Join(",",implementation));
      string[] maps=Maps();
      if(NativeCurl && (!maps.Any(line=>Decoded(line).Contains(ROOT+"/shared/") && line.Contains("System.Net.Http.Native.so")) ||
         !maps.Any(line=>Decoded(line).Contains(CURL+"/lib/"+CANDIDATE_FILE)))) throw new Exception("Wrong native HTTP/candidate curl mapping");
      Console.WriteLine(JsonSerializer.Serialize(new {stage="http-passed-before-https",handler=NativeCurl?"CurlHandler":"SocketsHttpHandler",nativeMappings=maps}));
      await Exchange(client,certificate,true);
      if(callbacks==0) throw new Exception("HTTPS certificate callback was not executed");
      using(var standardHandler=new HttpClientHandler()) {
       standardHandler.UseProxy=false; standardHandler.SslProtocols=SslProtocols.Tls12;
       if(standardHandler.ServerCertificateCustomValidationCallback!=null) throw new Exception("Default trust fixture has a custom callback");
       using(var standardClient=new HttpClient(standardHandler)) { standardClient.Timeout=TimeSpan.FromSeconds(10);
        await Exchange(standardClient,certificate,true);
        if(!fields.Select(field=>field.GetValue(standardHandler)).Where(value=>value!=null)
         .Any(value=>value.GetType().FullName.Contains(NativeCurl?"CurlHandler":"SocketsHttpHandler"))) throw new Exception("Default HTTPS did not select expected handler");
       }
      }
      if(NativeCurl) {
       string http=Directory.GetFiles(ROOT+"/shared/Microsoft.NETCore.App","System.Net.Http.Native.so",SearchOption.AllDirectories).Single();
       string curl=CURL+"/lib/"+CANDIDATE_FILE;
       Console.WriteLine("NATIVE_HANDLER_MARKER="+JsonSerializer.Serialize(new {status="passed",handler="CurlHandler",
        http="passed",https="passed",httpsDefaultTrust="passed",tls12="passed",callbackCount=callbacks,network="none",userId=uid,
        nativeHttp=new{path=http,sha256=Hash(http)},curl=new{path=curl,sha256=Hash(curl)},nativeMappings=Maps()}));
      } else {
       Console.WriteLine("CBODOTNET_NATIVE_CA_PROOF="+JsonSerializer.Serialize(new {status="passed",handler="SocketsHttpHandler",
        defaultTrustHttps="passed",tls12="passed",network="none",userId=uid}));
      }
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
'''.replace('USER',json.dumps(expected_user)).replace('ROOT',json.dumps(sdk_root)).replace('CANDIDATE_FILE',json.dumps(curl_file)).replace('CURL',json.dumps(curl_root)).replace('VERSION',json.dumps(version)).replace('FIXTURE',json.dumps(fixture)).replace('EXPECTED_UID',str(user_id)).replace('NATIVE_PROBE','true' if native_curl else 'false').replace('NATIVE_HANDLER_MARKER','CBODOTNET_NATIVE_CURL_PROOF')
