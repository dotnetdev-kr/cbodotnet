"""Version-aware runtime probes for the explicitly selected glibc SDK families."""
import json
import hashlib
import os
from pathlib import Path
import re
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SERIES = {'3.0', '3.1', '5.0', '6.0', '7.0', '8.0', '9.0', '10.0'}


def require(value, message):
    if not value:
        raise ValueError(message)


def series(version):
    require(isinstance(version, str) and re.fullmatch(r'[1-9][0-9]*\.[0-9]+\.[0-9]+', version), 'An exact stable SDK version is required')
    value = '.'.join(version.split('.')[:2])
    require(value in SERIES, 'Unreviewed SDK runtime family')
    return value


def target_framework(version):
    value = series(version)
    return ('netcoreapp' if value.startswith('3.') else 'net') + value


framework = target_framework


def forced_curl_script(version,sdk_root,expected_user,*,cli='cbodotnet',workdir='/work/native-curl',runtime_env=None,curl_root=None,user_id=10001):
    from native_curl_runtime import script
    return script(version,sdk_root,expected_user,cli=cli,workdir=workdir,runtime_env=runtime_env,curl_root=curl_root,user_id=user_id)


def validate_forced_curl_output(output,version,sdk_root,curl_root,user_id,architecture):
    from native_curl_runtime import validate
    return validate(output,version,sdk_root,curl_root,user_id,architecture)


def require_installed_provider_roots(plan):
    """Public installation verification must never repair a missing provider."""
    if series(plan['sdkVersion']) not in {'3.0', '3.1', '5.0'}:
        return
    import legacy_compat
    import legacy_curl
    roots = [legacy_compat.PROVIDER_ROOT]
    if legacy_curl.required(plan):
        roots.append(legacy_curl.PROVIDER_ROOT)
    require(all(Path(root).is_dir() and not Path(root).is_symlink() for root in roots),
            'Published packages did not install all ordinary managed provider roots; local repair is forbidden')


def audit_core3_http_libraries(version, sdk_root, runtime_env=None, runner=None):
    """Core3's optional native HTTP handler must resolve its stock libcurl ABI."""
    if series(version) not in {'3.0', '3.1'}:
        return []
    root = Path(sdk_root)
    matches = sorted({path for prefix in ('', 'lib')
        for path in root.glob('shared/Microsoft.NETCore.App/*/' + prefix + 'System.Net.Http.Native.so')})
    require(matches and all(path.is_file() for path in matches), 'Missing Core3 System.Net.Http.Native.so component')
    rows = []
    for path in matches:
        environment = dict(os.environ, **(runtime_env or {}))
        if runner is None:
            result = subprocess.run(['ldd', str(path)], env=environment, check=True, text=True, capture_output=True)
            value = result.stdout + result.stderr
        else:
            value = runner(['ldd', path], env=environment)
        provider = re.search(r'^\s*libcurl\.so\.4\s+=>\s+(/\S+)\s+\(', value, re.MULTILINE)
        require('not found' not in value and provider is not None,
                'Core3 native HTTP requires resolved stock libcurl.so.4: ' + str(path) + '\n' + value)
        rows.append(dict(path=path.relative_to(root).as_posix(), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            ldd=value, libcurlProviderPath=provider[1]))
    return rows


def runtime_policy(version, architecture):
    value = series(version)
    require(architecture in {'x64', 'aarch64'}, 'A public native SDK architecture is required')
    profile_path = ROOT / f'profiles/dotnet-{version}-linux-{architecture}.json'
    profile = json.loads(profile_path.read_bytes())
    require(profile['sdkVersion'] == version and profile['target']['libc'] == 'glibc', 'Runtime profile differs from selected SDK')
    rid = 'linux-' + ('arm64' if architecture == 'aarch64' else 'x64')
    require(profile['target']['rid'] == rid, 'Runtime profile target architecture differs')
    maximum = profile['target']['intendedMaximumGlibcRequirement']
    expected = None
    if value != '10.0':
        preparation = json.loads((ROOT / 'releases/additional-sdk-preparation.json').read_bytes())
        matches = [row for row in preparation['sdks'] if row['sdkVersion'] == version]
        require(len(matches) == 1, 'Exact recorded SDK ABI observation is required')
        expected = matches[0]['architectures'][architecture]['recordedElfObservation']['maximumRequiredVersions']
        maximum = expected['GLIBC']
    return dict(sdkVersion=version, series=value, framework=target_framework(version), architecture=architecture,
                targetRid=rid, sdkRoot='/opt/cbodotnet/' + value, maxGlibc=maximum,
                recordedMaximumRequiredVersions=expected, legacy=value in {'3.0', '3.1', '5.0'},
                profile=str(profile_path.relative_to(ROOT)), sourceCommit=profile['source']['commit'])


def policy(plan):
    architecture = plan['architecture']
    return runtime_policy(plan['sdkVersion'], architecture['public'] if isinstance(architecture, dict) else architecture)


def validate_host_rid(info, version, architecture, variant):
    match = re.search(r'^\s*RID:\s+(\S+)\s*$', info, re.MULTILINE)
    suffix = 'arm64' if architecture == 'aarch64' else 'x64'
    require(architecture in {'x64', 'aarch64'}, 'Unreviewed host RID architecture')
    allowed = {'linux-' + suffix}
    if int(series(version).split('.')[0]) <= 7:
        prefixes = {'ubuntu-22.04': ['ubuntu.22.04'], 'ubuntu-24.04': ['ubuntu.24.04'],
                    'debian-13': ['debian.13'], 'fedora-45': ['fedora.45'],
                    'rocky-9.8': ['rocky.9', 'rocky.9.8', 'rhel.9', 'rhel.9.8'], 'arch-rolling': ['arch']}
        require(variant in prefixes, 'Unreviewed host RID distribution')
        allowed.update(prefix + '-' + suffix for prefix in prefixes[variant])
    require(match is not None and match[1] in allowed, 'SDK host RID differs from its native architecture/distribution: '
            + (match[1] if match is not None else '<missing>') + '; admitted: ' + ', '.join(sorted(allowed)))
    return match[1]


def smoke_program(sdk_root, expected_user, framework):
    """Classic hosting/C# syntax and crypto APIs supported from Core3 through NET10."""
    return '''using System; using System.IO; using System.Linq; using System.Diagnostics;
using System.Globalization; using System.Net.Http; using System.Security.Cryptography;
using System.Threading.Tasks; using System.Net; using System.Net.Sockets; using System.Net.Security;
using System.Security.Authentication; using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore; using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting; using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting.Server.Features;
public static class Program {
 public static async Task Main(string[] args) {
  string root=ROOT, user=USER;
  if(Environment.UserName!=user || !typeof(object).Assembly.Location.StartsWith(root+"/shared/")) throw new Exception("Wrong runtime root/user");
  string expected=args[0]=="dll" ? root+"/dotnet" : Path.GetFullPath("bin/Debug/FRAMEWORK/Smoke");
  if(Process.GetCurrentProcess().MainModule.FileName!=expected) throw new Exception("Wrong DLL/apphost process");
  byte[] data=new byte[32]; using(var random=RandomNumberGenerator.Create()) { random.GetBytes(data); }
  if(!Array.Exists(data, value=>value!=0)) throw new Exception("Random bytes");
  using(var rsa=RSA.Create()) { rsa.KeySize=2048;
   byte[] signature=rsa.SignData(data,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
   if(!rsa.VerifyData(data,signature,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1)) throw new Exception("RSA");
   signature[0]^=1;
   if(rsa.VerifyData(data,signature,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1)) throw new Exception("Altered RSA signature");
  }
  if(!1234.5m.ToString("N1",CultureInfo.GetCultureInfo("fr-FR")).Contains("234,5")) throw new Exception("ICU");
  var tls=CheckTls();
  if(await Task.WhenAny(tls,Task.Delay(15000))!=tls) throw new Exception("TLS timeout");
  await tls; Console.WriteLine("published-tls12-passed");
  using(var app=WebHost.CreateDefaultBuilder(Array.Empty<string>()).UseUrls("http://127.0.0.1:0")
   .Configure(builder=>builder.Run(context=>context.Response.WriteAsync("published-http-passed"))).Build()) {
   await app.StartAsync();
   try { string url=app.ServerFeatures.Get<IServerAddressesFeature>().Addresses.Single();
    using(var client=new HttpClient()) { if(await client.GetStringAsync(url)!="published-http-passed") throw new Exception("HTTP"); }
   } finally { await app.StopAsync(); }
  }
  Console.WriteLine("published-offline-"+args[0]+"-http-crypto-icu-passed");
 }
 private static async Task CheckTls() {
  using(var key=RSA.Create()) { key.KeySize=2048;
   var request=new CertificateRequest("CN=localhost",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
   using(var certificate=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddDays(1))) {
    var listener=new TcpListener(IPAddress.Loopback,0); listener.Start();
    try {
     int port=((IPEndPoint)listener.LocalEndpoint).Port;
     var server=Task.Run(async()=> { using(var peer=await listener.AcceptTcpClientAsync())
      using(var stream=new SslStream(peer.GetStream(),false)) {
       await stream.AuthenticateAsServerAsync(certificate,false,SslProtocols.Tls12,false);
       if(stream.SslProtocol!=SslProtocols.Tls12) throw new Exception("Server TLS version");
       byte[] data=new byte[1]; if(await stream.ReadAsync(data,0,1)!=1 || data[0]!=41) throw new Exception("TLS request");
       data[0]=42; await stream.WriteAsync(data,0,1);
      }
     });
     using(var peer=new TcpClient()) { await peer.ConnectAsync(IPAddress.Loopback,port);
      using(var stream=new SslStream(peer.GetStream(),false,(sender,remote,chain,errors)=>remote!=null && remote.GetRawCertData().SequenceEqual(certificate.RawData))) {
       await stream.AuthenticateAsClientAsync("localhost",null,SslProtocols.Tls12,false);
       if(stream.SslProtocol!=SslProtocols.Tls12) throw new Exception("Client TLS version");
       byte[] data=new byte[]{41}; await stream.WriteAsync(data,0,1);
       if(await stream.ReadAsync(data,0,1)!=1 || data[0]!=42) throw new Exception("TLS response");
      }
     }
     await server;
    } finally { listener.Stop(); }
   }
  }
 }
}
'''.replace('ROOT', json.dumps(sdk_root)).replace('USER', json.dumps(expected_user)).replace('FRAMEWORK', framework)


def smoke_script(version, sdk_root, expected_user, cli='dotnet', workdir='/work/smoke', runtime_env=None):
    framework = target_framework(version)
    require(isinstance(sdk_root, str) and sdk_root.startswith('/') and '\n' not in sdk_root,
            'An absolute SDK runtime root is required')
    project = ('<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>' + framework
               + '</TargetFramework><OutputType>Exe</OutputType><UseAppHost>true</UseAppHost></PropertyGroup></Project>')
    exports = ''
    for key, value in (runtime_env or {}).items():
        require(key in {'LD_LIBRARY_PATH', 'OPENSSL_CONF', 'CLR_OPENSSL_VERSION_OVERRIDE', 'CLR_ICU_VERSION_OVERRIDE',
                        'DOTNET_ICU_VERSION_OVERRIDE', 'DOTNET_SYSTEM_GLOBALIZATION_APPLOCALICU', 'SSL_CERT_FILE'}
                and isinstance(value, str) and '\0' not in value and '\n' not in value, 'Unreviewed compatibility runtime environment')
        exports += '\nexport ' + key + '=' + shlex.quote(value)
    return ('set -eu\nmkdir -p ' + shlex.quote(workdir) + '\ncd ' + shlex.quote(workdir) + exports
            + '\nexport DOTNET_ROOT=' + shlex.quote(sdk_root)
            + '\nexport DOTNET_ROOT_X64="$DOTNET_ROOT" DOTNET_ROOT_ARM64="$DOTNET_ROOT" DOTNET_MULTILEVEL_LOOKUP=0'
            + '\ncat > global.json <<\'GLOBAL\'\n' + json.dumps({'sdk': {'version': version, 'rollForward': 'disable'}}) + '\nGLOBAL'
            + '\ncat > NuGet.Config <<\'NUGET\'\n<configuration><packageSources><clear /></packageSources></configuration>\nNUGET'
            + '\ncat > Smoke.csproj <<\'PROJECT\'\n' + project + '\nPROJECT'
            + '\ncat > Program.cs <<\'PROGRAM\'\n' + smoke_program(sdk_root, expected_user, framework) + '\nPROGRAM\n'
            + shlex.quote(cli) + ' restore --configfile NuGet.Config\n'
            + shlex.quote(cli) + ' build --no-restore\n'
            + shlex.quote(cli) + ' bin/Debug/' + framework + '/Smoke.dll dll\n'
            + 'bin/Debug/' + framework + '/Smoke apphost\n')


def validate_smoke_output(output):
    require(all('published-offline-' + mode + '-http-crypto-icu-passed' in output for mode in ('dll', 'apphost')),
            'Non-root offline DLL/apphost, HTTP, cryptography or ICU smoke failed')
    require(output.count('published-tls12-passed') >= 2, 'Both DLL and apphost must execute the TLS1.2 handshake')
    return {name: 'passed' for name in ('consoleDllExecution', 'consoleApphostExecution', 'aspNetCoreLoopbackHttp',
                                     'rsaSha256SignAndVerify', 'cryptographicRandomBytes', 'frFrDecimalFormatting', 'tls12LoopbackHandshake')}
