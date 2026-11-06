"""Clean-caller and historical-r2 gates for the corrected Core3 archive launcher.

Only launcher contract 2 opts in. Historical signed reports remain readable.
The standalone wrapper supplies the private environment; only direct apphosts
receive the separately documented environment from the surrounding harness.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

from consumer_archive import ROOT, REPOSITORY, descriptor, encoded, ordinary_file, require

HISTORICAL_MANIFESTS = {
    '3.1.426': '8ac3032b1a81743d96c93e2ac611b3e5abde30c01d729bd8a9c6facfff2fc0a5',
    '3.0.103': 'ac0a29c365e6a0a2a48daaee995ddba058ea3fcbaec0ff99e2ab69ddf5092c68',
}
HISTORICAL_SIGNATURES = {
    '3.1.426': 'd5e17c352272afd2a6e0f3804ef4b9824aa96e7508ec60624f459923f2e63cbf',
    '3.0.103': 'b9264b0837b86d29aebf9f5df953b4c7dd87f320cc87428d665200a0ccd08ba8',
}
SCOPED = ('LD_LIBRARY_PATH', 'OPENSSL_CONF', 'CLR_OPENSSL_VERSION_OVERRIDE',
          'CLR_ICU_VERSION_OVERRIDE', 'SSL_CERT_FILE')
REMOVED = ('LD_LIBRARY_PATH', 'OPENSSL_CONF', 'CLR_OPENSSL_VERSION_OVERRIDE',
           'CLR_ICU_VERSION_OVERRIDE', 'DOTNET_ICU_VERSION_OVERRIDE',
           'DOTNET_SYSTEM_GLOBALIZATION_APPLOCALICU', 'CBODOTNET_COMPAT_SCOPE',
           'CBODOTNET_COMPAT_ROOT', 'CBODOTNET_CURL_COMPAT_ROOT',
           'DOTNET_ROOT', 'DOTNET_ROOT_X64', 'DOTNET_ROOT_ARM64',
           'DOTNET_HOST_PATH', 'DOTNET_MULTILEVEL_LOOKUP') + tuple(
    'CBODOTNET_COMPAT_SAVED_' + name + suffix
    for name in SCOPED for suffix in ('_SET', '_VALUE'))
NEGATIVES = ('missing-base', 'missing-curl', 'substituted-curl', 'tampered-curl',
             'unsafe-base-colon', 'unsafe-curl-semicolon', 'unsafe-curl-token')
SCOPE = 'consumer-archive-clean-caller-environment'


def required(plan):
    version = plan.get('archiveLauncherVersion', 1)
    require(type(version) is int and version in (1, 2), 'Unsupported archive launcher qualification contract')
    revision=plan.get('packageRevision',1)
    require(type(revision) is int and revision>0,'A positive exact archive revision is required')
    corrected = plan.get('sdkVersion') in HISTORICAL_MANIFESTS and revision >= 3
    require(version == (2 if corrected else 1), 'Core3 r3 and later require archive launcher contract 2')
    return version == 2


def roots(plan):
    return dict(CBODOTNET_COMPAT_ROOT=plan['compatibility']['root'],
                CBODOTNET_CURL_COMPAT_ROOT=plan['nativeHttpCompatibility']['root'])


def clean_environment(environment=None, *, preserve_certificate=False):
    result = dict(os.environ if environment is None else environment)
    for name in REMOVED + (() if preserve_certificate else ('SSL_CERT_FILE',)):
        result.pop(name, None)
    return result


def clean_wrapper(path, command, plan, *, preserve_certificate=True):
    arguments = ['env']
    for name in REMOVED + (() if preserve_certificate else ('SSL_CERT_FILE',)):
        arguments += ['-u', name]
    arguments += [name + '=' + value for name, value in roots(plan).items()]
    arguments += [str(command)]
    path = Path(path)
    require(not path.exists() and not path.is_symlink(), 'A fresh clean-caller shim is required')
    path.write_text('#!/bin/sh\nexec ' + shlex.join(arguments) + ' "$@"\n')
    path.chmod(0o755)
    return path


def receive_historical(build, workspace):
    """Authenticate and anonymously fetch the exact retained r2 comparison input."""
    plan = build['plan']
    if not required(plan):
        return None
    from consumer_archive_site import authenticate_receipt, fetch_bytes, load_archive_status
    candidates = [row for row in load_archive_status()['publications']
                  if row['identity']['sdkVersion'] == plan['sdkVersion']
                  and row['identity']['packageRevision'] == 2]
    require(len(candidates) == 1, 'The exact original Core3 r2 receipt is required')
    receipt = candidates[0]
    require(receipt['manifestSha256'] == HISTORICAL_MANIFESTS[plan['sdkVersion']],
            'The reviewed original Core3 r2 manifest pin changed')
    signature = next(row for row in receipt['assets'] if row['name'] == 'distribution-manifest.json.asc')
    require(signature['sha256'] == HISTORICAL_SIGNATURES[plan['sdkVersion']] and signature['size'] == 228,
            'The reviewed original Core3 r2 signature pin changed')
    destination = Path(workspace) / 'historical'
    destination.mkdir()
    metadata = destination / 'metadata'; metadata.mkdir()

    def fetch(url, maximum):
        data = fetch_bytes(url, maximum)
        (metadata / url.rsplit('/', 1)[-1]).write_bytes(data)
        return data

    manifest = authenticate_receipt(receipt, historical=True, fetch=fetch)
    require(hashlib.sha256(encoded(manifest)).hexdigest() == receipt['manifestSha256'],
            'Original r2 manifest canonical bytes differ from the reviewed pin')
    record = next(row for row in manifest['records'] if row['architecture'] == plan['architecture'])
    previous = record['build']
    require(previous['plan']['packageRevision'] == 2
            and previous['plan']['sourceManifestSha256'] == plan['sourceManifestSha256']
            and previous['qualifiedPayload'] == build['qualifiedPayload'],
            'Historical comparison must use the same immutable SDK payload')
    assets = {row['name']: row for row in receipt['assets']}
    artifact = assets[record['artifactAsset']]
    # The public downloader admits exact names, bounded sizes and SHA256 bytes,
    # and deliberately never attaches GitHub credentials to release requests.
    from consumer_archive_public import download
    download(artifact, destination / artifact['name'])
    (destination / 'build.json').write_bytes(encoded(previous))
    state = dict(schemaVersion=1, status='authenticated', revision=2,
        sdkVersion=plan['sdkVersion'], architecture=plan['architecture'],
        manifestUrl=receipt['manifestUrl'], manifestSha256=receipt['manifestSha256'],
        signatureUrl=receipt['signatureUrl'], signingFingerprint=receipt['signingFingerprint'],
        artifact=artifact, qualifiedPayload=previous['qualifiedPayload'],
        command=next(row for row in previous['commands'] if row['path'] == 'cbodotnet'),
        manifest=manifest,
        signature={key: assets['distribution-manifest.json.asc'][key] for key in ('name', 'size', 'sha256')})
    (destination / 'source.json').write_bytes(encoded(state))
    return state


def prepare_historical(build, workspace, install, tools):
    if not required(build['plan']):
        return None
    source = json.loads(ordinary_file(Path(workspace) / 'historical/source.json').read_bytes())
    previous = json.loads(ordinary_file(Path(workspace) / 'historical/build.json').read_bytes())
    artifact = ordinary_file(Path(workspace) / 'historical' / source['artifact']['name'])
    require(descriptor(artifact) == {key: source['artifact'][key] for key in ('name', 'size', 'sha256')},
            'Historical r2 archive changed after authentication')
    tools.extract_sdk(artifact, Path(install) / 'historical r2 archive')
    tree = Path(install) / 'historical r2 archive' / previous['directory']
    require(descriptor(tree / 'cbodotnet') == dict(name='cbodotnet', size=source['command']['size'],
            sha256=source['command']['sha256']), 'Extracted historical wrapper differs from signed r2 bytes')
    return dict(source, root=str(tree))


def environment_probe(plan, variant, payload, cli, work, api):
    """Compile and execute a real child after removing all ambient provider state."""
    from sdk_runtime import target_framework
    import legacy_compat
    base, curl = plan['compatibility']['root'], plan['nativeHttpCompatibility']['root']
    expected_ca = legacy_compat.environment(dict(plan, variant=variant))['SSL_CERT_FILE']
    program = r'''using System; using System.IO; using System.Linq; using System.Globalization;
using System.Security.Cryptography; using System.Text; using System.Text.Json;
public static class Program {
 public static void Main() {
  using(var rsa=RSA.Create()) { rsa.KeySize=2048; var bytes=Encoding.UTF8.GetBytes("archive-provider");
   var signature=rsa.SignData(bytes,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
   if(!rsa.VerifyData(bytes,signature,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1)) throw new Exception("RSA failed"); }
  if(!1234.5m.ToString("N1",new CultureInfo("fr-FR")).Contains(",")) throw new Exception("ICU failed");
  if(Environment.GetEnvironmentVariable("SSL_CERT_FILE")!=@CA@ || !File.Exists(@CA@)) throw new Exception("Wrapper stock CA differs");
  if(Environment.GetEnvironmentVariable("OPENSSL_CONF")!=@BASE@+"/openssl.cnf"
     || Environment.GetEnvironmentVariable("CLR_OPENSSL_VERSION_OVERRIDE")!="1.1"
     || Environment.GetEnvironmentVariable("CLR_ICU_VERSION_OVERRIDE")!="67") throw new Exception("Wrapper provider environment missing");
  if(Environment.GetEnvironmentVariable("LD_LIBRARY_PATH")!=@CURL@+"/lib:"+@BASE@+"/lib") throw new Exception("Wrapper library order differs");
  var maps=File.ReadAllLines("/proc/self/maps").Where(line=>line.Contains("libcrypto")||line.Contains("libssl")||line.Contains("libicu")).ToArray();
  Console.WriteLine("CBODOTNET_ARCHIVE_PROVIDER="+JsonSerializer.Serialize(new {status="passed",baseRoot=@BASE@,curlRoot=@CURL@,
   certificateFile=@CA@,opensslConfiguration=Environment.GetEnvironmentVariable("OPENSSL_CONF"),
   libraryPath=Environment.GetEnvironmentVariable("LD_LIBRARY_PATH"),nativeMappings=maps}));
 }
}
'''.replace('@BASE@', json.dumps(base)).replace('@CURL@', json.dumps(curl)).replace('@CA@', json.dumps(expected_ca))
    framework = target_framework(plan['sdkVersion'])
    work = Path(work)
    api.user_run(['mkdir', '--', work])
    (work / 'Probe.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>' + framework
        + '</TargetFramework><OutputType>Exe</OutputType></PropertyGroup></Project>')
    (work / 'Program.cs').write_text(program)
    (work / 'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>')
    api.user_run(['sh', '-ec', 'cd "$1"; "$2" restore --configfile NuGet.Config; "$2" build --no-restore',
                  'archive-probe', work, cli])
    output = api.user_run([cli, work / ('bin/Debug/' + framework + '/Probe.dll')])
    rows = [line.removeprefix('CBODOTNET_ARCHIVE_PROVIDER=') for line in output.splitlines()
            if line.startswith('CBODOTNET_ARCHIVE_PROVIDER=')]
    require(len(rows) == 1, 'One actual root-only archive environment probe is required')
    proof = json.loads(rows[0])
    from native_curl_runtime import decoded_mapping
    mappings = {decoded_mapping(line).split(None,5)[5] for line in proof['nativeMappings'] if len(line.split(None,5))==6}
    manifest = json.loads(Path(base, 'provider-manifest.json').read_bytes())
    components = [row for row in manifest['files'] if row['type'] == 'file'
                  and (row['path'].startswith('lib/libcrypto.so.') or row['path'].startswith('lib/libicu'))]
    require(components and all(base + '/' + row['path'] in mappings for row in components),
            'Clean archive child did not map the exact private crypto/ICU components')
    proof.update(scope='clean-archive-private-provider-environment', userId=10001, network='none',
        components=[dict(path=base + '/' + row['path'], sha256=row['sha256']) for row in components])
    return proof


def negative_cases(plan, command, api, work):
    """Missing, substituted, unsafe and changed providers must fail before host execution."""
    roots_env = roots(plan)
    base = Path(roots_env['CBODOTNET_COMPAT_ROOT'])
    curl = Path(roots_env['CBODOTNET_CURL_COMPAT_ROOT'])
    missing = str(Path(work) / 'missing-provider')
    cases = [
        ('missing-base', dict(CBODOTNET_COMPAT_ROOT=missing)),
        ('missing-curl', dict(CBODOTNET_CURL_COMPAT_ROOT=missing)),
        ('substituted-curl', dict(CBODOTNET_CURL_COMPAT_ROOT=str(base))),
        ('unsafe-base-colon', dict(CBODOTNET_COMPAT_ROOT=str(base) + ':other')),
        ('unsafe-curl-semicolon', dict(CBODOTNET_CURL_COMPAT_ROOT=str(curl) + ';other')),
        ('unsafe-curl-token', dict(CBODOTNET_CURL_COMPAT_ROOT=str(curl) + '/$ORIGIN')),
    ]
    result = {}
    for name, extra in cases:
        response = api.user_result([command, '--version'], extra=dict(roots_env, **extra), clean=True)
        require(response.returncode != 0 and response.stdout == '',
                'Archive executed a host with an invalid provider: ' + name)
        result[name] = dict(status='passed', exitCode=response.returncode, noHostOutput=True)
    component = curl / 'lib/libcurl.so.4.5.0'
    before = component.read_bytes()
    try:
        component.write_bytes(before + b'archive-qualification-tamper')
        response = api.user_result([command, '--version'], extra=roots_env, clean=True)
        require(response.returncode != 0 and response.stdout == '', 'Changed provider bytes executed the SDK host')
        result['tampered-curl'] = dict(status='passed', exitCode=response.returncode, noHostOutput=True)
    finally:
        component.write_bytes(before)
    return result


def reproduce_historical(plan, source, payload, cli, work, api):
    """The same real HTTPS request passes the new wrapper and fails retained r2."""
    from sdk_runtime import target_framework
    framework = target_framework(plan['sdkVersion']); work = Path(work)
    api.user_run(['mkdir', '--', work])
    program = r'''using System; using System.IO; using System.Linq; using System.Net; using System.Net.Http;
using System.Net.Sockets; using System.Net.Security; using System.Security.Authentication;
using System.Security.Cryptography; using System.Security.Cryptography.X509Certificates; using System.Threading.Tasks;
public static class Program {
 public static async Task Main(string[] args) {
  if(Environment.GetEnvironmentVariable("DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER")!="0"
    || !typeof(object).Assembly.Location.StartsWith(args[0]+"/shared/")) throw new Exception("Wrong forced Curl runtime");
  using(var key=RSA.Create()) { key.KeySize=2048;
   var req=new CertificateRequest("CN=localhost",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
   using(var cert=req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddDays(1))) {
    var listener=new TcpListener(IPAddress.Loopback,0); listener.Start();
    try { var port=((IPEndPoint)listener.LocalEndpoint).Port;
     var server=Task.Run(async()=> { using(var peer=await listener.AcceptTcpClientAsync())
      using(var ssl=new SslStream(peer.GetStream(),false)) {
       await ssl.AuthenticateAsServerAsync(cert,false,SslProtocols.Tls12,false);
       var request=new byte[8192]; await ssl.ReadAsync(request,0,request.Length);
       var bytes=System.Text.Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
       await ssl.WriteAsync(bytes,0,bytes.Length);
      }});
     var callbacks=0;
     using(var handler=new HttpClientHandler()) { handler.ServerCertificateCustomValidationCallback=(message,remote,chain,errors)=> {callbacks++;return remote!=null&&remote.RawData.SequenceEqual(cert.RawData);};
      handler.SslProtocols=SslProtocols.Tls12;
      using(var client=new HttpClient(handler)) { client.Timeout=TimeSpan.FromSeconds(15);
       if(await client.GetStringAsync("https://localhost:"+port+"/")!="ok") throw new Exception("HTTPS failed");
      }
     }
     await server; if(callbacks<1) throw new Exception("Certificate callback not observed");
     Console.WriteLine("CORE3_STANDALONE_CURL_REPRO_PASSED");
    } finally { listener.Stop(); }
   }
  }
 }
}
'''
    (work / 'Repro.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>' + framework
        + '</TargetFramework><OutputType>Exe</OutputType></PropertyGroup></Project>')
    (work / 'Program.cs').write_text(program)
    (work / 'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>')
    api.user_run(['sh', '-ec', 'cd "$1"; "$2" restore --configfile NuGet.Config; "$2" build --no-restore',
                  'archive-repro', work, cli])
    dll = work / ('bin/Debug/' + framework + '/Repro.dll')
    positive = api.user_result([cli, dll, payload], extra={'DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER': '0'}, clean=True)
    require(positive.returncode == 0 and 'CORE3_STANDALONE_CURL_REPRO_PASSED' in positive.stdout,
            'Corrected wrapper failed the historical Curl HTTPS positive control\n' + positive.stderr[-3000:])
    previous = Path(source['root'])
    negative = api.user_result([previous / 'cbodotnet', dll, previous / 'payload'],
        extra=dict(roots(plan), DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER='0'), clean=True)
    diagnostics = negative.stdout + '\n' + negative.stderr
    require(negative.returncode != 0 and 'CORE3_STANDALONE_CURL_REPRO_PASSED' not in negative.stdout
            and 'Wrong forced Curl runtime' not in diagnostics
            and re.search(r'Curl|SSL|System\.Net\.Http\.Native|libcurl', diagnostics, re.IGNORECASE),
            'Actual r2 clean-caller Curl failure was not reproduced\n' + diagnostics[-3000:])
    return dict(status='passed', scope='actual-published-r2-clean-caller-curl-failure',
        source={key: value for key, value in source.items() if key not in {'root', 'manifest'}},
        runtimeRoot=str(previous / 'payload'), userId=10001, network='none',
        forcedSocketsHttpHandler='0', positiveControl='passed', correctedRevision=plan['packageRevision'],
        historicalExitCode=negative.returncode, historicalStdout=negative.stdout[-9000:],
        historicalStderr=negative.stderr[-9000:], programSha256=hashlib.sha256(program.encode()).hexdigest(),
        assembly=descriptor(dll))


def validate_clean_report(report, plan):
    """Only the new explicitly versioned archive contract requires these gates."""
    if not required(plan):
        return
    require(plan['sdkVersion'] in HISTORICAL_MANIFESTS and plan['packageRevision'] >= 3,
            'Clean archive launcher contract requires a corrected Core3 revision')
    base, curl = plan['compatibility']['root'], plan['nativeHttpCompatibility']['root']
    from native_curl_runtime import decoded_mapping
    import legacy_compat
    publication = report.get('historicalR2Publication', {})
    manifest = publication.get('manifest', {})
    require(publication.get('schemaVersion') == 1 and publication.get('status') == 'authenticated'
            and publication.get('manifestSha256') == HISTORICAL_MANIFESTS[plan['sdkVersion']]
            and hashlib.sha256(encoded(manifest)).hexdigest() == publication['manifestSha256']
            and publication.get('signingFingerprint') == manifest.get('signingFingerprint')
            and publication.get('signatureUrl') == f'https://github.com/{REPOSITORY}/releases/download/distribution-archive-sdk-{plan["sdkVersion"]}-r2/distribution-manifest.json.asc'
            and manifest.get('identity', {}).get('sdkVersion') == plan['sdkVersion']
            and manifest['identity'].get('packageRevision') == 2,
            'New archive proof lacks the exact authenticated original-r2 publication')
    records = [row for row in manifest.get('records', []) if row.get('architecture') == plan['architecture']]
    require(len(records) == 1, 'Original-r2 archive architecture proof is incomplete')
    previous_build = records[0]['build']
    previous_asset = next(row for row in manifest['assets'] if row['name'] == records[0]['artifactAsset'])
    signature = publication.get('signature', {})
    require({key: publication.get('artifact', {}).get(key) for key in ('name', 'size', 'sha256')} == previous_asset
            and publication['artifact'].get('url') == f'https://github.com/{REPOSITORY}/releases/download/{manifest["tag"]}/' + previous_asset['name']
            and publication.get('command') == next(row for row in previous_build['commands'] if row['path'] == 'cbodotnet')
            and publication.get('qualifiedPayload') == previous_build['qualifiedPayload'] == report['qualifiedPayload']
            and previous_build['plan']['sourceManifestSha256'] == plan['sourceManifestSha256']
            and signature == dict(name='distribution-manifest.json.asc', size=228,
                sha256=HISTORICAL_SIGNATURES[plan['sdkVersion']]),
            'Original-r2 source, wrapper, artifact or signature byte binding differs')
    for key, field in (('compatibility', 'compatibility'), ('nativeHttpCompatibility', 'nativeHttpCompatibility')):
        companions = [row for row in manifest.get(key, []) if row.get('architecture') == plan['architecture']]
        require(len(companions) == 1 and companions[0]['record']['companion'] == report[field]['companion']
                and companions[0]['record']['manifest'] == report[field]['manifest'],
                'Historical reproduction substituted another companion source or byte revision')
    expected_components = [dict(path=base + '/' + row['path'], sha256=row['sha256'])
        for row in report['compatibility']['manifest']['files'] if row['type'] == 'file'
        and (row['path'].startswith('lib/libcrypto.so.') or row['path'].startswith('lib/libicu'))]
    expected_crypto = [dict(path=base + '/' + row['path'], sha256=row['sha256'])
        for row in report['compatibility']['manifest']['files'] if row['type'] == 'file'
        and row['path'].startswith(('lib/libcrypto.so.', 'lib/libssl.so.'))]
    for space in report['userSpaces']:
        proof = space.get('cleanCallerEnvironment', {})
        require(proof.get('schemaVersion') == 1 and proof.get('scope') == SCOPE and proof.get('status') == 'passed'
                and proof.get('callerEnvironment') == 'verified-root-variables-only'
                and proof.get('removedVariables') == list(REMOVED)
                and proof.get('rootVariables') == roots(plan)
                and proof.get('cliIsolation') == 'env-unset-before-each-wrapper-execution'
                and proof.get('apphostEnvironment') == 'explicit-documented-provider-environment'
                and proof.get('functionalChecks') == space['functionalChecks']
                and proof.get('nativeCurlHandler') == space['nativeCurlHandler'],
                'New archive report lacks exact clean-caller CLI qualification')
        crypto_mappings = {decoded_mapping(line).split(None,5)[5] for line in space['nativeCurlHandler'].get('nativeMappings', [])
                           if len(line.split(None,5))==6}
        require(proof.get('nativeCryptoComponents') == expected_crypto and len(expected_crypto) == 2
                and all(row['path'] in crypto_mappings for row in expected_crypto),
                'Clean archive forced CurlHandler did not map the exact private SSL/crypto components')
        probe = proof.get('providerProbe', {})
        expected_ca = legacy_compat.environment(dict(plan, variant=space['variant']))['SSL_CERT_FILE']
        components = probe.get('components', [])
        mappings = {decoded_mapping(line).split(None,5)[5] for line in probe.get('nativeMappings', [])
                    if len(line.split(None,5))==6}
        require(probe.get('status') == 'passed' and probe.get('scope') == 'clean-archive-private-provider-environment'
                and probe.get('baseRoot') == base and probe.get('curlRoot') == curl
                and probe.get('certificateFile') == expected_ca
                and probe.get('opensslConfiguration') == base + '/openssl.cnf'
                and probe.get('libraryPath') == curl + '/lib:' + base + '/lib'
                and probe.get('userId') == 10001 and probe.get('network') == 'none'
                and components == expected_components and len(components) >= 4 and all(re.fullmatch(r'[a-f0-9]{64}', row.get('sha256', ''))
                    and row.get('path', '').startswith(base + '/lib/')
                    and row['path'] in mappings for row in components),
                'New archive clean-caller private crypto/ICU/CA proof is incomplete')
        negatives = proof.get('negativeCases', {})
        require(set(negatives) == set(NEGATIVES) and all(row.get('status') == 'passed'
                and type(row.get('exitCode')) is int and row['exitCode'] != 0
                and row.get('noHostOutput') is True for row in negatives.values()),
                'New archive missing/substituted/unsafe/tampered provider rejection is incomplete')
        previous = proof.get('historicalR2', {}); source = previous.get('source', {})
        assembly=previous.get('assembly',{})
        require(previous.get('status') == 'passed'
                and previous.get('scope') == 'actual-published-r2-clean-caller-curl-failure'
                and source.get('manifestSha256') == HISTORICAL_MANIFESTS[plan['sdkVersion']]
                and source.get('sdkVersion') == plan['sdkVersion'] and source.get('revision') == 2
                and source.get('architecture') == plan['architecture']
                and source == {key: value for key, value in publication.items() if key != 'manifest'}
                and source.get('qualifiedPayload') == report['qualifiedPayload']
                and source.get('manifestUrl') == f'https://github.com/{REPOSITORY}/releases/download/distribution-archive-sdk-{plan["sdkVersion"]}-r2/distribution-manifest.json'
                and previous.get('positiveControl') == 'passed'
                and previous.get('correctedRevision') == plan['packageRevision']
                and previous.get('userId') == 10001 and previous.get('network') == 'none'
                and previous.get('forcedSocketsHttpHandler') == '0'
                and previous.get('runtimeRoot') == '/opt/cbodotnet-consumer-validation/historical r2 archive/'+previous_build['directory']+'/payload'
                and assembly.get('name') == 'Repro.dll' and type(assembly.get('size')) is int
                and 0 < assembly['size'] < 16*1024**2 and re.fullmatch(r'[a-f0-9]{64}',assembly.get('sha256',''))
                and type(previous.get('historicalExitCode')) is int and previous['historicalExitCode'] != 0
                and 'CORE3_STANDALONE_CURL_REPRO_PASSED' not in previous.get('historicalStdout', '')
                and 'Wrong forced Curl runtime' not in (previous.get('historicalStdout', '') + previous.get('historicalStderr', ''))
                and re.search(r'Curl|SSL|System\.Net\.Http\.Native|libcurl',
                    previous.get('historicalStdout', '') + previous.get('historicalStderr', ''), re.IGNORECASE)
                and re.fullmatch(r'[a-f0-9]{64}', previous.get('programSha256', '')),
                'New archive proof omits the authenticated actual-r2 failure and new-wrapper positive control')
        from consumer_archive_lifecycle import validate_lifecycle_evidence
        lifecycle = proof.get('lifecycle', {})
        validate_lifecycle_evidence(lifecycle, plan)
        require(lifecycle['reinstall']['artifact'] == report['artifact'],
                'New archive reinstallation used another artifact than the exact signed report')
