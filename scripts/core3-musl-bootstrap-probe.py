#!/usr/bin/env python3
"""Probe a private Core3 ARM64 musl bootstrap; never emits a consumer SDK.

Run non-root inside the exact SDK-free Alpine candidate container. Imported
upstream SDK PE/data inputs remain an explicit bootstrap dependency. Every ELF
from that input is excluded, ReadyToRun is disabled, and only the original
official ARM64 musl runtime plus the source-ported crypto candidate may execute.
"""
import argparse,hashlib,json,os,pathlib,platform,resource,shutil,subprocess,tarfile,tempfile,time,zipfile
import musl_archive as MUSL
ROOT=pathlib.Path(__file__).resolve().parent.parent
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--inputs-dir',type=pathlib.Path,required=True)
parser.add_argument('--family',choices=('core31','core30'),default='core31')
parser.add_argument('--output-dir',type=pathlib.Path,required=True)
parser.add_argument('--native-evidence',type=pathlib.Path,required=True)
parser.add_argument('--trace-evidence',type=pathlib.Path,help='Optional successful original-manifest trace rebuild evidence.')
parser.add_argument('--tls',action='store_true',help='Also connect to the official release-metadata HTTPS endpoint using system trust.')
args=parser.parse_args()
profile=json.loads((ROOT/'profiles/experimental/core3-musl.json').read_text())
suffix='31' if args.family=='core31' else '30'
sdk_version='3.1.422' if suffix=='31' else '3.0.100'
runtime_version='3.1.28' if suffix=='31' else '3.0.0'
tfm='netcoreapp3.1' if suffix=='31' else 'netcoreapp3.0'
if (platform.system()!='Linux' or platform.machine()!='aarch64' or os.geteuid()==0
    or pathlib.Path('/etc/alpine-release').read_text().strip()!=profile['candidateAlpine'] or shutil.which('dotnet')):
 raise SystemExit('Native ARM64, non-root, exact SDK-free Alpine required')
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
r=args.inputs_dir.absolute();out=args.output_dir.absolute();evidence=args.native_evidence.absolute()
for path in (r,out,evidence):
 if path==pathlib.Path(path.anchor) or '..' in path.parts or any(p.is_symlink() for p in (path,*path.parents)):
  raise SystemExit('Ordinary absolute control paths required')
out.mkdir(parents=True,exist_ok=True)
if any(out.iterdir()):raise SystemExit('A new empty output directory is required')
native_result=json.loads((evidence/'results.json').read_text())
if not (native_result.get('candidatePort') is True and native_result.get('allRequestedTargetsPassed') is True
        and native_result.get('qualification') is False and native_result.get('architecture')=='aarch64'):
 raise SystemExit('A successful unqualified native source-port evidence set is required')
temporary=tempfile.TemporaryDirectory(prefix='cbodotnet-core3-bootstrap-')
workspace=pathlib.Path(temporary.name);boot=workspace/'bootstrap';boot.mkdir()
inputs=profile['bootstrapProbeInputs' if suffix=='31' else 'bootstrapCore30Inputs']
for row in inputs:
 name=row['name'];raw=(r/name).read_bytes()
 if len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256'] or hashlib.sha512(raw).hexdigest()!=row['sha512']:
  raise SystemExit('Imported upstream bootstrap input identity differs: '+name)
framework=boot/'shared/Microsoft.NETCore.App'/runtime_version
foreign_components=[];framework_metadata=[]
if suffix=='31':
 with tarfile.open(r/'bootstrap-runtime.tar.gz') as stream:stream.extractall(boot,filter='data')
else:
 framework.mkdir(parents=True)
 for row in inputs:
  if not row['name'].endswith('.nupkg'):continue
  with zipfile.ZipFile(r/row['name']) as archive:
   for name in archive.namelist():
    path=pathlib.PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts:raise SystemExit('Unsafe NuGet member path')
    if name.endswith('/'):continue
    if '/native/' in name and not name.startswith('runtimes/linux-musl-arm64/native/'):
     data=archive.read(name);foreign_components.append(dict(package=row['name'],path=name,sha256=hashlib.sha256(data).hexdigest(),elfMachine=int.from_bytes(data[18:20],'little') if data[:4]==b'\x7fELF' else None,disposition='foreign cross-tool excluded from the native bootstrap'));continue
    if name.startswith('runtimes/linux-musl-arm64/native/'):
     relative=name.split('/native/',1)[1]
     root=boot if row['role']=='dotnet-host' else boot/'host/fxr'/runtime_version if row['role']=='hostfxr' else framework
    elif '/lib/netcoreapp3.0/' in name and row['role']=='runtime-pack':
     relative=name.split('/lib/netcoreapp3.0/',1)[1];root=framework
    else:continue
    target=root/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(archive.read(name));target.chmod(0o755)
excluded=[];imported=[]
sdk_archive='bootstrap-sdk.tar.gz' if suffix=='31' else 'bootstrap-sdk30.tar.gz'
with tarfile.open(r/sdk_archive,mode='r|gz') as stream:
 for m in stream:
  p=pathlib.PurePosixPath(m.name);assert not p.is_absolute() and '..' not in p.parts
  name=str(p)
  if not m.isfile():continue
  data=stream.extractfile(m).read();row=dict(path=name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
  if data.startswith(b'\x7fELF'):excluded.append(row);continue
  if suffix=='30' and name.startswith('shared/Microsoft.NETCore.App/3.0.0/') and (name.endswith('.json') or name.endswith('/.version')):
   adapted=data.replace(b'linux-arm64',b'linux-musl-arm64') if name.endswith('.json') else data
   target=framework/pathlib.PurePosixPath(name).name;target.write_bytes(adapted)
   framework_metadata.append(dict(path=target.name,originalSha256=row['sha256'],generatedSha256=hashlib.sha256(adapted).hexdigest(),change='Private bootstrap metadata RID adaptation only; source producer must generate its own framework metadata.'))
  if not name.startswith(('sdk/','packs/','templates/')):continue
  target=boot/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);target.chmod(m.mode&0o755);imported.append(row)
(out/'imported-sdk-files.json').write_text(json.dumps(dict(scope='Private bootstrap experiment: upstream SDK/pack/template files only; every ELF excluded. ReadyToRun disabled. This is not a redistributable SDK or a source-built SDK claim.',imported=imported,excludedElfs=excluded),indent=2)+'\n')
(out/'framework-composition.json').write_text(json.dumps(dict(qualification=False,family=args.family,excludedForeignTargets=foreign_components,generatedMetadata=framework_metadata),indent=2)+'\n')
overrides=dict(HOME=str(workspace/'home'),DOTNET_CLI_HOME=str(workspace/'home'),DOTNET_CLI_TELEMETRY_OPTOUT='1',DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',DOTNET_NOLOGO='1',DOTNET_SYSTEM_GLOBALIZATION_INVARIANT='false',DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER='1',COMPlus_ReadyToRun='0',MSBUILDDISABLENODEREUSE='1')
env=dict(os.environ,**overrides)
records=[]
def run(name,cmd,extra=None):
 log=out/(name+'.log');start=time.monotonic()
 with log.open('x') as s:
  s.write(json.dumps(cmd)+'\n');s.flush()
  try:code=subprocess.run(cmd,env=dict(env,**(extra or {})),stdout=s,stderr=subprocess.STDOUT,timeout=90).returncode
  except subprocess.TimeoutExpired:code=124
 record=dict(name=name,command=cmd,environmentOverrides=extra or {},exitCode=code,seconds=round(time.monotonic()-start,2),log=log.name,sha256=hashlib.sha256(log.read_bytes()).hexdigest());records.append(record);return code
run('native-host-info',[str(boot/'dotnet'),'--info'])
run('sdk-default-icu',[str(boot/'dotnet'),'--version'])
run('sdk-icu78',[str(boot/'dotnet'),'--version'],dict(CLR_ICU_VERSION_OVERRIDE='78'))
run('msbuild-before-openssl3-port',[str(boot/'dotnet'),'msbuild','-version','-nologo'])
shim=evidence/('candidate-native/corefx'+suffix+'-OpenSsl.so')
if not shim.is_file():raise ValueError('Successful branch-native OpenSSL3 source probe required')
smoke=json.loads((evidence/('corefx'+suffix+'-native-smoke.json')).read_text())
if hashlib.sha256(shim.read_bytes()).hexdigest()!=smoke['sha256']:raise SystemExit('Compiled crypto candidate differs from its native smoke receipt')
native=framework/'System.Security.Cryptography.Native.OpenSsl.so'
old=hashlib.sha256(native.read_bytes()).hexdigest();shutil.copyfile(shim,native)
source_pin=next(x for x in profile['sourceInputs'] if x['name']=='corefx'+suffix)
(out/'crypto-replacement.json').write_text(json.dumps(dict(originalOfficialMuslSha256=old,replacementSha256=hashlib.sha256(native.read_bytes()).hexdigest(),replacementSource=source_pin,runtime=runtime_version,qualification=False),indent=2)+'\n')
run('msbuild-after-openssl3-port',[str(boot/'dotnet'),'msbuild','-version','-nologo'])
if args.trace_evidence:
 trace_root=args.trace_evidence.absolute();trace_result=json.loads((trace_root/'results.json').read_text())
 if not (trace_result.get('allRequestedTargetsPassed') is True and trace_result.get('qualification') is False
         and trace_result.get('architecture')=='aarch64'):raise SystemExit('Successful native trace source evidence required')
 trace=trace_root/('candidate-native/coreclr'+suffix+'-traceptprovider.so')
 trace_smoke=json.loads((trace_root/('coreclr'+suffix+'-trace-smoke.json')).read_text())
 if hashlib.sha256(trace.read_bytes()).hexdigest()!=trace_smoke['sha256']:raise SystemExit('Trace candidate differs from its original-source receipt')
 target=framework/'libcoreclrtraceptprovider.so'
 (out/'trace-replacement.json').write_text(json.dumps(dict(originalOfficialMuslSha256=hashlib.sha256(target.read_bytes()).hexdigest(),replacementSha256=trace_smoke['sha256'],sourceEvidence=str(trace_root),qualification=False),indent=2)+'\n')
 shutil.copyfile(trace,target)
probe=workspace/'probe';probe.mkdir()
code='''using System;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Net.Http;
class Probe {
 static void Check(bool ok, string name) { if (!ok) throw new Exception(name); Console.WriteLine("PASS " + name); }
 static void Main(string[] args) {
  Check(RuntimeInformation.ProcessArchitecture == Architecture.Arm64, "native ARM64");
  Check(CultureInfo.GetCultureInfo("fr-FR").NumberFormat.NumberDecimalSeparator == "," && CultureInfo.GetCultureInfo("tr-TR").TextInfo.ToUpper("i") == "İ", "full ICU globalization");
  var message = Encoding.UTF8.GetBytes("abc");
  using (var sha = SHA256.Create()) Check(BitConverter.ToString(sha.ComputeHash(message)).Replace("-", "") == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", "SHA256 known vector");
  var random = new byte[32]; RandomNumberGenerator.Fill(random); Check(random.Any(x => x != 0), "secure random");
  using (var rsa=RSA.Create(2048)) { var signature=rsa.SignData(message,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1); Check(rsa.VerifyData(message,signature,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1), "RSA sign verify");
   var req = new CertificateRequest("CN=core3-musl-probe",rsa,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
   using(var cert=req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1))) Check(cert.Subject.Contains("core3-musl-probe"), "X509 certificate construction"); }
  using(var ec=ECDsa.Create(ECCurve.NamedCurves.nistP256)) { var signature=ec.SignData(message,HashAlgorithmName.SHA256); Check(ec.VerifyData(message,signature,HashAlgorithmName.SHA256), "ECDSA sign verify"); }
  var key=new byte[32];RandomNumberGenerator.Fill(key);var nonce=new byte[12];RandomNumberGenerator.Fill(nonce);var ciphertext=new byte[message.Length];var plaintext=new byte[message.Length];var tag=new byte[16];
  using(var aes=new AesGcm(key)) {aes.Encrypt(nonce,message,ciphertext,tag);aes.Decrypt(nonce,ciphertext,tag,plaintext);Check(message.SequenceEqual(plaintext),"AES GCM roundtrip");}
  if(args.Length>0 && args[0]=="tls") using(var http=new HttpClient()) {http.Timeout=TimeSpan.FromSeconds(30);var response=http.GetAsync("https://builds.dotnet.microsoft.com/dotnet/release-metadata/3.1/releases.json").GetAwaiter().GetResult();Check(response.IsSuccessStatusCode,"HTTPS with system trust");}
 }
}
'''
(probe/'Probe.cs').write_text(code);(out/'Probe.cs').write_text(code)
refs=next((boot/'packs/Microsoft.NETCore.App.Ref').glob('*/ref/'+tfm))
response='/noconfig\n/nostdlib+\n/target:exe\n/out:'+str(probe/'Probe.dll')+'\n'+'\n'.join('/r:'+str(x) for x in sorted(refs.glob('*.dll')))+'\n'+str(probe/'Probe.cs')+'\n'
(probe/'compile.rsp').write_text(response);(out/'compile.rsp').write_text(response)
(probe/'Probe.runtimeconfig.json').write_text(json.dumps(dict(runtimeOptions=dict(tfm=tfm,framework=dict(name='Microsoft.NETCore.App',version=runtime_version)))))
if run('compile-managed-probe',[str(boot/'dotnet'),str(boot/('sdk/'+sdk_version+'/Roslyn/bincore/csc.dll')),'@'+str(probe/'compile.rsp')])==0:
 run('managed-crypto-globalization',[str(boot/'dotnet'),str(probe/'Probe.dll')])
 if args.tls:run('managed-system-trust-tls',[str(boot/'dotnet'),str(probe/'Probe.dll'),'tls'])
(probe/'Probe.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>'+tfm+'</TargetFramework><OutputType>Exe</OutputType><UseAppHost>false</UseAppHost></PropertyGroup></Project>')
(probe/'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>')
if run('sdk-project-offline-restore',[str(boot/'dotnet'),'restore',str(probe/'Probe.csproj'),'--configfile',str(probe/'NuGet.Config'),'-p:UseAppHost=false'])==0:
 if run('sdk-project-offline-build',[str(boot/'dotnet'),'build',str(probe/'Probe.csproj'),'--no-restore','-p:UseAppHost=false','-c','Release','-m:2'])==0:
  run('sdk-project-native-run',[str(boot/'dotnet'),str(probe/('bin/Release/'+tfm+'/Probe.dll'))])
elfs=[]
for path in sorted(boot.rglob('*')):
 if not path.is_file() or path.is_symlink():continue
 with path.open('rb') as stream:magic=stream.read(4)
 if magic==b'\x7fELF':
  inspected=MUSL.inspect_elf(path)
  labels=MUSL.reviewed_gcc_abi_labels(inspected)
  if inspected['machine']!='AArch64' or inspected['interpreter'] not in (None,'/lib/ld-musl-aarch64.so.1') or 'libc.so.6' in inspected['needed']:
   raise SystemExit('Non-musl or foreign ELF in private bootstrap')
  elfs.append(dict(path=path.relative_to(boot).as_posix(),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),reviewedAbiVersionLabels=labels,**inspected))
try:
 closure=MUSL.audit_elf(boot,'aarch64')
except ValueError as error:
 closure=dict(status='not-qualified',reason=str(error),scope='Complete closure gate is retained as an unresolved producer requirement; functional bootstrap success does not override it.')
(out/'elf-audit.json').write_text(json.dumps(dict(elfs=elfs,closure=closure,sharedAuditorSha256=hashlib.sha256(pathlib.Path(MUSL.__file__).read_bytes()).hexdigest()),indent=2)+'\n')
(out/'retained-inputs.json').write_text(json.dumps(dict(inputs=inputs,nativeEvidence=str(evidence),candidateCryptoSha256=smoke['sha256']),indent=2)+'\n')
(out/'results.json').write_text(json.dumps(dict(qualification=False,releaseAdmission=False,architecture='aarch64',family=args.family,environment=overrides,records=records,nativeClosureStatus=closure['status'],expectedOriginalCryptoFailure='msbuild-before-openssl3-port',scope='Private bootstrap prototype only. No apphost, ASP.NET, full source SDK graph or two-CPU release qualification claim.'),indent=2)+'\n')
print(json.dumps(dict(status='private-bootstrap-probe-recorded',qualification=False,targetExitCodes={x['name']:x['exitCode'] for x in records})))
temporary.cleanup()
