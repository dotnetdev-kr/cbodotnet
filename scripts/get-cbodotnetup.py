#!/usr/bin/env python3
"""SDK-free bootstrap. Requires Python3, GnuPG, CA certificates, GNU stat on Alpine and an ordinary Linux user."""
import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import subprocess
import ssl
import tempfile
import urllib.parse
import urllib.request

FINGERPRINT='D7D154B4B33C19A82B95B13688135410ACD9C0EA'
CATALOG='https://dotnetdev.kr/cbodotnet/cbodotnetup/v3/catalog.json'
MUSL_CATALOG='https://dotnetdev.kr/cbodotnet/cbodotnetup/v4/catalog.json'
OWNER='cbodotnetup-v1'
PUBLIC_KEY='''-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEauqamxYJKwYBBAHaRw8BAQdAoMhTP7GorluFi8j13VymBXtMGFiNWx86qnJ1
R1gGXm20QkNvbW11bml0eSBCdWlsZCBvZiAuTkVUIChidWlsdCBieSAuTkVUIERl
dikgLSBkaXN0cmlidXRpb24gc2lnbmluZ4iWBBMWCAA+FiEE19FUtLM8GagrlbE2
iBNUEKzZwOoFAmrqmpsCGwMFCQPCZwAFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AA
CgkQiBNUEKzZwOqiDgD8CWactLuBXLB88qZi6ZUk0AjVzY/0Eo90U4Tv7UYC+IgA
/jtkOoDkSNh/xzgb16VaD4+0EzoT1d0exbD4zyTYRBIC
=euC5
-----END PGP PUBLIC KEY BLOCK-----
'''


def require(value, message):
    if not value: raise ValueError(message)


def ordinary(path):
    path=Path(path).absolute()
    require(not any(p.is_symlink() for p in (path,*path.parents)), 'Refusing a symlink in an installation path: '+str(path))
    return path


def private(path):
    path=ordinary(path); path.mkdir(parents=True,exist_ok=True,mode=0o700)
    info=path.stat();require(info.st_uid==os.geteuid() and not info.st_mode & 0o022, 'Installation directory is unowned or writable by another user')
    return path


def atomic(path, data, mode=0o600):
    path=ordinary(path)
    fd,temporary=tempfile.mkstemp(prefix='.cbodotnetup-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as output: output.write(data);output.flush();os.fsync(output.fileno())
        os.chmod(temporary,mode);os.replace(temporary,path)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def pairs(items):
    result={}
    for key,value in items:
        require(key not in result,'Duplicate JSON property');result[key]=value
    return result


def decode(raw):
    return json.loads(raw,object_pairs_hook=pairs)


def elf_target(data):
    """Read the CPU and actual loader without executing an untrusted executable."""
    require(len(data)>=64 and data[:7]==b'\x7fELF\x02\x01\x01','A little-endian ELF64 executable is required')
    machine=struct.unpack_from('<H',data,18)[0]
    arch={62:'x64',183:'arm64'}.get(machine)
    require(arch,'Unsupported ELF CPU architecture')
    offset=struct.unpack_from('<Q',data,32)[0]
    size,count=struct.unpack_from('<HH',data,54)
    require(size==56 and 0<count<=1024 and offset>=64 and offset+size*count<=len(data),'Invalid ELF program headers')
    loaders=[]
    for index in range(count):
        start=offset+index*size
        if struct.unpack_from('<I',data,start)[0]!=3:continue
        position=struct.unpack_from('<Q',data,start+8)[0]
        length=struct.unpack_from('<Q',data,start+32)[0]
        require(1<length<=4096 and position+length<=len(data),'Invalid ELF interpreter bounds')
        raw=data[position:position+length]
        require(raw[-1:]==b'\0' and b'\0' not in raw[:-1],'Invalid ELF interpreter string')
        loaders.append(raw[:-1].decode('ascii'))
    require(len(loaders)==1,'Exactly one dynamic ELF interpreter is required')
    loader=loaders[0]
    musl={'x64':'/lib/ld-musl-x86_64.so.1','arm64':'/lib/ld-musl-aarch64.so.1'}
    glibc={'x64':{'/lib64/ld-linux-x86-64.so.2','/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'},
           'arm64':{'/lib/ld-linux-aarch64.so.1','/lib64/ld-linux-aarch64.so.1','/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1'}}
    libc='musl' if loader==musl[arch] else 'glibc' if loader in glibc[arch] else None
    require(libc,'Unqualified ELF interpreter/libc')
    return dict(architecture=arch,libc=libc,rid='linux-'+('musl-' if libc=='musl' else '')+arch)


def os_release(text):
    result={}
    for line in text.splitlines():
        if not line or line.startswith('#') or '=' not in line:continue
        key,value=line.split('=',1)
        require(key not in result,'Duplicate operating system identity')
        if len(value)>=2 and value[0]==value[-1] and value[0] in ('"',"'"):value=value[1:-1]
        result[key]=value
    return result


def detect_host(machine,data,release,alpine_release='',apk_database=''):
    target=elf_target(data)
    require({'x86_64':'x64','aarch64':'arm64','arm64':'arm64'}.get(machine)==target['architecture'],
            'Running Python ELF CPU differs from the host architecture')
    release=os_release(release)
    if target['libc']=='musl':
        require(release.get('ID')=='alpine' and release.get('VERSION_ID')=='3.24.4' and alpine_release.strip()=='3.24.4',
                'Only native musl Alpine 3.24.4 is qualified')
        require(not {'gcompat','libc6-compat'} & {line[2:] for line in apk_database.splitlines() if line.startswith('P:')},
                'glibc compatibility packages are not admitted on native musl Alpine')
    else:require(release.get('ID')!='alpine','A glibc executable on Alpine is not a native musl host')
    return target


def host():
    return detect_host(platform.machine(),Path('/proc/self/exe').read_bytes(),Path('/etc/os-release').read_text(),
        Path('/etc/alpine-release').read_text() if Path('/etc/alpine-release').exists() else '',
        Path('/lib/apk/db/installed').read_text() if Path('/lib/apk/db/installed').exists() else '')


def gnu_stat():
    # Alpine packages GNU stat at /bin/stat; glibc systems commonly use /usr/bin/stat.
    # BusyBox also provides /bin/stat, so an executable path alone is insufficient.
    for path in ('/usr/bin/stat','/bin/stat'):
        if not (Path(path).is_file() and os.access(path,os.X_OK)):continue
        try:
            result=subprocess.run([path,'--version'],capture_output=True,text=True,timeout=10,
                env=dict(os.environ,LC_ALL='C'))
            if result.returncode==0 and re.match(r'^stat \(GNU coreutils\) [0-9]',result.stdout):return path
        except (OSError,subprocess.SubprocessError,UnicodeError):pass
    raise ValueError('Install GNU stat before bootstrapping on Alpine: apk add coreutils')


def prerequisites(target=None):
    if target is not None and target['libc']=='musl':
        gnu_stat()
    require(all(Path(path).is_file() and os.access(path,os.X_OK) for path in ('/usr/bin/gpg','/usr/bin/gpgv')),
            'Install GnuPG (gpg and gpgv) before bootstrapping')
    require(ssl.create_default_context().cert_store_stats()['x509_ca']>0,
            'Install the system CA certificates before bootstrapping')


def admit_tool(catalog,target):
    """Keep each libc feed isolated even when an offline catalog is supplied."""
    require((catalog['schemaVersion']==4 and catalog.get('libc')=='musl') if target['libc']=='musl'
            else catalog['schemaVersion'] in (2,3) and 'libc' not in catalog,
            'Signed catalog schema/libc differs from the native host')
    permitted={'linux-musl-x64','linux-musl-arm64'} if target['libc']=='musl' else {'linux-x64','linux-arm64'}
    require(all(t['rid'] in permitted for t in catalog['tools']),'Catalog mixes tool libc identities')
    candidates=[t for t in catalog['tools'] if t['rid']==target['rid'] and 'tool/'+t['version']+'/'+t['rid'] not in catalog['revoked']]
    require(candidates,'No qualified tool for this libc/architecture')
    require(all(isinstance(t.get('version'),str) and re.fullmatch(r'(0|[1-9][0-9]*)\.[0-9]+\.[0-9]+',t['version']) for t in candidates),
            'Invalid tool version')
    tool=max(candidates,key=lambda t:tuple(map(int,t['version'].split('.'))))
    require(catalog['schemaVersion']!=3 or tuple(map(int,tool['version'].split('.'))) >= (0,4,0),
            'A schema3 catalog requires a provider-aware installer; use the compatible v2 feed for older tools')
    require(catalog['schemaVersion']!=4 or tuple(map(int,tool['version'].split('.'))) >= (0,5,0),
            'A musl catalog requires a musl-aware installer')
    return candidates,tool


def allowed(url):
    uri=urllib.parse.urlsplit(url)
    require(uri.scheme=='https' and uri.hostname in {'github.com','dotnetdev.kr','objects.githubusercontent.com','release-assets.githubusercontent.com'}
            and not uri.username and not uri.password and uri.port in (None,443) and not uri.fragment,'Untrusted HTTPS origin or redirect')


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,message,headers,url):
        allowed(url);return super().redirect_request(request,fp,code,message,headers,url)


def download(url,maximum):
    allowed(url)
    with urllib.request.build_opener(Redirect()).open(urllib.request.Request(url,headers={'User-Agent':'cbodotnetup-bootstrap/0.5.1','Accept-Encoding':'identity'}),timeout=60) as incoming:
        data=incoming.read(maximum+1);encoding=incoming.headers.get('Content-Encoding','identity').lower()
    require(0<len(data)<=maximum,'Download exceeded its size bound')
    if encoding=='gzip':
        import gzip,io
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:data=compressed.read(maximum+1)
        require(0<len(data)<=maximum,'Decompressed download exceeded its size bound')
    else:require(encoding in ('','identity'),'Unsupported bootstrap content encoding')
    return data


def verify(data,signature,directory):
    home=directory/'gpg';home.mkdir(mode=0o700);(home/'public.asc').write_text(PUBLIC_KEY)
    keyring=home/'trusted.gpg'
    subprocess.run(['/usr/bin/gpg','--no-options','--batch','--no-autostart','--homedir',str(home),'--dearmor','--output',str(keyring),str(home/'public.asc')],check=True,capture_output=True,timeout=30)
    (directory/'catalog.json').write_bytes(data);(directory/'catalog.json.asc').write_bytes(signature)
    result=subprocess.run(['/usr/bin/gpgv','--homedir',str(home),'--keyring',str(keyring),'--status-fd','1',str(directory/'catalog.json.asc'),str(directory/'catalog.json')],check=True,capture_output=True,text=True,timeout=30)
    require(sum(s.startswith('[GNUPG:] VALIDSIG '+FINGERPRINT+' ') for s in result.stdout.splitlines())==1 and not any(s in result.stdout for s in ('REVKEYSIG','EXPKEYSIG','KEYEXPIRED','EXPSIG')),'Catalog signer is not the independently pinned live project identity')


def validate(value,now):
    require(type(value['schemaVersion']) is int and value['schemaVersion'] in (2,3,4) and value['kind']=='cbodotnetup-installation-catalog' and value['signingFingerprint']==FINGERPRINT
            and type(value['sequence']) is int and value['sequence']>0,'Invalid signed catalog identity')
    require(value['schemaVersion']!=4 or value.get('libc')=='musl','Schema4 requires the separate native musl identity')
    issued=datetime.fromisoformat(value['issuedAt'].replace('Z','+00:00'));expires=datetime.fromisoformat(value['expiresAt'].replace('Z','+00:00'))
    require(issued.utcoffset()==expires.utcoffset()==timedelta(0) and issued<=now+timedelta(minutes=5)
            and issued<expires and now<expires and expires-issued<=timedelta(days=31),'Catalog is expired, future-dated or has excessive validity')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog-file',type=Path,help='Offline project-signed catalog, with adjacent .asc')
    parser.add_argument('--binary-file',type=Path,help='Offline binary; must match the signed tool descriptor')
    parser.add_argument('--install-dir',type=Path,default=Path.home()/'.local/bin')
    args=parser.parse_args()
    require(platform.system()=='Linux' and os.geteuid()!=0,'Run as a regular Linux user without sudo')
    target=host();prerequisites(target);rid=target['rid']
    root=Path(os.environ.get('CBODOTNETUP_HOME',str(Path(os.environ.get('XDG_DATA_HOME',str(Path.home()/'.local/share')))/('cbodotnetup-musl' if target['libc']=='musl' else 'cbodotnetup'))))
    require(root.is_absolute() and root not in (Path('/'),Path.home()) and not any(str(root)==p or str(root).startswith(p+'/') for p in ('/opt','/usr','/etc','/var')),'Use a dedicated absolute user-local data root')
    require(not {'dotnetup','.dotnet'} & set(root.parts),'The official dotnet/dotnetup state roots are reserved')
    private(root)
    marker=root/'owner'
    if not marker.exists():
        require(not list(root.iterdir()),'Existing data directory is unrelated to cbodotnetup');atomic(marker,(OWNER+'\n').encode())
    require(ordinary(marker).read_text()==OWNER+'\n','Data root ownership differs')
    lock=ordinary(root/'operation.lock')
    with lock.open('a+b') as lease:
        fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
        # The old client's signed catalog and high-water remain available for tool rollback.
        cache_root=private(root/'cache');destination=private(args.install_dir.absolute())/'cbodotnetup';ordinary(destination)
        with tempfile.TemporaryDirectory(prefix='bootstrap-',dir=cache_root) as temporary:
            directory=Path(temporary)
            if args.catalog_file:
                file=ordinary(args.catalog_file);signature=ordinary(Path(str(file)+'.asc'))
                require(file.stat().st_size<=8*1024**2 and signature.stat().st_size<=64*1024,'Oversized local signed catalog')
                raw=file.read_bytes();sig=signature.read_bytes()
            else:
                endpoint=MUSL_CATALOG if target['libc']=='musl' else CATALOG
                raw=download(endpoint,8*1024**2);sig=download(endpoint+'.asc',64*1024)
            verify(raw,sig,directory);catalog=decode(raw);validate(catalog,datetime.now(timezone.utc));sha=hashlib.sha256(raw).hexdigest()
            candidates,tool=admit_tool(catalog,target)
            cache=private(cache_root/('v'+str(catalog['schemaVersion'])))
            high=cache/'high-water.json'
            if high.exists():
                previous=decode(ordinary(high).read_bytes())
                require(catalog['sequence']>previous['sequence'] or (catalog['sequence']==previous['sequence'] and sha==previous['sha256']),'Catalog rollback/conflict rejected')
            asset=tool['binary']
            require(re.fullmatch(r'(0|[1-9][0-9]*)\.[0-9]+\.[0-9]+',tool['version']) and asset['url']=='https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-v'+tool['version']+'/cbodotnetup-'+rid
                    and type(asset['size']) is int and 0<asset['size']<=128*1024**2 and re.fullmatch('[a-f0-9]{64}',asset['sha256']),'Invalid immutable tool descriptor')
            if args.binary_file:
                binary=ordinary(args.binary_file);require(binary.stat().st_size==asset['size'],'Offline binary has wrong size');data=binary.read_bytes()
            else:data=download(asset['url'],asset['size'])
            require(len(data)==asset['size'] and hashlib.sha256(data).hexdigest()==asset['sha256'],'Binary hash/size does not match the signed catalog')
            require(elf_target(data)==target,'Signed binary CPU/libc differs from the native host')
            notice=tool['notices']
            require(notice['url']==asset['url']+'.LICENSE.txt' and type(notice['size']) is int and 0<notice['size']<=8*1024**2 and re.fullmatch('[a-f0-9]{64}',notice['sha256']),'Unbound native runtime notices')
            if args.binary_file:
                notice_file=ordinary(Path(str(args.binary_file)+'.LICENSE.txt'));require(notice_file.stat().st_size==notice['size'],'Offline notices have wrong size');notice_data=notice_file.read_bytes()
            else:notice_data=download(notice['url'],notice['size'])
            require(len(notice_data)==notice['size'] and hashlib.sha256(notice_data).hexdigest()==notice['sha256'],'Native runtime notices differ from signed catalog')
            ownership_path=Path(str(destination)+'.ownership.json');ordinary(ownership_path)
            if destination.exists():
                existing=destination.read_bytes();actual=hashlib.sha256(existing).hexdigest()
                require(ownership_path.exists(),'Refusing to replace an unrelated executable')
                require(elf_target(existing)==target,'Refusing to replace an executable belonging to another CPU/libc')
                owned=decode(ownership_path.read_bytes())
                # Recover an interrupted self-update only when the actual bytes are an admitted signed tool.
                known={t['binary']['sha256'] for t in candidates}
                require(owned['owner']==OWNER and owned['path']==str(destination) and (actual==owned['sha256'] or actual in known),'Existing executable ownership or bytes differ')
            notice_destination=ordinary(Path(str(destination)+'.LICENSE.txt'))
            if notice_destination.exists():
                require(ownership_path.exists() and (hashlib.sha256(notice_destination.read_bytes()).hexdigest()==decode(ownership_path.read_bytes())['noticesSha256']
                    or hashlib.sha256(notice_destination.read_bytes()).hexdigest() in {t['notices']['sha256'] for t in candidates}),'Refusing to replace unrelated notices')
            atomic(notice_destination,notice_data)
            atomic(destination,data,0o755)
            atomic(ownership_path,json.dumps(dict(owner=OWNER,path=str(destination),version=tool['version'],sha256=asset['sha256'],noticesSha256=notice['sha256'],previousVersion=None,previousSha256=None)).encode())
            atomic(high,json.dumps(dict(sequence=catalog['sequence'],sha256=sha)).encode())
            atomic(cache/'catalog.json',raw);atomic(cache/'catalog.json.asc',sig)
    print('Installed verified cbodotnetup '+tool['version']+' at '+str(destination))
    print('Run '+str(destination)+' --help; add '+str(destination.parent)+' to PATH explicitly if desired.')


if __name__=='__main__':
    try:main()
    except Exception as error:raise SystemExit('cbodotnetup bootstrap: '+str(error))
