#!/usr/bin/env python3
"""SDK-free bootstrap. Dependencies: Python3, GnuPG and an ordinary Linux user."""
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
import subprocess
import tempfile
import urllib.parse
import urllib.request

FINGERPRINT='D7D154B4B33C19A82B95B13688135410ACD9C0EA'
CATALOG='https://dotnetdev.kr/cbodotnet/cbodotnetup/catalog.json'
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


def allowed(url):
    uri=urllib.parse.urlsplit(url)
    require(uri.scheme=='https' and uri.hostname in {'github.com','dotnetdev.kr','objects.githubusercontent.com','release-assets.githubusercontent.com'}
            and not uri.username and not uri.password and uri.port in (None,443) and not uri.fragment,'Untrusted HTTPS origin or redirect')


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,message,headers,url):
        allowed(url);return super().redirect_request(request,fp,code,message,headers,url)


def download(url,maximum):
    allowed(url)
    with urllib.request.build_opener(Redirect()).open(urllib.request.Request(url,headers={'User-Agent':'cbodotnetup-bootstrap/0.1.0'}),timeout=60) as incoming:
        data=incoming.read(maximum+1)
    require(0<len(data)<=maximum,'Download exceeded its size bound');return data


def verify(data,signature,directory):
    home=directory/'gpg';home.mkdir(mode=0o700);(home/'public.asc').write_text(PUBLIC_KEY)
    common=['/usr/bin/gpg','--no-options','--batch','--homedir',str(home)]
    subprocess.run(common+['--import',str(home/'public.asc')],check=True,capture_output=True,timeout=30)
    (directory/'catalog.json').write_bytes(data);(directory/'catalog.json.asc').write_bytes(signature)
    result=subprocess.run(common+['--no-auto-key-retrieve','--status-fd','1','--verify',str(directory/'catalog.json.asc'),str(directory/'catalog.json')],check=True,capture_output=True,text=True,timeout=30)
    require(sum(s.startswith('[GNUPG:] VALIDSIG '+FINGERPRINT+' ') for s in result.stdout.splitlines())==1,'Catalog signer is not the independently pinned project identity')


def validate(value,now):
    require(value['schemaVersion']==1 and value['kind']=='cbodotnetup-installation-catalog' and value['signingFingerprint']==FINGERPRINT
            and type(value['sequence']) is int and value['sequence']>0,'Invalid signed catalog identity')
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
    rid={'x86_64':'linux-x64','aarch64':'linux-arm64','arm64':'linux-arm64'}.get(platform.machine());require(rid,'Unsupported architecture')
    root=Path(os.environ.get('CBODOTNETUP_HOME',str(Path(os.environ.get('XDG_DATA_HOME',str(Path.home()/'.local/share')))/'cbodotnetup')))
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
        cache=private(root/'cache');destination=private(args.install_dir.absolute())/'cbodotnetup';ordinary(destination)
        with tempfile.TemporaryDirectory(prefix='bootstrap-',dir=cache) as temporary:
            directory=Path(temporary)
            if args.catalog_file:
                file=ordinary(args.catalog_file);signature=ordinary(Path(str(file)+'.asc'))
                require(file.stat().st_size<=8*1024**2 and signature.stat().st_size<=64*1024,'Oversized local signed catalog')
                raw=file.read_bytes();sig=signature.read_bytes()
            else:raw=download(CATALOG,8*1024**2);sig=download(CATALOG+'.asc',64*1024)
            verify(raw,sig,directory);catalog=decode(raw);validate(catalog,datetime.now(timezone.utc));sha=hashlib.sha256(raw).hexdigest()
            high=cache/'high-water.json'
            if high.exists():
                previous=decode(ordinary(high).read_bytes())
                require(catalog['sequence']>previous['sequence'] or (catalog['sequence']==previous['sequence'] and sha==previous['sha256']),'Catalog rollback/conflict rejected')
            candidates=[t for t in catalog['tools'] if t['rid']==rid and 'tool/'+t['version']+'/'+rid not in catalog['revoked']]
            require(candidates,'No qualified tool for this architecture')
            tool=max(candidates,key=lambda t:tuple(map(int,t['version'].split('.'))));asset=tool['binary']
            require(re.fullmatch(r'(0|[1-9][0-9]*)\.[0-9]+\.[0-9]+',tool['version']) and asset['url']=='https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-v'+tool['version']+'/cbodotnetup-'+rid
                    and type(asset['size']) is int and 0<asset['size']<=128*1024**2 and re.fullmatch('[a-f0-9]{64}',asset['sha256']),'Invalid immutable tool descriptor')
            if args.binary_file:
                binary=ordinary(args.binary_file);require(binary.stat().st_size==asset['size'],'Offline binary has wrong size');data=binary.read_bytes()
            else:data=download(asset['url'],asset['size'])
            require(len(data)==asset['size'] and hashlib.sha256(data).hexdigest()==asset['sha256'],'Binary hash/size does not match the signed catalog')
            ownership_path=Path(str(destination)+'.ownership.json');ordinary(ownership_path)
            if destination.exists():
                actual=hashlib.sha256(destination.read_bytes()).hexdigest()
                require(ownership_path.exists(),'Refusing to replace an unrelated executable')
                owned=decode(ownership_path.read_bytes())
                # Recover an interrupted self-update only when the actual bytes are an admitted signed tool.
                known={t['binary']['sha256'] for t in candidates}
                require(owned['owner']==OWNER and owned['path']==str(destination) and (actual==owned['sha256'] or actual in known),'Existing executable ownership or bytes differ')
            atomic(destination,data,0o755)
            atomic(ownership_path,json.dumps(dict(owner=OWNER,path=str(destination),version=tool['version'],sha256=asset['sha256'],previousVersion=None,previousSha256=None)).encode())
            atomic(high,json.dumps(dict(sequence=catalog['sequence'],sha256=sha)).encode())
            atomic(cache/'catalog.json',raw);atomic(cache/'catalog.json.asc',sig)
    print('Installed verified cbodotnetup '+tool['version']+' at '+str(destination))
    print('Run '+str(destination)+' --help; add '+str(destination.parent)+' to PATH explicitly if desired.')


if __name__=='__main__':
    try:main()
    except Exception as error:raise SystemExit('cbodotnetup bootstrap: '+str(error))
