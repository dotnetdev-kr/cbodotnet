"""Expose the installer feed only after authenticated public native qualification."""
from datetime import datetime, timezone
import hashlib
import html
import json
from pathlib import Path
import re
import subprocess
import tempfile

from downstream_release import require,load_status,verify_report_signature
from release_catalog import get_bytes

ROOT=Path(__file__).resolve().parents[1]


def prepare(output,status=None):
    path=ROOT/'releases/cbodotnetup-status.json'
    if status is None and not path.exists():return ''
    status=status or json.loads(path.read_bytes())
    require(status['schemaVersion']==1 and status['kind']=='cbodotnetup-availability' and status['status']=='published-postverified','Installer feed is not publicly post-verified')
    release=status['catalogRelease'];tag=release['tag']
    require(re.fullmatch(r'cbodotnetup-catalog-[1-9][0-9]*',tag) and int(tag.removeprefix('cbodotnetup-catalog-'))==status['catalogSequence'],'Installer feed has another immutable identity')
    assets={a['name']:a for a in release['assets']};raws={}
    for name in ('catalog.json','catalog.json.asc','freeze.json','freeze.json.asc','get-cbodotnetup.py'):
        asset=assets[name];url='https://github.com/dotnetdev-kr/cbodotnet/releases/download/'+tag+'/'+name
        require(asset['url']==url and 0<asset['size']<=8*1024**2,'Untrusted public installer metadata')
        raw=get_bytes(url,asset['size']);require(len(raw)==asset['size'] and hashlib.sha256(raw).hexdigest()==asset['sha256'],'Installer metadata differs from activation')
        raws[name]=raw
    with tempfile.TemporaryDirectory(prefix='cbodotnetup-site-') as temporary:
        directory=Path(temporary);key=directory/'trusted.gpg'
        subprocess.run(['gpg','--batch','--yes','--dearmor','--output',str(key),str(ROOT/'releases/downstream-signing-key.asc')],check=True,capture_output=True)
        for name,raw in raws.items():(directory/name).write_bytes(raw)
        for name in ('catalog.json','freeze.json'):verify_report_signature(directory/name,directory/(name+'.asc'),key,load_status(),'.github/workflows/distribution-release.yml')
    catalog=json.loads(raws['catalog.json']);freeze=json.loads(raws['freeze.json'])
    require(hashlib.sha256(raws['catalog.json']).hexdigest()==status['catalogSha256'] and catalog['sequence']==status['catalogSequence'],'Activated installer catalog changed')
    indexed={a['path']:a for a in freeze['files']}
    for name in ('catalog.json','catalog.json.asc','get-cbodotnetup.py'):
        require(indexed[name]['size']==len(raws[name]) and indexed[name]['sha256']==hashlib.sha256(raws[name]).hexdigest(),'Signed frozen bootstrap inventory differs')
    targets={(r['variant'],r['architecture']) for r in status['publicNativeVerification']}
    require(len(status['publicNativeVerification'])==8 and targets=={(v,a) for v in ('ubuntu-24.04','debian-13','fedora-45','rocky-9.8') for a in ('x64','aarch64')}
            and all(r['observation']['status']=='passed' and r['observation']['bootstrapBinarySource']=='public-https'
                and r['observation']['catalogSha256']==status['catalogSha256'] for r in status['publicNativeVerification']),'All eight public installer native proofs are required')
    now=datetime.now(timezone.utc);issued=datetime.fromisoformat(catalog['issuedAt'].replace('Z','+00:00'));expires=datetime.fromisoformat(catalog['expiresAt'].replace('Z','+00:00'))
    require(issued<expires and (expires-issued).days<=31,'Invalid installer catalog lifetime')
    if now>=expires:return '<h3>cbodotnetup</h3><p>The signed installer catalog expired. A fresh verified catalog is required before installation.</p>'
    destination=Path(output)/'cbodotnetup';destination.mkdir(parents=True,exist_ok=True)
    for name in ('catalog.json','catalog.json.asc','get-cbodotnetup.py'):(destination/name).write_bytes(raws[name])
    return ('<h3>cbodotnetup '+html.escape(status['version'])+'</h3><p>Verified per-user SDK manager for Linux glibc x64/AArch64 on Ubuntu24.04, Debian13, Fedora45 and Rocky9.8. '
        'Start with SDK10.0.403. Python3 and GnuPG are required; no installed .NET SDK is needed. '
        '<a href="https://github.com/dotnetdev-kr/cbodotnet/blob/main/docs/cbodotnetup.md">Bootstrap, trust and usage instructions</a>. '
        'Review the bootstrap and independently verify the project signing identity before running it. '
        '<a href="cbodotnetup/get-cbodotnetup.py">Download bootstrap</a> &middot; '
        '<a href="cbodotnetup/catalog.json">signed catalog</a> &middot; <a href="cbodotnetup/catalog.json.asc">signature</a>.</p>')
