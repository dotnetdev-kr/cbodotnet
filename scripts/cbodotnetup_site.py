"""Expose the installer feed only after authenticated public native qualification."""
from datetime import datetime, timedelta, timezone
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

CATALOG_FIELDS={'schemaVersion','kind','sequence','issuedAt','expiresAt','signingFingerprint',
                'revoked','sdks','tools','channels'}


def paired_catalogs(catalog,legacy):
    require(set(catalog)==set(legacy)==CATALOG_FIELDS and catalog['schemaVersion']==2
            and legacy['schemaVersion']==1,'Installer feed generations are not compatible')
    shared=CATALOG_FIELDS-{'schemaVersion','sdks','channels'}
    require(all(catalog[k]==legacy[k] for k in shared),'Paired installer feed trust or lifetime differs')
    require(legacy['channels']=={'10.0':'10.0.403-r2'} and len(legacy['sdks'])==2,
            'The legacy installer feed must preserve the qualified SDK10 revision2')
    require({sdk['rid'] for sdk in legacy['sdks']}=={'linux-x64','linux-arm64'},'Legacy feed CPU matrix differs')
    for sdk in legacy['sdks']:
        arch={'linux-x64':'x64','linux-arm64':'aarch64'}[sdk['rid']]
        expected='https://github.com/dotnetdev-kr/cbodotnet/releases/download/distribution-archive-sdk-10.0.403-r2/cbodotnet-sdk-10.0.403-linux-'+arch+'-branded-r2.tar.gz'
        require(sdk['sdkVersion']=='10.0.403' and sdk['revision']==2 and sdk['archive']['url']==expected,
                'The legacy installer SDK identity is not v1 compatible')


def fresh_catalog(value,now):
    issued=datetime.fromisoformat(value['issuedAt'].replace('Z','+00:00'))
    expires=datetime.fromisoformat(value['expiresAt'].replace('Z','+00:00'))
    require(issued.utcoffset()==expires.utcoffset()==timedelta(0) and issued<=now+timedelta(minutes=5)
            and issued<expires and expires-issued<=timedelta(days=31),'Invalid installer catalog lifetime')
    return now<expires


def prepare(output,status=None):
    path=ROOT/'releases/cbodotnetup-status.json'
    if status is None and not path.exists():return ''
    status=status or json.loads(path.read_bytes())
    require(status['schemaVersion']==1 and status['kind']=='cbodotnetup-availability' and status['status']=='published-postverified','Installer feed is not publicly post-verified')
    release=status['catalogRelease'];tag=release['tag']
    require(re.fullmatch(r'cbodotnetup-catalog-[1-9][0-9]*',tag) and int(tag.removeprefix('cbodotnetup-catalog-'))==status['catalogSequence'],'Installer feed has another immutable identity')
    dual='legacyCatalogSha256' in status or 'legacyCatalogSequence' in status
    require(not dual or {'legacyCatalogSha256','legacyCatalogSequence'}<=set(status),'Incomplete paired installer feed identity')
    assets={a['name']:a for a in release['assets']};raws={}
    require(len(assets)==len(release['assets']),'Duplicate installer metadata asset')
    names=('catalog.json','catalog.json.asc','freeze.json','freeze.json.asc','get-cbodotnetup.py')
    if dual:names+=('catalog-v1.json','catalog-v1.json.asc')
    for name in names:
        require(name in assets,'Installer metadata asset is missing: '+name)
        asset=assets[name];url='https://github.com/dotnetdev-kr/cbodotnet/releases/download/'+tag+'/'+name
        require(asset['url']==url and 0<asset['size']<=8*1024**2,'Untrusted public installer metadata')
        raw=get_bytes(url,asset['size']);require(len(raw)==asset['size'] and hashlib.sha256(raw).hexdigest()==asset['sha256'],'Installer metadata differs from activation')
        raws[name]=raw
    with tempfile.TemporaryDirectory(prefix='cbodotnetup-site-') as temporary:
        directory=Path(temporary);key=directory/'trusted.gpg'
        subprocess.run(['gpg','--batch','--yes','--dearmor','--output',str(key),str(ROOT/'releases/downstream-signing-key.asc')],check=True,capture_output=True)
        for name,raw in raws.items():(directory/name).write_bytes(raw)
        for name in ('catalog.json','freeze.json')+(('catalog-v1.json',) if dual else ()):
            verify_report_signature(directory/name,directory/(name+'.asc'),key,load_status(),'.github/workflows/distribution-release.yml')
    catalog=json.loads(raws['catalog.json']);freeze=json.loads(raws['freeze.json'])
    require(catalog['schemaVersion']==(2 if dual else 1),'Activated installer catalog schema is unsupported')
    require(hashlib.sha256(raws['catalog.json']).hexdigest()==status['catalogSha256'] and catalog['sequence']==status['catalogSequence'],'Activated installer catalog changed')
    legacy=None
    if dual:
        legacy=json.loads(raws['catalog-v1.json']);paired_catalogs(catalog,legacy)
        require(hashlib.sha256(raws['catalog-v1.json']).hexdigest()==status['legacyCatalogSha256']
                and legacy['sequence']==status['legacyCatalogSequence']==status['catalogSequence'],'Activated legacy installer catalog changed')
    indexed={a['path']:a for a in freeze['files']}
    require(len(indexed)==len(freeze['files']),'Duplicate frozen bootstrap input')
    for name in ('catalog.json','catalog.json.asc','get-cbodotnetup.py')+(('catalog-v1.json','catalog-v1.json.asc') if dual else ()):
        require(name in indexed and indexed[name]['size']==len(raws[name]) and indexed[name]['sha256']==hashlib.sha256(raws[name]).hexdigest(),'Signed frozen bootstrap inventory differs')
    targets={(r['variant'],r['architecture']) for r in status['publicNativeVerification']}
    require(len(status['publicNativeVerification'])==8 and targets=={(v,a) for v in ('ubuntu-24.04','debian-13','fedora-45','rocky-9.8') for a in ('x64','aarch64')}
            and all(r['observation']['status']=='passed' and r['observation']['bootstrapBinarySource']=='public-https'
                and r['observation']['catalogSha256']==status['catalogSha256'] for r in status['publicNativeVerification']),'All eight public installer native proofs are required')
    if dual:
        require(all(r['observation'].get('migration',{}).get('status')=='passed'
                and r['observation']['migration'].get('protocol')=='actual-0.1.0-self-update-rollback-reupgrade'
                and r['observation']['migration'].get('legacyCatalogSha256')==status['legacyCatalogSha256']
                for r in status['publicNativeVerification']),'All eight actual old-client migration proofs are required')
    now=datetime.now(timezone.utc)
    fresh=fresh_catalog(catalog,now)
    if legacy is not None:fresh=fresh_catalog(legacy,now) and fresh
    if not fresh:return '<h3>cbodotnetup</h3><p>The signed installer catalog expired. A fresh verified catalog is required before installation.</p>'
    destination=Path(output)/'cbodotnetup';destination.mkdir(parents=True,exist_ok=True)
    (destination/'get-cbodotnetup.py').write_bytes(raws['get-cbodotnetup.py'])
    for suffix in ('','.asc'):
        (destination/('catalog.json'+suffix)).write_bytes(raws[('catalog-v1.json' if dual else 'catalog.json')+suffix])
    catalog_link='cbodotnetup/catalog.json'
    if dual:
        current=destination/'v2';current.mkdir(exist_ok=True)
        for suffix in ('','.asc'):(current/('catalog.json'+suffix)).write_bytes(raws['catalog.json'+suffix])
        catalog_link='cbodotnetup/v2/catalog.json'
    return ('<h3>cbodotnetup '+html.escape(status['version'])+'</h3><p>Verified per-user SDK manager for Linux glibc x64/AArch64 on Ubuntu24.04, Debian13, Fedora45 and Rocky9.8. '
        'Start with SDK10.0.403. Python3 and GnuPG are required; no installed .NET SDK is needed. '
        '<a href="https://github.com/dotnetdev-kr/cbodotnet/blob/main/docs/cbodotnetup.md">Bootstrap, trust and usage instructions</a>. '
        'Review the bootstrap and independently verify the project signing identity before running it. '
        '<a href="cbodotnetup/get-cbodotnetup.py">Download bootstrap</a> &middot; '
        '<a href="'+catalog_link+'">signed catalog</a> &middot; <a href="'+catalog_link+'.asc">signature</a>.</p>')
