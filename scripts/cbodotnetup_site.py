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
from cbodotnetup_matrix import validate_additional_sdk_qualifications

ROOT=Path(__file__).resolve().parents[1]

CATALOG_FIELDS={'schemaVersion','kind','sequence','issuedAt','expiresAt','signingFingerprint',
                'revoked','sdks','tools','channels'}


def paired_catalogs(catalog,legacy,compatibility=None):
    if catalog['schemaVersion']==3:
        from cbodotnetup_providers import validate_provider_catalog
        validate_provider_catalog(catalog,compatibility)
        require(set(catalog)==CATALOG_FIELDS|{'compatibilityCatalog','providers','providerBindings'}
                and set(compatibility)==CATALOG_FIELDS,'Provider-aware catalog shape differs')
        require(catalog['compatibilityCatalog']['url']==f'https://github.com/dotnetdev-kr/cbodotnet/releases/download/cbodotnetup-catalog-{catalog["sequence"]}/catalog-v2.json',
                'Compatible modern feed URL differs from its signed release')
        from downstream_release import encoded
        raw=encoded(compatibility)
        require(catalog['compatibilityCatalog']['size']==len(raw)
                and catalog['compatibilityCatalog']['sha256']==hashlib.sha256(raw).hexdigest(),
                'Signed modern projection differs from the provider-aware catalog')
        shared=CATALOG_FIELDS-{'schemaVersion','sdks','channels'}
        require(all(catalog[key]==compatibility[key] for key in shared),
                'Provider-aware and compatible catalog trust or lifetime differs')
        catalog=compatibility
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
    triple='compatibilityCatalogSha256' in status or 'compatibilityCatalogSequence' in status
    musl='muslCatalogSha256' in status or 'muslCatalogSequence' in status
    require(not dual or {'legacyCatalogSha256','legacyCatalogSequence'}<=set(status),'Incomplete paired installer feed identity')
    require(not triple or dual and {'compatibilityCatalogSha256','compatibilityCatalogSequence'}<=set(status),
            'Incomplete provider-aware installer feed identity')
    require(not musl or triple and {'muslCatalogSha256','muslCatalogSequence'}<=set(status),
            'Incomplete separate native musl installer feed identity')
    assets={a['name']:a for a in release['assets']};raws={}
    require(len(assets)==len(release['assets']),'Duplicate installer metadata asset')
    names=('catalog.json','catalog.json.asc','freeze.json','freeze.json.asc','get-cbodotnetup.py')
    if dual:names+=('catalog-v1.json','catalog-v1.json.asc')
    if triple:names+=('catalog-v2.json','catalog-v2.json.asc')
    if musl:names+=('catalog-musl.json','catalog-musl.json.asc','catalog-musl-baseline.json','catalog-musl-baseline.json.asc')
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
        for name in ('catalog.json','freeze.json')+(('catalog-v1.json',) if dual else ())+(('catalog-v2.json',) if triple else ())+(('catalog-musl.json','catalog-musl-baseline.json') if musl else ()):
            verify_report_signature(directory/name,directory/(name+'.asc'),key,load_status(),'.github/workflows/distribution-release.yml')
    catalog=json.loads(raws['catalog.json']);freeze=json.loads(raws['freeze.json'])
    require(catalog['schemaVersion']==(3 if triple else 2 if dual else 1),'Activated installer catalog schema is unsupported')
    require(hashlib.sha256(raws['catalog.json']).hexdigest()==status['catalogSha256'] and catalog['sequence']==status['catalogSequence'],'Activated installer catalog changed')
    legacy=None
    compatibility=None
    if triple:
        compatibility=json.loads(raws['catalog-v2.json'])
        require(hashlib.sha256(raws['catalog-v2.json']).hexdigest()==status['compatibilityCatalogSha256']
                and compatibility['sequence']==status['compatibilityCatalogSequence']==status['catalogSequence'],
                'Activated compatible modern catalog changed')
    if dual:
        legacy=json.loads(raws['catalog-v1.json']);paired_catalogs(catalog,legacy,compatibility)
        require(hashlib.sha256(raws['catalog-v1.json']).hexdigest()==status['legacyCatalogSha256']
                and legacy['sequence']==status['legacyCatalogSequence']==status['catalogSequence'],'Activated legacy installer catalog changed')
    musl_catalog=None
    if musl:
        from cbodotnetup_musl import validate_catalog,validate_qualifications
        musl_catalog=json.loads(raws['catalog-musl.json'])
        validate_catalog(musl_catalog)
        require(hashlib.sha256(raws['catalog-musl.json']).hexdigest()==status['muslCatalogSha256']
                and musl_catalog['sequence']==status['muslCatalogSequence']==status['catalogSequence'],
                'Activated native musl catalog changed')
        require(all(musl_catalog[key]==catalog[key] for key in ('kind','sequence','issuedAt','expiresAt','signingFingerprint'))
                and set(catalog['revoked'])<=set(musl_catalog['revoked']),
                'Separate musl and glibc catalog trust, lifetime or inherited revocations differ')
        baseline=json.loads(raws['catalog-musl-baseline.json']);validate_catalog(baseline)
        require(all(baseline[key]==musl_catalog[key] for key in CATALOG_FIELDS-{'sequence','tools','schemaVersion'})
                and baseline['sequence']<musl_catalog['sequence'] and all(t['version']=='0.5.0' for t in baseline['tools'])
                and len(baseline['tools'])==2,'Actual musl baseline catalog differs from the signed final admission')
    indexed={a['path']:a for a in freeze['files']}
    require(len(indexed)==len(freeze['files']),'Duplicate frozen bootstrap input')
    for name in ('catalog.json','catalog.json.asc','get-cbodotnetup.py')+(('catalog-v1.json','catalog-v1.json.asc') if dual else ())+(('catalog-v2.json','catalog-v2.json.asc') if triple else ())+(('catalog-musl.json','catalog-musl.json.asc','catalog-musl-baseline.json','catalog-musl-baseline.json.asc') if musl else ()):
        require(name in indexed and indexed[name]['size']==len(raws[name]) and indexed[name]['sha256']==hashlib.sha256(raws[name]).hexdigest(),'Signed frozen bootstrap inventory differs')
    public=status['publicNativeVerification']
    glibc_public=[r for r in public if r['variant']!='alpine-3.24']
    musl_public=[r for r in public if r['variant']=='alpine-3.24']
    require(len(public)==(10 if musl else 8) and (musl or not musl_public),'Unexpected public installer qualification matrix')
    targets={(r['variant'],r['architecture']) for r in glibc_public}
    require(len(glibc_public)==8 and targets=={(v,a) for v in ('ubuntu-24.04','debian-13','fedora-45','rocky-9.8') for a in ('x64','aarch64')}
            and all(r['observation']['status']=='passed' and r['observation']['bootstrapBinarySource']=='public-https'
                and r['observation']['catalogSha256']==status['catalogSha256'] for r in glibc_public),'All eight public installer native proofs are required')
    if dual:
        require(all(r['observation'].get('migration',{}).get('status')=='passed'
                and r['observation']['migration'].get('protocol')=='actual-0.1.0-self-update-rollback-reupgrade'
                and r['observation']['migration'].get('legacyCatalogSha256')==status['legacyCatalogSha256']
                for r in glibc_public),'All eight actual old-client migration proofs are required')
    observations=[r['observation'] for r in glibc_public]
    validate_additional_sdk_qualifications(catalog,observations,tool_version=status['version'],compatibility_catalog=compatibility)
    if triple:
        from cbodotnetup_legacy import validate_legacy_qualifications
        validate_legacy_qualifications(catalog,observations,tool_version=status['version'],compatibility_catalog=compatibility)
    if any(s['sdkVersion']!='10.0.403' for s in catalog['sdks']):
        candidate=[r for r in status.get('nativeQualification',[]) if r['variant']!='alpine-3.24']
        require(len(candidate)==8 and {(r['variant'],r['architecture']) for r in candidate}==targets
                and all(r['observation']['status']=='passed'
                    and r['observation']['bootstrapBinarySource']=='protected-frozen-candidate'
                    and r['observation']['catalogSha256']==status['catalogSha256'] for r in candidate),
                'All eight candidate reports are required for additional SDK admission')
        candidate_observations=[r['observation'] for r in candidate]
        validate_additional_sdk_qualifications(catalog,candidate_observations,tool_version=status['version'],compatibility_catalog=compatibility)
        if triple:
            validate_legacy_qualifications(catalog,candidate_observations,tool_version=status['version'],compatibility_catalog=compatibility)
    if musl:
        musl_candidate=[r for r in status.get('nativeQualification',[]) if r['variant']=='alpine-3.24']
        for phase in (musl_candidate,musl_public):
            require(len(phase)==2 and {(r['variant'],r['architecture']) for r in phase}=={('alpine-3.24',a) for a in ('x64','aarch64')}
                    and all(r['observation'].get('variant')==r['variant'] and r['observation'].get('architecture')==r['architecture'] for r in phase),
                    'Both matching native musl installer CPU proof identities are required')
        bindings=dict(catalog_sha256=status['muslCatalogSha256'],bootstrap_sha256=hashlib.sha256(raws['get-cbodotnetup.py']).hexdigest(),
            freeze_sha256=hashlib.sha256(raws['freeze.json']).hexdigest(),version=status['version'])
        validate_qualifications(musl_catalog,[r['observation'] for r in musl_candidate],public=False,**bindings)
        validate_qualifications(musl_catalog,[r['observation'] for r in musl_public],public=True,**bindings)
    now=datetime.now(timezone.utc)
    fresh=fresh_catalog(catalog,now)
    if legacy is not None:fresh=fresh_catalog(legacy,now) and fresh
    if compatibility is not None:fresh=fresh_catalog(compatibility,now) and fresh
    if musl_catalog is not None:fresh=fresh_catalog(musl_catalog,now) and fresh
    if not fresh:return '<h3>cbodotnetup</h3><p>The signed installer catalog expired. A fresh verified catalog is required before installation.</p>'
    destination=Path(output)/'cbodotnetup';destination.mkdir(parents=True,exist_ok=True)
    (destination/'get-cbodotnetup.py').write_bytes(raws['get-cbodotnetup.py'])
    for suffix in ('','.asc'):
        (destination/('catalog.json'+suffix)).write_bytes(raws[('catalog-v1.json' if dual else 'catalog.json')+suffix])
    catalog_link='cbodotnetup/catalog.json'
    if dual:
        current=destination/'v2';current.mkdir(exist_ok=True)
        for suffix in ('','.asc'):(current/('catalog.json'+suffix)).write_bytes(raws[('catalog-v2.json' if triple else 'catalog.json')+suffix])
        catalog_link='cbodotnetup/v2/catalog.json'
    if triple:
        current=destination/'v3';current.mkdir(exist_ok=True)
        for suffix in ('','.asc'):(current/('catalog.json'+suffix)).write_bytes(raws['catalog.json'+suffix])
        catalog_link='cbodotnetup/v3/catalog.json'
    if musl:
        current=destination/'v4';current.mkdir(exist_ok=True)
        for suffix in ('','.asc'):(current/('catalog.json'+suffix)).write_bytes(raws['catalog-musl.json'+suffix])
    versions=sorted({s['sdkVersion'] for s in catalog['sdks']},key=lambda v:tuple(map(int,v.split('.'))),reverse=True)
    sdk_list=', '.join('<code>'+html.escape(v)+'</code>' for v in versions)
    return ('<h3>cbodotnetup '+html.escape(status['version'])+'</h3><p>Verified per-user SDK manager for Linux glibc x64/AArch64 on Ubuntu24.04, Debian13, Fedora45 and Rocky9.8. '
        'Community-qualified glibc SDKs: '+sdk_list+'. Python3, GnuPG and system CA certificates are required; no installed .NET SDK is needed. '
        +('Native musl Alpine3.24.4 x64/AArch64 separately admits SDK10.0.403 revision1 and also requires GNU stat from <code>coreutils</code>; glibc compatibility packages are not supported. '
          '<a href="cbodotnetup/v4/catalog.json">signed musl catalog</a> &middot; <a href="cbodotnetup/v4/catalog.json.asc">musl signature</a>. ' if musl else '')+
        ('SDK5/Core3 require explicit <code>--with-legacy-providers</code> consent for private compatibility libraries and retain their upstream end-of-life status. ' if triple else '')+
        '<a href="https://github.com/dotnetdev-kr/cbodotnet/blob/main/docs/cbodotnetup.md">Versions, lifecycle, bootstrap and usage instructions</a>. '
        'Review the bootstrap and independently verify the project signing identity before running it. '
        '<a href="cbodotnetup/get-cbodotnetup.py">Download bootstrap</a> &middot; '
        '<a href="'+catalog_link+'">signed catalog</a> &middot; <a href="'+catalog_link+'.asc">signature</a>.</p>')
