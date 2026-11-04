"""Authenticate small signed archive metadata before rendering consumer links."""
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request

from consumer_archive import (ARCHITECTURES,MANIFEST,SIGNATURE,REPOSITORY,ROOT,WORKFLOW,encoded,load_contract,load_status,
    ordinary_file,require,verify_report_signature)
from consumer_archive_release import release_tag,validate_bundle,validate_native_report,workflow_identity

STATUS=ROOT/'releases/archive-status.json'


def load_archive_status(path=None):
    path=Path(path) if path is not None else STATUS
    result=json.loads(ordinary_file(path).read_bytes()) if path.exists() else dict(schemaVersion=1,repository=REPOSITORY,publications=[])
    require(result.get('schemaVersion')==1 and result.get('repository')==REPOSITORY and isinstance(result.get('publications'),list),
        'Invalid consumer archive availability record')
    return result


def fetch_bytes(url,maximum):
    require(url.startswith(f'https://github.com/{REPOSITORY}/releases/download/distribution-archive-sdk-'),
        'Untrusted consumer release metadata URL')
    with urllib.request.urlopen(url,timeout=60) as incoming:data=incoming.read(maximum+1)
    require(0<len(data)<=maximum,'Consumer release metadata exceeds its bound')
    return data


def data_descriptor(name,data):
    return dict(name=name,size=len(data),sha256=hashlib.sha256(data).hexdigest())


def authenticate_receipt(receipt,*,policy=None,keyring=None,fetch=None,historical=False):
    """Download only metadata; signed archive/companion digests bind large assets."""
    policy=policy if policy is not None else load_status();fetch=fetch or fetch_bytes
    require(receipt.get('schemaVersion')==1 and receipt.get('kind')=='consumer-archive-publication-receipt'
        and receipt.get('status') in {'published-public-bytes-verified','published-postverified'},'Invalid consumer release receipt')
    common=receipt['identity'];tag=release_tag(common['sdkVersion'],common['packageRevision'])
    base=f'https://github.com/{REPOSITORY}/releases/download/{tag}/'
    require(common.get('channel')=='archive' and receipt['tag']==tag and receipt['manifestUrl']==base+MANIFEST
        and receipt['signatureUrl']==base+SIGNATURE and receipt['releaseUrl']==f'https://github.com/{REPOSITORY}/releases/tag/{tag}',
        'Consumer receipt URL or immutable identity differs')
    entries=receipt['assets'];names=[item.get('name','') for item in entries]
    require(len(set(names))==len(names) and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',name) for name in names),
        'Unsafe or duplicate consumer receipt asset')
    indexed={item['name']:item for item in entries}
    for item in entries:
        require(item.get('url')==base+item['name'] and type(item.get('size')) is int and item['size']>0
            and re.fullmatch(r'[a-f0-9]{64}',item.get('sha256','')),'Consumer receipt asset descriptor differs')
    raw=fetch(base+MANIFEST,16*1024**2);signature=fetch(base+SIGNATURE,1024**2)
    require(data_descriptor(MANIFEST,raw)=={key:indexed[MANIFEST][key] for key in ('name','size','sha256')}
        and hashlib.sha256(raw).hexdigest()==receipt['manifestSha256'],'Consumer signed manifest differs from receipt')
    require(data_descriptor(SIGNATURE,signature)=={key:indexed[SIGNATURE][key] for key in ('name','size','sha256')},
        'Consumer manifest signature differs from receipt')
    with tempfile.TemporaryDirectory(prefix='cbodotnet-consumer-metadata-') as temporary:
        temporary=Path(temporary);bundle=temporary/'bundle';bundle.mkdir()
        (bundle/MANIFEST).write_bytes(raw);(bundle/SIGNATURE).write_bytes(signature)
        if keyring is None:
            keyring=temporary/'trusted.gpg'
            subprocess.run(['gpg','--batch','--yes','--dearmor','--output',str(keyring),str(ROOT/'releases/downstream-signing-key.asc')],
                check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        signer=verify_report_signature(bundle/MANIFEST,bundle/SIGNATURE,keyring,policy,WORKFLOW,historical=historical)
        require(signer==receipt['signingFingerprint'],'Consumer receipt has another signer')
        manifest=json.loads(raw)
        require(manifest['identity']==common,'Consumer receipt identity differs from signed manifest')
        assets={item['name']:item for item in manifest['assets']}
        require(set(indexed)==set(assets)|{MANIFEST,SIGNATURE},'Consumer receipt omits or adds a signed asset')
        large={item['artifactAsset'] for item in manifest['records']}|{item['asset'] for key in ('compatibility','nativeHttpCompatibility') for item in manifest.get(key,[])}
        for name,item in assets.items():
            require(name in indexed and item=={key:indexed[name][key] for key in ('name','size','sha256')},
                'Consumer receipt does not bind exact signed asset descriptors')
            if name in large:continue
            require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',name) and item['size']<=16*1024**2,'Unsafe or oversized signed consumer metadata')
            data=fetch(base+name,min(item['size'],16*1024**2))
            require(data_descriptor(name,data)==item,'Public consumer metadata bytes changed')
            (bundle/name).write_bytes(data)
        verified=validate_bundle(bundle,keyring,policy=policy,historical=historical,metadata_only=True)
        require(verified==manifest,'Consumer manifest changed during authentication')
    return manifest


def validate_public_report(report,manifest,architecture,manifest_sha,*,expected_source=None):
    matches=[item for item in manifest['records'] if item['architecture']==architecture]
    require(len(matches)==1,'Public consumer architecture is absent from signed manifest')
    build=matches[0]['build']
    require(report.get('scope')=='published-consumer-archive-installation'
        and report.get('manifestSha256')==manifest_sha,'Public consumer report has another manifest or scope')
    source=workflow_identity(report['orchestration'])
    if expected_source is not None:require(source==expected_source,'Public consumer report came from another workflow run')
    normalized=copy.deepcopy(report);normalized['scope']='consumer-archive-installation'
    validate_native_report(normalized,build,source)
    expected=f'https://github.com/{REPOSITORY}/releases/download/{manifest["tag"]}/'+matches[0]['artifactAsset']
    require(report.get('downloadUrl')==expected,'Public consumer download URL differs from signed archive')
    return report


def postverified_receipt(receipt,reports,manifest,*,source=None):
    require(len(reports)==2 and {item['architecture'] for item in reports}==set(ARCHITECTURES),
        'Both native public consumer reports are required')
    for item in reports:
        report=item['report'];raw=encoded(report)
        require(hashlib.sha256(raw).hexdigest()==item['rawJsonSha256'] and len(raw)==item['rawJsonSize'],
            'Retained public consumer report bytes differ')
        validate_public_report(report,manifest,item['architecture'],receipt['manifestSha256'],expected_source=source)
    result=copy.deepcopy(receipt);result.update(status='published-postverified',consumerInstallationStatus='passed',
        postVerification=dict(reports=reports))
    return result


def archive_rows(path=None,*,status=None,policy=None,keyring=None,fetch=None):
    status=status if status is not None else load_archive_status(path)
    require(status.get('schemaVersion')==1 and status.get('repository')==REPOSITORY,'Invalid archive status source')
    latest={};seen=set()
    for receipt in status['publications']:
        require(receipt.get('status')=='published-postverified' and receipt.get('consumerInstallationStatus')=='passed',
            'Consumer availability requires actual native public verification')
        version=receipt['identity']['sdkVersion'];revision=receipt['identity']['packageRevision'];key=(version,revision)
        require(key not in seen,'Duplicate consumer archive publication identity');seen.add(key)
        manifest=authenticate_receipt(receipt,policy=policy,keyring=keyring,fetch=fetch,historical=True)
        postverified_receipt(receipt,receipt['postVerification']['reports'],manifest)
        if version not in latest or revision>latest[version][0]:latest[version]=(revision,receipt,manifest)
    rows=[]
    for version in sorted(latest,key=lambda item:tuple(map(int,item.split('.'))),reverse=True):
        revision,receipt,manifest=latest[version]
        assets={item['name']:item for item in receipt['assets']}
        for record in manifest['records']:
            plan=record['build']['plan'];asset=assets[record['artifactAsset']]
            companion=[item for item in manifest.get('compatibility',[]) if item['architecture']==record['architecture']]
            rows.append(dict(sdkVersion=version,packageRevision=revision,architecture=record['architecture'],targetRid=plan['targetRid'],
                archiveName=asset['name'],archiveUrl=asset['url'],archiveSha256=asset['sha256'],archiveSize=asset['size'],
                directory=record['build']['directory'],payloadDirectory='payload',userSpaces=plan['validatedUserSpaces'],
                manifestUrl=receipt['manifestUrl'],manifestSha256=receipt['manifestSha256'],signatureUrl=receipt['signatureUrl'],
                signingFingerprint=receipt['signingFingerprint'],compatibility=assets[companion[0]['asset']] if companion else None))
            native_http=[item for item in manifest.get('nativeHttpCompatibility',[]) if item['architecture']==record['architecture']]
            if native_http:rows[-1]['nativeHttpCompatibility']=assets[native_http[0]['asset']]
    return rows
