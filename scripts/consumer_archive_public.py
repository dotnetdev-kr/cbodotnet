"""Install exact anonymously downloaded signed consumer archives on native hosts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import urllib.request

import consumer_archive_ci as CI
from consumer_archive import ARCHITECTURES,REPORT_CHECKS,ROOT,encoded,fresh_directory,identity,require
from consumer_archive_site import authenticate_receipt,validate_public_report


def download(item,destination):
    require(item['name']==destination.name and not destination.exists(),'Fresh exact public archive destination required')
    digest=hashlib.sha256();size=0
    # Public GitHub asset requests deliberately carry no credential headers.
    with urllib.request.urlopen(item['url'],timeout=60) as incoming,destination.open('xb') as output:
        for data in iter(lambda:incoming.read(4*1024**2),b''):
            size+=len(data);require(size<=item['size'],'Public consumer asset exceeds its signed size');digest.update(data);output.write(data)
    require(size==item['size'] and digest.hexdigest()==item['sha256'],'Public consumer archive differs from signed bytes')


def postverify(receipt_path,architecture,workspace,keyring,output=None):
    require(os.geteuid()!=0 and architecture in ARCHITECTURES
        and platform.machine() in ({'x86_64'} if architecture=='x64' else {'aarch64','arm64'}),
        'A matching native non-root public consumer verifier is required')
    source=CI.source_identity()
    receipt=json.loads(Path(receipt_path).read_bytes());manifest=authenticate_receipt(receipt,keyring=keyring)
    workspace=fresh_directory(workspace);(workspace/'build').mkdir()
    record=next(item for item in manifest['records'] if item['architecture']==architecture)
    build=record['build'];plan=build['plan'];assets={item['name']:item for item in receipt['assets']}
    archive=assets[record['artifactAsset']]
    download(archive,workspace/'build'/archive['name'])
    (workspace/'build/package-build.json').write_bytes(encoded(build))
    compatibility=next((item for item in manifest.get('compatibility',[]) if item['architecture']==architecture),None)
    provider=None
    if compatibility:
        (workspace/'compat').mkdir();provider=compatibility['record']
        download(assets[compatibility['asset']],workspace/'compat'/provider['companion']['path'])
        (workspace/'compat/provider-build.json').write_bytes(encoded(provider))
    native_http=next((item for item in manifest.get('nativeHttpCompatibility',[]) if item['architecture']==architecture),None)
    native_http_provider=None
    if native_http:
        (workspace/'native-http-compat').mkdir();native_http_provider=native_http['record']
        download(assets[native_http['asset']],workspace/'native-http-compat'/native_http_provider['companion']['path'])
        (workspace/'native-http-compat/provider-build.json').write_bytes(encoded(native_http_provider))
    spaces=[]
    for variant in plan['validatedUserSpaces']:
        require(variant in CI.BASES,'Published archive user space is not admitted for native execution')
        cid=None;snapshot=None
        try:
            cid=CI.run(['docker','create','-v',f'{ROOT}:/repo:ro','-v',f'{workspace}:/delivery',CI.BASES[variant],
                'bash','-ec','apt-get update -qq && apt-get install -y --no-install-recommends python3 && '
                f'python3 /repo/scripts/consumer-archive-ci.py prepare --workspace /delivery --variant {variant}']).strip()
            CI.run(['docker','start','--attach',cid]);require(json.loads(CI.run(['docker','inspect',cid]))[0]['State']['ExitCode']==0,
                'Public consumer preparation failed')
            snapshot=CI.run(['docker','commit',cid]).strip()
            CI.run(['docker','run','--rm','--network','none','-v',f'{ROOT}:/repo:ro','-v',f'{workspace}:/delivery',snapshot,
                'python3','/repo/scripts/consumer-archive-ci.py','installed','--workspace','/delivery','--variant',variant])
        finally:
            if cid:subprocess.run(['docker','rm','--force',cid],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if snapshot:subprocess.run(['docker','image','rm',snapshot],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        report=json.loads((workspace/(variant+'-report.json')).read_bytes());report['baseImage']=CI.BASES[variant];spaces.append(report)
    result=dict(schemaVersion=1,scope='published-consumer-archive-installation',status='passed',architecture=architecture,
        identity=identity(plan),artifact=build['artifact'],commands=build['commands'],qualifiedPayload=build['qualifiedPayload'],
        orchestration=source,networkForBuild='none',checks=dict.fromkeys(REPORT_CHECKS,'passed'),userSpaces=spaces,
        manifestSha256=receipt['manifestSha256'],downloadUrl=archive['url'],
        compatibility=dict(required=False) if provider is None else dict(required=True,policySha256=provider['policySha256'],
            companion=provider['companion'],manifest=provider['manifest']))
    if build.get('archiveLayoutVersion',1)==2:result['wrapperLicense']=build['wrapperLicense']
    if native_http_provider is not None:
        result['nativeHttpCompatibility']=dict(required=True,policySha256=native_http_provider['policySha256'],
            companion=native_http_provider['companion'],manifest=native_http_provider['manifest'])
    validate_public_report(result,manifest,architecture,receipt['manifestSha256'],expected_source=source)
    output=Path(output) if output is not None else workspace/('published-'+architecture+'.json')
    output.write_bytes(encoded(result));return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--arch',choices=tuple(ARCHITECTURES),required=True);parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--keyring',type=Path,required=True);parser.add_argument('--output',type=Path)
    args=parser.parse_args();result=postverify(args.receipt,args.arch,args.workspace,args.keyring,args.output)
    print(json.dumps(dict(status=result['status'],architecture=args.arch,sdkVersion=result['identity']['sdkVersion'])))


if __name__=='__main__':main()
