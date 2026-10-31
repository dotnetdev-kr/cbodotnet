#!/usr/bin/env python3
"""Export the fixed Core 3.1 Focal builder's ICU66 as separate verification inputs."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import uuid

IMAGE='ab750d90bdf890c078039cf6f52d3dd44862f3df8f6cdaf4ea771a802e18e3a0'
OWNER='cbodotnet-core31-verification-icu66-v1'
LIBRARIES=['libicuuc.so.66','libicui18n.so.66','libicudata.so.66']

def directory(path):
    if not path.is_absolute() or path==Path(path.anchor) or any(p.is_symlink() for p in [path]+list(path.parents)) or not path.is_dir():
        raise ValueError('An absolute ordinary directory below the filesystem root is required: '+str(path))
    return path

def file(path):
    directory(path.parent)
    if path.is_symlink() or not path.is_file():raise ValueError('An ordinary file is required: '+str(path))
    return path

def fingerprint(path):
    file(path);before=path.stat();digest=hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda:source.read(1024*1024),b''):digest.update(block)
    after=path.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('An input changed while hashing')
    return {'bytes':after.st_size,'sha256':digest.hexdigest()}

def command(*args):
    p=subprocess.run(list(args),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if p.returncode:raise ValueError('Input inspection failed: '+p.stderr.decode('utf-8','replace')[-1800:])
    return p.stdout.decode('utf-8')

def write(path,record):
    with path.open('x') as output:json.dump(record,output,indent=2,sort_keys=True);output.write('\n')

def inspect(image_receipt,consumer):
    data=json.loads(file(image_receipt).read_text())
    if len(data)!=1 or data[0].get('Id','').replace('sha256:','')!=IMAGE or data[0].get('Architecture')!='arm64' or data[0].get('Os')!='linux':
        raise ValueError('The exact host-inspected Core 3.1 Focal image is required')
    os_path=Path('/etc/os-release')
    if os_path.is_symlink():
        target=os_path.resolve(strict=True)
        if target!=Path('/usr/lib/os-release'):raise ValueError('Unexpected OS identity symlink')
        os_record={'path':str(os_path),'linkTarget':os.readlink(str(os_path)),'resolvedPath':str(target)}
    else:
        target=file(os_path);os_record={'path':str(target),'resolvedPath':str(target)}
    os_text=file(target).read_text()
    if not re.search(r'^ID=ubuntu$',os_text,re.M) or not re.search(r'^VERSION_ID="?20\.04"?$',os_text,re.M):raise ValueError('Run in the actual Ubuntu20.04 producer')
    os_record.update(fingerprint(target))
    package=command('dpkg-query','-W','-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n','libicu66').strip().split('\t')
    if len(package)!=4 or package[0]!='libicu66' or not package[1].startswith('66.1-') or package[2]!='arm64' or package[3]!='installed':raise ValueError('The installed native ICU66 package identity differs')
    root=Path('/usr/lib/aarch64-linux-gnu');directory(root)
    files=[]
    for name in LIBRARIES:
        source=root/name
        if not source.is_symlink() or os.readlink(str(source))!=name+'.1':raise ValueError('The ICU66 SONAME symlink target differs')
        actual=file(root/(name+'.1'))
        if source.resolve(strict=True)!=actual:raise ValueError('The ICU66 symlink escapes its fixed directory')
        with actual.open('rb') as stream:header=stream.read(20)
        if header[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(header[18:20],'little')!=183:raise ValueError('A source ICU library is not ELF64 AArch64')
        dynamic=command('readelf','--dynamic','--wide',str(actual))
        soname=re.search(r'\(SONAME\).*\[([^\]]+)\]',dynamic)
        needed=re.findall(r'\(NEEDED\).*\[([^\]]+)\]',dynamic)
        if not soname or soname.group(1)!=name:raise ValueError('The ICU library SONAME differs')
        versions=command('readelf','--version-info','--wide',str(actual))
        glibc=sorted(set(re.findall(r'\bGLIBC_([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b',versions)),key=lambda s:tuple(map(int,s.split('.'))))
        ownership=command('dpkg-query','-S',str(actual)).strip()
        if not ownership.startswith('libicu66:arm64: '):raise ValueError('The source ICU library lacks expected package ownership')
        files.append(dict({'path':'lib/'+name,'sourcePath':str(actual),'sourceSonamePath':str(source),
                           'sourceLinkTarget':os.readlink(str(source)),'packageOwnership':ownership,
                           'mode':oct(actual.stat().st_mode&0o777),'elfMachine':'AArch64','soname':name,
                           'needed':needed,'maximumGlibcRequirement':glibc[-1] if glibc else None,
                           'glibcRequirements':glibc,'dynamicSection':dynamic},**fingerprint(actual)))
    license_path=file(Path('/usr/share/doc/libicu66/copyright'))
    ownership=command('dpkg-query','-S',str(license_path)).strip()
    if not ownership.startswith('libicu66:arm64: '):raise ValueError('The ICU copyright ownership differs')
    files.append(dict({'path':'LICENSE.icu.txt','sourcePath':str(license_path),'packageOwnership':ownership,
                       'mode':oct(license_path.stat().st_mode&0o777)},**fingerprint(license_path)))
    return {'owner':OWNER,'producerImageId':IMAGE,'producerImageInspection':fingerprint(image_receipt),
            'osRelease':os_record,'package':{'name':package[0],'version':package[1],'architecture':package[2],'status':package[3]},
            'files':files,'consumerDirectory':consumer,'consumerEnvironment':{'LD_LIBRARY_PATH':consumer+'/lib','CLR_ICU_VERSION_OVERRIDE':'66'},
            'scope':'Separate ICU66 verification dependencies from the exact Focal builder. Supplied read-only beside the unchanged SDK. Globalization remains enabled and is exercised with fr-FR. This does not establish compatibility with stock Debian13 ICU76.'}

def export(destination,contract):
    owner={'owner':OWNER,'producerImageId':IMAGE}
    env='#!/usr/bin/env bash\n# Separate Core 3.1 ICU66 verification inputs.\n'
    env+='\n'.join('export '+key+'='+shlex.quote(value) for key,value in sorted(contract['consumerEnvironment'].items()))+'\n'
    expected={row['path'] for row in contract['files']}|{'owner.json','compatibility-inputs.json','verification-env.sh'}
    if destination.exists() or destination.is_symlink():
        directory(destination)
        if json.loads(file(destination/'owner.json').read_text())!=owner:raise ValueError('Refusing an unknown ICU dependency directory')
        previous=json.loads(file(destination/'compatibility-inputs.json').read_text())
        if previous!=contract:raise ValueError('The retained ICU contract differs')
        observed=set()
        for path in destination.rglob('*'):
            if path.is_symlink():raise ValueError('A retained ICU input is a symlink')
            if path.is_file():observed.add(path.relative_to(destination).as_posix())
        if observed!=expected:raise ValueError('Retained ICU membership differs')
        for row in contract['files']:
            if fingerprint(destination/row['path'])!={k:row[k] for k in ['bytes','sha256']}:raise ValueError('A retained ICU file differs')
        if file(destination/'verification-env.sh').read_text()!=env:raise ValueError('The ICU environment differs')
        return 'verified-existing'
    stage=destination.parent/('.core31-verification-icu-'+uuid.uuid4().hex);stage.mkdir()
    for row in contract['files']:
        target=stage/row['path'];target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(row['sourcePath'],str(target));os.chmod(str(target),int(row['mode'],8))
        if fingerprint(target)!={k:row[k] for k in ['bytes','sha256']}:raise ValueError('An ICU copy differs')
    write(stage/'owner.json',owner);write(stage/'compatibility-inputs.json',contract)
    with (stage/'verification-env.sh').open('x') as output:output.write(env)
    stage.rename(destination)
    return 'exported'

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--destination',type=Path,required=True);p.add_argument('--reports-dir',type=Path,required=True);p.add_argument('--image-inspect',type=Path,required=True);p.add_argument('--consumer-directory',default='/verification-icu');a=p.parse_args()
    if platform.system()!='Linux' or platform.machine().lower() not in ('arm64','aarch64'):raise ValueError('Run in native ARM64 Linux')
    directory(a.destination.parent);directory(a.reports_dir)
    if a.destination==a.reports_dir or a.destination in a.reports_dir.parents or a.reports_dir in a.destination.parents:raise ValueError('Inputs and reports must be separate')
    if not a.consumer_directory.startswith('/') or a.consumer_directory=='/' or '..' in Path(a.consumer_directory).parts or re.search(r'[\s:\x00]',a.consumer_directory):raise ValueError('An ordinary absolute consumer path is required')
    report=a.reports_dir/'core31-verification-icu.json'
    if report.exists() or report.is_symlink():raise ValueError('Use a new ICU export report directory')
    record={'startedAtUtc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'failed','sdkArchiveModified':False}
    try:
        contract=inspect(a.image_inspect,a.consumer_directory.rstrip('/'))
        record.update({'inputContract':contract,'result':export(a.destination,contract),'status':'passed','contractFingerprint':fingerprint(a.destination/'compatibility-inputs.json')})
    except (OSError,ValueError,KeyError) as error:record['error']=str(error)
    record['finishedAtUtc']=datetime.datetime.now(datetime.timezone.utc).isoformat();write(report,record)
    print(json.dumps({'status':record['status'],'report':str(report),'error':record.get('error')}))
    return 0 if record['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
