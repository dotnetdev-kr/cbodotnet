"""Bounded static native product closure, using the existing complete auditor."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT=Path(__file__).resolve().parents[1]

def require(value,message):
    if not value:raise ValueError(message)

def fp(path):
    raw=path.read_bytes()
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),sha512=hashlib.sha512(raw).hexdigest())

def ordinary(path):
    require(path.is_absolute()and not any(item.is_symlink()for item in (path,*path.parents)),
        'Ordinary absolute static audit path required')
    return path

def save(path,value):
    with path.open('x',encoding='utf-8')as stream:json.dump(value,stream,indent=2);stream.write('\n')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('payload','output','indexes'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    for value in vars(args).values():ordinary(value)
    require(args.payload.is_dir()and args.indexes.is_dir()and not args.output.exists(),
        'Existing native payload/indexes and a fresh separate audit output required')
    require(not args.output.is_relative_to(args.payload),'Static evidence must be separate from native payload')
    pins=json.loads((ROOT/'scripts/core31-musl-host-elf-audit-pins.json').read_bytes())
    for name,pin in pins['codeFiles'].items():require(fp(ROOT/name)==pin,'Frozen auditor input changed: '+name)
    sys.path.insert(0,str(ROOT/'scripts'))
    import musl_archive as M
    native_before={path.name:fp(path)for path in args.payload.iterdir()if path.is_file()}
    require(set(native_before)=={'dotnet','apphost','libhostfxr.so','libhostpolicy.so','libnethost.so'},
        'Exactly five declared original host products required')
    args.output.mkdir()
    audit=M.audit_elf(args.payload,'aarch64')
    require(audit['hostElfCount']==5 and audit['nonHostElfCount']==0,'Every original host product must pass full native audit')
    package_records={};indexes=[]
    for channel,pin in pins['apkIndexes'].items():
        path=args.indexes/(channel+'-APKINDEX.tar.gz')
        require(fp(path)['sha256']==pin,'Frozen Alpine signed index changed')
        verification=subprocess.run(['apk','verify',str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        require(verification.returncode==0,'Frozen stock APK index signature verification failed')
        (args.output/(channel+'-index-verification.txt')).write_bytes(verification.stdout+verification.stderr)
        with tarfile.open(path)as archive:text=archive.extractfile('APKINDEX').read().decode()
        for block in text.split('\n\n'):
            row=dict(line.split(':',1)for line in block.splitlines()if ':'in line)
            if 'P'in row and 'V'in row:package_records[row['P']+'-'+row['V']]=dict(package=row['P'],version=row['V'],
                origin=row.get('o'),license=row.get('L'),checksum=row.get('C'),dependencyDeclarations=row.get('D'),
                repository=channel,signedIndexSha256=pin)
        indexes.append(dict(channel=channel,**fp(path),stockApkSignatureVerified=True))
    providers=[]
    for row in audit['stockLibraries']:
        owner=row['apkOwner'].split(' is owned by ',1)[1]
        require(owner in package_records,'Native provider absent from the frozen signed stock indexes')
        metadata=package_records[owner]
        require(metadata['version']==M.RUNTIME_PACKAGES.get(metadata['package']),
            'Actual provider is not an exact declared stock runtime root')
        providers.append(dict(path=row['path'],file=fp(Path(row['path'])),elf=row,package=metadata))
    require(native_before=={path.name:fp(path)for path in args.payload.iterdir()if path.is_file()},'Static audit changed native inputs')
    save(args.output/'complete-native-elf-closure.json',audit)
    save(args.output/'actual-stock-native-providers.json',dict(indexes=indexes,providers=providers,
        generalGlibcException=False,compatibilityProviderAllowed=False))
    save(args.output/'results.json',dict(status='passed-existing-provider-specific-native-host-elf-audit',
        hostProducts=5,stockProviders=len(providers),auditorSourceCommit=pins['sourceCommit'],auditorCodeFiles=pins['codeFiles'],
        productFingerprints=native_before,runtimeExecuted=False,compilerExecuted=False,qualificationAllowed=False,
        sourceAdmissionAllowed=False))
    print(json.dumps(dict(status='passed-existing-provider-specific-native-host-elf-audit',hostProducts=5,stockProviders=len(providers))))

if __name__=='__main__':main()
