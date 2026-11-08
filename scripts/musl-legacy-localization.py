#!/usr/bin/env python3
"""Retain explicitly imported MSBuild6 satellite inputs from its exact musl SDK.

This constructs only the original localization package's 52 managed resource
assemblies. It never copies executable/native SDK tooling into the producer.
The result is an imported Microsoft binary input, never a source-built package.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile

COMMIT='85d71072f8fa22cc761d6b65954da263364bee4d'
SDK='6.0.136'
VERSION='17.0.4-preview-24422-07'
SHA512={
 'aarch64':'2ccb4e58f9dfa0a09dce1687a60ae4911cf8c864abfc7d63cdc113bd228a253f9545d699e8709d1403ff28ce7cf8db0935e4796b05b0aa80eef6ae43d38b8537',
 'x64':'a93ba846501707808c6b8ea51aa763faf82cc215325aa310aa05d084caebd2c40f74048b384624a73988ba418bf72a71b57883c2a05a0a087a112d2c26b4266d'}
CULTURES=['cs','de','es','fr','it','ja','ko','pl','pt-BR','ru','tr','zh-Hans','zh-Hant']


def require(value,message):
    if not value:raise ValueError(message)


def fingerprint(path):
    hashes={k:hashlib.new(k) for k in ['sha256','sha512']}
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):
            for value in hashes.values():value.update(block)
    return dict(bytes=path.stat().st_size,**{k:v.hexdigest() for k,v in hashes.items()})


def build(args):
    require(args.sdk_archive.is_file() and not args.sdk_archive.is_symlink() and
        fingerprint(args.sdk_archive)['sha512']==SHA512[args.arch],'Exact official SDK6.0.136 musl archive required')
    commit=subprocess.check_output(['git','-c','safe.directory='+str(args.source),'-C',str(args.source),'rev-parse','HEAD'],text=True).strip()
    require(commit==COMMIT,'Complete matching MSBuild6 source required')
    require(not args.output.exists(),'Fresh localization input evidence directory required')
    args.output.mkdir(parents=True)
    nuspec_path=args.source/'src/Package/Localization/Microsoft.Build.Localization.nuspec'
    original=nuspec_path.read_bytes();document=ET.fromstring(original)
    files=[x for x in document.iter() if x.tag.rsplit('}',1)[-1]=='file']
    require(len(files)==52,'Original four-assembly/thirteen-culture localization definition differs')
    retained=args.output/'satellites';retained.mkdir()
    rows=[];contents={}
    with tarfile.open(args.sdk_archive,'r:gz') as archive:
        names={m.name.lstrip('./'):m for m in archive.getmembers()}
        for item in files:
            relative=item.get('src').replace('\\','/')
            require(len(Path(relative).parts)==2 and relative.split('/')[0] in CULTURES and relative.endswith('.resources.dll'),
                'Original localization input escaped managed satellite scope')
            sdk_member='sdk/'+SDK+'/'+relative;member=names[sdk_member]
            require(member.isfile() and member.size<1024*1024,'Only ordinary small managed resource assemblies may be imported')
            data=archive.extractfile(member).read();require(data[:2]==b'MZ','Imported satellite is not a managed PE assembly')
            path=retained/relative;path.parent.mkdir(exist_ok=True);path.write_bytes(data)
            target=item.get('target').replace('\\','/')
            require(target=='lib/netstandard1.3/'+relative,'Original localization package layout changed')
            contents[target]=data
            rows.append(dict(sdkMember=sdk_member,packageMember=target,relativePath=relative,**fingerprint(path)))
        for name in ['LICENSE.txt','ThirdPartyNotices.txt']:
            member=names.get(name)
            require(member is not None and member.isfile(),'Original official SDK license/notice is absent: '+name)
            contents['cbodotnet-provenance/'+name]=archive.extractfile(member).read()
    with tempfile.TemporaryDirectory(prefix='cbodotnet-msbuild6-metadata-') as temp:
        driver=Path(temp)
        (driver/'Metadata.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net6.0</TargetFramework><UseSharedCompilation>false</UseSharedCompilation></PropertyGroup></Project>')
        (driver/'NuGet.Config').write_text('<configuration><packageSources><clear/></packageSources></configuration>')
        (driver/'Program.cs').write_text('''using System;using System.IO;using System.Linq;using System.Reflection;using System.Reflection.Metadata;using System.Reflection.PortableExecutable;using System.Diagnostics;using System.Text.Json;
class P{static void Main(string[] args){Console.Write(JsonSerializer.Serialize(args.Select(p=>{using var stream=File.OpenRead(p);using var pe=new PEReader(stream);if(!pe.HasMetadata)throw new Exception("not managed");var reader=pe.GetMetadataReader();var a=reader.GetAssemblyDefinition();var v=FileVersionInfo.GetVersionInfo(p);return new {relativePath=Path.GetFileName(Path.GetDirectoryName(p))+"/"+Path.GetFileName(p),assemblyName=reader.GetString(a.Name),assemblyVersion=a.Version.ToString(),culture=reader.GetString(a.Culture),fileVersion=v.FileVersion,productVersion=v.ProductVersion,hasClrMetadata=pe.HasMetadata};})));}}
''')
        env=dict(os.environ,DOTNET_MULTILEVEL_LOOKUP='0',DOTNET_CLI_TELEMETRY_OPTOUT='1',DOTNET_CLI_HOME=str(driver/'home'))
        with (args.output/'metadata-build.log').open('x') as log:
            subprocess.run([str(args.dotnet),'build',str(driver/'Metadata.csproj'),'-c','Release','-p:UseSharedCompilation=false'],env=env,
                cwd=driver,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=180)
        metadata=json.loads(subprocess.check_output([str(args.dotnet),str(driver/'bin/Release/net6.0/Metadata.dll'),
            *[str(retained/r['relativePath']) for r in rows]],env=env,cwd=driver,text=True,timeout=30))
        by_path={m['relativePath']:m for m in metadata}
        for row in rows:
            value=by_path[row['relativePath']]
            require(value['culture']==row['relativePath'].split('/')[0] and value['assemblyVersion']=='15.1.0.0' and
                value['productVersion'].startswith('17.0.4') and COMMIT.startswith(value['productVersion'].split('+')[-1]),
                'Actual imported satellite metadata differs from matching source/version/culture')
            row['assemblyMetadata']=value
    # Resolve the *original* nuspec metadata tokens, retain that original file,
    # and state the reconstruction origin in the accompanying immutable record.
    text=original.decode('utf-8-sig')
    for before,after in {'$version$':VERSION,'$licenseExpression$':'MIT','$projectUrl$':'https://github.com/dotnet/msbuild',
        '$iconUrl$':'https://go.microsoft.com/fwlink/?LinkID=288859'}.items():text=text.replace(before,after)
    original_doc=ET.fromstring(text)
    ET.register_namespace('',original_doc.tag[1:].split('}',1)[0])
    for element in list(original_doc):
        if element.tag.rsplit('}',1)[-1]=='files':original_doc.remove(element)
    contents['Microsoft.Build.Localization.nuspec']=ET.tostring(original_doc,encoding='utf-8',xml_declaration=True)
    contents['cbodotnet-provenance/original-Microsoft.Build.Localization.nuspec']=original
    package=args.output/('Microsoft.Build.Localization.'+VERSION+'.nupkg')
    with zipfile.ZipFile(package,'x',compression=zipfile.ZIP_DEFLATED) as archive:
        for name,data in sorted(contents.items()):archive.writestr(name,data)
    record=dict(schemaVersion=1,kind='explicit-matching-imported-managed-localization',sdkVersion=SDK,architecture=args.arch,
        originalSdk=dict(path=str(args.sdk_archive),**fingerprint(args.sdk_archive)),
        packageId='Microsoft.Build.Localization',packageVersion=VERSION,sourceCommit=COMMIT,sourceRoot=str(args.source),
        originalNuspec=dict(path=str(nuspec_path),**fingerprint(nuspec_path)),files=rows,
        package=dict(name=package.name,**fingerprint(package)),cultures=CULTURES,
        locallySourceBuilt=False,nativeInputsImported=False,fullSdkUsedAsProduct=False,
        scope='Only original nuspec managed satellites imported from matching official musl SDK. Their corresponding full source and original licenses/notices remain required. This import may be shipped and must retain attribution.',
        qualificationAllowed=False,sourceAdmissionAllowed=False)
    (args.output/'origin.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(status='imported-exact-managed-satellites',count=len(rows),package=str(package))))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk-archive',type=Path,required=True)
    parser.add_argument('--arch',choices=['x64','aarch64'],required=True)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--dotnet',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();build(args)


if __name__=='__main__':main()
