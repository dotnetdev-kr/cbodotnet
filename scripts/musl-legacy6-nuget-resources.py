#!/usr/bin/env python3
"""Retain only matching official NuGet6 translation data and readable resources.

Primary NuGet assemblies remain rebuilt from source. Every admitted input here
must be a managed resource-only satellite with zero methods/fields/extra types,
zero linked resources and only the standard managed PE import thunk. Original
NuGet source, Apache-2.0 license/notices, nuspec and SDK notices are retained.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET

COMMIT='451e9bc27184dc49d04e975122c9e7189d525872'
SDK='6.0.136'
SHA512={
 'aarch64':'2ccb4e58f9dfa0a09dce1687a60ae4911cf8c864abfc7d63cdc113bd228a253f9545d699e8709d1403ff28ce7cf8db0935e4796b05b0aa80eef6ae43d38b8537',
 'x64':'a93ba846501707808c6b8ea51aa763faf82cc215325aa310aa05d084caebd2c40f74048b384624a73988ba418bf72a71b57883c2a05a0a087a112d2c26b4266d'}
CULTURES=['cs','de','es','fr','it','ja','ko','pl','pt-BR','ru','tr','zh-Hans','zh-Hant']
NAMES=['Microsoft.Build.NuGetSdkResolver','NuGet.Build.Tasks.Console','NuGet.Build.Tasks','NuGet.CommandLine.XPlat',
       'NuGet.Commands','NuGet.Common','NuGet.Configuration','NuGet.Credentials','NuGet.DependencyResolver.Core',
       'NuGet.Frameworks','NuGet.LibraryModel','NuGet.Localization','NuGet.PackageManagement','NuGet.Packaging.Core',
       'NuGet.Packaging','NuGet.ProjectModel','NuGet.Protocol','NuGet.Resolver','NuGet.Versioning','NuGet.VisualStudio.Contracts']
DRIVER=r'''using System;using System.IO;using System.Linq;using System.Collections;using System.Collections.Generic;
using System.Reflection;using System.Reflection.Metadata;using System.Reflection.PortableExecutable;using System.Diagnostics;
using System.Resources;using System.Security.Cryptography;using System.Text;using System.Text.Json;using System.Text.Encodings.Web;
using System.Xml;using System.Xml.Linq;
class P {
 static void Require(bool b,string m){if(!b)throw new Exception(m);}
 static string Hash(byte[] b)=>Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();
 static string CString(PEReader pe,int rva){var r=pe.GetSectionData(rva).GetReader();var b=new List<byte>();while(true){byte c=r.ReadByte();if(c==0)break;Require(b.Count<256,"long import");b.Add(c);}return Encoding.ASCII.GetString(b.ToArray());}
 static object Inspect(string path){using var stream=File.OpenRead(path);using var pe=new PEReader(stream);Require(pe.HasMetadata,"not managed");
  var md=pe.GetMetadataReader();var a=md.GetAssemblyDefinition();var header=pe.PEHeaders.CorHeader;
  Require(header!=null&&(header.Flags&CorFlags.ILOnly)!=0&&(header.Flags&CorFlags.NativeEntryPoint)==0&&header.EntryPointTokenOrRelativeVirtualAddress==0&&header.ManagedNativeHeaderDirectory.Size==0,"native/entrypoint payload");
  Require(md.MethodDefinitions.Count==0&&md.FieldDefinitions.Count==0&&md.TypeDefinitions.Count==1&&md.ExportedTypes.Count==0&&md.AssemblyFiles.Count==0,"unexpected executable definitions");
  var t=md.GetTypeDefinition(md.TypeDefinitions.Single());Require(md.GetString(t.Name)=="<Module>"&&md.GetString(t.Namespace)=="","unexpected type");
  var imports=new List<string>();var id=pe.PEHeaders.PEHeader.ImportTableDirectory;
  if(id.Size>0){var r=pe.GetSectionData(id.RelativeVirtualAddress).GetReader();for(int n=0;n<16;n++){int o=r.ReadInt32(),ts=r.ReadInt32(),f=r.ReadInt32(),name=r.ReadInt32(),thunk=r.ReadInt32();if(o==0&&ts==0&&f==0&&name==0&&thunk==0)break;string dll=CString(pe,name);Require(dll.Equals("mscoree.dll",StringComparison.OrdinalIgnoreCase),"unexpected native import");imports.Add(dll);}}
  var resources=new List<object>();
  foreach(var h in md.ManifestResources){var resource=md.GetManifestResource(h);Require(resource.Implementation.IsNil,"linked resource");
   var r=pe.GetSectionData(header.ResourcesDirectory.RelativeVirtualAddress+checked((int)resource.Offset)).GetReader();int count=r.ReadInt32();Require(count>0&&count<16*1024*1024,"resource size");byte[] bytes=r.ReadBytes(count);
   string resourceName=md.GetString(resource.Name);
   if(bytes.Length<4||BitConverter.ToUInt32(bytes,0)!=0xbeefcace){
    Require(resourceName.EndsWith(".xsd",StringComparison.Ordinal),"unexpected opaque satellite resource: "+resourceName);
    string text=new UTF8Encoding(false,true).GetString(bytes);using var xr=XmlReader.Create(new StringReader(text),new XmlReaderSettings{DtdProcessing=DtdProcessing.Prohibit,XmlResolver=null});var xml=XDocument.Load(xr);Require(xml.Root.Name==XName.Get("schema","http://www.w3.org/2001/XMLSchema"),"unexpected satellite XML schema");
    resources.Add(new{name=resourceName,sha256=Hash(bytes),format="xml-schema",text,entries=new SortedDictionary<string,object>()});continue;}
   using var rr=new ResourceReader(new MemoryStream(bytes));var values=new SortedDictionary<string,object>(StringComparer.Ordinal);var en=rr.GetEnumerator();
   while(en.MoveNext()){string key=(string)en.Key;rr.GetResourceData(key,out var type,out var data);Require(type=="ResourceTypeCode.String","non-string translation data");using var br=new BinaryReader(new MemoryStream(data),Encoding.UTF8);string value=br.ReadString();Require(br.BaseStream.Position==br.BaseStream.Length,"resource trailing data");values.Add(key,new{value,keySha256=Hash(Encoding.UTF8.GetBytes(key)),valueSha256=Hash(Encoding.UTF8.GetBytes(value))});}
   resources.Add(new{name=resourceName,sha256=Hash(bytes),format="dotnet-string-table",entries=values});}
  var pk=md.GetBlobBytes(a.PublicKey);var token=SHA1.HashData(pk).Reverse().Take(8).ToArray();var v=FileVersionInfo.GetVersionInfo(path);
  return new{path,assemblyName=md.GetString(a.Name),assemblyVersion=a.Version.ToString(),culture=md.GetString(a.Culture),fileVersion=v.FileVersion,productVersion=v.ProductVersion,
   publicKeyBase64=Convert.ToBase64String(pk),publicKeyToken=Convert.ToHexString(token).ToLowerInvariant(),managedResourceOnly=true,emptySatellite=resources.Count==0,methodBodies=0,extraTypes=0,fields=0,linkedResources=0,nativeImports=imports,resources};}
 static void Main(string[] args){var rows=args.Skip(1).Select(Inspect).ToArray();File.WriteAllText(args[0],JsonSerializer.Serialize(rows,new JsonSerializerOptions{WriteIndented=true,Encoder=JavaScriptEncoder.UnsafeRelaxedJsonEscaping}),new UTF8Encoding(false));}}
'''


def require(value,message):
    if not value:raise ValueError(message)


def fingerprint(path):
    hashes={name:hashlib.new(name) for name in ['sha256','sha512']}
    with path.open('rb') as source:
        for data in iter(lambda:source.read(1024*1024),b''):
            for h in hashes.values():h.update(data)
    return dict(bytes=path.stat().st_size,**{name:h.hexdigest() for name,h in hashes.items()})


def relative_names():
    names=[]
    for culture in CULTURES:
        names += [culture+'/'+name+'.resources.dll' for name in NAMES]
        names += ['Sdks/NuGet.Build.Tasks.Pack/'+tfm+'/'+culture+'/NuGet.Build.Tasks.Pack.resources.dll' for tfm in ['CoreCLR','Desktop']]
    return sorted(names)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk-archive',type=Path,required=True)
    parser.add_argument('--arch',choices=list(SHA512),required=True)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--dotnet',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    require(fingerprint(args.sdk_archive)['sha512']==SHA512[args.arch],'Matching official musl SDK6 archive bytes differ')
    commit=subprocess.check_output(['git','-c','safe.directory='+str(args.source),'-C',str(args.source),'rev-parse','HEAD'],text=True).strip()
    require(commit==COMMIT,'Complete exact corresponding NuGet source is required')
    require(not args.output.exists(),'Use a fresh translation-data input directory')
    args.output.mkdir(parents=True);resources=args.output/'resources';resources.mkdir();rows=[]
    expected={'sdk/'+SDK+'/'+relative:relative for relative in relative_names()};seen=set();inventory=[];omitted=[]
    notices=args.output/'licenses';notices.mkdir()
    # Stream once: randomized filesystem order in upstream gzip tarballs must
    # not cause one complete decompression for each separate satellite read.
    with tarfile.open(args.sdk_archive,mode='r|gz') as archive:
        for member in archive:
            original=member.name.lstrip('./')
            if member.isfile():inventory.append(dict(path=original,bytes=member.size))
            if original in expected:
                require(original not in seen and member.isfile() and 0<member.size<1024*1024,'Ambiguous or unsafe original satellite: '+original)
                seen.add(original);relative=expected[original]
                destination=resources/relative;destination.parent.mkdir(parents=True,exist_ok=True)
                destination.write_bytes(archive.extractfile(member).read())
                require(destination.read_bytes()[:2]==b'MZ','Expected a managed satellite PE')
                rows.append(dict(path=relative,sdkMember=original,origin='imported-official-translation-data',**fingerprint(destination)))
            elif original in ['LICENSE.txt','ThirdPartyNotices.txt']:
                require(member.isfile(),'Original SDK notice is not ordinary')
                (notices/('official-sdk-'+original)).write_bytes(archive.extractfile(member).read())
            elif original in ['sdk/'+SDK+'/'+culture+'/Test.Utility.resources.dll' for culture in CULTURES]:
                require(member.isfile(),'Original orphan test satellite is not ordinary')
                data=archive.extractfile(member).read()
                omitted.append(dict(path=original,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),sha512=hashlib.sha512(data).hexdigest(),
                    reason='Orphan unit-test fixture satellite; no primary Test.Utility assembly exists anywhere in the original SDK'))
    require(seen==set(expected),'An exact original translation satellite is absent')
    require(len(omitted)==13 and not any(Path(r['path']).name.lower() in ['test.utility.dll','test.utility.exe'] for r in inventory),
            'The narrow orphan-test-data omission requires whole-original-SDK absence of a primary Test.Utility assembly')
    (args.output/'official-sdk-file-inventory.json').write_text(json.dumps(dict(archive=fingerprint(args.sdk_archive),files=inventory),indent=2)+'\n')
    (args.output/'omitted-orphan-test-satellites.json').write_text(json.dumps(dict(files=omitted,
        primaryTestUtilityAssemblies=[],scope='Explicitly excluded orphan unit-test data, not Linux product translations'),indent=2)+'\n')
    rows.sort(key=lambda r:r['path'])
    for p in args.source.iterdir():
        if p.is_file() and any(n in p.name.lower() for n in ['license','notice']):shutil.copyfile(p,args.output/'licenses'/('nuget-source-'+p.name))
    nuspec=args.source/'src/NuGet.Core/NuGet.Localization/NuGet.Localization.nuspec'
    shutil.copyfile(nuspec,args.output/'licenses/original-NuGet.Localization.nuspec')
    require(any('license' in p.name.lower() for p in (args.output/'licenses').iterdir()),'Original source license is absent')
    with tempfile.TemporaryDirectory(prefix='cbodotnet-nuget-translation-reader-') as temporary:
        work=Path(temporary);(work/'Read.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net6.0</TargetFramework><UseSharedCompilation>false</UseSharedCompilation></PropertyGroup></Project>')
        (work/'Program.cs').write_text(DRIVER);(work/'NuGet.Config').write_text('<configuration><packageSources><clear/></packageSources></configuration>')
        (args.output/'resource-reader.cs').write_text(DRIVER)
        env=dict(os.environ,HOME=str(work/'home'),DOTNET_CLI_HOME=str(work/'home'),DOTNET_MULTILEVEL_LOOKUP='0',DOTNET_CLI_TELEMETRY_OPTOUT='1')
        commands=[[str(args.dotnet),'build',str(work/'Read.csproj'),'-c','Release','-p:UseSharedCompilation=false'],
            [str(args.dotnet),str(work/'bin/Release/net6.0/Read.dll'),str(args.output/'readable-resources.json'),*[str(resources/r['path']) for r in rows]]]
        for index,command in enumerate(commands):
            with (args.output/('reader-build.log' if index==0 else 'reader-execution.log')).open('x') as log:
                subprocess.run(command,cwd=work,env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=180)
    metadata=json.loads((args.output/'readable-resources.json').read_text());lookup={str(Path(row['path']).relative_to(resources)):row for row in metadata}
    source_data={fingerprint(p)['sha256']:p.relative_to(args.source).as_posix() for p in args.source.rglob('*.xsd')
                    if '.git' not in p.parts and '.packages' not in p.parts and 'artifacts' not in p.parts and p.is_file()}
    schema_proofs=[]
    def canonical_xml(element):
        return [element.tag,sorted(element.attrib.items()),element.text if element.text and element.text.strip() else '',
                [[canonical_xml(child),child.tail if child.tail and child.tail.strip() else ''] for child in element]]
    for row in rows:
        data=lookup[row['path']];culture=next(p for p in PurePosixPath(row['path']).parts if p in CULTURES)
        version,key=('6.0.6.4','b03f5f7f11d50a3a') if data['assemblyName']=='NuGet.VisualStudio.Contracts.resources' else ('6.0.6.4','31bf3856ad364e35')
        require(data['managedResourceOnly'] is True and data['methodBodies']==0 and data['extraTypes']==0 and data['fields']==0 and
            data['linkedResources']==0 and data['culture']==culture and data['assemblyVersion']==version and data['productVersion']==version and
            data['publicKeyToken']==key,'Unexpected satellite culture/version/key/ABI/executable scope: '+row['path'])
        row['assemblyMetadata']={k:v for k,v in data.items() if k not in ['path','resources']}
        for resource in data['resources']:
            if resource['format']=='xml-schema':
                if resource['sha256'] in source_data:
                    resource['sourcePath']=source_data[resource['sha256']]
                    resource['sourceByteIdentity']=True
                else:
                    # Explicitly reviewed upstream XML serialization result.
                    # This is not a general XML normalization/version fallback.
                    relative='src/NuGet.Core/NuGet.Packaging/compiler/resources/nuspec.xsd'
                    pristine=args.source/relative;generated=resource['text'].encode('utf8')
                    require(resource['name']=='NuGet.Packaging.compiler.resources.nuspec.xsd' and
                        resource['sha256']=='67465b7ba16b9238c6793607216f311dd3aad04a7cee8eb2c4efa8f5c4ebc6e9' and
                        hashlib.sha256(generated).hexdigest()==resource['sha256'] and
                        fingerprint(pristine)['sha256']=='5d4226dd761e3854ed02d33de390713c4c9846238a1d16f4b5f38192545ea417',
                        'Unreviewed generated XML source bytes')
                    texts=[pristine.read_text(),resource['text']]
                    require(all('<!DOCTYPE' not in text.upper() and '<!ENTITY' not in text.upper() and text.count('{0}')==3 for text in texts),
                        'Unsafe XML or changed namespace placeholder scope')
                    trees=[canonical_xml(ET.fromstring(text.replace('{0}','urn:cbodotnet:nuspec-namespace-placeholder'))) for text in texts]
                    require(trees[0]==trees[1],'Reviewed generated XML differs in ordered names/attributes/non-whitespace text')
                    xml=args.output/'static-xml-source-data';xml.mkdir(exist_ok=True)
                    for name,content in [('pristine-nuspec.xsd',pristine.read_bytes()),('embedded-nuspec.xsd',generated)]:
                        target=xml/name
                        if target.exists():require(target.read_bytes()==content,'Ambiguous repeated XML source data')
                        else:target.write_bytes(content)
                    proof=dict(sourcePath=relative,sourceCommit=COMMIT,sourceByteIdentity=False,
                        pristine=dict(path='static-xml-source-data/pristine-nuspec.xsd',**fingerprint(xml/'pristine-nuspec.xsd')),
                        generatedEmbedded=dict(path='static-xml-source-data/embedded-nuspec.xsd',**fingerprint(xml/'embedded-nuspec.xsd')),
                        namespaceSubstitution=dict(before='{0}',after='urn:cbodotnet:nuspec-namespace-placeholder',occurrencesEach=3),
                        orderedQualifiedNamesAttributesAndNonWhitespaceTextEquivalent=True,onlyWhitespaceIndentNodesIgnored=True,
                        dtdAndEntityDeclarationsRejected=True)
                    if not schema_proofs:schema_proofs.append(proof)
                    resource['sourcePath']=relative;resource['sourceByteIdentity']=False
                    resource['generatedSourcePath']='static-xml-source-data/embedded-nuspec.xsd'
        row['readableResources']=[dict(name=r['name'],sha256=r['sha256'],format=r['format'],entryCount=len(r['entries']),
            **{k:r[k] for k in ['sourcePath','sourceByteIdentity','generatedSourcePath'] if k in r}) for r in data['resources']]
    manifest=dict(schemaVersion=1,kind='imported-official-nuget-translation-data',sdkVersion=SDK,architecture=args.arch,
        officialSdk=dict(path=str(args.sdk_archive),**fingerprint(args.sdk_archive)),sourceRoot=str(args.source),sourceCommit=COMMIT,
        sourceLicense='Apache-2.0',cultures=CULTURES,files=rows,readableResources=dict(path='readable-resources.json',**fingerprint(args.output/'readable-resources.json')),
        originalSdkInventory=dict(path='official-sdk-file-inventory.json',**fingerprint(args.output/'official-sdk-file-inventory.json')),
        explicitOrphanTestOmissions=dict(path='omitted-orphan-test-satellites.json',**fingerprint(args.output/'omitted-orphan-test-satellites.json')),
        reviewedGeneratedStaticXml=schema_proofs,
        notices=[dict(path=p.relative_to(args.output).as_posix(),**fingerprint(p)) for p in sorted((args.output/'licenses').iterdir())],
        primaryNuGetAssembliesImported=False,nativeComponentsImported=False,wholeSdkUsedAsProduct=False,
        translationsLocallySourceBuilt=False,qualificationAllowed=False,sourceAdmissionAllowed=False,
        scope='Only exact original resource-only satellites. Readable original translation key/value data is retained with hashes; source-built NuGet primary assemblies are never replaced.')
    (args.output/'origin.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(dict(status='validated-resource-only-translations',files=len(rows),cultures=len(CULTURES))))


if __name__=='__main__':main()
