"""SDK5 CSS source recipe and exact original certificate-append bridge."""
import configparser
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import xml.etree.ElementTree as ET
import zipfile

SDK = '5.0.214'
POLICY_SHA256 = 'd9f883bb956183a96f40d9400f26f1508fc64c3039bd22afb07f334fe012b3d1'
ROOT_NAME = 'sdk5-original-css-imported-source-inputs'
ROLE = 'sdk5-original-css-package-image-and-independent-source-recipe'
KIND = 'reviewed-sdk5-css-imported-source-and-certificate-append'
FP = ('bytes', 'sha256', 'sha512')


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def ordinary(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary original SDK5 CSS input required')
    return path


def policy():
    raw = Path(__file__).with_name('musl-legacy5-css-declared-source-policy.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == POLICY_SHA256, 'Closed SDK5 CSS source policy differs')
    p = json.loads(raw)
    require(p['sdkVersion'] == SDK and p['kind'] == 'sdk5-unchanged-css-imported-source-policy'
            and p['sources']['external']['commit'] == '522d361e1cd703f1e8e526f5306e4ed18de1da41'
            and p['sources']['css']['commit'] == p['gitlink']['commit'] == 'd6d86bcd8c162b1ae22ef00955ff748d028dd0ee'
            and p['sources']['aspnetcore']['commit'] == '02c6de4ba6022025fcda7581415f310f8c73cdc3'
            and len(p['products']) == 1 and p['sourceBasis'] == 'canonical-image-certificate-append-and-independent-publisher-gitlink-recipe'
            and all(p[k] is False for k in ('sdk5DeclaredPublisherGitlink','publisherCompilerExecutionClaimed','localBuildClaimed','byteIdenticalCompilationClaimed')),
            'Distinct original SDK5 CSS source basis required')
    return p


def xml(raw):
    require(len(raw) <= 2 * 1024**2 and b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'Bounded original CSS XML without entities required')
    return ET.fromstring(raw)


def source_recipe(sources, p=None):
    p = p or policy()
    for role, expected in p['sources'].items():
        require(sources[role].keys() == expected['files'].keys(), 'Complete original CSS recipe and license files required')
        for name, row in expected['files'].items():
            raw = sources[role][name]
            require(fingerprint(raw) == {k:row[k] for k in FP}
                    and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['gitBlob'], 'Original CSS source recipe Git bytes differ')
    modules = configparser.ConfigParser(interpolation=None, strict=True); modules.read_string(sources['external']['.gitmodules'].decode('utf-8-sig'))
    declaration = modules['submodule "src/cssparser"']
    require(declaration['path'] == p['gitlink']['path'] and declaration['url'] == p['gitlink']['repository'], 'Independent publisher CSS Gitlink declaration differs')
    recipe = xml(sources['external']['repos/cssparser.proj'])
    require([x.text for x in recipe.iter('BuildCommandArgs')][0] == '$(ProjectDirectory)/src/Microsoft.Css.Parser/Microsoft.Css.Parser.csproj'
            and [x.get('Command') for x in recipe.iter('Exec')] == ['$(DotnetToolCommand) restore /bl:restore.binlog $(BuildCommandArgs)  ',
                '$(DotnetToolCommand) build /bl:build.binlog $(BuildCommandArgs)', '$(DotnetToolCommand) pack /bl:pack.binlog $(BuildCommandArgs)'], 'Exact independent publisher CSS project recipe required')
    project = xml(sources['css']['src/Microsoft.Css.Parser/Microsoft.Css.Parser.csproj'])
    require([x.text for x in project.iter('TargetFramework')] == ['netstandard2.0']
            and [x.text for x in project.iter('PackageLicenseUrl')] == ['https://github.com/dotnet/cssparser/blob/master/LICENSE.txt'], 'Original CSS framework and separate license reference required')
    require(sources['css']['azure-pipelines.yml'].count(b'dotnet pack --configuration $(buildConfiguration) /p:VersionSuffix=$(Build.BuildNumber)') == 1,
            'Exact original publisher build-number expression required')
    versions = xml(sources['aspnetcore']['eng/Versions.props'])
    require([x.text for x in versions.iter('MicrosoftCssParserPackageVersion')] == [p['canonicalPackageVersion']], 'Actual SDK5 Razor CSS version declaration required')
    consumer = xml(sources['aspnetcore']['src/Razor/Microsoft.AspNetCore.Razor.Tools/src/rzc.csproj'])
    require(len([x for x in consumer.iter('Reference') if x.get('Include') == 'Microsoft.Css.Parser']) == 1, 'Actual SDK5 Razor CSS consumer declaration required')
    return dict(sourceBasis=p['sourceBasis'], independentPublisherCommit=p['sources']['external']['commit'], sourceCommit=p['sources']['css']['commit'],
        sdk5RazorCommit=p['sources']['aspnetcore']['commit'], packageAndSdk5ConsumerVersion=p['canonicalPackageVersion'],
        publisherVersionExpression='VersionSuffix=$(Build.BuildNumber)', publisherRecipeHasLiteralPackageVersion=False,
        sdk5DeclaredPublisherGitlink=False, actualPublisherBuildNumberObserved=False, publisherCompilerExecutionClaimed=False, localBuildClaimed=False)


def certificate_append(canonical, distributor, p=None):
    """No signature verification or rewriting; compare the original two images."""
    p = p or policy()
    require(fingerprint(canonical) == p['packages']['canonical']['memberFingerprint']
            and fingerprint(distributor) == p['packages']['razor']['memberFingerprint'], 'Exact original CSS image fingerprints required')
    require(canonical[:2] == distributor[:2] == b'MZ' and len(canonical) >= 512, 'Original CSS PE images required')
    pe = struct.unpack_from('<I', canonical, 60)[0]
    require(0 <= pe <= len(canonical) - 248 and canonical[pe:pe + 4] == b'PE\0\0', 'Original CSS PE layout differs')
    optional = pe + 24
    require(struct.unpack_from('<H', canonical, optional)[0] == 0x10b, 'Exact original CSS PE32 header required')
    checksum_at, security_at = optional + 64, optional + 96 + 4 * 8
    require(checksum_at == 216 and security_at == 280 and struct.unpack_from('<II',canonical,security_at) == (0,0), 'Exact canonical CSS checksum/security fields required')
    offset, size = struct.unpack_from('<II', distributor, security_at)
    expected = p['certificate']
    require(offset == len(canonical) == expected['offset'] and offset % 8 == 0 and size == expected['region']['bytes']
            and size % 8 == 0 and offset + size == len(distributor), 'Exact EOF-aligned CSS certificate region required')
    require(canonical[:checksum_at] == distributor[:checksum_at]
            and canonical[checksum_at + 4:security_at] == distributor[checksum_at + 4:security_at]
            and canonical[security_at + 8:] == distributor[security_at + 8:offset], 'Every original CSS image byte outside checksum/security fields must match')
    certificate = distributor[offset:]; length, revision, kind = struct.unpack_from('<IHH',certificate)
    require(fingerprint(certificate) == expected['region'] and length == expected['dwLength'] == size
            and revision == expected['revision'] == 0x200 and kind == expected['certificateType'] == 2
            and expected['alignmentPadding'] == '', 'Exact original CSS WIN_CERTIFICATE structure and bytes required')
    def checksum(data):
        total = 0
        for at in range(0,len(data),2):
            if checksum_at <= at < checksum_at + 4: continue
            total += int.from_bytes(data[at:at + 2], 'little'); total = (total & 65535) + (total >> 16)
        return (total & 65535) + (total >> 16) + len(data)
    for image in (canonical, distributor): require(struct.unpack_from('<I',image,checksum_at)[0] == checksum(image), 'Original CSS PE checksum must validate independently')
    return dict(kind='exact-original-certificate-append-correspondence', canonicalImage=fingerprint(canonical), observedDistributorImage=fingerprint(distributor),
        certificateRegion=expected, comparedOriginalImageBytes=len(canonical)-12, checksumBytes=4, securityDirectoryBytes=8,
        originalImagesUnchanged=True, signatureAuthenticityValidated=False, signerIdentityClaimed=False)


def inspect_packages(packages, p=None):
    p = p or policy(); result = {}
    for role, row in p['packages'].items():
        path = ordinary(packages[row['fingerprint']['sha256']])
        require(path.is_file() and path.stat().st_size == row['fingerprint']['bytes'], 'Exact original SDK5 CSS package required')
        raw = path.read_bytes(); require(fingerprint(raw) == row['fingerprint'], 'Original SDK5 CSS package bytes differ')
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            node=row['nuspec']; spec=archive.read(node['path']); require(fingerprint(spec)=={k:node[k]for k in FP}, 'Original CSS package nuspec differs')
            metadata=xml(spec).find('{*}metadata')
            if role=='canonical':
                require(metadata.findtext('{*}id')=='Microsoft.Css.Parser' and metadata.findtext('{*}version')==p['canonicalPackageVersion']
                        and metadata.find('{*}repository') is None and metadata.find('{*}license') is None
                        and metadata.findtext('{*}licenseUrl')=='https://github.com/dotnet/cssparser/blob/master/LICENSE.txt', 'Canonical CSS metadata absence and separate license reference required')
            else:
                require(metadata.findtext('{*}id')=='Microsoft.NET.Sdk.Razor' and metadata.findtext('{*}version')=='5.0.17-servicing.22215.7', 'Original SDK5 Razor package identity required')
            require(fingerprint(archive.read(row['member']))==row['memberFingerprint'], 'Original canonical/distributor CSS member differs')
            for name,expected in row['notices'].items(): require(fingerprint(archive.read(name))==expected, 'Original CSS distributor notice differs')
        result[role]=raw
    with zipfile.ZipFile(io.BytesIO(result['canonical']))as first,zipfile.ZipFile(io.BytesIO(result['razor']))as second:
        certificate_append(first.read(p['packages']['canonical']['member']),second.read(p['packages']['razor']['member']),p)
    return result


def bodies(packages, recipe):
    p=policy(); encode=lambda value:(json.dumps(value,indent=2)+'\n').encode(); data={}
    for role,raw in packages.items():
        require(fingerprint(raw)==p['packages'][role]['fingerprint'], 'Retained original CSS package bytes differ')
        data['packages/'+p['packages'][role]['fingerprint']['sha256']+'.nupkg']=raw
    with zipfile.ZipFile(io.BytesIO(packages['canonical']))as first,zipfile.ZipFile(io.BytesIO(packages['razor']))as second:
        proof=certificate_append(first.read(p['packages']['canonical']['member']),second.read(p['packages']['razor']['member']),p)
    data.update({'source-recipe.json':encode(recipe),'original-image-correspondence.json':encode(proof),
        'origin.json':encode(dict(schemaVersion=1,sdkVersion=SDK,kind=KIND,policySha256=POLICY_SHA256,sourceBasis=p['sourceBasis'],
            sdk5DeclaredPublisherGitlink=False,publisherCompilerExecutionClaimed=False,localBuildClaimed=False,signatureAuthenticityValidated=False))})
    return data


def prepare(packages, sources, destination):
    p=policy(); selected={}
    for role,row in p['sources'].items():
        path=ordinary(sources[role]); git=['git','-c','safe.directory='+str(path),'-C',str(path)]
        require(subprocess.check_output(git+['rev-parse','HEAD'],text=True).strip()==row['commit'], 'Exact original CSS source checkout required')
        selected[role]={n:ordinary(path/n).read_bytes()for n in row['files']}
    data=bodies(inspect_packages(packages,p),source_recipe(selected,p)); destination=ordinary(destination)
    require(not destination.exists(), 'Fresh original SDK5 CSS input tree required'); destination.mkdir(parents=True)
    for name,raw in data.items():
        target=ordinary(destination/name);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    return dict(name=ROOT_NAME,kind='tree',path=str(destination),role=ROLE)


def validate(release, manifest, packages):
    p=policy();release=ordinary(release);B=module('sdk5_css_source_bytes','musl_legacy_admission.py');P=module('sdk5_css_source_tree','package-used-source.py')
    require(manifest.get('sdkVersion')==SDK and manifest.get('targetRid')in('linux-musl-arm64','linux-musl-x64'), 'Independent SDK5 CSS source delivery required')
    index=B.checked(release/'sources',manifest['index']);archive_path=B.checked(release/'sources',manifest['archive']);roots={}
    for role,expected in p['sources'].items():
        selected=[r for r in manifest['roots']if r.get('kind')in('git','git-export')and r.get('commit')==expected['commit']and r.get('tree')==expected['tree']and not r.get('exclude')and not r.get('deleted')]
        require(len(selected)==1, 'Complete pristine original CSS source Git tree required: '+role);roots[role]=selected[0]
    require(any(r.get('path')==p['gitlink']['path']and r.get('commit')==p['gitlink']['commit']and r.get('root')==roots['css']['name']for r in roots['external'].get('submodules',[])), 'Independent publisher CSS Gitlink must bind its full original child source')
    data_roots=[r for r in manifest['roots']if r['name']==ROOT_NAME]
    require(len(data_roots)==1 and data_roots[0]['kind']=='tree'and data_roots[0].get('role')==ROLE and data_roots[0].get('commit')is None, 'Original CSS package data must retain its non-Git role')
    prefixes={r['name']+'/':role for role,r in roots.items()};indexed={};baselines={role:{}for role in roots}
    with index.open(encoding='utf-8')as stream:
        for line in stream:
            row=json.loads(line);name=row['path'];chosen=next(((pre,role)for pre,role in prefixes.items()if name.startswith(pre)),None)
            if chosen:
                prefix,role=chosen;relative=name[len(prefix):];require(name not in indexed and row.get('baseline'), 'Unique original CSS source baseline required')
                indexed[name]=(role,relative,row);baselines[role][relative]=row['baseline']
            elif name.startswith(ROOT_NAME+'/'):
                require(name not in indexed,'Duplicate original CSS data member');indexed[name]=(None,name[len(ROOT_NAME)+1:],row)
    for role,baseline in baselines.items():
        for child in roots[role].get('submodules',[]):baseline[child['path']]=dict(mode='160000',blob=child['commit'])
        require(P.baseline_tree(baseline)==p['sources'][role]['tree'], 'Complete original CSS source baseline tree differs')
    sources={role:{}for role in roots};actual={};seen=set()
    with tarfile.open(archive_path,'r|gz')as archive:
        for entry in archive:
            if entry.name not in indexed:continue
            role,name,expected=indexed[entry.name]
            require(entry.name not in seen and entry.size<=64*1024**2 and ((expected['mode']=='120000'and entry.issym()and entry.mode==0o777)
                or(expected['mode']in('100644','100755')and entry.isfile()and entry.size==expected['bytes']and entry.mode==(0o755 if expected['mode']=='100755'else 0o644))), 'Exact original CSS archive type/mode/size required')
            raw=entry.linkname.encode()if entry.issym()else archive.extractfile(entry).read();require(fingerprint(raw)=={k:expected[k]for k in FP},'Archived original CSS source bytes differ')
            if role:
                require(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==expected['baseline']['blob']and expected['mode']==expected['baseline']['mode'], 'Pristine original CSS Git blob or mode differs')
                if name in p['sources'][role]['files']:sources[role][name]=raw
            else:
                require(entry.isfile(),'Ordinary original CSS package data required');actual[name]=raw
            seen.add(entry.name)
    require(seen==indexed.keys(),'Complete original CSS source archive required')
    require(actual==bodies(inspect_packages(packages,p),source_recipe(sources,p)), 'Retained original CSS packages and source recipe differ')
    products={name:dict(row,sourceRoot=roots['css']['name'],sourceCommit=p['sources']['css']['commit'],sourceBasis=p['sourceBasis'],
        independentPublisherRoot=roots['external']['name'],independentPublisherCommit=p['sources']['external']['commit'],sdk5RazorRoot=roots['aspnetcore']['name'],
        observedDistributorImage=row['fingerprint'],signatureAuthenticityValidated=False)for name,row in p['products'].items()}
    return dict(kind=KIND,dataRoot=ROOT_NAME,products=products,sdk5DeclaredPublisherGitlink=False,publisherCompilerExecutionClaimed=False,
        localBuildClaimed=False,signatureAuthenticityValidated=False,qualificationAllowed=False,sourceAdmissionAllowed=False)
