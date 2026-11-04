"""Signed, immutable promotion for the separate branded consumer archive channel."""
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from consumer_archive import (ARCHITECTURES, BRANDING, FUNCTIONAL_CHECKS, MANIFEST, PUBLIC_KEY, REPORT_CHECKS, REPOSITORY,
    ROOT, SIGNATURE, WORKFLOW, archive_name, compatibility_policy, descriptor, encoded, identity, intake, launcher_text,
    load_contract, load_status, ordinary_file, payload_summary, require, sdk_tools, verify_report_signature)
from downstream_publish import GitHubReleases, verify_remote_assets


def release_tag(version, revision):
    require(re.fullmatch(r'[1-9][0-9]*\.[0-9]+\.[0-9]+',version) and type(revision) is int and revision > 0,
            'Exact consumer archive release identity required')
    return f'distribution-archive-sdk-{version}-r{revision}'


def workflow_identity(value):
    require(isinstance(value,dict) and value.get('repository') == REPOSITORY and value.get('workflow') == WORKFLOW
        and re.fullmatch(r'[a-f0-9]{40}',value.get('commit',''))
        and all(re.fullmatch(r'[1-9][0-9]*',str(value.get(key,''))) for key in ('runId','runAttempt')),
        'The approved protected workflow and exact source run identity are required')
    return value


def verify_build(build_file, inputs):
    build_file=ordinary_file(build_file)
    build=json.loads(build_file.read_bytes())
    plan=build['plan']
    canonical=intake(inputs,plan['architecture'],plan['packageRevision'])
    require(plan == canonical and build.get('kind') == 'consumer-archive-build' and build.get('publicationAllowed') is False,
        'Archive build differs from its canonical qualified source')
    archive=ordinary_file(build_file.parent / build['artifact']['name'])
    require(descriptor(archive) == build['artifact'] and archive.name == archive_name(plan),'Consumer archive bytes changed')
    tools=sdk_tools()
    with tempfile.TemporaryDirectory(prefix='cbodotnet-consumer-verify-') as temporary:
        temporary=Path(temporary)
        tools.extract_sdk(Path(inputs) / plan['sdk']['name'],temporary / 'original')
        original=tools.snapshot(temporary / 'original')
        tools.extract_sdk(archive,temporary / 'consumer')
        tree=temporary / 'consumer' / build['directory']
        require(set(path.name for path in (temporary / 'consumer').iterdir()) == {build['directory']},'Unexpected consumer archive roots')
        expected_names={'dotnet','cbodotnet','cbodotnet-'+'.'.join(plan['sdkVersion'].split('.')[:2]),'payload','README.txt','distribution.json'}
        require(set(path.name for path in tree.iterdir()) == expected_names,'Unexpected consumer archive entrypoints')
        require(build['qualifiedPayload'] == payload_summary(original),'Archive source payload inventory changed')
        observed=tools.snapshot(tree / 'payload')
        added=build['additionalDirectories']
        approved=load_contract()['releases'][plan['sdkVersion']].get('additionalDirectories',['metadata'])
        require(added in ([],['metadata']) and set(added)<=set(approved) and all(name not in original and observed.get(name)==['directory',0o755] for name in added)
            and {key:value for key,value in observed.items() if key not in added} == original,'Consumer archive changed qualified payload bytes, modes or links')
        expected_wrapper=launcher_text(plan).encode()
        expected_commands=[]
        for name in ('dotnet','cbodotnet','cbodotnet-'+'.'.join(plan['sdkVersion'].split('.')[:2])):
            path=tree / name
            require(path.is_file() and not path.is_symlink() and path.read_bytes()==expected_wrapper
                and path.stat().st_mode & 0o777 == 0o755,'Consumer archive wrapper differs from reviewed implementation')
            expected_commands.append(dict(path=name,mode='0755',size=len(expected_wrapper),sha256=hashlib.sha256(expected_wrapper).hexdigest()))
        require(build['commands'] == expected_commands,'Consumer archive command inventory differs')
        require(json.loads((tree / 'distribution.json').read_bytes()) == dict(**plan,payloadDirectory='payload',additionalDirectories=added),
            'Consumer archive provenance differs')
    return build,archive


def validate_native_report(report, build, source):
    plan=build['plan']
    require(report.get('schemaVersion') == 1 and report.get('scope') == 'consumer-archive-installation' and report.get('status') == 'passed',
        'A complete native consumer archive installation report is required')
    require(report.get('architecture') == plan['architecture'] and report.get('identity') == identity(plan)
        and report.get('artifact') == build['artifact'] and report.get('commands') == build['commands']
        and report.get('qualifiedPayload') == build['qualifiedPayload'] and report.get('orchestration') == source,
        'Native consumer report is not bound to the exact source, archive and generated commands')
    require(report.get('networkForBuild') == 'none' and report.get('checks') == dict.fromkeys(REPORT_CHECKS,'passed'),
        'Native consumer checks are incomplete')
    spaces=report.get('userSpaces',[])
    require(len(spaces) == len(plan['validatedUserSpaces']) and {item.get('variant') for item in spaces} == set(plan['validatedUserSpaces']),
        'Native consumer user-space matrix is incomplete')
    for space in spaces:
        require(space.get('status') == 'passed' and space.get('networkForBuild') == 'none'
            and space.get('native') is True and space.get('architecture') == plan['architecture']
            and space.get('checks') == dict.fromkeys(REPORT_CHECKS,'passed')
            and space.get('functionalChecks') == dict.fromkeys(FUNCTIONAL_CHECKS,'passed'),'A native archive user-space gate failed')
    return report


def verify_compatibility(record_file,plan):
    import legacy_compat as compatibility
    path=ordinary_file(record_file); record=json.loads(path.read_bytes()); policy=compatibility.load_policy()
    require(record.get('architecture')==plan['architecture'] and record.get('providerRoot')==plan['compatibility']['root']
        and record.get('policySha256')==plan['compatibility']['policySha256'],'Consumer companion provider identity changed')
    manifest=record['manifest']
    require(manifest['packages']==policy['architectures'][plan['architecture']]['packages'] and manifest['sourcePackages']==policy['sources']
        and manifest['signingFingerprint']==policy['signingFingerprint'] and manifest['opensslConfiguration']==policy['opensslConfiguration'],
        'Consumer companion source provenance differs from reviewed provider policy')
    companion=record['companion']; require(companion['path']==plan['compatibility']['companionName'],'Consumer companion filename changed')
    archive=ordinary_file(path.parent/companion['path'])
    require(descriptor(archive)==dict(name=companion['path'],size=companion['size'],sha256=companion['sha256']),'Consumer companion bytes changed')
    with tempfile.TemporaryDirectory(prefix='cbodotnet-consumer-companion-') as temporary:
        extracted=Path(temporary)/'companion';sdk_tools().extract_sdk(archive,extracted)
        root=extracted/'rootfs'/compatibility.PROVIDER_ROOT.lstrip('/')
        compatibility.validate_tree(root,policy,plan['architecture'])
        require(json.loads((root/'provider-manifest.json').read_bytes())==manifest
            and json.loads((extracted/'provider-manifest.json').read_bytes())==manifest,'Consumer companion manifest changed')
        require([item for item in compatibility.tree_inventory(root) if item['path']!='provider-manifest.json']==manifest['files'],
            'Consumer companion file inventory changed')
    return record,archive


def create_bundle(build_files, report_files, inputs, output, signing_key, keyring, source, *, gnupg_home=None, policy=None,compatibility_files=()):
    from consumer_archive import fresh_directory
    source=workflow_identity(source)
    require(len(build_files)==len(report_files)==len(inputs)==2,'Both native consumer architectures are mandatory')
    policy=policy if policy is not None else load_status()
    records=[]; assets={}; observed=set(); first=None; companions=[]
    compatibility_files={json.loads(ordinary_file(path).read_bytes())['architecture']:path for path in compatibility_files}
    output=fresh_directory(output)

    def copy(path,name=None):
        path=ordinary_file(path); name=name or path.name
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',name) and name not in assets,'Conflicting consumer release asset')
        shutil.copyfile(path,output/name); assets[name]=descriptor(output/name)
        return name

    for build_file,report_file,input_dir in zip(build_files,report_files,inputs):
        build,archive=verify_build(build_file,input_dir)
        plan=build['plan']; arch=plan['architecture']
        require(arch not in observed,'Duplicate native consumer architecture'); observed.add(arch)
        common={key:plan[key] for key in ('sdkVersion','packageRevision','sourceReleaseTag','sourceManifestSha256')}
        require(first is None or first==common,'Consumer publication mixes SDK source identities'); first=common
        report_file=ordinary_file(report_file)
        report=json.loads(report_file.read_bytes()); validate_native_report(report,build,source)
        if plan['compatibility']['required']:
            require(arch in compatibility_files,'Required separately managed consumer companion is missing')
            provider,companion=verify_compatibility(compatibility_files.pop(arch),plan)
            require(report.get('compatibility',{}).get('companion')==provider['companion']
                and report['compatibility']['manifest']==provider['manifest'],'Native consumer proof names another compatibility companion')
            companions.append(dict(architecture=arch,record=provider,asset=copy(companion)))
        else:require(report.get('compatibility',{'required':False})=={'required':False},'Unexpected compatibility provider for modern SDK')
        artifact_asset=copy(archive)
        report_asset=copy(report_file,'archive-'+arch+'--installation-report.json')
        command=['gpg']+(['--homedir',str(gnupg_home)] if gnupg_home else [])
        report_signature=output/(report_asset+'.asc')
        subprocess.run(command+['--batch','--yes','--armor','--local-user',signing_key,'--output',str(report_signature),'--detach-sign',str(output/report_asset)],check=True)
        require(verify_report_signature(output/report_asset,report_signature,keyring,policy,WORKFLOW)==signing_key.upper(),'Unexpected native report signer')
        assets[report_signature.name]=descriptor(report_signature)
        records.append(dict(architecture=arch,build=build,artifactAsset=artifact_asset,reportAsset=report_asset,signatureAsset=report_signature.name))
    require(observed==set(ARCHITECTURES),'Incomplete consumer archive architecture matrix')
    require(not compatibility_files,'Unexpected or duplicate compatibility provider artifacts')
    copy(keyring,PUBLIC_KEY)
    # Retain the exact original manifest and checksums in the new signed release.
    for filename,public in [('release-manifest.json','source-release-manifest.json'),('SHA256SUMS','source-SHA256SUMS')]:
        data=[ordinary_file(Path(directory)/filename).read_bytes() for directory in inputs]
        require(data[0]==data[1],'Canonical two-architecture source metadata differs')
        (output/public).write_bytes(data[0]); assets[public]=descriptor(output/public)
    manifest=dict(schemaVersion=1,kind='branded-consumer-archive-publication',wrapperPolicyVersion=1,contractVersion=load_contract()['schemaVersion'],
        repository=REPOSITORY,tag=release_tag(first['sdkVersion'],first['packageRevision']),identity=dict(channel='archive',**first),
        targetCommit=source['commit'],sourceOrchestration=source,signingFingerprint=signing_key.upper(),status='validated-complete-matrix',
        records=sorted(records,key=lambda item:item['architecture']),compatibility=sorted(companions,key=lambda item:item['architecture']),
        assets=[assets[name] for name in sorted(assets)])
    (output/MANIFEST).write_bytes(encoded(manifest))
    command=['gpg']+(['--homedir',str(gnupg_home)] if gnupg_home else [])
    subprocess.run(command+['--batch','--yes','--armor','--local-user',signing_key,'--output',str(output/SIGNATURE),'--detach-sign',str(output/MANIFEST)],check=True)
    validate_bundle(output,keyring,policy=policy)
    return manifest


def validate_bundle(directory,keyring,*,policy=None,historical=False,metadata_only=False):
    directory=Path(directory).absolute(); policy=policy if policy is not None else load_status()
    data=ordinary_file(directory/MANIFEST).read_bytes()
    require(len(data)<=16*1024**2,'Consumer publication manifest exceeds its bound')
    manifest=json.loads(data)
    require(manifest.get('schemaVersion')==1 and manifest.get('kind')=='branded-consumer-archive-publication'
        and manifest.get('wrapperPolicyVersion')==1 and manifest.get('repository')==REPOSITORY
        and manifest.get('status')=='validated-complete-matrix','Invalid consumer publication manifest')
    source=workflow_identity(manifest['sourceOrchestration']); common=manifest['identity']
    require(common.get('channel')=='archive' and manifest['tag']==release_tag(common['sdkVersion'],common['packageRevision'])
        and manifest['targetCommit']==source['commit'],'Consumer release immutable identity differs')
    contract=load_contract(); admitted=contract['releases'].get(common['sdkVersion'],{})
    require(manifest['contractVersion']==contract['schemaVersion'] and admitted.get('manifestSha256')==common['sourceManifestSha256']
        and common['sourceReleaseTag']=='sdk-'+common['sdkVersion'],'Consumer canonical source is no longer admitted')
    signer=verify_report_signature(directory/MANIFEST,directory/SIGNATURE,keyring,policy,WORKFLOW,historical=historical)
    require(signer==manifest['signingFingerprint'],'Unexpected consumer manifest signer')
    assets=manifest['assets']; names=[item['name'] for item in assets]
    records=manifest['records']; require(len(records)==2 and {item['architecture'] for item in records}==set(ARCHITECTURES),
        'Consumer publication matrix is incomplete')
    large={item['artifactAsset'] for item in records}|{item['asset'] for item in manifest.get('compatibility',[])}
    expected_names=(set(names)-large if metadata_only else set(names))|{MANIFEST,SIGNATURE}
    require(len(set(names))==len(names) and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',name) for name in names)
        and set(names).isdisjoint({MANIFEST,SIGNATURE}) and {item.name for item in directory.iterdir()}==expected_names,
        'Consumer bundle has missing, unsafe or unexpected assets')
    indexed={item['name']:item for item in assets}
    for item in assets:
        if metadata_only and item['name'] in large:continue
        require(descriptor(ordinary_file(directory/item['name']))==item,'Consumer frozen asset changed')
    require(hashlib.sha256(ordinary_file(directory/'source-release-manifest.json').read_bytes()).hexdigest()==common['sourceManifestSha256'],
        'Consumer source manifest byte binding changed')
    from distribution_contract import validate_qualified_producers
    canonical=json.loads((directory/'source-release-manifest.json').read_bytes())
    validate_qualified_producers(canonical,admitted['target'])
    for item in records:
        build=item['build']; plan=build['plan']; arch=item['architecture']
        spaces_ok=(set(plan['validatedUserSpaces'])<=set(admitted['archiveUserSpaces']) if historical else plan['validatedUserSpaces']==admitted['archiveUserSpaces'])
        require(plan['architecture']==arch and all(plan.get(key)==value for key,value in common.items() if key!='channel')
            and plan['branding']==BRANDING and spaces_ok,
            'Consumer signed plan differs from current source admission')
        if not historical:require(plan['compatibility']==compatibility_policy(plan),'Consumer compatibility provider policy is no longer admitted')
        require(plan['sdk']==dict(canonical['architectures'][arch]['sdk'],url=f'https://github.com/{REPOSITORY}/releases/download/{common["sourceReleaseTag"]}/'+canonical['architectures'][arch]['sdk']['name'])
            and plan['producer']==canonical['architectures'][arch]['provenance'],'Consumer signed source SDK/producer changed')
        require(indexed[item['artifactAsset']]==build['artifact'],'Consumer signed archive digest binding changed')
        report=json.loads((directory/item['reportAsset']).read_bytes()); validate_native_report(report,build,source)
        require(verify_report_signature(directory/item['reportAsset'],directory/item['signatureAsset'],keyring,policy,WORKFLOW,historical=historical)==signer,
            'Consumer native report signature differs from publication signer')
        companion=[row for row in manifest.get('compatibility',[]) if row['architecture']==arch]
        if plan['compatibility']['required']:
            require(len(companion)==1,'Signed consumer compatibility matrix is incomplete')
            companion=companion[0]
            require(companion['record']['policySha256']==plan['compatibility']['policySha256']
                and indexed[companion['asset']]==dict(name=companion['record']['companion']['path'],
                    size=companion['record']['companion']['size'],sha256=companion['record']['companion']['sha256'])
                and report['compatibility']['manifest']==companion['record']['manifest'],'Signed consumer companion binding changed')
        else:require(not companion,'Unexpected signed consumer compatibility companion')
    require(len(manifest.get('compatibility',[]))==(2 if records[0]['build']['plan']['compatibility']['required'] else 0),
        'Unexpected signed consumer compatibility records')
    return manifest


def publish_bundle(directory,keyring,*,policy=None,transport=None):
    directory=Path(directory).absolute(); manifest=validate_bundle(directory,keyring,policy=policy)
    expected={item['name']:item for item in manifest['assets']}
    expected.update({name:descriptor(directory/name) for name in (MANIFEST,SIGNATURE)})
    transport=transport or GitHubReleases()
    release=transport.find(manifest['tag'])
    if release is None: release=transport.create(manifest)
    require(release.get('tag_name')==manifest['tag'] and release.get('target_commitish')==manifest['targetCommit']
        and release.get('prerelease') is False,'Unrelated existing release uses consumer identity')
    existing={item['name']:item for item in release.get('assets',[])}
    require(len(existing)==len(release.get('assets',[])) and set(existing)<=set(expected),'Unexpected existing consumer asset')
    with tempfile.TemporaryDirectory(prefix='cbodotnet-consumer-existing-') as temporary:
        for name,item in existing.items():
            path=Path(temporary)/name; transport.download(item,path,public=not release['draft'])
            require(descriptor(path)==expected[name],'Refusing to overwrite changed existing consumer assets')
    missing=set(expected)-set(existing)
    require(not missing or release['draft'] is True,'An incomplete public consumer release cannot be repaired in place')
    for name in sorted(missing): transport.upload(release,directory/name)
    for attempt in range(4):
        release=transport.get(release)
        if {item.get('name') for item in release.get('assets',[])}==set(expected):break
        require(attempt<3,'Consumer release asset listing did not converge')
        time.sleep(2**attempt)
    verify_remote_assets(release,expected,transport)
    if release['draft']: release=transport.publish(release)
    for attempt in range(4):
        release=transport.get(release)
        if release.get('draft') is False and release.get('html_url')==f'https://github.com/{REPOSITORY}/releases/tag/{manifest["tag"]}':break
        require(attempt<3,'Consumer release remained a draft or public URL did not converge')
        time.sleep(2**attempt)
    verify_remote_assets(release,expected,transport,public=True)
    base=f'https://github.com/{REPOSITORY}/releases/download/{manifest["tag"]}/'
    return dict(schemaVersion=1,kind='consumer-archive-publication-receipt',status='published-public-bytes-verified',
        consumerInstallationStatus='pending-native-public-verification',tag=manifest['tag'],identity=manifest['identity'],
        releaseUrl=release['html_url'],manifestUrl=base+MANIFEST,manifestSha256=expected[MANIFEST]['sha256'],signatureUrl=base+SIGNATURE,
        signingFingerprint=manifest['signingFingerprint'],assets=[dict(item,url=base+name) for name,item in sorted(expected.items())])
