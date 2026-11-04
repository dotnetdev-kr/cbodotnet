#!/usr/bin/env python3
"""Build and promote branded consumer archives beside immutable producer assets."""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tempfile

from distribution_contract import (ARCHITECTURES, BRANDING, REPOSITORY, load_contract,
                                   sha256_file, validate_qualified_producers)
from downstream_release import descriptor, encoded, load_status, ordinary_file, require, verify_report_signature
from downstream_publish import GitHubReleases, verify_remote_assets
from release_catalog import validate_release

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = 'distribution-manifest.json'
SIGNATURE = MANIFEST + '.asc'
PUBLIC_KEY = 'distribution-signing-key.gpg'
WORKFLOW = '.github/workflows/distribution-release.yml'
REPORT_CHECKS = {'command-aliases','cli-branding','version-stdout-compatible','sdk-list-paths',
    'host-root','source-integrity','payload-preservation','original-notices','relocation',
    'non-root','offline-network','offline-build-run','http-crypto-globalization'}


def sdk_tools():
    spec = importlib.util.spec_from_file_location('consumer_archive_sdk_tree', ROOT / 'scripts/test-distribution-coexistence.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fresh_directory(path):
    path = Path(path).absolute()
    require(path.parent.is_dir() and not path.exists() and not any(item.is_symlink() for item in [path,*path.parents]),
            'Use a fresh ordinary output directory')
    path.mkdir(mode=0o755)
    return path


def intake(directory, architecture, revision=1, *, contract=None, catalog=None):
    contract = contract if contract is not None else load_contract()
    require(architecture in ARCHITECTURES and type(revision) is int and 0 < revision < 2**31,
            'Exact architecture and positive archive revision required')
    directory = Path(directory)
    manifest_bytes = ordinary_file(directory / 'release-manifest.json').read_bytes()
    record = validate_release(json.loads(ordinary_file(directory / 'release.json').read_bytes()), manifest_bytes,
        ordinary_file(directory / 'SHA256SUMS').read_bytes(), REPOSITORY)
    version = record['sdkVersion']
    admitted = contract['releases'].get(version, {})
    source_sha = hashlib.sha256(manifest_bytes).hexdigest()
    require(admitted.get('manifestSha256') == source_sha, 'Canonical SDK manifest is not admitted by the reviewed source pin')
    validate_qualified_producers(record, admitted['target'], catalog)
    entry = record['architectures'][architecture]
    sdk = ordinary_file(directory / entry['sdk']['name'])
    require(descriptor(sdk) == {key: entry['sdk'][key] for key in ('name','size','sha256')}, 'Qualified SDK archive changed')
    result = dict(schemaVersion=1,kind='consumer-archive',status='prepared-unpublished',publicationAllowed=False,
        contractVersion=contract['schemaVersion'],sdkVersion=version,packageRevision=revision,architecture=architecture,
        sourceReleaseTag=record['tag'],sourceManifestSha256=source_sha,sourceManifestUrl=record['manifestUrl'],
        targetRid=ARCHITECTURES[architecture]['rid'],source=entry['source'],sdk=entry['sdk'],evidence=entry['evidence'],
        producer=entry['provenance'],branding=copy.deepcopy(BRANDING),licensePaths=admitted['licensePaths'],
        securitySupport=admitted['securitySupport'],validatedUserSpaces=list(admitted['archiveUserSpaces']))
    result['compatibility']=compatibility_policy(result)
    return result


def compatibility_policy(plan):
    from legacy_compat import required,load_policy,POLICY
    result=dict(required=required(plan))
    if result['required']:
        provider=load_policy()
        result.update(providerId=provider['providerId'],root=provider['root'],
            policySha256=hashlib.sha256(POLICY.read_text().replace('\r\n','\n').encode()).hexdigest(),
            companionName=f'cbodotnet-compat-rocky9-{provider["version"]}-linux-{plan["architecture"]}.tar.gz',
            archiveCaBundle='/etc/ssl/certs/ca-certificates.crt')
    return result


def identity(plan):
    return {key:plan[key] for key in ('sdkVersion','packageRevision','sourceReleaseTag','sourceManifestSha256','targetRid')}


def archive_stem(plan):
    return f'cbodotnet-{plan["sdkVersion"]}-linux-{plan["architecture"]}-r{plan["packageRevision"]}'


def archive_name(plan):
    return f'cbodotnet-sdk-{plan["sdkVersion"]}-linux-{plan["architecture"]}-branded-r{plan["packageRevision"]}.tar.gz'


def launcher_text(plan):
    versioned = '.'.join(plan['sdkVersion'].split('.')[:2])
    require(re.fullmatch(r'[1-9][0-9]*\.[0-9]+',versioned), 'Invalid SDK series')
    information = dict(schemaVersion=1,contractVersion=plan['contractVersion'],distributionBrand=BRANDING['displayName'],
        **identity(plan),brandingScope='distribution-wrapper',qualifiedPayloadModified=False,delivery='consumer-archive',compatibility=plan.get('compatibility',dict(required=False)))
    # The root is resolved only at execution, so movement never rewrites payload bytes.
    prefix = json.dumps(information,separators=(',',':'))[:-1] + ',"sdkRoot":"'
    replacements = {'@ARCH_ROOT@':'DOTNET_ROOT_X64' if plan['architecture']=='x64' else 'DOTNET_ROOT_ARM64',
        '@BRAND@':shlex.quote(BRANDING['displayName']),'@IDENTITY_PREFIX@':shlex.quote(prefix),'@IDENTITY_SUFFIX@':shlex.quote('"}')}
    from legacy_compat import launcher_environment
    replacements['@COMPAT@']=launcher_environment(dict(plan,variant='ubuntu-24.04'))
    template = (ROOT / 'scripts/cbodotnet-archive-launcher.sh.in').read_text(encoding='utf-8')
    return re.sub(r'@(?:ARCH_ROOT|BRAND|IDENTITY_PREFIX|IDENTITY_SUFFIX|COMPAT)@',lambda match:replacements[match[0]],template)


def payload_summary(rows):
    return dict(sha256=hashlib.sha256(encoded(rows)).hexdigest(),entries=len(rows),
        files=sum(row[0]=='file' for row in rows.values()),links=sum(row[0]=='link' for row in rows.values()))


def build_archive(inputs, architecture, revision, output, *, contract=None, catalog=None):
    plan = intake(inputs,architecture,revision,contract=contract,catalog=catalog)
    output = fresh_directory(output)
    tree = output / archive_stem(plan); tree.mkdir()
    payload = tree / 'payload'
    tools = sdk_tools()
    tools.extract_sdk(Path(inputs) / plan['sdk']['name'],payload)
    original = tools.snapshot(payload)
    require((payload / 'dotnet').is_file() and not (payload / 'dotnet').is_symlink()
            and os.access(payload / 'dotnet',os.X_OK),'Qualified payload lacks an executable host')
    for name in plan['licensePaths']:
        require((payload / name).is_file() and not (payload / name).is_symlink(),'Original SDK license/notice is absent')
    added = []
    if not (payload / 'metadata').exists():
        (payload / 'metadata').mkdir(mode=0o755); added.append('metadata')
    commands = []
    wrapper = launcher_text(plan).encode()
    for name in ('dotnet','cbodotnet','cbodotnet-' + '.'.join(plan['sdkVersion'].split('.')[:2])):
        path = tree / name; path.write_bytes(wrapper); path.chmod(0o755)
        commands.append(dict(path=name,mode='0755',size=len(wrapper),sha256=hashlib.sha256(wrapper).hexdigest()))
    (tree / 'distribution.json').write_bytes(encoded(dict(**plan,payloadDirectory='payload',additionalDirectories=added)))
    (tree / 'README.txt').write_text('Community Build of .NET (built by .NET Dev)\n\n'
        + 'Run ./cbodotnet, ./cbodotnet-' + '.'.join(plan['sdkVersion'].split('.')[:2]) + ' or ./dotnet.\n'
        + 'Add this extracted directory to PATH explicitly if desired. The unchanged SDK is under payload/.\n'
        + 'For direct apphost execution set DOTNET_ROOT to the absolute payload/ directory.\n'
        + 'Original licensing: payload/LICENSE.txt and payload/ThirdPartyNotices.txt.\n'
        + 'Source and qualification: ' + plan['sourceManifestUrl'] + '\n',encoding='utf-8',newline='\n')
    current = tools.snapshot(payload)
    require({key:value for key,value in current.items() if key not in added} == original,'Qualified payload bytes, modes or links changed')
    archive = output / archive_name(plan)
    import tarfile
    with archive.open('xb') as raw, gzip.GzipFile(filename='',fileobj=raw,mode='wb',mtime=0,compresslevel=6) as compressed:
        with tarfile.open(fileobj=compressed,mode='w|',format=tarfile.PAX_FORMAT) as tar:
            for path in [tree,*sorted(tree.rglob('*'))]:
                info = tar.gettarinfo(str(path),path.relative_to(output).as_posix())
                info.uid=info.gid=info.mtime=0; info.uname=info.gname=''
                if info.isfile():
                    with path.open('rb') as content: tar.addfile(info,content)
                else: tar.addfile(info)
    result = dict(schemaVersion=1,kind='consumer-archive-build',status='built-unpublished',publicationAllowed=False,
        plan=plan,artifact=descriptor(archive),directory=tree.name,commands=commands,
        qualifiedPayload=payload_summary(original),additionalDirectories=added)
    (output / 'package-build.json').write_bytes(encoded(result))
    return result


def metadata_patch(release, revision=1):
    """Draft only the title/body fields; callers control when metadata is applied."""
    tag = release.get('tag_name','')
    require(re.fullmatch(r'sdk-[1-9][0-9]*\.[0-9]+\.[0-9]+',tag),'Canonical SDK release required')
    version = tag[4:]
    replacement = f'https://github.com/{REPOSITORY}/releases/tag/distribution-archive-sdk-{version}-r{revision}'
    marker = '<!-- cbodotnet-unbranded-trial -->'
    previous = release.get('body','')
    if marker in previous:
        previous = previous.split('<!-- cbodotnet-original-release-notes -->\n',1)[-1]
    body = (marker + '\n**Trial / unbranded producer archive — direct installation is not recommended.**\n\n'
        + 'These assets preserve the original qualified SDK, used sources and evidence. Their CLI entrypoint has no '
        + 'Community Build branding and remains an immutable input for downstream packaging.\n\n'
        + '[Use the branded Community Build consumer archive](' + replacement + ') after that release has completed native '
        + 'validation and public verification. Published package and OCI choices are listed at https://dotnetdev.kr/cbodotnet/.\n\n'
        + 'Canonical tag, stable-release flags and asset bytes remain unchanged.\n\n'
        + '<!-- cbodotnet-original-release-notes -->\n' + previous)
    return dict(name=f'[Trial / not recommended] Unbranded .NET SDK {version}',body=body)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    build=commands.add_parser('build')
    build.add_argument('--inputs',type=Path,required=True); build.add_argument('--arch',choices=tuple(ARCHITECTURES),required=True)
    build.add_argument('--revision',type=int,default=1); build.add_argument('--output',type=Path,required=True)
    draft=commands.add_parser('draft-metadata'); draft.add_argument('--release',type=Path,required=True)
    bundle=commands.add_parser('bundle')
    bundle.add_argument('--builds',nargs='+',type=Path,required=True); bundle.add_argument('--reports',nargs='+',type=Path,required=True)
    bundle.add_argument('--inputs',nargs='+',type=Path,required=True); bundle.add_argument('--output',type=Path,required=True)
    bundle.add_argument('--compat-builds',nargs='*',type=Path,default=[])
    bundle.add_argument('--signing-key',required=True); bundle.add_argument('--keyring',type=Path,required=True)
    bundle.add_argument('--gnupg-home',type=Path); bundle.add_argument('--source-commit',required=True)
    bundle.add_argument('--source-run',required=True); bundle.add_argument('--source-attempt',required=True)
    for name in ('verify-bundle','publish'):
        promotion=commands.add_parser(name); promotion.add_argument('--bundle',type=Path,required=True)
        promotion.add_argument('--keyring',type=Path,required=True); promotion.add_argument('--receipt',type=Path)
    args=parser.parse_args()
    if args.command=='build': result=build_archive(args.inputs,args.arch,args.revision,args.output)
    elif args.command=='draft-metadata': result=metadata_patch(json.loads(args.release.read_bytes()))
    elif args.command=='bundle':
        from consumer_archive_release import create_bundle
        source=dict(repository=REPOSITORY,workflow=WORKFLOW,commit=args.source_commit,runId=args.source_run,runAttempt=args.source_attempt)
        result=create_bundle(args.builds,args.reports,args.inputs,args.output,args.signing_key,args.keyring,source,gnupg_home=args.gnupg_home,compatibility_files=args.compat_builds)
    else:
        from consumer_archive_release import validate_bundle,publish_bundle
        result=publish_bundle(args.bundle,args.keyring) if args.command=='publish' else validate_bundle(args.bundle,args.keyring)
        if args.receipt: args.receipt.write_bytes(encoded(result))
    print(json.dumps(result,sort_keys=True,indent=2))


if __name__=='__main__': main()
