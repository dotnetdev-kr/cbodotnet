#!/usr/bin/env python3
"""Build and promote branded consumer archives beside immutable producer assets."""
import argparse
import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
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
    'non-root','offline-network','offline-build-run','http-crypto-globalization','tls12-loopback'}
FUNCTIONAL_CHECKS={'consoleDllExecution','consoleApphostExecution','aspNetCoreLoopbackHttp','rsaSha256SignAndVerify',
    'cryptographicRandomBytes','frFrDecimalFormatting','tls12LoopbackHandshake'}


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
        securitySupport=admitted['securitySupport'],validatedUserSpaces=list(admitted['archiveUserSpaces']),archiveNamingVersion=2)
    if version in {'3.0.103','3.1.426'} and revision>=3:result['archiveLauncherVersion']=2
    result['compatibility']=compatibility_policy(result)
    native_http=native_http_compatibility_policy(result,admitted=admitted)
    if native_http is not None:result['nativeHttpCompatibility']=native_http
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
        if plan.get('archiveLauncherVersion')==2:
            result.pop('archiveCaBundle')
            result['archiveCaBundles']=['/etc/ssl/certs/ca-certificates.crt','/etc/pki/tls/certs/ca-bundle.crt']
    return result


def native_http_compatibility_policy(plan,*,admitted=None):
    if '.'.join(plan['sdkVersion'].split('.')[:2]) not in {'3.0','3.1'}:return None
    from legacy_curl import plan_policy
    result=plan_policy(plan)
    if admitted is not None:
        require(admitted.get('nativeHttpCompatibilityProvider')==result['providerId']
            and admitted.get('compatibilityProvider')==result['baseProviderId'],
            'Core3 consumer native HTTP compatibility provider is not admitted by the source contract')
    return result


def identity(plan):
    return {key:plan[key] for key in ('sdkVersion','packageRevision','sourceReleaseTag','sourceManifestSha256','targetRid')}


def archive_stem(plan):
    return f'cbodotnet-{plan["sdkVersion"]}-linux-{plan["architecture"]}-r{plan["packageRevision"]}'


def archive_name(plan):
    naming=plan.get('archiveNamingVersion',1)
    require(type(naming) is int and naming in (1,2),'Unsupported consumer archive naming version')
    qualifier='-branded' if naming==1 else ''
    return f'cbodotnet-sdk-{plan["sdkVersion"]}-linux-{plan["architecture"]}{qualifier}-r{plan["packageRevision"]}.tar.gz'


def archive_provider_records(plan):
    """Reconstruct exact companion trees from reviewed vendor/source policy pins.

    This does not authenticate an arbitrary extracted companion. Its caller must
    first verify the published archive and project signature; the generated
    launcher then rejects changes to this closed layout before using its loader
    paths. No live filesystem data participates in these expected values.
    """
    import legacy_compat as base
    import legacy_curl as curl
    arch=plan['architecture']
    require(arch in {'x64','aarch64'} and curl.required(plan),'Exact Core3 architecture required')
    records=[]
    for native_http,module,variable in ((False,base,'CBODOTNET_COMPAT_ROOT'),(True,curl,'CBODOTNET_CURL_COMPAT_ROOT')):
        policy=module.load_policy()
        inventory=[dict(path='lib',mode='0o755',type='directory')]
        for package in policy['architectures'][arch]['packages']:
            for item in package['files']:
                name=PurePosixPath(item['path']).name
                inventory.append(dict(path='lib/'+name,mode='0o755',type='file',size=item['size'],sha256=item['sha256']))
                for soname in item['soname']:
                    inventory.append(dict(path='lib/'+soname,mode='0o777',type='symlink',target=name))
            filename='LICENSE.curl.txt' if native_http else ('LICENSE.openssl.txt' if package['packageName']=='compat-openssl11' else 'LICENSE.icu.txt')
            require(len(package['licenses'])==1,'Exact companion license required')
            item=package['licenses'][0]
            inventory.append(dict(path=filename,mode='0o644',type='file',size=item['size'],sha256=item['sha256']))
        generated={'NOTICE.txt':module.notice_text(policy)}
        if not native_http:generated['openssl.cnf']=policy['opensslConfiguration']['content']
        for name,content in generated.items():
            raw=content.encode()
            inventory.append(dict(path=name,mode='0o644',type='file',size=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
        inventory.sort(key=lambda row:row['path'])
        manifest=dict(schemaVersion=1,providerId=policy['providerId'],architecture=arch,providerRoot=module.PROVIDER_ROOT,
            policySha256=hashlib.sha256(module.POLICY.read_text().replace('\r\n','\n').encode()).hexdigest(),
            signingFingerprint=module.FINGERPRINT,packages=policy['architectures'][arch]['packages'],
            sourcePackages=policy['sources'],key=policy['key'],securityScope=policy['securityScope'],files=copy.deepcopy(inventory))
        if native_http:manifest.update(baseProvider=policy['baseProvider'],nativeHttpComponents=policy['nativeHttpComponents'])
        else:manifest['opensslConfiguration']=policy['opensslConfiguration']
        raw=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
        inventory.append(dict(path='provider-manifest.json',mode='0o644',type='file',size=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
        inventory.sort(key=lambda row:row['path'])
        require(len({row['path'] for row in inventory})==len(inventory),'Duplicate companion layout')
        records.append(dict(variable=variable,root=module.PROVIDER_ROOT,providerId=policy['providerId'],inventory=inventory))
    return records


def archive_provider_preflight(plan):
    """Check a complete closed companion layout before setting any private LD path."""
    lines=['# Verify separately authenticated companions before activating private loader paths.',
        'for _cbodotnet_tool in sha256sum find readlink stat grep; do',
        '  command -v "$_cbodotnet_tool" >/dev/null 2>&1 || { echo "cbodotnet: companion verification requires sha256sum, find, readlink, stat and grep" >&2; exit 70; }',
        'done']
    for record in archive_provider_records(plan):
        lines += ['_cbodotnet_provider=${'+record['variable']+':-'+record['root']+'}',
            r'case "$_cbodotnet_provider" in /|*/|*//*|*/./*|*/../*|*/.|*/..|*:*|*\;*|*\$*) echo "cbodotnet: unsafe compatibility provider root" >&2; exit 70 ;; /*) ;; *) echo "cbodotnet: compatibility provider root must be absolute" >&2; exit 70 ;; esac',
            'if printf \'%s\' "$_cbodotnet_provider" | LC_ALL=C grep \'[[:cntrl:]]\' >/dev/null; then echo "cbodotnet: control characters in compatibility provider root" >&2; exit 70; fi',
            '_cbodotnet_parent=$_cbodotnet_provider',
            'while :; do',
            '  [ -d "$_cbodotnet_parent" ] && [ ! -L "$_cbodotnet_parent" ] || { echo "cbodotnet: compatibility provider directory is missing or symlinked" >&2; exit 70; }',
            '  [ "$_cbodotnet_parent" != / ] || break',
            '  _cbodotnet_parent=${_cbodotnet_parent%/*}; [ -n "$_cbodotnet_parent" ] || _cbodotnet_parent=/',
            'done']
        for row in record['inventory']:
            path='"$_cbodotnet_provider/'+row['path']+'"'
            require(re.fullmatch(r'[A-Za-z0-9._/-]+',row['path']) and '..' not in PurePosixPath(row['path']).parts,'Unsafe companion path pin')
            require(row['mode'] in {'0o644','0o755','0o777'},'Unreviewed companion file mode')
            lines.append('[ "$(stat -c %a -- '+path+')" = '+row['mode'][2:]+' ] || { echo "cbodotnet: companion file mode differs" >&2; exit 70; }')
            if row['type']=='directory':
                check='[ -d '+path+' ] && [ ! -L '+path+' ]'
            elif row['type']=='symlink':
                require(re.fullmatch(r'[A-Za-z0-9._-]+',row['target']),'Unsafe companion SONAME target')
                check='[ -L '+path+' ] && [ "$(readlink -- '+path+')" = '+shlex.quote(row['target'])+' ]'
            else:
                require(row['type']=='file' and re.fullmatch(r'[a-f0-9]{64}',row['sha256']),'Invalid companion file pin')
                lines += ['[ -f '+path+' ] && [ ! -L '+path+' ] && [ -r '+path+' ] || { echo "cbodotnet: missing or substituted companion file" >&2; exit 70; }',
                    '_cbodotnet_hash=$(sha256sum < '+path+') || { echo "cbodotnet: companion hash verification failed" >&2; exit 70; }',
                    '[ "${_cbodotnet_hash%% *}" = '+shlex.quote(row['sha256'])+' ] || { echo "cbodotnet: companion file hash differs from reviewed sources" >&2; exit 70; }']
                continue
            lines.append(check+' || { echo "cbodotnet: companion directory or SONAME differs" >&2; exit 70; }')
        lines += ['_cbodotnet_paths=$(find "$_cbodotnet_provider" -mindepth 1 -print) || { echo "cbodotnet: cannot inspect companion tree" >&2; exit 70; }',
            '_cbodotnet_count=0',
            'while IFS= read -r _cbodotnet_path; do',
            '  _cbodotnet_relative=${_cbodotnet_path#"$_cbodotnet_provider"/}',
            '  case "$_cbodotnet_relative" in '+ '|'.join(shlex.quote(row['path']) for row in record['inventory'])+') ;; *) echo "cbodotnet: unaccounted companion path" >&2; exit 70 ;; esac',
            '  _cbodotnet_count=$((_cbodotnet_count + 1))',
            'done <<EOF_CBODOTNET_PROVIDER_PATHS',
            '$_cbodotnet_paths',
            'EOF_CBODOTNET_PROVIDER_PATHS',
            '[ "$_cbodotnet_count" = '+str(len(record['inventory']))+' ] || { echo "cbodotnet: companion path inventory differs" >&2; exit 70; }']
    lines.append('unset _cbodotnet_tool _cbodotnet_provider _cbodotnet_parent _cbodotnet_hash _cbodotnet_paths _cbodotnet_path _cbodotnet_relative _cbodotnet_count')
    return '\n'.join(lines)+'\n'


def launcher_text(plan):
    versioned = '.'.join(plan['sdkVersion'].split('.')[:2])
    require(re.fullmatch(r'[1-9][0-9]*\.[0-9]+',versioned), 'Invalid SDK series')
    def ordered_policy(value,keys):
        return {key:value[key] for key in [*keys,*sorted(set(value)-set(keys))] if key in value}
    compatibility=ordered_policy(plan.get('compatibility',dict(required=False)),
        ('required','providerId','root','policySha256','companionName','archiveCaBundle'))
    information = dict(schemaVersion=1,contractVersion=plan['contractVersion'],distributionBrand=BRANDING['displayName'],
        **identity(plan),brandingScope='distribution-wrapper',qualifiedPayloadModified=False,delivery='consumer-archive',compatibility=compatibility)
    if 'nativeHttpCompatibility' in plan:
        information['nativeHttpCompatibility']=ordered_policy(plan['nativeHttpCompatibility'],
            ('required','providerId','root','policySha256','companionName','baseProviderId'))
    launcher_version=plan.get('archiveLauncherVersion',1)
    require(type(launcher_version) is int and launcher_version in (1,2),'Unsupported consumer archive launcher version')
    if launcher_version==2:
        require(plan['sdkVersion'] in {'3.0.103','3.1.426'} and plan['packageRevision']>=3,
                'The new archive launcher is only admitted for new Core3 revisions')
        information['archiveLauncherVersion']=2
    # The root is resolved only at execution, so movement never rewrites payload bytes.
    prefix = json.dumps(information,separators=(',',':'))[:-1] + ',"sdkRoot":"'
    replacements = {'@ARCH_ROOT@':'DOTNET_ROOT_X64' if plan['architecture']=='x64' else 'DOTNET_ROOT_ARM64',
        '@BRAND@':shlex.quote(BRANDING['displayName']),'@IDENTITY_PREFIX@':shlex.quote(prefix),'@IDENTITY_SUFFIX@':shlex.quote('"}')}
    from legacy_compat import launcher_environment
    replacements['@COMPAT@']=launcher_environment(dict(plan,variant='ubuntu-24.04'))
    if launcher_version==2:
        from legacy_curl import launcher_environment as native_http_environment
        # Restore a parent Community scope before verification subprocesses run.
        restore=launcher_environment(dict(plan,sdkVersion='10.0.403',variant='ubuntu-24.04'))
        ca_bundles=plan['compatibility'].get('archiveCaBundles')
        require(ca_bundles==['/etc/ssl/certs/ca-certificates.crt','/etc/pki/tls/certs/ca-bundle.crt'],
                'Exact reviewed archive CA bundle candidates required')
        ca_lines=['# Preserve an explicit caller CA, including an intentionally empty value.',
            'if [ "${CBODOTNET_COMPAT_SAVED_SSL_CERT_FILE_SET-}" != 1 ]; then']
        for index,path in enumerate(ca_bundles):
            ca_lines.append(('  if' if index==0 else '  elif')+' [ -r '+shlex.quote(path)+' ]; then export SSL_CERT_FILE='+shlex.quote(path))
        ca_lines+=['  else echo "cbodotnet: install a reviewed system CA bundle or set SSL_CERT_FILE explicitly" >&2; exit 70',
                   '  fi','fi']
        replacements['@COMPAT@']=restore+archive_provider_preflight(plan)+replacements['@COMPAT@']+'\n'.join(ca_lines)+'\n'+native_http_environment(plan)
    template = (ROOT / 'scripts/cbodotnet-archive-launcher.sh.in').read_text(encoding='utf-8')
    return re.sub(r'@(?:ARCH_ROOT|BRAND|IDENTITY_PREFIX|IDENTITY_SUFFIX|COMPAT)@',lambda match:replacements[match[0]],template)


def payload_summary(rows):
    return dict(sha256=hashlib.sha256(encoded(rows)).hexdigest(),entries=len(rows),
        files=sum(row[0]=='file' for row in rows.values()),links=sum(row[0]=='link' for row in rows.values()))


def verify_wrapper_license(tree,build,*,current=False):
    expected=build.get('wrapperLicense')
    require(build.get('archiveLayoutVersion')==2 and isinstance(expected,dict)
        and expected.get('name')=='LICENSE.wrapper.txt' and expected.get('mode')=='0644','Consumer archive wrapper license is absent')
    path=ordinary_file(Path(tree)/'LICENSE.wrapper.txt')
    require(dict(descriptor(path),mode=format(stat.S_IMODE(path.stat().st_mode),'04o'))==expected,
        'Consumer wrapper license bytes or mode changed')
    if current:require(path.read_bytes()==ordinary_file(ROOT/'LICENSE').read_bytes(),'Consumer wrapper license differs from exact project LICENSE')
    return expected


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
    admitted=(contract if contract is not None else load_contract())['releases'][plan['sdkVersion']]
    approved=admitted.get('additionalDirectories',['metadata'])
    require(approved in ([],['metadata']),'Unreviewed consumer payload directory addition')
    added = []
    for name in approved:
        if not (payload/name).exists():
            (payload/name).mkdir(mode=0o755);added.append(name)
    commands = []
    wrapper = launcher_text(plan).encode()
    for name in ('dotnet','cbodotnet','cbodotnet-' + '.'.join(plan['sdkVersion'].split('.')[:2])):
        path = tree / name; path.write_bytes(wrapper); path.chmod(0o755)
        commands.append(dict(path=name,mode='0755',size=len(wrapper),sha256=hashlib.sha256(wrapper).hexdigest()))
    wrapper_license=tree/'LICENSE.wrapper.txt'
    wrapper_license.write_bytes(ordinary_file(ROOT/'LICENSE').read_bytes());wrapper_license.chmod(0o644)
    (tree / 'distribution.json').write_bytes(encoded(dict(**plan,payloadDirectory='payload',additionalDirectories=added)))
    (tree / 'README.txt').write_text('Community Build of .NET (built by .NET Dev)\n\n'
        + 'Run ./cbodotnet, ./cbodotnet-' + '.'.join(plan['sdkVersion'].split('.')[:2]) + ' or ./dotnet.\n'
        + 'Add this extracted directory to PATH explicitly if desired. The unchanged SDK is under payload/.\n'
        + ('For direct apphost execution set DOTNET_ROOT and the complete provider environment below.\n'
           if plan.get('archiveLauncherVersion')==2 else 'For direct apphost execution set DOTNET_ROOT to the absolute payload/ directory.\n')
        + 'Original licensing: payload/LICENSE.txt and payload/ThirdPartyNotices.txt.\n'
        + 'Additional consumer wrappers: LICENSE.wrapper.txt (exact cbodotnet project MIT notice).\n'
        + 'Source and qualification: ' + plan['sourceManifestUrl'] + '\n'
        + ('Core3 additionally requires both separately managed compatibility companions.\n'
           + 'Native HTTP provider: ' + plan['nativeHttpCompatibility']['root'] + '\n'
           + 'Companion: ' + plan['nativeHttpCompatibility']['companionName'] + '\n'
           if 'nativeHttpCompatibility' in plan else '')
        + ('\nCore3 launcher contract v2:\n'
           + 'Authenticate the project distribution-manifest.json and detached signature first, then verify/extract the exact SDK and both companion archives.\n'
           + 'The launcher checks the pinned companion bytes, metadata, modes and SONAME layout; it does not perform project GPG verification.\n'
           + 'Set CBODOTNET_COMPAT_ROOT and CBODOTNET_CURL_COMPAT_ROOT to the absolute companion roots under their extracted rootfs directories.\n'
           + 'Roots must be ordinary directories with no symlink ancestors, controls, :, ; or $ loader syntax; ordinary spaces are supported.\n'
           + 'Runtime verification requires coreutils sha256sum/readlink/stat, find and grep.\n'
           + 'An explicit SSL_CERT_FILE is preserved. Otherwise the first readable reviewed stock CA path is used: /etc/ssl/certs/ca-certificates.crt or /etc/pki/tls/certs/ca-bundle.crt.\n'
           + 'CLI child processes get curl/lib before SSL/ICU/lib, private openssl.cnf, CLR_OPENSSL_VERSION_OVERRIDE=1.1 and CLR_ICU_VERSION_OVERRIDE=67.\n'
           + 'Direct apphosts require that same complete environment in addition to DOTNET_ROOT; setting DOTNET_ROOT alone is insufficient.\n'
           + 'Direct apphost example from this extracted archive directory, after companion verification/root setup:\n'
           + '  unset DOTNET_ROOT_X64 DOTNET_ROOT_ARM64 DOTNET_ROOT_X86\n'
           + '  export DOTNET_ROOT="$PWD/payload"\n'
           + '  export LD_LIBRARY_PATH="$CBODOTNET_CURL_COMPAT_ROOT/lib:$CBODOTNET_COMPAT_ROOT/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"\n'
           + '  export OPENSSL_CONF="$CBODOTNET_COMPAT_ROOT/openssl.cnf"\n'
           + '  export CLR_OPENSSL_VERSION_OVERRIDE=1.1 CLR_ICU_VERSION_OVERRIDE=67\n'
           + '  export SSL_CERT_FILE=/absolute/path/to/the/reviewed/system/CA-bundle\n'
           + '  ./your-apphost\n'
           if plan.get('archiveLauncherVersion')==2 else ''),encoding='utf-8',newline='\n')
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
    result = dict(schemaVersion=1,kind='consumer-archive-build',status='built-unpublished',publicationAllowed=False,archiveLayoutVersion=2,
        plan=plan,artifact=descriptor(archive),directory=tree.name,commands=commands,
        wrapperLicense=dict(descriptor(wrapper_license),mode='0644'),
        qualifiedPayload=payload_summary(original),additionalDirectories=added)
    verify_wrapper_license(tree,result,current=True)
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
    bundle.add_argument('--native-http-compat-builds',nargs='*',type=Path,default=[])
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
        result=create_bundle(args.builds,args.reports,args.inputs,args.output,args.signing_key,args.keyring,source,gnupg_home=args.gnupg_home,
            compatibility_files=args.compat_builds,native_http_compatibility_files=args.native_http_compat_builds)
    else:
        from consumer_archive_release import validate_bundle,publish_bundle
        result=publish_bundle(args.bundle,args.keyring) if args.command=='publish' else validate_bundle(args.bundle,args.keyring)
        if args.receipt: args.receipt.write_bytes(encoded(result))
    print(json.dumps(result,sort_keys=True,indent=2))


if __name__=='__main__': main()
