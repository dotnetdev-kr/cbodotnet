"""Native candidates and guarded publication of the separately qualified musl SDK."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.request

import musl_archive as ARCHIVE
import musl_contract as CONTRACT
from downstream_release import descriptor, encoded, ordinary_file, require
from downstream_publish import GitHubReleases
from musl_release import WORKFLOW
from release_catalog import get_bytes

ROOT = CONTRACT.ROOT


def fresh(path):
    return ARCHIVE.fresh_directory(path)


def orchestration():
    require(os.environ.get('GITHUB_REPOSITORY') == CONTRACT.REPOSITORY
            and os.environ.get('GITHUB_REF') == 'refs/heads/main'
            and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and os.environ.get('GITHUB_WORKFLOW_REF','').startswith(CONTRACT.REPOSITORY+'/'+WORKFLOW+'@'),
            'Native musl delivery must originate in the reviewed main-branch workflow')
    result = dict(repository=CONTRACT.REPOSITORY, workflow=WORKFLOW, commit=os.environ.get('GITHUB_SHA',''),
        runId=os.environ.get('GITHUB_RUN_ID',''), runAttempt=os.environ.get('GITHUB_RUN_ATTEMPT',''))
    require(re.fullmatch(r'[a-f0-9]{40}',result['commit'])
            and all(re.fullmatch(r'[1-9][0-9]*',result[name]) for name in ('runId','runAttempt')),
            'Exact musl delivery orchestration identity is required')
    return result


def download_asset(url, path, expected):
    """Public artifact requests never contain a GitHub authorization header."""
    require(isinstance(url,str) and url.startswith(f'https://github.com/{CONTRACT.REPOSITORY}/releases/download/'),
            'A canonical public musl release asset URL is required')
    path = Path(path)
    count = 0; digest = hashlib.sha256()
    with urllib.request.urlopen(url,timeout=120) as incoming, path.open('xb') as stream:
        for block in iter(lambda:incoming.read(4*1024**2), b''):
            count += len(block)
            require(count <= expected['size'], 'Public musl artifact exceeds its authenticated size')
            digest.update(block); stream.write(block)
    require(count == expected['size'] and digest.hexdigest() == expected['sha256'],
            'Public musl artifact differs from authenticated bytes')
    return descriptor(path)


def receive_source(architecture, output):
    require(architecture in CONTRACT.ARCHITECTURES, 'An exact public musl CPU is required')
    catalog = CONTRACT.load_qualification_catalog()
    matches = [row for row in catalog['builds'] if row['sdkVersion']=='10.0.403' and row['producerRevision']==1]
    require(len(matches)==1, 'The initial two-CPU musl producer is not independently qualified')
    row = matches[0]; tag = row['sourceReleaseTag']
    release = GitHubReleases().api(f'repos/{CONTRACT.REPOSITORY}/releases/tags/{tag}')
    base = f'https://github.com/{CONTRACT.REPOSITORY}/releases/download/{tag}/'
    manifest = get_bytes(base+'release-manifest.json',CONTRACT.MAX_MANIFEST_BYTES)
    checksums = get_bytes(base+'SHA256SUMS',CONTRACT.MAX_CHECKSUM_BYTES)
    source = CONTRACT.validate_producer_release(release,manifest,checksums)
    CONTRACT.require_qualified_producer(manifest,catalog=catalog)
    output = fresh(output)
    for name, raw in [('release.json',encoded(release)),('release-manifest.json',manifest),('SHA256SUMS',checksums)]:
        (output/name).write_bytes(raw)
    sdk = source['architectures'][architecture]['sdk']
    download_asset(base+sdk['name'],output/sdk['name'],sdk)
    return output


def archive_candidate(architecture, revision, workspace, output):
    origin = orchestration()
    workspace = fresh(workspace)
    inputs = receive_source(architecture,workspace/'inputs')
    build_directory = workspace/'build'
    build = ARCHIVE.build_archive(inputs,architecture,revision,build_directory)
    report = ARCHIVE.native(build_directory,architecture,workspace/'qualification')
    report['orchestration'] = origin
    output = fresh(output)
    for source, name in [(build_directory/build['artifact']['name'],build['artifact']['name']),
                         (build_directory/'package-build.json','package-build.json')]:
        shutil.copyfile(source,output/name)
        require(descriptor(output/name)['sha256']==descriptor(source)['sha256'],'Musl candidate copy changed bytes')
    (output/'qualification-report.json').write_bytes(encoded(report))
    return dict(status='validated-unpublished',architecture=architecture,sourceManifestSha256=build['plan']['sourceManifestSha256'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    receive=commands.add_parser('receive-source')
    receive.add_argument('--arch',choices=tuple(CONTRACT.ARCHITECTURES),required=True)
    receive.add_argument('--output',type=Path,required=True)
    archive=commands.add_parser('archive-candidate')
    archive.add_argument('--arch',choices=tuple(CONTRACT.ARCHITECTURES),required=True)
    archive.add_argument('--revision',type=int,default=1)
    archive.add_argument('--workspace',type=Path,required=True)
    archive.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.command=='receive-source':
        result=receive_source(args.arch,args.output)
        print(json.dumps(dict(status='received-qualified',directory=str(result))))
    else:
        print(json.dumps(archive_candidate(args.arch,args.revision,args.workspace,args.output)))


if __name__=='__main__':
    main()
