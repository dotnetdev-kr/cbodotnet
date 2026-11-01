#!/usr/bin/env python3
"""Track official stable SDK releases and derive a constrained build adapter."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'dotnetdev-kr/cbodotnet'
UPSTREAM = 'https://github.com/dotnet/dotnet'
WORKFLOW = REPOSITORY + '/.github/workflows/upstream-sdk.yml@refs/heads/main'
STABLE = re.compile(r'([0-9]+)\.([0-9]+)\.([0-9]+)\Z')
SHA = re.compile('[0-9a-f]{40}\\Z')


def require(value, message):
    if not value:
        raise ValueError(message)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(encode(value))


def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def version(value):
    match = STABLE.fullmatch(value) if isinstance(value, str) else None
    require(match, 'A stable numeric SDK version is required')
    return tuple(map(int, match.groups()))


def eligible_channel(value):
    match = re.fullmatch(r'([0-9]+)\.([0-9]+)', str(value))
    return bool(match and (int(match[1]) >= 5 or value in ('3.0', '3.1')))


def request(url, missing=False):
    require(url.startswith(('https://raw.githubusercontent.com/dotnet/', 'https://api.github.com/repos/')),
            'Only the official metadata and GitHub repository endpoints are allowed')
    headers = {'User-Agent': 'cbodotnet-upstream-tracker', 'Accept': 'application/vnd.github+json'}
    if url.startswith('https://api.github.com/') and os.environ.get('GH_TOKEN'):
        headers['Authorization'] = 'Bearer ' + os.environ['GH_TOKEN']
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as response:
            data = response.read(32 * 1024**2 + 1)
    except urllib.error.HTTPError as error:
        if missing and error.code == 404:
            return None
        raise
    require(len(data) <= 32 * 1024**2, 'Metadata exceeds its size limit')
    return data


def api(path, missing=False):
    data = request('https://api.github.com/repos/' + path, missing)
    return json.loads(data) if data is not None else None


def peel_tag(tag):
    data = api('dotnet/dotnet/git/ref/tags/' + tag, missing=True)
    if data is None:
        return None
    for _ in range(8):
        obj = data['object']
        require(SHA.fullmatch(obj['sha']), 'The upstream tag object has an invalid identity')
        if obj['type'] == 'commit':
            return obj['sha']
        require(obj['type'] == 'tag', 'An upstream tag must resolve to a commit')
        data = api('dotnet/dotnet/git/tags/' + obj['sha'])
    raise ValueError('Excessive annotated tag nesting')


def manifest_values(sdk, commit, read=None):
    version(sdk)
    require(SHA.fullmatch(commit), 'A full VMR commit is required')
    if read is None:
        read = lambda path: request('https://raw.githubusercontent.com/dotnet/dotnet/' + commit + '/' + path)
    global_json = json.loads(read('global.json'))
    dependencies = ET.fromstring(read('eng/Version.Details.xml'))
    rows = {}
    for item in dependencies.findall('.//Dependency'):
        name = item.get('Name')
        require(name not in rows, 'Ambiguous VMR dependency identity: ' + str(name))
        rows[name] = item
    shared = rows['Microsoft.NET.Sdk']
    runtime = rows['Microsoft.NETCore.App.Ref']
    pin = shared.findtext('Sha')
    require(SHA.fullmatch(pin or '') and runtime.findtext('Sha') == pin,
            'Runtime and shared SDK sources must identify one public corresponding VMR')
    runtime_version = runtime.get('Version')
    require(version(runtime_version)[:2] == version(sdk)[:2], 'Runtime and SDK channels differ')
    bootstrap = global_json['sdk']['version']
    version(bootstrap)
    package = shared.get('Version')
    require(re.fullmatch(r'10\.0\.[0-9]+-servicing\.[0-9]+\.[0-9]+', package or ''),
            'The admitted adapter requires the original servicing shared SDK package format')
    return dict(bootstrapSdk=bootstrap, sharedSdkPackage=package, sharedVmrCommit=pin, runtime=runtime_version)


def sdk_records(document):
    channel = document['channel-version']
    require(eligible_channel(channel), 'Unexpected metadata channel')
    rows = {}
    for release in document['releases']:
        candidates = list(release.get('sdks') or [])
        if release.get('sdk'):
            candidates.append(release['sdk'])
        for sdk in candidates:
            name = sdk.get('version')
            if not isinstance(name, str) or not STABLE.fullmatch(name):
                continue
            parts = version(name)
            require('.'.join(map(str, parts[:2])) == channel, 'SDK metadata crossed its channel')
            runtime = sdk.get('runtime-version') or (release.get('runtime') or {}).get('version')
            record = dict(sdkVersion=name, channel=channel, featureBand=(parts[2] // 100) * 100,
                          runtimeVersion=runtime, releaseDate=release['release-date'])
            if name in rows:
                require(rows[name]['runtimeVersion'] == runtime, 'Conflicting runtime metadata for ' + name)
            rows[name] = record
    return sorted(rows.values(), key=lambda row: version(row['sdkVersion']))


def latest_sdks(document):
    latest = {}
    for row in sdk_records(document):
        band = row['featureBand']
        if band not in latest or version(row['sdkVersion']) > version(latest[band]['sdkVersion']):
            latest[band] = row
    return sorted(latest.values(), key=lambda row: version(row['sdkVersion']))


def release_states():
    result = dict(published=set(), drafts=set())
    for page in range(1, 101):
        rows = api(REPOSITORY + '/releases?per_page=100&page=' + str(page))
        for row in rows:
            name = row['tag_name']
            if name.startswith('sdk-') and STABLE.fullmatch(name[4:]):
                result['drafts' if row['draft'] else 'published'].add(name[4:])
        if len(rows) < 100:
            return result
    raise ValueError('Release pagination exceeds its bound')


def plan(policy, documents, published, resolve=peel_tag, values=manifest_values, drafts=()):
    adapter = policy['adapter']; records = []; candidates = []
    for document in documents:
        selected = {row['sdkVersion']: row for row in latest_sdks(document)}
        for row in sdk_records(document):
            if (row['channel'] == adapter['channel'] and row['featureBand'] == adapter['featureBand']
                    and version(row['sdkVersion']) > version(adapter['baselineSdk'])):
                selected[row['sdkVersion']] = row
        for row in sorted(selected.values(), key=lambda item: version(item['sdkVersion'])):
            sdk = row['sdkVersion']
            if sdk in published:
                row.update(status='published', reason='The matching public community release exists')
            elif sdk in drafts:
                row.update(status='pending-publication-recovery',
                           reason='A matching draft exists; resume its exact qualified assets before rebuilding')
            elif row['channel'] != adapter['channel'] or row['featureBand'] != adapter['featureBand']:
                row.update(status='pending-adapter', reason='This SDK feature band needs a qualified version adapter')
            elif version(sdk) <= version(adapter['baselineSdk']):
                row.update(status='baseline', reason='The independently qualified pinned adapter already covers this version')
            else:
                pin = resolve('v' + sdk)
                if pin is None:
                    row.update(status='pending-source', reason='The exact public VMR SDK release tag is not available yet')
                else:
                    try:
                        inputs = values(sdk, pin)
                        require(inputs['runtime'] == row['runtimeVersion'], 'Published runtime metadata and VMR inputs differ')
                    except (ValueError, KeyError, TypeError, ET.ParseError) as error:
                        row.update(status='pending-adapter', reason=str(error))
                    else:
                        candidate = dict(schemaVersion=1, adapter=adapter['name'], sdkVersion=sdk,
                                         sourceCommit=pin, sourceTag='v' + sdk, upstreamInputs=inputs,
                                         runtimeVersion=row['runtimeVersion'], releaseDate=row['releaseDate'])
                        row.update(status='candidate', reason='Requires immutable input compatibility checks and both native builds',
                                   candidateSha256=digest(candidate))
                        candidates.append(candidate)
            records.append(row)
    candidates.sort(key=lambda item: version(item['sdkVersion']))
    selected = candidates[:policy['maximumCandidatesPerRun']]
    return dict(schemaVersion=1, selection=policy['selection'], records=records, candidates=selected,
                deferredCandidates=len(candidates) - len(selected))


def admit_candidates(result, maximum, check):
    admitted = []
    for candidate in result['candidates']:
        try:
            proof = check(candidate)
        except ValueError as error:
            row = next(item for item in result['records'] if item['sdkVersion'] == candidate['sdkVersion'])
            row.update(status='pending-adapter', reason=str(error))
            row.pop('candidateSha256', None)
        else:
            admitted.append(candidate)
            row = next(item for item in result['records'] if item['sdkVersion'] == candidate['sdkVersion'])
            row['compatibilityInventorySha256'] = digest(proof)
    result['candidates'] = admitted[:maximum]
    result['deferredCandidates'] = len(admitted) - len(result['candidates'])
    return result


def baseline_candidate(policy, documents, resolve=peel_tag, values=manifest_values):
    adapter = policy['adapter']; sdk = adapter['baselineSdk']
    rows = [row for document in documents for row in sdk_records(document) if row['sdkVersion'] == sdk]
    require(len(rows) == 1, 'The qualification baseline must occur in official stable release metadata')
    row = rows[0]; pin = resolve('v' + sdk)
    require(pin == adapter['baselineSource'], 'The baseline release tag differs from the qualified source pin')
    inputs = values(sdk, pin)
    require(inputs['runtime'] == row['runtimeVersion'], 'Baseline runtime metadata and source manifests differ')
    return dict(schemaVersion=1, adapter=adapter['name'], sdkVersion=sdk, sourceCommit=pin, sourceTag='v' + sdk,
                upstreamInputs=inputs, runtimeVersion=row['runtimeVersion'], releaseDate=row['releaseDate'], qualificationOnly=True)


def git(root, *args, data=None, env=None):
    command = ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.autocrlf=false', '-C', str(root), *args]
    return subprocess.check_output(command, input=data, env=env)


def source_metadata(directory, commits):
    require(not directory.exists(), 'Metadata checkout must be new')
    directory.mkdir(parents=True)
    git(directory, 'init', '--quiet')
    git(directory, 'remote', 'add', 'origin', UPSTREAM)
    git(directory, 'config', 'remote.origin.promisor', 'true')
    git(directory, 'config', 'remote.origin.partialclonefilter', 'blob:none')
    git(directory, 'fetch', '--quiet', '--filter=blob:none', '--depth=1', 'origin', *sorted(set(commits)))


def tree_entries(root, commit, *paths):
    data = git(root, 'ls-tree', '-r', '-z', commit, '--', *paths)
    result = {}
    for row in data.split(b'\0'):
        if row:
            meta, name = row.split(b'\t', 1)
            mode, kind, blob = meta.decode().split()
            result[name.decode()] = dict(mode=mode, type=kind, blob=blob)
    return result


def compatibility(root, policy, candidate):
    adapter = policy['adapter']; old = adapter['baselineSource']; new = candidate['sourceCommit']
    unchanged = {}
    baseline_inputs = tree_entries(root, old, *adapter['requiredUnchangedFiles'])
    current_inputs = tree_entries(root, new, *adapter['requiredUnchangedFiles'])
    for path in adapter['requiredUnchangedFiles']:
        require(path in baseline_inputs and baseline_inputs[path]['type'] == 'blob'
                and baseline_inputs[path]['mode'] in ('100644', '100755'), 'The qualified baseline input is absent: ' + path)
        require(current_inputs.get(path) == baseline_inputs[path],
                'pending-adapter: upstream compatibility input changed or disappeared: ' + path)
        before = git(root, 'show', old + ':' + path)
        after = git(root, 'show', new + ':' + path)
        require(before == after, 'pending-adapter: upstream compatibility input changed: ' + path)
        unchanged[path] = hashlib.sha256(after).hexdigest()
    baseline = tree_entries(root, old, *adapter['testRoots'])
    current = tree_entries(root, new, *adapter['testRoots'])
    # Version manifests may change inputs; executable test source and project definitions may not.
    included = lambda name: name.endswith(('.cs', '.csproj', '.targets')) or name.endswith('Directory.Build.props')
    before = {name: item for name, item in baseline.items() if included(name)}
    after = {name: item for name, item in current.items() if included(name)}
    require(before and before == after, 'pending-adapter: the original upstream test inventory or definitions changed')
    return dict(unchangedFiles=unchanged, upstreamTestInventorySha256=digest(after), upstreamTestFiles=len(after))


def attribute_audit(root, commit, baseline):
    entries = tree_entries(root, commit)
    require(entries, 'The shared VMR tree is empty')
    git(root, 'read-tree', commit)
    paths = sorted(entries)
    data = git(root, 'check-attr', '--cached', '-z', '--stdin', 'eol', data=b''.join(name.encode() + b'\0' for name in paths))
    records = data.decode().split('\0')
    require(records[-1] == '' and len(records[:-1]) == len(paths) * 3, 'Incomplete shared-source Git attribute audit')
    crlf = []
    for offset in range(0, len(records) - 1, 3):
        path, attribute, value = records[offset:offset + 3]
        require(path == paths[offset // 3] and attribute == 'eol', 'Shared-source attribute audit order differs')
        if value == 'crlf':
            crlf.append(path)
    result = dict(baseline)
    result.update(commit=commit, tree=git(root, 'rev-parse', commit + '^{tree}').decode().strip(),
                  attributeFiles=[dict(path=name, blobSha1=row['blob']) for name, row in sorted(entries.items())
                                  if name.rsplit('/', 1)[-1] == '.gitattributes'], paths=crlf)
    return result


def replace_exact(data, old, new, required=False):
    require(not required or old in data, 'A required immutable adapter input is absent: ' + old)
    return data.replace(old, new)


def transform(root, policy, candidate, audit):
    adapter = policy['adapter']; baseline = adapter['baselineSdk']
    profiles = sorted((root / 'profiles').glob('dotnet-' + baseline + '-linux-*.json'))
    require(len(profiles) == 2, 'Exactly two baseline native profiles are required')
    old_profile = load(profiles[0]); original_inputs = old_profile['upstreamInputs']
    require(old_profile['source']['commit'] == adapter['baselineSource']
            and original_inputs['sharedVmrCommit'] == adapter['baselineSharedSource'], 'The adapter baseline differs')
    audit_path = root / 'scripts/net10-shared-source-crlf.json'
    old_audit_bytes = audit_path.read_bytes(); old_audit = json.loads(old_audit_bytes)
    new_audit_bytes = encode(audit)
    replacements = {baseline: candidate['sdkVersion'], adapter['baselineSource']: candidate['sourceCommit'],
                    adapter['baselineSharedSource']: candidate['upstreamInputs']['sharedVmrCommit'],
                    old_audit['tree']: audit['tree'],
                    hashlib.sha256(old_audit_bytes).hexdigest(): hashlib.sha256(new_audit_bytes).hexdigest()}
    replacements.update({original_inputs[key]: value for key, value in candidate['upstreamInputs'].items()})
    for name in adapter['generatedFiles']:
        path = root / name
        data = path.read_text(encoding='utf-8')
        for old, new in replacements.items():
            data = replace_exact(data, old, new)
        if name == 'scripts/package-used-source.py':
            before = "len(policy['paths']) == " + str(len(old_audit['paths']))
            data = replace_exact(data, before, "len(policy['paths']) == " + str(len(audit['paths'])), required=True)
        if name == 'scripts/ci-net10-evidence.py':
            data = replace_exact(data, REPOSITORY + '/.github/workflows/sdk-x64.yml@refs/heads/main', WORKFLOW, required=True)
        path.write_text(data, encoding='utf-8', newline='\n')
    audit_path.write_bytes(new_audit_bytes)
    for path in profiles:
        profile = load(path)
        profile.update(sdkVersion=candidate['sdkVersion'], selectedAt=candidate['releaseDate'])
        profile['source'].update(tag=candidate['sourceTag'], commit=candidate['sourceCommit'])
        profile['upstreamInputs'] = candidate['upstreamInputs']
        profile['build']['officialBuildId'] = candidate['releaseDate'].replace('-', '') + '.1'
        destination = path.with_name(path.name.replace(baseline, candidate['sdkVersion']))
        require(destination == path or not destination.exists(), 'Generated SDK profile already exists')
        destination.write_bytes(encode(profile))
        if destination != path:
            path.unlink()


def generate(args):
    policy = load(args.project_root / 'profiles/upstream-policy.json'); candidate = load(args.candidate)
    adapter = policy['adapter']; sdk = candidate['sdkVersion']; parts = version(sdk)
    require(candidate['schemaVersion'] == 1 and candidate['adapter'] == adapter['name']
            and parts[:2] == (10, 0) and parts[2] // 100 == 4
            and (version(sdk) > version(adapter['baselineSdk'])
                 or (getattr(args, 'allow_baseline', False) and sdk == adapter['baselineSdk']))
            and candidate['sourceTag'] == 'v' + sdk and SHA.fullmatch(candidate['sourceCommit']), 'Unadmitted upstream candidate')
    require(SHA.fullmatch(candidate['upstreamInputs']['sharedVmrCommit']), 'Invalid shared VMR source pin')
    require(candidate['upstreamInputs']['runtime'] == candidate['runtimeVersion'], 'Candidate runtime metadata differs')
    dt.date.fromisoformat(candidate['releaseDate'])
    require(not args.destination.exists() and not args.attestation.exists(), 'Generation destinations must be fresh')
    require(args.destination.is_absolute() and args.attestation.is_absolute()
            and not any(path.is_symlink() for path in [args.destination, *args.destination.parents,
                                                      args.attestation, *args.attestation.parents]),
            'Generation requires ordinary absolute paths')
    require(not git(args.project_root, 'status', '--porcelain', '--untracked-files=all').strip(), 'The trusted orchestration checkout must be clean')
    parent = git(args.project_root, 'rev-parse', 'HEAD').decode().strip()
    require(not os.environ.get('GITHUB_SHA') or os.environ['GITHUB_SHA'] == parent, 'Trusted workflow checkout differs')
    require(peel_tag(candidate['sourceTag']) == candidate['sourceCommit'], 'The selected public release tag changed')
    metadata = args.destination.with_name(args.destination.name + '-metadata')
    source_metadata(metadata, [adapter['baselineSource'], candidate['sourceCommit'], candidate['upstreamInputs']['sharedVmrCommit']])
    read = lambda path: git(metadata, 'show', candidate['sourceCommit'] + ':' + path)
    require(manifest_values(sdk, candidate['sourceCommit'], read) == candidate['upstreamInputs'], 'Candidate inputs differ from immutable VMR manifests')
    evidence = compatibility(metadata, policy, candidate)
    audit = attribute_audit(metadata, candidate['upstreamInputs']['sharedVmrCommit'], load(args.project_root / 'scripts/net10-shared-source-crlf.json'))
    subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', 'clone', '--quiet', '--no-hardlinks', '--no-checkout',
                    str(args.project_root), str(args.destination)], check=True)
    git(args.destination, 'checkout', '--quiet', '--detach', parent)
    transform(args.destination, policy, candidate, audit)
    write(args.destination / 'profiles/generated-upstream.json', dict(candidate=candidate, parentCommit=parent, compatibility=evidence))
    git(args.destination, 'add', '--all')
    tree = git(args.destination, 'write-tree').decode().strip()
    environment = os.environ.copy()
    environment.update(GIT_AUTHOR_NAME='cbodotnet upstream automation', GIT_AUTHOR_EMAIL='upstream@cbodotnet.invalid',
                       GIT_COMMITTER_NAME='cbodotnet upstream automation', GIT_COMMITTER_EMAIL='upstream@cbodotnet.invalid',
                       GIT_AUTHOR_DATE='2000-01-01T00:00:00Z', GIT_COMMITTER_DATE='2000-01-01T00:00:00Z')
    message = ('Derive constrained SDK adapter ' + sdk + '\n\nCandidate SHA-256: ' + digest(candidate) + '\n').encode()
    commit = git(args.destination, 'commit-tree', tree, '-p', parent, data=message, env=environment).decode().strip()
    git(args.destination, 'reset', '--quiet', '--hard', commit)
    write(args.attestation, dict(schemaVersion=1, sourceProjectCommit=parent, generatedProjectCommit=commit,
                                generatedProjectTree=tree, candidateSha256=digest(candidate), candidate=candidate,
                                compatibility=evidence, generatedFiles=adapter['generatedFiles'],
                                sharedAttributeAuditSha256=hashlib.sha256(encode(audit)).hexdigest()))
    print(json.dumps(dict(status='generated', projectCommit=commit, sourceProjectCommit=parent)))


def discover(args):
    policy = load(args.policy)
    index = json.loads(request(policy['metadataIndex']))
    channels = set(policy['minimumChannels'])
    channels.update(row['channel-version'] for row in index['releases-index'] if eligible_channel(row['channel-version']))
    documents = [json.loads(request(policy['metadataTemplate'].format(channel=channel)))
                 for channel in sorted(channels, key=lambda item: tuple(map(int, item.split('.'))))]
    releases = release_states()
    # Inspect every queued immutable source before applying the build budget, so
    # an incompatible old update cannot permanently starve later compatible ones.
    expanded = dict(policy, maximumCandidatesPerRun=sys.maxsize)
    result = plan(expanded, documents, releases['published'], drafts=releases['drafts'])
    if args.qualify_baseline:
        result['candidates'] = [baseline_candidate(policy, documents)]
        result['qualificationOnly'] = True
    if result['candidates']:
        metadata = args.output.with_name(args.output.stem + '-metadata')
        source_metadata(metadata, [policy['adapter']['baselineSource'],
                                  *[row['sourceCommit'] for row in result['candidates']]])
        result = admit_candidates(result, policy['maximumCandidatesPerRun'],
                                  lambda candidate: compatibility(metadata, policy, candidate))
    result.update(checkedAtUtc=dt.datetime.now(dt.timezone.utc).isoformat(), metadataIndex=policy['metadataIndex'])
    write(args.output, result)
    if os.environ.get('GITHUB_OUTPUT'):
        versions = [{'sdk': row['sdkVersion'], 'candidate': row} for row in result['candidates']]
        matrix = [{'sdk': row['sdkVersion'], 'arch': arch, 'runner': runner, 'candidate': row}
                  for row in result['candidates'] for arch, runner in [('aarch64', 'ubuntu-24.04-arm'), ('x64', 'ubuntu-24.04')]]
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('matrix=' + json.dumps({'include': matrix}, separators=(',', ':')) + '\n')
            stream.write('versions=' + json.dumps({'include': versions}, separators=(',', ':')) + '\n')
            stream.write('has_candidates=' + str(bool(versions)).lower() + '\n')
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a') as stream:
            stream.write('| SDK | Feature band | Status | Reason |\n| --- | --- | --- | --- |\n')
            for row in result['records']:
                stream.write('| ' + ' | '.join([row['sdkVersion'], str(row['featureBand']), row['status'], row['reason'].replace('|', '/')]) + ' |\n')
    print(json.dumps(dict(status='tracked', candidates=len(result['candidates']), versions=len(result['records']))))


def main():
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('discover'); p.add_argument('--policy', type=Path, default=ROOT / 'profiles/upstream-policy.json')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--qualify-baseline', action='store_true', help='Qualify the admitted baseline without publishing a release')
    p = sub.add_parser('generate'); p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--project-root', type=Path, default=ROOT); p.add_argument('--destination', type=Path, required=True)
    p.add_argument('--attestation', type=Path, required=True)
    p.add_argument('--allow-baseline', action='store_true', help='Exercise the admitted baseline without selecting an update')
    args = parser.parse_args()
    if args.command == 'discover':
        discover(args)
    else:
        generate(args)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError, subprocess.CalledProcessError) as error:
        raise SystemExit('error: ' + str(error))
