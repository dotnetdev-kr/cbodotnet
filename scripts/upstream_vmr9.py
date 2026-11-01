#!/usr/bin/env python3
"""Derive a bounded NET9 1xx adapter without relaxing its qualification gates."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


BASELINE_SDK = '9.0.123'
BASELINE_SOURCE = '9f04b57d1366e21b3178648493d6edffeff2216e'
ARCHES = {'arm64': ('linux-arm64', 'aarch64', 183), 'x64': ('linux-x64', 'x86_64', 62)}
UNAVAILABLE = {'Microsoft.DotNet.Common.ProjectTemplates.9.0', 'Microsoft.EntityFrameworkCore.Tasks'}


def require(value, message):
    if not value:
        raise ValueError(message)


def stable(value):
    require(isinstance(value, str) and re.fullmatch(r'9\.0\.[0-9]+', value), 'A stable NET9 version is required')
    return tuple(map(int, value.split('.')))


def property_value(root, name):
    rows = root.findall('.//' + name)
    require(len(rows) == 1 and rows[0].text and not rows[0].attrib, 'A unique unconditional ' + name + ' is required')
    return rows[0].text.strip()


def manifest_values(sdk, commit, read):
    require(stable(sdk)[2] // 100 == 1, 'Only exact NET9 1xx sources are admitted')
    require(isinstance(commit, str) and re.fullmatch('[a-f0-9]{40}', commit), 'A complete VMR source commit is required')
    global_json = json.loads(read('global.json'))
    bootstrap = global_json['tools']['dotnet']
    require(stable(bootstrap)[2] // 100 == 1, 'The bootstrap must be a stable NET9 1xx SDK')
    declarations = ET.fromstring(read('eng/Versions.props'))
    require(property_value(declarations, 'PrivateSourceBuiltSdkVersion') == bootstrap,
            'The bootstrap and private source-built SDK declarations differ')
    psb = property_value(declarations, 'PrivateSourceBuiltArtifactsVersion')
    require(re.fullmatch(r'9\.0\.1[0-9]{2}-servicing\.[0-9]+\.[0-9]+', psb),
            'Unexpected NET9 source-built artifacts declaration')
    source = json.loads(read('src/source-manifest.json'))
    components = {}; package_versions = {}; runtime_versions = set()
    for item in source['repositories']:
        if item.get('path') not in ('runtime', 'aspnetcore'):
            continue
        name = item['path']; pin = item.get('commitSha'); package = item.get('packageVersion')
        require(name not in components and isinstance(pin, str) and re.fullmatch('[a-f0-9]{40}', pin),
                'Missing or ambiguous component source revision')
        match = re.fullmatch(r'(9\.0\.[0-9]+)-servicing\.[0-9]+\.[0-9]+', package or '')
        require(match, 'Unexpected component package version')
        components[name] = pin; package_versions[name] = package; runtime_versions.add(match[1])
    require(set(components) == {'runtime', 'aspnetcore'} and len(runtime_versions) == 1,
            'Runtime and ASP.NET sources must identify one exact NET9 runtime version')
    from upstream_vmr8 import bootstrap_sdk_files
    return dict(bootstrapSdk=bootstrap, sourceBuiltArtifacts=psb, runtime=runtime_versions.pop(),
                components=components, componentPackageVersions=package_versions,
                bootstrapSdkFiles=bootstrap_sdk_files(bootstrap))


def xml_without_versions(data):
    root = ET.fromstring(data)
    for name in ('PrivateSourceBuiltSdkVersion', 'PrivateSourceBuiltArtifactsVersion'):
        property_value(root, name)
        root.findall('.//' + name)[0].text = '<derived-version>'
    def normalize(node):
        node.text = node.text.strip() if node.text and node.text.strip() else None
        node.tail = None
        for child in node:
            normalize(child)
    normalize(root)
    return ET.tostring(root, encoding='utf-8')


def compatibility(root, policy, candidate, helpers):
    adapter = policy['adapter']; old = adapter['baselineSource']; new = candidate['sourceCommit']
    require(candidate['sdkVersion'] == BASELINE_SDK or stable(candidate['sdkVersion']) > stable(BASELINE_SDK),
            'NET9 adapter cannot downgrade its qualified SDK')
    require(stable(candidate['sdkVersion'])[2] // 100 == 1, 'NET9 higher-band sources need a separate adapter')
    unchanged = {}
    for path in adapter['requiredUnchangedFiles']:
        before = helpers.tree_entries(root, old, path).get(path)
        after = helpers.tree_entries(root, new, path).get(path)
        require(before and before['type'] == 'blob' and before['mode'] in ('100644', '100755') and after == before,
                'pending-adapter: original NET9 build input changed or disappeared: ' + path)
        data = helpers.git(root, 'show', old + ':' + path)
        require(data == helpers.git(root, 'show', new + ':' + path), 'NET9 immutable input bytes differ: ' + path)
        unchanged[path] = hashlib.sha256(data).hexdigest()
    inventories = {}
    for kind, roots in (('tests', adapter['testRoots']), ('integrity', adapter['integrityRoots'])):
        before = helpers.tree_entries(root, old, *roots); after = helpers.tree_entries(root, new, *roots)
        require(before and before == after, 'pending-adapter: original NET9 ' + kind + ' inventory changed')
        inventories[kind] = dict(files=len(after), sha256=helpers.digest(after))
    before = {name: row for name, row in helpers.tree_entries(root, old, 'test').items() if name.count('/') == 1}
    after = {name: row for name, row in helpers.tree_entries(root, new, 'test').items() if name.count('/') == 1}
    require(before and before == after, 'pending-adapter: top-level NET9 test import wiring changed')
    test_projects = ET.fromstring(helpers.git(root, 'show', new + ':test/tests.proj'))
    legacy = [item for item in test_projects.findall('.//ProjectReference')
              if 'Microsoft.DotNet.SourceBuild.SmokeTests' in item.get('Include', '')]
    require(len(legacy) == 1 and legacy[0].get('Condition') == "'$(DotNetBuildSourceOnly)' == 'true'",
            'The source-only SmokeTests exclusion differs from the ordinary NET9 graph')
    inventories['testImports'] = dict(files=len(after), sha256=helpers.digest(after))
    for path, expected in adapter['testSourceFiles'].items():
        data = helpers.git(root, 'show', new + ':' + path)
        require(len(data) == expected['bytes'] and hashlib.sha256(data).hexdigest() == expected['sha256'],
                'pending-adapter: an exact NET9 package test source changed')
    originals = {}
    for pin in (old, new):
        global_json = json.loads(helpers.git(root, 'show', pin + ':global.json'))
        value = global_json['tools'].pop('dotnet')
        require(stable(value)[2] // 100 == 1, 'Unsupported bootstrap feature band')
        originals[pin] = (global_json, xml_without_versions(helpers.git(root, 'show', pin + ':eng/Versions.props')))
    require(originals[old] == originals[new], 'pending-adapter: non-version bootstrap or PSB declarations changed')
    return dict(unchangedFiles=unchanged, inventories=inventories,
                bootstrapDeclarations='Only tools.dotnet and the two exact private version properties may differ',
                psbConstruction='Unused declaration; this ordinary NET9 graph does not consume a PSB archive',
                executedTestClosure=adapter['qualification']['executedTestClosure'],
                shippingPackages=262, availableBaselines=260, commonResults=522, scenarioResults=34,
                unavailableBaselineIds=sorted(UNAVAILABLE))


def transform(root, policy, candidate, helpers):
    adapter = policy['adapter']; old = adapter['baselineSdk']; inputs = candidate['upstreamInputs']
    profiles = sorted((root / 'profiles').glob('dotnet-' + old + '-linux-*.json'))
    require(len(profiles) == 2, 'Exactly two baseline NET9 profiles are required')
    original = helpers.load(profiles[0]); previous = original['upstreamInputs']
    require(original['source']['commit'] == adapter['baselineSource'], 'The qualified NET9 source profile differs')
    for name in adapter['generatedFiles']:
        path = root / name
        require(path.is_file() and not path.is_symlink()
                and hashlib.sha256(path.read_bytes()).hexdigest() == adapter['projectInputSha256'][name],
                'The exact trusted NET9 adapter input changed: ' + name)
    replacements = {old: candidate['sdkVersion'], adapter['baselineSource']: candidate['sourceCommit'],
                    previous['bootstrapSdk']: inputs['bootstrapSdk'], previous['runtime']: inputs['runtime']}
    replacements.update({value: inputs['components'][name] for name, value in adapter['baselineComponents'].items()})
    pattern = re.compile('|'.join(re.escape(value) for value in sorted(replacements, key=len, reverse=True)))
    for name in adapter['generatedFiles']:
        if name.endswith(('.json',)):
            continue
        path = root / name; data = path.read_text(encoding='utf-8')
        data = pattern.sub(lambda match: replacements[match[0]], data)
        if name == 'scripts/ci_vmr89_support.py':
            before = 'dotnetdev-kr/cbodotnet/.github/workflows/sdk-x64.yml@refs/heads/main'
            require(data.count(before) == 1, 'The original NET9 x64 workflow identity guard changed')
            data = data.replace(before, helpers.WORKFLOW)
            anchor = "        require(snapshot.get('packageCaseCoverageRequired') is True, 'Current pinned package case coverage is mandatory')"
            require(data.count(anchor) == 1, 'The original package case coverage guard changed')
            data = data.replace(anchor, anchor + "\n        from upstream_vmr9 import validate_bootstrap\n"
                "        validate_bootstrap(release, V[version]['bootstrap'], V[version]['commit'], arch, stages['prepare']['commands'])\n"
                "        from upstream_vmr9 import validate_bootstrap_use\n"
                "        validate_bootstrap_use(release, V[version]['bootstrap'], V[version]['commit'], arch,\n"
                "                               {key: stages[key]['commands'] for key in ('build', 'test')})")
        if name == 'scripts/ci-vmr89.py':
            anchor = "        S.freeze(PROJECT, self.source, self.output, self.version, self.identity, os.environ.get('GITHUB_WORKFLOW_REF', 'local'), self.arch)"
            require(data.count(anchor) == 1, 'The original source identity freeze command changed')
            data = data.replace(anchor, anchor + "\n        if self.version == '9':\n"
                "            self.run([sys.executable, self.frozen / 'scripts/upstream_vmr9.py', 'bootstrap',\n"
                "                      '--source-dir', self.source, '--profile', self.profile,\n"
                "                      '--reports-dir', self.reports / 'prepare/bootstrap', '--arch', self.arch])")
            # The original finally form is pinned separately from its build/test commands.
            actual = '        finally:\n            if observer: observer.finish()'
            require(data.count(actual) == 1, 'The original component-observer completion guard changed')
            data = data.replace(actual, actual + "\n        if self.version == '9':\n"
                "            self.run([sys.executable, self.frozen / 'scripts/upstream_vmr9.py', 'verify-bootstrap',\n"
                "                      '--source-dir', self.source, '--profile', self.profile,\n"
                "                      '--reports-dir', self.reports / 'prepare/bootstrap', '--arch', self.arch,\n"
                "                      '--stage', action, '--receipt-dir', self.reports / action])")
        if name == 'scripts/build-vmr9.sh':
            anchor = 'export DOTNET_NOLOGO=1 DOTNET_PROCESSOR_COUNT=$max_cpu_count'
            require(data.count(anchor) == 1, 'The original NET9 bootstrap environment anchor changed')
            data = data.replace(anchor, anchor + '\n# Consume the exact checksum-verified root bootstrap, including during tests.\n'
                'export DOTNET_INSTALL_DIR="$source_dir/.dotnet"\nexport use_installed_dotnet_cli=false\n'
                '[[ -x "$DOTNET_INSTALL_DIR/dotnet" && -d "$DOTNET_INSTALL_DIR/sdk/' + inputs['bootstrapSdk'] + '" ]] || '
                "{ echo 'Verified root bootstrap is absent.' >&2; exit 1; }\n"
                '[[ $("$DOTNET_INSTALL_DIR/dotnet" --version) == ' + inputs['bootstrapSdk'] + ' ]] || '
                "{ echo 'Verified root bootstrap version differs.' >&2; exit 1; }")
        path.write_text(data, encoding='utf-8', newline='\n')
    arm_path = root / 'scripts/ci-net9-test-cases.json'
    x64_path = root / 'scripts/ci-net9-test-cases-x64.json'
    arm = helpers.load(arm_path); x64 = helpers.load(x64_path)
    require(len(arm['shippingPackageIds']) == len(set(arm['shippingPackageIds'])) == 262
            and set(arm['unavailableBaselineIds']) == UNAVAILABLE
            and len(arm['sourceFiles']) == 4 and x64['sourceFiles'] == arm['sourceFiles']
            and x64['shippingPackageIds'] == [name.replace('linux-arm64', 'linux-x64') for name in arm['shippingPackageIds']]
            and x64['derivation']['arm64PolicySha256'] == hashlib.sha256(arm_path.read_bytes()).hexdigest()
            and x64['derivation']['targetRidSubstitutions'] == 8,
            'The exact 262-package policy and x64 derivation must remain intact')
    for value in (arm, x64):
        require(value['sdkVersion'] == old and value['sourceCommit'] == adapter['baselineSource'],
                'The original NET9 package policy source identity differs')
        value.update(sdkVersion=candidate['sdkVersion'], sourceCommit=candidate['sourceCommit'])
    arm_path.write_bytes(helpers.encode(arm))
    x64['derivation']['arm64PolicySha256'] = hashlib.sha256(arm_path.read_bytes()).hexdigest()
    x64_path.write_bytes(helpers.encode(x64))
    for path in profiles:
        profile = helpers.load(path)
        require(profile['source']['commit'] == adapter['baselineSource'] and profile['build']['sourceOnly'] is False,
                'The ordinary NET9 construction profile changed')
        profile.update(sdkVersion=candidate['sdkVersion'], selectedAt=candidate['releaseDate'])
        profile['source'].update(tag=candidate['sourceTag'], commit=candidate['sourceCommit'])
        profile['upstreamInputs'] = copy.deepcopy(inputs)
        profile['selection'] = dict(releaseDate=candidate['releaseDate'], reason=
            'Exact public NET9 1xx VMR release tag, constrained source compatibility and fresh dual-architecture qualification')
        for section in ('build', 'construction'):
            for key, value in profile[section].items():
                if isinstance(value, str):
                    profile[section][key] = value.replace(previous['runtime'], inputs['runtime'])
        destination = path.with_name(path.name.replace(old, candidate['sdkVersion']))
        require(destination == path or not destination.exists(), 'Refusing an existing generated NET9 profile')
        destination.write_bytes(helpers.encode(profile))
        if destination != path:
            path.unlink()


def ordinary(path):
    require(path.is_absolute() and not any(parent.is_symlink() for parent in [path, *path.parents]),
            'Ordinary absolute bootstrap paths are required')
    return path


def fingerprint(path):
    result = {name: hashlib.new(name) for name in ('sha256', 'sha512')}
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            for value in result.values():
                value.update(block)
    return dict(bytes=path.stat().st_size, **{key: value.hexdigest() for key, value in result.items()})


def byte_fingerprint(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), sha512=hashlib.sha512(data).hexdigest())


def root_files(source, version, arch):
    host_path = ordinary(source / '.dotnet/dotnet')
    assembly = ordinary(source / '.dotnet/sdk' / version / 'dotnet.dll')
    with host_path.open('rb') as stream:
        header = stream.read(20)
    require(len(header) == 20 and header[:6] == b'\x7fELF\x02\x01'
            and struct.unpack('<H', header[18:20])[0] == ARCHES[arch][2], 'Live bootstrap host architecture differs')
    return dict(host=dict(fingerprint(host_path), elfMachine=ARCHES[arch][2]), sdkAssembly=fingerprint(assembly))


def sdk_descriptor(profile, arch):
    require(arch in ARCHES and profile['target']['rid'] == ARCHES[arch][0], 'Bootstrap target architecture differs')
    version = profile['upstreamInputs']['bootstrapSdk']; stable(version)
    value = profile['upstreamInputs']['bootstrapSdkFiles'][arch]
    url = urllib.parse.urlsplit(value['url'])
    require(url.scheme == 'https' and url.hostname in {'builds.dotnet.microsoft.com', 'dotnetcli.blob.core.windows.net'}
            and not url.query and not url.fragment and not url.username and not url.password
            and url.path.endswith('/Sdk/' + version + '/dotnet-sdk-' + version + '-' + ARCHES[arch][0] + '.tar.gz')
            and isinstance(value.get('sha512'), str) and re.fullmatch('[a-f0-9]{128}', value['sha512']),
            'Exact official SDK bootstrap URL and SHA-512 are required')
    return version, value


def archive_members(archive, version, machine):
    rows = []; seen = set(); total = 0; host = None; assembly = None
    for entry in archive.getmembers():
        name = entry.name
        while name.startswith('./'):
            name = name[2:]
        if name in ('', '.') and entry.isdir():
            continue
        name = name.rstrip('/') if entry.isdir() else name
        relative = PurePosixPath(name)
        require(name and not relative.is_absolute() and '..' not in relative.parts
                and str(relative) == name and not any(char in name for char in '\\:\0\r\n')
                and name not in seen and (entry.isfile() or entry.isdir()), 'Unsafe or duplicate bootstrap SDK member')
        seen.add(name); total += entry.size; rows.append((entry, name))
        require(len(rows) <= 100000 and total <= 4 * 1024**3, 'Bootstrap SDK extraction exceeds its bound')
        if name == 'dotnet' and entry.isfile():
            require(0 < entry.size <= 16 * 1024**2, 'Bootstrap dotnet host exceeds its size bound')
            with archive.extractfile(entry) as stream:
                host = stream.read()
        if name == 'sdk/' + version + '/dotnet.dll' and entry.isfile():
            require(0 < entry.size <= 64 * 1024**2, 'Bootstrap SDK assembly exceeds its size bound')
            with archive.extractfile(entry) as stream:
                assembly = stream.read()
    require(host and len(host) >= 20 and host[:6] == b'\x7fELF\x02\x01'
            and struct.unpack('<H', host[18:20])[0] == machine, 'Bootstrap dotnet host ELF architecture differs')
    require(assembly, 'Bootstrap archive contains a different SDK version')
    return rows, dict(host=dict(byte_fingerprint(host), elfMachine=machine), sdkAssembly=byte_fingerprint(assembly))


def prepare_bootstrap(source, profile_path, reports, arch, invocation):
    source = ordinary(source.absolute()); profile_path = ordinary(profile_path.absolute()); reports = ordinary(reports.absolute())
    require(platform.system() == 'Linux' and platform.machine() == ARCHES[arch][1], 'A matching native Linux bootstrap host is required')
    profile = json.loads(profile_path.read_text()); version, descriptor = sdk_descriptor(profile, arch)
    pin = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    require(pin == profile['source']['commit'], 'The bootstrap source checkout identity differs')
    destination = source / '.dotnet'
    require(not destination.exists() and not destination.is_symlink() and not reports.exists()
            and reports.parent.is_dir() and source not in reports.parents and reports.parts[-3:] == ('reports', 'prepare', 'bootstrap'),
            'Fresh external bootstrap reports and SDK extraction paths are required')
    reports.mkdir()
    archive_path = reports / ('dotnet-sdk-' + version + '-' + ARCHES[arch][0] + '.tar.gz')
    with urllib.request.urlopen(descriptor['url'], timeout=60) as incoming, archive_path.open('xb') as output:
        total = 0
        for block in iter(lambda: incoming.read(1024 * 1024), b''):
            total += len(block); require(total <= 1024**3, 'Official bootstrap archive exceeds its download bound')
            output.write(block)
    observed = fingerprint(archive_path)
    require(observed['bytes'] > 0 and observed['sha512'] == descriptor['sha512'], 'Official bootstrap SDK SHA-512 mismatch')
    with tarfile.open(archive_path, 'r:gz') as archive:
        rows, identities = archive_members(archive, version, ARCHES[arch][2])
        require(sum(entry.size for entry, _ in rows) + 512 * 1024**2 < shutil.disk_usage(source).free,
                'Insufficient bootstrap extraction capacity')
        destination.mkdir(mode=0o700)
        for entry, name in rows:
            path = destination / name
            if entry.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(entry) as incoming, path.open('xb') as output:
                    shutil.copyfileobj(incoming, output)
            os.chmod(path, entry.mode & 0o777)
    environment = os.environ.copy()
    environment.update(DOTNET_ROOT=str(destination), DOTNET_MULTILEVEL_LOOKUP='0',
                       DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1', DOTNET_CLI_TELEMETRY_OPTOUT='1')
    reported = subprocess.check_output([str(destination / 'dotnet'), '--version'], cwd=source, env=environment, text=True).strip()
    require(reported == version, 'The native bootstrap SDK reports a different version')
    require(root_files(source, version, arch) == identities, 'Extracted bootstrap files differ from the official archive')
    record = dict(schemaVersion=1, status='passed', sdkVersion=version, targetRid=ARCHES[arch][0], sourceCommit=pin,
                  officialMetadataSha512=descriptor['sha512'], sha512Verified=True, reportedVersion=reported,
                  dotnetHost=identities['host'], sdkAssembly=identities['sdkAssembly'], invocation=invocation,
                  archive=dict(path=archive_path.relative_to(reports.parents[2]).as_posix(), **observed))
    (reports / 'bootstrap-sdk.json').write_text(json.dumps(record, indent=2) + '\n')


def validate_bootstrap(release, version, source_commit, arch, prepare_commands):
    profile = json.loads((release / 'reports/ci-inputs/effective-profile.json').read_text())
    selected, descriptor = sdk_descriptor(profile, arch)
    require(selected == version and profile['source']['commit'] == source_commit, 'Bootstrap profile source identity differs')
    receipt = json.loads((release / 'reports/prepare/bootstrap/bootstrap-sdk.json').read_text())
    require(receipt['schemaVersion'] == 1 and receipt['status'] == 'passed' and receipt['sdkVersion'] == version
            and receipt['targetRid'] == ARCHES[arch][0] and receipt['sourceCommit'] == source_commit
            and receipt['officialMetadataSha512'] == descriptor['sha512'] and receipt['sha512Verified'] is True
            and receipt['reportedVersion'] == version, 'Actual checksum-verified native bootstrap receipt differs')
    expected_path = 'reports/prepare/bootstrap/dotnet-sdk-' + version + '-' + ARCHES[arch][0] + '.tar.gz'
    require(receipt['archive']['path'] == expected_path, 'Unexpected preserved bootstrap archive path')
    archive_path = ordinary((release / expected_path).absolute())
    require(fingerprint(archive_path) == {key: receipt['archive'][key] for key in ('bytes', 'sha256', 'sha512')}
            and receipt['archive']['sha512'] == descriptor['sha512'], 'Preserved official bootstrap bytes changed')
    with tarfile.open(archive_path, 'r:gz') as archive:
        _, identities = archive_members(archive, version, ARCHES[arch][2])
    require(identities == dict(host=receipt['dotnetHost'], sdkAssembly=receipt['sdkAssembly']),
            'Preserved bootstrap native host or SDK assembly differs')
    invocation = receipt['invocation']
    require(isinstance(invocation, list) and len(invocation) == 11 and invocation[1].endswith('/reports/ci-inputs/project/scripts/upstream_vmr9.py')
            and invocation[2] == 'bootstrap' and invocation[3] == '--source-dir' and invocation[5] == '--profile'
            and invocation[7] == '--reports-dir' and invocation[9:] == ['--arch', arch]
            and sum(command == invocation for command in prepare_commands) == 1,
            'Exactly one actual generated bootstrap preparation command is required')


def verify_bootstrap_use(source, profile_path, reports, arch, stage, receipt_dir, invocation):
    source = ordinary(source.absolute()); profile_path = ordinary(profile_path.absolute())
    reports = ordinary(reports.absolute()); receipt_dir = ordinary(receipt_dir.absolute())
    require(stage in ('build', 'test') and receipt_dir == reports.parents[1] / stage and receipt_dir.is_dir(),
            'An exact existing bootstrap-use stage report directory is required')
    profile = json.loads(profile_path.read_text()); version, _ = sdk_descriptor(profile, arch)
    receipt = json.loads((reports / 'bootstrap-sdk.json').read_text())
    observed = root_files(source, version, arch)
    require(observed == dict(host=receipt['dotnetHost'], sdkAssembly=receipt['sdkAssembly']),
            'The original build replaced a pinned bootstrap host or SDK assembly')
    reported = subprocess.check_output([str(source / '.dotnet/dotnet'), '--version'], cwd=source, text=True).strip()
    require(reported == version, 'Consumed root bootstrap SDK version differs')
    result = dict(schemaVersion=1, status='passed', stage=stage, sourceCommit=profile['source']['commit'],
                  sdkVersion=version, targetRid=ARCHES[arch][0], rootFiles=observed,
                  reportedVersion=reported, invocation=invocation)
    with (receipt_dir / 'bootstrap-sdk-use.json').open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2); stream.write('\n')


def validate_bootstrap_use(release, version, source_commit, arch, stage_commands):
    preparation = json.loads((release / 'reports/prepare/bootstrap/bootstrap-sdk.json').read_text())
    expected = dict(host=preparation['dotnetHost'], sdkAssembly=preparation['sdkAssembly'])
    for stage in ('build', 'test'):
        receipt = json.loads((release / 'reports' / stage / 'bootstrap-sdk-use.json').read_text())
        require(receipt['schemaVersion'] == 1 and receipt['status'] == 'passed' and receipt['stage'] == stage
                and receipt['sourceCommit'] == source_commit and receipt['sdkVersion'] == version
                and receipt['targetRid'] == ARCHES[arch][0] and receipt['reportedVersion'] == version
                and receipt['rootFiles'] == expected, 'Actual unchanged root bootstrap use is required after ' + stage)
        invocation = receipt['invocation']
        require(isinstance(invocation, list) and len(invocation) == 15 and invocation[1].endswith('/reports/ci-inputs/project/scripts/upstream_vmr9.py')
                and invocation[2] == 'verify-bootstrap' and invocation[3] == '--source-dir' and invocation[5] == '--profile'
                and invocation[7] == '--reports-dir' and invocation[9:13] == ['--arch', arch, '--stage', stage]
                and invocation[13] == '--receipt-dir'
                and sum(command == invocation for command in stage_commands[stage]) == 1,
                'Exactly one actual post-' + stage + ' bootstrap verification command is required')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['bootstrap', 'verify-bootstrap'])
    for name in ('source-dir', 'profile', 'reports-dir'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--arch', choices=ARCHES, required=True)
    parser.add_argument('--stage', choices=('build', 'test'))
    parser.add_argument('--receipt-dir', type=Path)
    args = parser.parse_args()
    if args.command == 'bootstrap':
        require(args.stage is None and args.receipt_dir is None, 'Bootstrap preparation does not accept stage-use arguments')
        prepare_bootstrap(args.source_dir, args.profile, args.reports_dir, args.arch, [sys.executable, *sys.argv])
    else:
        require(args.stage and args.receipt_dir, 'Stage and receipt directory are required after bootstrap use')
        verify_bootstrap_use(args.source_dir, args.profile, args.reports_dir, args.arch,
                             args.stage, args.receipt_dir, [sys.executable, *sys.argv])


if __name__ == '__main__':
    main()
