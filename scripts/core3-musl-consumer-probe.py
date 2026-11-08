#!/usr/bin/env python3
"""Audit/run an unpublished Core3 musl apphost and ASP.NET in a separate worker."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

import musl_archive as MUSL

ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--runtime', type=Path, required=True)
parser.add_argument('--apphost-application', type=Path, required=True)
parser.add_argument('--aspnet-application', type=Path, required=True)
parser.add_argument('--output-dir', type=Path, required=True)
parser.add_argument('--tls', action='store_true', help='Also exercise HTTPS with the actual consumer system trust store.')
args = parser.parse_args()
MUSL.native_guard('aarch64')
if os.geteuid() == 0 or any(shutil.which(name) for name in ('dotnet', 'clang', 'gcc', 'g++', 'curl', 'gawk')):
    raise SystemExit('Non-root SDK/compiler/curl-CLI/gawk-free consumer required')
for path in (args.runtime, args.apphost_application, args.aspnet_application, args.output_dir):
    if not path.is_absolute() or path == Path('/') or '..' in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise SystemExit('Ordinary absolute evidence/payload paths required')
args.output_dir.mkdir(parents=True, exist_ok=True)
if any(args.output_dir.iterdir()):
    raise SystemExit('A new empty output directory is required')
profile = json.loads((ROOT / 'profiles/experimental/core3-musl.json').read_text())
index_pins = json.loads((ROOT / 'profiles/dotnet-10.0.403-linux-musl-aarch64.json').read_text())['apkIndexes']
roots = dict(MUSL.RUNTIME_PACKAGES, **profile['additionalRuntimePackageRoots'])
installed = subprocess.check_output(['apk', 'info', '-v'], text=True).splitlines()
if any(name + '-' + version not in installed for name, version in roots.items()):
    raise SystemExit('Every exact stock Core3 runtime root is required')
indexes, package_records = [], {}
for channel in ('main', 'community'):
    path = Path('/cbodotnet-pinned-indexes') / (channel + '-APKINDEX.tar.gz')
    subprocess.run(['apk', 'verify', str(path)], check=True, capture_output=True)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != index_pins[channel]['sha256']:
        raise SystemExit('Stock provider metadata differs from the frozen Alpine index pin')
    indexes.append(dict(channel=channel, sha256=digest))
    with tarfile.open(path) as archive:
        text = archive.extractfile('APKINDEX').read().decode()
    for block in text.split('\n\n'):
        row = dict(line.split(':', 1) for line in block.splitlines() if ':' in line)
        if 'P' in row and 'V' in row:
            package_records[row['P'] + '-' + row['V']] = dict(package=row['P'], version=row['V'],
                origin=row.get('o'), license=row.get('L'), checksum=row.get('C'),
                dependencyDeclarations=row.get('D'), repository=channel, signedIndexSha256=digest)

def write(name, value):
    (args.output_dir / name).write_text(json.dumps(value, indent=2) + '\n')

runtime_audit = MUSL.audit_elf(args.runtime, 'aarch64')
apphost_audit = MUSL.audit_elf(args.apphost_application, 'aarch64', entrypoint='Probe')
write('runtime-elf-closure.json', runtime_audit)
write('apphost-elf-closure.json', apphost_audit)
providers = {}
for audit in (runtime_audit, apphost_audit):
    for library in audit['stockLibraries']:
        owner = library['apkOwner'].split(' is owned by ', 1)[1]
        if owner not in package_records:
            raise SystemExit('Actual native provider is absent from the frozen signed indexes: ' + owner)
        providers[owner] = package_records[owner]
write('runtime-stock-policy.json', dict(qualification=False, packageRoots=roots,
      rootMetadata=[package_records[name + '-' + version] for name, version in roots.items()],
      actualNativeProviders=[providers[name] for name in sorted(providers)], signedIndexes=indexes,
      scope='Actual native closure and frozen stock package origin/licenses; diagnostic Python/readelf packages are not runtime roots.'))
env = dict(os.environ, HOME='/tmp/core3-consumer-home', DOTNET_ROOT=str(args.runtime),
    DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_SYSTEM_GLOBALIZATION_INVARIANT='false',
    DOTNET_CLI_TELEMETRY_OPTOUT='1', COMPlus_ReadyToRun='1', LANG='C.UTF-8', LC_ALL='C.UTF-8')
env.pop('CLR_ICU_VERSION_OVERRIDE', None)
sdk_list = subprocess.check_output([str(args.runtime / 'dotnet'), '--list-sdks'], env=env, text=True)
if sdk_list.strip():
    raise SystemExit('Consumer runtime contains an SDK')
records = []
commands = [
    ('native-apphost', [str(args.apphost_application / 'Probe')]),
    ('aspnet-loopback-http', [str(args.runtime / 'dotnet'), str(args.aspnet_application / 'Web.dll')]),
]
if args.tls:
    commands.append(('system-trust-https', [str(args.apphost_application / 'Probe'), 'tls']))
for name, command in commands:
    path = args.output_dir / (name + '.log')
    with path.open('x') as output:
        result = subprocess.run(command, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=90)
    records.append(dict(name=name, command=command, exitCode=result.returncode,
                   sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
write('results.json', dict(qualification=False, releaseAdmission=False, architecture='aarch64',
      normalReadyToRunEnabled=True, sdkPresent=False, compilerPresent=False, records=records,
      allChecksPassed=all(row['exitCode'] == 0 for row in records)))
print(json.dumps(dict(qualification=False, targetExitCodes={row['name']: row['exitCode'] for row in records})))
