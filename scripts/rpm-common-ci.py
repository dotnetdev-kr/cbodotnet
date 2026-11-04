#!/usr/bin/env python3
"""Prove that native RPM builders produce identical shared noarch packages."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess

from downstream_release import descriptor, encoded, require

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('rpm_common_native', ROOT / 'scripts/rpm-ci.py')
RPM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RPM)

BOOTSTRAP = r'''
repo=$1; variant=$2; output=$3
[[ $(id -u) == 0 && -f /.dockerenv ]]
. /etc/os-release
case "$ID:$VERSION_ID:$variant" in fedora:45:fedora-45|rocky:9.8:rocky-9.8) ;; *) exit 2 ;; esac
export PATH=/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin
dnf -y --setopt=install_weak_deps=False --setopt=tsflags= install \
  python3 rpm-build cpio tar gzip xz shadow-utils util-linux
if [[ $ID == rocky ]]; then
  dnf -y --setopt=install_weak_deps=False --setopt=tsflags= install python3.12
  install -d /usr/local/bin
  ln -sfn /usr/bin/python3.12 /usr/local/bin/python3
fi
[[ $BUILDER_UID =~ ^[1-9][0-9]*$ && $BUILDER_GID =~ ^[1-9][0-9]*$ ]]
groupadd --gid "$BUILDER_GID" cbot-builder
useradd --create-home --uid "$BUILDER_UID" --gid "$BUILDER_GID" cbot-builder
runuser -u cbot-builder -- env PATH="$PATH" python3 "$repo/scripts/rpm-common-ci.py" \
  container-build --variant "$variant" --output "$output"
'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    Path(path).write_bytes(encoded(value))


def container_build(args):
    from channel_packages import build_common_rpm, HOST_VERSION, rpm_release
    require(os.getuid() != 0 and Path('/.dockerenv').is_file(), 'A non-root native container builder is required')
    architecture = 'x64' if platform.machine() == 'x86_64' else 'aarch64'
    RPM.validate_target({'variant': args.variant, 'architecture': {'public': architecture}})
    output = args.output.resolve()
    build = build_common_rpm(args.variant, output)
    require(build.get('payloadPreserved') is True and len(build['packages']) == 1,
            'Exactly one preserved shared RPM is required')
    package = build['packages'][0]
    require(package.get('kind') == 'host' and package.get('architecture') == 'noarch'
            and re.fullmatch(r'cbodotnet-host-[A-Za-z0-9._+-]+\.rpm', package['path']), 'Unexpected shared RPM identity')
    path = output / package['path']
    require(descriptor(path) == {'name': package['path'], 'size': package['size'], 'sha256': package['sha256']},
            'Shared RPM changed after build verification')
    identity = RPM.run(['rpm', '-qp', '--queryformat', '%{NAME}\t%{VERSION}\t%{RELEASE}\t%{ARCH}', path]).strip().split('\t')
    require(identity == ['cbodotnet-host', HOST_VERSION.rsplit('-', 1)[0],
                         rpm_release({'variant': args.variant}, shared=True), 'noarch'], 'Native RPM header identity differs')
    header = RPM.run(['rpm', '-qp', '--xml', path]).encode('utf-8')
    (output / 'header.xml').write_bytes(header)
    lead = path.read_bytes()[:96]
    require(len(lead) == 96, 'RPM lead is incomplete')
    (output / 'lead.bin').write_bytes(lead)
    payload = subprocess.check_output(['rpm2cpio', str(path)])
    save(output / 'native-package.json', dict(schemaVersion=1, status='passed', variant=args.variant,
         architecture=architecture, package=descriptor(path), headerSha256=digest(header),
         leadSha256=digest(lead), cpioSha256=digest(payload), packageIdentity=identity))
    # Retain only the tiny package and evidence; scratch includes no SDK payload.
    for name in ('rpmbuild', 'rpm-host-tree', 'rpm-host-verified'):
        path = output / name
        if path.exists():
            require(path.is_dir() and not path.is_symlink(), 'Unexpected shared RPM scratch path')
            shutil.rmtree(path)


def native(args):
    require(os.getuid() != 0 and platform.machine() in RPM.expected_native(args.arch),
            'A matching non-root native Linux runner is required')
    workspace = args.workspace.resolve()
    require(not workspace.exists(), 'Common RPM workspace must be fresh')
    workspace.mkdir(parents=True)
    rows = []
    for variant in RPM.BASES:
        print('rpm-common-ci: build ' + variant + ' ' + args.arch, flush=True)
        command = ['docker', 'run', '--rm', '--user', '0', '-e', 'BUILDER_UID=' + str(os.getuid()),
                   '-e', 'BUILDER_GID=' + str(os.getgid()), '-v', f'{ROOT}:/repo:ro',
                   '-v', f'{workspace}:/delivery', RPM.BASES[variant][args.arch],
                   'bash', '-euo', 'pipefail', '-c', BOOTSTRAP, '--', '/repo', variant, '/delivery/' + variant]
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (workspace / (variant + '-build.log')).write_text(result.stdout, encoding='utf-8')
        require(result.returncode == 0, 'Common native RPM build failed: ' + variant + '\n' + result.stdout)
        row = json.loads((workspace / variant / 'native-package.json').read_bytes())
        require(row['architecture'] == args.arch and row['variant'] == variant and row['status'] == 'passed',
                'Common RPM result differs from its native target')
        row['baseImage'] = RPM.BASES[variant][args.arch]
        rows.append(row)
    save(workspace / 'native-common.json', dict(schemaVersion=1, status='passed', architecture=args.arch,
         sourceCommit=os.environ.get('GITHUB_SHA'), packages=rows))


def aggregate(received, output, source_commit=None):
    received, output = Path(received).resolve(), Path(output).resolve()
    require(not output.exists(), 'Common RPM aggregate output must be fresh')
    reports = sorted(received.rglob('native-common.json'))
    require(len(reports) == 2, 'Both native common RPM reports are required')
    rows, architectures = [], set()
    for path in reports:
        report = json.loads(path.read_bytes())
        architecture = report.get('architecture')
        require(report.get('schemaVersion') == 1 and report.get('status') == 'passed'
                and architecture in {'x64', 'aarch64'} and architecture not in architectures
                and (source_commit is None or report.get('sourceCommit') == source_commit),
                'Invalid or duplicate native common RPM provenance')
        architectures.add(architecture)
        require(len(report['packages']) == len(RPM.BASES), 'Common RPM distro matrix is incomplete')
        for row in report['packages']:
            variant, item = row['variant'], row['package']
            require(variant in RPM.BASES and row['architecture'] == architecture
                    and row['baseImage'] == RPM.BASES[variant][architecture]
                    and re.fullmatch(r'cbodotnet-host-[A-Za-z0-9._+-]+\.rpm', item['name']),
                    'Unexpected native common RPM target')
            directory = path.parent / variant
            require(descriptor(directory / item['name']) == item
                    and digest((directory / 'header.xml').read_bytes()) == row['headerSha256']
                    and digest((directory / 'lead.bin').read_bytes()) == row['leadSha256']
                    and re.fullmatch(r'[a-f0-9]{64}', row['cpioSha256']), 'Common RPM evidence changed after upload')
            rows.append(row)
    targets = [(row['variant'], row['architecture']) for row in rows]
    require(len(set(targets)) == 4 and set(targets) == {(v, a) for v in RPM.BASES for a in ('x64', 'aarch64')},
            'Common RPM native matrix differs from reviewed targets')
    differences = []
    for variant in RPM.BASES:
        selected = [row for row in rows if row['variant'] == variant]
        if any(len({row[field] if field != 'package' else row['package']['sha256'] for row in selected}) != 1
               for field in ('package', 'headerSha256', 'leadSha256', 'cpioSha256')):
            differences.append(variant)
    result = dict(schemaVersion=1, status='failed' if differences else 'passed', sourceCommit=source_commit,
                  packages=rows, differences=differences)
    save(output, result)
    require(not differences, 'Shared RPM bytes differ across native architectures: ' + ', '.join(differences))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('native')
    command.add_argument('--arch', choices=('x64', 'aarch64'), required=True)
    command.add_argument('--workspace', type=Path, required=True)
    command = commands.add_parser('container-build')
    command.add_argument('--variant', choices=tuple(RPM.BASES), required=True)
    command.add_argument('--output', type=Path, required=True)
    command = commands.add_parser('aggregate')
    command.add_argument('--received', type=Path, required=True)
    command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'native': native(args)
        elif args.command == 'container-build': container_build(args)
        else: print(json.dumps(aggregate(args.received, args.output, os.environ.get('GITHUB_SHA'))))
    except (ValueError, OSError, RuntimeError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
