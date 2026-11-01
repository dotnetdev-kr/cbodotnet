#!/usr/bin/env python3
"""Preserve the authenticated sysroot producer controls and real revalidation."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import runpy
LEGACY_ARCH = runpy.run_path(str(Path(__file__).with_name('ci_legacy_arch.py')))
ARCH = LEGACY_ARCH['selected_arch']()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=['arm64', 'x64'], default='arm64')
    parser.add_argument('--family', required=True, choices=['net5', 'core31', 'core30'])
    for name in ('inputs-dir', 'reports-dir'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    reports = args.reports_dir; helper = Path(__file__).parent / ('verify-sysroot' + ('5' if args.family == 'net5' else '-' + args.family) + '.py')
    extra = []
    if ARCH['arch'] == 'x64':
        helper = Path(__file__).parent / 'verify-legacy-x64-sysroot.py'
        extra = ['--family', args.family]
    result = subprocess.run([sys.executable, str(helper), '--sysroot', str(args.inputs_dir / (ARCH['arch'] + '-xenial')),
                             '--reports-dir', str(reports)] + extra, check=True, stdout=subprocess.PIPE, universal_newlines=True)
    verified = json.loads(result.stdout)
    if verified.get('status') != 'passed' or verified['files'] <= 0 or verified['symlinks'] <= 0:
        raise ValueError('Whole sysroot revalidation did not pass')
    with (reports / 'current-validation.json').open('x') as stream:
        json.dump(verified, stream, indent=2); stream.write('\n')
    provenance = json.loads((reports / 'sysroot-provenance.json').read_text())
    rows = []
    for index, row in enumerate(provenance['keyrings']):
        path = Path(row['path'])
        if not path.is_absolute() or not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']:
            raise ValueError('Actual authenticated producer keyring changed')
        destination = reports / ('signing-keyring-' + str(index) + '.gpg')
        with destination.open('xb') as output, path.open('rb') as source:
            shutil.copyfileobj(source, output)
        data = destination.read_bytes()
        rows.append({'path': 'reports/sysroot/' + destination.name, 'bytes': len(data),
                     'sha256': hashlib.sha256(data).hexdigest(), 'sha512': hashlib.sha512(data).hexdigest(), 'originalPath': str(path)})
    with (reports / 'producer-inputs.json').open('x') as stream:
        json.dump({'status': 'passed', 'keyrings': rows, 'scope': 'Exact keyrings from the authenticated producer receipt; normal complete sysroot verifier was rerun.'}, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
