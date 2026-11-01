#!/usr/bin/env python3
"""Apply or verify thirty-three bounded Core 3.0 source-build compatibility changes.

All pinned identities, original Git blobs, upstream patch bytes and local patch
hashes pass before mutation. Existing exact patched files are accepted; unknown
content is preserved and rejected. No completion semaphore is fabricated.
"""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
import tempfile

LEGACY_ARCH = runpy.run_path(str(Path(__file__).with_name('ci_legacy_arch.py')))
ARCH = LEGACY_ARCH['selected_arch']()


MANIFEST_SHA256 = '51a35ef6ec2dd1b9df5d49e26e233896fd2dc1614df0091cd37385e75859d1d5' if ARCH['arch'] == 'arm64' else 'a2e981c9a6b22235903ba05ae566a043100d46ff71c4d33bf1aef261777839f4'
PRIOR_MANIFEST_SHA256 = '444fbb6b21b6efebae6eff422771bb1f864ea2242e54b096a3e690def00ca80d'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def command(root, *args):
    process = subprocess.run(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false', *args],
                             cwd=str(root), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.returncode:
        raise ValueError(process.stderr.decode('utf-8', 'replace').strip())
    return process.stdout


def fixed(root, relative):
    path = root
    for part in Path(relative).parts:
        if part in ('..', '.'):
            raise ValueError('Unsafe fixed source path')
        path = path / part
        if path.is_symlink():
            raise ValueError('Symlink in fixed source path: ' + str(path))
    if not path.is_file():
        raise ValueError('Missing ordinary fixed file: ' + str(path))
    return path


def apply_chains(source, groups, originals, action, record, reports):
    """Prove complete original-to-final chains before any actual source write."""
    planned = []
    record['patchChains'] = []
    for relative, chain in groups.items():
        states = [chain[0][2]['originalSha256']]
        for _, _, item in chain:
            if item['originalSha256'] != states[-1]:
                raise ValueError('Non-contiguous exact patch chain: ' + relative)
            states.append(item['patchedSha256'])
        observed = sha(chain[0][0].read_bytes())
        if len(set(states)) != len(states) or observed not in states:
            raise ValueError('Unknown source contents; preserve and inspect: ' + relative)
        state = states.index(observed)
        if action == 'verify' and state != len(chain):
            raise ValueError('A required final patch state is absent: ' + relative)
        record['patchChains'].append({'target': relative, 'acceptedSha256States': states,
                                      'observedSha256': observed, 'finalSha256': states[-1],
                                      'pendingPatchCount': len(chain) - state})
        for index, (target, patch, item) in enumerate(chain):
            item['required'] = index >= state
            item['observedTargetSha256'] = observed
            if item['required']:
                item['beforeSha256'] = states[index]
                planned.append((target, patch, item))
            else:
                item.update({'beforeSha256': observed, 'afterSha256': states[-1],
                             'result': 'represented-by-later-patch' if index + 1 < len(chain) else 'already-applied'})
    # Start staging from the pinned Git blobs, even when the real source is
    # already at the reviewed intermediate or final state. Every declared
    # transition must reproduce its exact next bytes before any real mutation.
    with tempfile.TemporaryDirectory(prefix='core30-patch-chain-', dir=str(reports)) as temporary:
        stage = Path(temporary)
        command(stage, 'init', '--quiet')
        for relative, chain in groups.items():
            staged = stage / relative
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(originals[relative])
            for _, patch, item in chain:
                if sha(staged.read_bytes()) != item['originalSha256']:
                    raise ValueError('Staged original patch-chain bytes differ: ' + relative)
                command(stage, 'apply', '--check', '--whitespace=error-all', str(patch))
                command(stage, 'apply', '--whitespace=error-all', str(patch))
                if sha(staged.read_bytes()) != item['patchedSha256']:
                    raise ValueError('Staged patch-chain result differs: ' + relative)
    for summary in record['patchChains']:
        if sha((source / summary['target']).read_bytes()) != summary['observedSha256']:
            raise ValueError('Source changed after complete patch-chain preflight')
    for target, patch, item in planned:
        if sha(target.read_bytes()) != item['beforeSha256']:
            raise ValueError('Source changed during ordered patch application')
        command(source, 'apply', '--whitespace=error-all', str(patch))
        item.update({'changed': True, 'result': 'applied', 'afterSha256': sha(target.read_bytes())})
        record['changed'] = True
        if item['afterSha256'] != item['patchedSha256']:
            raise ValueError('Patched source SHA-256 mismatch: ' + item['target'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=['arm64','x64'], default='arm64')
    parser.add_argument('action', choices=['apply', 'verify'])
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--reports-dir', type=Path, required=True)
    args = parser.parse_args()
    helpers = Path(__file__).resolve().parent
    identity = runpy.run_path(str(helpers / 'core30-inputs.py'))['verify'](args.source_dir, args.profile)
    source = Path(identity['sourceDirectory'])
    reports = args.reports_dir
    if not reports.is_absolute() or reports.is_symlink() or not reports.is_dir() or source in reports.resolve().parents or reports.resolve() == source:
        raise ValueError('An existing external ordinary report directory is required')
    report_path = reports / ('core30-patches-' + args.action + '.json')
    if report_path.exists() or report_path.is_symlink():
        raise ValueError('Refusing a previous patch report')
    patch_root = helpers.parent / 'patches/core30'
    manifest_path = fixed(patch_root, 'manifest.json' if ARCH['arch'] == 'arm64' else 'manifest-x64.json')
    if sha(manifest_path.read_bytes()) != MANIFEST_SHA256:
        raise ValueError('Fixed patch manifest SHA-256 mismatch')
    manifest = json.loads(manifest_path.read_text())
    prior_spec = manifest['previousManifest']
    prior_path = fixed(patch_root, prior_spec['name'])
    if prior_spec['sha256'] != PRIOR_MANIFEST_SHA256 or sha(prior_path.read_bytes()) != PRIOR_MANIFEST_SHA256:
        raise ValueError('The reviewed earlier patch manifest changed')
    prior_manifest = json.loads(prior_path.read_text())
    prior_patches = prior_manifest['patches']
    if (prior_manifest['sourceCommit'] != manifest['sourceCommit'] or not prior_patches or
            manifest['patches'][:len(prior_patches)] != prior_patches):
        raise ValueError('The earlier reviewed patch specifications changed')
    commit = identity['sourceCommit']
    if manifest['sourceCommit'] != commit:
        raise ValueError('Patch manifest source commit mismatch')
    record = {'schemaVersion': 1, 'action': args.action, 'startedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'sourceCommit': commit, 'manifestSha256': MANIFEST_SHA256, 'status': 'failed',
              'previousManifestSha256': PRIOR_MANIFEST_SHA256,
              'patches': [], 'upstreamPatches': [], 'changed': False}
    result = 0
    try:
        groups, originals = {}, {}
        for spec in manifest['patches']:
            target, patch = fixed(source, spec['target']), fixed(patch_root, spec['name'])
            if sha(patch.read_bytes()) != spec['patchSha256']:
                raise ValueError('Fixed patch SHA-256 mismatch: ' + spec['name'])
            component = spec['component']
            if component:
                bare = source / '.git/modules/src' / (component['name'] + '.git')
                original = command(source, '--git-dir=' + str(bare), 'show', component['commit'] + ':' + component['path'])
                # Upstream patches still run normally later. This target has no
                # prior upstream edit; validate that fact against pinned blobs.
                upstream = source / 'patches' / component['name']
                expected_paths = command(source, 'ls-tree', '-r', '--name-only', commit, '--', 'patches/' + component['name']).decode().splitlines()
                actual_paths = [p.relative_to(source).as_posix() for p in sorted(upstream.glob('*.patch'))]
                if not expected_paths or sorted(expected_paths) != actual_paths:
                    raise ValueError('The upstream component patch set differs from its pinned file list')
                for relative in expected_paths:
                    path = fixed(source, relative)
                    pristine = command(source, 'show', commit + ':' + relative)
                    if path.is_symlink() or path.read_bytes() != pristine:
                        raise ValueError('An upstream patch differs from its pinned bytes: ' + relative)
                    diff_header = ('diff --git a/' + component['path'] + ' b/').encode()
                    if diff_header in pristine:
                        raise ValueError('Upstream also modifies this component target; an ordered baseline is required')
                    record['upstreamPatches'].append({'path': relative, 'sha256': sha(pristine)})
            else:
                original = command(source, 'show', commit + ':' + spec['target'])
            prior_chain = groups.get(spec['target'], [])
            if prior_chain:
                previous = prior_chain[-1][2]
                if (spec.get('afterPatch') != previous['name'] or
                        spec['originalSha256'] != previous['patchedSha256'] or spec['component'] != previous['component']):
                    raise ValueError('The declared reviewed intermediate patch state differs')
                git_sha = prior_chain[0][2]['originalSha256']
            else:
                if spec.get('afterPatch'):
                    raise ValueError('A patch predecessor is absent')
                git_sha = spec['originalSha256']
            if sha(original) != git_sha:
                raise ValueError('Pinned original Git blob mismatch: ' + spec['target'])
            stat = command(source, 'apply', '--numstat', str(patch)).decode().strip()
            expected = '{}\t{}\t{}'.format(spec['addedLines'], spec['removedLines'], spec['target'])
            if stat != expected:
                raise ValueError('Fixed patch scope mismatch')
            item = dict(spec, changed=False)
            record['patches'].append(item)
            groups.setdefault(spec['target'], []).append((target, patch, item))
            originals.setdefault(spec['target'], original)
        apply_chains(source, groups, originals, args.action, record, reports)
        record['status'] = 'passed'
    except (OSError, ValueError) as error:
        record['error'] = str(error); result = 1
    record['finishedAtUtc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with report_path.open('x', encoding='utf-8') as stream:
        json.dump(record, stream, indent=2); stream.write('\n')
    print(json.dumps({'status': record['status'], 'report': str(report_path), 'error': record.get('error')}))
    return result


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit('error: ' + str(error))
