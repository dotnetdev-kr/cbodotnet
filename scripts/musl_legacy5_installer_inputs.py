"""Recover SDK5's entire original installer from its six exact layout patches."""
import hashlib
import json
from pathlib import Path
import re
import tarfile

import musl_legacy5_native_inputs as N

B = N.module('sdk5_installer_original_byte_primitives', 'musl_legacy_admission.py')
P = N.module('sdk5_installer_original_git_primitives', 'package-used-source.py')
require = N.require
COMMIT = '430330f7c5428f031b4a835be3dcf5945f55a56a'
TREE = 'd3087a364c3598f1f4a82bb78e50a795ff5ca89f'
PATCHES = {
    'patches/net5-musl/0002-copy-local-source-built-components.patch':
        ('a631961d4e3045863eec1c6f3c2c8488208b6444cb1b66d4b9933dae1d4efa0d', ('src/redist/targets/GenerateLayout.targets',)),
    'patches/net5-musl/0003-scope-msi-only-package-to-windows.patch':
        ('c2e202bdf3fa297216eec12d7428591ff78b72b670536eb769d6e264724b5d1a', ('src/redist/targets/GenerateMSIs.targets',)),
    'patches/net5-musl/0004-scope-windows-layout-projects.patch':
        ('6ae6a70b26788024a985334ee308db5d53fcd4231892262ca67474996704a5bc', ('src/redist/redist.csproj',)),
    'patches/net7-musl/0006-copy-matching-source-built-native-runtime.patch':
        ('2736a1939720edd7ac72317e5b6c732d31498c52cf980ec6f062da7ba1fc97f1', ('src/redist/targets/GenerateLayout.targets',)),
    'patches/net5-musl/0008-select-source-built-crossgen-and-jit.patch':
        ('b762e32412e8284895b5467372621cf3cff4ae6318afbc30337d3830dec3a3a0', ('src/redist/targets/Crossgen.targets',)),
    'patches/net5-musl/0010-prefer-matching-framework-for-source-crossgen.patch':
        ('1733f106baf2430ad4b0eb499e27fa9a57405319b0ccd04c1f6900ce8eb0b283', ('src/redist/targets/Crossgen.targets',))}


def reverse_exact_hunks(actual, patch, target):
    """Reverse exact unique hunk bytes, retaining Git's original offset support.

    The same runtime-copy patch is applied to different original installer
    revisions with Git's recorded context offset. Coordinates do not replace
    source identity: every recovered file must equal its exact original blob.
    """
    lines = actual.decode().splitlines(True); diff = N.patch_sections(patch, (target,))[target].decode().splitlines(True)
    hunks = []; position = 2
    while position < len(diff):
        match = re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n', diff[position])
        require(match, 'Exact SDK5 installer patch hunk required'); position += 1; old, new = [], []
        while position < len(diff) and not diff[position].startswith('@@ '):
            line = diff[position]; require(line and line[0] in ' +-', 'Malformed SDK5 installer patch body')
            if line[0] in ' -': old.append(line[1:])
            if line[0] in ' +': new.append(line[1:])
            position += 1
        require(len(old) == int(match[2] or '1') and len(new) == int(match[4] or '1') and new,
                'Exact nonempty SDK5 installer patch hunk extents required'); hunks.append((old, new))
    previous = len(lines) + 1
    for old, new in reversed(hunks):
        starts = [i for i in range(len(lines) - len(new) + 1) if lines[i:i + len(new)] == new]
        require(len(starts) == 1 and starts[0] + len(new) <= previous, 'One ordered exact SDK5 installer patch result required')
        start = starts[0]; lines[start:start + len(new)] = old; previous = start
    return ''.join(lines).encode()


def validate(release, manifest):
    release = Path(release); roots = [row for row in manifest['roots'] if row['name'] == 'installer']
    require(len(roots) == 1 and roots[0]['kind'] in ('git', 'git-export') and roots[0].get('commit') == COMMIT
            and roots[0].get('tree') == TREE and not roots[0].get('deleted') and not roots[0].get('exclude'),
            'Complete original SDK5 installer Git source without exclusions or deletions required')
    indexed, baseline = {}, {}; orchestration = {'orchestration/' + name for name in PATCHES}
    with (release / 'sources' / B.portable(manifest['index']['path'])).open() as stream:
        for line in stream:
            row = json.loads(line); name = B.portable(row['path'])
            if name.startswith('installer/') or name in orchestration:
                require(name not in indexed, 'Duplicate SDK5 installer source member'); indexed[name] = row
                if name.startswith('installer/'):
                    require(row.get('baseline'), 'An unreviewed new SDK5 installer source input is present')
                    baseline[name[len('installer/'):]] = row['baseline']
    require(len(baseline) == roots[0]['files'] == 440 and P.baseline_tree(baseline) == TREE
            and orchestration <= indexed.keys(), 'Every original SDK5 installer file and exact applied patch must be archived')
    changed = {'installer/' + target for _, targets in PATCHES.values() for target in targets}; found, saved = set(), {}
    with tarfile.open(release / 'sources' / B.portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if entry.name not in indexed: continue
            require(entry.name not in found and (entry.isfile() or entry.issym()) and entry.size <= 64 * 1024**2,
                    'Unique ordinary bounded SDK5 installer source member required')
            raw = entry.linkname.encode() if entry.issym() else archive.extractfile(entry).read(); row = indexed[entry.name]
            require(N.fingerprint(raw) == {key: row[key] for key in N.FP}, 'Actual archived SDK5 installer source bytes differ')
            if entry.name.startswith('installer/') and entry.name not in changed:
                blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
                require(P.pristine_blob(row, blob, raw if entry.name.lower().endswith(('.cmd', '.bat', '.sln')) else None,
                        allow_audited_crlf=entry.name.lower().endswith('.sln')), 'Unreviewed SDK5 installer source change: ' + entry.name)
            else: saved[entry.name] = raw
            found.add(entry.name)
    require(found == indexed.keys(), 'Complete SDK5 installer source archive required')
    recovered = {name: saved[name] for name in changed}
    for name, (sha, targets) in reversed(list(PATCHES.items())):
        raw = saved['orchestration/' + name]; require(hashlib.sha256(raw).hexdigest() == sha, 'Exact applied SDK5 installer patch bytes required')
        sections = N.patch_sections(raw, targets)
        for target in targets: recovered['installer/' + target] = reverse_exact_hunks(recovered['installer/' + target], sections[target], target)
    for name, raw in recovered.items():
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        require(indexed[name]['baseline']['blob'] == blob, 'SDK5 installer patches must recover their exact original Git blobs')
    return dict(status='passed-complete-original-sdk5-installer-source', sourceCommit=COMMIT, sourceTree=TREE,
        originalFiles=len(baseline), changedOriginalFiles=len(changed), exactPatches=len(PATCHES),
        fullPristineSourceRecovered=True, arbitraryCSharpOrTargetEditsAccepted=False,
        qualificationAllowed=False, sourceAdmissionAllowed=False)
