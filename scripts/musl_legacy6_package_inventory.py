"""Closed disposition of five malformed, unused original SDK6 PDB inputs.

Their original package and names remain unchanged. They cannot satisfy any
shipping origin, and no corresponding-source or executable-payload claim is
made for these retained Windows debug symbols.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import zipfile

SHA = '3effe1e19c4236fef2259bd37a34ced651c017acdba85a45b750d27026216e8c'
POLICY_SHA = '882171a675d69aa00261fad73cfed05b6e11e79c5630cf7f1819686cc46b905e'
FP = ('bytes', 'sha256', 'sha512')


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def policy():
    raw = Path(__file__).with_name('musl-legacy6-unindexed-apphost-symbols.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == POLICY_SHA, 'Exact SDK6 unindexed debug-input policy required')
    p = json.loads(raw)
    require(p['schemaVersion'] == 1 and p['kind'] == 'sdk6-unindexed-original-apphost-debug-symbol-inputs' and p['sdkVersion'] == '6.0.136'
            and p['package']['sha256'] == SHA and p['originalPackageRetainedUnchanged'] is True
            and all(p[k] is False for k in ('sourceForSymbolsClaimed', 'shippingSymbolsAllowed', 'memberPathsNormalized'))
            and set(p['members']) == {'runtimes//native/' + n + '.pdb' for n in ('apphost', 'singlefilehost', 'nethost', 'comhost', 'ijwhost')},
            'Only the exact five original SDK6 nonshipping debug paths are reviewed')
    return p


def inspect(path, needed):
    spec = importlib.util.spec_from_file_location('sdk6_unindexed_debug_neutral_archive', Path(__file__).with_name('musl_legacy_admission.py'))
    B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
    p = policy(); path = Path(path).absolute()
    require(path.is_file() and not any(v.is_symlink() for v in (path, *path.parents)) and path.stat().st_size == p['package']['bytes'],
            'Exact bounded original SDK6 apphost debug package required')
    require(fingerprint(path.read_bytes()) == p['package'], 'Original SDK6 apphost raw package differs')
    require(not ({SHA} | {r['sha256'] for r in p['members'].values()}) & set(needed),
            'Unindexed malformed SDK6 debug inputs cannot satisfy actual shipping origins')
    inventory, excluded = {}, {}
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist(); require(len(names) == len(set(names)), 'Unique original SDK6 apphost ZIP members required')
        for entry in archive.infolist():
            if entry.is_dir(): continue
            require((entry.external_attr >> 16) & 0o170000 != 0o120000, 'Redirected SDK6 apphost member')
            name = entry.filename
            if name in p['members']:
                require(entry.file_size == p['members'][name]['bytes'] and entry.file_size <= 64 * 1024**2, 'Original bounded Windows PDB input required')
                raw = archive.read(entry)
                require(fingerprint(raw) == p['members'][name] and raw.startswith(b'Microsoft C/C++ MSF 7.00\r\n'), 'Original non-executable Windows debug-symbol bytes differ')
                excluded[name] = fingerprint(raw)
            else:
                B.portable(name)
                with archive.open(entry) as source: inventory[name] = B.digest_stream(source)
    require(excluded == p['members'], 'All five exact unindexed original debug members must remain present')
    return dict(package=p['package'], inventory=inventory, unindexedOriginalMembers=excluded,
        packageRetainedUnchanged=True, pathsNormalized=False, shippingOriginAllowed=False, correspondingSourceClaimed=False)
