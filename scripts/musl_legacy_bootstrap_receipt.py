"""Retain the actually downloaded legacy bootstrap at the admission boundary."""
import hashlib
import json
from pathlib import Path
import shutil


def require(value, message):
    if not value: raise ValueError(message)


def ordinary(path):
    path = Path(path).absolute()
    require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary downloaded bootstrap evidence required')
    return path


def fingerprint(path):
    hashes = {k: hashlib.new(k) for k in ('sha256', 'sha512')}; size = 0
    with ordinary(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            size += len(block)
            for digest in hashes.values(): digest.update(block)
    return dict(bytes=size, **{k: v.hexdigest() for k, v in hashes.items()})


def retain(workspace, profile, sdk, rid, reports):
    """Verify original preparation and archive bytes, then retain both receipts."""
    workspace, reports = Path(workspace).absolute(), Path(reports).absolute()
    prepared_path = ordinary(workspace / 'prepared.json'); prepared = json.loads(prepared_path.read_bytes())
    expected = profile['bootstrap']; original = prepared['bootstrap']; archive = ordinary(workspace / 'bootstrap-sdk.tar.gz')
    require(prepared.get('sdkVersion') == profile['sdkVersion'] == sdk and prepared.get('rid') == rid == expected['rid']
            and prepared.get('source', {}).get('repository') == 'https://github.com/dotnet/sdk'
            and prepared['source'].get('commit') == profile['componentCommits']['sdk'], 'Original tooling preparation/source/native RID differs')
    actual = fingerprint(archive)
    require(actual['bytes'] <= 512 * 1024**2 and all(original.get(k) == actual[k] for k in ('bytes', 'sha256', 'sha512'))
            and original.get('path') == str(archive) and original.get('url') == expected['url']
            and actual['sha512'] == expected['sha512'], 'Downloaded bootstrap archive/profile identity differs')
    require(not any(p.is_symlink() for p in (reports, *reports.parents)), 'Ordinary bootstrap receipt destination required')
    reports.mkdir(parents=True, exist_ok=True)
    original_receipt, receipt = reports / 'tooling-prepared.json', reports / 'bootstrap.json'
    require(not original_receipt.exists() and not receipt.exists(), 'Fresh bootstrap preparation receipts required')
    shutil.copyfile(prepared_path, original_receipt)
    require(fingerprint(original_receipt) == fingerprint(prepared_path), 'Original tooling preparation changed during retention')
    value = dict(schemaVersion=1, kind='validated-actual-legacy-bootstrap-input', version=expected['version'], rid=rid,
        url=original['url'], **actual, originalPreparation=dict(path='reports/prepare/tooling-prepared.json', **fingerprint(original_receipt)))
    with receipt.open('x', encoding='utf-8') as stream: json.dump(value, stream, indent=2); stream.write('\n')
    return value
