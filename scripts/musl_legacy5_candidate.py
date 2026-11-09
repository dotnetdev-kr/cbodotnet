"""Authenticate and privately retain completed normal SDK5 facts, never admit them.

The record factory revalidates live normal consumption and complete source/D
bytes. Saved receipts cannot mint this capability. No build or CLI is provided.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile

SDK = '5.0.214'
KIND = 'sdk5-normal-unadmitted-candidate'
STATUS = 'retained-unadmitted'
STAGES = ('prepare', 'build', 'scan', 'test', 'collect', 'verify')
IDENTITY = ('sdkVersion', 'architecture', 'targetRid', 'runId', 'runAttempt', 'buildId', 'projectCommit')
COMMITS = dict(sourceCommit='430330f7c5428f031b4a835be3dcf5945f55a56a',
    sdkSourceCommit='3fdf76c35026e311b7edc245d4b3d9e812fe532e',
    runtimeSourceCommit='6a984143635bde23e728abaaccbde52f5ea8fa3e')
FLAGS = ('qualificationAllowed', 'sourceAdmissionAllowed', 'releaseAvailabilityAllowed', 'wholeProducerSourceClosure')
FP = ('bytes', 'sha256', 'sha512')
MAX_JSON = 8 * 1024**2
RESERVE = 512 * 1024**2
STOPPED = ('docs/musl-sdk5-generated-source-inputs.md', 'scripts/musl_legacy5_generated_source_inputs.py',
           'tests/musl_legacy5_generated_source_inputs_test.py')
ROOT = Path(__file__).resolve().parents[1]
_FACTORY = object()


def require(value, message):
    if not value:
        raise ValueError(message)


def allowed_name(name):
    require(isinstance(name, str) and name and '\\' not in name and '\0' not in name
        and not PurePosixPath(name).is_absolute() and all(p not in ('', '.', '..') for p in name.split('/')),
        'Exact ordinary relative candidate member required')
    require(not any(name == item or name.endswith('/' + item) for item in STOPPED),
        'Stopped source is excluded before any body read')
    return name


def ordinary(value, *, directory=False, missing=False):
    path = Path(value)
    require(path.is_absolute() and '..' not in path.parts, 'Absolute unredirected candidate path required')
    require(not any(p.is_symlink() or getattr(p, 'is_junction', lambda: False)() for p in (path, *path.parents)),
        'Candidate path must not contain links or redirection')
    if not path.exists():
        require(missing, 'Candidate input is absent')
    else:
        mode = path.lstat().st_mode
        require(not mode & 0o7000 and (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)),
            'Ordinary candidate file/directory required')
    return path


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def unique_json(raw):
    def pairs(items):
        require(len(items) == len({key for key, _ in items}), 'Duplicate candidate JSON keys forbidden')
        return dict(items)
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_JSON, 'Bounded candidate JSON required')
    return json.loads(raw, object_pairs_hook=pairs)


def file_fingerprint(path, maximum):
    path = ordinary(path)
    require(type(maximum) is int and maximum > 0, 'Measured candidate file bound required')
    first = path.stat()
    require(0 <= first.st_size <= maximum, 'Candidate file exceeds measured bound before read')
    digests = {key: hashlib.new(key) for key in FP[1:]}; size = 0
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        while raw := stream.read(min(1024**2, maximum - size + 1)):
            size += len(raw)
            require(size <= maximum, 'Candidate file grew beyond measured bound')
            for digest in digests.values():
                digest.update(raw)
        after = os.fstat(stream.fileno())
    names = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    last = path.stat()
    require(size == after.st_size == first.st_size
        and all(getattr(first, k) == getattr(last, k) for k in names)
        and all(getattr(before, k) == getattr(after, k) for k in names)
        and (os.name != 'posix' or all(getattr(first, k) == getattr(before, k) for k in names)),
        'Candidate file changed during read')
    # Windows path stat and descriptor fstat expose different identity fields.
    # Its ordinary byte checks use each API's stable before/after identity;
    # the full capability factory remains POSIX-only with cross-API identity.
    return dict(bytes=size, **{key: value.hexdigest() for key, value in digests.items()})


def stable_raw(path, maximum=MAX_JSON):
    """Return exact immutable metadata bytes within the bound before allocation."""
    require(type(maximum) is int and 0 < maximum <= MAX_JSON, 'Finite candidate metadata byte limit required')
    before = file_fingerprint(path, maximum)
    with ordinary(path).open('rb') as stream:
        raw = stream.read(maximum + 1)
    require(0 < len(raw) <= maximum and fingerprint(raw) == before
        and file_fingerprint(path, maximum) == before, 'Candidate metadata changed before parsing')
    return raw


def load(path):
    return unique_json(stable_raw(path))


@dataclass(frozen=True)
class Limits:
    delivery_bytes: int
    file_bytes: int
    files: int

    def __post_init__(self):
        require(type(self.delivery_bytes) is int and 0 < self.delivery_bytes <= 64 * 1024**3
            and type(self.file_bytes) is int and 0 < self.file_bytes <= self.delivery_bytes
            and type(self.files) is int and 0 < self.files <= 20000, 'Finite measured candidate delivery limits required')


def identity(value):
    require(type(value) is dict and set(value) == set(IDENTITY) and value['sdkVersion'] == SDK
        and value['architecture'] in ('aarch64', 'x64')
        and value['targetRid'] == 'linux-musl-' + ('arm64' if value['architecture'] == 'aarch64' else 'x64')
        and isinstance(value['projectCommit'], str) and re.fullmatch('[a-f0-9]{40}', value['projectCommit'])
        and all(isinstance(value[k], str) and re.fullmatch('[A-Za-z0-9_.-]{1,128}', value[k])
                for k in ('runId', 'runAttempt', 'buildId')), 'Exact expected normal SDK5 identity required')
    return dict(value)


def inventory(delivery, limits):
    require(type(limits) is Limits, 'Concrete measured candidate limits required')
    delivery = ordinary(delivery, directory=True); paths = []
    for parent, dirs, names in os.walk(delivery, followlinks=False):
        for name in dirs:
            allowed_name((Path(parent) / name).relative_to(delivery).as_posix())
            ordinary(Path(parent) / name, directory=True)
        for name in names:
            path = Path(parent) / name; relative = allowed_name(path.relative_to(delivery).as_posix())
            require(relative != 'producer-validation.json', 'Candidate must never contain common producer-validation.json')
            ordinary(path); paths.append((relative, path))
            require(len(paths) <= limits.files, 'Candidate file count exceeds measured bound before body reads')
    require(paths and sum(path.stat().st_size for _, path in paths) <= limits.delivery_bytes,
        'Candidate total exceeds measured bound before body reads')
    rows = [dict(path=name, **file_fingerprint(path, limits.file_bytes)) for name, path in sorted(paths)]
    require(sum(row['bytes'] for row in rows) <= limits.delivery_bytes, 'Candidate changed beyond total measured bound')
    return rows


def parent_facts(delivery, expected_identity, *, require_collect=True):
    delivery = ordinary(delivery, directory=True); expected = identity(expected_identity)
    prepare = load(delivery / 'reports/prepare/identity.json')
    require(all(prepare.get(k) == value for k, value in {**expected, **COMMITS}.items())
        and prepare.get('libc') == 'musl' and all(prepare.get(k) is False for k in
        ('emulation', 'diagnosticPtrace', 'diagnosticPodman', 'previousPrivateSdkArchiveUsed')),
        'Actual normal preparation identity/source/CPU required')
    stages = {}
    for name in STAGES:
        if name == 'collect' and not require_collect:
            continue
        stage = load(delivery / 'reports/stages' / (name + '.json'))
        require(type(stage) is dict and stage.get('stage') == name and stage.get('status') == 'passed'
            and isinstance(stage.get('commands'), list), 'Actual completed normal stage required: ' + name)
        stages[name] = stage
    return prepare, stages


def sdk_descriptor(delivery, expected_identity, limits):
    """Original build report, raw E5 and actual final file must already agree."""
    require(type(limits) is Limits, 'Concrete measured candidate limits required')
    delivery = ordinary(delivery, directory=True); expected = identity(expected_identity)
    original = load(delivery / 'reports/build/construction.json')
    sdk = original.get('sdkArchive')
    require(original.get('sdkVersion') == SDK and type(sdk) is dict and set(sdk) == {'name', *FP}
        and isinstance(sdk['name'], str) and allowed_name(sdk['name']) == PurePosixPath(sdk['name']).name
        and type(sdk['bytes']) is int and 0 < sdk['bytes'] <= limits.file_bytes
        and re.fullmatch('[a-f0-9]{64}', sdk.get('sha256', ''))
        and re.fullmatch('[a-f0-9]{128}', sdk.get('sha512', '')), 'Original producer final SDK descriptor required')
    actual = file_fingerprint(delivery / sdk['name'], limits.file_bytes)
    require(actual == {key: sdk[key] for key in FP}, 'Original producer SDK descriptor differs from actual final archive')
    proof = load(delivery / 'reports/legacy-construction.json')
    require(proof.get('kind') == 'sdk5-musl-construction-proof' and proof.get('sdkVersion') == SDK
        and proof.get('architecture') == expected['architecture'] and proof.get('targetRid') == expected['targetRid']
        and proof.get('sdkArchive') == dict(path=sdk['name'], **actual) and isinstance(proof.get('unknowns'), list)
        and proof.get('diagnosticOnly') is False and proof.get('constructionInputScope') == 'normal-producer-inputs'
        and proof.get('qualificationAllowed') is False and proof.get('sourceAdmissionAllowed') is False,
        'Original normal E5 proof and unresolved raw unknowns must bind the exact SDK')
    return dict(sdk), proof


def producer_record(delivery, expected_identity, limits):
    prepare, _ = parent_facts(delivery, expected_identity, require_collect=False)
    sdk, _ = sdk_descriptor(delivery, expected_identity, limits)
    return dict(schemaVersion=1, kind='musl-sdk-build', producerRevision=1, **identity(expected_identity),
        **COMMITS, libc='musl', imageId=prepare['imageId'], sdk=sdk)


def draft_record(delivery, expected_identity, *, limits, require_collect=True):
    """Canonical byte draft only; it is not an authenticated capability/seal."""
    parent_facts(delivery, expected_identity, require_collect=require_collect)
    producer = producer_record(delivery, expected_identity, limits)
    require(load(Path(delivery) / 'producer-sdk.json') == producer, 'Exact actual producer-sdk descriptor required from the start')
    return dict(schemaVersion=1, kind=KIND, status=STATUS, producerRevision=1, **identity(expected_identity),
        **COMMITS, libc='musl', sdk=producer['sdk'], files=inventory(delivery, limits), **{key: False for key in FLAGS})


def normal_inputs(delivery, record, context, *, require_collect=True):
    import musl_legacy5_appinsights_normal as N
    N.validate_context(context)
    prepare, stages = parent_facts(delivery, {key: record[key] for key in IDENTITY}, require_collect=require_collect)
    require(Path(context['paths']['delivery']) == delivery
        and all(context.get(key) == record[key] for key in IDENTITY), 'Original normal context must bind this actual candidate')
    attempt = ordinary(context['paths']['attempt'], directory=True)
    host_roots = {'/inputs': attempt / 'inputs', '/output': attempt / 'output',
                  '/bootstrap': Path(context['paths']['bootstrap']), '/inspector': Path(context['paths']['inspector'])}
    return dict(context=context, record=record, prepare=prepare, stages=stages), attempt, host_roots


def live_consumption(delivery, record, context, *, require_collect=True):
    import musl_legacy5_appinsights_consumption as M
    bound, attempt, host_roots = normal_inputs(delivery, record, context, require_collect=require_collect)
    proof = load(delivery / 'reports/legacy-construction.json')
    roots_document = load(delivery / 'reports/source-roots.json')
    roots = {}
    for row in roots_document['roots']:
        require(row['name'] not in roots, 'Unique complete candidate source roots required')
        roots[row['name']] = dict(path=row['path'], kind=row.get('kind', 'git'), commit=row.get('expectedCommit'), role=row.get('role'))
    sdk_source = ordinary(Path(context['paths']['workspace']) / 'work/sdk', directory=True)
    feed = ordinary(Path(context['paths']['workspace']) / 'inputs/bootstrap-feed', directory=True)
    tooling = load(delivery / 'reports/build/sdk/results.json')
    validated = M.validate(delivery, record, proof, roots, tooling, app_workspace=attempt, app_host_roots=host_roots,
        sdk_source=sdk_source, feed=feed, normal_context=bound)
    return validated, dict(proof=proof, roots=roots, tooling=tooling, app_workspace=attempt,
        app_host_roots=host_roots, sdk_source=sdk_source, feed=feed, normal_context=bound)


def validate_capture(delivery, relative, validated, inputs):
    import musl_legacy5_appinsights_capture as C
    relative = allowed_name(relative); root = ordinary(delivery / relative, directory=True)
    result = C.validate_data(root); index = load(root / 'capture-index.json')
    require(index['actualNormalConsumption'] == validated and index['captureCode'] == C.code_pins()
        and index['existingFinalArchive'] == inputs['proof']['sdkArchive']
        and index['originalCompilerProof'] == inputs['proof']['componentCompilerProofs']['sdk'],
        'Capture index must equal freshly recomputed live normal facts/code, never saved flags')
    observations = C.observations(validated, inputs['sdk_source'], inputs['feed'])
    seen = set()
    for row in observations:
        pin = index['originalLogicalPaths'][row['logical']]
        require(file_fingerprint(row['path'], C.MAX_FILE) == {key: pin[key] for key in FP},
            'Captured cache/feed/Copy must still equal the actual original files')
        seen.add(row['logical'])
    require(seen == set(index['originalLogicalPaths']), 'Closed actual live capture observations required')
    return root, index, result


def _source_bindings(A, source, delivery_session, context, capture_root, capture_source_root):
    orchestration = source.require_orchestration(context)
    for name in ('musl_legacy5_candidate.py', 'musl_legacy5_candidate_collect.py'):
        selected = source.select({'orchestration/scripts/' + name})['orchestration/scripts/' + name]
        actual = (ROOT / 'scripts' / name).read_bytes(); row = selected['row']
        blob = hashlib.sha1(b'blob ' + str(len(actual)).encode() + b'\0' + actual).hexdigest()
        require(selected['raw'] == actual and row.get('baseline') == dict(mode=row['mode'], blob=blob),
            'Actual candidate code must belong to the exact archived orchestration Git bytes')
    public = source.root_for(context['paths']['delivery'] + '/reports/build/appinsights', kind='tree', role=A.APP_PUBLIC_ROLE)
    source.assert_closed_root(public['name'], A.public_app_members()[0], kind='tree', role=A.APP_PUBLIC_ROLE)
    capture = source.root_for(str(capture_root), kind='tree', role='sdk5-retained-actual-normal-App-consumption-data')
    require(capture['name'] == capture_source_root, 'Exact final indexed candidate capture root required')
    for root in (public, capture):
        origins = source.mint_delivery_root(delivery_session, root['name'])
        require(set(origins) == set(source.index_members(root['name'])), 'Complete source/D origin correspondence required')
    return orchestration


class AuthenticatedNormalCandidate:
    __slots__ = ('_delivery', '_metadata', '_limits', '_record_raw', '_receipt_raw', '_context_raw', '_sealed')

    def __setattr__(self, name, value):
        require(not getattr(self, '_sealed', False), 'Authenticated candidate facts are immutable')
        object.__setattr__(self, name, value)

    def __init__(self, token, delivery, metadata, record_raw, receipt_raw, limits, context_raw):
        require(token is _FACTORY, 'Only full actual candidate authentication can mint a capability')
        self._delivery, self._metadata, self._limits = delivery, metadata, limits
        self._record_raw, self._receipt_raw, self._context_raw = record_raw, receipt_raw, context_raw
        self._sealed = True

    def check(self):
        record = unique_json(self._record_raw)
        ordinary(self._metadata, directory=True)
        require(os.name == 'posix' and self._metadata.stat().st_uid == os.getuid()
            and stat.S_IMODE(self._metadata.stat().st_mode) == 0o700
            and all(stat.S_IMODE(ordinary(self._metadata / name).stat().st_mode) == 0o600
                for name in ('candidate.json', 'retention.json'))
            and {path.name for path in self._metadata.iterdir()} == {'candidate.json', 'retention.json'}
            and file_fingerprint(self._metadata / 'candidate.json', MAX_JSON) == fingerprint(self._record_raw)
            and file_fingerprint(self._metadata / 'retention.json', MAX_JSON) == fingerprint(self._receipt_raw)
            and inventory(self._delivery, self._limits) == record['files'], 'Sealed candidate or complete original D changed')
        return self

    @property
    def record(self):
        self.check(); return unique_json(self._record_raw)

    @property
    def normal_context(self):
        record = self.record
        prepare, stages = parent_facts(self._delivery, {key: record[key] for key in IDENTITY})
        return dict(context=unique_json(self._context_raw), record=record, prepare=prepare, stages=stages)


def preflight_resources(metadata_root, budget, limits):
    """Use explicit caller-measured combined limits before collection writes."""
    require(os.name == 'posix', 'Full normal candidate authentication requires POSIX; Windows ordinary tests are not a positive')
    import resource
    import musl_legacy5_appinsights_archive as A
    metadata = ordinary(metadata_root, directory=True, missing=True)
    require(not metadata.exists() and type(limits) is Limits and type(budget) is A.Budget
        and not any(budget.used.values()) and budget.files == 0 and budget.limits['public'] >= limits.delivery_bytes,
        'Fresh candidate metadata and unused measured source/public budgets required')
    parent = ordinary(metadata.parent, directory=True)
    require(parent.stat().st_uid == os.getuid() and not stat.S_IMODE(parent.stat().st_mode) & 0o022,
        'Candidate metadata parent must be caller-owned and not writable by other users')
    require(shutil.disk_usage(parent).free >= sum(budget.limits.values()) + RESERVE,
        'Measured combined candidate storage plus reserve required before snapshot writes')
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    require(Path('/proc/self/fd').is_dir() and (soft == resource.RLIM_INFINITY or
        soft - len(list(Path('/proc/self/fd').iterdir())) >= limits.files + 16),
        'Measured complete candidate descriptor capacity required before snapshots')
    return metadata, parent


def source_storage_exclusion(delivery, metadata, context, record):
    """Exclude every exact recorded source path before any staging is created."""
    delivery = ordinary(delivery, directory=True)
    metadata = ordinary(metadata, directory=True, missing=True)
    originals = [delivery, ROOT, *[ordinary(value, directory=True) for value in context['paths'].values()]]
    expected = {row['path']: {key: row[key] for key in FP} for row in record['files']}
    require(len(expected) == len(record['files']), 'Unique complete source-root journal bindings required')
    for relative, field in (('reports/source-roots.json', 'path'), ('sources/source-manifest.json', 'originalPath')):
        raw = stable_raw(delivery / relative)
        require(relative in expected and fingerprint(raw) == expected[relative],
            'Original source-root journal changed from the complete candidate inventory')
        document = unique_json(raw)
        require(type(document) is dict and type(document.get('roots')) is list and 0 < len(document['roots']) <= 4096,
            'Both complete original source-root journals required before staging')
        for row in document['roots']:
            require(type(row) is dict and isinstance(row.get(field), str), 'Exact original absolute source path required')
            originals.append(ordinary(row[field], directory=True))
    for root in originals:
        require(metadata != root and root not in metadata.parents and metadata not in root.parents
            and metadata.parent != root and root not in metadata.parent.parents,
            'Candidate metadata/staging must remain outside every original source root')
    return tuple(originals)


def authenticate_normal_candidate(delivery, metadata_root, expected_identity, *, normal_context,
        capture_relative, capture_source_root, budget, limits):
    """Full POSIX validation then one outside-D private atomic directory seal."""
    metadata, parent = preflight_resources(metadata_root, budget, limits)
    import musl_legacy5_appinsights_archive as A
    delivery = ordinary(delivery, directory=True)
    require(type(normal_context) is dict, 'Exact original normal context dictionary required')
    context_raw = encoded(normal_context)
    normal_context = unique_json(context_raw)
    roots = [delivery, ROOT, *[Path(value) for value in normal_context['paths'].values()]]
    require(all(metadata != path and path not in metadata.parents and metadata not in path.parents for path in roots),
        'Private candidate seal must stay outside D, W, J, BOOT and all original roots')
    record = draft_record(delivery, expected_identity, limits=limits)
    original_roots = source_storage_exclusion(delivery, metadata, normal_context, record)
    proof_raw = stable_raw(delivery / 'reports/legacy-construction.json')
    proof = unique_json(proof_raw)
    validated, inputs = live_consumption(delivery, record, normal_context)
    capture, index, capture_result = validate_capture(delivery, capture_relative, validated, inputs)
    expected = {key: record[key] for key in ('sdkVersion', 'projectCommit', 'runId', 'runAttempt', 'targetRid')}
    manifest_row = next((row for row in record['files'] if row['path'] == 'sources/source-manifest.json'), None)
    require(manifest_row is not None, 'Final complete source packet must precede candidate authentication')
    source = captured_delivery = None
    with tempfile.TemporaryDirectory(prefix='.sdk5-candidate-', dir=parent) as temporary:
        staging = Path(temporary); staging.chmod(0o700)
        require(all(staging != root and root not in staging.parents and staging not in root.parents for root in original_roots),
            'Actual candidate snapshot staging must remain outside every original source root')
        try:
            source = A.SourceSession.capture(delivery, expected, {key: manifest_row[key] for key in FP}, budget=budget, private_root=staging)
            captured_delivery = A.DeliverySession.capture(delivery, record, source, normal_context['paths']['delivery'], budget=budget, private_root=staging)
            orchestration = _source_bindings(A, source, captured_delivery, normal_context, capture, capture_source_root)
            require(index == load(capture / 'capture-index.json') and inputs['proof'] == proof
                and stable_raw(delivery / 'reports/legacy-construction.json') == proof_raw
                and draft_record(delivery, expected_identity, limits=limits) == record,
                'Original source/capture/raw unknowns or complete candidate D changed before seal')
            receipt = dict(schemaVersion=1, kind='sdk5-private-normal-candidate-retention', status=STATUS,
                record=fingerprint(encoded(record)), rawConstructionProof=fingerprint(proof_raw), rawEmitterUnknowns=proof['unknowns'],
                sourceByteVerification=source.result, orchestration=orchestration, captureDataValidation=capture_result,
                actualNormalConsumption=validated, captureSourceRoot=capture_source_root,
                archivedAppComponentConstructionValidated=False, fullPublicConstructionValidated=False,
                allDeliveryPrivateContentExclusionValidated=False, semanticSourceCorrespondenceResolved=False,
                x64BootstrapNativeSourcePositiveEstablished=False, **{key: False for key in FLAGS})
            record_raw, receipt_raw = encoded(record), encoded(receipt)
            require(len(record_raw) <= MAX_JSON and len(receipt_raw) <= MAX_JSON, 'Bounded candidate private seals required')
        finally:
            if captured_delivery is not None: captured_delivery.close()
            if source is not None: source.close()
        # Atomic promotion contains only private metadata, after all validators.
        # No success record is ever written into D or a common producer schema.
        for name, raw in (('candidate.json', record_raw), ('retention.json', receipt_raw)):
            with (staging / name).open('xb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            (staging / name).chmod(0o600)
        require({path.name for path in staging.iterdir()} == {'candidate.json', 'retention.json'}
            and not metadata.exists() and inventory(delivery, limits) == record['files'], 'Candidate changed before atomic seal')
        os.rename(staging, metadata)
    return AuthenticatedNormalCandidate(_FACTORY, delivery, metadata, record_raw, receipt_raw, limits, context_raw)
