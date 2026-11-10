"""Collect already-completed real normal SDK5 facts into a private candidate.

No CLI, build dispatch, execution wiring, publisher or admission route exists.
All product parsers/capture/packing remain their original guarded APIs.
"""
from datetime import datetime, timezone
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import musl_legacy5_candidate as V

APP_ROOT = 'sdk5-normal-app-public'
CAPTURE_ROOT = 'sdk5-normal-app-consumption'
CAPTURE_RELATIVE = 'reports/build/app-consumption-capture'


def _module(name):
    path = V.ROOT / 'scripts' / name
    spec = importlib.util.spec_from_file_location('sdk5_candidate_' + path.stem.replace('-', '_'), path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def _write(path, value, *, replace=False):
    path = V.ordinary(path, missing=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('wb' if replace else 'xb') as stream:
        stream.write(V.encoded(value))
    path.chmod(0o644)


def _roots(source_roots):
    V.require(type(source_roots) is list and source_roots, 'Actual completed source roots required')
    result = []; names = set()
    for row in source_roots:
        V.require(type(row) is dict and isinstance(row.get('name'), str)
            and row['name'] == V.allowed_name(row['name']) and '/' not in row['name']
            and row['name'] not in names | {'orchestration', APP_ROOT, CAPTURE_ROOT}
            and row.get('kind', 'git') in ('git', 'git-export', 'tree'), 'Unique actual candidate source root required')
        V.ordinary(row['path'], directory=True)
        names.add(row['name']); result.append(dict(row))
    return result


def _preflight(delivery, metadata_root, expected_identity, normal_context, source_roots, evidence_context, budget, limits):
    V.require(os.name == 'posix', 'Completed normal candidate collection requires POSIX; no Windows execution positive')
    delivery = V.ordinary(delivery, directory=True)
    metadata = V.ordinary(metadata_root, directory=True, missing=True)
    V.require(not metadata.exists() and not (delivery / 'producer-validation.json').exists()
        and not (delivery / 'reports/stages/collect.json').exists() and not (delivery / 'sources').exists()
        and not (delivery / 'producer-sdk.json').exists() and not (delivery / CAPTURE_RELATIVE).exists()
        and not (delivery / 'reports/legacy-construction.json').exists(), 'Fresh candidate-only collection outputs required')
    expected = V.identity(expected_identity)
    prepare, stages = V.parent_facts(delivery, expected, require_collect=False)
    V.require(type(evidence_context) is dict and evidence_context.get('sdkVersion') == V.SDK
        and evidence_context.get('architecture') == expected['architecture']
        and evidence_context.get('releaseDir') == str(delivery) and evidence_context.get('diagnosticOnly') is False,
        'Actual normal SDK5 evidence context required; diagnostic input is not a fallback')
    roots = _roots(source_roots)
    selected = {row['name']: dict(path=row['path'], kind=row.get('kind', 'git'), commit=row.get('expectedCommit'),
        **({'role': row['role']} if 'role' in row else {})) for row in roots}
    V.require(evidence_context.get('sourceRoots') == selected, 'Raw emitter and final packer must use the same actual source roots')
    paths = [delivery, V.ROOT, *[Path(value) for value in normal_context['paths'].values()],
             *[Path(row['path']) for row in roots]]
    V.require(all(metadata != path and path not in metadata.parents and metadata not in path.parents for path in paths),
        'Candidate private metadata must not overlap original sources or delivery')
    original = V.load(delivery / 'reports/build/construction.json')
    sdk = original.get('sdkArchive', {})
    V.require(set(sdk) == {'name', *V.FP} and sdk['name'] == Path(sdk['name']).name
        and evidence_context.get('sdkArchive') == str(delivery / sdk['name'])
        and V.file_fingerprint(delivery / V.allowed_name(sdk['name']), limits.file_bytes)
            == {key: sdk[key] for key in V.FP}, 'Original producer/final SDK identity must exist before collection')
    import musl_legacy5_appinsights_normal as N
    N.validate_context(normal_context)
    V.require(all(normal_context.get(key) == expected[key] for key in V.IDENTITY)
        and normal_context['paths']['delivery'] == str(delivery), 'Exact original normal App context required')
    V.preflight_resources(metadata, budget, limits)
    return delivery, metadata, expected, roots, prepare, stages


def collect_completed_normal(delivery, metadata_root, expected_identity, *, normal_context, source_roots,
        evidence_context, budget, limits):
    """No build: require completed normal stages, collect once, then authenticate.

    Failed collection retains its actual failed journal and private D. It never
    writes producer-validation.json and has no workflow/all-D upload endpoint.
    """
    delivery, metadata, expected, roots, _, _ = _preflight(delivery, metadata_root, expected_identity,
        normal_context, source_roots, evidence_context, budget, limits)
    started = datetime.now(timezone.utc).isoformat()
    stage_path = delivery / 'reports/stages/collect.json'
    try:
        emitter = _module('musl_legacy5_evidence.py')
        emitted = emitter.emit(evidence_context)
        raw_path = delivery / 'reports/legacy-construction.json'
        V.require(V.load(raw_path) == emitted, 'Original raw emitter result must equal retained unchanged bytes')
        raw_fp = V.file_fingerprint(raw_path, V.MAX_JSON)
        producer = V.producer_record(delivery, expected, limits)
        _write(delivery / 'producer-sdk.json', producer)
        app = Path(normal_context['paths']['delivery']) / 'reports/build/appinsights'
        V.ordinary(app, directory=True)
        roots.append(dict(name=APP_ROOT, kind='tree', path=str(app), role='sdk5-finite-app-public-source-and-evidence'))
        roots_path = delivery / 'reports/source-roots.json'
        V.require(not roots_path.exists(), 'Fresh explicit candidate source root journal required')
        _write(roots_path, dict(schemaVersion=1, roots=roots))
        # The draft already has the original SDK descriptor; it is not a seal.
        draft = V.draft_record(delivery, expected, limits=limits, require_collect=False)
        validated, actual = V.live_consumption(delivery, draft, normal_context, require_collect=False)
        import musl_legacy5_appinsights_capture as C
        # C.capture invokes M again. No saved validation result is accepted by C.
        C.capture(delivery, draft, actual['proof'], actual['roots'], actual['tooling'],
            app_workspace=actual['app_workspace'], app_host_roots=actual['app_host_roots'],
            sdk_source=actual['sdk_source'], feed=actual['feed'], normal_context=actual['normal_context'],
            destination=delivery / CAPTURE_RELATIVE)
        V.validate_capture(delivery, CAPTURE_RELATIVE, validated, actual)
        roots.append(dict(name=CAPTURE_ROOT, kind='tree', path=str(delivery / CAPTURE_RELATIVE), role=C.KIND))
        _write(roots_path, dict(schemaVersion=1, roots=roots), replace=True)
        packer = _module('package-used-source.py')
        packer.pack(SimpleNamespace(project_root=V.ROOT, project_commit=expected['projectCommit'],
            output_dir=delivery / 'sources', roots_json=roots_path, sdk_version=V.SDK,
            target_rid=expected['targetRid'], run_id=expected['runId'], run_attempt=expected['runAttempt']))
        source_manifest = packer.verify(SimpleNamespace(release_dir=delivery, expected_project_commit=expected['projectCommit'],
            expected_run_id=expected['runId'], expected_run_attempt=expected['runAttempt'], expected_target_rid=expected['targetRid']))
        generated_sources = _module('musl_legacy5_generated_source_inputs.py').validate(delivery, source_manifest)
        _write(delivery / 'reports/candidate-source-gaps.json', dict(schemaVersion=1,
            kind='sdk5-unadmitted-candidate-source-gaps', rawConstructionProof=raw_fp,
            rawEmitterUnknowns=emitted['unknowns'], independentlyResolvedRawUnknowns=[],
            unresolvedRawUnknowns=emitted['unknowns'], semanticCorrespondenceNotDerivedByCollector=True,
            archivedGeneratedDataProviderSources=generated_sources, actualNormalConsumptionCheckedSeparately=True,
            **{key: False for key in V.FLAGS}))
        V.require(V.file_fingerprint(raw_path, V.MAX_JSON) == raw_fp and V.load(raw_path) == emitted,
            'Raw unknowns/repository observations changed during collection')
        _write(stage_path, dict(stage='collect', status='passed', startedAtUtc=started,
            finishedAtUtc=datetime.now(timezone.utc).isoformat(), commands=[],
            scope='candidate-byte-collection-only-not-source-admission'))
        return V.authenticate_normal_candidate(delivery, metadata, expected, normal_context=normal_context,
            capture_relative=CAPTURE_RELATIVE, capture_source_root=CAPTURE_ROOT, budget=budget, limits=limits)
    except Exception as error:
        # A passed collect action is not a retained candidate. Authentication
        # failure supersedes it with an honest terminal failed collect journal.
        _write(stage_path, dict(stage='collect', status='failed', startedAtUtc=started,
            finishedAtUtc=datetime.now(timezone.utc).isoformat(), commands=[],
            errorType=type(error).__name__, error=str(error), candidateSealed=False,
            scope='candidate-byte-collection-only-not-source-admission'), replace=stage_path.exists())
        raise
