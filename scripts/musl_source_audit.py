"""Development-only, GET-only revalidation of sealed bytes from a failed musl run.

This tool never admits, publishes, signs, rebuilds or executes an SDK artifact.
Normal musl_release.validate_run still requires successful production origins.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys

from downstream_release import descriptor, encoded, ordinary_file
from musl_contract import ARCHITECTURES, REPOSITORY, require
from musl_release import PRODUCER_WORKFLOW, extract_artifact, extract_delivery, validate_artifact

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = '.github/workflows/musl-source-audit.yml'
STAGES = ['prepare', 'build', 'scan', 'test', 'collect', 'verify']
RUNNERS = {'x64': 'ubuntu-24.04', 'aarch64': 'ubuntu-24.04-arm'}


def sdk_module():
    spec = importlib.util.spec_from_file_location('musl_development_audit_validator', ROOT/'scripts/musl-sdk.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReadOnlyAPI:
    """Only explicit bounded project GET requests; no generic mutation method."""
    def __init__(self, gh='gh'):
        self.gh = gh

    def endpoint(self, endpoint):
        require(isinstance(endpoint, str) and endpoint.startswith('repos/'+REPOSITORY+'/')
                and not any(x in endpoint for x in ['\\', '\0', '\r', '\n', '#'])
                and all(x not in {'.', '..'} for x in endpoint.partition('?')[0].split('/')),
                'Only canonical project API GET endpoints are allowed')
        return endpoint

    def api(self, endpoint):
        result = subprocess.run([self.gh, 'api', self.endpoint(endpoint), '--method', 'GET'],
                                capture_output=True, check=True)
        require(len(result.stdout) <= 16*1024**2, 'Audit API metadata exceeds its bound')
        return json.loads(result.stdout)

    def download(self, artifact, output):
        with output.open('xb') as stream:
            subprocess.run([self.gh, 'api', self.endpoint(
                f'repos/{REPOSITORY}/actions/artifacts/{artifact["id"]}/zip'), '--method', 'GET'],
                stdout=stream, check=True)


def workflow_policy(raw):
    lines = raw.decode('utf-8').splitlines()
    positions = [i for i, line in enumerate(lines) if re.match(r'^\s*permissions\s*:', line)]
    require(len(positions) == 1 and lines[positions[0]] == 'permissions:',
            'Audit requires one explicit top-level permission block without job overrides')
    block = []
    for line in lines[positions[0]+1:]:
        if line and not line[0].isspace() and not line.lstrip().startswith('#'):
            break
        if line.strip() and not line.lstrip().startswith('#'):
            block.append(line)
    require(set(block) == {'  contents: read', '  actions: read'} and len(block) == 2
            and not any(re.match(r'^\s*environment\s*:', x) for x in lines)
            and not re.search(r'secrets\s*[.\[]', raw.decode('utf-8'), re.I),
            'Audit workflow may use only read-only contents/actions and no protected secrets/environment')


def audit_context(api, environ=None):
    env = os.environ if environ is None else environ
    require(env.get('GITHUB_ACTIONS') == 'true' and env.get('GITHUB_REPOSITORY') == REPOSITORY
            and env.get('GITHUB_REF') == 'refs/heads/main' and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and env.get('GITHUB_WORKFLOW_REF') == REPOSITORY+'/'+WORKFLOW+'@refs/heads/main'
            and env.get('GITHUB_WORKFLOW_SHA') == env.get('GITHUB_SHA') and env.get('GITHUB_JOB') == 'audit',
            'Only the exact manual main-branch read-only development audit job may run')
    commit = env.get('GITHUB_SHA', '')
    require(re.fullmatch('[a-f0-9]{40}', commit) and all(re.fullmatch('[1-9][0-9]*', env.get(x, ''))
        for x in ['GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT']), 'Invalid current audit identity')
    require(subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip() == commit,
            'Current audit checkout differs from exact workflow SHA')
    record = api.api(f'repos/{REPOSITORY}/actions/runs/{env["GITHUB_RUN_ID"]}/attempts/{env["GITHUB_RUN_ATTEMPT"]}')
    validate_origin(record, int(env['GITHUB_RUN_ID']), int(env['GITHUB_RUN_ATTEMPT']),
                    workflow=WORKFLOW, failed=False, commit=commit)
    contents = api.api(f'repos/{REPOSITORY}/contents/{WORKFLOW}?ref={commit}')
    require(contents.get('encoding') == 'base64', 'Actual current workflow bytes required')
    raw = base64.b64decode(contents['content'], validate=False)
    require(raw == ordinary_file(ROOT/WORKFLOW).read_bytes(), 'Audit workflow differs from authenticated current commit')
    workflow_policy(raw)
    return dict(repository=REPOSITORY, workflow=WORKFLOW, commit=commit,
                runId=env['GITHUB_RUN_ID'], runAttempt=env['GITHUB_RUN_ATTEMPT'],
                workflowSha256=hashlib.sha256(raw).hexdigest(), permissions=dict(contents='read', actions='read'),
                currentApiRun=record, actualStatus=record.get('status'), actualConclusion=record.get('conclusion'))


def validate_origin(run, run_id, attempt, *, workflow=PRODUCER_WORKFLOW, failed=True, commit=None):
    require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0,
            'Exact positive run and attempt required')
    require(isinstance(run, dict) and run.get('id') == run_id and run.get('run_attempt') == attempt
            and run.get('path') == workflow and run.get('head_branch') == 'main'
            and run.get('event') == 'workflow_dispatch' and run.get('repository', {}).get('full_name') == REPOSITORY
            and run.get('head_repository', {}).get('full_name') == REPOSITORY
            and re.fullmatch('[a-f0-9]{40}', run.get('head_sha', ''))
            and (commit is None or run['head_sha'] == commit), 'Exact trusted main workflow origin required')
    valid_lifecycle = ((failed and run.get('status') == 'completed' and run.get('conclusion') == 'failure')
            or (not failed and run.get('status') in {'queued', 'in_progress'} and run.get('conclusion') is None))
    if not valid_lifecycle:
        error = ValueError('Development audit requires a completed failed source and its exact active audit run; '
            f'actual status={run.get("status")!r}, conclusion={run.get("conclusion")!r}, failedSource={failed!r}')
        error.api_context = dict(role='failed-source' if failed else 'current-audit', actualRun=run,
                                 actualStatus=run.get('status'), actualConclusion=run.get('conclusion'))
        raise error
    return run['head_sha']


def pages(api, endpoint, key):
    result = []
    for page in range(1, 11):
        data = api.api(endpoint+f'?per_page=100&page={page}')
        require(isinstance(data, dict) and isinstance(data.get(key), list), 'Invalid bounded API listing')
        result.extend(data[key])
        if len(data[key]) < 100:
            return result
    raise ValueError('Audit API listing exceeds ten pages')


def native_jobs(run, jobs):
    selected = {}
    for arch, label in RUNNERS.items():
        matches = [j for j in jobs if j.get('name') == 'Native Alpine 3.24.4 '+arch]
        require(len(matches) == 1, 'Both original exact native producer jobs are required')
        job = matches[0]
        require(job.get('status') == 'completed' and job.get('conclusion') == 'failure'
                and job.get('head_sha') == run['head_sha'] and job.get('run_id') == run['id']
                and type(job.get('id')) is int and job['id'] > 0
                and type(job.get('runner_id')) is int and job['runner_id'] > 0
                and job.get('runner_group_name') == 'GitHub Actions'
                and job.get('runner_name') == 'GitHub Actions '+str(job['runner_id'])
                and isinstance(job.get('labels'), list) and label in job['labels']
                and 'self-hosted' not in job['labels'], 'Source job is not the completed failed native GitHub-hosted CPU job')
        start, end = [datetime.fromisoformat(job[k].replace('Z', '+00:00')) for k in ['started_at', 'completed_at']]
        require(start.tzinfo is not None and end >= start, 'Invalid native job timestamps')
        selected[arch] = job
    require(selected['x64']['id'] != selected['aarch64']['id'], 'Native matrix jobs must differ')
    return selected


def fresh(path):
    path = Path(path).absolute()
    require(not path.exists() and path.parent.is_dir() and not any(p.is_symlink() for p in [path, *path.parents]),
            'Use a fresh ordinary development audit path')
    path.mkdir()
    return path


def sealed_subset(original, output, run, arch):
    """Copy only the unchanged seal-declared ordinary files; never edit the original."""
    validator = sdk_module()
    original = Path(original).absolute()
    seal_path = ordinary_file(original/'producer-validation.json')
    seal = validator.load_json(seal_path)
    require(seal.get('schemaVersion') == 1 and seal.get('status') == 'passed'
            and seal.get('kind') == 'musl-sdk-producer-validation' and seal.get('diagnosticPtrace') is False
            and seal.get('architecture') == arch and seal.get('targetRid') == ARCHITECTURES[arch]['rid']
            and seal.get('libc') == 'musl' and seal.get('projectCommit') == run['head_sha']
            and seal.get('runId') == str(run['id']) and seal.get('runAttempt') == str(run['run_attempt'])
            and seal.get('allRequiredStages') == STAGES, 'Original source seal/project/run/mode differs')
    rows = seal.get('files')
    require(isinstance(rows, list) and 0 < len(rows) <= 100000, 'A bounded nonempty original source seal is required')
    output = fresh(output); names = set()
    for row in rows:
        require(isinstance(row, dict) and isinstance(row.get('path'), str), 'Invalid sealed file row')
        name = row['path']; relative = PurePosixPath(name)
        require(relative.parts and not relative.is_absolute() and relative.as_posix() == name
                and all(x not in {'.', '..'} for x in relative.parts)
                and not any(c in name for c in '\\:\0\r\n') and name not in names
                and name != 'producer-validation.json', 'Unsafe or duplicate sealed path')
        names.add(name); incoming = ordinary_file(original.joinpath(*relative.parts))
        require(all(row.get(k) == v for k, v in validator.fingerprint(incoming).items()), 'Original sealed bytes differ: '+name)
        target = output.joinpath(*relative.parts); target.parent.mkdir(parents=True, exist_ok=True)
        with incoming.open('rb') as source, target.open('xb') as destination:
            shutil.copyfileobj(source, destination, 4*1024**2)
        require(all(row.get(k) == v for k, v in validator.fingerprint(target).items()), 'Copied sealed bytes differ: '+name)
    shutil.copyfile(seal_path, output/'producer-validation.json')
    validator.delivery_index(output, rows)
    prepare = validator.load_json(output/'reports/prepare/identity.json')
    require(prepare.get('diagnosticPtrace') is False and prepare.get('projectCommit') == run['head_sha'],
            'Original prepare identity is diagnostic or does not match source commit')
    for name in STAGES:
        stage = validator.load_json(output/'reports/stages'/ (name+'.json'))
        require(stage.get('stage') == name and stage.get('status') == 'passed', 'An original required stage failed: '+name)
    excluded = sorted(p.relative_to(original).as_posix() for p in original.rglob('*') if p.is_file()
                      and p.relative_to(original).as_posix() not in names | {'producer-validation.json'})
    return output, dict(seal=descriptor(seal_path), declaredFileCount=len(names), excludedFileCount=len(excluded),
                        excludedFiles=excluded[:100], excludedFilesTruncated=len(excluded)>100)


def audit(run_id, attempt, arch, workspace, output, *, api=None):
    require(arch in ARCHITECTURES, 'Exact public native architecture required')
    api = ReadOnlyAPI() if api is None else api
    current = audit_context(api)
    run = api.api(f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}')
    validate_origin(run, run_id, attempt)
    jobs = native_jobs(run, pages(api, f'repos/{REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}/jobs', 'jobs'))
    artifacts = pages(api, f'repos/{REPOSITORY}/actions/runs/{run_id}/artifacts', 'artifacts')
    matches = [a for a in artifacts if a.get('name') == f'sdk-musl-net10-{arch}-{run_id}-{attempt}']
    require(len(matches) == 1, 'Exactly one authentic source artifact is required')
    artifact = validate_artifact(matches[0], run, matches[0]['name'])
    workspace = fresh(workspace); output = Path(output).absolute()
    require(not output.exists() and output.parent.is_dir() and workspace not in output.parents
            and not any(p.is_symlink() for p in [output, *output.parents]), 'Use a fresh external audit report path')
    archive = workspace/'source.zip'; api.download(artifact, archive)
    bundle = extract_artifact(archive, workspace/'transport',
        {'delivery.tar.gz', 'delivery.tar.gz.sha256', 'delivery.json'}, api_artifact=artifact)
    actual = descriptor(bundle/'delivery.tar.gz'); transport = sdk_module().load_json(bundle/'delivery.json')
    expected = dict(schemaVersion=1, kind='musl-sdk-producer-transport', status='passed', sdkVersion='10.0.403',
        libc='musl', architecture=arch, projectCommit=run['head_sha'], repository=REPOSITORY,
        runId=str(run_id), runAttempt=str(attempt), workflow=PRODUCER_WORKFLOW, bundle=actual)
    require(transport == expected, 'Original source transport record differs from exact API run or bundle')
    require((bundle/'delivery.tar.gz.sha256').read_text(encoding='ascii') in
        {actual['sha256']+'  delivery.tar.gz\n', actual['sha256']+' *delivery.tar.gz\n'}, 'Original envelope checksum differs')
    original = extract_delivery(bundle/'delivery.tar.gz', workspace/'original')
    subset, selection = sealed_subset(original, workspace/'sealed-subset', run, arch)
    log = workspace/'validator.log'
    with log.open('xb') as stream:
        result = subprocess.run([sys.executable, str(ROOT/'scripts/musl-sdk.py'), 'validate', '--release-dir', str(subset)],
            stdout=stream, stderr=subprocess.STDOUT)
    raw = log.read_bytes()
    record = dict(schemaVersion=1, kind='musl-failed-source-development-audit', status='dev-only-pass' if result.returncode==0 else 'dev-only-fail',
        devOnly=True, sourceAdmission=False, productionQualification=False, publicationAllowed=False,
        architecture=arch, audit=current, sourceRun=run, nativeSourceJobs=jobs,
        artifact=artifact, artifactZip=descriptor(archive), envelope=actual, selection=selection,
        canonicalApiMetadataSha256=dict(sourceRun=hashlib.sha256(encoded(run)).hexdigest(),
            nativeJobs=hashlib.sha256(encoded(jobs)).hexdigest(), artifact=hashlib.sha256(encoded(artifact)).hexdigest()),
        validator=dict(exitCode=result.returncode, code=descriptor(ROOT/'scripts/musl-sdk.py'),
                       log=descriptor(log), stdoutTail=raw[-16000:].decode('utf-8', errors='replace')))
    output.write_bytes(encoded(record))
    require(result.returncode == 0, 'Development-only revalidation failed; see exact validator log/report')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', type=int, required=True); parser.add_argument('--attempt', type=int, required=True)
    parser.add_argument('--arch', choices=sorted(ARCHITECTURES), required=True)
    parser.add_argument('--workspace', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = audit(args.run_id, args.attempt, args.arch, args.workspace, args.output)
    except Exception as error:
        failure_report(args.output, args, error)
        raise
    print(json.dumps(dict(status=result['status'], architecture=args.arch, sourceAdmission=False, productionQualification=False)))


def failure_report(output, args, error):
    """Preserve early failure reasons without overwriting a more complete result."""
    output = Path(output).absolute()
    if output.exists() or not output.parent.is_dir() or any(p.is_symlink() for p in [output, *output.parents]):
        return
    report = dict(schemaVersion=1, kind='musl-failed-source-development-audit', status='dev-only-fail',
        devOnly=True, sourceAdmission=False, productionQualification=False, publicationAllowed=False,
        architecture=args.arch, requestedSourceRunId=args.run_id, requestedSourceAttempt=args.attempt,
        originValidationCompleted=False, error=dict(type=type(error).__name__, reason=str(error)[-16000:]))
    if hasattr(error, 'api_context'):
        report['apiContext'] = error.api_context
    with output.open('xb') as stream:
        stream.write(encoded(report))


if __name__ == '__main__':
    main()
