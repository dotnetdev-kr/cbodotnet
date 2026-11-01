#!/usr/bin/env python3
"""Select an immutable successful promotion stage, including failed publication retries."""
import argparse
import json
import os
import re
import subprocess

REPOSITORY = 'dotnetdev-kr/cbodotnet'
TARGETS = ('net10', 'net9', 'net8', 'net7', 'net6', 'net5', 'core31', 'core30')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def api(path):
    return json.loads(subprocess.check_output(['gh', 'api', 'repos/' + REPOSITORY + '/' + path], text=True))


def select(target, run_id, attempt, run, jobs, artifacts):
    require(target in TARGETS and all(re.fullmatch(r'[1-9][0-9]{0,23}', str(value)) for value in (run_id, attempt)),
            'Invalid exact promotion stage identity')
    require(run['id'] == int(run_id) and run['run_attempt'] == int(attempt)
            and re.fullmatch('[a-f0-9]{40}', run['head_sha'])
            and run['head_branch'] == 'main' and run['event'] == 'workflow_dispatch'
            and run['repository']['full_name'] == run['head_repository']['full_name'] == REPOSITORY
            and run['path'] == '.github/workflows/publish-releases.yml', 'Untrusted promotion producer')
    matches = [job for job in jobs if job['name'] == 'Verify and stage ' + target]
    require(len(matches) == 1 and matches[0]['status'] == 'completed' and matches[0]['conclusion'] == 'success'
            and any(step['name'].startswith('Run actions/upload-artifact@') and step['conclusion'] == 'success'
                    for step in matches[0]['steps']), 'The exact independent verification and upload stage must have passed')
    name = f'public-{target}-{run_id}-{attempt}'
    selected = [artifact for artifact in artifacts if artifact['name'] == name and not artifact['expired']]
    require(len(selected) == 1, 'A unique unexpired exact-attempt promotion artifact is required')
    artifact = selected[0]
    producer = artifact['workflow_run']
    require(type(artifact['id']) is int and artifact['id'] > 0
            and isinstance(artifact.get('digest'), str) and re.fullmatch('sha256:[a-f0-9]{64}', artifact['digest'])
            and producer['id'] == int(run_id) and producer['head_sha'] == run['head_sha']
            and producer['head_branch'] == 'main' and producer['repository_id'] == producer['head_repository_id'],
            'The promotion artifact does not match its trusted successful stage')
    return {'id': str(artifact['id']), 'source_run': str(run_id), 'source_attempt': str(attempt),
            'publication_commit': run['head_sha']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=TARGETS, required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--run-attempt', required=True)
    args = parser.parse_args()
    require(all(re.fullmatch('[1-9][0-9]{0,23}', value) for value in (args.run_id, args.run_attempt)), 'Invalid run identity')
    base = 'actions/runs/' + args.run_id
    run = api(base + '/attempts/' + args.run_attempt)
    jobs = api(base + '/attempts/' + args.run_attempt + '/jobs?per_page=100')
    artifacts = api(base + '/artifacts?per_page=100')
    require(jobs['total_count'] <= 100 and artifacts['total_count'] <= 100, 'Promotion enumeration exceeds its explicit bound')
    selected = select(args.target, args.run_id, args.run_attempt, run, jobs['jobs'], artifacts['artifacts'])
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            for key, value in selected.items():
                output.write(key + '=' + value + '\n')
    print(json.dumps(selected))


if __name__ == '__main__':
    main()
