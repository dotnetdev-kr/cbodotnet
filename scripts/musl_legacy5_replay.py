"""Run the unchanged binary-log reader and retain legitimate empty replays."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

EMPTY_STAGES = {'original-solution-restore', 'original-net451-reference-package-restore',
                'Microsoft.TestPlatform.CLI-pack', 'Microsoft.TestPlatform.Build-pack'}


def validate(status, binlog, name, exit_code):
    if not (status.get('completedReplay') is True and status.get('buildSucceeded') is True
            and status.get('unfinishedTasks') == status.get('unfinishedSelectedTasks') == 0
            and status.get('failure') is None and status.get('inputSha256') == hashlib.sha256(binlog.read_bytes()).hexdigest()):
        raise ValueError('An unchanged complete successful SDK5 process binary-log replay is required')
    count = status.get('completedSelectedTasks')
    if not (type(count) is int and count >= 0 and
            ((exit_code == 0 and count > 0) or (exit_code == 1 and count == 0 and name in EMPTY_STAGES))):
        raise ValueError('Only the four original SDK5 VSTest stages may have zero selected reader tasks')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('dotnet', 'reader', 'sdk-dir', 'binlog', 'prefix'): parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--name', required=True); args = parser.parse_args()
    for path in (args.dotnet, args.reader, args.sdk_dir, args.binlog, args.prefix):
        if not path.is_absolute() or any(item.is_symlink() for item in (path, *path.parents)):
            raise ValueError('Ordinary absolute SDK5 reader paths required')
    if any(Path(str(args.prefix) + suffix).exists() for suffix in ('-status.json', '-tasks.jsonl', '-reader-command.json')):
        raise ValueError('Fresh SDK5 process replay outputs required')
    command = list(map(str, [args.dotnet, args.reader, args.binlog, args.sdk_dir, args.prefix]))
    result = subprocess.run(command, check=False)
    status = json.loads(Path(str(args.prefix) + '-status.json').read_text())
    validate(status, args.binlog, args.name, result.returncode)
    record = dict(replayName=args.name, command=command, readerExitCode=result.returncode,
        inputSha256=status['inputSha256'], selectedTasks=status['completedSelectedTasks'],
        emptyReplayHonestlyRetained=status['completedSelectedTasks'] == 0, contextsRenumbered=False,
        syntheticMergedReplay=False, qualificationAllowed=False, sourceAdmissionAllowed=False)
    Path(str(args.prefix) + '-reader-command.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__': main()
