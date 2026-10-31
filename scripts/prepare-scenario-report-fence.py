#!/usr/bin/env python3
"""Fence pinned xUnit scenario XML completion after the outer sink returns.

This changes report synchronization only. It preserves the original tests,
filters, execution summary, cancellation result and test failure exit status.
See https://github.com/xunit/xunit/issues/2090 and the pinned v2 utility sinks.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess

TARGET = 'src/scenario-tests/src/Microsoft.DotNet.ScenarioTests.Common/Program.cs'
PINS = {
    '10': ('5a2162bea6845eabc1fc721624a43568c65db3b1', '9a46196a2ba04f54fc7f8b20ae779112b9e6f7aaf494bd2397f54376e2b07137'),
    '9': ('9f04b57d1366e21b3178648493d6edffeff2216e', 'be98752a62758768e6d2589f1f49925abb82720b5e9a2dd609019e674443ae3b'),
}
ORIGINAL = '            var resultsSink = new DelegatingXmlCreationSink(summarySink, resultsXmlAssembly);'
REPLACEMENT = '            var resultsSink = new XmlReportCompletionSink(new DelegatingXmlCreationSink(summarySink, resultsXmlAssembly));'
ANCHOR = '        private static void SetupTestEnvironment('
FENCE = '''        // The inner summary event precedes DelegatingXmlCreationSink's XML finalization.
        // Signal only after the entire finished message has returned through that sink.
        private sealed class XmlReportCompletionSink : Xunit.LongLivedMarshalByRefObject, IExecutionSink
        {
            private readonly IExecutionSink innerSink;

            public XmlReportCompletionSink(IExecutionSink innerSink)
            {
                this.innerSink = innerSink;
            }

            public ExecutionSummary ExecutionSummary => innerSink.ExecutionSummary;

            public System.Threading.ManualResetEvent Finished { get; } = new(false);

            public bool OnMessageWithTypes(IMessageSinkMessage message, HashSet<string> messageTypes)
            {
                var result = innerSink.OnMessageWithTypes(message, messageTypes);
                if (message is ITestAssemblyFinished)
                {
                    Finished.Set();
                }
                return result;
            }

            public void Dispose()
            {
                innerSink.Dispose();
                Finished.Dispose();
            }
        }

'''


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fingerprint(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), sha512=hashlib.sha512(data).hexdigest())


def patched_source(original, version):
    require(version in PINS and hashlib.sha256(original).hexdigest() == PINS[version][1], 'Unknown pinned original scenario runner')
    text = original.decode('utf-8')
    require(text.count(ORIGINAL) == 1 and text.count(ANCHOR) == 1, 'Unexpected scenario runner synchronization layout')
    require(text.count('resultsSink.Finished.WaitOne();') == 1, 'The original report completion wait must remain')
    return text.replace(ORIGINAL, REPLACEMENT).replace(ANCHOR, FENCE + ANCHOR).encode('utf-8')


def ordinary(path):
    require(path.is_absolute() and path.is_file() and not any(p.is_symlink() for p in [path, *path.parents]), 'An ordinary absolute file is required: ' + str(path))
    return path


def verify_report(report_dir, version, helper_path):
    """Recheck the portable receipt against the exact committed helper and blobs."""
    original = ordinary(report_dir / 'Program.original.cs').read_bytes()
    patched = ordinary(report_dir / 'Program.patched.cs').read_bytes()
    require(patched == patched_source(original, version), 'Recorded XML completion fence source differs')
    record = json.loads(ordinary(report_dir / 'scenario-report-fence.json').read_text())
    require(record['schemaVersion'] == 1 and record['status'] == 'passed' and record['action'] == 'apply'
            and record['version'] == version and record['sourceCommit'] == PINS[version][0]
            and record['target'] == TARGET and record['changed'] is True,
            'Actual fresh pinned XML completion fence application required')
    require(record['original'] == fingerprint(original) and record['patched'] == fingerprint(patched)
            and record['helper'] == fingerprint(ordinary(helper_path).read_bytes()),
            'XML completion fence receipt fingerprints differ')
    return record


def apply(source, version, report_dir, action='apply'):
    require(version in PINS, 'Unsupported pinned scenario runner version')
    require(source.is_absolute() and source.is_dir() and not any(p.is_symlink() for p in [source, *source.parents]), 'An ordinary absolute source directory is required')
    git = lambda *args: subprocess.check_output(['git', '--no-optional-locks', '-C', str(source), *args])
    require(git('rev-parse', 'HEAD').decode().strip() == PINS[version][0], 'Unexpected pinned VMR commit')
    require(Path(git('rev-parse', '--show-toplevel').decode().strip()) == source, 'Source must be the VMR Git top level')
    original = git('cat-file', 'blob', 'HEAD:' + TARGET)
    patched = patched_source(original, version)
    target = ordinary(source / TARGET)
    before = target.read_bytes()
    require(before in (original, patched), 'Unknown current scenario runner; preserve it for review')
    require(action != 'verify' or before == patched, 'The XML completion fence is not applied')
    require(report_dir.is_absolute() and source not in report_dir.parents and report_dir != source
            and not report_dir.exists() and not any(p.is_symlink() for p in report_dir.parents), 'A new external ordinary report directory is required')
    report_dir.mkdir(parents=True)
    (report_dir / 'Program.original.cs').write_bytes(original)
    (report_dir / 'Program.patched.cs').write_bytes(patched)
    if before == original:
        target.write_bytes(patched)
    require(target.read_bytes() == patched, 'Scenario runner post-write verification failed')
    record = dict(schemaVersion=1, status='passed', action=action, version=version, sourceCommit=PINS[version][0], target=TARGET,
                  changed=before != patched, original=fingerprint(original), patched=fingerprint(patched),
                  helper=fingerprint(ordinary(Path(__file__).absolute()).read_bytes()),
                  completedAtUtc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  scope='Report completion synchronization only; original tests, filters, summary, cancellation and failure exit checks preserved.',
                  reference='https://github.com/xunit/xunit/issues/2090')
    (report_dir / 'scenario-report-fence.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['apply', 'verify'])
    parser.add_argument('--version', choices=sorted(PINS), required=True)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--reports-dir', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(apply(args.source_dir, args.version, args.reports_dir, args.action)))


if __name__ == '__main__':
    main()
