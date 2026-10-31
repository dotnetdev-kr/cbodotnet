#!/usr/bin/env python3
"""Deterministically reproduce the XML race with an actual xUnit utility DLL.

The explicit CLI uses an existing SDK and pinned original runner blobs. It does
not restore packages, execute product tests, or modify an existing source tree.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest
import xml.sax.saxutils

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('scenario_fence', ROOT / 'scripts/prepare-scenario-report-fence.py')
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)

FIXTURE = r'''
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Xunit;
using Xunit.Abstractions;
using Xunit.Sdk;

public class InterfaceProxy : DispatchProxy
{
    public Dictionary<string, object> Values = new();
    protected override object Invoke(MethodInfo method, object[] args)
        => Values.TryGetValue(method.Name, out var value) ? value : null;
}

public class Fixture
{
    static int assertions;
    static void Check(bool condition, string description)
    {
        if (!condition) throw new Exception(description);
        assertions++;
    }

    sealed class BarrierSink : IExecutionSink
    {
        readonly IExecutionSink inner;
        public readonly ManualResetEvent Entered = new(false);
        public readonly ManualResetEvent Release = new(false);
        public BarrierSink(IExecutionSink inner) { this.inner = inner; }
        public ExecutionSummary ExecutionSummary => inner.ExecutionSummary;
        public ManualResetEvent Finished => inner.Finished;
        public bool OnMessageWithTypes(IMessageSinkMessage message, HashSet<string> types)
        {
            var result = inner.OnMessageWithTypes(message, types);
            if (message is ITestAssemblyFinished)
            {
                Entered.Set();
                if (!Release.WaitOne(TimeSpan.FromSeconds(10))) throw new Exception("Fixture barrier timed out");
            }
            return result;
        }
        public void Dispose() { inner.Dispose(); Entered.Dispose(); Release.Dispose(); }
    }

    sealed class ThrowingSink : IExecutionSink
    {
        public ExecutionSummary ExecutionSummary { get; } = new();
        public ManualResetEvent Finished { get; } = new(false);
        public bool OnMessageWithTypes(IMessageSinkMessage message, HashSet<string> types) => throw new InvalidOperationException("original failure");
        public void Dispose() { Finished.Dispose(); }
    }

__FENCE__

    static ITestAssemblyFinished FinishedMessage()
    {
        var message = DispatchProxy.Create<ITestAssemblyFinished, InterfaceProxy>();
        var proxy = (InterfaceProxy)(object)message;
        proxy.Values["get_TestsRun"] = 3;
        proxy.Values["get_TestsFailed"] = 1;
        proxy.Values["get_TestsSkipped"] = 1;
        proxy.Values["get_ExecutionTime"] = 0.25m;
        return message;
    }

    public static void Main()
    {
#pragma warning disable CS0618 // Exercise the same original obsolete sinks as the pinned runner.
        Console.WriteLine("Actual utility: " + typeof(DelegatingXmlCreationSink).Assembly.FullName);
#pragma warning restore CS0618
        var message = FinishedMessage();
        var types = new HashSet<string> { typeof(ITestAssemblyFinished).FullName };
        foreach (bool cancelled in new[] { false, true })
        {
#pragma warning disable CS0618 // Exercise the original sink chain; the production wrapper above has no suppression.
            var summary = new DelegatingExecutionSummarySink(new TestMessageSink(), () => cancelled);
            var barrier = new BarrierSink(summary);
            var xml = new XElement("assembly");
            var original = new DelegatingXmlCreationSink(barrier, xml);
#pragma warning restore CS0618
            var fence = new XmlReportCompletionSink(original);
            var worker = Task.Run(() => fence.OnMessageWithTypes(message, types));
            try
            {
                Check(barrier.Entered.WaitOne(TimeSpan.FromSeconds(10)), "Real inner summary must process completion");
                Check(original.Finished.WaitOne(0), "Old wait releases before XML finalization");
                Check(xml.Attribute("total") == null, "Observed original premature completion has no XML totals");
                Check(!fence.Finished.WaitOne(0), "New fence must remain closed while outer XML sink is incomplete");
            }
            finally { barrier.Release.Set(); }
            Check(worker.GetAwaiter().GetResult() == !cancelled, "Original cancellation result must be preserved");
            Check(fence.Finished.WaitOne(0), "New fence completes after outer forwarding returns");
            Check((int)xml.Attribute("total") == 3 && (int)xml.Attribute("passed") == 1
                  && (int)xml.Attribute("failed") == 1 && (int)xml.Attribute("skipped") == 1,
                  "Real XML must have complete unchanged summary counts");
            Check(fence.ExecutionSummary.Failed == 1, "Original failing test count remains visible");
            fence.Dispose();
        }
        using (var fence = new XmlReportCompletionSink(new ThrowingSink()))
        {
            try { fence.OnMessageWithTypes(message, types); throw new Exception("Original exception swallowed"); }
            catch (InvalidOperationException error) { Check(error.Message == "original failure", "Original exception propagates"); }
            Check(!fence.Finished.WaitOne(0), "An incomplete exceptional XML sink must not signal success");
        }
        Console.WriteLine("Passed deterministic assertions: " + assertions);
    }
}
'''


class SourceGuards(unittest.TestCase):
    def test_exact_pinned_runners_only_change_report_synchronization(self):
        for version in ('10', '9'):
            original = (ROOT / ('tests/fixtures/scenario-report-fence/Program.net' + version + '.original.cs')).read_bytes()
            patched = F.patched_source(original, version)
            self.assertEqual(patched.replace(F.FENCE.encode(), b'').replace(F.REPLACEMENT.encode(), F.ORIGINAL.encode()), original)
            self.assertEqual(patched.count(b'resultsSink.Finished.WaitOne();'), 1)

    def test_unknown_source_or_changed_wait_is_rejected(self):
        for version in ('10', '9'):
            original = (ROOT / ('tests/fixtures/scenario-report-fence/Program.net' + version + '.original.cs')).read_bytes()
            for changed in (original + b'\n', original.replace(b'resultsSink.Finished.WaitOne();', b'testsFinished.Task.Wait();')):
                with self.assertRaisesRegex(ValueError, 'Unknown pinned original'):
                    F.patched_source(changed, version)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('dotnet', 'utility', 'abstractions', 'core', 'execution', 'source10', 'source9', 'output-dir'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    F.require(args.output_dir.is_absolute() and not args.output_dir.exists(), 'A new absolute fixture output is required')
    for version in ('10', '9'):
        original = getattr(args, 'source' + version).read_bytes()
        patched = F.patched_source(original, version)
        F.require(patched.count(F.FENCE.encode()) == 1 and patched.count(F.REPLACEMENT.encode()) == 1, 'Exactly one completion fence required')
        F.require(patched.replace(F.FENCE.encode(), b'').replace(F.REPLACEMENT.encode(), F.ORIGINAL.encode()) == original,
                  'No other pinned source bytes may change')
        for malformed in (original + b'\n', original.replace(b'resultsSink.Finished.WaitOne();', b'testsFinished.Task.Wait();')):
            try:
                F.patched_source(malformed, version)
            except ValueError:
                pass
            else:
                raise AssertionError('Unknown or unsafe pinned source was accepted')
    output = args.output_dir
    output.mkdir(parents=True)
    # Use the exact production fence implementation, not a test reimplementation.
    (output / 'Program.cs').write_text(FIXTURE.replace('__FENCE__', F.FENCE), encoding='utf-8')
    refs = ''.join('<Reference Include="' + name + '"><HintPath>' + xml.sax.saxutils.escape(str(path))
                   + '</HintPath></Reference>' for name, path in [('xunit.runner.utility', args.utility), ('xunit.abstractions', args.abstractions),
                                                                 ('xunit.core', args.core), ('xunit.execution', args.execution)])
    major = subprocess.check_output([str(args.dotnet), '--version']).decode().strip().split('.')[0]
    (output / 'Fixture.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net' + major
                                         + '.0</TargetFramework><OutputType>Exe</OutputType><ImplicitUsings>enable</ImplicitUsings>'
                                         + '<TreatWarningsAsErrors>true</TreatWarningsAsErrors></PropertyGroup><ItemGroup>' + refs + '</ItemGroup></Project>\n')
    (output / 'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>\n')
    private = output / 'private'; private.mkdir(mode=0o700)
    env = dict(os.environ, HOME=str(private), DOTNET_CLI_HOME=str(private), XDG_RUNTIME_DIR=str(private),
               DOTNET_GENERATE_ASPNET_CERTIFICATE='false', DOTNET_CLI_TELEMETRY_OPTOUT='1')
    commands = [[str(args.dotnet), 'build', str(output / 'Fixture.csproj'), '--configfile', str(output / 'NuGet.Config'), '--nologo'],
                [str(args.dotnet), str(output / ('bin/Debug/net' + major + '.0/Fixture.dll'))]]
    for index, command in enumerate(commands):
        result = subprocess.run(command, cwd=output, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
        (output / ('command-' + str(index) + '.log')).write_bytes(result.stdout)
        print(result.stdout.decode(errors='replace'))
        F.require(result.returncode == 0, 'Actual xUnit fixture command failed')
    (output / 'fixture-result.json').write_text(json.dumps(dict(status='passed', commands=commands,
        helper=F.fingerprint((ROOT / 'scripts/prepare-scenario-report-fence.py').read_bytes()),
        fixture=F.fingerprint(Path(__file__).read_bytes()),compiledSource=F.fingerprint((output / 'Program.cs').read_bytes()),
        inputs={name: dict(path=str(getattr(args, name)), **F.fingerprint(getattr(args, name).read_bytes()))
                for name in ('dotnet', 'utility', 'abstractions', 'core', 'execution', 'source10', 'source9')},
        scope='Actual pinned xUnit utility with deterministic post-summary barrier; no product test rerun.'), indent=2) + '\n')


if __name__ == '__main__':
    main()
