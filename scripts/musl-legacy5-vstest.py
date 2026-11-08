#!/usr/bin/env python3
"""Build the exact SDK5 VSTest source graph and its genuine dev packages.

The original source-build graph supplies Core hosts. Publisher-only Full/Mono
test hosts and closed coverage binaries are outside this Linux CLI layout.
Source and byte-consumption admission remain independent of this worker.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile

from musl_legacy5_nuget_graph import verify_original_raw_tree
import musl_managed_metadata as MANAGED
import musl_legacy_xlf as XLF

SDK = '5.0.214'
COMMIT = '99b911a57a02fc5d2eeef23e9ab8cbea4505678b'
VERSION = '16.9.4-dev'
FEEDS = ['https://api.nuget.org/v3/index.json',
    'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-tools/nuget/v3/index.json',
    'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet5/nuget/v3/index.json',
    'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public/nuget/v3/index.json',
    'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-eng/nuget/v3/index.json',
    'https://pkgs.dev.azure.com/dnceng/public/_packaging/test-tools/nuget/v3/index.json']


POLICY_SHA256 = '7f05db8d8910040c78fa3fb4103bfb53d7ff80488b9aadcffd730a05837d27bb'


def input_policy():
    path = Path(__file__).with_name('musl-legacy5-vstest-inputs.json')
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == POLICY_SHA256, 'Closed SDK5 VSTest input policy changed')
    policy = json.loads(raw)
    require(policy['sdkVersion'] == SDK and policy['sourceCommit'] == COMMIT and policy['sourceVersion'] == VERSION,
            'Exact SDK5 VSTest policy identity required')
    return policy


def check_reference_package(path):
    expected = input_policy()['compilerReferencePackage']
    require(path.is_file() and path.stat().st_size == expected['bytes'], 'Exact original net451 reference package size required')
    require(fingerprint(path) == {k: expected[k] for k in ('bytes', 'sha256', 'sha512')},
            'Exact original net451 reference package bytes required')


def check_imported_members(actual):
    require(actual == input_policy()['imports'], 'Closed original VSTest5 imported managed member bytes differ')


def require(value, message):
    if not value: raise ValueError(message)


def ordinary(path):
    require(path.is_absolute() and path != Path('/') and not any(p.is_symlink() for p in (path, *path.parents)),
            'An ordinary absolute source/output/bootstrap path is required')


def fingerprint(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2); stream.write('\n')


def git(source, *args):
    return subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), '-C', str(source), *args], text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', choices=[SDK], required=True)
    parser.add_argument('--arch', choices=['aarch64', 'x64'], required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--dotnet', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    for path in [args.source, args.dotnet, args.output]: ordinary(path)
    require(platform.system() == 'Linux' and os.getuid() != 0 and platform.machine() ==
            {'aarch64': 'aarch64', 'x64': 'x86_64'}[args.arch] and
            Path('/etc/alpine-release').read_text().strip() == '3.24.4', 'Matching native non-root Alpine 3.24.4 is required')
    original_tree = verify_original_raw_tree(args.source, COMMIT)
    require(not args.output.exists(), 'A fresh VSTest output directory is required')
    args.output.mkdir(parents=True)
    write(args.output / 'original-raw-git-tree.json', original_tree)
    settings = ET.parse(args.source / 'scripts/build/TestPlatform.Settings.targets')
    namespace = {'m': 'http://schemas.microsoft.com/developer/msbuild/2003'}
    require(settings.find('.//m:TPVersionPrefix', namespace).text == '16.9.4' and
            settings.find('.//m:Version', namespace).text == '$(TPVersionPrefix)-dev', 'Original VSTest dev version policy changed')
    input_policy()
    resources = XLF.generate(args.source, args.output / 'xlf-resource-generation.json', COMMIT)
    require(len(resources['rows']) == 234, 'The complete original SDK5 XLF set is required')
    generated = args.output / 'generated'; generated.mkdir()
    for row in resources['rows']:
        destination = generated / row['generated']; destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.source / row['generated'], destination)
    rid = 'linux-musl-' + ('arm64' if args.arch == 'aarch64' else 'x64')
    environment = dict(os.environ, DOTNET_ROOT=str(args.dotnet.parent), DOTNET_MULTILEVEL_LOOKUP='0',
        DOTNET_PROCESSOR_COUNT='1', DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',
        NUGET_PACKAGES=str(args.source / '.packages'), MSBUILDDISABLENODEREUSE='1')
    common = ['/p:Configuration=Release', '/p:DotNetBuildFromSource=true', '/p:LocalizedBuild=true',
        '/p:UseSharedCompilation=false', '/p:UseAppHost=false', '/p:EmitCompilerGeneratedFiles=true',
        '/p:NETCoreSdkRuntimeIdentifier=' + rid, '/p:ToolsRID=' + rid,
        '/p:RepositoryCommit=' + COMMIT, '/p:SourceRevisionId=' + COMMIT,
        '/p:RestoreSources=' + '%3B'.join(FEEDS), '/m:1', '/nologo']
    version_command = [str(args.dotnet), '--version']
    actual_version = subprocess.check_output(version_command, cwd=args.source, env=environment, text=True).strip()
    require(actual_version == '6.0.135', 'Exact compiler bootstrap6.0.135 required by this reviewed SDK5 source route')
    write(args.output / 'compiler-bootstrap.json', dict(command=version_command, version=actual_version, originalGlobalJsonUnchanged=True))
    commands = []

    def run(name, project, targets, extra=(), source_build=True):
        selected_common = common if source_build else [item.replace('/p:DotNetBuildFromSource=true', '/p:DotNetBuildFromSource=false') for item in common]
        command = list(map(str, [args.dotnet, 'msbuild', project, *selected_common, '/t:' + targets, *extra,
                                '/bl:' + str(args.output / (name + '.binlog'))]))
        started = datetime.now(timezone.utc).isoformat(); log = args.output / (name + '.log')
        with log.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(command) + '\n'); stream.flush()
            process = subprocess.run(command, cwd=args.source, env=environment, stdout=stream, stderr=subprocess.STDOUT, timeout=900)
        row = dict(name=name, command=command, exitCode=process.returncode, startedAt=started,
            completedAt=datetime.now(timezone.utc).isoformat(), log=log.name, **fingerprint(log))
        commands.append(row); write(args.output / (name + '-command.json'), row)
        require(process.returncode == 0, 'An original VSTest source command failed: ' + name)

    solution = args.source / 'TestPlatform_BuildFromSource.sln'
    run('original-solution-restore', solution, 'Restore')
    run('original-solution-build', solution, 'Build')
    stage = args.source / 'artifacts/Release'; stage.mkdir(parents=True, exist_ok=True)
    layout = stage / 'netcoreapp2.1'; layout.mkdir()
    for relative in ['src/package/package/package.csproj', 'src/vstest.console/vstest.console.csproj',
                     'src/datacollector/datacollector.csproj', 'src/testhost/testhost.csproj', 'src/testhost.x86/testhost.x86.csproj']:
        project = args.source / relative
        run(project.parent.name + '-publish', project, 'Restore;Publish', ['/p:TargetFramework=netcoreapp2.1', '/p:PublishDir=' + str(layout) + '/'])
    testhost = layout / 'TestHost'; testhost.mkdir()
    for name in ['testhost', 'testhost.x86']:
        for original in (args.source / 'src' / name / 'bin/Release/netcoreapp2.1').iterdir():
            if original.is_dir(): shutil.copytree(original, testhost / original.name, dirs_exist_ok=True)
            elif original.is_file(): shutil.copyfile(original, testhost / original.name)
    extensions = layout / 'Extensions'; extensions.mkdir()
    projects = {
        'Microsoft.TestPlatform.Extensions.TrxLogger': 'Microsoft.VisualStudio.TestPlatform.Extensions.Trx.TestLogger',
        'Microsoft.TestPlatform.Extensions.HtmlLogger': 'Microsoft.VisualStudio.TestPlatform.Extensions.Html.TestLogger',
        'Microsoft.TestPlatform.Extensions.BlameDataCollector': 'Microsoft.TestPlatform.Extensions.BlameDataCollector',
        'Microsoft.TestPlatform.TestHostProvider': 'Microsoft.TestPlatform.TestHostRuntimeProvider'}
    reference_inputs = args.output / 'reference-inputs'; reference_inputs.mkdir()
    reference_project = reference_inputs / 'ReferenceBootstrap.csproj'
    reference_project.write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>netstandard2.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Microsoft.NETFramework.ReferenceAssemblies.net451" Version="1.0.3" ExcludeAssets="all" /></ItemGroup></Project>\n')
    run('original-net451-reference-package-restore', reference_project, 'Restore')
    reference_package = args.source / '.packages/microsoft.netframework.referenceassemblies.net451/1.0.3/microsoft.netframework.referenceassemblies.net451.1.0.3.nupkg'
    require(reference_package.is_file(), 'Real official net451 reference package restore is required')
    check_reference_package(reference_package)
    with zipfile.ZipFile(reference_package) as archive:
        node = ET.fromstring(archive.read(next(n for n in archive.namelist() if n.endswith('.nuspec')))).find('{*}metadata')
        require(node.findtext('{*}id') == 'Microsoft.NETFramework.ReferenceAssemblies.net451' and node.findtext('{*}version') == '1.0.3', 'Exact original net451 reference identity required')
    shutil.copyfile(reference_package, reference_inputs / reference_package.name)
    shutil.copyfile(reference_package.parent / '.nupkg.metadata', reference_inputs / 'original-nupkg.metadata')
    reference_path = reference_package.parent / 'build/.NETFramework/v4.5.1'
    require((reference_path / 'mscorlib.dll').is_file(), 'Original net451 compiler reference directory missing')
    write(reference_inputs / 'origin.json', dict(package=dict(path=reference_package.name, **fingerprint(reference_package)), framework='net451', onlyCompilerReferenceInput=True, productTargetFrameworkChanged=False, referenceAssembliesCopiedToProduct=False, qualificationAllowed=False))
    eventlog = args.source / 'src/DataCollectors/Microsoft.TestPlatform.Extensions.EventLogCollector/Microsoft.TestPlatform.Extensions.EventLogCollector.csproj'
    reference_targets = reference_package.parent / 'build/Microsoft.NETFramework.ReferenceAssemblies.net451.targets'
    require(reference_targets.is_file(), 'Original reference-package build target is required')
    shutil.copyfile(reference_targets, reference_inputs / reference_targets.name)
    run('original-eventlog-net451-build', eventlog, 'Restore;Build', ['/p:CustomAfterMicrosoftCommonTargets=' + str(reference_targets)], source_build=False)
    projects['DataCollectors/Microsoft.TestPlatform.Extensions.EventLogCollector'] = 'Microsoft.TestPlatform.Extensions.EventLogCollector'
    extension_resources = []
    for project, base in projects.items():
        built = args.source / 'src' / project / ('bin/Release/net451' if project.startswith('DataCollectors/') else 'bin/Release/netstandard2.0')
        for suffix in ['.dll', '.pdb']:
            original = built / (base + suffix)
            require(original.is_file(), 'An original source-built extension is absent')
            shutil.copyfile(original, extensions / original.name)
            if (layout / original.name).is_file(): (layout / original.name).unlink()
        for culture in sorted(XLF.CULTURES):
            original = built / culture / (base + '.resources.dll')
            if original.is_file():
                destination = extensions / culture / original.name; destination.parent.mkdir(exist_ok=True)
                shutil.copyfile(original, destination)
                extension_resources.append(dict(path=destination.relative_to(stage).as_posix(), **fingerprint(destination)))
                if (layout / culture / original.name).is_file(): (layout / culture / original.name).unlink()
    dependency = args.source / 'src/Microsoft.TestPlatform.Extensions.BlameDataCollector/bin/Release/netstandard2.0/Microsoft.Diagnostics.NETCore.Client.dll'
    require(dependency.is_file(), 'Original Blame project CopyLocalLockFileAssemblies dependency is missing')
    shutil.copyfile(dependency, extensions / dependency.name)
    write(args.output / 'imported-blame-client.json', dict(originalPackageReference='Microsoft.Diagnostics.NETCore.Client/0.2.0-preview.20419.2', output=str(dependency), **fingerprint(dependency), compiledHere=False, separateSourceAttributionRequired=True))
    shutil.copytree(args.source / 'src/Microsoft.TestPlatform.Build/bin/Release', stage / 'Microsoft.TestPlatform.Build')
    nuspec = args.source / 'src/package/nuspec'
    for name in ['Microsoft.TestPlatform.CLI.csproj', 'Microsoft.TestPlatform.Build.csproj', 'TestPlatform.CLI.nuspec', 'TestPlatform.Build.nuspec']:
        shutil.copyfile(nuspec / name, stage / name)
    for name in ['ThirdPartyNotices.txt', 'Icon.png']: shutil.copyfile(args.source / 'src/package' / name, stage / name)
    shutil.copytree(args.source / 'src/package/licenses', stage / 'licenses')
    adaptations = []
    for name, old_tfm in [('TestPlatform.CLI.nuspec', 'netcoreapp2.1'), ('TestPlatform.Build.nuspec', 'netstandard2.0')]:
        path = stage / name
        original = path.read_bytes()
        require(original == (nuspec / name).read_bytes() and old_tfm.encode() in original and b'<version>15.0.0</version>' in original, 'Original staged packaging metadata differs')
        adjusted = original.replace(b'<version>15.0.0</version>', b'<version>$version$</version>')
        path.write_bytes(adjusted)
        adaptations.append(dict(path=name, originalSha256=hashlib.sha256(original).hexdigest(), adjustedSha256=hashlib.sha256(adjusted).hexdigest()))
    for name in ['Microsoft.TestPlatform.CLI.csproj', 'Microsoft.TestPlatform.Build.csproj']:
        path = stage / name
        original = path.read_bytes()
        needle = b'<NuspecProperties>version=$(Version)</NuspecProperties>'
        require(original == (nuspec / name).read_bytes() and needle in original, 'Original staged package project differs')
        adjusted = original.replace(needle, b'<NuspecProperties>version=$(Version);BranchName=$(BranchName);CommitId=$(CommitId)</NuspecProperties>')
        path.write_bytes(adjusted)
        adaptations.append(dict(path=name, originalSha256=hashlib.sha256(original).hexdigest(), adjustedSha256=hashlib.sha256(adjusted).hexdigest()))
    write(args.output / 'original-staged-packaging-adaptations.json', dict(sourceCommit=COMMIT, files=adaptations, csharpSourcesRetargeted=False, originalGitSourceChanged=False, publisherVersionRelabeled=False, qualificationAllowed=False))
    feed = args.output / 'source-built-feed'; feed.mkdir()
    for name in ['Microsoft.TestPlatform.CLI', 'Microsoft.TestPlatform.Build']:
        run(name + '-pack', stage / (name + '.csproj'), 'Restore;Pack', ['/p:Version=' + VERSION,
            '/p:BranchName=HEAD', '/p:CommitId=' + COMMIT, '/p:PackageOutputPath=' + str(feed)])
    packages, managed_count, source_count = [], 0, 0
    imported_members = {}
    for package in sorted(feed.glob('*.nupkg')):
        with zipfile.ZipFile(package) as archive:
            for member in archive.namelist():
                if member.endswith('/'): continue
                raw = archive.read(member)
                require(raw[:4] != b'\x7fELF', 'A managed source VSTest package contains native ELF payload')
                if member.lower().endswith(('.dll', '.exe')):
                    info = MANAGED.inspect(raw)
                    require(info['cliFlags'] & 1 and not info['cliFlags'] & 16 and info['managedNativeHeaderBytes'] == 0,
                            'A VSTest managed package contains an unreviewed native/ReadyToRun member')
                    managed_count += 1
                    own = any(COMMIT in str(v) for v in info['attributes'].values())
                    source_count += own
                    if not own:
                        require(member not in imported_members, 'Duplicate imported SDK5 VSTest member')
                        imported_members[member] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        packages.append(dict(path=package.relative_to(args.output).as_posix(), **fingerprint(package)))
    require({p['path'] for p in packages} == {'source-built-feed/Microsoft.TestPlatform.CLI.' + VERSION + '.nupkg',
            'source-built-feed/Microsoft.TestPlatform.Build.' + VERSION + '.nupkg'}, 'Both original source package products are required')
    require(managed_count == 339 and source_count == 301, 'Complete original VSTest5 source and import matrix required')
    check_imported_members(imported_members)
    write(args.output / 'results.json', dict(schemaVersion=1, kind='legacy-musl-vstest-source-build', status='passed',
        sdkVersion=SDK, architecture=args.arch, sourceCommit=COMMIT, sourceGraph='TestPlatform_BuildFromSource.sln',
        version=VERSION, originalSourceBuildFramework='netcoreapp2.1', originalBuildTaskFramework='netstandard2.0', eventLogOriginalFramework='net451', eventLogOriginalFullProjectGraphSelected=True, commands=commands, packages=packages,
        xlfResourceReceipt=fingerprint(args.output / 'xlf-resource-generation.json'), originalXlfFiles=234,
        managedPackageMembers=managed_count, sourceCommitAttributedMembers=source_count,
        importedDependenciesRequireSeparateSourceAttribution=True, compiledResourceAssembliesImported=False,
        originalSourceBuildCoreHostScope=True, fullMonoNetFrameworkTestHostProvided=False,
        closedCoverageInputImported=False, originalShellUnconditionalClosedCoverageCopyNotUsed=True,
        extensionResourcePlacement=extension_resources, vendorVersionRelabeled=False, readyToRunDisabled=False,
        qualificationAllowed=False, sourceAdmissionAllowed=False))
    print(json.dumps(dict(status='passed', version=VERSION, managedPackageMembers=managed_count, qualificationAllowed=False)))


if __name__ == '__main__': main()
