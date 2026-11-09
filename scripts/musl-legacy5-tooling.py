#!/usr/bin/env python3
"""Build SDK5 products before the original redist layout, without admission.

The derived filter records every original solution project. Packaging is a
separate original-project invocation so Web/Worker/Publish outputs are present.
NuGet writes the local source-package cache metadata through a real restore.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PureWindowsPath
import platform
import re
import stat
import subprocess
import xml.etree.ElementTree as ET
import zipfile

from musl_legacy5_nuget_graph import verify_original_raw_tree

ROOT = Path(__file__).resolve().parents[1]
SDK = '5.0.214'
COMMIT = '3fdf76c35026e311b7edc245d4b3d9e812fe532e'
BOOTSTRAP = '5.0.401'
PATCH = 'patches/net5-musl/0005-use-upstream-source-build-windowsdesktop-import-guard.patch'
PATCH_SHA = '5be185f50dbf6a7018989e62d4c02afed9341d7ccdab642da76236fc1224e6c1'
NUGET = {'microsoft.build.nugetsdkresolver', 'nuget.build.tasks', 'nuget.build.tasks.console', 'nuget.build.tasks.pack',
    'nuget.commandline.xplat', 'nuget.commands', 'nuget.common', 'nuget.configuration', 'nuget.credentials',
    'nuget.dependencyresolver.core', 'nuget.frameworks', 'nuget.librarymodel', 'nuget.packagemanagement',
    'nuget.packaging', 'nuget.packaging.core', 'nuget.projectmodel', 'nuget.protocol', 'nuget.resolver', 'nuget.versioning'}
VERSIONS = {**{name: '5.9.1-rc.8' for name in NUGET},
    'microsoft.testplatform.build': '16.9.4-dev', 'microsoft.testplatform.cli': '16.9.4-dev',
    'microsoft.codeanalysis.visualbasic.codestyle': '3.8.0-5.20519.18',
    'microsoft.fsharp.compiler': '11.3.2-beta.21102.9', 'microsoft.net.compilers.toolset': '3.9.0-6.21273.1'}


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def ordinary(path):
    require(path.is_absolute() and path != Path('/') and not any(p.is_symlink() for p in (path, *path.parents)),
            'Ordinary absolute SDK5 source/bootstrap/feed/report path required')


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, indent=2); stream.write('\n')


def git(source, *args):
    return subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), '-C', str(source), *args])


def product_filter(source, destination):
    """Keep original solution dependencies and all non-test product projects."""
    require(not destination.exists(), 'A fresh external SDK5 product filter directory required')
    require(source not in destination.parents, 'Derived SDK5 filter must remain outside its original Git source')
    solution = git(source, 'show', COMMIT + ':sdk.sln')
    require((source / 'sdk.sln').read_bytes() == solution, 'Original SDK5 solution bytes differ')
    destination.mkdir(); included, projects = [], []
    for line in solution.decode('utf-8-sig').splitlines():
        match = re.fullmatch(r'Project\([^)]*\) = "[^"]+", "([^"]+\.csproj)", "[^"]+"', line)
        if not match: continue
        name = match.group(1); relative = PureWindowsPath(name).as_posix()
        require(not relative.startswith('/') and '..' not in relative.split('/') and ':' not in relative,
                'Original SDK5 solution project path escaped source')
        raw = git(source, 'show', COMMIT + ':' + relative)
        require((source / relative).read_bytes() == raw and name not in {r['path'] for r in projects},
                'Unique exact original SDK5 project bytes required')
        path = destination / 'original-projects' / relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        test = '\\Tests\\' in name or '.UnitTests\\' in name
        if not test: included.append(name)
        projects.append(dict(path=name, gitPath=relative, gitBlob=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
                             included=not test, sha256=hashlib.sha256(raw).hexdigest()))
    require(len(projects) == 56 and len(included) == 25, 'The complete original SDK5 25-product/31-test solution inventory required')
    raw = (json.dumps(dict(solution=dict(path=str(source / 'sdk.sln'), projects=included)), indent=2) + '\n').encode()
    (destination / 'source-build.slnf').write_bytes(raw); (destination / 'sdk.sln').write_bytes(solution)
    origin = dict(kind='downstream-sdk5-external-derived-product-solution-filter', sourceCommit=COMMIT,
        sourceSolution=str(source / 'sdk.sln'), solutionSha256=hashlib.sha256(solution).hexdigest(),
        filterSha256=hashlib.sha256(raw).hexdigest(), projects=projects, includedCount=25, excludedOriginalTestProjects=31,
        selectionRule=dict(excludeOnlyCaseSensitivePathSubstrings=['\\Tests\\', '.UnitTests\\']),
        filterOutsideGitRoot=True, checkedInSourceBuildFilterClaimed=False, original68SmokeExclusions=[],
        qualificationAllowed=False, sourceAdmissionAllowed=False)
    write(destination / 'origin.json', origin)
    return destination / 'source-build.slnf'


def appinsights_contract():
    # Keep the original24 mode independent of the additive App source contract.
    import musl_legacy5_appinsights_consumption as M
    return M


def package_metadata(archive):
    # The honest derived F# input retains an original nuspec under provenance.
    # Only the single root nuspec supplies the actual package identity.
    names = archive.namelist(); specs = [n for n in names if '/' not in n and n.endswith('.nuspec')]
    require(len(names) == len(set(names)) and len(specs) == 1, 'Unique SDK5 source feed ZIP/nuspec members required')
    raw = archive.read(specs[0]); require(len(raw) <= 1024**2 and b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(),
                                        'Bounded plain original source package metadata required')
    node = ET.fromstring(raw).find('{*}metadata')
    require(node is not None, 'SDK5 source package metadata required')
    return node.findtext('{*}id'), node.findtext('{*}version')


def appinsights_package_input(feed, package):
    """Bind actual NPK bytes, never infer a strong source supplier proof."""
    M = appinsights_contract(); feed, package = Path(feed), Path(package)
    ordinary(feed); ordinary(package)
    require(feed.is_dir() and package.parent == feed and package.name == M.PACKAGE
            and package == feed / M.PACKAGE and package.is_file()
            and stat.S_ISREG(package.lstat().st_mode) and not package.lstat().st_mode & 0o7000,
            'Actual ordinary canonical feed/' + M.PACKAGE + ' package required')
    raw = package.read_bytes()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        identity, version = package_metadata(archive)
    require(identity and identity.lower() == M.ID.lower() and version == M.VERSION,
            'Exact local SDK5 App package identity/version required')
    return dict(path=str(package), file=M.PACKAGE, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                sha512=hashlib.sha512(raw).hexdigest()), raw


def feed_packages(feed, appinsights_package=None):
    M = appinsights_contract() if appinsights_package is not None else None
    versions = M.tooling_packages() if M else VERSIONS
    if M:
        require({name: version for name, version in versions.items() if name != M.ID.lower()} == VERSIONS,
                'Committed SDK5 App consumption and original24 package matrices differ')
        provided, app_raw = appinsights_package_input(feed, appinsights_package)
        paths = sorted(path for path in feed.iterdir() if path.suffix.lower() == '.nupkg')
    else:
        paths = sorted(feed.glob('*.nupkg'))
    records = []
    for path in paths:
        ordinary(path)
        if M:
            require(path.is_file() and stat.S_ISREG(path.lstat().st_mode) and not path.lstat().st_mode & 0o7000,
                    'Ordinary SDK5 explicit25 feed package file required')
        supplied_app = M is not None and path == Path(provided['path']) and path.name == M.PACKAGE
        with zipfile.ZipFile(io.BytesIO(app_raw) if supplied_app else path) as archive:
            identity, version = package_metadata(archive)
            require(identity and versions.get(identity.lower()) == version, 'An SDK5 source feed package/version is outside the original product matrix')
        actual = {key: provided[key] for key in ('bytes', 'sha256', 'sha512')} if supplied_app else fingerprint(path)
        row = dict(id=identity, version=version, file=path.name, **actual,
            role='matching-original-sdk-derived-compiler-input' if identity.lower() not in NUGET | {'microsoft.testplatform.build', 'microsoft.testplatform.cli'}
                 else 'local-source-component-product-requiring-independent-compiler-proof', compilerLocallySourceBuiltClaimed=False)
        if M and identity.lower() == M.ID.lower():
            require(supplied_app, 'SDK5 App feed package must be the exact provided canonical package')
            row.update(role='local-App-product-requiring-external-strong-supplier-proof',
                       externalStrongSupplierProofRequired=True, externalStrongSupplierProofValidated=False)
        records.append(row)
    count = 25 if M else 24
    require(len(records) == count and {r['id'].lower() for r in records} == versions.keys(),
            'Exactly' + str(count) + ' unique SDK5 source/derived compiler package inputs required')
    if M:
        require(appinsights_package_input(feed, appinsights_package)[0] == provided,
                'Provided SDK5 App package changed during feed inspection')
    return records


def cache_prime_project(packages):
    project = ET.Element('Project', Sdk='Microsoft.NET.Sdk')
    properties = ET.SubElement(project, 'PropertyGroup'); ET.SubElement(properties, 'TargetFramework').text = 'net5.0'
    ET.SubElement(properties, 'DisableImplicitFrameworkReferences').text = 'true'; items = ET.SubElement(project, 'ItemGroup')
    for row in packages: ET.SubElement(items, 'PackageDownload', Include=row['id'], Version='[' + row['version'] + ']')
    return ET.tostring(project, encoding='utf-8', xml_declaration=True)


def product_commands(dotnet, source, filter, output, arch, feed, translation_data, appinsights_package=None):
    cpu = 'arm64' if arch == 'aarch64' else 'x64'
    props = ['/p:Configuration=Release', '/p:ArcadeBuildFromSource=false', '/p:DotNetBuildFromSource=true',
        '/p:Architecture=' + cpu, '/p:OSName=linux-musl', '/p:Rid=linux-musl-' + cpu, '/p:PortableBuild=true', '/p:CrossBuild=false',
        '/p:ContinuousIntegrationBuild=true', '/p:UseSharedCompilation=false', '/p:EmitCompilerGeneratedFiles=true',
        '/p:RestoreAdditionalProjectSources=' + str(feed), '/p:MicrosoftTestPlatformCLIPackageVersion=16.9.4-dev',
        '/p:MicrosoftTestPlatformBuildPackageVersion=16.9.4-dev', '/p:CommunityMuslNuGetTranslationRoot=' + str(translation_data / 'resources'), '/m:2']
    if appinsights_package is not None:
        appinsights_package_input(feed, appinsights_package)
        props.append(appinsights_contract().PROPERTY)
    commands = [
        ('original-product-restore', [dotnet, 'restore', filter, *props, '/bl:' + str(output / 'restore.binlog')]),
        ('original-product-build', [source / 'build.sh', '--configuration', 'Release', '--rebuild', '--projects', filter,
            *props, '/bl:' + str(output / 'sdk.binlog')]),
        ('original-redist-build-pack', [source / 'build.sh', '--configuration', 'Release', '--rebuild', '--pack', '--projects',
            source / 'src/Layout/redist/redist.csproj', *props, '/bl:' + str(output / 'redist.binlog')])]
    if appinsights_package is not None:
        for _, command in commands: appinsights_contract().controlled_version_property(list(map(str, command)))
    return commands


def finalize_tooling_report(report, feed, appinsights_package=None, expected_app=None):
    if appinsights_package is None:
        require(expected_app is None, 'Legacy24 mode cannot bind an App input')
        return report
    provided, _ = appinsights_package_input(feed, appinsights_package)
    require(provided == expected_app, 'Actual provided SDK5 App package bytes changed during tooling')
    M = appinsights_contract(); M.validate_tooling(report, provided)
    return dict(report, sourceFeedMode='explicit25-with-local-App-input', appinsightsPackageInput=provided,
        externalStrongAppSupplierProofRequired=True, externalStrongAppSupplierProofValidated=False)


def prepare_source(source, output):
    write(output / 'original-raw-tree.json', verify_original_raw_tree(source, COMMIT))
    path = source / 'eng/restore-toolset.sh'; original = path.read_bytes()
    marker = b'  # The following frameworks and tools are used only for testing.\n'
    require(original.count(marker) == 1, 'Original SDK5 test-only bootstrap marker changed')
    replacement = (b'  # Product-only builds do not execute these historical test frameworks.\n'
                   b'  if [[ ${CBODOTNET_SKIP_LEGACY_TEST_RUNTIME_INSTALLS:-} == true ]]; then\n'
                   b'    return\n  fi\n\n' + marker)
    path.write_bytes(original.replace(marker, replacement, 1))
    write(output / 'test-runtime-hook.json', dict(path='eng/restore-toolset.sh', sourceCommit=COMMIT,
        originalSha256=hashlib.sha256(original).hexdigest(), adjustedSha256=fingerprint(path)['sha256'],
        environment='CBODOTNET_SKIP_LEGACY_TEST_RUNTIME_INSTALLS=true', original68SmokeExcluded=False))
    patch = ROOT / PATCH; require(fingerprint(patch)['sha256'] == PATCH_SHA, 'Pinned original SDK5 WindowsDesktop import guard patch differs')
    for options in [['--check'], []]:
        subprocess.run(['git', '-c', 'safe.directory=' + str(source), '-C', str(source), 'apply', *options, patch], check=True)
    spec = importlib.util.spec_from_file_location('sdk5_literal_translation_hook', ROOT / 'scripts/musl-legacy-tooling.py')
    legacy = importlib.util.module_from_spec(spec); spec.loader.exec_module(legacy)
    target = source / 'src/Layout/redist/targets/GenerateLayout.targets'; original = target.read_bytes()
    require(original.endswith(b'</Project>\n'), 'Original SDK5 redist layout terminator changed')
    target.write_bytes(original[:-len(b'</Project>\n')] + legacy.TRANSLATION_HOOK.encode() + b'</Project>\n')
    (output / 'source-changes.patch').write_bytes(git(source, 'diff', '--binary'))
    require((source / 'global.json').read_bytes() == git(source, 'show', COMMIT + ':global.json'), 'Original SDK5 global.json must remain unchanged')


def verify_cache(source, packages, feed):
    result = []
    for row in packages:
        folder = source / '.packages' / row['id'].lower() / row['version'].lower()
        package = folder / (row['id'].lower() + '.' + row['version'].lower() + '.nupkg')
        ordinary(package); ordinary(folder / '.nupkg.metadata')
        require(fingerprint(package) == {k: row[k] for k in ('bytes', 'sha256', 'sha512')}, 'Actual restored SDK5 source package bytes differ')
        metadata = json.loads((folder / '.nupkg.metadata').read_text())
        require(metadata['source'] == str(feed) and metadata['contentHash'] ==
                base64.b64encode(bytes.fromhex(row['sha512'])).decode(), 'Real NuGet local-source cache provenance required')
        require((folder / (package.name[:-6] + '.nupkg.sha512')).read_text().strip() == metadata['contentHash'],
                'Actual NuGet source-package checksum/cache metadata differs')
        result.append(dict(id=row['id'], version=row['version'], **fingerprint(package), metadata=metadata))
    return result


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', choices=[SDK], required=True); parser.add_argument('--arch', choices=['aarch64', 'x64'], required=True)
    for name in ['workspace', 'dotnet', 'feed', 'translation-data', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--appinsights-package', type=Path,
        help='Explicit canonical local App NPK; independent strong supplier proof remains mandatory outside this worker')
    return parser


def main():
    args = argument_parser().parse_args(); source = args.workspace / 'sdk'
    for path in [args.workspace, source, args.dotnet, args.feed, args.translation_data, args.output]: ordinary(path)
    require(platform.system() == 'Linux' and os.getuid() != 0 and platform.machine() == {'aarch64': 'aarch64', 'x64': 'x86_64'}[args.arch]
            and Path('/etc/alpine-release').read_text().strip() == '3.24.4', 'Matching native non-root Alpine3.24.4 required')
    require(not args.output.exists(), 'Fresh SDK5 tooling output required'); args.output.mkdir(parents=True)
    app_input = appinsights_package_input(args.feed, args.appinsights_package)[0] if args.appinsights_package is not None else None
    packages = feed_packages(args.feed, args.appinsights_package)
    data = json.loads((args.translation_data / 'origin.json').read_text())
    require(data['sdkVersion'] == SDK and data['sourceCommit'] == 'd525b0e670f3b6cbd5c73a35f04730a9f658c852'
            and data['architecture'] == args.arch and len(data['files']) == 286, 'Exact original SDK5 resource-only translation input required')
    for row in data['files']:
        require(row['path'].endswith('.resources.dll') and not row['path'].startswith('/') and '..' not in row['path'].split('/'),
                'Only ordinary SDK5 translation satellite paths supported')
        path = args.translation_data / 'resources' / row['path']; ordinary(path)
        require(fingerprint(path) == {k: row[k] for k in ('bytes', 'sha256', 'sha512')}, 'Original SDK5 translation data bytes differ')
    filter = product_filter(source, args.output / 'derived-product-solution')
    prepare_source(source, args.output)
    env = dict(os.environ, DOTNET_ROOT=str(args.dotnet.parent), DOTNET_INSTALL_DIR=str(args.dotnet.parent), DOTNET_MULTILEVEL_LOOKUP='0',
        DOTNET_PROCESSOR_COUNT='2', DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1', MSBUILDDISABLENODEREUSE='1',
        NUGET_PACKAGES=str(source / '.packages'), CBODOTNET_SKIP_LEGACY_TEST_RUNTIME_INSTALLS='true')
    commands = []
    def run(name, command):
        log = args.output / (name + '.log'); started = datetime.now(timezone.utc).isoformat()
        with log.open('x') as stream:
            stream.write(json.dumps(list(map(str, command))) + '\n'); stream.flush()
            process = subprocess.run(command, cwd=source, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=1800)
        row = dict(name=name, command=list(map(str, command)), exitCode=process.returncode,
            startedAt=started, completedAt=datetime.now(timezone.utc).isoformat(), log=log.name, **fingerprint(log))
        commands.append(row); write(args.output / (name + '-command.json'), row)
        require(process.returncode == 0, 'An original SDK5 product command failed: ' + name)
        return log.read_text()
    selected = run('bootstrap-sdk-version', [args.dotnet, '--version'])
    require(selected.partition('\n')[2].strip() == BOOTSTRAP, 'The original SDK5 global.json must select bootstrap5.0.401')
    prime = args.output / 'cache-prime'; prime.mkdir()
    (prime / 'SourcePackageDownloads.csproj').write_bytes(cache_prime_project(packages))
    config = ET.Element('configuration'); feeds = ET.SubElement(config, 'packageSources'); ET.SubElement(feeds, 'clear')
    ET.SubElement(feeds, 'add', key='exact-local-source-products', value=str(args.feed)); ET.SubElement(ET.SubElement(config, 'fallbackPackageFolders'), 'clear')
    (prime / 'NuGet.Config').write_bytes(ET.tostring(config, encoding='utf-8', xml_declaration=True))
    # Existing selected versions can silently win NuGet's cache lookup. Require
    # them absent before the real PackageDownload restore; do not fabricate metadata.
    require(all(not (source / '.packages' / r['id'].lower() / r['version'].lower()).exists() for r in packages),
            'SDK5 selected local source package versions must be absent before priming')
    run('source-package-cache-prime', [args.dotnet, 'restore', prime / 'SourcePackageDownloads.csproj', '--configfile', prime / 'NuGet.Config',
        '--packages', source / '.packages', '/p:UseSharedCompilation=false', '/m:2', '/bl:' + str(args.output / 'source-package-cache-prime.binlog')])
    cache = verify_cache(source, packages, args.feed); write(args.output / 'source-package-cache.json', dict(packages=packages, checks=cache, metadataFabricated=False))
    for name, command in product_commands(args.dotnet, source, filter, args.output, args.arch, args.feed,
                                          args.translation_data, args.appinsights_package):
        run(name, command)
    require(verify_cache(source, packages, args.feed) == cache, 'Actual own SDK5 input packages/provenance changed during product build')
    toolset = source / 'artifacts/packages/Release/NonShipping/dotnet-toolset-internal-5.0.214-ci.zip'
    with zipfile.ZipFile(toolset) as archive:
        names = archive.namelist(); require(len(names) == len(set(names)), 'Duplicate SDK5 toolset layout member')
        for sdk in ['Microsoft.NET.Sdk', 'Microsoft.NET.Sdk.Worker', 'Microsoft.NET.Sdk.Publish', 'Microsoft.NET.Sdk.Web', 'Microsoft.NET.Sdk.Web.ProjectSystem']:
            require('Sdks/' + sdk + '/Sdk/Sdk.props' in names and 'Sdks/' + sdk + '/Sdk/Sdk.targets' in names,
                    'An original SDK5 product SDK directory is absent after ordered redist packaging: ' + sdk)
    report = dict(schemaVersion=1, kind='legacy-musl-sdk5-source-tooling', status='passed', sdkVersion=SDK,
        architecture=args.arch, sourceCommit=COMMIT, bootstrapSdkVersion=BOOTSTRAP, commands=commands, packages=packages,
        derivedProductFilter=str(filter), originalProducts=25, originalTestProjectsExcludedFromProductBuild=31,
        original68SmokeExclusions=[], originalProductGraphCompletedBeforeRedistPackaging=True,
        originalRedistProjectExplicitSecondInvocation=True, originalSourceTfmsUnchanged=True, noManualLayoutFileCopies=True,
        toolset=dict(path=str(toolset), **fingerprint(toolset)), actualCompilerReplaysAndConsumptionRequireIndependentGate=True,
        importedTranslationsAreDataOnly=True, derivedCompilerPackagesLocallySourceBuiltClaimed=False,
        qualificationAllowed=False, sourceAdmissionAllowed=False)
    write(args.output / 'results.json', finalize_tooling_report(report, args.feed, args.appinsights_package, app_input))
    print(json.dumps(dict(status='passed', toolset=fingerprint(toolset), qualificationAllowed=False)))


if __name__ == '__main__': main()
