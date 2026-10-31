#!/usr/bin/env python3
"""Preserve byte-proven published packages before retrying the Core 3.0 graph.

The original graph requires new feed identities on every component invocation.
Feed nupkgs must match declared outputs or narrowly proven upstream producers.
Native/object/compiler caches and independent producer files remain unchanged.
The explicit root text-only SDK shim is packed directly into the feed; moving
that feed entry preserves its only archive while its pinned text sources stay.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import runpy
import subprocess
import xml.etree.ElementTree as ET
import zipfile


COMMIT = '40de72d1087a1d05dfd39c87f888a0611ec6c60f'
STANDARD_COMMIT = 'a5b5f2e1e369972c8ff1e2183979fab6099f52ef'
ARCADE_COMMIT = 'ce459ae07c3d7a1e68251268855e0bc7b3d97f75'


class UnprovenPackagesError(ValueError):
    def __init__(self, packages):
        self.packages = packages
        super().__init__('No byte-proven selected-component outputs for published feed packages: ' +
                         ', '.join(Path(row['path']).name for row in packages))


def standard_transport_output(source, component_root, component, adapter, values, helper):
    """Prove the pinned nonshipping transport producer omitted by its adapter."""
    if adapter != 'repos/standard.proj':
        return None
    if component['repository'] != 'https://github.com/dotnet/standard' or component['commit'] != STANDARD_COMMIT:
        raise ValueError('The Standard transport contract requires its exact selected source pin')
    declared = component_root / 'artifacts/packages/Release/Shipping'
    if Path(values['PackagesOutput']) != declared:
        raise ValueError('The pinned Standard adapter shipping-output contract changed')
    proofs, documents = [], {}
    for relative in ['src/packages.builds', 'src/netstandard/pkg/Microsoft.Private.Standard.pkgproj']:
        path = helper['ordinary_file'](component_root / relative)
        original = helper['git'](source, '--git-dir=' + str(source / '.git/modules/src/standard.git'),
                                 'show', STANDARD_COMMIT + ':' + relative)
        if path.read_bytes() != original:
            raise ValueError('The pinned Standard transport producer source changed: ' + relative)
        documents[relative] = ET.fromstring(original)
        proofs.append(dict({'path': str(path)}, **helper['fingerprint'](path)))
    ns = {'m': 'http://schemas.microsoft.com/developer/msbuild/2003'}
    traversal = documents['src/packages.builds']
    paths = [item.get('Include') for item in traversal.findall('m:ItemGroup/m:Project', ns)]
    transport = documents['src/netstandard/pkg/Microsoft.Private.Standard.pkgproj']
    shipping = transport.find('m:PropertyGroup/m:IsShipping', ns)
    references = [item.get('Include') for item in transport.findall('m:ItemGroup/m:ProjectReference', ns)]
    if ('netstandard\\pkg\\Microsoft.Private.Standard.pkgproj' not in paths or shipping is None or
            shipping.text != 'false' or '..\\ref\\netstandard.csproj' not in references):
        raise ValueError('The pinned Standard transport project/packaging contract differs')
    packaging_relative = 'src/Microsoft.DotNet.Build.Tasks.Packaging/src/build/Packaging.targets'
    packaging = helper['ordinary_file'](source / ('bin/src/arcade.' + ARCADE_COMMIT) / packaging_relative)
    original = helper['git'](source, '--git-dir=' + str(source / '.git/modules/src/arcade.git'),
                             'show', ARCADE_COMMIT + ':' + packaging_relative)
    if packaging.read_bytes() != original:
        raise ValueError('The pinned Arcade symbol-packaging producer source changed')
    parsed = ET.fromstring(original)
    symbol = next((item for item in parsed.iter() if item.tag.rsplit('}', 1)[-1] == 'SymbolPackageOutputPath'), None)
    pack = [item for item in parsed.iter() if item.get('SymbolPackageOutputDirectory') == '$(SymbolPackageOutputPath)']
    if (symbol is None or symbol.text != "$([MSBuild]::NormalizeDirectory('$(PackageOutputPath)', 'symbols'))" or
            symbol.get('Condition') != "'$(SymbolPackageOutputPath)' == ''" or not pack):
        raise ValueError('The pinned Arcade symbol-output contract differs')
    symbol_proof = dict({'path': str(packaging), 'sourceCommit': ARCADE_COMMIT}, **helper['fingerprint'](packaging))
    return {'directory': str(component_root / 'artifacts/packages/Release/NonShipping'),
            'allowedPackageIds': ['Microsoft.Private.Standard'], 'sourceCommit': STANDARD_COMMIT,
            'producerSources': proofs,
            'symbolOutputs': [
                {'directory': str(component_root / 'artifacts/packages/Release/NonShipping/symbols'),
                 'allowedPackageIds': ['Microsoft.Private.Standard'], 'symbolsOnly': True,
                 'sourceCommit': STANDARD_COMMIT, 'producerSources': proofs, 'symbolPackagerSource': symbol_proof},
                {'directory': str(declared / 'symbols'), 'allowedPackageIds': ['NETStandard.Library'], 'symbolsOnly': True,
                 'sourceCommit': STANDARD_COMMIT, 'declaredShippingOutput': str(declared), 'symbolPackagerSource': symbol_proof}],
            'scope': 'The original packages.builds includes this reference-project transport pkgproj with IsShipping=false. Only its exact package identity, selected repository commit and byte-equal local output may attest a published feed copy; no PSB identity is substituted.'}


def package_plan(feeds, producers, destination):
    """Require complete producer proof before a single feed file is moved."""
    plan, missing = [], []
    for path, info, package_identity in feeds:
        matches = [item for item in producers[path.name]
                   if item['fingerprint'] == info and item['packageIdentity'] == package_identity]
        if not matches:
            missing.append({'path': str(path), 'fingerprint': info, 'packageIdentity': package_identity,
                            'availableProducerCandidates': producers[path.name]})
            continue
        target = destination / path.name
        if target.exists() or target.is_symlink() or path.stat().st_dev != destination.stat().st_dev:
            raise ValueError('A retry quarantine target exists or is on a different filesystem')
        plan.append({'original': str(path), 'quarantine': str(target), 'fingerprint': info,
                     'packageIdentity': package_identity, 'matchingProducerOutputs': matches})
    if missing:
        raise UnprovenPackagesError(missing)
    return plan


def move_packages(plan, ordinary, fingerprint, moved):
    for row in plan:
        original, target = Path(row['original']), Path(row['quarantine'])
        if fingerprint(ordinary(original)) != row['fingerprint'] or target.exists() or target.is_symlink():
            raise ValueError('A published package changed after complete retry preflight')
        os.rename(str(original), str(target))
        if fingerprint(ordinary(target)) != row['fingerprint']:
            raise ValueError('A preserved retry package differs after its move')
        moved.append({'original': str(original), 'preserved': str(target), 'fingerprint': row['fingerprint']})


def nuspec(path):
    with zipfile.ZipFile(str(path)) as archive:
        names = [name for name in archive.namelist() if '/' not in name and name.endswith('.nuspec')]
        if len(names) != 1:
            raise ValueError('A producer package must have one root nuspec: ' + str(path))
        root = ET.fromstring(archive.read(names[0]))
    metadata = next((item for item in root if item.tag.rsplit('}', 1)[-1] == 'metadata'), None)
    if metadata is None:
        raise ValueError('Package metadata is absent')
    fields = {item.tag.rsplit('}', 1)[-1]: item for item in metadata}
    if 'id' not in fields or 'version' not in fields:
        raise ValueError('Package identity is absent')
    repository = fields.get('repository')
    return {'id': fields['id'].text, 'version': fields['version'].text,
            'repositoryCommit': repository.get('commit') if repository is not None else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--inputs-dir', type=Path, required=True)
    parser.add_argument('--reports-dir', type=Path, required=True)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--plan-only', action='store_true')
    args = parser.parse_args()
    helpers = Path(__file__).resolve().parent
    bootstrap = runpy.run_path(str(helpers / 'prepare-core30-bootstrap.py'))
    inputs_helper = runpy.run_path(str(helpers / 'core30-inputs.py'))
    directory, ordinary, fingerprint = bootstrap['directory'], bootstrap['ordinary_file'], bootstrap['fingerprint']
    identity = inputs_helper['verify'](args.source_dir, args.profile)
    source, inputs, reports = directory(args.source_dir), directory(args.inputs_dir), directory(args.reports_dir)
    if identity['sourceCommit'] != COMMIT or source in reports.parents or source in inputs.parents:
        raise ValueError('The pinned source, external private inputs and reports must be separate')
    report_path = reports / 'core30-retry-inputs.json'
    if report_path.exists() or report_path.is_symlink():
        raise ValueError('Use a new retry report directory')
    feed = directory(source / 'bin/obj/arm64/Release/blob-feed/packages')
    feeds = []
    for path in sorted(feed.iterdir()):
        if path.is_symlink() or not path.is_file() or path.suffix != '.nupkg':
            raise ValueError('Unexpected source-built feed entry: ' + str(path))
        ordinary(path)
        feeds.append((path, fingerprint(path), nuspec(path)))
    record = {'schemaVersion': 1, 'status': 'running', 'sourceCommit': COMMIT,
              'startedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'sourceDirectory': str(source), 'feedDirectory': str(feed), 'planOnly': args.plan_only,
              'commands': [], 'componentOutputs': [], 'packages': [], 'moved': [],
              'scope': 'Retry input preparation only. Preserve the original new-package guard; accept byte-equal pinned-component outputs and two explicit pinned upstream FSharp producer contracts. The root text-only SDK shim is packed directly into the feed and is identified as such. No native cache or independent producer output is removed.'}
    try:
        if not feeds:
            record.update({'status': 'passed', 'emptyFeed': True})
            return 0
        owner_root = directory(inputs / 'retry-quarantine', create=True)
        owner = owner_root / 'owner.json'
        ownership = {'sourceDirectory': str(source), 'sourceCommit': COMMIT,
                     'owner': 'cbodotnet-core30-retry-inputs-v1'}
        bootstrap['identical_or_new'](owner, (json.dumps(ownership, indent=2, sort_keys=True) + '\n').encode())
        destination = owner_root / reports.parent.name
        if destination.exists() or destination.is_symlink():
            raise ValueError('Refusing a previous retry quarantine directory')
        destination.mkdir(mode=0o700)
        packages_directory = destination / 'feed-packages'
        packages_directory.mkdir(mode=0o700)
        components = [(Path(item['directory']), item) for item in identity['exports']]
        wanted = {path.name for path, _, _ in feeds}
        producers = {name: [] for name in wanted}
        projects = bootstrap['git'](source, 'ls-tree', '-r', '--name-only', COMMIT, '--', 'repos').decode().splitlines()
        probes = reports / 'producer-evaluations'
        probes.mkdir()
        for relative in projects:
            if not relative.endswith('.proj'):
                continue
            name = Path(relative).stem
            probe = ET.Element('Project')
            ET.SubElement(probe, 'Import', {'Project': str(ordinary(source / relative))})
            target = ET.SubElement(probe, 'Target', {'Name': 'InspectPackageOutputs'})
            fields = ['ProjectDirectory', 'PackagesOutput', 'ShippingPackagesOutput', 'NonShippingPackagesOutput']
            files = {}
            for field in fields:
                output = probes / (name + '-' + field + '.txt')
                files[field] = output
                ET.SubElement(target, 'WriteLinesToFile', {'File': str(output), 'Lines': '$(' + field + ')',
                              'Overwrite': 'true', 'Encoding': 'UTF-8'})
            project = probes / (name + '.proj')
            ET.ElementTree(probe).write(str(project), encoding='utf-8', xml_declaration=True)
            command = [str(source / '.dotnet/dotnet'), str(source / '.dotnet/sdk/3.0.100/MSBuild.dll'), str(project),
                       '/t:InspectPackageOutputs', '/p:RepositoryName=' + name, '/p:Configuration=Release',
                       '/p:Platform=arm64', '/p:TargetOS=Linux', '/p:TargetRid=linux-arm64', '/p:PortableBuild=true',
                       '/p:NativeArm64Host=true', '/p:SDK_VERSION=3.0.100', '/p:ArchiveDownloadedPackages=false',
                       '/m:1', '/nr:false', '/v:minimal']
            bootstrap['run'](command, source, os.environ.copy(), probes / (name + '.log'), record['commands'])
            values = {field: ordinary(path).read_text(encoding='utf-8-sig').strip() for field, path in files.items()}
            output_values = [item.strip() for field in fields[1:] for item in values[field].split(';') if item.strip()]
            if not output_values:
                continue
            project_directory = Path(values['ProjectDirectory']).resolve()
            matches = [(root, item) for root, item in components if project_directory == root or root in project_directory.parents]
            if not matches:
                # Historical aggregate/obsolete adapters have no selected
                # manifest component. They cannot attest any feed package.
                record['componentOutputs'].append({'adapter': relative, 'directory': str(project_directory),
                                                   'ignored': 'No matching pinned source export'})
                continue
            if len(matches) != 1:
                raise ValueError('A package producer directory is not one verified source export: ' + name)
            component_root, component = matches[0]
            output_candidates = [(value, None) for value in output_values]
            extra = standard_transport_output(source, component_root, component, relative, values, bootstrap)
            if extra is not None:
                output_candidates.append((extra['directory'], extra))
                output_candidates.extend((item['directory'], item) for item in extra['symbolOutputs'])
            seen = set()
            for value, producer_contract in output_candidates:
                output = Path(value)
                if not output.is_absolute() or not (output == component_root or component_root in output.parents):
                    raise ValueError('A declared package output escapes its pinned component: ' + value)
                if not output.exists():
                    continue
                output = directory(output)
                if output in seen:
                    continue
                seen.add(output)
                record['componentOutputs'].append({'adapter': relative, 'directory': str(output),
                                                   'componentDirectory': str(component_root), 'componentCommit': component['commit'],
                                                   'additionalProducerContract': producer_contract})
                for package in sorted(output.glob('*.nupkg')):
                    if package.name not in wanted:
                        continue
                    if producer_contract is not None and producer_contract.get('symbolsOnly') and not package.name.endswith('.symbols.nupkg'):
                        continue
                    ordinary(package)
                    info = fingerprint(package)
                    package_identity = nuspec(package)
                    if producer_contract is not None and package_identity['id'] not in producer_contract['allowedPackageIds']:
                        continue
                    if package_identity['repositoryCommit'] and package_identity['repositoryCommit'] != component['commit']:
                        raise ValueError('A producer package repository commit differs from its pinned source: ' + str(package))
                    producers[package.name].append({'path': str(package), 'fingerprint': info,
                                                   'componentDirectory': str(component_root), 'componentCommit': component['commit'],
                                                   'adapter': relative, 'packageIdentity': package_identity,
                                                   'additionalProducerContract': producer_contract})
        # These exact upstream paths are outside the adapter's ordinary output
        # inventory. Each separate prover binds its source/packing contract and
        # full payload before it can attest one named package. This does not add
        # a general output-directory exception or waive symbol-package proof.
        contracts = {
            'FSharp.NET.Sdk.1.0.4-bundled-0100.nupkg': ('core30-fsharp-sdk-proof.py', 'repos/netcorecli-fsc.proj'),
            'Microsoft.FSharp.Compiler.10.6.0.symbols.nupkg': ('core30-fsharp-symbol-proof.py', 'repos/fsharp.proj')}
        record['additionalProducerProofs'] = []
        record['additionalProducerProofFailures'] = []
        for package, info, package_identity in feeds:
            if package.name not in contracts:
                continue
            module_name, adapter = contracts[package.name]
            try:
                module = ordinary(helpers / module_name)
                evidence = runpy.run_path(str(module))['prove'](source, package)
                producer = ordinary(Path(evidence['producerPath']))
                producer_identity = nuspec(producer)
                if (evidence.get('status') != 'passed' or evidence['packageIdentity'] != package_identity or
                        producer_identity != package_identity or fingerprint(producer) != info or fingerprint(ordinary(package)) != info):
                    raise ValueError('The explicit producer contract does not match the original feed snapshot')
                record['additionalProducerProofs'].append({'package': str(package), 'helper': dict({'path': str(module)}, **fingerprint(module)),
                                                           'evidence': evidence})
                producers[package.name].append({'path': str(producer), 'fingerprint': info, 'packageIdentity': producer_identity,
                                               'componentDirectory': evidence.get('componentDirectory', str(source)),
                                               'componentCommit': evidence.get('componentCommit', COMMIT), 'adapter': adapter,
                                               'additionalProducerContract': evidence})
            except (OSError, ValueError, KeyError, ET.ParseError, zipfile.BadZipFile) as error:
                # Keep the complete missing-producer audit rather than stop at
                # the first rejected special contract. No movement can happen.
                record['additionalProducerProofFailures'].append({'package': str(package), 'error': str(error)})
        record['packages'] = package_plan(feeds, producers, packages_directory)
        bootstrap['write_json'](reports / 'core30-retry-plan.json', record)
        if not args.plan_only:
            move_packages(record['packages'], ordinary, fingerprint, record['moved'])
        record.update({'status': 'passed', 'publishedPackagesProven': len(record['packages']),
                       'publishedPackagesQuarantined': len(record['moved']), 'recoveryDirectory': str(destination)})
        return 0
    except Exception as error:
        record.update({'status': 'failed', 'error': str(error)})
        if isinstance(error, UnprovenPackagesError):
            record['unprovenPackages'] = error.packages
            record['unprovenPackageCount'] = len(error.packages)
        raise
    finally:
        record['finishedAtUtc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        bootstrap['write_json'](report_path, record)
        print(json.dumps({'status': record['status'], 'report': str(report_path),
                          'packagesProven': len(record['packages']), 'packagesMoved': len(record['moved'])}))


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, ET.ParseError, zipfile.BadZipFile) as error:
        raise SystemExit('error: ' + str(error))
