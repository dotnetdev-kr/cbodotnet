"""Verify SDK6's original Core VSTest packaging and original XLF targets.

This reads source archives and completed compiler evidence. It builds no code,
executes no imported assembly, and grants no distribution qualification.
"""
import collections
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from musl_source_archive import open_source_archive

ROOT = Path(__file__).resolve().parents[1]
COMMIT = 'cc7fb0593127e24f55ce016fb3ac85b5b2857fec'
TREE = '64a7abaa0abbf25f525e52f7e3086931c2b59743'
VERSION = '17.0.3-dev'
GENERATED = 'vstest-generated'
FP = ('bytes', 'sha256', 'sha512')
FILES = {'scripts/build.sh': {'bytes': 20793,
                      'sha256': '7ba25a814097acc9748117c08205279f106d8715cf224f1e8df815e0db1ae86f',
                      'gitBlob': 'a4eee644b17de1153843b78d1e383202c977c739'},
 'scripts/build.ps1': {'bytes': 62100,
                       'sha256': 'e533567734613fbe81e48dcabcadf1afc9af4c96e4889782b1af11bd5ae8bc09',
                       'gitBlob': 'fe587b33de876b1732299007ccd82a2e6cec6def'},
 'src/testhost/testhost.csproj': {'bytes': 3363,
                                  'sha256': 'f886da03ab3c4583c4ebe31f128cbddd0c8a693e618e7a4b545c37b6289c60c8',
                                  'gitBlob': 'a780e4e9b961604c19fcfd93b364c2ce118d68bb'},
 'src/testhost.x86/testhost.x86.csproj': {'bytes': 3091,
                                          'sha256': 'd4c1a2ecf3c92e392114d5b89ea4c8daa894192ee682cd2bda32e00cbfe32475',
                                          'gitBlob': '7eb5cd156b8c2f728a3ea205b4f04d88d7a596cf'},
 'src/package/package/package.csproj': {'bytes': 4082,
                                        'sha256': 'ae7d56be822053f7bcb8b9e35fad38eac95ea782a1100ad30bc2e0d18889338d',
                                        'gitBlob': 'fe9908116d7de772c2209c2b2b55ff2bb1e5a910'},
 'src/package/external/external.csproj': {'bytes': 5542,
                                          'sha256': 'ed028efad841bb6dd1b760c96dea7c42a6ea23b2cb69c1ebd8534de83d5ca4e5',
                                          'gitBlob': '3005367769ced579a8494125e8ef86aa2268bb3d'},
 'src/package/nuspec/TestPlatform.CLI.nuspec': {'bytes': 1452,
                                                'sha256': 'ec90f0ae0f8c1efbf11e347ce103054acd9b41a24c7ba04eb8162f8ecd3df1d8',
                                                'gitBlob': '0e72bf5885f8e1b9e284ca76d0a407c83ce00fc9'},
 'TestPlatform_BuildFromSource.sln': {'bytes': 31500,
                                      'sha256': 'd50da640a85407af3504c68bf5495b6931ceb9ade4cc6373be73fa458108ed1a',
                                      'gitBlob': '119f72a3373cd461decc79870190595eda12cd85'},
 'src/package/nuspec/TestPlatform.Build.nuspec': {'bytes': 1504,
                                                  'sha256': '1463c83dee6261ab5408474e11adc7093184b5478d3522f7867d20d70f08599c',
                                                  'gitBlob': '3808b2965fd5816ec7c8d5af4899b2e73f4afc0c'},
 'src/package/nuspec/Microsoft.TestPlatform.CLI.csproj': {'bytes': 733,
                                                          'sha256': '3a95660f9ca84c156a4267ca60480ca7b11103503aa153a321ebdad59991a54e',
                                                          'gitBlob': 'e68582679c0da8745693764b1a1c6fc2ad79f74b'},
 'src/package/nuspec/Microsoft.TestPlatform.Build.csproj': {'bytes': 735,
                                                            'sha256': '1aa182b2ffc0be67eea01f4e86f7704a0933d0069dbb55144cdb612ea3b1108b',
                                                            'gitBlob': 'e982426e4453a89f0ed5bf521e83245de3cad986'},
 'scripts/build/TestPlatform.Settings.targets': {'bytes': 5815,
                                                 'sha256': 'b369e835b0ac145e3761f1910cc934f598a4b657dda423349c8ad72f8015a9a5',
                                                 'gitBlob': '7a4fdcedd4117a82af26f19ca41c26d929581584'},
 'src/package/licenses/LICENSE_NET.txt': {'bytes': 9062,
                                          'sha256': 'eb6370966273e1dc5a801c093e68d5999b33858c28031f453ac4a6467d5380df',
                                          'gitBlob': '5b03e9dce1e59a2cbbd0f323ece4cfff1835881f'},
 'src/package/ThirdPartyNotices.txt': {'bytes': 3111,
                                       'sha256': 'e23128ca98e5c42cf4cfa47c08a1fd3d212036a3a1cb877b161ae5c975e3c9b6',
                                       'gitBlob': '4c85ae8285f5420a6778cc364fefa69d2d45adf4'}}


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


B = module('sdk6_vstest_source_binary_primitives', 'musl_legacy_admission.py')
XLF = module('sdk6_vstest_source_xlf', 'musl_legacy_xlf.py')
P = module('sdk6_vstest_source_archive', 'package-used-source.py')
require, portable = B.require, B.portable


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def read_json(path):
    require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)),
            'Ordinary retained SDK6 VSTest report required')
    return json.loads(path.read_text(encoding='utf-8'))


def adaptations(originals):
    """Only derived staging metadata changes; original source remains intact."""
    result = []
    for name, old in [('TestPlatform.CLI.nuspec', 'netcoreapp2.1'), ('TestPlatform.Build.nuspec', 'netstandard2.0')]:
        raw = originals['src/package/nuspec/' + name]
        require(old.encode() in raw and b'<version>15.0.0</version>' in raw, 'Original SDK6 staged nuspec changed')
        adjusted = raw.replace(old.encode(), b'net6.0').replace(b'<version>15.0.0</version>', b'<version>$version$</version>')
        result.append(dict(path=name, originalSha256=hashlib.sha256(raw).hexdigest(), adjustedSha256=hashlib.sha256(adjusted).hexdigest()))
    for name in ['Microsoft.TestPlatform.CLI.csproj', 'Microsoft.TestPlatform.Build.csproj']:
        raw = originals['src/package/nuspec/' + name]
        needle = b'<NuspecProperties>version=$(Version)</NuspecProperties>'
        require(needle in raw, 'Original SDK6 staged package properties changed')
        adjusted = raw.replace(needle, b'<NuspecProperties>version=$(Version);BranchName=$(BranchName);CommitId=$(CommitId)</NuspecProperties>')
        result.append(dict(path=name, originalSha256=hashlib.sha256(raw).hexdigest(), adjustedSha256=hashlib.sha256(adjusted).hexdigest()))
    return dict(sourceCommit=COMMIT, files=result, csharpSourcesRetargeted=False,
                originalGitSourceChanged=False, publisherVersionRelabeled=False, qualificationAllowed=False)


def regenerate(originals, observed, generated):
    """Recreate plain RESX bytes from the actual original XLF, without fallback."""
    with tempfile.TemporaryDirectory(prefix='cbodotnet-vstest6-xlf-') as temporary:
        root = Path(temporary)
        for name, raw in originals.items():
            if name.endswith(('.xlf', '.resx')):
                destination = root / portable(name); destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(raw)
        receipt = XLF.generate(root, root / 'receipt.json', COMMIT)
        require(len(receipt['rows']) == 234 and receipt == observed,
                'SDK6 original XLF targets and generation receipt differ')
        expected = {row['generated']: (root / row['generated']).read_bytes() for row in receipt['rows']}
        require(generated == expected, 'Complete exact original-target SDK6 generated RESX bytes required')
        return receipt


def worker(release, proof, originals, observed_resources):
    base = release / 'reports/build/vstest'; results = read_json(base / 'results.json')
    require(results['schemaVersion'] == 1 and results['kind'] == 'legacy-musl-vstest-source-build'
            and results['status'] == 'passed' and results['sdkVersion'] == '6.0.136'
            and results['architecture'] in ('aarch64', 'x64') and results['sourceCommit'] == COMMIT
            and results['sourceGraph'] == 'TestPlatform_BuildFromSource.sln'
            and results['version'] == VERSION and results['originalSourceBuildFramework'] == 'net6.0'
            and results['originalXlfFiles'] == 234 and results['managedPackageMembers'] == 310
            and results['sourceCommitAttributedMembers'] == 304
            and results['originalSourceBuildCoreHostScope'] is True
            and results['importedDependenciesRequireSeparateSourceAttribution'] is True
            and results['originalShellUnconditionalClosedCoverageCopyNotUsed'] is True
            and all(results[k] is False for k in ('fullMonoNetFrameworkTestHostProvided', 'closedCoverageInputImported',
                'compiledResourceAssembliesImported', 'vendorVersionRelabeled', 'readyToRunDisabled',
                'qualificationAllowed', 'sourceAdmissionAllowed')),
            'Exact original SDK6 Core VSTest source worker result required')
    require(results['xlfResourceReceipt'] == fingerprint((base / 'xlf-resource-generation.json').read_bytes())
            and read_json(base / 'xlf-resource-generation.json') == observed_resources
            and read_json(base / 'original-staged-packaging-adaptations.json') == adaptations(originals),
            'SDK6 original resource and staged packaging transformations differ')
    expected_packages = {p['file']: {k: p[k] for k in FP} for p in proof['packages']}
    require(len(results['packages']) == 2 and
            {p['path']: {k: p[k] for k in FP} for p in results['packages']} ==
            {'source-built-feed/' + name: value for name, value in expected_packages.items()},
            'Validated SDK6 VSTest packages differ from the actual source worker products')
    for name, expected in expected_packages.items():
        path = base / 'source-built-feed' / portable(name)
        require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents))
                and B.fingerprint(path) == expected, 'Actual SDK6 VSTest worker package bytes differ')
    mount = proof['sourceMountRoot']; arch = 'arm64' if results['architecture'] == 'aarch64' else 'x64'
    rid = 'linux-musl-' + arch
    common = ['/p:Configuration=Release', '/p:DotNetBuildFromSource=true', '/p:LocalizedBuild=true',
        '/p:UseSharedCompilation=false', '/p:UseAppHost=false', '/p:EmitCompilerGeneratedFiles=true',
        '/p:NETCoreSdkRuntimeIdentifier=' + rid, '/p:ToolsRID=' + rid,
        '/p:RepositoryCommit=' + COMMIT, '/p:SourceRevisionId=' + COMMIT,
        '/p:RestoreSources=' + '%3B'.join(['https://api.nuget.org/v3/index.json',
            'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public/nuget/v3/index.json',
            'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-eng/nuget/v3/index.json',
            'https://pkgs.dev.azure.com/dnceng/public/_packaging/test-tools/nuget/v3/index.json']), '/m:2', '/nologo']
    expected = [('original-solution-restore', '/TestPlatform_BuildFromSource.sln', 'Restore', []),
                ('original-solution-build', '/TestPlatform_BuildFromSource.sln', 'Build', [])]
    for project in ['package/package', 'vstest.console', 'datacollector', 'testhost', 'testhost.x86']:
        name = project.split('/')[-1]
        expected.append((name + '-publish', '/src/' + project + '/' + name + '.csproj', 'Publish',
                         ['/p:TargetFramework=net6.0', '/p:PublishDir=' + mount + '/artifacts/Release/net6.0/']))
    for name in ['Microsoft.TestPlatform.CLI', 'Microsoft.TestPlatform.Build']:
        expected.append((name + '-pack', '/artifacts/Release/' + name + '.csproj', 'Restore;Pack',
                         ['/p:Version=' + VERSION, '/p:BranchName=HEAD', '/p:CommitId=' + COMMIT]))
    commands = results['commands']; require(len(commands) == len(expected), 'All nine original SDK6 VSTest commands required')
    output = None; dotnet = None
    for row, (name, project, targets, extra) in zip(commands, expected):
        argv = row['command']; require(isinstance(argv, list) and len(argv) > 4, 'Actual original VSTest command required')
        if output is None:
            require(argv[-1].startswith('/bl:/') and argv[-1].endswith('/' + name + '.binlog'), 'Original VSTest binary log required')
            output = argv[-1][4:].rsplit('/', 1)[0]; dotnet = argv[0]
            require(dotnet.startswith('/') and dotnet.endswith('/dotnet'), 'Explicit VSTest bootstrap host required')
        if name.endswith('-pack'): extra = extra + ['/p:PackageOutputPath=' + output + '/source-built-feed']
        require(argv == [dotnet, 'msbuild', mount + project, *common, '/t:' + targets, *extra, '/bl:' + output + '/' + name + '.binlog']
                and row['name'] == name and row['exitCode'] == 0 and row['log'] == name + '.log',
                'An original SDK6 VSTest source command or framework was overridden')
        log = base / portable(row['log'])
        require(log.is_file() and not any(p.is_symlink() for p in (log, *log.parents))
                and fingerprint(log.read_bytes()) == {k: row[k] for k in FP}
                and json.loads(log.read_text(encoding='utf-8').splitlines()[0]) == argv,
                'SDK6 VSTest actual command log differs')
    require(fingerprint(base.joinpath('original-solution-build.binlog').read_bytes()) == {k: proof['binlog'][k] for k in FP},
            'Validated SDK6 VSTest replay does not consume the worker source build binlog')
    return results


def resources(release, proof, generated, receipt):
    """Bind each shipping satellite to its real compiler output's project."""
    by_project = collections.defaultdict(dict)
    for row in receipt['rows']:
        project = row['generated'].split('/Resources/', 1)[0]
        document = ET.fromstring(generated[row['generated']])
        values = {node.attrib['name']: node.find('value').text or '' for node in document.findall('data')}
        by_project[(project, row['culture'])][row['generated']] = values
    seen_sources, products, embedded = set(), 0, 0
    packages = {p['path']: p for p in proof['packages']}
    for package_path, package in packages.items():
        path = release / portable(package_path)
        require(B.fingerprint(path) == {k: package[k] for k in FP}, 'Original SDK6 VSTest package fingerprint differs')
        with zipfile.ZipFile(path) as archive:
            require(len(archive.namelist()) == len(set(archive.namelist())), 'Duplicate SDK6 VSTest package member')
            for row in proof['compiledOutputs']:
                if row['packagePath'] != package_path or not row['member'].endswith('.resources.dll'): continue
                raw = archive.read(portable(row['member'])); require(fingerprint(raw) == row['fingerprint'], 'Shipping VSTest satellite bytes differ')
                identity = B.resource_only_pe(raw); culture = identity['culture']
                require(culture in XLF.CULTURES and PurePosixPath(row['member']).parent.name == culture
                        and identity['assemblyName'] + '.dll' == PurePosixPath(row['member']).name,
                        'SDK6 VSTest satellite culture/identity differs')
                output = row['outputPath']; mount = proof['sourceMountRoot']
                require(output.startswith(mount + '/') and output.count('/obj/') == 1, 'Actual VSTest satellite compiler project path required')
                project = output[len(mount) + 1:].split('/obj/', 1)[0]
                expected = by_project.get((project, culture))
                require(expected and len(identity['resources']) == len(expected), 'Complete original-XLF resources for actual VSTest compiler project required')
                remaining = dict(expected)
                for resource in identity['resources']:
                    values = {key: value['value'] for key, value in B.resource_strings(resource['data']).items()}
                    matches = [name for name, original in remaining.items() if original == values]
                    require(len(matches) == 1, 'Shipping VSTest resource strings differ from their original XLF targets')
                    seen_sources.add(matches[0]); del remaining[matches[0]]; embedded += 1
                require(not remaining, 'An original VSTest project resource was omitted')
                products += 1
    require(products == 273 and embedded == 299 and len(seen_sources) == 208,
            'Exact SDK6 VSTest source satellite/resource coverage required')
    return dict(satelliteMembers=products, embeddedResourceTables=embedded, consumedOriginalResx=len(seen_sources),
                retainedOriginalXlf=234, cultures=sorted(XLF.CULTURES))


def validate(release, manifest, validated_vstest):
    release = Path(release).absolute(); proof = validated_vstest['proof']
    require(proof['sdkVersion'] == '6.0.136' and proof['component'] == 'vstest' and proof['sourceCommit'] == COMMIT
            and len(validated_vstest['members']) == 304 and len(validated_vstest['imports']) == 6,
            'Independently compiler-validated genuine SDK6 VSTest products required')
    roots = [r for r in manifest['roots'] if r['name'] == 'vstest']
    data_roots = [r for r in manifest['roots'] if r['name'] == GENERATED]
    require(len(roots) == 1 and roots[0]['kind'] == 'git' and roots[0]['commit'] == COMMIT
            and roots[0]['tree'] == TREE and not roots[0].get('deleted') and not roots[0].get('submodules'),
            'Full exact original SDK6 VSTest Git source required')
    require(len(data_roots) == 1 and data_roots[0]['kind'] == 'tree'
            and data_roots[0]['role'] == 'generated-managed-component-source' and data_roots[0].get('commit') is None,
            'Original-target RESX data must keep its separate non-Git source role')
    observed = read_json(release / 'reports/build/vstest/xlf-resource-generation.json')
    generated_names = {portable(r['generated']) for r in observed['rows']}
    require(len(generated_names) == 234, 'Exactly 234 original SDK6 translation inputs required')
    indexed, baseline = {}, {}
    with (release / 'sources' / portable(manifest['index']['path'])).open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line); name = portable(row['path'])
            if name.startswith(('vstest/', GENERATED + '/')):
                require(name not in indexed, 'Duplicate SDK6 VSTest source index member'); indexed[name] = row
                if name.startswith('vstest/'):
                    relative = name[len('vstest/'):]
                    if row.get('baseline'): baseline[relative] = row['baseline']
                    else: require(relative in generated_names, 'Unreviewed added file inside original VSTest source')
    require(P.baseline_tree(baseline) == TREE, 'Full original SDK6 VSTest Git tree differs')
    originals, generated, seen = {}, {}, set()
    with open_source_archive(release, manifest) as archive:
        for entry in archive:
            if entry.name not in indexed: continue
            row = indexed[entry.name]; require(entry.name not in seen and entry.isfile() and entry.size <= 32 * 1024**2,
                'Unique ordinary bounded SDK6 VSTest source archive member required')
            raw = archive.extractfile(entry).read(); require(fingerprint(raw) == {k: row[k] for k in FP}, 'Archived original VSTest source bytes differ')
            seen.add(entry.name)
            if entry.name.startswith(GENERATED + '/'):
                relative = entry.name[len(GENERATED) + 1:]; require(relative in generated_names, 'Unreviewed VSTest generated-data member')
                generated[relative] = raw; continue
            relative = entry.name[len('vstest/'):]
            if row.get('baseline'):
                blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
                require(blob == row['baseline']['blob'], 'Original SDK6 VSTest source was modified')
                if relative in FILES:
                    expected = FILES[relative]
                    require(len(raw) == expected['bytes'] and hashlib.sha256(raw).hexdigest() == expected['sha256']
                            and blob == expected['gitBlob'], 'Closed original SDK6 source/package/license anchor differs')
                if relative in FILES or relative.endswith(('.xlf', '.resx')): originals[relative] = raw
            else:
                require(raw == (release / 'reports/build/vstest/generated' / relative).read_bytes(),
                        'Generated compiler source inside VSTest source differs from retained generated data')
    require(seen == indexed.keys() and FILES.keys() <= originals.keys(), 'Complete original SDK6 VSTest source archive coverage required')
    receipt = regenerate(originals, observed, generated)
    require(all((release / 'reports/build/vstest/generated' / name).read_bytes() == raw for name, raw in generated.items()),
            'Local VSTest original-target generated-source report differs')
    results = worker(release, proof, originals, receipt)
    for package in proof['packages']:
        with zipfile.ZipFile(release / portable(package['path'])) as archive:
            require(archive.read('LICENSE_NET.txt') == originals['src/package/licenses/LICENSE_NET.txt'],
                    'Original SDK6 VSTest license bytes differ')
            # The original CLI nuspec includes the notice; Build's nuspec does
            # not. Bind the actual original file declaration for each product.
            name = 'CLI' if package['id'] == 'Microsoft.TestPlatform.CLI' else 'Build'
            declared = b'<file src="ThirdPartyNotices.txt" target="" />' in originals['src/package/nuspec/TestPlatform.' + name + '.nuspec']
            require(('ThirdPartyNotices.txt' in archive.namelist()) == declared,
                    'Original SDK6 VSTest third-party notice packaging differs')
            if declared:
                require(archive.read('ThirdPartyNotices.txt') == originals['src/package/ThirdPartyNotices.txt'],
                        'Original SDK6 VSTest third-party notice bytes differ')
    return dict(kind='original-sdk6-vstest-core-source-and-xlf-target-contract', sourceRoot='vstest', sourceCommit=COMMIT,
                dataRoot=GENERATED, version=VERSION, **resources(release, proof, generated, receipt),
                originalSourceBuildCoreHostScope=results['originalSourceBuildCoreHostScope'],
                fullMonoNetFrameworkTestHostProvided=False, csharpSourcesRetargeted=False,
                importedDependenciesRequireSeparateSourceAttribution=True, qualificationAllowed=False,
                sourceAdmissionAllowed=False)
