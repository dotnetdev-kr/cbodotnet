"""Exact SDK5 template, reference and Arcade preferred-source inputs.

Original package metadata stays unchanged. A declared source, an independent
publisher recipe and literal preferred IL have distinct provenance; none is
presented as an observed publisher compilation or actual producer consumption.
"""
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import xml.etree.ElementTree as ET
import zipfile

SDK = '5.0.214'
ROOT_NAME = 'sdk5-literal-template-reference-build-source-inputs'
ROLE = 'sdk5-original-packages-and-distinct-preferred-source-recipes'
KIND = 'reviewed-sdk5-literal-template-reference-build-source-inputs'
POLICY_SHA256 = '10aec50ca04af2128840343eb54fab1a893d7b3bd4c3aa6abe4928f24f99474b'
FP = ('bytes', 'sha256', 'sha512')


def require(value, message):
    if not value:
        raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def portable(name):
    require(isinstance(name, str) and name and not any(c in name for c in '\\\0\r\n')
            and not PurePosixPath(name).is_absolute() and all(p not in ('', '.', '..') for p in name.split('/')),
            'Ordinary relative SDK5 literal source path required')
    return name


def ordinary(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary unredirected SDK5 literal input required')
    return path


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def encode(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode()


def policy():
    raw = ordinary(Path(__file__).with_name('musl-legacy5-literal-source-policy.json')).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == POLICY_SHA256, 'Closed original SDK5 literal-source policy differs')
    p = json.loads(raw)
    require(p.get('schemaVersion') == 1 and p.get('sdkVersion') == SDK
            and p.get('kind') == 'sdk5-literal-template-reference-and-build-package-preferred-source-policy'
            and len(p['sources']) == 17 and len(p['packages']) == 9 and len(p['products']) == 126
            and sum(len(v) for v in p['templates'].values()) == 45 and len(p['arcadeMemberOrigins']) == 18
            and len(p['referenceIL']['members']) == 121 and p['referenceIL']['methodBodies'] == 24959
            and p['sources']['netstandard-library']['commit'] == 'b7f182415927d3b98445d043e1680c56b9d1f17c'
            and p['sources']['arcade']['commit'] == 'ee744068a4fcccc5b8b56e0025f9c95aa19ff318'
            and p['nugetVersionTag']['name'] == '4.4.0.4475'
            and p['nugetVersionTag']['commit'] == p['sources']['nuget-versioning']['commit']
            and all(p[k] is False for k in ('packageRepositoryMetadataSynthesized', 'publisherCompilerExecutionClaimed',
                'localBuildClaimed', 'qualificationAllowed', 'sourceAdmissionAllowed')),
            'Distinct closed SDK5 source, package and honest provenance set required')
    return p


def xml(raw):
    require(isinstance(raw, bytes) and len(raw) <= 2 * 1024**2
            and b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'Bounded original XML without entities required')
    return ET.fromstring(raw)


def text_values(root, name):
    return [node.text for node in root.iter() if node.tag.rsplit('}', 1)[-1] == name]


def literal_correspondence(original, package, kind, encoding='utf-8-sig'):
    if kind == 'exact':
        require(original == package, 'Exact original source/package literal bytes required')
    else:
        require(kind == 'literal-original-text-with-publisher-package-EOL'
                and original.replace(b'\r\n', b'\n') == package.replace(b'\r\n', b'\n')
                and b'\r' not in original.replace(b'\r\n', b'') and b'\r' not in package.replace(b'\r\n', b''),
                'Only the fixed original text and publisher package line endings correspond')
        require(encoding in ('utf-8-sig', 'windows-1252') and b'\0' not in original and b'\0' not in package,
                'Only the explicitly pinned original text encoding is permitted')
        original.decode(encoding)
        package.decode(encoding)


def inspect_package(path, sha, p=None):
    p = p or policy()
    expected = p['packages'].get(sha)
    path = ordinary(path)
    require(expected is not None and path.is_file() and path.stat().st_size == expected['fingerprint']['bytes'],
            'Exact original SDK5 literal/dependency package required')
    raw = path.read_bytes()
    require(fingerprint(raw) == expected['fingerprint'], 'Original SDK5 package bytes differ before ZIP interpretation')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(len(entries) == len(expected['members']) and len({e.filename for e in entries}) == len(entries)
                and {e.filename for e in entries} == expected['members'].keys(), 'Complete unique original package member set required')
        for entry in entries:
            portable(entry.filename)
            require(not entry.is_dir(), 'Ordinary original package member required')
            require((entry.external_attr >> 16) & 0o170000 in (0, 0o100000) and entry.file_size <= 32 * 1024**2,
                    'Bounded ordinary original package member required')
            require(fingerprint(archive.read(entry)) == expected['members'][entry.filename], 'Original package member bytes differ')
        metadata = xml(archive.read(expected['nuspec'])).find('{*}metadata')
        repository = metadata.find('{*}repository')
        actual_repository = dict(repository.attrib) if repository is not None else None
        require(metadata.findtext('{*}id') == expected['id'] and metadata.findtext('{*}version') == expected['version']
                and actual_repository == expected['originalRepository']
                and {n: metadata.findtext('{*}' + n) for n in expected['originalLicense']} == expected['originalLicense'],
                'Original identity, absent or partial repository metadata and licensing must remain unchanged')
    return raw


def source_recipe(sources, p=None):
    p = p or policy()
    require(sources.keys() == p['sources'].keys(), 'All distinct SDK5 preferred source roles required')
    for role, declared in p['sources'].items():
        require(sources[role].keys() == declared['selectedFiles'].keys(), 'Complete original selected source and license set required')
        for name, identity in declared['selectedFiles'].items():
            raw = sources[role][name]
            require(fingerprint(raw) == {k: identity[k] for k in FP}
                    and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == identity['gitBlob'],
                    'Exact original preferred source Git bytes required: ' + role + '/' + name)
    installer = sources['installer']
    versions = xml(installer['eng/Versions.props'])
    require(text_values(versions, 'MicrosoftDotNetTestProjectTemplates50PackageVersion') == ['1.0.2-beta4.20420.1']
            and text_values(versions, 'NUnit3Templates50PackageVersion') == ['$(NUnit3DotNetNewTemplatePackageVersion)']
            and text_values(versions, 'NUnit3DotNetNewTemplatePackageVersion') == ['1.8.1']
            and text_values(versions, 'NETStandardLibraryRefPackageVersion') == ['2.1.0'], 'Original SDK5 installer package version declarations required')
    templates = xml(installer['src/redist/targets/BundledTemplates.targets'])
    wanted = {'Microsoft.DotNet.Test.ProjectTemplates.5.0', 'NUnit3.DotNetNew.Template'}
    require(wanted <= {n.get('Include') for n in templates.iter() if n.tag.rsplit('}', 1)[-1] == 'Bundled50Templates'}
            and any(n.get('SourceFiles') == '%(Bundled50Templates.RestoredNupkgPath)'
                and n.get('DestinationFolder') == '$(RedistLayoutPath)templates/$(BundledTemplates50InstallPath)'
                for n in templates.iter() if n.tag.rsplit('}', 1)[-1] == 'Copy'), 'Original complete template-package layout recipe required')
    layout = xml(installer['src/redist/targets/GenerateLayout.targets'])
    require(any(n.findtext('{*}PackageName') == 'NETStandard.Library.Ref' for n in layout.iter()
            if n.tag.rsplit('}', 1)[-1] == 'BundledLayoutPackage'), 'Original NETStandard targeting-pack copy recipe required')
    std = xml(sources['netstandard-library']['netstandard/pkg/NETStandard.Library.pkgproj'])
    require(text_values(std, 'Version') == ['2.0.1'], 'Exact description-declared NETStandard2.0.1 publisher recipe required')
    details = xml(sources['netstandard-ref-publisher']['eng/Version.Details.xml'])
    dependency = [n for n in details.iter('Dependency') if n.get('Name') == 'NETStandard.Library']
    require(len(dependency) == 1 and dependency[0].get('Version') == '2.1.0'
            and dependency[0].findtext('Sha') == p['sources']['standard21']['commit'], 'Original CoreSetup description commit must declare its actual standard2.1 source')
    arcade_versions = xml(sources['arcade']['eng/Versions.props'])
    require(text_values(arcade_versions, 'NuGetVersioningVersion') == ['4.4.0']
            and text_values(arcade_versions, 'SystemRuntimeCompilerServicesUnsafeVersion') == ['4.7.0']
            and text_values(arcade_versions, 'SystemMemoryVersion') == ['4.5.3']
            and text_values(arcade_versions, 'SystemThreadingTasksExtensionVersion') == ['4.5.2'], 'Exact original Arcade dependency versions required')
    arcade_project = xml(sources['arcade']['src/Microsoft.DotNet.Arcade.Sdk/Microsoft.DotNet.Arcade.Sdk.csproj'])
    require('net472;netcoreapp2.1' in text_values(arcade_project, 'TargetFrameworks'), 'Original Arcade framework recipe required')
    config = xml(sources['nuget-versioning']['build/config.props'])
    require(text_values(config, 'SemanticVersion') == ['4.4.0'] and text_values(config, 'NetCoreAssemblyBuildNumber') == ['3'],
            'Publisher NuGet tag and original preview3 version recipe required')
    index = json.loads(sources['corefx0f7f']['pkg/Microsoft.Private.PackageBaseline/packageIndex.json'])
    unsafe = index['Packages']['System.Runtime.CompilerServices.Unsafe']
    require(unsafe['BaselineVersion'] == '4.7.0' and unsafe['AssemblyVersionInPackageVersion']['4.0.6.0'] == '4.7.0'
            and b'System.Runtime.CompilerServices.Unsafe.il' in sources['corefx0f7f']['src/System.Runtime.CompilerServices.Unsafe/src/System.Runtime.CompilerServices.Unsafe.ilproj'],
            'Independent original publisher Unsafe4.7 assembly/package version and authored IL recipe required')
    return dict(kind='distinct-original-SDK5-literal-and-preferred-source-recipes',
        templateFiles=45, netstandard20DescriptionCommit=p['sources']['netstandard-library']['commit'],
        netstandard21DescriptionCommit=p['sources']['netstandard-ref-publisher']['commit'],
        netstandard21PreferredILCommit=p['sources']['assets']['commit'],
        arcadeDeclaredCommit=p['sources']['arcade']['commit'], nuget44PublisherVersionTag=p['nugetVersionTag'],
        unsafe47PreferredPublisherCommit=p['sources']['corefx0f7f']['commit'],
        unsafe47OriginalEmbeddedGitCommitClaimed=False, unsafe47OriginalNuspecRepositoryClaimed=False,
        packageRepositoryMetadataSynthesized=False, publisherCompilerExecutionClaimed=False, localBuildClaimed=False)


def package_bodies(packages, sources, p=None):
    p = p or policy()
    require(set(packages) == set(p['packages']), 'All nine original/canonical SDK5 package inputs required')
    recipe = source_recipe(sources, p)
    PE = module('sdk5_literal_pure_PE_metadata', 'musl_legacy_admission.py')
    IL = module('sdk5_literal_preferred_IL_decoder', 'musl_legacy_framework_il_inputs.py')
    NH = module('sdk5_literal_NuGet_content_hash', 'musl_nuget_content_hash.py')
    bodies = {'source-recipe.json': encode(recipe), 'policy.json': encode(p)}
    archives = {}
    for sha, raw in packages.items():
        require(fingerprint(raw) == p['packages'][sha]['fingerprint'], 'Exact original source-retained package bytes required')
        bodies['packages/' + sha + '.nupkg'] = raw
        archives[sha] = zipfile.ZipFile(io.BytesIO(raw))
    try:
        for sha, mappings in p['templates'].items():
            require(not p['packages'][sha]['managedMembers'], 'Literal template package must not contain managed code')
            for member, row in mappings.items():
                raw = archives[sha].read(member)
                literal_correspondence(sources[row['sourceRole']][row['sourcePath']], raw, row['kind'])
                bodies['literal-templates/' + sha + '/' + portable(member)] = raw
        ref_sha = next(sha for sha, row in p['packages'].items() if row['role'] == 'netstandardRef')
        total = 0
        for member, row in p['referenceIL']['members'].items():
            raw = archives[ref_sha].read(member)
            il_path = p['referenceIL']['prefix'] + member[:-4] + '.il'
            proof = IL.correspondence(raw, sources['assets'][il_path])
            require(proof['mvid'] == row['mvid'] and len(proof['methodBodies']) == row['methodBodies']
                    and proof['noRvaMethods'] == row['noRvaMethods'] and not proof['resources'], 'Complete original reference IL/method/MVID correspondence required')
            total += len(proof['methodBodies'])
            bodies['reference-il-correspondence/' + fingerprint(raw)['sha256'] + '.json'] = encode(proof)
        require(total == p['referenceIL']['methodBodies'], 'All reference method bodies must correspond to preferred IL')
        standard_sha = next(sha for sha, row in p['packages'].items() if row['role'] == 'netstandardLibrary')
        for member, expected in p['packages'][standard_sha]['managedMembers'].items():
            metadata = PE.MANAGED.inspect(archives[standard_sha].read(member))
            require(PE.embedded_component_source(metadata) == expected['embeddedSource']
                    == dict(sourceCommit=p['sources']['netstandard-library']['commit'], basis='assembly-informational-version'),
                    'All113 original NETStandard2.0.1 members must retain their actual embedded Git identity')
        arc_sha = next(sha for sha, row in p['packages'].items() if row['role'] == 'arcade')
        arcade = archives[arc_sha]
        deps = json.loads(arcade.read('tools/netcoreapp2.1/Microsoft.DotNet.Arcade.Sdk.deps.json'))
        original_members = {}
        for member, row in p['arcadeMemberOrigins'].items():
            raw = arcade.read(member)
            metadata = PE.MANAGED.inspect(raw)
            require(fingerprint(raw) == p['packages'][arc_sha]['managedMembers'][member]['fingerprint']
                    and PE.embedded_component_source(metadata) == row['originalEmbeddedSource'], 'Original complete Arcade member identity must remain unchanged')
            if row['kind'] == 'original-member-embedded-Git-identity':
                require(row['originalEmbeddedSource']['sourceCommit'] == p['sources'][row['preferredSourceRole']]['commit'], 'Original Arcade member must name its exact archived source')
            else:
                require(row['kind'] == 'exact-original-canonical-dependency-and-publisher-recipe'
                        and archives[row['canonicalPackageSha256']].read(row['canonicalMember']) == raw
                        and row['originalEmbeddedSource'] is None, 'Exact canonical dependency correspondence without invented embedded metadata required')
                dependency = p['packages'][row['canonicalPackageSha256']]
                if dependency['id'] == 'NuGet.Versioning':
                    require(dependency['version'] == '4.4.0' and row['preferredSourceRole'] == 'nuget-versioning'
                            and metadata['attributes'].get('System.Reflection.AssemblyFileVersionAttribute') == [p['nugetVersionTag']['name']]
                            and metadata['attributes'].get('System.Reflection.AssemblyInformationalVersionAttribute') == ['4.4.0-preview3'],
                            'Exact original NuGet package, preview3 build tag and preferred source role required')
                else:
                    require(dependency['id'] == 'System.Runtime.CompilerServices.Unsafe' and dependency['version'] == '4.7.0'
                            and row['preferredSourceRole'] == 'corefx0f7f' and metadata['assemblyVersion'] == '4.0.6.0',
                            'Exact original Unsafe4.7 package, assembly and independent publisher source role required')
                key = dependency['id'] + '/' + dependency['version']
                require(deps['libraries'][key]['sha512'] == 'sha512-' + NH.content_hash(packages[row['canonicalPackageSha256']]),
                        'Original Arcade deps content hash must bind the canonical dependency')
            original_members[member] = dict(row, fingerprint=fingerprint(raw), assemblyName=metadata['assemblyName'], assemblyVersion=metadata['assemblyVersion'])
        for member, row in p['arcadeLiteralMembers'].items():
            raw = arcade.read(member)
            if row['sourceCandidates']:
                for candidate in row['sourceCandidates']:
                    if candidate.get('encoding') == 'windows-1252':
                        require(member == 'tools/Licenses/VisualStudioExtensions.txt'
                                and candidate['sourcePath'] == 'src/Microsoft.DotNet.Arcade.Sdk/' + member,
                                'Only the original specific Windows-1252 license correspondence is reviewed')
                    literal_correspondence(sources['arcade'][candidate['sourcePath']], raw, candidate['kind'], candidate.get('encoding', 'utf-8-sig'))
            else:
                require(member in {'tools/net472/Microsoft.DotNet.Arcade.Sdk.dll.config',
                    'tools/netcoreapp2.1/Microsoft.DotNet.Arcade.Sdk.deps.json', 'tools/DefaultVersions.Generated.props'},
                    'Only the three closed readable generated Arcade inputs are admitted')
                raw.decode('utf-8-sig')
                if member.endswith('.props'):
                    root = xml(raw)
                    require(root.tag == 'Project' and len(root) == 1 and root[0].tag == 'PropertyGroup'
                            and not root[0].attrib and all(not n.attrib and not len(n) for n in root[0]),
                            'Generated original version input must contain only scalar properties')
            bodies['arcade-readable-inputs/' + portable(member)] = raw
        bodies['arcade-member-source-correspondence.json'] = encode(original_members)
        bodies['origin.json'] = encode(dict(schemaVersion=1, sdkVersion=SDK, kind=KIND, policySha256=POLICY_SHA256,
            packageRepositoryMetadataSynthesized=False, unsafe47OriginalEmbeddedGitCommitClaimed=False,
            publisherCompilerExecutionClaimed=False, packageSignatureAuthenticityClaimed=False,
            localBuildClaimed=False, actualProducerConsumptionValidated=False, qualificationAllowed=False, sourceAdmissionAllowed=False))
    finally:
        for archive in archives.values():
            archive.close()
    return bodies


def prepare(packages, sources, destination):
    p = policy()
    selected = {}
    for role, row in p['sources'].items():
        path = ordinary(sources[role])
        git = ['git', '-c', 'safe.directory=' + str(path), '-C', str(path)]
        require(subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip() == row['commit']
                and subprocess.check_output(git + ['rev-parse', 'HEAD^{tree}'], text=True).strip() == row['tree'], 'Exact original source Git commit/tree required')
        selected[role] = {n: subprocess.check_output(git + ['show', 'HEAD:' + n]) for n in row['selectedFiles']}
    raw = {sha: inspect_package(packages[sha], sha, p) for sha in p['packages']}
    bodies = package_bodies(raw, selected, p)
    destination = ordinary(destination)
    require(not destination.exists(), 'Fresh SDK5 literal-source supplemental tree required')
    destination.mkdir(parents=True)
    for name, value in bodies.items():
        path = destination / portable(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(value)
    return dict(name=ROOT_NAME, kind='tree', path=str(destination), role=ROLE)


def validate(release, manifest, packages):
    """Caller first authenticates the complete source packet with Packer.verify."""
    p = policy()
    release = ordinary(release)
    require(manifest.get('sdkVersion') == SDK and manifest.get('targetRid') in ('linux-musl-arm64', 'linux-musl-x64'),
            'Distinct SDK5 complete source packet required')
    B = module('sdk5_literal_source_byte_primitives', 'musl_legacy_admission.py')
    P = module('sdk5_literal_source_git_primitives', 'package-used-source.py')
    I = module('sdk5_literal_source_installer_guard', 'musl_legacy5_installer_inputs.py')
    installer_proof = I.validate(release, manifest)
    index_path = B.checked(release / 'sources', manifest['index'])
    archive_path = B.checked(release / 'sources', manifest['archive'])
    roots = {}
    for role, row in p['sources'].items():
        found = [r for r in manifest['roots'] if r.get('kind') in ('git', 'git-export') and r.get('commit') == row['commit']
                 and r.get('tree') == row['tree'] and not r.get('exclude') and not r.get('deleted')]
        require(len(found) == 1 and found[0]['files'] == row['files'], 'One complete original preferred-source tree required: ' + role)
        roots[role] = found[0]
    for role, row in p['sources'].items():
        actual = roots[role].get('submodules', [])
        require({(r['path'], r['commit']) for r in actual} == {(r['path'], r['commit']) for r in row['gitlinks']},
                'All exact original preferred-source Gitlinks required')
        for link in actual:
            child = [r for r in roots.values() if r['name'] == link['root'] and r['commit'] == link['commit']]
            require(len(child) == 1, 'Original Gitlink must bind its complete archived child source')
    data_roots = [r for r in manifest['roots'] if r['name'] == ROOT_NAME]
    require(len(data_roots) == 1 and data_roots[0]['kind'] == 'tree' and data_roots[0].get('role') == ROLE
            and data_roots[0].get('commit') is None, 'Literal/package inputs retain their distinct non-Git data role')
    prefixes = {r['name'] + '/': role for role, r in roots.items()}
    indexed, baselines = {}, {role: {} for role in roots}
    patches = {'orchestration/' + name for name in I.PATCHES}
    with index_path.open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            name = portable(row['path'])
            selected = next(((prefix, role) for prefix, role in prefixes.items() if name.startswith(prefix)), None)
            if selected:
                prefix, role = selected
                relative = name[len(prefix):]
                require(name not in indexed and row.get('baseline'), 'Unique complete original preferred-source baseline required')
                indexed[name] = (role, relative, row)
                baselines[role][relative] = row['baseline']
            elif name.startswith(ROOT_NAME + '/') or name in patches:
                require(name not in indexed, 'Unique literal data/patch member required')
                indexed[name] = (None, name, row)
    for role, baseline in baselines.items():
        require(len(baseline) == roots[role]['files'], 'Every original preferred-source file must remain indexed')
        for link in roots[role].get('submodules', []):
            baseline[link['path']] = dict(mode='160000', blob=link['commit'])
        require(P.baseline_tree(baseline) == p['sources'][role]['tree'], 'Complete original preferred-source Git tree differs')
    found, sources, data, patch_bytes = set(), {role: {} for role in roots}, {}, {}
    with tarfile.open(archive_path, 'r|gz') as archive:
        for entry in archive:
            if entry.name not in indexed:
                continue
            role, name, row = indexed[entry.name]
            require(entry.name not in found and entry.size <= 64 * 1024**2, 'Unique bounded original preferred-source archive member required')
            require((row['mode'] == '120000' and entry.issym() and entry.mode == 0o777)
                    or (row['mode'] in ('100644', '100755') and entry.isfile() and entry.size == row['bytes']
                        and entry.mode == (0o755 if row['mode'] == '100755' else 0o644)), 'Exact original archived source file type/mode/size required')
            raw = entry.linkname.encode() if entry.issym() else archive.extractfile(entry).read()
            require(fingerprint(raw) == {k: row[k] for k in FP}, 'Archived original source/input fingerprints differ')
            if role:
                require(row['mode'] == row['baseline']['mode'], 'Original source Git mode must remain exact')
                if role != 'installer':
                    require(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['baseline']['blob'],
                            'Complete pristine preferred-source Git bytes required')
                if name in p['sources'][role]['selectedFiles']:
                    sources[role][name] = raw
            elif entry.name in patches:
                patch_bytes[entry.name] = raw
            else:
                require(entry.isfile(), 'Literal supplementary data must be ordinary files')
                data[name[len(ROOT_NAME) + 1:]] = raw
            found.add(entry.name)
    require(found == indexed.keys(), 'Complete preferred-source and supplemental archive required')
    target = 'src/redist/targets/GenerateLayout.targets'
    for patch, (_, targets) in reversed(list(I.PATCHES.items())):
        if target in targets:
            sources['installer'][target] = I.reverse_exact_hunks(sources['installer'][target], patch_bytes['orchestration/' + patch], target)
    raw_packages = {sha: inspect_package(packages[sha], sha, p) for sha in p['packages']}
    require(data == package_bodies(raw_packages, sources, p), 'Every original package, literal input and complete derived correspondence must match')
    products = {name: dict(row, sourceBasis='closed-original-package-and-distinct-preferred-source-recipe') for name, row in p['products'].items()}
    return dict(kind=KIND, dataRoot=ROOT_NAME, products=products,
        packages={sha: dict(role=row['role'], sourceRoot=ROOT_NAME, sourceCommit=None,
            originalRepository=row['originalRepository'], sourceBasis='original-package-with-distinct-member-preferred-sources') for sha, row in p['packages'].items()},
        completeGitSourceRoots=len(roots), templateSourceFiles=45, referenceAssemblyInputs=121,
        referenceMethodBodies=24959, standard20EmbeddedSourceMembers=113, arcadeManagedMembers=18,
        originalInstallerSourceGuard=installer_proof, packageRepositoryMetadataSynthesized=False,
        unsafe47OriginalEmbeddedGitCommitClaimed=False, publisherCompilerExecutionClaimed=False,
        packageSignatureAuthenticityClaimed=False, localBuildClaimed=False,
        actualProducerConsumptionValidated=False, qualificationAllowed=False, sourceAdmissionAllowed=False)
