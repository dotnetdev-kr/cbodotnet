"""SDK6 original NuGet library graph, bounded Pack adaptation and source proof.

The caller first validates actual compiler/member evidence. This additional
leaf binds the original build commands and complete patched Git sources.
"""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import tarfile
import zipfile
from musl_source_archive import open_source_archive

ROOT = Path(__file__).resolve().parents[1]
SDK = '6.0.136'
COMMIT = '451e9bc27184dc49d04e975122c9e7189d525872'
TREE = '801b3070a0df1386c6593df4d40b7a5f066f1d77'
VERSION = '6.0.6-rc.4'
PROJECT = 'src/NuGet.Core/NuGet.Build.Tasks.Pack/NuGet.Build.Tasks.Pack.csproj'
ORIGINAL_BLOB = 'c94acffd885742b8c71f3e39818ca07ecdd08f4f'
PATCH = 'patches/net6-musl/0002-preserve-source-build-unmerged-pack-matrix.patch'
PATCH_SHA256 = '5e98dc1c81fd917017b48882fd71c9a731067b41a3e8d5280a832047f7a82fcd'
FRAMEWORKS = ['net40', 'net45', 'net472', 'net6.0', 'netstandard2.0']
CRLF_EXTENSIONS = ('.csproj', '.dbproj', '.filters', '.fsproj', '.props', '.sln', '.targets', '.vbproj', '.vcxitems', '.vcxproj')
SUBMODULES = {
    'submodules/Common': ('e6fac8061686c18531e2621ccef97dd5e0687a65', '11c9e8afb728e49c161c02a6d05b17bea009aacd'),
    'submodules/FileSystem': ('f1f3f0820a573b96b2faaf5b7e6be9a036e4c7aa', '2b74396a18f39043faa686296473c383b86f6bc7'),
    'submodules/NuGet.Build.Localization': ('f15db7b7c6f5affbea268632ef8333d2687c8031', '4b825dc642cb6eb9a060e54bf8d69288fbee4904')}
FP = ('bytes', 'sha256', 'sha512')
FEEDS = ['https://api.nuget.org/v3/index.json',
    'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public/nuget/v3/index.json',
    'https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-eng/nuget/v3/index.json']


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


B = module('sdk6_nuget_source_neutral_primitives', 'musl_legacy_admission.py')
P = module('sdk6_nuget_complete_source_packer', 'package-used-source.py')
require, portable = B.require, B.portable


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def read(path):
    path = Path(path).absolute()
    require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary SDK6 NuGet input required')
    return path.read_bytes()


def original_pack(patched, patch):
    require(hashlib.sha256(patch).hexdigest() == PATCH_SHA256, 'Exact reviewed three-condition NuGet6 Pack patch required')
    # The pinned upstream attributes require CRLF for this project. Preserve
    # actual archived bytes; reverse only a uniform original checkout encoding.
    if b'\r' in patched:
        canonical = patched.replace(b'\r\n', b'\n')
        require(b'\r' not in canonical and b'\0' not in canonical and patched == canonical.replace(b'\n', b'\r\n'),
                'Uniform original NuGet6 project line endings required')
        patched = canonical
    original = B.reverse_reviewed_patch(patched, patch, PROJECT)
    blob = hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest()
    require(blob == ORIGINAL_BLOB, 'NuGet6 Pack adaptation does not recover its original Git blob')
    return original


def pristine_source(row, raw, child_solutions=()):
    blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    # Exactly the Visual Studio suffixes declared eol=crlf by this pinned
    # parent's original .gitattributes; never a general source normalization.
    explicit = (row['path'].startswith('nuget/') and row['path'].lower().endswith(CRLF_EXTENSIONS)) or row['path'] in child_solutions
    windows = explicit or row['path'].lower().endswith(('.cmd', '.bat'))
    return P.pristine_blob(row, blob, raw if windows else None, allow_audited_crlf=explicit)


def worker(release, proof):
    directory = release / 'reports/build/nuget'
    result = json.loads(read(directory / 'results.json'))
    require(result['schemaVersion'] == 1 and result['kind'] == 'legacy-musl6-nuget-source-build'
            and result['status'] == 'passed' and result['sdkVersion'] == SDK and result['sourceCommit'] == COMMIT
            and result['version'] == VERSION and result['architecture'] in ('aarch64', 'x64')
            and result['sourceGraph'] == 'build/build.proj' and result['libraryFrameworks'] == FRAMEWORKS
            and result['managedPackageMembers'] == 72 and result['executableFramework'] == 'net6.0'
            and result['originalLibraryDefaultsSelectedExplicitly'] is True
            and all(result[k] is False for k in ('libraryFrameworksRemoved', 'productCSharpEdited', 'vendorVersionRelabeled',
                                                'qualificationAllowed', 'sourceAdmissionAllowed')),
            'Complete original SDK6 NuGet source-build matrix required')
    patch = read(ROOT / PATCH)
    require(result['sourcePatches'] == [dict(path=PATCH, **fingerprint(patch))]
            and read(directory / 'source.patch') == patch, 'Actual NuGet6 retained source adaptation differs')
    source = proof['sourceMountRoot']
    require(source == '/work/work/nuget', 'Exact normal SDK6 NuGet source mount required')
    commands = result['commands']
    require(len(commands) == 3, 'Exactly three original SDK6 NuGet source commands required')
    git = ['git', '-c', 'safe.directory=' + source, '-C', source, 'apply']
    expected = [('source-patch-check', git + ['--check', '/project/' + PATCH]),
                ('source-patch-apply', git + ['/project/' + PATCH]),
                ('original-library-matrix', ['/bootstrap/dotnet', 'msbuild', source + '/build/build.proj',
                 '-t:RestoreXPLAT,BuildXPLAT,PackXPLAT', '/p:Configuration=Release', '/p:BuildNumber=4', '/p:ReleaseLabel=rc',
                 '/p:IsXPlat=true', '/p:DotNetBuildFromSource=true', '/p:NetStandardVersion=netstandard2.0',
                 '/p:IsBuildOnlyXPLATProjects=false', '/p:BuildProjectReferences=true', '/p:RepositoryCommit=' + COMMIT,
                 '/p:SourceRevisionId=' + COMMIT, '/p:UseSharedCompilation=false', '/p:EmitCompilerGeneratedFiles=true',
                 '/p:RestoreSources=' + '%3B'.join(FEEDS), '/m:2',
                 '/bl:/delivery/reports/build/nuget/original-library-matrix.binlog', '/nologo'])]
    for row, (name, argv) in zip(commands, expected):
        require(row['name'] == name and row['command'] == argv and row['exitCode'] == 0 and row['log'] == name + '.log',
                'An original SDK6 NuGet source command or framework was overridden')
        raw = read(directory / row['log'])
        require(fingerprint(raw) == {k: row[k] for k in FP} and json.loads(raw.splitlines()[0]) == argv
                and json.loads(read(directory / (name + '-command.json'))) == row,
                'Actual SDK6 NuGet command receipt/log differs')
    require(fingerprint(read(directory / 'original-library-matrix.binlog')) == {k: proof['binlog'][k] for k in FP},
            'NuGet6 compiler replay does not consume its original source worker binlog')
    expected_packages = {'source-built-feed/' + row['file']: {k: row[k] for k in FP} for row in proof['packages']}
    require(len(result['packages']) == 19 and {row['path']: {k: row[k] for k in FP} for row in result['packages']} == expected_packages,
            'All nineteen actual NuGet6 source worker packages must match the compiler proof')
    frameworks = set()
    for relative, fp in expected_packages.items():
        raw = read(directory / portable(relative)); require(fingerprint(raw) == fp, 'Actual original NuGet6 worker package differs')
        with zipfile.ZipFile(directory / relative) as archive:
            frameworks.update(name.split('/')[1] for name in archive.namelist()
                              if name.startswith('lib/') and name.endswith('.dll') and not name.endswith('.resources.dll'))
    require(frameworks == set(FRAMEWORKS), 'Original NuGet6 package target framework matrix differs')
    return result, patch


def validate(release, manifest, validated_nuget):
    release = Path(release).absolute(); proof = validated_nuget['proof']
    require(proof['sdkVersion'] == SDK and proof['component'] == 'nuget' and proof['sourceCommit'] == COMMIT
            and len(validated_nuget['members']) == 72 and not validated_nuget['imports'],
            'Independently compiler-validated original NuGet6 products required')
    result, patch = worker(release, proof)
    all_roots = {row['name']: row for row in manifest['roots']}
    root = all_roots.get('nuget', {})
    require(root.get('kind') in ('git', 'git-export') and root.get('commit') == COMMIT and root.get('tree') == TREE
            and not root.get('deleted') and not root.get('exclude'), 'Complete original SDK6 NuGet Git source required')
    children = root.get('submodules', [])
    require(len(children) == 3 and {row['path']: row['commit'] for row in children} ==
            {name: pin[0] for name, pin in SUBMODULES.items()}, 'All three original NuGet6 Gitlinks required')
    roots = {'nuget': root}
    child_solutions = set()
    for child in children:
        row = all_roots.get(child['root'], {}); commit, tree = SUBMODULES[child['path']]
        require(row.get('kind') in ('git', 'git-export') and row.get('commit') == commit and row.get('tree') == tree
                and not row.get('deleted') and not row.get('exclude') and not row.get('submodules'),
                'Complete original NuGet6 Gitlink corresponding source required')
        roots[child['root']] = row
        # Each of these two pinned children independently declares only its
        # original solution's CRLF checkout encoding. Parent rules do not flow
        # across the Gitlink boundary.
        if child['path'] in ('submodules/Common', 'submodules/FileSystem'):
            child_solutions.add(child['root'] + '/' + child['path'].rsplit('/', 1)[1] + '.sln')
    indexed = {}; baselines = {name: {} for name in roots}
    with (release / 'sources' / portable(manifest['index']['path'])).open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line); name = portable(row['path']); prefix, _, relative = name.partition('/')
            if prefix not in roots: continue
            require(name not in indexed and row.get('baseline'), 'Unique original NuGet6 source baseline required')
            indexed[name] = row; baselines[prefix][relative] = row['baseline']
    for child in children: baselines['nuget'][child['path']] = dict(mode='160000', blob=child['commit'])
    require(all(P.baseline_tree(baselines[name]) == row['tree'] for name, row in roots.items()),
            'Complete original NuGet6 parent/submodule Git trees differ')
    seen = set(); patched = None
    with open_source_archive(release, manifest) as archive:
        for entry in archive:
            if entry.name not in indexed: continue
            require(entry.name not in seen and (entry.isfile() or entry.issym()) and entry.size <= 32 * 1024**2,
                    'Unique bounded original NuGet6 source archive member required')
            raw = entry.linkname.encode() if entry.issym() else archive.extractfile(entry).read()
            row = indexed[entry.name]; require(fingerprint(raw) == {k: row[k] for k in FP}, 'Archived NuGet6 source bytes differ')
            if entry.name == 'nuget/' + PROJECT:
                patched = raw
                require(original_pack(raw, patch) == read(release / 'reports/build/nuget/original-Pack.csproj'),
                        'Retained original NuGet6 Pack source differs')
            else:
                require(pristine_source(row, raw, child_solutions),
                        'An unreviewed NuGet6 original source or framework change is present')
            seen.add(entry.name)
    require(seen == indexed.keys() and patched is not None, 'Complete original patched NuGet6 source archive required')
    return dict(kind='original-sdk6-nuget-library-source-contract', sourceCommit=COMMIT, version=VERSION,
                packages=19, compiledMembers=72, libraryFrameworks=FRAMEWORKS, originalGitSourceRoots=4,
                originalSourceFiles=len(indexed), productCSharpEdited=False, vendorVersionRelabeled=False,
                qualificationAllowed=False, sourceAdmissionAllowed=False)
