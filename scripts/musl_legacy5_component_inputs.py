"""Full original SDK5 SDK, NuGet and VSTest source trees and exact changes."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import xml.etree.ElementTree as ET

import musl_legacy5_component_evidence as CE
import musl_legacy5_installer_inputs as INSTALLER
import musl_legacy5_native_inputs as N
import musl_legacy5_nuget_graph as GRAPH

B, P, require = CE.B, INSTALLER.P, CE.require
POLICIES = {
    'sdk': dict(commit=CE.COMMITS['sdk'], tree='74e630400d8d0e0f789820907182e05dcd1e04d2', files=2760),
    'nuget': dict(commit=CE.COMMITS['nuget'], tree='196d72db5e574cf7ca35f53d0113fb1bcc5cb847', files=4773),
    'vstest': dict(commit=CE.COMMITS['vstest'], tree='c9bcaf08d956526caf1374c9bb1340a367843604', files=1773)}
PATCHES = {
    'sdk': ('patches/net5-musl/0005-use-upstream-source-build-windowsdesktop-import-guard.patch',
            '5be185f50dbf6a7018989e62d4c02afed9341d7ccdab642da76236fc1224e6c1',
            'src/Tasks/Microsoft.NET.Build.Tasks/targets/Microsoft.NET.Sdk.props'),
    'nuget': ('patches/net5-musl/0009-preserve-original-nuget-unmerged-pack-matrix.patch',
              '7820689e72944f2c608810ad59a93b27c1ddd8459830907a63358dc5c683f286',
              'src/NuGet.Core/NuGet.Build.Tasks.Pack/NuGet.Build.Tasks.Pack.csproj')}
RESTORE_MARKER = b'  # The following frameworks and tools are used only for testing.\n'
RESTORE_HOOK = (b'  # Product-only builds do not execute these historical test frameworks.\n'
                b'  if [[ ${CBODOTNET_SKIP_LEGACY_TEST_RUNTIME_INSTALLS:-} == true ]]; then\n'
                b'    return\n  fi\n\n')
TRANSLATION_HOOK = b'''  <Target Name="CopyCommunityMuslNuGetTranslationData"
          AfterTargets="PublishTestCli"
          Condition="'$(CommunityMuslNuGetTranslationRoot)' != ''">
    <ItemGroup>
      <_CommunityMuslNuGetTranslation Include="$(CommunityMuslNuGetTranslationRoot)/**/*.resources.dll" />
    </ItemGroup>
    <Error Condition="'@(_CommunityMuslNuGetTranslation)' == ''"
           Text="The exact reviewed imported NuGet translation data is absent" />
    <Copy SourceFiles="@(_CommunityMuslNuGetTranslation)"
          DestinationFiles="@(_CommunityMuslNuGetTranslation->'$(OutputPath)/%(RecursiveDir)%(Filename)%(Extension)')"
          SkipUnchangedFiles="false" />
  </Target>

'''
NUGET_DRIVER = 'build/cbodotnet-xplat-source.proj'


def original_blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def original_source_mode(row, entry):
    """Declared byte edits never authorize a Git source type/mode change."""
    if row.get('baseline', {}).get('mode') == '120000':
        return (row.get('mode') == '120000' and entry.type == tarfile.SYMTYPE
                and entry.sparse is None and entry.mode == 0o777)
    return N.patched_source_mode(row, entry)

def patched_project_text(component, name, raw):
    if b'\r' not in raw: return raw
    # Git applies this exact reviewed Pack patch with its original CRLF
    # checkout rule. Only this single XML project may recover uniform LF for
    # reverse-patch comparison; actual archived/compiler input bytes remain
    # unchanged, and the recovered complete file must match the pinned blob.
    require(component == 'nuget' and name == PATCHES['nuget'][2], 'Only the exact patched SDK5 NuGet XML project may use its original checkout encoding')
    canonical = raw.replace(b'\r\n', b'\n')
    require(b'\r' not in canonical and b'\0' not in canonical and raw == canonical.replace(b'\n', b'\r\n'),
            'Only original uniform SDK5 NuGet project checkout encoding is allowed')
    return canonical


def reverse_sdk_hooks(name, raw):
    if name == 'eng/restore-toolset.sh':
        revised = RESTORE_HOOK + RESTORE_MARKER
        require(raw.count(revised) == 1, 'Exact SDK5 product-only test-runtime bootstrap hook required')
        return raw.replace(revised, RESTORE_MARKER, 1)
    if name == 'src/Layout/redist/targets/GenerateLayout.targets':
        end = TRANSLATION_HOOK + b'</Project>\n'
        require(raw.count(TRANSLATION_HOOK) == 1 and raw.endswith(end), 'Exact original SDK5 resource-only translation layout hook required')
        return raw[:-len(end)] + b'</Project>\n'
    return raw


def nuget_driver(projects):
    selected = []
    for name, raw in sorted(projects.items()):
        require(len(PurePosixPath(name).parts) == 4 and name.startswith('src/') and name.endswith('.csproj'),
                'Complete original SDK5 NuGet product project candidates required')
        if GRAPH.properties(ET.fromstring(raw), 'XPLATProject') == ['true']: selected.append(name)
    require(selected, 'Complete original SDK5 NuGet XPLAT product selection required')
    root = ET.Element('Project', DefaultTargets='RestoreXPLAT;BuildXPLAT;PackXPLAT')
    ET.SubElement(root, 'Import', Project='$(MSBuildThisFileDirectory)build.proj')
    group = ET.SubElement(ET.SubElement(root, 'Target', Name='GetXPLATProjects'), 'ItemGroup')
    for name in selected: ET.SubElement(group, 'XPLATProjects', Include='$(MSBuildThisFileDirectory)../' + name)
    ET.indent(root, space='  ')
    return ET.tostring(root, encoding='utf-8', xml_declaration=True) + b'\n', selected


def validate(release, manifest, component):
    require(component in POLICIES, 'Distinct original SDK5 component policy required')
    release = Path(release); policy = POLICIES[component]; all_roots = {r['name']: r for r in manifest['roots']}
    require(len(all_roots) == len(manifest['roots']) and component in all_roots, 'One complete original SDK5 component source root required')
    root = all_roots[component]
    require(root['kind'] in ('git', 'git-export') and root.get('commit') == policy['commit'] and root.get('tree') == policy['tree']
            and not root.get('deleted') and not root.get('exclude'), 'Complete original SDK5 component Git tree without omissions required')
    roots = {component: root}
    if component == 'nuget':
        require(len(root.get('submodules', [])) == 3, 'All three original SDK5 NuGet Gitlinks required')
        for child in root['submodules']:
            name = component + '-sub-' + hashlib.sha256(child['path'].encode()).hexdigest()[:12]
            require(name in all_roots and all_roots[name]['kind'] in ('git', 'git-export') and all_roots[name].get('commit') == child['commit']
                    and not all_roots[name].get('deleted') and not all_roots[name].get('exclude'), 'Complete exact original SDK5 NuGet Gitlink source required')
            roots[name] = all_roots[name]
    indexed, baselines = {}, {name: {} for name in roots}; patch = PATCHES.get(component)
    patch_name = 'orchestration/' + patch[0] if patch else None
    with (release / 'sources' / B.portable(manifest['index']['path'])).open() as stream:
        for line in stream:
            row = json.loads(line); name = B.portable(row['path']); parent, _, relative = name.partition('/')
            if parent not in roots and name != patch_name: continue
            require(name not in indexed, 'Unique SDK5 component source index required'); indexed[name] = row
            if parent in roots:
                if component == 'nuget' and parent == component and relative == NUGET_DRIVER:
                    require(not row.get('baseline'), 'The derived SDK5 NuGet driver must retain its explicit non-Git origin')
                else:
                    require(row.get('baseline'), 'An unreviewed new SDK5 component source file is present')
                    baselines[parent][relative] = row['baseline']
    for name, entry in roots.items():
        baseline = dict(baselines[name])
        for child in entry.get('submodules', []): baseline[child['path']] = dict(mode='160000', blob=child['commit'])
        require(P.baseline_tree(baseline) == entry['tree'] and len(baselines[name]) == entry['files'] - (1 if name == 'nuget' else 0),
                'Full original SDK5 component/Gitlink baseline required')
    require(len(baselines[component]) == policy['files'] and (not patch or patch_name in indexed), 'All original SDK5 source files and exact patch must be archived')
    changed = ({patch[2]} if patch else set()) | ({'eng/restore-toolset.sh', 'src/Layout/redist/targets/GenerateLayout.targets'} if component == 'sdk' else set())
    found, saved, projects = set(), {}, {}
    with tarfile.open(release / 'sources' / B.portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if entry.name not in indexed: continue
            require(entry.name not in found and (entry.isfile() or entry.issym()) and entry.size <= 64 * 1024**2,
                    'Unique ordinary bounded SDK5 component source required')
            row = indexed[entry.name]; parent, _, relative = entry.name.partition('/')
            if parent in roots and row.get('baseline'):
                require(original_source_mode(row, entry), 'SDK5 original component source must retain exact Git/index/TAR type and mode: ' + entry.name)
            raw = entry.linkname.encode() if entry.issym() else archive.extractfile(entry).read()
            require(N.fingerprint(raw) == {key: row[key] for key in N.FP}, 'Actual archived SDK5 component source bytes differ')
            if parent in roots:
                if parent == component and (relative in changed or component == 'nuget' and relative == NUGET_DRIVER): saved[relative] = raw
                else: require(original_blob(raw) == row['baseline']['blob'], 'Unreviewed SDK5 original component source change: ' + entry.name)
                if component == 'nuget' and parent == component and len(PurePosixPath(relative).parts) == 4 and relative.startswith('src/') and relative.endswith('.csproj'):
                    projects[relative] = raw
            else: saved['patch'] = raw
            found.add(entry.name)
    require(found == indexed.keys(), 'Complete original SDK5 component archive required')
    if patch:
        require(hashlib.sha256(saved['patch']).hexdigest() == patch[1], 'Exact SDK5 component source patch bytes required')
        # The pinned SDK5 WindowsDesktop patch is Git format-patch mail. Its
        # authenticated trailer is framing, while every source hunk stays exact.
        body = saved['patch'].split(b'\n-- \n', 1)[0] + (b'\n' if b'\n-- \n' in saved['patch'] else b'')
        section = N.patch_sections(body, (patch[2],))[patch[2]]
        saved[patch[2]] = INSTALLER.reverse_exact_hunks(patched_project_text(component, patch[2], saved[patch[2]]), section, patch[2])
    for name in changed:
        original = reverse_sdk_hooks(name, saved[name]) if component == 'sdk' else saved[name]
        require(original_blob(original) == indexed[component + '/' + name]['baseline']['blob'], 'SDK5 exact declared changes must recover original component Git blobs')
        if component == 'nuget' and name in projects: projects[name] = original
    selected = None
    if component == 'nuget':
        expected, selected = nuget_driver(projects)
        require(saved[NUGET_DRIVER] == expected, 'SDK5 NuGet derived driver must select exactly the original XPLAT projects')
    return dict(status='passed-complete-original-sdk5-component-source', component=component, sourceCommit=policy['commit'],
        sourceTree=policy['tree'], originalFiles=sum(map(len, baselines.values())), gitRoots=len(roots), changedOriginalFiles=len(changed),
        derivedNugetProjects=selected, arbitraryCSharpOrTargetEditsAccepted=False, qualificationAllowed=False, sourceAdmissionAllowed=False)
