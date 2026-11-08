"""Derive the exact original NuGet5 XPLAT product set without loading VS SDKs."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import xml.etree.ElementTree as ET

COMMIT = 'd525b0e670f3b6cbd5c73a35f04730a9f658c852'
PRODUCT_GLOB = '$(RepositoryRootDirectory)src\\*\\*\\*.csproj'


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def tag(element): return element.tag.rsplit('}', 1)[-1].casefold()


def verify_original_raw_tree(source, expected_commit=COMMIT):
    source = Path(source)
    git = ['git', '-c', 'safe.directory=' + str(source), '-C', str(source)]
    require(subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip() == expected_commit,
            'Exact original source commit required')
    require(not subprocess.check_output(git + ['ls-files', '--others', '--exclude-standard'], text=True),
            'No untracked source inputs may precede the build')
    count = 0
    children = []
    for entry in subprocess.check_output(git + ['ls-tree', '-rz', '--full-tree', expected_commit]).split(b'\0'):
        if not entry: continue
        header, encoded = entry.split(b'\t', 1)
        mode, kind, blob = header.decode().split()
        if kind == 'commit':
            child = source / encoded.decode()
            require(child.is_dir() and not child.is_symlink(), 'Original Gitlink source is missing/redirected')
            children.append(dict(path=encoded.decode(), **verify_original_raw_tree(child, blob)))
            continue
        path = source / encoded.decode()
        if mode == '120000':
            import os
            require(path.is_symlink(), 'Original source symlink differs')
            raw = os.readlink(path).encode()
        else:
            require(mode in {'100644', '100755'} and path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)),
                    'Original source file is absent or redirected')
            raw = path.read_bytes()
            if mode == '100755': require(path.stat().st_mode & 0o111, 'Original executable source mode is absent')
        require(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == blob,
                'Original source raw Git blob differs: ' + str(path))
        count += 1
    return dict(commit=expected_commit, files=count, submodules=children, allTrackedRawGitBlobsIdentical=True,
                untrackedInputs=False, gitEolStatusNotUsedAsSourceSubstitute=True)


def properties(document, property_name):
    parents = {child: parent for parent in document.iter() for child in parent}
    result = []
    for node in document.iter():
        if tag(node) != property_name.casefold(): continue
        parent = parents.get(node)
        require(parent is not None and tag(parent) == 'propertygroup' and parents.get(parent) is document,
                'Conditional/inherited XPLAT property structure requires source review')
        require(not node.attrib.get('Condition') and not parent.attrib,
                'Conditional XPLAT declaration requires source review')
        require(not node.attrib, 'Unexpected XPLAT declaration attribute')
        value = (node.text or '').strip().casefold()
        require(value in {'true', 'false'}, 'Dynamic XPLAT declaration requires source review')
        result.append(value)
    require(len(result) <= 1, 'XPLAT declaration override requires source review')
    return result


def prepare(source, destination):
    source, destination = Path(source), Path(destination)
    git = ['git', '-c', 'safe.directory=' + str(source), '-C', str(source)]
    require(subprocess.check_output(git + ['rev-parse', 'HEAD'], text=True).strip() == COMMIT,
            'Exact NuGet5 source commit required')
    require(not destination.exists(), 'Fresh graph evidence directory required')
    destination.mkdir(parents=True)

    def original(name): return subprocess.check_output(git + ['show', COMMIT + ':' + name])
    names = [line for line in subprocess.check_output(git + ['ls-tree', '-rz', '--name-only', COMMIT]).decode().split('\0') if line]
    products = [name for name in names if len(PurePosixPath(name).parts) == 4 and name.startswith('src/') and name.endswith('.csproj')]
    require(products and len(products) == len(set(products)), 'Complete original ProductProjects candidates required')
    all_product_declarations = []
    inherited = []
    scan = subprocess.run(git + ['grep', '-I', '-l', '-i', '-E',
        r'<[[:space:]]*(ProductProjects|XPLATProject)([[:space:]]|>)', COMMIT,
        '--', '*.props', '*.targets', '*.proj', '*.csproj'], capture_output=True, text=True)
    require(scan.returncode in {0, 1}, 'Original declaration enumeration failed')
    declaration_files = [line.removeprefix(COMMIT + ':') for line in scan.stdout.splitlines()]
    require(declaration_files and all(name in names for name in declaration_files), 'Original declaration source paths differ')
    for name in declaration_files:
        raw = original(name)
        if re.search(rb'<\s*ProductProjects(?:\s|>)', raw, re.I):
            document = ET.fromstring(raw)
            for node in document.iter():
                if tag(node) == 'productprojects':
                    require(node.attrib == {'Include': PRODUCT_GLOB}, 'Original ProductProjects declaration/override differs')
                    parents = {child: parent for parent in document.iter() for child in parent}
                    parent = parents.get(node)
                    require(parent is not None and tag(parent) == 'itemgroup' and parents.get(parent) is document and not parent.attrib,
                            'Conditional/inherited ProductProjects declaration requires source review')
                    all_product_declarations.append(dict(path=name, attributes=node.attrib, **fingerprint(raw)))
        if name not in products and any(tag(node) == 'xplatproject' for node in ET.fromstring(raw).iter()): inherited.append(name)
    require(len(all_product_declarations) == 1 and not inherited,
            'ProductProjects overrides or inherited XPLAT declarations require source review: ' + repr(inherited))
    records, selected = [], []
    originals = destination / 'original-projects'
    for name in products:
        raw = original(name)
        declaration = properties(ET.fromstring(raw), 'XPLATProject')
        include = declaration == ['true']
        records.append(dict(path=name, declarations=declaration, included=include, **fingerprint(raw)))
        if include: selected.append(name)
        path = originals / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
    require(selected, 'Original XPLAT selection is empty')
    root = ET.Element('Project', DefaultTargets='RestoreXPLAT;BuildXPLAT;PackXPLAT')
    ET.SubElement(root, 'Import', Project='$(MSBuildThisFileDirectory)build.proj')
    target = ET.SubElement(root, 'Target', Name='GetXPLATProjects')
    group = ET.SubElement(target, 'ItemGroup')
    for name in selected: ET.SubElement(group, 'XPLATProjects', Include='$(MSBuildThisFileDirectory)../' + name)
    ET.indent(root, space='  ')
    raw_driver = ET.tostring(root, encoding='utf-8', xml_declaration=True) + b'\n'
    driver = source / 'build/cbodotnet-xplat-source.proj'
    require(not driver.exists(), 'Fresh derived NuGet5 graph driver required')
    driver.write_bytes(raw_driver)
    (destination / driver.name).write_bytes(raw_driver)
    for name in ['build/common.project.props', 'build/common.targets', 'build/build.proj']:
        path = destination / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(original(name))
    document = dict(schemaVersion=1, kind='downstream-derived-nuget5-original-xplat-selection', sourceCommit=COMMIT,
        originalProductDeclarations=all_product_declarations, inheritedXplatDeclarations=inherited,
        productCandidates=records, selectedProjects=selected, selectedCount=len(selected), originalCandidateCount=len(products),
        driver=dict(path=driver.name, **fingerprint(raw_driver)),
        selector='Original GetXPLATProject condition: unconditional XPLATProject=true; absent/false excluded',
        conditionalOrInheritedDeclarationsAccepted=False, originalRestoreBuildPackBodiesUnchanged=True,
        originalFrameworkDefaultsUnchanged=True, originalFullRootGraphClaimed=False,
        qualificationAllowed=False, sourceAdmissionAllowed=False)
    (destination / 'origin.json').write_bytes((json.dumps(document, indent=2) + '\n').encode())
    return driver, document
