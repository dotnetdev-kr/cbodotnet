"""Prime SDK6's own component cache through a real offline NuGet restore."""
import base64
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import zipfile

PACKAGES = {name: '6.0.6-rc.4' for name in (
    'microsoft.build.nugetsdkresolver', 'nuget.build.tasks', 'nuget.build.tasks.console',
    'nuget.build.tasks.pack', 'nuget.commands', 'nuget.common', 'nuget.configuration',
    'nuget.credentials', 'nuget.dependencyresolver.core', 'nuget.frameworks',
    'nuget.librarymodel', 'nuget.packaging', 'nuget.packaging.core', 'nuget.projectmodel',
    'nuget.protocol', 'nuget.versioning', 'nuget.resolver', 'nuget.commandline.xplat',
    'nuget.packagemanagement')}
PACKAGES.update({'microsoft.testplatform.cli': '17.0.3-dev', 'microsoft.testplatform.build': '17.0.3-dev',
    'microsoft.build.localization': '17.0.4-cbodotnet.1'})


def require(value, message):
    if not value: raise ValueError(message)


def fingerprint(path):
    hashes = {k: hashlib.new(k) for k in ('sha256', 'sha512')}; size = 0
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            size += len(block)
            for digest in hashes.values(): digest.update(block)
    return dict(bytes=size, **{k: v.hexdigest() for k, v in hashes.items()})


def prepare(feed, destination):
    destination = Path(destination); require(not destination.exists(), 'Fresh SDK6 PackageDownload proof directory required')
    rows = []
    for path in sorted(Path(feed).glob('*.nupkg')):
        require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary exact source-built SDK6 package required')
        with zipfile.ZipFile(path) as archive:
            specs = [n for n in archive.namelist() if n.endswith('.nuspec')]; require(len(specs) == 1, 'One original source-built nuspec required')
            raw = archive.read(specs[0]); require(b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'Unsafe source-built package declaration')
            node = ET.fromstring(raw).find('{*}metadata'); identity, version = node.findtext('{*}id'), node.findtext('{*}version')
        require(re.fullmatch('[A-Za-z0-9_.-]+', identity) and PACKAGES.get(identity.lower()) == version
                and path.name.lower() == (identity + '.' + version + '.nupkg').lower(),
                'Exact genuine SDK6 component identity/version/file required')
        rows.append(dict(id=identity, version=version, file=path.name, **fingerprint(path)))
    require(len(rows) == 22 and {r['id'].lower(): r['version'] for r in rows} == PACKAGES,
            'All22 unique SDK6 source-built packages must be primed')
    destination.mkdir(parents=True)
    project = ET.Element('Project', Sdk='Microsoft.NET.Sdk'); props = ET.SubElement(project, 'PropertyGroup')
    ET.SubElement(props, 'TargetFramework').text = 'net6.0'; ET.SubElement(props, 'DisableImplicitFrameworkReferences').text = 'true'
    group = ET.SubElement(project, 'ItemGroup')
    for row in rows: ET.SubElement(group, 'PackageDownload', Include=row['id'], Version='[' + row['version'] + ']')
    ET.indent(project, space='  '); (destination / 'SourcePackageDownloads.csproj').write_bytes(ET.tostring(project, encoding='utf-8', xml_declaration=True) + b'\n')
    (destination / 'NuGet.Config').write_text('<configuration><packageSources><clear/><add key="exact-local-source-products" value="/work/inputs/bootstrap-feed"/></packageSources><fallbackPackageFolders><clear/></fallbackPackageFolders></configuration>\n')
    (destination / 'packages.json').write_text(json.dumps(dict(schemaVersion=1, sdkVersion='6.0.136', packages=rows), indent=2) + '\n')
    return rows


def validate(cache, packages, source='/work/inputs/bootstrap-feed'):
    require(source == '/work/inputs/bootstrap-feed' and len(packages) == 22
            and {r['id'].lower(): r['version'] for r in packages} == PACKAGES,
            'Exact SDK6 local-only cache priming component/source set required')
    checks = []
    for row in packages:
        directory = Path(cache) / row['id'].lower() / row['version'].lower()
        path = directory / (row['id'].lower() + '.' + row['version'].lower() + '.nupkg')
        require(path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)), 'Real ordinary NuGet-restored SDK6 package required')
        require(fingerprint(path) == {k: row[k] for k in ('bytes', 'sha256', 'sha512')}, 'SDK6 cache was populated from different same-version package bytes')
        metadata_path = directory / '.nupkg.metadata'; checksum = path.with_name(path.name + '.sha512')
        require(metadata_path.is_file() and checksum.is_file() and not metadata_path.is_symlink() and not checksum.is_symlink(), 'Actual NuGet restore metadata/checksum required')
        metadata = json.loads(metadata_path.read_text()); expected = base64.b64encode(bytes.fromhex(row['sha512'])).decode()
        require(metadata.get('version') == 2 and metadata.get('source') == source
                and metadata.get('contentHash') == expected and checksum.read_text().strip() == expected,
                'SDK6 local PackageDownload restore origin or content hash differs')
        checks.append(dict(id=row['id'], version=row['version'], sha256=row['sha256'], actualRestoreMetadata=metadata))
    return dict(status='passed', packages=checks, sdkVersion='6.0.136', source=source, network='none', metadataFabricated=False,
        originalNuGetPackageDownloadUsed=True, packageTypeCompatibilityOrDependencyGraphNotRewritten=True)
