"""SDK5's exact imported NuGet translation data and readable resource inputs.

These are original resource-only satellites, not rebuilt primary assemblies.
Only neutral PE, resource, archive and XML decoders are shared with other SDKs.
"""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import xml.etree.ElementTree as ET

import musl_legacy5_component_evidence as CE

ROOT = Path(__file__).resolve().parents[1]
B = CE.B
require, portable = B.require, B.portable
FP = CE.FP
SDK, COMMIT = '5.0.214', 'd525b0e670f3b6cbd5c73a35f04730a9f658c852'
ROOT_NAME, ROLE = 'nuget-translation-data', 'actual-imported-translation-data-and-generated-readable-source'
SCHEMA_SOURCE = 'src/NuGet.Core/NuGet.Packaging/compiler/resources/nuspec.xsd'
SCHEMA_ORIGINAL = (10620, 'b233d67e3879393f0b7fc7a77ea61ae6cf5fe0a1b705c56114c496dcf073dc50')
SCHEMA_EMBEDDED = (10720, '833d53f51d6d492da6e4a5e815819f52cbae94c56488ec1e0d88c1130c1b29de')
COUNTS = dict(satellites=286, resources=637, strings=36231, emptySatellites=65)
EXTRACTOR_SHA256 = '0b2ac38e73bbd4671618076b7fea7f656bb6075db109f87e559fcd5233e53a31'


def policy():
    path = ROOT / 'scripts/musl-legacy5-nuget-resources.py'
    require(hashlib.sha256(CE.ordinary(path).read_bytes()).hexdigest() == EXTRACTOR_SHA256,
            'Exact tracked original SDK5 resource extraction worker required')
    spec = importlib.util.spec_from_file_location('sdk5_original_translation_extractor', path)
    worker = importlib.util.module_from_spec(spec); spec.loader.exec_module(worker)
    require(worker.SDK == SDK and worker.COMMIT == COMMIT and len(worker.CULTURES) == 13
            and len(worker.NAMES) == 20 and len(worker.relative_names()) == 286
            and worker.METADATA_CULTURES == {'zh-Hans': 'zh-HANS', 'zh-Hant': 'zh-HANT'},
            'The distinct original SDK5 translation extraction policy is required')
    return worker


def raw_fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def schema_tree(raw):
    require(b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'SDK5 schema DTD/entities are forbidden')
    text = raw.decode('utf-8'); require(text.count('{0}') == 3, 'Exact SDK5 schema namespace placeholder count required')
    root = ET.fromstring(text.replace('{0}', 'urn:cbodotnet:nuspec-namespace-placeholder'))
    require(root.tag == '{http://www.w3.org/2001/XMLSchema}schema', 'Original SDK5 XML schema root required')
    def canonical(node):
        exact = lambda value: value if value and value.strip() else ''
        return [node.tag, sorted(node.attrib.items()), exact(node.text), [[canonical(child), exact(child.tail)] for child in node]]
    return canonical(root)


def validate_schema_equivalence(pristine, embedded):
    require((len(pristine), hashlib.sha256(pristine).hexdigest()) == SCHEMA_ORIGINAL
            and (len(embedded), hashlib.sha256(embedded).hexdigest()) == SCHEMA_EMBEDDED,
            'Exact SDK5 original and generated schema bytes required')
    require(schema_tree(pristine) == schema_tree(embedded), 'SDK5 schema ordered qualified names/attributes/non-whitespace text differ')


def comparison_inventory(path, record, wanted):
    worker = policy(); actual = CE.fingerprint(CE.ordinary(path))
    require(record.get('sdkVersion') == SDK and record.get('architecture') in worker.SHA512
            and actual['sha512'] == worker.SHA512[record['architecture']], 'Exact independently pinned SDK5 original comparison archive required')
    files, captured, seen = [], {}, set()
    with tarfile.open(path, 'r|gz') as archive:
        for entry in archive:
            if entry.isdir(): continue
            name = portable(entry.name.removeprefix('./'))
            require(entry.isfile() and name not in seen, 'One ordinary original SDK5 comparison member per path required'); seen.add(name)
            files.append(dict(path=name, bytes=entry.size))
            if name in wanted:
                require(entry.size <= 2 * 1024**2, 'Bounded original SDK5 satellite or notice required')
                captured[name] = raw_fingerprint(archive.extractfile(entry).read())
    require(captured.keys() == wanted, 'Every exact SDK5 translation/omission/notice member must be present')
    require(not any(PurePosixPath(name).name.lower() in {'test.utility.dll', 'test.utility.exe'} for name in seen),
            'Original SDK5 contains a primary Test.Utility assembly; orphan omission is forbidden')
    return dict(archive=actual, files=files), captured


def satellite_identity(binary, claimed, relative, worker):
    culture = next(part for part in PurePosixPath(relative).parts if part in worker.CULTURES)
    metadata_culture = worker.METADATA_CULTURES.get(culture, culture)
    contract = PurePosixPath(relative).name == 'NuGet.VisualStudio.Contracts.resources.dll'
    token = 'b03f5f7f11d50a3a' if contract else '31bf3856ad364e35'
    require(set(claimed) == {'assemblyName', 'assemblyVersion', 'culture', 'fileVersion', 'productVersion',
                'publicKeyBase64', 'publicKeyToken', 'managedResourceOnly', 'emptySatellite', 'methodBodies',
                'extraTypes', 'fields', 'linkedResources', 'nativeImports'}
            and binary['culture'] == metadata_culture and binary['assemblyVersion'] == '5.9.1.8'
            and binary['publicKeyToken'] == token and binary['assemblyName'] + '.dll' == PurePosixPath(relative).name
            and all(claimed.get(key) == binary[key] for key in ('assemblyName', 'assemblyVersion', 'culture',
                'publicKeyBase64', 'publicKeyToken', 'nativeImports'))
            and claimed.get('managedResourceOnly') is True
            and all(type(claimed.get(key)) is int and claimed[key] == 0 for key in ('methodBodies', 'extraTypes', 'fields', 'linkedResources'))
            and claimed.get('emptySatellite') is (not binary['resources'])
            and claimed.get('fileVersion') == '' and claimed.get('productVersion') == '5.9.1.8',
            'Exact SDK5 satellite resource-only ABI, culture, strong name and missing file-version mode required')


def validate_translation_data(release, record, manifest, comparison):
    """Reparse actual PE resources and the complete authenticated SDK archive."""
    release = Path(release); worker = policy(); directory = release / 'reports/build/nuget-translation-data'
    origin = json.loads(CE.ordinary(directory / 'origin.json').read_bytes())
    require(record.get('sdkVersion') == SDK and record.get('architecture') in worker.SHA512
            and origin.get('schemaVersion') == 1 and origin.get('kind') == 'imported-official-nuget-translation-data'
            and origin.get('sdkVersion') == SDK and origin.get('architecture') == record['architecture']
            and origin.get('sourceRoot') == '/work/work/nuget' and origin.get('sourceCommit') == COMMIT and origin.get('sourceLicense') == 'Apache-2.0'
            and origin.get('cultures') == worker.CULTURES and origin.get('officialSdk', {}).get('sha512') == worker.SHA512[record['architecture']]
            and all(origin.get(key) is False for key in ('primaryNuGetAssembliesImported', 'nativeComponentsImported',
                'wholeSdkUsedAsProduct', 'translationsLocallySourceBuilt', 'qualificationAllowed', 'sourceAdmissionAllowed')),
            'Exact distinct SDK5 imported translation data identity required')
    roots = {row['name']: row for row in manifest['roots']}
    require(len(roots) == len(manifest['roots']) and roots.get('nuget', {}).get('commit') == COMMIT
            and roots['nuget']['kind'] in ('git', 'git-export') and roots['nuget'].get('role') == 'build-source'
            and not roots['nuget'].get('deleted') and not roots['nuget'].get('exclude')
            and roots.get(ROOT_NAME, {}).get('kind') == 'tree' and roots[ROOT_NAME].get('role') == ROLE
            and roots[ROOT_NAME].get('commit') is None and not roots[ROOT_NAME].get('exclude'),
            'Complete original SDK5 NuGet Git and distinct translation-data roots required')
    index = {}
    with (release / 'sources' / portable(manifest['index']['path'])).open() as stream:
        for line in stream:
            row = json.loads(line); name = portable(row['path'])
            if name.startswith(('nuget/', ROOT_NAME + '/')):
                require(name not in index, 'Duplicate SDK5 translation/source member'); index[name] = row
    def local(descriptor):
        path = B.checked(directory, descriptor); name = ROOT_NAME + '/' + descriptor['path']
        require(name in index and all(index[name][key] == descriptor[key] for key in FP), 'Complete actual SDK5 translation data must be archived')
        return path
    schema_proofs = origin.get('reviewedGeneratedStaticXml', [])
    require(len(schema_proofs) == 1, 'One exact SDK5 generated static NuGet schema disposition required'); schema = schema_proofs[0]
    require(set(schema) == {'sourcePath', 'sourceCommit', 'sourceByteIdentity', 'pristine', 'generatedEmbedded', 'namespaceSubstitution',
                'orderedQualifiedNamesAttributesAndNonWhitespaceTextEquivalent', 'onlyWhitespaceIndentNodesIgnored', 'dtdAndEntityDeclarationsRejected'}
            and schema['sourcePath'] == SCHEMA_SOURCE and schema['sourceCommit'] == COMMIT and schema['sourceByteIdentity'] is False
            and schema['namespaceSubstitution'] == dict(before='{0}', after='urn:cbodotnet:nuspec-namespace-placeholder', occurrencesEach=3)
            and all(schema[key] is True for key in ('orderedQualifiedNamesAttributesAndNonWhitespaceTextEquivalent',
                'onlyWhitespaceIndentNodesIgnored', 'dtdAndEntityDeclarationsRejected')), 'Exact reviewed SDK5 schema source contract required')
    pristine, embedded = local(schema['pristine']).read_bytes(), local(schema['generatedEmbedded']).read_bytes()
    require((len(pristine), hashlib.sha256(pristine).hexdigest()) == SCHEMA_ORIGINAL
            and (len(embedded), hashlib.sha256(embedded).hexdigest()) == SCHEMA_EMBEDDED,
            'Exact SDK5 original and generated schema bytes required')
    validate_schema_equivalence(pristine, embedded)
    source_schema = index.get('nuget/' + SCHEMA_SOURCE, {})
    require(all(source_schema.get(key) == raw_fingerprint(pristine)[key] for key in FP), 'SDK5 schema input must equal its actual original Git source')
    readable = json.loads(local(origin['readableResources']).read_bytes()); readable_by_path = {}
    require(isinstance(readable, list) and len(readable) == 286, 'All original SDK5 readable satellite rows required')
    for row in readable:
        require(isinstance(row.get('path'), str) and '/resources/' in row['path'], 'Actual SDK5 satellite reader path required')
        relative = portable(row['path'].rsplit('/resources/', 1)[1]); require(relative not in readable_by_path, 'Unique original SDK5 readable satellite path required')
        readable_by_path[relative] = row
    rows = origin.get('files', []); expected = set(worker.relative_names())
    require(len(rows) == len(expected) == 286 and {row['path'] for row in rows} == expected == readable_by_path.keys()
            and not any('Test.Utility' in name for name in expected), 'Exact complete SDK5 product satellite universe required')
    products, counts = {}, dict(satellites=0, resources=0, strings=0, emptySatellites=0)
    for row in rows:
        relative = portable(row['path']); path = CE.ordinary(directory / 'resources' / relative); fp = CE.fingerprint(path)
        require(all(row.get(key) == fp[key] for key in FP) and row.get('sdkMember') == 'sdk/' + SDK + '/' + relative
                and row.get('origin') == 'imported-official-translation-data'
                and all(index.get(ROOT_NAME + '/resources/' + relative, {}).get(key) == fp[key] for key in FP),
                'Actual SDK5 translation bytes/path differ from their archived inputs')
        binary = B.resource_only_pe(path.read_bytes()); satellite_identity(binary, row['assemblyMetadata'], relative, worker)
        data = readable_by_path[relative]
        require({key: value for key, value in data.items() if key not in ('path', 'resources')} == row['assemblyMetadata']
                and {r['name'] for r in data['resources']} == {r['name'] for r in binary['resources']}
                and len(data['resources']) == len(binary['resources']), 'Every original SDK5 embedded resource must have literal readable data')
        descriptions = []
        for resource in binary['resources']:
            raw, name = resource['data'], resource['name']; value = next(r for r in data['resources'] if r['name'] == name); sha = hashlib.sha256(raw).hexdigest()
            require(value.get('sha256') == sha, 'SDK5 readable resource must hash its actual embedded bytes')
            if raw[:4] == b'\xce\xca\xef\xbe':
                values = B.resource_strings(raw)
                require(value.get('format') == 'dotnet-string-table' and value.get('entries') == values,
                        'Literal original SDK5 resource keys, values and string fingerprints must agree')
                counts['strings'] += len(values)
            else:
                require(name == 'NuGet.Packaging.compiler.resources.nuspec.xsd' and raw == embedded
                        and value.get('format') == 'xml-schema' and value.get('text') == raw.decode('utf-8') and value.get('entries') == {},
                        'Only the exact reviewed SDK5 static schema may complement literal string tables')
            description = dict(name=name, sha256=sha, format=value['format'], entryCount=len(value['entries']))
            if value['format'] == 'xml-schema': description.update(sourcePath=SCHEMA_SOURCE, sourceByteIdentity=False, generatedSourcePath='static-xml-source-data/embedded-nuspec.xsd')
            descriptions.append(description); counts['resources'] += 1
        require(row.get('readableResources') == descriptions, 'Complete SDK5 literal resource description matrix required')
        products[row['sdkMember']] = fp; counts['satellites'] += 1; counts['emptySatellites'] += not binary['resources']
    require(counts == COUNTS, 'Exact SDK5 286 satellites, 637 resources, 36231 strings and 65 empty satellites required')
    inventory = json.loads(local(origin['originalSdkInventory']).read_bytes()); omissions = json.loads(local(origin['explicitOrphanTestOmissions']).read_bytes()); omitted = omissions.get('files', [])
    expected_omissions = {'sdk/' + SDK + '/' + culture + '/Test.Utility.resources.dll' for culture in worker.CULTURES}
    require(inventory.get('archive') == {key: origin['officialSdk'][key] for key in FP} and isinstance(inventory.get('files'), list)
            and len(inventory['files']) > 1000 and omissions.get('primaryTestUtilityAssemblies') == [] and len(omitted) == 13
            and {row['path'] for row in omitted} == expected_omissions, 'Exactly thirteen original orphan SDK5 test satellites require whole-archive absence proof')
    paths = {portable(row['path']): row for row in inventory['files']}
    require(len(paths) == len(inventory['files']) and not any(PurePosixPath(name).name.lower() in {'test.utility.dll', 'test.utility.exe'} for name in paths),
            'The full original SDK5 inventory must contain no primary Test.Utility assembly')
    for row in omitted:
        require(row['path'] in paths and paths[row['path']]['bytes'] == row['bytes']
                and re.fullmatch('[a-f0-9]{64}', row.get('sha256', '')) and re.fullmatch('[a-f0-9]{128}', row.get('sha512', ''))
                and row.get('reason') == 'Orphan unit-test fixture satellite; no primary Test.Utility assembly exists anywhere in the original SDK',
                'Exact original SDK5 orphan satellite identity and reason required')
    notices = origin.get('notices', []); notice_by_path = {row['path']: row for row in notices}
    notice_sources = {'licenses/nuget-source-LICENSE.txt': 'nuget/LICENSE.txt',
        'licenses/nuget-source-THIRD-PARTY-NOTICES.txt': 'nuget/THIRD-PARTY-NOTICES.txt',
        'licenses/original-NuGet.Localization.nuspec': 'nuget/src/NuGet.Core/NuGet.Localization/NuGet.Localization.nuspec'}
    expected_notices = set(notice_sources) | {'licenses/official-sdk-LICENSE.txt', 'licenses/official-sdk-ThirdPartyNotices.txt'}
    require(len(notices) == len(notice_by_path) == 5 and notice_by_path.keys() == expected_notices, 'All five original SDK5 SDK/NuGet license and package definition inputs required')
    for name, row in notice_by_path.items():
        local(row)
        if name in notice_sources:
            require(notice_sources[name] in index and all(index[notice_sources[name]].get(key) == row[key] for key in FP),
                    'SDK5 translation notices must be exact original NuGet source/license bytes')
    compared, original = comparison_inventory(B.checked(release, comparison), record,
        {row['sdkMember'] for row in rows} | expected_omissions | {'LICENSE.txt', 'ThirdPartyNotices.txt'})
    require(compared == inventory and compared['archive'] == {key: origin['officialSdk'][key] for key in FP},
            'Complete SDK5 original file inventory must be recomputed from the authenticated archive')
    for row in rows + omitted:
        require(original[row.get('sdkMember', row['path'])] == {key: row[key] for key in FP}, 'SDK5 translation/omission byte identity differs from the exact original archive member')
    for name in ('LICENSE.txt', 'ThirdPartyNotices.txt'):
        require(original[name] == {key: notice_by_path['licenses/official-sdk-' + name][key] for key in FP}, 'SDK5 original archive notice bytes differ')
    require(CE.ordinary(directory / 'resource-reader.cs').read_bytes() == worker.DRIVER.encode(), 'Actual SDK5 translation inspection source must equal the tracked original worker source')
    allowed = {'origin.json', 'resource-reader.cs', 'reader-build.log', 'reader-execution.log', 'readable-resources.json',
        'official-sdk-file-inventory.json', 'omitted-orphan-test-satellites.json', schema['pristine']['path'], schema['generatedEmbedded']['path']}
    allowed |= set(notice_by_path) | {'resources/' + name for name in expected}
    actual_tree = {}
    for path in directory.rglob('*'):
        require(not path.is_symlink(), 'Linked SDK5 translation inputs are forbidden')
        if path.is_file(): actual_tree[path.relative_to(directory).as_posix()] = CE.fingerprint(path)
    require(actual_tree.keys() == allowed and roots[ROOT_NAME]['files'] == len(actual_tree), 'Closed complete original SDK5 translation data tree required')
    indexed_tree = {name[len(ROOT_NAME) + 1:]: {key: row[key] for key in FP} for name, row in index.items() if name.startswith(ROOT_NAME + '/')}
    require(indexed_tree == actual_tree, 'Every SDK5 translation data byte must occur in the source index')
    seen = set()
    with tarfile.open(release / 'sources' / portable(manifest['archive']['path']), 'r|gz') as archive:
        for entry in archive:
            if not entry.name.startswith(ROOT_NAME + '/'): continue
            name = entry.name[len(ROOT_NAME) + 1:]
            require(entry.isfile() and name in actual_tree and name not in seen and entry.size == actual_tree[name]['bytes']
                    and entry.size <= 64 * 1024**2 and raw_fingerprint(archive.extractfile(entry).read()) == actual_tree[name],
                    'Complete actual SDK5 translation data source archive required'); seen.add(name)
    require(seen == actual_tree.keys(), 'No original SDK5 translation data may be omitted from its source archive')
    return dict(status='passed-sdk5-original-resource-only-translation-source', products=products, counts=counts,
        sourceRoot='nuget', sourceCommit=COMMIT, dataRoot=ROOT_NAME, importedOfficialData=True,
        translationsLocallySourceBuilt=False, originalTranslationAuthoringFilesClaimed=False,
        qualificationAllowed=False, sourceAdmissionAllowed=False)
