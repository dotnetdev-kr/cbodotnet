"""SDK6 exact original resource-only translation source contract.

The neutral PE/resource decoders are shared. SDK6 package ABI, original SDK
archive hashes and corresponding NuGet commit are explicit and independent.
"""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/filename)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
B=module('sdk6_resource_neutral_binary_parsers','musl_legacy_admission.py')
require,load,checked,fingerprint,portable=B.require,B.load,B.checked,B.fingerprint,B.portable
resource_only_pe,resource_strings,validate_schema_equivalence,source_member=B.resource_only_pe,B.resource_strings,B.validate_schema_equivalence,B.source_member
P=B.P
FP={'bytes','sha256','sha512'}
SDK='6.0.136'
COMMIT='451e9bc27184dc49d04e975122c9e7189d525872'
COMPARISON_SHA512={
'aarch64':'2ccb4e58f9dfa0a09dce1687a60ae4911cf8c864abfc7d63cdc113bd228a253f9545d699e8709d1403ff28ce7cf8db0935e4796b05b0aa80eef6ae43d38b8537',
'x64':'a93ba846501707808c6b8ea51aa763faf82cc215325aa310aa05d084caebd2c40f74048b384624a73988ba418bf72a71b57883c2a05a0a087a112d2c26b4266d'}

def comparison_sdk_inventory(path, record, wanted):
    actual = fingerprint(path)
    require(record['sdkVersion'] == SDK and actual['sha512'] == COMPARISON_SHA512[record['architecture']],
            'Retained original SDK comparison archive identity differs')
    files, captured = [], {}
    seen = set()
    with tarfile.open(path, 'r|gz') as archive:
        for entry in archive:
            if entry.isdir():
                continue
            name = portable(entry.name.removeprefix('./'))
            require(entry.isfile() and name not in seen, 'Comparison SDK must have one ordinary member per path')
            seen.add(name)
            files.append(dict(path=name, bytes=entry.size))
            if name in wanted:
                require(entry.size <= 2 * 1024**2, 'Comparison translation/notice member exceeds its bound')
                raw = archive.extractfile(entry).read()
                captured[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())
    require(set(captured) == set(wanted), 'An exact original SDK translation/omission/notice member is absent')
    return dict(archive=actual, files=files), captured

def validate_translation_data(release, record, source_manifest):
    policy = module('legacy_admission_translation_policy', 'musl-legacy6-nuget-resources.py')
    directory = release / 'reports/build/nuget-translation-data'
    origin = load(directory / 'origin.json')
    require(origin.get('schemaVersion') == 1 and origin.get('kind') == 'imported-official-nuget-translation-data'
            and origin.get('sdkVersion') == record['sdkVersion'] and origin.get('architecture') == record['architecture']
            and origin.get('sourceCommit') == COMMIT
            and origin.get('sourceLicense') == 'Apache-2.0' and origin.get('cultures') == list(P.SOURCE_CULTURES)
            and all(origin.get(key) is False for key in ('primaryNuGetAssembliesImported', 'nativeComponentsImported',
                'wholeSdkUsedAsProduct', 'translationsLocallySourceBuilt', 'qualificationAllowed', 'sourceAdmissionAllowed'))
            and origin.get('officialSdk', {}).get('sha512') == policy.SHA512[record['architecture']],
            'Exact resource-only NuGet product translation input identity required')
    index = {}
    with (release / 'sources' / source_manifest['index']['path']).open() as stream:
        for line in stream:
            row = json.loads(line)
            index[row['path']] = row
    roots = {root['name']: root for root in source_manifest['roots']}
    require('nuget-translation-data' in roots and roots['nuget-translation-data'].get('kind') == 'tree',
            'Complete readable imported translation data must be retained as used sources')
    source_schemas = {row['sha256'] for name, row in index.items() if name.startswith('nuget/') and name.endswith('.xsd')}
    canonical_source = None
    def local(descriptor):
        path = checked(directory, descriptor)
        relative = 'nuget-translation-data/' + descriptor['path']
        require(relative in index and all(index[relative].get(key) == descriptor[key] for key in FP),
                'Translation data/notice is absent from the complete source archive')
        return path
    schema_proofs = origin.get('reviewedGeneratedStaticXml', [])
    require(len(schema_proofs) == 1, 'One closed reviewed generated NuGet schema proof required')
    schema = schema_proofs[0]
    require(set(schema) == {'sourcePath', 'sourceCommit', 'sourceByteIdentity', 'pristine', 'generatedEmbedded',
                'namespaceSubstitution', 'orderedQualifiedNamesAttributesAndNonWhitespaceTextEquivalent',
                'onlyWhitespaceIndentNodesIgnored', 'dtdAndEntityDeclarationsRejected'}
            and schema['sourceCommit'] == COMMIT and schema['sourceByteIdentity'] is False
            and schema['namespaceSubstitution'] == dict(before='{0}', after='urn:cbodotnet:nuspec-namespace-placeholder', occurrencesEach=3)
            and all(schema[key] is True for key in ('orderedQualifiedNamesAttributesAndNonWhitespaceTextEquivalent',
                                                   'onlyWhitespaceIndentNodesIgnored', 'dtdAndEntityDeclarationsRejected')),
            'NuGet generated schema disposition differs')
    pristine_schema = local(schema['pristine']).read_bytes()
    embedded_schema = local(schema['generatedEmbedded']).read_bytes()
    validate_schema_equivalence(pristine_schema, embedded_schema)
    original_schema = index.get('nuget/' + portable(schema['sourcePath']), {})
    require(original_schema.get('bytes') == len(pristine_schema)
            and original_schema.get('sha256') == hashlib.sha256(pristine_schema).hexdigest(),
            'NuGet schema proof does not correspond to complete pinned source bytes')
    readable = load(local(origin['readableResources']))
    require(isinstance(readable, list) and len(readable) == 286, 'All 286 product satellite metadata rows required')
    readable_by_path = {}
    for item in readable:
        require('/resources/' in item.get('path', ''), 'Readable satellite path differs')
        relative = item['path'].rsplit('/resources/', 1)[1]
        require(relative not in readable_by_path, 'Duplicate readable satellite metadata')
        readable_by_path[relative] = item
    expected = set(policy.relative_names())
    require(len(expected) == 286 and not any('Test.Utility' in name for name in expected), 'Reviewed product translation scope differs')
    rows = origin.get('files', [])
    require(len(rows) == 286 and {row['path'] for row in rows} == expected == set(readable_by_path),
            'A product satellite is missing or an orphan/test payload was included')
    products = {}
    for row in rows:
        relative = portable(row['path'])
        path = directory / 'resources' / relative
        fp = fingerprint(path)
        require(all(row.get(key) == value for key, value in fp.items())
                and row.get('sdkMember') == 'sdk/' + record['sdkVersion'] + '/' + relative
                and row.get('origin') == 'imported-official-translation-data', 'Actual translation satellite bytes differ')
        source_name = 'nuget-translation-data/resources/' + relative
        require(source_name in index and all(index[source_name].get(key) == value for key, value in fp.items()),
                'Actual translation satellite input is absent from the source archive')
        binary = resource_only_pe(path.read_bytes())
        culture = next(part for part in PurePosixPath(relative).parts if part in P.SOURCE_CULTURES)
        claimed = row['assemblyMetadata']
        contract = PurePosixPath(relative).name == 'NuGet.VisualStudio.Contracts.resources.dll'
        version, token = ('6.0.6.4', 'b03f5f7f11d50a3a') if contract else ('6.0.6.4', '31bf3856ad364e35')
        require(binary['culture'] == culture and binary['assemblyVersion'] == version and binary['publicKeyToken'] == token
                and binary['assemblyName'] + '.dll' == PurePosixPath(relative).name
                and all(claimed.get(key) == binary[key] for key in
                        ('assemblyName', 'assemblyVersion', 'culture', 'publicKeyBase64', 'publicKeyToken', 'nativeImports'))
                and claimed.get('managedResourceOnly') is True
                and all(claimed.get(key) == 0 for key in ('methodBodies', 'extraTypes', 'fields', 'linkedResources'))
                and claimed.get('emptySatellite') is (not binary['resources']), 'Satellite executable/ABI metadata differs from its actual PE')
        data = readable_by_path[relative]
        require({item['name'] for item in data['resources']} == {item['name'] for item in binary['resources']}
                and len(data['resources']) == len(binary['resources']), 'Readable satellite resource coverage differs')
        descriptions = []
        for resource in binary['resources']:
            raw, name = resource['data'], resource['name']
            value = next(item for item in data['resources'] if item['name'] == name)
            sha = hashlib.sha256(raw).hexdigest()
            require(value['sha256'] == sha, 'Readable resource hash differs from actual embedded bytes')
            if raw[:4] == b'\xce\xca\xef\xbe':
                require(value.get('format') == 'dotnet-string-table' and value.get('entries') == resource_strings(raw),
                        'Readable translation keys/values differ from actual intrinsic resource strings')
            else:
                require(name.endswith('.xsd') and value.get('format') == 'xml-schema'
                        and raw.decode('utf-8') == value.get('text') and value.get('entries') == {}
                        and b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper()
                        and ET.fromstring(raw.decode('utf-8').replace('{0}',
                            'urn:cbodotnet:nuspec-namespace-placeholder')).tag == '{http://www.w3.org/2001/XMLSchema}schema',
                        'Opaque embedded satellite data is forbidden')
                if sha not in source_schemas:
                    if canonical_source is None:
                        sources = [name for name, item in index.items() if name.startswith('nuget/') and name.endswith('.xsd')
                            and item['bytes'] == 10723 and item['sha256'] == '5d4226dd761e3854ed02d33de390713c4c9846238a1d16f4b5f38192545ea417']
                        require(sources, 'Exact corresponding pristine NuGet schema source is absent')
                        canonical_source = source_member(release, source_manifest, sources[0])
                    validate_schema_equivalence(canonical_source, raw)
                    require(any(name.startswith('nuget-translation-data/') and name.endswith('.xsd')
                                and item['bytes'] == 10822 and item['sha256'] == sha for name, item in index.items()),
                            'Generated equivalent NuGet schema must be retained explicitly as generated data')
            description = dict(name=name, sha256=sha, format=value['format'], entryCount=len(value['entries']))
            if value['format'] == 'xml-schema':
                declaration = next(item for item in row['readableResources'] if item['name'] == name)
                source_path = portable(declaration.get('sourcePath'))
                actual_source = index.get('nuget/' + source_path, {})
                if sha in source_schemas:
                    require(actual_source.get('sha256') == sha, 'Embedded schema source path differs')
                    description.update(sourcePath=source_path, sourceByteIdentity=True)
                else:
                    require(source_path == schema['sourcePath'], 'Generated schema must use its exact reviewed corresponding source')
                    description.update(sourcePath=source_path, sourceByteIdentity=False,
                                       generatedSourcePath='static-xml-source-data/embedded-nuspec.xsd')
            descriptions.append(description)
        require(row.get('readableResources') == descriptions, 'Satellite readable source inventory differs')
        products[row['sdkMember']] = fp
    inventory = load(local(origin['originalSdkInventory']))
    require(inventory.get('archive') == {key: origin['officialSdk'][key] for key in FP}
            and isinstance(inventory.get('files'), list) and len(inventory['files']) > 1000,
            'Whole exact official SDK file inventory is required for orphan omission')
    paths = {portable(row['path']): row for row in inventory['files']}
    require(len(paths) == len(inventory['files'])
            and not any(PurePosixPath(name).name.lower() in {'test.utility.dll', 'test.utility.exe'} for name in paths),
            'A primary Test.Utility assembly exists; omission is not authorized')
    omissions = load(local(origin['explicitOrphanTestOmissions']))
    omitted = omissions.get('files', [])
    expected_omissions = {'sdk/' + record['sdkVersion'] + '/' + culture + '/Test.Utility.resources.dll' for culture in P.SOURCE_CULTURES}
    require(omissions.get('primaryTestUtilityAssemblies') == [] and len(omitted) == 13
            and {row['path'] for row in omitted} == expected_omissions,
            'Only the exact thirteen orphan unit-test satellites may be omitted')
    for row in omitted:
        require(row['path'] in paths and paths[row['path']]['bytes'] == row['bytes']
                and re.fullmatch('[a-f0-9]{64}', row.get('sha256', ''))
                and re.fullmatch('[a-f0-9]{128}', row.get('sha512', ''))
                and row.get('reason') == 'Orphan unit-test fixture satellite; no primary Test.Utility assembly exists anywhere in the original SDK',
                'The explicit orphan-test omission bytes/reason differ')
    notices = origin.get('notices', [])
    require(notices and any('nuget-source-' in row['path'] and 'license' in row['path'].lower() for row in notices)
            and {'licenses/official-sdk-LICENSE.txt', 'licenses/official-sdk-ThirdPartyNotices.txt',
                 'licenses/original-NuGet.Localization.nuspec'} <= {row['path'] for row in notices},
            'Original NuGet and official SDK source/license notices are incomplete')
    for notice in notices:
        local(notice)
    compared_names = {row['sdkMember'] for row in rows} | expected_omissions | {'LICENSE.txt', 'ThirdPartyNotices.txt'}
    compared, original_members = comparison_sdk_inventory(
        release / 'reports/construction-inputs/original-sdk-comparison.tar.gz', record, compared_names)
    require(compared['archive'] == {key: origin['officialSdk'][key] for key in FP}
            and inventory == compared, 'Whole official SDK file inventory is not the actual retained archive')
    for row in rows:
        require(original_members[row['sdkMember']] == {key: row[key] for key in FP}, 'Translation bytes differ from the authenticated official SDK member')
    for row in omitted:
        require(original_members[row['path']] == {key: row[key] for key in FP}, 'Omitted orphan test satellite hashes differ from the actual official archive')
    for name in ('LICENSE.txt', 'ThirdPartyNotices.txt'):
        notice = next(row for row in notices if row['path'] == 'licenses/official-sdk-' + name)
        require(original_members[name] == {key: notice[key] for key in FP}, 'Original SDK notice bytes differ from their actual authenticated archive')
    return products
