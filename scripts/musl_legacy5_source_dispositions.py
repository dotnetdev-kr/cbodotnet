"""Derive SDK5 per-path source decisions while retaining raw emitter unknowns.

This is the imported-source part of A5. It invokes the distinct validators;
an independent source correspondence is kept separate from actual package
consumption, compiler execution, worker and whole-release admission gates.
"""
import copy
import hashlib
import json
from pathlib import Path
import tarfile
import zipfile

import musl_legacy5_component_evidence as CE
import musl_legacy5_construction_inputs as CONSTRUCTION
import musl_legacy5_framework_inputs as F
import musl_legacy5_msbuild_resources as L
import musl_legacy5_embedded_source_inputs as E
import musl_legacy5_newtonsoft_source_inputs as J
import musl_legacy5_cecil_source_inputs as C
import musl_legacy5_unsafe_source_inputs as U
import musl_legacy5_css_source_inputs as S
import musl_legacy5_translation_inputs as T
import musl_legacy5_compiler_source_inputs as COMPILERS

B = CE.B
require, portable = B.require, B.portable
COUNTS = dict(framework=114, localization=56, embedded=27, newtonsoft=3, cecil=3, unsafe=2, css=1, translations=286)


def fingerprint(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), sha512=hashlib.sha512(raw).hexdigest())


def package_pins():
    groups = dict(framework=[F.policy()['package']], localization=[L.policy()['package']],
        embedded=list(E.policy()['packages'].values()), newtonsoft=list(J.policy()['packages'].values()),
        cecil=[C.policy()['package']], unsafe=[U.policy()['package']], css=list(S.policy()['packages'].values()))
    pins, owners = {}, {}
    for name, rows in groups.items():
        owners[name] = []
        for row in rows:
            fp = row.get('fingerprint', row); fp = {key: fp[key] for key in CE.FP}; sha = fp['sha256']
            require(sha not in pins or pins[sha] == fp, 'One original SDK5 source-package fingerprint per SHA required')
            pins[sha] = fp; owners[name].append(sha)
    return pins, owners


def validate_source_leaves(release, record, manifest, inputs):
    """Caller must first verify the complete combined used-source packet."""
    release = Path(release)
    require(record.get('sdkVersion') == CE.SDK and set(inputs) == {'packages', 'newtonsoftDistributions', 'originalSdkComparison'},
            'Exact SDK5 source-correspondence input roles required')
    pins, owners = package_pins(); require(set(inputs['packages']) == set(pins), 'All and only the closed SDK5 source-correspondence packages are required')
    packages = {}
    for sha, descriptor in inputs['packages'].items():
        require(set(descriptor) == {'path', *CE.FP} and all(descriptor[key] == pins[sha][key] for key in CE.FP), 'Exact SDK5 canonical source-package descriptor required')
        packages[sha] = B.checked(release, descriptor)
    distribution_policy = J.policy()['distributions']; require(set(inputs['newtonsoftDistributions']) == set(distribution_policy), 'Both original Json.NET publisher distributions required')
    require(all(set(descriptor) == {'path', *CE.FP} for descriptor in inputs['newtonsoftDistributions'].values())
            and set(inputs['originalSdkComparison']) == {'path', *CE.FP}, 'Closed SDK5 original distribution/comparison descriptors required')
    distributions = {version: B.checked(release, descriptor) for version, descriptor in inputs['newtonsoftDistributions'].items()}
    one = lambda name: packages[owners[name][0]]
    selected = lambda name: {sha: packages[sha] for sha in owners[name]}
    leaves = dict(framework=F.validate(release, manifest, one('framework')),
        localization=L.validate(release, manifest, one('localization')), embedded=E.validate(release, manifest, selected('embedded')),
        newtonsoft=J.validate(release, manifest, selected('newtonsoft'), distributions), cecil=C.validate(release, manifest, one('cecil')),
        unsafe=U.validate(release, manifest, one('unsafe')), css=S.validate(release, manifest, selected('css')),
        translations=T.validate_translation_data(release, record, manifest, inputs['originalSdkComparison']))
    derived = COMPILERS.validate(release, manifest, record, inputs['originalSdkComparison'])
    return leaves, derived


def source_catalog(leaves):
    require(set(leaves) == set(COUNTS), 'Every distinct SDK5 imported source validator must execute')
    catalog = {}; framework = {row['path']: row for row in F.policy()['layout']}
    for validator, result in leaves.items():
        products = result.get('products'); require(isinstance(products, dict) and len(products) == COUNTS[validator], 'Closed SDK5 per-validator product cardinality required: ' + validator)
        for name, product in products.items():
            name = portable(name); fp = product.get('fingerprint', product); fp = {key: fp[key] for key in CE.FP}
            require(name not in catalog, 'One SDK5 source validator per shipping path required')
            row = dict(path=name, sourceValidator=validator, fingerprint=fp, sourceDataRoot=result.get('dataRoot'),
                sourceBasis=product.get('sourceBasis', result.get('sourceBasis', result.get('basis', result.get('kind', result.get('status'))))),
                sourceRoot=product.get('sourceRoot', result.get('sourceRoot')), sourceCommit=product.get('sourceCommit', result.get('sourceCommit')),
                allowedActualPackageMembers=copy.deepcopy(product.get('allowedPackageMembers', [])), actualDerivedCompilerContainerRequired=False)
            for key in ('gitSourceRoot', 'gitSourceCommit', 'publisherParentRoot', 'publisherParentCommit', 'independentPublisherRoot',
                        'independentPublisherCommit', 'canonicalPackageMember', 'observedDistributorImage', 'signatureAuthenticityValidated'):
                if key in product: row[key] = copy.deepcopy(product[key])
            if validator == 'framework':
                relative = name.removeprefix('sdk/' + CE.SDK + '/'); declared = framework.get(relative, framework.get(name))
                require(declared is not None, 'Exact SDK5 framework layout source row required')
                row['allowedActualPackageMembers'] = [dict(packageSha256=F.PACKAGE_SHA, member=declared['packageMember'])]
                row['sourceBasis'] = 'sdk5-direct-canonical-framework-and-original-sdk-copy-recipe'
            elif validator == 'localization':
                row['allowedActualPackageMembers'] = [dict(packageSha256=L.policy()['package']['sha256'], member='lib/netstandard1.3/' + name.removeprefix('sdk/' + CE.SDK + '/'))]
            elif validator == 'unsafe':
                row['actualDerivedCompilerContainerRequired'] = product['actualDerivedContainerMustBeValidatedByProducerContract']
                if not row['actualDerivedCompilerContainerRequired']: row['allowedActualPackageMembers'] = [copy.deepcopy(product['canonicalPackageMember'])]
            elif validator == 'translations':
                row['sourceDataRoot'] = T.ROOT_NAME; row['sourceBasis'] = 'original-sdk5-resource-only-import-with-literal-readable-data'
            for pair in row['allowedActualPackageMembers']:
                require(set(pair) == {'packageSha256', 'member'} and isinstance(pair['packageSha256'], str), 'Closed SDK5 actual supplier package/member pair required')
                portable(pair['member'])
            catalog[name] = row
    return catalog


def managed_input_fingerprints(release, record, proof):
    """Bind all PE/whole-package paths, including paths outside the SDK prefix."""
    release = Path(release); descriptor = CONSTRUCTION.validate_final_sdk_archive(record, proof); archive_path = B.checked(release, descriptor)
    values, seen = {}, set()
    with tarfile.open(archive_path, 'r|gz') as archive:
        for entry in archive:
            if entry.isdir(): continue
            name = portable(entry.name.removeprefix('./')); require(entry.isfile() and name not in seen, 'Unique ordinary final SDK5 input member required'); seen.add(name)
            with archive.extractfile(entry) as stream:
                prefix = stream.read(4)
                if not (prefix.startswith(b'MZ') or name.lower().endswith(('.dll', '.exe', '.nupkg'))): continue
                require(entry.size <= 128 * 1024**2, 'Bounded managed SDK5 input required'); raw = prefix + stream.read()
            fp = fingerprint(raw); require(name in proof['inventory'] and all(proof['inventory'][name][key] == fp[key] for key in ('bytes', 'sha256')), 'Actual managed SDK5 inventory differs')
            values[name] = fp
    installer = json.loads(B.checked(release, proof['installerBuildReplay']).read_bytes()); toolset = B.checked(release, {key: proof['artifacts']['toolset'][key] for key in ('path', *CE.FP)})
    transformed = set()
    with zipfile.ZipFile(toolset) as archive:
        for row in installer['transformations']:
            name = portable(row['archivePath']); require(name in values and name not in transformed and row['input'] == 'toolset'
                and row['outputSha256'] == values[name]['sha256'], 'Unique actual SDK5 pre-Crossgen source input required')
            raw = archive.read(portable(row['member'])); fp = fingerprint(raw); require(fp['sha256'] == row['inputSha256'], 'Actual SDK5 pre-Crossgen toolset member differs')
            values[name] = fp; transformed.add(name)
    return values


def _package_pair(release, proof, declared, fp):
    if declared.get('packagePath') is None or declared.get('packageMember') is None: return None
    package = CE.ordinary(Path(release) / portable(declared['packagePath'])); actual = CE.fingerprint(package)
    require(declared['packagePath'] == 'imported-inputs/' + actual['sha256'] + '.nupkg', 'Canonical retained actual SDK5 package path required')
    artifact = proof['artifacts'].get('package-' + actual['sha256'])
    require(artifact is not None and artifact.get('kind') == 'managed-package' and all(artifact[key] == actual[key] for key in CE.FP), 'Actual unchanged SDK5 managed package artifact required')
    member = portable(declared['packageMember'])
    with zipfile.ZipFile(package) as archive:
        require(member in archive.namelist() and archive.getinfo(member).file_size <= 128 * 1024**2, 'Actual bounded SDK5 package member required')
        require(fingerprint(archive.read(member)) == fp, 'Actual SDK5 shipping/pre-Crossgen bytes must equal their declared package member')
    return dict(packageSha256=actual['sha256'], member=member)


def derive_correspondence(release, proof, input_fingerprints, leaves, derived_compilers):
    """Return bounded evidence; missing supplier/source gates remain explicit."""
    require(proof.get('kind') == 'sdk5-musl-construction-proof' and proof.get('sdkVersion') == CE.SDK, 'Distinct raw SDK5 constructor evidence required')
    original_unknowns = copy.deepcopy(proof['unknowns']); catalog = source_catalog(leaves); rows = {row['path']: row for row in proof['managedShipping']}
    require(len(rows) == len(proof['managedShipping']), 'Unique raw SDK5 managed shipping declarations required')
    dispositions, pending = {}, []
    for name, source in catalog.items():
        fp = input_fingerprints.get(name)
        if fp != source['fingerprint']:
            pending.append(dict(kind='source-product-byte-or-presence', path=name)); continue
        declared = rows.get(name)
        value = copy.deepcopy(source); value.update(sourceCorrespondenceValidated=True, actualSupplierBindingValidated=False,
            rawEmitterDeclarationPresent=declared is not None, actualProducerConsumptionValidated=False)
        if source['sourceValidator'] == 'translations':
            require(declared is not None and declared['origin'] == 'imported-official-translation-data' and declared['sourceRoot'] == 'nuget'
                    and declared['sourceCommit'] == T.COMMIT and declared['packagePath'] is declared['packageMember'] is None,
                    'Exact original SDK5 imported translation declaration required'); value['actualSupplierBindingValidated'] = True
        else:
            if source['actualDerivedCompilerContainerRequired']:
                compiler = next(row for row in derived_compilers['packages'] if row['path'].startswith('Microsoft.Net.Compilers.Toolset.'))
                allowed = [dict(packageSha256=compiler['sha256'], member='tasks/netcoreapp3.1/bincore/System.Runtime.CompilerServices.Unsafe.dll')]
            else: allowed = source['allowedActualPackageMembers']
            if declared is not None:
                pair = _package_pair(release, proof, declared, fp); value['observedActualPackageMembers'] = [pair] if pair is not None else []
                value['actualSupplierBindingValidated'] = pair in allowed
            else:
                # The raw emitter deliberately omits source declarations it
                # could not prove. Derive byte suppliers from only the closed
                # validated pairs; retain their raw unknowns and never invent
                # an emitter row or a claim of producer Copy consumption.
                candidates = []
                for pair in allowed:
                    artifact = proof['artifacts'].get('package-' + pair['packageSha256'])
                    if artifact is None: continue
                    candidate = dict(packagePath=artifact['path'], packageMember=pair['member'])
                    candidates.append(_package_pair(release, proof, candidate, fp))
                value['observedActualPackageMembers'] = candidates
                value['actualSupplierBindingValidated'] = bool(candidates)
        if not value['actualSupplierBindingValidated']: pending.append(dict(kind='source-product-actual-supplier', path=name, validator=source['sourceValidator']))
        dispositions[name] = value
    pins, owners = package_pins(); resolutions, unresolved = [], []
    for index, unknown in enumerate(original_unknowns):
        if unknown['kind'] == 'unmapped-managed-source' and unknown.get('path') in dispositions and dispositions[unknown['path']]['actualSupplierBindingValidated']:
            resolutions.append(dict(rawUnknownIndex=index, rawUnknown=copy.deepcopy(unknown), dispositionPath=unknown['path']))
        elif unknown['kind'] == 'unmapped-package-source' and unknown.get('artifact', '').removeprefix('package-') in pins:
            sha = unknown['artifact'].removeprefix('package-'); artifact = proof['artifacts'][unknown['artifact']]
            require(artifact['kind'] == 'managed-package' and all(artifact[key] == pins[sha][key] for key in CE.FP), 'Original SDK5 canonical source package bytes must retain their raw kind and fingerprints')
            require(artifact['path'] == 'imported-inputs/' + sha + '.nupkg', 'Exact retained original SDK5 source-package path required')
            B.checked(Path(release), {key: artifact[key] for key in ('path', *CE.FP)})
            resolutions.append(dict(rawUnknownIndex=index, rawUnknown=copy.deepcopy(unknown), canonicalPackageSha256=sha,
                independentlyValidatedBy=[name for name, values in owners.items() if sha in values], rawRepositoryMetadataPreserved=True))
        else: unresolved.append(dict(rawUnknownIndex=index, rawUnknown=copy.deepcopy(unknown)))
    require(proof['unknowns'] == original_unknowns, 'Raw SDK5 emitter unknowns must never be deleted or rewritten')
    return dict(kind='sdk5-derived-imported-source-correspondence', sourceDispositions=dispositions, rawEmitterUnknowns=original_unknowns,
        independentlyResolvedRawUnknowns=resolutions, unresolvedRawUnknowns=unresolved, pendingSourceGates=pending,
        managedInputPathsHandledByThisPart=sorted(dispositions), managedInputPathsRequiringOtherGuards=sorted(set(input_fingerprints) - dispositions.keys()),
        remainingWholeProducerGates=['closed artifact roles and all input/source consumption', 'original compiler/source/installer/native/Reader worker guards',
            'native bootstrap compiler source closure', 'all remaining literal/reference/template/Arcade/App source inputs', 'all consumer checks and normal producer boundary'],
        wholeProducerSourceClosure=False, qualificationAllowed=False, sourceAdmissionAllowed=False)


def derive(release, record, manifest, proof, inputs):
    leaves, compilers = validate_source_leaves(release, record, manifest, inputs)
    actual_inputs = managed_input_fingerprints(release, record, proof)
    return derive_correspondence(release, proof, actual_inputs, leaves, compilers)
