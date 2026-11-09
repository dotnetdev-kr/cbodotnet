"""Add the reviewed SDK5 literal source leaf to per-path correspondence.

This is a bounded A5 building block. Canonical source correspondence, observed
supplier bytes and actual producer Copy/restore execution remain distinct.
Raw constructor kinds, repository metadata and unknowns are never rewritten.
"""
import copy
from pathlib import Path
import tarfile
import zipfile

import musl_legacy5_component_evidence as CE
import musl_legacy5_literal_source_inputs as LITERAL
import musl_legacy5_construction_inputs as CONSTRUCTION

B=CE.B
require,portable=B.require,B.portable
FP=set(CE.FP)


def input_fingerprints(release,record,proof):
    """Capture all126 literal products, including their three non-PE files."""
    expected=set(LITERAL.policy()['products']);actual={}
    final=CONSTRUCTION.validate_final_sdk_archive(record,proof)
    with tarfile.open(B.checked(Path(release),final),'r|gz')as archive:
        for entry in archive:
            name=entry.name.removeprefix('./')
            if name not in expected:continue
            require(entry.isfile()and name not in actual and entry.size<=128*1024**2,
                'Unique bounded ordinary SDK5 literal final product required')
            row=LITERAL.fingerprint(archive.extractfile(entry).read())
            require(name in proof['inventory']and all(proof['inventory'][name].get(key)==row[key]for key in('bytes','sha256')),
                'Actual SDK5 literal data/PE/package inventory differs')
            actual[name]=row
    require(actual.keys()==expected,'Every literal SDK5 reference/template/data final path required')
    return actual


def validate_source(release,record,manifest,inputs):
    """The caller must first authenticate the complete combined source packet."""
    policy=LITERAL.policy()
    require(record.get('sdkVersion')==CE.SDK and set(inputs)=={'packages'}
        and set(inputs['packages'])==set(policy['packages']), 'Closed nine-package SDK5 literal source input roles required')
    packages={}
    for sha,row in inputs['packages'].items():
        require(set(row)=={'path',*FP}and {key:row[key]for key in FP}==policy['packages'][sha]['fingerprint'],
            'Exact retained canonical SDK5 literal source package descriptor required')
        packages[sha]=B.checked(Path(release),row)
    return LITERAL.validate(release,manifest,packages)


def source_catalog(validated):
    policy=LITERAL.policy();products=validated.get('products',{})
    expected={name:dict(row,sourceBasis='closed-original-package-and-distinct-preferred-source-recipe')for name,row in policy['products'].items()}
    require(validated.get('kind')==LITERAL.KIND and validated.get('dataRoot')==LITERAL.ROOT_NAME
        and products==expected and len(products)==126, 'All126 exact reviewed SDK5 literal source products required')
    result={}
    for name,row in products.items():
        name=portable(name);sha=row['packageSha256'];member=row['member'];package=policy['packages'][sha]
        require(member is None or portable(member)==member,'Exact SDK5 canonical literal source package member required')
        require(row['fingerprint']==(package['fingerprint']if member is None else package['members'][member]),
            'SDK5 literal product must retain its exact original canonical package/member bytes')
        result[name]=dict(path=name,sourceValidator='literal',fingerprint=copy.deepcopy(row['fingerprint']),
            sourceDataRoot=LITERAL.ROOT_NAME,sourceRoot=LITERAL.ROOT_NAME,sourceCommit=None,
            sourceBasis=row['sourceBasis'],sourceRole=row['sourceRole'],
            canonicalPackageMember=dict(packageSha256=sha,member=member),
            originalRepository=copy.deepcopy(package['originalRepository']),
            publisherCompilerExecutionClaimed=False,localBuildClaimed=False)
    return result


def actual_package_artifact(release,proof,sha):
    pinned=LITERAL.policy()['packages'][sha]
    artifact=proof['artifacts'].get('package-'+sha)
    require(artifact is not None and artifact.get('kind')=='managed-package'
        and artifact.get('path')=='imported-inputs/'+sha+'.nupkg'
        and all(artifact.get(key)==pinned['fingerprint'][key]for key in FP)
        and artifact.get('repository')==pinned['originalRepository'],
        'Literal SDK5 supplier must retain its canonical named raw package/kind/bytes/repository')
    package=B.checked(Path(release),{key:artifact[key]for key in('path',*CE.FP)})
    return package,artifact


def actual_supplier(release,proof,source):
    pair=source['canonicalPackageMember'];sha=pair['packageSha256'];member=pair['member']
    package,artifact=actual_package_artifact(release,proof,sha)
    return _member_supplier(source,package,artifact)


def _member_supplier(source,package,artifact):
    member=source['canonicalPackageMember']['member']
    if member is None:actual=CE.fingerprint(package)
    else:
        with zipfile.ZipFile(package)as archive:
            require(archive.namelist().count(member)==1 and archive.getinfo(member).file_size<=128*1024**2,
                'Unique bounded actual SDK5 literal supplier member required')
            actual=LITERAL.fingerprint(archive.read(member))
    require(actual==source['fingerprint'],'Actual SDK5 literal supplier member and preferred-source product differ')
    return dict(package={key:artifact[key]for key in('path',*CE.FP)},member=member,
        rawSourceRoot=artifact['sourceRoot'],rawSourceCommit=artifact['sourceCommit'],
        originalRepository=copy.deepcopy(artifact['repository']))


def combine_correspondence(proof,base,additions,package_sources):
    """Compose explanations by raw index; preserve every original unknown row."""
    raw=copy.deepcopy(proof['unknowns'])
    require(base.get('rawEmitterUnknowns')==raw,'SDK5 source correspondence must retain identical original raw unknowns')
    products=copy.deepcopy(base['sourceDispositions'])
    require(not(products.keys()&additions.keys()),'Distinct SDK5 literal and prior per-path source roles required')
    require(all(row.get('sourceCorrespondenceValidated')is True and row.get('actualSupplierBindingValidated')is True
        and row.get('actualProducerConsumptionValidated')is False for row in additions.values()),
        'Literal source explanations require verified supplier correspondence without a producer-consumption claim')
    products.update(copy.deepcopy(additions))
    resolutions=copy.deepcopy(base['independentlyResolvedRawUnknowns']);resolved={row['rawUnknownIndex']for row in resolutions}
    require(len(resolved)==len(resolutions)and all(type(index)is int and 0<=index<len(raw)for index in resolved),
        'Unique exact original SDK5 raw unknown resolution indexes required')
    require(all(row.get('rawUnknown')==raw[row['rawUnknownIndex']]for row in resolutions),
        'Prior SDK5 resolution explanations must preserve the exact original indexed raw unknown')
    for index,unknown in enumerate(raw):
        if index in resolved:continue
        if unknown.get('kind')=='unmapped-managed-source'and unknown.get('path')in additions:
            resolutions.append(dict(rawUnknownIndex=index,rawUnknown=copy.deepcopy(unknown),dispositionPath=unknown['path']))
            resolved.add(index)
        elif unknown.get('kind')=='unmapped-package-source'and unknown.get('artifact','').removeprefix('package-')in package_sources:
            sha=unknown['artifact'].removeprefix('package-')
            resolutions.append(dict(rawUnknownIndex=index,rawUnknown=copy.deepcopy(unknown),canonicalPackageSha256=sha,
                independentlyValidatedBy=['literal'],rawRepositoryMetadataPreserved=True))
            resolved.add(index)
    unresolved=[dict(rawUnknownIndex=index,rawUnknown=copy.deepcopy(row))for index,row in enumerate(raw)if index not in resolved]
    require(proof['unknowns']==raw,'SDK5 literal integration may not delete or rewrite raw constructor unknowns')
    return dict(kind='sdk5-imported-and-literal-source-correspondence',sourceDispositions=products,rawEmitterUnknowns=raw,
        independentlyResolvedRawUnknowns=resolutions,unresolvedRawUnknowns=unresolved,
        actualProducerConsumptionValidated=False,wholeProducerSourceClosure=False,qualificationAllowed=False,sourceAdmissionAllowed=False)


def derive(release,proof,input_fingerprints,validated_literal,base):
    require(proof.get('kind')=='sdk5-musl-construction-proof'and proof.get('sdkVersion')==CE.SDK,
        'Distinct original SDK5 constructor proof required for literal correspondence')
    catalog=source_catalog(validated_literal);additions={};suppliers={};package_sources={}
    verified={sha:actual_package_artifact(release,proof,sha)for sha in LITERAL.policy()['packages']if 'package-'+sha in proof['artifacts']}
    for name,source in catalog.items():
        require(input_fingerprints.get(name)==source['fingerprint'],
            'Actual final/pre-Crossgen SDK5 literal path must equal its exact preferred-source product: '+name)
        sha=source['canonicalPackageMember']['packageSha256']
        require(sha in verified,'Canonical SDK5 literal shipping supplier must be retained as an actual raw package')
        supplier=_member_supplier(source,*verified[sha]);suppliers[sha]=supplier
        additions[name]=dict(source,sourceCorrespondenceValidated=True,actualSupplierBindingValidated=True,
            actualProducerConsumptionValidated=False,rawEmitterDeclarationPresent=any(row.get('path')==name for row in proof['managedShipping']),
            observedActualPackageMembers=[copy.deepcopy(source['canonicalPackageMember'])],actualSupplier=supplier)
    # Arcade/NETStandard.Library and canonical embedded dependencies can be
    # build inputs without a whole-package shipping product. Resolve a raw
    # package unknown only if that actual raw artifact is present and rehashed.
    for sha,(path,artifact)in verified.items():
        package_sources[sha]=dict(path=artifact['path'],**{key:artifact[key]for key in CE.FP})
    combined=combine_correspondence(proof,base,additions,package_sources)
    return dict(combined,literalSourceLeaf=copy.deepcopy(validated_literal),literalProducts=126,
        literalCanonicalActualSupplierPackages=len(suppliers),
        literalActualRawPackageSources=package_sources,
        pendingSourceGates=copy.deepcopy(base.get('pendingSourceGates',[])),
        remainingWholeProducerGates=['actual original literal restore/Copy consumption and original importer/worker boundary',
            'all original generated-data, App, native/bootstrap and license gates',
            'one combined complete source packet and every aggregate A5/normal producer guard'])


def validate(release,record,manifest,proof,inputs,base):
    literal=validate_source(release,record,manifest,inputs)
    actual=input_fingerprints(release,record,proof)
    return derive(release,proof,actual,literal,base)
