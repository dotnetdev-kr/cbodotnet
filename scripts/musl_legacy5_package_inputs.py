"""SDK5 raw restored-package envelopes, independent of source dispositions.

Original repository metadata, including its absence, stays literal. A source
leaf may separately explain a package without changing this retained input.
This check proves neither restore/Copy execution nor whole source admission.
"""
import copy
import json
from pathlib import Path

import musl_legacy5_component_evidence as CE
import musl_legacy5_evidence as E

B=CE.B
require, portable=B.require,B.portable
FP=set(CE.FP)
ARTIFACT_FIELDS=FP|{'path','kind','sourceRoot','sourceCommit','sourceBasis','repository'}
RESTORED_FIELDS=FP|{'retained','cache','path','actualCacheRole','repository','actualCacheReferences'}


def validate(release, proof, roots, compiler):
    """Validate raw package bytes/metadata without resolving emitter unknowns."""
    release=Path(release)
    require(proof.get('kind')=='sdk5-musl-construction-proof' and proof.get('sdkVersion')==CE.SDK,
            'The distinct SDK5 construction proof is required')
    descriptor=proof.get('restoredInputs')
    require(isinstance(descriptor,dict) and set(descriptor)==FP|{'path'}, 'Closed SDK5 raw-restored report descriptor required')
    report=json.loads(B.checked(release,descriptor).read_bytes())
    require(report.get('schemaVersion')==1 and isinstance(report.get('packages'),list), 'Actual SDK5 raw-restored package inventory required')
    expected_built={}
    require(set(compiler)==set(CE.COMMITS), 'Every actual SDK5 component compiler proof is required')
    for component,validated in compiler.items():
        require(validated['proof'].get('component')==component and validated['proof'].get('sourceCommit')==CE.COMMITS[component],
                'Distinct actual SDK5 compiler package source required')
        for package in validated['proof']['packages']:
            if component=='sdk': continue
            sha=package['sha256']; require(sha not in expected_built,'One actual SDK5 built-package component per fingerprint required')
            expected_built[sha]=(component,{key:package[key] for key in CE.FP})
    observed={}
    for row in report['packages']:
        require(isinstance(row,dict) and set(row)==RESTORED_FIELDS, 'Closed SDK5 original restore observation required')
        sha=row['sha256']; name='imported-inputs/'+sha+'.nupkg'
        require(row['retained']==name and sha not in observed and portable(row['path'])==row['path']
                and '/' not in row['path'] and isinstance(row['cache'],str) and row['cache'].startswith('/')
                and isinstance(row['actualCacheRole'],str) and row['actualCacheRole']
                and isinstance(row['actualCacheReferences'],list) and row['actualCacheReferences'],
                'Unique canonical actual SDK5 raw package and cache observations required')
        package=B.checked(release,dict(path=name,**{key:row[key] for key in CE.FP}))
        metadata=E.nuspec_metadata(package); repository=metadata.find('{*}repository')
        original=dict(repository.attrib) if repository is not None else None
        require(row['repository']==original,'Actual SDK5 cache repository metadata must remain literal')
        observed[sha]=dict(path=name,**{key:row[key] for key in CE.FP},repository=original,
            packageId=metadata.findtext('{*}id'),packageVersion=metadata.findtext('{*}version'))
    unknowns=[]; artifacts={}
    for name,row in proof['artifacts'].items():
        if not name.startswith('package-'):
            require(row.get('kind')!='managed-package','SDK5 managed-package kind requires its canonical named role')
            continue
        sha=name.removeprefix('package-')
        require(set(row)==ARTIFACT_FIELDS and row.get('kind')=='managed-package' and sha in observed
                and row['sha256']==sha and all(row[key]==observed[sha][key] for key in ('path',*CE.FP))
                and row['repository']==observed[sha]['repository'], 'Original SDK5 package role/path/bytes/repository must remain literal')
        original=observed[sha]['repository']; commit=original.get('commit') if original is not None else None
        require(row['sourceCommit']==commit, 'SDK5 package source commit must equal its actual original repository metadata')
        if sha in expected_built:
            component,fp=expected_built[sha]
            require(all(row[key]==fp[key] for key in CE.FP) and row['sourceRoot']==component
                    and row['sourceCommit']==CE.COMMITS[component]
                    and row['sourceBasis']=='actual-compiler-bound-source-package', 'Actual SDK5 source-built package/compiler provenance required')
        else:
            candidates=[root for root,value in roots.items() if value.get('kind','git') in ('git','git-export') and value.get('commit')==commit]
            require(row['sourceBasis']=='original-package-repository'
                    and (row['sourceRoot'] in candidates if candidates and commit is not None else row['sourceRoot'] is None),
                    'SDK5 original package source root must follow unchanged repository metadata')
        if row['sourceRoot'] is None:
            unknowns.append(dict(kind='unmapped-package-source',artifact=name,id=observed[sha]['packageId'],
                version=observed[sha]['packageVersion'],originalRepository=copy.deepcopy(original)))
        artifacts[name]=copy.deepcopy(observed[sha])
    actual_unknowns=[row for row in proof['unknowns'] if row.get('kind')=='unmapped-package-source']
    canonical=lambda rows: sorted(json.dumps(row,sort_keys=True) for row in rows)
    require(canonical(actual_unknowns)==canonical(unknowns), 'Every raw SDK5 unmapped-package source observation must remain unchanged')
    return dict(kind='sdk5-original-restored-package-envelopes',restored={sha:{key:value[key] for key in ('path',*CE.FP)} for sha,value in observed.items()},
        packageArtifacts=artifacts,rawUnmappedPackageSources=copy.deepcopy(actual_unknowns),
        actualProducerConsumptionValidated=False,sourceAdmissionAllowed=False,qualificationAllowed=False)
