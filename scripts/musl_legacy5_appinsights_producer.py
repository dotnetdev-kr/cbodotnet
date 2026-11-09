"""Explicit normal SDK5 caller for the finite external App reference bootstrap.

The full SDK route stays closed until its complete collection/admission contract
is installed. No prior private App or SDK output is accepted by this caller.
"""
import hashlib
from pathlib import Path
import time
import urllib.error
import urllib.request

import musl_legacy5_appinsights_reference_bootstrap as R
from release_catalog import anonymous_release_download_request, fresh_release_url

N=R.N
require=N.require


def _normal(producer):
    require(producer.sdk==N.SDK and producer.engine==N.P.DOCKER_ENGINE
        and producer.diagnostic is False and producer.diagnostic_ptrace is False,
        'Only the explicit normal Docker SDK5 producer may construct this App supplier')
    W,D,J=map(N.ordinary,(producer.workspace,producer.output,N.P.ROOT))
    require(all(a!=b and a not in b.parents and b not in a.parents
        for i,a in enumerate((W,D,J))for b in(W,D,J)[i+1:]),
        'Distinct normal SDK5 workspace, delivery and project required')
    return W,D,J


def _acquire(url,path,expected):
    """Keep failed inputs private; retry opening gateway failures only."""
    path=N.ordinary(path);require(not path.exists(),'Fresh exact App input acquisition required')
    github=url.startswith('https://github.com/')
    for attempt in range(3 if github else 1):
        request=urllib.request.Request(fresh_release_url(url,attempt)if github else url,
            headers={'User-Agent':'cbodotnet-sdk5-App-inputs','Accept':'application/octet-stream'})
        try:incoming=urllib.request.urlopen(request,timeout=90)
        except urllib.error.HTTPError as error:
            if not github or error.code not in(502,503,504):
                error.close();raise
            error.close()
            if attempt==2:
                incoming=urllib.request.urlopen(anonymous_release_download_request(url,
                    dict(size=expected['bytes'],sha256=expected['sha256'])),timeout=90)
                break
            time.sleep(2*(attempt+1))
        else:break
    with incoming,path.open('xb')as target:
        count=0
        while block:=incoming.read(65536):
            count+=len(block);require(count<=expected['bytes'],'Exact private App acquisition size exceeded')
            target.write(block)
    path.chmod(0o644);actual=N.fingerprint(path)
    require(all(actual[key]==value for key,value in expected.items()),'Whole original private App acquisition differs')
    return N.descriptor(path)


def prepare_inputs(producer):
    W,D,J=_normal(producer);strong,worker=N.original_validators();p=worker.policy()
    private=W/'private';private.mkdir(exist_ok=True)
    inputs=private/'appinsights-acquired';require(not inputs.exists(),'Fresh App acquisition directory required');inputs.mkdir()
    source=producer.clone('appinsights',p['source']['repository'],N.SOURCE)
    targets=producer.clone('appinsights-mono-targets',p['portableTargets']['repository'],p['portableTargets']['commit'])
    reference=_acquire(p['referenceZip']['url'],inputs/'reference.zip',p['referenceZip']['fingerprint'])
    comparison=_acquire(p['originalPackage']['url'],inputs/'original.nupkg',p['originalPackage']['officialPackage'])
    origin=R.policy()['referenceOrigin'];repository=origin['repository'].removeprefix('https://github.com/')
    notice_url='https://raw.githubusercontent.com/'+repository+'/'+origin['historicalMerge']+'/'+origin['noticePath']
    notice=_acquire(notice_url,inputs/'historical-reference-notice.txt',origin['notice'])
    R._notice(Path(notice['path']))
    value=dict(kind='normal-SDK5-fresh-App-supplier-inputs',source=str(source),targets=str(targets),
        reference=reference,comparison=comparison,historicalNotice=notice,
        privateInputsOutsideEntireDelivery=True,previousPrivateAppOrSdkOutputUsed=False)
    N.write(inputs/'acquired-inputs.json',value)
    return value


def build_supplier(producer):
    W,D,J=_normal(producer);inputs=W/'private/appinsights-acquired'
    acquired=N.read(inputs/'acquired-inputs.json');strong,worker=N.original_validators();p=worker.policy()
    require(acquired['kind']=='normal-SDK5-fresh-App-supplier-inputs'
        and acquired['source']==str(W/'work/appinsights')
        and acquired['targets']==str(W/'work/appinsights-mono-targets')
        and acquired['privateInputsOutsideEntireDelivery']is True
        and acquired['previousPrivateAppOrSdkOutputUsed']is False,'Exact fresh normal App supplier inputs required')
    for name,filename,pin in [('reference','reference.zip',p['referenceZip']['fingerprint']),
        ('comparison','original.nupkg',p['originalPackage']['officialPackage']),
        ('historicalNotice','historical-reference-notice.txt',R.policy()['referenceOrigin']['notice'])]:
        path=N.checked(inputs/filename,acquired[name]);require(all(N.fingerprint(path)[k]==v for k,v in pin.items()),'Original App input changed')
    prepare=N.read(D/'reports/prepare/identity.json')
    record={key:prepare[key]for key in N.IDENTITY}
    require(record['projectCommit']==producer.project and record['sdkVersion']==producer.sdk
        and record['architecture']==producer.args.arch and record['runId']==producer.args.run_id
        and record['runAttempt']==producer.args.run_attempt and record['buildId']==producer.args.build_id,
        'Actual producer identity must bind this new App stage')
    diagnostics=D/'reports/diagnostics'/('container-'+str(len(producer.commands)).zfill(4))
    context=R.normal_context(record,prepare,workspace=W,delivery=D,project=J,diagnostics=diagnostics,uid=producer.uid,gid=producer.gid)
    R.prepare_normal(Path(acquired['source']),inputs/'reference.zip',Path(acquired['targets']),inputs/'original.nupkg',
        J/'scripts/musl-legacy-reader',context=context,historical_notice=inputs/'historical-reference-notice.txt')
    R.execute_normal(context,producer=producer)
    stages=dict(prepare=N.read(D/'reports/stages/prepare.json'),build=dict(commands=producer.commands))
    bound=dict(context=context,record=record,prepare=prepare,stages=stages)
    attempt=Path(context['paths']['attempt'])
    host_roots={'/inputs':attempt/'inputs','/output':attempt/'output','/bootstrap':producer.boot5,'/inspector':producer.boot6}
    result=R.package_normal(attempt,host_roots,normal_context=bound)
    package=D/'reports/build/appinsights/product'/N.PACKAGE
    N.checked(package,result['supplierPackage'])
    target=N.ordinary(producer.feed/N.PACKAGE);require(not target.exists(),'No preseeded App supplier package permitted')
    raw=package.read_bytes()
    actual=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),sha512=hashlib.sha512(raw).hexdigest())
    require(actual=={key:result['supplierPackage'][key]for key in N.FP},'Actual compiled App package changed before feed publication')
    R.scan_content(raw,R._forbidden(attempt))
    with target.open('xb')as stream:stream.write(raw)
    target.chmod(0o644);require(N.fingerprint(target)==N.fingerprint(package),'Actual App feed supplier bytes differ')
    producer.appinsights_context=context
    producer.appinsights_supplier=result
    return dict(file=target.name,component='appinsights',sourceCommit=N.SOURCE,
        origin='genuine-normal-original-App5-source-build',retained=package.relative_to(D).as_posix(),**N.fingerprint(package))
