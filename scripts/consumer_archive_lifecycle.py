"""Actual retained-revision/reinstall/removal evidence for Core3 archive v2.

This disposable-container gate does not install an official SDK package. It
records whether protected global roots are present or absent, and preserves
those observations, package state, provider trees and stock native libraries.
"""
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess

from consumer_archive import BRANDING, descriptor, encoded, identity, ordinary_file, payload_summary, require

INSTALL_ROOT=Path('/opt/cbodotnet-consumer-validation')
GLOBAL_PATHS=('/usr/bin/dotnet','/usr/share/dotnet','/usr/lib64/dotnet','/usr/lib/dotnet','/opt/dotnet','/opt/cbodotnet')
SCOPE='consumer-archive-installation-lifecycle'
SYSTEM_SCOPE='consumer-archive-preexisting-system-state'
TRANSITIONS=(2,3,2,3)
RPM_VOLATILE=('.rpm.lock','.dbenv.lock')


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def _container_guard(api):
    require(os.name=='posix' and os.geteuid()==0
        and (Path('/.dockerenv').is_file() or Path('/run/.containerenv').is_file()),
        'Archive lifecycle requires a disposable root Linux container')
    root=Path(api.INSTALL)
    require(root==INSTALL_ROOT and root.is_dir() and not any(path.is_symlink() for path in [root,*root.parents])
        and root.resolve()==root,'Archive lifecycle install root is not the exact ordinary owned container root')
    return root


def _owned(root,path,*,must_exist=True,symlink=False):
    path=Path(path)
    require(path.is_absolute() and str(PurePosixPath(path))==str(path) and '..' not in path.parts
        and path!=root and root in path.parents,'Archive lifecycle path escapes its owned container root')
    require(not any(parent.is_symlink() for parent in path.parents),'Archive lifecycle path has a symlinked parent')
    require(root in path.resolve(strict=False).parents,'Archive lifecycle resolved path escapes its owned root')
    if must_exist:require(path.exists() or path.is_symlink(),'Archive lifecycle owned path is missing')
    if not symlink:require(not path.is_symlink(),'Archive lifecycle directory is unexpectedly symlinked')
    return path


def _file_digest(path):
    value=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024**2),b''):value.update(block)
    return value.hexdigest()


def _entry(path):
    info=path.lstat()
    result=dict(mode=oct(stat.S_IMODE(info.st_mode)),uid=info.st_uid,gid=info.st_gid)
    if path.is_symlink():result.update(type='symlink',target=os.readlink(path))
    elif path.is_file():result.update(type='file',size=info.st_size,sha256=_file_digest(path))
    elif path.is_dir():result['type']='directory'
    else:raise ValueError('Unexpected protected filesystem object: '+str(path))
    return result


def _path_state(path,*,package_database=False):
    path=Path(path)
    if not path.exists() and not path.is_symlink():return dict(path=str(path),present=False)
    result=dict(path=str(path),present=True,**_entry(path))
    if path.is_symlink():
        target=path.resolve(strict=True)
        result['resolvedTarget']=_path_state(target,package_database=package_database)
    elif path.is_dir():
        rows=[]
        for child in sorted(path.rglob('*')):
            if package_database and (child.name in RPM_VOLATILE or child.name.endswith(('-shm','-wal','-journal'))):continue
            rows.append(dict(path=child.relative_to(path).as_posix(),**_entry(child)))
            require(len(rows)<=200000,'Protected tree exceeds the bounded archive audit inventory')
        result.update(entries=len(rows),inventorySha256=digest(rows),files=sum(row['type']=='file' for row in rows),
            links=sum(row['type']=='symlink' for row in rows))
    return result


def _package_state(api):
    if Path('/var/lib/dpkg/status').is_file():
        manager='dpkg';database=Path('/var/lib/dpkg')
        inventory=api.run(['dpkg-query','-W','-f=${binary:Package} ${Version} ${Architecture}\n'])
    else:
        manager='rpm'
        database=Path(api.run(['rpm','--eval','%{_dbpath}']).strip())
        require(database.is_absolute() and database.is_dir(),'RPM did not expose its authoritative package database')
        inventory=api.run(['rpm','-qa','--qf','%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE} %{ARCH}\n'])
    rows=sorted(inventory.splitlines());require(rows and all(rows),'Package inventory is unavailable')
    # Read-only RPM queries can create SQLite auxiliary/lock files. The main DB
    # bytes and complete package inventory are pinned; auxiliaries are explicit.
    return dict(manager=manager,inventorySha256=digest(rows),packageCount=len(rows),
        database=_path_state(database.resolve(strict=True),package_database=True),
        excludedVolatileNames=list(RPM_VOLATILE)+['*-shm','*-wal','*-journal'])


def _ldd_paths(output):
    """Read only glibc mapping lines, never absolute-prefix diagnostics."""
    require(not re.search(r'=>\s+not found(?:\s|$)',output),
            'Archive runtime dependency is missing during system capture')
    result=[]
    for line in output.splitlines():
        # Version warnings begin with the input ELF's absolute path too, but
        # do not end with a loaded-address field. Paths may contain spaces.
        match=re.fullmatch(r'\s*(?:\S+\s+=>\s+)?(/.+?)\s+\(0x[0-9A-Fa-f]+\)\s*',line)
        if match:result.append(match.group(1))
    return result


def _stock_libraries(payload,providers,runtime_env,api,root):
    inputs={Path(payload)/'dotnet'}
    inputs.update(path for path in (Path(payload)/'host/fxr').glob('*/libhostfxr.so') if path.is_file())
    # Audit the host/runtime and the mandatory Core3 HTTP path. Optional SDK
    # diagnostics (for example the LTTng trace provider) are not admitted here.
    for name in ('libhostpolicy.so','libcoreclr.so','System.Net.Http.Native.so'):
        inputs.update(path for path in (Path(payload)/'shared/Microsoft.NETCore.App').glob('*/'+name) if path.is_file())
    for provider in providers:
        inputs.update(path for path in (Path(provider)/'lib').iterdir() if path.is_file() and not path.is_symlink())
    paths=set();environment=dict(os.environ,**runtime_env)
    for binary in sorted(inputs):
        with binary.open('rb') as stream:magic=stream.read(4)
        require(magic==b'\x7fELF','Archive runtime native input is not an ELF file')
        result=subprocess.run(['ldd',str(binary)],env=environment,text=True,capture_output=True,timeout=30)
        combined=result.stdout+'\n'+result.stderr
        if result.returncode!=0:
            require('not a dynamic executable' in combined or 'statically linked' in combined,
                    'Cannot inventory archive runtime transitive dependencies: '+str(binary)+'\n'+combined)
            continue
        # Both streams are checked for missing dependencies; stdout alone
        # supplies successful mappings (stderr contains loader diagnostics).
        _ldd_paths(combined)
        for name in _ldd_paths(result.stdout):
            candidate=Path(name)
            if root in candidate.resolve(strict=True).parents:continue
            if any(candidate.resolve(strict=True)==Path(provider).resolve(strict=True)
                   or Path(provider).resolve(strict=True) in candidate.resolve(strict=True).parents for provider in providers):continue
            paths.add(candidate)
    require(paths,'No stock runtime or provider dependency paths were observed')
    return [str(path) for path in sorted(inputs)],[_path_state(path) for path in sorted(paths)]


def capture_system_state(plan,payload,runtime_env,api):
    root=_container_guard(api);_owned(root,payload)
    from consumer_archive_clean import roots
    providers=list(roots(plan).values())
    sentinel=_owned(root,root/'unrelated user state',must_exist=False)
    require(not sentinel.exists(),'The unrelated lifecycle sentinel must be fresh')
    sentinel.mkdir(mode=0o755);os.chown(sentinel,10001,10001)
    marker=sentinel/'keep.txt'
    api.user_run(['sh','-ec','printf "%s\\n" "unrelated user state: preserve through archive lifecycle" > "$1"',
                  'archive-lifecycle-sentinel',marker])
    require(marker.is_file() and marker.stat().st_uid==10001,'The unrelated sentinel is not an actual unprivileged user file')
    inputs,libraries=_stock_libraries(payload,providers,runtime_env,api,root)
    return dict(schemaVersion=1,scope=SYSTEM_SCOPE,sdkVersion=plan['sdkVersion'],architecture=plan['architecture'],
        officialPackageProvisioned=False,globalPaths=[_path_state(path) for path in GLOBAL_PATHS],
        providers=[_path_state(path) for path in providers],stockLibraries=libraries,libraryInputs=inputs,
        packages=_package_state(api),unrelatedSentinel=_path_state(sentinel),
        sentinelPurpose='deliberately-created-unrelated-user-file-for-qualification')


def _resnapshot(baseline,api):
    result=copy.deepcopy(baseline)
    for name in ('globalPaths','providers','stockLibraries'):
        result[name]=[_path_state(row['path']) for row in baseline[name]]
    result['unrelatedSentinel']=_path_state(baseline['unrelatedSentinel']['path'])
    result['packages']=_package_state(api)
    return result


def _inventory(tree,tools):
    rows=tools.snapshot(tree)
    return dict(sha256=digest(rows),entries=len(rows),files=sum(row[0]=='file' for row in rows.values()),
                links=sum(row[0]=='link' for row in rows.values()))


def _observe(command,tree,revision,plan,api):
    from consumer_archive_clean import roots
    response=api.user_result([command,'--version'],extra=roots(plan),clean=True)
    require(response.returncode==0 and response.stdout==plan['sdkVersion']+'\n'
        and response.stderr==BRANDING['displayName']+'\n','Retained archive selection version or branding changed')
    info=json.loads(api.user_run([command,'--cbodotnet-info'],extra=roots(plan),clean=True))
    expected=dict(identity(plan),packageRevision=revision)
    require(all(info.get(key)==value for key,value in expected.items())
        and info.get('sdkRoot')==str(tree/'payload') and info.get('qualifiedPayloadModified') is False,
        'Retained archive selection resolved another physical SDK or revision')
    return dict(revision=revision,root=str(tree),payload=str(tree/'payload'),versionStdout=response.stdout,
                brandingStderr=response.stderr,identity=info)


def qualify(plan,build,workspace,relocated,historical,baseline,api):
    root=_container_guard(api);tools=api.sdk_tools()
    current=_owned(root,relocated);previous=_owned(root,historical['root'])
    require(current.is_dir() and previous.is_dir() and current!=previous
        and current not in previous.parents and previous not in current.parents,'Both distinct retained archive roots are required')
    require(plan.get('archiveLauncherVersion')==2 and plan['packageRevision']==3,'Retained r2/r3 lifecycle requires exact archive contract 2 revision3')
    inventories=dict(r2=_inventory(previous,tools),r3=_inventory(current,tools))
    for tree in (previous,current):
        rows=tools.snapshot(tree/'payload')
        require(payload_summary({key:value for key,value in rows.items() if key not in build['additionalDirectories']})==build['qualifiedPayload'],
                'Retained archive lifecycle started with modified qualified SDK bytes')
    selected=_owned(root,root/'selected archive CLI',must_exist=False)
    require(not selected.exists() and not selected.is_symlink(),'Lifecycle selection path must be fresh')
    transitions=[]
    for revision in TRANSITIONS:
        tree=previous if revision==2 else current
        if selected.is_symlink():selected.unlink()
        require(not selected.exists(),'Lifecycle selection would replace an unrelated file')
        selected.symlink_to(tree/'cbodotnet')
        observation=_observe(selected,tree,revision,plan,api)
        transitions.append(dict(observation,linkTarget=os.readlink(selected)))
    require(inventories==dict(r2=_inventory(previous,tools),r3=_inventory(current,tools)),
            'Selection/rollback changed a retained archive tree')
    reinstall_parent=_owned(root,root/'reinstalled r3 archive',must_exist=False)
    artifact=ordinary_file(Path(workspace)/'build'/build['artifact']['name'])
    require(descriptor(artifact)==build['artifact'],'Reinstallation source archive differs from the actual qualified artifact')
    tools.extract_sdk(artifact,reinstall_parent)
    reinstalled=_owned(root,reinstall_parent/build['directory'])
    require({path.name for path in reinstall_parent.iterdir()}=={build['directory']},'Reinstall archive added another installation root')
    reinstalled_inventory=_inventory(reinstalled,tools)
    require(reinstalled_inventory==inventories['r3'],'Reinstallation changed wrapper, SDK, license or metadata bytes/modes/links')
    reinstalled_command=_observe(reinstalled/'cbodotnet',reinstalled,3,plan,api)
    require(_inventory(reinstalled,tools)==reinstalled_inventory,'Non-root reinstall execution changed installed archive files')
    reinstall=dict(root=str(reinstalled),artifact=descriptor(artifact),inventory=reinstalled_inventory,
        retainedInventory=inventories['r3'],identical=True,commandObservation=reinstalled_command)
    # Every recursive removal is preceded by a resolved, ordinary path check.
    removed=[]
    for tree in (previous,current,reinstalled):
        _owned(root,tree);require(tree.is_dir(),'Lifecycle removal requires an ordinary owned archive tree')
        shutil.rmtree(tree);require(not tree.exists() and not tree.is_symlink(),'Owned archive removal failed')
        removed.append(str(tree))
    _owned(root,selected,symlink=True)
    require(selected.is_symlink() and os.readlink(selected)==str(current/'cbodotnet'),'Lifecycle selector was substituted before removal')
    selected.unlink()
    from consumer_archive_clean import roots
    missing=api.user_result([selected,'--version'],extra=roots(plan),clean=True)
    require(missing.returncode!=0 and not missing.stdout,'Removed archive selection fell back to another SDK')
    after=_resnapshot(baseline,api)
    require(after==baseline,'Archive selection/reinstall/removal changed protected system or provider state')
    proof=dict(schemaVersion=1,scope=SCOPE,status='passed',sdkVersion=plan['sdkVersion'],architecture=plan['architecture'],
        userId=10001,network='none',officialPackageProvisioned=False,installRoot=str(root),
        selectionTransitions=transitions,retainedInventories=inventories,reinstall=reinstall,
        removal=dict(roots=removed,allAbsent=True,selectionRemoved=True,missingSelectionExitCode=missing.returncode,noHostOutput=True),
        systemBefore=baseline,systemAfter=after,systemStateUnchanged=True,providersUnchanged=True)
    validate_lifecycle_evidence(proof,plan)
    return proof


def _valid_inventory(value):
    return isinstance(value,dict) and re.fullmatch(r'[a-f0-9]{64}',value.get('sha256','')) and all(
        type(value.get(key)) is int and value[key]>=0 for key in ('entries','files','links')) and value['entries']>0 and value['entries']>=value['files']+value['links']


def _valid_owned(value,root):
    path=PurePosixPath(value)
    return path.is_absolute() and str(path)==value and '..' not in path.parts and path!=root and root in path.parents


def _valid_path_state(value,*,allow_absent=True,depth=0):
    if not isinstance(value,dict) or not PurePosixPath(value.get('path','')).is_absolute():return False
    if value.get('present') is False:return allow_absent and set(value)=={'path','present'}
    if value.get('present') is not True or not re.fullmatch(r'0o[0-7]{3,4}',value.get('mode','')):return False
    if not all(type(value.get(key)) is int and value[key]>=0 for key in ('uid','gid')):return False
    if value.get('type')=='file':return type(value.get('size')) is int and value['size']>=0 and bool(re.fullmatch(r'[a-f0-9]{64}',value.get('sha256','')))
    if value.get('type')=='symlink':return depth==0 and isinstance(value.get('target'),str) and bool(value['target']) and _valid_path_state(value.get('resolvedTarget'),allow_absent=False,depth=depth+1)
    return value.get('type')=='directory' and all(type(value.get(key)) is int and value[key]>=0 for key in ('entries','files','links')) and value['entries']>=value['files']+value['links'] and bool(re.fullmatch(r'[a-f0-9]{64}',value.get('inventorySha256','')))


def validate_lifecycle_evidence(proof,plan):
    require(proof.get('schemaVersion')==1 and proof.get('scope')==SCOPE and proof.get('status')=='passed'
        and proof.get('sdkVersion')==plan['sdkVersion'] and proof.get('architecture')==plan['architecture']
        and proof.get('userId')==10001 and proof.get('network')=='none' and proof.get('officialPackageProvisioned') is False
        and proof.get('installRoot')==str(INSTALL_ROOT),'Actual archive lifecycle proof is missing or has another target')
    root=PurePosixPath(proof['installRoot']);transitions=proof.get('selectionTransitions',[])
    require(len(transitions)==4 and [row.get('revision') for row in transitions]==list(TRANSITIONS),'Actual retained revision rollback sequence is incomplete')
    paths={}
    for row in transitions:
        revision=row['revision'];info=row.get('identity',{});tree=row.get('root','')
        require(_valid_owned(tree,root) and row.get('payload')==tree+'/payload'
            and row.get('linkTarget')==tree+'/cbodotnet' and row.get('versionStdout')==plan['sdkVersion']+'\n'
            and row.get('brandingStderr')==BRANDING['displayName']+'\n'
            and all(info.get(key)==value for key,value in dict(identity(plan),packageRevision=revision).items())
            and info.get('sdkRoot')==tree+'/payload' and info.get('qualifiedPayloadModified') is False,
            'Retained selection lacks actual numeric/identity/root binding')
        require(revision not in paths or paths[revision]==tree,'A retained revision changed physical roots during rollback')
        paths[revision]=tree
    require(paths[2]!=paths[3],'Lifecycle claims two revisions from one physical archive root')
    inventories=proof.get('retainedInventories',{})
    require(set(inventories)=={'r2','r3'} and all(_valid_inventory(value) for value in inventories.values()),'Retained archive inventory evidence is missing')
    reinstall=proof.get('reinstall',{});new_root=reinstall.get('root','');observation=reinstall.get('commandObservation',{})
    artifact=reinstall.get('artifact',{})
    require(_valid_owned(new_root,root) and new_root not in paths.values() and reinstall.get('identical') is True
        and reinstall.get('inventory')==reinstall.get('retainedInventory')==inventories['r3']
        and re.fullmatch(r'cbodotnet-sdk-'+re.escape(plan['sdkVersion'])+'-linux-'+re.escape(plan['architecture'])+r'-r3\.tar\.gz',artifact.get('name',''))
        and type(artifact.get('size')) is int and artifact['size']>0 and re.fullmatch(r'[a-f0-9]{64}',artifact.get('sha256',''))
        and observation.get('root')==new_root and observation.get('payload')==new_root+'/payload'
        and observation.get('revision')==3 and observation.get('versionStdout')==plan['sdkVersion']+'\n'
        and observation.get('brandingStderr')==BRANDING['displayName']+'\n'
        and observation.get('identity',{}).get('sdkRoot')==new_root+'/payload'
        and observation['identity'].get('qualifiedPayloadModified') is False
        and all(observation['identity'].get(key)==value for key,value in identity(plan).items()),
        'Fresh actual archive reinstallation/inventory evidence differs')
    removal=proof.get('removal',{})
    require(removal.get('roots')==[paths[2],paths[3],new_root] and removal.get('allAbsent') is True
        and removal.get('selectionRemoved') is True and removal.get('noHostOutput') is True
        and type(removal.get('missingSelectionExitCode')) is int and removal['missingSelectionExitCode']!=0,
        'Actual owned archive removal/no-fallback evidence is incomplete')
    before=proof.get('systemBefore',{});after=proof.get('systemAfter',{})
    require(before==after and proof.get('systemStateUnchanged') is True and proof.get('providersUnchanged') is True
        and before.get('schemaVersion')==1 and before.get('scope')==SYSTEM_SCOPE
        and before.get('sdkVersion')==plan['sdkVersion'] and before.get('architecture')==plan['architecture']
        and before.get('officialPackageProvisioned') is False
        and [row.get('path') for row in before.get('globalPaths',[])]==list(GLOBAL_PATHS)
        and all(_valid_path_state(row) for row in before['globalPaths']),
        'Protected global state or actual present/absent baseline changed')
    expected_providers=[plan['compatibility']['root'],plan['nativeHttpCompatibility']['root']]
    require([row.get('path') for row in before.get('providers',[])]==expected_providers
        and all(_valid_path_state(row,allow_absent=False) and row.get('type')=='directory'
            and re.fullmatch(r'[a-f0-9]{64}',row.get('inventorySha256','')) and row.get('files',0)>0 for row in before['providers']),
        'Whole provider-tree preservation evidence is incomplete')
    libraries=before.get('stockLibraries',[]);packages=before.get('packages',{});sentinel=before.get('unrelatedSentinel',{})
    require(libraries and len({row.get('path') for row in libraries})==len(libraries)
        and all(_valid_path_state(row,allow_absent=False) and row.get('type') in {'file','symlink'} for row in libraries)
        and before.get('libraryInputs') and packages.get('manager') in {'dpkg','rpm'}
        and type(packages.get('packageCount')) is int and packages['packageCount']>0
        and re.fullmatch(r'[a-f0-9]{64}',packages.get('inventorySha256',''))
        and _valid_path_state(packages.get('database',{}),allow_absent=False) and packages['database'].get('type')=='directory'
        and re.fullmatch(r'[a-f0-9]{64}',packages['database'].get('inventorySha256',''))
        and sentinel.get('path')==str(root/'unrelated user state') and _valid_path_state(sentinel,allow_absent=False)
        and sentinel.get('type')=='directory' and sentinel.get('uid')==10001 and sentinel.get('files')==1
        and re.fullmatch(r'[a-f0-9]{64}',sentinel.get('inventorySha256',''))
        and before.get('sentinelPurpose')=='deliberately-created-unrelated-user-file-for-qualification',
        'Package database, stock/transitive library or unrelated-user state proof is incomplete')
    return proof
