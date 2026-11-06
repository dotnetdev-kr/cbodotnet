"""Native, private-provider qualification for explicitly admitted legacy SDKs.

The installer owns provider installation. This harness never repairs a missing
provider or substitutes a system installation for an owned companion.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import time

from consumer_archive import FUNCTIONAL_CHECKS
from downstream_release import encoded, require


LEGACY_VERSIONS = ('5.0.214', '3.1.426', '3.0.103')
BASE_PROVIDER = 'rocky9-20261104'
CURL_PROVIDER = 'rocky8-curl-20261104'
SCOPE = 'cbodotnetup-private-legacy-provider-installation'
CHECKS = ('explicit-provider-consent', 'signature-authentication', 'exact-sdk-source-binding',
          'provider-source-binding', 'owned-private-provider-roots', 'missing-provider-rejection',
          'substituted-provider-rejection', 'tampered-provider-rejection', 'revoked-sdk-rejection',
          'revoked-provider-rejection', 'incompatible-provider-abi-rejection', 'interrupted-recovery',
          'idempotent-install', 'tracked-update', 'sdk-rollback', 'provider-sharing',
          'provider-reference-preservation', 'unreferenced-provider-gc', 'project-sdk-selection',
          'clean-manager-provider-environment', 'default-certificate-trust', 'offline-build-apphost-aspnet',
          'immutable-sdk-and-provider-files', 'official-package-coexistence', 'removal')
ENVIRONMENT = ('LD_LIBRARY_PATH', 'OPENSSL_CONF', 'CLR_OPENSSL_VERSION_OVERRIDE',
               'CLR_ICU_VERSION_OVERRIDE', 'DOTNET_ICU_VERSION_OVERRIDE',
               'DOTNET_SYSTEM_GLOBALIZATION_APPLOCALICU')
SCOPED_ENVIRONMENT = ('LD_LIBRARY_PATH', 'OPENSSL_CONF', 'CLR_OPENSSL_VERSION_OVERRIDE',
                      'CLR_ICU_VERSION_OVERRIDE', 'SSL_CERT_FILE')


def load(path):
    return json.loads(Path(path).read_bytes())


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def file_hash(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'An ordinary qualification metadata file is required')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sdk_id(sdk):
    return sdk['sdkVersion'] + '-r' + str(sdk['revision']) + '/' + sdk['rid']


def provider_id(provider):
    return provider['providerId'] + '-r' + str(provider['revision']) + '/' + provider['rid']


def providers_for(catalog, sdk):
    require(catalog['schemaVersion'] == 3 and sdk['sdkVersion'] in LEGACY_VERSIONS
            and sdk['requiresLegacyProvider'], 'Legacy qualification requires the provider-aware signed feed')
    bindings = [binding for binding in catalog['providerBindings'] if binding['sdkId'] == sdk_id(sdk)]
    require(len(bindings) == 1 and bindings[0]['sourceManifestSha256'] == sdk['sourceManifestSha256']
            and bindings[0]['archiveSha256'] == sdk['archive']['sha256'], 'Legacy SDK provider binding differs')
    indexed = {provider_id(provider): provider for provider in catalog['providers']}
    require(len(indexed) == len(catalog['providers']) and all(identifier in indexed for identifier in bindings[0]['providerIds']),
            'Missing or duplicate provider identity')
    providers = [indexed[identifier] for identifier in bindings[0]['providerIds']]
    kinds = [BASE_PROVIDER, CURL_PROVIDER] if sdk['sdkVersion'].startswith('3.') else [BASE_PROVIDER]
    require([provider['providerId'] for provider in providers] == kinds
            and all(provider['rid'] == sdk['rid'] and provider['libc'] == 'glibc'
                    and all(target in provider['targets'] for target in sdk['targets']) for provider in providers),
            'Legacy SDK provider set or target coverage differs')
    return providers


def provider_store(root, provider):
    return Path(root) / 'providers' / provider_id(provider)


def runtime_root(root, provider):
    return provider_store(root, provider) / 'content/rootfs' / provider['root'].lstrip('/')


def provider_observations(root, catalog, sdk):
    result = []
    for provider in providers_for(catalog, sdk):
        directory = provider_store(root, provider)
        receipt = load(directory / 'receipt.json')
        require(receipt['schemaVersion'] == 1 and receipt['owner'] == 'cbodotnetup-v1'
                and receipt['release'] == provider, 'Owned provider receipt differs from signed admission')
        inventory = load(directory / 'inventory.json')
        result.append(dict(id=provider_id(provider), providerId=provider['providerId'], revision=provider['revision'],
            rid=provider['rid'], archive=provider['archive'], policySha256=provider['policySha256'],
            manifestSha256=provider['manifestSha256'], sourceManifest=provider['sourceManifest'],
            sourceSignature=provider['sourceSignature'],
            storeRelativePath='providers/' + provider_id(provider), root=str(runtime_root(root, provider)),
            receiptSha256=file_hash(directory / 'receipt.json'), inventorySha256=file_hash(directory / 'inventory.json'),
            treeSha256=digest(inventory), retainedCatalogSha256=file_hash(directory / 'catalog.json')))
    references = load(Path(root) / 'toolchains-v3' / sdk_id(sdk) / 'providers.json')
    require(references == dict(schemaVersion=1, sdkId=sdk_id(sdk),
                              providerIds=[provider_id(provider) for provider in providers_for(catalog, sdk)]),
            'Activated legacy SDK did not retain its exact provider references')
    return result


def runtime_environment(root, catalog, sdk, variant):
    import legacy_compat
    import legacy_curl
    plan = dict(sdkVersion=sdk['sdkVersion'], variant=variant)
    providers = providers_for(catalog, sdk)
    environment = legacy_compat.environment(plan, root=str(runtime_root(root, providers[0])))
    if len(providers) == 2:
        environment = legacy_curl.environment(plan, root=str(runtime_root(root, providers[1])), base_environment=environment)
    return environment


def clean_manager_wrapper(path, root, binary, sdk, *, preserve_certificate=True):
    """Strip ambient provider state so real manager setup is required by probes."""
    names = list(ENVIRONMENT) + ['CBODOTNET_COMPAT_ROOT', 'CBODOTNET_CURL_COMPAT_ROOT', 'CBODOTNET_COMPAT_SCOPE']
    names += ['CBODOTNET_COMPAT_SAVED_' + name + suffix for name in SCOPED_ENVIRONMENT for suffix in ('_SET', '_VALUE')]
    if not preserve_certificate:
        names.append('SSL_CERT_FILE')
    command = ['env']
    for name in names:
        command += ['-u', name]
    command += ['CBODOTNETUP_HOME=' + str(root), str(binary), 'run', sdk['sdkVersion'] + '-r' + str(sdk['revision']), '--']
    Path(path).write_text('#!/bin/sh\nexec ' + shlex.join(command) + ' "$@"\n')
    Path(path).chmod(0o755)
    return Path(path)


def _fresh_negative(args, api, sdk, suffix, fixture, error):
    root, binary = api.matrix_paths(args)
    root = Path(str(root) + '-' + suffix); binary = binary.parent.parent / (binary.parent.name + '-' + suffix) / binary.name
    require(not root.exists() and not binary.parent.exists(), 'Fresh legacy rejection root required')
    api.matrix_bootstrap(args, root, binary, args.bundle / fixture)
    result = api.matrix_user(root, [binary, '--catalog', args.bundle / fixture,
                                  'install', sdk['sdkVersion'] + '-r' + str(sdk['revision']), '--with-legacy-providers'], check=False)
    require(result.returncode != 0 and error in result.stderr,
            'Legacy signed rejection fixture did not reject before activation: ' + suffix + '\n' + result.stderr[-3000:])
    require(all(not list((root / name).iterdir()) for name in ('toolchains-v3', 'providers', 'staging')),
            'Rejected provider admission extracted an active SDK, provider or staging payload')
    return dict(status='passed', fixture=fixture, catalogSha256=file_hash(args.bundle / fixture), exitCode=result.returncode,
                noPayloadExtracted=True)


def _tool_rollback_with_providers(args, api, root, binary, sdk, peer, baseline, migration):
    from cbodotnetup_project import owned_sdk_state
    catalog=load(args.bundle/'catalog.json')
    if not args.public:
        return dict(status='public-verification-required',protocol='protected-frozen-candidate-bootstrap',migration=migration)
    api.matrix_user(root,[binary,'doctor'])
    before=owned_sdk_state(root)
    compatibility=[binary,'--catalog',args.bundle/'catalog-v2.json']
    api.matrix_user(root,[*compatibility,'self','rollback'])
    require(api.matrix_user(root,[binary,'--version']).stdout.strip()=='0.3.0'
            and file_hash(binary)==migration['oldBinarySha256'], 'Provider-state rollback did not restore the actual 0.3 client')
    exact=baseline['sdkVersion']+'-r'+str(baseline['revision'])
    modern=api.matrix_user(root,[binary,'run',exact,'--','--version'])
    require(modern.stdout==baseline['sdkVersion']+'\n' and modern.stderr==api.MULTI.BRAND+'\n',
            'Rolled-back project-aware client could not run the retained modern SDK with legacy state present')
    require(owned_sdk_state(root)==before,'Old project-aware client changed legacy SDK/provider state')
    api.matrix_user(root,[*compatibility,'self','update'])
    require(api.matrix_user(root,[binary,'--version']).stdout.strip()==api.load(api.POLICY)['version'],
            'Old project-aware client could not re-upgrade with installed private providers')
    api.matrix_user(root,[binary,'--catalog',args.bundle/'catalog.json','list','--available'])
    api.matrix_user(root,[binary,'doctor'])
    legacy=api.matrix_user(root,[binary,'run',sdk['sdkVersion']+'-r'+str(sdk['revision']),'--','--version'])
    peer_run=api.matrix_user(root,[binary,'run',peer['sdkVersion']+'-r'+str(peer['revision']),'--','--version'])
    require(legacy.stdout==sdk['sdkVersion']+'\n' and legacy.stderr==api.MULTI.BRAND+'\n'
            and peer_run.stdout==peer['sdkVersion']+'\n' and peer_run.stderr==api.MULTI.BRAND+'\n'
            and owned_sdk_state(root)==before,'Tool rollback/re-upgrade changed a retained legacy SDK or companion')
    return dict(status='passed',protocol='actual-0.3.0-recovery-with-installed-legacy-providers',migration=migration,
        fromVersion=api.load(api.POLICY)['version'],retainedVersion='0.3.0',oldBinarySha256=migration['oldBinarySha256'],
        currentBinarySha256=file_hash(binary),sdkIds=sorted(sdk_id(release) for release in (baseline,sdk,peer)),
        providerIds=sorted({provider_id(provider) for release in (sdk,peer) for provider in providers_for(catalog,release)}),
        ownedStateBeforeSha256=digest(before),ownedStateAfterSha256=digest(owned_sdk_state(root)),
        modernSdkExecutedAfterRollback=True,legacySdkExecutedAfterReupgrade=True,
        peerSdkExecutedAfterReupgrade=True,
        allSdkAndProviderInventoriesVerified=True,selectionAndReceiptsUnchanged=True)


def install(args, api):
    """Online private install, signed negative fixtures, interruption and sharing."""
    api.MULTI.check_container(args.variant, args.arch); api.verify_bundle(args.bundle)
    catalog, sdk = api.matrix_sdk(args); root, binary = api.matrix_paths(args)
    require(not root.exists() and not binary.parent.exists(), 'Fresh private legacy qualification root required')
    providers_for(catalog, sdk)
    baseline = next(release for release in catalog['sdks'] if release['sdkVersion'] == '10.0.403' and release['rid'] == sdk['rid'])
    exact = sdk['sdkVersion'] + '-r' + str(sdk['revision']); baseline_exact = baseline['sdkVersion'] + '-r' + str(baseline['revision'])
    manager = [binary, '--catalog', args.bundle / 'catalog.json']
    if sdk['sdkVersion']=='5.0.214':
        previous_project_client=api.matrix_previous_tool_upgrade(args,root,binary,baseline,previous_version='0.3.0')
    else:
        previous_project_client=None
        api.matrix_bootstrap(args, root, binary, args.bundle / 'catalog.json')
        api.matrix_user(root, [*manager, 'install', baseline_exact])
    consent = api.matrix_user(root, [*manager, 'install', exact], check=False)
    require(consent.returncode != 0 and '--with-legacy-providers' in consent.stderr,
            'First legacy installation did not require explicit provider consent')
    require(not list((root / 'toolchains-v3').iterdir()) and not list((root / 'providers').iterdir())
            and not list((root / 'staging').iterdir()), 'Missing provider consent downloaded or extracted a payload')
    negatives = dict(
        revokedSdk=_fresh_negative(args, api, sdk, 'revoked-sdk', 'catalog-v3-revoked.json', 'revoked'),
        revokedProvider=_fresh_negative(args, api, sdk, 'revoked-provider', 'catalog-v3-provider-revoked.json', 'revoked'),
        incompatibleAbi=_fresh_negative(args, api, sdk, 'incompatible-abi', 'catalog-v3-provider-incompatible.json', 'ABI requires glibc'))
    high = (root / 'cache/v3/high-water.json').read_bytes()
    bad = root / 'bad-catalog.json'; bad.write_bytes((args.bundle / 'catalog.json').read_bytes() + b' ')
    import shutil
    shutil.copyfile(args.bundle / 'catalog.json.asc', str(bad) + '.asc')
    require(api.matrix_user(root, [binary, '--catalog', bad, 'install', exact, '--with-legacy-providers'], check=False).returncode != 0
            and (root / 'cache/v3/high-water.json').read_bytes() == high, 'Legacy installation accepted a modified catalog signature')
    log = args.workspace / ('legacy-' + sdk['sdkVersion'] + '-interrupted.log')
    with log.open('w') as output:
        child = api.user_process([*manager, 'install', exact, '--with-legacy-providers'], stdout=output,
                                 extra_environment={'CBODOTNETUP_HOME': str(root)})
        interrupted = False
        try:
            deadline = time.monotonic() + 90
            while child.poll() is None and time.monotonic() < deadline:
                if any((stage / 'prepared/source-manifest.json').is_file() or (stage / 'source.json').is_file()
                       for stage in (root / 'staging').iterdir() if stage.is_dir()):
                    os.killpg(child.pid, signal.SIGKILL); interrupted = True; break
                time.sleep(0.02)
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=30)
    require(interrupted and not (root / 'toolchains-v3' / sdk_id(sdk)).exists(),
            'Interrupted provider installation exposed an active legacy SDK; ' + log.read_text()[-3000:])
    api.matrix_user(root, [binary, 'gc'])
    require(not list((root / 'staging').iterdir()) and not list((root / 'providers').iterdir()),
            'Interrupted private-provider installation was not collected safely')
    api.matrix_user(root, [*manager, 'install', '--channel', '.'.join(sdk['sdkVersion'].split('.')[:2]), '--with-legacy-providers'])
    api.matrix_user(root, [*manager, 'install', exact]); api.matrix_user(root, [*manager, 'update']); api.matrix_user(root, [binary, 'rollback', exact])
    api.matrix_user(root, [binary, 'doctor'])
    initial = provider_observations(root, catalog, sdk)
    peer = next(release for release in catalog['sdks'] if release['sdkVersion'] == ('3.0.103' if sdk['sdkVersion'] == '3.1.426' else '3.1.426')
                and release['rid'] == sdk['rid'])
    peer_exact = peer['sdkVersion'] + '-r' + str(peer['revision'])
    api.matrix_user(root, [*manager, 'install', peer_exact, '--with-legacy-providers'])
    peer_records = provider_observations(root, catalog, peer)
    tool_rollback=(_tool_rollback_with_providers(args,api,root,binary,sdk,peer,baseline,previous_project_client)
                   if previous_project_client is not None else None)
    shared = sorted(set(record['id'] for record in initial) & {record['id'] for record in peer_records})
    require(shared, 'Legacy coexistence did not share an exact provider revision')
    api.matrix_user(root, [binary, 'remove', exact]); api.matrix_user(root, [binary, 'gc']); api.matrix_user(root, [binary, 'doctor'])
    retained = provider_observations(root, catalog, peer)
    require(retained == peer_records, 'Removing a legacy SDK changed a provider still referenced by its peer')
    result = api.matrix_user(root, [binary, 'run', peer_exact, '--', '--version'])
    require(result.stdout == peer['sdkVersion'] + '\n' and result.stderr == api.MULTI.BRAND + '\n',
            'A peer could not run after removing another SDK that shared its provider')
    api.matrix_user(root, [*manager, 'install', exact, '--with-legacy-providers'])
    api.matrix_user(root, [binary, 'remove', peer_exact]); api.matrix_user(root, [binary, 'gc']); api.matrix_user(root, [binary, 'doctor'])
    require(provider_observations(root, catalog, sdk) == initial, 'Peer removal changed the retained target provider revision')
    require(set(api.matrix_user(root, [binary, 'list']).stdout.splitlines()) == {sdk_id(sdk), sdk_id(baseline)},
            'Private-provider sharing changed another SDK installation')
    api.matrix_user(root, [binary, 'shell', 'enable'])
    sharing = dict(status='passed', peerSdkId=sdk_id(peer), sharedProviderIds=shared,
                   peerArchiveSha256=peer['archive']['sha256'], peerSourceManifestSha256=peer['sourceManifestSha256'],
                   retainedPeerProviderReceipts={record['id']: record['receiptSha256'] for record in retained},
                   retainedAfterRemove=True, targetProviderStatePreserved=True, unreferencedGc=True)
    api.save(args.workspace / ('legacy-' + sdk['sdkVersion'] + '-state.json'), dict(sdk=sdk, exact=exact, baseline=baseline,
        baselineExact=baseline_exact, providers=initial, sharing=sharing, negatives=negatives,toolRollback=tool_rollback,
        consentRejected=True, consentNoPayloadExtracted=True, interruptedRecovery=True,
        catalogSha256=file_hash(args.bundle / 'catalog.json'), binarySha256=file_hash(binary),
        bootstrapSha256=file_hash(args.bundle / 'get-cbodotnetup.py'),
        bootstrapBinarySource='public-https' if args.public else 'protected-frozen-candidate'))


def _probe_provider_environment(args, api, root, binary, sdk, catalog, payload, clean_cli, work):
    """A real managed child must load the private OpenSSL/ICU from a clean parent."""
    from sdk_runtime import target_framework
    import legacy_compat
    providers = providers_for(catalog, sdk)
    base = str(runtime_root(root, providers[0])); curl = str(runtime_root(root, providers[1])) if len(providers) == 2 else ''
    expected_ca = legacy_compat.environment(dict(sdkVersion=sdk['sdkVersion'], variant=args.variant), root=base)['SSL_CERT_FILE']
    program = r'''using System; using System.IO; using System.Linq; using System.Globalization;
using System.Security.Cryptography; using System.Text; using System.Text.Json;
public static class Program {
 public static void Main() {
  using (var rsa = RSA.Create()) { rsa.KeySize = 2048; var data = Encoding.UTF8.GetBytes("private-provider");
   var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
   if (!rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) throw new Exception("RSA failed"); }
  if (1234.5m.ToString("N1", new CultureInfo("fr-FR")).IndexOf(',') < 0) throw new Exception("ICU failed");
  var ca = Environment.GetEnvironmentVariable("SSL_CERT_FILE");
  if (ca != EXPECTED_CA || !File.Exists(ca)) throw new Exception("Target stock CA path was not set by the manager");
  var config = Environment.GetEnvironmentVariable("OPENSSL_CONF");
  if (config != BASE_ROOT + "/openssl.cnf" || Environment.GetEnvironmentVariable("CLR_OPENSSL_VERSION_OVERRIDE") != "1.1")
   throw new Exception("Private OpenSSL environment was not set by the manager");
  if (CORE3 && Environment.GetEnvironmentVariable("CLR_ICU_VERSION_OVERRIDE") != "67") throw new Exception("Private ICU environment missing");
  var mappings = File.ReadAllLines("/proc/self/maps").Where(line => line.Contains("libcrypto") || line.Contains("libssl") || line.Contains("libicu")).ToArray();
  Console.WriteLine("CBODOTNETUP_PRIVATE_PROVIDER=" + JsonSerializer.Serialize(new { status="passed", baseRoot=BASE_ROOT,
   curlRoot=CURL_ROOT, certificateFile=ca, opensslConfiguration=config,
   libraryPath=Environment.GetEnvironmentVariable("LD_LIBRARY_PATH"), nativeMappings=mappings }));
 }
}
'''.replace('EXPECTED_CA', json.dumps(expected_ca)).replace('BASE_ROOT', json.dumps(base)).replace('CURL_ROOT', json.dumps(curl)).replace('CORE3', 'true' if len(providers) == 2 else 'false')
    framework = target_framework(sdk['sdkVersion'])
    project = '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>'+framework+'</TargetFramework><OutputType>Exe</OutputType></PropertyGroup></Project>'
    require(not work.exists(),'A fresh unprivileged private-provider probe workspace is required')
    api.matrix_user(root,['mkdir','--',work])
    (work / 'Probe.csproj').write_text(project); (work / 'Program.cs').write_text(program)
    (work / 'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>')
    api.matrix_user(root, ['sh', '-ec', 'cd "$1"; "$2" restore --configfile NuGet.Config; "$2" build --no-restore', 'private-probe', work, clean_cli])
    output = api.matrix_user(root, [clean_cli, work / ('bin/Debug/'+framework+'/Probe.dll')]).stdout
    rows = [line[len('CBODOTNETUP_PRIVATE_PROVIDER='):] for line in output.splitlines() if line.startswith('CBODOTNETUP_PRIVATE_PROVIDER=')]
    require(len(rows) == 1, 'One actual clean-manager private provider mapping proof is required')
    proof = json.loads(rows[0])
    require(proof['status'] == 'passed' and proof['baseRoot'] == base and proof['curlRoot'] == curl
            and proof['certificateFile'] == expected_ca and proof['opensslConfiguration'] == base+'/openssl.cnf',
            'Private provider environment selected another root or CA bundle')
    from native_curl_runtime import decoded_mapping
    mappings = [decoded_mapping(line) for line in proof['nativeMappings']]
    components = [row for row in providers[0]['manifest']['files'] if row['type'] == 'file' and row['path'].startswith('lib/libcrypto.so.')]
    if sdk['sdkVersion'].startswith('3.'):
        components += [row for row in providers[0]['manifest']['files'] if row['type'] == 'file' and row['path'].startswith('lib/libicu')]
    require(components and all(any(base + '/' + component['path'] in line for line in mappings) for component in components),
            'The real child did not map the exact owned crypto/ICU components')
    proof.update(scope='clean-manager-private-provider-environment', userId=10001, network='none',
                 components=[dict(path=base+'/'+row['path'],sha256=row['sha256']) for row in components])
    return proof


def smoke(args, api):
    """Offline actual SDK, apphost, provider mapping, CurlHandler and safe removal."""
    from cbodotnetup_project import qualify_project_selection
    from sdk_runtime import (smoke_script, validate_smoke_output, forced_curl_script,
                             validate_forced_curl_output, audit_core3_http_libraries)
    import native_curl_runtime
    api.MULTI.check_container(args.variant, args.arch, offline=True)
    state = load(args.workspace / ('legacy-' + args.sdk_version + '-state.json'))
    sdk, baseline = state['sdk'], state['baseline']; catalog = load(args.bundle / 'catalog.json')
    root, binary = api.matrix_paths(args); home = Path('/home') / api.MULTI.USER
    payload = root / 'toolchains-v3' / sdk_id(sdk) / 'content' / sdk['archiveRoot'] / 'payload'
    providers = providers_for(catalog, sdk)
    before = provider_observations(root, catalog, sdk)
    aliases = []
    for name, expected in [('cbodotnet', baseline), ('cbodotnet-10.0', baseline),
                           ('cbodotnet-' + '.'.join(sdk['sdkVersion'].split('.')[:2]), sdk)]:
        result = api.matrix_user(root, [root / 'bin' / name, '--version'])
        require(result.stdout == expected['sdkVersion'] + '\n' and result.stderr == api.MULTI.BRAND + '\n',
                'Legacy side-by-side alias selected another SDK or lost branding')
        info = json.loads(api.matrix_user(root, [root / 'bin' / name, '--cbodotnet-info']).stdout)
        require(info['sdkVersion'] == expected['sdkVersion'] and info['packageRevision'] == expected['revision']
                and info['targetRid'] == expected['rid'] and info['sourceManifestSha256'] == expected['sourceManifestSha256']
                and info['qualifiedPayloadModified'] is False, 'Legacy alias source identity differs')
        aliases.append(info)
    component = next(row for row in providers[0]['manifest']['files'] if row['type'] == 'file' and row['path'].startswith('lib/'))
    target = runtime_root(root, providers[0]) / component['path']; original = target.read_bytes()
    hidden = target.with_name(target.name + '.qualification-hidden')
    try:
        target.rename(hidden)
        missing = api.matrix_user(root, [binary, 'run', state['exact'], '--', '--version'], check=False)
        require(missing.returncode != 0 and not missing.stdout.strip(), 'Missing private provider fell back to a system provider')
    finally:
        if hidden.exists(): hidden.rename(target)
    try:
        target.write_bytes(original + b'qualification-tamper')
        tampered = api.matrix_user(root, [binary, 'doctor'], check=False)
        require(tampered.returncode != 0, 'Changed private provider bytes passed doctor')
        target.write_bytes((payload / 'LICENSE.txt').read_bytes())
        substituted = api.matrix_user(root, [binary, 'run', state['exact'], '--', '--version'], check=False)
        require(substituted.returncode != 0 and not substituted.stdout.strip(), 'Substituted provider executed or fell back to a system installation')
    finally:
        target.write_bytes(original)
    api.matrix_user(root, [binary, 'doctor'])
    normal_cli = clean_manager_wrapper(home / ('run-legacy-'+sdk['sdkVersion']+'.sh'), root, binary, sdk)
    clean_cli = clean_manager_wrapper(home / ('run-clean-legacy-'+sdk['sdkVersion']+'.sh'), root, binary, sdk, preserve_certificate=False)
    environment = runtime_environment(root, catalog, sdk, args.variant)
    manager_environment = _probe_provider_environment(args, api, root, binary, sdk, catalog, payload, clean_cli,
                                                     home / ('private-provider-probe-'+sdk['sdkVersion']))
    functional = validate_smoke_output(api.matrix_user(root, ['sh', '-ec', smoke_script(sdk['sdkVersion'], str(payload), api.MULTI.USER,
        cli=str(normal_cli), workdir=str(home / ('legacy-offline-'+sdk['sdkVersion'])), runtime_env=environment)]).stdout)
    if sdk['sdkVersion'].startswith('3.'):
        curl_root = str(runtime_root(root, providers[1]))
        output = api.matrix_user(root, ['sh', '-ec', forced_curl_script(sdk['sdkVersion'], str(payload), api.MULTI.USER,
            cli=str(normal_cli), workdir=str(home / ('legacy-native-curl-'+sdk['sdkVersion'])),
            runtime_env=environment, curl_root=curl_root, user_id=10001)]).stdout
        native_curl = validate_forced_curl_output(output, sdk['sdkVersion'], str(payload), curl_root, 10001, args.arch)
        default_trust = {name: native_curl[name] for name in ('httpsDefaultTrust', 'tls12')}
        def runner(arguments, *, env=None):
            return api.run(arguments, env=env, capture_output=True).stdout
        native_http = audit_core3_http_libraries(sdk['sdkVersion'], payload, environment, runner=runner)
        require(native_http and all(row['libcurlProviderPath'].startswith(curl_root + '/') for row in native_http),
                'Core3 native HTTP loader resolved a system curl library')
    else:
        output = api.matrix_user(root, ['sh', '-ec', native_curl_runtime.standard_trust_script(sdk['sdkVersion'], str(payload), api.MULTI.USER,
            cli=str(normal_cli), workdir=str(home / ('legacy-native-ca-'+sdk['sdkVersion'])), runtime_env=environment)]).stdout
        default_trust = native_curl_runtime.validate_standard_trust(output)
        native_curl = None; native_http = []
    project = qualify_project_selection(root, binary, sdk, baseline, home / ('legacy-project-selection-'+sdk['sdkVersion']), api.matrix_user)
    api.matrix_user(root, [binary, 'doctor'])
    require(provider_observations(root, catalog, sdk) == before == state['providers'],
            'Offline execution changed owned companion receipts, inventories or source linkage')
    api.matrix_user(root, [binary, 'rollback', state['exact']])
    api.matrix_user(root, [binary, 'remove', state['exact']]); api.matrix_user(root, [binary, 'gc'])
    require(not list((root / 'providers').iterdir()) and not list((root / 'toolchains-v3').iterdir()),
            'Removing the final legacy reference left an active or unreferenced private provider')
    require(api.matrix_user(root, [binary, 'list']).stdout.strip() == sdk_id(baseline)
            and api.matrix_user(root, [root / 'bin/cbodotnet', '--version']).stdout == baseline['sdkVersion']+'\n',
            'Legacy removal changed the retained modern SDK')
    require(api.matrix_user(root, [binary, 'rollback', state['exact']], check=False).returncode != 0,
            'Removed legacy selection fell back to another SDK')
    api.matrix_user(root, [binary, 'doctor']); api.matrix_user(root, [binary, 'remove', state['baselineExact']])
    require(api.matrix_user(root, [binary, 'list']).stdout == '', 'Legacy lifecycle left an SDK payload installed')
    absent = api.matrix_user(root, [root / 'bin/cbodotnet', '--version'], check=False)
    require(absent.returncode != 0 and not absent.stdout, 'Empty legacy root fell back to a package/system SDK')
    api.matrix_user(root, [binary, 'shell', 'disable'])
    original_state = api.load(args.workspace / 'installed.json')
    require(api.MULTI.APT.inventory(Path('/opt/cbodotnet')) == original_state['packageInventory'], 'Legacy lifecycle changed Community package inventory')
    api.MULTI.integrity(original_state['packages'], api.MULTI.TARGETS[args.variant])
    if api.MULTI.TARGETS[args.variant] == 'deb': from apt_official import assert_unchanged
    else: from rpm_official import assert_unchanged
    assert_unchanged(args.workspace / 'official.json')
    require((home / '.local/share/dotnetup/owner-test').read_text() == 'untouched', 'Legacy lifecycle changed official installer state')
    target_record = api.load_contract()['operatingSystems'][args.variant]
    proof = dict(schemaVersion=1, scope=SCOPE, status='passed', sdkVersion=sdk['sdkVersion'], revision=sdk['revision'], rid=sdk['rid'],
        target=dict(os=target_record['id'],versionId=target_record['versionId'],rid=sdk['rid']), variant=args.variant, architecture=args.arch,
        archive=sdk['archive'], sourceManifestSha256=sdk['sourceManifestSha256'], catalogSha256=state['catalogSha256'],
        bootstrapSha256=state['bootstrapSha256'], binarySha256=state['binarySha256'], bootstrapBinarySource=state['bootstrapBinarySource'],
        networkForBuild='none', userId=10001, checks=dict.fromkeys(CHECKS,'passed'), functionalChecks=functional, aliases=aliases,
        projectSelection=project, providerQualification=dict(status='passed', providers=before, sharing=state['sharing'], negatives=state['negatives'],toolRollback=state['toolRollback'],
            consentRejected=state['consentRejected'], consentNoPayloadExtracted=state['consentNoPayloadExtracted'],
            interruptedRecovery=state['interruptedRecovery'], missingRejected=True, tamperRejected=True, substitutedRejected=True,
            managerEnvironment=manager_environment, nativeHttpLibraries=native_http, defaultTrust=default_trust, nativeCurlHandler=native_curl,
            ownedSdkBytesUnchanged=True, ownedProviderBytesUnchanged=True, officialAndPackageStateUnchanged=True,
            unreferencedProvidersCollected=True, providerEnvironmentScope='child-only; same-process success/failure restoration is covered by the native source suite'))
    api.save(args.workspace / ('legacy-'+sdk['sdkVersion']+'-observation.json'), proof)
    report = api.load(args.workspace / 'report.json'); report.setdefault('legacySdkQualifications', []).append(proof)
    api.save(args.workspace / 'report.json', report)


def validate_project_client_migration(value, observation, catalog, compatibility_catalog, tool_version):
    """The shipped 0.3 binary must retain an authenticated recovery path."""
    require(isinstance(value,dict) and compatibility_catalog is not None and compatibility_catalog['schemaVersion']==2,
            'Actual project-aware schema2 client migration evidence is required')
    public = observation['bootstrapBinarySource'] == 'public-https'
    old_tools = [tool for tool in compatibility_catalog['tools'] if tool['version']=='0.3.0'
                 and 'tool/'+tool['version']+'/'+tool['rid'] not in compatibility_catalog['revoked']]
    old = [tool for tool in old_tools if tool['rid'] == ('linux-x64' if observation['architecture']=='x64' else 'linux-arm64')]
    prior = dict(compatibility_catalog,sequence=compatibility_catalog['sequence']-1,tools=old_tools)
    baseline = next(sdk for sdk in catalog['sdks'] if sdk['sdkVersion']=='10.0.403' and sdk['rid']==old[0]['rid']) if len(old)==1 else None
    require(len(old)==1 and value.get('status')=='passed' and value.get('fromVersion')=='0.3.0' and value.get('toVersion')==tool_version
            and value.get('protocol')==('actual-0.3.0-self-update-rollback-reupgrade' if public else 'protected-frozen-candidate-bootstrap-from-0.3.0')
            and value.get('oldBinarySha256')==old[0]['binary']['sha256'] and value.get('currentBinarySha256')==observation['binarySha256']
            and value.get('currentCatalogSha256')==observation['catalogSha256']
            and value.get('compatibilityCatalogSha256')==catalog['compatibilityCatalog']['sha256']==digest(compatibility_catalog)
            and value.get('previousCatalogSha256')==value.get('baselineCatalogSha256')==digest(prior)
            and value.get('baseline')=={key:baseline[key] for key in ('sdkVersion','revision','rid')}
            and value.get('baselineReceiptUnchanged') is True and value.get('baselineOwnedStateUnchanged') is True
            and value.get('baselinePayloadVerified') is True and value.get('rollbackVerified') is public,
            'Project-aware previous-client binary/catalog/recovery evidence differs')
    for name in ('baselineReceiptSha256','baselineInventorySha256','baselineOwnedStateSha256'):
        require(isinstance(value.get(name),str) and re.fullmatch('[a-f0-9]{64}',value[name]), 'Previous-client retained state hash is incomplete')


def validate_legacy_qualifications(catalog, observations, *, tool_version, compatibility_catalog=None):
    """Return exact passed legacy cells; metadata alone is never qualification."""
    expected = {}
    for sdk in catalog['sdks']:
        if not sdk['requiresLegacyProvider']: continue
        providers_for(catalog, sdk)
        require(sdk_id(sdk) not in catalog['revoked'], 'Revoked legacy SDK cannot be promoted')
        for target in sdk['targets']:
            key=(sdk['sdkVersion'],sdk['rid'],target['os'],target['versionId'])
            require(key not in expected and target['rid']==sdk['rid'], 'Duplicate or inconsistent legacy target')
            expected[key]=(sdk,target)
    if not expected: return []
    require(catalog['schemaVersion']==3 and compatibility_catalog is not None,
            'Legacy promotion requires its authenticated schema2 compatibility projection')
    seen=set(); result=[]
    for observation in observations:
        validate_project_client_migration(observation.get('projectClientMigration'), observation, catalog, compatibility_catalog, tool_version)
        rows=observation.get('legacySdkQualifications',[])
        require(isinstance(rows,list), 'Legacy SDK qualification must be an array')
        for row in rows:
            target=row['target']; key=(row['sdkVersion'],row['rid'],target['os'],target['versionId'])
            require(key in expected and key not in seen, 'Unexpected or duplicate legacy SDK qualification cell')
            sdk,admitted=expected[key]; providers=providers_for(catalog,sdk)
            architecture={'linux-x64':'x64','linux-arm64':'aarch64'}[sdk['rid']]
            require(row['schemaVersion']==1 and row['scope']==SCOPE and row['status']=='passed'
                    and row['revision']==sdk['revision'] and row['archive']==sdk['archive']
                    and row['sourceManifestSha256']==sdk['sourceManifestSha256'] and target==admitted
                    and row['variant']==observation['variant']==target['os']+'-'+target['versionId']
                    and row['architecture']==observation['architecture']==architecture
                    and all(row[field]==observation[field] for field in ('catalogSha256','bootstrapSha256','binarySha256','bootstrapBinarySource'))
                    and row['checks']==dict.fromkeys(CHECKS,'passed') and row['functionalChecks']==dict.fromkeys(FUNCTIONAL_CHECKS,'passed')
                    and row['networkForBuild']=='none' and row['userId']==10001, 'Legacy SDK identity, offline execution or lifecycle evidence differs')
            baseline=next(release for release in catalog['sdks'] if release['sdkVersion']=='10.0.403' and release['rid']==sdk['rid'])
            aliases=row['aliases'];require(len(aliases)==3,'Legacy alias proof is incomplete')
            for alias,release in zip(aliases,[baseline,baseline,sdk]):
                require(all(alias.get(field)==value for field,value in dict(sdkVersion=release['sdkVersion'],packageRevision=release['revision'],
                    targetRid=release['rid'],sourceManifestSha256=release['sourceManifestSha256'],qualifiedPayloadModified=False).items()),
                    'Legacy alias source/revision/RID differs')
            from cbodotnetup_project import validate_project_evidence
            validate_project_evidence(row['projectSelection'],sdk,baseline,catalog)
            proof=row['providerQualification']
            require(proof['status']=='passed' and all(proof.get(field) is True for field in ('consentRejected','consentNoPayloadExtracted',
                'interruptedRecovery','missingRejected','tamperRejected','substitutedRejected','ownedSdkBytesUnchanged',
                'ownedProviderBytesUnchanged','officialAndPackageStateUnchanged','unreferencedProvidersCollected')),
                'Legacy provider rejection, recovery or preservation evidence is incomplete')
            records=proof['providers']; require(len(records)==len(providers),'Legacy companion proof set differs')
            for record,provider in zip(records,providers):
                require('provider/'+provider_id(provider) not in catalog['revoked']
                        and record['id']==provider_id(provider) and record['providerId']==provider['providerId']
                        and record['revision']==provider['revision'] and record['rid']==provider['rid']
                        and all(record[field]==provider[field] for field in ('archive','policySha256','manifestSha256','sourceManifest','sourceSignature'))
                        and record['storeRelativePath']=='providers/'+provider_id(provider)
                        and record['root']=='/home/cbot-multi-sdk/.local/share/cbodotnetup-matrix-'+sdk['sdkVersion']
                            +'/providers/'+provider_id(provider)+'/content/rootfs'+provider['root']
                        and record['retainedCatalogSha256']==row['catalogSha256'],
                        'Legacy companion source/revision/private root differs')
                for name in ('receiptSha256','inventorySha256','treeSha256','retainedCatalogSha256'):
                    require(re.fullmatch('[a-f0-9]{64}',record[name]),'Legacy provider receipt/inventory hash is incomplete')
            sharing=proof['sharing']
            peers=[release for release in catalog['sdks'] if sdk_id(release)==sharing['peerSdkId']]
            shared=({provider_id(provider) for provider in providers}&{provider_id(provider) for provider in providers_for(catalog,peers[0])}
                    if len(peers)==1 else set())
            require(sharing['status']=='passed' and len(peers)==1 and peers[0]['requiresLegacyProvider'] and peers[0]['rid']==sdk['rid']
                    and sharing['peerArchiveSha256']==peers[0]['archive']['sha256']
                    and sharing['peerSourceManifestSha256']==peers[0]['sourceManifestSha256'] and shared
                    and set(sharing['sharedProviderIds'])==shared and len(sharing['sharedProviderIds'])==len(shared)
                    and all(sharing.get(field) is True for field in ('retainedAfterRemove','targetProviderStatePreserved','unreferencedGc'))
                    and set(sharing['retainedPeerProviderReceipts'])=={provider_id(provider) for provider in providers_for(catalog,peers[0])}
                    and all(re.fullmatch('[a-f0-9]{64}',value) for value in sharing['retainedPeerProviderReceipts'].values()),
                    'Legacy provider sharing/reference removal proof is incomplete')
            recovery=proof.get('toolRollback')
            if sdk['sdkVersion']=='5.0.214':
                require(isinstance(recovery,dict),'Actual tool recovery with installed legacy/provider state is required')
                validate_project_client_migration(recovery.get('migration'),observation,catalog,compatibility_catalog,tool_version)
                public=row['bootstrapBinarySource']=='public-https'
                if public:
                    require(recovery.get('status')=='passed' and recovery.get('protocol')=='actual-0.3.0-recovery-with-installed-legacy-providers'
                            and recovery.get('fromVersion')==tool_version and recovery.get('retainedVersion')=='0.3.0'
                            and recovery.get('oldBinarySha256')==recovery['migration']['oldBinarySha256']
                            and recovery.get('currentBinarySha256')==row['binarySha256']
                            and recovery.get('sdkIds')==sorted(sdk_id(release) for release in (baseline,sdk,peers[0]))
                            and recovery.get('providerIds')==sorted({provider_id(provider) for release in (sdk,peers[0]) for provider in providers_for(catalog,release)})
                            and re.fullmatch('[a-f0-9]{64}',recovery.get('ownedStateBeforeSha256',''))
                            and recovery.get('ownedStateBeforeSha256')==recovery.get('ownedStateAfterSha256')
                            and all(recovery.get(field) is True for field in ('modernSdkExecutedAfterRollback','legacySdkExecutedAfterReupgrade',
                                'peerSdkExecutedAfterReupgrade','allSdkAndProviderInventoriesVerified','selectionAndReceiptsUnchanged')),
                            'Tool rollback changed existing SDK/provider references or could not recover their execution')
                else:
                    require(set(recovery)=={'status','protocol','migration'} and recovery['status']=='public-verification-required'
                            and recovery['protocol']=='protected-frozen-candidate-bootstrap',
                            'A frozen candidate cannot claim an actual unpublished tool rollback')
            else:
                require(recovery is None,'The per-target SDK5 row owns the existing-provider tool rollback proof')
            negatives=proof['negatives']
            fixtures={'revokedSdk':'catalog-v3-revoked.json','revokedProvider':'catalog-v3-provider-revoked.json','incompatibleAbi':'catalog-v3-provider-incompatible.json'}
            expected_fixtures=dict(
                revokedSdk=dict(catalog,revoked=sorted(set(catalog['revoked'])|{sdk_id(release) for release in catalog['sdks'] if release['requiresLegacyProvider']})),
                revokedProvider=dict(catalog,revoked=sorted(set(catalog['revoked'])|{'provider/'+provider_id(provider) for provider in catalog['providers']})),
                incompatibleAbi=dict(catalog,providers=[dict(provider,minimumGlibc='999.0') for provider in catalog['providers']]))
            require(set(negatives)==set(fixtures) and all(value['status']=='passed' and value['fixture']==fixtures[name]
                and value['noPayloadExtracted'] is True and type(value['exitCode']) is int and value['exitCode']!=0
                and value['catalogSha256']==digest(expected_fixtures[name]) for name,value in negatives.items()),
                'Signed negative provider admission fixtures are incomplete')
            environment=proof['managerEnvironment'];base=records[0]['root']
            import legacy_compat
            expected_ca=legacy_compat.environment(dict(sdkVersion=sdk['sdkVersion'],variant=row['variant']),root=base)['SSL_CERT_FILE']
            require(environment['status']=='passed' and environment['scope']=='clean-manager-private-provider-environment'
                    and environment['network']=='none' and environment['userId']==10001 and environment['baseRoot']==base
                    and environment['opensslConfiguration']==base+'/openssl.cnf'
                    and environment['certificateFile']==expected_ca
                    and environment['curlRoot']==(records[1]['root'] if len(records)==2 else '')
                    and environment['libraryPath']==(':'.join(record['root']+'/lib' for record in reversed(records)))
                    and environment['nativeMappings'] and environment['components'], 'Clean-manager private native environment proof is incomplete')
            from native_curl_runtime import decoded_mapping
            expected_components=[entry for entry in providers[0]['manifest']['files'] if entry['type']=='file'
                and (entry['path'].startswith('lib/libcrypto.so.') or sdk['sdkVersion'].startswith('3.') and entry['path'].startswith('lib/libicu'))]
            require(environment['components']==[dict(path=base+'/'+entry['path'],sha256=entry['sha256']) for entry in expected_components],
                    'Clean manager did not prove every required crypto/ICU mapping')
            for component in environment['components']:
                matches=[entry for entry in providers[0]['manifest']['files'] if base+'/'+entry['path']==component['path'] and entry['type']=='file']
                require(len(matches)==1 and matches[0]['sha256']==component['sha256']
                        and any(component['path'] in decoded_mapping(line) for line in environment['nativeMappings']),
                        'Actual child native mapping differs from its signed companion source bytes')
            if sdk['sdkVersion'].startswith('3.'):
                native=proof['nativeCurlHandler']
                require(isinstance(native,dict) and native.get('status')=='passed' and native.get('handler')=='CurlHandler'
                        and native.get('http')==native.get('https')==native.get('httpsDefaultTrust')==native.get('tls12')=='passed'
                        and type(native.get('callbackCount')) is int and native['callbackCount']>0
                        and native.get('network')=='none' and native.get('userId')==10001
                        and native['curl']['path'].startswith(records[1]['root']+'/lib/')
                        and proof['defaultTrust']==dict(httpsDefaultTrust='passed',tls12='passed')
                        and proof['nativeHttpLibraries'] and all(entry['libcurlProviderPath'].startswith(records[1]['root']+'/') for entry in proof['nativeHttpLibraries']),
                        'Core3 forced native CurlHandler/default trust/library proof is incomplete')
                import legacy_curl
                from native_curl_runtime import validate as validate_native_curl
                payload='/home/cbot-multi-sdk/.local/share/cbodotnetup-matrix-'+sdk['sdkVersion']+'/toolchains-v3/'+sdk_id(sdk)+'/content/'+sdk['archiveRoot']+'/payload'
                validate_native_curl('CBODOTNET_NATIVE_CURL_PROOF='+json.dumps(native),sdk['sdkVersion'],payload,records[1]['root'],10001,architecture)
                pins=legacy_curl.runtime_pins(dict(sdkVersion=sdk['sdkVersion'],architecture=dict(public=architecture)))
                require(all(entry['path']==pins['nativeHttp']['path'] and entry['sha256']==pins['nativeHttp']['sha256']
                            for entry in proof['nativeHttpLibraries']), 'Core3 native HTTP source component differs')
            else:
                require(proof['nativeCurlHandler'] is None and proof['nativeHttpLibraries']==[]
                        and proof['defaultTrust']==dict(status='passed',handler='SocketsHttpHandler',defaultTrustHttps='passed',tls12='passed',network='none',userId=10001),
                        'SDK5 ordinary certificate trust proof is incomplete')
            seen.add(key);result.append(dict(sdkVersion=sdk['sdkVersion'],revision=sdk['revision'],rid=sdk['rid'],target=target,
                variant=row['variant'],architecture=architecture,archive=sdk['archive'],sourceManifestSha256=sdk['sourceManifestSha256'],
                providerIds=[provider_id(provider) for provider in providers],status='passed'))
    require(seen==set(expected),'Every admitted legacy SDK/OS/CPU cell needs independent native evidence')
    return sorted(result,key=lambda row:(row['sdkVersion'],row['variant'],row['architecture']))
