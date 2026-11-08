"""Pinned native Alpine source-build routes for the .NET 8 and 9 VMRs."""
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = {
    '9.0.123': dict(source='9f04b57d1366e21b3178648493d6edffeff2216e', bootstrap='9.0.121',
                  runtime='9.0.22', sourceOnly=False,
                  runtimeSource='faaecba82df8933d7af60972138ce25f9c776cbd',
                  aspnetSource='5aeb916d29e761492c987f1c09895c3ba9cbe1ac'),
    '8.0.133': dict(source='7d1bf90885cff22e7da72b27e9848e42fd3cb1ae', bootstrap='8.0.131',
                  runtime='8.0.33', sourceOnly=True,
                  runtimeSource='da7a9beabf4cccc624399d583f52f080a4c858c2',
                  aspnetSource='380bd0d498fbaa0a8ddd67c325aa748dd21f7596'),
}
ARCHITECTURES = {
    'x64': dict(machine='x86_64', image='amd64', upstream='x64', rid='linux-musl-x64'),
    'aarch64': dict(machine='aarch64', image='arm64', upstream='arm64', rid='linux-musl-arm64'),
}
NET9_ADDITIONAL_PACKAGES = [dict(id='NETStandard.Library.NETFramework', version='2.0.1-servicing-26011-01',
    fileName='netstandard.library.netframework.2.0.1-servicing-26011-01.nupkg',
    url='https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet-public/nuget/v3/flat2/netstandard.library.netframework/2.0.1-servicing-26011-01/netstandard.library.netframework.2.0.1-servicing-26011-01.nupkg',
    bytes=1844646, sha256='218dd4c63d3f800de697bca41178827a52df0a9ec7a9b47520327d91ebc7051c',
    sha512='714a0fad007482d3bdacd4e4d88460003c0dc2e97f326525bdddc5ac0a09151951a45817de436ceb753aa766f3b8ae421fefc074a617698291e3f663146930fc',
    correspondingSource=dict(root='vmr', path='src/source-build-assets/src/targetPacks/ILsrc/netstandard.library.netframework/2.0.1-servicing-26011-01',
                             tree='e149c55e5c641bbac5906cc12db0dbcfcbd778f9', kind='complete-upstream-il-and-msbuild-source'))]


def require(value, message):
    if not value:
        raise ValueError(message)


def profile(sdk, arch, root=ROOT):
    require(sdk in VERSIONS and arch in ARCHITECTURES, 'Unreviewed modern musl source route')
    path = root / 'profiles' / ('dotnet-' + sdk + '-linux-musl-' + arch + '.json')
    value = json.loads(path.read_text(encoding='utf-8'))
    expected, target = VERSIONS[sdk], ARCHITECTURES[arch]
    require(value.get('additionalPackages') == (NET9_ADDITIONAL_PACKAGES if sdk.startswith('9.') else []),
            'Reviewed exact additional targeting input/source pin differs')
    require(value['sdkVersion'] == sdk and value['source']['commit'] == expected['source']
            and value['source']['tag'] == 'v' + sdk and value['source']['repository'] == 'https://github.com/dotnet/dotnet'
            and value['target'] == dict(rid=target['rid'], libc='musl')
            and value['host'] == dict(os='linux', architecture=target['upstream'], emulation=False), 'Source/CPU/libc pin differs')
    require(value['bootstrap']['version'] == expected['bootstrap'] and value['bootstrap']['rid'] == target['rid']
            and re.fullmatch('[a-f0-9]{128}', value['bootstrap']['sha512'])
            and value['bootstrap']['url'] == 'https://builds.dotnet.microsoft.com/dotnet/Sdk/' + expected['bootstrap']
            + '/dotnet-sdk-' + expected['bootstrap'] + '-' + target['rid'] + '.tar.gz', 'Native bootstrap pin differs')
    build = value['build']
    require(build['sourceOnly'] is expected['sourceOnly'] and build['crossBuild'] is False
            and build['portableBuild'] is True and build['cleanWhileBuilding'] is False
            and build['maxCpuCount'] == 2 and build['compiler'] == '/usr/bin/clang-20'
            and build['cxxCompiler'] == '/usr/bin/clang++-20', 'Reviewed native toolchain route differs')
    require(value['container']['version'] == '3.24.4'
            and value['upstreamInputs']['runtime'] == expected['runtime']
            and value['qualification']['status'] == 'pending', 'Unreviewed Alpine/runtime qualification route')
    for packages in ('buildPackages', 'runtimePackages'):
        require(not any(p['P'] in ('gcompat', 'libc6-compat', 'glibc') for p in value[packages]),
                'glibc compatibility providers are forbidden')
        require(any(p['P'] == 'icu-data-full' for p in value[packages]), 'Full ICU data is mandatory')
    kerberos = [p for p in value['buildPackages'] if p['P'] == 'krb5-dev']
    require(len(kerberos) == 1 and kerberos[0]['V'] == '1.22.2-r1'
            and kerberos[0]['c'] == '92bc4f0d36aa5307e819fb57167fc19952cf515f'
            and kerberos[0]['repository'] == 'main', 'Native runtime Kerberos development input differs')
    supplemental = value.get('supplementalSourceGit', [])
    require(hashlib.sha256(json.dumps(supplemental, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        == ('2689b350bceb0b6a082a4d2dc9f79e828532f7fb3f1f869162bf440c254c02a8' if expected['sourceOnly']
            else '1d079cb10bdbdae5924077bbb8d7010e8e5a9e0e7a6cbd28103c51539cee7570'),
        'Reviewed serviced package/source/license registry differs')
    reference_audit = dict(path='scripts/musl-reference-audit-policy.json',
        sha256='a225d95dc15db8025320de1736a8d6ee68683894375168cca63057a28a9780ba')
    require(build.get('referenceAuditDisposition') == (reference_audit if expected['sourceOnly'] else None),
            'Unreviewed reference-only audit disposition')
    if expected['sourceOnly']:
        require(hashlib.sha256((root / reference_audit['path']).read_bytes()).hexdigest() == reference_audit['sha256'],
                'Reference-only audit policy bytes differ')
    expected_patches = ({'patches/net8/0002-preserve-portable-aspnetcore-target.patch':
                         'b03fab8085c959debc05892fb1920edaa8f514f90d4189994de23608abcc7d8a',
                         'patches/musl/net8/0001-retain-reference-audit-warnings.patch':
                         'ab698abeac802febfd8dc1f27c7c05784911bed55c84d1df49f3de5e98f45daf',
                         'patches/musl/net8/0002-service-arcade-build-dependencies.patch':
                         '639c9cb360475f35a87db9bd338c3165ab909f7d5d698b57df1e0d8edfc5a434',
                         'patches/musl/net8/0003-select-native-musl-aspnet-crossgen-host.patch':
                         '8a2ef25b59eedac11d4b061048be3d4b93796399899e7bf9e1884d7220f9cec4'} if expected['sourceOnly'] else {
                         'patches/musl/net9/0001-use-fixed-build-helper-msbuild.patch':
                         '444916928c5c78a8232c3baba53b7d0c2d09ea4ad9bd4fe3536b1b11055b823e',
                         'patches/musl/net9/0002-use-fixed-build-helper-asn1.patch':
                         '862fbb3852f396d93c4033bbfba256531a54d0210916271c0eea5eec6b9de395',
                         'patches/musl/net9/0003-use-fixed-templating-nuget.patch':
                         '579ba989c5ec56a046b7d1e1b2aa6549d892102063effe02a25a1e9e91cce6ee',
                         'patches/musl/net9/0004-use-fixed-razor-messagepack.patch':
                         '0e3b9b14eca6c9dd5033479cc92af92892aac069f5b16e2a92e0f6b15f26b1d4',
                         'patches/musl/net9/0005-preserve-native-aspnetcore-musl-target.patch':
                         '71bff321157426db0e31940b48816851e80146d8af5c4c80fde40f9e243574e5',
                         'patches/musl/net9/0006-use-maintained-fsharp-test-telemetry.patch':
                         'a9c383a8f9d6b55c702698aec507025948cb21eeedb047801e7128eb84a7409f',
                         'patches/musl/net9/0007-stabilize-locally-built-nuget-version.patch':
                         '437746010a829cb1ec9be55e730c62a6c0a4ee0a0c600062340ff40accf71774',
                         'patches/musl/net9/0008-use-native-musl-sdk-installer-crossgen-host.patch':
                         'a548dfb8f18250d1f634d4aafd24bbdc132c4dd81ee03946560d252209351ff4'})
    require(len(build['patches']) == len(expected_patches)
            and {p['path'] for p in build['patches']} == set(expected_patches), 'Unreviewed source patch set')
    for patch in build['patches']:
        require(patch['sha256'] == expected_patches[patch['path']]
                and hashlib.sha256((root / patch['path']).read_bytes()).hexdigest() == patch['sha256'],
                'Native musl source patch differs')
    return value


def build_command(sdk, arch, test=False, official_archive=None):
    """Use each tag's real switches; never relabel a glibc invocation."""
    value = profile(sdk, arch)
    target = ARCHITECTURES[arch]
    environment = ['env', '-u', 'ROOTFS_DIR', '-u', 'CLR_CC', '-u', 'CLR_CXX', '-u', 'CrossBuild',
                   'CC=/usr/bin/clang-20', 'CXX=/usr/bin/clang++-20',
                   'CLR_CC=/usr/bin/clang-20', 'CLR_CXX=/usr/bin/clang++-20',
                   'CppCompilerAndLinker=/usr/bin/clang-20', 'PortableBuild=true', 'CrossBuild=false']
    if sdk.startswith('9.'):
        command = ['./build.sh', '--configuration', 'Release', '--rid', target['rid'], '--ci', '--binaryLog',
                   '/p:TargetArchitecture=' + target['upstream'], '/p:TargetOS=linux-musl',
                   '/p:CrossBuild=false', '/p:PortableBuild=true', '/m:2']
        if test:
            require(official_archive == '/inputs/official-sdk.tar.gz', 'Exact musl upstream comparison archive required')
            command += ['--test', '/p:UBTestsMsftSdkArchivePath=' + official_archive]
    else:
        environment += ['BUILD_SOURCEVERSION=' + value['source']['commit']]
        command = ['./build.sh', '--online', '--with-sdk', '/vmr/.dotnet']
        if test:
            require(official_archive == '/inputs/official-sdk.tar.gz', 'Exact musl upstream comparison archive required')
            environment += ['RUNNING_IN_CI=true', 'SMOKE_TESTS_RUNNING_IN_CI=true',
                            'SMOKE_TESTS_WARN_SDK_CONTENT_DIFFS=true',
                            'SMOKE_TESTS_MSFT_SDK_TARBALL_PATH=' + official_archive]
            command += ['--run-smoke-test']
        command += ['--', '/p:Configuration=Release', '/p:Platform=' + target['upstream'],
                    '/p:TargetOS=Linux', '/p:TargetRid=' + target['rid'],
                    '/p:PortableBuild=true', '/p:CrossBuild=false', '/m:2']
    return environment + command


def parse_upstream_results(sdk, arch, trx, scenario=None):
    """Check every emitted result and counter; record identities for independent review."""
    ns = {'t': 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'}
    root = ET.parse(trx).getroot()
    rows = root.findall('./t:Results/t:UnitTestResult', ns)
    counters = root.find('./t:ResultSummary/t:Counters', ns)
    require(counters is not None and rows and len({r.get('executionId') for r in rows}) == len(rows),
            'Actual complete uniquely identified upstream TRX required')
    skipped = {'LicenseScanTests.ScanForLicenses', 'PoisonTests.VerifyUsage'} if sdk.startswith('8.') else set()
    actual_skips = [r for r in rows if r.get('outcome') != 'Passed']
    require({'.'.join(r.get('testName', '').split('.')[-2:]) for r in actual_skips} == skipped
            and len(actual_skips) == len(skipped) and all(r.get('outcome') == 'NotExecuted' for r in actual_skips),
            'Unexpected upstream test failure or skip')
    passed = len(rows) - len(skipped)
    require(all(int(counters.get(k, '-1')) == v for k, v in
                dict(total=len(rows), executed=passed, passed=passed, failed=0).items()),
            'Actual upstream counters differ')
    require((len(rows) == 46 if sdk.startswith('8.') else len(rows) == 522), 'Incomplete upstream test graph')
    result = dict(total=len(rows), passed=passed, skipped=len(skipped), failed=0,
                  skippedTests=sorted(skipped), testNames=sorted(r.get('testName') for r in rows))
    if sdk.startswith('9.'):
        # Source/graph-identical package theories use the native musl RID.
        # Derive only the eight target-RID package names; the pinned source
        # methods, complete universe and unavailable baseline policy stay fixed.
        policy = json.loads((ROOT / 'scripts/ci-net9-test-cases.json').read_text())
        require(policy['sourceCommit'] == VERSIONS[sdk]['source'] and len(policy['shippingPackageIds']) == 262,
                'Pinned NET9 package graph differs')
        packages = {name.replace('linux-arm64', ARCHITECTURES[arch]['rid']) for name in policy['shippingPackageIds']}
        available = packages - set(policy['unavailableBaselineIds'])
        expected = {(method, name) for method in policy['packageMethods'] for name in available}
        found, facts = set(), set()
        for row in rows:
            name = row.get('testName', '')
            if name in policy['factMethods']:
                require(name not in facts, 'Duplicate original NET9 SDK fact')
                facts.add(name)
                continue
            methods = [method for method in policy['packageMethods'] if name.startswith(method + '(packageName: "')]
            require(len(methods) == 1 and name.endswith(')'), 'Unexpected original NET9 package theory identity')
            method = methods[0]
            argument = name[len(method + '(packageName: "'):].split(', testNugetPackagePath: ', 1)
            require(len(argument) == 2 and ', baselineNugetPackagePath: ' in argument[1], 'Malformed NET9 package theory')
            choices = [package for package in available
                       if argument[0] == (package[:50] + '"···' if len(package) > 50 else package + '"')]
            require(len(choices) == 1 and (method, choices[0]) not in found, 'Unexpected/duplicate NET9 musl package case')
            found.add((method, choices[0]))
        require(found == expected and facts == set(policy['factMethods']), 'Complete exact NET9 musl package graph required')
        result['packageCases'] = dict(packageIdentities=len(available), packageTheoryResults=len(found), sdkFacts=len(facts),
                                      unavailableBaselineIds=policy['unavailableBaselineIds'])
        require(scenario is not None, 'Actual NET9 scenario XML required')
        suites = ET.parse(scenario).getroot()
        assemblies = suites.findall('./assembly')
        tests = suites.findall('./assembly/collection/test')
        require(len(assemblies) == 1 and len(tests) == 34 and len({t.get('name') for t in tests}) == 34,
                'All 34 original NET9 scenarios required')
        counts = {k: sum(t.get('result') == label for t in tests)
                  for k, label in [('passed', 'Pass'), ('failed', 'Fail'), ('skipped', 'Skip')]}
        require(counts == dict(passed=32, failed=0, skipped=2)
                and {t.get('method') for t in tests if t.get('result') == 'Skip'}
                == {'VerifyWorkloadCmd', 'VerifyAspireTemplate'}, 'Unexpected NET9 scenario outcome')
        result['scenarios'] = dict(total=34, **counts, testNames=sorted(t.get('name') for t in tests))
    return result
