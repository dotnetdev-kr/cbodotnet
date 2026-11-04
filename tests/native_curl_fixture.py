"""Explicit synthetic Core3 evidence for metadata rejection tests, never a receipt."""
import copy


def evidence(version='3.1.426', arch='x64', channel='deb', sdk_root=None, provider_root=None):
    import legacy_curl as provider
    policy = provider.load_policy()
    plan = dict(sdkVersion=version, architecture=dict(public=arch))
    pins = provider.runtime_pins(plan)
    sdk_root = sdk_root or '/opt/cbodotnet/' + '.'.join(version.split('.')[:2])
    provider_root = provider_root or provider.PROVIDER_ROOT
    native = dict(pins['nativeHttp'], path=sdk_root + '/' + pins['nativeHttp']['path'])
    curl = dict(pins['curl'], path=provider_root + '/' + pins['curl']['path'])
    proof = dict(status='passed', required=True, providerRoot=provider_root, architecture=arch,
        policySha256=provider.policy_hash(), signingFingerprint=provider.FINGERPRINT, treeSha256='1' * 64,
        sourcePackages=copy.deepcopy(policy['architectures'][arch]['packages']), sourceRpmPackages=copy.deepcopy(policy['sources']))
    return dict(nativeHttpCompatibilityProvider=[proof], nativeCurlHandler=dict(status='passed', handler='CurlHandler',
        http='passed', https='passed', httpsDefaultTrust='passed', tls12='passed', callbackCount=1,
        network='none', userId=1654 if channel == 'oci' else 10001, nativeHttp=native, curl=curl,
        nativeMappings=['1000-2000 r-xp 0000 00:00 1 ' + native['path'], '3000-4000 r-xp 0000 00:00 2 ' + curl['path']]))
