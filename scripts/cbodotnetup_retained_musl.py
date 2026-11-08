"""Exact released musl build reports retained across consumer helper maintenance.

These four reports are the immutable public 0.5.0/0.5.1 assets from release run
42387946152. Matching their complete canonical bytes does not admit a new build.
All compiled source inputs, authenticated SDK, actual binary bytes, current
dependency audit and fresh candidate/public native execution are still checked.
"""
import hashlib

from downstream_release import encoded, require

REPORTS = {
    ('0.5.0', 'aarch64'): 'ce696d1103cf09663532f07380266cf1a2b233a10fd0d7ee6f14c899348f23a0',
    ('0.5.0', 'x64'): 'c0382344fb4ed3bfb1c1e78fae9b8d2cf2b9cf02b88c81aa7c13a2f1eb3f36e7',
    ('0.5.1', 'aarch64'): 'f6d80c9be75737ddc885d807fb2ded730de2881347a088226f2437a895872028',
    ('0.5.1', 'x64'): '2b90ffa62cf44c80184a35979b3b3df13a85a9b3724638227193df31cc786fb7',
}


def validate_build_inputs(report, architecture):
    from cbodotnetup_musl_native import build_inputs
    if report.get('buildInputs') == build_inputs(architecture):
        return 'current-reviewed-inputs'
    expected = REPORTS.get((report.get('version'), architecture))
    require(expected is not None and hashlib.sha256(encoded(report)).hexdigest() == expected,
            'Musl build inputs differ from current inputs and every exact retained public build report')
    from cbodotnetup_release import tool_inputs
    # Policy-only catalog sequence/lifetime changes are already excluded by the
    # existing tool source validator. Executable source changes require a release.
    actual = {k: v for k, v in report['sourceInputs'].items() if k != 'releases/cbodotnetup-policy.json'}
    current = {k: v for k, v in tool_inputs().items() if k != 'releases/cbodotnetup-policy.json'}
    require(actual == current, 'A retained musl executable cannot represent changed compiled source inputs')
    return 'exact-retained-public-report'
