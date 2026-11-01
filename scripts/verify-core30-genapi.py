#!/usr/bin/env python3
"""Require valid original GenAPI host settings and real native code generation."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import runpy
import stat
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile

import runpy
LEGACY_ARCH = runpy.run_path(str(Path(__file__).with_name('ci_legacy_arch.py')))
ARCH = LEGACY_ARCH['selected_arch']()

ARCADE = 'ce459ae07c3d7a1e68251268855e0bc7b3d97f75'
ROOT = '40de72d1087a1d05dfd39c87f888a0611ec6c60f'
VERSION = '1.0.0-beta.19463.3'


def check_configuration(value):
    options = value['runtimeOptions']
    if (options['tfm'] != 'netcoreapp2.1' or options['framework']['name'] != 'Microsoft.NETCore.App' or
            options['framework']['version'] != '2.1.0' or options.get('rollForwardOnNoCandidateFx') != 2 or
            'rollForward' in options or 'applyPatches' in options):
        raise ValueError('GenAPI must retain only its original supported major-roll-forward setting2; dual host policies are invalid')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=['arm64', 'x64'], default='arm64')
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--reference-root', type=Path, required=True)
    parser.add_argument('--reports-dir', type=Path, required=True)
    parser.add_argument('--input-report', type=Path, required=True)
    args = parser.parse_args()
    helper = runpy.run_path(str(Path(__file__).resolve().with_name('prepare-core30-bootstrap.py')))
    directory, ordinary, fingerprint = helper['directory'], helper['ordinary_file'], helper['fingerprint']
    source, refs, reports = directory(args.source_dir), directory(args.reference_root), directory(args.reports_dir)
    if platform.system() != 'Linux' or platform.machine().lower() not in (ARCH['uname'], ARCH['arch']):
        raise ValueError('Native Linux ARM64 execution is required')
    if helper['git'](source, 'rev-parse', 'HEAD').decode().strip() != ROOT:
        raise ValueError('The pinned source root differs')
    input_report = ordinary(args.input_report)
    verified = json.loads(input_report.read_text())
    if (verified['status'] != 'passed' or verified['sourceCommit'] != ROOT or verified['sourceDirectory'] != str(source) or
            verified['bootstrapVersion'] != '3.0.100' or verified['bootstrapExecutionVerified'] is not True):
        raise ValueError('Bind the actual earlier verified bootstrap-input report')
    expected_bootstrap = {str(source / '.dotnet' / name) for name in ['dotnet', 'sdk/3.0.100/MSBuild.dll', 'sdk/3.0.100/.version']}
    if {row['path'] for row in verified['bootstrapFiles']} != expected_bootstrap:
        raise ValueError('The verified bootstrap-file set differs')
    for row in verified['bootstrapFiles']:
        actual = fingerprint(ordinary(Path(row['path'])))
        if any(actual[name] != row[name] for name in ('bytes', 'sha256')):
            raise ValueError('An actually verified bootstrap file changed')
    dotnet = ordinary(source / '.dotnet/dotnet')
    with dotnet.open('rb') as stream:
        header = stream.read(20)
    if header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != ARCH['machine']:
        raise ValueError('The actual bootstrap host is not ELF64 AArch64')
    output = reports / 'genapi-validation.json'
    if output.exists() or output.is_symlink() or source == reports or source in reports.parents:
        raise ValueError('Use a fresh external GenAPI validation report directory')
    component = directory(source / ('bin/src/arcade.' + ARCADE))
    if ordinary(component / '.git/HEAD').read_text().strip() != ARCADE:
        raise ValueError('The pinned GenAPI producer differs')
    template_relative = 'src/Microsoft.DotNet.GenAPI/runtimeconfig.template.json'
    template = ordinary(component / template_relative)
    original = helper['git'](source, '--git-dir=' + str(source / '.git/modules/src/arcade.git'), 'show', ARCADE + ':' + template_relative)
    if template.read_bytes() != original or json.loads(original.decode('utf-8-sig')) != {'rollForwardOnNoCandidateFx': 2}:
        raise ValueError('The original GenAPI major-roll-forward template changed')
    package = ordinary(component / ('artifacts/packages/Release/NonShipping/Microsoft.DotNet.GenAPI.' + VERSION + '.nupkg'))
    record = {'schemaVersion': 1, 'status': 'running', 'startedAtUtc': helper['now'](), 'arcadeCommit': ARCADE,
              'originalRuntimeTemplate': dict({'path': str(template)}, **fingerprint(template)),
              'sourceProducedPackage': dict({'path': str(package)}, **fingerprint(package)), 'commands': [],
              'nativePlatform': {'system': platform.system(), 'machine': platform.machine()},
              'verifiedBootstrapInputReport': dict({'path': str(input_report)}, **fingerprint(input_report)),
              'verifiedBootstrapFiles': verified['bootstrapFiles'],
              'sdkBuildCompletionClaimed': False, 'executedWindowsOutput': False,
              'scope': 'Validate the locally source-built GenAPI tool before normal package publication/CoreFX use. Reject invalid host-policy combinations, run native Linux help and actual bounded reference-source generation. No package/runtimeconfig source is edited and no Windows output is executed.'}
    try:
        tool = ordinary(component / 'artifacts/bin/Microsoft.DotNet.GenAPI/Release/netcoreapp2.1/Microsoft.DotNet.GenAPI.dll')
        config = ordinary(tool.with_name('Microsoft.DotNet.GenAPI.runtimeconfig.json'))
        config_bytes = config.read_bytes()
        check_configuration(json.loads(config_bytes.decode('utf-8-sig')))
        with zipfile.ZipFile(str(package)) as archive:
            names = set()
            for item in archive.infolist():
                name = PurePosixPath(item.filename)
                normalized = name.as_posix() + ('/' if item.is_dir() else '')
                mode = item.external_attr >> 16
                if (name.is_absolute() or '..' in name.parts or '\\' in item.filename or '\x00' in item.filename or
                        normalized != item.filename or item.filename in names or stat.S_ISLNK(mode) or
                        stat.S_IFMT(mode) not in (0, stat.S_IFDIR, stat.S_IFREG)):
                    raise ValueError('An ambiguous or unsafe GenAPI package member is present')
                names.add(item.filename)
            nuspecs = [name for name in names if '/' not in name and name.endswith('.nuspec')]
            if len(nuspecs) != 1:
                raise ValueError('The source-produced GenAPI nuspec differs')
            metadata = next(item for item in ET.fromstring(archive.read(nuspecs[0])) if item.tag.rsplit('}', 1)[-1] == 'metadata')
            fields = {item.tag.rsplit('}', 1)[-1]: item for item in metadata}
            if fields['id'].text != 'Microsoft.DotNet.GenAPI' or fields['version'].text != VERSION or fields['repository'].get('commit') != ARCADE:
                raise ValueError('The actual source-produced GenAPI package identity differs')
            for tfm, extension in [('net472', '.exe'), ('netcoreapp2.1', '.dll')]:
                member = 'tools/' + tfm + '/Microsoft.DotNet.GenAPI' + extension
                local = ordinary(component / ('artifacts/bin/Microsoft.DotNet.GenAPI/Release/' + tfm + '/Microsoft.DotNet.GenAPI' + extension))
                if archive.read(member) != local.read_bytes():
                    raise ValueError('The original framework tool payload differs from its source-produced package')
            if archive.read('tools/netcoreapp2.1/Microsoft.DotNet.GenAPI.runtimeconfig.json') != config_bytes:
                raise ValueError('The packaged and source-output runtime settings differ')
        home = Path(tempfile.mkdtemp(prefix='cbodotnet-core30-genapi-', dir='/tmp'))
        os.chmod(str(home), 0o700)
        runtime = home / 'runtime'
        runtime.mkdir(mode=0o700)
        if stat.S_IMODE(home.stat().st_mode) != 0o700 or stat.S_IMODE(runtime.stat().st_mode) != 0o700:
            raise ValueError('Native private execution state must have mode0700')
        record['privateExecutionState'] = {'home': str(home), 'xdgRuntimeDirectory': str(runtime),
                                           'mode': '0700', 'nativeTemporaryDirectory': True, 'archived': False}
        environment = os.environ.copy()
        for name in ['DOTNET_ROLL_FORWARD', 'DOTNET_ROLL_FORWARD_ON_NO_CANDIDATE_FX', 'DOTNET_APPLY_PATCHES']:
            environment.pop(name, None)
        environment.update({'HOME': str(home), 'DOTNET_CLI_HOME': str(home), 'XDG_RUNTIME_DIR': str(runtime),
                            'DOTNET_GENERATE_ASPNET_CERTIFICATE': 'false', 'DOTNET_MULTILEVEL_LOOKUP': '0',
                            'DOTNET_CLI_TELEMETRY_OPTOUT': '1', 'DOTNET_SKIP_FIRST_TIME_EXPERIENCE': '1'})
        command = [str(dotnet), str(tool), '--help']
        helper['run'](command, reports, environment, reports / 'genapi-help.log', record['commands'])
        input_path = ordinary(refs / '.NETFramework/v4.7.2/System.ComponentModel.DataAnnotations.dll')
        generated = reports / 'DataAnnotations.notsupported.cs'
        if generated.exists() or generated.is_symlink():
            raise ValueError('Refusing a previous generation-probe output')
        command = [str(dotnet), str(tool), str(input_path), '--lib-path',
                   str(refs / '.NETFramework/v4.7.2') + ';' + str(refs / '.NETFramework/v4.7.2/Facades'),
                   '--out', str(generated), '--lang-version', 'preview', '--throw', 'SR.PlatformNotSupported_GenApiProbe', '--global']
        helper['run'](command, reports, environment, reports / 'genapi-generation.log', record['commands'])
        generated_text = ordinary(generated).read_text(encoding='utf-8-sig')
        if not (100 < generated.stat().st_size < 4 * 1024 * 1024) or 'ValidationAttribute' not in generated_text or 'PlatformNotSupported_GenApiProbe' not in generated_text:
            raise ValueError('The real GenAPI reference-generation probe output is incomplete')
        record.update({'status': 'passed', 'actualTool': dict({'path': str(tool)}, **fingerprint(tool)),
                       'runtimeConfiguration': dict({'path': str(config), 'value': json.loads(config_bytes.decode('utf-8-sig'))}, **fingerprint(config)),
                       'hostConfigurationValid': True, 'nativeHelpExitCode': record['commands'][0]['exitCode'],
                       'actualGenerationExitCode': record['commands'][1]['exitCode'],
                       'generationInputReferenceAssembly': dict({'path': str(input_path), 'prebuiltReferenceInput': True}, **fingerprint(input_path)),
                       'generatedSource': dict({'path': str(generated)}, **fingerprint(generated))})
        if fingerprint(package) != {key: record['sourceProducedPackage'][key] for key in ('bytes', 'sha256', 'sha512')}:
            raise ValueError('The GenAPI package changed during validation')
        return 0
    except Exception as error:
        record.update({'status': 'failed', 'error': str(error)})
        raise
    finally:
        record['finishedAtUtc'] = helper['now']()
        helper['write_json'](output, record)
        print(json.dumps({'status': record['status'], 'report': str(output), 'sdkBuildCompletionClaimed': False}))


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, ET.ParseError, zipfile.BadZipFile) as error:
        raise SystemExit('error: ' + str(error))
