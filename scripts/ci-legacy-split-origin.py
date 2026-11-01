#!/usr/bin/env python3
"""Require a fresh, current-generation split CoreCLR/CoreFX/CoreSetup byte chain."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import shutil
import xml.etree.ElementTree as ET
import zipfile

import runpy
LEGACY_ARCH = runpy.run_path(str(Path(__file__).with_name('ci_legacy_arch.py')))
ARCH = LEGACY_ARCH['selected_arch']()

spec = importlib.util.spec_from_file_location('legacy_origin', Path(__file__).with_name('ci-legacy-origin.py'))
origin = importlib.util.module_from_spec(spec); spec.loader.exec_module(origin)
require, fp, same, ordinary, digest = origin.require, origin.fp, origin.same, origin.ordinary, origin.digest


def audit(args, sdk):
    _, version, layout, commit = origin.CONFIG[args.family]
    pins = origin.PINS[args.family]; source = args.source_dir
    roots = {name: source / layout / 'src' / (name + '.' + sha) for name, sha in pins.items()}
    for name, root in roots.items():
        require(ordinary(root / '.git/HEAD').read_text().strip() == pins[name], 'Split component source pin differs')
    clr = roots['coreclr'] / ('bin/Product/Linux.' + ARCH['arch'] + '.Release')
    fx = roots['corefx'] / 'artifacts/bin'; setup = roots['core-setup']
    native_corelib, il_corelib = fp(clr / 'System.Private.CoreLib.dll'), fp(clr / 'IL/System.Private.CoreLib.dll')
    require(native_corelib['sha256'] != il_corelib['sha256'], 'CoreLib is an IL-only copy')
    header = ordinary(clr / 'crossgen').read_bytes()[:20]
    require(header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[18:20], 'little') == ARCH['machine'], 'Native crossgen has the wrong ELF architecture')
    clr_log = roots['coreclr'] / ('bin/Logs/CrossgenCoreLib_Linux.' + ARCH['arch'] + '.Release.log')
    text = ordinary(clr_log).read_text(errors='replace')
    markers = ['Native image ' + str(clr / 'System.Private.CoreLib.dll') + ' generated successfully.',
               "Successfully generated perfmap for native assembly '" + str(clr / 'System.Private.CoreLib.dll') + "'."]
    require(all(marker in text for marker in markers), 'CoreLib native-image/perf-map completion is absent')
    assets_path = setup / 'artifacts/obj/netcoreapp/project.assets.json'
    assets = json.loads(ordinary(assets_path).read_text())
    cache = source / 'packages/restored'
    require(list(assets['packageFolders']) == [str(cache) + '/'], 'CoreSetup restored another package folder')
    feed = source / layout / ('obj/' + ARCH['arch'] + '/Release/blob-feed/packages')
    prefix = 'shared/Microsoft.NETCore.App/' + version + '/'
    tfm = 'netcoreapp' + ('3.0' if args.family == 'core30' else '3.1')
    package_definitions = [
        (('transport.runtime.' + ARCH['rid'] + '.Microsoft.NETCore.Runtime.CoreCLR'), 'coreclr', clr / '.nuget/pkg'),
        (('transport.runtime.' + ARCH['rid'] + '.Microsoft.NETCore.Jit'), 'coreclr', clr / '.nuget/pkg'),
        (('runtime.' + ARCH['rid'] + '.Microsoft.Private.CoreFx.NETCoreApp'), 'corefx', roots['corefx'] / 'artifacts/packages/Release/NonShipping')]
    payloads = {}; packages = []; tools = []
    preserved = args.output_dir / 'reports/construction/split-inputs'; preserved.mkdir()
    shutil.copyfile(assets_path, preserved / 'core-setup-project.assets.json')
    for package_id, component, produced_dir in package_definitions:
        keys = [key for key in assets['libraries'] if key.rsplit('/', 1)[0].lower() == package_id.lower()]
        require(len(keys) == 1, 'Exactly one resolved split package is required')
        key = keys[0]; package_version = key.rsplit('/', 1)[1]; library = assets['libraries'][key]
        relative = package_id.lower() + '/' + package_version
        require(library['type'] == 'package' and library['path'] == relative, 'Unexpected split package resolution')
        filename = package_id + '.' + package_version + '.nupkg'
        producer = produced_dir / filename; published = feed / filename
        produced, published_fp = fp(producer), fp(published); same(produced, published_fp)
        require(library['sha512'] == produced['sha512Base64'], 'Consumed package generation differs from the current producer')
        cached = cache / relative / filename.lower()
        cache_present = cached.exists()
        if cache_present:
            same(produced, fp(cached))
        else:
            live = cache / relative
            require(not live.is_symlink() and (not live.exists() or all(p.is_dir() and not p.is_symlink() for p in live.rglob('*'))),
                    'A partial unexpected consumer package cache remains')
        destination = preserved / filename; shutil.copyfile(producer, destination); same(produced, fp(destination))
        package_row = {'packageId': package_id, 'version': package_version, 'component': component,
                       'componentCommit': pins[component], 'producer': produced, 'feed': published_fp,
                       'assetsSha512Verified': True, 'liveConsumerCachePresent': cache_present,
                       'retainedArchive': fp(destination), 'payloads': []}
        with zipfile.ZipFile(producer) as archive:
            entries = archive.infolist(); names = [entry.filename for entry in entries]
            require(len(names) == len(set(names)), 'Duplicate split package member')
            nuspecs = [n for n in names if n.endswith('.nuspec')]
            require(len(nuspecs) == 1, 'Exactly one split package identity is required')
            xml = ET.fromstring(archive.read(nuspecs[0])); metadata = [node for node in xml if node.tag.rsplit('}', 1)[-1] == 'metadata']
            require(len(metadata) == 1, 'Split package metadata is absent')
            fields = {node.tag.rsplit('}', 1)[-1]: node for node in metadata[0]}
            require(fields['id'].text == package_id and fields['version'].text == package_version
                    and fields['repository'].get('commit') == pins[component], 'Split package identity/source differs')
            for entry in entries:
                name = entry.filename; parsed = PurePosixPath(name)
                require(not parsed.is_absolute() and '..' not in parsed.parts and '\\' not in name, 'Unsafe split archive member')
                basename = parsed.name
                native = name.startswith(('runtimes/' + ARCH['rid'] + '/native/')) and (name.endswith('.so') or basename == 'System.Private.CoreLib.dll')
                managed = component == 'corefx' and name.startswith(('runtimes/' + ARCH['rid'] + '/lib/') + tfm + '/') and name.endswith('.dll')
                tool = name == 'tools/crossgen'
                if not (native or managed or tool):
                    continue
                require(not entry.is_dir() and (entry.external_attr >> 16) & 0o170000 in (0, 0o100000), 'Selected split payload must be regular')
                output = clr / basename if component == 'coreclr' else fx / ('runtime' if managed else 'native') / ('netcoreapp-Linux-Release-' + ARCH['arch']) / basename
                with archive.open(entry) as stream:
                    packed = dict(member=name, **digest(stream))
                built = fp(output); same(packed, built)
                if cache_present:
                    same(packed, fp(cache / relative / name))
                row = {'component': component, 'packageMember': packed, 'componentOutput': built,
                       'managedCoreFxAssembly': managed, 'currentComponentOutputMatchesConsumedGeneration': True}
                package_row['payloads'].append(row)
                if tool:
                    tools.append(row)
                else:
                    require(prefix + basename not in payloads, 'Duplicate split runtime payload')
                    payloads[prefix + basename] = row
        packages.append(package_row)
    managed = sum(row['managedCoreFxAssembly'] for row in payloads.values())
    native_count = len(payloads) - managed
    require(managed == 164 and native_count == 13 and len(tools) == 1, 'Pinned split payload coverage differs')
    for name, member in [('dotnet', 'dotnet'), ('libhostfxr.so', 'host/fxr/' + version + '/libhostfxr.so'),
                         ('libhostpolicy.so', prefix + 'libhostpolicy.so')]:
        payloads[member] = {'component': 'core-setup', 'componentOutput': fp(setup / ('artifacts/bin/' + ARCH['rid'] + '.Release/corehost') / name),
                            'managedCoreFxAssembly': False}
    runtime_path = source / layout / ('obj/' + ARCH['arch'] + '/Release/blob-feed/assets') / ('dotnet-runtime-' + version + ('-' + ARCH['rid'] + '.tar.gz'))
    runtime = origin.tar_tree(runtime_path, payload_only=True)
    require(set(runtime) == set(payloads), 'Every runtime DLL/shared library/dotnet host needs a component producer')
    setup_log = source / layout / 'logs/core-setup.log'; text = ordinary(setup_log).read_text(errors='replace')
    transformations = []
    for member, row in payloads.items():
        actual = runtime[member]; built = row['componentOutput']
        if (actual['bytes'], actual['sha256']) == (built['bytes'], built['sha256']):
            row['transform'] = 'unchanged'
        elif row['managedCoreFxAssembly']:
            generated = setup / ('artifacts/bin/' + ARCH['rid'] + '.Release/crossgen/netcoreapp/runtimes/' + ARCH['rid'] + '/lib') / tfm / PurePosixPath(member).name
            same(fp(generated), actual)
            marker = 'Native image ' + str(generated) + ' generated successfully.'
            require(marker in text, 'Completed CoreFX native-image generation is absent')
            row.update(transform='native-image-generated', nativeImageOutput=fp(generated), successLogMarker=marker)
            transformations.append(member)
        else:
            raise ValueError('A native component payload differs from its runtime archive')
    require(len(transformations) == 162, 'Pinned CoreFX native-image transformation coverage differs')
    final = origin.tar_tree(sdk, payload_only=True)
    for member in payloads:
        same(runtime[member], final[member])
    shutil.copyfile(clr_log, preserved / 'corelib-crossgen.log'); shutil.copyfile(setup_log, preserved / 'core-setup.log')
    return {'schemaVersion': 1, 'status': 'passed', 'sourceCommit': commit, 'componentCommits': pins,
            'sdkArchive': fp(sdk), 'runtimeArchive': fp(runtime_path), 'consumerAssets': fp(preserved / 'core-setup-project.assets.json'),
            'componentPackages': packages, 'runtimePayloads': payloads, 'nativeCrossgenTool': tools[0],
            'finalSdkCompared': True, 'freshCurrentGenerationOnly': True,
            'coreLibNativeImage': {'ilInput': il_corelib, 'nativeOutput': native_corelib, 'nativeOutputDiffersFromIl': True,
                                   'crossgenElfMachine': ARCH['elf'], 'completedLog': fp(preserved / 'corelib-crossgen.log')},
            'counts': {'coreFxManagedPackageAssemblies': managed, 'coreFxNativeImageTransformations': len(transformations),
                       'nativeAndCoreLibPayloads': native_count, 'coreSetupHostOutputs': 3, 'runtimeArchiveMembersVerified': len(payloads)},
            'completeRuntimePayloadCoverage': {'verified': True, 'members': sorted(payloads)},
            'scope': 'Fresh current producer equals root feed equals actual resolved-assets package generation. Live cache presence is explicit. No historical payload exceptions, clean bootstrap or Stage2 assertion.'}
