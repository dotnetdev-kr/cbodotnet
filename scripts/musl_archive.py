"""Independent native-musl archive construction and Alpine consumer qualification."""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import stat
import subprocess
import tarfile
import time

import musl_contract as CONTRACT
from downstream_release import descriptor, encoded, ordinary_file, require

ROOT = CONTRACT.ROOT
ARCHITECTURES = CONTRACT.ARCHITECTURES
BRANDING = CONTRACT.BRANDING
BASES = {
    'x64': 'alpine:3.24.4@sha256:0f49f331d9212aff11b932863be4eb01cdf962969aa86dab7d1ee21ac6f5f52b',
    'aarch64': 'alpine:3.24.4@sha256:1829893486be257df5049ab3b7fc95afbd0fc09d89803cbc580bda1ba5386b29',
}
RUNTIME_PACKAGES = {
    'musl': '1.2.6-r3', 'ca-certificates': '20261020-r0', 'libgcc': '15.2.0-r5',
    'libstdc++': '15.2.0-r5', 'libssl3': '3.5.9-r0', 'libcrypto3': '3.5.9-r0',
    'icu-libs': '78.1-r0', 'icu-data-full': '78.1-r0', 'tzdata': '2026f-r0',
    'krb5-libs': '1.22.2-r1', 'zlib': '1.4-r0',
    'brotli-libs': '1.2.1-r0', 'lttng-ust': '2.14.2-r0',
}
FUNCTIONAL_CHECKS = {
    'consoleDllExecution', 'consoleApphostExecution', 'aspNetCoreLoopbackHttp',
    'rsaSha256SignAndVerify', 'cryptographicRandomBytes', 'frFrDecimalFormatting',
    'tls12LoopbackHandshake', 'fullIcuCulturesAndCalendars', 'timeZoneDatabase',
}
REPORT_CHECKS = {
    'source-integrity', 'payload-preservation', 'original-notices', 'wrapper-license',
    'command-aliases', 'cli-branding', 'version-stdout-compatible', 'sdk-list-paths',
    'host-root-rid', 'relocation', 'non-root', 'offline-network', 'offline-build-run',
    'complete-payload-elf-audit', 'stock-native-dependency-closure', 'system-trust-https',
}


def tools():
    specification = importlib.util.spec_from_file_location('musl_sdk_tree', ROOT / 'scripts/test-distribution-coexistence.py')
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def fresh_directory(value):
    path = Path(value).absolute()
    require(path.parent.is_dir() and not path.exists() and not path.is_symlink()
            and not any(parent.is_symlink() for parent in path.parents), 'A fresh ordinary directory is required')
    path.mkdir(mode=0o755)
    return path


def plan_architecture(plan):
    architecture = plan.get('architecture')
    public = architecture.get('public') if isinstance(architecture, dict) else architecture
    require(public in ARCHITECTURES and (not isinstance(architecture, dict) or architecture == ARCHITECTURES[public])
            and plan.get('libc') == 'musl' and plan.get('targetRid') == ARCHITECTURES[public]['rid'],
            'An explicit matching musl plan architecture/libc/RID is required')
    return public


def identity(plan):
    plan_architecture(plan)
    return {key: plan[key] for key in ('sdkVersion', 'producerRevision', 'packageRevision', 'libc',
                                      'targetRid', 'sourceReleaseTag', 'sourceManifestSha256')}


def launcher_text(plan, root=None):
    """A relocatable archive wrapper, or the same isolated host at a fixed APK root."""
    arch = plan_architecture(plan)
    CONTRACT.version_revision(plan['sdkVersion'], plan['packageRevision'])
    information = dict(schemaVersion=1, contractVersion=plan['contractVersion'], distributionBrand=BRANDING['displayName'],
        **identity(plan), brandingScope='distribution-wrapper', qualifiedPayloadModified=False,
        delivery='consumer-archive' if root is None else plan['channel'])
    template = (ROOT / 'scripts/cbodotnet-archive-launcher.sh.in').read_text(encoding='utf-8')
    if root is not None:
        path = PurePosixPath(root)
        require(isinstance(root, str) and path.is_absolute() and str(path) == root and root != '/'
                and '..' not in path.parts and not any(char in root for char in '\\:\0\r\n'), 'Unsafe musl SDK root')
        # The existing template's only root assignment is replaced before token expansion.
        require(template.count('DOTNET_ROOT=$directory/payload') == 1, 'Unexpected archive launcher root template')
        template = template.replace('DOTNET_ROOT=$directory/payload', 'DOTNET_ROOT=' + shlex.quote(root))
    prefix = json.dumps(information, separators=(',', ':'))[:-1] + ',"sdkRoot":"'
    replacements = {'@ARCH_ROOT@': 'DOTNET_ROOT_X64' if arch == 'x64' else 'DOTNET_ROOT_ARM64',
        '@BRAND@': shlex.quote(BRANDING['displayName']), '@IDENTITY_PREFIX@': shlex.quote(prefix),
        '@IDENTITY_SUFFIX@': shlex.quote('"}'), '@COMPAT@': ''}
    result = re.sub(r'@(?:ARCH_ROOT|BRAND|IDENTITY_PREFIX|IDENTITY_SUFFIX|COMPAT)@',
                    lambda match: replacements[match[0]], template)
    require(not re.search(r'@[A-Z_]+@', result), 'Unresolved musl launcher token')
    return result


def intake(inputs, arch, revision=1, *, contract=None, catalog=None):
    inputs = Path(inputs)
    return CONTRACT.verified_plan(json.loads(ordinary_file(inputs / 'release.json').read_bytes()),
        ordinary_file(inputs / 'release-manifest.json').read_bytes(), ordinary_file(inputs / 'SHA256SUMS').read_bytes(),
        inputs / json.loads(ordinary_file(inputs / 'release-manifest.json').read_bytes())['architectures'][arch]['sdk']['name'],
        'archive', 'alpine-3.24', arch, revision, contract=contract, catalog=catalog)


def payload_summary(rows):
    return dict(sha256=hashlib.sha256(encoded(rows)).hexdigest(), entries=len(rows),
                files=sum(row[0] == 'file' for row in rows.values()), links=sum(row[0] == 'link' for row in rows.values()))


def archive_stem(plan):
    return f'cbodotnet-{plan["sdkVersion"]}-linux-musl-{plan_architecture(plan)}-r{plan["packageRevision"]}'


def build_archive(inputs, architecture, revision, output, *, contract=None, catalog=None):
    plan = intake(inputs, architecture, revision, contract=contract, catalog=catalog)
    output = fresh_directory(output)
    tree = output / archive_stem(plan)
    tree.mkdir(mode=0o755)
    payload = tree / 'payload'
    api = tools()
    api.extract_sdk(Path(inputs) / plan['sdk']['name'], payload)
    original = api.snapshot(payload)
    require((payload / 'dotnet').is_file() and not (payload / 'dotnet').is_symlink()
            and os.access(payload / 'dotnet', os.X_OK), 'Musl SDK payload has no ordinary executable host')
    for name in plan['licensePaths']:
        ordinary_file(payload / name)
    added = []
    for name in plan['additionalDirectories']:
        require(name == 'metadata', 'Unreviewed musl payload addition')
        path = payload / name
        if not path.exists():
            path.mkdir(mode=0o755)
            added.append(name)
    wrapper = launcher_text(plan).encode()
    commands = []
    for name in ('dotnet', 'cbodotnet', 'cbodotnet-' + '.'.join(plan['sdkVersion'].split('.')[:2])):
        path = tree / name
        path.write_bytes(wrapper)
        path.chmod(0o755)
        commands.append(dict(path=name, mode='0755', size=len(wrapper), sha256=hashlib.sha256(wrapper).hexdigest()))
    license_path = tree / 'LICENSE.wrapper.txt'
    license_path.write_bytes(ordinary_file(ROOT / 'LICENSE').read_bytes())
    license_path.chmod(0o644)
    (tree / 'distribution.json').write_bytes(encoded(dict(plan, payloadDirectory='payload', additionalDirectories=added)))
    (tree / 'README.txt').write_text(BRANDING['displayName'] + '\n\n'
        'Target user space: native musl Linux on Alpine 3.24.4. Verify the signed release evidence before use.\n'
        'Run ./cbodotnet, ./cbodotnet-10.0 or ./dotnet. The unchanged SDK is under payload/.\n'
        'Direct apphosts need DOTNET_ROOT set to the absolute payload/ directory.\n'
        'Original notices: payload/LICENSE.txt and payload/ThirdPartyNotices.txt.\n'
        'Additional wrappers: LICENSE.wrapper.txt (the project MIT notice).\n'
        'NativeAOT and workloads are not qualified. cbodotnetup admission is tracked separately in issue 30.\n'
        'Source and producer evidence: ' + plan['sourceManifestUrl'] + '\n', encoding='utf-8')
    current = api.snapshot(payload)
    require({key: value for key, value in current.items() if key not in added} == original,
            'Musl construction changed qualified payload bytes, links or modes')
    archive = output / CONTRACT.archive_name(plan['sdkVersion'], architecture, revision)
    with archive.open('xb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0, compresslevel=6) as compressed:
        with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as tar:
            for path in [tree, *sorted(tree.rglob('*'))]:
                entry = tar.gettarinfo(str(path), path.relative_to(output).as_posix())
                entry.uid = entry.gid = entry.mtime = 0
                entry.uname = entry.gname = ''
                if entry.isfile():
                    with path.open('rb') as content:
                        tar.addfile(entry, content)
                else:
                    tar.addfile(entry)
    result = dict(schemaVersion=1, kind='musl-consumer-archive-build', status='built-unpublished', publicationAllowed=False,
        archiveLayoutVersion=1, plan=plan, artifact=descriptor(archive), directory=tree.name, commands=commands,
        wrapperLicense=dict(descriptor(license_path), mode='0644'), qualifiedPayload=payload_summary(original), additionalDirectories=added)
    (output / 'package-build.json').write_bytes(encoded(result))
    return result


def run(arguments, *, cwd=None, env=None):
    result = subprocess.run(list(map(str, arguments)), cwd=cwd, env=env, text=True, capture_output=True)
    require(result.returncode == 0, 'Musl qualification command failed: ' + str(arguments[0]) + '\n'
            + result.stdout[-9000:] + result.stderr[-9000:])
    return result.stdout


def native_guard(architecture):
    require(architecture in ARCHITECTURES and platform.system() == 'Linux'
            and platform.machine() == ('x86_64' if architecture == 'x64' else 'aarch64'),
            'A matching native Linux CPU is mandatory; emulation is not accepted')
    require(Path('/etc/alpine-release').is_file() and Path('/etc/alpine-release').read_text().strip() == '3.24.4'
            and Path(ARCHITECTURES[architecture]['interpreter']).is_file(), 'The exact reviewed Alpine musl user space is required')
    require(not os.environ.get('LD_LIBRARY_PATH') and not os.environ.get('LD_PRELOAD'),
            'Native closure audit requires a clean loader environment')
    installed = run(['apk', 'info']).splitlines()
    require(not set(installed) & {'gcompat', 'libc6-compat', 'glibc'}, 'Glibc compatibility layers are forbidden')


def inspect_elf(path):
    output = run(['readelf', '--wide', '--file-header', '--program-headers', '--dynamic', '--version-info', path])
    machine = re.search(r'^\s*Machine:\s*(.+)$', output, re.MULTILINE)
    elf_type = re.search(r'^\s*Type:\s*(\S+)', output, re.MULTILINE)
    elf_class = re.search(r'^\s*Class:\s*(\S+)', output, re.MULTILINE)
    interpreter = re.search(r'\[Requesting program interpreter:\s*([^\]]+)\]', output)
    version_needs = output.split('Version needs section', 1)[-1] if 'Version needs section' in output else ''
    needs = {}
    current = None
    for line in version_needs.splitlines():
        file_match = re.search(r'\bFile:\s*(\S+)\s+Cnt:', line)
        if file_match:
            current = file_match[1]
            require(current not in needs, 'Duplicate ELF version-needs provider')
            needs[current] = []
        name_match = re.search(r'\bName:\s*(\S+)', line)
        if name_match:
            require(current is not None, 'ELF version need has no provider')
            needs[current].append(name_match[1])
    definitions = output.split('Version definition section', 1)[-1] if 'Version definition section' in output else ''
    definitions = definitions.split('Version needs section', 1)[0]
    return dict(machine=machine.group(1).strip() if machine else None, elfType=elf_type.group(1) if elf_type else None,
        elfClass=elf_class.group(1) if elf_class else None, interpreter=interpreter.group(1) if interpreter else None,
        needed=re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', output),
        runpaths=[item for group in re.findall(r'\((?:RUNPATH|RPATH)\).*?\[([^\]]*)\]', output) for item in group.split(':')],
        glibcRequirements=sorted(set(re.findall(r'\bGLIBC_[A-Za-z0-9_.]+', version_needs))),
        versionNeeds=[dict(file=name, versions=versions) for name, versions in needs.items()],
        versionDefinitions=sorted(set(re.findall(r'\bName:\s*(\S+)', definitions))))


def reviewed_gcc_abi_labels(record):
    """GLIBC_2.0 on libgcc_s is GCC's unwind ABI label, never a libc exemption."""
    observed = [(row['file'], version) for row in record.get('versionNeeds', [])
                for version in row['versions'] if version.startswith('GLIBC_')]
    require(sorted(version for _, version in observed) == record['glibcRequirements'],
            'ELF GLIBC version requirements have no complete provider attribution')
    require(all(file == 'libgcc_s.so.1' and version == 'GLIBC_2.0' for file, version in observed),
            'Host ELF has genuine glibc version requirements')
    return [dict(file=file, version=version, disposition='gcc-unwind-abi-label') for file, version in observed]


def target_classifications(policy, payload, architecture):
    require(isinstance(policy, list), 'An explicit non-host target policy list is required')
    classified = {}
    pattern = r'packs/Microsoft\.NETCore\.App\.(?:Host|Runtime)\.(linux-(?:musl-)?(?:x64|arm64))/[^/]+/runtimes/([^/]+)/native/[^/]+'
    for row in policy:
        require(isinstance(row, dict) and set(row) == {'path', 'sha256', 'targetRid', 'reason'}
                and isinstance(row.get('path'), str), 'Invalid non-host target classification')
        match = re.fullmatch(pattern, row['path'])
        require(match is not None and match[1] == match[2] == row['targetRid']
                and row['targetRid'] != ARCHITECTURES[architecture]['rid']
                and isinstance(row.get('reason'), str) and row['reason'].strip()
                and re.fullmatch(r'[a-f0-9]{64}', row.get('sha256', '')) and row['path'] not in classified,
                'Non-host exemption must identify an exact foreign RID pack file')
        path = ordinary_file(payload / row['path'])
        require(descriptor(path)['sha256'] == row['sha256'], 'Non-host target-pack bytes changed')
        classified[row['path']] = row
    return classified


def resolve_system_path(candidate, root):
    """Resolve exported image links inside their virtual root, never the host /lib."""
    root, candidate = Path(root), Path(candidate)
    require(root == candidate or root in candidate.parents, 'System library candidate is outside its reviewed root')
    pending = list(candidate.relative_to(root).parts)
    resolved, links = root, 0
    while pending:
        part = pending.pop(0)
        if part == '.':
            continue
        if part == '..':
            require(resolved != root, 'Exported system library link escapes its root')
            resolved = resolved.parent
            continue
        path = resolved / part
        if path.is_symlink():
            links += 1
            require(links <= 40, 'Exported system library link cycle')
            target = PurePosixPath(os.readlink(path))
            require(not any(char in str(target) for char in '\\\0\r\n'), 'Unsafe exported library link target')
            if target.is_absolute():
                resolved = root
                pending = list(target.parts[1:]) + pending
            else:
                pending = list(target.parts) + pending
        else:
            if not path.exists():
                return None
            resolved = path
    return resolved if resolved.is_file() else None


def audit_elf(payload, architecture, target_policy=None, *, system_root=Path('/'), native=True):
    """Inspect every regular ELF; resolve host DT_NEEDED transitively to stock APKs."""
    require(architecture in ARCHITECTURES, 'Unknown musl audit architecture')
    payload = Path(payload).resolve(strict=True)
    system_root = Path(system_root).resolve(strict=True)
    if native:
        require(system_root == Path('/'), 'Native musl closure must use the actual Alpine root')
        native_guard(architecture)
    classified = target_classifications(target_policy or [], payload, architecture)
    rows, links, static_archives, system = [], [], [], {}
    used_classifications = set()
    expected = ARCHITECTURES[architecture]

    def inspected(path):
        record = dict(path=str(path), **descriptor(path), **inspect_elf(path))
        require(record['elfClass'] == 'ELF64' and record['machine'] == expected['elfMachine']
                and record['elfType'] in {'DYN', 'EXEC', 'REL'}, 'Host ELF has the wrong architecture, class or type: ' + str(path))
        require(record['interpreter'] in (None, expected['interpreter']),
                'Host ELF has a non-musl interpreter: ' + str(path))
        record['reviewedAbiVersionLabels'] = reviewed_gcc_abi_labels(record)
        require(all(re.fullmatch(r'[A-Za-z0-9._+-]+', name) for name in record['needed']), 'Unsafe ELF dependency name')
        return record

    def search_directories(record, path):
        result = []
        for item in record['runpaths']:
            require(item and '\x00' not in item, 'Empty or unsafe ELF runpath')
            expanded = item.replace('${ORIGIN}', str(path.parent)).replace('$ORIGIN', str(path.parent))
            require('$' not in expanded and expanded.startswith('/'), 'Unreviewed ELF loader token or relative runpath')
            virtual = Path(expanded)
            if virtual in {Path('/lib'), Path('/usr/lib'), Path('/usr/local/lib')}:
                directory = system_root / virtual.relative_to('/')
            else:
                directory = virtual.resolve()
                require(directory == payload or payload in directory.parents, 'ELF runpath escapes reviewed roots')
            result.append(directory)
        return result + [system_root / 'lib', system_root / 'usr/local/lib', system_root / 'usr/lib']

    def closure(path, record, visiting):
        dependencies = []
        for needed in record['needed']:
            candidates = [directory / needed for directory in search_directories(record, path)]
            resolved = None
            for item in candidates:
                if item == payload or payload in item.parents:
                    target = item.resolve(strict=False)
                    require(payload in target.parents, 'Payload native library link escapes its root')
                    if target.is_file():
                        resolved = target
                else:
                    resolved = resolve_system_path(item, system_root)
                if resolved is not None:
                    break
            require(resolved is not None, 'Unresolved native ELF dependency: ' + needed + ' from ' + str(path))
            own = resolved == payload or payload in resolved.parents
            require(own or any(base == resolved or base in resolved.parents
                    for base in (system_root / 'lib', system_root / 'usr/lib', system_root / 'usr/local/lib')),
                    'Resolved ELF dependency escapes reviewed roots')
            if own:
                require(resolved.relative_to(payload).as_posix() not in classified, 'Host dependency resolves to a non-host target pack')
            key = str(resolved)
            if key not in visiting:
                visiting.add(key)
                provider = inspected(resolved)
                provider['dependencies'] = closure(resolved, provider, visiting)
                if not own:
                    if native:
                        provider['apkOwner'] = run(['apk', 'info', '--who-owns', resolved]).strip()
                        require(provider['apkOwner'], 'Native library is not owned by a stock APK')
                    system[key] = provider
            labels = [row for row in record['reviewedAbiVersionLabels'] if row['file'] == needed]
            if labels:
                require(not own and needed == 'libgcc_s.so.1', 'GCC unwind ABI label must resolve to stock system libgcc')
                provider = system.get(key)
                require(provider is not None and 'GLIBC_2.0' in provider.get('versionDefinitions', []),
                        'Stock libgcc does not define the reviewed GCC unwind ABI version label')
                if native:
                    require(provider.get('apkOwner', '').endswith(' is owned by libgcc-' + RUNTIME_PACKAGES['libgcc']),
                            'GCC unwind ABI label provider is not the exact reviewed stock libgcc APK')
            dependencies.append(dict(needed=needed, resolved=key, provider='payload' if own else 'stock-system',
                                     sha256=descriptor(resolved)['sha256']))
        return dependencies

    for path in sorted(payload.rglob('*')):
        relative = path.relative_to(payload).as_posix()
        if path.is_symlink():
            resolved = path.resolve(strict=True)
            require(payload in resolved.parents and resolved.is_file(), 'Payload link escapes its ordinary file root')
            links.append(dict(path=relative, target=os.readlink(path), resolved=resolved.relative_to(payload).as_posix()))
            continue
        if not path.is_file():
            require(path.is_dir(), 'Unsupported payload filesystem object')
            continue
        with path.open('rb') as stream:
            magic = stream.read(8)
        if magic.startswith(b'!<arch>\n'):
            static_archives.append(dict(path=relative, **descriptor(path), disposition='target-link-input-not-executed'))
        if not magic.startswith(b'\x7fELF'):
            continue
        if relative in classified:
            row = classified[relative]
            observed = inspect_elf(path)
            rid_arch = 'aarch64' if row['targetRid'].endswith('arm64') else 'x64'
            require(observed['machine'] == ARCHITECTURES[rid_arch]['elfMachine'], 'Foreign target-pack ELF machine differs from declared RID')
            rows.append(dict(path=relative, **descriptor(path), **observed, disposition='non-host-target-pack', classification=row))
            used_classifications.add(relative)
        else:
            record = inspected(path)
            record['path'] = relative
            if relative == 'dotnet':
                require(record['interpreter'] == expected['interpreter'] and record['elfType'] in {'DYN', 'EXEC'},
                        'Musl SDK host lacks the matching native interpreter')
            record['dependencies'] = closure(path, record, {str(path)})
            record['disposition'] = 'host-runtime-or-tool'
            rows.append(record)
    require(any(row['path'] == 'dotnet' and row['disposition'] == 'host-runtime-or-tool' for row in rows),
            'Complete payload audit did not find the native dotnet host')
    require(used_classifications == set(classified), 'Unused non-host target classification is not permitted')
    return dict(schemaVersion=1, scope='musl-complete-payload-elf-closure', status='passed', native=native, libc='musl',
        architecture=architecture, targetRid=expected['rid'], elfFiles=rows, symlinks=links,
        stockLibraries=[system[key] for key in sorted(system)], nativeLinkArchives=static_archives,
        staticArchiveScope='Recorded target link inputs; NativeAOT and workloads are not qualified.',
        hostElfCount=sum(row['disposition'] == 'host-runtime-or-tool' for row in rows),
        nonHostElfCount=sum(row['disposition'] == 'non-host-target-pack' for row in rows))


def full_smoke_script(plan, payload, cli, workdir, *, expected_user='cbot-musl'):
    """Real DLL/apphost, ASP.NET, RSA, TLS, full ICU and timezone checks offline."""
    from sdk_runtime import smoke_script
    require(isinstance(expected_user, str) and re.fullmatch(r'[a-z_][a-z0-9_-]*', expected_user),
            'An explicit ordinary non-root smoke-test user is required')
    script = smoke_script(plan['sdkVersion'], str(payload), expected_user, cli=str(cli), workdir=str(workdir))
    additional = '''
  var cultureNames=new[]{"fr-FR","ko-KR","ar-SA","th-TH","ja-JP"};
  foreach(var name in cultureNames) {
   var culture=CultureInfo.GetCultureInfo(name);
   if(culture.Name!=name || culture.DateTimeFormat.MonthNames[0].Length==0) throw new Exception("Full ICU culture "+name);
  }
  var calendarDate=new DateTime(2026,1,1);
  if(!CultureInfo.GetCultureInfo("th-TH").OptionalCalendars.Any(calendar=>calendar is ThaiBuddhistCalendar)
   || new ThaiBuddhistCalendar().GetYear(calendarDate)!=2569) throw new Exception("Thai calendar");
  if(!CultureInfo.GetCultureInfo("ar-SA").OptionalCalendars.Any(calendar=>calendar is UmAlQuraCalendar)
   || new UmAlQuraCalendar().GetYear(calendarDate)!=1447) throw new Exception("Arabic calendar");
  if(CultureInfo.GetCultureInfo("ko-KR").CompareInfo.Compare("가","나")>=0) throw new Exception("Korean collation");
  var instant=new DateTimeOffset(2026,1,1,0,0,0,TimeSpan.Zero);
  if(TimeZoneInfo.FindSystemTimeZoneById("Asia/Seoul").GetUtcOffset(instant)!=TimeSpan.FromHours(9)
   || TimeZoneInfo.FindSystemTimeZoneById("Europe/Paris").GetUtcOffset(instant)!=TimeSpan.FromHours(1)) throw new Exception("tzdata");
  Console.WriteLine("published-full-icu-calendars-timezones-passed");
'''
    marker = '  var tls=CheckTls();'
    require(script.count(marker) == 1, 'Unexpected pure smoke program template')
    return script.replace(marker, additional + marker)


def trust_probe_script(plan, payload, cli, workdir):
    """Build the system-trust HTTPS probe offline; its later invocation is online."""
    project = '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Exe</OutputType></PropertyGroup></Project>'
    program = '''using System; using System.Net.Http; using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
public static class Program { public static async Task Main() {
 using(var roots=new X509Store(StoreName.Root,StoreLocation.LocalMachine)) {
  roots.Open(OpenFlags.ReadOnly); if(roots.Certificates.Count<20) throw new Exception("System CA trust store absent");
  Console.WriteLine("system-root-count="+roots.Certificates.Count);
 }
 using(var handler=new HttpClientHandler()) {
  handler.UseProxy=false;
  using(var client=new HttpClient(handler)) {
   client.Timeout=TimeSpan.FromSeconds(45);
   using(var request=new HttpRequestMessage(HttpMethod.Head,"TRUST_URL"))
   using(var response=await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead)) {
    response.EnsureSuccessStatusCode();
    if(response.RequestMessage.RequestUri.Scheme!="https") throw new Exception("HTTPS redirect downgrade");
    Console.WriteLine("system-trust-https-passed");
   }
  }
 }
}}
'''.replace('TRUST_URL', trust_url(plan_architecture(plan)))
    return ('set -eu\nmkdir -p ' + shlex.quote(str(workdir)) + '\ncd ' + shlex.quote(str(workdir))
        + '\ncat > global.json <<\'GLOBAL\'\n' + json.dumps(dict(sdk=dict(version=plan['sdkVersion'], rollForward='disable'))) + '\nGLOBAL'
        + '\ncat > NuGet.Config <<\'NUGET\'\n<configuration><packageSources><clear /></packageSources></configuration>\nNUGET'
        + '\ncat > Trust.csproj <<\'PROJECT\'\n' + project + '\nPROJECT'
        + '\ncat > Program.cs <<\'PROGRAM\'\n' + program + '\nPROGRAM\n'
        + shlex.quote(str(cli)) + ' restore --configfile NuGet.Config\n'
        + shlex.quote(str(cli)) + ' build --no-restore\n')


def trust_url(architecture):
    require(architecture in ARCHITECTURES, 'An explicit system-trust probe architecture is required')
    return 'https://dl-cdn.alpinelinux.org/alpine/v3.24/main/' + ARCHITECTURES[architecture]['apk'] + '/APKINDEX.tar.gz'


def installed(build_directory, architecture, workspace, target_policy=None):
    native_guard(architecture)
    require(os.geteuid() == 10001 and os.getegid() == 10001, 'Actual non-root UID/GID 10001 qualification is required')
    require({path.name for path in Path('/sys/class/net').iterdir()} == {'lo'}, 'Actual network-none qualification is required')
    build_directory, workspace = Path(build_directory), Path(workspace)
    build = json.loads(ordinary_file(build_directory / 'package-build.json').read_bytes())
    plan = build['plan']
    require(plan_architecture(plan) == architecture, 'Qualification architecture differs from built SDK')
    archive = ordinary_file(build_directory / build['artifact']['name'])
    require(descriptor(archive) == build['artifact'], 'Consumer archive changed before native qualification')
    api = tools()
    extracted = workspace / 'original'
    api.extract_sdk(archive, extracted)
    source_tree = extracted / build['directory']
    require(source_tree.is_dir() and {path.name for path in extracted.iterdir()} == {build['directory']},
            'Consumer archive has an unexpected top-level root')
    relocated = workspace / 'relocated musl archive'
    source_tree.rename(relocated)
    payload = relocated / 'payload'
    original = api.snapshot(payload)
    require(payload_summary({key: value for key, value in original.items() if key not in build['additionalDirectories']})
            == build['qualifiedPayload'], 'Consumer payload differs from its qualified producer snapshot')
    require(ordinary_file(relocated / 'LICENSE.wrapper.txt').read_bytes() == ordinary_file(ROOT / 'LICENSE').read_bytes(),
            'Consumer wrapper license changed')
    commands = []
    environment = dict(os.environ, HOME='/home/cbot-musl', DOTNET_CLI_HOME='/home/cbot-musl/cli',
        NUGET_PACKAGES='/home/cbot-musl/nuget', DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',
        DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE='true',
        DOTNET_NOLOGO='1', DOTNET_CLI_UI_LANGUAGE='en-US', LC_ALL='C')
    for name in ('LD_LIBRARY_PATH', 'LD_PRELOAD', 'DOTNET_ROOT', 'DOTNET_ROOT_X64', 'DOTNET_ROOT_ARM64',
                 'DOTNET_HOST_PATH', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'DOTNET_SYSTEM_GLOBALIZATION_INVARIANT'):
        environment.pop(name, None)
    for name in ('dotnet', 'cbodotnet', 'cbodotnet-' + '.'.join(plan['sdkVersion'].split('.')[:2])):
        command = relocated / name
        require(command.read_text() == launcher_text(plan) and stat.S_IMODE(command.stat().st_mode) == 0o755,
                'Consumer wrapper bytes or mode changed')
        result = subprocess.run([str(command), '--version'], env=environment, capture_output=True, text=True)
        require(result.returncode == 0 and result.stdout == plan['sdkVersion'] + '\n'
                and result.stderr == BRANDING['displayName'] + '\n', 'Musl alias numeric stdout/branding stderr differs')
        information = json.loads(run([command, '--cbodotnet-info'], env=environment))
        require(all(information.get(key) == value for key, value in identity(plan).items())
                and information.get('sdkRoot') == str(payload) and information.get('qualifiedPayloadModified') is False,
                'Musl alias source/root identity differs')
        require(run([command, '--list-sdks'], env=environment).splitlines()
                == [plan['sdkVersion'] + ' [' + str(payload / 'sdk') + ']'], 'Musl SDK selection escaped its root')
        info = run([command, '--info'], env=environment)
        require(info.startswith(BRANDING['displayName'] + '\n') and str(payload) in info
                and re.search(r'^\s*RID:\s*' + re.escape(plan['targetRid']) + r'\s*$', info, re.MULTILINE),
                'Musl host brand/root/RID differs')
        commands.append(dict(command=name, targetRid=plan['targetRid'], sdkRoot=str(payload)))
    elf = audit_elf(payload, architecture, target_policy)
    (workspace / 'elf-audit.json').write_bytes(encoded(elf))
    cli = relocated / 'cbodotnet'
    from sdk_runtime import validate_smoke_output
    output = run(['sh', '-ec', full_smoke_script(plan, payload, cli, workspace / 'offline-project')], env=environment)
    functional = validate_smoke_output(output)
    require(output.count('published-full-icu-calendars-timezones-passed') >= 2,
            'Both DLL and apphost must pass full ICU cultures/calendars/timezone tests')
    functional.update(fullIcuCulturesAndCalendars='passed', timeZoneDatabase='passed')
    (workspace / 'functional.txt').write_text(output)
    run(['sh', '-ec', trust_probe_script(plan, payload, cli, workspace / 'system-trust')], env=environment)
    # A missing archive host cannot fall back to a system dotnet on PATH.
    host = payload / 'dotnet'
    hidden = payload / 'dotnet.hidden'
    host.rename(hidden)
    try:
        result = subprocess.run([str(cli), '--version'], env=environment, capture_output=True, text=True)
        require(result.returncode != 0, 'Musl wrapper fell back when its selected host was absent')
    finally:
        hidden.rename(host)
    require(api.snapshot(payload) == original, 'Non-root execution changed qualified musl payload bytes, links or modes')
    for notice in plan['licensePaths']:
        require(api.snapshot(payload).get(notice) == original.get(notice), 'Original musl notices changed')
    (workspace / 'offline-report.json').write_bytes(encoded(dict(schemaVersion=1, scope='musl-consumer-archive-offline',
        status='passed', architecture=architecture, libc='musl', targetRid=plan['targetRid'], native=True,
        networkForBuild='none', uid=os.geteuid(), gid=os.getegid(), identity=identity(plan), archive=build['artifact'],
        checks=dict.fromkeys(REPORT_CHECKS - {'system-trust-https'}, 'passed'), functionalChecks=functional,
        commands=commands, elfAudit=descriptor(workspace / 'elf-audit.json'),
        dependencies=run(['apk', 'info', '-v']).splitlines(), caBundle=descriptor(Path('/etc/ssl/cert.pem').resolve(strict=True)),
        trustProbe=str(workspace / 'system-trust/bin/Debug/net10.0/Trust.dll'), cli=str(cli), payload=str(payload))))
    return dict(status='passed', scope='musl-consumer-archive-offline')


def native(build_directory, architecture, workspace, target_policy=None):
    require(platform.system() == 'Linux' and platform.machine() == ('x86_64' if architecture == 'x64' else 'aarch64'),
            'A matching native Linux Docker host is mandatory')
    build_directory = Path(build_directory).resolve(strict=True)
    workspace = fresh_directory(workspace)
    workspace.chmod(0o777)
    build = json.loads(ordinary_file(build_directory / 'package-build.json').read_bytes())
    require(plan_architecture(build['plan']) == architecture, 'Native Docker architecture differs from build')
    server_architecture = run(['docker', 'info', '--format', '{{.Architecture}}']).strip()
    require(server_architecture in ({'x86_64', 'amd64'} if architecture == 'x64' else {'aarch64', 'arm64'}),
            'Docker server must use the same native CPU; remote cross-CPU execution is not accepted')
    policy_path = workspace / 'target-policy.json'
    policy_path.write_bytes(encoded(target_policy or []))
    containerfile = workspace / 'Containerfile'
    package_pins = [name + '=' + version for name, version in RUNTIME_PACKAGES.items()]
    containerfile.write_text('FROM ' + BASES[architecture] + '\nRUN apk add --no-cache '
        + ' '.join(package_pins) + ' python3 binutils && '
        'test "$(cat /etc/alpine-release)" = 3.24.4 && ! command -v dotnet && '
        '! apk info | grep -E "^(dotnet|aspnetcore|gcompat|libc6-compat|glibc)" && '
        'addgroup -g 10001 cbot-musl && adduser -D -u 10001 -G cbot-musl cbot-musl\n', encoding='utf-8')
    image = 'cbodotnet-musl-qualification:' + architecture + '-' + str(time.time_ns())
    run(['docker', 'build', '--pull=false', '--network=default', '-f', containerfile, '-t', image, workspace])
    image_info = json.loads(run(['docker', 'image', 'inspect', image]))[0]
    require(image_info.get('Architecture') == ('amd64' if architecture == 'x64' else 'arm64')
            and image_info.get('Os') == 'linux', 'Prepared qualification image has another native CPU')
    common = ['docker', 'run', '--rm', '--user', '10001:10001', '--cap-drop=ALL', '--security-opt=no-new-privileges',
        '-v', str(ROOT) + ':/project:ro', '-v', str(build_directory) + ':/build:ro',
        '-v', str(workspace) + ':/qualification', '-e', 'PYTHONDONTWRITEBYTECODE=1', '-w', '/project']
    run([*common, '--network=none', image, 'python3', 'scripts/musl_archive.py', 'installed', '--build', '/build',
        '--arch', architecture, '--workspace', '/qualification', '--target-policy', '/qualification/target-policy.json'])
    offline = json.loads(ordinary_file(workspace / 'offline-report.json').read_bytes())
    trust = run([*common, '--network=default', '-e', 'HOME=/home/cbot-musl', '-e', 'DOTNET_CLI_HOME=/home/cbot-musl/cli',
        image, offline['cli'], offline['trustProbe']])
    require('system-trust-https-passed' in trust and re.search(r'system-root-count=[1-9][0-9]+', trust),
            'Real HTTPS with the stock system CA trust failed')
    (workspace / 'system-trust.txt').write_text(trust)
    report = dict(schemaVersion=1, scope='musl-consumer-archive-installation', status='passed', architecture=architecture,
        libc='musl', targetRid=build['plan']['targetRid'], native=True, networkForBuild='none', identity=identity(build['plan']),
        artifact=build['artifact'], checks=dict.fromkeys(REPORT_CHECKS, 'passed'), functionalChecks=offline['functionalChecks'],
        userSpaces=[dict(variant='alpine-3.24', alpineVersion='3.24.4', base=BASES[architecture], imageId=image_info['Id'],
            uid=10001, gid=10001, status='passed', offline=offline,
            elfAudit=json.loads(ordinary_file(workspace / 'elf-audit.json').read_bytes()),
            systemTrustHttps=dict(status='passed', network='default-only-after-offline-build',
                url=trust_url(architecture), outputSha256=hashlib.sha256(trust.encode()).hexdigest()))])
    (workspace / 'report.json').write_bytes(encoded(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('build')
    build.add_argument('--inputs', type=Path, required=True)
    build.add_argument('--arch', choices=tuple(ARCHITECTURES), required=True)
    build.add_argument('--revision', type=int, default=1)
    build.add_argument('--output', type=Path, required=True)
    audit = commands.add_parser('audit')
    audit.add_argument('--payload', type=Path, required=True)
    audit.add_argument('--arch', choices=tuple(ARCHITECTURES), required=True)
    audit.add_argument('--target-policy', type=Path)
    audit.add_argument('--output', type=Path, required=True)
    for name in ('native', 'installed'):
        command = commands.add_parser(name)
        command.add_argument('--build', type=Path, required=True)
        command.add_argument('--arch', choices=tuple(ARCHITECTURES), required=True)
        command.add_argument('--workspace', type=Path, required=True)
        command.add_argument('--target-policy', type=Path)
    args = parser.parse_args()
    if args.command == 'build':
        result = build_archive(args.inputs, args.arch, args.revision, args.output)
    elif args.command == 'audit':
        policy = json.loads(args.target_policy.read_bytes()) if args.target_policy else []
        result = audit_elf(args.payload, args.arch, policy)
        require(not args.output.exists(), 'Fresh ELF audit output required')
        args.output.write_bytes(encoded(result))
    else:
        policy = json.loads(args.target_policy.read_bytes()) if args.target_policy else []
        result = (native if args.command == 'native' else installed)(args.build, args.arch, args.workspace, policy)
    print(json.dumps(dict(status='passed', kind=result.get('kind', result.get('scope')))))


if __name__ == '__main__':
    main()
