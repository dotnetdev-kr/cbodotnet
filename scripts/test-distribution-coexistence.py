#!/usr/bin/env python3
"""Exercise the contract launcher with real official and qualified SDKs as a user."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import posixpath
import re
import shutil
import stat
import subprocess
import tarfile

from distribution_contract import verified_plan
from distribution_commands import stage_commands


def require(value, message):
    if not value:
        raise ValueError(message)


def sha256(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def snapshot(root):
    """Include names, file bytes, links and permissions, without following links."""
    result = {}
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root).as_posix()
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            result[relative] = ['link', mode, os.readlink(path)]
        elif path.is_file():
            result[relative] = ['file', mode, sha256(path)]
        elif path.is_dir():
            result[relative] = ['directory', mode]
        else:
            raise ValueError('Unexpected installed file type: ' + str(path))
    return result


def extract_sdk(archive_path, destination):
    """Extract only ordinary members and contained file links into a fresh root."""
    require(not destination.exists() and not destination.is_symlink(), 'SDK root must be fresh')
    with tarfile.open(archive_path, 'r:gz') as archive:
        entries = archive.getmembers()
        require(0 < len(entries) <= 200000, 'Unexpected SDK archive member count')
        members = {}
        for entry in entries:
            name = posixpath.normpath(entry.name)
            path = PurePosixPath(name)
            require(not path.is_absolute() and '..' not in path.parts
                    and not any(c in entry.name for c in '\\:\0\r\n'), 'Unsafe SDK archive member')
            require(name not in members, 'Duplicate SDK archive member')
            require((entry.isdir() or entry.isfile() or entry.issym() or entry.islnk())
                    and not entry.mode & 0o7000, 'Unsafe SDK archive type or permission bits')
            require(name != '.' or entry.isdir(), 'Invalid SDK archive root')
            members[name] = entry
        # Requiring links to ordinary files avoids cycles, directory links and
        # link-parent extraction attacks while retaining ordinary SDK file links.
        for name, entry in members.items():
            for parent in PurePosixPath(name).parents:
                if str(parent) in members:
                    require(members[str(parent)].isdir(), 'SDK member has a non-directory parent')
            if entry.issym() or entry.islnk():
                require(not entry.linkname.startswith('/')
                        and not any(c in entry.linkname for c in '\\:\0\r\n'), 'Unsafe SDK link')
                target = posixpath.normpath(posixpath.join(posixpath.dirname(name), entry.linkname)
                                           if entry.issym() else entry.linkname)
                require(target in members and members[target].isfile(), 'SDK link must name an ordinary archive file')
        require(sum(entry.size for entry in entries) + 512 * 1024**2
                < shutil.disk_usage(destination.parent).free, 'Insufficient SDK extraction space')
        destination.mkdir(mode=0o755)
        for name, entry in members.items():
            if name == '.':
                continue
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if entry.isdir():
                path.mkdir(exist_ok=True)
            elif entry.isfile():
                with archive.extractfile(entry) as source, path.open('xb') as output:
                    shutil.copyfileobj(source, output)
            else:
                continue
            os.chmod(path, entry.mode & 0o777)
        for name, entry in members.items():
            if entry.issym():
                (destination / name).symlink_to(entry.linkname)
            elif entry.islnk():
                os.link(destination / posixpath.normpath(entry.linkname), destination / name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk-archive', required=True, type=Path)
    parser.add_argument('--release-json', required=True, type=Path)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--checksums', required=True, type=Path)
    parser.add_argument('--official-dotnet', required=True, type=Path)
    parser.add_argument('--work-dir', required=True, type=Path)
    parser.add_argument('--arch', required=True, choices=('x64', 'aarch64'))
    parser.add_argument('--variant', default='ubuntu-24.04')
    parser.add_argument('--mode', choices=('package', 'oci'), default='package',
                        help='Test native commands or the container command layout in a private prefix')
    args = parser.parse_args()
    require(platform.system() == 'Linux' and os.geteuid() != 0, 'Run this smoke test as a non-root Linux user')
    require(platform.machine() in ({'aarch64', 'arm64'} if args.arch == 'aarch64' else {'x86_64'}),
            'A native matching architecture is required')
    plan = verified_plan(json.loads(args.release_json.read_text()), args.manifest.read_bytes(),
                         args.checksums.read_bytes(), args.sdk_archive, 'deb', args.variant, args.arch)
    official = args.official_dotnet.resolve(strict=True)
    require(official.is_file() and official.name == 'dotnet' and os.access(official, os.X_OK),
            'An existing official dotnet executable is required')
    work = args.work_dir.absolute()
    require(not work.exists() and not work.is_symlink() and work.parent.is_dir(), 'Use a fresh work directory')
    require(not any(path.is_symlink() for path in work.parents), 'Use an ordinary work directory')
    require(official.parent != work and work not in official.parents and official.parent not in work.parents,
            'The official SDK and test prefix must be separate')
    work.mkdir(mode=0o700)
    prefix = work / 'prefix'
    sdk = prefix / plan['package']['root'].lstrip('/')
    launcher = prefix / plan['package']['launcher'].lstrip('/')
    sdk.parent.mkdir(parents=True)
    launcher.parent.mkdir(parents=True)
    command_bin = prefix / ('usr/local/bin' if args.mode == 'oci' else 'usr/bin')
    env = dict(os.environ, PATH=str(command_bin) + os.pathsep + str(official.parent) + os.pathsep + os.environ.get('PATH', ''),
               DOTNET_CLI_HOME=str(work / 'home'), NUGET_PACKAGES=str(work / 'nuget'),
               DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1', DOTNET_NOLOGO='1',
               DOTNET_CLI_UI_LANGUAGE='en', LC_ALL='C',
               DOTNET_ROOT=str(official.parent), DOTNET_ROOT_X64=str(official.parent),
               DOTNET_ROOT_ARM64=str(official.parent), DOTNET_HOST_PATH=str(official))

    def run(command, directory=work):
        result = subprocess.run([str(item) for item in command], cwd=directory, env=env,
                                text=True, capture_output=True)
        if result.returncode:
            raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)
        return result.stdout

    original_version = run(['dotnet', '--version']).strip()
    require(Path(shutil.which('dotnet', path=env['PATH'])).resolve() == official, 'Official PATH resolution changed')
    # Complete the official SDK's own first-use initialization before comparing
    # its installation across the cbodotnet install/use/removal operation.
    official_before = snapshot(official.parent)
    extract_sdk(args.sdk_archive, sdk)
    require((sdk / 'dotnet').is_file() and not (sdk / 'dotnet').is_symlink()
            and os.access(sdk / 'dotnet', os.X_OK), 'Archive has no ordinary executable dotnet host')
    additional_directories = plan['additionalDirectories']
    for name in additional_directories:
        relative = PurePosixPath(name)
        require(name and str(relative) == name and not relative.is_absolute()
                and '..' not in relative.parts and name != '.'
                and not any(c in name for c in '\\:\0\r\n'), 'Unsafe additional SDK directory')
        path = sdk / name
        require(not path.exists() and not path.is_symlink(), 'Additional directory would overlay SDK payload')
        require(path.parent.is_dir() and not any(parent.is_symlink() for parent in path.parents),
                'Additional directory has no ordinary existing parent')
        path.mkdir(mode=0o755)
        require(path.is_dir() and not path.is_symlink() and not any(path.iterdir()),
                'Additional SDK directory must be ordinary and empty')
    payload_before = snapshot(sdk)
    command_inventory = stage_commands(prefix, plan, mode=args.mode, runtime_prefix=str(prefix))
    (work / 'command-inventory.json').write_text(json.dumps(command_inventory, indent=2) + '\n')
    expected_version = json.loads(args.manifest.read_bytes())['sdkVersion']
    require(run([launcher, '--version']).strip() == expected_version, 'Wrapper selected a different SDK')
    command_names = ['cbodotnet-' + '.'.join(expected_version.split('.')[:2]), 'cbodotnet']
    if args.mode == 'oci':
        command_names.append('dotnet')
    for name in command_names:
        result = subprocess.run([name, '--version'], cwd=work, env=env, text=True, capture_output=True)
        require(result.returncode == 0 and result.stdout == expected_version + '\n', 'Alias selected a different SDK: ' + name)
        require(result.stderr.strip() == plan['branding']['displayName'], 'Version branding stream mismatch: ' + name)
        identity = json.loads(run([name, '--cbodotnet-info']))
        require(identity['distributionBrand'] == plan['branding']['displayName']
                and identity['sourceManifestSha256'] == plan['sourceManifestSha256']
                and identity['sdkVersion'] == expected_version, 'Alias provenance mismatch: ' + name)
        require(run([name, '--info']).startswith(plan['branding']['displayName'] + '\n'), 'Information branding missing: ' + name)
    require(str(sdk / 'sdk') in run([launcher, '--list-sdks']), 'SDK resolution escaped the cbodotnet root')
    info = run([launcher, '--info'])
    require(str(sdk) in info, 'Host information does not reference the isolated root')
    rid = re.search(r'^\s*RID:\s+(\S+)\s*$', info, re.MULTILINE)
    require(rid and rid[1] == plan['targetRid'], 'Host information reports a different target RID')
    project = work / 'console'
    project.mkdir()
    (project / 'global.json').write_text(json.dumps({'sdk': {'version': expected_version, 'rollForward': 'disable'}}))
    (project / 'NuGet.Config').write_text('<configuration><packageSources><clear /></packageSources></configuration>')
    (project / 'Smoke.csproj').write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                                         '<OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework>'
                                         '</PropertyGroup></Project>')
    (project / 'Program.cs').write_text('using System; using System.Globalization; using System.Security.Cryptography;\n'
                                      'Console.WriteLine(Environment.ProcessPath);\n'
                                      'Console.WriteLine(typeof(object).Assembly.Location);\n'
                                      'Console.WriteLine(1234.5m.ToString("N1", CultureInfo.GetCultureInfo("fr-FR")));\n'
                                      'using var rsa = RSA.Create(); var b = RandomNumberGenerator.GetBytes(32);\n'
                                      'var s = rsa.SignData(b, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);\n'
                                      'if (!rsa.VerifyData(b,s,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1)) throw new Exception();\n'
                                      'Console.WriteLine("crypto-passed");\n')
    (work / 'restore.txt').write_text(run([launcher, 'restore', '--configfile', 'NuGet.Config'], project))
    (work / 'build.txt').write_text(run([launcher, 'build', '--no-restore'], project))
    output = run([launcher, project / 'bin/Debug/net10.0/Smoke.dll'], project)
    require(output.splitlines()[0] == str(sdk / 'dotnet') and str(sdk / 'shared/Microsoft.NETCore.App') in output,
            'The application used a different host/runtime')
    require('crypto-passed' in output and '234,5' in output, 'Crypto/globalization smoke failed')
    require(snapshot(sdk) == payload_before, 'SDK execution changed the qualified installed payload')
    require(run([official, '--version']).strip() == original_version, 'Installation changed official dotnet behavior')
    if args.mode == 'package':
        require(run(['dotnet', '--version']).strip() == original_version, 'Native installation changed official dotnet selection')
    # Even an otherwise working official dotnet on PATH must never rescue a
    # launcher whose selected cbodotnet installation is missing.
    hidden_host = sdk / 'dotnet.hidden'
    (sdk / 'dotnet').rename(hidden_host)
    try:
        try:
            run([launcher, '--version'])
        except subprocess.CalledProcessError:
            pass
        else:
            raise ValueError('Wrapper fell back to a global dotnet host')
    finally:
        hidden_host.rename(sdk / 'dotnet')
    # Remove exactly the two contract-owned paths inside our freshly created prefix.
    require(sdk.resolve().is_relative_to(prefix.resolve()) and launcher.resolve().is_relative_to(prefix.resolve()),
            'Removal escaped the private prefix')
    shutil.rmtree(sdk)
    for record in command_inventory:
        command = prefix / record['path'].lstrip('/')
        require(command.resolve().is_relative_to(prefix.resolve()), 'Command removal escaped the private prefix')
        command.unlink()
    require(run(['dotnet', '--version']).strip() == original_version, 'Removal changed official dotnet selection')
    require(snapshot(official.parent) == official_before, 'The official installation changed')
    try:
        run([launcher, '--version'])
    except FileNotFoundError:
        pass
    else:
        raise ValueError('Removed launcher unexpectedly remains executable')
    report = {'status': 'passed', 'sdkVersion': expected_version, 'architecture': args.arch,
              'officialVersion': original_version, 'officialDotnet': str(official),
              'targetRid': plan['targetRid'], 'additionalDirectories': additional_directories,
              'preparedVariant': args.variant, 'osRelease': Path('/etc/os-release').read_text(),
              'commandMode': args.mode, 'commandNames': command_names,
              'branding': plan['branding'], 'commandInventory': command_inventory,
              'checks': ['non-root', 'qualified-archive', 'isolated-host-runtime', 'offline-build-run',
                         'crypto-globalization', 'no-global-host-fallback', 'sdk-payload-unchanged',
                         'official-tree-unchanged', 'command-aliases', 'cli-branding',
                         'version-stdout-compatible', 'uninstall'],
              'publicationQualified': False}
    (work / 'coexistence.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
