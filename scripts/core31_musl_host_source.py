"""Private SDK31 original core-setup host production worker; review before execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
COMMIT = 'f94bb2c3ff432dcc4a6229eca2f978197bf06150'
TREE = 'a2cd9841d6f8f666a0767f56a3636800866d2072'
ARCADE_VERSION = '1.0.0-beta.22314.5'
ARCADE_COMMIT = 'fe57b3babcfc203dd61b7229b54d399b2e3f3c72'
ARCADE_PIN = dict(bytes=1176271, sha256='df1fc7f7afb96b726730d781d3a5a87855ce7c368c15a7e2242efd8fbaa974b2',
                  sha512='c8a1eb32709b75aba6ab6828982cc983a8f8a5dcf141c311efc1aad103a39fda355a7d1b1dffd33d62bbff13285349fb44e887ded8495b093fbc8558a75b9b80')
BOOTSTRAP_SHA512 = 'aaa3e485166a5779a41cc7ec33a03e322d57aaede0dc4afed850d56371e9fdf06fd458eef412660b82a4773a8b625b213a0db7202623206d72c6a68a4fb90032'
BUILD_BEFORE = '47be891c3bef8027a8f05c5e60abb9d56967bc2329d518a27c2eb52e5573dc21'
BUILD_AFTER = 'adaa5f3e5dfc8edc556a4afd61281b135ff8fbc02936281776efcf333c5cb2db'
RID_OLD = b'        else\n            __rid_plat="linux"\n        fi\n    fi\n}\n'
RID_NEW = b'        else\n            if [[ "$__rid_plat" != "linux-musl" ]]; then\n                __rid_plat="linux"\n            fi\n        fi\n    fi\n}\n'
PRODUCTS = ('dotnet', 'libhostfxr.so', 'libhostpolicy.so', 'apphost', 'libnethost.so')
TARGET_DIRECTORIES = {'dotnet': ('dotnet', 'dotnet'), 'libhostfxr.so': ('fxr', 'hostfxr'),
    'libhostpolicy.so': ('hostpolicy', 'hostpolicy'), 'apphost': ('apphost', 'apphost'),
    'libnethost.so': ('nethost', 'nethost')}


def require(value, message):
    if not value:
        raise ValueError(message)


def fp(path):
    digests = (hashlib.sha256(), hashlib.sha512())
    size = 0
    with path.open('rb') as stream:
        while raw := stream.read(1024 * 1024):
            size += len(raw)
            for digest in digests:
                digest.update(raw)
    return dict(bytes=size, sha256=digests[0].hexdigest(), sha512=digests[1].hexdigest())


STOCK_COMPILER_PIN = dict(bytes=198752,
    sha256='c1e8c04019e903a3bf0cb3945515bf37d88e7d55e4d13ce2fafbf26f8dc34807',
    sha512='ee25525e0247329b741460f645d133a74a7d172abc0988e61f1c3b0262a3bda2ce7651854adc15c9c9e404596f28caac07e9eb6bbacd95175faf8e0647de9425')


def require_stock_compiler(path):
    # Alpine packages clang++ as an identical regular ELF, not the clang-20
    # inode. Authenticate the actual executed bytes, never a wrapper's claim.
    require(path is not None, 'Required stock compiler path is absent')
    path = Path(path)
    require(path.is_absolute() and path.is_file() and path.stat().st_mode & 0o111,
            'Stock compiler must be an absolute executable regular file')
    with path.open('rb') as stream:
        prefix = stream.read(20)
    require(prefix[:6] == b'\x7fELF\x02\x01' and int.from_bytes(prefix[18:20], 'little') == 183,
            'Stock compiler must be the reviewed ARM64 ELF driver')
    require(fp(path) == STOCK_COMPILER_PIN, 'Actual compiler bytes differ from reviewed stock Clang20')
    return dict(path=str(path), resolved=str(path.resolve()), **STOCK_COMPILER_PIN)


def save(path, value):
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def ordinary(path, *, exists=True):
    require(path.is_absolute() and path != Path('/') and
            not any(p.is_symlink() for p in (path, *path.parents)), 'Ordinary absolute path required: ' + str(path))
    if exists:
        require(path.exists(), 'Input missing: ' + str(path))
    return path


def adapt_build(raw):
    require(hashlib.sha256(raw).hexdigest() == BUILD_BEFORE and raw.count(RID_OLD) == 1,
            'Exact original portable RID block required')
    changed = raw.replace(RID_OLD, RID_NEW)
    require(hashlib.sha256(changed).hexdigest() == BUILD_AFTER, 'Unexpected private RID delta')
    return changed


DECLARED_CHECKOUT_EOL = {'Microsoft.DotNet.CoreSetup.sln': {'gitBlob': '879ff1844296bdcf68737e526e615902ddf5b2dd', 'original': {'bytes': 17686, 'sha256': 'be88573d11730ce8709ea7c020e344fddbf1549e9620dccc3e99a804d340c30a', 'sha512': '24a001027d51d667ffa28f7cb53cac4d710c93cafc04362260a0e5339d533ce177b8c3bed1b43b1438f543857b439dfef8e96c972480411d02ab05865fa5876d'}, 'checkout': {'bytes': 17913, 'sha256': '930bf5e559e10a8bd5df837418a72cc5f6b0fec6348d3feccc598e209b3dd1ce', 'sha512': '9fd8af1f69eaccb8c74da5a090e7458244a2b6b79ca6c4cbedc8d86e50cbee26ccd06e7a0407f94f346540dcee075b13eab41ded092113dd5d96aec547da1c94'}}, 'tools-local/tasks/core-setup.tasks.sln': {'gitBlob': 'aeea0b3930f6b2d35c015c37495416233d000507', 'original': {'bytes': 900, 'sha256': '1e3f99059fbe474612d503ba3d11172a36cced8d3c532385976aafb6d43fcee1', 'sha512': 'ccc2be258add10a3b69e218e311422af8301a54fd0f267b5ac763a436c80c2918de268cfcd131d5bc64af42184da52699f81a88fb7ae0e70f82f0708d16d8920'}, 'checkout': {'bytes': 922, 'sha256': '3cbec70a6d73fcbf64425f6a857cd218a8e42bd7cbfb4234ac3291882abbc69b', 'sha512': '9a7ecf51c39781d35f3e037c740fd62e8addc9d0e2290467f1886e811df8f5344bda47986f14a4ea35dbbd412489be429c50bfa7819b3abf15309fb112e1b48e'}}}


def materialize_declared_checkout_eol(source, raw_tree, run):
    # Only the two observed, publisher-forced CRLF solution files are eligible.
    # Authenticate the Git tree, original blob and attributes before any write;
    # never generalize this into normalization or an exception in source guards.
    tree = {}
    for record in raw_tree.split(b'\0'):
        if record:
            header, name = record.split(b'\t', 1)
            mode, kind, oid = header.decode().split()
            tree[name.decode('utf-8')] = (mode, kind, oid)
    plans = []
    for number, (rel, pin) in enumerate(DECLARED_CHECKOUT_EOL.items()):
        require(tree.get(rel) == ('100644', 'blob', pin['gitBlob']),
                'Declared source materialization requires the fixed original Git entry: ' + rel)
        path = ordinary(source / rel)
        require(path.is_file() and stat.S_IMODE(path.stat().st_mode) == 0o644,
                'Declared source materialization requires original regular file mode: ' + rel)
        original = run('read-declared-eol-original-' + str(number),
                ['git', 'cat-file', 'blob', pin['gitBlob']], source, capture=True)
        require(hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest() == pin['gitBlob']
                and dict(bytes=len(original),sha256=hashlib.sha256(original).hexdigest(),
                    sha512=hashlib.sha512(original).hexdigest()) == pin['original'],
                'Declared materialization original Git bytes changed: ' + rel)
        attrs = run('read-declared-eol-attributes-' + str(number),
                ['git', 'check-attr', '-z', 'text', 'eol', '--', rel], source, capture=True)
        require(attrs == (rel + '\0text\0auto\0' + rel + '\0eol\0crlf\0').encode(),
                'Original publisher-forced checkout attributes changed: ' + rel)
        before = fp(path)
        require(before in (pin['original'], pin['checkout']),
                'Only fixed original Git bytes or observed publisher CRLF checkout bytes may be materialized: ' + rel)
        current = path.read_bytes()
        require(current == original or (b'\r' not in original
                and current == original.replace(b'\n', b'\r\n')),
                'Declared checkout is not solely original publisher-forced CRLF: ' + rel)
        plans.append((path,original,dict(path=rel,gitBlob=pin['gitBlob'],mode='100644',before=before,
            expectedOriginal=pin['original'],attributes=attrs.decode().split('\0')[:-1],
            action='already-original-git-bytes' if current==original else 'materialized-original-git-blob-bytes')))
    for path, original, row in plans:
        if row['action'] == 'materialized-original-git-blob-bytes':
            path.write_bytes(original)
        require(fp(path) == row['expectedOriginal'] and stat.S_IMODE(path.stat().st_mode) == 0o644,
                'Declared original Git-byte materialization did not preserve exact bytes/mode')
        row['after'] = fp(path)
    return dict(status='passed-declared-original-git-byte-checkout-materialization',
        declaredPaths=2,filesWritten=sum(row['action']=='materialized-original-git-blob-bytes'for _,_,row in plans),
        sourcePolicyExceptions=[],rows=[row for _,_,row in plans])


SDK_RESOLVER_PATCH = {'path': 'src/corehost/cli/fxr/sdk_resolver.cpp', 'gitBlob': '3e5e5914d77a1ee326e023df31af2acf95806499', 'before': {'bytes': 16657, 'sha256': '080905de9d18644b3659c2e3d4714ed170a3de1cb83699b205e5255408543af3', 'sha512': '70610d01ea315caf64f4278298f5c8a70df693aaf8a93a9c2a1950e979e083fd741a712723fa714778f19a4da5764abaeb0b9124342c1a3301a49973c5e86964'}, 'after': {'bytes': 16677, 'sha256': '96432e0afff77db97b5302ca6f18362312e518efe06670727cbbe3fad1ab2351', 'sha512': '88ead3558e60507c0d0da3bfa1a1d269944c5abb778253d3f15ee0bbd806ff68dfd208e0d37fbeea3417fa44a12d7ec6ac36b92dd8e8441f61301b31c0a3aeab'}, 'locations': [{'line': 41, 'before': '    version(move(version)),\n', 'after': '    version(std::move(version)),\n'}, {'line': 341, 'before': '    global_file = move(global_file_path);\n', 'after': '    global_file = std::move(global_file_path);\n'}, {'line': 455, 'before': '            sdk_path = move(probe_path);\n', 'after': '            sdk_path = std::move(probe_path);\n'}, {'line': 507, 'before': '        resolved_version_str = move(version);\n', 'after': '        resolved_version_str = std::move(version);\n'}]}


def adapt_sdk_resolver(raw):
    pin=SDK_RESOLVER_PATCH
    actual=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),sha512=hashlib.sha512(raw).hexdigest())
    require(actual==pin['before'] and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==pin['gitBlob'],
            'Exact original sdk_resolver Git bytes required')
    changed=raw
    for location in pin['locations']:
        before=location['before'].encode();after=location['after'].encode()
        require(changed.count(before)==1,'Exact std::move qualification context required')
        changed=changed.replace(before,after,1)
    require(dict(bytes=len(changed),sha256=hashlib.sha256(changed).hexdigest(),sha512=hashlib.sha512(changed).hexdigest())==pin['after'],
            'Unexpected sdk_resolver namespace qualification delta')
    return changed


def fresh_restore_output(output):
    path=ordinary(output/'restore-inputs',exists=False)
    require(not path.exists(),'Fresh restore evidence directory required')
    path.mkdir()
    return path


AUDIT_SOURCES = {'scripts/musl_archive.py': {'bytes': 43570, 'sha256': 'b216041e536491d8afc851938c31fd3163aff201ec24abba0a56e196b003014d', 'sha512': 'c9d7832743cc5dbaebc4554a2cdda1052e7aa32bd356f53104a3648ecfbd1280908af37b8379a12eb2d8c31f9ccdac70cfe7a9c8ef675e8093f64a1b25f2bc38'}, 'scripts/downstream_release.py': {'bytes': 31713, 'sha256': 'a4ff0a7d89fc93cd813762413af89dfed315cc492b15e80b050e6ad8d8f6b668', 'sha512': '886a52db9e1a2f56ea8e29b00a3bf0e9c1e25d65b0c3eab300ec77c2d28ddad7960c9af177bde7bdde21a3ec43b26471c9af324fb475aeffc8bc84a9f2f21be6'}, 'scripts/musl_contract.py': {'bytes': 20378, 'sha256': '191ae7d3d3d08f70b5cc77acea306c59a41f3991e23b773fe5455772c3b4ecfa', 'sha512': '1465dca8c070409b2dad457939c1ffaefde6b42947912469b78753b2faa5fbd553d0c983c3d29798d75ea0c11002830b5d71328ccb74b9a947be2ac199f877b5'}, 'scripts/sdk_runtime.py': {'bytes': 13126, 'sha256': '18b6baf81ef5aecb9f9472f9759a50b0a01695350b5797c3b037d6d1a8b7eb9c', 'sha512': '8f1b59cd93dccc6acacdb1f8b938d3822c73a0988ac90201b0b25534b29509f43be1b1633e4c2a50cb6af49a5f080516fbff12fbfdc09ba78d0942f25d555f8c'}, 'scripts/distribution_contract.py': {'bytes': 17447, 'sha256': 'a2ca4af9a1bd063d3229a0bb8b9160f52e561c37b6ed8442ce9bc6340938016f', 'sha512': '9129842f30b1957754d8bcf3efb81f58f13732584915b2384f5f0b62656bd1af0f9dfd1af1284ed32bb06f928d61c4adbb08b62bc98cd30b4940b6603f70e52a'}, 'scripts/release_catalog.py': {'bytes': 25223, 'sha256': '44f4aa5959baadae131885f7f674817ebf9f4d6f5dad9a6c8db4e65eec01193f', 'sha512': '035d9cb1fa432d2f9678ef8d57863e60a7dcaf437f2f71ea51ccf82648477b38f91dd4e08762051d6e782e3c3bc03f737bf6f28b7f9e0bfcf680c93044f9957f'}, 'scripts/musl_source_transport.py': {'bytes': 13772, 'sha256': '7acf0977e567b7f490faa7389925a135e2840208130fa31d08c94cdcae14fb18', 'sha512': '3c18e7e9fd707bcc68758d274b1ea16700066add259d3c1e752fb4b110457fc86464b5f849465b98423676693b2f5a1cd11b79b5f47e69ea4f4ee222396d3696'}, 'scripts/core31_musl_host_elf.py': {'bytes': 4641, 'sha256': '8cb927df3081c79bd7ee84bdb617064d6f1cab263f0b7a465b1bc53d2a91a746', 'sha512': '1a35d2693c141f4c0a8652f2d84949f1ad75525befeacd0254c6b274e29d44ae8cfbae6af04c1dc831be1861c4abebf87b91afe4f249b760d03649d0b1e987ff'}, 'scripts/core31-musl-host-elf-audit-pins.json': {'bytes': 2654, 'sha256': '7c4e9b2a6b0de1b9049d69f06dfb771dafcaffe3bbe7b66759e03fe4af9595bd', 'sha512': 'e73ba8b3a8f6cdad559233abae9c4d8978bfb50db0e1138bb2abde0a2227759cab76406472b067307e6ce1018d75a7055bde6e99b53e1a6fcbc66ff81ee82d7e'}, 'scripts/musl_evidence_transport.py': {'bytes': 9344, 'sha256': '02153b043d0e134a4af29967d551826bfe882ba05836a499c4cb4bc0d9f763e2', 'sha512': 'b2a5fb7c2780c639f3804ad0e5be6b444be7dfcb1047a745bc78506478e8477be1a8eb30edcbafcc15a8d24f9ab991544092844d7298dab27b5edf403d4dab84'}}

def main():
    import resource
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-git', 'bootstrap', 'bootstrap-archive', 'arcade-package', 'work-dir', 'output-dir'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--official-build-id', required=True)
    parser.add_argument('--execute-reviewed-host-build', action='store_true', required=True)
    args = parser.parse_args()
    require(platform.system() == 'Linux' and platform.machine() == 'aarch64' and os.getuid() == 1000
            and Path('/etc/alpine-release').read_text().strip() == '3.24.4', 'Native non-root ARM64 Alpine3.24.4 required')
    require(len(os.sched_getaffinity(0)) == 2, 'Exactly two assigned native CPUs required')
    require(re.fullmatch(r'2026[0-9]{4}\.[1-9][0-9]*', args.official_build_id), 'Actual dated attempt identity required')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Anonymous W^X code mappings also obey RLIMIT_FSIZE. The separately
    # retained per-stage scratch/report byte checks bound regular disk data.
    require(resource.getrlimit(resource.RLIMIT_FSIZE) == (resource.RLIM_INFINITY, resource.RLIM_INFINITY),
            'Standard anonymous-memory-compatible file-size limits required')
    for name, value in vars(args).items():
        if isinstance(value, Path):
            ordinary(value, exists=name not in ('work_dir', 'output_dir'))
    work, output = args.work_dir, args.output_dir
    require(not work.exists() and not output.exists() and not work.is_relative_to(output)
            and not output.is_relative_to(work), 'Fresh separate work/evidence roots required')
    work.mkdir(parents=True)
    output.mkdir(parents=True)
    records = []
    started = time.monotonic()
    result = dict(status='failed-private-original-host-attempt', sdkVersion='3.1.426',
                  qualificationAllowed=False, sourceAdmissionAllowed=False, sourceSdkProduct=False,
                  wholeNormalProducer=False, sourceCommit=COMMIT, sourceTree=TREE,
                  originalGlobalPinsModified=False, importedHostOutputUsed=False,
                  officialBuildId=args.official_build_id, records=records)
    env = dict(os.environ, HOME=str(work / 'home'), DOTNET_CLI_HOME=str(work / 'home'),
               DOTNET_ROOT=str(args.bootstrap), DOTNET_MULTILEVEL_LOOKUP='0',
               DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_PROCESSOR_COUNT='2',
               NUGET_PACKAGES=str(work / 'version-packages'), NUGET_XMLDOC_MODE='none',
               CMAKE_BUILD_PARALLEL_LEVEL='2', MAKEFLAGS='-j2', COMPlus_ReadyToRun='1')
    for key in ('ROOTFS_DIR', 'CROSSCOMPILE', 'CrossBuild', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS',
                'MSBuildSDKsPath', 'DOTNET_MSBUILD_SDK_RESOLVER_CLI_DIR', 'DOTNET_ROLL_FORWARD'):
        env.pop(key, None)

    def run(name, command, cwd=None, timeout=300, capture=False):
        remaining = 900 - (time.monotonic() - started)
        require(remaining > 0, 'Whole attempt exceeded 900 seconds')
        timeout = min(timeout, remaining)
        log = output / (name + '.log')
        begin = time.monotonic()
        with log.open('xb') as stream:
            stream.write((json.dumps(list(map(str, command))) + '\n').encode())
            stream.flush()
            process = subprocess.Popen(list(map(str, command)), cwd=cwd, env=env,
                                       stdout=subprocess.PIPE if capture else stream,
                                       stderr=stream, start_new_session=True)
            try:
                stdout, _ = process.communicate(timeout=timeout)
                code = process.returncode
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    stdout, _ = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    stdout, _ = process.communicate()
                code = 124
            if capture and stdout:
                stream.write(stdout)
        records.append(dict(name=name, command=list(map(str, command)), exitCode=code,
                            seconds=round(time.monotonic() - begin, 3), log=log.name, **fp(log)))
        # Append-only command events retain the actual outcome before collection.
        with (output / 'command-events.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(records[-1]) + '\n')
        print(name, code, records[-1]['seconds'], flush=True)
        require(code == 0, 'Original host stage failed: ' + name)
        for directory, maximum in ((work, 2 * 1024**3), (output, 256 * 1024**2)):
            size = sum(p.stat().st_size for p in directory.rglob('*') if p.is_file() and not p.is_symlink())
            require(size <= maximum, 'Own stage disk budget exceeded: ' + str(directory))
        return stdout if capture else b''

    try:
        tool_versions = {}
        for tool in ('clang-20', 'clang++-20', 'cmake', 'git', 'make', 'readelf', 'objcopy'):
            require(shutil.which(tool) is not None, 'Required original worker tool absent: ' + tool)
            tool_versions[tool] = run('tool-' + tool.replace('+', 'p'), [tool, '--version'], capture=True).decode()
        require('20.1.8' in tool_versions['clang-20'] and '20.1.8' in tool_versions['clang++-20']
                and 'cmake version 4.2.3' in tool_versions['cmake'], 'Reviewed stock compiler/CMake versions differ')
        save(output / 'actual-tool-versions.json', tool_versions)
        compiler_identities = {tool: require_stock_compiler(shutil.which(tool))
                               for tool in ('clang', 'clang++', 'clang-20', 'clang++-20')}
        save(output / 'actual-stock-compiler-identities.json', compiler_identities)
        require(not any(shutil.which(t) for t in ('clang-3.5', 'clang++-3.5', 'clang-3.6', 'clang++-3.6',
                    'clang-3.9', 'clang++-3.9', 'clang-5.0', 'clang++-5.0')),
                'Original script would select another historical compiler')
        require(fp(args.arcade_package) == ARCADE_PIN, 'Wrong original Arcade22314.5 bytes')
        require(args.arcade_package.name == 'microsoft.dotnet.arcade.sdk.' + ARCADE_VERSION + '.nupkg',
                'Original package canonical filename required')
        require(fp(args.bootstrap_archive)['sha512'] == BOOTSTRAP_SHA512, 'Wrong private SDK8.0.131 archive')
        # Reuse a read-only existing original bootstrap without another SDK copy.
        bootstrap_members = []
        with tarfile.open(args.bootstrap_archive, 'r|gz') as archive:
            for member in archive:
                rel = PurePosixPath(member.name)
                require(not rel.is_absolute() and '..' not in rel.parts, 'Unsafe bootstrap archive path')
                if member.isfile():
                    installed = ordinary(args.bootstrap / str(rel))
                    digest = hashlib.sha256()
                    source_stream = archive.extractfile(member)
                    while raw := source_stream.read(1024 * 1024):
                        digest.update(raw)
                    actual = fp(installed)
                    require(actual['bytes'] == member.size and actual['sha256'] == digest.hexdigest(),
                            'Read-only bootstrap is not the original archive: ' + str(rel))
                    bootstrap_members.append(dict(path=str(rel), **actual))
                elif member.issym():
                    raise ValueError('Bootstrap symlink requires explicit review; no implicit adaptation')
        save(output / 'private-bootstrap-correspondence.json', dict(version='8.0.131',
             role='Imported MSBuild version-generator tooling only; no binary product output',
             archive=fp(args.bootstrap_archive), members=bootstrap_members))
        source = work / 'source'
        run('clone-original-host-source', ['git', '-c', 'core.autocrlf=false', 'clone', '--no-hardlinks',
                                         '--no-checkout', args.source_git, source])
        run('checkout-original-commit', ['git', 'checkout', '--detach', COMMIT], source)
        run('record-original-upstream-url', ['git', 'remote', 'set-url', 'origin', 'https://github.com/dotnet/core-setup'], source)
        require(run('verify-original-tree', ['git', 'rev-parse', 'HEAD^{tree}'], source, capture=True).decode().strip() == TREE,
                'Wrong original source tree')
        raw_tree = run('original-source-tree', ['git', 'ls-tree', '-rz', '--full-tree', COMMIT], source, capture=True)
        materialization = materialize_declared_checkout_eol(source, raw_tree, run)
        save(output / 'declared-git-byte-checkout-materialization.json', materialization)
        originals = []
        for record in raw_tree.split(b'\0'):
            if not record:
                continue
            header, name = record.split(b'\t', 1)
            mode, kind, oid = header.decode().split()
            require(kind == 'blob' and mode in ('100644', '100755'), 'Unexpected original source type/Gitlink')
            rel = name.decode('utf-8')
            path = ordinary(source / rel)
            require(path.is_file() and stat.S_IMODE(path.stat().st_mode) == (0o755 if mode=='100755' else 0o644),
                    'Checkout differs from original Git mode: ' + rel)
            raw = path.read_bytes()
            require(hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == oid,
                    'Checkout differs from original Git blob: ' + rel)
            originals.append(dict(path=rel, mode=mode, gitBlob=oid, **fp(path)))
        require(len(originals) == 998, 'Original complete host source file count differs')
        save(output / 'original-source-files.json', originals)
        globals_before = (source / 'global.json').read_bytes()
        require(json.loads(globals_before) == dict(tools=dict(dotnet='3.1.420'),
                **{'msbuild-sdks': {'Microsoft.DotNet.Arcade.Sdk': ARCADE_VERSION}}), 'Original global pins changed')
        for name in ('global.json', 'LICENSE.TXT', 'THIRD-PARTY-NOTICES.TXT'):
            shutil.copyfile(source / name, output / ('original-' + name))
        build_sh = source / 'src/corehost/build.sh'
        build_sh.write_bytes(adapt_build(build_sh.read_bytes()))
        patch = run('exact-private-source-delta', ['git', 'diff', '--binary', '--', 'src/corehost/build.sh'], source, capture=True)
        (output / 'preserve-native-musl-portable-rid.patch').write_bytes(patch)
        sdk_resolver=source/SDK_RESOLVER_PATCH['path']
        sdk_resolver_before=fp(sdk_resolver)
        sdk_resolver.write_bytes(adapt_sdk_resolver(sdk_resolver.read_bytes()))
        resolver_patch=run('exact-sdk-resolver-namespace-delta',
            ['git','diff','--binary','--',SDK_RESOLVER_PATCH['path']],source,capture=True)
        (output/'qualify-original-sdk-resolver-std-move.patch').write_bytes(resolver_patch)
        save(output/'declared-native-source-adaptations.json',dict(rows=[
            dict(path='src/corehost/build.sh',gitBlob='fb503e74f074c52a15f3538860e90ef5e39e4665',before={'bytes': 9698, 'sha256': '47be891c3bef8027a8f05c5e60abb9d56967bc2329d518a27c2eb52e5573dc21', 'sha512': 'bd4de01279b03bb638afe35f59dab7e4d5e1cebd20436f4cdbf302f922df35f9b1f962124f8a9c063e74647e22811c03a1f2b3ba9791bedb8fb1164b60e3d8fd'},after=fp(build_sh),
                purpose='Preserve native portable musl RID'),
            dict(path=SDK_RESOLVER_PATCH['path'],gitBlob=SDK_RESOLVER_PATCH['gitBlob'],before=sdk_resolver_before,
                after=fp(sdk_resolver),purpose='Qualify four existing std::move calls for Clang20; no warning waiver',
                locations=SDK_RESOLVER_PATCH['locations'])],sourcePolicyExceptions=[],compilerWarningWaivers=[]))
        wrappers = work / 'tool-wrappers'
        wrappers.mkdir()
        real_cmake = shutil.which('cmake')
        wrapper = wrappers / 'cmake'
        wrapper.write_text('#!/usr/bin/env python3\nimport json,os,sys\n'
            'args=sys.argv[1:]\n'
            'if args and args[0] != "--build":\n'
            ' args += ["-DCMAKE_POLICY_VERSION_MINIMUM=3.5", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"]\n'
            'with open(os.environ["SDK31_CMAKE_EVENTS"], "a") as f: f.write(json.dumps(args)+"\\n")\n'
            'os.execv(' + repr(real_cmake) + ', [' + repr(real_cmake) + '] + args)\n', encoding='utf-8')
        wrapper.chmod(0o755)
        env.update(PATH=str(wrappers) + ':' + env['PATH'], SDK31_CMAKE_EVENTS=str(output / 'cmake-events.jsonl'))
        save(output / 'private-cmake-wrapper.json', dict(realCmake=real_cmake, wrapper=fp(wrapper),
              addedConfigureArguments=['-DCMAKE_POLICY_VERSION_MINIMUM=3.5', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'],
              originalOptimizationAndHardeningUnchanged=True, compilerWarningWaivers=[]))
        shutil.copyfile(wrapper, output / 'cmake-wrapper.py')
        local_feed = work / 'original-version-feed'
        local_feed.mkdir()
        shutil.copyfile(args.arcade_package, local_feed / args.arcade_package.name)
        infrastructure_dir = work / 'version-input-project'
        infrastructure_dir.mkdir()
        infrastructure = infrastructure_dir / 'version-input-restore.csproj'
        infrastructure.write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework>'
             '</PropertyGroup><ItemGroup><PackageDownload Include="Microsoft.DotNet.Arcade.Sdk" Version="[' + ARCADE_VERSION +
             ']" /></ItemGroup></Project>\n', encoding='utf-8')
        dotnet = args.bootstrap / 'dotnet'
        msbuild = args.bootstrap / 'sdk/8.0.131/MSBuild.dll'
        require(run('actual-private-bootstrap-version', [dotnet, '--version'], work, capture=True).decode().strip()
                == '8.0.131', 'Wrong actual private version host SDK selected')
        run('restore-exact-original-version-sdk', [dotnet, msbuild, infrastructure, '/t:Restore', '/m:2', '/nr:false',
             '/p:RestoreSources=' + str(local_feed), '/bl:' + str(output / 'version-input-restore.binlog')], work)
        cache_arcade = work / 'version-packages/microsoft.dotnet.arcade.sdk' / ARCADE_VERSION
        require(fp(cache_arcade / args.arcade_package.name) == ARCADE_PIN, 'Actual version SDK resolver cache bytes differ')
        with zipfile.ZipFile(args.arcade_package) as archive:
            version_targets = archive.read('tools/Version.targets')
        require((cache_arcade / 'tools/Version.targets').read_bytes() == version_targets, 'Version target extraction changed')
        (output / 'original-arcade-Version.targets').write_bytes(version_targets)
        save(output / 'original-version-sdk-input.json', dict(version=ARCADE_VERSION, **ARCADE_PIN,
             publisherRepository='https://github.com/dotnet/arcade', publisherCommit=ARCADE_COMMIT,
             originalLicense='MIT', signatureTrustClaimed=False, sourceBuiltToolClaimed=False,
             projectAssetsBindingClaimed=False, role='Exact imported original SDK resolver/version-generation input'))
        capture = work / 'capture-host-inputs.targets'
        capture.write_text('''<Project><Target Name="RecordSdk31HostInputs" BeforeTargets="BuildCoreHostUnix"
 DependsOnTargets="GetProductVersions;GenerateNativeVersionFile">
 <Error Condition="!Exists('$(NativeVersionFile)')" Text="Actual original native version source is required" />
 <Error Condition="'$(FileVersion)' == '' or $(FileVersion.StartsWith('42.'))" Text="Dated original FileVersion required" />
 <Error Condition="'$(VersionSuffixDateStamp)' == ''" Text="Original dated version target must run" />
 <WriteLinesToFile File="''' + str(output / 'evaluated-host-inputs.txt') + '''" Overwrite="true"
 Lines="ProductVersion=$(ProductVersion);AppHostVersion=$(AppHostVersion);HostVersion=$(HostVersion);HostResolverVersion=$(HostResolverVersion);HostPolicyVersion=$(HostPolicyVersion);FileVersion=$(FileVersion);VersionSuffixDateStamp=$(VersionSuffixDateStamp);OfficialBuildId=$(OfficialBuildId);SourceRevisionId=$(SourceRevisionId);NativeVersionFile=$(NativeVersionFile);ConfigurationGroup=$(ConfigurationGroup);PortableBuild=$(PortableBuild);TargetArchitecture=$(TargetArchitecture);LatestCommit=$(LatestCommit)" />
 </Target></Project>''', encoding='utf-8')
        command = [dotnet, msbuild, source / 'src/corehost/build.proj', '/restore', '/t:Build', '/m:2', '/nr:false',
             '/p:Configuration=Linux_Release', '/p:ConfigurationGroup=Release', '/p:OSGroup=Linux',
             '/p:TargetArchitecture=arm64', '/p:PortableBuild=true', '/p:CrossBuild=false', '/p:StripSymbols=true',
             '/p:OfficialBuildId=' + args.official_build_id, '/p:ContinuousIntegrationBuild=true',
             '/p:RepositoryCommit=' + COMMIT, '/p:SourceRevisionId=' + COMMIT,
             '/p:NativeVersionFile=' + str(source / 'artifacts/obj/_version.c'),
             '/p:UseSharedCompilation=false', '/p:CustomAfterMicrosoftCommonTargets=' + str(capture),
             '/p:RestoreAdditionalProjectSources=' + str(local_feed), '/bl:' + str(output / 'original-host-build.binlog')]
        save(output / 'actual-original-host-command.json', dict(command=list(map(str, command)),
             originalProductProject='src/corehost/build.proj', originalGlobalPinsPreserved=True,
             versionPropertyOverrides=[], originalBuildRecipe=True, privateBootstrapSdk='8.0.131'))
        run('original-versioned-release-host-build', command, source, timeout=600)
        require((source / 'global.json').read_bytes() == globals_before, 'Original global.json was modified')
        values = dict(line.split('=', 1) for line in (output / 'evaluated-host-inputs.txt').read_text().splitlines() if '=' in line)
        require(values['SourceRevisionId'] == COMMIT and values['OfficialBuildId'] == args.official_build_id
                and values['ConfigurationGroup'] == 'Release' and values['TargetArchitecture'] == 'arm64'
                and values['PortableBuild'] == 'true' and not values['FileVersion'].startswith('42.'), 'Evaluated native inputs differ')
        require(values['ProductVersion'].startswith('3.1.32') and all(values[k] == values['ProductVersion']
                for k in ('AppHostVersion', 'HostVersion', 'HostResolverVersion', 'HostPolicyVersion')),
                'Original source-generated host package versions differ')
        version = source / 'artifacts/obj/_version.c'
        version_raw = version.read_bytes()
        expected_marker = ('@(#)Version ' + values['FileVersion'] + ' @Commit: ' + COMMIT).encode()
        require(expected_marker in version_raw and b'No version information produced' not in version_raw,
                'Original version source fell back or lacks actual dated version/commit')
        shutil.copyfile(version, output / '_version.c')
        obj = source / 'artifacts/obj/linux-musl-arm64.Release/corehost'
        installed = source / 'artifacts/bin/linux-musl-arm64.Release/corehost'
        commands = json.loads((obj / 'compile_commands.json').read_text())
        version_compiles = []
        for row in commands:
            argv = row.get('arguments') or shlex.split(row['command'])
            require_stock_compiler(argv[0])
            require(all(flag in argv for flag in ['-O3', '-Werror', '-fstack-protector-strong', '-DNDEBUG']),
                    'Original Release/native compiler flags weakened')
            if Path(row['file']).resolve() == version.resolve():
                version_compiles.append(row)
        for target in ('dotnet', 'hostfxr', 'hostpolicy', 'apphost', 'nethost'):
            require(any('CMakeFiles/' + target + '.dir/' in (r.get('command') or ' '.join(r['arguments']))
                        for r in version_compiles), 'Actual generated version source is unbound to target: ' + target)
        products = []
        native = output / 'native'
        native.mkdir()
        for name in PRODUCTS:
            path = installed / name
            directory, target = TARGET_DIRECTORIES[name]
            built = obj / 'cli' / directory / name
            require(fp(built) == fp(path), 'Installed ELF does not equal the actual original target output')
            link = obj / 'cli' / directory / 'CMakeFiles' / (target + '.dir') / 'link.txt'
            link_raw = link.read_bytes()
            require(b'_version.c.o' in link_raw and b'-Wl,-z,relro,-z,now' in link_raw,
                    'Original actual target link is not bound to the version object/hardening')
            shutil.copyfile(link, output / (target + '-link.txt'))
            raw = path.read_bytes()
            require(raw[:6] == b'\x7fELF\x02\x01' and int.from_bytes(raw[18:20], 'little') == 183
                    and expected_marker in raw and b'No version information produced' not in raw,
                    'Actual source ARM64 ELF/native version binding failed: ' + name)
            details = run('readelf-' + name, ['readelf', '-h', '-l', '-d', '-n', '-V', path], capture=True).decode()
            require('GNU_RELRO' in details and 'BIND_NOW' in details,
                    'Original musl/RELRO/NOW hardening absent: ' + name)
            if name in ('dotnet', 'apphost'):
                require('/lib/ld-musl-aarch64.so.1' in details, 'Native musl executable interpreter absent')
            shutil.copyfile(path, native / name)
            dbg = path.with_name(path.name + '.dbg')
            require(dbg.is_file(), 'Original split symbols absent: ' + name)
            require(fp(built.with_name(built.name + '.dbg')) == fp(dbg), 'Installed debug output differs')
            shutil.copyfile(dbg, native / dbg.name)
            products.append(dict(name=name, originalPath=str(path), **fp(path), debug=fp(dbg),
                                 actualBuiltPath=str(built), originalLinkInput=fp(link), installedBytesEqualBuilt=True,
                                 sourceGeneratedNativeVersion=values['FileVersion'], nativeVersionByteMatched=True))
        # Full unchanged provider-specific ELF audit resolves every DT_NEEDED
        # to exact stock APKs; GLIBC text is never generally exempted.
        for name,pin in AUDIT_SOURCES.items():
            require(fp(ROOT/name)==pin,'Frozen complete native auditor input changed: '+name)
        audit_payload=work/'native-host-audit-payload'
        require(not audit_payload.exists(),'Fresh native audit payload required')
        audit_payload.mkdir()
        for name in PRODUCTS:
            shutil.copyfile(installed/name,audit_payload/name)
            require(fp(installed/name)==fp(audit_payload/name),'Static ELF audit copy differs from actual product')
        native_audit_output=output/'native-elf-audit'
        run('complete-provider-specific-native-elf-audit',
            [sys.executable,ROOT/'scripts/core31_musl_host_elf.py',
                '--payload',audit_payload,'--output',native_audit_output,'--indexes','/indexes'],timeout=90)
        native_audit=json.loads((native_audit_output/'results.json').read_bytes())
        require(native_audit['status']=='passed-existing-provider-specific-native-host-elf-audit'
                and native_audit['hostProducts']==5,'Complete original host ELF audit did not pass')
        result['nativeElfAudit']=dict(completeClosure=fp(native_audit_output/'complete-native-elf-closure.json'),
            stockProviders=fp(native_audit_output/'actual-stock-native-providers.json'),
            auditorSources=AUDIT_SOURCES,runtimeExecuted=False,compilerExecuted=False)
        for name in ('compile_commands.json', 'CMakeCache.txt', 'install_manifest.txt'):
            shutil.copyfile(obj / name, output / name)
        save(output / 'native-version-compiler-bindings.json', dict(versionSource=fp(version),
             expectedMarker=expected_marker.decode(), fileVersion=values['FileVersion'], rows=version_compiles))
        # Freeze every original source file against exactly two declared adaptations.
        declared_after={'src/corehost/build.sh': {'bytes': 9774, 'sha256': 'adaa5f3e5dfc8edc556a4afd61281b135ff8fbc02936281776efcf333c5cb2db', 'sha512': 'feb6199ed351f4701c3e3425c7cff0bcffbcf1a577f57e054cee3ca033e7ad207d6c3916c8939b1a71bb5564128941fddde0cc5939e29cac3729f98132428157'}, 'src/corehost/cli/fxr/sdk_resolver.cpp': {'bytes': 16677, 'sha256': '96432e0afff77db97b5302ca6f18362312e518efe06670727cbbe3fad1ab2351', 'sha512': '88ead3558e60507c0d0da3bfa1a1d269944c5abb778253d3f15ee0bbd806ff68dfd208e0d37fbeea3417fa44a12d7ec6ac36b92dd8e8441f61301b31c0a3aeab'}}
        after = []
        for row in originals:
            path = source / row['path']
            actual = fp(path)
            require(actual == declared_after.get(row['path'],{k:row[k]for k in ('bytes','sha256','sha512')})
                    and stat.S_IMODE(path.stat().st_mode)==(0o755 if row['mode']=='100755' else 0o644),
                    'Unexpected original source byte/mode change: ' + row['path'])
            after.append(dict(path=row['path'], **actual))
        save(output / 'actual-source-files-after.json', after)
        result.update(status='passed-private-original-sdk31-host-source-production', products=products,
                      generatedVersionSource=fp(version), fileVersion=values['FileVersion'],
                      originalSourceFiles=998, privateSourceChanges=['src/corehost/build.sh portable musl RID','src/corehost/cli/fxr/sdk_resolver.cpp four std::move namespace qualifications'],
                      sourceVersionFileHandwritten=False, compileDatabaseVersionBindings=len(version_compiles),
                      originalReleaseOptimizationAndHardening=True, symbolsRetained=True)
    except Exception as error:
        result['error'] = dict(type=type(error).__name__, message=str(error))
        raise
    finally:
        # Account for genuine source-scoped restore inputs even when a later
        # native stage fails. Collection errors cannot turn a failed stage green.
        if 'source' in locals() and source.is_dir() and list(source.rglob('project.assets.json')):
            try:
                reader = ROOT / 'scripts/core3_musl_restore_inputs.py'
                require(fp(reader)['sha256'] == '7cb6ea6292d443deb6b943015c273513352765cd463bb95ac817bdf222660b1a',
                        'Reviewed SDK31 neutral restore reader changed')
                sys.path.insert(0, str(reader.parent))
                import core3_musl_restore_inputs as RESTORE
                roots = [source]
                if 'infrastructure' in locals():
                    roots.append(infrastructure.parent)
                restore_output=fresh_restore_output(output)
                accounting = RESTORE.snapshot(work, restore_output, asset_roots=roots)
                result['actualRestoreAccounting'] = dict(assets=len(accounting['assets']),
                    packages=len(accounting['packages']), bindings=len(accounting['usedPackageBindings']),
                    completeCorrespondingSourceClaimed=False, reader=fp(reader))
            except Exception as error:
                result['restoreAccountingError'] = dict(type=type(error).__name__, message=str(error))
                if result['status'].startswith('passed-'):
                    result['status'] = 'failed-private-original-host-evidence-collection'
        result['seconds'] = round(time.monotonic() - started, 3)
        if result['status'].startswith('passed-') and 'actualRestoreAccounting' not in result:
            result['status'] = 'failed-private-original-host-evidence-collection'
            result['restoreAccountingError'] = dict(type='ValueError', message='No genuine original project restore assets captured')
        save(output / 'results.json', result)
        if result['status'] == 'failed-private-original-host-evidence-collection':
            raise ValueError('Original host build passed but required restore evidence collection failed')


if __name__ == '__main__':
    main()
