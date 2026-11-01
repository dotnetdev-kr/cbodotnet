#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == --help ]]; then
  echo 'Usage: prepare-sysroot6.sh /absolute/generated-source /absolute/inputs /absolute/reports UID GID [--arch arm64|x64]'
  echo 'Run in a dedicated matching native privileged root container; the source can be read-only.'
  exit 0
fi
[[ $# == 5 || ( $# == 7 && $6 == --arch ) ]] || { echo 'Expected generated source, input parent, report paths, owner UID/GID and optional architecture.' >&2; exit 2; }
[[ $1 == /* && $2 == /* && $3 == /* && $4 =~ ^[0-9]+$ && $5 =~ ^[0-9]+$ ]] || { echo 'Absolute paths and numeric UID/GID are required.' >&2; exit 2; }
arch=${7:-arm64}
case "$arch" in arm64) native=aarch64 ;; x64) native=x86_64 ;; *) echo 'Unsupported architecture.' >&2; exit 2 ;; esac
[[ $(uname -s) == Linux && $(uname -m) == "$native" && $(id -u) == 0 ]] || { echo 'A matching native Linux root preparation container is required.' >&2; exit 1; }
source_dir=$(realpath -e "$1")
inputs_dir=$(realpath -e "$2")
mkdir -p "$3"
reports_dir=$(realpath -e "$3")
owner_uid=$4
owner_gid=$5
[[ $source_dir != / && ! -L $1 && ! -L $2 && ! -L $3 ]] || { echo 'Source, inputs, and reports must be ordinary directory paths.' >&2; exit 2; }
[[ $inputs_dir != / && $inputs_dir != "$source_dir" && $inputs_dir != "$source_dir"/* ]] || { echo 'Unsafe input parent.' >&2; exit 2; }
[[ $reports_dir != / && $reports_dir != "$source_dir" && $reports_dir != "$source_dir"/* && $reports_dir != "$inputs_dir" && $reports_dir != "$inputs_dir"/* ]] || { echo 'Reports must be outside the source and inputs.' >&2; exit 2; }
installer_commit=d638663530d923adbe0442604b7a6562127321e9
runtime_commit=f1dd57165bfd91875761329ac3a8b17f6606ad18
runtime_dir=$source_dir/src/runtime
installer_dir=$source_dir/src/installer
for path in "$source_dir/git-info" "$runtime_dir" "$installer_dir"; do
  [[ -d $path && ! -L $path ]] || { echo "Missing ordinary generated-source directory: $path" >&2; exit 1; }
done
for pair in "installer:$installer_commit" "runtime:$runtime_commit"; do
  repository=${pair%%:*}
  expected_commit=${pair#*:}
  component=$source_dir/src/$repository
  [[ $(git -c safe.directory="$component" -C "$component" rev-parse --show-toplevel) == "$component" ]] || { echo "Unexpected $repository Git worktree." >&2; exit 1; }
  [[ $(git -c safe.directory="$component" -C "$component" rev-parse HEAD) == "$expected_commit" ]] || { echo "Generated $repository commit mismatch." >&2; exit 1; }
done
python3 - "$source_dir" "$installer_commit" "$runtime_commit" <<'PY'
import pathlib
import sys
import xml.etree.ElementTree as ET

source = pathlib.Path(sys.argv[1])
for name, expected in zip(('installer', 'runtime'), sys.argv[2:]):
    metadata = source / 'git-info' / (name + '.props')
    if metadata.is_symlink() or not metadata.is_file():
        raise SystemExit('Missing ordinary generated-source metadata: ' + str(metadata))
    matches = ET.parse(metadata).getroot().findall('./PropertyGroup/GitCommitHash')
    if len(matches) != 1 or matches[0].text != expected:
        raise SystemExit('Generated-source metadata commit mismatch: ' + name)
PY
generator=$runtime_dir/eng/common/cross/build-rootfs.sh
[[ -f $generator && ! -L $generator ]] || { echo 'Missing pinned runtime sysroot generator.' >&2; exit 1; }
expected_generator_hash=$(git -c safe.directory="$runtime_dir" -C "$runtime_dir" show "$runtime_commit:eng/common/cross/build-rootfs.sh" | sha256sum | cut -d ' ' -f 1)
[[ $(sha256sum "$generator" | cut -d ' ' -f 1) == "$expected_generator_hash" ]] || { echo 'The runtime sysroot generator differs from its pinned source.' >&2; exit 1; }
rootfs_dir=$inputs_dir/$arch-xenial
# The upstream generator recursively recreates its target. Failed attempts must
# be preserved; never reuse an existing path, including a dangling link.
[[ ! -e $rootfs_dir && ! -L $rootfs_dir ]] || { echo "Refusing existing sysroot: $rootfs_dir" >&2; exit 1; }
for name in sysroot-files.sha256 sysroot-file-list.sha256 sysroot-symlinks.tsv sysroot-packages.tsv sysroot-provenance.json; do
  [[ ! -e $reports_dir/$name && ! -L $reports_dir/$name ]] || { echo "Refusing previous sysroot report: $name" >&2; exit 1; }
done
for tool in debootstrap qemu-debootstrap chroot gpgv sha256sum python3; do
  command -v "$tool" >/dev/null || { echo "Missing preparation tool: $tool" >&2; exit 1; }
done
keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
current_keys=/usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg
historical_keys=/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
for path in "$keyring" "$current_keys" "$historical_keys"; do
  [[ -s $path ]] || { echo "Missing signature-verification keyring: $path" >&2; exit 1; }
done
cat "$current_keys" "$historical_keys" | cmp - "$keyring"
if [[ $arch == x64 ]]; then
  exec bash "$(dirname -- "${BASH_SOURCE[0]}")/prepare-net67-x64-sysroot.sh" \
    "$source_dir" "$inputs_dir" "$reports_dir" "$owner_uid" "$owner_gid" 6
fi
attempt_id=$(date -u +%Y%m%dT%H%M%S)-$$
log_file=$reports_dir/sysroot-prepare-$attempt_id.log
cd "$runtime_dir"
# Use the runtime producer's unchanged generator and selected package sources.
# The matching native host executes target tools directly through qemu-debootstrap.
./eng/common/cross/build-rootfs.sh "$arch" xenial --rootfsdir "$rootfs_dir" 2>&1 | tee "$log_file"
[[ -d $rootfs_dir/usr/include && ! -L $rootfs_dir ]] || { echo 'The generated sysroot is incomplete.' >&2; exit 1; }
find "$rootfs_dir" -type f -print0 | sort -z | xargs -0 sha256sum > "$reports_dir/sysroot-files.sha256"
sha256sum "$reports_dir/sysroot-files.sha256" > "$reports_dir/sysroot-file-list.sha256"
find "$rootfs_dir" -type l -printf '%p\t%l\n' | sort > "$reports_dir/sysroot-symlinks.tsv"
chroot "$rootfs_dir" dpkg-query -W '-f=${binary:Package}\t${Version}\t${Architecture}\n' > "$reports_dir/sysroot-packages.tsv"
python3 - "$source_dir" "$reports_dir" "$rootfs_dir" "$log_file" "$keyring" "$current_keys" "$historical_keys" "$arch" <<'PY'
import datetime
import hashlib
import json
import pathlib
import sys

arch = sys.argv[-1]
source, reports, rootfs, log, *keyrings = map(pathlib.Path, sys.argv[1:-1])
generator = source / 'src/runtime/eng/common/cross/build-rootfs.sh'
record = {
    'preparedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'sourceCommit': 'd638663530d923adbe0442604b7a6562127321e9',
    'runtimeCommit': 'f1dd57165bfd91875761329ac3a8b17f6606ad18',
    'generator': str(generator.relative_to(source)),
    'generatorSha256': hashlib.sha256(generator.read_bytes()).hexdigest(),
    'generatorArguments': [arch, 'xenial', '--rootfsdir', str(rootfs)],
    'packageSignatureVerification': True,
    'qemuDebootstrapWrapper': True,
    'emulation': False,
    'logFile': str(log),
    'sourceMetadata': [{'path': str(path.relative_to(source)),
                        'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                       for path in (source / 'git-info/installer.props', source / 'git-info/runtime.props')],
    'keyrings': [{'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                 for path in keyrings],
}
(reports / 'sysroot-provenance.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
PY
# Both destinations were resolved and checked above; chown only these new paths.
chown -R -- "$owner_uid:$owner_gid" "$rootfs_dir"
chown -- "$owner_uid:$owner_gid" "$log_file" \
  "$reports_dir/sysroot-files.sha256" "$reports_dir/sysroot-file-list.sha256" \
  "$reports_dir/sysroot-symlinks.tsv" "$reports_dir/sysroot-packages.tsv" \
  "$reports_dir/sysroot-provenance.json"
echo "Prepared signed-package $arch Xenial sysroot: $rootfs_dir"
