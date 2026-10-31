#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == --help ]]; then
  echo 'Usage: prepare-sysroot5.sh SOURCE_DIR INPUTS_DIR REPORTS_DIR UID GID'
  echo 'Run in the dedicated native ARM64 privileged root container.'
  exit 0
fi
[[ $# == 5 && $1 == /* && $2 == /* && $3 == /* && $4 =~ ^[0-9]+$ && $5 =~ ^[0-9]+$ ]] || { echo 'Absolute paths and numeric UID/GID are required.' >&2; exit 2; }
[[ $(uname -s) == Linux && $(uname -m) == aarch64 && $(id -u) == 0 ]] || { echo 'A native Linux ARM64 root preparation container is required.' >&2; exit 1; }
source_dir=$(realpath -e "$1")
inputs_dir=$(realpath -e "$2")
mkdir -p "$3"
reports_dir=$(realpath -e "$3")
owner_uid=$4
owner_gid=$5
[[ ! -L $1 && ! -L $2 && ! -L $3 && $source_dir != / && $inputs_dir != / && $reports_dir != / ]]
[[ $inputs_dir != "$source_dir" && $inputs_dir != "$source_dir"/* ]]
[[ $reports_dir != "$source_dir" && $reports_dir != "$source_dir"/* && $reports_dir != "$inputs_dir" && $reports_dir != "$inputs_dir"/* ]]
source_commit=d414ecb2d997a9b3f38aaaeddace30ca097e546d
runtime_commit=6a984143635bde23e728abaaccbde52f5ea8fa3e
runtime_dir=$source_dir/artifacts/src/runtime.$runtime_commit
bare=$source_dir/.git/modules/src/runtime.git
[[ $(git -c safe.directory="$source_dir" -C "$source_dir" rev-parse HEAD) == "$source_commit" ]]
[[ -d $runtime_dir && ! -L $runtime_dir && -d $bare && ! -L $bare ]]
[[ $(cat "$runtime_dir/.git/HEAD") == "$runtime_commit" ]]
[[ $(git -c safe.directory="$bare" --git-dir="$bare" rev-parse "$runtime_commit^{commit}") == "$runtime_commit" ]]
generator=$runtime_dir/eng/common/cross/build-rootfs.sh
sources=$runtime_dir/eng/common/cross/arm64/sources.list.xenial
[[ -f $generator && ! -L $generator && -f $sources && ! -L $sources ]]
generator_hash=bd94cd8083b3b9ddcb7e3187181f296254e7c227e1a117a83940f29e5d8a61ef
sources_hash=1faf6648c681e1eeae3a44ba3dd36e2175861898c0ce4f1329d5857d78dfdc8e
[[ $(sha256sum "$generator" | cut -d ' ' -f 1) == "$generator_hash" ]]
[[ $(sha256sum "$sources" | cut -d ' ' -f 1) == "$sources_hash" ]]
[[ $(git -c safe.directory="$bare" --git-dir="$bare" show "$runtime_commit:eng/common/cross/build-rootfs.sh" | sha256sum | cut -d ' ' -f 1) == "$generator_hash" ]]
[[ $(git -c safe.directory="$bare" --git-dir="$bare" show "$runtime_commit:eng/common/cross/arm64/sources.list.xenial" | sha256sum | cut -d ' ' -f 1) == "$sources_hash" ]]
rootfs_dir=$inputs_dir/arm64-xenial
# The unchanged upstream generator recursively recreates its target. Refuse
# every existing target, including a dangling link, and preserve failed attempts.
[[ ! -e $rootfs_dir && ! -L $rootfs_dir ]] || { echo "Refusing existing sysroot: $rootfs_dir" >&2; exit 1; }
for name in sysroot-files.sha256 sysroot-file-list.sha256 sysroot-symlinks.tsv sysroot-packages.tsv sysroot-provenance.json; do
  [[ ! -e $reports_dir/$name && ! -L $reports_dir/$name ]] || { echo "Refusing previous sysroot report: $name" >&2; exit 1; }
done
for tool in debootstrap qemu-debootstrap chroot gpgv sha256sum python3; do command -v "$tool" >/dev/null; done
keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
current_keys=/usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg
historical_keys=/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
for path in "$keyring" "$current_keys" "$historical_keys"; do [[ -s $path ]]; done
cat "$current_keys" "$historical_keys" | cmp - "$keyring"
log_file=$reports_dir/sysroot-prepare-$(date -u +%Y%m%dT%H%M%S)-$$.log
cd "$runtime_dir"
./eng/common/cross/build-rootfs.sh arm64 xenial --rootfsdir "$rootfs_dir" 2>&1 | tee "$log_file"
[[ -d $rootfs_dir/usr/include && ! -L $rootfs_dir ]]
grep -q 'Valid Release signature' "$log_file" || { echo 'The preparation log did not prove Release signature validation.' >&2; exit 1; }
find "$rootfs_dir" -type f -print0 | sort -z | xargs -0 sha256sum > "$reports_dir/sysroot-files.sha256"
sha256sum "$reports_dir/sysroot-files.sha256" > "$reports_dir/sysroot-file-list.sha256"
find "$rootfs_dir" -type l -printf '%p\t%l\n' | sort > "$reports_dir/sysroot-symlinks.tsv"
chroot "$rootfs_dir" dpkg-query -W '-f=${binary:Package}\t${Version}\t${Architecture}\n' > "$reports_dir/sysroot-packages.tsv"
python3 - "$source_dir" "$reports_dir" "$rootfs_dir" "$log_file" "$keyring" "$current_keys" "$historical_keys" <<'PY'
import datetime, hashlib, json, pathlib, sys
source, reports, rootfs, log, *keys = map(pathlib.Path, sys.argv[1:])
runtime = source / 'artifacts/src/runtime.6a984143635bde23e728abaaccbde52f5ea8fa3e'
files = [runtime / 'eng/common/cross/build-rootfs.sh', runtime / 'eng/common/cross/arm64/sources.list.xenial']
record = {
    'schemaVersion': 1, 'preparedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'sourceCommit': 'd414ecb2d997a9b3f38aaaeddace30ca097e546d',
    'runtimeCommit': '6a984143635bde23e728abaaccbde52f5ea8fa3e', 'sysroot': str(rootfs),
    'generator': str(files[0].relative_to(source)), 'generatorSha256': hashlib.sha256(files[0].read_bytes()).hexdigest(),
    'sourcesSha256': hashlib.sha256(files[1].read_bytes()).hexdigest(),
    'generatorArguments': ['arm64', 'xenial', '--rootfsdir', str(rootfs)],
    'packageSignatureVerification': True, 'releaseSignatureLogVerified': True,
    'qemuDebootstrapWrapper': True, 'emulation': False, 'logFile': str(log),
    'keyrings': [{'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in keys],
    'inputs': [{'path': str(p.relative_to(source)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in files],
}
with (reports / 'sysroot-provenance.json').open('x', encoding='utf-8') as output:
    json.dump(record, output, indent=2)
    output.write('\n')
PY
chown -R -- "$owner_uid:$owner_gid" "$rootfs_dir"
chown -- "$owner_uid:$owner_gid" "$log_file" "$reports_dir"/sysroot-*.sha256 \
  "$reports_dir/sysroot-symlinks.tsv" "$reports_dir/sysroot-packages.tsv" "$reports_dir/sysroot-provenance.json"
echo "Prepared signed-package ARM64 Xenial sysroot: $rootfs_dir"
