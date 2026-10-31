#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == --help ]]; then
  echo 'Usage: prepare-sysroot9.sh /absolute/vmr /absolute/inputs /absolute/reports UID GID'
  echo 'Run in a dedicated native ARM64 privileged root container; the source can be read-only.'
  exit 0
fi
[[ $# == 5 ]] || { echo 'Expected VMR, input parent, report paths, and owner UID/GID.' >&2; exit 2; }
[[ $1 == /* && $2 == /* && $3 == /* && $4 =~ ^[0-9]+$ && $5 =~ ^[0-9]+$ ]] || { echo 'Absolute paths and numeric UID/GID are required.' >&2; exit 2; }
[[ $(uname -s) == Linux && $(uname -m) == aarch64 && $(id -u) == 0 ]] || { echo 'A native Linux ARM64 root preparation container is required.' >&2; exit 1; }
source_dir=$(realpath -e "$1")
inputs_dir=$(realpath -e "$2")
mkdir -p "$3"
reports_dir=$(realpath -e "$3")
owner_uid=$4
owner_gid=$5
[[ $inputs_dir != / && $inputs_dir != "$source_dir" && $inputs_dir != "$source_dir"/* ]] || { echo 'Unsafe input parent.' >&2; exit 2; }
[[ $reports_dir != / && $reports_dir != "$source_dir" && $reports_dir != "$source_dir"/* && $reports_dir != "$inputs_dir" && $reports_dir != "$inputs_dir"/* ]] || { echo 'Reports must be outside the source and inputs.' >&2; exit 2; }
[[ $(git -c safe.directory="$source_dir" -C "$source_dir" rev-parse HEAD) == 9f04b57d1366e21b3178648493d6edffeff2216e ]] || { echo 'VMR commit mismatch.' >&2; exit 1; }
rootfs_dir=$inputs_dir/arm64-xenial
# The upstream generator recursively recreates its target. Never give it an
# existing path, including a dangling link. Failed attempts must be preserved.
[[ ! -e $rootfs_dir && ! -L $rootfs_dir ]] || { echo "Refusing existing sysroot: $rootfs_dir" >&2; exit 1; }
for name in sysroot-files.sha256 sysroot-file-list.sha256 sysroot-symlinks.tsv sysroot-packages.tsv sysroot-provenance.json; do
  [[ ! -e $reports_dir/$name && ! -L $reports_dir/$name ]] || { echo "Refusing previous sysroot report: $name" >&2; exit 1; }
done
for tool in debootstrap chroot gpgv sha256sum python3; do
  command -v "$tool" >/dev/null || { echo "Missing preparation tool: $tool" >&2; exit 1; }
done
keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
current_keys=/usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg
historical_keys=/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
for path in "$keyring" "$current_keys" "$historical_keys"; do
  [[ -s $path ]] || { echo "Missing signature-verification keyring: $path" >&2; exit 1; }
done
# Prove the configured verifier keyring is the recorded union from our image.
cat "$current_keys" "$historical_keys" | cmp - "$keyring"
attempt_id=$(date -u +%Y%m%dT%H%M%S)-$$
log_file=$reports_dir/sysroot-prepare-$attempt_id.log
cd "$source_dir"
# No --skipsigcheck, foreign architecture emulation, or source modifications.
./eng/common/cross/build-rootfs.sh arm64 xenial --rootfsdir "$rootfs_dir" 2>&1 | tee "$log_file"
[[ -d $rootfs_dir/usr/include && ! -L $rootfs_dir ]] || { echo 'The generated sysroot is incomplete.' >&2; exit 1; }
find "$rootfs_dir" -type f -print0 | sort -z | xargs -0 sha256sum > "$reports_dir/sysroot-files.sha256"
sha256sum "$reports_dir/sysroot-files.sha256" > "$reports_dir/sysroot-file-list.sha256"
find "$rootfs_dir" -type l -printf '%p\t%l\n' | sort > "$reports_dir/sysroot-symlinks.tsv"
chroot "$rootfs_dir" dpkg-query -W '-f=${binary:Package}\t${Version}\t${Architecture}\n' > "$reports_dir/sysroot-packages.tsv"
python3 - "$source_dir" "$reports_dir" "$rootfs_dir" "$log_file" "$keyring" "$current_keys" "$historical_keys" <<'PY'
import datetime
import hashlib
import json
import pathlib
import sys

source, reports, rootfs, log, *keyrings = map(pathlib.Path, sys.argv[1:])
generator = source / 'eng/common/cross/build-rootfs.sh'
record = {
    'preparedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'sourceCommit': '9f04b57d1366e21b3178648493d6edffeff2216e',
    'generator': 'eng/common/cross/build-rootfs.sh',
    'generatorSha256': hashlib.sha256(generator.read_bytes()).hexdigest(),
    'generatorArguments': ['arm64', 'xenial', '--rootfsdir', str(rootfs)],
    'packageSignatureVerification': True,
    'emulation': False,
    'logFile': str(log),
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
echo "Prepared signed-package ARM64 Xenial sysroot: $rootfs_dir"
