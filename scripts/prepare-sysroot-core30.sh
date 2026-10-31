#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} == --help ]]; then
  echo 'Usage: prepare-sysroot-core30.sh /absolute/source-build /absolute/inputs /absolute/reports UID GID'
  echo 'Run in a dedicated native ARM64 privileged root container with read-only sources.'
  exit 0
fi
[[ $# == 5 && $1 == /* && $2 == /* && $3 == /* && $4 =~ ^[0-9]+$ && $5 =~ ^[0-9]+$ ]] || { echo 'Absolute source, inputs, reports and numeric UID/GID are required.' >&2; exit 2; }
[[ $(uname -s) == Linux && $(uname -m) == aarch64 && $(id -u) == 0 ]] || { echo 'A native Linux ARM64 root container is required.' >&2; exit 1; }
source_dir=$(realpath -e "$1")
inputs_dir=$(realpath -e "$2")
mkdir -p "$3"
reports_dir=$(realpath -e "$3")
owner_uid=$4
owner_gid=$5
[[ ! -L $1 && ! -L $2 && ! -L $3 && $source_dir != / && $inputs_dir != / && $reports_dir != / ]] || { echo 'Ordinary non-root directories are required.' >&2; exit 2; }
[[ $inputs_dir != "$source_dir" && $inputs_dir != "$source_dir"/* && $reports_dir != "$source_dir" && $reports_dir != "$source_dir"/* && $reports_dir != "$inputs_dir" && $reports_dir != "$inputs_dir"/* ]] || { echo 'Sources, inputs and external reports must be separate.' >&2; exit 2; }
# The host Git security backport honors this selected owner context when a
# privileged container inspects the unprivileged account's read-only checkout.
[[ $(stat -c %u "$source_dir") == "$owner_uid" && $owner_uid != 0 ]] || { echo 'The selected UID must own the source checkout.' >&2; exit 1; }
export SUDO_UID=$owner_uid
source_commit=40de72d1087a1d05dfd39c87f888a0611ec6c60f
corefx_commit=a4238c9819075be9bff74e009da802ce47233f38
corefx_dir=$source_dir/bin/src/corefx.$corefx_commit
bare=$source_dir/.git/modules/src/corefx.git
[[ $(git -c safe.directory="$source_dir" -C "$source_dir" rev-parse --show-toplevel) == "$source_dir" && $(git -c safe.directory="$source_dir" -C "$source_dir" rev-parse HEAD) == "$source_commit" ]] || { echo 'Pinned source-build checkout mismatch.' >&2; exit 1; }
[[ -d $corefx_dir && ! -L $corefx_dir && -d $bare && ! -L $bare ]] || { echo 'Pinned CoreFX export and bare store are required.' >&2; exit 1; }
generator=$corefx_dir/cross/build-rootfs.sh
for relative in cross/build-rootfs.sh cross/arm64/sources.list.xenial; do
  path=$corefx_dir/$relative
  [[ -f $path && ! -L $path ]] || { echo "Missing ordinary pinned CoreFX input: $relative" >&2; exit 1; }
  git -c safe.directory="$bare" --git-dir="$bare" show "$corefx_commit:$relative" | cmp - "$path"
done
if grep -q -- '--no-check-gpg\|allow-unauthenticated' "$generator"; then
  echo 'The sysroot generator must retain package authentication.' >&2; exit 1
fi
rootfs_dir=$inputs_dir/arm64-xenial
[[ ! -e $rootfs_dir && ! -L $rootfs_dir ]] || { echo "Refusing existing sysroot: $rootfs_dir" >&2; exit 1; }
for name in sysroot-files.sha256 sysroot-file-list.sha256 sysroot-symlinks.tsv sysroot-packages.tsv sysroot-provenance.json; do
  [[ ! -e $reports_dir/$name && ! -L $reports_dir/$name ]] || { echo "Refusing previous report: $name" >&2; exit 1; }
done
for tool in debootstrap qemu-debootstrap chroot gpgv sha256sum python3; do command -v "$tool" >/dev/null; done
keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
current_keys=/usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg
historical_keys=/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
for path in "$keyring" "$current_keys" "$historical_keys"; do [[ -s $path ]]; done
cat "$current_keys" "$historical_keys" | cmp - "$keyring"
log_file=$reports_dir/sysroot-prepare-$(date -u +%Y%m%dT%H%M%S)-$$.log
cd "$corefx_dir"
# The unchanged producer defaults to authenticated qemu-debootstrap. ROOTFS_DIR
# chooses a fresh destination; no historical sysroot or package cache is reused.
ROOTFS_DIR="$rootfs_dir" bash "$generator" arm64 xenial no-lldb 2>&1 | tee "$log_file"
[[ -f $rootfs_dir/etc/os-release && -d $rootfs_dir/usr/include && ! -L $rootfs_dir ]] || { echo 'The generated sysroot is incomplete.' >&2; exit 1; }
grep -Eq '^I: (Release signature verified|Valid Release signature) \(key id 790BC7277767219C42C86F933B4FE6ACC0B21F32\)$' "$log_file" || { echo 'The authenticated Xenial archive signature and expected signing fingerprint were not recorded.' >&2; exit 1; }
# The old generator does not stop after every failed command. Require its
# complete requested development package set before accepting its result.
statuses=$(chroot "$rootfs_dir" dpkg-query -W '-f=${Status}\n' build-essential symlinks libicu-dev liblttng-ust-dev libunwind8-dev libcurl4-openssl-dev libkrb5-dev libssl-dev zlib1g-dev)
[[ $(printf '%s\n' "$statuses" | grep -c '^install ok installed$') == 9 ]] || { echo 'Required target development packages were not installed.' >&2; exit 1; }
chroot "$rootfs_dir" dpkg-query -W '-f=${binary:Package}\t${Version}\t${Architecture}\n' > "$reports_dir/sysroot-packages.tsv"
grep -Eq '^libc6:arm64[[:space:]]+2\.23' "$reports_dir/sysroot-packages.tsv" || { echo 'Expected ARM64 Xenial libc was not installed.' >&2; exit 1; }
find "$rootfs_dir" -type f -print0 | sort -z | xargs -0 sha256sum > "$reports_dir/sysroot-files.sha256"
sha256sum "$reports_dir/sysroot-files.sha256" > "$reports_dir/sysroot-file-list.sha256"
find "$rootfs_dir" -type l -printf '%p\t%l\n' | sort > "$reports_dir/sysroot-symlinks.tsv"
python3 - "$source_dir" "$reports_dir" "$rootfs_dir" "$log_file" "$keyring" "$current_keys" "$historical_keys" <<'PY'
import datetime, hashlib, json, os, pathlib, sys
source, reports, rootfs, log, *keys = map(pathlib.Path, sys.argv[1:])
relative = 'bin/src/corefx.a4238c9819075be9bff74e009da802ce47233f38/cross/build-rootfs.sh'
record = {
    'preparedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'sourceCommit': '40de72d1087a1d05dfd39c87f888a0611ec6c60f',
    'corefxCommit': 'a4238c9819075be9bff74e009da802ce47233f38',
    'generator': relative,
    'generatorSha256': hashlib.sha256((source / relative).read_bytes()).hexdigest(),
    'generatorArguments': ['arm64', 'xenial', 'no-lldb'],
    'generatorEnvironment': {'ROOTFS_DIR': str(rootfs)},
    'packageSignatureVerification': True,
    'signatureEvidence': 'The preserved preparation log records an authenticated Release signature and the expected Xenial archive signing fingerprint.',
    'signingKeyFingerprint': '790BC7277767219C42C86F933B4FE6ACC0B21F32',
    'qemuDebootstrapWrapper': True, 'emulation': False, 'logFile': str(log),
    'gitOwnerContext': {'sourceOwnerUid': source.stat().st_uid, 'sudoUid': int(os.environ['SUDO_UID']),
                        'globalGitConfigurationChanged': False},
    'keyrings': [{'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in keys],
}
with (reports / 'sysroot-provenance.json').open('x', encoding='utf-8') as output:
    json.dump(record, output, indent=2); output.write('\n')
PY
chown -R -- "$owner_uid:$owner_gid" "$rootfs_dir"
chown -- "$owner_uid:$owner_gid" "$log_file" "$reports_dir"/sysroot-{files.sha256,file-list.sha256,symlinks.tsv,packages.tsv,provenance.json}
echo "Prepared signed-package Core 3.0 ARM64 Xenial sysroot: $rootfs_dir"
