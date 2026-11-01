#!/usr/bin/env bash
set -euo pipefail

[[ $# == 6 && $1 == /* && $2 == /* && $3 == /* && $4 =~ ^[0-9]+$ && $5 =~ ^[0-9]+$ ]]
[[ $(uname -s) == Linux && $(uname -m) == x86_64 && $(id -u) == 0 ]]
source_dir=$(realpath -e "$1")
inputs_dir=$(realpath -e "$2")
reports_dir=$(realpath -e "$3")
owner_uid=$4
owner_gid=$5
major=$6
[[ $owner_uid != 0 && ! -L $1 && ! -L $2 && ! -L $3 ]]
[[ $source_dir != / && $inputs_dir != / && $reports_dir != / ]]
[[ $inputs_dir != "$source_dir" && $inputs_dir != "$source_dir"/* ]]
[[ $reports_dir != "$source_dir" && $reports_dir != "$source_dir"/* && $reports_dir != "$inputs_dir" && $reports_dir != "$inputs_dir"/* ]]
case "$major" in
  6) installer_commit=d638663530d923adbe0442604b7a6562127321e9; runtime_commit=f1dd57165bfd91875761329ac3a8b17f6606ad18; generator_hash=efaddf18971de883465ef172297cbb9821b2568fc2f41f360a0ba2e74eaa3704 ;;
  7) installer_commit=25b977658c06fd0217ec0bc0714398bb9d0a7bb0; runtime_commit=0fb6ac59fb1edbe4ed3ad62661df0eb7eacd7903; generator_hash=515ca92a06354898bfff4edf524292595eb75bef3668325d381b4c4bcdc1d979 ;;
  *) echo 'Unknown pinned .NET sysroot profile.' >&2; exit 1 ;;
esac
runtime_dir=$source_dir/src/runtime
generator=$runtime_dir/eng/common/cross/build-rootfs.sh
sources=$runtime_dir/eng/common/cross/x86/sources.list.xenial
[[ -f $generator && ! -L $generator && -f $sources && ! -L $sources ]]
[[ $(git -c safe.directory="$runtime_dir" -C "$runtime_dir" rev-parse HEAD) == "$runtime_commit" ]]
[[ $(sha256sum "$generator" | cut -d ' ' -f 1) == "$generator_hash" ]]
[[ $(sha256sum "$sources" | cut -d ' ' -f 1) == 81da96b804b513d7b3b41291e02c2a1198a432a452d11fa4558f25cada1ab78a ]]
for relative in eng/common/cross/build-rootfs.sh eng/common/cross/x86/sources.list.xenial; do
  git -c safe.directory="$runtime_dir" -C "$runtime_dir" show "$runtime_commit:$relative" | cmp - "$runtime_dir/$relative"
done
rootfs=$inputs_dir/x64-xenial
[[ ! -e $rootfs && ! -L $rootfs ]]
for name in sysroot-files.sha256 sysroot-file-list.sha256 sysroot-symlinks.tsv sysroot-packages.tsv sysroot-provenance.json archive-release archive-release.gpg archive-signature-status.txt apt-tls-ca.pem upstream-sources.list applied-sources.list debootstrap.log; do
  [[ ! -e $reports_dir/$name && ! -L $reports_dir/$name ]]
done
keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
current_keys=/usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg
historical_keys=/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
for path in "$keyring" "$current_keys" "$historical_keys"; do [[ -s $path && ! -L $path ]]; done
cat "$current_keys" "$historical_keys" | cmp - "$keyring"
export DEBIAN_FRONTEND=noninteractive

# Runtime 6 has no Linux x64 generator case; runtime 7 lacks its x64 Xenial
# source list. Keep their producers unchanged and use the same signed archive,
# x86 source list and development packages through native amd64 debootstrap.
mirror=https://archive.ubuntu.com/ubuntu
cp -- "$sources" "$reports_dir/upstream-sources.list"
curl --fail --silent --show-error --location "$mirror/dists/xenial/Release" -o "$reports_dir/archive-release"
curl --fail --silent --show-error --location "$mirror/dists/xenial/Release.gpg" -o "$reports_dir/archive-release.gpg"
gpgv --status-fd=1 --keyring "$keyring" "$reports_dir/archive-release.gpg" "$reports_dir/archive-release" > "$reports_dir/archive-signature-status.txt"
grep -Eq '^\[GNUPG:\] VALIDSIG (790BC7277767219C42C86F933B4FE6ACC0B21F32|F6ECB3762474EDA9D21B7022871920D1991BC93C|630239CC130E1A7FD81A27B140976EAF437D05B5) ' "$reports_dir/archive-signature-status.txt"
log=$reports_dir/sysroot-prepare-$(date -u +%Y%m%dT%H%M%S)-$$.log
preserve_failure() {
  status=$?
  if [[ $status != 0 && -f $rootfs/debootstrap/debootstrap.log && ! -L $rootfs/debootstrap/debootstrap.log ]]; then
    cp -- "$rootfs/debootstrap/debootstrap.log" "$reports_dir/debootstrap.log"
    chown -- "$owner_uid:$owner_gid" "$reports_dir/debootstrap.log"
  fi
  exit "$status"
}
trap preserve_failure EXIT
debootstrap --force-check-gpg --keyring="$keyring" --arch=amd64 xenial "$rootfs" "$mirror" 2>&1 | tee "$log"
grep -Eq '^I: (Release signature verified|Valid Release signature)' "$log"
# Keep the current producer CA bytes for Xenial apt's HTTPS transport. Package
# signatures, TLS peer verification and hostname verification stay enabled.
tls_ca_source=/etc/ssl/certs/ca-certificates.crt
tls_ca_target=/etc/ssl/certs/cbodotnet-producer-ca.pem
[[ -s $tls_ca_source && ! -L $tls_ca_source && ! -e $rootfs$tls_ca_target && ! -L $rootfs$tls_ca_target ]]
cp -- "$tls_ca_source" "$reports_dir/apt-tls-ca.pem"
install -m 0644 -- "$reports_dir/apt-tls-ca.pem" "$rootfs$tls_ca_target"
cmp -- "$tls_ca_source" "$rootfs$tls_ca_target"
apt_tls_options=(-o "Acquire::https::CaInfo=$tls_ca_target" -o Acquire::https::Verify-Peer=true -o Acquire::https::Verify-Host=true)
sed 's|http://archive.ubuntu.com/ubuntu/|https://archive.ubuntu.com/ubuntu/|g' "$sources" > "$rootfs/etc/apt/sources.list"
cp -- "$rootfs/etc/apt/sources.list" "$reports_dir/applied-sources.list"
packages=(build-essential symlinks libicu-dev liblttng-ust-dev libunwind8-dev libcurl4-openssl-dev libkrb5-dev libssl-dev zlib1g-dev libomp5 libomp-dev liblldb-3.9-dev)
chroot "$rootfs" apt-get "${apt_tls_options[@]}" update 2>&1 | tee -a "$log"
chroot "$rootfs" apt-get "${apt_tls_options[@]}" -f -y install 2>&1 | tee -a "$log"
chroot "$rootfs" apt-get "${apt_tls_options[@]}" -y install "${packages[@]}" 2>&1 | tee -a "$log"
chroot "$rootfs" symlinks -cr /usr 2>&1 | tee -a "$log"
chroot "$rootfs" apt-get "${apt_tls_options[@]}" clean 2>&1 | tee -a "$log"
statuses=$(chroot "$rootfs" dpkg-query -W '-f=${Status}\n' "${packages[@]}")
[[ $(printf '%s\n' "$statuses" | grep -c '^install ok installed$') == "${#packages[@]}" ]]
chroot "$rootfs" dpkg-query -W '-f=${binary:Package}\t${Version}\t${Architecture}\n' > "$reports_dir/sysroot-packages.tsv"
grep -Eq '^libc6(:amd64)?[[:space:]]+2\.23[^[:space:]]*[[:space:]]+amd64$' "$reports_dir/sysroot-packages.tsv"
[[ -d $rootfs/usr/include && ! -L $rootfs ]]
find "$rootfs" -type f -print0 | sort -z | xargs -0 sha256sum > "$reports_dir/sysroot-files.sha256"
sha256sum "$reports_dir/sysroot-files.sha256" > "$reports_dir/sysroot-file-list.sha256"
find "$rootfs" -type l -printf '%p\t%l\n' | sort > "$reports_dir/sysroot-symlinks.tsv"
python3 - "$source_dir" "$reports_dir" "$rootfs" "$log" "$keyring" "$current_keys" "$historical_keys" "$installer_commit" "$runtime_commit" "${BASH_SOURCE[0]}" "$tls_ca_source" "$tls_ca_target" "${packages[@]}" <<'PY'
import datetime
import hashlib
import json
import pathlib
import sys

source, reports, rootfs, log, keyring, current, historical = map(pathlib.Path, sys.argv[1:8])
installer, runtime, producer = sys.argv[8:11]
tls_source, tls_target = sys.argv[11:13]
packages = sys.argv[13:]
generator = source / 'src/runtime/eng/common/cross/build-rootfs.sh'
sources = source / 'src/runtime/eng/common/cross/x86/sources.list.xenial'

def fingerprint(path):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'sha512': hashlib.sha512(data).hexdigest()}

libc = (rootfs / 'lib/x86_64-linux-gnu/libc.so.6').resolve(strict=True)
if rootfs not in libc.parents or not libc.is_file():
    raise SystemExit('Native x64 sysroot libc escaped its target root')
header = libc.read_bytes()[:20]
if header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != 62:
    raise SystemExit('Native x64 sysroot libc must be ELF64 little-endian machine 62')
record = {
    'preparedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'sourceCommit': installer, 'runtimeCommit': runtime,
    'generator': str(generator.relative_to(source)),
    'generatorSha256': fingerprint(generator)['sha256'],
    'originalGeneratorVerified': True, 'upstreamGeneratorInvoked': False,
    'producer': fingerprint(pathlib.Path(producer).resolve(strict=True)),
    'method': 'explicit-native-amd64-debootstrap', 'architecture': 'amd64',
    'generatorArguments': ['--force-check-gpg', '--keyring=' + str(keyring), '--arch=amd64',
                           'xenial', str(rootfs), 'https://archive.ubuntu.com/ubuntu'],
    'packageSignatureVerification': True, 'releaseSignatureLogVerified': True,
    'qemuDebootstrapWrapper': False, 'emulation': False, 'logFile': str(log),
    'sourceList': fingerprint(sources), 'packageList': packages,
    'retainedSourceList': fingerprint(reports / 'upstream-sources.list'),
    'appliedSourceList': fingerprint(rootfs / 'etc/apt/sources.list'),
    'retainedAppliedSourceList': fingerprint(reports / 'applied-sources.list'),
    'sourceListTransformation': 'archive-http-to-https',
    'archiveRelease': fingerprint(reports / 'archive-release'),
    'archiveSignature': fingerprint(reports / 'archive-release.gpg'),
    'signatureStatus': fingerprint(reports / 'archive-signature-status.txt'),
    'aptTls': {'source': fingerprint(pathlib.Path(tls_source)), 'retained': fingerprint(reports / 'apt-tls-ca.pem'),
               'target': fingerprint(rootfs / tls_target.lstrip('/')), 'caInfo': tls_target,
               'peerVerification': True, 'hostVerification': True, 'packageSignatureVerification': True,
               'arguments': ['-o', 'Acquire::https::CaInfo=' + tls_target,
                             '-o', 'Acquire::https::Verify-Peer=true', '-o', 'Acquire::https::Verify-Host=true']},
    'sourceMetadata': [fingerprint(source / ('git-info/' + name + '.props')) for name in ('installer', 'runtime')],
    'keyrings': [fingerprint(path) for path in (keyring, current, historical)],
}
with (reports / 'sysroot-provenance.json').open('x') as output:
    json.dump(record, output, indent=2); output.write('\n')
PY
chown -R -- "$owner_uid:$owner_gid" "$rootfs"
chown -- "$owner_uid:$owner_gid" "$log" "$reports_dir"/sysroot-{files.sha256,file-list.sha256,symlinks.tsv,packages.tsv,provenance.json} "$reports_dir"/archive-* "$reports_dir/apt-tls-ca.pem" "$reports_dir/upstream-sources.list" "$reports_dir/applied-sources.list"
echo "Prepared signed-package native x64 Xenial sysroot: $rootfs"
