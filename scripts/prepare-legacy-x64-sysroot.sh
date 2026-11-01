#!/usr/bin/env bash
set -euo pipefail

[[ $# == 5 && $1 == /* && $2 == /* && $3 == /* && $4 =~ ^[0-9]+$ && $5 =~ ^[0-9]+$ ]]
[[ $(uname -s) == Linux && $(uname -m) == x86_64 && $(id -u) == 0 ]]
source_dir=$(realpath -e "$1")
inputs_dir=$(realpath -e "$2")
mkdir -p "$3"
reports_dir=$(realpath -e "$3")
owner_uid=$4
owner_gid=$5
[[ $owner_uid != 0 && $(stat -c %u "$source_dir") == "$owner_uid" ]]
[[ ! -L $1 && ! -L $2 && ! -L $3 && $source_dir != / && $inputs_dir != / && $reports_dir != / ]]
[[ $inputs_dir != "$source_dir" && $inputs_dir != "$source_dir"/* && $reports_dir != "$source_dir" && $reports_dir != "$source_dir"/* && $reports_dir != "$inputs_dir" && $reports_dir != "$inputs_dir"/* ]]
export SUDO_UID=$owner_uid DEBIAN_FRONTEND=noninteractive
source_commit=$(git -c safe.directory="$source_dir" -C "$source_dir" rev-parse HEAD)
case "$source_commit" in
  40de72d1087a1d05dfd39c87f888a0611ec6c60f) family=core30; component=corefx; component_commit=a4238c9819075be9bff74e009da802ce47233f38; layout=bin; relative=cross/build-rootfs.sh ;;
  ab8b115b5658237ee8916ae3586600b39fb2fd19) family=core31; component=corefx; component_commit=b58ef0a19eca6269799664d6288be14b7f0cef3e; layout=artifacts; relative=cross/build-rootfs.sh ;;
  d414ecb2d997a9b3f38aaaeddace30ca097e546d) family=net5; component=runtime; component_commit=6a984143635bde23e728abaaccbde52f5ea8fa3e; layout=artifacts; relative=eng/common/cross/build-rootfs.sh ;;
  *) echo 'Unknown pinned legacy source root.' >&2; exit 1 ;;
esac
component_dir=$source_dir/$layout/src/$component.$component_commit
bare=$source_dir/.git/modules/src/$component.git
[[ -d $component_dir && ! -L $component_dir && -d $bare && ! -L $bare ]]
generator=$component_dir/$relative
[[ -f $generator && ! -L $generator ]]
git -c safe.directory="$bare" --git-dir="$bare" show "$component_commit:$relative" | cmp - "$generator"
rootfs=$inputs_dir/x64-xenial
[[ ! -e $rootfs && ! -L $rootfs ]]
for name in sysroot-files.sha256 sysroot-file-list.sha256 sysroot-symlinks.tsv sysroot-packages.tsv sysroot-provenance.json archive-release archive-release.gpg archive-signature-status.txt; do
  [[ ! -e $reports_dir/$name && ! -L $reports_dir/$name ]]
done
keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
current_keys=/usr/share/keyrings/cbodotnet-current-ubuntu-archive.gpg
historical_keys=/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
for path in "$keyring" "$current_keys" "$historical_keys"; do [[ -s $path && ! -L $path ]]; done
cat "$current_keys" "$historical_keys" | cmp - "$keyring"
# These older upstream generators have no x64 case. This explicit native
# producer preserves their requested development package set and archive trust.
mirror=https://archive.ubuntu.com/ubuntu
curl --fail --silent --show-error --location "$mirror/dists/xenial/Release" -o "$reports_dir/archive-release"
curl --fail --silent --show-error --location "$mirror/dists/xenial/Release.gpg" -o "$reports_dir/archive-release.gpg"
gpgv --status-fd=1 --keyring "$keyring" "$reports_dir/archive-release.gpg" "$reports_dir/archive-release" > "$reports_dir/archive-signature-status.txt"
grep -Eq '^\[GNUPG:\] VALIDSIG (790BC7277767219C42C86F933B4FE6ACC0B21F32|F6ECB3762474EDA9D21B7022871920D1991BC93C|630239CC130E1A7FD81A27B140976EAF437D05B5) ' "$reports_dir/archive-signature-status.txt"
log=$reports_dir/sysroot-prepare-$(date -u +%Y%m%dT%H%M%S)-$$.log
debootstrap --force-check-gpg --keyring="$keyring" --arch=amd64 xenial "$rootfs" "$mirror" 2>&1 | tee "$log"
grep -Eq '^I: (Release signature verified|Valid Release signature)' "$log"
cat > "$rootfs/etc/apt/sources.list" <<EOF
deb $mirror xenial main restricted universe multiverse
deb $mirror xenial-updates main restricted universe multiverse
deb $mirror xenial-security main restricted universe multiverse
EOF
packages=(build-essential symlinks libicu-dev liblttng-ust-dev libunwind8-dev libcurl4-openssl-dev libkrb5-dev libssl-dev zlib1g-dev)
[[ $family != net5 ]] || packages+=(liblldb-3.9-dev)
chroot "$rootfs" apt-get update 2>&1 | tee -a "$log"
chroot "$rootfs" apt-get -y install "${packages[@]}" 2>&1 | tee -a "$log"
chroot "$rootfs" symlinks -cr /usr 2>&1 | tee -a "$log"
statuses=$(chroot "$rootfs" dpkg-query -W '-f=${Status}\n' "${packages[@]}")
[[ $(printf '%s\n' "$statuses" | grep -c '^install ok installed$') == "${#packages[@]}" ]]
chroot "$rootfs" dpkg-query -W '-f=${binary:Package}\t${Version}\t${Architecture}\n' > "$reports_dir/sysroot-packages.tsv"
grep -Eq '^libc6(:amd64)?[[:space:]]+2\.23[^[:space:]]*[[:space:]]+amd64$' "$reports_dir/sysroot-packages.tsv"
find "$rootfs" -type f -print0 | sort -z | xargs -0 sha256sum > "$reports_dir/sysroot-files.sha256"
sha256sum "$reports_dir/sysroot-files.sha256" > "$reports_dir/sysroot-file-list.sha256"
find "$rootfs" -type l -printf '%p\t%l\n' | sort > "$reports_dir/sysroot-symlinks.tsv"
python3 - "$source_dir" "$reports_dir" "$rootfs" "$log" "$keyring" "$current_keys" "$historical_keys" "$generator" "$component_commit" "$family" "${BASH_SOURCE[0]}" <<'PY'
import datetime, hashlib, json, os, pathlib, sys
source, reports, rootfs, log, keyring, current, historical, generator = map(pathlib.Path, sys.argv[1:9])
component, family, producer = sys.argv[9:]
def fp(path):
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
record = {'preparedAtUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'sourceCommit': {'net5':'d414ecb2d997a9b3f38aaaeddace30ca097e546d','core31':'ab8b115b5658237ee8916ae3586600b39fb2fd19','core30':'40de72d1087a1d05dfd39c87f888a0611ec6c60f'}[family],
          'family': family, 'architecture': 'amd64', 'sysroot': str(rootfs),
          'generator': str(generator.relative_to(source)), 'generatorSha256': fp(generator)['sha256'],
          'componentCommit': component, 'originalGeneratorVerified': True,
          'producer': fp(pathlib.Path(producer).resolve()), 'method': 'explicit-native-amd64-debootstrap',
          'generatorArguments': ['--force-check-gpg','--arch=amd64','xenial',str(rootfs),'https://archive.ubuntu.com/ubuntu'],
          'packageSignatureVerification': True, 'releaseSignatureLogVerified': True,
          'emulation': False, 'qemuDebootstrapWrapper': False, 'logFile': str(log),
          'archiveRelease': fp(reports/'archive-release'), 'archiveSignature': fp(reports/'archive-release.gpg'),
          'signatureStatus': fp(reports/'archive-signature-status.txt'),
          'keyrings': [fp(path) for path in (keyring,current,historical)],
          'gitOwnerContext': {'sourceOwnerUid': source.stat().st_uid,'sudoUid': int(os.environ['SUDO_UID']),'globalGitConfigurationChanged': False},
          'scope': 'Independent signed amd64 Xenial sysroot with the pinned legacy producer package set; no ARM sysroot or emulation.'}
with (reports/'sysroot-provenance.json').open('x') as output:
    json.dump(record,output,indent=2); output.write('\n')
PY
chown -R -- "$owner_uid:$owner_gid" "$rootfs"
chown -- "$owner_uid:$owner_gid" "$log" "$reports_dir"/sysroot-{files.sha256,file-list.sha256,symlinks.tsv,packages.tsv,provenance.json} "$reports_dir"/archive-*
