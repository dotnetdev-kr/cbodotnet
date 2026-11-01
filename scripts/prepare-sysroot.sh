#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == --help ]]; then
  echo 'Usage: prepare-sysroot.sh /absolute/vmr /absolute/inputs /absolute/reports [--arch arm64|x64]'
  exit 0
fi
[[ $# == 3 || ( $# == 5 && $4 == --arch ) ]] || { echo 'Expected VMR, input parent, report paths and optional architecture.' >&2; exit 2; }
arch=${5:-arm64}
case "$arch" in arm64) native=aarch64 ;; x64) native=x86_64 ;; *) echo 'Unsupported architecture.' >&2; exit 2 ;; esac
[[ $1 == /* && $2 == /* && $3 == /* ]] || { echo 'All paths must be absolute.' >&2; exit 2; }
source_dir=$(realpath -e "$1")
inputs_dir=$(realpath -e "$2")
reports_dir=$3
[[ $inputs_dir != / && $inputs_dir != "$source_dir" && $inputs_dir != "$source_dir"/* ]] || exit 2
[[ $(uname -s) == Linux && $(uname -m) == "$native" ]] || { echo 'A matching native Linux host is required.' >&2; exit 1; }
[[ $(git -C "$source_dir" rev-parse HEAD) == 5a2162bea6845eabc1fc721624a43568c65db3b1 ]] || exit 1
rootfs_dir=$inputs_dir/$arch-bionic
# Upstream recreates its target recursively; refuse any existing target here.
[[ ! -e $rootfs_dir && ! -L $rootfs_dir ]] || { echo "Refusing existing sysroot: $rootfs_dir" >&2; exit 1; }
mkdir -p "$reports_dir"
cd "$source_dir"
./eng/common/cross/build-rootfs.sh "$arch" bionic --skipemulation \
  --rootfsdir "$rootfs_dir" 2>&1 | tee "$reports_dir/sysroot-prepare.log"
find "$rootfs_dir" -type f -print0 | sort -z | xargs -0 sha256sum > "$reports_dir/sysroot-files.sha256"
sha256sum "$reports_dir/sysroot-files.sha256" > "$reports_dir/sysroot-file-list.sha256"
find "$rootfs_dir" -type l -printf '%p\t%l\n' | sort > "$reports_dir/sysroot-symlinks.tsv"
echo "Prepared signed-package $arch sysroot: $rootfs_dir"
