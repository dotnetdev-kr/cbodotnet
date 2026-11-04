#!/usr/bin/env bash
# This updates and installs packages only in the disposable native Arch container.
set -euo pipefail
[[ $(id -u) == 0 && $(uname -m) == x86_64 ]] || { echo 'A disposable native x86_64 root container is required.' >&2; exit 2; }
. /etc/os-release
[[ $ID == arch ]] || { echo 'Arch Linux is required.' >&2; exit 2; }
repo=$1
delivery=$2
[[ $delivery == /delivery && -d $delivery && ! -L $delivery && ${AUR_OUTPUT_UID:-} =~ ^[0-9]+$ && ${AUR_OUTPUT_GID:-} =~ ^[0-9]+$ ]] || {
  echo 'The mounted validation workspace and caller ownership are required.' >&2; exit 2;
}
# makepkg runs as its own unprivileged user. Return only this mounted scratch
# workspace to the host runner so it can retain evidence and remove caches.
trap 'chown -R --no-dereference -- "$AUR_OUTPUT_UID:$AUR_OUTPUT_GID" "$delivery"' EXIT
# Arch partial upgrades are unsupported. Record the resulting package versions in
# the report, while pinning the starting official image by immutable digest.
pacman -Syu --noconfirm --needed python namcap curl ca-certificates \
  glibc libgcc libstdc++ icu krb5 openssl zlib
python "$repo/scripts/aur-ci.py" installed --delivery "$delivery"
