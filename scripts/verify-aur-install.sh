#!/usr/bin/env bash
# This updates and installs packages only in the disposable native Arch container.
set -euo pipefail
[[ $(id -u) == 0 && $(uname -m) == x86_64 && -f /.dockerenv ]] || { echo 'A disposable native x86_64 root container is required.' >&2; exit 2; }
. /etc/os-release
[[ $ID == arch ]] || { echo 'Arch Linux is required.' >&2; exit 2; }
repo=$1
delivery=$2
phase=$3
[[ $delivery == /delivery && -d $delivery && ! -L $delivery && ${AUR_OUTPUT_UID:-} =~ ^[0-9]+$ && ${AUR_OUTPUT_GID:-} =~ ^[0-9]+$ ]] || {
  echo 'The mounted validation workspace and caller ownership are required.' >&2; exit 2;
}
# makepkg runs as its own unprivileged user. Return only this mounted scratch
# workspace to the host runner so it can retain evidence and remove caches.
trap 'chown -R --no-dereference -- "$AUR_OUTPUT_UID:$AUR_OUTPUT_GID" "$delivery"' EXIT
# Arch partial upgrades are unsupported. Record the resulting package versions in
# the report, while pinning the starting official image by immutable digest.
case "$phase" in
  prepare)
    # Official minimal images omit documentation via NoExtract. Validate normal
    # full-package Arch installation, including provenance and license notices,
    # so pacman -Qkk verifies every file owned by these packages.
    sed -i -E 's/^([[:space:]]*NoExtract[[:space:]]*=)/# complete-package validation: \1/' /etc/pacman.conf
    pacman -Syu --noconfirm --needed python namcap curl ca-certificates \
      glibc libgcc libstdc++ icu krb5 openssl zlib rpm-tools gnupg binutils
    if python - "$delivery/plan.json" <<'PY'
import json,sys
raise SystemExit(0 if json.load(open(sys.argv[1]))['sdkVersion'].startswith(('3.0.','3.1.')) else 1)
PY
    then pacman -S --noconfirm --needed libnghttp2 e2fsprogs; fi
    python "$repo/scripts/aur-ci.py" prepare --delivery "$delivery"
    ;;
  installed)
    python "$repo/scripts/aur-ci.py" installed --delivery "$delivery"
    ;;
  installed-provider)
    python "$repo/scripts/aur-ci.py" compatibility-installed --delivery "$delivery"
    ;;
  installed-coinstall)
    python "$repo/scripts/aur-coinstall-ci.py" installed --delivery "$delivery"
    ;;
  *) echo 'Unknown Arch validation phase.' >&2; exit 2 ;;
esac
