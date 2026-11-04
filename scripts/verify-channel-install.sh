#!/usr/bin/env bash
# Run only inside a disposable native Linux validation container.
set -euo pipefail
[[ $(id -u) == 0 && -f /.dockerenv ]] || { echo 'A disposable root installation container is required.' >&2; exit 2; }
repo=$1
delivery=$2
variant=$3
mode=$4
phase=${5:?Choose the prepare or lifecycle phase.}
. /etc/os-release
case "$ID:$VERSION_ID:$variant" in
  ubuntu:24.04:ubuntu-24.04) icu=libicu74; ssl=libssl3t64 ;;
  debian:13:debian-13) icu=libicu76; ssl=libssl3t64 ;;
  *) echo 'Unexpected installation verification OS.' >&2; exit 2 ;;
esac
if [[ $phase == prepare ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends python3 curl ca-certificates util-linux passwd binutils gnupg gpgv rpm rpm2cpio \
    libc6 libgcc-s1 libstdc++6 zlib1g libgssapi-krb5-2 "$icu" "$ssl"
elif [[ $phase == lifecycle ]]; then
  [[ $(ls /sys/class/net) == lo ]] || { echo 'Runtime validation requires Docker --network none.' >&2; exit 2; }
else
  echo 'Unknown installation verification phase.' >&2
  exit 2
fi
python3 "$repo/scripts/distribution-ci.py" installed --delivery "$delivery" --variant "$variant" --mode "$mode" --phase "$phase"
