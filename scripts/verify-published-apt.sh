#!/usr/bin/env bash
# Execute only in disposable containers created by distribution-site-check.yml.
set -euo pipefail
[[ $(id -u) == 0 && -f /.dockerenv ]] || { echo 'A disposable root Docker container is required.' >&2; exit 2; }
phase=$1; variant=$2; sdk=$3; revision=$4; fingerprint=$5; arch=$6; report=$7
[[ $phase == install || $phase == smoke ]]
[[ $sdk =~ ^[1-9][0-9]*\.[0-9]+\.[0-9]+$ && $revision =~ ^[1-9][0-9]*$ && $fingerprint =~ ^[A-F0-9]{40,64}$ ]]
. /etc/os-release
case "$ID:$VERSION_ID:$variant" in ubuntu:24.04:ubuntu-24.04|debian:13:debian-13) ;; *) exit 2 ;; esac
case "$arch:$(uname -m)" in x64:x86_64|aarch64:aarch64|aarch64:arm64) ;; *) exit 2 ;; esac
if [[ $phase == install ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends ca-certificates curl gnupg gpgv python3 util-linux passwd
fi
python3 /repo/scripts/published_apt.py "$phase" --variant "$variant" --sdk "$sdk" --revision "$revision" \
  --fingerprint "$fingerprint" --arch "$arch" --report "$report"
