#!/usr/bin/env bash
# Only disposable native Fedora/Rocky containers may execute these phases.
set -euo pipefail
[[ $(id -u) == 0 && -f /.dockerenv ]] || { echo 'A disposable root Docker container is required.' >&2; exit 2; }
repo=$1; delivery=$2; variant=$3; phase=$4
. /etc/os-release
case "$ID:$VERSION_ID:$variant" in fedora:45:fedora-45|rocky:9.8:rocky-9.8) ;; *) echo 'Unexpected RPM verification OS.' >&2; exit 2 ;; esac
export PATH=/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin
if [[ $phase == build || $phase == prepare || $phase == prepare-published ]]; then
  curl_package=curl
  # Rocky's base image already owns /usr/bin/curl through curl-minimal.
  # Its HTTP support covers the offline smoke probe without replacing it.
  if [[ $ID == rocky ]]; then curl_package=curl-minimal; fi
  dnf -y --setopt=install_weak_deps=False --setopt=tsflags= install \
    python3 rpm-build rpm-sign cpio tar gzip xz shadow-utils util-linux "$curl_package" ca-certificates binutils findutils gnupg2
  if [[ $ID == rocky ]]; then
    dnf -y --setopt=install_weak_deps=False --setopt=tsflags= install python3.12
    install -d /usr/local/bin
    ln -sfn /usr/bin/python3.12 /usr/local/bin/python3
  fi
  mapfile -t dependencies < <(python3 - "$delivery/plan.json" <<'PY'
import json,sys
for name in json.load(open(sys.argv[1]))['dependencies']:
    if name != 'cbodotnet-compat-rocky9': print(name)
PY
)
  dnf -y --setopt=install_weak_deps=False --setopt=tsflags= install "${dependencies[@]}"
fi
if [[ $phase == build ]]; then
  [[ ${BUILDER_UID:?} =~ ^[1-9][0-9]*$ && ${BUILDER_GID:?} =~ ^[1-9][0-9]*$ ]]
  groupadd --gid "$BUILDER_GID" cbot-builder
  useradd --create-home --uid "$BUILDER_UID" --gid "$BUILDER_GID" cbot-builder
  runuser -u cbot-builder -- env PATH="$PATH" python3 "$repo/scripts/rpm-ci.py" build-in-container --delivery "$delivery"
elif [[ $phase == prepare || $phase == prepare-published ]]; then
  python3 "$repo/scripts/rpm-ci.py" prepare-installed --delivery "$delivery" --published "$([[ $phase == prepare-published ]] && echo yes || echo no)"
elif [[ $phase == smoke ]]; then
  [[ $(ls /sys/class/net) == lo ]] || { echo 'RPM runtime proof requires Docker --network none.' >&2; exit 2; }
  python3 "$repo/scripts/rpm-ci.py" lifecycle --delivery "$delivery"
else
  echo 'Unknown RPM verification phase.' >&2; exit 2
fi
