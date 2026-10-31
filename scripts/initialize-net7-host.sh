#!/usr/bin/env bash
set -euo pipefail

[[ $# == 0 ]] || { echo 'This dedicated .NET 7 host initializer takes no arguments.' >&2; exit 2; }
[[ $(id -u) == 0 && $(uname -s) == Linux && $(uname -m) == aarch64 ]] || { echo 'A native Linux ARM64 root session is required.' >&2; exit 1; }
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 22.04 ]] || { echo 'The dedicated host must be Ubuntu 22.04.' >&2; exit 1; }
[[ ! -L /etc/wsl.conf && ( ! -e /etc/wsl.conf || -f /etc/wsl.conf ) ]] || { echo 'Refusing a non-regular /etc/wsl.conf.' >&2; exit 1; }
# Reject another configured default user before installing or creating anything.
if [[ -f /etc/wsl.conf ]]; then
  configured_defaults=$(awk '
    /^[[:space:]]*\[/ { section=tolower($0); sub(/^[[:space:]]*\[/,"",section); sub(/\].*$/,"",section); gsub(/[[:space:]]/,"",section) }
    section=="user" && tolower($0) ~ /^[[:space:]]*default[[:space:]]*=/ {
      value=$0; sub(/^[^=]*=/,"",value); sub(/[[:space:]]*[#;].*$/,"",value); gsub(/^[[:space:]]+|[[:space:]]+$/,"",value); print value
    }' /etc/wsl.conf)
  [[ -z $configured_defaults || $configured_defaults == build ]] || { echo 'Refusing another configured WSL default user.' >&2; exit 1; }
fi
if id build >/dev/null 2>&1; then
  [[ $(id -u build) == 1000 && $(id -g build) == 1000 && $(getent passwd build | cut -d: -f6) == /home/build && $(getent passwd build | cut -d: -f7) == /bin/bash ]] || { echo 'The existing build account must use UID:GID 1000:1000, /home/build, and /bin/bash.' >&2; exit 1; }
else
  ! getent passwd 1000 >/dev/null || { echo 'Refusing another UID 1000 account.' >&2; exit 1; }
  if getent group build >/dev/null; then
    [[ $(getent group build | cut -d: -f3) == 1000 ]] || { echo 'The existing build group must use GID 1000.' >&2; exit 1; }
  else
    ! getent group 1000 >/dev/null || { echo 'Refusing another GID 1000 group.' >&2; exit 1; }
    groupadd --gid 1000 build
  fi
  useradd --uid 1000 --gid 1000 --home-dir /home/build --create-home --shell /bin/bash build
fi
[[ $(getent group build | cut -d: -f3) == 1000 ]] || { echo 'The build group must use GID 1000.' >&2; exit 1; }
for directory in /home/build /home/build/cbodotnet /home/build/cbodotnet/net7 /home/build/cbodotnet/net7/work /home/build/cbodotnet/net7/inputs /home/build/cbodotnet/net7/container-home; do
  [[ ! -L $directory && ( ! -e $directory || -d $directory ) ]] || { echo "Refusing a non-directory or symbolic link: $directory" >&2; exit 1; }
done
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends podman git python3 curl ca-certificates xz-utils zstd binutils file gpgv uidmap
mkdir -p /home/build/cbodotnet/net7/work /home/build/cbodotnet/net7/inputs /home/build/cbodotnet/net7/container-home
# Change only these dedicated directory entries, without traversing their data.
chown build:build /home/build /home/build/cbodotnet /home/build/cbodotnet/net7 /home/build/cbodotnet/net7/work /home/build/cbodotnet/net7/inputs /home/build/cbodotnet/net7/container-home
python3 - <<'PY'
import configparser
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import stat
import subprocess
import tempfile

path = Path('/etc/wsl.conf')
original = path.read_text() if path.exists() else ''
configuration = configparser.ConfigParser(interpolation=None, strict=True)
configuration.read_string(original)
sections = [name for name in configuration.sections() if name.lower() == 'user']
if len(sections) > 1:
    raise SystemExit('Refusing duplicate WSL user sections')
if sections and configuration.has_option(sections[0], 'default'):
    if configuration.get(sections[0], 'default').strip() != 'build':
        raise SystemExit('Refusing another configured WSL default user')
    updated = original
elif sections:
    pattern = re.compile(r'(^[ \t]*\[' + re.escape(sections[0]) + r'\][^\n]*\n?)', re.MULTILINE)
    updated, count = pattern.subn(lambda match: match[0].rstrip('\n') + '\ndefault=build\n', original, count=1)
    if count != 1:
        raise SystemExit('The existing WSL user section could not be located safely')
else:
    updated = original.rstrip() + '\n\n[user]\ndefault=build\n'
if updated != original:
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix='.cbodotnet-wsl-', delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(updated)
    temporary.chmod(mode)
    os.replace(temporary, path)
packages = ['podman', 'git', 'python3', 'curl', 'ca-certificates', 'xz-utils', 'zstd', 'binutils', 'file', 'gpgv', 'uidmap']
versions = subprocess.check_output(['dpkg-query', '-W', '-f=${Package}\t${Version}\n', *packages], text=True)
account = pwd.getpwnam('build')
record = {'architecture': platform.machine(), 'user': 'build', 'uid': account.pw_uid,
          'gid': account.pw_gid, 'home': account.pw_dir,
          'workspace': '/home/build/cbodotnet/net7', 'configuredDefaultUser': 'build',
          'wslConfChanged': updated != original,
          'wslConfSha256': hashlib.sha256(path.read_bytes()).hexdigest(),
          'packages': dict(line.split('\t', 1) for line in versions.splitlines())}
print('CBODOTNET_HOST_STATE=' + json.dumps(record, sort_keys=True))
PY
