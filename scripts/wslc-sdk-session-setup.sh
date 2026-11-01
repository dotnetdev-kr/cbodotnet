#!/usr/bin/env bash
set -euo pipefail

architecture=${1:?Expected aarch64 or x64}
expected_sha=${2:?Expected SDK archive SHA256}
sdk_root=/opt/cbodotnet/sdk
archive=${3:?Expected copied SDK archive path}
case "$architecture" in
  aarch64|arm64) expected_machine=aarch64; expected_elf=183 ;;
  x64) expected_machine=x86_64; expected_elf=62 ;;
  *) echo "Unsupported architecture: $architecture" >&2; exit 1 ;;
esac
[[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]] || { echo 'Invalid archive SHA256.' >&2; exit 1; }
[[ $(uname -m) == "$expected_machine" ]] || { echo 'Container architecture does not match the SDK target.' >&2; exit 1; }

mkdir -p /opt/cbodotnet /work
if [[ -e "$sdk_root" ]]; then
  [[ -f "$sdk_root/.cbodotnet-archive-sha256" && $(cat "$sdk_root/.cbodotnet-archive-sha256") == "$expected_sha" ]] || {
    echo 'Existing SDK does not match the selected archive. Choose a new container name.' >&2
    exit 1
  }
else
  printf '%s  %s\n' "$expected_sha" "$archive" | sha256sum --check --status || {
    echo 'Copied SDK archive SHA256 does not match the Windows source.' >&2
    exit 1
  }
  staging=$(mktemp -d /opt/cbodotnet/.sdk.XXXXXX)
  trap 'rm -rf -- "$staging"' EXIT
  tar --extract --gzip --file "$archive" --directory "$staging" --no-same-owner
  [[ -x "$staging/dotnet" ]] || { echo 'Archive has no executable dotnet at its root.' >&2; exit 1; }
  # ELF e_machine is at byte 18; both supported Linux targets are little endian.
  actual_elf=$(od -An -tu2 -j18 -N2 "$staging/dotnet" | tr -d '[:space:]')
  [[ "$actual_elf" == "$expected_elf" ]] || { echo 'Archive dotnet binary has the wrong architecture.' >&2; exit 1; }
  "$staging/dotnet" --version
  printf '%s\n' "$expected_sha" > "$staging/.cbodotnet-archive-sha256"
  mv -- "$staging" "$sdk_root"
  trap - EXIT
  rm -- "$archive"
fi

cat > /opt/cbodotnet/session.bashrc <<'BASHRC'
[[ ! -r /etc/bash.bashrc ]] || source /etc/bash.bashrc
export DOTNET_ROOT=/opt/cbodotnet/sdk
export PATH="$DOTNET_ROOT:$PATH"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
export ASPNETCORE_URLS=http://0.0.0.0:5000
printf '\nSDK test workspace: /work\n'
printf 'Try: dotnet new console -o ConsoleDemo && dotnet run --project ConsoleDemo\n'
printf 'Web: dotnet new web -o WebDemo && dotnet run --project WebDemo --urls http://0.0.0.0:5000\n'
printf 'Leaving Bash retains the container and /work.\n\n'
BASHRC
"$sdk_root/dotnet" --info
