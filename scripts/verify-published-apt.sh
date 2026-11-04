#!/usr/bin/env bash
# Execute only in disposable containers created by distribution-site-check.yml.
set -euo pipefail
[[ $(id -u) == 0 && -f /.dockerenv ]] || { echo 'A disposable root Docker container is required.' >&2; exit 2; }
phase=$1; variant=$2; sdk=$3; revision=$4; fingerprint=$5; arch=$6; report=$7
[[ $sdk =~ ^[1-9][0-9]*\.[0-9]+\.[0-9]+$ && $revision =~ ^[1-9][0-9]*$ && $fingerprint =~ ^[A-F0-9]{40,64}$ ]]
series=${sdk%.*}
. /etc/os-release
case "$ID:$VERSION_ID:$variant" in ubuntu:24.04:ubuntu-24.04|debian:13:debian-13) ;; *) exit 2 ;; esac
case "$arch:$(uname -m)" in x64:x86_64|aarch64:aarch64|aarch64:arm64) ;; *) exit 2 ;; esac
package=cbodotnet-sdk-$series
brand='Community Build of .NET (built by .NET Dev)'
repository=https://dotnetdev.kr/cbodotnet/packages/deb/$variant
user=cbot-apt-smoke
work=/home/$user/project
if [[ $phase == install ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends ca-certificates curl gnupg python3 util-linux passwd
  curl --fail --silent --show-error --location --retry 3 \
    https://dotnetdev.kr/cbodotnet/cbodotnet-archive-keyring.gpg \
    --output /usr/share/keyrings/cbodotnet-archive-keyring.gpg
  # Match every primary fingerprint, so an appended unrelated key cannot inherit trust.
  actual=$(gpg --batch --show-keys --with-colons /usr/share/keyrings/cbodotnet-archive-keyring.gpg | \
    awk -F: '$1=="pub"{primary=1} $1=="fpr" && primary{print $10;primary=0}')
  [[ $actual == "$fingerprint" ]] || { echo 'Published repository key differs from reviewed policy.' >&2; exit 2; }
  printf 'deb [signed-by=/usr/share/keyrings/cbodotnet-archive-keyring.gpg] %s ./\n' "$repository" \
    > /etc/apt/sources.list.d/cbodotnet.list
  apt-get update
  apt-get install -y "$package=$sdk-$revision" cbodotnet-host
  [[ $(dpkg-query -W -f='${Version}' "$package") == "$sdk-$revision" ]]
  useradd --create-home --user-group --uid 10001 "$user"
  install -d -m 0755 -o "$user" -g "$user" "$work"
  for command in "cbodotnet-$series" cbodotnet; do
    runuser -u "$user" -- env HOME="/home/$user" DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
      "$command" --version > /tmp/cbodotnet-version.stdout 2> /tmp/cbodotnet-version.stderr
    [[ $(cat /tmp/cbodotnet-version.stdout) == "$sdk" && $(cat /tmp/cbodotnet-version.stderr) == "$brand" ]]
    "$command" --cbodotnet-info | python3 -c 'import json,sys; from pathlib import Path
v=json.load(sys.stdin); c=json.loads(Path("/repo/releases/distribution-contract.json").read_bytes())
assert v["sdkVersion"]==sys.argv[1] and v["distributionBrand"]==c["branding"]["displayName"]
assert v["sourceManifestSha256"]==c["releases"][sys.argv[1]]["manifestSha256"]' "$sdk"
  done
  printf '<configuration><packageSources><clear /></packageSources></configuration>\n' > "$work/NuGet.Config"
  printf '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net%s</TargetFramework><OutputType>Exe</OutputType></PropertyGroup></Project>\n' "$series" > "$work/Smoke.csproj"
  printf 'System.Console.WriteLine("published-https-apt-offline-passed");\n' > "$work/Program.cs"
  chown -R "$user:$user" "$work"
elif [[ $phase == smoke ]]; then
  [[ $(ls /sys/class/net) == lo ]] || { echo 'Offline proof must run with Docker --network none.' >&2; exit 2; }
  cd "$work"
  runuser -u "$user" -- env HOME="/home/$user" DOTNET_CLI_HOME="/home/$user" \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
    cbodotnet restore --configfile NuGet.Config
  runuser -u "$user" -- env HOME="/home/$user" DOTNET_CLI_HOME="/home/$user" \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 cbodotnet build --no-restore
  output=$(runuser -u "$user" -- cbodotnet "bin/Debug/net$series/Smoke.dll")
  [[ $output == published-https-apt-offline-passed ]]
  verification=$(dpkg -V "$package" cbodotnet-host)
  if [[ -n $verification ]]; then
    printf '%s\n' "$verification" >&2
    echo 'Published package integrity verification failed.' >&2; exit 1
  fi
  apt-get remove -y "$package" cbodotnet-host
  [[ ! -e /opt/cbodotnet/$series && ! -e /usr/bin/cbodotnet && ! -e /usr/bin/cbodotnet-$series ]]
  python3 - "$report" "$variant" "$sdk" "$revision" "$arch" "$fingerprint" "$repository" <<'PY'
import json,sys
from pathlib import Path
report,variant,sdk,revision,arch,key,repository=sys.argv[1:]
value=dict(schemaVersion=1,status='passed',scope='published-https-apt-installation',variant=variant,
           sdkVersion=sdk,packageRevision=int(revision),architecture=arch,signingFingerprint=key,
           repository=repository,networkForBuild='none',checks=['https-signed-apt-install','pinned-key',
           'command-aliases','cli-branding','version-stdout-compatible','non-root-offline-build-run','package-integrity','removal'])
Path(report).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
print(json.dumps(value,sort_keys=True))
PY
else
  echo 'Unknown proof phase.' >&2; exit 2
fi
