#!/bin/sh
# Seed exact stock-signed metadata before resolving any build/runtime package.
set -eu
[ "$#" -eq 4 ] || { echo 'usage: seed-musl-apk-cache.sh CACHE SNAPSHOTS MAIN_SHA256 COMMUNITY_SHA256' >&2; exit 2; }
cache=$1
snapshots=$2
main_sha=$3
community_sha=$4
case "$cache" in /*) ;; *) exit 2 ;; esac
case "$snapshots" in /*) ;; *) exit 2 ;; esac
[ "$cache" != / ] && [ "$snapshots" != / ] && [ -d "$cache" ] && [ -d "$snapshots" ]
[ ! -L "$cache" ] && [ ! -L "$snapshots" ]
for expected in "$main_sha" "$community_sha"; do
    printf '%s\n' "$expected" | grep -E '^[a-f0-9]{64}$' >/dev/null
done
main=$snapshots/main-APKINDEX.tar.gz
community=$snapshots/community-APKINDEX.tar.gz
for path in "$main" "$community"; do [ -f "$path" ] && [ ! -L "$path" ]; done
[ "$(sha256sum "$main" | cut -d ' ' -f 1)" = "$main_sha" ]
[ "$(sha256sum "$community" | cut -d ' ' -f 1)" = "$community_sha" ]
# Both raw signature envelopes are verified against the pinned image's stock keys.
apk verify "$main" "$community"
main_seen=0
community_seen=0
for index in "$cache"/APKINDEX.*.tar.gz; do
    [ -f "$index" ] && [ ! -L "$index" ]
    # Only identify apk's URL-derived cache names from the live seed. Its bytes
    # are replaced before dependency resolution and never select package inputs.
    if tar -xOzf "$index" APKINDEX | grep '^P:musl$' >/dev/null; then
        [ "$main_seen" -eq 0 ]
        cp "$main" "$index"
        main_seen=1
    elif tar -xOzf "$index" APKINDEX | grep '^P:dotnet10-sdk$' >/dev/null; then
        [ "$community_seen" -eq 0 ]
        cp "$community" "$index"
        community_seen=1
    else
        echo 'Unexpected Alpine repository cache namespace' >&2
        exit 2
    fi
done
[ "$main_seen" -eq 1 ] && [ "$community_seen" -eq 1 ]
sha256sum "$cache"/APKINDEX.*.tar.gz > "$cache/index-sha256.txt"
grep "$main_sha" "$cache/index-sha256.txt" >/dev/null
grep "$community_sha" "$cache/index-sha256.txt" >/dev/null
# The actual resolver opens the frozen cache with all networking forbidden.
apk --cache-dir "$cache" --no-network search --exact musl >/dev/null
