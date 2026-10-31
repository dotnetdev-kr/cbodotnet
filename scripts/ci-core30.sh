#!/usr/bin/env bash
set -euo pipefail
exec python3 "$(dirname "$(realpath -e "${BASH_SOURCE[0]}")")/ci-legacy-direct.py" --family core30 "$@"
