#!/usr/bin/env bash
set -euo pipefail
for argument in "$@"; do [[ $argument != --version && $argument != --version=* ]] || { echo 'The adapter pins .NET 9.' >&2; exit 2; }; done
exec python3 "$(dirname "$(realpath -e "${BASH_SOURCE[0]}")")/ci-vmr89.py" "${1:---help}" --version 9 "${@:2}"
