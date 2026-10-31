#!/usr/bin/env bash
# Run the pinned generated-source .NET 6 profile on native Linux ARM64 CI.
set -euo pipefail
exec python3 "$(dirname "$(realpath -e "${BASH_SOURCE[0]}")")/ci-net67.py" 6 "$@"
