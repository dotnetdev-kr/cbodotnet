#!/usr/bin/env bash
set -euo pipefail
[[ $# == 3 ]] || { echo 'Usage: prepare-source7.sh SOURCE INPUTS REPORTS' >&2; exit 2; }
source_dir=$(realpath -e "$1")
inputs_dir=$(realpath -e "$2")
reports_dir=$(realpath -e "$3")
helper=$(dirname "$(realpath -e "${BASH_SOURCE[0]}")")/bootstrap7-inputs.py
if [[ -f $inputs_dir/bootstrap7-prepared.json ]]; then
  python3 "$helper" verify --source-dir "$source_dir" --inputs-dir "$inputs_dir" --report "$reports_dir/bootstrap-inputs.json"
  exit 0
fi
shopt -s nullglob
transformed=("$source_dir"/packages/archive/Private.SourceBuilt.Artifacts.Bootstrap*.tar.gz)
(( ${#transformed[@]} == 0 )) || { echo 'An incomplete transformed bootstrap exists; preserve it and inspect the failed preparation before retrying.' >&2; exit 1; }
cd "$source_dir"
# .NET 7 bootstraps only when explicitly requested. Preserve the original first.
./prep.sh
python3 "$helper" save-originals --source-dir "$source_dir" --inputs-dir "$inputs_dir" --report "$reports_dir/bootstrap-originals.json"
./prep.sh --bootstrap
python3 "$helper" finalize --source-dir "$source_dir" --inputs-dir "$inputs_dir" --report "$reports_dir/bootstrap-inputs.json"
