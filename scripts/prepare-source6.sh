#!/usr/bin/env bash
set -euo pipefail
[[ $# == 3 ]] || { echo 'Usage: prepare-source6.sh SOURCE INPUTS REPORTS' >&2; exit 2; }
source_dir=$(realpath -e "$1")
inputs_dir=$(realpath -e "$2")
reports_dir=$(realpath -e "$3")
[[ $(uname -s) == Linux && $(uname -m) == aarch64 ]] || { echo 'A native Linux ARM64 preparation session is required.' >&2; exit 1; }
[[ $inputs_dir != "$source_dir" && $inputs_dir != "$source_dir"/* && $reports_dir != "$source_dir" && $reports_dir != "$source_dir"/* ]] || { echo 'Inputs and reports must be outside the generated source.' >&2; exit 1; }
for output in bootstrap-inputs.json bootstrap-originals.json; do
  [[ ! -e $reports_dir/$output && ! -L $reports_dir/$output ]] || { echo "Refusing a previous preparation report: $output" >&2; exit 1; }
done
helper=$(dirname "$(realpath -e "${BASH_SOURCE[0]}")")/bootstrap6-inputs.py
if [[ -f $inputs_dir/bootstrap6-prepared.json ]]; then
  python3 "$helper" verify --source-dir "$source_dir" --inputs-dir "$inputs_dir" --report "$reports_dir/bootstrap-inputs.json"
  exit 0
fi
shopt -s nullglob
transformed=("$source_dir"/packages/archive/Private.SourceBuilt.Artifacts.Bootstrap*.tar.gz)
(( ${#transformed[@]} == 0 )) || { echo 'An incomplete transformed bootstrap exists; preserve it and inspect the failed preparation before retrying.' >&2; exit 1; }
cd "$source_dir"
# .NET 6 bootstraps only when explicitly requested. Preserve the original first.
./prep.sh
python3 "$helper" save-originals --source-dir "$source_dir" --inputs-dir "$inputs_dir" --report "$reports_dir/bootstrap-originals.json"
./prep.sh --bootstrap
python3 "$helper" finalize --source-dir "$source_dir" --inputs-dir "$inputs_dir" --report "$reports_dir/bootstrap-inputs.json"
