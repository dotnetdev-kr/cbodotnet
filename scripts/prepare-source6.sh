#!/usr/bin/env bash
set -euo pipefail
[[ $# == 3 || ( $# == 5 && $4 == --arch ) ]] || { echo 'Usage: prepare-source6.sh SOURCE INPUTS REPORTS [--arch arm64|x64]' >&2; exit 2; }
arch=${5:-arm64}
case "$arch" in arm64) native=aarch64 ;; x64) native=x86_64 ;; *) echo 'Unsupported architecture.' >&2; exit 2 ;; esac
[[ $(uname -s) == Linux && $(uname -m) == "$native" ]] || { echo 'A matching native Linux preparation session is required.' >&2; exit 1; }
source_dir=$(realpath -e "$1")
inputs_dir=$(realpath -e "$2")
reports_dir=$(realpath -e "$3")
[[ $inputs_dir != "$source_dir" && $inputs_dir != "$source_dir"/* && $reports_dir != "$source_dir" && $reports_dir != "$source_dir"/* ]] || { echo 'Inputs and reports must be outside the generated source.' >&2; exit 1; }
for output in bootstrap-inputs.json bootstrap-originals.json; do
  [[ ! -e $reports_dir/$output && ! -L $reports_dir/$output ]] || { echo "Refusing a previous preparation report: $output" >&2; exit 1; }
done
helper=$(dirname "$(realpath -e "${BASH_SOURCE[0]}")")/bootstrap6-inputs.py
if [[ -f $inputs_dir/bootstrap6-prepared.json ]]; then
  python3 "$helper" verify --source-dir "$source_dir" --inputs-dir "$inputs_dir" --report "$reports_dir/bootstrap-inputs.json" --arch "$arch"
  exit 0
fi
shopt -s nullglob
transformed=("$source_dir"/packages/archive/Private.SourceBuilt.Artifacts.Bootstrap*.tar.gz)
(( ${#transformed[@]} == 0 )) || { echo 'An incomplete transformed bootstrap exists; preserve it and inspect the failed preparation before retrying.' >&2; exit 1; }
cd "$source_dir"
# .NET 6 bootstraps only when explicitly requested. Preserve the original first; native x64 already matches the original PSB host.
./prep.sh
python3 "$helper" save-originals --source-dir "$source_dir" --inputs-dir "$inputs_dir" --report "$reports_dir/bootstrap-originals.json" --arch "$arch"
if [[ $arch == arm64 ]]; then ./prep.sh --bootstrap; fi
python3 "$helper" finalize --source-dir "$source_dir" --inputs-dir "$inputs_dir" --report "$reports_dir/bootstrap-inputs.json" --arch "$arch"
