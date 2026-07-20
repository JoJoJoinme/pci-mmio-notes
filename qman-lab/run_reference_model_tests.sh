#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
output=${1:-}
command=(
  python3 -m unittest discover
  -s "$repo_dir/pci-resource-model/tests"
  -t "$repo_dir/pci-resource-model"
  -v
)

if [[ -z "$output" ]]; then
  exec "${command[@]}"
fi

mkdir -p "$(dirname "$output")"
set +e
"${command[@]}" 2>&1 | tee "$output"
status=${PIPESTATUS[0]}
set -e
exit "$status"
