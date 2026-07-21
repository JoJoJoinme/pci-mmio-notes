#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
model_dir="$repo_dir/pci-resource-model"
output=${1:-}

run_tests() {
  cd "$model_dir"
  export PYTHONPATH="$model_dir"
  python3 -m unittest -v tests.test_c20_capability_closure
  python3 -m unittest discover -v -s tests -t .
}

if [[ -z "$output" ]]; then
  run_tests
  exit 0
fi

mkdir -p "$(dirname "$output")"
set +e
run_tests 2>&1 | tee "$output"
status=${PIPESTATUS[0]}
set -e
exit "$status"
