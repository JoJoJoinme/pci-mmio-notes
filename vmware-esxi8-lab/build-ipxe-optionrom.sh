#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_dir="${IPXE_SOURCE_DIR:-/root/src/ipxe-optionrom-lab}"
output="${IPXE_ROM_OUTPUT:-/root/vm/esxi8-mf/optionrom/808610d3.efirom}"
expected_source="${IPXE_EXPECTED_SOURCE:-58ee55b3c13a3f53423091419f88bcb02fb5a035}"

actual_source=$(git -C "$source_dir" rev-parse HEAD)
if [[ "$actual_source" != "$expected_source" ]]; then
  echo "unexpected iPXE source: $actual_source (expected $expected_source)" >&2
  exit 2
fi

build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
git -C "$source_dir" archive "$expected_source" | tar -x -C "$build_dir"
mkdir -p "$build_dir/src/config/local" "$(dirname "$output")"
cp "$script_dir/optionrom/ipxe-serial-console.h" \
  "$build_dir/src/config/local/console.h"
git -C "$build_dir" apply --recount \
  "$script_dir/optionrom/0001-emit-esxi-directpath-marker.patch"

make -C "$build_dir/src" -j"${IPXE_BUILD_JOBS:-4}" \
  bin-x86_64-efi/808610d3.efirom
cp "$build_dir/src/bin-x86_64-efi/808610d3.efirom" "$output"

printf 'source=%s\n' "$actual_source"
sha256sum "$script_dir/optionrom/0001-emit-esxi-directpath-marker.patch" "$output"
file "$output"
