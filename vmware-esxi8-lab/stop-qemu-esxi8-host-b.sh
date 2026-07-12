#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export QEMU_ESXI_INSTANCE=b
export QEMU_ESXI_VM_DIR=/root/vm/esxi8-b
export QEMU_ESXI_TAP=tap-esxi8-b

exec "$script_dir/stop-qemu-esxi8-mf.sh"
