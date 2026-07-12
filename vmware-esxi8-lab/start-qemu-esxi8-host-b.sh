#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export QEMU_ESXI_INSTANCE=b
export QEMU_ESXI_NAME=esxi8-b
export QEMU_ESXI_VM_DIR=/root/vm/esxi8-b
export QEMU_ESXI_TAP=tap-esxi8-b
export QEMU_ESXI_MGMT_MAC=00:0c:29:ab:af:7d
export QEMU_ESXI_UUID=6a4e818a-51ce-7d7f-a21f-000c29abaf7d
export QEMU_ESXI_VNC_DISPLAY=6
export QEMU_ESXI_RAM_FILE=/root/vm/esxi8-b/guest-ram.bin
export QEMU_ESXI_SYSTEM_CONTROLLER="${QEMU_ESXI_SYSTEM_CONTROLLER:-ahci}"
export QEMU_ESXI_IVSHMEM_SIZE="${QEMU_ESXI_IVSHMEM_SIZE:-2G}"
export QEMU_ESXI_DHCP="${QEMU_ESXI_DHCP:-0}"

exec "$script_dir/start-qemu-esxi8-mf.sh"
