#!/usr/bin/env bash
set -euo pipefail

vm_dir="${QEMU_ESXI_VM_DIR:-/root/vm/esxi8-b}"
base_system="${QEMU_ESXI_BASE_SYSTEM:-/root/vm/esxi8-mf/esxi8-system.pre-aer-20260711.qcow2}"
ovmf_template="${QEMU_ESXI_OVMF_TEMPLATE:-/usr/share/OVMF/OVMF_VARS.fd}"

mkdir -p "$vm_dir"

if [[ ! -f "$vm_dir/esxi8-system.qcow2" ]]; then
  qemu-img create -f qcow2 -F qcow2 -b "$base_system" "$vm_dir/esxi8-system.qcow2"
fi

if [[ ! -f "$vm_dir/esxi8-datastore.qcow2" ]]; then
  qemu-img create -f qcow2 "$vm_dir/esxi8-datastore.qcow2" 64G
fi

if [[ ! -f "$vm_dir/OVMF_VARS.fd" ]]; then
  cp "$ovmf_template" "$vm_dir/OVMF_VARS.fd"
fi

truncate -s 8192M "$vm_dir/guest-ram.bin"
qemu-img info --backing-chain "$vm_dir/esxi8-system.qcow2"
