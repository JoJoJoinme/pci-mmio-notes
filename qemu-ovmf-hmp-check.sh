#!/usr/bin/env bash
set -euo pipefail

run_ovmf() {
  local name=$1
  shift
  local vars="/tmp/OVMF_VARS_${name}.fd"
  local port=$((4400 + RANDOM % 1000))
  cp /usr/share/OVMF/OVMF_VARS.fd "$vars"
  echo "===== OVMF CASE: $name ====="
  timeout 35 qemu-system-x86_64 \
    -machine pc-i440fx-jammy,accel=kvm:tcg \
    -cpu host \
    -m 3584M \
    -nodefaults \
    -display none \
    -serial none \
    -monitor tcp:127.0.0.1:"$port",server,nowait \
    -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file="$vars" \
    -object memory-backend-memfd,id=shm,size=1G,share=on \
    -device ivshmem-plain,memdev=shm \
    "$@" >/tmp/qemu-ovmf-"$name".log 2>&1 &
  local qemu_pid=$!
  sleep 8
  printf 'info pci\nquit\n' | nc -w 3 127.0.0.1 "$port" | sed -n '/Bus  0/,/QEMU/p'
  wait "$qemu_pid" || true
  echo
}

run_ovmf ovmf_default

run_ovmf fwcfg_only \
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0

run_ovmf fwcfg_and_hole64_zero \
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0 \
  -global i440FX-pcihost.pci-hole64-size=0
