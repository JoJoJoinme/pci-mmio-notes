#!/usr/bin/env bash
set -euo pipefail

workspace=${WORKSPACE:-/mnt/e/Code/PCI}
iso=${ISO:-$workspace/_artifacts/esxi-l3-pci-probe.iso}
out=${OUT:-$workspace/_artifacts/qemu-aer-surface}
cases=${CASES:-"ovmf_default ovmf_extcap_off seabios_default"}

mkdir -p "$out"

run_case() {
  local name=$1
  local firmware=$2
  local extcap=$3
  local vars="$out/$name-vars.fd"
  local log="$out/$name-serial.log"
  local -a firmware_args=()

  rm -f "$vars" "$log"
  if [[ "$firmware" == ovmf ]]; then
    cp /usr/share/OVMF/OVMF_VARS.fd "$vars"
    firmware_args=(
      -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd
      -drive if=pflash,format=raw,file="$vars"
    )
  fi

  timeout 120 qemu-system-x86_64 \
    -name "$name" \
    -machine q35,accel=kvm \
    -cpu host \
    -m 1024 \
    -smp 1 \
    -nic none \
    "${firmware_args[@]}" \
    -cdrom "$iso" \
    -boot d \
    -device "pcie-root-port,id=rp,chassis=1,slot=1,x-pcie-extcap-init=$extcap" \
    -device "e1000e,id=ep,bus=rp,x-pcie-extcap-init=$extcap" \
    -display none \
    -serial "file:$log" \
    -no-reboot

  grep -n -Ei '_OSC|AER|Root Port|Express|8086:10d3' "$log" >"$out/$name-aer.txt" || true
}

for name in $cases; do
  case "$name" in
    ovmf_default) run_case "$name" ovmf on ;;
    ovmf_extcap_off) run_case "$name" ovmf off ;;
    seabios_default) run_case "$name" seabios on ;;
    *) echo "unsupported case: $name" >&2; exit 2 ;;
  esac
done

for name in $cases; do
  echo "===== $name ====="
  cat "$out/$name-aer.txt"
done
