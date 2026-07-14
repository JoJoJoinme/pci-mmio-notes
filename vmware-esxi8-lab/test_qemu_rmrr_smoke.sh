#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace=${WORKSPACE:-/mnt/e/Code/PCI}
qemu=${QEMU_BINARY:-/root/src/qemu-6.2.0/build-capability-lab/qemu-system-x86_64}
output_dir=${OUTPUT_DIR:-$workspace/_artifacts/vmware-directpath-runs/20260713-qemu-rmrr-smoke-v1}
kernel="$workspace/_artifacts/esxi-l3-probe-iso/boot/vmlinuz"
initrd="$workspace/_artifacts/esxi-l3-probe-iso/boot/initrd.cpio"
rmrr_base=${RMRR_BASE:-0xf0000}
rmrr_limit=${RMRR_LIMIT:-0xfffff}
rmrr_sid=${RMRR_SID:-0x0100}
ram=${QEMU_RMRR_RAM:-512M}
machine_options="q35,accel=kvm,kernel-irqchip=split"
if [[ -n "${QEMU_RMRR_MACHINE_EXTRA:-}" ]]; then
  machine_options+=",${QEMU_RMRR_MACHINE_EXTRA}"
fi

mkdir -p "$output_dir"
PROFILE=rmrr "$script_dir/build-esxi-l3-probe-iso.sh" \
  >"$output_dir/build-iso.log" 2>&1

set +e
timeout 180 "$qemu" \
  -L /usr/share/qemu \
  -machine "$machine_options" \
  -cpu host \
  -smp 2 \
  -m "$ram" \
  -nodefaults \
  -kernel "$kernel" \
  -initrd "$initrd" \
  -append 'console=ttyS0,115200n8 rdinit=/init nokaslr quiet' \
  -device "intel-iommu,intremap=on,caching-mode=on,device-iotlb=on,x-rmrr-base=$rmrr_base,x-rmrr-limit=$rmrr_limit,x-rmrr-sid=$rmrr_sid" \
  -device pcie-root-port,id=rmrr_rp,bus=pcie.0,chassis=8,slot=8,addr=0x08.0 \
  -netdev user,id=rmrr_net,restrict=on \
  -device e1000e,id=rmrr_target,netdev=rmrr_net,bus=rmrr_rp,addr=0x00.0 \
  -display none \
  -monitor none \
  -serial stdio \
  -no-reboot \
  >"$output_dir/guest-serial.log" 2>"$output_dir/qemu.stderr.log"
qemu_rc=$?
set -e
printf '%s\n' "$qemu_rc" >"$output_dir/qemu-exit-code.txt"

python3 "$script_dir/parse_dmar_rmrr.py" \
  "$output_dir/guest-serial.log" \
  --expect-base "$rmrr_base" \
  --expect-limit "$rmrr_limit" \
  --expect-sid "$rmrr_sid" \
  --output "$output_dir/dmar-result.json"

grep -q RMRR-PROBE-COMPLETE "$output_dir/guest-serial.log"
sha256sum "$qemu" "$kernel" "$initrd" >"$output_dir/sha256.txt"
printf 'QEMU-RMRR-SMOKE-PASS output=%s\n' "$output_dir"
