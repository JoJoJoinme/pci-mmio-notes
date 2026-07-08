#!/usr/bin/env bash
set -euo pipefail

work=/tmp/mmio-initrd
initrd=/tmp/mmio-initrd.cpio
kernel=${KERNEL:-$(ls -1 /boot/vmlinuz-* | sort -V | tail -1)}
machine=${MACHINE:-pc-i440fx-jammy}
ram=${RAM:-3584M}
bar_size=${BAR_SIZE:-1G}
pci_args=${PCI_ARGS-pci=realloc}

rm -rf "$work"
mkdir -p "$work/bin" "$work/proc" "$work/sys" "$work/dev"
cp /usr/bin/busybox "$work/bin/busybox"
for app in sh mount cat printf poweroff; do
  ln -s busybox "$work/bin/$app"
done

cat > "$work/init" <<'INIT'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys

printf '=== cmdline ===\n'
cat /proc/cmdline

printf '\n=== PCI resources ===\n'
for d in /sys/bus/pci/devices/*; do
  [ -e "$d/vendor" ] || continue
  printf '\n%s vendor=%s device=%s class=%s\n' \
    "${d##*/}" "$(cat "$d/vendor")" "$(cat "$d/device")" "$(cat "$d/class")"
  n=0
  while read -r start end flags rest; do
    if [ "$start" != "0x0000000000000000" ] || [ "$end" != "0x0000000000000000" ]; then
      printf '  BAR/resource%-2s %s %s %s\n' "$n" "$start" "$end" "$flags"
    fi
    n=$((n + 1))
  done < "$d/resource"
done

printf '\n=== /proc/iomem PCI-ish lines ===\n'
while read -r line; do
  case "$line" in
    *PCI*|*0000:00*|*Window*) printf '%s\n' "$line" ;;
  esac
done < /proc/iomem

printf '\n=== done ===\n'
poweroff -f
INIT
chmod +x "$work/init"

(cd "$work" && find . -print0 | cpio --null -ov --format=newc > "$initrd") >/tmp/mmio-initrd.build.log 2>&1

run_case() {
  local name=$1
  shift
  echo "===== CASE: $name ====="
  timeout 90 qemu-system-x86_64 \
    -machine "$machine",accel=kvm:tcg \
    -cpu host \
    -m "$ram" \
    -nodefaults \
    -display none \
    -serial mon:stdio \
    -no-reboot \
    -kernel "$kernel" \
    -initrd "$initrd" \
    -append "console=ttyS0 rdinit=/init $pci_args nokaslr quiet" \
    -object memory-backend-memfd,id=shm,size="$bar_size",share=on \
    -device ivshmem-plain,memdev=shm \
    "$@" || true
  echo
}

run_case fwcfg_only \
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0

run_case fwcfg_and_hole64_zero \
  -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0 \
  -global i440FX-pcihost.pci-hole64-size=0
