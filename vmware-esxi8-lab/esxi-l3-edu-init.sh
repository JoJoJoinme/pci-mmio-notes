#!/bin/sh
export PATH=/bin:/usr/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

printf '=== EDU guest probe start ===\n'
printf 'cmdline: '
cat /proc/cmdline

mkdir -p /sys/firmware/efi/efivars
mount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null || true
marker_file=/sys/firmware/efi/efivars/EduProbePhase-2adbe080-82e4-4dc7-9b0f-55218d74b083

if [ -e "$marker_file" ] && grep -q EDU-SECOND "$marker_file" 2>/dev/null; then
  phase=second
else
  phase=first
fi
printf 'EDU-PHASE=%s\n' "$phase"

printf '\n=== PCI inventory before driver ===\n'
lspci -nn -tv || true
lspci -nn || true

if ! insmod /lib/modules/edu_probe.ko; then
  printf 'EDU-TEST-FAIL phase=%s reason=module-load\n' "$phase"
  dmesg | tail -120
  sleep 2
  poweroff -f
fi

sleep 1
printf '\n=== EDU driver evidence ===\n'
dmesg | grep 'EDU-' || true

target_path=
for device_path in /sys/bus/pci/devices/*; do
  [ -e "$device_path/vendor" ] || continue
  if [ "$(cat "$device_path/vendor")" = 0x1234 ] && \
     [ "$(cat "$device_path/device")" = 0x11e8 ]; then
    target_path=$device_path
    break
  fi
done

if [ -z "$target_path" ]; then
  printf 'EDU-TEST-FAIL phase=%s reason=device-not-found\n' "$phase"
  poweroff -f
fi

bdf=${target_path##*/}
printf '\n=== EDU PCI detail bdf=%s ===\n' "$bdf"
lspci -s "$bdf" -nn -vv || true
cat "$target_path/resource" || true

msi_count=0
for irq_file in "$target_path"/msi_irqs/*; do
  [ -e "$irq_file" ] || continue
  msi_count=$((msi_count + 1))
done
printf 'EDU-MSI-VECTORS phase=%s count=%s\n' "$phase" "$msi_count"
grep -E 'edu_probe|PCI-MSI' /proc/interrupts || true

if ! dmesg | grep -q 'EDU-PROBE-PASS'; then
  printf 'EDU-TEST-FAIL phase=%s reason=self-test\n' "$phase"
  poweroff -f
fi
if [ "$msi_count" -lt 1 ]; then
  printf 'EDU-TEST-FAIL phase=%s reason=no-msi-vector\n' "$phase"
  poweroff -f
fi

reset_state=$(dmesg | sed -n 's/.*EDU-RESET-SENTINEL .*state=\([^ ]*\).*/\1/p' | tail -1)
printf 'EDU-PHASE-PASS phase=%s reset_state=%s\n' "$phase" "${reset_state:-missing}"

if [ "$phase" = first ]; then
  printf '\007\000\000\000EDU-SECOND\n' > "$marker_file"
  sync
  printf 'EDU-REBOOTING\n'
  reboot -f
fi

rm -f "$marker_file" 2>/dev/null || true
sync
printf 'EDU-TEST-COMPLETE reset_state=%s\n' "${reset_state:-missing}"
# Leave a deterministic observation window for the L0 DMA teardown probe.
sleep 15
poweroff -f
