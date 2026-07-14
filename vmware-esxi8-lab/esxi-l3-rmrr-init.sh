#!/bin/sh
export PATH=/bin:/usr/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

printf '%s\n' 'RMRR-PROBE-BEGIN'
printf '%s\n' '=== cmdline ==='
cat /proc/cmdline

printf '%s\n' '=== dmesg DMAR/RMRR ==='
dmesg | grep -Ei 'DMAR|IOMMU|RMRR|reserved region' || true

printf '%s\n' '=== iomem ==='
cat /proc/iomem

printf '%s\n' '=== PCI target ==='
for d in /sys/bus/pci/devices/*; do
  [ -r "$d/vendor" ] || continue
  vendor=$(cat "$d/vendor")
  device=$(cat "$d/device")
  class=$(cat "$d/class")
  bdf=${d##*/}
  printf 'pci_device=%s id=%s:%s class=%s\n' "$bdf" "$vendor" "$device" "$class"
  case "$class" in
    0x0200*) ;;
    *) continue ;;
  esac
  printf 'target_bdf=%s\n' "$bdf"
  printf 'target_id=%s:%s\n' "$vendor" "$device"
  [ -e "$d/iommu_group" ] && printf 'target_iommu_group=%s\n' "$(readlink -f "$d/iommu_group")"
done

if [ -r /sys/firmware/acpi/tables/DMAR ]; then
  printf '%s\n' 'DMAR-RAW-BEGIN'
  busybox xxd -p -c 256 /sys/firmware/acpi/tables/DMAR
  printf '%s\n' 'DMAR-RAW-END'
else
  printf '%s\n' 'DMAR-MISSING'
fi

printf '%s\n' 'RMRR-PROBE-COMPLETE'
sync
poweroff -f
