#!/bin/sh
export PATH=/bin:/usr/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

printf '=== P2P guest probe start ===\n'
printf 'cmdline: '
cat /proc/cmdline

printf '\n=== PCI inventory before driver ===\n'
lspci -nn -tv || true
lspci -nn || true

printf '\n=== PCI resources before driver ===\n'
for device_path in /sys/bus/pci/devices/*; do
  [ -e "$device_path/vendor" ] || continue
  vendor=$(cat "$device_path/vendor")
  device=$(cat "$device_path/device")
  if { [ "$vendor" = 0x1234 ] && [ "$device" = 0x11e8 ]; } || \
     { [ "$vendor" = 0x1af4 ] && [ "$device" = 0x1110 ]; }; then
    printf '%s vendor=%s device=%s\n' "${device_path##*/}" "$vendor" "$device"
    cat "$device_path/resource" || true
  fi
done
sync

if ! insmod /lib/modules/edu_probe.ko; then
  printf 'P2P-RESULT=fail reason=module-load\n'
else
  sleep 1
  printf '\n=== EDU P2P driver evidence ===\n'
  dmesg | grep 'EDU-' || true
  if dmesg | grep -q 'EDU-P2P-PASS'; then
    printf 'P2P-RESULT=pass\n'
  elif dmesg | grep -q 'EDU-P2P-FAIL'; then
    printf 'P2P-RESULT=fail reason=peer-dma-mismatch\n'
  else
    printf 'P2P-RESULT=fail reason=no-peer-result\n'
  fi
fi

printf 'P2P-TEST-COMPLETE\n'
sync
sleep 3
poweroff -f
