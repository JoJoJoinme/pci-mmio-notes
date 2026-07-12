#!/bin/sh
export PATH=/bin:/usr/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

printf '=== R01 guest reboot probe start ===\n'
printf 'cmdline: '
cat /proc/cmdline

mkdir -p /sys/firmware/efi/efivars
mount -t efivarfs efivarfs /sys/firmware/efi/efivars 2>/dev/null || true
marker_file=/sys/firmware/efi/efivars/R01Phase-12345678-1234-1234-1234-123456789abc
if [ ! -d /sys/firmware/efi/efivars ]; then
  printf 'R01-ERROR efivarfs-not-available\n'
  poweroff -f
fi

if [ -e "$marker_file" ] && grep -q R01-SECOND "$marker_file" 2>/dev/null; then
  phase=second
else
  phase=first
fi
printf 'R01-PHASE=%s marker=efivarfs\n' "$phase"

insmod /lib/modules/e1000e.ko 2>/dev/null || true
sleep 2

traffic_interface=
for netpath in /sys/class/net/*; do
  candidate=${netpath##*/}
  [ "$candidate" = lo ] && continue
  traffic_interface=$candidate
  ip link set "$traffic_interface" up 2>/dev/null || true
  ip addr add 10.0.2.15/24 dev "$traffic_interface" 2>/dev/null || true
  break
done

for attempt in 1 2 3; do
  if [ -n "$traffic_interface" ]; then
    ping -c 1 -W 1 10.0.2.2 >/dev/null 2>&1 || true
  fi
done

if [ -n "$traffic_interface" ]; then
  printf 'R01-TRAFFIC phase=%s interface=%s rx=%s tx=%s\n' \
    "$phase" "$traffic_interface" \
    "$(cat "/sys/class/net/$traffic_interface/statistics/rx_packets")" \
    "$(cat "/sys/class/net/$traffic_interface/statistics/tx_packets")"
  grep -E "$traffic_interface|e1000e" /proc/interrupts || true
fi

if [ "$phase" = first ]; then
  printf '\007\000\000\000R01-SECOND\n' > "$marker_file"
  sync
  printf 'R01-REBOOTING\n'
  reboot -f
fi

rm -f "$marker_file" 2>/dev/null || true
printf 'R01-REBOOT-COMPLETE\n'
sync
sleep 10
poweroff -f
