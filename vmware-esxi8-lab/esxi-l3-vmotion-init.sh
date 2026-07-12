#!/bin/sh
export PATH=/bin:/usr/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

printf '=== vMotion guest probe start ===\n'
printf 'cmdline: '
cat /proc/cmdline

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

printf '\n=== initial PCI inventory ===\n'
lspci -nn -tv || true
lspci -nn || true
printf '\n=== firmware root windows ===\n'
dmesg | grep -E 'root bus resource|BAR [0-9]|bridge window' || true
printf '\n=== iomem map ===\n'
cat /proc/iomem || true
for device_path in /sys/bus/pci/devices/*; do
  [ -e "$device_path/vendor" ] || continue
  vendor=$(cat "$device_path/vendor")
  device=$(cat "$device_path/device")
  case "$vendor:$device" in
    0x8086:0x10d3|0x1af4:0x1110|0x1b36:0x0005|0x1234:0x11e8)
      bdf=${device_path##*/}
      printf '\n--- DirectPath target %s vendor=%s device=%s ---\n' "$bdf" "$vendor" "$device"
      lspci -s "$bdf" -vv || true
      awk '$3 != "0x0000000000000000" { print }' "$device_path/resource" 2>/dev/null || true
      ;;
  esac
done

sequence=0
while :; do
  sequence=$((sequence + 1))
  if [ -n "$traffic_interface" ]; then
    ping -c 1 -W 1 10.0.2.2 >/dev/null 2>&1 || true
    printf 'DMA-TRAFFIC interface=%s rx=%s tx=%s\n' \
      "$traffic_interface" \
      "$(cat "/sys/class/net/$traffic_interface/statistics/rx_packets")" \
      "$(cat "/sys/class/net/$traffic_interface/statistics/tx_packets")"
    grep -E "$traffic_interface|e1000e" /proc/interrupts || true
  fi
  printf 'VMOTION-HEARTBEAT sequence=%s uptime=' "$sequence"
  cut -d ' ' -f 1 /proc/uptime
  sleep 5
done
