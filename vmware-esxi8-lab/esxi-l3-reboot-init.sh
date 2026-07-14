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
stage_file=/sys/firmware/efi/efivars/PciOpromStage-7f0b5e31-4381-4c45-9a7e-52119f628431
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

if [ -e "$stage_file" ]; then
  set -- $(/bin/busybox od -An -tx4 -N12 "$stage_file" 2>/dev/null)
  stage_attrs=${1:-missing}
  stage_magic=${2:-missing}
  stage_value=${3:-missing}
  stage_size=$(/bin/busybox wc -c < "$stage_file")
  printf 'R01-OPROM-STAGE phase=%s present=1 attrs=%s magic=%s value=%s size=%s\n' \
    "$phase" "$stage_attrs" "$stage_magic" "$stage_value" "$stage_size"
else
  printf 'R01-OPROM-STAGE phase=%s present=0 attrs=none magic=none value=none size=0\n' \
    "$phase"
fi

/bin/busybox mkdir -p /tmp
for pci_path in /sys/bus/pci/devices/*; do
  [ -r "$pci_path/vendor" ] || continue
  [ -r "$pci_path/device" ] || continue
  [ "$(cat "$pci_path/vendor")" = 0x8086 ] || continue
  [ "$(cat "$pci_path/device")" = 0x10d3 ] || continue
  bdf=${pci_path##*/}
  rom_file=$pci_path/rom
  rom_copy=/tmp/rom-${bdf}.bin
  : > "$rom_copy"
  if [ -e "$rom_file" ]; then
    printf 1 > "$rom_file" 2>/dev/null || true
    /bin/busybox dd if="$rom_file" of="$rom_copy" bs=4096 count=64 \
      2>/dev/null || true
    printf 0 > "$rom_file" 2>/dev/null || true
  fi
  rom_size=$(/bin/busybox wc -c < "$rom_copy")
  if [ "$rom_size" -gt 0 ]; then
    rom_sha=$(/bin/busybox sha256sum "$rom_copy" | /bin/busybox cut -d ' ' -f 1)
    rom_head=$(/bin/busybox od -An -tx1 -N4 "$rom_copy" | \
      /bin/busybox tr -d ' \n')
  else
    rom_sha=none
    rom_head=none
  fi
  printf 'R01-ROM phase=%s bdf=%s size=%s sha256=%s head=%s\n' \
    "$phase" "$bdf" "$rom_size" "$rom_sha" "$rom_head"
done

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
