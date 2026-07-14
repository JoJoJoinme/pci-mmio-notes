#!/bin/sh
export PATH=/bin:/usr/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

read_dword() {
  file=$1
  offset=$2
  value=$(dd if="$file" bs=1 skip="$offset" count=4 2>/dev/null | busybox od -An -tx4)
  printf '%s' "$value" | tr -d ' \n'
}

dump_surface() {
  phase=$1
  for d in /sys/bus/pci/devices/*; do
    [ -r "$d/vendor" ] || continue
    bdf=${d##*/}
    vendor=$(cat "$d/vendor")
    device=$(cat "$d/device")
    class=$(cat "$d/class")
    kind=
    if [ "$vendor:$device" = 0x8086:0x10d3 ]; then
      kind=endpoint
    else
      case "$class" in
        0x0604*) kind=bridge ;;
        *) continue ;;
      esac
    fi
    config="$d/config"
    header=$(read_dword "$config" 256)
    ues=$(read_dword "$config" 260)
    ces=$(read_dword "$config" 272)
    root_status=$(read_dword "$config" 304)
    printf 'AER-SURFACE phase=%s kind=%s bdf=%s vendor=%s device=%s header=0x%s ues=0x%s ces=0x%s root_status=0x%s\n' \
      "$phase" "$kind" "$bdf" "$vendor" "$device" \
      "${header:-unavailable}" "${ues:-unavailable}" \
      "${ces:-unavailable}" "${root_status:-unavailable}"
  done
}

printf '%s\n' 'AER-SURFACE-PROBE-BEGIN'
printf '%s\n' '=== ACPI PCIe ownership ==='
dmesg | grep -Ei '_OSC|OS now controls|platform does not support' || true
printf '%s\n' '=== lspci AER visibility ==='
lspci -nn -vv | grep -Ei '^[0-9a-f:.]+ |Advanced Error Reporting|AER|Root Port|Ethernet' || true

dump_surface before
printf '%s\n' 'AER-SURFACE-INJECTION-WINDOW'
sleep 15
dump_surface after

printf '%s\n' '=== post-injection AER logs ==='
dmesg | grep -Ei 'AER|PCIe Bus Error|Corrected|Uncorrected|Non-Fatal|Fatal' || true
printf '%s\n' 'AER-SURFACE-PROBE-COMPLETE'
sync
poweroff -f
