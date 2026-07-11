#!/bin/sh
export PATH=/bin:/usr/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

dump_aer_state() {
  phase=$1
  printf '\n=== AER state: %s ===\n' "$phase"
  lspci -nn || true
  for d in /sys/bus/pci/devices/*; do
    [ -e "$d/vendor" ] || continue
    vendor=$(cat "$d/vendor")
    device=$(cat "$d/device")
    case "$vendor:$device" in
      0x8086:0x10d3|0x1af4:0x1110)
        bdf=${d##*/}
        printf '\n--- target %s vendor=%s device=%s ---\n' "$bdf" "$vendor" "$device"
        printf '%s\n' '-- config 0xe0-0x13f --'
        dd if="$d/config" bs=16 skip=14 count=6 2>/dev/null | hexdump -C || true
        for f in aer_dev_correctable aer_dev_fatal aer_dev_nonfatal; do
          [ -e "$d/$f" ] && {
            printf '%s:\n' "$f"
            cat "$d/$f"
          }
        done
        ;;
    esac
  done
  printf '\n--- dmesg AER/PCI tail ---\n'
  dmesg | grep -Ei 'AER|PCIe Bus Error|Corrected|Uncorrected|Non-Fatal|Fatal|e1000e' | tail -120 || true
}

printf '=== AER guest probe start ===\n'
printf 'cmdline: '
cat /proc/cmdline

if insmod /lib/modules/e1000e.ko; then
  sleep 2
  printf '\n=== e1000e loaded ===\n'
else
  printf '\n=== e1000e load failed ===\n'
fi

dump_aer_state before-injection
printf '\n=== AER injection window open ===\n'
sleep 90
printf '\n=== AER injection window closed ===\n'
dump_aer_state after-injection
printf '\n=== AER guest probe done ===\n'
sync
poweroff -f
