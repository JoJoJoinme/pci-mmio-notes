#!/bin/sh
export PATH=/bin:/usr/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

read_u8() (
  file=$1
  offset=$2
  dd if="$file" bs=1 skip="$offset" count=1 2>/dev/null |
    od -An -tu1 | tr -d ' \n'
)

read_le16() (
  file=$1
  offset=$2
  set -- $(dd if="$file" bs=1 skip="$offset" count=2 2>/dev/null | od -An -tx1)
  if [ "$#" -ne 2 ]; then
    printf unavailable
  else
    printf '%s%s' "$2" "$1"
  fi
)

read_le32() (
  file=$1
  offset=$2
  set -- $(dd if="$file" bs=1 skip="$offset" count=4 2>/dev/null | od -An -tx1)
  if [ "$#" -ne 4 ]; then
    printf unavailable
  else
    printf '%s%s%s%s' "$4" "$3" "$2" "$1"
  fi
)

find_pcie_cap() (
  file=$1
  pointer=$(read_u8 "$file" 52)
  hops=0
  while [ -n "$pointer" ] && [ "$pointer" -ge 64 ] && [ "$pointer" -lt 256 ] && [ "$hops" -lt 48 ]; do
    pointer=$((pointer & 252))
    cap_id=$(read_u8 "$file" "$pointer")
    if [ "$cap_id" = 16 ]; then
      printf '%d' "$pointer"
      exit 0
    fi
    pointer=$(read_u8 "$file" $((pointer + 1)))
    hops=$((hops + 1))
  done
  printf unavailable
)

dump_target_state() {
  phase=$1
  directory=$2
  bdf=${directory##*/}
  config="$directory/config"
  vendor=$(cat "$directory/vendor")
  device=$(cat "$directory/device")
  class=$(cat "$directory/class")
  pcie_cap=$(find_pcie_cap "$config")
  if [ "$pcie_cap" = unavailable ]; then
    devctl=unavailable
    devsta=unavailable
  else
    devctl=$(read_le16 "$config" $((pcie_cap + 8)))
    devsta=$(read_le16 "$config" $((pcie_cap + 10)))
  fi

  # The instrumented e1000e, modern virtio-net and EDU endpoints place AER at
  # 0x100.  ESXi may hide the capability header while retaining the backing
  # register body, so this test intentionally records both discovery and raw
  # bytes instead of following only the extended-capability chain.
  aer_offset=256
  aer_header=$(read_le32 "$config" "$aer_offset")
  ues=$(read_le32 "$config" $((aer_offset + 4)))
  uem=$(read_le32 "$config" $((aer_offset + 8)))
  severity=$(read_le32 "$config" $((aer_offset + 12)))
  ces=$(read_le32 "$config" $((aer_offset + 16)))
  cem=$(read_le32 "$config" $((aer_offset + 20)))
  aer_capctl=$(read_le32 "$config" $((aer_offset + 24)))
  root_cmd=$(read_le32 "$config" $((aer_offset + 44)))
  root_status=$(read_le32 "$config" $((aer_offset + 48)))
  root_source=$(read_le32 "$config" $((aer_offset + 52)))
  command=$(read_le16 "$config" 4)
  status=$(read_le16 "$config" 6)

  aer_discoverable=no
  case "$aer_header" in
    ????0001) aer_discoverable=yes ;;
  esac
  printf 'AER-STATE phase=%s bdf=%s vendor=%s device=%s class=%s command=0x%s status=0x%s pcie_cap=%s devctl=0x%s devsta=0x%s aer_offset=0x100 aer_header=0x%s aer_discoverable=%s ues=0x%s uem=0x%s severity=0x%s ces=0x%s cem=0x%s aer_capctl=0x%s root_cmd=0x%s root_status=0x%s root_source=0x%s\n' \
    "$phase" "$bdf" "$vendor" "$device" "$class" "$command" "$status" \
    "$pcie_cap" "$devctl" "$devsta" "$aer_header" "$aer_discoverable" \
    "$ues" "$uem" "$severity" "$ces" "$cem" "$aer_capctl" \
    "$root_cmd" "$root_status" "$root_source"
}

dump_aer_state() {
  phase=$1
  printf '\n=== AER state: %s ===\n' "$phase"
  lspci -nn || true
  for d in /sys/bus/pci/devices/*; do
    [ -e "$d/vendor" ] || continue
    vendor=$(cat "$d/vendor")
    device=$(cat "$d/device")
    case "$vendor:$device" in
      0x8086:0x10d3|0x1af4:0x1041|0x1af4:0x1110)
        bdf=${d##*/}
        printf '\n--- target %s vendor=%s device=%s ---\n' "$bdf" "$vendor" "$device"
        dump_target_state "$phase" "$d"
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
window_seconds=45
for option in $(cat /proc/cmdline); do
  case "$option" in
    aer_window_seconds=*) window_seconds=${option#*=} ;;
  esac
done
case "$window_seconds" in
  ''|*[!0-9]*) window_seconds=45 ;;
esac
printf 'AER-WINDOW seconds=%s\n' "$window_seconds"
sleep "$window_seconds"
printf '\n=== AER injection window closed ===\n'
dump_aer_state after-injection
printf '\n=== AER guest probe done ===\n'
sync
poweroff -f
