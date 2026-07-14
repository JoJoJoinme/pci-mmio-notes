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

printf '%s\n' 'SRIOV-SURFACE-PROBE-BEGIN'
nvme_core_load=fail
nvme_load=fail
dca_load=fail
i2c_algo_bit_load=fail
igb_load=fail
igbvf_load=fail
insmod /lib/modules/nvme-core.ko >/dev/null 2>&1 && nvme_core_load=ok
insmod /lib/modules/nvme.ko >/dev/null 2>&1 && nvme_load=ok
insmod /lib/modules/dca.ko >/dev/null 2>&1 && dca_load=ok
insmod /lib/modules/i2c-algo-bit.ko >/dev/null 2>&1 && i2c_algo_bit_load=ok
insmod /lib/modules/igb.ko >/dev/null 2>&1 && igb_load=ok
insmod /lib/modules/igbvf.ko >/dev/null 2>&1 && igbvf_load=ok
printf 'SRIOV-MODULES nvme-core=%s nvme=%s dca=%s i2c-algo-bit=%s igb=%s igbvf=%s\n' \
  "$nvme_core_load" "$nvme_load" "$dca_load" "$i2c_algo_bit_load" \
  "$igb_load" "$igbvf_load"
busybox sleep 2
found=0
for d in /sys/bus/pci/devices/*; do
  [ -r "$d/vendor" ] || continue
  vendor=$(cat "$d/vendor")
  device=$(cat "$d/device")
  case "$vendor:$device" in
    0x1b36:0x0010|0x8086:0x10c9|0x8086:0x10ca) ;;
    *) continue ;;
  esac
  found=$((found + 1))
  bdf=${d##*/}
  total=absent
  num=absent
  [ -r "$d/sriov_totalvfs" ] && total=$(cat "$d/sriov_totalvfs")
  [ -r "$d/sriov_numvfs" ] && num=$(cat "$d/sriov_numvfs")
  physfn=absent
  [ -L "$d/physfn" ] && physfn=$(basename "$(readlink -f "$d/physfn")")
  driver=absent
  [ -L "$d/driver" ] && driver=$(basename "$(readlink -f "$d/driver")")
  config="$d/config"
  h100=$(read_dword "$config" 256)
  h120=$(read_dword "$config" 288)
  ctrl=$(read_dword "$config" 296)
  counts=$(read_dword "$config" 300)
  printf 'SRIOV-SURFACE bdf=%s vendor=%s device=%s totalvfs=%s numvfs=%s physfn=%s h100=0x%s h120=0x%s ctrl=0x%s counts=0x%s\n' \
    "$bdf" "$vendor" "$device" "$total" "$num" "$physfn" \
    "${h100:-unavailable}" "${h120:-unavailable}" \
    "${ctrl:-unavailable}" "${counts:-unavailable}"
  lspci -Dnn -s "$bdf" -vv -xxxx || true

  enable=not-available
  disable=not-available
  num_before=$num
  num_after=$num
  num_final=$num
  vf_count=0
  if [ -r "$d/sriov_numvfs" ]; then
    num_before=$(cat "$d/sriov_numvfs")
    if [ "$num_before" = 0 ]; then
      if echo 1 > "$d/sriov_numvfs" 2>/dev/null; then
        enable=ok
      else
        enable=failed
      fi
    else
      enable=already-enabled
    fi
    busybox sleep 1
    num_after=$(cat "$d/sriov_numvfs")
    for candidate in /sys/bus/pci/devices/*; do
      [ -L "$candidate/physfn" ] || continue
      [ "$(readlink -f "$candidate/physfn")" = "$(readlink -f "$d")" ] || continue
      vf_count=$((vf_count + 1))
    done
    if [ "$num_after" != 0 ]; then
      if echo 0 > "$d/sriov_numvfs" 2>/dev/null; then
        disable=ok
      else
        disable=failed
      fi
    else
      disable=already-disabled
    fi
    busybox sleep 1
    num_final=$(cat "$d/sriov_numvfs")
  fi
  printf 'SRIOV-ACTION bdf=%s driver=%s num-before=%s enable=%s num-after=%s vf-count=%s disable=%s num-final=%s\n' \
    "$bdf" "$driver" "$num_before" "$enable" "$num_after" \
    "$vf_count" "$disable" "$num_final"
done

printf 'SRIOV-SURFACE-COUNT=%s\n' "$found"
busybox dmesg | busybox grep -i -e sriov -e 'virtual function' -e nvme || true
printf '%s\n' 'SRIOV-SURFACE-PROBE-COMPLETE'
sync
poweroff -f
