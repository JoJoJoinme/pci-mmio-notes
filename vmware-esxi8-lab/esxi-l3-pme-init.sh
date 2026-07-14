#!/bin/sh
export PATH=/bin:/usr/bin

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

cfg_read()
{
  cfg_reg=$(printf '%x.%s' "$2" "$3")
  setpci -s "$1" "$cfg_reg" 2>/dev/null
}

find_cap()
{
  cap_bdf=$1
  cap_wanted=$2
  cap_next=$(cfg_read "$cap_bdf" 52 b) || return 1
  cap_ptr=$((0x$cap_next & 0xfc))
  cap_hops=0

  while [ "$cap_ptr" -ne 0 ] && [ "$cap_hops" -lt 48 ]; do
    cap_id=$(cfg_read "$cap_bdf" "$cap_ptr" b) || return 1
    if [ "$((0x$cap_id))" -eq "$cap_wanted" ]; then
      printf '%x\n' "$cap_ptr"
      return 0
    fi
    cap_next=$(cfg_read "$cap_bdf" "$((cap_ptr + 1))" b) || return 1
    cap_ptr=$((0x$cap_next & 0xfc))
    cap_hops=$((cap_hops + 1))
  done
  return 1
}

printf '%s\n' 'PME-PROBE-BEGIN'
printf '%s\n' '=== cmdline ==='
cat /proc/cmdline
printf '%s\n' '=== ACPI PCIe ownership ==='
dmesg | grep -Ei '_OSC|OS now controls|PCIe.*PME|PME.*IRQ' || true

target_path=
for d in /sys/bus/pci/devices/*; do
  [ -r "$d/vendor" ] || continue
  [ "$(cat "$d/vendor")" = 0x8086 ] || continue
  [ "$(cat "$d/device")" = 0x10d3 ] || continue
  target_path=$d
  break
done

if [ -z "$target_path" ]; then
  printf '%s\n' 'PME-ERROR target-8086:10d3-not-found'
  printf '%s\n' 'PME-PROBE-COMPLETE'
  poweroff -f
fi

bdf=${target_path##*/}
printf 'PME-TARGET bdf=%s driver=%s\n' \
  "$bdf" "$(basename "$(readlink -f "$target_path/driver" 2>/dev/null)" 2>/dev/null || printf none)"
printf '%s\n' '=== target lspci ==='
lspci -s "$bdf" -nn -vv 2>/dev/null || true

pm_cap=$(find_cap "$bdf" 1 || true)
exp_cap=$(find_cap "$bdf" 16 || true)
pmcsr_reg=
if [ -n "$pm_cap" ]; then
  pmcsr_reg=$(printf '%x' "$((0x$pm_cap + 4))")
  pmcsr_auto=$(setpci -s "$bdf" "$pmcsr_reg.w" 2>/dev/null || printf unavailable)
else
  pmcsr_auto=unavailable
fi
printf 'PME-AUTO endpoint_pm_cap=%s endpoint_exp_cap=%s endpoint_pmcsr=%s\n' \
  "${pm_cap:-none}" "${exp_cap:-none}" "$pmcsr_auto"

printf '%s\n' '=== guest PCIe root ports before arm ==='
root_bdfs=
for d in /sys/bus/pci/devices/*; do
  [ -r "$d/class" ] || continue
  case "$(cat "$d/class")" in
    0x0604*) ;;
    *) continue ;;
  esac
  root=${d##*/}
  root_exp=$(find_cap "$root" 16 || true)
  [ -n "$root_exp" ] || continue
  root_ctl_reg=$(printf '%x' "$((0x$root_exp + 0x1c))")
  root_sta_reg=$(printf '%x' "$((0x$root_exp + 0x20))")
  root_ctl=$(setpci -s "$root" "$root_ctl_reg.w" 2>/dev/null || printf unavailable)
  root_sta=$(setpci -s "$root" "$root_sta_reg.l" 2>/dev/null || printf unavailable)
  root_irq=$(cat "$d/irq" 2>/dev/null || printf unavailable)
  printf 'PME-ROOT-BEFORE bdf=%s exp_cap=%s root_ctl=%s root_sta=%s irq=%s\n' \
    "$root" "$root_exp" "$root_ctl" "$root_sta" "$root_irq"
  root_bdfs="$root_bdfs $root"
done

printf '%s\n' '=== interrupts before arm ==='
cat /proc/interrupts

if [ -z "$pm_cap" ]; then
  printf '%s\n' 'PME-ERROR target-has-no-PM-capability'
  printf '%s\n' 'PME-PROBE-COMPLETE'
  poweroff -f
fi

# Clear a stale W1C PME Status bit, then force PME Enable for a deterministic
# message-injection test.  The automatic pre-arm state remains recorded above.
setpci -s "$bdf" "$pmcsr_reg.w=8000:8000"
setpci -s "$bdf" "$pmcsr_reg.w=0100:0100"
pmcsr_armed=$(setpci -s "$bdf" "$pmcsr_reg.w")
printf 'PME-ARMED bdf=%s endpoint_pmcsr=%s\n' "$bdf" "$pmcsr_armed"

previous=$pmcsr_armed
iteration=0
while [ "$iteration" -lt 30 ]; do
  sleep 2
  iteration=$((iteration + 1))
  current=$(setpci -s "$bdf" "$pmcsr_reg.w" 2>/dev/null || printf unavailable)
  if [ "$current" != "$previous" ] || [ "$iteration" -eq 30 ]; then
    printf 'PME-POLL iteration=%s endpoint_pmcsr=%s\n' "$iteration" "$current"
    previous=$current
  fi
done

printf '%s\n' '=== guest PCIe root ports after injection window ==='
for root in $root_bdfs; do
  root_exp=$(find_cap "$root" 16 || true)
  root_ctl_reg=$(printf '%x' "$((0x$root_exp + 0x1c))")
  root_sta_reg=$(printf '%x' "$((0x$root_exp + 0x20))")
  root_ctl=$(setpci -s "$root" "$root_ctl_reg.w" 2>/dev/null || printf unavailable)
  root_sta=$(setpci -s "$root" "$root_sta_reg.l" 2>/dev/null || printf unavailable)
  root_irq=$(cat "/sys/bus/pci/devices/$root/irq" 2>/dev/null || printf unavailable)
  printf 'PME-ROOT-AFTER bdf=%s root_ctl=%s root_sta=%s irq=%s\n' \
    "$root" "$root_ctl" "$root_sta" "$root_irq"
done

printf '%s\n' '=== interrupts after injection window ==='
cat /proc/interrupts
printf '%s\n' '=== dmesg after injection window ==='
dmesg | grep -Ei '_OSC|PCIe.*PME|PME.*IRQ|wake|power management' || true
printf 'PME-FINAL endpoint_pmcsr=%s\n' \
  "$(setpci -s "$bdf" "$pmcsr_reg.w" 2>/dev/null || printf unavailable)"
printf '%s\n' 'PME-PROBE-COMPLETE'
sync
poweroff -f
