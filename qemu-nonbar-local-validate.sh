#!/usr/bin/env bash
set -euo pipefail

work=${WORKDIR:-/tmp/qemu-nonbar-validate}
initrd="$work/initrd.cpio"
kernel=${KERNEL:-$(ls -1 /boot/vmlinuz-* | sort -V | tail -1)}
ovmf_code=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE.fd}
ovmf_vars_template=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS.fd}
timeout_s=${QEMU_TIMEOUT:-45}
cases=${CASES:-q35_rootport_default q35_rootport_custom_link q35_rootport_disable_acs q35_intel_iommu}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

copy_with_deps() {
  local bin=$1
  local dest="$work/root$bin"
  mkdir -p "$(dirname "$dest")"
  cp "$bin" "$dest"
  ldd "$bin" 2>/dev/null | awk '
    /=> \// { print $3 }
    /ld-linux/ { print $1 }
    /^\// { print $1 }
  ' | while read -r lib; do
    [ -e "$lib" ] || continue
    mkdir -p "$work/root$(dirname "$lib")"
    cp -n "$lib" "$work/root$lib"
  done
}

build_initrd() {
  rm -rf "$work/root"
  mkdir -p "$work/root/bin" "$work/root/proc" "$work/root/sys" "$work/root/dev" "$work/root/usr/share/misc"
  cp /usr/bin/busybox "$work/root/bin/busybox"
  for app in sh mount cat printf poweroff sleep dmesg find readlink sort grep head sed awk tr cut basename dirname; do
    ln -s busybox "$work/root/bin/$app"
  done
  copy_with_deps /usr/bin/lspci
  copy_with_deps /usr/bin/setpci
  if [ -e /usr/share/misc/pci.ids ]; then
    cp /usr/share/misc/pci.ids "$work/root/usr/share/misc/pci.ids"
  fi

  cat > "$work/root/init" <<'INIT'
#!/bin/sh
export PATH=/bin:/usr/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys

printf '=== cmdline ===\n'
cat /proc/cmdline

printf '\n=== dmesg iommu/acpi/pci lines ===\n'
dmesg | grep -Ei 'DMAR|IOMMU|AMD-Vi|ACPI:.*DMAR|PCI host bridge|root bus resource|ACPI: PCI Root Bridge|pci 0000:' | head -220 || true

printf '\n=== lspci tree ===\n'
lspci -nn -tv || true

printf '\n=== lspci selected verbose ===\n'
lspci -nnvv | grep -Ei '^[0-9a-f:.]+ |Express|LnkCap|LnkSta|ACSCap|ACSCtl|MSI|MSI-X|IOMMU|AER|Root Port|Ethernet|Virtio|Non-Volatile|Memory controller|VGA' || true

printf '\n=== sysfs pci devices ===\n'
for d in /sys/bus/pci/devices/*; do
  [ -e "$d/vendor" ] || continue
  bdf=${d##*/}
  printf '%s vendor=%s device=%s class=%s\n' "$bdf" "$(cat "$d/vendor")" "$(cat "$d/device")" "$(cat "$d/class")"
  for f in current_link_speed current_link_width max_link_speed max_link_width numa_node reset_method; do
    [ -e "$d/$f" ] && printf '  %s=%s\n' "$f" "$(cat "$d/$f" 2>/dev/null)"
  done
  if [ -e "$d/resource" ]; then
    n=0
    while read -r start end flags rest; do
      if [ "$start" != "0x0000000000000000" ] || [ "$end" != "0x0000000000000000" ]; then
        printf '  resource%-2s %s %s %s\n' "$n" "$start" "$end" "$flags"
      fi
      n=$((n + 1))
    done < "$d/resource"
  fi
  if [ -e "$d/iommu_group" ]; then
    printf '  iommu_group=%s\n' "$(readlink -f "$d/iommu_group" 2>/dev/null)"
  fi
done

printf '\n=== guest iommu groups ===\n'
for g in /sys/kernel/iommu_groups/*; do
  [ -d "$g" ] || continue
  printf '%s\n' "$g"
  find "$g/devices" -maxdepth 1 -type l 2>/dev/null | sort | sed 's/^/  /'
done

printf '\n=== done ===\n'
poweroff -f
INIT
  chmod +x "$work/root/init"
  (cd "$work/root" && find . -print0 | cpio --null -ov --format=newc > "$initrd") \
    > "$work/initrd.build.log" 2>&1
}

run_case() {
  local name=$1
  shift
  local vars="$work/OVMF_VARS_${name}.fd"
  local machine_args="q35,accel=kvm:tcg"
  local kernel_extra=""
  if [ "$name" = "q35_intel_iommu" ]; then
    machine_args="q35,accel=kvm:tcg,kernel_irqchip=split"
    kernel_extra=" intel_iommu=on"
  fi
  cp "$ovmf_vars_template" "$vars"
  echo "===== CASE: $name ====="
  timeout "$timeout_s" qemu-system-x86_64 \
    -machine "$machine_args" \
    -cpu host \
    -m 1024M \
    -nodefaults \
    -display none \
    -serial mon:stdio \
    -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file="$ovmf_code" \
    -drive if=pflash,format=raw,file="$vars" \
    -kernel "$kernel" \
    -initrd "$initrd" \
    -append "console=ttyS0 rdinit=/init quiet${kernel_extra}" \
    "$@" || true
  echo
}

need qemu-system-x86_64
need cpio
need ldd
need lspci
need setpci

mkdir -p "$work"
build_initrd

echo "KERNEL=$kernel"
echo "OVMF_CODE=$ovmf_code"
echo "OVMF_VARS=$ovmf_vars_template"
echo

for case_name in $cases; do
  case "$case_name" in
    q35_rootport_default)
      run_case "$case_name" \
        -netdev user,id=n0 \
        -device pcie-root-port,id=rp1,chassis=1,slot=1 \
        -device e1000e,netdev=n0,bus=rp1,addr=00.0
      ;;
    q35_rootport_custom_link)
      run_case "$case_name" \
        -netdev user,id=n0 \
        -device pcie-root-port,id=rp1,chassis=1,slot=1,x-speed=8,x-width=4 \
        -device e1000e,netdev=n0,bus=rp1,addr=00.0
      ;;
    q35_rootport_disable_acs)
      run_case "$case_name" \
        -netdev user,id=n0 \
        -device pcie-root-port,id=rp1,chassis=1,slot=1,disable-acs=on \
        -device e1000e,netdev=n0,bus=rp1,addr=00.0
      ;;
    q35_intel_iommu)
      run_case "$case_name" \
        -device intel-iommu,intremap=on,caching-mode=on \
        -netdev user,id=n0 \
        -device pcie-root-port,id=rp1,chassis=1,slot=1 \
        -device e1000e,netdev=n0,bus=rp1,addr=00.0
      ;;
    *)
      echo "unknown case: $case_name" >&2
      exit 1
      ;;
  esac
done
