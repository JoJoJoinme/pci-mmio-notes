#!/usr/bin/env bash
set -euo pipefail

work=${WORKDIR:-/tmp/ovmf-initrd-mmio}
initrd="$work/initrd.cpio"
kernel=${KERNEL:-$(ls -1 /boot/vmlinuz-* | sort -V | tail -1)}
machine=${MACHINE:-pc-i440fx-jammy}
ram=${RAM:-3584M}
bar_sizes=${BAR_SIZES:-256M 512M 1G}
cases=${CASES:-ovmf_default ovmf_fwcfg_zero ovmf_host_zero ovmf_both_zero}
qemu_timeout=${QEMU_TIMEOUT:-75}
cpu=${CPU:-host}
host_bridge=${HOST_BRIDGE:-auto}
linux_kernel_args=${LINUX_KERNEL_ARGS:-}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

find_ovmf_file() {
  local env_name=$1
  shift
  local candidate

  if [ -n "${!env_name:-}" ]; then
    printf '%s\n' "${!env_name}"
    return
  fi

  for candidate in "$@"; do
    if [ -e "$candidate" ]; then
      printf '%s\n' "$candidate"
      return
    fi
  done

  echo "unable to find $env_name; set $env_name explicitly" >&2
  exit 1
}

build_initrd() {
  rm -rf "$work/root"
  mkdir -p "$work/root/bin" "$work/root/proc" "$work/root/sys" "$work/root/dev"
  cp /usr/bin/busybox "$work/root/bin/busybox"
  for app in sh mount cat printf poweroff sleep; do
    ln -s busybox "$work/root/bin/$app"
  done

  cat > "$work/root/init" <<'INIT'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys

printf '=== cmdline ===\n'
cat /proc/cmdline

printf '\n=== root bus resources ===\n'
for b in /sys/class/pci_bus/*; do
  [ -e "$b/device/resource" ] || continue
  printf '%s\n' "${b##*/}"
  n=0
  while read -r start end flags rest; do
    if [ "$start" != "0x0000000000000000" ] || [ "$end" != "0x0000000000000000" ]; then
      printf '  bus-resource%-2s %s %s %s\n' "$n" "$start" "$end" "$flags"
    fi
    n=$((n + 1))
  done < "$b/device/resource"
done

printf '\n=== ivshmem target ===\n'
found=0
for d in /sys/bus/pci/devices/*; do
  [ -e "$d/vendor" ] || continue
  vendor=$(cat "$d/vendor")
  device=$(cat "$d/device")
  class=$(cat "$d/class")
  if [ "$vendor" = "0x1af4" ] && [ "$device" = "0x1110" ]; then
    found=1
    printf '%s vendor=%s device=%s class=%s\n' "${d##*/}" "$vendor" "$device" "$class"
    n=0
    while read -r start end flags rest; do
      if [ "$start" != "0x0000000000000000" ] || [ "$end" != "0x0000000000000000" ]; then
        printf '  BAR/resource%-2s %s %s %s\n' "$n" "$start" "$end" "$flags"
      fi
      n=$((n + 1))
    done < "$d/resource"
  fi
done
[ "$found" -eq 1 ] || echo "ivshmem target 1af4:1110 not found"

printf '\n=== /proc/iomem PCI-ish lines ===\n'
while read -r line; do
  case "$line" in
    *PCI*|*0000:00*|*Window*) printf '%s\n' "$line" ;;
  esac
done < /proc/iomem

printf '\n=== done ===\n'
poweroff -f
INIT
  chmod +x "$work/root/init"
  (cd "$work/root" && find . -print0 | cpio --null -ov --format=newc > "$initrd") \
    > "$work/initrd.build.log" 2>&1
}

run_case() {
  local name=$1
  local bar_size=$2
  shift 2
  local vars="$work/OVMF_VARS_${name}_${bar_size}.fd"
  cp "$ovmf_vars_template" "$vars"

  echo "===== CASE: ${name}_bar-${bar_size} ====="
  timeout "$qemu_timeout" qemu-system-x86_64 \
    -machine "$machine",accel=kvm:tcg \
    -cpu "$cpu" \
    -m "$ram" \
    -nodefaults \
    -display none \
    -serial mon:stdio \
    -no-reboot \
    -drive if=pflash,format=raw,readonly=on,file="$ovmf_code" \
    -drive if=pflash,format=raw,file="$vars" \
    -kernel "$kernel" \
    -initrd "$initrd" \
    -append "console=ttyS0 rdinit=/init nokaslr quiet $linux_kernel_args" \
    -object memory-backend-memfd,id=shm,size="$bar_size",share=on \
    -device ivshmem-plain,memdev=shm \
    "$@" || true
  echo
}

run_named_case() {
  local case_name=$1
  local bar_size=$2

  case "$case_name" in
    ovmf_default)
      run_case "$case_name" "$bar_size"
      ;;
    ovmf_fwcfg_zero)
      run_case "$case_name" "$bar_size" \
        -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0
      ;;
    ovmf_host_zero)
      run_case "$case_name" "$bar_size" \
        -global "$host_bridge".pci-hole64-size=0
      ;;
    ovmf_both_zero)
      run_case "$case_name" "$bar_size" \
        -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0 \
        -global "$host_bridge".pci-hole64-size=0
      ;;
    ovmf_both_2g)
      run_case "$case_name" "$bar_size" \
        -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=2048 \
        -global "$host_bridge".pci-hole64-size=2G
      ;;
    ovmf_both_4g)
      run_case "$case_name" "$bar_size" \
        -fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=4096 \
        -global "$host_bridge".pci-hole64-size=4G
      ;;
    *)
      echo "unknown case: $case_name" >&2
      exit 1
      ;;
  esac
}

need qemu-system-x86_64
need cpio

if [ "$host_bridge" = auto ]; then
  case "$machine" in
    *q35*) host_bridge=q35-pcihost ;;
    *) host_bridge=i440FX-pcihost ;;
  esac
fi

mkdir -p "$work"
ovmf_code=$(find_ovmf_file OVMF_CODE \
  /usr/share/OVMF/OVMF_CODE.fd \
  /usr/share/OVMF/OVMF_CODE_4M.fd \
  /usr/share/edk2/ovmf/OVMF_CODE.fd \
  /usr/share/edk2/ovmf/OVMF_CODE.4m.fd)
ovmf_vars_template=$(find_ovmf_file OVMF_VARS \
  /usr/share/OVMF/OVMF_VARS.fd \
  /usr/share/OVMF/OVMF_VARS_4M.fd \
  /usr/share/edk2/ovmf/OVMF_VARS.fd \
  /usr/share/edk2/ovmf/OVMF_VARS.4m.fd)

build_initrd

echo "OVMF_CODE=$ovmf_code"
echo "OVMF_VARS=$ovmf_vars_template"
echo "KERNEL=$kernel"
echo "MACHINE=$machine"
echo "HOST_BRIDGE=$host_bridge"
echo "BAR_SIZES=$bar_sizes"
echo "CASES=$cases"
echo "LINUX_KERNEL_ARGS=${linux_kernel_args:-<none>}"
echo

for one_bar_size in $bar_sizes; do
  for one_case in $cases; do
    run_named_case "$one_case" "$one_bar_size"
  done
done
