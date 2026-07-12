#!/usr/bin/env bash
set -euo pipefail

workspace=/mnt/e/Code/PCI
root="$workspace/_artifacts/mmio-tests/nonbar-local/final/root"
iso_root="$workspace/_artifacts/esxi-l3-probe-iso"
profile=${PROFILE:-probe}
case "$profile" in
  probe)
    output="$workspace/_artifacts/esxi-l3-pci-probe.iso"
    ;;
  aer)
    output="$workspace/_artifacts/esxi-l3-aer-probe.iso"
    ;;
  vmotion)
    output="$workspace/_artifacts/esxi-l3-vmotion-probe.iso"
    ;;
  largebar)
    output="$workspace/_artifacts/esxi-l3-largebar-probe.iso"
    ;;
  edu)
    output="$workspace/_artifacts/esxi-l3-edu-probe.iso"
    ;;
  reboot)
    output="$workspace/_artifacts/esxi-l3-reboot-probe.iso"
    ;;
  intx)
    output="$workspace/_artifacts/esxi-l3-intx-probe.iso"
    ;;
  *)
    echo "unsupported PROFILE: $profile" >&2
    exit 2
    ;;
esac
kernel_release=5.15.0-185-generic

original_init=
original_grub=
module_build_dir=
cleanup() {
  if [[ -n "$original_init" ]]; then
    cp "$original_init" "$root/init"
    rm -f "$original_init"
  fi
  if [[ -n "$original_grub" ]]; then
    cp "$original_grub" "$iso_root/boot/grub/grub.cfg"
    rm -f "$original_grub"
  fi
  if [[ -n "$module_build_dir" ]]; then
    rm -rf "$module_build_dir"
  fi
  if [[ "$profile" == edu ]]; then
    rm -f "$root/lib/modules/edu_probe.ko"
  fi
}

if [[ "$profile" != probe ]]; then
  original_init=$(mktemp)
  cp "$root/init" "$original_init"
  trap cleanup EXIT
  if [[ "$profile" == aer ]]; then
    cp "$workspace/_artifacts/esxi-l3-aer-init.sh" "$root/init"
  elif [[ "$profile" == reboot ]]; then
    cp "$workspace/github-export/vmware-esxi8-lab/esxi-l3-reboot-init.sh" "$root/init"
  elif [[ "$profile" == edu ]]; then
    cp "$workspace/github-export/vmware-esxi8-lab/esxi-l3-edu-init.sh" "$root/init"
  else
    cp "$workspace/github-export/vmware-esxi8-lab/esxi-l3-vmotion-init.sh" "$root/init"
  fi
  chmod +x "$root/init"
fi

if [[ "$profile" == intx ]]; then
  original_grub=$(mktemp)
  cp "$iso_root/boot/grub/grub.cfg" "$original_grub"
  sed -i 's/ rdinit=\/init quiet/ rdinit=\/init quiet pci=nomsi/' \
    "$iso_root/boot/grub/grub.cfg"
fi

mkdir -p "$root/lib/modules"
cp "/lib/modules/$kernel_release/kernel/drivers/net/ethernet/intel/e1000e/e1000e.ko" \
  "$root/lib/modules/e1000e.ko"

if [[ "$profile" == edu ]]; then
  headers="/lib/modules/$kernel_release/build"
  if [[ ! -d "$headers" ]]; then
    echo "missing kernel headers: $headers" >&2
    echo "install linux-headers-$kernel_release" >&2
    exit 2
  fi
  module_build_dir=$(mktemp -d)
  cp "$workspace/github-export/vmware-esxi8-lab/edu-probe/Makefile" \
    "$workspace/github-export/vmware-esxi8-lab/edu-probe/edu_probe.c" \
    "$module_build_dir/"
  make -s -C "$headers" M="$module_build_dir" modules
  cp "$module_build_dir/edu_probe.ko" "$root/lib/modules/edu_probe.ko"
fi

for app in dd insmod ip ping poweroff reboot sync; do
  ln -sf busybox "$root/bin/$app"
done

(
  cd "$root"
  find . -print0 | cpio --null -o --format=newc > "$iso_root/boot/initrd.cpio"
)

grub-mkrescue -o "$output" "$iso_root"
sha256sum "$output"
file "$output"
