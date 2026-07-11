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
  *)
    echo "unsupported PROFILE: $profile" >&2
    exit 2
    ;;
esac
kernel_release=5.15.0-185-generic

original_init=
if [[ "$profile" == aer ]]; then
  original_init=$(mktemp)
  cp "$root/init" "$original_init"
  trap 'cp "$original_init" "$root/init"; rm -f "$original_init"' EXIT
  cp "$workspace/_artifacts/esxi-l3-aer-init.sh" "$root/init"
  chmod +x "$root/init"
fi

mkdir -p "$root/lib/modules"
cp "/lib/modules/$kernel_release/kernel/drivers/net/ethernet/intel/e1000e/e1000e.ko" \
  "$root/lib/modules/e1000e.ko"

for app in insmod ip ping; do
  ln -sf busybox "$root/bin/$app"
done

(
  cd "$root"
  find . -print0 | cpio --null -o --format=newc > "$iso_root/boot/initrd.cpio"
)

grub-mkrescue -o "$output" "$iso_root"
sha256sum "$output"
file "$output"
