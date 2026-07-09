#!/usr/bin/env bash
set -euo pipefail

echo "=== host vfio/iommu evidence ==="
uname -a

echo
echo "/dev/vfio:"
ls -la /dev/vfio 2>/dev/null || true

echo
echo "/sys/kernel/iommu_groups count:"
find /sys/kernel/iommu_groups -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l

echo
echo "/sys/bus/pci/devices:"
for d in /sys/bus/pci/devices/*; do
  [ -e "$d/vendor" ] || continue
  bdf=${d##*/}
  printf "%s vendor=%s device=%s class=%s\n" \
    "$bdf" \
    "$(cat "$d/vendor")" \
    "$(cat "$d/device")" \
    "$(cat "$d/class")"
done
