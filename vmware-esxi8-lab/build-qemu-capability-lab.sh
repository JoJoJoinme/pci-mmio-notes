#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_dir="${QEMU_CAP_SOURCE_DIR:-/root/src/qemu-6.2.0}"
build_dir="${QEMU_CAP_BUILD_DIR:-$source_dir/build-capability-lab}"
root_cap_patch="$script_dir/qemu-patches/0001-virtio-pci-root-complex-capabilities.patch"
pme_patch="$script_dir/qemu-patches/0002-pcie-pme-injection-lab.patch"
ivshmem_patch="$script_dir/qemu-patches/0003-ivshmem-page-aligned-bar0-lab.patch"
rmrr_patch="$script_dir/qemu-patches/0004-intel-iommu-rmrr-lab.patch"
aer_visibility_patch="$script_dir/qemu-patches/0005-vmware-aer-visibility-lab.patch"
oprom_marker_patch="$script_dir/qemu-patches/0006-e1000e-option-rom-marker-trace.patch"
oprom_counter_patch="$script_dir/qemu-patches/0007-e1000e-option-rom-marker-counter.patch"
d3hot_reset_patch="$script_dir/qemu-patches/0008-virtio-pci-d3hot-reset-lab.patch"
pme_d3hot_patch="$script_dir/qemu-patches/0009-virtio-pci-pme-d3hot-advertisement-lab.patch"
class_code_patch="$script_dir/qemu-patches/0014-virtio-net-pci-class-code-lab.patch"

if [[ ! -f "$source_dir/VERSION" ]]; then
  echo "QEMU source tree not found at $source_dir" >&2
  exit 2
fi

if ! grep -q pcie_root_cap_init "$source_dir/hw/virtio/virtio-pci.c"; then
  patch -d "$source_dir" -p1 < "$root_cap_patch"
fi
if ! grep -q x-pme-inject "$source_dir/hw/net/e1000e.c"; then
  patch -d "$source_dir" -p1 < "$pme_patch"
fi
if ! grep -q x-page-aligned-bar0 "$source_dir/hw/misc/ivshmem.c"; then
  patch -d "$source_dir" -p1 < "$ivshmem_patch"
fi
if ! grep -q x-rmrr-base "$source_dir/hw/i386/intel_iommu.c"; then
  patch -d "$source_dir" -p1 < "$rmrr_patch"
fi
if ! grep -q x-vmware-deny-pcie-aer "$source_dir/include/hw/i386/pc.h"; then
  patch -d "$source_dir" -p1 < "$aer_visibility_patch"
fi
if ! grep -q e1000e_option_rom_marker "$source_dir/hw/net/trace-events"; then
  patch -d "$source_dir" -p1 < "$oprom_marker_patch"
fi
if ! grep -q option-rom-marker-count "$source_dir/hw/net/e1000e.c"; then
  patch -d "$source_dir" -p1 < "$oprom_counter_patch"
fi
if ! grep -q x-pcie-d3hot-reset "$source_dir/hw/virtio/virtio-pci.c"; then
  patch -d "$source_dir" -p1 < "$d3hot_reset_patch"
fi
if ! grep -q x-pcie-pme-d3hot "$source_dir/hw/virtio/virtio-pci.c"; then
  patch -d "$source_dir" -p1 < "$pme_d3hot_patch"
fi
if ! grep -q x-pci-class-code "$source_dir/hw/virtio/virtio-net-pci.c"; then
  patch -d "$source_dir" -p1 < "$class_code_patch"
fi

if [[ ! -f "$build_dir/build.ninja" ]]; then
  mkdir -p "$build_dir"
  (
    cd "$build_dir"
    "$source_dir/configure" \
      --target-list=x86_64-softmmu \
      --enable-kvm \
      --enable-slirp \
      --enable-trace-backends=simple \
      --disable-werror \
      --disable-docs
  )
fi

ninja -C "$build_dir" qemu-system-x86_64 trace/trace-events-all
"$build_dir/qemu-system-x86_64" --version
sha256sum \
  "$build_dir/qemu-system-x86_64" \
  "$build_dir/trace/trace-events-all" \
  "$root_cap_patch" \
  "$pme_patch" \
  "$ivshmem_patch" \
  "$rmrr_patch" \
  "$aer_visibility_patch" \
  "$oprom_marker_patch" \
  "$oprom_counter_patch" \
  "$d3hot_reset_patch" \
  "$pme_d3hot_patch" \
  "$class_code_patch"
