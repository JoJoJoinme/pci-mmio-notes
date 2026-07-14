#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
runner=${RUNNER:-"$repo_dir/qemu-ovmf-real-linux-validate.sh"}
workdir=${WORKDIR:-/tmp/qemu-firmware-layout-matrix}
base_image=${BASE_IMAGE:-"$workdir/noble-server-cloudimg-amd64.img"}
qemu_timeout=${QEMU_TIMEOUT:-600}
results="$workdir/results.tsv"
overall=pass

mkdir -p "$workdir"
printf 'profile\tfirmware\tmachine\ttopology\taperture_case\tguest_done\ttarget_visible\tbar2_mapped\troot_count\texpected_bar2\texpected_roots\tverdict\n' > "$results"

run_profile() {
  local profile=$1
  local firmware=$2
  local machine=$3
  local topology=$4
  local aperture_case=$5
  local disable_modern=$6
  local expected_bar2=$7
  local expected_roots=$8
  local profile_dir="$workdir/$profile"
  local case_dir="$profile_dir/${aperture_case}_bar-2G"
  local serial="$case_dir/serial.log"
  local runner_log="$profile_dir/runner.log"
  local runner_status
  local guest_done=false
  local target_visible=false
  local bar2_mapped=false
  local root_count=0
  local verdict=fail

  mkdir -p "$profile_dir"
  set +e
  env \
    WORKDIR="$profile_dir" \
    BASE_IMAGE="$base_image" \
    FIRMWARE="$firmware" \
    MACHINE="$machine" \
    TOPOLOGY="$topology" \
    RAM=2G \
    BAR_SIZES=2G \
    CASES="$aperture_case" \
    QEMU_TIMEOUT="$qemu_timeout" \
    VIRTIO_DISABLE_MODERN="$disable_modern" \
    bash "$runner" > "$runner_log" 2>&1
  runner_status=$?
  set -e

  if [ -f "$serial" ]; then
    if grep -q '^=== done ===' "$serial"; then
      guest_done=true
    fi
    if awk '
      /^=== ivshmem target ===/ { target = 1; next }
      /^=== \/proc\/iomem PCI-ish lines ===/ { target = 0 }
      target && /vendor=0x1af4 device=0x1110/ { found = 1 }
      END { exit(found ? 0 : 1) }
    ' "$serial"; then
      target_visible=true
    fi
    if awk '
      /^=== ivshmem target ===/ { target = 1; next }
      /^=== \/proc\/iomem PCI-ish lines ===/ { target = 0 }
      target && /^  BAR\/resource2  0x[0-9a-f]+ 0x[0-9a-f]+/ { found = 1 }
      END { exit(found ? 0 : 1) }
    ' "$serial"; then
      bar2_mapped=true
    fi
    root_count=$(awk '
      /^=== ACPI PCI roots ===/ { roots = 1; next }
      /^=== lspci tree ===/ { roots = 0 }
      roots && /ACPI: PCI Root Bridge/ { count++ }
      END { print count + 0 }
    ' "$serial")
  fi

  if [ "$runner_status" -eq 0 ] && \
     [ "$guest_done" = true ] && \
     [ "$target_visible" = true ] && \
     [ "$bar2_mapped" = "$expected_bar2" ] && \
     [ "$root_count" -eq "$expected_roots" ]; then
    verdict=pass
  else
    overall=fail
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$profile" "$firmware" "$machine" "$topology" "$aperture_case" \
    "$guest_done" "$target_visible" "$bar2_mapped" "$root_count" \
    "$expected_bar2" "$expected_roots" "$verdict" >> "$results"
  printf '%-43s %s\n' "$profile" "$verdict"
}

run_profile seabios-i440fx-single seabios pc-i440fx-jammy single-root ovmf_host_2g 0 true 1
run_profile seabios-i440fx-pci-bridge seabios pc-i440fx-jammy pci-bridge ovmf_host_2g 0 true 1
run_profile ovmf-i440fx-single ovmf pc-i440fx-jammy single-root ovmf_both_2g 1 true 1
run_profile ovmf-i440fx-pci-bridge-exact2g ovmf pc-i440fx-jammy pci-bridge ovmf_both_2g 1 false 1
run_profile ovmf-i440fx-pci-bridge-4g-control ovmf pc-i440fx-jammy pci-bridge ovmf_both_4g 1 true 1
run_profile ovmf-i440fx-pxb ovmf pc-i440fx-jammy pxb-multi-root ovmf_both_2g 1 true 2
run_profile ovmf-q35-root-port ovmf pc-q35-jammy q35-root-port ovmf_both_2g 1 true 1

echo
cat "$results"

if [ "$overall" != pass ]; then
  exit 1
fi
