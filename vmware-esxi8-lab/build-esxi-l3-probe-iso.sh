#!/usr/bin/env bash
set -euo pipefail

workspace=/mnt/e/Code/PCI
root="$workspace/_artifacts/mmio-tests/nonbar-local/final/root"
iso_root="$workspace/_artifacts/esxi-l3-probe-iso"
profile=${PROFILE:-probe}
aer_window_seconds=0
aer_runner_grace_seconds=0
case "$profile" in
  probe)
    output="$workspace/_artifacts/esxi-l3-pci-probe.iso"
    ;;
  aer)
    output="$workspace/_artifacts/esxi-l3-aer-probe.iso"
    ;;
  aer-surface)
    output="$workspace/_artifacts/esxi-l3-aer-surface-probe.iso"
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
  p2p)
    output="$workspace/_artifacts/esxi-l3-p2p-probe.iso"
    ;;
  rmrr)
    output="$workspace/_artifacts/esxi-l3-rmrr-probe.iso"
    ;;
  pme)
    output="$workspace/_artifacts/esxi-l3-pme-probe.iso"
    ;;
  sriov)
    output="$workspace/_artifacts/esxi-l3-sriov-probe.iso"
    ;;
  *)
    echo "unsupported PROFILE: $profile" >&2
    exit 2
    ;;
esac
kernel_release=5.15.0-185-generic
kernel_config="/boot/config-$kernel_release"
if [[ "$profile" == aer ]]; then
  grep -qx 'CONFIG_VIRTIO=y' "$kernel_config"
  grep -qx 'CONFIG_VIRTIO_PCI=y' "$kernel_config"
  grep -qx 'CONFIG_VIRTIO_NET=m' "$kernel_config"
  grep -q \
    '^kernel/drivers/net/virtio_net\.ko: .*kernel/drivers/net/net_failover\.ko .*kernel/net/core/failover\.ko$' \
    "/lib/modules/$kernel_release/modules.dep"
fi

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
  if [[ "$profile" == edu || "$profile" == p2p ]]; then
    rm -f "$root/lib/modules/edu_probe.ko"
  fi
  if [[ "$profile" == aer ]]; then
    rm -f \
      "$root/lib/modules/failover.ko" \
      "$root/lib/modules/net_failover.ko" \
      "$root/lib/modules/virtio_net.ko"
  fi
  if [[ "$profile" == sriov ]]; then
    rm -f \
      "$root/lib/modules/nvme-core.ko" \
      "$root/lib/modules/nvme.ko" \
      "$root/lib/modules/dca.ko" \
      "$root/lib/modules/i2c-algo-bit.ko" \
      "$root/lib/modules/igb.ko" \
      "$root/lib/modules/igbvf.ko"
  fi
}

save_grub() {
  if [[ -z "$original_grub" ]]; then
    original_grub=$(mktemp)
    cp "$iso_root/boot/grub/grub.cfg" "$original_grub"
  fi
}

if [[ "$profile" != probe ]]; then
  original_init=$(mktemp)
  cp "$root/init" "$original_init"
  trap cleanup EXIT
  if [[ "$profile" == aer ]]; then
    cp "$workspace/github-export/vmware-esxi8-lab/esxi-l3-aer-init.sh" "$root/init"
  elif [[ "$profile" == aer-surface ]]; then
    cp "$workspace/github-export/vmware-esxi8-lab/esxi-l3-aer-surface-init.sh" "$root/init"
  elif [[ "$profile" == reboot ]]; then
    cp "$workspace/github-export/vmware-esxi8-lab/esxi-l3-reboot-init.sh" "$root/init"
  elif [[ "$profile" == edu ]]; then
    cp "$workspace/github-export/vmware-esxi8-lab/esxi-l3-edu-init.sh" "$root/init"
  elif [[ "$profile" == p2p ]]; then
    cp "$workspace/github-export/vmware-esxi8-lab/esxi-l3-p2p-init.sh" "$root/init"
  elif [[ "$profile" == rmrr ]]; then
    cp "$workspace/github-export/vmware-esxi8-lab/esxi-l3-rmrr-init.sh" "$root/init"
  elif [[ "$profile" == pme ]]; then
    cp "$workspace/github-export/vmware-esxi8-lab/esxi-l3-pme-init.sh" "$root/init"
  elif [[ "$profile" == sriov ]]; then
    cp "$workspace/github-export/vmware-esxi8-lab/esxi-l3-sriov-init.sh" "$root/init"
  else
    cp "$workspace/github-export/vmware-esxi8-lab/esxi-l3-vmotion-init.sh" "$root/init"
  fi
  chmod +x "$root/init"
fi

if [[ "$profile" == intx ]]; then
  save_grub
  sed -i 's/ rdinit=\/init quiet/ rdinit=\/init quiet pci=nomsi/' \
    "$iso_root/boot/grub/grub.cfg"
fi

if [[ "$profile" == aer ]]; then
  aer_window_seconds=${AER_WINDOW_SECONDS:-90}
  aer_runner_grace_seconds=${AER_RUNNER_GRACE_SECONDS:-300}
  for value in "$aer_window_seconds" "$aer_runner_grace_seconds"; do
    case "$value" in
      ''|*[!0-9]*)
        echo "AER window/grace values must be positive integers" >&2
        exit 2
        ;;
    esac
  done
  if [[ "$aer_window_seconds" -le 0 || "$aer_runner_grace_seconds" -le 0 ]]; then
    echo "AER window/grace values must be positive" >&2
    exit 2
  fi
  save_grub
  sed -i \
    "s# rdinit=/init quiet# rdinit=/init quiet aer_window_seconds=$aer_window_seconds aer_runner_managed=1 aer_runner_grace_seconds=$aer_runner_grace_seconds#" \
    "$iso_root/boot/grub/grub.cfg"
  for token in \
    "aer_window_seconds=$aer_window_seconds" \
    "aer_runner_managed=1" \
    "aer_runner_grace_seconds=$aer_runner_grace_seconds"; do
    token_count=$(grep -oF "$token" "$iso_root/boot/grub/grub.cfg" | wc -l)
    if [[ "$token_count" -ne 1 ]]; then
      echo "AER GRUB token must occur exactly once: $token" >&2
      exit 2
    fi
  done
fi

if [[ "${KERNEL_DEBUG:-0}" == 1 ]]; then
  save_grub
  sed -i \
    's/ rdinit=\/init quiet/ rdinit=\/init ignore_loglevel loglevel=8 earlyprintk=serial,ttyS0,115200/' \
    "$iso_root/boot/grub/grub.cfg"
fi

mkdir -p "$root/lib/modules"
cp "/lib/modules/$kernel_release/kernel/drivers/net/ethernet/intel/e1000e/e1000e.ko" \
  "$root/lib/modules/e1000e.ko"

if [[ "$profile" == aer ]]; then
  cp "/lib/modules/$kernel_release/kernel/net/core/failover.ko" \
    "$root/lib/modules/failover.ko"
  cp "/lib/modules/$kernel_release/kernel/drivers/net/net_failover.ko" \
    "$root/lib/modules/net_failover.ko"
  cp "/lib/modules/$kernel_release/kernel/drivers/net/virtio_net.ko" \
    "$root/lib/modules/virtio_net.ko"
fi

if [[ "$profile" == sriov ]]; then
  cp "/lib/modules/$kernel_release/kernel/drivers/nvme/host/nvme-core.ko" \
    "$root/lib/modules/nvme-core.ko"
  cp "/lib/modules/$kernel_release/kernel/drivers/nvme/host/nvme.ko" \
    "$root/lib/modules/nvme.ko"
  cp "/lib/modules/$kernel_release/kernel/drivers/dca/dca.ko" \
    "$root/lib/modules/dca.ko"
  cp "/lib/modules/$kernel_release/kernel/drivers/i2c/algos/i2c-algo-bit.ko" \
    "$root/lib/modules/i2c-algo-bit.ko"
  cp "/lib/modules/$kernel_release/kernel/drivers/net/ethernet/intel/igb/igb.ko" \
    "$root/lib/modules/igb.ko"
  cp "/lib/modules/$kernel_release/kernel/drivers/net/ethernet/intel/igbvf/igbvf.ko" \
    "$root/lib/modules/igbvf.ko"
fi

if [[ "$profile" == edu || "$profile" == p2p ]]; then
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

for app in dd hexdump insmod ip od ping poweroff reboot sync; do
  ln -sf busybox "$root/bin/$app"
done

(
  cd "$root"
  find . -print0 | cpio --null -o --format=newc > "$iso_root/boot/initrd.cpio"
)

grub-mkrescue -o "$output" "$iso_root"
sha256sum "$output"
file "$output"

attestation="${output}.build.json"
python3 - \
  "$attestation" \
  "$output" \
  "$profile" \
  "$kernel_release" \
  "$aer_window_seconds" \
  "$aer_runner_grace_seconds" \
  "$(readlink -f "$0")" \
  "$workspace/github-export/vmware-esxi8-lab/esxi-l3-aer-init.sh" \
  "$iso_root/boot/grub/grub.cfg" \
  "$iso_root/boot/initrd.cpio" \
  "$iso_root/boot/vmlinuz" \
  "$kernel_config" \
  "$root/lib/modules/e1000e.ko" \
  "$root/lib/modules/failover.ko" \
  "$root/lib/modules/net_failover.ko" \
  "$root/lib/modules/virtio_net.ko" <<'PY'
import datetime
import hashlib
import json
import pathlib
import sys

(
    attestation_path,
    iso_path,
    profile,
    kernel_release,
    aer_window_seconds,
    aer_runner_grace_seconds,
    *input_paths,
) = sys.argv[1:]


def sha256(path):
    digest = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


inputs = []
for raw_path in input_paths:
    path = pathlib.Path(raw_path)
    if path.is_file():
        inputs.append(
            {
                "path": str(path),
                "sha256": sha256(path),
            }
        )

value = {
    "schemaVersion": 1,
    "profile": profile,
    "kernelRelease": kernel_release,
    "aer": (
        {
            "windowSeconds": int(aer_window_seconds),
            "runnerManaged": True,
            "runnerWatchdogGraceSeconds": int(aer_runner_grace_seconds),
        }
        if profile == "aer"
        else None
    ),
    "builtAtUtc": datetime.datetime.now(
        datetime.timezone.utc
    ).isoformat().replace("+00:00", "Z"),
    "iso": {
        "path": iso_path,
        "sha256": sha256(iso_path),
    },
    "inputs": inputs,
}
pathlib.Path(attestation_path).write_text(
    json.dumps(value, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(f"attestation {attestation_path} sha256={sha256(attestation_path)}")
PY
