#!/usr/bin/env python3
"""Prove that VFIO's global unsafe switch is not a per-device DMA verdict."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path


CASES = ("no-iommu", "iommu-with-unsafe-switch")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command_output(command: list[str]) -> str:
    return subprocess.run(
        command,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout.strip()


def write_seed(case: str, seed_dir: Path, seed_image: Path) -> None:
    seed_dir.mkdir(parents=True, exist_ok=True)
    (seed_dir / "meta-data").write_text(
        f"instance-id: qman-vfio-{case}-{time.time_ns()}\n"
        f"local-hostname: qman-vfio-{case}\n",
        encoding="ascii",
    )
    proof = f"""#!/usr/bin/env bash
set -u
exec >/dev/ttyS0 2>&1

case_name={case!r}
marker=/var/lib/qman-vfio-iommu-rebooted
failures=0

echo VFIO_SPLIT_BEGIN
echo VFIO_SPLIT_CASE=$case_name
echo KERNEL=$(uname -r)
echo CMDLINE=$(cat /proc/cmdline)

target=
for device in /sys/bus/pci/devices/*; do
    [ "$(cat "$device/vendor" 2>/dev/null)" = "0x8086" ] || continue
    [ "$(cat "$device/device" 2>/dev/null)" = "0x10d3" ] || continue
    target=$device
    break
done

if [ -z "$target" ]; then
    echo TARGET_NOT_FOUND
    failures=$((failures + 1))
else
    bdf=${{target##*/}}
    pre_group=
    if [ -L "$target/iommu_group" ]; then
        pre_group=$(basename "$(readlink -f "$target/iommu_group")")
    fi
    echo TARGET_BDF=$bdf
    echo PRE_BIND_GROUP=${{pre_group:-none}}

    if [ "$case_name" = "iommu-with-unsafe-switch" ] && [ -z "$pre_group" ] && [ ! -e "$marker" ]; then
        mkdir -p /etc/default/grub.d
        printf '%s\n' 'GRUB_CMDLINE_LINUX_DEFAULT="intel_iommu=on"' \
            > /etc/default/grub.d/99-qman-vfio-iommu.cfg
        update-grub
        touch "$marker"
        echo IOMMU_REBOOT_REQUESTED
        sync
        reboot
        exit 0
    fi

    if ! modprobe vfio enable_unsafe_noiommu_mode=1; then
        echo VFIO_MODULE_LOAD_FAILED
        failures=$((failures + 1))
    fi
    if [ -e /sys/module/vfio/parameters/enable_unsafe_noiommu_mode ]; then
        echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
    fi
    if ! modprobe vfio-pci; then
        echo VFIO_PCI_MODULE_LOAD_FAILED
        failures=$((failures + 1))
    fi

    unsafe=$(cat /sys/module/vfio/parameters/enable_unsafe_noiommu_mode 2>/dev/null || true)
    echo UNSAFE_SWITCH=${{unsafe:-missing}}
    if [ "$unsafe" != "Y" ] && [ "$unsafe" != "1" ]; then
        failures=$((failures + 1))
    fi

    echo vfio-pci > "$target/driver_override"
    if [ -L "$target/driver" ]; then
        echo "$bdf" > "$target/driver/unbind"
    fi
    if ! echo "$bdf" > /sys/bus/pci/drivers/vfio-pci/bind; then
        echo VFIO_BIND_FAILED
        failures=$((failures + 1))
    fi
    sleep 2

    driver=$(basename "$(readlink -f "$target/driver" 2>/dev/null)" 2>/dev/null || true)
    group=
    if [ -L "$target/iommu_group" ]; then
        group=$(basename "$(readlink -f "$target/iommu_group")")
    fi
    echo POST_BIND_DRIVER=${{driver:-none}}
    echo POST_BIND_GROUP=${{group:-none}}
    find /dev/vfio -maxdepth 2 -printf 'VFIO_NODE=%p\n' 2>/dev/null | sort

    if [ "$driver" != "vfio-pci" ] || [ -z "$group" ]; then
        failures=$((failures + 1))
    elif [ "$case_name" = "no-iommu" ]; then
        [ -z "$pre_group" ] || failures=$((failures + 1))
        if [ -e "/dev/vfio/noiommu-$group" ] && [ ! -e "/dev/vfio/$group" ]; then
            echo DMA_MODE=no-iommu
        else
            echo NOIOMMU_NODE_ASSERTION_FAILED
            failures=$((failures + 1))
        fi
    else
        [ -n "$pre_group" ] || failures=$((failures + 1))
        if [ -e "/dev/vfio/$group" ] && [ ! -e "/dev/vfio/noiommu-$group" ]; then
            echo DMA_MODE=iommu
        else
            echo IOMMU_NODE_ASSERTION_FAILED
            failures=$((failures + 1))
        fi
    fi
fi

echo VFIO_SPLIT_FAILURES=$failures
if [ "$failures" -eq 0 ]; then
    echo VFIO_SPLIT_PASS
else
    echo VFIO_SPLIT_FAIL
fi
sync
poweroff -f
"""
    indented_proof = "".join(f"      {line}\n" for line in proof.splitlines())
    user_data = f"""#cloud-config
datasource_list: [ NoCloud, None ]
network:
  config: disabled
output:
  all: "| tee -a /var/log/cloud-init-output.log /dev/ttyS0"
write_files:
  - path: /usr/local/sbin/qman-vfio-split-proof.sh
    permissions: '0755'
    content: |
{indented_proof}  - path: /etc/systemd/system/qman-vfio-split-proof.service
    permissions: '0644'
    content: |
      [Unit]
      Description=Qman VFIO IOMMU/no-IOMMU split proof
      After=cloud-final.service

      [Service]
      Type=oneshot
      ExecStart=/usr/local/sbin/qman-vfio-split-proof.sh

      [Install]
      WantedBy=multi-user.target
runcmd:
  - [ systemctl, enable, qman-vfio-split-proof.service ]
  - [ /usr/local/sbin/qman-vfio-split-proof.sh ]
"""
    (seed_dir / "user-data").write_text(user_data, encoding="ascii")
    subprocess.run(
        [
            "xorriso",
            "-as",
            "mkisofs",
            "-quiet",
            "-output",
            str(seed_image),
            "-volid",
            "cidata",
            "-joliet",
            "-rock",
            "user-data",
            "meta-data",
        ],
        cwd=seed_dir,
        check=True,
    )


def run_case(args: argparse.Namespace, case: str, output: Path) -> dict[str, object]:
    case_dir = output / case
    case_dir.mkdir(parents=True, exist_ok=True)
    overlay = case_dir / "os.qcow2"
    vars_file = case_dir / "OVMF_VARS.fd"
    seed_image = case_dir / "seed.iso"
    serial_log = case_dir / "serial.log"

    shutil.copyfile(args.ovmf_vars, vars_file)
    image_info = json.loads(
        command_output(["qemu-img", "info", "--output=json", str(args.base_image)])
    )
    subprocess.run(
        [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-F",
            image_info["format"],
            "-b",
            str(args.base_image),
            str(overlay),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    write_seed(case, case_dir / "seed", seed_image)

    command = [
        str(args.qemu),
        "-machine",
        "q35,accel=kvm,kernel-irqchip=split",
        "-cpu",
        "host",
        "-m",
        "1536",
        "-smp",
        "2",
        "-nodefaults",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-monitor",
        "none",
        "-no-reboot",
        "-device",
        "pcie-root-port,id=test_rp,bus=pcie.0,addr=0x02,chassis=2",
        "-device",
        "e1000e,id=testnic,bus=test_rp,addr=0x00",
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={args.ovmf_code}",
        "-drive",
        f"if=pflash,format=raw,file={vars_file}",
        "-drive",
        f"if=none,id=osdisk,format=qcow2,file={overlay}",
        "-device",
        "virtio-blk-pci,drive=osdisk",
        "-drive",
        f"if=none,id=cidata,format=raw,readonly=on,file={seed_image}",
        "-device",
        "virtio-blk-pci,drive=cidata",
        "-device",
        "virtio-rng-pci",
        "-netdev",
        "user,id=net0",
        "-device",
        "virtio-net-pci,netdev=net0",
    ]
    if case == "iommu-with-unsafe-switch":
        command.extend(
            [
                "-device",
                "intel-iommu,intremap=on,caching-mode=on,device-iotlb=on",
            ]
        )

    started = time.monotonic()
    timed_out = False
    with serial_log.open("w", encoding="utf-8") as stream:
        try:
            completed = subprocess.run(
                command,
                stdout=stream,
                stderr=subprocess.STDOUT,
                timeout=args.timeout,
            )
            return_code = completed.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            return_code = None
    log = serial_log.read_text(encoding="utf-8", errors="replace")
    result = {
        "case": case,
        "passed": "VFIO_SPLIT_PASS" in log and "VFIO_SPLIT_FAILURES=0" in log,
        "timedOut": timed_out,
        "returnCode": return_code,
        "durationSeconds": round(time.monotonic() - started, 3),
        "unsafeSwitch": "Y" if "UNSAFE_SWITCH=Y" in log else "unknown",
        "dmaMode": (
            "no-iommu"
            if "DMA_MODE=no-iommu" in log
            else "iommu"
            if "DMA_MODE=iommu" in log
            else "unknown"
        ),
        "serialLog": str(serial_log),
        "command": command,
    }
    (case_dir / "result.json").write_text(
        json.dumps(result, indent=2) + "\n",
        encoding="utf-8",
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--qemu",
        type=Path,
        default=Path("/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64"),
    )
    parser.add_argument(
        "--base-image",
        type=Path,
        default=Path("/mnt/e/Code/PCI/_artifacts/noble-server-cloudimg-amd64.img"),
    )
    parser.add_argument(
        "--ovmf-code",
        type=Path,
        default=Path("/usr/share/OVMF/OVMF_CODE.fd"),
    )
    parser.add_argument(
        "--ovmf-vars",
        type=Path,
        default=Path("/usr/share/OVMF/OVMF_VARS.fd"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=360)
    args = parser.parse_args()

    for path in (args.qemu, args.base_image, args.ovmf_code, args.ovmf_vars):
        if not path.is_file():
            raise FileNotFoundError(path)
    args.output.mkdir(parents=True, exist_ok=True)

    results = [run_case(args, case, args.output) for case in CASES]
    summary = {
        "schemaVersion": 1,
        "test": "qemu-vfio-noiommu-split",
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "qemu": {"path": str(args.qemu), "sha256": sha256(args.qemu)},
        "baseImage": {
            "path": str(args.base_image),
            "sha256": sha256(args.base_image),
        },
        "cases": results,
        "verdict": "pass" if all(result["passed"] for result in results) else "fail",
    }
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2))
    raise SystemExit(0 if summary["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
