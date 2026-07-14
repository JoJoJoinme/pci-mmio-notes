#!/usr/bin/env python3
"""Boot Linux and prove QEMU's NVMe SR-IOV PF/VF lifecycle via sysfs."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path


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


def write_seed(seed_dir: Path, seed_image: Path) -> None:
    seed_dir.mkdir(parents=True, exist_ok=True)
    (seed_dir / "meta-data").write_text(
        f"instance-id: qemu-sriov-{time.time_ns()}\n"
        "local-hostname: qemu-sriov\n",
        encoding="ascii",
    )
    (seed_dir / "user-data").write_text(
        """#cloud-config
datasource_list: [ NoCloud, None ]
network:
  config: disabled
output:
  all: "| tee -a /var/log/cloud-init-output.log /dev/ttyS0"
write_files:
  - path: /usr/local/sbin/qemu-sriov-proof.sh
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      exec >/dev/ttyS0 2>&1
      failures=0
      echo SRIOV_TEST_BEGIN
      uname -a

      pf=
      for device in /sys/bus/pci/devices/*; do
        [ -f "$device/sriov_totalvfs" ] || continue
        total=$(cat "$device/sriov_totalvfs")
        if [ "$total" -gt 0 ]; then
          pf=$device
          break
        fi
      done

      if [ -z "$pf" ]; then
        echo PF_NOT_FOUND
        failures=$((failures + 1))
      else
        pf_bdf=${pf##*/}
        echo PF_BDF=$pf_bdf
        echo PF_VENDOR=$(cat "$pf/vendor")
        echo PF_DEVICE=$(cat "$pf/device")
        echo PF_TOTAL_VFS=$(cat "$pf/sriov_totalvfs")
        echo PF_NUM_VFS_BEFORE=$(cat "$pf/sriov_numvfs")
        if command -v lspci >/dev/null 2>&1; then
          lspci -Dnn -s "$pf_bdf" -vv
        fi

        if ! echo 1 > "$pf/sriov_numvfs"; then
          echo VF_ENABLE_FAILED
          failures=$((failures + 1))
        fi
        sleep 1
        echo PF_NUM_VFS_ENABLED=$(cat "$pf/sriov_numvfs")

        vf=
        vf_count=0
        for device in /sys/bus/pci/devices/*; do
          [ -L "$device/physfn" ] || continue
          if [ "$(readlink -f "$device/physfn")" = "$(readlink -f "$pf")" ]; then
            vf=$device
            vf_count=$((vf_count + 1))
          fi
        done
        echo VF_COUNT_ENABLED=$vf_count
        if [ "$vf_count" -ne 1 ] || [ -z "$vf" ]; then
          echo VF_ENUMERATION_FAILED
          failures=$((failures + 1))
        else
          vf_bdf=${vf##*/}
          vf_vendor=$(cat "$vf/vendor")
          vf_device=$(cat "$vf/device")
          echo VF_BDF=$vf_bdf
          echo VF_VENDOR=$vf_vendor
          echo VF_DEVICE=$vf_device
          echo VF_PHYSFN=$(basename "$(readlink -f "$vf/physfn")")
          if [ "$vf_vendor" != "0x1b36" ] || [ "$vf_device" != "0x0010" ]; then
            echo VF_ID_MISMATCH
            failures=$((failures + 1))
          fi
          if command -v lspci >/dev/null 2>&1; then
            lspci -Dnn -s "$vf_bdf" -vv
          fi
        fi

        if ! echo 0 > "$pf/sriov_numvfs"; then
          echo VF_DISABLE_FAILED
          failures=$((failures + 1))
        fi
        sleep 1
        vf_count=0
        for device in /sys/bus/pci/devices/*; do
          [ -L "$device/physfn" ] || continue
          if [ "$(readlink -f "$device/physfn")" = "$(readlink -f "$pf")" ]; then
            vf_count=$((vf_count + 1))
          fi
        done
        echo PF_NUM_VFS_AFTER_DISABLE=$(cat "$pf/sriov_numvfs")
        echo VF_COUNT_AFTER_DISABLE=$vf_count
        if [ "$vf_count" -ne 0 ]; then
          failures=$((failures + 1))
        fi
      fi

      echo SRIOV_FAILURES=$failures
      if [ "$failures" -eq 0 ]; then
        echo SRIOV_TEST_PASS
      else
        echo SRIOV_TEST_FAIL
      fi
      sync
      poweroff -f
runcmd:
  - [ /usr/local/sbin/qemu-sriov-proof.sh ]
""",
        encoding="ascii",
    )
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


def marker(log: str, name: str) -> str | None:
    prefix = f"{name}="
    for line in log.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip()
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--qemu",
        default="/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64",
    )
    parser.add_argument(
        "--base-image",
        default=(
            "/mnt/e/Code/PCI/_artifacts/"
            "noble-server-cloudimg-amd64.img"
        ),
    )
    parser.add_argument("--ovmf-code", default="/usr/share/OVMF/OVMF_CODE.fd")
    parser.add_argument("--ovmf-vars", default="/usr/share/OVMF/OVMF_VARS.fd")
    parser.add_argument(
        "--vf-config-ids",
        action="store_true",
        help="enable the default-off x-sriov-vf-config-ids QEMU lab property",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=int, default=420)
    args = parser.parse_args()

    qemu = Path(args.qemu).resolve()
    base_image = Path(args.base_image).resolve()
    ovmf_code = Path(args.ovmf_code).resolve()
    ovmf_vars_template = Path(args.ovmf_vars).resolve()
    for required in (qemu, base_image, ovmf_code, ovmf_vars_template):
        if not required.is_file():
            raise FileNotFoundError(required)

    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    overlay = output / "os.qcow2"
    vars_file = output / "OVMF_VARS.fd"
    seed_image = output / "seed.iso"
    serial_log = output / "serial.log"
    for generated in (overlay, vars_file, seed_image, serial_log):
        if generated.exists():
            generated.unlink()

    shutil.copyfile(ovmf_vars_template, vars_file)
    image_info = json.loads(
        command_output(["qemu-img", "info", "--output=json", str(base_image)])
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
            str(base_image),
            str(overlay),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    write_seed(output / "seed", seed_image)

    nvme_options = (
        "nvme,id=nvme0,serial=directpath-sriov,subsys=subsys0,"
        "bus=sriov_rp,addr=0x00.0,sriov_max_vfs=1,"
        "sriov_vq_flexible=2,sriov_vi_flexible=1"
    )
    if args.vf_config_ids:
        nvme_options += ",x-sriov-vf-config-ids=on"

    command = [
        str(qemu),
        "-machine",
        "q35,accel=kvm",
        "-cpu",
        "host",
        "-m",
        "2048",
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
        "pcie-root-port,id=sriov_rp,bus=pcie.0,addr=0x02,chassis=2",
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={ovmf_code}",
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
        "-device",
        "nvme-subsys,id=subsys0",
        "-device",
        nvme_options,
        "-trace",
        "enable=sriov_register_vfs",
        "-trace",
        "enable=sriov_unregister_vfs",
        "-trace",
        "enable=sriov_config_write",
    ]

    timed_out = False
    return_code: int | None = None
    with serial_log.open("w", encoding="utf-8") as log_stream:
        try:
            completed = subprocess.run(
                command,
                stdout=log_stream,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=args.timeout,
            )
            return_code = completed.returncode
        except subprocess.TimeoutExpired:
            timed_out = True

    log = serial_log.read_text(encoding="utf-8", errors="replace")
    checks = {
        "qemuExitedCleanly": return_code == 0,
        "notTimedOut": not timed_out,
        "pfFound": marker(log, "PF_BDF") is not None,
        "oneVfEnabled": marker(log, "VF_COUNT_ENABLED") == "1",
        "vfVendor": marker(log, "VF_VENDOR") == "0x1b36",
        "vfDevice": marker(log, "VF_DEVICE") == "0x0010",
        "vfLinksToPf": (
            marker(log, "VF_PHYSFN") is not None
            and marker(log, "VF_PHYSFN") == marker(log, "PF_BDF")
        ),
        "vfRemoved": marker(log, "VF_COUNT_AFTER_DISABLE") == "0",
        "guestPassMarker": "SRIOV_TEST_PASS" in log,
        "qemuRegisterTrace": "sriov_register_vfs" in log,
        "qemuUnregisterTrace": "sriov_unregister_vfs" in log,
    }
    result = {
        "case": "QEMU-NVMe-SR-IOV-Linux-PF-VF-lifecycle",
        "mode": {"vfConfigIdsLabProperty": args.vf_config_ids},
        "command": command,
        "qemu": {
            "path": str(qemu),
            "version": command_output([str(qemu), "--version"]).splitlines()[0],
            "sha256": sha256(qemu),
        },
        "firmware": {
            "code": str(ovmf_code),
            "codeSha256": sha256(ovmf_code),
            "varsTemplate": str(ovmf_vars_template),
            "varsTemplateSha256": sha256(ovmf_vars_template),
        },
        "baseImage": {
            "path": str(base_image),
            "format": image_info["format"],
            "sha256": sha256(base_image),
        },
        "guest": {
            "pfBdf": marker(log, "PF_BDF"),
            "pfVendor": marker(log, "PF_VENDOR"),
            "pfDevice": marker(log, "PF_DEVICE"),
            "totalVfs": marker(log, "PF_TOTAL_VFS"),
            "vfBdf": marker(log, "VF_BDF"),
            "vfVendor": marker(log, "VF_VENDOR"),
            "vfDevice": marker(log, "VF_DEVICE"),
            "vfPhysfn": marker(log, "VF_PHYSFN"),
        },
        "process": {
            "returnCode": return_code,
            "timedOut": timed_out,
        },
        "checks": checks,
        "verdict": "pass" if all(checks.values()) else "fail",
    }
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    (output / "result.json").write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
