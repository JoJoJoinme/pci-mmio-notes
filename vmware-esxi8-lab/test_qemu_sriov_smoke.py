#!/usr/bin/env python3
"""Validate QEMU NVMe SR-IOV PF/VF creation through PCI config space."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import socket
import subprocess
import tempfile
import time
from pathlib import Path


MCFG_BASE = 0xB0000000
PCI_CONFIG_ADDRESS = 0xCF8
PCI_CONFIG_DATA = 0xCFC
Q35_PCIEXBAR_OFFSET = 0x60
Q35_PCIEXBAR_ENABLE = 1
PF_BUS = 0
PF_DEVICE = 9
PF_FUNCTION = 0
PCI_EXT_CAP_ID_SRIOV = 0x10


class QTestClient:
    def __init__(self, path: Path):
        self.connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.connection.settimeout(3)
        self.connection.connect(str(path))

    def close(self) -> None:
        self.connection.close()

    def command(self, command: str) -> str:
        self.connection.sendall(command.encode("ascii") + b"\n")
        response = b""
        while b"\n" not in response:
            response += self.connection.recv(65536)
        return response.decode("ascii", errors="replace").strip()


def qtest(client: QTestClient, command: str) -> int | None:
    response = client.command(command)
    if not response.startswith("OK"):
        raise RuntimeError(f"qtest command failed: {command!r}: {response!r}")
    match = re.search(r"0x[0-9a-fA-F]+|\b\d+\b", response[2:])
    return int(match.group(0), 0) if match else None


def pio_read32(client: QTestClient, port: int) -> int:
    value = qtest(client, f"inl 0x{port:x}")
    if value is None:
        raise RuntimeError("qtest inl returned no value")
    return value


def pio_write32(client: QTestClient, port: int, value: int) -> None:
    qtest(client, f"outl 0x{port:x} 0x{value:08x}")


def legacy_config_address(
    bus: int,
    device: int,
    function: int,
    offset: int,
) -> int:
    return (
        0x80000000
        | (bus << 16)
        | (device << 11)
        | (function << 8)
        | (offset & 0xFC)
    )


def legacy_config_read32(
    client: QTestClient,
    bus: int,
    device: int,
    function: int,
    offset: int,
) -> int:
    pio_write32(
        client,
        PCI_CONFIG_ADDRESS,
        legacy_config_address(bus, device, function, offset),
    )
    return pio_read32(client, PCI_CONFIG_DATA)


def legacy_config_write32(
    client: QTestClient,
    bus: int,
    device: int,
    function: int,
    offset: int,
    value: int,
) -> None:
    pio_write32(
        client,
        PCI_CONFIG_ADDRESS,
        legacy_config_address(bus, device, function, offset),
    )
    pio_write32(client, PCI_CONFIG_DATA, value)


def enable_q35_ecam(client: QTestClient) -> tuple[int, int]:
    before = legacy_config_read32(client, 0, 0, 0, Q35_PCIEXBAR_OFFSET)
    expected_base = MCFG_BASE | Q35_PCIEXBAR_ENABLE
    legacy_config_write32(
        client,
        0,
        0,
        0,
        Q35_PCIEXBAR_OFFSET,
        expected_base,
    )
    after = legacy_config_read32(client, 0, 0, 0, Q35_PCIEXBAR_OFFSET)
    if after != expected_base:
        raise RuntimeError(
            f"failed to enable Q35 PCIEXBAR: before=0x{before:08x}, "
            f"after=0x{after:08x}"
        )
    return before, after


def ecam_address(bus: int, device: int, function: int, offset: int) -> int:
    return (
        MCFG_BASE
        + (bus << 20)
        + (device << 15)
        + (function << 12)
        + offset
    )


def config_read16(
    client: QTestClient,
    bus: int,
    device: int,
    function: int,
    offset: int,
) -> int:
    value = qtest(
        client,
        f"readw 0x{ecam_address(bus, device, function, offset):x}",
    )
    if value is None:
        raise RuntimeError("qtest readw returned no value")
    return value


def config_read32(
    client: QTestClient,
    bus: int,
    device: int,
    function: int,
    offset: int,
) -> int:
    value = qtest(
        client,
        f"readl 0x{ecam_address(bus, device, function, offset):x}",
    )
    if value is None:
        raise RuntimeError("qtest readl returned no value")
    return value


def config_write16(
    client: QTestClient,
    bus: int,
    device: int,
    function: int,
    offset: int,
    value: int,
) -> None:
    qtest(
        client,
        f"writew 0x{ecam_address(bus, device, function, offset):x} 0x{value:04x}",
    )


def find_extended_capability(client: QTestClient, capability_id: int) -> int | None:
    pointer = 0x100
    visited: set[int] = set()
    while pointer and pointer not in visited:
        visited.add(pointer)
        header = config_read32(
            client, PF_BUS, PF_DEVICE, PF_FUNCTION, pointer
        )
        if header in (0, 0xFFFFFFFF):
            return None
        if header & 0xFFFF == capability_id:
            return pointer
        pointer = (header >> 20) & 0xFFC
    return None


def wait_socket(path: Path, process: subprocess.Popen[str], timeout: int = 15) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise RuntimeError(f"QEMU exited before creating {path}")
        time.sleep(0.05)
    raise TimeoutError(path)


def hmp_quit(path: Path) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as monitor:
        monitor.settimeout(3)
        monitor.connect(str(path))
        received = b""
        while b"(qemu)" not in received:
            received += monitor.recv(65536)
        monitor.sendall(b"quit\n")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--qemu",
        default="/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64",
    )
    parser.add_argument(
        "--vf-config-ids",
        action="store_true",
        help="enable the default-off x-sriov-vf-config-ids QEMU lab property",
    )
    parser.add_argument(
        "--device-profile",
        choices=("nvme", "igb-i350"),
        default="nvme",
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    qemu = Path(args.qemu).resolve()
    if not qemu.is_file():
        raise FileNotFoundError(qemu)
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="qemu-sriov-smoke-") as temporary:
        temporary_path = Path(temporary)
        qtest_path = temporary_path / "qtest.sock"
        monitor_path = temporary_path / "monitor.sock"
        if args.device_profile == "nvme":
            device_options = (
                "nvme,id=nvme0,serial=directpath-sriov,subsys=subsys0,"
                "bus=pcie.0,addr=0x09.0,sriov_max_vfs=1,"
                "sriov_vq_flexible=2,sriov_vi_flexible=1"
            )
            device_arguments = ["-device", "nvme-subsys,id=subsys0"]
            if args.vf_config_ids:
                device_options += ",x-sriov-vf-config-ids=on"
        else:
            if args.vf_config_ids:
                parser.error("--vf-config-ids is only valid for the nvme profile")
            device_options = (
                "igb,id=igb0,netdev=igbnet,bus=pcie.0,addr=0x09.0,"
                "x-pci-device-id=0x1521,x-pci-vf-device-id=0x1520,"
                "x-pci-subsystem-vendor-id=0x8086,x-pci-subsystem-id=0x0000"
            )
            device_arguments = ["-netdev", "user,id=igbnet,restrict=on"]
        command = [
            str(qemu),
            "-nodefaults",
            "-machine",
            "q35,accel=qtest",
            "-display",
            "none",
            "-S",
            *device_arguments,
            "-device",
            device_options,
            "-qtest",
            f"unix:{qtest_path},server=on,wait=off",
            "-monitor",
            f"unix:{monitor_path},server,nowait",
            "-trace",
            "enable=sriov_register_vfs",
            "-trace",
            "enable=sriov_unregister_vfs",
            "-trace",
            "enable=sriov_config_write",
        ]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        result: dict = {
            "case": f"QEMU-{args.device_profile}-SR-IOV-PF-VF-smoke",
            "deviceProfile": args.device_profile,
            "command": command,
            "qemu": {"path": str(qemu), "sha256": sha256(qemu)},
            "verdict": "running",
        }
        try:
            wait_socket(qtest_path, process)
            wait_socket(monitor_path, process)
            client = QTestClient(qtest_path)
            try:
                pciexbar_before, pciexbar_after = enable_q35_ecam(client)
                pf_vendor = config_read16(
                    client, PF_BUS, PF_DEVICE, PF_FUNCTION, 0x00
                )
                pf_device = config_read16(
                    client, PF_BUS, PF_DEVICE, PF_FUNCTION, 0x02
                )
                pf_subsystem_vendor = config_read16(
                    client, PF_BUS, PF_DEVICE, PF_FUNCTION, 0x2C
                )
                pf_subsystem_device = config_read16(
                    client, PF_BUS, PF_DEVICE, PF_FUNCTION, 0x2E
                )
                sriov = find_extended_capability(client, PCI_EXT_CAP_ID_SRIOV)
                if sriov is None:
                    raise RuntimeError("SR-IOV extended capability not found")
                extended_header_100 = config_read32(
                    client, PF_BUS, PF_DEVICE, PF_FUNCTION, 0x100
                )
                extended_header_120 = config_read32(
                    client, PF_BUS, PF_DEVICE, PF_FUNCTION, 0x120
                )

                control_before = config_read16(
                    client, PF_BUS, PF_DEVICE, PF_FUNCTION, sriov + 0x08
                )
                initial_vfs = config_read16(
                    client, PF_BUS, PF_DEVICE, PF_FUNCTION, sriov + 0x0C
                )
                total_vfs = config_read16(
                    client, PF_BUS, PF_DEVICE, PF_FUNCTION, sriov + 0x0E
                )
                num_vfs_before = config_read16(
                    client, PF_BUS, PF_DEVICE, PF_FUNCTION, sriov + 0x10
                )
                first_vf_offset = config_read16(
                    client, PF_BUS, PF_DEVICE, PF_FUNCTION, sriov + 0x14
                )
                vf_stride = config_read16(
                    client, PF_BUS, PF_DEVICE, PF_FUNCTION, sriov + 0x16
                )
                advertised_vf_device = config_read16(
                    client, PF_BUS, PF_DEVICE, PF_FUNCTION, sriov + 0x1A
                )

                config_write16(
                    client, PF_BUS, PF_DEVICE, PF_FUNCTION, sriov + 0x10, 1
                )
                config_write16(
                    client,
                    PF_BUS,
                    PF_DEVICE,
                    PF_FUNCTION,
                    sriov + 0x08,
                    control_before | 1,
                )
                time.sleep(0.1)

                pf_rid = (PF_BUS << 8) | (PF_DEVICE << 3) | PF_FUNCTION
                vf_rid = pf_rid + first_vf_offset
                vf_bus = vf_rid >> 8
                vf_device = (vf_rid >> 3) & 0x1F
                vf_function = vf_rid & 7
                vf_vendor = config_read16(
                    client, vf_bus, vf_device, vf_function, 0x00
                )
                vf_device_id = config_read16(
                    client, vf_bus, vf_device, vf_function, 0x02
                )
                num_vfs_enabled = config_read16(
                    client, PF_BUS, PF_DEVICE, PF_FUNCTION, sriov + 0x10
                )
                control_enabled = config_read16(
                    client, PF_BUS, PF_DEVICE, PF_FUNCTION, sriov + 0x08
                )

                config_write16(
                    client,
                    PF_BUS,
                    PF_DEVICE,
                    PF_FUNCTION,
                    sriov + 0x08,
                    control_before & ~1,
                )
                config_write16(
                    client, PF_BUS, PF_DEVICE, PF_FUNCTION, sriov + 0x10, 0
                )
                time.sleep(0.1)
                vf_vendor_after_disable = config_read16(
                    client, vf_bus, vf_device, vf_function, 0x00
                )
                hmp_quit(monitor_path)
            finally:
                client.close()

            result["config"] = {
                "pciexbarBefore": f"0x{pciexbar_before:08x}",
                "pciexbarAfter": f"0x{pciexbar_after:08x}",
                "extendedHeader100": f"0x{extended_header_100:08x}",
                "extendedHeader120": f"0x{extended_header_120:08x}",
                "pfBdf": f"0000:{PF_BUS:02x}:{PF_DEVICE:02x}.{PF_FUNCTION}",
                "pfVendor": f"0x{pf_vendor:04x}",
                "pfDevice": f"0x{pf_device:04x}",
                "pfSubsystemVendor": f"0x{pf_subsystem_vendor:04x}",
                "pfSubsystemDevice": f"0x{pf_subsystem_device:04x}",
                "sriovCapabilityOffset": f"0x{sriov:03x}",
                "initialVfs": initial_vfs,
                "totalVfs": total_vfs,
                "numVfsBefore": num_vfs_before,
                "numVfsEnabled": num_vfs_enabled,
                "firstVfOffset": first_vf_offset,
                "vfStride": vf_stride,
                "advertisedVfDevice": f"0x{advertised_vf_device:04x}",
                "controlBefore": f"0x{control_before:04x}",
                "controlEnabled": f"0x{control_enabled:04x}",
                "vfBdf": f"0000:{vf_bus:02x}:{vf_device:02x}.{vf_function}",
                "vfVendor": f"0x{vf_vendor:04x}",
                "vfDevice": f"0x{vf_device_id:04x}",
                "vfVendorAfterDisable": f"0x{vf_vendor_after_disable:04x}",
            }
            stdout, stderr = process.communicate(timeout=15)
            checks = {
                "qemuExitedCleanly": process.returncode == 0,
                "pfPresent": pf_vendor not in (0, 0xFFFF),
                "profileIdentityMatches": (
                    (
                        pf_vendor == 0x8086
                        and pf_device == 0x1521
                        and pf_subsystem_vendor == 0x8086
                        and pf_subsystem_device == 0x0000
                    )
                    if args.device_profile == "igb-i350"
                    else pf_vendor == 0x1B36 and pf_device == 0x0010
                ),
                "sriovCapabilityPresent": sriov >= 0x100,
                "vfsAdvertised": initial_vfs >= 1 and total_vfs >= 1,
                "vfEnableLatched": bool(control_enabled & 1),
                "numVfsLatched": num_vfs_enabled == 1,
                "vfRegisterCallback": any(
                    "sriov_register_vfs" in line for line in stderr.splitlines()
                ),
                "vfUnregisterCallback": any(
                    "sriov_unregister_vfs" in line for line in stderr.splitlines()
                ),
                "rawVfConfigMatchesSelectedMode": (
                    (
                        vf_vendor == pf_vendor
                        and vf_device_id == advertised_vf_device
                    )
                    if args.vf_config_ids
                    else vf_vendor == 0xFFFF and vf_device_id == 0xFFFF
                ),
                "rawVfConfigStillSentinelAfterDisable": (
                    vf_vendor_after_disable == 0xFFFF
                ),
            }
            result["checks"] = checks
            result["scope"] = {
                "proves": (
                    "PF SR-IOV capability, VFE/NumVFs writes, and QEMU "
                    "register/unregister callbacks"
                ),
                "doesNotProve": (
                    "guest OS VF enumeration; use test_qemu_sriov_linux.py"
                ),
                "rawVfIds": (
                    "lab property exposes the PF VID and advertised VF DID "
                    "in an enabled VF's raw config space"
                    if args.vf_config_ids
                    else "stock QEMU auto-created VF config objects retain "
                    "0xffff VID/DID sentinels; Linux constructs the VF "
                    "pci_dev from the PF SR-IOV capability"
                ),
            }
            result["mode"] = {
                "vfConfigIdsLabProperty": args.vf_config_ids,
            }
            result["stdout"] = stdout.splitlines()
            result["stderr"] = stderr.splitlines()
            result["verdict"] = "pass" if all(checks.values()) else "fail"
        except Exception:
            process.terminate()
            process.communicate(timeout=15)
            raise

    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    (output / "result.json").write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
