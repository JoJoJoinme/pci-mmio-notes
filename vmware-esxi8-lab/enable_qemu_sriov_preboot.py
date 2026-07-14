#!/usr/bin/env python3
"""Enable one QEMU SR-IOV VF before firmware starts, then resume the VM."""

from __future__ import annotations

import argparse
import json
import socket
import time
from pathlib import Path

from test_qemu_sriov_smoke import (
    PCI_EXT_CAP_ID_SRIOV,
    QTestClient,
    config_read16,
    config_read32,
    config_write16,
    ecam_address,
    enable_q35_ecam,
    qtest,
)


def config_write32(
    client: QTestClient,
    bus: int,
    device: int,
    function: int,
    offset: int,
    value: int,
) -> None:
    qtest(
        client,
        f"writel 0x{ecam_address(bus, device, function, offset):x} "
        f"0x{value:08x}",
    )


def find_extended_capability(
    client: QTestClient,
    bus: int,
    device: int,
    function: int,
    capability_id: int,
) -> tuple[int | None, list[dict[str, str]]]:
    pointer = 0x100
    visited: set[int] = set()
    chain: list[dict[str, str]] = []
    while pointer and pointer not in visited:
        visited.add(pointer)
        header = config_read32(client, bus, device, function, pointer)
        chain.append(
            {
                "offset": f"0x{pointer:03x}",
                "header": f"0x{header:08x}",
                "id": f"0x{header & 0xffff:04x}",
            }
        )
        if header in (0, 0xFFFFFFFF):
            break
        if header & 0xFFFF == capability_id:
            return pointer, chain
        pointer = (header >> 20) & 0xFFC
    return None, chain


def hmp_command(path: Path, command: str) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as monitor:
        monitor.settimeout(3)
        monitor.connect(str(path))
        received = bytearray()
        deadline = time.monotonic() + 3
        while b"(qemu)" not in received and time.monotonic() < deadline:
            received.extend(monitor.recv(65536))
        monitor.sendall(command.encode("ascii") + b"\n")
        time.sleep(0.25)
        try:
            received.extend(monitor.recv(65536))
        except TimeoutError:
            pass
    return received.decode("utf-8", errors="replace")


def wait_path(path: Path, timeout: int = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    raise TimeoutError(path)


def parse_bdf(value: str) -> tuple[int, int, int]:
    domain_bus, device_function = value.rsplit(":", 1)
    _, bus = domain_bus.split(":", 1)
    device, function = device_function.split(".", 1)
    return int(bus, 16), int(device, 16), int(function, 16)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qtest", required=True)
    parser.add_argument("--monitor", required=True)
    parser.add_argument("--root-port", default="0000:00:0a.0")
    parser.add_argument("--secondary-bus", type=lambda item: int(item, 0), default=2)
    parser.add_argument("--pf", default="0000:02:00.0")
    parser.add_argument("--num-vfs", type=int, default=1)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    qtest_path = Path(args.qtest)
    monitor_path = Path(args.monitor)
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    wait_path(qtest_path)
    wait_path(monitor_path)

    root_bus, root_device, root_function = parse_bdf(args.root_port)
    pf_bus, pf_device, pf_function = parse_bdf(args.pf)
    if pf_bus != args.secondary_bus:
        raise ValueError("PF bus must match --secondary-bus")

    client = QTestClient(qtest_path)
    try:
        pciexbar_before, pciexbar_after = enable_q35_ecam(client)
        root_vendor = config_read16(
            client, root_bus, root_device, root_function, 0x00
        )
        root_device_id = config_read16(
            client, root_bus, root_device, root_function, 0x02
        )
        bus_numbers_before = config_read32(
            client, root_bus, root_device, root_function, 0x18
        )
        bus_numbers = (args.secondary_bus << 16) | (args.secondary_bus << 8)
        config_write32(
            client,
            root_bus,
            root_device,
            root_function,
            0x18,
            bus_numbers,
        )
        bus_numbers_after = config_read32(
            client, root_bus, root_device, root_function, 0x18
        )

        pf_vendor = config_read16(client, pf_bus, pf_device, pf_function, 0x00)
        pf_device_id = config_read16(client, pf_bus, pf_device, pf_function, 0x02)
        sriov, capability_chain = find_extended_capability(
            client,
            pf_bus,
            pf_device,
            pf_function,
            PCI_EXT_CAP_ID_SRIOV,
        )
        if sriov is None:
            raise RuntimeError("SR-IOV capability not found on PF")

        total_vfs = config_read16(
            client, pf_bus, pf_device, pf_function, sriov + 0x0E
        )
        if args.num_vfs < 1 or args.num_vfs > total_vfs:
            raise ValueError(
                f"requested {args.num_vfs} VFs, PF advertises {total_vfs}"
            )
        control_before = config_read16(
            client, pf_bus, pf_device, pf_function, sriov + 0x08
        )
        config_write16(
            client,
            pf_bus,
            pf_device,
            pf_function,
            sriov + 0x10,
            args.num_vfs,
        )
        config_write16(
            client,
            pf_bus,
            pf_device,
            pf_function,
            sriov + 0x08,
            control_before | 1,
        )
        control_after = config_read16(
            client, pf_bus, pf_device, pf_function, sriov + 0x08
        )
        num_vfs_after = config_read16(
            client, pf_bus, pf_device, pf_function, sriov + 0x10
        )
    finally:
        client.close()

    status_before = hmp_command(monitor_path, "info status")
    continue_output = hmp_command(monitor_path, "cont")
    time.sleep(0.25)
    status_after = hmp_command(monitor_path, "info status")
    checks = {
        "q35EcamEnabled": pciexbar_after & 1 == 1,
        "rootPortPresent": root_vendor not in (0, 0xFFFF),
        "rootPortBusProgrammed": bus_numbers_after == bus_numbers,
        "pfPresent": pf_vendor == 0x1B36 and pf_device_id == 0x0010,
        "sriovCapabilityPresent": sriov >= 0x100,
        "vfEnableLatched": bool(control_after & 1),
        "numVfsLatched": num_vfs_after == args.num_vfs,
        "vmWasPaused": "paused" in status_before.lower(),
        "vmIsRunning": "running" in status_after.lower(),
    }
    result = {
        "case": "QEMU-SR-IOV-pre-firmware-enable",
        "input": {
            "rootPort": args.root_port,
            "secondaryBus": args.secondary_bus,
            "pf": args.pf,
            "numVfs": args.num_vfs,
        },
        "config": {
            "pciexbarBefore": f"0x{pciexbar_before:08x}",
            "pciexbarAfter": f"0x{pciexbar_after:08x}",
            "rootVendor": f"0x{root_vendor:04x}",
            "rootDevice": f"0x{root_device_id:04x}",
            "rootBusNumbersBefore": f"0x{bus_numbers_before:08x}",
            "rootBusNumbersAfter": f"0x{bus_numbers_after:08x}",
            "pfVendor": f"0x{pf_vendor:04x}",
            "pfDevice": f"0x{pf_device_id:04x}",
            "sriovOffset": f"0x{sriov:03x}",
            "capabilityChain": capability_chain,
            "totalVfs": total_vfs,
            "controlBefore": f"0x{control_before:04x}",
            "controlAfter": f"0x{control_after:04x}",
            "numVfsAfter": num_vfs_after,
        },
        "monitor": {
            "statusBefore": status_before,
            "continue": continue_output,
            "statusAfter": status_after,
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
