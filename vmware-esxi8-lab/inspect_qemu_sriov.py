#!/usr/bin/env python3
"""Capture the live raw PF/VF config surface from a QEMU qtest socket."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from enable_qemu_sriov_preboot import (
    find_extended_capability,
    hmp_command,
    parse_bdf,
    wait_path,
)
from test_qemu_sriov_smoke import (
    PCI_EXT_CAP_ID_SRIOV,
    QTestClient,
    config_read16,
    enable_q35_ecam,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qtest", required=True)
    parser.add_argument("--monitor", required=True)
    parser.add_argument("--pf", default="0000:02:00.0")
    parser.add_argument("--vf", default="0000:02:00.1")
    parser.add_argument("--expect-vf-visible", action="store_true")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    qtest_path = Path(args.qtest)
    monitor_path = Path(args.monitor)
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    wait_path(qtest_path)
    wait_path(monitor_path)

    pf_bus, pf_device, pf_function = parse_bdf(args.pf)
    vf_bus, vf_device, vf_function = parse_bdf(args.vf)
    client = QTestClient(qtest_path)
    try:
        pciexbar_before, pciexbar_after = enable_q35_ecam(client)
        pf_vendor = config_read16(client, pf_bus, pf_device, pf_function, 0x00)
        pf_device_id = config_read16(
            client, pf_bus, pf_device, pf_function, 0x02
        )
        sriov, chain = find_extended_capability(
            client,
            pf_bus,
            pf_device,
            pf_function,
            PCI_EXT_CAP_ID_SRIOV,
        )
        if sriov is None:
            raise RuntimeError("PF SR-IOV capability not found")
        control = config_read16(
            client, pf_bus, pf_device, pf_function, sriov + 0x08
        )
        total_vfs = config_read16(
            client, pf_bus, pf_device, pf_function, sriov + 0x0E
        )
        num_vfs = config_read16(
            client, pf_bus, pf_device, pf_function, sriov + 0x10
        )
        vf_vendor = config_read16(client, vf_bus, vf_device, vf_function, 0x00)
        vf_device_id = config_read16(
            client, vf_bus, vf_device, vf_function, 0x02
        )
    finally:
        client.close()

    vf_visible = vf_vendor not in (0, 0xFFFF)
    checks = {
        "q35EcamEnabled": bool(pciexbar_after & 1),
        "pfPresent": pf_vendor not in (0, 0xFFFF),
        "sriovCapabilityPresent": sriov >= 0x100,
        "vfEnableLatched": bool(control & 1),
        "numVfsNonzero": num_vfs > 0,
        "vfVisibilityMatchesExpectation": (
            vf_visible if args.expect_vf_visible else not vf_visible
        ),
    }
    result = {
        "case": "QEMU-SR-IOV-live-raw-config",
        "input": {
            "pf": args.pf,
            "vf": args.vf,
            "expectVfVisible": args.expect_vf_visible,
        },
        "config": {
            "pciexbarBefore": f"0x{pciexbar_before:08x}",
            "pciexbarAfter": f"0x{pciexbar_after:08x}",
            "pfVendor": f"0x{pf_vendor:04x}",
            "pfDevice": f"0x{pf_device_id:04x}",
            "sriovOffset": f"0x{sriov:03x}",
            "capabilityChain": chain,
            "control": f"0x{control:04x}",
            "totalVfs": total_vfs,
            "numVfs": num_vfs,
            "vfVendor": f"0x{vf_vendor:04x}",
            "vfDevice": f"0x{vf_device_id:04x}",
        },
        "monitor": {"infoPci": hmp_command(monitor_path, "info pci")},
        "checks": checks,
        "verdict": "pass" if all(checks.values()) else "fail",
    }
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    (output / "result.json").write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
