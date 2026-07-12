#!/usr/bin/env python3
import argparse
import atexit
import json
import os
import shutil
import ssl
from datetime import datetime, timezone
from pathlib import Path

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

import test_esxi_vmotion_matrix as lab
from test_esxi_dynamic_bar_envelope import (
    qemu_command_line,
    qemu_hmp_info_pci,
    serial_summary,
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vcenter", default="192.168.91.131")
    parser.add_argument("--host", default="172.31.91.11")
    parser.add_argument("--vcsa-caveat", default="vcsa803-codex-credentials")
    parser.add_argument("--datacenter", default="PCI-Lab")
    parser.add_argument("--cluster", default="PCI-DirectPath-Lab")
    parser.add_argument("--datastore", default="qemu-shared")
    parser.add_argument("--nfs-root", default="/root/vm/esxi8-mf/nfsds")
    parser.add_argument("--qemu-name", default="esxi8-b")
    parser.add_argument("--qemu-monitor", default="/root/vm/esxi8-b/monitor.sock")
    parser.add_argument("--requested-devices", type=int, default=2)
    parser.add_argument(
        "--use64bit-mmio", choices=("absent", "true", "false"), default="absent"
    )
    parser.add_argument("--size-gb", type=int)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        os.environ.pop(name, None)
    os.environ["NO_PROXY"] = ",".join((args.vcenter, args.host))

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    result_path = output_dir / "result.json"
    run_id = output_dir.name
    result = {
        "runId": run_id,
        "startedAt": datetime.now(timezone.utc).isoformat(),
        "case": "M07-Dynamic-BAR-aggregate",
        "input": {
            "candidateClass": {"vendorId": 0x1AF4, "deviceId": 0x1110},
            "requestedDevices": args.requested_devices,
            "use64bitMmio": args.use64bit_mmio,
            "sizeGb": args.size_gb,
        },
        "outerQemu": {
            "command": qemu_command_line(args.qemu_name),
            "infoPci": qemu_hmp_info_pci(args.qemu_monitor),
        },
    }

    def save():
        result_path.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    service_instance = SmartConnect(
        host=args.vcenter,
        user=lab.caveat_field(args.vcsa_caveat, "SSO Username"),
        pwd=lab.caveat_field(args.vcsa_caveat, "SSO Password"),
        sslContext=context,
    )
    atexit.register(Disconnect, service_instance)
    content = service_instance.RetrieveContent()
    datacenter = lab.ensure_datacenter(content, args.datacenter)
    clusters = [
        item
        for item in datacenter.hostFolder.childEntity
        if isinstance(item, vim.ClusterComputeResource) and item.name == args.cluster
    ]
    if len(clusters) != 1:
        raise RuntimeError(f"Expected one cluster {args.cluster!r}")
    cluster = clusters[0]
    hosts = [item for item in lab.inventory(content, vim.HostSystem) if item.name == args.host]
    if len(hosts) != 1:
        raise RuntimeError(f"Expected one host {args.host!r}")
    host = hosts[0]
    if host.runtime.connectionState != vim.HostSystem.ConnectionState.connected:
        raise RuntimeError(f"Host {args.host} is not connected")

    candidates = sorted(
        item.id
        for item in host.hardware.pciDevice
        if (item.vendorId & 0xFFFF, item.deviceId & 0xFFFF) == (0x1AF4, 0x1110)
    )
    active = sorted(
        item.id
        for item in host.config.pciPassthruInfo
        if item.id in candidates and item.passthruActive
    )
    result["host"] = {
        "product": host.config.product.fullName,
        "candidates": candidates,
        "active": active,
    }
    if len(candidates) != args.requested_devices or active != candidates:
        raise RuntimeError(
            f"Expected exactly {args.requested_devices} active candidate(s)"
        )

    relative_root = f"dynamic-aggregate/{run_id}"
    vm_name = f"dynamic-aggregate-{run_id}"
    vm_root = Path(args.nfs_root) / relative_root / vm_name
    serial_path = vm_root / "guest-serial.log"
    existing = [vm for vm in lab.inventory(content, vim.VirtualMachine) if vm.name == vm_name]
    if existing:
        vm = existing[0]
    else:
        vmx_path = lab.write_vmx(
            vm_root,
            vm_name,
            f"/vmfs/volumes/{args.datastore}/iso/esxi-l3-vmotion-probe.iso",
        )
        vm = lab.register_vm(
            datacenter,
            cluster,
            host,
            args.datastore,
            f"{relative_root}/{vm_name}/{vmx_path.name}",
            vm_name,
        )
        lab.add_dynamic_devices(
            vm,
            args.requested_devices,
            vendor_id=0x1AF4,
            device_id=0x1110,
            label_prefix="Dynamic aggregate ivshmem",
        )

    extra_config = []
    if args.use64bit_mmio != "absent":
        extra_config.append(
            vim.option.OptionValue(
                key="pciPassthru.use64bitMMIO",
                value=args.use64bit_mmio.upper(),
            )
        )
    if args.size_gb is not None:
        extra_config.append(
            vim.option.OptionValue(
                key="pciPassthru.64bitMMIOSizeGB", value=str(args.size_gb)
            )
        )
    if extra_config:
        lab.wait_task(vm.ReconfigVM_Task(vim.vm.ConfigSpec(extraConfig=extra_config)))

    try:
        lab.power_off(vm)
        vmx_text = (vm_root / f"{vm_name}.vmx").read_text(
            encoding="utf-8", errors="replace"
        )
        result["persistentMmioKeys"] = [
            line
            for line in vmx_text.splitlines()
            if "use64bitMMIO" in line or "64bitMMIOSizeGB" in line
        ]
        lab.power_on(vm, host, serial_path, marker_timeout=600)
        serial_copy = output_dir / "guest-serial.log"
        shutil.copyfile(serial_path, serial_copy)
        snapshot = lab.vm_snapshot(vm)
        result["runtime"] = snapshot
        result["guest"] = serial_summary(serial_copy)
        result["guest"]["targetCount"] = serial_copy.read_text(
            encoding="utf-8", errors="replace"
        ).count("--- DirectPath target")
        assigned = sorted(
            item["assignedId"] for item in snapshot["devices"] if item["assignedId"]
        )
        keys_expected = args.use64bit_mmio != "absent" or args.size_gb is not None
        result["verdict"] = (
            "pass"
            if assigned == candidates
            and bool(result["persistentMmioKeys"]) == keys_expected
            and result["guest"]["heartbeat"]
            and result["guest"]["targetCount"] == args.requested_devices
            else "fail"
        )
    except Exception as error:
        result["verdict"] = "fail"
        result["fault"] = lab.fault_snapshot(error)
    finally:
        lab.power_off(vm)
        result["poweredOffFinal"] = lab.vm_snapshot(vm)
        result["finishedAt"] = datetime.now(timezone.utc).isoformat()
        save()

    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
