#!/usr/bin/env python3
import argparse
import atexit
import json
import os
import re
import shutil
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

import test_esxi_vmotion_matrix as lab


def qemu_command_line(name: str):
    for process_dir in Path("/proc").iterdir():
        if not process_dir.name.isdigit():
            continue
        try:
            arguments = (process_dir / "cmdline").read_bytes().split(b"\0")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        decoded = [value.decode("utf-8", errors="replace") for value in arguments if value]
        if decoded and "qemu-system" in decoded[0] and name in decoded:
            return {"pid": int(process_dir.name), "argv": decoded}
    raise RuntimeError(f"Could not find outer QEMU process {name!r}")


def qemu_hmp_info_pci(monitor_path: str):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(3)
        stream.connect(monitor_path)
        time.sleep(0.1)
        try:
            stream.recv(65536)
        except TimeoutError:
            pass
        stream.sendall(b"info pci\n")
        time.sleep(0.5)
        chunks = []
        while True:
            try:
                chunks.append(stream.recv(65536))
            except TimeoutError:
                break
            if chunks and chunks[-1].endswith(b"(qemu) "):
                break
    text = b"".join(chunks).decode("utf-8", errors="replace")
    return re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", text)


def serial_summary(path: Path):
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    selected = []
    include_resources = 0
    for line in lines:
        if "root bus resource" in line or "bridge window" in line:
            selected.append(line)
        if line.startswith("--- DirectPath target"):
            selected.append(line)
            include_resources = 8
            continue
        if include_resources:
            if line.startswith("0x"):
                selected.append(line)
            include_resources -= 1
    return {
        "heartbeat": "VMOTION-HEARTBEAT" in text,
        "selectedAddressLines": selected,
        "bytes": len(text.encode("utf-8")),
    }


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
        "input": {
            "policy": "no pciPassthru.use64bitMMIO or 64bitMMIOSizeGB keys",
            "candidateClass": {"vendorId": 0x1AF4, "deviceId": 0x1110},
            "topology": "candidates behind independent PCIe root ports",
            "expectedOuterDevices": {
                "0000:01:01.0": "1G test_ivshmem",
                "0000:02:00.0": "2G test_ivshmem_alt",
            },
        },
        "outerQemu": {
            "command": qemu_command_line(args.qemu_name),
            "infoPci": qemu_hmp_info_pci(args.qemu_monitor),
        },
        "cases": {},
    }

    def save():
        result_path.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
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
        raise RuntimeError(f"Expected one cluster {args.cluster!r}, found {len(clusters)}")
    cluster = clusters[0]
    hosts = [item for item in lab.inventory(content, vim.HostSystem) if item.name == args.host]
    if len(hosts) != 1:
        raise RuntimeError(f"Expected one host {args.host!r}, found {len(hosts)}")
    host = hosts[0]
    if host.runtime.connectionState != vim.HostSystem.ConnectionState.connected:
        raise RuntimeError(f"Host {args.host} is not connected")

    candidate_devices = [
        {
            "id": item.id,
            "vendorId": item.vendorId & 0xFFFF,
            "deviceId": item.deviceId & 0xFFFF,
            "deviceName": item.deviceName,
        }
        for item in host.hardware.pciDevice
        if (item.vendorId & 0xFFFF, item.deviceId & 0xFFFF) == (0x1AF4, 0x1110)
    ]
    passthrough = [
        {
            "id": item.id,
            "passthruEnabled": item.passthruEnabled,
            "passthruActive": item.passthruActive,
        }
        for item in host.config.pciPassthruInfo
        if item.id in {device["id"] for device in candidate_devices}
    ]
    result["host"] = {
        "name": host.name,
        "product": host.config.product.fullName,
        "uuid": host.hardware.systemInfo.uuid,
        "candidateDevices": candidate_devices,
        "passthrough": passthrough,
        "dynamicClasses": [
            {
                "vendorId": item.vendorId,
                "deviceId": item.deviceId,
                "vendorName": item.vendorName,
                "deviceName": item.deviceName,
            }
            for item in host.configManager.assignableHardwareManager.RetrieveDynamicPassthroughInfo()
        ],
    }
    if len(candidate_devices) != 2 or not all(item["passthruActive"] for item in passthrough):
        raise RuntimeError("The two heterogeneous ivshmem candidates are not both active")
    save()

    relative_root = f"dynamic-envelope/{run_id}"
    vm_root = Path(args.nfs_root) / relative_root
    iso_path = f"/vmfs/volumes/{args.datastore}/iso/esxi-l3-vmotion-probe.iso"
    names = {
        "target": f"dynamic-envelope-target-{run_id}",
        "blocker": f"dynamic-envelope-blocker-{run_id}",
    }
    existing = {vm.name: vm for vm in lab.inventory(content, vim.VirtualMachine)}
    vms = {}
    for role, name in names.items():
        if name in existing:
            vms[role] = existing[name]
            continue
        vmx_path = lab.write_vmx(vm_root / name, name, iso_path)
        vm = lab.register_vm(
            datacenter,
            cluster,
            host,
            args.datastore,
            f"{relative_root}/{name}/{vmx_path.name}",
            name,
        )
        lab.add_dynamic_devices(
            vm,
            1,
            vendor_id=0x1AF4,
            device_id=0x1110,
            label_prefix="Dynamic heterogeneous ivshmem",
        )
        vms[role] = vm

    target = vms["target"]
    blocker = vms["blocker"]
    target_serial = vm_root / names["target"] / "guest-serial.log"
    blocker_serial = vm_root / names["blocker"] / "guest-serial.log"
    try:
        lab.power_off(target)
        lab.power_off(blocker)

        lab.power_on(target, host, target_serial, marker_timeout=600)
        alone_serial = output_dir / "target-alone-serial.log"
        shutil.copyfile(target_serial, alone_serial)
        result["cases"]["X01-target-alone"] = {
            "runtime": lab.vm_snapshot(target),
            "serial": alone_serial.name,
            "guest": serial_summary(alone_serial),
        }
        lab.power_off(target)
        save()

        lab.power_on(blocker, host)
        result["cases"]["X01-blocker"] = {"runtime": lab.vm_snapshot(blocker)}
        lab.power_on(target, host, target_serial, marker_timeout=600)
        constrained_serial = output_dir / "target-constrained-serial.log"
        shutil.copyfile(target_serial, constrained_serial)
        result["cases"]["X01-target-with-blocker"] = {
            "runtime": lab.vm_snapshot(target),
            "serial": constrained_serial.name,
            "guest": serial_summary(constrained_serial),
        }

        alone_id = result["cases"]["X01-target-alone"]["runtime"]["devices"][0]["assignedId"]
        blocker_id = result["cases"]["X01-blocker"]["runtime"]["devices"][0]["assignedId"]
        constrained_id = result["cases"]["X01-target-with-blocker"]["runtime"]["devices"][0]["assignedId"]
        result["verdict"] = (
            "pass"
            if alone_id == blocker_id
            and constrained_id != blocker_id
            and result["cases"]["X01-target-alone"]["guest"]["heartbeat"]
            and result["cases"]["X01-target-with-blocker"]["guest"]["heartbeat"]
            else "fail"
        )
    except Exception as error:
        result["verdict"] = "fail"
        result["fault"] = lab.fault_snapshot(error)
    finally:
        lab.power_off(target)
        lab.power_off(blocker)

    result["finishedAt"] = datetime.now(timezone.utc).isoformat()
    save()
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
