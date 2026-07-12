#!/usr/bin/env python3
import argparse
import atexit
import json
import os
import re
import shutil
import ssl
from datetime import datetime, timezone
from pathlib import Path

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

import test_esxi_vmotion_matrix as lab


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vcenter", default="192.168.91.131")
    parser.add_argument("--host", default="172.31.91.11")
    parser.add_argument("--vcsa-caveat", default="vcsa803-codex-credentials")
    parser.add_argument("--datacenter", default="PCI-Lab")
    parser.add_argument("--cluster", default="PCI-DirectPath-Lab")
    parser.add_argument("--datastore", default="qemu-shared")
    parser.add_argument("--nfs-root", default="/root/vm/esxi8-mf/nfsds")
    parser.add_argument("--iso", default="esxi-l3-reboot-probe.iso")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        os.environ.pop(name, None)
    os.environ["NO_PROXY"] = ",".join((args.vcenter, args.host))

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    result_path = output_dir / "result.json"
    run_id = output_dir.name
    result = {"runId": run_id, "case": "R01-guest-reboot-after-traffic", "startedAt": utc_now(), "verdict": "running"}

    def save():
        result_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    save()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        service_instance = SmartConnect(
            host=args.vcenter,
            user=lab.caveat_field(args.vcsa_caveat, "SSO Username"),
            pwd=lab.caveat_field(args.vcsa_caveat, "SSO Password"),
            sslContext=context,
        )
        atexit.register(Disconnect, service_instance)
        content = service_instance.RetrieveContent()
        datacenter = next(
            item for item in content.rootFolder.childEntity
            if isinstance(item, vim.Datacenter) and item.name == args.datacenter
        )
        cluster = next(
            item for item in datacenter.hostFolder.childEntity
            if isinstance(item, vim.ClusterComputeResource) and item.name == args.cluster
        )
        host = next(
            item for item in lab.inventory(content, vim.HostSystem)
            if item.name == args.host
        )
        if host.runtime.connectionState != vim.HostSystem.ConnectionState.connected:
            raise RuntimeError(f"Host {args.host} is not connected")

        matching_ids = {
            item.id for item in host.hardware.pciDevice
            if (item.vendorId & 0xFFFF, item.deviceId & 0xFFFF) == (0x8086, 0x10D3)
        }
        candidates = sorted(
            item.id for item in host.config.pciPassthruInfo
            if item.passthruActive and item.id in matching_ids
        )
        result["host"] = {
            "product": host.config.product.fullName,
            "activeCandidates": candidates,
        }
        if not candidates:
            raise RuntimeError("No active e1000e Dynamic DirectPath candidate")

        relative_root = f"guest-reboot/{run_id}"
        vm_name = f"guest-reboot-{run_id}"
        vm_root = Path(args.nfs_root) / relative_root / vm_name
        serial_path = vm_root / "guest-serial.log"
        existing = [
            vm for vm in lab.inventory(content, vim.VirtualMachine)
            if vm.name == vm_name
        ]
        if existing:
            vm = existing[0]
            lab.power_off(vm)
        else:
            vmx_path = lab.write_vmx(
                vm_root,
                vm_name,
                f"/vmfs/volumes/{args.datastore}/iso/{args.iso}",
            )
            vm = lab.register_vm(
                datacenter,
                cluster,
                host,
                args.datastore,
                f"{relative_root}/{vm_name}/{vmx_path.name}",
                vm_name,
            )
            lab.add_dynamic_devices(vm, 1)
    except Exception as error:
        result["verdict"] = "fail"
        result["fault"] = lab.fault_snapshot(error)
        result["finishedAt"] = utc_now()
        save()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        raise SystemExit(1)

    try:
        if serial_path.exists():
            serial_path.unlink()
        lab.wait_task(vm.PowerOnVM_Task(host=host))
        lab.wait_power_state(vm, vim.VirtualMachinePowerState.poweredOn)
        result["poweredOn"] = lab.vm_snapshot(vm)
        save()
        lab.wait_serial_marker(serial_path, "R01-REBOOT-COMPLETE", timeout=600)
        text = serial_path.read_text(encoding="utf-8", errors="replace")
        shutil.copyfile(serial_path, output_dir / "guest-serial.log")
        traffic = [
            {"phase": phase, "rx": int(rx), "tx": int(tx)}
            for phase, rx, tx in re.findall(r"R01-TRAFFIC phase=(first|second).*?rx=(\d+) tx=(\d+)", text)
        ]
        result["guest"] = {
            "firstPhase": "R01-PHASE=first" in text,
            "secondPhase": "R01-PHASE=second" in text,
            "rebootMarker": "R01-REBOOTING" in text,
            "completeMarker": "R01-REBOOT-COMPLETE" in text,
            "traffic": traffic,
        }
        vmware_log = vm_root / "vmware.log"
        if vmware_log.exists():
            shutil.copyfile(vmware_log, output_dir / "vmware.log")
        result["verdict"] = "pass" if (
            result["guest"]["firstPhase"]
            and result["guest"]["secondPhase"]
            and result["guest"]["rebootMarker"]
            and result["guest"]["completeMarker"]
            and {item["phase"] for item in traffic} == {"first", "second"}
            and all(item["tx"] > 0 for item in traffic)
        ) else "fail"
    except Exception as error:
        result["verdict"] = "fail"
        result["fault"] = lab.fault_snapshot(error)
    finally:
        try:
            lab.power_off(vm)
        except Exception as error:
            result["cleanupFault"] = lab.fault_snapshot(error)
        result["poweredOffFinal"] = lab.vm_snapshot(vm)
        result["finishedAt"] = utc_now()
        save()

    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
