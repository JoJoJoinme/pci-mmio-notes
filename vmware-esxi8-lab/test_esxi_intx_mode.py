#!/usr/bin/env python3
import argparse
import atexit
import json
import os
import re
import shutil
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

import test_esxi_vmotion_matrix as lab


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vcenter", default="192.168.91.131")
    parser.add_argument("--host", default="172.31.91.11")
    parser.add_argument("--vcsa-caveat", default="vcsa803-codex-credentials")
    parser.add_argument("--datacenter", default="PCI-Lab")
    parser.add_argument("--cluster", default="PCI-DirectPath-Lab")
    parser.add_argument("--datastore", default="qemu-shared")
    parser.add_argument("--nfs-root", default="/root/vm/esxi8-mf/nfsds")
    parser.add_argument("--iso", default="esxi-l3-intx-probe.iso")
    parser.add_argument("--settle-seconds", type=int, default=60)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        os.environ.pop(name, None)
    os.environ["NO_PROXY"] = ",".join((args.vcenter, args.host))

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    result_path = output_dir / "result.json"
    run_id = output_dir.name
    result = {"runId": run_id, "case": "I01-INTx-forced-with-pci-nomsi", "startedAt": datetime.now(timezone.utc).isoformat(), "verdict": "running"}

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

        relative_root = f"interrupt-mode/{run_id}"
        vm_name = f"interrupt-mode-{run_id}"
        vm_root = Path(args.nfs_root) / relative_root / vm_name
        serial_path = vm_root / "guest-serial.log"
        existing = [
            vm for vm in lab.inventory(content, vim.VirtualMachine)
            if vm.name == vm_name
        ]
        if existing:
            vm = existing[0]
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
        result["finishedAt"] = datetime.now(timezone.utc).isoformat()
        save()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        raise SystemExit(1)

    try:
        lab.power_off(vm)
        lab.power_on(vm, host, serial_path, marker_timeout=300)
        time.sleep(args.settle_seconds)
        text = serial_path.read_text(encoding="utf-8", errors="replace")
        shutil.copyfile(serial_path, output_dir / "guest-serial.log")
        interrupt_lines = [line for line in text.splitlines() if "e1000e" in line or re.search(r"\beth\d+\b", line)]
        traffic = [(int(rx), int(tx)) for rx, tx in re.findall(r"DMA-TRAFFIC .*?rx=(\d+) tx=(\d+)", text)]
        result["runtime"] = lab.vm_snapshot(vm)
        result["guest"] = {
            "cmdlineHasPciNomsi": "pci=nomsi" in text,
            "msixDisabled": "MSI-X: Enable-" in text,
            "msiDisabled": "MSI: Enable-" in text,
            "interruptLines": interrupt_lines,
            "traffic": [{"rx": rx, "tx": tx} for rx, tx in traffic],
        }
        result["verdict"] = "pass" if (
            result["guest"]["cmdlineHasPciNomsi"]
            and result["guest"]["msixDisabled"]
            and result["guest"]["msiDisabled"]
            and interrupt_lines
            and traffic
            and max(tx for _, tx in traffic) > 0
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
        result["finishedAt"] = datetime.now(timezone.utc).isoformat()
        save()

    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
