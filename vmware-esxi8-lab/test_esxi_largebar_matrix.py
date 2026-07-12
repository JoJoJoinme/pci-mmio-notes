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
from test_esxi_dynamic_bar_envelope import qemu_command_line, qemu_hmp_info_pci


VENDOR_ID = 0x1B36
DEVICE_ID = 0x0005
DEFAULT_CASES = (
    "absent",
    "false",
    "size-only",
    "false-size",
    "true-only",
    "true-size",
    "true-undersized",
)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def case_config(name, bar_size_gb):
    if name not in DEFAULT_CASES:
        raise ValueError(f"Unsupported case {name!r}")
    use64 = None
    size = None
    if name == "false":
        use64 = False
    elif name == "size-only":
        size = bar_size_gb
    elif name == "false-size":
        use64 = False
        size = bar_size_gb
    elif name == "true-only":
        use64 = True
    elif name == "true-size":
        use64 = True
        size = bar_size_gb
    elif name == "true-undersized":
        use64 = True
        size = bar_size_gb // 2

    expected = "mapping-pass"
    if name in {"absent", "false", "size-only", "false-size", "true-undersized"}:
        expected = "power-on-fail"
    elif name == "true-only" and bar_size_gb > 32:
        expected = "power-on-fail"
    return {"use64bitMmio": use64, "sizeGb": size, "expected": expected}


def vmx_mmio_lines(config):
    lines = []
    if config["use64bitMmio"] is not None:
        value = "TRUE" if config["use64bitMmio"] else "FALSE"
        lines.append(f'pciPassthru.use64bitMMIO = "{value}"')
    if config["sizeGb"] is not None:
        lines.append(f'pciPassthru.64bitMMIOSizeGB = "{config["sizeGb"]}"')
    return lines


def interesting_vmx_log(path):
    if not path.exists():
        return []
    pattern = re.compile(
        r"PCIPassthru|64bitMMIO|pages needed|IOMMU mappings|RootBridge|DevicePowerOn",
        re.IGNORECASE,
    )
    return [
        line
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if pattern.search(line)
    ][-400:]


def copy_if_present(source, destination):
    if source.exists():
        shutil.copyfile(source, destination)
        return True
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vcenter", default="192.168.91.131")
    parser.add_argument("--host", default="172.31.91.10")
    parser.add_argument("--vcsa-caveat", default="vcsa803-codex-credentials")
    parser.add_argument("--datacenter", default="PCI-Lab")
    parser.add_argument("--cluster", default="PCI-DirectPath-Lab")
    parser.add_argument("--datastore", default="qemu-shared")
    parser.add_argument("--nfs-root", default="/root/vm/esxi8-mf/nfsds")
    parser.add_argument("--qemu-name", default="esxi8-a")
    parser.add_argument("--qemu-monitor", default="/root/vm/esxi8-mf/monitor.sock")
    parser.add_argument("--bdf", default="0000:01:01.0")
    parser.add_argument("--bar-size-gb", type=int, required=True, choices=(32, 64))
    parser.add_argument("--cases", nargs="+", default=list(DEFAULT_CASES))
    parser.add_argument("--power-timeout", type=int, default=300)
    parser.add_argument("--serial-timeout", type=int, default=120)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    unknown = sorted(set(args.cases) - set(DEFAULT_CASES))
    if unknown:
        parser.error(f"unsupported cases: {', '.join(unknown)}")

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
    result = {
        "runId": output_dir.name,
        "case": "M04-pci-testdev-large-BAR-matrix",
        "startedAt": utc_now(),
        "input": {
            "barSizeGb": args.bar_size_gb,
            "bdf": args.bdf,
            "candidate": {"vendorId": VENDOR_ID, "deviceId": DEVICE_ID},
            "cases": args.cases,
        },
        "outerQemu": {
            "command": qemu_command_line(args.qemu_name),
            "infoPci": qemu_hmp_info_pci(args.qemu_monitor),
        },
        "cases": {},
        "verdict": "running",
    }

    def save():
        result_path.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    save()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    service_instance = None
    try:
        service_instance = SmartConnect(
            host=args.vcenter,
            user=lab.caveat_field(args.vcsa_caveat, "SSO Username"),
            pwd=lab.caveat_field(args.vcsa_caveat, "SSO Password"),
            sslContext=context,
        )
        atexit.register(Disconnect, service_instance)
        content = service_instance.RetrieveContent()
        datacenter = lab.ensure_datacenter(content, args.datacenter)
        cluster = next(
            item
            for item in datacenter.hostFolder.childEntity
            if isinstance(item, vim.ClusterComputeResource) and item.name == args.cluster
        )
        host = next(
            item for item in lab.inventory(content, vim.HostSystem) if item.name == args.host
        )
        if host.runtime.connectionState != vim.HostSystem.ConnectionState.connected:
            raise RuntimeError(f"Host {args.host} is not connected")

        devices = [item for item in host.hardware.pciDevice if item.id == args.bdf]
        if len(devices) != 1:
            raise RuntimeError(f"Expected one PCI device {args.bdf}, found {len(devices)}")
        device = devices[0]
        identity = (device.vendorId & 0xFFFF, device.deviceId & 0xFFFF)
        if identity != (VENDOR_ID, DEVICE_ID):
            raise RuntimeError(
                f"{args.bdf} is {identity[0]:04x}:{identity[1]:04x}, expected 1b36:0005"
            )
        passthrough = next(
            item for item in host.config.pciPassthruInfo if item.id == args.bdf
        )
        if not passthrough.passthruActive:
            raise RuntimeError(f"PCI device {args.bdf} is not active for passthrough")
        result["host"] = {
            "product": host.config.product.fullName,
            "connectionState": str(host.runtime.connectionState),
            "inMaintenanceMode": host.runtime.inMaintenanceMode,
            "device": {
                "id": device.id,
                "vendorId": identity[0],
                "deviceId": identity[1],
                "deviceName": device.deviceName,
                "passthruActive": passthrough.passthruActive,
            },
        }
        if host.runtime.inMaintenanceMode:
            raise RuntimeError(f"Host {args.host} is still in maintenance mode in vCenter")
        save()
    except Exception as error:
        result["verdict"] = "fail-preflight"
        result["fault"] = lab.fault_snapshot(error)
        result["finishedAt"] = utc_now()
        save()
        print(json.dumps(result, indent=2, ensure_ascii=False))
        raise SystemExit(1)

    for case_name in args.cases:
        config = case_config(case_name, args.bar_size_gb)
        case_result = {
            "config": config,
            "startedAt": utc_now(),
            "outcome": "running",
        }
        result["cases"][case_name] = case_result
        save()

        case_dir = output_dir / case_name
        case_dir.mkdir(parents=True, exist_ok=True)
        relative_root = f"largebar/{output_dir.name}/{case_name}"
        vm_name = f"largebar-{args.bar_size_gb}g-{output_dir.name}-{case_name}"
        vm_root = Path(args.nfs_root) / relative_root / vm_name
        serial_path = vm_root / "guest-serial.log"
        vmware_log = vm_root / "vmware.log"
        vm = None
        try:
            case_result["stage"] = "inventory-existing-vm"
            existing = [
                item for item in lab.inventory(content, vim.VirtualMachine) if item.name == vm_name
            ]
            if existing:
                vm = existing[0]
                case_result["stage"] = "cleanup-existing-vm"
                lab.power_off(vm)
                vm.UnregisterVM()

            case_result["stage"] = "write-vmx"
            extra_lines = lab.static_pci_lines(host, args.bdf)
            extra_lines.extend(vmx_mmio_lines(config))
            vmx_path = lab.write_vmx(
                vm_root,
                vm_name,
                f"/vmfs/volumes/{args.datastore}/iso/esxi-l3-largebar-probe.iso",
                extra_lines=extra_lines,
            )
            case_result["stage"] = "register-vm"
            vm = lab.register_vm(
                datacenter,
                cluster,
                host,
                args.datastore,
                f"{relative_root}/{vm_name}/{vmx_path.name}",
                vm_name,
            )
            case_result["configured"] = lab.vm_snapshot(vm)
            case_result["effectiveInputVmx"] = vmx_path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()

            if serial_path.exists():
                serial_path.unlink()
            case_result["stage"] = "power-on"
            task = vm.PowerOnVM_Task(host=host)
            try:
                lab.wait_task(task, timeout=args.power_timeout)
                lab.wait_power_state(vm, vim.VirtualMachinePowerState.poweredOn)
                case_result["poweredOn"] = lab.vm_snapshot(vm)
            except Exception as error:
                case_result["outcome"] = "power-on-fail"
                case_result["fault"] = lab.fault_snapshot(error)
            else:
                try:
                    lab.wait_serial_marker(
                        serial_path, "VMOTION-HEARTBEAT", timeout=args.serial_timeout
                    )
                    case_result["outcome"] = "guest-pass"
                except Exception as error:
                    case_result["outcome"] = "power-on-pass-guest-timeout"
                    case_result["guestFault"] = lab.fault_snapshot(error)

            copy_if_present(serial_path, case_dir / "guest-serial.log")
            copy_if_present(vmware_log, case_dir / "vmware.log")
            copy_if_present(vm_root / f"{vm_name}.vmx", case_dir / "effective.vmx")
            if serial_path.exists():
                serial_text = serial_path.read_text(encoding="utf-8", errors="replace")
                case_result["guest"] = {
                    "heartbeat": "VMOTION-HEARTBEAT" in serial_text,
                    "targetVisible": "vendor=0x1b36 device=0x0005" in serial_text,
                    "selectedLines": [
                        line
                        for line in serial_text.splitlines()
                        if "DirectPath target" in line
                        or "root bus resource" in line
                        or "0x000000" in line
                    ][-200:],
                }
            case_result["vmxLogExcerpt"] = interesting_vmx_log(vmware_log)
            mapping_created = any(
                "successfully created the IOMMU mappings" in line
                for line in case_result["vmxLogExcerpt"]
            )
            case_result["mappingCreated"] = mapping_created
            if case_result["outcome"] == "power-on-pass-guest-timeout" and mapping_created:
                case_result["outcome"] = "mapping-pass-guest-timeout"
            if config["expected"] == "mapping-pass":
                case_result["matchesExpected"] = case_result["outcome"] in {
                    "guest-pass",
                    "mapping-pass-guest-timeout",
                }
            else:
                case_result["matchesExpected"] = case_result["outcome"] == config["expected"]
            case_result["stage"] = "complete"
        except Exception as error:
            case_result["outcome"] = "runner-fail"
            case_result["fault"] = lab.fault_snapshot(error)
            case_result["matchesExpected"] = False
        finally:
            if vm is not None:
                try:
                    lab.power_off(vm)
                    case_result["poweredOffFinal"] = lab.vm_snapshot(vm)
                except Exception as error:
                    case_result["cleanupFault"] = lab.fault_snapshot(error)
                try:
                    vm.UnregisterVM()
                except Exception as error:
                    case_result["unregisterFault"] = lab.fault_snapshot(error)
            case_result["finishedAt"] = utc_now()
            save()

    result["verdict"] = (
        "pass"
        if result["cases"]
        and all(item.get("matchesExpected") for item in result["cases"].values())
        else "fail"
    )
    result["finishedAt"] = utc_now()
    save()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
