#!/usr/bin/env python3
"""Run the large-BAR DirectPath matrix against one standalone ESXi host."""

from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import shutil
import ssl
import time
from pathlib import Path
from typing import Any

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

import test_esxi_vmotion_matrix as lab
from esxi_passthru_capability import (
    EsxiSsh,
    caveat_field,
    ensure_nfs_datastore,
    utc_now,
    wait_for_esxi,
)
from test_esxi_dynamic_bar_envelope import qemu_command_line, qemu_hmp_info_pci
from test_esxi_largebar_matrix import (
    DEFAULT_CASES,
    DEVICE_ID,
    VENDOR_ID,
    bounded_vm_name,
    case_config,
    copy_if_present,
    interesting_vmx_log,
    vmx_mmio_lines,
)


def save(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def direct_host(content) -> vim.HostSystem:
    hosts = lab.inventory(content, vim.HostSystem)
    if len(hosts) != 1:
        raise RuntimeError(f"expected one standalone ESXi host, found {len(hosts)}")
    return hosts[0]


def wait_vm(content, name: str, timeout: int = 60) -> vim.VirtualMachine:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        matches = [vm for vm in lab.inventory(content, vim.VirtualMachine) if vm.name == name]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise RuntimeError(f"multiple registered VMs named {name!r}")
        time.sleep(1)
    raise TimeoutError(f"registered VM {name!r} did not appear in direct ESXi inventory")


def command_snapshot(process) -> dict[str, Any]:
    return {
        "returnCode": process.returncode,
        "stdout": process.stdout.splitlines(),
        "stderr": process.stderr.splitlines(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="172.31.91.10")
    parser.add_argument("--user", default="root")
    parser.add_argument("--caveat", default="esxi8-auto-codex-credentials")
    parser.add_argument("--datastore", default="qemu-shared")
    parser.add_argument("--nfs-root", default="/root/vm/esxi8-mf/nfsds")
    parser.add_argument(
        "--iso", default="/mnt/e/Code/PCI/_artifacts/esxi-l3-largebar-probe.iso"
    )
    parser.add_argument("--qemu-name", default="esxi8-a")
    parser.add_argument("--qemu-monitor", default="/root/vm/esxi8-mf/monitor.sock")
    parser.add_argument("--bdf", default="0000:01:01.0")
    parser.add_argument("--bar-size-gb", type=int, required=True, choices=(8, 32, 64))
    parser.add_argument("--cases", nargs="+", default=list(DEFAULT_CASES))
    parser.add_argument("--host-timeout", type=int, default=600)
    parser.add_argument("--power-timeout", type=int, default=300)
    parser.add_argument("--serial-timeout", type=int, default=180)
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
    os.environ["NO_PROXY"] = args.host

    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    result_path = output / "result.json"
    result: dict[str, Any] = {
        "runId": output.name,
        "case": "M04-pci-testdev-large-BAR-matrix-direct-esxi",
        "startedAt": utc_now(),
        "controlPlane": "standalone ESXi API plus public vim-cmd",
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
    save(result_path, result)

    password = caveat_field(args.caveat, "Password")
    ssh = EsxiSsh(args.host, password, args.user)
    try:
        result["hostVersion"] = wait_for_esxi(ssh, timeout=args.host_timeout)
        result["datastore"] = ensure_nfs_datastore(ssh, volume=args.datastore)

        iso_source = Path(args.iso)
        if not iso_source.is_file():
            raise FileNotFoundError(iso_source)
        iso_target = Path(args.nfs_root) / "iso" / iso_source.name
        iso_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(iso_source, iso_target)
        result["probeIso"] = {
            "source": str(iso_source),
            "datastorePath": f"/vmfs/volumes/{args.datastore}/iso/{iso_source.name}",
            "bytes": iso_source.stat().st_size,
        }

        context = ssl._create_unverified_context()
        service_instance = SmartConnect(
            host=args.host,
            user=args.user,
            pwd=password,
            sslContext=context,
        )
        atexit.register(Disconnect, service_instance)
        content = service_instance.RetrieveContent()
        host = direct_host(content)
        devices = [item for item in host.hardware.pciDevice if item.id == args.bdf]
        if len(devices) != 1:
            raise RuntimeError(f"expected one PCI device {args.bdf}, found {len(devices)}")
        device = devices[0]
        identity = (device.vendorId & 0xFFFF, device.deviceId & 0xFFFF)
        if identity != (VENDOR_ID, DEVICE_ID):
            raise RuntimeError(
                f"{args.bdf} is {identity[0]:04x}:{identity[1]:04x}, "
                f"expected {VENDOR_ID:04x}:{DEVICE_ID:04x}"
            )
        passthrough = next(
            item for item in host.config.pciPassthruInfo if item.id == args.bdf
        )
        result["host"] = {
            "name": host.name,
            "product": host.config.product.fullName,
            "connectionState": str(host.runtime.connectionState),
            "device": {
                "id": device.id,
                "vendorId": identity[0],
                "deviceId": identity[1],
                "deviceName": device.deviceName,
                "passthruCapable": passthrough.passthruCapable,
                "passthruEnabled": passthrough.passthruEnabled,
                "passthruActive": passthrough.passthruActive,
            },
        }
        if not passthrough.passthruActive:
            raise RuntimeError(f"PCI device {args.bdf} is not active for passthrough")
        save(result_path, result)
    except Exception as error:
        result["verdict"] = "fail-preflight"
        result["fault"] = lab.fault_snapshot(error)
        result["finishedAt"] = utc_now()
        save(result_path, result)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        raise SystemExit(1)

    for case_name in args.cases:
        config = case_config(case_name, args.bar_size_gb)
        case_result: dict[str, Any] = {
            "config": config,
            "startedAt": utc_now(),
            "outcome": "running",
        }
        result["cases"][case_name] = case_result
        save(result_path, result)

        case_dir = output / case_name
        case_dir.mkdir(parents=True, exist_ok=True)
        relative_root = f"largebar/{output.name}/{case_name}"
        logical_vm_name = f"largebar-{args.bar_size_gb}g-{output.name}-{case_name}"
        vm_name = bounded_vm_name(logical_vm_name)
        case_result["vmName"] = {
            "logical": logical_vm_name,
            "registered": vm_name,
            "truncated": vm_name != logical_vm_name,
        }
        vm_root = Path(args.nfs_root) / relative_root / vm_name
        serial_path = vm_root / "guest-serial.log"
        vmware_log = vm_root / "vmware.log"
        vm = None
        vm_id = None
        try:
            existing = [
                item for item in lab.inventory(content, vim.VirtualMachine) if item.name == vm_name
            ]
            for stale in existing:
                lab.power_off(stale)
                stale.UnregisterVM()

            extra_lines = lab.static_pci_lines(host, args.bdf)
            extra_lines.extend(vmx_mmio_lines(config))
            vmx_path = lab.write_vmx(
                vm_root,
                vm_name,
                f"/vmfs/volumes/{args.datastore}/iso/{Path(args.iso).name}",
                extra_lines=extra_lines,
            )
            register = ssh.run(
                "vim-cmd solo/registervm "
                f"/vmfs/volumes/{args.datastore}/{relative_root}/{vm_name}/{vmx_path.name}",
                check=False,
                timeout=90,
            )
            case_result["register"] = command_snapshot(register)
            match = re.search(r"(?m)^\s*(\d+)\s*$", register.stdout)
            if register.returncode != 0 or not match:
                raise RuntimeError("vim-cmd solo/registervm did not return a VM id")
            vm_id = match.group(1)
            vm = wait_vm(content, vm_name)
            case_result["configured"] = lab.vm_snapshot(vm)
            case_result["effectiveInputVmx"] = vmx_path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()

            if serial_path.exists():
                serial_path.unlink()
            power = ssh.run(
                f"vim-cmd vmsvc/power.on {vm_id}",
                check=False,
                timeout=args.power_timeout,
            )
            case_result["powerCommand"] = command_snapshot(power)
            if power.returncode != 0:
                case_result["outcome"] = "power-on-fail"
            else:
                lab.wait_power_state(vm, vim.VirtualMachinePowerState.poweredOn)
                case_result["poweredOn"] = lab.vm_snapshot(vm)
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
            copy_if_present(vmx_path, case_dir / "effective.vmx")
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
                case_result["matchesExpected"] = (
                    case_result["outcome"] == config["expected"]
                )
        except Exception as error:
            case_result["outcome"] = "runner-fail"
            case_result["fault"] = lab.fault_snapshot(error)
            case_result["matchesExpected"] = False
        finally:
            if vm_id is not None:
                power_off = ssh.run(
                    f"vim-cmd vmsvc/power.off {vm_id}", check=False, timeout=90
                )
                unregister = ssh.run(
                    f"vim-cmd vmsvc/unregister {vm_id}", check=False, timeout=90
                )
                case_result["cleanup"] = {
                    "powerOff": command_snapshot(power_off),
                    "unregister": command_snapshot(unregister),
                }
            case_result["finishedAt"] = utc_now()
            save(result_path, result)

    result["verdict"] = (
        "pass"
        if result["cases"]
        and all(item.get("matchesExpected") for item in result["cases"].values())
        else "fail"
    )
    result["finishedAt"] = utc_now()
    save(result_path, result)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
