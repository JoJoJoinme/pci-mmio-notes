#!/usr/bin/env python3
"""Correlate ESXi DirectPath VM power-on with an outer-QEMU FLR reset."""

from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
import re
import shutil
import ssl
import time
from pathlib import Path

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

import test_esxi_vmotion_matrix as lab
from esxi_passthru_capability import EsxiSsh, collect_case, utc_now
from qemu_simpletrace import decode_simpletrace, selected_reset_lines
from test_esxi_passthru_capability_matrix import (
    CASES,
    MONITOR,
    RESTORE_ENV,
    start_outer,
    stop_outer,
)


BDF = "0000:00:09.0"
TRACE_FILE = Path("/root/vm/esxi8-mf/qemu-trace.log")


def save(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def connect_vcenter(address: str, user: str, password: str, timeout: int):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            return SmartConnect(
                host=address,
                user=user,
                pwd=password,
                sslContext=context,
            )
        except Exception as error:  # vCenter needs time to rediscover the host.
            last_error = error
            time.sleep(5)
    raise TimeoutError(f"vCenter connection did not recover: {last_error}")


def wait_connected_host(content, address: str, timeout: int):
    deadline = time.monotonic() + timeout
    last_state = None
    while time.monotonic() < deadline:
        matches = [
            item
            for item in lab.inventory(content, vim.HostSystem)
            if item.name == address
        ]
        if matches:
            host = matches[0]
            host.Reload()
            last_state = str(host.runtime.connectionState)
            if host.runtime.connectionState == vim.HostSystem.ConnectionState.connected:
                return host
        time.sleep(5)
    raise TimeoutError(f"Host {address} did not reconnect; last state={last_state}")


def trace_snapshot(output_dir: Path, label: str) -> list[str]:
    decoded = decode_simpletrace(TRACE_FILE)
    lines = selected_reset_lines(decoded)
    (output_dir / f"outer-reset-trace-{label}.log").write_text(
        "\n".join(lines) + ("\n" if lines else ""),
        encoding="utf-8",
    )
    return lines


def vmware_log_excerpt(path: Path) -> list[str]:
    if not path.exists():
        return []
    pattern = re.compile(r"PCIPassthru|IOMMU|reset|DevicePowerOn", re.IGNORECASE)
    return [
        line
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if pattern.search(line)
    ][-500:]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vcenter", default="192.168.91.131")
    parser.add_argument("--host", default="172.31.91.10")
    parser.add_argument("--vcsa-caveat", default="vcsa803-codex-credentials")
    parser.add_argument("--esxi-caveat", default="esxi8-auto-codex-credentials")
    parser.add_argument("--datacenter", default="PCI-Lab")
    parser.add_argument("--cluster", default="PCI-DirectPath-Lab")
    parser.add_argument("--datastore", default="qemu-shared")
    parser.add_argument("--nfs-root", default="/root/vm/esxi8-mf/nfsds")
    parser.add_argument("--iso", default="esxi-l3-vmotion-probe.iso")
    parser.add_argument("--timeout", type=int, default=720)
    parser.add_argument("--output", required=True)
    parser.add_argument("--no-restore", action="store_true")
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

    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    result_path = output_dir / "result.json"
    run_id = output_dir.name
    result = {
        "runId": run_id,
        "case": "R00-ESXi-DirectPath-FLR-outer-QEMU-correlation",
        "startedAt": utc_now(),
        "bdf": BDF,
        "verdict": "running",
    }
    save(result_path, result)

    esxi_password = lab.caveat_field(args.esxi_caveat, "Password")
    ssh = EsxiSsh(args.host, esxi_password)
    service_instance = None
    vm = None
    vm_root = None

    try:
        stop_outer(ssh)
        result["esxiVersion"] = start_outer(
            CASES["root-virtio-flr-only"]["env"],
            ssh,
            args.timeout,
            output_dir / "outer-start.log",
        ).splitlines()

        owner = ssh.run(
            f"esxcli hardware pci pcipassthru set -d {BDF} -e true -a; "
            f"esxcli hardware pci list | sed -n '/{BDF}/,/^$/p'",
            check=False,
            timeout=120,
        )
        (output_dir / "owner-enable.txt").write_text(
            owner.stdout + owner.stderr,
            encoding="utf-8",
        )
        time.sleep(5)

        capability = collect_case(
            output_dir / "capability",
            case_id="root-virtio-flr-vm-power",
            host=args.host,
            user="root",
            password=esxi_password,
            qemu_name="esxi8-a",
            monitor=MONITOR,
            targets=[BDF],
            requested={"purpose": "FLR reset correlation during VM power-on"},
        )
        esxcli = capability["devices"][BDF]["esxcli"]
        result["capability"] = {
            "passthruCapable": esxcli.get("Passthru Capable"),
            "configuredOwner": esxcli.get("Configured Owner"),
            "currentOwner": esxcli.get("Current Owner"),
            "resetMethod": esxcli.get("Reset Method"),
        }
        save(result_path, result)

        service_instance = connect_vcenter(
            args.vcenter,
            lab.caveat_field(args.vcsa_caveat, "SSO Username"),
            lab.caveat_field(args.vcsa_caveat, "SSO Password"),
            args.timeout,
        )
        atexit.register(Disconnect, service_instance)
        content = service_instance.RetrieveContent()
        host = wait_connected_host(content, args.host, args.timeout)
        datacenter = next(
            item
            for item in content.rootFolder.childEntity
            if isinstance(item, vim.Datacenter) and item.name == args.datacenter
        )
        cluster = next(
            item
            for item in datacenter.hostFolder.childEntity
            if isinstance(item, vim.ClusterComputeResource) and item.name == args.cluster
        )
        if host.runtime.inMaintenanceMode:
            lab.wait_task(host.ExitMaintenanceMode_Task(timeout=300))

        pci_info = next(item for item in host.config.pciPassthruInfo if item.id == BDF)
        result["vSpherePassthruInfo"] = {
            "enabled": pci_info.passthruEnabled,
            "active": pci_info.passthruActive,
            "capable": pci_info.passthruCapable,
            "dependent": pci_info.dependentDevice,
        }
        if not pci_info.passthruActive:
            raise RuntimeError(f"{BDF} did not become active for passthrough")

        vm_name = f"flr-{run_id}"
        relative_root = f"flr/{run_id}"
        vm_root = Path(args.nfs_root) / relative_root / vm_name
        serial_path = vm_root / "guest-serial.log"
        existing = [
            item for item in lab.inventory(content, vim.VirtualMachine) if item.name == vm_name
        ]
        if existing:
            lab.power_off(existing[0])
            existing[0].UnregisterVM()

        vmx_path = lab.write_vmx(
            vm_root,
            vm_name,
            f"/vmfs/volumes/{args.datastore}/iso/{args.iso}",
            extra_lines=lab.static_pci_lines(host, BDF),
        )
        vm = lab.register_vm(
            datacenter,
            cluster,
            host,
            args.datastore,
            f"{relative_root}/{vm_name}/{vmx_path.name}",
            vm_name,
        )
        result["configured"] = lab.vm_snapshot(vm)
        before = trace_snapshot(output_dir, "before-power-on")

        lab.power_on(vm, host, serial_path=serial_path, marker_timeout=args.timeout)
        result["poweredOn"] = lab.vm_snapshot(vm)
        time.sleep(3)
        after_on = trace_snapshot(output_dir, "after-power-on")
        power_on_delta = after_on[len(before) :]

        lab.power_off(vm)
        time.sleep(3)
        after_off = trace_snapshot(output_dir, "after-power-off")
        power_off_delta = after_off[len(after_on) :]

        vmware_log = vm_root / "vmware.log"
        for source, name in (
            (serial_path, "guest-serial.log"),
            (vmware_log, "vmware.log"),
            (vm_root / f"{vm_name}.vmx", "effective.vmx"),
        ):
            if source.exists():
                shutil.copyfile(source, output_dir / name)

        (output_dir / "outer-reset-trace-power-on-delta.log").write_text(
            "\n".join(power_on_delta) + ("\n" if power_on_delta else ""),
            encoding="utf-8",
        )
        (output_dir / "outer-reset-trace-power-off-delta.log").write_text(
            "\n".join(power_off_delta) + ("\n" if power_off_delta else ""),
            encoding="utf-8",
        )
        trace_bytes = TRACE_FILE.read_bytes()
        result["outerTrace"] = {
            "size": len(trace_bytes),
            "sha256": hashlib.sha256(trace_bytes).hexdigest(),
            "resetLinesBeforePowerOn": len(before),
            "powerOnDelta": power_on_delta,
            "powerOffDelta": power_off_delta,
        }
        result["vmwareLogExcerpt"] = vmware_log_excerpt(vmware_log)
        checks = {
            "capabilityTrue": result["capability"]["passthruCapable"] == "true",
            "functionResetSelected": "Function" in str(
                result["capability"]["resetMethod"]
            ),
            "passthroughActive": result["vSpherePassthruInfo"]["active"] is True,
            "guestBooted": serial_path.exists()
            and "VMOTION-HEARTBEAT" in serial_path.read_text(
                encoding="utf-8", errors="replace"
            ),
            "virtioResetDuringPowerOn": any(
                "virtio-net-pci" in line for line in power_on_delta
            ),
            "vmwareLogHasPassthrough": any(
                "PCIPassthru" in line for line in result["vmwareLogExcerpt"]
            ),
        }
        result["checks"] = checks
        result["verdict"] = "pass" if all(checks.values()) else "fail"
    except Exception as error:
        result["verdict"] = "blocked"
        result["fault"] = lab.fault_snapshot(error)
    finally:
        if vm is not None:
            try:
                lab.power_off(vm)
            except Exception as error:
                result["cleanupPowerFault"] = lab.fault_snapshot(error)
            try:
                vm.UnregisterVM()
            except Exception as error:
                result["cleanupUnregisterFault"] = lab.fault_snapshot(error)
        if not args.no_restore:
            try:
                stop_outer(ssh)
                result["restoreEsxiVersion"] = start_outer(
                    RESTORE_ENV,
                    ssh,
                    args.timeout,
                    output_dir / "restore-start.log",
                ).splitlines()
                result["restoreVerdict"] = "pass"
            except Exception as error:
                result["restoreVerdict"] = "blocked"
                result["restoreFault"] = lab.fault_snapshot(error)
        result["finishedAt"] = utc_now()
        save(result_path, result)

    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
