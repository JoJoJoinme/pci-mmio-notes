#!/usr/bin/env python3
"""Reproduce public ESXi DirectPath owner and dependent-lease behavior."""

from __future__ import annotations

import argparse
import atexit
import json
import re
import shlex
import ssl
import time
from pathlib import Path
from typing import Any

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

from esxi_passthru_capability import EsxiSsh, caveat_field, utc_now

BDF_PATTERN = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")


def wait_task(task: Any, timeout: int = 240) -> Any:
    deadline = time.monotonic() + timeout
    while task.info.state in (vim.TaskInfo.State.queued, vim.TaskInfo.State.running):
        if time.monotonic() >= deadline:
            raise TimeoutError("vSphere task timed out")
        time.sleep(1)
    if task.info.state != vim.TaskInfo.State.success:
        raise task.info.error
    return task.info.result


def fault_snapshot(error: Exception) -> dict[str, Any]:
    return {
        "type": type(error).__name__,
        "message": str(error),
        "faultMessages": [
            {
                "key": getattr(message, "key", None),
                "message": getattr(message, "message", None),
            }
            for message in (getattr(error, "faultMessage", None) or [])
        ],
    }


def passthru_state(host: vim.HostSystem, targets: set[str]) -> list[dict[str, Any]]:
    host.Reload()
    return [
        {
            "id": item.id,
            "capable": item.passthruCapable,
            "enabled": item.passthruEnabled,
            "active": item.passthruActive,
            "dependentDevice": item.dependentDevice,
        }
        for item in (host.config.pciPassthruInfo or [])
        if item.id in targets
    ]


def inventory(content: Any, kind: type) -> list[Any]:
    view = content.viewManager.CreateContainerView(content.rootFolder, [kind], True)
    try:
        return list(view.view)
    finally:
        view.Destroy()


def validate_targets(
    host: vim.HostSystem,
    targets: list[str],
    management_bdf: str,
    expected_build: str,
    expected_system_uuid: str,
    required_capable: list[str],
) -> dict[str, Any]:
    if host.config.product.build != expected_build:
        raise RuntimeError(
            f"expected ESXi build {expected_build}, got {host.config.product.build}"
        )
    if host.hardware.systemInfo.uuid.lower() != expected_system_uuid.lower():
        raise RuntimeError(
            "expected ESXi system UUID "
            f"{expected_system_uuid}, got {host.hardware.systemInfo.uuid}"
        )
    normalized = [target.lower() for target in targets]
    if len(normalized) != len(set(normalized)):
        raise RuntimeError("duplicate PCI BDFs are not allowed")
    invalid = [target for target in normalized if not BDF_PATTERN.fullmatch(target)]
    if invalid:
        raise RuntimeError(f"invalid PCI BDFs: {invalid}")
    requested_for_change = {target.lower() for target in required_capable}
    if management_bdf.lower() in requested_for_change:
        raise RuntimeError(f"refusing to operate on management BDF {management_bdf}")

    pci = {device.id: device for device in (host.hardware.pciDevice or [])}
    passthru = {item.id: item for item in (host.config.pciPassthruInfo or [])}
    missing = [
        target for target in normalized if target not in pci or target not in passthru
    ]
    if missing:
        raise RuntimeError(f"targets absent from host inventory: {missing}")
    incapable = [
        target
        for target in required_capable
        if not passthru[target.lower()].passthruCapable
    ]
    if incapable:
        raise RuntimeError(f"targets are not passthru capable: {incapable}")
    return {
        "product": host.config.product.fullName,
        "systemUuid": host.hardware.systemInfo.uuid,
        "checkedBdfs": normalized,
        "managementBdf": management_bdf.lower(),
    }


def command_snapshot(ssh: EsxiSsh, observe: list[str]) -> dict[str, Any]:
    commands = {
        "version": "esxcli system version get",
        "uptime": "esxcli system stats uptime get",
        "platform": "esxcli hardware platform get",
        "iommuEvidence": (
            "grep -Ei 'ACPI DMAR table not found|IOMMU is not available|"
            "IOV_EnableDMARemap' /var/log/vmkernel.log | tail -n 40"
        ),
        "passthruList": "esxcli hardware pci pcipassthru list",
        "physicalNics": "esxcli network nic list",
        "standardVswitches": "esxcli network vswitch standard list",
        "vmkernelInterfaces": "esxcli network ip interface list",
    }
    snapshot: dict[str, Any] = {}
    for name, command in commands.items():
        completed = ssh.run(command, check=False, timeout=120)
        snapshot[name] = {
            "command": command,
            "exitCode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }

    pci_command = "esxcli hardware pci list"
    completed = ssh.run(pci_command, check=False, timeout=120)
    snapshot["pciInventoryCommand"] = {
        "command": pci_command,
        "exitCode": completed.returncode,
        "stderr": completed.stderr,
    }
    for bdf in observe:
        match = re.search(
            rf"(?ms)^{re.escape(bdf)}\r?$.*?(?=^[0-9a-f]{{4}}:"
            rf"[0-9a-f]{{2}}:[0-9a-f]{{2}}\.[0-7]\r?$|\Z)",
            completed.stdout,
        )
        snapshot[f"pci-{bdf}"] = {
            "sourceCommand": pci_command,
            "found": match is not None,
            "stdout": match.group(0).rstrip() + "\n" if match else "",
        }
    return snapshot


def public_log_snapshot(ssh: EsxiSsh) -> dict[str, Any]:
    commands = {
        "hostd": (
            "grep -Ei 'pci.?passthru|vswitchUplink|vmnic' /var/log/hostd.log "
            "| tail -n 300"
        ),
        "vmkernel": (
            "grep -Ei 'pci.?passthru|vswitch|vmnic' /var/log/vmkernel.log | tail -n 300"
        ),
    }
    logs: dict[str, Any] = {}
    for name, command in commands.items():
        completed = ssh.run(command, check=False, timeout=120)
        logs[name] = {
            "exitCode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    return logs


def run_api_set(
    host: vim.HostSystem,
    ssh: EsxiSsh,
    targets: list[str],
    observe: list[str],
    *,
    enabled: bool,
    apply_now: bool,
) -> dict[str, Any]:
    observe_set = set(observe)
    result: dict[str, Any] = {
        "request": {
            "targets": targets,
            "enabled": enabled,
            "applyNow": apply_now,
        },
        "observedBdfs": observe,
        "before": passthru_state(host, observe_set),
        "hostBefore": command_snapshot(ssh, observe),
    }
    configs = [
        vim.host.PciPassthruConfig(
            id=target,
            passthruEnabled=enabled,
            applyNow=apply_now,
        )
        for target in targets
    ]
    try:
        host.configManager.pciPassthruSystem.UpdatePassthruConfig(config=configs)
        result["outcome"] = "success"
    except Exception as error:
        result["outcome"] = "fault"
        result["fault"] = fault_snapshot(error)
    result["after"] = passthru_state(host, observe_set)
    result["hostAfter"] = command_snapshot(ssh, observe)
    result["publicLogs"] = public_log_snapshot(ssh)
    return result


def power_off(vm: vim.VirtualMachine) -> None:
    vm.Reload()
    if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
        wait_task(vm.PowerOffVM_Task())
        time.sleep(2)


def power_on(vm: vim.VirtualMachine, host: vim.HostSystem) -> dict[str, Any]:
    try:
        wait_task(vm.PowerOnVM_Task(host=host))
        time.sleep(3)
        vm.Reload()
        return {"outcome": "success", "powerState": str(vm.runtime.powerState)}
    except Exception as error:
        vm.Reload()
        return {
            "outcome": "fault",
            "powerState": str(vm.runtime.powerState),
            "fault": fault_snapshot(error),
        }


def static_device(info: Any, key: int) -> vim.vm.device.VirtualPCIPassthrough:
    device = info.pciDevice
    backing = vim.vm.device.VirtualPCIPassthrough.DeviceBackingInfo(
        id=device.id,
        deviceId=f"{device.deviceId & 0xFFFF:x}",
        vendorId=device.vendorId,
        systemId=info.systemId,
        deviceName=device.deviceName,
        useAutoDetect=False,
    )
    return vim.vm.device.VirtualPCIPassthrough(
        key=key,
        deviceInfo=vim.Description(label=f"Static {device.id}", summary=device.id),
        backing=backing,
    )


def create_vm(
    datacenter: vim.Datacenter,
    host: vim.HostSystem,
    datastore: str,
    name: str,
    devices: list[vim.vm.device.VirtualPCIPassthrough],
) -> vim.VirtualMachine:
    changes = [
        vim.vm.device.VirtualDeviceSpec(
            operation=vim.vm.device.VirtualDeviceSpec.Operation.add,
            device=device,
        )
        for device in devices
    ]
    spec = vim.vm.ConfigSpec(
        name=name,
        guestId="other5xLinux64Guest",
        version="vmx-20",
        files=vim.vm.FileInfo(vmPathName=f"[{datastore}] {name}"),
        numCPUs=1,
        memoryMB=1024,
        firmware="efi",
        memoryReservationLockedToMax=True,
        deviceChange=changes,
    )
    return wait_task(
        datacenter.vmFolder.CreateVM_Task(
            config=spec,
            pool=host.parent.resourcePool,
            host=host,
        )
    )


def vm_log_path(vm: vim.VirtualMachine) -> str | None:
    match = re.fullmatch(r"\[([^]]+)]\s+(.+\.vmx)", vm.config.files.vmPathName)
    if not match:
        return None
    datastore, vmx = match.groups()
    directory = vmx.rsplit("/", 1)[0]
    return f"/vmfs/volumes/{datastore}/{directory}/vmware.log"


def save_vm_log(ssh: EsxiSsh, vm: vim.VirtualMachine, output: Path) -> str:
    path = vm_log_path(vm)
    if path is None:
        return ""
    completed = ssh.run(f"cat {shlex.quote(path)}", check=False, timeout=120)
    output.write_text(completed.stdout, encoding="utf-8")
    return completed.stdout


def passthru_log_markers(log: str) -> list[str]:
    return [
        line
        for line in log.splitlines()
        if "AH Failed" in line
        or "suitable device" in line
        or "pciPassthru" in line
        and "power on failed" in line.lower()
    ][-40:]


def run_admission_pair(
    content: Any,
    host: vim.HostSystem,
    ssh: EsxiSsh,
    targets: list[str],
    datastore: str,
    output_dir: Path,
) -> dict[str, Any]:
    if len(targets) != 2:
        raise ValueError("admission-pair requires exactly two targets")
    if len(set(targets)) != 2:
        raise ValueError("admission-pair requires two distinct targets")
    if host.runtime.inMaintenanceMode:
        raise RuntimeError(
            "admission-pair requires the ESXi host to be out of maintenance mode"
        )
    state = {item["id"]: item for item in passthru_state(host, set(targets))}
    dependencies = {state[target]["dependentDevice"] for target in targets}
    if len(dependencies) != 1 or not next(iter(dependencies)):
        raise RuntimeError("targets do not share one non-empty dependentDevice")
    if not all(state[target]["active"] for target in targets):
        raise RuntimeError("both targets must be passthruActive before admission test")

    target_info = host.parent.environmentBrowser.QueryConfigTarget(host=host)
    available = {item.pciDevice.id: item for item in (target_info.pciPassthrough or [])}
    if any(target not in available for target in targets):
        raise RuntimeError("active targets are absent from QueryConfigTarget")

    datacenter = inventory(content, vim.Datacenter)[0]
    suffix = re.sub(r"[^a-z0-9]+", "-", output_dir.name.lower()).strip("-")[-24:]
    created: list[vim.VirtualMachine] = []
    result: dict[str, Any] = {
        "dependentDevice": next(iter(dependencies)),
        "targets": targets,
    }
    try:
        vm_a = create_vm(
            datacenter,
            host,
            datastore,
            f"owner-a-{suffix}",
            [static_device(available[targets[0]], -100)],
        )
        created.append(vm_a)
        vm_b = create_vm(
            datacenter,
            host,
            datastore,
            f"owner-b-{suffix}",
            [static_device(available[targets[1]], -100)],
        )
        created.append(vm_b)
        result["firstVm"] = power_on(vm_a, host)
        first_log = save_vm_log(
            ssh, vm_a, output_dir / "phase-1-first-vm-powered-on.log"
        )
        result["firstVm"]["vmwareLogMarkers"] = passthru_log_markers(first_log)
        result["secondVmWhileFirstRuns"] = power_on(vm_b, host)
        conflict_log = save_vm_log(
            ssh, vm_b, output_dir / "phase-2-second-vm-conflict.log"
        )
        result["secondVmWhileFirstRuns"]["vmwareLogMarkers"] = passthru_log_markers(
            conflict_log
        )
        power_off(vm_a)
        result["secondVmAfterRelease"] = power_on(vm_b, host)
        released_log = save_vm_log(
            ssh, vm_b, output_dir / "phase-3-second-vm-after-release.log"
        )
        result["secondVmAfterRelease"]["vmwareLogMarkers"] = passthru_log_markers(
            released_log
        )
        power_off(vm_b)

        vm_both = create_vm(
            datacenter,
            host,
            datastore,
            f"owner-both-{suffix}",
            [
                static_device(available[targets[0]], -100),
                static_device(available[targets[1]], -101),
            ],
        )
        created.append(vm_both)
        result["sameVmBothFunctions"] = power_on(vm_both, host)
        same_vm_log = save_vm_log(
            ssh, vm_both, output_dir / "phase-4-same-vm-both-functions.log"
        )
        result["sameVmBothFunctions"]["vmwareLogMarkers"] = passthru_log_markers(
            same_vm_log
        )

        result["verdict"] = (
            "pass"
            if result["firstVm"]["outcome"] == "success"
            and result["secondVmWhileFirstRuns"]["outcome"] == "fault"
            and result["secondVmAfterRelease"]["outcome"] == "success"
            and result["sameVmBothFunctions"]["outcome"] == "fault"
            else "unexpected-observation"
        )
        return result
    finally:
        for vm in created:
            try:
                save_vm_log(ssh, vm, output_dir / f"{vm.name}-vmware.log")
                power_off(vm)
                wait_task(vm.Destroy_Task())
            except Exception as error:
                result.setdefault("cleanupFaults", []).append(
                    {"vm": vm.name, "fault": fault_snapshot(error)}
                )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("snapshot", "api-set", "admission-pair"))
    parser.add_argument("--host", default="172.31.91.10")
    parser.add_argument("--caveat", default="esxi8-auto-codex-credentials")
    parser.add_argument("--output", required=True)
    parser.add_argument("--target", action="append", required=True)
    parser.add_argument(
        "--observe",
        action="append",
        default=[],
        help="additional BDF to read before/after without adding it to the request",
    )
    parser.add_argument(
        "--observe-all",
        action="store_true",
        help="read every HostPciPassthruInfo entry; valid only for snapshot mode",
    )
    parser.add_argument("--management-bdf", default="0000:00:05.0")
    parser.add_argument("--expected-build", default="24280767")
    parser.add_argument(
        "--expected-system-uuid",
        default="6a4e818a-51ce-7d7f-a21f-000c29abaf6d",
    )
    parser.add_argument("--datastore", default="pci-mmio-local")
    parser.add_argument("--enable", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--apply-now", action="store_true")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    password = caveat_field(args.caveat, "Password")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    service_instance = SmartConnect(
        host=args.host,
        user="root",
        pwd=password,
        sslContext=context,
        connectionPoolTimeout=20,
    )
    atexit.register(Disconnect, service_instance)
    content = service_instance.RetrieveContent()
    host = inventory(content, vim.HostSystem)[0]
    targets = [target.lower() for target in args.target]
    if len(targets) != len(set(targets)):
        raise RuntimeError("duplicate --target BDFs are not allowed")
    if args.observe_all and args.mode != "snapshot":
        raise RuntimeError("--observe-all is valid only for snapshot mode")
    observed_inputs = [item.lower() for item in args.observe]
    if args.observe_all:
        observed_inputs.extend(
            sorted(item.id.lower() for item in (host.config.pciPassthruInfo or []))
        )
    observe = list(dict.fromkeys(targets + observed_inputs))
    checked_bdfs = list(dict.fromkeys(targets + observe))
    ssh = EsxiSsh(args.host, password)
    result: dict[str, Any] = {
        "observedAt": utc_now(),
        "mode": args.mode,
        "safety": validate_targets(
            host,
            checked_bdfs,
            args.management_bdf,
            args.expected_build,
            args.expected_system_uuid,
            targets if args.mode != "snapshot" else [],
        ),
        "requestedBdfs": targets,
        "observedBdfs": observe,
    }
    if args.mode == "snapshot":
        result["state"] = passthru_state(host, set(observe))
        result["hostState"] = command_snapshot(ssh, observe)
    elif not args.execute:
        result["outcome"] = "dry-run"
        result["plannedRequest"] = {
            "targets": targets,
            "observe": observe,
            "enable": args.enable,
            "applyNow": args.apply_now,
        }
    elif args.mode == "api-set":
        result["apiSet"] = run_api_set(
            host,
            ssh,
            targets,
            observe,
            enabled=args.enable,
            apply_now=args.apply_now,
        )
    else:
        result["admissionPair"] = run_admission_pair(
            content,
            host,
            ssh,
            targets,
            args.datastore,
            output_dir,
        )

    result_path = output_dir / "result.json"
    result_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
