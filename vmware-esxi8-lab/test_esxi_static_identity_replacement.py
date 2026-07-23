#!/usr/bin/env python3
"""Observe ESXi Static DirectPath behavior when one outer BDF changes identity.

The runner keeps the ESXi system disk, host UUID, topology and BDF fixed.  It
creates a Static backing while card A is present, then cold-boots controlled
card-B variants and attempts to power the unchanged VM on.  Every variant is
returned to card A before the next one so a prior replacement cannot pollute a
later observation.
"""

from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

from esxi_passthru_capability import EsxiSsh, caveat_field, collect_case
import test_esxi_owner_activation as owner
import test_esxi_passthru_capability_matrix as capability


TARGET_BDF = "0000:01:00.0"
OBSERVE_BDFS = [TARGET_BDF, "0000:01:00.1", "0000:00:08.0"]
QEMU_BINARY = "/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64"

BASE_ENV = {
    "QEMU_ESXI_QEMU_BINARY": QEMU_BINARY,
    "QEMU_ESXI_TOPOLOGY": "pcie",
    "QEMU_ESXI_IVSHMEM_SIZE": "0",
    "QEMU_ESXI_IVSHMEM_ALT_SIZE": "0",
    "QEMU_ESXI_PCI_TESTDEV_MEMBAR_SIZE": "0",
    "QEMU_ESXI_EDU": "0",
    "QEMU_ESXI_VIRTIO_NET": "0",
    "QEMU_ESXI_TRACE": "1",
    "QEMU_ESXI_IOMMU": "1",
    "QEMU_ESXI_TEST_FN0_MODEL": "e1000e",
    "QEMU_ESXI_TEST_FN1_MODEL": "e1000e",
    "QEMU_ESXI_TEST_FN0_MAC": "52:54:00:08:00:00",
    "QEMU_ESXI_TEST_FN1_MAC": "52:54:00:08:00:01",
    "QEMU_ESXI_TEST_FN0_SUBSYS_VENDOR": "0x8086",
    "QEMU_ESXI_TEST_FN0_SUBSYS_DEVICE": "0xa001",
    "QEMU_ESXI_TEST_FN1_SUBSYS_VENDOR": "0x8086",
    "QEMU_ESXI_TEST_FN1_SUBSYS_DEVICE": "0xa002",
}

VARIANTS = {
    "mac-dsn": {
        "env": {"QEMU_ESXI_TEST_FN0_MAC": "52:54:00:08:10:00"},
        "changed": ["MAC", "PCIe DSN derived by QEMU e1000e", "NVM permanent MAC"],
        "kept": ["BDF", "VID:DID", "subsystem", "topology", "host UUID"],
    },
    "subsystem": {
        "env": {"QEMU_ESXI_TEST_FN0_SUBSYS_DEVICE": "0xb001"},
        "changed": ["subsystem device ID"],
        "kept": ["BDF", "VID:DID", "MAC/DSN", "topology", "host UUID"],
    },
    "device-model": {
        "env": {"QEMU_ESXI_TEST_FN0_MODEL": "virtio-net-pci"},
        "changed": ["device model", "VID:DID", "PCI config identity"],
        "kept": ["BDF", "MAC", "topology", "host UUID"],
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect(host_address: str, password: str) -> tuple[Any, Any, vim.HostSystem]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    service = SmartConnect(
        host=host_address,
        user="root",
        pwd=password,
        sslContext=context,
        connectionPoolTimeout=20,
    )
    content = service.RetrieveContent()
    host = owner.inventory(content, vim.HostSystem)[0]
    return service, content, host


def host_device_snapshot(host: vim.HostSystem, bdf: str) -> dict[str, Any]:
    host.Reload()
    devices = [item for item in (host.hardware.pciDevice or []) if item.id == bdf]
    states = [item for item in (host.config.pciPassthruInfo or []) if item.id == bdf]
    result: dict[str, Any] = {"id": bdf, "observedAt": utc_now()}
    if len(devices) == 1:
        item = devices[0]
        result["device"] = {
            "vendorId": item.vendorId & 0xFFFF,
            "deviceId": item.deviceId & 0xFFFF,
            "subVendorId": item.subVendorId & 0xFFFF,
            "subDeviceId": item.subDeviceId & 0xFFFF,
            "classId": item.classId,
            "deviceName": item.deviceName,
            "parentBridge": item.parentBridge,
        }
    else:
        result["deviceCount"] = len(devices)
    if len(states) == 1:
        item = states[0]
        result["passthru"] = {
            "capable": item.passthruCapable,
            "enabled": item.passthruEnabled,
            "active": item.passthruActive,
            "dependentDevice": item.dependentDevice,
        }
    else:
        result["passthruCount"] = len(states)
    return result


def find_vm(content: Any, name: str) -> vim.VirtualMachine:
    matches = [vm for vm in owner.inventory(content, vim.VirtualMachine) if vm.name == name]
    if len(matches) != 1:
        raise RuntimeError(f"expected one VM {name!r}, found {len(matches)}")
    return matches[0]


def ensure_active(host: vim.HostSystem, bdf: str) -> dict[str, Any]:
    before = host_device_snapshot(host, bdf)
    state = before.get("passthru", {})
    if state.get("enabled") and state.get("active"):
        return {"before": before, "action": "already-active", "after": before}
    config = vim.host.PciPassthruConfig(id=bdf, passthruEnabled=True, applyNow=True)
    host.configManager.pciPassthruSystem.UpdatePassthruConfig(config=[config])
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        after = host_device_snapshot(host, bdf)
        state = after.get("passthru", {})
        if state.get("enabled") and state.get("active"):
            return {"before": before, "action": "enable-apply-now", "after": after}
        time.sleep(2)
    raise RuntimeError(f"{bdf} did not become passthru active")


def backing_snapshot(vm: vim.VirtualMachine) -> dict[str, Any]:
    vm.Reload()
    matches = [
        item
        for item in vm.config.hardware.device
        if isinstance(item, vim.vm.device.VirtualPCIPassthrough)
    ]
    if len(matches) != 1:
        raise RuntimeError(f"expected one passthrough backing, found {len(matches)}")
    device = matches[0]
    backing = device.backing
    return {
        "key": device.key,
        "id": getattr(backing, "id", None),
        "vendorId": getattr(backing, "vendorId", None),
        "deviceId": getattr(backing, "deviceId", None),
        "systemId": getattr(backing, "systemId", None),
        "deviceName": getattr(backing, "deviceName", None),
        "useAutoDetect": getattr(backing, "useAutoDetect", None),
    }


def power_attempt(vm: vim.VirtualMachine, host: vim.HostSystem) -> dict[str, Any]:
    before = {
        "powerState": str(vm.runtime.powerState),
        "backing": backing_snapshot(vm),
    }
    task = owner.power_on(vm, host)
    after = {
        "powerState": str(vm.runtime.powerState),
        "backing": backing_snapshot(vm),
    }
    if task["outcome"] == "success":
        owner.power_off(vm)
        after["poweredOffAgain"] = True
    return {"before": before, "task": task, "after": after}


def collect_phase(
    output: Path,
    phase: str,
    host_address: str,
    password: str,
    env: dict[str, str],
) -> dict[str, Any]:
    phase_dir = output / phase
    return collect_case(
        phase_dir,
        case_id=f"VMW-STATIC-IDENTITY-001-{phase}",
        host=host_address,
        user="root",
        password=password,
        qemu_name="esxi8-a",
        monitor=capability.MONITOR,
        targets=OBSERVE_BDFS,
        requested={"identityEnvironment": env, "subject": TARGET_BDF},
    )


def stop_start(
    ssh: EsxiSsh,
    env: dict[str, str],
    output: Path,
    phase: str,
    timeout: int,
) -> None:
    (output / phase).mkdir(parents=True, exist_ok=True)
    capability.stop_outer(ssh)
    capability.start_outer(
        env,
        ssh,
        timeout,
        output / phase / "outer-start.log",
    )


def classify_variant(
    name: str,
    baseline: dict[str, Any],
    variant: dict[str, Any],
) -> dict[str, Any]:
    old = baseline["hostDevice"].get("device", {})
    new = variant["hostDevice"].get("device", {})
    attempt = variant["powerAttempt"]["task"]["outcome"]
    owner_state = variant["hostDevice"].get("passthru", {})
    if name == "device-model":
        behavior = (
            "PUBLIC_ID_MISMATCH_DENIED"
            if attempt == "fault"
            else "PUBLIC_ID_MISMATCH_ACCEPTED"
        )
    elif name == "subsystem":
        behavior = (
            "SUBSYSTEM_CHANGE_ACCEPTED_BY_STATIC_BACKING"
            if attempt == "success"
            else "SUBSYSTEM_CHANGE_DENIED"
        )
    else:
        behavior = (
            "MAC_DSN_CHANGE_ACCEPTED_BY_STATIC_BACKING"
            if attempt == "success"
            else "MAC_DSN_CHANGE_DENIED_OR_OTHER_ADMISSION_FAULT"
        )
    return {
        "oldPublicIdentity": old,
        "newPublicIdentity": new,
        "ownerIntentInherited": bool(owner_state.get("enabled")),
        "ownerEffectiveInherited": bool(owner_state.get("active")),
        "staticPowerOnOutcome": attempt,
        "behavior": behavior,
        "boundary": (
            "A successful MAC/DSN or subsystem variant proves only that the "
            "unchanged public Static backing did not reject that change. It does "
            "not prove whether ESXi stores a private fingerprint that happened to "
            "remain equal. A device-model result tests the public VID:DID gate."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="172.31.91.10")
    parser.add_argument("--caveat", default="esxi8-auto-codex-credentials")
    parser.add_argument("--datastore", default="pci-mmio-local")
    parser.add_argument("--variant", action="append", choices=tuple(VARIANTS))
    parser.add_argument("--boot-timeout", type=int, default=720)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    selected = args.variant or list(VARIANTS)
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    password = caveat_field(args.caveat, "Password")
    ssh = EsxiSsh(args.host, password)
    suffix = hashlib.sha256(output.name.encode()).hexdigest()[:8]
    vm_name = f"static-identity-{suffix}"
    result: dict[str, Any] = {
        "schemaVersion": 1,
        "runId": output.name,
        "experimentId": "VMW-STATIC-IDENTITY-001",
        "startedAt": utc_now(),
        "targetBdf": TARGET_BDF,
        "variantsRequested": selected,
        "baseEnvironment": BASE_ENV,
        "variants": {},
    }
    result_path = output / "result.json"

    def save() -> None:
        result["updatedAt"] = utc_now()
        result_path.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    save()
    service = None
    vm = None
    current_environment_is_base = False
    try:
        stop_start(
            ssh,
            BASE_ENV,
            output,
            "baseline-start",
            args.boot_timeout,
        )
        current_environment_is_base = True
        service, content, host = connect(args.host, password)
        if host.config.product.build != "24280767":
            raise RuntimeError(f"unexpected ESXi build {host.config.product.build}")
        result["ownerActivation"] = ensure_active(host, TARGET_BDF)
        target = host.parent.environmentBrowser.QueryConfigTarget(host=host)
        available = {
            item.pciDevice.id: item for item in (target.pciPassthrough or [])
        }
        if TARGET_BDF not in available:
            raise RuntimeError(f"{TARGET_BDF} absent from QueryConfigTarget")
        datacenter = owner.inventory(content, vim.Datacenter)[0]
        vm = owner.create_vm(
            datacenter,
            host,
            args.datastore,
            vm_name,
            [owner.static_device(available[TARGET_BDF], -100)],
        )
        result["baseline"] = {
            "hostDevice": host_device_snapshot(host, TARGET_BDF),
            "backing": backing_snapshot(vm),
            "powerAttempt": power_attempt(vm, host),
            "evidence": collect_phase(output, "baseline", args.host, password, BASE_ENV),
        }
        save()
        Disconnect(service)
        service = None

        for name in selected:
            variant_definition = VARIANTS[name]
            variant_env = {**BASE_ENV, **variant_definition["env"]}
            phase_dir = output / name
            phase_dir.mkdir(parents=True, exist_ok=True)
            stop_start(ssh, variant_env, output, name, args.boot_timeout)
            current_environment_is_base = False
            service, content, host = connect(args.host, password)
            vm = find_vm(content, vm_name)
            record = {
                "changed": variant_definition["changed"],
                "kept": variant_definition["kept"],
                "environment": variant_env,
                "hostDevice": host_device_snapshot(host, TARGET_BDF),
                "backing": backing_snapshot(vm),
                "powerAttempt": power_attempt(vm, host),
                "evidence": collect_phase(output, name, args.host, password, variant_env),
            }
            record["assessment"] = classify_variant(name, result["baseline"], record)
            result["variants"][name] = record
            save()
            Disconnect(service)
            service = None

            restore_name = f"restore-after-{name}"
            stop_start(ssh, BASE_ENV, output, restore_name, args.boot_timeout)
            current_environment_is_base = True
            service, content, host = connect(args.host, password)
            vm = find_vm(content, vm_name)
            restore = {
                "hostDevice": host_device_snapshot(host, TARGET_BDF),
                "powerAttempt": power_attempt(vm, host),
                "evidence": collect_phase(
                    output, restore_name, args.host, password, BASE_ENV
                ),
            }
            record["restore"] = restore
            record["restoreVerdict"] = (
                "PASS"
                if restore["powerAttempt"]["task"]["outcome"] == "success"
                and restore["hostDevice"].get("device")
                == result["baseline"]["hostDevice"].get("device")
                else "FAIL"
            )
            save()
            Disconnect(service)
            service = None

        result["verdict"] = (
            "OBSERVED"
            if result["variants"]
            and all(item.get("restoreVerdict") == "PASS" for item in result["variants"].values())
            else "FAIL"
        )
    finally:
        if service is not None:
            Disconnect(service)
            service = None
        if not current_environment_is_base:
            try:
                stop_start(
                    ssh,
                    BASE_ENV,
                    output,
                    "cleanup-restore-baseline",
                    args.boot_timeout,
                )
                current_environment_is_base = True
            except Exception as error:
                result["outerRestoreFault"] = owner.fault_snapshot(error)
        if service is None:
            try:
                service, content, host = connect(args.host, password)
            except Exception as error:
                result["cleanupConnectFault"] = owner.fault_snapshot(error)
        if service is not None:
            try:
                vm = find_vm(content, vm_name)
                owner.power_off(vm)
                owner.wait_task(vm.Destroy_Task())
                result["cleanup"] = "vm-destroyed"
            except Exception as error:
                result["cleanupFault"] = owner.fault_snapshot(error)
            Disconnect(service)
        result["finishedAt"] = utc_now()
        save()

    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result.get("verdict") == "OBSERVED" else 1)


if __name__ == "__main__":
    main()
