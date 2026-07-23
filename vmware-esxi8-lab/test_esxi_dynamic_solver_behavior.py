#!/usr/bin/env python3
"""Observe ESXi Dynamic DirectPath binding, atomicity and solver behavior.

This is a black-box behavior runner.  It deliberately reports task overlap and
the exact candidate set so a serialized control-plane result is not mislabeled
as proof of VMware's private locking or solver implementation.
"""

from __future__ import annotations

import argparse
import atexit
import concurrent.futures
import hashlib
import json
import ssl
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim

import test_esxi_owner_activation as owner


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple)):
        return [json_value(item) for item in value]
    if hasattr(value, "_moId"):
        return {"moid": value._moId, "type": type(value).__name__}
    return str(value)


def fresh_vm(vm: vim.VirtualMachine) -> vim.VirtualMachine:
    """Return a new read-only proxy without invoking Reload during a VM task."""
    return vim.VirtualMachine(vm._moId, vm._stub)


def backing_snapshot(
    vm: vim.VirtualMachine, *, reload: bool = True
) -> list[dict[str, Any]]:
    if reload:
        vm.Reload()
    result: list[dict[str, Any]] = []
    for device in vm.config.hardware.device:
        if not isinstance(device, vim.vm.device.VirtualPCIPassthrough):
            continue
        backing = device.backing
        result.append(
            {
                "key": device.key,
                "label": device.deviceInfo.label if device.deviceInfo else None,
                "assignedId": getattr(backing, "assignedId", None),
                "customLabel": getattr(backing, "customLabel", None),
                "allowedDevice": [
                    {
                        "vendorId": getattr(item, "vendorId", None),
                        "deviceId": getattr(item, "deviceId", None),
                        "subVendorId": getattr(item, "subVendorId", None),
                        "subDeviceId": getattr(item, "subDeviceId", None),
                        "revisionId": getattr(item, "revisionId", None),
                    }
                    for item in (getattr(backing, "allowedDevice", None) or [])
                ],
            }
        )
    return sorted(result, key=lambda item: item["key"])


def vm_snapshot(vm: vim.VirtualMachine, *, reload: bool = True) -> dict[str, Any]:
    if reload:
        vm.Reload()
    else:
        vm = fresh_vm(vm)
    return {
        "observedAt": utc_now(),
        "name": vm.name,
        "moid": vm._moId,
        "powerState": str(vm.runtime.powerState),
        "host": vm.runtime.host.name if vm.runtime.host else None,
        "devices": backing_snapshot(vm, reload=False),
    }


def assigned_ids(vm: vim.VirtualMachine) -> list[str]:
    return sorted(
        item["assignedId"]
        for item in backing_snapshot(vm)
        if item["assignedId"] is not None
    )


def manager_bindings(host: vim.HostSystem) -> dict[str, Any]:
    manager = host.configManager.assignableHardwareManager
    result: dict[str, Any] = {}
    for name in ("binding", "config"):
        try:
            values = getattr(manager, name, None) or []
            result[name] = [
                {
                    field: json_value(getattr(item, field, None))
                    for field in (
                        "instanceId",
                        "vm",
                        "host",
                        "pciId",
                        "deviceKey",
                        "attributeOverride",
                    )
                    if getattr(item, field, None) is not None
                }
                for item in values
            ]
        except Exception as error:
            result[name] = {"error": f"{type(error).__name__}: {error}"}
    return result


def allowed_device(
    vendor_id: int,
    device_id: int,
    *,
    sub_vendor_id: int | None = None,
    sub_device_id: int | None = None,
) -> vim.vm.device.VirtualPCIPassthrough.AllowedDevice:
    kwargs: dict[str, Any] = {"vendorId": vendor_id, "deviceId": device_id}
    if sub_vendor_id is not None:
        kwargs["subVendorId"] = sub_vendor_id
    if sub_device_id is not None:
        kwargs["subDeviceId"] = sub_device_id
    return vim.vm.device.VirtualPCIPassthrough.AllowedDevice(**kwargs)


def dynamic_device(
    key: int,
    label: str,
    allowed: list[vim.vm.device.VirtualPCIPassthrough.AllowedDevice],
) -> vim.vm.device.VirtualPCIPassthrough:
    backing = vim.vm.device.VirtualPCIPassthrough.DynamicBackingInfo(
        allowedDevice=allowed
    )
    return vim.vm.device.VirtualPCIPassthrough(
        key=key,
        deviceInfo=vim.Description(label=label, summary=label),
        backing=backing,
    )


def create_dynamic_vm(
    datacenter: vim.Datacenter,
    host: vim.HostSystem,
    datastore: str,
    name: str,
    requirements: list[list[vim.vm.device.VirtualPCIPassthrough.AllowedDevice]],
) -> vim.VirtualMachine:
    devices = [
        dynamic_device(-100 - index, f"Dynamic requirement {index}", allowed)
        for index, allowed in enumerate(requirements)
    ]
    return owner.create_vm(datacenter, host, datastore, name, devices)


def task_result(task: Any, timeout: int = 600) -> dict[str, Any]:
    started = utc_now()
    try:
        owner.wait_task(task, timeout=timeout)
        outcome = "success"
        fault = None
    except Exception as error:
        outcome = "fault"
        fault = owner.fault_snapshot(error)
    info = task.info
    result = {
        "task": task._moId,
        "submittedAt": started,
        "queueTime": json_value(getattr(info, "queueTime", None)),
        "startTime": json_value(getattr(info, "startTime", None)),
        "completeTime": json_value(getattr(info, "completeTime", None)),
        "state": str(info.state),
        "outcome": outcome,
    }
    if fault is not None:
        result["fault"] = fault
    return result


def power_on_observed(
    vm: vim.VirtualMachine,
    host: vim.HostSystem,
    poll_seconds: float,
) -> dict[str, Any]:
    task = vm.PowerOnVM_Task(host=host)
    timeline: list[dict[str, Any]] = []
    while task.info.state in (vim.TaskInfo.State.queued, vim.TaskInfo.State.running):
        timeline.append(
            {
                "taskState": str(task.info.state),
                "vm": vm_snapshot(vm, reload=False),
                "bindings": manager_bindings(host),
            }
        )
        time.sleep(poll_seconds)
    outcome = task_result(task)
    timeline.append(
        {
            "taskState": str(task.info.state),
            "vm": vm_snapshot(vm),
            "bindings": manager_bindings(host),
        }
    )
    return {"task": outcome, "timeline": timeline, "final": vm_snapshot(vm)}


def power_off_observed(
    vm: vim.VirtualMachine,
    host: vim.HostSystem,
    poll_seconds: float,
) -> dict[str, Any]:
    vm.Reload()
    if vm.runtime.powerState != vim.VirtualMachinePowerState.poweredOn:
        return {"skipped": True, "reason": "not-powered-on", "final": vm_snapshot(vm)}
    task = vm.PowerOffVM_Task()
    timeline: list[dict[str, Any]] = []
    while task.info.state in (vim.TaskInfo.State.queued, vim.TaskInfo.State.running):
        timeline.append(
            {
                "taskState": str(task.info.state),
                "vm": vm_snapshot(vm, reload=False),
                "bindings": manager_bindings(host),
            }
        )
        time.sleep(poll_seconds)
    outcome = task_result(task)
    timeline.append(
        {
            "taskState": str(task.info.state),
            "vm": vm_snapshot(vm),
            "bindings": manager_bindings(host),
        }
    )
    return {"task": outcome, "timeline": timeline, "final": vm_snapshot(vm)}


def concurrent_worker(
    host_address: str,
    password: str,
    vm_moid: str,
    host_moid: str,
    barrier: threading.Barrier,
) -> dict[str, Any]:
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
    try:
        vm = vim.VirtualMachine(vm_moid, service._stub)
        host = vim.HostSystem(host_moid, service._stub)
        barrier.wait(timeout=30)
        submitted = utc_now()
        task = vm.PowerOnVM_Task(host=host)
        result = task_result(task)
        result["clientSubmittedAt"] = submitted
        return result
    finally:
        Disconnect(service)


def host_candidates(
    host: vim.HostSystem,
    vendor_id: int,
    device_id: int,
) -> list[dict[str, Any]]:
    passthru = {item.id: item for item in (host.config.pciPassthruInfo or [])}
    result = []
    for item in host.hardware.pciDevice or []:
        if (item.vendorId & 0xFFFF, item.deviceId & 0xFFFF) != (
            vendor_id,
            device_id,
        ):
            continue
        state = passthru.get(item.id)
        result.append(
            {
                "id": item.id,
                "vendorId": item.vendorId & 0xFFFF,
                "deviceId": item.deviceId & 0xFFFF,
                "subVendorId": item.subVendorId & 0xFFFF,
                "subDeviceId": item.subDeviceId & 0xFFFF,
                "parentBridge": item.parentBridge,
                "capable": state.passthruCapable if state else None,
                "enabled": state.passthruEnabled if state else None,
                "active": state.passthruActive if state else None,
                "dependentDevice": state.dependentDevice if state else None,
            }
        )
    return sorted(result, key=lambda item: item["id"])


def quiesce_and_destroy(vm: vim.VirtualMachine) -> dict[str, Any]:
    record: dict[str, Any] = {"vm": vm.name, "moid": vm._moId}
    try:
        for task in list(vm.recentTask or []):
            if task.info.state in (
                vim.TaskInfo.State.queued,
                vim.TaskInfo.State.running,
            ):
                task_record = task_result(task)
                record.setdefault("waitedTasks", []).append(task_record)
        owner.power_off(vm)
        owner.wait_task(vm.Destroy_Task())
        record["outcome"] = "destroyed"
    except Exception as error:
        record["outcome"] = "fault"
        record["fault"] = owner.fault_snapshot(error)
    return record


def run_lifecycle(
    datacenter: vim.Datacenter,
    host: vim.HostSystem,
    datastore: str,
    prefix: str,
    generic: vim.vm.device.VirtualPCIPassthrough.AllowedDevice,
    poll_seconds: float,
    created: list[vim.VirtualMachine],
) -> dict[str, Any]:
    vm = create_dynamic_vm(datacenter, host, datastore, f"{prefix}-life", [[generic]])
    created.append(vm)
    result = {"before": vm_snapshot(vm)}
    result["firstPowerOn"] = power_on_observed(vm, host, poll_seconds)
    first = assigned_ids(vm)
    result["firstPowerOff"] = power_off_observed(vm, host, poll_seconds)
    off_first = assigned_ids(vm)
    result["secondPowerOn"] = power_on_observed(vm, host, poll_seconds)
    second = assigned_ids(vm)
    result["secondPowerOff"] = power_off_observed(vm, host, poll_seconds)
    off_second = assigned_ids(vm)
    result["assessment"] = {
        "firstAssigned": first,
        "secondAssigned": second,
        "firstOffAssigned": off_first,
        "secondOffAssigned": off_second,
        "verdict": (
            "PASS"
            if len(first) == 1 and len(second) == 1 and not off_first and not off_second
            else "FAIL"
        ),
        "meaning": (
            "assignedId is a runtime binding: present after successful power-on, "
            "absent after each power-off; reuse of the same BDF is permitted."
        ),
    }
    return result


def run_atomicity(
    datacenter: vim.Datacenter,
    host: vim.HostSystem,
    datastore: str,
    prefix: str,
    generic: vim.vm.device.VirtualPCIPassthrough.AllowedDevice,
    poll_seconds: float,
    created: list[vim.VirtualMachine],
) -> dict[str, Any]:
    blocker = create_dynamic_vm(datacenter, host, datastore, f"{prefix}-block", [[generic]])
    target = create_dynamic_vm(
        datacenter, host, datastore, f"{prefix}-target", [[generic], [generic]]
    )
    probe = create_dynamic_vm(datacenter, host, datastore, f"{prefix}-probe", [[generic]])
    created.extend((blocker, target, probe))
    result: dict[str, Any] = {}
    result["blockerOn"] = power_on_observed(blocker, host, poll_seconds)
    result["targetWhileBlocked"] = power_on_observed(target, host, poll_seconds)
    target_failed_ids = assigned_ids(target)
    result["probeWhileBlocked"] = power_on_observed(probe, host, poll_seconds)
    probe_ids = assigned_ids(probe)
    result["bindingsAfterFailedTarget"] = manager_bindings(host)
    result["probeOff"] = power_off_observed(probe, host, poll_seconds)
    result["blockerOff"] = power_off_observed(blocker, host, poll_seconds)
    result["targetRetry"] = power_on_observed(target, host, poll_seconds)
    retry_ids = assigned_ids(target)
    result["targetOff"] = power_off_observed(target, host, poll_seconds)
    final_ids = assigned_ids(target)
    result["assessment"] = {
        "failedTargetAssigned": target_failed_ids,
        "probeAssigned": probe_ids,
        "retryAssigned": retry_ids,
        "finalAssigned": final_ids,
        "verdict": (
            "PASS"
            if result["targetWhileBlocked"]["task"]["outcome"] == "fault"
            and not target_failed_ids
            and len(probe_ids) == 1
            and len(retry_ids) == 2
            and len(set(retry_ids)) == 2
            and not final_ids
            else "FAIL"
        ),
        "meaning": (
            "A failed two-device solve left no assignedId and did not leak the "
            "remaining candidate; after release the complete request succeeded."
        ),
    }
    return result


def run_concurrency(
    datacenter: vim.Datacenter,
    host: vim.HostSystem,
    datastore: str,
    prefix: str,
    generic: vim.vm.device.VirtualPCIPassthrough.AllowedDevice,
    host_address: str,
    password: str,
    poll_seconds: float,
    created: list[vim.VirtualMachine],
) -> dict[str, Any]:
    vm_a = create_dynamic_vm(
        datacenter, host, datastore, f"{prefix}-race-a", [[generic], [generic]]
    )
    vm_b = create_dynamic_vm(
        datacenter, host, datastore, f"{prefix}-race-b", [[generic], [generic]]
    )
    created.extend((vm_a, vm_b))
    barrier = threading.Barrier(2)
    timeline: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = {
            "a": pool.submit(
                concurrent_worker,
                host_address,
                password,
                vm_a._moId,
                host._moId,
                barrier,
            ),
            "b": pool.submit(
                concurrent_worker,
                host_address,
                password,
                vm_b._moId,
                host._moId,
                barrier,
            ),
        }
        while not all(future.done() for future in futures.values()):
            timeline.append(
                {
                    "observedAt": utc_now(),
                    "a": vm_snapshot(vm_a, reload=False),
                    "b": vm_snapshot(vm_b, reload=False),
                    "bindings": manager_bindings(host),
                }
            )
            time.sleep(poll_seconds)
        tasks = {name: future.result() for name, future in futures.items()}
    snapshots = {"a": vm_snapshot(vm_a), "b": vm_snapshot(vm_b)}
    ids = {"a": assigned_ids(vm_a), "b": assigned_ids(vm_b)}
    winners = [name for name, task in tasks.items() if task["outcome"] == "success"]
    loser = "b" if winners == ["a"] else "a" if winners == ["b"] else None
    winner = winners[0] if len(winners) == 1 else None
    if winner is not None:
        power_off_observed(vm_a if winner == "a" else vm_b, host, poll_seconds)
    retry = None
    retry_ids: list[str] = []
    if loser is not None:
        loser_vm = vm_a if loser == "a" else vm_b
        retry = power_on_observed(loser_vm, host, poll_seconds)
        retry_ids = assigned_ids(loser_vm)
        power_off_observed(loser_vm, host, poll_seconds)
    queue_windows = {
        name: {
            "startTime": task.get("startTime"),
            "completeTime": task.get("completeTime"),
        }
        for name, task in tasks.items()
    }
    return {
        "tasks": tasks,
        "timeline": timeline,
        "afterRace": snapshots,
        "assignedAfterRace": ids,
        "bindingsAfterRace": manager_bindings(host),
        "loserRetry": retry,
        "loserRetryAssigned": retry_ids,
        "assessment": {
            "winner": winner,
            "loser": loser,
            "taskWindows": queue_windows,
            "verdict": (
                "PASS"
                if winner is not None
                and len(ids[winner]) == 2
                and len(set(ids[winner])) == 2
                and not ids[loser]
                and retry is not None
                and retry["task"]["outcome"] == "success"
                and len(retry_ids) == 2
                else "FAIL"
            ),
            "meaning": (
                "Exactly one complete two-device assignment won; the loser had "
                "zero bindings and succeeded only after the winner released. "
                "Task timestamps determine whether this proves concurrent overlap "
                "or only externally serialized behavior."
            ),
        },
    }


def run_global_matching(
    datacenter: vim.Datacenter,
    host: vim.HostSystem,
    datastore: str,
    prefix: str,
    candidates: list[dict[str, Any]],
    vendor_id: int,
    device_id: int,
    poll_seconds: float,
    created: list[vim.VirtualMachine],
) -> dict[str, Any]:
    distinct = {
        (item["subVendorId"], item["subDeviceId"]): item for item in candidates
    }
    if len(distinct) != 2:
        return {
            "assessment": {
                "verdict": "BLOCKED_ENV",
                "reason": "global matching needs exactly two distinguishable subsystem tuples",
            }
        }
    tuples = sorted(distinct)
    exact_a = allowed_device(
        vendor_id,
        device_id,
        sub_vendor_id=tuples[0][0],
        sub_device_id=tuples[0][1],
    )
    exact_b = allowed_device(
        vendor_id,
        device_id,
        sub_vendor_id=tuples[1][0],
        sub_device_id=tuples[1][1],
    )
    variants = [
        ("flex-first-ab", [[exact_a, exact_b], [exact_a]]),
        ("flex-first-ba", [[exact_b, exact_a], [exact_a]]),
        ("exact-first", [[exact_a], [exact_a, exact_b]]),
    ]
    records: dict[str, Any] = {}
    for name, requirements in variants:
        vm = create_dynamic_vm(
            datacenter, host, datastore, f"{prefix}-{name}", requirements
        )
        created.append(vm)
        record = {"before": vm_snapshot(vm)}
        record["powerOn"] = power_on_observed(vm, host, poll_seconds)
        record["assigned"] = assigned_ids(vm)
        record["powerOff"] = power_off_observed(vm, host, poll_seconds)
        records[name] = record
    passed = all(
        item["powerOn"]["task"]["outcome"] == "success"
        and len(item["assigned"]) == 2
        and len(set(item["assigned"])) == 2
        for item in records.values()
    )
    return {
        "subsystemTuples": tuples,
        "variants": records,
        "assessment": {
            "verdict": "PASS" if passed else "FAIL",
            "meaning": (
                "Every greedy-trap permutation found the complete matching: the "
                "flexible requirement used B while the exact requirement used A. "
                "This proves complete-match behavior, not VMware's private algorithm."
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--case",
        action="append",
        choices=("lifecycle", "atomicity", "concurrency", "global"),
        help="repeat to select cases; default runs all",
    )
    parser.add_argument("--host", default="172.31.91.10")
    parser.add_argument("--caveat", default="esxi8-auto-codex-credentials")
    parser.add_argument("--datastore", default="pci-mmio-local")
    parser.add_argument("--vendor-id", type=lambda value: int(value, 0), default=0x8086)
    parser.add_argument("--device-id", type=lambda value: int(value, 0), default=0x10D3)
    parser.add_argument("--expected-build", default="24280767")
    parser.add_argument("--poll-ms", type=int, default=100)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    selected = args.case or ["lifecycle", "atomicity", "concurrency", "global"]
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    password = owner.caveat_field(args.caveat, "Password")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    service = SmartConnect(
        host=args.host,
        user="root",
        pwd=password,
        sslContext=context,
        connectionPoolTimeout=20,
    )
    atexit.register(Disconnect, service)
    content = service.RetrieveContent()
    host = owner.inventory(content, vim.HostSystem)[0]
    datacenter = owner.inventory(content, vim.Datacenter)[0]
    candidates = host_candidates(host, args.vendor_id, args.device_id)
    result: dict[str, Any] = {
        "schemaVersion": 1,
        "runId": output.name,
        "startedAt": utc_now(),
        "referenceBaseline": {
            "product": host.config.product.fullName,
            "build": host.config.product.build,
            "systemUuid": host.hardware.systemInfo.uuid,
        },
        "input": {
            "host": args.host,
            "vendorId": args.vendor_id,
            "deviceId": args.device_id,
            "cases": selected,
            "pollMs": args.poll_ms,
        },
        "candidates": candidates,
        "initialBindings": manager_bindings(host),
        "cases": {},
    }
    result_path = output / "result.json"

    def save() -> None:
        result["updatedAt"] = utc_now()
        result_path.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    save()
    if host.config.product.build != args.expected_build:
        raise RuntimeError(
            f"expected build {args.expected_build}, got {host.config.product.build}"
        )
    active = [item for item in candidates if item["active"]]
    if len(active) != 2:
        raise RuntimeError(f"expected exactly two active candidates, got {active}")
    generic = allowed_device(args.vendor_id, args.device_id)
    suffix = hashlib.sha256(output.name.encode()).hexdigest()[:8]
    prefix = f"dyn-{suffix}"
    poll_seconds = max(args.poll_ms, 20) / 1000
    stale_cleanup = [
        quiesce_and_destroy(vm)
        for vm in owner.inventory(content, vim.VirtualMachine)
        if vm.name.startswith(prefix)
    ]
    if stale_cleanup:
        result["staleCleanup"] = stale_cleanup
        save()
    created: list[vim.VirtualMachine] = []
    try:
        if "lifecycle" in selected:
            result["cases"]["VMW-DYN-LIFECYCLE-001"] = run_lifecycle(
                datacenter, host, args.datastore, prefix, generic, poll_seconds, created
            )
            save()
        if "atomicity" in selected:
            result["cases"]["VMW-DYN-ATOMIC-001"] = run_atomicity(
                datacenter, host, args.datastore, prefix, generic, poll_seconds, created
            )
            save()
        if "concurrency" in selected:
            result["cases"]["VMW-DYN-CONCURRENCY-001"] = run_concurrency(
                datacenter,
                host,
                args.datastore,
                prefix,
                generic,
                args.host,
                password,
                poll_seconds,
                created,
            )
            save()
        if "global" in selected:
            result["cases"]["VMW-DYN-GLOBAL-001"] = run_global_matching(
                datacenter,
                host,
                args.datastore,
                prefix,
                candidates,
                args.vendor_id,
                args.device_id,
                poll_seconds,
                created,
            )
            save()
    finally:
        cleanup: list[dict[str, Any]] = []
        for vm in reversed(created):
            cleanup.append(quiesce_and_destroy(vm))
        result["cleanup"] = cleanup
        result["finalBindings"] = manager_bindings(host)
        result["finishedAt"] = utc_now()
        save()

    verdicts = [
        record.get("assessment", {}).get("verdict")
        for record in result["cases"].values()
    ]
    result["verdict"] = (
        "PASS"
        if verdicts and all(item in ("PASS", "BLOCKED_ENV") for item in verdicts)
        else "FAIL"
    )
    save()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
