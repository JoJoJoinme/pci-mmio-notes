#!/usr/bin/env python3
"""Observe ESXi DirectPath handling of endpoint-scoped ACPI RMRRs."""

from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

from pyVim.connect import Disconnect
from pyVmomi import vim

import test_esxi_vmotion_matrix as lab
from esxi_passthru_capability import (
    EsxiSsh,
    caveat_field,
    collect_case,
    ensure_nfs_datastore,
    utc_now,
)
from test_esxi_flr_reset import connect_vcenter, wait_connected_host
from test_esxi_passthru_capability_matrix import (
    CAPABILITY_QEMU,
    MONITOR,
    RESTORE_ENV,
    qemu_pid,
    start_outer,
    stop_outer,
)


TARGET_BDF = "0000:01:01.0"
ROOT_PORT_BDF = "0000:00:08.0"
ISO_NAME = "esxi-l3-rmrr-probe.iso"
OUTER_SERIAL = Path("/root/vm/esxi8-mf/serial.log")
OUTER_QEMU_LOG = Path("/root/vm/esxi8-mf/qemu.log")
OUTER_TRACE = Path("/root/vm/esxi8-mf/qemu-trace.log")

CASES: dict[str, dict[str, Any]] = {
    "bios-reserved": {
        "base": 0x000F0000,
        "limit": 0x000FFFFF,
        "rangeClass": "VM BIOS reserved memory (640K-1MB)",
        "expected": "l3-power-on",
    },
    "automatic-pci-hole": {
        "base": 0x40000000,
        "limit": 0x401FFFFF,
        "rangeClass": "below 4GB in the 256MB-4GB automatic-adjustment range",
        "expected": "l3-power-on",
        "outerEnv": {"QEMU_ESXI_MAX_RAM_BELOW_4G": "1G"},
    },
    "unsupported-low-ram": {
        "base": 0x01000000,
        "limit": 0x011FFFFF,
        "rangeClass": "between 1MB and 256MB, overlapping host System RAM",
        "expected": "host-or-l3-reject",
        "bootTimeout": 300,
    },
}


def save(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def rmrr_env(case: dict[str, Any]) -> dict[str, str]:
    result = {
        "QEMU_ESXI_TOPOLOGY": "pcie",
        "QEMU_ESXI_IVSHMEM_SIZE": "0",
        "QEMU_ESXI_IVSHMEM_ALT_SIZE": "0",
        "QEMU_ESXI_PCI_TESTDEV_MEMBAR_SIZE": "0",
        "QEMU_ESXI_EDU": "0",
        "QEMU_ESXI_VIRTIO_NET": "1",
        "QEMU_ESXI_VIRTIO_FLR": "on",
        "QEMU_ESXI_TRACE": "1",
        "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
        "QEMU_ESXI_IOMMU_OPTIONS": (
            f",x-rmrr-base=0x{case['base']:x}"
            f",x-rmrr-limit=0x{case['limit']:x}"
            ",x-rmrr-sid=0x0108"
        ),
    }
    result.update(case.get("outerEnv", {}))
    return result


def copy_if_present(source: Path, target: Path) -> None:
    if source.exists():
        shutil.copyfile(source, target)


def collect_host_rmrr_log(ssh: EsxiSsh, path: Path) -> None:
    command = (
        "grep -Eai 'RMRR|reserved memory|memory region|overlap|DMAR' "
        "/var/log/vmkernel.log /var/log/hostd.log /var/log/syslog.log "
        "2>/dev/null | tail -n 1200 || true"
    )
    completed = ssh.run(command, check=False, timeout=90)
    path.write_text(completed.stdout + completed.stderr, encoding="utf-8")


def wait_terminal(vm, serial_path: Path, timeout: int) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if serial_path.exists():
            text = serial_path.read_text(encoding="utf-8", errors="replace")
            if "RMRR-PROBE-COMPLETE" in text:
                return "guest-complete"
        vm.Reload()
        if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOff:
            return "vm-powered-off"
        time.sleep(2)
    return "timeout"


def vmware_excerpt(path: Path) -> list[str]:
    if not path.exists():
        return []
    pattern = re.compile(
        r"RMRR|reserved|overlap|PCIPassthru|pciHole|memory region|DevicePowerOn",
        re.IGNORECASE,
    )
    return [
        line
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if pattern.search(line)
    ][-700:]


def run_l3(
    case_id: str,
    case: dict[str, Any],
    case_dir: Path,
    content,
    datacenter,
    cluster,
    host,
    datastore: str,
    nfs_root: Path,
    timeout: int,
) -> dict[str, Any]:
    vm_name = f"rmrr-{case_dir.parent.name}-{case_id}"
    relative_root = f"rmrr/{case_dir.parent.name}/{case_id}"
    vm_root = nfs_root / relative_root / vm_name
    serial_path = vm_root / "guest-serial.log"
    vmware_log = vm_root / "vmware.log"
    record: dict[str, Any] = {"vmName": vm_name, "powerOnSucceeded": False}
    vm = None
    try:
        existing = [
            item for item in lab.inventory(content, vim.VirtualMachine)
            if item.name == vm_name
        ]
        if existing:
            lab.power_off(existing[0])
            existing[0].UnregisterVM()

        extra = lab.static_pci_lines(host, TARGET_BDF, index=0)
        vmx_path = lab.write_vmx(
            vm_root,
            vm_name,
            f"/vmfs/volumes/{datastore}/iso/{ISO_NAME}",
            extra_lines=extra,
            memory_mb=2048,
        )
        vm = lab.register_vm(
            datacenter,
            cluster,
            host,
            datastore,
            f"{relative_root}/{vm_name}/{vmx_path.name}",
            vm_name,
        )
        record["configured"] = lab.vm_snapshot(vm)
        if serial_path.exists():
            serial_path.unlink()
        try:
            lab.wait_task(vm.PowerOnVM_Task(host=host))
            record["powerOnSucceeded"] = True
            record["terminalReason"] = wait_terminal(vm, serial_path, timeout)
        except Exception as error:
            record["powerOnFault"] = lab.fault_snapshot(error)
            record["terminalReason"] = "power-on-rejected"

        serial_text = (
            serial_path.read_text(encoding="utf-8", errors="replace")
            if serial_path.exists()
            else ""
        )
        requested_range = f"{case['base']:08x}-{case['limit']:08x}"
        range_lines = []
        for line in serial_text.splitlines():
            match = re.match(
                r"^\s*([0-9a-f]+)-([0-9a-f]+)\s*:\s*(.+)$",
                line,
                re.IGNORECASE,
            )
            if not match:
                continue
            start, end = int(match.group(1), 16), int(match.group(2), 16)
            if start <= case["base"] and case["limit"] <= end:
                range_lines.append(line)
        record["guest"] = {
            "complete": "RMRR-PROBE-COMPLETE" in serial_text,
            "dmarPresent": "DMAR-RAW-BEGIN" in serial_text,
            "targetBdf": next(
                iter(re.findall(r"(?m)^target_bdf=(.+)$", serial_text)),
                None,
            ),
            "requestedRange": requested_range,
            "requestedRangeLines": range_lines,
            "overlapsSystemRam": any("System RAM" in line for line in range_lines),
        }
        copy_if_present(serial_path, case_dir / "guest-serial.log")
        copy_if_present(vmware_log, case_dir / "vmware.log")
        copy_if_present(vm_root / f"{vm_name}.vmx", case_dir / "effective.vmx")
        record["vmwareLogExcerpt"] = vmware_excerpt(vmware_log)

        if case["expected"] == "l3-power-on":
            vmware_text = "\n".join(record["vmwareLogExcerpt"])
            checks = {
                "powerOnSucceeded": record["powerOnSucceeded"],
                "guestCompleted": record["guest"]["complete"],
                "hostRecognizedRmrr": "Device has 1 RMRRs" in vmware_text,
                "hostCreatedIommuMappings": (
                    "successfully created the IOMMU mappings" in vmware_text
                ),
                "requestedRangeRepresented": bool(range_lines),
                "rmrrDoesNotOverlapGuestSystemRam": not record["guest"][
                    "overlapsSystemRam"
                ],
            }
        else:
            combined = json.dumps(record, ensure_ascii=False)
            checks = {
                "rejectedBeforeGuestCompletion": not record["guest"]["complete"],
                "observableRejection": (
                    not record["powerOnSucceeded"]
                    or bool(
                        re.search(
                            r"overlap|memory region|RMRR|not capable|DevicePowerOn",
                            combined,
                            re.IGNORECASE,
                        )
                    )
                ),
            }
        record["checks"] = checks
        record["verdict"] = "pass" if all(checks.values()) else "fail"
    finally:
        if vm is not None:
            try:
                lab.power_off(vm)
            except Exception as error:
                record["cleanupPowerFault"] = lab.fault_snapshot(error)
            try:
                vm.UnregisterVM()
            except Exception as error:
                record["cleanupUnregisterFault"] = lab.fault_snapshot(error)
    return record


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
    parser.add_argument("--timeout", type=int, default=720)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cases", nargs="+", default=list(CASES))
    parser.add_argument("--no-restore", action="store_true")
    args = parser.parse_args()

    unknown = sorted(set(args.cases) - set(CASES))
    if unknown:
        parser.error(f"unknown cases: {', '.join(unknown)}")
    for name in (
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
        "http_proxy", "https_proxy", "all_proxy",
    ):
        os.environ.pop(name, None)
    os.environ["NO_PROXY"] = ",".join((args.vcenter, args.host))

    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    result_path = output_dir / "matrix-result.json"
    result: dict[str, Any] = {
        "runId": output_dir.name,
        "case": "S03-ESXi-DirectPath-RMRR-range-matrix",
        "startedAt": utc_now(),
        "targetBdf": TARGET_BDF,
        "cases": {},
        "verdict": "running",
    }
    save(result_path, result)

    esxi_password = caveat_field(args.esxi_caveat, "Password")
    vcsa_user = caveat_field(args.vcsa_caveat, "SSO Username")
    vcsa_password = caveat_field(args.vcsa_caveat, "SSO Password")
    ssh = EsxiSsh(args.host, esxi_password)
    nfs_root = Path(args.nfs_root)
    source_iso = Path("/mnt/e/Code/PCI/_artifacts") / ISO_NAME
    target_iso = nfs_root / "iso" / ISO_NAME
    if not source_iso.exists():
        raise FileNotFoundError(f"missing RMRR probe ISO: {source_iso}")
    target_iso.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_iso, target_iso)

    try:
        for case_id in args.cases:
            case = CASES[case_id]
            case_dir = output_dir / case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            record: dict[str, Any] = {
                "startedAt": utc_now(),
                "range": {
                    "base": f"0x{case['base']:x}",
                    "limit": f"0x{case['limit']:x}",
                    "class": case["rangeClass"],
                },
                "expected": case["expected"],
                "verdict": "running",
            }
            result["cases"][case_id] = record
            save(result_path, result)
            service_instance = None
            try:
                stop_outer(ssh)
                env = rmrr_env(case)
                record["outerEnv"] = env
                record["esxiVersion"] = start_outer(
                    env,
                    ssh,
                    case.get("bootTimeout", args.timeout),
                    case_dir / "outer-start.log",
                ).splitlines()
                record["nfsDatastore"] = ensure_nfs_datastore(
                    ssh, args.datastore
                )
                collect_host_rmrr_log(ssh, case_dir / "host-rmrr.log")
                capability = collect_case(
                    case_dir / "capability",
                    case_id=case_id,
                    host=args.host,
                    user="root",
                    password=esxi_password,
                    qemu_name="esxi8-a",
                    monitor=MONITOR,
                    targets=[TARGET_BDF, ROOT_PORT_BDF],
                    requested={"rmrr": record["range"], "env": env},
                )
                device = capability["devices"].get(TARGET_BDF, {})
                record["capability"] = device.get("esxcli")

                enable = ssh.run(
                    f"esxcli hardware pci pcipassthru set -d {TARGET_BDF} -e true -a",
                    check=False,
                    timeout=90,
                )
                record["enablePassthru"] = {
                    "exitCode": enable.returncode,
                    "output": enable.stdout + enable.stderr,
                }
                time.sleep(3)

                service_instance = connect_vcenter(
                    args.vcenter,
                    vcsa_user,
                    vcsa_password,
                    args.timeout,
                )
                atexit.register(Disconnect, service_instance)
                content = service_instance.RetrieveContent()
                host = wait_connected_host(content, args.host, args.timeout)
                host = lab.wait_host_hardware(host, TARGET_BDF, args.timeout)
                datacenter = lab.ensure_datacenter(content, args.datacenter)
                cluster = lab.ensure_cluster(datacenter, args.cluster)
                record["l3"] = run_l3(
                    case_id,
                    case,
                    case_dir,
                    content,
                    datacenter,
                    cluster,
                    host,
                    args.datastore,
                    nfs_root,
                    args.timeout,
                )
                record["verdict"] = record["l3"]["verdict"]
            except Exception as error:
                record["fault"] = lab.fault_snapshot(error)
                for source, name in (
                    (OUTER_SERIAL, "outer-serial.log"),
                    (OUTER_QEMU_LOG, "outer-qemu.log"),
                    (OUTER_TRACE, "outer-qemu-trace.log"),
                ):
                    copy_if_present(source, case_dir / name)
                if (
                    case["expected"] == "host-or-l3-reject"
                    and isinstance(error, TimeoutError)
                ):
                    serial_size = OUTER_SERIAL.stat().st_size if OUTER_SERIAL.exists() else 0
                    record["rejectionStage"] = "esxi-host-boot"
                    record["hostBoot"] = {
                        "sshReady": False,
                        "outerQemuAliveAtTimeout": qemu_pid() is not None,
                        "outerSerialBytes": serial_size,
                    }
                    record["checks"] = {
                        "hostRejectedBeforeL3": True,
                        "outerQemuWasRunning": qemu_pid() is not None,
                        "esxiProducedBootSerial": serial_size > 0,
                    }
                    record["verdict"] = (
                        "pass" if all(record["checks"].values()) else "blocked"
                    )
                else:
                    record["verdict"] = "blocked"
            finally:
                if service_instance is not None:
                    Disconnect(service_instance)
                record["finishedAt"] = utc_now()
                save(result_path, result)
    finally:
        if not args.no_restore:
            restore: dict[str, Any] = {"startedAt": utc_now()}
            result["restore"] = restore
            save(result_path, result)
            try:
                stop_outer(ssh)
                restore["esxiVersion"] = start_outer(
                    RESTORE_ENV,
                    ssh,
                    args.timeout,
                    output_dir / "restore-start.log",
                ).splitlines()
                restore["nfsDatastore"] = ensure_nfs_datastore(
                    ssh, args.datastore
                )
                restore["verdict"] = "pass"
            except Exception as error:
                restore["fault"] = lab.fault_snapshot(error)
                restore["verdict"] = "blocked"
            restore["finishedAt"] = utc_now()

    verdicts = [case["verdict"] for case in result["cases"].values()]
    result["verdict"] = (
        "pass" if verdicts and all(verdict == "pass" for verdict in verdicts)
        else "fail"
    )
    result["finishedAt"] = utc_now()
    save(result_path, result)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
