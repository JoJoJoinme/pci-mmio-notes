#!/usr/bin/env python3
"""Observe ESXi DirectPath handling of a controlled PCIe PME message."""

from __future__ import annotations

import argparse
import atexit
import hashlib
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
    hmp_command,
    utc_now,
)
from qemu_simpletrace import decode_simpletrace
from test_esxi_flr_reset import connect_vcenter, wait_connected_host
from test_esxi_passthru_capability_matrix import (
    CAPABILITY_QEMU,
    MONITOR,
    RESTORE_ENV,
    start_outer,
    stop_outer,
)


TARGET_BDF = "0000:01:00.0"
RESET_PEER_BDF = "0000:01:00.1"
ROOT_PORT_BDF = "0000:00:08.0"
ISO_NAME = "esxi-l3-pme-probe.iso"
TRACE_FILE = Path("/root/vm/esxi8-mf/qemu-trace.log")
PME_TRACE_EVENTS = Path(__file__).resolve().parent / "qemu-esxi8-pme-trace-events"
QOM_PATH = "/machine/peripheral/test_fn0"
CASES = (
    {
        "id": "default",
        "osc": None,
        "expectedNativePmeGrant": True,
    },
    {
        "id": "explicit-all-0x1f",
        "osc": "31",
        "expectedNativePmeGrant": True,
    },
    {
        "id": "deny-pme-0x1b",
        "osc": "27",
        "expectedNativePmeGrant": False,
    },
)


def save(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def copy_if_present(source: Path, target: Path) -> None:
    if source.exists():
        shutil.copyfile(source, target)


def parse_hmp_bool(text: str) -> bool | None:
    matches = re.findall(r"(?im)^\s*(true|false)\s*$", text)
    if not matches:
        return None
    return matches[-1].lower() == "true"


def qom_snapshot(case_dir: Path, label: str) -> dict[str, Any]:
    properties = (
        "x-pme-enabled",
        "x-pme-status",
        "x-upstream-pme-enabled",
        "x-upstream-pme-status",
    )
    snapshot: dict[str, Any] = {}
    raw_parts = []
    for prop in properties:
        raw = hmp_command(MONITOR, f"qom-get {QOM_PATH} {prop}")
        raw_parts.append(f"=== {prop} ===\n{raw}")
        snapshot[prop] = parse_hmp_bool(raw)
    (case_dir / f"qom-{label}.txt").write_text(
        "\n".join(raw_parts),
        encoding="utf-8",
    )
    return snapshot


def inject_pme(case_dir: Path) -> str:
    output = hmp_command(MONITOR, f"qom-set {QOM_PATH} x-pme-inject true")
    (case_dir / "qom-inject.txt").write_text(output, encoding="utf-8")
    return output


def pme_trace_lines() -> list[str]:
    if not TRACE_FILE.exists():
        return []
    decoded = decode_simpletrace(TRACE_FILE)
    return [
        line for line in decoded.splitlines()
        if line.startswith("e1000e_pme_inject ")
    ]


def write_trace(path: Path, lines: list[str]) -> None:
    path.write_text(
        "\n".join(lines) + ("\n" if lines else ""),
        encoding="utf-8",
    )


def pmcsr_values(serial_text: str) -> dict[str, list[int]]:
    values: dict[str, list[int]] = {"auto": [], "armed": [], "poll": [], "final": []}
    patterns = {
        "auto": r"^PME-AUTO .*endpoint_pmcsr=([0-9a-fA-F]{4})$",
        "armed": r"^PME-ARMED .*endpoint_pmcsr=([0-9a-fA-F]{4})$",
        "poll": r"^PME-POLL .*endpoint_pmcsr=([0-9a-fA-F]{4})$",
        "final": r"^PME-FINAL endpoint_pmcsr=([0-9a-fA-F]{4})$",
    }
    for key, pattern in patterns.items():
        values[key] = [int(item, 16) for item in re.findall(pattern, serial_text, re.MULTILINE)]
    return values


def native_pme_granted(serial_text: str) -> bool | None:
    lines = [
        line for line in serial_text.splitlines()
        if "OS now controls" in line
    ]
    if not lines:
        return None
    return any(re.search(r"\bPME\b", line) for line in lines)


def interrupt_count(serial_text: str, heading: str) -> int | None:
    start = serial_text.find(heading)
    if start < 0:
        return None
    start += len(heading)
    next_heading = serial_text.find("\n=== ", start)
    section = serial_text[start: next_heading if next_heading >= 0 else None]
    total = 0
    matched = False
    for line in section.splitlines():
        if "PCIe PME" not in line:
            continue
        match = re.match(r"^\s*\d+:\s+((?:\d+\s+)+)", line)
        if not match:
            continue
        total += sum(int(value) for value in match.group(1).split())
        matched = True
    return total if matched else None


def collect_host_log(ssh: EsxiSsh, path: Path) -> list[str]:
    command = (
        "tail -n 1800 /var/log/vmkernel.log /var/log/vobd.log "
        "/var/log/hostd.log /var/log/vpxa.log 2>/dev/null | "
        "grep -Eai 'PME|Power Management|PCIPassthru|0000:01:00.0|01:00.0' || true"
    )
    completed = ssh.run(command, check=False, timeout=90)
    text = completed.stdout + completed.stderr
    path.write_text(text, encoding="utf-8")
    return text.splitlines()[-1000:]


def run_case(
    case: dict[str, Any],
    output_dir: Path,
    ssh: EsxiSsh,
    content,
    datacenter,
    cluster,
    host,
    datastore: str,
    nfs_root: Path,
    timeout: int,
    firmware: str,
) -> dict[str, Any]:
    case_id = case["id"]
    case_dir = output_dir / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    vm_name = f"pme-{output_dir.name}-{case_id}"
    relative_root = f"pme/{output_dir.name}/{case_id}"
    vm_root = nfs_root / relative_root / vm_name
    serial_path = vm_root / "guest-serial.log"
    vmware_log = vm_root / "vmware.log"
    vm = None
    record: dict[str, Any] = {
        "acpiOscPcie": case["osc"],
        "expectedNativePmeGrant": case["expectedNativePmeGrant"],
        "verdict": "running",
    }
    try:
        existing = [
            item for item in lab.inventory(content, vim.VirtualMachine)
            if item.name == vm_name
        ]
        if existing:
            lab.power_off(existing[0])
            existing[0].UnregisterVM()

        extra = lab.static_pci_lines(host, TARGET_BDF, index=0)
        extra.extend(lab.static_pci_lines(host, RESET_PEER_BDF, index=1))
        if case["osc"] is not None:
            extra.append(f'acpi.osc.pcie = "{case["osc"]}"')
        vmx_path = lab.write_vmx(
            vm_root,
            vm_name,
            f"/vmfs/volumes/{datastore}/iso/{ISO_NAME}",
            extra_lines=extra,
            firmware=firmware,
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
        serial_path.unlink(missing_ok=True)

        trace_before = pme_trace_lines()
        lab.wait_task(vm.PowerOnVM_Task(host=host))
        lab.wait_serial_marker(serial_path, "PME-ARMED", timeout=timeout)
        record["qomBeforeInject"] = qom_snapshot(case_dir, "before-inject")
        record["injectOutput"] = inject_pme(case_dir)
        record["qomImmediatelyAfterInject"] = qom_snapshot(case_dir, "after-inject")
        time.sleep(3)
        record["qomAfterThreeSeconds"] = qom_snapshot(case_dir, "after-3s")
        lab.wait_serial_marker(serial_path, "PME-PROBE-COMPLETE", timeout=timeout)

        trace_after = pme_trace_lines()
        trace_delta = trace_after[len(trace_before):]
        write_trace(case_dir / "outer-pme-trace-delta.log", trace_delta)
        serial_text = serial_path.read_text(encoding="utf-8", errors="replace")
        copy_if_present(serial_path, case_dir / "guest-serial.log")
        copy_if_present(vmware_log, case_dir / "vmware.log")
        copy_if_present(vm_root / f"{vm_name}.vmx", case_dir / "effective.vmx")
        host_lines = collect_host_log(ssh, case_dir / "host-pme.log")

        values = pmcsr_values(serial_text)
        irq_before = interrupt_count(serial_text, "=== interrupts before arm ===")
        irq_after = interrupt_count(serial_text, "=== interrupts after injection window ===")
        irq_delta = (
            irq_after - irq_before
            if irq_before is not None and irq_after is not None
            else None
        )
        grant = native_pme_granted(serial_text)
        guest_saw_status = any(
            value & 0x8000
            for key in ("poll", "final")
            for value in values[key]
        )
        record["observation"] = {
            "nativePmeGranted": grant,
            "pmcsr": values,
            "guestSawEndpointPmeStatus": guest_saw_status,
            "guestPciePmeIrqBefore": irq_before,
            "guestPciePmeIrqAfter": irq_after,
            "guestPciePmeIrqDelta": irq_delta,
            "outerTraceDelta": trace_delta,
            "hostLogExcerpt": host_lines,
        }
        record["checks"] = {
            "guestCompleted": "PME-PROBE-COMPLETE" in serial_text,
            "guestArmedPhysicalFunction": bool(values["armed"])
            and bool(values["armed"][-1] & 0x0100),
            "qemuObservedFunctionEnabled": record["qomBeforeInject"].get(
                "x-pme-enabled"
            ) is True,
            "qemuEndpointStatusSet": record["qomAfterThreeSeconds"].get(
                "x-pme-status"
            ) is True,
            "qemuRootStatusSet": record["qomAfterThreeSeconds"].get(
                "x-upstream-pme-status"
            ) is True,
        }
        record["diagnosticChecks"] = {
            "qemuTraceVisibleBeforeOuterStop": len(trace_delta) == 1,
        }
        record["semanticChecks"] = {
            "oscGrantMatchesRequestedMask": (
                grant == case["expectedNativePmeGrant"]
                if grant is not None
                else None
            ),
            "noGuestNativePmeInterruptDelta": irq_delta in (None, 0),
            "matchesKbIgnoredPmeModel": (
                record["qomAfterThreeSeconds"].get("x-upstream-pme-status") is True
                and irq_delta in (None, 0)
            ),
        }
        record["verdict"] = (
            "pass" if all(record["checks"].values()) else "fail"
        )
    except Exception as error:
        record["fault"] = lab.fault_snapshot(error)
        record["bootDiagnostics"] = {
            "serialExists": serial_path.exists(),
            "serialBytes": serial_path.stat().st_size if serial_path.exists() else 0,
            "vmwareLogExists": vmware_log.exists(),
            "vmwareLogBytes": vmware_log.stat().st_size if vmware_log.exists() else 0,
        }
        record["verdict"] = "blocked"
    finally:
        copy_if_present(serial_path, case_dir / "guest-serial.log")
        copy_if_present(vmware_log, case_dir / "vmware.log")
        copy_if_present(vm_root / f"{vm_name}.vmx", case_dir / "effective.vmx")
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
    parser.add_argument(
        "--cases",
        nargs="+",
        choices=[case["id"] for case in CASES],
        default=[case["id"] for case in CASES],
    )
    parser.add_argument("--firmware", choices=("efi", "bios"), default="efi")
    parser.add_argument("--no-restore", action="store_true")
    args = parser.parse_args()

    for name in (
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
        "http_proxy", "https_proxy", "all_proxy",
    ):
        os.environ.pop(name, None)
    os.environ["NO_PROXY"] = ",".join((args.vcenter, args.host))

    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    result_path = output_dir / "result.json"
    result: dict[str, Any] = {
        "runId": output_dir.name,
        "case": "S02-ESXi-DirectPath-PCIe-PME",
        "startedAt": utc_now(),
        "target": TARGET_BDF,
        "firmware": args.firmware,
        "acpiOscControlBit": {
            "bit": 2,
            "meaning": "PCI Express Native Power Management Events control",
        },
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
        raise FileNotFoundError(f"missing PME probe ISO: {source_iso}")
    target_iso.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_iso, target_iso)

    service_instance = None
    try:
        stop_outer(ssh)
        env = {
            "QEMU_ESXI_TOPOLOGY": "pcie",
            "QEMU_ESXI_IVSHMEM_SIZE": "0",
            "QEMU_ESXI_IVSHMEM_ALT_SIZE": "0",
            "QEMU_ESXI_PCI_TESTDEV_MEMBAR_SIZE": "0",
            "QEMU_ESXI_EDU": "0",
            "QEMU_ESXI_VIRTIO_NET": "0",
            "QEMU_ESXI_TRACE": "1",
            "QEMU_ESXI_TRACE_EVENTS": str(PME_TRACE_EVENTS),
            "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
        }
        result["esxiVersion"] = start_outer(
            env,
            ssh,
            args.timeout,
            output_dir / "outer-start.log",
        ).splitlines()
        result["nfsDatastore"] = ensure_nfs_datastore(ssh, args.datastore)
        capability = collect_case(
            output_dir / "capability",
            case_id="pme-host",
            host=args.host,
            user="root",
            password=esxi_password,
            qemu_name="esxi8-a",
            monitor=MONITOR,
            targets=[TARGET_BDF, RESET_PEER_BDF, ROOT_PORT_BDF],
            requested={"purpose": "controlled PCIe PME message observation"},
        )
        result["capability"] = {
            bdf: capability["devices"].get(bdf, {}).get("esxcli")
            for bdf in (TARGET_BDF, RESET_PEER_BDF)
        }
        result["enablePassthru"] = {}
        for bdf in (TARGET_BDF, RESET_PEER_BDF):
            enable = ssh.run(
                f"esxcli hardware pci pcipassthru set -d {bdf} -e true -a",
                check=False,
                timeout=90,
            )
            result["enablePassthru"][bdf] = {
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

        selected_cases = [case for case in CASES if case["id"] in args.cases]
        for case in selected_cases:
            result["cases"][case["id"]] = run_case(
                case,
                output_dir,
                ssh,
                content,
                datacenter,
                cluster,
                host,
                args.datastore,
                nfs_root,
                args.timeout,
                args.firmware,
            )
            save(result_path, result)

        # The simple trace backend flushes buffered records when QEMU exits.
        # Stop the purpose-built outer instance before decoding, then let the
        # normal finally block restore the baseline topology.
        stop_outer(ssh)
        result["experimentalOuterStoppedAt"] = utc_now()
        trace_bytes = TRACE_FILE.read_bytes() if TRACE_FILE.exists() else b""
        injection_lines = pme_trace_lines()
        result["outerTrace"] = {
            "path": str(TRACE_FILE),
            "size": len(trace_bytes),
            "sha256": hashlib.sha256(trace_bytes).hexdigest(),
            "injectionLines": injection_lines,
            "expectedInjectionCount": len(selected_cases),
        }
        exact_trace_count = len(injection_lines) == len(selected_cases)
        for index, case in enumerate(selected_cases):
            record = result["cases"][case["id"]]
            case_trace = [injection_lines[index]] if exact_trace_count else []
            record["observation"]["outerTraceAfterStop"] = case_trace
            record["checks"]["qemuTraceRecordedAfterStop"] = len(case_trace) == 1
            record["semanticChecks"]["matchesKbIgnoredPmeModel"] = (
                len(case_trace) == 1
                and record["qomAfterThreeSeconds"].get(
                    "x-upstream-pme-status"
                ) is True
                and record["observation"]["guestPciePmeIrqDelta"] in (None, 0)
            )
            record["verdict"] = (
                "pass" if all(record["checks"].values()) else "fail"
            )
        result["verdict"] = (
            "pass"
            if all(item["verdict"] == "pass" for item in result["cases"].values())
            else "fail"
        )
    except Exception as error:
        result["fault"] = lab.fault_snapshot(error)
        result["verdict"] = "blocked"
    finally:
        if service_instance is not None:
            Disconnect(service_instance)
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

    result["finishedAt"] = utc_now()
    save(result_path, result)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
