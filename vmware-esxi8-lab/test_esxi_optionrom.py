#!/usr/bin/env python3
"""Prove ESXi DirectPath EFI option-ROM execution on power-on and restart."""

from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
import re
import shutil
import socket
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
ROM_MARKER = "ESXI-DIRECTPATH-OPROM-EXECUTED"
STAGE_MAGIC = "53544147"
ROM_PATH = Path(
    os.environ.get(
        "QEMU_ESXI_TEST_ROMFILE",
        "/root/vm/esxi8-mf/optionrom/808610d3.efirom",
    )
)
OUTER_SERIAL = Path("/root/vm/esxi8-mf/serial.log")
TRACE_FILE = Path("/root/vm/esxi8-mf/qemu-trace.log")
ISO_NAME = "esxi-l3-reboot-probe.iso"
CASES = {
    "default-disabled": False,
    "enabled": True,
}


def save(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def start_outer_with_oprom(
    ssh: EsxiSsh,
    timeout: int,
    startup_log: Path,
) -> list[str]:
    return start_outer(
        {
            "QEMU_ESXI_TOPOLOGY": "pcie",
            "QEMU_ESXI_IVSHMEM_SIZE": "0",
            "QEMU_ESXI_IVSHMEM_ALT_SIZE": "0",
            "QEMU_ESXI_PCI_TESTDEV_MEMBAR_SIZE": "0",
            "QEMU_ESXI_EDU": "0",
            "QEMU_ESXI_VIRTIO_NET": "0",
            "QEMU_ESXI_TRACE": "1",
            "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
            "QEMU_ESXI_TEST_ROMFILE": str(ROM_PATH),
        },
        ssh,
        timeout,
        startup_log,
        boot_options=" pcipSaveOPROM=TRUE",
    ).splitlines()


def copy_if_present(source: Path, target: Path) -> None:
    if source.exists():
        shutil.copyfile(source, target)


def hmp_command(command: str) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as monitor:
        monitor.settimeout(3)
        monitor.connect(str(MONITOR))
        received = b""
        while b"(qemu)" not in received:
            received += monitor.recv(65536)
        monitor.sendall(command.encode("ascii") + b"\n")
        received = b""
        while b"(qemu)" not in received:
            received += monitor.recv(65536)
    return received.decode("utf-8", errors="replace")


def option_rom_marker_count() -> tuple[int, str]:
    response = hmp_command(
        "qom-get /machine/peripheral/test_fn0 option-rom-marker-count"
    )
    cleaned = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", response)
    values = [line.strip() for line in cleaned.replace("\r", "").splitlines()]
    numeric = [
        int(line, 0)
        for line in values
        if re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", line)
    ]
    if not numeric:
        raise RuntimeError(f"No marker counter in HMP response: {cleaned!r}")
    return numeric[-1], response


def option_rom_trace_lines() -> list[str]:
    if not TRACE_FILE.exists():
        return []
    return [
        line
        for line in decode_simpletrace(TRACE_FILE).splitlines()
        if line.startswith("e1000e_option_rom_marker ")
    ]


def run_vm(
    enabled: bool,
    output_dir: Path,
    content,
    datacenter,
    cluster,
    host,
    datastore: str,
    nfs_root: Path,
    timeout: int,
) -> dict[str, Any]:
    case_id = "enabled" if enabled else "default-disabled"
    case_dir = output_dir / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    vm_name = f"oprom-{output_dir.name}-{case_id}"
    relative_root = f"optionrom/{output_dir.name}/{case_id}"
    vm_root = nfs_root / relative_root / vm_name
    serial_path = vm_root / "guest-serial.log"
    vmware_log = vm_root / "vmware.log"
    vm = None
    record: dict[str, Any] = {"opromEnabled": enabled, "verdict": "running"}
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
        if enabled:
            extra.append('pciPassthru0.opromEnabled = "TRUE"')
        vmx_path = lab.write_vmx(
            vm_root,
            vm_name,
            f"/vmfs/volumes/{datastore}/iso/{ISO_NAME}",
            extra_lines=extra,
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
        marker_before, marker_before_raw = option_rom_marker_count()
        lab.wait_task(vm.PowerOnVM_Task(host=host))
        serial_wait_fault = None
        try:
            lab.wait_serial_marker(
                serial_path, "R01-REBOOT-COMPLETE", timeout=timeout
            )
        except TimeoutError as error:
            serial_wait_fault = error
        serial_text = serial_path.read_text(encoding="utf-8", errors="replace")
        rom_probes = [
            {
                "phase": match.group("phase"),
                "bdf": match.group("bdf"),
                "size": int(match.group("size")),
                "sha256": match.group("sha256"),
                "header": match.group("header"),
            }
            for match in re.finditer(
                r"^R01-ROM phase=(?P<phase>\S+) bdf=(?P<bdf>\S+) "
                r"size=(?P<size>\d+) sha256=(?P<sha256>\S+) "
                r"head=(?P<header>\S+)$",
                serial_text,
                re.MULTILINE,
            )
        ]
        stage_probes = [
            {
                "phase": match.group("phase"),
                "present": match.group("present") == "1",
                "attributes": match.group("attributes"),
                "magic": match.group("magic"),
                "value": match.group("value"),
                "size": int(match.group("size")),
            }
            for match in re.finditer(
                r"^R01-OPROM-STAGE phase=(?P<phase>\S+) "
                r"present=(?P<present>[01]) "
                r"attrs=(?P<attributes>\S+) magic=(?P<magic>\S+) "
                r"value=(?P<value>\S+) size=(?P<size>\d+)$",
                serial_text,
                re.MULTILINE,
            )
        ]
        stage_by_phase = {
            probe["phase"]: probe for probe in stage_probes
        }
        marker_after, marker_after_raw = option_rom_marker_count()
        marker_delta = marker_after - marker_before
        (case_dir / "outer-option-rom-counter.txt").write_text(
            f"before={marker_before}\nafter={marker_after}\n"
            f"delta={marker_delta}\n\n=== before raw ===\n"
            f"{marker_before_raw}\n=== after raw ===\n{marker_after_raw}",
            encoding="utf-8",
        )
        trace_snapshot = option_rom_trace_lines()
        (case_dir / "outer-option-rom-trace-snapshot.log").write_text(
            "\n".join(trace_snapshot) + ("\n" if trace_snapshot else ""),
            encoding="utf-8",
        )
        record["guest"] = {
            "romMarkerCount": serial_text.count(ROM_MARKER),
            "romProbes": rom_probes,
            "entryStageProbes": stage_probes,
            "outerOptionRomCounterBefore": marker_before,
            "outerOptionRomCounterAfter": marker_after,
            "outerOptionRomCounterDelta": marker_delta,
            "outerOptionRomTraceSnapshot": trace_snapshot,
            "firstPhase": "R01-PHASE=first" in serial_text,
            "secondPhase": "R01-PHASE=second" in serial_text,
            "rebootComplete": "R01-REBOOT-COMPLETE" in serial_text,
            "markerLines": [
                line for line in serial_text.splitlines() if ROM_MARKER in line
            ],
        }
        copy_if_present(serial_path, case_dir / "guest-serial.log")
        copy_if_present(vmware_log, case_dir / "vmware.log")
        copy_if_present(vm_root / f"{vm_name}.vmx", case_dir / "effective.vmx")
        vmware_text = (
            vmware_log.read_text(encoding="utf-8", errors="replace")
            if vmware_log.exists()
            else ""
        )
        record["vmwareLogExcerpt"] = [
            line
            for line in vmware_text.splitlines()
            if re.search(r"OPROM|option ROM|PCIPassthru", line, re.IGNORECASE)
        ][-500:]
        if serial_wait_fault is not None:
            record["fault"] = lab.fault_snapshot(serial_wait_fault)
            record["verdict"] = "blocked"
            return record
        if enabled:
            first_stage = stage_by_phase.get("first", {})
            second_stage = stage_by_phase.get("second", {})
            checks = {
                "entryObservedOnPowerOn": (
                    first_stage.get("present") is True
                    and first_stage.get("magic") == STAGE_MAGIC
                    and first_stage.get("value") == "00000001"
                    and first_stage.get("size") == 12
                ),
                "entryObservedOnRestart": (
                    second_stage.get("present") is True
                    and second_stage.get("magic") == STAGE_MAGIC
                    and second_stage.get("value") == "00000002"
                    and second_stage.get("size") == 12
                ),
                "hostCounterProvesPowerOnAndRestart": marker_delta == 2,
                "guestRestarted": (
                    record["guest"]["firstPhase"]
                    and record["guest"]["secondPhase"]
                    and record["guest"]["rebootComplete"]
                ),
            }
            entry_observed = (
                checks["entryObservedOnPowerOn"]
                and checks["entryObservedOnRestart"]
            )
            if entry_observed and marker_delta == 2:
                record["observationClassification"] = "entry-and-bar-observed"
            elif entry_observed:
                record["observationClassification"] = (
                    "entry-observed-bar-marker-missing"
                )
            else:
                record["observationClassification"] = "entry-not-observed"
        else:
            reported_phases = {probe["phase"] for probe in stage_probes}
            checks = {
                "romExecutionDisabledByDefault": marker_delta == 0,
                "entryStageAbsentOnPowerOnAndRestart": (
                    reported_phases == {"first", "second"}
                    and all(not probe["present"] for probe in stage_probes)
                ),
                "guestRestarted": record["guest"]["rebootComplete"],
            }
            record["observationClassification"] = (
                "entry-disabled" if all(checks.values()) else "unexpected"
            )
        record["checks"] = checks
        record["verdict"] = "pass" if all(checks.values()) else "fail"
    except Exception as error:
        record["fault"] = lab.fault_snapshot(error)
        record["verdict"] = "blocked"
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
    parser.add_argument("--cases", nargs="+", choices=CASES, default=list(CASES))
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
        "case": "S01-ESXi-DirectPath-EFI-option-ROM",
        "startedAt": utc_now(),
        "rom": {
            "path": str(ROM_PATH),
            "sha256": hashlib.sha256(ROM_PATH.read_bytes()).hexdigest(),
            "targetPciId": "8086:10d3",
            "marker": ROM_MARKER,
            "stageVariable": {
                "name": "PciOpromStage",
                "guid": "7f0b5e31-4381-4c45-9a7e-52119f628431",
                "magic": STAGE_MAGIC,
            },
        },
        "casesRequested": args.cases,
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
    if not ROM_PATH.exists() or not source_iso.exists():
        raise FileNotFoundError("option ROM or reboot probe ISO is missing")
    target_iso.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_iso, target_iso)

    service_instance = None
    try:
        stop_outer(ssh)
        result["esxiVersion"] = start_outer_with_oprom(
            ssh,
            args.timeout,
            output_dir / "outer-start.log",
        )
        result["nfsDatastore"] = ensure_nfs_datastore(ssh, args.datastore)
        outer_marker_count, outer_marker_raw = option_rom_marker_count()
        result["outerFirmwareOptionRomMarkerCount"] = outer_marker_count
        result["outerFirmwareOptionRomExecuted"] = outer_marker_count >= 1
        (output_dir / "outer-option-rom-counter.txt").write_text(
            outer_marker_raw, encoding="utf-8"
        )
        outer_text = OUTER_SERIAL.read_text(encoding="utf-8", errors="replace")
        result["outerSerialRomMarkerCount"] = outer_text.count(ROM_MARKER)
        shutil.copyfile(OUTER_SERIAL, output_dir / "outer-serial.log")
        capability = collect_case(
            output_dir / "capability",
            case_id="optionrom-host",
            host=args.host,
            user="root",
            password=esxi_password,
            qemu_name="esxi8-a",
            monitor=MONITOR,
            targets=[TARGET_BDF, RESET_PEER_BDF, ROOT_PORT_BDF],
            requested={
                "bootOption": "pcipSaveOPROM=TRUE",
                "rom": result["rom"],
            },
        )
        result["capability"] = {
            bdf: capability["devices"].get(bdf, {}).get("esxcli")
            for bdf in (TARGET_BDF, RESET_PEER_BDF)
        }
        kernel_setting = ssh.run(
            "esxcli system settings kernel list -o pcipSaveOPROM 2>&1 || true",
            check=False,
            timeout=60,
        )
        (output_dir / "pcipSaveOPROM-setting.txt").write_text(
            kernel_setting.stdout + kernel_setting.stderr,
            encoding="utf-8",
        )
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
        for case_id in args.cases:
            enabled = CASES[case_id]
            result["cases"][case_id] = run_vm(
                enabled,
                output_dir,
                content,
                datacenter,
                cluster,
                host,
                args.datastore,
                nfs_root,
                args.timeout,
            )
            save(result_path, result)
        result["verdict"] = (
            "pass"
            if result["outerFirmwareOptionRomExecuted"]
            and all(
                case["verdict"] == "pass"
                for case in result["cases"].values()
            )
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
