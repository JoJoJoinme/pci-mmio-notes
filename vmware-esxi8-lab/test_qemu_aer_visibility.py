#!/usr/bin/env python3
"""Validate the opt-in QEMU surface matching ESXi DirectPath AER visibility."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from esxi_passthru_capability import hmp_command


CASES = (
    {"id": "ovmf-default", "firmware": "ovmf", "hidden": False},
    {"id": "ovmf-vmware-profile", "firmware": "ovmf", "hidden": True},
    {"id": "seabios-vmware-profile", "firmware": "seabios", "hidden": True},
)


def save(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def wait_marker(
    path: Path,
    marker: str,
    timeout: int,
    process: subprocess.Popen | None = None,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and marker in path.read_text(
            encoding="utf-8", errors="replace"
        ):
            return
        if process is not None and process.poll() is not None:
            raise RuntimeError(
                f"QEMU exited with {process.returncode} before marker {marker!r}"
            )
        time.sleep(0.2)
    raise TimeoutError(f"marker {marker!r} not found in {path}")


def parse_surfaces(text: str, phase: str) -> list[dict[str, Any]]:
    pattern = re.compile(
        rf"^AER-SURFACE phase={phase} kind=(\w+) bdf=(\S+) "
        r"vendor=(\S+) device=(\S+) header=0x([0-9a-fA-F]+) "
        r"ues=0x([0-9a-fA-F]+) ces=0x([0-9a-fA-F]+) "
        r"root_status=0x([0-9a-fA-F]+)$",
        re.MULTILINE,
    )
    return [
        {
            "kind": match.group(1),
            "bdf": match.group(2),
            "vendor": match.group(3),
            "device": match.group(4),
            "header": int(match.group(5), 16),
            "uncorrectableStatus": int(match.group(6), 16),
            "correctableStatus": int(match.group(7), 16),
            "rootStatus": int(match.group(8), 16),
        }
        for match in pattern.finditer(text)
    ]


def native_aer_granted(text: str) -> bool | None:
    ownership = [line for line in text.splitlines() if "OS now controls" in line]
    if ownership:
        return any(re.search(r"\bAER\b", line) for line in ownership)
    denied = [
        line for line in text.splitlines()
        if "platform does not support" in line and "AER" in line
    ]
    if denied:
        return False
    return None


def first_kind(items: list[dict[str, Any]], kind: str) -> dict[str, Any] | None:
    return next((item for item in items if item["kind"] == kind), None)


def run_case(
    case: dict[str, Any],
    qemu: Path,
    iso: Path,
    output_dir: Path,
    timeout: int,
) -> dict[str, Any]:
    case_dir = output_dir / case["id"]
    case_dir.mkdir(parents=True, exist_ok=True)
    serial = case_dir / "guest-serial.log"
    monitor = Path("/tmp") / f"qemu-aer-{os.getpid()}-{case['id']}.sock"
    qemu_log = case_dir / "qemu-stderr.log"
    vars_path = case_dir / "OVMF_VARS.fd"
    for path in (serial, monitor, qemu_log, vars_path):
        path.unlink(missing_ok=True)

    machine = "q35,accel=kvm"
    root_options = "pcie-root-port,id=rp,chassis=1,slot=1"
    endpoint_options = "e1000e,id=ep,bus=rp,addr=0"
    if case["hidden"]:
        machine += ",x-vmware-deny-pcie-aer=on"
        root_options += ",x-hide-aer=on"
        endpoint_options += ",x-hide-aer=on"

    command = [
        str(qemu),
        "-name", case["id"],
        "-machine", machine,
        "-cpu", "host",
        "-m", "512",
        "-smp", "1",
        "-nic", "none",
    ]
    if case["firmware"] == "ovmf":
        shutil.copyfile("/usr/share/OVMF/OVMF_VARS.fd", vars_path)
        command.extend(
            [
                "-drive",
                "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd",
                "-drive",
                f"if=pflash,format=raw,file={vars_path}",
            ]
        )
    command.extend(
        [
            "-cdrom", str(iso),
            "-boot", "d",
            "-device", root_options,
            "-device", endpoint_options,
            "-display", "none",
            "-monitor", f"unix:{monitor},server,nowait",
            "-serial", f"file:{serial}",
            "-no-reboot",
        ]
    )
    with qemu_log.open("w", encoding="utf-8") as stderr:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=stderr)
    record: dict[str, Any] = {
        "firmware": case["firmware"],
        "vmwareProfile": case["hidden"],
        "command": command,
        "verdict": "running",
    }
    try:
        wait_marker(serial, "AER-SURFACE-INJECTION-WINDOW", timeout, process)
        injection = hmp_command(monitor, "pcie_aer_inject_error -c ep 0x1")
        if "unknown command" in injection.lower() or "invalid" in injection.lower():
            injection += hmp_command(
                monitor,
                "pcie_aer_inject_error ep 0x1 0 0 0 0",
            )
        (case_dir / "hmp-injection.txt").write_text(injection, encoding="utf-8")
        wait_marker(serial, "AER-SURFACE-PROBE-COMPLETE", timeout, process)
        process.wait(timeout=30)
        serial_text = serial.read_text(encoding="utf-8", errors="replace")
        before = parse_surfaces(serial_text, "before")
        after = parse_surfaces(serial_text, "after")
        endpoint_before = first_kind(before, "endpoint")
        endpoint_after = first_kind(after, "endpoint")
        bridge_before = first_kind(before, "bridge")
        bridge_after = first_kind(after, "bridge")
        grant = native_aer_granted(serial_text)
        record["observation"] = {
            "nativeAerGranted": grant,
            "before": before,
            "after": after,
            "injectionOutput": injection.splitlines(),
            "guestAerLogLines": [
                line for line in serial_text.splitlines()
                if re.search(r"AER|PCIe Bus Error|Corrected", line, re.IGNORECASE)
            ],
        }
        common_checks = {
            "qemuExitedCleanly": process.returncode == 0,
            "endpointObserved": endpoint_before is not None and endpoint_after is not None,
            "rootPortObserved": bridge_before is not None and bridge_after is not None,
            "injectionAccepted": "OK" in injection,
        }
        if case["hidden"]:
            profile_checks = {
                "endpointAerHeaderHidden": endpoint_before is not None
                and endpoint_before["header"] == 0,
                "rootAerHeaderHidden": bridge_before is not None
                and bridge_before["header"] == 0,
                "nativeAerDeniedByOsc": grant is False,
                "rawEndpointBodyPreserved": endpoint_after is not None
                and bool(endpoint_after["correctableStatus"] & 0x1),
                "rootErrorStatusUnchanged": bridge_after is not None
                and bridge_after["rootStatus"] == 0,
            }
        else:
            profile_checks = {
                "endpointAerHeaderVisible": endpoint_before is not None
                and endpoint_before["header"] != 0,
                "rootAerHeaderVisible": bridge_before is not None
                and bridge_before["header"] != 0,
                "nativeAerGrantedByOsc": grant is True,
            }
        record["checks"] = {**common_checks, **profile_checks}
        record["verdict"] = (
            "pass" if all(record["checks"].values()) else "fail"
        )
    except Exception as error:
        record["fault"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        record["verdict"] = "blocked"
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        monitor.unlink(missing_ok=True)
    return record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--qemu",
        default="/root/src/qemu-6.2.0/build-capability-lab/qemu-system-x86_64",
    )
    parser.add_argument(
        "--iso",
        default="/mnt/e/Code/PCI/_artifacts/esxi-l3-aer-surface-probe.iso",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()

    qemu = Path(args.qemu)
    iso = Path(args.iso)
    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if not qemu.exists() or not iso.exists():
        raise FileNotFoundError(f"missing QEMU or probe ISO: {qemu}, {iso}")

    result: dict[str, Any] = {
        "case": "Q-AER-VMware-visible-surface",
        "qemu": {
            "path": str(qemu),
            "sha256": hashlib.sha256(qemu.read_bytes()).hexdigest(),
        },
        "iso": {
            "path": str(iso),
            "sha256": hashlib.sha256(iso.read_bytes()).hexdigest(),
        },
        "cases": {},
        "verdict": "running",
    }
    save(output_dir / "result.json", result)
    for case in CASES:
        result["cases"][case["id"]] = run_case(
            case,
            qemu,
            iso,
            output_dir,
            args.timeout,
        )
        save(output_dir / "result.json", result)
    result["verdict"] = (
        "pass"
        if all(case["verdict"] == "pass" for case in result["cases"].values())
        else "fail"
    )
    save(output_dir / "result.json", result)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
