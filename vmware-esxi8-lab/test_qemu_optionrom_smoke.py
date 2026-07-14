#!/usr/bin/env python3
"""Calibrate the EFI option-ROM marker directly under QEMU and OVMF."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import socket
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from qemu_simpletrace import decode_simpletrace


MARKER = "ESXI-DIRECTPATH-OPROM-EXECUTED"
GUEST_MARKER = "=== R01 guest reboot probe start ==="
STAGE_PREFIX = "R01-OPROM-STAGE phase=first"
BDS_MARKER = 'BdsDxe: starting Boot0001 "UEFI QEMU DVD-ROM'


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hmp_command(socket_path: Path, command: str) -> str:
    """Run one HMP command against a local diagnostic monitor."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as monitor:
        monitor.settimeout(2)
        monitor.connect(str(socket_path))
        received = b""
        while b"(qemu)" not in received:
            received += monitor.recv(65536)
        monitor.sendall(command.encode("ascii") + b"\n")
        received = b""
        while b"(qemu)" not in received:
            received += monitor.recv(65536)
    return received.decode("utf-8", errors="replace")


def qom_uint64(response: str) -> int:
    cleaned = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", response)
    values = [line.strip() for line in cleaned.replace("\r", "").splitlines()]
    numeric = [int(line, 0) for line in values if re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", line)]
    if not numeric:
        raise ValueError(f"No QOM integer in HMP response: {cleaned!r}")
    return numeric[-1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument(
        "--rom",
        default="/root/vm/esxi8-mf/optionrom/808610d3.efirom",
    )
    parser.add_argument("--ovmf-code", default="/usr/share/OVMF/OVMF_CODE.fd")
    parser.add_argument("--ovmf-vars", default="/usr/share/OVMF/OVMF_VARS.fd")
    parser.add_argument(
        "--probe-iso",
        default="/mnt/e/Code/PCI/_artifacts/esxi-l3-reboot-probe.iso",
    )
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument(
        "--disable-rom",
        action="store_true",
        help="Run the identical boot as a no-option-ROM control.",
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    rom = Path(args.rom).resolve()
    ovmf_code = Path(args.ovmf_code).resolve()
    ovmf_vars = Path(args.ovmf_vars).resolve()
    probe_iso = Path(args.probe_iso).resolve()
    for path in (rom, ovmf_code, ovmf_vars, probe_iso):
        if not path.is_file():
            raise FileNotFoundError(path)

    started_at = utc_now()
    with tempfile.TemporaryDirectory(prefix="qemu-oprom-smoke-") as temporary:
        temporary_path = Path(temporary)
        writable_vars = temporary_path / "OVMF_VARS.fd"
        serial_path = temporary_path / "serial.log"
        trace_path = temporary_path / "qemu-trace.log"
        trace_events = temporary_path / "trace-events"
        monitor_path = temporary_path / "monitor.sock"
        shutil.copyfile(ovmf_vars, writable_vars)
        trace_events.write_text("e1000e_option_rom_marker\n", encoding="utf-8")
        nic_options = "e1000e,id=nic0,netdev=n0,mac=52:54:00:12:34:56"
        if not args.disable_rom:
            nic_options += f",romfile={rom}"
        command = [
            args.qemu,
            "-nodefaults",
            "-machine", "q35,accel=kvm",
            "-cpu", "host",
            "-m", "1024",
            "-drive",
            f"if=pflash,format=raw,readonly=on,file={ovmf_code}",
            "-drive",
            f"if=pflash,format=raw,file={writable_vars}",
            "-netdev", "user,id=n0,restrict=on",
            "-device", nic_options,
            "-drive",
            f"if=none,id=probe,format=raw,readonly=on,file={probe_iso}",
            "-device", "ide-cd,drive=probe,bus=ide.1,bootindex=1",
            "-display", "none",
            "-monitor", f"unix:{monitor_path},server,nowait",
            "-serial", f"file:{serial_path}",
            "-trace", f"events={trace_events},file={trace_path}",
            "-no-reboot",
        ]
        timed_out = False
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        terminated_after_guest_marker = False
        terminated_after_stage_probe = False
        milestones: dict[str, float] = {}
        diagnostics: dict[str, str] = {}
        boot_started = time.monotonic()
        try:
            deadline = time.monotonic() + args.timeout
            while process.poll() is None and time.monotonic() < deadline:
                serial_so_far = (
                    serial_path.read_text(encoding="utf-8", errors="replace")
                    if serial_path.exists()
                    else ""
                )
                elapsed = round(time.monotonic() - boot_started, 3)
                if BDS_MARKER in serial_so_far:
                    milestones.setdefault("bdsStartedSeconds", elapsed)
                if GUEST_MARKER in serial_so_far:
                    milestones.setdefault("linuxMarkerSeconds", elapsed)
                if STAGE_PREFIX in serial_so_far:
                    milestones.setdefault("stageProbeSeconds", elapsed)
                    terminated_after_guest_marker = True
                    terminated_after_stage_probe = True
                    break
                time.sleep(0.2)
            if process.poll() is None:
                timed_out = not terminated_after_guest_marker
                try:
                    qom_response = hmp_command(
                        monitor_path,
                        "qom-get /machine/peripheral/nic0 "
                        "option-rom-marker-count",
                    )
                    diagnostics["option-rom-marker-count"] = qom_response
                    diagnostics["optionRomMarkerCount"] = qom_uint64(
                        qom_response
                    )
                except (OSError, TimeoutError, ValueError) as error:
                    diagnostics["option-rom-marker-count"] = f"ERROR: {error}"
                for diagnostic_command in (
                    "info registers",
                    "info pci",
                    "info cpus",
                ):
                    try:
                        diagnostics[diagnostic_command] = hmp_command(
                            monitor_path, diagnostic_command
                        )
                    except (OSError, TimeoutError) as error:
                        diagnostics[diagnostic_command] = f"ERROR: {error}"
                try:
                    hmp_command(monitor_path, "trace-file flush")
                except (OSError, TimeoutError):
                    pass
                # The simple trace backend buffers records. Let QEMU handle
                # SIGTERM and flush them before falling back to a hard kill.
                process.terminate()
            stdout, stderr = process.communicate(timeout=10)
            return_code = process.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
            return_code = process.returncode

        serial_text = (
            serial_path.read_text(encoding="utf-8", errors="replace")
            if serial_path.exists()
            else ""
        )
        (output / "serial.log").write_text(serial_text, encoding="utf-8")
        (output / "qemu.stdout").write_text(stdout, encoding="utf-8")
        (output / "qemu.stderr").write_text(stderr, encoding="utf-8")
        (output / "qemu-monitor-diagnostics.json").write_text(
            json.dumps(diagnostics, indent=2) + "\n", encoding="utf-8"
        )
        shutil.copyfile(writable_vars, output / "OVMF_VARS.after.fd")
        shutil.copyfile(trace_path, output / "qemu-trace.log")

    qemu_version = subprocess.run(
        [args.qemu, "--version"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.splitlines()
    marker_count = serial_text.count(MARKER)
    decoded_trace = decode_simpletrace(output / "qemu-trace.log")
    (output / "qemu-trace.decoded.log").write_text(
        decoded_trace, encoding="utf-8"
    )
    trace_lines = [
        line
        for line in decoded_trace.splitlines()
        if line.startswith("e1000e_option_rom_marker ")
    ]
    expected_trace_count = 0 if args.disable_rom else 1
    expected_qom_count = expected_trace_count
    qom_count = diagnostics.get("optionRomMarkerCount")
    stage_match = re.search(
        r"^R01-OPROM-STAGE phase=first present=(?P<present>[01]) "
        r"attrs=(?P<attrs>\S+) magic=(?P<magic>\S+) "
        r"value=(?P<value>\S+) size=(?P<size>\d+)$",
        serial_text,
        re.MULTILINE,
    )
    stage_probe = (
        {
            "present": stage_match.group("present") == "1",
            "attributes": stage_match.group("attrs"),
            "magic": stage_match.group("magic"),
            "value": stage_match.group("value"),
            "size": int(stage_match.group("size")),
        }
        if stage_match
        else None
    )
    expected_stage_present = not args.disable_rom
    checks = {
        "barMarkerTraceCountMatches": len(trace_lines) == expected_trace_count,
        "liveMarkerCounterMatches": qom_count == expected_qom_count,
        "firmwareStartedBootTarget": BDS_MARKER in serial_text,
        "firmwareContinuedToLinux": GUEST_MARKER in serial_text,
        "stageProbeReported": stage_probe is not None,
        "entryStageMatches": (
            stage_probe is not None
            and stage_probe["present"] == expected_stage_present
            and (
                not expected_stage_present
                or (
                    stage_probe["magic"] == "53544147"
                    and stage_probe["value"] == "00000001"
                    and stage_probe["size"] == 12
                )
            )
        ),
    }
    result = {
        "case": (
            "QEMU-OVMF-no-option-ROM-control"
            if args.disable_rom
            else "QEMU-OVMF-EFI-option-ROM-calibration"
        ),
        "startedAt": started_at,
        "finishedAt": utc_now(),
        "qemuVersion": qemu_version,
        "command": command,
        "rom": {"path": str(rom), "sha256": sha256(rom)},
        "probeIso": {"path": str(probe_iso), "sha256": sha256(probe_iso)},
        "marker": MARKER,
        "markerCount": marker_count,
        "barMarkerTrace": trace_lines,
        "expectedBarMarkerTraceCount": expected_trace_count,
        "optionRomMarkerCount": qom_count,
        "expectedOptionRomMarkerCount": expected_qom_count,
        "milestones": milestones,
        "ipxeBannerObserved": (
            "iPXE" in serial_text or "iiPPXXEE" in serial_text
        ),
        "guestMarker": GUEST_MARKER,
        "guestReachedLinux": GUEST_MARKER in serial_text,
        "terminatedAfterGuestMarker": terminated_after_guest_marker,
        "terminatedAfterStageProbe": terminated_after_stage_probe,
        "entryStageProbe": stage_probe,
        "timedOutAfterCalibrationWindow": timed_out,
        "qemuReturnCode": return_code,
        "checks": checks,
        "verdict": "pass" if all(checks.values()) else "fail",
    }
    (output / "result.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
