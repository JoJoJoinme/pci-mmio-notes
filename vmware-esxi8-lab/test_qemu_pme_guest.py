#!/usr/bin/env python3
"""Exercise the controlled PCIe PME path with a real Linux guest."""

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


QOM_PATH = "/machine/peripheral/test_fn0"


class SerialMarkerError(RuntimeError):
    def __init__(self, message: str, serial_text: str):
        super().__init__(message)
        self.serial_text = serial_text


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hmp_command(socket_path: Path, command: str) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as monitor:
        monitor.settimeout(3)
        monitor.connect(str(socket_path))
        received = b""
        while b"(qemu)" not in received:
            received += monitor.recv(65536)
        monitor.sendall(command.encode("ascii") + b"\n")
        received = b""
        while b"(qemu)" not in received:
            received += monitor.recv(65536)
    return received.decode("utf-8", errors="replace")


def hmp_bool(response: str) -> bool | None:
    cleaned = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", response)
    matches = re.findall(r"(?im)^\s*(true|false)\s*$", cleaned)
    return matches[-1].lower() == "true" if matches else None


def qom_snapshot(monitor: Path) -> tuple[dict[str, bool | None], str]:
    values: dict[str, bool | None] = {}
    raw = []
    for prop in (
        "x-pme-enabled",
        "x-pme-status",
        "x-upstream-pme-enabled",
        "x-upstream-pme-status",
    ):
        response = hmp_command(monitor, f"qom-get {QOM_PATH} {prop}")
        values[prop] = hmp_bool(response)
        raw.append(f"=== {prop} ===\n{response}")
    return values, "\n".join(raw)


def read_serial(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def wait_marker(process: subprocess.Popen[str], path: Path, marker: str, timeout: int) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = read_serial(path)
        if marker in text:
            return text
        if process.poll() is not None:
            raise SerialMarkerError(
                f"QEMU exited with {process.returncode} before serial marker {marker!r}",
                text,
            )
        time.sleep(0.2)
    text = read_serial(path)
    raise SerialMarkerError(
        f"Serial marker {marker!r} not found in {path}",
        text,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--qemu",
        default="/root/src/qemu-6.2.0/build-capability-lab/qemu-system-x86_64",
    )
    parser.add_argument("--ovmf-code", default="/usr/share/OVMF/OVMF_CODE.fd")
    parser.add_argument("--ovmf-vars", default="/usr/share/OVMF/OVMF_VARS.fd")
    parser.add_argument(
        "--probe-iso",
        default="/mnt/e/Code/PCI/_artifacts/esxi-l3-pme-probe.iso",
    )
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    qemu = Path(args.qemu).resolve()
    ovmf_code = Path(args.ovmf_code).resolve()
    ovmf_vars = Path(args.ovmf_vars).resolve()
    probe_iso = Path(args.probe_iso).resolve()
    for path in (qemu, ovmf_code, ovmf_vars, probe_iso):
        if not path.is_file():
            raise FileNotFoundError(path)

    result: dict = {
        "case": "QEMU-OVMF-Linux-PCIe-PME-end-to-end",
        "startedAt": utc_now(),
        "inputs": {
            "qemu": str(qemu),
            "qemuSha256": sha256(qemu),
            "ovmfCode": str(ovmf_code),
            "ovmfCodeSha256": sha256(ovmf_code),
            "probeIso": str(probe_iso),
            "probeIsoSha256": sha256(probe_iso),
        },
        "verdict": "running",
    }
    process: subprocess.Popen[str] | None = None
    stdout = ""
    stderr = ""
    serial_text = ""
    try:
        with tempfile.TemporaryDirectory(prefix="qemu-pme-guest-") as temporary:
            temporary_path = Path(temporary)
            writable_vars = temporary_path / "OVMF_VARS.fd"
            serial_path = temporary_path / "serial.log"
            monitor_path = temporary_path / "monitor.sock"
            trace_path = temporary_path / "qemu-trace.log"
            trace_events = temporary_path / "trace-events"
            shutil.copyfile(ovmf_vars, writable_vars)
            trace_events.write_text("e1000e_pme_inject\n", encoding="ascii")

            command = [
                str(qemu),
                "-nodefaults",
                "-machine", "q35,accel=kvm",
                "-cpu", "host",
                "-m", "1024",
                "-drive", f"if=pflash,format=raw,readonly=on,file={ovmf_code}",
                "-drive", f"if=pflash,format=raw,file={writable_vars}",
                "-device",
                "pcie-root-port,id=pme_rp,bus=pcie.0,chassis=8,slot=8,addr=0x08.0",
                "-netdev", "user,id=n0,restrict=on",
                "-device",
                "e1000e,id=test_fn0,netdev=n0,mac=52:54:00:08:00:00,bus=pme_rp,addr=0",
                "-drive",
                f"if=none,id=probe,format=raw,readonly=on,file={probe_iso}",
                "-device", "ide-cd,drive=probe,bus=ide.1,bootindex=1",
                "-display", "none",
                "-monitor", f"unix:{monitor_path},server,nowait",
                "-serial", f"file:{serial_path}",
                "-trace", f"events={trace_events},file={trace_path}",
                "-no-reboot",
            ]
            result["command"] = command
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            wait_marker(process, serial_path, "PME-ARMED", args.timeout)
            before, before_raw = qom_snapshot(monitor_path)
            (output / "qom-before.txt").write_text(before_raw, encoding="utf-8")
            injection = hmp_command(
                monitor_path, f"qom-set {QOM_PATH} x-pme-inject true"
            )
            (output / "qom-inject.txt").write_text(injection, encoding="utf-8")
            immediate, immediate_raw = qom_snapshot(monitor_path)
            (output / "qom-immediate.txt").write_text(
                immediate_raw, encoding="utf-8"
            )
            serial_text = wait_marker(
                process, serial_path, "PME-PROBE-COMPLETE", args.timeout
            )
            try:
                after, after_raw = qom_snapshot(monitor_path)
            except (OSError, TimeoutError) as error:
                after = {}
                after_raw = f"QEMU exited before final QOM snapshot: {error}\n"
            (output / "qom-after.txt").write_text(after_raw, encoding="utf-8")
            process.wait(timeout=30)
            stdout, stderr = process.communicate()

            shutil.copyfile(trace_path, output / "qemu-trace.log")
            trace_text = decode_simpletrace(trace_path)
            (output / "qemu-trace-decoded.log").write_text(
                trace_text, encoding="utf-8"
            )
            result["qom"] = {
                "before": before,
                "immediatelyAfterInjection": immediate,
                "afterGuestCompletion": after,
            }
            result["injectionResponse"] = injection
            result["traceInjectionLines"] = [
                line
                for line in trace_text.splitlines()
                if line.startswith("e1000e_pme_inject ")
            ]
    except Exception as error:
        serial_text = getattr(error, "serial_text", serial_text)
        result["fault"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()

    (output / "serial.log").write_text(serial_text, encoding="utf-8")
    (output / "qemu.stdout").write_text(stdout, encoding="utf-8")
    (output / "qemu.stderr").write_text(stderr, encoding="utf-8")

    pmcsr_values = [
        int(value, 16)
        for value in re.findall(
            r"^PME-(?:ARMED|POLL|FINAL).*endpoint_pmcsr=([0-9a-fA-F]{4})$",
            serial_text,
            re.MULTILINE,
        )
    ]
    pme_irq_counts = [
        int(value)
        for value in re.findall(
            r"^\s*\d+:\s+(\d+).*\bPCIe PME\b",
            serial_text,
            re.MULTILINE,
        )
    ]
    trace_root_status = [
        int(value, 16)
        for line in result.get("traceInjectionLines", [])
        for value in re.findall(r"\broot_status=0x([0-9a-fA-F]+)", line)
    ]
    qom = result.get("qom", {})
    before = qom.get("before", {})
    immediate = qom.get("immediatelyAfterInjection", {})
    result["observations"] = {
        "guestPmcsrSamples": [f"0x{value:04x}" for value in pmcsr_values],
        "guestPmeIrqCounts": pme_irq_counts,
        "traceRootStatus": [f"0x{value:x}" for value in trace_root_status],
        "immediateEndpointStatus": immediate.get("x-pme-status"),
        "note": (
            "Linux may service the PME interrupt and clear endpoint PME Enable/Status "
            "before the post-injection QOM snapshot."
        ),
    }
    checks = {
        "guestArmedPme": "PME-ARMED" in serial_text,
        "qemuObservedPmeEnable": before.get("x-pme-enabled") is True,
        "qemuObservedRootPmeEnable": before.get("x-upstream-pme-enabled") is True,
        "traceReportedRootPmeStatus": any(
            value & 0x10000 for value in trace_root_status
        ),
        "guestPmeInterruptIncremented": (
            len(pme_irq_counts) >= 2 and pme_irq_counts[-1] > pme_irq_counts[0]
        ),
        "guestConsumedPme": (
            bool(pmcsr_values)
            and bool(pmcsr_values[0] & 0x0100)
            and not bool(pmcsr_values[-1] & 0x0100)
        ),
        "guestCompleted": "PME-PROBE-COMPLETE" in serial_text,
        "singleInjectionTrace": len(result.get("traceInjectionLines", [])) == 1,
    }
    result["checks"] = checks
    result["verdict"] = "pass" if all(checks.values()) else "fail"
    result["finishedAt"] = utc_now()
    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    (output / "result.json").write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
