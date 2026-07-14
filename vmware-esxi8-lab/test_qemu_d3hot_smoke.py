#!/usr/bin/env python3
"""Validate the opt-in virtio-pci D3hot-to-D0 reset instrumentation."""

from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from qemu_simpletrace import decode_simpletrace


CONFIG_ADDRESS = 0xCF8
CONFIG_DATA = 0xCFC
DEVICE = 9


class QTestClient:
    def __init__(self, path: Path):
        self.connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.connection.settimeout(3)
        self.connection.connect(str(path))

    def close(self) -> None:
        self.connection.close()

    def command(self, command: str) -> str:
        self.connection.sendall(command.encode("ascii") + b"\n")
        response = b""
        while b"\n" not in response:
            response += self.connection.recv(65536)
        return response.decode("ascii", errors="replace").strip()


def hmp_command(path: Path, command: str) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as monitor:
        monitor.settimeout(3)
        monitor.connect(str(path))
        received = b""
        while b"(qemu)" not in received:
            received += monitor.recv(65536)
        monitor.sendall(command.encode("ascii") + b"\n")
        received = b""
        while b"(qemu)" not in received:
            chunk = monitor.recv(65536)
            if not chunk:
                break
            received += chunk
    return received.decode("utf-8", errors="replace")


def qtest(client: QTestClient, command: str) -> int | None:
    response = client.command(command)
    if not response.startswith("OK"):
        raise RuntimeError(f"qtest command failed: {command!r}: {response!r}")
    match = re.search(r"0x[0-9a-fA-F]+|\b\d+\b", response[2:])
    return int(match.group(0), 0) if match else None


def config_select(client: QTestClient, offset: int) -> None:
    address = 0x80000000 | (DEVICE << 11) | (offset & ~3)
    qtest(client, f"outl 0x{CONFIG_ADDRESS:x} 0x{address:x}")


def config_read8(client: QTestClient, offset: int) -> int:
    config_select(client, offset)
    value = qtest(client, f"inb 0x{CONFIG_DATA + (offset & 3):x}")
    if value is None:
        raise RuntimeError("qtest inb returned no value")
    return value


def config_read16(client: QTestClient, offset: int) -> int:
    if offset & 1:
        return config_read8(client, offset) | (config_read8(client, offset + 1) << 8)
    config_select(client, offset)
    value = qtest(client, f"inw 0x{CONFIG_DATA + (offset & 2):x}")
    if value is None:
        raise RuntimeError("qtest inw returned no value")
    return value


def config_write16(client: QTestClient, offset: int, value: int) -> None:
    if offset & 1:
        raise ValueError(f"unaligned config write: 0x{offset:x}")
    config_select(client, offset)
    qtest(client, f"outw 0x{CONFIG_DATA + (offset & 2):x} 0x{value:04x}")


def find_capability(client: QTestClient, capability_id: int) -> int | None:
    pointer = config_read8(client, 0x34) & ~3
    visited = set()
    while pointer and pointer not in visited:
        visited.add(pointer)
        if config_read8(client, pointer) == capability_id:
            return pointer
        pointer = config_read8(client, pointer + 1) & ~3
    return None


def wait_socket(path: Path, process: subprocess.Popen[str], timeout: int = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise RuntimeError(f"QEMU exited before creating {path}")
        time.sleep(0.05)
    raise TimeoutError(path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--qemu",
        default="/root/src/qemu-6.2.0/build-capability-lab/qemu-system-x86_64",
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    qemu = Path(args.qemu).resolve()
    if not qemu.is_file():
        raise FileNotFoundError(qemu)

    with tempfile.TemporaryDirectory(prefix="qemu-d3hot-smoke-") as temporary:
        temporary_path = Path(temporary)
        qtest_path = temporary_path / "qtest.sock"
        monitor_path = temporary_path / "monitor.sock"
        trace_path = temporary_path / "qemu-trace.log"
        trace_events = temporary_path / "trace-events"
        trace_events.write_text(
            "virtio_pci_pmcsr_write\nvirtio_pci_d3hot_reset\nqdev_reset\n",
            encoding="ascii",
        )
        command = [
            str(qemu),
            "-nodefaults",
            "-machine", "q35,accel=qtest",
            "-display", "none",
            "-S",
            "-device",
            (
                "virtio-net-pci,id=test_virtio_net,bus=pcie.0,addr=0x09.0,"
                "disable-legacy=on,x-pcie-root-cap-init=on,"
                "x-pcie-flr-init=off,x-pcie-pm-init=on,"
                "x-pcie-d3hot-reset=on,x-pcie-pme-d3hot=on"
            ),
            "-qtest", f"unix:{qtest_path},server=on,wait=off",
            "-monitor", f"unix:{monitor_path},server,nowait",
            "-trace", f"events={trace_events},file={trace_path}",
        ]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        result: dict = {"command": command, "verdict": "running"}
        try:
            wait_socket(qtest_path, process)
            wait_socket(monitor_path, process)
            client = QTestClient(qtest_path)
            try:
                vendor = config_read16(client, 0x00)
                device = config_read16(client, 0x02)
                pm_cap = find_capability(client, 0x01)
                if pm_cap is None:
                    raise RuntimeError("PM capability not found")
                pmc = config_read16(client, pm_cap + 2)
                pmcsr_offset = pm_cap + 4
                initial = config_read16(client, pmcsr_offset)
                config_write16(client, pmcsr_offset, (initial & ~3) | 3)
                d3hot = config_read16(client, pmcsr_offset)
                config_write16(client, pmcsr_offset, d3hot & ~3)
                final = config_read16(client, pmcsr_offset)
                hmp_command(monitor_path, "quit")
            finally:
                client.close()
            result["config"] = {
                "vendor": f"0x{vendor:04x}",
                "device": f"0x{device:04x}",
                "pmCapabilityOffset": f"0x{pm_cap:02x}",
                "pmCapabilities": f"0x{pmc:04x}",
                "pmeD3hotAdvertised": bool(pmc & 0x4000),
                "pmcsrInitial": f"0x{initial:04x}",
                "pmcsrD3hot": f"0x{d3hot:04x}",
                "pmcsrFinal": f"0x{final:04x}",
            }
            stdout, stderr = process.communicate(timeout=10)
        except Exception:
            process.terminate()
            stdout, stderr = process.communicate(timeout=10)
            raise

        trace_text = decode_simpletrace(trace_path)
        (output / "qemu-trace-decoded.log").write_text(
            trace_text, encoding="utf-8"
        )
        pmcsr_lines = [
            line
            for line in trace_text.splitlines()
            if line.startswith("virtio_pci_pmcsr_write ")
        ]
        d3hot_lines = [
            line
            for line in trace_text.splitlines()
            if line.startswith("virtio_pci_d3hot_reset ")
        ]
        result["trace"] = {
            "pmcsrWrites": pmcsr_lines,
            "d3hotResets": d3hot_lines,
        }
        checks = {
            "pmeD3hotAdvertised": result.get("config", {}).get(
                "pmeD3hotAdvertised"
            ) is True,
            "qemuExitedCleanly": process.returncode == 0,
            "virtioDevicePresent": result["config"]["vendor"] == "0x1af4",
            "enteredD3hot": int(result["config"]["pmcsrD3hot"], 16) & 3 == 3,
            "returnedToD0": int(result["config"]["pmcsrFinal"], 16) & 3 == 0,
            "twoPmcsrWritesTraced": len(pmcsr_lines) == 2,
            "oneD3hotResetTraced": len(d3hot_lines) == 1,
        }
        result["checks"] = checks
        result["stdout"] = stdout.splitlines()
        result["stderr"] = stderr.splitlines()
        result["verdict"] = "pass" if all(checks.values()) else "fail"

    rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    (output / "result.json").write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    raise SystemExit(0 if result["verdict"] == "pass" else 1)


if __name__ == "__main__":
    main()
