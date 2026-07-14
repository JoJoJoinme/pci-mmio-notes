#!/usr/bin/env python3
"""Run the public-observable ESXi DirectPath capability decision matrix."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from esxi_passthru_capability import (
    EsxiSsh,
    caveat_field,
    collect_case,
    utc_now,
    wait_for_esxi,
)
from qemu_simpletrace import decode_simpletrace


SCRIPT_DIR = Path(__file__).resolve().parent
START_SCRIPT = SCRIPT_DIR / "start-qemu-esxi8-host-a.sh"
STOP_SCRIPT = SCRIPT_DIR / "stop-qemu-esxi8-mf.sh"
PID_FILE = Path("/root/vm/esxi8-mf/qemu.pid")
TRACE_FILE = Path("/root/vm/esxi8-mf/qemu-trace.log")
MONITOR = Path("/root/vm/esxi8-mf/monitor.sock")
OUTER_SERIAL = Path("/root/vm/esxi8-mf/serial.log")
BOOT_OPTIONS_SCRIPT = SCRIPT_DIR / "qemu-esxi8-boot-options.py"
CAPABILITY_QEMU = "/root/src/qemu-6.2.0/build-capability-lab/qemu-system-x86_64"

BASE_ENV = {
    "QEMU_ESXI_TOPOLOGY": "pcie",
    "QEMU_ESXI_IVSHMEM_SIZE": "0",
    "QEMU_ESXI_IVSHMEM_ALT_SIZE": "0",
    "QEMU_ESXI_PCI_TESTDEV_MEMBAR_SIZE": "0",
    "QEMU_ESXI_EDU": "0",
    "QEMU_ESXI_VIRTIO_NET": "0",
    "QEMU_ESXI_VIRTIO_CLASS": "",
    "QEMU_ESXI_X3130_UPSTREAM": "0",
    "QEMU_ESXI_EEPRO100": "0",
    "QEMU_ESXI_DISABLE_ACS": "0",
    "QEMU_ESXI_IOMMU": "1",
    "QEMU_ESXI_TRACE": "1",
}

CASES: dict[str, dict[str, Any]] = {
    "pcie-no-iommu": {
        "env": {"QEMU_ESXI_IOMMU": "0"},
        "targets": ["0000:01:00.0", "0000:00:08.0"],
        "subject": "0000:01:00.0",
        "expected": {"capable": False},
        "variable": "Remove the platform DMA-remapping unit while preserving topology",
    },
    "pcie-edu-bridge-reset": {
        "env": {"QEMU_ESXI_EDU": "1"},
        "targets": ["0000:01:01.0", "0000:00:08.0"],
        "subject": "0000:01:01.0",
        "expected": {"capable": True, "reset": "Bridge reset"},
        "variable": "Endpoint without PCIe/PM/FLR capability below a PCIe root port",
    },
    "pcie-x3130-upstream-flr": {
        "env": {"QEMU_ESXI_X3130_UPSTREAM": "1"},
        "targets": ["0000:01:02.0", "0000:00:08.0"],
        "subject": "0000:01:02.0",
        "expected": {"capable": False, "reset": "Function reset"},
        "variable": (
            "Add a real Type-1 PCIe switch upstream port with native FLR; "
            "keep the non-FLR Root Port as the same-boot control"
        ),
    },
    "root-e1000e-no-function-reset": {
        "env": {"QEMU_ESXI_TOPOLOGY": "root"},
        "targets": ["0000:00:08.0", "0000:00:08.1"],
        "subject": "0000:00:08.0",
        "expected": {"capable": False, "reset": "None"},
        "variable": "e1000e moved from a resettable bridge to the root complex",
    },
    "root-virtio-flr-pm": {
        "env": {
            "QEMU_ESXI_TOPOLOGY": "root",
            "QEMU_ESXI_VIRTIO_NET": "1",
            "QEMU_ESXI_VIRTIO_FLR": "on",
            "QEMU_ESXI_VIRTIO_PM": "on",
            "QEMU_ESXI_VIRTIO_ROOT_CAP": "on",
            "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
        },
        "targets": ["0000:00:09.0", "0000:00:08.0"],
        "subject": "0000:00:09.0",
        "expected": {"capable": True, "resetContains": "Function"},
        "variable": "Root-complex endpoint with both FLR and PCIe PM",
    },
    "root-virtio-flr-only": {
        "env": {
            "QEMU_ESXI_TOPOLOGY": "root",
            "QEMU_ESXI_VIRTIO_NET": "1",
            "QEMU_ESXI_VIRTIO_FLR": "on",
            "QEMU_ESXI_VIRTIO_PM": "off",
            "QEMU_ESXI_VIRTIO_ROOT_CAP": "on",
            "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
        },
        "targets": ["0000:00:09.0", "0000:00:08.0"],
        "subject": "0000:00:09.0",
        "expected": {"capable": True, "resetContains": "Function"},
        "variable": "Make PMCSR state bits read-only while preserving FLR",
    },
    "root-virtio-class-network": {
        "env": {
            "QEMU_ESXI_TOPOLOGY": "root",
            "QEMU_ESXI_VIRTIO_NET": "1",
            "QEMU_ESXI_VIRTIO_CLASS": "0x0200",
            "QEMU_ESXI_VIRTIO_FLR": "on",
            "QEMU_ESXI_VIRTIO_PM": "off",
            "QEMU_ESXI_VIRTIO_ROOT_CAP": "on",
            "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
        },
        "targets": ["0000:00:09.0", "0000:00:08.0"],
        "subject": "0000:00:09.0",
        "expected": {"capable": True, "resetContains": "Function"},
        "variable": "Explicit 0x0200 network class control with FLR",
    },
    "root-virtio-class-memory": {
        "env": {
            "QEMU_ESXI_TOPOLOGY": "root",
            "QEMU_ESXI_VIRTIO_NET": "1",
            "QEMU_ESXI_VIRTIO_CLASS": "0x0500",
            "QEMU_ESXI_VIRTIO_FLR": "on",
            "QEMU_ESXI_VIRTIO_PM": "off",
            "QEMU_ESXI_VIRTIO_ROOT_CAP": "on",
            "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
        },
        "targets": ["0000:00:09.0", "0000:00:08.0"],
        "subject": "0000:00:09.0",
        "expected": {"capable": True, "resetContains": "Function"},
        "variable": "Change only the endpoint class to 0x0500 RAM memory",
    },
    "root-virtio-class-pentium": {
        "env": {
            "QEMU_ESXI_TOPOLOGY": "root",
            "QEMU_ESXI_VIRTIO_NET": "1",
            "QEMU_ESXI_VIRTIO_CLASS": "0x0b02",
            "QEMU_ESXI_VIRTIO_FLR": "on",
            "QEMU_ESXI_VIRTIO_PM": "off",
            "QEMU_ESXI_VIRTIO_ROOT_CAP": "on",
            "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
        },
        "targets": ["0000:00:09.0", "0000:00:08.0"],
        "subject": "0000:00:09.0",
        "expected": {"capable": True, "resetContains": "Function"},
        "variable": "Change only the endpoint class to 0x0b02 Pentium processor",
    },
    "root-virtio-class-coprocessor": {
        "env": {
            "QEMU_ESXI_TOPOLOGY": "root",
            "QEMU_ESXI_VIRTIO_NET": "1",
            "QEMU_ESXI_VIRTIO_CLASS": "0x0b40",
            "QEMU_ESXI_VIRTIO_FLR": "on",
            "QEMU_ESXI_VIRTIO_PM": "off",
            "QEMU_ESXI_VIRTIO_ROOT_CAP": "on",
            "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
        },
        "targets": ["0000:00:09.0", "0000:00:08.0"],
        "subject": "0000:00:09.0",
        "expected": {"capable": True, "resetContains": "Function"},
        "variable": "Change only the endpoint class to 0x0b40 co-processor",
    },
    "root-virtio-class-host-bridge": {
        "env": {
            "QEMU_ESXI_TOPOLOGY": "root",
            "QEMU_ESXI_VIRTIO_NET": "1",
            "QEMU_ESXI_VIRTIO_CLASS": "0x0600",
            "QEMU_ESXI_VIRTIO_FLR": "on",
            "QEMU_ESXI_VIRTIO_PM": "off",
            "QEMU_ESXI_VIRTIO_ROOT_CAP": "on",
            "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
        },
        "targets": ["0000:00:09.0", "0000:00:08.0"],
        "subject": "0000:00:09.0",
        "expected": {"capable": True, "resetContains": "Function"},
        "variable": (
            "Change only the Type-0 endpoint class to 0x0600 host bridge"
        ),
    },
    "root-virtio-class-pci-bridge": {
        "env": {
            "QEMU_ESXI_TOPOLOGY": "root",
            "QEMU_ESXI_VIRTIO_NET": "1",
            "QEMU_ESXI_VIRTIO_CLASS": "0x0604",
            "QEMU_ESXI_VIRTIO_FLR": "on",
            "QEMU_ESXI_VIRTIO_PM": "off",
            "QEMU_ESXI_VIRTIO_ROOT_CAP": "on",
            "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
        },
        "targets": ["0000:00:09.0", "0000:00:08.0"],
        "subject": "0000:00:09.0",
        "expected": {"capable": True, "resetContains": "Function"},
        "variable": (
            "Change only the Type-0 endpoint class to 0x0604 PCI bridge"
        ),
    },
    "root-virtio-pm-only": {
        "env": {
            "QEMU_ESXI_TOPOLOGY": "root",
            "QEMU_ESXI_VIRTIO_NET": "1",
            "QEMU_ESXI_VIRTIO_FLR": "off",
            "QEMU_ESXI_VIRTIO_PM": "on",
            "QEMU_ESXI_VIRTIO_ROOT_CAP": "on",
            "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
        },
        "targets": ["0000:00:09.0", "0000:00:08.0"],
        "subject": "0000:00:09.0",
        "expected": {"capable": False, "reset": "None"},
        "variable": (
            "Expose the PCI PM capability without FLR; QEMU's virtio-pci "
            "PMCSR does not by itself implement a usable D3hot function reset"
        ),
    },
    "root-virtio-d3hot-reset": {
        "env": {
            "QEMU_ESXI_TOPOLOGY": "root",
            "QEMU_ESXI_VIRTIO_NET": "1",
            "QEMU_ESXI_VIRTIO_FLR": "off",
            "QEMU_ESXI_VIRTIO_PM": "on",
            "QEMU_ESXI_VIRTIO_D3HOT_RESET": "on",
            "QEMU_ESXI_VIRTIO_ROOT_CAP": "on",
            "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
        },
        "targets": ["0000:00:09.0", "0000:00:08.0"],
        "subject": "0000:00:09.0",
        "expected": {"capable": False, "reset": "None"},
        "captureD3hotTrace": True,
        "variable": (
            "Implement D3hot-to-D0 reset without advertising PME_D3hot; test "
            "whether behavior alone is discoverable during admission"
        ),
    },
    "root-virtio-pme-d3hot-advertised-only": {
        "env": {
            "QEMU_ESXI_TOPOLOGY": "root",
            "QEMU_ESXI_VIRTIO_NET": "1",
            "QEMU_ESXI_VIRTIO_FLR": "off",
            "QEMU_ESXI_VIRTIO_PM": "on",
            "QEMU_ESXI_VIRTIO_D3HOT_RESET": "off",
            "QEMU_ESXI_VIRTIO_PME_D3HOT": "on",
            "QEMU_ESXI_VIRTIO_ROOT_CAP": "on",
            "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
        },
        "targets": ["0000:00:09.0", "0000:00:08.0"],
        "subject": "0000:00:09.0",
        "expected": {"capable": False, "reset": "None"},
        "captureD3hotTrace": True,
        "variable": (
            "Advertise PME_D3hot and writable PMCSR while deliberately not "
            "implementing the D3hot-to-D0 device reset"
        ),
    },
    "root-virtio-d3hot-reset-advertised": {
        "env": {
            "QEMU_ESXI_TOPOLOGY": "root",
            "QEMU_ESXI_VIRTIO_NET": "1",
            "QEMU_ESXI_VIRTIO_FLR": "off",
            "QEMU_ESXI_VIRTIO_PM": "on",
            "QEMU_ESXI_VIRTIO_D3HOT_RESET": "on",
            "QEMU_ESXI_VIRTIO_PME_D3HOT": "on",
            "QEMU_ESXI_VIRTIO_ROOT_CAP": "on",
            "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
        },
        "targets": ["0000:00:09.0", "0000:00:08.0"],
        "subject": "0000:00:09.0",
        "expected": {"capable": False, "reset": "None"},
        "captureD3hotTrace": True,
        "variable": (
            "Advertise PME_D3hot and implement the matching D3hot-to-D0 "
            "soft-reset transition while FLR remains disabled"
        ),
    },
    "root-virtio-no-flr-no-pm": {
        "env": {
            "QEMU_ESXI_TOPOLOGY": "root",
            "QEMU_ESXI_VIRTIO_NET": "1",
            "QEMU_ESXI_VIRTIO_FLR": "off",
            "QEMU_ESXI_VIRTIO_PM": "off",
            "QEMU_ESXI_VIRTIO_ROOT_CAP": "on",
            "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
        },
        "targets": ["0000:00:09.0", "0000:00:08.0"],
        "subject": "0000:00:09.0",
        "expected": {"capable": False, "reset": "None"},
        "variable": "Remove FLR and make PMCSR state bits read-only at the root complex",
    },
    "root-i82559-native-pm": {
        "env": {
            "QEMU_ESXI_TOPOLOGY": "root",
            "QEMU_ESXI_EEPRO100": "1",
            "QEMU_ESXI_QEMU_BINARY": CAPABILITY_QEMU,
        },
        "targets": ["0000:00:09.0", "0000:00:08.0"],
        "subject": "0000:00:09.0",
        "expected": {"capable": False, "reset": "None"},
        "variable": (
            "Use QEMU's unmodified conventional-PCI i82559ER with PMC "
            "0x7e21 but its documented unimplemented PMCSR state machine"
        ),
    },
    "pcie-virtio-no-flr-no-pm": {
        "env": {
            "QEMU_ESXI_VIRTIO_NET": "1",
            "QEMU_ESXI_VIRTIO_FLR": "off",
            "QEMU_ESXI_VIRTIO_PM": "off",
        },
        "targets": ["0000:01:01.0", "0000:00:08.0"],
        "subject": "0000:01:01.0",
        "expected": {"capable": True, "reset": "Bridge reset"},
        "variable": "Restore an upstream bridge while endpoint FLR and PM stay absent",
    },
    "pcie-virtio-no-acs": {
        "env": {
            "QEMU_ESXI_VIRTIO_NET": "1",
            "QEMU_ESXI_VIRTIO_FLR": "off",
            "QEMU_ESXI_VIRTIO_PM": "off",
            "QEMU_ESXI_DISABLE_ACS": "1",
        },
        "targets": ["0000:01:01.0", "0000:00:08.0"],
        "subject": "0000:01:01.0",
        "expected": {"capable": True, "reset": "Bridge reset"},
        "variable": "Disable root-port ACS under the lab's recorded ACS-check bypass",
    },
    "pcie-virtio-no-acs-strict": {
        "env": {
            "QEMU_ESXI_VIRTIO_NET": "1",
            "QEMU_ESXI_VIRTIO_FLR": "off",
            "QEMU_ESXI_VIRTIO_PM": "off",
            "QEMU_ESXI_DISABLE_ACS": "1",
        },
        "bootOptions": " enableACSCheckForRP=TRUE",
        "targets": ["0000:01:01.0", "0000:00:08.0"],
        "subject": "0000:01:01.0",
        "expected": {"capable": False},
        "variable": (
            "Disable root-port ACS while explicitly enabling the ESXi "
            "root-port ACS admission check"
        ),
    },
    "legacy-virtio-no-flr-no-pm": {
        "env": {
            "QEMU_ESXI_TOPOLOGY": "legacy",
            "QEMU_ESXI_VIRTIO_NET": "1",
            "QEMU_ESXI_VIRTIO_DISABLE_LEGACY": "off",
            "QEMU_ESXI_VIRTIO_DISABLE_PCIE": "on",
            "QEMU_ESXI_VIRTIO_FLR": "off",
            "QEMU_ESXI_VIRTIO_PM": "off",
        },
        "targets": ["0000:02:02.0", "0000:01:00.0", "0000:00:08.0"],
        "subject": "0000:02:02.0",
        "expected": {"capable": True, "reset": "Bridge reset"},
        "variable": "Conventional endpoint below a PCIe-to-PCI bridge",
    },
}

RESTORE_ENV = {
    **BASE_ENV,
    "QEMU_ESXI_EDU": "1",
}


def save(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def qemu_pid() -> int | None:
    try:
        pid = int(PID_FILE.read_text(encoding="ascii").strip())
    except (FileNotFoundError, ValueError):
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    return pid


def stop_outer(ssh: EsxiSsh, timeout: int = 240) -> None:
    if qemu_pid() is None:
        return
    graceful_shutdown_requested = False
    try:
        ssh.run(
            "vim-cmd hostsvc/maintenance_mode_enter >/dev/null 2>&1 || true; "
            "esxcli system shutdown poweroff --delay=10 "
            "--reason='DirectPath capability matrix'",
            timeout=60,
        )
        graceful_shutdown_requested = True
    except (RuntimeError, subprocess.TimeoutExpired):
        pass
    if graceful_shutdown_requested:
        deadline = time.monotonic() + timeout
        while qemu_pid() is not None and time.monotonic() < deadline:
            time.sleep(2)
    if qemu_pid() is not None:
        subprocess.run(["bash", str(STOP_SCRIPT)], check=True, timeout=60)
    deadline = time.monotonic() + 30
    while qemu_pid() is not None and time.monotonic() < deadline:
        time.sleep(1)
    if qemu_pid() is not None:
        raise RuntimeError("Outer QEMU did not stop")


def start_outer(
    case_env: dict[str, str],
    ssh: EsxiSsh,
    timeout: int,
    startup_log: Path,
    boot_options: str | None = None,
) -> str:
    # Matrix cases must not inherit a previous scenario's endpoint shape.
    # Callers pass every QEMU_ESXI_* input explicitly through BASE_ENV/case_env.
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("QEMU_ESXI_")
    }
    env.update(BASE_ENV)
    env.update(case_env)
    injector = None
    if boot_options is not None:
        OUTER_SERIAL.unlink(missing_ok=True)
        injector = subprocess.Popen(
            [
                "python3",
                str(BOOT_OPTIONS_SCRIPT),
                "--options",
                boot_options,
                "--serial",
                str(OUTER_SERIAL),
                "--monitor",
                str(MONITOR),
                "--timeout",
                str(min(timeout, 300)),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    completed = subprocess.run(
        ["bash", str(START_SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    startup_text = completed.stdout + completed.stderr
    if injector is not None:
        if completed.returncode:
            injector.terminate()
        injection_stdout, injection_stderr = injector.communicate(
            timeout=min(timeout + 30, 330)
        )
        startup_text += "\n=== boot option injector ===\n"
        startup_text += injection_stdout + injection_stderr
    qemu_log = Path("/root/vm/esxi8-mf/qemu.log")
    if qemu_log.exists():
        startup_text += "\n=== qemu.log ===\n"
        startup_text += qemu_log.read_text(encoding="utf-8", errors="replace")
    startup_log.write_text(startup_text, encoding="utf-8")
    if completed.returncode:
        raise RuntimeError(
            f"Outer QEMU launcher failed with exit {completed.returncode}; "
            f"see {startup_log}"
        )
    if injector is not None and injector.returncode:
        raise RuntimeError(
            f"Boot option injector failed with exit {injector.returncode}; "
            f"see {startup_log}"
        )
    deadline = time.monotonic() + 30
    while qemu_pid() is None and time.monotonic() < deadline:
        time.sleep(1)
    if qemu_pid() is None:
        raise RuntimeError("Outer QEMU did not create a live pid")
    version = wait_for_esxi(ssh, timeout=timeout)
    ssh.run("vim-cmd hostsvc/maintenance_mode_exit >/dev/null 2>&1 || true")
    time.sleep(8)
    return version


def bool_value(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() == "true":
            return True
        if value.lower() == "false":
            return False
    return None


def evaluate(result: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    subject = case["subject"].lower()
    esxcli = (result.get("devices", {}).get(subject, {}).get("esxcli") or {})
    observed = {
        "capable": bool_value(esxcli.get("Passthru Capable")),
        "reset": esxcli.get("Reset Method"),
        "parent": esxcli.get("Parent Device Address"),
        "dependent": esxcli.get("Dependent Device Address"),
    }
    failures: list[str] = []
    expected = case["expected"]
    if observed["capable"] != expected.get("capable"):
        failures.append(
            f"capable expected {expected.get('capable')} got {observed['capable']}"
        )
    if "reset" in expected and observed["reset"] != expected["reset"]:
        failures.append(
            f"reset expected {expected['reset']!r} got {observed['reset']!r}"
        )
    if "resetContains" in expected and expected["resetContains"] not in str(
        observed["reset"]
    ):
        failures.append(
            f"reset expected to contain {expected['resetContains']!r}, "
            f"got {observed['reset']!r}"
        )
    config = result.get("devices", {}).get(subject, {}).get("config", {})
    standard_names = [item.get("name") for item in config.get("standard", [])]
    pcie = next(
        (item for item in config.get("standard", []) if item.get("id") == "0x10"),
        {},
    )
    observed["standardCapabilities"] = standard_names
    observed["flrCapable"] = pcie.get("functionLevelResetCapable")
    return {
        "subject": subject,
        "expected": expected,
        "observed": observed,
        "verdict": "pass" if not failures else "fail",
        "failures": failures,
    }


def trace_delta(offset: int) -> str:
    if not TRACE_FILE.exists():
        return ""
    if TRACE_FILE.stat().st_size < offset:
        offset = 0
    with TRACE_FILE.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(offset)
        lines = handle.readlines()
    selected = [
        line
        for line in lines
        if re.search(r"qdev_reset|qbus_reset|resettable", line, re.IGNORECASE)
    ]
    return "".join(selected)


def d3hot_trace_snapshot(output_dir: Path) -> dict[str, Any]:
    decoded = decode_simpletrace(TRACE_FILE)
    lines = [
        line
        for line in decoded.splitlines()
        if line.startswith(
            ("virtio_pci_pmcsr_write ", "virtio_pci_d3hot_reset ")
        )
    ]
    (output_dir / "outer-d3hot-trace.log").write_text(
        "\n".join(lines) + ("\n" if lines else ""),
        encoding="utf-8",
    )
    return {
        "pmcsrWriteCount": sum(
            line.startswith("virtio_pci_pmcsr_write ") for line in lines
        ),
        "d3hotResetCount": sum(
            line.startswith("virtio_pci_d3hot_reset ") for line in lines
        ),
        "lines": lines[-100:],
    }


def exercise_owner(
    ssh: EsxiSsh,
    subject: str,
    output_dir: Path,
    capable: bool | None,
    current_owner: str | None,
) -> dict[str, Any]:
    if not capable:
        return {"attempted": False, "reason": "subject-not-capable"}
    offset = TRACE_FILE.stat().st_size if TRACE_FILE.exists() else 0
    commands = []
    if current_owner == "VM Passthru":
        commands.append(
            f"esxcli hardware pci pcipassthru set -d {subject} -e false -a"
        )
    commands.extend(
        [
            f"esxcli hardware pci pcipassthru set -d {subject} -e true -a",
            f"esxcli hardware pci list | sed -n '/{subject}/,/^$/p'",
        ]
    )
    outputs: list[str] = []
    for command in commands:
        completed = ssh.run(command, check=False, timeout=90)
        outputs.append(
            f"$ {command}\nexit={completed.returncode}\n"
            f"{completed.stdout}{completed.stderr}\n"
        )
        time.sleep(2)
    text = "\n".join(outputs)
    (output_dir / "owner-toggle.txt").write_text(text, encoding="utf-8")
    reset_trace = trace_delta(offset)
    (output_dir / "owner-toggle-reset-trace.txt").write_text(
        reset_trace, encoding="utf-8"
    )
    return {
        "attempted": True,
        "commandsSucceeded": all("exit=0" in item for item in outputs),
        "traceStartOffset": offset,
        "resetTraceLineCount": len(reset_trace.splitlines()),
        "evidence": ["owner-toggle.txt", "owner-toggle-reset-trace.txt"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="172.31.91.10")
    parser.add_argument("--user", default="root")
    parser.add_argument("--caveat", default="esxi8-auto-codex-credentials")
    parser.add_argument("--qemu-name", default="esxi8-a")
    parser.add_argument("--boot-timeout", type=int, default=720)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cases", nargs="+", default=list(CASES))
    parser.add_argument("--no-owner-exercise", action="store_true")
    parser.add_argument("--no-restore", action="store_true")
    args = parser.parse_args()

    unknown = sorted(set(args.cases) - set(CASES))
    if unknown:
        parser.error(f"unknown cases: {', '.join(unknown)}")

    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    password = caveat_field(args.caveat, "Password")
    ssh = EsxiSsh(args.host, password, args.user)
    matrix: dict[str, Any] = {
        "runId": output.name,
        "case": "ESXi-DirectPath-passthruCapable-public-observable-matrix",
        "startedAt": utc_now(),
        "host": args.host,
        "casesRequested": args.cases,
        "cases": {},
        "verdict": "running",
    }
    matrix_path = output / "matrix-result.json"
    save(matrix_path, matrix)

    try:
        for case_id in args.cases:
            case = CASES[case_id]
            case_dir = output / case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            record: dict[str, Any] = {
                "startedAt": utc_now(),
                "variable": case["variable"],
                "env": {**BASE_ENV, **case["env"]},
                "targets": case["targets"],
                "subject": case["subject"],
                "verdict": "running",
            }
            if case.get("bootOptions") is not None:
                record["bootOptions"] = case["bootOptions"]
            matrix["cases"][case_id] = record
            save(matrix_path, matrix)
            try:
                stop_outer(ssh)
                record["esxiVersion"] = start_outer(
                    case["env"],
                    ssh,
                    args.boot_timeout,
                    case_dir / "outer-start.log",
                    boot_options=case.get("bootOptions"),
                ).splitlines()
                result = collect_case(
                    case_dir,
                    case_id=case_id,
                    host=args.host,
                    user=args.user,
                    password=password,
                    qemu_name=args.qemu_name,
                    monitor=MONITOR,
                    targets=case["targets"],
                    requested={
                        "variable": case["variable"],
                        "env": record["env"],
                        "subject": case["subject"],
                    },
                )
                assessment = evaluate(result, case)
                record["assessment"] = assessment
                if case.get("captureD3hotTrace"):
                    record["d3hotTraceAfterEsxiBoot"] = d3hot_trace_snapshot(
                        case_dir
                    )
                if not args.no_owner_exercise:
                    record["ownerExercise"] = exercise_owner(
                        ssh,
                        case["subject"],
                        case_dir,
                        assessment["observed"]["capable"],
                        (
                            result["devices"][case["subject"]]["esxcli"] or {}
                        ).get("Current Owner"),
                    )
                if case.get("captureD3hotTrace"):
                    record["d3hotTraceAfterOwnerExercise"] = (
                        d3hot_trace_snapshot(case_dir)
                    )
                record["verdict"] = assessment["verdict"]
            except Exception as error:
                record["error"] = f"{type(error).__name__}: {error}"
                record["verdict"] = "blocked"
            record["finishedAt"] = utc_now()
            save(matrix_path, matrix)
    finally:
        if not args.no_restore:
            restore: dict[str, Any] = {"startedAt": utc_now()}
            matrix["restore"] = restore
            save(matrix_path, matrix)
            try:
                stop_outer(ssh)
                restore["esxiVersion"] = start_outer(
                    RESTORE_ENV,
                    ssh,
                    args.boot_timeout,
                    output / "restore-start.log",
                ).splitlines()
                restore["verdict"] = "pass"
            except Exception as error:
                restore["error"] = f"{type(error).__name__}: {error}"
                restore["verdict"] = "blocked"
            restore["finishedAt"] = utc_now()

    verdicts = [entry["verdict"] for entry in matrix["cases"].values()]
    if verdicts and all(verdict == "pass" for verdict in verdicts):
        matrix["verdict"] = "pass"
    elif any(verdict == "fail" for verdict in verdicts):
        matrix["verdict"] = "fail"
    else:
        matrix["verdict"] = "partial"
    matrix["finishedAt"] = utc_now()
    save(matrix_path, matrix)
    print(json.dumps(matrix, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
