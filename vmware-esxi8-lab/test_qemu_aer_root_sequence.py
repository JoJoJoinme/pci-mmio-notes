#!/usr/bin/env python3
"""Run stock-QEMU PCIe Correctable AER root-state sequences.

This runner is a no-guest, register-level positive control for the public
PCIe AER state model.  It does not inject a physical link fault and it does
not constitute evidence about ESXi service delivery, interrupts, recovery,
or VMware implementation internals.

Every ``(sequence, repeat)`` tuple starts a fresh QEMU process.  The runner
uses the stock ``pcie_aer_inject_error`` HMP command and QTest configuration
space accesses exposed by :mod:`test_qemu_aer_correctable_matrix`.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import test_qemu_aer_correctable_matrix as aer


SCHEMA_VERSION = 1
MODEL_ID = "PCIe-AER-public-register-message-routing-positive-control-v1"
SEQUENCES = (
    "first-multiple",
    "independent-w1c",
    "bit-or",
    "rearm",
)
SUPPORTED_GATES = ("g100", "g101")

B0_NAME = "RCVR"
B1_NAME = "BAD_TLP"
B0 = aer.CORRECTABLE_BITS[B0_NAME]
B1 = aer.CORRECTABLE_BITS[B1_NAME]
SEQUENCE_BITS = B0 | B1

OBSERVATION_MATCH = "MATCH"
OBSERVATION_DIVERGED = "DIVERGED"
OBSERVATION_INCONCLUSIVE = "INCONCLUSIVE"
OBSERVATION_BLOCKED = "BLOCKED"
OBSERVATION_STATES = (
    OBSERVATION_MATCH,
    OBSERVATION_DIVERGED,
    OBSERVATION_INCONCLUSIVE,
    OBSERVATION_BLOCKED,
)

ROOT_COR_FIRST = aer.PCI_ERR_ROOT_COR_RCV
ROOT_COR_MULTIPLE = (
    aer.PCI_ERR_ROOT_COR_RCV | aer.PCI_ERR_ROOT_MULTI_COR_RCV
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def snapshot_pair(
    client: aer.QTestClient,
    endpoint: dict[str, int],
    root: dict[str, int],
) -> dict[str, dict[str, int]]:
    return {
        "endpoint": aer.endpoint_snapshot(client, endpoint),
        "rootPort": aer.root_snapshot(client, root),
    }


def endpoint_registers(
    endpoint: dict[str, int],
) -> tuple[int, int, int, int, int]:
    return (
        endpoint["bus"],
        endpoint["device"],
        endpoint["function"],
        endpoint["pcieCapabilityOffset"],
        endpoint["aerCapabilityOffset"],
    )


def root_registers(
    root: dict[str, int],
) -> tuple[int, int, int, int, int]:
    return (
        root["bus"],
        root["device"],
        root["function"],
        root["pcieCapabilityOffset"],
        root["aerCapabilityOffset"],
    )


def clear_endpoint_ces(
    client: aer.QTestClient,
    endpoint: dict[str, int],
    bits: int,
) -> None:
    bus, device, function, _, aer_offset = endpoint_registers(endpoint)
    aer.config_write32(
        client,
        bus,
        device,
        function,
        aer_offset + aer.PCI_ERR_COR_STATUS,
        bits,
    )


def clear_endpoint_ced(
    client: aer.QTestClient,
    endpoint: dict[str, int],
) -> None:
    bus, device, function, pcie_offset, _ = endpoint_registers(endpoint)
    aer.config_write16(
        client,
        bus,
        device,
        function,
        pcie_offset + aer.PCI_EXP_DEVSTA,
        aer.PCI_EXP_DEVSTA_CED,
    )


def clear_root_correctable(
    client: aer.QTestClient,
    root: dict[str, int],
) -> None:
    bus, device, function, _, aer_offset = root_registers(root)
    aer.config_write32(
        client,
        bus,
        device,
        function,
        aer_offset + aer.PCI_ERR_ROOT_STATUS,
        aer.PCI_ERR_ROOT_COR_MASK,
    )


def configure_sequence(
    client: aer.QTestClient,
    endpoint: dict[str, int],
    root: dict[str, int],
    gate: aer.Gate,
) -> None:
    """Clear status and configure both sequence bits for a routed case."""

    aer.clear_and_configure_case(client, endpoint, root, B0, gate)
    bus, device, function, _, aer_offset = endpoint_registers(endpoint)
    mask = aer.config_read32(
        client,
        bus,
        device,
        function,
        aer_offset + aer.PCI_ERR_COR_MASK,
    )
    aer.config_write32(
        client,
        bus,
        device,
        function,
        aer_offset + aer.PCI_ERR_COR_MASK,
        mask & ~SEQUENCE_BITS,
    )


def root_source_matches(state: dict[str, Any], requester_id: int) -> bool:
    return (
        state["rootPort"]["errorSourceIdentification"] & 0xFFFF
    ) == requester_id


def endpoint_exact(
    state: dict[str, Any],
    *,
    ces: int,
    ced: bool,
) -> bool:
    endpoint = state["endpoint"]
    return (
        endpoint["correctableErrorStatus"] == ces
        and bool(endpoint["deviceStatus"] & aer.PCI_EXP_DEVSTA_CED) == ced
        and (
            endpoint["deviceStatus"] & aer.PCI_EXP_DEVSTA_ERROR_MASK
        )
        == (aer.PCI_EXP_DEVSTA_CED if ced else 0)
    )


def root_correctable_exact(
    state: dict[str, Any],
    *,
    root_status: int,
    requester_id: int | None,
) -> bool:
    root = state["rootPort"]
    status_exact = (
        root["rootErrorStatus"] & aer.PCI_ERR_ROOT_STATUS_W1C
    ) == root_status
    if requester_id is None:
        return status_exact
    return status_exact and root_source_matches(state, requester_id)


def safety_checks(
    label: str,
    state: dict[str, Any],
) -> dict[str, bool]:
    endpoint = state["endpoint"]
    root = state["rootPort"]
    return {
        f"{label}:endpoint-ues-zero": (
            endpoint["uncorrectableErrorStatus"] == 0
        ),
        f"{label}:endpoint-device-status-correctable-only": not bool(
            endpoint["deviceStatus"]
            & (aer.PCI_EXP_DEVSTA_ERROR_MASK & ~aer.PCI_EXP_DEVSTA_CED)
        ),
        f"{label}:root-ues-zero": root["uncorrectableErrorStatus"] == 0,
        f"{label}:root-ces-zero": root["correctableErrorStatus"] == 0,
        f"{label}:root-device-status-clean": not bool(
            root["deviceStatus"] & aer.PCI_EXP_DEVSTA_ERROR_MASK
        ),
        f"{label}:root-no-uncorrectable-reception": not bool(
            root["rootErrorStatus"] & aer.PCI_ERR_ROOT_UNCOR_MASK
        ),
        f"{label}:uncorrectable-source-zero": not bool(
            root["errorSourceIdentification"] & 0xFFFF0000
        ),
    }


def required_labels(sequence: str) -> tuple[str, ...]:
    labels = {
        "first-multiple": (
            "effective-controls",
            "pre-injection",
            "first-b0",
            "repeated-b0",
            "stable-after-repeat",
            "post-cleanup",
        ),
        "independent-w1c": (
            "effective-controls",
            "pre-injection",
            "initial-b0",
            "initial-window",
            "after-endpoint-clear-only",
            "after-root-cleanup-for-rebuild",
            "rebuilt-b0",
            "after-root-clear-only",
            "post-cleanup",
        ),
        "bit-or": (
            "effective-controls",
            "pre-injection",
            "first-b0",
            "second-b1",
            "stable-after-or",
            "post-cleanup",
        ),
        "rearm": (
            "effective-controls",
            "pre-injection",
            "initial-b0",
            "initial-window",
            "after-ces-clear-only",
            "after-ced-clear-only",
            "after-root-clear",
            "rearmed-b0",
            "rearmed-window",
            "post-cleanup",
        ),
    }
    return labels[sequence]


def expected_injection_labels(sequence: str) -> tuple[str, ...]:
    return {
        "first-multiple": ("first-b0", "repeated-b0"),
        "independent-w1c": ("initial-b0", "rebuilt-b0"),
        "bit-or": ("first-b0", "second-b1"),
        "rearm": ("initial-b0", "rearmed-b0"),
    }[sequence]


def evaluate_sequence(
    *,
    sequence: str,
    gate: aer.Gate,
    endpoint_requester_id: int,
    snapshots: dict[str, dict[str, Any]],
    injections: list[dict[str, Any]],
) -> dict[str, Any]:
    """Evaluate a completed sequence against the public-model control oracle."""

    missing = [
        label for label in required_labels(sequence) if label not in snapshots
    ]
    injection_by_label = {
        item.get("label"): item for item in injections if item.get("label")
    }
    missing_injections = [
        label
        for label in expected_injection_labels(sequence)
        if label not in injection_by_label
    ]
    if missing or missing_injections:
        return {
            "modelId": MODEL_ID,
            "observationState": OBSERVATION_INCONCLUSIVE,
            "verdict": "INCONCLUSIVE",
            "missingSnapshots": missing,
            "missingInjections": missing_injections,
            "checks": {},
        }

    controls = snapshots["effective-controls"]
    baseline = snapshots["pre-injection"]
    endpoint_controls = controls["endpoint"]
    root_controls = controls["rootPort"]
    checks: dict[str, bool] = {
        "gate-supported": gate.name in SUPPORTED_GATES,
        "endpoint-cere-enabled": bool(
            endpoint_controls["deviceControl"] & aer.PCI_EXP_DEVCTL_CERE
        ),
        "b0-unmasked": not bool(
            endpoint_controls["correctableErrorMask"] & B0
        ),
        "b1-unmasked": not bool(
            endpoint_controls["correctableErrorMask"] & B1
        ),
        "root-bridge-serr-enabled": bool(
            root_controls["bridgeControl"] & aer.PCI_BRIDGE_CTL_SERR
        ),
        "root-cere-enabled": bool(
            root_controls["deviceControl"] & aer.PCI_EXP_DEVCTL_CERE
        ),
        "root-command-matches-gate": bool(
            root_controls["rootErrorCommand"]
            & aer.PCI_ERR_ROOT_CMD_COR_EN
        )
        == gate.root_cor_enable,
        "clean-endpoint-baseline": endpoint_exact(
            baseline, ces=0, ced=False
        ),
        "clean-root-status-baseline": root_correctable_exact(
            baseline, root_status=0, requester_id=None
        ),
        "clean-root-source-baseline": (
            baseline["rootPort"]["errorSourceIdentification"] == 0
        ),
    }
    for label in expected_injection_labels(sequence):
        checks[f"{label}:hmp-accepted"] = bool(
            injection_by_label[label].get("accepted")
        )

    for label in required_labels(sequence):
        checks.update(safety_checks(label, snapshots[label]))

    def ep(label: str, ces: int, ced: bool = True) -> None:
        checks[f"{label}:endpoint-exact"] = endpoint_exact(
            snapshots[label], ces=ces, ced=ced
        )

    def root(
        label: str,
        status: int,
        *,
        source: bool = True,
    ) -> None:
        checks[f"{label}:root-correctable-exact"] = root_correctable_exact(
            snapshots[label],
            root_status=status,
            requester_id=endpoint_requester_id if source else None,
        )

    if sequence == "first-multiple":
        ep("first-b0", B0)
        root("first-b0", ROOT_COR_FIRST)
        ep("repeated-b0", B0)
        root("repeated-b0", ROOT_COR_MULTIPLE)
        ep("stable-after-repeat", B0)
        root("stable-after-repeat", ROOT_COR_MULTIPLE)
        ep("post-cleanup", 0, False)
        root("post-cleanup", 0, source=False)
    elif sequence == "independent-w1c":
        for label in ("initial-b0", "initial-window"):
            ep(label, B0)
            root(label, ROOT_COR_FIRST)
        ep("after-endpoint-clear-only", 0, False)
        root("after-endpoint-clear-only", ROOT_COR_FIRST)
        ep("after-root-cleanup-for-rebuild", 0, False)
        root("after-root-cleanup-for-rebuild", 0, source=False)
        ep("rebuilt-b0", B0)
        root("rebuilt-b0", ROOT_COR_FIRST)
        ep("after-root-clear-only", B0)
        root("after-root-clear-only", 0, source=False)
        ep("post-cleanup", 0, False)
        root("post-cleanup", 0, source=False)
    elif sequence == "bit-or":
        ep("first-b0", B0)
        root("first-b0", ROOT_COR_FIRST)
        ep("second-b1", B0 | B1)
        root("second-b1", ROOT_COR_MULTIPLE)
        ep("stable-after-or", B0 | B1)
        root("stable-after-or", ROOT_COR_MULTIPLE)
        ep("post-cleanup", 0, False)
        root("post-cleanup", 0, source=False)
    elif sequence == "rearm":
        for label in ("initial-b0", "initial-window"):
            ep(label, B0)
            root(label, ROOT_COR_FIRST)
        ep("after-ces-clear-only", 0, True)
        root("after-ces-clear-only", ROOT_COR_FIRST)
        ep("after-ced-clear-only", 0, False)
        root("after-ced-clear-only", ROOT_COR_FIRST)
        ep("after-root-clear", 0, False)
        root("after-root-clear", 0, source=False)
        for label in ("rearmed-b0", "rearmed-window"):
            ep(label, B0)
            root(label, ROOT_COR_FIRST)
        ep("post-cleanup", 0, False)
        root("post-cleanup", 0, source=False)
    else:
        raise ValueError(f"unknown sequence: {sequence}")

    state = (
        OBSERVATION_MATCH
        if checks and all(checks.values())
        else OBSERVATION_DIVERGED
    )
    return {
        "modelId": MODEL_ID,
        "observationState": state,
        "verdict": "PASS" if state == OBSERVATION_MATCH else "FAIL",
        "missingSnapshots": [],
        "missingInjections": [],
        "checks": checks,
        "failedChecks": [
            name for name, passed in checks.items() if not passed
        ],
        "sourceAfterRootW1cPolicy": (
            "observed-but-not-constrained; Root Status W1C independence is "
            "the oracle, not Root Source clearing"
        ),
    }


def blocked_oracle(error: BaseException) -> dict[str, Any]:
    return {
        "modelId": MODEL_ID,
        "observationState": OBSERVATION_BLOCKED,
        "verdict": "BLOCKED",
        "checks": {},
        "fault": {
            "type": type(error).__name__,
            "message": str(error),
        },
    }


class SequenceRecorder:
    def __init__(
        self,
        *,
        client: aer.QTestClient,
        monitor_path: Path,
        endpoint: dict[str, int],
        root: dict[str, int],
    ):
        self.client = client
        self.monitor_path = monitor_path
        self.endpoint = endpoint
        self.root = root
        self.snapshots: dict[str, dict[str, Any]] = {}
        self.injections: list[dict[str, Any]] = []
        self.hmp_transcript: list[str] = []
        self.phases: dict[str, list[dict[str, Any]]] = {
            "t3Immediate": [],
            "t4Window": [],
            "t5TransitionOrClear": [],
        }

    def capture(
        self,
        label: str,
        *,
        phase: str,
        operation: str,
    ) -> dict[str, Any]:
        state = snapshot_pair(self.client, self.endpoint, self.root)
        self.snapshots[label] = state
        record = {
            "label": label,
            "operation": operation,
            "observedAtUtc": utc_now(),
            "snapshot": state,
        }
        self.phases[phase].append(record)
        return state

    def inject(
        self,
        *,
        label: str,
        bit_name: str,
        phase: str,
    ) -> dict[str, Any]:
        command = f"pcie_aer_inject_error ep {bit_name}"
        raw = aer.hmp_command(self.monitor_path, command)
        accepted = "OK id: ep" in raw
        injection = {
            "label": label,
            "command": command,
            "accepted": accepted,
            "ackPattern": "OK id: ep",
            "raw": raw,
            "observedAtUtc": utc_now(),
        }
        self.injections.append(injection)
        self.hmp_transcript.extend(
            (f"### {label}: {command}", raw.rstrip(), "")
        )
        self.capture(label, phase=phase, operation=command)
        return injection


def execute_sequence(
    *,
    sequence: str,
    recorder: SequenceRecorder,
    observation_window_ms: int,
) -> None:
    client = recorder.client
    endpoint = recorder.endpoint
    root = recorder.root

    def wait_and_capture(label: str, operation: str) -> None:
        time.sleep(observation_window_ms / 1000)
        recorder.capture(label, phase="t4Window", operation=operation)

    def cleanup(label: str = "post-cleanup") -> None:
        clear_endpoint_ces(client, endpoint, SEQUENCE_BITS)
        clear_endpoint_ced(client, endpoint)
        clear_root_correctable(client, root)
        recorder.capture(
            label,
            phase="t5TransitionOrClear",
            operation="W1C endpoint CES/CED and Root Correctable Status",
        )

    if sequence == "first-multiple":
        recorder.inject(label="first-b0", bit_name=B0_NAME, phase="t3Immediate")
        recorder.inject(
            label="repeated-b0",
            bit_name=B0_NAME,
            phase="t3Immediate",
        )
        wait_and_capture(
            "stable-after-repeat",
            f"wait {observation_window_ms} ms after repeated B0",
        )
        cleanup()
    elif sequence == "independent-w1c":
        recorder.inject(
            label="initial-b0",
            bit_name=B0_NAME,
            phase="t3Immediate",
        )
        wait_and_capture(
            "initial-window",
            f"wait {observation_window_ms} ms after initial B0",
        )
        clear_endpoint_ces(client, endpoint, B0)
        clear_endpoint_ced(client, endpoint)
        recorder.capture(
            "after-endpoint-clear-only",
            phase="t5TransitionOrClear",
            operation="W1C endpoint CES.B0 and Device Status.CED only",
        )
        clear_root_correctable(client, root)
        recorder.capture(
            "after-root-cleanup-for-rebuild",
            phase="t5TransitionOrClear",
            operation="W1C Root Correctable Status to rebuild clean state",
        )
        recorder.inject(
            label="rebuilt-b0",
            bit_name=B0_NAME,
            phase="t5TransitionOrClear",
        )
        clear_root_correctable(client, root)
        recorder.capture(
            "after-root-clear-only",
            phase="t5TransitionOrClear",
            operation="W1C Root Correctable Status only",
        )
        clear_endpoint_ces(client, endpoint, B0)
        clear_endpoint_ced(client, endpoint)
        recorder.capture(
            "post-cleanup",
            phase="t5TransitionOrClear",
            operation="W1C remaining endpoint CES/CED",
        )
    elif sequence == "bit-or":
        recorder.inject(label="first-b0", bit_name=B0_NAME, phase="t3Immediate")
        recorder.inject(label="second-b1", bit_name=B1_NAME, phase="t3Immediate")
        wait_and_capture(
            "stable-after-or",
            f"wait {observation_window_ms} ms after B0 then B1",
        )
        cleanup()
    elif sequence == "rearm":
        recorder.inject(
            label="initial-b0",
            bit_name=B0_NAME,
            phase="t3Immediate",
        )
        wait_and_capture(
            "initial-window",
            f"wait {observation_window_ms} ms after initial B0",
        )
        clear_endpoint_ces(client, endpoint, B0)
        recorder.capture(
            "after-ces-clear-only",
            phase="t5TransitionOrClear",
            operation="W1C endpoint CES.B0 only",
        )
        clear_endpoint_ced(client, endpoint)
        recorder.capture(
            "after-ced-clear-only",
            phase="t5TransitionOrClear",
            operation="W1C endpoint Device Status.CED only",
        )
        clear_root_correctable(client, root)
        recorder.capture(
            "after-root-clear",
            phase="t5TransitionOrClear",
            operation="W1C Root Correctable Status only",
        )
        recorder.inject(
            label="rearmed-b0",
            bit_name=B0_NAME,
            phase="t5TransitionOrClear",
        )
        time.sleep(observation_window_ms / 1000)
        recorder.capture(
            "rearmed-window",
            phase="t5TransitionOrClear",
            operation=f"wait {observation_window_ms} ms after re-armed B0",
        )
        cleanup()
    else:
        raise ValueError(f"unknown sequence: {sequence}")


def qemu_command(
    qemu: Path,
    qtest_path: Path,
    monitor_path: Path,
) -> list[str]:
    return [
        str(qemu),
        "-nodefaults",
        "-machine",
        "q35,accel=qtest",
        "-display",
        "none",
        "-S",
        "-nic",
        "none",
        "-device",
        "pcie-root-port,id=rp,bus=pcie.0,addr=0x02.0,chassis=2,slot=2",
        "-device",
        (
            "virtio-net-pci,id=ep,bus=rp,addr=0x00.0,"
            "disable-legacy=on,aer=on"
        ),
        "-qtest",
        f"unix:{qtest_path},server=on,wait=off",
        "-monitor",
        f"unix:{monitor_path},server,nowait",
    ]


def write_text(path: Path, text: str, *, encoding: str = "utf-8") -> str:
    path.write_text(text, encoding=encoding)
    return aer.sha256_file(path)


def write_artifact_manifest(case_dir: Path) -> str:
    manifest = case_dir / "artifact-manifest.sha256"
    files = sorted(
        path
        for path in case_dir.rglob("*")
        if path.is_file() and path != manifest
    )
    lines = [
        f"{aer.sha256_file(path)}  {path.relative_to(case_dir).as_posix()}"
        for path in files
    ]
    write_text(manifest, "\n".join(lines) + "\n", encoding="ascii")
    return aer.sha256_file(manifest)


def run_sequence_case(
    *,
    qemu: Path,
    qemu_version: str,
    qemu_hash: str,
    qemu_source: dict[str, str] | None,
    output_dir: Path,
    sequence: str,
    repeat_index: int,
    gate: aer.Gate,
    socket_timeout: int,
    observation_window_ms: int,
) -> dict[str, Any]:
    case_id = f"{sequence}__{gate.name}__r{repeat_index:02d}"
    case_dir = output_dir / "cases" / case_id
    case_dir.mkdir(parents=True, exist_ok=False)
    started_at = utc_now()
    case_spec = {
        "schemaVersion": SCHEMA_VERSION,
        "caseId": case_id,
        "modelId": MODEL_ID,
        "sequence": sequence,
        "repeatIndex": repeat_index,
        "gate": gate.name,
        "gateTuple": {
            "endpointCere": gate.endpoint_cere,
            "correctableMaskBit": False,
            "rootCorrectableCommand": gate.root_cor_enable,
        },
        "bits": [
            {"name": B0_NAME, "value": B0},
            {"name": B1_NAME, "value": B1},
        ],
        "claimBoundary": (
            "Stock-QEMU no-guest register/message-routing positive control only; "
            "not ESXi, physical-link, IRQ, log-delivery, or recovery evidence"
        ),
    }
    phases: dict[str, Any] = {
        "t0Baseline": {},
        "t1EffectiveControls": {},
        "t2PreInjection": {},
        "t3Immediate": [],
        "t4Window": [],
        "t5TransitionOrClear": [],
    }
    snapshots: dict[str, dict[str, Any]] = {}
    injections: list[dict[str, Any]] = []
    hmp_transcript = ""
    qemu_stdout = ""
    qemu_stderr = ""
    command: list[str] = []
    oracle: dict[str, Any]
    process: subprocess.Popen[str] | None = None
    client: aer.QTestClient | None = None
    monitor_path: Path | None = None

    with tempfile.TemporaryDirectory(prefix=f"qemu-aer-seq-{case_id}-") as tmp:
        tmp_path = Path(tmp)
        qtest_path = tmp_path / "qtest.sock"
        monitor_path = tmp_path / "monitor.sock"
        command = qemu_command(qemu, qtest_path, monitor_path)
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            aer.wait_socket(qtest_path, process, socket_timeout)
            aer.wait_socket(monitor_path, process, socket_timeout)
            client = aer.QTestClient(qtest_path)
            pciexbar = aer.enable_q35_ecam(client)
            bus_numbers = aer.configure_root_port_bus(client)
            root = aer.discover_device(
                client,
                bus=aer.ROOT_BUS,
                device=aer.ROOT_DEVICE,
                function=aer.ROOT_FUNCTION,
                expected_type=aer.PCI_EXP_TYPE_ROOT_PORT,
            )
            endpoint = aer.discover_device(
                client,
                bus=aer.ENDPOINT_BUS,
                device=aer.ENDPOINT_DEVICE,
                function=aer.ENDPOINT_FUNCTION,
                expected_type=aer.PCI_EXP_TYPE_ENDPOINT,
            )
            cold = snapshot_pair(client, endpoint, root)
            phases["t0Baseline"] = {
                "observedAtUtc": utc_now(),
                "q35Pciexbar": pciexbar,
                "rootPortBusNumbers": bus_numbers,
                "rootPort": root,
                "endpoint": endpoint,
                "coldSnapshot": cold,
            }

            configure_sequence(client, endpoint, root, gate)
            controls = snapshot_pair(client, endpoint, root)
            snapshots["effective-controls"] = controls
            phases["t1EffectiveControls"] = {
                "observedAtUtc": utc_now(),
                "gate": case_spec["gateTuple"],
                "snapshot": controls,
            }
            pre_injection = snapshot_pair(client, endpoint, root)
            snapshots["pre-injection"] = pre_injection
            phases["t2PreInjection"] = {
                "observedAtUtc": utc_now(),
                "snapshot": pre_injection,
            }

            recorder = SequenceRecorder(
                client=client,
                monitor_path=monitor_path,
                endpoint=endpoint,
                root=root,
            )
            recorder.snapshots.update(snapshots)
            execute_sequence(
                sequence=sequence,
                recorder=recorder,
                observation_window_ms=observation_window_ms,
            )
            snapshots = recorder.snapshots
            injections = recorder.injections
            phases.update(recorder.phases)
            hmp_transcript = "\n".join(recorder.hmp_transcript)
            oracle = evaluate_sequence(
                sequence=sequence,
                gate=gate,
                endpoint_requester_id=endpoint["requesterId"],
                snapshots=snapshots,
                injections=injections,
            )
        except Exception as error:
            oracle = blocked_oracle(error)
        finally:
            if client is not None:
                client.close()
            if process is not None:
                if monitor_path is not None:
                    aer.terminate_process(process, monitor_path)
                qemu_stdout, qemu_stderr = process.communicate(timeout=5)

    ended_at = utc_now()
    run_manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "caseId": case_id,
        "startedAtUtc": started_at,
        "endedAtUtc": ended_at,
        "host": {
            "platform": platform.platform(),
            "python": sys.version,
        },
        "qemu": {
            "path": str(qemu),
            "version": qemu_version,
            "sha256": qemu_hash,
            "aerSource": qemu_source,
        },
        "runner": {
            "path": str(Path(__file__).resolve()),
            "sha256": aer.sha256_file(Path(__file__).resolve()),
        },
        "command": command,
        "freshQemuProcessPerSequenceRepeat": True,
        "observationWindowMs": observation_window_ms,
    }
    result = {
        "schemaVersion": SCHEMA_VERSION,
        "case": case_spec,
        "run": {
            "startedAtUtc": started_at,
            "endedAtUtc": ended_at,
            "qemuExitCode": process.returncode if process is not None else None,
        },
        "injections": injections,
        "oracle": oracle,
        "verdict": oracle["verdict"],
    }

    artifacts: dict[str, dict[str, str]] = {}

    def save_named(name: str, value: Any) -> None:
        path = case_dir / name
        digest = aer.save_json(path, value)
        artifacts[name] = {
            "path": str(path.relative_to(output_dir)).replace("\\", "/"),
            "sha256": digest,
        }

    save_named("case.json", case_spec)
    save_named("run-manifest.json", run_manifest)
    save_named("t0-baseline.json", phases["t0Baseline"])
    save_named("t1-effective-controls.json", phases["t1EffectiveControls"])
    save_named("t2-pre-injection.json", phases["t2PreInjection"])
    save_named("t3-immediate.json", phases["t3Immediate"])
    save_named("t4-window.json", phases["t4Window"])
    save_named(
        "t5-transition-or-clear.json",
        phases["t5TransitionOrClear"],
    )
    save_named("oracle.json", oracle)
    hmp_path = case_dir / "hmp.txt"
    artifacts["hmp.txt"] = {
        "path": str(hmp_path.relative_to(output_dir)).replace("\\", "/"),
        "sha256": write_text(hmp_path, hmp_transcript),
    }
    stdout_path = case_dir / "qemu-stdout.txt"
    artifacts["qemu-stdout.txt"] = {
        "path": str(stdout_path.relative_to(output_dir)).replace("\\", "/"),
        "sha256": write_text(stdout_path, qemu_stdout),
    }
    stderr_path = case_dir / "qemu-stderr.txt"
    artifacts["qemu-stderr.txt"] = {
        "path": str(stderr_path.relative_to(output_dir)).replace("\\", "/"),
        "sha256": write_text(stderr_path, qemu_stderr),
    }
    result["artifacts"] = artifacts
    result_path = case_dir / "result.json"
    result_digest = aer.save_json(result_path, result)
    manifest_digest = write_artifact_manifest(case_dir)
    return {
        "caseId": case_id,
        "sequence": sequence,
        "repeatIndex": repeat_index,
        "gate": gate.name,
        "observationState": oracle["observationState"],
        "verdict": oracle["verdict"],
        "failedChecks": oracle.get("failedChecks", []),
        "fault": oracle.get("fault"),
        "result": {
            "path": str(result_path.relative_to(output_dir)).replace("\\", "/"),
            "sha256": result_digest,
        },
        "artifactManifest": {
            "path": str(
                (case_dir / "artifact-manifest.sha256").relative_to(output_dir)
            ).replace("\\", "/"),
            "sha256": manifest_digest,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run QEMU 11 Correctable AER First/Multiple, independent W1C, "
            "bit-OR, and re-arm positive-control sequences."
        )
    )
    parser.add_argument(
        "--qemu",
        default="/root/src/qemu-11.0.2/build-lab/qemu-system-x86_64",
    )
    parser.add_argument(
        "--qemu-aer-source",
        default="/root/src/qemu-11.0.2/hw/pci/pcie_aer.c",
        help="optional exact source file corresponding to the tested QEMU tree",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--sequence",
        action="append",
        choices=SEQUENCES,
        help="run only this sequence; repeat for multiple (default: all four)",
    )
    parser.add_argument(
        "--gate",
        choices=SUPPORTED_GATES,
        default="g101",
        help="g101 observes command enabled; g100 checks deposition equivalence",
    )
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--socket-timeout", type=int, default=10)
    parser.add_argument("--observation-window-ms", type=int, default=100)
    return parser.parse_args()


def aggregate_verdict(cases: list[dict[str, Any]]) -> str:
    verdicts = [case["verdict"] for case in cases]
    if verdicts and all(verdict == "PASS" for verdict in verdicts):
        return "PASS"
    if any(verdict == "BLOCKED" for verdict in verdicts):
        return "BLOCKED"
    if any(verdict == "FAIL" for verdict in verdicts):
        return "FAIL"
    return "INCONCLUSIVE"


def main() -> None:
    args = parse_args()
    if args.repeat < 1:
        raise ValueError("--repeat must be at least 1")
    if args.socket_timeout < 1:
        raise ValueError("--socket-timeout must be at least 1")
    if args.observation_window_ms < 0:
        raise ValueError("--observation-window-ms cannot be negative")

    qemu = Path(args.qemu).resolve()
    if not qemu.is_file():
        raise FileNotFoundError(qemu)
    output_dir = Path(args.output).resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise RuntimeError(f"output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    qemu_version = subprocess.run(
        [str(qemu), "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.splitlines()[0]
    if not re.search(r"QEMU emulator version 11(?:\.|\b)", qemu_version):
        raise RuntimeError(f"expected QEMU 11, got: {qemu_version}")
    qemu_hash = aer.sha256_file(qemu)

    qemu_source_path = Path(args.qemu_aer_source).resolve()
    qemu_source = (
        {
            "path": str(qemu_source_path),
            "sha256": aer.sha256_file(qemu_source_path),
        }
        if qemu_source_path.is_file()
        else None
    )
    selected_sequences = args.sequence or list(SEQUENCES)
    started_at = utc_now()
    aggregate: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "case": "QEMU-11-stock-AER-Correctable-root-state-sequences",
        "modelId": MODEL_ID,
        "scope": (
            "No-guest HMP+QTest register/message-routing positive control. "
            "No claim about ESXi, physical PCIe faults, interrupt delivery, "
            "logs, device recovery, quarantine, or tenant reuse."
        ),
        "executionStartedAtUtc": started_at,
        "topology": {
            "machine": "q35,accel=qtest",
            "rootPort": "pcie-root-port,id=rp",
            "endpoint": "virtio-net-pci,id=ep,disable-legacy=on,aer=on",
        },
        "qemu": {
            "path": str(qemu),
            "version": qemu_version,
            "sha256": qemu_hash,
            "aerSource": qemu_source,
        },
        "runner": {
            "path": str(Path(__file__).resolve()),
            "sha256": aer.sha256_file(Path(__file__).resolve()),
        },
        "requestedSequences": selected_sequences,
        "gate": args.gate,
        "repeat": args.repeat,
        "freshQemuProcessPerSequenceRepeat": True,
        "observationStates": list(OBSERVATION_STATES),
        "cases": [],
        "verdict": "RUNNING",
    }
    aer.save_json(output_dir / "result.json", aggregate)

    gate = aer.GATES[args.gate]
    for sequence in selected_sequences:
        for repeat_index in range(1, args.repeat + 1):
            case_result = run_sequence_case(
                qemu=qemu,
                qemu_version=qemu_version,
                qemu_hash=qemu_hash,
                qemu_source=qemu_source,
                output_dir=output_dir,
                sequence=sequence,
                repeat_index=repeat_index,
                gate=gate,
                socket_timeout=args.socket_timeout,
                observation_window_ms=args.observation_window_ms,
            )
            aggregate["cases"].append(case_result)
            aer.save_json(output_dir / "result.json", aggregate)

    aggregate["executionEndedAtUtc"] = utc_now()
    aggregate["verdict"] = aggregate_verdict(aggregate["cases"])
    aggregate["counts"] = {
        state: sum(
            case["observationState"] == state for case in aggregate["cases"]
        )
        for state in OBSERVATION_STATES
    }
    digest = aer.save_json(output_dir / "result.json", aggregate)
    print(
        json.dumps(
            {
                "verdict": aggregate["verdict"],
                "caseCount": len(aggregate["cases"]),
                "counts": aggregate["counts"],
                "result": str(output_dir / "result.json"),
                "sha256": digest,
            },
            indent=2,
        )
    )
    raise SystemExit(0 if aggregate["verdict"] == "PASS" else 1)


if __name__ == "__main__":
    main()
