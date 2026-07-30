#!/usr/bin/env python3
"""Offline unit tests for the ESXi Correctable AER root-sequence runner."""

from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

import esxi_passthru_capability as capability
import test_esxi_aer_root_sequence as runner
import test_esxi_log_window_v2_unit as log_v2_fixture
import test_qemu_aer_correctable_matrix as aer
import test_qemu_aer_root_sequence as qseq


REQUESTER_ID = 0x0101
OUTER_ENDPOINT_BDF = runner.DEFAULT_OUTER_ENDPOINT_BDF
OUTER_ROOT_BDF = runner.DEFAULT_OUTER_ROOT_BDF
VALID_HMP_ACK = (
    "OK id: test_fn1 root bus: 0000:00, bus: 1 devfn: 0.1\n"
)


def evaluate_observation(
    candidate: dict[str, Any],
    profile: dict[str, Any],
    *,
    outer_endpoint_bdf: Any = OUTER_ENDPOINT_BDF,
    outer_root_bdf: Any = OUTER_ROOT_BDF,
) -> dict[str, Any]:
    """Evaluate one fixture with an explicit frozen topology."""

    return runner.evaluate_case_observation(
        candidate,
        profile,
        outer_endpoint_bdf=outer_endpoint_bdf,
        outer_root_bdf=outer_root_bdf,
    )


def state(
    *,
    ces: int = 0,
    ced: bool = False,
    root_status: int = 0,
    source: int = 0,
    root_command: bool = True,
    ues: int = 0,
) -> dict[str, dict[str, int]]:
    return {
        "endpoint": {
            "deviceControl": aer.PCI_EXP_DEVCTL_CERE,
            "deviceStatus": aer.PCI_EXP_DEVSTA_CED if ced else 0,
            "uncorrectableErrorStatus": ues,
            "correctableErrorStatus": ces,
            "correctableErrorMask": 0,
        },
        "rootPort": {
            "bridgeControl": aer.PCI_BRIDGE_CTL_SERR,
            "deviceControl": aer.PCI_EXP_DEVCTL_CERE,
            "deviceStatus": 0,
            "uncorrectableErrorStatus": 0,
            "correctableErrorStatus": 0,
            "correctableErrorMask": 0,
            "rootErrorCommand": (
                aer.PCI_ERR_ROOT_CMD_COR_EN if root_command else 0
            ),
            "rootErrorStatus": root_status,
            "errorSourceIdentification": source,
        },
    }


def matched_fixture(
    name: str,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], str]:
    clean = state()
    first = state(
        ces=runner.B0,
        ced=True,
        root_status=qseq.ROOT_COR_FIRST,
        source=REQUESTER_ID,
    )
    multiple_b0 = state(
        ces=runner.B0,
        ced=True,
        root_status=qseq.ROOT_COR_MULTIPLE,
        source=REQUESTER_ID,
    )
    snapshots: dict[str, dict[str, Any]] = {
        "effective-controls": copy.deepcopy(clean),
        "pre-injection": copy.deepcopy(clean),
    }
    terminal = ""
    if name == "first-multiple":
        snapshots.update(
            {
                "first-b0": first,
                "first-window-observation": copy.deepcopy(first),
                "repeated-b0": multiple_b0,
                "stable-after-repeat": copy.deepcopy(multiple_b0),
                "post-cleanup": copy.deepcopy(clean),
            }
        )
        terminal = "stable-after-repeat"
    elif name == "independent-w1c":
        endpoint_cleared_root_live = state(
            root_status=qseq.ROOT_COR_FIRST,
            source=REQUESTER_ID,
        )
        root_cleared_endpoint_live = state(
            ces=runner.B0,
            ced=True,
            source=REQUESTER_ID,
        )
        clean_source_persists = state(source=REQUESTER_ID)
        snapshots.update(
            {
                "initial-b0": first,
                "initial-window": copy.deepcopy(first),
                "after-endpoint-clear-only-immediate": copy.deepcopy(
                    endpoint_cleared_root_live
                ),
                "after-endpoint-clear-only": endpoint_cleared_root_live,
                "after-root-cleanup-for-rebuild": clean_source_persists,
                "rebuilt-b0": copy.deepcopy(first),
                "after-root-clear-only-immediate": copy.deepcopy(
                    root_cleared_endpoint_live
                ),
                "after-root-clear-only": root_cleared_endpoint_live,
                "post-cleanup": clean_source_persists,
            }
        )
        terminal = "after-root-clear-only"
    elif name == "bit-or":
        both = state(
            ces=runner.B0 | runner.B1,
            ced=True,
            root_status=qseq.ROOT_COR_MULTIPLE,
            source=REQUESTER_ID,
        )
        snapshots.update(
            {
                "first-b0": first,
                "second-b1": both,
                "stable-after-or": copy.deepcopy(both),
                "post-cleanup": state(source=REQUESTER_ID),
            }
        )
        terminal = "stable-after-or"
    elif name == "rearm":
        root_live_ces_clear = state(
            ced=True,
            root_status=qseq.ROOT_COR_FIRST,
            source=REQUESTER_ID,
        )
        root_live_endpoint_clear = state(
            root_status=qseq.ROOT_COR_FIRST,
            source=REQUESTER_ID,
        )
        clean_source_persists = state(source=REQUESTER_ID)
        snapshots.update(
            {
                "initial-b0": first,
                "initial-window": copy.deepcopy(first),
                "after-ces-clear-only": root_live_ces_clear,
                "after-ced-clear-only": root_live_endpoint_clear,
                "after-root-clear": clean_source_persists,
                "rearmed-b0": copy.deepcopy(first),
                "rearmed-window": copy.deepcopy(first),
                "post-cleanup": clean_source_persists,
            }
        )
        terminal = "rearmed-window"
    else:
        raise ValueError(name)
    injections = []
    for label in qseq.expected_injection_labels(name):
        bit_name, mask = (
            (runner.B1_NAME, runner.B1)
            if label == "second-b1"
            else (runner.B0_NAME, runner.B0)
        )
        injections.append(
            {
                "label": label,
                "bit": bit_name,
                "mask": f"0x{mask:08x}",
                "command": (
                    "pcie_aer_inject_error -c test_fn1 "
                    f"0x{mask:08x}"
                ),
                "attempted": True,
                "mutationBoundaryCrossed": True,
                "safetyBoundary": "ATTRIBUTION_WINDOW",
                "accepted": True,
                "commandIssuedAt": "2026-07-29T00:00:00.000000Z",
                "elapsedSeconds": 0.001,
                "observedAt": "2026-07-29T00:00:00.001000Z",
                "raw": VALID_HMP_ACK,
                "fault": None,
            }
        )
    return snapshots, injections, terminal


def outer(public: dict[str, dict[str, int]]) -> dict[str, Any]:
    return {
        "endpointState": copy.deepcopy(public["endpoint"]),
        "rootState": copy.deepcopy(public["rootPort"]),
    }


def raw_gate_evidence(
    public: dict[str, dict[str, int]],
    gate: str = "g101",
    *,
    enforce_gate: bool = True,
) -> dict[str, Any]:
    snapshot = outer(public)
    effective = runner.esxi_aer.gate_tuple_from_snapshot(
        snapshot,
        runner.CONTROLLED_BITS,
    )
    requested = runner.SUPPORTED_GATES[gate]
    root_path = runner.esxi_aer.root_path_from_snapshot(snapshot)
    correctable_mask = int(
        snapshot["endpointState"]["correctableErrorMask"]
    )
    return {
        "requested": requested.as_dict() if enforce_gate else None,
        "effective": effective.as_dict(),
        "rootPath": root_path.as_dict(),
        "correctableMask": correctable_mask,
        "checks": (
            {
                "tupleMatches": effective == requested,
                "rootPathOpen": root_path.open,
                "b0AndB1Unmasked": not bool(
                    correctable_mask & runner.CONTROLLED_BITS
                ),
            }
            if enforce_gate
            else {
                "not-enforced-during-pre-sequence-owner-activation": True,
            }
        ),
    }


def raw_transition(
    command: str,
    status: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "command": command,
        "output": "",
        "status": f"VM status: {status}",
        "observedAt": "2026-07-29T00:00:00.000000Z",
        "reason": reason,
    }


def raw_gc_guard() -> dict[str, Any]:
    return {
        "wasEnabled": True,
        "thresholds": [700, 10, 10],
        "countsBefore": [1, 2, 3],
        "preResumeCollected": 0,
        "disabledBeforeResume": True,
        "armedAt": "2026-07-29T00:00:00.000000Z",
        "releaseState": "REENABLED_AFTER_PAUSE",
        "postPauseCollected": 0,
        "releasedAt": "2026-07-29T00:00:01.000000Z",
        "fault": None,
    }


def pinned_topology() -> dict[str, Any]:
    public = state()
    endpoint_state = copy.deepcopy(public["endpoint"])
    endpoint_state.update(
        {
            "aerHeader": 0x00020001,
            "uncorrectableErrorMask": 0,
        }
    )
    root_state = copy.deepcopy(public["rootPort"])
    root_state.update(
        {
            "aerHeader": 0x14820001,
            "primaryBus": 0,
            "secondaryBus": 1,
            "subordinateBus": 1,
        }
    )
    return {
        "q35Pciexbar": aer.MCFG_BASE | aer.Q35_PCIEXBAR_ENABLE,
        "endpoint": {
            "bus": 1,
            "device": 0,
            "function": 1,
            "requesterId": 0x0101,
            "vendorId": 0x1AF4,
            "deviceId": 0x1041,
            "pcieCapabilityOffset": 0x40,
            "aerCapabilityOffset": 0x100,
            "aerHeader": 0x00020001,
            "pcieType": aer.PCI_EXP_TYPE_ENDPOINT,
        },
        "endpointState": endpoint_state,
        "root": {
            "bus": 0,
            "device": 1,
            "function": 0,
            "requesterId": 0x0008,
            "vendorId": 0x1B36,
            "deviceId": 0x000C,
            "pcieCapabilityOffset": 0x54,
            "aerCapabilityOffset": 0x100,
            "aerHeader": 0x14820001,
            "pcieType": aer.PCI_EXP_TYPE_ROOT_PORT,
        },
        "rootState": root_state,
    }


def artifact_gate_topology() -> dict[str, Any]:
    """Return the coherent-case topology bound to the default lab BDFs."""

    topology = pinned_topology()
    topology["root"]["device"] = 8
    topology["root"]["requesterId"] = 0x0040
    return topology


def raw_coverage_window(
    boundary: str,
    label: str,
) -> dict[str, Any]:
    snapshot = outer(state())
    return {
        "label": label,
        "safetyBoundary": boundary,
        "safetyWindowKind": "MONITORED_WORKER",
        "maximumPollIntervalSeconds": 0.05,
        "pollIntervalSeconds": 0.025,
        "sampleCount": 1,
        "maximumObservedPollGapSeconds": 0.01,
        "tailGapSeconds": 0.01,
        "finalStopConfirmedElapsedSeconds": 0.021,
        "lastSampleFinishedElapsedSeconds": 0.011,
        "samples": [
            {
                "sampleIndex": 0,
                "actualElapsedSeconds": 0.011,
                "delaySeconds": 0.011,
                "sampleStartGapSeconds": 0.01,
                "sampleDurationSeconds": 0.001,
                "snapshot": snapshot,
                "safetyFaults": [],
            }
        ],
        "safetyEvents": [],
        "monitorFault": None,
        "immediateStopFault": None,
        "finalStopFault": None,
        "executorShutdownFault": None,
        "controlFault": None,
        "tailGapFault": None,
        "pause": {"state": "paused"},
        "coverageComplete": True,
    }


def raw_scheduled_poll(boundary: str) -> dict[str, Any]:
    snapshot = outer(state())
    samples: list[dict[str, Any]] = []
    for index in range(26):
        sample_start = round(index * 0.04, 9)
        actual_elapsed = round(sample_start + 0.001, 9)
        samples.append(
            {
                "sampleIndex": index,
                "actualElapsedSeconds": actual_elapsed,
                "sampleStartGapSeconds": 0.0 if index == 0 else 0.04,
                "sampleDurationSeconds": 0.001,
                "capturedAt": f"fixture-{boundary}-{index}",
                "readback": None,
                "safetyFaults": [],
                "snapshot": copy.deepcopy(snapshot),
            }
        )
    targets = [0.0, 0.05, 0.25, 1.0]
    timeline = []
    for target in targets:
        sample = next(
            item
            for item in samples
            if item["actualElapsedSeconds"] >= target
        )
        timeline.append(
            {
                "delaySeconds": target,
                "targetDelaySeconds": target,
                "actualElapsedSeconds": sample["actualElapsedSeconds"],
                "sampleIndex": sample["sampleIndex"],
                "capturedAt": sample["capturedAt"],
                "readback": sample["readback"],
                "safetyFaults": [],
                "snapshot": copy.deepcopy(sample["snapshot"]),
            }
        )
    return {
        "safetyWindowKind": "CONTINUOUS_TIMELINE",
        "safetyBoundary": boundary,
        "targetDelaysSeconds": targets,
        "targetCount": len(targets),
        "maximumPollIntervalSeconds": 0.05,
        "targetPollIntervalSeconds": 0.025,
        "maximumObservedPollGapSeconds": 0.04,
        "sampleCount": len(samples),
        "samples": samples,
        "timeline": timeline,
        "completedTargetCount": len(targets),
        "complete": True,
        "pollFaults": [],
        "safetyEvents": [],
    }


def raw_gate_window(
    *,
    boundary: str,
    kind: str,
    outcome: str,
    label: str,
) -> dict[str, Any]:
    poll = raw_scheduled_poll(boundary)
    last_elapsed = poll["samples"][-1]["actualElapsedSeconds"]
    poll["closure"] = {
        "mode": "PAUSED_ACK",
        "stopConfirmed": True,
        "stopConfirmedElapsedSeconds": last_elapsed + 0.01,
        "lastSampleFinishedElapsedSeconds": last_elapsed,
        "tailGapSeconds": 0.01,
    }
    return {
        "label": label,
        "startedAt": "2026-07-29T00:00:00.100000Z",
        "finishedAt": "2026-07-29T00:00:00.900000Z",
        "safetyBoundary": boundary,
        "safetyWindowKind": kind,
        "outcome": outcome,
        "qemuHeldPaused": True,
        "timeline": {
            "resume": {"state": "running"},
            "resumedSafetyPoll": poll,
        },
    }


def raw_service_window(
    label: str,
    description: str = "fixture service window",
) -> dict[str, Any]:
    scheduled = raw_scheduled_poll("ATTRIBUTION_WINDOW")
    samples = []
    for source in scheduled["samples"]:
        snapshot = copy.deepcopy(source["snapshot"])
        public = runner.outer_to_public_state(snapshot)
        samples.append(
            {
                "sampleIndex": source["sampleIndex"],
                "actualElapsedSeconds": source[
                    "actualElapsedSeconds"
                ],
                "sampleStartGapSeconds": source[
                    "sampleStartGapSeconds"
                ],
                "sampleDurationSeconds": source[
                    "sampleDurationSeconds"
                ],
                "capturedAt": source["capturedAt"],
                "gate": raw_gate_evidence(public),
                "endpoint": {
                    "deviceStatus": public["endpoint"]["deviceStatus"],
                    "uncorrectableErrorStatus": public["endpoint"][
                        "uncorrectableErrorStatus"
                    ],
                    "correctableErrorStatus": public["endpoint"][
                        "correctableErrorStatus"
                    ],
                },
                "root": {
                    "deviceStatus": public["rootPort"]["deviceStatus"],
                    "uncorrectableErrorStatus": public["rootPort"][
                        "uncorrectableErrorStatus"
                    ],
                    "rootErrorStatus": public["rootPort"][
                        "rootErrorStatus"
                    ],
                },
                "safetyFaults": [],
                "snapshot": snapshot,
                "partial": False,
            }
        )
    timeline = []
    for source in scheduled["timeline"]:
        sample = samples[source["sampleIndex"]]
        timeline.append(
            {
                "delaySeconds": source["delaySeconds"],
                "targetDelaySeconds": source["targetDelaySeconds"],
                "actualElapsedSeconds": source[
                    "actualElapsedSeconds"
                ],
                "sampleIndex": source["sampleIndex"],
                "capturedAt": source["capturedAt"],
                "gate": copy.deepcopy(sample["gate"]),
                "safetyFaults": [],
                "snapshot": copy.deepcopy(sample["snapshot"]),
            }
        )
    last_elapsed = samples[-1]["actualElapsedSeconds"]
    poll = {
        "maximumIntervalSeconds": scheduled[
            "maximumPollIntervalSeconds"
        ],
        "targetIntervalSeconds": scheduled["targetPollIntervalSeconds"],
        "targetDelaysSeconds": scheduled["targetDelaysSeconds"],
        "sampleCount": len(samples),
        "targetCount": scheduled["targetCount"],
        "completedTargetCount": scheduled["completedTargetCount"],
        "maximumObservedGapSeconds": scheduled[
            "maximumObservedPollGapSeconds"
        ],
        "maximumObservedReadDurationSeconds": 0.001,
        "snapshotMode": "PINNED_TOPOLOGY_BLOCK_BATCH",
        "pauseConfirmedElapsedSeconds": last_elapsed + 0.01,
        "lastSampleFinishedElapsedSeconds": last_elapsed,
        "tailGapSeconds": 0.01,
        "samples": samples,
    }
    return {
        "label": label,
        "description": description,
        "safetyBoundary": "ATTRIBUTION_WINDOW",
        "safetyWindowKind": "SERVICE_WINDOW",
        "startedAtMonotonic": 1.0,
        "resume": raw_transition(
            "cont",
            "running",
            f"fixture service window {label}",
        ),
        "timeline": timeline,
        "safetyPoll": poll,
        "ownerObservation": None,
        "ownerObservationPolicy": (
            "pre-sequence and monitored terminal bracket only"
        ),
        "timelineFault": None,
        "pause": raw_transition(
            "stop",
            "paused",
            f"close fixture service window {label}",
        ),
        "pauseFault": None,
        "pauseTailFault": None,
        "pythonGcGuard": raw_gc_guard(),
        "gcGuardFault": None,
        "finalizationFault": None,
        "coverageComplete": True,
        "finishedAt": "2026-07-29T00:00:01.000000Z",
    }


def raw_monitored_window(
    label: str,
    description: str,
    *,
    boundary: str = "ATTRIBUTION_WINDOW",
    enforce_gate: bool = True,
) -> dict[str, Any]:
    public = state()
    snapshot = outer(public)
    sample = {
        "sampleIndex": 0,
        "delaySeconds": 0.011,
        "actualElapsedSeconds": 0.011,
        "sampleStartGapSeconds": 0.01,
        "sampleDurationSeconds": 0.001,
        "observedAt": "2026-07-29T00:00:00.011000Z",
        "gate": raw_gate_evidence(
            public,
            enforce_gate=enforce_gate,
        ),
        "endpoint": {
            "deviceStatus": public["endpoint"]["deviceStatus"],
            "uncorrectableErrorStatus": public["endpoint"][
                "uncorrectableErrorStatus"
            ],
            "correctableErrorStatus": public["endpoint"][
                "correctableErrorStatus"
            ],
        },
        "root": {
            "deviceStatus": public["rootPort"]["deviceStatus"],
            "uncorrectableErrorStatus": public["rootPort"][
                "uncorrectableErrorStatus"
            ],
            "rootErrorStatus": public["rootPort"]["rootErrorStatus"],
        },
        "safetyFaults": [],
        "snapshot": snapshot,
        "readFault": None,
        "partial": False,
    }
    return {
        "label": label,
        "description": description,
        "safetyBoundary": boundary,
        "safetyWindowKind": "MONITORED_WORKER",
        "enforceGate": enforce_gate,
        "startedAtMonotonic": 1.0,
        "resume": raw_transition(
            "cont",
            "running",
            f"fixture monitored window {label}",
        ),
        "maximumPollIntervalSeconds": 0.05,
        "pollIntervalSeconds": 0.025,
        "sampleCount": 1,
        "maximumObservedPollGapSeconds": 0.01,
        "maximumObservedReadDurationSeconds": 0.001,
        "snapshotMode": "PINNED_TOPOLOGY_BLOCK_BATCH",
        "finalStopConfirmedElapsedSeconds": 0.021,
        "lastSampleFinishedElapsedSeconds": 0.011,
        "tailGapSeconds": 0.01,
        "samples": [sample],
        "firstSnapshot": copy.deepcopy(snapshot),
        "lastSnapshot": copy.deepcopy(snapshot),
        "safetyEvents": [],
        "monitorFault": None,
        "immediateStopFault": None,
        "finalStopFault": None,
        "executorShutdownFault": None,
        "cancelFault": None,
        "pythonGcGuard": raw_gc_guard(),
        "gcGuardFault": None,
        "controlFault": None,
        "tailGapFault": None,
        "finalizationFault": None,
        "gateFault": False,
        "workerFault": None,
        "pause": raw_transition(
            "stop",
            "paused",
            f"close fixture monitored window {label}",
        ),
        "coverageComplete": True,
        "finishedAt": "2026-07-29T00:00:01.000000Z",
    }


def raw_public_snapshot_record(
    label: str,
    snapshot: dict[str, dict[str, int]],
    *,
    phase: str,
    boundary: str,
    operation: str = "fixture paused numeric capture",
    gate: str = "g101",
) -> dict[str, Any]:
    raw_snapshot = outer(snapshot)
    return {
        "recordKind": runner.PAUSED_NUMERIC_SNAPSHOT_RECORD_KIND,
        "label": label,
        "phase": phase,
        "operation": operation,
        "safetyBoundary": boundary,
        "observedAt": "2026-07-26T00:00:00.000000Z",
        "qemuPaused": True,
        "gate": raw_gate_evidence(snapshot, gate),
        "snapshot": raw_snapshot,
        "sourceMeaning": runner.root_source_meaning(snapshot),
        "safetyFaults": [],
        "partial": False,
    }


def raw_pre_mutation_snapshot_record(
    label: str,
    snapshot: dict[str, dict[str, int]],
    *,
    boundary: str,
    operation: str = "fixture pre-mutation authority",
    gate: str = "g101",
) -> dict[str, Any]:
    return {
        "recordKind": (
            runner.PRE_MUTATION_NUMERIC_SNAPSHOT_RECORD_KIND
        ),
        "label": f"{label}-pre-state",
        "operation": operation,
        "safetyBoundary": boundary,
        "observedAt": "2026-07-26T00:00:00.000000Z",
        "qemuPaused": True,
        "gate": raw_gate_evidence(snapshot, gate),
        "snapshot": outer(snapshot),
        "safetyFaults": [],
        "partial": False,
    }


def raw_final_running_window() -> dict[str, Any]:
    return {
        "label": "fixture-final-running-tail",
        "safetyBoundary": "POST_CLEANUP",
        "safetyWindowKind": "FINAL_RUNNING_STABILIZATION",
        "outcome": "CLEAN_RUNNING",
        "resume": {"state": "running"},
        "safetyPoll": raw_scheduled_poll("POST_CLEANUP"),
        "gateFaults": [],
        "resumeFault": None,
        "samplerFault": None,
        "postSamplerAnalysisFault": None,
        "failStopFault": None,
        "finalizationFault": None,
    }


def normalized_fixture_coverage() -> list[dict[str, Any]]:
    return runner.build_safety_coverage(
        t0={
            "preSequenceSafetyWindows": [
                raw_coverage_window("PRE_INJECTION", "fixture-pre")
            ]
        },
        t1={},
        t2={},
        t3={},
        t4={
            "windows": [
                raw_coverage_window(
                    "ATTRIBUTION_WINDOW",
                    "fixture-attribution",
                )
            ]
        },
        t5={
            "activeVmCleanupSafetyWindows": [
                raw_coverage_window("POST_CLEANUP", "fixture-post")
            ]
        },
        cleanup={},
    )


def evaluation_input(
    sequence: str,
    *,
    owner_phase: str = "O0",
) -> dict[str, Any]:
    snapshots, injections, terminal = matched_fixture(sequence)
    terminal_state = snapshots[terminal]
    active_users = (
        []
        if owner_phase == "O0"
        else [{"vm": "runner-vm", "runnerCreated": True}]
    )
    candidate = {
        "schemaVersion": 1,
        "caseId": f"fixture-{sequence}",
        "sequence": sequence,
        "gate": "g101",
        "ownerPhase": owner_phase,
        "qemuDevice": "test_fn1",
        "requesterId": REQUESTER_ID,
        "enteredInjection": True,
        "preflight": {
            "environmentBound": True,
            "ownerBound": True,
            "cleanBaseline": True,
            "gatePausedReadback": True,
            "evidenceProtocolReady": True,
        },
        "snapshots": snapshots,
        "injections": injections,
        "ownerObservations": [
            {
                "currentOwner": (
                    "VMkernel"
                    if owner_phase == "O0"
                    else "VM Passthru"
                ),
                "activeUsers": active_users,
                "hostResponsive": True,
            }
        ],
        "gateStable": True,
        "hostProjection": {
            "hostEndpoint": {
                "deviceControl": terminal_state["endpoint"][
                    "deviceControl"
                ],
                "deviceStatus": terminal_state["endpoint"]["deviceStatus"],
                "correctableStatus": terminal_state["endpoint"][
                    "correctableErrorStatus"
                ],
                "uncorrectableStatus": 0,
                "correctableMask": terminal_state["endpoint"][
                    "correctableErrorMask"
                ],
            },
            "hostRoot": {
                "bridgeControl": terminal_state["rootPort"][
                    "bridgeControl"
                ],
                "deviceControl": terminal_state["rootPort"][
                    "deviceControl"
                ],
                "deviceStatus": terminal_state["rootPort"]["deviceStatus"],
                "correctableStatus": terminal_state["rootPort"][
                    "correctableErrorStatus"
                ],
                "correctableMask": terminal_state["rootPort"][
                    "correctableErrorMask"
                ],
                "rootErrorStatus": terminal_state["rootPort"][
                    "rootErrorStatus"
                ],
                "uncorrectableStatus": 0,
                "rootErrorCommand": terminal_state["rootPort"][
                    "rootErrorCommand"
                ],
                "errorSourceIdentification": terminal_state["rootPort"][
                    "errorSourceIdentification"
                ],
            },
            "outerBeforeRemote": outer(terminal_state),
            "outerAfterRemote": outer(terminal_state),
        },
        "hostLogClassification": (
            "NOT_OBSERVED_IN_MARKER_AND_BYTE_CURSOR_WINDOW"
        ),
        "guestClassification": (
            "NOT_APPLICABLE_O0"
            if owner_phase == "O0"
            else "O4_BOUND_DRIVER_AND_HEARTBEAT"
        ),
        "o4GuestEvidenceValid": owner_phase == "O4",
        "evidenceComplete": True,
        "safetyCoverage": normalized_fixture_coverage(),
        "safetyFaults": [],
        "containmentRequired": False,
        "containmentReasons": [],
        "containmentEvidence": [],
        "fault": None,
        "cleanupComplete": True,
    }
    candidate["safetyObservations"] = [
        {
            "boundary": "PRE_INJECTION",
            "endpointDeviceStatus": 0,
            "endpointUncorrectableErrorStatus": 0,
            "rootDeviceStatus": 0,
            "rootUncorrectableErrorStatus": 0,
            "rootErrorStatus": 0,
            "provenance": {
                "sourceKind": "QTEST_OUTER_SNAPSHOT",
                "artifact": "t0-baseline.json",
                "jsonPath": "/explicitBaselineClear/after",
                "label": "fixture-clean-baseline",
                "boundarySource": "ALLOW_LISTED_ARTIFACT_ROUTE",
            },
        }
    ]
    return candidate


def write_required_case_artifacts(root: Path) -> None:
    for name in runner.REQUIRED_CASE_ARTIFACTS - {
        "artifact-manifest.sha256"
    }:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix == ".json":
            path.write_text("{}\n", encoding="utf-8")
        else:
            path.write_text("fixture\n", encoding="utf-8")


def write_root_manifest(root: Path) -> None:
    manifest = root / "artifact-manifest.sha256"
    lines = [
        f"{runner.sha256_file(path)}  {path.relative_to(root).as_posix()}"
        for path in sorted(root.rglob("*"))
        if path.is_file() and path != manifest
    ]
    manifest.write_text("\n".join(lines) + "\n", encoding="ascii")


def v2_inventory_record() -> dict[str, Any]:
    command = runner.log_v2.inventory_command()
    digest = "0" * 64
    stdout = "\n".join(
        (
            f"MEMBER\t{source}\t{remote_path}\t1\t0\t1\t0\t{digest}"
        )
        for source, remote_path in runner.log_v2.LOG_PATHS.items()
    ) + "\n"
    return runner.log_v2.parse_inventory(
        stdout,
        command=command,
        return_code=0,
        stderr="",
    )


def v2_marker_write_record(marker: str) -> dict[str, Any]:
    return {
        "protocol": runner.log_v2.PROTOCOL_ID,
        "marker": marker,
        "command": runner.log_v2.marker_command(marker),
        "returnCode": 0,
        "stdout": "",
        "stderr": "",
        "observedAt": "2026-07-29T00:00:00.000000Z",
    }


def v2_marker_visibility_record(marker: str) -> dict[str, Any]:
    line = (
        "2026-07-29T00:00:00.000Z In(123) "
        f"Hostd[456]: mark: {marker}"
    )
    sources = {
        source: {
            "command": runner.log_v2.marker_probe_command(source),
            "returnCode": 0,
            "stdout": line + "\n",
            "stderr": "",
            "authenticCount": 1,
            "matchedLines": [line],
        }
        for source in runner.log_v2.LOG_PATHS
    }
    return {
        "protocol": runner.log_v2.PROTOCOL_ID,
        "marker": marker,
        "visible": True,
        "ambiguous": False,
        "sources": copy.deepcopy(sources),
        "attempts": [{"sources": copy.deepcopy(sources)}],
    }


def write_coherent_case(
    case_dir: Path,
    profile_path: Path,
    *,
    case_id: str = "o0__bit-or__g101__r01",
    campaign_id: str = "fixture-campaign",
    sequence: str = "bit-or",
    gate: str = "g101",
    repeat_index: int = 1,
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate = evaluation_input(sequence)
    candidate.update(
        {
            "campaignId": campaign_id,
            "caseRunId": f"{campaign_id}--{case_id}",
            "caseId": case_id,
            "gate": gate,
            "repeatIndex": repeat_index,
        }
    )
    schema_path = profile_path.with_name("oracle-profile.schema.json")
    shutil.copyfile(runner.ORACLE_PROFILE_SCHEMA, schema_path)
    profile = runner.load_oracle_profile(profile_path, schema_path)
    timing = profile["timingEnvelope"]
    protocol = runner.log_v2.protocol_for_case(campaign_id, case_id)
    terminal_alias = {
        "first-multiple": "stable-after-repeat",
        "independent-w1c": "after-root-clear-only",
        "bit-or": "stable-after-or",
        "rearm": "rearmed-window",
    }[sequence]
    candidate["snapshots"]["terminal-post-host-window"] = copy.deepcopy(
        candidate["snapshots"][terminal_alias]
    )
    closed_plan = runner.planned_phase_records(
        sequence=sequence,
        owner_phase=candidate["ownerPhase"],
        qemu_device=candidate["qemuDevice"],
    )
    phase_records: dict[str, list[dict[str, Any]]] = {
        phase: [] for phase in ("t2", "t3", "t4", "t5")
    }
    for phase, specifications in closed_plan.items():
        for specification in specifications:
            record_kind = specification.get("recordKind")
            window_kind = specification.get("safetyWindowKind")
            label = specification["label"]
            if record_kind == runner.PAUSED_NUMERIC_SNAPSHOT_RECORD_KIND:
                snapshot = candidate["snapshots"].get(label)
                if snapshot is None:
                    raise AssertionError(
                        f"fixture lacks planned snapshot {label}"
                    )
                record = raw_public_snapshot_record(
                    label,
                    snapshot,
                    phase=specification["phase"],
                    boundary=specification["safetyBoundary"],
                    operation=specification["operation"],
                    gate=gate,
                )
            elif (
                record_kind
                == runner.PRE_MUTATION_NUMERIC_SNAPSHOT_RECORD_KIND
            ):
                record = raw_pre_mutation_snapshot_record(
                    label.removesuffix("-pre-state"),
                    state(),
                    boundary=specification["safetyBoundary"],
                    operation=specification["operation"],
                    gate=gate,
                )
            elif (
                record_kind
                == runner.O4_GUEST_WINDOW_RECEIPT_RECORD_KIND
            ):
                window_seconds = float(timing["guestWindowSeconds"])
                elapsed = 1.0
                record = {
                    "recordKind": (
                        runner.O4_GUEST_WINDOW_RECEIPT_RECORD_KIND
                    ),
                    "label": label,
                    "observedAt": "2026-07-29T00:00:00.000000Z",
                    "window": {
                        "windowSeconds": window_seconds,
                        "elapsedSinceOpenObserved": elapsed,
                        "remainingSeconds": window_seconds - elapsed,
                        "requiredRemainingSeconds": float(
                            timing[
                                "minimumGuestWindowRemainingSecondsO4"
                            ]
                        ),
                    },
                }
            elif window_kind == "SERVICE_WINDOW":
                record = raw_service_window(
                    label,
                    specification["description"],
                )
            elif window_kind == "MONITORED_WORKER":
                record = raw_monitored_window(
                    label,
                    specification["description"],
                )
            else:
                raise AssertionError(
                    f"unsupported fixture plan record: {specification}"
                )
            phase_records[phase].append(record)
    owner = {
        **copy.deepcopy(candidate["ownerObservations"][0]),
        "label": "t0-owner",
        "observedAt": "2026-07-29T00:00:00.000000Z",
        "target": {},
        "heartbeatSource": "monitored terminal uptime command",
    }
    terminal_owner = {
        **copy.deepcopy(owner),
        "label": "t4-terminal-owner",
        "observedAt": "2026-07-29T00:00:01.000000Z",
    }
    candidate["ownerObservations"] = [
        copy.deepcopy(owner),
        copy.deepcopy(terminal_owner),
    ]
    case_spec = {
        "schemaVersion": runner.SCHEMA_VERSION,
        "modelId": runner.RUNNER_MODEL_ID,
        "campaignId": candidate["campaignId"],
        "caseRunId": candidate["caseRunId"],
        "caseId": case_id,
        "ownerPhase": candidate["ownerPhase"],
        "sequence": candidate["sequence"],
        "gate": candidate["gate"],
        "repeatIndex": candidate["repeatIndex"],
        "qemuDevice": candidate["qemuDevice"],
        "controlledBits": [
            {"name": runner.B0_NAME, "mask": f"0x{runner.B0:08x}"},
            {"name": runner.B1_NAME, "mask": f"0x{runner.B1:08x}"},
        ],
        "requestedGate": runner.SUPPORTED_GATES[gate].as_dict(),
        "ownerContract": runner.OWNER_PHASES[candidate["ownerPhase"]],
        "logWindowProtocol": protocol,
        "claimBoundary": runner.case_claim_boundary(),
        "safetyBoundary": {
            "injectionClass": "Correctable-only",
            "hmpForm": (
                "pcie_aer_inject_error -c <closed-qdev> "
                "<B0-or-B1-mask>"
            ),
            "uncorrectableInjectionSurface": False,
            "maximumSafetyPollIntervalSeconds": timing[
                "maximumSafetyPollIntervalSeconds"
            ],
            "safetyPollTargetIntervalSeconds": (
                timing["maximumSafetyPollIntervalSeconds"] / 2.0
            ),
            "qtestWritableFields": runner.QTEST_WRITABLE_FIELD_CLAIMS,
        },
    }
    dependency_paths = (
        Path(runner.__file__).resolve(),
        runner.SCRIPT_DIR / "esxi_log_window_v2.py",
        runner.SCRIPT_DIR / "test_esxi_aer_correctable_matrix.py",
        runner.SCRIPT_DIR / "test_qemu_aer_correctable_matrix.py",
        runner.SCRIPT_DIR / "test_qemu_aer_root_sequence.py",
        runner.SCRIPT_DIR / "esxi_passthru_capability.py",
        profile_path.resolve(),
        schema_path.resolve(),
    )
    repository_inputs = [
        {
            "path": str(path),
            "exists": True,
            "sha256": runner.sha256_file(path),
        }
        for path in dependency_paths
    ]
    fixture_environment = {
        "esxi": {"build": "fixture", "systemUuid": "fixture"},
        "outerQemu": {
            "pid": 1,
            "commandLine": [
                "fixture-qemu",
                "-device",
                (
                    "pcie-root-port,id=test_rp,bus=pcie.0,"
                    "addr=0x08.0"
                ),
                "-device",
                (
                    "virtio-net-pci,id=test_fn1,bus=test_rp,"
                    "addr=0x00.1"
                ),
            ],
        },
    }
    source_hashes = {
        "hashAlgorithm": "SHA-256",
        "capturedAt": "fixture",
        "environment": fixture_environment,
        "repositoryInputs": repository_inputs,
        "pythonPackages": {
            name: runner.installed_distribution_version(name)
            for name in ("jsonschema", "pyvmomi")
        },
        "qemuAerSource": None,
        "outerQemuBinary": {
            "commandLine": ["fixture-qemu"],
            "path": None,
            "exists": False,
            "sha256": None,
        },
    }
    runner.save_json(
        case_dir / "case.json",
        case_spec,
    )
    runner.save_json(
        case_dir / "run-manifest.json",
        {
            "schemaVersion": runner.SCHEMA_VERSION,
            "runId": candidate["campaignId"],
            "campaignId": candidate["campaignId"],
            "caseRunId": candidate["caseRunId"],
            "caseId": case_id,
            "ownerPhase": candidate["ownerPhase"],
            "sequence": candidate["sequence"],
            "gate": candidate["gate"],
            "repeatIndex": candidate["repeatIndex"],
            "qemuDevice": candidate["qemuDevice"],
            "startedAt": "2026-07-29T00:00:00.000000Z",
            "host": {
                "platform": "fixture-platform",
                "python": "fixture-python",
            },
            "runner": {
                "path": str(Path(runner.__file__).resolve()),
                "sha256": runner.sha256_file(
                    Path(runner.__file__).resolve()
                ),
            },
            "runtimeDependencies": repository_inputs,
            "oracleProfile": {
                "path": str(profile_path.resolve()),
                "sha256": runner.sha256_file(profile_path),
                "id": profile["id"],
                "profileState": profile["profileState"],
                "schemaSha256": runner.sha256_file(schema_path),
            },
            "environment": fixture_environment,
            "timelineDelaysSeconds": timing["timelineDelaysSeconds"],
            "finalObservationSecondsO0": timing[
                "minimumFinalObservationSecondsO0"
            ],
            "freshExplicitBaselinePerCase": True,
            "sourcePolicy": profile["sourcePolicy"],
        },
    )
    runner.save_json(
        case_dir / "source-and-binary-hashes.json",
        source_hashes,
    )
    pre_sequence_window = raw_monitored_window(
        "pre-sequence-evidence-collection",
        (
            "validate the retained ESXi log rotation-chain layout, write an "
            "official per-source BEFORE marker, and collect baseline "
            "host/owner proof under continuous Correctable-only safety polling"
        ),
        boundary="PRE_INJECTION",
        enforce_gate=False,
    )
    clean_public = state()
    t0 = {
        "startedAt": "2026-07-29T00:00:00.000000Z",
        "environment": copy.deepcopy(fixture_environment),
        "explicitBaselineClear": {},
        "postBaselineClearPausedReadback": {
            "label": "post-baseline-clear-paused-readback",
            "safetyBoundary": "PRE_INJECTION",
            "snapshot": outer(clean_public),
            "safetyFaults": [],
            "partial": False,
        },
        "hostPhase": None,
        "faults": [],
        "ownerObservation": owner,
        "preflight": copy.deepcopy(candidate["preflight"]),
        "guestBefore": None,
        "preSequenceSafetyWindows": [pre_sequence_window],
        "preSequenceSafetyMonitor": {
            "maximumPollIntervalSeconds": pre_sequence_window[
                "maximumPollIntervalSeconds"
            ],
            "maximumObservedPollGapSeconds": pre_sequence_window[
                "maximumObservedPollGapSeconds"
            ],
            "sampleCount": pre_sequence_window["sampleCount"],
            "safetyEvents": pre_sequence_window["safetyEvents"],
        },
        "kernelPreconditions": {
            "enablePCIErrorsRuntimeTrue": True,
            "pcipDisablePciErrReportingRuntimeFalse": True,
        },
        "finishedAt": "2026-07-29T00:00:01.000000Z",
    }
    def v2_pieces(
        _source: str,
        case_protocol: dict[str, Any],
    ) -> list[tuple[int | None, str, bytes]]:
        return [
            (
                None,
                "plain",
                (
                    log_v2_fixture._marker_line(case_protocol["before"])
                    + log_v2_fixture._marker_line(case_protocol["after"])
                ),
            )
        ]

    prior_campaign = log_v2_fixture.CAMPAIGN_ID
    prior_case = log_v2_fixture.CASE_ID
    try:
        log_v2_fixture.CAMPAIGN_ID = campaign_id
        log_v2_fixture.CASE_ID = case_id
        v2_fixture = log_v2_fixture._CaseFixture(
            case_dir,
            v2_pieces,
        )
    finally:
        log_v2_fixture.CAMPAIGN_ID = prior_campaign
        log_v2_fixture.CASE_ID = prior_case
    self_protocol = v2_fixture.protocol
    if self_protocol != protocol:
        raise AssertionError("fixture V2 protocol drifted")
    t0["logWindowPreflightInventory"] = v2_inventory_record()
    t0["beforeMarker"] = v2_marker_write_record(protocol["before"])
    t0["beforeMarkerVisibility"] = v2_marker_visibility_record(
        protocol["before"]
    )
    gate_lease = raw_gate_window(
        boundary="PRE_INJECTION",
        kind="GATE_LEASE_APPLY",
        outcome="EFFECTIVE",
        label="fixture-gate-apply",
    )
    gate_topology = artifact_gate_topology()
    gate_lease["original"] = {
        "capturedAt": "2026-07-29T00:00:00.000000Z",
        "readback": runner.esxi_aer.gate_readback(
            gate_topology,
            runner.CONTROLLED_BITS,
        ),
        "safetyFaults": [],
        "snapshot": gate_topology,
    }
    t1 = {
        "requestedGate": runner.SUPPORTED_GATES[gate].as_dict(),
        "controlledBits": f"0x{runner.CONTROLLED_BITS:08x}",
        "gateStable": candidate["gateStable"],
        "activeVm": None,
        "remoteIsoSha256": None,
        "gateLease": gate_lease,
    }
    t2 = {
        "steps": phase_records["t2"],
    }
    t3 = {
        "snapshots": phase_records["t3"],
        "injections": copy.deepcopy(candidate["injections"]),
    }
    terminal_projection = candidate["hostProjection"]
    terminal_phase = {
        "aer": {
            key: value
            for key, value in terminal_projection["hostEndpoint"].items()
            if key not in {"deviceControl", "deviceStatus"}
        },
        "endpointPcie": {
            "deviceControl": terminal_projection["hostEndpoint"][
                "deviceControl"
            ],
            "deviceStatus": terminal_projection["hostEndpoint"][
                "deviceStatus"
            ],
        },
        "rootAer": {
            key: value
            for key, value in terminal_projection["hostRoot"].items()
            if key not in {
                "bridgeControl",
                "deviceControl",
                "deviceStatus",
            }
        },
        "rootPcie": {
            "deviceControl": terminal_projection["hostRoot"][
                "deviceControl"
            ],
            "deviceStatus": terminal_projection["hostRoot"][
                "deviceStatus"
            ],
        },
        "rootBridgeControl": terminal_projection["hostRoot"][
            "bridgeControl"
        ],
        "outerQemuAer": copy.deepcopy(
            terminal_projection["outerBeforeRemote"]
        ),
        "outerQemuAerPostRemote": copy.deepcopy(
            terminal_projection["outerAfterRemote"]
        ),
        "outerQemuAerSamples": terminal_projection.get("outerSamples"),
        "startedAt": None,
        "outerQemuAerCapturedAt": None,
        "finishedAt": None,
    }
    t0["hostPhase"] = copy.deepcopy(terminal_phase)
    candidate["hostProjection"] = runner.phase_projection(terminal_phase)
    v2_window = runner.log_v2.rebuild_log_window(
        case_dir=case_dir,
        campaign_id=campaign_id,
        case_id=case_id,
        case_protocol=protocol,
        capture_summary=v2_fixture.summary,
        semantic_classifier=runner.esxi_aer.aer_log_lines,
    )
    if v2_window["complete"] is not True:
        raise AssertionError(v2_window["faults"])
    candidate["hostLogClassification"] = v2_window["classification"]
    close_log_monitor = next(
        item
        for item in phase_records["t4"]
        if item.get("label") == "close-log-window"
    )
    t4 = {
        "windows": phase_records["t4"],
        "hostTerminalPhase": copy.deepcopy(terminal_phase),
        "hostProjection": copy.deepcopy(candidate["hostProjection"]),
        "terminalOwnerObservation": copy.deepcopy(terminal_owner),
        "logWindow": v2_window,
        "logWindowCapture": copy.deepcopy(v2_fixture.summary),
        "afterMarker": v2_marker_write_record(protocol["after"]),
        "afterMarkerVisibility": v2_marker_visibility_record(
            protocol["after"]
        ),
        "logWindowSafetyMonitor": {
            "maximumPollIntervalSeconds": close_log_monitor[
                "maximumPollIntervalSeconds"
            ],
            "maximumObservedPollGapSeconds": close_log_monitor[
                "maximumObservedPollGapSeconds"
            ],
            "sampleCount": close_log_monitor["sampleCount"],
            "safetyEvents": close_log_monitor["safetyEvents"],
        },
        "guest": None,
    }
    cleanup = {
        "startedAt": "2026-07-29T00:00:00.000000Z",
        "actions": [
            {
                "gateRestore": "RESTORED",
                "safeStop": False,
            }
        ],
        "complete": candidate["cleanupComplete"],
        "containmentRequired": candidate["containmentRequired"],
        "finishedAt": "2026-07-29T00:00:01.000000Z",
    }
    t5 = {
        "operations": phase_records["t5"],
        "evaluationEvidence": {
            "evidenceComplete": candidate["evidenceComplete"],
            "evidenceProtocolChecks": {},
            "runtimeSafetyFaults": copy.deepcopy(
                candidate["safetyFaults"]
            ),
            "containmentRequired": candidate["containmentRequired"],
            "containmentReasons": copy.deepcopy(
                candidate["containmentReasons"]
            ),
            "executionFault": candidate["fault"],
            "cleanupComplete": candidate["cleanupComplete"],
        },
        "gateRestore": raw_gate_window(
            boundary="POST_CLEANUP",
            kind="GATE_LEASE_RESTORE",
            outcome="RESTORED",
            label="fixture-gate-restore",
        ),
        "finalRunningSafetyTail": raw_final_running_window(),
        "activeVmCleanup": None,
        "preCleanupQemuState": "paused",
        "stateBeforeFinalSafetyTail": "paused",
        "finalSafetyTailPausedBaseline": {
            "safetyBoundary": "POST_CLEANUP",
            "captureSnapshotMode": "PINNED_TOPOLOGY_BLOCK_BATCH",
            "runnableSnapshotMode": "PINNED_TOPOLOGY_BLOCK_BATCH",
            "topologySeedMode": "LEASE_ORIGINAL",
            "snapshot": outer(state()),
            "safetyFaults": [],
            "partial": False,
        },
        "finalQemuState": "running",
        "containment": {
            "required": candidate["containmentRequired"],
            "reasons": copy.deepcopy(candidate["containmentReasons"]),
            "observedSafetySideEffect": False,
        },
    }
    candidate["safetyObservations"] = runner.build_numeric_safety_observations(
        t0=t0,
        t1=t1,
        t2=t2,
        t3=t3,
        t4=t4,
        t5=t5,
        cleanup=cleanup,
        baseline_phase=terminal_phase,
        terminal_phase=terminal_phase,
    )
    candidate["safetyCoverage"] = runner.build_safety_coverage(
        t0=t0,
        t1=t1,
        t2=t2,
        t3=t3,
        t4=t4,
        t5=t5,
        cleanup=cleanup,
    )
    evidence_protocol = runner.derive_raw_evidence_protocol(
        sequence=sequence,
        qemu_device=candidate["qemuDevice"],
        outer_endpoint_bdf=OUTER_ENDPOINT_BDF,
        outer_root_bdf=OUTER_ROOT_BDF,
        owner_phase=candidate["ownerPhase"],
        t0=t0,
        t1=t1,
        t2=t2,
        t3=t3,
        t4=t4,
        t5=t5,
        cleanup=cleanup,
        baseline_phase=terminal_phase,
        terminal_phase=terminal_phase,
        safety_coverage=candidate["safetyCoverage"],
        bounded_log_window_complete=v2_window["complete"] is True,
    )
    candidate["evidenceComplete"] = evidence_protocol["complete"]
    t5["evaluationEvidence"]["evidenceComplete"] = evidence_protocol[
        "complete"
    ]
    t5["evaluationEvidence"]["evidenceProtocolChecks"] = (
        evidence_protocol["checks"]
    )
    runner.save_json(case_dir / "t0-baseline.json", t0)
    runner.save_json(case_dir / "t1-effective-controls.json", t1)
    runner.save_json(case_dir / "t2-pre-injection.json", t2)
    runner.save_json(case_dir / "t3-immediate.json", t3)
    runner.save_json(case_dir / "t4-window.json", t4)
    runner.save_json(case_dir / "t5-transition-or-clear.json", t5)
    runner.save_json(case_dir / "cleanup.json", cleanup)
    runner.save_json(
        case_dir / "raw-esxi" / "t0-baseline" / "phase.json",
        terminal_phase,
    )
    runner.save_json(
        case_dir / "raw-esxi" / "t4-terminal" / "phase.json",
        terminal_phase,
    )
    oracle = evaluate_observation(
        candidate,
        runner.load_oracle_profile(profile_path, schema_path),
    )
    runner.save_json(case_dir / "evaluation-input.json", candidate)
    runner.save_json(case_dir / "oracle.json", oracle)
    hmp_transcript = runner.render_hmp_transcript(candidate["injections"])
    if hmp_transcript is None:
        raise AssertionError("fixture injection transcript is malformed")
    runner.save_text(case_dir / "hmp.txt", hmp_transcript)
    result = {
        "schemaVersion": runner.SCHEMA_VERSION,
        "case": case_spec,
        "startedAt": "2026-07-29T00:00:00.000000Z",
        "finishedAt": "2026-07-29T00:00:02.000000Z",
        "observationState": oracle["observationState"],
        "verdict": oracle["verdict"],
        "observationDigest": oracle["observationDigest"],
        "safetyStop": oracle["safetyStop"],
        "enteredInjection": candidate["enteredInjection"],
        "fault": candidate["fault"],
        "cleanupComplete": candidate["cleanupComplete"],
        "containmentRequired": oracle["containmentRequired"],
        "containmentReasons": oracle["containmentReasons"],
        "runtimeContainmentRequired": candidate[
            "containmentRequired"
        ],
        "runtimeContainmentReasons": candidate["containmentReasons"],
        "claimBoundary": runner.case_claim_boundary(),
    }
    runner.save_json(case_dir / "result.json", result)
    runner.write_artifact_manifest(case_dir)
    return oracle, result


def resign_evaluation_artifacts(
    case_dir: Path,
    profile: dict[str, Any],
    candidate: dict[str, Any],
) -> None:
    """Re-sign every derived artifact after an adversarial input mutation."""

    runner.save_json(case_dir / "evaluation-input.json", candidate)
    recomputed = evaluate_observation(candidate, profile)
    if isinstance(candidate.get("fault"), dict):
        recomputed["executionFault"] = copy.deepcopy(candidate["fault"])
    runner.save_json(case_dir / "oracle.json", recomputed)
    result_path = case_dir / "result.json"
    result = runner.load_json(result_path)
    for field_name in (
        "observationState",
        "verdict",
        "observationDigest",
        "safetyStop",
    ):
        result[field_name] = recomputed.get(field_name)
    result["enteredInjection"] = candidate["enteredInjection"]
    result["fault"] = candidate["fault"]
    result["cleanupComplete"] = candidate["cleanupComplete"]
    result["containmentRequired"] = candidate["containmentRequired"]
    result["containmentReasons"] = copy.deepcopy(
        candidate["containmentReasons"]
    )
    runner.save_json(result_path, result)
    runner.write_artifact_manifest(case_dir)


def synchronize_evaluation_from_raw(
    case_dir: Path,
    profile: dict[str, Any],
) -> dict[str, Any]:
    """Rebuild every evaluator fact an attacker can legitimately recompute."""

    raw = runner.reconstruct_evaluation_sources(case_dir, profile)
    candidate = runner.load_json(case_dir / "evaluation-input.json")
    mappings = {
        "snapshots": "snapshots",
        "injections": "injections",
        "ownerObservations": "ownerObservations",
        "hostProjection": "hostProjection",
        "hostLogClassification": "hostLogClassification",
        "o4GuestEvidenceValid": "o4GuestEvidenceValid",
        "preflight": "preflight",
        "gateStable": "gateStable",
        "enteredInjection": "enteredInjection",
        "evidenceComplete": "evidenceComplete",
        "safetyObservations": "safetyObservations",
        "safetyCoverage": "safetyCoverage",
        "safetyFaults": "safetyFaults",
        "containmentRequired": "containmentRequired",
        "containmentReasons": "containmentReasons",
        "containmentEvidence": "containmentEvidence",
        "fault": "fault",
        "cleanupComplete": "cleanupComplete",
    }
    for destination, source in mappings.items():
        candidate[destination] = copy.deepcopy(raw[source])
    candidate["requesterId"] = raw["sourceRequesterId"]
    candidate["guestClassification"] = (
        "NOT_APPLICABLE_O0"
        if candidate["ownerPhase"] == "O0"
        else (
            "O4_BOUND_DRIVER_AND_HEARTBEAT"
            if candidate["o4GuestEvidenceValid"]
            else "O4_GUEST_EVIDENCE_INCOMPLETE"
        )
    )
    resign_evaluation_artifacts(case_dir, profile, candidate)
    return candidate


class EsxiRootSequenceOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.profile = runner.load_oracle_profile(
            runner.DEFAULT_ORACLE_PROFILE
        )

    def test_hmp_command_is_prompt_driven_without_fixed_sleep(self) -> None:
        fake_socket = mock.MagicMock()
        fake_socket.__enter__.return_value = fake_socket
        fake_socket.recv.side_effect = [
            b"QEMU monitor\r\n(qemu) ",
            b"cont\r\n(qemu) ",
            b"info status\r\nVM status: running\r\n(qemu) ",
        ]
        with (
            mock.patch.object(
                capability.socket,
                "AF_UNIX",
                1,
                create=True,
            ),
            mock.patch.object(
                capability.socket,
                "socket",
                return_value=fake_socket,
            ),
            mock.patch.object(capability.time, "sleep") as sleep,
        ):
            output = capability.hmp_command(
                Path("monitor.sock"),
                "cont",
                "info status",
            )
        sleep.assert_not_called()
        fake_socket.settimeout.assert_called_once_with(2)
        fake_socket.connect.assert_called_once_with("monitor.sock")
        self.assertEqual(
            [mock.call(b"cont\n"), mock.call(b"info status\n")],
            fake_socket.sendall.call_args_list,
        )
        self.assertIn("VM status: running", output)

    def test_hmp_command_rejects_multiline_input(self) -> None:
        fake_socket = mock.MagicMock()
        fake_socket.__enter__.return_value = fake_socket
        fake_socket.recv.return_value = b"QEMU monitor\r\n(qemu) "
        with (
            mock.patch.object(
                capability.socket,
                "AF_UNIX",
                1,
                create=True,
            ),
            mock.patch.object(
                capability.socket,
                "socket",
                return_value=fake_socket,
            ),
        ):
            with self.assertRaises(ValueError):
                capability.hmp_command(
                    Path("monitor.sock"),
                    "info status\nquit",
                )
        fake_socket.sendall.assert_not_called()

    def test_pinned_topology_snapshot_uses_only_dynamic_register_reads(
        self,
    ) -> None:
        topology = pinned_topology()
        original = copy.deepcopy(topology)

        class FakeQTestClient:
            def __init__(self) -> None:
                self.sent_commands: list[str] = []
                self.batches: list[list[str]] = []
                self.closed = False

            def command(self, command: str) -> str:
                raise AssertionError(
                    f"block-batch path issued a scalar command: {command}"
                )

            def commands(self, commands: list[str]) -> list[str]:
                batch = list(commands)
                self.batches.append(batch)
                self.sent_commands.extend(batch)
                responses = []
                for command in batch:
                    size = int(command.rsplit(" ", 1)[1], 0)
                    responses.append("OK 0x" + ("00" * size))
                return responses

            def close(self) -> None:
                self.closed = True

        client = FakeQTestClient()
        with (
            mock.patch.object(Path, "is_socket", return_value=True),
            mock.patch.object(
                runner.esxi_aer.qemu_aer,
                "QTestClient",
                return_value=client,
            ),
            mock.patch.object(
                runner.esxi_aer.qemu_aer,
                "legacy_config_read32",
                side_effect=AssertionError("hot path rediscovered PCIEXBAR"),
            ),
            mock.patch.object(
                runner.esxi_aer.qemu_aer,
                "discover_device",
                side_effect=AssertionError("hot path rediscovered topology"),
            ),
        ):
            snapshot = runner.esxi_aer.outer_qemu_aer_snapshot(
                Path("qtest.sock"),
                "0000:01:00.1",
                "0000:00:01.0",
                topology=topology,
            )

        expected_commands = [
            f"read 0x{aer.ecam_address(1, 0, 1, 0x48):x} 0xd0",
            f"read 0x{aer.ecam_address(0, 1, 0, 0x3e):x} 0xfa",
        ]
        self.assertEqual(expected_commands, client.sent_commands)
        self.assertEqual([expected_commands], client.batches)
        self.assertEqual(2, len(client.sent_commands))
        self.assertEqual(
            len(client.sent_commands),
            len(set(client.sent_commands)),
        )
        self.assertTrue(client.closed)
        self.assertEqual(original, topology)
        self.assertEqual(original["endpoint"], snapshot["endpoint"])
        self.assertEqual(original["root"], snapshot["root"])
        self.assertEqual(
            original["endpointState"]["uncorrectableErrorMask"],
            snapshot["endpointState"]["uncorrectableErrorMask"],
        )
        self.assertEqual(
            original["rootState"]["correctableErrorMask"],
            snapshot["rootState"]["correctableErrorMask"],
        )

    def test_pinned_topology_snapshot_fails_before_qtest_on_bad_binding(
        self,
    ) -> None:
        malformed_topologies: list[dict[str, Any]] = []
        wrong_bdf = pinned_topology()
        wrong_bdf["endpoint"]["function"] = 0
        malformed_topologies.append(wrong_bdf)
        bad_pcie_offset = pinned_topology()
        bad_pcie_offset["root"]["pcieCapabilityOffset"] = 0
        malformed_topologies.append(bad_pcie_offset)
        bad_aer_header = pinned_topology()
        bad_aer_header["endpoint"]["aerHeader"] = 0x00020010
        malformed_topologies.append(bad_aer_header)
        missing_static_field = pinned_topology()
        del missing_static_field["endpointState"][
            "uncorrectableErrorMask"
        ]
        malformed_topologies.append(missing_static_field)

        for topology in malformed_topologies:
            with self.subTest(topology=topology):
                with (
                    mock.patch.object(Path, "is_socket", return_value=True),
                    mock.patch.object(
                        runner.esxi_aer.qemu_aer,
                        "QTestClient",
                    ) as qtest_client,
                ):
                    with self.assertRaises(
                        runner.esxi_aer.BlockedEnvironment
                    ):
                        runner.esxi_aer.outer_qemu_aer_snapshot(
                            Path("qtest.sock"),
                            "0000:01:00.1",
                            "0000:00:01.0",
                            topology=topology,
                        )
                qtest_client.assert_not_called()

    def test_qtest_batch_preserves_coalesced_response_lines(self) -> None:
        client = aer.QTestClient.__new__(aer.QTestClient)
        client.connection = mock.MagicMock()
        client._receive_buffer = b""
        client.connection.recv.return_value = (
            b"OK 0x0000\nOK 0x1111\n"
        )
        responses = client.commands(
            (
                "read 0x1000 0x2",
                "read 0x2000 0x2",
            )
        )
        self.assertEqual(
            ["OK 0x0000", "OK 0x1111"],
            responses,
        )
        client.connection.sendall.assert_called_once_with(
            b"read 0x1000 0x2\nread 0x2000 0x2\n"
        )
        client.connection.recv.assert_called_once_with(65536)
        self.assertEqual(b"", client._receive_buffer)

    def test_qtest_block_batch_rejects_wrong_byte_count(self) -> None:
        client = mock.Mock()
        client.commands.return_value = ["OK 0x00"]
        with self.assertRaisesRegex(
            RuntimeError,
            "wrong byte count",
        ):
            aer.qtest_read_blocks(client, ((0x1000, 2),))

    def test_isolated_active_user_probe_returns_payload_and_closes(
        self,
    ) -> None:
        api = SimpleNamespace(
            host_address="172.31.91.10",
            user="root",
            password="fixture",
        )
        probe = mock.Mock()
        probe.closed = False
        probe.result.return_value = {
            "ok": True,
            "users": [],
            "capturedAt": "fixture-time",
        }
        with mock.patch.object(
            runner.esxi_aer,
            "start_active_user_probe",
            return_value=probe,
        ) as start_probe:
            payload = runner.esxi_aer.isolated_active_passthrough_users(
                api,
                "0000:01:00.1",
            )
        self.assertEqual([], payload["users"])
        start_probe.assert_called_once_with(
            "172.31.91.10",
            "root",
            "fixture",
            "0000:01:00.1",
        )
        probe.result.assert_called_once_with(
            runner.esxi_aer.OWNER_PROBE_HARD_TIMEOUT_SECONDS
        )
        probe.cancel.assert_called_once_with()

    def test_runnable_gc_guard_collects_only_outside_runnable_window(
        self,
    ) -> None:
        events: list[str] = []
        enabled = True

        def collect() -> int:
            events.append("collect")
            return len(events)

        def disable() -> None:
            nonlocal enabled
            events.append("disable")
            enabled = False

        def enable() -> None:
            nonlocal enabled
            events.append("enable")
            enabled = True

        with (
            mock.patch.object(
                runner.gc,
                "isenabled",
                side_effect=lambda: enabled,
            ),
            mock.patch.object(
                runner.gc,
                "collect",
                side_effect=collect,
            ),
            mock.patch.object(
                runner.gc,
                "disable",
                side_effect=disable,
            ),
            mock.patch.object(
                runner.gc,
                "enable",
                side_effect=enable,
            ),
            mock.patch.object(
                runner.gc,
                "get_threshold",
                return_value=(700, 10, 10),
            ),
            mock.patch.object(
                runner.gc,
                "get_count",
                return_value=(1, 2, 3),
            ),
        ):
            guard = runner.arm_runnable_gc_guard()
            self.assertEqual(["collect", "disable"], events)
            self.assertEqual("ARMED", guard["releaseState"])
            self.assertIsNone(
                runner.release_runnable_gc_guard(
                    guard,
                    paused_confirmed=True,
                )
            )
        self.assertEqual(
            ["collect", "disable", "enable", "collect"],
            events,
        )
        self.assertEqual(
            "REENABLED_AFTER_PAUSE",
            guard["releaseState"],
        )

    def test_runnable_gc_guard_stays_disabled_without_paused_ack(
        self,
    ) -> None:
        guard = {
            "wasEnabled": True,
            "releaseState": "ARMED",
            "postPauseCollected": None,
            "releasedAt": None,
            "fault": None,
        }
        with (
            mock.patch.object(runner.gc, "enable") as enable,
            mock.patch.object(runner.gc, "collect") as collect,
        ):
            self.assertIsNone(
                runner.release_runnable_gc_guard(
                    guard,
                    paused_confirmed=False,
                )
            )
        enable.assert_not_called()
        collect.assert_not_called()
        self.assertEqual(
            "DEFERRED_STOP_UNCONFIRMED",
            guard["releaseState"],
        )

    def test_all_sequences_match_public_model_candidate(self) -> None:
        for sequence in runner.SEQUENCES:
            with self.subTest(sequence=sequence):
                result = evaluate_observation(
                    evaluation_input(sequence),
                    self.profile,
                )
                self.assertEqual(runner.OBSERVATION_MATCH,
                                 result["observationState"])
                self.assertEqual("MATCH", result["verdict"])
                self.assertFalse(
                    result["esxiBlackboxOracle"]["failedChecks"]
                )

    def test_stale_source_is_ignored_only_when_root_status_is_clear(self) -> None:
        candidate = evaluation_input("first-multiple")
        candidate["snapshots"]["pre-injection"]["rootPort"][
            "errorSourceIdentification"
        ] = REQUESTER_ID
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(runner.OBSERVATION_MATCH,
                         result["observationState"])
        self.assertFalse(
            result["sourceQualification"]["pre-injection"]["meaningful"]
        )

        candidate = evaluation_input("first-multiple")
        candidate["snapshots"]["first-window-observation"]["rootPort"][
            "errorSourceIdentification"
        ] = 0x9999
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(runner.OBSERVATION_DIVERGED,
                         result["observationState"])

    def test_missing_snapshot_is_inconclusive(self) -> None:
        candidate = evaluation_input("bit-or")
        del candidate["snapshots"]["stable-after-or"]
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(runner.OBSERVATION_INCONCLUSIVE,
                         result["observationState"])

    def test_malformed_snapshot_is_inconclusive_without_crashing(self) -> None:
        candidate = evaluation_input("rearm")
        del candidate["snapshots"]["pre-injection"]["rootPort"][
            "bridgeControl"
        ]
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_INCONCLUSIVE,
            result["observationState"],
        )
        self.assertIn(
            "pre-injection:rootPort.bridgeControl is not an integer",
            result["evidenceShapeFaults"],
        )

    def test_partial_host_projection_is_inconclusive_without_crashing(
        self,
    ) -> None:
        candidate = evaluation_input("bit-or")
        del candidate["hostProjection"]["hostRoot"]["rootErrorCommand"]
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_INCONCLUSIVE,
            result["observationState"],
        )
        self.assertFalse(
            result["esxiBlackboxOracle"]["hostProjection"]["complete"]
        )

    def test_paused_immediate_fixture_mismatch_is_inconclusive(self) -> None:
        candidate = evaluation_input("first-multiple")
        candidate["snapshots"]["first-b0"]["endpoint"][
            "correctableErrorStatus"
        ] = runner.B1
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_INCONCLUSIVE,
            result["observationState"],
        )
        self.assertEqual(
            qseq.OBSERVATION_DIVERGED,
            result["fixtureOracle"]["observationState"],
        )
        self.assertIn(
            "first-b0:paused-immediate-exact",
            result["fixtureOracle"]["failedChecks"],
        )

    def test_preflight_failure_before_injection_is_blocked(self) -> None:
        candidate = evaluation_input("rearm")
        candidate["enteredInjection"] = False
        candidate["injections"] = []
        candidate["preflight"]["ownerBound"] = False
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(runner.OBSERVATION_BLOCKED,
                         result["observationState"])

    def test_valid_multiple_mismatch_is_diverged(self) -> None:
        candidate = evaluation_input("first-multiple")
        candidate["snapshots"]["stable-after-repeat"]["rootPort"][
            "rootErrorStatus"
        ] = qseq.ROOT_COR_FIRST
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(runner.OBSERVATION_DIVERGED,
                         result["observationState"])
        self.assertEqual(
            qseq.OBSERVATION_MATCH,
            result["fixtureOracle"]["observationState"],
        )
        self.assertIn(
            "stable-after-repeat:matches-profile-allowed-state",
            result["esxiBlackboxOracle"]["failedChecks"],
        )

    def test_meaningless_source_only_changes_raw_digest(self) -> None:
        clean = evaluation_input("first-multiple")
        stale_source = copy.deepcopy(clean)
        stale_source["snapshots"]["pre-injection"]["rootPort"][
            "errorSourceIdentification"
        ] = 0xBEEF
        clean_result = evaluate_observation(clean, self.profile)
        stale_result = evaluate_observation(
            stale_source,
            self.profile,
        )
        self.assertEqual(
            clean_result["observationDigest"],
            stale_result["observationDigest"],
        )
        self.assertNotEqual(
            clean_result["rawObservationDigest"],
            stale_result["rawObservationDigest"],
        )
        self.assertFalse(
            stale_result["sourceQualification"]["pre-injection"][
                "meaningful"
            ]
        )

    def test_observe_only_log_classification_is_not_comparison_input(
        self,
    ) -> None:
        absent = evaluation_input("bit-or")
        observed = copy.deepcopy(absent)
        observed["hostLogClassification"] = "CORRECTABLE_AER_OBSERVED"
        absent_result = evaluate_observation(absent, self.profile)
        observed_result = evaluate_observation(
            observed,
            self.profile,
        )
        self.assertEqual(
            absent_result["observationDigest"],
            observed_result["observationDigest"],
        )
        self.assertNotEqual(
            absent_result["rawObservationDigest"],
            observed_result["rawObservationDigest"],
        )

    def test_baseline_safety_fault_blocks_and_latches_safety_stop(
        self,
    ) -> None:
        candidate = evaluation_input("rearm")
        candidate["enteredInjection"] = False
        candidate["injections"] = []
        candidate["preflight"]["cleanBaseline"] = False
        candidate["snapshots"]["pre-injection"]["endpoint"][
            "uncorrectableErrorStatus"
        ] = 1
        candidate["safetyFaults"] = [
            {"label": "baseline", "faults": ["endpoint UES=1"]}
        ]
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_BLOCKED,
            result["observationState"],
        )
        self.assertEqual("BLOCKED_UNSAFE_BASELINE", result["verdict"])
        self.assertTrue(result["safetyStop"])

    def test_containment_without_safety_is_inconclusive_not_safety_stop(
        self,
    ) -> None:
        candidate = evaluation_input("bit-or")
        candidate["containmentRequired"] = True
        candidate["containmentReasons"] = ["cleanup state is unknown"]
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_INCONCLUSIVE,
            result["observationState"],
        )
        self.assertEqual(
            "INCONCLUSIVE_CONTAINMENT_REQUIRED",
            result["verdict"],
        )
        self.assertFalse(result["safetyStop"])

    def test_uncorrectable_side_effect_latches_safety_stop(self) -> None:
        candidate = evaluation_input("rearm")
        candidate["snapshots"]["rearmed-b0"]["endpoint"][
            "uncorrectableErrorStatus"
        ] = 1
        candidate["safetyFaults"] = [
            {"label": "rearmed-b0", "faults": ["endpoint UES=1"]}
        ]
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(runner.OBSERVATION_DIVERGED,
                         result["observationState"])
        self.assertEqual("FAIL_SAFETY", result["verdict"])
        self.assertTrue(result["safetyStop"])

    def test_snapshot_uncorrectable_is_derived_without_supplied_fault(
        self,
    ) -> None:
        candidate = evaluation_input("bit-or")
        candidate["snapshots"]["second-b1"]["endpoint"][
            "uncorrectableErrorStatus"
        ] = 1
        candidate["safetyFaults"] = []
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_DIVERGED,
            result["observationState"],
        )
        self.assertEqual("FAIL_SAFETY", result["verdict"])
        self.assertTrue(result["safetyStop"])
        self.assertTrue(
            any(
                item.get("label") == "snapshot:second-b1"
                for item in result["safetyFaults"]
            )
        )

    def test_supplied_free_text_safety_fault_is_not_authoritative(
        self,
    ) -> None:
        candidate = evaluation_input("bit-or")
        candidate["safetyFaults"] = [
            {"label": "fabricated", "faults": ["endpoint UES=1"]}
        ]
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_INCONCLUSIVE,
            result["observationState"],
        )
        self.assertFalse(result["safetyStop"])
        self.assertTrue(result["containmentRequired"])

    def test_post_cleanup_numeric_safety_is_containment_not_divergence(
        self,
    ) -> None:
        candidate = evaluation_input("bit-or")
        candidate["snapshots"]["post-cleanup"]["endpoint"][
            "uncorrectableErrorStatus"
        ] = 1
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_INCONCLUSIVE,
            result["observationState"],
        )
        self.assertEqual(
            "INCONCLUSIVE_CONTAINMENT_REQUIRED",
            result["verdict"],
        )
        self.assertTrue(result["safetyStop"])

    def test_partial_numeric_observation_retains_known_unsafe_field(
        self,
    ) -> None:
        candidate = evaluation_input("bit-or")
        observation = copy.deepcopy(candidate["safetyObservations"][0])
        observation.update(
            {
                "boundary": "ATTRIBUTION_WINDOW",
                "endpointUncorrectableErrorStatus": 1,
            }
        )
        observation["provenance"].update(
            {
                "artifact": "t4-window.json",
                "jsonPath": "/windows/0/samples/0/snapshot",
                "label": "partial-attribution-sample",
            }
        )
        del observation["rootDeviceStatus"]
        candidate["safetyObservations"] = [observation]
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_DIVERGED,
            result["observationState"],
        )
        self.assertEqual("FAIL_SAFETY", result["verdict"])
        self.assertTrue(result["safetyStop"])
        self.assertIn(
            (
                "safetyObservations[0].rootDeviceStatus is not a "
                "non-negative integer"
            ),
            result["evidenceShapeFaults"],
        )

    def test_boundary_provenance_splice_is_invalid_not_divergence(
        self,
    ) -> None:
        candidate = evaluation_input("bit-or")
        observation = copy.deepcopy(candidate["safetyObservations"][0])
        observation.update(
            {
                "boundary": "POST_CLEANUP",
                "endpointUncorrectableErrorStatus": 1,
            }
        )
        observation["provenance"].update(
            {
                "artifact": "t4-window.json",
                "jsonPath": "/windows/0/samples/0/snapshot",
                "label": "spoofed-post-boundary",
            }
        )
        candidate["safetyObservations"] = [observation]
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_INCONCLUSIVE,
            result["observationState"],
        )
        self.assertNotEqual("FAIL_SAFETY", result["verdict"])
        self.assertFalse(result["safetyStop"])
        self.assertTrue(result["containmentRequired"])

    def test_post_cleanup_label_spoof_remains_attribution_safety(
        self,
    ) -> None:
        candidate = evaluation_input("bit-or")
        candidate["snapshots"]["post-cleanup-spoof"] = state(ues=1)
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_DIVERGED,
            result["observationState"],
        )
        self.assertEqual("FAIL_SAFETY", result["verdict"])
        self.assertTrue(result["safetyStop"])

    def test_pre_injection_unsafe_after_entry_requires_containment(
        self,
    ) -> None:
        candidate = evaluation_input("bit-or")
        candidate["safetyObservations"][0][
            "endpointUncorrectableErrorStatus"
        ] = 1
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_INCONCLUSIVE,
            result["observationState"],
        )
        self.assertEqual(
            "INCONCLUSIVE_CONTAINMENT_REQUIRED",
            result["verdict"],
        )
        self.assertTrue(result["safetyStop"])

    def test_pre_injection_unsafe_blocks_even_with_green_preflight(
        self,
    ) -> None:
        candidate = evaluation_input("bit-or")
        candidate["enteredInjection"] = False
        candidate["injections"] = []
        candidate["safetyObservations"][0][
            "endpointUncorrectableErrorStatus"
        ] = 1
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_BLOCKED,
            result["observationState"],
        )
        self.assertEqual("BLOCKED_UNSAFE_BASELINE", result["verdict"])
        self.assertTrue(result["safetyStop"])

    def test_zero_numeric_safety_observations_cannot_match(self) -> None:
        for observations in (None, []):
            with self.subTest(observations=observations):
                candidate = evaluation_input("bit-or")
                if observations is None:
                    del candidate["safetyObservations"]
                else:
                    candidate["safetyObservations"] = observations
                result = evaluate_observation(
                    candidate,
                    self.profile,
                )
                self.assertEqual(
                    runner.OBSERVATION_INCONCLUSIVE,
                    result["observationState"],
                )

    def test_incomplete_safety_coverage_cannot_match(self) -> None:
        candidate = evaluation_input("bit-or")
        attribution = next(
            item
            for item in candidate["safetyCoverage"]
            if item["boundary"] == "ATTRIBUTION_WINDOW"
        )
        attribution["complete"] = False
        attribution["faults"] = ["finalStopFault is non-null"]
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_INCONCLUSIVE,
            result["observationState"],
        )
        self.assertEqual(
            "INCONCLUSIVE_CONTAINMENT_REQUIRED",
            result["verdict"],
        )

    def test_pre_injection_coverage_gap_blocks_before_entry(self) -> None:
        candidate = evaluation_input("bit-or")
        candidate["enteredInjection"] = False
        candidate["injections"] = []
        pre = next(
            item
            for item in candidate["safetyCoverage"]
            if item["boundary"] == "PRE_INJECTION"
        )
        pre["complete"] = False
        pre["faults"] = ["monitorFault is non-null"]
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_BLOCKED,
            result["observationState"],
        )
        self.assertEqual("BLOCKED_SAFETY_COVERAGE", result["verdict"])

    def test_coverage_gap_above_declared_maximum_cannot_match(self) -> None:
        candidate = evaluation_input("bit-or")
        attribution = next(
            item
            for item in candidate["safetyCoverage"]
            if item["boundary"] == "ATTRIBUTION_WINDOW"
        )
        attribution["maximumObservedGapSeconds"] = 9.0
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_INCONCLUSIVE,
            result["observationState"],
        )
        self.assertTrue(
            any(
                "maximumObservedGapSeconds exceeds maximum" in fault
                for fault in result["evidenceShapeFaults"]
            )
        )

    def test_coverage_missing_timing_summary_cannot_match(self) -> None:
        candidate = evaluation_input("bit-or")
        for item in candidate["safetyCoverage"]:
            item.pop("maximumIntervalSeconds", None)
            item.pop("maximumObservedGapSeconds", None)
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_INCONCLUSIVE,
            result["observationState"],
        )
        self.assertTrue(result["evidenceShapeFaults"])

    def test_coverage_timing_is_bound_to_frozen_profile(self) -> None:
        for invalid_maximum in (999.0, float("inf")):
            with self.subTest(invalid_maximum=invalid_maximum):
                candidate = evaluation_input("bit-or")
                for item in candidate["safetyCoverage"]:
                    item["maximumIntervalSeconds"] = invalid_maximum
                result = evaluate_observation(
                    candidate,
                    self.profile,
                )
                self.assertEqual(
                    runner.OBSERVATION_INCONCLUSIVE,
                    result["observationState"],
                )
                self.assertTrue(
                    any(
                        "frozen profile" in fault
                        or "maximumIntervalSeconds is invalid" in fault
                        for fault in result["evidenceShapeFaults"]
                    )
                )

        candidate = evaluation_input("bit-or")
        scheduled = copy.deepcopy(candidate["safetyCoverage"][0])
        scheduled["kind"] = "SERVICE_WINDOW"
        scheduled["targetDelaysSeconds"] = [0.0, 1.0]
        faults = runner.safety_coverage_profile_faults(
            {"safetyCoverage": [scheduled]},
            self.profile,
        )
        self.assertTrue(
            any("targetDelaysSeconds" in fault for fault in faults)
        )

    def test_coverage_requires_closed_numeric_surface_per_sample(
        self,
    ) -> None:
        window = raw_coverage_window(
            "ATTRIBUTION_WINDOW",
            "missing-raw-snapshot",
        )
        del window["samples"][0]["snapshot"]
        coverage = runner.build_safety_coverage(
            t0={},
            t1={},
            t2={},
            t3={},
            t4={"windows": [window]},
            t5={},
            cleanup={},
        )
        self.assertEqual(1, len(coverage))
        self.assertFalse(coverage[0]["complete"])
        self.assertTrue(
            any(
                "numeric safety snapshot is missing" in fault
                for fault in coverage[0]["faults"]
            )
        )

    def test_monitored_worker_elapsed_chronology_is_recomputed(
        self,
    ) -> None:
        window = raw_coverage_window(
            "ATTRIBUTION_WINDOW",
            "forged-monitored-chronology",
        )
        window["samples"][0]["actualElapsedSeconds"] = 1.0
        window["lastSampleFinishedElapsedSeconds"] = 1.0
        window["finalStopConfirmedElapsedSeconds"] = 1.01
        coverage = runner.build_safety_coverage(
            t0={},
            t1={},
            t2={},
            t3={},
            t4={"windows": [window]},
            t5={},
            cleanup={},
        )
        self.assertEqual(1, len(coverage))
        self.assertFalse(coverage[0]["complete"])
        self.assertTrue(
            any(
                "elapsed chronology disagrees" in fault
                for fault in coverage[0]["faults"]
            )
        )

    def test_gate_coverage_requires_recomputed_stop_tail(self) -> None:
        sample = copy.deepcopy(
            raw_coverage_window(
                "PRE_INJECTION",
                "gate-tail",
            )["samples"][0]
        )
        sample["actualElapsedSeconds"] = 1.0
        gate_lease = {
            "label": "gate-tail",
            "safetyBoundary": "PRE_INJECTION",
            "safetyWindowKind": "GATE_LEASE_APPLY",
            "outcome": "EFFECTIVE",
            "qemuHeldPaused": True,
            "timeline": {
                "resume": {"state": "running"},
                "resumedSafetyPoll": {
                    "targetDelaysSeconds": [0.0, 0.05, 0.25, 1.0],
                    "maximumPollIntervalSeconds": 0.05,
                    "sampleCount": 1,
                    "maximumObservedPollGapSeconds": 0.01,
                    "completedTargetCount": 4,
                    "complete": True,
                    "pollFaults": [],
                    "samples": [sample],
                    "closure": {
                        "mode": "PAUSED_ACK",
                        "stopConfirmed": True,
                    },
                },
            },
        }
        coverage = runner.build_safety_coverage(
            t0={},
            t1={"gateLease": gate_lease},
            t2={},
            t3={},
            t4={},
            t5={},
            cleanup={},
        )
        self.assertEqual(1, len(coverage))
        self.assertFalse(coverage[0]["complete"])
        self.assertIn(
            "gate runnable-window tail is incomplete",
            coverage[0]["faults"],
        )

    def test_empty_gate_timeline_is_incomplete_not_ignored(self) -> None:
        coverage = runner.build_safety_coverage(
            t0={},
            t1={
                "gateLease": {
                    "label": "empty-gate",
                    "safetyBoundary": "PRE_INJECTION",
                    "safetyWindowKind": "GATE_LEASE_APPLY",
                    "outcome": "EFFECTIVE",
                    "timeline": {},
                }
            },
            t2={},
            t3={},
            t4={},
            t5={},
            cleanup={},
        )
        self.assertEqual(1, len(coverage))
        self.assertFalse(coverage[0]["complete"])
        self.assertIn(
            "continuous safety poll is missing",
            coverage[0]["faults"],
        )

    def test_missing_window_kind_on_raw_route_is_not_ignored(self) -> None:
        window = raw_coverage_window(
            "ATTRIBUTION_WINDOW",
            "stable-after-or",
        )
        del window["safetyWindowKind"]
        coverage = runner.build_safety_coverage(
            t0={},
            t1={},
            t2={},
            t3={},
            t4={"windows": [window]},
            t5={},
            cleanup={},
        )
        self.assertEqual(1, len(coverage))
        self.assertFalse(coverage[0]["complete"])
        self.assertIn(
            "safetyWindowKind is missing from a runnable route",
            coverage[0]["faults"],
        )

    def test_only_exact_paused_snapshot_kind_skips_t4_window_coverage(
        self,
    ) -> None:
        record = raw_public_snapshot_record(
            "stable-after-or",
            state(
                ces=runner.B0 | runner.B1,
                ced=True,
                root_status=qseq.ROOT_COR_MULTIPLE,
                source=REQUESTER_ID,
            ),
            phase="t4",
            boundary="ATTRIBUTION_WINDOW",
        )
        coverage = runner.build_safety_coverage(
            t0={},
            t1={},
            t2={},
            t3={},
            t4={"windows": [record]},
            t5={},
            cleanup={},
        )
        self.assertEqual([], coverage)

        variants = {
            "deleted-kind": lambda item: item.pop("recordKind"),
            "partial": lambda item: item.__setitem__("partial", True),
            "forged-field": lambda item: item.__setitem__(
                "coverageComplete",
                True,
            ),
        }
        for name, mutate in variants.items():
            with self.subTest(name=name):
                malformed = copy.deepcopy(record)
                mutate(malformed)
                coverage = runner.build_safety_coverage(
                    t0={},
                    t1={},
                    t2={},
                    t3={},
                    t4={"windows": [malformed]},
                    t5={},
                    cleanup={},
                )
                self.assertEqual(1, len(coverage))
                self.assertFalse(coverage[0]["complete"])
                self.assertTrue(coverage[0]["faults"])

        forged_window = raw_service_window("stable-after-or")
        forged_window["recordKind"] = (
            runner.PAUSED_NUMERIC_SNAPSHOT_RECORD_KIND
        )
        coverage = runner.build_safety_coverage(
            t0={},
            t1={},
            t2={},
            t3={},
            t4={"windows": [forged_window]},
            t5={},
            cleanup={},
        )
        self.assertEqual(1, len(coverage))
        self.assertFalse(coverage[0]["complete"])
        self.assertTrue(
            any(
                "paused numeric snapshot record" in fault
                for fault in coverage[0]["faults"]
            )
        )

    def test_evidence_protocol_requires_every_sequence_service_label(
        self,
    ) -> None:
        sequence = "first-multiple"
        t0 = {
            "hostPhase": {},
            "preSequenceSafetyWindows": [
                raw_coverage_window("PRE_INJECTION", "fixture-pre")
            ],
        }
        t1 = {
            "gateLease": raw_gate_window(
                boundary="PRE_INJECTION",
                kind="GATE_LEASE_APPLY",
                outcome="EFFECTIVE",
                label="fixture-gate-apply",
            )
        }
        t4 = {
            "windows": [
                raw_service_window(
                    runner.BEHAVIOR_LABELS[sequence][0]
                )
            ],
            "hostTerminalPhase": {},
        }
        t5 = {
            "operations": [{"label": "fixture-cleanup"}],
            "gateRestore": raw_gate_window(
                boundary="POST_CLEANUP",
                kind="GATE_LEASE_RESTORE",
                outcome="RESTORED",
                label="fixture-gate-restore",
            ),
            "activeVmCleanupSafetyWindows": [
                raw_coverage_window("POST_CLEANUP", "fixture-post")
            ],
        }
        coverage = runner.build_safety_coverage(
            t0=t0,
            t1=t1,
            t2={"steps": [{"label": "fixture-step"}]},
            t3={
                "injections": [
                    {
                        "attempted": True,
                        "mutationBoundaryCrossed": True,
                    }
                ],
                "snapshots": [{"label": "fixture-snapshot"}],
            },
            t4=t4,
            t5=t5,
            cleanup={"complete": True},
        )
        protocol = runner.derive_raw_evidence_protocol(
            sequence=sequence,
            qemu_device="test_fn1",
            outer_endpoint_bdf=OUTER_ENDPOINT_BDF,
            outer_root_bdf=OUTER_ROOT_BDF,
            owner_phase="O0",
            t0=t0,
            t1=t1,
            t2={"steps": [{"label": "fixture-step"}]},
            t3={
                "injections": [
                    {
                        "attempted": True,
                        "mutationBoundaryCrossed": True,
                    }
                ],
                "snapshots": [{"label": "fixture-snapshot"}],
            },
            t4=t4,
            t5=t5,
            cleanup={"complete": True},
            baseline_phase={},
            terminal_phase={},
            safety_coverage=coverage,
            bounded_log_window_complete=True,
        )
        self.assertTrue(
            protocol["checks"]["coverage-gate-lease-apply-complete"]
        )
        self.assertTrue(
            protocol["checks"]["coverage-gate-lease-restore-complete"]
        )
        self.assertFalse(
            protocol["checks"]["coverage-service-labels-complete"]
        )

    def test_service_target_completion_is_bound_to_numeric_samples(
        self,
    ) -> None:
        sample = copy.deepcopy(
            raw_coverage_window(
                "ATTRIBUTION_WINDOW",
                "service-targets",
            )["samples"][0]
        )
        sample.update(
            {
                "sampleIndex": 0,
                "actualElapsedSeconds": 1.0,
                "capturedAt": "fixture",
            }
        )
        targets = [0.0, 0.05, 0.25, 1.0]
        timeline = [
            {
                "delaySeconds": target,
                "targetDelaySeconds": target,
                "actualElapsedSeconds": 1.0,
                "sampleIndex": 0,
                "capturedAt": "fixture",
                "safetyFaults": [],
                "snapshot": copy.deepcopy(sample["snapshot"]),
            }
            for target in targets
        ]
        service = {
            "label": "service-targets",
            "safetyBoundary": "ATTRIBUTION_WINDOW",
            "safetyWindowKind": "SERVICE_WINDOW",
            "timeline": timeline,
            "safetyPoll": {
                "targetDelaysSeconds": targets,
                "targetCount": 0,
                "completedTargetCount": 0,
                "maximumIntervalSeconds": 0.05,
                "sampleCount": 1,
                "maximumObservedGapSeconds": 0.01,
                "tailGapSeconds": 0.01,
                "samples": [sample],
            },
            "timelineFault": None,
            "pause": {"state": "paused"},
            "pauseFault": None,
            "pauseTailFault": None,
            "coverageComplete": True,
        }
        coverage = runner.build_safety_coverage(
            t0={},
            t1={},
            t2={},
            t3={},
            t4={"windows": [service]},
            t5={},
            cleanup={},
        )
        self.assertEqual(1, len(coverage))
        self.assertFalse(coverage[0]["complete"])
        self.assertIn(
            "target-delay coverage is incomplete",
            coverage[0]["faults"],
        )
        service["safetyPoll"]["targetCount"] = len(targets)
        service["safetyPoll"]["completedTargetCount"] = len(targets)
        coverage = runner.build_safety_coverage(
            t0={},
            t1={},
            t2={},
            t3={},
            t4={"windows": [service]},
            t5={},
            cleanup={},
        )
        self.assertFalse(coverage[0]["complete"])
        self.assertTrue(
            any(
                "elapsed chronology disagrees" in fault
                for fault in coverage[0]["faults"]
            )
        )

    def test_scheduled_target_needs_elapsed_sample_binding(self) -> None:
        sample = copy.deepcopy(
            raw_coverage_window(
                "POST_CLEANUP",
                "target-binding",
            )["samples"][0]
        )
        sample["sampleIndex"] = 0
        sample["capturedAt"] = "fixture"
        targets = [0.0, 0.05, 0.25, 1.0]
        poll = {
            "targetDelaysSeconds": targets,
            "targetCount": 4,
            "completedTargetCount": 4,
            "maximumPollIntervalSeconds": 0.05,
            "sampleCount": 1,
            "maximumObservedPollGapSeconds": 0.01,
            "samples": [sample],
            "timeline": [
                {
                    "delaySeconds": target,
                    "targetDelaySeconds": target,
                    "actualElapsedSeconds": 1.0,
                    "sampleIndex": 0,
                    "capturedAt": "fixture",
                    "safetyFaults": [],
                    "snapshot": copy.deepcopy(sample["snapshot"]),
                }
                for target in targets
            ],
            "pollFaults": [],
            "complete": True,
        }
        final_tail = {
            "label": "target-binding",
            "safetyBoundary": "POST_CLEANUP",
            "safetyWindowKind": "FINAL_RUNNING_STABILIZATION",
            "outcome": "CLEAN_RUNNING",
            "safetyPoll": poll,
            "resumeFault": None,
            "samplerFault": None,
            "failStopFault": None,
            "gateFaults": [],
        }
        coverage = runner.build_safety_coverage(
            t0={},
            t1={},
            t2={},
            t3={},
            t4={},
            t5={"finalRunningSafetyTail": final_tail},
            cleanup={},
        )
        self.assertEqual(1, len(coverage))
        self.assertFalse(coverage[0]["complete"])
        self.assertTrue(
            any(
                "elapsed time disagrees with its sample" in fault
                for fault in coverage[0]["faults"]
            )
        )

    def test_coverage_provenance_route_splice_cannot_match(self) -> None:
        candidate = evaluation_input("bit-or")
        attribution = next(
            item
            for item in candidate["safetyCoverage"]
            if item["boundary"] == "ATTRIBUTION_WINDOW"
        )
        attribution["provenance"]["jsonPath"] = "/fabricated/window"
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_INCONCLUSIVE,
            result["observationState"],
        )
        self.assertTrue(
            any(
                "not an allow-listed raw window route" in fault
                for fault in result["evidenceShapeFaults"]
            )
        )

    def test_derived_runtime_summary_cannot_be_numeric_authority(
        self,
    ) -> None:
        t5 = {
            "evaluationEvidence": {
                "runtimeSafetyFaults": [
                    {
                        "snapshot": outer(state(ues=1)),
                    }
                ]
            }
        }
        observations = runner.build_numeric_safety_observations(
            t0={},
            t1={},
            t2={},
            t3={},
            t4={},
            t5=t5,
            cleanup={},
            baseline_phase=None,
            terminal_phase=None,
        )
        self.assertEqual([], observations)

    def test_continuous_gate_sampler_covers_targets_with_bounded_gaps(
        self,
    ) -> None:
        class Clock:
            now = 0.0

            def monotonic(self) -> float:
                return self.now

            def sleep(self, seconds: float) -> None:
                self.now += seconds

        clock = Clock()
        snapshot = outer(state())
        with (
            mock.patch.object(
                runner.esxi_aer.time,
                "monotonic",
                side_effect=clock.monotonic,
            ),
            mock.patch.object(
                runner.esxi_aer.time,
                "sleep",
                side_effect=clock.sleep,
            ),
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                side_effect=lambda *_args: copy.deepcopy(snapshot),
            ),
        ):
            record = runner.esxi_aer.sample_gate_timeline_continuous(
                Path("qtest.sock"),
                "0000:01:00.1",
                "0000:00:01.0",
                runner.CONTROLLED_BITS,
                tuple(
                    self.profile["timingEnvelope"][
                        "timelineDelaysSeconds"
                    ]
                ),
                started_at=0.0,
                maximum_poll_interval=0.05,
                target_poll_interval=0.025,
            )
        self.assertTrue(record["complete"])
        self.assertEqual(record["completedTargetCount"], 4)
        self.assertGreaterEqual(record["sampleCount"], 5)
        self.assertLessEqual(
            record["maximumObservedPollGapSeconds"],
            0.05,
        )
        self.assertEqual(
            [item["targetDelaySeconds"] for item in record["timeline"]],
            [0.0, 0.05, 0.25, 1.0],
        )
        final_tail = {
            "label": "fixture-final-tail",
            "safetyBoundary": "POST_CLEANUP",
            "safetyWindowKind": "FINAL_RUNNING_STABILIZATION",
            "outcome": "CLEAN_RUNNING",
            "safetyPoll": record,
            "gateFaults": [],
        }
        coverage = runner.build_safety_coverage(
            t0={},
            t1={},
            t2={},
            t3={},
            t4={},
            t5={"finalRunningSafetyTail": final_tail},
            cleanup={},
        )
        self.assertEqual(1, len(coverage))
        self.assertTrue(coverage[0]["complete"], coverage[0]["faults"])
        self.assertEqual(
            [],
            runner.safety_coverage_profile_faults(
                {"safetyCoverage": coverage},
                self.profile,
            ),
        )

    def test_continuous_gate_sampler_retains_safety_before_timing_fault(
        self,
    ) -> None:
        class Clock:
            now = 0.0

            def monotonic(self) -> float:
                return self.now

            def sleep(self, seconds: float) -> None:
                self.now += seconds

        clock = Clock()
        unsafe = outer(state(ues=1))

        def slow_unsafe_snapshot(*_args: Any) -> dict[str, Any]:
            clock.now += 0.06
            return copy.deepcopy(unsafe)

        with (
            mock.patch.object(
                runner.esxi_aer.time,
                "monotonic",
                side_effect=clock.monotonic,
            ),
            mock.patch.object(
                runner.esxi_aer.time,
                "sleep",
                side_effect=clock.sleep,
            ),
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                side_effect=slow_unsafe_snapshot,
            ),
        ):
            record = runner.esxi_aer.sample_gate_timeline_continuous(
                Path("qtest.sock"),
                "0000:01:00.1",
                "0000:00:01.0",
                runner.CONTROLLED_BITS,
                (0.0, 0.05),
                started_at=0.0,
                maximum_poll_interval=0.05,
                target_poll_interval=0.025,
            )
        self.assertFalse(record["complete"])
        self.assertTrue(record["safetyEvents"])
        self.assertTrue(
            any(
                item["type"] == "SafetyPollReadDurationExceeded"
                for item in record["pollFaults"]
            )
        )

    def test_continuous_sampler_finalization_cannot_erase_shared_unsafe_read(
        self,
    ) -> None:
        class Clock:
            now = 0.0

            def monotonic(self) -> float:
                return self.now

            def sleep(self, seconds: float) -> None:
                self.now += seconds

        clock = Clock()
        partial: dict[str, Any] = {}
        with (
            mock.patch.object(
                runner.esxi_aer.time,
                "monotonic",
                side_effect=clock.monotonic,
            ),
            mock.patch.object(
                runner.esxi_aer.time,
                "sleep",
                side_effect=clock.sleep,
            ),
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                return_value=outer(state(ues=1)),
            ),
            mock.patch.object(
                runner.esxi_aer,
                "utc_now",
                side_effect=["sample", KeyboardInterrupt()],
            ),
        ):
            record = runner.esxi_aer.sample_gate_timeline_continuous(
                Path("qtest.sock"),
                "0000:01:00.1",
                "0000:00:01.0",
                runner.CONTROLLED_BITS,
                (0.0,),
                started_at=0.0,
                maximum_poll_interval=0.05,
                target_poll_interval=0.025,
                _partial_record=partial,
            )
        self.assertIs(record, partial)
        self.assertEqual(
            1,
            partial["samples"][0]["snapshot"]["endpointState"][
                "uncorrectableErrorStatus"
            ],
        )
        self.assertTrue(partial["safetyEvents"])
        self.assertTrue(
            any(
                item.get("phase") == "safety-poll-finalization"
                for item in partial["pollFaults"]
            )
        )

    def test_baseline_clear_failure_retains_numeric_unsafe_snapshot(
        self,
    ) -> None:
        unsafe = outer(state(ues=1))
        with (
            mock.patch.object(
                runner.esxi_aer,
                "hmp_command",
                side_effect=["", "VM status: paused"],
            ),
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                return_value=unsafe,
            ),
        ):
            with self.assertRaises(
                runner.esxi_aer.BaselineClearFailure
            ) as captured:
                runner.esxi_aer.clear_outer_qemu_aer_baseline(
                    Path("monitor.sock"),
                    Path("qtest.sock"),
                    "0000:01:00.1",
                    "0000:00:01.0",
                    "strict",
                    leave_paused=True,
                )
        error = captured.exception
        self.assertTrue(error.safety)
        self.assertEqual(
            1,
            error.result["before"]["endpointState"][
                "uncorrectableErrorStatus"
            ],
        )
        self.assertTrue(error.result["qemuHeldPaused"])

    def test_baseline_parser_interrupt_cannot_downgrade_raw_unsafe(
        self,
    ) -> None:
        unsafe = outer(state(ues=1))
        with (
            mock.patch.object(
                runner.esxi_aer,
                "hmp_command",
                side_effect=["", "VM status: paused"],
            ),
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                return_value=unsafe,
            ),
            mock.patch.object(
                runner.esxi_aer,
                "outer_snapshot_safety_faults",
                side_effect=KeyboardInterrupt(),
            ),
        ):
            with self.assertRaises(
                runner.esxi_aer.BaselineClearFailure
            ) as captured:
                runner.esxi_aer.clear_outer_qemu_aer_baseline(
                    Path("monitor.sock"),
                    Path("qtest.sock"),
                    "0000:01:00.1",
                    "0000:00:01.0",
                    "strict",
                    leave_paused=True,
                )
        self.assertTrue(captured.exception.safety)
        self.assertIn(
            "endpoint UES=0x00000001",
            captured.exception.result["numericSafetyFaults"],
        )

    def test_baseline_final_timestamp_interrupt_remains_typed_safety(
        self,
    ) -> None:
        unsafe = outer(state(ues=1))
        with (
            mock.patch.object(
                runner.esxi_aer,
                "hmp_command",
                side_effect=["", "VM status: paused"],
            ),
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                return_value=unsafe,
            ),
            mock.patch.object(
                runner.esxi_aer,
                "utc_now",
                side_effect=["started", KeyboardInterrupt()],
            ),
        ):
            with self.assertRaises(
                runner.esxi_aer.BaselineClearFailure
            ) as captured:
                runner.esxi_aer.clear_outer_qemu_aer_baseline(
                    Path("monitor.sock"),
                    Path("qtest.sock"),
                    "0000:01:00.1",
                    "0000:00:01.0",
                    "strict",
                    leave_paused=True,
                )
        self.assertTrue(captured.exception.safety)
        self.assertEqual(
            "KeyboardInterrupt",
            captured.exception.result["finalizationFault"]["type"],
        )
        self.assertEqual(
            1,
            captured.exception.result["before"]["endpointState"][
                "uncorrectableErrorStatus"
            ],
        )

    def test_gate_apply_prewrite_safety_retains_lease_snapshot(
        self,
    ) -> None:
        unsafe = outer(state(ues=1))
        with (
            mock.patch.object(
                runner.esxi_aer,
                "transition_qemu",
                return_value={"state": "paused"},
            ),
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                return_value=unsafe,
            ),
        ):
            with self.assertRaises(
                runner.esxi_aer.GateLeaseApplyFailure
            ) as captured:
                runner.esxi_aer.apply_gate_lease(
                    Path("monitor.sock"),
                    Path("qtest.sock"),
                    "0000:01:00.1",
                    "0000:00:01.0",
                    runner.CONTROLLED_BITS,
                    runner.SUPPORTED_GATES["g101"],
                    enable_root_path=True,
                    hold_paused_after_sampling=True,
                )
        error = captured.exception
        self.assertTrue(error.safety)
        self.assertEqual(
            "PRE_WRITE_SAFETY_FAULT_HELD_PAUSED",
            error.lease["outcome"],
        )
        self.assertEqual(
            1,
            error.lease["original"]["snapshot"]["endpointState"][
                "uncorrectableErrorStatus"
            ],
        )

    def test_gate_restore_parse_failure_retains_partial_numeric_result(
        self,
    ) -> None:
        original = outer(state())
        malformed = copy.deepcopy(original)
        del malformed["endpointState"]["correctableErrorMask"]
        lease = {
            "original": {"snapshot": original},
            "rootPathLease": {"managed": False},
        }
        with (
            mock.patch.object(
                runner.esxi_aer,
                "transition_qemu",
                return_value={"state": "paused"},
            ),
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                return_value=malformed,
            ),
        ):
            with self.assertRaises(
                runner.esxi_aer.GateLeaseRestoreFailure
            ) as captured:
                runner.esxi_aer.restore_gate_lease(
                    Path("monitor.sock"),
                    Path("qtest.sock"),
                    "0000:01:00.1",
                    "0000:00:01.0",
                    runner.CONTROLLED_BITS,
                    lease,
                    safe_stop=False,
                )
        result = captured.exception.result
        self.assertEqual(
            "RESTORE_TRANSACTION_FAILED_HELD_PAUSED",
            result["outcome"],
        )
        self.assertEqual(
            malformed,
            result["timeline"]["before"]["snapshot"],
        )
        self.assertTrue(result["qemuHeldPaused"])

    def test_service_metadata_interrupt_reclassifies_attached_raw_safety(
        self,
    ) -> None:
        args = SimpleNamespace(
            timeline_delays=(0.0,),
            maximum_safety_poll_interval_seconds=0.1,
            safety_poll_target_interval_seconds=0.01,
            outer_endpoint_bdf="0000:01:00.1",
            outer_root_bdf="0000:00:01.0",
        )
        recorder = runner.LiveSequenceRecorder(
            args=args,
            case_dir=Path("."),
            monitor=Path("monitor.sock"),
            qtest_socket=Path("qtest.sock"),
            ssh=mock.Mock(),
            api=mock.Mock(),
            active_vm=None,
            requested_gate=runner.SUPPORTED_GATES["g101"],
            topology=outer(state()),
        )
        recorder.paused = True
        transitions: list[str] = []

        def resume(_reason: str) -> dict[str, Any]:
            transitions.append("cont")
            recorder.paused = False
            return {"state": "running"}

        def pause(_reason: str) -> dict[str, Any]:
            transitions.append("stop")
            recorder.paused = True
            return {"state": "paused"}

        with (
            mock.patch.object(recorder, "resume", side_effect=resume),
            mock.patch.object(recorder, "pause", side_effect=pause),
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                return_value=outer(state(ues=1)),
            ),
            mock.patch.object(
                runner,
                "utc_now",
                side_effect=KeyboardInterrupt(),
            ),
        ):
            with self.assertRaises(runner.esxi_aer.SafetyViolation):
                recorder.service_window("unsafe-service", "fixture")
        self.assertEqual(["cont", "stop"], transitions)
        record = recorder.t4[-1]
        self.assertEqual(1, record["safetyPoll"]["sampleCount"])
        self.assertEqual(
            1,
            record["safetyPoll"]["samples"][0]["snapshot"][
                "endpointState"
            ]["uncorrectableErrorStatus"],
        )
        self.assertTrue(recorder.safety_faults)

    def test_monitored_window_retains_read_and_both_stop_faults(
        self,
    ) -> None:
        args = SimpleNamespace(
            maximum_safety_poll_interval_seconds=0.1,
            safety_poll_target_interval_seconds=0.01,
            outer_endpoint_bdf="0000:01:00.1",
            outer_root_bdf="0000:00:01.0",
        )
        recorder = runner.LiveSequenceRecorder(
            args=args,
            case_dir=Path("."),
            monitor=Path("monitor.sock"),
            qtest_socket=Path("qtest.sock"),
            ssh=mock.Mock(),
            api=mock.Mock(),
            active_vm=None,
            requested_gate=runner.SUPPORTED_GATES["g101"],
            topology=outer(state()),
        )
        recorder.paused = True

        def resume(_reason: str) -> dict[str, Any]:
            recorder.paused = False
            return {"state": "running"}

        def stop_failure(_reason: str) -> dict[str, Any]:
            raise RuntimeError("stop readback failed")

        with (
            mock.patch.object(recorder, "resume", side_effect=resume),
            mock.patch.object(recorder, "pause", side_effect=stop_failure),
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                side_effect=[
                    outer(state()),
                    RuntimeError("qtest read failed"),
                ],
            ),
        ):
            with self.assertRaises(runner.FixtureInvalid):
                recorder.monitored_runnable(
                    label="fault-window",
                    description="fixture",
                    worker=lambda cancel: cancel.wait(1.0),
                )
        record = recorder.t4[-1]
        self.assertEqual("RuntimeError", record["monitorFault"]["type"])
        self.assertEqual(
            "RuntimeError",
            record["immediateStopFault"]["type"],
        )
        self.assertEqual(
            "RuntimeError",
            record["finalStopFault"]["type"],
        )
        self.assertFalse(record["coverageComplete"])

    def test_monitored_window_excludes_paused_gc_from_first_gap(
        self,
    ) -> None:
        args = SimpleNamespace(
            maximum_safety_poll_interval_seconds=0.05,
            safety_poll_target_interval_seconds=0.01,
            outer_endpoint_bdf="0000:01:00.1",
            outer_root_bdf="0000:00:01.0",
        )
        recorder = runner.LiveSequenceRecorder(
            args=args,
            case_dir=Path("."),
            monitor=Path("monitor.sock"),
            qtest_socket=Path("qtest.sock"),
            ssh=mock.Mock(),
            api=mock.Mock(),
            active_vm=None,
            requested_gate=runner.SUPPORTED_GATES["g101"],
            topology=outer(state()),
        )
        recorder.paused = True

        def slow_paused_arm() -> dict[str, Any]:
            runner.time.sleep(0.06)
            return {
                "wasEnabled": True,
                "releaseState": "ARMED",
            }

        def resume(_reason: str) -> dict[str, Any]:
            recorder.paused = False
            return {"state": "running"}

        def pause(_reason: str) -> dict[str, Any]:
            recorder.paused = True
            return {"state": "paused"}

        with (
            mock.patch.object(
                runner,
                "arm_runnable_gc_guard",
                side_effect=slow_paused_arm,
            ),
            mock.patch.object(
                runner,
                "release_runnable_gc_guard",
                return_value=None,
            ),
            mock.patch.object(recorder, "resume", side_effect=resume),
            mock.patch.object(recorder, "pause", side_effect=pause),
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                return_value=outer(state()),
            ),
        ):
            result, record = recorder.monitored_runnable(
                label="paused-gc-exclusion",
                description="fixture",
                worker=lambda _cancel: {"done": True},
            )
        self.assertEqual({"done": True}, result)
        self.assertTrue(record["coverageComplete"])
        self.assertLess(
            record["maximumObservedPollGapSeconds"],
            0.05,
        )

    def test_monitored_window_samples_while_final_stop_is_in_flight(
        self,
    ) -> None:
        args = SimpleNamespace(
            maximum_safety_poll_interval_seconds=0.1,
            safety_poll_target_interval_seconds=0.01,
            outer_endpoint_bdf="0000:01:00.1",
            outer_root_bdf="0000:00:01.0",
        )
        recorder = runner.LiveSequenceRecorder(
            args=args,
            case_dir=Path("."),
            monitor=Path("monitor.sock"),
            qtest_socket=Path("qtest.sock"),
            ssh=mock.Mock(),
            api=mock.Mock(),
            active_vm=None,
            requested_gate=runner.SUPPORTED_GATES["g101"],
            topology=outer(state()),
        )
        recorder.paused = True

        def resume(_reason: str) -> dict[str, Any]:
            recorder.paused = False
            return {"state": "running"}

        def slow_pause(_reason: str) -> dict[str, Any]:
            runner.time.sleep(0.15)
            recorder.paused = True
            return {"state": "paused"}

        with (
            mock.patch.object(recorder, "resume", side_effect=resume),
            mock.patch.object(recorder, "pause", side_effect=slow_pause),
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                return_value=outer(state()),
            ),
        ):
            result, record = recorder.monitored_runnable(
                label="covered-final-stop",
                description="fixture",
                worker=lambda _cancel: {"done": True},
            )
        self.assertEqual({"done": True}, result)
        self.assertTrue(record["coverageComplete"])
        self.assertGreater(record["sampleCount"], 3)
        self.assertLess(record["tailGapSeconds"], 0.1)
        self.assertLess(record["maximumObservedPollGapSeconds"], 0.1)

    def test_monitored_cancel_interrupt_cannot_skip_final_stop(
        self,
    ) -> None:
        args = SimpleNamespace(
            maximum_safety_poll_interval_seconds=0.1,
            safety_poll_target_interval_seconds=0.01,
            outer_endpoint_bdf="0000:01:00.1",
            outer_root_bdf="0000:00:01.0",
        )
        recorder = runner.LiveSequenceRecorder(
            args=args,
            case_dir=Path("."),
            monitor=Path("monitor.sock"),
            qtest_socket=Path("qtest.sock"),
            ssh=mock.Mock(),
            api=mock.Mock(),
            active_vm=None,
            requested_gate=runner.SUPPORTED_GATES["g101"],
            topology=outer(state()),
        )
        recorder.paused = True
        transitions: list[str] = []

        def resume(_reason: str) -> dict[str, Any]:
            transitions.append("cont")
            recorder.paused = False
            return {"state": "running"}

        def pause(_reason: str) -> dict[str, Any]:
            transitions.append("stop")
            recorder.paused = True
            return {"state": "paused"}

        class InterruptingCancel:
            def set(self) -> None:
                raise KeyboardInterrupt()

            def wait(self, _seconds: float) -> bool:
                return False

            def is_set(self) -> bool:
                return False

        with (
            mock.patch.object(recorder, "resume", side_effect=resume),
            mock.patch.object(recorder, "pause", side_effect=pause),
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                return_value=outer(state()),
            ),
            mock.patch.object(
                runner,
                "new_cancel_event",
                return_value=InterruptingCancel(),
            ),
        ):
            with self.assertRaises(runner.FixtureInvalid):
                recorder.monitored_runnable(
                    label="cancel-interrupt",
                    description="fixture",
                    worker=lambda _cancel: {"done": True},
                )
        self.assertEqual("cont", transitions[0])
        self.assertIn("stop", transitions)
        record = recorder.t4[-1]
        self.assertEqual(
            "KeyboardInterrupt",
            record["cancelFault"]["type"],
        )
        self.assertFalse(record["coverageComplete"])

    def test_monitored_final_timestamp_interrupt_preserves_safety_verdict(
        self,
    ) -> None:
        args = SimpleNamespace(
            maximum_safety_poll_interval_seconds=0.1,
            safety_poll_target_interval_seconds=0.01,
            outer_endpoint_bdf="0000:01:00.1",
            outer_root_bdf="0000:00:01.0",
        )
        recorder = runner.LiveSequenceRecorder(
            args=args,
            case_dir=Path("."),
            monitor=Path("monitor.sock"),
            qtest_socket=Path("qtest.sock"),
            ssh=mock.Mock(),
            api=mock.Mock(),
            active_vm=None,
            requested_gate=runner.SUPPORTED_GATES["g101"],
            topology=outer(state()),
        )
        recorder.paused = True
        transitions: list[str] = []

        def resume(_reason: str) -> dict[str, Any]:
            transitions.append("cont")
            recorder.paused = False
            return {"state": "running"}

        def pause(_reason: str) -> dict[str, Any]:
            transitions.append("stop")
            recorder.paused = True
            return {"state": "paused"}

        with (
            mock.patch.object(recorder, "resume", side_effect=resume),
            mock.patch.object(recorder, "pause", side_effect=pause),
            mock.patch.object(
                recorder,
                "check_gate",
                return_value={"checks": {"fixture": True}},
            ),
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                return_value=outer(state(ues=1)),
            ),
            mock.patch.object(
                runner,
                "utc_now",
                side_effect=["sample", KeyboardInterrupt()],
            ),
        ):
            with self.assertRaises(runner.esxi_aer.SafetyViolation):
                recorder.monitored_runnable(
                    label="unsafe-finalization",
                    description="fixture",
                    worker=lambda _cancel: {"done": True},
                )
        self.assertEqual(["cont", "stop"], transitions)
        record = recorder.t4[-1]
        self.assertEqual(
            "KeyboardInterrupt",
            record["finalizationFault"]["type"],
        )
        self.assertTrue(record["safetyEvents"])
        self.assertTrue(recorder.safety_faults)
        self.assertFalse(record["coverageComplete"])

    def test_final_tail_keyboard_interrupt_still_attempts_fail_stop(
        self,
    ) -> None:
        args = SimpleNamespace(
            outer_endpoint_bdf="0000:01:00.1",
            outer_root_bdf="0000:00:01.0",
            timeline_delays=(0.0, 0.1),
            maximum_safety_poll_interval_seconds=0.1,
            safety_poll_target_interval_seconds=0.05,
        )
        transitions: list[str] = []

        def transition(
            _monitor: Path,
            command: str,
            _expected: str,
        ) -> dict[str, Any]:
            transitions.append(command)
            return {"state": _expected}

        with (
            mock.patch.object(
                runner.esxi_aer,
                "transition_qemu",
                side_effect=transition,
            ),
            mock.patch.object(
                runner.esxi_aer,
                "sample_gate_timeline_continuous",
                side_effect=KeyboardInterrupt(),
            ),
        ):
            result = runner.resume_with_safety_stabilization(
                args=args,
                monitor=Path("monitor.sock"),
                qtest_socket=Path("qtest.sock"),
                label="final-tail",
                expected_gate=None,
                expected_root_path=None,
                topology=pinned_topology(),
            )
        self.assertEqual(["cont", "stop"], transitions)
        self.assertEqual(
            "SAMPLER_FAILED_HELD_PAUSED",
            result["outcome"],
        )
        self.assertEqual("KeyboardInterrupt", result["samplerFault"]["type"])

    def test_final_tail_malformed_sampler_result_is_fail_stopped(
        self,
    ) -> None:
        args = SimpleNamespace(
            outer_endpoint_bdf="0000:01:00.1",
            outer_root_bdf="0000:00:01.0",
            timeline_delays=(0.0, 0.1),
            maximum_safety_poll_interval_seconds=0.1,
            safety_poll_target_interval_seconds=0.05,
        )
        transitions: list[str] = []

        def transition(
            _monitor: Path,
            command: str,
            expected: str,
        ) -> dict[str, Any]:
            transitions.append(command)
            return {"state": expected}

        topology = pinned_topology()
        with (
            mock.patch.object(
                runner.esxi_aer,
                "transition_qemu",
                side_effect=transition,
            ),
            mock.patch.object(
                runner.esxi_aer,
                "sample_gate_timeline_continuous",
                return_value={
                    "samples": [{}],
                    "safetyEvents": [],
                    "pollFaults": [],
                    "complete": True,
                },
            ) as sampler,
        ):
            result = runner.resume_with_safety_stabilization(
                args=args,
                monitor=Path("monitor.sock"),
                qtest_socket=Path("qtest.sock"),
                label="final-tail",
                expected_gate=None,
                expected_root_path=None,
                topology=topology,
            )
        self.assertEqual(["cont", "stop"], transitions)
        self.assertIs(topology, sampler.call_args.kwargs["topology"])
        self.assertEqual(
            "TAIL_ANALYSIS_FAILED_HELD_PAUSED",
            result["outcome"],
        )
        self.assertEqual(
            "KeyError",
            result["postSamplerAnalysisFault"]["type"],
        )

    def test_final_tail_requires_topology_before_resume(self) -> None:
        args = SimpleNamespace(
            outer_endpoint_bdf="0000:01:00.1",
            outer_root_bdf="0000:00:01.0",
            timeline_delays=(0.0, 0.1),
            maximum_safety_poll_interval_seconds=0.1,
            safety_poll_target_interval_seconds=0.05,
        )
        with (
            mock.patch.object(
                runner.esxi_aer,
                "transition_qemu",
            ) as transition,
            mock.patch.object(
                runner.esxi_aer,
                "sample_gate_timeline_continuous",
            ) as sampler,
        ):
            with self.assertRaises(runner.esxi_aer.BlockedEnvironment):
                runner.resume_with_safety_stabilization(
                    args=args,
                    monitor=Path("monitor.sock"),
                    qtest_socket=Path("qtest.sock"),
                    label="final-tail",
                    expected_gate=None,
                    expected_root_path=None,
                    topology=None,  # type: ignore[arg-type]
                )
        transition.assert_not_called()
        sampler.assert_not_called()

    def test_paused_final_tail_uses_cleanup_topology_without_lease(
        self,
    ) -> None:
        args = SimpleNamespace(
            outer_endpoint_bdf="0000:01:00.1",
            outer_root_bdf="0000:00:01.0",
        )
        cleanup_topology = pinned_topology()
        refreshed_topology = copy.deepcopy(cleanup_topology)
        with mock.patch.object(
            runner.esxi_aer,
            "outer_qemu_aer_snapshot",
            return_value=refreshed_topology,
        ) as snapshot:
            result = runner.capture_paused_final_tail_inputs(
                args=args,
                qtest_socket=Path("qtest.sock"),
                lease=None,
                cleanup_topology=cleanup_topology,
            )
        snapshot.assert_called_once_with(
            Path("qtest.sock"),
            "0000:01:00.1",
            "0000:00:01.0",
            topology=cleanup_topology,
        )
        self.assertIs(refreshed_topology, result["topology"])
        self.assertIsNone(result["expectedGate"])
        self.assertIsNone(result["expectedRootPath"])
        self.assertEqual(
            "ACTIVE_VM_CLEANUP",
            result["baseline"]["topologySeedMode"],
        )
        self.assertEqual(
            "PINNED_TOPOLOGY_BLOCK_BATCH",
            result["baseline"]["captureSnapshotMode"],
        )
        self.assertEqual(
            "PINNED_TOPOLOGY_BLOCK_BATCH",
            result["baseline"]["runnableSnapshotMode"],
        )

    def test_paused_final_tail_discovers_once_when_no_seed_exists(
        self,
    ) -> None:
        args = SimpleNamespace(
            outer_endpoint_bdf="0000:01:00.1",
            outer_root_bdf="0000:00:01.0",
        )
        refreshed_topology = pinned_topology()
        with mock.patch.object(
            runner.esxi_aer,
            "outer_qemu_aer_snapshot",
            return_value=refreshed_topology,
        ) as snapshot:
            result = runner.capture_paused_final_tail_inputs(
                args=args,
                qtest_socket=Path("qtest.sock"),
                lease=None,
                cleanup_topology=None,
            )
        snapshot.assert_called_once_with(
            Path("qtest.sock"),
            "0000:01:00.1",
            "0000:00:01.0",
            topology=None,
        )
        self.assertIs(refreshed_topology, result["topology"])
        self.assertEqual(
            "PAUSED_FULL_DISCOVERY",
            result["baseline"]["topologySeedMode"],
        )
        self.assertEqual(
            "FULL_DISCOVERY",
            result["baseline"]["captureSnapshotMode"],
        )
        self.assertEqual(
            "PINNED_TOPOLOGY_BLOCK_BATCH",
            result["baseline"]["runnableSnapshotMode"],
        )

    def test_paused_final_tail_keeps_lease_restore_oracle(
        self,
    ) -> None:
        args = SimpleNamespace(
            outer_endpoint_bdf="0000:01:00.1",
            outer_root_bdf="0000:00:01.0",
        )
        original = pinned_topology()
        cleanup_topology = copy.deepcopy(original)
        cleanup_topology["endpointState"]["deviceControl"] = 0
        cleanup_topology["rootState"]["rootErrorCommand"] = 0
        cleanup_topology["rootState"]["deviceControl"] = 0
        cleanup_topology["rootState"]["bridgeControl"] = 0
        lease = {"original": {"snapshot": original}}
        with mock.patch.object(
            runner.esxi_aer,
            "outer_qemu_aer_snapshot",
            return_value=cleanup_topology,
        ) as snapshot:
            result = runner.capture_paused_final_tail_inputs(
                args=args,
                qtest_socket=Path("qtest.sock"),
                lease=lease,
                cleanup_topology=cleanup_topology,
            )
        snapshot.assert_called_once_with(
            Path("qtest.sock"),
            "0000:01:00.1",
            "0000:00:01.0",
            topology=cleanup_topology,
        )
        self.assertEqual("101", result["expectedGate"].label)
        self.assertTrue(result["expectedRootPath"].open)
        self.assertIs(cleanup_topology, result["topology"])

    def test_gate_apply_malformed_sampler_result_is_typed_fail_stop(
        self,
    ) -> None:
        clean = outer(state())
        transitions: list[str] = []

        def transition(
            _monitor: Path,
            command: str,
            expected: str,
        ) -> dict[str, Any]:
            transitions.append(command)
            return {"state": expected}

        with (
            mock.patch.object(
                runner.esxi_aer,
                "transition_qemu",
                side_effect=transition,
            ),
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                side_effect=[copy.deepcopy(clean), copy.deepcopy(clean)],
            ),
            mock.patch.object(
                runner.esxi_aer,
                "write_gate_tuple",
            ),
            mock.patch.object(
                runner.esxi_aer.qemu_aer,
                "QTestClient",
            ),
            mock.patch.object(
                runner.esxi_aer,
                "sample_gate_timeline_continuous",
                return_value={
                    "timeline": [],
                    "samples": [{}],
                    "pollFaults": [],
                },
            ),
        ):
            with self.assertRaises(
                runner.esxi_aer.GateLeaseApplyFailure
            ) as captured:
                runner.esxi_aer.apply_gate_lease(
                    Path("monitor.sock"),
                    Path("qtest.sock"),
                    "0000:01:00.1",
                    "0000:00:01.0",
                    runner.CONTROLLED_BITS,
                    runner.SUPPORTED_GATES["g101"],
                    enable_root_path=True,
                    maximum_safety_poll_interval=0.1,
                    safety_poll_target_interval=0.05,
                    hold_paused_after_sampling=False,
                )
        self.assertEqual(["stop", "cont", "stop"], transitions)
        lease = captured.exception.lease
        self.assertTrue(lease["qemuHeldPaused"])
        self.assertEqual("KeyError", lease["postProcessingFault"]["type"])

    def test_gate_restore_malformed_sampler_result_is_typed_fail_stop(
        self,
    ) -> None:
        clean = outer(state())
        lease = {
            "original": {"snapshot": copy.deepcopy(clean)},
            "rootPathLease": {"managed": False},
        }
        transitions: list[str] = []

        def transition(
            _monitor: Path,
            command: str,
            expected: str,
        ) -> dict[str, Any]:
            transitions.append(command)
            return {"state": expected}

        with (
            mock.patch.object(
                runner.esxi_aer,
                "transition_qemu",
                side_effect=transition,
            ),
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                side_effect=[copy.deepcopy(clean), copy.deepcopy(clean)],
            ),
            mock.patch.object(
                runner.esxi_aer,
                "write_gate_tuple",
            ),
            mock.patch.object(
                runner.esxi_aer.qemu_aer,
                "QTestClient",
            ),
            mock.patch.object(
                runner.esxi_aer,
                "sample_gate_timeline_continuous",
                return_value={
                    "timeline": [],
                    "samples": [{}],
                    "pollFaults": [],
                },
            ),
        ):
            with self.assertRaises(
                runner.esxi_aer.GateLeaseRestoreFailure
            ) as captured:
                runner.esxi_aer.restore_gate_lease(
                    Path("monitor.sock"),
                    Path("qtest.sock"),
                    "0000:01:00.1",
                    "0000:00:01.0",
                    runner.CONTROLLED_BITS,
                    lease,
                    safe_stop=False,
                    maximum_safety_poll_interval=0.1,
                    safety_poll_target_interval=0.05,
                    hold_paused_after_sampling=False,
                )
        self.assertEqual(["stop", "cont", "stop"], transitions)
        result = captured.exception.result
        self.assertTrue(result["qemuHeldPaused"])
        self.assertEqual("KeyError", result["postProcessingFault"]["type"])

    def test_gate_apply_partial_unsafe_readback_keeps_safety_outcome(
        self,
    ) -> None:
        clean = outer(state())
        real_gate_readback = runner.esxi_aer.gate_readback
        for ues, expected_outcome in (
            (1, "SAFETY_FAULT_AFTER_APPLY"),
            (0, "SAFETY_POLL_INCOMPLETE_AFTER_APPLY"),
        ):
            with self.subTest(ues=ues):
                transitions: list[str] = []
                gate_read_count = 0

                def transition(
                    _monitor: Path,
                    command: str,
                    expected: str,
                ) -> dict[str, Any]:
                    transitions.append(command)
                    return {"state": expected}

                def interrupt_resumed_readback(
                    snapshot: dict[str, Any],
                    mask: int,
                ) -> dict[str, Any]:
                    nonlocal gate_read_count
                    gate_read_count += 1
                    if gate_read_count == 3:
                        raise KeyboardInterrupt()
                    return real_gate_readback(snapshot, mask)

                with (
                    mock.patch.object(
                        runner.esxi_aer,
                        "transition_qemu",
                        side_effect=transition,
                    ),
                    mock.patch.object(
                        runner.esxi_aer,
                        "outer_qemu_aer_snapshot",
                        side_effect=[
                            copy.deepcopy(clean),
                            copy.deepcopy(clean),
                            outer(state(ues=ues)),
                        ],
                    ),
                    mock.patch.object(runner.esxi_aer, "write_gate_tuple"),
                    mock.patch.object(
                        runner.esxi_aer.qemu_aer,
                        "QTestClient",
                    ),
                    mock.patch.object(
                        runner.esxi_aer,
                        "gate_readback",
                        side_effect=interrupt_resumed_readback,
                    ),
                ):
                    lease = runner.esxi_aer.apply_gate_lease(
                        Path("monitor.sock"),
                        Path("qtest.sock"),
                        "0000:01:00.1",
                        "0000:00:01.0",
                        runner.CONTROLLED_BITS,
                        runner.SUPPORTED_GATES["g101"],
                        enable_root_path=True,
                        timeline_delays=(0.0,),
                        maximum_safety_poll_interval=1.0,
                        safety_poll_target_interval=0.5,
                        hold_paused_after_sampling=False,
                    )
            self.assertEqual(["stop", "cont", "stop"], transitions)
            self.assertEqual(expected_outcome, lease["outcome"])
            self.assertTrue(lease["qemuHeldPaused"])
            self.assertIsNone(lease["effective"])
            self.assertIsNotNone(lease["lastConfirmedEffective"])
            poll = lease["timeline"]["resumedSafetyPoll"]
            self.assertEqual("PAUSED_ACK", poll["closure"]["mode"])
            self.assertTrue(poll["samples"][0]["partial"])
            self.assertEqual(
                "qtest-safety-parse",
                poll["pollFaults"][0]["phase"],
            )
            self.assertEqual(bool(ues), bool(lease["resumedSafetyFaults"]))
            self.assertNotIn("postProcessingFault", lease)

    def test_gate_restore_partial_unsafe_readback_keeps_safety_outcome(
        self,
    ) -> None:
        clean = outer(state())
        real_gate_readback = runner.esxi_aer.gate_readback
        for ues, expected_outcome in (
            (1, "RESTORE_SAFETY_FAULT_HELD_PAUSED"),
            (0, "RESTORE_SAFETY_POLL_INCOMPLETE_HELD_PAUSED"),
        ):
            with self.subTest(ues=ues):
                lease = {
                    "original": {"snapshot": copy.deepcopy(clean)},
                    "rootPathLease": {"managed": False},
                }
                transitions: list[str] = []
                gate_read_count = 0

                def transition(
                    _monitor: Path,
                    command: str,
                    expected: str,
                ) -> dict[str, Any]:
                    transitions.append(command)
                    return {"state": expected}

                def interrupt_resumed_readback(
                    snapshot: dict[str, Any],
                    mask: int,
                ) -> dict[str, Any]:
                    nonlocal gate_read_count
                    gate_read_count += 1
                    if gate_read_count == 3:
                        raise KeyboardInterrupt()
                    return real_gate_readback(snapshot, mask)

                with (
                    mock.patch.object(
                        runner.esxi_aer,
                        "transition_qemu",
                        side_effect=transition,
                    ),
                    mock.patch.object(
                        runner.esxi_aer,
                        "outer_qemu_aer_snapshot",
                        side_effect=[
                            copy.deepcopy(clean),
                            copy.deepcopy(clean),
                            outer(state(ues=ues)),
                        ],
                    ),
                    mock.patch.object(runner.esxi_aer, "write_gate_tuple"),
                    mock.patch.object(
                        runner.esxi_aer.qemu_aer,
                        "QTestClient",
                    ),
                    mock.patch.object(
                        runner.esxi_aer,
                        "gate_readback",
                        side_effect=interrupt_resumed_readback,
                    ),
                ):
                    result = runner.esxi_aer.restore_gate_lease(
                        Path("monitor.sock"),
                        Path("qtest.sock"),
                        "0000:01:00.1",
                        "0000:00:01.0",
                        runner.CONTROLLED_BITS,
                        lease,
                        safe_stop=False,
                        timeline_delays=(0.0,),
                        maximum_safety_poll_interval=1.0,
                        safety_poll_target_interval=0.5,
                        hold_paused_after_sampling=False,
                    )
            self.assertEqual(["stop", "cont", "stop"], transitions)
            self.assertEqual(expected_outcome, result["outcome"])
            self.assertTrue(result["qemuHeldPaused"])
            self.assertIsNone(result["effective"])
            self.assertIsNotNone(result["lastConfirmedEffective"])
            poll = result["timeline"]["resumedSafetyPoll"]
            self.assertEqual("PAUSED_ACK", poll["closure"]["mode"])
            self.assertTrue(poll["samples"][0]["partial"])
            self.assertEqual(
                "qtest-safety-parse",
                poll["pollFaults"][0]["phase"],
            )
            self.assertEqual(
                bool(ues),
                bool(result["resumedSafetyFaults"]),
            )
            self.assertNotIn("postProcessingFault", result)

    def test_gate_effective_requires_explicit_complete_marker(self) -> None:
        clean = outer(state())
        readback = runner.esxi_aer.gate_readback(
            clean,
            runner.CONTROLLED_BITS,
        )
        for label, marker, include_marker in (
            ("missing", None, False),
            ("none", None, True),
            ("true", True, True),
            ("string", "false", True),
        ):
            with self.subTest(marker=label):
                sample = {
                    "readback": copy.deepcopy(readback),
                    "snapshot": copy.deepcopy(clean),
                }
                if include_marker:
                    sample["partial"] = marker
                record = {
                    "timeline": {
                        "pausedApplied": {
                            "readback": copy.deepcopy(readback),
                        }
                    },
                    "rootPathLease": {},
                }
                with self.assertRaises(TypeError):
                    runner.esxi_aer._record_resumed_gate_effective(
                        record,
                        [sample],
                        [],
                    )

    def test_partial_readback_cannot_be_last_confirmed_effective(self) -> None:
        clean = outer(state())
        readback = runner.esxi_aer.gate_readback(
            clean,
            runner.CONTROLLED_BITS,
        )
        terminal_snapshot = outer(state(ues=1))
        terminal_sample = {
            "readback": None,
            "snapshot": terminal_snapshot,
            "partial": True,
        }
        record = {
            "timeline": {
                "pausedApplied": {
                    "readback": copy.deepcopy(readback),
                }
            },
            "rootPathLease": {},
        }
        with self.assertRaises(TypeError):
            runner.esxi_aer._record_resumed_gate_effective(
                record,
                [
                    {
                        "readback": copy.deepcopy(readback),
                        "snapshot": copy.deepcopy(clean),
                        "partial": True,
                    },
                    terminal_sample,
                ],
                [
                    {
                        "phase": "qtest-safety-parse",
                        "snapshot": terminal_snapshot,
                    }
                ],
            )

    def test_pre_state_retains_partial_numeric_safety_before_shape_parse(
        self,
    ) -> None:
        args = SimpleNamespace(
            outer_endpoint_bdf="0000:01:00.1",
            outer_root_bdf="0000:00:01.0",
        )
        recorder = runner.LiveSequenceRecorder(
            args=args,
            case_dir=Path("."),
            monitor=Path("monitor.sock"),
            qtest_socket=Path("qtest.sock"),
            ssh=mock.Mock(),
            api=mock.Mock(),
            active_vm=None,
            requested_gate=runner.SUPPORTED_GATES["g101"],
            topology=outer(state()),
        )
        malformed_unsafe = outer(state(ues=1))
        del malformed_unsafe["endpointState"]["deviceStatus"]
        with mock.patch.object(
            runner.esxi_aer,
            "outer_qemu_aer_snapshot",
            return_value=malformed_unsafe,
        ):
            with self.assertRaises(runner.esxi_aer.SafetyViolation):
                recorder.record_pre_state("partial", "fixture")
        self.assertEqual(1, len(recorder.t2))
        self.assertEqual(
            runner.PRE_MUTATION_NUMERIC_SNAPSHOT_RECORD_KIND,
            recorder.t2[0]["recordKind"],
        )
        self.assertEqual(
            1,
            recorder.t2[0]["snapshot"]["endpointState"][
                "uncorrectableErrorStatus"
            ],
        )
        self.assertTrue(recorder.t2[0]["safetyFaults"])

    def test_post_cleanup_clear_pre_state_is_bound_to_t5(self) -> None:
        args = SimpleNamespace(
            outer_endpoint_bdf="0000:01:00.1",
            outer_root_bdf="0000:00:01.0",
        )
        recorder = runner.LiveSequenceRecorder(
            args=args,
            case_dir=Path("."),
            monitor=Path("monitor.sock"),
            qtest_socket=Path("qtest.sock"),
            ssh=mock.Mock(),
            api=mock.Mock(),
            active_vm=None,
            requested_gate=runner.SUPPORTED_GATES["g101"],
            topology=outer(state()),
        )
        recorder.paused = True
        recorder.mutation_boundary_crossed = True
        with (
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                side_effect=[outer(state()), outer(state())],
            ),
            mock.patch.object(recorder, "_qtest_write"),
        ):
            recorder.clear(
                "post-cleanup",
                operations=("clear-ces",),
                public_description="fixture cleanup",
                require_gate=False,
                safety_boundary="POST_CLEANUP",
            )
        self.assertEqual([], recorder.t2)
        self.assertEqual(2, len(recorder.t5))
        self.assertEqual(
            {"POST_CLEANUP"},
            {item["safetyBoundary"] for item in recorder.t5},
        )
        self.assertEqual(
            {
                runner.PRE_MUTATION_NUMERIC_SNAPSHOT_RECORD_KIND,
                runner.PAUSED_NUMERIC_SNAPSHOT_RECORD_KIND,
            },
            {item["recordKind"] for item in recorder.t5},
        )

    def test_sampler_parse_fault_retains_just_read_snapshot(self) -> None:
        malformed = {"endpointState": {}, "rootState": {}}
        with mock.patch.object(
            runner.esxi_aer,
            "outer_qemu_aer_snapshot",
            return_value=malformed,
        ):
            record = runner.esxi_aer.sample_gate_timeline_continuous(
                Path("qtest.sock"),
                "0000:01:00.1",
                "0000:00:01.0",
                runner.CONTROLLED_BITS,
                (0.0, 0.1),
                started_at=runner.esxi_aer.time.monotonic(),
                maximum_poll_interval=0.1,
                target_poll_interval=0.05,
            )
        self.assertFalse(record["complete"])
        parse_fault = next(
            item
            for item in record["pollFaults"]
            if item.get("phase") == "qtest-safety-parse"
        )
        self.assertEqual(malformed, parse_fault["snapshot"])

    def test_sampler_parse_fault_retains_known_numeric_safety_event(
        self,
    ) -> None:
        malformed_unsafe = outer(state(ues=1))
        del malformed_unsafe["endpointState"]["correctableErrorMask"]
        with mock.patch.object(
            runner.esxi_aer,
            "outer_qemu_aer_snapshot",
            return_value=malformed_unsafe,
        ):
            record = runner.esxi_aer.sample_gate_timeline_continuous(
                Path("qtest.sock"),
                "0000:01:00.1",
                "0000:00:01.0",
                runner.CONTROLLED_BITS,
                (0.0, 0.1),
                started_at=runner.esxi_aer.time.monotonic(),
                maximum_poll_interval=0.1,
                target_poll_interval=0.05,
            )
        self.assertFalse(record["complete"])
        self.assertEqual(1, record["sampleCount"])
        self.assertTrue(record["samples"][0]["partial"])
        self.assertTrue(record["safetyEvents"])
        self.assertIn(
            "endpoint UES=0x00000001",
            record["safetyEvents"][0]["faults"],
        )

    def test_sampler_gate_interrupt_retains_known_numeric_safety_event(
        self,
    ) -> None:
        unsafe = outer(state(ues=1))
        with (
            mock.patch.object(
                runner.esxi_aer,
                "outer_qemu_aer_snapshot",
                return_value=unsafe,
            ),
            mock.patch.object(
                runner.esxi_aer,
                "gate_readback",
                side_effect=KeyboardInterrupt(),
            ),
        ):
            record = runner.esxi_aer.sample_gate_timeline_continuous(
                Path("qtest.sock"),
                "0000:01:00.1",
                "0000:00:01.0",
                runner.CONTROLLED_BITS,
                (0.0, 0.1),
                started_at=runner.esxi_aer.time.monotonic(),
                maximum_poll_interval=0.1,
                target_poll_interval=0.05,
            )
        self.assertFalse(record["complete"])
        self.assertEqual(unsafe, record["samples"][0]["snapshot"])
        self.assertTrue(record["safetyEvents"])
        self.assertIn(
            "endpoint UES=0x00000001",
            record["safetyEvents"][0]["faults"],
        )

    def test_o4_requires_bound_driver_and_heartbeat(self) -> None:
        candidate = evaluation_input("bit-or", owner_phase="O4")
        candidate["o4GuestEvidenceValid"] = False
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(runner.OBSERVATION_INCONCLUSIVE,
                         result["observationState"])

    def test_repeat_aggregation_is_fail_closed(self) -> None:
        matched = [
            evaluate_observation(
                evaluation_input("first-multiple"),
                self.profile,
            )
            for _ in range(3)
        ]
        aggregate = runner.aggregate_sequence_repeats(matched, 3)
        self.assertEqual(runner.OBSERVATION_MATCH,
                         aggregate["observationState"])

        mixed = copy.deepcopy(matched)
        mixed[0]["observationState"] = runner.OBSERVATION_DIVERGED
        aggregate = runner.aggregate_sequence_repeats(mixed, 3)
        self.assertEqual(runner.OBSERVATION_INCONCLUSIVE,
                         aggregate["observationState"])

        aggregate = runner.aggregate_sequence_repeats(matched[:2], 3)
        self.assertEqual(runner.OBSERVATION_INCONCLUSIVE,
                         aggregate["observationState"])

    def test_guest_owner_and_heartbeat_parser(self) -> None:
        text = "\n".join(
            [
                (
                    "AER-OWNER phase=before-injection bdf=0000:02:00.0 "
                    "vendor=0x1af4 device=0x1041 driver=virtio-pci"
                ),
                "AER-HEARTBEAT index=0 uptime=1.0 remaining=45",
                "AER-HEARTBEAT index=1 uptime=6.0 remaining=40",
            ]
        )
        parsed = runner.parse_guest_owner_evidence(
            text,
            expected_vendor_id=0x1AF4,
            expected_device_id=0x1041,
        )
        self.assertTrue(parsed["validO4Evidence"])

        parsed = runner.parse_guest_owner_evidence(
            text.replace("driver=virtio-pci", "driver=unbound"),
            expected_vendor_id=0x1AF4,
            expected_device_id=0x1041,
        )
        self.assertFalse(parsed["validO4Evidence"])

    def test_o4_parser_rejects_wrong_duplicate_or_gapped_identity_proof(
        self,
    ) -> None:
        owner = (
            "AER-OWNER phase=before-injection bdf=0000:02:00.0 "
            "vendor=0x1af4 device=0x1041 driver=virtio-pci"
        )
        heartbeats = "\n".join(
            [
                "AER-HEARTBEAT index=0 uptime=1.0 remaining=45",
                "AER-HEARTBEAT index=1 uptime=6.0 remaining=40",
            ]
        )
        cases = {
            "wrong-identity": (
                owner.replace("device=0x1041", "device=0x1042")
                + "\n"
                + heartbeats
            ),
            "duplicate-target": owner + "\n" + owner + "\n" + heartbeats,
            "heartbeat-gap": (
                owner
                + "\n"
                + heartbeats.replace("index=1", "index=2")
            ),
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                parsed = runner.parse_guest_owner_evidence(
                    text,
                    expected_vendor_id=0x1AF4,
                    expected_device_id=0x1041,
                )
                self.assertFalse(parsed["validO4Evidence"])

    def test_o4_parser_and_json_loader_reject_overflowed_uptime(
        self,
    ) -> None:
        text = "\n".join(
            [
                (
                    "AER-OWNER phase=before-injection bdf=0000:02:00.0 "
                    "vendor=0x1af4 device=0x1041 driver=virtio-pci"
                ),
                "AER-HEARTBEAT index=0 uptime=1.0 remaining=45",
                "AER-HEARTBEAT index=1 uptime=1e309 remaining=40",
            ]
        )
        parsed = runner.parse_guest_owner_evidence(
            text,
            expected_vendor_id=0x1AF4,
            expected_device_id=0x1041,
        )
        self.assertIsNone(parsed["heartbeats"][1]["uptimeSeconds"])
        self.assertFalse(parsed["validO4Evidence"])

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "overflow.json"
            path.write_text('{"uptime": 1e309}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                runner.load_json(path)

    def test_host_projection_rejects_cross_bracket_mixed_tuple(self) -> None:
        candidate = evaluation_input("bit-or")
        before = candidate["snapshots"]["first-b0"]
        after = candidate["snapshots"]["stable-after-or"]
        candidate["hostProjection"]["outerBeforeRemote"] = outer(before)
        candidate["hostProjection"]["outerAfterRemote"] = outer(after)
        candidate["hostProjection"]["hostEndpoint"][
            "correctableStatus"
        ] = before["endpoint"]["correctableErrorStatus"]
        candidate["hostProjection"]["hostRoot"][
            "rootErrorStatus"
        ] = after["rootPort"]["rootErrorStatus"]
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_DIVERGED,
            result["observationState"],
            (
                "a host projection assembled from different before/after "
                "tuples must not pass independent field-membership checks"
            ),
        )

    def test_host_projection_accepts_contemporaneous_middle_sample(
        self,
    ) -> None:
        candidate = evaluation_input("bit-or")
        clean = candidate["snapshots"]["pre-injection"]
        terminal = candidate["snapshots"]["stable-after-or"]
        candidate["hostProjection"]["outerBeforeRemote"] = outer(clean)
        candidate["hostProjection"]["outerAfterRemote"] = outer(clean)
        candidate["hostProjection"]["outerSamples"] = [
            {
                "sampleIndex": 0,
                "actualElapsedSeconds": 0.025,
                "snapshot": outer(clean),
            },
            {
                "sampleIndex": 1,
                "actualElapsedSeconds": 0.050,
                "snapshot": outer(terminal),
            },
            {
                "sampleIndex": 2,
                "actualElapsedSeconds": 0.075,
                "snapshot": outer(clean),
            },
        ]
        result = evaluate_observation(candidate, self.profile)
        self.assertEqual(
            runner.OBSERVATION_MATCH,
            result["observationState"],
            "an ESXi tuple must match any complete contemporaneous sample",
        )
        projection = result["esxiBlackboxOracle"]["hostProjection"]
        self.assertEqual(projection["outerSampleCount"], 3)

    def test_case_plan_never_mixes_owner_phases(self) -> None:
        plan = runner.build_case_plan(
            owner_phase="O4",
            gate="g101",
            sequences=runner.SEQUENCES,
            repeat=3,
        )
        self.assertEqual(12, len(plan))
        self.assertEqual({"O4"}, {item["ownerPhase"] for item in plan})
        with self.assertRaises(ValueError):
            runner.build_case_plan(
                owner_phase="O0,O4",
                gate="g101",
                sequences=runner.SEQUENCES,
                repeat=3,
            )

    def test_manifest_verifier_detects_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_required_case_artifacts(root)
            runner.write_artifact_manifest(root)
            verified = runner.verify_artifact_manifest(root)
            self.assertTrue(verified["verified"])
            (root / "oracle.json").write_text(
                json.dumps({"tampered": True}) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(runner.ManifestError):
                runner.verify_artifact_manifest(root)

    def test_manifest_rejects_duplicate_noncanonical_and_unbound_paths(
        self,
    ) -> None:
        for mode in ("duplicate", "noncanonical", "unbound"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                write_required_case_artifacts(root)
                runner.write_artifact_manifest(root)
                manifest = root / "artifact-manifest.sha256"
                lines = manifest.read_text(encoding="ascii").splitlines()
                if mode == "duplicate":
                    lines.append(lines[0])
                    manifest.write_text(
                        "\n".join(lines) + "\n",
                        encoding="ascii",
                    )
                elif mode == "noncanonical":
                    digest, relative = lines[0].split("  ", 1)
                    lines[0] = f"{digest}  ./{relative}"
                    manifest.write_text(
                        "\n".join(lines) + "\n",
                        encoding="ascii",
                    )
                else:
                    (root / "unbound.txt").write_text(
                        "not in manifest\n",
                        encoding="utf-8",
                    )
                with self.assertRaises(runner.ManifestError):
                    runner.verify_artifact_manifest(root)

    def test_case_offline_verifier_detects_semantic_result_tamper(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            _, result = write_coherent_case(case_dir, profile_path)
            baseline = runner.evaluate_case_directory(
                case_dir,
                profile_path,
            )
            self.assertTrue(baseline["exactMatch"])
            self.assertTrue(
                baseline["dependencyClosure"]["checks"][
                    "code:esxi_log_window_v2.py"
                ]
            )

            result["observationState"] = runner.OBSERVATION_DIVERGED
            runner.save_json(case_dir / "result.json", result)
            runner.write_artifact_manifest(case_dir)
            tampered = runner.evaluate_case_directory(
                case_dir,
                profile_path,
            )
            self.assertFalse(tampered["resultExactMatch"])
            self.assertFalse(tampered["exactMatch"])

    def test_strict_pre_injection_empty_stages_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = Path(temporary)
            (case_dir / "guest-serial-final.log").write_bytes(b"")
            t0 = {
                "logWindowPreflightInventory": None,
                "beforeMarker": None,
                "beforeMarkerVisibility": None,
                "guestBefore": None,
            }
            t1 = {"activeVm": None}
            t4 = {
                "afterMarker": None,
                "afterMarkerVisibility": None,
                "logWindow": None,
                "logWindowCapture": None,
                "guest": None,
            }
            log_evidence = {
                "complete": False,
                "classification": "INCONCLUSIVE_LOG_WINDOW",
                "semanticAerLines": [],
                "semanticAerEvents": [],
                "selectedAttempt": None,
                "controlArtifact": None,
            }
            guest_evidence = {
                "required": True,
                "artifactsPresent": False,
                "validO4Evidence": False,
                "kernelEventLines": [],
                "summaryConsistency": {
                    "beforeArtifact": False,
                    "beforeOwnerEvidence": False,
                    "beforeWindowRemainingEvidence": False,
                    "activeVmBeforeArtifact": False,
                    "requiredWindowPolicy": False,
                    "afterArtifact": False,
                    "afterOwnerEvidence": False,
                    "kernelEventLines": False,
                },
            }
            self.assertTrue(
                runner.strict_pre_injection_log_stage_absence(
                    case_dir=case_dir,
                    t0=t0,
                    t4=t4,
                    evidence=log_evidence,
                )
            )
            self.assertTrue(
                runner.strict_pre_injection_o4_guest_stage_absence(
                    case_dir=case_dir,
                    t0=t0,
                    t1=t1,
                    t4=t4,
                    evidence=guest_evidence,
                )
            )

    def test_pre_injection_empty_stage_checks_reject_partial_or_raw_data(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = Path(temporary)
            t0 = {
                "logWindowPreflightInventory": None,
                "beforeMarker": None,
                "beforeMarkerVisibility": None,
                "guestBefore": None,
            }
            t1 = {"activeVm": None}
            t4 = {
                "afterMarker": None,
                "afterMarkerVisibility": None,
                "logWindow": None,
                "logWindowCapture": None,
                "guest": None,
            }
            log_evidence = {
                "complete": False,
                "classification": "INCONCLUSIVE_LOG_WINDOW",
                "semanticAerLines": [],
            }
            guest_evidence = {
                "required": True,
                "artifactsPresent": False,
                "validO4Evidence": False,
                "kernelEventLines": [],
                "summaryConsistency": {
                    "beforeArtifact": False,
                    "beforeOwnerEvidence": False,
                    "beforeWindowRemainingEvidence": False,
                    "activeVmBeforeArtifact": False,
                    "requiredWindowPolicy": False,
                    "afterArtifact": False,
                    "afterOwnerEvidence": False,
                    "kernelEventLines": False,
                },
            }

            missing_t0 = copy.deepcopy(t0)
            del missing_t0["beforeMarker"]
            self.assertFalse(
                runner.strict_pre_injection_log_stage_absence(
                    case_dir=case_dir,
                    t0=missing_t0,
                    t4=t4,
                    evidence=log_evidence,
                )
            )
            raw_dir = case_dir / "raw-esxi" / "log-window"
            raw_dir.mkdir(parents=True)
            (raw_dir / "syslog.log").write_text(
                "unexpected\n",
                encoding="utf-8",
            )
            self.assertFalse(
                runner.strict_pre_injection_log_stage_absence(
                    case_dir=case_dir,
                    t0=t0,
                    t4=t4,
                    evidence=log_evidence,
                )
            )
            (case_dir / "guest-serial-final.log").write_text(
                "unexpected\n",
                encoding="utf-8",
            )
            self.assertFalse(
                runner.strict_pre_injection_o4_guest_stage_absence(
                    case_dir=case_dir,
                    t0=t0,
                    t1=t1,
                    t4=t4,
                    evidence=guest_evidence,
                )
            )

    def test_o0_guest_stage_requires_explicit_clean_not_applicable_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = Path(temporary)
            t0 = {"guestBefore": None}
            t1 = {"activeVm": None}
            t4 = {"guest": None}
            evidence = {
                "required": False,
                "validO4Evidence": False,
                "summaryConsistency": {},
            }
            self.assertTrue(
                runner.strict_o0_guest_stage_absence(
                    case_dir=case_dir,
                    t0=t0,
                    t1=t1,
                    t4=t4,
                    evidence=evidence,
                )
            )
            (case_dir / "guest-serial-final.log").mkdir()
            self.assertFalse(
                runner.strict_o0_guest_stage_absence(
                    case_dir=case_dir,
                    t0=t0,
                    t1=t1,
                    t4=t4,
                    evidence=evidence,
                )
            )

    def test_injection_boundary_records_fail_closed_on_shape_or_presence(
        self,
    ) -> None:
        valid = copy.deepcopy(
            evaluation_input("bit-or")["injections"][0]
        )
        rejected = copy.deepcopy(valid)
        rejected.update(
            {
                "accepted": False,
                "raw": "HMP command was not acknowledged\n",
            }
        )
        invalid_boundary = copy.deepcopy(valid)
        invalid_boundary["attempted"] = False
        invalid_boundary["mutationBoundaryCrossed"] = False
        cases = (
            ([], False, []),
            ([valid], True, []),
            ([rejected], False, []),
            (None, True, ["injections is not a list"]),
            ({}, True, ["injections is not a list"]),
            (
                [invalid_boundary],
                True,
                [
                    "injections[0].attempted is not true",
                    (
                        "injections[0].mutationBoundaryCrossed "
                        "is not true"
                    ),
                ],
            ),
        )
        for value, entered, expected_faults in cases:
            with self.subTest(value=value):
                self.assertIs(
                    runner.entered_injection_from_records(
                        value,
                        sequence="bit-or",
                        qemu_device="test_fn1",
                        outer_endpoint_bdf=OUTER_ENDPOINT_BDF,
                        outer_root_bdf=OUTER_ROOT_BDF,
                    ),
                    entered,
                )
                actual_faults = runner.injection_record_shape_faults(
                    value,
                    sequence="bit-or",
                    qemu_device="test_fn1",
                    outer_endpoint_bdf=OUTER_ENDPOINT_BDF,
                    outer_root_bdf=OUTER_ROOT_BDF,
                )
                self.assertTrue(set(expected_faults).issubset(actual_faults))
                if not expected_faults:
                    self.assertEqual([], actual_faults)
        self.assertFalse(
            runner.verified_entered_injection_from_records(
                [invalid_boundary],
                sequence="bit-or",
                qemu_device="test_fn1",
                outer_endpoint_bdf=OUTER_ENDPOINT_BDF,
                outer_root_bdf=OUTER_ROOT_BDF,
            )
        )

    def test_live_injection_boundary_is_false_before_ack_and_true_after_ack(
        self,
    ) -> None:
        args = SimpleNamespace(
            qemu_device="test_fn1",
            outer_endpoint_bdf="0000:01:00.1",
            outer_root_bdf="0000:00:01.0",
        )

        def new_recorder() -> runner.LiveSequenceRecorder:
            recorder = runner.LiveSequenceRecorder(
                args=args,
                case_dir=Path("."),
                monitor=Path("monitor.sock"),
                qtest_socket=Path("qtest.sock"),
                ssh=mock.Mock(),
                api=mock.Mock(),
                active_vm=None,
                requested_gate=runner.SUPPORTED_GATES["g101"],
                topology=outer(state()),
            )
            recorder.paused = True
            return recorder

        before_hmp = new_recorder()
        with (
            mock.patch.object(
                before_hmp,
                "record_pre_state",
                side_effect=RuntimeError("pre-HMP failure"),
            ),
            mock.patch.object(runner, "hmp_command") as dispatch,
        ):
            with self.assertRaisesRegex(RuntimeError, "pre-HMP"):
                before_hmp.inject("first-b0", runner.B0_NAME)
        dispatch.assert_not_called()
        self.assertEqual([], before_hmp.injections)
        self.assertFalse(
            runner.verified_entered_injection_from_records(
                before_hmp.injections,
                sequence="bit-or",
                qemu_device="test_fn1",
                outer_endpoint_bdf=args.outer_endpoint_bdf,
                outer_root_bdf=args.outer_root_bdf,
            )
        )

        before_ack = new_recorder()
        with (
            mock.patch.object(before_ack, "record_pre_state"),
            mock.patch.object(
                runner,
                "hmp_command",
                side_effect=RuntimeError("HMP readback failed"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "readback"):
                before_ack.inject("first-b0", runner.B0_NAME)
        self.assertEqual(1, len(before_ack.injections))
        self.assertFalse(before_ack.injections[0]["accepted"])
        self.assertEqual(
            [],
            runner.injection_record_shape_faults(
                before_ack.injections,
                sequence="bit-or",
                qemu_device="test_fn1",
                outer_endpoint_bdf=args.outer_endpoint_bdf,
                outer_root_bdf=args.outer_root_bdf,
            ),
        )
        self.assertFalse(
            runner.verified_entered_injection_from_records(
                before_ack.injections,
                sequence="bit-or",
                qemu_device="test_fn1",
                outer_endpoint_bdf=args.outer_endpoint_bdf,
                outer_root_bdf=args.outer_root_bdf,
            )
        )
        cleanup_decision = runner.derive_cleanup_containment_decision(
            recorder=before_ack,
            entered_injection=False,
            containment_required=False,
            containment_reasons=[],
            safety_latched=False,
        )
        self.assertEqual(
            {
                "unacknowledgedMutation": True,
                "containmentRequired": True,
                "containmentReasons": [
                    runner.UNACKNOWLEDGED_MUTATION_CONTAINMENT_REASON
                ],
                "safeStop": True,
            },
            cleanup_decision,
        )
        self.assertEqual(
            {
                "unacknowledgedMutation": True,
                "containmentRequired": True,
                "containmentReasons": [
                    "existing containment",
                    runner.UNACKNOWLEDGED_MUTATION_CONTAINMENT_REASON,
                ],
                "safeStop": True,
            },
            runner.derive_cleanup_containment_decision(
                recorder=before_ack,
                entered_injection=False,
                containment_required=True,
                containment_reasons=["existing containment"],
                safety_latched=False,
            ),
        )

        after_ack = new_recorder()
        with (
            mock.patch.object(after_ack, "record_pre_state"),
            mock.patch.object(
                runner,
                "hmp_command",
                return_value=VALID_HMP_ACK,
            ),
            mock.patch.object(
                after_ack,
                "capture",
                side_effect=RuntimeError("post-ACK capture failed"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "post-ACK"):
                after_ack.inject("first-b0", runner.B0_NAME)
        self.assertTrue(after_ack.injections[0]["accepted"])
        self.assertTrue(
            runner.verified_entered_injection_from_records(
                after_ack.injections,
                sequence="bit-or",
                qemu_device="test_fn1",
                outer_endpoint_bdf=args.outer_endpoint_bdf,
                outer_root_bdf=args.outer_root_bdf,
            )
        )
        self.assertFalse(
            runner.unacknowledged_mutation_requires_containment(
                after_ack,
                entered_injection=True,
            )
        )
        self.assertEqual(
            {
                "unacknowledgedMutation": False,
                "containmentRequired": False,
                "containmentReasons": [],
                "safeStop": False,
            },
            runner.derive_cleanup_containment_decision(
                recorder=after_ack,
                entered_injection=True,
                containment_required=False,
                containment_reasons=[],
                safety_latched=False,
            ),
        )

        ack_finalization = new_recorder()
        with (
            mock.patch.object(ack_finalization, "record_pre_state"),
            mock.patch.object(
                runner,
                "hmp_command",
                return_value=VALID_HMP_ACK,
            ),
            mock.patch.object(
                runner,
                "utc_now",
                side_effect=[
                    "2026-07-29T00:00:00.000000Z",
                    KeyboardInterrupt(),
                ],
            ),
            mock.patch.object(ack_finalization, "capture") as capture,
        ):
            with self.assertRaises(KeyboardInterrupt):
                ack_finalization.inject("first-b0", runner.B0_NAME)
        capture.assert_not_called()
        self.assertEqual(
            [],
            runner.injection_record_shape_faults(
                ack_finalization.injections,
                sequence="bit-or",
                qemu_device="test_fn1",
                outer_endpoint_bdf=args.outer_endpoint_bdf,
                outer_root_bdf=args.outer_root_bdf,
            ),
        )
        self.assertTrue(
            runner.verified_entered_injection_from_records(
                ack_finalization.injections,
                sequence="bit-or",
                qemu_device="test_fn1",
                outer_endpoint_bdf=args.outer_endpoint_bdf,
                outer_root_bdf=args.outer_root_bdf,
            )
        )

    def test_pre_hmp_o4_before_prefix_is_a_complete_offline_artifact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            case_id = "o4__bit-or__g101__r01"
            write_coherent_case(
                case_dir,
                profile_path,
                case_id=case_id,
            )

            case_spec = runner.load_json(case_dir / "case.json")
            case_spec["ownerPhase"] = "O4"
            case_spec["ownerContract"] = runner.OWNER_PHASES["O4"]
            runner.save_json(case_dir / "case.json", case_spec)
            run_manifest = runner.load_json(
                case_dir / "run-manifest.json"
            )
            run_manifest["ownerPhase"] = "O4"
            runner.save_json(
                case_dir / "run-manifest.json",
                run_manifest,
            )
            result = runner.load_json(case_dir / "result.json")
            result["case"] = copy.deepcopy(case_spec)
            runner.save_json(case_dir / "result.json", result)
            candidate = runner.load_json(
                case_dir / "evaluation-input.json"
            )
            candidate["ownerPhase"] = "O4"
            runner.save_json(
                case_dir / "evaluation-input.json",
                candidate,
            )

            t0 = runner.load_json(case_dir / "t0-baseline.json")
            t0["preflight"].update(
                {
                    "ownerBound": False,
                    "gatePausedReadback": False,
                    "evidenceProtocolReady": False,
                }
            )
            serial_dir = case_dir / "guest-serial"
            serial_dir.mkdir()
            before_text = "\n".join(
                [
                    (
                        "AER-OWNER phase=before-injection "
                        "bdf=0000:02:00.0 vendor=0x1af4 "
                        "device=0x1041 driver=virtio-pci"
                    ),
                    "AER-HEARTBEAT index=0 uptime=1.00 remaining=90",
                    "",
                ]
            )
            (serial_dir / "before-sequence.log").write_text(
                before_text,
                encoding="utf-8",
            )
            before_evidence = runner.parse_guest_owner_evidence(
                before_text,
                expected_vendor_id=0x1AF4,
                expected_device_id=0x1041,
            )
            required_seconds = float(
                self.profile["timingEnvelope"][
                    "minimumGuestWindowRemainingSecondsO4"
                ]
            )
            t0["guestBefore"] = {
                "artifact": "guest-serial/before-sequence.log",
                "ownerEvidence": before_evidence,
                "windowRemainingEvidence": {
                    "source": (
                        "latest guest AER-HEARTBEAT remaining"
                    ),
                    "publishedSeconds": 90,
                    "heartbeatIntervalAllowanceSeconds": 5,
                    "conservativeLowerBoundSeconds": 85,
                    "requiredSeconds": required_seconds,
                },
            }
            prior_t1 = runner.load_json(
                case_dir / "t1-effective-controls.json"
            )
            t1 = {
                "requestedGate": prior_t1["requestedGate"],
                "controlledBits": prior_t1["controlledBits"],
                "gateLease": None,
                "activeVm": {
                    "guestSerialArtifact": (
                        "guest-serial/before-sequence.log"
                    ),
                    "start": {
                        "vmName": "aer-prefix-fixture",
                        "vmid": "1794",
                        "remoteDirectory": "/vmfs/volumes/lab/prefix",
                        "remoteVmx": "/vmfs/volumes/lab/prefix/case.vmx",
                        "serial": "/vmfs/volumes/lab/prefix/serial.log",
                        "activeUsers": [
                            {
                                "backingIds": ["0000:01:00.1"],
                                "backingType": (
                                    "vim.vm.device.VirtualPCIPassthrough."
                                    "DeviceBackingInfo"
                                ),
                                "deviceKey": 13000,
                                "label": "PCI device 0",
                                "vm": "aer-prefix-fixture",
                                "vmMoId": "1794",
                            }
                        ],
                        "activeUserProbe": {
                            "mode": "ISOLATED_PROCESS",
                            "capturedAt": (
                                "2026-07-29T00:00:00.000000Z"
                            ),
                        },
                        "windowSeconds": 90,
                    },
                    "window": {
                        "windowSeconds": 90.0,
                        "elapsedSinceOpenObserved": 1.0,
                        "remainingSeconds": 89.0,
                        "requiredRemainingSeconds": required_seconds,
                    },
                },
                "remoteIsoSha256": None,
                "gateStable": False,
            }
            t2 = {"steps": []}
            t3 = {"injections": [], "snapshots": []}
            t4 = {
                "windows": [],
                "hostTerminalPhase": None,
                "hostProjection": None,
                "guest": None,
                "afterMarker": None,
                "afterMarkerVisibility": None,
                "logWindowCapture": None,
                "logWindow": None,
            }
            fault = {
                "type": "InconclusiveObservation",
                "message": "fixture failure before HMP dispatch",
            }
            t5 = {
                "operations": [],
                "gateRestore": None,
                "activeVmCleanup": None,
                "finalQemuState": "running",
                "containment": {
                    "required": False,
                    "reasons": [],
                    "observedSafetySideEffect": False,
                },
                "evaluationEvidence": {
                    "evidenceComplete": False,
                    "evidenceProtocolChecks": {},
                    "runtimeSafetyFaults": [],
                    "containmentRequired": False,
                    "containmentReasons": [],
                    "executionFault": fault,
                    "cleanupComplete": True,
                },
            }
            cleanup = {
                "startedAt": "2026-07-29T00:00:00.000000Z",
                "actions": [],
                "complete": True,
                "containmentRequired": False,
                "finishedAt": "2026-07-29T00:00:01.000000Z",
            }
            prefix_coverage = runner.build_safety_coverage(
                t0=t0,
                t1=t1,
                t2=t2,
                t3=t3,
                t4=t4,
                t5=t5,
                cleanup=cleanup,
            )
            prefix_protocol = runner.derive_raw_evidence_protocol(
                sequence=case_spec["sequence"],
                qemu_device=case_spec["qemuDevice"],
                outer_endpoint_bdf=OUTER_ENDPOINT_BDF,
                outer_root_bdf=OUTER_ROOT_BDF,
                owner_phase=case_spec["ownerPhase"],
                t0=t0,
                t1=t1,
                t2=t2,
                t3=t3,
                t4=t4,
                t5=t5,
                cleanup=cleanup,
                baseline_phase=t0["hostPhase"],
                terminal_phase=None,
                safety_coverage=prefix_coverage,
                bounded_log_window_complete=False,
            )
            t5["evaluationEvidence"]["evidenceComplete"] = (
                prefix_protocol["complete"]
            )
            t5["evaluationEvidence"]["evidenceProtocolChecks"] = (
                prefix_protocol["checks"]
            )
            for filename, value in (
                ("t0-baseline.json", t0),
                ("t1-effective-controls.json", t1),
                ("t2-pre-injection.json", t2),
                ("t3-immediate.json", t3),
                ("t4-window.json", t4),
                ("t5-transition-or-clear.json", t5),
                ("cleanup.json", cleanup),
            ):
                runner.save_json(case_dir / filename, value)
            shutil.rmtree(case_dir / "raw-esxi" / "log-window-v2")
            shutil.rmtree(case_dir / "raw-esxi" / "t4-terminal")
            runner.save_text(case_dir / "hmp.txt", "")

            synchronized = synchronize_evaluation_from_raw(
                case_dir,
                self.profile,
            )
            verification = runner.evaluate_case_directory(
                case_dir,
                profile_path,
            )
            self.assertFalse(synchronized["enteredInjection"])
            self.assertEqual(-1, synchronized["requesterId"])
            self.assertFalse(synchronized["o4GuestEvidenceValid"])
            self.assertEqual(
                "O4_GUEST_EVIDENCE_INCOMPLETE",
                synchronized["guestClassification"],
            )
            self.assertTrue(
                verification["rawConsistencyChecks"][
                    "host-log-raw-summary"
                ]
            )
            self.assertTrue(
                verification["rawConsistencyChecks"][
                    "o4-guest-raw-summary"
                ]
            )
            self.assertTrue(verification["rawSourceExactMatch"])
            self.assertTrue(verification["resultExactMatch"])
            self.assertTrue(verification["exactMatch"])

            raw_sources = runner.reconstruct_evaluation_sources(
                case_dir,
                self.profile,
            )
            stored_t0 = runner.load_json(
                case_dir / "t0-baseline.json"
            )
            stored_t1 = runner.load_json(
                case_dir / "t1-effective-controls.json"
            )
            stored_t4 = runner.load_json(case_dir / "t4-window.json")
            stored_t5 = runner.load_json(
                case_dir / "t5-transition-or-clear.json"
            )
            rogue_log_namespace = (
                case_dir / "raw-esxi" / "log-window-shadow"
            )
            rogue_log_namespace.mkdir()
            self.assertFalse(
                runner.exact_nonentered_log_stage_summary(
                    case_dir=case_dir,
                    case_protocol=case_spec["logWindowProtocol"],
                    t0=stored_t0,
                    t4=stored_t4,
                    evidence=raw_sources["logWindowEvidence"],
                )
            )
            shutil.rmtree(rogue_log_namespace)
            log_nested_variants = {
                "inventory": lambda value: value[
                    "logWindowPreflightInventory"
                ].update({"behaviorAuthority": "FORGED"}),
                "marker-write": lambda value: value[
                    "beforeMarker"
                ].update({"behaviorAuthority": "FORGED"}),
                "marker-visibility": lambda value: value[
                    "beforeMarkerVisibility"
                ].update({"behaviorAuthority": "FORGED"}),
            }
            for variant, mutate in log_nested_variants.items():
                with self.subTest(log_nested_variant=variant):
                    local_t0 = copy.deepcopy(stored_t0)
                    mutate(local_t0)
                    self.assertFalse(
                        runner.exact_nonentered_log_stage_summary(
                            case_dir=case_dir,
                            case_protocol=case_spec[
                                "logWindowProtocol"
                            ],
                            t0=local_t0,
                            t4=stored_t4,
                            evidence=raw_sources[
                                "logWindowEvidence"
                            ],
                        )
                    )
            nested_variants = {
                "guest-before": lambda t0, _t1: t0[
                    "guestBefore"
                ].update({"behaviorAuthority": "FORGED"}),
                "active-vm": lambda _t0, t1: t1["activeVm"].update(
                    {"behaviorAuthority": "FORGED"}
                ),
                "active-vm-start": lambda _t0, t1: t1["activeVm"][
                    "start"
                ].update({"behaviorAuthority": "FORGED"}),
                "active-vm-window": lambda _t0, t1: t1["activeVm"][
                    "window"
                ].update({"behaviorAuthority": "FORGED"}),
                "active-user-probe": lambda _t0, t1: t1["activeVm"][
                    "start"
                ]["activeUserProbe"].update(
                    {"behaviorAuthority": "FORGED"}
                ),
                "active-user": lambda _t0, t1: t1["activeVm"][
                    "start"
                ]["activeUsers"][0].update(
                    {"behaviorAuthority": "FORGED"}
                ),
            }
            for variant, mutate in nested_variants.items():
                with self.subTest(nested_variant=variant):
                    local_t0 = copy.deepcopy(stored_t0)
                    local_t1 = copy.deepcopy(stored_t1)
                    mutate(local_t0, local_t1)
                    self.assertFalse(
                        runner.exact_nonentered_o4_guest_stage_summary(
                            case_dir=case_dir,
                            t0=local_t0,
                            t1=local_t1,
                            t4=stored_t4,
                            t5=stored_t5,
                            evidence=raw_sources[
                                "guestSerialEvidence"
                            ],
                        )
                    )

            cleanup_serial_path = (
                case_dir / "guest-serial-final.log"
            )
            cleanup_serial_path.write_bytes(
                (
                    case_dir
                    / "guest-serial"
                    / "before-sequence.log"
                ).read_bytes()
                + (
                    b"AER-HEARTBEAT index=1 "
                    b"uptime=6.00 remaining=85\n"
                )
            )
            valid_cleanup_t5 = copy.deepcopy(stored_t5)
            valid_cleanup_t5["activeVmCleanup"] = {
                "actions": [
                    {
                        "copy": "serial.log",
                        "destination": "guest-serial-final.log",
                        "success": True,
                    }
                ]
            }
            self.assertTrue(
                runner.exact_nonentered_o4_guest_stage_summary(
                    case_dir=case_dir,
                    t0=stored_t0,
                    t1=stored_t1,
                    t4=stored_t4,
                    t5=valid_cleanup_t5,
                    evidence=raw_sources["guestSerialEvidence"],
                )
            )

            wrong_copy_t5 = copy.deepcopy(valid_cleanup_t5)
            wrong_copy_t5["activeVmCleanup"]["actions"][0][
                "copy"
            ] = "foreign-serial.log"
            self.assertFalse(
                runner.exact_nonentered_o4_guest_stage_summary(
                    case_dir=case_dir,
                    t0=stored_t0,
                    t1=stored_t1,
                    t4=stored_t4,
                    t5=wrong_copy_t5,
                    evidence=raw_sources["guestSerialEvidence"],
                )
            )

            wrong_source_t1 = copy.deepcopy(stored_t1)
            wrong_source_t1["activeVm"]["start"]["serial"] = (
                "/attacker/source/serial.log"
            )
            self.assertFalse(
                runner.exact_nonentered_o4_guest_stage_summary(
                    case_dir=case_dir,
                    t0=stored_t0,
                    t1=wrong_source_t1,
                    t4=stored_t4,
                    t5=valid_cleanup_t5,
                    evidence=raw_sources["guestSerialEvidence"],
                )
            )

            extra_copy_t5 = copy.deepcopy(valid_cleanup_t5)
            extra_copy_t5["activeVmCleanup"]["actions"].append(
                {
                    "copy": "foreign-serial.log",
                    "destination": "guest-serial-final.log ",
                    "success": True,
                }
            )
            self.assertFalse(
                runner.exact_nonentered_o4_guest_stage_summary(
                    case_dir=case_dir,
                    t0=stored_t0,
                    t1=stored_t1,
                    t4=stored_t4,
                    t5=extra_copy_t5,
                    evidence=raw_sources["guestSerialEvidence"],
                )
            )

            before_bytes = (
                case_dir
                / "guest-serial"
                / "before-sequence.log"
            ).read_bytes()
            crlf_before_path = case_dir / "crlf-before.log"
            crlf_final_path = case_dir / "crlf-final.log"
            crlf_before_path.write_bytes(
                before_bytes.replace(b"\n", b"\r\n")
            )
            crlf_final_path.write_bytes(
                crlf_before_path.read_bytes()
                + (
                    b"AER-HEARTBEAT index=1 "
                    b"uptime=6.00 remaining=85\r\n"
                )
            )
            self.assertTrue(
                runner.exact_guest_heartbeat_append(
                    before_path=crlf_before_path,
                    final_path=crlf_final_path,
                )
            )
            crlf_final_path.write_bytes(
                crlf_before_path.read_bytes()
                + (
                    b"AER-HEARTBEAT index=1 "
                    b"uptime=6.00 remaining=85\n"
                )
            )
            self.assertFalse(
                runner.exact_guest_heartbeat_append(
                    before_path=crlf_before_path,
                    final_path=crlf_final_path,
                )
            )
            crlf_before_path.unlink()
            crlf_final_path.unlink()
            invalid_suffixes = (
                b"FORGED\n",
                (
                    b"AER-HEARTBEAT index=2 "
                    b"uptime=6.00 remaining=85\n"
                ),
                (
                    b"AER-HEARTBEAT index=1 "
                    b"uptime=6.00 remaining=84\n"
                ),
                (
                    b"AER-HEARTBEAT index=0001 "
                    b"uptime=000006 remaining=0085\n"
                ),
                b"\xff\n",
            )
            for suffix in invalid_suffixes:
                with self.subTest(cleanup_suffix=suffix):
                    cleanup_serial_path.write_bytes(
                        before_bytes + suffix
                    )
                    self.assertFalse(
                        runner.exact_nonentered_o4_guest_stage_summary(
                            case_dir=case_dir,
                            t0=stored_t0,
                            t1=stored_t1,
                            t4=stored_t4,
                            t5=valid_cleanup_t5,
                            evidence=raw_sources[
                                "guestSerialEvidence"
                            ],
                        )
                    )

            stored_t0["guestBefore"]["behaviorAuthority"] = "FORGED"
            runner.save_json(case_dir / "t0-baseline.json", stored_t0)
            synchronize_evaluation_from_raw(case_dir, self.profile)
            forged_nested = runner.evaluate_case_directory(
                case_dir,
                profile_path,
            )
            self.assertFalse(
                forged_nested["rawConsistencyChecks"][
                    "o4-guest-raw-summary"
                ]
            )
            self.assertFalse(forged_nested["rawSourceExactMatch"])
            self.assertFalse(forged_nested["exactMatch"])

            del stored_t0["guestBefore"]["behaviorAuthority"]
            runner.save_json(case_dir / "t0-baseline.json", stored_t0)
            (case_dir / "guest-serial-final.log").write_text(
                "unbound terminal guest evidence\n",
                encoding="utf-8",
            )
            synchronize_evaluation_from_raw(case_dir, self.profile)
            unbound_cleanup_serial = runner.evaluate_case_directory(
                case_dir,
                profile_path,
            )
            self.assertFalse(
                unbound_cleanup_serial["rawConsistencyChecks"][
                    "o4-guest-raw-summary"
                ]
            )
            self.assertFalse(unbound_cleanup_serial["rawSourceExactMatch"])
            self.assertFalse(unbound_cleanup_serial["exactMatch"])

    def test_complete_raw_window_cannot_be_downgraded_to_no_injection(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            write_coherent_case(case_dir, profile_path)
            t3_path = case_dir / "t3-immediate.json"
            t3 = runner.load_json(t3_path)
            t3["injections"] = []
            runner.save_json(t3_path, t3)
            evaluation_path = case_dir / "evaluation-input.json"
            evaluation = runner.load_json(evaluation_path)
            evaluation["injections"] = []
            evaluation["enteredInjection"] = False
            runner.save_json(evaluation_path, evaluation)
            runner.write_artifact_manifest(case_dir)

            verification = runner.evaluate_case_directory(
                case_dir,
                profile_path,
            )
            self.assertFalse(
                verification["rawConsistencyChecks"][
                    "host-log-raw-summary"
                ]
            )
            self.assertFalse(verification["rawSourceExactMatch"])
            self.assertFalse(verification["exactMatch"])

    def test_phase_and_injection_container_shapes_are_not_normalized(
        self,
    ) -> None:
        variants = (
            ("t2-pre-injection.json", "steps"),
            ("t3-immediate.json", "snapshots"),
            ("t4-window.json", "windows"),
            ("t5-transition-or-clear.json", "operations"),
            ("t3-immediate.json", "injections"),
        )
        for filename, key in variants:
            with self.subTest(filename=filename, key=key):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    profile_path = root / "oracle-profile.json"
                    runner.save_json(profile_path, self.profile)
                    case_dir = root / "case"
                    write_coherent_case(case_dir, profile_path)
                    path = case_dir / filename
                    value = runner.load_json(path)
                    value[key] = None
                    runner.save_json(path, value)
                    rebuilt = runner.reconstruct_evaluation_sources(
                        case_dir,
                        self.profile,
                    )
                    self.assertTrue(rebuilt["recordShapeFaults"])
                    self.assertFalse(rebuilt["evidenceComplete"])

    def test_unknown_phase_items_cannot_preserve_exact_match(self) -> None:
        variants = (
            ("t2-pre-injection.json", "steps"),
            ("t3-immediate.json", "snapshots"),
            ("t4-window.json", "windows"),
            ("t5-transition-or-clear.json", "operations"),
        )
        for filename, key in variants:
            with self.subTest(filename=filename, key=key):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    profile_path = root / "oracle-profile.json"
                    runner.save_json(profile_path, self.profile)
                    case_dir = root / "case"
                    write_coherent_case(case_dir, profile_path)
                    path = case_dir / filename
                    value = runner.load_json(path)
                    value[key].append({})
                    runner.save_json(path, value)
                    runner.write_artifact_manifest(case_dir)
                    verification = runner.evaluate_case_directory(
                        case_dir,
                        profile_path,
                    )
                    self.assertFalse(
                        verification["rawConsistencyChecks"][
                            "phase-and-injection-records-valid"
                        ]
                    )
                    self.assertFalse(verification["rawSourceExactMatch"])
                    self.assertFalse(verification["exactMatch"])

    def test_phase_artifact_roots_reject_unknown_authority_fields(self) -> None:
        filenames = (
            "t0-baseline.json",
            "t1-effective-controls.json",
            "t2-pre-injection.json",
            "t3-immediate.json",
            "t4-window.json",
            "t5-transition-or-clear.json",
            "cleanup.json",
        )
        for filename in filenames:
            with self.subTest(filename=filename):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    profile_path = root / "oracle-profile.json"
                    runner.save_json(profile_path, self.profile)
                    case_dir = root / "case"
                    write_coherent_case(case_dir, profile_path)
                    path = case_dir / filename
                    value = runner.load_json(path)
                    value["behaviorAuthority"] = "FORGED"
                    runner.save_json(path, value)
                    runner.write_artifact_manifest(case_dir)
                    verification = runner.evaluate_case_directory(
                        case_dir,
                        profile_path,
                    )
                    self.assertFalse(
                        verification["rawConsistencyChecks"][
                            "phase-and-injection-records-valid"
                        ]
                    )
                    self.assertFalse(verification["exactMatch"])

    def test_allowed_optional_phase_fields_reject_forged_authority(
        self,
    ) -> None:
        variants = {
            "t0-kernel-preconditions": (
                "t0-baseline.json",
                lambda value: value["kernelPreconditions"].update(
                    {"behaviorAuthority": "FORGED"}
                ),
            ),
            "t1-startup-pause": (
                "t1-effective-controls.json",
                lambda value: value.__setitem__(
                    "activeVmStartupPause",
                    {"behaviorAuthority": "FORGED"},
                ),
            ),
            "t4-log-window-fault": (
                "t4-window.json",
                lambda value: value.__setitem__(
                    "logWindowDerivationFault",
                    {"behaviorAuthority": "FORGED"},
                ),
            ),
            "t5-emergency-hold-fault": (
                "t5-transition-or-clear.json",
                lambda value: value.__setitem__(
                    "emergencyHoldFault",
                    {"behaviorAuthority": "FORGED"},
                ),
            ),
        }
        for variant, (filename, mutate) in variants.items():
            with self.subTest(variant=variant):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    profile_path = root / "oracle-profile.json"
                    runner.save_json(profile_path, self.profile)
                    case_dir = root / "case"
                    write_coherent_case(case_dir, profile_path)
                    path = case_dir / filename
                    value = runner.load_json(path)
                    mutate(value)
                    runner.save_json(path, value)
                    synchronize_evaluation_from_raw(
                        case_dir,
                        self.profile,
                    )
                    verification = runner.evaluate_case_directory(
                        case_dir,
                        profile_path,
                    )
                    self.assertFalse(
                        verification["rawConsistencyChecks"][
                            "phase-and-injection-records-valid"
                        ]
                    )
                    self.assertFalse(verification["exactMatch"])

    def test_unenforced_monitored_gate_uses_the_exact_producer_branch(
        self,
    ) -> None:
        record = raw_monitored_window(
            "pre-sequence-evidence-collection",
            "fixture pre-gate worker",
            boundary="PRE_INJECTION",
            enforce_gate=False,
        )
        self.assertEqual(
            [],
            runner.runnable_window_record_shape_faults(
                record,
                phase="t0",
                expected_gate="g101",
            ),
        )
        self.assertIsNone(record["samples"][0]["gate"]["requested"])
        self.assertEqual(
            {
                "not-enforced-during-pre-sequence-owner-activation": True,
            },
            record["samples"][0]["gate"]["checks"],
        )
        forged = copy.deepcopy(record)
        forged["samples"][0]["gate"] = raw_gate_evidence(state())
        self.assertTrue(
            runner.runnable_window_record_shape_faults(
                forged,
                phase="t0",
                expected_gate="g101",
            )
        )

    def test_imported_transition_utc_offset_is_a_closed_timestamp(
        self,
    ) -> None:
        with mock.patch.object(
            runner.esxi_aer,
            "hmp_command",
            side_effect=["", "VM status: paused"],
        ):
            transition = runner.esxi_aer.transition_qemu(
                Path("monitor.sock"),
                "stop",
                "paused",
            )
        self.assertTrue(transition["observedAt"].endswith("+00:00"))
        self.assertEqual(
            [],
            runner.direct_transition_record_shape_faults(
                transition,
                expected_command="stop",
                expected_status="paused",
            ),
        )
        non_utc = copy.deepcopy(transition)
        non_utc["observedAt"] = "2026-07-29T00:00:00+01:00"
        self.assertTrue(
            runner.direct_transition_record_shape_faults(
                non_utc,
                expected_command="stop",
                expected_status="paused",
            )
        )

    def test_incomplete_cleanup_cannot_hide_forged_branch_faults(
        self,
    ) -> None:
        fault_fields = (
            "emergencyHoldFault",
            "gateRestoreFault",
            "finalQemuStateFault",
            "containmentHoldFault",
        )
        for field_name in fault_fields:
            with self.subTest(field_name=field_name):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    profile_path = root / "oracle-profile.json"
                    runner.save_json(profile_path, self.profile)
                    case_dir = root / "case"
                    write_coherent_case(case_dir, profile_path)
                    cleanup_path = case_dir / "cleanup.json"
                    cleanup = runner.load_json(cleanup_path)
                    cleanup["complete"] = False
                    runner.save_json(cleanup_path, cleanup)
                    t5_path = case_dir / "t5-transition-or-clear.json"
                    t5 = runner.load_json(t5_path)
                    t5[field_name] = {"behaviorAuthority": "FORGED"}
                    runner.save_json(t5_path, t5)
                    synchronize_evaluation_from_raw(
                        case_dir,
                        self.profile,
                    )
                    verification = runner.evaluate_case_directory(
                        case_dir,
                        profile_path,
                    )
                    self.assertFalse(
                        verification["rawConsistencyChecks"][
                            "phase-and-injection-records-valid"
                        ]
                    )
                    self.assertFalse(verification["rawSourceExactMatch"])
                    self.assertFalse(verification["exactMatch"])

    def test_cleanup_and_evaluation_ledgers_fail_closed_after_resign(
        self,
    ) -> None:
        variants = {
            "cleanup-containment-mismatch": (
                lambda cleanup, _t5: cleanup.__setitem__(
                    "containmentRequired",
                    True,
                )
            ),
            "cleanup-containment-type": (
                lambda cleanup, _t5: cleanup.__setitem__(
                    "containmentRequired",
                    "false",
                )
            ),
            "cleanup-actions-not-list": (
                lambda cleanup, _t5: cleanup.__setitem__(
                    "actions",
                    "RESTORED",
                )
            ),
            "cleanup-actions-unknown": (
                lambda cleanup, _t5: cleanup["actions"].append(
                    {"behaviorAuthority": "FORGED"}
                )
            ),
            "cleanup-gate-ledger-drift": (
                lambda cleanup, _t5: cleanup.__setitem__(
                    "actions",
                    [
                        {
                            "gateRestore": "RESTORE_FAILED",
                            "safeStop": True,
                        }
                    ],
                )
            ),
            "cleanup-started-at-invalid": (
                lambda cleanup, _t5: cleanup.__setitem__(
                    "startedAt",
                    "FORGED",
                )
            ),
            "cleanup-finished-at-null": (
                lambda cleanup, _t5: cleanup.__setitem__(
                    "finishedAt",
                    None,
                )
            ),
            "cleanup-time-reversed": (
                lambda cleanup, _t5: cleanup.update(
                    {
                        "startedAt": "2026-07-29T00:00:02.000000Z",
                        "finishedAt": "2026-07-29T00:00:01.000000Z",
                    }
                )
            ),
            "gate-restore-before-cleanup": (
                lambda _cleanup, t5: t5["gateRestore"].update(
                    {
                        "startedAt": "2026-07-28T00:00:00.100000Z",
                        "finishedAt": "2026-07-28T00:00:00.900000Z",
                    }
                )
            ),
            "gate-restore-after-cleanup": (
                lambda _cleanup, t5: t5["gateRestore"].update(
                    {
                        "startedAt": "2026-07-30T00:00:00.100000Z",
                        "finishedAt": "2026-07-30T00:00:00.900000Z",
                    }
                )
            ),
            "o0-active-cleanup-error": (
                lambda _cleanup, t5: t5.__setitem__(
                    "activeVmCleanup",
                    {"error": "forged cleanup failure"},
                )
            ),
            "containment-extra-field": (
                lambda _cleanup, t5: t5["containment"].update(
                    {"behaviorAuthority": "FORGED"}
                )
            ),
            "evaluation-extra-field": (
                lambda _cleanup, t5: t5["evaluationEvidence"].update(
                    {"behaviorAuthority": "FORGED"}
                )
            ),
            "evaluation-cleanup-drift": (
                lambda _cleanup, t5: t5["evaluationEvidence"].__setitem__(
                    "cleanupComplete",
                    False,
                )
            ),
            "evaluation-protocol-drift": (
                lambda _cleanup, t5: t5["evaluationEvidence"][
                    "evidenceProtocolChecks"
                ].__setitem__(
                    "cleanup-complete",
                    False,
                )
            ),
            "evaluation-forged-safety-fault": (
                lambda _cleanup, t5: t5["evaluationEvidence"].__setitem__(
                    "executionFault",
                    {
                        "type": "SafetyViolation",
                        "message": "forged cleanup safety failure",
                    },
                )
            ),
            "evaluation-runtime-safety-shape": (
                lambda _cleanup, t5: t5["evaluationEvidence"].__setitem__(
                    "runtimeSafetyFaults",
                    [{"behaviorAuthority": "FORGED"}],
                )
            ),
        }
        for variant, mutate in variants.items():
            with self.subTest(variant=variant):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    profile_path = root / "oracle-profile.json"
                    runner.save_json(profile_path, self.profile)
                    case_dir = root / "case"
                    write_coherent_case(case_dir, profile_path)
                    cleanup_path = case_dir / "cleanup.json"
                    t5_path = case_dir / "t5-transition-or-clear.json"
                    cleanup = runner.load_json(cleanup_path)
                    t5 = runner.load_json(t5_path)
                    mutate(cleanup, t5)
                    runner.save_json(cleanup_path, cleanup)
                    runner.save_json(t5_path, t5)
                    synchronize_evaluation_from_raw(
                        case_dir,
                        self.profile,
                    )
                    verification = runner.evaluate_case_directory(
                        case_dir,
                        profile_path,
                    )
                    self.assertFalse(
                        verification["rawConsistencyChecks"][
                            "phase-and-injection-records-valid"
                        ]
                    )
                    self.assertFalse(verification["rawSourceExactMatch"])
                    self.assertFalse(verification["exactMatch"])

    def test_registered_active_vm_cleanup_requires_unregister_result(
        self,
    ) -> None:
        cleanup = {
            "startedAt": "2026-07-29T00:00:00.000000Z",
            "actions": [
                {
                    "output": "Powering off VM:",
                    "powerOffReturnCode": 0,
                }
            ],
            "remainingActiveUsers": [],
            "activeUserProbes": [
                {
                    "mode": "ISOLATED_PROCESS",
                    "capturedAt": "2026-07-29T00:00:01.000000Z",
                }
            ],
            "finishedAt": "2026-07-29T00:00:02.000000Z",
        }
        checks = runner.active_vm_cleanup_checks(
            cleanup,
            expected_registered=True,
        )
        self.assertFalse(checks["critical-return-codes-zero"])
        cleanup["actions"].append({"unregisterReturnCode": 0})
        checks = runner.active_vm_cleanup_checks(
            cleanup,
            expected_registered=True,
        )
        self.assertTrue(checks["critical-return-codes-zero"])
        cleanup["activeUserProbes"] = []
        self.assertTrue(
            any(
                "no active-user probe" in fault
                for fault in runner.active_vm_cleanup_record_faults(
                    cleanup,
                    active_vm=None,
                )
            )
        )
        cleanup["activeUserProbes"] = [
            {
                "mode": "ISOLATED_PROCESS",
                "capturedAt": "2026-07-29T00:00:01.000000Z",
            }
        ]
        active_vm = {
            "start": {
                "remoteDirectory": "/vmfs/volumes/lab/case",
                "serial": "/vmfs/volumes/lab/case/serial.log",
                "remoteVmx": "/vmfs/volumes/lab/case/case.vmx",
            }
        }
        self.assertTrue(
            any(
                "exact frozen copies" in fault
                for fault in runner.active_vm_cleanup_record_faults(
                    cleanup,
                    active_vm=active_vm,
                )
            )
        )

    def test_incomplete_optional_monitor_fields_are_rebuilt_and_closed(
        self,
    ) -> None:
        variants = {
            "nested-sample-authority": lambda t0: t0[
                "preSequenceSafetyWindows"
            ][0]["samples"][0].update(
                {"behaviorAuthority": "FORGED"}
            ),
            "summary-drift": lambda t0: t0[
                "preSequenceSafetyMonitor"
            ].__setitem__(
                "sampleCount",
                t0["preSequenceSafetyMonitor"]["sampleCount"] + 1,
            ),
        }
        for variant, mutate in variants.items():
            with self.subTest(variant=variant):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    profile_path = root / "oracle-profile.json"
                    runner.save_json(profile_path, self.profile)
                    case_dir = root / "case"
                    write_coherent_case(case_dir, profile_path)
                    cleanup_path = case_dir / "cleanup.json"
                    cleanup = runner.load_json(cleanup_path)
                    cleanup["complete"] = False
                    runner.save_json(cleanup_path, cleanup)
                    t0_path = case_dir / "t0-baseline.json"
                    t0 = runner.load_json(t0_path)
                    mutate(t0)
                    runner.save_json(t0_path, t0)
                    synchronize_evaluation_from_raw(
                        case_dir,
                        self.profile,
                    )
                    verification = runner.evaluate_case_directory(
                        case_dir,
                        profile_path,
                    )
                    self.assertFalse(
                        verification["rawConsistencyChecks"][
                            "phase-and-injection-records-valid"
                        ]
                    )
                    self.assertFalse(verification["exactMatch"])

    def test_optional_live_routes_match_emitted_record_shapes(self) -> None:
        for phase, boundary, enforce_gate in (
            ("t0", "PRE_INJECTION", False),
            ("t1", "PRE_INJECTION", False),
            ("t4", "ATTRIBUTION_WINDOW", True),
            ("t5", "POST_CLEANUP", False),
        ):
            with self.subTest(phase=phase):
                record = raw_monitored_window(
                    f"fixture-{phase}",
                    f"fixture monitored route for {phase}",
                    boundary=boundary,
                    enforce_gate=enforce_gate,
                )
                self.assertEqual(
                    [],
                    runner.runnable_window_record_shape_faults(
                        record,
                        phase=phase,
                    ),
                )
        cleanup_baseline = {
            "safetyBoundary": "POST_CLEANUP",
            "snapshot": outer(state()),
            "safetyFaults": [],
            "partial": False,
        }
        self.assertEqual(
            [],
            runner.optional_phase_field_faults(
                t0={},
                t1={},
                t4={},
                t5={
                    "activeVmCleanupPausedBaseline": cleanup_baseline,
                    "gateRestoreFault": {
                        "type": "FixtureFault",
                        "message": "closed failure branch",
                    },
                },
            ),
        )

    def test_malformed_nested_phase_values_fail_closed_without_crash(
        self,
    ) -> None:
        variants = {
            "t0-window-null-record": (
                "t0-baseline.json",
                lambda value: value.__setitem__(
                    "preSequenceSafetyWindows",
                    [None],
                ),
            ),
            "t0-baseline-null-snapshot": (
                "t0-baseline.json",
                lambda value: value[
                    "postBaselineClearPausedReadback"
                ].__setitem__("snapshot", None),
            ),
            "t1-null-startup-pause": (
                "t1-effective-controls.json",
                lambda value: value.__setitem__(
                    "activeVmStartupPause",
                    None,
                ),
            ),
            "t4-null-service-poll": (
                "t4-window.json",
                lambda value: value["windows"][0].__setitem__(
                    "safetyPoll",
                    None,
                ),
            ),
            "t4-scalar-monitored-samples": (
                "t4-window.json",
                lambda value: value["windows"][-1].__setitem__(
                    "samples",
                    1,
                ),
            ),
            "t5-null-final-baseline": (
                "t5-transition-or-clear.json",
                lambda value: value.__setitem__(
                    "finalSafetyTailPausedBaseline",
                    None,
                ),
            ),
            "t5-null-hold": (
                "t5-transition-or-clear.json",
                lambda value: value.__setitem__(
                    "emergencyHold",
                    None,
                ),
            ),
            "t5-null-cleanup-window-record": (
                "t5-transition-or-clear.json",
                lambda value: value.__setitem__(
                    "activeVmCleanupSafetyWindows",
                    [None],
                ),
            ),
            "t5-null-branch-fault": (
                "t5-transition-or-clear.json",
                lambda value: value.__setitem__(
                    "gateRestoreFault",
                    None,
                ),
            ),
        }
        for variant, (filename, mutate) in variants.items():
            with self.subTest(variant=variant):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    profile_path = root / "oracle-profile.json"
                    runner.save_json(profile_path, self.profile)
                    case_dir = root / "case"
                    write_coherent_case(case_dir, profile_path)
                    path = case_dir / filename
                    value = runner.load_json(path)
                    mutate(value)
                    runner.save_json(path, value)
                    runner.write_artifact_manifest(case_dir)
                    verification = runner.evaluate_case_directory(
                        case_dir,
                        profile_path,
                    )
                    self.assertFalse(
                        verification["rawConsistencyChecks"][
                            "phase-and-injection-records-valid"
                        ]
                    )
                    self.assertFalse(verification["exactMatch"])

    def test_non_object_phase_roots_are_rejected_at_parse_boundary(
        self,
    ) -> None:
        filenames = (
            "t0-baseline.json",
            "t1-effective-controls.json",
            "t2-pre-injection.json",
            "t3-immediate.json",
            "t4-window.json",
            "t5-transition-or-clear.json",
            "cleanup.json",
        )
        for filename in filenames:
            with self.subTest(filename=filename):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    profile_path = root / "oracle-profile.json"
                    runner.save_json(profile_path, self.profile)
                    case_dir = root / "case"
                    write_coherent_case(case_dir, profile_path)
                    runner.save_json(case_dir / filename, [])
                    runner.write_artifact_manifest(case_dir)
                    with self.assertRaisesRegex(
                        ValueError,
                        "JSON root must be an object",
                    ):
                        runner.evaluate_case_directory(
                            case_dir,
                            profile_path,
                        )

    def test_non_object_authority_roots_fail_closed(self) -> None:
        variants = {
            "case": "case.json",
            "evaluationInput": "evaluation-input.json",
            "result": "result.json",
            "oracle": "oracle.json",
        }
        for variant, filename in variants.items():
            with self.subTest(variant=variant):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    profile_path = root / "oracle-profile.json"
                    runner.save_json(profile_path, self.profile)
                    case_dir = root / "case"
                    write_coherent_case(case_dir, profile_path)
                    runner.save_json(case_dir / filename, [])
                    runner.write_artifact_manifest(case_dir)
                    with self.assertRaisesRegex(
                        ValueError,
                        "JSON root must be an object",
                    ):
                        runner.evaluate_case_directory(
                            case_dir,
                            profile_path,
                        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            write_coherent_case(case_dir, profile_path)
            runner.save_json(case_dir / "run-manifest.json", [])
            runner.write_artifact_manifest(case_dir)
            with self.assertRaisesRegex(
                ValueError,
                "JSON root must be an object",
            ):
                runner.evaluate_case_directory(
                    case_dir,
                    profile_path,
                )

    def test_sequence_record_route_and_order_cannot_be_resigned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            write_coherent_case(case_dir, profile_path)
            t3_path = case_dir / "t3-immediate.json"
            t4_path = case_dir / "t4-window.json"
            t3 = runner.load_json(t3_path)
            t4 = runner.load_json(t4_path)
            first_b0 = next(
                item
                for item in t3["snapshots"]
                if item["label"] == "first-b0"
            )
            t3["snapshots"].remove(first_b0)
            first_b0["phase"] = "t4"
            t4["windows"].insert(0, first_b0)
            runner.save_json(t3_path, t3)
            runner.save_json(t4_path, t4)
            synchronize_evaluation_from_raw(
                case_dir,
                self.profile,
            )
            verification = runner.evaluate_case_directory(
                case_dir,
                profile_path,
            )
            self.assertFalse(
                verification["rawConsistencyChecks"][
                    "phase-and-injection-records-valid"
                ]
            )
            self.assertFalse(verification["exactMatch"])

    def test_live_sequence_dispatch_matches_the_closed_action_plan(
        self,
    ) -> None:
        class TraceRecorder:
            def __init__(self) -> None:
                self.calls: list[dict[str, Any]] = []

            def inject(self, label: str, bit: str) -> None:
                self.calls.append(
                    {"kind": "inject", "label": label, "bit": bit}
                )

            def service_window(
                self,
                label: str,
                description: str,
            ) -> None:
                self.calls.append(
                    {
                        "kind": "service",
                        "label": label,
                        "description": description,
                    }
                )

            def clear(
                self,
                label: str,
                *,
                operations: tuple[str, ...],
                public_description: str,
            ) -> None:
                self.calls.append(
                    {
                        "kind": "clear",
                        "label": label,
                        "description": public_description,
                    }
                )

        for sequence, specifications in (
            runner.SEQUENCE_ACTION_SPECS.items()
        ):
            with self.subTest(sequence=sequence):
                recorder = TraceRecorder()
                terminal = runner.execute_sequence_until_terminal(
                    sequence,
                    recorder,  # type: ignore[arg-type]
                )
                expected = [
                    {
                        "kind": item["kind"],
                        "label": item["label"],
                        **(
                            {"bit": item["bit"]}
                            if item["kind"] == "inject"
                            else {
                                "description": (
                                    item["description"]
                                    if item["kind"] == "service"
                                    else item["operation"]
                                )
                            }
                        ),
                    }
                    for item in specifications
                ]
                self.assertEqual(expected, recorder.calls)
                self.assertEqual(
                    next(
                        item["label"]
                        for item in reversed(specifications)
                        if item["kind"] == "service"
                    ),
                    terminal,
                )

    def test_t4_nested_records_use_closed_raw_schemas(self) -> None:
        variants = {
            "service-resume": lambda t4: t4["windows"][0]["resume"].update(
                {"behaviorAuthority": "FORGED"}
            ),
            "service-poll": lambda t4: t4["windows"][0][
                "safetyPoll"
            ].update({"behaviorAuthority": "FORGED"}),
            "service-timeline": lambda t4: t4["windows"][0][
                "timeline"
            ][0].update({"behaviorAuthority": "FORGED"}),
            "paused-snapshot": lambda t4: t4["windows"][1][
                "snapshot"
            ].update({"behaviorAuthority": "FORGED"}),
            "paused-gate": lambda t4: t4["windows"][1]["gate"].update(
                {"behaviorAuthority": "FORGED"}
            ),
            "monitored-sample": lambda t4: t4["windows"][-1][
                "samples"
            ][0].update({"behaviorAuthority": "FORGED"}),
            "monitored-null-sample": lambda t4: t4["windows"][-1].update(
                {"samples": [None], "sampleCount": 1}
            ),
        }
        for variant, mutate in variants.items():
            with self.subTest(variant=variant):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    profile_path = root / "oracle-profile.json"
                    runner.save_json(profile_path, self.profile)
                    case_dir = root / "case"
                    write_coherent_case(case_dir, profile_path)
                    path = case_dir / "t4-window.json"
                    t4 = runner.load_json(path)
                    mutate(t4)
                    runner.save_json(path, t4)
                    runner.write_artifact_manifest(case_dir)
                    verification = runner.evaluate_case_directory(
                        case_dir,
                        profile_path,
                    )
                    self.assertFalse(verification["rawSourceExactMatch"])
                    self.assertFalse(verification["exactMatch"])

    def test_non_snapshot_phase_records_have_closed_schemas(self) -> None:
        receipt = {
            "recordKind": runner.O4_GUEST_WINDOW_RECEIPT_RECORD_KIND,
            "label": "o4-window-before-sequence",
            "observedAt": "2026-07-29T00:00:00.000000Z",
            "window": {
                "windowSeconds": 90.0,
                "elapsedSinceOpenObserved": 1.0,
                "remainingSeconds": 89.0,
                "requiredRemainingSeconds": 45.0,
            },
        }
        self.assertEqual(
            [],
            runner.o4_guest_window_receipt_faults(
                receipt,
                owner_phase="O4",
                oracle_profile=self.profile,
            ),
        )
        missing_kind = copy.deepcopy(receipt)
        del missing_kind["recordKind"]
        self.assertTrue(
            runner.o4_guest_window_receipt_faults(
                missing_kind,
                owner_phase="O4",
                oracle_profile=self.profile,
            )
        )
        self.assertTrue(
            runner.o4_guest_window_receipt_faults(
                receipt,
                owner_phase="O0",
                oracle_profile=self.profile,
            )
        )
        service = raw_service_window("stable-after-or")
        self.assertEqual(
            [],
            runner.runnable_window_record_shape_faults(
                service,
                phase="t4",
            ),
        )
        del service["description"]
        self.assertTrue(
            runner.runnable_window_record_shape_faults(
                service,
                phase="t4",
            )
        )

    def test_entered_stage_summaries_require_full_valid_evidence(self) -> None:
        log_evidence = {
            "complete": True,
            "summaryConsistency": {
                field: True
                for field in runner.LOG_WINDOW_V2_SUMMARY_CONSISTENCY_FIELDS
            },
        }
        self.assertTrue(
            runner.complete_injected_log_summary(log_evidence)
        )
        partial_log = copy.deepcopy(log_evidence)
        partial_log["summaryConsistency"].pop("storedWindowExact")
        self.assertFalse(
            runner.complete_injected_log_summary(partial_log)
        )
        truthy_log = copy.deepcopy(log_evidence)
        truthy_log["summaryConsistency"]["storedWindowExact"] = 1
        self.assertFalse(
            runner.complete_injected_log_summary(truthy_log)
        )

        guest_evidence = {
            "required": True,
            "artifactsPresent": True,
            "validO4Evidence": True,
            "summaryConsistency": {
                field: True
                for field in runner.O4_GUEST_SUMMARY_CONSISTENCY_FIELDS
            },
        }
        self.assertTrue(
            runner.complete_injected_o4_guest_summary(guest_evidence)
        )
        invalid_guest = copy.deepcopy(guest_evidence)
        invalid_guest["validO4Evidence"] = False
        self.assertFalse(
            runner.complete_injected_o4_guest_summary(invalid_guest)
        )
        partial_guest = copy.deepcopy(guest_evidence)
        partial_guest["summaryConsistency"].pop("afterOwnerEvidence")
        self.assertFalse(
            runner.complete_injected_o4_guest_summary(partial_guest)
        )
        self.assertFalse(runner.raw_o4_guest_evidence_valid(None))
        self.assertFalse(
            runner.raw_o4_guest_evidence_valid(
                {"validO4Evidence": False}
            )
        )
        self.assertTrue(
            runner.raw_o4_guest_evidence_valid(
                {"validO4Evidence": True}
            )
        )

    def test_injection_ack_and_hmp_transcript_are_exactly_bound(self) -> None:
        injections = copy.deepcopy(
            evaluation_input("bit-or")["injections"]
        )
        realistic_transcript = (
            "QEMU 11.0.2 monitor - type 'help' for more information\r\n"
            "(qemu) pcie_aer_inject_error -c test_fn1 0x00000001\r\n"
            + VALID_HMP_ACK
            + "(qemu) "
        )
        self.assertTrue(
            runner.exclusive_correctable_hmp_ack(
                realistic_transcript,
                "test_fn1",
                outer_endpoint_bdf=OUTER_ENDPOINT_BDF,
                outer_root_bdf=OUTER_ROOT_BDF,
            )
        )
        invalid_acks = (
            "OK id: test_fn1\n",
            (
                "OK id:test_fn1 root bus: 0000:00, "
                "bus: 1 devfn: 0.1\n"
            ),
            (
                "OK id: test_fn1 root bus: 0000:01, "
                "bus: 1 devfn: 0.1\n"
            ),
            (
                "OK id: test_fn1 root bus: 0000:00, "
                "bus: 2 devfn: 0.1\n"
            ),
            (
                "OK id: test_fn1 root bus: 0000:00, "
                "bus: 1 devfn: 1.0\n"
            ),
            VALID_HMP_ACK.rstrip("\n") + " trailing-junk\n",
            VALID_HMP_ACK
            + (
                "OK id: foreign root bus: 0000:00, "
                "bus: 1 devfn: 0.1\n"
            ),
            VALID_HMP_ACK + "Error: command failed\n",
            VALID_HMP_ACK + "foreign status reports failure inline\n",
            VALID_HMP_ACK + VALID_HMP_ACK,
        )
        for raw in invalid_acks:
            with self.subTest(raw=raw):
                self.assertFalse(
                    runner.exclusive_correctable_hmp_ack(
                        raw,
                        "test_fn1",
                        outer_endpoint_bdf=OUTER_ENDPOINT_BDF,
                        outer_root_bdf=OUTER_ROOT_BDF,
                    )
                )
        self.assertFalse(
            runner.exclusive_correctable_hmp_ack(
                VALID_HMP_ACK,
                "test_fn1",
                outer_endpoint_bdf="0000:02:00.1",
                outer_root_bdf=OUTER_ROOT_BDF,
            )
        )
        self.assertFalse(
            runner.exclusive_correctable_hmp_ack(
                VALID_HMP_ACK,
                "test_fn1",
                outer_endpoint_bdf=OUTER_ENDPOINT_BDF,
                outer_root_bdf="0000:01:08.0",
            )
        )

        topology_pair = runner.outer_bdf_pair_from_gate_lease(
            {
                "gateLease": {
                    "original": {
                        "snapshot": artifact_gate_topology(),
                    }
                }
            }
        )
        self.assertEqual(
            (OUTER_ENDPOINT_BDF, OUTER_ROOT_BDF),
            topology_pair,
        )
        malformed_topology = artifact_gate_topology()
        malformed_topology["endpoint"]["requesterId"] = 0
        self.assertEqual(
            (None, None),
            runner.outer_bdf_pair_from_gate_lease(
                {
                    "gateLease": {
                        "original": {
                            "snapshot": malformed_topology,
                        }
                    }
                }
            ),
        )
        static_topology = artifact_gate_topology()
        self.assertEqual(
            [],
            runner.static_outer_topology_identity_faults(
                static_topology
            ),
        )
        static_topology_variants = {
            "q35": lambda value: value.update(
                {"q35Pciexbar": 0}
            ),
            "endpoint-type": lambda value: value["endpoint"].update(
                {"pcieType": aer.PCI_EXP_TYPE_ROOT_PORT}
            ),
            "root-pcie-offset": lambda value: value["root"].update(
                {"pcieCapabilityOffset": 0x101}
            ),
            "endpoint-aer-id": lambda value: value["endpoint"].update(
                {"aerHeader": 0}
            ),
        }
        for variant, mutate in static_topology_variants.items():
            with self.subTest(static_topology_variant=variant):
                malformed = copy.deepcopy(static_topology)
                mutate(malformed)
                self.assertTrue(
                    runner.static_outer_topology_identity_faults(
                        malformed
                    )
                )
        topology_argv = [
            "fixture-qemu",
            "-device",
            "pcie-root-port,id=test_rp,bus=pcie.0,addr=0x08.0",
            "-device",
            (
                "virtio-net-pci,id=test_fn1,bus=test_rp,"
                "addr=0x00.1"
            ),
        ]
        self.assertEqual(
            [],
            runner.qemu_argv_topology_faults(
                command_line=topology_argv,
                qemu_device="test_fn1",
                outer_endpoint_bdf=OUTER_ENDPOINT_BDF,
                outer_root_bdf=OUTER_ROOT_BDF,
            ),
        )
        for wrong_same_bus_root in (
            "0000:00:09.0",
            "0000:00:08.1",
        ):
            with self.subTest(
                wrong_same_bus_root=wrong_same_bus_root
            ):
                self.assertTrue(
                    runner.qemu_argv_topology_faults(
                        command_line=topology_argv,
                        qemu_device="test_fn1",
                        outer_endpoint_bdf=OUTER_ENDPOINT_BDF,
                        outer_root_bdf=wrong_same_bus_root,
                    )
                )
        self.assertEqual(
            [],
            runner.injection_record_shape_faults(
                injections,
                sequence="bit-or",
                qemu_device="test_fn1",
                outer_endpoint_bdf=OUTER_ENDPOINT_BDF,
                outer_root_bdf=OUTER_ROOT_BDF,
            ),
        )
        no_topology_faults = runner.injection_record_shape_faults(
            injections,
            sequence="bit-or",
            qemu_device="test_fn1",
            outer_endpoint_bdf=None,
            outer_root_bdf=None,
        )
        self.assertIn(
            "non-empty injections lack one closed outer topology identity",
            no_topology_faults,
        )
        self.assertTrue(
            runner.entered_injection_from_records(
                injections,
                sequence="bit-or",
                qemu_device="test_fn1",
                outer_endpoint_bdf=None,
                outer_root_bdf=None,
            )
        )
        self.assertEqual(
            [],
            runner.injection_record_shape_faults(
                [],
                sequence="bit-or",
                qemu_device="test_fn1",
                outer_endpoint_bdf=None,
                outer_root_bdf=None,
            ),
        )
        self.assertFalse(
            runner.entered_injection_from_records(
                [],
                sequence="bit-or",
                qemu_device="test_fn1",
                outer_endpoint_bdf=None,
                outer_root_bdf=None,
            )
        )
        missing_topology_input = evaluation_input("bit-or")
        with self.assertRaises(TypeError):
            runner.evaluate_case_observation(
                missing_topology_input,
                self.profile,
            )
        missing_topology_result = evaluate_observation(
            missing_topology_input,
            self.profile,
            outer_endpoint_bdf=None,
            outer_root_bdf=None,
        )
        self.assertNotEqual(
            runner.OBSERVATION_MATCH,
            missing_topology_result["observationState"],
        )
        missing_raw = copy.deepcopy(injections)
        missing_raw[0]["raw"] = None
        self.assertTrue(
            runner.injection_record_shape_faults(
                missing_raw,
                sequence="bit-or",
                qemu_device="test_fn1",
                outer_endpoint_bdf=OUTER_ENDPOINT_BDF,
                outer_root_bdf=OUTER_ROOT_BDF,
            )
        )
        missing_field = copy.deepcopy(injections)
        del missing_field[0]["commandIssuedAt"]
        self.assertTrue(
            runner.injection_record_shape_faults(
                missing_field,
                sequence="bit-or",
                qemu_device="test_fn1",
                outer_endpoint_bdf=OUTER_ENDPOINT_BDF,
                outer_root_bdf=OUTER_ROOT_BDF,
            )
        )
        contradictory_ack = copy.deepcopy(injections)
        contradictory_ack[0]["raw"] = (
            VALID_HMP_ACK + "Error: command failed\n"
        )
        self.assertTrue(
            runner.injection_record_shape_faults(
                contradictory_ack,
                sequence="bit-or",
                qemu_device="test_fn1",
                outer_endpoint_bdf=OUTER_ENDPOINT_BDF,
                outer_root_bdf=OUTER_ROOT_BDF,
            )
        )
        duplicate_ack = copy.deepcopy(injections)
        duplicate_ack[0]["raw"] = (
            VALID_HMP_ACK + VALID_HMP_ACK
        )
        self.assertTrue(
            runner.injection_record_shape_faults(
                duplicate_ack,
                sequence="bit-or",
                qemu_device="test_fn1",
                outer_endpoint_bdf=OUTER_ENDPOINT_BDF,
                outer_root_bdf=OUTER_ROOT_BDF,
            )
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            write_coherent_case(case_dir, profile_path)
            (case_dir / "hmp.txt").write_text(
                "forged transcript\n",
                encoding="utf-8",
            )
            runner.write_artifact_manifest(case_dir)
            verification = runner.evaluate_case_directory(
                case_dir,
                profile_path,
            )
            self.assertFalse(
                verification["rawConsistencyChecks"]["hmp-transcript"]
            )
            self.assertFalse(verification["exactMatch"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            write_coherent_case(case_dir, profile_path)
            t3_path = case_dir / "t3-immediate.json"
            t3 = runner.load_json(t3_path)
            t3["injections"][0]["raw"] = (
                VALID_HMP_ACK + "Error: command failed\n"
            )
            runner.save_json(t3_path, t3)
            (case_dir / "hmp.txt").write_text(
                runner.render_hmp_transcript(t3["injections"]),
                encoding="utf-8",
            )
            synchronize_evaluation_from_raw(
                case_dir,
                self.profile,
            )
            verification = runner.evaluate_case_directory(
                case_dir,
                profile_path,
            )
            self.assertFalse(
                verification["rawConsistencyChecks"][
                    "phase-and-injection-records-valid"
                ]
            )
            self.assertFalse(verification["exactMatch"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            write_coherent_case(case_dir, profile_path)
            t3_path = case_dir / "t3-immediate.json"
            t3 = runner.load_json(t3_path)
            first_snapshot = t3["snapshots"][0]["snapshot"]
            first_snapshot["rootState"]["rootErrorStatus"] = 0
            t3["snapshots"][0]["sourceMeaning"] = (
                runner.root_source_meaning(
                    runner.outer_to_public_state(first_snapshot)
                )
            )
            runner.save_json(t3_path, t3)
            synchronize_evaluation_from_raw(
                case_dir,
                self.profile,
            )
            raw_sources = runner.reconstruct_evaluation_sources(
                case_dir,
                self.profile,
            )
            verification = runner.evaluate_case_directory(
                case_dir,
                profile_path,
            )
            self.assertEqual(-1, raw_sources["sourceRequesterId"])
            self.assertTrue(
                any(
                    "first verified post-ACK Root Source"
                    in fault
                    for fault in raw_sources["recordShapeFaults"]
                )
            )
            self.assertFalse(
                verification["rawConsistencyChecks"][
                    "phase-and-injection-records-valid"
                ]
            )
            self.assertFalse(verification["exactMatch"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            write_coherent_case(case_dir, profile_path)
            t1_path = case_dir / "t1-effective-controls.json"
            t1 = runner.load_json(t1_path)
            topology = t1["gateLease"]["original"]["snapshot"]
            topology["endpoint"]["bus"] = 2
            topology["endpoint"]["requesterId"] = 0x0201
            runner.save_json(t1_path, t1)
            t3_path = case_dir / "t3-immediate.json"
            t3 = runner.load_json(t3_path)
            for injection in t3["injections"]:
                injection["raw"] = injection["raw"].replace(
                    "bus: 1 devfn:",
                    "bus: 2 devfn:",
                )
            runner.save_json(t3_path, t3)
            runner.save_text(
                case_dir / "hmp.txt",
                runner.render_hmp_transcript(t3["injections"]) or "",
            )
            synchronized = synchronize_evaluation_from_raw(
                case_dir,
                self.profile,
            )
            verification = runner.evaluate_case_directory(
                case_dir,
                profile_path,
            )
            self.assertFalse(synchronized["evidenceComplete"])
            self.assertTrue(
                any(
                    "topology" in fault
                    or "declared BDF" in fault
                    or "requester IDs" in fault
                    or "Root Source" in fault
                    for fault in runner.reconstruct_evaluation_sources(
                        case_dir,
                        self.profile,
                    )["recordShapeFaults"]
                )
            )
            self.assertFalse(
                verification["rawConsistencyChecks"][
                    "phase-and-injection-records-valid"
                ]
            )
            self.assertFalse(verification["exactMatch"])

    def test_hmp_transcript_preserves_raw_crlf_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            write_coherent_case(case_dir, profile_path)
            t3_path = case_dir / "t3-immediate.json"
            t3 = runner.load_json(t3_path)
            for injection in t3["injections"]:
                injection["raw"] = (
                    "QEMU monitor\r\n"
                    + injection["raw"].rstrip("\n")
                    + "\r\n"
                )
            runner.save_json(t3_path, t3)
            transcript = runner.render_hmp_transcript(t3["injections"])
            self.assertIsInstance(transcript, str)
            runner.save_text(case_dir / "hmp.txt", transcript)

            synchronized = synchronize_evaluation_from_raw(
                case_dir,
                self.profile,
            )
            verification = runner.evaluate_case_directory(
                case_dir,
                profile_path,
            )

            self.assertIn(b"\r\n", (case_dir / "hmp.txt").read_bytes())
            self.assertTrue(synchronized["evidenceComplete"])
            self.assertTrue(
                verification["rawConsistencyChecks"]["hmp-transcript"]
            )
            self.assertTrue(verification["exactMatch"])

    def test_authority_artifacts_reject_extra_claim_fields(self) -> None:
        variants = ("case", "runManifest", "evaluationInput", "result")
        for variant in variants:
            with self.subTest(variant=variant):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    profile_path = root / "oracle-profile.json"
                    runner.save_json(profile_path, self.profile)
                    case_dir = root / "case"
                    write_coherent_case(case_dir, profile_path)
                    filenames = {
                        "case": "case.json",
                        "runManifest": "run-manifest.json",
                        "evaluationInput": "evaluation-input.json",
                        "result": "result.json",
                    }
                    path = case_dir / filenames[variant]
                    value = runner.load_json(path)
                    value["behaviorAuthority"] = "FULL_PROFILE"
                    runner.save_json(path, value)
                    if variant == "case":
                        result_path = case_dir / "result.json"
                        result = runner.load_json(result_path)
                        result["case"] = value
                        runner.save_json(result_path, result)
                    runner.write_artifact_manifest(case_dir)
                    verification = runner.evaluate_case_directory(
                        case_dir,
                        profile_path,
                    )
                    self.assertTrue(
                        verification["artifactShapeFaults"][variant]
                    )
                    self.assertFalse(verification["exactMatch"])

    def test_evaluation_identity_cannot_be_resigned_away(self) -> None:
        variants = {
            "campaignId": "forged-campaign",
            "caseRunId": "forged-campaign--forged-case",
            "requesterId": 0,
        }
        for field_name, forged_value in variants.items():
            with self.subTest(field_name=field_name):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    profile_path = root / "oracle-profile.json"
                    runner.save_json(profile_path, self.profile)
                    case_dir = root / "case"
                    write_coherent_case(case_dir, profile_path)
                    evaluation_path = case_dir / "evaluation-input.json"
                    candidate = runner.load_json(evaluation_path)
                    candidate[field_name] = forged_value
                    runner.save_json(evaluation_path, candidate)
                    recomputed = evaluate_observation(
                        candidate,
                        self.profile,
                    )
                    runner.save_json(case_dir / "oracle.json", recomputed)
                    result_path = case_dir / "result.json"
                    result = runner.load_json(result_path)
                    for result_field in (
                        "observationState",
                        "verdict",
                        "observationDigest",
                        "safetyStop",
                    ):
                        result[result_field] = recomputed[result_field]
                    runner.save_json(result_path, result)
                    runner.write_artifact_manifest(case_dir)
                    verification = runner.evaluate_case_directory(
                        case_dir,
                        profile_path,
                    )
                    self.assertFalse(verification["exactMatch"])
                    if field_name == "requesterId":
                        self.assertFalse(
                            verification["rawConsistencyChecks"][
                                "requester-id"
                            ]
                        )
                    else:
                        self.assertFalse(
                            verification["identityConsistencyChecks"][
                                f"case/evaluation:{field_name}"
                            ]
                        )

    def test_containment_evidence_is_rebuilt_from_raw_restore_facts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            write_coherent_case(case_dir, profile_path)
            candidate = runner.load_json(
                case_dir / "evaluation-input.json"
            )
            candidate["containmentEvidence"] = [
                {"behaviorAuthority": "FORGED"}
            ]
            resign_evaluation_artifacts(
                case_dir,
                self.profile,
                candidate,
            )
            verification = runner.evaluate_case_directory(
                case_dir,
                profile_path,
            )
            self.assertFalse(
                verification["rawConsistencyChecks"][
                    "containment-evidence"
                ]
            )
            self.assertFalse(verification["exactMatch"])

    def test_current_model_cannot_downgrade_from_log_window_v2(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            write_coherent_case(case_dir, profile_path)
            case_path = case_dir / "case.json"
            case_spec = runner.load_json(case_path)
            del case_spec["logWindowProtocol"]
            runner.save_json(case_path, case_spec)
            result_path = case_dir / "result.json"
            result = runner.load_json(result_path)
            result["case"] = case_spec
            runner.save_json(result_path, result)
            runner.write_artifact_manifest(case_dir)
            verification = runner.evaluate_case_directory(
                case_dir,
                profile_path,
            )
            self.assertTrue(verification["artifactShapeFaults"]["case"])
            self.assertFalse(verification["identityExactMatch"])
            self.assertFalse(verification["exactMatch"])

    def test_manifest_rejects_symbolic_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            write_coherent_case(case_dir, profile_path)
            link = case_dir / "dangling-evidence-link"
            try:
                link.symlink_to(case_dir / "missing-target")
            except OSError as error:
                self.skipTest(f"symbolic links are unavailable: {error}")
            with self.assertRaisesRegex(
                runner.ManifestError,
                "symbolic links",
            ):
                runner.verify_artifact_manifest(case_dir)

    def test_result_separates_runtime_and_oracle_containment(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            _, result = write_coherent_case(case_dir, profile_path)
            candidate = runner.load_json(
                case_dir / "evaluation-input.json"
            )
            candidate["safetyCoverage"][0]["complete"] = False
            candidate["safetyCoverage"][0]["faults"] = [
                "fixture offline-derived coverage fault"
            ]
            self.assertFalse(candidate["containmentRequired"])
            oracle = evaluate_observation(
                candidate,
                self.profile,
            )
            self.assertTrue(oracle["containmentRequired"])
            runner.save_json(
                case_dir / "evaluation-input.json",
                candidate,
            )
            runner.save_json(case_dir / "oracle.json", oracle)
            result.update(
                {
                    "observationState": oracle["observationState"],
                    "verdict": oracle["verdict"],
                    "observationDigest": oracle.get(
                        "observationDigest"
                    ),
                    "safetyStop": oracle["safetyStop"],
                    "containmentRequired": oracle[
                        "containmentRequired"
                    ],
                    "containmentReasons": oracle[
                        "containmentReasons"
                    ],
                    "runtimeContainmentRequired": candidate[
                        "containmentRequired"
                    ],
                    "runtimeContainmentReasons": candidate[
                        "containmentReasons"
                    ],
                }
            )
            runner.save_json(case_dir / "result.json", result)
            runner.write_artifact_manifest(case_dir)
            verification = runner.evaluate_case_directory(
                case_dir,
                profile_path,
            )
            self.assertTrue(verification["oracleExactMatch"])
            self.assertTrue(verification["resultExactMatch"])
            self.assertTrue(
                verification["resultConsistencyChecks"][
                    "runtime-containment-required"
                ]
            )
            self.assertTrue(
                verification["resultConsistencyChecks"][
                    "oracle-containment-required"
                ]
            )
            self.assertFalse(
                verification["rawSourceExactMatch"],
                "the synthetic raw/evaluation mismatch remains visible",
            )

    def test_case_offline_verifier_rejects_deleted_service_coverage(
        self,
    ) -> None:
        for tamper in ("missing-kind", "missing-window"):
            with self.subTest(tamper=tamper):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    profile_path = root / "oracle-profile.json"
                    runner.save_json(profile_path, self.profile)
                    case_dir = root / "case"
                    write_coherent_case(case_dir, profile_path)
                    t4_path = case_dir / "t4-window.json"
                    t4 = runner.load_json(t4_path)
                    if tamper == "missing-kind":
                        del t4["windows"][0]["safetyWindowKind"]
                    else:
                        del t4["windows"][0]
                    runner.save_json(t4_path, t4)
                    runner.write_artifact_manifest(case_dir)
                    verification = runner.evaluate_case_directory(
                        case_dir,
                        profile_path,
                    )
                    self.assertFalse(verification["exactMatch"])
                    reconstructed = runner.reconstruct_evaluation_sources(
                        case_dir,
                        self.profile,
                    )
                    self.assertFalse(
                        reconstructed["evidenceComplete"]
                    )

    def test_offline_snapshots_exclude_pre_state_and_require_public_kind(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            write_coherent_case(case_dir, profile_path)
            t2_path = case_dir / "t2-pre-injection.json"
            t2 = runner.load_json(t2_path)
            t2["steps"].append(
                raw_pre_mutation_snapshot_record(
                    "forged-public-candidate",
                    state(),
                    boundary="PRE_INJECTION",
                )
            )
            runner.save_json(t2_path, t2)
            rebuilt = runner.reconstruct_evaluation_sources(
                case_dir,
                self.profile,
            )
            self.assertNotIn(
                "forged-public-candidate-pre-state",
                rebuilt["snapshots"],
            )
            self.assertEqual([], rebuilt["snapshotRecordFaults"])
            t3_path = case_dir / "t3-immediate.json"
            t3 = runner.load_json(t3_path)
            t3["snapshots"].append(
                raw_pre_mutation_snapshot_record(
                    "spliced-pre-state",
                    state(),
                    boundary="ATTRIBUTION_WINDOW",
                )
            )
            runner.save_json(t3_path, t3)
            rebuilt = runner.reconstruct_evaluation_sources(
                case_dir,
                self.profile,
            )
            self.assertTrue(
                any(
                    "outside t2/t5" in fault
                    for fault in rebuilt["snapshotRecordFaults"]
                )
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            write_coherent_case(case_dir, profile_path)
            t2_path = case_dir / "t2-pre-injection.json"
            t2 = runner.load_json(t2_path)
            del t2["steps"][0]["recordKind"]
            runner.save_json(t2_path, t2)
            runner.write_artifact_manifest(case_dir)
            verification = runner.evaluate_case_directory(
                case_dir,
                profile_path,
            )
            self.assertFalse(
                verification["rawConsistencyChecks"][
                    "phase-and-injection-records-valid"
                ]
            )
            self.assertFalse(verification["exactMatch"])
            rebuilt = runner.reconstruct_evaluation_sources(
                case_dir,
                self.profile,
            )
            self.assertTrue(rebuilt["recordShapeFaults"])
            self.assertFalse(rebuilt["evidenceComplete"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            write_coherent_case(case_dir, profile_path)
            t2_path = case_dir / "t2-pre-injection.json"
            t2 = runner.load_json(t2_path)
            del t2["steps"][0]["snapshot"]
            runner.save_json(t2_path, t2)
            rebuilt = runner.reconstruct_evaluation_sources(
                case_dir,
                self.profile,
            )
            self.assertTrue(
                any(
                    "snapshot is not an object" in fault
                    for fault in rebuilt["snapshotRecordFaults"]
                )
            )
            self.assertFalse(rebuilt["evidenceComplete"])

    def test_case_offline_verifier_reparses_bound_log_bytes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            case_dir = root / "case"
            write_coherent_case(case_dir, profile_path)
            syslog = (
                case_dir
                / "raw-esxi"
                / "log-window-v2"
                / "attempt-01"
                / "syslog"
                / "active.raw"
            )
            with syslog.open("a", encoding="utf-8") as stream:
                stream.write(
                    "vmkernel: PCIe Bus Error severity=Corrected\n"
                )
            runner.write_artifact_manifest(case_dir)
            verification = runner.evaluate_case_directory(
                case_dir,
                profile_path,
            )
            self.assertFalse(
                verification["rawConsistencyChecks"][
                    "host-log-classification"
                ]
            )
            self.assertFalse(verification["exactMatch"])

    def test_v2_marker_writer_uses_official_esxcli_surface(self) -> None:
        protocol = runner.log_v2.protocol_for_case(
            "fixture-campaign",
            "fixture-bit-or",
        )
        ssh = mock.Mock()
        ssh.run.return_value = SimpleNamespace(
            returncode=0,
            stdout="",
            stderr="",
        )
        record = runner.write_official_log_marker_v2(
            ssh,
            protocol["before"],
        )
        expected = runner.log_v2.marker_command(protocol["before"])
        ssh.run.assert_called_once_with(
            expected,
            check=False,
            timeout=30,
        )
        self.assertEqual(record["command"], expected)
        self.assertEqual(record["protocol"], runner.log_v2.PROTOCOL_ID)
        self.assertNotIn("logger -t", record["command"])

    def test_v2_live_open_close_retains_raw_records(self) -> None:
        campaign_id = "fixture-campaign"
        case_id = "fixture-bit-or"
        protocol = runner.log_v2.protocol_for_case(
            campaign_id,
            case_id,
        )
        inventory = v2_inventory_record()
        before_visibility = v2_marker_visibility_record(
            protocol["before"]
        )
        after_visibility = v2_marker_visibility_record(
            protocol["after"]
        )
        capture = {
            "protocol": copy.deepcopy(protocol),
            "attemptCount": 1,
            "selectedAttempt": 1,
            "attempts": [],
            "complete": True,
        }
        rebuilt = {
            "protocol": copy.deepcopy(protocol),
            "complete": True,
            "classification": (
                "NOT_OBSERVED_IN_STRICT_PER_SOURCE_MARKER_WINDOW"
            ),
        }
        ssh = mock.Mock()
        ssh.run.return_value = SimpleNamespace(
            returncode=0,
            stdout="",
            stderr="",
        )
        transfer = mock.Mock()
        cancel = runner.threading.Event()
        t0: dict[str, Any] = {}
        t4: dict[str, Any] = {}
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = Path(temporary)
            with (
                mock.patch.object(
                    runner.log_v2,
                    "capture_inventory",
                    return_value=copy.deepcopy(inventory),
                ) as capture_inventory,
                mock.patch.object(
                    runner.log_v2,
                    "wait_for_marker",
                    side_effect=[
                        copy.deepcopy(before_visibility),
                        copy.deepcopy(after_visibility),
                    ],
                ) as wait_for_marker,
                mock.patch.object(
                    runner.log_v2,
                    "capture_rotation_chain",
                    return_value=copy.deepcopy(capture),
                ) as capture_chain,
                mock.patch.object(
                    runner.log_v2,
                    "rebuild_log_window",
                    return_value=copy.deepcopy(rebuilt),
                ) as rebuild_window,
            ):
                opened = runner.open_v2_log_window(
                    ssh=ssh,
                    campaign_id=campaign_id,
                    case_id=case_id,
                    protocol=protocol,
                    cancel=cancel,
                    evidence=t0,
                )
                closed = runner.close_v2_log_window(
                    ssh=ssh,
                    transfer=transfer,
                    case_dir=case_dir,
                    campaign_id=campaign_id,
                    case_id=case_id,
                    protocol=protocol,
                    cancel=cancel,
                    evidence=t4,
                )

        capture_inventory.assert_called_once_with(ssh)
        self.assertEqual(wait_for_marker.call_count, 2)
        self.assertEqual(
            [call.args[1] for call in wait_for_marker.call_args_list],
            [protocol["before"], protocol["after"]],
        )
        capture_chain.assert_called_once_with(
            ssh,
            transfer,
            case_dir,
            protocol,
        )
        self.assertIs(
            rebuild_window.call_args.kwargs["semantic_classifier"],
            runner.esxi_aer.aer_log_lines,
        )
        self.assertEqual(
            opened["logWindowPreflightInventory"],
            inventory,
        )
        self.assertEqual(t0["beforeMarkerVisibility"], before_visibility)
        self.assertEqual(t4["afterMarkerVisibility"], after_visibility)
        self.assertEqual(t4["logWindowCapture"], capture)
        self.assertEqual(t4["logWindow"], rebuilt)
        self.assertEqual(closed["window"], rebuilt)
        self.assertEqual(
            [call.args[0] for call in ssh.run.call_args_list],
            [
                runner.log_v2.marker_command(protocol["before"]),
                runner.log_v2.marker_command(protocol["after"]),
            ],
        )

    def test_v2_live_close_can_defer_local_window_derivation(self) -> None:
        campaign_id = "fixture-campaign"
        case_id = "fixture-bit-or"
        protocol = runner.log_v2.protocol_for_case(
            campaign_id,
            case_id,
        )
        visibility = v2_marker_visibility_record(protocol["after"])
        capture = {
            "protocol": copy.deepcopy(protocol),
            "attemptCount": 1,
            "selectedAttempt": 1,
            "attempts": [],
            "complete": True,
        }
        ssh = mock.Mock()
        ssh.run.return_value = SimpleNamespace(
            returncode=0,
            stdout="",
            stderr="",
        )
        evidence: dict[str, Any] = {}
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(
                runner.log_v2,
                "wait_for_marker",
                return_value=copy.deepcopy(visibility),
            ),
            mock.patch.object(
                runner.log_v2,
                "capture_rotation_chain",
                return_value=copy.deepcopy(capture),
            ),
            mock.patch.object(
                runner.log_v2,
                "rebuild_log_window",
            ) as rebuild,
        ):
            closed = runner.close_v2_log_window(
                ssh=ssh,
                transfer=mock.Mock(),
                case_dir=Path(temporary),
                campaign_id=campaign_id,
                case_id=case_id,
                protocol=protocol,
                cancel=runner.threading.Event(),
                evidence=evidence,
                derive_window=False,
            )
        rebuild.assert_not_called()
        self.assertEqual(capture, closed["capture"])
        self.assertNotIn("window", closed)
        self.assertEqual(capture, evidence["logWindowCapture"])
        self.assertNotIn("logWindow", evidence)

    def test_v2_log_rebuild_dispatches_and_exact_checks_t0_t4(
        self,
    ) -> None:
        campaign_id = "fixture-campaign"
        case_id = "fixture-bit-or"
        protocol = runner.log_v2.protocol_for_case(
            campaign_id,
            case_id,
        )
        capture = {
            "protocol": copy.deepcopy(protocol),
            "attemptCount": 1,
            "selectedAttempt": 1,
            "attempts": [],
            "complete": True,
        }
        rebuilt = {
            "protocol": copy.deepcopy(protocol),
            "complete": True,
            "faults": [],
            "selectedAttempt": 1,
            "controlArtifact": (
                "raw-esxi/log-window-v2/attempt-01/control.json"
            ),
            "sources": {},
            "semanticAerEvents": [],
            "semanticAerLines": [],
            "classification": (
                "NOT_OBSERVED_IN_STRICT_PER_SOURCE_MARKER_WINDOW"
            ),
            "notEquivalentTo": "fixture",
        }
        case_spec = {
            "campaignId": campaign_id,
            "caseId": case_id,
            "logWindowProtocol": copy.deepcopy(protocol),
        }
        t0 = {
            "logWindowPreflightInventory": v2_inventory_record(),
            "beforeMarker": v2_marker_write_record(protocol["before"]),
            "beforeMarkerVisibility": v2_marker_visibility_record(
                protocol["before"]
            ),
        }
        t4 = {
            "afterMarker": v2_marker_write_record(protocol["after"]),
            "afterMarkerVisibility": v2_marker_visibility_record(
                protocol["after"]
            ),
            "logWindowCapture": capture,
            "logWindow": copy.deepcopy(rebuilt),
        }
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(
                runner.log_v2,
                "rebuild_log_window",
                return_value=copy.deepcopy(rebuilt),
            ) as rebuild:
                result = runner.rebuild_bounded_log_window(
                    case_dir=Path(temporary),
                    case_spec=case_spec,
                    t0=t0,
                    t4=t4,
                )
        self.assertTrue(result["complete"])
        self.assertTrue(all(result["summaryConsistency"].values()))
        self.assertIs(
            rebuild.call_args.kwargs["semantic_classifier"],
            runner.esxi_aer.aer_log_lines,
        )
        self.assertEqual(
            rebuild.call_args.kwargs["capture_summary"],
            capture,
        )

        t4["logWindow"]["classification"] = "FORGED"
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(
                runner.log_v2,
                "rebuild_log_window",
                return_value=copy.deepcopy(rebuilt),
            ):
                result = runner.rebuild_bounded_log_window(
                    case_dir=Path(temporary),
                    case_spec=case_spec,
                    t0=t0,
                    t4=t4,
                )
        self.assertFalse(
            result["summaryConsistency"]["storedWindowExact"]
        )

        t4["logWindow"] = copy.deepcopy(rebuilt)
        t0["beforeMarkerVisibility"]["sources"]["syslog"][
            "stdout"
        ] = ""
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(
                runner.log_v2,
                "rebuild_log_window",
                return_value=copy.deepcopy(rebuilt),
            ):
                result = runner.rebuild_bounded_log_window(
                    case_dir=Path(temporary),
                    case_spec=case_spec,
                    t0=t0,
                    t4=t4,
                )
        self.assertFalse(
            result["summaryConsistency"]["beforeMarkerVisibility"]
        )

    def test_log_window_is_bound_to_v2_preflight_capture_and_control(
        self,
    ) -> None:
        for variant in (
            "preflight-inventory",
            "capture-summary",
            "control-artifact",
        ):
            with self.subTest(variant=variant):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    profile_path = root / "oracle-profile.json"
                    runner.save_json(profile_path, self.profile)
                    case_dir = root / "case"
                    write_coherent_case(case_dir, profile_path)
                    t0_path = case_dir / "t0-baseline.json"
                    t4_path = case_dir / "t4-window.json"
                    t0 = runner.load_json(t0_path)
                    t4 = runner.load_json(t4_path)
                    if variant == "preflight-inventory":
                        t0["logWindowPreflightInventory"]["complete"] = False
                    elif variant == "capture-summary":
                        t4["logWindowCapture"]["attemptCount"] = 2
                    else:
                        control_path = (
                            case_dir
                            / "raw-esxi"
                            / "log-window-v2"
                            / "attempt-01"
                            / "control.json"
                        )
                        control = runner.load_json(control_path)
                        control["complete"] = False
                        runner.save_json(control_path, control)

                    runner.save_json(t0_path, t0)
                    runner.save_json(t4_path, t4)
                    runner.write_artifact_manifest(case_dir)
                    verification = runner.evaluate_case_directory(
                        case_dir,
                        profile_path,
                    )
                    self.assertFalse(
                        verification["rawConsistencyChecks"][
                            "host-log-raw-summary"
                        ]
                    )
                    self.assertFalse(verification["exactMatch"])

    def test_o4_serial_summary_cannot_override_raw_guest_bytes(
        self,
    ) -> None:
        valid_text = "\n".join(
            [
                (
                    "AER-OWNER phase=before-injection "
                    "bdf=0000:02:00.0 vendor=0x1af4 "
                    "device=0x1041 driver=virtio-pci"
                ),
                "AER-HEARTBEAT index=0 uptime=1.0 remaining=45",
                "AER-HEARTBEAT index=1 uptime=6.0 remaining=40",
            ]
        )
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = Path(temporary)
            serial_dir = case_dir / "guest-serial"
            serial_dir.mkdir()
            (serial_dir / "before-sequence.log").write_text(
                valid_text,
                encoding="utf-8",
            )
            (serial_dir / "after-sequence.log").write_text(
                valid_text.replace("driver=virtio-pci", "driver=unbound"),
                encoding="utf-8",
            )
            evidence = runner.rebuild_guest_serial_evidence(
                case_dir=case_dir,
                case_spec={"ownerPhase": "O4"},
                oracle_profile=self.profile,
                t0={
                    "guestBefore": {
                        "artifact": "guest-serial/before-sequence.log",
                        "ownerEvidence": {"validO4Evidence": True},
                    }
                },
                t1={
                    "activeVm": {
                        "guestSerialArtifact": (
                            "guest-serial/before-sequence.log"
                        ),
                        "window": {
                            "requiredRemainingSeconds": 45.0,
                        },
                    }
                },
                t4={
                    "guest": {
                        "artifact": "guest-serial/after-sequence.log",
                        "ownerEvidence": {"validO4Evidence": True},
                        "kernelEventLines": [],
                    }
                },
            )
        self.assertFalse(evidence["validO4Evidence"])
        self.assertFalse(
            evidence["summaryConsistency"]["afterOwnerEvidence"]
        )

    def test_o4_serial_rebuild_mirrors_before_window_and_after_heartbeat(
        self,
    ) -> None:
        owner = (
            "AER-OWNER phase=before-injection "
            "bdf=0000:02:00.0 vendor=0x1af4 "
            "device=0x1041 driver=virtio-pci"
        )
        before_text = (
            owner
            + "\nAER-HEARTBEAT index=0 uptime=1.0 remaining=90\n"
        )
        after_text = (
            before_text
            + "AER-HEARTBEAT index=1 uptime=6.0 remaining=85\n"
            + (
                "AER-OWNER phase=after-injection "
                "bdf=0000:02:00.0 vendor=0x1af4 "
                "device=0x1041 driver=virtio-pci\n"
            )
        )
        before_evidence = runner.parse_guest_owner_evidence(
            before_text,
            expected_vendor_id=0x1AF4,
            expected_device_id=0x1041,
        )
        after_evidence = runner.parse_guest_owner_evidence(
            after_text,
            expected_vendor_id=0x1AF4,
            expected_device_id=0x1041,
        )
        self.assertFalse(before_evidence["validO4Evidence"])
        self.assertTrue(before_evidence["beforeDriverBound"])
        self.assertTrue(after_evidence["validO4Evidence"])
        t0 = {
            "guestBefore": {
                "artifact": "guest-serial/before-sequence.log",
                "ownerEvidence": before_evidence,
                "windowRemainingEvidence": {
                    "source": (
                        "latest guest AER-HEARTBEAT remaining"
                    ),
                    "publishedSeconds": 90,
                    "heartbeatIntervalAllowanceSeconds": 5,
                    "conservativeLowerBoundSeconds": 85,
                    "requiredSeconds": 45.0,
                },
            }
        }
        t1 = {
            "activeVm": {
                "guestSerialArtifact": (
                    "guest-serial/before-sequence.log"
                ),
                "window": {"requiredRemainingSeconds": 45.0},
            }
        }
        t4 = {
            "guest": {
                "artifact": "guest-serial/after-sequence.log",
                "ownerEvidence": after_evidence,
                "kernelEventLines": [],
            }
        }
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = Path(temporary)
            serial_dir = case_dir / "guest-serial"
            serial_dir.mkdir()
            (serial_dir / "before-sequence.log").write_text(
                before_text,
                encoding="utf-8",
            )
            (serial_dir / "after-sequence.log").write_text(
                after_text,
                encoding="utf-8",
            )
            evidence = runner.rebuild_guest_serial_evidence(
                case_dir=case_dir,
                case_spec={"ownerPhase": "O4"},
                oracle_profile=self.profile,
                t0=t0,
                t1=t1,
                t4=t4,
            )
            self.assertTrue(evidence["validO4Evidence"])
            self.assertTrue(evidence["beforeWindowRemainingValid"])
            self.assertTrue(
                all(evidence["summaryConsistency"].values())
            )

            tampered_t0 = copy.deepcopy(t0)
            tampered_t0["guestBefore"]["windowRemainingEvidence"][
                "publishedSeconds"
            ] = 89
            tampered = runner.rebuild_guest_serial_evidence(
                case_dir=case_dir,
                case_spec={"ownerPhase": "O4"},
                oracle_profile=self.profile,
                t0=tampered_t0,
                t1=t1,
                t4=t4,
            )
            self.assertFalse(tampered["validO4Evidence"])
            self.assertFalse(
                tampered["summaryConsistency"][
                    "beforeWindowRemainingEvidence"
                ]
            )

    def test_execution_policy_binds_exact_case_boundary(self) -> None:
        cases = runner.build_case_plan(
            owner_phase="O4",
            gate="g101",
            sequences=self.profile["requiredSequences"],
            repeat=self.profile["minimumRepeats"],
        )
        planned_ids = [item["caseId"] for item in cases]
        full = runner.build_execution_policy(cases, None)
        self.assertEqual(full["mode"], runner.EXECUTION_MODE_FULL_PROFILE)
        self.assertIsNone(full["stopAfterCaseId"])
        bounded = runner.build_execution_policy(cases, planned_ids[0])
        self.assertEqual(
            bounded,
            {
                "version": runner.EXECUTION_POLICY_VERSION,
                "mode": runner.EXECUTION_MODE_STOP_AFTER_CASE,
                "stopAfterCaseId": planned_ids[0],
                "stopAfterOrdinal": 1,
            },
        )
        self.assertEqual(
            runner.build_boundary_stop(bounded, planned_ids),
            {
                "kind": "REQUESTED_CASE_BOUNDARY",
                "afterCase": planned_ids[0],
                "completedCaseCount": 1,
                "remainingCaseIds": planned_ids[1:],
                "requiredAction": runner.BOUNDARY_REQUIRED_ACTION,
            },
        )
        legacy_policy, provenance = (
            runner.normalize_campaign_execution_policy(
                campaign_plan={},
                campaign_result={},
                expected_plan_cases=cases,
            )
        )
        self.assertEqual(legacy_policy, full)
        self.assertEqual(
            provenance,
            "LEGACY_IMPLICIT_FULL_PROFILE",
        )
        with self.assertRaisesRegex(
            runner.ManifestError,
            "missing or inconsistent",
        ):
            runner.normalize_campaign_execution_policy(
                campaign_plan={"executionPolicy": bounded},
                campaign_result={},
                expected_plan_cases=cases,
            )
        for invalid in ("../unsafe", "o4__missing__g101__r01", planned_ids[-1]):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    runner.build_execution_policy(cases, invalid)

    def test_bounded_run_validation_keeps_full_profile_requirements(
        self,
    ) -> None:
        cases = runner.build_case_plan(
            owner_phase="O4",
            gate="g101",
            sequences=self.profile["requiredSequences"],
            repeat=self.profile["minimumRepeats"],
        )
        common = {
            "output": "fixture",
            "execute_correctable": True,
            "authorized_lab_target": True,
            "gate": self.profile["gate"],
            "repeat": self.profile["minimumRepeats"],
            "sequence": list(self.profile["requiredSequences"]),
            "stop_after_case": cases[0]["caseId"],
        }
        for override in (
            {"repeat": self.profile["minimumRepeats"] - 1},
            {"sequence": [self.profile["requiredSequences"][0]]},
        ):
            args = SimpleNamespace(**(common | override))
            parser = mock.Mock()
            parser.error.side_effect = ValueError
            with self.subTest(override=override):
                with self.assertRaises(ValueError):
                    runner.validate_run_args(parser, args, self.profile)

    def test_campaign_stops_after_one_manifest_complete_case(self) -> None:
        cases = runner.build_case_plan(
            owner_phase="O4",
            gate="g101",
            sequences=self.profile["requiredSequences"],
            repeat=self.profile["minimumRepeats"],
        )
        first_case_id = cases[0]["caseId"]

        def fake_run_case(**kwargs: Any) -> dict[str, Any]:
            case_plan = kwargs["case_plan"]
            return {
                "caseId": case_plan["caseId"],
                "caseRunId": (
                    f"{kwargs['campaign_id']}--{case_plan['caseId']}"
                ),
                "ownerPhase": case_plan["ownerPhase"],
                "sequence": case_plan["sequence"],
                "gate": case_plan["gate"],
                "repeatIndex": case_plan["repeatIndex"],
                "observationState": runner.OBSERVATION_MATCH,
                "verdict": "MATCH",
                "observationDigest": "fixture",
                "safetyStop": False,
                "enteredInjection": True,
                "fault": None,
                "cleanupComplete": True,
                "containmentRequired": False,
                "result": {"path": "fixture", "sha256": "0" * 64},
                "manifest": {"path": "fixture", "sha256": "0" * 64},
            }

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "campaign"
            args = SimpleNamespace(
                oracle_profile=str(runner.DEFAULT_ORACLE_PROFILE),
                owner_phase="O4",
                gate="g101",
                sequence=None,
                repeat=self.profile["minimumRepeats"],
                stop_after_case=first_case_id,
                run_id="fixture-boundary-campaign",
                output=str(output),
                caveat="fixture",
                host="fixture",
                user="root",
                qemu_name="fixture",
                qemu_monitor="/fixture/monitor.sock",
            )
            api = mock.Mock()
            with (
                mock.patch.object(
                    runner,
                    "load_oracle_profile",
                    return_value=self.profile,
                ),
                mock.patch.object(runner, "validate_run_args"),
                mock.patch.object(runner, "caveat_field", return_value="secret"),
                mock.patch.object(runner, "EsxiSsh", return_value=mock.Mock()),
                mock.patch.object(
                    runner.esxi_aer,
                    "EsxiScp",
                    return_value=mock.Mock(),
                ),
                mock.patch.object(
                    runner.esxi_aer,
                    "ApiSession",
                    return_value=api,
                ),
                mock.patch.object(
                    runner,
                    "environment_identity",
                    return_value={"fixture": True},
                ),
                mock.patch.object(
                    runner,
                    "source_and_binary_hashes",
                    return_value={
                        "environment": {"fixture": True},
                        "repositoryInputs": {},
                    },
                ),
                mock.patch.object(
                    runner,
                    "run_case",
                    side_effect=fake_run_case,
                ) as run_case_mock,
                mock.patch.object(
                    runner.esxi_aer,
                    "qemu_runtime_state",
                    return_value="running",
                ),
            ):
                campaign = runner.run_campaign(
                    runner.build_parser(),
                    args,
                )

        self.assertEqual(run_case_mock.call_count, 1)
        self.assertEqual(
            campaign["boundaryStop"]["afterCase"],
            first_case_id,
        )
        self.assertEqual(len(campaign["cases"]), 1)
        self.assertEqual(
            campaign["incompletePlan"],
            [item["caseId"] for item in cases[1:]],
        )
        self.assertEqual(
            campaign["aggregate"]["observationState"],
            runner.OBSERVATION_INCONCLUSIVE,
        )
        self.assertEqual(campaign["finalQemuState"], "running")

    def test_verify_campaign_termination_recomputes_stop_class(self) -> None:
        cases = runner.build_case_plan(
            owner_phase="O4",
            gate="g101",
            sequences=self.profile["requiredSequences"],
            repeat=self.profile["minimumRepeats"],
        )
        planned_ids = [item["caseId"] for item in cases]
        policy = runner.build_execution_policy(cases, planned_ids[0])
        boundary = runner.build_boundary_stop(policy, planned_ids)
        result = runner.verify_campaign_termination(
            campaign_result={"boundaryStop": boundary},
            planned_ids=planned_ids,
            completed_ids=planned_ids[:1],
            incomplete_ids=planned_ids[1:],
            execution_policy=policy,
        )
        self.assertEqual(result["completionClass"], "INTENTIONAL_PREFIX")
        self.assertFalse(result["fullPlanComplete"])

        safety = {
            "afterCase": planned_ids[0],
            "remainingCaseIds": planned_ids[1:],
            "requiredAction": "fixture",
        }
        result = runner.verify_campaign_termination(
            campaign_result={"safetyStop": safety},
            planned_ids=planned_ids,
            completed_ids=planned_ids[:1],
            incomplete_ids=planned_ids[1:],
            execution_policy=policy,
        )
        self.assertEqual(result["completionClass"], "SAFETY_STOP")

        with self.assertRaisesRegex(
            runner.ManifestError,
            "no manifest-bound termination cause",
        ):
            runner.verify_campaign_termination(
                campaign_result={},
                planned_ids=planned_ids,
                completed_ids=planned_ids[:1],
                incomplete_ids=planned_ids[1:],
                execution_policy=policy,
            )
        full_policy = runner.build_execution_policy(cases, None)
        with self.assertRaisesRegex(
            runner.ManifestError,
            "FULL_PROFILE campaign cannot claim boundaryStop",
        ):
            runner.verify_campaign_termination(
                campaign_result={"boundaryStop": boundary},
                planned_ids=planned_ids,
                completed_ids=planned_ids[:1],
                incomplete_ids=planned_ids[1:],
                execution_policy=full_policy,
            )

    def test_verify_require_complete_exit_code_is_opt_in(self) -> None:
        incomplete = {
            "verified": True,
            "fullPlanComplete": False,
        }
        complete = {
            "verified": True,
            "fullPlanComplete": True,
        }
        with (
            mock.patch(
                "sys.argv",
                ["runner", "verify-run", "--input", "fixture"],
            ),
            mock.patch.object(
                runner,
                "verify_campaign",
                return_value=copy.deepcopy(incomplete),
            ),
            mock.patch("builtins.print"),
        ):
            self.assertEqual(runner.main(), 0)
        with (
            mock.patch(
                "sys.argv",
                [
                    "runner",
                    "verify-run",
                    "--input",
                    "fixture",
                    "--require-complete",
                ],
            ),
            mock.patch.object(
                runner,
                "verify_campaign",
                return_value=copy.deepcopy(incomplete),
            ),
            mock.patch("builtins.print"),
        ):
            self.assertEqual(runner.main(), 2)
        with (
            mock.patch(
                "sys.argv",
                [
                    "runner",
                    "verify-run",
                    "--input",
                    "fixture",
                    "--require-complete",
                ],
            ),
            mock.patch.object(
                runner,
                "verify_campaign",
                return_value=copy.deepcopy(complete),
            ),
            mock.patch("builtins.print"),
        ):
            self.assertEqual(runner.main(), 0)

    def test_campaign_verifier_detects_cross_reference_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            campaign_id = "fixture-campaign"
            profile_path = root / "oracle-profile.json"
            runner.save_json(profile_path, self.profile)
            plan_cases = runner.build_case_plan(
                owner_phase="O0",
                gate="g101",
                sequences=self.profile["requiredSequences"],
                repeat=self.profile["minimumRepeats"],
            )
            first_case = plan_cases[0]
            case_id = first_case["caseId"]
            case_dir = root / "cases" / case_id
            oracle, case_result = write_coherent_case(
                case_dir,
                profile_path,
                case_id=case_id,
                campaign_id=campaign_id,
                sequence=first_case["sequence"],
                gate=first_case["gate"],
                repeat_index=first_case["repeatIndex"],
            )
            schema_path = root / "oracle-profile.schema.json"
            profile_binding = {
                "sha256": runner.sha256_file(profile_path),
                "schemaSha256": runner.sha256_file(schema_path),
            }
            execution_policy = runner.build_execution_policy(
                plan_cases,
                case_id,
            )
            plan = {
                "schemaVersion": runner.SCHEMA_VERSION,
                "modelId": runner.RUNNER_MODEL_ID,
                "runId": campaign_id,
                "ownerPhase": "O0",
                "gate": "g101",
                "sequences": self.profile["requiredSequences"],
                "repeat": self.profile["minimumRepeats"],
                "oracleProfile": profile_binding,
                "executionPolicy": execution_policy,
                "cases": plan_cases,
                "claimBoundary": runner.case_claim_boundary(),
            }
            summary = {
                "caseId": case_id,
                "caseRunId": case_result["case"]["caseRunId"],
                "ownerPhase": first_case["ownerPhase"],
                "sequence": first_case["sequence"],
                "gate": first_case["gate"],
                "repeatIndex": first_case["repeatIndex"],
                "observationState": oracle["observationState"],
                "verdict": oracle["verdict"],
                "observationDigest": oracle["observationDigest"],
                "safetyStop": oracle["safetyStop"],
                "enteredInjection": case_result["enteredInjection"],
                "cleanupComplete": case_result["cleanupComplete"],
                "containmentRequired": case_result["containmentRequired"],
                "result": {
                    "path": f"cases/{case_id}/result.json",
                    "sha256": runner.sha256_file(
                        case_dir / "result.json"
                    ),
                },
                "manifest": {
                    "path": f"cases/{case_id}/artifact-manifest.sha256",
                    "sha256": runner.sha256_file(
                        case_dir / "artifact-manifest.sha256"
                    ),
                },
            }
            aggregate = runner.aggregate_campaign(
                [summary],
                owner_phase="O0",
                sequences=self.profile["requiredSequences"],
                minimum_repeats=self.profile["minimumRepeats"],
            )
            aggregate["observationState"] = (
                runner.OBSERVATION_INCONCLUSIVE
            )
            source_hashes = runner.load_json(
                case_dir / "source-and-binary-hashes.json"
            )
            runner.save_json(
                root / "source-and-binary-hashes.json",
                source_hashes,
            )
            campaign_result = {
                "schemaVersion": runner.SCHEMA_VERSION,
                "modelId": runner.RUNNER_MODEL_ID,
                "runId": campaign_id,
                "ownerPhase": "O0",
                "gate": "g101",
                "sequences": self.profile["requiredSequences"],
                "repeat": self.profile["minimumRepeats"],
                "oracleProfile": profile_binding,
                "executionPolicy": execution_policy,
                "plannedCaseIds": [
                    item["caseId"] for item in plan_cases
                ],
                "cases": [summary],
                "incompletePlan": [
                    item["caseId"] for item in plan_cases[1:]
                ],
                "boundaryStop": runner.build_boundary_stop(
                    execution_policy,
                    [item["caseId"] for item in plan_cases],
                ),
                "aggregate": aggregate,
                "environment": source_hashes["environment"],
                "sourceAndBinaryHashes": source_hashes,
                "claimBoundary": runner.case_claim_boundary(),
            }
            runner.save_json(root / "campaign-plan.json", plan)
            runner.save_json(root / "result.json", campaign_result)
            (root / "result.json.sha256").write_text(
                f"{runner.sha256_file(root / 'result.json')}  result.json\n",
                encoding="ascii",
            )
            write_root_manifest(root)
            verification = runner.verify_campaign(root)
            self.assertTrue(verification["verified"])
            self.assertEqual(
                verification["completionClass"],
                "INTENTIONAL_PREFIX",
            )
            self.assertFalse(verification["fullPlanComplete"])

            original_boundary_stop = copy.deepcopy(
                campaign_result.pop("boundaryStop")
            )
            runner.save_json(root / "result.json", campaign_result)
            (root / "result.json.sha256").write_text(
                f"{runner.sha256_file(root / 'result.json')}  result.json\n",
                encoding="ascii",
            )
            write_root_manifest(root)
            with self.assertRaisesRegex(
                runner.ManifestError,
                "no manifest-bound termination cause",
            ):
                runner.verify_campaign(root)
            campaign_result["boundaryStop"] = copy.deepcopy(
                original_boundary_stop
            )

            campaign_result["boundaryStop"]["remainingCaseIds"] = (
                campaign_result["boundaryStop"]["remainingCaseIds"][1:]
            )
            runner.save_json(root / "result.json", campaign_result)
            (root / "result.json.sha256").write_text(
                f"{runner.sha256_file(root / 'result.json')}  result.json\n",
                encoding="ascii",
            )
            write_root_manifest(root)
            with self.assertRaisesRegex(
                runner.ManifestError,
                "completed-prefix partition",
            ):
                runner.verify_campaign(root)
            campaign_result["boundaryStop"] = copy.deepcopy(
                original_boundary_stop
            )

            campaign_result["cleanupStop"] = {
                "afterCase": case_id,
                "remainingCaseIds": campaign_result["incompletePlan"],
                "requiredAction": "fixture",
            }
            runner.save_json(root / "result.json", campaign_result)
            (root / "result.json.sha256").write_text(
                f"{runner.sha256_file(root / 'result.json')}  result.json\n",
                encoding="ascii",
            )
            write_root_manifest(root)
            with self.assertRaisesRegex(
                runner.ManifestError,
                "mutually exclusive termination causes",
            ):
                runner.verify_campaign(root)
            del campaign_result["cleanupStop"]

            runner.save_json(root / "result.json", campaign_result)
            (root / "result.json.sha256").write_text(
                f"{runner.sha256_file(root / 'result.json')}  result.json\n",
                encoding="ascii",
            )
            write_root_manifest(root)
            original_repeat_index = plan["cases"][-1]["repeatIndex"]
            plan["cases"][-1]["repeatIndex"] = 999
            runner.save_json(root / "campaign-plan.json", plan)
            write_root_manifest(root)
            with self.assertRaises(runner.ManifestError):
                runner.verify_campaign(root)
            plan["cases"][-1]["repeatIndex"] = original_repeat_index
            runner.save_json(root / "campaign-plan.json", plan)

            campaign_result["cases"][0]["verdict"] = "DIVERGED"
            runner.save_json(root / "result.json", campaign_result)
            (root / "result.json.sha256").write_text(
                f"{runner.sha256_file(root / 'result.json')}  result.json\n",
                encoding="ascii",
            )
            write_root_manifest(root)
            with self.assertRaises(runner.ManifestError):
                runner.verify_campaign(root)


if __name__ == "__main__":
    unittest.main()
