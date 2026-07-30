#!/usr/bin/env python3
"""Run Correctable-only PCIe AER root-state sequences around nested ESXi.

This is a black-box compatibility runner for an isolated, authorized lab.  It
uses only public PCI configuration registers, stock QEMU HMP/QTest controls,
ESXi public inventory/API surfaces, guest-visible configuration space, and
bounded logs.  It does not infer or reconstruct VMware private code.

The stimulus surface is deliberately closed:

* Receiver Error (B0) and Bad TLP (B1) are the only injectable bits.
* Every injection is ``pcie_aer_inject_error -c``.
* QTest writes are limited to Correctable status/mask/reporting fields and
  their upstream Correctable route controls.
* Any Uncorrectable state or non-CED Device Status bit stops the campaign.

One invocation accepts exactly one owner phase.  O0 and O4 require different
preconfigured ESXi owner states and must never be auto-transitioned inside one
experiment.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import copy
import gc
import hashlib
import importlib.metadata
import json
import math
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

from jsonschema import Draft202012Validator

import esxi_log_window_v2 as log_v2
import test_esxi_aer_correctable_matrix as esxi_aer
import test_qemu_aer_correctable_matrix as qemu_aer
import test_qemu_aer_root_sequence as qemu_sequence
from esxi_passthru_capability import EsxiSsh, caveat_field, hmp_command


SCRIPT_DIR = Path(__file__).resolve().parent
REPOSITORY_ROOT = SCRIPT_DIR.parent
DEFAULT_ORACLE_PROFILE = (
    REPOSITORY_ROOT
    / "contracts"
    / "vmware-aer-root-sequence-public-model-candidate-v1.json"
)
ORACLE_PROFILE_SCHEMA = (
    REPOSITORY_ROOT
    / "contracts"
    / "vmware-aer-root-sequence-oracle-profile.schema.json"
)
DEFAULT_LOCAL_AER_ISO = (
    REPOSITORY_ROOT.parent / "_artifacts" / "esxi-l3-aer-probe.iso"
)
DEFAULT_LOCAL_AER_ISO_ATTESTATION = Path(
    str(DEFAULT_LOCAL_AER_ISO) + ".build.json"
)
EXPECTED_AER_GUEST_KERNEL_RELEASE = "5.15.0-185-generic"
DEFAULT_OUTER_ENDPOINT_BDF = "0000:01:00.1"
DEFAULT_OUTER_ROOT_BDF = "0000:00:08.0"

SCHEMA_VERSION = 1
RUNNER_MODEL_ID = "VMW-DIRECTPATH-AER-ROOT-SEQUENCE-BLACKBOX-V1"
EXECUTION_POLICY_VERSION = 1
EXECUTION_MODE_FULL_PROFILE = "FULL_PROFILE"
EXECUTION_MODE_STOP_AFTER_CASE = "STOP_AFTER_CASE"
CAMPAIGN_TERMINATION_FIELDS = (
    "safetyStop",
    "cleanupStop",
    "blockedStop",
    "boundaryStop",
    "fault",
)
BOUNDARY_REQUIRED_ACTION = (
    "verify and review this bounded campaign offline; start a fresh "
    "unbounded campaign only after explicit acceptance"
)
SEQUENCES = qemu_sequence.SEQUENCES
BEHAVIOR_LABELS = {
    "first-multiple": (
        "first-window-observation",
        "stable-after-repeat",
    ),
    "independent-w1c": (
        "initial-window",
        "after-endpoint-clear-only",
        "after-root-clear-only",
    ),
    "bit-or": ("stable-after-or",),
    "rearm": ("initial-window", "rearmed-window"),
}
OWNER_PHASES = {
    "O0": {
        "runnerOwnerState": "Native",
        "currentOwner": "VMkernel",
        "activeUsers": "NONE",
    },
    "O4": {
        "runnerOwnerState": "PassthruActive",
        "currentOwner": "VM Passthru",
        "activeUsers": "EXACTLY_ONE_RUNNER_CREATED_VM",
    },
}
SUPPORTED_GATES = {
    "g100": esxi_aer.GateTuple(True, False, False),
    "g101": esxi_aer.GateTuple(True, False, True),
}

B0_NAME = "receiver_error"
B1_NAME = "bad_tlp"
B0 = esxi_aer.SAFE_CORRECTABLE_BITS[B0_NAME]
B1 = esxi_aer.SAFE_CORRECTABLE_BITS[B1_NAME]
CONTROLLED_BITS = B0 | B1
SAFE_INJECTION_BITS = {B0_NAME: B0, B1_NAME: B1}

OBSERVATION_MATCH = "MATCH"
OBSERVATION_DIVERGED = "DIVERGED"
OBSERVATION_INCONCLUSIVE = "INCONCLUSIVE"
OBSERVATION_BLOCKED = "BLOCKED"
OBSERVATION_STATES = {
    OBSERVATION_MATCH,
    OBSERVATION_DIVERGED,
    OBSERVATION_INCONCLUSIVE,
    OBSERVATION_BLOCKED,
}

LOG_PATHS = {
    "vmkernel": "/var/run/log/vmkernel.log",
    "vobd": "/var/run/log/vobd.log",
    "syslog": "/var/run/log/syslog.log",
}
REQUIRED_CASE_ARTIFACTS = {
    "case.json",
    "run-manifest.json",
    "source-and-binary-hashes.json",
    "t0-baseline.json",
    "t1-effective-controls.json",
    "t2-pre-injection.json",
    "t3-immediate.json",
    "t4-window.json",
    "t5-transition-or-clear.json",
    "evaluation-input.json",
    "oracle.json",
    "hmp.txt",
    "cleanup.json",
    "result.json",
    "artifact-manifest.sha256",
}
REQUIRED_CAMPAIGN_ARTIFACTS = {
    "campaign-plan.json",
    "oracle-profile.json",
    "oracle-profile.schema.json",
    "result.json",
    "result.json.sha256",
}
SAFETY_ARTIFACT_BOUNDARIES = {
    "t0-baseline.json": "PRE_INJECTION",
    "t1-effective-controls.json": "PRE_INJECTION",
    "t3-immediate.json": "ATTRIBUTION_WINDOW",
    "t4-window.json": "ATTRIBUTION_WINDOW",
    "cleanup.json": "POST_CLEANUP",
    "raw-esxi/t0-baseline/phase.json": "PRE_INJECTION",
    "raw-esxi/t4-terminal/phase.json": "ATTRIBUTION_WINDOW",
}
SAFETY_BOUNDARIES = {
    "PRE_INJECTION",
    "ATTRIBUTION_WINDOW",
    "POST_CLEANUP",
}
SAFETY_DERIVED_KEYS = {
    # These are evaluator summaries or diagnostic copies, never independent
    # numeric authority.  In particular, runtimeSafetyFaults may contain a
    # copied snapshot and must not feed itself back into POST_CLEANUP evidence.
    "evaluationEvidence",
    "runtimeSafetyFaults",
    "containment",
    "containmentEvidence",
    "hostProjection",
}
CASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]+$")
QEMU_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
EXPECTED_PCI_ID_RE = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$")
BOOT_ID_RE = re.compile(r"^[0-9a-fA-F-]{8,64}$")


class FixtureInvalid(RuntimeError):
    """The controlled QEMU stimulus was not valid enough to compare ESXi."""


class ManifestError(ValueError):
    """A raw artifact manifest is incomplete or has drifted."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def stamp_finished_at(record: dict[str, Any]) -> dict[str, str] | None:
    """Best-effort evidence timestamp that can never erase prior raw facts."""

    try:
        record["finishedAt"] = utc_now()
        record.setdefault("finalizationFault", None)
        return None
    except BaseException as error:
        fault = {
            "type": type(error).__name__,
            "message": str(error),
        }
        record["finishedAt"] = None
        record["finalizationFault"] = fault
        return fault


def arm_runnable_gc_guard() -> dict[str, Any]:
    """Collect while paused, then suppress cyclic-GC stalls while runnable."""

    was_enabled = gc.isenabled()
    record: dict[str, Any] = {
        "wasEnabled": was_enabled,
        "thresholds": list(gc.get_threshold()),
        "countsBefore": list(gc.get_count()),
        "preResumeCollected": None,
        "disabledBeforeResume": False,
        "armedAt": None,
        "releaseState": "ARMING",
        "postPauseCollected": None,
        "releasedAt": None,
        "fault": None,
    }
    try:
        record["preResumeCollected"] = gc.collect()
        gc.disable()
        record["disabledBeforeResume"] = not gc.isenabled()
        if not record["disabledBeforeResume"]:
            raise RuntimeError("cyclic GC remained enabled")
        record["armedAt"] = (
            datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
        record["releaseState"] = "ARMED"
        return record
    except BaseException as error:
        if was_enabled:
            gc.enable()
        record["fault"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        record["releaseState"] = "ARM_FAILED"
        raise


def release_runnable_gc_guard(
    record: dict[str, Any],
    *,
    paused_confirmed: bool,
) -> dict[str, str] | None:
    """Restore cyclic GC only after the runnable window has a paused ACK."""

    if not paused_confirmed:
        record["releaseState"] = "DEFERRED_STOP_UNCONFIRMED"
        return None
    try:
        if record.get("wasEnabled") is True:
            gc.enable()
            record["postPauseCollected"] = gc.collect()
        record["releasedAt"] = (
            datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
        record["releaseState"] = (
            "REENABLED_AFTER_PAUSE"
            if record.get("wasEnabled") is True
            else "LEFT_DISABLED_AS_FOUND"
        )
        return None
    except BaseException as error:
        fault = {
            "type": type(error).__name__,
            "message": str(error),
        }
        record["fault"] = fault
        record["releaseState"] = "RELEASE_FAILED"
        return fault


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def installed_distribution_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def save_json(path: Path, value: Any) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(
        value,
        indent=2,
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
    ) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")
    return sha256_bytes(text.encode("utf-8"))


def save_text(path: Path, value: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8", newline="\n")
    return sha256_bytes(value.encode("utf-8"))


def load_json(path: Path) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=lambda token: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON number {token!r} in {path}")
        ),
    )
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")

    def reject_non_finite(item: Any, json_path: str) -> None:
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError(
                f"non-finite JSON number at {json_path} in {path}"
            )
        if isinstance(item, dict):
            for key, child in item.items():
                reject_non_finite(child, f"{json_path}/{key}")
        elif isinstance(item, list):
            for index, child in enumerate(item):
                reject_non_finite(child, f"{json_path}/{index}")

    reject_non_finite(value, "")
    return value


def load_oracle_profile(
    path: Path,
    schema_path: Path = ORACLE_PROFILE_SCHEMA,
) -> dict[str, Any]:
    profile = load_json(path)
    schema = load_json(schema_path)
    errors = sorted(
        Draft202012Validator(schema).iter_errors(profile),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        details = "; ".join(
            f"{'/'.join(str(item) for item in error.absolute_path) or '<root>'}: "
            f"{error.message}"
            for error in errors
        )
        raise ValueError(f"invalid oracle profile {path}: {details}")
    for owner_phase in OWNER_PHASES:
        for sequence, required_labels in BEHAVIOR_LABELS.items():
            configured = profile["expectedStates"][owner_phase][sequence]
            if set(configured) != set(required_labels):
                raise ValueError(
                    f"invalid oracle profile {path}: "
                    f"{owner_phase}/{sequence} expected labels "
                    f"{sorted(configured)} differ from "
                    f"{sorted(required_labels)}"
                )
    return profile


def extract_iso_member(
    iso_path: Path,
    member: str,
    destination: Path,
) -> None:
    xorriso = shutil.which("xorriso")
    if xorriso is None:
        raise ValueError(
            "xorriso is required to verify embedded AER ISO contents"
        )
    result = subprocess.run(
        [
            xorriso,
            "-osirrox",
            "on",
            "-indev",
            str(iso_path),
            "-extract",
            member,
            str(destination),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0 or not destination.is_file():
        raise ValueError(
            f"could not extract {member} from the AER ISO: "
            f"rc={result.returncode}, stderr={result.stderr.strip()!r}"
        )


def load_aer_iso_attestation(
    path: Path,
    iso_path: Path,
    timing_envelope: dict[str, Any],
) -> dict[str, Any]:
    value = load_json(path)
    if value.get("schemaVersion") != 1 or value.get("profile") != "aer":
        raise ValueError(
            "AER ISO attestation must be schemaVersion=1/profile=aer"
        )
    if value.get("kernelRelease") != EXPECTED_AER_GUEST_KERNEL_RELEASE:
        raise ValueError(
            "AER ISO attestation has an unexpected guest kernel release"
        )
    iso = value.get("iso")
    if not isinstance(iso, dict):
        raise ValueError("AER ISO attestation lacks an iso object")
    actual_iso_hash = sha256_file(iso_path)
    if iso.get("sha256") != actual_iso_hash:
        raise ValueError(
            "local AER ISO hash differs from its build attestation"
        )
    aer = value.get("aer")
    if (
        not isinstance(aer, dict)
        or aer.get("runnerManaged") is not True
        or aer.get("windowSeconds")
        != timing_envelope["guestWindowSeconds"]
        or aer.get("runnerWatchdogGraceSeconds")
        != timing_envelope["runnerWatchdogGraceSeconds"]
    ):
        raise ValueError(
            "AER ISO timing/watchdog attestation differs from the oracle profile"
        )
    inputs = value.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        raise ValueError("AER ISO attestation has no build inputs")
    by_name: dict[str, list[str]] = {}
    for index, item in enumerate(inputs):
        if not isinstance(item, dict):
            raise ValueError(f"AER ISO input {index} is not an object")
        raw_path = item.get("path")
        digest = item.get("sha256")
        if (
            not isinstance(raw_path, str)
            or not re.fullmatch(r"[0-9a-f]{64}", str(digest))
        ):
            raise ValueError(f"AER ISO input {index} is malformed")
        by_name.setdefault(Path(raw_path).name, []).append(str(digest))
    required_current_inputs = {
        "build-esxi-l3-probe-iso.sh": sha256_file(
            SCRIPT_DIR / "build-esxi-l3-probe-iso.sh"
        ),
        "esxi-l3-aer-init.sh": sha256_file(
            SCRIPT_DIR / "esxi-l3-aer-init.sh"
        ),
    }
    required_embedded_inputs = {
        "e1000e.ko",
        "failover.ko",
        "net_failover.ko",
        "virtio_net.ko",
        "grub.cfg",
        "initrd.cpio",
        "vmlinuz",
    }
    for name, expected in required_current_inputs.items():
        if by_name.get(name) != [expected]:
            raise ValueError(
                f"AER ISO attestation does not bind current {name}"
            )
    malformed_embedded = sorted(
        name
        for name in required_embedded_inputs
        if len(by_name.get(name, [])) != 1
    )
    expected_config_name = (
        f"config-{EXPECTED_AER_GUEST_KERNEL_RELEASE}"
    )
    if len(by_name.get(expected_config_name, [])) != 1:
        malformed_embedded.append(expected_config_name)
    if malformed_embedded:
        raise ValueError(
            "AER ISO attestation lacks unique required build inputs: "
            + ", ".join(malformed_embedded)
        )

    with tempfile.TemporaryDirectory(
        prefix="esxi-aer-iso-verify-"
    ) as temporary:
        verify_root = Path(temporary)
        embedded_grub = verify_root / "grub.cfg"
        embedded_initrd = verify_root / "initrd.cpio"
        embedded_kernel = verify_root / "vmlinuz"
        extract_iso_member(
            iso_path,
            "/boot/grub/grub.cfg",
            embedded_grub,
        )
        extract_iso_member(
            iso_path,
            "/boot/initrd.cpio",
            embedded_initrd,
        )
        extract_iso_member(
            iso_path,
            "/boot/vmlinuz",
            embedded_kernel,
        )
        direct_members = {
            "grub.cfg": embedded_grub,
            "initrd.cpio": embedded_initrd,
            "vmlinuz": embedded_kernel,
        }
        for name, member_path in direct_members.items():
            if by_name[name] != [sha256_file(member_path)]:
                raise ValueError(
                    f"AER ISO embedded {name} differs from its attested input"
                )

        grub_text = embedded_grub.read_text(
            encoding="utf-8",
            errors="strict",
        )
        expected_grub_tokens = (
            f"aer_window_seconds={timing_envelope['guestWindowSeconds']}",
            "aer_runner_managed=1",
            "aer_runner_grace_seconds="
            f"{timing_envelope['runnerWatchdogGraceSeconds']}",
        )
        if any(grub_text.count(token) != 1 for token in expected_grub_tokens):
            raise ValueError(
                "AER ISO embedded GRUB command line does not contain the "
                "unique attested window/watchdog tuple"
            )

        cpio = shutil.which("cpio")
        if cpio is None:
            raise ValueError(
                "cpio is required to verify the embedded AER initrd"
            )
        initrd_root = verify_root / "initrd"
        initrd_root.mkdir()
        unpack = subprocess.run(
            [cpio, "-id", "--quiet"],
            cwd=initrd_root,
            input=embedded_initrd.read_bytes(),
            capture_output=True,
            timeout=120,
            check=False,
        )
        if unpack.returncode != 0:
            raise ValueError(
                "could not unpack the embedded AER initrd: "
                + unpack.stderr.decode("utf-8", errors="replace")
            )
        embedded_init = initrd_root / "init"
        if (
            not embedded_init.is_file()
            or sha256_file(embedded_init)
            != required_current_inputs["esxi-l3-aer-init.sh"]
        ):
            raise ValueError(
                "AER ISO initrd does not embed the current AER init script"
            )
        for module_name in (
            "e1000e.ko",
            "failover.ko",
            "net_failover.ko",
            "virtio_net.ko",
        ):
            module_path = initrd_root / "lib" / "modules" / module_name
            if (
                not module_path.is_file()
                or by_name[module_name] != [sha256_file(module_path)]
            ):
                raise ValueError(
                    "AER ISO initrd module differs from its attested input: "
                    f"{module_name}"
                )
    return {
        "path": str(path),
        "sha256": sha256_file(path),
        "isoPath": str(iso_path),
        "isoSha256": actual_iso_hash,
        "value": value,
    }


def build_case_plan(
    *,
    owner_phase: str,
    gate: str,
    sequences: Iterable[str],
    repeat: int,
) -> list[dict[str, Any]]:
    if owner_phase not in OWNER_PHASES:
        raise ValueError(f"unsupported owner phase: {owner_phase}")
    if gate not in SUPPORTED_GATES:
        raise ValueError(f"unsupported gate: {gate}")
    if repeat <= 0:
        raise ValueError("repeat must be positive")
    selected = list(sequences)
    if not selected:
        raise ValueError("at least one sequence is required")
    if len(selected) != len(set(selected)):
        raise ValueError("sequence selections must be unique")
    unknown = sorted(set(selected) - set(SEQUENCES))
    if unknown:
        raise ValueError(f"unknown sequence selections: {unknown}")
    plan: list[dict[str, Any]] = []
    for sequence in selected:
        for repeat_index in range(1, repeat + 1):
            case_id = (
                f"{owner_phase.lower()}__{sequence}__{gate}__r{repeat_index:02d}"
            )
            if not CASE_ID_RE.fullmatch(case_id):
                raise AssertionError(f"generated unsafe case ID: {case_id}")
            plan.append(
                {
                    "caseId": case_id,
                    "ownerPhase": owner_phase,
                    "sequence": sequence,
                    "gate": gate,
                    "repeatIndex": repeat_index,
                }
            )
    return plan


def build_execution_policy(
    cases: list[dict[str, Any]],
    stop_after_case: str | None,
) -> dict[str, Any]:
    planned_ids = [item["caseId"] for item in cases]
    if stop_after_case is None:
        return {
            "version": EXECUTION_POLICY_VERSION,
            "mode": EXECUTION_MODE_FULL_PROFILE,
            "stopAfterCaseId": None,
            "stopAfterOrdinal": None,
        }
    if (
        not isinstance(stop_after_case, str)
        or not CASE_ID_RE.fullmatch(stop_after_case)
    ):
        raise ValueError("stop-after case ID is unsafe")
    if stop_after_case not in planned_ids:
        raise ValueError(
            "stop-after case is not in the deterministic plan: "
            f"{stop_after_case}"
        )
    ordinal = planned_ids.index(stop_after_case) + 1
    if ordinal == len(planned_ids):
        raise ValueError(
            "stop-after case cannot be the final planned case; omit the "
            "boundary for a full campaign"
        )
    return {
        "version": EXECUTION_POLICY_VERSION,
        "mode": EXECUTION_MODE_STOP_AFTER_CASE,
        "stopAfterCaseId": stop_after_case,
        "stopAfterOrdinal": ordinal,
    }


def build_boundary_stop(
    execution_policy: dict[str, Any],
    planned_ids: list[str],
) -> dict[str, Any]:
    if execution_policy.get("mode") != EXECUTION_MODE_STOP_AFTER_CASE:
        raise ValueError("boundary stop requires a STOP_AFTER_CASE policy")
    ordinal = execution_policy.get("stopAfterOrdinal")
    target = execution_policy.get("stopAfterCaseId")
    if (
        not isinstance(ordinal, int)
        or isinstance(ordinal, bool)
        or ordinal <= 0
        or ordinal >= len(planned_ids)
        or not isinstance(target, str)
        or planned_ids[ordinal - 1] != target
    ):
        raise ValueError("boundary stop policy differs from the case plan")
    return {
        "kind": "REQUESTED_CASE_BOUNDARY",
        "afterCase": target,
        "completedCaseCount": ordinal,
        "remainingCaseIds": planned_ids[ordinal:],
        "requiredAction": BOUNDARY_REQUIRED_ACTION,
    }


def outer_to_public_state(snapshot: dict[str, Any]) -> dict[str, dict[str, int]]:
    return {
        "endpoint": copy.deepcopy(snapshot["endpointState"]),
        "rootPort": copy.deepcopy(snapshot["rootState"]),
    }


PUBLIC_SNAPSHOT_FIELDS = {
    "endpoint": {
        "deviceControl",
        "deviceStatus",
        "uncorrectableErrorStatus",
        "correctableErrorStatus",
        "correctableErrorMask",
    },
    "rootPort": {
        "bridgeControl",
        "deviceControl",
        "deviceStatus",
        "uncorrectableErrorStatus",
        "correctableErrorStatus",
        "correctableErrorMask",
        "rootErrorCommand",
        "rootErrorStatus",
        "errorSourceIdentification",
    },
}


def public_snapshot_shape_faults(
    snapshots: dict[str, Any],
) -> list[str]:
    """Return structural faults before invoking the strict public-model oracle."""

    faults: list[str] = []
    for label, state in snapshots.items():
        if not isinstance(label, str) or not isinstance(state, dict):
            faults.append(f"{label!r}: snapshot is not an object")
            continue
        for section, required_fields in PUBLIC_SNAPSHOT_FIELDS.items():
            values = state.get(section)
            if not isinstance(values, dict):
                faults.append(f"{label}:{section} is not an object")
                continue
            for field_name in sorted(required_fields):
                value = values.get(field_name)
                if not isinstance(value, int) or isinstance(value, bool):
                    faults.append(
                        f"{label}:{section}.{field_name} is not an integer"
                    )
    return faults


def root_source_meaning(state: dict[str, Any]) -> dict[str, Any]:
    root = state["rootPort"]
    status = int(root["rootErrorStatus"])
    meaningful = bool(status & qemu_aer.PCI_ERR_ROOT_COR_RCV)
    return {
        "rootErrorStatus": status,
        "source": int(root["errorSourceIdentification"]),
        "meaningful": meaningful,
        "correctableRequesterId": (
            int(root["errorSourceIdentification"]) & 0xFFFF
            if meaningful
            else None
        ),
    }


def source_qualified_snapshots(
    snapshots: dict[str, dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Apply the preregistered rule that Source is meaningless without COR_RCV.

    The returned copy is only for reuse of the QEMU positive-control oracle.
    Raw Source values remain unmodified in every artifact.
    """

    normalized = copy.deepcopy(snapshots)
    qualifications: dict[str, Any] = {}
    for label, state in normalized.items():
        meaning = root_source_meaning(state)
        qualifications[label] = meaning
        if not meaning["meaningful"]:
            state["rootPort"]["errorSourceIdentification"] = 0
    return normalized, qualifications


def fixture_projection(
    sequence: str,
    snapshots: dict[str, dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Project only paused immediate states into the public QEMU fixture oracle."""

    required = {
        "first-multiple": (
            "effective-controls",
            "pre-injection",
            "first-b0",
            "repeated-b0",
        ),
        "independent-w1c": (
            "effective-controls",
            "pre-injection",
            "initial-b0",
            "after-endpoint-clear-only-immediate",
            "after-root-cleanup-for-rebuild",
            "rebuilt-b0",
            "after-root-clear-only-immediate",
        ),
        "bit-or": (
            "effective-controls",
            "pre-injection",
            "first-b0",
            "second-b1",
        ),
        "rearm": (
            "effective-controls",
            "pre-injection",
            "initial-b0",
            "after-ces-clear-only",
            "after-ced-clear-only",
            "after-root-clear",
            "rearmed-b0",
        ),
    }[sequence]
    missing = [label for label in required if label not in snapshots]
    if missing:
        return {}, missing
    projected = {
        label: copy.deepcopy(snapshots[label])
        for label in required
    }
    projected["post-cleanup"] = copy.deepcopy(
        snapshots["pre-injection"]
    )
    if sequence == "first-multiple":
        projected["stable-after-repeat"] = copy.deepcopy(
            snapshots["repeated-b0"]
        )
    elif sequence == "independent-w1c":
        projected["initial-window"] = copy.deepcopy(
            snapshots["initial-b0"]
        )
        projected["after-endpoint-clear-only"] = copy.deepcopy(
            snapshots["after-endpoint-clear-only-immediate"]
        )
        projected["after-root-clear-only"] = copy.deepcopy(
            snapshots["after-root-clear-only-immediate"]
        )
    elif sequence == "bit-or":
        projected["stable-after-or"] = copy.deepcopy(
            snapshots["second-b1"]
        )
    elif sequence == "rearm":
        projected["initial-window"] = copy.deepcopy(
            snapshots["initial-b0"]
        )
        projected["rearmed-window"] = copy.deepcopy(
            snapshots["rearmed-b0"]
        )
    return projected, []


def canonical_behavior_state(
    state: dict[str, Any],
) -> dict[str, Any]:
    endpoint = state["endpoint"]
    root = state["rootPort"]
    root_status = int(root["rootErrorStatus"]) & qemu_aer.PCI_ERR_ROOT_STATUS_W1C
    return {
        "endpointCorrectableStatus": int(
            endpoint["correctableErrorStatus"]
        ),
        "endpointCed": bool(
            int(endpoint["deviceStatus"]) & qemu_aer.PCI_EXP_DEVSTA_CED
        ),
        "rootErrorStatus": root_status,
        "rootSource": (
            int(root["errorSourceIdentification"]) & 0xFFFF
            if root_status & qemu_aer.PCI_ERR_ROOT_COR_RCV
            else None
        ),
        "endpointCere": bool(
            int(endpoint["deviceControl"]) & qemu_aer.PCI_EXP_DEVCTL_CERE
        ),
        "controlledBitsMasked": bool(
            int(endpoint["correctableErrorMask"]) & CONTROLLED_BITS
        ),
        "rootCorEnabled": bool(
            int(root["rootErrorCommand"]) & qemu_aer.PCI_ERR_ROOT_CMD_COR_EN
        ),
        "rootPathOpen": bool(
            int(root["bridgeControl"]) & qemu_aer.PCI_BRIDGE_CTL_SERR
        )
        and bool(
            int(root["deviceControl"]) & qemu_aer.PCI_EXP_DEVCTL_CERE
        ),
    }


def behavior_state_matches(
    observed: dict[str, Any],
    expected: dict[str, Any],
    requester_id: int,
) -> bool:
    for field_name in (
        "endpointCorrectableStatus",
        "endpointCed",
        "rootErrorStatus",
        "endpointCere",
        "controlledBitsMasked",
        "rootCorEnabled",
        "rootPathOpen",
    ):
        if observed[field_name] != expected[field_name]:
            return False
    source_policy = expected["rootSource"]
    if source_policy == "REQUESTER_ID":
        return observed["rootSource"] == requester_id
    if source_policy == "ZERO":
        return observed["rootSource"] == 0
    if source_policy == "IGNORED_WITHOUT_COR_RCV":
        return observed["rootSource"] is None
    return False


def evaluate_profile_behavior(
    *,
    profile: dict[str, Any],
    owner_phase: str,
    sequence: str,
    requester_id: int,
    snapshots: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    vectors = profile["expectedStates"][owner_phase][sequence]
    checks: dict[str, bool] = {}
    observed_states: dict[str, Any] = {}
    missing: list[str] = []
    for label in BEHAVIOR_LABELS[sequence]:
        state = snapshots.get(label)
        if not isinstance(state, dict):
            missing.append(label)
            continue
        observed = canonical_behavior_state(state)
        observed_states[label] = observed
        checks[f"{label}:matches-profile-allowed-state"] = any(
            behavior_state_matches(observed, expected, requester_id)
            for expected in vectors[label]
        )
    return {
        "profileState": profile["profileState"],
        "ownerPhase": owner_phase,
        "sequence": sequence,
        "requiredLabels": list(BEHAVIOR_LABELS[sequence]),
        "missingLabels": missing,
        "checks": checks,
        "failedChecks": sorted(
            name for name, passed in checks.items() if not passed
        ),
        "observedStates": observed_states,
        "allowedStates": copy.deepcopy(vectors),
    }


def fixture_expected_states() -> dict[str, dict[str, Any]]:
    def expected(
        ces: int,
        ced: bool,
        root_status: int,
        source: str,
    ) -> dict[str, Any]:
        return {
            "endpointCorrectableStatus": ces,
            "endpointCed": ced,
            "rootErrorStatus": root_status,
            "rootSource": source,
            "endpointCere": True,
            "controlledBitsMasked": False,
            "rootCorEnabled": True,
            "rootPathOpen": True,
        }

    return {
        "first-b0": expected(
            B0, True, qemu_sequence.ROOT_COR_FIRST, "REQUESTER_ID"
        ),
        "initial-b0": expected(
            B0, True, qemu_sequence.ROOT_COR_FIRST, "REQUESTER_ID"
        ),
        "rebuilt-b0": expected(
            B0, True, qemu_sequence.ROOT_COR_FIRST, "REQUESTER_ID"
        ),
        "rearmed-b0": expected(
            B0, True, qemu_sequence.ROOT_COR_FIRST, "REQUESTER_ID"
        ),
        "repeated-b0": expected(
            B0, True, qemu_sequence.ROOT_COR_MULTIPLE, "REQUESTER_ID"
        ),
        "second-b1": expected(
            B0 | B1,
            True,
            qemu_sequence.ROOT_COR_MULTIPLE,
            "REQUESTER_ID",
        ),
        "after-endpoint-clear-only-immediate": expected(
            0, False, qemu_sequence.ROOT_COR_FIRST, "REQUESTER_ID"
        ),
        "after-root-cleanup-for-rebuild": expected(
            0, False, 0, "IGNORED_WITHOUT_COR_RCV"
        ),
        "after-root-clear-only-immediate": expected(
            B0, True, 0, "IGNORED_WITHOUT_COR_RCV"
        ),
        "after-ces-clear-only": expected(
            0, True, qemu_sequence.ROOT_COR_FIRST, "REQUESTER_ID"
        ),
        "after-ced-clear-only": expected(
            0, False, qemu_sequence.ROOT_COR_FIRST, "REQUESTER_ID"
        ),
        "after-root-clear": expected(
            0, False, 0, "IGNORED_WITHOUT_COR_RCV"
        ),
    }


FIXTURE_REQUIRED_LABELS = {
    "first-multiple": (
        "effective-controls",
        "pre-injection",
        "first-b0",
        "repeated-b0",
    ),
    "independent-w1c": (
        "effective-controls",
        "pre-injection",
        "initial-b0",
        "after-endpoint-clear-only-immediate",
        "after-root-cleanup-for-rebuild",
        "rebuilt-b0",
        "after-root-clear-only-immediate",
    ),
    "bit-or": (
        "effective-controls",
        "pre-injection",
        "first-b0",
        "second-b1",
    ),
    "rearm": (
        "effective-controls",
        "pre-injection",
        "initial-b0",
        "after-ces-clear-only",
        "after-ced-clear-only",
        "after-root-clear",
        "rearmed-b0",
    ),
}

def evaluate_fixture_observation(
    *,
    sequence: str,
    gate_name: str,
    requester_id: int,
    qemu_device: str,
    snapshots: dict[str, dict[str, Any]],
    injections: list[dict[str, Any]],
) -> dict[str, Any]:
    required = FIXTURE_REQUIRED_LABELS[sequence]
    missing_snapshots = [
        label for label in required if label not in snapshots
    ]
    expected_injections = qemu_sequence.expected_injection_labels(sequence)
    actual_injection_labels = [
        item.get("label") if isinstance(item, dict) else None
        for item in injections
    ]
    exact_injection_sequence = (
        actual_injection_labels == list(expected_injections)
    )
    injection_by_label = {
        str(item["label"]): item
        for item in injections
        if isinstance(item, dict) and isinstance(item.get("label"), str)
    }
    missing_injections = [
        label
        for label in expected_injections
        if label not in injection_by_label
    ]
    if (
        missing_snapshots
        or missing_injections
        or not exact_injection_sequence
    ):
        return {
            "modelId": qemu_sequence.MODEL_ID,
            "observationState": qemu_sequence.OBSERVATION_INCONCLUSIVE,
            "verdict": "INCONCLUSIVE",
            "missingSnapshots": missing_snapshots,
            "missingInjections": missing_injections,
            "expectedInjectionLabels": list(expected_injections),
            "actualInjectionLabels": actual_injection_labels,
            "checks": {},
        }

    controls = snapshots["effective-controls"]
    baseline = snapshots["pre-injection"]
    endpoint = controls["endpoint"]
    root = controls["rootPort"]
    gate = qemu_aer.GATES[gate_name]
    checks: dict[str, bool] = {
        "gate-supported": gate.name in qemu_sequence.SUPPORTED_GATES,
        "endpoint-cere-enabled": bool(
            int(endpoint["deviceControl"]) & qemu_aer.PCI_EXP_DEVCTL_CERE
        ),
        "b0-unmasked": not bool(
            int(endpoint["correctableErrorMask"]) & B0
        ),
        "b1-unmasked": not bool(
            int(endpoint["correctableErrorMask"]) & B1
        ),
        "root-bridge-serr-enabled": bool(
            int(root["bridgeControl"]) & qemu_aer.PCI_BRIDGE_CTL_SERR
        ),
        "root-cere-enabled": bool(
            int(root["deviceControl"]) & qemu_aer.PCI_EXP_DEVCTL_CERE
        ),
        "root-command-matches-gate": bool(
            int(root["rootErrorCommand"]) & qemu_aer.PCI_ERR_ROOT_CMD_COR_EN
        )
        == gate.root_cor_enable,
        "clean-endpoint-baseline": qemu_sequence.endpoint_exact(
            baseline,
            ces=0,
            ced=False,
        ),
        "clean-root-status-baseline": qemu_sequence.root_correctable_exact(
            baseline,
            root_status=0,
            requester_id=None,
        ),
    }
    for label in expected_injections:
        item = injection_by_label[label]
        bit_name, mask = (
            (B1_NAME, B1)
            if label == "second-b1"
            else (B0_NAME, B0)
        )
        expected_command = (
            f"pcie_aer_inject_error -c {qemu_device} 0x{mask:08x}"
        )
        checks[f"{label}:hmp-accepted"] = item.get("accepted") is True
        checks[f"{label}:correctable-bit-name"] = (
            item.get("bit") == bit_name
        )
        checks[f"{label}:exact-mask"] = (
            item.get("mask") == f"0x{mask:08x}"
        )
        checks[f"{label}:closed-correctable-command"] = (
            item.get("command") == expected_command
        )
    expectations = fixture_expected_states()
    for label in required:
        state = snapshots[label]
        checks.update(qemu_sequence.safety_checks(label, state))
        if label in expectations:
            observed = canonical_behavior_state(state)
            checks[f"{label}:paused-immediate-exact"] = (
                behavior_state_matches(
                    observed,
                    expectations[label],
                    requester_id,
                )
            )
    state = (
        qemu_sequence.OBSERVATION_MATCH
        if checks and all(checks.values())
        else qemu_sequence.OBSERVATION_DIVERGED
    )
    return {
        "modelId": qemu_sequence.MODEL_ID,
        "observationState": state,
        "verdict": (
            "PASS"
            if state == qemu_sequence.OBSERVATION_MATCH
            else "FAIL"
        ),
        "missingSnapshots": [],
        "missingInjections": [],
        "checks": checks,
        "failedChecks": sorted(
            name for name, passed in checks.items() if not passed
        ),
        "scope": (
            "Paused controls, HMP ACK/deposition and QTest W1C validity "
            "only; post-resume ESXi states are excluded."
        ),
    }


def expected_owner_checks(
    owner_phase: str,
    observations: list[dict[str, Any]],
) -> dict[str, bool]:
    expected = OWNER_PHASES.get(owner_phase)
    if expected is None:
        return {"owner-phase-supported": False}
    checks: dict[str, bool] = {}
    for index, item in enumerate(observations):
        prefix = f"owner-observation-{index:02d}"
        if not isinstance(item, dict):
            checks[f"{prefix}:object"] = False
            continue
        checks[f"{prefix}:current-owner"] = (
            item.get("currentOwner") == expected["currentOwner"]
        )
        users = item.get("activeUsers")
        if expected["activeUsers"] == "NONE":
            checks[f"{prefix}:no-active-users"] = users == []
        else:
            checks[f"{prefix}:one-runner-user"] = bool(
                isinstance(users, list)
                and len(users) == 1
                and isinstance(users[0], dict)
                and users[0].get("runnerCreated") is True
            )
        checks[f"{prefix}:host-responsive"] = (
            item.get("hostResponsive") is True
        )
    return checks


def host_projection_safety_faults(
    projection: dict[str, Any] | None,
) -> list[str]:
    """Return fail-stop faults from the ESXi raw view of the same AER pair."""

    if not isinstance(projection, dict):
        return []
    endpoint = projection.get("hostEndpoint")
    root = projection.get("hostRoot")
    if not isinstance(endpoint, dict) or not isinstance(root, dict):
        return []
    faults: list[str] = []
    try:
        endpoint_ues: int | None = int(endpoint["uncorrectableStatus"])
    except (KeyError, TypeError, ValueError):
        endpoint_ues = None
    try:
        root_ues: int | None = int(root["uncorrectableStatus"])
    except (KeyError, TypeError, ValueError):
        root_ues = None
    try:
        root_status: int | None = int(root["rootErrorStatus"])
    except (KeyError, TypeError, ValueError):
        root_status = None
    try:
        endpoint_device_status: int | None = int(endpoint["deviceStatus"])
    except (KeyError, TypeError, ValueError):
        endpoint_device_status = None
    try:
        root_device_status: int | None = int(root["deviceStatus"])
    except (KeyError, TypeError, ValueError):
        root_device_status = None
    # Parse each safety surface independently: one malformed peer field must
    # never erase a known non-zero Uncorrectable observation.
    if endpoint_ues:
        faults.append(f"ESXi endpoint UES=0x{endpoint_ues:08x}")
    if root_ues:
        faults.append(f"ESXi root UES=0x{root_ues:08x}")
    if endpoint_device_status is not None:
        endpoint_non_ced = endpoint_device_status & (
            qemu_aer.PCI_EXP_DEVSTA_ERROR_MASK
            ^ qemu_aer.PCI_EXP_DEVSTA_CED
        )
        if endpoint_non_ced:
            faults.append(
                "ESXi endpoint DeviceStatus non-CED="
                f"0x{endpoint_non_ced:04x}"
            )
    if root_device_status is not None:
        root_non_ced = root_device_status & (
            qemu_aer.PCI_EXP_DEVSTA_ERROR_MASK
            ^ qemu_aer.PCI_EXP_DEVSTA_CED
        )
        if root_non_ced:
            faults.append(
                "ESXi root DeviceStatus non-CED="
                f"0x{root_non_ced:04x}"
            )
    if root_status is not None:
        root_uncorrectable = (
            root_status & qemu_aer.PCI_ERR_ROOT_UNCOR_MASK
        )
        if root_uncorrectable:
            faults.append(
                "ESXi root uncorrectable reception="
                f"0x{root_uncorrectable:08x}"
            )
    return faults


def host_projection_checks(
    projection: dict[str, Any] | None,
) -> tuple[dict[str, bool], dict[str, Any]]:
    if not isinstance(projection, dict):
        return {}, {"complete": False, "reason": "missing host projection"}
    host_endpoint = projection.get("hostEndpoint")
    host_root = projection.get("hostRoot")
    outer_before = projection.get("outerBeforeRemote")
    outer_after = projection.get("outerAfterRemote")
    outer_samples_raw = projection.get("outerSamples")
    complete = all(
        isinstance(item, dict)
        for item in (host_endpoint, host_root, outer_before, outer_after)
    )
    if not complete:
        return {}, {
            "complete": False,
            "reason": "host/outer projection bracket is incomplete",
        }

    tuple_fields = (
        "endpointDeviceControl",
        "endpointDeviceStatus",
        "endpointUncorrectableStatus",
        "endpointCorrectableStatus",
        "endpointCorrectableMask",
        "rootBridgeControl",
        "rootDeviceControl",
        "rootDeviceStatus",
        "rootUncorrectableStatus",
        "rootCorrectableStatus",
        "rootCorrectableMask",
        "rootErrorCommand",
        "rootErrorStatus",
        "qualifiedRootSource",
    )

    def canonical_tuple(
        endpoint_device_control: int,
        endpoint_device_status: int,
        endpoint_ues: int,
        endpoint_ces: int,
        endpoint_mask: int,
        root_bridge_control: int,
        root_device_control: int,
        root_device_status: int,
        root_ues: int,
        root_ces: int,
        root_mask: int,
        root_command: int,
        root_status: int,
        root_source: int,
    ) -> tuple[int | None, ...]:
        qualified_source = (
            root_source & 0xFFFF
            if root_status & qemu_aer.PCI_ERR_ROOT_COR_RCV
            else None
        )
        return (
            endpoint_device_control,
            endpoint_device_status,
            endpoint_ues,
            endpoint_ces,
            endpoint_mask,
            root_bridge_control,
            root_device_control,
            root_device_status,
            root_ues,
            root_ces,
            root_mask,
            root_command,
            root_status,
            qualified_source,
        )

    def outer_tuple(item: dict[str, Any]) -> tuple[int | None, ...]:
        return canonical_tuple(
            int(item["endpointState"]["deviceControl"]),
            int(item["endpointState"]["deviceStatus"]),
            int(item["endpointState"]["uncorrectableErrorStatus"]),
            int(item["endpointState"]["correctableErrorStatus"]),
            int(item["endpointState"]["correctableErrorMask"]),
            int(item["rootState"]["bridgeControl"]),
            int(item["rootState"]["deviceControl"]),
            int(item["rootState"]["deviceStatus"]),
            int(item["rootState"]["uncorrectableErrorStatus"]),
            int(item["rootState"]["correctableErrorStatus"]),
            int(item["rootState"]["correctableErrorMask"]),
            int(item["rootState"]["rootErrorCommand"]),
            int(item["rootState"]["rootErrorStatus"]),
            int(item["rootState"]["errorSourceIdentification"]),
        )

    def tuple_record(
        value: tuple[int | None, ...],
    ) -> dict[str, int | None]:
        return dict(zip(tuple_fields, value, strict=True))

    try:
        before_tuple = outer_tuple(outer_before)
        after_tuple = outer_tuple(outer_after)
        sample_tuples: list[tuple[int | None, ...]] = []
        if isinstance(outer_samples_raw, list):
            for item in outer_samples_raw:
                snapshot = (
                    item.get("snapshot")
                    if isinstance(item, dict)
                    and isinstance(item.get("snapshot"), dict)
                    else item
                )
                if not isinstance(snapshot, dict):
                    raise TypeError(
                        "outerSamples entry does not contain a snapshot"
                    )
                sample_tuples.append(outer_tuple(snapshot))
        host_tuple = canonical_tuple(
            int(host_endpoint["deviceControl"]),
            int(host_endpoint["deviceStatus"]),
            int(host_endpoint["uncorrectableStatus"]),
            int(host_endpoint["correctableStatus"]),
            int(host_endpoint["correctableMask"]),
            int(host_root["bridgeControl"]),
            int(host_root["deviceControl"]),
            int(host_root["deviceStatus"]),
            int(host_root["uncorrectableStatus"]),
            int(host_root["correctableStatus"]),
            int(host_root["correctableMask"]),
            int(host_root["rootErrorCommand"]),
            int(host_root["rootErrorStatus"]),
            int(host_root["errorSourceIdentification"]),
        )
        outer_safety_clean = not (
            esxi_aer.outer_snapshot_safety_faults(outer_before)
            or esxi_aer.outer_snapshot_safety_faults(outer_after)
            or any(
                esxi_aer.outer_snapshot_safety_faults(
                    (
                        item.get("snapshot")
                        if isinstance(item, dict)
                        and isinstance(item.get("snapshot"), dict)
                        else item
                    )
                )
                for item in (
                    outer_samples_raw
                    if isinstance(outer_samples_raw, list)
                    else []
                )
            )
        )
    except (KeyError, TypeError, ValueError) as error:
        return {}, {
            "complete": False,
            "reason": (
                "host/outer projection contains a missing or non-numeric "
                f"register field: {type(error).__name__}: {error}"
            ),
        }
    candidate_tuples = list(
        dict.fromkeys((before_tuple, *sample_tuples, after_tuple))
    )
    host_by_field = tuple_record(host_tuple)
    candidates_by_field = {
        field_name: {item[index] for item in candidate_tuples}
        for index, field_name in enumerate(tuple_fields)
    }
    checks = {
        "host-projection-equals-one-monitored-outer-snapshot": (
            host_tuple in candidate_tuples
        ),
        "host-endpoint-ces-matches-monitored-window": (
            host_by_field["endpointCorrectableStatus"]
            in candidates_by_field["endpointCorrectableStatus"]
        ),
        "host-endpoint-ues-matches-monitored-window": (
            host_by_field["endpointUncorrectableStatus"]
            in candidates_by_field["endpointUncorrectableStatus"]
        ),
        "host-root-status-matches-monitored-window": (
            host_by_field["rootErrorStatus"]
            in candidates_by_field["rootErrorStatus"]
        ),
        "host-root-ues-matches-monitored-window": (
            host_by_field["rootUncorrectableStatus"]
            in candidates_by_field["rootUncorrectableStatus"]
        ),
        "host-endpoint-mask-matches-monitored-window": (
            host_by_field["endpointCorrectableMask"]
            in candidates_by_field["endpointCorrectableMask"]
        ),
        "host-root-command-matches-monitored-window": (
            host_by_field["rootErrorCommand"]
            in candidates_by_field["rootErrorCommand"]
        ),
        "host-root-source-matches-qualified-monitored-window": (
            host_by_field["qualifiedRootSource"]
            in candidates_by_field["qualifiedRootSource"]
        ),
        "host-endpoint-device-control-matches-monitored-window": (
            host_by_field["endpointDeviceControl"]
            in candidates_by_field["endpointDeviceControl"]
        ),
        "host-endpoint-device-status-matches-monitored-window": (
            host_by_field["endpointDeviceStatus"]
            in candidates_by_field["endpointDeviceStatus"]
        ),
        "host-root-bridge-control-matches-monitored-window": (
            host_by_field["rootBridgeControl"]
            in candidates_by_field["rootBridgeControl"]
        ),
        "host-root-device-control-matches-monitored-window": (
            host_by_field["rootDeviceControl"]
            in candidates_by_field["rootDeviceControl"]
        ),
        "host-root-device-status-matches-monitored-window": (
            host_by_field["rootDeviceStatus"]
            in candidates_by_field["rootDeviceStatus"]
        ),
        "host-root-ces-matches-monitored-window": (
            host_by_field["rootCorrectableStatus"]
            in candidates_by_field["rootCorrectableStatus"]
        ),
        "host-root-mask-matches-monitored-window": (
            host_by_field["rootCorrectableMask"]
            in candidates_by_field["rootCorrectableMask"]
        ),
        "host-endpoint-ues-zero": (
            host_by_field["endpointUncorrectableStatus"] == 0
        ),
        "host-root-ues-zero": (
            host_by_field["rootUncorrectableStatus"] == 0
        ),
        "outer-bracket-safety-clean": outer_safety_clean,
    }
    return checks, {
        "complete": True,
        "hostTuple": tuple_record(host_tuple),
        "outerCandidateTuples": [
            tuple_record(item) for item in candidate_tuples
        ],
        "outerSampleCount": (
            len(outer_samples_raw)
            if isinstance(outer_samples_raw, list)
            else 0
        ),
        "endpointCesCandidates": sorted(
            candidates_by_field["endpointCorrectableStatus"]
        ),
        "rootStatusCandidates": sorted(
            candidates_by_field["rootErrorStatus"]
        ),
        "endpointMaskCandidates": sorted(
            candidates_by_field["endpointCorrectableMask"]
        ),
        "rootCommandCandidates": sorted(
            candidates_by_field["rootErrorCommand"]
        ),
        "qualifiedRootSourceCandidates": sorted(
            candidates_by_field["qualifiedRootSource"],
            key=lambda value: (-1 if value is None else value),
        ),
    }


def safety_observation_identity_faults(
    observation: Any,
    *,
    index: int,
) -> list[str]:
    """Validate the closed provenance identity of one numeric observation.

    Numeric values remain independently shape-checked so a known unsafe field
    is retained even when a peer field is missing.  Provenance, however, must
    be trusted before the observation can be used to claim an ESXi divergence.
    """

    prefix = f"safetyObservations[{index}]"
    if not isinstance(observation, dict):
        return [f"{prefix} is not an object"]
    faults: list[str] = []
    boundary = observation.get("boundary")
    if boundary not in SAFETY_BOUNDARIES:
        faults.append(f"{prefix}.boundary is not a closed enum value")
    provenance = observation.get("provenance")
    if not isinstance(provenance, dict):
        return faults + [f"{prefix}.provenance is not an object"]
    for key in (
        "sourceKind",
        "artifact",
        "jsonPath",
        "label",
        "boundarySource",
    ):
        if not isinstance(provenance.get(key), str):
            faults.append(f"{prefix}.provenance.{key} is not a string")
    if faults:
        return faults

    source_kind = provenance["sourceKind"]
    artifact = provenance["artifact"]
    json_path = provenance["jsonPath"]
    label = provenance["label"]
    boundary_source = provenance["boundarySource"]
    if not label:
        faults.append(f"{prefix}.provenance.label is empty")
    if json_path and not json_path.startswith("/"):
        faults.append(f"{prefix}.provenance.jsonPath is not absolute")
    if boundary_source not in {
        "EXPLICIT_RECORD",
        "ALLOW_LISTED_ARTIFACT_ROUTE",
    }:
        faults.append(
            f"{prefix}.provenance.boundarySource is not a closed enum value"
        )

    expected_boundary = SAFETY_ARTIFACT_BOUNDARIES.get(artifact)
    if source_kind == "ESXI_PUBLIC_CONFIG_PROJECTION":
        if artifact not in {
            "raw-esxi/t0-baseline/phase.json",
            "raw-esxi/t4-terminal/phase.json",
        }:
            faults.append(
                f"{prefix}.provenance.artifact is not an ESXi raw phase"
            )
        elif boundary != expected_boundary:
            faults.append(
                f"{prefix}.boundary disagrees with its raw ESXi phase"
            )
        return faults
    if source_kind != "QTEST_OUTER_SNAPSHOT":
        faults.append(f"{prefix}.provenance.sourceKind is not allow-listed")
        return faults

    if expected_boundary is not None:
        if boundary != expected_boundary:
            faults.append(
                f"{prefix}.boundary disagrees with its raw artifact phase"
            )
    elif artifact == "t2-pre-injection.json":
        if boundary not in {"PRE_INJECTION", "ATTRIBUTION_WINDOW"}:
            faults.append(
                f"{prefix}.boundary is invalid for a T2 mutation bracket"
            )
        if boundary_source != "EXPLICIT_RECORD":
            faults.append(
                f"{prefix}.boundary lacks an explicit T2 record boundary"
            )
    elif artifact == "t5-transition-or-clear.json":
        if boundary not in {"ATTRIBUTION_WINDOW", "POST_CLEANUP"}:
            faults.append(
                f"{prefix}.boundary is invalid for a T5 cleanup bracket"
            )
        if (
            json_path.startswith("/operations/")
            and boundary_source != "EXPLICIT_RECORD"
        ):
            faults.append(
                f"{prefix}.boundary lacks an explicit T5 operation boundary"
            )
    else:
        faults.append(f"{prefix}.provenance.artifact is not allow-listed")
    return faults


def derive_evaluation_safety_faults(
    evaluation_input: dict[str, Any],
) -> list[dict[str, Any]]:
    """Derive fail-stop facts from raw evaluator inputs.

    The caller-supplied ``safetyFaults`` list remains useful runtime evidence,
    but it is never the sole authority.  Every public snapshot and every
    available ESXi/outer projection is independently inspected so a propagation
    omission cannot downgrade an observed Uncorrectable state.
    """

    records: list[dict[str, Any]] = []

    def faults_from_values(
        *,
        endpoint_device_status: int | None,
        endpoint_ues: int | None,
        root_device_status: int | None,
        root_ues: int | None,
        root_status: int | None,
    ) -> list[str]:
        faults: list[str] = []
        if endpoint_ues:
            faults.append(f"endpoint UES=0x{endpoint_ues:08x}")
        if root_ues:
            faults.append(f"root UES=0x{root_ues:08x}")
        if endpoint_device_status is not None:
            endpoint_non_ced = endpoint_device_status & (
                qemu_aer.PCI_EXP_DEVSTA_ERROR_MASK
                ^ qemu_aer.PCI_EXP_DEVSTA_CED
            )
            if endpoint_non_ced:
                faults.append(
                    "endpoint DeviceStatus non-CED="
                    f"0x{endpoint_non_ced:04x}"
                )
        if root_device_status is not None:
            root_non_ced = root_device_status & (
                qemu_aer.PCI_EXP_DEVSTA_ERROR_MASK
                ^ qemu_aer.PCI_EXP_DEVSTA_CED
            )
            if root_non_ced:
                faults.append(
                    f"root DeviceStatus non-CED=0x{root_non_ced:04x}"
                )
        if root_status is not None:
            root_uncorrectable = (
                root_status & qemu_aer.PCI_ERR_ROOT_UNCOR_MASK
            )
            if root_uncorrectable:
                faults.append(
                    "root uncorrectable reception="
                    f"0x{root_uncorrectable:08x}"
                )
        return faults

    def public_faults(item: Any) -> list[str]:
        if not isinstance(item, dict):
            return []
        endpoint = item.get("endpoint")
        root = item.get("rootPort")
        if not isinstance(endpoint, dict) or not isinstance(root, dict):
            return []
        def parsed(container: dict[str, Any], key: str) -> int | None:
            try:
                return int(container[key])
            except (KeyError, TypeError, ValueError):
                return None

        endpoint_ues = parsed(endpoint, "uncorrectableErrorStatus")
        root_ues = parsed(root, "uncorrectableErrorStatus")
        endpoint_device_status = parsed(endpoint, "deviceStatus")
        root_device_status = parsed(root, "deviceStatus")
        root_status = parsed(root, "rootErrorStatus")
        return faults_from_values(
            endpoint_device_status=endpoint_device_status,
            endpoint_ues=endpoint_ues,
            root_device_status=root_device_status,
            root_ues=root_ues,
            root_status=root_status,
        )

    observations = evaluation_input.get("safetyObservations")
    if isinstance(observations, list):
        for index, observation in enumerate(observations):
            if not isinstance(observation, dict):
                continue
            if safety_observation_identity_faults(
                observation,
                index=index,
            ):
                # An unbound numeric claim requires containment, but cannot be
                # elevated into VMware divergence or FAIL_SAFETY authority.
                continue
            boundary = str(observation.get("boundary") or "UNKNOWN")

            def observed_int(key: str) -> int | None:
                try:
                    return int(observation[key])
                except (KeyError, TypeError, ValueError):
                    return None

            values = {
                "endpoint_device_status": observed_int(
                    "endpointDeviceStatus"
                ),
                "endpoint_ues": observed_int(
                    "endpointUncorrectableErrorStatus"
                ),
                "root_device_status": observed_int("rootDeviceStatus"),
                "root_ues": observed_int(
                    "rootUncorrectableErrorStatus"
                ),
                "root_status": observed_int("rootErrorStatus"),
            }
            faults = faults_from_values(**values)
            if faults:
                provenance = observation.get("provenance")
                label = (
                    provenance.get("label")
                    if isinstance(provenance, dict)
                    else None
                )
                records.append(
                    {
                        "label": (
                            str(label)
                            if isinstance(label, str) and label
                            else f"safety-observation:{index:04d}"
                        ),
                        "boundary": boundary,
                        "faults": faults,
                        "derived": True,
                    }
                )

    snapshots = evaluation_input.get("snapshots")
    if isinstance(snapshots, dict):
        for label, snapshot in sorted(snapshots.items()):
            faults = public_faults(snapshot)
            if faults:
                boundary = (
                    "POST_CLEANUP"
                    if label == "post-cleanup"
                    else (
                        "PRE_INJECTION"
                        if label in {"effective-controls", "pre-injection"}
                        else "ATTRIBUTION_WINDOW"
                    )
                )
                records.append(
                    {
                        "label": f"snapshot:{label}",
                        "boundary": boundary,
                        "faults": faults,
                        "derived": True,
                    }
                )

    projection = evaluation_input.get("hostProjection")
    projection_faults = host_projection_safety_faults(
        projection if isinstance(projection, dict) else None
    )
    if projection_faults:
        records.append(
            {
                "label": "host-projection",
                "boundary": "ATTRIBUTION_WINDOW",
                "faults": projection_faults,
                "derived": True,
            }
        )
    if isinstance(projection, dict):
        outer_candidates: list[tuple[str, Any]] = [
            ("outer-before-remote", projection.get("outerBeforeRemote")),
            ("outer-after-remote", projection.get("outerAfterRemote")),
        ]
        outer_samples = projection.get("outerSamples")
        if isinstance(outer_samples, list):
            outer_candidates.extend(
                (
                    f"outer-sample:{index:04d}",
                    (
                        item.get("snapshot")
                        if isinstance(item, dict)
                        and isinstance(item.get("snapshot"), dict)
                        else item
                    ),
                )
                for index, item in enumerate(outer_samples)
            )
        for label, snapshot in outer_candidates:
            if not isinstance(snapshot, dict):
                continue
            try:
                faults = esxi_aer.outer_snapshot_safety_faults(snapshot)
            except (KeyError, TypeError, ValueError):
                continue
            if faults:
                records.append(
                    {
                        "label": label,
                        "boundary": "ATTRIBUTION_WINDOW",
                        "faults": faults,
                        "derived": True,
                    }
                )

    # Canonical de-duplication keeps digests independent of which redundant
    # safety surface observed the same runtime-supplied record first.
    unique: dict[bytes, dict[str, Any]] = {}
    for item in records:
        normalized = {
            "label": str(item.get("label", "")),
            "boundary": str(
                item.get("boundary") or "ATTRIBUTION_WINDOW"
            ),
            "faults": sorted(
                str(value)
                for value in (
                    item.get("faults")
                    if isinstance(item.get("faults"), list)
                    else []
                )
            ),
        }
        if item.get("derived") is True:
            normalized["derived"] = True
        unique[canonical_json(normalized)] = normalized
    return [
        unique[key]
        for key in sorted(unique)
    ]


def collect_numeric_safety_observations(
    artifacts: Iterable[tuple[str, str, Any]],
) -> list[dict[str, Any]]:
    """Extract the five immutable fail-stop integers from allow-listed raw data.

    The walk deliberately excludes evaluator summaries.  Mixed-phase artifacts
    such as T2 and T5 carry an explicit ``safetyBoundary`` on each raw record;
    the supplied artifact route is only a fallback for single-phase containers.
    """

    observations: list[dict[str, Any]] = []

    def parsed_int(container: dict[str, Any], key: str) -> int | None:
        value = container.get(key)
        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value <= 0xFFFFFFFF
        ):
            return value
        return None

    def walk(
        value: Any,
        *,
        artifact: str,
        boundary: str,
        path: str,
        inherited_label: str | None,
        boundary_source: str,
    ) -> None:
        if isinstance(value, dict):
            label = (
                str(value["label"])
                if isinstance(value.get("label"), str)
                else inherited_label
            )
            explicit_boundary = value.get("safetyBoundary")
            local_boundary = (
                str(explicit_boundary)
                if explicit_boundary in SAFETY_BOUNDARIES
                else boundary
            )
            local_boundary_source = (
                "EXPLICIT_RECORD"
                if explicit_boundary in SAFETY_BOUNDARIES
                else boundary_source
            )
            endpoint = value.get("endpointState")
            root = value.get("rootState")
            if isinstance(endpoint, dict) and isinstance(root, dict):
                numeric_values = {
                    "endpointDeviceStatus": parsed_int(
                        endpoint,
                        "deviceStatus",
                    ),
                    "endpointUncorrectableErrorStatus": parsed_int(
                        endpoint,
                        "uncorrectableErrorStatus",
                    ),
                    "rootDeviceStatus": parsed_int(root, "deviceStatus"),
                    "rootUncorrectableErrorStatus": parsed_int(
                        root,
                        "uncorrectableErrorStatus",
                    ),
                    "rootErrorStatus": parsed_int(root, "rootErrorStatus"),
                }
                if any(item is not None for item in numeric_values.values()):
                    observation: dict[str, Any] = {
                        "boundary": local_boundary,
                        "provenance": {
                            "sourceKind": "QTEST_OUTER_SNAPSHOT",
                            "artifact": artifact,
                            "jsonPath": path,
                            "label": (
                                label
                                or path.rsplit("/", 1)[-1]
                                or artifact
                            ),
                            "boundarySource": local_boundary_source,
                        },
                    }
                    observation.update(
                        {
                            key: item
                            for key, item in numeric_values.items()
                            if item is not None
                        }
                    )
                    observations.append(observation)
            for key in sorted(value):
                if key in SAFETY_DERIVED_KEYS:
                    continue
                walk(
                    value[key],
                    artifact=artifact,
                    boundary=local_boundary,
                    path=f"{path}/{key}",
                    inherited_label=label,
                    boundary_source=local_boundary_source,
                )
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(
                    item,
                    artifact=artifact,
                    boundary=boundary,
                    path=f"{path}/{index}",
                    inherited_label=inherited_label,
                    boundary_source=boundary_source,
                )

    for artifact, boundary, value in artifacts:
        if boundary not in SAFETY_BOUNDARIES:
            raise ValueError(f"invalid safety observation boundary: {boundary}")
        walk(
            value,
            artifact=artifact,
            boundary=boundary,
            path="",
            inherited_label=None,
            boundary_source="ALLOW_LISTED_ARTIFACT_ROUTE",
        )
    # Exact provenance can repeat when a snapshot is referenced through two
    # in-memory summaries.  Canonical de-duplication keeps one immutable record.
    unique = {
        canonical_json(item): item
        for item in observations
    }
    return [unique[key] for key in sorted(unique)]


INJECTION_RECORD_FIELDS = {
    "label",
    "bit",
    "mask",
    "command",
    "attempted",
    "mutationBoundaryCrossed",
    "safetyBoundary",
    "accepted",
    "commandIssuedAt",
    "elapsedSeconds",
    "observedAt",
    "raw",
    "fault",
}


def _canonical_outer_bdf_parts(value: Any) -> tuple[str, int, int, int] | None:
    """Return the domain/bus/device/function encoded by one canonical BDF."""

    if not isinstance(value, str):
        return None
    canonical = esxi_aer.canonical_bdf(value)
    if canonical is None:
        return None
    match = re.fullmatch(
        r"([0-9a-f]{4}):([0-9a-f]{2}):([0-9a-f]{2})\.([0-7])",
        canonical,
    )
    if match is None:
        return None
    return (
        match.group(1),
        int(match.group(2), 16),
        int(match.group(3), 16),
        int(match.group(4), 16),
    )


def _closed_outer_bdf_pair(
    endpoint_value: Any,
    root_value: Any,
) -> tuple[str, str] | None:
    """Return one canonical same-domain endpoint/root pair or fail closed."""

    endpoint = _canonical_outer_bdf_parts(endpoint_value)
    root = _canonical_outer_bdf_parts(root_value)
    if endpoint is None or root is None:
        return None
    endpoint_canonical = esxi_aer.canonical_bdf(endpoint_value)
    root_canonical = esxi_aer.canonical_bdf(root_value)
    if (
        endpoint_canonical != endpoint_value
        or root_canonical != root_value
        or endpoint[0] != root[0]
        or endpoint[0] != "0000"
        or endpoint_value == root_value
    ):
        return None
    return endpoint_value, root_value


def _bdf_from_snapshot_identity(value: Any) -> str | None:
    """Rebuild the domain-zero BDF retained by a raw QTest topology."""

    if not isinstance(value, dict):
        return None
    bus = value.get("bus")
    device = value.get("device")
    function = value.get("function")
    if (
        not isinstance(bus, int)
        or isinstance(bus, bool)
        or not 0 <= bus <= 0xFF
        or not isinstance(device, int)
        or isinstance(device, bool)
        or not 0 <= device <= 0x1F
        or not isinstance(function, int)
        or isinstance(function, bool)
        or not 0 <= function <= 7
    ):
        return None
    requester_id = value.get("requesterId")
    expected_requester_id = (bus << 8) | (device << 3) | function
    if (
        not isinstance(requester_id, int)
        or isinstance(requester_id, bool)
        or requester_id != expected_requester_id
    ):
        return None
    return f"0000:{bus:02x}:{device:02x}.{function:x}"


def outer_bdf_pair_from_gate_lease(
    t1: Any,
) -> tuple[str | None, str | None]:
    """Derive the only ACK identity from the manifest-bound gate snapshot."""

    gate_lease = t1.get("gateLease") if isinstance(t1, dict) else None
    original = (
        gate_lease.get("original")
        if isinstance(gate_lease, dict)
        else None
    )
    snapshot = (
        original.get("snapshot")
        if isinstance(original, dict)
        else None
    )
    if not isinstance(snapshot, dict):
        return None, None
    endpoint_bdf = _bdf_from_snapshot_identity(snapshot.get("endpoint"))
    root_bdf = _bdf_from_snapshot_identity(snapshot.get("root"))
    if endpoint_bdf is None or root_bdf is None:
        return None, None
    return endpoint_bdf, root_bdf


def _expected_correctable_hmp_ack_line(
    *,
    qemu_device: Any,
    outer_endpoint_bdf: Any,
    outer_root_bdf: Any,
) -> str | None:
    """Rebuild QEMU's exact public success line for the frozen topology."""

    if (
        not isinstance(qemu_device, str)
        or QEMU_DEVICE_ID_RE.fullmatch(qemu_device) is None
    ):
        return None
    endpoint = _canonical_outer_bdf_parts(outer_endpoint_bdf)
    root = _canonical_outer_bdf_parts(outer_root_bdf)
    if endpoint is None or root is None or endpoint[0] != root[0]:
        return None
    endpoint_domain, endpoint_bus, endpoint_device, endpoint_function = (
        endpoint
    )
    root_domain, root_bus, _root_device, _root_function = root
    if endpoint_domain != root_domain:
        return None
    # QEMU 11.0.2 pci-hmp-cmds.c uses exactly:
    # "OK id: %s root bus: %s, bus: %x devfn: %x.%x\n"
    return (
        f"OK id: {qemu_device} root bus: {root_domain}:{root_bus:02x}, "
        f"bus: {endpoint_bus:x} "
        f"devfn: {endpoint_device:x}.{endpoint_function:x}"
    )


def exclusive_correctable_hmp_ack(
    raw: Any,
    qemu_device: Any,
    *,
    outer_endpoint_bdf: Any,
    outer_root_bdf: Any,
) -> bool:
    """Accept one exact qdev-and-topology-bound HMP ACK."""

    if not isinstance(raw, str):
        return False
    expected_ack = _expected_correctable_hmp_ack_line(
        qemu_device=qemu_device,
        outer_endpoint_bdf=outer_endpoint_bdf,
        outer_root_bdf=outer_root_bdf,
    )
    if expected_ack is None:
        return False
    lines = raw.splitlines()
    ack_matches = [line for line in lines if line == expected_ack]
    foreign_or_malformed_ack = any(
        "OK id:" in line and line != expected_ack
        for line in lines
    )
    contradictory_hmp_result = bool(
        re.search(
            r"(?i)(?:\berror\b|\bunknown command\b|"
            r"\binvalid (?:command|parameter)\b|\bfailed\b|\bfailure\b)",
            raw,
        )
    )
    return bool(
        len(ack_matches) == 1
        and not foreign_or_malformed_ack
        and not contradictory_hmp_result
    )


def injection_record_shape_faults(
    value: Any,
    *,
    sequence: Any = None,
    qemu_device: Any = None,
    outer_endpoint_bdf: Any,
    outer_root_bdf: Any,
) -> list[str]:
    """Validate and semantically replay the closed raw HMP records."""

    if not isinstance(value, list):
        return ["injections is not a list"]
    faults: list[str] = []
    expected_labels = (
        list(qemu_sequence.expected_injection_labels(sequence))
        if sequence in SEQUENCES
        else None
    )
    observed_labels: list[Any] = []
    valid_device = (
        isinstance(qemu_device, str)
        and QEMU_DEVICE_ID_RE.fullmatch(qemu_device) is not None
    )
    expected_ack_line = _expected_correctable_hmp_ack_line(
        qemu_device=qemu_device,
        outer_endpoint_bdf=outer_endpoint_bdf,
        outer_root_bdf=outer_root_bdf,
    )
    if value and expected_ack_line is None:
        faults.append(
            "non-empty injections lack one closed outer topology identity"
        )
    for index, item in enumerate(value):
        prefix = f"injections[{index}]"
        if not isinstance(item, dict):
            faults.append(f"{prefix} is not an object")
            observed_labels.append(None)
            continue
        if set(item) != INJECTION_RECORD_FIELDS:
            faults.append(f"{prefix} fields differ from the closed schema")
        label = item.get("label")
        observed_labels.append(label)
        if not isinstance(label, str) or not label:
            faults.append(f"{prefix}.label is not a non-empty string")
        bit = item.get("bit")
        mask = item.get("mask")
        expected_bit = (
            B1_NAME if label == "second-b1" else B0_NAME
        )
        expected_mask = SAFE_INJECTION_BITS.get(expected_bit)
        expected_mask_text = (
            f"0x{expected_mask:08x}"
            if isinstance(expected_mask, int)
            else None
        )
        if bit != expected_bit:
            faults.append(f"{prefix}.bit disagrees with its sequence label")
        if mask != expected_mask_text:
            faults.append(f"{prefix}.mask disagrees with its sequence label")
        expected_command = (
            f"pcie_aer_inject_error -c {qemu_device} "
            f"{expected_mask_text}"
            if valid_device and expected_mask_text is not None
            else None
        )
        if expected_command is None or item.get("command") != expected_command:
            faults.append(
                f"{prefix}.command is not the closed Correctable command"
            )
        if item.get("attempted") is not True:
            faults.append(f"{prefix}.attempted is not true")
        if item.get("mutationBoundaryCrossed") is not True:
            faults.append(
                f"{prefix}.mutationBoundaryCrossed is not true"
            )
        if item.get("safetyBoundary") != "ATTRIBUTION_WINDOW":
            faults.append(
                f"{prefix}.safetyBoundary is not ATTRIBUTION_WINDOW"
            )
        accepted = item.get("accepted")
        if not isinstance(accepted, bool):
            faults.append(f"{prefix}.accepted is not a boolean")
        for field_name in ("commandIssuedAt", "observedAt"):
            timestamp = item.get(field_name)
            if not isinstance(timestamp, str) or not timestamp:
                faults.append(
                    f"{prefix}.{field_name} is not a non-empty string"
                )
        elapsed = item.get("elapsedSeconds")
        if (
            not isinstance(elapsed, (int, float))
            or isinstance(elapsed, bool)
            or not math.isfinite(float(elapsed))
            or elapsed < 0
        ):
            faults.append(
                f"{prefix}.elapsedSeconds is not finite and non-negative"
            )
        raw = item.get("raw")
        fault = item.get("fault")
        fault_valid = (
            isinstance(fault, dict)
            and set(fault) == {"type", "message"}
            and isinstance(fault.get("type"), str)
            and bool(fault.get("type"))
            and isinstance(fault.get("message"), str)
        )
        acked = exclusive_correctable_hmp_ack(
            raw,
            qemu_device,
            outer_endpoint_bdf=outer_endpoint_bdf,
            outer_root_bdf=outer_root_bdf,
        )
        if accepted is True:
            if not isinstance(raw, str) or not acked:
                faults.append(
                    f"{prefix}.accepted is not supported by the raw HMP ACK"
                )
            if fault is not None:
                faults.append(
                    f"{prefix}.accepted record carries a dispatch fault"
                )
        elif accepted is False:
            dispatch_fault = raw is None and fault_valid
            non_ack = (
                isinstance(raw, str)
                and not acked
                and fault is None
            )
            if not dispatch_fault and not non_ack:
                faults.append(
                    f"{prefix}.rejected record is not a closed dispatch "
                    "fault or non-ACK result"
                )
        if fault is not None and not fault_valid:
            faults.append(f"{prefix}.fault is not the closed fault object")
    if expected_labels is None:
        faults.append("sequence is not a closed sequence")
    elif observed_labels != expected_labels[: len(observed_labels)]:
        faults.append(
            "injection labels are not the exact planned sequence prefix"
        )
    if len(observed_labels) > len(expected_labels or []):
        faults.append("injection count exceeds the planned sequence")
    return sorted(set(faults))


def render_hmp_transcript(value: Any) -> str | None:
    """Rebuild the exact human-readable transcript from raw injection facts."""

    if not isinstance(value, list):
        return None
    lines: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            return None
        label = item.get("label")
        command = item.get("command")
        if not isinstance(label, str) or not isinstance(command, str):
            return None
        lines.append(f"### {label}: {command}")
        raw = item.get("raw")
        fault = item.get("fault")
        if isinstance(raw, str):
            lines.append(raw.rstrip())
        elif (
            isinstance(fault, dict)
            and isinstance(fault.get("type"), str)
            and isinstance(fault.get("message"), str)
        ):
            lines.append(
                "HMP dispatch/readback fault: "
                f"{fault['type']}: {fault['message']}"
            )
        else:
            return None
        lines.append("")
    return "\n".join(lines)


def verified_entered_injection_from_records(
    value: Any,
    *,
    sequence: Any,
    qemu_device: Any,
    outer_endpoint_bdf: Any,
    outer_root_bdf: Any,
) -> bool:
    """Return true only after a closed planned prefix contains an exact ACK."""

    if not isinstance(value, list):
        return False
    for prefix_length in range(1, len(value) + 1):
        prefix = value[:prefix_length]
        if injection_record_shape_faults(
            prefix,
            sequence=sequence,
            qemu_device=qemu_device,
            outer_endpoint_bdf=outer_endpoint_bdf,
            outer_root_bdf=outer_root_bdf,
        ):
            continue
        terminal = prefix[-1]
        if (
            isinstance(terminal, dict)
            and terminal.get("accepted") is True
            and exclusive_correctable_hmp_ack(
                terminal.get("raw"),
                qemu_device,
                outer_endpoint_bdf=outer_endpoint_bdf,
                outer_root_bdf=outer_root_bdf,
            )
        ):
            return True
    return False


def entered_injection_from_records(
    value: Any,
    *,
    sequence: Any = None,
    qemu_device: Any = None,
    outer_endpoint_bdf: Any,
    outer_root_bdf: Any,
) -> bool:
    """Reconstruct the boundary, conservatively treating malformed raw as in."""

    if not isinstance(value, list):
        return True
    if not value:
        return False
    # Without the closed case identity a non-empty record cannot be proved
    # rejected.  Offline callers therefore retain the conservative boundary.
    if sequence not in SEQUENCES or not isinstance(qemu_device, str):
        return True
    if injection_record_shape_faults(
        value,
        sequence=sequence,
        qemu_device=qemu_device,
        outer_endpoint_bdf=outer_endpoint_bdf,
        outer_root_bdf=outer_root_bdf,
    ):
        return True
    return verified_entered_injection_from_records(
        value,
        sequence=sequence,
        qemu_device=qemu_device,
        outer_endpoint_bdf=outer_endpoint_bdf,
        outer_root_bdf=outer_root_bdf,
    )


UNACKNOWLEDGED_MUTATION_CONTAINMENT_REASON = (
    "HMP mutation dispatch crossed without an exact Correctable ACK"
)


def unacknowledged_mutation_requires_containment(
    recorder: Any,
    *,
    entered_injection: bool,
) -> bool:
    """Separate uncertain dispatch containment from the exact ACK boundary."""

    return bool(
        recorder is not None
        and getattr(recorder, "mutation_boundary_crossed", False) is True
        and entered_injection is False
    )


def latch_unacknowledged_mutation_containment(
    recorder: Any,
    *,
    entered_injection: bool,
    containment_reasons: list[str],
) -> bool:
    """Persist the reason and return whether containment is required."""

    required = unacknowledged_mutation_requires_containment(
        recorder,
        entered_injection=entered_injection,
    )
    if (
        required
        and UNACKNOWLEDGED_MUTATION_CONTAINMENT_REASON
        not in containment_reasons
    ):
        containment_reasons.append(
            UNACKNOWLEDGED_MUTATION_CONTAINMENT_REASON
        )
    return required


def cleanup_requires_safe_stop(
    *,
    containment_required: bool,
    safety_latched: bool,
    recorder: Any,
    entered_injection: bool,
) -> bool:
    """Derive the cleanup hold, including dispatches whose ACK was lost."""

    return bool(
        containment_required
        or safety_latched
        or bool(recorder and recorder.safety_faults)
        or unacknowledged_mutation_requires_containment(
            recorder,
            entered_injection=entered_injection,
        )
    )


def derive_cleanup_containment_decision(
    *,
    recorder: Any,
    entered_injection: bool,
    containment_required: bool,
    containment_reasons: list[str],
    safety_latched: bool,
) -> dict[str, Any]:
    """Return the single fail-closed decision consumed by ``run_case``."""

    reasons = list(containment_reasons)
    unacknowledged_mutation = (
        latch_unacknowledged_mutation_containment(
            recorder,
            entered_injection=entered_injection,
            containment_reasons=reasons,
        )
    )
    effective_containment = bool(
        containment_required or unacknowledged_mutation
    )
    return {
        "unacknowledgedMutation": unacknowledged_mutation,
        "containmentRequired": effective_containment,
        "containmentReasons": reasons,
        "safeStop": cleanup_requires_safe_stop(
            containment_required=effective_containment,
            safety_latched=safety_latched,
            recorder=recorder,
            entered_injection=entered_injection,
        ),
    }


def host_projection_numeric_safety_observation(
    projection: Any,
    *,
    artifact: str,
    boundary: str,
    json_path: str,
    label: str,
) -> dict[str, Any] | None:
    """Create one five-register observation from an ESXi public projection."""

    if (
        boundary not in SAFETY_BOUNDARIES
        or not isinstance(projection, dict)
    ):
        return None
    endpoint = projection.get("hostEndpoint")
    root = projection.get("hostRoot")
    if not isinstance(endpoint, dict) or not isinstance(root, dict):
        return None

    def parsed(container: dict[str, Any], key: str) -> int | None:
        value = container.get(key)
        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value <= 0xFFFFFFFF
        ):
            return value
        return None

    values = {
        "endpointDeviceStatus": parsed(endpoint, "deviceStatus"),
        "endpointUncorrectableErrorStatus": parsed(
            endpoint,
            "uncorrectableStatus",
        ),
        "rootDeviceStatus": parsed(root, "deviceStatus"),
        "rootUncorrectableErrorStatus": parsed(
            root,
            "uncorrectableStatus",
        ),
        "rootErrorStatus": parsed(root, "rootErrorStatus"),
    }
    if not any(item is not None for item in values.values()):
        return None
    observation: dict[str, Any] = {
        "boundary": boundary,
        "provenance": {
            "sourceKind": "ESXI_PUBLIC_CONFIG_PROJECTION",
            "artifact": artifact,
            "jsonPath": json_path,
            "label": label,
            "boundarySource": "ALLOW_LISTED_ARTIFACT_ROUTE",
        },
    }
    observation.update(
        {key: item for key, item in values.items() if item is not None}
    )
    return observation


def build_numeric_safety_observations(
    *,
    t0: dict[str, Any],
    t1: dict[str, Any],
    t2: dict[str, Any],
    t3: dict[str, Any],
    t4: dict[str, Any],
    t5: dict[str, Any],
    cleanup: dict[str, Any],
    baseline_phase: dict[str, Any] | None,
    terminal_phase: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Rebuild numeric authority only from explicit, allow-listed raw routes."""

    operations = (
        t5.get("operations")
        if isinstance(t5.get("operations"), list)
        else []
    )
    t5_post_cleanup = {
        key: copy.deepcopy(t5.get(key))
        for key in (
            "gateRestore",
            "activeVmCleanupPausedBaseline",
            "activeVmCleanupSafetyWindows",
            "finalSafetyTailPausedBaseline",
            "finalRunningSafetyTail",
        )
        if key in t5
    }
    observations = collect_numeric_safety_observations(
        (
            ("t0-baseline.json", "PRE_INJECTION", t0),
            ("t1-effective-controls.json", "PRE_INJECTION", t1),
            ("t2-pre-injection.json", "PRE_INJECTION", t2),
            ("t3-immediate.json", "ATTRIBUTION_WINDOW", t3),
            ("t4-window.json", "ATTRIBUTION_WINDOW", t4),
            (
                "t5-transition-or-clear.json",
                "ATTRIBUTION_WINDOW",
                # Keep malformed or missing record boundaries visible.  A
                # valid explicit POST_CLEANUP boundary overrides this route;
                # a missing one remains untrusted and fails shape validation.
                {"operations": operations},
            ),
            (
                "t5-transition-or-clear.json",
                "POST_CLEANUP",
                t5_post_cleanup,
            ),
            ("cleanup.json", "POST_CLEANUP", cleanup),
        )
    )
    for projection, artifact, boundary, label in (
        (
            phase_projection(baseline_phase),
            "raw-esxi/t0-baseline/phase.json",
            "PRE_INJECTION",
            "esxi-host-baseline",
        ),
        (
            phase_projection(terminal_phase),
            "raw-esxi/t4-terminal/phase.json",
            "ATTRIBUTION_WINDOW",
            "esxi-host-terminal",
        ),
    ):
        observation = host_projection_numeric_safety_observation(
            projection,
            artifact=artifact,
            boundary=boundary,
            json_path="",
            label=label,
        )
        if observation is not None:
            observations.append(observation)
    unique = {canonical_json(item): item for item in observations}
    return [unique[key] for key in sorted(unique)]


SAFETY_WINDOW_KINDS = {
    "CONTINUOUS_TIMELINE",
    "GATE_LEASE_APPLY",
    "GATE_LEASE_RESTORE",
    "SERVICE_WINDOW",
    "MONITORED_WORKER",
    "FINAL_RUNNING_STABILIZATION",
}

PAUSED_NUMERIC_SNAPSHOT_RECORD_KIND = "PAUSED_NUMERIC_SNAPSHOT"
PRE_MUTATION_NUMERIC_SNAPSHOT_RECORD_KIND = (
    "PRE_MUTATION_NUMERIC_SNAPSHOT"
)
PAUSED_NUMERIC_SNAPSHOT_RECORD_FIELDS = {
    "recordKind",
    "label",
    "phase",
    "operation",
    "safetyBoundary",
    "observedAt",
    "qemuPaused",
    "gate",
    "snapshot",
    "sourceMeaning",
    "safetyFaults",
    "partial",
}
PRE_MUTATION_NUMERIC_SNAPSHOT_RECORD_FIELDS = {
    "recordKind",
    "label",
    "operation",
    "safetyBoundary",
    "observedAt",
    "qemuPaused",
    "gate",
    "snapshot",
    "safetyFaults",
    "partial",
}
O4_GUEST_WINDOW_RECEIPT_RECORD_KIND = "O4_GUEST_WINDOW_RECEIPT"
O4_GUEST_WINDOW_RECEIPT_FIELDS = {
    "recordKind",
    "label",
    "observedAt",
    "window",
}
O4_GUEST_WINDOW_FIELDS = {
    "windowSeconds",
    "elapsedSinceOpenObserved",
    "remainingSeconds",
    "requiredRemainingSeconds",
}
SERVICE_WINDOW_RECORD_FIELDS = {
    "label",
    "description",
    "safetyBoundary",
    "safetyWindowKind",
    "startedAtMonotonic",
    "resume",
    "timeline",
    "safetyPoll",
    "ownerObservation",
    "ownerObservationPolicy",
    "timelineFault",
    "pause",
    "pauseFault",
    "pauseTailFault",
    "pythonGcGuard",
    "gcGuardFault",
    "finalizationFault",
    "coverageComplete",
    "finishedAt",
}
MONITORED_WORKER_RECORD_FIELDS = {
    "label",
    "description",
    "safetyBoundary",
    "safetyWindowKind",
    "enforceGate",
    "startedAtMonotonic",
    "resume",
    "maximumPollIntervalSeconds",
    "pollIntervalSeconds",
    "sampleCount",
    "maximumObservedPollGapSeconds",
    "maximumObservedReadDurationSeconds",
    "snapshotMode",
    "finalStopConfirmedElapsedSeconds",
    "lastSampleFinishedElapsedSeconds",
    "tailGapSeconds",
    "samples",
    "firstSnapshot",
    "lastSnapshot",
    "safetyEvents",
    "monitorFault",
    "immediateStopFault",
    "finalStopFault",
    "executorShutdownFault",
    "cancelFault",
    "pythonGcGuard",
    "gcGuardFault",
    "controlFault",
    "tailGapFault",
    "finalizationFault",
    "gateFault",
    "workerFault",
    "pause",
    "coverageComplete",
    "finishedAt",
}

PHASE_ARTIFACT_ALLOWED_FIELDS = {
    "t0": {
        "startedAt",
        "environment",
        "explicitBaselineClear",
        "hostPhase",
        "logWindowPreflightInventory",
        "beforeMarker",
        "beforeMarkerVisibility",
        "ownerObservation",
        "guestBefore",
        "faults",
        "postBaselineClearPausedReadback",
        "preSequenceSafetyWindows",
        "preSequenceSafetyMonitor",
        "kernelPreconditions",
        "finishedAt",
        "preflight",
    },
    "t1": {
        "requestedGate",
        "controlledBits",
        "gateLease",
        "activeVm",
        "remoteIsoSha256",
        "activeVmStartupPause",
        "activeVmStartupPausedBaseline",
        "activeVmSafetyWindows",
        "activeVmSafetyMonitor",
        "gateStable",
    },
    "t2": {"steps"},
    "t3": {"injections", "snapshots"},
    "t4": {
        "windows",
        "hostTerminalPhase",
        "hostProjection",
        "terminalOwnerObservation",
        "guest",
        "afterMarker",
        "afterMarkerVisibility",
        "logWindowCapture",
        "logWindow",
        "logWindowSafetyMonitor",
        "logWindowDerivationFault",
    },
    "t5": {
        "operations",
        "gateRestore",
        "gateRestoreFault",
        "emergencyHold",
        "emergencyHoldFault",
        "containmentHold",
        "containmentHoldFault",
        "preCleanupQemuState",
        "preCleanupQemuStateFault",
        "unknownStateEmergencyHold",
        "unknownStateEmergencyHoldFault",
        "activeVmCleanup",
        "activeVmCleanupPause",
        "activeVmCleanupPausedBaseline",
        "activeVmCleanupSafetyWindows",
        "activeVmCleanupSafetyMonitor",
        "activeVmCleanupChecks",
        "stateBeforeFinalSafetyTail",
        "finalSafetyTailPausedBaseline",
        "finalRunningSafetyTail",
        "postCleanupContainmentHold",
        "postCleanupContainmentHoldFault",
        "finalQemuState",
        "finalQemuStateFault",
        "finalStateEmergencyHold",
        "finalStateEmergencyHoldFault",
        "containment",
        "evaluationEvidence",
    },
    "cleanup": {
        "startedAt",
        "actions",
        "complete",
        "containmentRequired",
        "finishedAt",
    },
}
PHASE_ARTIFACT_REQUIRED_FIELDS = {
    "t0": {
        "startedAt",
        "environment",
        "explicitBaselineClear",
        "hostPhase",
        "logWindowPreflightInventory",
        "beforeMarker",
        "beforeMarkerVisibility",
        "ownerObservation",
        "guestBefore",
        "faults",
        "finishedAt",
        "preflight",
    },
    "t1": {
        "requestedGate",
        "controlledBits",
        "gateLease",
        "activeVm",
        "remoteIsoSha256",
        "gateStable",
    },
    "t2": {"steps"},
    "t3": {"injections", "snapshots"},
    "t4": {
        "windows",
        "hostTerminalPhase",
        "hostProjection",
        "guest",
        "afterMarker",
        "afterMarkerVisibility",
        "logWindowCapture",
        "logWindow",
    },
    "t5": {
        "operations",
        "gateRestore",
        "activeVmCleanup",
        "finalQemuState",
        "containment",
        "evaluationEvidence",
    },
    "cleanup": {
        "startedAt",
        "actions",
        "complete",
        "containmentRequired",
        "finishedAt",
    },
}
SUCCESS_T1_O0_FIELDS = PHASE_ARTIFACT_REQUIRED_FIELDS["t1"]
SUCCESS_T1_O4_FIELDS = PHASE_ARTIFACT_ALLOWED_FIELDS["t1"]
SUCCESS_T4_FIELDS = (
    PHASE_ARTIFACT_ALLOWED_FIELDS["t4"] - {"logWindowDerivationFault"}
)
SUCCESS_T5_O0_FIELDS = {
    "operations",
    "gateRestore",
    "activeVmCleanup",
    "finalQemuState",
    "preCleanupQemuState",
    "stateBeforeFinalSafetyTail",
    "finalSafetyTailPausedBaseline",
    "finalRunningSafetyTail",
    "containment",
    "evaluationEvidence",
}
SUCCESS_T5_O4_FIELDS = SUCCESS_T5_O0_FIELDS | {
    "activeVmCleanupPausedBaseline",
    "activeVmCleanupSafetyWindows",
    "activeVmCleanupSafetyMonitor",
    "activeVmCleanupChecks",
}
MONITOR_SUMMARY_FIELDS = {
    "maximumPollIntervalSeconds",
    "maximumObservedPollGapSeconds",
    "sampleCount",
    "safetyEvents",
}
OWNER_OBSERVATION_FIELDS = {
    "label",
    "observedAt",
    "currentOwner",
    "target",
    "activeUsers",
    "hostResponsive",
    "heartbeatSource",
}
PAUSED_BASELINE_FIELDS = {
    "label",
    "safetyBoundary",
    "snapshot",
    "safetyFaults",
    "partial",
}
UNLABELED_PAUSED_BASELINE_FIELDS = PAUSED_BASELINE_FIELDS - {"label"}
FINAL_TAIL_BASELINE_FIELDS = {
    "safetyBoundary",
    "captureSnapshotMode",
    "runnableSnapshotMode",
    "topologySeedMode",
    "snapshot",
    "safetyFaults",
    "partial",
}

SEQUENCE_ACTION_SPECS = {
    "first-multiple": (
        {"kind": "inject", "label": "first-b0", "bit": B0_NAME},
        {
            "kind": "service",
            "label": "first-window-observation",
            "description": "bounded ESXi observation after first B0",
        },
        {"kind": "inject", "label": "repeated-b0", "bit": B0_NAME},
        {
            "kind": "service",
            "label": "stable-after-repeat",
            "description": "bounded ESXi observation after repeated B0",
        },
    ),
    "independent-w1c": (
        {"kind": "inject", "label": "initial-b0", "bit": B0_NAME},
        {
            "kind": "service",
            "label": "initial-window",
            "description": "bounded ESXi observation after initial B0",
        },
        {
            "kind": "clear",
            "label": "after-endpoint-clear-only-immediate",
            "operation": (
                "W1C Endpoint CES.B0/B1 and Device Status.CED only"
            ),
        },
        {
            "kind": "service",
            "label": "after-endpoint-clear-only",
            "description": (
                "bounded ESXi observation after Endpoint-only W1C"
            ),
        },
        {
            "kind": "clear",
            "label": "after-root-cleanup-for-rebuild",
            "operation": (
                "W1C Root Correctable Status for clean rebuild"
            ),
        },
        {"kind": "inject", "label": "rebuilt-b0", "bit": B0_NAME},
        {
            "kind": "clear",
            "label": "after-root-clear-only-immediate",
            "operation": "W1C Root Correctable Status only",
        },
        {
            "kind": "service",
            "label": "after-root-clear-only",
            "description": "bounded ESXi observation after Root-only W1C",
        },
    ),
    "bit-or": (
        {"kind": "inject", "label": "first-b0", "bit": B0_NAME},
        {"kind": "inject", "label": "second-b1", "bit": B1_NAME},
        {
            "kind": "service",
            "label": "stable-after-or",
            "description": (
                "bounded ESXi observation after paused B0 then B1 OR"
            ),
        },
    ),
    "rearm": (
        {"kind": "inject", "label": "initial-b0", "bit": B0_NAME},
        {
            "kind": "service",
            "label": "initial-window",
            "description": "bounded ESXi observation after initial B0",
        },
        {
            "kind": "clear",
            "label": "after-ces-clear-only",
            "operation": "W1C Endpoint CES.B0/B1 only",
        },
        {
            "kind": "clear",
            "label": "after-ced-clear-only",
            "operation": "W1C Endpoint Device Status.CED only",
        },
        {
            "kind": "clear",
            "label": "after-root-clear",
            "operation": "W1C Root Correctable Status only",
        },
        {"kind": "inject", "label": "rearmed-b0", "bit": B0_NAME},
        {
            "kind": "service",
            "label": "rearmed-window",
            "description": "bounded ESXi observation after re-armed B0",
        },
    ),
}


def phase_artifact_root_faults(
    phase: str,
    value: Any,
) -> list[str]:
    """Reject authority keys outside each current phase artifact schema."""

    if not isinstance(value, dict):
        return [f"{phase} phase artifact is not an object"]
    allowed = PHASE_ARTIFACT_ALLOWED_FIELDS[phase]
    required = PHASE_ARTIFACT_REQUIRED_FIELDS[phase]
    faults: list[str] = []
    unknown = sorted(set(value) - allowed)
    missing = sorted(required - set(value))
    if unknown:
        faults.append(
            f"{phase} phase artifact has unknown fields: {unknown}"
        )
    if missing:
        faults.append(
            f"{phase} phase artifact is missing required fields: {missing}"
        )
    return faults


def _monitor_summary_from_record(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {
        "maximumPollIntervalSeconds": value.get(
            "maximumPollIntervalSeconds"
        ),
        "maximumObservedPollGapSeconds": value.get(
            "maximumObservedPollGapSeconds"
        ),
        "sampleCount": value.get("sampleCount"),
        "safetyEvents": value.get("safetyEvents"),
    }


def owner_observation_shape_faults(
    value: Any,
    *,
    expected_label: str,
) -> list[str]:
    faults = _closed_fields_fault(
        value,
        OWNER_OBSERVATION_FIELDS,
        "owner observation",
    )
    if faults or not isinstance(value, dict):
        return faults
    if value.get("label") != expected_label:
        faults.append("owner observation label is not exact")
    if _utc_datetime(value.get("observedAt")) is None:
        faults.append("owner observation observedAt is not UTC")
    if not isinstance(value.get("currentOwner"), str):
        faults.append("owner observation currentOwner is not a string")
    if not isinstance(value.get("target"), dict):
        faults.append("owner observation target is not an object")
    active_users = value.get("activeUsers")
    if not isinstance(active_users, list) or any(
        not isinstance(item, dict) for item in active_users
    ):
        faults.append("owner observation activeUsers is malformed")
    if not isinstance(value.get("hostResponsive"), bool):
        faults.append("owner observation hostResponsive is not boolean")
    if value.get("heartbeatSource") != (
        "monitored terminal uptime command"
    ):
        faults.append("owner observation heartbeatSource is not exact")
    return sorted(set(faults))


def successful_phase_artifact_faults(
    *,
    t0: dict[str, Any],
    t1: dict[str, Any],
    t4: dict[str, Any],
    t5: dict[str, Any],
    cleanup: dict[str, Any],
    owner_phase: Any,
) -> list[str]:
    """Require the one exact successful root variant for conclusive evidence."""

    expected = {
        "t0": PHASE_ARTIFACT_ALLOWED_FIELDS["t0"],
        "t1": (
            SUCCESS_T1_O4_FIELDS
            if owner_phase == "O4"
            else SUCCESS_T1_O0_FIELDS
        ),
        "t4": SUCCESS_T4_FIELDS,
        "t5": (
            SUCCESS_T5_O4_FIELDS
            if owner_phase == "O4"
            else SUCCESS_T5_O0_FIELDS
        ),
        "cleanup": PHASE_ARTIFACT_ALLOWED_FIELDS["cleanup"],
    }
    artifacts = {
        "t0": t0,
        "t1": t1,
        "t4": t4,
        "t5": t5,
        "cleanup": cleanup,
    }
    faults: list[str] = []
    for phase_name, expected_fields in expected.items():
        if set(artifacts[phase_name]) != expected_fields:
            faults.append(
                f"{phase_name} fields differ from the successful schema"
            )

    post_baseline = t0.get("postBaselineClearPausedReadback")
    local = _closed_fields_fault(
        post_baseline,
        PAUSED_BASELINE_FIELDS,
        "post-baseline paused readback",
    )
    faults.extend(local)
    if isinstance(post_baseline, dict):
        if (
            post_baseline.get("label")
            != "post-baseline-clear-paused-readback"
            or post_baseline.get("safetyBoundary") != "PRE_INJECTION"
            or post_baseline.get("partial") is not False
        ):
            faults.append("post-baseline paused readback identity drifted")
        snapshot = post_baseline.get("snapshot")
        faults.extend(outer_snapshot_shape_faults(snapshot))
        try:
            derived = esxi_aer._partial_numeric_safety_faults(snapshot)
        except (KeyError, TypeError, ValueError):
            derived = []
            faults.append("post-baseline safety cannot be derived")
        if post_baseline.get("safetyFaults") != derived or derived:
            faults.append("post-baseline safety evidence is not clean")
    if t0.get("kernelPreconditions") != {
        "enablePCIErrorsRuntimeTrue": True,
        "pcipDisablePciErrReportingRuntimeFalse": True,
    }:
        faults.append("t0 kernelPreconditions are not exact")
    if not isinstance(t0.get("explicitBaselineClear"), dict):
        faults.append("t0 explicitBaselineClear is not an object")

    faults.extend(
        owner_observation_shape_faults(
            t0.get("ownerObservation"),
            expected_label="t0-owner",
        )
    )
    faults.extend(
        owner_observation_shape_faults(
            t4.get("terminalOwnerObservation"),
            expected_label="t4-terminal-owner",
        )
    )

    summary_bindings = [
        (
            "t0 pre-sequence",
            t0.get("preSequenceSafetyMonitor"),
            (
                t0.get("preSequenceSafetyWindows", [None])[-1]
                if isinstance(t0.get("preSequenceSafetyWindows"), list)
                and t0["preSequenceSafetyWindows"]
                else None
            ),
        ),
        (
            "t4 log-window",
            t4.get("logWindowSafetyMonitor"),
            next(
                (
                    item
                    for item in t4.get("windows", [])
                    if isinstance(item, dict)
                    and item.get("label") == "close-log-window"
                ),
                None,
            ),
        ),
    ]
    if owner_phase == "O4":
        summary_bindings.append(
            (
                "t1 active-VM",
                t1.get("activeVmSafetyMonitor"),
                (
                    t1.get("activeVmSafetyWindows", [None])[-1]
                    if isinstance(t1.get("activeVmSafetyWindows"), list)
                    and t1["activeVmSafetyWindows"]
                    else None
                ),
            )
        )
    for label, summary, source in summary_bindings:
        if (
            not isinstance(summary, dict)
            or set(summary) != MONITOR_SUMMARY_FIELDS
            or summary != _monitor_summary_from_record(source)
        ):
            faults.append(f"{label} monitor summary is not exact")

    if t5.get("preCleanupQemuState") != "paused":
        faults.append("t5 preCleanupQemuState is not paused")
    if t5.get("stateBeforeFinalSafetyTail") != "paused":
        faults.append("t5 stateBeforeFinalSafetyTail is not paused")
    if t5.get("finalQemuState") != "running":
        faults.append("t5 finalQemuState is not running")
    if t5.get("containment") != {
        "required": False,
        "reasons": [],
        "observedSafetySideEffect": False,
    }:
        faults.append("t5 containment is not the successful closed state")
    final_baseline = t5.get("finalSafetyTailPausedBaseline")
    faults.extend(
        _closed_fields_fault(
            final_baseline,
            FINAL_TAIL_BASELINE_FIELDS,
            "final safety-tail paused baseline",
        )
    )
    if isinstance(final_baseline, dict):
        if (
            final_baseline.get("safetyBoundary") != "POST_CLEANUP"
            or final_baseline.get("runnableSnapshotMode")
            != "PINNED_TOPOLOGY_BLOCK_BATCH"
            or final_baseline.get("partial") is not False
        ):
            faults.append("final safety-tail baseline identity drifted")
        snapshot = final_baseline.get("snapshot")
        faults.extend(outer_snapshot_shape_faults(snapshot))
        try:
            derived = esxi_aer._partial_numeric_safety_faults(snapshot)
        except (KeyError, TypeError, ValueError):
            derived = []
            faults.append("final safety-tail safety cannot be derived")
        if final_baseline.get("safetyFaults") != derived or derived:
            faults.append("final safety-tail baseline is not clean")
    if owner_phase == "O4":
        for (
            label,
            baseline,
            expected_fields,
            expected_label,
            expected_boundary,
        ) in (
            (
                "t1 active-VM startup baseline",
                t1.get("activeVmStartupPausedBaseline"),
                PAUSED_BASELINE_FIELDS,
                "o4-owner-activation-paused-baseline",
                "PRE_INJECTION",
            ),
            (
                "t5 active-VM cleanup baseline",
                t5.get("activeVmCleanupPausedBaseline"),
                UNLABELED_PAUSED_BASELINE_FIELDS,
                None,
                "POST_CLEANUP",
            ),
        ):
            faults.extend(
                _closed_fields_fault(
                    baseline,
                    expected_fields,
                    label,
                )
            )
            if not isinstance(baseline, dict):
                continue
            if (
                baseline.get("safetyBoundary") != expected_boundary
                or (
                    expected_label is not None
                    and baseline.get("label") != expected_label
                )
                or baseline.get("partial") is not False
            ):
                faults.append(f"{label} identity is not exact")
            snapshot = baseline.get("snapshot")
            faults.extend(outer_snapshot_shape_faults(snapshot))
            try:
                derived = esxi_aer._partial_numeric_safety_faults(
                    snapshot
                )
            except (KeyError, TypeError, ValueError):
                derived = []
                faults.append(f"{label} safety cannot be derived")
            if baseline.get("safetyFaults") != derived or derived:
                faults.append(f"{label} is not clean")
        expected_cleanup_checks = active_vm_cleanup_checks(
            t5.get("activeVmCleanup"),
            expected_registered=True,
        )
        if t5.get("activeVmCleanupChecks") != expected_cleanup_checks:
            faults.append("t5 activeVmCleanupChecks are not recomputed")
    return sorted(set(faults))


def optional_phase_field_faults(
    *,
    t0: dict[str, Any],
    t1: dict[str, Any],
    t4: dict[str, Any],
    t5: dict[str, Any],
    expected_gate: str | None = None,
) -> list[str]:
    """Close every branch-only phase field even for failed/incomplete cases."""

    faults: list[str] = []

    kernel = t0.get("kernelPreconditions")
    if "kernelPreconditions" in t0 and (
        not isinstance(kernel, dict)
        or set(kernel)
        != {
            "enablePCIErrorsRuntimeTrue",
            "pcipDisablePciErrReportingRuntimeFalse",
        }
        or any(not isinstance(item, bool) for item in kernel.values())
    ):
        faults.append("t0 kernelPreconditions are malformed")

    for (
        container_name,
        container,
        field_name,
        boundary,
        expected_fields,
        expected_label,
    ) in (
        (
            "t0",
            t0,
            "postBaselineClearPausedReadback",
            "PRE_INJECTION",
            PAUSED_BASELINE_FIELDS,
            "post-baseline-clear-paused-readback",
        ),
        (
            "t1",
            t1,
            "activeVmStartupPausedBaseline",
            "PRE_INJECTION",
            PAUSED_BASELINE_FIELDS,
            "o4-owner-activation-paused-baseline",
        ),
        (
            "t5",
            t5,
            "activeVmCleanupPausedBaseline",
            "POST_CLEANUP",
            UNLABELED_PAUSED_BASELINE_FIELDS,
            None,
        ),
    ):
        if field_name not in container:
            continue
        baseline = container.get(field_name)
        local = _closed_fields_fault(
            baseline,
            expected_fields,
            f"{container_name}.{field_name}",
        )
        faults.extend(local)
        if not isinstance(baseline, dict):
            continue
        if (
            baseline.get("safetyBoundary") != boundary
            or (
                expected_label is not None
                and baseline.get("label") != expected_label
            )
            or not isinstance(baseline.get("partial"), bool)
        ):
            faults.append(f"{container_name}.{field_name} identity drifted")
        snapshot = baseline.get("snapshot")
        faults.extend(outer_snapshot_shape_faults(snapshot))
        try:
            derived = esxi_aer._partial_numeric_safety_faults(snapshot)
        except (KeyError, TypeError, ValueError):
            derived = []
            faults.append(
                f"{container_name}.{field_name} safety cannot be derived"
            )
        if baseline.get("safetyFaults") != derived:
            faults.append(
                f"{container_name}.{field_name} safetyFaults are not exact"
            )

    if "finalSafetyTailPausedBaseline" in t5:
        baseline = t5.get("finalSafetyTailPausedBaseline")
        faults.extend(
            _closed_fields_fault(
                baseline,
                FINAL_TAIL_BASELINE_FIELDS,
                "t5.finalSafetyTailPausedBaseline",
            )
        )
        if isinstance(baseline, dict):
            if (
                baseline.get("safetyBoundary") != "POST_CLEANUP"
                or baseline.get("runnableSnapshotMode")
                != "PINNED_TOPOLOGY_BLOCK_BATCH"
                or not isinstance(baseline.get("partial"), bool)
            ):
                faults.append(
                    "t5.finalSafetyTailPausedBaseline identity drifted"
                )
            snapshot = baseline.get("snapshot")
            faults.extend(outer_snapshot_shape_faults(snapshot))
            try:
                derived = esxi_aer._partial_numeric_safety_faults(snapshot)
            except (KeyError, TypeError, ValueError):
                derived = []
                faults.append(
                    "t5.finalSafetyTailPausedBaseline safety cannot "
                    "be derived"
                )
            if baseline.get("safetyFaults") != derived:
                faults.append(
                    "t5.finalSafetyTailPausedBaseline safetyFaults "
                    "are not exact"
                )

    for container_name, container, field_name, expected_label in (
        ("t0", t0, "ownerObservation", "t0-owner"),
        ("t4", t4, "terminalOwnerObservation", "t4-terminal-owner"),
    ):
        if field_name in container and container.get(field_name) is not None:
            faults.extend(
                f"{container_name}.{field_name}: {fault}"
                for fault in owner_observation_shape_faults(
                    container[field_name],
                    expected_label=expected_label,
                )
            )

    summary_bindings = (
        (
            "t0",
            t0,
            "preSequenceSafetyMonitor",
            (
                t0.get("preSequenceSafetyWindows", [None])[-1]
                if isinstance(t0.get("preSequenceSafetyWindows"), list)
                and t0["preSequenceSafetyWindows"]
                else None
            ),
        ),
        (
            "t1",
            t1,
            "activeVmSafetyMonitor",
            (
                t1.get("activeVmSafetyWindows", [None])[-1]
                if isinstance(t1.get("activeVmSafetyWindows"), list)
                and t1["activeVmSafetyWindows"]
                else None
            ),
        ),
        (
            "t4",
            t4,
            "logWindowSafetyMonitor",
            (
                next(
                    (
                        item
                        for item in t4["windows"]
                        if isinstance(item, dict)
                        and item.get("label") == "close-log-window"
                    ),
                    None,
                )
                if isinstance(t4.get("windows"), list)
                else None
            ),
        ),
        (
            "t5",
            t5,
            "activeVmCleanupSafetyMonitor",
            (
                t5.get("activeVmCleanupSafetyWindows", [None])[-1]
                if isinstance(
                    t5.get("activeVmCleanupSafetyWindows"),
                    list,
                )
                and t5["activeVmCleanupSafetyWindows"]
                else None
            ),
        ),
    )
    for container_name, container, field_name, source in summary_bindings:
        if field_name not in container:
            continue
        summary = container.get(field_name)
        if (
            not isinstance(summary, dict)
            or set(summary) != MONITOR_SUMMARY_FIELDS
            or summary != _monitor_summary_from_record(source)
        ):
            faults.append(
                f"{container_name}.{field_name} is not exact"
            )

    if "activeVmStartupPause" in t1:
        faults.extend(
            f"t1.activeVmStartupPause: {fault}"
            for fault in direct_transition_record_shape_faults(
                t1.get("activeVmStartupPause"),
                expected_command="stop",
                expected_status="paused",
            )
        )
    if "activeVmCleanupPause" in t5:
        faults.extend(
            f"t5.activeVmCleanupPause: {fault}"
            for fault in direct_transition_record_shape_faults(
                t5.get("activeVmCleanupPause"),
                expected_command="stop",
                expected_status="paused",
            )
        )

    hold_fields = (
        "emergencyHold",
        "containmentHold",
        "unknownStateEmergencyHold",
        "postCleanupContainmentHold",
        "finalStateEmergencyHold",
    )
    for field_name in hold_fields:
        if field_name in t5:
            faults.extend(
                f"t5.{field_name}: {fault}"
                for fault in direct_transition_record_shape_faults(
                    t5.get(field_name),
                    expected_command="stop",
                    expected_status="paused",
                )
            )

    branch_fault_fields = (
        "gateRestoreFault",
        "emergencyHoldFault",
        "containmentHoldFault",
        "preCleanupQemuStateFault",
        "unknownStateEmergencyHoldFault",
        "postCleanupContainmentHoldFault",
        "finalQemuStateFault",
        "finalStateEmergencyHoldFault",
    )
    for field_name in branch_fault_fields:
        if field_name in t5 and (
            not isinstance(t5.get(field_name), dict)
            or not _closed_fault_or_none(t5[field_name])
        ):
            faults.append(f"t5.{field_name} is not a closed fault")
    if "logWindowDerivationFault" in t4 and (
        not isinstance(t4.get("logWindowDerivationFault"), dict)
        or not _closed_fault_or_none(t4["logWindowDerivationFault"])
    ):
        faults.append("t4.logWindowDerivationFault is not a closed fault")

    for field_name in (
        "preCleanupQemuState",
        "stateBeforeFinalSafetyTail",
        "finalQemuState",
    ):
        if field_name in t5 and t5.get(field_name) not in {
            "paused",
            "running",
            "unknown",
        }:
            faults.append(f"t5.{field_name} is not a closed QEMU state")

    for container_name, container, field_name, phase in (
        ("t0", t0, "preSequenceSafetyWindows", "t0"),
        ("t1", t1, "activeVmSafetyWindows", "t1"),
        ("t5", t5, "activeVmCleanupSafetyWindows", "t5"),
    ):
        if field_name in container:
            windows = container.get(field_name)
            if (
                not isinstance(windows, list)
                or any(not isinstance(item, dict) for item in windows)
            ):
                faults.append(
                    f"{container_name}.{field_name} is not an object list"
                )
            else:
                for index, item in enumerate(windows):
                    faults.extend(
                        f"{container_name}.{field_name}[{index}]: {fault}"
                        for fault in runnable_window_record_shape_faults(
                            item,
                            phase=phase,
                            expected_gate=expected_gate,
                        )
                    )

    if "activeVmCleanupChecks" in t5:
        expected_checks = active_vm_cleanup_checks(
            t5.get("activeVmCleanup"),
            expected_registered=True,
        )
        if t5.get("activeVmCleanupChecks") != expected_checks:
            faults.append("t5.activeVmCleanupChecks are not exact")
    return sorted(set(faults))


def planned_phase_records(
    *,
    sequence: Any,
    owner_phase: Any,
    qemu_device: Any,
) -> dict[str, list[dict[str, Any]]]:
    """Build the exact ordered record identities emitted by a complete case."""

    plan = {"t2": [], "t3": [], "t4": [], "t5": []}
    if (
        sequence not in SEQUENCE_ACTION_SPECS
        or owner_phase not in OWNER_PHASES
        or not isinstance(qemu_device, str)
        or QEMU_DEVICE_ID_RE.fullmatch(qemu_device) is None
    ):
        return plan

    plan["t2"].extend(
        [
            {
                "recordKind": PAUSED_NUMERIC_SNAPSHOT_RECORD_KIND,
                "label": "effective-controls",
                "phase": "t2",
                "operation": "read back g101/g100 and root-path lease",
                "safetyBoundary": "PRE_INJECTION",
            },
            {
                "recordKind": PAUSED_NUMERIC_SNAPSHOT_RECORD_KIND,
                "label": "pre-injection",
                "phase": "t2",
                "operation": "last precise pre-injection state",
                "safetyBoundary": "PRE_INJECTION",
            },
        ]
    )
    if owner_phase == "O4":
        plan["t2"].append(
            {
                "recordKind": O4_GUEST_WINDOW_RECEIPT_RECORD_KIND,
                "label": "o4-window-before-sequence",
            }
        )

    mutation_crossed = False
    for action in SEQUENCE_ACTION_SPECS[sequence]:
        kind = action["kind"]
        label = action["label"]
        if kind == "inject":
            mask = SAFE_INJECTION_BITS[action["bit"]]
            operation = (
                f"pcie_aer_inject_error -c {qemu_device} 0x{mask:08x}"
            )
            plan["t2"].append(
                {
                    "recordKind": (
                        PRE_MUTATION_NUMERIC_SNAPSHOT_RECORD_KIND
                    ),
                    "label": f"{label}-pre-state",
                    "operation": operation,
                    "safetyBoundary": (
                        "ATTRIBUTION_WINDOW"
                        if mutation_crossed
                        else "PRE_INJECTION"
                    ),
                }
            )
            plan["t3"].append(
                {
                    "recordKind": PAUSED_NUMERIC_SNAPSHOT_RECORD_KIND,
                    "label": label,
                    "phase": "t3",
                    "operation": operation,
                    "safetyBoundary": "ATTRIBUTION_WINDOW",
                }
            )
            mutation_crossed = True
        elif kind == "clear":
            operation = action["operation"]
            plan["t2"].append(
                {
                    "recordKind": (
                        PRE_MUTATION_NUMERIC_SNAPSHOT_RECORD_KIND
                    ),
                    "label": f"{label}-pre-state",
                    "operation": operation,
                    "safetyBoundary": "ATTRIBUTION_WINDOW",
                }
            )
            plan["t5"].append(
                {
                    "recordKind": PAUSED_NUMERIC_SNAPSHOT_RECORD_KIND,
                    "label": label,
                    "phase": "t5",
                    "operation": operation,
                    "safetyBoundary": "ATTRIBUTION_WINDOW",
                }
            )
        elif kind == "service":
            description = action["description"]
            plan["t4"].extend(
                [
                    {
                        "safetyWindowKind": "SERVICE_WINDOW",
                        "label": label,
                        "description": description,
                        "safetyBoundary": "ATTRIBUTION_WINDOW",
                    },
                    {
                        "recordKind": (
                            PAUSED_NUMERIC_SNAPSHOT_RECORD_KIND
                        ),
                        "label": label,
                        "phase": "t4",
                        "operation": (
                            f"post-resume window: {description}"
                        ),
                        "safetyBoundary": "ATTRIBUTION_WINDOW",
                    },
                ]
            )

    plan["t4"].extend(
        [
            {
                "safetyWindowKind": "MONITORED_WORKER",
                "label": "terminal-esxi-projection",
                "description": (
                    "collect terminal ESXi projection under continuous "
                    "Correctable-only safety polling"
                ),
                "safetyBoundary": "ATTRIBUTION_WINDOW",
            },
            {
                "recordKind": PAUSED_NUMERIC_SNAPSHOT_RECORD_KIND,
                "label": "terminal-post-host-window",
                "phase": "t4",
                "operation": (
                    "post-resume terminal snapshot after ESXi raw projection"
                ),
                "safetyBoundary": "ATTRIBUTION_WINDOW",
            },
            (
                {
                    "safetyWindowKind": "MONITORED_WORKER",
                    "label": "guest-completion",
                    "description": (
                        "wait for the runner-managed O4 guest terminal "
                        "marker under continuous Correctable-only safety "
                        "polling"
                    ),
                    "safetyBoundary": "ATTRIBUTION_WINDOW",
                }
                if owner_phase == "O4"
                else {
                    "safetyWindowKind": "MONITORED_WORKER",
                    "label": "o0-final-observation",
                    "description": "bounded O0 terminal observation",
                    "safetyBoundary": "ATTRIBUTION_WINDOW",
                }
            ),
            {
                "safetyWindowKind": "MONITORED_WORKER",
                "label": "close-log-window",
                "description": (
                    "write the official per-source AFTER marker, stage the "
                    "retained rotation chains, and rebuild the strict "
                    "sequence log window before restore or VM teardown"
                ),
                "safetyBoundary": "ATTRIBUTION_WINDOW",
            },
        ]
    )
    cleanup_operation = (
        "W1C Endpoint CES.B0/B1, Device Status.CED and "
        "Root Correctable Status"
    )
    plan["t5"].extend(
        [
            {
                "recordKind": PRE_MUTATION_NUMERIC_SNAPSHOT_RECORD_KIND,
                "label": "post-cleanup-pre-state",
                "operation": cleanup_operation,
                "safetyBoundary": "POST_CLEANUP",
            },
            {
                "recordKind": PAUSED_NUMERIC_SNAPSHOT_RECORD_KIND,
                "label": "post-cleanup",
                "phase": "t5",
                "operation": cleanup_operation,
                "safetyBoundary": "POST_CLEANUP",
            },
        ]
    )
    return plan


def phase_record_plan_faults(
    *,
    phase: str,
    records: Any,
    expected: list[dict[str, Any]],
) -> list[str]:
    """Require every observed phase list to be an exact ordered plan prefix."""

    if not isinstance(records, list):
        return [f"{phase} records are not a list"]
    faults: list[str] = []
    if len(records) > len(expected):
        faults.append(f"{phase} contains records beyond the closed plan")
    for index, item in enumerate(records[: len(expected)]):
        if not isinstance(item, dict):
            continue
        for field_name, expected_value in expected[index].items():
            if item.get(field_name) != expected_value:
                faults.append(
                    f"{phase}[{index}].{field_name} differs from the "
                    "ordered sequence plan"
                )
    return sorted(set(faults))


MINIMAL_OUTER_SNAPSHOT_FIELDS = {"endpointState", "rootState"}
FULL_OUTER_SNAPSHOT_FIELDS = {
    "q35Pciexbar",
    "endpoint",
    "endpointState",
    "root",
    "rootState",
}
MINIMAL_ENDPOINT_STATE_FIELDS = PUBLIC_SNAPSHOT_FIELDS["endpoint"]
FULL_ENDPOINT_STATE_FIELDS = MINIMAL_ENDPOINT_STATE_FIELDS | {
    "aerHeader",
    "uncorrectableErrorMask",
}
MINIMAL_ROOT_STATE_FIELDS = PUBLIC_SNAPSHOT_FIELDS["rootPort"]
FULL_ROOT_STATE_FIELDS = MINIMAL_ROOT_STATE_FIELDS | {
    "aerHeader",
    "primaryBus",
    "secondaryBus",
    "subordinateBus",
}
OUTER_DEVICE_IDENTITY_FIELDS = {
    "bus",
    "device",
    "function",
    "requesterId",
    "vendorId",
    "deviceId",
    "pcieCapabilityOffset",
    "aerCapabilityOffset",
    "aerHeader",
    "pcieType",
}
GATE_RECORD_FIELDS = {
    "requested",
    "effective",
    "rootPath",
    "correctableMask",
    "checks",
}
GATE_CHECK_FIELDS = {
    "tupleMatches",
    "rootPathOpen",
    "b0AndB1Unmasked",
}
TRANSITION_RECORD_FIELDS = {
    "command",
    "output",
    "status",
    "observedAt",
    "reason",
}
DIRECT_TRANSITION_RECORD_FIELDS = TRANSITION_RECORD_FIELDS - {"reason"}
GC_GUARD_RECORD_FIELDS = {
    "wasEnabled",
    "thresholds",
    "countsBefore",
    "preResumeCollected",
    "disabledBeforeResume",
    "armedAt",
    "releaseState",
    "postPauseCollected",
    "releasedAt",
    "fault",
}
SERVICE_SAFETY_POLL_FIELDS = {
    "maximumIntervalSeconds",
    "targetIntervalSeconds",
    "targetDelaysSeconds",
    "sampleCount",
    "targetCount",
    "completedTargetCount",
    "maximumObservedGapSeconds",
    "maximumObservedReadDurationSeconds",
    "snapshotMode",
    "pauseConfirmedElapsedSeconds",
    "lastSampleFinishedElapsedSeconds",
    "tailGapSeconds",
    "samples",
}
SERVICE_SAMPLE_FIELDS = {
    "sampleIndex",
    "actualElapsedSeconds",
    "sampleStartGapSeconds",
    "sampleDurationSeconds",
    "capturedAt",
    "gate",
    "endpoint",
    "root",
    "safetyFaults",
    "snapshot",
    "partial",
}
SERVICE_TIMELINE_FIELDS = {
    "delaySeconds",
    "targetDelaySeconds",
    "actualElapsedSeconds",
    "sampleIndex",
    "capturedAt",
    "gate",
    "safetyFaults",
    "snapshot",
}
MONITORED_SAMPLE_FIELDS = {
    "sampleIndex",
    "delaySeconds",
    "actualElapsedSeconds",
    "sampleStartGapSeconds",
    "sampleDurationSeconds",
    "observedAt",
    "gate",
    "endpoint",
    "root",
    "safetyFaults",
    "snapshot",
    "readFault",
    "partial",
}
SAMPLE_ENDPOINT_FIELDS = {
    "deviceStatus",
    "uncorrectableErrorStatus",
    "correctableErrorStatus",
}
SAMPLE_ROOT_FIELDS = {
    "deviceStatus",
    "uncorrectableErrorStatus",
    "rootErrorStatus",
}


def _closed_fields_fault(
    value: Any,
    expected_fields: set[str],
    label: str,
) -> list[str]:
    if not isinstance(value, dict):
        return [f"{label} is not an object"]
    if set(value) != expected_fields:
        return [f"{label} fields differ from the closed schema"]
    return []


def outer_snapshot_shape_faults(value: Any) -> list[str]:
    """Close every raw QTest snapshot container used by phase authority."""

    if not isinstance(value, dict):
        return ["outer snapshot is not an object"]
    keys = frozenset(value)
    if keys not in {
        frozenset(MINIMAL_OUTER_SNAPSHOT_FIELDS),
        frozenset(FULL_OUTER_SNAPSHOT_FIELDS),
    }:
        return ["outer snapshot fields differ from the closed schema"]
    faults: list[str] = []
    endpoint_state = value.get("endpointState")
    root_state = value.get("rootState")
    expected_endpoint_fields = (
        FULL_ENDPOINT_STATE_FIELDS
        if keys == FULL_OUTER_SNAPSHOT_FIELDS
        else MINIMAL_ENDPOINT_STATE_FIELDS
    )
    expected_root_fields = (
        FULL_ROOT_STATE_FIELDS
        if keys == FULL_OUTER_SNAPSHOT_FIELDS
        else MINIMAL_ROOT_STATE_FIELDS
    )
    faults.extend(
        _closed_fields_fault(
            endpoint_state,
            set(expected_endpoint_fields),
            "outer snapshot endpointState",
        )
    )
    faults.extend(
        _closed_fields_fault(
            root_state,
            set(expected_root_fields),
            "outer snapshot rootState",
        )
    )
    for section_name, section in (
        ("endpointState", endpoint_state),
        ("rootState", root_state),
    ):
        if isinstance(section, dict):
            for field_name, raw in section.items():
                if not isinstance(raw, int) or isinstance(raw, bool):
                    faults.append(
                        f"outer snapshot {section_name}.{field_name} "
                        "is not an integer"
                    )
    if keys == FULL_OUTER_SNAPSHOT_FIELDS:
        q35 = value.get("q35Pciexbar")
        if not isinstance(q35, int) or isinstance(q35, bool):
            faults.append("outer snapshot q35Pciexbar is not an integer")
        for section_name in ("endpoint", "root"):
            section = value.get(section_name)
            faults.extend(
                _closed_fields_fault(
                    section,
                    OUTER_DEVICE_IDENTITY_FIELDS,
                    f"outer snapshot {section_name}",
                )
            )
            if isinstance(section, dict) and any(
                not isinstance(raw, int) or isinstance(raw, bool)
                for raw in section.values()
            ):
                faults.append(
                    f"outer snapshot {section_name} identity is not numeric"
                )
    return sorted(set(faults))


def _iter_full_outer_snapshots(
    value: Any,
    *,
    path: str,
) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield every raw snapshot that carries its own topology identity."""

    if isinstance(value, dict):
        if set(value) == FULL_OUTER_SNAPSHOT_FIELDS:
            yield path, value
            return
        for key, nested in value.items():
            yield from _iter_full_outer_snapshots(
                nested,
                path=f"{path}/{key}",
            )
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _iter_full_outer_snapshots(
                nested,
                path=f"{path}/{index}",
            )


def static_outer_topology_identity_faults(
    value: Any,
) -> list[str]:
    """Replay the immutable topology checks used by the live QTest reader."""

    faults = outer_snapshot_shape_faults(value)
    if faults or not isinstance(value, dict):
        return faults
    expected_pciexbar = (
        qemu_aer.MCFG_BASE | qemu_aer.Q35_PCIEXBAR_ENABLE
    )
    if value.get("q35Pciexbar") != expected_pciexbar:
        faults.append("Q35 PCIEXBAR identity differs from the lab accessor")
    endpoint = value.get("endpoint")
    root = value.get("root")
    for label, identity, expected_type in (
        ("endpoint", endpoint, qemu_aer.PCI_EXP_TYPE_ENDPOINT),
        ("root", root, qemu_aer.PCI_EXP_TYPE_ROOT_PORT),
    ):
        if not isinstance(identity, dict):
            continue
        if _bdf_from_snapshot_identity(identity) is None:
            faults.append(f"{label} BDF/requester identity is invalid")
        if identity.get("pcieType") != expected_type:
            faults.append(f"{label} PCIe type is invalid")
        pcie_offset = identity.get("pcieCapabilityOffset")
        aer_offset = identity.get("aerCapabilityOffset")
        aer_header = identity.get("aerHeader")
        if (
            not isinstance(pcie_offset, int)
            or isinstance(pcie_offset, bool)
            or pcie_offset < 0x40
            or pcie_offset >= 0x100
            or pcie_offset % 4
        ):
            faults.append(f"{label} PCIe capability offset is invalid")
        if (
            not isinstance(aer_offset, int)
            or isinstance(aer_offset, bool)
            or aer_offset < 0x100
            or aer_offset > 0xFFC
            or aer_offset % 4
        ):
            faults.append(f"{label} AER capability offset is invalid")
        if (
            not isinstance(aer_header, int)
            or isinstance(aer_header, bool)
            or aer_header & 0xFFFF != qemu_aer.PCI_EXT_CAP_ID_ERR
        ):
            faults.append(f"{label} AER header is not AER")
        for field_name in ("vendorId", "deviceId"):
            raw = identity.get(field_name)
            if (
                not isinstance(raw, int)
                or isinstance(raw, bool)
                or not 0 <= raw <= 0xFFFF
            ):
                faults.append(f"{label} {field_name} is not 16-bit")
    return sorted(set(faults))


def frozen_outer_topology_faults(
    *,
    phase_artifacts: dict[str, Any],
    t1: dict[str, Any],
    outer_endpoint_bdf: Any,
    outer_root_bdf: Any,
    require_full_snapshot: bool,
) -> list[str]:
    """Bind every identity-bearing snapshot to one declared gate anchor."""

    declared_pair = _closed_outer_bdf_pair(
        outer_endpoint_bdf,
        outer_root_bdf,
    )
    if declared_pair is None:
        return (
            ["entered case lacks one closed domain-zero outer topology pair"]
            if require_full_snapshot
            else []
        )
    endpoint_parts = _canonical_outer_bdf_parts(declared_pair[0])
    root_parts = _canonical_outer_bdf_parts(declared_pair[1])
    assert endpoint_parts is not None
    assert root_parts is not None

    full_snapshots = [
        item
        for phase_name, artifact in phase_artifacts.items()
        for item in _iter_full_outer_snapshots(
            artifact,
            path=phase_name,
        )
    ]
    gate_lease = t1.get("gateLease") if isinstance(t1, dict) else None
    original = (
        gate_lease.get("original")
        if isinstance(gate_lease, dict)
        else None
    )
    anchor = (
        original.get("snapshot")
        if isinstance(original, dict)
        else None
    )
    if anchor is not None:
        anchor_faults = static_outer_topology_identity_faults(anchor)
        if (
            anchor_faults
            or not isinstance(anchor, dict)
            or set(anchor) != FULL_OUTER_SNAPSHOT_FIELDS
        ):
            return [
                "t1 gate-lease original snapshot is not one closed full "
                "topology anchor"
            ]
    elif full_snapshots:
        anchor = full_snapshots[0][1]
    elif require_full_snapshot:
        return ["entered phase artifacts contain no full topology snapshot"]
    else:
        return []
    assert isinstance(anchor, dict)
    anchor_endpoint = anchor.get("endpoint")
    anchor_root = anchor.get("root")
    if (
        _bdf_from_snapshot_identity(anchor_endpoint) != declared_pair[0]
        or _bdf_from_snapshot_identity(anchor_root) != declared_pair[1]
    ):
        return [
            "t1 gate-lease topology differs from the declared outer BDF pair"
        ]

    faults: list[str] = []
    observed = 0
    for path, snapshot in full_snapshots:
        observed += 1
        if static_outer_topology_identity_faults(snapshot):
            faults.append(f"{path}: full outer snapshot is malformed")
            continue
        endpoint_identity = snapshot.get("endpoint")
        root_identity = snapshot.get("root")
        root_state = snapshot.get("rootState")
        if (
            endpoint_identity != anchor_endpoint
            or root_identity != anchor_root
            or snapshot.get("q35Pciexbar")
            != anchor.get("q35Pciexbar")
        ):
            faults.append(
                f"{path}: topology identity differs from the gate anchor"
            )
        if (
            _bdf_from_snapshot_identity(endpoint_identity)
            != declared_pair[0]
            or _bdf_from_snapshot_identity(root_identity)
            != declared_pair[1]
        ):
            faults.append(
                f"{path}: topology identity differs from the declared BDFs"
            )
        if not isinstance(root_state, dict):
            faults.append(f"{path}: rootState is not an object")
            continue
        primary = root_state.get("primaryBus")
        secondary = root_state.get("secondaryBus")
        subordinate = root_state.get("subordinateBus")
        if (
            primary != root_parts[1]
            or secondary != endpoint_parts[1]
            or subordinate != endpoint_parts[1]
        ):
            faults.append(
                f"{path}: bridge bus range does not bind root to endpoint"
            )
        if (
            isinstance(endpoint_identity, dict)
            and endpoint_identity.get("aerHeader")
            != snapshot.get("endpointState", {}).get("aerHeader")
        ):
            faults.append(
                f"{path}: endpoint AER capability identity drifted"
            )
        if (
            isinstance(root_identity, dict)
            and root_identity.get("aerHeader")
            != root_state.get("aerHeader")
        ):
            faults.append(
                f"{path}: root AER capability identity drifted"
            )
    if observed == 0:
        faults.append("phase artifacts contain no full topology snapshot")
    return sorted(set(faults))


def _qemu_device_argv_records(value: Any) -> list[dict[str, str]]:
    """Parse the closed, comma-separated -device records used by this lab."""

    if not isinstance(value, list) or any(
        not isinstance(item, str) for item in value
    ):
        return []
    specifications: list[str] = []
    for index, token in enumerate(value):
        if token == "-device" and index + 1 < len(value):
            specifications.append(value[index + 1])
        elif token.startswith("-device="):
            specifications.append(token.split("=", 1)[1])
    records: list[dict[str, str]] = []
    for specification in specifications:
        fields = specification.split(",")
        if not fields or not fields[0]:
            continue
        record = {"model": fields[0]}
        malformed = False
        for field_value in fields[1:]:
            if "=" not in field_value:
                continue
            key, raw = field_value.split("=", 1)
            if not key or key in record:
                malformed = True
                break
            record[key] = raw
        if not malformed:
            records.append(record)
    return records


def _qemu_addr_devfn(value: Any) -> tuple[int, int] | None:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(
        r"(?:0x)?([0-9a-fA-F]{1,2})(?:\.([0-7]))?",
        value,
    )
    if match is None:
        return None
    device = int(match.group(1), 16)
    function = int(match.group(2) or "0", 16)
    if device > 0x1F:
        return None
    return device, function


def qemu_argv_topology_faults(
    *,
    command_line: Any,
    qemu_device: Any,
    outer_endpoint_bdf: Any,
    outer_root_bdf: Any,
) -> list[str]:
    """Bind declared devfns to the independently captured QEMU argv chain."""

    declared_pair = _closed_outer_bdf_pair(
        outer_endpoint_bdf,
        outer_root_bdf,
    )
    if (
        declared_pair is None
        or not isinstance(qemu_device, str)
        or QEMU_DEVICE_ID_RE.fullmatch(qemu_device) is None
    ):
        return ["QEMU argv topology inputs are not closed"]
    endpoint_parts = _canonical_outer_bdf_parts(declared_pair[0])
    root_parts = _canonical_outer_bdf_parts(declared_pair[1])
    assert endpoint_parts is not None
    assert root_parts is not None
    records = _qemu_device_argv_records(command_line)
    endpoint_records = [
        item for item in records if item.get("id") == qemu_device
    ]
    if len(endpoint_records) != 1:
        return ["QEMU argv lacks one unique declared endpoint qdev"]
    endpoint_record = endpoint_records[0]
    parent_id = endpoint_record.get("bus")
    parent_records = [
        item
        for item in records
        if isinstance(parent_id, str) and item.get("id") == parent_id
    ]
    faults: list[str] = []
    if _qemu_addr_devfn(endpoint_record.get("addr")) != (
        endpoint_parts[2],
        endpoint_parts[3],
    ):
        faults.append("QEMU argv endpoint devfn differs from the declared BDF")
    if len(parent_records) != 1:
        faults.append("QEMU argv lacks one unique endpoint parent")
        return faults
    parent = parent_records[0]
    if (
        parent.get("model") != "pcie-root-port"
        or parent.get("bus") != "pcie.0"
        or root_parts[1] != 0
    ):
        faults.append("QEMU argv parent is not the declared root-bus port")
    if _qemu_addr_devfn(parent.get("addr")) != (
        root_parts[2],
        root_parts[3],
    ):
        faults.append("QEMU argv root devfn differs from the declared BDF")
    return sorted(set(faults))


def gate_record_shape_faults(
    value: Any,
    *,
    snapshot: Any,
    expected_gate: str | None,
    enforce_gate: bool = True,
) -> list[str]:
    """Recompute the exact gate record from its bound raw snapshot."""

    faults = _closed_fields_fault(value, GATE_RECORD_FIELDS, "gate record")
    if faults or not isinstance(value, dict):
        return faults
    if not isinstance(snapshot, dict):
        return ["gate record lacks a closed raw snapshot"]
    try:
        effective = esxi_aer.gate_tuple_from_snapshot(
            snapshot,
            CONTROLLED_BITS,
        )
        root_path = esxi_aer.root_path_from_snapshot(snapshot)
        correctable_mask = int(
            snapshot["endpointState"]["correctableErrorMask"]
        )
    except (KeyError, TypeError, ValueError):
        return ["gate record cannot be recomputed from its raw snapshot"]
    if enforce_gate:
        if expected_gate in SUPPORTED_GATES:
            requested = SUPPORTED_GATES[expected_gate]
        else:
            requested_matches = [
                candidate
                for candidate in SUPPORTED_GATES.values()
                if value.get("requested") == candidate.as_dict()
            ]
            if len(requested_matches) != 1:
                return ["gate record lacks a closed expected gate"]
            requested = requested_matches[0]
        expected = {
            "requested": requested.as_dict(),
            "effective": effective.as_dict(),
            "rootPath": root_path.as_dict(),
            "correctableMask": correctable_mask,
            "checks": {
                "tupleMatches": effective == requested,
                "rootPathOpen": root_path.open,
                "b0AndB1Unmasked": not bool(
                    correctable_mask & CONTROLLED_BITS
                ),
            },
        }
    else:
        expected = {
            "requested": None,
            "effective": effective.as_dict(),
            "rootPath": root_path.as_dict(),
            "correctableMask": correctable_mask,
            "checks": {
                "not-enforced-during-pre-sequence-owner-activation": True,
            },
        }
    if value != expected:
        faults.append(
            "gate record differs from its raw snapshot and enforcement mode"
        )
    return sorted(set(faults))


def transition_record_shape_faults(
    value: Any,
    *,
    expected_command: str,
    expected_status: str,
) -> list[str]:
    faults = _closed_fields_fault(
        value,
        TRANSITION_RECORD_FIELDS,
        "QEMU transition",
    )
    if faults or not isinstance(value, dict):
        return faults
    if value.get("command") != expected_command:
        faults.append("QEMU transition command is not exact")
    if not isinstance(value.get("output"), str):
        faults.append("QEMU transition output is not a string")
    status = value.get("status")
    if (
        not isinstance(status, str)
        or expected_status.lower() not in status.lower()
    ):
        faults.append("QEMU transition status is not exact")
    for field_name in ("observedAt", "reason"):
        if (
            not isinstance(value.get(field_name), str)
            or not value[field_name]
        ):
            faults.append(f"QEMU transition {field_name} is not a string")
    return sorted(set(faults))


def direct_transition_record_shape_faults(
    value: Any,
    *,
    expected_command: str,
    expected_status: str,
) -> list[str]:
    faults = _closed_fields_fault(
        value,
        DIRECT_TRANSITION_RECORD_FIELDS,
        "direct QEMU transition",
    )
    if faults or not isinstance(value, dict):
        return faults
    if value.get("command") != expected_command:
        faults.append("direct QEMU transition command is not exact")
    if not isinstance(value.get("output"), str):
        faults.append("direct QEMU transition output is not a string")
    status = value.get("status")
    if (
        not isinstance(status, str)
        or expected_status.lower() not in status.lower()
    ):
        faults.append("direct QEMU transition status is not exact")
    if _utc_datetime(value.get("observedAt")) is None:
        faults.append("direct QEMU transition observedAt is not UTC")
    return sorted(set(faults))


def gc_guard_record_shape_faults(value: Any) -> list[str]:
    faults = _closed_fields_fault(
        value,
        GC_GUARD_RECORD_FIELDS,
        "cyclic-GC guard",
    )
    if faults or not isinstance(value, dict):
        return faults
    if not isinstance(value.get("wasEnabled"), bool):
        faults.append("cyclic-GC guard wasEnabled is not boolean")
    if not isinstance(value.get("disabledBeforeResume"), bool):
        faults.append(
            "cyclic-GC guard disabledBeforeResume is not boolean"
        )
    for field_name in ("thresholds", "countsBefore"):
        raw = value.get(field_name)
        if (
            not isinstance(raw, list)
            or not raw
            or any(
                not isinstance(item, int) or isinstance(item, bool)
                for item in raw
            )
        ):
            faults.append(f"cyclic-GC guard {field_name} is not numeric")
    for field_name in ("preResumeCollected", "postPauseCollected"):
        raw = value.get(field_name)
        if (
            raw is not None
            and (not isinstance(raw, int) or isinstance(raw, bool) or raw < 0)
        ):
            faults.append(f"cyclic-GC guard {field_name} is malformed")
    for field_name in ("armedAt", "releasedAt", "releaseState"):
        if (
            not isinstance(value.get(field_name), str)
            or not value[field_name]
        ):
            faults.append(f"cyclic-GC guard {field_name} is not a string")
    if value.get("fault") is not None:
        faults.append("cyclic-GC guard carries a fault")
    return sorted(set(faults))

SAFETY_COVERAGE_PATH_PATTERNS = {
    ("t0-baseline.json", "MONITORED_WORKER"): (
        re.compile(r"^/preSequenceSafetyWindows/[0-9]+$"),
    ),
    ("t1-effective-controls.json", "MONITORED_WORKER"): (
        re.compile(r"^/activeVmSafetyWindows/[0-9]+$"),
    ),
    ("t1-effective-controls.json", "GATE_LEASE_APPLY"): (
        re.compile(r"^/gateLease$"),
    ),
    ("t4-window.json", "SERVICE_WINDOW"): (
        re.compile(r"^/windows/[0-9]+$"),
    ),
    ("t4-window.json", "MONITORED_WORKER"): (
        re.compile(r"^/windows/[0-9]+$"),
    ),
    ("t5-transition-or-clear.json", "GATE_LEASE_RESTORE"): (
        re.compile(r"^/gateRestore$"),
    ),
    ("t5-transition-or-clear.json", "MONITORED_WORKER"): (
        re.compile(r"^/activeVmCleanupSafetyWindows/[0-9]+$"),
    ),
    (
        "t5-transition-or-clear.json",
        "FINAL_RUNNING_STABILIZATION",
    ): (
        re.compile(r"^/finalRunningSafetyTail$"),
    ),
}


def _numeric_snapshot_record_common_faults(
    record: dict[str, Any],
    *,
    expected_gate: str | None = None,
) -> list[str]:
    """Validate the closed, successful paused numeric-record core."""

    faults: list[str] = []
    label = record.get("label")
    if not isinstance(label, str) or not label:
        faults.append("label is not a non-empty string")
    operation = record.get("operation")
    if not isinstance(operation, str) or not operation:
        faults.append("operation is not a non-empty string")
    if record.get("safetyBoundary") not in SAFETY_BOUNDARIES:
        faults.append("safetyBoundary is not a closed enum value")
    observed_at = record.get("observedAt")
    if not isinstance(observed_at, str) or not observed_at:
        faults.append("observedAt is not a non-empty string")
    if record.get("qemuPaused") is not True:
        faults.append("qemuPaused is not true")
    if record.get("partial") is not False:
        faults.append("partial is not false")
    snapshot = record.get("snapshot")
    if not isinstance(snapshot, dict):
        faults.append("snapshot is not an object")
        return faults
    faults.extend(outer_snapshot_shape_faults(snapshot))
    faults.extend(
        gate_record_shape_faults(
            record.get("gate"),
            snapshot=snapshot,
            expected_gate=expected_gate,
        )
    )
    endpoint = snapshot.get("endpointState")
    root = snapshot.get("rootState")
    if not isinstance(endpoint, dict) or not isinstance(root, dict):
        faults.append("snapshot endpoint/root state is missing")
        return faults
    try:
        public = outer_to_public_state(snapshot)
    except (KeyError, TypeError, ValueError):
        faults.append("snapshot cannot be projected to the public state")
    else:
        faults.extend(
            f"snapshot public shape: {fault}"
            for fault in public_snapshot_shape_faults({"record": public})
        )
    try:
        derived = esxi_aer._partial_numeric_safety_faults(snapshot)
    except (KeyError, TypeError, ValueError):
        derived = []
        faults.append("numeric snapshot safety cannot be derived")
    claimed = record.get("safetyFaults")
    if not isinstance(claimed, list) or any(
        not isinstance(item, str) for item in claimed
    ):
        faults.append("safetyFaults is not a string list")
    elif sorted(set(claimed)) != sorted(set(derived)):
        faults.append("safetyFaults disagrees with raw registers")
    if derived:
        faults.append("numeric snapshot contains fail-stop evidence")
    return faults


def paused_numeric_snapshot_record_faults(
    record: dict[str, Any],
    *,
    expected_phase: str | None = None,
    expected_boundary: str | None = None,
    expected_gate: str | None = None,
) -> list[str]:
    """Validate the exact public snapshot record emitted by ``capture``."""

    faults = _numeric_snapshot_record_common_faults(
        record,
        expected_gate=expected_gate,
    )
    if set(record) != PAUSED_NUMERIC_SNAPSHOT_RECORD_FIELDS:
        faults.append("record fields differ from the closed public schema")
    if record.get("recordKind") != PAUSED_NUMERIC_SNAPSHOT_RECORD_KIND:
        faults.append("recordKind is not PAUSED_NUMERIC_SNAPSHOT")
    phase = record.get("phase")
    if phase not in {"t2", "t3", "t4", "t5"}:
        faults.append("phase is not a public snapshot phase")
    if expected_phase is not None and phase != expected_phase:
        faults.append("phase disagrees with its raw artifact route")
    if (
        expected_boundary is not None
        and record.get("safetyBoundary") != expected_boundary
    ):
        faults.append("safetyBoundary disagrees with its raw artifact route")
    if (
        isinstance(record.get("label"), str)
        and record["label"].endswith("-pre-state")
    ):
        faults.append("public snapshot label is reserved for pre-state")
    snapshot = record.get("snapshot")
    if isinstance(snapshot, dict):
        try:
            expected_source = root_source_meaning(
                outer_to_public_state(snapshot)
            )
        except (KeyError, TypeError, ValueError):
            expected_source = None
        if (
            expected_source is None
            or record.get("sourceMeaning") != expected_source
        ):
            faults.append("sourceMeaning disagrees with the raw snapshot")
    return sorted(set(faults))


def pre_mutation_numeric_snapshot_record_faults(
    record: dict[str, Any],
    *,
    expected_gate: str | None = None,
) -> list[str]:
    """Validate the exact private pre-mutation numeric authority record."""

    faults = _numeric_snapshot_record_common_faults(
        record,
        expected_gate=expected_gate,
    )
    if set(record) != PRE_MUTATION_NUMERIC_SNAPSHOT_RECORD_FIELDS:
        faults.append("record fields differ from the closed pre-state schema")
    if (
        record.get("recordKind")
        != PRE_MUTATION_NUMERIC_SNAPSHOT_RECORD_KIND
    ):
        faults.append(
            "recordKind is not PRE_MUTATION_NUMERIC_SNAPSHOT"
        )
    label = record.get("label")
    if not isinstance(label, str) or not label.endswith("-pre-state"):
        faults.append("pre-state label lacks the reserved suffix")
    return sorted(set(faults))


def o4_guest_window_receipt_faults(
    record: dict[str, Any],
    *,
    owner_phase: Any,
    oracle_profile: dict[str, Any],
) -> list[str]:
    """Validate the one non-snapshot record allowed in ``t2.steps``."""

    faults: list[str] = []
    if set(record) != O4_GUEST_WINDOW_RECEIPT_FIELDS:
        faults.append("record fields differ from the closed O4 receipt schema")
    if record.get("recordKind") != O4_GUEST_WINDOW_RECEIPT_RECORD_KIND:
        faults.append("recordKind is not O4_GUEST_WINDOW_RECEIPT")
    if owner_phase != "O4":
        faults.append("O4 guest-window receipt appears outside O4")
    if record.get("label") != "o4-window-before-sequence":
        faults.append("O4 guest-window receipt label is not exact")
    observed_at = record.get("observedAt")
    if not isinstance(observed_at, str) or not observed_at:
        faults.append("O4 guest-window observedAt is not a non-empty string")
    window = record.get("window")
    if not isinstance(window, dict):
        faults.append("O4 guest-window value is not an object")
        return sorted(set(faults))
    if set(window) != O4_GUEST_WINDOW_FIELDS:
        faults.append("O4 guest-window fields differ from the closed schema")

    values: dict[str, float] = {}
    for field_name in O4_GUEST_WINDOW_FIELDS:
        value = window.get(field_name)
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
        ):
            faults.append(f"O4 guest-window {field_name} is not finite")
        else:
            values[field_name] = float(value)
    if len(values) != len(O4_GUEST_WINDOW_FIELDS):
        return sorted(set(faults))

    timing = oracle_profile.get("timingEnvelope")
    timing = timing if isinstance(timing, dict) else {}
    attested_window = timing.get("guestWindowSeconds")
    minimum_required = timing.get("minimumGuestWindowRemainingSecondsO4")
    if (
        not isinstance(attested_window, (int, float))
        or isinstance(attested_window, bool)
        or not math.isfinite(float(attested_window))
        or values["windowSeconds"] != float(attested_window)
    ):
        faults.append("O4 guest-window duration differs from the profile")
    if (
        not isinstance(minimum_required, (int, float))
        or isinstance(minimum_required, bool)
        or not math.isfinite(float(minimum_required))
        or values["requiredRemainingSeconds"] < float(minimum_required)
    ):
        faults.append("O4 guest-window required duration is below the profile")
    if values["elapsedSinceOpenObserved"] < 0:
        faults.append("O4 guest-window elapsed duration is negative")
    if values["requiredRemainingSeconds"] <= 0:
        faults.append("O4 guest-window required duration is not positive")
    if (
        values["remainingSeconds"]
        < values["requiredRemainingSeconds"]
    ):
        faults.append("O4 guest-window remaining duration is insufficient")
    if not math.isclose(
        values["windowSeconds"] - values["elapsedSinceOpenObserved"],
        values["remainingSeconds"],
        rel_tol=0.0,
        abs_tol=1e-9,
    ):
        faults.append("O4 guest-window arithmetic is inconsistent")
    return sorted(set(faults))


def _successful_numeric_sample_faults(
    sample: Any,
    *,
    expected_fields: set[str],
    expected_gate: str | None,
    enforce_gate: bool = True,
    timestamp_field: str,
) -> list[str]:
    faults = _closed_fields_fault(
        sample,
        expected_fields,
        "runnable numeric sample",
    )
    if faults or not isinstance(sample, dict):
        return faults
    snapshot = sample.get("snapshot")
    faults.extend(outer_snapshot_shape_faults(snapshot))
    faults.extend(
        gate_record_shape_faults(
            sample.get("gate"),
            snapshot=snapshot,
            expected_gate=expected_gate,
            enforce_gate=enforce_gate,
        )
    )
    for field_name in (
        "actualElapsedSeconds",
        "sampleStartGapSeconds",
        "sampleDurationSeconds",
    ):
        raw = sample.get(field_name)
        if not _finite_number(raw) or float(raw) < 0:
            faults.append(f"runnable sample {field_name} is invalid")
    if "delaySeconds" in expected_fields:
        raw_delay = sample.get("delaySeconds")
        if not _finite_number(raw_delay) or float(raw_delay) < 0:
            faults.append("runnable sample delaySeconds is invalid")
    if (
        not isinstance(sample.get("sampleIndex"), int)
        or isinstance(sample.get("sampleIndex"), bool)
        or sample["sampleIndex"] < 0
    ):
        faults.append("runnable sample index is invalid")
    if (
        not isinstance(sample.get(timestamp_field), str)
        or not sample[timestamp_field]
    ):
        faults.append(f"runnable sample {timestamp_field} is invalid")
    if sample.get("partial") is not False:
        faults.append("runnable sample is partial")
    if "readFault" in expected_fields and sample.get("readFault") is not None:
        faults.append("runnable sample carries a read fault")
    try:
        derived = esxi_aer._partial_numeric_safety_faults(snapshot)
    except (KeyError, TypeError, ValueError):
        derived = []
        faults.append("runnable sample safety cannot be derived")
    if sample.get("safetyFaults") != derived or derived:
        faults.append("runnable sample safetyFaults are not clean and exact")
    if isinstance(snapshot, dict):
        endpoint_state = snapshot.get("endpointState")
        root_state = snapshot.get("rootState")
        try:
            expected_endpoint = {
                "deviceStatus": int(endpoint_state["deviceStatus"]),
                "uncorrectableErrorStatus": int(
                    endpoint_state["uncorrectableErrorStatus"]
                ),
                "correctableErrorStatus": int(
                    endpoint_state["correctableErrorStatus"]
                ),
            }
            expected_root = {
                "deviceStatus": int(root_state["deviceStatus"]),
                "uncorrectableErrorStatus": int(
                    root_state["uncorrectableErrorStatus"]
                ),
                "rootErrorStatus": int(root_state["rootErrorStatus"]),
            }
        except (KeyError, TypeError, ValueError):
            expected_endpoint = None
            expected_root = None
        if (
            not isinstance(sample.get("endpoint"), dict)
            or set(sample["endpoint"]) != SAMPLE_ENDPOINT_FIELDS
            or sample["endpoint"] != expected_endpoint
        ):
            faults.append("runnable sample endpoint projection is not exact")
        if (
            not isinstance(sample.get("root"), dict)
            or set(sample["root"]) != SAMPLE_ROOT_FIELDS
            or sample["root"] != expected_root
        ):
            faults.append("runnable sample root projection is not exact")
    return sorted(set(faults))


def runnable_window_record_shape_faults(
    record: dict[str, Any],
    *,
    phase: str,
    expected_gate: str | None = None,
) -> list[str]:
    """Close runnable-window records on their exact phase route."""

    kind = record.get("safetyWindowKind")
    expected_boundary = {
        "t0": "PRE_INJECTION",
        "t1": "PRE_INJECTION",
        "t4": "ATTRIBUTION_WINDOW",
        "t5": "POST_CLEANUP",
    }.get(phase)
    if expected_boundary is None:
        return ["runnable-window record appears outside a closed route"]
    if kind == "SERVICE_WINDOW":
        if phase != "t4":
            return ["SERVICE_WINDOW appears outside t4"]
        expected_fields = SERVICE_WINDOW_RECORD_FIELDS
    elif kind == "MONITORED_WORKER":
        expected_fields = MONITORED_WORKER_RECORD_FIELDS
    else:
        return ["record is not a closed runnable-window kind"]
    faults: list[str] = []
    if set(record) != expected_fields:
        faults.append(f"{kind} fields differ from the closed schema")
    if (
        not isinstance(record.get("label"), str)
        or not record.get("label")
    ):
        faults.append(f"{kind} label is not a non-empty string")
    if (
        not isinstance(record.get("description"), str)
        or not record.get("description")
    ):
        faults.append(f"{kind} description is not a non-empty string")
    if record.get("safetyBoundary") not in SAFETY_BOUNDARIES:
        faults.append(f"{kind} safetyBoundary is not a closed enum value")
    if kind == "SERVICE_WINDOW":
        if record.get("safetyBoundary") != expected_boundary:
            faults.append("SERVICE_WINDOW is outside ATTRIBUTION_WINDOW")
        if record.get("ownerObservationPolicy") != (
            "pre-sequence and monitored terminal bracket only"
        ):
            faults.append("SERVICE_WINDOW owner-observation policy drifted")
        if record.get("ownerObservation") is not None:
            faults.append("SERVICE_WINDOW ownerObservation is not null")
        faults.extend(
            transition_record_shape_faults(
                record.get("resume"),
                expected_command="cont",
                expected_status="running",
            )
        )
        faults.extend(
            transition_record_shape_faults(
                record.get("pause"),
                expected_command="stop",
                expected_status="paused",
            )
        )
        faults.extend(
            gc_guard_record_shape_faults(record.get("pythonGcGuard"))
        )
        for field_name in (
            "timelineFault",
            "pauseFault",
            "pauseTailFault",
            "gcGuardFault",
            "finalizationFault",
        ):
            if record.get(field_name) is not None:
                faults.append(f"SERVICE_WINDOW {field_name} is non-null")
        if record.get("coverageComplete") is not True:
            faults.append("SERVICE_WINDOW coverageComplete is not true")
        poll = record.get("safetyPoll")
        faults.extend(
            _closed_fields_fault(
                poll,
                SERVICE_SAFETY_POLL_FIELDS,
                "SERVICE_WINDOW safetyPoll",
            )
        )
        if isinstance(poll, dict):
            samples = poll.get("samples")
            if not isinstance(samples, list) or not samples:
                faults.append("SERVICE_WINDOW has no numeric samples")
            else:
                for index, sample in enumerate(samples):
                    faults.extend(
                        f"SERVICE_WINDOW samples[{index}]: {fault}"
                        for fault in _successful_numeric_sample_faults(
                            sample,
                            expected_fields=SERVICE_SAMPLE_FIELDS,
                            expected_gate=expected_gate,
                            timestamp_field="capturedAt",
                        )
                    )
                if poll.get("sampleCount") != len(samples):
                    faults.append(
                        "SERVICE_WINDOW sampleCount differs from samples"
                    )
            timeline = record.get("timeline")
            if not isinstance(timeline, list):
                faults.append("SERVICE_WINDOW timeline is not a list")
            else:
                for index, item in enumerate(timeline):
                    local = _closed_fields_fault(
                        item,
                        SERVICE_TIMELINE_FIELDS,
                        f"SERVICE_WINDOW timeline[{index}]",
                    )
                    faults.extend(local)
                    if isinstance(item, dict):
                        snapshot = item.get("snapshot")
                        faults.extend(outer_snapshot_shape_faults(snapshot))
                        faults.extend(
                            gate_record_shape_faults(
                                item.get("gate"),
                                snapshot=snapshot,
                                expected_gate=expected_gate,
                            )
                        )
                        try:
                            derived = (
                                esxi_aer._partial_numeric_safety_faults(
                                    snapshot
                                )
                            )
                        except (KeyError, TypeError, ValueError):
                            derived = []
                            faults.append(
                                "SERVICE_WINDOW timeline safety cannot "
                                "be derived"
                            )
                        if item.get("safetyFaults") != derived or derived:
                            faults.append(
                                "SERVICE_WINDOW timeline safety is not exact"
                            )
        if not _finite_number(record.get("startedAtMonotonic")):
            faults.append("SERVICE_WINDOW startedAtMonotonic is invalid")
        if (
            not isinstance(record.get("finishedAt"), str)
            or not record["finishedAt"]
        ):
            faults.append("SERVICE_WINDOW finishedAt is invalid")
    else:
        expected_enforce_gate = phase == "t4"
        if record.get("enforceGate") is not expected_enforce_gate:
            faults.append(
                "MONITORED_WORKER enforceGate disagrees with its route"
            )
        if record.get("safetyBoundary") != expected_boundary:
            faults.append(
                "MONITORED_WORKER safetyBoundary disagrees with its route"
            )
        faults.extend(
            transition_record_shape_faults(
                record.get("resume"),
                expected_command="cont",
                expected_status="running",
            )
        )
        faults.extend(
            transition_record_shape_faults(
                record.get("pause"),
                expected_command="stop",
                expected_status="paused",
            )
        )
        faults.extend(
            gc_guard_record_shape_faults(record.get("pythonGcGuard"))
        )
        for field_name in (
            "monitorFault",
            "immediateStopFault",
            "finalStopFault",
            "executorShutdownFault",
            "cancelFault",
            "gcGuardFault",
            "controlFault",
            "tailGapFault",
            "finalizationFault",
            "workerFault",
        ):
            if record.get(field_name) is not None:
                faults.append(f"MONITORED_WORKER {field_name} is non-null")
        if record.get("gateFault") is not False:
            faults.append("MONITORED_WORKER gateFault is not false")
        if record.get("coverageComplete") is not True:
            faults.append("MONITORED_WORKER coverageComplete is not true")
        if record.get("snapshotMode") != "PINNED_TOPOLOGY_BLOCK_BATCH":
            faults.append("MONITORED_WORKER snapshotMode is not exact")
        samples = record.get("samples")
        if not isinstance(samples, list) or not samples:
            faults.append("MONITORED_WORKER has no numeric samples")
        else:
            for index, sample in enumerate(samples):
                faults.extend(
                    f"MONITORED_WORKER samples[{index}]: {fault}"
                    for fault in _successful_numeric_sample_faults(
                        sample,
                        expected_fields=MONITORED_SAMPLE_FIELDS,
                        expected_gate=expected_gate,
                        enforce_gate=expected_enforce_gate,
                        timestamp_field="observedAt",
                    )
                )
            if record.get("sampleCount") != len(samples):
                faults.append(
                    "MONITORED_WORKER sampleCount differs from samples"
                )
            first_sample = (
                samples[0] if isinstance(samples[0], dict) else {}
            )
            last_sample = (
                samples[-1] if isinstance(samples[-1], dict) else {}
            )
            if record.get("firstSnapshot") != first_sample.get("snapshot"):
                faults.append(
                    "MONITORED_WORKER firstSnapshot is not exact"
                )
            if record.get("lastSnapshot") != last_sample.get("snapshot"):
                faults.append(
                    "MONITORED_WORKER lastSnapshot is not exact"
                )
        if record.get("safetyEvents") != []:
            faults.append("MONITORED_WORKER safetyEvents are not empty")
        for field_name in (
            "startedAtMonotonic",
            "maximumPollIntervalSeconds",
            "pollIntervalSeconds",
            "maximumObservedPollGapSeconds",
            "maximumObservedReadDurationSeconds",
            "finalStopConfirmedElapsedSeconds",
            "lastSampleFinishedElapsedSeconds",
            "tailGapSeconds",
        ):
            if not _finite_number(record.get(field_name)):
                faults.append(
                    f"MONITORED_WORKER {field_name} is invalid"
                )
        if (
            not isinstance(record.get("finishedAt"), str)
            or not record["finishedAt"]
        ):
            faults.append("MONITORED_WORKER finishedAt is invalid")
    return sorted(set(faults))


def _collect_safety_coverage_v1_draft(
    artifacts: Iterable[tuple[str, str, Any]],
) -> list[dict[str, Any]]:
    """Normalize every allow-listed runnable window into offline coverage."""

    records: list[dict[str, Any]] = []

    def numeric(value: Any) -> float | None:
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and value >= 0
        ):
            return float(value)
        return None

    def normalize(
        value: dict[str, Any],
        *,
        artifact: str,
        route_boundary: str,
        path: str,
        inherited_label: str | None,
    ) -> None:
        kind = value.get("safetyWindowKind")
        explicit_boundary = value.get("safetyBoundary")
        boundary = (
            str(explicit_boundary)
            if explicit_boundary in SAFETY_BOUNDARIES
            else route_boundary
        )
        boundary_source = (
            "EXPLICIT_RECORD"
            if explicit_boundary in SAFETY_BOUNDARIES
            else "ALLOW_LISTED_ARTIFACT_ROUTE"
        )
        label = (
            str(value["label"])
            if isinstance(value.get("label"), str)
            else (inherited_label or path.rsplit("/", 1)[-1] or artifact)
        )
        if kind == "CONTINUOUS_TIMELINE":
            poll = value
        elif kind in {"GATE_LEASE_APPLY", "GATE_LEASE_RESTORE"}:
            timeline = value.get("timeline")
            timeline = timeline if isinstance(timeline, dict) else {}
            poll = timeline.get("resumedSafetyPoll")
            poll = poll if isinstance(poll, dict) else {}
        elif kind == "FINAL_RUNNING_STABILIZATION":
            poll = value.get("safetyPoll")
            poll = poll if isinstance(poll, dict) else {}
        elif kind == "SERVICE_WINDOW":
            poll = value.get("safetyPoll")
            poll = poll if isinstance(poll, dict) else {}
        else:
            poll = value

        samples = poll.get("samples")
        samples = samples if isinstance(samples, list) else []
        declared_count = poll.get("sampleCount")
        declared_count = (
            declared_count
            if isinstance(declared_count, int)
            and not isinstance(declared_count, bool)
            else None
        )
        maximum_interval = numeric(
            poll.get(
                "maximumPollIntervalSeconds",
                poll.get(
                    "maximumIntervalSeconds",
                    value.get("maximumPollIntervalSeconds"),
                ),
            )
        )
        maximum_observed_gap = numeric(
            poll.get(
                "maximumObservedPollGapSeconds",
                poll.get(
                    "maximumObservedGapSeconds",
                    value.get("maximumObservedPollGapSeconds"),
                ),
            )
        )
        durations = [
            numeric(item.get("sampleDurationSeconds"))
            for item in samples
            if isinstance(item, dict)
        ]
        maximum_read_duration = max(
            (item for item in durations if item is not None),
            default=None,
        )
        closure = poll.get("closure")
        closure = closure if isinstance(closure, dict) else {}
        tail_gap = numeric(
            closure.get(
                "tailGapSeconds",
                poll.get(
                    "tailGapSeconds",
                    value.get("tailGapSeconds"),
                ),
            )
        )
        fault_fields = (
            "timelineFault",
            "pauseFault",
            "pauseTailFault",
            "monitorFault",
            "immediateStopFault",
            "finalStopFault",
            "executorShutdownFault",
            "controlFault",
            "tailGapFault",
            "samplerFault",
            "resumeFault",
            "failStopFault",
            "safetyHoldFault",
            "samplerFailureHoldFault",
            "resumeFailureHoldFault",
        )
        faults = [
            {
                "field": field,
                "value": copy.deepcopy(value.get(field)),
            }
            for field in fault_fields
            if value.get(field) not in (None, [], {})
        ]
        poll_faults = poll.get("pollFaults")
        if isinstance(poll_faults, list) and poll_faults:
            faults.append(
                {
                    "field": "pollFaults",
                    "value": copy.deepcopy(poll_faults),
                }
            )

        if kind in {"SERVICE_WINDOW", "MONITORED_WORKER"}:
            claimed_complete = value.get("coverageComplete") is True
        elif kind == "FINAL_RUNNING_STABILIZATION":
            claimed_complete = bool(
                poll.get("complete") is True
                and value.get("outcome") == "CLEAN_RUNNING"
            )
        else:
            claimed_complete = poll.get("complete") is True
            if kind in {"GATE_LEASE_APPLY", "GATE_LEASE_RESTORE"}:
                mode = closure.get("mode")
                claimed_complete = bool(
                    claimed_complete
                    and (
                        mode == "RUNNING_AFTER_TARGET_COVERAGE"
                        or (
                            mode == "PAUSED_ACK"
                            and closure.get("stopConfirmed") is True
                        )
                    )
                )
        derived_complete = bool(
            claimed_complete
            and declared_count == len(samples)
            and len(samples) > 0
            and maximum_interval is not None
            and maximum_interval > 0
            and maximum_observed_gap is not None
            and maximum_observed_gap <= maximum_interval
            and (
                maximum_read_duration is None
                or maximum_read_duration <= maximum_interval
            )
            and (
                tail_gap is None
                or tail_gap <= maximum_interval
            )
            and not faults
        )
        records.append(
            {
                "boundary": boundary,
                "windowKind": kind,
                "declaredSampleCount": declared_count,
                "observedSampleCount": len(samples),
                "maximumIntervalSeconds": maximum_interval,
                "maximumObservedGapSeconds": maximum_observed_gap,
                "maximumReadDurationSeconds": maximum_read_duration,
                "tailGapSeconds": tail_gap,
                "faults": faults,
                "complete": derived_complete,
                "provenance": {
                    "artifact": artifact,
                    "jsonPath": path,
                    "label": label,
                    "boundarySource": boundary_source,
                },
            }
        )

    def walk(
        value: Any,
        *,
        artifact: str,
        boundary: str,
        path: str,
        inherited_label: str | None,
    ) -> None:
        if isinstance(value, dict):
            label = (
                str(value["label"])
                if isinstance(value.get("label"), str)
                else inherited_label
            )
            kind = value.get("safetyWindowKind")
            if kind in SAFETY_WINDOW_KINDS:
                normalize(
                    value,
                    artifact=artifact,
                    route_boundary=boundary,
                    path=path,
                    inherited_label=label,
                )
                return
            for key in sorted(value):
                if key in SAFETY_DERIVED_KEYS:
                    continue
                walk(
                    value[key],
                    artifact=artifact,
                    boundary=boundary,
                    path=f"{path}/{key}",
                    inherited_label=label,
                )
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(
                    item,
                    artifact=artifact,
                    boundary=boundary,
                    path=f"{path}/{index}",
                    inherited_label=inherited_label,
                )

    for artifact, boundary, value in artifacts:
        if boundary not in SAFETY_BOUNDARIES:
            raise ValueError(f"invalid safety coverage boundary: {boundary}")
        walk(
            value,
            artifact=artifact,
            boundary=boundary,
            path="",
            inherited_label=None,
        )
    unique = {canonical_json(item): item for item in records}
    return [unique[key] for key in sorted(unique)]


def _build_safety_coverage_v1_draft(
    *,
    t0: dict[str, Any],
    t1: dict[str, Any],
    t4: dict[str, Any],
    t5: dict[str, Any],
) -> list[dict[str, Any]]:
    """Collect runnable-window coverage from the four allow-listed phases."""

    return _collect_safety_coverage_v1_draft(
        (
            ("t0-baseline.json", "PRE_INJECTION", t0),
            ("t1-effective-controls.json", "PRE_INJECTION", t1),
            ("t4-window.json", "ATTRIBUTION_WINDOW", t4),
            ("t5-transition-or-clear.json", "POST_CLEANUP", t5),
        )
    )


def _safety_coverage_shape_faults_v1_draft(
    evaluation_input: dict[str, Any],
) -> list[str]:
    coverage = evaluation_input.get("safetyCoverage")
    if coverage is None:
        return ["safetyCoverage is missing"]
    if not isinstance(coverage, list):
        return ["safetyCoverage is not a list"]
    if not coverage:
        return ["safetyCoverage is empty"]
    faults: list[str] = []
    artifact_boundaries = {
        "t0-baseline.json": "PRE_INJECTION",
        "t1-effective-controls.json": "PRE_INJECTION",
        "t4-window.json": "ATTRIBUTION_WINDOW",
        "t5-transition-or-clear.json": "POST_CLEANUP",
    }
    for index, item in enumerate(coverage):
        prefix = f"safetyCoverage[{index}]"
        if not isinstance(item, dict):
            faults.append(f"{prefix} is not an object")
            continue
        if item.get("boundary") not in SAFETY_BOUNDARIES:
            faults.append(f"{prefix}.boundary is not a closed enum value")
        if item.get("windowKind") not in SAFETY_WINDOW_KINDS:
            faults.append(f"{prefix}.windowKind is not allow-listed")
        for key in ("declaredSampleCount", "observedSampleCount"):
            value = item.get(key)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                faults.append(f"{prefix}.{key} is not a non-negative integer")
        for key in (
            "maximumIntervalSeconds",
            "maximumObservedGapSeconds",
        ):
            value = item.get(key)
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or value < 0
            ):
                faults.append(f"{prefix}.{key} is not a non-negative number")
        for key in ("maximumReadDurationSeconds", "tailGapSeconds"):
            value = item.get(key)
            if value is not None and (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or value < 0
            ):
                faults.append(f"{prefix}.{key} is not null or non-negative")
        if not isinstance(item.get("faults"), list):
            faults.append(f"{prefix}.faults is not a list")
        if not isinstance(item.get("complete"), bool):
            faults.append(f"{prefix}.complete is not a boolean")
        provenance = item.get("provenance")
        if not isinstance(provenance, dict):
            faults.append(f"{prefix}.provenance is not an object")
            continue
        for key in ("artifact", "jsonPath", "label", "boundarySource"):
            if not isinstance(provenance.get(key), str):
                faults.append(f"{prefix}.provenance.{key} is not a string")
        artifact = provenance.get("artifact")
        expected = artifact_boundaries.get(artifact)
        if expected is None:
            faults.append(f"{prefix}.provenance.artifact is not allow-listed")
        elif item.get("boundary") != expected:
            faults.append(
                f"{prefix}.boundary disagrees with its raw artifact phase"
            )
    observed_boundaries = {
        item.get("boundary")
        for item in coverage
        if isinstance(item, dict)
    }
    required_boundaries = (
        SAFETY_BOUNDARIES
        if evaluation_input.get("enteredInjection") is True
        else {"PRE_INJECTION"}
    )
    for boundary in sorted(required_boundaries - observed_boundaries):
        faults.append(f"safetyCoverage lacks {boundary}")
    return sorted(set(faults))


def _derive_safety_coverage_faults_v1_draft(
    evaluation_input: dict[str, Any],
) -> list[dict[str, Any]]:
    coverage = evaluation_input.get("safetyCoverage")
    if not isinstance(coverage, list):
        return []
    records: list[dict[str, Any]] = []
    for index, item in enumerate(coverage):
        if not isinstance(item, dict):
            continue
        if item.get("boundary") not in SAFETY_BOUNDARIES:
            continue
        if item.get("complete") is True:
            continue
        provenance = item.get("provenance")
        label = (
            provenance.get("label")
            if isinstance(provenance, dict)
            else None
        )
        records.append(
            {
                "label": (
                    label
                    if isinstance(label, str) and label
                    else f"safety-coverage:{index:04d}"
                ),
                "boundary": item.get("boundary"),
                "faults": (
                    copy.deepcopy(item.get("faults"))
                    if isinstance(item.get("faults"), list)
                    else []
                )
                + ["runnable safety coverage is incomplete"],
            }
        )
    return records


def build_safety_coverage(
    *,
    t0: dict[str, Any],
    t1: dict[str, Any],
    t2: dict[str, Any],
    t3: dict[str, Any],
    t4: dict[str, Any],
    t5: dict[str, Any],
    cleanup: dict[str, Any],
) -> list[dict[str, Any]]:
    """Recompute runnable-window coverage from manifest-bound raw metadata."""

    coverage: list[dict[str, Any]] = []

    def number(value: Any) -> float | None:
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and value >= 0
            and math.isfinite(float(value))
        ):
            return float(value)
        return None

    def route_requires_window(artifact: str, path: str) -> bool:
        return any(
            route_artifact == artifact
            and any(pattern.fullmatch(path) for pattern in patterns)
            for (route_artifact, _kind), patterns in (
                SAFETY_COVERAGE_PATH_PATTERNS.items()
            )
        )

    def is_t4_window_route(artifact: str, path: str) -> bool:
        return bool(
            artifact == "t4-window.json"
            and re.fullmatch(r"/windows/[0-9]+", path)
        )

    def numeric_safety_snapshot_faults(
        sample: dict[str, Any],
        *,
        index: int,
    ) -> list[str]:
        snapshot = sample.get("snapshot")
        if not isinstance(snapshot, dict):
            return [f"samples[{index}] numeric safety snapshot is missing"]
        endpoint = snapshot.get("endpointState")
        root = snapshot.get("rootState")
        if not isinstance(endpoint, dict) or not isinstance(root, dict):
            return [
                f"samples[{index}] numeric safety snapshot endpoints "
                "are missing"
            ]
        field_specs = (
            (endpoint, "deviceStatus", 0xFFFF, "endpoint Device Status"),
            (
                endpoint,
                "uncorrectableErrorStatus",
                0xFFFFFFFF,
                "endpoint UES",
            ),
            (root, "deviceStatus", 0xFFFF, "root Device Status"),
            (
                root,
                "uncorrectableErrorStatus",
                0xFFFFFFFF,
                "root UES",
            ),
            (
                root,
                "rootErrorStatus",
                0xFFFFFFFF,
                "Root Error Status",
            ),
        )
        local: list[str] = []
        for container, key, maximum, label in field_specs:
            raw = container.get(key)
            if (
                not isinstance(raw, int)
                or isinstance(raw, bool)
                or raw < 0
                or raw > maximum
            ):
                local.append(
                    f"samples[{index}] {label} is not a bounded integer"
                )
        derived = esxi_aer._partial_numeric_safety_faults(snapshot)
        claimed = sample.get("safetyFaults")
        if not isinstance(claimed, list) or any(
            not isinstance(item, str) for item in claimed
        ):
            local.append(
                f"samples[{index}] safetyFaults is not a string list"
            )
        elif sorted(set(claimed)) != sorted(set(derived)):
            local.append(
                f"samples[{index}] safetyFaults disagrees with raw registers"
            )
        if derived:
            local.append(
                f"samples[{index}] contains numeric fail-stop evidence"
            )
        return local

    def poll_facts(poll: Any) -> dict[str, Any]:
        faults: list[str] = []
        if not isinstance(poll, dict):
            return {
                "complete": False,
                "faults": ["continuous safety poll is missing"],
                "sampleCount": 0,
                "maximumIntervalSeconds": None,
                "maximumObservedGapSeconds": None,
                "targetDelaysSeconds": None,
            }
        samples = poll.get("samples")
        samples = samples if isinstance(samples, list) else []
        target_delays = poll.get("targetDelaysSeconds")
        declared_count = poll.get("sampleCount")
        maximum = number(
            poll.get(
                "maximumPollIntervalSeconds",
                poll.get("maximumIntervalSeconds"),
            )
        )
        declared_gap = number(
            poll.get(
                "maximumObservedPollGapSeconds",
                poll.get("maximumObservedGapSeconds"),
            )
        )
        declared_read_duration = (
            number(poll.get("maximumObservedReadDurationSeconds"))
            if "maximumObservedReadDurationSeconds" in poll
            else None
        )
        if not samples:
            faults.append("no numeric safety samples")
        if (
            not isinstance(declared_count, int)
            or isinstance(declared_count, bool)
            or declared_count != len(samples)
        ):
            faults.append("sampleCount differs from the raw sample list")
        if maximum is None or maximum <= 0:
            faults.append("maximum safety poll interval is invalid")
        observed_gaps: list[float] = []
        observed_read_durations: list[float] = []
        prior_sample_start_elapsed: float | None = None
        for index, sample in enumerate(samples):
            if not isinstance(sample, dict):
                faults.append(f"samples[{index}] is not an object")
                continue
            faults.extend(
                numeric_safety_snapshot_faults(sample, index=index)
            )
            gap = number(sample.get("sampleStartGapSeconds"))
            duration = number(sample.get("sampleDurationSeconds"))
            if gap is None:
                faults.append(f"samples[{index}] gap is missing")
            else:
                observed_gaps.append(gap)
                if maximum is not None and gap > maximum:
                    faults.append(f"samples[{index}] gap exceeds maximum")
            if duration is None:
                faults.append(f"samples[{index}] duration is missing")
            else:
                observed_read_durations.append(duration)
                if maximum is not None and duration > maximum:
                    faults.append(
                        f"samples[{index}] read duration exceeds maximum"
                    )
            actual_elapsed = number(
                sample.get("actualElapsedSeconds")
            )
            if sample.get("sampleIndex") != index:
                faults.append(
                    f"samples[{index}] sampleIndex is not sequential"
                )
            if (
                actual_elapsed is None
                or duration is None
                or gap is None
                or actual_elapsed < duration
            ):
                faults.append(
                    f"samples[{index}] elapsed chronology is incomplete"
                )
            else:
                sample_start_elapsed = actual_elapsed - duration
                expected_gap = (
                    sample_start_elapsed
                    if prior_sample_start_elapsed is None
                    else (
                        sample_start_elapsed
                        - prior_sample_start_elapsed
                    )
                )
                if (
                    sample_start_elapsed < 0
                    or expected_gap < 0
                    or abs(expected_gap - gap) > 1e-9
                ):
                    faults.append(
                        f"samples[{index}] elapsed chronology "
                        "disagrees with its start gap and duration"
                    )
                prior_sample_start_elapsed = sample_start_elapsed
        recomputed_gap = max(observed_gaps, default=0.0)
        if (
            declared_gap is None
            or abs(declared_gap - recomputed_gap) > 1e-9
        ):
            faults.append(
                "maximumObservedGapSeconds differs from raw samples"
            )
        recomputed_read_duration = max(
            observed_read_durations,
            default=0.0,
        )
        if (
            "maximumObservedReadDurationSeconds" in poll
            and (
                declared_read_duration is None
                or abs(
                    declared_read_duration - recomputed_read_duration
                )
                > 1e-9
            )
        ):
            faults.append(
                "maximumObservedReadDurationSeconds differs from raw samples"
            )
        raw_poll_faults = poll.get("pollFaults")
        if isinstance(raw_poll_faults, list) and raw_poll_faults:
            faults.append("pollFaults is non-empty")
        elif raw_poll_faults is not None and not isinstance(
            raw_poll_faults,
            list,
        ):
            faults.append("pollFaults is malformed")
        declared_target_count = poll.get("targetCount")
        completed_targets = poll.get("completedTargetCount")
        normalized_target_delays: list[float] | None = None
        if target_delays is not None:
            if not isinstance(target_delays, list):
                faults.append("target-delay coverage is incomplete")
            else:
                normalized_target_delays = [
                    number(item) for item in target_delays
                ]
                if (
                    any(item is None for item in normalized_target_delays)
                    or any(
                        later <= earlier
                        for earlier, later in zip(
                            normalized_target_delays,
                            normalized_target_delays[1:],
                        )
                    )
                ):
                    faults.append("target delays are invalid")
                if (
                    not isinstance(declared_target_count, int)
                    or isinstance(declared_target_count, bool)
                    or declared_target_count != len(target_delays)
                    or not isinstance(completed_targets, int)
                    or isinstance(completed_targets, bool)
                    or completed_targets != len(target_delays)
                ):
                    faults.append("target-delay coverage is incomplete")
                raw_timeline = poll.get("timeline")
                if (
                    not isinstance(raw_timeline, list)
                    or len(raw_timeline) != len(target_delays)
                ):
                    faults.append(
                        "target timeline differs from the declared plan"
                    )
                elif (
                    normalized_target_delays is not None
                    and not any(
                        item is None
                        for item in normalized_target_delays
                    )
                ):
                    for target_index, (
                        target,
                        target_record,
                    ) in enumerate(
                        zip(
                            normalized_target_delays,
                            raw_timeline,
                        )
                    ):
                        if not isinstance(target_record, dict):
                            faults.append(
                                f"target timeline[{target_index}] is "
                                "not an object"
                            )
                            continue
                        record_target = number(
                            target_record.get("targetDelaySeconds")
                        )
                        record_delay = number(
                            target_record.get("delaySeconds")
                        )
                        record_elapsed = number(
                            target_record.get("actualElapsedSeconds")
                        )
                        sample_index = target_record.get("sampleIndex")
                        if (
                            record_target is None
                            or record_delay is None
                            or abs(record_target - target) > 1e-9
                            or abs(record_delay - target) > 1e-9
                            or record_elapsed is None
                            or record_elapsed < target
                        ):
                            faults.append(
                                f"target timeline[{target_index}] timing "
                                "is not bound to its target"
                            )
                        if (
                            not isinstance(sample_index, int)
                            or isinstance(sample_index, bool)
                            or sample_index < 0
                            or sample_index >= len(samples)
                            or not isinstance(samples[sample_index], dict)
                        ):
                            faults.append(
                                f"target timeline[{target_index}] has no "
                                "valid numeric sample binding"
                            )
                            continue
                        source_sample = samples[sample_index]
                        sample_elapsed = number(
                            source_sample.get("actualElapsedSeconds")
                        )
                        if (
                            source_sample.get("sampleIndex") != sample_index
                            or sample_elapsed is None
                            or record_elapsed is None
                            or abs(sample_elapsed - record_elapsed) > 1e-9
                        ):
                            faults.append(
                                f"target timeline[{target_index}] elapsed "
                                "time disagrees with its sample"
                            )
                        for binding_key in (
                            "capturedAt",
                            "safetyFaults",
                            "snapshot",
                        ):
                            if (
                                target_record.get(binding_key)
                                != source_sample.get(binding_key)
                            ):
                                faults.append(
                                    f"target timeline[{target_index}]."
                                    f"{binding_key} disagrees with its "
                                    "sample"
                                )
                        for optional_binding in ("readback", "gate"):
                            if (
                                optional_binding in target_record
                                and target_record.get(optional_binding)
                                != source_sample.get(optional_binding)
                            ):
                                faults.append(
                                    f"target timeline[{target_index}]."
                                    f"{optional_binding} disagrees with "
                                    "its sample"
                                )
        if "complete" in poll and poll.get("complete") is not True:
            faults.append("continuous poll did not declare complete")
        return {
            "complete": not faults,
            "faults": sorted(set(faults)),
            "sampleCount": len(samples),
            "maximumIntervalSeconds": maximum,
            "maximumObservedGapSeconds": recomputed_gap,
            "targetDelaysSeconds": normalized_target_delays,
        }

    def normalized_window(
        value: dict[str, Any],
        *,
        artifact: str,
        path: str,
    ) -> dict[str, Any] | None:
        kind = value.get("safetyWindowKind")
        boundary = value.get("safetyBoundary")
        missing_kind = not isinstance(kind, str)
        if missing_kind and not route_requires_window(artifact, path):
            return None
        label = (
            value.get("label")
            if isinstance(value.get("label"), str)
            else path.rsplit("/", 1)[-1] or kind
        )
        faults: list[str] = []
        if is_t4_window_route(artifact, path) and "recordKind" in value:
            if (
                value.get("recordKind")
                == PAUSED_NUMERIC_SNAPSHOT_RECORD_KIND
            ):
                faults.extend(
                    f"paused numeric snapshot record: {fault}"
                    for fault in paused_numeric_snapshot_record_faults(
                        value,
                        expected_phase="t4",
                        expected_boundary="ATTRIBUTION_WINDOW",
                    )
                )
            else:
                faults.append(
                    "recordKind is not a runnable window or the closed "
                    "paused numeric snapshot kind"
                )
        if missing_kind:
            faults.append("safetyWindowKind is missing from a runnable route")
        facts: dict[str, Any]
        if kind == "SERVICE_WINDOW":
            poll = value.get("safetyPoll")
            poll = poll if isinstance(poll, dict) else {}
            timeline = value.get("timeline")
            timeline = timeline if isinstance(timeline, list) else []
            enriched_poll = dict(poll)
            enriched_poll["timeline"] = timeline
            facts = poll_facts(enriched_poll)
            for key in (
                "timelineFault",
                "pauseFault",
                "pauseTailFault",
                "gcGuardFault",
                "finalizationFault",
            ):
                if value.get(key) is not None:
                    faults.append(f"{key} is non-null")
            if value.get("pause") is None:
                faults.append("service-window paused ACK is missing")
            tail = number(poll.get("tailGapSeconds"))
            maximum = facts["maximumIntervalSeconds"]
            if tail is None:
                faults.append("service-window tail gap is missing")
            elif maximum is not None and tail > maximum:
                faults.append("service-window tail gap exceeds maximum")
            pause_elapsed = number(
                poll.get("pauseConfirmedElapsedSeconds")
            )
            last_elapsed = number(
                poll.get("lastSampleFinishedElapsedSeconds")
            )
            samples = poll.get("samples")
            samples = samples if isinstance(samples, list) else []
            raw_last_elapsed = (
                number(samples[-1].get("actualElapsedSeconds"))
                if samples and isinstance(samples[-1], dict)
                else None
            )
            if (
                pause_elapsed is None
                or last_elapsed is None
                or tail is None
                or pause_elapsed < last_elapsed
                or raw_last_elapsed is None
                or abs(raw_last_elapsed - last_elapsed) > 1e-9
                or abs((pause_elapsed - last_elapsed) - tail) > 1e-9
            ):
                faults.append(
                    "service-window tail is not bound to the last "
                    "numeric sample and paused ACK"
                )
        elif kind == "MONITORED_WORKER":
            facts = poll_facts(
                {
                    "samples": value.get("samples"),
                    "sampleCount": value.get("sampleCount"),
                    "maximumIntervalSeconds": value.get(
                        "maximumPollIntervalSeconds"
                    ),
                    "maximumObservedGapSeconds": value.get(
                        "maximumObservedPollGapSeconds"
                    ),
                    "pollFaults": [],
                    **(
                        {
                            "maximumObservedReadDurationSeconds": value[
                                "maximumObservedReadDurationSeconds"
                            ]
                        }
                        if "maximumObservedReadDurationSeconds" in value
                        else {}
                    ),
                }
            )
            for key in (
                "monitorFault",
                "immediateStopFault",
                "finalStopFault",
                "executorShutdownFault",
                "cancelFault",
                "gcGuardFault",
                "controlFault",
                "tailGapFault",
                "finalizationFault",
            ):
                if value.get(key) is not None:
                    faults.append(f"{key} is non-null")
            if value.get("pause") is None:
                faults.append("monitored-window paused ACK is missing")
            tail = number(value.get("tailGapSeconds"))
            maximum = facts["maximumIntervalSeconds"]
            if tail is None:
                faults.append("monitored-window tail gap is missing")
            elif maximum is not None and tail > maximum:
                faults.append("monitored-window tail gap exceeds maximum")
            stop_elapsed = number(
                value.get("finalStopConfirmedElapsedSeconds")
            )
            last_elapsed = number(
                value.get("lastSampleFinishedElapsedSeconds")
            )
            samples = value.get("samples")
            samples = samples if isinstance(samples, list) else []
            raw_last_elapsed = (
                number(samples[-1].get("actualElapsedSeconds"))
                if samples and isinstance(samples[-1], dict)
                else None
            )
            if (
                stop_elapsed is None
                or last_elapsed is None
                or tail is None
                or stop_elapsed < last_elapsed
                or raw_last_elapsed is None
                or abs(raw_last_elapsed - last_elapsed) > 1e-9
                or abs((stop_elapsed - last_elapsed) - tail) > 1e-9
            ):
                faults.append(
                    "monitored-window tail is not bound to the last "
                    "numeric sample and paused ACK"
                )
        elif kind in {"GATE_LEASE_APPLY", "GATE_LEASE_RESTORE"}:
            timeline = value.get("timeline")
            timeline = timeline if isinstance(timeline, dict) else {}
            facts = poll_facts(timeline.get("resumedSafetyPoll"))
            for key in (
                "resumeFault",
                "resumeFailureHoldFault",
                "postResumeSamplerFault",
                "samplerFailureHoldFault",
                "safetyHoldFault",
            ):
                if value.get(key) is not None:
                    faults.append(f"{key} is non-null")
            poll = timeline.get("resumedSafetyPoll")
            poll = poll if isinstance(poll, dict) else {}
            closure = poll.get("closure")
            closure = closure if isinstance(closure, dict) else {}
            if (
                closure.get("mode") != "PAUSED_ACK"
                or closure.get("stopConfirmed") is not True
                or value.get("qemuHeldPaused") is not True
            ):
                faults.append("gate runnable-window closure is unconfirmed")
            stop_elapsed = number(
                closure.get("stopConfirmedElapsedSeconds")
            )
            last_sample_elapsed = number(
                closure.get("lastSampleFinishedElapsedSeconds")
            )
            tail_gap = number(closure.get("tailGapSeconds"))
            maximum = facts["maximumIntervalSeconds"]
            if (
                stop_elapsed is None
                or last_sample_elapsed is None
                or tail_gap is None
                or stop_elapsed < last_sample_elapsed
            ):
                faults.append("gate runnable-window tail is incomplete")
            else:
                recomputed_tail = stop_elapsed - last_sample_elapsed
                if abs(tail_gap - recomputed_tail) > 1e-9:
                    faults.append(
                        "gate runnable-window tail differs from raw timing"
                    )
                if maximum is not None and tail_gap > maximum:
                    faults.append(
                        "gate runnable-window tail exceeds maximum"
                    )
                poll_samples = poll.get("samples")
                poll_samples = (
                    poll_samples
                    if isinstance(poll_samples, list)
                    else []
                )
                raw_last_elapsed = (
                    number(
                        poll_samples[-1].get("actualElapsedSeconds")
                    )
                    if (
                        poll_samples
                        and isinstance(poll_samples[-1], dict)
                    )
                    else None
                )
                if (
                    raw_last_elapsed is None
                    or abs(
                        raw_last_elapsed - last_sample_elapsed
                    )
                    > 1e-9
                ):
                    faults.append(
                        "gate closure tail is not bound to the last "
                        "numeric sample"
                    )
            expected_outcome = (
                "EFFECTIVE"
                if kind == "GATE_LEASE_APPLY"
                else "RESTORED"
            )
            if value.get("outcome") != expected_outcome:
                faults.append("gate lease outcome is not clean")
        elif kind == "FINAL_RUNNING_STABILIZATION":
            facts = poll_facts(value.get("safetyPoll"))
            for key in (
                "resumeFault",
                "samplerFault",
                "postSamplerAnalysisFault",
                "failStopFault",
                "finalizationFault",
            ):
                if value.get(key) is not None:
                    faults.append(f"{key} is non-null")
            if value.get("gateFaults"):
                faults.append("restored gate drifted in final tail")
            if value.get("outcome") != "CLEAN_RUNNING":
                faults.append("final running stabilization is not clean")
        elif kind == "CONTINUOUS_TIMELINE":
            facts = poll_facts(value)
        else:
            facts = {
                "complete": False,
                "faults": [f"unknown safetyWindowKind {kind!r}"],
                "sampleCount": 0,
                "maximumIntervalSeconds": None,
                "maximumObservedGapSeconds": None,
            }
        if boundary not in SAFETY_BOUNDARIES:
            faults.append("safety boundary is not a closed enum value")
        all_faults = sorted(set(facts["faults"] + faults))
        return {
            "boundary": boundary,
            "kind": kind,
            "complete": not all_faults,
            "faults": all_faults,
            "sampleCount": facts["sampleCount"],
            "maximumIntervalSeconds": facts[
                "maximumIntervalSeconds"
            ],
            "maximumObservedGapSeconds": facts[
                "maximumObservedGapSeconds"
            ],
            "targetDelaysSeconds": facts.get("targetDelaysSeconds"),
            "provenance": {
                "artifact": artifact,
                "jsonPath": path,
                "label": label,
            },
        }

    def walk(value: Any, *, artifact: str, path: str) -> None:
        if isinstance(value, dict):
            if (
                is_t4_window_route(artifact, path)
                and value.get("recordKind")
                == PAUSED_NUMERIC_SNAPSHOT_RECORD_KIND
                and not paused_numeric_snapshot_record_faults(
                    value,
                    expected_phase="t4",
                    expected_boundary="ATTRIBUTION_WINDOW",
                )
            ):
                # ``capture`` records are paused point observations, not
                # runnable intervals.  Only the exact closed record may leave
                # the heterogeneous t4/windows route without coverage.
                return
            normalized = normalized_window(
                value,
                artifact=artifact,
                path=path,
            )
            if normalized is not None:
                coverage.append(normalized)
                # Wrapper windows bind their nested poll.  Walking that poll a
                # second time would count one runnable interval twice.
                return
            for key in sorted(value):
                if key in SAFETY_DERIVED_KEYS:
                    continue
                walk(
                    value[key],
                    artifact=artifact,
                    path=f"{path}/{key}",
                )
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(
                    item,
                    artifact=artifact,
                    path=f"{path}/{index}",
                )

    # Runnable coverage authority is closed to the phases and exact field
    # routes emitted by this runner.  T2/T3 remain numeric state authority,
    # but never carry runnable-window coverage records.
    for artifact, value in (
        ("t0-baseline.json", t0),
        ("t1-effective-controls.json", t1),
        ("t4-window.json", t4),
        ("t5-transition-or-clear.json", t5),
    ):
        walk(value, artifact=artifact, path="")
    return sorted(
        coverage,
        key=lambda item: (
            str(item.get("provenance", {}).get("artifact")),
            str(item.get("provenance", {}).get("jsonPath")),
        ),
    )


def safety_coverage_shape_faults(
    evaluation_input: dict[str, Any],
) -> list[str]:
    coverage = evaluation_input.get("safetyCoverage")
    if not isinstance(coverage, list):
        return ["safetyCoverage is not a list"]
    if not coverage:
        return ["safetyCoverage is empty"]
    faults: list[str] = []
    seen_provenance: set[tuple[str, str]] = set()

    def number(value: Any) -> float | None:
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and value >= 0
            and math.isfinite(float(value))
        ):
            return float(value)
        return None

    for index, item in enumerate(coverage):
        prefix = f"safetyCoverage[{index}]"
        if not isinstance(item, dict):
            faults.append(f"{prefix} is not an object")
            continue
        if item.get("boundary") not in SAFETY_BOUNDARIES:
            faults.append(f"{prefix}.boundary is invalid")
        if item.get("kind") not in SAFETY_WINDOW_KINDS:
            faults.append(f"{prefix}.kind is not allow-listed")
        if not isinstance(item.get("complete"), bool):
            faults.append(f"{prefix}.complete is not a boolean")
        if not isinstance(item.get("faults"), list):
            faults.append(f"{prefix}.faults is not a list")
        sample_count = item.get("sampleCount")
        if (
            not isinstance(sample_count, int)
            or isinstance(sample_count, bool)
            or sample_count <= 0
        ):
            faults.append(f"{prefix}.sampleCount is invalid")
        maximum_interval = number(item.get("maximumIntervalSeconds"))
        maximum_gap = number(item.get("maximumObservedGapSeconds"))
        if maximum_interval is None or maximum_interval <= 0:
            faults.append(
                f"{prefix}.maximumIntervalSeconds is invalid"
            )
        if maximum_gap is None:
            faults.append(
                f"{prefix}.maximumObservedGapSeconds is invalid"
            )
        elif (
            maximum_interval is not None
            and maximum_interval > 0
            and maximum_gap > maximum_interval
        ):
            faults.append(
                f"{prefix}.maximumObservedGapSeconds exceeds maximum"
            )
        target_delays = item.get("targetDelaysSeconds")
        if target_delays is not None:
            if not isinstance(target_delays, list) or not target_delays:
                faults.append(
                    f"{prefix}.targetDelaysSeconds is invalid"
                )
            else:
                parsed_targets = [number(value) for value in target_delays]
                if (
                    any(value is None for value in parsed_targets)
                    or any(
                        later <= earlier
                        for earlier, later in zip(
                            parsed_targets,
                            parsed_targets[1:],
                        )
                    )
                ):
                    faults.append(
                        f"{prefix}.targetDelaysSeconds is invalid"
                    )
        item_faults = item.get("faults")
        if isinstance(item_faults, list):
            for fault_index, fault in enumerate(item_faults):
                if not isinstance(fault, str) or not fault:
                    faults.append(
                        f"{prefix}.faults[{fault_index}] is not a "
                        "non-empty string"
                    )
        provenance = item.get("provenance")
        if not isinstance(provenance, dict):
            faults.append(f"{prefix}.provenance is not an object")
        else:
            for key in ("artifact", "jsonPath", "label"):
                if not isinstance(provenance.get(key), str):
                    faults.append(
                        f"{prefix}.provenance.{key} is not a string"
                    )
            artifact = provenance.get("artifact")
            expected_boundary = {
                "t0-baseline.json": "PRE_INJECTION",
                "t1-effective-controls.json": "PRE_INJECTION",
                "t4-window.json": "ATTRIBUTION_WINDOW",
                "t5-transition-or-clear.json": "POST_CLEANUP",
            }.get(artifact)
            if expected_boundary is None:
                faults.append(
                    f"{prefix}.provenance.artifact is not allow-listed"
                )
            elif item.get("boundary") != expected_boundary:
                faults.append(
                    f"{prefix}.boundary disagrees with its raw artifact phase"
                )
            json_path = provenance.get("jsonPath")
            kind = item.get("kind")
            if isinstance(artifact, str) and isinstance(json_path, str):
                identity = (artifact, json_path)
                if identity in seen_provenance:
                    faults.append(
                        f"{prefix}.provenance duplicates another window"
                    )
                seen_provenance.add(identity)
                patterns = SAFETY_COVERAGE_PATH_PATTERNS.get(
                    (artifact, kind),
                    (),
                )
                if not any(
                    pattern.fullmatch(json_path)
                    for pattern in patterns
                ):
                    faults.append(
                        f"{prefix}.provenance.jsonPath is not an "
                        "allow-listed raw window route"
                    )
    observed_boundaries = {
        item.get("boundary")
        for item in coverage
        if isinstance(item, dict)
    }
    required_boundaries = (
        SAFETY_BOUNDARIES
        if evaluation_input.get("enteredInjection") is True
        else {"PRE_INJECTION"}
    )
    for boundary in sorted(required_boundaries - observed_boundaries):
        faults.append(f"safetyCoverage lacks {boundary}")
    return sorted(set(faults))


def safety_coverage_profile_faults(
    evaluation_input: dict[str, Any],
    oracle_profile: dict[str, Any],
) -> list[str]:
    """Bind every runnable window to the frozen profile timing envelope."""

    timing = oracle_profile.get("timingEnvelope")
    timing = timing if isinstance(timing, dict) else {}
    raw_maximum = timing.get("maximumSafetyPollIntervalSeconds")
    if (
        not isinstance(raw_maximum, (int, float))
        or isinstance(raw_maximum, bool)
        or not math.isfinite(float(raw_maximum))
        or float(raw_maximum) <= 0
    ):
        return ["oracle profile maximum safety poll interval is invalid"]
    expected_maximum = float(raw_maximum)
    raw_targets = timing.get("timelineDelaysSeconds")
    if not isinstance(raw_targets, list) or not raw_targets:
        return ["oracle profile timeline delays are invalid"]
    expected_targets: list[float] = []
    for value in raw_targets:
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            or float(value) < 0
        ):
            return ["oracle profile timeline delays are invalid"]
        expected_targets.append(float(value))
    if any(
        later <= earlier
        for earlier, later in zip(
            expected_targets,
            expected_targets[1:],
        )
    ):
        return ["oracle profile timeline delays are invalid"]

    coverage = evaluation_input.get("safetyCoverage")
    if not isinstance(coverage, list):
        return []
    scheduled_kinds = {
        "CONTINUOUS_TIMELINE",
        "GATE_LEASE_APPLY",
        "GATE_LEASE_RESTORE",
        "SERVICE_WINDOW",
        "FINAL_RUNNING_STABILIZATION",
    }
    faults: list[str] = []
    for index, item in enumerate(coverage):
        if not isinstance(item, dict):
            continue
        raw_observed_maximum = item.get("maximumIntervalSeconds")
        if (
            not isinstance(raw_observed_maximum, (int, float))
            or isinstance(raw_observed_maximum, bool)
            or not math.isfinite(float(raw_observed_maximum))
            or not math.isclose(
                float(raw_observed_maximum),
                expected_maximum,
                rel_tol=0.0,
                abs_tol=1e-12,
            )
        ):
            faults.append(
                f"safetyCoverage[{index}].maximumIntervalSeconds "
                "differs from the frozen profile"
            )
        if item.get("kind") in scheduled_kinds:
            observed_targets = item.get("targetDelaysSeconds")
            if (
                not isinstance(observed_targets, list)
                or len(observed_targets) != len(expected_targets)
                or any(
                    not isinstance(value, (int, float))
                    or isinstance(value, bool)
                    or not math.isfinite(float(value))
                    for value in observed_targets
                )
                or any(
                    not math.isclose(
                        float(observed),
                        expected,
                        rel_tol=0.0,
                        abs_tol=1e-12,
                    )
                    for observed, expected in zip(
                        observed_targets,
                        expected_targets,
                    )
                )
            ):
                faults.append(
                    f"safetyCoverage[{index}].targetDelaysSeconds "
                    "differs from the frozen profile"
                )
    return sorted(set(faults))


def derive_raw_evidence_protocol(
    *,
    sequence: str,
    qemu_device: str,
    outer_endpoint_bdf: Any,
    outer_root_bdf: Any,
    owner_phase: str,
    t0: dict[str, Any],
    t1: dict[str, Any],
    t2: dict[str, Any],
    t3: dict[str, Any],
    t4: dict[str, Any],
    t5: dict[str, Any],
    cleanup: dict[str, Any],
    baseline_phase: dict[str, Any] | None,
    terminal_phase: dict[str, Any] | None,
    safety_coverage: list[dict[str, Any]],
    bounded_log_window_complete: bool,
) -> dict[str, Any]:
    """Derive T0-T5 completeness without trusting evaluationEvidence."""

    observed_boundaries = {
        item.get("boundary")
        for item in safety_coverage
        if (
            isinstance(item, dict)
            and item.get("complete") is True
            and item.get("sampleCount", 0) > 0
            and not item.get("faults")
        )
    }

    def clean_coverage(
        *,
        artifact: str,
        json_path: str | None = None,
        kind: str | None = None,
    ) -> list[dict[str, Any]]:
        return [
            item
            for item in safety_coverage
            if (
                isinstance(item, dict)
                and item.get("complete") is True
                and isinstance(item.get("sampleCount"), int)
                and not isinstance(item.get("sampleCount"), bool)
                and item.get("sampleCount", 0) > 0
                and not item.get("faults")
                and isinstance(item.get("provenance"), dict)
                and item["provenance"].get("artifact") == artifact
                and (
                    json_path is None
                    or item["provenance"].get("jsonPath") == json_path
                )
                and (kind is None or item.get("kind") == kind)
            )
        ]

    required_service_labels = set(BEHAVIOR_LABELS.get(sequence, ()))
    complete_service_windows = clean_coverage(
        artifact="t4-window.json",
        kind="SERVICE_WINDOW",
    )
    complete_service_labels = {
        item["provenance"].get("label")
        for item in complete_service_windows
    }
    pre_sequence_monitors = clean_coverage(
        artifact="t0-baseline.json",
        kind="MONITORED_WORKER",
    )
    active_start_monitors = clean_coverage(
        artifact="t1-effective-controls.json",
        kind="MONITORED_WORKER",
    )
    active_cleanup_monitors = clean_coverage(
        artifact="t5-transition-or-clear.json",
        kind="MONITORED_WORKER",
    )
    final_running_tails = clean_coverage(
        artifact="t5-transition-or-clear.json",
        json_path="/finalRunningSafetyTail",
        kind="FINAL_RUNNING_STABILIZATION",
    )
    checks = {
        "mutation-boundary-crossed": entered_injection_from_records(
            t3.get("injections"),
            sequence=sequence,
            qemu_device=qemu_device,
            outer_endpoint_bdf=outer_endpoint_bdf,
            outer_root_bdf=outer_root_bdf,
        ),
        "baseline-host-phase": isinstance(baseline_phase, dict),
        "terminal-host-phase": isinstance(terminal_phase, dict),
        "gate-lease-effective": (
            isinstance(t1.get("gateLease"), dict)
            and t1["gateLease"].get("outcome") == "EFFECTIVE"
        ),
        "t2-steps-present": bool(
            isinstance(t2.get("steps"), list) and t2["steps"]
        ),
        "t3-injections-present": bool(
            isinstance(t3.get("injections"), list)
            and t3["injections"]
        ),
        "t3-snapshots-present": bool(
            isinstance(t3.get("snapshots"), list)
            and t3["snapshots"]
        ),
        "t4-windows-present": bool(
            isinstance(t4.get("windows"), list) and t4["windows"]
        ),
        "bounded-log-window-complete": (
            bounded_log_window_complete is True
        ),
        "t5-operations-present": bool(
            isinstance(t5.get("operations"), list)
            and t5["operations"]
        ),
        "gate-restore-complete": (
            isinstance(t5.get("gateRestore"), dict)
            and t5["gateRestore"].get("outcome") == "RESTORED"
        ),
        "cleanup-complete": cleanup.get("complete") is True,
        "coverage-records-present": bool(safety_coverage),
        "coverage-all-complete": bool(safety_coverage)
        and all(
            isinstance(item, dict)
            and item.get("complete") is True
            and item.get("sampleCount", 0) > 0
            and not item.get("faults")
            for item in safety_coverage
        ),
        "coverage-boundaries-complete": (
            observed_boundaries == SAFETY_BOUNDARIES
        ),
        "coverage-gate-lease-apply-complete": bool(
            clean_coverage(
                artifact="t1-effective-controls.json",
                json_path="/gateLease",
                kind="GATE_LEASE_APPLY",
            )
        ),
        "coverage-gate-lease-restore-complete": bool(
            clean_coverage(
                artifact="t5-transition-or-clear.json",
                json_path="/gateRestore",
                kind="GATE_LEASE_RESTORE",
            )
        ),
        "coverage-service-labels-complete": bool(required_service_labels)
        and complete_service_labels == required_service_labels,
        "coverage-service-window-count-exact": (
            bool(required_service_labels)
            and len(complete_service_windows) == len(required_service_labels)
        ),
        "coverage-pre-sequence-monitor-exact": (
            len(pre_sequence_monitors) == 1
        ),
        "coverage-final-running-tail-exact": len(final_running_tails) == 1,
        "coverage-o4-startup-monitor-exact": (
            owner_phase != "O4" or len(active_start_monitors) == 1
        ),
        "coverage-o4-cleanup-monitor-exact": (
            owner_phase != "O4" or len(active_cleanup_monitors) == 1
        ),
        "t0-phase-copy-bound": (
            isinstance(baseline_phase, dict)
            and t0.get("hostPhase") == baseline_phase
        ),
        "t4-phase-copy-bound": (
            isinstance(terminal_phase, dict)
            and t4.get("hostTerminalPhase") == terminal_phase
        ),
    }
    return {
        "complete": all(checks.values()),
        "checks": checks,
    }


def safety_observation_shape_faults(
    evaluation_input: dict[str, Any],
) -> list[str]:
    observations = evaluation_input.get("safetyObservations")
    if observations is None:
        return ["safetyObservations is missing"]
    if not isinstance(observations, list):
        return ["safetyObservations is not a list"]
    if not observations:
        return ["safetyObservations is empty"]
    faults: list[str] = []
    required_numeric = (
        "endpointDeviceStatus",
        "endpointUncorrectableErrorStatus",
        "rootDeviceStatus",
        "rootUncorrectableErrorStatus",
        "rootErrorStatus",
    )
    for index, item in enumerate(observations):
        prefix = f"safetyObservations[{index}]"
        if not isinstance(item, dict):
            faults.append(f"{prefix} is not an object")
            continue
        faults.extend(
            safety_observation_identity_faults(item, index=index)
        )
        for key in required_numeric:
            value = item.get(key)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                or value > 0xFFFFFFFF
            ):
                faults.append(f"{prefix}.{key} is not a non-negative integer")
    return sorted(set(faults))


def evaluate_case_observation(
    evaluation_input: dict[str, Any],
    oracle_profile: dict[str, Any],
    *,
    outer_endpoint_bdf: str,
    outer_root_bdf: str,
) -> dict[str, Any]:
    """Pure four-state evaluator for one raw case."""

    sequence = evaluation_input.get("sequence")
    gate_name = evaluation_input.get("gate")
    owner_phase = evaluation_input.get("ownerPhase")
    entered_injection_claim = evaluation_input.get("enteredInjection")
    preflight = evaluation_input.get("preflight")
    preflight = preflight if isinstance(preflight, dict) else {}
    snapshots = evaluation_input.get("snapshots")
    snapshots = snapshots if isinstance(snapshots, dict) else {}
    raw_injections = evaluation_input.get("injections")
    injection_shape_faults = injection_record_shape_faults(
        raw_injections,
        sequence=sequence,
        qemu_device=evaluation_input.get("qemuDevice"),
        outer_endpoint_bdf=outer_endpoint_bdf,
        outer_root_bdf=outer_root_bdf,
    )
    raw_entered_injection = entered_injection_from_records(
        raw_injections,
        sequence=sequence,
        qemu_device=evaluation_input.get("qemuDevice"),
        outer_endpoint_bdf=outer_endpoint_bdf,
        outer_root_bdf=outer_root_bdf,
    )
    if not isinstance(entered_injection_claim, bool):
        injection_shape_faults.append(
            "enteredInjection is not a boolean"
        )
    if (
        isinstance(entered_injection_claim, bool)
        and raw_entered_injection is not entered_injection_claim
    ):
        injection_shape_faults.append(
            "enteredInjection differs from the verified raw HMP ACK boundary"
        )
    entered_injection = bool(
        entered_injection_claim is True
        or raw_entered_injection
        or injection_shape_faults
    )
    injections = (
        raw_injections if isinstance(raw_injections, list) else []
    )
    owner_observations = evaluation_input.get("ownerObservations")
    owner_observations = (
        owner_observations if isinstance(owner_observations, list) else []
    )
    safety_faults = derive_evaluation_safety_faults(evaluation_input)
    supplied_safety_faults = evaluation_input.get("safetyFaults")
    supplied_safety_faults = (
        supplied_safety_faults
        if isinstance(supplied_safety_faults, list)
        else []
    )
    safety_claim_consistent = bool(supplied_safety_faults) == bool(
        safety_faults
    )
    containment_required = (
        evaluation_input.get("containmentRequired") is True
    )
    containment_reasons = evaluation_input.get("containmentReasons")
    containment_reasons = (
        containment_reasons
        if isinstance(containment_reasons, list)
        else []
    )
    safety_coverage = evaluation_input.get("safetyCoverage")
    safety_coverage = (
        safety_coverage if isinstance(safety_coverage, list) else []
    )
    incomplete_coverage = [
        item
        for item in safety_coverage
        if (
            not isinstance(item, dict)
            or item.get("complete") is not True
            or item.get("sampleCount") == 0
            or bool(item.get("faults"))
        )
    ]
    base = {
        "schemaVersion": SCHEMA_VERSION,
        "modelId": RUNNER_MODEL_ID,
        "oracleProfile": {
            "id": oracle_profile.get("id"),
            "sha256": sha256_bytes(canonical_json(oracle_profile)),
            "profileState": oracle_profile.get("profileState"),
            "comparisonTarget": oracle_profile.get("comparisonTarget"),
        },
        "sequence": sequence,
        "gate": gate_name,
        "ownerPhase": owner_phase,
        "claimBoundary": oracle_profile.get("claimBoundary"),
        # The evaluator always publishes its effective containment conclusion.
        # This begins with the runtime claim and may be strengthened by
        # independently reconstructed safety/coverage evidence below.
        "containmentRequired": containment_required,
        "containmentReasons": copy.deepcopy(containment_reasons),
    }

    required_preflight = {
        "environmentBound",
        "ownerBound",
        "cleanBaseline",
        "gatePausedReadback",
        "evidenceProtocolReady",
    }
    failed_preflight = sorted(
        name for name in required_preflight if preflight.get(name) is not True
    )
    pre_injection_safety = [
        item
        for item in safety_faults
        if isinstance(item, dict)
        and item.get("boundary") == "PRE_INJECTION"
    ]
    if pre_injection_safety and not entered_injection:
        return {
            **base,
            "observationState": OBSERVATION_BLOCKED,
            "verdict": "BLOCKED_UNSAFE_BASELINE",
            "fixtureOracle": None,
            "esxiBlackboxOracle": None,
            "failedPreflight": failed_preflight,
            "safetyStop": True,
            "safetyFaults": safety_faults,
            "containmentRequired": True,
            "containmentReasons": (
                containment_reasons
                + ["numeric PRE_INJECTION safety observation is non-clean"]
            ),
        }
    pre_injection_coverage_faults = [
        item
        for item in incomplete_coverage
        if isinstance(item, dict)
        and item.get("boundary") == "PRE_INJECTION"
    ]
    has_complete_pre_injection_coverage = any(
        isinstance(item, dict)
        and item.get("boundary") == "PRE_INJECTION"
        and item.get("complete") is True
        and isinstance(item.get("sampleCount"), int)
        and item.get("sampleCount", 0) > 0
        and not item.get("faults")
        for item in safety_coverage
    )
    if (
        (
            pre_injection_coverage_faults
            or not has_complete_pre_injection_coverage
        )
        and not entered_injection
    ):
        return {
            **base,
            "observationState": OBSERVATION_BLOCKED,
            "verdict": "BLOCKED_SAFETY_COVERAGE",
            "fixtureOracle": None,
            "esxiBlackboxOracle": None,
            "failedPreflight": failed_preflight,
            "safetyStop": bool(safety_faults),
            "safetyFaults": safety_faults,
            "safetyCoverage": safety_coverage,
            "containmentRequired": True,
            "containmentReasons": (
                containment_reasons
                + ["PRE_INJECTION runnable safety coverage is incomplete"]
            ),
        }
    if failed_preflight and not entered_injection:
        return {
            **base,
            "observationState": OBSERVATION_BLOCKED,
            "verdict": (
                "BLOCKED_UNSAFE_BASELINE"
                if safety_faults or containment_required
                else "BLOCKED"
            ),
            "fixtureOracle": None,
            "esxiBlackboxOracle": None,
            "failedPreflight": failed_preflight,
            "safetyStop": bool(safety_faults),
            "safetyFaults": safety_faults,
            "containmentRequired": containment_required,
            "containmentReasons": containment_reasons,
        }

    if (
        sequence not in SEQUENCES
        or gate_name not in SUPPORTED_GATES
        or owner_phase not in OWNER_PHASES
    ):
        return {
            **base,
            "observationState": OBSERVATION_INCONCLUSIVE,
            "verdict": "INCONCLUSIVE",
            "fixtureOracle": None,
            "esxiBlackboxOracle": None,
            "fault": (
                "unknown sequence, gate or owner phase in evaluation input"
            ),
            "safetyStop": bool(safety_faults),
        }

    requester_id = evaluation_input.get("requesterId")
    qemu_device = evaluation_input.get("qemuDevice")
    shape_faults = public_snapshot_shape_faults(snapshots)
    shape_faults.extend(safety_observation_shape_faults(evaluation_input))
    shape_faults.extend(safety_coverage_shape_faults(evaluation_input))
    shape_faults.extend(
        safety_coverage_profile_faults(
            evaluation_input,
            oracle_profile,
        )
    )
    shape_faults.extend(injection_shape_faults)
    shape_faults.extend(
        f"ownerObservations[{index}] is not an object"
        for index, item in enumerate(owner_observations)
        if not isinstance(item, dict)
    )
    if not isinstance(evaluation_input.get("gateStable"), bool):
        shape_faults.append("gateStable is not a boolean")
    if (
        not isinstance(requester_id, int)
        or isinstance(requester_id, bool)
        or not 0 <= requester_id <= 0xFFFF
    ):
        shape_faults.append("requesterId is not a 16-bit integer")
    if (
        not isinstance(qemu_device, str)
        or QEMU_DEVICE_ID_RE.fullmatch(qemu_device) is None
    ):
        shape_faults.append("qemuDevice is not a closed safe device ID")
    if shape_faults:
        attribution_safety = any(
            isinstance(item, dict)
            and item.get("boundary") == "ATTRIBUTION_WINDOW"
            for item in safety_faults
        )
        return {
            **base,
            "observationState": (
                OBSERVATION_DIVERGED
                if attribution_safety
                else OBSERVATION_INCONCLUSIVE
            ),
            "verdict": (
                "FAIL_SAFETY"
                if attribution_safety
                else "INCONCLUSIVE"
            ),
            "fixtureOracle": None,
            "esxiBlackboxOracle": None,
            "evidenceShapeFaults": shape_faults,
            "fault": "raw evidence is structurally incomplete or malformed",
            "safetyStop": bool(safety_faults),
            "safetyFaults": safety_faults,
            "safetyCoverage": safety_coverage,
            "containmentRequired": True,
            "containmentReasons": (
                containment_reasons
                + ["numeric safety evidence coverage is malformed"]
            ),
        }

    qualified, source_qualification = source_qualified_snapshots(snapshots)
    try:
        fixture_oracle = evaluate_fixture_observation(
            sequence=sequence,
            gate_name=gate_name,
            requester_id=requester_id,
            qemu_device=qemu_device,
            snapshots=qualified,
            injections=injections,
        )
    except (KeyError, TypeError, ValueError) as error:
        return {
            **base,
            "observationState": OBSERVATION_INCONCLUSIVE,
            "verdict": "INCONCLUSIVE",
            "fixtureOracle": None,
            "esxiBlackboxOracle": None,
            "fault": (
                "strict public-model fixture oracle rejected raw "
                f"evidence: {type(error).__name__}: {error}"
            ),
                "safetyStop": bool(safety_faults),
            "safetyFaults": safety_faults,
        }
    behavior_oracle = evaluate_profile_behavior(
        profile=oracle_profile,
        owner_phase=owner_phase,
        sequence=sequence,
        requester_id=requester_id,
        snapshots=qualified,
    )
    injection_failures = [
        item.get("label")
        for item in injections
        if item.get("accepted") is not True
    ]
    missing_injections = fixture_oracle.get("missingInjections", [])
    evidence_complete = evaluation_input.get("evidenceComplete") is True
    owner_checks = expected_owner_checks(owner_phase, owner_observations)
    projection_checks, projection_observation = host_projection_checks(
        evaluation_input.get("hostProjection")
    )
    o4_guest_valid = (
        owner_phase != "O4"
        or evaluation_input.get("o4GuestEvidenceValid") is True
    )

    inconclusive_reasons: list[str] = []
    if failed_preflight:
        inconclusive_reasons.append(
            "preflight became invalid after the mutation boundary: "
            + ",".join(failed_preflight)
        )
    if injection_failures or missing_injections:
        inconclusive_reasons.append(
            "one or more planned Correctable injections lack a valid ACK"
        )
    if not evidence_complete:
        inconclusive_reasons.append("T0-T5 evidence protocol is incomplete")
    if not owner_observations or not all(owner_checks.values()):
        inconclusive_reasons.append(
            "owner/active-user/heartbeat evidence is incomplete or unstable"
        )
    if not projection_observation.get("complete"):
        inconclusive_reasons.append("ESXi/outer raw projection bracket is incomplete")
    if not o4_guest_valid:
        inconclusive_reasons.append(
            "O4 lacks a bound guest driver and heartbeat evidence"
        )
    if fixture_oracle["observationState"] != qemu_sequence.OBSERVATION_MATCH:
        inconclusive_reasons.append(
            "paused immediate fixture stimulus did not match the public "
            "QEMU control; this is not a VMware divergence"
        )
    if evaluation_input.get("gateStable") is not True:
        inconclusive_reasons.append(
            "the requested gate/root-path tuple did not remain effective "
            "after T1; the requested-value oracle is not attributable"
        )
    if behavior_oracle["missingLabels"]:
        inconclusive_reasons.append(
            "required post-resume VMware behavior labels are missing: "
            + ",".join(behavior_oracle["missingLabels"])
        )
    if not safety_claim_consistent:
        inconclusive_reasons.append(
            "runtime safetyFaults claim disagrees with numeric raw safety "
            "observations"
        )
    if incomplete_coverage:
        inconclusive_reasons.append(
            "one or more runnable safety windows have incomplete polling or "
            "fail-stop coverage"
        )

    all_checks = {
        **behavior_oracle.get("checks", {}),
        **owner_checks,
        **projection_checks,
    }
    failed_checks = sorted(
        name for name, value in all_checks.items() if value is not True
    )
    sequence_safety_faults = [
        item
        for item in safety_faults
        if isinstance(item, dict)
        and item.get("boundary") == "ATTRIBUTION_WINDOW"
    ]
    non_attribution_safety_faults = [
        item
        for item in safety_faults
        if not (
            isinstance(item, dict)
            and item.get("boundary") == "ATTRIBUTION_WINDOW"
        )
    ]
    safety_stop = bool(safety_faults)
    effective_containment_required = bool(
        containment_required
        or non_attribution_safety_faults
        or not safety_claim_consistent
        or incomplete_coverage
    )

    if sequence_safety_faults:
        state = OBSERVATION_DIVERGED
        verdict = "FAIL_SAFETY"
    elif effective_containment_required or safety_faults:
        state = OBSERVATION_INCONCLUSIVE
        verdict = "INCONCLUSIVE_CONTAINMENT_REQUIRED"
    elif inconclusive_reasons:
        state = OBSERVATION_INCONCLUSIVE
        verdict = "INCONCLUSIVE"
    elif failed_checks:
        state = OBSERVATION_DIVERGED
        verdict = "DIVERGED"
    else:
        state = OBSERVATION_MATCH
        verdict = "MATCH"

    normalized_comparison = {
        "sequence": sequence,
        "gate": gate_name,
        "ownerPhase": owner_phase,
        "oracleProfileId": oracle_profile["id"],
        "behaviorStates": behavior_oracle["observedStates"],
        "hostProjection": (
            {"state": "MATCHED_ONE_MONITORED_SNAPSHOT"}
            if (
                projection_observation.get("complete")
                and projection_checks
                and all(projection_checks.values())
            )
            else (
                {
                    "state": "DIVERGED_FROM_BRACKET",
                    "hostTuple": projection_observation.get("hostTuple"),
                    "outerCandidateTuples": projection_observation.get(
                        "outerCandidateTuples"
                    ),
                }
                if projection_observation.get("complete")
                else {"state": "INCOMPLETE"}
            )
        ),
        "failedChecks": failed_checks,
        "safetyFaults": [
            {
                "label": item.get("label"),
                "boundary": item.get("boundary"),
                "faults": sorted(str(value) for value in item.get("faults", [])),
            }
            for item in safety_faults
            if isinstance(item, dict)
        ],
    }
    raw_observation = {
        **normalized_comparison,
        "fixtureState": fixture_oracle["observationState"],
        "sourceQualification": source_qualification,
        "hostProjection": projection_observation,
        "hostLogClassification": evaluation_input.get(
            "hostLogClassification"
        ),
        "guestClassification": evaluation_input.get("guestClassification"),
        "containmentRequired": effective_containment_required,
        "containmentReasons": containment_reasons,
    }
    return {
        **base,
        "observationState": state,
        "verdict": verdict,
        "fixtureOracle": {
            **fixture_oracle,
            "scope": (
                "Frozen/paused outer-QEMU stimulus validity only; a failure "
                "here is not a VMware divergence."
            ),
        },
        "esxiBlackboxOracle": {
            "hypothesis": oracle_profile["sequencePolicy"],
            "profileBehavior": behavior_oracle,
            "checks": all_checks,
            "failedChecks": failed_checks,
            "inconclusiveReasons": inconclusive_reasons,
            "hostProjection": projection_observation,
            "hostLogPolicy": oracle_profile["hostLogPolicy"],
            "guestPolicy": oracle_profile["guestPolicy"],
        },
        "sourceQualification": source_qualification,
        "safetyStop": safety_stop,
        "safetyFaults": safety_faults,
        "safetyCoverage": safety_coverage,
        "containmentRequired": effective_containment_required,
        "containmentReasons": containment_reasons,
        "observationDigest": sha256_bytes(
            canonical_json(normalized_comparison)
        ),
        "rawObservationDigest": sha256_bytes(
            canonical_json(raw_observation)
        ),
    }


def aggregate_sequence_repeats(
    cases: list[dict[str, Any]],
    minimum_repeats: int,
) -> dict[str, Any]:
    if not cases:
        return {
            "observationState": OBSERVATION_BLOCKED,
            "reason": "no cases",
        }
    states = [item["observationState"] for item in cases]
    digests = [item.get("observationDigest") for item in cases]
    if len(cases) < minimum_repeats:
        state = OBSERVATION_INCONCLUSIVE
        reason = (
            f"{len(cases)} repeats are below the profile minimum "
            f"{minimum_repeats}"
        )
    elif all(item == OBSERVATION_MATCH for item in states):
        state = OBSERVATION_MATCH
        reason = "all required repeats matched"
    elif all(item == OBSERVATION_DIVERGED for item in states):
        if len(set(digests)) == 1 and None not in digests:
            state = OBSERVATION_DIVERGED
            reason = "all required repeats produced the same normalized divergence"
        else:
            state = OBSERVATION_INCONCLUSIVE
            reason = "divergent repeats were not normalized-identical"
    elif all(item == OBSERVATION_BLOCKED for item in states):
        state = OBSERVATION_BLOCKED
        reason = "all repeats were blocked before injection"
    else:
        state = OBSERVATION_INCONCLUSIVE
        reason = "repeat states were mixed"
    return {
        "observationState": state,
        "reason": reason,
        "repeatCount": len(cases),
        "stateCounts": {
            value: states.count(value)
            for value in sorted(OBSERVATION_STATES)
        },
        "observationDigests": digests,
    }


def aggregate_campaign(
    case_results: list[dict[str, Any]],
    *,
    owner_phase: str,
    sequences: list[str],
    minimum_repeats: int,
) -> dict[str, Any]:
    groups: dict[str, Any] = {}
    for sequence in sequences:
        selected = [
            item
            for item in case_results
            if item.get("sequence") == sequence
            and item.get("ownerPhase") == owner_phase
        ]
        groups[sequence] = aggregate_sequence_repeats(
            selected,
            minimum_repeats,
        )
    group_states = [
        groups[sequence]["observationState"] for sequence in sequences
    ]
    if group_states and all(
        state == OBSERVATION_MATCH for state in group_states
    ):
        campaign_state = OBSERVATION_MATCH
    elif group_states and all(
        state == OBSERVATION_BLOCKED for state in group_states
    ):
        campaign_state = OBSERVATION_BLOCKED
    elif any(state == OBSERVATION_INCONCLUSIVE for state in group_states):
        campaign_state = OBSERVATION_INCONCLUSIVE
    elif any(state == OBSERVATION_BLOCKED for state in group_states):
        campaign_state = OBSERVATION_INCONCLUSIVE
    else:
        campaign_state = OBSERVATION_DIVERGED
    return {
        "ownerPhase": owner_phase,
        "observationState": campaign_state,
        "groups": groups,
        "plannedSequences": sequences,
        "minimumRepeats": minimum_repeats,
        "safetyStop": any(
            item.get("safetyStop") is True for item in case_results
        ),
    }


def parse_guest_owner_evidence(
    text: str,
    *,
    expected_vendor_id: int | None = None,
    expected_device_id: int | None = None,
) -> dict[str, Any]:
    owner_records: list[dict[str, Any]] = []
    for match in re.finditer(
        r"^AER-OWNER phase=(\S+) bdf=(\S+) vendor=(\S+) "
        r"device=(\S+) driver=(\S+)$",
        text,
        re.MULTILINE,
    ):
        try:
            vendor_id = int(match.group(3), 16)
            device_id = int(match.group(4), 16)
        except ValueError:
            vendor_id = None
            device_id = None
        owner_records.append(
            {
                "phase": match.group(1),
                "bdf": match.group(2),
                "vendor": match.group(3),
                "device": match.group(4),
                "driver": match.group(5),
                "vendorId": vendor_id,
                "deviceId": device_id,
                "textOffset": match.start(),
            }
        )
    heartbeats: list[dict[str, Any]] = []
    for match in re.finditer(
        r"^AER-HEARTBEAT index=(\d+) uptime=(\S+) remaining=(\d+)$",
        text,
        re.MULTILINE,
    ):
        try:
            uptime = float(match.group(2))
        except ValueError:
            uptime = None
        if uptime is not None and (
            not math.isfinite(uptime) or uptime < 0
        ):
            uptime = None
        heartbeats.append(
            {
            "index": int(match.group(1)),
            "uptime": match.group(2),
            "uptimeSeconds": uptime,
            "remaining": int(match.group(3)),
            "textOffset": match.start(),
            }
        )
    target_records = [
        item
        for item in owner_records
        if item["phase"] == "before-injection"
        and expected_vendor_id is not None
        and expected_device_id is not None
        and item["vendorId"] == expected_vendor_id
        and item["deviceId"] == expected_device_id
    ]
    identity_bound = bool(
        expected_vendor_id is not None
        and expected_device_id is not None
        and len(target_records) == 1
    )
    before_bound = bool(
        identity_bound
        and target_records[0]["driver"]
        not in {"unbound", "unavailable", "(null)", "none"}
    )
    heartbeat_contiguous = bool(
        heartbeats
        and heartbeats[0]["index"] == 0
        and all(
            later["index"] == earlier["index"] + 1
            for earlier, later in zip(heartbeats, heartbeats[1:])
        )
    )
    heartbeat_uptime_monotonic = bool(
        heartbeats
        and all(item["uptimeSeconds"] is not None for item in heartbeats)
        and all(
            later["uptimeSeconds"] > earlier["uptimeSeconds"]
            for earlier, later in zip(heartbeats, heartbeats[1:])
        )
    )
    heartbeat_remaining_decreases = bool(
        heartbeats
        and all(
            later["remaining"] < earlier["remaining"]
            for earlier, later in zip(heartbeats, heartbeats[1:])
        )
    )
    owner_precedes_heartbeat = bool(
        identity_bound
        and heartbeats
        and target_records[0]["textOffset"] < heartbeats[0]["textOffset"]
    )
    valid_heartbeat = bool(
        len(heartbeats) >= 2
        and heartbeat_contiguous
        and heartbeat_uptime_monotonic
        and heartbeat_remaining_decreases
        and owner_precedes_heartbeat
    )
    return {
        "expectedIdentity": {
            "vendorId": expected_vendor_id,
            "deviceId": expected_device_id,
        }
        ,
        "ownerRecords": owner_records,
        "matchedBeforeOwnerRecords": target_records,
        "heartbeats": heartbeats,
        "identityBound": identity_bound,
        "beforeDriverBound": before_bound,
        "heartbeatContiguous": heartbeat_contiguous,
        "heartbeatUptimeMonotonic": heartbeat_uptime_monotonic,
        "heartbeatRemainingDecreases": heartbeat_remaining_decreases,
        "ownerPrecedesHeartbeat": owner_precedes_heartbeat,
        "heartbeatMonotonic": valid_heartbeat,
        "validO4Evidence": (
            before_bound
            and valid_heartbeat
        ),
    }


def reject_symlinks_under(root: Path) -> None:
    """Reject aliases and dangling links from every evidence closure."""

    if root.is_symlink():
        raise ManifestError(f"artifact root is a symbolic link: {root}")
    links = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_symlink()
    )
    if links:
        raise ManifestError(f"symbolic links are forbidden in artifacts: {links}")


def path_exists_or_is_symlink(path: Path) -> bool:
    """``Path.exists`` is false for dangling links; evidence must not be."""

    return path.exists() or path.is_symlink()


def write_artifact_manifest(case_dir: Path) -> str:
    reject_symlinks_under(case_dir)
    manifest = case_dir / "artifact-manifest.sha256"
    files = sorted(
        path
        for path in case_dir.rglob("*")
        if path.is_file() and path != manifest
    )
    lines = [
        f"{sha256_file(path)}  {path.relative_to(case_dir).as_posix()}"
        for path in files
    ]
    save_text(manifest, "\n".join(lines) + "\n")
    return sha256_file(manifest)


def verify_artifact_manifest(case_dir: Path) -> dict[str, Any]:
    reject_symlinks_under(case_dir)
    manifest = case_dir / "artifact-manifest.sha256"
    if not manifest.is_file() or manifest.is_symlink():
        raise ManifestError(f"missing manifest: {manifest}")
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(
        manifest.read_text(encoding="ascii").splitlines(),
        start=1,
    ):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        if not match:
            raise ManifestError(
                f"invalid manifest line {line_number}: {line!r}"
            )
        expected, relative = match.groups()
        relative_path = Path(relative)
        canonical_relative = relative_path.as_posix()
        if (
            canonical_relative in seen
            or relative != canonical_relative
            or relative_path.is_absolute()
            or ".." in relative_path.parts
            or "." in relative_path.parts
            or any(":" in part for part in relative_path.parts)
        ):
            raise ManifestError(
                f"unsafe or duplicate manifest path: {relative!r}"
            )
        seen.add(canonical_relative)
        lexical_target = case_dir / relative_path
        if lexical_target.is_symlink():
            raise ManifestError(f"manifest target is a symbolic link: {relative}")
        target = lexical_target.resolve()
        try:
            target.relative_to(case_dir.resolve())
        except ValueError as error:
            raise ManifestError(
                f"manifest path escapes case directory: {relative!r}"
            ) from error
        if not target.is_file():
            raise ManifestError(f"manifest target is missing: {relative}")
        actual = sha256_file(target)
        entries.append(
            {
                "path": relative,
                "expected": expected,
                "actual": actual,
                "match": actual == expected,
            }
        )
    failures = [item for item in entries if not item["match"]]
    present = {
        path.relative_to(case_dir).as_posix()
        for path in case_dir.rglob("*")
        if path.is_file() and path != manifest
    }
    unbound = sorted(present - seen)
    missing_required = sorted(
        name for name in REQUIRED_CASE_ARTIFACTS if not (case_dir / name).is_file()
    )
    if failures or unbound or missing_required:
        raise ManifestError(
            "manifest verification failed: "
            f"hashFailures={[item['path'] for item in failures]}, "
            f"unbound={unbound}, missingRequired={missing_required}"
        )
    return {
        "manifest": str(manifest),
        "manifestSha256": sha256_file(manifest),
        "entryCount": len(entries),
        "verified": len(entries),
        "failures": [],
        "unbound": [],
        "missingRequired": [],
    }


def capture_log_cursors(ssh: EsxiSsh) -> dict[str, Any]:
    cursors: dict[str, Any] = {}
    for name, remote_path in LOG_PATHS.items():
        command = f"stat -c '%i %s' {shlex.quote(remote_path)}"
        result = ssh.run(command, check=False, timeout=30)
        match = re.search(r"^(\d+)\s+(\d+)\s*$", result.stdout)
        cursors[name] = {
            "path": remote_path,
            "command": command,
            "returnCode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "inode": int(match.group(1)) if match else None,
            "offsetBytes": int(match.group(2)) if match else None,
            "capturedAt": utc_now(),
            "parseable": result.returncode == 0 and match is not None,
        }
    return cursors


def write_log_marker(ssh: EsxiSsh, marker: str) -> dict[str, Any]:
    esxi_aer.validate_safe_id(marker, "log marker")
    command = f"logger -t PCI-AER-ROOT-SEQ {shlex.quote(marker)}"
    result = ssh.run(command, check=False, timeout=30)
    return {
        "marker": marker,
        "command": command,
        "returnCode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "observedAt": utc_now(),
    }


def write_official_log_marker_v2(
    ssh: EsxiSsh,
    marker: str,
) -> dict[str, Any]:
    """Write one V2 bracket through ESXi's public syslog marker surface."""

    command = log_v2.marker_command(marker)
    result = ssh.run(command, check=False, timeout=30)
    return {
        "protocol": log_v2.PROTOCOL_ID,
        "marker": marker,
        "command": command,
        "returnCode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "observedAt": utc_now(),
    }


def wait_for_log_marker(
    ssh: EsxiSsh,
    marker: str,
    cancel: threading.Event,
    *,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    esxi_aer.validate_safe_id(marker, "log marker")
    # Do not put the marker in the remote probe command: ESXi records SSH
    # "running command" audit lines in syslog, which would self-match.
    command = f"tail -n 400 {shlex.quote(LOG_PATHS['syslog'])}"
    deadline = time.monotonic() + timeout_seconds
    attempts: list[dict[str, Any]] = []
    while not cancel.is_set() and time.monotonic() < deadline:
        result = ssh.run(command, check=False, timeout=30)
        attempts.append(
            {
                "returnCode": result.returncode,
                "observedAt": utc_now(),
            }
        )
        visible_lines = [
            line
            for line in result.stdout.splitlines()
            if (
                marker in line
                and "PCI-AER-ROOT-SEQ" in line
                and "sshd-session" not in line
                and "running command" not in line
            )
        ]
        if result.returncode == 0 and visible_lines:
            return {
                "marker": marker,
                "command": command,
                "visible": True,
                "matchedLines": visible_lines,
                "attempts": attempts,
            }
        cancel.wait(0.1)
    return {
        "marker": marker,
        "command": command,
        "visible": False,
        "cancelled": cancel.is_set(),
        "attempts": attempts,
    }


def collect_log_window(
    ssh: EsxiSsh,
    case_dir: Path,
    cursors: dict[str, Any],
    *,
    before_marker: str,
    after_marker: str,
) -> dict[str, Any]:
    window: dict[str, Any] = {
        "startedAt": utc_now(),
        "files": {},
        "complete": True,
    }
    all_lines: list[str] = []
    all_text: list[str] = []
    raw_dir = case_dir / "raw-esxi" / "log-window"
    raw_dir.mkdir(parents=True, exist_ok=True)
    for name, cursor in cursors.items():
        remote_path = cursor["path"]
        end_stat_command = (
            f"stat -c '%i %s' {shlex.quote(remote_path)}"
        )
        state = ssh.run(
            end_stat_command,
            check=False,
            timeout=30,
        )
        match = re.search(r"^(\d+)\s+(\d+)\s*$", state.stdout)
        end_inode = int(match.group(1)) if match else None
        end_size = int(match.group(2)) if match else None
        start_inode = cursor.get("inode")
        start_offset = cursor.get("offsetBytes")
        stable = (
            cursor.get("parseable") is True
            and state.returncode == 0
            and match is not None
            and end_inode == start_inode
            and isinstance(start_offset, int)
            and isinstance(end_size, int)
            and end_size >= start_offset
        )
        output_path = raw_dir / f"{name}.log"
        if stable:
            byte_count = end_size - start_offset
            command = (
                f"dd if={shlex.quote(remote_path)} bs=1 "
                f"skip={start_offset} count={byte_count} 2>/dev/null"
            )
            capture = esxi_aer.run_remote_capture(
                ssh,
                command,
                output_path,
                timeout=180,
            )
            text = output_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
            exact_capture = bool(
                capture.get("returnCode") == 0
                and output_path.stat().st_size == byte_count
            )
            if not exact_capture:
                window["complete"] = False
            all_text.append(text)
            all_lines.extend(text.splitlines())
        else:
            byte_count = None
            exact_capture = False
            capture = None
            save_text(
                output_path,
                (
                    "LOG WINDOW INCOMPLETE: inode changed, file shrank, "
                    "or stat/cursor was unavailable.\n"
                ),
            )
            window["complete"] = False
        window["files"][name] = {
            "path": remote_path,
            "startInode": start_inode,
            "endInode": end_inode,
            "startOffsetBytes": start_offset,
            "endSizeBytes": end_size,
            "boundedByteCount": byte_count,
            "stableAppendWindow": stable,
            "exactByteCapture": exact_capture,
            "capture": capture,
            "endStat": {
                "command": end_stat_command,
                "returnCode": state.returncode,
                "stdout": state.stdout,
                "stderr": state.stderr,
            },
            "artifact": str(output_path.relative_to(case_dir)).replace(
                "\\", "/"
            ),
        }
    combined_text = "\n".join(all_text)
    combined_lines = combined_text.splitlines()
    before_marker_lines = [
        line
        for line in combined_lines
        if (
            before_marker in line
            and "PCI-AER-ROOT-SEQ" in line
            and "sshd-session" not in line
            and "running command" not in line
        )
    ]
    after_marker_lines = [
        line
        for line in combined_lines
        if (
            after_marker in line
            and "PCI-AER-ROOT-SEQ" in line
            and "sshd-session" not in line
            and "running command" not in line
        )
    ]
    window["markers"] = {
        "before": {
            "value": before_marker,
            "present": bool(before_marker_lines),
            "matchedLines": before_marker_lines,
        },
        "after": {
            "value": after_marker,
            "present": bool(after_marker_lines),
            "matchedLines": after_marker_lines,
        },
    }
    if not all(item["present"] for item in window["markers"].values()):
        window["complete"] = False
    marker_lines = [
        line
        for line in all_lines
        if (
            "PCI-AER-ROOT-SEQ" in line
            or before_marker in line
            or after_marker in line
        )
    ]
    semantic_input = [line for line in all_lines if line not in marker_lines]
    semantic_lines = esxi_aer.aer_log_lines(semantic_input)
    window["excludedRunnerMarkerLines"] = marker_lines
    window["semanticAerLines"] = semantic_lines
    window["classification"] = (
        "MATCHING_EVENT_OBSERVED"
        if semantic_lines
        else (
            "NOT_OBSERVED_IN_MARKER_AND_BYTE_CURSOR_WINDOW"
            if window["complete"]
            else "INCONCLUSIVE_LOG_WINDOW"
        )
    )
    window["notEquivalentTo"] = (
        "proof that ESXi did not service an interrupt or error"
    )
    window["finishedAt"] = utc_now()
    return window


def _v2_inventory_record_exact(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    try:
        rebuilt = log_v2.parse_inventory(
            value.get("stdout"),
            command=value.get("command"),
            return_code=value.get("returnCode"),
            stderr=value.get("stderr"),
        )
    except Exception:
        return False
    return rebuilt == value and rebuilt.get("complete") is True


def _v2_marker_write_record_exact(
    value: Any,
    marker: str,
) -> bool:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "protocol",
            "marker",
            "command",
            "returnCode",
            "stdout",
            "stderr",
            "observedAt",
        }
    ):
        return False
    try:
        command = log_v2.marker_command(marker)
    except ValueError:
        return False
    return bool(
        value.get("protocol") == log_v2.PROTOCOL_ID
        and value.get("marker") == marker
        and value.get("command") == command
        and value.get("returnCode") == 0
        and isinstance(value.get("stdout"), str)
        and value.get("stderr") == ""
        and isinstance(value.get("observedAt"), str)
        and value.get("observedAt")
    )


def _v2_marker_source_records_exact(
    value: Any,
    marker: str,
) -> bool:
    if not isinstance(value, dict) or set(value) != set(log_v2.LOG_PATHS):
        return False
    for source in log_v2.LOG_PATHS:
        record = value.get(source)
        if (
            not isinstance(record, dict)
            or set(record)
            != {
                "command",
                "returnCode",
                "stdout",
                "stderr",
                "authenticCount",
                "matchedLines",
            }
        ):
            return False
        lines = record.get("matchedLines")
        if not isinstance(lines, list) or not all(
            isinstance(line, str) for line in lines
        ):
            return False
        if (
            record.get("command") != log_v2.marker_probe_command(source)
            or record.get("returnCode") != 0
            or not isinstance(record.get("stdout"), str)
            or record.get("stderr") != ""
            or record.get("authenticCount") != len(lines)
            or log_v2.authentic_marker_lines(
                record["stdout"],
                marker,
            )
            != lines
        ):
            return False
    return True


def _v2_marker_visibility_record_exact(
    value: Any,
    marker: str,
) -> bool:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "protocol",
            "marker",
            "visible",
            "ambiguous",
            "sources",
            "attempts",
        }
    ):
        return False
    attempts = value.get("attempts")
    if not isinstance(attempts, list) or not attempts:
        return False
    for attempt in attempts:
        if (
            not isinstance(attempt, dict)
            or set(attempt) != {"sources"}
            or not _v2_marker_source_records_exact(
                attempt.get("sources"),
                marker,
            )
        ):
            return False
    sources = value.get("sources")
    if (
        sources != attempts[-1]["sources"]
        or not _v2_marker_source_records_exact(sources, marker)
    ):
        return False
    successful = all(
        record.get("returnCode") == 0
        and record.get("stderr") == ""
        and record.get("authenticCount") == 1
        for record in sources.values()
    )
    return bool(
        value.get("protocol") == log_v2.PROTOCOL_ID
        and value.get("marker") == marker
        and value.get("visible") is True
        and value.get("ambiguous") is False
        and successful
    )


def _v2_capture_summary_shape_exact(
    value: Any,
    protocol: dict[str, Any],
) -> bool:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "protocol",
            "attemptCount",
            "selectedAttempt",
            "attempts",
            "complete",
        }
        or value.get("protocol") != protocol
        or value.get("complete") is not True
    ):
        return False
    attempts = value.get("attempts")
    if not isinstance(attempts, list):
        return False
    return all(
        isinstance(item, dict)
        and set(item)
        == {
            "attempt",
            "complete",
            "faults",
            "controlArtifact",
            "controlSha256",
        }
        for item in attempts
    )


def open_v2_log_window(
    *,
    ssh: EsxiSsh,
    campaign_id: str,
    case_id: str,
    protocol: dict[str, Any],
    cancel: threading.Event,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    """Validate layout and publish the official V2 BEFORE bracket."""

    protocol = log_v2.validate_protocol(
        protocol,
        campaign_id=campaign_id,
        case_id=case_id,
    )
    inventory = log_v2.capture_inventory(ssh)
    evidence["logWindowPreflightInventory"] = inventory
    if inventory.get("complete") is not True:
        raise esxi_aer.BlockedEnvironment(
            "the retained ESXi log rotation-chain layout preflight "
            "is incomplete"
        )
    if cancel.is_set():
        return {"cancelledBySafetyMonitor": True}
    marker_write = write_official_log_marker_v2(
        ssh,
        protocol["before"],
    )
    evidence["beforeMarker"] = marker_write
    if marker_write["returnCode"] != 0 or marker_write["stderr"]:
        raise esxi_aer.BlockedEnvironment(
            "the official BEFORE log marker command failed"
        )
    marker_visibility = log_v2.wait_for_marker(
        ssh,
        protocol["before"],
        cancel,
        monotonic=time.monotonic,
    )
    evidence["beforeMarkerVisibility"] = marker_visibility
    if not _v2_marker_visibility_record_exact(
        marker_visibility,
        protocol["before"],
    ):
        raise esxi_aer.BlockedEnvironment(
            "the official BEFORE log marker was not uniquely visible "
            "in every required ESXi log source"
        )
    if cancel.is_set():
        return {"cancelledBySafetyMonitor": True}
    return {
        "logWindowPreflightInventory": inventory,
        "beforeMarker": marker_write,
        "beforeMarkerVisibility": marker_visibility,
    }


def close_v2_log_window(
    *,
    ssh: EsxiSsh,
    transfer: esxi_aer.EsxiScp,
    case_dir: Path,
    campaign_id: str,
    case_id: str,
    protocol: dict[str, Any],
    cancel: threading.Event,
    evidence: dict[str, Any],
    derive_window: bool = True,
) -> dict[str, Any]:
    """Publish AFTER and stage the rotation chain.

    The live runner passes ``derive_window=False`` so the CPU-heavy, local-only
    decode/hash/classification step runs after the monitored runnable has
    stopped QEMU.  The default retains the standalone helper contract used by
    offline/unit callers.
    """

    protocol = log_v2.validate_protocol(
        protocol,
        campaign_id=campaign_id,
        case_id=case_id,
    )
    marker_result = write_official_log_marker_v2(
        ssh,
        protocol["after"],
    )
    evidence["afterMarker"] = marker_result
    if marker_result["returnCode"] != 0 or marker_result["stderr"]:
        raise esxi_aer.InconclusiveObservation(
            "the official AFTER log marker command failed"
        )
    visibility = log_v2.wait_for_marker(
        ssh,
        protocol["after"],
        cancel,
        monotonic=time.monotonic,
    )
    evidence["afterMarkerVisibility"] = visibility
    if not _v2_marker_visibility_record_exact(
        visibility,
        protocol["after"],
    ):
        raise esxi_aer.InconclusiveObservation(
            "the official AFTER log marker was not uniquely visible "
            "in every required ESXi log source"
        )
    if cancel.is_set():
        return {
            "cancelledBySafetyMonitor": True,
            "afterMarker": marker_result,
            "afterMarkerVisibility": visibility,
        }
    capture_summary = log_v2.capture_rotation_chain(
        ssh,
        transfer,
        case_dir,
        protocol,
    )
    evidence["logWindowCapture"] = capture_summary
    result = {
        "afterMarker": marker_result,
        "afterMarkerVisibility": visibility,
        "capture": capture_summary,
    }
    if not derive_window:
        return result
    window = log_v2.rebuild_log_window(
        case_dir=case_dir,
        campaign_id=campaign_id,
        case_id=case_id,
        case_protocol=protocol,
        capture_summary=capture_summary,
        semantic_classifier=esxi_aer.aer_log_lines,
    )
    evidence["logWindow"] = window
    result["window"] = window
    return result


def rebuild_v2_log_window(
    *,
    case_dir: Path,
    case_spec: dict[str, Any],
    t0: dict[str, Any],
    t4: dict[str, Any],
) -> dict[str, Any]:
    """Rebuild and exact-check the official per-source V2 marker bracket."""

    campaign_id = case_spec.get("campaignId")
    case_id = case_spec.get("caseId")
    case_protocol = case_spec.get("logWindowProtocol")
    capture_summary = t4.get("logWindowCapture")
    rebuilt = log_v2.rebuild_log_window(
        case_dir=case_dir,
        campaign_id=campaign_id,
        case_id=case_id,
        case_protocol=case_protocol,
        capture_summary=capture_summary,
        semantic_classifier=esxi_aer.aer_log_lines,
    )
    protocol = rebuilt["protocol"]
    stored_window = t4.get("logWindow")
    summary_consistency = {
        "protocolFrozen": case_protocol == protocol,
        "preflightInventory": _v2_inventory_record_exact(
            t0.get("logWindowPreflightInventory")
        ),
        "beforeMarkerWrite": _v2_marker_write_record_exact(
            t0.get("beforeMarker"),
            protocol["before"],
        ),
        "beforeMarkerVisibility": _v2_marker_visibility_record_exact(
            t0.get("beforeMarkerVisibility"),
            protocol["before"],
        ),
        "afterMarkerWrite": _v2_marker_write_record_exact(
            t4.get("afterMarker"),
            protocol["after"],
        ),
        "afterMarkerVisibility": _v2_marker_visibility_record_exact(
            t4.get("afterMarkerVisibility"),
            protocol["after"],
        ),
        "captureSummary": _v2_capture_summary_shape_exact(
            capture_summary,
            protocol,
        ),
        "rebuiltComplete": rebuilt.get("complete") is True,
        "storedWindowExact": stored_window == rebuilt,
    }
    return {
        **rebuilt,
        "summaryConsistency": summary_consistency,
    }


def rebuild_bounded_log_window(
    *,
    case_dir: Path,
    case_spec: dict[str, Any],
    t0: dict[str, Any],
    t4: dict[str, Any],
) -> dict[str, Any]:
    """Reclassify a manifest-bound ESXi log window from its raw artifacts."""

    if "logWindowProtocol" in case_spec:
        return rebuild_v2_log_window(
            case_dir=case_dir,
            case_spec=case_spec,
            t0=t0,
            t4=t4,
        )

    campaign_id = case_spec.get("campaignId")
    case_id = case_spec.get("caseId")
    expected_before = (
        f"{campaign_id}-{case_id}-BEFORE"
        if isinstance(campaign_id, str) and isinstance(case_id, str)
        else None
    )
    expected_after = (
        f"{campaign_id}-{case_id}-AFTER"
        if isinstance(campaign_id, str) and isinstance(case_id, str)
        else None
    )
    summary = t4.get("logWindow")
    summary = summary if isinstance(summary, dict) else {}
    summary_files = summary.get("files")
    summary_files = (
        summary_files if isinstance(summary_files, dict) else {}
    )
    raw_cursors = t0.get("logCursors")
    raw_cursors = raw_cursors if isinstance(raw_cursors, dict) else {}

    def parse_stat_evidence(
        value: Any,
        *,
        expected_command: str,
    ) -> tuple[int | None, int | None, bool, bool]:
        if not isinstance(value, dict):
            return None, None, False, False
        return_code = value.get("returnCode")
        stdout = value.get("stdout")
        record_exact = bool(
            value.get("command") == expected_command
            and isinstance(return_code, int)
            and not isinstance(return_code, bool)
            and isinstance(stdout, str)
            and isinstance(value.get("stderr"), str)
        )
        match = (
            re.fullmatch(r"(\d+)\s+(\d+)\s*", stdout)
            if record_exact and return_code == 0
            else None
        )
        parsed = match is not None
        return (
            int(match.group(1)) if match else None,
            int(match.group(2)) if match else None,
            record_exact,
            parsed,
        )

    texts: list[str] = []
    files: dict[str, Any] = {}
    for name, remote_path in LOG_PATHS.items():
        expected_artifact = f"raw-esxi/log-window/{name}.log"
        path = case_dir / Path(expected_artifact)
        metadata = summary_files.get(name)
        metadata = metadata if isinstance(metadata, dict) else {}
        cursor = raw_cursors.get(name)
        cursor = cursor if isinstance(cursor, dict) else {}
        stat_command = f"stat -c '%i %s' {shlex.quote(remote_path)}"
        (
            cursor_inode,
            cursor_offset,
            cursor_record_exact,
            cursor_parsed,
        ) = parse_stat_evidence(
            cursor,
            expected_command=stat_command,
        )
        cursor_exact = bool(
            cursor_record_exact
            and cursor.get("path") == remote_path
            and cursor.get("parseable") is cursor_parsed
            and cursor.get("inode") == cursor_inode
            and cursor.get("offsetBytes") == cursor_offset
        )
        (
            stat_end_inode,
            stat_end_size,
            end_stat_record_exact,
            end_stat_parsed,
        ) = parse_stat_evidence(
            metadata.get("endStat"),
            expected_command=stat_command,
        )
        exists = path.is_file()
        raw = path.read_bytes() if exists else b""
        text = raw.decode("utf-8", errors="replace")
        texts.append(text)
        bounded_count = metadata.get("boundedByteCount")
        start_offset = metadata.get("startOffsetBytes")
        end_size = metadata.get("endSizeBytes")
        start_inode = metadata.get("startInode")
        end_inode = metadata.get("endInode")
        window_starts_at_cursor = bool(
            cursor_exact
            and start_inode == cursor_inode
            and start_offset == cursor_offset
        )
        end_stat_exact = bool(
            end_stat_record_exact
            and end_inode == stat_end_inode
            and end_size == stat_end_size
        )
        derived_stable = bool(
            cursor_parsed
            and end_stat_parsed
            and stat_end_inode == cursor_inode
            and isinstance(cursor_offset, int)
            and isinstance(stat_end_size, int)
            and stat_end_size >= cursor_offset
        )
        expected_bounded_count = (
            stat_end_size - cursor_offset
            if derived_stable
            and isinstance(stat_end_size, int)
            and isinstance(cursor_offset, int)
            else None
        )
        byte_bracket_exact = bool(
            window_starts_at_cursor
            and end_stat_exact
            and bounded_count == expected_bounded_count
        )
        stable_claim_exact = (
            metadata.get("stableAppendWindow") is derived_stable
        )
        capture = metadata.get("capture")
        expected_capture_command = (
            (
                f"dd if={shlex.quote(remote_path)} bs=1 "
                f"skip={cursor_offset} count={expected_bounded_count} "
                "2>/dev/null"
            )
            if derived_stable
            else None
        )
        capture_metadata_exact = bool(
            (
                derived_stable
                and isinstance(capture, dict)
                and capture.get("command") == expected_capture_command
                and isinstance(capture.get("returnCode"), int)
                and not isinstance(capture.get("returnCode"), bool)
                and capture.get("stdout") == f"{name}.log"
                and capture.get("stderr")
                in (None, f"{name}.log.stderr")
            )
            or (not derived_stable and capture is None)
        )
        capture_return_code = (
            capture.get("returnCode")
            if isinstance(capture, dict)
            else None
        )
        actual_size_exact = bool(
            exists
            and isinstance(expected_bounded_count, int)
            and len(raw) == expected_bounded_count
        )
        derived_exact_capture = bool(
            derived_stable
            and capture_metadata_exact
            and capture_return_code == 0
            and actual_size_exact
        )
        exact_capture_claim_exact = (
            metadata.get("exactByteCapture") is derived_exact_capture
        )
        authority_checks = {
            "artifactExact": metadata.get("artifact") == expected_artifact,
            "remotePathExact": metadata.get("path") == remote_path,
            "rawArtifactPresent": exists,
            "preSequenceCursorExact": cursor_exact,
            "windowStartsAtCursor": window_starts_at_cursor,
            "endStatExact": end_stat_exact,
            "stableAppendWindowClaimExact": stable_claim_exact,
            "byteBracketExact": byte_bracket_exact,
            "captureMetadataExact": capture_metadata_exact,
            "exactByteCaptureClaimExact": exact_capture_claim_exact,
        }
        checks = {
            **authority_checks,
            "inodeStable": derived_stable,
            "actualSizeExact": actual_size_exact,
            "stableAppendWindow": derived_stable,
            "exactByteCapture": derived_exact_capture,
            "captureCommandExact": bool(
                derived_stable
                and isinstance(capture, dict)
                and capture.get("command") == expected_capture_command
            ),
            "captureReturnCode": capture_return_code == 0,
        }
        files[name] = {
            "artifact": expected_artifact,
            "actualSizeBytes": len(raw) if exists else None,
            "checks": checks,
            "complete": bool(
                all(authority_checks.values())
                and derived_stable
                and derived_exact_capture
            ),
            "summaryConsistent": all(authority_checks.values()),
        }

    combined_text = "\n".join(texts)
    combined_lines = combined_text.splitlines()

    def marker_lines(marker: str | None) -> list[str]:
        if not isinstance(marker, str) or not marker:
            return []
        return [
            line
            for line in combined_lines
            if (
                marker in line
                and "PCI-AER-ROOT-SEQ" in line
                and "sshd-session" not in line
                and "running command" not in line
            )
        ]

    before_lines = marker_lines(expected_before)
    after_lines = marker_lines(expected_after)
    excluded_marker_lines = [
        line
        for line in combined_lines
        if (
            "PCI-AER-ROOT-SEQ" in line
            or (
                isinstance(expected_before, str)
                and expected_before in line
            )
            or (
                isinstance(expected_after, str)
                and expected_after in line
            )
        )
    ]
    semantic_input = [
        line for line in combined_lines if line not in excluded_marker_lines
    ]
    semantic_lines = esxi_aer.aer_log_lines(semantic_input)
    complete = bool(
        files
        and all(item["complete"] for item in files.values())
        and before_lines
        and after_lines
    )
    classification = (
        "MATCHING_EVENT_OBSERVED"
        if semantic_lines
        else (
            "NOT_OBSERVED_IN_MARKER_AND_BYTE_CURSOR_WINDOW"
            if complete
            else "INCONCLUSIVE_LOG_WINDOW"
        )
    )
    recomputed_markers = {
        "before": {
            "value": expected_before,
            "present": bool(before_lines),
            "matchedLines": before_lines,
        },
        "after": {
            "value": expected_after,
            "present": bool(after_lines),
            "matchedLines": after_lines,
        },
    }
    t0_before = t0.get("beforeMarker")
    t0_before = t0_before if isinstance(t0_before, dict) else {}
    t4_after = t4.get("afterMarker")
    t4_after = t4_after if isinstance(t4_after, dict) else {}
    summary_markers = summary.get("markers")
    summary_markers = (
        summary_markers if isinstance(summary_markers, dict) else {}
    )
    return {
        "complete": complete,
        "classification": classification,
        "semanticAerLines": semantic_lines,
        "excludedRunnerMarkerLines": excluded_marker_lines,
        "markers": recomputed_markers,
        "files": files,
        "summaryConsistency": {
            "beforeMarkerIdentity": (
                t0_before.get("marker") == expected_before
            ),
            "afterMarkerIdentity": (
                t4_after.get("marker") == expected_after
            ),
            "fileMetadata": bool(
                files
                and all(
                    item["summaryConsistent"]
                    for item in files.values()
                )
            ),
            "complete": summary.get("complete") is complete,
            "classification": (
                summary.get("classification") == classification
            ),
            "semanticAerLines": (
                summary.get("semanticAerLines") == semantic_lines
            ),
            "excludedRunnerMarkerLines": (
                summary.get("excludedRunnerMarkerLines")
                == excluded_marker_lines
            ),
            "markers": summary_markers == recomputed_markers,
        },
    }


def rebuild_guest_serial_evidence(
    *,
    case_dir: Path,
    case_spec: dict[str, Any],
    oracle_profile: dict[str, Any],
    t0: dict[str, Any],
    t1: dict[str, Any],
    t4: dict[str, Any],
) -> dict[str, Any]:
    """Reparse O4 ownership/heartbeat proof from the bound serial artifacts."""

    required = case_spec.get("ownerPhase") == "O4"
    if not required:
        return {
            "required": False,
            "validO4Evidence": False,
            "summaryConsistency": {},
        }
    expected_pci = (
        oracle_profile.get("environmentBinding", {}).get("expectedPciId")
    )
    match = (
        re.fullmatch(r"([0-9a-fA-F]{4}):([0-9a-fA-F]{4})", expected_pci)
        if isinstance(expected_pci, str)
        else None
    )
    vendor_id = int(match.group(1), 16) if match else None
    device_id = int(match.group(2), 16) if match else None
    before_artifact = "guest-serial/before-sequence.log"
    after_artifact = "guest-serial/after-sequence.log"
    before_path = case_dir / before_artifact
    after_path = case_dir / after_artifact
    before_text = (
        before_path.read_text(encoding="utf-8", errors="replace")
        if before_path.is_file()
        else ""
    )
    after_text = (
        after_path.read_text(encoding="utf-8", errors="replace")
        if after_path.is_file()
        else ""
    )
    before_evidence = parse_guest_owner_evidence(
        before_text,
        expected_vendor_id=vendor_id,
        expected_device_id=device_id,
    )
    after_evidence = parse_guest_owner_evidence(
        after_text,
        expected_vendor_id=vendor_id,
        expected_device_id=device_id,
    )
    kernel_lines = esxi_aer.guest_aer_event_lines(after_text)
    before_summary = t0.get("guestBefore")
    before_summary = (
        before_summary if isinstance(before_summary, dict) else {}
    )
    after_summary = t4.get("guest")
    after_summary = (
        after_summary if isinstance(after_summary, dict) else {}
    )
    active_vm_summary = t1.get("activeVm")
    active_vm_summary = (
        active_vm_summary if isinstance(active_vm_summary, dict) else {}
    )
    active_vm_window = active_vm_summary.get("window")
    active_vm_window = (
        active_vm_window if isinstance(active_vm_window, dict) else {}
    )

    def finite_nonnegative(value: Any) -> float | None:
        if (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
            and value >= 0
        ):
            return float(value)
        return None

    required_seconds = finite_nonnegative(
        active_vm_window.get("requiredRemainingSeconds")
    )
    timing = oracle_profile.get("timingEnvelope")
    timing = timing if isinstance(timing, dict) else {}
    minimum_required = finite_nonnegative(
        timing.get("minimumGuestWindowRemainingSecondsO4")
    )
    attested_window = finite_nonnegative(
        timing.get("guestWindowSeconds")
    )
    heartbeat_allowance = 5
    required_policy_bound = bool(
        required_seconds is not None
        and minimum_required is not None
        and required_seconds >= minimum_required
        and attested_window is not None
        and required_seconds + heartbeat_allowance <= attested_window
    )
    before_heartbeats = before_evidence.get("heartbeats")
    before_heartbeats = (
        before_heartbeats if isinstance(before_heartbeats, list) else []
    )
    latest_heartbeat = (
        before_heartbeats[-1]
        if (
            before_heartbeats
            and isinstance(before_heartbeats[-1], dict)
        )
        else None
    )
    published_seconds = (
        latest_heartbeat.get("remaining")
        if isinstance(latest_heartbeat, dict)
        and isinstance(latest_heartbeat.get("remaining"), int)
        and not isinstance(latest_heartbeat.get("remaining"), bool)
        else None
    )
    conservative_seconds = (
        max(0, published_seconds - heartbeat_allowance)
        if isinstance(published_seconds, int)
        else None
    )
    recomputed_window_remaining = {
        "source": "latest guest AER-HEARTBEAT remaining",
        "publishedSeconds": published_seconds,
        "heartbeatIntervalAllowanceSeconds": heartbeat_allowance,
        "conservativeLowerBoundSeconds": conservative_seconds,
        "requiredSeconds": required_seconds,
    }
    stored_window_remaining = before_summary.get(
        "windowRemainingEvidence"
    )
    window_summary_consistent = (
        stored_window_remaining == recomputed_window_remaining
    )
    before_window_valid = bool(
        required_policy_bound
        and window_summary_consistent
        and conservative_seconds is not None
        and required_seconds is not None
        and conservative_seconds >= required_seconds
    )
    before_driver_identity_valid = (
        before_evidence.get("beforeDriverBound") is True
    )
    after_complete_heartbeat_valid = (
        after_evidence.get("validO4Evidence") is True
    )
    artifacts_present = (
        before_path.is_file() and after_path.is_file()
    )
    return {
        "required": True,
        "expectedIdentity": {
            "vendorId": vendor_id,
            "deviceId": device_id,
        },
        "artifactsPresent": artifacts_present,
        "beforeOwnerEvidence": before_evidence,
        "beforeWindowRemainingEvidence": recomputed_window_remaining,
        "beforeDriverAndIdentityValid": before_driver_identity_valid,
        "beforeWindowRemainingValid": before_window_valid,
        "afterOwnerEvidence": after_evidence,
        "afterCompleteHeartbeatValid": after_complete_heartbeat_valid,
        "kernelEventLines": kernel_lines,
        "validO4Evidence": bool(
            artifacts_present
            and before_driver_identity_valid
            and before_window_valid
            and after_complete_heartbeat_valid
        ),
        "summaryConsistency": {
            "beforeArtifact": (
                before_summary.get("artifact") == before_artifact
            ),
            "beforeOwnerEvidence": (
                before_summary.get("ownerEvidence") == before_evidence
            ),
            "beforeWindowRemainingEvidence": window_summary_consistent,
            "activeVmBeforeArtifact": (
                active_vm_summary.get("guestSerialArtifact")
                == before_artifact
            ),
            "requiredWindowPolicy": required_policy_bound,
            "afterArtifact": (
                after_summary.get("artifact") == after_artifact
            ),
            "afterOwnerEvidence": (
                after_summary.get("ownerEvidence") == after_evidence
            ),
            "kernelEventLines": (
                after_summary.get("kernelEventLines") == kernel_lines
            ),
        },
    }


def pre_injection_log_stage_artifacts_absent(case_dir: Path) -> bool:
    """Reject every retained log-window namespace before HMP entry."""

    raw_esxi = case_dir / "raw-esxi"
    try:
        if raw_esxi.is_symlink() or (
            path_exists_or_is_symlink(raw_esxi)
            and not raw_esxi.is_dir()
        ):
            return False
        children = (
            list(raw_esxi.iterdir()) if raw_esxi.is_dir() else []
        )
    except OSError:
        return False
    return not any(
        item.name.startswith("log-window")
        or item.name.startswith("log_window")
        for item in children
    )


def strict_pre_injection_log_stage_absence(
    *,
    case_dir: Path,
    t0: dict[str, Any],
    t4: dict[str, Any],
    evidence: dict[str, Any],
) -> bool:
    """Verify the closed empty state when execution never opened a log window."""

    t0_null_fields = {
        "logWindowPreflightInventory",
        "beforeMarker",
        "beforeMarkerVisibility",
    }
    t4_null_fields = {
        "afterMarker",
        "afterMarkerVisibility",
        "logWindow",
        "logWindowCapture",
    }
    if (
        not t0_null_fields.issubset(t0)
        or not t4_null_fields.issubset(t4)
        or any(t0[field] is not None for field in t0_null_fields)
        or any(t4[field] is not None for field in t4_null_fields)
    ):
        return False
    if not pre_injection_log_stage_artifacts_absent(case_dir):
        return False
    if (
        evidence.get("complete") is not False
        or evidence.get("classification") != "INCONCLUSIVE_LOG_WINDOW"
        or evidence.get("semanticAerLines") != []
    ):
        return False
    if "semanticAerEvents" in evidence:
        return bool(
            evidence.get("semanticAerEvents") == []
            and evidence.get("selectedAttempt") is None
            and evidence.get("controlArtifact") is None
        )
    return True


def strict_pre_injection_o4_guest_stage_absence(
    *,
    case_dir: Path,
    t0: dict[str, Any],
    t1: dict[str, Any],
    t4: dict[str, Any],
    evidence: dict[str, Any],
) -> bool:
    """Verify that no O4 guest evidence stage was minted before injection."""

    if (
        "guestBefore" not in t0
        or "activeVm" not in t1
        or "guest" not in t4
        or t0["guestBefore"] is not None
        or t1["activeVm"] is not None
        or t4["guest"] is not None
        or path_exists_or_is_symlink(case_dir / "guest-serial")
    ):
        return False
    final_serial = case_dir / "guest-serial-final.log"
    if path_exists_or_is_symlink(final_serial) and (
        final_serial.is_symlink()
        or not final_serial.is_file()
        or final_serial.stat().st_size != 0
    ):
        return False
    consistency = evidence.get("summaryConsistency")
    expected_consistency_fields = {
        "beforeArtifact",
        "beforeOwnerEvidence",
        "beforeWindowRemainingEvidence",
        "activeVmBeforeArtifact",
        "requiredWindowPolicy",
        "afterArtifact",
        "afterOwnerEvidence",
        "kernelEventLines",
    }
    return bool(
        evidence.get("required") is True
        and evidence.get("artifactsPresent") is False
        and evidence.get("validO4Evidence") is False
        and evidence.get("kernelEventLines") == []
        and isinstance(consistency, dict)
        and set(consistency) == expected_consistency_fields
        and all(value is False for value in consistency.values())
    )


LOG_WINDOW_V2_SUMMARY_CONSISTENCY_FIELDS = frozenset(
    {
        "protocolFrozen",
        "preflightInventory",
        "beforeMarkerWrite",
        "beforeMarkerVisibility",
        "afterMarkerWrite",
        "afterMarkerVisibility",
        "captureSummary",
        "rebuiltComplete",
        "storedWindowExact",
    }
)

O4_GUEST_SUMMARY_CONSISTENCY_FIELDS = frozenset(
    {
        "beforeArtifact",
        "beforeOwnerEvidence",
        "beforeWindowRemainingEvidence",
        "activeVmBeforeArtifact",
        "requiredWindowPolicy",
        "afterArtifact",
        "afterOwnerEvidence",
        "kernelEventLines",
    }
)

O4_GUEST_BEFORE_FIELDS = frozenset(
    {"artifact", "ownerEvidence", "windowRemainingEvidence"}
)
O4_GUEST_WINDOW_REMAINING_FIELDS = frozenset(
    {
        "source",
        "publishedSeconds",
        "heartbeatIntervalAllowanceSeconds",
        "conservativeLowerBoundSeconds",
        "requiredSeconds",
    }
)
O4_ACTIVE_VM_BEFORE_FIELDS = frozenset(
    {"start", "window", "guestSerialArtifact"}
)
O4_ACTIVE_VM_START_FIELDS = frozenset(
    {
        "vmName",
        "vmid",
        "remoteDirectory",
        "remoteVmx",
        "serial",
        "activeUsers",
        "activeUserProbe",
        "windowSeconds",
    }
)
O4_ACTIVE_USER_FIELDS = frozenset(
    {
        "backingIds",
        "backingType",
        "deviceKey",
        "label",
        "vm",
        "vmMoId",
    }
)


def exact_o4_before_stage_records(
    *,
    t0: dict[str, Any],
    t1: dict[str, Any],
    before_artifact: str,
) -> bool:
    """Close every nested producer record retained by an O4 BEFORE prefix."""

    before = t0.get("guestBefore")
    active_vm = t1.get("activeVm")
    if (
        not isinstance(before, dict)
        or set(before) != O4_GUEST_BEFORE_FIELDS
        or before.get("artifact") != before_artifact
        or not isinstance(before.get("ownerEvidence"), dict)
        or not isinstance(active_vm, dict)
        or set(active_vm) != O4_ACTIVE_VM_BEFORE_FIELDS
        or active_vm.get("guestSerialArtifact") != before_artifact
    ):
        return False

    remaining = before.get("windowRemainingEvidence")
    active_window = active_vm.get("window")
    start = active_vm.get("start")
    if (
        not isinstance(remaining, dict)
        or set(remaining) != O4_GUEST_WINDOW_REMAINING_FIELDS
        or remaining.get("source")
        != "latest guest AER-HEARTBEAT remaining"
        or not isinstance(active_window, dict)
        or set(active_window) != O4_GUEST_WINDOW_FIELDS
        or not isinstance(start, dict)
        or set(start) != O4_ACTIVE_VM_START_FIELDS
    ):
        return False

    published = remaining.get("publishedSeconds")
    allowance = remaining.get("heartbeatIntervalAllowanceSeconds")
    conservative = remaining.get("conservativeLowerBoundSeconds")
    required = remaining.get("requiredSeconds")
    if (
        not isinstance(published, int)
        or isinstance(published, bool)
        or published < 0
        or allowance != 5
        or conservative != max(0, published - allowance)
        or not _finite_number(required)
        or float(required) <= 0
        or conservative < float(required)
    ):
        return False

    window_values: dict[str, float] = {}
    for field_name in O4_GUEST_WINDOW_FIELDS:
        value = active_window.get(field_name)
        if not _finite_number(value):
            return False
        window_values[field_name] = float(value)
    if (
        window_values["windowSeconds"] <= 0
        or window_values["elapsedSinceOpenObserved"] < 0
        or window_values["requiredRemainingSeconds"] <= 0
        or window_values["remainingSeconds"]
        < window_values["requiredRemainingSeconds"]
        or window_values["requiredRemainingSeconds"] != float(required)
        or not math.isclose(
            window_values["windowSeconds"]
            - window_values["elapsedSinceOpenObserved"],
            window_values["remainingSeconds"],
            rel_tol=0.0,
            abs_tol=1e-9,
        )
    ):
        return False

    string_fields = (
        "vmName",
        "vmid",
        "remoteDirectory",
        "remoteVmx",
        "serial",
    )
    if (
        any(
            not isinstance(start.get(field_name), str)
            or not start[field_name]
            for field_name in string_fields
        )
        or not isinstance(start.get("windowSeconds"), int)
        or isinstance(start.get("windowSeconds"), bool)
        or start["windowSeconds"] <= 0
        or float(start["windowSeconds"]) != window_values["windowSeconds"]
        or closed_active_vm_remote_path_names(start) is None
    ):
        return False

    active_user_probe = start.get("activeUserProbe")
    if (
        not isinstance(active_user_probe, dict)
        or set(active_user_probe) != {"mode", "capturedAt"}
        or active_user_probe.get("mode") != "ISOLATED_PROCESS"
        or _utc_datetime(active_user_probe.get("capturedAt")) is None
    ):
        return False
    active_users = start.get("activeUsers")
    if not isinstance(active_users, list) or not active_users:
        return False
    matching_user = False
    for user in active_users:
        if not isinstance(user, dict) or set(user) != O4_ACTIVE_USER_FIELDS:
            return False
        backing_ids = user.get("backingIds")
        if (
            not isinstance(backing_ids, list)
            or not backing_ids
            or any(
                not isinstance(item, str)
                or esxi_aer.BDF_RE.fullmatch(item) is None
                for item in backing_ids
            )
            or user.get("backingType")
            != "vim.vm.device.VirtualPCIPassthrough.DeviceBackingInfo"
            or not isinstance(user.get("deviceKey"), int)
            or isinstance(user.get("deviceKey"), bool)
            or not isinstance(user.get("label"), str)
            or not user["label"]
            or not isinstance(user.get("vm"), str)
            or not user["vm"]
            or not isinstance(user.get("vmMoId"), str)
            or not user["vmMoId"]
        ):
            return False
        matching_user = bool(
            matching_user
            or (
                user["vm"] == start["vmName"]
                and user["vmMoId"] == start["vmid"]
            )
        )
    return matching_user


def closed_active_vm_remote_path_names(
    start: Any,
) -> tuple[str, str] | None:
    """Bind cleanup basenames to the exact ESXi directory retained at start."""

    if not isinstance(start, dict):
        return None
    remote_directory = start.get("remoteDirectory")
    serial = start.get("serial")
    remote_vmx = start.get("remoteVmx")
    if not all(
        isinstance(value, str) and value
        for value in (remote_directory, serial, remote_vmx)
    ):
        return None
    remote_path = PurePosixPath(remote_directory)
    serial_path = PurePosixPath(serial)
    vmx_path = PurePosixPath(remote_vmx)
    if (
        not remote_path.is_absolute()
        or not serial_path.is_absolute()
        or not vmx_path.is_absolute()
        or str(remote_path) != remote_directory
        or str(serial_path) != serial
        or str(vmx_path) != remote_vmx
        or serial_path.parent != remote_path
        or vmx_path.parent != remote_path
        or not serial_path.name.endswith(".log")
        or not vmx_path.name.endswith(".vmx")
    ):
        return None
    return serial_path.name, vmx_path.name


def exact_nonentered_log_stage_summary(
    *,
    case_dir: Path,
    case_protocol: Any,
    t0: dict[str, Any],
    t4: dict[str, Any],
    evidence: dict[str, Any],
) -> bool:
    """Accept only the exact EMPTY or successful BEFORE-only V2 prefix."""

    consistency = evidence.get("summaryConsistency")
    if (
        not isinstance(consistency, dict)
        or set(consistency) != LOG_WINDOW_V2_SUMMARY_CONSISTENCY_FIELDS
        or not isinstance(case_protocol, dict)
        or evidence.get("protocol") != case_protocol
        or evidence.get("complete") is not False
        or evidence.get("classification") != "INCONCLUSIVE_LOG_WINDOW"
        or evidence.get("semanticAerLines") != []
        or evidence.get("semanticAerEvents") != []
        or evidence.get("selectedAttempt") is not None
        or evidence.get("controlArtifact") is not None
    ):
        return False
    empty_consistency = {
        field: field == "protocolFrozen"
        for field in LOG_WINDOW_V2_SUMMARY_CONSISTENCY_FIELDS
    }
    if consistency == empty_consistency:
        return strict_pre_injection_log_stage_absence(
            case_dir=case_dir,
            t0=t0,
            t4=t4,
            evidence=evidence,
        )

    before_consistency = {
        field: field
        in {
            "protocolFrozen",
            "preflightInventory",
            "beforeMarkerWrite",
            "beforeMarkerVisibility",
        }
        for field in LOG_WINDOW_V2_SUMMARY_CONSISTENCY_FIELDS
    }
    t0_fields = (
        "logWindowPreflightInventory",
        "beforeMarker",
        "beforeMarkerVisibility",
    )
    t4_fields = (
        "afterMarker",
        "afterMarkerVisibility",
        "logWindow",
        "logWindowCapture",
    )
    before_marker = case_protocol.get("before")
    return bool(
        consistency == before_consistency
        and isinstance(before_marker, str)
        and _v2_inventory_record_exact(
            t0.get("logWindowPreflightInventory")
        )
        and _v2_marker_write_record_exact(
            t0.get("beforeMarker"),
            before_marker,
        )
        and _v2_marker_visibility_record_exact(
            t0.get("beforeMarkerVisibility"),
            before_marker,
        )
        and all(
            field in t0 and isinstance(t0.get(field), dict)
            for field in t0_fields
        )
        and all(field in t4 and t4.get(field) is None for field in t4_fields)
        and pre_injection_log_stage_artifacts_absent(case_dir)
    )


GUEST_HEARTBEAT_APPEND_LINE_RE = re.compile(
    rb"AER-HEARTBEAT index=(0|[1-9][0-9]*) "
    rb"uptime=(0|[1-9][0-9]*)\.[0-9]{2} "
    rb"remaining=(0|[1-9][0-9]*)"
)


def _consistent_serial_line_ending(value: bytes) -> bytes | None:
    """Return LF or CRLF only when every serial line uses that one style."""

    if value.endswith(b"\r\n"):
        without_crlf = value.replace(b"\r\n", b"")
        return (
            b"\r\n"
            if b"\r" not in without_crlf and b"\n" not in without_crlf
            else None
        )
    if value.endswith(b"\n") and b"\r" not in value:
        return b"\n"
    return None


def exact_guest_heartbeat_append(
    *,
    before_path: Path,
    final_path: Path,
) -> bool:
    """Accept equality or only the probe's next contiguous heartbeat lines."""

    if (
        not before_path.is_file()
        or before_path.is_symlink()
        or not final_path.is_file()
        or final_path.is_symlink()
    ):
        return False
    try:
        before_bytes = before_path.read_bytes()
        final_bytes = final_path.read_bytes()
        before_text_raw = before_bytes.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    line_ending = _consistent_serial_line_ending(before_bytes)
    if line_ending is None:
        return False
    before_text = (
        before_text_raw.replace("\r\n", "\n")
        if line_ending == b"\r\n"
        else before_text_raw
    )

    before_lines = before_bytes.split(line_ending)
    if not before_lines or before_lines[-1] != b"":
        return False
    raw_before_heartbeats: list[
        tuple[int, float, int]
    ] = []
    for line in before_lines[:-1]:
        if not line.startswith(b"AER-HEARTBEAT "):
            continue
        match = GUEST_HEARTBEAT_APPEND_LINE_RE.fullmatch(line)
        if match is None:
            return False
        raw_before_heartbeats.append(
            (
                int(match.group(1)),
                float(
                    line[
                        line.index(b"uptime=") + len(b"uptime=") :
                        line.index(b" remaining=")
                    ].decode("ascii")
                ),
                int(match.group(3)),
            )
        )

    before_evidence = parse_guest_owner_evidence(before_text)
    before_heartbeats = before_evidence.get("heartbeats")
    if (
        not isinstance(before_heartbeats, list)
        or not before_heartbeats
        or len(raw_before_heartbeats) != len(before_heartbeats)
        or raw_before_heartbeats[0][0] != 0
        or any(
            later[0] != earlier[0] + 1
            or later[1] <= earlier[1]
            or later[2]
            != earlier[2] - min(5, earlier[2])
            or later[2] <= 0
            for earlier, later in zip(
                raw_before_heartbeats,
                raw_before_heartbeats[1:],
            )
        )
        or before_evidence.get("heartbeatContiguous") is not True
        or before_evidence.get("heartbeatUptimeMonotonic") is not True
        or before_evidence.get("heartbeatRemainingDecreases") is not True
    ):
        return False
    if final_bytes == before_bytes:
        return True
    if not final_bytes.startswith(before_bytes):
        return False
    suffix = final_bytes[len(before_bytes) :]
    if not suffix.endswith(line_ending):
        return False
    suffix_parts = suffix.split(line_ending)
    if not suffix_parts or suffix_parts[-1] != b"":
        return False
    terminal = before_heartbeats[-1]
    if not isinstance(terminal, dict):
        return False
    previous_index = terminal.get("index")
    previous_uptime = terminal.get("uptimeSeconds")
    previous_remaining = terminal.get("remaining")
    if (
        not isinstance(previous_index, int)
        or isinstance(previous_index, bool)
        or not isinstance(previous_uptime, (int, float))
        or isinstance(previous_uptime, bool)
        or not math.isfinite(float(previous_uptime))
        or not isinstance(previous_remaining, int)
        or isinstance(previous_remaining, bool)
        or previous_remaining <= 0
    ):
        return False

    for line in suffix_parts[:-1]:
        match = GUEST_HEARTBEAT_APPEND_LINE_RE.fullmatch(line)
        if match is None:
            return False
        index = int(match.group(1))
        uptime = float(
            line[
                line.index(b"uptime=") + len(b"uptime=") :
                line.index(b" remaining=")
            ].decode("ascii")
        )
        remaining = int(match.group(3))
        expected_remaining = previous_remaining - min(
            5,
            previous_remaining,
        )
        if (
            index != previous_index + 1
            or not math.isfinite(uptime)
            or uptime <= float(previous_uptime)
            or remaining <= 0
            or remaining != expected_remaining
        ):
            return False
        previous_index = index
        previous_uptime = uptime
        previous_remaining = remaining
    return True


def exact_nonentered_o4_guest_stage_summary(
    *,
    case_dir: Path,
    t0: dict[str, Any],
    t1: dict[str, Any],
    t4: dict[str, Any],
    t5: dict[str, Any],
    evidence: dict[str, Any],
) -> bool:
    """Accept only the exact EMPTY or valid BEFORE-only O4 serial prefix."""

    consistency = evidence.get("summaryConsistency")
    if (
        not isinstance(consistency, dict)
        or set(consistency) != O4_GUEST_SUMMARY_CONSISTENCY_FIELDS
        or evidence.get("required") is not True
        or evidence.get("artifactsPresent") is not False
        or evidence.get("validO4Evidence") is not False
        or evidence.get("kernelEventLines") != []
    ):
        return False
    empty_consistency = {
        field: False for field in O4_GUEST_SUMMARY_CONSISTENCY_FIELDS
    }
    if consistency == empty_consistency:
        return strict_pre_injection_o4_guest_stage_absence(
            case_dir=case_dir,
            t0=t0,
            t1=t1,
            t4=t4,
            evidence=evidence,
        )

    before_consistency = {
        field: field
        in {
            "beforeArtifact",
            "beforeOwnerEvidence",
            "beforeWindowRemainingEvidence",
            "activeVmBeforeArtifact",
            "requiredWindowPolicy",
        }
        for field in O4_GUEST_SUMMARY_CONSISTENCY_FIELDS
    }
    guest_dir = case_dir / "guest-serial"
    before_path = guest_dir / "before-sequence.log"
    after_path = guest_dir / "after-sequence.log"
    cleanup_serial_path = case_dir / "guest-serial-final.log"
    try:
        guest_children = (
            {item.name for item in guest_dir.iterdir()}
            if guest_dir.is_dir() and not guest_dir.is_symlink()
            else set()
        )
        unexpected_guest_siblings = {
            item.name
            for item in case_dir.iterdir()
            if (
                item.name.startswith("guest-serial")
                and item.name != "guest-serial"
            )
        }
        cleanup_record = t5.get("activeVmCleanup")
        cleanup_actions = (
            cleanup_record.get("actions")
            if isinstance(cleanup_record, dict)
            else None
        )
        cleanup_actions = (
            cleanup_actions if isinstance(cleanup_actions, list) else []
        )
        serial_copy_actions = [
            item
            for item in cleanup_actions
            if (
                isinstance(item, dict)
                and item.get("destination") == "guest-serial-final.log"
            )
        ]
        cleanup_serial_present = (
            cleanup_serial_path.is_file()
            and not cleanup_serial_path.is_symlink()
        )
        active_vm = t1.get("activeVm")
        active_start = (
            active_vm.get("start")
            if isinstance(active_vm, dict)
            else None
        )
        remote_path_names = closed_active_vm_remote_path_names(
            active_start
        )
        expected_copy_name = (
            remote_path_names[0]
            if remote_path_names is not None
            else None
        )
        expected_copy_pairs = (
            {
                (
                    remote_path_names[0],
                    "guest-serial-final.log",
                ),
                ("vmware.log", "vmware.log"),
                (remote_path_names[1], "effective.vmx"),
            }
            if remote_path_names is not None
            else set()
        )
        copy_shaped_actions = [
            item
            for item in cleanup_actions
            if (
                isinstance(item, dict)
                and bool(
                    set(item) & {"copy", "destination", "success"}
                )
            )
        ]
        observed_copy_pairs = [
            (item.get("copy"), item.get("destination"))
            for item in copy_shaped_actions
        ]
        copy_actions_exact = bool(
            remote_path_names is not None
            and all(
                set(item) == {"copy", "destination", "success"}
                and (item.get("copy"), item.get("destination"))
                in expected_copy_pairs
                and isinstance(item.get("success"), bool)
                for item in copy_shaped_actions
            )
            and len(observed_copy_pairs)
            == len(set(observed_copy_pairs))
        )
        cleanup_serial_exact = False
        if cleanup_serial_present and before_path.is_file():
            cleanup_serial_exact = bool(
                copy_actions_exact
                and len(serial_copy_actions) == 1
                and set(serial_copy_actions[0])
                == {"copy", "destination", "success"}
                and expected_copy_name is not None
                and serial_copy_actions[0].get("copy")
                == expected_copy_name
                and serial_copy_actions[0].get("success") is True
                and exact_guest_heartbeat_append(
                    before_path=before_path,
                    final_path=cleanup_serial_path,
                )
            )
        elif not path_exists_or_is_symlink(cleanup_serial_path):
            cleanup_serial_exact = bool(
                copy_actions_exact
                and not any(
                    item.get("success") is True
                    for item in serial_copy_actions
                )
            )
    except OSError:
        return False
    return bool(
        consistency == before_consistency
        and exact_o4_before_stage_records(
            t0=t0,
            t1=t1,
            before_artifact="guest-serial/before-sequence.log",
        )
        and "guest" in t4
        and t4.get("guest") is None
        and before_path.is_file()
        and not before_path.is_symlink()
        and not path_exists_or_is_symlink(after_path)
        and guest_children == {"before-sequence.log"}
        and unexpected_guest_siblings
        <= {"guest-serial-final.log"}
        and cleanup_serial_exact
        and evidence.get("beforeDriverAndIdentityValid") is True
        and evidence.get("beforeWindowRemainingValid") is True
        and evidence.get("afterCompleteHeartbeatValid") is False
    )


def complete_injected_log_summary(evidence: dict[str, Any]) -> bool:
    """Require the complete, closed Log Window V2 entered-stage summary."""

    consistency = evidence.get("summaryConsistency")
    return bool(
        evidence.get("complete") is True
        and isinstance(consistency, dict)
        and set(consistency) == LOG_WINDOW_V2_SUMMARY_CONSISTENCY_FIELDS
        and all(value is True for value in consistency.values())
    )


def complete_injected_o4_guest_summary(evidence: dict[str, Any]) -> bool:
    """Require complete O4 artifacts and a closed, all-true summary."""

    consistency = evidence.get("summaryConsistency")
    return bool(
        evidence.get("required") is True
        and evidence.get("artifactsPresent") is True
        and evidence.get("validO4Evidence") is True
        and isinstance(consistency, dict)
        and set(consistency) == O4_GUEST_SUMMARY_CONSISTENCY_FIELDS
        and all(value is True for value in consistency.values())
    )


def raw_o4_guest_evidence_valid(evidence: Any) -> bool:
    """Return only the observed O4 evidence fact, never O0 applicability."""

    return bool(
        isinstance(evidence, dict)
        and evidence.get("validO4Evidence") is True
    )


def strict_o0_guest_stage_absence(
    *,
    case_dir: Path,
    t0: dict[str, Any],
    t1: dict[str, Any],
    t4: dict[str, Any],
    evidence: dict[str, Any],
) -> bool:
    """Verify the explicit not-applicable guest state for an O0 case."""

    return bool(
        "guestBefore" in t0
        and "activeVm" in t1
        and "guest" in t4
        and t0["guestBefore"] is None
        and t1["activeVm"] is None
        and t4["guest"] is None
        and not path_exists_or_is_symlink(case_dir / "guest-serial")
        and not path_exists_or_is_symlink(
            case_dir / "guest-serial-final.log"
        )
        and evidence
        == {
            "required": False,
            "validO4Evidence": False,
            "summaryConsistency": {},
        }
    )


def expected_pci_id(target: dict[str, str]) -> str | None:
    try:
        return (
            f"{int(target['Vendor ID'], 16):04x}:"
            f"{int(target['Device ID'], 16):04x}"
        )
    except (KeyError, TypeError, ValueError):
        return None


def owner_observation(
    *,
    ssh: EsxiSsh,
    api: esxi_aer.ApiSession,
    bdf: str,
    active_vm: esxi_aer.ActiveVm | None,
    label: str,
) -> dict[str, Any]:
    pci = ssh.run("localcli hardware pci list", check=False, timeout=60)
    target = esxi_aer.extract_esxcli_device(pci.stdout, bdf)
    users = api.active_passthrough_users(bdf)
    runner_vm_name = active_vm.vm_name if active_vm is not None else None
    normalized_users = []
    for user in users:
        item = dict(user)
        item["runnerCreated"] = bool(
            runner_vm_name and item.get("vm") == runner_vm_name
        )
        normalized_users.append(item)
    heartbeat = ssh.run(
        "printf AER-ROOT-SEQUENCE-ALIVE",
        check=False,
        timeout=30,
    )
    return {
        "label": label,
        "observedAt": utc_now(),
        "currentOwner": (
            target.get("Current Owner") if isinstance(target, dict) else None
        ),
        "target": target,
        "activeUsers": normalized_users,
        "hostResponsive": (
            heartbeat.returncode == 0
            and "AER-ROOT-SEQUENCE-ALIVE" in heartbeat.stdout
        ),
        "heartbeatReturnCode": heartbeat.returncode,
    }


def outer_qemu_process_identity(name: str) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    proc_root = Path("/proc")
    if proc_root.is_dir():
        for entry in proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                data = (entry / "cmdline").read_bytes()
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            argv = [
                item.decode("utf-8", errors="replace")
                for item in data.split(b"\0")
                if item
            ]
            if not argv or not Path(argv[0]).name.startswith(
                "qemu-system-x86_64"
            ):
                continue
            qemu_name: str | None = None
            for index, item in enumerate(argv):
                if item == "-name" and index + 1 < len(argv):
                    qemu_name = argv[index + 1].split(",", 1)[0]
                    break
                if item.startswith("-name="):
                    qemu_name = item.split("=", 1)[1].split(",", 1)[0]
                    break
            if qemu_name == name:
                candidates.append(
                    {
                        "pid": int(entry.name),
                        "commandLine": argv,
                    }
                )
    candidates.sort(key=lambda item: item["pid"])
    return {
        "name": name,
        "candidateCount": len(candidates),
        "unique": len(candidates) == 1,
        "candidates": candidates,
        "pid": candidates[0]["pid"] if len(candidates) == 1 else None,
        "commandLine": (
            candidates[0]["commandLine"] if len(candidates) == 1 else []
        ),
    }


def environment_identity(
    *,
    api: esxi_aer.ApiSession,
    ssh: EsxiSsh,
    qemu_name: str,
) -> dict[str, Any]:
    product = api.host.config.product
    qemu_process = outer_qemu_process_identity(qemu_name)
    boot_time = api.host.runtime.bootTime
    version = ssh.run("vmware -vl", check=False, timeout=30)
    return {
        "esxi": {
            "fullName": product.fullName,
            "version": product.version,
            "build": product.build,
            "apiVersion": product.apiVersion,
            "systemUuid": api.system_uuid,
            "bootTime": (
                boot_time.isoformat()
                if hasattr(boot_time, "isoformat")
                else str(boot_time)
            ),
            "vmwareVersionCommand": version.stdout.strip(),
        },
        "outerQemu": qemu_process,
    }


def source_and_binary_hashes(
    *,
    args: argparse.Namespace,
    oracle_profile_path: Path,
    environment: dict[str, Any],
) -> dict[str, Any]:
    repository_inputs = [
        Path(__file__).resolve(),
        SCRIPT_DIR / "esxi_log_window_v2.py",
        SCRIPT_DIR / "test_esxi_aer_correctable_matrix.py",
        SCRIPT_DIR / "test_qemu_aer_correctable_matrix.py",
        SCRIPT_DIR / "test_qemu_aer_root_sequence.py",
        SCRIPT_DIR / "esxi_passthru_capability.py",
        oracle_profile_path,
        ORACLE_PROFILE_SCHEMA,
    ]
    if args.owner_phase == "O4":
        repository_inputs.extend(
            [
                SCRIPT_DIR / "esxi-l3-aer-init.sh",
                SCRIPT_DIR / "build-esxi-l3-probe-iso.sh",
                Path(args.base_vmx).resolve(),
                Path(args.local_iso).resolve(),
                Path(args.local_iso_attestation).resolve(),
            ]
        )
    records: list[dict[str, Any]] = []
    for path in repository_inputs:
        records.append(
            {
                "path": str(path),
                "exists": path.is_file(),
                "sha256": sha256_file(path) if path.is_file() else None,
            }
        )
    qemu_aer_source_record: dict[str, Any] | None = None
    if args.qemu_aer_source:
        source_path = Path(args.qemu_aer_source).resolve()
        qemu_aer_source_record = {
            "path": str(source_path),
            "exists": source_path.is_file(),
            "sha256": (
                sha256_file(source_path) if source_path.is_file() else None
            ),
        }
        records.append(qemu_aer_source_record)
    command_line = environment["outerQemu"].get("commandLine", [])
    binary_record: dict[str, Any] = {
        "commandLine": command_line,
        "path": None,
        "exists": False,
        "sha256": None,
    }
    try:
        if (
            isinstance(command_line, list)
            and command_line
            and isinstance(command_line[0], str)
        ):
            raw_binary = command_line[0]
            located_binary = (
                raw_binary
                if Path(raw_binary).is_absolute()
                else shutil.which(raw_binary)
            )
            binary = Path(located_binary).resolve() if located_binary else None
        elif isinstance(command_line, str):
            split_command = shlex.split(command_line)
            binary = Path(split_command[0]).resolve() if split_command else None
        else:
            binary = None
    except (IndexError, TypeError, ValueError):
        binary = None
    if binary is not None:
        binary_record.update(
            {
                "path": str(binary),
                "exists": binary.is_file(),
                "sha256": sha256_file(binary) if binary.is_file() else None,
            }
        )
    return {
        "hashAlgorithm": "SHA-256",
        "capturedAt": utc_now(),
        "environment": environment,
        "repositoryInputs": records,
        "pythonPackages": {
            distribution: installed_distribution_version(distribution)
            for distribution in ("jsonschema", "pyvmomi")
        },
        "qemuAerSource": qemu_aer_source_record,
        "outerQemuBinary": binary_record,
    }


def frozen_input_hash(
    source_hashes: dict[str, Any],
    path: Path,
) -> str:
    resolved = str(path.resolve())
    matches = [
        item
        for item in source_hashes.get("repositoryInputs", [])
        if isinstance(item, dict) and item.get("path") == resolved
    ]
    if len(matches) != 1 or not re.fullmatch(
        r"[0-9a-f]{64}",
        str(matches[0].get("sha256")),
    ):
        raise ValueError(f"no unique frozen hash for runtime input {resolved}")
    return str(matches[0]["sha256"])


def runtime_dependency_drift(
    source_hashes: dict[str, Any],
    environment: dict[str, Any],
) -> list[str]:
    faults: list[str] = []
    for item in source_hashes.get("repositoryInputs", []):
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            faults.append("malformed frozen repository input")
            continue
        path = Path(item["path"])
        actual = sha256_file(path) if path.is_file() else None
        if actual != item.get("sha256"):
            faults.append(f"runtime input drift: {path}")
    binary = source_hashes.get("outerQemuBinary")
    binary = binary if isinstance(binary, dict) else {}
    binary_path = binary.get("path")
    if isinstance(binary_path, str):
        path = Path(binary_path)
        actual = sha256_file(path) if path.is_file() else None
        if actual != binary.get("sha256"):
            faults.append(f"outer QEMU binary drift: {path}")
    else:
        faults.append("outer QEMU binary path is not frozen")
    expected_outer = environment.get("outerQemu")
    expected_outer = expected_outer if isinstance(expected_outer, dict) else {}
    current_outer = outer_qemu_process_identity(
        str(expected_outer.get("name", ""))
    )
    if (
        current_outer.get("unique") is not True
        or current_outer.get("pid") != expected_outer.get("pid")
        or current_outer.get("commandLine")
        != expected_outer.get("commandLine")
    ):
        faults.append("outer QEMU PID/argv identity drift")
    return faults


def new_cancel_event() -> threading.Event:
    """Create one worker-cancellation event through a testable local seam."""

    return threading.Event()


@dataclass
class LiveSequenceRecorder:
    args: argparse.Namespace
    case_dir: Path
    monitor: Path
    qtest_socket: Path
    ssh: EsxiSsh
    api: esxi_aer.ApiSession
    active_vm: esxi_aer.ActiveVm | None
    requested_gate: esxi_aer.GateTuple
    topology: dict[str, Any]
    forced_safety_boundary: str | None = None
    snapshots: dict[str, dict[str, Any]] = field(default_factory=dict)
    injections: list[dict[str, Any]] = field(default_factory=list)
    owner_observations: list[dict[str, Any]] = field(default_factory=list)
    safety_faults: list[dict[str, Any]] = field(default_factory=list)
    hmp_transcript: list[str] = field(default_factory=list)
    t2: list[dict[str, Any]] = field(default_factory=list)
    t3: list[dict[str, Any]] = field(default_factory=list)
    t4: list[dict[str, Any]] = field(default_factory=list)
    t5: list[dict[str, Any]] = field(default_factory=list)
    gate_stable: bool = True
    paused: bool = False
    mutation_boundary_crossed: bool = False

    @property
    def endpoint(self) -> dict[str, Any]:
        return self.topology["endpoint"]

    @property
    def root(self) -> dict[str, Any]:
        return self.topology["root"]

    @property
    def current_safety_boundary(self) -> str:
        if self.forced_safety_boundary in SAFETY_BOUNDARIES:
            return str(self.forced_safety_boundary)
        return (
            "ATTRIBUTION_WINDOW"
            if self.mutation_boundary_crossed
            else "PRE_INJECTION"
        )

    def pause(self, reason: str) -> dict[str, Any]:
        transition = esxi_aer.transition_qemu(
            self.monitor,
            "stop",
            "paused",
        )
        self.paused = True
        transition["reason"] = reason
        return transition

    def resume(self, reason: str) -> dict[str, Any]:
        transition = esxi_aer.transition_qemu(
            self.monitor,
            "cont",
            "running",
        )
        self.paused = False
        transition["reason"] = reason
        return transition

    def check_gate(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        effective = esxi_aer.gate_tuple_from_snapshot(
            snapshot,
            CONTROLLED_BITS,
        )
        root_path = esxi_aer.root_path_from_snapshot(snapshot)
        correctable_mask = int(
            snapshot["endpointState"]["correctableErrorMask"]
        )
        checks = {
            "tupleMatches": effective == self.requested_gate,
            "rootPathOpen": root_path.open,
            "b0AndB1Unmasked": not bool(
                correctable_mask & CONTROLLED_BITS
            ),
        }
        if not all(checks.values()):
            self.gate_stable = False
        return {
            "requested": self.requested_gate.as_dict(),
            "effective": effective.as_dict(),
            "rootPath": root_path.as_dict(),
            "correctableMask": correctable_mask,
            "checks": checks,
        }

    def capture(
        self,
        label: str,
        *,
        phase: str,
        operation: str,
        require_gate: bool = True,
        safety_boundary: str | None = None,
    ) -> dict[str, Any]:
        snapshot = esxi_aer.outer_qemu_aer_snapshot(
            self.qtest_socket,
            self.args.outer_endpoint_bdf,
            self.args.outer_root_bdf,
        )
        record_boundary = safety_boundary or self.current_safety_boundary
        if record_boundary not in SAFETY_BOUNDARIES:
            raise ValueError(
                f"invalid capture safety boundary: {record_boundary}"
            )
        record: dict[str, Any] = {
            "recordKind": PAUSED_NUMERIC_SNAPSHOT_RECORD_KIND,
            "label": label,
            "phase": phase,
            "operation": operation,
            "safetyBoundary": record_boundary,
            "observedAt": None,
            "qemuPaused": self.paused,
            "gate": None,
            "snapshot": snapshot,
            "sourceMeaning": None,
            "safetyFaults": [],
            "partial": True,
        }
        getattr(self, phase).append(record)
        # Persist the raw numeric authority before any public projection, gate
        # parse, or safety-shape parse can fail.
        faults = esxi_aer._partial_numeric_safety_faults(snapshot)
        record["safetyFaults"] = faults
        if faults:
            fault = {
                "label": label,
                "faults": faults,
                "snapshot": snapshot,
            }
            self.safety_faults.append(fault)
            raise esxi_aer.SafetyViolation(
                f"unsafe Correctable-only state at {label}: "
                + "; ".join(faults)
            )
        record["observedAt"] = utc_now()
        try:
            public = outer_to_public_state(snapshot)
            self.snapshots[label] = public
            gate = self.check_gate(snapshot)
            record["gate"] = gate
            record["sourceMeaning"] = root_source_meaning(public)
        except BaseException as error:
            record["parseFault"] = {
                "type": type(error).__name__,
                "message": str(error),
            }
            raise
        record["partial"] = False
        if require_gate and not all(gate["checks"].values()):
            raise FixtureInvalid(
                f"effective gate/root path drifted at {label}: {gate}"
            )
        return snapshot

    def record_pre_state(
        self,
        label: str,
        operation: str,
        *,
        safety_boundary: str | None = None,
        phase: str = "t2",
    ) -> None:
        record_boundary = safety_boundary or self.current_safety_boundary
        if record_boundary not in SAFETY_BOUNDARIES:
            raise ValueError(
                f"invalid pre-state safety boundary: {record_boundary}"
            )
        if phase not in {"t2", "t5"}:
            raise ValueError(f"invalid pre-state phase: {phase}")
        snapshot = esxi_aer.outer_qemu_aer_snapshot(
            self.qtest_socket,
            self.args.outer_endpoint_bdf,
            self.args.outer_root_bdf,
        )
        record: dict[str, Any] = {
            "recordKind": PRE_MUTATION_NUMERIC_SNAPSHOT_RECORD_KIND,
            "label": f"{label}-pre-state",
            "operation": operation,
            "safetyBoundary": record_boundary,
            "observedAt": None,
            "qemuPaused": self.paused,
            "snapshot": snapshot,
            "gate": None,
            "safetyFaults": [],
            "partial": True,
        }
        getattr(self, phase).append(record)
        faults = esxi_aer._partial_numeric_safety_faults(snapshot)
        record["safetyFaults"] = faults
        if faults:
            self.safety_faults.append(
                {
                    "label": f"{label}-pre",
                    "faults": faults,
                    "snapshot": snapshot,
                }
            )
            raise esxi_aer.SafetyViolation(
                f"unsafe pre-state before {label}: " + "; ".join(faults)
            )
        record["observedAt"] = utc_now()
        try:
            record["gate"] = self.check_gate(snapshot)
        except BaseException as error:
            record["parseFault"] = {
                "type": type(error).__name__,
                "message": str(error),
            }
            raise
        record["partial"] = False

    def inject(self, label: str, bit_name: str) -> None:
        if not self.paused:
            raise FixtureInvalid("Correctable injection requires paused outer QEMU")
        if bit_name not in SAFE_INJECTION_BITS:
            raise ValueError(f"unsafe injection bit: {bit_name!r}")
        mask = SAFE_INJECTION_BITS[bit_name]
        command = esxi_aer.build_injection_command(
            self.args.qemu_device,
            mask,
        )
        expected = (
            f"pcie_aer_inject_error -c {self.args.qemu_device} "
            f"0x{mask:08x}"
        )
        if command != expected:
            raise AssertionError(
                f"closed Correctable command builder drift: {command!r}"
            )
        self.record_pre_state(label, command)
        injection: dict[str, Any] = {
            "label": label,
            "bit": bit_name,
            "mask": f"0x{mask:08x}",
            "command": command,
            # HMP command dispatch is the mutation boundary.  A later ACK or
            # status-read failure cannot prove that QEMU ignored the command.
            "attempted": True,
            "mutationBoundaryCrossed": True,
            "safetyBoundary": "ATTRIBUTION_WINDOW",
            "accepted": False,
            "commandIssuedAt": utc_now(),
            "elapsedSeconds": None,
            "observedAt": None,
            "raw": None,
            "fault": None,
        }
        # If the local clock fails here, no HMP mutation has been attempted and
        # no injection record may be minted.
        started = time.monotonic()
        self.injections.append(injection)
        self.mutation_boundary_crossed = True
        try:
            raw = hmp_command(self.monitor, command)
        except BaseException as error:
            try:
                elapsed = max(0.0, time.monotonic() - started)
            except BaseException:
                elapsed = 0.0
            try:
                observed_at = utc_now()
            except BaseException:
                observed_at = injection["commandIssuedAt"]
            injection.update(
                {
                    "elapsedSeconds": elapsed,
                    "observedAt": observed_at,
                    "fault": {
                        "type": type(error).__name__,
                        "message": str(error),
                    },
                }
            )
            self.hmp_transcript.extend(
                [
                    f"### {label}: {command}",
                    (
                        "HMP dispatch/readback fault: "
                        f"{type(error).__name__}: {error}"
                    ),
                    "",
                ]
            )
            raise
        finalization_error: BaseException | None = None
        try:
            elapsed = max(0.0, time.monotonic() - started)
        except BaseException as error:
            elapsed = 0.0
            finalization_error = error
        try:
            observed_at = utc_now()
        except BaseException as error:
            observed_at = injection["commandIssuedAt"]
            if finalization_error is None:
                finalization_error = error
        accepted = exclusive_correctable_hmp_ack(
            raw,
            self.args.qemu_device,
            outer_endpoint_bdf=self.args.outer_endpoint_bdf,
            outer_root_bdf=self.args.outer_root_bdf,
        )
        if not isinstance(raw, str):
            malformed = FixtureInvalid(
                "QEMU returned a non-string Correctable injection result"
            )
            injection.update(
                {
                    "elapsedSeconds": elapsed,
                    "observedAt": observed_at,
                    "fault": {
                        "type": type(malformed).__name__,
                        "message": str(malformed),
                    },
                }
            )
            self.hmp_transcript.extend(
                [
                    f"### {label}: {command}",
                    (
                        "HMP dispatch/readback fault: "
                        f"{type(malformed).__name__}: {malformed}"
                    ),
                    "",
                ]
            )
            raise malformed
        injection.update(
            {
                "accepted": accepted,
                "elapsedSeconds": elapsed,
                "observedAt": observed_at,
                "raw": raw,
            }
        )
        self.hmp_transcript.extend(
            [f"### {label}: {command}", raw.rstrip(), ""]
        )
        if finalization_error is not None:
            raise finalization_error
        if not accepted:
            raise FixtureInvalid(
                f"QEMU did not ACK Correctable injection {label}: {raw!r}"
            )
        self.capture(
            label,
            phase="t3",
            operation=command,
        )

    def _qtest_write(self, operation: str) -> None:
        client = qemu_aer.QTestClient(self.qtest_socket)
        try:
            if operation == "clear-ces":
                qemu_sequence.clear_endpoint_ces(
                    client,
                    self.endpoint,
                    CONTROLLED_BITS,
                )
            elif operation == "clear-ced":
                qemu_sequence.clear_endpoint_ced(client, self.endpoint)
            elif operation == "clear-root":
                qemu_sequence.clear_root_correctable(client, self.root)
            else:
                raise ValueError(f"unsupported qtest operation: {operation}")
        finally:
            client.close()

    def clear(
        self,
        label: str,
        *,
        operations: tuple[str, ...],
        public_description: str,
        require_gate: bool = True,
        safety_boundary: str | None = None,
    ) -> None:
        if not self.paused:
            raise FixtureInvalid("W1C operation requires paused outer QEMU")
        record_boundary = safety_boundary or self.current_safety_boundary
        self.record_pre_state(
            label,
            public_description,
            safety_boundary=record_boundary,
            phase=(
                "t5"
                if record_boundary == "POST_CLEANUP"
                else "t2"
            ),
        )
        for operation in operations:
            self._qtest_write(operation)
        self.capture(
            label,
            phase="t5",
            operation=public_description,
            require_gate=require_gate,
            safety_boundary=safety_boundary,
        )

    def service_window(self, label: str, description: str) -> None:
        if not self.paused:
            raise FixtureInvalid("service window must start from paused QEMU")
        transition_resume: dict[str, Any] | None = None
        transition_pause: dict[str, Any] | None = None
        resume_attempted = False
        started = time.monotonic()
        timeline: list[dict[str, Any]] = []
        safety_samples: list[dict[str, Any]] = []
        maximum_observed_poll_gap = 0.0
        maximum_observed_read_duration = 0.0
        timeline_fault: BaseException | None = None
        pause_fault: BaseException | None = None
        pause_tail_fault: dict[str, Any] | None = None
        gc_guard_fault: dict[str, str] | None = None
        gc_guard: dict[str, Any] | None = None
        last_sample_finished: float | None = None
        pause_confirmed: float | None = None
        target_delays = tuple(
            float(value) for value in self.args.timeline_delays
        )
        maximum_gap = float(
            self.args.maximum_safety_poll_interval_seconds
        )
        target_period = float(
            self.args.safety_poll_target_interval_seconds
        )
        target_index = 0
        record: dict[str, Any] = {
            "label": label,
            "description": description,
            "safetyBoundary": "ATTRIBUTION_WINDOW",
            "safetyWindowKind": "SERVICE_WINDOW",
            "startedAtMonotonic": started,
            "resume": None,
            "timeline": timeline,
            "safetyPoll": {
                "maximumIntervalSeconds": maximum_gap,
                "targetIntervalSeconds": target_period,
                "targetDelaysSeconds": list(target_delays),
                "sampleCount": 0,
                "targetCount": len(target_delays),
                "completedTargetCount": 0,
                "maximumObservedGapSeconds": 0.0,
                "maximumObservedReadDurationSeconds": 0.0,
                "snapshotMode": "PINNED_TOPOLOGY_BLOCK_BATCH",
                "pauseConfirmedElapsedSeconds": None,
                "lastSampleFinishedElapsedSeconds": None,
                "tailGapSeconds": None,
                "samples": safety_samples,
            },
            "ownerObservation": None,
            "ownerObservationPolicy": (
                "pre-sequence and monitored terminal bracket only"
            ),
            "timelineFault": None,
            "pause": None,
            "pauseFault": None,
            "pauseTailFault": None,
            "pythonGcGuard": None,
            "gcGuardFault": None,
            "finalizationFault": None,
            "coverageComplete": False,
            "finishedAt": None,
        }
        # Attach the mutable window before `cont`.  Every subsequent raw read
        # is committed into this caller-owned object, so an interruption in
        # metadata or finalization cannot make a runnable interval disappear.
        self.t4.append(record)
        try:
            gc_guard = arm_runnable_gc_guard()
            record["pythonGcGuard"] = gc_guard
        except BaseException as error:
            record["gcGuardFault"] = {
                "type": type(error).__name__,
                "message": str(error),
            }
            stamp_finished_at(record)
            raise FixtureInvalid(
                f"could not arm service-window cyclic-GC guard at "
                f"{label}: {error}"
            ) from error
        # The frozen envelope begins immediately before ``cont``.  Paused
        # pre-window GC collection is deliberately outside that interval.
        started = time.monotonic()
        record["startedAtMonotonic"] = started
        try:
            # Set the attempt flag before issuing `cont`: the monitor command
            # can take effect even if its subsequent status readback fails.
            resume_attempted = True
            transition_resume = self.resume(description)
            next_poll_at = started
            prior_sample_started: float | None = None
            while target_index < len(target_delays):
                remaining = next_poll_at - time.monotonic()
                if remaining > 0:
                    time.sleep(remaining)
                sample_started = time.monotonic()
                gap = (
                    sample_started - prior_sample_started
                    if prior_sample_started is not None
                    else sample_started - started
                )
                maximum_observed_poll_gap = max(
                    maximum_observed_poll_gap,
                    gap,
                )
                if gap > maximum_gap:
                    raise FixtureInvalid(
                        "Correctable-only safety polling exceeded "
                        f"{maximum_gap:.6f}s at {label}: "
                        f"observed {gap:.6f}s"
                    )
                snapshot = esxi_aer.outer_qemu_aer_snapshot(
                    self.qtest_socket,
                    self.args.outer_endpoint_bdf,
                    self.args.outer_root_bdf,
                    topology=self.topology,
                )
                safety_sample: dict[str, Any] = {
                    "sampleIndex": len(safety_samples),
                    "actualElapsedSeconds": None,
                    "sampleStartGapSeconds": gap,
                    "sampleDurationSeconds": None,
                    "capturedAt": None,
                    "gate": None,
                    "endpoint": None,
                    "root": None,
                    "safetyFaults": [],
                    "snapshot": snapshot,
                    "partial": True,
                }
                safety_samples.append(safety_sample)
                record["safetyPoll"]["sampleCount"] = len(safety_samples)
                sample_finished = time.monotonic()
                last_sample_finished = sample_finished
                sample_duration = sample_finished - sample_started
                maximum_observed_read_duration = max(
                    maximum_observed_read_duration,
                    sample_duration,
                )
                record["safetyPoll"][
                    "maximumObservedReadDurationSeconds"
                ] = maximum_observed_read_duration
                actual_elapsed = sample_finished - started
                # Persist the raw numeric read and independently derive the
                # five-register fail-stop surface before gate/public-state
                # parsing.  A later control interruption must not erase an
                # already observed unsafe value.
                faults = esxi_aer._partial_numeric_safety_faults(snapshot)
                safety_sample.update(
                    {
                        "actualElapsedSeconds": actual_elapsed,
                        "sampleDurationSeconds": sample_duration,
                        "capturedAt": utc_now(),
                        "safetyFaults": faults,
                    }
                )
                gate = self.check_gate(snapshot)
                safety_sample.update(
                    {
                        "gate": gate,
                    "endpoint": {
                        "deviceStatus": int(
                            snapshot["endpointState"]["deviceStatus"]
                        ),
                        "uncorrectableErrorStatus": int(
                            snapshot["endpointState"][
                                "uncorrectableErrorStatus"
                            ]
                        ),
                        "correctableErrorStatus": int(
                            snapshot["endpointState"][
                                "correctableErrorStatus"
                            ]
                        ),
                    },
                    "root": {
                        "deviceStatus": int(
                            snapshot["rootState"]["deviceStatus"]
                        ),
                        "uncorrectableErrorStatus": int(
                            snapshot["rootState"][
                                "uncorrectableErrorStatus"
                            ]
                        ),
                        "rootErrorStatus": int(
                            snapshot["rootState"]["rootErrorStatus"]
                        ),
                    },
                    "partial": False,
                    }
                )
                if sample_duration > maximum_gap:
                    raise FixtureInvalid(
                        "one Correctable-only safety read exceeded "
                        f"{maximum_gap:.6f}s at {label}: "
                        f"observed {sample_duration:.6f}s"
                    )
                while (
                    target_index < len(target_delays)
                    and actual_elapsed >= target_delays[target_index]
                ):
                    target_delay = target_delays[target_index]
                    timeline.append(
                        {
                            "delaySeconds": target_delay,
                            "targetDelaySeconds": target_delay,
                            "actualElapsedSeconds": actual_elapsed,
                            "sampleIndex": safety_sample["sampleIndex"],
                            "capturedAt": safety_sample["capturedAt"],
                            "gate": copy.deepcopy(gate),
                            "safetyFaults": copy.deepcopy(faults),
                            "snapshot": copy.deepcopy(snapshot),
                        }
                    )
                    target_index += 1
                    record["safetyPoll"]["completedTargetCount"] = target_index
                if faults:
                    break
                prior_sample_started = sample_started
                next_poll_at += target_period
        except BaseException as error:
            timeline_fault = error
        finally:
            if resume_attempted:
                try:
                    # Always issue an idempotent stop after a cont attempt.
                    # Do not trust the cached paused flag after partial monitor
                    # success or a failed `info status` readback.
                    transition_pause = self.pause(
                        f"close service window {label}"
                    )
                    pause_confirmed = time.monotonic()
                except BaseException as error:
                    pause_fault = error
            if gc_guard is not None:
                gc_guard_fault = release_runnable_gc_guard(
                    gc_guard,
                    paused_confirmed=pause_confirmed is not None,
                )
        if pause_confirmed is not None and last_sample_finished is not None:
            tail_gap = pause_confirmed - last_sample_finished
            if tail_gap > maximum_gap:
                pause_tail_fault = {
                    "type": "SafetyPollTailGapExceeded",
                    "message": (
                        "last safety sample to paused ACK exceeded "
                        f"{maximum_gap:.6f}s at {label}: "
                        f"observed {tail_gap:.6f}s"
                    ),
                    "observedSeconds": tail_gap,
                    "maximumSeconds": maximum_gap,
                }
        else:
            tail_gap = None
        pause_confirmed_elapsed = (
            pause_confirmed - started
            if pause_confirmed is not None
            else None
        )
        last_sample_finished_elapsed = (
            last_sample_finished - started
            if last_sample_finished is not None
            else None
        )
        sample_faults = []
        for item in safety_samples:
            raw_faults = list(
                item.get("safetyFaults")
                or esxi_aer._partial_numeric_safety_faults(
                    item.get("snapshot")
                )
            )
            if raw_faults:
                item["safetyFaults"] = raw_faults
                sample_faults.append(
                    {
                        "delaySeconds": item.get("actualElapsedSeconds"),
                        "faults": raw_faults,
                        "snapshot": item.get("snapshot"),
                    }
                )
        record["resume"] = transition_resume
        record["timeline"] = timeline
        record["safetyPoll"].update(
            {
                "sampleCount": len(safety_samples),
                "completedTargetCount": target_index,
                "maximumObservedGapSeconds": maximum_observed_poll_gap,
                "maximumObservedReadDurationSeconds": (
                    maximum_observed_read_duration
                ),
                "pauseConfirmedElapsedSeconds": pause_confirmed_elapsed,
                "lastSampleFinishedElapsedSeconds": (
                    last_sample_finished_elapsed
                ),
                "tailGapSeconds": tail_gap,
            }
        )
        record["pause"] = transition_pause
        record["timelineFault"] = (
            {
                "type": type(timeline_fault).__name__,
                "message": str(timeline_fault),
            }
            if timeline_fault is not None
            else None
        )
        record["pauseFault"] = (
            {
                "type": type(pause_fault).__name__,
                "message": str(pause_fault),
            }
            if pause_fault is not None
            else None
        )
        record["pauseTailFault"] = pause_tail_fault
        record["gcGuardFault"] = gc_guard_fault
        finalization_fault = stamp_finished_at(record)
        if (
            timeline_fault is not None
            or pause_fault is not None
            or pause_tail_fault is not None
            or gc_guard_fault is not None
            or finalization_fault is not None
        ):
            record["coverageComplete"] = False
            if sample_faults:
                self.safety_faults.extend(
                    {
                        "label": f"{label}@{item['delaySeconds']}",
                        "faults": item["faults"],
                        "snapshot": item["snapshot"],
                    }
                    for item in sample_faults
                )
                raise esxi_aer.SafetyViolation(
                    "unsafe state appeared before the service window could "
                    f"be cleanly closed at {label}"
                )
            failure = pause_fault or timeline_fault
            if failure is None and gc_guard_fault is not None:
                failure = FixtureInvalid(
                    f"cyclic-GC guard release failed: {gc_guard_fault}"
                )
            if failure is None and finalization_fault is not None:
                failure = FixtureInvalid(
                    f"service-window finalization failed: "
                    f"{finalization_fault}"
                )
            if failure is None:
                failure = FixtureInvalid(
                    str(pause_tail_fault["message"])
                )
            raise FixtureInvalid(
                f"service-window sampler failed at {label}: "
                f"{type(failure).__name__}: {failure}"
            ) from failure
        # Close the runnable window before any SSH/API round trip.  Owner
        # continuity is proved by the pre-sequence and monitored terminal
        # observations; keeping ESXi running here after a safety/gate sample
        # would violate the fail-stop boundary.
        record["coverageComplete"] = bool(
            safety_samples
            and target_index == len(target_delays)
            and transition_pause is not None
        )
        if sample_faults:
            self.safety_faults.extend(
                {
                    "label": f"{label}@{item['delaySeconds']}",
                    "faults": item["faults"],
                    "snapshot": item["snapshot"],
                }
                for item in sample_faults
            )
            raise esxi_aer.SafetyViolation(
                f"unsafe state appeared in service window {label}"
            )
        if not self.gate_stable:
            raise FixtureInvalid(
                f"effective gate/root path drifted in service window {label}"
            )
        self.capture(
            label,
            phase="t4",
            operation=f"post-resume window: {description}",
        )

    def monitored_runnable(
        self,
        *,
        label: str,
        description: str,
        worker: Callable[[threading.Event], Any],
        poll_interval_seconds: float | None = None,
        enforce_gate: bool = True,
    ) -> tuple[Any, dict[str, Any]]:
        """Run blocking ESXi work while continuously enforcing fail-stop."""

        if not self.paused:
            raise FixtureInvalid(
                "a monitored runnable window must start from paused QEMU"
            )
        cancel = new_cancel_event()
        started = time.monotonic()
        maximum_poll_interval = float(
            self.args.maximum_safety_poll_interval_seconds
        )
        target_poll_interval = float(
            poll_interval_seconds
            if poll_interval_seconds is not None
            else self.args.safety_poll_target_interval_seconds
        )
        if (
            target_poll_interval <= 0
            or target_poll_interval > maximum_poll_interval
        ):
            raise FixtureInvalid(
                "monitored runnable poll target is outside the immutable "
                "safety envelope"
            )
        compact_samples: list[dict[str, Any]] = []
        first_snapshot: dict[str, Any] | None = None
        last_snapshot: dict[str, Any] | None = None
        safety_events: list[dict[str, Any]] = []
        monitor_fault: dict[str, str] | None = None
        immediate_stop_fault: dict[str, str] | None = None
        final_stop_fault: dict[str, str] | None = None
        executor_shutdown_fault: dict[str, str] | None = None
        cancel_fault: dict[str, str] | None = None
        gc_guard_fault: dict[str, str] | None = None
        gc_guard: dict[str, Any] | None = None
        control_fault: BaseException | None = None
        gate_fault = False
        transition_resume: dict[str, Any] | None = None
        transition_pause: dict[str, Any] | None = None
        worker_fault: BaseException | None = None
        worker_result: Any = None
        prior_sample_started: float | None = None
        last_sample_finished: float | None = None
        final_stop_confirmed: float | None = None
        maximum_observed_poll_gap = 0.0
        maximum_observed_read_duration = 0.0
        next_poll_at = started
        record: dict[str, Any] = {
            "label": label,
            "description": description,
            "safetyBoundary": self.current_safety_boundary,
            "safetyWindowKind": "MONITORED_WORKER",
            "enforceGate": enforce_gate,
            "startedAtMonotonic": started,
            "resume": None,
            "maximumPollIntervalSeconds": maximum_poll_interval,
            "pollIntervalSeconds": target_poll_interval,
            "sampleCount": 0,
            "maximumObservedPollGapSeconds": 0.0,
            "maximumObservedReadDurationSeconds": 0.0,
            "snapshotMode": "PINNED_TOPOLOGY_BLOCK_BATCH",
            "finalStopConfirmedElapsedSeconds": None,
            "lastSampleFinishedElapsedSeconds": None,
            "tailGapSeconds": None,
            "samples": compact_samples,
            "firstSnapshot": None,
            "lastSnapshot": None,
            "safetyEvents": safety_events,
            "monitorFault": None,
            "immediateStopFault": None,
            "finalStopFault": None,
            "executorShutdownFault": None,
            "cancelFault": None,
            "pythonGcGuard": None,
            "gcGuardFault": None,
            "controlFault": None,
            "tailGapFault": None,
            "finalizationFault": None,
            "gateFault": False,
            "workerFault": None,
            "pause": None,
            "coverageComplete": False,
            "finishedAt": None,
        }
        self.t4.append(record)

        def sample_once() -> None:
            nonlocal first_snapshot, last_snapshot, gate_fault
            nonlocal prior_sample_started, maximum_observed_poll_gap
            nonlocal maximum_observed_read_duration
            nonlocal next_poll_at
            nonlocal last_sample_finished
            sample_started = time.monotonic()
            gap = (
                sample_started - prior_sample_started
                if prior_sample_started is not None
                else sample_started - started
            )
            maximum_observed_poll_gap = max(
                maximum_observed_poll_gap,
                gap,
            )
            compact_sample: dict[str, Any] = {
                "sampleIndex": len(compact_samples),
                "delaySeconds": None,
                "actualElapsedSeconds": sample_started - started,
                "sampleStartGapSeconds": gap,
                "sampleDurationSeconds": 0.0,
                "observedAt": None,
                "gate": None,
                "endpoint": None,
                "root": None,
                "safetyFaults": [],
                "snapshot": None,
                "readFault": None,
                "partial": True,
            }
            # Persist the scheduling attempt before enforcing its deadline.
            # Otherwise the declared maximum can contain an overrun that the
            # manifest-bound raw sample list cannot independently recompute.
            compact_samples.append(compact_sample)
            record["sampleCount"] = len(compact_samples)
            prior_sample_started = sample_started
            next_poll_at = sample_started + target_poll_interval
            if gap > maximum_poll_interval:
                last_sample_finished = sample_started
                raise FixtureInvalid(
                    "Correctable-only safety polling exceeded "
                    f"{maximum_poll_interval:.6f}s in {label}: "
                    f"observed {gap:.6f}s"
                )
            try:
                snapshot = esxi_aer.outer_qemu_aer_snapshot(
                    self.qtest_socket,
                    self.args.outer_endpoint_bdf,
                    self.args.outer_root_bdf,
                    topology=self.topology,
                )
            except BaseException as error:
                sample_finished = time.monotonic()
                last_sample_finished = sample_finished
                sample_duration = sample_finished - sample_started
                maximum_observed_read_duration = max(
                    maximum_observed_read_duration,
                    sample_duration,
                )
                record["maximumObservedReadDurationSeconds"] = (
                    maximum_observed_read_duration
                )
                compact_sample.update(
                    {
                        "actualElapsedSeconds": sample_finished - started,
                        "sampleDurationSeconds": sample_duration,
                        "readFault": {
                            "type": type(error).__name__,
                            "message": str(error),
                        },
                    }
                )
                raise
            sample_finished = time.monotonic()
            last_sample_finished = sample_finished
            sample_duration = sample_finished - sample_started
            maximum_observed_read_duration = max(
                maximum_observed_read_duration,
                sample_duration,
            )
            record["maximumObservedReadDurationSeconds"] = (
                maximum_observed_read_duration
            )
            compact_sample["snapshot"] = snapshot
            if first_snapshot is None:
                first_snapshot = copy.deepcopy(snapshot)
            last_snapshot = copy.deepcopy(snapshot)
            # Commit the raw five-register safety surface before any gate
            # projection.  ``check_gate`` can fail after the QTest read, but
            # that cannot make the read disappear from the persisted window.
            faults = esxi_aer._partial_numeric_safety_faults(snapshot)
            compact_sample.update(
                {
                    "delaySeconds": sample_finished - started,
                    "actualElapsedSeconds": sample_finished - started,
                    "sampleDurationSeconds": sample_duration,
                    "safetyFaults": faults,
                }
            )
            compact_sample["observedAt"] = utc_now()
            if faults:
                safety_events.append(
                    {
                        "label": label,
                        "faults": faults,
                        "snapshot": copy.deepcopy(snapshot),
                    }
                )
            if enforce_gate:
                gate = self.check_gate(snapshot)
            else:
                gate = {
                    "requested": None,
                    "effective": esxi_aer.gate_tuple_from_snapshot(
                        snapshot,
                        CONTROLLED_BITS,
                    ).as_dict(),
                    "rootPath": esxi_aer.root_path_from_snapshot(
                        snapshot
                    ).as_dict(),
                    "correctableMask": int(
                        snapshot["endpointState"]["correctableErrorMask"]
                    ),
                    "checks": {
                        "not-enforced-during-pre-sequence-owner-activation": (
                            True
                        ),
                    },
                }
            compact_sample.update(
                {
                    "gate": gate,
                    "endpoint": {
                        "deviceStatus": int(
                            snapshot["endpointState"]["deviceStatus"]
                        ),
                        "uncorrectableErrorStatus": int(
                            snapshot["endpointState"][
                                "uncorrectableErrorStatus"
                            ]
                        ),
                        "correctableErrorStatus": int(
                            snapshot["endpointState"][
                                "correctableErrorStatus"
                            ]
                        ),
                    },
                    "root": {
                        "deviceStatus": int(
                            snapshot["rootState"]["deviceStatus"]
                        ),
                        "uncorrectableErrorStatus": int(
                            snapshot["rootState"][
                                "uncorrectableErrorStatus"
                            ]
                        ),
                        "rootErrorStatus": int(
                            snapshot["rootState"]["rootErrorStatus"]
                        ),
                    },
                    "partial": False,
                }
            )
            if sample_duration > maximum_poll_interval:
                raise FixtureInvalid(
                    "one Correctable-only safety read exceeded "
                    f"{maximum_poll_interval:.6f}s in {label}: "
                    f"observed {sample_duration:.6f}s"
                )
            if enforce_gate and not all(gate["checks"].values()):
                gate_fault = True

        try:
            gc_guard = arm_runnable_gc_guard()
            record["pythonGcGuard"] = gc_guard
        except BaseException as error:
            record["gcGuardFault"] = {
                "type": type(error).__name__,
                "message": str(error),
            }
            stamp_finished_at(record)
            raise FixtureInvalid(
                f"could not arm runnable cyclic-GC guard in {label}: {error}"
            ) from error

        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="esxi-aer-monitored",
        )
        # Bind the first gap to the actual runnable transition, excluding all
        # paused setup (GC collection, evidence allocation and executor init).
        started = time.monotonic()
        record["startedAtMonotonic"] = started
        next_poll_at = started
        future: concurrent.futures.Future[Any] | None = None
        stop_future: concurrent.futures.Future[Any] | None = None
        resume_attempted = False
        try:
            # A failed transition readback does not prove `cont` was inert.
            resume_attempted = True
            try:
                transition_resume = self.resume(description)
            except BaseException as error:
                monitor_fault = {
                    "type": type(error).__name__,
                    "message": (
                        "could not confirm monitored-window resume: "
                        f"{error}"
                    ),
                }
            if monitor_fault is None:
                try:
                    sample_once()
                except BaseException as error:
                    monitor_fault = {
                        "type": type(error).__name__,
                        "message": str(error),
                    }
            if not safety_events and not gate_fault and monitor_fault is None:
                future = executor.submit(worker, cancel)
            while future is not None and not future.done():
                try:
                    sample_once()
                except BaseException as error:
                    monitor_fault = {
                        "type": type(error).__name__,
                        "message": str(error),
                    }
                if safety_events or gate_fault or monitor_fault is not None:
                    cancel.set()
                    if not self.paused:
                        try:
                            transition_pause = self.pause(
                                f"fail-stop monitored window {label}"
                            )
                        except BaseException as error:
                            immediate_stop_fault = {
                                "type": type(error).__name__,
                                "message": (
                                    "could not confirm immediate monitored "
                                    f"fail-stop: {error}"
                                ),
                            }
                    break
                remaining = next_poll_at - time.monotonic()
                if remaining > 0:
                    cancel.wait(remaining)
            if (
                future is not None
                and future.done()
                and not safety_events
                and not gate_fault
                and monitor_fault is None
            ):
                try:
                    worker_result = future.result()
                except BaseException as error:  # retain exact worker failure
                    worker_fault = error
                try:
                    sample_once()
                except BaseException as error:
                    monitor_fault = {
                        "type": type(error).__name__,
                        "message": str(error),
                    }
        except BaseException as error:
            control_fault = error
        finally:
            try:
                cancel.set()
            except BaseException as error:
                cancel_fault = {
                    "type": type(error).__name__,
                    "message": str(error),
                }
            covered_final_stop = bool(
                resume_attempted
                and future is not None
                and future.done()
                and monitor_fault is None
                and not safety_events
                and not gate_fault
                and immediate_stop_fault is None
            )
            if covered_final_stop:
                try:
                    # Keep sampling while the HMP stop/readback transaction is
                    # in flight.  A synchronous stop can legitimately take
                    # longer than one 50 ms poll interval; that latency must
                    # not create an unobserved runnable tail.
                    stop_future = executor.submit(
                        self.pause,
                        f"close monitored window {label}",
                    )
                    while not stop_future.done():
                        try:
                            sample_once()
                        except BaseException as error:
                            monitor_fault = {
                                "type": type(error).__name__,
                                "message": str(error),
                            }
                            break
                        remaining = next_poll_at - time.monotonic()
                        if remaining > 0:
                            time.sleep(remaining)
                    transition_pause = stop_future.result()
                    final_stop_confirmed = time.monotonic()
                except BaseException as error:
                    final_stop_fault = {
                        "type": type(error).__name__,
                        "message": (
                            "could not confirm outer QEMU fail-stop: "
                            f"{error}"
                        ),
                    }
            elif resume_attempted:
                try:
                    # On an already-failed monitor path, prioritize immediate
                    # fail-stop and repeat the stop idempotently even when an
                    # earlier best-effort stop appeared to succeed.
                    transition_pause = self.pause(
                        f"close monitored window {label}"
                    )
                    final_stop_confirmed = time.monotonic()
                except BaseException as error:
                    final_stop_fault = {
                        "type": type(error).__name__,
                        "message": (
                            "could not confirm outer QEMU fail-stop: "
                            f"{error}"
                        ),
                    }
            if future is not None and not future.done():
                try:
                    worker_result = future.result()
                except BaseException as error:
                    worker_fault = worker_fault or error
            try:
                executor.shutdown(wait=True, cancel_futures=True)
            except BaseException as error:
                executor_shutdown_fault = {
                    "type": type(error).__name__,
                    "message": str(error),
                }
            if gc_guard is not None:
                gc_guard_fault = release_runnable_gc_guard(
                    gc_guard,
                    paused_confirmed=final_stop_confirmed is not None,
                )

        tail_gap = (
            final_stop_confirmed - last_sample_finished
            if (
                final_stop_confirmed is not None
                and last_sample_finished is not None
            )
            else None
        )
        tail_gap_fault = bool(
            tail_gap is not None
            and tail_gap > maximum_poll_interval
        )
        final_stop_confirmed_elapsed = (
            final_stop_confirmed - started
            if final_stop_confirmed is not None
            else None
        )
        last_sample_finished_elapsed = (
            last_sample_finished - started
            if last_sample_finished is not None
            else None
        )
        # Rebuild safety events from the caller-owned raw samples.  Metadata,
        # timestamp or gate projection may have failed after the QTest read but
        # before the fast path appended an event.
        safety_events.clear()
        for item in compact_samples:
            raw_faults = list(
                item.get("safetyFaults")
                or esxi_aer._partial_numeric_safety_faults(
                    item.get("snapshot")
                )
            )
            if raw_faults:
                item["safetyFaults"] = raw_faults
                safety_events.append(
                    {
                        "label": label,
                        "sampleIndex": item.get("sampleIndex"),
                        "actualElapsedSeconds": item.get(
                            "actualElapsedSeconds"
                        ),
                        "faults": raw_faults,
                        "snapshot": item.get("snapshot"),
                    }
                )

        record.update(
            {
                "resume": transition_resume,
                "sampleCount": len(compact_samples),
                "maximumObservedPollGapSeconds": maximum_observed_poll_gap,
                "maximumObservedReadDurationSeconds": (
                    maximum_observed_read_duration
                ),
                "finalStopConfirmedElapsedSeconds": (
                    final_stop_confirmed_elapsed
                ),
                "lastSampleFinishedElapsedSeconds": (
                    last_sample_finished_elapsed
                ),
                "tailGapSeconds": tail_gap,
                "firstSnapshot": first_snapshot,
                "lastSnapshot": last_snapshot,
                "monitorFault": monitor_fault,
                "immediateStopFault": immediate_stop_fault,
                "finalStopFault": final_stop_fault,
                "executorShutdownFault": executor_shutdown_fault,
                "cancelFault": cancel_fault,
                "gcGuardFault": gc_guard_fault,
                "controlFault": (
                    {
                        "type": type(control_fault).__name__,
                        "message": str(control_fault),
                    }
                    if control_fault is not None
                    else None
                ),
                "tailGapFault": (
                    {
                        "type": "SafetyPollTailGapExceeded",
                        "observedSeconds": tail_gap,
                        "maximumSeconds": maximum_poll_interval,
                    }
                    if tail_gap_fault
                    else None
                ),
                "gateFault": gate_fault,
                "workerFault": (
                    {
                        "type": type(worker_fault).__name__,
                        "message": str(worker_fault),
                    }
                    if worker_fault is not None
                    else None
                ),
                "pause": transition_pause,
                "coverageComplete": bool(
                    compact_samples
                    and monitor_fault is None
                    and immediate_stop_fault is None
                    and final_stop_fault is None
                    and executor_shutdown_fault is None
                    and cancel_fault is None
                    and gc_guard_fault is None
                    and control_fault is None
                    and not tail_gap_fault
                    and transition_pause is not None
                ),
            }
        )
        finalization_fault = stamp_finished_at(record)
        if finalization_fault is not None:
            record["coverageComplete"] = False
        if safety_events:
            self.safety_faults.extend(copy.deepcopy(safety_events))
            raise esxi_aer.SafetyViolation(
                f"unsafe state appeared in monitored window {label}"
            )
        coverage_faults = [
            item
            for item in (
                monitor_fault,
                immediate_stop_fault,
                final_stop_fault,
                executor_shutdown_fault,
                cancel_fault,
                gc_guard_fault,
                record["controlFault"],
                record["tailGapFault"],
                finalization_fault,
            )
            if item is not None
        ]
        if coverage_faults:
            raise FixtureInvalid(
                f"safety monitor/fail-stop failed in {label}: "
                f"{coverage_faults}"
            )
        if gate_fault:
            raise FixtureInvalid(
                f"effective gate/root path drifted in monitored window {label}"
            )
        if worker_fault is not None:
            raise worker_fault
        return worker_result, record


def _complete_resume_safety_stabilization(
    *,
    record: dict[str, Any],
    safety_poll: dict[str, Any],
    monitor: Path,
    expected_gate: esxi_aer.GateTuple | None,
    expected_root_path: esxi_aer.RootPathState | None,
) -> None:
    """Analyze the final runnable tail inside its caller's fail-stop guard."""

    for sample in safety_poll["samples"]:
        snapshot = sample["snapshot"]
        faults: list[str] = []
        try:
            if (
                expected_gate is not None
                and esxi_aer.gate_tuple_from_snapshot(
                    snapshot,
                    CONTROLLED_BITS,
                )
                != expected_gate
            ):
                faults.append(
                    "restored endpoint/root Correctable gate drifted"
                )
            if (
                expected_root_path is not None
                and esxi_aer.root_path_from_snapshot(snapshot)
                != expected_root_path
            ):
                faults.append("restored auxiliary Root Port path drifted")
        except Exception as error:
            faults.append(
                "restored gate analysis failed: "
                f"{type(error).__name__}: {error}"
            )
        if faults:
            record["gateFaults"].append(
                {
                    "sampleIndex": sample["sampleIndex"],
                    "actualElapsedSeconds": sample[
                        "actualElapsedSeconds"
                    ],
                    "faults": faults,
                    "snapshot": copy.deepcopy(snapshot),
                }
            )

    safety_events = list(safety_poll.get("safetyEvents") or [])
    poll_faults = list(safety_poll.get("pollFaults") or [])
    if safety_events or poll_faults or record["gateFaults"]:
        try:
            record["failStop"] = esxi_aer.transition_qemu(
                monitor,
                "stop",
                "paused",
            )
            if safety_events:
                record["outcome"] = "SAFETY_FAULT_HELD_PAUSED"
            elif poll_faults:
                record["outcome"] = "SAFETY_POLL_INCOMPLETE_HELD_PAUSED"
            else:
                record["outcome"] = "RESTORED_GATE_DRIFT_HELD_PAUSED"
        except BaseException as hold_error:
            record["failStopFault"] = {
                "type": type(hold_error).__name__,
                "message": str(hold_error),
            }
            record["outcome"] = "TAIL_FAULT_AND_FAIL_STOP_UNCONFIRMED"
    elif safety_poll.get("complete") is not True:
        try:
            record["failStop"] = esxi_aer.transition_qemu(
                monitor,
                "stop",
                "paused",
            )
            record["outcome"] = "TAIL_INCOMPLETE_HELD_PAUSED"
        except BaseException as hold_error:
            record["failStopFault"] = {
                "type": type(hold_error).__name__,
                "message": str(hold_error),
            }
            record["outcome"] = "TAIL_INCOMPLETE_AND_FAIL_STOP_UNCONFIRMED"
    else:
        record["outcome"] = "CLEAN_RUNNING"


def resume_with_safety_stabilization(
    *,
    args: argparse.Namespace,
    monitor: Path,
    qtest_socket: Path,
    label: str,
    expected_gate: esxi_aer.GateTuple | None,
    expected_root_path: esxi_aer.RootPathState | None,
    topology: dict[str, Any],
) -> dict[str, Any]:
    """Resume the outer QEMU through a measured final safety tail window."""

    if not isinstance(topology, dict) or not topology:
        raise esxi_aer.BlockedEnvironment(
            "final running safety tail requires a non-empty topology "
            "captured while outer QEMU is paused"
        )
    record: dict[str, Any] = {
        "label": label,
        "safetyBoundary": "POST_CLEANUP",
        "safetyWindowKind": "FINAL_RUNNING_STABILIZATION",
        "startedAt": utc_now(),
        "outcome": "RESUMING",
        "resume": None,
        "safetyPoll": None,
        "gateFaults": [],
    }
    started = time.monotonic()
    try:
        record["resume"] = esxi_aer.transition_qemu(
            monitor,
            "cont",
            "running",
        )
    except BaseException as error:
        record["resumeFault"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        try:
            record["failStop"] = esxi_aer.transition_qemu(
                monitor,
                "stop",
                "paused",
            )
            record["outcome"] = "RESUME_FAILED_HELD_PAUSED"
        except BaseException as hold_error:
            record["failStopFault"] = {
                "type": type(hold_error).__name__,
                "message": str(hold_error),
            }
            record["outcome"] = "RESUME_AND_FAIL_STOP_UNCONFIRMED"
        stamp_finished_at(record)
        return record

    try:
        safety_poll: dict[str, Any] = {}
        record["safetyPoll"] = safety_poll
        safety_poll = esxi_aer.sample_gate_timeline_continuous(
            qtest_socket,
            args.outer_endpoint_bdf,
            args.outer_root_bdf,
            CONTROLLED_BITS,
            args.timeline_delays,
            started_at=started,
            maximum_poll_interval=(
                args.maximum_safety_poll_interval_seconds
            ),
            target_poll_interval=(
                args.safety_poll_target_interval_seconds
            ),
            safety_boundary="POST_CLEANUP",
            topology=topology,
            _partial_record=safety_poll,
        )
    except BaseException as error:
        record["samplerFault"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        try:
            record["failStop"] = esxi_aer.transition_qemu(
                monitor,
                "stop",
                "paused",
            )
            record["outcome"] = "SAMPLER_FAILED_HELD_PAUSED"
        except BaseException as hold_error:
            record["failStopFault"] = {
                "type": type(hold_error).__name__,
                "message": str(hold_error),
            }
            record["outcome"] = "SAMPLER_AND_FAIL_STOP_UNCONFIRMED"
        stamp_finished_at(record)
        return record
    record["safetyPoll"] = safety_poll
    try:
        _complete_resume_safety_stabilization(
            record=record,
            safety_poll=safety_poll,
            monitor=monitor,
            expected_gate=expected_gate,
            expected_root_path=expected_root_path,
        )
    except BaseException as error:
        record["postSamplerAnalysisFault"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        try:
            record["failStop"] = esxi_aer.transition_qemu(
                monitor,
                "stop",
                "paused",
            )
            record["outcome"] = "TAIL_ANALYSIS_FAILED_HELD_PAUSED"
        except BaseException as hold_error:
            record["failStopFault"] = {
                "type": type(hold_error).__name__,
                "message": str(hold_error),
            }
            record["outcome"] = (
                "TAIL_ANALYSIS_AND_FAIL_STOP_UNCONFIRMED"
            )
    stamp_finished_at(record)
    return record


def capture_paused_final_tail_inputs(
    *,
    args: argparse.Namespace,
    qtest_socket: Path,
    lease: dict[str, Any] | None,
    cleanup_topology: dict[str, Any] | None,
) -> dict[str, Any]:
    """Refresh the final-tail read plan while outer QEMU is still paused.

    The cleanup snapshot is preferred only as an immutable topology seed.
    A gate restore oracle, when one exists, remains the lease's original
    snapshot so a bad restore cannot authorize its own current state.
    """

    restore_snapshot = (
        lease["original"]["snapshot"]
        if lease is not None
        else None
    )
    if cleanup_topology is not None:
        topology_seed = cleanup_topology
        topology_seed_mode = "ACTIVE_VM_CLEANUP"
    elif restore_snapshot is not None:
        topology_seed = restore_snapshot
        topology_seed_mode = "LEASE_ORIGINAL"
    else:
        topology_seed = None
        topology_seed_mode = "PAUSED_FULL_DISCOVERY"
    topology = esxi_aer.outer_qemu_aer_snapshot(
        qtest_socket,
        args.outer_endpoint_bdf,
        args.outer_root_bdf,
        topology=topology_seed,
    )
    safety_faults = esxi_aer._partial_numeric_safety_faults(topology)
    return {
        "baseline": {
            "safetyBoundary": "POST_CLEANUP",
            "captureSnapshotMode": (
                "FULL_DISCOVERY"
                if topology_seed is None
                else "PINNED_TOPOLOGY_BLOCK_BATCH"
            ),
            "runnableSnapshotMode": "PINNED_TOPOLOGY_BLOCK_BATCH",
            "topologySeedMode": topology_seed_mode,
            "snapshot": topology,
            "safetyFaults": safety_faults,
            "partial": False,
        },
        "topology": topology,
        "expectedGate": (
            esxi_aer.gate_tuple_from_snapshot(
                restore_snapshot,
                CONTROLLED_BITS,
            )
            if restore_snapshot is not None
            else None
        ),
        "expectedRootPath": (
            esxi_aer.root_path_from_snapshot(restore_snapshot)
            if restore_snapshot is not None
            else None
        ),
    }


def execute_sequence_until_terminal(
    sequence: str,
    recorder: LiveSequenceRecorder,
) -> str:
    if sequence == "first-multiple":
        recorder.inject("first-b0", B0_NAME)
        recorder.service_window(
            "first-window-observation",
            "bounded ESXi observation after first B0",
        )
        recorder.inject("repeated-b0", B0_NAME)
        recorder.service_window(
            "stable-after-repeat",
            "bounded ESXi observation after repeated B0",
        )
        return "stable-after-repeat"
    if sequence == "independent-w1c":
        recorder.inject("initial-b0", B0_NAME)
        recorder.service_window(
            "initial-window",
            "bounded ESXi observation after initial B0",
        )
        recorder.clear(
            "after-endpoint-clear-only-immediate",
            operations=("clear-ces", "clear-ced"),
            public_description="W1C Endpoint CES.B0/B1 and Device Status.CED only",
        )
        recorder.service_window(
            "after-endpoint-clear-only",
            "bounded ESXi observation after Endpoint-only W1C",
        )
        recorder.clear(
            "after-root-cleanup-for-rebuild",
            operations=("clear-root",),
            public_description="W1C Root Correctable Status for clean rebuild",
        )
        recorder.inject("rebuilt-b0", B0_NAME)
        recorder.clear(
            "after-root-clear-only-immediate",
            operations=("clear-root",),
            public_description="W1C Root Correctable Status only",
        )
        recorder.service_window(
            "after-root-clear-only",
            "bounded ESXi observation after Root-only W1C",
        )
        return "after-root-clear-only"
    if sequence == "bit-or":
        recorder.inject("first-b0", B0_NAME)
        recorder.inject("second-b1", B1_NAME)
        recorder.service_window(
            "stable-after-or",
            "bounded ESXi observation after paused B0 then B1 OR",
        )
        return "stable-after-or"
    if sequence == "rearm":
        recorder.inject("initial-b0", B0_NAME)
        recorder.service_window(
            "initial-window",
            "bounded ESXi observation after initial B0",
        )
        recorder.clear(
            "after-ces-clear-only",
            operations=("clear-ces",),
            public_description="W1C Endpoint CES.B0/B1 only",
        )
        recorder.clear(
            "after-ced-clear-only",
            operations=("clear-ced",),
            public_description="W1C Endpoint Device Status.CED only",
        )
        recorder.clear(
            "after-root-clear",
            operations=("clear-root",),
            public_description="W1C Root Correctable Status only",
        )
        recorder.inject("rearmed-b0", B0_NAME)
        recorder.service_window(
            "rearmed-window",
            "bounded ESXi observation after re-armed B0",
        )
        return "rearmed-window"
    raise ValueError(f"unknown sequence: {sequence}")


def pcie_capability_snapshot(
    values: dict[int, int] | None,
) -> dict[str, Any] | None:
    """Parse the public PCIe capability Device Control/Status pair."""

    if values is None:
        return None
    pointer = values.get(0x34)
    if pointer is None:
        return None
    offset = int(pointer) & 0xFC
    visited: set[int] = set()
    for _ in range(48):
        if (
            offset in visited
            or offset < 0x40
            or offset > 0xFC
            or offset % 4
        ):
            return None
        visited.add(offset)
        capability_id = values.get(offset)
        next_pointer = values.get(offset + 1)
        if capability_id is None or next_pointer is None:
            return None
        if int(capability_id) == 0x10:
            device_control = esxi_aer.read_le(values, offset + 0x08, 2)
            device_status = esxi_aer.read_le(values, offset + 0x0A, 2)
            if device_control is None or device_status is None:
                return None
            return {
                "offset": offset,
                "deviceControl": device_control,
                "deviceStatus": device_status,
            }
        offset = int(next_pointer) & 0xFC
        if offset == 0:
            return None
    return None


def merge_host_projection_surface(
    aer: Any,
    pcie: Any,
    *,
    bridge_control: Any = None,
) -> dict[str, Any] | None:
    if not isinstance(aer, dict) or not isinstance(pcie, dict):
        return None
    merged = copy.deepcopy(aer)
    merged["deviceControl"] = pcie.get("deviceControl")
    merged["deviceStatus"] = pcie.get("deviceStatus")
    if bridge_control is not None:
        merged["bridgeControl"] = bridge_control
    return merged


def phase_projection(phase: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(phase, dict):
        return None
    return {
        "hostEndpoint": merge_host_projection_surface(
            phase.get("aer"),
            phase.get("endpointPcie"),
        ),
        "hostRoot": merge_host_projection_surface(
            phase.get("rootAer"),
            phase.get("rootPcie"),
            bridge_control=phase.get("rootBridgeControl"),
        ),
        "outerBeforeRemote": phase.get("outerQemuAer"),
        "outerAfterRemote": phase.get("outerQemuAerPostRemote"),
        "outerSamples": phase.get("outerQemuAerSamples"),
        "capturedAt": {
            "startedAt": phase.get("startedAt"),
            "outerBefore": phase.get("outerQemuAerCapturedAt"),
            "finishedAt": phase.get("finishedAt"),
        },
    }


def collect_remote_phase_cancellable(
    *,
    case_dir: Path,
    phase: str,
    ssh: EsxiSsh,
    api: esxi_aer.ApiSession,
    bdf: str,
    root_bdf: str,
    log_lines: int,
    cancel: threading.Event,
) -> dict[str, Any]:
    """Collect ESXi-only surfaces; the caller owns continuous QTest polling."""

    phase_dir = case_dir / phase
    phase_dir.mkdir(parents=True, exist_ok=False)
    record: dict[str, Any] = {
        "phase": phase,
        "startedAt": utc_now(),
        "commands": {},
        "outerQemuCollection": (
            "owned by the caller's continuously monitored time bracket"
        ),
    }
    try:
        for filename, template in esxi_aer.COLLECTOR_COMMANDS:
            if cancel.is_set():
                record["cancelledBySafetyMonitor"] = True
                break
            command = template.format(log_lines=log_lines)
            record["commands"][filename] = esxi_aer.run_remote_capture(
                ssh,
                command,
                phase_dir / filename,
                timeout=45,
            )
        if cancel.is_set():
            record["cancelledBySafetyMonitor"] = True
            return record

        pci_path = phase_dir / "pci.txt"
        lspci_path = phase_dir / "lspci-ext.txt"
        if not pci_path.is_file() or not lspci_path.is_file():
            raise esxi_aer.InconclusiveObservation(
                "terminal ESXi PCI captures are incomplete"
            )
        pci_text = pci_path.read_text(encoding="utf-8", errors="replace")
        lspci_text = lspci_path.read_text(
            encoding="utf-8",
            errors="replace",
        )
        target = esxi_aer.extract_esxcli_device(pci_text, bdf)
        config = esxi_aer.extract_lspci_bytes(lspci_text, bdf)
        root_config = esxi_aer.extract_lspci_bytes(lspci_text, root_bdf)
        record["target"] = target
        record["aer"] = esxi_aer.aer_snapshot(config)
        record["rootAer"] = esxi_aer.aer_snapshot(root_config)
        record["endpointPcie"] = pcie_capability_snapshot(config)
        record["rootPcie"] = pcie_capability_snapshot(root_config)
        record["rootBridgeControl"] = (
            esxi_aer.read_le(root_config, 0x3E, 2)
            if root_config is not None
            else None
        )
        if cancel.is_set():
            record["cancelledBySafetyMonitor"] = True
            return record
        record["activePassthroughUsers"] = api.active_passthrough_users(bdf)
        return record
    finally:
        record["finishedAt"] = utc_now()
        save_json(phase_dir / "phase.json", record)


def owner_observation_from_phase(
    *,
    phase: dict[str, Any],
    active_vm: esxi_aer.ActiveVm | None,
    label: str,
) -> dict[str, Any]:
    target = phase.get("target")
    users = phase.get("activePassthroughUsers")
    users = users if isinstance(users, list) else []
    runner_vm_name = active_vm.vm_name if active_vm is not None else None
    normalized_users: list[dict[str, Any]] = []
    for raw in users:
        if not isinstance(raw, dict):
            normalized_users.append({"invalidRawUser": repr(raw)})
            continue
        item = dict(raw)
        item["runnerCreated"] = bool(
            runner_vm_name and item.get("vm") == runner_vm_name
        )
        normalized_users.append(item)
    uptime = phase.get("commands", {}).get("uptime.txt")
    return {
        "label": label,
        "observedAt": phase.get("finishedAt") or utc_now(),
        "currentOwner": (
            target.get("Current Owner") if isinstance(target, dict) else None
        ),
        "target": target,
        "activeUsers": normalized_users,
        "hostResponsive": bool(
            isinstance(uptime, dict) and uptime.get("returnCode") == 0
        ),
        "heartbeatSource": "monitored terminal uptime command",
    }


def validate_environment_binding(
    *,
    args: argparse.Namespace,
    environment: dict[str, Any],
    target: dict[str, str] | None,
    source_hashes: dict[str, Any],
    oracle_profile: dict[str, Any],
) -> list[str]:
    faults: list[str] = []
    esxi = environment["esxi"]
    if str(esxi.get("build")) != str(args.expected_esxi_build):
        faults.append(
            f"ESXi build={esxi.get('build')!r}, "
            f"expected={args.expected_esxi_build!r}"
        )
    if str(esxi.get("systemUuid", "")).lower() != (
        args.expected_system_uuid.lower()
    ):
        faults.append(
            f"system UUID={esxi.get('systemUuid')!r}, "
            f"expected={args.expected_system_uuid!r}"
        )
    observed_pci_id = expected_pci_id(target or {})
    if observed_pci_id != args.expected_pci_id.lower():
        faults.append(
            f"PCI ID={observed_pci_id!r}, expected={args.expected_pci_id!r}"
        )
    outer = environment.get("outerQemu")
    outer = outer if isinstance(outer, dict) else {}
    if outer.get("unique") is not True or outer.get("candidateCount") != 1:
        faults.append(
            "outer QEMU process identity is not unique: "
            f"candidateCount={outer.get('candidateCount')!r}"
        )
    command_line = outer.get("commandLine")
    command_line = command_line if isinstance(command_line, list) else []
    for label, socket_path in (
        ("monitor", str(Path(args.qemu_monitor))),
        ("qtest", str(Path(args.qtest_socket))),
    ):
        if not any(
            isinstance(item, str) and socket_path in item
            for item in command_line
        ):
            faults.append(
                f"outer QEMU argv does not bind the requested {label} "
                f"socket {socket_path!r}"
            )
    binary = source_hashes.get("outerQemuBinary")
    binary = binary if isinstance(binary, dict) else {}
    if (
        binary.get("exists") is not True
        or not re.fullmatch(r"[0-9a-f]{64}", str(binary.get("sha256")))
    ):
        faults.append("outer QEMU binary hash is unavailable")
    source = source_hashes.get("qemuAerSource")
    source = source if isinstance(source, dict) else {}
    if (
        source.get("exists") is not True
        or not re.fullmatch(r"[0-9a-f]{64}", str(source.get("sha256")))
    ):
        faults.append("QEMU pcie_aer.c source hash is unavailable")
    binding = oracle_profile["environmentBinding"]
    if source.get("sha256") != binding["qemuAerSourceSha256"]:
        faults.append(
            "QEMU pcie_aer.c hash differs from the immutable profile"
        )
    if (
        binding["outerQemuBinarySha256"] is not None
        and binary.get("sha256")
        != binding["outerQemuBinarySha256"]
    ):
        faults.append(
            "outer QEMU binary hash differs from the frozen profile"
        )
    missing_inputs = [
        str(item.get("path"))
        for item in source_hashes.get("repositoryInputs", [])
        if not isinstance(item, dict)
        or item.get("exists") is not True
        or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256")))
    ]
    if missing_inputs:
        faults.append(
            "runtime dependency hashes are unavailable: "
            + ", ".join(missing_inputs)
        )
    return faults


def owner_binding_faults(
    *,
    owner_phase: str,
    observation: dict[str, Any],
) -> list[str]:
    expected = OWNER_PHASES[owner_phase]
    faults: list[str] = []
    if observation.get("currentOwner") != expected["currentOwner"]:
        faults.append(
            f"Current Owner={observation.get('currentOwner')!r}, "
            f"expected={expected['currentOwner']!r}"
        )
    users = observation.get("activeUsers")
    if expected["activeUsers"] == "NONE":
        if users != []:
            faults.append(f"O0 active users are not empty: {users!r}")
    elif not (
        isinstance(users, list)
        and len(users) == 1
        and isinstance(users[0], dict)
        and users[0].get("runnerCreated") is True
    ):
        faults.append(
            "O4 does not have exactly one runner-created active user: "
            f"{users!r}"
        )
    if observation.get("hostResponsive") is not True:
        faults.append("ESXi heartbeat failed")
    return faults


def active_vm_cleanup_checks(
    value: Any,
    *,
    expected_registered: bool,
) -> dict[str, bool]:
    if not isinstance(value, dict):
        return {"cleanup-record-object": False}
    actions = value.get("actions")
    actions = actions if isinstance(actions, list) else []
    return_codes: list[int] = []
    unregister_codes: list[int] = []
    for item in actions:
        if not isinstance(item, dict):
            return_codes.append(-1)
            continue
        for key in ("powerOffReturnCode", "unregisterReturnCode"):
            if key in item:
                raw = item.get(key)
                code = (
                    raw
                    if isinstance(raw, int) and not isinstance(raw, bool)
                    else -1
                )
                return_codes.append(code)
                if key == "unregisterReturnCode":
                    unregister_codes.append(code)
    return {
        "no-cleanup-error": "error" not in value,
        "not-cancelled-by-safety-monitor": (
            value.get("cancelledBySafetyMonitor") is not True
        ),
        "no-active-user-query-error": (
            "remainingActiveUsersError" not in value
        ),
        "critical-return-codes-zero": (
            (
                bool(unregister_codes)
                if expected_registered
                else True
            )
            and all(code == 0 for code in return_codes)
        ),
        "no-remaining-active-users": (
            value.get("remainingActiveUsers") == []
        ),
    }


ACTIVE_VM_CLEANUP_FIELDS = {
    "startedAt",
    "actions",
    "cancelledBySafetyMonitor",
    "remainingActiveUsers",
    "activeUserProbes",
    "remainingActiveUsersError",
    "finishedAt",
}
ACTIVE_VM_CLEANUP_REQUIRED_FIELDS = {
    "startedAt",
    "actions",
    "finishedAt",
}
T5_CONTAINMENT_FIELDS = {
    "required",
    "reasons",
    "observedSafetySideEffect",
}
EVALUATION_EVIDENCE_FIELDS = {
    "evidenceComplete",
    "evidenceProtocolChecks",
    "runtimeSafetyFaults",
    "containmentRequired",
    "containmentReasons",
    "executionFault",
    "cleanupComplete",
}
RUNTIME_SAFETY_FAULT_FIELD_SETS = {
    frozenset({"label", "faults"}),
    frozenset({"label", "faults", "snapshot"}),
    frozenset({"label", "faults", "projection"}),
    frozenset({"label", "faults", "observation"}),
}


def _time_envelope_faults(
    *,
    started_at: Any,
    finished_at: Any,
    label: str,
) -> list[str]:
    started = _utc_datetime(started_at)
    finished = _utc_datetime(finished_at)
    faults: list[str] = []
    if started is None:
        faults.append(f"{label} startedAt is not UTC")
    if finished is None:
        faults.append(f"{label} finishedAt is not UTC")
    if started is not None and finished is not None and finished < started:
        faults.append(f"{label} time envelope is reversed")
    return faults


def active_vm_cleanup_record_faults(
    value: Any,
    *,
    active_vm: Any,
) -> list[str]:
    """Close the normal, deferred and failed active-VM cleanup variants."""

    if value is None:
        return []
    if not isinstance(value, dict):
        return ["t5.activeVmCleanup is not an object or null"]
    if set(value) == {"error"}:
        return (
            []
            if _non_empty_string(value.get("error"))
            else ["t5.activeVmCleanup error is not a non-empty string"]
        )
    if set(value) == {"deferred", "reason"}:
        return (
            []
            if value.get("deferred") is True
            and _non_empty_string(value.get("reason"))
            else ["t5.activeVmCleanup deferred record is not closed"]
        )

    faults: list[str] = []
    unknown = sorted(set(value) - ACTIVE_VM_CLEANUP_FIELDS)
    missing = sorted(ACTIVE_VM_CLEANUP_REQUIRED_FIELDS - set(value))
    if unknown:
        faults.append(
            f"t5.activeVmCleanup has unknown fields: {unknown}"
        )
    if missing:
        faults.append(
            f"t5.activeVmCleanup is missing required fields: {missing}"
        )
    faults.extend(
        _time_envelope_faults(
            started_at=value.get("startedAt"),
            finished_at=value.get("finishedAt"),
            label="t5.activeVmCleanup",
        )
    )

    cancelled = value.get("cancelledBySafetyMonitor")
    if cancelled is not None and cancelled is not True:
        faults.append(
            "t5.activeVmCleanup cancelledBySafetyMonitor is not true"
        )
    has_success_summary = (
        "remainingActiveUsers" in value and "activeUserProbes" in value
    )
    has_error_summary = "remainingActiveUsersError" in value
    if has_success_summary == has_error_summary:
        faults.append(
            "t5.activeVmCleanup has no unique active-user result branch"
        )
    if has_error_summary and not _non_empty_string(
        value.get("remainingActiveUsersError")
    ):
        faults.append(
            "t5.activeVmCleanup remainingActiveUsersError is invalid"
        )
    remaining = value.get("remainingActiveUsers")
    if has_success_summary and (
        not isinstance(remaining, list)
        or any(not isinstance(item, dict) for item in remaining)
    ):
        faults.append(
            "t5.activeVmCleanup remainingActiveUsers is not an object list"
        )
    probes = value.get("activeUserProbes")
    if has_success_summary:
        if not isinstance(probes, list):
            faults.append(
                "t5.activeVmCleanup activeUserProbes is not a list"
            )
        else:
            if cancelled is not True and not probes:
                faults.append(
                    "t5.activeVmCleanup has no active-user probe"
                )
            for index, probe in enumerate(probes):
                if (
                    not isinstance(probe, dict)
                    or set(probe) != {"mode", "capturedAt"}
                    or probe.get("mode") != "ISOLATED_PROCESS"
                    or _utc_datetime(probe.get("capturedAt")) is None
                ):
                    faults.append(
                        "t5.activeVmCleanup activeUserProbes"
                        f"[{index}] is not closed"
                    )

    actions = value.get("actions")
    if not isinstance(actions, list):
        return sorted(
            set(
                faults
                + ["t5.activeVmCleanup actions is not a list"]
            )
        )
    start = (
        active_vm.get("start")
        if isinstance(active_vm, dict)
        else None
    )
    remote_names = closed_active_vm_remote_path_names(start)
    expected_copy_pairs = (
        {
            (remote_names[0], "guest-serial-final.log"),
            ("vmware.log", "vmware.log"),
            (remote_names[1], "effective.vmx"),
        }
        if remote_names is not None
        else None
    )
    observed_copy_pairs: list[tuple[Any, Any]] = []
    action_ranks: list[int] = []
    for index, action in enumerate(actions):
        prefix = f"t5.activeVmCleanup actions[{index}]"
        if not isinstance(action, dict):
            faults.append(f"{prefix} is not an object")
            continue
        fields = set(action)
        if fields == {"copy", "destination", "success"}:
            pair = (action.get("copy"), action.get("destination"))
            observed_copy_pairs.append(pair)
            action_ranks.append(0)
            if (
                not all(_non_empty_string(item) for item in pair)
                or action.get("destination")
                not in {
                    "guest-serial-final.log",
                    "vmware.log",
                    "effective.vmx",
                }
                or not isinstance(action.get("success"), bool)
                or (
                    expected_copy_pairs is not None
                    and pair not in expected_copy_pairs
                )
            ):
                faults.append(f"{prefix} copy record is not closed")
        elif fields == {"output", "powerOffReturnCode"}:
            action_ranks.append(1)
            code = action.get("powerOffReturnCode")
            if (
                not isinstance(code, int)
                or isinstance(code, bool)
                or not isinstance(action.get("output"), str)
            ):
                faults.append(f"{prefix} power-off record is not closed")
        elif fields == {"unregisterReturnCode"}:
            action_ranks.append(2)
            code = action.get("unregisterReturnCode")
            if not isinstance(code, int) or isinstance(code, bool):
                faults.append(f"{prefix} unregister record is not closed")
        else:
            faults.append(f"{prefix} has an unknown action shape")
    if len(observed_copy_pairs) != len(set(observed_copy_pairs)):
        faults.append("t5.activeVmCleanup repeats a copy action")
    if (
        expected_copy_pairs is not None
        and cancelled is not True
        and set(observed_copy_pairs) != expected_copy_pairs
    ):
        faults.append(
            "t5.activeVmCleanup does not attempt the exact frozen copies"
        )
    if action_ranks != sorted(action_ranks):
        faults.append("t5.activeVmCleanup action order is not canonical")
    if action_ranks.count(1) > 1 or action_ranks.count(2) > 1:
        faults.append("t5.activeVmCleanup repeats a terminal action")
    return sorted(set(faults))


def runtime_safety_faults_shape_faults(value: Any) -> list[str]:
    """Reject free-form runtime safety claims retained in evaluationEvidence."""

    if not isinstance(value, list):
        return ["t5.evaluationEvidence runtimeSafetyFaults is not a list"]
    faults: list[str] = []
    for index, item in enumerate(value):
        prefix = f"t5.evaluationEvidence runtimeSafetyFaults[{index}]"
        if (
            not isinstance(item, dict)
            or frozenset(item) not in RUNTIME_SAFETY_FAULT_FIELD_SETS
        ):
            faults.append(f"{prefix} is not a closed record")
            continue
        if not _non_empty_string(item.get("label")):
            faults.append(f"{prefix}.label is invalid")
        item_faults = item.get("faults")
        if (
            not isinstance(item_faults, list)
            or not item_faults
            or any(not _non_empty_string(raw) for raw in item_faults)
        ):
            faults.append(f"{prefix}.faults is not a non-empty string list")
        if "snapshot" in item:
            faults.extend(
                f"{prefix}.snapshot: {fault}"
                for fault in outer_snapshot_shape_faults(
                    item.get("snapshot")
                )
            )
        if "projection" in item and not isinstance(
            item.get("projection"), dict
        ):
            faults.append(f"{prefix}.projection is not an object")
        if "observation" in item:
            observation = item.get("observation")
            if (
                not isinstance(observation, dict)
                or observation.get("faults") != item_faults
            ):
                faults.append(f"{prefix}.observation is not bound")
    return sorted(set(faults))


def cleanup_evidence_faults(
    *,
    cleanup: Any,
    t1: Any,
    t5: Any,
    owner_phase: Any,
    evidence_protocol: Any,
) -> list[str]:
    """Recompute cleanup completion and close every duplicated summary."""

    if not isinstance(cleanup, dict) or not isinstance(t5, dict):
        return ["cleanup/T5 evidence roots are not objects"]
    t1 = t1 if isinstance(t1, dict) else {}
    faults: list[str] = []
    cleanup_started = _utc_datetime(cleanup.get("startedAt"))
    cleanup_finished = _utc_datetime(cleanup.get("finishedAt"))
    faults.extend(
        _time_envelope_faults(
            started_at=cleanup.get("startedAt"),
            finished_at=cleanup.get("finishedAt"),
            label="cleanup",
        )
    )
    if not isinstance(cleanup.get("complete"), bool):
        faults.append("cleanup.complete is not boolean")
    if not isinstance(cleanup.get("containmentRequired"), bool):
        faults.append("cleanup.containmentRequired is not boolean")

    containment = t5.get("containment")
    containment_valid = bool(
        isinstance(containment, dict)
        and set(containment) == T5_CONTAINMENT_FIELDS
        and isinstance(containment.get("required"), bool)
        and isinstance(containment.get("observedSafetySideEffect"), bool)
        and isinstance(containment.get("reasons"), list)
        and all(
            _non_empty_string(item)
            for item in containment.get("reasons", [])
        )
    )
    if not containment_valid:
        faults.append("t5.containment is not a closed record")
        containment = {}
    containment_required = containment.get("required") is True
    containment_reasons = containment.get("reasons")
    containment_reasons = (
        containment_reasons
        if isinstance(containment_reasons, list)
        else []
    )
    observed_safety = (
        containment.get("observedSafetySideEffect") is True
    )
    if containment_required and not containment_reasons:
        faults.append("t5.containment required state lacks a reason")
    if not containment_required and containment_reasons:
        faults.append("t5.containment has reasons without containment")
    if cleanup.get("containmentRequired") != containment.get("required"):
        faults.append(
            "cleanup.containmentRequired differs from t5.containment"
        )

    active_vm_cleanup = t5.get("activeVmCleanup")
    faults.extend(
        active_vm_cleanup_record_faults(
            active_vm_cleanup,
            active_vm=t1.get("activeVm"),
        )
    )
    if owner_phase == "O0" and active_vm_cleanup is not None:
        faults.append("O0 carries an activeVmCleanup record")
    active_cleanup_kind = (
        "none"
        if active_vm_cleanup is None
        else (
            "error"
            if isinstance(active_vm_cleanup, dict)
            and set(active_vm_cleanup) == {"error"}
            else (
                "deferred"
                if isinstance(active_vm_cleanup, dict)
                and set(active_vm_cleanup) == {"deferred", "reason"}
                else "normal"
            )
        )
    )
    cleanup_checks = t5.get("activeVmCleanupChecks")
    if active_cleanup_kind == "normal":
        expected_checks = active_vm_cleanup_checks(
            active_vm_cleanup,
            expected_registered=True,
        )
        if (
            not isinstance(cleanup_checks, dict)
            or cleanup_checks != expected_checks
            or any(
                not isinstance(item, bool)
                for item in cleanup_checks.values()
            )
        ):
            faults.append("t5.activeVmCleanupChecks are not exact")
        active_cleanup_complete = bool(
            isinstance(cleanup_checks, dict)
            and cleanup_checks
            and all(item is True for item in cleanup_checks.values())
        )
        if active_cleanup_complete and not active_vm_cleanup.get(
            "activeUserProbes"
        ):
            faults.append(
                "complete active-VM cleanup lacks an active-user probe"
            )
    else:
        active_cleanup_complete = active_cleanup_kind == "none"
        if "activeVmCleanupChecks" in t5:
            faults.append(
                "t5.activeVmCleanupChecks exist without a normal cleanup"
            )

    restore = t5.get("gateRestore")
    restore_fault = t5.get("gateRestoreFault")
    lease_exists = isinstance(t1.get("gateLease"), dict)
    restore_complete = bool(
        (not lease_exists and restore is None)
        or (
            isinstance(restore, dict)
            and restore.get("outcome") == "RESTORED"
            and restore_fault is None
        )
    )
    if restore is not None and not isinstance(restore, dict):
        faults.append("t5.gateRestore is not an object or null")
    if isinstance(restore, dict):
        faults.extend(
            _time_envelope_faults(
                started_at=restore.get("startedAt"),
                finished_at=restore.get("finishedAt"),
                label="t5.gateRestore",
            )
        )
    restore_started = (
        _utc_datetime(restore.get("startedAt"))
        if isinstance(restore, dict)
        else None
    )
    restore_finished = (
        _utc_datetime(restore.get("finishedAt"))
        if isinstance(restore, dict)
        else None
    )
    active_cleanup_started = (
        _utc_datetime(active_vm_cleanup.get("startedAt"))
        if active_cleanup_kind == "normal"
        else None
    )
    active_cleanup_finished = (
        _utc_datetime(active_vm_cleanup.get("finishedAt"))
        if active_cleanup_kind == "normal"
        else None
    )
    for label, nested_started, nested_finished in (
        ("t5.gateRestore", restore_started, restore_finished),
        (
            "t5.activeVmCleanup",
            active_cleanup_started,
            active_cleanup_finished,
        ),
    ):
        if (
            cleanup_started is not None
            and nested_started is not None
            and nested_started < cleanup_started
        ):
            faults.append(f"{label} starts before cleanup")
        if (
            cleanup_finished is not None
            and nested_finished is not None
            and nested_finished > cleanup_finished
        ):
            faults.append(f"{label} finishes after cleanup")
    if (
        restore_finished is not None
        and active_cleanup_started is not None
        and active_cleanup_started < restore_finished
    ):
        faults.append("active-VM cleanup starts before gate restore finishes")

    actions = cleanup.get("actions")
    gate_ledger: list[dict[str, Any]] = []
    active_ledger: list[dict[str, Any]] = []
    if not isinstance(actions, list):
        faults.append("cleanup.actions is not a list")
    else:
        ranks: list[int] = []
        for index, action in enumerate(actions):
            prefix = f"cleanup.actions[{index}]"
            if not isinstance(action, dict):
                faults.append(f"{prefix} is not an object")
            elif set(action) == {"gateRestore", "safeStop"}:
                ranks.append(0)
                gate_ledger.append(action)
                if (
                    not _non_empty_string(action.get("gateRestore"))
                    or not isinstance(action.get("safeStop"), bool)
                ):
                    faults.append(f"{prefix} gate-restore claim is invalid")
            elif set(action) == {"activeVmCleanup"}:
                ranks.append(1)
                active_ledger.append(action)
            else:
                faults.append(f"{prefix} has an unknown ledger shape")
        if ranks != sorted(ranks):
            faults.append("cleanup.actions order is not canonical")
        if len(gate_ledger) > 1 or len(active_ledger) > 1:
            faults.append("cleanup.actions repeats a ledger entry")

    gate_ledger_required = bool(
        isinstance(restore, dict) and restore_fault is None
    )
    if gate_ledger_required:
        if (
            len(gate_ledger) != 1
            or gate_ledger[0].get("gateRestore")
            != restore.get("outcome")
        ):
            faults.append(
                "cleanup gate-restore ledger does not mirror t5.gateRestore"
            )
    elif gate_ledger:
        faults.append("cleanup gate-restore ledger has no completed source")
    active_ledger_required = active_cleanup_kind == "normal"
    if active_ledger_required:
        if (
            len(active_ledger) != 1
            or active_ledger[0].get("activeVmCleanup")
            != active_vm_cleanup
        ):
            faults.append(
                "cleanup active-VM ledger does not mirror "
                "t5.activeVmCleanup"
            )
    elif active_ledger:
        faults.append("cleanup active-VM ledger has no normal source")

    branch_fault_fields = {
        "gateRestoreFault",
        "emergencyHoldFault",
        "containmentHoldFault",
        "preCleanupQemuStateFault",
        "unknownStateEmergencyHoldFault",
        "postCleanupContainmentHoldFault",
        "finalQemuStateFault",
        "finalStateEmergencyHoldFault",
    }
    hold_fields = {
        "emergencyHold",
        "containmentHold",
        "unknownStateEmergencyHold",
        "postCleanupContainmentHold",
        "finalStateEmergencyHold",
    }
    mandatory_containment = bool(
        observed_safety
        or active_cleanup_kind in {"error", "deferred"}
        or not restore_complete
        or t5.get("finalQemuState") != "running"
        or any(field in t5 for field in branch_fault_fields)
        or any(field in t5 for field in hold_fields)
    )
    if mandatory_containment and not containment_required:
        faults.append("raw cleanup failures are not contained")

    expected_complete = bool(
        not containment_required
        and t5.get("finalQemuState") == "running"
        and restore_complete
        and active_cleanup_complete
    )
    if cleanup.get("complete") is not expected_complete:
        faults.append("cleanup.complete is not recomputed from T5 facts")
    if expected_complete and gate_ledger and gate_ledger[0].get(
        "safeStop"
    ) is not False:
        faults.append("successful cleanup gate restore claims safeStop")

    evaluation_evidence = t5.get("evaluationEvidence")
    if (
        not isinstance(evaluation_evidence, dict)
        or set(evaluation_evidence) != EVALUATION_EVIDENCE_FIELDS
    ):
        faults.append("t5.evaluationEvidence is not a closed record")
        evaluation_evidence = {}
    protocol_checks = (
        evidence_protocol.get("checks")
        if isinstance(evidence_protocol, dict)
        else None
    )
    protocol_complete = (
        evidence_protocol.get("complete")
        if isinstance(evidence_protocol, dict)
        else None
    )
    if (
        not isinstance(protocol_checks, dict)
        or any(not isinstance(item, bool) for item in protocol_checks.values())
    ):
        faults.append("recomputed evidenceProtocolChecks are not closed")
    if (
        evaluation_evidence.get("evidenceProtocolChecks")
        != protocol_checks
    ):
        faults.append(
            "t5.evaluationEvidence evidenceProtocolChecks are not recomputed"
        )
    if (
        evaluation_evidence.get("evidenceComplete")
        is not protocol_complete
    ):
        faults.append(
            "t5.evaluationEvidence evidenceComplete is not recomputed"
        )
    if evaluation_evidence.get("cleanupComplete") is not cleanup.get(
        "complete"
    ):
        faults.append(
            "t5.evaluationEvidence cleanupComplete differs from cleanup"
        )
    if (
        evaluation_evidence.get("containmentRequired")
        is not containment.get("required")
        or evaluation_evidence.get("containmentReasons")
        != containment_reasons
    ):
        faults.append(
            "t5.evaluationEvidence containment summary differs from T5"
        )
    runtime_safety_faults = evaluation_evidence.get(
        "runtimeSafetyFaults"
    )
    faults.extend(
        runtime_safety_faults_shape_faults(runtime_safety_faults)
    )
    if isinstance(runtime_safety_faults, list) and (
        bool(runtime_safety_faults) != observed_safety
    ):
        faults.append(
            "t5 containment safety latch differs from runtimeSafetyFaults"
        )
    execution_fault = evaluation_evidence.get("executionFault")
    if not _closed_fault_or_none(execution_fault):
        faults.append("t5.evaluationEvidence executionFault is not closed")
    if (
        isinstance(execution_fault, dict)
        and execution_fault.get("type") == "SafetyViolation"
        and (
            not observed_safety
            or not containment_required
            or not runtime_safety_faults
        )
    ):
        faults.append(
            "SafetyViolation executionFault lacks raw safety containment"
        )
    if cleanup.get("complete") is False and execution_fault is None:
        faults.append("incomplete cleanup lacks an execution fault")
    if protocol_complete is True and execution_fault is not None:
        faults.append("complete evidence carries an execution fault")
    return sorted(set(faults))


def case_claim_boundary() -> dict[str, Any]:
    return {
        "scope": (
            "Exact nested ESXi build/device/owner/gate black-box observation "
            "using public configuration registers, public API/inventory, "
            "guest raw config and bounded logs"
        ),
        "excluded": [
            "VMware private code or internal control flow",
            "physical-link error generation",
            "interrupt or service attribution from log absence",
            "physical-device recovery, health or quarantine",
            "Qman implementation, qualification or release closure",
        ],
    }


CASE_SPEC_FIELDS = {
    "schemaVersion",
    "modelId",
    "campaignId",
    "caseRunId",
    "caseId",
    "ownerPhase",
    "sequence",
    "gate",
    "repeatIndex",
    "qemuDevice",
    "controlledBits",
    "requestedGate",
    "ownerContract",
    "logWindowProtocol",
    "claimBoundary",
    "safetyBoundary",
}
RUN_MANIFEST_FIELDS = {
    "schemaVersion",
    "runId",
    "campaignId",
    "caseRunId",
    "caseId",
    "ownerPhase",
    "sequence",
    "gate",
    "repeatIndex",
    "qemuDevice",
    "startedAt",
    "host",
    "runner",
    "runtimeDependencies",
    "oracleProfile",
    "environment",
    "timelineDelaysSeconds",
    "finalObservationSecondsO0",
    "freshExplicitBaselinePerCase",
    "sourcePolicy",
}
EVALUATION_INPUT_FIELDS = {
    "schemaVersion",
    "campaignId",
    "caseRunId",
    "caseId",
    "sequence",
    "gate",
    "ownerPhase",
    "repeatIndex",
    "qemuDevice",
    "requesterId",
    "enteredInjection",
    "preflight",
    "snapshots",
    "injections",
    "ownerObservations",
    "gateStable",
    "hostProjection",
    "hostLogClassification",
    "guestClassification",
    "o4GuestEvidenceValid",
    "evidenceComplete",
    "safetyObservations",
    "safetyCoverage",
    "safetyFaults",
    "containmentRequired",
    "containmentReasons",
    "containmentEvidence",
    "fault",
    "cleanupComplete",
}
CASE_RESULT_FIELDS = {
    "schemaVersion",
    "case",
    "startedAt",
    "finishedAt",
    "observationState",
    "verdict",
    "observationDigest",
    "safetyStop",
    "enteredInjection",
    "fault",
    "cleanupComplete",
    "containmentRequired",
    "containmentReasons",
    "runtimeContainmentRequired",
    "runtimeContainmentReasons",
    "claimBoundary",
}
QTEST_WRITABLE_FIELD_CLAIMS = [
    "Endpoint CES.B0/B1 W1C",
    "Endpoint Device Status.CED W1C",
    "Endpoint CEM.B0/B1",
    "Endpoint Device Control.CERE",
    "Root Bridge Control.SERR",
    "Root Device Control.CERE",
    "Root Error Command.COR_EN",
    "Root Correctable Status W1C",
]
PREFLIGHT_FIELDS = {
    "environmentBound",
    "ownerBound",
    "cleanBaseline",
    "gatePausedReadback",
    "evidenceProtocolReady",
}
HOST_LOG_CLASSIFICATIONS = {
    "MATCHING_EVENT_OBSERVED",
    "NOT_OBSERVED_IN_MARKER_AND_BYTE_CURSOR_WINDOW",
    "NOT_OBSERVED_IN_STRICT_PER_SOURCE_MARKER_WINDOW",
    "INCONCLUSIVE_LOG_WINDOW",
}
GUEST_CLASSIFICATIONS = {
    "O4_BOUND_DRIVER_AND_HEARTBEAT",
    "NOT_APPLICABLE_O0",
    "O4_GUEST_EVIDENCE_INCOMPLETE",
}
CONTAINMENT_EVIDENCE_ITEM_FIELDS = {
    "label",
    "faults",
    "observation",
}
CONTAINMENT_OBSERVATION_FIELD_SETS = {
    frozenset({"delaySeconds", "faults", "snapshot"}),
    frozenset({"delaySeconds", "faults", "snapshot", "phase"}),
    frozenset({"delaySeconds", "faults", "phase"}),
}


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _finite_number(value: Any) -> bool:
    return bool(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _utc_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    if value.endswith("Z"):
        iso_value = value[:-1] + "+00:00"
    elif value.endswith("+00:00"):
        # Imported producers use ``datetime.now(timezone.utc).isoformat()``.
        iso_value = value
    else:
        return None
    try:
        parsed = datetime.fromisoformat(iso_value)
    except ValueError:
        return None
    if parsed.utcoffset() != timedelta(0):
        return None
    return parsed


def _closed_fault_or_none(value: Any) -> bool:
    return bool(
        value is None
        or (
            isinstance(value, dict)
            and set(value) == {"type", "message"}
            and _non_empty_string(value.get("type"))
            and isinstance(value.get("message"), str)
        )
    )


def case_spec_shape_faults(
    case_spec: Any,
    oracle_profile: dict[str, Any],
) -> list[str]:
    """Validate the exact case contract emitted by the current model."""

    if not isinstance(case_spec, dict):
        return ["case.json root is not an object"]
    faults: list[str] = []
    if set(case_spec) != CASE_SPEC_FIELDS:
        faults.append("case.json fields differ from the current closed schema")
    if case_spec.get("schemaVersion") != SCHEMA_VERSION:
        faults.append("case.json schemaVersion is not current")
    if case_spec.get("modelId") != RUNNER_MODEL_ID:
        faults.append("case.json modelId is not current")
    campaign_id = case_spec.get("campaignId")
    case_id = case_spec.get("caseId")
    owner_phase = case_spec.get("ownerPhase")
    sequence = case_spec.get("sequence")
    gate = case_spec.get("gate")
    repeat_index = case_spec.get("repeatIndex")
    qemu_device = case_spec.get("qemuDevice")
    if not _non_empty_string(campaign_id):
        faults.append("case campaignId is not a non-empty string")
    if not isinstance(case_id, str) or CASE_ID_RE.fullmatch(case_id) is None:
        faults.append("caseId is not canonical")
    if owner_phase not in OWNER_PHASES:
        faults.append("case ownerPhase is not closed")
    if sequence not in SEQUENCES:
        faults.append("case sequence is not closed")
    if gate not in SUPPORTED_GATES:
        faults.append("case gate is not closed")
    if (
        not isinstance(repeat_index, int)
        or isinstance(repeat_index, bool)
        or repeat_index <= 0
    ):
        faults.append("case repeatIndex is not a positive integer")
    if (
        isinstance(case_id, str)
        and owner_phase in OWNER_PHASES
        and sequence in SEQUENCES
        and gate in SUPPORTED_GATES
        and isinstance(repeat_index, int)
        and not isinstance(repeat_index, bool)
        and repeat_index > 0
        and case_id
        != (
            f"{owner_phase.lower()}__{sequence}__{gate}"
            f"__r{repeat_index:02d}"
        )
    ):
        faults.append("caseId differs from the deterministic case identity")
    expected_case_run_id = (
        f"{campaign_id}--{case_id}"
        if isinstance(campaign_id, str) and isinstance(case_id, str)
        else None
    )
    if (
        expected_case_run_id is None
        or case_spec.get("caseRunId") != expected_case_run_id
    ):
        faults.append("caseRunId differs from campaignId/caseId")
    if (
        not isinstance(qemu_device, str)
        or QEMU_DEVICE_ID_RE.fullmatch(qemu_device) is None
    ):
        faults.append("case qemuDevice is not a closed safe ID")
    if case_spec.get("controlledBits") != [
        {"name": B0_NAME, "mask": f"0x{B0:08x}"},
        {"name": B1_NAME, "mask": f"0x{B1:08x}"},
    ]:
        faults.append("case controlledBits differ from B0/B1")
    if (
        gate in SUPPORTED_GATES
        and case_spec.get("requestedGate") != SUPPORTED_GATES[gate].as_dict()
    ):
        faults.append("case requestedGate differs from the closed gate")
    if (
        owner_phase in OWNER_PHASES
        and case_spec.get("ownerContract") != OWNER_PHASES[owner_phase]
    ):
        faults.append("case ownerContract differs from ownerPhase")
    try:
        expected_protocol = log_v2.protocol_for_case(
            str(campaign_id),
            str(case_id),
        )
    except ValueError:
        expected_protocol = None
    if (
        expected_protocol is None
        or case_spec.get("logWindowProtocol") != expected_protocol
    ):
        faults.append("case logWindowProtocol is not exact V2")
    if case_spec.get("claimBoundary") != case_claim_boundary():
        faults.append("case claimBoundary drifted")

    timing = oracle_profile.get("timingEnvelope")
    timing = timing if isinstance(timing, dict) else {}
    maximum = timing.get("maximumSafetyPollIntervalSeconds")
    expected_safety = {
        "injectionClass": "Correctable-only",
        "hmpForm": (
            "pcie_aer_inject_error -c <closed-qdev> <B0-or-B1-mask>"
        ),
        "uncorrectableInjectionSurface": False,
        "maximumSafetyPollIntervalSeconds": maximum,
        "safetyPollTargetIntervalSeconds": (
            float(maximum) / 2.0 if _finite_number(maximum) else None
        ),
        "qtestWritableFields": QTEST_WRITABLE_FIELD_CLAIMS,
    }
    if case_spec.get("safetyBoundary") != expected_safety:
        faults.append("case safetyBoundary differs from the frozen profile")
    return sorted(set(faults))


def run_manifest_shape_faults(
    run_manifest: Any,
    oracle_profile: dict[str, Any],
) -> list[str]:
    """Validate the current runner's exact authority-facing run record."""

    if not isinstance(run_manifest, dict):
        return ["run-manifest root is not an object"]
    faults: list[str] = []
    if set(run_manifest) != RUN_MANIFEST_FIELDS:
        faults.append("run-manifest fields differ from the closed schema")
    if run_manifest.get("schemaVersion") != SCHEMA_VERSION:
        faults.append("run-manifest schemaVersion is not current")
    if _utc_datetime(run_manifest.get("startedAt")) is None:
        faults.append("run-manifest startedAt is not a UTC timestamp")
    host = run_manifest.get("host")
    if (
        not isinstance(host, dict)
        or set(host) != {"platform", "python"}
        or not all(_non_empty_string(value) for value in host.values())
    ):
        faults.append("run-manifest host record is not closed")
    runner_record = run_manifest.get("runner")
    if (
        not isinstance(runner_record, dict)
        or set(runner_record) != {"path", "sha256"}
        or runner_record.get("path") != str(Path(__file__).resolve())
        or runner_record.get("sha256")
        != sha256_file(Path(__file__).resolve())
    ):
        faults.append("run-manifest runner binding is not exact")
    if not isinstance(run_manifest.get("runtimeDependencies"), list):
        faults.append("run-manifest runtimeDependencies is not a list")
    oracle_record = run_manifest.get("oracleProfile")
    if (
        not isinstance(oracle_record, dict)
        or set(oracle_record)
        != {"path", "sha256", "id", "profileState", "schemaSha256"}
        or not _non_empty_string(oracle_record.get("path"))
        or oracle_record.get("id") != oracle_profile.get("id")
        or oracle_record.get("profileState")
        != oracle_profile.get("profileState")
    ):
        faults.append("run-manifest oracleProfile record is not closed")
    if not isinstance(run_manifest.get("environment"), dict):
        faults.append("run-manifest environment is not an object")
    timing = oracle_profile.get("timingEnvelope")
    timing = timing if isinstance(timing, dict) else {}
    if (
        run_manifest.get("timelineDelaysSeconds")
        != timing.get("timelineDelaysSeconds")
    ):
        faults.append("run-manifest timeline delays differ from the profile")
    final_observation = run_manifest.get("finalObservationSecondsO0")
    minimum_final = timing.get("minimumFinalObservationSecondsO0")
    if (
        not _finite_number(final_observation)
        or not _finite_number(minimum_final)
        or float(final_observation) < float(minimum_final)
    ):
        faults.append("run-manifest O0 final observation is below the profile")
    if run_manifest.get("freshExplicitBaselinePerCase") is not True:
        faults.append("run-manifest lacks a fresh per-case baseline")
    if run_manifest.get("sourcePolicy") != oracle_profile.get("sourcePolicy"):
        faults.append("run-manifest sourcePolicy differs from the profile")
    return sorted(set(faults))


def evaluation_input_shape_faults(
    value: Any,
) -> list[str]:
    """Reject omitted or injected evaluator claims before semantic replay."""

    if not isinstance(value, dict):
        return ["evaluation-input root is not an object"]
    faults: list[str] = []
    if set(value) != EVALUATION_INPUT_FIELDS:
        faults.append("evaluation-input fields differ from the closed schema")
    if value.get("schemaVersion") != SCHEMA_VERSION:
        faults.append("evaluation-input schemaVersion is not current")
    for field_name in ("campaignId", "caseRunId", "caseId", "qemuDevice"):
        if not _non_empty_string(value.get(field_name)):
            faults.append(f"evaluation-input {field_name} is not a string")
    repeat_index = value.get("repeatIndex")
    if (
        not isinstance(repeat_index, int)
        or isinstance(repeat_index, bool)
        or repeat_index <= 0
    ):
        faults.append("evaluation-input repeatIndex is not positive")
    requester_id = value.get("requesterId")
    if (
        not isinstance(requester_id, int)
        or isinstance(requester_id, bool)
        or not -1 <= requester_id <= 0xFFFF
    ):
        faults.append("evaluation-input requesterId is not bounded")
    preflight = value.get("preflight")
    if (
        not isinstance(preflight, dict)
        or set(preflight) != PREFLIGHT_FIELDS
        or any(not isinstance(item, bool) for item in preflight.values())
    ):
        faults.append("evaluation-input preflight is not closed")
    for field_name, expected_type in (
        ("snapshots", dict),
        ("injections", list),
        ("ownerObservations", list),
        ("safetyObservations", list),
        ("safetyCoverage", list),
        ("safetyFaults", list),
        ("containmentReasons", list),
        ("containmentEvidence", list),
    ):
        if not isinstance(value.get(field_name), expected_type):
            faults.append(
                f"evaluation-input {field_name} has the wrong type"
            )
    for field_name in (
        "enteredInjection",
        "gateStable",
        "o4GuestEvidenceValid",
        "evidenceComplete",
        "containmentRequired",
        "cleanupComplete",
    ):
        if not isinstance(value.get(field_name), bool):
            faults.append(
                f"evaluation-input {field_name} is not a boolean"
            )
    if value.get("hostProjection") is not None and not isinstance(
        value.get("hostProjection"),
        dict,
    ):
        faults.append("evaluation-input hostProjection has the wrong type")
    if value.get("hostLogClassification") not in HOST_LOG_CLASSIFICATIONS:
        faults.append("evaluation-input host-log classification is not closed")
    if value.get("guestClassification") not in GUEST_CLASSIFICATIONS:
        faults.append("evaluation-input guest classification is not closed")
    reasons = value.get("containmentReasons")
    if isinstance(reasons, list) and not all(
        isinstance(item, str) for item in reasons
    ):
        faults.append("evaluation-input containmentReasons is not a string list")
    containment_evidence = value.get("containmentEvidence")
    if isinstance(containment_evidence, list):
        for index, item in enumerate(containment_evidence):
            prefix = f"evaluation-input containmentEvidence[{index}]"
            if (
                not isinstance(item, dict)
                or set(item) != CONTAINMENT_EVIDENCE_ITEM_FIELDS
                or item.get("label") != "gate-restore"
            ):
                faults.append(f"{prefix} is not a closed item")
                continue
            item_faults = item.get("faults")
            observation = item.get("observation")
            if (
                not isinstance(item_faults, list)
                or not item_faults
                or any(not isinstance(raw, str) for raw in item_faults)
            ):
                faults.append(f"{prefix}.faults is not a string list")
            if (
                not isinstance(observation, dict)
                or frozenset(observation)
                not in CONTAINMENT_OBSERVATION_FIELD_SETS
            ):
                faults.append(f"{prefix}.observation is not closed")
                continue
            if observation.get("faults") != item_faults:
                faults.append(
                    f"{prefix}.faults differs from its observation"
                )
            delay = observation.get("delaySeconds")
            if delay is not None and (
                not _finite_number(delay) or float(delay) < 0
            ):
                faults.append(f"{prefix}.delaySeconds is invalid")
            if "snapshot" in observation:
                faults.extend(
                    f"{prefix}.snapshot: {fault}"
                    for fault in outer_snapshot_shape_faults(
                        observation.get("snapshot")
                    )
                )
            if "phase" in observation and observation.get("phase") not in {
                None,
                "paused-restore",
                "resumed",
            }:
                faults.append(f"{prefix}.phase is not closed")
    if not _closed_fault_or_none(value.get("fault")):
        faults.append("evaluation-input fault is not closed")
    return sorted(set(faults))


def case_result_shape_faults(value: Any) -> list[str]:
    """Validate the exact live result object, including its time envelope."""

    if not isinstance(value, dict):
        return ["result.json root is not an object"]
    faults: list[str] = []
    if set(value) != CASE_RESULT_FIELDS:
        faults.append("result.json fields differ from the closed schema")
    if value.get("schemaVersion") != SCHEMA_VERSION:
        faults.append("result.json schemaVersion is not current")
    if not isinstance(value.get("case"), dict):
        faults.append("result.json case is not an object")
    started_at = _utc_datetime(value.get("startedAt"))
    finished_at = _utc_datetime(value.get("finishedAt"))
    if started_at is None:
        faults.append("result.json startedAt is not a UTC timestamp")
    if finished_at is None:
        faults.append("result.json finishedAt is not a UTC timestamp")
    if (
        started_at is not None
        and finished_at is not None
        and finished_at < started_at
    ):
        faults.append("result.json time envelope is reversed")
    if not _non_empty_string(value.get("verdict")):
        faults.append("result.json verdict is not a string")
    if value.get("observationState") not in OBSERVATION_STATES:
        faults.append("result.json observationState is not closed")
    observation_digest = value.get("observationDigest")
    if (
        observation_digest is not None
        and (
            not isinstance(observation_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", observation_digest) is None
        )
    ):
        faults.append("result.json observationDigest is malformed")
    for field_name in (
        "safetyStop",
        "enteredInjection",
        "cleanupComplete",
        "containmentRequired",
        "runtimeContainmentRequired",
    ):
        if not isinstance(value.get(field_name), bool):
            faults.append(f"result.json {field_name} is not a boolean")
    for field_name in ("containmentReasons", "runtimeContainmentReasons"):
        reasons = value.get(field_name)
        if not isinstance(reasons, list) or not all(
            isinstance(item, str) for item in reasons
        ):
            faults.append(f"result.json {field_name} is not a string list")
    if not _closed_fault_or_none(value.get("fault")):
        faults.append("result.json fault is not closed")
    if value.get("claimBoundary") != case_claim_boundary():
        faults.append("result.json claimBoundary drifted")
    return sorted(set(faults))


def run_case(
    *,
    args: argparse.Namespace,
    campaign_id: str,
    case_plan: dict[str, Any],
    output_dir: Path,
    oracle_profile: dict[str, Any],
    oracle_profile_path: Path,
    environment: dict[str, Any],
    source_hashes: dict[str, Any],
    ssh: EsxiSsh,
    transfer: esxi_aer.EsxiScp,
    api: esxi_aer.ApiSession,
) -> dict[str, Any]:
    case_id = case_plan["caseId"]
    case_dir = output_dir / "cases" / case_id
    case_dir.mkdir(parents=True, exist_ok=False)
    started_at = utc_now()
    monitor = Path(args.qemu_monitor)
    qtest_socket = Path(args.qtest_socket)
    requested_gate = SUPPORTED_GATES[case_plan["gate"]]
    case_spec = {
        "schemaVersion": SCHEMA_VERSION,
        "modelId": RUNNER_MODEL_ID,
        "campaignId": campaign_id,
        "caseRunId": f"{campaign_id}--{case_id}",
        **case_plan,
        "qemuDevice": args.qemu_device,
        "controlledBits": [
            {"name": B0_NAME, "mask": f"0x{B0:08x}"},
            {"name": B1_NAME, "mask": f"0x{B1:08x}"},
        ],
        "requestedGate": requested_gate.as_dict(),
        "ownerContract": OWNER_PHASES[case_plan["ownerPhase"]],
        "logWindowProtocol": log_v2.protocol_for_case(
            campaign_id,
            case_id,
        ),
        "claimBoundary": case_claim_boundary(),
        "safetyBoundary": {
            "injectionClass": "Correctable-only",
            "hmpForm": (
                "pcie_aer_inject_error -c <closed-qdev> "
                "<B0-or-B1-mask>"
            ),
            "uncorrectableInjectionSurface": False,
            "maximumSafetyPollIntervalSeconds": (
                args.maximum_safety_poll_interval_seconds
            ),
            "safetyPollTargetIntervalSeconds": (
                args.safety_poll_target_interval_seconds
            ),
            "qtestWritableFields": [
                "Endpoint CES.B0/B1 W1C",
                "Endpoint Device Status.CED W1C",
                "Endpoint CEM.B0/B1",
                "Endpoint Device Control.CERE",
                "Root Bridge Control.SERR",
                "Root Device Control.CERE",
                "Root Error Command.COR_EN",
                "Root Correctable Status W1C",
            ],
        },
    }
    save_json(case_dir / "case.json", case_spec)

    run_manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "runId": campaign_id,
        "campaignId": campaign_id,
        "caseRunId": case_spec["caseRunId"],
        "caseId": case_id,
        "ownerPhase": case_plan["ownerPhase"],
        "sequence": case_plan["sequence"],
        "gate": case_plan["gate"],
        "repeatIndex": case_plan["repeatIndex"],
        "qemuDevice": args.qemu_device,
        "startedAt": started_at,
        "host": {
            "platform": platform.platform(),
            "python": sys.version,
        },
        "runner": {
            "path": str(Path(__file__).resolve()),
            "sha256": frozen_input_hash(
                source_hashes,
                Path(__file__).resolve(),
            ),
        },
        "runtimeDependencies": source_hashes["repositoryInputs"],
        "oracleProfile": {
            "path": str(oracle_profile_path),
            "sha256": frozen_input_hash(
                source_hashes,
                oracle_profile_path,
            ),
            "id": oracle_profile["id"],
            "profileState": oracle_profile["profileState"],
            "schemaSha256": frozen_input_hash(
                source_hashes,
                ORACLE_PROFILE_SCHEMA,
            ),
        },
        "environment": environment,
        "timelineDelaysSeconds": args.timeline_delays,
        "finalObservationSecondsO0": args.final_observation_seconds,
        "freshExplicitBaselinePerCase": True,
        "sourcePolicy": oracle_profile["sourcePolicy"],
    }
    save_json(case_dir / "run-manifest.json", run_manifest)
    save_json(case_dir / "source-and-binary-hashes.json", source_hashes)

    t0: dict[str, Any] = {
        "startedAt": utc_now(),
        "environment": environment,
        "explicitBaselineClear": None,
        "hostPhase": None,
        "logWindowPreflightInventory": None,
        "beforeMarker": None,
        "beforeMarkerVisibility": None,
        "ownerObservation": None,
        "guestBefore": None,
        "faults": [],
    }
    t1: dict[str, Any] = {
        "requestedGate": requested_gate.as_dict(),
        "controlledBits": f"0x{CONTROLLED_BITS:08x}",
        "gateLease": None,
        "activeVm": None,
        "remoteIsoSha256": None,
    }
    t2: dict[str, Any] = {"steps": []}
    t3: dict[str, Any] = {"injections": [], "snapshots": []}
    t4: dict[str, Any] = {
        "windows": [],
        "hostTerminalPhase": None,
        "hostProjection": None,
        "guest": None,
        "afterMarker": None,
        "afterMarkerVisibility": None,
        "logWindowCapture": None,
        "logWindow": None,
    }
    t5: dict[str, Any] = {
        "operations": [],
        "gateRestore": None,
        "activeVmCleanup": None,
        "finalQemuState": None,
    }
    cleanup: dict[str, Any] = {
        "startedAt": utc_now(),
        "actions": [],
        "complete": False,
    }

    active_vm: esxi_aer.ActiveVm | None = None
    startup_recorder: LiveSequenceRecorder | None = None
    preflight_recorder: LiveSequenceRecorder | None = None
    cleanup_recorder: LiveSequenceRecorder | None = None
    cleanup_topology: dict[str, Any] | None = None
    lease: dict[str, Any] | None = None
    recorder: LiveSequenceRecorder | None = None
    baseline_phase: dict[str, Any] | None = None
    terminal_phase: dict[str, Any] | None = None
    log_window: dict[str, Any] | None = None
    guest_evidence: dict[str, Any] | None = None
    terminal_label: str | None = None
    entered_injection = False
    fault: dict[str, Any] | None = None
    safety_latched = False
    explicit_safety_faults: list[dict[str, Any]] = []
    containment_evidence: list[dict[str, Any]] = []
    containment_required = False
    containment_reasons: list[str] = []
    preflight = {
        "environmentBound": False,
        "ownerBound": False,
        "cleanBaseline": False,
        "gatePausedReadback": False,
        "evidenceProtocolReady": False,
    }

    def verified_runtime_injection_boundary() -> bool:
        return verified_entered_injection_from_records(
            recorder.injections if recorder is not None else [],
            sequence=case_plan["sequence"],
            qemu_device=args.qemu_device,
            outer_endpoint_bdf=args.outer_endpoint_bdf,
            outer_root_bdf=args.outer_root_bdf,
        )

    try:
        drift_faults = runtime_dependency_drift(
            source_hashes,
            environment,
        )
        if drift_faults:
            raise esxi_aer.BlockedEnvironment(
                "frozen runtime dependency drift: "
                + "; ".join(drift_faults)
            )
        if not args.authorized_lab_target:
            raise esxi_aer.BlockedEnvironment(
                "--authorized-lab-target is required for execution"
            )
        if esxi_aer.qemu_runtime_state(monitor) != "running":
            raise esxi_aer.BlockedEnvironment(
                f"outer QEMU is not running: {monitor}"
            )
        if not qtest_socket.exists():
            raise esxi_aer.BlockedEnvironment(
                f"QTest socket is absent: {qtest_socket}"
            )
        info_pci = hmp_command(monitor, "info pci")
        save_text(case_dir / "raw-esxi" / "qemu-info-pci-preflight.txt", info_pci)
        if not re.search(
            rf'id\s+"{re.escape(args.qemu_device)}"',
            info_pci,
        ):
            raise esxi_aer.BlockedEnvironment(
                f"QEMU device {args.qemu_device!r} is absent"
            )

        initial_pci = ssh.run(
            "localcli hardware pci list",
            check=False,
            timeout=60,
        )
        target = esxi_aer.extract_esxcli_device(
            initial_pci.stdout,
            args.esxi_endpoint_bdf,
        )
        if target is None:
            raise esxi_aer.BlockedEnvironment(
                f"ESXi inventory lacks {args.esxi_endpoint_bdf}"
            )
        binding_faults = validate_environment_binding(
            args=args,
            environment=environment,
            target=target,
            source_hashes=source_hashes,
            oracle_profile=oracle_profile,
        )
        if binding_faults:
            t0["faults"].extend(binding_faults)
            raise esxi_aer.BlockedEnvironment(
                "environment binding failed: " + "; ".join(binding_faults)
            )
        preflight["environmentBound"] = True

        initial_users = api.active_passthrough_users(
            args.esxi_endpoint_bdf
        )
        if initial_users:
            raise esxi_aer.BlockedEnvironment(
                "target already has active passthrough users before the "
                f"runner-created O4 VM: {initial_users}"
            )
        expected_pre_vm_owner = (
            "VMkernel"
            if case_plan["ownerPhase"] == "O0"
            else "VM Passthru"
        )
        if target.get("Current Owner") != expected_pre_vm_owner:
            raise esxi_aer.BlockedEnvironment(
                f"pre-case Current Owner={target.get('Current Owner')!r}, "
                f"expected={expected_pre_vm_owner!r}"
            )

        if case_plan["ownerPhase"] == "O4":
            vendor_id, device_id = esxi_aer.target_ids(target)
            local_iso = Path(args.local_iso).resolve()
            local_attestation = load_aer_iso_attestation(
                Path(args.local_iso_attestation).resolve(),
                local_iso,
                oracle_profile["timingEnvelope"],
            )
            remote_hash = ssh.run(
                f"sha256sum {shlex.quote(args.remote_iso)}",
                check=False,
                timeout=60,
            )
            remote_match = re.fullmatch(
                r"([0-9a-f]{64})\s+\*?.+",
                remote_hash.stdout.strip(),
            )
            t1["remoteIsoSha256"] = {
                "path": args.remote_iso,
                "returnCode": remote_hash.returncode,
                "stdout": remote_hash.stdout.strip(),
                "localIso": local_attestation,
                "exactMatch": bool(
                    remote_hash.returncode == 0
                    and remote_match is not None
                    and remote_match.group(1)
                    == local_attestation["isoSha256"]
                ),
            }
            if not t1["remoteIsoSha256"]["exactMatch"]:
                raise esxi_aer.BlockedEnvironment(
                    "remote AER ISO is not the locally attested build"
                )
            active_vm = esxi_aer.ActiveVm(
                ssh=ssh,
                transfer=transfer,
                api=api,
                case_dir=case_dir,
                run_id=campaign_id,
                case_id=case_id,
                datastore=args.datastore,
                remote_iso=args.remote_iso,
                base_vmx=Path(args.base_vmx),
                bdf=args.esxi_endpoint_bdf,
                vendor_id=vendor_id,
                device_id=device_id,
                marker_timeout=args.guest_marker_timeout,
            )
            guest_before_path = (
                case_dir / "guest-serial" / "before-sequence.log"
            )
            t1["activeVmStartupPause"] = esxi_aer.transition_qemu(
                monitor,
                "stop",
                "paused",
            )
            startup_topology = esxi_aer.outer_qemu_aer_snapshot(
                qtest_socket,
                args.outer_endpoint_bdf,
                args.outer_root_bdf,
            )
            startup_baseline = {
                "label": "o4-owner-activation-paused-baseline",
                "safetyBoundary": "PRE_INJECTION",
                "snapshot": startup_topology,
                "safetyFaults": [],
                "partial": True,
            }
            t1["activeVmStartupPausedBaseline"] = startup_baseline
            startup_safety_faults = (
                esxi_aer._partial_numeric_safety_faults(startup_topology)
            )
            startup_baseline["safetyFaults"] = startup_safety_faults
            if startup_safety_faults:
                explicit_safety_faults.append(
                    {
                        "label": "o4-owner-activation-paused-baseline",
                        "faults": startup_safety_faults,
                        "snapshot": startup_topology,
                    }
                )
                raise esxi_aer.SafetyViolation(
                    "unsafe state existed before O4 owner activation: "
                    + "; ".join(startup_safety_faults)
                )
            startup_baseline["partial"] = False
            startup_recorder = LiveSequenceRecorder(
                args=args,
                case_dir=case_dir,
                monitor=monitor,
                qtest_socket=qtest_socket,
                ssh=ssh,
                api=api,
                active_vm=active_vm,
                requested_gate=esxi_aer.gate_tuple_from_snapshot(
                    startup_topology,
                    CONTROLLED_BITS,
                ),
                topology=startup_topology,
            )
            startup_recorder.paused = True

            def active_vm_start_worker(
                cancel: threading.Event,
            ) -> dict[str, Any]:
                start_result = active_vm.start(cancel)
                if cancel.is_set():
                    return {"cancelledBySafetyMonitor": True}
                window = active_vm.require_window_remaining(
                    float(args.guest_min_window_seconds)
                )
                active_vm.copy_guest_serial(
                    guest_before_path,
                    required=True,
                )
                return {
                    "start": start_result,
                    "window": window,
                    "guestSerialArtifact": str(
                        guest_before_path.relative_to(case_dir)
                    ).replace("\\", "/"),
                }

            try:
                active_start_result, active_start_monitor = (
                    startup_recorder.monitored_runnable(
                        label="o4-owner-activation",
                        description=(
                            "start the runner-created DirectPath guest and "
                            "wait for its bounded AER window under continuous "
                            "Correctable-only safety polling"
                        ),
                        worker=active_vm_start_worker,
                        enforce_gate=False,
                    )
                )
            finally:
                t1["activeVmSafetyWindows"] = startup_recorder.t4
            t1["activeVm"] = active_start_result
            t1["activeVmSafetyMonitor"] = {
                "maximumPollIntervalSeconds": active_start_monitor[
                    "maximumPollIntervalSeconds"
                ],
                "maximumObservedPollGapSeconds": active_start_monitor[
                    "maximumObservedPollGapSeconds"
                ],
                "sampleCount": active_start_monitor["sampleCount"],
                "safetyEvents": active_start_monitor["safetyEvents"],
            }
            guest_before_text = guest_before_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
            guest_evidence = parse_guest_owner_evidence(
                guest_before_text,
                expected_vendor_id=active_vm.vendor_id,
                expected_device_id=active_vm.device_id,
            )
            t0["guestBefore"] = {
                "artifact": str(
                    guest_before_path.relative_to(case_dir)
                ).replace("\\", "/"),
                "ownerEvidence": guest_evidence,
            }
            guest_heartbeats = guest_evidence.get("heartbeats")
            latest_heartbeat = (
                guest_heartbeats[-1]
                if isinstance(guest_heartbeats, list)
                and guest_heartbeats
                and isinstance(guest_heartbeats[-1], dict)
                else None
            )
            published_remaining = (
                int(latest_heartbeat["remaining"])
                if isinstance(latest_heartbeat, dict)
                and isinstance(latest_heartbeat.get("remaining"), int)
                else None
            )
            # The guest emits a heartbeat every five seconds.  Treat the
            # published value minus one full interval as the conservative
            # lower bound at collection time; the local marker-observation
            # timestamp alone can overestimate the remaining window.
            conservative_remaining = (
                max(0, published_remaining - 5)
                if published_remaining is not None
                else None
            )
            t0["guestBefore"]["windowRemainingEvidence"] = {
                "source": "latest guest AER-HEARTBEAT remaining",
                "publishedSeconds": published_remaining,
                "heartbeatIntervalAllowanceSeconds": 5,
                "conservativeLowerBoundSeconds": conservative_remaining,
                "requiredSeconds": args.guest_min_window_seconds,
            }
            if (
                conservative_remaining is None
                or conservative_remaining < args.guest_min_window_seconds
            ):
                raise esxi_aer.BlockedEnvironment(
                    "O4 guest heartbeat does not prove the required "
                    "remaining injection window"
                )
            if not guest_evidence["beforeDriverBound"]:
                raise esxi_aer.BlockedEnvironment(
                    "O4 guest probe does not prove a bound target driver; "
                    "rebuild/upload the instrumented AER ISO"
                )

        try:
            baseline_clear = esxi_aer.clear_outer_qemu_aer_baseline(
                monitor,
                qtest_socket,
                args.outer_endpoint_bdf,
                args.outer_root_bdf,
                "strict",
                leave_paused=True,
            )
        except esxi_aer.BaselineClearFailure as error:
            baseline_clear = error.result
            t0["explicitBaselineClear"] = baseline_clear
            if error.safety:
                safety_latched = True
                raise esxi_aer.SafetyViolation(str(error)) from error
            raise esxi_aer.InconclusiveObservation(str(error)) from error
        t0["explicitBaselineClear"] = baseline_clear
        preflight["cleanBaseline"] = bool(baseline_clear.get("clean"))

        clean_snapshot = esxi_aer.outer_qemu_aer_snapshot(
            qtest_socket,
            args.outer_endpoint_bdf,
            args.outer_root_bdf,
        )
        clean_readback = {
            "label": "post-baseline-clear-paused-readback",
            "safetyBoundary": "PRE_INJECTION",
            "snapshot": clean_snapshot,
            "safetyFaults": [],
            "partial": True,
        }
        t0["postBaselineClearPausedReadback"] = clean_readback
        clean_safety_faults = esxi_aer._partial_numeric_safety_faults(
            clean_snapshot
        )
        clean_readback["safetyFaults"] = clean_safety_faults
        if clean_safety_faults:
            explicit_safety_faults.append(
                {
                    "label": "post-baseline-clear-paused-readback",
                    "faults": clean_safety_faults,
                    "snapshot": clean_snapshot,
                }
            )
            raise esxi_aer.SafetyViolation(
                "baseline clear ended with unsafe state: "
                + "; ".join(clean_safety_faults)
            )
        clean_readback["partial"] = False
        mask_bits = int(
            clean_snapshot["endpointState"]["correctableErrorMask"]
        ) & CONTROLLED_BITS
        if mask_bits not in (0, CONTROLLED_BITS):
            raise esxi_aer.InconclusiveObservation(
                "B0/B1 have mixed original mask values; the shared exact "
                "sequence lease refuses a lossy restore"
            )

        log_protocol = case_spec["logWindowProtocol"]
        preflight_recorder = LiveSequenceRecorder(
            args=args,
            case_dir=case_dir,
            monitor=monitor,
            qtest_socket=qtest_socket,
            ssh=ssh,
            api=api,
            active_vm=active_vm,
            requested_gate=esxi_aer.gate_tuple_from_snapshot(
                clean_snapshot,
                CONTROLLED_BITS,
            ),
            topology=clean_snapshot,
        )
        preflight_recorder.paused = True

        def collect_pre_sequence_evidence(
            cancel: threading.Event,
        ) -> dict[str, Any]:
            log_open = open_v2_log_window(
                ssh=ssh,
                campaign_id=campaign_id,
                case_id=case_id,
                protocol=log_protocol,
                cancel=cancel,
                evidence=t0,
            )
            if log_open.get("cancelledBySafetyMonitor") is True:
                return log_open
            phase = collect_remote_phase_cancellable(
                case_dir=case_dir,
                phase="raw-esxi/t0-baseline",
                ssh=ssh,
                api=api,
                bdf=args.esxi_endpoint_bdf,
                root_bdf=args.esxi_root_bdf,
                log_lines=args.log_lines,
                cancel=cancel,
            )
            kernel = esxi_aer.kernel_preconditions(
                case_dir / "raw-esxi" / "t0-baseline"
            )
            if not all(kernel.values()):
                raise esxi_aer.BlockedEnvironment(
                    "ESXi AER runtime kernel preconditions are not effective"
                )
            if cancel.is_set():
                return {"cancelledBySafetyMonitor": True}
            owner = owner_observation_from_phase(
                phase=phase,
                active_vm=active_vm,
                label="t0-owner",
            )
            owner_faults = owner_binding_faults(
                owner_phase=case_plan["ownerPhase"],
                observation=owner,
            )
            if owner_faults:
                raise esxi_aer.BlockedEnvironment(
                    "owner binding failed: " + "; ".join(owner_faults)
                )
            return {
                **log_open,
                "hostPhase": phase,
                "kernelPreconditions": kernel,
                "ownerObservation": owner,
            }

        try:
            pre_sequence, pre_sequence_monitor = (
                preflight_recorder.monitored_runnable(
                    label="pre-sequence-evidence-collection",
                    description=(
                        "validate the retained ESXi log rotation-chain layout, "
                        "write an official per-source BEFORE marker, and "
                        "collect baseline host/owner proof under continuous "
                        "Correctable-only safety polling"
                    ),
                    worker=collect_pre_sequence_evidence,
                    enforce_gate=False,
                )
            )
        finally:
            t0["preSequenceSafetyWindows"] = preflight_recorder.t4
        if (
            not isinstance(pre_sequence, dict)
            or pre_sequence.get("cancelledBySafetyMonitor") is True
        ):
            raise FixtureInvalid(
                "pre-sequence evidence collection did not complete"
            )
        t0["preSequenceSafetyMonitor"] = {
            "maximumPollIntervalSeconds": pre_sequence_monitor[
                "maximumPollIntervalSeconds"
            ],
            "maximumObservedPollGapSeconds": pre_sequence_monitor[
                "maximumObservedPollGapSeconds"
            ],
            "sampleCount": pre_sequence_monitor["sampleCount"],
            "safetyEvents": pre_sequence_monitor["safetyEvents"],
        }
        t0["logWindowPreflightInventory"] = pre_sequence[
            "logWindowPreflightInventory"
        ]
        t0["beforeMarker"] = pre_sequence["beforeMarker"]
        t0["beforeMarkerVisibility"] = pre_sequence[
            "beforeMarkerVisibility"
        ]
        baseline_phase = pre_sequence["hostPhase"]
        baseline_phase["outerQemuAer"] = pre_sequence_monitor[
            "firstSnapshot"
        ]
        baseline_phase["outerQemuAerCapturedAt"] = (
            pre_sequence_monitor["samples"][0]["observedAt"]
            if pre_sequence_monitor["samples"]
            else None
        )
        baseline_phase["outerQemuAerPostRemote"] = pre_sequence_monitor[
            "lastSnapshot"
        ]
        baseline_phase["outerQemuAerSamples"] = [
            {
                "sampleIndex": index,
                "actualElapsedSeconds": item.get("delaySeconds"),
                "observedAt": item.get("observedAt"),
                "snapshot": copy.deepcopy(item.get("snapshot")),
            }
            for index, item in enumerate(pre_sequence_monitor["samples"])
            if isinstance(item, dict)
            and isinstance(item.get("snapshot"), dict)
        ]
        save_json(
            case_dir / "raw-esxi" / "t0-baseline" / "phase.json",
            baseline_phase,
        )
        t0["hostPhase"] = baseline_phase
        t0["kernelPreconditions"] = pre_sequence[
            "kernelPreconditions"
        ]
        initial_owner = pre_sequence["ownerObservation"]
        t0["ownerObservation"] = initial_owner
        preflight["ownerBound"] = True

        try:
            lease = esxi_aer.apply_gate_lease(
                monitor,
                qtest_socket,
                args.outer_endpoint_bdf,
                args.outer_root_bdf,
                CONTROLLED_BITS,
                requested_gate,
                enable_root_path=True,
                timeline_delays=args.timeline_delays,
                maximum_safety_poll_interval=(
                    args.maximum_safety_poll_interval_seconds
                ),
                safety_poll_target_interval=(
                    args.safety_poll_target_interval_seconds
                ),
                hold_paused_after_sampling=True,
            )
        except esxi_aer.GateLeaseApplyFailure as error:
            lease = error.lease
            t1["gateLease"] = lease
            if error.safety:
                safety_latched = True
                raise esxi_aer.SafetyViolation(str(error)) from error
            raise esxi_aer.InconclusiveObservation(str(error)) from error
        t1["gateLease"] = lease
        if lease.get("outcome") in {
            "SAFETY_FAULT_DURING_APPLY",
            "SAFETY_FAULT_AFTER_APPLY",
        }:
            safety_latched = True
            raise esxi_aer.SafetyViolation(
                f"unsafe gate lease outcome: {lease.get('outcome')}"
            )
        if lease.get("outcome") != "EFFECTIVE":
            raise esxi_aer.InconclusiveObservation(
                "requested gate was not stable after resume: "
                f"{lease.get('outcome')}"
            )
        preflight["gatePausedReadback"] = True
        preflight["evidenceProtocolReady"] = True

        topology = lease["timeline"]["pausedApplied"]["snapshot"]
        recorder = LiveSequenceRecorder(
            args=args,
            case_dir=case_dir,
            monitor=monitor,
            qtest_socket=qtest_socket,
            ssh=ssh,
            api=api,
            active_vm=active_vm,
            requested_gate=requested_gate,
            topology=topology,
        )
        recorder.owner_observations.append(initial_owner)
        recorder.pause("capture M26 effective controls")
        recorder.capture(
            "effective-controls",
            phase="t2",
            operation="read back g101/g100 and root-path lease",
        )
        recorder.capture(
            "pre-injection",
            phase="t2",
            operation="last precise pre-injection state",
        )
        if active_vm is not None:
            recorder.t2.append(
                {
                    "recordKind": O4_GUEST_WINDOW_RECEIPT_RECORD_KIND,
                    "label": "o4-window-before-sequence",
                    "observedAt": utc_now(),
                    "window": active_vm.require_window_remaining(
                        float(args.guest_min_window_seconds)
                    ),
                }
            )
        terminal_label = execute_sequence_until_terminal(
            case_plan["sequence"],
            recorder,
        )
        entered_injection = verified_runtime_injection_boundary()

        def terminal_remote_worker(
            cancel: threading.Event,
        ) -> dict[str, Any]:
            return collect_remote_phase_cancellable(
                case_dir=case_dir,
                phase="raw-esxi/t4-terminal",
                ssh=ssh,
                api=api,
                bdf=args.esxi_endpoint_bdf,
                root_bdf=args.esxi_root_bdf,
                log_lines=args.log_lines,
                cancel=cancel,
            )

        terminal_phase, terminal_monitor = recorder.monitored_runnable(
            label="terminal-esxi-projection",
            description=(
                "collect terminal ESXi projection under continuous "
                "Correctable-only safety polling"
            ),
            worker=terminal_remote_worker,
        )
        terminal_phase["outerQemuAer"] = terminal_monitor["firstSnapshot"]
        terminal_phase["outerQemuAerCapturedAt"] = (
            terminal_monitor["samples"][0]["observedAt"]
            if terminal_monitor["samples"]
            else None
        )
        terminal_phase["outerQemuAerPostRemote"] = terminal_monitor[
            "lastSnapshot"
        ]
        terminal_phase["outerQemuAerSamples"] = [
            {
                "sampleIndex": index,
                "actualElapsedSeconds": item.get("delaySeconds"),
                "observedAt": item.get("observedAt"),
                "snapshot": copy.deepcopy(item.get("snapshot")),
            }
            for index, item in enumerate(terminal_monitor["samples"])
            if isinstance(item, dict)
            and isinstance(item.get("snapshot"), dict)
        ]
        terminal_phase["outerSafetyMonitor"] = {
            "pollIntervalSeconds": terminal_monitor[
                "pollIntervalSeconds"
            ],
            "sampleCount": terminal_monitor["sampleCount"],
            "safetyEvents": terminal_monitor["safetyEvents"],
            "monitorFault": terminal_monitor["monitorFault"],
        }
        save_json(
            case_dir / "raw-esxi" / "t4-terminal" / "phase.json",
            terminal_phase,
        )
        t4["hostTerminalPhase"] = terminal_phase
        t4["hostProjection"] = phase_projection(terminal_phase)
        host_projection_faults = host_projection_safety_faults(
            t4["hostProjection"]
        )
        if host_projection_faults:
            recorder.safety_faults.append(
                {
                    "label": "terminal-esxi-projection",
                    "faults": host_projection_faults,
                    "projection": copy.deepcopy(t4["hostProjection"]),
                }
            )
            raise esxi_aer.SafetyViolation(
                "unsafe Uncorrectable evidence appeared in the ESXi raw "
                "projection: "
                + "; ".join(host_projection_faults)
            )
        active_owner = owner_observation_from_phase(
            phase=terminal_phase,
            active_vm=active_vm,
            label="t4-terminal-owner",
        )
        recorder.owner_observations.append(active_owner)
        t4["terminalOwnerObservation"] = active_owner

        terminal_snapshot = recorder.capture(
            "terminal-post-host-window",
            phase="t4",
            operation=(
                "post-resume terminal snapshot after ESXi raw projection"
            ),
        )
        recorder.snapshots[terminal_label] = outer_to_public_state(
            terminal_snapshot
        )

        if active_vm is not None:
            final_guest_path = (
                case_dir / "guest-serial" / "after-sequence.log"
            )

            def guest_completion_worker(
                cancel: threading.Event,
            ) -> dict[str, Any]:
                if not active_vm.remote_dir or not active_vm.serial_name:
                    raise esxi_aer.InconclusiveObservation(
                        "active VM serial path is unavailable"
                    )
                serial_path = (
                    f"{active_vm.remote_dir}/{active_vm.serial_name}"
                )
                deadline = time.monotonic() + args.guest_complete_timeout
                while time.monotonic() < deadline:
                    if cancel.is_set():
                        return {"cancelledBySafetyMonitor": True}
                    probe = ssh.run(
                        "grep -F '=== AER guest probe done ===' "
                        f"{shlex.quote(serial_path)} 2>/dev/null",
                        check=False,
                        timeout=30,
                    )
                    if (
                        probe.returncode == 0
                        and "guest probe done" in probe.stdout
                    ):
                        break
                    cancel.wait(2)
                else:
                    raise esxi_aer.InconclusiveObservation(
                        "active DirectPath guest did not produce its "
                        "post-injection marker"
                    )
                if cancel.is_set():
                    return {"cancelledBySafetyMonitor": True}
                active_vm.copy_guest_serial(
                    final_guest_path,
                    required=True,
                )
                return {
                    "artifact": str(
                        final_guest_path.relative_to(case_dir)
                    ).replace("\\", "/")
                }

            guest_result, guest_monitor = recorder.monitored_runnable(
                label="guest-completion",
                description=(
                    "wait for the runner-managed O4 guest terminal marker "
                    "under continuous Correctable-only safety polling"
                ),
                worker=guest_completion_worker,
            )
            final_guest_text = final_guest_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
            guest_evidence = parse_guest_owner_evidence(
                final_guest_text,
                expected_vendor_id=active_vm.vendor_id,
                expected_device_id=active_vm.device_id,
            )
            t4["guest"] = {
                **guest_result,
                "ownerEvidence": guest_evidence,
                "safetyMonitor": {
                    "pollIntervalSeconds": guest_monitor[
                        "pollIntervalSeconds"
                    ],
                    "sampleCount": guest_monitor["sampleCount"],
                    "safetyEvents": guest_monitor["safetyEvents"],
                },
                "kernelEventLines": esxi_aer.guest_aer_event_lines(
                    final_guest_text
                ),
            }
        elif args.final_observation_seconds:
            recorder.monitored_runnable(
                label="o0-final-observation",
                description="bounded O0 terminal observation",
                worker=lambda cancel: cancel.wait(
                    args.final_observation_seconds
                ),
            )

        def close_log_window_worker(
            cancel: threading.Event,
        ) -> dict[str, Any]:
            return close_v2_log_window(
                ssh=ssh,
                transfer=transfer,
                case_dir=case_dir,
                campaign_id=campaign_id,
                case_id=case_id,
                protocol=log_protocol,
                cancel=cancel,
                evidence=t4,
                derive_window=False,
            )

        log_close_result, log_close_monitor = recorder.monitored_runnable(
            label="close-log-window",
            description=(
                "write the official per-source AFTER marker, stage the "
                "retained rotation chains, and rebuild the strict sequence "
                "log window before restore or VM teardown"
            ),
            worker=close_log_window_worker,
        )
        if (
            not isinstance(log_close_result, dict)
            or log_close_result.get("cancelledBySafetyMonitor") is True
        ):
            raise esxi_aer.InconclusiveObservation(
                "the official per-source marker/rotation-chain log window "
                "did not complete"
            )
        t4["afterMarker"] = log_close_result["afterMarker"]
        t4["afterMarkerVisibility"] = log_close_result[
            "afterMarkerVisibility"
        ]
        t4["logWindowCapture"] = log_close_result["capture"]
        # QEMU is paused again here.  Decode, hash and semantically classify
        # only the immutable local capture so Python CPU work cannot starve the
        # 50 ms Correctable-only fail-stop sampler.
        log_window = log_v2.rebuild_log_window(
            case_dir=case_dir,
            campaign_id=campaign_id,
            case_id=case_id,
            case_protocol=log_protocol,
            capture_summary=log_close_result["capture"],
            semantic_classifier=esxi_aer.aer_log_lines,
        )
        t4["logWindow"] = log_window
        t4["logWindowSafetyMonitor"] = {
            "maximumPollIntervalSeconds": log_close_monitor[
                "maximumPollIntervalSeconds"
            ],
            "maximumObservedPollGapSeconds": log_close_monitor[
                "maximumObservedPollGapSeconds"
            ],
            "sampleCount": log_close_monitor["sampleCount"],
            "safetyEvents": log_close_monitor["safetyEvents"],
        }
        if log_window.get("complete") is not True:
            raise esxi_aer.InconclusiveObservation(
                "the official per-source marker/rotation-chain log window "
                "is incomplete"
            )

        recorder.clear(
            "post-cleanup",
            operations=("clear-ces", "clear-ced", "clear-root"),
            public_description=(
                "W1C Endpoint CES.B0/B1, Device Status.CED and "
                "Root Correctable Status"
            ),
            require_gate=False,
            safety_boundary="POST_CLEANUP",
        )
    except esxi_aer.BlockedEnvironment as error:
        entered_injection = verified_runtime_injection_boundary()
        fault = {"type": type(error).__name__, "message": str(error)}
    except (esxi_aer.InconclusiveObservation, FixtureInvalid) as error:
        entered_injection = verified_runtime_injection_boundary()
        fault = {"type": type(error).__name__, "message": str(error)}
    except esxi_aer.SafetyViolation as error:
        safety_latched = True
        containment_required = True
        containment_reasons.append(
            f"observed safety violation: {error}"
        )
        if recorder is None or not recorder.safety_faults:
            explicit_safety_faults.append(
                {
                    "label": "safety-violation",
                    "faults": [str(error)],
                }
            )
        entered_injection = verified_runtime_injection_boundary()
        fault = {"type": type(error).__name__, "message": str(error)}
    except Exception as error:
        entered_injection = verified_runtime_injection_boundary()
        fault = {"type": type(error).__name__, "message": str(error)}
    except BaseException as error:
        # A control interruption after any possible ``cont``/injection
        # dispatch is converted into a manifest-bound containment result.  The
        # cleanup/fail-stop transaction below must run and persist before the
        # process can finish the case.
        entered_injection = verified_runtime_injection_boundary()
        containment_required = True
        containment_reasons.append(
            "control interruption required fail-stop: "
            f"{type(error).__name__}: {error}"
        )
        fault = {
            "type": type(error).__name__,
            "message": str(error),
        }
    finally:
        cleanup_decision = derive_cleanup_containment_decision(
            recorder=recorder,
            entered_injection=entered_injection,
            containment_required=containment_required,
            containment_reasons=containment_reasons,
            safety_latched=safety_latched,
        )
        containment_required = cleanup_decision["containmentRequired"]
        containment_reasons = cleanup_decision["containmentReasons"]
        if recorder is not None:
            t2["steps"] = recorder.t2
            t3["injections"] = recorder.injections
            t3["snapshots"] = recorder.t3
            t4["windows"] = recorder.t4
            t5["operations"] = recorder.t5

        if lease is not None:
            safe_stop = cleanup_decision["safeStop"]
            try:
                # restore_gate_lease performs its own paused read/modify/read
                # transaction.  Never briefly resume a dirty or unattributable
                # partial sequence merely to pause it again for restore.
                restore = esxi_aer.restore_gate_lease(
                    monitor,
                    qtest_socket,
                    args.outer_endpoint_bdf,
                    args.outer_root_bdf,
                    CONTROLLED_BITS,
                    lease,
                    safe_stop=safe_stop,
                    timeline_delays=args.timeline_delays,
                    maximum_safety_poll_interval=(
                        args.maximum_safety_poll_interval_seconds
                    ),
                    safety_poll_target_interval=(
                        args.safety_poll_target_interval_seconds
                    ),
                    hold_paused_after_sampling=True,
                )
                t5["gateRestore"] = restore
                cleanup["actions"].append(
                    {
                        "gateRestore": restore.get("outcome"),
                        "safeStop": safe_stop,
                    }
                )
                restore_outcome = str(restore.get("outcome"))
                restore_safety_faults = list(
                    restore.get("resumedSafetyFaults") or []
                )
                paused_restore = restore.get("timeline", {}).get(
                    "pausedApplied",
                    {},
                )
                if isinstance(paused_restore, dict) and paused_restore.get(
                    "safetyFaults"
                ):
                    restore_safety_faults.append(
                        {
                            "delaySeconds": None,
                            "faults": paused_restore["safetyFaults"],
                            "phase": "paused-restore",
                        }
                    )
                if "SAFETY_FAULT" in restore_outcome or restore_safety_faults:
                    safety_latched = True
                    containment_required = True
                    containment_reasons.append(
                        f"restore observed safety evidence: {restore_outcome}"
                    )
                    explicit_safety_faults.extend(
                        {
                            "label": (
                                "post-cleanup-gate-restore"
                                f"-{index:02d}"
                            ),
                            "faults": list(item.get("faults") or []),
                            "observation": copy.deepcopy(item),
                        }
                        for index, item in enumerate(
                            restore_safety_faults,
                            start=1,
                        )
                        if isinstance(item, dict)
                    )
                    if (
                        "SAFETY_FAULT" in restore_outcome
                        and not restore_safety_faults
                    ):
                        explicit_safety_faults.append(
                            {
                                "label": "post-cleanup-gate-restore-outcome",
                                "faults": [restore_outcome],
                            }
                        )
                    containment_evidence.extend(
                        {
                            "label": "gate-restore",
                            "faults": list(item.get("faults") or []),
                            "observation": item,
                        }
                        for item in restore_safety_faults
                        if isinstance(item, dict)
                    )
                if safe_stop:
                    containment_required = True
                elif restore_outcome != "RESTORED":
                    containment_required = True
                    containment_reasons.append(
                        f"gate restore incomplete: {restore_outcome}"
                    )
                    fault = fault or {
                        "type": "GateRestoreIncomplete",
                        "message": (
                            "gate A-B-A restore did not reach RESTORED: "
                            f"{restore_outcome}"
                        ),
                    }
            except esxi_aer.GateLeaseRestoreFailure as error:
                partial_restore = error.result
                t5["gateRestore"] = partial_restore
                t5["gateRestoreFault"] = {
                    "type": type(error).__name__,
                    "message": str(error),
                }
                partial_safety_faults = list(
                    partial_restore.get("resumedSafetyFaults") or []
                )
                paused_partial = partial_restore.get("timeline", {}).get(
                    "pausedApplied",
                    {},
                )
                if (
                    isinstance(paused_partial, dict)
                    and paused_partial.get("safetyFaults")
                ):
                    partial_safety_faults.append(
                        {
                            "delaySeconds": None,
                            "faults": paused_partial["safetyFaults"],
                            "phase": "paused-restore",
                        }
                    )
                if error.safety or partial_safety_faults:
                    safety_latched = True
                    explicit_safety_faults.extend(
                        {
                            "label": (
                                "post-cleanup-gate-restore-partial"
                                f"-{index:02d}"
                            ),
                            "faults": list(item.get("faults") or []),
                            "observation": copy.deepcopy(item),
                        }
                        for index, item in enumerate(
                            partial_safety_faults,
                            start=1,
                        )
                        if isinstance(item, dict)
                    )
                    if error.safety and not partial_safety_faults:
                        explicit_safety_faults.append(
                            {
                                "label": (
                                    "post-cleanup-gate-restore-partial-outcome"
                                ),
                                "faults": [
                                    str(partial_restore.get("outcome"))
                                ],
                            }
                        )
                containment_required = True
                containment_reasons.append(
                    "gate restore partial failure: "
                    f"{type(error).__name__}: {error}"
                )
                fault = fault or t5["gateRestoreFault"]
                try:
                    if esxi_aer.qemu_runtime_state(monitor) != "paused":
                        t5["emergencyHold"] = esxi_aer.transition_qemu(
                            monitor,
                            "stop",
                            "paused",
                        )
                except BaseException as hold_error:
                    t5["emergencyHoldFault"] = {
                        "type": type(hold_error).__name__,
                        "message": str(hold_error),
                    }
                    containment_reasons.append(
                        "emergency hold could not be confirmed: "
                        f"{type(hold_error).__name__}: {hold_error}"
                    )
            except BaseException as error:
                containment_required = True
                containment_reasons.append(
                    f"gate restore fault: {type(error).__name__}: {error}"
                )
                t5["gateRestoreFault"] = {
                    "type": type(error).__name__,
                    "message": str(error),
                }
                fault = fault or t5["gateRestoreFault"]
                try:
                    state_after_restore_fault = esxi_aer.qemu_runtime_state(
                        monitor
                    )
                    if state_after_restore_fault != "paused":
                        t5["emergencyHold"] = esxi_aer.transition_qemu(
                            monitor,
                            "stop",
                            "paused",
                        )
                except BaseException as hold_error:
                    t5["emergencyHoldFault"] = {
                        "type": type(hold_error).__name__,
                        "message": str(hold_error),
                    }
                    containment_reasons.append(
                        "emergency hold could not be confirmed: "
                        f"{type(hold_error).__name__}: {hold_error}"
                    )

        if containment_required:
            try:
                if esxi_aer.qemu_runtime_state(monitor) != "paused":
                    t5["containmentHold"] = esxi_aer.transition_qemu(
                        monitor,
                        "stop",
                        "paused",
                    )
            except BaseException as hold_error:
                t5["containmentHoldFault"] = {
                    "type": type(hold_error).__name__,
                    "message": str(hold_error),
                }
                containment_reasons.append(
                    "containment hold could not be confirmed: "
                    f"{type(hold_error).__name__}: {hold_error}"
                )

        try:
            pre_cleanup_qemu_state = esxi_aer.qemu_runtime_state(monitor)
        except BaseException as state_error:
            pre_cleanup_qemu_state = "unknown"
            t5["preCleanupQemuStateFault"] = {
                "type": type(state_error).__name__,
                "message": str(state_error),
            }
            containment_required = True
            containment_reasons.append(
                "outer QEMU state could not be read before cleanup: "
                f"{type(state_error).__name__}: {state_error}"
            )
        t5["preCleanupQemuState"] = pre_cleanup_qemu_state
        if pre_cleanup_qemu_state not in {"running", "paused"}:
            containment_required = True
            containment_reasons.append(
                "outer QEMU state was unknown before cleanup"
            )
            try:
                t5["unknownStateEmergencyHold"] = (
                    esxi_aer.transition_qemu(
                        monitor,
                        "stop",
                        "paused",
                    )
                )
            except BaseException as hold_error:
                t5["unknownStateEmergencyHoldFault"] = {
                    "type": type(hold_error).__name__,
                    "message": str(hold_error),
                }
        if active_vm is not None:
            if containment_required:
                t5["activeVmCleanup"] = {
                    "deferred": True,
                    "reason": (
                        "outer QEMU is held paused for safety evidence; "
                        "recover/quarantine the lab before VM cleanup"
                    ),
                }
            else:
                try:
                    if pre_cleanup_qemu_state == "running":
                        t5["activeVmCleanupPause"] = (
                            esxi_aer.transition_qemu(
                                monitor,
                                "stop",
                                "paused",
                            )
                        )
                    cleanup_topology = esxi_aer.outer_qemu_aer_snapshot(
                        qtest_socket,
                        args.outer_endpoint_bdf,
                        args.outer_root_bdf,
                    )
                    t5["activeVmCleanupPausedBaseline"] = {
                        "safetyBoundary": "POST_CLEANUP",
                        "snapshot": cleanup_topology,
                        "safetyFaults": [],
                        "partial": True,
                    }
                    cleanup_baseline_faults = (
                        esxi_aer._partial_numeric_safety_faults(
                            cleanup_topology
                        )
                    )
                    t5["activeVmCleanupPausedBaseline"][
                        "safetyFaults"
                    ] = cleanup_baseline_faults
                    if cleanup_baseline_faults:
                        explicit_safety_faults.append(
                            {
                                "label": (
                                    "post-cleanup-active-vm-paused-baseline"
                                ),
                                "faults": cleanup_baseline_faults,
                                "snapshot": cleanup_topology,
                            }
                        )
                        raise esxi_aer.SafetyViolation(
                            "unsafe state existed before active VM cleanup: "
                                + "; ".join(cleanup_baseline_faults)
                            )
                    t5["activeVmCleanupPausedBaseline"]["partial"] = False
                    cleanup_recorder = LiveSequenceRecorder(
                        args=args,
                        case_dir=case_dir,
                        monitor=monitor,
                        qtest_socket=qtest_socket,
                        ssh=ssh,
                        api=api,
                        active_vm=active_vm,
                        requested_gate=(
                            esxi_aer.gate_tuple_from_snapshot(
                                cleanup_topology,
                                CONTROLLED_BITS,
                            )
                        ),
                        topology=cleanup_topology,
                        forced_safety_boundary="POST_CLEANUP",
                    )
                    cleanup_recorder.paused = True
                    vm_cleanup_monitor: dict[str, Any] | None = None
                    try:
                        vm_cleanup, vm_cleanup_monitor = (
                            cleanup_recorder.monitored_runnable(
                                label="post-cleanup-active-vm-cleanup",
                                description=(
                                    "power off, unregister and release the "
                                    "runner-created DirectPath VM under "
                                    "continuous Correctable-only safety polling"
                                ),
                                worker=lambda cancel: active_vm.cleanup(cancel),
                                enforce_gate=False,
                            )
                        )
                    finally:
                        # Retain sampler gaps/faults even when the worker or
                        # fail-stop path raises.
                        t5["activeVmCleanupSafetyWindows"] = (
                            cleanup_recorder.t4
                        )
                    t5["activeVmCleanup"] = vm_cleanup
                    assert vm_cleanup_monitor is not None
                    t5["activeVmCleanupSafetyMonitor"] = {
                        "maximumPollIntervalSeconds": vm_cleanup_monitor[
                            "maximumPollIntervalSeconds"
                        ],
                        "maximumObservedPollGapSeconds": vm_cleanup_monitor[
                            "maximumObservedPollGapSeconds"
                        ],
                        "sampleCount": vm_cleanup_monitor["sampleCount"],
                        "safetyEvents": vm_cleanup_monitor["safetyEvents"],
                    }
                    cleanup["actions"].append(
                        {"activeVmCleanup": vm_cleanup}
                    )
                    vm_cleanup_checks = active_vm_cleanup_checks(
                        vm_cleanup,
                        expected_registered=active_vm.vmid is not None,
                    )
                    t5["activeVmCleanupChecks"] = vm_cleanup_checks
                    if not all(vm_cleanup_checks.values()):
                        containment_required = True
                        containment_reasons.append(
                            "active VM cleanup postconditions failed"
                        )
                        fault = fault or {
                            "type": "ActiveVmCleanupIncomplete",
                            "message": json.dumps(
                                vm_cleanup_checks,
                                sort_keys=True,
                            ),
                        }
                except esxi_aer.SafetyViolation as error:
                    safety_latched = True
                    containment_required = True
                    containment_reasons.append(
                        "active VM cleanup observed safety evidence: "
                        f"{error}"
                    )
                    t5["activeVmCleanup"] = {
                        "error": f"{type(error).__name__}: {error}"
                    }
                    fault = fault or {
                        "type": type(error).__name__,
                        "message": str(error),
                    }
                except BaseException as error:
                    t5["activeVmCleanup"] = {
                        "error": f"{type(error).__name__}: {error}"
                    }
                    fault = fault or {
                        "type": type(error).__name__,
                        "message": str(error),
                    }
                    containment_required = True
                    containment_reasons.append(
                        "active VM cleanup raised an exception"
                    )
        if not containment_required:
            try:
                state_before_final_tail = esxi_aer.qemu_runtime_state(
                    monitor
                )
                t5["stateBeforeFinalSafetyTail"] = state_before_final_tail
                if state_before_final_tail == "paused":
                    final_tail_inputs = (
                        capture_paused_final_tail_inputs(
                            args=args,
                            qtest_socket=qtest_socket,
                            lease=lease,
                            cleanup_topology=cleanup_topology,
                        )
                    )
                    final_tail_baseline = final_tail_inputs["baseline"]
                    t5["finalSafetyTailPausedBaseline"] = (
                        final_tail_baseline
                    )
                    final_tail_faults = list(
                        final_tail_baseline["safetyFaults"]
                    )
                    if final_tail_faults:
                        safety_latched = True
                        explicit_safety_faults.append(
                            {
                                "label": (
                                    "post-cleanup-final-running-paused-"
                                    "baseline"
                                ),
                                "faults": final_tail_faults,
                                "snapshot": copy.deepcopy(
                                    final_tail_baseline["snapshot"]
                                ),
                            }
                        )
                        raise esxi_aer.SafetyViolation(
                            "unsafe state existed before final running "
                            "safety tail: "
                            + "; ".join(final_tail_faults)
                        )
                    final_tail = resume_with_safety_stabilization(
                        args=args,
                        monitor=monitor,
                        qtest_socket=qtest_socket,
                        label="post-cleanup-final-running-stabilization",
                        expected_gate=final_tail_inputs["expectedGate"],
                        expected_root_path=final_tail_inputs[
                            "expectedRootPath"
                        ],
                        topology=final_tail_inputs["topology"],
                    )
                    t5["finalRunningSafetyTail"] = final_tail
                    tail_safety_events = list(
                        (
                            final_tail.get("safetyPoll") or {}
                        ).get("safetyEvents")
                        or []
                    )
                    if tail_safety_events:
                        safety_latched = True
                        explicit_safety_faults.extend(
                            {
                                "label": (
                                    "post-cleanup-final-running-tail"
                                    f"-{index:02d}"
                                ),
                                "faults": list(item.get("faults") or []),
                                "snapshot": copy.deepcopy(
                                    item.get("snapshot")
                                ),
                            }
                            for index, item in enumerate(
                                tail_safety_events,
                                start=1,
                            )
                            if isinstance(item, dict)
                        )
                    if final_tail.get("outcome") != "CLEAN_RUNNING":
                        containment_required = True
                        containment_reasons.append(
                            "final running safety tail did not stabilize: "
                            f"{final_tail.get('outcome')}"
                        )
                        fault = fault or {
                            "type": (
                                "SafetyViolation"
                                if tail_safety_events
                                else "FinalSafetyTailIncomplete"
                            ),
                            "message": str(final_tail.get("outcome")),
                        }
                elif state_before_final_tail != "running":
                    containment_required = True
                    containment_reasons.append(
                        "outer QEMU state was neither paused nor running "
                        "before final safety tail"
                    )
            except BaseException as error:
                containment_required = True
                containment_reasons.append(
                    "final running safety tail raised: "
                    f"{type(error).__name__}: {error}"
                )
                fault = fault or {
                    "type": type(error).__name__,
                    "message": str(error),
                }
        if containment_required:
            try:
                if esxi_aer.qemu_runtime_state(monitor) != "paused":
                    t5["postCleanupContainmentHold"] = (
                        esxi_aer.transition_qemu(
                            monitor,
                            "stop",
                            "paused",
                        )
                    )
            except BaseException as hold_error:
                t5["postCleanupContainmentHoldFault"] = {
                    "type": type(hold_error).__name__,
                    "message": str(hold_error),
                }
                containment_reasons.append(
                    "post-cleanup hold could not be confirmed: "
                    f"{type(hold_error).__name__}: {hold_error}"
                )
        try:
            final_qemu_state = esxi_aer.qemu_runtime_state(monitor)
        except BaseException as state_error:
            final_qemu_state = "unknown"
            t5["finalQemuStateFault"] = {
                "type": type(state_error).__name__,
                "message": str(state_error),
            }
            containment_required = True
            containment_reasons.append(
                "outer QEMU final state could not be read: "
                f"{type(state_error).__name__}: {state_error}"
            )
        t5["finalQemuState"] = final_qemu_state
        if final_qemu_state != "running" and not containment_required:
            containment_required = True
            containment_reasons.append(
                "outer QEMU did not finish in the confirmed running state"
            )
            try:
                t5["finalStateEmergencyHold"] = (
                    esxi_aer.transition_qemu(
                        monitor,
                        "stop",
                        "paused",
                    )
                )
            except BaseException as hold_error:
                t5["finalStateEmergencyHoldFault"] = {
                    "type": type(hold_error).__name__,
                    "message": str(hold_error),
                }
        cleanup["complete"] = bool(
            not containment_required
            and final_qemu_state == "running"
            and (
                active_vm is None
                or (
                    isinstance(t5.get("activeVmCleanup"), dict)
                    and not t5["activeVmCleanup"].get("error")
                    and not t5["activeVmCleanup"].get("deferred")
                    and isinstance(
                        t5.get("activeVmCleanupChecks"),
                        dict,
                    )
                    and all(t5["activeVmCleanupChecks"].values())
                )
            )
            and (
                lease is None
                or (
                    isinstance(t5.get("gateRestore"), dict)
                    and t5["gateRestore"].get("outcome") == "RESTORED"
                )
            )
        )
        t5["containment"] = {
            "required": containment_required,
            "reasons": containment_reasons,
            "observedSafetySideEffect": safety_latched,
        }
        cleanup["containmentRequired"] = containment_required
        cleanup["finishedAt"] = utc_now()

    # A monitored runnable may fail closed after the immutable rotation chain
    # was staged but before its return value reached the caller.  Recover that
    # raw capture locally after cleanup so runtime and offline evaluators bind
    # the same log classification.  No ESXi/QEMU surface is accessed here.
    if not isinstance(log_window, dict):
        retained_log_window = t4.get("logWindow")
        if isinstance(retained_log_window, dict):
            log_window = retained_log_window
        elif isinstance(t4.get("logWindowCapture"), dict):
            try:
                log_window = log_v2.rebuild_log_window(
                    case_dir=case_dir,
                    campaign_id=campaign_id,
                    case_id=case_id,
                    case_protocol=log_protocol,
                    capture_summary=t4["logWindowCapture"],
                    semantic_classifier=esxi_aer.aer_log_lines,
                )
                t4["logWindow"] = log_window
            except BaseException as error:
                t4["logWindowDerivationFault"] = {
                    "type": type(error).__name__,
                    "message": str(error),
                }

    t0["finishedAt"] = utc_now()
    save_json(case_dir / "t0-baseline.json", t0)
    save_json(case_dir / "t1-effective-controls.json", t1)
    save_json(case_dir / "t2-pre-injection.json", t2)
    save_json(case_dir / "t3-immediate.json", t3)
    save_json(case_dir / "t4-window.json", t4)
    save_json(case_dir / "t5-transition-or-clear.json", t5)
    save_text(
        case_dir / "hmp.txt",
        (
            "\n".join(recorder.hmp_transcript)
            if recorder is not None
            else ""
        ),
    )
    save_json(case_dir / "cleanup.json", cleanup)

    snapshots = recorder.snapshots if recorder is not None else {}
    injections = recorder.injections if recorder is not None else []
    owner_observations = (
        recorder.owner_observations
        if recorder is not None
        else (
            [t0["ownerObservation"]]
            if isinstance(t0.get("ownerObservation"), dict)
            else []
        )
    )
    safety_faults = (
        copy.deepcopy(recorder.safety_faults)
        if recorder is not None
        else []
    )
    if startup_recorder is not None:
        safety_faults.extend(
            copy.deepcopy(startup_recorder.safety_faults)
        )
    if preflight_recorder is not None:
        safety_faults.extend(
            copy.deepcopy(preflight_recorder.safety_faults)
        )
    if cleanup_recorder is not None:
        safety_faults.extend(
            copy.deepcopy(cleanup_recorder.safety_faults)
        )
    safety_faults.extend(copy.deepcopy(explicit_safety_faults))
    runtime_guest_serial_evidence = rebuild_guest_serial_evidence(
        case_dir=case_dir,
        case_spec=case_spec,
        oracle_profile=oracle_profile,
        t0=t0,
        t1=t1,
        t4=t4,
    )
    o4_valid = raw_o4_guest_evidence_valid(
        runtime_guest_serial_evidence
    )
    t0["preflight"] = copy.deepcopy(preflight)
    t1["gateStable"] = bool(recorder and recorder.gate_stable)
    safety_coverage = build_safety_coverage(
        t0=t0,
        t1=t1,
        t2=t2,
        t3=t3,
        t4=t4,
        t5=t5,
        cleanup=cleanup,
    )
    evidence_protocol = derive_raw_evidence_protocol(
        sequence=str(case_plan["sequence"]),
        qemu_device=str(args.qemu_device),
        outer_endpoint_bdf=args.outer_endpoint_bdf,
        outer_root_bdf=args.outer_root_bdf,
        owner_phase=str(case_plan["ownerPhase"]),
        t0=t0,
        t1=t1,
        t2=t2,
        t3=t3,
        t4=t4,
        t5=t5,
        cleanup=cleanup,
        baseline_phase=baseline_phase,
        terminal_phase=terminal_phase,
        safety_coverage=safety_coverage,
        bounded_log_window_complete=bool(
            isinstance(log_window, dict)
            and log_window.get("complete") is True
        ),
    )
    evidence_complete = evidence_protocol["complete"]
    t5["evaluationEvidence"] = {
        "evidenceComplete": evidence_complete,
        "evidenceProtocolChecks": evidence_protocol["checks"],
        "runtimeSafetyFaults": copy.deepcopy(safety_faults),
        "containmentRequired": containment_required,
        "containmentReasons": copy.deepcopy(containment_reasons),
        "executionFault": copy.deepcopy(fault),
        "cleanupComplete": cleanup["complete"],
    }
    # These evaluator inputs are raw phase facts, not a second oracle.  Persist
    # them before deriving safetyObservations so offline reconstruction consumes
    # the exact same manifest-bound containers.
    save_json(case_dir / "t0-baseline.json", t0)
    save_json(case_dir / "t1-effective-controls.json", t1)
    save_json(case_dir / "t5-transition-or-clear.json", t5)
    save_json(case_dir / "cleanup.json", cleanup)
    safety_observations = build_numeric_safety_observations(
        t0=t0,
        t1=t1,
        t2=t2,
        t3=t3,
        t4=t4,
        t5=t5,
        cleanup=cleanup,
        baseline_phase=baseline_phase,
        terminal_phase=terminal_phase,
    )
    evaluation_input = {
        "schemaVersion": SCHEMA_VERSION,
        "campaignId": campaign_id,
        "caseRunId": case_spec["caseRunId"],
        "caseId": case_id,
        "sequence": case_plan["sequence"],
        "gate": case_plan["gate"],
        "ownerPhase": case_plan["ownerPhase"],
        "repeatIndex": case_plan["repeatIndex"],
        "qemuDevice": args.qemu_device,
        "requesterId": (
            int(recorder.endpoint["requesterId"])
            if entered_injection and recorder is not None
            else -1
        ),
        "enteredInjection": entered_injection,
        "preflight": preflight,
        "snapshots": snapshots,
        "injections": injections,
        "ownerObservations": owner_observations,
        "gateStable": bool(recorder and recorder.gate_stable),
        "hostProjection": phase_projection(terminal_phase),
        "hostLogClassification": (
            log_window.get("classification")
            if isinstance(log_window, dict)
            else "INCONCLUSIVE_LOG_WINDOW"
        ),
        "guestClassification": (
            "O4_BOUND_DRIVER_AND_HEARTBEAT"
            if o4_valid and case_plan["ownerPhase"] == "O4"
            else (
                "NOT_APPLICABLE_O0"
                if case_plan["ownerPhase"] == "O0"
                else "O4_GUEST_EVIDENCE_INCOMPLETE"
            )
        ),
        "o4GuestEvidenceValid": o4_valid,
        "evidenceComplete": evidence_complete,
        "safetyObservations": safety_observations,
        "safetyCoverage": safety_coverage,
        "safetyFaults": safety_faults,
        "containmentRequired": containment_required,
        "containmentReasons": containment_reasons,
        "containmentEvidence": containment_evidence,
        "fault": fault,
        "cleanupComplete": cleanup["complete"],
    }
    save_json(case_dir / "evaluation-input.json", evaluation_input)
    oracle = evaluate_case_observation(
        evaluation_input,
        oracle_profile,
        outer_endpoint_bdf=args.outer_endpoint_bdf,
        outer_root_bdf=args.outer_root_bdf,
    )
    if fault is not None:
        oracle["executionFault"] = fault
    save_json(case_dir / "oracle.json", oracle)

    result = {
        "schemaVersion": SCHEMA_VERSION,
        "case": case_spec,
        "startedAt": started_at,
        "finishedAt": utc_now(),
        "observationState": oracle["observationState"],
        "verdict": oracle["verdict"],
        "observationDigest": oracle.get("observationDigest"),
        "safetyStop": oracle.get("safetyStop", False),
        "enteredInjection": entered_injection,
        "fault": fault,
        "cleanupComplete": cleanup["complete"],
        # ``containmentRequired`` is the oracle/effective conclusion used by
        # the case and campaign result.  Preserve the runtime state under
        # explicit fields so offline evidence-derived containment cannot make
        # a newly written result internally contradictory.
        "containmentRequired": oracle["containmentRequired"],
        "containmentReasons": oracle["containmentReasons"],
        "runtimeContainmentRequired": containment_required,
        "runtimeContainmentReasons": containment_reasons,
        "claimBoundary": case_claim_boundary(),
    }
    save_json(case_dir / "result.json", result)
    manifest_digest = write_artifact_manifest(case_dir)
    return {
        "caseId": case_id,
        "caseRunId": case_spec["caseRunId"],
        "ownerPhase": case_plan["ownerPhase"],
        "sequence": case_plan["sequence"],
        "gate": case_plan["gate"],
        "repeatIndex": case_plan["repeatIndex"],
        "observationState": oracle["observationState"],
        "verdict": oracle["verdict"],
        "observationDigest": oracle.get("observationDigest"),
        "safetyStop": oracle.get("safetyStop", False),
        "enteredInjection": entered_injection,
        "fault": fault,
        "cleanupComplete": cleanup["complete"],
        "containmentRequired": oracle["containmentRequired"],
        "result": {
            "path": str(
                (case_dir / "result.json").relative_to(output_dir)
            ).replace("\\", "/"),
            "sha256": sha256_file(case_dir / "result.json"),
        },
        "manifest": {
            "path": str(
                (case_dir / "artifact-manifest.sha256").relative_to(
                    output_dir
                )
            ).replace("\\", "/"),
            "sha256": manifest_digest,
        },
    }


def parse_timeline_delays(raw: str) -> tuple[float, ...]:
    try:
        values = tuple(float(item.strip()) for item in raw.split(","))
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "timeline delays must be comma-separated numbers"
        ) from error
    if (
        not values
        or any(value < 0 for value in values)
        or tuple(sorted(values)) != values
        or len(set(values)) != len(values)
    ):
        raise argparse.ArgumentTypeError(
            "timeline delays must be unique, non-negative and ascending"
        )
    return values


def normalize_campaign_execution_policy(
    *,
    campaign_plan: dict[str, Any],
    campaign_result: dict[str, Any],
    expected_plan_cases: list[dict[str, Any]],
) -> tuple[dict[str, Any], str]:
    plan_policy = campaign_plan.get("executionPolicy")
    result_policy = campaign_result.get("executionPolicy")
    if plan_policy is None and result_policy is None:
        return (
            build_execution_policy(expected_plan_cases, None),
            "LEGACY_IMPLICIT_FULL_PROFILE",
        )
    if (
        not isinstance(plan_policy, dict)
        or plan_policy != result_policy
    ):
        raise ManifestError(
            "campaign execution policies are missing or inconsistent"
        )
    mode = plan_policy.get("mode")
    if mode == EXECUTION_MODE_FULL_PROFILE:
        requested_target = None
    elif mode == EXECUTION_MODE_STOP_AFTER_CASE:
        requested_target = plan_policy.get("stopAfterCaseId")
    else:
        raise ManifestError("unsupported campaign execution policy")
    try:
        expected_policy = build_execution_policy(
            expected_plan_cases,
            requested_target,
        )
    except ValueError as error:
        raise ManifestError(
            f"invalid campaign execution policy: {error}"
        ) from error
    if plan_policy != expected_policy:
        raise ManifestError(
            "campaign execution policy is not deterministic"
        )
    return copy.deepcopy(expected_policy), "MANIFEST_BOUND"


def verify_campaign_termination(
    *,
    campaign_result: dict[str, Any],
    planned_ids: list[str],
    completed_ids: list[str],
    incomplete_ids: list[str],
    execution_policy: dict[str, Any],
) -> dict[str, Any]:
    present_causes: list[str] = []
    for name in CAMPAIGN_TERMINATION_FIELDS:
        value = campaign_result.get(name)
        if value is None:
            continue
        if not isinstance(value, dict) or not value:
            raise ManifestError(
                f"campaign termination cause {name} is malformed"
            )
        present_causes.append(name)
    if len(present_causes) > 1:
        raise ManifestError(
            "campaign has mutually exclusive termination causes: "
            f"{present_causes}"
        )
    termination_cause = (
        present_causes[0] if present_causes else None
    )
    if incomplete_ids and termination_cause is None:
        raise ManifestError(
            "partial campaign has no manifest-bound termination cause"
        )

    case_bound_causes = {
        "safetyStop",
        "cleanupStop",
        "blockedStop",
        "boundaryStop",
    }
    if termination_cause in case_bound_causes:
        if not completed_ids:
            raise ManifestError(
                "case-bound termination has no completed case"
            )
        stop = campaign_result[termination_cause]
        if (
            stop.get("afterCase") != completed_ids[-1]
            or stop.get("remainingCaseIds") != incomplete_ids
        ):
            raise ManifestError(
                "campaign termination boundary differs from the "
                "completed-prefix partition"
            )
    elif termination_cause == "fault":
        fault = campaign_result["fault"]
        if (
            not isinstance(fault.get("type"), str)
            or not isinstance(fault.get("message"), str)
        ):
            raise ManifestError("campaign fault is malformed")

    completed_count = len(completed_ids)
    if execution_policy["mode"] == EXECUTION_MODE_FULL_PROFILE:
        if termination_cause == "boundaryStop":
            raise ManifestError(
                "FULL_PROFILE campaign cannot claim boundaryStop"
            )
    else:
        stop_ordinal = execution_policy["stopAfterOrdinal"]
        if completed_count > stop_ordinal:
            raise ManifestError(
                "campaign executed beyond its requested case boundary"
            )
        if not incomplete_ids:
            raise ManifestError(
                "bounded campaign unexpectedly claims full-plan completion"
            )
        if termination_cause == "boundaryStop":
            try:
                expected_boundary = build_boundary_stop(
                    execution_policy,
                    planned_ids,
                )
            except ValueError as error:
                raise ManifestError(
                    f"invalid campaign boundary stop: {error}"
                ) from error
            if (
                completed_count != stop_ordinal
                or campaign_result["boundaryStop"]
                != expected_boundary
            ):
                raise ManifestError(
                    "boundaryStop differs from deterministic execution policy"
                )

    full_plan_executed = not incomplete_ids
    full_plan_complete = (
        full_plan_executed and termination_cause is None
    )
    if full_plan_complete:
        completion_class = "FULL_PLAN"
    else:
        completion_class = {
            "boundaryStop": "INTENTIONAL_PREFIX",
            "safetyStop": "SAFETY_STOP",
            "cleanupStop": "CLEANUP_STOP",
            "blockedStop": "BLOCKED_STOP",
            "fault": "FAULT_STOP",
        }[termination_cause]
    return {
        "terminationCause": termination_cause,
        "completionClass": completion_class,
        "fullPlanExecuted": full_plan_executed,
        "fullPlanComplete": full_plan_complete,
    }


def verify_campaign(output_dir: Path) -> dict[str, Any]:
    reject_symlinks_under(output_dir)
    case_root = output_dir / "cases"
    if not case_root.is_dir():
        raise ManifestError(f"campaign cases directory is missing: {case_root}")
    case_results: list[dict[str, Any]] = []
    for case_dir in sorted(path for path in case_root.iterdir() if path.is_dir()):
        verification = verify_artifact_manifest(case_dir)
        case_result = load_json(case_dir / "result.json")
        case_results.append(
            {
                "caseId": case_dir.name,
                "verification": verification,
                "observationState": case_result.get("observationState"),
            }
        )
    root_manifest = output_dir / "artifact-manifest.sha256"
    if not root_manifest.is_file():
        raise ManifestError(
            f"campaign manifest is missing: {root_manifest}"
        )
    root_entries = 0
    root_seen: set[str] = set()
    for line_number, line in enumerate(
        root_manifest.read_text(encoding="ascii").splitlines(),
        start=1,
    ):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        if not match:
            raise ManifestError(
                f"invalid campaign manifest line {line_number}: {line!r}"
            )
        expected, relative = match.groups()
        relative_path = Path(relative)
        canonical_relative = relative_path.as_posix()
        if (
            canonical_relative in root_seen
            or relative != canonical_relative
            or relative_path.is_absolute()
            or ".." in relative_path.parts
            or "." in relative_path.parts
            or any(":" in part for part in relative_path.parts)
            or canonical_relative == root_manifest.name
        ):
            raise ManifestError(
                f"unsafe or duplicate campaign manifest path: {relative!r}"
            )
        root_seen.add(canonical_relative)
        target = (output_dir / relative_path).resolve()
        try:
            target.relative_to(output_dir.resolve())
        except ValueError as error:
            raise ManifestError(
                f"campaign manifest path escapes output: {relative!r}"
            ) from error
        if not target.is_file() or sha256_file(target) != expected:
            raise ManifestError(
                f"campaign manifest target missing or drifted: {relative}"
            )
        root_entries += 1
    root_present = {
        path.relative_to(output_dir).as_posix()
        for path in output_dir.rglob("*")
        if path.is_file() and path != root_manifest
    }
    root_unbound = sorted(root_present - root_seen)
    if root_unbound:
        raise ManifestError(
            f"campaign manifest leaves files unbound: {root_unbound}"
        )
    missing_campaign_artifacts = sorted(
        name
        for name in REQUIRED_CAMPAIGN_ARTIFACTS
        if not (output_dir / name).is_file()
    )
    if missing_campaign_artifacts:
        raise ManifestError(
            "campaign is missing required artifacts: "
            f"{missing_campaign_artifacts}"
        )
    result_path = output_dir / "result.json"
    sidecar = output_dir / "result.json.sha256"
    if not result_path.is_file() or not sidecar.is_file():
        raise ManifestError("campaign result or SHA-256 sidecar is missing")
    sidecar_match = re.fullmatch(
        r"([0-9a-f]{64})  result\.json\n?",
        sidecar.read_text(encoding="ascii"),
    )
    if (
        sidecar_match is None
        or sidecar_match.group(1) != sha256_file(result_path)
    ):
        raise ManifestError("campaign result SHA-256 sidecar drift")
    campaign_result = load_json(result_path)
    campaign_plan = load_json(output_dir / "campaign-plan.json")
    profile_path = output_dir / "oracle-profile.json"
    profile_schema_path = output_dir / "oracle-profile.schema.json"
    profile_hash = sha256_file(profile_path)
    profile_schema_hash = sha256_file(profile_schema_path)
    if (
        campaign_result.get("oracleProfile", {}).get("sha256")
        != profile_hash
        or campaign_plan.get("oracleProfile", {}).get("sha256")
        != profile_hash
        or campaign_result.get("oracleProfile", {}).get("schemaSha256")
        != profile_schema_hash
        or campaign_plan.get("oracleProfile", {}).get("schemaSha256")
        != profile_schema_hash
    ):
        raise ManifestError(
            "campaign plan/result do not bind the frozen oracle profile "
            "and schema"
        )
    frozen_profile = load_oracle_profile(
        profile_path,
        profile_schema_path,
    )
    run_id = campaign_result.get("runId")
    campaign_identity_checks = {
        "run-id": (
            isinstance(run_id, str)
            and bool(run_id)
            and run_id == campaign_plan.get("runId")
        ),
        "owner-phase": (
            campaign_result.get("ownerPhase")
            == campaign_plan.get("ownerPhase")
        ),
        "gate": campaign_result.get("gate") == campaign_plan.get("gate"),
        "sequences": (
            campaign_result.get("sequences")
            == campaign_plan.get("sequences")
            == frozen_profile.get("requiredSequences")
        ),
        "repeat": (
            campaign_result.get("repeat")
            == campaign_plan.get("repeat")
            and isinstance(campaign_plan.get("repeat"), int)
            and campaign_plan.get("repeat")
            >= int(frozen_profile["minimumRepeats"])
        ),
        "schema-version": (
            campaign_result.get("schemaVersion")
            == campaign_plan.get("schemaVersion")
            == SCHEMA_VERSION
        ),
        "model-id": (
            campaign_result.get("modelId")
            == campaign_plan.get("modelId")
            == RUNNER_MODEL_ID
        ),
        "claim-boundary": (
            campaign_result.get("claimBoundary")
            == campaign_plan.get("claimBoundary")
            == case_claim_boundary()
        ),
        "execution-policy": (
            campaign_result.get("executionPolicy")
            == campaign_plan.get("executionPolicy")
        ),
    }
    if not all(campaign_identity_checks.values()):
        raise ManifestError(
            "campaign plan/result identity closure failed: "
            f"{campaign_identity_checks}"
        )
    planned_ids = campaign_result.get("plannedCaseIds")
    plan_cases = campaign_plan.get("cases")
    result_cases = campaign_result.get("cases")
    incomplete_ids = campaign_result.get("incompletePlan")
    if not all(
        isinstance(value, list)
        for value in (planned_ids, plan_cases, result_cases, incomplete_ids)
    ):
        raise ManifestError(
            "campaign plan/result case collections are malformed"
        )
    try:
        expected_plan_cases = build_case_plan(
            owner_phase=str(campaign_plan["ownerPhase"]),
            gate=str(campaign_plan["gate"]),
            sequences=list(frozen_profile["requiredSequences"]),
            repeat=int(campaign_plan["repeat"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ManifestError(
            "campaign plan cannot be regenerated from frozen inputs"
        ) from error
    if plan_cases != expected_plan_cases:
        raise ManifestError(
            "campaign cases differ from the deterministic frozen case plan"
        )
    expected_planned_ids = [
        item["caseId"] for item in expected_plan_cases
    ]
    if planned_ids != expected_planned_ids:
        raise ManifestError(
            "campaign plannedCaseIds differ from the deterministic case plan"
        )
    execution_policy, execution_policy_provenance = (
        normalize_campaign_execution_policy(
            campaign_plan=campaign_plan,
            campaign_result=campaign_result,
            expected_plan_cases=expected_plan_cases,
        )
    )
    plan_ids = [
        item.get("caseId") if isinstance(item, dict) else None
        for item in plan_cases
    ]
    if (
        any(
            not isinstance(case_id, str)
            or not CASE_ID_RE.fullmatch(case_id)
            for case_id in planned_ids
        )
        or len(planned_ids) != len(set(planned_ids))
        or plan_ids != planned_ids
    ):
        raise ManifestError(
            "campaign plannedCaseIds do not exactly match the case plan"
        )
    summary_by_id: dict[str, dict[str, Any]] = {}
    for item in result_cases:
        if not isinstance(item, dict):
            raise ManifestError("campaign case summary is not an object")
        case_id = item.get("caseId")
        if (
            not isinstance(case_id, str)
            or case_id in summary_by_id
            or not CASE_ID_RE.fullmatch(case_id)
        ):
            raise ManifestError(
                f"unsafe or duplicate campaign case summary: {case_id!r}"
            )
        summary_by_id[case_id] = item
    actual_case_ids = [item["caseId"] for item in case_results]
    if set(actual_case_ids) != set(summary_by_id):
        raise ManifestError(
            "campaign case directories differ from result case summaries"
        )
    if (
        any(not isinstance(case_id, str) for case_id in incomplete_ids)
        or len(incomplete_ids) != len(set(incomplete_ids))
        or set(summary_by_id) & set(incomplete_ids)
        or set(summary_by_id) | set(incomplete_ids) != set(planned_ids)
    ):
        raise ManifestError(
            "completed and incomplete case IDs do not partition the plan"
        )
    summary_order = [
        item.get("caseId") for item in result_cases
        if isinstance(item, dict)
    ]
    if (
        summary_order != planned_ids[: len(summary_order)]
        or incomplete_ids != planned_ids[len(summary_order) :]
    ):
        raise ManifestError(
            "completed cases are not the exact ordered prefix of the plan"
        )
    termination = verify_campaign_termination(
        campaign_result=campaign_result,
        planned_ids=planned_ids,
        completed_ids=summary_order,
        incomplete_ids=incomplete_ids,
        execution_policy=execution_policy,
    )
    plan_by_id = {
        item["caseId"]: item
        for item in plan_cases
        if isinstance(item, dict)
        and isinstance(item.get("caseId"), str)
    }
    verified_flat_cases: list[dict[str, Any]] = []
    root_source_hashes = (
        load_json(output_dir / "source-and-binary-hashes.json")
        if (output_dir / "source-and-binary-hashes.json").is_file()
        else None
    )
    for case_id, summary in summary_by_id.items():
        case_dir = case_root / case_id
        case_result_path = case_dir / "result.json"
        case_manifest_path = case_dir / "artifact-manifest.sha256"
        expected_result_relative = f"cases/{case_id}/result.json"
        expected_manifest_relative = (
            f"cases/{case_id}/artifact-manifest.sha256"
        )
        result_ref = summary.get("result")
        manifest_ref = summary.get("manifest")
        if (
            not isinstance(result_ref, dict)
            or result_ref.get("path") != expected_result_relative
            or result_ref.get("sha256")
            != sha256_file(case_result_path)
            or not isinstance(manifest_ref, dict)
            or manifest_ref.get("path") != expected_manifest_relative
            or manifest_ref.get("sha256")
            != sha256_file(case_manifest_path)
        ):
            raise ManifestError(
                f"campaign case references drifted for {case_id}"
            )
        raw_case_result = load_json(case_result_path)
        raw_case_spec = raw_case_result.get("case")
        raw_case_spec = (
            raw_case_spec if isinstance(raw_case_spec, dict) else {}
        )
        case_spec_file = load_json(case_dir / "case.json")
        case_run_manifest = load_json(case_dir / "run-manifest.json")
        case_source_hashes = load_json(
            case_dir / "source-and-binary-hashes.json"
        )
        planned_case = plan_by_id.get(case_id)
        planned_case = (
            planned_case if isinstance(planned_case, dict) else {}
        )
        cross_checks = {
            "case-object-file": raw_case_spec == case_spec_file,
            "case-id": (
                raw_case_spec.get("caseId") == case_id
            ),
            "campaign-id": (
                raw_case_spec.get("campaignId")
                == case_run_manifest.get("campaignId")
                == case_run_manifest.get("runId")
                == run_id
            ),
            "case-run-id": (
                summary.get("caseRunId")
                == raw_case_spec.get("caseRunId")
                == case_run_manifest.get("caseRunId")
                == f"{run_id}--{case_id}"
            ),
            "owner-phase": (
                summary.get("ownerPhase")
                == raw_case_spec.get("ownerPhase")
                == case_run_manifest.get("ownerPhase")
                == planned_case.get("ownerPhase")
                == campaign_plan.get("ownerPhase")
            ),
            "sequence": (
                summary.get("sequence")
                == raw_case_spec.get("sequence")
                == case_run_manifest.get("sequence")
                == planned_case.get("sequence")
            ),
            "gate": (
                summary.get("gate")
                == raw_case_spec.get("gate")
                == case_run_manifest.get("gate")
                == planned_case.get("gate")
                == campaign_plan.get("gate")
            ),
            "repeat-index": (
                summary.get("repeatIndex")
                == raw_case_spec.get("repeatIndex")
                == case_run_manifest.get("repeatIndex")
                == planned_case.get("repeatIndex")
            ),
            "environment": (
                root_source_hashes is not None
                and case_run_manifest.get("environment")
                == campaign_result.get("environment")
                == root_source_hashes.get("environment")
            ),
            "source-hashes": (
                root_source_hashes is not None
                and case_source_hashes == root_source_hashes
                and case_run_manifest.get("runtimeDependencies")
                == root_source_hashes.get("repositoryInputs")
            ),
            "observation-state": (
                summary.get("observationState")
                == raw_case_result.get("observationState")
            ),
            "verdict": summary.get("verdict") == raw_case_result.get("verdict"),
            "digest": (
                summary.get("observationDigest")
                == raw_case_result.get("observationDigest")
            ),
            "safety-stop": (
                summary.get("safetyStop")
                == raw_case_result.get("safetyStop")
            ),
            "entered-injection": (
                summary.get("enteredInjection")
                == raw_case_result.get("enteredInjection")
            ),
            "cleanup-complete": (
                summary.get("cleanupComplete")
                == raw_case_result.get("cleanupComplete")
            ),
            "containment-required": (
                summary.get("containmentRequired")
                == raw_case_result.get("containmentRequired")
            ),
        }
        if not all(cross_checks.values()):
            raise ManifestError(
                f"campaign/case result mismatch for {case_id}: "
                f"{cross_checks}"
            )
        offline_case = evaluate_case_directory(case_dir, profile_path)
        if offline_case.get("exactMatch") is not True:
            raise ManifestError(
                f"case {case_id} failed offline semantic recomputation: "
                f"{offline_case}"
            )
        verified_flat_cases.append(
            {
                "caseId": case_id,
                "caseRunId": raw_case_spec.get("caseRunId"),
                "ownerPhase": raw_case_spec.get("ownerPhase"),
                "sequence": raw_case_spec.get("sequence"),
                "gate": raw_case_spec.get("gate"),
                "repeatIndex": raw_case_spec.get("repeatIndex"),
                "observationState": raw_case_result.get(
                    "observationState"
                ),
                "verdict": raw_case_result.get("verdict"),
                "observationDigest": raw_case_result.get(
                    "observationDigest"
                ),
                "safetyStop": raw_case_result.get("safetyStop"),
                "enteredInjection": raw_case_result.get(
                    "enteredInjection"
                ),
                "cleanupComplete": raw_case_result.get(
                    "cleanupComplete"
                ),
                "containmentRequired": raw_case_result.get(
                    "containmentRequired"
                ),
            }
        )
        for item in case_results:
            if item["caseId"] == case_id:
                item["offlineEvaluation"] = offline_case
                break

    recomputed_aggregate = aggregate_campaign(
        verified_flat_cases,
        owner_phase=str(campaign_plan["ownerPhase"]),
        sequences=list(campaign_plan["sequences"]),
        minimum_repeats=int(frozen_profile["minimumRepeats"]),
    )
    if campaign_result.get("fault") and not verified_flat_cases:
        recomputed_aggregate["observationState"] = OBSERVATION_BLOCKED
    elif campaign_result.get("cleanupStop"):
        recomputed_aggregate["observationState"] = OBSERVATION_INCONCLUSIVE
    elif campaign_result.get("blockedStop"):
        recomputed_aggregate["observationState"] = OBSERVATION_BLOCKED
    elif campaign_result.get("boundaryStop"):
        recomputed_aggregate["observationState"] = OBSERVATION_INCONCLUSIVE
    elif incomplete_ids and not campaign_result.get("safetyStop"):
        recomputed_aggregate["observationState"] = OBSERVATION_INCONCLUSIVE
    if campaign_result.get("aggregate") != recomputed_aggregate:
        raise ManifestError(
            "campaign aggregate differs from trusted per-case recomputation"
        )
    return {
        "campaign": str(output_dir),
        "caseCount": len(case_results),
        "caseManifestEntries": sum(
            item["verification"]["entryCount"] for item in case_results
        ),
        "rootManifestEntries": root_entries,
        "resultSha256": sha256_file(result_path),
        "cases": case_results,
        "campaignIdentityChecks": campaign_identity_checks,
        "executionPolicy": execution_policy,
        "executionPolicyProvenance": execution_policy_provenance,
        "terminationCause": termination["terminationCause"],
        "completionClass": termination["completionClass"],
        "fullPlanExecuted": termination["fullPlanExecuted"],
        "fullPlanComplete": termination["fullPlanComplete"],
        "fullProfileConclusionEligible": (
            termination["fullPlanComplete"]
            and recomputed_aggregate["observationState"]
            in {OBSERVATION_MATCH, OBSERVATION_DIVERGED}
        ),
        "recomputedAggregate": recomputed_aggregate,
        "verified": True,
    }


def reconstruct_containment_evidence(t5: dict[str, Any]) -> list[dict[str, Any]]:
    """Rebuild the evaluator's containment detail from raw gate restore facts."""

    restore = t5.get("gateRestore")
    restore = restore if isinstance(restore, dict) else {}
    raw_resumed = restore.get("resumedSafetyFaults")
    resumed = raw_resumed if isinstance(raw_resumed, list) else []
    observations = [
        copy.deepcopy(item)
        for item in resumed
        if isinstance(item, dict)
    ]
    paused_applied = restore.get("timeline")
    paused_applied = (
        paused_applied.get("pausedApplied")
        if isinstance(paused_applied, dict)
        else None
    )
    if (
        isinstance(paused_applied, dict)
        and isinstance(paused_applied.get("safetyFaults"), list)
        and paused_applied["safetyFaults"]
    ):
        observations.append(
            {
                "delaySeconds": None,
                "faults": copy.deepcopy(paused_applied["safetyFaults"]),
                "phase": "paused-restore",
            }
        )
    return [
        {
            "label": "gate-restore",
            "faults": list(item.get("faults") or []),
            "observation": item,
        }
        for item in observations
    ]


def reconstruct_evaluation_sources(
    case_dir: Path,
    oracle_profile: dict[str, Any],
) -> dict[str, Any]:
    t0 = load_json(case_dir / "t0-baseline.json")
    t1 = load_json(case_dir / "t1-effective-controls.json")
    t2 = load_json(case_dir / "t2-pre-injection.json")
    t3 = load_json(case_dir / "t3-immediate.json")
    t4 = load_json(case_dir / "t4-window.json")
    t5 = load_json(case_dir / "t5-transition-or-clear.json")
    cleanup = load_json(case_dir / "cleanup.json")
    case_spec = load_json(case_dir / "case.json")
    run_manifest = load_json(case_dir / "run-manifest.json")
    lease_endpoint_bdf, lease_root_bdf = outer_bdf_pair_from_gate_lease(t1)
    frozen_outer_pair = _closed_outer_bdf_pair(
        lease_endpoint_bdf,
        lease_root_bdf,
    )
    outer_endpoint_bdf, outer_root_bdf = (
        frozen_outer_pair
        if frozen_outer_pair is not None
        else (None, None)
    )
    snapshots: dict[str, Any] = {}
    snapshot_record_faults: list[str] = []
    record_shape_faults: list[str] = []
    valid_t3_snapshots: dict[str, dict[str, Any]] = {}
    o4_guest_window_receipt_count = 0

    phase_artifacts = {
        "t0": t0,
        "t1": t1,
        "t2": t2,
        "t3": t3,
        "t4": t4,
        "t5": t5,
        "cleanup": cleanup,
    }
    for phase_name, phase_value in phase_artifacts.items():
        record_shape_faults.extend(
            phase_artifact_root_faults(phase_name, phase_value)
        )
    record_shape_faults.extend(
        frozen_outer_topology_faults(
            phase_artifacts=phase_artifacts,
            t1=t1,
            outer_endpoint_bdf=outer_endpoint_bdf,
            outer_root_bdf=outer_root_bdf,
            require_full_snapshot=bool(
                isinstance(t3.get("injections"), list)
                and t3["injections"]
            ),
        )
    )
    environment = run_manifest.get("environment")
    environment = environment if isinstance(environment, dict) else {}
    outer_qemu = environment.get("outerQemu")
    outer_qemu = outer_qemu if isinstance(outer_qemu, dict) else {}
    if frozen_outer_pair is not None or (
        isinstance(t3.get("injections"), list)
        and bool(t3["injections"])
    ):
        record_shape_faults.extend(
            qemu_argv_topology_faults(
                command_line=outer_qemu.get("commandLine"),
                qemu_device=case_spec.get("qemuDevice"),
                outer_endpoint_bdf=outer_endpoint_bdf,
                outer_root_bdf=outer_root_bdf,
            )
        )
    record_shape_faults.extend(
        optional_phase_field_faults(
            t0=t0,
            t1=t1,
            t4=t4,
            t5=t5,
            expected_gate=case_spec.get("gate"),
        )
    )
    phase_plan = planned_phase_records(
        sequence=case_spec.get("sequence"),
        owner_phase=case_spec.get("ownerPhase"),
        qemu_device=case_spec.get("qemuDevice"),
    )
    for phase, key, container in (
        ("t2", "steps", t2),
        ("t3", "snapshots", t3),
        ("t4", "windows", t4),
        ("t5", "operations", t5),
    ):
        if key not in container:
            record_shape_faults.append(f"{phase}.{key} is missing")
            continue
        records = container[key]
        if not isinstance(records, list):
            record_shape_faults.append(
                f"{phase}.{key} is not a list"
            )
            continue
        record_shape_faults.extend(
            phase_record_plan_faults(
                phase=phase,
                records=records,
                expected=phase_plan[phase],
            )
        )
        for index, item in enumerate(records):
            if not isinstance(item, dict):
                record_shape_faults.append(
                    f"{phase}.{key}[{index}] is not an object"
                )
                continue
            label = item.get("label")
            snapshot = item.get("snapshot")
            provenance = f"{phase}[{index}]"
            record_kind = item.get("recordKind")
            if record_kind == PAUSED_NUMERIC_SNAPSHOT_RECORD_KIND:
                faults = paused_numeric_snapshot_record_faults(
                    item,
                    expected_phase=phase,
                    expected_boundary={
                        "t2": "PRE_INJECTION",
                        "t3": "ATTRIBUTION_WINDOW",
                        "t4": "ATTRIBUTION_WINDOW",
                    }.get(phase),
                    expected_gate=case_spec.get("gate"),
                )
                if faults:
                    snapshot_record_faults.extend(
                        f"{provenance}: {fault}" for fault in faults
                    )
                    continue
                assert isinstance(label, str)
                assert isinstance(snapshot, dict)
                if label in snapshots:
                    snapshot_record_faults.append(
                        f"{provenance}: duplicate public snapshot label "
                        f"{label!r}"
                    )
                    continue
                public_snapshot = outer_to_public_state(snapshot)
                snapshots[label] = public_snapshot
                if phase == "t3":
                    valid_t3_snapshots[label] = snapshot
                continue
            if (
                record_kind
                == PRE_MUTATION_NUMERIC_SNAPSHOT_RECORD_KIND
            ):
                faults = pre_mutation_numeric_snapshot_record_faults(
                    item,
                    expected_gate=case_spec.get("gate"),
                )
                if phase not in {"t2", "t5"}:
                    faults.append(
                        "pre-mutation snapshot is outside t2/t5"
                    )
                if faults:
                    snapshot_record_faults.extend(
                        f"{provenance}: {fault}" for fault in faults
                    )
                # Pre-mutation authority is retained for numeric safety
                # reconstruction, but never projected into the public
                # behavior-oracle snapshot namespace.
                continue
            if record_kind == O4_GUEST_WINDOW_RECEIPT_RECORD_KIND:
                faults = o4_guest_window_receipt_faults(
                    item,
                    owner_phase=case_spec.get("ownerPhase"),
                    oracle_profile=oracle_profile,
                )
                if phase != "t2":
                    faults.append("O4 guest-window receipt is outside t2")
                if faults:
                    record_shape_faults.extend(
                        f"{provenance}: {fault}" for fault in faults
                    )
                o4_guest_window_receipt_count += 1
                continue
            if item.get("safetyWindowKind") in {
                "SERVICE_WINDOW",
                "MONITORED_WORKER",
            }:
                faults = runnable_window_record_shape_faults(
                    item,
                    phase=phase,
                    expected_gate=case_spec.get("gate"),
                )
                if faults:
                    record_shape_faults.extend(
                        f"{provenance}: {fault}" for fault in faults
                    )
                continue
            record_shape_faults.append(
                f"{provenance}: record lacks a closed phase record kind"
            )
    raw_injections = t3.get("injections")
    injection_shape_faults = injection_record_shape_faults(
        raw_injections,
        sequence=case_spec.get("sequence"),
        qemu_device=case_spec.get("qemuDevice"),
        outer_endpoint_bdf=outer_endpoint_bdf,
        outer_root_bdf=outer_root_bdf,
    )
    record_shape_faults.extend(
        f"t3.{fault}" for fault in injection_shape_faults
    )
    entered_injection = entered_injection_from_records(
        raw_injections,
        sequence=case_spec.get("sequence"),
        qemu_device=case_spec.get("qemuDevice"),
        outer_endpoint_bdf=outer_endpoint_bdf,
        outer_root_bdf=outer_root_bdf,
    )
    if o4_guest_window_receipt_count > 1:
        record_shape_faults.append(
            "t2 contains more than one O4 guest-window receipt"
        )
    if (
        entered_injection
        and case_spec.get("ownerPhase") == "O4"
        and o4_guest_window_receipt_count != 1
    ):
        record_shape_faults.append(
            "entered O4 case lacks exactly one guest-window receipt"
        )
    endpoint_parts = _canonical_outer_bdf_parts(outer_endpoint_bdf)
    expected_requester_id = (
        (
            endpoint_parts[1] << 8
            | endpoint_parts[2] << 3
            | endpoint_parts[3]
        )
        if endpoint_parts is not None
        else None
    )
    first_source_requester_id = -1
    if entered_injection:
        expected_injection_labels = (
            list(
                qemu_sequence.expected_injection_labels(
                    case_spec.get("sequence")
                )
            )
            if case_spec.get("sequence") in SEQUENCES
            else []
        )
        first_label = (
            expected_injection_labels[0]
            if expected_injection_labels
            else None
        )
        first_snapshot = valid_t3_snapshots.get(first_label)
        try:
            first_source_meaning = (
                root_source_meaning(
                    outer_to_public_state(first_snapshot)
                )
                if isinstance(first_snapshot, dict)
                else None
            )
        except (KeyError, TypeError, ValueError):
            first_source_meaning = None
        observed_requester_id = (
            first_source_meaning.get("correctableRequesterId")
            if isinstance(first_source_meaning, dict)
            and first_source_meaning.get("meaningful") is True
            else None
        )
        if (
            injection_shape_faults
            or first_label is None
            or not isinstance(first_snapshot, dict)
            or not isinstance(observed_requester_id, int)
            or isinstance(observed_requester_id, bool)
            or observed_requester_id != expected_requester_id
        ):
            record_shape_faults.append(
                "first verified post-ACK Root Source does not bind "
                "the frozen endpoint requester"
            )
        else:
            first_source_requester_id = observed_requester_id
    hmp_path = case_dir / "hmp.txt"
    expected_hmp_transcript = render_hmp_transcript(raw_injections)
    hmp_transcript_exact = bool(
        expected_hmp_transcript is not None
        and hmp_path.is_file()
        and not hmp_path.is_symlink()
        and hmp_path.read_bytes()
        == expected_hmp_transcript.encode("utf-8")
    )
    if not hmp_transcript_exact:
        record_shape_faults.append(
            "hmp.txt differs from the closed raw injection transcript"
        )
    terminal_alias = {
        "first-multiple": "stable-after-repeat",
        "independent-w1c": "after-root-clear-only",
        "bit-or": "stable-after-or",
        "rearm": "rearmed-window",
    }
    terminal_snapshot = snapshots.get("terminal-post-host-window")
    sequence = case_spec.get("sequence")
    if (
        isinstance(terminal_snapshot, dict)
        and sequence in terminal_alias
    ):
        snapshots[terminal_alias[sequence]] = copy.deepcopy(
            terminal_snapshot
        )
    owners = []
    for item in (
        t0.get("ownerObservation"),
        t4.get("terminalOwnerObservation"),
    ):
        if isinstance(item, dict):
            owners.append(item)
    log_window_evidence = rebuild_bounded_log_window(
        case_dir=case_dir,
        case_spec=case_spec,
        t0=t0,
        t4=t4,
    )
    guest_serial_evidence = rebuild_guest_serial_evidence(
        case_dir=case_dir,
        case_spec=case_spec,
        oracle_profile=oracle_profile,
        t0=t0,
        t1=t1,
        t4=t4,
    )
    terminal_phase_path = (
        case_dir / "raw-esxi" / "t4-terminal" / "phase.json"
    )
    terminal_phase = (
        load_json(terminal_phase_path)
        if terminal_phase_path.is_file()
        else None
    )
    baseline_phase_path = (
        case_dir / "raw-esxi" / "t0-baseline" / "phase.json"
    )
    baseline_raw_phase = (
        load_json(baseline_phase_path)
        if baseline_phase_path.is_file()
        else None
    )
    safety_observations = build_numeric_safety_observations(
        t0=t0,
        t1=t1,
        t2=t2,
        t3=t3,
        t4=t4,
        t5=t5,
        cleanup=cleanup,
        baseline_phase=baseline_raw_phase,
        terminal_phase=terminal_phase,
    )
    safety_coverage = build_safety_coverage(
        t0=t0,
        t1=t1,
        t2=t2,
        t3=t3,
        t4=t4,
        t5=t5,
        cleanup=cleanup,
    )
    evidence_protocol = derive_raw_evidence_protocol(
        sequence=str(case_spec.get("sequence")),
        qemu_device=str(case_spec.get("qemuDevice")),
        outer_endpoint_bdf=outer_endpoint_bdf,
        outer_root_bdf=outer_root_bdf,
        owner_phase=str(case_spec.get("ownerPhase")),
        t0=t0,
        t1=t1,
        t2=t2,
        t3=t3,
        t4=t4,
        t5=t5,
        cleanup=cleanup,
        baseline_phase=baseline_raw_phase,
        terminal_phase=terminal_phase,
        safety_coverage=safety_coverage,
        bounded_log_window_complete=(
            log_window_evidence["complete"] is True
        ),
    )
    record_shape_faults.extend(
        cleanup_evidence_faults(
            cleanup=cleanup,
            t1=t1,
            t5=t5,
            owner_phase=case_spec.get("ownerPhase"),
            evidence_protocol=evidence_protocol,
        )
    )
    if (
        evidence_protocol["complete"]
        and cleanup.get("complete") is True
    ):
        record_shape_faults.extend(
            successful_phase_artifact_faults(
                t0=t0,
                t1=t1,
                t4=t4,
                t5=t5,
                cleanup=cleanup,
                owner_phase=case_spec.get("ownerPhase"),
            )
        )
    phase_plan_complete = all(
        isinstance(
            {
                "t2": t2,
                "t3": t3,
                "t4": t4,
                "t5": t5,
            }[phase].get(key),
            list,
        )
        and len(
            {
                "t2": t2,
                "t3": t3,
                "t4": t4,
                "t5": t5,
            }[phase][key]
        )
        == len(phase_plan[phase])
        for phase, key in (
            ("t2", "steps"),
            ("t3", "snapshots"),
            ("t4", "windows"),
            ("t5", "operations"),
        )
    )
    if evidence_protocol["complete"] and not phase_plan_complete:
        record_shape_faults.append(
            "complete raw evidence does not contain the exact phase plan"
        )
    evaluation_evidence = t5.get("evaluationEvidence")
    evaluation_evidence = (
        evaluation_evidence
        if isinstance(evaluation_evidence, dict)
        else {}
    )
    return {
        "caseSpec": case_spec,
        "outerEndpointBdf": outer_endpoint_bdf,
        "outerRootBdf": outer_root_bdf,
        "baselineHostPhase": baseline_raw_phase,
        "terminalHostPhase": terminal_phase,
        "snapshots": snapshots,
        "injections": (
            raw_injections
            if isinstance(raw_injections, list)
            else []
        ),
        "ownerObservations": owners,
        "hostProjection": phase_projection(terminal_phase),
        "hostLogClassification": log_window_evidence[
            "classification"
        ],
        "logWindowEvidence": log_window_evidence,
        "o4GuestEvidenceValid": guest_serial_evidence[
            "validO4Evidence"
        ],
        "guestSerialEvidence": guest_serial_evidence,
        "preflight": t0.get("preflight"),
        "gateStable": t1.get("gateStable"),
        "enteredInjection": entered_injection,
        "sourceRequesterId": (
            first_source_requester_id if entered_injection else -1
        ),
        "hmpTranscriptExact": hmp_transcript_exact,
        "evidenceComplete": bool(
            evidence_protocol["complete"]
            and not snapshot_record_faults
            and not record_shape_faults
        ),
        "evidenceProtocolChecks": evidence_protocol["checks"],
        "snapshotRecordFaults": sorted(set(snapshot_record_faults)),
        "recordShapeFaults": sorted(set(record_shape_faults)),
        "safetyObservations": safety_observations,
        "safetyCoverage": safety_coverage,
        "safetyFaults": evaluation_evidence.get(
            "runtimeSafetyFaults"
        ),
        "containmentRequired": evaluation_evidence.get(
            "containmentRequired"
        ),
        "containmentReasons": evaluation_evidence.get(
            "containmentReasons"
        ),
        "containmentEvidence": reconstruct_containment_evidence(t5),
        "fault": evaluation_evidence.get("executionFault"),
        "cleanupComplete": cleanup.get("complete") is True,
    }


def verify_case_dependency_closure(
    *,
    case_dir: Path,
    run_manifest: dict[str, Any],
    oracle_profile_path: Path,
    oracle_schema_path: Path,
) -> dict[str, Any]:
    source_hashes = load_json(
        case_dir / "source-and-binary-hashes.json"
    )
    if not isinstance(source_hashes, dict):
        raise ManifestError(
            "source-and-binary-hashes root is not an object"
        )
    repository_inputs = source_hashes.get("repositoryInputs")
    if not isinstance(repository_inputs, list):
        raise ManifestError("frozen repositoryInputs is not a list")
    if run_manifest.get("runtimeDependencies") != repository_inputs:
        raise ManifestError(
            "run-manifest runtimeDependencies differ from the frozen source "
            "record"
        )
    required_code = (
        Path(__file__).resolve(),
        SCRIPT_DIR / "esxi_log_window_v2.py",
        SCRIPT_DIR / "test_esxi_aer_correctable_matrix.py",
        SCRIPT_DIR / "test_qemu_aer_correctable_matrix.py",
        SCRIPT_DIR / "test_qemu_aer_root_sequence.py",
        SCRIPT_DIR / "esxi_passthru_capability.py",
    )
    checks: dict[str, bool] = {}
    for path in required_code:
        resolved = str(path.resolve())
        matches = [
            item
            for item in repository_inputs
            if isinstance(item, dict) and item.get("path") == resolved
        ]
        checks[f"code:{path.name}"] = bool(
            len(matches) == 1
            and matches[0].get("exists") is True
            and matches[0].get("sha256") == sha256_file(path)
        )
    profile_hash = sha256_file(oracle_profile_path)
    schema_hash = sha256_file(oracle_schema_path)
    checks["profile-hash-present"] = (
        sum(
            1
            for item in repository_inputs
            if isinstance(item, dict)
            and item.get("sha256") == profile_hash
        )
        == 1
    )
    checks["schema-hash-present"] = (
        sum(
            1
            for item in repository_inputs
            if isinstance(item, dict)
            and item.get("sha256") == schema_hash
        )
        == 1
    )
    checks["run-manifest-runner"] = (
        run_manifest.get("runner", {}).get("sha256")
        == sha256_file(Path(__file__).resolve())
    )
    checks["run-manifest-profile"] = (
        run_manifest.get("oracleProfile", {}).get("sha256")
        == profile_hash
    )
    checks["run-manifest-profile-schema"] = (
        run_manifest.get("oracleProfile", {}).get("schemaSha256")
        == schema_hash
    )
    expected_packages = {
        name: installed_distribution_version(name)
        for name in ("jsonschema", "pyvmomi")
    }
    checks["python-package-versions"] = (
        source_hashes.get("pythonPackages") == expected_packages
    )
    failed = sorted(name for name, value in checks.items() if not value)
    if failed:
        raise ManifestError(
            "offline evaluator dependency closure failed: "
            + ", ".join(failed)
        )
    return {
        "checks": checks,
        "sourceAndBinaryHashes": source_hashes,
        "oracleSchemaSha256": schema_hash,
        "verified": True,
    }


def evaluate_case_directory(
    case_dir: Path,
    oracle_profile_path: Path,
) -> dict[str, Any]:
    verification = verify_artifact_manifest(case_dir)
    run_manifest = load_json(case_dir / "run-manifest.json")
    oracle_schema_path = oracle_profile_path.with_name(
        "oracle-profile.schema.json"
    )
    if not oracle_schema_path.is_file():
        raise ManifestError(
            "frozen oracle profile schema is missing beside the profile"
        )
    dependency_closure = verify_case_dependency_closure(
        case_dir=case_dir,
        run_manifest=run_manifest,
        oracle_profile_path=oracle_profile_path,
        oracle_schema_path=oracle_schema_path,
    )
    expected_profile_hash = (
        run_manifest.get("oracleProfile", {}).get("sha256")
    )
    actual_profile_hash = sha256_file(oracle_profile_path)
    if expected_profile_hash != actual_profile_hash:
        raise ManifestError(
            "oracle profile hash does not match the immutable run manifest"
        )
    profile = load_oracle_profile(
        oracle_profile_path,
        oracle_schema_path,
    )
    evaluation_input = load_json(case_dir / "evaluation-input.json")
    evaluation_shape_faults = evaluation_input_shape_faults(evaluation_input)
    raw_sources = reconstruct_evaluation_sources(case_dir, profile)
    recomputed = evaluate_case_observation(
        evaluation_input,
        profile,
        outer_endpoint_bdf=raw_sources["outerEndpointBdf"],
        outer_root_bdf=raw_sources["outerRootBdf"],
    )
    execution_fault = evaluation_input.get("fault")
    if isinstance(execution_fault, dict):
        recomputed["executionFault"] = copy.deepcopy(execution_fault)
    stored = load_json(case_dir / "oracle.json")
    case_result = load_json(case_dir / "result.json")
    case_spec = raw_sources["caseSpec"]
    case_shape_faults = case_spec_shape_faults(case_spec, profile)
    run_manifest_faults = run_manifest_shape_faults(run_manifest, profile)
    result_shape_faults = case_result_shape_faults(case_result)
    t0 = load_json(case_dir / "t0-baseline.json")
    t1 = load_json(case_dir / "t1-effective-controls.json")
    t4 = load_json(case_dir / "t4-window.json")
    t5 = load_json(case_dir / "t5-transition-or-clear.json")
    entered_injection = raw_sources["enteredInjection"]
    log_summary_consistent = complete_injected_log_summary(
        raw_sources["logWindowEvidence"]
    )
    nonentered_log_stage_exact = bool(
        not entered_injection
        and exact_nonentered_log_stage_summary(
            case_dir=case_dir,
            case_protocol=case_spec.get("logWindowProtocol"),
            t0=t0,
            t4=t4,
            evidence=raw_sources["logWindowEvidence"],
        )
    )
    guest_summary_consistent = complete_injected_o4_guest_summary(
        raw_sources["guestSerialEvidence"]
    )
    nonentered_guest_stage_exact = bool(
        not entered_injection
        and exact_nonentered_o4_guest_stage_summary(
            case_dir=case_dir,
            t0=t0,
            t1=t1,
            t4=t4,
            t5=t5,
            evidence=raw_sources["guestSerialEvidence"],
        )
    )
    o0_guest_stage_absent = bool(
        case_spec.get("ownerPhase") == "O0"
        and strict_o0_guest_stage_absence(
            case_dir=case_dir,
            t0=t0,
            t1=t1,
            t4=t4,
            evidence=raw_sources["guestSerialEvidence"],
        )
    )
    host_log_raw_summary_exact = (
        log_summary_consistent
        if entered_injection
        else nonentered_log_stage_exact
    )
    guest_raw_summary_exact = (
        (
            guest_summary_consistent
            if entered_injection
            else nonentered_guest_stage_exact
        )
        if case_spec.get("ownerPhase") == "O4"
        else o0_guest_stage_absent
    )
    result_case = case_result.get("case")
    result_case = result_case if isinstance(result_case, dict) else {}
    identity_fields = (
        "caseId",
        "ownerPhase",
        "sequence",
        "gate",
        "repeatIndex",
        "qemuDevice",
    )
    identity_consistency_checks = {
        f"case/evaluation:{field}": (
            case_spec.get(field) == evaluation_input.get(field)
        )
        for field in identity_fields
    }
    identity_consistency_checks.update(
        {
            f"case/run-manifest:{field}": (
                case_spec.get(field) == run_manifest.get(field)
            )
            for field in identity_fields
        }
    )
    identity_consistency_checks.update(
        {
            "case/evaluation:campaignId": (
                case_spec.get("campaignId")
                == evaluation_input.get("campaignId")
            ),
            "case/evaluation:caseRunId": (
                case_spec.get("caseRunId")
                == evaluation_input.get("caseRunId")
            ),
            "result-case-exact": result_case == case_spec,
            "run-id-campaign-id": (
                run_manifest.get("runId")
                == run_manifest.get("campaignId")
                == case_spec.get("campaignId")
            ),
            "case-run-id": (
                case_spec.get("caseRunId")
                == run_manifest.get("caseRunId")
                == (
                    f"{case_spec.get('campaignId')}--"
                    f"{case_spec.get('caseId')}"
                )
            ),
            "schema-version": (
                case_spec.get("schemaVersion")
                == run_manifest.get("schemaVersion")
                == evaluation_input.get("schemaVersion")
                == SCHEMA_VERSION
            ),
            "model-id": case_spec.get("modelId") == RUNNER_MODEL_ID,
            "case-schema-closed": not case_shape_faults,
            "run-manifest-schema-closed": not run_manifest_faults,
            "evaluation-input-schema-closed": not evaluation_shape_faults,
            "run-manifest-environment-bound": (
                run_manifest.get("environment")
                == dependency_closure["sourceAndBinaryHashes"].get(
                    "environment"
                )
            ),
        }
    )
    expected_guest_classification = (
        "NOT_APPLICABLE_O0"
        if case_spec.get("ownerPhase") == "O0"
        else (
            "O4_BOUND_DRIVER_AND_HEARTBEAT"
            if raw_sources["o4GuestEvidenceValid"]
            else "O4_GUEST_EVIDENCE_INCOMPLETE"
        )
    )
    raw_consistency_checks = {
        "baseline-host-phase": (
            raw_sources["baselineHostPhase"]
            == t0.get("hostPhase")
        ),
        "terminal-host-phase": (
            raw_sources["terminalHostPhase"]
            == t4.get("hostTerminalPhase")
        ),
        "snapshots": raw_sources["snapshots"]
        == evaluation_input.get("snapshots"),
        "snapshot-records-valid": not raw_sources[
            "snapshotRecordFaults"
        ],
        "phase-and-injection-records-valid": not raw_sources[
            "recordShapeFaults"
        ],
        "hmp-transcript": raw_sources["hmpTranscriptExact"],
        "injections": raw_sources["injections"]
        == evaluation_input.get("injections"),
        "entered-injection": (
            raw_sources["enteredInjection"]
            == evaluation_input.get("enteredInjection")
        ),
        "requester-id": (
            raw_sources["sourceRequesterId"]
            == evaluation_input.get("requesterId")
        ),
        "owner-observations": raw_sources["ownerObservations"]
        == evaluation_input.get("ownerObservations"),
        "host-projection": raw_sources["hostProjection"]
        == evaluation_input.get("hostProjection"),
        "host-log-classification": (
            raw_sources["hostLogClassification"]
            == evaluation_input.get("hostLogClassification")
        ),
        "host-log-raw-summary": host_log_raw_summary_exact,
        "o4-guest-evidence": (
            raw_sources["o4GuestEvidenceValid"]
            == evaluation_input.get("o4GuestEvidenceValid")
        ),
        "o4-guest-raw-summary": guest_raw_summary_exact,
        "guest-classification": (
            evaluation_input.get("guestClassification")
            == expected_guest_classification
        ),
        "preflight": (
            raw_sources["preflight"]
            == evaluation_input.get("preflight")
        ),
        "gate-stable": (
            raw_sources["gateStable"]
            == evaluation_input.get("gateStable")
        ),
        "evidence-complete": (
            raw_sources["evidenceComplete"]
            == evaluation_input.get("evidenceComplete")
        ),
        "safety-observations": (
            raw_sources["safetyObservations"]
            == evaluation_input.get("safetyObservations")
        ),
        "safety-coverage": (
            raw_sources["safetyCoverage"]
            == evaluation_input.get("safetyCoverage")
        ),
        "runtime-safety-faults": (
            raw_sources["safetyFaults"]
            == evaluation_input.get("safetyFaults")
        ),
        "containment-required": (
            raw_sources["containmentRequired"]
            == evaluation_input.get("containmentRequired")
        ),
        "containment-reasons": (
            raw_sources["containmentReasons"]
            == evaluation_input.get("containmentReasons")
        ),
        "containment-evidence": (
            raw_sources["containmentEvidence"]
            == evaluation_input.get("containmentEvidence")
        ),
        "execution-fault": (
            raw_sources["fault"]
            == evaluation_input.get("fault")
        ),
        "cleanup-complete": (
            raw_sources["cleanupComplete"]
            == evaluation_input.get("cleanupComplete")
        ),
    }
    result_consistency_checks = {
        "result-schema-closed": not result_shape_faults,
        "case-object": result_case == case_spec,
        "started-at": (
            case_result.get("startedAt") == run_manifest.get("startedAt")
        ),
        "observation-state": (
            case_result.get("observationState")
            == stored.get("observationState")
            == recomputed.get("observationState")
        ),
        "verdict": (
            case_result.get("verdict")
            == stored.get("verdict")
            == recomputed.get("verdict")
        ),
        "observation-digest": (
            case_result.get("observationDigest")
            == stored.get("observationDigest")
            == recomputed.get("observationDigest")
        ),
        "safety-stop": (
            case_result.get("safetyStop")
            == stored.get("safetyStop")
            == recomputed.get("safetyStop")
        ),
        "entered-injection": (
            case_result.get("enteredInjection")
            == evaluation_input.get("enteredInjection")
        ),
        "fault": case_result.get("fault") == evaluation_input.get("fault"),
        "cleanup-complete": (
            case_result.get("cleanupComplete")
            == evaluation_input.get("cleanupComplete")
        ),
        "runtime-containment-required": (
            case_result.get("runtimeContainmentRequired")
            == evaluation_input.get("containmentRequired")
        ),
        "runtime-containment-reasons": (
            case_result.get("runtimeContainmentReasons")
            == evaluation_input.get("containmentReasons")
        ),
        "oracle-containment-required": (
            case_result.get("containmentRequired")
            == stored.get("containmentRequired")
            == recomputed.get("containmentRequired")
        ),
        "oracle-containment-reasons": (
            case_result.get("containmentReasons")
            == stored.get("containmentReasons")
            == recomputed.get("containmentReasons")
        ),
        "claim-boundary": (
            case_result.get("claimBoundary")
            == case_spec.get("claimBoundary")
            == case_claim_boundary()
        ),
    }
    oracle_exact = stored == recomputed
    raw_exact = all(raw_consistency_checks.values())
    result_exact = all(result_consistency_checks.values())
    identity_exact = all(identity_consistency_checks.values())
    return {
        "case": str(case_dir),
        "manifest": verification,
        "oracleProfileSha256": actual_profile_hash,
        "dependencyClosure": dependency_closure,
        "storedObservationState": stored.get("observationState"),
        "recomputedObservationState": recomputed.get("observationState"),
        "storedObservationDigest": stored.get("observationDigest"),
        "recomputedObservationDigest": recomputed.get("observationDigest"),
        "oracleExactMatch": oracle_exact,
        "rawSourceExactMatch": raw_exact,
        "resultExactMatch": result_exact,
        "identityExactMatch": identity_exact,
        "rawConsistencyChecks": raw_consistency_checks,
        "resultConsistencyChecks": result_consistency_checks,
        "identityConsistencyChecks": identity_consistency_checks,
        "artifactShapeFaults": {
            "case": case_shape_faults,
            "runManifest": run_manifest_faults,
            "evaluationInput": evaluation_shape_faults,
            "result": result_shape_faults,
        },
        "exactMatch": (
            oracle_exact
            and raw_exact
            and result_exact
            and identity_exact
        ),
        "recomputedOracle": recomputed,
    }


def add_common_plan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--owner-phase", choices=sorted(OWNER_PHASES), required=True)
    parser.add_argument(
        "--sequence",
        action="append",
        choices=SEQUENCES,
        help="repeat to select sequences; default is all four",
    )
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--gate", choices=sorted(SUPPORTED_GATES), default="g101")
    parser.add_argument("--run-id")
    parser.add_argument("--output")
    parser.add_argument(
        "--stop-after-case",
        metavar="CASE_ID",
        help=(
            "finish and close the campaign immediately after this exact "
            "manifest-complete case; the immutable full-profile plan is "
            "retained"
        ),
    )
    parser.add_argument(
        "--oracle-profile",
        default=str(DEFAULT_ORACLE_PROFILE),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run or evaluate Correctable-only ESXi DirectPath AER "
            "Root Status/Source/W1C sequences."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser(
        "plan",
        help="render the immutable case plan without connecting or injecting",
    )
    add_common_plan_arguments(plan)

    run = subparsers.add_parser(
        "run",
        help="execute one preconfigured owner phase in the authorized lab",
    )
    add_common_plan_arguments(run)
    run.add_argument("--host", default="172.31.91.10")
    run.add_argument("--user", default="root")
    run.add_argument("--caveat", default="esxi8-auto-codex-credentials")
    run.add_argument("--expected-esxi-build", default="24280767")
    run.add_argument("--expected-system-uuid", required=True)
    run.add_argument("--expected-pci-id", default="1af4:1041")
    run.add_argument("--qemu-name", default="esxi8-mf")
    run.add_argument("--qemu-device", default="test_fn1")
    run.add_argument(
        "--qemu-monitor",
        default="/root/vm/esxi8-mf/monitor.sock",
    )
    run.add_argument(
        "--qtest-socket",
        default="/root/vm/esxi8-mf/qtest.sock",
    )
    run.add_argument(
        "--qemu-aer-source",
        default="/root/src/qemu-11.0.2/hw/pci/pcie_aer.c",
    )
    run.add_argument(
        "--outer-endpoint-bdf",
        default=DEFAULT_OUTER_ENDPOINT_BDF,
    )
    run.add_argument("--outer-root-bdf", default=DEFAULT_OUTER_ROOT_BDF)
    run.add_argument("--esxi-endpoint-bdf", default="0000:01:00.1")
    run.add_argument("--esxi-root-bdf", default="0000:00:08.0")
    run.add_argument("--datastore", default="pci-mmio-local")
    run.add_argument(
        "--remote-iso",
        default=(
            "/vmfs/volumes/pci-mmio-local/iso/"
            "esxi-l3-aer-probe.iso"
        ),
    )
    run.add_argument(
        "--local-iso",
        default=str(DEFAULT_LOCAL_AER_ISO),
    )
    run.add_argument(
        "--local-iso-attestation",
        default=str(DEFAULT_LOCAL_AER_ISO_ATTESTATION),
    )
    run.add_argument(
        "--base-vmx",
        default=str(esxi_aer.DEFAULT_BASE_VMX),
    )
    run.add_argument("--guest-marker-timeout", type=int, default=360)
    run.add_argument("--guest-complete-timeout", type=int, default=180)
    run.add_argument("--guest-min-window-seconds", type=int, default=45)
    run.add_argument("--final-observation-seconds", type=float, default=1.0)
    run.add_argument("--log-lines", type=int, default=2400)
    run.add_argument(
        "--timeline-delays",
        type=parse_timeline_delays,
        default=parse_timeline_delays("0,0.05,0.25,1.0"),
    )
    run.add_argument(
        "--authorized-lab-target",
        action="store_true",
        help=(
            "attest that the exact BDF is an isolated lab-only target, not "
            "management, datastore, storage, or a production uplink"
        ),
    )
    run.add_argument(
        "--execute-correctable",
        action="store_true",
        help="required mutation acknowledgement; no Uncorrectable path exists",
    )

    evaluate = subparsers.add_parser(
        "evaluate",
        help="verify a raw case and recompute its four-state oracle offline",
    )
    evaluate.add_argument("--input", required=True)
    evaluate.add_argument(
        "--oracle-profile",
        default=str(DEFAULT_ORACLE_PROFILE),
    )

    verify = subparsers.add_parser(
        "verify-run",
        help="verify campaign/case manifests and the aggregate sidecar",
    )
    verify.add_argument("--input", required=True)
    verify.add_argument(
        "--require-complete",
        action="store_true",
        help=(
            "return non-zero unless the verified artifact closed the entire "
            "immutable plan without a campaign termination cause"
        ),
    )

    subparsers.add_parser(
        "selftest",
        help="validate the profile and closed Correctable command surface",
    )
    return parser


def validate_run_args(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    profile: dict[str, Any],
) -> None:
    if not args.output:
        parser.error("run requires --output")
    if not args.execute_correctable:
        parser.error("run requires --execute-correctable")
    if not args.authorized_lab_target:
        parser.error("run requires --authorized-lab-target")
    if args.gate != profile["gate"]:
        parser.error(
            f"requested gate {args.gate} differs from immutable profile "
            f"gate {profile['gate']}"
        )
    if args.repeat <= 0:
        parser.error("--repeat must be positive")
    if args.repeat < int(profile["minimumRepeats"]):
        parser.error(
            f"--repeat must be at least profile minimum "
            f"{profile['minimumRepeats']}"
        )
    selected_sequences = args.sequence or list(SEQUENCES)
    if selected_sequences != profile["requiredSequences"]:
        parser.error(
            "run requires the profile's exact ordered sequence set: "
            f"{profile['requiredSequences']}"
        )
    try:
        validation_plan = build_case_plan(
            owner_phase=args.owner_phase,
            gate=args.gate,
            sequences=selected_sequences,
            repeat=args.repeat,
        )
        build_execution_policy(
            validation_plan,
            args.stop_after_case,
        )
    except ValueError as error:
        parser.error(str(error))
    timing = profile["timingEnvelope"]
    args.maximum_safety_poll_interval_seconds = float(
        timing["maximumSafetyPollIntervalSeconds"]
    )
    # Schedule at half the contractual maximum so normal QTest read latency
    # does not consume the entire fail-stop interval.  The observed gap is
    # still measured and enforced at runtime.
    args.safety_poll_target_interval_seconds = (
        args.maximum_safety_poll_interval_seconds / 2.0
    )
    if list(args.timeline_delays) != timing["timelineDelaysSeconds"]:
        parser.error(
            "--timeline-delays must exactly match the immutable profile"
        )
    if (
        args.final_observation_seconds
        < timing["minimumFinalObservationSecondsO0"]
    ):
        parser.error(
            "--final-observation-seconds is below the profile minimum"
        )
    if (
        args.guest_min_window_seconds
        < timing["minimumGuestWindowRemainingSecondsO4"]
    ):
        parser.error(
            "--guest-min-window-seconds is below the profile minimum"
        )
    if args.guest_min_window_seconds + 5 > timing["guestWindowSeconds"]:
        parser.error(
            "--guest-min-window-seconds plus the heartbeat-age allowance "
            "exceeds the attested guest window"
        )
    if (
        args.guest_complete_timeout
        > timing["runnerWatchdogGraceSeconds"]
    ):
        parser.error(
            "--guest-complete-timeout exceeds the runner-managed guest "
            "watchdog grace"
        )
    binding = profile["environmentBinding"]
    if str(args.expected_esxi_build) != binding["expectedEsxiBuild"]:
        parser.error(
            "--expected-esxi-build differs from the immutable profile"
        )
    if args.expected_pci_id.lower() != binding["expectedPciId"]:
        parser.error(
            "--expected-pci-id differs from the immutable profile"
        )
    if (
        binding["expectedSystemUuid"] is not None
        and args.expected_system_uuid.lower()
        != binding["expectedSystemUuid"].lower()
    ):
        parser.error(
            "--expected-system-uuid differs from the frozen profile"
        )
    if not EXPECTED_PCI_ID_RE.fullmatch(args.expected_pci_id):
        parser.error("--expected-pci-id must be vvvv:dddd")
    if not args.expected_system_uuid.strip():
        parser.error("--expected-system-uuid must be non-empty")
    for label, value in (
        ("outer endpoint", args.outer_endpoint_bdf),
        ("outer root", args.outer_root_bdf),
        ("ESXi endpoint", args.esxi_endpoint_bdf),
        ("ESXi root", args.esxi_root_bdf),
    ):
        if not esxi_aer.BDF_RE.fullmatch(value):
            parser.error(f"invalid {label} BDF: {value!r}")
    esxi_aer.validate_safe_id(args.qemu_device, "QEMU device")
    if not esxi_aer.SAFE_DATASTORE_RE.fullmatch(args.datastore):
        parser.error(f"invalid datastore: {args.datastore!r}")
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", args.remote_iso):
        parser.error(f"invalid remote ISO path: {args.remote_iso!r}")
    if (
        args.guest_marker_timeout <= 0
        or args.guest_complete_timeout <= 0
        or args.guest_min_window_seconds <= 0
        or args.final_observation_seconds < 0
        or args.log_lines < 100
    ):
        parser.error("timeouts/windows must be positive and log-lines >= 100")
    base_vmx = Path(args.base_vmx)
    if args.owner_phase == "O4" and not base_vmx.is_file():
        parser.error(f"base VMX is missing: {base_vmx}")
    if args.owner_phase == "O4":
        local_iso = Path(args.local_iso).resolve()
        local_attestation = Path(args.local_iso_attestation).resolve()
        if not local_iso.is_file():
            parser.error(f"local AER ISO is missing: {local_iso}")
        if not local_attestation.is_file():
            parser.error(
                f"local AER ISO attestation is missing: {local_attestation}"
            )
        try:
            load_aer_iso_attestation(
                local_attestation,
                local_iso,
                profile["timingEnvelope"],
            )
        except (OSError, ValueError) as error:
            parser.error(f"invalid local AER ISO attestation: {error}")


def render_plan(args: argparse.Namespace, profile: dict[str, Any]) -> dict[str, Any]:
    sequences = args.sequence or list(SEQUENCES)
    cases = build_case_plan(
        owner_phase=args.owner_phase,
        gate=args.gate,
        sequences=sequences,
        repeat=args.repeat,
    )
    execution_policy = build_execution_policy(
        cases,
        getattr(args, "stop_after_case", None),
    )
    return {
        "schemaVersion": SCHEMA_VERSION,
        "modelId": RUNNER_MODEL_ID,
        "generatedAt": utc_now(),
        "runId": args.run_id,
        "ownerPhase": args.owner_phase,
        "gate": args.gate,
        "sequences": sequences,
        "repeat": args.repeat,
        "caseCount": len(cases),
        "executionPolicy": execution_policy,
        "profileCoverage": {
            "requiredSequences": profile["requiredSequences"],
            "minimumRepeats": profile["minimumRepeats"],
            "complete": bool(
                sequences == profile["requiredSequences"]
                and args.repeat >= profile["minimumRepeats"]
            ),
        },
        "oracleProfile": {
            "path": str(Path(args.oracle_profile).resolve()),
            "id": profile["id"],
            "profileState": profile["profileState"],
            "sha256": sha256_file(Path(args.oracle_profile).resolve()),
            "schemaSha256": sha256_file(ORACLE_PROFILE_SCHEMA),
        },
        "cases": cases,
        "claimBoundary": case_claim_boundary(),
    }


def run_campaign(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
) -> dict[str, Any]:
    oracle_profile_path = Path(args.oracle_profile).resolve()
    oracle_profile = load_oracle_profile(oracle_profile_path)
    validate_run_args(parser, args, oracle_profile)
    plan = render_plan(args, oracle_profile)
    campaign_id = args.run_id or (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid.uuid4().hex[:8]
    )
    esxi_aer.validate_safe_id(campaign_id, "run ID")
    plan["runId"] = campaign_id

    output_dir = Path(args.output).resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        parser.error(f"output directory is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "cases").mkdir(exist_ok=False)
    shutil.copyfile(
        oracle_profile_path,
        output_dir / "oracle-profile.json",
    )
    shutil.copyfile(
        ORACLE_PROFILE_SCHEMA,
        output_dir / "oracle-profile.schema.json",
    )
    if (
        sha256_file(output_dir / "oracle-profile.json")
        != plan["oracleProfile"]["sha256"]
    ):
        raise ManifestError("frozen oracle profile copy drifted at campaign start")
    save_json(output_dir / "campaign-plan.json", plan)

    planned_ids = [item["caseId"] for item in plan["cases"]]
    execution_policy = plan["executionPolicy"]
    campaign: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "modelId": RUNNER_MODEL_ID,
        "runId": campaign_id,
        "startedAt": utc_now(),
        "ownerPhase": args.owner_phase,
        "gate": args.gate,
        "sequences": list(args.sequence or SEQUENCES),
        "repeat": args.repeat,
        "oracleProfile": plan["oracleProfile"],
        "executionPolicy": copy.deepcopy(execution_policy),
        "plannedCaseIds": planned_ids,
        "cases": [],
        "aggregate": None,
        "safetyBoundary": {
            "correctableOnly": True,
            "bits": SAFE_INJECTION_BITS,
            "uncorrectableInjectionSurface": False,
        },
        "claimBoundary": case_claim_boundary(),
    }
    save_json(output_dir / "result.json", campaign)

    password: str | None = None
    api: esxi_aer.ApiSession | None = None
    environment: dict[str, Any] | None = None
    campaign_fault: dict[str, Any] | None = None
    try:
        password = caveat_field(args.caveat, "Password")
        ssh = EsxiSsh(args.host, password, user=args.user)
        transfer = esxi_aer.EsxiScp(args.host, args.user, password)
        api = esxi_aer.ApiSession(args.host, args.user, password)
        environment = environment_identity(
            api=api,
            ssh=ssh,
            qemu_name=args.qemu_name,
        )
        source_hashes = source_and_binary_hashes(
            args=args,
            oracle_profile_path=oracle_profile_path,
            environment=environment,
        )
        campaign["environment"] = environment
        campaign["sourceAndBinaryHashes"] = source_hashes
        save_json(output_dir / "source-and-binary-hashes.json", source_hashes)
        for index, item in enumerate(plan["cases"]):
            result = run_case(
                args=args,
                campaign_id=campaign_id,
                case_plan=item,
                output_dir=output_dir,
                oracle_profile=oracle_profile,
                oracle_profile_path=oracle_profile_path,
                environment=environment,
                source_hashes=source_hashes,
                ssh=ssh,
                transfer=transfer,
                api=api,
            )
            campaign["cases"].append(result)
            save_json(output_dir / "result.json", campaign)
            if result.get("safetyStop"):
                campaign["safetyStop"] = {
                    "afterCase": result["caseId"],
                    "remainingCaseIds": [
                        case["caseId"] for case in plan["cases"][index + 1 :]
                    ],
                    "requiredAction": (
                        "inspect the held-paused outer QEMU evidence and "
                        "recover or quarantine the isolated lab"
                    ),
                }
                break
            if (
                result.get("containmentRequired") is True
                or result.get("cleanupComplete") is not True
            ):
                campaign["cleanupStop"] = {
                    "afterCase": result["caseId"],
                    "remainingCaseIds": [
                        case["caseId"]
                        for case in plan["cases"][index + 1 :]
                    ],
                    "requiredAction": (
                        "do not inject another case; restore the gate, "
                        "remove any runner VM/user, and prove outer QEMU "
                        "running with a clean baseline"
                    ),
                }
                break
            if (
                result.get("observationState") == OBSERVATION_BLOCKED
                and result.get("enteredInjection") is not True
            ):
                campaign["blockedStop"] = {
                    "afterCase": result["caseId"],
                    "remainingCaseIds": [
                        case["caseId"]
                        for case in plan["cases"][index + 1 :]
                    ],
                    "requiredAction": (
                        "repair the immutable environment/owner preflight "
                        "before starting a fresh campaign"
                    ),
                }
                break
            if (
                execution_policy["mode"]
                == EXECUTION_MODE_STOP_AFTER_CASE
                and item["caseId"]
                == execution_policy["stopAfterCaseId"]
            ):
                campaign["boundaryStop"] = build_boundary_stop(
                    execution_policy,
                    planned_ids,
                )
                break
    except BaseException as error:
        campaign_fault = {
            "type": type(error).__name__,
            "message": str(error),
        }
        campaign["fault"] = campaign_fault
    finally:
        try:
            final_state = esxi_aer.qemu_runtime_state(
                Path(args.qemu_monitor)
            )
        except BaseException as state_error:
            final_state = "unknown"
            campaign["finalQemuStateFault"] = {
                "type": type(state_error).__name__,
                "message": str(state_error),
            }
        campaign["finalQemuState"] = final_state
        if api is not None:
            try:
                api.close(remote_logout=final_state == "running")
                campaign["apiCloseMode"] = (
                    "REMOTE_LOGOUT"
                    if final_state == "running"
                    else "LOCAL_DROP_ONLY"
                )
            except BaseException as error:
                campaign["apiCloseFault"] = {
                    "type": type(error).__name__,
                    "message": str(error),
                }
        password = None

    sequences = args.sequence or list(SEQUENCES)
    minimum_repeats = int(oracle_profile["minimumRepeats"])
    campaign["aggregate"] = aggregate_campaign(
        campaign["cases"],
        owner_phase=args.owner_phase,
        sequences=sequences,
        minimum_repeats=minimum_repeats,
    )
    completed_ids = {item["caseId"] for item in campaign["cases"]}
    campaign["incompletePlan"] = [
        item["caseId"]
        for item in plan["cases"]
        if item["caseId"] not in completed_ids
    ]
    if campaign_fault and not campaign["cases"]:
        campaign["aggregate"]["observationState"] = OBSERVATION_BLOCKED
    elif campaign.get("cleanupStop"):
        campaign["aggregate"]["observationState"] = OBSERVATION_INCONCLUSIVE
    elif campaign.get("blockedStop"):
        campaign["aggregate"]["observationState"] = OBSERVATION_BLOCKED
    elif campaign.get("boundaryStop"):
        campaign["aggregate"]["observationState"] = OBSERVATION_INCONCLUSIVE
    elif campaign["incompletePlan"] and not campaign.get("safetyStop"):
        campaign["aggregate"]["observationState"] = OBSERVATION_INCONCLUSIVE
    campaign["finishedAt"] = utc_now()
    save_json(output_dir / "result.json", campaign)
    result_hash = sha256_file(output_dir / "result.json")
    save_text(
        output_dir / "result.json.sha256",
        f"{result_hash}  result.json\n",
    )
    write_artifact_manifest(output_dir)
    campaign["resultSha256"] = result_hash
    campaign["output"] = str(output_dir)
    return campaign


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "selftest":
        profile = load_oracle_profile(DEFAULT_ORACLE_PROFILE)
        command = esxi_aer.build_injection_command("test_fn1", B0)
        if command != "pcie_aer_inject_error -c test_fn1 0x00000001":
            raise AssertionError("Correctable-only command builder drift")
        print(
            json.dumps(
                {
                    "selftest": "PASS",
                    "profile": profile["id"],
                    "safeBits": SAFE_INJECTION_BITS,
                    "sequences": SEQUENCES,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.command == "verify-run":
        value = verify_campaign(Path(args.input).resolve())
        if args.require_complete:
            value["requireCompleteSatisfied"] = value["fullPlanComplete"]
        print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))
        if args.require_complete and not value["fullPlanComplete"]:
            return 2
        return 0
    if args.command == "evaluate":
        value = evaluate_case_directory(
            Path(args.input).resolve(),
            Path(args.oracle_profile).resolve(),
        )
        print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))
        return 0 if value["exactMatch"] else 2

    profile = load_oracle_profile(Path(args.oracle_profile).resolve())
    if args.command == "plan":
        try:
            value = render_plan(args, profile)
        except ValueError as error:
            parser.error(str(error))
        if args.output:
            output = Path(args.output).resolve()
            if output.exists() and output.is_dir():
                output = output / "campaign-plan.json"
            save_json(output, value)
        print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))
        return 0

    campaign = run_campaign(parser, args)
    print(json.dumps(campaign, indent=2, ensure_ascii=False, sort_keys=True))
    state = campaign["aggregate"]["observationState"]
    if campaign["aggregate"].get("safetyStop"):
        return 4
    return {
        OBSERVATION_MATCH: 0,
        OBSERVATION_DIVERGED: 1,
        OBSERVATION_INCONCLUSIVE: 2,
        OBSERVATION_BLOCKED: 3,
    }[state]


if __name__ == "__main__":
    raise SystemExit(main())
