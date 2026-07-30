#!/usr/bin/env python3
"""Evaluate the repository's IPD, project, risk, and acceptance release contracts.

The evaluator deliberately separates structural validity from release readiness:

* ``status`` succeeds when contracts are parseable and consistent, even while the
  project is blocked. This makes an incomplete state observable without hiding it.
* ``release`` fails closed until every milestone, decision, risk, and acceptance
  requirement is closed.
* ``run-cases`` executes the runner declared by one or more acceptance definitions.

Only Python's standard library is required.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]

RISK_STATES = {
    "OPEN",
    "CONTROL_IMPLEMENTED",
    "VERIFIED",
    "FEATURE_DISABLED",
    "INVALIDATED",
}
BLOCKING_RISK_STATES = {"OPEN", "CONTROL_IMPLEMENTED", "INVALIDATED"}
RISK_EVIDENCE_GRADES = {"NONE", "E2", "E3", "E4"}
CASE_STATES = {
    "EXECUTABLE",
    "IMPLEMENTATION_BLOCKED",
    "HARDWARE_BLOCKED",
    "FEATURE_DISABLED",
}
CASE_DEPENDENCY_REQUIRED_FIELDS = {
    "requiredTechStories",
    "dependsOnCaseIds",
}
CASE_DEPENDENCY_CLOSEABLE_STATES = {"EXECUTABLE", "FEATURE_DISABLED"}
MILESTONE_STATES = {"NOT_STARTED", "IN_PROGRESS", "BLOCKED", "DONE"}
PROJECT_MILESTONES = {
    "G0": "Design and contract convergence",
    "G1": "Host inventory and qualification baseline",
    "G2": "Static single-host transaction controller",
    "G3": "Owner activation and boot reconcile",
    "G4": "Dynamic selection and full resource planning",
    "G5": "Planned online-host cold relocation",
    "G6": "Production qualification and release",
}
PROJECT_FREEZE_RULES = [
    "Do not expand product capability claims while G0 is incomplete.",
    "Do not treat synthetic or reference-model evidence as physical hardware qualification.",
    "Do not mark a milestone complete without executable acceptance evidence.",
    "Do not bypass OPEN, CONTROL_IMPLEMENTED, or INVALIDATED risk states.",
]
REQUIRED_PRODUCT_DECISION_IDS = (
    "ADR-002",
    "ADR-003",
    "ADR-005",
    "ADR-007",
    "ADR-010",
)
G0_AUTHORITATIVE_DOCUMENTS = {
    "productDecisionsContract": "contracts/product-decisions.json",
    "compatibilityProfilePolicy": "contracts/compatibility-profile-policy.json",
    "qemuVfioLaunchSurface": "contracts/qemu-vfio-launch-surface.json",
    "vmwareEvidenceIndex": "contracts/vmware-evidence-index.json",
    "architectureDecisions": "decisions/README.md",
}
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
CASE_ID_RE = re.compile(r"^[COSDMF][0-9]{2}[a-z]?$")
FEATURE_ID_RE = re.compile(r"^F\d+$")
USER_STORY_ID_RE = re.compile(r"^US-(F\d+)-\d{2}$")
TECH_STORY_ID_RE = re.compile(r"^TS-(F\d+)-\d{2}$")
VMWARE_SOURCE_ID_RE = re.compile(r"^VMW-SRC-\d{3}$")
VMWARE_EXPERIMENT_ID_RE = re.compile(r"^VMW-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
QMAN_EVIDENCE_ID_RE = re.compile(r"^QMAN-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
QMAN_EVIDENCE_GRADES = {"E2", "E3", "E4"}
QMAN_EVIDENCE_VERDICTS = {"PASS", "PARTIAL", "FAIL"}
QMAN_CLAIM_BOUNDARIES = {
    "REFERENCE_ONLY",
    "COMPONENT_ONLY",
    "END_TO_END_PRODUCT",
    "PHYSICAL_QUALIFICATION",
}
QMAN_E4_REQUIRED_RISKS = {
    "R01",
    "R02",
    "R03",
    "R07",
    "R12",
    "R13",
    "R14",
    "R15",
    "R20",
    "R21",
    "R22",
    "R23",
    "R24",
    "R27",
    "R28",
    "R29",
    "R35",
}
QMAN_RESULT_REQUIRED_FIELDS = {
    "schemaVersion",
    "id",
    "observedAt",
    "subject",
    "evidenceGrade",
    "claimBoundary",
    "verdict",
    "sourceState",
    "sut",
    "hypotheses",
    "observations",
    "mapping",
    "artifacts",
    "closureEffect",
    "limitations",
}
QMAN_SOURCE_STATE_REQUIRED_FIELDS = {
    "baseCommit",
    "dirtyWorkingTree",
    "runnerHashes",
}
QMAN_SOURCE_STATE_FIELDS = QMAN_SOURCE_STATE_REQUIRED_FIELDS | {"inputHashes"}
QMAN_SUT_FIELDS = {"environment", "components"}
QMAN_COMPONENT_REQUIRED_FIELDS = {"name", "version"}
QMAN_COMPONENT_FIELDS = QMAN_COMPONENT_REQUIRED_FIELDS | {"sha256"}
QMAN_OBSERVATION_FIELDS = {"name", "result"}
QMAN_MAPPING_FIELDS = {"techStories", "caseIds", "riskIds"}
QMAN_ARTIFACT_FIELDS = {"path", "sha256", "retention"}
QMAN_CLOSURE_FIELDS = {"productCasesClosed", "risksClosed", "statusUpdated"}
QMAN_HARDWARE_BLOCKED_CASES = {"C12", "M08", "M12", "M13", "S06", "S08"}
QMAN_EVIDENCE_INDEX_FIELDS = {
    "schemaVersion",
    "sourceDocument",
    "resultSchema",
    "grades",
    "closurePolicy",
    "records",
}
QMAN_CLOSURE_POLICY_FIELDS = {
    "referenceSubjects",
    "invariants",
    "e4RequiredRisks",
}
QMAN_EVIDENCE_RECORD_FIELDS = {
    "id",
    "resultPath",
    "resultSha256",
    "subject",
    "evidenceGrade",
    "verdict",
    "techStories",
    "caseIds",
    "riskIds",
}
IPD_STATES = {"DEFINED_NOT_ACCEPTED", "ACCEPTED"}
IPD_RELEASE_STATES = {"PROPOSED_FOR_REVIEW", "ACCEPTED", "RETIRED"}
IPD_PRODUCT_BOUNDARY = {
    "technicalScope": "GENERIC_SAFE_PCI_PASSTHROUGH",
    "productionSupportScope": "EXACT_COMPATIBILITY_PROFILE_ONLY",
    "unqualifiedMode": "ISOLATED_ADMIN_LAB_ONLY",
}
IPD_UNSUPPORTED_OPERATIONS = {
    "LIVE_MIGRATION",
    "FAULT_TOLERANCE",
    "SNAPSHOT",
    "SUSPEND_RESUME",
    "GUEST_RUNTIME_PCI_HOTPLUG",
    "BMC_OR_POWER_FENCING",
    "HOST_FAILURE_AUTOMATIC_HA_RESTART",
}
IPD_CAPABILITY_DIMENSIONS = {
    "TECHNICALLY_ATTACHABLE": (
        "A safe attach plan exists for this device instance and immutable host snapshot."
    ),
    "ELIGIBLE": (
        "The current VM request also satisfies availability, health, ownership, lease, "
        "resource, and policy constraints."
    ),
    "QUALIFIED": (
        "An exact versioned platform/device/guest/workload profile passed Qman "
        "physical-hardware cases with evidence hashes."
    ),
    "SUPPORTED": (
        "A qualified profile is admitted to the V3 compatibility catalog by product policy."
    ),
}
IPD_CAPABILITY_INVARIANTS = {
    "PRODUCTION_ELIGIBLE_IMPLIES_SUPPORTED_PROFILE_MATCH",
    "SUPPORTED_IMPLIES_QUALIFIED",
    "ELIGIBLE_IMPLIES_TECHNICALLY_ATTACHABLE",
    "TECHNICALLY_ATTACHABLE_DOES_NOT_IMPLY_QUALIFIED",
    "VMWARE_OBSERVATION_DOES_NOT_IMPLY_QMAN_QUALIFIED_OR_SUPPORTED",
}
VMWARE_COVERAGE_STATES = {"VERIFIED", "PARTIAL", "UNKNOWN", "NOT_APPLICABLE"}
VMWARE_EXECUTION_STATES = {"OBSERVED", "PARTIAL", "PLANNED", "BLOCKED_PHYSICAL"}
VMWARE_NO_RUN_STATES = {"PLANNED", "BLOCKED_PHYSICAL"}
VMWARE_TRACE_GOVERNANCE_ARTIFACTS = {
    "tools/evaluate_release.py",
    "tools/generate_vmware_evidence_index.py",
    "tests/test_vmware_evidence_index.py",
}
VMWARE_EVIDENCE_INDEX_FIELDS = {
    "schemaVersion",
    "asOf",
    "subject",
    "sourceModel",
    "hashAlgorithm",
    "recordCount",
    "tracePolicy",
    "records",
}
VMWARE_EVIDENCE_RECORD_FIELDS = {
    "experimentId",
    "executionState",
    "techStoryIds",
    "legacyCaseIds",
    "derivedAcceptanceCaseIds",
    "runIds",
    "evidence",
    "noRunReason",
    "limitations",
}
VMWARE_EVIDENCE_ARTIFACT_FIELDS = {"path", "sha256"}
VMWARE_CONTROL_REFERENCE_FIELDS = {
    "id",
    "subject",
    "basisKind",
    "evidencePath",
    "sha256",
    "runIds",
    "publicSources",
    "proves",
    "doesNotProve",
    "closureAuthority",
}
VMWARE_CONTROL_PUBLIC_SOURCE_FIELDS = {"title", "url"}
VMWARE_TRACE_SUMMARY_FIELDS = {
    "schemaVersion",
    "runId",
    "observedAt",
    "subject",
    "verdict",
    "statement",
    "counts",
    "closureAuthority",
    "artifacts",
    "limitations",
}
VMWARE_TRACE_CLOSURE_AUTHORITY = {
    "acceptanceCases": "NONE",
    "qmanImplementation": "NONE",
    "qmanQualification": "NONE",
    "release": "NONE",
}
LEGACY_ADAPTER_ONLY_DIFFERENCES = {
    "backendKind",
    "dmaDomainIdentity",
    "launchGrant",
    "qemuRenderer",
    "attachReceipt",
}
LEGACY_REQUIRED_ISOLATION = {
    "PER_VM_TRANSIENT_IDENTITY",
    "PER_VM_MOUNT_NAMESPACE_WITH_ONLY_AUTHORIZED_VFIO_GROUP_NODES",
    "DEVICE_CGROUP_OR_LSM_ALLOWLIST",
    "READ_ONLY_SYSFS_VIEW_BOUND_TO_AUTHORIZED_BDFS",
    "NO_ALTERNATE_QMP_OR_RAW_LAUNCH_ENTRYPOINT",
}
LEGACY_POST_SPAWN_RECEIPT = {
    "QEMU_PID_STARTTIME",
    "QEMU_ARGV_HASH",
    "AUTHORIZED_BDF_AND_GROUP",
    "PROC_FD_DEVICE_IDENTITY",
    "QMP_QOM_DEVICE_IDENTITY",
    "LEASE_AND_RUN_GENERATION",
}
HCL_ARCHETYPE_TRAITS = {
    "CONSUMER_GPU": {
        "large-or-resizable-bar",
        "multifunction-audio",
        "option-rom",
        "reset",
        "guest-workload",
    },
    "PROFESSIONAL_GPU": {
        "large-bar",
        "msix",
        "long-workload",
        "reset",
        "optional-p2p-policy",
    },
    "HBA": {
        "host-storage-dependency",
        "boot-critical-deny",
        "downstream-device-scope",
        "reset",
        "driver-restore",
    },
    "ACCELERATOR": {
        "large-bar",
        "dma-queues",
        "msix",
        "reset",
        "ats-pri-pasid-policy",
    },
}
VMWARE_TRUTH_KINDS = {
    "OFFICIAL_CONTRACT",
    "OBSERVED_BEHAVIOR",
    "INFERRED_MECHANISM",
    "QMAN_DECISION",
}
VMWARE_OFFICIAL_HOSTS = {
    "knowledge.broadcom.com",
    "developer.broadcom.com",
    "compatibilityguide.broadcom.com",
    "www.vmware.com",
}
IPD_SUPPLEMENT_KINDS = {
    "STATUS_GATE",
    "NORMATIVE_DESIGN",
    "IMPLEMENTATION_BLUEPRINT",
    "ACCEPTANCE",
    "OFFICIAL_CONTRACT",
    "REFERENCE_OBSERVATION",
    "REFERENCE_MODEL",
    "QMAN_VERIFICATION",
    "QMAN_QUALIFICATION",
    "HISTORICAL_INPUT",
}


@dataclass(frozen=True)
class DesignContracts:
    risks: dict[str, dict[str, str]]
    cases: tuple[str, ...]


@dataclass(frozen=True)
class QmanRiskClosureReceipt:
    """A risk closure claim emitted only after its Qman record is fully valid."""

    evidence_id: str
    result_sha256: str
    evidence_grade: str


@dataclass
class Evaluation:
    errors: list[str]
    blockers: list[str]
    project: dict[str, Any]
    ipd_counts: Counter[str]
    vmware_counts: Counter[str]
    qman_evidence_counts: Counter[str]
    risk_counts: Counter[str]
    acceptance_counts: Counter[str]
    risk_total: int
    case_total: int
    missing_cases: list[str]
    executable_cases: dict[str, dict[str, Any]]


def parse_json_bytes(payload: bytes, label: str) -> dict[str, Any]:
    """Strictly parse one immutable JSON payload as an object."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate object key {key!r}")
            value[key] = item
        return value

    def reject_non_finite(token: str) -> Any:
        raise ValueError(f"non-finite JSON number {token!r}")

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"invalid UTF-8 in {label}: {exc}") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_non_finite,
        )
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid JSON in {label}:{exc.lineno}: {exc.msg}"
        ) from exc
    except RecursionError as exc:
        raise ValueError(f"invalid JSON in {label}: nesting is too deep") from exc
    except ValueError as exc:
        raise ValueError(f"invalid JSON in {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"contract root must be an object: {label}")
    return value


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
    except FileNotFoundError as exc:
        raise ValueError(f"missing contract: {path.relative_to(ROOT)}") from exc
    return parse_json_bytes(payload, str(path.relative_to(ROOT)))


def load_repository_json(relative: str, label: str) -> dict[str, Any]:
    """Load a fixed contract entry only after repository containment checks."""

    path_errors: list[str] = []
    path = repository_file(relative, label, path_errors)
    if path is None:
        raise ValueError(path_errors[-1])
    return load_json(path)


def section(text: str, start: str, end: str) -> str:
    try:
        return text.split(start, 1)[1].split(end, 1)[0]
    except IndexError as exc:
        raise ValueError(f"cannot locate design section between {start!r} and {end!r}") from exc


def extract_design_contracts(design_path: Path) -> DesignContracts:
    text = design_path.read_text(encoding="utf-8")

    risk_text = section(text, "## 18.", "### 18.1")
    risks: dict[str, dict[str, str]] = {}
    for line in risk_text.splitlines():
        if not re.match(r"^\|\s*R\d{2}\s*\|", line):
            continue
        columns = [part.strip() for part in line.strip().strip("|").split("|")]
        if len(columns) != 5:
            raise ValueError(f"risk row does not have five columns: {line}")
        risk_id, title, impact, prevention, detection = columns
        if risk_id in risks:
            raise ValueError(f"duplicate risk ID in design: {risk_id}")
        risks[risk_id] = {
            "title": title,
            "impact": impact,
            "prevention": prevention,
            "detection": detection,
        }

    case_text = section(text, "## 19.", "## 20.")
    case_ids: list[str] = []
    for match in re.finditer(r"^\|\s*([COSDMF]\d{2}[a-z]?)\s*\|", case_text, re.MULTILINE):
        case_id = match.group(1)
        if case_id not in case_ids:
            case_ids.append(case_id)

    return DesignContracts(risks=risks, cases=tuple(case_ids))


def is_iso_date(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def string_set(value: Any) -> set[str] | None:
    """Return a set only for an actual list of strings."""

    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        return None
    return set(value)


def is_rfc3339_datetime(value: Any) -> bool:
    if not isinstance(value, str) or not RFC3339_RE.fullmatch(value):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def validate_qman_result_shape(
    evidence_id: str,
    result: dict[str, Any],
    errors: list[str],
) -> None:
    """Validate the closed runtime shape before evidence can affect any gate."""

    prefix = f"Qman evidence {evidence_id}"
    if set(result) != QMAN_RESULT_REQUIRED_FIELDS:
        errors.append(f"{prefix} result fields must match the closed schema exactly")
    schema_version = result.get("schemaVersion")
    if type(schema_version) is not int or schema_version != 1:
        errors.append(f"{prefix} schemaVersion must be integer 1")
    result_id = result.get("id")
    if (
        not isinstance(result_id, str)
        or not QMAN_EVIDENCE_ID_RE.fullmatch(result_id)
        or result_id != evidence_id
    ):
        errors.append(f"{prefix} result id is invalid or differs from the index")
    if not is_rfc3339_datetime(result.get("observedAt")):
        errors.append(f"{prefix} observedAt must be a timezone-aware RFC3339 date-time")

    source_state = result.get("sourceState")
    if not isinstance(source_state, dict):
        errors.append(f"{prefix} sourceState must be an object")
        source_state = {}
    elif (
        not QMAN_SOURCE_STATE_REQUIRED_FIELDS.issubset(source_state)
        or not set(source_state).issubset(QMAN_SOURCE_STATE_FIELDS)
    ):
        errors.append(f"{prefix} sourceState fields have drifted")
    base_commit = source_state.get("baseCommit")
    if not isinstance(base_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", base_commit):
        errors.append(f"{prefix} sourceState.baseCommit must be 40 lowercase hex characters")
    if type(source_state.get("dirtyWorkingTree")) is not bool:
        errors.append(f"{prefix} sourceState.dirtyWorkingTree must be boolean")
    for field in ("runnerHashes", "inputHashes"):
        hashes = source_state.get(field)
        if field == "inputHashes" and hashes is None:
            continue
        if not isinstance(hashes, dict) or not hashes:
            errors.append(f"{prefix} sourceState.{field} must be a non-empty object")
            continue
        for relative, digest in hashes.items():
            if not isinstance(relative, str) or not relative:
                errors.append(f"{prefix} sourceState.{field} paths must be non-empty strings")
            if not isinstance(digest, str) or not HASH_RE.fullmatch(digest):
                errors.append(f"{prefix} sourceState.{field} hashes must be lowercase SHA-256")

    sut = result.get("sut")
    if not isinstance(sut, dict):
        errors.append(f"{prefix} sut must be an object")
        sut = {}
    elif set(sut) != QMAN_SUT_FIELDS:
        errors.append(f"{prefix} sut fields must be environment and components only")
    environment = sut.get("environment")
    if not isinstance(environment, str) or not environment:
        errors.append(f"{prefix} sut.environment must be a non-empty string")
    components = sut.get("components")
    if not isinstance(components, list) or not components:
        errors.append(f"{prefix} sut.components must be a non-empty array")
        components = []
    for component in components:
        if not isinstance(component, dict):
            errors.append(f"{prefix} sut component must be an object")
            continue
        if (
            not QMAN_COMPONENT_REQUIRED_FIELDS.issubset(component)
            or not set(component).issubset(QMAN_COMPONENT_FIELDS)
        ):
            errors.append(f"{prefix} sut component fields have drifted")
        for field in ("name", "version"):
            if not isinstance(component.get(field), str) or not component.get(field):
                errors.append(f"{prefix} sut component {field} must be non-empty")
        component_hash = component.get("sha256")
        if component_hash is not None and (
            not isinstance(component_hash, str) or not HASH_RE.fullmatch(component_hash)
        ):
            errors.append(f"{prefix} sut component sha256 is invalid")

    for field in ("hypotheses", "limitations"):
        values = result.get(field)
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(item, str) or not item for item in values)
        ):
            errors.append(f"{prefix} {field} must be a non-empty string array")

    observations = result.get("observations")
    if not isinstance(observations, list) or not observations:
        errors.append(f"{prefix} observations must be a non-empty array")
        observations = []
    for observation in observations:
        if not isinstance(observation, dict):
            errors.append(f"{prefix} observation must be an object")
            continue
        if set(observation) != QMAN_OBSERVATION_FIELDS:
            errors.append(f"{prefix} observation fields must be name and result only")
        if not isinstance(observation.get("name"), str) or not observation.get("name"):
            errors.append(f"{prefix} observation name must be non-empty")
        observed = observation.get("result")
        valid_observed = isinstance(observed, (str, bool, dict, list)) or (
            isinstance(observed, (int, float))
            and not isinstance(observed, bool)
            and math.isfinite(observed)
        )
        if not valid_observed:
            errors.append(f"{prefix} observation result has an invalid JSON type")

    mapping = result.get("mapping")
    if not isinstance(mapping, dict):
        errors.append(f"{prefix} mapping must be an object")
        mapping = {}
    elif set(mapping) != QMAN_MAPPING_FIELDS:
        errors.append(f"{prefix} mapping fields must match the closed schema exactly")
    mapping_rules = {
        "techStories": (False, TECH_STORY_ID_RE),
        "caseIds": (True, CASE_ID_RE),
        "riskIds": (False, re.compile(r"^R[0-9]{2}$")),
    }
    for field, (allow_empty, pattern) in mapping_rules.items():
        values = mapping.get(field)
        valid_values = string_set(values)
        if (
            valid_values is None
            or (not allow_empty and not values)
            or not isinstance(values, list)
            or len(values) != len(valid_values)
            or any(not pattern.fullmatch(item) for item in valid_values)
        ):
            errors.append(f"{prefix} mapping.{field} is invalid")

    artifacts = result.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append(f"{prefix} artifacts must be a non-empty array")
        artifacts = []
    artifact_paths: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            errors.append(f"{prefix} artifact must be an object")
            continue
        if set(artifact) != QMAN_ARTIFACT_FIELDS:
            errors.append(f"{prefix} artifact fields must match the closed schema exactly")
        artifact_path = artifact.get("path")
        if (
            not isinstance(artifact_path, str)
            or not artifact_path
            or artifact_path in artifact_paths
        ):
            errors.append(f"{prefix} artifact path must be non-empty and unique")
        else:
            artifact_paths.add(artifact_path)
        artifact_hash = artifact.get("sha256")
        if not isinstance(artifact_hash, str) or not HASH_RE.fullmatch(artifact_hash):
            errors.append(f"{prefix} artifact sha256 is invalid")
        retention = artifact.get("retention")
        if not isinstance(retention, str) or retention not in {"COMMITTED", "LOCAL_RAW"}:
            errors.append(f"{prefix} artifact retention is invalid")

    closure = result.get("closureEffect")
    if not isinstance(closure, dict):
        errors.append(f"{prefix} closureEffect must be an object")
        closure = {}
    elif set(closure) != QMAN_CLOSURE_FIELDS:
        errors.append(f"{prefix} closureEffect fields must match the closed schema exactly")
    for field, pattern in (
        ("productCasesClosed", CASE_ID_RE),
        ("risksClosed", re.compile(r"^R[0-9]{2}$")),
    ):
        values = closure.get(field)
        valid_values = string_set(values)
        if (
            valid_values is None
            or not isinstance(values, list)
            or len(values) != len(valid_values)
            or any(not pattern.fullmatch(item) for item in valid_values)
        ):
            errors.append(f"{prefix} closureEffect.{field} is invalid")
    if type(closure.get("statusUpdated")) is not bool:
        errors.append(f"{prefix} closureEffect.statusUpdated must be boolean")


def validate_product_decisions(
    contract: dict[str, Any],
    known_tech_stories: set[str],
    known_cases: set[str],
    known_risks: set[str],
    errors: list[str],
) -> tuple[list[str], bool]:
    """Validate the five G0 decisions and derive the unresolved ADR list."""

    initial_error_count = len(errors)
    if contract.get("schemaVersion") != 1:
        errors.append("product-decisions.json schemaVersion must be 1")
    if not is_iso_date(contract.get("asOf")):
        errors.append("product-decisions.json asOf must be an ISO calendar date")

    required = contract.get("requiredDecisionIds")
    if required != list(REQUIRED_PRODUCT_DECISION_IDS):
        errors.append(
            "product-decisions requiredDecisionIds must be exactly "
            f"{list(REQUIRED_PRODUCT_DECISION_IDS)}"
        )

    records = contract.get("records")
    if not isinstance(records, list):
        errors.append("product-decisions records must be a list")
        return list(REQUIRED_PRODUCT_DECISION_IDS), False

    by_id: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            errors.append("every product decision record must be an object")
            continue
        decision_id = record.get("id")
        if not isinstance(decision_id, str) or decision_id in by_id:
            errors.append(f"invalid or duplicate product decision ID: {decision_id!r}")
            continue
        by_id[decision_id] = record

    expected_ids = set(REQUIRED_PRODUCT_DECISION_IDS)
    missing = sorted(expected_ids - set(by_id))
    extra = sorted(set(by_id) - expected_ids)
    if missing:
        errors.append("product-decisions is missing required ADRs: " + ", ".join(missing))
    if extra:
        errors.append("product-decisions has unexpected ADRs: " + ", ".join(extra))

    unresolved: list[str] = []
    reference_fields = {
        "techStories": known_tech_stories,
        "caseIds": known_cases,
        "riskIds": known_risks,
    }
    for decision_id in REQUIRED_PRODUCT_DECISION_IDS:
        record = by_id.get(decision_id)
        if record is None:
            unresolved.append(decision_id)
            continue
        record_error_count = len(errors)
        if record.get("status") != "ACCEPTED":
            errors.append(f"required product decision {decision_id} must be ACCEPTED")
        for field in ("title", "owner", "source", "decision"):
            value = record.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(
                    f"product decision {decision_id} must declare non-empty {field}"
                )
        if not is_iso_date(record.get("decidedAt")):
            errors.append(
                f"product decision {decision_id} decidedAt must be an ISO calendar date"
            )
        consequences = record.get("consequences")
        if (
            not isinstance(consequences, list)
            or not consequences
            or any(not isinstance(item, str) or not item.strip() for item in consequences)
        ):
            errors.append(
                f"product decision {decision_id} consequences must be non-empty strings"
            )
        for field, known_ids in reference_fields.items():
            values = record.get(field)
            if (
                not isinstance(values, list)
                or not values
                or any(not isinstance(item, str) for item in values)
            ):
                errors.append(
                    f"product decision {decision_id} {field} must be a non-empty string list"
                )
                continue
            if len(values) != len(set(values)):
                errors.append(
                    f"product decision {decision_id} {field} must be unique"
                )
            unknown = sorted(set(values) - known_ids)
            if unknown:
                errors.append(
                    f"product decision {decision_id} {field} has unknown IDs: {unknown}"
                )
        if record.get("status") != "ACCEPTED" or len(errors) != record_error_count:
            unresolved.append(decision_id)

    return unresolved, len(errors) == initial_error_count


def validate_project_status(
    project: dict[str, Any],
    derived_open_decisions: list[str],
    errors: list[str],
    blockers: list[str],
) -> None:
    if project.get("schemaVersion") != 1:
        errors.append("project-status.json schemaVersion must be 1")
    if project.get("currentClaim") != "REFERENCE_AND_QUALIFICATION_MODEL_ONLY":
        errors.append(
            "project-status currentClaim must remain REFERENCE_AND_QUALIFICATION_MODEL_ONLY"
        )
    if project.get("freezeRules") != PROJECT_FREEZE_RULES:
        errors.append("project-status freezeRules must match the frozen governance rules")

    documents = project.get("authoritativeDocuments")
    if not isinstance(documents, dict) or not documents:
        errors.append("project-status.json must declare authoritativeDocuments")
    else:
        for name, relative in documents.items():
            repository_file(relative, f"authoritative document {name!r}", errors)
        for name, expected_path in G0_AUTHORITATIVE_DOCUMENTS.items():
            if documents.get(name) != expected_path:
                errors.append(
                    f"authoritative document {name!r} must be registered as {expected_path!r}"
                )

    milestones = project.get("milestones")
    if not isinstance(milestones, list) or not milestones:
        errors.append("project-status.json must contain milestones")
        return

    milestone_ids: list[str] = []
    milestone_by_id: dict[str, dict[str, Any]] = {}
    for item in milestones:
        if not isinstance(item, dict):
            errors.append("every milestone must be an object")
            continue
        milestone_id = item.get("id")
        state = item.get("status")
        if not isinstance(milestone_id, str) or not milestone_id:
            errors.append("every milestone must have a non-empty id")
            continue
        if milestone_id in milestone_by_id:
            errors.append(f"duplicate milestone id: {milestone_id}")
            continue
        if not isinstance(state, str) or state not in MILESTONE_STATES:
            errors.append(f"milestone {milestone_id} has invalid status: {state!r}")
        expected_name = PROJECT_MILESTONES.get(milestone_id)
        if expected_name is None or item.get("name") != expected_name:
            errors.append(f"milestone {milestone_id} name or identity has drifted")
        milestone_ids.append(milestone_id)
        milestone_by_id[milestone_id] = item

    if milestone_ids != list(PROJECT_MILESTONES):
        errors.append("project milestones must be exactly ordered G0 through G6")

    in_progress = [mid for mid in milestone_ids if milestone_by_id[mid].get("status") == "IN_PROGRESS"]
    current = project.get("currentMilestone")
    if current is None:
        if in_progress:
            errors.append(f"currentMilestone is null but milestones are IN_PROGRESS: {in_progress}")
    elif not isinstance(current, str) or current not in milestone_by_id:
        errors.append(f"currentMilestone is not declared: {current!r}")
    elif milestone_by_id[current].get("status") != "IN_PROGRESS" or in_progress != [current]:
        errors.append(f"exactly currentMilestone must be IN_PROGRESS; observed {in_progress}")
    else:
        current_index = milestone_ids.index(current)
        incomplete_predecessors = [
            milestone_id
            for milestone_id in milestone_ids[:current_index]
            if milestone_by_id[milestone_id].get("status") != "DONE"
        ]
        if incomplete_predecessors:
            errors.append(
                "milestones before currentMilestone must be DONE: "
                + ", ".join(incomplete_predecessors)
            )

    unfinished = [mid for mid in milestone_ids if milestone_by_id[mid].get("status") != "DONE"]
    if unfinished:
        blockers.append("unfinished milestones: " + ", ".join(unfinished))

    decisions = project.get("openDecisions")
    if not isinstance(decisions, list) or any(not isinstance(item, str) for item in decisions):
        errors.append("openDecisions must be a list of ADR IDs")
    else:
        if len(decisions) != len(set(decisions)):
            errors.append("openDecisions must not contain duplicates")
        if decisions != derived_open_decisions:
            errors.append(
                "openDecisions must equal unresolved product decisions: "
                f"declared={decisions}, derived={derived_open_decisions}"
            )
        if decisions:
            blockers.append("open product/platform decisions: " + ", ".join(decisions))


def validate_compatibility_profile_policy(
    policy: dict[str, Any], errors: list[str]
) -> bool:
    """Validate the frozen six-platform, Legacy-first and HCL boundary."""

    initial_error_count = len(errors)
    if policy.get("schemaVersion") != 1:
        errors.append("compatibility-profile-policy schemaVersion must be 1")
    if not is_iso_date(policy.get("asOf")):
        errors.append("compatibility-profile-policy asOf must be an ISO calendar date")
    if policy.get("capabilityTarget") != "V3_FULL_DIRECTPATH":
        errors.append("compatibility capabilityTarget must be V3_FULL_DIRECTPATH")

    backend = policy.get("backendPolicy")
    if not isinstance(backend, dict):
        errors.append("compatibility backendPolicy must be an object")
        backend = {}
    backend_expectations = {
        "currentProductFamily": "LEGACY_VFIO_TYPE1",
        "selection": "EXACT_PROFILE_PIN",
        "silentFallback": False,
        "noIommu": "HARD_REJECT",
        "sharedControlPlane": True,
    }
    for field, expected in backend_expectations.items():
        if backend.get(field) != expected:
            errors.append(
                f"compatibility backendPolicy.{field} must be {expected!r}"
            )
    allowed_types = backend.get("allowedConfiguredTypes")
    if (
        not isinstance(allowed_types, list)
        or any(not isinstance(item, str) for item in allowed_types)
        or set(allowed_types)
        != {
            "VFIO_TYPE1V2_IOMMU",
            "VFIO_TYPE1_IOMMU",
        }
    ):
        errors.append(
            "compatibility allowedConfiguredTypes must exactly pin TYPE1v2 and TYPE1 IOMMU"
        )
    future_families = backend.get("futureFamilies")
    if (
        not isinstance(future_families, list)
        or any(not isinstance(item, str) for item in future_families)
        or set(future_families) != {"VFIO_CDEV_IOMMUFD"}
    ):
        errors.append(
            "compatibility futureFamilies must isolate VFIO_CDEV_IOMMUFD from the current backend"
        )
    adapter_differences = backend.get("adapterOnlyDifferences")
    if (
        not isinstance(adapter_differences, list)
        or len(adapter_differences) != len(LEGACY_ADAPTER_ONLY_DIFFERENCES)
        or set(adapter_differences) != LEGACY_ADAPTER_ONLY_DIFFERENCES
    ):
        errors.append(
            "compatibility adapterOnlyDifferences must exactly preserve the shared-control-plane adapter boundary"
        )
    legacy_authorization = backend.get("legacyLaunchAuthorization")
    if not isinstance(legacy_authorization, dict):
        errors.append("compatibility legacyLaunchAuthorization must be an object")
        legacy_authorization = {}
    if legacy_authorization.get("qemuDeviceSelector") != "EXACT_HOST_BDF":
        errors.append("Legacy launch authorization must select one exact host BDF")
    if legacy_authorization.get("preopenedDeviceFdPassing") is not False:
        errors.append("Legacy launch authorization must not claim pre-opened device fd passing")
    authorization_sets = {
        "requiredIsolation": LEGACY_REQUIRED_ISOLATION,
        "postSpawnReceipt": LEGACY_POST_SPAWN_RECEIPT,
    }
    for field, expected_values in authorization_sets.items():
        values = legacy_authorization.get(field)
        if (
            not isinstance(values, list)
            or len(values) != len(expected_values)
            or set(values) != expected_values
        ):
            errors.append(
                f"compatibility legacyLaunchAuthorization.{field} must exactly match the frozen security boundary"
            )

    host_policy = policy.get("hostConfigurationPolicy")
    if not isinstance(host_policy, dict):
        errors.append("compatibility hostConfigurationPolicy must be an object")
        host_policy = {}
    host_expectations = {
        "modifiesBios": False,
        "modifiesKernelCommandLine": False,
        "iommuProbe": "RUNTIME_FAIL_CLOSED",
        "interruptIsolationProbe": "RUNTIME_FAIL_CLOSED",
        "acsOverride": "NEVER_TRUST_AS_PHYSICAL_ISOLATION_PROOF",
    }
    for field, expected in host_expectations.items():
        if host_policy.get(field) != expected:
            errors.append(
                f"compatibility hostConfigurationPolicy.{field} must be {expected!r}"
            )

    expected_platforms = {
        "TEST-KYLIN-V10-ARM": {
            "deliveryClass": "SMALL_SCALE_TEST_SHIPMENT",
            "os": "Kylin V10",
            "architecture": "ARM64",
            "kernel": "4.19",
            "qemu": "5.0",
        },
        "TEST-KYLIN-V10-C86": {
            "deliveryClass": "SMALL_SCALE_TEST_SHIPMENT",
            "os": "Kylin V10",
            "architecture": "C86",
            "kernel": "4.19",
            "qemu": "5.0",
        },
        "TEST-RH-X86": {
            "deliveryClass": "SMALL_SCALE_TEST_SHIPMENT",
            "os": "RH-family",
            "architecture": "X86_64",
            "kernel": "4.18",
            "qemu": "5.0",
        },
        "MAIN-KYLIN-V11-ARM": {
            "deliveryClass": "MAINLINE",
            "os": "Kylin V11",
            "architecture": "ARM64",
            "kernel": "6.6",
            "qemu": "10.2",
        },
        "MAIN-KYLIN-V11-C86": {
            "deliveryClass": "MAINLINE",
            "os": "Kylin V11",
            "architecture": "C86",
            "kernel": "6.6",
            "qemu": "10.2",
        },
        "MAIN-OPENEULER-X86": {
            "deliveryClass": "MAINLINE",
            "os": "openEuler",
            "architecture": "X86_64",
            "kernel": "6.6",
            "qemu": "10.2",
        },
    }
    platforms = policy.get("platforms")
    if not isinstance(platforms, list):
        errors.append("compatibility platforms must be a list")
        platforms = []
    if len(platforms) != 6:
        errors.append("compatibility policy must declare exactly six platform rows")
    platforms_by_id: dict[str, dict[str, Any]] = {}
    for platform in platforms:
        if not isinstance(platform, dict):
            errors.append("every compatibility platform row must be an object")
            continue
        platform_id = platform.get("id")
        if not isinstance(platform_id, str) or platform_id in platforms_by_id:
            errors.append(f"invalid or duplicate compatibility platform ID: {platform_id!r}")
            continue
        platforms_by_id[platform_id] = platform
    missing_platforms = sorted(set(expected_platforms) - set(platforms_by_id))
    extra_platforms = sorted(set(platforms_by_id) - set(expected_platforms))
    if missing_platforms:
        errors.append("compatibility policy is missing platform rows: " + ", ".join(missing_platforms))
    if extra_platforms:
        errors.append("compatibility policy has unexpected platform rows: " + ", ".join(extra_platforms))

    x86_matrix = {
        ("q35", "UEFI"),
        ("q35", "SeaBIOS"),
        ("i440fx", "UEFI"),
        ("i440fx", "SeaBIOS"),
    }
    arm_matrix = {("virt", "UEFI")}
    for platform_id, expected in expected_platforms.items():
        platform = platforms_by_id.get(platform_id)
        if platform is None:
            continue
        for field, expected_value in expected.items():
            if platform.get(field) != expected_value:
                errors.append(
                    f"platform {platform_id} {field} must be {expected_value!r}"
                )
        if platform.get("capabilityModel") != "V3_FULL_DIRECTPATH":
            errors.append(f"platform {platform_id} must expose the V3 capability model")
        if platform.get("backendFamily") != "LEGACY_VFIO_TYPE1":
            errors.append(f"platform {platform_id} must use the current Legacy backend")
        machine_firmware = platform.get("machineFirmware")
        observed_matrix: set[tuple[str, str]] = set()
        if not isinstance(machine_firmware, list):
            errors.append(f"platform {platform_id} machineFirmware must be a list")
        else:
            for item in machine_firmware:
                if not isinstance(item, dict):
                    errors.append(
                        f"platform {platform_id} machineFirmware entries must be objects"
                    )
                    continue
                machine = item.get("machine")
                firmware = item.get("firmware")
                if not isinstance(machine, str) or not isinstance(firmware, str):
                    errors.append(
                        f"platform {platform_id} machineFirmware entries must contain strings"
                    )
                    continue
                observed_matrix.add((machine, firmware))
            if len(observed_matrix) != len(machine_firmware):
                errors.append(f"platform {platform_id} machineFirmware entries must be unique")
        required_matrix = (
            arm_matrix if expected["architecture"] == "ARM64" else x86_matrix
        )
        if observed_matrix != required_matrix:
            matrix_name = "virt+UEFI" if required_matrix == arm_matrix else "x86/C86 four-cell"
            errors.append(
                f"platform {platform_id} must use the exact {matrix_name} machine/firmware matrix"
            )

    hcl = policy.get("hclPolicy")
    if not isinstance(hcl, dict):
        errors.append("compatibility hclPolicy must be an object")
        hcl = {}
    hcl_expectations = {
        "engineScope": "GENERIC_PCI",
        "productionRequiresExactCatalogMatch": True,
        "wildcardSupportEntryAllowed": False,
        "unqualifiedLabProductionEligible": False,
    }
    for field, expected in hcl_expectations.items():
        if hcl.get(field) != expected:
            errors.append(f"compatibility hclPolicy.{field} must be {expected!r}")
    archetypes = hcl.get("archetypes")
    archetype_ids = {
        item.get("id")
        for item in archetypes
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    } if isinstance(archetypes, list) else set()
    if archetype_ids != set(HCL_ARCHETYPE_TRAITS):
        errors.append("compatibility HCL must declare the four frozen technical archetypes")
    if not isinstance(archetypes, list) or len(archetypes) != len(archetype_ids):
        errors.append("compatibility HCL archetypes must be unique objects")
    if isinstance(archetypes, list):
        for archetype in archetypes:
            if not isinstance(archetype, dict):
                continue
            archetype_id = archetype.get("id")
            coverage = archetype.get("requiredTraitCoverage")
            expected_coverage = (
                HCL_ARCHETYPE_TRAITS.get(archetype_id)
                if isinstance(archetype_id, str)
                else None
            )
            if (
                expected_coverage is None
                or string_set(coverage) != expected_coverage
                or not isinstance(coverage, list)
                or len(coverage) != len(expected_coverage)
            ):
                errors.append(
                    f"HCL archetype {archetype_id!r} must exactly match its frozen required trait coverage"
                )
    issuer = hcl.get("qualificationIssuer")
    approver = hcl.get("supportedCatalogApprover")
    if issuer != "Qualification Engineering":
        errors.append(
            "compatibility HCL qualificationIssuer must be Qualification Engineering"
        )
    if approver != "Product Release":
        errors.append(
            "compatibility HCL supportedCatalogApprover must be Product Release"
        )
    catalog_lifecycle = hcl.get("catalogLifecycle")
    if (
        not isinstance(catalog_lifecycle, list)
        or any(not isinstance(item, str) for item in catalog_lifecycle)
        or set(catalog_lifecycle)
        != {"SIGNED", "VERSIONED", "REVOCABLE", "HASH_BOUND"}
    ):
        errors.append("compatibility HCL catalog lifecycle must be signed, versioned, revocable and hash-bound")

    cluster = policy.get("clusterPolicy")
    if not isinstance(cluster, dict):
        errors.append("compatibility clusterPolicy must be an object")
        cluster = {}
    cluster_expectations = {
        "supportedRelocation": "PLANNED_COLD_RELOCATION_BETWEEN_ONLINE_HOSTS",
        "requiresSourceCleanReleaseReceipt": True,
        "targetMustResolveAgain": True,
        "sourceUnreachableAction": "HOLD_LEASE_KEEP_VM_STOPPED_NO_REASSIGNMENT",
        "hostFailureAutomaticRestart": False,
        "bmcOrPowerFenceIntegration": False,
        "logicalEpochPurpose": "REJECT_STALE_CONTROL_MUTATIONS_ONLY",
    }
    for field, expected in cluster_expectations.items():
        if cluster.get(field) != expected:
            errors.append(f"compatibility clusterPolicy.{field} must be {expected!r}")

    return len(errors) == initial_error_count


def validate_qemu_vfio_launch_surface(
    contract: dict[str, Any],
    compatibility_policy: dict[str, Any],
    errors: list[str],
) -> bool:
    """Validate the version-specific Legacy versus IOMMUFD launch surface."""

    initial_error_count = len(errors)

    def string_set(value: Any) -> set[str]:
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            return set()
        return set(value)

    if contract.get("schemaVersion") != 1:
        errors.append("qemu-vfio-launch-surface schemaVersion must be 1")
    if not is_iso_date(contract.get("asOf")):
        errors.append("qemu-vfio-launch-surface asOf must be an ISO calendar date")
    property_semantics = contract.get("devicePropertiesSemantics")
    if not isinstance(property_semantics, dict):
        errors.append("qemu-vfio-launch-surface must define devicePropertiesSemantics")
        property_semantics = {}
    if property_semantics.get("kind") != "QUALIFICATION_PROFILE_ALLOWLIST":
        errors.append("deviceProperties must be a qualification-profile allowlist")
    if property_semantics.get("binarySurfaceComplete") is not False:
        errors.append("deviceProperties must not claim to be the complete QEMU binary surface")
    if (
        property_semantics.get("externalDeviceFdPropertyMeaning")
        != "PROFILE_ALLOWS_EXTERNAL_DEVICE_FD"
    ):
        errors.append(
            "externalDeviceFdProperty must describe profile permission, not binary exposure"
        )
    semantics_rule = property_semantics.get("rule")
    if not isinstance(semantics_rule, str) or not semantics_rule.strip():
        errors.append("deviceProperties semantics must declare the binary/profile boundary rule")
    profiles = contract.get("profiles")
    if not isinstance(profiles, list):
        errors.append("qemu-vfio-launch-surface profiles must be a list")
        profiles = []
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for profile in profiles:
        if not isinstance(profile, dict):
            errors.append("every QEMU launch-surface profile must be an object")
            continue
        qemu = profile.get("qemu")
        backend = profile.get("backend")
        key = (qemu, backend)
        if not isinstance(qemu, str) or not isinstance(backend, str) or key in by_key:
            errors.append(f"invalid or duplicate QEMU launch-surface profile: {key!r}")
            continue
        by_key[key] = profile
        properties = profile.get("deviceProperties")
        if not isinstance(properties, list) or any(
            not isinstance(item, str) for item in properties
        ):
            errors.append(f"QEMU launch profile {key!r} deviceProperties must be strings")
            properties = []
        elif len(properties) != len(set(properties)):
            errors.append(f"QEMU launch profile {key!r} deviceProperties must be unique")
        has_external_fd = profile.get("externalDeviceFdProperty")
        if not isinstance(has_external_fd, bool):
            errors.append(
                f"QEMU launch profile {key!r} externalDeviceFdProperty must be boolean"
            )
        if backend == "LEGACY_VFIO_TYPE1":
            if has_external_fd is not False or {"fd", "iommufd"} & set(properties):
                errors.append(
                    f"Legacy QEMU qualification profile {qemu} must not allow external fd/iommufd properties"
                )
        elif has_external_fd is True and backend != "VFIO_CDEV_IOMMUFD":
            errors.append(
                f"QEMU launch profile {qemu} may expose fd only for VFIO_CDEV_IOMMUFD"
            )

    expected_profile_keys = {
        ("5.0", "LEGACY_VFIO_TYPE1"),
        ("6.2", "LEGACY_VFIO_TYPE1"),
        ("10.2", "LEGACY_VFIO_TYPE1"),
        ("10.2", "VFIO_CDEV_IOMMUFD"),
    }
    if set(by_key) != expected_profile_keys:
        errors.append(
            "QEMU launch surface must contain exactly four profiles: 5.0/6.2/10.2 Legacy and 10.2 IOMMUFD"
        )

    expected_usage = {
        ("5.0", "LEGACY_VFIO_TYPE1"): "CURRENT_PRODUCT",
        ("6.2", "LEGACY_VFIO_TYPE1"): "REFERENCE_COMPATIBILITY_PROBE",
        ("10.2", "LEGACY_VFIO_TYPE1"): "CURRENT_PRODUCT",
        ("10.2", "VFIO_CDEV_IOMMUFD"): "FUTURE_QUALIFICATION_ONLY",
    }
    for key, usage in expected_usage.items():
        profile = by_key.get(key)
        if profile is not None and profile.get("qualificationUsage") != usage:
            errors.append(f"QEMU launch profile {key!r} qualificationUsage must be {usage}")

    qemu5_legacy = by_key.get(("5.0", "LEGACY_VFIO_TYPE1"))
    if qemu5_legacy is None:
        errors.append("QEMU 5.0 Legacy launch-surface profile is required")
    elif not isinstance(qemu5_legacy.get("deviceProperties"), list) or set(
        item
        for item in qemu5_legacy.get("deviceProperties", [])
        if isinstance(item, str)
    ) != {"host", "sysfsdev"}:
        errors.append("QEMU 5.0 Legacy vfio-pci properties must be exactly host and sysfsdev")
    qemu6_legacy = by_key.get(("6.2", "LEGACY_VFIO_TYPE1"))
    if qemu6_legacy is None:
        errors.append("QEMU 6.2 Legacy launch-surface profile is required")
    elif string_set(qemu6_legacy.get("deviceProperties")) != {"host", "sysfsdev"}:
        errors.append("QEMU 6.2 Legacy vfio-pci properties must be exactly host and sysfsdev")
    qemu10_legacy = by_key.get(("10.2", "LEGACY_VFIO_TYPE1"))
    if qemu10_legacy is None:
        errors.append("QEMU 10.2 current Legacy launch-surface profile is required")
    else:
        if string_set(qemu10_legacy.get("deviceProperties")) != {"host", "sysfsdev"}:
            errors.append(
                "QEMU 10.2 Legacy qualification properties must be exactly host and sysfsdev"
            )
        if string_set(qemu10_legacy.get("binaryMayExposeAdditionalProperties")) != {
            "fd",
            "iommufd",
        }:
            errors.append(
                "QEMU 10.2 Legacy profile must record that the binary may expose fd/iommufd"
            )
        if qemu10_legacy.get("binaryExposureCondition") != "CONFIG_IOMMUFD":
            errors.append(
                "QEMU 10.2 Legacy binary fd/iommufd exposure must be conditional on CONFIG_IOMMUFD"
            )
        if string_set(qemu10_legacy.get("profileForbiddenProperties")) != {
            "fd",
            "iommufd",
        }:
            errors.append(
                "QEMU 10.2 Legacy qualification profile must explicitly forbid fd/iommufd"
            )
    qemu10_iommufd = by_key.get(("10.2", "VFIO_CDEV_IOMMUFD"))
    if qemu10_iommufd is None:
        errors.append("QEMU 10.2 IOMMUFD launch-surface profile is required")
    else:
        raw_properties = qemu10_iommufd.get("deviceProperties")
        properties = (
            set(item for item in raw_properties if isinstance(item, str))
            if isinstance(raw_properties, list)
            else set()
        )
        if properties != {"host", "sysfsdev", "iommufd", "fd"}:
            errors.append("QEMU 10.2 IOMMUFD properties must be exactly host, sysfsdev, iommufd and fd")
        if qemu10_iommufd.get("externalDeviceFdProperty") is not True:
            errors.append("QEMU 10.2 IOMMUFD profile must mark external fd support")
        if qemu10_iommufd.get("fdPropertyCompileGuard") != "CONFIG_IOMMUFD":
            errors.append("QEMU 10.2 fd property must be guarded by CONFIG_IOMMUFD")

    decision = contract.get("qmanDecision")
    if not isinstance(decision, dict):
        errors.append("qemu-vfio-launch-surface qmanDecision must be an object")
        decision = {}
    current_backend = (
        compatibility_policy.get("backendPolicy", {}).get("currentProductFamily")
        if isinstance(compatibility_policy.get("backendPolicy"), dict)
        else None
    )
    if decision.get("currentBackend") != "LEGACY_VFIO_TYPE1" or decision.get(
        "currentBackend"
    ) != current_backend:
        errors.append("Qman launch decision must match the current Legacy compatibility backend")
    if decision.get("launchGrantKind") != "AUTHORIZED_DEVICE_PATH":
        errors.append("Qman Legacy launch grant must be AUTHORIZED_DEVICE_PATH")
    if decision.get("qemuArgument") != "-device vfio-pci,host=<exact-bdf>":
        errors.append("Qman Legacy launch argument must pin one exact host BDF")
    authorization_boundary = decision.get("authorizationBoundary")
    if not isinstance(authorization_boundary, str) or not authorization_boundary.strip():
        errors.append("Qman Legacy launch decision must declare its authorization boundary")
    forbidden = decision.get("forbidden")
    expected_forbidden = {
        "CLAIM_LEGACY_FD_ONLY_ON_STOCK_QEMU_5_0",
        "SHARED_QEMU_UID_WITH_BROAD_DEV_VFIO_ACCESS",
        "SILENT_LEGACY_TO_IOMMUFD_FALLBACK",
        "RAW_QEMU_OR_ALTERNATE_MONITOR_BYPASS",
    }
    if (
        not isinstance(forbidden, list)
        or any(not isinstance(item, str) for item in forbidden)
        or set(forbidden) != expected_forbidden
    ):
        errors.append("Qman Legacy launch decision must preserve all four forbidden paths")

    return len(errors) == initial_error_count


def validate_g0_completion(
    project: dict[str, Any],
    *,
    decisions_ready: bool,
    profile_ready: bool,
    launch_surface_ready: bool,
    acceptance_ready: bool,
    risk_governance_ready: bool,
    errors: list[str],
) -> None:
    milestones = project.get("milestones")
    if not isinstance(milestones, list):
        return
    milestone_by_id = {
        item.get("id"): item
        for item in milestones
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    if milestone_by_id.get("G0", {}).get("status") != "DONE":
        return
    readiness = {
        "accepted product decisions": decisions_ready,
        "compatibility profile policy": profile_ready,
        "QEMU VFIO launch surface": launch_surface_ready,
        "101 classified acceptance cases": acceptance_ready,
        "39 governed risks": risk_governance_ready,
    }
    missing = [name for name, ready in readiness.items() if not ready]
    if missing:
        errors.append("G0 is DONE without required convergence: " + ", ".join(missing))


def validate_risks(
    policy: dict[str, Any],
    design: DesignContracts,
    qman_risk_closure_receipts: dict[str, list[QmanRiskClosureReceipt]],
    errors: list[str],
    blockers: list[str],
) -> Counter[str]:
    if policy.get("schemaVersion") != 1:
        errors.append("risk-status.json schemaVersion must be 1")
    expected = policy.get("expectedRiskCount")
    if expected != len(design.risks):
        errors.append(
            f"risk source count drift: policy expects {expected}, design contains {len(design.risks)}"
        )

    records = policy.get("records")
    if not isinstance(records, list):
        errors.append("risk-status.json records must be a list")
        return Counter()

    by_id: dict[str, dict[str, Any]] = {}
    counts: Counter[str] = Counter()
    incomplete_closed: list[str] = []
    if not isinstance(qman_risk_closure_receipts, dict):
        errors.append("validated Qman risk closure receipts must be a mapping")
        qman_risk_closure_receipts = {}
    required_keys = {
        "id",
        "status",
        "owner",
        "containmentRecovery",
        "testIds",
        "evidenceGrade",
        "artifactHashes",
    }

    for record in records:
        if not isinstance(record, dict):
            errors.append("every risk status record must be an object")
            continue
        missing_keys = required_keys - set(record)
        if missing_keys:
            errors.append(f"risk record missing keys {sorted(missing_keys)}: {record.get('id')!r}")
            continue
        risk_id = record["id"]
        if not isinstance(risk_id, str) or risk_id in by_id:
            errors.append(f"invalid or duplicate risk ID: {risk_id!r}")
            continue
        by_id[risk_id] = record
        state = record["status"]
        if state not in RISK_STATES:
            errors.append(f"risk {risk_id} has invalid status: {state!r}")
            continue
        counts[state] += 1

        owner = record["owner"]
        if not isinstance(owner, str) or not owner.strip():
            errors.append(f"risk {risk_id} must declare a non-empty accountable owner role")
        containment_recovery = record["containmentRecovery"]
        if (
            not isinstance(containment_recovery, str)
            or not containment_recovery.strip()
        ):
            errors.append(
                f"risk {risk_id} must declare non-empty containmentRecovery"
            )

        test_ids = record["testIds"]
        hashes = record["artifactHashes"]
        evidence_grade = record["evidenceGrade"]
        if not isinstance(test_ids, list) or any(not isinstance(item, str) for item in test_ids):
            errors.append(f"risk {risk_id} testIds must be a list of strings")
            test_ids = []
        else:
            if len(test_ids) != len(set(test_ids)):
                errors.append(f"risk {risk_id} testIds must be unique")
            if not test_ids:
                errors.append(f"risk {risk_id} must reference at least one design Case ID")
            unknown_test_ids = sorted(set(test_ids) - set(design.cases))
            if unknown_test_ids:
                errors.append(
                    f"risk {risk_id} references unknown product test IDs: {unknown_test_ids}"
                )
        if not isinstance(hashes, list) or any(not isinstance(item, str) for item in hashes):
            errors.append(f"risk {risk_id} artifactHashes must be a list of strings")
            hashes = []
        elif any(not HASH_RE.fullmatch(item) for item in hashes):
            errors.append(f"risk {risk_id} contains a non-SHA256 artifact hash")
        elif len(hashes) != len(set(hashes)):
            errors.append(f"risk {risk_id} artifactHashes must be unique")
        if evidence_grade not in RISK_EVIDENCE_GRADES:
            errors.append(f"risk {risk_id} has invalid evidenceGrade: {evidence_grade!r}")

        if state == "OPEN":
            if evidence_grade != "NONE":
                errors.append(f"open risk {risk_id} evidenceGrade must be NONE")
            if hashes:
                errors.append(f"open risk {risk_id} artifactHashes must be empty")

        if state in {"VERIFIED", "FEATURE_DISABLED"}:
            complete = (
                bool(record["owner"])
                and bool(record["containmentRecovery"])
                and bool(test_ids)
                and evidence_grade in {"E3", "E4"}
                and bool(hashes)
            )
            closing_evidence = qman_risk_closure_receipts.get(risk_id, [])
            closure_matches = any(
                isinstance(receipt, QmanRiskClosureReceipt)
                and receipt.result_sha256 in hashes
                and receipt.evidence_grade == evidence_grade
                for receipt in closing_evidence
            )
            complete = complete and closure_matches
            if not complete:
                incomplete_closed.append(risk_id)

    source_ids = set(design.risks)
    status_ids = set(by_id)
    missing = sorted(source_ids - status_ids)
    extra = sorted(status_ids - source_ids)
    if missing:
        errors.append("risk-status.json is missing: " + ", ".join(missing))
    if extra:
        errors.append("risk-status.json has IDs absent from design: " + ", ".join(extra))
    if incomplete_closed:
        blockers.append(
            "risks claim closure without owner/recovery/known-test/E3-or-E4/Qman-closure-evidence: "
            + ", ".join(incomplete_closed)
        )

    blocking_ids = sorted(
        risk_id
        for risk_id, record in by_id.items()
        if record.get("status") in BLOCKING_RISK_STATES
    )
    if blocking_ids:
        blockers.append(
            f"blocking risk states: {len(blocking_ids)}/{len(design.risks)} records"
        )
    return counts


def collect_ipd_tech_story_ids(contract: dict[str, Any]) -> set[str]:
    """Return the machine-defined TS IDs without assuming the IPD tree is valid."""

    features = contract.get("features")
    if not isinstance(features, list):
        return set()
    story_ids: set[str] = set()
    for feature in features:
        if not isinstance(feature, dict):
            continue
        tech_stories = feature.get("techStories")
        if not isinstance(tech_stories, list):
            continue
        for story in tech_stories:
            story_id = story.get("id") if isinstance(story, dict) else None
            if isinstance(story_id, str):
                story_ids.add(story_id)
    return story_ids


def validate_acceptance_dependencies(
    definitions: dict[str, dict[str, Any]],
    design_case_ids: set[str],
    known_tech_story_ids: set[str],
    errors: list[str],
    blockers: list[str],
) -> None:
    """Validate dependency structure and report incomplete closure as blockers.

    A dependency is structurally valid when it points at one of the 101 design
    Case IDs, even if that Case has not been defined yet.  Undefined, blocked,
    or reference-scope prerequisites therefore make release unready without
    corrupting the contract.  Unknown IDs, unknown TS IDs, self-dependencies,
    and cycles are contract errors.
    """

    graph: dict[str, list[str]] = {}
    for case_id, case in definitions.items():
        required_tech_stories = case.get("requiredTechStories")
        if not isinstance(required_tech_stories, list) or any(
            not isinstance(item, str) for item in required_tech_stories
        ):
            errors.append(
                f"acceptance case {case_id} requiredTechStories must be a string list"
            )
        else:
            if len(required_tech_stories) != len(set(required_tech_stories)):
                errors.append(
                    f"acceptance case {case_id} requiredTechStories must be unique"
                )
            unknown_tech_stories = sorted(
                set(required_tech_stories) - known_tech_story_ids
            )
            if unknown_tech_stories:
                errors.append(
                    f"acceptance case {case_id} references unknown tech stories: "
                    f"{unknown_tech_stories}"
                )

        dependencies = case.get("dependsOnCaseIds")
        if not isinstance(dependencies, list) or any(
            not isinstance(item, str) for item in dependencies
        ):
            errors.append(
                f"acceptance case {case_id} dependsOnCaseIds must be a string list"
            )
            graph[case_id] = []
            continue
        if len(dependencies) != len(set(dependencies)):
            errors.append(f"acceptance case {case_id} dependsOnCaseIds must be unique")
        if case_id in dependencies:
            errors.append(f"acceptance case {case_id} cannot depend on itself")
        unknown_case_ids = sorted(set(dependencies) - design_case_ids)
        if unknown_case_ids:
            errors.append(
                f"acceptance case {case_id} references unknown dependency cases: "
                f"{unknown_case_ids}"
            )
        graph[case_id] = list(
            dict.fromkeys(
                dependency
                for dependency in dependencies
                if dependency in design_case_ids and dependency != case_id
            )
        )

    colors: dict[str, int] = {}
    stack: list[str] = []
    reported_cycles: set[frozenset[str]] = set()

    def visit(case_id: str) -> None:
        colors[case_id] = 1
        stack.append(case_id)
        for dependency in graph.get(case_id, []):
            if dependency not in graph:
                continue
            color = colors.get(dependency, 0)
            if color == 0:
                visit(dependency)
            elif color == 1:
                cycle_start = stack.index(dependency)
                cycle = stack[cycle_start:] + [dependency]
                cycle_key = frozenset(cycle)
                if cycle_key not in reported_cycles:
                    reported_cycles.add(cycle_key)
                    errors.append(
                        "acceptance dependency graph contains a cycle: "
                        + " -> ".join(cycle)
                    )
        stack.pop()
        colors[case_id] = 2

    for case_id in sorted(graph):
        if colors.get(case_id, 0) == 0:
            visit(case_id)

    for case_id, dependencies in sorted(graph.items()):
        dependent = definitions[case_id]
        for dependency_id in dependencies:
            dependency = definitions.get(dependency_id)
            if dependency is None:
                blockers.append(
                    f"acceptance dependency is not defined: {case_id} -> {dependency_id}"
                )
                continue
            if dependent.get("scope") == "PRODUCT" and dependency.get("scope") != "PRODUCT":
                blockers.append(
                    "product acceptance dependency is reference-only: "
                    f"{case_id} -> {dependency_id}"
                )
                continue
            dependency_status = dependency.get("status")
            if dependency_status not in CASE_DEPENDENCY_CLOSEABLE_STATES:
                blockers.append(
                    "acceptance dependency is not closure-ready: "
                    f"{case_id} -> {dependency_id} ({dependency_status})"
                )


def validate_acceptance(
    policy: dict[str, Any],
    design: DesignContracts,
    known_risks: set[str],
    known_tech_story_ids: set[str],
    errors: list[str],
    blockers: list[str],
) -> tuple[Counter[str], list[str], dict[str, dict[str, Any]]]:
    if policy.get("schemaVersion") != 2:
        errors.append("acceptance-policy.json schemaVersion must be 2")
    expected = policy.get("expectedCaseCount")
    if expected != len(design.cases):
        errors.append(
            f"acceptance source count drift: policy expects {expected}, design contains {len(design.cases)}"
        )

    directory_value = policy.get("caseDefinitionDirectory")
    if not isinstance(directory_value, str):
        errors.append("acceptance policy must declare caseDefinitionDirectory")
        return Counter(), list(design.cases), {}
    directory = repository_directory(
        directory_value, "acceptance definition directory", errors
    )
    if directory is None:
        return Counter(), list(design.cases), {}

    allowed = string_set(policy.get("allowedStatuses"))
    if allowed != CASE_STATES:
        errors.append(f"acceptance allowedStatuses must be {sorted(CASE_STATES)}")
    if policy.get("definitionFileForms") != [
        "SINGLE_CASE_OBJECT",
        "EXPLICIT_RECORDS_ARRAY",
    ]:
        errors.append(
            "acceptance definitionFileForms must allow only single objects and explicit records arrays"
        )
    if policy.get("wildcardsAllowed") is not False:
        errors.append("acceptance policy must forbid wildcard case definitions")

    dependency_policy = policy.get("dependencyPolicy")
    if not isinstance(dependency_policy, dict):
        errors.append("acceptance policy must declare dependencyPolicy")
    else:
        required_fields = dependency_policy.get("requiredFields")
        if (
            not isinstance(required_fields, list)
            or any(not isinstance(item, str) for item in required_fields)
            or set(required_fields) != CASE_DEPENDENCY_REQUIRED_FIELDS
        ):
            errors.append(
                "acceptance dependencyPolicy requiredFields must be "
                f"{sorted(CASE_DEPENDENCY_REQUIRED_FIELDS)}"
            )
        closeable_statuses = dependency_policy.get("closeableStatuses")
        if (
            not isinstance(closeable_statuses, list)
            or any(not isinstance(item, str) for item in closeable_statuses)
            or set(closeable_statuses) != CASE_DEPENDENCY_CLOSEABLE_STATES
        ):
            errors.append(
                "acceptance dependencyPolicy closeableStatuses must be "
                f"{sorted(CASE_DEPENDENCY_CLOSEABLE_STATES)}"
            )
        if dependency_policy.get("productDependenciesRequireProductScope") is not True:
            errors.append(
                "acceptance dependencyPolicy must require PRODUCT scope dependencies"
            )
        if dependency_policy.get("undefinedOrUnreadyEffect") != "RELEASE_BLOCKER":
            errors.append(
                "acceptance dependencyPolicy undefinedOrUnreadyEffect must be RELEASE_BLOCKER"
            )
        if dependency_policy.get("unknownReferenceOrCycleEffect") != "CONTRACT_INVALID":
            errors.append(
                "acceptance dependencyPolicy unknownReferenceOrCycleEffect must be CONTRACT_INVALID"
            )

    definitions: dict[str, dict[str, Any]] = {}
    counts: Counter[str] = Counter()
    executable: dict[str, dict[str, Any]] = {}
    reference_only: list[str] = []
    case_sources: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(directory.glob("*.json")):
        resolved_path = repository_discovered_file(
            path, f"acceptance definition {path.name}", errors
        )
        if resolved_path is None:
            continue
        try:
            payload = load_json(resolved_path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if "records" not in payload:
            case_sources.append((path, payload))
            continue
        records = payload.get("records")
        if not isinstance(records, list) or not records:
            errors.append(f"acceptance registry {path.name} records must be a non-empty list")
            continue
        for index, case in enumerate(records):
            if not isinstance(case, dict):
                errors.append(
                    f"acceptance registry {path.name} record {index} must be an object"
                )
                continue
            case_sources.append((path, case))

    for path, case in case_sources:
        case_id = case.get("id")
        if not isinstance(case_id, str) or case_id in definitions:
            errors.append(f"invalid or duplicate acceptance case id in {path.name}: {case_id!r}")
            continue
        definitions[case_id] = case
        if case_id not in design.cases:
            errors.append(f"acceptance definition is absent from design section 19: {case_id}")
        state = case.get("status")
        if state not in CASE_STATES:
            errors.append(f"acceptance case {case_id} has invalid status: {state!r}")
            continue
        counts[state] += 1

        scope = case.get("scope")
        if scope not in {"PRODUCT", "REFERENCE_MODEL"}:
            errors.append(f"acceptance case {case_id} has invalid scope: {scope!r}")
        blocker = case.get("blocker")
        if not isinstance(blocker, str) or not blocker.strip():
            errors.append(f"acceptance case {case_id} must declare a non-empty blocker")
        target_milestone = case.get("targetMilestone")
        if not isinstance(target_milestone, str) or not re.fullmatch(
            r"G[0-6]", target_milestone
        ):
            errors.append(
                f"acceptance case {case_id} must declare targetMilestone G0 through G6"
            )

        risk_ids = case.get("riskIds")
        if not isinstance(risk_ids, list) or not risk_ids:
            errors.append(f"acceptance case {case_id} must reference at least one risk ID")
        else:
            if any(not isinstance(risk_id, str) for risk_id in risk_ids):
                errors.append(f"acceptance case {case_id} riskIds must be strings")
                risk_ids = []
            elif len(risk_ids) != len(set(risk_ids)):
                errors.append(f"acceptance case {case_id} riskIds must be unique")
            unknown = sorted(set(risk_ids) - known_risks)
            if unknown:
                errors.append(f"acceptance case {case_id} references unknown risks: {unknown}")

        if state in {"EXECUTABLE", "FEATURE_DISABLED"}:
            runner = case.get("runner")
            if not isinstance(runner, dict):
                errors.append(f"runnable case {case_id} must declare runner")
                continue
            cwd = runner.get("cwd")
            argv = runner.get("argv")
            if repository_directory(
                cwd, f"runnable case {case_id} runner cwd", errors
            ) is None:
                continue
            if (
                not isinstance(argv, list)
                or not argv
                or any(not isinstance(arg, str) or not arg for arg in argv)
            ):
                errors.append(f"runnable case {case_id} runner argv must be a non-empty string list")
                continue
            if state == "FEATURE_DISABLED" and not case.get("negativeGate"):
                errors.append(f"feature-disabled case {case_id} must describe its negativeGate")
                continue
            executable[case_id] = case
            if case.get("scope") != "PRODUCT" and state == "EXECUTABLE":
                reference_only.append(case_id)

    validate_acceptance_dependencies(
        definitions,
        set(design.cases),
        known_tech_story_ids,
        errors,
        blockers,
    )

    missing = [case_id for case_id in design.cases if case_id not in definitions]
    if missing:
        blockers.append(
            f"unclassified acceptance cases: {len(missing)}/{len(design.cases)}"
        )
    hardware_blocked = [
        case_id for case_id, case in definitions.items() if case.get("status") == "HARDWARE_BLOCKED"
    ]
    implementation_blocked = [
        case_id
        for case_id, case in definitions.items()
        if case.get("status") == "IMPLEMENTATION_BLOCKED"
    ]
    if implementation_blocked:
        blockers.append(
            "implementation-blocked acceptance cases: "
            + ", ".join(sorted(implementation_blocked))
        )
    if hardware_blocked:
        blockers.append("hardware-blocked acceptance cases: " + ", ".join(sorted(hardware_blocked)))
    if reference_only:
        blockers.append(
            "reference-only executable cases do not close product gates: "
            + ", ".join(sorted(reference_only))
        )
    return counts, missing, executable


def validate_ipd_tree(
    contract: dict[str, Any],
    project: dict[str, Any],
    errors: list[str],
) -> Counter[str]:
    """Validate that the human and machine IPD trees describe one stable hierarchy."""

    counts: Counter[str] = Counter()
    if contract.get("schemaVersion") != 2:
        errors.append("ipd-tree.json schemaVersion must be 2")
    if contract.get("state") not in IPD_STATES:
        errors.append(f"ipd-tree.json has invalid state: {contract.get('state')!r}")

    source_value = contract.get("sourceDocument")
    material_map_value = contract.get("materialMap")
    source_text = ""
    for label, value in (
        ("sourceDocument", source_value),
        ("materialMap", material_map_value),
    ):
        resolved = repository_file(value, f"ipd-tree.json {label}", errors)
        if label == "sourceDocument" and resolved is not None:
            source_text = resolved.read_text(encoding="utf-8")

    documents = project.get("authoritativeDocuments")
    if isinstance(documents, dict):
        if documents.get("productTree") != source_value:
            errors.append("project-status productTree must match ipd-tree sourceDocument")
        if documents.get("materialMap") != material_map_value:
            errors.append("project-status materialMap must match ipd-tree materialMap")

    epic = contract.get("epic")
    if not isinstance(epic, dict):
        errors.append("ipd-tree.json epic must be an object")
        epic = {}
    epic_id = epic.get("id")
    if not isinstance(epic_id, str) or not epic_id:
        errors.append("ipd-tree.json epic must have a non-empty id")
    else:
        counts["epics"] += 1
        if source_text and epic_id not in source_text:
            errors.append(f"IPD source document is missing epic ID: {epic_id}")

    features = contract.get("features")
    if not isinstance(features, list) or not features:
        errors.append("ipd-tree.json features must be a non-empty list")
        return counts

    feature_ids: list[str] = []
    all_user_ids: set[str] = set()
    all_tech_ids: set[str] = set()
    for feature in features:
        if not isinstance(feature, dict):
            errors.append("every IPD feature must be an object")
            continue
        feature_id = feature.get("id")
        if not isinstance(feature_id, str) or not FEATURE_ID_RE.fullmatch(feature_id):
            errors.append(f"invalid IPD feature ID: {feature_id!r}")
            continue
        if feature_id in feature_ids:
            errors.append(f"duplicate IPD feature ID: {feature_id}")
            continue
        feature_ids.append(feature_id)
        counts["features"] += 1
        if source_text and feature_id not in source_text:
            errors.append(f"IPD source document is missing feature ID: {feature_id}")
        if not feature.get("title") or not feature.get("outcome"):
            errors.append(f"IPD feature {feature_id} must declare title and outcome")

        stories = feature.get("userStories")
        if not isinstance(stories, list) or not stories:
            errors.append(f"IPD feature {feature_id} must contain userStories")
            stories = []
        feature_user_ids: set[str] = set()
        for story in stories:
            if not isinstance(story, dict):
                errors.append(f"every user story in {feature_id} must be an object")
                continue
            story_id = story.get("id")
            match = USER_STORY_ID_RE.fullmatch(story_id) if isinstance(story_id, str) else None
            if not match or match.group(1) != feature_id:
                errors.append(f"invalid user story ID under {feature_id}: {story_id!r}")
                continue
            if story_id in all_user_ids:
                errors.append(f"duplicate user story ID: {story_id}")
                continue
            if not story.get("title"):
                errors.append(f"user story {story_id} must declare title")
            all_user_ids.add(story_id)
            feature_user_ids.add(story_id)
            counts["user_stories"] += 1
            if source_text and story_id not in source_text:
                errors.append(f"IPD source document is missing user story ID: {story_id}")

        tech_stories = feature.get("techStories")
        if not isinstance(tech_stories, list) or not tech_stories:
            errors.append(f"IPD feature {feature_id} must contain techStories")
            tech_stories = []
        supported_user_ids: set[str] = set()
        for story in tech_stories:
            if not isinstance(story, dict):
                errors.append(f"every tech story in {feature_id} must be an object")
                continue
            story_id = story.get("id")
            match = TECH_STORY_ID_RE.fullmatch(story_id) if isinstance(story_id, str) else None
            if not match or match.group(1) != feature_id:
                errors.append(f"invalid tech story ID under {feature_id}: {story_id!r}")
                continue
            if story_id in all_tech_ids:
                errors.append(f"duplicate tech story ID: {story_id}")
                continue
            if not story.get("title"):
                errors.append(f"tech story {story_id} must declare title")
            all_tech_ids.add(story_id)
            counts["tech_stories"] += 1
            if source_text and story_id not in source_text:
                errors.append(f"IPD source document is missing tech story ID: {story_id}")

            primary = story.get("primaryUserStory")
            supports = story.get("supports")
            if not isinstance(supports, list) or not supports or any(
                not isinstance(item, str) for item in supports
            ):
                errors.append(f"tech story {story_id} supports must be a non-empty string list")
                supports = []
            unknown = sorted(set(supports) - feature_user_ids)
            if unknown:
                errors.append(f"tech story {story_id} supports unknown user stories: {unknown}")
            supported_user_ids.update(set(supports) & feature_user_ids)
            if primary not in feature_user_ids or primary not in supports:
                errors.append(
                    f"tech story {story_id} primaryUserStory must be local and included in supports"
                )

        uncovered_user_ids = sorted(feature_user_ids - supported_user_ids)
        if uncovered_user_ids:
            errors.append(
                f"IPD feature {feature_id} has user stories without tech support: "
                + ", ".join(uncovered_user_ids)
            )

        supplements = feature.get("supplements")
        if not isinstance(supplements, list) or not supplements:
            errors.append(f"IPD feature {feature_id} must contain supplements")
            supplements = []
        for supplement in supplements:
            if not isinstance(supplement, dict):
                errors.append(f"every supplement in {feature_id} must be an object")
                continue
            kind = supplement.get("kind")
            relative = supplement.get("path")
            if kind not in IPD_SUPPLEMENT_KINDS:
                errors.append(f"IPD feature {feature_id} has invalid supplement kind: {kind!r}")
            repository_file(
                relative, f"IPD feature {feature_id} supplement", errors
            )
            counts["supplements"] += 1

    declared_feature_ids = epic.get("featureIds")
    if declared_feature_ids != feature_ids:
        errors.append(
            "IPD epic featureIds must exactly match feature order: " + ", ".join(feature_ids)
        )

    release_slices = contract.get("releaseSlices")
    if not isinstance(release_slices, list) or not release_slices:
        errors.append("ipd-tree.json releaseSlices must be a non-empty list")
        release_slices = []
    release_ids: set[str] = set()
    release_features_by_id: dict[str, set[str]] = {}
    for release in release_slices:
        if not isinstance(release, dict):
            errors.append("every IPD release slice must be an object")
            continue
        release_id = release.get("id")
        if not isinstance(release_id, str) or not release_id or release_id in release_ids:
            errors.append(f"invalid or duplicate IPD release slice ID: {release_id!r}")
            continue
        release_ids.add(release_id)
        counts["release_slices"] += 1
        if release.get("status") not in IPD_RELEASE_STATES:
            errors.append(
                f"IPD release slice {release_id} has invalid status: {release.get('status')!r}"
            )
        slices = release.get("featureSlices")
        if not isinstance(slices, list) or not slices:
            errors.append(f"IPD release slice {release_id} must contain featureSlices")
            continue
        release_features_by_id[release_id] = {
            item.get("featureId") for item in slices if isinstance(item, dict)
        }
        for item in slices:
            if not isinstance(item, dict) or item.get("featureId") not in feature_ids:
                errors.append(f"IPD release slice {release_id} references an unknown feature")
            elif not item.get("scope"):
                errors.append(
                    f"IPD release slice {release_id}/{item.get('featureId')} must declare scope"
                )

    boundary = contract.get("productBoundary")
    if not isinstance(boundary, dict):
        errors.append("ipd-tree.json must declare productBoundary")
        boundary = {}
    target_release = boundary.get("targetRelease")
    if target_release not in release_ids:
        errors.append(f"IPD product targetRelease is not declared: {target_release!r}")
    elif release_features_by_id.get(target_release) != set(feature_ids):
        errors.append("IPD target release must include every feature exactly once")
    if project.get("targetRelease") != target_release:
        errors.append("project-status targetRelease must match IPD productBoundary")
    delivery_model = boundary.get("deliveryModel")
    if delivery_model != "SINGLE_TARGET_MULTI_WAVE":
        errors.append("IPD deliveryModel must be SINGLE_TARGET_MULTI_WAVE")
    if project.get("deliveryModel") != delivery_model:
        errors.append("project-status deliveryModel must match IPD productBoundary")
    for key, expected_value in IPD_PRODUCT_BOUNDARY.items():
        if boundary.get(key) != expected_value:
            errors.append(
                f"IPD productBoundary {key} must be {expected_value!r}"
            )
    unsupported = boundary.get("explicitlyUnsupportedOperations")
    if (
        string_set(unsupported) != IPD_UNSUPPORTED_OPERATIONS
        or not isinstance(unsupported, list)
        or len(unsupported) != len(IPD_UNSUPPORTED_OPERATIONS)
    ):
        errors.append(
            "IPD explicitlyUnsupportedOperations must exactly match the frozen unsupported set"
        )

    dimensions = contract.get("capabilityDimensions")
    if not isinstance(dimensions, dict):
        errors.append("ipd-tree.json must declare capabilityDimensions")
    else:
        if set(dimensions) != set(IPD_CAPABILITY_DIMENSIONS) | {"invariants"}:
            errors.append("IPD capabilityDimensions fields must match the frozen model")
        for dimension, expected_text in IPD_CAPABILITY_DIMENSIONS.items():
            if dimensions.get(dimension) != expected_text:
                errors.append(f"IPD capability dimension {dimension} has drifted")
        invariants = dimensions.get("invariants")
        if (
            string_set(invariants) != IPD_CAPABILITY_INVARIANTS
            or not isinstance(invariants, list)
            or len(invariants) != len(IPD_CAPABILITY_INVARIANTS)
        ):
            errors.append(
                "IPD capabilityDimensions invariants must exactly match the frozen implication set"
            )

    waves = contract.get("implementationWaves")
    if not isinstance(waves, list) or not waves:
        errors.append("ipd-tree.json implementationWaves must be a non-empty list")
        waves = []
    wave_ids: set[str] = set()
    project_milestones = {
        item.get("id")
        for item in project.get("milestones", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    seen_wave_milestones: set[str] = set()
    for wave in waves:
        if not isinstance(wave, dict):
            errors.append("every IPD implementation wave must be an object")
            continue
        wave_id = wave.get("id")
        if not isinstance(wave_id, str) or not wave_id or wave_id in wave_ids:
            errors.append(f"invalid or duplicate IPD implementation wave ID: {wave_id!r}")
            continue
        wave_ids.add(wave_id)
        counts["implementation_waves"] += 1
        milestone = wave.get("milestone")
        if milestone not in project_milestones or milestone in seen_wave_milestones:
            errors.append(f"IPD wave {wave_id} has invalid or duplicate milestone: {milestone!r}")
        elif isinstance(milestone, str):
            seen_wave_milestones.add(milestone)
        wave_features = wave.get("featureIds")
        if not isinstance(wave_features, list) or not wave_features:
            errors.append(f"IPD wave {wave_id} must contain featureIds")
        else:
            unknown_features = sorted(set(wave_features) - set(feature_ids))
            if unknown_features:
                errors.append(f"IPD wave {wave_id} references unknown features: {unknown_features}")
        if not wave.get("name") or not wave.get("outcome"):
            errors.append(f"IPD wave {wave_id} must declare name and outcome")
    if seen_wave_milestones != project_milestones:
        errors.append(
            "IPD implementation waves must cover every project milestone exactly once"
        )

    mappings = contract.get("crossCuttingMappings")
    if not isinstance(mappings, dict):
        errors.append("ipd-tree.json must declare crossCuttingMappings")
    else:
        path_keys = {
            "sourceDocument",
            "statusContract",
            "policyContract",
            "caseDirectory",
            "materialMap",
            "artifactDirectory",
            "behaviorContract",
            "sourceRegister",
            "resultSchema",
            "evidenceIndex",
        }
        for mapping_name, mapping in mappings.items():
            if not isinstance(mapping, dict):
                errors.append(f"IPD cross-cutting mapping {mapping_name} must be an object")
                continue
            for key, relative in mapping.items():
                if key in path_keys:
                    repository_entry(
                        relative,
                        f"IPD cross-cutting mapping {mapping_name}.{key}",
                        errors,
                    )

    return counts


def _repository_path(
    relative: Any,
    label: str,
    errors: list[str],
    kind: str,
) -> Path | None:
    """Resolve one repository-owned path without permitting aliases or escape."""

    if not isinstance(relative, str) or not relative:
        errors.append(f"{label} must be a non-empty repository-relative path")
        return None
    relative_path = Path(relative)
    if relative_path.is_absolute():
        errors.append(f"{label} must be repository-relative: {relative!r}")
        return None
    if ".." in relative_path.parts:
        errors.append(f"{label} must not contain path traversal: {relative!r}")
        return None
    root = ROOT.resolve()
    lexical_candidate = ROOT / relative_path
    if lexical_candidate.is_symlink():
        errors.append(f"{label} must not be a symbolic link: {relative!r}")
        return None
    candidate = lexical_candidate.resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        errors.append(f"{label} escapes the repository: {relative!r}")
        return None
    if kind == "file":
        exists = candidate.is_file()
    elif kind == "directory":
        exists = candidate.is_dir()
    else:
        exists = candidate.exists()
    if not exists:
        errors.append(f"{label} is not a repository {kind}: {relative!r}")
        return None
    return candidate


def repository_entry(
    relative: Any,
    label: str,
    errors: list[str],
) -> Path | None:
    """Resolve an existing repository-owned file or directory."""

    return _repository_path(relative, label, errors, "entry")


def repository_file(
    relative: Any,
    label: str,
    errors: list[str],
) -> Path | None:
    """Resolve one repository-owned file."""

    return _repository_path(relative, label, errors, "file")


def repository_directory(
    relative: Any,
    label: str,
    errors: list[str],
) -> Path | None:
    """Resolve one repository-owned directory."""

    return _repository_path(relative, label, errors, "directory")


def repository_discovered_file(
    path: Path,
    label: str,
    errors: list[str],
) -> Path | None:
    """Validate a file discovered inside a trusted directory without following links out."""

    if path.is_symlink():
        errors.append(f"{label} must not be a symbolic link: {path.name!r}")
        return None
    root = ROOT.resolve()
    candidate = path.resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        errors.append(f"{label} escapes the repository: {str(path)!r}")
        return None
    if not candidate.is_file():
        errors.append(f"{label} is not a repository file: {str(path)!r}")
        return None
    return candidate


def validate_qman_input_hashes(
    evidence_id: str,
    input_hashes: Any,
    errors: list[str],
) -> None:
    """Validate optional hashes for model, fixture and test inputs."""

    if input_hashes is None:
        return
    if not isinstance(input_hashes, dict) or not input_hashes:
        errors.append(
            f"Qman evidence {evidence_id} inputHashes must be non-empty when present"
        )
        return
    for input_relative, expected_input_hash in input_hashes.items():
        input_path = repository_file(
            input_relative,
            f"Qman evidence {evidence_id} inputHashes path",
            errors,
        )
        if not isinstance(expected_input_hash, str) or not HASH_RE.fullmatch(
            expected_input_hash
        ):
            errors.append(
                f"Qman evidence {evidence_id} has invalid input SHA-256: "
                f"{input_relative!r}"
            )
        elif input_path is not None:
            actual_input_hash = hashlib.sha256(input_path.read_bytes()).hexdigest()
            if actual_input_hash != expected_input_hash:
                errors.append(
                    f"Qman evidence {evidence_id} input hash drift: {input_relative}"
                )


def validate_qman_closure_effect(
    evidence_id: str,
    result: dict[str, Any],
    reference_subjects: set[str],
    e4_required_risks: set[str],
    errors: list[str],
) -> None:
    """Enforce evidence-grade boundaries independently from evidence presence."""

    mapping = result.get("mapping")
    if not isinstance(mapping, dict):
        errors.append(f"Qman evidence {evidence_id} mapping must be an object")
        mapping = {}
    mapped_cases = string_set(mapping.get("caseIds"))
    if mapped_cases is None:
        errors.append(f"Qman evidence {evidence_id} mapping.caseIds must be a string list")
        mapped_cases = set()
    mapped_risks = string_set(mapping.get("riskIds"))
    if mapped_risks is None:
        errors.append(f"Qman evidence {evidence_id} mapping.riskIds must be a string list")
        mapped_risks = set()

    closure = result.get("closureEffect")
    if not isinstance(closure, dict):
        errors.append(f"Qman evidence {evidence_id} closureEffect must be an object")
        return
    product_cases = closure.get("productCasesClosed")
    risks = closure.get("risksClosed")
    status_updated = closure.get("statusUpdated")
    if not isinstance(product_cases, list) or any(
        not isinstance(item, str) for item in product_cases
    ):
        errors.append(
            f"Qman evidence {evidence_id} productCasesClosed must be a string list"
        )
        product_cases = []
    elif len(product_cases) != len(set(product_cases)):
        errors.append(f"Qman evidence {evidence_id} duplicates product case closures")
    if not isinstance(risks, list) or any(not isinstance(item, str) for item in risks):
        errors.append(f"Qman evidence {evidence_id} risksClosed must be a string list")
        risks = []
    elif len(risks) != len(set(risks)):
        errors.append(f"Qman evidence {evidence_id} duplicates risk closures")
    if not isinstance(status_updated, bool):
        errors.append(f"Qman evidence {evidence_id} statusUpdated must be boolean")
        status_updated = False

    unknown_cases = sorted(set(product_cases) - mapped_cases)
    unknown_risks = sorted(set(risks) - mapped_risks)
    if unknown_cases:
        errors.append(
            f"Qman evidence {evidence_id} closes unmapped product cases: {unknown_cases}"
        )
    if unknown_risks:
        errors.append(f"Qman evidence {evidence_id} closes unmapped risks: {unknown_risks}")

    subject = result.get("subject")
    grade = result.get("evidenceGrade")
    claim_boundary = result.get("claimBoundary")
    if not isinstance(subject, str):
        errors.append(f"Qman evidence {evidence_id} subject must be a string")
        subject = None
    if not isinstance(grade, str):
        errors.append(f"Qman evidence {evidence_id} evidenceGrade must be a string")
        grade = None
    if not isinstance(claim_boundary, str):
        errors.append(f"Qman evidence {evidence_id} claimBoundary must be a string")
        claim_boundary = None
    attempts_closure = bool(product_cases or risks or status_updated)
    if subject in reference_subjects:
        if claim_boundary != "REFERENCE_ONLY":
            errors.append(
                f"Qman evidence {evidence_id} reference subject must use REFERENCE_ONLY"
            )
        if attempts_closure:
            errors.append(
                f"Qman evidence {evidence_id} reference subject cannot close product cases/risks"
            )
    elif subject == "QMAN_COMPONENT":
        if claim_boundary != "COMPONENT_ONLY":
            errors.append(
                f"Qman evidence {evidence_id} component subject must use COMPONENT_ONLY"
            )
    elif subject == "QMAN_END_TO_END":
        expected_boundary = {
            "E3": "END_TO_END_PRODUCT",
            "E4": "PHYSICAL_QUALIFICATION",
        }.get(grade)
        if expected_boundary is None or claim_boundary != expected_boundary:
            errors.append(
                f"Qman evidence {evidence_id} end-to-end subject grade/boundary matrix is invalid"
            )
    if grade == "E4" and (
        subject != "QMAN_END_TO_END" or claim_boundary != "PHYSICAL_QUALIFICATION"
    ):
        errors.append(
            f"Qman evidence {evidence_id} E4 requires end-to-end physical qualification"
        )
    if claim_boundary == "PHYSICAL_QUALIFICATION" and grade != "E4":
        errors.append(
            f"Qman evidence {evidence_id} physical qualification boundary requires E4"
        )
    if grade == "E2" and attempts_closure:
        errors.append(
            f"Qman evidence {evidence_id} E2 cannot close product cases/risks"
        )
    if attempts_closure and subject != "QMAN_END_TO_END":
        errors.append(
            f"Qman evidence {evidence_id} non-end-to-end subject cannot close product state"
        )
    if attempts_closure and claim_boundary not in {
        "END_TO_END_PRODUCT",
        "PHYSICAL_QUALIFICATION",
    }:
        errors.append(
            f"Qman evidence {evidence_id} product state closure requires an end-to-end claim boundary"
        )
    if grade == "E3":
        forbidden = sorted(set(risks) & e4_required_risks)
        if forbidden:
            errors.append(
                f"Qman evidence {evidence_id} E3 cannot close E4-required risks: {forbidden}"
            )
        forbidden_cases = sorted(set(product_cases) & QMAN_HARDWARE_BLOCKED_CASES)
        if forbidden_cases:
            errors.append(
                f"Qman evidence {evidence_id} E3 cannot close hardware-blocked cases: "
                f"{forbidden_cases}"
            )
    physical_risk_closures = sorted(set(risks) & e4_required_risks)
    if physical_risk_closures and (
        grade != "E4" or claim_boundary != "PHYSICAL_QUALIFICATION"
    ):
        errors.append(
            f"Qman evidence {evidence_id} E4-required risk closure requires E4 physical qualification: "
            f"{physical_risk_closures}"
        )
    if attempts_closure and result.get("verdict") != "PASS":
        errors.append(
            f"Qman evidence {evidence_id} cannot close product state without PASS verdict"
        )
    source_state = result.get("sourceState")
    if attempts_closure and (
        not isinstance(source_state, dict)
        or source_state.get("dirtyWorkingTree") is not False
    ):
        errors.append(
            f"Qman evidence {evidence_id} cannot close product state from a dirty source tree"
        )
    artifacts = result.get("artifacts")
    has_committed_artifact = isinstance(artifacts, list) and any(
        isinstance(artifact, dict) and artifact.get("retention") == "COMMITTED"
        for artifact in artifacts
    )
    if attempts_closure and not has_committed_artifact:
        errors.append(
            f"Qman evidence {evidence_id} closure requires a committed artifact"
        )
    if grade == "E4" and attempts_closure:
        errors.append(
            f"Qman evidence {evidence_id} E4 is review-only until an independent qualification approval contract exists"
        )


def validate_qman_evidence(
    index: dict[str, Any],
    result_schema: dict[str, Any],
    ipd_contract: dict[str, Any],
    design: DesignContracts,
    errors: list[str],
    risk_closure_receipts: dict[
        str, list[QmanRiskClosureReceipt]
    ] | None = None,
) -> Counter[str]:
    """Validate Qman evidence and emit only fully authenticated risk receipts."""

    qman_error_count = len(errors)
    candidate_risk_receipts: dict[str, list[QmanRiskClosureReceipt]] = {}
    if risk_closure_receipts is not None:
        risk_closure_receipts.clear()
    counts: Counter[str] = Counter()
    if set(index) != QMAN_EVIDENCE_INDEX_FIELDS:
        errors.append("qman-evidence-index root fields must match the closed schema exactly")
    if index.get("schemaVersion") != 1:
        errors.append("qman-evidence-index.json schemaVersion must be 1")

    source_document = repository_file(
        index.get("sourceDocument"),
        "Qman evidence sourceDocument",
        errors,
    )
    if source_document is not None and not source_document.read_text(
        encoding="utf-8"
    ).strip():
        errors.append("Qman evidence sourceDocument must not be empty")

    result_schema_path = index.get("resultSchema")
    if result_schema_path != "contracts/qman-technical-evidence.schema.json":
        errors.append(
            "qman-evidence-index resultSchema must be "
            "contracts/qman-technical-evidence.schema.json"
        )
    repository_file(result_schema_path, "Qman evidence resultSchema", errors)

    if result_schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append("Qman evidence result schema must use JSON Schema draft 2020-12")
    if result_schema.get("type") != "object" or result_schema.get(
        "additionalProperties"
    ) is not False:
        errors.append(
            "Qman evidence result schema must be a closed object schema"
        )
    schema_required = result_schema.get("required")
    if string_set(schema_required) != QMAN_RESULT_REQUIRED_FIELDS:
        errors.append("Qman evidence result schema required fields have drifted")
    schema_properties = result_schema.get("properties")
    if not isinstance(schema_properties, dict) or not QMAN_RESULT_REQUIRED_FIELDS.issubset(
        schema_properties
    ):
        errors.append("Qman evidence result schema properties are incomplete")
        schema_properties = {}

    schema_version_property = schema_properties.get("schemaVersion")
    if not isinstance(schema_version_property, dict) or schema_version_property != {
        "type": "integer",
        "const": 1,
    }:
        errors.append("Qman evidence schemaVersion schema must pin integer 1")
    sut_property = schema_properties.get("sut")
    sut_components = (
        sut_property.get("properties", {}).get("components")
        if isinstance(sut_property, dict)
        and isinstance(sut_property.get("properties"), dict)
        else None
    )
    component_item = (
        sut_components.get("items") if isinstance(sut_components, dict) else None
    )
    observations_property = schema_properties.get("observations")
    observation_item = (
        observations_property.get("items")
        if isinstance(observations_property, dict)
        else None
    )
    if not isinstance(sut_property, dict) or sut_property.get(
        "additionalProperties"
    ) is not False:
        errors.append("Qman evidence schema sut must be a closed object")
    if not isinstance(component_item, dict) or component_item.get(
        "additionalProperties"
    ) is not False:
        errors.append("Qman evidence schema component items must be closed objects")
    if not isinstance(observation_item, dict) or observation_item.get(
        "additionalProperties"
    ) is not False:
        errors.append("Qman evidence schema observation items must be closed objects")
    mapping_property = schema_properties.get("mapping")
    mapping_properties = (
        mapping_property.get("properties")
        if isinstance(mapping_property, dict)
        and isinstance(mapping_property.get("properties"), dict)
        else {}
    )
    case_items = (
        mapping_properties.get("caseIds", {}).get("items")
        if isinstance(mapping_properties.get("caseIds"), dict)
        else None
    )
    if not isinstance(case_items, dict) or case_items.get("pattern") != (
        "^[COSDMF][0-9]{2}[a-z]?$"
    ):
        errors.append("Qman evidence schema caseIds pattern has drifted")

    subject_property = schema_properties.get("subject", {})
    grade_property = schema_properties.get("evidenceGrade", {})
    boundary_property = schema_properties.get("claimBoundary", {})
    verdict_property = schema_properties.get("verdict", {})
    schema_subjects = (
        string_set(subject_property.get("enum"))
        if isinstance(subject_property, dict)
        else None
    ) or set()
    grade_values = (
        string_set(grade_property.get("enum"))
        if isinstance(grade_property, dict)
        else None
    )
    boundary_values = (
        string_set(boundary_property.get("enum"))
        if isinstance(boundary_property, dict)
        else None
    )
    verdict_values = (
        string_set(verdict_property.get("enum"))
        if isinstance(verdict_property, dict)
        else None
    )
    if grade_values != QMAN_EVIDENCE_GRADES:
        errors.append("Qman evidence result schema evidenceGrade enum has drifted")
    if boundary_values != QMAN_CLAIM_BOUNDARIES:
        errors.append("Qman evidence result schema claimBoundary enum has drifted")
    if verdict_values != QMAN_EVIDENCE_VERDICTS:
        errors.append("Qman evidence result schema verdict enum has drifted")

    grades = index.get("grades")
    if not isinstance(grades, dict) or set(grades) != QMAN_EVIDENCE_GRADES or any(
        not isinstance(value, str) or not value for value in grades.values()
    ):
        errors.append("qman-evidence-index grades must define E2, E3, and E4")

    closure_policy = index.get("closurePolicy")
    if not isinstance(closure_policy, dict):
        errors.append("qman-evidence-index closurePolicy must be an object")
        closure_policy = {}
    elif set(closure_policy) != QMAN_CLOSURE_POLICY_FIELDS:
        errors.append("Qman closurePolicy fields must match the closed schema exactly")
    reference_values = closure_policy.get("referenceSubjects")
    if not isinstance(reference_values, list) or not reference_values or any(
        not isinstance(item, str) for item in reference_values
    ):
        errors.append("Qman closurePolicy referenceSubjects must be a non-empty string list")
        reference_subjects: set[str] = set()
    else:
        reference_subjects = set(reference_values)
        if len(reference_subjects) != len(reference_values):
            errors.append("Qman closurePolicy referenceSubjects must be unique")
        unknown_subjects = sorted(reference_subjects - schema_subjects)
        if unknown_subjects:
            errors.append(
                f"Qman closurePolicy has subjects absent from result schema: {unknown_subjects}"
            )

    required_invariants = {
        "REFERENCE_SUBJECT_NEVER_CLOSES_PRODUCT_CASE",
        "COMPONENT_SUBJECT_NEVER_CLOSES_PRODUCT_STATE",
        "E2_NEVER_CLOSES_PRODUCT_CASE_OR_RISK",
        "E3_NEVER_CLOSES_E4_REQUIRED_HARDWARE_RISK",
        "E4_REVIEW_ONLY_UNTIL_SIGNED_QUALIFICATION_APPROVAL_CONTRACT",
        "SUPPORTED_REQUIRES_E4_PHYSICAL_QUALIFICATION_AND_PRODUCT_GATE",
        "EVIDENCE_HASH_DRIFT_INVALIDATES_RECORD",
    }
    invariants = closure_policy.get("invariants")
    if string_set(invariants) != required_invariants or len(invariants) != len(
        required_invariants
    ):
        errors.append("Qman closurePolicy invariants have drifted")

    e4_values = closure_policy.get("e4RequiredRisks")
    if (
        string_set(e4_values) != QMAN_E4_REQUIRED_RISKS
        or not isinstance(e4_values, list)
        or len(e4_values) != len(QMAN_E4_REQUIRED_RISKS)
    ):
        errors.append(
            "Qman closurePolicy e4RequiredRisks must exactly match the frozen physical-risk set"
        )
    e4_required_risks = set(QMAN_E4_REQUIRED_RISKS)
    missing_e4_risks = sorted(e4_required_risks - set(design.risks))
    if missing_e4_risks:
        errors.append(
            f"Qman design is missing frozen E4 risks: {missing_e4_risks}"
        )

    known_tech_stories: set[str] = set()
    ipd_features = ipd_contract.get("features")
    if not isinstance(ipd_features, list):
        errors.append("Qman evidence IPD features must be a list")
        ipd_features = []
    for feature in ipd_features:
        if not isinstance(feature, dict):
            continue
        tech_stories = feature.get("techStories")
        if not isinstance(tech_stories, list):
            errors.append("Qman evidence IPD techStories must be a list")
            continue
        known_tech_stories.update(
            story["id"]
            for story in tech_stories
            if isinstance(story, dict) and isinstance(story.get("id"), str)
        )
    known_cases = set(design.cases)
    known_risks = set(design.risks)
    records = index.get("records")
    if not isinstance(records, list) or not records:
        errors.append("qman-evidence-index records must be a non-empty list")
        return counts

    seen_ids: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            errors.append("every Qman evidence index record must be an object")
            continue
        evidence_id = record.get("id")
        if (
            not isinstance(evidence_id, str)
            or not QMAN_EVIDENCE_ID_RE.fullmatch(evidence_id)
            or evidence_id in seen_ids
        ):
            errors.append(f"invalid or duplicate Qman evidence ID: {evidence_id!r}")
            continue
        seen_ids.add(evidence_id)
        record_error_count = len(errors)
        record_counts: Counter[str] = Counter(records=1)
        if set(record) != QMAN_EVIDENCE_RECORD_FIELDS:
            errors.append(
                f"Qman evidence index {evidence_id} fields must match the closed schema exactly"
            )

        result_path = repository_file(
            record.get("resultPath"),
            f"Qman evidence {evidence_id} resultPath",
            errors,
        )
        result_payload = result_path.read_bytes() if result_path is not None else None
        expected_result_hash = record.get("resultSha256")
        actual_result_hash = (
            hashlib.sha256(result_payload).hexdigest()
            if result_payload is not None
            else None
        )
        if not isinstance(expected_result_hash, str) or not HASH_RE.fullmatch(
            expected_result_hash
        ):
            errors.append(f"Qman evidence {evidence_id} has invalid result SHA-256")
        elif actual_result_hash is not None:
            if actual_result_hash != expected_result_hash:
                errors.append(
                    f"Qman evidence {evidence_id} result hash drift: "
                    f"{record.get('resultPath')}"
                )
        if result_path is None:
            continue
        try:
            result = parse_json_bytes(
                result_payload,
                str(result_path.relative_to(ROOT)),
            )
        except ValueError as exc:
            errors.append(str(exc))
            continue

        validate_qman_result_shape(evidence_id, result, errors)
        missing_result_fields = sorted(QMAN_RESULT_REQUIRED_FIELDS - set(result))
        extra_result_fields = sorted(set(result) - set(schema_properties))
        if missing_result_fields:
            errors.append(
                f"Qman evidence {evidence_id} result missing fields: {missing_result_fields}"
            )
        if extra_result_fields:
            errors.append(
                f"Qman evidence {evidence_id} result has schema-forbidden fields: "
                f"{extra_result_fields}"
            )
        if result.get("schemaVersion") != 1:
            errors.append(f"Qman evidence {evidence_id} schemaVersion must be 1")
        if result.get("id") != evidence_id:
            errors.append(f"Qman evidence {evidence_id} result id does not match index")
        subject = result.get("subject")
        grade = result.get("evidenceGrade")
        verdict = result.get("verdict")
        if not isinstance(subject, str) or subject not in schema_subjects:
            errors.append(f"Qman evidence {evidence_id} has invalid subject: {subject!r}")
            subject = None
        if not isinstance(grade, str) or grade not in QMAN_EVIDENCE_GRADES:
            errors.append(f"Qman evidence {evidence_id} has invalid grade: {grade!r}")
            grade = None
        else:
            record_counts[grade] += 1
        if not isinstance(verdict, str) or verdict not in QMAN_EVIDENCE_VERDICTS:
            errors.append(f"Qman evidence {evidence_id} has invalid verdict: {verdict!r}")
            verdict = None
        else:
            record_counts[verdict] += 1
        claim_boundary = result.get("claimBoundary")
        if (
            not isinstance(claim_boundary, str)
            or claim_boundary not in QMAN_CLAIM_BOUNDARIES
        ):
            errors.append(
                f"Qman evidence {evidence_id} has invalid claimBoundary: "
                f"{claim_boundary!r}"
            )
            claim_boundary = None
        else:
            record_counts[f"boundary:{claim_boundary}"] += 1

        for field in ("subject", "evidenceGrade", "verdict"):
            if result.get(field) != record.get(field):
                errors.append(
                    f"Qman evidence {evidence_id} {field} differs between index and result"
                )

        mapping = result.get("mapping")
        if not isinstance(mapping, dict):
            errors.append(f"Qman evidence {evidence_id} mapping must be an object")
            mapping = {}
        for index_key, result_key, known in (
            ("techStories", "techStories", known_tech_stories),
            ("caseIds", "caseIds", known_cases),
            ("riskIds", "riskIds", known_risks),
        ):
            index_values = record.get(index_key)
            result_values = mapping.get(result_key)
            if not isinstance(index_values, list) or any(
                not isinstance(item, str) for item in index_values
            ):
                errors.append(
                    f"Qman evidence {evidence_id} index {index_key} must be a string list"
                )
                index_values = []
            elif len(index_values) != len(set(index_values)):
                errors.append(
                    f"Qman evidence {evidence_id} index {index_key} must be unique"
                )
            if not isinstance(result_values, list) or any(
                not isinstance(item, str) for item in result_values
            ):
                errors.append(
                    f"Qman evidence {evidence_id} result {result_key} must be a string list"
                )
                result_values = []
            elif len(result_values) != len(set(result_values)):
                errors.append(
                    f"Qman evidence {evidence_id} result {result_key} must be unique"
                )
            if index_values != result_values:
                errors.append(
                    f"Qman evidence {evidence_id} {index_key} differs between index and result"
                )
            unknown = sorted(set(result_values) - known)
            if unknown:
                errors.append(
                    f"Qman evidence {evidence_id} references unknown {result_key}: {unknown}"
                )
        if not mapping.get("techStories"):
            errors.append(f"Qman evidence {evidence_id} must reference tech stories")
        if not mapping.get("riskIds"):
            errors.append(f"Qman evidence {evidence_id} must reference risks")

        source_state = result.get("sourceState")
        if not isinstance(source_state, dict):
            errors.append(f"Qman evidence {evidence_id} sourceState must be an object")
            source_state = {}
        base_commit = source_state.get("baseCommit")
        if not isinstance(base_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", base_commit):
            errors.append(f"Qman evidence {evidence_id} has invalid baseCommit")
        if not isinstance(source_state.get("dirtyWorkingTree"), bool):
            errors.append(f"Qman evidence {evidence_id} dirtyWorkingTree must be boolean")
        runner_hashes = source_state.get("runnerHashes")
        if not isinstance(runner_hashes, dict) or not runner_hashes:
            errors.append(f"Qman evidence {evidence_id} runnerHashes must be non-empty")
        else:
            for runner_relative, expected_runner_hash in runner_hashes.items():
                runner_path = repository_file(
                    runner_relative,
                    f"Qman evidence {evidence_id} runnerHashes path",
                    errors,
                )
                if not isinstance(expected_runner_hash, str) or not HASH_RE.fullmatch(
                    expected_runner_hash
                ):
                    errors.append(
                        f"Qman evidence {evidence_id} has invalid runner SHA-256: "
                        f"{runner_relative!r}"
                    )
                elif runner_path is not None:
                    actual_runner_hash = hashlib.sha256(runner_path.read_bytes()).hexdigest()
                    if actual_runner_hash != expected_runner_hash:
                        errors.append(
                            f"Qman evidence {evidence_id} runner hash drift: "
                            f"{runner_relative}"
                        )

        validate_qman_input_hashes(
            evidence_id,
            source_state.get("inputHashes"),
            errors,
        )

        artifacts = result.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            errors.append(f"Qman evidence {evidence_id} artifacts must be non-empty")
        else:
            for artifact in artifacts:
                if not isinstance(artifact, dict):
                    errors.append(
                        f"Qman evidence {evidence_id} artifact must be an object"
                    )
                    continue
                artifact_path = artifact.get("path")
                artifact_hash = artifact.get("sha256")
                retention = artifact.get("retention")
                if not isinstance(artifact_hash, str) or not HASH_RE.fullmatch(artifact_hash):
                    errors.append(
                        f"Qman evidence {evidence_id} artifact has invalid SHA-256"
                    )
                if not isinstance(retention, str) or retention not in {
                    "COMMITTED",
                    "LOCAL_RAW",
                }:
                    errors.append(
                        f"Qman evidence {evidence_id} artifact has invalid retention: "
                        f"{retention!r}"
                    )
                if retention == "COMMITTED":
                    committed_path = repository_file(
                        artifact_path,
                        f"Qman evidence {evidence_id} committed artifact",
                        errors,
                    )
                    if (
                        committed_path is not None
                        and isinstance(artifact_hash, str)
                        and HASH_RE.fullmatch(artifact_hash)
                        and hashlib.sha256(committed_path.read_bytes()).hexdigest()
                        != artifact_hash
                    ):
                        errors.append(
                            f"Qman evidence {evidence_id} committed artifact hash drift: "
                            f"{artifact_path}"
                        )
                elif not isinstance(artifact_path, str) or not artifact_path:
                    errors.append(
                        f"Qman evidence {evidence_id} local artifact path must be non-empty"
                    )

        validate_qman_closure_effect(
            evidence_id,
            result,
            reference_subjects,
            e4_required_risks,
            errors,
        )
        closure = result.get("closureEffect")
        if isinstance(closure, dict):
            cases_closed = closure.get("productCasesClosed")
            risks_closed = closure.get("risksClosed")
            if isinstance(cases_closed, list):
                record_counts["product_case_closures"] += len(cases_closed)
            if isinstance(risks_closed, list):
                record_counts["risk_closures"] += len(risks_closed)
            if closure.get("statusUpdated") is True:
                record_counts["status_updates"] += 1
        if subject in reference_subjects:
            record_counts["reference"] += 1
        elif subject == "QMAN_COMPONENT":
            record_counts["component"] += 1
        elif subject == "QMAN_END_TO_END":
            record_counts["end_to_end"] += 1
        if len(errors) == record_error_count:
            counts.update(record_counts)
            if (
                actual_result_hash is not None
                and isinstance(grade, str)
                and isinstance(closure, dict)
            ):
                closed_risks = closure.get("risksClosed")
                if isinstance(closed_risks, list):
                    for risk_id in closed_risks:
                        if isinstance(risk_id, str):
                            candidate_risk_receipts.setdefault(risk_id, []).append(
                                QmanRiskClosureReceipt(
                                    evidence_id=evidence_id,
                                    result_sha256=actual_result_hash,
                                    evidence_grade=grade,
                                )
                            )

    if risk_closure_receipts is not None and len(errors) == qman_error_count:
        risk_closure_receipts.update(candidate_risk_receipts)
    return counts


def validate_project_qman_evidence_observation(
    project: dict[str, Any],
    counts: Counter[str],
    errors: list[str],
) -> None:
    """Prevent the human-facing project snapshot from drifting from the evidence index."""

    observations = project.get("observations")
    if not isinstance(observations, dict):
        errors.append("project-status observations must be an object")
        return
    observed = observations.get("qmanTechnicalEvidence")
    if not isinstance(observed, dict):
        errors.append("project-status must summarize qmanTechnicalEvidence")
        return

    expected_grades = {grade: counts[grade] for grade in sorted(QMAN_EVIDENCE_GRADES)}
    expected_boundaries = {
        boundary: counts[f"boundary:{boundary}"]
        for boundary in sorted(QMAN_CLAIM_BOUNDARIES)
    }
    expected = {
        "records": counts["records"],
        "grades": expected_grades,
        "claimBoundaries": expected_boundaries,
        "productCasesClosed": counts["product_case_closures"],
        "risksClosed": counts["risk_closures"],
        "statusUpdated": counts["status_updates"] > 0,
    }
    for field, expected_value in expected.items():
        if observed.get(field) != expected_value:
            errors.append(
                "project-status qmanTechnicalEvidence "
                f"{field} drift: expected {expected_value!r}, "
                f"observed {observed.get(field)!r}"
            )


def validate_vmware_reference(
    model: dict[str, Any],
    source_register: dict[str, Any],
    result_schema: dict[str, Any],
    ipd_contract: dict[str, Any],
    project: dict[str, Any],
    errors: list[str],
) -> Counter[str]:
    """Validate VMware official sources, experiment namespace, and TS coverage."""

    counts: Counter[str] = Counter()
    documents = project.get("authoritativeDocuments")

    if source_register.get("schemaVersion") != 1:
        errors.append("vmware-source-register.json schemaVersion must be 1")
    if source_register.get("subject") != "VMWARE_ESXI":
        errors.append("vmware-source-register.json subject must be VMWARE_ESXI")

    sources = source_register.get("sources")
    if not isinstance(sources, list) or not sources:
        errors.append("vmware-source-register.json sources must be a non-empty list")
        sources = []
    sources_by_id: dict[str, dict[str, Any]] = {}
    for source in sources:
        if not isinstance(source, dict):
            errors.append("every VMware source must be an object")
            continue
        source_id = source.get("id")
        if (
            not isinstance(source_id, str)
            or not VMWARE_SOURCE_ID_RE.fullmatch(source_id)
            or source_id in sources_by_id
        ):
            errors.append(f"invalid or duplicate VMware source ID: {source_id!r}")
            continue
        sources_by_id[source_id] = source
        counts["sources"] += 1
        url = source.get("url")
        parsed = urlparse(url) if isinstance(url, str) else None
        if (
            parsed is None
            or parsed.scheme != "https"
            or parsed.hostname not in VMWARE_OFFICIAL_HOSTS
        ):
            errors.append(f"VMware source {source_id} must use an approved official HTTPS host")
        claims = source.get("claims")
        if not isinstance(claims, list) or not claims or any(
            not isinstance(item, str) or not item for item in claims
        ):
            errors.append(f"VMware source {source_id} must declare non-empty claims")
        if not isinstance(source.get("limitations"), str) or not source.get("limitations"):
            errors.append(f"VMware source {source_id} must declare limitations")

    if model.get("schemaVersion") != 1:
        errors.append("vmware-behavior-model.json schemaVersion must be 1")
    if model.get("subject") != "VMWARE_ESXI":
        errors.append("vmware-behavior-model.json subject must be VMWARE_ESXI")
    source_document = model.get("sourceDocument")
    source_register_path = model.get("sourceRegister")
    result_schema_path = model.get("resultSchema")
    source_text = ""
    source_file = repository_file(
        source_document, "VMware behavior sourceDocument", errors
    )
    if source_file is not None:
        source_text = source_file.read_text(encoding="utf-8")
    repository_file(
        source_register_path, "VMware behavior sourceRegister", errors
    )
    repository_file(result_schema_path, "VMware behavior resultSchema", errors)

    if isinstance(documents, dict):
        if documents.get("vmwareBehaviorModel") != source_document:
            errors.append("project-status vmwareBehaviorModel must match VMware sourceDocument")
        if documents.get("vmwareBehaviorContract") != "contracts/vmware-behavior-model.json":
            errors.append("project-status must register vmware-behavior-model.json")
        if documents.get("vmwareSourceRegister") != source_register_path:
            errors.append("project-status vmwareSourceRegister must match VMware sourceRegister")
        if documents.get("vmwareResultSchema") != result_schema_path:
            errors.append("project-status vmwareResultSchema must match VMware resultSchema")

    required_result_fields = {
        "schemaVersion",
        "caseId",
        "legacyIds",
        "subject",
        "runId",
        "startedAt",
        "sutProfile",
        "techStories",
        "basisKinds",
        "sourceIds",
        "inputs",
        "expected",
        "observed",
        "verdict",
        "artifacts",
        "limitations",
    }
    if result_schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append("VMware result schema must use JSON Schema draft 2020-12")
    if result_schema.get("type") != "object":
        errors.append("VMware result schema root type must be object")
    schema_required = result_schema.get("required")
    if string_set(schema_required) != required_result_fields:
        errors.append("VMware result schema required fields have drifted")
    schema_properties = result_schema.get("properties")
    if not isinstance(schema_properties, dict) or not required_result_fields.issubset(
        schema_properties
    ):
        errors.append("VMware result schema properties are incomplete")

    if string_set(model.get("coverageStatuses")) != VMWARE_COVERAGE_STATES:
        errors.append(
            "vmware-behavior-model coverageStatuses must be "
            + ", ".join(sorted(VMWARE_COVERAGE_STATES))
        )
    if string_set(model.get("truthKinds")) != VMWARE_TRUTH_KINDS:
        errors.append(
            "vmware-behavior-model truthKinds must be "
            + ", ".join(sorted(VMWARE_TRUTH_KINDS))
        )

    baseline = model.get("referenceBaseline")
    registered_baseline = source_register.get("referenceBaseline")
    if not isinstance(baseline, dict) or not isinstance(registered_baseline, dict):
        errors.append("VMware contracts must declare referenceBaseline objects")
    else:
        pairs = {
            "build": "build",
            "apiVersion": "apiVersion",
            "virtualHardware": "virtualHardware",
        }
        for model_key, register_key in pairs.items():
            if baseline.get(model_key) != registered_baseline.get(register_key):
                errors.append(f"VMware reference baseline mismatch for {model_key}")

    experiments = model.get("experiments")
    if not isinstance(experiments, list) or not experiments:
        errors.append("vmware-behavior-model experiments must be a non-empty list")
        experiments = []
    experiments_by_id: dict[str, dict[str, Any]] = {}
    for experiment in experiments:
        if not isinstance(experiment, dict):
            errors.append("every VMware experiment must be an object")
            continue
        experiment_id = experiment.get("id")
        if (
            not isinstance(experiment_id, str)
            or not VMWARE_EXPERIMENT_ID_RE.fullmatch(experiment_id)
            or experiment_id in experiments_by_id
        ):
            errors.append(f"invalid or duplicate VMware experiment ID: {experiment_id!r}")
            continue
        experiments_by_id[experiment_id] = experiment
        counts["experiments"] += 1
        execution_state = experiment.get("executionState")
        if (
            not isinstance(execution_state, str)
            or execution_state not in VMWARE_EXECUTION_STATES
        ):
            errors.append(
                f"VMware experiment {experiment_id} has invalid executionState: "
                f"{execution_state!r}"
            )
        if not experiment.get("title"):
            errors.append(f"VMware experiment {experiment_id} must declare title")
        legacy_ids = experiment.get("legacyIds")
        if not isinstance(legacy_ids, list) or any(
            not isinstance(item, str) for item in legacy_ids
        ):
            errors.append(f"VMware experiment {experiment_id} legacyIds must be strings")
        evidence_paths = experiment.get("evidencePaths")
        runner_paths = experiment.get("runnerPaths")
        normalized_evidence_paths: list[str] = []
        resolved_evidence_paths: dict[str, Path] = {}
        for key, paths in (("evidencePaths", evidence_paths), ("runnerPaths", runner_paths)):
            if not isinstance(paths, list) or any(not isinstance(item, str) for item in paths):
                errors.append(f"VMware experiment {experiment_id} {key} must be strings")
                continue
            if len(paths) != len(set(paths)):
                errors.append(f"VMware experiment {experiment_id} {key} must be unique")
            for relative in paths:
                resolved = repository_file(
                    relative,
                    f"VMware experiment {experiment_id} {key} path",
                    errors,
                )
                if key == "evidencePaths" and resolved is not None:
                    resolved_evidence_paths[relative] = resolved
            if key == "evidencePaths":
                normalized_evidence_paths = paths
        if execution_state == "OBSERVED" and not normalized_evidence_paths:
            errors.append(f"observed VMware experiment {experiment_id} must reference evidence")
        evidence_hashes = experiment.get("evidenceSha256")
        if execution_state == "OBSERVED" or evidence_hashes is not None:
            if not isinstance(evidence_hashes, dict) or set(evidence_hashes) != set(
                normalized_evidence_paths
            ):
                errors.append(
                    f"VMware experiment {experiment_id} must hash every evidence path"
                )
            else:
                for relative, expected_hash in evidence_hashes.items():
                    if not isinstance(expected_hash, str) or not HASH_RE.fullmatch(expected_hash):
                        errors.append(
                            f"VMware experiment {experiment_id} has an invalid evidence SHA-256"
                        )
                        continue
                    path = resolved_evidence_paths.get(relative)
                    if path is not None:
                        actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
                        if actual_hash != expected_hash:
                            errors.append(
                                f"VMware experiment {experiment_id} evidence hash drift: {relative}"
                            )
        control_references = experiment.get("controlReferences", [])
        if not isinstance(control_references, list):
            errors.append(
                f"VMware experiment {experiment_id} controlReferences must be a list"
            )
            control_references = []
        control_ids: set[str] = set()
        control_paths: set[str] = set()
        for reference in control_references:
            if not isinstance(reference, dict):
                errors.append(
                    f"VMware experiment {experiment_id} control reference must be an object"
                )
                continue
            if set(reference) != VMWARE_CONTROL_REFERENCE_FIELDS:
                errors.append(
                    f"VMware experiment {experiment_id} control reference fields must "
                    "match the typed non-closing contract"
                )
            reference_id = reference.get("id")
            if (
                not isinstance(reference_id, str)
                or not reference_id
                or reference_id in control_ids
            ):
                errors.append(
                    f"VMware experiment {experiment_id} control reference ID is "
                    f"invalid or duplicate: {reference_id!r}"
                )
            else:
                control_ids.add(reference_id)
            subject = reference.get("subject")
            if (
                not isinstance(subject, str)
                or not subject
                or subject == model.get("subject")
            ):
                errors.append(
                    f"VMware experiment {experiment_id} control reference "
                    "must declare a non-VMware subject"
                )
            if reference.get("basisKind") != "EXECUTED_PUBLIC_MODEL_CONTROL":
                errors.append(
                    f"VMware experiment {experiment_id} control reference basisKind "
                    "must be EXECUTED_PUBLIC_MODEL_CONTROL"
                )
            control_path = reference.get("evidencePath")
            if (
                not isinstance(control_path, str)
                or not control_path
                or control_path in control_paths
            ):
                errors.append(
                    f"VMware experiment {experiment_id} control evidence path is "
                    f"invalid or duplicate: {control_path!r}"
                )
                control_file = None
            else:
                control_paths.add(control_path)
                if control_path in normalized_evidence_paths:
                    errors.append(
                        f"VMware experiment {experiment_id} control evidence must not "
                        "also be VMware evidence"
                    )
                control_file = repository_file(
                    control_path,
                    (
                        f"VMware experiment {experiment_id} control reference "
                        f"{reference_id!r} evidence path"
                    ),
                    errors,
                )
            control_hash = reference.get("sha256")
            if not isinstance(control_hash, str) or not HASH_RE.fullmatch(control_hash):
                errors.append(
                    f"VMware experiment {experiment_id} control reference SHA-256 "
                    "is invalid"
                )
            elif control_file is not None:
                actual_hash = hashlib.sha256(control_file.read_bytes()).hexdigest()
                if actual_hash != control_hash:
                    errors.append(
                        f"VMware experiment {experiment_id} control reference hash "
                        f"drift: {control_path}"
                    )
                try:
                    control_payload = load_json(control_file)
                except ValueError as error:
                    errors.append(str(error))
                else:
                    if control_payload.get("subject") != subject:
                        errors.append(
                            f"VMware experiment {experiment_id} control reference "
                            "subject does not match the referenced evidence"
                        )
            control_run_ids = reference.get("runIds")
            if (
                not isinstance(control_run_ids, list)
                or not control_run_ids
                or any(
                    not isinstance(item, str) or not item
                    for item in control_run_ids
                )
                or len(control_run_ids) != len(set(control_run_ids))
            ):
                errors.append(
                    f"VMware experiment {experiment_id} control reference runIds "
                    "must be non-empty unique strings"
                )
            public_sources = reference.get("publicSources")
            if not isinstance(public_sources, list) or not public_sources:
                errors.append(
                    f"VMware experiment {experiment_id} control reference must bind "
                    "publicSources"
                )
                public_sources = []
            source_urls: set[str] = set()
            for source in public_sources:
                if (
                    not isinstance(source, dict)
                    or set(source) != VMWARE_CONTROL_PUBLIC_SOURCE_FIELDS
                    or not isinstance(source.get("title"), str)
                    or not source.get("title")
                    or not isinstance(source.get("url"), str)
                    or not re.fullmatch(r"https://\S+", source.get("url", ""))
                ):
                    errors.append(
                        f"VMware experiment {experiment_id} control public source "
                        "must contain only a title and HTTPS URL"
                    )
                    continue
                if source["url"] in source_urls:
                    errors.append(
                        f"VMware experiment {experiment_id} control public source URLs "
                        "must be unique"
                    )
                source_urls.add(source["url"])
            if not isinstance(reference.get("proves"), str) or not reference.get(
                "proves"
            ):
                errors.append(
                    f"VMware experiment {experiment_id} control reference must state "
                    "what it proves"
                )
            does_not_prove = reference.get("doesNotProve")
            if (
                not isinstance(does_not_prove, list)
                or not does_not_prove
                or any(not isinstance(item, str) or not item for item in does_not_prove)
            ):
                errors.append(
                    f"VMware experiment {experiment_id} control reference must state "
                    "non-empty doesNotProve boundaries"
                )
            if reference.get("closureAuthority") != "NONE":
                errors.append(
                    f"VMware experiment {experiment_id} control reference "
                    "closureAuthority must remain NONE"
                )
        limitations = experiment.get("limitations")
        if not isinstance(limitations, list) or not limitations or any(
            not isinstance(item, str) for item in limitations
        ):
            errors.append(f"VMware experiment {experiment_id} must declare limitations")

    ipd_features = ipd_contract.get("features")
    if not isinstance(ipd_features, list):
        ipd_features = []
    ipd_tech_ids = {
        story.get("id")
        for feature in ipd_features
        if isinstance(feature, dict)
        for story in feature.get("techStories", [])
        if isinstance(story, dict) and isinstance(story.get("id"), str)
    }
    coverage = model.get("techStoryCoverage")
    if not isinstance(coverage, list):
        errors.append("vmware-behavior-model techStoryCoverage must be a list")
        coverage = []
    covered_ids: set[str] = set()
    for record in coverage:
        if not isinstance(record, dict):
            errors.append("every VMware tech-story coverage record must be an object")
            continue
        tech_story_id = record.get("techStoryId")
        if not isinstance(tech_story_id, str) or tech_story_id in covered_ids:
            errors.append(f"invalid or duplicate VMware techStoryId: {tech_story_id!r}")
            continue
        covered_ids.add(tech_story_id)
        counts["tech_stories"] += 1
        if source_text and tech_story_id not in source_text:
            errors.append(f"VMware human model is missing tech story ID: {tech_story_id}")
        status = record.get("status")
        if not isinstance(status, str) or status not in VMWARE_COVERAGE_STATES:
            errors.append(
                f"VMware coverage {tech_story_id} has invalid status: {status!r}"
            )
        else:
            counts[status] += 1
        source_ids = record.get("sourceIds")
        experiment_ids = record.get("experimentIds")
        if not isinstance(source_ids, list) or any(not isinstance(item, str) for item in source_ids):
            errors.append(f"VMware coverage {tech_story_id} sourceIds must be strings")
            source_ids = []
        if not isinstance(experiment_ids, list) or any(
            not isinstance(item, str) for item in experiment_ids
        ):
            errors.append(f"VMware coverage {tech_story_id} experimentIds must be strings")
            experiment_ids = []
        unknown_sources = sorted(set(source_ids) - set(sources_by_id))
        unknown_experiments = sorted(set(experiment_ids) - set(experiments_by_id))
        if unknown_sources:
            errors.append(
                f"VMware coverage {tech_story_id} references unknown sources: {unknown_sources}"
            )
        if unknown_experiments:
            errors.append(
                f"VMware coverage {tech_story_id} references unknown experiments: "
                f"{unknown_experiments}"
            )
        if status == "VERIFIED" and not any(
            experiments_by_id.get(item, {}).get("executionState") == "OBSERVED"
            for item in experiment_ids
        ):
            errors.append(
                f"verified VMware coverage {tech_story_id} needs an observed experiment"
            )
        if status == "NOT_APPLICABLE" and experiment_ids:
            errors.append(
                f"not-applicable VMware coverage {tech_story_id} must not reference experiments"
            )
        if not isinstance(record.get("observableContract"), str) or not record.get(
            "observableContract"
        ):
            errors.append(f"VMware coverage {tech_story_id} must declare observableContract")

    missing_coverage = sorted(ipd_tech_ids - covered_ids)
    extra_coverage = sorted(covered_ids - ipd_tech_ids)
    if missing_coverage:
        errors.append("VMware behavior model is missing tech stories: " + ", ".join(missing_coverage))
    if extra_coverage:
        errors.append("VMware behavior model has unknown tech stories: " + ", ".join(extra_coverage))

    return counts


def _acceptance_definitions_for_vmware_trace(
    policy: dict[str, Any], errors: list[str]
) -> dict[str, dict[str, Any]]:
    """Load the explicit acceptance records used for derived reference links.

    This helper deliberately does not decide acceptance readiness.  It only exposes
    the already-governed ``requiredTechStories`` join key so the VMware index can
    record a non-closing reference association without duplicating product state.
    """

    directory_value = policy.get("caseDefinitionDirectory")
    if not isinstance(directory_value, str):
        errors.append(
            "VMware evidence trace needs acceptance-policy caseDefinitionDirectory"
        )
        return {}
    directory = repository_directory(
        directory_value,
        "VMware evidence trace acceptance directory",
        errors,
    )
    if directory is None:
        return {}

    definitions: dict[str, dict[str, Any]] = {}
    for path in sorted(directory.glob("*.json")):
        resolved_path = repository_discovered_file(
            path,
            f"VMware evidence trace acceptance definition {path.name}",
            errors,
        )
        if resolved_path is None:
            continue
        try:
            payload = load_json(resolved_path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        records = payload.get("records") if isinstance(payload, dict) else None
        candidates = records if records is not None else [payload]
        if not isinstance(candidates, list):
            errors.append(
                f"VMware evidence trace cannot read acceptance registry {path.name}"
            )
            continue
        for case in candidates:
            case_id = case.get("id") if isinstance(case, dict) else None
            if not isinstance(case_id, str) or case_id in definitions:
                errors.append(
                    "VMware evidence trace found invalid or duplicate acceptance case "
                    f"in {path.name}: {case_id!r}"
                )
                continue
            definitions[case_id] = case
    return definitions


def validate_vmware_evidence_index(
    index: dict[str, Any],
    model: dict[str, Any],
    acceptance_policy: dict[str, Any],
    project: dict[str, Any],
    errors: list[str],
) -> Counter[str]:
    """Validate the non-closing VMware TS -> experiment -> run -> artifact index."""

    counts: Counter[str] = Counter()
    if set(index) != VMWARE_EVIDENCE_INDEX_FIELDS:
        errors.append(
            "vmware-evidence-index root fields must match the non-closing schema exactly"
        )
    if index.get("schemaVersion") != 1:
        errors.append("vmware-evidence-index.json schemaVersion must be 1")
    if index.get("subject") != "VMWARE_ESXI":
        errors.append("vmware-evidence-index.json subject must be VMWARE_ESXI")
    if index.get("sourceModel") != "contracts/vmware-behavior-model.json":
        errors.append(
            "vmware-evidence-index.json sourceModel must be contracts/vmware-behavior-model.json"
        )
    if index.get("hashAlgorithm") != "SHA-256":
        errors.append("vmware-evidence-index.json hashAlgorithm must be SHA-256")

    documents = project.get("authoritativeDocuments")
    if not isinstance(documents, dict) or documents.get("vmwareEvidenceIndex") != (
        "contracts/vmware-evidence-index.json"
    ):
        errors.append("project-status must register vmware-evidence-index.json")

    trace_policy = index.get("tracePolicy")
    expected_trace_policy = {
        "techStoryAssociation": "EXACT_FROM_VMWARE_BEHAVIOR_MODEL",
        "acceptanceCaseAssociation": (
            "DERIVED_FROM_ACCEPTANCE_REQUIRED_TECH_STORIES"
        ),
        "acceptanceClosureAuthority": "NONE",
        "qmanImplementationClosureAuthority": "NONE",
        "qmanQualificationClosureAuthority": "NONE",
        "noRunStates": sorted(VMWARE_NO_RUN_STATES),
    }
    if trace_policy != expected_trace_policy:
        errors.append(
            "vmware-evidence-index tracePolicy must preserve exact derived/non-closing semantics"
        )

    experiments = model.get("experiments")
    if not isinstance(experiments, list):
        experiments = []
    experiments_by_id = {
        item.get("id"): item
        for item in experiments
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    tech_story_ids_by_experiment: dict[str, set[str]] = {
        experiment_id: set() for experiment_id in experiments_by_id
    }
    coverage_records = model.get("techStoryCoverage")
    if not isinstance(coverage_records, list):
        errors.append("VMware evidence source techStoryCoverage must be a list")
        coverage_records = []
    for coverage in coverage_records:
        if not isinstance(coverage, dict):
            continue
        tech_story_id = coverage.get("techStoryId")
        if not isinstance(tech_story_id, str):
            continue
        coverage_experiment_ids = coverage.get("experimentIds")
        if not isinstance(coverage_experiment_ids, list) or any(
            not isinstance(item, str) for item in coverage_experiment_ids
        ):
            errors.append(
                f"VMware evidence source coverage {tech_story_id} experimentIds must be a list"
            )
            continue
        for experiment_id in coverage_experiment_ids:
            if experiment_id in tech_story_ids_by_experiment:
                tech_story_ids_by_experiment[experiment_id].add(tech_story_id)

    acceptance_definitions = _acceptance_definitions_for_vmware_trace(
        acceptance_policy, errors
    )
    acceptance_case_ids_by_tech_story: dict[str, set[str]] = {}
    for case_id, case in acceptance_definitions.items():
        required = case.get("requiredTechStories")
        if not isinstance(required, list):
            continue
        for tech_story_id in required:
            if isinstance(tech_story_id, str):
                acceptance_case_ids_by_tech_story.setdefault(
                    tech_story_id, set()
                ).add(case_id)

    records = index.get("records")
    if not isinstance(records, list):
        errors.append("vmware-evidence-index records must be a list")
        records = []
    if index.get("recordCount") != len(records):
        errors.append("vmware-evidence-index recordCount must equal records length")

    records_by_id: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            errors.append("every VMware evidence index record must be an object")
            continue
        if set(record) != VMWARE_EVIDENCE_RECORD_FIELDS:
            errors.append(
                "VMware evidence record fields must match the non-closing schema exactly"
            )
        experiment_id = record.get("experimentId")
        if (
            not isinstance(experiment_id, str)
            or experiment_id in records_by_id
            or experiment_id not in experiments_by_id
        ):
            errors.append(
                f"invalid, duplicate, or unknown VMware evidence experiment: {experiment_id!r}"
            )
            continue
        records_by_id[experiment_id] = record
        counts["records"] += 1

        experiment = experiments_by_id[experiment_id]
        execution_state = record.get("executionState")
        execution_state_valid = (
            isinstance(execution_state, str)
            and execution_state in VMWARE_EXECUTION_STATES
        )
        if not execution_state_valid:
            errors.append(
                f"VMware evidence {experiment_id} executionState must be a known string"
            )
        if execution_state != experiment.get("executionState"):
            errors.append(
                f"VMware evidence {experiment_id} executionState drift: {execution_state!r}"
            )
        if record.get("legacyCaseIds") != experiment.get("legacyIds"):
            errors.append(f"VMware evidence {experiment_id} legacyCaseIds drift")
        if record.get("limitations") != experiment.get("limitations"):
            errors.append(f"VMware evidence {experiment_id} limitations drift")

        expected_tech_stories = sorted(
            tech_story_ids_by_experiment.get(experiment_id, set())
        )
        if record.get("techStoryIds") != expected_tech_stories:
            errors.append(f"VMware evidence {experiment_id} techStoryIds drift")
        expected_acceptance_cases = sorted(
            {
                case_id
                for tech_story_id in expected_tech_stories
                for case_id in acceptance_case_ids_by_tech_story.get(
                    tech_story_id, set()
                )
            }
        )
        if record.get("derivedAcceptanceCaseIds") != expected_acceptance_cases:
            errors.append(
                f"VMware evidence {experiment_id} derivedAcceptanceCaseIds drift"
            )
        counts["derived_acceptance_links"] += len(expected_acceptance_cases)

        run_ids = record.get("runIds")
        evidence_records = record.get("evidence")
        no_run_reason = record.get("noRunReason")
        if not isinstance(run_ids, list) or any(
            not isinstance(item, str) or not item for item in run_ids
        ):
            errors.append(f"VMware evidence {experiment_id} runIds must be strings")
            run_ids = []
        if len(run_ids) != len(set(run_ids)):
            errors.append(f"VMware evidence {experiment_id} runIds must be unique")
        if not isinstance(evidence_records, list):
            errors.append(f"VMware evidence {experiment_id} evidence must be a list")
            evidence_records = []

        if execution_state_valid and execution_state in VMWARE_NO_RUN_STATES:
            counts["no_run"] += 1
            if run_ids or evidence_records:
                errors.append(
                    f"no-run VMware evidence {experiment_id} cannot bind runs or artifacts"
                )
            if not isinstance(no_run_reason, str) or not no_run_reason:
                errors.append(
                    f"no-run VMware evidence {experiment_id} must declare noRunReason"
                )
            if experiment.get("evidencePaths"):
                errors.append(
                    f"no-run VMware experiment {experiment_id} cannot declare evidencePaths"
                )
            continue

        counts["evidence_bound"] += 1
        if not run_ids:
            errors.append(f"executed VMware evidence {experiment_id} needs a runId")
        if no_run_reason is not None:
            errors.append(
                f"executed VMware evidence {experiment_id} must set noRunReason to null"
            )
        expected_paths = experiment.get("evidencePaths")
        expected_paths_valid = isinstance(expected_paths, list) and all(
            isinstance(item, str) for item in expected_paths
        )
        if not expected_paths_valid:
            errors.append(
                f"VMware evidence source {experiment_id} evidencePaths must be a string list"
            )
            expected_paths = []
        indexed_paths = [
            item.get("path") for item in evidence_records if isinstance(item, dict)
        ]
        indexed_paths_valid = all(isinstance(item, str) for item in indexed_paths)
        if (
            not indexed_paths_valid
            or sorted(indexed_paths) != sorted(expected_paths)
        ):
            errors.append(f"VMware evidence {experiment_id} evidence path drift")

        evidence_text = ""
        seen_paths: set[str] = set()
        resolved_evidence_paths: dict[str, Path] = {}
        for artifact in evidence_records:
            if not isinstance(artifact, dict):
                errors.append(
                    f"VMware evidence {experiment_id} artifact must be an object"
                )
                continue
            if set(artifact) != VMWARE_EVIDENCE_ARTIFACT_FIELDS:
                errors.append(
                    f"VMware evidence {experiment_id} artifact fields must be path and sha256 only"
                )
            path_value = artifact.get("path")
            expected_hash = artifact.get("sha256")
            if not isinstance(path_value, str) or path_value in seen_paths:
                errors.append(
                    f"VMware evidence {experiment_id} artifact path is invalid or duplicate"
                )
                continue
            seen_paths.add(path_value)
            if not isinstance(expected_hash, str) or not HASH_RE.fullmatch(expected_hash):
                errors.append(
                    f"VMware evidence {experiment_id} artifact SHA-256 is invalid: {path_value}"
                )
                continue
            path = repository_file(
                path_value,
                f"VMware evidence {experiment_id} artifact path",
                errors,
            )
            if path is None:
                continue
            resolved_evidence_paths[path_value] = path
            payload = path.read_bytes()
            actual_hash = hashlib.sha256(payload).hexdigest()
            if actual_hash != expected_hash:
                errors.append(
                    f"VMware evidence {experiment_id} artifact hash drift: {path_value}"
                )
            evidence_text += payload.decode("utf-8", errors="replace") + "\n"
            counts["artifacts"] += 1
        for run_id in run_ids:
            if run_id not in evidence_text:
                errors.append(
                    f"VMware evidence {experiment_id} runId is absent from indexed artifacts: {run_id}"
                )

        if experiment_id == "VMW-TRACE-001" and evidence_records:
            trace_artifact = evidence_records[0]
            trace_relative = (
                trace_artifact.get("path")
                if isinstance(trace_artifact, dict)
                else None
            )
            trace_path = resolved_evidence_paths.get(trace_relative)
            if trace_path is None:
                continue
            try:
                trace_summary = load_json(trace_path)
            except ValueError as exc:
                errors.append(str(exc))
                trace_summary = {}
            if set(trace_summary) != VMWARE_TRACE_SUMMARY_FIELDS:
                errors.append(
                    "VMW-TRACE-001 summary fields must match the non-closing schema exactly"
                )
            if trace_summary.get("schemaVersion") != 1:
                errors.append("VMW-TRACE-001 summary schemaVersion must be 1")
            if trace_summary.get("runId") not in run_ids:
                errors.append("VMW-TRACE-001 summary runId must match its evidence record")
            if trace_summary.get("subject") != "VMWARE_ESXI_REFERENCE_GOVERNANCE":
                errors.append("VMW-TRACE-001 summary subject has drifted")
            if trace_summary.get("verdict") != "PARTIAL":
                errors.append("VMW-TRACE-001 summary verdict must remain PARTIAL")
            if trace_summary.get("closureAuthority") != VMWARE_TRACE_CLOSURE_AUTHORITY:
                errors.append(
                    "VMW-TRACE-001 summary closureAuthority must remain NONE for every Qman gate"
                )
            governance_artifacts = trace_summary.get("artifacts")
            if not isinstance(governance_artifacts, list):
                errors.append("VMW-TRACE-001 summary artifacts must be a list")
                governance_artifacts = []
            governance_paths = {
                item.get("path")
                for item in governance_artifacts
                if isinstance(item, dict)
            }
            if governance_paths != VMWARE_TRACE_GOVERNANCE_ARTIFACTS:
                errors.append(
                    "VMW-TRACE-001 summary must hash exactly the non-circular "
                    "generator/evaluator/test governance artifacts"
                )
            for artifact in governance_artifacts:
                if not isinstance(artifact, dict):
                    errors.append("VMW-TRACE-001 governance artifact must be an object")
                    continue
                if set(artifact) != VMWARE_EVIDENCE_ARTIFACT_FIELDS:
                    errors.append(
                        "VMW-TRACE-001 governance artifact fields must be path and sha256 only"
                    )
                relative = artifact.get("path")
                expected_hash = artifact.get("sha256")
                if (
                    not isinstance(relative, str)
                    or not isinstance(expected_hash, str)
                    or not HASH_RE.fullmatch(expected_hash)
                ):
                    errors.append("VMW-TRACE-001 governance artifact is invalid")
                    continue
                path = repository_file(
                    relative, "VMW-TRACE-001 governance artifact path", errors
                )
                if path is not None and hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
                    errors.append(
                        f"VMW-TRACE-001 governance artifact hash drift: {relative}"
                    )

    missing = sorted(set(experiments_by_id) - set(records_by_id))
    extra = sorted(set(records_by_id) - set(experiments_by_id))
    if missing:
        errors.append("VMware evidence index is missing experiments: " + ", ".join(missing))
    if extra:
        errors.append("VMware evidence index has extra experiments: " + ", ".join(extra))
    if index.get("recordCount") != len(experiments_by_id):
        errors.append(
            "vmware-evidence-index recordCount must equal VMware experiment count"
        )

    observations = project.get("observations")
    if not isinstance(observations, dict):
        errors.append("project-status observations must be an object")
        observations = {}
    observation = observations.get("vmwareEvidenceTrace")
    expected_observation = {
        "asOf": index.get("asOf"),
        "records": counts["records"],
        "evidenceBound": counts["evidence_bound"],
        "noRun": counts["no_run"],
        "derivedAcceptanceLinks": counts["derived_acceptance_links"],
        "closureAuthority": "NONE",
    }
    if observation != expected_observation:
        errors.append(
            "project-status vmwareEvidenceTrace observation must match VMware evidence index"
        )
    return counts


def invalid_evaluation(message: str) -> Evaluation:
    """Build a fail-closed result when contract loading or validation cannot continue."""

    return Evaluation(
        errors=[message],
        blockers=[],
        project={},
        ipd_counts=Counter(),
        vmware_counts=Counter(),
        qman_evidence_counts=Counter(),
        risk_counts=Counter(),
        acceptance_counts=Counter(),
        risk_total=0,
        case_total=0,
        missing_cases=[],
        executable_cases={},
    )


def validate_project_portable_observation(
    project: dict[str, Any],
    contract: dict[str, Any],
    template: dict[str, Any],
    errors: list[str],
) -> None:
    """Keep the human/project status axes tied to generated portable artifacts."""

    observations = project.get("observations")
    observation = (
        observations.get("portableImplementationContract")
        if isinstance(observations, dict)
        else None
    )
    matrix = contract.get("mappingSurface", {}).get("verificationMatrix", [])
    mappings = template.get("mappings", [])
    statuses = template.get("statusAxes", {})
    topology = template.get("artifactTopology", {})
    expected = {
        "asOf": project.get("asOf"),
        "contractRevision": contract.get("revision"),
        "portableSpecReady": (
            contract.get("statusAxes", {})
            .get("portableSpecification", {})
            .get("status")
            == "READY"
        ),
        "mappingItems": len(mappings) if isinstance(mappings, list) else -1,
        "verificationMatrixRows": len(matrix) if isinstance(matrix, list) else -1,
        "targetCodeMapped": statuses.get("TARGET_CODE_MAPPED"),
        "productImplemented": statuses.get("PRODUCT_IMPLEMENTED"),
        "qualified": statuses.get("QUALIFIED"),
        "privateRepositoryRequiredForPortableClosure": False,
        "artifactConstructionOrder": topology.get("graph"),
    }
    if observation != expected:
        errors.append(
            "project-status portableImplementationContract observation must match "
            "the generated portable contract and baseline integration-map template"
        )


def run_portable_handoff_gate(
    mode: str,
    *,
    map_path: str = "contracts/qman-integration-map.template.json",
    trusted_root_digest: str | None = None,
    external_rollback_anchor: str | None = None,
    external_catalog_anchor: str | None = None,
    trust_anchor_freshness_envelope: str | None = None,
    catalog_anchor_freshness_envelope: str | None = None,
    verifier_nonce: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the independent portable semantic gate through its public CLI."""

    argv = [
        sys.executable,
        str(ROOT / "tools" / "validate_portable_handoff.py"),
        mode,
        "--root",
        str(ROOT),
        "--map",
        map_path,
    ]
    if trusted_root_digest is not None:
        argv.extend(["--trusted-root-digest", trusted_root_digest])
    if external_rollback_anchor is not None:
        argv.extend(["--external-rollback-anchor", external_rollback_anchor])
    if external_catalog_anchor is not None:
        argv.extend(["--external-catalog-anchor", external_catalog_anchor])
    if trust_anchor_freshness_envelope is not None:
        argv.extend(
            ["--trust-anchor-freshness-envelope", trust_anchor_freshness_envelope]
        )
    if catalog_anchor_freshness_envelope is not None:
        argv.extend(
            ["--catalog-anchor-freshness-envelope", catalog_anchor_freshness_envelope]
        )
    if verifier_nonce is not None:
        argv.extend(["--verifier-nonce", verifier_nonce])
    try:
        return subprocess.run(
            argv,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(
            argv,
            2,
            stdout="",
            stderr=f"ERROR: portable semantic validator could not run: {exc}\n",
        )


def append_portable_gate_errors(
    completed: subprocess.CompletedProcess[str], errors: list[str]
) -> None:
    """Normalize validator output into the repository contract error list."""

    if completed.returncode == 0:
        return
    lines = [
        line.strip()
        for line in (completed.stderr + "\n" + completed.stdout).splitlines()
        if line.strip()
    ]
    semantic_errors = [
        line.removeprefix("ERROR: ") for line in lines if line.startswith("ERROR: ")
    ]
    if not semantic_errors:
        semantic_errors = lines or [
            f"portable semantic validator exited {completed.returncode} without diagnostics"
        ]
    errors.extend(f"portable handoff: {item}" for item in semantic_errors)


def validate_portable_release_axes(map_path: str) -> list[str]:
    """Require the detached release map to claim every promoted axis explicitly."""

    candidate = Path(map_path)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    try:
        mapping = load_json(candidate.resolve(strict=True))
    except (OSError, ValueError) as exc:
        return [f"cannot load detached integration map {candidate}: {exc}"]
    expected = {
        "PORTABLE_SPEC_READY": True,
        "TARGET_CODE_MAPPED": True,
        "PRODUCT_IMPLEMENTED": True,
        "QUALIFIED": True,
    }
    axes = mapping.get("statusAxes")
    if axes != expected:
        return [
            "detached integration map statusAxes must exactly equal "
            f"{expected!r}; observed {axes!r}"
        ]
    return []


def _evaluate_unchecked() -> Evaluation:
    errors: list[str] = []
    blockers: list[str] = []

    try:
        project = load_repository_json(
            "contracts/project-status.json", "project status contract"
        )
        ipd_contract = load_repository_json(
            "contracts/ipd-tree.json", "IPD tree contract"
        )
        vmware_model = load_repository_json(
            "contracts/vmware-behavior-model.json", "VMware behavior contract"
        )
        vmware_sources = load_repository_json(
            "contracts/vmware-source-register.json", "VMware source register"
        )
        vmware_result_schema = load_repository_json(
            "contracts/vmware-experiment-result.schema.json",
            "VMware result schema",
        )
        vmware_evidence_index = load_repository_json(
            "contracts/vmware-evidence-index.json", "VMware evidence index"
        )
        qman_evidence_index = load_repository_json(
            "contracts/qman-evidence-index.json", "Qman evidence index"
        )
        qman_evidence_schema = load_repository_json(
            "contracts/qman-technical-evidence.schema.json",
            "Qman evidence schema",
        )
        product_decisions = load_repository_json(
            "contracts/product-decisions.json", "product decisions contract"
        )
        compatibility_profile_policy = load_repository_json(
            "contracts/compatibility-profile-policy.json",
            "compatibility profile policy",
        )
        qemu_vfio_launch_surface = load_repository_json(
            "contracts/qemu-vfio-launch-surface.json", "QEMU VFIO launch surface"
        )
        portable_contract = load_repository_json(
            "contracts/directpath-portable-control-contract.json",
            "DirectPath portable control contract",
        )
        portable_template = load_repository_json(
            "contracts/qman-integration-map.template.json",
            "DirectPath integration-map baseline template",
        )
        risk_policy = load_repository_json(
            "contracts/risk-status.json", "risk status contract"
        )
        acceptance_policy = load_repository_json(
            "contracts/acceptance-policy.json", "acceptance policy contract"
        )
        design_errors: list[str] = []
        design_path = repository_file(
            risk_policy.get("sourceDocument"),
            "risk-status sourceDocument",
            design_errors,
        )
        if design_path is None:
            raise ValueError(design_errors[-1])
        design = extract_design_contracts(design_path)
    except (OSError, ValueError) as exc:
        return invalid_evaluation(str(exc))

    if acceptance_policy.get("sourceDocument") != risk_policy.get("sourceDocument"):
        errors.append("risk and acceptance contracts must use the same detailed-design source")

    append_portable_gate_errors(run_portable_handoff_gate("baseline"), errors)
    validate_project_portable_observation(
        project, portable_contract, portable_template, errors
    )

    known_tech_story_ids = collect_ipd_tech_story_ids(ipd_contract)
    derived_open_decisions, decision_contract_valid = validate_product_decisions(
        product_decisions,
        known_tech_story_ids,
        set(design.cases),
        set(design.risks),
        errors,
    )
    validate_project_status(project, derived_open_decisions, errors, blockers)
    compatibility_profile_valid = validate_compatibility_profile_policy(
        compatibility_profile_policy, errors
    )
    launch_surface_valid = validate_qemu_vfio_launch_surface(
        qemu_vfio_launch_surface,
        compatibility_profile_policy,
        errors,
    )
    ipd_counts = validate_ipd_tree(ipd_contract, project, errors)
    vmware_counts = validate_vmware_reference(
        vmware_model,
        vmware_sources,
        vmware_result_schema,
        ipd_contract,
        project,
        errors,
    )
    validate_vmware_evidence_index(
        vmware_evidence_index,
        vmware_model,
        acceptance_policy,
        project,
        errors,
    )
    qman_risk_closure_receipts: dict[
        str, list[QmanRiskClosureReceipt]
    ] = {}
    qman_evidence_counts = validate_qman_evidence(
        qman_evidence_index,
        qman_evidence_schema,
        ipd_contract,
        design,
        errors,
        qman_risk_closure_receipts,
    )
    validate_project_qman_evidence_observation(
        project,
        qman_evidence_counts,
        errors,
    )
    risk_error_count = len(errors)
    risk_counts = validate_risks(
        risk_policy,
        design,
        qman_risk_closure_receipts,
        errors,
        blockers,
    )
    risk_governance_ready = (
        len(errors) == risk_error_count
        and sum(risk_counts.values()) == len(design.risks) == 39
    )
    acceptance_error_count = len(errors)
    acceptance_counts, missing_cases, executable = validate_acceptance(
        acceptance_policy,
        design,
        set(design.risks),
        known_tech_story_ids,
        errors,
        blockers,
    )
    acceptance_ready = (
        len(errors) == acceptance_error_count
        and not missing_cases
        and sum(acceptance_counts.values()) == len(design.cases) == 101
    )
    validate_g0_completion(
        project,
        decisions_ready=decision_contract_valid and not derived_open_decisions,
        profile_ready=compatibility_profile_valid,
        launch_surface_ready=launch_surface_valid,
        acceptance_ready=acceptance_ready,
        risk_governance_ready=risk_governance_ready,
        errors=errors,
    )

    return Evaluation(
        errors=errors,
        blockers=blockers,
        project=project,
        ipd_counts=ipd_counts,
        vmware_counts=vmware_counts,
        qman_evidence_counts=qman_evidence_counts,
        risk_counts=risk_counts,
        acceptance_counts=acceptance_counts,
        risk_total=len(design.risks),
        case_total=len(design.cases),
        missing_cases=missing_cases,
        executable_cases=executable,
    )


def evaluate() -> Evaluation:
    """Evaluate contracts without allowing malformed structure to crash the gate."""

    try:
        return _evaluate_unchecked()
    except (
        AttributeError,
        IndexError,
        KeyError,
        OSError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        return invalid_evaluation(
            "contract validation stopped safely on malformed structure: "
            f"{type(exc).__name__}: {exc}"
        )


def format_counts(counts: Counter[str]) -> str:
    if not counts:
        return "none"
    return ", ".join(f"{key}={counts[key]}" for key in sorted(counts))


def print_report(result: Evaluation) -> None:
    current = result.project.get("currentMilestone", "UNKNOWN")
    claim = result.project.get("currentClaim", "UNKNOWN")
    target = result.project.get("targetRelease", "UNKNOWN")
    delivery_model = result.project.get("deliveryModel", "UNKNOWN")
    print(f"Current milestone: {current}")
    print(f"Current claim: {claim}")
    print(f"Target release: {target} ({delivery_model})")
    observations = result.project.get("observations", {})
    portable = (
        observations.get("portableImplementationContract", {})
        if isinstance(observations, dict)
        else {}
    )
    if isinstance(portable, dict) and portable:
        print(
            "Portable handoff: "
            f"revision={portable.get('contractRevision')}, "
            f"spec_ready={portable.get('portableSpecReady')}, "
            f"mapping_items={portable.get('mappingItems')}, "
            f"target_mapped={portable.get('targetCodeMapped')}, "
            f"implemented={portable.get('productImplemented')}, "
            f"qualified={portable.get('qualified')}"
        )
    print(
        "IPD: "
        f"epics={result.ipd_counts['epics']}, "
        f"features={result.ipd_counts['features']}, "
        f"user_stories={result.ipd_counts['user_stories']}, "
        f"tech_stories={result.ipd_counts['tech_stories']}"
    )
    vmware_status_counts = Counter(
        {
            key: result.vmware_counts[key]
            for key in VMWARE_COVERAGE_STATES
            if result.vmware_counts[key]
        }
    )
    print(
        "VMware reference: "
        f"sources={result.vmware_counts['sources']}, "
        f"experiments={result.vmware_counts['experiments']}, "
        f"tech_stories={result.vmware_counts['tech_stories']} "
        f"({format_counts(vmware_status_counts)})"
    )
    qman_grade_counts = Counter(
        {
            grade: result.qman_evidence_counts[grade]
            for grade in QMAN_EVIDENCE_GRADES
            if result.qman_evidence_counts[grade]
        }
    )
    print(
        "Qman evidence: "
        f"records={result.qman_evidence_counts['records']} "
        f"({format_counts(qman_grade_counts)}; "
        f"reference={result.qman_evidence_counts['reference']}, "
        f"component={result.qman_evidence_counts['component']}, "
        f"end_to_end={result.qman_evidence_counts['end_to_end']}, "
        "product_case_closures="
        f"{result.qman_evidence_counts['product_case_closures']}, "
        f"risk_closures={result.qman_evidence_counts['risk_closures']})"
    )
    print(f"Risks: {result.risk_total} ({format_counts(result.risk_counts)})")
    defined = sum(result.acceptance_counts.values())
    print(
        f"Acceptance: {defined}/{result.case_total} defined "
        f"({format_counts(result.acceptance_counts)}); {len(result.missing_cases)} unclassified"
    )
    decisions = result.project.get("openDecisions", [])
    print(f"Open decisions: {len(decisions)}")

    if result.errors:
        print("Contract: INVALID")
        for error in result.errors:
            print(f"  ERROR: {error}")
    else:
        print("Contract: VALID")

    release_state = "BLOCKED" if result.errors or result.blockers else "READY"
    print(f"Release: {release_state}")
    for blocker in result.blockers:
        print(f"  BLOCKER: {blocker}")


def run_case(case: dict[str, Any]) -> bool:
    case_id = case["id"]
    runner = case["runner"]
    argv = [sys.executable if arg == "{python}" else arg for arg in runner["argv"]]
    cwd_errors: list[str] = []
    cwd = repository_directory(
        runner.get("cwd"), f"runnable case {case_id} runner cwd", cwd_errors
    )
    if cwd is None:
        print(f"Case {case_id}: FAIL(invalid runner cwd: {cwd_errors[-1]})")
        return False
    print(f"Running {case_id}: {' '.join(argv)}")
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"Case {case_id}: FAIL(runner error: {exc})")
        return False
    if completed.stdout:
        print(completed.stdout.rstrip())
    if completed.stderr:
        print(completed.stderr.rstrip())
    outcome = "PASS" if completed.returncode == 0 else f"FAIL({completed.returncode})"
    print(f"Case {case_id}: {outcome}")
    return completed.returncode == 0


def select_cases(result: Evaluation, requested: list[str] | None) -> tuple[list[dict[str, Any]], list[str]]:
    if not requested:
        return [result.executable_cases[key] for key in sorted(result.executable_cases)], []
    unknown = [case_id for case_id in requested if case_id not in result.executable_cases]
    selected = [result.executable_cases[case_id] for case_id in requested if case_id in result.executable_cases]
    return selected, unknown


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status", help="validate contracts and report current blockers")
    release_parser = subparsers.add_parser(
        "release",
        help="validate the detached portable map, run executable cases, and fail closed",
    )
    release_parser.add_argument(
        "--map",
        default="contracts/qman-integration-map.template.json",
        help="detached final integration map; the baseline template intentionally cannot release",
    )
    release_parser.add_argument(
        "--trusted-root-digest",
        default=None,
        help="out-of-band CONFIG-TRUST-ROOT-DIGEST",
    )
    release_parser.add_argument(
        "--external-rollback-anchor",
        default=None,
        help="out-of-band key-ring rollback-anchor JSON path",
    )
    release_parser.add_argument(
        "--external-catalog-anchor",
        default=None,
        help="out-of-band supported-catalog rollback-anchor JSON path",
    )
    release_parser.add_argument(
        "--trust-anchor-freshness-envelope",
        default=None,
        help="live root-signed trust-anchor response to --verifier-nonce",
    )
    release_parser.add_argument(
        "--catalog-anchor-freshness-envelope",
        default=None,
        help="live root-signed catalog-anchor response to --verifier-nonce",
    )
    release_parser.add_argument(
        "--verifier-nonce",
        default=None,
        help="fresh out-of-band verifier nonce; never read from release artifacts",
    )
    run_parser = subparsers.add_parser("run-cases", help="run declared executable acceptance cases")
    run_parser.add_argument("--case", action="append", dest="cases", help="case ID; repeat as needed")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = evaluate()
    print_report(result)
    if result.errors:
        return 2

    if args.command == "status":
        return 0

    if args.command == "release":
        portable_release_errors = validate_portable_release_axes(args.map)
        portable_gate = run_portable_handoff_gate(
            "all",
            map_path=args.map,
            trusted_root_digest=args.trusted_root_digest,
            external_rollback_anchor=args.external_rollback_anchor,
            external_catalog_anchor=args.external_catalog_anchor,
            trust_anchor_freshness_envelope=args.trust_anchor_freshness_envelope,
            catalog_anchor_freshness_envelope=args.catalog_anchor_freshness_envelope,
            verifier_nonce=args.verifier_nonce,
        )
        if portable_gate.stdout:
            print(portable_gate.stdout.rstrip())
        if portable_gate.stderr:
            print(portable_gate.stderr.rstrip())
        if portable_gate.returncode != 0:
            portable_release_errors.append(
                f"portable semantic gate exited {portable_gate.returncode}"
            )
        if portable_release_errors:
            print("Portable release gate: BLOCKED")
            for error in portable_release_errors:
                print(f"  BLOCKER: {error}")
            return 1

    requested = getattr(args, "cases", None)
    selected, unknown = select_cases(result, requested)
    if unknown:
        print("Not executable or unknown: " + ", ".join(unknown))
        return 2
    if not selected:
        print("No executable acceptance cases are defined.")
        return 2
    cases_passed = all([run_case(case) for case in selected])

    if args.command == "run-cases":
        return 0 if cases_passed else 1
    return 0 if cases_passed and not result.blockers else 1


if __name__ == "__main__":
    raise SystemExit(main())
