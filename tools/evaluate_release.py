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
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"

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
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
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
IPD_STATES = {"DEFINED_NOT_ACCEPTED", "ACCEPTED"}
IPD_RELEASE_STATES = {"PROPOSED_FOR_REVIEW", "ACCEPTED", "RETIRED"}
VMWARE_COVERAGE_STATES = {"VERIFIED", "PARTIAL", "UNKNOWN", "NOT_APPLICABLE"}
VMWARE_EXECUTION_STATES = {"OBSERVED", "PARTIAL", "PLANNED", "BLOCKED_PHYSICAL"}
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


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"missing contract: {path.relative_to(ROOT)}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid JSON in {path.relative_to(ROOT)}:{exc.lineno}: {exc.msg}"
        ) from exc
    if not isinstance(value, dict):
        raise ValueError(f"contract root must be an object: {path.relative_to(ROOT)}")
    return value


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


def validate_project_status(project: dict[str, Any], errors: list[str], blockers: list[str]) -> None:
    if project.get("schemaVersion") != 1:
        errors.append("project-status.json schemaVersion must be 1")

    documents = project.get("authoritativeDocuments")
    if not isinstance(documents, dict) or not documents:
        errors.append("project-status.json must declare authoritativeDocuments")
    else:
        for name, relative in documents.items():
            if not isinstance(relative, str) or not (ROOT / relative).exists():
                errors.append(f"authoritative document {name!r} does not exist: {relative!r}")

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
        if state not in MILESTONE_STATES:
            errors.append(f"milestone {milestone_id} has invalid status: {state!r}")
        milestone_ids.append(milestone_id)
        milestone_by_id[milestone_id] = item

    in_progress = [mid for mid in milestone_ids if milestone_by_id[mid].get("status") == "IN_PROGRESS"]
    current = project.get("currentMilestone")
    if current is None:
        if in_progress:
            errors.append(f"currentMilestone is null but milestones are IN_PROGRESS: {in_progress}")
    elif current not in milestone_by_id:
        errors.append(f"currentMilestone is not declared: {current!r}")
    elif milestone_by_id[current].get("status") != "IN_PROGRESS" or in_progress != [current]:
        errors.append(f"exactly currentMilestone must be IN_PROGRESS; observed {in_progress}")

    unfinished = [mid for mid in milestone_ids if milestone_by_id[mid].get("status") != "DONE"]
    if unfinished:
        blockers.append("unfinished milestones: " + ", ".join(unfinished))

    decisions = project.get("openDecisions")
    if not isinstance(decisions, list) or any(not isinstance(item, str) for item in decisions):
        errors.append("openDecisions must be a list of ADR IDs")
    elif decisions:
        blockers.append("open product/platform decisions: " + ", ".join(decisions))


def validate_risks(
    policy: dict[str, Any],
    design: DesignContracts,
    qman_evidence_index: dict[str, Any],
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
    closure_evidence_by_risk: dict[str, list[tuple[str, str]]] = {}
    indexed_evidence = qman_evidence_index.get("records")
    if isinstance(indexed_evidence, list):
        for evidence_record in indexed_evidence:
            if not isinstance(evidence_record, dict):
                continue
            result_relative = evidence_record.get("resultPath")
            result_hash = evidence_record.get("resultSha256")
            if not isinstance(result_relative, str) or not isinstance(result_hash, str):
                continue
            result_path = ROOT / result_relative
            try:
                evidence_result = load_json(result_path)
            except ValueError:
                continue
            closure = evidence_result.get("closureEffect")
            closed_risks = closure.get("risksClosed") if isinstance(closure, dict) else None
            grade = evidence_result.get("evidenceGrade")
            if not isinstance(closed_risks, list) or not isinstance(grade, str):
                continue
            for closed_risk in closed_risks:
                if isinstance(closed_risk, str):
                    closure_evidence_by_risk.setdefault(closed_risk, []).append(
                        (result_hash, grade)
                    )
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

        test_ids = record["testIds"]
        hashes = record["artifactHashes"]
        evidence_grade = record["evidenceGrade"]
        if not isinstance(test_ids, list) or any(not isinstance(item, str) for item in test_ids):
            errors.append(f"risk {risk_id} testIds must be a list of strings")
            test_ids = []
        else:
            if len(test_ids) != len(set(test_ids)):
                errors.append(f"risk {risk_id} testIds must be unique")
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

        if state in {"VERIFIED", "FEATURE_DISABLED"}:
            complete = (
                bool(record["owner"])
                and bool(record["containmentRecovery"])
                and bool(test_ids)
                and evidence_grade in {"E3", "E4"}
                and bool(hashes)
            )
            closing_evidence = closure_evidence_by_risk.get(risk_id, [])
            closure_matches = any(
                result_hash in hashes and result_grade == evidence_grade
                for result_hash, result_grade in closing_evidence
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
    directory = ROOT / directory_value
    if not directory.is_dir():
        errors.append(f"acceptance definition directory does not exist: {directory_value}")
        return Counter(), list(design.cases), {}

    allowed = set(policy.get("allowedStatuses", []))
    if allowed != CASE_STATES:
        errors.append(f"acceptance allowedStatuses must be {sorted(CASE_STATES)}")

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
    for path in sorted(directory.glob("*.json")):
        try:
            case = load_json(path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
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

        risk_ids = case.get("riskIds")
        if not isinstance(risk_ids, list) or not risk_ids:
            errors.append(f"acceptance case {case_id} must reference at least one risk ID")
        else:
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
            if not isinstance(cwd, str) or not (ROOT / cwd).is_dir():
                errors.append(f"runnable case {case_id} runner cwd does not exist: {cwd!r}")
                continue
            if not isinstance(argv, list) or not argv or any(not isinstance(arg, str) for arg in argv):
                errors.append(f"runnable case {case_id} runner argv must be a non-empty string list")
                continue
            if state == "FEATURE_DISABLED" and not case.get("negativeGate"):
                errors.append(f"feature-disabled case {case_id} must describe its negativeGate")
                continue
            executable[case_id] = case
            if case.get("scope") != "PRODUCT" and state == "EXECUTABLE":
                reference_only.append(case_id)
        elif state == "IMPLEMENTATION_BLOCKED":
            if not case.get("blocker") or not case.get("targetMilestone"):
                errors.append(
                    f"implementation-blocked case {case_id} must declare blocker and targetMilestone"
                )
        elif state == "HARDWARE_BLOCKED" and not case.get("blocker"):
            errors.append(f"hardware-blocked case {case_id} must describe its blocker")

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
        if not isinstance(value, str) or not (ROOT / value).is_file():
            errors.append(f"ipd-tree.json {label} does not exist: {value!r}")
        elif label == "sourceDocument":
            source_text = (ROOT / value).read_text(encoding="utf-8")

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
            if not isinstance(relative, str) or not (ROOT / relative).exists():
                errors.append(
                    f"IPD feature {feature_id} supplement does not exist: {relative!r}"
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
    for key in ("technicalScope", "productionSupportScope", "unqualifiedMode"):
        if not isinstance(boundary.get(key), str) or not boundary.get(key):
            errors.append(f"IPD productBoundary must declare {key}")
    unsupported = boundary.get("explicitlyUnsupportedOperations")
    if not isinstance(unsupported, list) or not unsupported or any(
        not isinstance(item, str) for item in unsupported
    ):
        errors.append("IPD explicitlyUnsupportedOperations must be a non-empty string list")

    dimensions = contract.get("capabilityDimensions")
    required_dimensions = {
        "TECHNICALLY_ATTACHABLE",
        "ELIGIBLE",
        "QUALIFIED",
        "SUPPORTED",
    }
    if not isinstance(dimensions, dict):
        errors.append("ipd-tree.json must declare capabilityDimensions")
    else:
        missing_dimensions = sorted(required_dimensions - set(dimensions))
        if missing_dimensions:
            errors.append("IPD capabilityDimensions missing: " + ", ".join(missing_dimensions))
        invariants = dimensions.get("invariants")
        if not isinstance(invariants, list) or not invariants or any(
            not isinstance(item, str) for item in invariants
        ):
            errors.append("IPD capabilityDimensions invariants must be a non-empty string list")

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
                if key in path_keys and (
                    not isinstance(relative, str) or not (ROOT / relative).exists()
                ):
                    errors.append(
                        f"IPD cross-cutting mapping {mapping_name}.{key} does not exist: "
                        f"{relative!r}"
                    )

    return counts


def repository_file(
    relative: Any,
    label: str,
    errors: list[str],
) -> Path | None:
    """Resolve one repository-owned file without permitting absolute/path traversal."""

    if not isinstance(relative, str) or not relative:
        errors.append(f"{label} must be a non-empty repository-relative path")
        return None
    relative_path = Path(relative)
    if relative_path.is_absolute():
        errors.append(f"{label} must be repository-relative: {relative!r}")
        return None
    root = ROOT.resolve()
    candidate = (ROOT / relative_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        errors.append(f"{label} escapes the repository: {relative!r}")
        return None
    if not candidate.is_file():
        errors.append(f"{label} does not exist: {relative!r}")
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
        mapping = {}
    mapped_cases = set(mapping.get("caseIds", [])) if isinstance(
        mapping.get("caseIds"), list
    ) else set()
    mapped_risks = set(mapping.get("riskIds", [])) if isinstance(
        mapping.get("riskIds"), list
    ) else set()

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
        if claim_boundary not in {"END_TO_END_PRODUCT", "PHYSICAL_QUALIFICATION"}:
            errors.append(
                f"Qman evidence {evidence_id} end-to-end subject must use an end-to-end claim boundary"
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


def validate_qman_evidence(
    index: dict[str, Any],
    result_schema: dict[str, Any],
    ipd_contract: dict[str, Any],
    design: DesignContracts,
    errors: list[str],
) -> Counter[str]:
    """Validate committed Qman evidence, provenance hashes, and closure boundaries."""

    counts: Counter[str] = Counter()
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
    if not isinstance(schema_required, list) or set(schema_required) != QMAN_RESULT_REQUIRED_FIELDS:
        errors.append("Qman evidence result schema required fields have drifted")
    schema_properties = result_schema.get("properties")
    if not isinstance(schema_properties, dict) or not QMAN_RESULT_REQUIRED_FIELDS.issubset(
        schema_properties
    ):
        errors.append("Qman evidence result schema properties are incomplete")
        schema_properties = {}

    subject_property = schema_properties.get("subject", {})
    grade_property = schema_properties.get("evidenceGrade", {})
    boundary_property = schema_properties.get("claimBoundary", {})
    verdict_property = schema_properties.get("verdict", {})
    schema_subjects = set(subject_property.get("enum", [])) if isinstance(
        subject_property, dict
    ) else set()
    if set(grade_property.get("enum", [])) != QMAN_EVIDENCE_GRADES:
        errors.append("Qman evidence result schema evidenceGrade enum has drifted")
    if set(boundary_property.get("enum", [])) != QMAN_CLAIM_BOUNDARIES:
        errors.append("Qman evidence result schema claimBoundary enum has drifted")
    if set(verdict_property.get("enum", [])) != QMAN_EVIDENCE_VERDICTS:
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
        "SUPPORTED_REQUIRES_E4_PHYSICAL_QUALIFICATION_AND_PRODUCT_GATE",
        "EVIDENCE_HASH_DRIFT_INVALIDATES_RECORD",
    }
    invariants = closure_policy.get("invariants")
    if not isinstance(invariants, list) or set(invariants) != required_invariants:
        errors.append("Qman closurePolicy invariants have drifted")

    e4_values = closure_policy.get("e4RequiredRisks")
    if not isinstance(e4_values, list) or not e4_values or any(
        not isinstance(item, str) for item in e4_values
    ):
        errors.append("Qman closurePolicy e4RequiredRisks must be a non-empty string list")
        e4_required_risks: set[str] = set()
    else:
        e4_required_risks = set(e4_values)
        if len(e4_required_risks) != len(e4_values):
            errors.append("Qman closurePolicy e4RequiredRisks must be unique")
        unknown_e4_risks = sorted(e4_required_risks - set(design.risks))
        if unknown_e4_risks:
            errors.append(
                f"Qman closurePolicy references unknown E4 risks: {unknown_e4_risks}"
            )

    known_tech_stories = {
        story.get("id")
        for feature in ipd_contract.get("features", [])
        if isinstance(feature, dict)
        for story in feature.get("techStories", [])
        if isinstance(story, dict) and isinstance(story.get("id"), str)
    }
    known_cases = set(design.cases)
    known_risks = set(design.risks)
    records = index.get("records")
    if not isinstance(records, list) or not records:
        errors.append("qman-evidence-index records must be a non-empty list")
        return counts

    record_required = {
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
        counts["records"] += 1
        missing_record_fields = sorted(record_required - set(record))
        if missing_record_fields:
            errors.append(
                f"Qman evidence index {evidence_id} missing fields: {missing_record_fields}"
            )
            continue

        result_path = repository_file(
            record.get("resultPath"),
            f"Qman evidence {evidence_id} resultPath",
            errors,
        )
        expected_result_hash = record.get("resultSha256")
        if not isinstance(expected_result_hash, str) or not HASH_RE.fullmatch(
            expected_result_hash
        ):
            errors.append(f"Qman evidence {evidence_id} has invalid result SHA-256")
        elif result_path is not None:
            actual_result_hash = hashlib.sha256(result_path.read_bytes()).hexdigest()
            if actual_result_hash != expected_result_hash:
                errors.append(
                    f"Qman evidence {evidence_id} result hash drift: "
                    f"{record.get('resultPath')}"
                )
        if result_path is None:
            continue
        try:
            result = load_json(result_path)
        except ValueError as exc:
            errors.append(str(exc))
            continue

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
        if subject not in schema_subjects:
            errors.append(f"Qman evidence {evidence_id} has invalid subject: {subject!r}")
        if grade not in QMAN_EVIDENCE_GRADES:
            errors.append(f"Qman evidence {evidence_id} has invalid grade: {grade!r}")
        else:
            counts[grade] += 1
        if verdict not in QMAN_EVIDENCE_VERDICTS:
            errors.append(f"Qman evidence {evidence_id} has invalid verdict: {verdict!r}")
        else:
            counts[verdict] += 1
        claim_boundary = result.get("claimBoundary")
        if claim_boundary not in QMAN_CLAIM_BOUNDARIES:
            errors.append(
                f"Qman evidence {evidence_id} has invalid claimBoundary: "
                f"{claim_boundary!r}"
            )
        else:
            counts[f"boundary:{claim_boundary}"] += 1

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
                if retention not in {"COMMITTED", "LOCAL_RAW"}:
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
                counts["product_case_closures"] += len(cases_closed)
            if isinstance(risks_closed, list):
                counts["risk_closures"] += len(risks_closed)
            if closure.get("statusUpdated") is True:
                counts["status_updates"] += 1
        if subject in reference_subjects:
            counts["reference"] += 1
        elif subject == "QMAN_COMPONENT":
            counts["component"] += 1
        elif subject == "QMAN_END_TO_END":
            counts["end_to_end"] += 1

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
    if not isinstance(source_document, str) or not (ROOT / source_document).is_file():
        errors.append(f"VMware behavior sourceDocument does not exist: {source_document!r}")
    else:
        source_text = (ROOT / source_document).read_text(encoding="utf-8")
    if (
        not isinstance(source_register_path, str)
        or not (ROOT / source_register_path).is_file()
    ):
        errors.append(f"VMware behavior sourceRegister does not exist: {source_register_path!r}")
    if not isinstance(result_schema_path, str) or not (ROOT / result_schema_path).is_file():
        errors.append(f"VMware behavior resultSchema does not exist: {result_schema_path!r}")

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
    if not isinstance(schema_required, list) or set(schema_required) != required_result_fields:
        errors.append("VMware result schema required fields have drifted")
    schema_properties = result_schema.get("properties")
    if not isinstance(schema_properties, dict) or not required_result_fields.issubset(
        schema_properties
    ):
        errors.append("VMware result schema properties are incomplete")

    if set(model.get("coverageStatuses", [])) != VMWARE_COVERAGE_STATES:
        errors.append(
            "vmware-behavior-model coverageStatuses must be "
            + ", ".join(sorted(VMWARE_COVERAGE_STATES))
        )
    if set(model.get("truthKinds", [])) != VMWARE_TRUTH_KINDS:
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
        if execution_state not in VMWARE_EXECUTION_STATES:
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
        for key, paths in (("evidencePaths", evidence_paths), ("runnerPaths", runner_paths)):
            if not isinstance(paths, list) or any(not isinstance(item, str) for item in paths):
                errors.append(f"VMware experiment {experiment_id} {key} must be strings")
                continue
            missing_paths = [relative for relative in paths if not (ROOT / relative).exists()]
            if missing_paths:
                errors.append(
                    f"VMware experiment {experiment_id} {key} do not exist: {missing_paths}"
                )
        if execution_state == "OBSERVED" and not evidence_paths:
            errors.append(f"observed VMware experiment {experiment_id} must reference evidence")
        evidence_hashes = experiment.get("evidenceSha256")
        if execution_state == "OBSERVED":
            if not isinstance(evidence_hashes, dict) or set(evidence_hashes) != set(
                evidence_paths or []
            ):
                errors.append(
                    f"observed VMware experiment {experiment_id} must hash every evidence path"
                )
            else:
                for relative, expected_hash in evidence_hashes.items():
                    if not isinstance(expected_hash, str) or not HASH_RE.fullmatch(expected_hash):
                        errors.append(
                            f"VMware experiment {experiment_id} has an invalid evidence SHA-256"
                        )
                        continue
                    path = ROOT / relative
                    if path.is_file():
                        actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
                        if actual_hash != expected_hash:
                            errors.append(
                                f"VMware experiment {experiment_id} evidence hash drift: {relative}"
                            )
        limitations = experiment.get("limitations")
        if not isinstance(limitations, list) or not limitations or any(
            not isinstance(item, str) for item in limitations
        ):
            errors.append(f"VMware experiment {experiment_id} must declare limitations")

    ipd_tech_ids = {
        story.get("id")
        for feature in ipd_contract.get("features", [])
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
        if status not in VMWARE_COVERAGE_STATES:
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


def evaluate() -> Evaluation:
    errors: list[str] = []
    blockers: list[str] = []

    try:
        project = load_json(CONTRACTS / "project-status.json")
        ipd_contract = load_json(CONTRACTS / "ipd-tree.json")
        vmware_model = load_json(CONTRACTS / "vmware-behavior-model.json")
        vmware_sources = load_json(CONTRACTS / "vmware-source-register.json")
        vmware_result_schema = load_json(
            CONTRACTS / "vmware-experiment-result.schema.json"
        )
        qman_evidence_index = load_json(CONTRACTS / "qman-evidence-index.json")
        qman_evidence_schema = load_json(
            CONTRACTS / "qman-technical-evidence.schema.json"
        )
        risk_policy = load_json(CONTRACTS / "risk-status.json")
        acceptance_policy = load_json(CONTRACTS / "acceptance-policy.json")
        design_path = ROOT / risk_policy.get("sourceDocument", "")
        design = extract_design_contracts(design_path)
    except (OSError, ValueError) as exc:
        return Evaluation(
            errors=[str(exc)],
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

    if acceptance_policy.get("sourceDocument") != risk_policy.get("sourceDocument"):
        errors.append("risk and acceptance contracts must use the same detailed-design source")

    validate_project_status(project, errors, blockers)
    ipd_counts = validate_ipd_tree(ipd_contract, project, errors)
    vmware_counts = validate_vmware_reference(
        vmware_model,
        vmware_sources,
        vmware_result_schema,
        ipd_contract,
        project,
        errors,
    )
    qman_evidence_counts = validate_qman_evidence(
        qman_evidence_index,
        qman_evidence_schema,
        ipd_contract,
        design,
        errors,
    )
    validate_project_qman_evidence_observation(
        project,
        qman_evidence_counts,
        errors,
    )
    risk_counts = validate_risks(
        risk_policy,
        design,
        qman_evidence_index,
        errors,
        blockers,
    )
    acceptance_counts, missing_cases, executable = validate_acceptance(
        acceptance_policy,
        design,
        set(design.risks),
        collect_ipd_tech_story_ids(ipd_contract),
        errors,
        blockers,
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
    cwd = ROOT / runner["cwd"]
    print(f"Running {case_id}: {' '.join(argv)}")
    completed = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
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
    subparsers.add_parser("release", help="run executable cases and fail closed on any blocker")
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
