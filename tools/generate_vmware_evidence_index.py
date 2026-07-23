#!/usr/bin/env python3
"""Generate the non-closing VMware experiment evidence index deterministically."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MODEL_RELATIVE = "contracts/vmware-behavior-model.json"
ACCEPTANCE_POLICY_RELATIVE = "contracts/acceptance-policy.json"
OUTPUT_RELATIVE = "contracts/vmware-evidence-index.json"
NO_RUN_STATES = {"PLANNED", "BLOCKED_PHYSICAL"}


# A representative existing run is enough to bind an executed experiment to its
# registered evidence. The evidence file itself may aggregate more than one run.
RUN_IDS = {
    "VMW-CAP-001": ["20260714-esxi8-passthru-capability-matrix-v4"],
    "VMW-DMA-001": ["20260714-esxi8-edu-dma-teardown-v5"],
    "VMW-ACS-001": ["20260714-esxi8-no-acs-global-bypass-v1"],
    "VMW-DEP-001": ["20260718-esxi8-owner-activation-legacy-v2"],
    "VMW-OWNER-001": ["20260718-esxi8-owner-activation-v1"],
    "VMW-OWNER-002": ["20260718-esxi8-owner-reproducer-v3"],
    "VMW-OWNER-004": ["20260718-esxi8-owner-activation-v1"],
    "VMW-OWNER-005": ["20260718-esxi8-owner-activation-legacy-v2"],
    "VMW-STATIC-001": ["20260711-lifecycle"],
    "VMW-STATIC-002": ["20260711-dynamic-envelope-isolated"],
    "VMW-STATIC-LIFE-001": ["20260711-host-crash"],
    "VMW-ADMISSION-001": ["20260715-firmware-layout-matrix-final"],
    "VMW-ADMISSION-002": ["20260711-single-4g-true-size4"],
    "VMW-GUEST-VERIFY-001": ["20260712-esxi8-edu-msi-dma-reset-v4"],
    "VMW-AER-COR-001": [
        "20260723T002305Z-76d79e36",
        "20260723T003751Z-16496a4c",
        "20260723T001720Z-e19407a0",
        "20260723T004345Z-fae1a783",
        "20260723-qemu11-aer-emr-control-v1",
        "20260723-qemu11-aer-emr-allbits-v1",
        "20260723-esxi8-aer-virtio-idle-emr-v2",
        "20260723-esxi8-aer-virtio-active-emr-representative-v2",
        "20260723-esxi8-aer-virtio-active-g101-final-v1",
        "20260723-esxi8-aer-virtio-active-g100-parser-final-v1",
    ],
    "VMW-RESET-001": ["20260712-esxi8-edu-msi-dma-reset-v4"],
    "VMW-TEARDOWN-001": ["20260714-esxi8-edu-dma-teardown-v5"],
    "VMW-CRASH-001": ["20260711-host-crash"],
    "VMW-LIFECYCLE-001": ["20260711-vmotion"],
    "VMW-DYNAMIC-001": ["20260711-dynamic-envelope-isolated"],
    "VMW-DYNAMIC-002": ["20260711-dynamic-aggregate-2x1g"],
    "VMW-DYNAMIC-003": ["20260718-esxi8-owner-reproducer-v3"],
    "VMW-DYNAMIC-004": ["20260711-vmotion"],
    "VMW-CLUSTER-001": ["20260711-vmotion"],
    "VMW-CLUSTER-002": ["20260711-vmotion"],
    "VMW-CLUSTER-FAILURE-001": ["20260711-host-crash"],
    "VMW-OPS-001": ["20260718-esxi8-owner-activation-v1"],
    "VMW-EVIDENCE-001": ["20260714-esxi8-edu-dma-teardown-v5"],
    "VMW-TRACE-001": ["20260723-vmware-evidence-index-v2"],
}

NO_RUN_REASONS = {
    "VMW-QUAL-001": (
        "Physical GPU, HBA and accelerator qualification evidence is not available "
        "in the nested-QEMU laboratory."
    ),
    "VMW-OWNER-003": (
        "No deterministic mid-bundle owner-transition failure injection exists."
    ),
    "VMW-STATIC-IDENTITY-001": (
        "No controlled same-BDF device, subsystem or ROM identity replacement run exists."
    ),
    "VMW-QUARANTINE-001": (
        "No deterministic reset or clean-state failure injection exists."
    ),
    "VMW-COLD-CLEAN-001": (
        "Existing source teardown and target reselection observations are separate runs, "
        "not one correlated clean relocation transaction."
    ),
    "VMW-COLD-NOCLEAN-001": (
        "No deterministic dirty-device or reset-failure relocation hook exists."
    ),
    "VMW-COLD-EXHAUST-001": (
        "Existing exhaustion occurs on the target after another case, not during one "
        "source-release to target-reservation relocation transaction."
    ),
    "VMW-CLUSTER-FENCE-001": (
        "Physical host fencing is outside the online-host-only nested cluster scope."
    ),
}


def load_json(path: Path) -> dict[str, Any]:
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
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_non_finite,
        )
    except RecursionError as exc:
        raise ValueError(f"invalid JSON in {path}: nesting is too deep") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def repository_file(relative: Any, label: str) -> Path:
    """Resolve a canonical repository path and reject traversal/symlink escape."""

    if not isinstance(relative, str) or not relative:
        raise ValueError(f"{label} must be a non-empty repository-relative path")
    relative_path = Path(relative)
    if relative_path.is_absolute():
        raise ValueError(f"{label} must be repository-relative: {relative!r}")
    if ".." in relative_path.parts:
        raise ValueError(f"{label} must not contain path traversal: {relative!r}")
    root = ROOT.resolve()
    lexical_candidate = ROOT / relative_path
    if lexical_candidate.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link: {relative!r}")
    candidate = lexical_candidate.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} escapes the repository: {relative!r}") from exc
    if not candidate.is_file():
        raise ValueError(f"{label} does not exist: {relative!r}")
    return candidate


def repository_directory(relative: Any, label: str) -> Path:
    """Resolve a repository directory and reject traversal/symlink escape."""

    if not isinstance(relative, str) or not relative:
        raise ValueError(f"{label} must be a non-empty repository-relative path")
    relative_path = Path(relative)
    if relative_path.is_absolute():
        raise ValueError(f"{label} must be repository-relative: {relative!r}")
    if ".." in relative_path.parts:
        raise ValueError(f"{label} must not contain path traversal: {relative!r}")
    root = ROOT.resolve()
    lexical_candidate = ROOT / relative_path
    if lexical_candidate.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link: {relative!r}")
    candidate = lexical_candidate.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} escapes the repository: {relative!r}") from exc
    if not candidate.is_dir():
        raise ValueError(f"{label} does not exist: {relative!r}")
    return candidate


def repository_output_file(relative: Any, label: str) -> Path:
    """Resolve a repository output without following an existing link."""

    if not isinstance(relative, str) or not relative:
        raise ValueError(f"{label} must be a non-empty repository-relative path")
    relative_path = Path(relative)
    if relative_path.is_absolute():
        raise ValueError(f"{label} must be repository-relative: {relative!r}")
    if ".." in relative_path.parts:
        raise ValueError(f"{label} must not contain path traversal: {relative!r}")
    candidate = ROOT / relative_path
    if candidate.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link: {relative!r}")
    root = ROOT.resolve()
    parent = candidate.parent.resolve()
    try:
        parent.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} parent escapes the repository: {relative!r}") from exc
    if not parent.is_dir():
        raise ValueError(f"{label} parent does not exist: {relative!r}")
    if candidate.exists() and not candidate.is_file():
        raise ValueError(f"{label} is not a regular file: {relative!r}")
    return candidate


def repository_discovered_file(path: Path, label: str) -> Path:
    """Validate a generated-input file without trusting directory-entry symlinks."""

    if path.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link: {path.name!r}")
    root = ROOT.resolve()
    candidate = path.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} escapes the repository: {str(path)!r}") from exc
    if not candidate.is_file():
        raise ValueError(f"{label} is not a repository file: {str(path)!r}")
    return candidate


def acceptance_definitions(policy: dict[str, Any]) -> list[dict[str, Any]]:
    directory = repository_directory(
        policy.get("caseDefinitionDirectory"), "acceptance case definition directory"
    )
    definitions: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        resolved_path = repository_discovered_file(
            path, f"acceptance definition {path.name}"
        )
        payload = load_json(resolved_path)
        records = payload.get("records") if isinstance(payload, dict) else None
        definitions.extend(records if records is not None else [payload])
    return definitions


def build() -> dict[str, Any]:
    model = load_json(repository_file(MODEL_RELATIVE, "VMware behavior model"))
    policy = load_json(
        repository_file(ACCEPTANCE_POLICY_RELATIVE, "acceptance policy")
    )
    cases = acceptance_definitions(policy)

    experiment_ids = {item["id"] for item in model["experiments"]}
    executed_ids = {
        item["id"]
        for item in model["experiments"]
        if item["executionState"] not in NO_RUN_STATES
    }
    no_run_ids = experiment_ids - executed_ids
    missing_runs = sorted(executed_ids - set(RUN_IDS))
    extra_runs = sorted(set(RUN_IDS) - executed_ids)
    missing_reasons = sorted(no_run_ids - set(NO_RUN_REASONS))
    extra_reasons = sorted(set(NO_RUN_REASONS) - no_run_ids)
    if missing_runs or extra_runs or missing_reasons or extra_reasons:
        raise ValueError(
            "incomplete mapping: "
            f"missing runs={missing_runs}, extra runs={extra_runs}, "
            f"missing reasons={missing_reasons}, extra reasons={extra_reasons}"
        )

    tech_stories_by_experiment = {item["id"]: set() for item in model["experiments"]}
    for coverage in model["techStoryCoverage"]:
        for experiment_id in coverage.get("experimentIds", []):
            tech_stories_by_experiment[experiment_id].add(coverage["techStoryId"])

    cases_by_tech_story: dict[str, set[str]] = {}
    for case in cases:
        for tech_story_id in case.get("requiredTechStories", []):
            cases_by_tech_story.setdefault(tech_story_id, set()).add(case["id"])

    records = []
    for experiment in model["experiments"]:
        experiment_id = experiment["id"]
        tech_story_ids = sorted(tech_stories_by_experiment[experiment_id])
        derived_case_ids = sorted(
            {
                case_id
                for tech_story_id in tech_story_ids
                for case_id in cases_by_tech_story.get(tech_story_id, set())
            }
        )
        no_run = experiment["executionState"] in NO_RUN_STATES
        records.append(
            {
                "experimentId": experiment_id,
                "executionState": experiment["executionState"],
                "techStoryIds": tech_story_ids,
                "legacyCaseIds": experiment["legacyIds"],
                "derivedAcceptanceCaseIds": derived_case_ids,
                "runIds": [] if no_run else RUN_IDS[experiment_id],
                "evidence": []
                if no_run
                else [
                    {
                        "path": path,
                        "sha256": sha256(
                            repository_file(
                                path, f"VMware experiment {experiment_id} evidence path"
                            )
                        ),
                    }
                    for path in experiment["evidencePaths"]
                ],
                "noRunReason": NO_RUN_REASONS[experiment_id] if no_run else None,
                "limitations": experiment["limitations"],
            }
        )

    return {
        "schemaVersion": 1,
        "asOf": "2026-07-23",
        "subject": "VMWARE_ESXI",
        "sourceModel": "contracts/vmware-behavior-model.json",
        "hashAlgorithm": "SHA-256",
        "recordCount": len(records),
        "tracePolicy": {
            "techStoryAssociation": "EXACT_FROM_VMWARE_BEHAVIOR_MODEL",
            "acceptanceCaseAssociation": (
                "DERIVED_FROM_ACCEPTANCE_REQUIRED_TECH_STORIES"
            ),
            "acceptanceClosureAuthority": "NONE",
            "qmanImplementationClosureAuthority": "NONE",
            "qmanQualificationClosureAuthority": "NONE",
            "noRunStates": sorted(NO_RUN_STATES),
        },
        "records": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = json.dumps(build(), indent=2, ensure_ascii=False) + "\n"
    output_path = repository_output_file(OUTPUT_RELATIVE, "VMware evidence index")
    if args.check:
        if not output_path.is_file() or output_path.read_text(encoding="utf-8") != rendered:
            print(f"stale: {output_path.relative_to(ROOT)}")
            return 1
        print(f"current: {output_path.relative_to(ROOT)}")
        return 0
    output_path.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"generated: {output_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
