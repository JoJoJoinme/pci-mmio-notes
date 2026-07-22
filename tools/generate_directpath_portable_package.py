#!/usr/bin/env python3
"""Deterministically close the DirectPath portable package and mapping surface.

The portable contract hash is meaningful only if every normative source is also
hash-bound.  This generator updates that closure, the exact ordered mapping
surface in the integration-map schema, and the empty integration-map template.
It never advances target mapping, implementation, or qualification status.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import unicodedata
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "contracts/directpath-portable-control-contract.json"
SCHEMA_PATH = ROOT / "contracts/qman-integration-map.schema.json"
TEMPLATE_PATH = ROOT / "contracts/qman-integration-map.template.json"
SCENARIO_SCHEMA_PATH = ROOT / "contracts/directpath-acceptance-scenario.schema.json"


TYPED_COVERAGE_RULES = {
    "CANONICALIZATION": "CANONICALIZATION_PROFILE_TYPED_TRACE_OR_ALL",
    "GUARD": "GUARD_TYPED_TRACE_OR_ALL",
    "CONFIG": "CONFIG_TYPED_TRACE_OR_ALL",
    "MIGRATION": "MIGRATION_TYPED_TRACE_OR_ALL",
    "TELEMETRY": "TELEMETRY_TYPED_TRACE_OR_ALL",
    "TEST": "TEST_SELF",
    "PARITY_OBLIGATION": "PARITY_DECLARED_TESTS_OR_ALL",
    "PORT": "PORT_TECH_STORY_INTERSECTION_OR_ALL",
    "OPERATION": "OPERATION_OWNER_PORT_OR_ALL",
    "TRANSITION": "TRANSITION_OPERATION_UNION_WITH_CRASH_SIDE_EFFECT_OR_ALL",
    "STATE_MACHINE": "STATE_MACHINE_TRANSITION_UNION_OR_ALL",
    "REASON": "REASON_LISTING_OPERATION_UNION_OR_ALL",
    "CAS_RULE": "CAS_RULE_REFERENCING_TRANSITION_UNION_OR_ALL",
    "EQUIVALENCE": "EQUIVALENCE_TEST_DYNAMIC_OR_ALL",
    "ENTITY": "ENTITY_STATE_MACHINE_UNION_OR_ALL",
}
CONSERVATIVE_COVERAGE_RULE = "CONSERVATIVE_ALL"


def render(document: Any) -> bytes:
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_bytes(document: Any) -> bytes:
    """Canonical JSON for the simple tree-index records used here."""

    return json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def tree_digest(path: Path) -> str:
    records: list[dict[str, str]] = []
    portable_names: set[str] = set()
    children = list(path.rglob("*"))
    children.sort(key=lambda item: canonical_bytes(item.relative_to(path).as_posix()))
    for child in children:
        if child.is_symlink():
            raise ValueError(f"normative tree must not contain symlinks: {child}")
        relative = child.relative_to(path).as_posix()
        if ".git" in Path(relative).parts:
            raise ValueError(f"normative tree must not contain .git/submodules: {child}")
        if unicodedata.normalize("NFC", relative) != relative:
            raise ValueError(f"normative tree path is not NFC: {relative}")
        if child.is_file():
            portable_key = relative.casefold()
            if portable_key in portable_names:
                raise ValueError(f"normative tree has a case-fold collision: {relative}")
            portable_names.add(portable_key)
            records.append(
                {
                    "path": relative,
                    "sha256": digest_bytes(child.read_bytes()),
                }
            )
    if not records:
        raise ValueError(f"normative tree is empty: {path}")
    return digest_bytes(canonical_bytes(records))


def derive_mapping_items(contract: dict[str, Any]) -> list[tuple[str, str, str]]:
    items = [
        *[("CANONICALIZATION", item["id"]) for item in contract["canonicalizationContract"]["profiles"]],
        *[("GUARD", item["id"]) for item in contract["safetyGuards"]],
        ("EQUIVALENCE", contract["dynamicCandidateEquivalence"]["id"]),
        *[("PORT", item["id"]) for item in contract["requiredPorts"]],
        *[("ENTITY", item["id"]) for item in contract["dataEntities"]],
        *[("OPERATION", item["id"]) for item in contract["backendNeutralOperations"]],
        *[("STATE_MACHINE", item["id"]) for item in contract["stateMachines"]],
        *[
            ("TRANSITION", transition["id"])
            for machine in contract["stateMachines"]
            for transition in machine["transitions"]
        ],
        *[("CAS_RULE", item["id"]) for item in contract["casRules"]],
        *[("REASON", item["code"]) for item in contract["errorContract"]["reasonCodes"]],
        *[("CONFIG", item["id"]) for item in contract["configurationContract"]["settings"]],
        *[("MIGRATION", item["id"]) for item in contract["migrationContract"]["steps"]],
        *[("TELEMETRY", item["id"]) for item in contract["telemetryContract"]["metrics"]],
        *[("TEST", item["id"]) for item in contract["acceptanceObligations"]],
        *[("PARITY_OBLIGATION", item["id"]) for item in contract["vmwareParityObligations"]],
    ]
    overrides = {
        (item["kind"], item["contractItemId"]): item["releaseTrack"]
        for item in contract["mappingSurface"]["releaseTrackOverrides"]
    }
    default = contract["mappingSurface"]["releaseTrackDefault"]
    result = [(kind, item_id, overrides.get((kind, item_id), default)) for kind, item_id in items]
    if len(result) != len({(kind, item_id) for kind, item_id, _ in result}):
        raise ValueError("portable mapping surface contains duplicate kind/id")
    return result


def ordered_unique(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def derive_verification_matrix(
    contract: dict[str, Any],
    items: list[tuple[str, str, str]],
) -> list[dict[str, Any]]:
    """Derive contract-owned test requirements without trusting target claims."""

    obligations = contract["acceptanceObligations"]
    obligation_by_id = {item["id"]: item for item in obligations}
    obligation_order = [item["id"] for item in obligations]
    if len(obligation_by_id) != len(obligations):
        raise ValueError("acceptanceObligations contains duplicate ids")
    if "TEST-DYNAMIC" not in obligation_by_id:
        raise ValueError("TEST-DYNAMIC acceptance obligation is required")
    if "TEST-CRASH-RECONCILE-AUDIT" not in obligation_by_id:
        raise ValueError("TEST-CRASH-RECONCILE-AUDIT acceptance obligation is required")

    scenario_schema = json.loads(SCENARIO_SCHEMA_PATH.read_text(encoding="utf-8"))
    oracle_classes = sorted(
        scenario_schema["$defs"]["oracleMatrix"]["properties"].keys()
    )
    if len(oracle_classes) != 8:
        raise ValueError(
            "acceptance scenario oracleMatrix must expose exactly eight oracle classes"
        )

    ports = {item["id"]: item for item in contract["requiredPorts"]}
    operations = {item["id"]: item for item in contract["backendNeutralOperations"]}
    state_machines = {item["id"]: item for item in contract["stateMachines"]}
    transitions = {
        transition["id"]: transition
        for machine in contract["stateMachines"]
        for transition in machine["transitions"]
    }
    parity = {item["id"]: item for item in contract["vmwareParityObligations"]}

    def normalize_obligations(candidate_ids: list[str]) -> list[str]:
        unknown = set(candidate_ids) - set(obligation_by_id)
        if unknown:
            raise ValueError(
                "verification derivation references unknown acceptance obligations: "
                + ", ".join(sorted(unknown))
            )
        wanted = set(candidate_ids)
        result = [item_id for item_id in obligation_order if item_id in wanted]
        return result or list(obligation_order)

    port_obligations: dict[str, list[str]] = {}
    for port_id, port in ports.items():
        tech_story_ids = set(port["techStoryIds"])
        port_obligations[port_id] = normalize_obligations(
            [
                obligation["id"]
                for obligation in obligations
                if tech_story_ids.intersection(obligation["techStoryIds"])
            ]
        )

    operation_obligations: dict[str, list[str]] = {}
    for operation_id, operation in operations.items():
        owner_port_id = operation["ownerPortId"]
        if owner_port_id not in port_obligations:
            raise ValueError(
                f"operation {operation_id} references unknown owner port {owner_port_id}"
            )
        operation_obligations[operation_id] = list(port_obligations[owner_port_id])

    transition_obligations: dict[str, list[str]] = {}
    for transition_id, transition in transitions.items():
        operation_ids = transition["operationIds"]
        unknown_operations = set(operation_ids) - set(operations)
        if unknown_operations:
            raise ValueError(
                f"transition {transition_id} references unknown operations: "
                + ", ".join(sorted(unknown_operations))
            )
        candidate_ids = [
            obligation_id
            for operation_id in operation_ids
            for obligation_id in operation_obligations[operation_id]
        ]
        if any(operations[operation_id]["sideEffect"] != "NONE" for operation_id in operation_ids):
            candidate_ids.append("TEST-CRASH-RECONCILE-AUDIT")
        transition_obligations[transition_id] = normalize_obligations(
            ordered_unique(candidate_ids)
        )

    machine_obligations: dict[str, list[str]] = {}
    entity_obligations: dict[str, list[str]] = {}
    for machine_id, machine in state_machines.items():
        candidate_ids = [
            obligation_id
            for transition in machine["transitions"]
            for obligation_id in transition_obligations[transition["id"]]
        ]
        derived = normalize_obligations(ordered_unique(candidate_ids))
        machine_obligations[machine_id] = derived
        entity_obligations.setdefault(machine["entityId"], []).extend(derived)
    entity_obligations = {
        entity_id: normalize_obligations(ordered_unique(candidate_ids))
        for entity_id, candidate_ids in entity_obligations.items()
    }

    cas_obligations: dict[str, list[str]] = {}
    for cas_rule in contract["casRules"]:
        candidate_ids = [
            obligation_id
            for transition in transitions.values()
            if cas_rule["id"] in transition["casRuleIds"]
            for obligation_id in transition_obligations[transition["id"]]
        ]
        cas_obligations[cas_rule["id"]] = normalize_obligations(
            ordered_unique(candidate_ids)
        )

    reason_obligations: dict[str, list[str]] = {}
    for reason in contract["errorContract"]["reasonCodes"]:
        candidate_ids = [
            obligation_id
            for operation in operations.values()
            if reason["code"] in operation["failureReasonCodes"]
            for obligation_id in operation_obligations[operation["id"]]
        ]
        reason_obligations[reason["code"]] = normalize_obligations(
            ordered_unique(candidate_ids)
        )

    def obligations_for(kind: str, item_id: str) -> list[str]:
        if kind == "TEST":
            return normalize_obligations([item_id])
        if kind == "PARITY_OBLIGATION":
            return normalize_obligations(parity[item_id]["testObligationIds"])
        if kind == "PORT":
            return port_obligations[item_id]
        if kind == "OPERATION":
            return operation_obligations[item_id]
        if kind == "TRANSITION":
            return transition_obligations[item_id]
        if kind == "STATE_MACHINE":
            return machine_obligations[item_id]
        if kind == "REASON":
            return reason_obligations[item_id]
        if kind == "CAS_RULE":
            return cas_obligations[item_id]
        if kind == "EQUIVALENCE":
            return normalize_obligations(["TEST-DYNAMIC"])
        if kind == "ENTITY" and item_id in entity_obligations:
            return entity_obligations[item_id]
        return list(obligation_order)

    matrix: list[dict[str, Any]] = []
    for kind, item_id, _track in items:
        required_obligations = obligations_for(kind, item_id)
        required_cases = ordered_unique(
            [
                case_id
                for obligation_id in required_obligations
                for case_id in obligation_by_id[obligation_id]["caseIds"]
            ]
        )
        row: dict[str, Any] = {
            "kind": kind,
            "contractItemId": item_id,
            "requiredTestObligationIds": required_obligations,
            "requiredCaseIds": required_cases,
            "requiredOracleClasses": oracle_classes,
            "typedCoverageRule": TYPED_COVERAGE_RULES.get(
                kind, CONSERVATIVE_COVERAGE_RULE
            ),
        }
        row["requirementDigest"] = digest_bytes(canonical_bytes(row))
        matrix.append(row)

    if [(row["kind"], row["contractItemId"]) for row in matrix] != [
        (kind, item_id) for kind, item_id, _track in items
    ]:
        raise ValueError("verification matrix order differs from mapping surface")
    if len(matrix) != len(
        {(row["kind"], row["contractItemId"]) for row in matrix}
    ):
        raise ValueError("verification matrix contains duplicate kind/id")
    return matrix


def prefix_schema(
    kind: str,
    item_id: str,
    track: str,
    verification_requirement_digest: str,
) -> dict[str, Any]:
    return {
        "allOf": [
            {"$ref": "#/$defs/mapping"},
            {
                "type": "object",
                "properties": {
                    "contractItemId": {"const": item_id},
                    "kind": {"const": kind},
                    "releaseTrack": {"const": track},
                    "verificationRequirementDigest": {
                        "const": verification_requirement_digest
                    },
                },
                "required": [
                    "contractItemId",
                    "kind",
                    "releaseTrack",
                    "verificationRequirementDigest",
                ],
            },
        ]
    }


def template_mapping(
    kind: str,
    item_id: str,
    track: str,
    authority_digest: str,
    verification_requirement_digest: str,
) -> dict[str, Any]:
    deferred = track == "FUTURE_SEPARATELY_QUALIFIED"
    return {
        "contractItemId": item_id,
        "kind": kind,
        "releaseTrack": track,
        "verificationRequirementDigest": verification_requirement_digest,
        "mappingStatus": "DEFERRED" if deferred else "UNMAPPED",
        "disposition": "DEFERRED" if deferred else "UNMAPPED",
        "implementationStatus": (
            "NOT_APPLICABLE_CURRENT_RELEASE" if deferred else "NOT_STARTED"
        ),
        "targetBindings": [],
        "targetTestBindings": [],
        "transitionExecutionBinding": None,
        "conflict": None,
        "deferDecision": (
            {
                "authorityPath": "contracts/product-decisions.json",
                "authoritySha256": authority_digest,
                "authorityDecisionId": "ADR-002",
                "decision": "DEFER_CURRENT_RELEASE",
                "releaseTrack": "FUTURE_SEPARATELY_QUALIFIED",
                "authorizationModel": "PORTABLE_NORMATIVE_SOURCE_CLOSURE",
                "approvalEvidenceHash": authority_digest,
            }
            if deferred
            else None
        ),
        "notes": (
            "Current Legacy-first release; enabling this future track requires "
            "separate mapping, implementation, qualification, and release approval."
            if deferred
            else ""
        ),
    }


def desired_documents() -> tuple[bytes, bytes, bytes]:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))

    items = derive_mapping_items(contract)
    verification_matrix = derive_verification_matrix(contract, items)
    contract["mappingSurface"]["verificationMatrixVersion"] = 1
    contract["mappingSurface"]["verificationMatrix"] = verification_matrix
    contract["mappingSurface"]["verificationMatrixRule"] = (
        "The generator emits exactly one ordered, hash-bound row for every derived "
        "mapping item. TEST is self-covered; PARITY uses its declared tests; PORT "
        "uses acceptance Tech Story intersection; OPERATION inherits its owner PORT; "
        "TRANSITION unions its operations and adds TEST-CRASH-RECONCILE-AUDIT when "
        "any operation is side-effecting; STATE_MACHINE unions its transitions; "
        "REASON unions listing operations; CAS_RULE unions referencing transitions; "
        "EQUIVALENCE uses TEST-DYNAMIC; ENTITY uses its FSM when present; all other "
        "kinds and every empty derivation conservatively require all obligations. "
        "requiredCaseIds is the exact ordered union of those obligations and every "
        "row requires all eight scenario oracle classes. requirementDigest is "
        "SHA-256(CANONICAL-JSON-V1(row without requirementDigest)). A target mapping "
        "binds this digest by const; scenario self-claims cannot reduce or expand it."
    )
    revision = contract["revision"]
    schema["properties"]["sourceContract"]["properties"]["revision"] = {
        "const": revision
    }
    mapping_definition = schema["$defs"]["mapping"]
    if "verificationRequirementDigest" not in mapping_definition["required"]:
        mapping_definition["required"].insert(2, "verificationRequirementDigest")
    mapping_definition["properties"]["verificationRequirementDigest"] = {
        "type": "string",
        "pattern": "^sha256:[0-9a-f]{64}$",
    }
    matrix_semantic_rule = (
        "Every mapping.verificationRequirementDigest equals the const digest in its "
        "ordered prefix item and the matching source contract verificationMatrix row. "
        "Recompute each row digest over CANONICAL-JSON-V1 with requirementDigest "
        "omitted; target test bindings and scenario claims cannot alter requirements."
    )
    semantic_rules = schema.setdefault("x-qmanSemanticValidationRules", [])
    if matrix_semantic_rule not in semantic_rules:
        semantic_rules.append(matrix_semantic_rule)
    mapping_schema = schema["properties"]["mappings"]
    mapping_schema["minItems"] = len(items)
    mapping_schema["maxItems"] = len(items)
    mapping_schema["prefixItems"] = [
        prefix_schema(*item, row["requirementDigest"])
        for item, row in zip(items, verification_matrix)
    ]

    template["sourceContract"]["contractId"] = contract["contractId"]
    template["sourceContract"]["revision"] = revision
    template["sourceContract"]["sha256"] = None
    template["mapDigest"] = None
    template["scenarioBindingDigest"] = None
    authority_digest = digest_bytes((ROOT / "contracts/product-decisions.json").read_bytes())
    template["mappings"] = [
        template_mapping(
            kind,
            item_id,
            track,
            authority_digest,
            row["requirementDigest"],
        )
        for (kind, item_id, track), row in zip(items, verification_matrix)
    ]

    schema_bytes = render(schema)
    template_bytes = render(template)
    byte_overrides = {
        "contracts/qman-integration-map.schema.json": schema_bytes,
    }
    sources = contract.get("normativeSources")
    if not isinstance(sources, list) or not sources or not all(
        isinstance(item, str) and item for item in sources
    ):
        raise ValueError("normativeSources must be a non-empty string list")
    if len(sources) != len(set(sources)):
        raise ValueError("normativeSources contains duplicates")
    prior_closure = contract.get("normativeSourceClosure")
    if not isinstance(prior_closure, list):
        raise ValueError("normativeSourceClosure must be an array")
    prior_scopes = {
        item.get("path"): item.get("hashScope")
        for item in prior_closure
        if isinstance(item, dict)
    }
    closure = []
    for relative in sources:
        candidate = (ROOT / relative).resolve()
        candidate.relative_to(ROOT.resolve())
        default_scope = "REPOSITORY_TREE_V1" if candidate.is_dir() else "GIT_BLOB_BYTES"
        closure.append(
            {
                "path": relative,
                "hashScope": prior_scopes.get(relative, default_scope),
                "sha256": "sha256:" + ("0" * 64),
            }
        )
    contract["normativeSourceClosure"] = closure
    for entry in closure:
        relative = entry["path"]
        candidate = (ROOT / relative).resolve()
        candidate.relative_to(ROOT.resolve())
        scope = entry["hashScope"]
        if scope == "GIT_BLOB_BYTES":
            if not candidate.is_file():
                raise ValueError(f"normative file is missing: {relative}")
            entry["sha256"] = digest_bytes(
                byte_overrides.get(relative, candidate.read_bytes())
            )
        elif scope == "REPOSITORY_TREE_V1":
            if not candidate.is_dir():
                raise ValueError(f"normative tree is missing: {relative}")
            entry["sha256"] = tree_digest(candidate)
        else:
            raise ValueError(f"unknown normative hash scope: {scope}")

    return render(contract), schema_bytes, template_bytes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if generated files drift")
    args = parser.parse_args()
    desired = desired_documents()
    paths = (CONTRACT_PATH, SCHEMA_PATH, TEMPLATE_PATH)
    drift = [path for path, data in zip(paths, desired) if path.read_bytes() != data]
    if args.check:
        if drift:
            for path in drift:
                print(f"drift: {path.relative_to(ROOT)}")
            return 1
        print("portable package closure: current")
        return 0
    for path, data in zip(paths, desired):
        path.write_bytes(data)
        print(f"generated: {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
