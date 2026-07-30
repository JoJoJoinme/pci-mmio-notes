#!/usr/bin/env python3
"""Generate the closed DirectPath acceptance Case contract registry.

The design matrix, explicit Case classifications, and portable control contract
are independent normative inputs.  This tool joins them deterministically so a
target repository cannot replace a Case pass condition with a weaker test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DESIGN = ROOT / "qemu-static-dynamic-directpath-design.md"
POLICY = ROOT / "contracts/acceptance-policy.json"
PORTABLE = ROOT / "contracts/directpath-portable-control-contract.json"
SCENARIO_SCHEMA = ROOT / "contracts/directpath-acceptance-scenario.schema.json"
CASES = ROOT / "acceptance/cases"
OUTPUT = ROOT / "contracts/directpath-acceptance-case-contracts.json"

ORACLE_CLASSES = [
    "authoritativeWrites",
    "cleanup",
    "finalStates",
    "idempotencyOracle",
    "immediateResults",
    "mustNotOccur",
    "mustOccur",
    "physicalOracle",
]

EXPLICIT_TRACE_FIELDS = (
    "requiredPortIds",
    "requiredOperationIds",
    "requiredTransitionIds",
    "requiredEntityIds",
    "requiredReasonIds",
)


def render(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(ROOT)} is not a JSON object")
    return value


def require_nfc(value: str, label: str) -> str:
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{label} is not NFC")
    return value


def design_rows() -> list[dict[str, str]]:
    text = DESIGN.read_text(encoding="utf-8")
    try:
        body = text.split("## 19.", 1)[1].split("## 20.", 1)[0]
    except IndexError as exc:
        raise ValueError("cannot locate design section 19") from exc
    rows: list[dict[str, str]] = []
    for line in body.splitlines():
        if re.match(r"^\|\s*[COSDMF]\d{2}[a-z]?\s*\|", line) is None:
            continue
        columns = [part.strip() for part in line.strip().strip("|").split("|")]
        if len(columns) != 4:
            raise ValueError(f"Case row must have four columns: {line}")
        case_id, title, pass_condition, source_evidence = columns
        rows.append(
            {
                "caseId": require_nfc(case_id, f"{case_id}.caseId"),
                "title": require_nfc(title, f"{case_id}.title"),
                "passCondition": require_nfc(
                    pass_condition, f"{case_id}.passCondition"
                ),
                "sourceEvidence": require_nfc(
                    source_evidence, f"{case_id}.sourceEvidence"
                ),
            }
        )
    ids = [row["caseId"] for row in rows]
    if len(rows) != 101 or len(set(ids)) != 101:
        raise ValueError(f"design section 19 must contain 101 unique Cases, got {len(rows)}")
    return rows


def case_definitions() -> dict[str, tuple[dict[str, Any], str, str]]:
    result: dict[str, tuple[dict[str, Any], str, str]] = {}
    for path in sorted(CASES.glob("*.json")):
        document = load_json(path)
        records = document.get("records", [document])
        if not isinstance(records, list):
            raise ValueError(f"{path.relative_to(ROOT)} records is not an array")
        file_digest = digest(path.read_bytes())
        relative = path.relative_to(ROOT).as_posix()
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("id"), str):
                raise ValueError(f"{relative} contains an invalid Case record")
            case_id = record["id"]
            if case_id in result:
                raise ValueError(f"duplicate Case {case_id}")
            result[case_id] = (record, relative, file_digest)
    if len(result) != 101:
        raise ValueError(f"acceptance/cases must define 101 Cases, got {len(result)}")
    return result


def assertion_oracle(statement: str) -> str:
    lowered = statement.casefold()
    if any(word in lowered for word in ("idempot", "replay", "重复", "重放")):
        return "idempotencyOracle"
    if any(word in lowered for word in ("cleanup", "release", "rollback", "quarant", "清理", "释放", "回滚", "隔离")):
        return "cleanup"
    if any(word in lowered for word in ("must not", " never ", "reject", "deny", "without", "不得", "拒绝", "不能", "不可")):
        return "mustNotOccur"
    if any(word in lowered for word in ("commit", "lease", "resourceversion", "cas", "持久", "事务", "租约")):
        return "authoritativeWrites"
    if any(word in lowered for word in ("state", " free", "attached", "状态")):
        return "finalStates"
    return "physicalOracle"


def fault_classes(text: str) -> list[str]:
    lowered = text.casefold()
    values: set[str] = set()
    if any(word in lowered for word in ("qemu start", "qemu 启动", "spawn qemu")):
        values.add("QEMU_START_FAILURE")
    if any(word in lowered for word in ("stale", "epoch", "generation", "版本漂移", "过期")):
        values.add("STALE_AUTHORITY")
    if any(word in lowered for word in ("crash", "崩溃")):
        values.add("PROCESS_CRASH")
    if any(word in lowered for word in ("race", "concurrent", "duplicate", "replay", "idempot", "并发", "重复", "重放")):
        values.add("CONCURRENCY_REPLAY")
    if any(word in lowered for word in ("host unreachable", "host loss", "source loss", "主机不可达", "源主机丢失")):
        values.add("HOST_UNREACHABLE")
    if any(word in lowered for word in ("cleanup", "release", "rollback", "清理", "释放", "回滚")) and any(
        word in lowered for word in ("fail", "uncertain", "error", "失败", "不确定")
    ):
        values.add("CLEAN_RELEASE_FAILURE")
    if "reset" in lowered and any(
        word in lowered for word in ("fail", "without", "unsafe", "拒绝", "失败", "不安全")
    ):
        values.add("RESET_FAILURE")
    return sorted(values)


def artifact_schemas(text: str) -> list[str]:
    lowered = text.casefold()
    values = {
        "contracts/directpath-acceptance-scenario.schema.json",
        "contracts/directpath-execution-evidence-index.schema.json",
        "contracts/directpath-runner-manifest.schema.json",
    }
    if any(word in lowered for word in ("release", "cleanup", "rollback", "relocat", "释放", "清理", "回滚", "迁移")):
        values.update(
            {
                "contracts/directpath-clean-release-receipt.schema.json",
                "contracts/directpath-authority-entities.schema.json#/$defs/ENTITY-CLEAN-RELEASE-ACCEPTANCE",
            }
        )
    if any(word in lowered for word in ("qualif", "catalog", "supported", "hcl", "兼容", "认证")):
        values.update(
            {
                "contracts/directpath-qualification-record.schema.json",
                "contracts/directpath-qualification-subject-manifest.schema.json",
            }
        )
    if any(word in lowered for word in ("identity", "bdf", "serial", "deviceuid", "身份", "设备标识")):
        values.add("contracts/directpath-identity-v1.schema.json")
    return sorted(values)


def required_artifact_schemas(
    definition: dict[str, Any],
    semantic_text: str,
) -> list[str]:
    """Join heuristic defaults with an optional closed, explicit Case list."""

    derived = set(artifact_schemas(semantic_text))
    explicit = definition.get("requiredArtifactSchemaRefs", [])
    if not isinstance(explicit, list) or any(
        not isinstance(item, str) or not item for item in explicit
    ):
        raise ValueError(
            f"Case {definition.get('id')} requiredArtifactSchemaRefs "
            "must be a string list"
        )
    if len(explicit) != len(set(explicit)):
        raise ValueError(
            f"Case {definition.get('id')} requiredArtifactSchemaRefs "
            "must be unique"
        )
    if explicit != sorted(explicit):
        raise ValueError(
            f"Case {definition.get('id')} requiredArtifactSchemaRefs "
            "must use ascending schema-ref order"
        )
    for schema_ref in explicit:
        schema_path = schema_ref.split("#", 1)[0]
        if not schema_path.startswith("contracts/"):
            raise ValueError(
                f"Case {definition.get('id')} schema ref must stay under "
                f"contracts/: {schema_ref}"
            )
        if not (ROOT / schema_path).is_file():
            raise ValueError(
                f"Case {definition.get('id')} references missing schema "
                f"{schema_path}"
            )
    return sorted(derived.union(explicit))


def indexed_records(
    records: list[dict[str, Any]], id_field: str, label: str
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(records):
        item_id = record.get(id_field)
        if not isinstance(item_id, str) or not item_id:
            raise ValueError(f"{label}[{index}].{id_field} is not a non-empty string")
        if item_id in result:
            raise ValueError(f"{label} contains duplicate {id_field} {item_id}")
        result[item_id] = record
    return result


def explicit_id_set(
    definition: dict[str, Any],
    field: str,
    known_ids: set[str],
    *,
    allow_empty: bool,
) -> list[str]:
    value = definition.get(field)
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ValueError(f"Case {definition.get('id')} {field} must be a string list")
    if len(value) != len(set(value)):
        raise ValueError(f"Case {definition.get('id')} {field} must be unique")
    if value != sorted(value):
        raise ValueError(
            f"Case {definition.get('id')} {field} must use ascending ID order"
        )
    if not allow_empty and not value:
        raise ValueError(f"Case {definition.get('id')} {field} must not be empty")
    unknown = set(value) - known_ids
    if unknown:
        raise ValueError(
            f"Case {definition.get('id')} {field} references unknown IDs "
            f"{sorted(unknown)}"
        )
    return list(value)


def resolve_required_trace(
    definition: dict[str, Any],
    *,
    derived_ports: list[str],
    port_by_id: dict[str, dict[str, Any]],
    operation_by_id: dict[str, dict[str, Any]],
    transition_by_id: dict[str, dict[str, Any]],
    entity_by_id: dict[str, dict[str, Any]],
    reason_by_id: dict[str, dict[str, Any]],
) -> tuple[list[str], list[str], list[str], list[str], list[str]]:
    """Resolve a Case trace, validating every explicit cross-reference.

    Legacy Case records omit all five fields and retain the Tech Story-derived
    port/operation/transition surface.  Once a Case opts in, all five fields
    are mandatory so a partial override cannot silently reintroduce the broad
    Tech Story union for the remaining dimensions.
    """

    present = [field for field in EXPLICIT_TRACE_FIELDS if field in definition]
    if present and len(present) != len(EXPLICIT_TRACE_FIELDS):
        missing = sorted(set(EXPLICIT_TRACE_FIELDS) - set(present))
        raise ValueError(
            f"Case {definition.get('id')} explicit trace is partial; missing {missing}"
        )

    if not present:
        required_ports = sorted(derived_ports)
        required_port_set = set(required_ports)
        required_operations = sorted(
            operation_id
            for operation_id, operation in operation_by_id.items()
            if operation["ownerPortId"] in required_port_set
        )
        required_operation_set = set(required_operations)
        required_transitions = sorted(
            transition_id
            for transition_id, transition in transition_by_id.items()
            if set(transition["operationIds"]).intersection(required_operation_set)
        )
        return (
            required_ports,
            required_operations,
            required_transitions,
            [],
            [],
        )

    required_ports = explicit_id_set(
        definition,
        "requiredPortIds",
        set(port_by_id),
        allow_empty=False,
    )
    required_operations = explicit_id_set(
        definition,
        "requiredOperationIds",
        set(operation_by_id),
        allow_empty=False,
    )
    required_transitions = explicit_id_set(
        definition,
        "requiredTransitionIds",
        set(transition_by_id),
        allow_empty=True,
    )
    required_entities = explicit_id_set(
        definition,
        "requiredEntityIds",
        set(entity_by_id),
        allow_empty=False,
    )
    required_reasons = explicit_id_set(
        definition,
        "requiredReasonIds",
        set(reason_by_id),
        allow_empty=False,
    )

    operation_set = set(required_operations)
    owner_ports = {
        operation_by_id[operation_id]["ownerPortId"]
        for operation_id in required_operations
    }
    if set(required_ports) != owner_ports:
        raise ValueError(
            f"Case {definition.get('id')} requiredPortIds must exactly equal "
            f"required operation owners {sorted(owner_ports)}"
        )
    for transition_id in required_transitions:
        referenced_operations = set(transition_by_id[transition_id]["operationIds"])
        if not referenced_operations.issubset(operation_set):
            raise ValueError(
                f"Case {definition.get('id')} transition {transition_id} references "
                "operations outside requiredOperationIds "
                f"{sorted(referenced_operations - operation_set)}"
            )
    return (
        required_ports,
        required_operations,
        required_transitions,
        required_entities,
        required_reasons,
    )


def generate() -> dict[str, Any]:
    policy = load_json(POLICY)
    portable = load_json(PORTABLE)
    rows = design_rows()
    definitions = case_definitions()

    obligations = portable["acceptanceObligations"]
    parity = portable["vmwareParityObligations"]
    ports = portable["requiredPorts"]
    operations = portable["backendNeutralOperations"]
    transitions = [
        transition
        for machine in portable["stateMachines"]
        for transition in machine["transitions"]
    ]
    port_by_id = indexed_records(ports, "id", "requiredPorts")
    operation_by_id = indexed_records(
        operations, "id", "backendNeutralOperations"
    )
    transition_by_id = indexed_records(transitions, "id", "stateMachine transitions")
    entity_by_id = indexed_records(portable["dataEntities"], "id", "dataEntities")
    reason_by_id = indexed_records(
        portable["errorContract"]["reasonCodes"], "code", "errorContract.reasonCodes"
    )
    for operation_id, operation in operation_by_id.items():
        owner = operation.get("ownerPortId")
        if owner not in port_by_id:
            raise ValueError(
                f"operation {operation_id} references unknown owner port {owner}"
            )
        unknown_reasons = set(operation.get("failureReasonCodes", [])) - set(
            reason_by_id
        )
        if unknown_reasons:
            raise ValueError(
                f"operation {operation_id} references unknown reason IDs "
                f"{sorted(unknown_reasons)}"
            )
    for transition_id, transition in transition_by_id.items():
        unknown_operations = set(transition.get("operationIds", [])) - set(
            operation_by_id
        )
        if unknown_operations:
            raise ValueError(
                f"transition {transition_id} references unknown operation IDs "
                f"{sorted(unknown_operations)}"
            )
        unknown_reasons = set(transition.get("failureReasonCodes", [])) - set(
            reason_by_id
        )
        if unknown_reasons:
            raise ValueError(
                f"transition {transition_id} references unknown reason IDs "
                f"{sorted(unknown_reasons)}"
            )
    for machine in portable["stateMachines"]:
        if machine.get("entityId") not in entity_by_id:
            raise ValueError(
                f"state machine {machine.get('id')} references unknown entity "
                f"{machine.get('entityId')}"
            )
    scenario_schema = load_json(SCENARIO_SCHEMA)
    actual_oracles = sorted(
        scenario_schema["$defs"]["oracleMatrix"]["properties"].keys()
    )
    if actual_oracles != ORACLE_CLASSES:
        raise ValueError("acceptance scenario oracle classes drifted")

    records: list[dict[str, Any]] = []
    for row in rows:
        case_id = row["caseId"]
        if case_id not in definitions:
            raise ValueError(f"design Case {case_id} has no definition")
        definition, definition_path, definition_file_digest = definitions[case_id]
        stories = sorted(definition["requiredTechStories"])
        story_set = set(stories)
        test_ids = sorted(
            item["id"] for item in obligations if case_id in item["caseIds"]
        )
        if not test_ids:
            raise ValueError(f"Case {case_id} has no acceptance obligation")
        parity_ids = sorted(
            item["id"]
            for item in parity
            if set(item["testObligationIds"]).intersection(test_ids)
        )
        derived_ports = sorted(
            item["id"]
            for item in ports
            if set(item["techStoryIds"]).intersection(story_set)
        )
        (
            required_ports,
            required_operations,
            required_transitions,
            required_entities,
            required_reasons,
        ) = resolve_required_trace(
            definition,
            derived_ports=derived_ports,
            port_by_id=port_by_id,
            operation_by_id=operation_by_id,
            transition_by_id=transition_by_id,
            entity_by_id=entity_by_id,
            reason_by_id=reason_by_id,
        )
        if not required_ports or not required_operations:
            raise ValueError(f"Case {case_id} has an empty derived executable trace surface")

        semantic_text_parts = [
            row["title"],
            row["passCondition"],
            definition.get("title", ""),
            definition.get("blocker", ""),
            *(definition.get("assertions") or []),
        ]
        semantic_text = "\n".join(
            value for value in semantic_text_parts if isinstance(value, str)
        )
        faults = fault_classes(semantic_text)

        matrix_projection = {
            "section": "19",
            "title": row["title"],
            "passCondition": row["passCondition"],
            "sourceEvidence": row["sourceEvidence"],
        }
        matrix = {
            **matrix_projection,
            "rowDigest": digest(canonical(matrix_projection)),
        }

        assertion_sources: list[tuple[str, str]] = [
            ("DESIGN_PASS_CONDITION", row["passCondition"])
        ]
        for statement in definition.get("assertions") or []:
            if statement != row["passCondition"]:
                assertion_sources.append(("CASE_ASSERTION", statement))
        assertions: list[dict[str, Any]] = []
        counters: dict[str, int] = {}
        for source_kind, statement in assertion_sources:
            prefix = "PASS" if source_kind == "DESIGN_PASS_CONDITION" else "ASSERT"
            counters[prefix] = counters.get(prefix, 0) + 1
            assertion_projection = {
                "assertionId": f"{case_id}-{prefix}-{counters[prefix]:03d}",
                "sourceKind": source_kind,
                "statement": require_nfc(statement, f"{case_id} assertion"),
                "statementSha256": digest(statement.encode("utf-8")),
                "requiredOracleClass": assertion_oracle(statement),
                "predicateEvaluator": "TARGET-PREDICATE-INTERFACE-V1",
            }
            assertions.append(
                {
                    **assertion_projection,
                    "assertionDigest": digest(canonical(assertion_projection)),
                }
            )

        classification = {
            "scope": definition["scope"],
            "status": definition["status"],
            "targetMilestone": definition["targetMilestone"],
            "proofBoundaryOrNull": definition.get("proofBoundary"),
            "riskIds": sorted(definition["riskIds"]),
            "techStoryIds": stories,
            "dependsOnCaseIds": sorted(definition["dependsOnCaseIds"]),
        }
        minimum_duration = 300 if definition["status"] == "HARDWARE_BLOCKED" else (10 if faults else 1)
        explicit_entity_reason_trace = (
            {
                "requiredEntityIds": required_entities,
                "requiredReasonIds": required_reasons,
            }
            if "requiredEntityIds" in definition
            else {}
        )
        record_projection = {
            "caseId": case_id,
            "definitionPath": definition_path,
            "definitionFileSha256": definition_file_digest,
            "definitionRecordSha256": digest(canonical(definition)),
            "designMatrix": matrix,
            "classification": classification,
            "testObligationIds": test_ids,
            "parityObligationIds": parity_ids,
            "requiredPortIds": required_ports,
            "requiredOperationIds": required_operations,
            "requiredTransitionIds": required_transitions,
            **explicit_entity_reason_trace,
            "requiredFaultClasses": faults,
            "requiredArtifactSchemaRefs": required_artifact_schemas(
                definition,
                semantic_text,
            ),
            "requiredOracleClasses": ORACLE_CLASSES,
            "minimumRepeat": 3 if faults else 1,
            "minimumDurationSeconds": minimum_duration,
            "assertions": assertions,
            "evidenceBoundary": {
                "productClosureGrade": "E3-END-TO-END-PRODUCT",
                "qualificationClosureGrade": "E4-PHYSICAL-QUALIFICATION",
                "componentOrReferenceEvidenceMayCloseProduct": False,
                "vmwareObservationMayCloseProduct": False,
                "blockedCaseMayExecuteAsClosure": False,
                "dependencyClosureRequired": True,
            },
        }
        records.append(
            {
                **record_projection,
                "caseContractDigest": digest(
                    canonical({**record_projection, "caseContractDigest": None})
                ),
            }
        )

    if policy.get("expectedCaseCount") != len(records):
        raise ValueError("acceptance policy count does not match generated Case contracts")
    root_projection = {
        "schemaVersion": 1,
        "registryId": "QMAN-DIRECTPATH-ACCEPTANCE-CASE-CONTRACTS",
        "generationAlgorithm": "DERIVED-CLOSED-CASE-CONTRACT-V1",
        "portableContractId": portable["contractId"],
        "portableContractRevision": portable["revision"],
        "sourcePolicySha256": digest(POLICY.read_bytes()),
        "sourceDesignSha256": digest(DESIGN.read_bytes()),
        "oracleClasses": ORACLE_CLASSES,
        "caseCount": len(records),
        "records": records,
    }
    return {
        **root_projection,
        "registryDigest": digest(
            canonical({**root_projection, "registryDigest": None})
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = render(generate())
    if args.check:
        actual = OUTPUT.read_bytes() if OUTPUT.exists() else b""
        if actual != expected:
            print(f"STALE: {OUTPUT.relative_to(ROOT)}")
            return 1
        print(f"PASS: {OUTPUT.relative_to(ROOT)} is current")
        return 0
    OUTPUT.write_bytes(expected)
    print(f"WROTE: {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
